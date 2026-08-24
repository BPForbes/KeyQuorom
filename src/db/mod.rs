use rusqlite::{Connection, Result};
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");

/// Opens or creates a KeyQuorum SQLite database at the specified path and applies its schema.
///
/// # Examples
///
/// ```
/// let connection = open(":memory:")?;
/// # Ok::<(), rusqlite::Error>(())
/// ```
///
/// Repeated calls safely reapply the schema.
///
/// # Errors
///
/// Returns an error if the database cannot be opened or initialized.
pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
}

/// Opens an in-memory SQLite database and applies the database schema.
///
/// # Returns
///
/// A connection to the initialized in-memory database.
///
/// # Examples
///
/// ```
/// let connection = keyquorum::db::open_in_memory().unwrap();
/// assert!(connection.is_autocommit());
/// ```
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    init(&conn)?;
    Ok(conn)
}

/// Initializes a SQLite connection for KeyQuorum use.
///
/// Configures lock contention handling, enables foreign-key enforcement, and
/// applies the database schema.
///
/// # Examples
///
/// ```
/// # use rusqlite::Connection;
/// # let conn = Connection::open_in_memory().unwrap();
/// init(&conn).unwrap();
/// ```
fn init(conn: &Connection) -> Result<()> {
    // Block briefly on lock contention instead of failing immediately with
    // SQLITE_BUSY, so concurrent access from multiple connections (e.g. a
    // share redemption race) resolves in commit order rather than erroring.
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.execute_batch(SCHEMA)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    #[test]
    fn schema_applies_cleanly() {
        let conn = open_in_memory().expect("schema should apply");
        let table_count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get(0),
            )
            .expect("query should succeed");
        assert_eq!(table_count, 8);
    }

    #[test]
    fn schema_is_idempotent() {
        let conn = open_in_memory().expect("schema should apply");
        conn.execute_batch(SCHEMA)
            .expect("re-applying schema should not error");
    }

    #[test]
    fn quorum_threshold_must_be_positive() {
        let conn = open_in_memory().expect("schema should apply");
        let result = conn.execute(
            "INSERT INTO files (name, encrypted_path, content_hash, quorum_threshold)
             VALUES ('secret.txt', '/data/secret.txt.enc', 'deadbeef', 0)",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn file_key_share_requires_known_file_and_key() {
        let conn = open_in_memory().expect("schema should apply");
        let result = conn.execute(
            "INSERT INTO file_key_shares (file_id, hardware_key_id, wrapped_share)
             VALUES (1, 1, x'00')",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn quorum_threshold_accepts_valid_integer() {
        let conn = open_in_memory().expect("schema should apply");
        let result = conn.execute(
            "INSERT INTO files (name, encrypted_path, content_hash, quorum_threshold)
             VALUES ('secret.txt', '/data/secret.txt.enc', 'deadbeef', 2)",
            [],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn quorum_threshold_rejects_non_integer_numeric_value() {
        let conn = open_in_memory().expect("schema should apply");
        let result = conn.execute(
            "INSERT INTO files (name, encrypted_path, content_hash, quorum_threshold)
             VALUES ('secret.txt', '/data/secret.txt.enc', 'deadbeef', ?1)",
            params![0.5_f64],
        );
        assert!(result.is_err());
    }

    #[test]
    fn quorum_threshold_rejects_non_numeric_text() {
        let conn = open_in_memory().expect("schema should apply");
        let result = conn.execute(
            "INSERT INTO files (name, encrypted_path, content_hash, quorum_threshold)
             VALUES ('secret.txt', '/data/secret.txt.enc', 'deadbeef', ?1)",
            params!["abc"],
        );
        assert!(result.is_err());
    }

    /// Seeds a database with two hardware keys and a file whose quorum requires both corresponding shares.
    ///
    /// # Examples
    ///
    /// ```
    /// # let conn = rusqlite::Connection::open_in_memory().unwrap();
    /// # conn.execute_batch(include_str!("schema.sql")).unwrap();
    /// seed_two_of_two_file(&conn);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if any seed row cannot be inserted.
    fn seed_two_of_two_file(conn: &Connection) {
        conn.execute(
            "INSERT INTO hardware_keys (id, label, fingerprint, public_key) VALUES
             (1, 'key-a', 'fp-a', x'01'),
             (2, 'key-b', 'fp-b', x'02')",
            [],
        )
        .expect("seed hardware_keys");
        conn.execute(
            "INSERT INTO files (id, name, encrypted_path, content_hash, quorum_threshold)
             VALUES (1, 'secret.txt', '/data/secret.txt.enc', 'deadbeef', 2)",
            [],
        )
        .expect("seed files");
        conn.execute(
            "INSERT INTO file_key_shares (file_id, hardware_key_id, wrapped_share) VALUES
             (1, 1, x'aa'),
             (1, 2, x'bb')",
            [],
        )
        .expect("seed file_key_shares");
    }

    #[test]
    fn deleting_hardware_key_backing_a_share_is_blocked() {
        let conn = open_in_memory().expect("schema should apply");
        seed_two_of_two_file(&conn);
        let result = conn.execute("DELETE FROM hardware_keys WHERE id = 1", []);
        assert!(result.is_err());
    }

    #[test]
    fn removing_last_required_share_is_blocked() {
        let conn = open_in_memory().expect("schema should apply");
        seed_two_of_two_file(&conn);
        let result = conn.execute(
            "DELETE FROM file_key_shares WHERE file_id = 1 AND hardware_key_id = 1",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn removing_a_surplus_share_is_allowed() {
        let conn = open_in_memory().expect("schema should apply");
        conn.execute(
            "INSERT INTO hardware_keys (id, label, fingerprint, public_key) VALUES
             (1, 'key-a', 'fp-a', x'01'),
             (2, 'key-b', 'fp-b', x'02')",
            [],
        )
        .expect("seed hardware_keys");
        // 1-of-2: quorum only needs one key, so two registered shares
        // leaves one to spare.
        conn.execute(
            "INSERT INTO files (id, name, encrypted_path, content_hash, quorum_threshold)
             VALUES (1, 'secret.txt', '/data/secret.txt.enc', 'deadbeef', 1)",
            [],
        )
        .expect("seed files");
        conn.execute(
            "INSERT INTO file_key_shares (file_id, hardware_key_id, wrapped_share) VALUES
             (1, 1, x'aa'),
             (1, 2, x'bb')",
            [],
        )
        .expect("seed file_key_shares");

        let result = conn.execute(
            "DELETE FROM file_key_shares WHERE file_id = 1 AND hardware_key_id = 1",
            [],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn raising_quorum_threshold_above_share_count_is_blocked() {
        let conn = open_in_memory().expect("schema should apply");
        seed_two_of_two_file(&conn);
        let result = conn.execute("UPDATE files SET quorum_threshold = 3 WHERE id = 1", []);
        assert!(result.is_err());
    }

    #[test]
    fn lowering_quorum_threshold_is_allowed() {
        let conn = open_in_memory().expect("schema should apply");
        seed_two_of_two_file(&conn);
        let result = conn.execute("UPDATE files SET quorum_threshold = 1 WHERE id = 1", []);
        assert!(result.is_ok());
    }

    #[test]
    fn moving_a_required_share_to_another_file_is_blocked() {
        let conn = open_in_memory().expect("schema should apply");
        seed_two_of_two_file(&conn);
        conn.execute(
            "INSERT INTO files (id, name, encrypted_path, content_hash, quorum_threshold)
             VALUES (2, 'other.txt', '/data/other.txt.enc', 'beefdead', 1)",
            [],
        )
        .expect("seed second file");

        let result = conn.execute(
            "UPDATE file_key_shares SET file_id = 2 WHERE file_id = 1 AND hardware_key_id = 1",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn moving_a_surplus_share_to_another_file_is_allowed() {
        let conn = open_in_memory().expect("schema should apply");
        conn.execute(
            "INSERT INTO hardware_keys (id, label, fingerprint, public_key) VALUES
             (1, 'key-a', 'fp-a', x'01'),
             (2, 'key-b', 'fp-b', x'02')",
            [],
        )
        .expect("seed hardware_keys");
        conn.execute(
            "INSERT INTO files (id, name, encrypted_path, content_hash, quorum_threshold) VALUES
             (1, 'secret.txt', '/data/secret.txt.enc', 'deadbeef', 1),
             (2, 'other.txt', '/data/other.txt.enc', 'beefdead', 1)",
            [],
        )
        .expect("seed files");
        conn.execute(
            "INSERT INTO file_key_shares (file_id, hardware_key_id, wrapped_share) VALUES
             (1, 1, x'aa'),
             (1, 2, x'bb')",
            [],
        )
        .expect("seed file_key_shares");

        // File 1 is 1-of-2, so moving key 1's share to file 2 still leaves
        // file 1 with one share, satisfying its threshold.
        let result = conn.execute(
            "UPDATE file_key_shares SET file_id = 2 WHERE file_id = 1 AND hardware_key_id = 1",
            [],
        );
        assert!(result.is_ok());
    }
}

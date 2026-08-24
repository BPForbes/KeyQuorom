use rusqlite::{Connection, Result};

const SCHEMA: &str = include_str!("schema.sql");

/// Opens (creating if needed) a KeyQuorum SQLite database at `path` and
/// applies the schema. Safe to call repeatedly; every statement is
/// idempotent.
pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
}

/// Opens an in-memory database with the schema applied. Intended for tests.
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    init(&conn)?;
    Ok(conn)
}

fn init(conn: &Connection) -> Result<()> {
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

    /// Seeds a 2-of-2 file: both registered hardware keys are required to
    /// meet the quorum, so neither backing share has any slack.
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
}

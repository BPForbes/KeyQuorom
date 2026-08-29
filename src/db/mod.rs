use rusqlite::{Connection, Result};
use std::time::Duration;

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
    // Block briefly on lock contention instead of failing immediately with
    // SQLITE_BUSY, so concurrent access from multiple connections (e.g. a
    // share redemption race) resolves in commit order rather than erroring.
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.execute_batch(SCHEMA)?;
    migrate(conn)
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.iter().any(|name| name == column))
}

/// `CREATE TABLE IF NOT EXISTS` never adds columns to an already-created
/// table. Databases from before `key_nodes.is_active` must be altered
/// before any SELECT of that column.
fn migrate(conn: &Connection) -> Result<()> {
    // BEGIN IMMEDIATE serializes this check-and-alter against concurrent
    // `open`s so two connections cannot both decide the column is missing.
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = (|| -> Result<()> {
        if table_has_column(conn, "key_nodes", "is_active")? {
            return Ok(());
        }
        conn.execute(
            "ALTER TABLE key_nodes ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            if table_has_column(conn, "key_nodes", "is_active")? {
                return Ok(());
            }
            Err(err)
        }
    }
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
        assert_eq!(table_count, 12);
    }

    #[test]
    fn schema_is_idempotent() {
        let conn = open_in_memory().expect("schema should apply");
        conn.execute_batch(SCHEMA)
            .expect("re-applying schema should not error");
    }

    fn seed_encryption_key(conn: &Connection, id: i64) {
        conn.execute(
            "INSERT INTO hardware_keys (id, label, key_type, fingerprint, public_key)
             VALUES (?1, 'enc-key', 'encryption', ?2, x'01')",
            params![id, format!("fp-enc-{id}")],
        )
        .expect("seed encryption hardware_keys row");
    }

    fn seed_signing_key(conn: &Connection, id: i64) {
        conn.execute(
            "INSERT INTO hardware_keys (id, label, key_type, fingerprint, public_key)
             VALUES (?1, 'sign-key', 'signing', ?2, x'02')",
            params![id, format!("fp-sign-{id}")],
        )
        .expect("seed signing hardware_keys row");
    }

    fn seed_key(conn: &Connection, id: i64) {
        conn.execute(
            "INSERT INTO keys (id, label) VALUES (?1, 'test-key')",
            params![id],
        )
        .expect("seed keys row");
    }

    #[test]
    fn key_node_leaf_backed_by_signing_key_is_blocked() {
        let conn = open_in_memory().expect("schema should apply");
        seed_signing_key(&conn, 1);
        seed_key(&conn, 1);

        let result = conn.execute(
            "INSERT INTO key_nodes (key_id, label, hardware_key_id, wrapped_share)
             VALUES (1, 'leaf', 1, x'aa')",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn key_node_leaf_backed_by_encryption_key_is_allowed() {
        let conn = open_in_memory().expect("schema should apply");
        seed_encryption_key(&conn, 1);
        seed_key(&conn, 1);

        let result = conn.execute(
            "INSERT INTO key_nodes (key_id, label, hardware_key_id, wrapped_share)
             VALUES (1, 'leaf', 1, x'aa')",
            [],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn key_node_leaf_cannot_be_reassigned_to_a_signing_key_via_update() {
        let conn = open_in_memory().expect("schema should apply");
        seed_encryption_key(&conn, 1);
        seed_signing_key(&conn, 2);
        seed_key(&conn, 1);
        conn.execute(
            "INSERT INTO key_nodes (key_id, label, hardware_key_id, wrapped_share)
             VALUES (1, 'leaf', 1, x'aa')",
            [],
        )
        .expect("seed key_nodes leaf");

        let result = conn.execute(
            "UPDATE key_nodes SET hardware_key_id = 2 WHERE key_id = 1 AND label = 'leaf'",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn key_node_rejects_mixed_split_and_leaf_shape() {
        let conn = open_in_memory().expect("schema should apply");
        seed_encryption_key(&conn, 1);
        seed_key(&conn, 1);

        // threshold set alongside hardware_key_id/wrapped_share: neither a
        // clean split node nor a clean leaf.
        let result = conn.execute(
            "INSERT INTO key_nodes (key_id, label, threshold, hardware_key_id, wrapped_share)
             VALUES (1, 'bad', 2, 1, x'aa')",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn key_node_rejects_neither_split_nor_leaf_shape() {
        let conn = open_in_memory().expect("schema should apply");
        seed_key(&conn, 1);

        let result = conn.execute(
            "INSERT INTO key_nodes (key_id, label) VALUES (1, 'empty')",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn key_node_split_node_is_allowed() {
        let conn = open_in_memory().expect("schema should apply");
        seed_key(&conn, 1);

        let result = conn.execute(
            "INSERT INTO key_nodes (key_id, label, threshold) VALUES (1, 'split', 2)",
            [],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn files_key_id_must_reference_an_existing_key() {
        let conn = open_in_memory().expect("schema should apply");
        let result = conn.execute(
            "INSERT INTO files (name, encrypted_path, key_id, nonce)
             VALUES ('secret.txt', '/data/secret.txt.enc', 999, x'00')",
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn opening_a_legacy_key_nodes_table_adds_is_active() {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE key_nodes (
                id                INTEGER PRIMARY KEY,
                key_id            INTEGER NOT NULL,
                parent_id         INTEGER,
                label             TEXT NOT NULL,
                threshold         INTEGER,
                hardware_key_id   INTEGER,
                wrapped_share     BLOB
             );
             CREATE TABLE keys (
                id INTEGER PRIMARY KEY,
                label TEXT NOT NULL
             );
             INSERT INTO keys (id, label) VALUES (1, 'legacy');
             INSERT INTO key_nodes (key_id, label, threshold) VALUES (1, 'root', 1);",
        )
        .expect("legacy schema should apply");

        assert!(!table_has_column(&conn, "key_nodes", "is_active").unwrap());
        init(&conn).expect("init should migrate the legacy table");

        let is_active: i64 = conn
            .query_row(
                "SELECT is_active FROM key_nodes WHERE label = 'root'",
                [],
                |row| row.get(0),
            )
            .expect("is_active should be readable after migrate");
        assert_eq!(is_active, 1);
        init(&conn).expect("a second init must be idempotent");
    }

    #[test]
    fn files_key_id_referencing_an_existing_key_is_allowed() {
        let conn = open_in_memory().expect("schema should apply");
        seed_key(&conn, 1);

        let result = conn.execute(
            "INSERT INTO files (name, encrypted_path, key_id, nonce)
             VALUES ('secret.txt', '/data/secret.txt.enc', 1, x'00')",
            [],
        );
        assert!(result.is_ok());
    }
}

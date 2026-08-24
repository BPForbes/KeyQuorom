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
        assert_eq!(table_count, 4);
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
}

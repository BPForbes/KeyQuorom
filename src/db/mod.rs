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
mod tests;

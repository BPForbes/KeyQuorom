use rusqlite::{Connection, OptionalExtension, Result};
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

fn table_sql(conn: &Connection, table: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        rusqlite::params![table],
        |row| row.get(0),
    )
    .optional()
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
        if !table_has_column(conn, "key_nodes", "is_active")? {
            conn.execute(
                "ALTER TABLE key_nodes ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        rebuild_key_nodes_if_share_required(conn)?;
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

/// Older databases required every leaf to store `wrapped_share`. Personal
/// stores now keep topology-only leaves (peers/siblings) without a share.
fn rebuild_key_nodes_if_share_required(conn: &Connection) -> Result<()> {
    let Some(sql) = table_sql(conn, "key_nodes")? else {
        return Ok(());
    };
    if !sql.contains("wrapped_share IS NOT NULL") {
        return Ok(());
    }
    conn.pragma_update(None, "foreign_keys", false)?;
    conn.execute_batch(
        "CREATE TABLE key_nodes_new (
            id                INTEGER PRIMARY KEY,
            key_id            INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
            parent_id         INTEGER REFERENCES key_nodes_new(id) ON DELETE CASCADE,
            label             TEXT NOT NULL,
            threshold         INTEGER CHECK (threshold IS NULL OR threshold > 0),
            hardware_key_id   INTEGER REFERENCES hardware_keys(id) ON DELETE RESTRICT,
            wrapped_share     BLOB,
            is_active         INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            CHECK (
                (threshold IS NOT NULL AND hardware_key_id IS NULL AND wrapped_share IS NULL)
                OR (threshold IS NULL AND hardware_key_id IS NOT NULL)
            )
        );
        INSERT INTO key_nodes_new
            (id, key_id, parent_id, label, threshold, hardware_key_id, wrapped_share, is_active)
            SELECT id, key_id, parent_id, label, threshold, hardware_key_id, wrapped_share, is_active
            FROM key_nodes;
        DROP TABLE key_nodes;
        ALTER TABLE key_nodes_new RENAME TO key_nodes;
        CREATE INDEX IF NOT EXISTS idx_key_nodes_parent ON key_nodes (parent_id);
        CREATE INDEX IF NOT EXISTS idx_key_nodes_key ON key_nodes (key_id);
        CREATE INDEX IF NOT EXISTS idx_key_nodes_hardware_key ON key_nodes (hardware_key_id);",
    )?;
    conn.execute_batch(SCHEMA)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

#[cfg(test)]
mod tests;

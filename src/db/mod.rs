use rusqlite::{Connection, OptionalExtension, Result};
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");

pub mod relay_credential;

/// Opens (creating if needed) a KeyQuorum SQLite database at `path` and
/// applies the schema. Safe to call repeatedly; every statement is
/// idempotent. The file is owner-only (0600) on Unix because this store
/// can hold sealed shares and loaded relay API keys.
pub fn open(path: &str) -> crate::error::Result<Connection> {
    let conn = Connection::open(path)?;
    // Restrict before schema writes so a newly created file is not left
    // world-readable while `init` applies tables. Journal sidecars created
    // during that work are restricted afterward.
    restrict_db_files(path)?;
    init(&conn)?;
    restrict_db_files(path)?;
    Ok(conn)
}

fn restrict_db_files(path: &str) -> crate::error::Result<()> {
    restrict_owner_only(path)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = format!("{path}{suffix}");
        if std::path::Path::new(&sidecar).is_file() {
            restrict_owner_only(&sidecar)?;
        }
    }
    Ok(())
}

fn restrict_owner_only(path: &str) -> crate::error::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        if meta.is_file() {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Run `f` inside `BEGIN IMMEDIATE` so a later failure rolls back earlier
/// writes. Nested calls (already in a transaction) just invoke `f`.
pub(crate) fn with_immediate_transaction<T>(
    conn: &Connection,
    f: impl FnOnce() -> crate::error::Result<T>,
) -> crate::error::Result<T> {
    if !conn.is_autocommit() {
        return f();
    }
    conn.execute("BEGIN IMMEDIATE", [])?;
    match f() {
        Ok(value) => {
            if let Err(err) = conn.execute("COMMIT", []) {
                let _ = conn.execute("ROLLBACK", []);
                return Err(err.into());
            }
            Ok(value)
        }
        Err(err) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(err)
        }
    }
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
    // SQLite ignores `PRAGMA foreign_keys` inside a transaction, so turn
    // enforcement off first. `rebuild_key_nodes_if_share_required` drops
    // and recreates `key_nodes`; with FKs still on, that would cascade
    // through `key_node_bridges` and `key_node_links`.
    conn.pragma_update(None, "foreign_keys", false)?;
    let result = (|| -> Result<()> {
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
                let share_required = table_sql(conn, "key_nodes")?
                    .is_some_and(|sql| sql.contains("wrapped_share IS NOT NULL"));
                if table_has_column(conn, "key_nodes", "is_active")? && !share_required {
                    return Ok(());
                }
                Err(err)
            }
        }
    })();
    conn.pragma_update(None, "foreign_keys", true)?;
    result
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
    // Copy dependent rows first. `DROP TABLE key_nodes` still cascades when
    // foreign keys are on; the copies survive that wipe and are restored
    // after the rebuilt table exists. TEMP tables live on this connection
    // only, so a crashed migrate cannot leave leftover rebuild tables.
    conn.execute_batch(
        "DROP TABLE IF EXISTS key_node_bridges_rebuild;
         DROP TABLE IF EXISTS key_node_links_rebuild;
         CREATE TEMP TABLE key_node_bridges_rebuild AS SELECT * FROM key_node_bridges;
         CREATE TEMP TABLE key_node_links_rebuild AS SELECT * FROM key_node_links;
         CREATE TABLE key_nodes_new (
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
        CREATE INDEX IF NOT EXISTS idx_key_nodes_hardware_key ON key_nodes (hardware_key_id);
        DELETE FROM key_node_bridges;
        DELETE FROM key_node_links;
        INSERT INTO key_node_bridges SELECT * FROM key_node_bridges_rebuild;
        INSERT INTO key_node_links SELECT * FROM key_node_links_rebuild;
        DROP TABLE key_node_bridges_rebuild;
        DROP TABLE key_node_links_rebuild;",
    )?;
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

#[cfg(test)]
mod tests;

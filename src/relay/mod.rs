//! Online mailbox for opaque `.kqpb` envelopes, plus the canonical
//! *public* split-tree topology.
//!
//! The relay never unseals envelopes and never holds wrapped shares or
//! private keys. Full public-tree context is stored as JSON documents.
//! Pushing envelopes merges the sender's public topology into those
//! documents; pull returns a sliced copy for the recipient fingerprint
//! that a personal SQLite store translates.

mod api_key;
mod client;
mod mailbox;
mod org_tree;
#[cfg(feature = "provider")]
mod server;

pub use api_key::{
    authenticate, authenticate_licensee, authorize_licensee_or_bootstrap,
    bootstrap_licensee_if_empty, check_hash, check_token, create as create_api_key,
    create_licensee_issuer_if_empty, hash_bearer, licensee_issuer_exists, list as list_api_keys,
    record_provider_auth_event, revoke as revoke_api_key, rotate as rotate_api_key, ApiKeyInfo,
    ApiKeyScope, AuthedKey, CreatedApiKey, CreatedLicensee, KeyCheck, NewApiKey,
};
pub use client::{
    authenticate_provider, check_key, check_key_hash, fetch_tree_context, publish_tree,
    pull as pull_inbox, push as push_inbox, push_with_trees as push_inbox_with_trees,
    push_with_trees_until as push_inbox_with_trees_until, validate_relay_url, InboxAccepted,
    InboxEnvelope, InboxList, InboxPush, KeyCheckRequest, KeyCheckResponse,
    ProviderIdentityRequest, ProviderIdentityResponse,
};
pub use mailbox::{
    list_after, purge_expired as purge_expired_envelopes, store, store_until, MailboxPage,
    StoredEnvelope, DEFAULT_INBOX_PAGE, MAX_INBOX_PAGE,
};
pub use org_tree::{
    context_for_fingerprint, contexts_for_fingerprint, get_public_tree, list_public_trees,
    merge_public_tree, put_public_tree, slices_for_fingerprint,
};
#[cfg(feature = "provider")]
pub use server::{router, AppState, ProviderIdentity, MAX_ENVELOPE_BYTES};

use crate::error::{Error, Result};
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");

const ORGANIZATION_TABLES: [&str; 4] = [
    "hardware_keys",
    "private_bridges",
    "credentials",
    "key_nodes",
];

/// Opens (creating if needed) the relay's own SQLite database and applies
/// the mailbox + public-tree schema. This is not a personal organization
/// database and must not receive wrapped shares or private keys.
///
/// An existing organization store is refused before any relay tables are
/// created, so a `--db` mix-up cannot merge the two schemas.
pub fn open(path: &str) -> Result<Connection> {
    let path_ref = Path::new(path);
    if path_ref.is_file() {
        let meta = std::fs::metadata(path_ref)?;
        if meta.len() > 0 {
            let probe = Connection::open(path)?;
            if looks_like_organization_database(&probe)? {
                return Err(Error::OrganizationDatabase);
            }
        }
    }
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
}

fn looks_like_organization_database(conn: &Connection) -> Result<bool> {
    for table in ORGANIZATION_TABLES {
        let found: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if found > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Opens an in-memory relay database. Intended for tests.
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    init(&conn)?;
    Ok(conn)
}

fn init(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.execute_batch(SCHEMA)?;
    migrate(conn)
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.iter().any(|name| name == column))
}

/// `CREATE TABLE IF NOT EXISTS` never adds columns to an already-created
/// table. Mailboxes from before envelope TTL need `expires_at`.
fn migrate(conn: &Connection) -> Result<()> {
    if !table_has_column(conn, "mailbox", "expires_at")? {
        conn.execute("ALTER TABLE mailbox ADD COLUMN expires_at TEXT", [])?;
    }
    Ok(())
}

#[cfg(test)]
mod test_helpers;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

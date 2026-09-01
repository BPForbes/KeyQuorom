//! Online mailbox for opaque `.kqpb` envelopes.
//!
//! The relay is transport only: it stores and forwards sealed packages
//! indexed by the recipient X25519 fingerprint from the outer header. It
//! never unseals envelopes and never holds organization SQLite data or
//! private keys.

mod api_key;
mod client;
mod mailbox;
mod server;

pub use api_key::{
    authenticate, bootstrap_admin_if_empty, create as create_api_key, list as list_api_keys,
    revoke as revoke_api_key, rotate as rotate_api_key, ApiKeyInfo, ApiKeyScope, AuthedKey,
    CreatedApiKey, NewApiKey,
};
pub use client::{pull as pull_inbox, push as push_inbox, InboxAccepted, InboxEnvelope, InboxList};
pub use mailbox::{list_after, store, StoredEnvelope};
pub use server::{router, AppState, MAX_ENVELOPE_BYTES};

use crate::error::Result;
use rusqlite::Connection;
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");

/// Opens (creating if needed) the relay's own SQLite database and applies
/// the mailbox schema. This is not the organization database.
pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    init(&conn)?;
    Ok(conn)
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
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

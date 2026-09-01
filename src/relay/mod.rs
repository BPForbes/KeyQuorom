//! Online mailbox for opaque `.kqpb` envelopes, plus the canonical
//! *public* split-tree topology.
//!
//! The relay never unseals envelopes and never holds wrapped shares or
//! private keys. Full public-tree context is stored as JSON documents.
//! Pushing envelopes updates those documents; pull returns a sliced copy
//! for the recipient fingerprint that a personal SQLite store translates.

mod api_key;
mod client;
mod mailbox;
mod org_tree;
mod server;

pub use api_key::{
    authenticate, bootstrap_admin_if_empty, check_hash, check_token, create as create_api_key,
    hash_bearer, list as list_api_keys, revoke as revoke_api_key, rotate as rotate_api_key,
    ApiKeyInfo, ApiKeyScope, AuthedKey, CreatedApiKey, KeyCheck, NewApiKey,
};
pub use client::{
    check_key, check_key_hash, fetch_tree_context, publish_tree, pull as pull_inbox,
    push as push_inbox, push_with_trees as push_inbox_with_trees, InboxAccepted, InboxEnvelope,
    InboxList, InboxPush, KeyCheckRequest, KeyCheckResponse,
};
pub use mailbox::{list_after, store, StoredEnvelope};
pub use org_tree::{
    context_for_fingerprint, contexts_for_fingerprint, get_public_tree, list_public_trees,
    put_public_tree, slices_for_fingerprint,
};
pub use server::{router, AppState, MAX_ENVELOPE_BYTES};

use crate::error::Result;
use rusqlite::Connection;
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");

/// Opens (creating if needed) the relay's own SQLite database and applies
/// the mailbox + public-tree schema. This is not a personal organization
/// database and must not receive wrapped shares or private keys.
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

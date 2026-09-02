//! Opaque envelope store. The only header field used for routing is the
//! recipient X25519 public key; the sealed payload is stored verbatim.

use crate::error::{Error, Result};
use crate::keys;
use crate::private_bridge;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

/// Default `GET /inbox` page when `limit` is omitted.
pub const DEFAULT_INBOX_PAGE: i64 = 100;
/// Hard cap on a single inbox read. Keep in sync with `Error::InvalidInboxPage`.
pub const MAX_INBOX_PAGE: i64 = 500;

#[derive(Clone, Debug)]
pub struct StoredEnvelope {
    pub id: i64,
    pub recipient_fingerprint: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MailboxPage {
    pub envelopes: Vec<StoredEnvelope>,
    pub next_after: Option<i64>,
}

pub fn store(conn: &Connection, envelope: &[u8]) -> Result<(i64, String, bool)> {
    store_until(conn, envelope, None)
}

/// Store an opaque envelope, optionally with a UTC expiry
/// (`YYYY-MM-DD HH:MM:00`). The host scan and inbox pull drop expired rows.
pub fn store_until(
    conn: &Connection,
    envelope: &[u8],
    expires_at: Option<&str>,
) -> Result<(i64, String, bool)> {
    let recipient_public_key = private_bridge::routing_public_key(envelope)?;
    let fingerprint = keys::fingerprint(&recipient_public_key);
    let content_hash = hex::encode(Sha256::digest(envelope));

    conn.execute(
        "INSERT OR IGNORE INTO mailbox
            (recipient_fingerprint, envelope, content_hash, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![fingerprint, envelope, content_hash, expires_at],
    )?;

    if conn.changes() == 1 {
        Ok((conn.last_insert_rowid(), fingerprint, false))
    } else {
        let id: i64 = conn.query_row(
            "SELECT id FROM mailbox
             WHERE recipient_fingerprint = ?1 AND content_hash = ?2",
            params![fingerprint, content_hash],
            |row| row.get(0),
        )?;
        Ok((id, fingerprint, true))
    }
}

pub fn list_after(
    conn: &Connection,
    fingerprint: &str,
    after: Option<i64>,
    limit: Option<i64>,
) -> Result<MailboxPage> {
    let page = match limit {
        None => DEFAULT_INBOX_PAGE,
        Some(n) if (1..=MAX_INBOX_PAGE).contains(&n) => n,
        Some(_) => return Err(Error::InvalidInboxPage),
    };
    let after = after.unwrap_or(0);
    let fetch = page.saturating_add(1);
    purge_expired(conn)?;
    let mut stmt = conn.prepare(
        "SELECT id, recipient_fingerprint, envelope
         FROM mailbox
         WHERE recipient_fingerprint = ?1 AND id > ?2
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
         ORDER BY id ASC
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![fingerprint, after, fetch], |row| {
        Ok(StoredEnvelope {
            id: row.get(0)?,
            recipient_fingerprint: row.get(1)?,
            bytes: row.get(2)?,
        })
    })?;
    let mut envelopes = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let next_after = if envelopes.len() > page as usize {
        envelopes.pop();
        envelopes.last().map(|item| item.id)
    } else {
        None
    };
    Ok(MailboxPage {
        envelopes,
        next_after,
    })
}

/// Deletes mailbox rows whose date-based TTL has passed. The sealed
/// envelope bytes live in this table, so the DELETE is what removes them
/// from disk (the SQLite file).
pub fn purge_expired(conn: &Connection) -> Result<u64> {
    conn.execute(
        "DELETE FROM mailbox
         WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')",
        [],
    )?;
    Ok(conn.changes())
}

//! Personal-store copy of a relay API key.
//!
//! The relay keeps only `hex(SHA-256(raw))`. This module stores that hash
//! (used for `POST /keycheck`) and the bearer sealed with a random
//! AES-256-GCM wrapping key so later commands can authenticate without
//! re-entering the token. The wrapping key lives in this same owner-only
//! SQLite file — it is not a second password, it keeps the bearer off
//! casual SQL dumps of `key_hash` alone.

use crate::crypto::{self, KEY_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Clone, Debug)]
pub struct StoredRelayKey {
    pub relay_url: String,
    pub scope: String,
    pub key_hash: String,
    pub token: String,
    pub remote_id: Option<i64>,
    pub label: Option<String>,
}

pub fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

pub fn save(conn: &Connection, cred: &StoredRelayKey) -> Result<()> {
    let url = normalize_url(&cred.relay_url);
    let wrap_key = crypto::random_key();
    let wrap_nonce = crypto::random_nonce();
    let wrapped_token = crypto::encrypt(&wrap_key, &wrap_nonce, cred.token.as_bytes());
    conn.execute(
        "INSERT INTO relay_credentials
            (relay_url, scope, key_hash, wrap_key, wrap_nonce, wrapped_token,
             remote_id, label, last_checked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
         ON CONFLICT(relay_url, scope) DO UPDATE SET
            key_hash = excluded.key_hash,
            wrap_key = excluded.wrap_key,
            wrap_nonce = excluded.wrap_nonce,
            wrapped_token = excluded.wrapped_token,
            remote_id = excluded.remote_id,
            label = excluded.label,
            stored_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
            last_checked_at = excluded.last_checked_at",
        params![
            url,
            cred.scope,
            cred.key_hash,
            wrap_key.as_slice(),
            wrap_nonce.as_slice(),
            wrapped_token,
            cred.remote_id,
            cred.label
        ],
    )?;
    Ok(())
}

struct SealedRelayRow {
    relay_url: String,
    scope: String,
    key_hash: String,
    wrap_key: Vec<u8>,
    wrap_nonce: Vec<u8>,
    wrapped_token: Vec<u8>,
    remote_id: Option<i64>,
    label: Option<String>,
}

fn row_to_sealed(row: &rusqlite::Row<'_>) -> rusqlite::Result<SealedRelayRow> {
    Ok(SealedRelayRow {
        relay_url: row.get(0)?,
        scope: row.get(1)?,
        key_hash: row.get(2)?,
        wrap_key: row.get(3)?,
        wrap_nonce: row.get(4)?,
        wrapped_token: row.get(5)?,
        remote_id: row.get(6)?,
        label: row.get(7)?,
    })
}

fn unwrap_row(row: SealedRelayRow) -> Result<StoredRelayKey> {
    let wrap_key: [u8; KEY_LEN] = row
        .wrap_key
        .try_into()
        .map_err(|_| Error::IntegrityCheckFailed)?;
    let wrap_nonce: [u8; NONCE_LEN] = row
        .wrap_nonce
        .try_into()
        .map_err(|_| Error::IntegrityCheckFailed)?;
    let token = crypto::decrypt(&wrap_key, &wrap_nonce, &row.wrapped_token)
        .map_err(|_| Error::IntegrityCheckFailed)?;
    let token = String::from_utf8(token).map_err(|_| Error::IntegrityCheckFailed)?;
    Ok(StoredRelayKey {
        relay_url: row.relay_url,
        scope: row.scope,
        key_hash: row.key_hash,
        token,
        remote_id: row.remote_id,
        label: row.label,
    })
}

pub fn get(conn: &Connection, relay_url: &str, scope: &str) -> Result<Option<StoredRelayKey>> {
    let url = normalize_url(relay_url);
    let row = conn
        .query_row(
            "SELECT relay_url, scope, key_hash, wrap_key, wrap_nonce, wrapped_token,
                    remote_id, label
             FROM relay_credentials WHERE relay_url = ?1 AND scope = ?2",
            params![url, scope],
            row_to_sealed,
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some(row) => Ok(Some(unwrap_row(row)?)),
    }
}

pub fn get_for_scope(conn: &Connection, scope: &str) -> Result<Vec<StoredRelayKey>> {
    let mut stmt = conn.prepare(
        "SELECT relay_url, scope, key_hash, wrap_key, wrap_nonce, wrapped_token,
                remote_id, label
         FROM relay_credentials WHERE scope = ?1",
    )?;
    let rows = stmt.query_map(params![scope], row_to_sealed)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(unwrap_row(row?)?);
    }
    Ok(out)
}

pub fn touch_checked(conn: &Connection, relay_url: &str, scope: &str) -> Result<()> {
    conn.execute(
        "UPDATE relay_credentials
         SET last_checked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE relay_url = ?1 AND scope = ?2",
        params![normalize_url(relay_url), scope],
    )?;
    Ok(())
}

pub fn delete(conn: &Connection, relay_url: &str, scope: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM relay_credentials WHERE relay_url = ?1 AND scope = ?2",
        params![normalize_url(relay_url), scope],
    )?;
    Ok(())
}

//! Time-limited, revocable share links for vault credentials and
//! password-locked files. File shares may use a relative `--ttl-seconds`
//! lifetime or a date-based UTC `--expires`; the latter stamps the file
//! itself, and a late redeem or unlock deletes the ciphertext from disk.
//!
//! A share's bearer token is only ever returned to the caller once, at
//! creation time; the database stores just a SHA-256 hash of it, looked up
//! the same way on redemption, so a leaked database dump doesn't hand out
//! usable tokens.

use crate::error::{Error, Result};
use crate::locked_files;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const TOKEN_LEN: usize = 32;

pub struct Share {
    pub id: i64,
    pub token: String,
    pub expires_at: String,
}

fn generate_token() -> (String, String) {
    let mut raw = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = hex::encode(Sha256::digest(raw));
    (token, token_hash)
}

fn hash_token(token: &str) -> Result<String> {
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::InvalidShareToken)?;
    Ok(hex::encode(Sha256::digest(raw)))
}

/// Resolves a bearer token to its share row's own id, without consuming a
/// use — needed so a PIN-protected share (see `pin.rs`) can be checked
/// *before* redemption consumes what might be its only remaining use.
fn share_id_for_token(conn: &Connection, table: &str, token: &str) -> Result<i64> {
    let token_hash = hash_token(token)?;
    conn.query_row(
        &format!("SELECT id FROM {table} WHERE token_hash = ?1"),
        params![token_hash],
        |row| row.get(0),
    )
    .map_err(|_| Error::InvalidShareToken)
}

pub fn credential_share_id_for_token(conn: &Connection, token: &str) -> Result<i64> {
    share_id_for_token(conn, "credential_shares", token)
}

pub fn file_share_id_for_token(conn: &Connection, token: &str) -> Result<i64> {
    share_id_for_token(conn, "file_shares", token)
}

fn create_share(
    conn: &Connection,
    table: &str,
    id_column: &str,
    resource_id: i64,
    ttl_seconds: Option<i64>,
    expires_at: Option<&str>,
    max_uses: Option<i64>,
) -> Result<Share> {
    let (token, token_hash) = generate_token();

    match (ttl_seconds, expires_at) {
        (Some(ttl_seconds), None) => {
            conn.execute(
                &format!(
                    "INSERT INTO {table} ({id_column}, token_hash, expires_at, max_uses)
                     VALUES (?1, ?2, datetime('now', ?3), ?4)"
                ),
                params![
                    resource_id,
                    token_hash,
                    format!("{ttl_seconds:+} seconds"),
                    max_uses
                ],
            )?;
        }
        (None, Some(expires_at)) => {
            conn.execute(
                &format!(
                    "INSERT INTO {table} ({id_column}, token_hash, expires_at, max_uses)
                     VALUES (?1, ?2, ?3, ?4)"
                ),
                params![resource_id, token_hash, expires_at, max_uses],
            )?;
        }
        _ => return Err(Error::InvalidExpiresAt),
    }

    let id = conn.last_insert_rowid();
    let expires_at: String = conn.query_row(
        &format!("SELECT expires_at FROM {table} WHERE id = ?1"),
        params![id],
        |row| row.get(0),
    )?;

    Ok(Share {
        id,
        token,
        expires_at,
    })
}

fn redeem_share(conn: &Connection, table: &str, id_column: &str, token: &str) -> Result<i64> {
    let token_hash = hash_token(token)?;

    // Eligibility check and use_count increment happen in one statement, so
    // two concurrent redemptions of a max_uses = 1 share can't both read
    // "not yet exhausted" before either writes — only one UPDATE can ever
    // match and claim the row.
    let claimed = conn.execute(
        &format!(
            "UPDATE {table}
             SET use_count = use_count + 1
             WHERE token_hash = ?1
               AND revoked_at IS NULL
               AND datetime(expires_at) > datetime('now')
               AND (max_uses IS NULL OR use_count < max_uses)"
        ),
        params![token_hash],
    )?;

    if claimed == 1 {
        let resource_id: i64 = conn.query_row(
            &format!("SELECT {id_column} FROM {table} WHERE token_hash = ?1"),
            params![token_hash],
            |row| row.get(0),
        )?;
        return Ok(resource_id);
    }

    // The update above is what actually enforces access control; this is a
    // read-only follow-up purely to report why it didn't match.
    let row: Option<(bool, bool, Option<i64>, i64)> = conn
        .query_row(
            &format!(
                "SELECT revoked_at IS NOT NULL,
                        datetime(expires_at) <= datetime('now'),
                        max_uses, use_count
                 FROM {table} WHERE token_hash = ?1"
            ),
            params![token_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;

    let Some((revoked, expired, max_uses, use_count)) = row else {
        return Err(Error::InvalidShareToken);
    };

    if revoked {
        Err(Error::ShareRevoked)
    } else if expired {
        Err(Error::ShareExpired)
    } else if max_uses.is_some_and(|limit| use_count >= limit) {
        Err(Error::ShareExhausted)
    } else {
        // State moved between the update and this read (another caller
        // claimed the share in between); it's exhausted from this caller's
        // point of view either way.
        Err(Error::ShareExhausted)
    }
}

fn revoke_share(conn: &Connection, table: &str, share_id: i64) -> Result<()> {
    conn.execute(
        &format!("UPDATE {table} SET revoked_at = datetime('now') WHERE id = ?1"),
        params![share_id],
    )?;
    Ok(())
}

pub fn create_credential_share(
    conn: &Connection,
    credential_id: i64,
    ttl_seconds: i64,
    max_uses: Option<i64>,
) -> Result<Share> {
    create_share(
        conn,
        "credential_shares",
        "credential_id",
        credential_id,
        Some(ttl_seconds),
        None,
        max_uses,
    )
}

pub fn redeem_credential_share(conn: &Connection, token: &str) -> Result<i64> {
    redeem_share(conn, "credential_shares", "credential_id", token)
}

pub fn revoke_credential_share(conn: &Connection, share_id: i64) -> Result<()> {
    revoke_share(conn, "credential_shares", share_id)
}

pub fn create_file_share(
    conn: &Connection,
    file_id: i64,
    ttl_seconds: i64,
    max_uses: Option<i64>,
) -> Result<Share> {
    create_share(
        conn,
        "file_shares",
        "file_id",
        file_id,
        Some(ttl_seconds),
        None,
        max_uses,
    )
}

/// Date-based file share: the file itself expires at `expires_at` (UTC
/// `YYYY-MM-DD HH:MM:00`). A late redeem or unlock deletes the ciphertext.
pub fn create_file_share_until(
    conn: &Connection,
    file_id: i64,
    expires_at: &str,
    max_uses: Option<i64>,
) -> Result<Share> {
    locked_files::set_expires_at(conn, file_id, expires_at)?;
    create_share(
        conn,
        "file_shares",
        "file_id",
        file_id,
        None,
        Some(expires_at),
        max_uses,
    )
}

/// Drops an expired date-based TTL file (ciphertext + row) when the share
/// token resolves to one. Unknown tokens are left for redemption to reject.
pub fn purge_expired_file_share(conn: &Connection, token: &str) -> Result<()> {
    let token_hash = hash_token(token)?;
    let file_id: Option<i64> = conn
        .query_row(
            "SELECT file_id FROM file_shares WHERE token_hash = ?1",
            params![token_hash],
            |row| row.get(0),
        )
        .optional()?;
    let Some(file_id) = file_id else {
        return Ok(());
    };
    locked_files::purge_if_expired(conn, file_id)
}

pub fn redeem_file_share(conn: &Connection, token: &str) -> Result<i64> {
    purge_expired_file_share(conn, token)?;
    redeem_share(conn, "file_shares", "file_id", token)
}

pub fn revoke_file_share(conn: &Connection, share_id: i64) -> Result<()> {
    revoke_share(conn, "file_shares", share_id)
}

#[cfg(test)]
#[path = "sharing/tests.rs"]
mod tests;

//! Time-limited, revocable share links for vault credentials and
//! password-locked files.
//!
//! A share's bearer token is only ever returned to the caller once, at
//! creation time; the database stores just a SHA-256 hash of it, looked up
//! the same way on redemption, so a leaked database dump doesn't hand out
//! usable tokens.

use crate::error::{Error, Result};
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

fn create_share(
    conn: &Connection,
    table: &str,
    id_column: &str,
    resource_id: i64,
    ttl_seconds: i64,
    max_uses: Option<i64>,
) -> Result<Share> {
    let (token, token_hash) = generate_token();

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

    let row: Option<(i64, i64, bool, bool, Option<i64>, i64)> = conn
        .query_row(
            &format!(
                "SELECT id, {id_column},
                        datetime(expires_at) <= datetime('now'),
                        revoked_at IS NOT NULL,
                        max_uses, use_count
                 FROM {table} WHERE token_hash = ?1"
            ),
            params![token_hash],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;

    let (share_id, resource_id, expired, revoked, max_uses, use_count) =
        row.ok_or(Error::InvalidShareToken)?;

    if revoked {
        return Err(Error::ShareRevoked);
    }
    if expired {
        return Err(Error::ShareExpired);
    }
    if let Some(limit) = max_uses {
        if use_count >= limit {
            return Err(Error::ShareExhausted);
        }
    }

    conn.execute(
        &format!("UPDATE {table} SET use_count = use_count + 1 WHERE id = ?1"),
        params![share_id],
    )?;

    Ok(resource_id)
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
        ttl_seconds,
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
        ttl_seconds,
        max_uses,
    )
}

pub fn redeem_file_share(conn: &Connection, token: &str) -> Result<i64> {
    redeem_share(conn, "file_shares", "file_id", token)
}

pub fn revoke_file_share(conn: &Connection, share_id: i64) -> Result<()> {
    revoke_share(conn, "file_shares", share_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::vault;

    fn seed_credential(conn: &Connection) -> i64 {
        vault::add_credential(conn, "Email", None, "s3cr3t", "master-pw")
            .expect("add_credential should succeed")
    }

    #[test]
    fn redeem_immediately_after_create_succeeds() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id = seed_credential(&conn);

        let share = create_credential_share(&conn, credential_id, 3600, None)
            .expect("create_credential_share should succeed");
        let resolved = redeem_credential_share(&conn, &share.token)
            .expect("redeem_credential_share should succeed");

        assert_eq!(resolved, credential_id);
    }

    #[test]
    fn redeem_rejects_unknown_token() {
        let conn = db::open_in_memory().expect("schema should apply");
        let result = redeem_credential_share(&conn, "not-a-real-token");
        assert!(matches!(result, Err(Error::InvalidShareToken)));
    }

    #[test]
    fn redeem_rejects_expired_share() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id = seed_credential(&conn);

        let share = create_credential_share(&conn, credential_id, -1, None)
            .expect("create_credential_share should succeed");
        let result = redeem_credential_share(&conn, &share.token);

        assert!(matches!(result, Err(Error::ShareExpired)));
    }

    #[test]
    fn redeem_rejects_revoked_share() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id = seed_credential(&conn);

        let share = create_credential_share(&conn, credential_id, 3600, None)
            .expect("create_credential_share should succeed");
        revoke_credential_share(&conn, share.id).expect("revoke_credential_share should succeed");
        let result = redeem_credential_share(&conn, &share.token);

        assert!(matches!(result, Err(Error::ShareRevoked)));
    }

    #[test]
    fn redeem_enforces_max_uses() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id = seed_credential(&conn);

        let share = create_credential_share(&conn, credential_id, 3600, Some(1))
            .expect("create_credential_share should succeed");

        redeem_credential_share(&conn, &share.token).expect("first redemption should succeed");
        let second = redeem_credential_share(&conn, &share.token);

        assert!(matches!(second, Err(Error::ShareExhausted)));
    }
}

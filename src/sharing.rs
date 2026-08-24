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

/// Generates a URL-safe bearer token and its SHA-256 hash.
///
/// # Examples
///
/// ```
/// let (token, token_hash) = generate_token();
/// assert!(!token.is_empty());
/// assert_eq!(token_hash.len(), 64);
/// ```
fn generate_token() -> (String, String) {
    let mut raw = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = hex::encode(Sha256::digest(raw));
    (token, token_hash)
}

/// Hashes a URL-safe, unpadded Base64-encoded share token with SHA-256.
///
/// # Errors
///
/// Returns `Error::InvalidShareToken` when `token` is not valid URL-safe,
/// unpadded Base64.
///
/// # Examples
///
/// ```
/// let hash = hash_token("AQ").unwrap();
/// assert_eq!(hash.len(), 64);
/// ```
fn hash_token(token: &str) -> Result<String> {
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| Error::InvalidShareToken)?;
    Ok(hex::encode(Sha256::digest(raw)))
}

/// Creates a time-limited share for a resource.
///
/// The generated bearer token is included in the returned share and should be
/// provided to the recipient.
///
/// # Examples
///
/// ```
/// conn.execute_batch(
///     "CREATE TABLE shares (
///         id INTEGER PRIMARY KEY,
///         resource_id INTEGER NOT NULL,
///         token_hash TEXT NOT NULL,
///         expires_at TEXT NOT NULL,
///         max_uses INTEGER
///     )",
/// )?;
///
/// let share = create_share(&conn, "shares", "resource_id", 42, 3600, Some(1))?;
/// assert_eq!(share.id, 1);
/// assert!(!share.token.is_empty());
/// # Ok::<(), rusqlite::Error>(())
/// ```
///
/// # Parameters
///
/// * `table` - The share table into which the record is inserted.
/// * `id_column` - The column containing the shared resource identifier.
/// * `resource_id` - The identifier of the resource being shared.
/// * `ttl_seconds` - The number of seconds until the share expires.
/// * `max_uses` - The maximum number of redemptions, or unlimited when `None`.
///
/// # Returns
///
/// The created share, including its bearer token and expiration timestamp.
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

/// Redeems an eligible share token and returns the associated resource ID.
///
/// A share can be redeemed only while it is active, unexpired, and within its
/// usage limit. Each successful redemption consumes one permitted use.
///
/// # Examples
///
/// ```
/// # use rusqlite::Connection;
/// # let conn = Connection::open_in_memory().unwrap();
/// # conn.execute(
/// #     "CREATE TABLE shares (
/// #          resource_id INTEGER NOT NULL,
/// #          token_hash TEXT NOT NULL,
/// #          revoked_at TEXT,
/// #          expires_at TEXT NOT NULL,
/// #          max_uses INTEGER,
/// #          use_count INTEGER NOT NULL
/// #      )",
/// #     [],
/// # ).unwrap();
/// # let token = "example-token";
/// # let hash = hash_token(token).unwrap();
/// # conn.execute(
/// #     "INSERT INTO shares
/// #      (resource_id, token_hash, expires_at, use_count)
/// #      VALUES (42, ?1, datetime('now', '+1 hour'), 0)",
/// #     [&hash],
/// # ).unwrap();
/// let resource_id = redeem_share(&conn, "shares", "resource_id", token).unwrap();
/// assert_eq!(resource_id, 42);
/// ```
///
/// # Errors
///
/// Returns an error when the token is invalid, the share is revoked or
/// expired, or its usage limit has been reached.
fn redeem_share(conn: &Connection, table: &str, id_column: &str, token: &str) -> Result<i64> {
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

/// Revokes a share by recording its revocation time.

///

/// # Parameters

///

/// * `table` - Name of the share table containing the share.

/// * `share_id` - Identifier of the share to revoke.

///

/// # Examples

///

/// ```

/// let conn = rusqlite::Connection::open_in_memory()?;

/// conn.execute(

///     "CREATE TABLE shares (id INTEGER PRIMARY KEY, revoked_at TEXT)",

///     [],

/// )?;

/// conn.execute("INSERT INTO shares (id) VALUES (1)", [])?;

///

/// revoke_share(&conn, "shares", 1)?;

/// # Ok::<(), Box<dyn std::error::Error>>(())

/// ```
fn revoke_share(conn: &Connection, table: &str, share_id: i64) -> Result<()> {
    conn.execute(
        &format!("UPDATE {table} SET revoked_at = datetime('now') WHERE id = ?1"),
        params![share_id],
    )?;
    Ok(())
}

/// Creates a time-limited share link for a credential.
///
/// The returned token is needed to redeem the share and is available only when
/// the share is created. An optional maximum-use limit can restrict the number
/// of successful redemptions.
///
/// # Arguments
///
/// * `credential_id` - The identifier of the credential to share.
/// * `ttl_seconds` - The number of seconds until the share expires.
/// * `max_uses` - The maximum number of successful redemptions, or `None` for
///   unlimited use.
///
/// # Returns
///
/// The newly created share, including its identifier, bearer token, and
/// expiration timestamp.
///
/// # Examples
///
/// ```no_run
/// let conn = rusqlite::Connection::open_in_memory()?;
/// let share = create_credential_share(&conn, 42, 3600, Some(1))?;
/// println!("Share token: {}", share.token);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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

/// Redeems a credential share token and returns the associated credential ID.
///
/// A share can be redeemed only while it is valid, unrevoked, unexpired, and below its usage limit.
///
/// # Examples
///
/// ```no_run
/// # fn example(conn: &rusqlite::Connection, token: &str) -> crate::Result<()> {
/// let credential_id = redeem_credential_share(conn, token)?;
/// # let _ = credential_id;
/// # Ok(())
/// # }
/// ```
///
/// Returns the credential ID associated with the share.
pub fn redeem_credential_share(conn: &Connection, token: &str) -> Result<i64> {
    redeem_share(conn, "credential_shares", "credential_id", token)
}

/// Revokes a credential share so it can no longer be redeemed.
///
/// # Examples
///
/// ```no_run
/// let conn = rusqlite::Connection::open_in_memory().unwrap();
/// revoke_credential_share(&conn, 1).unwrap();
/// ```
pub fn revoke_credential_share(conn: &Connection, share_id: i64) -> Result<()> {
    revoke_share(conn, "credential_shares", share_id)
}

/// Creates a time-limited share link for a file.

///

/// # Parameters

///

/// * `file_id` identifies the file to share.

/// * `ttl_seconds` specifies how long the share remains valid.

/// * `max_uses` optionally limits the number of successful redemptions.

///

/// # Examples

///

/// ```no_run

/// # use rusqlite::Connection;

/// # use crate::sharing::create_file_share;

/// let conn = Connection::open("app.db")?;

/// let share = create_file_share(&conn, 42, 3600, Some(1))?;

/// println!("{}", share.token);

/// # Ok::<(), Box<dyn std::error::Error>>(())

/// ```

///

/// Returns the generated share, including its token and expiration time.
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

/// Redeems a file share token and returns the associated file ID.
///
/// # Examples
///
/// ```no_run
/// use rusqlite::Connection;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let conn = Connection::open("app.db")?;
/// let file_id = redeem_file_share(&conn, token)?;
/// # let _ = file_id;
/// # Ok(())
/// # }
/// ```
///
/// `token` must be an unexpired, unrevoked share token with available uses.
///
/// # Errors
///
/// Returns an error if the token is invalid or the share cannot be redeemed.
pub fn redeem_file_share(conn: &Connection, token: &str) -> Result<i64> {
    redeem_share(conn, "file_shares", "file_id", token)
}

/// Revokes a file share so it can no longer be redeemed.

///

/// # Examples

///

/// ```no_run

/// # use rusqlite::Connection;

/// # let conn = Connection::open_in_memory().unwrap();

/// revoke_file_share(&conn, 1).unwrap();

/// ```
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

    #[test]
    fn concurrent_redemption_allows_exactly_one_success() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().expect("tempdir should be created");
        let db_path = dir
            .path()
            .join("keyquorum.sqlite")
            .to_str()
            .expect("path should be valid UTF-8")
            .to_string();

        let setup_conn = db::open(&db_path).expect("schema should apply");
        let credential_id = seed_credential(&setup_conn);
        let share = create_credential_share(&setup_conn, credential_id, 3600, Some(1))
            .expect("create_credential_share should succeed");
        drop(setup_conn);

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let token = share.token.clone();
                let db_path = db_path.clone();
                thread::spawn(move || {
                    let conn = db::open(&db_path).expect("schema should apply");
                    barrier.wait();
                    redeem_credential_share(&conn, &token)
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread should not panic"))
            .collect();

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let rejections = results
            .iter()
            .filter(|r| matches!(r, Err(Error::ShareExhausted)))
            .count();

        assert_eq!(successes, 1);
        assert_eq!(rejections, 1);
    }
}

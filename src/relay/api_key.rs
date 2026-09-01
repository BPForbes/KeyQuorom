//! API keys for the relay and other KeyQuorum project services.
//!
//! The bearer is returned once at creation; the database stores only
//! `hex(SHA-256(raw))`, matching `sharing.rs`.

use crate::error::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const TOKEN_LEN: usize = 32;
const TOKEN_PREFIX: &str = "kq_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKeyScope {
    InboxPush,
    InboxPull,
    Admin,
}

impl ApiKeyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InboxPush => "inbox.push",
            Self::InboxPull => "inbox.pull",
            Self::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "inbox.push" => Ok(Self::InboxPush),
            "inbox.pull" => Ok(Self::InboxPull),
            "admin" => Ok(Self::Admin),
            _ => Err(Error::InvalidApiKeyRequest),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ApiKeyInfo {
    pub id: i64,
    pub scope: String,
    pub recipient_fingerprint: Option<String>,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CreatedApiKey {
    pub info: ApiKeyInfo,
    pub token: String,
}

#[derive(Clone, Debug)]
pub struct NewApiKey {
    pub scope: ApiKeyScope,
    pub recipient_fingerprint: Option<String>,
    pub label: Option<String>,
    pub ttl_seconds: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct AuthedKey {
    pub id: i64,
    pub scope: ApiKeyScope,
    pub recipient_fingerprint: Option<String>,
}

fn generate_bearer() -> (String, String) {
    let mut raw = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut raw);
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let token_hash = hex::encode(Sha256::digest(raw));
    (token, token_hash)
}

fn hash_bearer(token: &str) -> Result<String> {
    let rest = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(Error::InvalidApiKey)?;
    let raw = URL_SAFE_NO_PAD
        .decode(rest)
        .map_err(|_| Error::InvalidApiKey)?;
    if raw.len() != TOKEN_LEN {
        return Err(Error::InvalidApiKey);
    }
    Ok(hex::encode(Sha256::digest(raw)))
}

fn normalize_fingerprint(fingerprint: &str) -> Result<String> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidApiKeyRequest);
    }
    Ok(fingerprint.to_ascii_lowercase())
}

fn load_info(conn: &Connection, id: i64) -> Result<ApiKeyInfo> {
    conn.query_row(
        "SELECT id, scope, recipient_fingerprint, label, created_at, expires_at,
                revoked_at, last_used_at
         FROM api_keys WHERE id = ?1",
        params![id],
        row_to_info,
    )
    .map_err(|_| Error::ApiKeyNotFound)
}

fn row_to_info(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiKeyInfo> {
    Ok(ApiKeyInfo {
        id: row.get(0)?,
        scope: row.get(1)?,
        recipient_fingerprint: row.get(2)?,
        label: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        revoked_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}

/// Hands out a new bearer once and stores only its hash.
pub fn create(conn: &Connection, new: &NewApiKey) -> Result<CreatedApiKey> {
    let fingerprint = match (new.scope, new.recipient_fingerprint.as_deref()) {
        (ApiKeyScope::InboxPull, Some(fp)) => Some(normalize_fingerprint(fp)?),
        (ApiKeyScope::InboxPull, None) => return Err(Error::InvalidApiKeyRequest),
        (_, Some(_)) => return Err(Error::InvalidApiKeyRequest),
        (_, None) => None,
    };

    let (token, token_hash) = generate_bearer();
    if let Some(ttl) = new.ttl_seconds {
        conn.execute(
            "INSERT INTO api_keys (key_hash, scope, recipient_fingerprint, label, expires_at)
             VALUES (?1, ?2, ?3, ?4, datetime('now', ?5))",
            params![
                token_hash,
                new.scope.as_str(),
                fingerprint,
                new.label,
                format!("{ttl:+} seconds")
            ],
        )?;
    } else {
        conn.execute(
            "INSERT INTO api_keys (key_hash, scope, recipient_fingerprint, label)
             VALUES (?1, ?2, ?3, ?4)",
            params![token_hash, new.scope.as_str(), fingerprint, new.label],
        )?;
    }

    let id = conn.last_insert_rowid();
    Ok(CreatedApiKey {
        info: load_info(conn, id)?,
        token,
    })
}

pub fn list(conn: &Connection) -> Result<Vec<ApiKeyInfo>> {
    let mut stmt = conn.prepare(
        "SELECT id, scope, recipient_fingerprint, label, created_at, expires_at,
                revoked_at, last_used_at
         FROM api_keys ORDER BY id",
    )?;
    let rows = stmt.query_map([], row_to_info)?;
    rows.collect::<rusqlite::Result<_>>().map_err(Error::from)
}

pub fn revoke(conn: &Connection, id: i64) -> Result<()> {
    let n = conn.execute(
        "UPDATE api_keys
         SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1 AND revoked_at IS NULL",
        params![id],
    )?;
    if n == 1 {
        return Ok(());
    }
    let exists: Option<i64> = conn
        .query_row(
            "SELECT id FROM api_keys WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_some() {
        Ok(())
    } else {
        Err(Error::ApiKeyNotFound)
    }
}

/// Inserts a replacement key with the same scope and binding, then revokes the old one.
pub fn rotate(conn: &Connection, id: i64) -> Result<CreatedApiKey> {
    let info = load_info(conn, id)?;
    if info.revoked_at.is_some() {
        return Err(Error::ApiKeyRevoked);
    }
    let scope = ApiKeyScope::parse(&info.scope)?;
    let created = create(
        conn,
        &NewApiKey {
            scope,
            recipient_fingerprint: info.recipient_fingerprint.clone(),
            label: info.label.clone(),
            ttl_seconds: None,
        },
    )?;
    if let Some(expires_at) = &info.expires_at {
        conn.execute(
            "UPDATE api_keys SET expires_at = ?1 WHERE id = ?2",
            params![expires_at, created.info.id],
        )?;
    }
    revoke(conn, id)?;
    Ok(CreatedApiKey {
        info: load_info(conn, created.info.id)?,
        token: created.token,
    })
}

/// Atomic lookup: stamps last-used only when the key is live, unexpired, and in `required`.
pub fn authenticate(conn: &Connection, token: &str, required: ApiKeyScope) -> Result<AuthedKey> {
    let token_hash = hash_bearer(token)?;
    let claimed = conn.execute(
        "UPDATE api_keys
         SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE key_hash = ?1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))
           AND scope = ?2",
        params![token_hash, required.as_str()],
    )?;

    if claimed == 1 {
        let (id, fingerprint): (i64, Option<String>) = conn.query_row(
            "SELECT id, recipient_fingerprint FROM api_keys WHERE key_hash = ?1",
            params![token_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        return Ok(AuthedKey {
            id,
            scope: required,
            recipient_fingerprint: fingerprint,
        });
    }

    let row: Option<(bool, bool, String)> = conn
        .query_row(
            "SELECT revoked_at IS NOT NULL,
                    expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now'),
                    scope
             FROM api_keys WHERE key_hash = ?1",
            params![token_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;

    let Some((revoked, expired, scope)) = row else {
        return Err(Error::InvalidApiKey);
    };
    if revoked {
        Err(Error::ApiKeyRevoked)
    } else if expired {
        Err(Error::ApiKeyExpired)
    } else if scope != required.as_str() {
        Err(Error::ApiKeyScopeDenied)
    } else {
        Err(Error::InvalidApiKey)
    }
}

/// Mints a one-time admin bearer when the table is empty.
pub fn bootstrap_admin_if_empty(conn: &Connection) -> Result<Option<CreatedApiKey>> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM api_keys", [], |row| row.get(0))?;
    if n == 0 {
        Ok(Some(create(
            conn,
            &NewApiKey {
                scope: ApiKeyScope::Admin,
                recipient_fingerprint: None,
                label: Some("bootstrap".to_string()),
                ttl_seconds: None,
            },
        )?))
    } else {
        Ok(None)
    }
}

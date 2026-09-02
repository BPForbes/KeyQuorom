//! Unauthenticated API-key registration.
//!
//! `POST /api/v1/{provider_id}/register` mints a `kq_…` bearer after the
//! caller proves possession of a hardware signing key. The provider id is
//! the group; the hardware public key and `keys::fingerprint` identify
//! who registered and when. The KeyQuorum relay identity key signs that
//! binding. The raw bearer is returned once; only `hex(SHA-256(raw))`
//! is stored.

use super::api_key::{self, ApiKeyScope, NewApiKey};
use crate::error::{Error, Result};
use crate::keys;
use crate::signing;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

const REGISTER_DOMAIN: &[u8] = b"KQ-REGISTER-v1";
const RECEIPT_DOMAIN: &[u8] = b"KQ-REGISTER-RECEIPT-v1";
const SIG_LEN: usize = 64;
const KEY_LEN: usize = 32;

/// Current HTTP version segment (`/api/v1/…`).
pub const API_VERSION: &str = "v1";

/// Body for `POST /api/v1/{provider_id}/register`. No API key.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Hex-encoded 32-byte Ed25519 public key of the hardware token.
    pub public_key: String,
    /// Hex-encoded Ed25519 signature over [`register_preimage`].
    pub signature: String,
    /// `inbox.push` (default) or `inbox.pull`. `admin` is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Minted bearer plus the KeyQuorum-signed registration receipt.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct RegisterResponse {
    /// Raw `kq_…` bearer. Shown once; not stored.
    pub token: String,
    pub id: i64,
    pub scope: String,
    pub provider_id: String,
    pub hardware_fingerprint: String,
    pub hardware_public_key: String,
    pub registered_at: String,
    /// Hex-encoded Ed25519 signature over [`receipt_preimage`].
    pub keyquorum_signature: String,
}

/// One stored registration row. Never includes a bearer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub id: i64,
    pub provider_id: String,
    pub hardware_fingerprint: String,
    pub hardware_public_key: String,
    pub api_key_id: i64,
    pub registered_at: String,
    pub keyquorum_signature: String,
}

fn put_len(hasher: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::InvalidApiKeyRequest)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn require_ascii_id(value: &str) -> Result<()> {
    if value.is_empty() || !value.is_ascii() {
        return Err(Error::InvalidApiKeyRequest);
    }
    Ok(())
}

/// Domain-separated preimage the hardware token must sign.
pub fn register_preimage(provider_id: &str, public_key: &[u8; KEY_LEN]) -> Result<[u8; 32]> {
    require_ascii_id(provider_id)?;
    let mut hasher = Sha256::new();
    hasher.update(REGISTER_DOMAIN);
    put_len(&mut hasher, provider_id.as_bytes())?;
    hasher.update(public_key);
    Ok(hasher.finalize().into())
}

/// Domain-separated preimage the KeyQuorum relay identity key signs.
pub fn receipt_preimage(
    provider_id: &str,
    hardware_public_key: &[u8; KEY_LEN],
    hardware_fingerprint: &str,
    api_key_id: i64,
    key_hash: &str,
    registered_at: &str,
) -> Result<[u8; 32]> {
    require_ascii_id(provider_id)?;
    if hardware_fingerprint.len() != 64
        || !hardware_fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
        || key_hash.len() != 64
        || !key_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || registered_at.is_empty()
        || !registered_at.is_ascii()
    {
        return Err(Error::InvalidApiKeyRequest);
    }
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_DOMAIN);
    put_len(&mut hasher, provider_id.as_bytes())?;
    hasher.update(hardware_public_key);
    put_len(&mut hasher, hardware_fingerprint.as_bytes())?;
    hasher.update(api_key_id.to_be_bytes());
    put_len(&mut hasher, key_hash.as_bytes())?;
    put_len(&mut hasher, registered_at.as_bytes())?;
    Ok(hasher.finalize().into())
}

/// Sign a registration proof with a hardware signing seed.
pub fn sign_register_proof(
    hardware_private_key: &[u8; KEY_LEN],
    provider_id: &str,
) -> Result<([u8; KEY_LEN], [u8; SIG_LEN])> {
    let public = ed25519_dalek::SigningKey::from_bytes(hardware_private_key)
        .verifying_key()
        .to_bytes();
    let signature = signing::sign(
        hardware_private_key,
        &register_preimage(provider_id, &public)?,
    );
    Ok((public, signature))
}

pub fn verify_register_proof(
    provider_id: &str,
    public_key: &[u8; KEY_LEN],
    signature: &[u8; SIG_LEN],
) -> Result<String> {
    signing::verify_signature(
        public_key,
        &register_preimage(provider_id, public_key)?,
        signature,
    )?;
    Ok(keys::fingerprint(public_key))
}

pub fn verify_receipt(
    relay_public_key: &[u8; KEY_LEN],
    receipt: &RegisterResponse,
    key_hash: &str,
    hardware_public_key: &[u8; KEY_LEN],
) -> Result<()> {
    let signature = parse_hex_array::<SIG_LEN>(&receipt.keyquorum_signature)?;
    signing::verify_signature(
        relay_public_key,
        &receipt_preimage(
            &receipt.provider_id,
            hardware_public_key,
            &receipt.hardware_fingerprint,
            receipt.id,
            key_hash,
            &receipt.registered_at,
        )?,
        &signature,
    )
}

fn parse_hex_array<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value.trim()).map_err(|_| Error::InvalidPublicKey)?;
    bytes.try_into().map_err(|_| Error::InvalidPublicKey)
}

fn parse_scope(scope: Option<&str>) -> Result<ApiKeyScope> {
    match scope {
        None | Some("") => Ok(ApiKeyScope::InboxPush),
        Some("inbox.push") => Ok(ApiKeyScope::InboxPush),
        Some("inbox.pull") => Ok(ApiKeyScope::InboxPull),
        Some("admin") => Err(Error::InvalidApiKeyRequest),
        Some(_) => Err(Error::InvalidApiKeyRequest),
    }
}

/// Mint a bearer after a hardware possession proof and record who registered.
///
/// `path_provider_id` must equal this host's certified `expected_provider_id`.
pub fn register(
    conn: &Connection,
    path_provider_id: &str,
    expected_provider_id: &str,
    relay_private_key: &[u8; KEY_LEN],
    request: &RegisterRequest,
) -> Result<RegisterResponse> {
    if path_provider_id != expected_provider_id {
        return Err(Error::UnknownProvider);
    }
    require_ascii_id(path_provider_id)?;
    let public_key = parse_hex_array::<KEY_LEN>(&request.public_key)?;
    let signature = parse_hex_array::<SIG_LEN>(&request.signature)?;
    let fingerprint = verify_register_proof(path_provider_id, &public_key, &signature)?;
    let scope = parse_scope(request.scope.as_deref())?;
    let recipient_fingerprint = match scope {
        ApiKeyScope::InboxPull => Some(fingerprint.clone()),
        ApiKeyScope::InboxPush => None,
        ApiKeyScope::Admin => return Err(Error::InvalidApiKeyRequest),
    };

    crate::db::with_immediate_transaction(conn, || {
        let created = api_key::create(
            conn,
            &NewApiKey {
                scope,
                recipient_fingerprint,
                label: request.label.clone(),
                ttl_seconds: None,
            },
        )?;
        let key_hash = api_key::hash_bearer(&created.token)?;
        let registered_at = created.info.created_at.clone();
        let receipt_sig = signing::sign(
            relay_private_key,
            &receipt_preimage(
                path_provider_id,
                &public_key,
                &fingerprint,
                created.info.id,
                &key_hash,
                &registered_at,
            )?,
        );
        let keyquorum_signature = hex::encode(receipt_sig);
        conn.execute(
            "INSERT INTO api_key_registrations
             (provider_id, hardware_fingerprint, hardware_public_key, api_key_id,
              registered_at, keyquorum_signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                path_provider_id,
                fingerprint,
                hex::encode(public_key),
                created.info.id,
                registered_at,
                keyquorum_signature,
            ],
        )?;
        Ok(RegisterResponse {
            token: created.token,
            id: created.info.id,
            scope: created.info.scope,
            provider_id: path_provider_id.to_string(),
            hardware_fingerprint: fingerprint,
            hardware_public_key: hex::encode(public_key),
            registered_at,
            keyquorum_signature,
        })
    })
}

pub fn list_for_provider(conn: &Connection, provider_id: &str) -> Result<Vec<Registration>> {
    let mut stmt = conn.prepare(
        "SELECT id, provider_id, hardware_fingerprint, hardware_public_key,
                api_key_id, registered_at, keyquorum_signature
         FROM api_key_registrations
         WHERE provider_id = ?1
         ORDER BY registered_at, id",
    )?;
    let rows = stmt.query_map(params![provider_id], row_to_registration)?;
    rows.collect::<rusqlite::Result<_>>().map_err(Error::from)
}

pub fn list_for_hardware(
    conn: &Connection,
    provider_id: &str,
    hardware_fingerprint: &str,
) -> Result<Vec<Registration>> {
    let mut stmt = conn.prepare(
        "SELECT id, provider_id, hardware_fingerprint, hardware_public_key,
                api_key_id, registered_at, keyquorum_signature
         FROM api_key_registrations
         WHERE provider_id = ?1 AND hardware_fingerprint = ?2
         ORDER BY registered_at, id",
    )?;
    let rows = stmt.query_map(
        params![provider_id, hardware_fingerprint],
        row_to_registration,
    )?;
    rows.collect::<rusqlite::Result<_>>().map_err(Error::from)
}

fn row_to_registration(row: &rusqlite::Row<'_>) -> rusqlite::Result<Registration> {
    Ok(Registration {
        id: row.get(0)?,
        provider_id: row.get(1)?,
        hardware_fingerprint: row.get(2)?,
        hardware_public_key: row.get(3)?,
        api_key_id: row.get(4)?,
        registered_at: row.get(5)?,
        keyquorum_signature: row.get(6)?,
    })
}

#[cfg(test)]
#[path = "register/tests.rs"]
mod tests;

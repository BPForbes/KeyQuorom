//! Hardware-key registry: keypair generation (pure, no I/O — this project
//! deliberately does not commit to a private-key custody scheme yet, see
//! README's Roadmap) and CRUD over the `hardware_keys` table.

use crate::error::{Error, Result};
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension, Row};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyType {
    Encryption,
    Signing,
}

impl KeyType {
    fn as_str(self) -> &'static str {
        match self {
            KeyType::Encryption => "encryption",
            KeyType::Signing => "signing",
        }
    }

    fn from_db_str(s: &str) -> Self {
        match s {
            "encryption" => KeyType::Encryption,
            "signing" => KeyType::Signing,
            other => unreachable!(
                "hardware_keys.key_type CHECK constraint guarantees 'encryption' or 'signing', got {other:?}"
            ),
        }
    }
}

pub struct HardwareKey {
    pub id: i64,
    pub label: String,
    pub key_type: KeyType,
    pub fingerprint: String,
    pub public_key: Vec<u8>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

/// Fingerprint = hex(sha256(raw public key bytes)), matching `sharing.rs`'s
/// existing `hex::encode(Sha256::digest(..))` token-hashing style — the
/// only fingerprinting precedent in this codebase.
pub fn fingerprint(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// Pure, no I/O: generates a new X25519 keypair for wrapping quorum shares.
pub fn generate_encryption_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public = *secret.public_key().as_bytes();
    (Zeroizing::new(secret.to_bytes()), public)
}

/// Pure, no I/O: generates a new Ed25519 keypair for signature verification.
pub fn generate_signing_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public = signing_key.verifying_key().to_bytes();
    (Zeroizing::new(signing_key.to_bytes()), public)
}

const SELECT_COLUMNS: &str = "id, label, key_type, fingerprint, public_key, created_at, revoked_at";

fn row_to_key(row: &Row) -> rusqlite::Result<HardwareKey> {
    let key_type: String = row.get(2)?;
    Ok(HardwareKey {
        id: row.get(0)?,
        label: row.get(1)?,
        key_type: KeyType::from_db_str(&key_type),
        fingerprint: row.get(3)?,
        public_key: row.get(4)?,
        created_at: row.get(5)?,
        revoked_at: row.get(6)?,
    })
}

pub fn register_key(
    conn: &Connection,
    label: &str,
    key_type: KeyType,
    public_key: &[u8],
) -> Result<i64> {
    if public_key.len() != 32 {
        return Err(Error::InvalidPublicKey);
    }
    let fp = fingerprint(public_key);
    conn.execute(
        "INSERT INTO hardware_keys (label, key_type, fingerprint, public_key) VALUES (?1, ?2, ?3, ?4)",
        params![label, key_type.as_str(), fp, public_key],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn list_keys(conn: &Connection) -> Result<Vec<HardwareKey>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_COLUMNS} FROM hardware_keys ORDER BY id"
    ))?;
    let rows = stmt.query_map([], row_to_key)?;
    let keys = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(keys)
}

pub fn get_key(conn: &Connection, id: i64) -> Result<HardwareKey> {
    let key = conn.query_row(
        &format!("SELECT {SELECT_COLUMNS} FROM hardware_keys WHERE id = ?1"),
        params![id],
        row_to_key,
    )?;
    Ok(key)
}

pub fn get_key_by_public_key(conn: &Connection, public_key: &[u8]) -> Result<HardwareKey> {
    conn.query_row(
        &format!("SELECT {SELECT_COLUMNS} FROM hardware_keys WHERE public_key = ?1"),
        params![public_key],
        row_to_key,
    )
    .optional()?
    .ok_or(Error::InvalidPublicKey)
}

/// Raw 32-byte public or private key material from a hex dump, PEM, or
/// OpenSSH `.pub` line — the files `generate` writes and the usual
/// standard key-file shapes.
pub fn parse_key_text(contents: &str) -> Result<Vec<u8>> {
    let trimmed = contents.trim();
    if trimmed.starts_with("-----BEGIN ") {
        return decode_pem_key(trimmed);
    }
    if let Some(raw) = parse_openssh_public(trimmed) {
        return Ok(raw);
    }
    hex::decode(trimmed).map_err(|_| Error::InvalidPublicKey)
}

pub fn encryption_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let secret_key = crypto_box::SecretKey::from(*secret);
    *secret_key.public_key().as_bytes()
}

/// RFC 8410 SubjectPublicKeyInfo prefixes (BIT STRING of 32 key bytes).
const SPKI_X25519: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];
const SPKI_ED25519: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// RFC 8410 PKCS#8 OneAsymmetricKey prefixes (OCTET STRING of 32 key bytes).
const PKCS8_X25519: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];
const PKCS8_ED25519: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn decode_pem_key(text: &str) -> Result<Vec<u8>> {
    let mut saw_label = false;
    let mut b64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let name = rest.strip_suffix("-----").ok_or(Error::InvalidPublicKey)?;
            if !pem_label_is_curve_key(name) {
                return Err(Error::InvalidPublicKey);
            }
            saw_label = true;
            inside = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if inside {
            b64.push_str(line);
        }
    }
    if !saw_label {
        return Err(Error::InvalidPublicKey);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| Error::InvalidPublicKey)?;
    extract_curve_key_bytes(&der)
}

fn pem_label_is_curve_key(label: &str) -> bool {
    matches!(
        label,
        "PUBLIC KEY"
            | "PRIVATE KEY"
            | "ED25519 PUBLIC KEY"
            | "ED25519 PRIVATE KEY"
            | "X25519 PUBLIC KEY"
            | "X25519 PRIVATE KEY"
    )
}

fn extract_curve_key_bytes(der: &[u8]) -> Result<Vec<u8>> {
    if der.len() == 32 {
        return Ok(der.to_vec());
    }
    for prefix in [SPKI_X25519, SPKI_ED25519, PKCS8_X25519, PKCS8_ED25519] {
        if der.len() == prefix.len() + 32 && der.starts_with(prefix) {
            return Ok(der[prefix.len()..].to_vec());
        }
    }
    Err(Error::InvalidPublicKey)
}

fn parse_openssh_public(line: &str) -> Option<Vec<u8>> {
    let mut parts = line.split_whitespace();
    let algo = parts.next()?;
    if algo != "ssh-ed25519" {
        return None;
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(parts.next()?)
        .ok()?;
    parse_ssh_ed25519_blob(&data)
}

fn parse_ssh_ed25519_blob(mut data: &[u8]) -> Option<Vec<u8>> {
    let algo = read_ssh_string(&mut data)?;
    if algo != b"ssh-ed25519" {
        return None;
    }
    let key = read_ssh_string(&mut data)?;
    if key.len() != 32 || !data.is_empty() {
        return None;
    }
    Some(key.to_vec())
}

fn read_ssh_string<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(data[..4].try_into().ok()?) as usize;
    *data = &data[4..];
    if data.len() < len {
        return None;
    }
    let (head, tail) = data.split_at(len);
    *data = tail;
    Some(head)
}

pub fn revoke_key(conn: &Connection, id: i64) -> Result<()> {
    conn.execute(
        "UPDATE hardware_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
        params![id],
    )?;
    Ok(())
}

pub fn remove_key(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM hardware_keys WHERE id = ?1", params![id])?;
    Ok(())
}

/// Used internally by `key_tree::validate` — enforces the application
/// policy that only active encryption-purpose keys may back a quorum leaf.
pub(crate) fn get_active_encryption_key(conn: &Connection, id: i64) -> Result<HardwareKey> {
    let key = get_key(conn, id)?;
    if key.key_type != KeyType::Encryption {
        return Err(Error::WrongKeyType);
    }
    if key.revoked_at.is_some() {
        return Err(Error::KeyRevoked);
    }
    Ok(key)
}

#[cfg(test)]
#[path = "keys_tests/tests.rs"]
mod tests;

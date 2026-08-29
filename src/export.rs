//! Portable, self-contained export bundles: re-encrypts a credential's or
//! file's plaintext (which the exporter already has via their own local
//! master/lock password) to a recipient's public key, so it can be handed
//! to someone with no access to this database. Opening a bundle
//! (`import`) needs the recipient's private key, which this project has
//! no custody story for yet — see README's Roadmap.
//!
//! The bundle format is a small hand-rolled, length-prefixed binary
//! framing rather than serde+serde_json: this codebase has zero serde
//! today and already hand-rolls `sharing.rs`'s token framing, and more
//! importantly, `import`'s future decoder will parse bytes from an
//! untrusted sender — a small, fixed-width, hand-checked parser keeps
//! that attack surface much smaller than a general JSON parser over
//! attacker-controlled input would.
//!
//! Layout (all multi-byte integers big-endian):
//!   magic "KQXB" (4) | format_version (1) | bundle_type (1)
//!   | recipient_public_key (32) | payload_len (4) | sealed_payload (payload_len)
//! where bundle_type 1 = credential, 2 = file. The recipient's name/label
//! stays inside the sealed payload rather than the outer header — a
//! credential label or file name can be sensitive on its own, and the
//! outer header is the one part of a bundle that's never encrypted.
//! The sealed payload's plaintext (before sealing) is, for a credential:
//!   label_len (2) | label (label_len) | username_len (2) | username (username_len)
//!   | password_len (2) | password (password_len)
//! (username_len = 0 means no username) and for a file:
//!   name_len (2) | name (name_len) | file_bytes (remainder)

use crate::error::{Error, Result};
use crate::{locked_files, vault};
use rusqlite::{params, Connection};

const MAGIC: &[u8; 4] = b"KQXB";
const FORMAT_VERSION: u8 = 1;
const BUNDLE_TYPE_CREDENTIAL: u8 = 1;
const BUNDLE_TYPE_FILE: u8 = 2;

pub fn export_credential(
    conn: &Connection,
    credential_id: i64,
    master_password: &str,
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let credential = vault::get_credential(conn, credential_id, master_password)?;

    let mut payload = Vec::new();
    encode_len_prefixed(&mut payload, credential.label.as_bytes())?;
    encode_len_prefixed(
        &mut payload,
        credential.username.as_deref().unwrap_or("").as_bytes(),
    )?;
    encode_len_prefixed(&mut payload, credential.password.as_bytes())?;

    encode_bundle(BUNDLE_TYPE_CREDENTIAL, recipient_public_key, &payload)
}

pub fn export_file(
    conn: &Connection,
    file_id: i64,
    password: &str,
    recipient_public_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let name: String = conn.query_row(
        "SELECT name FROM password_locked_files WHERE id = ?1",
        params![file_id],
        |row| row.get(0),
    )?;
    let plaintext = locked_files::unlock_file(conn, file_id, password)?;

    let mut payload = Vec::new();
    encode_len_prefixed(&mut payload, name.as_bytes())?;
    payload.extend_from_slice(&plaintext);

    encode_bundle(BUNDLE_TYPE_FILE, recipient_public_key, &payload)
}

/// Appends `bytes` to `out` with a `u16` length prefix. Fails, without
/// writing anything to `out`, if `bytes` exceeds what a `u16` length can
/// encode — silently truncating the cast instead would corrupt the whole
/// bundle's framing downstream of this field.
fn encode_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A handful of X25519 curve points have small order and, under
/// Diffie-Hellman with *any* scalar, always yield an all-zero shared
/// secret (RFC 7748) — the trivial case is 32 zero bytes. Sealing to one
/// of these would produce a bundle anyone could open without any private
/// key at all. Detecting this needs only one clamped scalar (clamping
/// forces it to be a multiple of the curve's cofactor, so every low-order
/// point collapses to zero the same way regardless of which one is used);
/// the probe scalar's value is otherwise irrelevant and is never used for
/// real encryption.
fn is_weak_x25519_public_key(public_key: &[u8; 32]) -> bool {
    x25519_dalek::x25519([1u8; 32], *public_key) == [0u8; 32]
}

fn encode_bundle(
    bundle_type: u8,
    recipient_public_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if is_weak_x25519_public_key(recipient_public_key) {
        return Err(Error::InvalidPublicKey);
    }

    let public_key = crypto_box::PublicKey::from_bytes(*recipient_public_key);
    let sealed_payload = public_key
        .seal(&mut rand::rngs::OsRng, plaintext)
        .expect("crypto_box sealing should not fail for an in-memory payload");
    let payload_len =
        u32::try_from(sealed_payload.len()).map_err(|_| Error::BundleFieldTooLarge)?;

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(bundle_type);
    out.extend_from_slice(recipient_public_key);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&sealed_payload);
    Ok(out)
}

#[cfg(test)]
#[path = "export/tests.rs"]
mod tests;

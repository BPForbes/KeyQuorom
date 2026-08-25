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
//!   | recipient_public_key (32) | name_len (2) | name (name_len)
//!   | payload_len (4) | sealed_payload (payload_len)
//! where bundle_type 1 = credential, 2 = file, and the sealed payload's
//! plaintext (before sealing) is, for a credential:
//!   username_len (2) | username (username_len) | password_len (2) | password (password_len)
//! (username_len = 0 means no username) and for a file, the raw file
//! bytes with no further framing (the name is already carried above).

use crate::error::Result;
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
    encode_len_prefixed(
        &mut payload,
        credential.username.as_deref().unwrap_or("").as_bytes(),
    );
    encode_len_prefixed(&mut payload, credential.password.as_bytes());

    encode_bundle(
        BUNDLE_TYPE_CREDENTIAL,
        &credential.label,
        recipient_public_key,
        &payload,
    )
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

    encode_bundle(BUNDLE_TYPE_FILE, &name, recipient_public_key, &plaintext)
}

fn encode_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn encode_bundle(
    bundle_type: u8,
    name: &str,
    recipient_public_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let public_key = crypto_box::PublicKey::from_bytes(*recipient_public_key);
    let sealed_payload = public_key
        .seal(&mut rand::rngs::OsRng, plaintext)
        .expect("crypto_box sealing should not fail for an in-memory payload");

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.push(bundle_type);
    out.extend_from_slice(recipient_public_key);
    let name_bytes = name.as_bytes();
    out.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&(sealed_payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&sealed_payload);
    Ok(out)
}

// The header decoder below is intentionally test-only: there's no
// legitimate caller for a public "parse a bundle header" function until
// `import` exists, and shipping one anyway would be scaffolding ahead of
// need. It exists here purely so export's own round-trip tests can verify
// what got encoded.
#[cfg(test)]
struct DecodedBundle {
    bundle_type: u8,
    recipient_public_key: [u8; 32],
    name: String,
    sealed_payload: Vec<u8>,
}

#[cfg(test)]
fn decode_bundle(bytes: &[u8]) -> DecodedBundle {
    assert_eq!(&bytes[0..4], MAGIC);
    assert_eq!(bytes[4], FORMAT_VERSION);
    let bundle_type = bytes[5];
    let recipient_public_key: [u8; 32] = bytes[6..38].try_into().unwrap();
    let name_len = u16::from_be_bytes([bytes[38], bytes[39]]) as usize;
    let name_end = 40 + name_len;
    let name = String::from_utf8(bytes[40..name_end].to_vec()).unwrap();
    let payload_len =
        u32::from_be_bytes(bytes[name_end..name_end + 4].try_into().unwrap()) as usize;
    let sealed_payload = bytes[name_end + 4..name_end + 4 + payload_len].to_vec();

    DecodedBundle {
        bundle_type,
        recipient_public_key,
        name,
        sealed_payload,
    }
}

#[cfg(test)]
fn decode_len_prefixed(bytes: &[u8], offset: &mut usize) -> Vec<u8> {
    let len = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]) as usize;
    *offset += 2;
    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::vault;
    use std::fs;

    fn recipient_keypair() -> (crypto_box::SecretKey, [u8; 32]) {
        let secret_key = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let public_key = *secret_key.public_key().as_bytes();
        (secret_key, public_key)
    }

    #[test]
    fn export_credential_bundle_header_round_trips() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id =
            vault::add_credential(&conn, "Email", Some("bailey"), "s3cr3t", "master-pw")
                .expect("add_credential should succeed");
        let (_secret_key, public_key) = recipient_keypair();

        let bundle = export_credential(&conn, credential_id, "master-pw", &public_key)
            .expect("export_credential should succeed");

        let decoded = decode_bundle(&bundle);
        assert_eq!(decoded.bundle_type, BUNDLE_TYPE_CREDENTIAL);
        assert_eq!(decoded.recipient_public_key, public_key);
        assert_eq!(decoded.name, "Email");
    }

    #[test]
    fn export_credential_bundle_only_opens_with_the_matching_secret_key() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id = vault::add_credential(&conn, "Email", None, "s3cr3t", "master-pw")
            .expect("add_credential should succeed");
        let (secret_key_a, public_key_a) = recipient_keypair();
        let (secret_key_b, _public_key_b) = recipient_keypair();

        let bundle = export_credential(&conn, credential_id, "master-pw", &public_key_a)
            .expect("export_credential should succeed");
        let decoded = decode_bundle(&bundle);

        assert!(secret_key_b.unseal(&decoded.sealed_payload).is_err());
        assert!(secret_key_a.unseal(&decoded.sealed_payload).is_ok());
    }

    #[test]
    fn export_credential_inner_payload_round_trips() {
        let conn = db::open_in_memory().expect("schema should apply");
        let credential_id =
            vault::add_credential(&conn, "Email", Some("bailey"), "s3cr3t", "master-pw")
                .expect("add_credential should succeed");
        let (secret_key, public_key) = recipient_keypair();

        let bundle = export_credential(&conn, credential_id, "master-pw", &public_key)
            .expect("export_credential should succeed");
        let decoded = decode_bundle(&bundle);
        let plaintext = secret_key
            .unseal(&decoded.sealed_payload)
            .expect("unseal should succeed with the matching secret key");

        let mut offset = 0;
        let username = decode_len_prefixed(&plaintext, &mut offset);
        let password = decode_len_prefixed(&plaintext, &mut offset);
        assert_eq!(String::from_utf8(username).unwrap(), "bailey");
        assert_eq!(String::from_utf8(password).unwrap(), "s3cr3t");
    }

    #[test]
    fn export_file_bundle_round_trips() {
        let conn = db::open_in_memory().expect("schema should apply");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let source_path = dir.path().join("secret.txt");
        let encrypted_path = dir.path().join("secret.txt.kqenc");
        fs::write(&source_path, b"the quorum has been reached").unwrap();

        let file_id = locked_files::lock_file(&conn, &source_path, &encrypted_path, "hunter2")
            .expect("lock_file should succeed");
        let (secret_key, public_key) = recipient_keypair();

        let bundle = export_file(&conn, file_id, "hunter2", &public_key)
            .expect("export_file should succeed");
        let decoded = decode_bundle(&bundle);
        assert_eq!(decoded.bundle_type, BUNDLE_TYPE_FILE);
        assert_eq!(decoded.name, "secret.txt");

        let plaintext = secret_key
            .unseal(&decoded.sealed_payload)
            .expect("unseal should succeed with the matching secret key");
        assert_eq!(plaintext, b"the quorum has been reached");
    }
}

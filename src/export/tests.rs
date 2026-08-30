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
    let label = decode_len_prefixed(&plaintext, &mut offset);
    let username = decode_len_prefixed(&plaintext, &mut offset);
    let password = decode_len_prefixed(&plaintext, &mut offset);
    assert_eq!(String::from_utf8(label).unwrap(), "Email");
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

    let bundle =
        export_file(&conn, file_id, "hunter2", &public_key).expect("export_file should succeed");
    let decoded = decode_bundle(&bundle);
    assert_eq!(decoded.bundle_type, BUNDLE_TYPE_FILE);

    let plaintext = secret_key
        .unseal(&decoded.sealed_payload)
        .expect("unseal should succeed with the matching secret key");
    let mut offset = 0;
    let name = decode_len_prefixed(&plaintext, &mut offset);
    assert_eq!(String::from_utf8(name).unwrap(), "secret.txt");
    assert_eq!(&plaintext[offset..], b"the quorum has been reached");
}

#[test]
fn encode_len_prefixed_accepts_a_field_at_the_u16_boundary() {
    let mut out = Vec::new();
    let bytes = vec![0u8; u16::MAX as usize];
    assert!(encode_len_prefixed(&mut out, &bytes).is_ok());
}

#[test]
fn encode_len_prefixed_rejects_a_field_one_byte_over_the_boundary() {
    let mut out = Vec::new();
    let bytes = vec![0u8; u16::MAX as usize + 1];
    assert!(matches!(
        encode_len_prefixed(&mut out, &bytes),
        Err(Error::BundleFieldTooLarge)
    ));
}

#[test]
fn export_credential_rejects_an_oversized_label() {
    let conn = db::open_in_memory().expect("schema should apply");
    let long_label = "x".repeat(u16::MAX as usize + 1);
    let credential_id = vault::add_credential(&conn, &long_label, None, "s3cr3t", "master-pw")
        .expect("add_credential should succeed");
    let (_secret_key, public_key) = recipient_keypair();

    let result = export_credential(&conn, credential_id, "master-pw", &public_key);
    assert!(matches!(result, Err(Error::BundleFieldTooLarge)));
}

#[test]
fn export_rejects_an_all_zero_recipient_public_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let credential_id = vault::add_credential(&conn, "Email", None, "s3cr3t", "master-pw")
        .expect("add_credential should succeed");

    let result = export_credential(&conn, credential_id, "master-pw", &[0u8; 32]);
    assert!(matches!(result, Err(Error::InvalidPublicKey)));
}

// The header decoder below is intentionally test-only: there's no
// legitimate caller for a public "parse a bundle header" function until
// `import` exists, and shipping one anyway would be scaffolding ahead of
// need. It exists here purely so export's own round-trip tests can verify
// what got encoded.

struct DecodedBundle {
    bundle_type: u8,
    recipient_public_key: [u8; 32],
    sealed_payload: Vec<u8>,
}

fn decode_bundle(bytes: &[u8]) -> DecodedBundle {
    assert_eq!(&bytes[0..4], MAGIC);
    assert_eq!(bytes[4], FORMAT_VERSION);
    let bundle_type = bytes[5];
    let recipient_public_key: [u8; 32] = bytes[6..38].try_into().unwrap();
    let payload_len = u32::from_be_bytes(bytes[38..42].try_into().unwrap()) as usize;
    let sealed_payload = bytes[42..42 + payload_len].to_vec();

    DecodedBundle {
        bundle_type,
        recipient_public_key,
        sealed_payload,
    }
}

fn decode_len_prefixed(bytes: &[u8], offset: &mut usize) -> Vec<u8> {
    let len = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]) as usize;
    *offset += 2;
    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    value
}

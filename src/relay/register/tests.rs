use super::*;
use crate::keys;
use crate::relay;
use crate::signing;

fn register_one(
    conn: &rusqlite::Connection,
    provider_id: &str,
    relay_private: &[u8; 32],
    hardware_private: &[u8; 32],
    scope: Option<&str>,
    label: Option<&str>,
) -> RegisterResponse {
    let (public, signature) = sign_register_proof(hardware_private, provider_id).expect("sign");
    register(
        conn,
        provider_id,
        provider_id,
        relay_private,
        &RegisterRequest {
            public_key: hex::encode(public),
            signature: hex::encode(signature),
            scope: scope.map(str::to_string),
            label: label.map(str::to_string),
        },
    )
    .expect("register")
}

#[test]
fn register_mints_key_and_tracks_hardware() {
    let conn = relay::open_in_memory().expect("schema");
    let (relay_sk, relay_pk) = keys::generate_signing_keypair();
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let provider_id = "Acme Security Services";
    let receipt = register_one(&conn, provider_id, &relay_sk, &hw_sk, None, Some("desk"));
    assert!(receipt.token.starts_with("kq_"));
    assert_eq!(receipt.scope, "inbox.push");
    assert_eq!(receipt.provider_id, provider_id);
    assert_eq!(receipt.hardware_public_key, hex::encode(hw_pk));
    assert_eq!(receipt.hardware_fingerprint, keys::fingerprint(&hw_pk));
    assert!(!receipt.registered_at.is_empty());

    let key_hash = api_key::hash_bearer(&receipt.token).expect("hash");
    verify_receipt(&relay_pk, &receipt, &key_hash, &hw_pk).expect("receipt");

    let rows = list_for_hardware(&conn, provider_id, &receipt.hardware_fingerprint).expect("list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].api_key_id, receipt.id);
    assert_eq!(rows[0].registered_at, receipt.registered_at);
    assert_eq!(rows[0].hardware_public_key, hex::encode(hw_pk));
}

#[test]
fn same_hardware_can_register_again_and_history_is_kept() {
    let conn = relay::open_in_memory().expect("schema");
    let (relay_sk, _) = keys::generate_signing_keypair();
    let (hw_sk, _) = keys::generate_signing_keypair();
    let provider_id = "acme";
    let first = register_one(&conn, provider_id, &relay_sk, &hw_sk, None, Some("a"));
    let second = register_one(&conn, provider_id, &relay_sk, &hw_sk, None, Some("b"));
    assert_ne!(first.id, second.id);
    assert_ne!(first.token, second.token);
    let rows = list_for_provider(&conn, provider_id).expect("list");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].api_key_id, first.id);
    assert_eq!(rows[1].api_key_id, second.id);
}

#[test]
fn pull_scope_binds_recipient_to_hardware_fingerprint() {
    let conn = relay::open_in_memory().expect("schema");
    let (relay_sk, _) = keys::generate_signing_keypair();
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let receipt = register_one(&conn, "acme", &relay_sk, &hw_sk, Some("inbox.pull"), None);
    assert_eq!(receipt.scope, "inbox.pull");
    let info = relay::list_api_keys(&conn).expect("list");
    assert_eq!(
        info[0].recipient_fingerprint.as_deref(),
        Some(keys::fingerprint(&hw_pk).as_str())
    );
}

#[test]
fn wrong_provider_path_is_rejected() {
    let conn = relay::open_in_memory().expect("schema");
    let (relay_sk, _) = keys::generate_signing_keypair();
    let (hw_sk, _) = keys::generate_signing_keypair();
    let (public, signature) = sign_register_proof(&hw_sk, "acme").expect("sign");
    assert!(matches!(
        register(
            &conn,
            "other",
            "acme",
            &relay_sk,
            &RegisterRequest {
                public_key: hex::encode(public),
                signature: hex::encode(signature),
                scope: None,
                label: None,
            },
        ),
        Err(Error::UnknownProvider)
    ));
}

#[test]
fn admin_scope_is_refused() {
    let conn = relay::open_in_memory().expect("schema");
    let (relay_sk, _) = keys::generate_signing_keypair();
    let (hw_sk, _) = keys::generate_signing_keypair();
    let (public, signature) = sign_register_proof(&hw_sk, "acme").expect("sign");
    assert!(matches!(
        register(
            &conn,
            "acme",
            "acme",
            &relay_sk,
            &RegisterRequest {
                public_key: hex::encode(public),
                signature: hex::encode(signature),
                scope: Some("admin".into()),
                label: None,
            },
        ),
        Err(Error::InvalidApiKeyRequest)
    ));
}

#[test]
fn forged_signature_is_rejected() {
    let conn = relay::open_in_memory().expect("schema");
    let (relay_sk, _) = keys::generate_signing_keypair();
    let (hw_sk, _) = keys::generate_signing_keypair();
    let (public, _) = sign_register_proof(&hw_sk, "acme").expect("sign");
    let (other_sk, _) = keys::generate_signing_keypair();
    let forged = signing::sign(&other_sk, &register_preimage("acme", &public).expect("pre"));
    assert!(matches!(
        register(
            &conn,
            "acme",
            "acme",
            &relay_sk,
            &RegisterRequest {
                public_key: hex::encode(public),
                signature: hex::encode(forged),
                scope: None,
                label: None,
            },
        ),
        Err(Error::SignatureVerificationFailed)
    ));
}

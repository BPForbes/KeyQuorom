use super::super::*;
use crate::db;

#[test]
fn keypair_generation_is_distinct_across_calls() {
    let (sk_a, pk_a) = generate_encryption_keypair();
    let (sk_b, pk_b) = generate_encryption_keypair();
    assert_ne!(*sk_a, *sk_b);
    assert_ne!(pk_a, pk_b);

    let (sign_sk_a, sign_pk_a) = generate_signing_keypair();
    let (sign_sk_b, sign_pk_b) = generate_signing_keypair();
    assert_ne!(*sign_sk_a, *sign_sk_b);
    assert_ne!(sign_pk_a, sign_pk_b);
}

#[test]
fn register_and_list_roundtrip() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    let key = get_key(&conn, id).expect("get_key should succeed");
    assert_eq!(key.label, "Alice");
    assert_eq!(key.key_type, KeyType::Encryption);
    assert_eq!(key.public_key, public_key);
    assert_eq!(key.fingerprint, fingerprint(&public_key));
    assert!(key.revoked_at.is_none());

    let keys = list_keys(&conn).expect("list_keys should succeed");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, id);
}

#[test]
fn register_key_rejects_wrong_length_public_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let result = register_key(&conn, "Alice", KeyType::Encryption, &[0u8; 31]);
    assert!(matches!(result, Err(Error::InvalidPublicKey)));

    let keys = list_keys(&conn).expect("list_keys should succeed");
    assert!(keys.is_empty());
}

#[test]
fn duplicate_fingerprint_is_rejected() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("first register_key should succeed");

    let result = register_key(&conn, "Alice (copy)", KeyType::Encryption, &public_key);
    assert!(matches!(result, Err(Error::Db(_))));
}

#[test]
fn revoke_sets_revoked_at() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    revoke_key(&conn, id).expect("revoke_key should succeed");
    let key = get_key(&conn, id).expect("get_key should succeed");
    assert!(key.revoked_at.is_some());
}

#[test]
fn remove_key_succeeds_when_unused() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    remove_key(&conn, id).expect("remove_key should succeed");
    assert!(get_key(&conn, id).is_err());
}

#[test]
fn get_active_encryption_key_rejects_revoked_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");
    revoke_key(&conn, id).expect("revoke_key should succeed");

    let result = get_active_encryption_key(&conn, id);
    assert!(matches!(result, Err(Error::KeyRevoked)));
}

#[test]
fn get_active_encryption_key_rejects_signing_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_signing_keypair();
    let id = register_key(&conn, "Alice", KeyType::Signing, &public_key)
        .expect("register_key should succeed");

    let result = get_active_encryption_key(&conn, id);
    assert!(matches!(result, Err(Error::WrongKeyType)));
}

#[test]
fn get_active_encryption_key_accepts_active_encryption_key() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    let key = get_active_encryption_key(&conn, id).expect("key should be active");
    assert_eq!(key.id, id);
}

#[test]
fn get_key_by_public_key_finds_the_registered_row() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_, public_key) = generate_encryption_keypair();
    let id = register_key(&conn, "Alice", KeyType::Encryption, &public_key)
        .expect("register_key should succeed");

    let key = get_key_by_public_key(&conn, &public_key).expect("lookup should succeed");
    assert_eq!(key.id, id);
    assert!(get_key_by_public_key(&conn, &[0u8; 32]).is_err());
}

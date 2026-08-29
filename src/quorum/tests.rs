use super::*;
use crate::db;
use crate::key_tree::NodeSpec;
use crate::keys::{self, KeyType};

fn register_encryption_key(conn: &Connection, label: &str) -> (i64, crypto_box::SecretKey) {
    let secret_key = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public_key = *secret_key.public_key().as_bytes();
    let id = keys::register_key(conn, label, KeyType::Encryption, &public_key)
        .expect("register_key should succeed");
    (id, secret_key)
}

fn unwrap_leaf_share(
    conn: &Connection,
    node_id: i64,
    secret_key: &crypto_box::SecretKey,
) -> Vec<u8> {
    crate::key_tree::unwrap_leaf_share(conn, node_id, &secret_key.to_bytes())
        .expect("unseal should succeed with the matching secret key")
}

fn leaf_ids_by_label(conn: &Connection, key_id: i64) -> HashMap<String, i64> {
    let mut stmt = conn
        .prepare(
            "SELECT id, label FROM key_nodes WHERE key_id = ?1 AND hardware_key_id IS NOT NULL",
        )
        .unwrap();
    stmt.query_map(params![key_id], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(0)?))
    })
    .unwrap()
    .collect::<rusqlite::Result<HashMap<_, _>>>()
    .unwrap()
}

#[test]
fn lock_status_and_unlock_roundtrip_with_threshold_met() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let (id_b, sk_b) = register_encryption_key(&conn, "b");
    let (id_c, _sk_c) = register_encryption_key(&conn, "c");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "c".into(),
                hardware_key_id: id_c,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let file_id = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec)
        .expect("lock_file should succeed");

    let file_status = status(&conn, file_id).expect("status should succeed");
    assert_eq!(file_status.tree.root.threshold, Some(2));
    assert_eq!(file_status.tree.root.children.len(), 3);

    let key_id = file_status.tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let raw_b = unwrap_leaf_share(&conn, leaves[&"b".to_string()], &sk_b);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);
    shares.insert(leaves[&"b".to_string()], raw_b);

    let plaintext = unlock_file(&conn, file_id, &shares).expect("unlock_file should succeed");
    assert_eq!(plaintext, b"the quorum has been reached");
}

#[test]
fn unlock_fails_with_too_few_shares() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let file_id = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec)
        .expect("lock_file should succeed");

    let key_id = status(&conn, file_id).unwrap().tree.key_id;
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);

    let result = unlock_file(&conn, file_id, &shares);
    assert!(matches!(result, Err(Error::QuorumNotMet)));
}

#[test]
fn lock_rejects_threshold_above_recipient_count() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![NodeSpec::Leaf {
            label: "a".into(),
            hardware_key_id: id_a,
            allowed_bridges: vec![],
        }],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(matches!(result, Err(Error::InvalidQuorumThreshold)));
    assert!(!encrypted_path.exists());
}

#[test]
fn lock_cleans_up_ciphertext_when_starting_the_transaction_fails() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");

    let spec = NodeSpec::Leaf {
        label: "a".into(),
        hardware_key_id: id_a,
        allowed_bridges: vec![],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    // Force conn.transaction() to fail inside lock_file: open a
    // transaction on this same connection first, via raw SQL rather
    // than rusqlite's Transaction guard (which would hold a Rust-level
    // borrow on `conn` and conflict with passing `&mut conn` below).
    conn.execute_batch("BEGIN").expect("BEGIN should succeed");

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(result.is_err());
    assert!(
        !encrypted_path.exists(),
        "ciphertext should be cleaned up even when the transaction never opens"
    );

    conn.execute_batch("ROLLBACK")
        .expect("ROLLBACK should succeed");
}

#[test]
fn lock_rejects_signing_key_as_recipient() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    let id = keys::register_key(&conn, "signer", KeyType::Signing, &public_key)
        .expect("register_key should succeed");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "signer".into(),
                hardware_key_id: id,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(matches!(result, Err(Error::WrongKeyType)));
    assert!(!encrypted_path.exists());
}

#[test]
fn lock_rejects_revoked_recipient() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");
    keys::revoke_key(&conn, id_a).expect("revoke_key should succeed");
    let (id_b, _sk_b) = register_encryption_key(&conn, "b");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "b".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let result = lock_file(&mut conn, &source_path, &encrypted_path, None, &spec);
    assert!(matches!(result, Err(Error::KeyRevoked)));
    assert!(!encrypted_path.exists());
}

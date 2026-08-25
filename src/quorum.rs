//! Hardware-key-quorum file protection: encrypts a file under a random
//! data key, then splits that key via `key_tree::split` so unlocking the
//! file means reconstructing that key's tree — a flat "M-of-N hardware
//! keys" quorum is just the simplest possible tree shape.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use crate::key_tree::{self, NodeSpec, TreeSummary};
use crate::locked_files;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct FileStatus {
    pub id: i64,
    pub name: String,
    pub encrypted_path: String,
    pub created_at: String,
    pub tree: TreeSummary,
}

/// Encrypts `source_path` under a fresh random data key and splits that
/// key per `tree_spec`. The ciphertext is written first, outside any
/// database transaction (mirroring `locked_files::lock_file`'s reasoning:
/// `create_new` fails atomically if `encrypted_path` is already in use,
/// and this keeps the write lock held only for the DB work that follows).
/// The key-tree build and the `files` row insert happen in one
/// transaction, so a failure partway through never leaves a `files` row
/// pointing at an incomplete tree, or vice versa; on any failure the
/// just-written ciphertext file is removed too.
pub fn lock_file(
    conn: &mut Connection,
    source_path: &Path,
    encrypted_path: &Path,
    name: Option<&str>,
    tree_spec: &NodeSpec,
) -> Result<i64> {
    key_tree::validate(conn, tree_spec)?;
    let encrypted_path_str = encrypted_path.to_str().ok_or(Error::InvalidPath)?;

    let plaintext = fs::read(source_path)?;
    let data_key = crypto::random_key();
    let nonce = crypto::random_nonce();
    let ciphertext = crypto::encrypt(&data_key, &nonce, &plaintext);

    let name = name.map(str::to_owned).unwrap_or_else(|| {
        source_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });

    locked_files::write_owner_only(encrypted_path, &ciphertext)?;

    let tx = conn.transaction()?;
    let insert = (|| -> Result<i64> {
        let key_id = key_tree::build_tree(&tx, &name, &data_key[..], tree_spec)?;
        tx.execute(
            "INSERT INTO files (name, encrypted_path, key_id, nonce) VALUES (?1, ?2, ?3, ?4)",
            params![name, encrypted_path_str, key_id, nonce.to_vec()],
        )?;
        Ok(tx.last_insert_rowid())
    })();

    match insert {
        Ok(file_id) => {
            tx.commit()?;
            Ok(file_id)
        }
        Err(e) => {
            let _ = fs::remove_file(encrypted_path);
            Err(e)
        }
    }
}

pub fn status(conn: &Connection, file_id: i64) -> Result<FileStatus> {
    let (name, encrypted_path, key_id, created_at): (String, String, i64, String) = conn
        .query_row(
            "SELECT name, encrypted_path, key_id, created_at FROM files WHERE id = ?1",
            params![file_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let tree = key_tree::describe(conn, key_id)?;

    Ok(FileStatus {
        id: file_id,
        name,
        encrypted_path,
        created_at,
        tree,
    })
}

/// `raw_shares` maps a leaf `key_nodes.id` to its already-unwrapped raw
/// share bytes — see `key_tree`'s module doc comment for why obtaining
/// them is the caller's responsibility this round.
pub fn unlock_file(
    conn: &Connection,
    file_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let (encrypted_path, key_id, nonce): (String, i64, Vec<u8>) = conn.query_row(
        "SELECT encrypted_path, key_id, nonce FROM files WHERE id = ?1",
        params![file_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let result = reconstruct_and_decrypt(conn, key_id, &encrypted_path, &nonce, raw_shares);

    // Best-effort audit trail: unlock_events already existed in the schema
    // for exactly this, unused until now. A raw share's origin (which
    // hardware key it came from) isn't known yet without the deferred
    // unwrap step, so this logs only a count and the outcome.
    let _ = conn.execute(
        "INSERT INTO unlock_events (file_id, success, keys_presented) VALUES (?1, ?2, ?3)",
        params![
            file_id,
            result.is_ok() as i64,
            format!("{} raw share(s) presented", raw_shares.len())
        ],
    );

    result
}

fn reconstruct_and_decrypt(
    conn: &Connection,
    key_id: i64,
    encrypted_path: &str,
    nonce: &[u8],
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let data_key = key_tree::reconstruct(conn, key_id, raw_shares)?;
    let data_key: [u8; crypto::KEY_LEN] = data_key.try_into().map_err(|_| Error::QuorumNotMet)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::IntegrityCheckFailed)?;

    let ciphertext = fs::read(encrypted_path)?;
    crypto::decrypt(&data_key, &nonce, &ciphertext).map_err(|_| Error::IntegrityCheckFailed)
}

#[cfg(test)]
mod tests {
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
        let wrapped: Vec<u8> = conn
            .query_row(
                "SELECT wrapped_share FROM key_nodes WHERE id = ?1",
                params![node_id],
                |row| row.get(0),
            )
            .expect("leaf node should exist");
        secret_key
            .unseal(&wrapped)
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
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
                },
                NodeSpec::Leaf {
                    label: "c".into(),
                    hardware_key_id: id_c,
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
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
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
            children: vec![NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
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
            children: vec![
                NodeSpec::Leaf {
                    label: "signer".into(),
                    hardware_key_id: id,
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
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
            children: vec![
                NodeSpec::Leaf {
                    label: "a".into(),
                    hardware_key_id: id_a,
                },
                NodeSpec::Leaf {
                    label: "b".into(),
                    hardware_key_id: id_b,
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
}

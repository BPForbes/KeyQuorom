use super::super::*;
use crate::keys::KeyType;
use rusqlite::Connection;
use std::collections::HashMap;

pub(super) fn register_encryption_key(
    conn: &Connection,
    label: &str,
) -> (i64, crypto_box::SecretKey) {
    let secret_key = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public_key = *secret_key.public_key().as_bytes();
    let id = keys::register_key(conn, label, KeyType::Encryption, &public_key)
        .expect("register_key should succeed");
    (id, secret_key)
}

pub(super) fn unseal_leaf(
    conn: &Connection,
    node_id: i64,
    secret_key: &crypto_box::SecretKey,
) -> Vec<u8> {
    super::super::unwrap_leaf_share(conn, node_id, &secret_key.to_bytes())
        .expect("unseal should succeed with the matching secret key")
}

pub(super) fn leaf_ids_by_label(conn: &Connection, key_id: i64) -> HashMap<String, i64> {
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

pub(super) fn wrapped_shares_by_id(conn: &Connection, key_id: i64) -> HashMap<i64, Vec<u8>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, wrapped_share FROM key_nodes
             WHERE key_id = ?1 AND wrapped_share IS NOT NULL",
        )
        .unwrap();
    stmt.query_map(params![key_id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })
    .unwrap()
    .collect::<rusqlite::Result<HashMap<_, _>>>()
    .unwrap()
}

pub(super) fn department_tree_spec(ma1: i64, ma2: i64, ma3: i64, mb: i64) -> NodeSpec {
    NodeSpec::Split {
        label: "M".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Split {
                label: "M.A".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![
                    NodeSpec::Leaf {
                        label: "M.A.1".into(),
                        hardware_key_id: ma1,
                        allowed_bridges: vec!["M.B".into()],
                    },
                    NodeSpec::Leaf {
                        label: "M.A.2".into(),
                        hardware_key_id: ma2,
                        allowed_bridges: vec![],
                    },
                    NodeSpec::Leaf {
                        label: "M.A.3".into(),
                        hardware_key_id: ma3,
                        allowed_bridges: vec![],
                    },
                ],
            },
            NodeSpec::Leaf {
                label: "M.B".into(),
                hardware_key_id: mb,
                allowed_bridges: vec![],
            },
        ],
    }
}

pub(super) fn two_department_spec(software: i64, accounting: i64) -> NodeSpec {
    NodeSpec::flat_split(
        "M",
        2,
        vec![("M.S".into(), software), ("M.A".into(), accounting)],
    )
}

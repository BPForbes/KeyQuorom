//! Recursive key splitting: a secret is organized as a tree of nodes, each
//! either a LEAF (a Shamir share sealed to one registered encryption
//! hardware key) or a SPLIT (its own threshold, dividing its value among
//! its children, recursively). A flat "M-of-N hardware keys" quorum is
//! just a one-level tree — a single SPLIT root with N LEAF children.
//!
//! Turning a LEAF's `wrapped_share` back into raw share bytes needs a
//! hardware key's private key, which this project has no custody story
//! for yet (see README's Roadmap) — `reconstruct` below takes already
//! -unwrapped raw shares as opaque bytes; obtaining them is the caller's
//! responsibility.

use crate::error::{Error, Result};
use crate::keys;
use rusqlite::{params, Connection, Row};
use serde::Deserialize;
use sharks::{Share, Sharks};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum NodeSpec {
    Leaf {
        label: String,
        hardware_key_id: i64,
    },
    Split {
        label: String,
        threshold: u8,
        children: Vec<NodeSpec>,
    },
}

pub struct TreeNodeSummary {
    pub id: i64,
    pub label: String,
    pub threshold: Option<i64>,
    pub hardware_key_id: Option<i64>,
    pub hardware_key_label: Option<String>,
    pub children: Vec<TreeNodeSummary>,
}

pub struct TreeSummary {
    pub key_id: i64,
    pub label: String,
    pub root: TreeNodeSummary,
}

/// Every `Split`'s threshold must be in `1..=children.len()`, every `Leaf`
/// must reference an active encryption-purpose hardware key, and the tree
/// must contain at least one leaf overall.
pub fn validate(conn: &Connection, spec: &NodeSpec) -> Result<()> {
    let mut leaf_count = 0usize;
    validate_node(conn, spec, &mut leaf_count)?;
    if leaf_count == 0 {
        return Err(Error::InvalidQuorumThreshold);
    }
    Ok(())
}

fn validate_node(conn: &Connection, spec: &NodeSpec, leaf_count: &mut usize) -> Result<()> {
    match spec {
        NodeSpec::Leaf {
            hardware_key_id, ..
        } => {
            keys::get_active_encryption_key(conn, *hardware_key_id)?;
            *leaf_count += 1;
            Ok(())
        }
        NodeSpec::Split {
            threshold,
            children,
            ..
        } => {
            if children.is_empty() || *threshold == 0 || (*threshold as usize) > children.len() {
                return Err(Error::InvalidQuorumThreshold);
            }
            for child in children {
                validate_node(conn, child, leaf_count)?;
            }
            Ok(())
        }
    }
}

/// Creates a `keys` row and the whole `key_nodes` tree in one transaction:
/// recursively Shamir-splits `secret` at each `Split` node, and for each
/// child either seals-and-inserts a leaf or recurses with that child's
/// own share as the next level's secret. Rolls back entirely on any
/// failure — a half-built tree would be silently unrecoverable, not just
/// incomplete.
pub fn split(conn: &mut Connection, label: &str, secret: &[u8], spec: &NodeSpec) -> Result<i64> {
    let tx = conn.transaction()?;
    let key_id = build_tree(&tx, label, secret, spec)?;
    tx.commit()?;
    Ok(key_id)
}

/// Builds a key's tree using the given connection, which may already be
/// inside a transaction the caller manages (e.g. `quorum::lock_file`
/// combining this with its own `files` row insert into one atomic write).
/// Does not open or commit any transaction of its own.
pub(crate) fn build_tree(
    conn: &Connection,
    label: &str,
    secret: &[u8],
    spec: &NodeSpec,
) -> Result<i64> {
    validate(conn, spec)?;
    conn.execute("INSERT INTO keys (label) VALUES (?1)", params![label])?;
    let key_id = conn.last_insert_rowid();
    split_node(conn, key_id, None, secret, spec)?;
    Ok(key_id)
}

fn split_node(
    conn: &Connection,
    key_id: i64,
    parent_id: Option<i64>,
    secret: &[u8],
    spec: &NodeSpec,
) -> Result<()> {
    match spec {
        NodeSpec::Leaf {
            label,
            hardware_key_id,
        } => {
            let hardware_key = keys::get_active_encryption_key(conn, *hardware_key_id)?;
            let public_key_bytes: [u8; 32] = hardware_key.public_key[..]
                .try_into()
                .map_err(|_| Error::InvalidPublicKey)?;
            let public_key = crypto_box::PublicKey::from_bytes(public_key_bytes);
            let wrapped_share = public_key
                .seal(&mut rand::rngs::OsRng, secret)
                .expect("crypto_box sealing should not fail for an in-memory share");
            conn.execute(
                "INSERT INTO key_nodes (key_id, parent_id, label, hardware_key_id, wrapped_share)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![key_id, parent_id, label, hardware_key_id, wrapped_share],
            )?;
            Ok(())
        }
        NodeSpec::Split {
            label,
            threshold,
            children,
        } => {
            conn.execute(
                "INSERT INTO key_nodes (key_id, parent_id, label, threshold)
                 VALUES (?1, ?2, ?3, ?4)",
                params![key_id, parent_id, label, *threshold as i64],
            )?;
            let node_id = conn.last_insert_rowid();

            let sharks = Sharks(*threshold);
            let shares: Vec<Share> = sharks
                .dealer_rng(secret, &mut rand::rngs::OsRng)
                .take(children.len())
                .collect();

            for (child_spec, share) in children.iter().zip(shares.iter()) {
                let raw_share: Vec<u8> = Vec::from(share);
                split_node(conn, key_id, Some(node_id), &raw_share, child_spec)?;
            }
            Ok(())
        }
    }
}

/// `raw_shares` maps a leaf `key_nodes.id` to its already-unwrapped raw
/// share bytes (obtaining them is the deferred unwrap step — see the
/// module doc comment). Recursive bottom-up walk: a leaf resolves iff its
/// id is present in `raw_shares`; a split node resolves once at least
/// `threshold` of its children resolve (recursively), via
/// `Sharks::recover`. Returns `QuorumNotMet` if the root can't be
/// resolved.
pub fn reconstruct(
    conn: &Connection,
    key_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let root_id = root_node_id(conn, key_id)?;
    reconstruct_node(conn, root_id, raw_shares)
}

fn root_node_id(conn: &Connection, key_id: i64) -> Result<i64> {
    let root_id = conn.query_row(
        "SELECT id FROM key_nodes WHERE key_id = ?1 AND parent_id IS NULL",
        params![key_id],
        |row| row.get(0),
    )?;
    Ok(root_id)
}

fn reconstruct_node(
    conn: &Connection,
    node_id: i64,
    raw_shares: &HashMap<i64, Vec<u8>>,
) -> Result<Vec<u8>> {
    let (threshold, hardware_key_id): (Option<i64>, Option<i64>) = conn.query_row(
        "SELECT threshold, hardware_key_id FROM key_nodes WHERE id = ?1",
        params![node_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    if hardware_key_id.is_some() {
        return raw_shares.get(&node_id).cloned().ok_or(Error::QuorumNotMet);
    }

    let threshold = threshold.ok_or(Error::QuorumNotMet)? as usize;

    let mut stmt = conn.prepare("SELECT id FROM key_nodes WHERE parent_id = ?1 ORDER BY id")?;
    let child_ids: Vec<i64> = stmt
        .query_map(params![node_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let mut resolved: Vec<Share> = Vec::new();
    for child_id in child_ids {
        if resolved.len() >= threshold {
            break;
        }
        if let Ok(value) = reconstruct_node(conn, child_id, raw_shares) {
            let share = Share::try_from(value.as_slice()).map_err(|_| Error::QuorumNotMet)?;
            resolved.push(share);
        }
    }

    if resolved.len() < threshold {
        return Err(Error::QuorumNotMet);
    }

    Sharks(threshold as u8)
        .recover(resolved.iter())
        .map_err(|_| Error::QuorumNotMet)
}

/// Read-only tree summary — labels, thresholds, and which hardware key
/// backs each leaf — for `key tree <id>` / audit review.
pub fn describe(conn: &Connection, key_id: i64) -> Result<TreeSummary> {
    let label: String = conn.query_row(
        "SELECT label FROM keys WHERE id = ?1",
        params![key_id],
        |row| row.get(0),
    )?;
    let root_id = root_node_id(conn, key_id)?;
    let root = describe_node(conn, root_id)?;
    Ok(TreeSummary {
        key_id,
        label,
        root,
    })
}

fn describe_node(conn: &Connection, node_id: i64) -> Result<TreeNodeSummary> {
    let (label, threshold, hardware_key_id) = describe_row(conn, node_id)?;

    let hardware_key_label = match hardware_key_id {
        Some(id) => Some(keys::get_key(conn, id)?.label),
        None => None,
    };

    let mut stmt = conn.prepare("SELECT id FROM key_nodes WHERE parent_id = ?1 ORDER BY id")?;
    let child_ids: Vec<i64> = stmt
        .query_map(params![node_id], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(stmt);

    let mut children = Vec::with_capacity(child_ids.len());
    for child_id in child_ids {
        children.push(describe_node(conn, child_id)?);
    }

    Ok(TreeNodeSummary {
        id: node_id,
        label,
        threshold,
        hardware_key_id,
        hardware_key_label,
        children,
    })
}

fn describe_row(conn: &Connection, node_id: i64) -> Result<(String, Option<i64>, Option<i64>)> {
    let row = conn.query_row(
        "SELECT label, threshold, hardware_key_id FROM key_nodes WHERE id = ?1",
        params![node_id],
        |row: &Row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::keys::KeyType;

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
    fn flat_tree_round_trips_split_and_reconstruct() {
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

        let secret = b"the quorum has been reached!!!!".to_vec();
        let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
        let raw_b = unwrap_leaf_share(&conn, leaves[&"b".to_string()], &sk_b);

        let mut shares = HashMap::new();
        shares.insert(leaves[&"a".to_string()], raw_a);
        shares.insert(leaves[&"b".to_string()], raw_b);

        let recovered = reconstruct(&conn, key_id, &shares).expect("reconstruct should succeed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn flat_tree_reconstruct_fails_with_too_few_shares() {
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

        let secret = b"top secret data key value here!".to_vec();
        let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

        let leaves = leaf_ids_by_label(&conn, key_id);
        let raw_a = unwrap_leaf_share(&conn, leaves[&"a".to_string()], &sk_a);
        let mut shares = HashMap::new();
        shares.insert(leaves[&"a".to_string()], raw_a);

        let result = reconstruct(&conn, key_id, &shares);
        assert!(matches!(result, Err(Error::QuorumNotMet)));
    }

    #[test]
    fn nested_tree_round_trips_across_branches() {
        // "CEO alone" OR a 2-of-2 department quorum, where one department
        // (cxo) is itself split 2-of-2.
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ceo_id, _ceo_sk) = register_encryption_key(&conn, "ceo");
        let (cfo_id, cfo_sk) = register_encryption_key(&conn, "cfo");
        let (coo_id, coo_sk) = register_encryption_key(&conn, "coo");
        let (it_id, it_sk) = register_encryption_key(&conn, "it");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 1,
            children: vec![
                NodeSpec::Leaf {
                    label: "ceo".into(),
                    hardware_key_id: ceo_id,
                },
                NodeSpec::Split {
                    label: "departments".into(),
                    threshold: 2,
                    children: vec![
                        NodeSpec::Split {
                            label: "cxo".into(),
                            threshold: 2,
                            children: vec![
                                NodeSpec::Leaf {
                                    label: "cfo".into(),
                                    hardware_key_id: cfo_id,
                                },
                                NodeSpec::Leaf {
                                    label: "coo".into(),
                                    hardware_key_id: coo_id,
                                },
                            ],
                        },
                        NodeSpec::Leaf {
                            label: "it".into(),
                            hardware_key_id: it_id,
                        },
                    ],
                },
            ],
        };

        let secret = b"company master secret 32 bytes!".to_vec();
        let key_id = split(&mut conn, "nested", &secret, &spec).expect("split should succeed");
        let leaves = leaf_ids_by_label(&conn, key_id);

        let raw_cfo = unwrap_leaf_share(&conn, leaves[&"cfo".to_string()], &cfo_sk);
        let raw_coo = unwrap_leaf_share(&conn, leaves[&"coo".to_string()], &coo_sk);
        let raw_it = unwrap_leaf_share(&conn, leaves[&"it".to_string()], &it_sk);

        let mut shares = HashMap::new();
        shares.insert(leaves[&"cfo".to_string()], raw_cfo);
        shares.insert(leaves[&"coo".to_string()], raw_coo);
        shares.insert(leaves[&"it".to_string()], raw_it);

        let recovered = reconstruct(&conn, key_id, &shares)
            .expect("reconstruct should succeed via department branch");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn nested_tree_fails_when_a_branch_is_short_even_if_others_are_oversupplied() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (ceo_id, _ceo_sk) = register_encryption_key(&conn, "ceo");
        let (cfo_id, cfo_sk) = register_encryption_key(&conn, "cfo");
        let (coo_id, _coo_sk) = register_encryption_key(&conn, "coo");
        let (it_id, it_sk) = register_encryption_key(&conn, "it");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2, // needs 2 of {ceo, departments} — ceo alone is no longer enough
            children: vec![
                NodeSpec::Leaf {
                    label: "ceo".into(),
                    hardware_key_id: ceo_id,
                },
                NodeSpec::Split {
                    label: "departments".into(),
                    threshold: 2,
                    children: vec![
                        NodeSpec::Split {
                            label: "cxo".into(),
                            threshold: 2,
                            children: vec![
                                NodeSpec::Leaf {
                                    label: "cfo".into(),
                                    hardware_key_id: cfo_id,
                                },
                                NodeSpec::Leaf {
                                    label: "coo".into(),
                                    hardware_key_id: coo_id,
                                },
                            ],
                        },
                        NodeSpec::Leaf {
                            label: "it".into(),
                            hardware_key_id: it_id,
                        },
                    ],
                },
            ],
        };

        let secret = b"another 32-byte company secret!".to_vec();
        let key_id = split(&mut conn, "nested", &secret, &spec).expect("split should succeed");
        let leaves = leaf_ids_by_label(&conn, key_id);

        // Only cfo (not coo) from the cxo branch, plus it: cxo's own 2-of-2
        // is short by one, so "departments" can't resolve, and ceo wasn't
        // supplied either, so root's 2-of-2 has nothing to work with.
        let raw_cfo = unwrap_leaf_share(&conn, leaves[&"cfo".to_string()], &cfo_sk);
        let raw_it = unwrap_leaf_share(&conn, leaves[&"it".to_string()], &it_sk);

        let mut shares = HashMap::new();
        shares.insert(leaves[&"cfo".to_string()], raw_cfo);
        shares.insert(leaves[&"it".to_string()], raw_it);

        let result = reconstruct(&conn, key_id, &shares);
        assert!(matches!(result, Err(Error::QuorumNotMet)));
    }

    #[test]
    fn validate_rejects_threshold_above_children_count() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "a");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 2,
            children: vec![NodeSpec::Leaf {
                label: "a".into(),
                hardware_key_id: id_a,
            }],
        };

        assert!(matches!(
            validate(&conn, &spec),
            Err(Error::InvalidQuorumThreshold)
        ));
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "a");
        let (id_b, _) = register_encryption_key(&conn, "b");

        let spec = NodeSpec::Split {
            label: "root".into(),
            threshold: 0,
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

        assert!(matches!(
            validate(&conn, &spec),
            Err(Error::InvalidQuorumThreshold)
        ));
    }

    #[test]
    fn validate_rejects_signing_key_as_leaf() {
        let conn = db::open_in_memory().expect("schema should apply");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let id = keys::register_key(&conn, "signer", KeyType::Signing, &public_key)
            .expect("register_key should succeed");

        let spec = NodeSpec::Leaf {
            label: "leaf".into(),
            hardware_key_id: id,
        };
        assert!(matches!(validate(&conn, &spec), Err(Error::WrongKeyType)));
    }

    #[test]
    fn validate_rejects_revoked_key_as_leaf() {
        let conn = db::open_in_memory().expect("schema should apply");
        let (id, _) = register_encryption_key(&conn, "a");
        keys::revoke_key(&conn, id).expect("revoke_key should succeed");

        let spec = NodeSpec::Leaf {
            label: "leaf".into(),
            hardware_key_id: id,
        };
        assert!(matches!(validate(&conn, &spec), Err(Error::KeyRevoked)));
    }

    #[test]
    fn describe_reports_labels_thresholds_and_leaf_key_labels() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let (id_a, _) = register_encryption_key(&conn, "alice");
        let (id_b, _) = register_encryption_key(&conn, "bob");

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
        let secret = b"describe-me-describe-me-32bytes".to_vec();
        let key_id = split(&mut conn, "described", &secret, &spec).expect("split should succeed");

        let summary = describe(&conn, key_id).expect("describe should succeed");
        assert_eq!(summary.label, "described");
        assert_eq!(summary.root.threshold, Some(1));
        assert_eq!(summary.root.children.len(), 2);
        let labels: Vec<_> = summary
            .root
            .children
            .iter()
            .map(|c| c.hardware_key_label.clone().unwrap())
            .collect();
        assert!(labels.contains(&"alice".to_string()));
        assert!(labels.contains(&"bob".to_string()));
    }
}

use super::super::*;
use super::common::*;
use crate::db;
use std::collections::HashMap;

#[test]
fn flat_tree_round_trips_split_and_reconstruct() {
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

    let secret = b"the quorum has been reached!!!!".to_vec();
    let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unseal_leaf(&conn, leaves[&"a".to_string()], &sk_a);
    let raw_b = unseal_leaf(&conn, leaves[&"b".to_string()], &sk_b);

    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], raw_a);
    shares.insert(leaves[&"b".to_string()], raw_b);

    let recovered = reconstruct(&conn, key_id, &shares).expect("reconstruct should succeed");
    assert_eq!(recovered, secret);
}

#[test]
fn reconstruct_skips_a_malformed_share_instead_of_aborting() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _sk_a) = register_encryption_key(&conn, "a");
    let (id_b, sk_b) = register_encryption_key(&conn, "b");
    let (id_c, sk_c) = register_encryption_key(&conn, "c");

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

    let secret = b"the quorum has been reached!!!!".to_vec();
    let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_b = unseal_leaf(&conn, leaves[&"b".to_string()], &sk_b);
    let raw_c = unseal_leaf(&conn, leaves[&"c".to_string()], &sk_c);

    // A genuinely malformed "share" (not valid Share-encoded bytes)
    // for `a` — the first leaf tried, in id order, since children are
    // inserted in spec order — alongside two real, correctly-unwrapped
    // shares for b and c. Before the fix, hitting the malformed entry
    // while still under threshold aborted the *entire* reconstruction
    // via `?`, never even trying b or c.
    let mut shares = HashMap::new();
    shares.insert(leaves[&"a".to_string()], vec![0xFF]);
    shares.insert(leaves[&"b".to_string()], raw_b);
    shares.insert(leaves[&"c".to_string()], raw_c);

    let recovered = reconstruct(&conn, key_id, &shares)
        .expect("reconstruct should succeed despite one malformed share");
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

    let secret = b"top secret data key value here!".to_vec();
    let key_id = split(&mut conn, "flat", &secret, &spec).expect("split should succeed");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unseal_leaf(&conn, leaves[&"a".to_string()], &sk_a);
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
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "ceo".into(),
                hardware_key_id: ceo_id,
                allowed_bridges: vec![],
            },
            NodeSpec::Split {
                label: "departments".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![
                    NodeSpec::Split {
                        label: "cxo".into(),
                        threshold: 2,
                        allowed_bridges: vec![],
                        children: vec![
                            NodeSpec::Leaf {
                                label: "cfo".into(),
                                hardware_key_id: cfo_id,
                                allowed_bridges: vec![],
                            },
                            NodeSpec::Leaf {
                                label: "coo".into(),
                                hardware_key_id: coo_id,
                                allowed_bridges: vec![],
                            },
                        ],
                    },
                    NodeSpec::Leaf {
                        label: "it".into(),
                        hardware_key_id: it_id,
                        allowed_bridges: vec![],
                    },
                ],
            },
        ],
    };

    let secret = b"company master secret 32 bytes!".to_vec();
    let key_id = split(&mut conn, "nested", &secret, &spec).expect("split should succeed");
    let leaves = leaf_ids_by_label(&conn, key_id);

    let raw_cfo = unseal_leaf(&conn, leaves[&"cfo".to_string()], &cfo_sk);
    let raw_coo = unseal_leaf(&conn, leaves[&"coo".to_string()], &coo_sk);
    let raw_it = unseal_leaf(&conn, leaves[&"it".to_string()], &it_sk);

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
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "ceo".into(),
                hardware_key_id: ceo_id,
                allowed_bridges: vec![],
            },
            NodeSpec::Split {
                label: "departments".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![
                    NodeSpec::Split {
                        label: "cxo".into(),
                        threshold: 2,
                        allowed_bridges: vec![],
                        children: vec![
                            NodeSpec::Leaf {
                                label: "cfo".into(),
                                hardware_key_id: cfo_id,
                                allowed_bridges: vec![],
                            },
                            NodeSpec::Leaf {
                                label: "coo".into(),
                                hardware_key_id: coo_id,
                                allowed_bridges: vec![],
                            },
                        ],
                    },
                    NodeSpec::Leaf {
                        label: "it".into(),
                        hardware_key_id: it_id,
                        allowed_bridges: vec![],
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
    let raw_cfo = unseal_leaf(&conn, leaves[&"cfo".to_string()], &cfo_sk);
    let raw_it = unseal_leaf(&conn, leaves[&"it".to_string()], &it_sk);

    let mut shares = HashMap::new();
    shares.insert(leaves[&"cfo".to_string()], raw_cfo);
    shares.insert(leaves[&"it".to_string()], raw_it);

    let result = reconstruct(&conn, key_id, &shares);
    assert!(matches!(result, Err(Error::QuorumNotMet)));
}

#[test]
fn lca_of_department_siblings_is_the_department_node() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (ma1, _) = register_encryption_key(&conn, "ma1");
    let (ma2, _) = register_encryption_key(&conn, "ma2");
    let (ma3, _) = register_encryption_key(&conn, "ma3");
    let (mb, _) = register_encryption_key(&conn, "mb");
    let spec = department_tree_spec(ma1, ma2, ma3, mb);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

    let tree = KeyQuorumTree::load(&conn, key_id).expect("load should succeed");
    let a1 = tree.index_by_label("M.A.1").unwrap();
    let a2 = tree.index_by_label("M.A.2").unwrap();
    let mb_idx = tree.index_by_label("M.B").unwrap();
    let ma = tree.index_by_label("M.A").unwrap();

    assert_eq!(tree.find_lowest_common_ancestor(a1, a2).unwrap(), ma);
    assert_eq!(
        tree.find_lowest_common_ancestor(a1, mb_idx).unwrap(),
        tree.root_index
    );
    assert_eq!(tree.find_lowest_common_ancestor(a1, a1).unwrap(), a1);
    assert_eq!(
        tree.find_lowest_common_ancestor_of(&[a1, a2, ma]).unwrap(),
        ma
    );
}

#[test]
fn split_and_reconstruct_a_pub_file_payload() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "alice");
    let (id_b, sk_b) = register_encryption_key(&conn, "bob");
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
    let pub_file = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
    );
    let key_id = split(&mut conn, "master-pub", pub_file.as_bytes(), &spec)
        .expect("split should accept a pub-file payload");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut shares = HashMap::new();
    shares.insert(leaves["a"], unseal_leaf(&conn, leaves["a"], &sk_a));
    shares.insert(leaves["b"], unseal_leaf(&conn, leaves["b"], &sk_b));
    let recovered = reconstruct(&conn, key_id, &shares).expect("reconstruct");
    assert_eq!(recovered, pub_file.as_bytes());
}

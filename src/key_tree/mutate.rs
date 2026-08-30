use super::super::*;
use super::common::*;
use crate::db;
use std::collections::HashMap;

#[test]
fn unwrap_leaf_share_rejects_the_wrong_secret() {
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
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "flat", secret, &spec).expect("split should succeed");
    let leaves = leaf_ids_by_label(&conn, key_id);
    assert!(super::super::unwrap_leaf_share(&conn, leaves["a"], &sk_b.to_bytes()).is_err());
    let raw = super::super::unwrap_leaf_share(&conn, leaves["a"], &sk_a.to_bytes())
        .expect("matching secret should unwrap");
    assert!(!raw.is_empty());
}

#[test]
fn export_spec_omits_inactive_leaves_and_keeps_binds() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let spec = two_department_spec(id_s, id_a);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "master", secret, &spec).expect("split");
    bind_all_sibling_leaf_pairs(&conn, key_id).expect("auto-bind");
    let exported = export_spec(&conn, key_id).expect("export");
    match exported {
        NodeSpec::Split {
            label,
            threshold,
            children,
            ..
        } => {
            assert_eq!(label, "M");
            assert_eq!(threshold, 2);
            assert_eq!(children.len(), 2);
            let mut peers = children[0].allowed_bridges().to_vec();
            peers.sort();
            assert!(peers.contains(&"M.A".to_string()) || peers.contains(&"M.S".to_string()));
        }
        NodeSpec::Leaf { .. } => panic!("expected split"),
    }

    let (id_f, _sk_f) = register_encryption_key(&conn, "finance");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut presented = HashMap::new();
    presented.insert(leaves["M.S"], unseal_leaf(&conn, leaves["M.S"], &sk_s));
    presented.insert(leaves["M.A"], unseal_leaf(&conn, leaves["M.A"], &sk_a));
    add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &presented).expect("add");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let evicted = leaves["M.F"];
    let mut survivors = HashMap::new();
    survivors.insert(leaves["M.S"], unseal_leaf(&conn, leaves["M.S"], &sk_s));
    survivors.insert(leaves["M.A"], unseal_leaf(&conn, leaves["M.A"], &sk_a));
    evict_and_refresh(&mut conn, key_id, evicted, &survivors).expect("evict finance");
    match export_spec(&conn, key_id).expect("export after evict") {
        NodeSpec::Split { children, .. } => {
            let labels: Vec<_> = children.iter().map(|c| c.label().to_string()).collect();
            assert_eq!(labels, vec!["M.S".to_string(), "M.A".to_string()]);
        }
        NodeSpec::Leaf { .. } => panic!("expected split"),
    }
}

#[test]
fn add_leaf_rejects_duplicate_or_zero_share_coordinates() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let (id_f, _sk_f) = register_encryption_key(&conn, "finance");
    let spec = two_department_spec(id_s, id_a);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "master", secret, &spec).expect("split");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_s = unseal_leaf(&conn, leaves["M.S"], &sk_s);
    let raw_a = unseal_leaf(&conn, leaves["M.A"], &sk_a);
    let before = wrapped_shares_by_id(&conn, key_id);

    let mut duplicate = HashMap::new();
    duplicate.insert(leaves["M.S"], raw_s.clone());
    duplicate.insert(leaves["M.A"], raw_s.clone());
    assert!(matches!(
        add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &duplicate),
        Err(Error::ShareShapeMismatch)
    ));
    assert_eq!(wrapped_shares_by_id(&conn, key_id), before);

    let mut zero_x = raw_s.clone();
    zero_x[0] = 0;
    let mut with_zero = HashMap::new();
    with_zero.insert(leaves["M.S"], zero_x);
    with_zero.insert(leaves["M.A"], raw_a.clone());
    assert!(matches!(
        add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &with_zero),
        Err(Error::ShareShapeMismatch)
    ));
    assert_eq!(wrapped_shares_by_id(&conn, key_id), before);

    let mut distinct = HashMap::new();
    distinct.insert(leaves["M.S"], raw_s);
    distinct.insert(leaves["M.A"], raw_a);
    add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &distinct)
        .expect("distinct shares should add");
    assert_ne!(wrapped_shares_by_id(&conn, key_id), before);
}

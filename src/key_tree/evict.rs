use super::super::*;
use super::common::*;
use crate::db;
use std::collections::HashMap;

#[test]
fn evicting_ma3_lets_survivors_reach_root_without_the_parent_or_old_share() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id1, sk1) = register_encryption_key(&conn, "ma1");
    let (id2, sk2) = register_encryption_key(&conn, "ma2");
    let (id3, sk3) = register_encryption_key(&conn, "ma3");
    let (idb, _skb) = register_encryption_key(&conn, "mb");
    let spec = department_tree_spec(id1, id2, id3, idb);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw1 = unseal_leaf(&conn, leaves["M.A.1"], &sk1);
    let raw2 = unseal_leaf(&conn, leaves["M.A.2"], &sk2);
    let raw3 = unseal_leaf(&conn, leaves["M.A.3"], &sk3);

    let mut before = HashMap::new();
    before.insert(leaves["M.A.1"], raw1.clone());
    before.insert(leaves["M.A.2"], raw2.clone());
    assert_eq!(reconstruct(&conn, key_id, &before).unwrap(), secret);

    let mut survivors = HashMap::new();
    survivors.insert(leaves["M.A.1"], raw1.clone());
    survivors.insert(leaves["M.A.2"], raw2.clone());
    evict_and_refresh(&mut conn, key_id, leaves["M.A.3"], &survivors)
        .expect("evict should succeed");

    let tree = KeyQuorumTree::load(&conn, key_id).expect("load should succeed");
    let ma = tree.index_by_label("M.A").unwrap();
    assert_eq!(tree.nodes[ma].threshold, Some(2));
    assert!(!tree.nodes[tree.index_by_label("M.A.3").unwrap()].is_active);

    let new1 = unseal_leaf(&conn, leaves["M.A.1"], &sk1);
    let new2 = unseal_leaf(&conn, leaves["M.A.2"], &sk2);
    let mut after = HashMap::new();
    after.insert(leaves["M.A.1"], new1.clone());
    after.insert(leaves["M.A.2"], new2.clone());
    assert_eq!(reconstruct(&conn, key_id, &after).unwrap(), secret);

    let lca = tree
        .find_lowest_common_ancestor(
            tree.index_by_label("M.A.1").unwrap(),
            tree.index_by_label("M.A.2").unwrap(),
        )
        .unwrap();
    assert_eq!(
        reconstruct_from_lca(&conn, key_id, lca, &after).unwrap(),
        secret
    );

    let mut stale = HashMap::new();
    stale.insert(leaves["M.A.1"], new1);
    stale.insert(leaves["M.A.3"], raw3);
    assert!(matches!(
        reconstruct(&conn, key_id, &stale),
        Err(Error::QuorumNotMet)
    ));
}

#[test]
fn evict_rejects_the_same_raw_share_for_two_survivors() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id1, sk1) = register_encryption_key(&conn, "ma1");
    let (id2, _) = register_encryption_key(&conn, "ma2");
    let (id3, _) = register_encryption_key(&conn, "ma3");
    let (idb, _) = register_encryption_key(&conn, "mb");
    let spec = department_tree_spec(id1, id2, id3, idb);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw1 = unseal_leaf(&conn, leaves["M.A.1"], &sk1);
    let mut survivors = HashMap::new();
    survivors.insert(leaves["M.A.1"], raw1.clone());
    survivors.insert(leaves["M.A.2"], raw1);
    assert!(matches!(
        evict_and_refresh(&mut conn, key_id, leaves["M.A.3"], &survivors),
        Err(Error::ShareShapeMismatch)
    ));
    let tree = KeyQuorumTree::load(&conn, key_id).expect("load should succeed");
    assert!(tree.nodes[tree.index_by_label("M.A.3").unwrap()].is_active);
}

#[test]
fn evict_rejects_a_parent_threshold_of_one() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_a, sk_a) = register_encryption_key(&conn, "a");
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
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "flat", secret, &spec).expect("split should succeed");
    let leaves = leaf_ids_by_label(&conn, key_id);
    let raw_a = unseal_leaf(&conn, leaves["a"], &sk_a);
    let mut survivors = HashMap::new();
    survivors.insert(leaves["a"], raw_a);
    assert!(matches!(
        evict_and_refresh(&mut conn, key_id, leaves["b"], &survivors),
        Err(Error::CannotEvict)
    ));
}

#[test]
fn evict_drops_binds_that_mention_the_evicted_node() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id1, sk1) = register_encryption_key(&conn, "ma1");
    let (id2, sk2) = register_encryption_key(&conn, "ma2");
    let (id3, _sk3) = register_encryption_key(&conn, "ma3");
    let (idb, _skb) = register_encryption_key(&conn, "mb");
    let spec = department_tree_spec(id1, id2, id3, idb);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "org", secret, &spec).expect("split");
    add_bridge(&conn, key_id, "M.A.1", "M.B").expect("keep this bind");
    bind_pair(&conn, key_id, "M.A.1", "M.A.3").expect("bind to evicted");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let mut survivors = HashMap::new();
    survivors.insert(leaves["M.A.1"], unseal_leaf(&conn, leaves["M.A.1"], &sk1));
    survivors.insert(leaves["M.A.2"], unseal_leaf(&conn, leaves["M.A.2"], &sk2));
    evict_and_refresh(&mut conn, key_id, leaves["M.A.3"], &survivors).expect("evict");

    let listing = list_bridges(&conn, key_id).expect("list");
    assert!(listing
        .established
        .iter()
        .any(|l| { (l.from == "M.A.1" && l.to == "M.B") || (l.from == "M.B" && l.to == "M.A.1") }));
    assert!(!listing
        .established
        .iter()
        .any(|l| l.from == "M.A.3" || l.to == "M.A.3"));
    assert!(!listing
        .allowed
        .iter()
        .any(|(from, to)| from == "M.A.3" || to == "M.A.3"));
}

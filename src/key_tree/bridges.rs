use super::super::*;
use super::common::*;
use crate::db;
use std::collections::HashMap;

#[test]
fn bridge_allow_add_remove_and_deny() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (ma1, _) = register_encryption_key(&conn, "ma1");
    let (ma2, _) = register_encryption_key(&conn, "ma2");
    let (ma3, _) = register_encryption_key(&conn, "ma3");
    let (mb, _) = register_encryption_key(&conn, "mb");
    let spec = department_tree_spec(ma1, ma2, ma3, mb);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

    add_bridge(&conn, key_id, "M.A.1", "M.B").expect("spec whitelist should allow");
    let listing = list_bridges(&conn, key_id).expect("list should succeed");
    assert!(listing
        .established
        .iter()
        .any(|l| (l.from == "M.A.1" && l.to == "M.B") || (l.from == "M.B" && l.to == "M.A.1")));

    remove_bridge(&conn, key_id, "M.B", "M.A.1").expect("remove should succeed");
    assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
    assert!(matches!(
        remove_bridge(&conn, key_id, "M.A.1", "M.B"),
        Err(Error::BridgeNotFound)
    ));

    assert!(matches!(
        add_bridge(&conn, key_id, "M.A.2", "M.B"),
        Err(Error::BridgeNotWhitelisted)
    ));
    allow_bridge(&conn, key_id, "M.A.2", "M.B").expect("allow should succeed");
    add_bridge(&conn, key_id, "M.A.2", "M.B").expect("now whitelisted");
    deny_bridge(&conn, key_id, "M.A.2", "M.B").expect("deny should succeed");
    assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
    assert!(matches!(
        add_bridge(&conn, key_id, "M.A.2", "M.B"),
        Err(Error::BridgeNotWhitelisted)
    ));
    assert!(matches!(
        add_bridge(&conn, key_id, "missing", "M.B"),
        Err(Error::NodeNotFound)
    ));
}

#[test]
fn deny_bridge_removes_the_reverse_whitelist_entry() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (ma1, _) = register_encryption_key(&conn, "ma1");
    let (ma2, _) = register_encryption_key(&conn, "ma2");
    let (ma3, _) = register_encryption_key(&conn, "ma3");
    let (mb, _) = register_encryption_key(&conn, "mb");
    let spec = department_tree_spec(ma1, ma2, ma3, mb);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "org", secret, &spec).expect("split should succeed");

    // Spec already whitelists M.A.1 -> M.B; add the reverse so either
    // side would authorize a pairing after a one-way deny.
    allow_bridge(&conn, key_id, "M.B", "M.A.1").expect("reverse allow should succeed");
    add_bridge(&conn, key_id, "M.A.1", "M.B").expect("either whitelist should allow");
    deny_bridge(&conn, key_id, "M.A.1", "M.B").expect("deny should succeed");
    assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
    assert!(matches!(
        add_bridge(&conn, key_id, "M.B", "M.A.1"),
        Err(Error::BridgeNotWhitelisted)
    ));
}

#[test]
fn bind_survives_rebind_and_adding_a_leaf() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, sk_s) = register_encryption_key(&conn, "software");
    let (id_a, sk_a) = register_encryption_key(&conn, "accounting");
    let (id_new_s, sk_new_s) = register_encryption_key(&conn, "software-new");
    let (id_f, sk_f) = register_encryption_key(&conn, "finance");
    let spec = two_department_spec(id_s, id_a);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "master", secret, &spec).expect("split");
    bind_pair(&conn, key_id, "M.S", "M.A").expect("bind departments");

    let leaves = leaf_ids_by_label(&conn, key_id);
    let ms_id = leaves["M.S"];
    let ma_id = leaves["M.A"];
    rebind_leaf(&conn, key_id, "M.S", id_new_s, &sk_s.to_bytes()).expect("rebind");
    assert_eq!(leaf_ids_by_label(&conn, key_id)["M.S"], ms_id);
    let listing = list_bridges(&conn, key_id).expect("list");
    assert!(listing
        .established
        .iter()
        .any(|l| { (l.from == "M.S" && l.to == "M.A") || (l.from == "M.A" && l.to == "M.S") }));

    let mut after_rebind = HashMap::new();
    after_rebind.insert(ms_id, unseal_leaf(&conn, ms_id, &sk_new_s));
    after_rebind.insert(ma_id, unseal_leaf(&conn, ma_id, &sk_a));
    assert_eq!(reconstruct(&conn, key_id, &after_rebind).unwrap(), secret);

    let new_id = add_leaf_and_reshare(&mut conn, key_id, "M", "M.F", id_f, &after_rebind)
        .expect("add finance");
    assert_eq!(leaf_ids_by_label(&conn, key_id)["M.S"], ms_id);
    assert_eq!(leaf_ids_by_label(&conn, key_id)["M.A"], ma_id);
    assert_eq!(leaf_ids_by_label(&conn, key_id)["M.F"], new_id);
    let listing = list_bridges(&conn, key_id).expect("list after add");
    assert!(listing
        .established
        .iter()
        .any(|l| { (l.from == "M.S" && l.to == "M.A") || (l.from == "M.A" && l.to == "M.S") }));

    let new_s = unseal_leaf(&conn, ms_id, &sk_new_s);
    let new_a = unseal_leaf(&conn, ma_id, &sk_a);
    let new_f = unseal_leaf(&conn, new_id, &sk_f);
    let mut survivors = HashMap::new();
    survivors.insert(ms_id, new_s.clone());
    survivors.insert(ma_id, new_a.clone());
    assert_eq!(reconstruct(&conn, key_id, &survivors).unwrap(), secret);
    let mut with_new = HashMap::new();
    with_new.insert(ms_id, new_s);
    with_new.insert(new_id, new_f);
    assert_eq!(reconstruct(&conn, key_id, &with_new).unwrap(), secret);
    // A full old quorum still encodes the same secret (Shamir). Mixing
    // one old share with one new-polynomial share must not.
    let mut mixed = HashMap::new();
    mixed.insert(ms_id, after_rebind[&ms_id].clone());
    mixed.insert(ma_id, new_a);
    if let Ok(mixed_secret) = reconstruct(&conn, key_id, &mixed) {
        assert_ne!(
            mixed_secret, secret,
            "mixed-generation sibling shares must not yield the parent secret"
        );
    }
}

#[test]
fn revoke_drops_every_bind_for_that_hardware_key() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (id_s, _) = register_encryption_key(&conn, "software");
    let (id_a, _) = register_encryption_key(&conn, "accounting");
    let spec = two_department_spec(id_s, id_a);
    let secret = b"company master secret 32 bytes!";
    let key_id = split(&mut conn, "master", secret, &spec).expect("split");
    bind_all_sibling_leaf_pairs(&conn, key_id).expect("bind");
    assert!(!list_bridges(&conn, key_id).unwrap().established.is_empty());
    let trees = list_trees(&conn).expect("list trees");
    assert_eq!(trees.len(), 1);
    assert_eq!(trees[0].label, "master");
    let dropped = drop_bindings_for_hardware(&conn, id_s).expect("drop");
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].label, "M.S");
    assert!(list_bridges(&conn, key_id).unwrap().established.is_empty());
    assert!(list_bridges(&conn, key_id)
        .unwrap()
        .allowed
        .iter()
        .all(|(from, to)| from != "M.S" && to != "M.S"));
}

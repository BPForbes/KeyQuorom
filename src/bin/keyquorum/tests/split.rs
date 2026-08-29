use super::super::*;

#[test]
fn collect_shares_unwraps_from_standard_key_files() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (sk_a, pk_a) = keys::generate_encryption_keypair();
    let (sk_b, pk_b) = keys::generate_encryption_keypair();
    let id_a = keys::register_key(&conn, "alice", keys::KeyType::Encryption, &pk_a)
        .expect("register alice");
    let id_b =
        keys::register_key(&conn, "bob", keys::KeyType::Encryption, &pk_b).expect("register bob");
    let spec = NodeSpec::Split {
        label: "team".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "alice".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "bob".into(),
                hardware_key_id: id_b,
                allowed_bridges: vec![],
            },
        ],
    };
    let secret = b"company master secret 32 bytes!";
    let key_id = key_tree::split(&mut conn, "team", secret, &spec).expect("split");
    let summary = key_tree::describe(&conn, key_id).expect("describe");

    let dir = tempfile::tempdir().expect("tempdir");
    let alice_key = dir.path().join("alice.key");
    let bob_pub = dir.path().join("bob.pub");
    let bob_key = dir.path().join("bob.key");
    fs::write(&alice_key, hex::encode(*sk_a)).expect("write alice.key");
    fs::write(&bob_pub, hex::encode(pk_b)).expect("write bob.pub");
    fs::write(&bob_key, hex::encode(*sk_b)).expect("write bob.key");

    let shares = collect_shares(
        &conn,
        &summary.root,
        &[
            alice_key.to_str().unwrap().to_string(),
            bob_pub.to_str().unwrap().to_string(),
        ],
    )
    .expect("key files should unwrap leaf shares");
    let recovered = key_tree::reconstruct(&conn, key_id, &shares).expect("reconstruct");
    assert_eq!(recovered, secret);
}

#[test]
fn split_and_reassemble_a_pub_file() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (sk_a, pk_a) = keys::generate_encryption_keypair();
    let (sk_b, pk_b) = keys::generate_encryption_keypair();
    let id_a = keys::register_key(&conn, "alice", keys::KeyType::Encryption, &pk_a)
        .expect("register alice");
    let id_b =
        keys::register_key(&conn, "bob", keys::KeyType::Encryption, &pk_b).expect("register bob");

    let dir = tempfile::tempdir().expect("tempdir");
    let alice_pub = dir.path().join("alice.pub");
    let alice_key = dir.path().join("alice.key");
    let bob_key = dir.path().join("bob.key");
    let master_pub = dir.path().join("master.pub");
    let out_pub = dir.path().join("master-out.pub");
    fs::write(&alice_pub, hex::encode(pk_a)).expect("write alice.pub");
    fs::write(&alice_key, hex::encode(*sk_a)).expect("write alice.key");
    fs::write(&bob_key, hex::encode(*sk_b)).expect("write bob.key");
    let master_body = format!("{}\n", hex::encode([0xCDu8; 32]));
    fs::write(&master_pub, &master_body).expect("write master.pub");

    let spec = NodeSpec::flat_split(
        "team",
        2,
        vec![("alice".into(), id_a), ("bob".into(), id_b)],
    );

    let payload = read_key_file_payload(&master_pub).expect("payload");
    let key_id = key_tree::split(&mut conn, "master pub", &payload, &spec).expect("split");
    let summary = key_tree::describe(&conn, key_id).expect("describe");
    let shares = collect_shares(
        &conn,
        &summary.root,
        &[
            alice_key.to_str().unwrap().to_string(),
            bob_key.to_str().unwrap().to_string(),
        ],
    )
    .expect("unwrap holders");
    let recovered = key_tree::reconstruct(&conn, key_id, &shares).expect("reconstruct");
    write_reassembled_secret(&recovered, Some(&out_pub)).expect("write");
    assert_eq!(
        fs::read(&out_pub).expect("read out"),
        master_body.as_bytes()
    );
}

#[test]
fn nested_snapshot_still_resolves_public_key_files() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (_sk_a, pk_a) = keys::generate_encryption_keypair();
    let id_a = keys::register_key(&conn, "alice", keys::KeyType::Encryption, &pk_a)
        .expect("register alice");
    let dir = tempfile::tempdir().expect("tempdir");
    let alice_pub = dir.path().join("alice.pub");
    let snapshot = dir.path().join("nested.json");
    fs::write(&alice_pub, hex::encode(pk_a)).expect("write alice.pub");
    fs::write(
        &snapshot,
        r#"{"label":"root","threshold":1,"children":[
            {"label":"alice","public_key_file":"alice.pub"}
        ]}"#,
    )
    .expect("write snapshot");
    let spec = parse_tree_spec(&conn, &snapshot).expect("snapshot should resolve pub files");
    match spec {
        NodeSpec::Split { children, .. } => match &children[0] {
            NodeSpec::Leaf {
                hardware_key_id, ..
            } => assert_eq!(*hardware_key_id, id_a),
            NodeSpec::Split { .. } => panic!("expected leaf"),
        },
        NodeSpec::Leaf { .. } => panic!("expected split"),
    }
}

#[test]
fn split_from_leaves_builds_and_binds_the_live_tree() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir");
    let software_pub = dir.path().join("SoftwareDepartment.pub");
    let accounting_pub = dir.path().join("AccountingDepartment.pub");
    let master_pub = dir.path().join("master.pub");
    let snapshot = dir.path().join("org.json");
    let master_body = format!("{}\n", hex::encode([0x11u8; 32]));
    fs::write(&master_pub, &master_body).expect("write master.pub");

    let spec = build_spec_from_leaves(
        &conn,
        "master",
        None,
        2,
        &[
            format!("M.S={}", software_pub.display()),
            format!("M.A={}", accounting_pub.display()),
        ],
        true,
        true,
    )
    .expect("leaves should become a spec");
    match &spec {
        NodeSpec::Split {
            label, threshold, ..
        } => {
            assert_eq!(label, "M");
            assert_eq!(*threshold, 2);
        }
        NodeSpec::Leaf { .. } => panic!("expected split"),
    }
    assert!(software_pub.is_file());
    assert!(dir.path().join("SoftwareDepartment.key").is_file());
    assert!(accounting_pub.is_file());
    assert_eq!(keys::list_keys(&conn).expect("list").len(), 2);

    let payload = read_key_file_payload(&master_pub).expect("payload");
    let key_id = key_tree::split(&mut conn, "master", &payload, &spec).expect("split");
    key_tree::bind_all_sibling_leaf_pairs(&conn, key_id).expect("auto-bind");
    let listing = key_tree::list_bridges(&conn, key_id).expect("list");
    assert!(listing
        .established
        .iter()
        .any(|l| { (l.from == "M.S" && l.to == "M.A") || (l.from == "M.A" && l.to == "M.S") }));

    write_live_spec(&conn, key_id, &snapshot).expect("export");
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&snapshot).expect("read snapshot"))
            .expect("spec json");
    assert_eq!(parsed["label"], "M");
    assert_eq!(parsed["threshold"], 2);
    assert_eq!(parsed["children"][0]["label"], "M.S");
    assert!(parsed["children"][0].get("public_key_file").is_none());
    assert!(parsed["children"][0]["hardware_key_id"].is_number());
}

#[test]
fn reconstruct_department_pubs_yields_master_pub() {
    let mut conn = db::open_in_memory().expect("schema should apply");
    let (sk_s, pk_s) = keys::generate_encryption_keypair();
    let (sk_a, pk_a) = keys::generate_encryption_keypair();
    keys::register_key(&conn, "software", keys::KeyType::Encryption, &pk_s)
        .expect("register software");
    keys::register_key(&conn, "accounting", keys::KeyType::Encryption, &pk_a)
        .expect("register accounting");

    let dir = tempfile::tempdir().expect("tempdir");
    let software_pub = dir.path().join("SoftwareDepartment.pub");
    let software_key = dir.path().join("SoftwareDepartment.key");
    let accounting_pub = dir.path().join("AccountingDepartment.pub");
    let accounting_key = dir.path().join("AccountingDepartment.key");
    let master_pub = dir.path().join("master.pub");
    let out_pub = dir.path().join("master-out.pub");
    fs::write(&software_pub, hex::encode(pk_s)).expect("write software pub");
    fs::write(&software_key, hex::encode(*sk_s)).expect("write software key");
    fs::write(&accounting_pub, hex::encode(pk_a)).expect("write accounting pub");
    fs::write(&accounting_key, hex::encode(*sk_a)).expect("write accounting key");
    let master_body = format!("{}\n", hex::encode([0x11u8; 32]));
    fs::write(&master_pub, &master_body).expect("write master.pub");

    let spec = build_spec_from_leaves(
        &conn,
        "master",
        None,
        2,
        &[
            format!("M.S={}", software_pub.display()),
            format!("M.A={}", accounting_pub.display()),
        ],
        false,
        false,
    )
    .expect("leaves should become a live spec");
    let payload = read_key_file_payload(&master_pub).expect("payload");
    let key_id = key_tree::split(&mut conn, "master", &payload, &spec).expect("split");
    let summary = key_tree::describe(&conn, key_id).expect("describe");
    let shares = collect_shares(
        &conn,
        &summary.root,
        &[
            software_pub.to_str().unwrap().to_string(),
            accounting_pub.to_str().unwrap().to_string(),
        ],
    )
    .expect("department pubs should unwrap with sibling .key files");

    let from_root = key_tree::reconstruct(&conn, key_id, &shares).expect("root reconstruct");
    assert_eq!(from_root, master_body.as_bytes());
    let software_only: HashMap<_, _> = shares
        .iter()
        .take(1)
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    assert!(
        key_tree::reconstruct(&conn, key_id, &software_only).is_err(),
        "threshold 2 must refuse a single department"
    );

    let tree = key_tree::KeyQuorumTree::load(&conn, key_id).expect("load");
    let idx_s = resolve_node_index(&conn, &tree, software_pub.to_str().unwrap())
        .expect("M.S from software pub");
    let idx_a = resolve_node_index(&conn, &tree, accounting_pub.to_str().unwrap())
        .expect("M.A from accounting pub");
    assert_eq!(tree.nodes[idx_s].id, "M.S");
    assert_eq!(tree.nodes[idx_a].id, "M.A");
    let lca = tree
        .find_lowest_common_ancestor(idx_s, idx_a)
        .expect("LCA of the departments is M");
    assert_eq!(tree.nodes[lca].id, "M");
    let from_lca =
        key_tree::reconstruct_from_lca(&conn, key_id, lca, &shares).expect("LCA reconstruct");
    write_reassembled_secret(&from_lca, Some(&out_pub)).expect("write");
    assert_eq!(
        fs::read(&out_pub).expect("read out"),
        master_body.as_bytes()
    );
}

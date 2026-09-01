use super::super::*;
use super::common::*;
use crate::db;
use crate::error::Error;
use rusqlite::params;
use std::collections::{HashMap, HashSet};

fn two_branch_org_spec(a1: i64, a2: i64, s1: i64, s2: i64) -> NodeSpec {
    NodeSpec::Split {
        label: "M".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Split {
                label: "M.A".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![
                    NodeSpec::Leaf {
                        label: "M.A.1".into(),
                        hardware_key_id: a1,
                        allowed_bridges: vec![],
                    },
                    NodeSpec::Leaf {
                        label: "M.A.2".into(),
                        hardware_key_id: a2,
                        allowed_bridges: vec![],
                    },
                ],
            },
            NodeSpec::Split {
                label: "M.S".into(),
                threshold: 2,
                allowed_bridges: vec![],
                children: vec![
                    NodeSpec::Leaf {
                        label: "M.S.1".into(),
                        hardware_key_id: s1,
                        allowed_bridges: vec![],
                    },
                    NodeSpec::Leaf {
                        label: "M.S.2".into(),
                        hardware_key_id: s2,
                        allowed_bridges: vec![],
                    },
                ],
            },
        ],
    }
}

fn labels(conn: &rusqlite::Connection, key_id: i64) -> HashSet<String> {
    let mut stmt = conn
        .prepare("SELECT label FROM key_nodes WHERE key_id = ?1")
        .unwrap();
    stmt.query_map(params![key_id], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<HashSet<_>>>()
        .unwrap()
}

fn wrapped_share(conn: &rusqlite::Connection, key_id: i64, label: &str) -> Option<Vec<u8>> {
    conn.query_row(
        "SELECT wrapped_share FROM key_nodes WHERE key_id = ?1 AND label = ?2",
        params![key_id, label],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn ms2_sees_lineage_siblings_and_bridge_peer_but_not_peer_sibling() {
    let mut conn = db::open_in_memory().expect("schema");
    let (a1, _) = register_encryption_key(&conn, "a1");
    let (a2, _) = register_encryption_key(&conn, "a2");
    let (s1, _) = register_encryption_key(&conn, "s1");
    let (s2, _) = register_encryption_key(&conn, "s2");
    let spec = two_branch_org_spec(a1, a2, s1, s2);
    let key_id = split(&mut conn, "org", b"company master secret 32 bytes!", &spec).expect("split");

    let without_bridge = visible_labels(&conn, key_id, "M.S.2").expect("visible");
    assert_eq!(
        without_bridge,
        HashSet::from(["M".into(), "M.S".into(), "M.S.1".into(), "M.S.2".into(),])
    );

    allow_bridge(&conn, key_id, "M.S.2", "M.A.2").expect("whitelist");
    let still_without_link = visible_labels(&conn, key_id, "M.S.2").expect("visible");
    assert_eq!(still_without_link, without_bridge);

    add_bridge(&conn, key_id, "M.S.2", "M.A.2").expect("establish");
    let with_peer = visible_labels(&conn, key_id, "M.S.2").expect("visible");
    assert_eq!(
        with_peer,
        HashSet::from([
            "M".into(),
            "M.A".into(),
            "M.A.2".into(),
            "M.S".into(),
            "M.S.1".into(),
            "M.S.2".into(),
        ])
    );
    assert!(!with_peer.contains("M.A.1"));

    bind_pair(&conn, key_id, "M.S.2", "M.A.1").expect("second bridge");
    let full = visible_labels(&conn, key_id, "M.S.2").expect("visible");
    assert!(full.contains("M.A.1"));
}

#[test]
fn project_local_drops_irrelevant_leaves_and_keeps_own_share() {
    let mut conn = db::open_in_memory().expect("schema");
    let (a1, _) = register_encryption_key(&conn, "a1");
    let (a2, _) = register_encryption_key(&conn, "a2");
    let (s1, _) = register_encryption_key(&conn, "s1");
    let (s2, _) = register_encryption_key(&conn, "s2");
    let spec = two_branch_org_spec(a1, a2, s1, s2);
    let key_id = split(&mut conn, "org", b"company master secret 32 bytes!", &spec).expect("split");
    bind_pair(&conn, key_id, "M.S.2", "M.A.2").expect("bridge");
    allow_bridge(&conn, key_id, "M.S.2", "M.A.1").expect("future peer");
    let own_share = wrapped_share(&conn, key_id, "M.S.2").expect("own share");

    project_local(&conn, key_id, "M.S.2").expect("project");
    assert_eq!(
        labels(&conn, key_id),
        HashSet::from([
            "M".into(),
            "M.A".into(),
            "M.A.2".into(),
            "M.S".into(),
            "M.S.1".into(),
            "M.S.2".into(),
        ])
    );
    assert_eq!(
        wrapped_share(&conn, key_id, "M.S.2").as_deref(),
        Some(own_share.as_slice())
    );
    let future_peer: i64 = conn
        .query_row(
            "SELECT count(*) FROM key_node_bridges
             WHERE node_id = (SELECT id FROM key_nodes WHERE key_id = ?1 AND label = 'M.S.2')
               AND peer_label = 'M.A.1'",
            params![key_id],
            |row| row.get(0),
        )
        .expect("preserved whitelist");
    assert_eq!(future_peer, 1);
}

#[test]
fn fetch_slice_can_add_a_topology_only_peer_after_a_new_bridge() {
    let mut operator = db::open_in_memory().expect("schema");
    let (a1, _) = register_encryption_key(&operator, "a1");
    let (a2, _) = register_encryption_key(&operator, "a2");
    let (s1, _) = register_encryption_key(&operator, "s1");
    let (s2, _) = register_encryption_key(&operator, "s2");
    let spec = two_branch_org_spec(a1, a2, s1, s2);
    let key_id = split(
        &mut operator,
        "org",
        b"company master secret 32 bytes!",
        &spec,
    )
    .expect("split");
    bind_pair(&operator, key_id, "M.S.2", "M.A.2").expect("first bridge");

    let personal = db::open_in_memory().expect("personal");
    let first = export_public_tree(&operator, key_id).expect("export");
    let seed = ["M.S.2".to_string()];
    let visible = visible_labels_in_public_tree(&first, &seed);
    let slice = filter_public_tree(&first, &visible);
    let personal_id = apply_public_tree(&personal, None, &slice).expect("first fetch");
    assert!(!labels(&personal, personal_id).contains("M.A.1"));
    assert!(labels(&personal, personal_id).contains("M.A.2"));
    assert!(wrapped_share(&personal, personal_id, "M.A.2").is_none());

    bind_pair(&operator, key_id, "M.S.2", "M.A.1").expect("second bridge");
    let updated = export_public_tree(&operator, key_id).expect("export");
    let visible = visible_labels_in_public_tree(&updated, &seed);
    let slice = filter_public_tree(&updated, &visible);
    apply_public_tree(&personal, Some(personal_id), &slice).expect("second fetch");
    assert!(labels(&personal, personal_id).contains("M.A.1"));
    assert!(wrapped_share(&personal, personal_id, "M.A.1").is_none());
}

#[test]
fn apply_public_tree_rolls_back_when_a_whitelist_edge_is_invalid() {
    let personal = db::open_in_memory().expect("personal");
    let (_sk, a2) = crate::keys::generate_encryption_keypair();
    let (_sk2, s2) = crate::keys::generate_encryption_keypair();
    let snapshot = PublicTree {
        label: "org".into(),
        generation: 1,
        nodes: vec![
            PublicNode {
                label: "M".into(),
                parent_label: None,
                threshold: Some(2),
                is_active: true,
                encryption_fingerprint: None,
                encryption_public_key: None,
            },
            PublicNode {
                label: "M.A".into(),
                parent_label: Some("M".into()),
                threshold: Some(2),
                is_active: true,
                encryption_fingerprint: None,
                encryption_public_key: None,
            },
            PublicNode {
                label: "M.S".into(),
                parent_label: Some("M".into()),
                threshold: Some(2),
                is_active: true,
                encryption_fingerprint: None,
                encryption_public_key: None,
            },
            PublicNode {
                label: "M.A.2".into(),
                parent_label: Some("M.A".into()),
                threshold: None,
                is_active: true,
                encryption_fingerprint: Some(crate::keys::fingerprint(&a2)),
                encryption_public_key: Some(hex::encode(a2)),
            },
            PublicNode {
                label: "M.S.2".into(),
                parent_label: Some("M.S".into()),
                threshold: None,
                is_active: true,
                encryption_fingerprint: Some(crate::keys::fingerprint(&s2)),
                encryption_public_key: Some(hex::encode(s2)),
            },
        ],
        whitelist: vec![PublicEdge {
            from: "M.S.2".into(),
            to: "M.A.2".into(),
        }],
        links: vec![],
    };
    let key_id = apply_public_tree(&personal, None, &snapshot).expect("first apply");
    let before: i64 = personal
        .query_row(
            "SELECT count(*) FROM key_node_bridges
             WHERE node_id IN (SELECT id FROM key_nodes WHERE key_id = ?1)",
            params![key_id],
            |row| row.get(0),
        )
        .expect("whitelist count");
    assert_eq!(before, 1);
    let mut bad = snapshot.clone();
    bad.whitelist.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.S.2".into(),
    });
    assert!(matches!(
        apply_public_tree(&personal, Some(key_id), &bad),
        Err(Error::InvalidBridge)
    ));
    let after: i64 = personal
        .query_row(
            "SELECT count(*) FROM key_node_bridges
             WHERE node_id IN (SELECT id FROM key_nodes WHERE key_id = ?1)",
            params![key_id],
            |row| row.get(0),
        )
        .expect("whitelist after");
    assert_eq!(after, 1);
}

#[test]
fn apply_public_tree_replaces_topology_only_hardware_keys() {
    let personal = db::open_in_memory().expect("personal");
    let (_sk, first) = crate::keys::generate_encryption_keypair();
    let snapshot = PublicTree {
        label: "org".into(),
        generation: 1,
        nodes: vec![
            PublicNode {
                label: "M".into(),
                parent_label: None,
                threshold: Some(2),
                is_active: true,
                encryption_fingerprint: None,
                encryption_public_key: None,
            },
            PublicNode {
                label: "M.A.2".into(),
                parent_label: Some("M".into()),
                threshold: None,
                is_active: true,
                encryption_fingerprint: Some(crate::keys::fingerprint(&first)),
                encryption_public_key: Some(hex::encode(first)),
            },
        ],
        whitelist: vec![],
        links: vec![],
    };
    let key_id = apply_public_tree(&personal, None, &snapshot).expect("first");
    let original: i64 = personal
        .query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE key_id = ?1 AND label = 'M.A.2'",
            params![key_id],
            |row| row.get(0),
        )
        .expect("original key");
    let (_sk2, rotated) = crate::keys::generate_encryption_keypair();
    let mut refreshed = snapshot;
    refreshed.nodes[1].encryption_fingerprint = Some(crate::keys::fingerprint(&rotated));
    refreshed.nodes[1].encryption_public_key = Some(hex::encode(rotated));
    apply_public_tree(&personal, Some(key_id), &refreshed).expect("refresh");
    let updated: i64 = personal
        .query_row(
            "SELECT hardware_key_id FROM key_nodes WHERE key_id = ?1 AND label = 'M.A.2'",
            params![key_id],
            |row| row.get(0),
        )
        .expect("updated key");
    assert_ne!(updated, original);
    let fp: String = personal
        .query_row(
            "SELECT fingerprint FROM hardware_keys WHERE id = ?1",
            params![updated],
            |row| row.get(0),
        )
        .expect("fp");
    assert_eq!(fp, crate::keys::fingerprint(&rotated));
}

#[test]
fn apply_public_tree_clears_wrapped_share_when_hardware_key_rotates() {
    let mut conn = db::open_in_memory().expect("schema");
    let (a1, _) = register_encryption_key(&conn, "a1");
    let (a2, _) = register_encryption_key(&conn, "a2");
    let spec = NodeSpec::Split {
        label: "M".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "M.A.1".into(),
                hardware_key_id: a1,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "M.A.2".into(),
                hardware_key_id: a2,
                allowed_bridges: vec![],
            },
        ],
    };
    let key_id = split(&mut conn, "org", b"company master secret 32 bytes!", &spec).expect("split");
    assert!(wrapped_share(&conn, key_id, "M.A.2").is_some());
    let mut snapshot = export_public_tree(&conn, key_id).expect("export");
    let (_sk, rotated) = crate::keys::generate_encryption_keypair();
    let leaf = snapshot
        .nodes
        .iter_mut()
        .find(|n| n.label == "M.A.2")
        .expect("leaf");
    leaf.encryption_fingerprint = Some(crate::keys::fingerprint(&rotated));
    leaf.encryption_public_key = Some(hex::encode(rotated));
    apply_public_tree(&conn, Some(key_id), &snapshot).expect("rotate");
    assert!(wrapped_share(&conn, key_id, "M.A.2").is_none());
    let fp: String = conn
        .query_row(
            "SELECT fingerprint FROM hardware_keys
             WHERE id = (SELECT hardware_key_id FROM key_nodes WHERE key_id = ?1 AND label = 'M.A.2')",
            params![key_id],
            |row| row.get(0),
        )
        .expect("fp");
    assert_eq!(fp, crate::keys::fingerprint(&rotated));
}

#[test]
fn apply_public_tree_rejects_a_lower_generation() {
    let personal = db::open_in_memory().expect("personal");
    let (_sk, a2) = crate::keys::generate_encryption_keypair();
    let mut snapshot = PublicTree {
        label: "org".into(),
        generation: 2,
        nodes: vec![
            PublicNode {
                label: "M".into(),
                parent_label: None,
                threshold: Some(2),
                is_active: true,
                encryption_fingerprint: None,
                encryption_public_key: None,
            },
            PublicNode {
                label: "M.A.2".into(),
                parent_label: Some("M".into()),
                threshold: None,
                is_active: true,
                encryption_fingerprint: Some(crate::keys::fingerprint(&a2)),
                encryption_public_key: Some(hex::encode(a2)),
            },
        ],
        whitelist: vec![],
        links: vec![],
    };
    let key_id = apply_public_tree(&personal, None, &snapshot).expect("first");
    assert_eq!(
        export_public_tree(&personal, key_id)
            .expect("export")
            .generation,
        2
    );
    snapshot.generation = 1;
    assert!(matches!(
        apply_public_tree(&personal, Some(key_id), &snapshot),
        Err(Error::StalePublicTree)
    ));
    assert_eq!(
        export_public_tree(&personal, key_id)
            .expect("kept")
            .generation,
        2
    );
}

#[test]
fn visible_from_maps_stops_on_a_parent_cycle() {
    let mut parent_of = HashMap::new();
    parent_of.insert("A".into(), Some("B".into()));
    parent_of.insert("B".into(), Some("A".into()));
    let children_of = HashMap::new();
    let visible = visible_from_maps(&parent_of, &children_of, &[], &["A".to_string()]);
    assert_eq!(visible, HashSet::from(["A".into(), "B".into()]));
}

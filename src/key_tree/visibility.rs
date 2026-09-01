use super::super::*;
use super::common::*;
use crate::db;
use rusqlite::params;
use std::collections::HashSet;

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

use crate::key_tree::{PublicEdge, PublicNode, PublicTree};
use crate::keys;
use crate::relay::{self, ApiKeyScope, NewApiKey};

pub(crate) fn fake_kqpb(public_key: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"KQPB");
    out.push(2);
    out.push(1);
    out.extend_from_slice(&public_key);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(crate) fn sample_envelope() -> (Vec<u8>, String) {
    let (_sk, pk) = keys::generate_encryption_keypair();
    let bytes = fake_kqpb(pk, b"opaque-letter");
    (bytes, keys::fingerprint(&pk))
}

pub(crate) fn push_key(conn: &rusqlite::Connection) -> String {
    relay::create_api_key(
        conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("op".into()),
            ttl_seconds: None,
        },
    )
    .expect("push key")
    .token
}

pub(crate) fn pull_key(conn: &rusqlite::Connection, fingerprint: &str) -> String {
    relay::create_api_key(
        conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPull,
            recipient_fingerprint: Some(fingerprint.to_string()),
            label: Some("device".into()),
            ttl_seconds: None,
        },
    )
    .expect("pull key")
    .token
}

pub(crate) fn admin_key(conn: &rusqlite::Connection) -> String {
    relay::create_api_key(
        conn,
        &NewApiKey {
            scope: ApiKeyScope::Admin,
            recipient_fingerprint: None,
            label: Some("admin".into()),
            ttl_seconds: None,
        },
    )
    .expect("admin key")
    .token
}

pub(crate) fn split_node(label: &str, parent: Option<&str>) -> PublicNode {
    PublicNode {
        label: label.into(),
        parent_label: parent.map(str::to_string),
        threshold: Some(2),
        is_active: true,
        encryption_fingerprint: None,
        encryption_public_key: None,
    }
}

pub(crate) fn leaf_node(label: &str, parent: &str, public_key: &[u8; 32]) -> PublicNode {
    PublicNode {
        label: label.into(),
        parent_label: Some(parent.into()),
        threshold: None,
        is_active: true,
        encryption_fingerprint: Some(keys::fingerprint(public_key)),
        encryption_public_key: Some(hex::encode(public_key)),
    }
}

pub(crate) fn example_org_tree() -> (PublicTree, [u8; 32]) {
    let (_a1_sk, a1) = keys::generate_encryption_keypair();
    let (_a2_sk, a2) = keys::generate_encryption_keypair();
    let (_s1_sk, s1) = keys::generate_encryption_keypair();
    let (_s2_sk, s2) = keys::generate_encryption_keypair();
    let tree = PublicTree {
        label: "org".into(),
        generation: 1,
        nodes: vec![
            split_node("M", None),
            split_node("M.A", Some("M")),
            split_node("M.S", Some("M")),
            leaf_node("M.A.1", "M.A", &a1),
            leaf_node("M.A.2", "M.A", &a2),
            leaf_node("M.S.1", "M.S", &s1),
            leaf_node("M.S.2", "M.S", &s2),
        ],
        whitelist: vec![
            PublicEdge {
                from: "M.S.2".into(),
                to: "M.A.2".into(),
            },
            PublicEdge {
                from: "M.A.2".into(),
                to: "M.S.2".into(),
            },
        ],
        links: vec![PublicEdge {
            from: "M.S.2".into(),
            to: "M.A.2".into(),
        }],
    };
    (tree, s2)
}

pub(crate) fn link_ma1(tree: &mut PublicTree) {
    tree.links.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    tree.whitelist.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    tree.whitelist.push(PublicEdge {
        from: "M.A.1".into(),
        to: "M.S.2".into(),
    });
}

pub(crate) fn node_labels(tree: &PublicTree) -> Vec<String> {
    let mut labels: Vec<_> = tree.nodes.iter().map(|n| n.label.clone()).collect();
    labels.sort();
    labels
}

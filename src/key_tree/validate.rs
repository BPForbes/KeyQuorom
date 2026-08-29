use super::super::*;
use super::common::*;
use crate::db;
use crate::keys::KeyType;

#[test]
fn validate_rejects_threshold_above_children_count() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _) = register_encryption_key(&conn, "a");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 2,
        allowed_bridges: vec![],
        children: vec![NodeSpec::Leaf {
            label: "a".into(),
            hardware_key_id: id_a,
            allowed_bridges: vec![],
        }],
    };

    assert!(matches!(
        validate(&conn, &spec),
        Err(Error::InvalidQuorumThreshold)
    ));
}

#[test]
fn validate_rejects_more_than_255_children() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _) = register_encryption_key(&conn, "a");

    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: (0..256)
            .map(|i| NodeSpec::Leaf {
                label: format!("leaf-{i}"),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            })
            .collect(),
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
        allowed_bridges: vec![],
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
        allowed_bridges: vec![],
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

#[test]
fn node_spec_rejects_an_object_mixing_leaf_and_split_fields() {
    let json = r#"{"label": "confused", "hardware_key_id": 1, "threshold": 2, "children": []}"#;
    let result: std::result::Result<NodeSpec, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn node_spec_rejects_an_unexpected_field() {
    let json = r#"{"label": "leaf", "hardware_key_id": 1, "extra": true}"#;
    let result: std::result::Result<NodeSpec, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn node_spec_accepts_allowed_bridges_on_a_leaf() {
    let json = r#"{"label": "alice", "hardware_key_id": 1, "allowed_bridges": ["bob"]}"#;
    let spec: NodeSpec = serde_json::from_str(json).expect("spec should parse");
    assert_eq!(spec.allowed_bridges(), &["bob".to_string()]);
}

#[test]
fn validate_rejects_duplicate_labels() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (id_a, _) = register_encryption_key(&conn, "a");
    let spec = NodeSpec::Split {
        label: "root".into(),
        threshold: 1,
        allowed_bridges: vec![],
        children: vec![
            NodeSpec::Leaf {
                label: "dup".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
            NodeSpec::Leaf {
                label: "dup".into(),
                hardware_key_id: id_a,
                allowed_bridges: vec![],
            },
        ],
    };
    assert!(matches!(
        validate(&conn, &spec),
        Err(Error::DuplicateNodeLabel)
    ));
}

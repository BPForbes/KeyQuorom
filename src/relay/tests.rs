use crate::error::Error;
use crate::key_tree::{PublicEdge, PublicNode, PublicTree};
use crate::keys;
use crate::relay::{self, ApiKeyScope, AppState, NewApiKey, MAX_ENVELOPE_BYTES};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tower::ServiceExt;

fn fake_kqpb(public_key: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"KQPB");
    out.push(2);
    out.push(1);
    out.extend_from_slice(&public_key);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn sample_envelope() -> (Vec<u8>, String) {
    let (_sk, pk) = keys::generate_encryption_keypair();
    let bytes = fake_kqpb(pk, b"opaque-letter");
    (bytes, keys::fingerprint(&pk))
}

fn push_key(conn: &rusqlite::Connection) -> String {
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

fn pull_key(conn: &rusqlite::Connection, fingerprint: &str) -> String {
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

fn admin_key(conn: &rusqlite::Connection) -> String {
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

#[test]
fn api_key_lifecycle_create_validate_rotate_revoke() {
    let conn = relay::open_in_memory().expect("schema");
    let created = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("ops".into()),
            ttl_seconds: None,
        },
    )
    .expect("create");

    relay::authenticate(&conn, &created.token, ApiKeyScope::InboxPush).expect("valid");
    assert!(matches!(
        relay::authenticate(&conn, &created.token, ApiKeyScope::InboxPull),
        Err(Error::ApiKeyScopeDenied)
    ));

    let rotated = relay::rotate_api_key(&conn, created.info.id).expect("rotate");
    assert!(matches!(
        relay::authenticate(&conn, &created.token, ApiKeyScope::InboxPush),
        Err(Error::ApiKeyRevoked)
    ));
    relay::authenticate(&conn, &rotated.token, ApiKeyScope::InboxPush).expect("new key");

    relay::revoke_api_key(&conn, rotated.info.id).expect("revoke");
    assert!(matches!(
        relay::authenticate(&conn, &rotated.token, ApiKeyScope::InboxPush),
        Err(Error::ApiKeyRevoked)
    ));
}

#[test]
fn api_key_rejects_expired_and_unknown() {
    let conn = relay::open_in_memory().expect("schema");
    let created = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::Admin,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: Some(-1),
        },
    )
    .expect("create expired");
    assert!(matches!(
        relay::authenticate(&conn, &created.token, ApiKeyScope::Admin),
        Err(Error::ApiKeyExpired)
    ));
    assert!(matches!(
        relay::authenticate(
            &conn,
            "kq_notarealtokenvalue0123456789ABCD",
            ApiKeyScope::Admin
        ),
        Err(Error::InvalidApiKey)
    ));
}

#[test]
fn api_key_rejects_ttl_that_sqlite_cannot_represent() {
    let conn = relay::open_in_memory().expect("schema");
    for ttl in [0, i64::MIN, i64::MAX] {
        assert!(
            matches!(
                relay::create_api_key(
                    &conn,
                    &NewApiKey {
                        scope: ApiKeyScope::Admin,
                        recipient_fingerprint: None,
                        label: None,
                        ttl_seconds: Some(ttl),
                    },
                ),
                Err(Error::InvalidApiKeyRequest)
            ),
            "ttl {ttl} must not mint a key"
        );
    }
    let count: i64 = conn
        .query_row("SELECT count(*) FROM api_keys", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 0);
}

#[test]
fn pull_key_requires_fingerprint_and_cannot_bind_push() {
    let conn = relay::open_in_memory().expect("schema");
    assert!(matches!(
        relay::create_api_key(
            &conn,
            &NewApiKey {
                scope: ApiKeyScope::InboxPull,
                recipient_fingerprint: None,
                label: None,
                ttl_seconds: None,
            },
        ),
        Err(Error::InvalidApiKeyRequest)
    ));
    let (_sk, pk) = keys::generate_encryption_keypair();
    let fp = keys::fingerprint(&pk);
    assert!(matches!(
        relay::create_api_key(
            &conn,
            &NewApiKey {
                scope: ApiKeyScope::InboxPush,
                recipient_fingerprint: Some(fp),
                label: None,
                ttl_seconds: None,
            },
        ),
        Err(Error::InvalidApiKeyRequest)
    ));
}

#[test]
fn mailbox_stores_bytes_verbatim_and_dedupes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    let (id, fp, dup) = relay::store(&conn, &envelope).expect("store");
    assert!(!dup);
    assert_eq!(fp, fingerprint);
    let (id2, _, dup2) = relay::store(&conn, &envelope).expect("dedupe");
    assert!(dup2);
    assert_eq!(id, id2);
    let listed = relay::list_after(&conn, &fingerprint, None, None).expect("list");
    assert_eq!(listed.envelopes.len(), 1);
    assert_eq!(listed.envelopes[0].bytes, envelope);
    assert!(listed.next_after.is_none());
}

#[test]
fn mailbox_list_after_pages_and_rejects_invalid_limits() {
    let conn = relay::open_in_memory().expect("schema");
    let (_sk, pk) = keys::generate_encryption_keypair();
    let fingerprint = keys::fingerprint(&pk);
    for payload in [b"one".as_slice(), b"two", b"three"] {
        relay::store(&conn, &fake_kqpb(pk, payload)).expect("store");
    }
    let first = relay::list_after(&conn, &fingerprint, None, Some(2)).expect("page");
    assert_eq!(first.envelopes.len(), 2);
    let cursor = first.next_after.expect("continuation");
    assert_eq!(cursor, first.envelopes[1].id);
    let second = relay::list_after(&conn, &fingerprint, Some(cursor), Some(2)).expect("rest");
    assert_eq!(second.envelopes.len(), 1);
    assert!(second.next_after.is_none());
    assert!(matches!(
        relay::list_after(&conn, &fingerprint, None, Some(0)),
        Err(Error::InvalidInboxPage)
    ));
    assert!(matches!(
        relay::list_after(&conn, &fingerprint, None, Some(501)),
        Err(Error::InvalidInboxPage)
    ));
}

#[test]
fn mailbox_rejects_truncated_and_wrong_magic() {
    let conn = relay::open_in_memory().expect("schema");
    assert!(matches!(
        relay::store(&conn, b"KQBN"),
        Err(Error::InvalidBridgePackage)
    ));
    assert!(matches!(
        relay::store(&conn, b"KQPB\x02"),
        Err(Error::InvalidBridgePackage)
    ));
}

#[test]
fn bootstrap_licensee_only_when_empty() {
    let conn = relay::open_in_memory().expect("schema");
    let first = relay::bootstrap_licensee_if_empty(&conn)
        .expect("bootstrap")
        .expect("created");
    assert!(first.token.starts_with("kql_"));
    assert!(relay::bootstrap_licensee_if_empty(&conn)
        .expect("second")
        .is_none());
    relay::authenticate_licensee(&conn, &first.token).expect("licensee works");
    assert!(matches!(
        relay::authenticate_licensee(&conn, "kq_notarealtokenvalue0123456789ABCD"),
        Err(Error::InvalidLicenseeKey)
    ));
}

async fn body_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn router_health_and_openapi_are_public() {
    let conn = relay::open_in_memory().expect("schema");
    let app = relay::router(AppState::new(conn));
    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let spec = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spec.status(), StatusCode::OK);
    let json = body_json(spec).await;
    assert!(json["paths"]["/inbox"].is_object());
    assert!(json["paths"]["/api-keys"].is_object());
    assert!(json["paths"]["/keycheck"].is_object());
    assert!(json["paths"]["/keycheck"]["post"].get("security").is_none());
}

#[tokio::test]
async fn router_enforces_scopes_and_returns_opaque_bytes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    let push = push_key(&conn);
    let pull = pull_key(&conn, &fingerprint);
    let other_fp = keys::fingerprint(&[9u8; 32]);
    let other_pull = pull_key(&conn, &other_fp);
    let admin = admin_key(&conn);
    let app = relay::router(AppState::new(conn));

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(envelope.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let stored = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .header("Content-Type", "application/octet-stream")
                .body(Body::from(envelope.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stored.status(), StatusCode::CREATED);

    let pull_denied_as_push = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pull_denied_as_push.status(), StatusCode::FORBIDDEN);

    let got = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    let json = body_json(got).await;
    let encoded = json["envelopes"][0]["bytes"].as_str().unwrap();
    let decoded = STANDARD.decode(encoded).expect("base64");
    assert_eq!(decoded, envelope);

    let empty = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("X-Api-Key", &other_pull)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    let empty_json = body_json(empty).await;
    assert_eq!(empty_json["envelopes"].as_array().unwrap().len(), 0);
    assert_eq!(empty_json["trees"].as_array().unwrap().len(), 0);

    let unauth = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api-keys")
                .header("Authorization", format!("Bearer {push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::FORBIDDEN);

    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api-keys")
                .header("Authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);

    let mint_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api-keys")
                .header("Authorization", format!("Bearer {admin}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"scope":"inbox.push","label":"stolen"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mint_denied.status(), StatusCode::METHOD_NOT_ALLOWED);

    let rotate_gone = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api-keys/1/rotate")
                .header("Authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotate_gone.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_listener_round_trip_with_ureq() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    let push = push_key(&conn);
    let pull = pull_key(&conn, &fingerprint);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = relay::router(AppState::new(conn));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let url = format!("http://{addr}");
    let accepted = relay::push_inbox(&url, &push, &envelope).expect("push");
    assert_eq!(accepted.recipient_fingerprint, fingerprint);
    let listed = relay::pull_inbox(&url, &pull, None, None).expect("pull");
    assert_eq!(listed.envelopes.len(), 1);
    assert!(listed.trees.is_empty());
    let decoded = STANDARD.decode(&listed.envelopes[0].bytes).expect("base64");
    assert_eq!(decoded, envelope);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushing_an_envelope_updates_full_tree_and_pull_returns_a_slice() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, mailbox_fp) = sample_envelope();
    let (tree, s2) = example_org_tree(false);
    let s2_fp = keys::fingerprint(&s2);
    let push = push_key(&conn);
    let pull_s2 = pull_key(&conn, &s2_fp);
    let pull_mailbox = pull_key(&conn, &mailbox_fp);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = relay::router(AppState::new(conn));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let url = format!("http://{addr}");
    relay::push_inbox_with_trees(&url, &push, &envelope, std::slice::from_ref(&tree))
        .expect("push with tree");

    let for_member = relay::pull_inbox(&url, &pull_s2, None, None).expect("member pull");
    assert!(for_member.envelopes.is_empty());
    assert_eq!(for_member.trees.len(), 1);
    let labels: Vec<&str> = for_member.trees[0]
        .nodes
        .iter()
        .map(|node| node.label.as_str())
        .collect();
    assert!(labels.contains(&"M.A.2"));
    assert!(labels.contains(&"M.S.2"));
    assert!(!labels.contains(&"M.A.1"));

    let mut with_ma1 = tree.clone();
    with_ma1.links.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    with_ma1.whitelist.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    with_ma1.whitelist.push(PublicEdge {
        from: "M.A.1".into(),
        to: "M.S.2".into(),
    });
    relay::push_inbox_with_trees(&url, &push, &envelope, std::slice::from_ref(&with_ma1))
        .expect("push updated tree");
    let expanded = relay::pull_inbox(&url, &pull_s2, None, None).expect("expanded");
    assert_eq!(expanded.trees[0].generation, 2);
    assert!(expanded.trees[0]
        .nodes
        .iter()
        .any(|node| node.label == "M.A.1"));

    let mail = relay::pull_inbox(&url, &pull_mailbox, None, None).expect("mailbox pull");
    assert_eq!(mail.envelopes.len(), 1);
    assert!(mail.trees.is_empty());
}

#[test]
fn max_envelope_constant_is_one_mib() {
    assert_eq!(MAX_ENVELOPE_BYTES, 1024 * 1024);
}

fn split_node(label: &str, parent: Option<&str>) -> PublicNode {
    PublicNode {
        label: label.into(),
        parent_label: parent.map(str::to_string),
        threshold: Some(2),
        is_active: true,
        encryption_fingerprint: None,
        encryption_public_key: None,
    }
}

fn leaf_node(label: &str, parent: &str, public_key: &[u8; 32]) -> PublicNode {
    PublicNode {
        label: label.into(),
        parent_label: Some(parent.into()),
        threshold: None,
        is_active: true,
        encryption_fingerprint: Some(keys::fingerprint(public_key)),
        encryption_public_key: Some(hex::encode(public_key)),
    }
}

fn example_org_tree(link_ma1: bool) -> (PublicTree, [u8; 32]) {
    let (_a1_sk, a1) = keys::generate_encryption_keypair();
    let (_a2_sk, a2) = keys::generate_encryption_keypair();
    let (_s1_sk, s1) = keys::generate_encryption_keypair();
    let (_s2_sk, s2) = keys::generate_encryption_keypair();
    let mut links = vec![PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.2".into(),
    }];
    let mut whitelist = vec![
        PublicEdge {
            from: "M.S.2".into(),
            to: "M.A.2".into(),
        },
        PublicEdge {
            from: "M.A.2".into(),
            to: "M.S.2".into(),
        },
    ];
    if link_ma1 {
        links.push(PublicEdge {
            from: "M.S.2".into(),
            to: "M.A.1".into(),
        });
        whitelist.push(PublicEdge {
            from: "M.S.2".into(),
            to: "M.A.1".into(),
        });
        whitelist.push(PublicEdge {
            from: "M.A.1".into(),
            to: "M.S.2".into(),
        });
    }
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
        whitelist,
        links,
    };
    (tree, s2)
}

fn node_labels(tree: &PublicTree) -> Vec<String> {
    let mut labels: Vec<_> = tree.nodes.iter().map(|n| n.label.clone()).collect();
    labels.sort();
    labels
}

#[test]
fn org_tree_put_and_context_omits_unrelated_peer_sibling() {
    let conn = relay::open_in_memory().expect("schema");
    let (tree, s2) = example_org_tree(false);
    let stored = relay::put_public_tree(&conn, &tree).expect("put");
    assert_eq!(stored.generation, 1);
    let fp = keys::fingerprint(&s2);
    let slice = relay::context_for_fingerprint(&conn, "org", &fp).expect("context");
    assert_eq!(
        node_labels(&slice),
        vec!["M", "M.A", "M.A.2", "M.S", "M.S.1", "M.S.2"]
    );

    let mut with_ma1 = tree.clone();
    with_ma1.links.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    with_ma1.whitelist.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    with_ma1.whitelist.push(PublicEdge {
        from: "M.A.1".into(),
        to: "M.S.2".into(),
    });
    let stored = relay::put_public_tree(&conn, &with_ma1).expect("put again");
    assert_eq!(stored.generation, 2);
    let slice = relay::context_for_fingerprint(&conn, "org", &fp).expect("expanded");
    assert!(node_labels(&slice).contains(&"M.A.1".to_string()));
    assert!(matches!(
        relay::context_for_fingerprint(&conn, "org", "deadbeef"),
        Err(Error::NodeNotFound)
    ));
    assert!(relay::contexts_for_fingerprint(&conn, "deadbeef")
        .expect("unknown fp")
        .is_empty());
    assert!(matches!(
        relay::get_public_tree(&conn, "missing"),
        Err(Error::TreeNotFound)
    ));
}

#[test]
fn put_public_tree_rejects_a_parent_cycle() {
    let conn = relay::open_in_memory().expect("schema");
    let tree = PublicTree {
        label: "org".into(),
        generation: 1,
        nodes: vec![
            split_node("M", None),
            split_node("A", Some("B")),
            split_node("B", Some("A")),
        ],
        whitelist: vec![],
        links: vec![],
    };
    assert!(matches!(
        relay::put_public_tree(&conn, &tree),
        Err(Error::InvalidTreeSpec)
    ));
    assert!(matches!(
        relay::get_public_tree(&conn, "org"),
        Err(Error::TreeNotFound)
    ));
}

#[test]
fn relay_open_rejects_an_organization_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("org.sqlite");
    let path_str = path.to_str().expect("utf-8");
    crate::db::open(path_str).expect("organization store");
    assert!(matches!(
        relay::open(path_str),
        Err(Error::OrganizationDatabase)
    ));
    let relay_path = dir.path().join("relay.sqlite");
    let relay_str = relay_path.to_str().expect("utf-8");
    relay::open(relay_str).expect("create relay db");
    relay::open(relay_str).expect("reopen relay db");
}

#[test]
fn put_public_tree_keeps_the_previous_tree_when_a_duplicate_edge_is_rejected() {
    let conn = relay::open_in_memory().expect("schema");
    let (mut tree, _) = example_org_tree(false);
    let stored = relay::put_public_tree(&conn, &tree).expect("put");
    assert_eq!(stored.generation, 1);
    tree.whitelist.push(tree.whitelist[0].clone());
    assert!(matches!(
        relay::put_public_tree(&conn, &tree),
        Err(Error::InvalidBridge)
    ));
    let kept = relay::get_public_tree(&conn, "org").expect("kept");
    assert_eq!(kept.generation, 1);
    assert_eq!(kept.nodes.len(), 7);
}

#[tokio::test]
async fn inbox_get_rejects_invalid_page_sizes() {
    let conn = relay::open_in_memory().expect("schema");
    let pull = pull_key(&conn, &keys::fingerprint(&[1u8; 32]));
    let app = relay::router(AppState::new(conn));
    for uri in ["/inbox?limit=0", "/inbox?limit=501"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("Authorization", format!("Bearer {pull}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn push_rolls_back_trees_and_envelope_when_a_later_tree_is_invalid() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, mailbox_fp) = sample_envelope();
    let (good, s2) = example_org_tree(false);
    let s2_fp = keys::fingerprint(&s2);
    let push = push_key(&conn);
    let pull_s2 = pull_key(&conn, &s2_fp);
    let pull_mailbox = pull_key(&conn, &mailbox_fp);
    let cyclic = PublicTree {
        label: "other".into(),
        generation: 1,
        nodes: vec![
            split_node("M", None),
            split_node("A", Some("B")),
            split_node("B", Some("A")),
        ],
        whitelist: vec![],
        links: vec![],
    };
    let body = serde_json::to_vec(&relay::InboxPush {
        bytes: STANDARD.encode(&envelope),
        trees: vec![good, cyclic],
    })
    .unwrap();
    let app = relay::router(AppState::new(conn));

    let stored = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {push}"))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stored.status(), StatusCode::BAD_REQUEST);

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/trees/org/context")
                .header("Authorization", format!("Bearer {pull_s2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let listed = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull_mailbox}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let json = body_json(listed).await;
    assert_eq!(json["envelopes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn router_publish_and_fetch_tree_context() {
    let conn = relay::open_in_memory().expect("schema");
    let (tree, s2) = example_org_tree(false);
    let fp = keys::fingerprint(&s2);
    let admin = admin_key(&conn);
    let pull = pull_key(&conn, &fp);
    let push = push_key(&conn);
    let app = relay::router(AppState::new(conn));

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/trees")
                .header("Authorization", format!("Bearer {pull}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&tree).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let published = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/trees")
                .header("Authorization", format!("Bearer {admin}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&tree).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(published.status(), StatusCode::OK);
    let json = body_json(published).await;
    assert_eq!(json["generation"], 1);

    let push_denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/trees/org/context")
                .header("Authorization", format!("Bearer {push}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(push_denied.status(), StatusCode::FORBIDDEN);

    let got = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/trees/org/context")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    let json = body_json(got).await;
    let labels: Vec<&str> = json["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["label"].as_str().unwrap())
        .collect();
    assert!(labels.contains(&"M.A.2"));
    assert!(!labels.contains(&"M.A.1"));

    let inbox = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inbox.status(), StatusCode::OK);
    let inbox_json = body_json(inbox).await;
    assert_eq!(inbox_json["envelopes"].as_array().unwrap().len(), 0);
    let inbox_labels: Vec<&str> = inbox_json["trees"][0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["label"].as_str().unwrap())
        .collect();
    assert!(inbox_labels.contains(&"M.A.2"));
    assert!(!inbox_labels.contains(&"M.A.1"));

    let mut with_ma1 = tree.clone();
    with_ma1.links.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    with_ma1.whitelist.push(PublicEdge {
        from: "M.S.2".into(),
        to: "M.A.1".into(),
    });
    with_ma1.whitelist.push(PublicEdge {
        from: "M.A.1".into(),
        to: "M.S.2".into(),
    });
    let republished = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/trees")
                .header("Authorization", format!("Bearer {admin}"))
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&with_ma1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(republished.status(), StatusCode::OK);

    let expanded = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inbox")
                .header("Authorization", format!("Bearer {pull}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expanded.status(), StatusCode::OK);
    let expanded_json = body_json(expanded).await;
    let expanded_labels: Vec<&str> = expanded_json["trees"][0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["label"].as_str().unwrap())
        .collect();
    assert!(expanded_labels.contains(&"M.A.1"));

    let spec = app
        .oneshot(
            Request::builder()
                .uri("/api-docs/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let spec_json = body_json(spec).await;
    assert!(spec_json["paths"]["/trees"].is_object());
    assert!(spec_json["paths"]["/trees/{label}/context"].is_object());
    assert!(spec_json["components"]["schemas"]["InboxList"]["properties"]["trees"].is_object());
}

#[test]
fn keycheck_accepts_live_token_and_hash_without_stamping_use() {
    let conn = relay::open_in_memory().expect("schema");
    let created = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("ops".into()),
            ttl_seconds: None,
        },
    )
    .expect("create");
    let check = relay::check_token(&conn, &created.token).expect("token");
    assert!(check.valid);
    assert_eq!(check.scope.as_deref(), Some("inbox.push"));
    assert_eq!(check.label.as_deref(), Some("ops"));
    let hash = relay::hash_bearer(&created.token).expect("hash");
    let by_hash = relay::check_hash(&conn, &hash).expect("hash");
    assert_eq!(by_hash, check);
    let last_used: Option<String> = conn
        .query_row(
            "SELECT last_used_at FROM api_keys WHERE id = ?1",
            rusqlite::params![created.info.id],
            |row| row.get(0),
        )
        .expect("last_used");
    assert!(last_used.is_none());
    assert!(
        !relay::check_token(&conn, "kq_notarealtokenvalue0123456789ABCD")
            .expect("junk")
            .valid
    );
}

#[test]
fn keycheck_treats_expired_and_revoked_as_invalid() {
    let conn = relay::open_in_memory().expect("schema");
    let expired = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::Admin,
            recipient_fingerprint: None,
            label: None,
            ttl_seconds: Some(-1),
        },
    )
    .expect("expired");
    assert!(
        !relay::check_token(&conn, &expired.token)
            .expect("check expired")
            .valid
    );

    let live = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::Admin,
            recipient_fingerprint: None,
            label: Some("keep".into()),
            ttl_seconds: None,
        },
    )
    .expect("live");
    relay::revoke_api_key(&conn, live.info.id).expect("revoke");
    assert!(
        !relay::check_token(&conn, &live.token)
            .expect("check revoked")
            .valid
    );
}

#[tokio::test]
async fn keycheck_route_is_public() {
    let conn = relay::open_in_memory().expect("schema");
    let created = relay::create_api_key(
        &conn,
        &NewApiKey {
            scope: ApiKeyScope::InboxPush,
            recipient_fingerprint: None,
            label: Some("ops".into()),
            ttl_seconds: None,
        },
    )
    .expect("create");
    let hash = relay::hash_bearer(&created.token).expect("hash");
    let app = relay::router(AppState::new(conn));

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"token":"{}"}}"#, created.token)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let json = body_json(ok).await;
    assert_eq!(json["valid"], true);
    assert_eq!(json["scope"], "inbox.push");

    let by_hash = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(r#"{{"key_hash":"{hash}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(by_hash.status(), StatusCode::OK);
    assert_eq!(body_json(by_hash).await["valid"], true);

    let unknown = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/keycheck")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"token":"kq_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::OK);
    assert_eq!(body_json(unknown).await["valid"], false);
}

#[tokio::test]
async fn check_key_client_and_stored_hash_can_push() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, _fp) = sample_envelope();
    let token = push_key(&conn);
    let app = relay::router(AppState::new(conn));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let token_c = token.clone();
    let base_c = base.clone();
    let check = tokio::task::spawn_blocking(move || relay::check_key(&base_c, &token_c))
        .await
        .unwrap()
        .expect("check_key");
    assert!(check.valid);
    let hash = relay::hash_bearer(&token).expect("hash");
    let org = crate::db::open_in_memory().expect("org");
    crate::db::relay_credential::save(
        &org,
        &crate::db::relay_credential::StoredRelayKey {
            relay_url: base.clone(),
            scope: check.scope.clone().expect("scope"),
            key_hash: hash.clone(),
            token: token.clone(),
            remote_id: check.id,
            label: check.label.clone(),
        },
    )
    .expect("save");
    let base_h = base.clone();
    let hash_c = hash.clone();
    let recheck = tokio::task::spawn_blocking(move || relay::check_key_hash(&base_h, &hash_c))
        .await
        .unwrap()
        .expect("check_key_hash");
    assert!(recheck.valid);
    let stored = crate::db::relay_credential::get(&org, &base, "inbox.push")
        .expect("get")
        .expect("row");
    let env = envelope.clone();
    let base_p = base.clone();
    let tok = stored.token.clone();
    let accepted = tokio::task::spawn_blocking(move || relay::push_inbox(&base_p, &tok, &env))
        .await
        .unwrap()
        .expect("push");
    assert!(accepted.id > 0);
}

use crate::error::Error;
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
    let listed = relay::list_after(&conn, &fingerprint, None).expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].bytes, envelope);
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
fn bootstrap_admin_only_when_empty() {
    let conn = relay::open_in_memory().expect("schema");
    let first = relay::bootstrap_admin_if_empty(&conn)
        .expect("bootstrap")
        .expect("created");
    assert_eq!(first.info.scope, "admin");
    assert!(relay::bootstrap_admin_if_empty(&conn)
        .expect("second")
        .is_none());
    relay::authenticate(&conn, &first.token, ApiKeyScope::Admin).expect("admin works");
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
    let listed = relay::pull_inbox(&url, &pull, None).expect("pull");
    assert_eq!(listed.envelopes.len(), 1);
    let decoded = STANDARD.decode(&listed.envelopes[0].bytes).expect("base64");
    assert_eq!(decoded, envelope);
}

#[test]
fn max_envelope_constant_is_one_mib() {
    assert_eq!(MAX_ENVELOPE_BYTES, 1024 * 1024);
}

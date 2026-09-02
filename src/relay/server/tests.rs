use super::super::test_helpers::*;
use super::{router, AppState, ProviderIdentity, MAX_ENVELOPE_BYTES};
use crate::key_tree::PublicTree;
use crate::keys;
use crate::provider::test_helpers::issued_identity;
use crate::relay::{self, ApiKeyScope, NewApiKey};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tower::ServiceExt;

async fn body_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn router_health_and_openapi_are_public() {
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::new(conn));
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
    assert!(json["paths"]["/provider-identity"].is_object());
    assert!(json["paths"]["/provider-identity"]["post"]
        .get("security")
        .is_none());
    assert!(json["components"]["securitySchemes"]["api_key"].is_object());
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
    let app = router(AppState::new(conn));

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

    let again = app
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
    assert_eq!(again.status(), StatusCode::OK);

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

#[test]
fn max_envelope_constant_is_one_mib() {
    assert_eq!(MAX_ENVELOPE_BYTES, 1024 * 1024);
}

#[tokio::test]
async fn inbox_get_rejects_invalid_page_sizes() {
    let conn = relay::open_in_memory().expect("schema");
    let pull = pull_key(&conn, &keys::fingerprint(&[1u8; 32]));
    let app = router(AppState::new(conn));
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
    let (good, s2) = example_org_tree();
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
        expires_at: None,
    })
    .unwrap();
    let app = router(AppState::new(conn));

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
    let (tree, s2) = example_org_tree();
    let fp = keys::fingerprint(&s2);
    let admin = admin_key(&conn);
    let pull = pull_key(&conn, &fp);
    let push = push_key(&conn);
    let app = router(AppState::new(conn));

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
    link_ma1(&mut with_ma1);
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
    let app = router(AppState::new(conn));

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
async fn inbox_pull_drops_expired_envelopes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    relay::store_until(&conn, &envelope, Some("2099-12-31 23:59:00")).expect("store");
    conn.execute(
        "UPDATE mailbox SET expires_at = datetime('now', '-1 minutes')",
        [],
    )
    .expect("expire");
    let pull = pull_key(&conn, &fingerprint);
    let app = router(AppState::new(conn));
    let got = app
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
    assert_eq!(json["envelopes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn inbox_push_rejects_a_past_expires() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, _) = sample_envelope();
    let push = push_key(&conn);
    let app = router(AppState::new(conn));
    let body = serde_json::to_vec(&relay::InboxPush {
        bytes: STANDARD.encode(&envelope),
        trees: vec![],
        expires_at: Some("2000-01-01 00:00:00".into()),
    })
    .unwrap();
    let denied = app
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
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn provider_identity_is_unavailable_without_configured_identity() {
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::new(conn));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/provider-identity")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn provider_identity_signs_a_valid_challenge() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::with_identity(
        conn,
        ProviderIdentity {
            certificate: issued.certificate.clone(),
            relay_private_key: issued.relay_private.clone(),
        },
    ));
    let challenge = crate::provider::random_challenge();
    let body = serde_json::json!({
        "challenge": STANDARD.encode(challenge)
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/provider-identity")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    let cert = STANDARD
        .decode(json["certificate"].as_str().expect("cert"))
        .expect("cert b64");
    let signature: [u8; 64] = STANDARD
        .decode(json["signature"].as_str().expect("sig"))
        .expect("sig b64")
        .try_into()
        .expect("64");
    let parsed = crate::provider::parse_certificate(&cert).expect("parse");
    crate::provider::verify_challenge(&parsed, &challenge, &signature).expect("sig");
}

#[tokio::test]
async fn provider_identity_rejects_a_short_challenge() {
    let issued = issued_identity("2027-09-02 00:00:00");
    let conn = relay::open_in_memory().expect("schema");
    let app = router(AppState::with_identity(
        conn,
        ProviderIdentity {
            certificate: issued.certificate,
            relay_private_key: issued.relay_private,
        },
    ));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/provider-identity")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"challenge":"AAAA"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

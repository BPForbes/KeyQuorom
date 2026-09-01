#[cfg(feature = "provider")]
use super::super::test_helpers::*;
use super::*;
#[cfg(feature = "provider")]
use crate::keys;
#[cfg(feature = "provider")]
use crate::relay::{self, AppState};
#[cfg(feature = "provider")]
use base64::engine::general_purpose::STANDARD;
use std::time::Duration;

#[test]
fn rejects_remote_http_and_allows_loopback_and_https() {
    assert!(validate_relay_url("http://example.com:8787").is_err());
    assert!(validate_relay_url("http://192.168.1.10").is_err());
    assert!(validate_relay_url("ftp://127.0.0.1").is_err());
    validate_relay_url("http://127.0.0.1:8787").expect("loopback");
    validate_relay_url("http://localhost:8787").expect("localhost");
    validate_relay_url("http://[::1]:8787").expect("ipv6");
    validate_relay_url("https://relay.example.com").expect("https");
}

#[test]
fn rejects_backslash_host_confusion() {
    // Manual authority splitting treated `localhost` as the host; the
    // WHATWG parser (and ureq) treat `\` as `/`, so the host is the
    // attacker and HTTP would leak the bearer if we allowed it.
    let confused = r"http://attacker.example\@localhost";
    assert!(validate_relay_url(confused).is_err());
    assert!(relay_request_url(confused, "/inbox").is_err());
    assert!(validate_relay_url("http://attacker.example@localhost").is_err());
    let url = relay_request_url("http://127.0.0.1:8787", "/inbox").expect("loopback");
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    assert_eq!(url.path(), "/inbox");
}

#[test]
fn stalled_peer_is_terminated_by_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        std::thread::sleep(Duration::from_secs(5));
        drop(stream);
    });
    let agent = http_agent_builder()
        .timeout(Duration::from_millis(400))
        .build();
    let started = std::time::Instant::now();
    let result = agent.get(&format!("http://{addr}/")).call();
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(feature = "provider")]
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
    let accepted = {
        let url = url.clone();
        let push = push.clone();
        let envelope = envelope.clone();
        tokio::task::spawn_blocking(move || relay::push_inbox(&url, &push, &envelope))
            .await
            .expect("join")
            .expect("push")
    };
    assert_eq!(accepted.recipient_fingerprint, fingerprint);
    let listed = {
        let url = url.clone();
        let pull = pull.clone();
        tokio::task::spawn_blocking(move || relay::pull_inbox(&url, &pull, None, None))
            .await
            .expect("join")
            .expect("pull")
    };
    assert_eq!(listed.envelopes.len(), 1);
    assert!(listed.trees.is_empty());
    let decoded = STANDARD.decode(&listed.envelopes[0].bytes).expect("base64");
    assert_eq!(decoded, envelope);
}

#[cfg(feature = "provider")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushing_an_envelope_updates_full_tree_and_pull_returns_a_slice() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, mailbox_fp) = sample_envelope();
    let (tree, s2) = example_org_tree();
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
    {
        let url = url.clone();
        let push = push.clone();
        let envelope = envelope.clone();
        let tree = tree.clone();
        tokio::task::spawn_blocking(move || {
            relay::push_inbox_with_trees(&url, &push, &envelope, std::slice::from_ref(&tree))
        })
        .await
        .expect("join")
        .expect("push with tree");
    }

    let for_member = {
        let url = url.clone();
        let pull_s2 = pull_s2.clone();
        tokio::task::spawn_blocking(move || relay::pull_inbox(&url, &pull_s2, None, None))
            .await
            .expect("join")
            .expect("member pull")
    };
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
    link_ma1(&mut with_ma1);
    {
        let url = url.clone();
        let push = push.clone();
        let envelope = envelope.clone();
        tokio::task::spawn_blocking(move || {
            relay::push_inbox_with_trees(&url, &push, &envelope, std::slice::from_ref(&with_ma1))
        })
        .await
        .expect("join")
        .expect("push updated tree");
    }
    let expanded = {
        let url = url.clone();
        let pull_s2 = pull_s2.clone();
        tokio::task::spawn_blocking(move || relay::pull_inbox(&url, &pull_s2, None, None))
            .await
            .expect("join")
            .expect("expanded")
    };
    assert_eq!(expanded.trees[0].generation, 2);
    assert!(expanded.trees[0]
        .nodes
        .iter()
        .any(|node| node.label == "M.A.1"));

    let mail = {
        let url = url.clone();
        let pull_mailbox = pull_mailbox.clone();
        tokio::task::spawn_blocking(move || relay::pull_inbox(&url, &pull_mailbox, None, None))
            .await
            .expect("join")
            .expect("mailbox pull")
    };
    assert_eq!(mail.envelopes.len(), 1);
    assert!(mail.trees.is_empty());
}

#[cfg(feature = "provider")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn personal_store_push_does_not_erase_unrelated_relay_nodes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, _) = sample_envelope();
    let (tree, _s2) = example_org_tree();
    let a1_fp = tree
        .nodes
        .iter()
        .find(|node| node.label == "M.A.1")
        .and_then(|node| node.encryption_fingerprint.clone())
        .expect("a1 fp");
    let push = push_key(&conn);
    let pull_a1 = pull_key(&conn, &a1_fp);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = relay::router(AppState::new(conn));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let url = format!("http://{addr}");
    {
        let url = url.clone();
        let push = push.clone();
        let envelope = envelope.clone();
        let tree = tree.clone();
        tokio::task::spawn_blocking(move || {
            relay::push_inbox_with_trees(&url, &push, &envelope, std::slice::from_ref(&tree))
        })
        .await
        .expect("join")
        .expect("publish full tree");
    }
    let personal = crate::key_tree::filter_public_tree(
        &tree,
        &crate::key_tree::visible_labels_in_public_tree(&tree, &[String::from("M.S.2")]),
    );
    assert!(!personal.nodes.iter().any(|node| node.label == "M.A.1"));
    {
        let url = url.clone();
        let push = push.clone();
        let envelope = envelope.clone();
        tokio::task::spawn_blocking(move || {
            relay::push_inbox_with_trees(&url, &push, &envelope, std::slice::from_ref(&personal))
        })
        .await
        .expect("join")
        .expect("push personal subgraph");
    }
    let for_a1 = {
        let url = url.clone();
        let pull_a1 = pull_a1.clone();
        tokio::task::spawn_blocking(move || relay::pull_inbox(&url, &pull_a1, None, None))
            .await
            .expect("join")
            .expect("unrelated pull")
    };
    assert!(for_a1.trees[0]
        .nodes
        .iter()
        .any(|node| node.label == "M.A.1"));
}

#[cfg(feature = "provider")]
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

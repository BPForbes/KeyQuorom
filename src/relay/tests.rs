use super::test_helpers::*;
use crate::error::Error;
use crate::key_tree::PublicTree;
use crate::keys;
use crate::relay::{self, ApiKeyScope, NewApiKey};

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
    assert!(matches!(
        relay::authenticate(
            &conn,
            "kq_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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
fn mailbox_scan_deletes_expired_envelopes() {
    let conn = relay::open_in_memory().expect("schema");
    let (live, fingerprint) = sample_envelope();
    relay::store_until(&conn, &live, Some("2099-12-31 23:59:00")).expect("store live");
    let (_sk, pk) = keys::generate_encryption_keypair();
    let dead = fake_kqpb(pk, b"stale");
    let dead_fp = keys::fingerprint(&pk);
    relay::store_until(&conn, &dead, Some("2099-12-31 23:59:00")).expect("store dead");
    conn.execute(
        "UPDATE mailbox SET expires_at = datetime('now', '-1 minutes')
         WHERE recipient_fingerprint = ?1",
        rusqlite::params![dead_fp],
    )
    .expect("stamp past expiry");

    let purged = relay::purge_expired_envelopes(&conn).expect("scan");
    assert_eq!(purged, 1);
    let live_page = relay::list_after(&conn, &fingerprint, None, None).expect("list live");
    assert_eq!(live_page.envelopes.len(), 1);
    let dead_page = relay::list_after(&conn, &dead_fp, None, None).expect("list dead");
    assert!(dead_page.envelopes.is_empty());
}

#[test]
fn mailbox_list_hides_expired_envelopes() {
    let conn = relay::open_in_memory().expect("schema");
    let (envelope, fingerprint) = sample_envelope();
    relay::store_until(&conn, &envelope, Some("2099-12-31 23:59:00")).expect("store");
    conn.execute(
        "UPDATE mailbox SET expires_at = datetime('now', '-1 minutes')",
        [],
    )
    .expect("stamp past expiry");

    let listed = relay::list_after(&conn, &fingerprint, None, None).expect("list");
    assert!(listed.envelopes.is_empty());
    let remaining: i64 = conn
        .query_row("SELECT count(*) FROM mailbox", [], |row| row.get(0))
        .unwrap();
    assert_eq!(remaining, 0);
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
fn create_licensee_issuer_is_once_only_and_audit_has_no_secrets() {
    let conn = relay::open_in_memory().expect("schema");
    assert!(!relay::licensee_issuer_exists(&conn).expect("exists"));
    let first = relay::create_licensee_issuer_if_empty(&conn).expect("mint");
    assert!(first.token.starts_with("kql_"));
    assert!(matches!(
        relay::create_licensee_issuer_if_empty(&conn),
        Err(Error::ApiRootAlreadyExists)
    ));
    relay::record_provider_auth_event(
        &conn,
        "api-root.generate",
        Some("Acme"),
        Some("corp-vpn"),
        Some("abcd"),
        true,
    )
    .expect("audit");
    let (op, success, fingerprint): (String, i64, String) = conn
        .query_row(
            "SELECT operation, success, hardware_fingerprints FROM provider_auth_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("row");
    assert_eq!(op, "api-root.generate");
    assert_eq!(success, 1);
    assert_eq!(fingerprint, "abcd");
    let token_hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM provider_auth_events
             WHERE operation = ?1 OR provider_id = ?1 OR network_id = ?1
                OR hardware_fingerprints = ?1",
            [first.token.as_str()],
            |row| row.get(0),
        )
        .expect("token search");
    assert_eq!(token_hits, 0);
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

#[test]
fn supplied_licensee_key_does_not_bootstrap_an_empty_issuer_store() {
    let conn = relay::open_in_memory().expect("schema");
    assert!(matches!(
        relay::authorize_licensee_or_bootstrap(
            &conn,
            Some("kql_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        ),
        Err(Error::InvalidLicenseeKey)
    ));
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM licensee_issuer", [], |row| row.get(0))
        .expect("count");
    assert_eq!(n, 0);
    assert!(matches!(
        relay::authorize_licensee_or_bootstrap(&conn, Some("")),
        Err(Error::InvalidLicenseeKey)
    ));
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM licensee_issuer", [], |row| row.get(0))
        .expect("count after empty");
    assert_eq!(n, 0);
    let created = relay::authorize_licensee_or_bootstrap(&conn, None)
        .expect("bootstrap")
        .expect("created");
    let again = relay::authorize_licensee_or_bootstrap(&conn, Some(&created.token))
        .expect("supplied key authenticates");
    assert!(again.is_none());
}

#[test]
fn org_tree_put_and_context_omits_unrelated_peer_sibling() {
    let conn = relay::open_in_memory().expect("schema");
    let (tree, s2) = example_org_tree();
    let stored = relay::put_public_tree(&conn, &tree).expect("put");
    assert_eq!(stored.generation, 1);
    let fp = keys::fingerprint(&s2);
    let slice = relay::context_for_fingerprint(&conn, "org", &fp).expect("context");
    assert_eq!(
        node_labels(&slice),
        vec!["M", "M.A", "M.A.2", "M.S", "M.S.1", "M.S.2"]
    );

    let mut with_ma1 = tree.clone();
    link_ma1(&mut with_ma1);
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
fn merge_public_tree_keeps_nodes_absent_from_a_personal_slice() {
    let conn = relay::open_in_memory().expect("schema");
    let (tree, s2) = example_org_tree();
    relay::put_public_tree(&conn, &tree).expect("full");
    let slice =
        relay::context_for_fingerprint(&conn, "org", &keys::fingerprint(&s2)).expect("slice");
    assert!(!node_labels(&slice).contains(&"M.A.1".to_string()));
    let merged = relay::merge_public_tree(&conn, &slice).expect("merge slice");
    assert_eq!(merged.generation, 2);
    let stored = relay::get_public_tree(&conn, "org").expect("full still");
    assert!(node_labels(&stored).contains(&"M.A.1".to_string()));
    let a1_fp = tree
        .nodes
        .iter()
        .find(|node| node.label == "M.A.1")
        .and_then(|node| node.encryption_fingerprint.clone())
        .expect("a1 fp");
    let for_a1 = relay::context_for_fingerprint(&conn, "org", &a1_fp).expect("a1 context");
    assert!(node_labels(&for_a1).contains(&"M.A.1".to_string()));
}

#[test]
fn put_public_tree_rejects_a_link_without_a_whitelist_edge() {
    let conn = relay::open_in_memory().expect("schema");
    let (mut tree, _) = example_org_tree();
    tree.whitelist.clear();
    assert!(matches!(
        relay::put_public_tree(&conn, &tree),
        Err(Error::InvalidBridge)
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
    let (mut tree, _) = example_org_tree();
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

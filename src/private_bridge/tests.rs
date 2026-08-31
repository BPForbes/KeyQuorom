use super::*;
use crate::crypto::SALT_LEN;
use crate::db;
use crate::keys::KeyType;
use std::collections::BTreeSet;

fn enc(conn: &Connection, label: &str) -> (crypto_box::SecretKey, [u8; 32]) {
    let secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
    let public = *secret.public_key().as_bytes();
    keys::register_key(conn, label, KeyType::Encryption, &public).expect("register");
    (secret, public)
}

fn sign_key(conn: &Connection, label: &str) -> (zeroize::Zeroizing<[u8; 32]>, [u8; 32]) {
    let (secret, public) = keys::generate_signing_keypair();
    keys::register_key(conn, label, KeyType::Signing, &public).expect("register signing");
    (secret, public)
}

fn party(label: &str, pk: [u8; 32], signing_pk: [u8; 32]) -> BridgePartyInput {
    BridgePartyInput {
        label: label.to_string(),
        encryption_public_key: pk,
        signing_public_key: Some(signing_pk),
    }
}

fn supervisor(label: &str, pk: [u8; 32]) -> BridgePartyInput {
    BridgePartyInput {
        label: label.to_string(),
        encryption_public_key: pk,
        signing_public_key: None,
    }
}

fn five_party_keys(conn: &Connection) -> [(crypto_box::SecretKey, [u8; 32]); 5] {
    [
        enc(conn, "M.S.2"),
        enc(conn, "M.S.3"),
        enc(conn, "M.A.2"),
        enc(conn, "M.S"),
        enc(conn, "M.A"),
    ]
}

#[test]
fn notify_set_for_three_employees_is_five_stores() {
    let labels = notify_labels(["M.S.2", "M.S.3", "M.A.2"]);
    assert_eq!(
        labels,
        vec![
            "M.A".to_string(),
            "M.A.2".to_string(),
            "M.S".to_string(),
            "M.S.2".to_string(),
            "M.S.3".to_string(),
        ]
    );
    assert!(!labels.iter().any(|l| l == "M"));
    assert_eq!(parent_node_label("M.S.2"), Some("M.S"));
    assert_eq!(parent_node_label("M.S"), Some("M"));
    assert_eq!(parent_node_label("M"), None);
}

#[test]
fn create_emits_packages_for_members_and_department_managers() {
    let conn = db::open_in_memory().expect("schema");
    let [(_, pk_s2), (_, pk_s3), (_, pk_a2), (_, pk_s), (_, pk_a)] = five_party_keys(&conn);
    let [(_, spk_s2), (_, spk_s3), (_, spk_a2)] = [
        sign_key(&conn, "M.S.2"),
        sign_key(&conn, "M.S.3"),
        sign_key(&conn, "M.A.2"),
    ];
    let created = create(
        &conn,
        None,
        Some("eng-acct"),
        &[
            party("M.S.2", pk_s2, spk_s2),
            party("M.S.3", pk_s3, spk_s3),
            party("M.A.2", pk_a2, spk_a2),
        ],
        &[supervisor("M.S", pk_s), supervisor("M.A", pk_a)],
        Some("M.S.2"),
    )
    .expect("create");

    assert_eq!(created.packages.len(), 5);
    let mut labels: Vec<_> = created.packages.iter().map(|p| p.label.as_str()).collect();
    labels.sort();
    assert_eq!(labels, ["M.A", "M.A.2", "M.S", "M.S.2", "M.S.3"]);
    assert_eq!(
        created
            .packages
            .iter()
            .filter(|p| p.role == PartyRole::Member)
            .count(),
        3
    );
    assert_eq!(
        created
            .packages
            .iter()
            .filter(|p| p.role == PartyRole::Supervisor)
            .count(),
        2
    );

    let summary = get(&conn, &created.uid).expect("get");
    assert!(!summary.destroyed);
    assert_eq!(summary.generation, 1);
    assert_eq!(summary.salt.len(), SALT_LEN);
    let local = summary
        .parties
        .iter()
        .find(|p| p.label == "M.S.2")
        .expect("local member");
    assert!(local.is_local && local.has_sealed_key);
    assert!(!summary
        .parties
        .iter()
        .any(|p| p.label == "M.A.2" && p.has_sealed_key));
}

#[test]
fn independent_stores_import_sign_and_verify() {
    let creator = db::open_in_memory().expect("schema");
    let [(_sk_s2, pk_s2), (sk_s3, pk_s3), (sk_a2, pk_a2), (sk_s, pk_s), (sk_a, pk_a)] =
        five_party_keys(&creator);
    let [(_, spk_s2), (_, spk_s3), (sign_a2, spk_a2)] = [
        sign_key(&creator, "M.S.2"),
        sign_key(&creator, "M.S.3"),
        sign_key(&creator, "M.A.2"),
    ];
    let created = create(
        &creator,
        None,
        Some("eng-acct"),
        &[
            party("M.S.2", pk_s2, spk_s2),
            party("M.S.3", pk_s3, spk_s3),
            party("M.A.2", pk_a2, spk_a2),
        ],
        &[supervisor("M.S", pk_s), supervisor("M.A", pk_a)],
        Some("M.S.2"),
    )
    .expect("create");

    let pkg = |label: &str| {
        created
            .packages
            .iter()
            .find(|p| p.label == label)
            .expect("package")
            .bytes
            .clone()
    };

    let db_s3 = db::open_in_memory().expect("s3 db");
    let db_a2 = db::open_in_memory().expect("a2 db");
    let db_ms = db::open_in_memory().expect("ms db");
    let db_ma = db::open_in_memory().expect("ma db");
    import_package(&db_s3, &pkg("M.S.3"), &sk_s3.to_bytes()).expect("import s3");
    import_package(&db_a2, &pkg("M.A.2"), &sk_a2.to_bytes()).expect("import a2");
    let ms = import_package(&db_ms, &pkg("M.S"), &sk_s.to_bytes()).expect("import manager S");
    let ma = import_package(&db_ma, &pkg("M.A"), &sk_a.to_bytes()).expect("import manager A");
    assert!(!ms.parties.iter().any(|p| p.has_sealed_key));
    assert!(!ma.parties.iter().any(|p| p.has_sealed_key));
    assert!(ms
        .parties
        .iter()
        .any(|p| p.label == "M.S" && p.role == PartyRole::Supervisor && p.is_local));

    let sign_sk = sign_a2;
    let message = b"quarterly shared PDF";
    let artifact = sign_message(
        &db_a2,
        &created.uid,
        "M.A.2",
        &sk_a2.to_bytes(),
        &sign_sk,
        message,
    )
    .expect("sign");
    verify_message(&creator, &created.uid, "M.S.2", message, &artifact).expect("s2 verifies");
    verify_message(&db_s3, &created.uid, "M.S.3", message, &artifact).expect("s3 verifies");
    assert!(matches!(
        verify_message(&db_ms, &created.uid, "M.S", message, &artifact),
        Err(Error::NotBridgeMember)
    ));

    let again = sign_message(
        &db_a2,
        &created.uid,
        "M.A.2",
        &sk_a2.to_bytes(),
        &sign_sk,
        message,
    )
    .expect("sign again");
    assert_ne!(artifact.signature_salt, again.signature_salt);
    verify_message(&db_s3, &created.uid, "M.S.3", message, &again).expect("second sig");
}

#[test]
fn remove_member_rotates_and_notifies_remaining_stores() {
    let creator = db::open_in_memory().expect("schema");
    let [(sk_s2, pk_s2), (sk_s3, pk_s3), (sk_a2, pk_a2), (_, pk_s), (_, pk_a)] =
        five_party_keys(&creator);
    let [(sign_s2, spk_s2), (_, spk_s3), (_, spk_a2)] = [
        sign_key(&creator, "M.S.2"),
        sign_key(&creator, "M.S.3"),
        sign_key(&creator, "M.A.2"),
    ];
    let created = create(
        &creator,
        None,
        Some("eng-acct"),
        &[
            party("M.S.2", pk_s2, spk_s2),
            party("M.S.3", pk_s3, spk_s3),
            party("M.A.2", pk_a2, spk_a2),
        ],
        &[supervisor("M.S", pk_s), supervisor("M.A", pk_a)],
        Some("M.S.2"),
    )
    .expect("create");
    let pkg = |label: &str| {
        created
            .packages
            .iter()
            .find(|p| p.label == label)
            .unwrap()
            .bytes
            .clone()
    };
    let db_a2 = db::open_in_memory().expect("a2");
    import_package(&db_a2, &pkg("M.A.2"), &sk_a2.to_bytes()).expect("import a2");
    let db_s3 = db::open_in_memory().expect("s3");
    import_package(&db_s3, &pkg("M.S.3"), &sk_s3.to_bytes()).expect("import s3");

    let sign_sk = sign_s2;
    let old_sig = sign_message(
        &creator,
        &created.uid,
        "M.S.2",
        &sk_s2.to_bytes(),
        &sign_sk,
        b"old",
    )
    .expect("old sig");

    let outcome =
        remove_member(&creator, &created.uid, "M.S.3", "M.S.2", &sk_s2.to_bytes()).expect("remove");
    assert!(!outcome.destroyed);
    assert_eq!(
        outcome.remaining_members,
        vec!["M.A.2".to_string(), "M.S.2".to_string()]
    );
    let labels: BTreeSet<_> = outcome.packages.iter().map(|p| p.label.as_str()).collect();
    assert!(labels.contains("M.A.2"));
    assert!(labels.contains("M.S"));
    assert!(labels.contains("M.A"));
    assert!(labels.contains("M.S.3"));

    let a2_rotate = outcome
        .packages
        .iter()
        .find(|p| p.label == "M.A.2" && p.role == PartyRole::Member)
        .expect("a2 rotate");
    import_package(&db_a2, &a2_rotate.bytes, &sk_a2.to_bytes()).expect("a2 import rotate");
    assert!(matches!(
        import_package(&db_a2, &a2_rotate.bytes, &sk_a2.to_bytes()),
        Err(Error::BridgeGenerationMismatch)
    ));

    assert!(matches!(
        verify_message(&db_a2, &created.uid, "M.A.2", b"old", &old_sig),
        Err(Error::BridgeGenerationMismatch)
    ));
    let new_sig = sign_message(
        &creator,
        &created.uid,
        "M.S.2",
        &sk_s2.to_bytes(),
        &sign_sk,
        b"new",
    )
    .expect("new sig");
    verify_message(&db_a2, &created.uid, "M.A.2", b"new", &new_sig).expect("new verifies");
    assert!(matches!(
        verify_message(&db_s3, &created.uid, "M.S.3", b"new", &new_sig),
        Err(Error::NotBridgeMember) | Err(Error::BridgeGenerationMismatch)
    ));

    let s3_destroy = outcome
        .packages
        .iter()
        .find(|p| p.label == "M.S.3")
        .expect("s3 destroy");
    import_package(&db_s3, &s3_destroy.bytes, &sk_s3.to_bytes()).expect("s3 ingest destroy");
    assert!(get(&db_s3, &created.uid).unwrap().destroyed);
}

#[test]
fn removing_a_manager_who_still_supervises_keeps_them_on_the_roster() {
    let creator = db::open_in_memory().expect("schema");
    let (sk_s, pk_s) = enc(&creator, "M.S");
    let (sk_s2, pk_s2) = enc(&creator, "M.S.2");
    let (_, pk_a2) = enc(&creator, "M.A.2");
    let (sk_m, pk_m) = enc(&creator, "M");
    let (_, pk_a) = enc(&creator, "M.A");
    let (_, spk_s) = sign_key(&creator, "M.S");
    let (_, spk_s2) = sign_key(&creator, "M.S.2");
    let (_, spk_a2) = sign_key(&creator, "M.A.2");
    // M.S signs as a member *and* is M.S.2's department manager.
    let created = create(
        &creator,
        None,
        Some("eng-acct"),
        &[
            party("M.S", pk_s, spk_s),
            party("M.S.2", pk_s2, spk_s2),
            party("M.A.2", pk_a2, spk_a2),
        ],
        &[supervisor("M", pk_m), supervisor("M.A", pk_a)],
        Some("M.S.2"),
    )
    .expect("create");

    let invite = |label: &str| {
        created
            .packages
            .iter()
            .find(|p| p.label == label)
            .unwrap_or_else(|| panic!("invite for {label}"))
            .bytes
            .clone()
    };
    let db_s = db::open_in_memory().expect("m.s store");
    import_package(&db_s, &invite("M.S"), &sk_s.to_bytes()).expect("import M.S invite");
    let db_m = db::open_in_memory().expect("m store");
    import_package(&db_m, &invite("M"), &sk_m.to_bytes()).expect("import M invite");

    let outcome =
        remove_member(&creator, &created.uid, "M.S", "M.S.2", &sk_s2.to_bytes()).expect("remove");
    assert!(!outcome.destroyed);

    // One envelope per store, or the CLI cannot write them to one directory.
    let labels: Vec<&str> = outcome.packages.iter().map(|p| p.label.as_str()).collect();
    let unique: BTreeSet<&str> = labels.iter().copied().collect();
    assert_eq!(
        labels.len(),
        unique.len(),
        "duplicate envelopes: {labels:?}"
    );
    // M.S stays on as M.S.2's manager; M was only there for member M.S.
    assert_eq!(
        unique,
        BTreeSet::from(["M", "M.A", "M.A.2", "M.S", "M.S.2"])
    );

    let for_s = outcome
        .packages
        .iter()
        .find(|p| p.label == "M.S")
        .expect("M.S package");
    assert_eq!(for_s.role, PartyRole::Supervisor);
    import_package(&db_s, &for_s.bytes, &sk_s.to_bytes()).expect("M.S tracks the new generation");
    let s_view = get(&db_s, &created.uid).expect("M.S summary");
    assert!(!s_view.destroyed);
    assert_eq!(s_view.generation, created.generation + 1);
    assert!(s_view
        .parties
        .iter()
        .any(|p| p.label == "M.S" && p.role == PartyRole::Supervisor && !p.has_sealed_key));

    // M supervised nobody but member M.S, so their store drops the bridge.
    let for_m = outcome
        .packages
        .iter()
        .find(|p| p.label == "M")
        .expect("M package");
    import_package(&db_m, &for_m.bytes, &sk_m.to_bytes()).expect("M ingests destroy");
    assert!(get(&db_m, &created.uid).expect("M summary").destroyed);
}

#[test]
fn two_member_bridge_is_destroyed_when_one_leaves() {
    let conn = db::open_in_memory().expect("schema");
    let (sk_s3, pk_s3) = enc(&conn, "M.S.3");
    let (_, pk_a1) = enc(&conn, "M.A.1");
    let (_, pk_s) = enc(&conn, "M.S");
    let (_, pk_a) = enc(&conn, "M.A");
    let (_, spk_s3) = sign_key(&conn, "M.S.3");
    let (_, spk_a1) = sign_key(&conn, "M.A.1");
    let created = create(
        &conn,
        None,
        None,
        &[party("M.S.3", pk_s3, spk_s3), party("M.A.1", pk_a1, spk_a1)],
        &[supervisor("M.S", pk_s), supervisor("M.A", pk_a)],
        Some("M.S.3"),
    )
    .expect("create");
    let outcome =
        remove_member(&conn, &created.uid, "M.A.1", "M.S.3", &sk_s3.to_bytes()).expect("destroy");
    assert!(outcome.destroyed);
    assert!(get(&conn, &created.uid).unwrap().destroyed);
    let notify = notify_labels(["M.S.3", "M.A.1"]);
    assert_eq!(notify.len(), 4);
}

#[test]
fn create_requires_department_manager_pubs() {
    let conn = db::open_in_memory().expect("schema");
    let (_, pk_s2) = enc(&conn, "M.S.2");
    let (_, pk_a2) = enc(&conn, "M.A.2");
    let (_, spk_s2) = sign_key(&conn, "M.S.2");
    let (_, spk_a2) = sign_key(&conn, "M.A.2");
    let err = create(
        &conn,
        None,
        None,
        &[party("M.S.2", pk_s2, spk_s2), party("M.A.2", pk_a2, spk_a2)],
        &[],
        Some("M.S.2"),
    )
    .unwrap_err();
    assert!(matches!(err, Error::NodeNotFound));
}

#[test]
fn coordinator_evict_notice_lists_five_stakeholders() {
    let mut conn = db::open_in_memory().expect("schema");
    let (_, pk_s2) = enc(&conn, "M.S.2");
    let (_, pk_s3) = enc(&conn, "M.S.3");
    let (_, pk_a2) = enc(&conn, "M.A.2");
    let (_, pk_s) = enc(&conn, "M.S");
    let (_, pk_a) = enc(&conn, "M.A");
    let id_s2 = keys::list_keys(&conn)
        .unwrap()
        .into_iter()
        .find(|k| k.label == "M.S.2")
        .unwrap()
        .id;
    let id_s3 = keys::list_keys(&conn)
        .unwrap()
        .into_iter()
        .find(|k| k.label == "M.S.3")
        .unwrap()
        .id;
    let spec = crate::key_tree::NodeSpec::flat_split(
        "root",
        2,
        vec![("M.S.2".into(), id_s2), ("M.S.3".into(), id_s3)],
    );
    let (_, spk_s2) = sign_key(&conn, "M.S.2");
    let (_, spk_s3) = sign_key(&conn, "M.S.3");
    let (_, spk_a2) = sign_key(&conn, "M.A.2");
    let secret = *crate::crypto::random_key();
    let key_id = crate::key_tree::split(&mut conn, "org", &secret, &spec).expect("split");
    create(
        &conn,
        Some(key_id),
        Some("eng-acct"),
        &[
            party("M.S.2", pk_s2, spk_s2),
            party("M.S.3", pk_s3, spk_s3),
            party("M.A.2", pk_a2, spk_a2),
        ],
        &[supervisor("M.S", pk_s), supervisor("M.A", pk_a)],
        None,
    )
    .expect("create coordinator view");

    let changes = on_leaf_removed(&conn, key_id, "M.S.3").expect("notice");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].kind, BridgeChangeKind::NeedsMemberRotate);
    assert_eq!(changes[0].notify.len(), 5);
    assert!(changes[0].notify.iter().any(|l| l == "M.A"));
    assert!(changes[0].notify.iter().any(|l| l == "M.S"));
}

#[test]
fn verify_rejects_impersonation_with_unrelated_personal_key() {
    let creator = db::open_in_memory().expect("schema");
    let [(sk_s2, pk_s2), (_, pk_s3), (_, pk_a2), (_, pk_s), (_, pk_a)] = five_party_keys(&creator);
    let [(sign_s2, spk_s2), (_, spk_s3), (sign_a2, spk_a2)] = [
        sign_key(&creator, "M.S.2"),
        sign_key(&creator, "M.S.3"),
        sign_key(&creator, "M.A.2"),
    ];
    let created = create(
        &creator,
        None,
        Some("eng-acct"),
        &[
            party("M.S.2", pk_s2, spk_s2),
            party("M.S.3", pk_s3, spk_s3),
            party("M.A.2", pk_a2, spk_a2),
        ],
        &[supervisor("M.S", pk_s), supervisor("M.A", pk_a)],
        Some("M.S.2"),
    )
    .expect("create");

    let bridge_sk =
        unseal_local_secret(&creator, &created.uid, "M.S.2", &sk_s2.to_bytes()).expect("unseal");
    let (attacker_sk, _) = keys::generate_signing_keypair();
    let artifact = crate::signing::sign_with_bridge(
        &created.uid,
        created.generation,
        &created.salt,
        "M.A.2",
        &bridge_sk,
        &attacker_sk,
        b"forged",
    )
    .expect("crafted artifact");
    assert!(matches!(
        verify_message(&creator, &created.uid, "M.S.2", b"forged", &artifact),
        Err(Error::SignatureVerificationFailed)
    ));
    let (wrong_sk, _) = keys::generate_signing_keypair();
    assert!(matches!(
        sign_message(
            &creator,
            &created.uid,
            "M.S.2",
            &sk_s2.to_bytes(),
            &wrong_sk,
            b"nope",
        ),
        Err(Error::IntegrityCheckFailed)
    ));

    let valid = crate::signing::sign_with_bridge(
        &created.uid,
        created.generation,
        &created.salt,
        "M.A.2",
        &bridge_sk,
        &sign_a2,
        b"ok",
    )
    .expect("roster-bound artifact");
    verify_message(&creator, &created.uid, "M.S.2", b"ok", &valid).expect("roster key verifies");

    replace_registered_signing_key(&creator, "M.A.2");
    assert!(matches!(
        verify_message(&creator, &created.uid, "M.S.2", b"ok", &valid),
        Err(Error::IntegrityCheckFailed)
    ));

    replace_registered_signing_key(&creator, "M.S.2");
    assert!(matches!(
        sign_message(
            &creator,
            &created.uid,
            "M.S.2",
            &sk_s2.to_bytes(),
            &sign_s2,
            b"later",
        ),
        Err(Error::IntegrityCheckFailed)
    ));
}

fn replace_registered_signing_key(conn: &Connection, label: &str) {
    let old = keys::list_keys(conn)
        .expect("list")
        .into_iter()
        .find(|k| k.label == label && k.key_type == KeyType::Signing && k.revoked_at.is_none())
        .expect("active signing key");
    keys::revoke_key(conn, old.id).expect("revoke old signing key");
    let (_, replacement) = keys::generate_signing_keypair();
    keys::register_key(conn, label, KeyType::Signing, &replacement).expect("register replacement");
}

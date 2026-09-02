use super::super::*;

#[test]
fn share_options_reject_unusable_limits() {
    for args in [
        [
            "keyquorum",
            "share",
            "create-file",
            "1",
            "--ttl-seconds",
            "0",
        ],
        ["keyquorum", "share", "create-file", "1", "--max-uses", "-1"],
        [
            "keyquorum",
            "share",
            "create-file",
            "1",
            "--expires",
            "2026-12-31",
        ],
        [
            "keyquorum",
            "share",
            "create-file",
            "1",
            "--expires",
            "2026-13-01 00:00",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }

    assert!(Cli::try_parse_from([
        "keyquorum",
        "share",
        "create-file",
        "1",
        "--expires",
        "2026-12-31 23:59",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "password",
        "--state",
        "0",
        "--source",
        "secret.txt",
        "--encrypted-path",
        "secret.txt.kqenc",
        "--expires",
        "2026-12-31 23:59",
    ])
    .is_ok());
}

#[test]
fn pin_every_use_requires_enabling_a_pin() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "share",
        "create-credential",
        "1",
        "--pin-required-every-use",
    ])
    .is_err());
}

#[test]
fn quorum_status_rejects_mutating_options() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "quorum",
        "--status",
        "--id",
        "1",
        "--output",
        "plaintext",
    ])
    .is_err());
}

#[test]
fn access_modes_require_and_reject_mode_specific_options() {
    for args in [
        vec!["keyquorum", "access", "password", "--state", "0"],
        vec![
            "keyquorum",
            "access",
            "password",
            "--state",
            "1",
            "--id",
            "1",
            "--source",
            "plaintext",
        ],
        vec![
            "keyquorum",
            "access",
            "quorum",
            "--state",
            "0",
            "--source",
            "plaintext",
            "--encrypted-path",
            "ciphertext",
            "--tree-spec",
            "tree.json",
            "--leaf",
            "a=a.pub",
        ],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }

    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "password",
        "--state",
        "1",
        "--id",
        "1",
        "--output",
        "plaintext",
    ])
    .is_ok());
}

#[test]
fn top_level_tree_and_bridge_parse() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bridge",
        "allow",
        "1",
        "--node",
        "M.A.1",
        "--peer",
        "M.B",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bridge",
        "add",
        "1",
        "--from",
        "M.A.1",
        "--to",
        "M.B",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bridge",
        "remove",
        "1",
        "--from",
        "M.A.1",
        "--to",
        "M.B",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "lca", "1", "--node", "M.A.1", "M.A.2"]).is_err());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "1", "--node", "M.A.1", "M.A.2",]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "1", "--node", "only-one"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "reconstruct",
        "1",
        "--node",
        "M.A.1",
        "M.A.2",
        "--share-file",
        "alice.pub",
        "--output",
        "master.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "split",
        "--tree-spec",
        "team.json",
        "--label",
        "master pub",
        "--source",
        "master.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "split",
        "--label",
        "master",
        "--threshold",
        "2",
        "--leaf",
        "M.S=SoftwareDepartment.pub",
        "--leaf",
        "M.A=AccountingDepartment.pub",
        "--source",
        "master.pub",
        "--generate-keys",
        "--register",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "split",
        "--tree-spec",
        "org.json",
        "--label",
        "master",
        "--leaf",
        "M.S=SoftwareDepartment.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "spec", "--label", "M"]).is_err());
    assert!(
        Cli::try_parse_from(["keyquorum", "bind", "1", "--node", "M.S", "--peer", "M.A",]).is_ok()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bind",
        "1",
        "--node",
        "M.S",
        "--public-key-file",
        "NewSoftware.pub",
        "--share-file",
        "SoftwareDepartment.key",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "bind",
        "1",
        "--node",
        "M.S",
        "--peer",
        "M.A",
        "--public-key-file",
        "NewSoftware.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "add",
        "1",
        "--parent",
        "M",
        "--node",
        "M.F",
        "--public-key-file",
        "FinanceDepartment.pub",
        "--share-file",
        "SoftwareDepartment.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "1", "--output", "org.json",]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "tree",
        "1",
        "--node",
        "M.S",
        "M.A",
        "--output",
        "org.json",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "evict", "1", "--node-id", "5"]).is_err());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "revoke",
        "3",
        "--key-id",
        "1",
        "--node",
        "carol",
        "--evict",
        "--share-file",
        "alice.key",
        "--deny-peer",
        "it",
        "--remove-peer",
        "bob",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3", "--evict"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "publish", "1"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "fetch", "1"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "fetch", "--label", "master"]).is_ok());
    assert!(Cli::try_parse_from(["keyquorum", "tree", "fetch"]).is_err());
    assert!(
        Cli::try_parse_from(["keyquorum", "tree", "project", "1", "--as-node", "M.S.2"]).is_err()
    );
    assert!(Cli::try_parse_from([
        "keyquorum",
        "generate",
        "--type",
        "encryption",
        "--public-key-out",
        "alice.pub",
        "--label",
        "alice",
        "--register",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "generate",
        "--type",
        "encryption",
        "--public-key-out",
        "alice.pub",
        "--register",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "access",
        "quorum",
        "--state",
        "0",
        "--source",
        "secret.txt",
        "--encrypted-path",
        "secret.txt.kqenc",
        "--leaf",
        "alice=alice.pub",
        "--leaf",
        "bob=bob.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "key",
        "split",
        "--label",
        "master",
        "--leaf",
        "a=a.pub",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3", "--key-id", "1", "--evict"]).is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "revoke",
        "3",
        "--key-id",
        "1",
        "--node",
        "carol",
        "--share-file",
        "alice.key",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "revoke", "3", "--deny-peer", "it"]).is_err());
}

#[test]
fn infer_root_label_from_dotted_leaves_or_fallback() {
    assert_eq!(
        infer_root_label(&["M.S".into(), "M.A".into()], None, "master").unwrap(),
        "M"
    );
    assert_eq!(
        infer_root_label(&["alice".into(), "bob".into()], None, "team").unwrap(),
        "team"
    );
    assert_eq!(
        infer_root_label(&["M.S".into(), "M.A".into()], Some("org"), "master").unwrap(),
        "org"
    );
}

#[test]
fn relay_push_requires_dir() {
    assert!(Cli::try_parse_from(["keyquorum", "relay", "push"]).is_err());
}

#[test]
fn relay_pull_requires_output_or_import() {
    assert!(Cli::try_parse_from(["keyquorum", "relay", "pull"]).is_err());
}

#[test]
fn relay_pull_import_requires_share_file() {
    assert!(Cli::try_parse_from(["keyquorum", "relay", "pull", "--import"]).is_err());
}

#[test]
fn relay_pull_import_with_share_file_parses() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "relay",
        "pull",
        "--import",
        "--share-file",
        "alice.key",
        "--url",
        "http://127.0.0.1:8787",
    ])
    .is_ok());
}

#[test]
fn relay_push_with_dir_parses() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "relay",
        "push",
        "--dir",
        "./packages",
        "--url",
        "http://127.0.0.1:8787",
    ])
    .is_ok());
}

#[test]
fn loadkey_parses_with_and_without_positional_key() {
    assert!(Cli::try_parse_from(["keyquorum", "loadkey"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "loadkey",
        "kq_example",
        "--url",
        "http://127.0.0.1:8787",
    ])
    .is_ok());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_keys_list_parses() {
    assert!(Cli::try_parse_from(["keyquorum", "host", "keys", "list"]).is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "--mailbox-db",
        "mailbox.sqlite",
        "serve",
        "--bind",
        "127.0.0.1:0",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "serve",
        "--scan-db",
        "org.sqlite",
        "--scan-interval-seconds",
        "15",
    ])
    .is_ok());
    assert!(
        Cli::try_parse_from(["keyquorum", "host", "serve", "--scan-interval-seconds", "0",])
            .is_err()
    );
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_identity_and_certify_parse() {
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "identity",
        "generate",
        "--public-key-out",
        "relay.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "certify",
        "--relay-public-key",
        "relay.pub",
        "--provider-id",
        "acme",
        "--serial",
        "KQP-1",
        "--expires-at",
        "2027-09-02 00:00:00",
        "--out",
        "provider.kqcert",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "krl",
        "--serial",
        "KQP-1",
        "--out",
        "revocations.kqrl",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "serve",
        "--cert",
        "provider.kqcert",
        "--relay-key",
        "relay.key",
        "--krl",
        "revocations.kqrl",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "provider-root.pub",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "provider-root.pub",
        "--network",
        "10.8.0.0/24",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "root",
        "generate",
        "--public-key-out",
        "provider-root.pub",
        "--ssid",
        "Office",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "policy",
        "issue",
        "--relay-public-key",
        "relay.pub",
        "--provider-id",
        "acme",
        "--policy-id",
        "KQP-POL-1",
        "--expires-at",
        "2027-09-02 00:00:00",
        "--hardware-fingerprint",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--out",
        "provider.kqpolicy",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "policy",
        "issue",
        "--relay-public-key",
        "relay.pub",
        "--provider-id",
        "acme",
        "--policy-id",
        "KQP-POL-1",
        "--expires-at",
        "2027-09-02 00:00:00",
        "--hardware-fingerprint",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--corporate-network",
        "corp-vpn:10.8.0.0/24",
        "--out",
        "provider.kqpolicy",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "relay",
        "register",
        "--url",
        "http://127.0.0.1:8787",
        "--provider-id",
        "acme",
        "--hardware-key",
        "hw.key",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "keyquorum",
        "host",
        "keys",
        "create",
        "--scope",
        "inbox.push",
    ])
    .is_err());
    assert!(Cli::try_parse_from(["keyquorum", "host", "keys", "rotate", "--id", "1"]).is_err());
}

#[cfg(feature = "provider")]
#[test]
fn provider_host_is_omitted_from_top_level_help() {
    use clap::CommandFactory;
    let help = Cli::command().render_long_help().to_string();
    assert!(
        !help
            .lines()
            .any(|line| line.split_whitespace().next() == Some("host")),
        "hidden host command leaked into --help:\n{help}"
    );
}

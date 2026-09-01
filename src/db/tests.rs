use super::*;
use rusqlite::params;

#[test]
fn schema_applies_cleanly() {
    let conn = open_in_memory().expect("schema should apply");
    let table_count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .expect("query should succeed");
    assert_eq!(table_count, 17);
}

#[test]
fn schema_is_idempotent() {
    let conn = open_in_memory().expect("schema should apply");
    conn.execute_batch(SCHEMA)
        .expect("re-applying schema should not error");
}

fn seed_encryption_key(conn: &Connection, id: i64) {
    conn.execute(
        "INSERT INTO hardware_keys (id, label, key_type, fingerprint, public_key)
             VALUES (?1, 'enc-key', 'encryption', ?2, x'01')",
        params![id, format!("fp-enc-{id}")],
    )
    .expect("seed encryption hardware_keys row");
}

fn seed_signing_key(conn: &Connection, id: i64) {
    conn.execute(
        "INSERT INTO hardware_keys (id, label, key_type, fingerprint, public_key)
             VALUES (?1, 'sign-key', 'signing', ?2, x'02')",
        params![id, format!("fp-sign-{id}")],
    )
    .expect("seed signing hardware_keys row");
}

fn seed_key(conn: &Connection, id: i64) {
    conn.execute(
        "INSERT INTO keys (id, label) VALUES (?1, 'test-key')",
        params![id],
    )
    .expect("seed keys row");
}

#[test]
fn key_node_leaf_backed_by_signing_key_is_blocked() {
    let conn = open_in_memory().expect("schema should apply");
    seed_signing_key(&conn, 1);
    seed_key(&conn, 1);

    let result = conn.execute(
        "INSERT INTO key_nodes (key_id, label, hardware_key_id, wrapped_share)
             VALUES (1, 'leaf', 1, x'aa')",
        [],
    );
    assert!(result.is_err());
}

#[test]
fn key_node_leaf_backed_by_encryption_key_is_allowed() {
    let conn = open_in_memory().expect("schema should apply");
    seed_encryption_key(&conn, 1);
    seed_key(&conn, 1);

    let result = conn.execute(
        "INSERT INTO key_nodes (key_id, label, hardware_key_id, wrapped_share)
             VALUES (1, 'leaf', 1, x'aa')",
        [],
    );
    assert!(result.is_ok());
}

#[test]
fn key_node_topology_only_leaf_is_allowed() {
    let conn = open_in_memory().expect("schema should apply");
    seed_encryption_key(&conn, 1);
    seed_key(&conn, 1);

    let result = conn.execute(
        "INSERT INTO key_nodes (key_id, label, hardware_key_id)
             VALUES (1, 'peer', 1)",
        [],
    );
    assert!(result.is_ok());
    let share: Option<Vec<u8>> = conn
        .query_row(
            "SELECT wrapped_share FROM key_nodes WHERE label = 'peer'",
            [],
            |row| row.get(0),
        )
        .expect("row");
    assert!(share.is_none());
}

#[test]
fn key_node_leaf_cannot_be_reassigned_to_a_signing_key_via_update() {
    let conn = open_in_memory().expect("schema should apply");
    seed_encryption_key(&conn, 1);
    seed_signing_key(&conn, 2);
    seed_key(&conn, 1);
    conn.execute(
        "INSERT INTO key_nodes (key_id, label, hardware_key_id, wrapped_share)
             VALUES (1, 'leaf', 1, x'aa')",
        [],
    )
    .expect("seed key_nodes leaf");

    let result = conn.execute(
        "UPDATE key_nodes SET hardware_key_id = 2 WHERE key_id = 1 AND label = 'leaf'",
        [],
    );
    assert!(result.is_err());
}

#[test]
fn key_node_rejects_mixed_split_and_leaf_shape() {
    let conn = open_in_memory().expect("schema should apply");
    seed_encryption_key(&conn, 1);
    seed_key(&conn, 1);

    // threshold set alongside hardware_key_id/wrapped_share: neither a
    // clean split node nor a clean leaf.
    let result = conn.execute(
        "INSERT INTO key_nodes (key_id, label, threshold, hardware_key_id, wrapped_share)
             VALUES (1, 'bad', 2, 1, x'aa')",
        [],
    );
    assert!(result.is_err());
}

#[test]
fn key_node_rejects_neither_split_nor_leaf_shape() {
    let conn = open_in_memory().expect("schema should apply");
    seed_key(&conn, 1);

    let result = conn.execute(
        "INSERT INTO key_nodes (key_id, label) VALUES (1, 'empty')",
        [],
    );
    assert!(result.is_err());
}

#[test]
fn key_node_split_node_is_allowed() {
    let conn = open_in_memory().expect("schema should apply");
    seed_key(&conn, 1);

    let result = conn.execute(
        "INSERT INTO key_nodes (key_id, label, threshold) VALUES (1, 'split', 2)",
        [],
    );
    assert!(result.is_ok());
}

#[test]
fn files_key_id_must_reference_an_existing_key() {
    let conn = open_in_memory().expect("schema should apply");
    let result = conn.execute(
        "INSERT INTO files (name, encrypted_path, key_id, nonce)
             VALUES ('secret.txt', '/data/secret.txt.enc', 999, x'00')",
        [],
    );
    assert!(result.is_err());
}

#[test]
fn opening_a_legacy_key_nodes_table_adds_is_active() {
    let conn = Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(
        "CREATE TABLE key_nodes (
                id                INTEGER PRIMARY KEY,
                key_id            INTEGER NOT NULL,
                parent_id         INTEGER,
                label             TEXT NOT NULL,
                threshold         INTEGER,
                hardware_key_id   INTEGER,
                wrapped_share     BLOB
             );
             CREATE TABLE keys (
                id INTEGER PRIMARY KEY,
                label TEXT NOT NULL
             );
             INSERT INTO keys (id, label) VALUES (1, 'legacy');
             INSERT INTO key_nodes (key_id, label, threshold) VALUES (1, 'root', 1);",
    )
    .expect("legacy schema should apply");

    assert!(!table_has_column(&conn, "key_nodes", "is_active").unwrap());
    init(&conn).expect("init should migrate the legacy table");

    let is_active: i64 = conn
        .query_row(
            "SELECT is_active FROM key_nodes WHERE label = 'root'",
            [],
            |row| row.get(0),
        )
        .expect("is_active should be readable after migrate");
    assert_eq!(is_active, 1);
    init(&conn).expect("a second init must be idempotent");
}

#[test]
fn rebuilding_share_required_key_nodes_keeps_bridge_rows() {
    let conn = Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE keys (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL
         );
         CREATE TABLE hardware_keys (
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            key_type TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            public_key BLOB NOT NULL
         );
         CREATE TABLE key_nodes (
            id INTEGER PRIMARY KEY,
            key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
            parent_id INTEGER REFERENCES key_nodes(id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            threshold INTEGER,
            hardware_key_id INTEGER REFERENCES hardware_keys(id),
            wrapped_share BLOB,
            is_active INTEGER NOT NULL DEFAULT 1,
            CHECK (
                (threshold IS NOT NULL AND hardware_key_id IS NULL AND wrapped_share IS NULL)
                OR (threshold IS NULL AND hardware_key_id IS NOT NULL AND wrapped_share IS NOT NULL)
            )
         );
         CREATE TABLE key_node_bridges (
            node_id INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
            peer_label TEXT NOT NULL,
            PRIMARY KEY (node_id, peer_label)
         );
         CREATE TABLE key_node_links (
            node_a_id INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
            node_b_id INTEGER NOT NULL REFERENCES key_nodes(id) ON DELETE CASCADE,
            established_at TEXT NOT NULL DEFAULT 'now',
            PRIMARY KEY (node_a_id, node_b_id),
            CHECK (node_a_id < node_b_id)
         );
         INSERT INTO keys (id, label) VALUES (1, 'legacy');
         INSERT INTO hardware_keys (id, label, key_type, fingerprint, public_key)
            VALUES (1, 'a', 'encryption', 'fp-a', x'01'),
                   (2, 'b', 'encryption', 'fp-b', x'02');
         INSERT INTO key_nodes (id, key_id, parent_id, label, threshold, is_active)
            VALUES (1, 1, NULL, 'root', 2, 1);
         INSERT INTO key_nodes (id, key_id, parent_id, label, hardware_key_id, wrapped_share, is_active)
            VALUES (2, 1, 1, 'left', 1, x'aa', 1),
                   (3, 1, 1, 'right', 2, x'bb', 1);
         INSERT INTO key_node_bridges (node_id, peer_label) VALUES (2, 'right');
         INSERT INTO key_node_links (node_a_id, node_b_id) VALUES (2, 3);",
    )
    .expect("legacy schema should apply");

    init(&conn).expect("init should rebuild key_nodes");

    let bridges: i64 = conn
        .query_row("SELECT count(*) FROM key_node_bridges", [], |row| {
            row.get(0)
        })
        .expect("bridges");
    let links: i64 = conn
        .query_row("SELECT count(*) FROM key_node_links", [], |row| row.get(0))
        .expect("links");
    assert_eq!(bridges, 1);
    assert_eq!(links, 1);
    let sql = table_sql(&conn, "key_nodes")
        .expect("sql")
        .expect("key_nodes");
    assert!(
        !sql.contains("wrapped_share IS NOT NULL"),
        "rebuild should drop the share-required check: {sql}"
    );
}

#[test]
fn private_bridge_member_requires_a_signing_public_key() {
    let conn = open_in_memory().expect("schema should apply");
    conn.execute(
        "INSERT INTO private_bridges (uid, generation, public_key, salt)
         VALUES ('uid', 1, x'00', x'01')",
        [],
    )
    .expect("bridge row");
    let rejected = conn.execute(
        "INSERT INTO private_bridge_members
         (bridge_id, node_label, encryption_public_key, signing_public_key, role)
         VALUES (1, 'M.S.2', x'02', NULL, 'member')",
        [],
    );
    assert!(rejected.is_err());
    let accepted = conn.execute(
        "INSERT INTO private_bridge_members
         (bridge_id, node_label, encryption_public_key, signing_public_key, role)
         VALUES (1, 'M.S', x'03', NULL, 'supervisor')",
        [],
    );
    assert!(accepted.is_ok());
}

#[test]
fn files_key_id_referencing_an_existing_key_is_allowed() {
    let conn = open_in_memory().expect("schema should apply");
    seed_key(&conn, 1);

    let result = conn.execute(
        "INSERT INTO files (name, encrypted_path, key_id, nonce)
             VALUES ('secret.txt', '/data/secret.txt.enc', 1, x'00')",
        [],
    );
    assert!(result.is_ok());
}

#[test]
fn relay_credential_roundtrip_seals_the_bearer() {
    let conn = open_in_memory().expect("schema");
    let stored = relay_credential::StoredRelayKey {
        relay_url: "http://127.0.0.1:8787/".into(),
        scope: "inbox.pull".into(),
        key_hash: "a".repeat(64),
        token: "kq_test-bearer".into(),
        remote_id: Some(7),
        label: Some("alice".into()),
    };
    relay_credential::save(&conn, &stored).expect("save");
    let loaded = relay_credential::get(&conn, "http://127.0.0.1:8787", "inbox.pull")
        .expect("get")
        .expect("row");
    assert_eq!(loaded.token, "kq_test-bearer");
    assert_eq!(loaded.key_hash, stored.key_hash);
    assert_eq!(loaded.relay_url, "http://127.0.0.1:8787");
    assert_eq!(loaded.remote_id, Some(7));
    let plaintext: i64 = conn
        .query_row(
            "SELECT count(*) FROM relay_credentials WHERE wrapped_token = ?1",
            rusqlite::params![b"kq_test-bearer".as_slice()],
            |row| row.get(0),
        )
        .expect("scan");
    assert_eq!(plaintext, 0, "bearer must not be stored in the clear");
}

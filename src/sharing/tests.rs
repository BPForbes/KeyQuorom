use super::*;
use crate::db;
use crate::locked_files;
use crate::vault;
use rusqlite::params;
use std::fs;

fn seed_credential(conn: &Connection) -> i64 {
    vault::add_credential(conn, "Email", None, "s3cr3t", "master-pw")
        .expect("add_credential should succeed")
}

#[test]
fn redeem_immediately_after_create_succeeds() {
    let conn = db::open_in_memory().expect("schema should apply");
    let credential_id = seed_credential(&conn);

    let share = create_credential_share(&conn, credential_id, 3600, None)
        .expect("create_credential_share should succeed");
    let resolved = redeem_credential_share(&conn, &share.token)
        .expect("redeem_credential_share should succeed");

    assert_eq!(resolved, credential_id);
}

#[test]
fn redeem_rejects_unknown_token() {
    let conn = db::open_in_memory().expect("schema should apply");
    let result = redeem_credential_share(&conn, "not-a-real-token");
    assert!(matches!(result, Err(Error::InvalidShareToken)));
}

#[test]
fn share_id_for_token_resolves_without_consuming_a_use() {
    let conn = db::open_in_memory().expect("schema should apply");
    let credential_id = seed_credential(&conn);
    let share = create_credential_share(&conn, credential_id, 3600, Some(1))
        .expect("create_credential_share should succeed");

    let peeked = credential_share_id_for_token(&conn, &share.token)
        .expect("credential_share_id_for_token should succeed");
    assert_eq!(peeked, share.id);

    // Peeking didn't consume the single allowed use.
    let resolved = redeem_credential_share(&conn, &share.token)
        .expect("redeem_credential_share should still succeed");
    assert_eq!(resolved, credential_id);
}

#[test]
fn redeem_rejects_expired_share() {
    let conn = db::open_in_memory().expect("schema should apply");
    let credential_id = seed_credential(&conn);

    let share = create_credential_share(&conn, credential_id, -1, None)
        .expect("create_credential_share should succeed");
    let result = redeem_credential_share(&conn, &share.token);

    assert!(matches!(result, Err(Error::ShareExpired)));
}

#[test]
fn redeem_rejects_revoked_share() {
    let conn = db::open_in_memory().expect("schema should apply");
    let credential_id = seed_credential(&conn);

    let share = create_credential_share(&conn, credential_id, 3600, None)
        .expect("create_credential_share should succeed");
    revoke_credential_share(&conn, share.id).expect("revoke_credential_share should succeed");
    let result = redeem_credential_share(&conn, &share.token);

    assert!(matches!(result, Err(Error::ShareRevoked)));
}

#[test]
fn redeem_enforces_max_uses() {
    let conn = db::open_in_memory().expect("schema should apply");
    let credential_id = seed_credential(&conn);

    let share = create_credential_share(&conn, credential_id, 3600, Some(1))
        .expect("create_credential_share should succeed");

    redeem_credential_share(&conn, &share.token).expect("first redemption should succeed");
    let second = redeem_credential_share(&conn, &share.token);

    assert!(matches!(second, Err(Error::ShareExhausted)));
}

#[test]
fn concurrent_redemption_allows_exactly_one_success() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let dir = tempfile::tempdir().expect("tempdir should be created");
    let db_path = dir
        .path()
        .join("keyquorum.sqlite")
        .to_str()
        .expect("path should be valid UTF-8")
        .to_string();

    let setup_conn = db::open(&db_path).expect("schema should apply");
    let credential_id = seed_credential(&setup_conn);
    let share = create_credential_share(&setup_conn, credential_id, 3600, Some(1))
        .expect("create_credential_share should succeed");
    drop(setup_conn);

    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let token = share.token.clone();
            let db_path = db_path.clone();
            thread::spawn(move || {
                let conn = db::open(&db_path).expect("schema should apply");
                barrier.wait();
                redeem_credential_share(&conn, &token)
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread should not panic"))
        .collect();

    let successes = results.iter().filter(|r| r.is_ok()).count();
    let rejections = results
        .iter()
        .filter(|r| matches!(r, Err(Error::ShareExhausted)))
        .count();

    assert_eq!(successes, 1);
    assert_eq!(rejections, 1);
}

fn seed_locked_file(conn: &Connection) -> (i64, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"ttl file").unwrap();
    let file_id = locked_files::lock_file(conn, &source_path, &encrypted_path, "hunter2")
        .expect("lock_file should succeed");
    (file_id, dir, encrypted_path)
}

#[test]
fn date_based_file_share_redeems_before_expiry() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (file_id, _dir, encrypted_path) = seed_locked_file(&conn);
    let expires_at = locked_files::parse_expires_utc("2099-12-31 23:59").expect("valid expiry");

    let share = create_file_share_until(&conn, file_id, &expires_at, None)
        .expect("create_file_share_until should succeed");
    let resolved = redeem_file_share(&conn, &share.token).expect("redeem before expiry");

    assert_eq!(resolved, file_id);
    assert!(encrypted_path.exists());
}

#[test]
fn late_access_of_date_based_file_share_deletes_ciphertext() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (file_id, _dir, encrypted_path) = seed_locked_file(&conn);
    let expires_at = locked_files::parse_expires_utc("2099-12-31 23:59").expect("valid expiry");
    let share = create_file_share_until(&conn, file_id, &expires_at, None)
        .expect("create_file_share_until should succeed");

    conn.execute(
        "UPDATE password_locked_files SET expires_at = datetime('now', '-1 minutes') WHERE id = ?1",
        params![file_id],
    )
    .expect("stamp a past file expiry");

    let result = redeem_file_share(&conn, &share.token);
    assert!(matches!(result, Err(Error::FileExpired)));
    assert!(!encrypted_path.exists());

    let file_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM password_locked_files WHERE id = ?1)",
            params![file_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!file_exists);
}

#[test]
fn relative_ttl_share_expiry_does_not_delete_the_file() {
    let conn = db::open_in_memory().expect("schema should apply");
    let (file_id, _dir, encrypted_path) = seed_locked_file(&conn);

    let share =
        create_file_share(&conn, file_id, -1, None).expect("create_file_share should succeed");
    let result = redeem_file_share(&conn, &share.token);

    assert!(matches!(result, Err(Error::ShareExpired)));
    assert!(encrypted_path.exists());
}

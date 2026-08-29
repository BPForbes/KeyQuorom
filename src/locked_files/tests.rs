use super::*;
use crate::db;

#[test]
fn lock_and_unlock_roundtrip() {
    let conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let id = lock_file(&conn, &source_path, &encrypted_path, "hunter2")
        .expect("lock_file should succeed");
    let plaintext = unlock_file(&conn, id, "hunter2").expect("unlock_file should succeed");

    assert_eq!(plaintext, b"the quorum has been reached");
}

#[test]
fn unlock_fails_with_wrong_password() {
    let conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    let id = lock_file(&conn, &source_path, &encrypted_path, "hunter2")
        .expect("lock_file should succeed");
    let result = unlock_file(&conn, id, "not-hunter2");

    assert!(matches!(result, Err(Error::InvalidPassword)));
}

#[test]
fn reusing_an_encrypted_path_fails_without_touching_the_original() {
    let conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    lock_file(&conn, &source_path, &encrypted_path, "hunter2")
        .expect("first lock_file should succeed");

    let other_source_path = dir.path().join("other.txt");
    fs::write(&other_source_path, b"a different secret").unwrap();
    let second = lock_file(&conn, &other_source_path, &encrypted_path, "different-pw");
    assert!(second.is_err());

    let id: i64 = conn
        .query_row(
            "SELECT id FROM password_locked_files WHERE encrypted_path = ?1",
            params![encrypted_path.to_string_lossy()],
            |row| row.get(0),
        )
        .expect("original row should still exist");
    let plaintext = unlock_file(&conn, id, "hunter2")
        .expect("original file should remain decryptable with its original password");
    assert_eq!(plaintext, b"the quorum has been reached");
}

#[test]
fn locking_refuses_to_overwrite_an_untracked_existing_file() {
    let conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    // A file already sits at encrypted_path but isn't tracked by any row.
    fs::write(&encrypted_path, b"unrelated pre-existing data").unwrap();

    let result = lock_file(&conn, &source_path, &encrypted_path, "hunter2");
    assert!(result.is_err());

    let contents = fs::read(&encrypted_path).unwrap();
    assert_eq!(contents, b"unrelated pre-existing data");

    let row_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM password_locked_files WHERE encrypted_path = ?1)",
            params![encrypted_path.to_string_lossy()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!row_exists);
}

#[cfg(unix)]
#[test]
fn locked_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    let encrypted_path = dir.path().join("secret.txt.kqenc");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    lock_file(&conn, &source_path, &encrypted_path, "hunter2").expect("lock_file should succeed");

    let mode = fs::metadata(&encrypted_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn locking_rejects_a_non_utf8_encrypted_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let conn = db::open_in_memory().expect("schema should apply");
    let dir = tempfile::tempdir().expect("tempdir should be created");
    let source_path = dir.path().join("secret.txt");
    fs::write(&source_path, b"the quorum has been reached").unwrap();

    // 0xFF is not valid UTF-8 in any position, but Unix filenames are
    // arbitrary bytes, so this is a legal (if unusual) path.
    let bad_name = OsStr::from_bytes(b"secret-\xFF.kqenc");
    let encrypted_path = dir.path().join(bad_name);

    let result = lock_file(&conn, &source_path, &encrypted_path, "hunter2");
    assert!(matches!(result, Err(Error::InvalidPath)));
    assert!(!encrypted_path.exists());
}

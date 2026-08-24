//! Password-locked files: a single-password protection tier for files,
//! independent of the hardware-key-quorum mechanism in `db`.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use rusqlite::{params, Connection};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Encrypts a source file with a key derived from a password and stores the ciphertext at the target path.
///
/// Database metadata and the encrypted file are committed together, so a database insertion or file-write
/// failure does not commit the new lock record.
///
/// # Arguments
///
/// * `source_path` - Path to the plaintext file.
/// * `encrypted_path` - Path where the ciphertext is written.
/// * `password` - Password used to derive the encryption key.
///
/// # Returns
///
/// The database ID assigned to the new locked-file record.
///
/// # Examples
///
/// ```no_run
/// let id = lock_file(&mut conn, source_path, encrypted_path, "correct horse battery staple")?;
/// assert!(id > 0);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn lock_file(
    conn: &mut Connection,
    source_path: &Path,
    encrypted_path: &Path,
    password: &str,
) -> Result<i64> {
    let plaintext = fs::read(source_path)?;

    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext);

    let name = source_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO password_locked_files (name, encrypted_path, kdf_salt, nonce)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            name,
            encrypted_path.to_string_lossy(),
            salt.to_vec(),
            nonce.to_vec()
        ],
    )?;
    let id = tx.last_insert_rowid();

    write_owner_only(encrypted_path, &ciphertext)?;

    tx.commit()?;
    Ok(id)
}

/// Decrypts a password-locked file and returns its plaintext.
///
/// Authentication failures, including an incorrect password or tampered
/// ciphertext, are reported as [`Error::InvalidPassword`]. Malformed nonce
/// data is reported as an integrity-check failure.
///
/// # Examples
///
/// ```
/// # let conn = rusqlite::Connection::open_in_memory().unwrap();
/// # let id = 1;
/// let plaintext = unlock_file(&conn, id, "password");
/// ```
///
/// # Returns
///
/// The decrypted plaintext bytes.
pub fn unlock_file(conn: &Connection, id: i64, password: &str) -> Result<Vec<u8>> {
    let (encrypted_path, salt, nonce): (String, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT encrypted_path, kdf_salt, nonce
         FROM password_locked_files WHERE id = ?1",
        params![id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;

    let ciphertext = fs::read(&encrypted_path)?;
    let key = crypto::derive_key(password, &salt)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::IntegrityCheckFailed)?;
    let plaintext =
        crypto::decrypt(&key, &nonce, &ciphertext).map_err(|_| Error::InvalidPassword)?;

    Ok(plaintext)
}

/// Writes file contents with owner-only permissions.
///
/// On Unix, the file is created or truncated with permissions `0600`.
///
/// # Examples
///
/// ```
/// let path = std::env::temp_dir().join("write_owner_only_example");
/// write_owner_only(&path, b"secret")?;
/// assert_eq!(std::fs::read(&path)?, b"secret");
/// std::fs::remove_file(path)?;
/// # Ok::<(), std::io::Error>(())
/// ```
fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    Ok(())
}

/// Writes file contents using the standard filesystem operations available on non-Unix systems.
///
/// # Examples
///
/// ```rust,no_run
/// # #[cfg(not(unix))]
/// # {
/// use std::path::Path;
///
/// write_owner_only(Path::new("output.dat"), b"file contents").unwrap();
/// # }
/// ```
fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn lock_and_unlock_roundtrip() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let source_path = dir.path().join("secret.txt");
        let encrypted_path = dir.path().join("secret.txt.kqenc");
        fs::write(&source_path, b"the quorum has been reached").unwrap();

        let id = lock_file(&mut conn, &source_path, &encrypted_path, "hunter2")
            .expect("lock_file should succeed");
        let plaintext = unlock_file(&conn, id, "hunter2").expect("unlock_file should succeed");

        assert_eq!(plaintext, b"the quorum has been reached");
    }

    #[test]
    fn unlock_fails_with_wrong_password() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let source_path = dir.path().join("secret.txt");
        let encrypted_path = dir.path().join("secret.txt.kqenc");
        fs::write(&source_path, b"the quorum has been reached").unwrap();

        let id = lock_file(&mut conn, &source_path, &encrypted_path, "hunter2")
            .expect("lock_file should succeed");
        let result = unlock_file(&conn, id, "not-hunter2");

        assert!(matches!(result, Err(Error::InvalidPassword)));
    }

    #[test]
    fn reusing_an_encrypted_path_fails_without_touching_the_original() {
        let mut conn = db::open_in_memory().expect("schema should apply");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let source_path = dir.path().join("secret.txt");
        let encrypted_path = dir.path().join("secret.txt.kqenc");
        fs::write(&source_path, b"the quorum has been reached").unwrap();

        lock_file(&mut conn, &source_path, &encrypted_path, "hunter2")
            .expect("first lock_file should succeed");

        let other_source_path = dir.path().join("other.txt");
        fs::write(&other_source_path, b"a different secret").unwrap();
        let second = lock_file(
            &mut conn,
            &other_source_path,
            &encrypted_path,
            "different-pw",
        );
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

    #[cfg(unix)]
    #[test]
    fn locked_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let mut conn = db::open_in_memory().expect("schema should apply");
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let source_path = dir.path().join("secret.txt");
        let encrypted_path = dir.path().join("secret.txt.kqenc");
        fs::write(&source_path, b"the quorum has been reached").unwrap();

        lock_file(&mut conn, &source_path, &encrypted_path, "hunter2")
            .expect("lock_file should succeed");

        let mode = fs::metadata(&encrypted_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

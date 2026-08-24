//! Password-locked files: a single-password protection tier for files,
//! independent of the hardware-key-quorum mechanism in `db`.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Encrypts the file at `source_path` with a key derived from `password`,
/// writes the ciphertext to `encrypted_path`, and records it. Returns the
/// new row's id.
pub fn lock_file(
    conn: &Connection,
    source_path: &Path,
    encrypted_path: &Path,
    password: &str,
) -> Result<i64> {
    let plaintext = fs::read(source_path)?;
    let content_hash = hex::encode(Sha256::digest(&plaintext));

    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext);

    fs::write(encrypted_path, &ciphertext)?;

    let name = source_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    conn.execute(
        "INSERT INTO password_locked_files
             (name, encrypted_path, content_hash, kdf_salt, nonce)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            name,
            encrypted_path.to_string_lossy(),
            content_hash,
            salt.to_vec(),
            nonce.to_vec()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Decrypts the password-locked file `id` with `password` and returns its
/// plaintext bytes, after verifying it against the recorded content hash.
pub fn unlock_file(conn: &Connection, id: i64, password: &str) -> Result<Vec<u8>> {
    let (encrypted_path, content_hash, salt, nonce): (String, String, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT encrypted_path, content_hash, kdf_salt, nonce
             FROM password_locked_files WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;

    let ciphertext = fs::read(&encrypted_path)?;
    let key = crypto::derive_key(password, &salt)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::IntegrityCheckFailed)?;
    let plaintext =
        crypto::decrypt(&key, &nonce, &ciphertext).map_err(|_| Error::InvalidPassword)?;

    let actual_hash = hex::encode(Sha256::digest(&plaintext));
    if actual_hash != content_hash {
        return Err(Error::IntegrityCheckFailed);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
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
}

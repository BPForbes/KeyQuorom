//! Password-locked files: a single-password protection tier for files,
//! independent of the hardware-key-quorum mechanism in `db`.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use rusqlite::{params, Connection};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Encrypts the file at `source_path` with a key derived from `password`
/// and writes the ciphertext to `encrypted_path`, then records it.
///
/// The ciphertext is written first, outside any database transaction:
/// `create_new` fails atomically if `encrypted_path` is already in use, so
/// we never overwrite data we don't own, and this keeps the database write
/// lock held for only the short INSERT that follows rather than for the
/// file I/O. If that INSERT then fails for any reason (most likely a
/// duplicate `encrypted_path` already tracked by another row), the file we
/// just wrote is removed so it isn't left behind untracked.
pub fn lock_file(
    conn: &Connection,
    source_path: &Path,
    encrypted_path: &Path,
    password: &str,
) -> Result<i64> {
    let encrypted_path_str = encrypted_path.to_str().ok_or(Error::InvalidPath)?;

    let plaintext = fs::read(source_path)?;

    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, &plaintext);

    let name = source_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    write_owner_only(encrypted_path, &ciphertext)?;

    let insert = conn.execute(
        "INSERT INTO password_locked_files (name, encrypted_path, kdf_salt, nonce)
         VALUES (?1, ?2, ?3, ?4)",
        params![name, encrypted_path_str, salt.to_vec(), nonce.to_vec()],
    );

    match insert {
        Ok(_) => Ok(conn.last_insert_rowid()),
        Err(e) => {
            let _ = fs::remove_file(encrypted_path);
            Err(e.into())
        }
    }
}

/// Decrypts the password-locked file `id` with `password` and returns its
/// plaintext bytes. AES-256-GCM's authentication tag is what verifies the
/// result is intact — a wrong password or a tampered ciphertext both
/// surface as `Error::InvalidPassword`.
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

/// Writes `contents` to a newly created file at `path`, owner-only (0600)
/// on Unix. Refuses to touch a pre-existing file (`create_new`), and
/// cleans up its own partial write if anything after creation fails —
/// but only ever removes a file it created itself.
#[cfg(unix)]
pub fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;

    if let Err(e) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    drop(file);

    // Best-effort: a newly created directory entry isn't guaranteed durable
    // until its parent directory is synced too. The file's own data is
    // already durable via sync_all above regardless of whether this
    // succeeds.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Non-Unix fallback: there's no portable API called here to restrict file
/// permissions, so despite the name, this does **not** provide an
/// owner-only guarantee on this platform — only the `create_new` (refuse
/// to touch a pre-existing file) and cleanup-on-partial-write behavior
/// carry over from the Unix version above. Callers on a non-Unix target
/// must not assume the written file is protected from other local users.
#[cfg(not(unix))]
pub fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    if let Err(e) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e.into());
    }

    Ok(())
}

#[cfg(test)]
#[path = "locked_files/tests.rs"]
mod tests;

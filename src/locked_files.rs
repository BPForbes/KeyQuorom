//! Password-locked files: a single-password protection tier for files,
//! independent of the hardware-key-quorum mechanism in `db`.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension};
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
    lock_file_until(conn, source_path, encrypted_path, password, None)
}

/// Like [`lock_file`], and records a UTC expiry (`YYYY-MM-DD HH:MM:00`).
/// After that instant, [`unlock_file`] deletes the ciphertext from disk.
pub fn lock_file_until(
    conn: &Connection,
    source_path: &Path,
    encrypted_path: &Path,
    password: &str,
    expires_at: Option<&str>,
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
        "INSERT INTO password_locked_files (name, encrypted_path, kdf_salt, nonce, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            name,
            encrypted_path_str,
            salt.to_vec(),
            nonce.to_vec(),
            expires_at
        ],
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
///
/// If the file has a date-based TTL that has already passed, the ciphertext
/// is removed from disk and the database row is dropped before any decrypt
/// is attempted.
pub fn unlock_file(conn: &Connection, id: i64, password: &str) -> Result<Vec<u8>> {
    purge_if_expired(conn, id)?;

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

/// Parses `yyyy-mm-dd hh:mm` as a UTC instant and returns
/// `YYYY-MM-DD HH:MM:00` for SQLite `datetime()` comparison.
pub fn parse_expires_utc(value: &str) -> Result<String> {
    let Some((date, time)) = value.split_once(' ') else {
        return Err(Error::InvalidExpiresAt);
    };
    let date_parts: Vec<&str> = date.split('-').collect();
    let time_parts: Vec<&str> = time.split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 2 {
        return Err(Error::InvalidExpiresAt);
    }
    let year = parse_fixed_digits(date_parts[0], 4).ok_or(Error::InvalidExpiresAt)?;
    let month = parse_fixed_digits(date_parts[1], 2).ok_or(Error::InvalidExpiresAt)?;
    let day = parse_fixed_digits(date_parts[2], 2).ok_or(Error::InvalidExpiresAt)?;
    let hour = parse_fixed_digits(time_parts[0], 2).ok_or(Error::InvalidExpiresAt)?;
    let minute = parse_fixed_digits(time_parts[1], 2).ok_or(Error::InvalidExpiresAt)?;
    if year == 0 || month < 1 || month > 12 || hour > 23 || minute > 59 {
        return Err(Error::InvalidExpiresAt);
    }
    if day < 1 || day > days_in_month(year, month) {
        return Err(Error::InvalidExpiresAt);
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:00"
    ))
}

/// Rejects a parsed UTC expiry that is not strictly after SQLite `now`.
pub fn require_future_expires_utc(conn: &Connection, expires_at: &str) -> Result<()> {
    let future: bool = conn.query_row(
        "SELECT datetime(?1) > datetime('now')",
        params![expires_at],
        |row| row.get(0),
    )?;
    if future {
        Ok(())
    } else {
        Err(Error::ExpiresAtInPast)
    }
}

pub fn set_expires_at(conn: &Connection, file_id: i64, expires_at: &str) -> Result<()> {
    conn.query_row(
        "SELECT id FROM password_locked_files WHERE id = ?1",
        params![file_id],
        |_| Ok(()),
    )?;
    conn.execute(
        "UPDATE password_locked_files SET expires_at = ?1 WHERE id = ?2",
        params![expires_at, file_id],
    )?;
    Ok(())
}

/// If this file's date-based TTL has passed, delete the ciphertext and the
/// tracking row. No-op when the file has no expiry or is still live.
pub fn purge_if_expired(conn: &Connection, file_id: i64) -> Result<()> {
    let row: Option<(String, bool)> = conn
        .query_row(
            "SELECT encrypted_path,
                    expires_at IS NOT NULL AND datetime(expires_at) <= datetime('now')
             FROM password_locked_files WHERE id = ?1",
            params![file_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((encrypted_path, expired)) = row else {
        return Ok(());
    };
    if !expired {
        return Ok(());
    }
    destroy_file(conn, file_id, &encrypted_path)?;
    Err(Error::FileExpired)
}

fn destroy_file(conn: &Connection, file_id: i64, encrypted_path: &str) -> Result<()> {
    let _ = fs::remove_file(encrypted_path);
    conn.execute(
        "DELETE FROM pins
         WHERE resource_type = 'file_share'
           AND resource_id IN (SELECT id FROM file_shares WHERE file_id = ?1)",
        params![file_id],
    )?;
    conn.execute(
        "DELETE FROM pins WHERE resource_type = 'locked_file' AND resource_id = ?1",
        params![file_id],
    )?;
    conn.execute(
        "DELETE FROM password_locked_files WHERE id = ?1",
        params![file_id],
    )?;
    Ok(())
}

fn parse_fixed_digits(value: &str, width: usize) -> Option<u32> {
    if value.len() != width || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
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

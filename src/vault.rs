//! A small password manager: each credential is encrypted independently
//! under a key derived from a caller-supplied master password.

use crate::crypto::{self, NONCE_LEN};
use crate::error::{Error, Result};
use rusqlite::{params, Connection};

pub struct Credential {
    pub id: i64,
    pub label: String,
    pub username: Option<String>,
    pub password: String,
}

/// Stores a credential encrypted with a key derived from the master password.
///
/// # Returns
///
/// The SQLite row ID assigned to the new credential.
///
/// # Examples
///
/// ```
/// use rusqlite::Connection;
///
/// let conn = Connection::open_in_memory().unwrap();
/// conn.execute_batch(
///     "CREATE TABLE credentials (
///         id INTEGER PRIMARY KEY,
///         label TEXT NOT NULL,
///         username TEXT,
///         kdf_salt BLOB NOT NULL,
///         nonce BLOB NOT NULL,
///         ciphertext BLOB NOT NULL
///     )",
/// ).unwrap();
///
/// let id = add_credential(
///     &conn,
///     "Email",
///     Some("user@example.com"),
///     "secret",
///     "master password",
/// ).unwrap();
///
/// assert!(id > 0);
/// ```
pub fn add_credential(
    conn: &Connection,
    label: &str,
    username: Option<&str>,
    password: &str,
    master_password: &str,
) -> Result<i64> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(master_password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, password.as_bytes());

    conn.execute(
        "INSERT INTO credentials (label, username, kdf_salt, nonce, ciphertext)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![label, username, salt.to_vec(), nonce.to_vec(), ciphertext],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Retrieves and decrypts a credential by its identifier.
///
/// # Errors
///
/// Returns an error if the credential cannot be queried, the master password
/// is invalid, or the stored nonce or password data fails integrity checks.
///
/// # Examples
///
/// ```no_run
/// let conn = rusqlite::Connection::open_in_memory()?;
/// let credential = get_credential(&conn, 1, "master password")?;
/// println!("{}", credential.label);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn get_credential(conn: &Connection, id: i64, master_password: &str) -> Result<Credential> {
pub fn get_credential(conn: &Connection, id: i64, master_password: &str) -> Result<Credential> {
    let (label, username, salt, nonce, ciphertext): (
        String,
        Option<String>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = conn.query_row(
        "SELECT label, username, kdf_salt, nonce, ciphertext
         FROM credentials WHERE id = ?1",
        params![id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;

    let key = crypto::derive_key(master_password, &salt)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::IntegrityCheckFailed)?;
    let plaintext =
        crypto::decrypt(&key, &nonce, &ciphertext).map_err(|_| Error::InvalidPassword)?;
    let password = String::from_utf8(plaintext).map_err(|_| Error::IntegrityCheckFailed)?;

    Ok(Credential {
        id,
        label,
        username,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn add_and_get_credential_roundtrip() {
        let conn = db::open_in_memory().expect("schema should apply");
        let id = add_credential(&conn, "Email", Some("bailey"), "s3cr3t", "master-pw")
            .expect("add_credential should succeed");

        let credential =
            get_credential(&conn, id, "master-pw").expect("get_credential should succeed");

        assert_eq!(credential.label, "Email");
        assert_eq!(credential.username.as_deref(), Some("bailey"));
        assert_eq!(credential.password, "s3cr3t");
    }

    #[test]
    fn get_credential_fails_with_wrong_master_password() {
        let conn = db::open_in_memory().expect("schema should apply");
        let id = add_credential(&conn, "Email", None, "s3cr3t", "master-pw")
            .expect("add_credential should succeed");

        let result = get_credential(&conn, id, "wrong-master-pw");
        assert!(matches!(result, Err(Error::InvalidPassword)));
    }
}

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

/// Encrypts and stores a credential, returning its database ID.

///

/// # Arguments

///

/// * `label` - Display label for the credential.

/// * `username` - Optional username associated with the credential.

/// * `password` - Plaintext password to encrypt and store.

/// * `master_password` - Password used to derive the encryption key.

///

/// # Examples

///

/// ```

/// # use rusqlite::Connection;

/// # let conn = Connection::open_in_memory().unwrap();

/// # conn.execute(

/// #     "CREATE TABLE credentials (

/// #         id INTEGER PRIMARY KEY,

/// #         label TEXT NOT NULL,

/// #         username TEXT,

/// #         kdf_salt BLOB NOT NULL,

/// #         nonce BLOB NOT NULL,

/// #         ciphertext BLOB NOT NULL

/// #     )",

/// #     [],

/// # ).unwrap();

/// let id = add_credential(

///     &conn,

///     "Email",

///     Some("alice@example.com"),

///     "secret",

///     "master password",

/// ).unwrap();

/// assert_eq!(id, 1);

/// ```

///

/// # Errors

///

/// Returns an error if key derivation or database insertion fails.
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

/// Retrieves and decrypts a credential using the supplied master password.
///
/// # Parameters
///
/// * `id` — Identifier of the credential to retrieve.
/// * `master_password` — Password used to derive the decryption key.
///
/// # Errors
///
/// Returns an error if the credential cannot be retrieved, the stored data fails
/// integrity checks, or the master password is incorrect.
///
/// # Examples
///
/// ```
/// # use rusqlite::Connection;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = Connection::open_in_memory()?;
/// # conn.execute_batch("
/// #     CREATE TABLE credentials (
/// #         id INTEGER PRIMARY KEY,
/// #         label TEXT NOT NULL,
/// #         username TEXT,
/// #         kdf_salt BLOB NOT NULL,
/// #         nonce BLOB NOT NULL,
/// #         ciphertext BLOB NOT NULL
/// #     )
/// # ")?;
/// let id = add_credential(&conn, "Email", Some("alice"), "secret", "master")?;
/// let credential = get_credential(&conn, id, "master")?;
///
/// assert_eq!(credential.password, "secret");
/// # Ok(())
/// # }
/// ```
///
/// Returns the decrypted credential.
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

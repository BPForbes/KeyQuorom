//! Password-based key derivation and symmetric encryption primitives shared
//! by the password vault and password-locked-file features.

use crate::error::Error;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// AES-GCM authentication failure: either the key was wrong or the
/// ciphertext was tampered with. Deliberately carries no further detail.
#[derive(Debug)]
pub struct DecryptError;

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decryption failed: wrong key or corrupted ciphertext")
    }
}

impl std::error::Error for DecryptError {}

/// Generates a cryptographically random salt.
///
/// # Examples
///
/// ```
/// let salt = random_salt();
/// assert_eq!(salt.len(), SALT_LEN);
/// ```
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generates a cryptographically random nonce for AES-GCM encryption.
///
/// # Examples
///
/// ```
/// let nonce = random_nonce();
/// assert_eq!(nonce.len(), NONCE_LEN);
/// ```
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Creates the explicitly pinned Argon2id configuration used for key derivation.
///
/// # Examples
///
/// ```
/// let _algorithm = argon2id();
/// ```
fn argon2id() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("hard-coded Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Derives a 256-bit encryption key from a password and salt using Argon2id.
/// The returned key is zeroed when dropped.
///
/// # Errors
///
/// Returns [`Error::KeyDerivationFailed`] if key derivation fails.
///
/// # Examples
///
/// ```
/// let salt = [0u8; SALT_LEN];
/// let key = derive_key("password", &salt).unwrap();
/// assert_eq!(key.len(), KEY_LEN);
/// ```
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2id()
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(key)
}

/// Encrypts plaintext using AES-256-GCM with the provided key and nonce.
///
/// # Examples
///
/// ```
/// let key = [0u8; KEY_LEN];
/// let nonce = [0u8; NONCE_LEN];
/// let ciphertext = encrypt(&key, &nonce, b"secret message");
///
/// assert!(!ciphertext.is_empty());
/// ```
///
/// # Panics
///
/// Panics if the encryption operation fails, such as when the plaintext exceeds
/// AES-GCM's supported size limit.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("AES-256-GCM encryption should not fail for in-memory plaintext")
}

/// Authenticates and decrypts AES-256-GCM ciphertext using the supplied key and nonce.

///

/// # Examples

///

/// ```

/// let key = [0u8; KEY_LEN];

/// let nonce = [0u8; NONCE_LEN];

/// let ciphertext = encrypt(&key, &nonce, b"secret");

///

/// let plaintext = decrypt(&key, &nonce, &ciphertext).unwrap();

/// assert_eq!(plaintext, b"secret");

/// ```

///

/// # Errors

///

/// Returns `DecryptError` when authentication fails, including when the key

/// or nonce is incorrect or the ciphertext has been modified.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| DecryptError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_is_deterministic_for_same_password_and_salt() {
        let salt = random_salt();
        let a = derive_key("correct horse battery staple", &salt).unwrap();
        let b = derive_key("correct horse battery staple", &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_key_differs_for_different_passwords() {
        let salt = random_salt();
        let a = derive_key("password-one", &salt).unwrap();
        let b = derive_key("password-two", &salt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("hunter2", &random_salt()).unwrap();
        let nonce = random_nonce();
        let plaintext = b"the quorum has been reached";

        let ciphertext = encrypt(&key, &nonce, plaintext);
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let salt = random_salt();
        let nonce = random_nonce();
        let key = derive_key("hunter2", &salt).unwrap();
        let wrong_key = derive_key("not-hunter2", &salt).unwrap();

        let ciphertext = encrypt(&key, &nonce, b"top secret");

        assert!(decrypt(&wrong_key, &nonce, &ciphertext).is_err());
    }
}

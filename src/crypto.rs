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

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generates a random 256-bit data key for hardware-key-quorum file
/// encryption (as opposed to `derive_key`, which is password-based). The
/// returned buffer is zeroed on drop.
pub fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut key[..]);
    key
}

/// Argon2id parameters, pinned explicitly rather than via `Argon2::default()`
/// (they currently match that default) so a future upgrade of the `argon2`
/// crate can't silently change the parameters out from under
/// already-encrypted records.
fn argon2id() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("hard-coded Argon2id parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Derives a 256-bit key from `password` and `salt` using Argon2id. The
/// returned buffer is zeroed on drop.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2id()
        .hash_password_into(password.as_bytes(), salt, &mut key[..])
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(key)
}

/// Encrypts `plaintext` with AES-256-GCM under `key`/`nonce`. Infallible in
/// practice: with a correctly sized key and nonce the only failure mode is
/// a plaintext exceeding AES-GCM's ~64GiB limit, far beyond anything this
/// project encrypts in one call.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("AES-256-GCM encryption should not fail for in-memory plaintext")
}

/// Decrypts `ciphertext` with AES-256-GCM under `key`/`nonce`. Fails (and
/// must be allowed to fail) whenever the key is wrong or the ciphertext
/// has been tampered with — the AEAD authentication tag is what actually
/// detects an incorrect password.
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
    fn random_key_differs_across_calls() {
        let a = random_key();
        let b = random_key();
        assert_ne!(*a, *b);
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

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

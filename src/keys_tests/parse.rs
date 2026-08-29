use super::super::*;
use base64::Engine;

#[test]
fn parse_key_text_accepts_hex_pem_and_openssh() {
    let raw = [0x11u8; 32];
    assert_eq!(parse_key_text(&hex::encode(raw)).unwrap(), raw);

    let pem_body = Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{pem_body}\n-----END PUBLIC KEY-----\n");
    assert_eq!(parse_key_text(&pem).unwrap(), raw);

    let mut spki = SPKI_X25519.to_vec();
    spki.extend_from_slice(&raw);
    let spki_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        Engine::encode(&base64::engine::general_purpose::STANDARD, spki)
    );
    assert_eq!(parse_key_text(&spki_pem).unwrap(), raw);

    let mut openssh_blob = Vec::from(*b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20");
    openssh_blob.extend_from_slice(&raw);
    let line = format!(
        "ssh-ed25519 {} alice@host",
        Engine::encode(&base64::engine::general_purpose::STANDARD, openssh_blob)
    );
    assert_eq!(parse_key_text(&line).unwrap(), raw);
}

#[test]
fn parse_key_text_rejects_non_curve_pem_and_openssh() {
    let raw = [0x22u8; 40];
    let rsa_pem = format!(
        "-----BEGIN RSA PUBLIC KEY-----\n{}\n-----END RSA PUBLIC KEY-----\n",
        Engine::encode(&base64::engine::general_purpose::STANDARD, raw)
    );
    assert!(parse_key_text(&rsa_pem).is_err());

    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        Engine::encode(&base64::engine::general_purpose::STANDARD, raw)
    );
    assert!(parse_key_text(&public_pem).is_err());

    let mut ssh_rsa = Vec::from(*b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x20");
    ssh_rsa.extend_from_slice(&[0x33u8; 32]);
    let line = format!(
        "ssh-rsa {} alice@host",
        Engine::encode(&base64::engine::general_purpose::STANDARD, ssh_rsa)
    );
    assert!(parse_key_text(&line).is_err());
}

#[test]
fn encryption_public_from_secret_matches_generated_pair() {
    let (secret, public) = generate_encryption_keypair();
    assert_eq!(encryption_public_from_secret(&secret), public);
}

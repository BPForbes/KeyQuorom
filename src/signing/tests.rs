use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn generate() -> (SigningKey, [u8; 32]) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let public_key = signing_key.verifying_key().to_bytes();
    (signing_key, public_key)
}

#[test]
fn valid_signature_verifies() {
    let (signing_key, public_key) = generate();
    let message = b"the quorum has been reached";
    let signature = signing_key.sign(message);

    let result = verify_signature(&public_key, message, &signature.to_bytes());
    assert!(result.is_ok());
}

#[test]
fn tampered_message_is_rejected() {
    let (signing_key, public_key) = generate();
    let signature = signing_key.sign(b"the quorum has been reached");

    let result = verify_signature(
        &public_key,
        b"the quorum has NOT been reached",
        &signature.to_bytes(),
    );
    assert!(matches!(result, Err(Error::SignatureVerificationFailed)));
}

#[test]
fn wrong_public_key_is_rejected() {
    let (signing_key, _public_key) = generate();
    let (_other_signing_key, other_public_key) = generate();
    let message = b"the quorum has been reached";
    let signature = signing_key.sign(message);

    let result = verify_signature(&other_public_key, message, &signature.to_bytes());
    assert!(matches!(result, Err(Error::SignatureVerificationFailed)));
}

#[test]
fn malformed_public_key_is_rejected() {
    // Not every 32-byte value decompresses to a valid Edwards point —
    // this one doesn't (verified against ed25519-dalek directly).
    let mut malformed_public_key = [0u8; 32];
    malformed_public_key[0] = 0x01;
    malformed_public_key[31] = 0x20;
    let (signing_key, _public_key) = generate();
    let signature = signing_key.sign(b"the quorum has been reached");

    let result = verify_signature(
        &malformed_public_key,
        b"the quorum has been reached",
        &signature.to_bytes(),
    );
    assert!(matches!(result, Err(Error::InvalidPublicKey)));
}

#[test]
fn sign_round_trips_through_verify() {
    let (signing_key, public_key) = generate();
    let message = b"file bytes";
    let signature = sign(&signing_key.to_bytes(), message);
    assert!(verify_signature(&public_key, message, &signature).is_ok());
}

#[test]
fn bridge_dual_signature_binds_salts_and_rejects_wrong_message() {
    let (bridge, bridge_pub) = generate();
    let (personal, _) = generate();
    let message = b"co-signed pdf";
    let artifact = sign_with_bridge(
        "abc",
        1,
        &[7u8; 16],
        "M.A.2",
        &bridge.to_bytes(),
        &personal.to_bytes(),
        message,
    )
    .expect("sign");
    let personal_pub = personal.verifying_key().to_bytes();
    assert!(verify_bridge_signature(&artifact, &bridge_pub, &personal_pub, message).is_ok());
    assert!(matches!(
        verify_bridge_signature(&artifact, &bridge_pub, &personal_pub, b"tampered"),
        Err(Error::SignatureVerificationFailed)
    ));
    let (_, other_pub) = generate();
    assert!(matches!(
        verify_bridge_signature(&artifact, &bridge_pub, &other_pub, message),
        Err(Error::SignatureVerificationFailed)
    ));
    let encoded = encode_bridge_signature(&artifact).expect("encode");
    let decoded = decode_bridge_signature(&encoded).expect("decode");
    assert_eq!(decoded, artifact);
    let again = sign_with_bridge(
        "abc",
        1,
        &[7u8; 16],
        "M.A.2",
        &bridge.to_bytes(),
        &personal.to_bytes(),
        message,
    )
    .expect("sign");
    assert_ne!(artifact.signature_salt, again.signature_salt);
}

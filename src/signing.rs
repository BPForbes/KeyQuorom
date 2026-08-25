//! Ed25519 signature verification. Producing signatures (`sign`) needs a
//! private signing key, which this project has no custody story for yet —
//! see README's Roadmap.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verifies `signature` over `message` under `public_key`. Uses
/// `verify_strict` rather than `verify` — it rejects the non-canonical
/// signature malleability `verify` allows.
pub fn verify_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| Error::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
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
}

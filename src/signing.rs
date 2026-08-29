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
#[path = "signing/tests.rs"]
mod tests;

//! Ed25519 signatures. `verify_signature` is standalone. Producing a
//! signature still takes a private key the caller already holds (a file
//! or stdin) — this crate does not persist signing secrets.
//!
//! Private-bridge artifacts (`KQBS`) bind a bridge salt, a per-signature
//! salt, and both a shared bridge key and the signer's personal key.

use crate::crypto::{random_salt, SALT_LEN};
use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const ARTIFACT_MAGIC: &[u8; 4] = b"KQBS";
const ARTIFACT_VERSION: u8 = 1;
const SIGN_DOMAIN: &[u8] = b"KQBRIDGE-SIGN-v1";

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

/// Ed25519-sign `message` with a 32-byte seed. The caller supplies the
/// private key; nothing here writes it to disk.
pub fn sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(private_key);
    signing_key.sign(message).to_bytes()
}

/// Fields carried in a private-bridge signature artifact. Salts and the
/// signer pub are public; verification recomputes the domain-separated
/// preimage from them plus the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeSignature {
    pub uid: String,
    pub generation: u32,
    pub bridge_salt: [u8; SALT_LEN],
    pub signature_salt: [u8; SALT_LEN],
    pub signer_label: String,
    pub signer_public_key: [u8; 32],
    pub bridge_signature: [u8; 64],
    pub personal_signature: [u8; 64],
}

pub fn bridge_sign_preimage(
    uid: &str,
    generation: u32,
    bridge_salt: &[u8; SALT_LEN],
    signature_salt: &[u8; SALT_LEN],
    signer_label: &str,
    signer_public_key: &[u8; 32],
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGN_DOMAIN);
    hasher.update(uid.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(bridge_salt);
    hasher.update(signature_salt);
    hasher.update(signer_label.as_bytes());
    hasher.update(signer_public_key);
    hasher.update(message);
    hasher.finalize().into()
}

pub fn sign_with_bridge(
    uid: &str,
    generation: u32,
    bridge_salt: &[u8; SALT_LEN],
    signer_label: &str,
    bridge_private_key: &[u8; 32],
    personal_private_key: &[u8; 32],
    message: &[u8],
) -> Result<BridgeSignature> {
    let signing_key = SigningKey::from_bytes(personal_private_key);
    let signer_public_key = signing_key.verifying_key().to_bytes();
    let signature_salt = random_salt();
    let preimage = bridge_sign_preimage(
        uid,
        generation,
        bridge_salt,
        &signature_salt,
        signer_label,
        &signer_public_key,
        message,
    );
    Ok(BridgeSignature {
        uid: uid.to_string(),
        generation,
        bridge_salt: *bridge_salt,
        signature_salt,
        signer_label: signer_label.to_string(),
        signer_public_key,
        bridge_signature: sign(bridge_private_key, &preimage),
        personal_signature: sign(personal_private_key, &preimage),
    })
}

pub fn verify_bridge_signature(
    artifact: &BridgeSignature,
    bridge_public_key: &[u8; 32],
    signer_public_key: &[u8; 32],
    message: &[u8],
) -> Result<()> {
    if artifact.signer_public_key != *signer_public_key {
        return Err(Error::SignatureVerificationFailed);
    }
    let preimage = bridge_sign_preimage(
        &artifact.uid,
        artifact.generation,
        &artifact.bridge_salt,
        &artifact.signature_salt,
        &artifact.signer_label,
        signer_public_key,
        message,
    );
    verify_signature(bridge_public_key, &preimage, &artifact.bridge_signature)?;
    verify_signature(signer_public_key, &preimage, &artifact.personal_signature)
}

pub fn encode_bridge_signature(artifact: &BridgeSignature) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(ARTIFACT_MAGIC);
    out.push(ARTIFACT_VERSION);
    push_len_prefixed(&mut out, artifact.uid.as_bytes())?;
    out.extend_from_slice(&artifact.generation.to_be_bytes());
    out.extend_from_slice(&artifact.bridge_salt);
    out.extend_from_slice(&artifact.signature_salt);
    push_len_prefixed(&mut out, artifact.signer_label.as_bytes())?;
    out.extend_from_slice(&artifact.signer_public_key);
    out.extend_from_slice(&artifact.bridge_signature);
    out.extend_from_slice(&artifact.personal_signature);
    Ok(out)
}

pub fn decode_bridge_signature(bytes: &[u8]) -> Result<BridgeSignature> {
    let mut data = bytes;
    if take_n(&mut data, 4)? != ARTIFACT_MAGIC {
        return Err(Error::InvalidBridgePackage);
    }
    if take_u8(&mut data)? != ARTIFACT_VERSION {
        return Err(Error::InvalidBridgePackage);
    }
    let uid = std::str::from_utf8(take_len_prefixed(&mut data)?)
        .map_err(|_| Error::InvalidBridgePackage)?
        .to_string();
    let generation = u32::from_be_bytes(take_array(&mut data)?);
    let bridge_salt = take_array(&mut data)?;
    let signature_salt = take_array(&mut data)?;
    let signer_label = std::str::from_utf8(take_len_prefixed(&mut data)?)
        .map_err(|_| Error::InvalidBridgePackage)?
        .to_string();
    let signer_public_key = take_array(&mut data)?;
    let bridge_signature = take_array(&mut data)?;
    let personal_signature = take_array(&mut data)?;
    if !data.is_empty() {
        return Err(Error::InvalidBridgePackage);
    }
    Ok(BridgeSignature {
        uid,
        generation,
        bridge_salt,
        signature_salt,
        signer_label,
        signer_public_key,
        bridge_signature,
        personal_signature,
    })
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_u8(data: &mut &[u8]) -> Result<u8> {
    let (b, rest) = data.split_first().ok_or(Error::InvalidBridgePackage)?;
    *data = rest;
    Ok(*b)
}

fn take_n<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if data.len() < n {
        return Err(Error::InvalidBridgePackage);
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

fn take_array<const N: usize>(data: &mut &[u8]) -> Result<[u8; N]> {
    take_n(data, N)?
        .try_into()
        .map_err(|_| Error::InvalidBridgePackage)
}

fn take_len_prefixed<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = u16::from_be_bytes(take_array(data)?) as usize;
    take_n(data, len)
}

#[cfg(test)]
#[path = "signing/tests.rs"]
mod tests;

//! KeyQuorum-signed provider identity.
//!
//! `--features provider` only compiles mailbox-host *capabilities*. A
//! trusted relay is a provider build plus a `provider.kqcert` signed by
//! the offline KeyQuorum provider root, plus possession of the matching
//! relay private key. Official clients authenticate that identity; a
//! modified relay binary cannot make an unmodified client trust it.
//!
//! The compiled-in root public key is a verifier only. The matching
//! private key is not in this repository.

use crate::error::{Error, Result};
use crate::signing;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const CERT_MAGIC: &[u8; 4] = b"KQPC";
const KRL_MAGIC: &[u8; 4] = b"KQRL";
const FORMAT_VERSION: u8 = 1;
const CERT_DOMAIN: &[u8] = b"KQPROVIDER-CERT-v1";
const CHALLENGE_DOMAIN: &[u8] = b"KQPROVIDER-CHALLENGE-v1";
const KRL_DOMAIN: &[u8] = b"KQPROVIDER-KRL-v1";
const CHALLENGE_LEN: usize = 32;
const SIG_LEN: usize = 64;
const KEY_LEN: usize = 32;

/// Relay, mailbox, and host-local API-key administration.
pub const CAP_RELAY: u32 = 1 << 0;
pub const CAP_MAILBOX: u32 = 1 << 1;
pub const CAP_API_ADMIN: u32 = 1 << 2;
pub const CAP_PROVIDER: u32 = CAP_RELAY | CAP_MAILBOX | CAP_API_ADMIN;

/// Offline KeyQuorum provider-root verifying key. Replace with the
/// official offline-generated root before production issuance. The
/// matching private key must never appear in git, CI, or this tree.
pub const KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY: [u8; 32] = [
    0xf6, 0x82, 0x4a, 0xad, 0xd7, 0x57, 0x02, 0x42, 0x11, 0x5e, 0x50, 0xd5, 0x4c, 0x15, 0x32, 0xb8,
    0xcd, 0x9f, 0xa1, 0x2a, 0x9a, 0x5f, 0xc5, 0x49, 0x7b, 0x1c, 0x83, 0x88, 0x36, 0x29, 0x7c, 0x0d,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub provider_id: String,
    pub serial: String,
    pub relay_public_key: [u8; 32],
    pub issued_at: String,
    pub expires_at: String,
    pub capabilities: u32,
    pub issuer_id: String,
}

#[derive(Clone, Debug)]
pub struct NewCertificate<'a> {
    pub provider_id: &'a str,
    pub serial: &'a str,
    pub relay_public_key: &'a [u8; 32],
    pub issued_at: &'a str,
    pub expires_at: &'a str,
    pub capabilities: u32,
    pub issuer_id: &'a str,
}

/// Relay keypair used as the provider identity (Ed25519). The secret
/// stays on the provider machine — ideally a TPM/HSM later.
pub fn generate_relay_identity() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    crate::keys::generate_signing_keypair()
}

pub fn issue_certificate(
    root_private_key: &[u8; 32],
    spec: &NewCertificate<'_>,
) -> Result<Vec<u8>> {
    let body = encode_cert_body(spec)?;
    let mut out = Vec::with_capacity(4 + 1 + body.len() + SIG_LEN);
    out.extend_from_slice(CERT_MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&body);
    let signature = signing::sign(root_private_key, &cert_preimage(&body));
    out.extend_from_slice(&signature);
    Ok(out)
}

pub fn parse_certificate(bytes: &[u8]) -> Result<Certificate> {
    let (cert, _body) = parse_certificate_body(bytes)?;
    Ok(cert)
}

pub fn verify_certificate(
    root_public_key: &[u8; 32],
    bytes: &[u8],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Certificate> {
    let (cert, body) = parse_certificate_body(bytes)?;
    let signature: [u8; SIG_LEN] = bytes[bytes.len() - SIG_LEN..]
        .try_into()
        .map_err(|_| Error::InvalidProviderCertificate)?;
    signing::verify_signature(root_public_key, &cert_preimage(&body), &signature)
        .map_err(|_| Error::InvalidProviderCertificate)?;
    if revoked.contains(&cert.serial) {
        return Err(Error::ProviderCertificateRevoked);
    }
    if cert.expires_at.as_str() <= now_utc {
        return Err(Error::ProviderCertificateExpired);
    }
    if cert.capabilities & CAP_PROVIDER != CAP_PROVIDER {
        return Err(Error::ProviderCapabilityDenied);
    }
    Ok(cert)
}

/// Confirm this process holds the private key named in the certificate.
pub fn self_check(
    root_public_key: &[u8; 32],
    certificate: &[u8],
    relay_private_key: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Certificate> {
    let cert = verify_certificate(root_public_key, certificate, now_utc, revoked)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(relay_private_key);
    if signing_key.verifying_key().to_bytes() != cert.relay_public_key {
        return Err(Error::RelayIdentityMismatch);
    }
    Ok(cert)
}

pub fn random_challenge() -> [u8; CHALLENGE_LEN] {
    *crate::crypto::random_key()
}

pub fn sign_challenge(relay_private_key: &[u8; 32], challenge: &[u8]) -> Result<[u8; SIG_LEN]> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(Error::InvalidProviderChallenge);
    }
    Ok(signing::sign(
        relay_private_key,
        &challenge_preimage(challenge),
    ))
}

pub fn verify_challenge(
    cert: &Certificate,
    challenge: &[u8],
    signature: &[u8; SIG_LEN],
) -> Result<()> {
    if challenge.len() != CHALLENGE_LEN {
        return Err(Error::InvalidProviderChallenge);
    }
    signing::verify_signature(
        &cert.relay_public_key,
        &challenge_preimage(challenge),
        signature,
    )
    .map_err(|_| Error::UntrustedRelay)
}

pub fn issue_revocation_list(
    root_private_key: &[u8; 32],
    issued_at: &str,
    serials: &[String],
) -> Result<Vec<u8>> {
    let body = encode_krl_body(issued_at, serials)?;
    let mut out = Vec::with_capacity(4 + 1 + body.len() + SIG_LEN);
    out.extend_from_slice(KRL_MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&body);
    let signature = signing::sign(root_private_key, &krl_preimage(&body));
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Load a signed revocation list. Missing path → empty set. A present
/// path is fail-closed: unreadable or invalid material is an error.
pub fn load_revocation_list(
    root_public_key: &[u8; 32],
    path: Option<&Path>,
) -> Result<HashSet<String>> {
    let Some(path) = path else {
        return Ok(HashSet::new());
    };
    let bytes = std::fs::read(path)?;
    verify_revocation_list(root_public_key, &bytes)
}

pub fn parse_capabilities(spec: &str) -> Result<u32> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("provider") {
        return Ok(CAP_PROVIDER);
    }
    let mut caps = 0u32;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        caps |= match part {
            "relay" => CAP_RELAY,
            "mailbox" => CAP_MAILBOX,
            "api-key-administration" | "api-admin" => CAP_API_ADMIN,
            _ => return Err(Error::ProviderCapabilityDenied),
        };
    }
    if caps == 0 {
        Err(Error::ProviderCapabilityDenied)
    } else {
        Ok(caps)
    }
}

pub fn verify_revocation_list(root_public_key: &[u8; 32], bytes: &[u8]) -> Result<HashSet<String>> {
    if bytes.len() < 4 + 1 + SIG_LEN || bytes[..4] != *KRL_MAGIC {
        return Err(Error::InvalidProviderCertificate);
    }
    if bytes[4] != FORMAT_VERSION {
        return Err(Error::InvalidProviderCertificate);
    }
    let body = &bytes[5..bytes.len() - SIG_LEN];
    let signature: [u8; SIG_LEN] = bytes[bytes.len() - SIG_LEN..]
        .try_into()
        .map_err(|_| Error::InvalidProviderCertificate)?;
    signing::verify_signature(root_public_key, &krl_preimage(body), &signature)
        .map_err(|_| Error::InvalidProviderCertificate)?;
    decode_krl_serials(body)
}

/// UTC `YYYY-MM-DD HH:MM:00` from the system clock, for expiry checks
/// when no SQLite connection is available.
pub fn system_now_utc() -> Result<String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?
        .as_secs();
    Ok(unix_to_utc_minute(secs))
}

fn cert_preimage(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CERT_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn challenge_preimage(challenge: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(challenge);
    hasher.finalize().into()
}

fn krl_preimage(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KRL_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_cert_body(spec: &NewCertificate<'_>) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    put_str(&mut body, spec.provider_id)?;
    put_str(&mut body, spec.serial)?;
    body.extend_from_slice(spec.relay_public_key);
    put_str(&mut body, spec.issued_at)?;
    put_str(&mut body, spec.expires_at)?;
    body.extend_from_slice(&spec.capabilities.to_be_bytes());
    put_str(&mut body, spec.issuer_id)?;
    Ok(body)
}

fn parse_certificate_body(bytes: &[u8]) -> Result<(Certificate, Vec<u8>)> {
    if bytes.len() < 4 + 1 + KEY_LEN + SIG_LEN || bytes[..4] != *CERT_MAGIC {
        return Err(Error::InvalidProviderCertificate);
    }
    if bytes[4] != FORMAT_VERSION {
        return Err(Error::InvalidProviderCertificate);
    }
    let body = bytes[5..bytes.len() - SIG_LEN].to_vec();
    let mut offset = 0;
    let provider_id = take_str(&body, &mut offset)?;
    let serial = take_str(&body, &mut offset)?;
    let relay_public_key: [u8; 32] = body
        .get(offset..offset + KEY_LEN)
        .ok_or(Error::InvalidProviderCertificate)?
        .try_into()
        .map_err(|_| Error::InvalidProviderCertificate)?;
    offset += KEY_LEN;
    let issued_at = take_str(&body, &mut offset)?;
    let expires_at = take_str(&body, &mut offset)?;
    let capabilities = u32::from_be_bytes(
        body.get(offset..offset + 4)
            .ok_or(Error::InvalidProviderCertificate)?
            .try_into()
            .map_err(|_| Error::InvalidProviderCertificate)?,
    );
    offset += 4;
    let issuer_id = take_str(&body, &mut offset)?;
    if offset != body.len() {
        return Err(Error::InvalidProviderCertificate);
    }
    Ok((
        Certificate {
            provider_id,
            serial,
            relay_public_key,
            issued_at,
            expires_at,
            capabilities,
            issuer_id,
        },
        body,
    ))
}

fn encode_krl_body(issued_at: &str, serials: &[String]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    put_str(&mut body, issued_at)?;
    let count = u16::try_from(serials.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    body.extend_from_slice(&count.to_be_bytes());
    for serial in serials {
        put_str(&mut body, serial)?;
    }
    Ok(body)
}

fn decode_krl_serials(body: &[u8]) -> Result<HashSet<String>> {
    let mut offset = 0;
    let _issued = take_str(body, &mut offset)?;
    let count = u16::from_be_bytes(
        body.get(offset..offset + 2)
            .ok_or(Error::InvalidProviderCertificate)?
            .try_into()
            .map_err(|_| Error::InvalidProviderCertificate)?,
    );
    offset += 2;
    let mut serials = HashSet::new();
    for _ in 0..count {
        serials.insert(take_str(body, &mut offset)?);
    }
    if offset != body.len() {
        return Err(Error::InvalidProviderCertificate);
    }
    Ok(serials)
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    if !value.is_ascii() || value.is_empty() {
        return Err(Error::InvalidProviderCertificate);
    }
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_str(buf: &[u8], offset: &mut usize) -> Result<String> {
    let len_bytes = buf
        .get(*offset..*offset + 2)
        .ok_or(Error::InvalidProviderCertificate)?;
    let len = u16::from_be_bytes(
        len_bytes
            .try_into()
            .map_err(|_| Error::InvalidProviderCertificate)?,
    ) as usize;
    *offset += 2;
    let bytes = buf
        .get(*offset..*offset + len)
        .ok_or(Error::InvalidProviderCertificate)?;
    *offset += len;
    let value = std::str::from_utf8(bytes).map_err(|_| Error::InvalidProviderCertificate)?;
    if !value.is_ascii() || value.is_empty() {
        return Err(Error::InvalidProviderCertificate);
    }
    Ok(value.to_string())
}

pub(crate) fn unix_to_utc_minute(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:00")
}

/// Howard Hinnant's civil-from-days (UTC, proleptic Gregorian).
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + i64::from(m <= 2);
    (y as i32, m as u32, d as u32)
}

pub mod root_network;

#[cfg(test)]
#[path = "provider/test_helpers.rs"]
pub(crate) mod test_helpers;

#[cfg(test)]
#[path = "provider/tests.rs"]
mod tests;

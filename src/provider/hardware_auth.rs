//! Provider hardware authority and proof-of-possession.
//!
//! `KeyType::Signing` means the token can sign. It does not mean the
//! token is a provider key. Official API-root minting requires a
//! fingerprint listed in the signed policy, role `ProviderApiRoot`, and
//! a fresh signature over the domain-separated challenge.

use crate::error::{Error, Result};
use crate::keys::{self, KeyType};
use crate::provider::policy::ProviderPolicy;
use crate::signing;
use sha2::{Digest, Sha256};

const API_ROOT_DOMAIN: &[u8] = b"KQ-API-ROOT-v1";
const NONCE_LEN: usize = 32;
const SIG_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareAuthority {
    ProviderApiRoot,
    ProviderRelayAdmin,
}

impl HardwareAuthority {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::ProviderApiRoot => 1,
            Self::ProviderRelayAdmin => 2,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::ProviderApiRoot),
            2 => Ok(Self::ProviderRelayAdmin),
            _ => Err(Error::InvalidProviderPolicy),
        }
    }

    pub fn parse(spec: &str) -> Result<Self> {
        match spec.trim() {
            "provider-api-root" | "api-root" => Ok(Self::ProviderApiRoot),
            "provider-relay-admin" | "relay-admin" => Ok(Self::ProviderRelayAdmin),
            _ => Err(Error::InvalidProviderPolicy),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedHardware {
    pub fingerprint: String,
    pub required_key_type: KeyType,
    pub authority: HardwareAuthority,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderChallenge<'a> {
    pub provider_id: &'a str,
    pub relay_id: &'a [u8; 32],
    pub network_policy_id: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a [u8; 32],
    pub required_authority: HardwareAuthority,
}

pub fn api_root_preimage(challenge: &ProviderChallenge<'_>) -> Result<[u8; 32]> {
    if challenge.nonce.len() != NONCE_LEN {
        return Err(Error::InvalidProviderChallenge);
    }
    if !challenge.provider_id.is_ascii()
        || challenge.provider_id.is_empty()
        || !challenge.network_policy_id.is_ascii()
        || challenge.network_policy_id.is_empty()
        || !challenge.timestamp.is_ascii()
        || challenge.timestamp.is_empty()
    {
        return Err(Error::InvalidProviderChallenge);
    }
    let mut hasher = Sha256::new();
    hasher.update(API_ROOT_DOMAIN);
    put_len(&mut hasher, challenge.provider_id.as_bytes())?;
    hasher.update(challenge.relay_id);
    put_len(&mut hasher, challenge.network_policy_id.as_bytes())?;
    put_len(&mut hasher, challenge.timestamp.as_bytes())?;
    hasher.update(challenge.nonce);
    Ok(hasher.finalize().into())
}

pub fn sign_provider_hardware(
    hardware_private_key: &[u8; 32],
    challenge: &ProviderChallenge<'_>,
) -> Result<[u8; SIG_LEN]> {
    Ok(signing::sign(
        hardware_private_key,
        &api_root_preimage(challenge)?,
    ))
}

pub fn verify_provider_hardware(
    policy: &ProviderPolicy,
    challenge: &ProviderChallenge<'_>,
    presented_public_key: &[u8; 32],
    signature: &[u8; SIG_LEN],
) -> Result<AuthorizedHardware> {
    if policy.hardware_threshold != 1 {
        return Err(Error::InvalidProviderPolicy);
    }
    let fingerprint = keys::fingerprint(presented_public_key);
    let entry = policy
        .hardware_entry(&fingerprint)
        .ok_or(Error::ProviderHardwareDenied)?;
    if entry.revoked {
        return Err(Error::ProviderHardwareRevoked);
    }
    if entry.key_type != KeyType::Signing {
        return Err(Error::WrongKeyType);
    }
    if entry.authority != challenge.required_authority {
        return Err(Error::ProviderHardwareDenied);
    }
    signing::verify_signature(
        presented_public_key,
        &api_root_preimage(challenge)?,
        signature,
    )
    .map_err(|_| Error::ProviderHardwareDenied)?;
    Ok(AuthorizedHardware {
        fingerprint,
        required_key_type: KeyType::Signing,
        authority: entry.authority,
    })
}

fn put_len(hasher: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::InvalidProviderChallenge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

#[cfg(test)]
#[path = "hardware_auth/tests.rs"]
mod tests;

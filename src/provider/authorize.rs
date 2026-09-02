//! Combined provider gates for official API-root generation.
//!
//! Official `kql_…` minting requires a KeyQuorum-signed certificate,
//! a matching relay key, a signed Corporate Network (VPN tunnel or
//! associated Wi-Fi), and proof of authorized provider hardware.
//! Caller-supplied CIDRs/SSIDs and SQLite rows are not authority.

use crate::error::{Error, Result};
use crate::provider::hardware_auth::{self, HardwareAuthority, ProviderChallenge};
use crate::provider::network::WifiLink;
use crate::provider::policy::{self, ProviderPolicy, PERM_API_ROOT_GENERATE};
use crate::provider::root_network::{self, LocalAddress, NetworkAuthority};
use crate::provider::{self, Certificate, CAP_PROVIDER};
use std::collections::HashSet;

pub struct ApiRootRequest<'a> {
    pub root_public_key: &'a [u8; 32],
    pub certificate: &'a [u8],
    pub relay_private_key: &'a [u8; 32],
    pub policy: &'a [u8],
    pub now_utc: &'a str,
    pub revoked: &'a HashSet<String>,
    pub network_id: &'a str,
    pub local_addrs: &'a [LocalAddress],
    pub wifi_links: &'a [WifiLink],
    pub caller_networks: &'a [String],
    pub hardware_public_key: &'a [u8; 32],
    pub hardware_signature: &'a [u8; 64],
    pub timestamp: &'a str,
    pub nonce: &'a [u8; 32],
}

pub struct AuthorizedApiRoot {
    pub certificate: Certificate,
    pub policy: ProviderPolicy,
    pub hardware_fingerprint: String,
    pub network_id: String,
}

pub fn authorize_api_root_generation(req: &ApiRootRequest<'_>) -> Result<AuthorizedApiRoot> {
    if !req.caller_networks.is_empty() {
        return Err(Error::CallerNetworkNotAuthoritative);
    }
    let certificate = provider::self_check(
        req.root_public_key,
        req.certificate,
        req.relay_private_key,
        req.now_utc,
        req.revoked,
    )?;
    let policy = policy::verify_policy(req.root_public_key, req.policy, req.now_utc)?;
    if policy.provider_id != certificate.provider_id
        || policy.relay_public_key != certificate.relay_public_key
        || policy.capabilities & CAP_PROVIDER != CAP_PROVIDER
        || !policy.has_permission(PERM_API_ROOT_GENERATE)
    {
        return Err(Error::InvalidProviderPolicy);
    }
    root_network::authorize_corporate_network(
        NetworkAuthority::Signed {
            policy: &policy,
            network_id: req.network_id,
        },
        req.local_addrs,
        req.wifi_links,
    )?;
    let challenge = ProviderChallenge {
        provider_id: &certificate.provider_id,
        relay_id: &certificate.relay_public_key,
        network_policy_id: req.network_id,
        timestamp: req.timestamp,
        nonce: req.nonce,
        required_authority: HardwareAuthority::ProviderApiRoot,
    };
    let hardware = hardware_auth::verify_provider_hardware(
        &policy,
        &challenge,
        req.hardware_public_key,
        req.hardware_signature,
    )?;
    Ok(AuthorizedApiRoot {
        certificate,
        hardware_fingerprint: hardware.fingerprint,
        network_id: req.network_id.to_string(),
        policy,
    })
}

#[cfg(test)]
#[path = "authorize/tests.rs"]
mod tests;

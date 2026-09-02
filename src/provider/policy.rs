//! Provider-root-signed hardware and Corporate Network policy.
//!
//! Production CIDRs and provider hardware fingerprints live in this
//! artifact, not in caller `--network` flags or SQLite rows. Official
//! clients still pin the compiled-in root public key; this file only
//! authorizes which networks and tokens the seller may use.

use crate::error::{Error, Result};
use crate::keys::KeyType;
use crate::provider::hardware_auth::HardwareAuthority;
use crate::signing;
use sha2::{Digest, Sha256};

const POLICY_MAGIC: &[u8; 4] = b"KQPL";
const FORMAT_VERSION: u8 = 1;
const POLICY_DOMAIN: &[u8] = b"KQPROVIDER-POLICY-v1";
const SIG_LEN: usize = 64;
const KEY_LEN: usize = 32;

pub const PERM_API_ROOT_GENERATE: &str = "api-root.generate";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkMode {
    Vpn,
    Wifi,
    Ethernet,
}

impl NetworkMode {
    fn to_u8(self) -> u8 {
        match self {
            Self::Vpn => 1,
            Self::Wifi => 2,
            Self::Ethernet => 3,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Vpn),
            2 => Ok(Self::Wifi),
            3 => Ok(Self::Ethernet),
            _ => Err(Error::InvalidProviderPolicy),
        }
    }

    pub fn parse(spec: &str) -> Result<Self> {
        match spec.trim() {
            "vpn" => Ok(Self::Vpn),
            "wifi" => Ok(Self::Wifi),
            "ethernet" => Ok(Self::Ethernet),
            _ => Err(Error::InvalidProviderPolicy),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareAuthorityEntry {
    pub fingerprint: String,
    pub key_type: KeyType,
    pub authority: HardwareAuthority,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorporateNetwork {
    pub network_id: String,
    pub mode: NetworkMode,
    pub cidrs: Vec<String>,
    pub ssid: Option<String>,
    pub bssid_mac: Option<String>,
    pub gateway_mac: Option<String>,
    pub verifier_public_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderPolicy {
    pub provider_id: String,
    pub policy_id: String,
    pub relay_public_key: [u8; 32],
    pub issued_at: String,
    pub expires_at: String,
    pub capabilities: u32,
    pub hardware_threshold: u8,
    pub hardware: Vec<HardwareAuthorityEntry>,
    pub networks: Vec<CorporateNetwork>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NewPolicy<'a> {
    pub provider_id: &'a str,
    pub policy_id: &'a str,
    pub relay_public_key: &'a [u8; 32],
    pub issued_at: &'a str,
    pub expires_at: &'a str,
    pub capabilities: u32,
    pub hardware_threshold: u8,
    pub hardware: &'a [HardwareAuthorityEntry],
    pub networks: &'a [CorporateNetwork],
    pub permissions: &'a [String],
}

pub fn issue_policy(root_private_key: &[u8; 32], spec: &NewPolicy<'_>) -> Result<Vec<u8>> {
    let body = encode_policy_body(spec)?;
    let mut out = Vec::with_capacity(4 + 1 + body.len() + SIG_LEN);
    out.extend_from_slice(POLICY_MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&body);
    let signature = signing::sign(root_private_key, &policy_preimage(&body));
    out.extend_from_slice(&signature);
    Ok(out)
}

pub fn parse_policy(bytes: &[u8]) -> Result<ProviderPolicy> {
    let (policy, _body) = parse_policy_body(bytes)?;
    Ok(policy)
}

pub fn verify_policy(
    root_public_key: &[u8; 32],
    bytes: &[u8],
    now_utc: &str,
) -> Result<ProviderPolicy> {
    let (policy, body) = parse_policy_body(bytes)?;
    let signature: [u8; SIG_LEN] = bytes[bytes.len() - SIG_LEN..]
        .try_into()
        .map_err(|_| Error::InvalidProviderPolicy)?;
    signing::verify_signature(root_public_key, &policy_preimage(&body), &signature)
        .map_err(|_| Error::InvalidProviderPolicy)?;
    if policy.expires_at.as_str() <= now_utc {
        return Err(Error::ProviderPolicyExpired);
    }
    Ok(policy)
}

impl ProviderPolicy {
    pub fn corporate_network(&self, network_id: &str) -> Result<&CorporateNetwork> {
        self.networks
            .iter()
            .find(|network| network.network_id == network_id)
            .ok_or(Error::RootNetworkRequired)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|item| item == permission)
    }

    pub fn hardware_entry(&self, fingerprint: &str) -> Option<&HardwareAuthorityEntry> {
        self.hardware
            .iter()
            .find(|entry| entry.fingerprint == fingerprint)
    }
}

pub fn normalize_fingerprint(fingerprint: &str) -> Result<String> {
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::InvalidProviderPolicy);
    }
    Ok(fingerprint.to_ascii_lowercase())
}

fn policy_preimage(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn encode_policy_body(spec: &NewPolicy<'_>) -> Result<Vec<u8>> {
    if spec.hardware.is_empty() || spec.networks.is_empty() || spec.permissions.is_empty() {
        return Err(Error::InvalidProviderPolicy);
    }
    if spec.hardware_threshold == 0 || usize::from(spec.hardware_threshold) > spec.hardware.len() {
        return Err(Error::InvalidProviderPolicy);
    }
    let mut body = Vec::new();
    put_str(&mut body, spec.provider_id)?;
    put_str(&mut body, spec.policy_id)?;
    body.extend_from_slice(spec.relay_public_key);
    put_str(&mut body, spec.issued_at)?;
    put_str(&mut body, spec.expires_at)?;
    body.extend_from_slice(&spec.capabilities.to_be_bytes());
    body.push(spec.hardware_threshold);
    put_u16(&mut body, spec.hardware.len())?;
    for entry in spec.hardware {
        put_str(&mut body, &normalize_fingerprint(&entry.fingerprint)?)?;
        body.push(key_type_to_u8(entry.key_type)?);
        body.push(entry.authority.to_u8());
        body.push(u8::from(entry.revoked));
    }
    put_u16(&mut body, spec.networks.len())?;
    for network in spec.networks {
        encode_network(&mut body, network)?;
    }
    put_u16(&mut body, spec.permissions.len())?;
    for permission in spec.permissions {
        put_str(&mut body, permission)?;
    }
    Ok(body)
}

fn validate_network(network: &CorporateNetwork) -> Result<()> {
    match network.mode {
        NetworkMode::Vpn => {
            if network.cidrs.is_empty() {
                return Err(Error::InvalidProviderPolicy);
            }
        }
        NetworkMode::Wifi => {
            if network.ssid.as_deref().is_none_or(str::is_empty) {
                return Err(Error::InvalidProviderPolicy);
            }
        }
        NetworkMode::Ethernet => {
            if network.cidrs.is_empty() {
                return Err(Error::InvalidProviderPolicy);
            }
        }
    }
    Ok(())
}

fn encode_network(body: &mut Vec<u8>, network: &CorporateNetwork) -> Result<()> {
    validate_network(network)?;
    put_str(body, &network.network_id)?;
    body.push(network.mode.to_u8());
    put_u16(body, network.cidrs.len())?;
    for cidr in &network.cidrs {
        put_str(body, cidr)?;
    }
    put_opt_str(body, network.ssid.as_deref())?;
    put_opt_str(body, network.bssid_mac.as_deref())?;
    put_opt_str(body, network.gateway_mac.as_deref())?;
    match network.verifier_public_key {
        Some(key) => {
            body.push(1);
            body.extend_from_slice(&key);
        }
        None => body.push(0),
    }
    Ok(())
}

fn parse_policy_body(bytes: &[u8]) -> Result<(ProviderPolicy, Vec<u8>)> {
    if bytes.len() < 4 + 1 + KEY_LEN + SIG_LEN || bytes[..4] != *POLICY_MAGIC {
        return Err(Error::InvalidProviderPolicy);
    }
    if bytes[4] != FORMAT_VERSION {
        return Err(Error::InvalidProviderPolicy);
    }
    let body = bytes[5..bytes.len() - SIG_LEN].to_vec();
    let mut offset = 0;
    let provider_id = take_str(&body, &mut offset)?;
    let policy_id = take_str(&body, &mut offset)?;
    let relay_public_key: [u8; 32] = body
        .get(offset..offset + KEY_LEN)
        .ok_or(Error::InvalidProviderPolicy)?
        .try_into()
        .map_err(|_| Error::InvalidProviderPolicy)?;
    offset += KEY_LEN;
    let issued_at = take_str(&body, &mut offset)?;
    let expires_at = take_str(&body, &mut offset)?;
    let capabilities = u32::from_be_bytes(
        body.get(offset..offset + 4)
            .ok_or(Error::InvalidProviderPolicy)?
            .try_into()
            .map_err(|_| Error::InvalidProviderPolicy)?,
    );
    offset += 4;
    let hardware_threshold = *body.get(offset).ok_or(Error::InvalidProviderPolicy)?;
    offset += 1;
    let hardware_count = take_u16(&body, &mut offset)?;
    let mut hardware = Vec::with_capacity(hardware_count);
    for _ in 0..hardware_count {
        let fingerprint = normalize_fingerprint(&take_str(&body, &mut offset)?)?;
        let key_type = key_type_from_u8(*body.get(offset).ok_or(Error::InvalidProviderPolicy)?)?;
        offset += 1;
        let authority =
            HardwareAuthority::from_u8(*body.get(offset).ok_or(Error::InvalidProviderPolicy)?)?;
        offset += 1;
        let revoked = *body.get(offset).ok_or(Error::InvalidProviderPolicy)?;
        offset += 1;
        if revoked > 1 {
            return Err(Error::InvalidProviderPolicy);
        }
        hardware.push(HardwareAuthorityEntry {
            fingerprint,
            key_type,
            authority,
            revoked: revoked == 1,
        });
    }
    let network_count = take_u16(&body, &mut offset)?;
    let mut networks = Vec::with_capacity(network_count);
    for _ in 0..network_count {
        networks.push(decode_network(&body, &mut offset)?);
    }
    let permission_count = take_u16(&body, &mut offset)?;
    let mut permissions = Vec::with_capacity(permission_count);
    for _ in 0..permission_count {
        permissions.push(take_str(&body, &mut offset)?);
    }
    if offset != body.len()
        || hardware.is_empty()
        || networks.is_empty()
        || permissions.is_empty()
        || hardware_threshold == 0
        || usize::from(hardware_threshold) > hardware.len()
    {
        return Err(Error::InvalidProviderPolicy);
    }
    Ok((
        ProviderPolicy {
            provider_id,
            policy_id,
            relay_public_key,
            issued_at,
            expires_at,
            capabilities,
            hardware_threshold,
            hardware,
            networks,
            permissions,
        },
        body,
    ))
}

fn decode_network(body: &[u8], offset: &mut usize) -> Result<CorporateNetwork> {
    let network_id = take_str(body, offset)?;
    let mode = NetworkMode::from_u8(*body.get(*offset).ok_or(Error::InvalidProviderPolicy)?)?;
    *offset += 1;
    let cidr_count = take_u16(body, offset)?;
    let mut cidrs = Vec::with_capacity(cidr_count);
    for _ in 0..cidr_count {
        cidrs.push(take_str(body, offset)?);
    }
    let ssid = take_opt_str(body, offset)?;
    let bssid_mac = take_opt_str(body, offset)?;
    let gateway_mac = take_opt_str(body, offset)?;
    let flag = *body.get(*offset).ok_or(Error::InvalidProviderPolicy)?;
    *offset += 1;
    let verifier_public_key = match flag {
        0 => None,
        1 => {
            let key: [u8; 32] = body
                .get(*offset..*offset + KEY_LEN)
                .ok_or(Error::InvalidProviderPolicy)?
                .try_into()
                .map_err(|_| Error::InvalidProviderPolicy)?;
            *offset += KEY_LEN;
            Some(key)
        }
        _ => return Err(Error::InvalidProviderPolicy),
    };
    let network = CorporateNetwork {
        network_id,
        mode,
        cidrs,
        ssid,
        bssid_mac,
        gateway_mac,
        verifier_public_key,
    };
    validate_network(&network)?;
    Ok(network)
}

fn key_type_to_u8(key_type: KeyType) -> Result<u8> {
    match key_type {
        KeyType::Signing => Ok(1),
        KeyType::Encryption => Err(Error::WrongKeyType),
    }
}

fn key_type_from_u8(value: u8) -> Result<KeyType> {
    match value {
        1 => Ok(KeyType::Signing),
        _ => Err(Error::WrongKeyType),
    }
}

fn put_u16(out: &mut Vec<u8>, value: usize) -> Result<()> {
    let count = u16::try_from(value).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn take_u16(buf: &[u8], offset: &mut usize) -> Result<usize> {
    let bytes = buf
        .get(*offset..*offset + 2)
        .ok_or(Error::InvalidProviderPolicy)?;
    *offset += 2;
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| Error::InvalidProviderPolicy)?) as usize)
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    if !value.is_ascii() || value.is_empty() {
        return Err(Error::InvalidProviderPolicy);
    }
    put_len_bytes(out, value.as_bytes())
}

fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) if !value.is_empty() => put_len_bytes(out, value.as_bytes()),
        _ => put_len_bytes(out, &[]),
    }
}

fn put_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::BundleFieldTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn take_str(buf: &[u8], offset: &mut usize) -> Result<String> {
    let value = take_opt_str(buf, offset)?.ok_or(Error::InvalidProviderPolicy)?;
    if !value.is_ascii() {
        return Err(Error::InvalidProviderPolicy);
    }
    Ok(value)
}

fn take_opt_str(buf: &[u8], offset: &mut usize) -> Result<Option<String>> {
    let len_bytes = buf
        .get(*offset..*offset + 2)
        .ok_or(Error::InvalidProviderPolicy)?;
    let len = u16::from_be_bytes(
        len_bytes
            .try_into()
            .map_err(|_| Error::InvalidProviderPolicy)?,
    ) as usize;
    *offset += 2;
    let bytes = buf
        .get(*offset..*offset + len)
        .ok_or(Error::InvalidProviderPolicy)?;
    *offset += len;
    if bytes.is_empty() {
        return Ok(None);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| Error::InvalidProviderPolicy)?;
    Ok(Some(value.to_string()))
}

#[cfg(test)]
#[path = "policy/tests.rs"]
mod tests;

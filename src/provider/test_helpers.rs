use super::*;
use std::collections::HashSet;
use zeroize::Zeroizing;

pub(crate) struct IssuedIdentity {
    pub root_public: [u8; 32],
    pub relay_private: Zeroizing<[u8; 32]>,
    pub relay_public: [u8; 32],
    pub certificate: Vec<u8>,
}

pub(crate) fn issued_identity(expires_at: &str) -> IssuedIdentity {
    issued_identity_with_caps(expires_at, CAP_PROVIDER)
}

pub(crate) fn issued_identity_with_caps(expires_at: &str, capabilities: u32) -> IssuedIdentity {
    let (root_private, root_public) = crate::keys::generate_signing_keypair();
    let (relay_private, relay_public) = generate_relay_identity();
    let certificate = issue_certificate(
        &root_private,
        &NewCertificate {
            provider_id: "Acme Security Services",
            serial: "KQP-000184",
            relay_public_key: &relay_public,
            issued_at: "2026-01-01 00:00:00",
            expires_at,
            capabilities,
            issuer_id: "KeyQuorumRoot",
        },
    )
    .expect("issue");
    IssuedIdentity {
        root_public,
        relay_private,
        relay_public,
        certificate,
    }
}

pub(crate) fn empty_revoked() -> HashSet<String> {
    HashSet::new()
}

pub(crate) fn listed_provider_policy(
    provider_id: &str,
    relay_public: [u8; 32],
    hardware_fingerprints: &[&str],
) -> crate::provider::policy::ProviderPolicy {
    use crate::keys::KeyType;
    use crate::provider::hardware_auth::HardwareAuthority;
    use crate::provider::policy::{
        CorporateNetwork, HardwareAuthorityEntry, NetworkMode, ProviderPolicy,
    };
    ProviderPolicy {
        provider_id: provider_id.to_string(),
        policy_id: "KQP-POL-TEST".into(),
        relay_public_key: relay_public,
        issued_at: "2026-01-01 00:00:00".into(),
        expires_at: "2027-09-02 00:00:00".into(),
        capabilities: CAP_PROVIDER,
        hardware_threshold: 1,
        hardware: hardware_fingerprints
            .iter()
            .map(|fp| HardwareAuthorityEntry {
                fingerprint: fp.to_string(),
                key_type: KeyType::Signing,
                authority: HardwareAuthority::ProviderApiRoot,
                revoked: false,
            })
            .collect(),
        networks: vec![CorporateNetwork {
            network_id: "corp-vpn".into(),
            mode: NetworkMode::Vpn,
            cidrs: vec!["10.8.0.0/24".into()],
            ssid: None,
            bssid_mac: None,
            gateway_mac: None,
            verifier_public_key: None,
        }],
        permissions: vec!["api-root.generate".into()],
    }
}

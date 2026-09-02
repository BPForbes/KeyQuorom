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

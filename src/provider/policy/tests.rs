use super::*;
use crate::error::Error;
use crate::keys::{self, KeyType};
use crate::provider::hardware_auth::HardwareAuthority;
use crate::provider::{generate_relay_identity, CAP_PROVIDER};

fn sample_hardware(fingerprint: &str, revoked: bool) -> HardwareAuthorityEntry {
    HardwareAuthorityEntry {
        fingerprint: fingerprint.to_string(),
        key_type: KeyType::Signing,
        authority: HardwareAuthority::ProviderApiRoot,
        revoked,
    }
}

fn sample_network(id: &str, cidr: &str) -> CorporateNetwork {
    CorporateNetwork {
        network_id: id.to_string(),
        mode: NetworkMode::Vpn,
        cidrs: vec![cidr.to_string()],
        ssid: None,
        bssid_mac: None,
        gateway_mac: None,
        verifier_public_key: None,
    }
}

fn issue_sample(root: &[u8; 32], relay: &[u8; 32], hardware: &[HardwareAuthorityEntry]) -> Vec<u8> {
    issue_policy(
        root,
        &NewPolicy {
            provider_id: "Acme Security Services",
            policy_id: "KQP-POL-1",
            relay_public_key: relay,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-09-02 00:00:00",
            capabilities: CAP_PROVIDER,
            hardware_threshold: 1,
            hardware,
            networks: &[
                sample_network("corp-vpn", "10.8.0.0/24"),
                sample_network("lab-vpn", "10.9.0.0/24"),
            ],
            permissions: &[PERM_API_ROOT_GENERATE.to_string()],
        },
    )
    .expect("issue policy")
}

#[test]
fn issue_and_verify_policy_round_trip() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let fp = keys::fingerprint(&relay_pk);
    let bytes = issue_sample(&root_sk, &relay_pk, &[sample_hardware(&fp, false)]);
    let policy = verify_policy(&root_pk, &bytes, "2026-09-02 12:00:00").expect("verify");
    assert_eq!(policy.provider_id, "Acme Security Services");
    assert_eq!(policy.policy_id, "KQP-POL-1");
    assert_eq!(policy.relay_public_key, relay_pk);
    assert_eq!(policy.hardware[0].fingerprint, fp);
    assert_eq!(policy.networks.len(), 2);
    assert!(policy.has_permission(PERM_API_ROOT_GENERATE));
    assert!(policy.corporate_network("lab-vpn").is_ok());
}

#[test]
fn expired_or_foreign_policy_is_rejected() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let fp = keys::fingerprint(&relay_pk);
    let bytes = issue_sample(&root_sk, &relay_pk, &[sample_hardware(&fp, false)]);
    assert!(matches!(
        verify_policy(&root_pk, &bytes, "2027-09-02 00:00:00"),
        Err(Error::ProviderPolicyExpired)
    ));
    let (_, other) = keys::generate_signing_keypair();
    assert!(matches!(
        verify_policy(&other, &bytes, "2026-09-02 12:00:00"),
        Err(Error::InvalidProviderPolicy)
    ));
}

#[test]
fn sqlite_style_tamper_cannot_invent_policy_fields() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let fp = keys::fingerprint(&relay_pk);
    let mut bytes = issue_sample(&root_sk, &relay_pk, &[sample_hardware(&fp, false)]);
    let parsed = parse_policy(&bytes).expect("parse");
    assert!(parsed.corporate_network("forged-vpn").is_err());
    // Flip a payload byte; signature must fail closed.
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    assert!(matches!(
        verify_policy(&root_pk, &bytes, "2026-09-02 12:00:00"),
        Err(Error::InvalidProviderPolicy)
    ));
}

#[test]
fn issue_rejects_empty_hardware_or_networks() {
    let (root_sk, _) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let err = issue_policy(
        &root_sk,
        &NewPolicy {
            provider_id: "Acme",
            policy_id: "p1",
            relay_public_key: &relay_pk,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-01-01 00:00:00",
            capabilities: CAP_PROVIDER,
            hardware_threshold: 1,
            hardware: &[],
            networks: &[sample_network("corp-vpn", "10.8.0.0/24")],
            permissions: &[PERM_API_ROOT_GENERATE.to_string()],
        },
    )
    .unwrap_err();
    assert!(matches!(err, Error::InvalidProviderPolicy));
}

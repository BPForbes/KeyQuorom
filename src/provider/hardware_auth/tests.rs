use super::*;
use crate::error::Error;
use crate::keys::{self, KeyType};
use crate::provider::policy::{
    issue_policy, verify_policy, CorporateNetwork, HardwareAuthorityEntry, NetworkMode, NewPolicy,
    PERM_API_ROOT_GENERATE,
};
use crate::provider::{generate_relay_identity, CAP_PROVIDER};

fn policy_with(
    root_sk: &[u8; 32],
    root_pk: &[u8; 32],
    relay_pk: &[u8; 32],
    hardware: &[HardwareAuthorityEntry],
) -> ProviderPolicy {
    let bytes = issue_policy(
        root_sk,
        &NewPolicy {
            provider_id: "Acme Security Services",
            policy_id: "KQP-POL-1",
            relay_public_key: relay_pk,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-09-02 00:00:00",
            capabilities: CAP_PROVIDER,
            hardware_threshold: 1,
            hardware,
            networks: &[CorporateNetwork {
                network_id: "corp-vpn".into(),
                mode: NetworkMode::Vpn,
                cidrs: vec!["10.8.0.0/24".into()],
                ssid: None,
                bssid_mac: None,
                gateway_mac: None,
                verifier_public_key: None,
            }],
            permissions: &[PERM_API_ROOT_GENERATE.to_string()],
        },
    )
    .expect("issue");
    verify_policy(root_pk, &bytes, "2026-09-02 12:00:00").expect("verify")
}

fn challenge<'a>(
    provider_id: &'a str,
    relay_id: &'a [u8; 32],
    nonce: &'a [u8; 32],
) -> ProviderChallenge<'a> {
    ProviderChallenge {
        provider_id,
        relay_id,
        network_policy_id: "corp-vpn",
        timestamp: "2026-09-02 12:00:00",
        nonce,
        required_authority: HardwareAuthority::ProviderApiRoot,
    }
}

#[test]
fn authorized_signing_key_proves_possession() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let fp = keys::fingerprint(&hw_pk);
    let policy = policy_with(
        &root_sk,
        &root_pk,
        &relay_pk,
        &[HardwareAuthorityEntry {
            fingerprint: fp.clone(),
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderApiRoot,
            revoked: false,
        }],
    );
    let nonce = [7u8; 32];
    let ch = challenge("Acme Security Services", &relay_pk, &nonce);
    let signature = sign_provider_hardware(&hw_sk, &ch).expect("sign");
    let authorized = verify_provider_hardware(&policy, &ch, &hw_pk, &signature).expect("ok");
    assert_eq!(authorized.fingerprint, fp);
    assert_eq!(authorized.authority, HardwareAuthority::ProviderApiRoot);
}

#[test]
fn customer_signing_key_is_rejected() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let (provider_sk, provider_pk) = keys::generate_signing_keypair();
    let (customer_sk, customer_pk) = keys::generate_signing_keypair();
    let policy = policy_with(
        &root_sk,
        &root_pk,
        &relay_pk,
        &[HardwareAuthorityEntry {
            fingerprint: keys::fingerprint(&provider_pk),
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderApiRoot,
            revoked: false,
        }],
    );
    let nonce = [3u8; 32];
    let ch = challenge("Acme Security Services", &relay_pk, &nonce);
    let signature = sign_provider_hardware(&customer_sk, &ch).expect("sign");
    assert!(matches!(
        verify_provider_hardware(&policy, &ch, &customer_pk, &signature),
        Err(Error::ProviderHardwareDenied)
    ));
    let _ = provider_sk;
}

#[test]
fn wrong_signature_is_rejected() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let (other_sk, _) = keys::generate_signing_keypair();
    let policy = policy_with(
        &root_sk,
        &root_pk,
        &relay_pk,
        &[HardwareAuthorityEntry {
            fingerprint: keys::fingerprint(&hw_pk),
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderApiRoot,
            revoked: false,
        }],
    );
    let nonce = [9u8; 32];
    let ch = challenge("Acme Security Services", &relay_pk, &nonce);
    let signature = sign_provider_hardware(&other_sk, &ch).expect("sign");
    assert!(matches!(
        verify_provider_hardware(&policy, &ch, &hw_pk, &signature),
        Err(Error::ProviderHardwareDenied)
    ));
    let _ = hw_sk;
}

#[test]
fn revoked_provider_hardware_is_rejected() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let policy = policy_with(
        &root_sk,
        &root_pk,
        &relay_pk,
        &[HardwareAuthorityEntry {
            fingerprint: keys::fingerprint(&hw_pk),
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderApiRoot,
            revoked: true,
        }],
    );
    let nonce = [1u8; 32];
    let ch = challenge("Acme Security Services", &relay_pk, &nonce);
    let signature = sign_provider_hardware(&hw_sk, &ch).expect("sign");
    assert!(matches!(
        verify_provider_hardware(&policy, &ch, &hw_pk, &signature),
        Err(Error::ProviderHardwareRevoked)
    ));
}

#[test]
fn relay_admin_role_cannot_mint_api_root() {
    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let policy = policy_with(
        &root_sk,
        &root_pk,
        &relay_pk,
        &[HardwareAuthorityEntry {
            fingerprint: keys::fingerprint(&hw_pk),
            key_type: KeyType::Signing,
            authority: HardwareAuthority::ProviderRelayAdmin,
            revoked: false,
        }],
    );
    let nonce = [4u8; 32];
    let ch = challenge("Acme Security Services", &relay_pk, &nonce);
    let signature = sign_provider_hardware(&hw_sk, &ch).expect("sign");
    assert!(matches!(
        verify_provider_hardware(&policy, &ch, &hw_pk, &signature),
        Err(Error::ProviderHardwareDenied)
    ));
}

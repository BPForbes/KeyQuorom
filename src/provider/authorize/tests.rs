use super::*;
use crate::error::Error;
use crate::keys::{self, KeyType};
use crate::provider::hardware_auth::{self, HardwareAuthority, ProviderChallenge};
use crate::provider::policy::{
    issue_policy, CorporateNetwork, HardwareAuthorityEntry, NetworkMode, NewPolicy,
    PERM_API_ROOT_GENERATE,
};
use crate::provider::root_network::LocalAddress;
use crate::provider::{issue_certificate, NewCertificate, CAP_PROVIDER};
use crate::relay;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

fn empty_revoked() -> &'static HashSet<String> {
    static EMPTY: OnceLock<HashSet<String>> = OnceLock::new();
    EMPTY.get_or_init(HashSet::new)
}

fn tunnel(addr: &str) -> LocalAddress {
    LocalAddress {
        iface: "wg0".into(),
        addr: addr.parse::<IpAddr>().unwrap(),
        is_tunnel: true,
    }
}

fn lan(addr: &str) -> LocalAddress {
    LocalAddress {
        iface: "eth0".into(),
        addr: addr.parse::<IpAddr>().unwrap(),
        is_tunnel: false,
    }
}

struct Fixture {
    root_public: [u8; 32],
    certificate: Vec<u8>,
    relay_private: zeroize::Zeroizing<[u8; 32]>,
    relay_public: [u8; 32],
    policy: Vec<u8>,
    hardware_private: zeroize::Zeroizing<[u8; 32]>,
    hardware_public: [u8; 32],
}

fn fixture(networks: &[CorporateNetwork], hardware: &[HardwareAuthorityEntry]) -> Fixture {
    let (root_sk, _) = keys::generate_signing_keypair();
    let (relay_private, relay_public) = crate::provider::generate_relay_identity();
    let certificate = issue_certificate(
        &root_sk,
        &NewCertificate {
            provider_id: "Acme Security Services",
            serial: "KQP-000184",
            relay_public_key: &relay_public,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-09-02 00:00:00",
            capabilities: CAP_PROVIDER,
            issuer_id: "KeyQuorumRoot",
        },
    )
    .expect("cert");
    let policy = issue_policy(
        &root_sk,
        &NewPolicy {
            provider_id: "Acme Security Services",
            policy_id: "KQP-POL-1",
            relay_public_key: &relay_public,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-09-02 00:00:00",
            capabilities: CAP_PROVIDER,
            hardware_threshold: 1,
            hardware,
            networks,
            permissions: &[PERM_API_ROOT_GENERATE.to_string()],
        },
    )
    .expect("policy");
    let (hardware_private, hardware_public) = keys::generate_signing_keypair();
    Fixture {
        root_public: {
            let verifying = ed25519_dalek::SigningKey::from_bytes(&root_sk).verifying_key();
            verifying.to_bytes()
        },
        certificate,
        relay_private,
        relay_public,
        policy,
        hardware_private,
        hardware_public,
    }
}

fn vpn(id: &str, cidr: &str) -> CorporateNetwork {
    CorporateNetwork {
        network_id: id.into(),
        mode: NetworkMode::Vpn,
        cidrs: vec![cidr.into()],
        ssid: None,
        bssid_mac: None,
        gateway_mac: None,
        verifier_public_key: None,
    }
}

fn provider_hw(fp: &str) -> HardwareAuthorityEntry {
    HardwareAuthorityEntry {
        fingerprint: fp.to_string(),
        key_type: KeyType::Signing,
        authority: HardwareAuthority::ProviderApiRoot,
        revoked: false,
    }
}

fn sign_for(fix: &Fixture, network_id: &str) -> ([u8; 64], [u8; 32]) {
    let nonce = [11u8; 32];
    let challenge = ProviderChallenge {
        provider_id: "Acme Security Services",
        relay_id: &fix.relay_public,
        network_policy_id: network_id,
        timestamp: "2026-09-02 12:00:00",
        nonce: &nonce,
        required_authority: HardwareAuthority::ProviderApiRoot,
    };
    let signature =
        hardware_auth::sign_provider_hardware(&fix.hardware_private, &challenge).expect("sign");
    (signature, nonce)
}

fn request<'a>(
    fix: &'a Fixture,
    network_id: &'a str,
    addrs: &'a [LocalAddress],
    caller_networks: &'a [String],
    signature: &'a [u8; 64],
    nonce: &'a [u8; 32],
    hardware_public: &'a [u8; 32],
) -> ApiRootRequest<'a> {
    ApiRootRequest {
        root_public_key: &fix.root_public,
        certificate: &fix.certificate,
        relay_private_key: &fix.relay_private,
        policy: &fix.policy,
        now_utc: "2026-09-02 12:00:00",
        revoked: empty_revoked(),
        network_id,
        local_addrs: addrs,
        caller_networks,
        hardware_public_key: hardware_public,
        hardware_signature: signature,
        timestamp: "2026-09-02 12:00:00",
        nonce,
    }
}

fn authorized_fixture() -> Fixture {
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let entry = provider_hw(&keys::fingerprint(&hw_pk));
    let mut fix = fixture(&[vpn("corp-vpn", "10.8.0.0/24")], &[entry]);
    fix.hardware_private = hw_sk;
    fix.hardware_public = hw_pk;
    fix
}

#[test]
fn missing_certificate_cannot_authorize() {
    let fix = authorized_fixture();
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [tunnel("10.8.0.2")];
    let mut req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    let empty = Vec::new();
    req.certificate = &empty;
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::InvalidProviderCertificate)
    ));
}

#[test]
fn valid_certificate_with_wrong_relay_key_is_rejected() {
    let mut fix = authorized_fixture();
    let (other, _) = crate::provider::generate_relay_identity();
    fix.relay_private = other;
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [tunnel("10.8.0.2")];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::RelayIdentityMismatch)
    ));
}

#[test]
fn identity_outside_corporate_networks_is_rejected() {
    let fix = authorized_fixture();
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [tunnel("192.168.1.9")];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::RootNetworkRequired)
    ));
}

#[test]
fn caller_supplied_cidr_is_not_production_authority() {
    let fix = authorized_fixture();
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [tunnel("10.8.0.2")];
    let caller = ["10.8.0.0/24".to_string()];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &caller,
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::CallerNetworkNotAuthoritative)
    ));
    assert!(matches!(
        crate::provider::root_network::authorize_corporate_network(
            crate::provider::root_network::NetworkAuthority::CallerCidr(
                crate::provider::root_network::parse_network_list("10.8.0.0/24").unwrap(),
            ),
            &addrs,
        ),
        Err(Error::CallerNetworkNotAuthoritative)
    ));
}

#[test]
fn matching_cidr_on_non_tunnel_is_rejected() {
    let fix = authorized_fixture();
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [lan("10.8.0.2")];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::RootNetworkRequired)
    ));
}

#[test]
fn customer_signing_key_is_rejected_even_on_approved_tunnel() {
    let fix = authorized_fixture();
    let (customer_sk, customer_pk) = keys::generate_signing_keypair();
    let nonce = [11u8; 32];
    let challenge = ProviderChallenge {
        provider_id: "Acme Security Services",
        relay_id: &fix.relay_public,
        network_policy_id: "corp-vpn",
        timestamp: "2026-09-02 12:00:00",
        nonce: &nonce,
        required_authority: HardwareAuthority::ProviderApiRoot,
    };
    let signature = hardware_auth::sign_provider_hardware(&customer_sk, &challenge).expect("sign");
    let addrs = [tunnel("10.8.0.2")];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &customer_pk,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::ProviderHardwareDenied)
    ));
}

#[test]
fn wrong_hardware_signature_is_rejected() {
    let fix = authorized_fixture();
    let (other_sk, _) = keys::generate_signing_keypair();
    let nonce = [11u8; 32];
    let challenge = ProviderChallenge {
        provider_id: "Acme Security Services",
        relay_id: &fix.relay_public,
        network_policy_id: "corp-vpn",
        timestamp: "2026-09-02 12:00:00",
        nonce: &nonce,
        required_authority: HardwareAuthority::ProviderApiRoot,
    };
    let signature = hardware_auth::sign_provider_hardware(&other_sk, &challenge).expect("sign");
    let addrs = [tunnel("10.8.0.2")];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::ProviderHardwareDenied)
    ));
}

#[test]
fn revoked_provider_hardware_is_rejected() {
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let mut revoked = provider_hw(&keys::fingerprint(&hw_pk));
    revoked.revoked = true;
    let mut fix = fixture(&[vpn("corp-vpn", "10.8.0.0/24")], &[revoked]);
    fix.hardware_private = hw_sk;
    fix.hardware_public = hw_pk;
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [tunnel("10.8.0.2")];
    let req = request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    );
    assert!(matches!(
        authorize_api_root_generation(&req),
        Err(Error::ProviderHardwareRevoked)
    ));
}

#[test]
fn approved_hardware_on_signed_corporate_network_succeeds() {
    let fix = authorized_fixture();
    let (signature, nonce) = sign_for(&fix, "corp-vpn");
    let addrs = [tunnel("10.8.0.2")];
    let authorized = authorize_api_root_generation(&request(
        &fix,
        "corp-vpn",
        &addrs,
        &[],
        &signature,
        &nonce,
        &fix.hardware_public,
    ))
    .expect("authorized");
    assert_eq!(authorized.network_id, "corp-vpn");
    assert_eq!(
        authorized.hardware_fingerprint,
        keys::fingerprint(&fix.hardware_public)
    );
}

#[test]
fn api_root_cannot_be_generated_twice() {
    let conn = relay::open_in_memory().expect("schema");
    let first = relay::create_licensee_issuer_if_empty(&conn).expect("first");
    assert!(first.token.starts_with("kql_"));
    assert!(matches!(
        relay::create_licensee_issuer_if_empty(&conn),
        Err(Error::ApiRootAlreadyExists)
    ));
}

#[test]
fn sqlite_insert_cannot_bypass_signed_policy() {
    let fix = authorized_fixture();
    let conn = relay::open_in_memory().expect("schema");
    conn.execute(
        "INSERT INTO provider_auth_events
         (operation, provider_id, network_id, hardware_fingerprints, success)
         VALUES ('api-root.generate', 'forged', 'forged-vpn', 'deadbeef', 1)",
        [],
    )
    .expect("insert");
    let (customer_sk, customer_pk) = keys::generate_signing_keypair();
    let nonce = [11u8; 32];
    let challenge = ProviderChallenge {
        provider_id: "Acme Security Services",
        relay_id: &fix.relay_public,
        network_policy_id: "corp-vpn",
        timestamp: "2026-09-02 12:00:00",
        nonce: &nonce,
        required_authority: HardwareAuthority::ProviderApiRoot,
    };
    let signature = hardware_auth::sign_provider_hardware(&customer_sk, &challenge).expect("sign");
    let addrs = [tunnel("10.8.0.2")];
    assert!(matches!(
        authorize_api_root_generation(&request(
            &fix,
            "corp-vpn",
            &addrs,
            &[],
            &signature,
            &nonce,
            &customer_pk,
        )),
        Err(Error::ProviderHardwareDenied)
    ));
}

#[test]
fn multiple_corporate_networks_are_or_while_hardware_stays_mandatory() {
    let (hw_sk, hw_pk) = keys::generate_signing_keypair();
    let entry = provider_hw(&keys::fingerprint(&hw_pk));
    let mut fix = fixture(
        &[
            vpn("corp-vpn", "10.8.0.0/24"),
            vpn("lab-vpn", "10.9.0.0/24"),
        ],
        &[entry],
    );
    fix.hardware_private = hw_sk;
    fix.hardware_public = hw_pk;

    let (sig_lab, nonce_lab) = sign_for(&fix, "lab-vpn");
    let lab = [tunnel("10.9.0.4")];
    authorize_api_root_generation(&request(
        &fix,
        "lab-vpn",
        &lab,
        &[],
        &sig_lab,
        &nonce_lab,
        &fix.hardware_public,
    ))
    .expect("lab network");

    let (sig_corp, nonce_corp) = sign_for(&fix, "corp-vpn");
    let corp = [tunnel("10.8.0.2")];
    authorize_api_root_generation(&request(
        &fix,
        "corp-vpn",
        &corp,
        &[],
        &sig_corp,
        &nonce_corp,
        &fix.hardware_public,
    ))
    .expect("corp network");

    let (customer_sk, customer_pk) = keys::generate_signing_keypair();
    let challenge = ProviderChallenge {
        provider_id: "Acme Security Services",
        relay_id: &fix.relay_public,
        network_policy_id: "lab-vpn",
        timestamp: "2026-09-02 12:00:00",
        nonce: &nonce_lab,
        required_authority: HardwareAuthority::ProviderApiRoot,
    };
    let bad_sig = hardware_auth::sign_provider_hardware(&customer_sk, &challenge).expect("sign");
    assert!(matches!(
        authorize_api_root_generation(&request(
            &fix,
            "lab-vpn",
            &lab,
            &[],
            &bad_sig,
            &nonce_lab,
            &customer_pk,
        )),
        Err(Error::ProviderHardwareDenied)
    ));
}

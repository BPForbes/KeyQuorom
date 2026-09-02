use super::*;
use crate::error::Error;
use std::net::IpAddr;

#[test]
fn parse_ipv4_and_ipv6_cidrs() {
    let v4 = parse_network("10.8.0.0/24").unwrap();
    assert!(v4.contains("10.8.0.12".parse().unwrap()));
    assert!(!v4.contains("10.9.0.1".parse().unwrap()));
    let bare = parse_network("192.0.2.1").unwrap();
    assert!(bare.contains("192.0.2.1".parse().unwrap()));
    assert!(!bare.contains("192.0.2.2".parse().unwrap()));
    let v6 = parse_network("fd7a:115c:a1e0::/48").unwrap();
    assert!(v6.contains("fd7a:115c:a1e0:a:0:0:0:1".parse().unwrap()));
    assert!(!v6.contains("fd7b::1".parse().unwrap()));
    assert!(matches!(
        parse_network("not-a-cidr"),
        Err(Error::InvalidRootNetwork)
    ));
    assert!(matches!(
        parse_network_list(""),
        Err(Error::RootNetworkRequired)
    ));
}

#[test]
fn tunnel_names_and_arphrd() {
    assert!(is_tunnel_name("wg0"));
    assert!(is_tunnel_name("tun0"));
    assert!(is_tunnel_name("tailscale0"));
    assert!(is_tunnel_name("utun3"));
    assert!(!is_tunnel_name("eth0"));
    assert!(!is_tunnel_name("wlan0"));
    assert!(!is_tunnel_name("docker0"));
    assert!(is_tunnel_arphrd(65534));
    assert!(is_tunnel_arphrd(768));
    assert!(!is_tunnel_arphrd(1));
}

#[test]
fn only_tunnel_addresses_in_the_cidr_authorize() {
    let nets = parse_network_list("10.8.0.0/24").unwrap();
    let ok = [LocalAddress {
        iface: "wg0".into(),
        addr: "10.8.0.2".parse::<IpAddr>().unwrap(),
        is_tunnel: true,
    }];
    assert!(authorized_on_tunnel(&nets, &ok));
    let lan = [LocalAddress {
        iface: "eth0".into(),
        addr: "10.8.0.2".parse::<IpAddr>().unwrap(),
        is_tunnel: false,
    }];
    assert!(!authorized_on_tunnel(&nets, &lan));
    let other = [LocalAddress {
        iface: "wg0".into(),
        addr: "192.168.1.9".parse::<IpAddr>().unwrap(),
        is_tunnel: true,
    }];
    assert!(!authorized_on_tunnel(&nets, &other));
    assert!(!authorized_on_tunnel(&[], &ok));
}

#[test]
fn signed_vpn_entry_requires_tunnel_and_rejects_caller_cidrs() {
    use crate::keys::{self, KeyType};
    use crate::provider::hardware_auth::HardwareAuthority;
    use crate::provider::policy::{
        issue_policy, verify_policy, CorporateNetwork, HardwareAuthorityEntry, NetworkMode,
        NewPolicy, PERM_API_ROOT_GENERATE,
    };
    use crate::provider::{generate_relay_identity, CAP_PROVIDER};

    let (root_sk, root_pk) = keys::generate_signing_keypair();
    let (_, relay_pk) = generate_relay_identity();
    let bytes = issue_policy(
        &root_sk,
        &NewPolicy {
            provider_id: "Acme",
            policy_id: "p1",
            relay_public_key: &relay_pk,
            issued_at: "2026-01-01 00:00:00",
            expires_at: "2027-01-01 00:00:00",
            capabilities: CAP_PROVIDER,
            hardware_threshold: 1,
            hardware: &[HardwareAuthorityEntry {
                fingerprint: keys::fingerprint(&relay_pk),
                key_type: KeyType::Signing,
                authority: HardwareAuthority::ProviderApiRoot,
                revoked: false,
            }],
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
    .unwrap();
    let policy = verify_policy(&root_pk, &bytes, "2026-09-02 12:00:00").unwrap();
    let ok = [LocalAddress {
        iface: "wg0".into(),
        addr: "10.8.0.2".parse::<IpAddr>().unwrap(),
        is_tunnel: true,
    }];
    authorize_corporate_network(
        NetworkAuthority::Signed {
            policy: &policy,
            network_id: "corp-vpn",
        },
        &ok,
    )
    .unwrap();
    let lan = [LocalAddress {
        iface: "eth0".into(),
        addr: "10.8.0.2".parse::<IpAddr>().unwrap(),
        is_tunnel: false,
    }];
    assert!(matches!(
        authorize_corporate_network(
            NetworkAuthority::Signed {
                policy: &policy,
                network_id: "corp-vpn",
            },
            &lan,
        ),
        Err(Error::RootNetworkRequired)
    ));
    assert!(matches!(
        authorize_corporate_network(
            NetworkAuthority::CallerCidr(parse_network_list("10.8.0.0/24").unwrap()),
            &ok,
        ),
        Err(Error::CallerNetworkNotAuthoritative)
    ));
}

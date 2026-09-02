use super::*;
use crate::error::Error;
use crate::provider::policy::{CorporateNetwork, NetworkMode};
use crate::provider::root_network::LocalAddress;
use std::net::IpAddr;

fn wifi_net(ssid: &str, bssid: Option<&str>, cidrs: &[&str]) -> CorporateNetwork {
    CorporateNetwork {
        network_id: "corp-wifi".into(),
        mode: NetworkMode::Wifi,
        cidrs: cidrs.iter().map(|s| (*s).to_string()).collect(),
        ssid: Some(ssid.into()),
        bssid_mac: bssid.map(str::to_string),
        gateway_mac: None,
        verifier_public_key: None,
    }
}

fn link(ssid: &str, bssid: Option<&str>) -> WifiLink {
    WifiLink {
        iface: "wlan0".into(),
        ssid: ssid.into(),
        bssid: bssid.map(str::to_string),
    }
}

fn wifi_addr(ip: &str) -> LocalAddress {
    LocalAddress {
        iface: "wlan0".into(),
        addr: ip.parse::<IpAddr>().unwrap(),
        is_tunnel: false,
        is_wifi: true,
    }
}

#[test]
fn ssid_match_does_not_require_a_fixed_ip() {
    let network = wifi_net("Office", None, &[]);
    let links = [link("Office", Some("aa:bb:cc:dd:ee:ff"))];
    let addrs = [wifi_addr("192.168.47.19")];
    assert!(wifi_authorized(&network, &links, &addrs).unwrap());
    let other_ip = [wifi_addr("10.1.2.3")];
    assert!(wifi_authorized(&network, &links, &other_ip).unwrap());
}

#[test]
fn optional_cidr_accepts_any_address_in_the_subnet() {
    let network = wifi_net("Office", None, &["192.168.10.0/24"]);
    let links = [link("Office", None)];
    assert!(wifi_authorized(&network, &links, &[wifi_addr("192.168.10.80")]).unwrap());
    assert!(!wifi_authorized(&network, &links, &[wifi_addr("10.8.0.2")]).unwrap());
}

#[test]
fn wrong_ssid_or_bssid_is_rejected() {
    let network = wifi_net("Office", Some("aa:bb:cc:dd:ee:ff"), &[]);
    assert!(!wifi_authorized(&network, &[link("Guest", Some("aa:bb:cc:dd:ee:ff"))], &[]).unwrap());
    assert!(!wifi_authorized(&network, &[link("Office", Some("11:22:33:44:55:66"))], &[]).unwrap());
}

#[test]
fn bssid_normalizes_separators() {
    assert_eq!(
        normalize_bssid("AA-BB-CC-DD-EE-FF").unwrap(),
        "aa:bb:cc:dd:ee:ff"
    );
    assert!(matches!(
        normalize_bssid("not-a-mac"),
        Err(Error::InvalidProviderPolicy)
    ));
}

#[test]
fn ceremony_ssid_list_matches_association() {
    let links = [link("Office", None)];
    assert!(associated_with_any_ssid(&["Office".into()], &links));
    assert!(!associated_with_any_ssid(&["Other".into()], &links));
}

//! Local VPN/tunnel presence check.
//!
//! This is a presence gate, not a cryptographic root of trust. Official
//! clients still verify `provider.kqcert` against the compiled-in public
//! key. Production API-root minting matches a provider-root-signed
//! Corporate Network; caller `--network` CIDRs are not that authority.

use crate::error::{Error, Result};
use crate::provider::policy::{CorporateNetwork, NetworkMode, ProviderPolicy};
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// IPv4 or IPv6 CIDR that identifies the seller VPN pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    V4 { addr: u32, prefix: u8 },
    V6 { addr: u128, prefix: u8 },
}

/// One local interface address, plus whether that interface looks like a tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAddress {
    pub iface: String,
    pub addr: IpAddr,
    pub is_tunnel: bool,
    pub is_wifi: bool,
}

pub fn parse_network(spec: &str) -> Result<Network> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(Error::InvalidRootNetwork);
    }
    let (addr_text, prefix_text) = match spec.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (spec, None),
    };
    if addr_text.contains(':') {
        let addr: Ipv6Addr = addr_text.parse().map_err(|_| Error::InvalidRootNetwork)?;
        let prefix = match prefix_text {
            Some(p) => p.parse::<u8>().map_err(|_| Error::InvalidRootNetwork)?,
            None => 128,
        };
        if prefix > 128 {
            return Err(Error::InvalidRootNetwork);
        }
        Ok(Network::V6 {
            addr: u128::from(addr),
            prefix,
        })
    } else {
        let addr: Ipv4Addr = addr_text.parse().map_err(|_| Error::InvalidRootNetwork)?;
        let prefix = match prefix_text {
            Some(p) => p.parse::<u8>().map_err(|_| Error::InvalidRootNetwork)?,
            None => 32,
        };
        if prefix > 32 {
            return Err(Error::InvalidRootNetwork);
        }
        Ok(Network::V4 {
            addr: u32::from(addr),
            prefix,
        })
    }
}

pub fn parse_network_list(spec: &str) -> Result<Vec<Network>> {
    let mut out = Vec::new();
    for part in spec.split([',', ' ', '\n']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(parse_network(part)?);
    }
    if out.is_empty() {
        Err(Error::RootNetworkRequired)
    } else {
        Ok(out)
    }
}

/// `--network` flags win; otherwise `KEYQUORUM_ROOT_NETWORKS`.
pub fn networks_from_cli_or_env(cli: &[String]) -> Result<Vec<Network>> {
    let mut parts = Vec::new();
    for item in cli {
        parts.extend(
            item.split([',', ' ', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    if parts.is_empty() {
        if let Ok(env) = std::env::var("KEYQUORUM_ROOT_NETWORKS") {
            parts.extend(
                env.split([',', ' ', '\n'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    if parts.is_empty() {
        return Err(Error::RootNetworkRequired);
    }
    parts.iter().map(|s| parse_network(s)).collect()
}

impl Network {
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { addr, prefix }, IpAddr::V4(v)) => {
                let host = u32::from(v);
                let mask = ipv4_mask(prefix);
                (host & mask) == (addr & mask)
            }
            (Self::V6 { addr, prefix }, IpAddr::V6(v)) => {
                let host = u128::from(v);
                let mask = ipv6_mask(prefix);
                (host & mask) == (addr & mask)
            }
            _ => false,
        }
    }
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - u32::from(prefix))
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        !0u128 << (128 - u32::from(prefix))
    }
}

pub fn is_tunnel_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "tun",
        "tap",
        "wg",
        "utun",
        "tailscale",
        "ts-",
        "proton",
        "nordlynx",
        "ppp",
        "sit",
        "gre",
        "ipsec",
        "zt",
        "oc",
        "cscotun",
        "gpd",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Linux `ARPHRD_*` values used by tun, WireGuard, GRE, SIT, PPP.
pub fn is_tunnel_arphrd(kind: u32) -> bool {
    matches!(kind, 256 | 512 | 768 | 769 | 776 | 778 | 823 | 65534)
}

pub fn authorized_on_tunnel(networks: &[Network], addrs: &[LocalAddress]) -> bool {
    if networks.is_empty() {
        return false;
    }
    addrs
        .iter()
        .any(|addr| addr.is_tunnel && networks.iter().any(|network| network.contains(addr.addr)))
}

pub fn require_authorized_tunnel(networks: &[Network]) -> Result<()> {
    if !authorized_on_tunnel(networks, &list_local_addresses()?) {
        return Err(Error::RootNetworkRequired);
    }
    Ok(())
}

/// Production API-root minting selects a signed Corporate Network.
/// Caller CIDRs remain a ceremony/dev path for `host root generate` only.
pub enum NetworkAuthority<'a> {
    Signed {
        policy: &'a ProviderPolicy,
        network_id: &'a str,
    },
    CallerCidr(Vec<Network>),
}

pub fn authorize_corporate_network(
    authority: NetworkAuthority<'_>,
    addrs: &[LocalAddress],
    wifi: &[crate::provider::network::WifiLink],
) -> Result<()> {
    match authority {
        NetworkAuthority::CallerCidr(_) => Err(Error::CallerNetworkNotAuthoritative),
        NetworkAuthority::Signed { policy, network_id } => {
            require_signed_network_presence(policy.corporate_network(network_id)?, addrs, wifi)
        }
    }
}

pub fn require_signed_network_presence(
    network: &CorporateNetwork,
    addrs: &[LocalAddress],
    wifi: &[crate::provider::network::WifiLink],
) -> Result<()> {
    match network.mode {
        NetworkMode::Vpn => {
            let parsed = network
                .cidrs
                .iter()
                .map(|cidr| parse_network(cidr))
                .collect::<Result<Vec<_>>>()?;
            if parsed.is_empty() || !authorized_on_tunnel(&parsed, addrs) {
                return Err(Error::RootNetworkRequired);
            }
            Ok(())
        }
        NetworkMode::Wifi => {
            if crate::provider::network::wifi_authorized(network, wifi, addrs)? {
                Ok(())
            } else {
                Err(Error::RootNetworkRequired)
            }
        }
        NetworkMode::Ethernet => Err(Error::ProviderNetworkModeUnsupported),
    }
}

/// Ceremony gate for `host root generate`. Caller CIDRs or SSIDs are a
/// presence check only — they are not production API-root authority.
pub fn require_root_ceremony(networks: &[Network], ssids: &[String]) -> Result<()> {
    if networks.is_empty() && ssids.is_empty() {
        return Err(Error::RootNetworkRequired);
    }
    if !networks.is_empty() && authorized_on_tunnel(networks, &list_local_addresses()?) {
        return Ok(());
    }
    if !ssids.is_empty()
        && crate::provider::network::associated_with_any_ssid(
            ssids,
            &crate::provider::network::list_wifi_links()?,
        )
    {
        return Ok(());
    }
    Err(Error::RootNetworkRequired)
}

pub fn optional_networks_from_cli_or_env(cli: &[String]) -> Result<Vec<Network>> {
    match networks_from_cli_or_env(cli) {
        Ok(networks) => Ok(networks),
        Err(Error::RootNetworkRequired) => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

pub fn list_local_addresses() -> Result<Vec<LocalAddress>> {
    unsafe { list_local_addresses_getifaddrs() }
}

unsafe fn list_local_addresses_getifaddrs() -> Result<Vec<LocalAddress>> {
    let mut raw: *mut libc::ifaddrs = std::ptr::null_mut();
    if libc::getifaddrs(&mut raw) != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let mut out = Vec::new();
    let mut cur = raw;
    while !cur.is_null() {
        let iface = &*cur;
        let loopback = iface.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint != 0;
        if !loopback {
            if let Some(addr) = sockaddr_to_ip(iface.ifa_addr) {
                let name = CStr::from_ptr(iface.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let is_tunnel = is_tunnel_name(&name) || sysfs_is_tunnel(&name);
                let is_wifi = crate::provider::network::is_wifi_name(&name)
                    || crate::provider::network::sysfs_is_wifi(&name);
                out.push(LocalAddress {
                    iface: name,
                    addr,
                    is_tunnel,
                    is_wifi,
                });
            }
        }
        cur = iface.ifa_next;
    }
    libc::freeifaddrs(raw);
    Ok(out)
}

fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family as i32 };
    match family {
        libc::AF_INET => {
            let sin = unsafe { &*(addr as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn sysfs_is_tunnel(name: &str) -> bool {
    let path = Path::new("/sys/class/net").join(name).join("type");
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    text.trim().parse::<u32>().is_ok_and(is_tunnel_arphrd)
}

#[cfg(test)]
#[path = "root_network/tests.rs"]
mod tests;

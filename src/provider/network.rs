//! Live Corporate Network detection (Wi-Fi and related adapters).
//!
//! SSIDs, BSSIDs, and subnets are never compiled in. Production values
//! live in a provider-root-signed policy. A DHCP address may change;
//! matching is by SSID (and optional BSSID / optional CIDR).

use crate::error::{Error, Result};
use crate::provider::policy::{CorporateNetwork, NetworkMode};
use crate::provider::root_network::{self, LocalAddress, Network};

#[cfg(target_os = "linux")]
mod linux;

/// One associated Wi-Fi link. `ssid` is the advertised network name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiLink {
    pub iface: String,
    pub ssid: String,
    pub bssid: Option<String>,
}

pub fn is_wifi_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("wlan")
        || name.starts_with("wlp")
        || name.starts_with("wlx")
        || name.starts_with("wifi")
}

pub fn sysfs_is_wifi(name: &str) -> bool {
    let base = std::path::Path::new("/sys/class/net").join(name);
    base.join("wireless").exists() || base.join("phy80211").exists()
}

pub fn normalize_bssid(value: &str) -> Result<String> {
    let hex: String = value
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|b| (b as char).to_ascii_lowercase())
        .collect();
    if hex.len() != 12 {
        return Err(Error::InvalidProviderPolicy);
    }
    Ok(hex
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or("00"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// `--ssid` flags win; otherwise `KEYQUORUM_ROOT_SSIDS`.
pub fn ssids_from_cli_or_env(cli: &[String]) -> Vec<String> {
    let mut parts = Vec::new();
    for item in cli {
        parts.extend(
            item.split([',', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    if parts.is_empty() {
        if let Ok(env) = std::env::var("KEYQUORUM_ROOT_SSIDS") {
            parts.extend(
                env.split([',', '\n'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    parts
}

pub fn associated_with_any_ssid(ssids: &[String], links: &[WifiLink]) -> bool {
    ssids.iter().any(|want| {
        links
            .iter()
            .any(|link| !link.ssid.is_empty() && link.ssid == *want)
    })
}

pub fn wifi_authorized(
    network: &CorporateNetwork,
    links: &[WifiLink],
    addrs: &[LocalAddress],
) -> Result<bool> {
    if network.mode != NetworkMode::Wifi {
        return Ok(false);
    }
    let Some(ssid) = network.ssid.as_deref().filter(|s| !s.is_empty()) else {
        return Err(Error::InvalidProviderPolicy);
    };
    let want_bssid = match network.bssid_mac.as_deref() {
        Some(raw) if !raw.is_empty() => Some(normalize_bssid(raw)?),
        _ => None,
    };
    let cidrs = network
        .cidrs
        .iter()
        .map(|cidr| root_network::parse_network(cidr))
        .collect::<Result<Vec<Network>>>()?;
    Ok(links.iter().any(|link| {
        if link.ssid != ssid {
            return false;
        }
        if let Some(want) = want_bssid.as_deref() {
            match link
                .bssid
                .as_deref()
                .and_then(|have| normalize_bssid(have).ok())
            {
                Some(have) if have == want => {}
                _ => return false,
            }
        }
        if cidrs.is_empty() {
            return true;
        }
        addrs.iter().any(|addr| {
            addr.is_wifi
                && addr.iface == link.iface
                && cidrs.iter().any(|cidr| cidr.contains(addr.addr))
        })
    }))
}

pub fn list_wifi_links() -> Result<Vec<WifiLink>> {
    #[cfg(target_os = "linux")]
    {
        linux::list_wifi_links()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}

#[cfg(test)]
#[path = "network/tests.rs"]
mod tests;

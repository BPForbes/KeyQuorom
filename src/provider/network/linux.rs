//! Linux Wi-Fi association via Wireless Extensions ioctl.

use super::WifiLink;
use crate::error::Result;
use std::fs;

const SIOCGIWESSID: libc::c_ulong = 0x8B1B;
const SIOCGIWAP: libc::c_ulong = 0x8B15;
const IW_ESSID_MAX_SIZE: usize = 32;

#[repr(C)]
struct IwPoint {
    pointer: *mut u8,
    length: u16,
    flags: u16,
}

#[repr(C)]
union IwReqData {
    essid: std::mem::ManuallyDrop<IwPoint>,
    ap_addr: libc::sockaddr,
}

#[repr(C)]
struct IwReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    u: IwReqData,
}

pub fn list_wifi_links() -> Result<Vec<WifiLink>> {
    let mut out = Vec::new();
    for iface in wifi_interface_names() {
        if let Some(link) = read_link(&iface) {
            out.push(link);
        }
    }
    Ok(out)
}

fn wifi_interface_names() -> Vec<String> {
    let mut names = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return names;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if super::is_wifi_name(&name) || super::sysfs_is_wifi(&name) {
            names.push(name);
        }
    }
    names
}

fn read_link(iface: &str) -> Option<WifiLink> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return None;
    }
    let ssid = unsafe { read_essid(sock, iface) };
    let bssid = unsafe { read_bssid(sock, iface) };
    unsafe {
        libc::close(sock);
    }
    let ssid = ssid.filter(|s| !s.is_empty())?;
    Some(WifiLink {
        iface: iface.to_string(),
        ssid,
        bssid,
    })
}

fn fill_name(req: &mut IwReq, iface: &str) -> bool {
    let bytes = iface.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return false;
    }
    req.ifr_name.fill(0);
    for (dst, src) in req.ifr_name.iter_mut().zip(bytes.iter().copied()) {
        *dst = src as libc::c_char;
    }
    true
}

unsafe fn read_essid(sock: libc::c_int, iface: &str) -> Option<String> {
    let mut buf = [0u8; IW_ESSID_MAX_SIZE + 1];
    let mut req = std::mem::zeroed::<IwReq>();
    if !fill_name(&mut req, iface) {
        return None;
    }
    req.u.essid = std::mem::ManuallyDrop::new(IwPoint {
        pointer: buf.as_mut_ptr(),
        length: IW_ESSID_MAX_SIZE as u16,
        flags: 0,
    });
    if libc::ioctl(sock, SIOCGIWESSID, &mut req) != 0 {
        return None;
    }
    let len = (*req.u.essid).length as usize;
    let bytes = buf.get(..len.min(IW_ESSID_MAX_SIZE))?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

unsafe fn read_bssid(sock: libc::c_int, iface: &str) -> Option<String> {
    let mut req = std::mem::zeroed::<IwReq>();
    if !fill_name(&mut req, iface) {
        return None;
    }
    if libc::ioctl(sock, SIOCGIWAP, &mut req) != 0 {
        return None;
    }
    let data = req.u.ap_addr.sa_data;
    let mac = [
        data[0] as u8,
        data[1] as u8,
        data[2] as u8,
        data[3] as u8,
        data[4] as u8,
        data[5] as u8,
    ];
    if mac.iter().all(|b| *b == 0) {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

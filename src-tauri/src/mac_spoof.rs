use std::process::Command;

use crate::helper::{root, rand_bytes, primary_interface};

fn hw_mac(iface: &str) -> Option<String> {
    let out = Command::new("networksetup")
        .args(["-getmacaddress", iface]).output().ok()?;
    let stdout = String::from_utf8(out.stdout).ok()?;
    stdout.split_whitespace()
        .find(|w| w.contains(':') && w.len() == 17)
        .map(|s| s.to_string())
}

fn ifconfig_ether_root(iface: &str, mac: &str) {
    root("/sbin/ifconfig", &[iface, "down"]);
    std::thread::sleep(std::time::Duration::from_millis(300));
    root("/sbin/ifconfig", &[iface, "ether", mac]);
    root("/sbin/ifconfig", &[iface, "up"]);
}

pub fn mac_spoof_enable() {
    let iface = primary_interface();
    const APPLE_OUIS: &[[u8; 3]] = &[
        [0x3c, 0x06, 0x30], [0xa8, 0x66, 0x7f], [0x8c, 0x85, 0x90],
        [0xf0, 0x18, 0x98], [0x00, 0x17, 0xf2], [0x28, 0xcf, 0xe9],
        [0xac, 0xbc, 0x32], [0x60, 0x03, 0x08], [0xe8, 0x8d, 0x28],
        [0x78, 0x4f, 0x43],
    ];
    let b = rand_bytes(4);
    let oui = APPLE_OUIS[(b[0] as usize) % APPLE_OUIS.len()];
    let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        oui[0], oui[1], oui[2], b[1], b[2], b[3]);
    ifconfig_ether_root(&iface, &mac);
}

pub fn mac_spoof_restore() {
    let iface = primary_interface();
    if let Some(orig) = hw_mac(&iface) {
        ifconfig_ether_root(&iface, &orig);
    }
}

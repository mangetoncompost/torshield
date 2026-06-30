use std::io::Read;
use std::process::Command;
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use crate::config::Config;
use crate::helper::opsec_dir;

pub fn tor_ready() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9050".parse().unwrap(),
        std::time::Duration::from_secs(1),
    ).is_ok()
}

pub fn tor_pid() -> Option<u32> {
    std::fs::read_to_string(format!("{}/tor.pid", opsec_dir())).ok()
        .and_then(|s| s.trim().parse().ok())
}

pub fn start_tor(cfg: &Config) -> bool {
    let dir    = opsec_dir();
    let data   = format!("{}/tor_data", dir);
    let conf   = format!("{}/torrc", dir);
    let pid    = format!("{}/tor.pid", dir);
    let log    = format!("{}/tor.log", dir);
    let cookie = format!("{}/tor_data/control_auth", dir);
    std::fs::create_dir_all(&cookie).ok();
    let excluded = cfg.excluded_nodes();
    let exclude_line = if excluded.is_empty() { String::new() }
        else { format!("ExcludeExitNodes {}\nStrictNodes 1\n", excluded) };
    std::fs::write(&conf, format!(
        "SocksPort 9050\nControlPort 9051\nCookieAuthentication 1\n\
         CookieAuthFile {cookie}/control_auth_cookie\n\
         DataDirectory {data}\nLog notice file {log}\n\
         DNSPort 9053\nMaxCircuitDirtiness 600\n{exclude_line}"
    )).ok();
    Command::new("tor")
        .args(["-f", &conf, "--PidFile", &pid, "--RunAsDaemon", "1"])
        .spawn().is_ok()
}

pub fn stop_tor() {
    if let Some(pid) = tor_pid() {
        Command::new("kill").arg(pid.to_string()).output().ok();
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if tor_pid().is_none() { break; }
        }
    }
    std::fs::remove_file(format!("{}/tor.pid", opsec_dir())).ok();
}

// SAFECOOKIE authentication per spec 193 - challenge/response HMAC-SHA256.
// Never sends the cookie file in cleartext over the TCP socket.
pub fn new_tor_identity() -> bool {
    let cookie_path = format!("{}/tor_data/control_auth/control_auth_cookie", opsec_dir());
    let cookie = match std::fs::read(&cookie_path) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };

    let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9051".parse().unwrap(),
        std::time::Duration::from_secs(3),
    ) else { return false; };
    s.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();
    use std::io::Write;

    let mut client_nonce = [0u8; 32];
    getrandom::fill(&mut client_nonce).unwrap();
    let client_nonce_hex: String = client_nonce.iter().map(|b| format!("{:02x}", b)).collect();

    if s.write_all(
        format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", client_nonce_hex).as_bytes()
    ).is_err() { return false; }

    let mut buf = [0u8; 512];
    let n = match s.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return false,
    };
    let line = match std::str::from_utf8(&buf[..n]) {
        Ok(l) => l,
        Err(_) => return false,
    };
    if !line.starts_with("250 AUTHCHALLENGE") { return false; }

    let server_hash_hex = line.split("SERVERHASH=")
        .nth(1).and_then(|s| s.split_whitespace().next()).unwrap_or("");
    let server_nonce_hex = line.split("SERVERNONCE=")
        .nth(1).and_then(|s| s.split_whitespace().next().map(|s| s.trim_end_matches("\r\n")))
        .unwrap_or("");

    let server_hash  = hex_decode(server_hash_hex);
    let server_nonce = hex_decode(server_nonce_hex);
    if server_hash.len() != 32 || server_nonce.len() != 32 { return false; }

    let server_key = b"Tor safe cookie authentication server-to-controller hash";
    let mut mac_srv = HmacSha256::new_from_slice(server_key).unwrap();
    mac_srv.update(&cookie);
    mac_srv.update(&client_nonce);
    mac_srv.update(&server_nonce);
    if mac_srv.verify_slice(&server_hash).is_err() { return false; }

    let ctrl_key = b"Tor safe cookie authentication controller-to-server hash";
    let mut mac_ctrl = HmacSha256::new_from_slice(ctrl_key).unwrap();
    mac_ctrl.update(&cookie);
    mac_ctrl.update(&client_nonce);
    mac_ctrl.update(&server_nonce);
    let controller_hash = mac_ctrl.finalize().into_bytes();
    let controller_hash_hex: String = controller_hash.iter().map(|b| format!("{:02x}", b)).collect();

    if s.write_all(
        format!("AUTHENTICATE {}\r\nSIGNAL NEWNYM\r\nQUIT\r\n", controller_hash_hex).as_bytes()
    ).is_err() { return false; }

    let mut resp = String::new();
    s.read_to_string(&mut resp).ok();
    resp.contains("250 OK")
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

pub async fn fetch_tor_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").ok()?)
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    client.get("https://api.ipify.org").send().await.ok()?.text().await.ok()
}

pub async fn fetch_real_ip() -> Option<String> {
    reqwest::Client::builder().no_proxy()
        .timeout(std::time::Duration::from_secs(5)).build().ok()?
        .get("https://api.ipify.org").send().await.ok()?.text().await.ok()
}

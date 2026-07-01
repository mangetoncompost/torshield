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

fn tor_bin() -> Option<String> {
    // Resolve to an absolute path - never rely on PATH for a security-critical binary.
    for candidate in ["/opt/homebrew/bin/tor", "/usr/local/bin/tor", "/usr/bin/tor"] {
        if std::path::Path::new(candidate).exists() { return Some(candidate.into()); }
    }
    // Last resort: ask which(1) but validate the result is an absolute path
    let out = std::process::Command::new("which").arg("tor").output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.starts_with('/') && std::path::Path::new(&s).exists() { Some(s) } else { None }
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
    // Restrict torrc to owner-only: prevents local modification of exit node
    // exclusions, CookieAuthFile path, or injection of HiddenServiceDir.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&conf, std::fs::Permissions::from_mode(0o600)).ok();
    let Some(tor) = tor_bin() else { return false; };
    Command::new(&tor)
        .args(["-f", &conf, "--PidFile", &pid, "--RunAsDaemon", "1"])
        .spawn().is_ok()
}

pub fn stop_tor() {
    if let Some(pid) = tor_pid() {
        // tor runs as the current user - kill directly with /bin/kill (absolute path,
        // required by execv which does not search PATH).
        Command::new("/bin/kill").arg(pid.to_string()).output().ok();
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

    let server_hash  = match hex_decode(server_hash_hex)  { Some(v) if v.len() == 32 => v, _ => return false };
    let server_nonce = match hex_decode(server_nonce_hex) { Some(v) if v.len() == 32 => v, _ => return false };

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

// Returns None on odd-length input or invalid hex - never panics.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    s.as_bytes().chunks(2)
        .map(|c| {
            let h = std::str::from_utf8(c).ok()?;
            u8::from_str_radix(h, 16).ok()
        })
        .collect()
}

pub async fn fetch_tor_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").ok()?)
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    client.get("https://api.ipify.org").send().await.ok()?.text().await.ok()
}

// Fetch the real public IP directly (no proxy) - only called when TorShield is OFF,
// so the IP is not meant to be hidden. Uses no_proxy() to bypass any stale system
// proxy config left from a previous session.
pub async fn fetch_real_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(8)).build().ok()?;
    let ip = client.get("https://api.ipify.org").send().await.ok()?.text().await.ok()?;
    let ip = ip.trim().to_string();
    if ip.is_empty() { None } else { Some(ip) }
}

// Read the real IP from the default interface without any outbound network request.
// Avoids exposing the real IP to api.ipify.org at startup before Tor is active.
pub fn local_real_ip() -> Option<String> {
    let out = std::process::Command::new("ipconfig")
        .args(["getifaddr", &crate::helper::primary_interface()])
        .output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let ip = s.trim().to_string();
    if ip.is_empty() { None } else { Some(ip) }
}

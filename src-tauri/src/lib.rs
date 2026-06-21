use std::io::Read;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder, CheckMenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle,
};
use tauri_plugin_autostart::MacosLauncher;
use tokio::sync::watch;

// ── SF Symbol icon generation ─────────────────────────────────────────────────

fn sf_symbol_png(symbol: &str, size: u32, out: &str) -> bool {
    let src      = include_str!("gen_icon.m");
    let src_path = format!("{}/gen_icon.m",  opsec_dir());
    let bin_path = format!("{}/gen_icon",    opsec_dir());
    std::fs::create_dir_all(opsec_dir()).ok();
    if std::fs::write(&src_path, src).is_err() { return false; }
    if !std::path::Path::new(&bin_path).exists() {
        let ok = Command::new("clang")
            .args(["-framework", "AppKit", "-framework", "Foundation",
                   &src_path, "-o", &bin_path, "-fobjc-arc"])
            .output().map(|o| o.status.success()).unwrap_or(false);
        if !ok { return false; }
    }
    Command::new(&bin_path).args([symbol, out, &size.to_string()])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub exclude_us:   bool,
    pub exclude_gb:   bool,
    pub exclude_au:   bool,
    pub exclude_ca:   bool,
    pub exclude_nz:   bool,
    pub exclude_de:   bool,
    pub exclude_fr:   bool,
    pub rotate_mins:  u32,
    pub mac_spoof:    bool,
    pub dns_leak:     bool,
    pub pf_firewall:  bool,
    pub clear_logs:   bool,
    pub firefox:      bool,
    pub resist_fp:      bool,
    pub ua_spoof:       bool,
    pub lang_spoof:     bool,
    pub spotify_bypass: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exclude_us: true, exclude_gb: true, exclude_au: true,
            exclude_ca: true, exclude_nz: true, exclude_de: false, exclude_fr: false,
            rotate_mins: 0,
            mac_spoof: true, dns_leak: true, pf_firewall: false,
            clear_logs: true, firefox: true, resist_fp: true,
            ua_spoof: true, lang_spoof: true, spotify_bypass: false,
        }
    }
}

impl Config {
    fn load() -> Self {
        let path = format!("{}/torshield.json", opsec_dir());
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    fn save(&self) {
        let dir = opsec_dir();
        std::fs::create_dir_all(&dir).ok();
        let path = format!("{}/torshield.json", dir);
        if let Ok(json) = serde_json::to_string_pretty(self) {
            std::fs::write(path, json).ok();
        }
    }
    fn excluded_nodes(&self) -> String {
        let mut v = vec![];
        if self.exclude_us { v.push("{us}"); }
        if self.exclude_gb { v.push("{gb}"); }
        if self.exclude_au { v.push("{au}"); }
        if self.exclude_ca { v.push("{ca}"); }
        if self.exclude_nz { v.push("{nz}"); }
        if self.exclude_de { v.push("{de}"); }
        if self.exclude_fr { v.push("{fr}"); }
        v.join(",")
    }
}

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct OpsecState {
    pub active:   bool,
    pub tor_ip:   Option<String>,
    pub real_ip:  Option<String>,
    pub config:   Option<Config>,
}

type Shared = Arc<Mutex<(OpsecState, Config)>>;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn opsec_dir() -> String {
    format!("{}/.config/opsec", std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

fn icon_path(active: bool) -> String {
    format!("{}/{}", opsec_dir(), if active { "icon_on.png" } else { "icon_off.png" })
}

fn lock_path() -> String { format!("{}/active.lock", opsec_dir()) }

fn sh(cmd: &str, args: &[&str]) {
    Command::new(cmd).args(args).output().ok();
}

// Retourne les services reseau actifs (filtre les desactives marques d'un *)
fn get_network_services() -> Vec<String> {
    Command::new("networksetup").arg("-listallnetworkservices").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with('*'))
        .map(|l| l.to_string())
        .collect()
}

fn primary_interface() -> String {
    Command::new("route").args(["get", "default"]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find(|l| l.contains("interface:"))
            .map(|l| l.split_whitespace().last().unwrap_or("en0").to_string()))
        .unwrap_or_else(|| "en0".to_string())
}

fn tor_ready() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9050".parse().unwrap(),
        std::time::Duration::from_secs(1),
    ).is_ok()
}

fn tor_pid() -> Option<u32> {
    std::fs::read_to_string(format!("{}/tor.pid", opsec_dir())).ok()
        .and_then(|s| s.trim().parse().ok())
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_err() {
            // /dev/urandom lisible mais read a echoue - fallback horloge
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos()
                    .wrapping_add(i as u32 * 0x9e3779b9)) as u8;
            }
        }
    }
    buf
}

async fn fetch_tor_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").ok()?)
        .timeout(std::time::Duration::from_secs(10)).build().ok()?;
    client.get("https://api.ipify.org").send().await.ok()?.text().await.ok()
}

async fn fetch_real_ip() -> Option<String> {
    reqwest::Client::builder().no_proxy()
        .timeout(std::time::Duration::from_secs(5)).build().ok()?
        .get("https://api.ipify.org").send().await.ok()?.text().await.ok()
}

// ── Tor ───────────────────────────────────────────────────────────────────────

fn start_tor(cfg: &Config) -> bool {
    let dir    = opsec_dir();
    let data   = format!("{}/tor_data", dir);
    let conf   = format!("{}/torrc", dir);
    let pid    = format!("{}/tor.pid", dir);
    let log    = format!("{}/tor.log", dir);
    let cookie = format!("{}/tor_data/control_auth", dir);
    std::fs::create_dir_all(&cookie).ok();
    let excluded    = cfg.excluded_nodes();
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

fn stop_tor() {
    if let Some(pid) = tor_pid() {
        sh("kill", &[&pid.to_string()]);
        // Attendre l'arret effectif (max 3s)
        for _ in 0..30 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if tor_pid().is_none() { break; }
        }
    }
    std::fs::remove_file(format!("{}/tor.pid", opsec_dir())).ok();
}

// Envoie SIGNAL NEWNYM et verifie la reponse 250 OK.
fn new_tor_identity() -> bool {
    let cookie = format!("{}/tor_data/control_auth/control_auth_cookie", opsec_dir());
    let auth = std::fs::read(&cookie)
        .map(|b| b.iter().map(|x| format!("{:02x}", x)).collect::<String>())
        .unwrap_or_default();
    let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9051".parse().unwrap(),
        std::time::Duration::from_secs(3),
    ) else { return false; };
    s.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok();
    use std::io::Write;
    if s.write_all(
        format!("AUTHENTICATE {}\r\nSIGNAL NEWNYM\r\nQUIT\r\n", auth).as_bytes()
    ).is_err() { return false; }
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok();
    resp.contains("250 OK")
}

// ── Proxy systeme ─────────────────────────────────────────────────────────────

const SPOTIFY_BYPASS_DOMAINS: &str =
    "localhost, 127.0.0.1, *.spotify.com, *.scdn.co, *.spotilocal.com, *.pscdn.co";

fn proxy_enable(spotify_bypass: bool) {
    let bypass = if spotify_bypass { SPOTIFY_BYPASS_DOMAINS } else { "localhost, 127.0.0.1" };
    for svc in get_network_services() {
        sh("networksetup", &["-setsocksfirewallproxy", &svc, "127.0.0.1", "9050", "off"]);
        sh("networksetup", &["-setsocksfirewallproxystate", &svc, "on"]);
        sh("networksetup", &["-setproxybypassdomains", &svc, bypass]);
    }
}

fn proxy_disable() {
    for svc in get_network_services() {
        sh("networksetup", &["-setsocksfirewallproxystate", &svc, "off"]);
    }
}

// ── IPv6 ──────────────────────────────────────────────────────────────────────

fn ipv6_disable() {
    for svc in get_network_services() { sh("networksetup", &["-setv6off", &svc]); }
}

fn ipv6_restore() {
    for svc in get_network_services() { sh("networksetup", &["-setv6automatic", &svc]); }
}

// ── MAC spoofing ──────────────────────────────────────────────────────────────

// networksetup -getmacaddress retourne la MAC hardware permanente
// meme quand l'interface est actuellement spoofee
fn hw_mac(iface: &str) -> Option<String> {
    let out = Command::new("networksetup")
        .args(["-getmacaddress", iface]).output().ok()?;
    let stdout = String::from_utf8(out.stdout).ok()?;
    stdout.split_whitespace()
        .find(|w| w.contains(':') && w.len() == 17)
        .map(|s| s.to_string())
}

// ifconfig ether necessite root depuis macOS Ventura - elevation via osascript (une seule dialog admin)
fn ifconfig_ether_root(iface: &str, mac: &str) {
    // down/ether/up en une seule commande root
    let script = format!(
        "do shell script \
         \"ifconfig {iface} down; sleep 0.3; ifconfig {iface} ether {mac}; ifconfig {iface} up\" \
         with administrator privileges"
    );
    Command::new("osascript").args(["-e", &script]).output().ok();
}

fn mac_spoof_enable() {
    let iface = primary_interface();
    // OUI Apple legitimes - evite la detection par profiling NAC/802.1X
    const APPLE_OUIS: &[[u8; 3]] = &[
        [0x3c, 0x06, 0x30], [0xa8, 0x66, 0x7f], [0x8c, 0x85, 0x90],
        [0xf0, 0x18, 0x98], [0x00, 0x17, 0xf2], [0x28, 0xcf, 0xe9],
        [0xac, 0xbc, 0x32], [0x60, 0x03, 0x08], [0xe8, 0x8d, 0x28],
        [0x78, 0x4f, 0x43],
    ];
    let b = rand_bytes(4); // 1 byte pour picker l'OUI, 3 pour le NIC
    let oui = APPLE_OUIS[(b[0] as usize) % APPLE_OUIS.len()];
    let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        oui[0], oui[1], oui[2], b[1], b[2], b[3]);
    ifconfig_ether_root(&iface, &mac);
}

fn mac_spoof_restore() {
    let iface = primary_interface();
    if let Some(orig) = hw_mac(&iface) {
        ifconfig_ether_root(&iface, &orig);
    }
}

// ── DNS leak fix via dnsmasq ──────────────────────────────────────────────────

fn dns_leak_enable() {
    let dir          = opsec_dir();
    let pid_file     = format!("{}/dnsmasq.pid", dir);
    let dnsmasq_conf = format!("{}/dnsmasq.conf", dir);

    std::fs::write(&dnsmasq_conf, format!(
        "no-resolv\nserver=127.0.0.1#9053\nlisten-address=127.0.0.1\nport=53\n\
         pid-file={pid_file}\n"
    )).ok();

    if !Command::new("which").arg("dnsmasq")
        .output().map(|o| o.status.success()).unwrap_or(false) { return; }

    // Port 53 requiert root - elevation via boite de dialogue macOS native.
    // On echappe le path en remplacant les apostrophes pour eviter l'injection.
    let safe_conf = dnsmasq_conf.replace('\'', "'\\''");
    let script = format!(
        "do shell script \"dnsmasq -C '{safe_conf}'\" with administrator privileges"
    );
    Command::new("osascript").args(["-e", &script]).output().ok();

    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "127.0.0.1"]);
    }
}

fn dns_leak_disable() {
    let dir      = opsec_dir();
    let pid_file = format!("{}/dnsmasq.pid", dir);
    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
        sh("kill", &[pid.trim()]);
        std::fs::remove_file(&pid_file).ok();
    }
    let dnsmasq_conf = format!("{}/dnsmasq.conf", dir);
    sh("pkill", &["-f", &format!("dnsmasq.*{}", dnsmasq_conf)]);
    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "empty"]);
    }
}

// ── pf firewall - kill switch ─────────────────────────────────────────────────

fn build_pf_rules() -> String {
    let iface = primary_interface();
    format!(
        "# TorShield kill switch\n\
         set skip on lo0\n\
         block all\n\
         pass out on {iface} proto tcp to 127.0.0.1 port 9050 keep state\n\
         pass out on {iface} proto tcp to any port 9050 keep state\n\
         pass out proto udp to any port 53 keep state\n\
         block out proto udp to 224.0.0.251 port 5353\n\
         block out proto udp to ff02::fb port 5353\n\
         pass in all\n"
    )
}

fn pf_enable() {
    let pf_conf   = format!("{}/pf.conf",        opsec_dir());
    let pf_backup = format!("{}/pf_backup.txt",  opsec_dir());
    std::fs::write(&pf_conf, build_pf_rules()).ok();
    if let Ok(out) = Command::new("pfctl").args(["-sr"]).output() {
        if !out.stdout.is_empty() {
            std::fs::write(&pf_backup, &out.stdout).ok();
        }
    }
    sh("pfctl", &["-f", &pf_conf, "-e"]);
}

fn pf_disable() {
    let pf_backup = format!("{}/pf_backup.txt", opsec_dir());
    let pf_conf   = format!("{}/pf.conf",       opsec_dir());
    if std::path::Path::new(&pf_backup).exists() {
        if std::fs::metadata(&pf_backup).map(|m| m.len() > 0).unwrap_or(false) {
            sh("pfctl", &["-f", &pf_backup]);
        } else {
            sh("pfctl", &["-d"]);
        }
        std::fs::remove_file(&pf_backup).ok();
    } else {
        sh("pfctl", &["-d"]);
    }
    std::fs::remove_file(&pf_conf).ok();
}

// ── Logs systeme ──────────────────────────────────────────────────────────────

fn clear_logs() {
    Command::new("log").args(["erase", "--all"]).output().ok();
    std::fs::remove_dir_all(format!("{}/Library/Logs/CrashReporter",
        std::env::var("HOME").unwrap_or_default())).ok();
    std::fs::write(format!("{}/tor.log", opsec_dir()), "").ok();
}

// ── Firefox hardening ─────────────────────────────────────────────────────────

fn firefox_prefs(ua: bool, lang: bool, resist_fp: bool) -> String {
    let mut p = String::from(r#"
// TorShield
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", 9050);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("geo.enabled", false);
user_pref("geo.provider.use_corelocation", false);
user_pref("permissions.default.geo", 2);
user_pref("dom.battery.enabled", false);
user_pref("layout.css.prefers-color-scheme.content-override", 1);
user_pref("browser.startup.page", 3);
"#);
    p.push_str(&format!(
        "user_pref(\"privacy.resistFingerprinting\", {r});\n\
         user_pref(\"privacy.resistFingerprinting.spoofOsAsWindows\", {r});\n\
         user_pref(\"privacy.fingerprintingProtection\", {r});\n\
         user_pref(\"privacy.fingerprintingProtection.overrides\", \"+AllTargets\");\n\
         user_pref(\"dom.webaudio.enabled\", {w});\n",
        r = if resist_fp { "true" } else { "false" },
        w = if resist_fp { "false" } else { "true" }
    ));
    if ua && !resist_fp {
        p.push_str("user_pref(\"general.useragent.override\", \
            \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) \
            Gecko/20100101 Firefox/128.0\");\n");
    }
    if lang {
        p.push_str("user_pref(\"intl.accept_languages\", \"en-US, en\");\n");
        p.push_str("user_pref(\"javascript.use_us_english_locale\", true);\n");
    }
    p
}

fn firefox_running() -> bool {
    // -ix : insensible a la casse, matche firefox et firefox-bin
    Command::new("pgrep").args(["-ix", "firefox"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

const CANVASBLOCKER_ID: &str = "{bc3b3d9e-b4eb-41ae-b0b6-3de78bd66f6e}";
const CANVASBLOCKER_URL: &str =
    "https://addons.mozilla.org/firefox/downloads/latest/canvasblocker/latest.xpi";

async fn ensure_canvasblocker(ff_profiles: &str) {
    let xpi_cache = format!("{}/canvasblocker.xpi", opsec_dir());
    if !std::path::Path::new(&xpi_cache).exists() {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30)).build() else { return; };
        let Ok(resp) = client.get(CANVASBLOCKER_URL).send().await else { return; };
        let Ok(bytes) = resp.bytes().await else { return; };
        std::fs::write(&xpi_cache, &bytes).ok();
    }
    for entry in std::fs::read_dir(ff_profiles).into_iter().flatten().flatten() {
        if !entry.path().is_dir() { continue; }
        let ext_dir = entry.path().join("extensions");
        std::fs::create_dir_all(&ext_dir).ok();
        let dest = ext_dir.join(format!("{}.xpi", CANVASBLOCKER_ID));
        if !dest.exists() {
            std::fs::copy(&xpi_cache, &dest).ok();
        }
    }
}

fn firefox_apply(enable: bool, cfg: &Config) {
    let home = std::env::var("HOME").unwrap_or_default();
    let ff   = format!("{}/Library/Application Support/Firefox/Profiles", home);
    if !std::path::Path::new(&ff).is_dir() { return; }

    let was_running = firefox_running();
    if was_running {
        Command::new("osascript")
            .args(["-e", "tell application \"Firefox\" to quit"]).output().ok();
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let blocked = [
        "TorShield", "network.proxy", "media.peerconnection",
        "geo.", "permissions.default.geo", "dom.battery",
        "layout.css.prefers", "privacy.resistFingerprinting",
        "privacy.fingerprintingProtection", "dom.webaudio.enabled",
        "general.useragent.override", "intl.accept_languages",
        "javascript.use_us_english_locale", "spoofOsAsWindows",
    ];

    for entry in std::fs::read_dir(&ff).into_iter().flatten().flatten() {
        if !entry.path().is_dir() { continue; }
        let ujs = entry.path().join("user.js");
        let pjs = entry.path().join("prefs.js");
        let bak = entry.path().join("user.js.opsec_bak");

        let strip = |content: &str| -> String {
            content.lines()
                .filter(|l| !blocked.iter().any(|b| l.contains(b)))
                .collect::<Vec<_>>().join("\n")
        };

        if enable {
            if ujs.exists() && !bak.exists() { std::fs::copy(&ujs, &bak).ok(); }
            let base = strip(&std::fs::read_to_string(&ujs).unwrap_or_default());
            std::fs::write(&ujs,
                base + &firefox_prefs(cfg.ua_spoof, cfg.lang_spoof, cfg.resist_fp)
            ).ok();
            if let Ok(p) = std::fs::read_to_string(&pjs) {
                let mut out = strip(&p);
                out.push_str("\nuser_pref(\"layout.css.prefers-color-scheme.content-override\", 1);\n");
                out.push_str(&format!("user_pref(\"privacy.resistFingerprinting\", {});\n",
                    if cfg.resist_fp { "true" } else { "false" }));
                if cfg.ua_spoof {
                    out.push_str("user_pref(\"general.useragent.override\", \
                        \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) \
                        Gecko/20100101 Firefox/128.0\");\n");
                }
                if cfg.lang_spoof {
                    out.push_str("user_pref(\"intl.accept_languages\", \"en-US, en\");\n");
                }
                std::fs::write(&pjs, out).ok();
            }
        } else {
            if bak.exists() {
                std::fs::copy(&bak, &ujs).ok();
                std::fs::remove_file(&bak).ok();
            } else {
                std::fs::write(&ujs,
                    strip(&std::fs::read_to_string(&ujs).unwrap_or_default())
                ).ok();
            }
            if let Ok(mut c) = std::fs::read_to_string(&ujs) {
                c.push_str("\nuser_pref(\"layout.css.prefers-color-scheme.content-override\", 2);\n");
                std::fs::write(&ujs, c).ok();
            }
            if let Ok(p) = std::fs::read_to_string(&pjs) {
                let mut out = strip(&p);
                out.push_str("\nuser_pref(\"layout.css.prefers-color-scheme.content-override\", 2);\n");
                out.push_str("user_pref(\"privacy.resistFingerprinting\", false);\n");
                std::fs::write(&pjs, out).ok();
            }
        }
    }

    if was_running {
        Command::new("open").args(["-a", "Firefox"]).spawn().ok();
    }
}

// ── Enable / Disable OPSEC ────────────────────────────────────────────────────

async fn do_enable(shared: &Shared) {
    let cfg = shared.lock().unwrap().1.clone();

    if cfg.clear_logs { clear_logs(); }
    if cfg.mac_spoof  { mac_spoof_enable(); }

    start_tor(&cfg);
    let mut waited = 0u8;
    while !tor_ready() && waited < 30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        waited += 1;
    }

    proxy_enable(cfg.spotify_bypass);
    ipv6_disable();
    if cfg.dns_leak    { dns_leak_enable(); }
    if cfg.pf_firewall { pf_enable(); }

    // Lock ecrit avant firefox_apply pour garantir le recovery meme si
    // l'app est tuee pendant la fermeture/reouverture de Firefox
    std::fs::create_dir_all(opsec_dir()).ok();
    std::fs::write(lock_path(), "").ok();

    if cfg.firefox {
        let home = std::env::var("HOME").unwrap_or_default();
        let ff = format!("{}/Library/Application Support/Firefox/Profiles", home);
        ensure_canvasblocker(&ff).await;
        firefox_apply(true, &cfg);
    }

    let tor_ip  = fetch_tor_ip().await;
    // fetch_real_ip bypass le proxy : si kill switch pf actif, retourne None (correct)
    let real_ip = fetch_real_ip().await;

    let mut lock = shared.lock().unwrap();
    lock.0.active  = true;
    lock.0.tor_ip  = tor_ip;
    lock.0.real_ip = real_ip;
}

async fn do_disable(shared: &Shared) {
    let cfg = shared.lock().unwrap().1.clone();

    if cfg.pf_firewall { pf_disable(); }
    if cfg.dns_leak    { dns_leak_disable(); }
    proxy_disable();
    ipv6_restore();
    if cfg.firefox { firefox_apply(false, &cfg); }
    stop_tor();
    if cfg.mac_spoof { mac_spoof_restore(); }

    std::fs::remove_file(lock_path()).ok();

    let real_ip = fetch_real_ip().await;

    let mut lock = shared.lock().unwrap();
    lock.0.active  = false;
    lock.0.tor_ip  = None;
    lock.0.real_ip = real_ip;
}

// Teardown synchrone - utilise au quit et au recovery post-crash
fn emergency_teardown(cfg: &Config) {
    if cfg.pf_firewall { pf_disable(); }
    if cfg.dns_leak    { dns_leak_disable(); }
    proxy_disable();
    ipv6_restore();
    if cfg.firefox     { firefox_apply(false, cfg); }
    stop_tor();
    if cfg.mac_spoof   { mac_spoof_restore(); }
    std::fs::remove_file(lock_path()).ok();
}

// ── Menu ──────────────────────────────────────────────────────────────────────

fn rebuild_menu(app: &AppHandle, state: &OpsecState, cfg: &Config) {
    use tauri_plugin_autostart::ManagerExt;
    let active  = state.active;
    let tor_ip  = state.tor_ip.clone().unwrap_or_else(|| "-".into());
    let real_ip = state.real_ip.clone().unwrap_or_else(|| "-".into());

    let mk  = |id: &str, label: &str|
        MenuItemBuilder::new(label).id(id).build(app).unwrap();
    let mkd = |id: &str, label: &str|
        MenuItemBuilder::new(label).id(id).enabled(false).build(app).unwrap();
    let chk = |id: &str, label: &str, checked: bool|
        CheckMenuItemBuilder::new(label).id(id).checked(checked).build(app).unwrap();

    let status_label = if active { format!("Active - {}", tor_ip) } else { "Inactive".into() };
    let item_status  = mkd("status",  &status_label);
    let item_real    = mkd("real_ip", &format!("Real IP: {}  (hidden)", real_ip));

    let item_toggle = mk("toggle", if active { "Disable OPSEC" } else { "Enable OPSEC" });
    let item_rotate = MenuItemBuilder::new("New Tor identity")
        .id("rotate").enabled(active).build(app).unwrap();

    let sub_nodes = SubmenuBuilder::new(app, "Excluded exit nodes")
        .item(&chk("node_us", "US  United States",   cfg.exclude_us))
        .item(&chk("node_gb", "GB  United Kingdom",  cfg.exclude_gb))
        .item(&chk("node_au", "AU  Australia",       cfg.exclude_au))
        .item(&chk("node_ca", "CA  Canada",          cfg.exclude_ca))
        .item(&chk("node_nz", "NZ  New Zealand",     cfg.exclude_nz))
        .item(&chk("node_de", "DE  Germany",         cfg.exclude_de))
        .item(&chk("node_fr", "FR  France",          cfg.exclude_fr))
        .build().unwrap();

    let rot_label = match cfg.rotate_mins {
        0  => "Auto-rotate: off",
        5  => "Auto-rotate: 5 min",
        15 => "Auto-rotate: 15 min",
        30 => "Auto-rotate: 30 min",
        _  => "Auto-rotate",
    };
    let sub_rotate = SubmenuBuilder::new(app, rot_label)
        .item(&chk("rot_off", "Off",          cfg.rotate_mins == 0))
        .item(&chk("rot_5",   "Every 5 min",  cfg.rotate_mins == 5))
        .item(&chk("rot_15",  "Every 15 min", cfg.rotate_mins == 15))
        .item(&chk("rot_30",  "Every 30 min", cfg.rotate_mins == 30))
        .build().unwrap();

    let sub_bypass = SubmenuBuilder::new(app, "Bypass")
        .item(&chk("prot_spotify", "Spotify (direct)",  cfg.spotify_bypass))
        .build().unwrap();

    let sub_prot = SubmenuBuilder::new(app, "Protections")
        .item(&chk("prot_ff",   "Firefox (proxy + WebRTC off)", cfg.firefox))
        .item(&chk("prot_rfp",  "Firefox resistFingerprinting", cfg.resist_fp))
        .item(&chk("prot_mac",  "MAC spoofing",                 cfg.mac_spoof))
        .item(&chk("prot_dns",  "DNS leak fix (dnsmasq)",       cfg.dns_leak))
        .item(&chk("prot_pf",   "Kill switch (pf firewall)",    cfg.pf_firewall))
        .item(&chk("prot_logs", "Clear logs on start",          cfg.clear_logs))
        .item(&chk("prot_ua",   "Spoof User-Agent (Windows)",   cfg.ua_spoof))
        .item(&chk("prot_lang", "Neutral language (en-US)",     cfg.lang_spoof))
        .build().unwrap();

    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let item_login   = chk("login", "Launch at login", autostart_on);

    let menu = MenuBuilder::new(app)
        .item(&item_status)
        .item(&item_real)
        .separator()
        .item(&item_toggle)
        .item(&item_rotate)
        .separator()
        .item(&sub_nodes)
        .item(&sub_rotate)
        .item(&sub_prot)
        .item(&sub_bypass)
        .separator()
        .item(&item_login)
        .separator()
        .item(&mk("quit", "Quit TorShield"))
        .build().unwrap();

    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu)).ok();
        let path = icon_path(active);
        if let Ok(bytes) = std::fs::read(&path) {
            if let Ok(img) = Image::from_bytes(&bytes) { tray.set_icon(Some(img)).ok(); }
        }
        tray.set_icon_as_template(true).ok();
    }
}

// ── Config toggle helper ──────────────────────────────────────────────────────

fn toggle_cfg<F: FnOnce(&mut Config)>(shared: &Shared, f: F) -> Config {
    let mut lock = shared.lock().unwrap();
    f(&mut lock.1);
    let cfg = lock.1.clone();
    drop(lock);
    cfg.save();
    cfg
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let cfg = Config::load();

    // Recovery post-crash : teardown propre si la session precedente n'a pas ete fermee
    if std::path::Path::new(&lock_path()).exists() {
        emergency_teardown(&cfg);
    }

    let shared: Shared = Arc::new(Mutex::new((OpsecState::default(), cfg)));
    let (rot_tx, rot_rx) = watch::channel::<u32>(0);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec![])))
        .manage(shared.clone())
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Icones dans ~/.config/opsec/ (hors /tmp)
            std::fs::create_dir_all(opsec_dir()).ok();
            let _ = std::fs::remove_file(format!("{}/gen_icon", opsec_dir()));
            sf_symbol_png("shield",           18, &icon_path(false));
            sf_symbol_png("lock.shield.fill", 18, &icon_path(true));

            let icon = std::fs::read(icon_path(false))
                .ok()
                .and_then(|b| Image::from_bytes(&b).ok())
                .unwrap_or_else(|| Image::new_owned(vec![0u8; 18 * 18 * 4], 18, 18));

            let shared_ref = shared.clone();
            let app_handle = app.handle().clone();

            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .icon_as_template(true)
                .tooltip("TorShield")
                .show_menu_on_left_click(true)
                .on_menu_event(move |app, event| {
                    let shared = shared_ref.clone();
                    let app    = app.clone();
                    let rot_tx = rot_tx.clone();
                    match event.id().as_ref() {

                        "toggle" => {
                            let is_active = shared.lock().unwrap().0.active;
                            tauri::async_runtime::spawn(async move {
                                if is_active { do_disable(&shared).await; }
                                else         { do_enable(&shared).await; }
                                let (state, cfg) = shared.lock().unwrap().clone();
                                rebuild_menu(&app, &state, &cfg);
                            });
                        }

                        "rotate" => {
                            let shared2 = shared.clone();
                            tauri::async_runtime::spawn(async move {
                                new_tor_identity();
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                let ip = fetch_tor_ip().await;
                                shared2.lock().unwrap().0.tor_ip = ip;
                                let (state, cfg) = shared2.lock().unwrap().clone();
                                rebuild_menu(&app, &state, &cfg);
                            });
                        }

                        "node_us" => { let cfg = toggle_cfg(&shared, |c| c.exclude_us = !c.exclude_us); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_gb" => { let cfg = toggle_cfg(&shared, |c| c.exclude_gb = !c.exclude_gb); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_au" => { let cfg = toggle_cfg(&shared, |c| c.exclude_au = !c.exclude_au); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_ca" => { let cfg = toggle_cfg(&shared, |c| c.exclude_ca = !c.exclude_ca); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_nz" => { let cfg = toggle_cfg(&shared, |c| c.exclude_nz = !c.exclude_nz); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_de" => { let cfg = toggle_cfg(&shared, |c| c.exclude_de = !c.exclude_de); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_fr" => { let cfg = toggle_cfg(&shared, |c| c.exclude_fr = !c.exclude_fr); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }

                        "rot_off" => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 0);  rot_tx.send(0).ok();  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "rot_5"   => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 5);  rot_tx.send(5).ok();  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "rot_15"  => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 15); rot_tx.send(15).ok(); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "rot_30"  => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 30); rot_tx.send(30).ok(); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }

                        "prot_ff" => {
                            let cfg = toggle_cfg(&shared, |c| c.firefox = !c.firefox);
                            let (state, _) = shared.lock().unwrap().clone();
                            if state.active { firefox_apply(cfg.firefox, &cfg); }
                            rebuild_menu(&app, &state, &cfg);
                        }
                        "prot_rfp" => {
                            let cfg = toggle_cfg(&shared, |c| c.resist_fp = !c.resist_fp);
                            let (state, _) = shared.lock().unwrap().clone();
                            if state.active && cfg.firefox { firefox_apply(true, &cfg); }
                            rebuild_menu(&app, &state, &cfg);
                        }
                        "prot_mac"  => { let cfg = toggle_cfg(&shared, |c| c.mac_spoof   = !c.mac_spoof);   let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_dns"  => { let cfg = toggle_cfg(&shared, |c| c.dns_leak    = !c.dns_leak);    let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_pf"   => { let cfg = toggle_cfg(&shared, |c| c.pf_firewall = !c.pf_firewall); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_logs" => { let cfg = toggle_cfg(&shared, |c| c.clear_logs  = !c.clear_logs);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_ua"   => { let cfg = toggle_cfg(&shared, |c| c.ua_spoof    = !c.ua_spoof);    let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_lang" => { let cfg = toggle_cfg(&shared, |c| c.lang_spoof  = !c.lang_spoof);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_spotify" => {
                            let cfg = toggle_cfg(&shared, |c| c.spotify_bypass = !c.spotify_bypass);
                            let (state, _) = shared.lock().unwrap().clone();
                            if state.active { proxy_enable(cfg.spotify_bypass); }
                            rebuild_menu(&app, &state, &cfg);
                        }

                        "login" => {
                            use tauri_plugin_autostart::ManagerExt;
                            let al = app.autolaunch();
                            if al.is_enabled().unwrap_or(false) { al.disable().ok(); }
                            else { al.enable().ok(); }
                            let (state, cfg) = shared.lock().unwrap().clone();
                            rebuild_menu(&app, &state, &cfg);
                        }

                        "quit" => {
                            let active = shared.lock().unwrap().0.active;
                            if active {
                                let cfg = shared.lock().unwrap().1.clone();
                                emergency_teardown(&cfg);
                            }
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            // IP reelle au demarrage
            let shared2 = shared.clone();
            let app2    = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                let ip = fetch_real_ip().await;
                let mut lock = shared2.lock().unwrap();
                lock.0.real_ip = ip;
                let (state, cfg) = lock.clone();
                drop(lock);
                rebuild_menu(&app2, &state, &cfg);
            });

            // Rotation automatique - timer reset immediat sur changement de config
            let shared3 = shared.clone();
            let app3    = app_handle.clone();
            let mut rot_rx = rot_rx;
            tauri::async_runtime::spawn(async move {
                loop {
                    let mins   = shared3.lock().unwrap().1.rotate_mins;
                    let active = shared3.lock().unwrap().0.active;
                    if mins == 0 || !active {
                        tokio::select! {
                            _ = rot_rx.changed() => {}
                            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                        }
                        continue;
                    }
                    let sleep = tokio::time::sleep(
                        std::time::Duration::from_secs(mins as u64 * 60)
                    );
                    tokio::pin!(sleep);
                    tokio::select! {
                        _ = &mut sleep => {
                            if shared3.lock().unwrap().0.active {
                                new_tor_identity();
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                let ip = fetch_tor_ip().await;
                                shared3.lock().unwrap().0.tor_ip = ip;
                                let (state, cfg) = shared3.lock().unwrap().clone();
                                rebuild_menu(&app3, &state, &cfg);
                            }
                        }
                        _ = rot_rx.changed() => {}
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("TorShield error");
}

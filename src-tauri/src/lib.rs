use std::process::Command;
use std::sync::{Arc, Mutex};
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder, CheckMenuItemBuilder},
    tray::TrayIconBuilder,
    AppHandle,
};
use tauri_plugin_autostart::MacosLauncher;

// ── SF Symbol icon generation ─────────────────────────────────────────────────

fn sf_symbol_png(symbol: &str, size: u32, out: &str) -> bool {
    let src = include_str!("gen_icon.m");
    let src_path = "/tmp/torshield_gen_icon.m";
    let bin_path = "/tmp/torshield_gen_icon";
    if std::fs::write(src_path, src).is_err() { return false; }
    if !std::path::Path::new(bin_path).exists() {
        let ok = Command::new("clang")
            .args(["-framework", "AppKit", "-framework", "Foundation",
                   src_path, "-o", bin_path, "-fobjc-arc"])
            .output().map(|o| o.status.success()).unwrap_or(false);
        if !ok { return false; }
    }
    Command::new(bin_path).args([symbol, out, &size.to_string()])
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
    pub rotate_mins:  u32,   // 0 = désactivé
    pub mac_spoof:    bool,
    pub dns_leak:     bool,  // dnsmasq over Tor
    pub pf_firewall:  bool,  // bloque tout non-Tor
    pub clear_logs:   bool,
    pub firefox:      bool,  // hardening Firefox activé
    pub resist_fp:    bool,  // resistFingerprinting (casse WebGL/canvas)
    pub ua_spoof:     bool,
    pub lang_spoof:   bool,
    pub launch_login: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exclude_us: true, exclude_gb: true, exclude_au: true,
            exclude_ca: true, exclude_nz: true, exclude_de: false, exclude_fr: false,
            rotate_mins: 0,
            mac_spoof: true, dns_leak: true, pf_firewall: false,
            clear_logs: true, firefox: true, resist_fp: false, ua_spoof: true, lang_spoof: true,
            launch_login: false,
        }
    }
}

impl Config {
    fn load() -> Self {
        let path = format!("{}/.config/opsec/torshield.json", std::env::var("HOME").unwrap_or_default());
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    fn save(&self) {
        let path = format!("{}/.config/opsec/torshield.json", std::env::var("HOME").unwrap_or_default());
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

fn sh(cmd: &str, args: &[&str]) {
    Command::new(cmd).args(args).output().ok();
}

fn get_network_services() -> Vec<String> {
    Command::new("networksetup").arg("-listallnetworkservices").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default().lines().skip(1).map(|l| l.to_string()).collect()
}

fn primary_interface() -> String {
    Command::new("route").args(["get", "default"]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find(|l| l.contains("interface:"))
            .map(|l| l.split_whitespace().last().unwrap_or("en0").to_string()))
        .unwrap_or_else(|| "en0".to_string())
}

fn tor_ready() -> bool {
    std::net::TcpStream::connect("127.0.0.1:9050").is_ok()
}

fn tor_pid() -> Option<u32> {
    std::fs::read_to_string(format!("{}/tor.pid", opsec_dir())).ok()
        .and_then(|s| s.trim().parse().ok())
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
    let dir   = opsec_dir();
    let data  = format!("{}/tor_data", dir);
    let conf  = format!("{}/torrc", dir);
    let pid   = format!("{}/tor.pid", dir);
    let log   = format!("{}/tor.log", dir);
    let cookie = format!("{}/tor_data/control_auth", dir);
    std::fs::create_dir_all(&cookie).ok();
    let excluded = cfg.excluded_nodes();
    let exclude_line = if excluded.is_empty() { String::new() }
        else { format!("ExcludeExitNodes {}\nStrictNodes 1\n", excluded) };
    std::fs::write(&conf, format!(
        "SocksPort 9050\nControlPort 9051\nCookieAuthentication 1\n\
         CookieAuthFile {cookie}/control_auth_cookie\n\
         DataDirectory {data}\nLog notice file {log}\n\
         MaxCircuitDirtiness 600\n{exclude_line}"
    )).ok();
    Command::new("tor").args(["-f", &conf, "--PidFile", &pid, "--RunAsDaemon", "1"]).spawn().is_ok()
}

fn stop_tor() {
    if let Some(pid) = tor_pid() { sh("kill", &[&pid.to_string()]); }
    std::fs::remove_file(format!("{}/tor.pid", opsec_dir())).ok();
}

fn new_tor_identity() {
    let cookie = format!("{}/tor_data/control_auth/control_auth_cookie", opsec_dir());
    let auth = std::fs::read(&cookie)
        .map(|b| b.iter().map(|x| format!("{:02x}", x)).collect::<String>())
        .unwrap_or_default();
    if let Ok(mut s) = std::net::TcpStream::connect("127.0.0.1:9051") {
        use std::io::Write;
        s.write_all(format!("AUTHENTICATE {}\r\nSIGNAL NEWNYM\r\nQUIT\r\n", auth).as_bytes()).ok();
    }
}

// ── Proxy système ─────────────────────────────────────────────────────────────

fn proxy_enable() {
    for svc in get_network_services() {
        sh("networksetup", &["-setsocksfirewallproxy", &svc, "127.0.0.1", "9050", "off"]);
        sh("networksetup", &["-setsocksfirewallproxystate", &svc, "on"]);
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

fn mac_spoof_enable() {
    let iface = primary_interface();
    // Génère une MAC random avec bit "locally administered" à 1
    let b = || -> u8 { (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
        .subsec_nanos() & 0xFF) as u8 };
    let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        (b() & 0xFE) | 0x02, b(), b(), b(), b(), b());
    sh("ifconfig", &[&iface, "ether", &mac]);
}

fn mac_spoof_restore() {
    // Recharge le HW MAC via networksetup (relink interface)
    let iface = primary_interface();
    sh("ifconfig", &[&iface, "down"]);
    sh("ifconfig", &[&iface, "up"]);
}

// ── DNS leak fix via dnsmasq ──────────────────────────────────────────────────

fn dns_leak_enable() {
    // Configure dnsmasq pour résoudre tout via Tor (127.0.0.1:9053)
    // Tor doit écouter sur DNSPort 9053
    let dir = opsec_dir();
    let dnsmasq_conf = format!("{}/dnsmasq.conf", dir);
    std::fs::write(&dnsmasq_conf,
        "no-resolv\nserver=127.0.0.1#9053\nlisten-address=127.0.0.1\nport=5353\n"
    ).ok();

    // Patch torrc pour ajouter DNSPort (si supporté par cette build)
    let torrc = format!("{}/torrc", dir);
    if let Ok(mut content) = std::fs::read_to_string(&torrc) {
        if !content.contains("DNSPort") {
            content.push_str("DNSPort 9053\n");
            std::fs::write(&torrc, &content).ok();
            // Reload tor
            if let Some(pid) = tor_pid() {
                sh("kill", &["-HUP", &pid.to_string()]);
            }
        }
    }

    // Lance dnsmasq
    if Command::new("which").arg("dnsmasq").output().map(|o| o.status.success()).unwrap_or(false) {
        Command::new("dnsmasq").args(["-C", &dnsmasq_conf, "--pid-file=/tmp/torshield_dnsmasq.pid"])
            .spawn().ok();
        // Force DNS système vers 127.0.0.1
        for svc in get_network_services() {
            sh("networksetup", &["-setdnsservers", &svc, "127.0.0.1"]);
        }
    }
}

fn dns_leak_disable() {
    // Arrête dnsmasq
    if let Ok(pid) = std::fs::read_to_string("/tmp/torshield_dnsmasq.pid") {
        sh("kill", &[pid.trim()]);
        std::fs::remove_file("/tmp/torshield_dnsmasq.pid").ok();
    }
    sh("pkill", &["-f", "dnsmasq.*torshield"]);
    // Remet DNS automatique
    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "empty"]);
    }
}

// ── pf firewall — kill switch ─────────────────────────────────────────────────

const PF_RULES: &str = r#"
# TorShield kill switch — tout doit passer par Tor
set skip on lo0
block all
pass out on en0 proto tcp to 127.0.0.1 port 9050 keep state
pass out on en0 proto tcp to any port 9050 keep state
pass out proto udp to any port 53 keep state
pass in all
"#;

fn pf_enable() {
    std::fs::write("/tmp/torshield_pf.conf", PF_RULES).ok();
    // Backup
    Command::new("pfctl").args(["-sr"]).output()
        .map(|o| std::fs::write("/tmp/torshield_pf_backup.txt", o.stdout).ok()).ok();
    sh("pfctl", &["-f", "/tmp/torshield_pf.conf", "-e"]);
}

fn pf_disable() {
    // Restore ou désactive simplement
    if std::path::Path::new("/tmp/torshield_pf_backup.txt").exists() {
        sh("pfctl", &["-f", "/tmp/torshield_pf_backup.txt"]);
    } else {
        sh("pfctl", &["-d"]);
    }
    std::fs::remove_file("/tmp/torshield_pf.conf").ok();
}

// ── Logs système ──────────────────────────────────────────────────────────────

fn clear_logs() {
    // Efface les logs unifiés macOS (nécessite root via sudo ou privileges)
    Command::new("log").args(["erase", "--all"]).output().ok();
    // Logs réseau
    std::fs::remove_dir_all(format!("{}/Library/Logs/CrashReporter",
        std::env::var("HOME").unwrap_or_default())).ok();
    // Tor log
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
user_pref("geo.enabled", false);
user_pref("geo.provider.use_corelocation", false);
user_pref("permissions.default.geo", 2);
user_pref("dom.battery.enabled", false);
user_pref("layout.css.prefers-color-scheme.content-override", 1);
user_pref("browser.startup.page", 3);
"#);
    p.push_str(&format!(
        "user_pref(\"privacy.resistFingerprinting\", {});\n",
        if resist_fp { "true" } else { "false" }
    ));
    if ua {
        p.push_str("user_pref(\"general.useragent.override\", \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0\");\n");
    }
    if lang {
        p.push_str("user_pref(\"intl.accept_languages\", \"en-US, en\");\n");
        p.push_str("user_pref(\"javascript.use_us_english_locale\", true);\n");
    }
    p
}

fn firefox_apply(enable: bool, cfg: &Config) {
    let home = std::env::var("HOME").unwrap_or_default();
    let ff = format!("{}/Library/Application Support/Firefox/Profiles", home);
    if !std::path::Path::new(&ff).is_dir() { return; }

    Command::new("osascript")
        .args(["-e", "tell application \"Firefox\" to quit"]).output().ok();
    std::thread::sleep(std::time::Duration::from_secs(2));

    let blocked = [
        "TorShield", "network.proxy", "media.peerconnection",
        "geo.", "permissions.default.geo", "dom.battery",
        "layout.css.prefers", "privacy.resistFingerprinting",
        "general.useragent.override", "intl.accept_languages",
        "javascript.use_us_english_locale",
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
            std::fs::write(&ujs, base + &firefox_prefs(cfg.ua_spoof, cfg.lang_spoof, cfg.resist_fp)).ok();
            if let Ok(p) = std::fs::read_to_string(&pjs) {
                let mut out = strip(&p);
                out.push_str("\nuser_pref(\"layout.css.prefers-color-scheme.content-override\", 1);\n");
                out.push_str(&format!("user_pref(\"privacy.resistFingerprinting\", {});\n",
                    if cfg.resist_fp { "true" } else { "false" }));
                if cfg.ua_spoof { out.push_str("user_pref(\"general.useragent.override\", \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0\");\n"); }
                if cfg.lang_spoof { out.push_str("user_pref(\"intl.accept_languages\", \"en-US, en\");\n"); }
                std::fs::write(&pjs, out).ok();
            }
        } else {
            if bak.exists() {
                std::fs::copy(&bak, &ujs).ok();
                std::fs::remove_file(&bak).ok();
            } else {
                std::fs::write(&ujs, strip(&std::fs::read_to_string(&ujs).unwrap_or_default())).ok();
            }
            if let Ok(mut c) = std::fs::read_to_string(&ujs) {
                c.push_str("\nuser_pref(\"layout.css.prefers-color-scheme.content-override\", 2);\n");
                std::fs::write(&ujs, c).ok();
            }
            if let Ok(p) = std::fs::read_to_string(&pjs) {
                let mut out = strip(&p);
                out.push_str("\nuser_pref(\"layout.css.prefers-color-scheme.content-override\", 2);\n");
                std::fs::write(&pjs, out).ok();
            }
        }
    }
    Command::new("open").args(["-a", "Firefox"]).spawn().ok();
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

    proxy_enable();
    ipv6_disable();
    if cfg.dns_leak    { dns_leak_enable(); }
    if cfg.pf_firewall { pf_enable(); }
    if cfg.firefox     { firefox_apply(true, &cfg); }

    let tor_ip  = fetch_tor_ip().await;
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
    if cfg.firefox     { firefox_apply(false, &cfg); }
    stop_tor();
    if cfg.mac_spoof { mac_spoof_restore(); }

    let real_ip = fetch_real_ip().await;

    let mut lock = shared.lock().unwrap();
    lock.0.active  = false;
    lock.0.tor_ip  = None;
    lock.0.real_ip = real_ip;
}

// ── Menu ──────────────────────────────────────────────────────────────────────

fn rebuild_menu(app: &AppHandle, state: &OpsecState, cfg: &Config) {
    use tauri_plugin_autostart::ManagerExt;
    let active  = state.active;
    let tor_ip  = state.tor_ip.clone().unwrap_or_else(|| "—".into());
    let real_ip = state.real_ip.clone().unwrap_or_else(|| "—".into());

    let mk  = |id: &str, label: &str| MenuItemBuilder::new(label).id(id).build(app).unwrap();
    let mkd = |id: &str, label: &str| MenuItemBuilder::new(label).id(id).enabled(false).build(app).unwrap();
    let chk = |id: &str, label: &str, checked: bool|
        CheckMenuItemBuilder::new(label).id(id).checked(checked).build(app).unwrap();

    // ── Status ──
    let status_label = if active { format!("● Actif  —  {}", tor_ip) } else { "○ Inactif".into() };
    let item_status  = mkd("status", &status_label);
    let item_real    = mkd("real_ip", &format!("IP réelle : {}  (masquée)", real_ip));

    // ── Actions ──
    let item_toggle  = mk("toggle",  if active { "Désactiver OPSEC" } else { "Activer OPSEC" });
    let item_rotate  = MenuItemBuilder::new("Nouvelle identité Tor")
        .id("rotate").enabled(active).build(app).unwrap();

    // ── Sous-menu Exit nodes ──
    let sub_nodes = SubmenuBuilder::new(app, "Pays exclus (exit nodes)")
        .item(&chk("node_us", "🇺🇸  États-Unis",    cfg.exclude_us))
        .item(&chk("node_gb", "🇬🇧  Royaume-Uni",   cfg.exclude_gb))
        .item(&chk("node_au", "🇦🇺  Australie",     cfg.exclude_au))
        .item(&chk("node_ca", "🇨🇦  Canada",         cfg.exclude_ca))
        .item(&chk("node_nz", "🇳🇿  Nouvelle-Zélande", cfg.exclude_nz))
        .item(&chk("node_de", "🇩🇪  Allemagne",     cfg.exclude_de))
        .item(&chk("node_fr", "🇫🇷  France",         cfg.exclude_fr))
        .build().unwrap();

    // ── Sous-menu Rotation ──
    let rot_label = match cfg.rotate_mins {
        0   => "Rotation auto : désactivée",
        5   => "Rotation auto : 5 min ✓",
        15  => "Rotation auto : 15 min ✓",
        30  => "Rotation auto : 30 min ✓",
        _   => "Rotation auto",
    };
    let sub_rotate = SubmenuBuilder::new(app, rot_label)
        .item(&chk("rot_off", "Désactivée",    cfg.rotate_mins == 0))
        .item(&chk("rot_5",   "Toutes les 5 min",  cfg.rotate_mins == 5))
        .item(&chk("rot_15",  "Toutes les 15 min", cfg.rotate_mins == 15))
        .item(&chk("rot_30",  "Toutes les 30 min", cfg.rotate_mins == 30))
        .build().unwrap();

    // ── Sous-menu Protections ──
    let sub_prot = SubmenuBuilder::new(app, "Protections")
        .item(&chk("prot_ff",   "Firefox (proxy + WebRTC off)",   cfg.firefox))
        .item(&chk("prot_rfp",  "Firefox resistFingerprinting ⚠", cfg.resist_fp))
        .item(&chk("prot_mac",  "Spoofing MAC",                   cfg.mac_spoof))
        .item(&chk("prot_dns",  "Anti DNS leak (dnsmasq)",      cfg.dns_leak))
        .item(&chk("prot_pf",   "Kill switch (pf firewall)",    cfg.pf_firewall))
        .item(&chk("prot_logs", "Effacer logs au démarrage",    cfg.clear_logs))
        .item(&chk("prot_ua",   "User-Agent Windows/Firefox",   cfg.ua_spoof))
        .item(&chk("prot_lang", "Langue neutre (en-US)",        cfg.lang_spoof))
        .build().unwrap();

    // ── Démarrage auto ──
    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let item_login = chk("login", "Lancer au démarrage", autostart_on);

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
        .separator()
        .item(&item_login)
        .separator()
        .item(&mk("quit", "Quitter TorShield"))
        .build().unwrap();

    if let Some(tray) = app.tray_by_id("main") {
        tray.set_menu(Some(menu)).ok();
        let icon_path = if active { "/tmp/torshield_on.png" } else { "/tmp/torshield_off.png" };
        if let Ok(bytes) = std::fs::read(icon_path) {
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
    let shared: Shared = Arc::new(Mutex::new((OpsecState::default(), cfg)));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec![])))
        .manage(shared.clone())
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Icônes SF Symbols
            sf_symbol_png("shield",           18, "/tmp/torshield_off.png");
            sf_symbol_png("lock.shield.fill", 18, "/tmp/torshield_on.png");
            if !std::path::Path::new("/tmp/torshield_off.png").exists() {
                std::fs::write("/tmp/torshield_off.png", include_bytes!("../icons/tray_off.png")).ok();
                std::fs::write("/tmp/torshield_on.png",  include_bytes!("../icons/tray_on.png")).ok();
            }

            let icon_bytes = std::fs::read("/tmp/torshield_off.png")
                .unwrap_or_else(|_| include_bytes!("../icons/tray_off.png").to_vec());
            let icon = Image::from_bytes(&icon_bytes)?;

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
                    match event.id().as_ref() {

                        // ── Toggle principal ──
                        "toggle" => {
                            let is_active = shared.lock().unwrap().0.active;
                            tauri::async_runtime::spawn(async move {
                                if is_active { do_disable(&shared).await; }
                                else         { do_enable(&shared).await;  }
                                let (state, cfg) = shared.lock().unwrap().clone();
                                rebuild_menu(&app, &state, &cfg);
                            });
                        }

                        // ── Rotation manuelle ──
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

                        // ── Exit nodes ──
                        "node_us" => { let cfg = toggle_cfg(&shared, |c| c.exclude_us = !c.exclude_us); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_gb" => { let cfg = toggle_cfg(&shared, |c| c.exclude_gb = !c.exclude_gb); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_au" => { let cfg = toggle_cfg(&shared, |c| c.exclude_au = !c.exclude_au); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_ca" => { let cfg = toggle_cfg(&shared, |c| c.exclude_ca = !c.exclude_ca); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_nz" => { let cfg = toggle_cfg(&shared, |c| c.exclude_nz = !c.exclude_nz); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_de" => { let cfg = toggle_cfg(&shared, |c| c.exclude_de = !c.exclude_de); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "node_fr" => { let cfg = toggle_cfg(&shared, |c| c.exclude_fr = !c.exclude_fr); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }

                        // ── Rotation auto ──
                        "rot_off" => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 0);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "rot_5"   => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 5);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "rot_15"  => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 15); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "rot_30"  => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 30); let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }

                        // ── Protections ──
                        "prot_ff" => {
                            let cfg = toggle_cfg(&shared, |c| c.firefox = !c.firefox);
                            let (state, _) = shared.lock().unwrap().clone();
                            // applique immédiatement si OPSEC déjà actif
                            if state.active { firefox_apply(cfg.firefox, &cfg); }
                            rebuild_menu(&app, &state, &cfg);
                        }
                        "prot_rfp" => {
                            let cfg = toggle_cfg(&shared, |c| c.resist_fp = !c.resist_fp);
                            let (state, _) = shared.lock().unwrap().clone();
                            if state.active && cfg.firefox { firefox_apply(true, &cfg); }
                            rebuild_menu(&app, &state, &cfg);
                        }
                        "prot_mac"  => { let cfg = toggle_cfg(&shared, |c| c.mac_spoof    = !c.mac_spoof);    let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_dns"  => { let cfg = toggle_cfg(&shared, |c| c.dns_leak     = !c.dns_leak);     let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_pf"   => { let cfg = toggle_cfg(&shared, |c| c.pf_firewall  = !c.pf_firewall);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_logs" => { let cfg = toggle_cfg(&shared, |c| c.clear_logs   = !c.clear_logs);   let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_ua"   => { let cfg = toggle_cfg(&shared, |c| c.ua_spoof     = !c.ua_spoof);     let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_lang" => { let cfg = toggle_cfg(&shared, |c| c.lang_spoof   = !c.lang_spoof);   let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }

                        // ── Login ──
                        "login" => {
                            use tauri_plugin_autostart::ManagerExt;
                            let al = app.autolaunch();
                            if al.is_enabled().unwrap_or(false) { al.disable().ok(); }
                            else { al.enable().ok(); }
                            let (state, cfg) = shared.lock().unwrap().clone();
                            rebuild_menu(&app, &state, &cfg);
                        }

                        // ── Quit ──
                        "quit" => {
                            let active = shared.lock().unwrap().0.active;
                            if active {
                                let cfg = shared.lock().unwrap().1.clone();
                                if cfg.pf_firewall  { pf_disable(); }
                                if cfg.dns_leak     { dns_leak_disable(); }
                                proxy_disable(); ipv6_restore();
                                if cfg.firefox { firefox_apply(false, &cfg); }
                                stop_tor();
                                if cfg.mac_spoof { mac_spoof_restore(); }
                            }
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            // IP réelle au démarrage
            let shared2   = shared.clone();
            let app2      = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                let ip = fetch_real_ip().await;
                let mut lock = shared2.lock().unwrap();
                lock.0.real_ip = ip;
                let (state, cfg) = lock.clone();
                drop(lock);
                rebuild_menu(&app2, &state, &cfg);
            });

            // Rotation automatique si configurée
            let shared3 = shared.clone();
            let app3    = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    let mins = shared3.lock().unwrap().1.rotate_mins;
                    if mins > 0 && shared3.lock().unwrap().0.active {
                        tokio::time::sleep(std::time::Duration::from_secs(mins as u64 * 60)).await;
                        new_tor_identity();
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        let ip = fetch_tor_ip().await;
                        shared3.lock().unwrap().0.tor_ip = ip;
                        let (state, cfg) = shared3.lock().unwrap().clone();
                        rebuild_menu(&app3, &state, &cfg);
                    } else {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("TorShield error");
}

use std::process::Command;
use tauri::{
    image::Image,
    menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder, CheckMenuItemBuilder},
    AppHandle,
};

use crate::config::{Config, OpsecState, Shared};
use crate::helper::{helper_ok, icon_path};
use crate::tor::tor_ready;

pub fn rebuild_menu(app: &AppHandle, state: &OpsecState, cfg: &Config) {
    use tauri_plugin_autostart::ManagerExt;
    let active  = state.active;
    let tor_ip  = state.tor_ip.clone().unwrap_or_else(|| "—".into());
    let real_ip = state.real_ip.clone().unwrap_or_else(|| "—".into());

    let mk  = |id: &str, label: &str|
        MenuItemBuilder::new(label).id(id).build(app).unwrap();
    let mkd = |id: &str, label: &str|
        MenuItemBuilder::new(label).id(id).enabled(false).build(app).unwrap();
    let chk = |id: &str, label: &str, checked: bool|
        CheckMenuItemBuilder::new(label).id(id).checked(checked).build(app).unwrap();

    // Header
    let version_label = format!("TorShield  v{}", env!("CARGO_PKG_VERSION"));

    // Status block
    let (status_label, real_label) = if active {
        (
            format!("Connected  |  Exit: {}", tor_ip),
            format!("Real IP: {}  (concealed)", real_ip),
        )
    } else {
        (
            "Disconnected".into(),
            format!("Real IP: {}", real_ip),
        )
    };

    let item_status = mkd("status",  &status_label);
    let item_real   = mkd("real_ip", &real_label);

    // Dependencies
    let tor_ok_     = tor_ready();
    let helper_ok__ = helper_ok();
    let dnsmasq_bin = ["/opt/homebrew/sbin/dnsmasq", "/usr/local/sbin/dnsmasq", "/usr/sbin/dnsmasq"]
        .iter().any(|p| std::path::Path::new(p).exists());
    let clang_ok    = Command::new("clang").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false);

    let dep_status = |ok: bool, ok_label: &str, fix: &str| -> String {
        if ok {
            format!("[OK]  {ok_label}")
        } else {
            format!("[!]   {fix}")
        }
    };

    let sub_deps = SubmenuBuilder::new(app, "Dependencies")
        .item(&mkd("dep_helper",  &dep_status(helper_ok__, "ts_helper", "brew install? (run TorShield)")))
        .item(&mkd("dep_tor",     &dep_status(tor_ok_,     "Tor",       "brew install tor")))
        .item(&mkd("dep_dnsmasq", &dep_status(dnsmasq_bin, "dnsmasq",   "brew install dnsmasq")))
        .item(&mkd("dep_clang",   &dep_status(clang_ok,    "clang",     "xcode-select --install")))
        .build().unwrap();

    // Primary action
    let item_toggle = mk("toggle", if active { "Disconnect" } else { "Connect" });
    let item_rotate = MenuItemBuilder::new("New Identity")
        .id("rotate").enabled(active).build(app).unwrap();

    // Excluded exit nodes
    let sub_nodes = SubmenuBuilder::new(app, "Exclude Exit Nodes")
        .item(&chk("node_us", "United States  (US)", cfg.exclude_us))
        .item(&chk("node_gb", "United Kingdom  (GB)", cfg.exclude_gb))
        .item(&chk("node_au", "Australia  (AU)",      cfg.exclude_au))
        .item(&chk("node_ca", "Canada  (CA)",         cfg.exclude_ca))
        .item(&chk("node_nz", "New Zealand  (NZ)",    cfg.exclude_nz))
        .item(&chk("node_de", "Germany  (DE)",        cfg.exclude_de))
        .item(&chk("node_fr", "France  (FR)",         cfg.exclude_fr))
        .build().unwrap();

    // Identity rotation
    let rot_label = match cfg.rotate_mins {
        0  => "Identity Rotation: Off",
        2  => "Identity Rotation: 2 min",
        5  => "Identity Rotation: 5 min",
        15 => "Identity Rotation: 15 min",
        30 => "Identity Rotation: 30 min",
        _  => "Identity Rotation",
    };
    let sub_rotate = SubmenuBuilder::new(app, rot_label)
        .item(&chk("rot_off", "Disabled",       cfg.rotate_mins == 0))
        .item(&chk("rot_2",   "Every 2 min",    cfg.rotate_mins == 2))
        .item(&chk("rot_5",   "Every 5 min",    cfg.rotate_mins == 5))
        .item(&chk("rot_15",  "Every 15 min",   cfg.rotate_mins == 15))
        .item(&chk("rot_30",  "Every 30 min",   cfg.rotate_mins == 30))
        .build().unwrap();

    // Protections
    let sub_prot = SubmenuBuilder::new(app, "Protections")
        .item(&chk("prot_ff",   "Firefox Hardening",         cfg.firefox))
        .item(&chk("prot_rfp",  "Fingerprint Resistance",    cfg.resist_fp))
        .item(&chk("prot_mac",  "MAC Address Randomization", cfg.mac_spoof))
        .item(&chk("prot_dns",  "DNS Leak Protection",       cfg.dns_leak))
        .item(&chk("prot_pf",   "Kill Switch",               cfg.pf_firewall))
        .item(&chk("prot_logs", "Purge Logs on Connect",     cfg.clear_logs))
        .item(&chk("prot_ua",   "Spoof User-Agent",          cfg.ua_spoof))
        .build().unwrap();

    // Advanced
    let sub_adv = SubmenuBuilder::new(app, "Advanced")
        .item(&chk("prot_lang", "Force English Locale",       cfg.lang_spoof))
        .item(&chk("prot_env",  "Proxy Env Vars (CLI tools)", cfg.env_inject))
        .build().unwrap();

    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let item_login   = chk("login", "Launch at Login", autostart_on);

    let menu = MenuBuilder::new(app)
        .item(&mkd("version", &version_label))
        .item(&item_status)
        .item(&item_real)
        .separator()
        .item(&item_toggle)
        .item(&item_rotate)
        .separator()
        .item(&sub_nodes)
        .item(&sub_rotate)
        .item(&sub_prot)
        .item(&sub_adv)
        .item(&sub_deps)
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

pub fn toggle_cfg<F: FnOnce(&mut Config)>(shared: &Shared, f: F) -> Config {
    let mut lock = shared.lock().unwrap();
    f(&mut lock.1);
    let cfg = lock.1.clone();
    drop(lock);
    cfg.save();
    cfg
}

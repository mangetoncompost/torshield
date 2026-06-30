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
    let tor_ip  = state.tor_ip.clone().unwrap_or_else(|| "-".into());
    let real_ip = state.real_ip.clone().unwrap_or_else(|| "-".into());

    let mk  = |id: &str, label: &str|
        MenuItemBuilder::new(label).id(id).build(app).unwrap();
    let mkd = |id: &str, label: &str|
        MenuItemBuilder::new(label).id(id).enabled(false).build(app).unwrap();
    let chk = |id: &str, label: &str, checked: bool|
        CheckMenuItemBuilder::new(label).id(id).checked(checked).build(app).unwrap();

    let status_label  = if active { format!("Active - {}", tor_ip) } else { "Inactive".into() };
    let version_label = format!("TorShield v{}", env!("CARGO_PKG_VERSION"));
    let item_status   = mkd("status",  &status_label);
    let item_real     = mkd("real_ip", &format!("Real IP: {}  (hidden)", real_ip));

    let tor_ok_     = tor_ready();
    let helper_ok__ = helper_ok();
    let dnsmasq_bin = ["/opt/homebrew/sbin/dnsmasq", "/usr/local/sbin/dnsmasq", "/usr/sbin/dnsmasq"]
        .iter().any(|p| std::path::Path::new(p).exists());
    let clang_ok    = Command::new("clang").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false);

    let sub_deps = SubmenuBuilder::new(app, "Dependencies")
        .item(&mkd("dep_helper",  &format!("{} ts_helper (root commands)",
            if helper_ok__ { "+" } else { "! install needed" })))
        .item(&mkd("dep_tor",     &format!("{} tor",
            if tor_ok_     { "+" } else { "! brew install tor" })))
        .item(&mkd("dep_dnsmasq", &format!("{} dnsmasq (DNS leak fix)",
            if dnsmasq_bin { "+" } else { "! brew install dnsmasq" })))
        .item(&mkd("dep_clang",   &format!("{} clang (helper compiler)",
            if clang_ok    { "+" } else { "! xcode-select --install" })))
        .build().unwrap();

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

    let sub_prot = SubmenuBuilder::new(app, "Protections")
        .item(&chk("prot_ff",   "Firefox (proxy + WebRTC off)", cfg.firefox))
        .item(&chk("prot_rfp",  "Firefox resistFingerprinting", cfg.resist_fp))
        .item(&chk("prot_mac",  "MAC spoofing",                 cfg.mac_spoof))
        .item(&chk("prot_dns",  "DNS leak fix (dnsmasq)",       cfg.dns_leak))
        .item(&chk("prot_pf",   "Kill switch (pf firewall)",    cfg.pf_firewall))
        .item(&chk("prot_logs", "Clear logs on start",          cfg.clear_logs))
        .item(&chk("prot_ua",   "Spoof User-Agent (Windows)",   cfg.ua_spoof))
        .build().unwrap();

    let sub_dev = SubmenuBuilder::new(app, "Dev / Scripts")
        .item(&chk("prot_lang", "Neutral language (en-US)",       cfg.lang_spoof))
        .item(&chk("prot_env",  "Env vars (Python/curl/wget/Go)", cfg.env_inject))
        .build().unwrap();

    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let item_login   = chk("login", "Launch at login", autostart_on);

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
        .item(&sub_dev)
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

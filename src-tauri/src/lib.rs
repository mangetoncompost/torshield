mod config;
mod firewall;
mod firefox;
mod helper;
mod mac_spoof;
mod menu;
mod proxy;
mod tor;

use std::sync::{Arc, Mutex};
use tauri::{image::Image, tray::TrayIconBuilder};
use tauri_plugin_autostart::MacosLauncher;
use tokio::sync::watch;

use config::{Config, OpsecState, Shared};
use firewall::{pf_disable, pf_enable, ensure_watchdog};
use firefox::{ensure_canvasblocker, firefox_apply};
use helper::{clear_logs, ensure_helper, ensure_opsec_dir, icon_path, lock_path, notify, opsec_dir, sf_symbol_png};
use mac_spoof::{mac_spoof_enable, mac_spoof_restore, mac_spoof_rotate};
use menu::{rebuild_menu, toggle_cfg};
use proxy::{dns_leak_disable, dns_leak_enable, env_inject_disable, env_inject_enable,
            hostname_anonymize, hostname_restore, hostname_rotate,
            ipv6_disable, ipv6_restore, proxy_disable, proxy_enable};
use tor::{fetch_real_ip, fetch_tor_ip, local_real_ip, new_tor_identity, start_tor, stop_tor, tor_ready};

async fn do_enable(shared: &Shared) {
    let cfg = shared.lock().unwrap().1.clone();

    if cfg.clear_logs { clear_logs(); }
    // IPv6 disabled before MAC spoof: ifconfig down/up triggers NDP Router
    // Solicitations that may expose the fe80:: link-local (EUI-64 derived) before
    // the interface comes back up. Disabling IPv6 first prevents those packets.
    ipv6_disable();
    if cfg.mac_spoof  { mac_spoof_enable(); }

    start_tor(&cfg);
    let mut waited = 0u8;
    while !tor_ready() && waited < 30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        waited += 1;
    }

    if !tor_ready() {
        notify("Connection Failed", "Tor did not start - check that Tor is installed");
        return;
    }

    proxy_enable();
    hostname_anonymize();
    if cfg.dns_leak    { dns_leak_enable(); }
    if cfg.pf_firewall { pf_enable(); }
    if cfg.env_inject  { env_inject_enable(); }

    ensure_opsec_dir();
    std::fs::write(lock_path(), "").ok();

    if cfg.firefox {
        let home = std::env::var("HOME").unwrap_or_default();
        let ff = format!("{}/Library/Application Support/Firefox/Profiles", home);
        ensure_canvasblocker(&ff).await;
        firefox_apply(true, &cfg);
    }

    let tor_ip = fetch_tor_ip().await;

    let notif_body = match &tor_ip {
        Some(ip) => format!("Exit node: {ip}"),
        None     => "Connected via Tor".into(),
    };
    notify("Connected", &notif_body);

    let mut lock = shared.lock().unwrap();
    lock.0.active = true;
    lock.0.tor_ip = tor_ip;
}

async fn do_disable(shared: &Shared) {
    let cfg = shared.lock().unwrap().1.clone();

    if cfg.pf_firewall { pf_disable(); }
    if cfg.dns_leak    { dns_leak_disable(); }
    if cfg.env_inject  { env_inject_disable(); }
    proxy_disable();
    hostname_restore();
    ipv6_restore();
    if cfg.firefox { firefox_apply(false, &cfg); }
    stop_tor();
    if cfg.mac_spoof { mac_spoof_restore(); }

    std::fs::remove_file(lock_path()).ok();
    notify("Disconnected", "All protections off");

    let real_ip = fetch_real_ip().await.or_else(local_real_ip);

    let mut lock = shared.lock().unwrap();
    lock.0.active  = false;
    lock.0.tor_ip  = None;
    lock.0.real_ip = real_ip;
}

fn emergency_teardown(cfg: &Config) {
    if cfg.pf_firewall { pf_disable(); }
    if cfg.dns_leak    { dns_leak_disable(); }
    if cfg.env_inject  { env_inject_disable(); }
    proxy_disable();
    hostname_restore();
    ipv6_restore();
    if cfg.firefox     { firefox_apply(false, cfg); }
    stop_tor();
    if cfg.mac_spoof   { mac_spoof_restore(); }
    std::fs::remove_file(lock_path()).ok();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let cfg = Config::load();

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

            ensure_helper(app);
            ensure_watchdog();
            pf_disable();

            ensure_opsec_dir();
            let _ = std::fs::remove_file(format!("{}/gen_icon", opsec_dir()));
            sf_symbol_png("shield",           18, &icon_path(false));
            sf_symbol_png("lock.shield.fill", 18, &icon_path(true));

            let icon = std::fs::read(icon_path(false))
                .ok()
                .and_then(|b| Image::from_bytes(&b).ok())
                .unwrap_or_else(|| Image::new_owned(vec![0u8; 18 * 18 * 4], 18, 18));

            let shared_ref  = shared.clone();
            let app_handle  = app.handle().clone();

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
                                let cfg = shared2.lock().unwrap().1.clone();
                                new_tor_identity();
                                if cfg.mac_spoof  { mac_spoof_rotate(); }
                                hostname_rotate();
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                let ip = fetch_tor_ip().await;
                                if let Some(ref exit) = ip {
                                    notify("New Identity", &format!("Exit node: {exit}"));
                                } else {
                                    notify("New Identity", "Circuit rotated");
                                }
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
                        "rot_2"   => { let cfg = toggle_cfg(&shared, |c| c.rotate_mins = 2);  rot_tx.send(2).ok();  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
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
                        "prot_pf"   => {
                            let cfg = toggle_cfg(&shared, |c| c.pf_firewall = !c.pf_firewall);
                            let (state, _) = shared.lock().unwrap().clone();
                            if state.active {
                                if cfg.pf_firewall { pf_enable(); }
                                else               { pf_disable(); }
                            }
                            rebuild_menu(&app, &state, &cfg);
                        }
                        "prot_logs" => { let cfg = toggle_cfg(&shared, |c| c.clear_logs  = !c.clear_logs);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_ua"   => { let cfg = toggle_cfg(&shared, |c| c.ua_spoof    = !c.ua_spoof);    let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_lang"      => { let cfg = toggle_cfg(&shared, |c| c.lang_spoof  = !c.lang_spoof);  let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_snowflake" => { let cfg = toggle_cfg(&shared, |c| c.snowflake   = !c.snowflake);   let s = shared.lock().unwrap().0.clone(); rebuild_menu(&app, &s, &cfg); }
                        "prot_env"  => {
                            let cfg = toggle_cfg(&shared, |c| c.env_inject = !c.env_inject);
                            let (state, _) = shared.lock().unwrap().clone();
                            if state.active {
                                if cfg.env_inject { env_inject_enable(); }
                                else              { env_inject_disable(); }
                            }
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

            // Show local IP immediately (no network), then fetch public IP in background
            // and update the menu when it arrives.
            {
                let ip = local_real_ip();
                let mut lock = shared.lock().unwrap();
                lock.0.real_ip = ip;
                let (state, cfg) = lock.clone();
                drop(lock);
                rebuild_menu(&app_handle, &state, &cfg);
            }
            {
                let shared_ip = shared.clone();
                let app_ip    = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(ip) = fetch_real_ip().await {
                        let mut lock = shared_ip.lock().unwrap();
                        if !lock.0.active {
                            lock.0.real_ip = Some(ip);
                            let (state, cfg) = lock.clone();
                            drop(lock);
                            rebuild_menu(&app_ip, &state, &cfg);
                        }
                    }
                });
            }

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
                            let (is_active, cfg) = {
                                let lock = shared3.lock().unwrap();
                                (lock.0.active, lock.1.clone())
                            };
                            if is_active {
                                new_tor_identity();
                                if cfg.mac_spoof  { mac_spoof_rotate(); }
                                hostname_rotate();
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                let ip = fetch_tor_ip().await;
                                if let Some(ref exit) = ip {
                                    notify("Identity Rotated", &format!("Exit node: {exit}"));
                                } else {
                                    notify("Identity Rotated", "New circuit active");
                                }
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

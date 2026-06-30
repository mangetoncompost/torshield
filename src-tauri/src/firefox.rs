use std::process::Command;

use crate::config::Config;

const CANVASBLOCKER_ID: &str = "{bc3b3d9e-b4eb-41ae-b0b6-3de78bd66f6e}";
const CANVASBLOCKER_URL: &str =
    "https://addons.mozilla.org/firefox/downloads/latest/canvasblocker/latest.xpi";

use crate::helper::opsec_dir;

fn firefox_version() -> String {
    let ver = Command::new("/Applications/Firefox.app/Contents/MacOS/firefox")
        .arg("--version").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .or_else(|| {
            Command::new("defaults")
                .args(["read", "/Applications/Firefox.app/Contents/Info.plist",
                       "CFBundleShortVersionString"])
                .output().ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let maj_min: String = ver.split('.').take(2)
        .collect::<Vec<_>>().join(".");
    if maj_min.is_empty() { "128.0".to_string() } else { maj_min }
}

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
user_pref("network.http.http3.enabled", false);
user_pref("network.http.http2.enabled", true);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.prefetch-next", false);
user_pref("browser.send_pings", false);
user_pref("media.navigator.enabled", false);
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
        let ver = firefox_version();
        let rv  = ver.split('.').next().unwrap_or("128");
        p.push_str(&format!(
            "user_pref(\"general.useragent.override\", \
             \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{rv}.0) \
             Gecko/20100101 Firefox/{ver}\");\n"
        ));
    }
    if lang {
        p.push_str("user_pref(\"intl.accept_languages\", \"en-US, en\");\n");
        p.push_str("user_pref(\"javascript.use_us_english_locale\", true);\n");
    }
    p
}

fn firefox_running() -> bool {
    Command::new("pgrep").args(["-ix", "firefox"]).output()
        .map(|o| o.status.success()).unwrap_or(false)
}

pub async fn ensure_canvasblocker(ff_profiles: &str) {
    let xpi_cache = format!("{}/canvasblocker.xpi", opsec_dir());
    if !std::path::Path::new(&xpi_cache).exists() {
        let Ok(client) = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").unwrap())
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

pub fn firefox_apply(enable: bool, cfg: &Config) {
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
        "network.http.http3", "network.http.http2.enabled",
        "network.dns.disablePrefetch", "network.prefetch-next",
        "browser.send_pings", "media.navigator.enabled",
        "browser.startup.page",
    ];

    // Exact prefix match on user_pref("...") lines only - avoids stripping
    // third-party prefs whose name accidentally contains a blocked substring.
    let strip = |content: &str| -> String {
        content.lines()
            .filter(|l| {
                let t = l.trim_start();
                if !t.starts_with("user_pref(\"") { return true; }
                let name_start = "user_pref(\"".len();
                let name = &t[name_start..];
                !blocked.iter().any(|b| name.starts_with(b))
            })
            .collect::<Vec<_>>().join("\n")
    };

    for entry in std::fs::read_dir(&ff).into_iter().flatten().flatten() {
        if !entry.path().is_dir() { continue; }
        let ujs = entry.path().join("user.js");
        let pjs = entry.path().join("prefs.js");
        let bak = entry.path().join("user.js.opsec_bak");

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
                    let ver = firefox_version();
                    let rv  = ver.split('.').next().unwrap_or("128");
                    out.push_str(&format!(
                        "user_pref(\"general.useragent.override\", \
                         \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{rv}.0) \
                         Gecko/20100101 Firefox/{ver}\");\n"
                    ));
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

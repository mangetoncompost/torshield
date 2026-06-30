use std::process::Command;
use tauri::Manager;

pub const TS_HELPER: &str = "/usr/local/bin/ts_helper";

pub fn opsec_dir() -> String {
    format!("{}/.config/opsec", std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

pub fn icon_path(active: bool) -> String {
    format!("{}/{}", opsec_dir(), if active { "icon_on.png" } else { "icon_off.png" })
}

pub fn lock_path() -> String {
    format!("{}/active.lock", opsec_dir())
}

pub fn sh(cmd: &str, args: &[&str]) {
    Command::new(cmd).args(args).output().ok();
}

pub fn root(cmd: &str, args: &[&str]) {
    let mut full = vec![cmd];
    full.extend_from_slice(args);
    Command::new(TS_HELPER).args(&full).output().ok();
}

pub fn rand_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("getrandom failed");
    buf
}

pub fn get_network_services() -> Vec<String> {
    Command::new("networksetup").arg("-listallnetworkservices").output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with('*'))
        .map(|l| l.to_string())
        .collect()
}

pub fn primary_interface() -> String {
    Command::new("route").args(["get", "default"]).output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().find(|l| l.contains("interface:"))
            .map(|l| l.split_whitespace().last().unwrap_or("en0").to_string()))
        .unwrap_or_else(|| "en0".to_string())
}

pub fn clear_logs() {
    Command::new("log").args(["erase", "--all"]).output().ok();
    std::fs::remove_dir_all(format!("{}/Library/Logs/CrashReporter",
        std::env::var("HOME").unwrap_or_default())).ok();
    std::fs::write(format!("{}/tor.log", opsec_dir()), "").ok();
}

pub fn helper_ok() -> bool {
    use std::os::unix::fs::MetadataExt;
    let path = std::path::Path::new(TS_HELPER);
    match std::fs::metadata(path) {
        Ok(m) => m.uid() == 0 && (m.mode() & 0o4000 != 0),
        Err(_) => false,
    }
}

pub fn ensure_helper(app: &tauri::App) {
    if helper_ok() { return; }

    let bundle_src = app.path()
        .resource_dir()
        .ok()
        .map(|d| d.join("ts_helper.c"))
        .filter(|p| p.exists());

    let tmp_bin_file = match tempfile::Builder::new()
        .prefix("ts_helper_")
        .tempfile_in("/tmp")
    {
        Ok(f) => f,
        Err(_) => return,
    };
    let tmp_bin_path = tmp_bin_file.path().to_path_buf();
    drop(tmp_bin_file);

    let compiled = match bundle_src {
        Some(ref p) => {
            Command::new("clang")
                .args([p.to_str().unwrap_or(""), "-o", tmp_bin_path.to_str().unwrap_or("")])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        None => {
            let src_tmp = match tempfile::Builder::new()
                .prefix("ts_helper_src_")
                .suffix(".c")
                .tempfile_in("/tmp")
            {
                Ok(f) => f,
                Err(_) => return,
            };
            let src_path = src_tmp.path().to_path_buf();
            if std::fs::write(&src_path, include_str!("ts_helper.c")).is_err() { return; }
            let ok = Command::new("clang")
                .args([src_path.to_str().unwrap_or(""), "-o", tmp_bin_path.to_str().unwrap_or("")])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            ok
        }
    };

    if !compiled { return; }

    let meta = std::fs::symlink_metadata(&tmp_bin_path);
    let is_regular = meta.map(|m| m.file_type().is_file()).unwrap_or(false);
    if !is_regular { return; }

    let tmp_str = tmp_bin_path.to_string_lossy();
    let script = format!(
        "do shell script \
         \"cp '{tmp}' '{dst}' && chown root:wheel '{dst}' && chmod 4755 '{dst}'\" \
         with administrator privileges",
        tmp = tmp_str.replace('\'', "'\\''"),
        dst = TS_HELPER,
    );
    Command::new("osascript").args(["-e", &script]).output().ok();
    std::fs::remove_file(&tmp_bin_path).ok();
}

pub fn sf_symbol_png(symbol: &str, size: u32, out: &str) -> bool {
    let src      = include_str!("gen_icon.m");
    let src_path = format!("{}/gen_icon.m", opsec_dir());
    let bin_path = format!("{}/gen_icon",   opsec_dir());
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

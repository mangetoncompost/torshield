use std::process::Command;
use tauri::Manager;

pub const TS_HELPER: &str = "/usr/local/bin/ts_helper";

pub fn opsec_dir() -> String {
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        // If HOME is unset (early-boot LaunchAgent), resolve from passwd database
        // rather than falling back to /tmp (world-listable) to keep secrets private (MED-7).
        _ => home_from_passwd().unwrap_or_else(|| "/tmp".into()),
    };
    format!("{home}/.config/opsec")
}

fn home_from_passwd() -> Option<String> {
    use std::ffi::c_char;

    #[repr(C)]
    struct Passwd {
        pw_name:   *const c_char,
        pw_passwd: *const c_char,
        pw_uid:    u32,
        pw_gid:    u32,
        pw_gecos:  *const c_char,
        pw_dir:    *const c_char,
        pw_shell:  *const c_char,
    }

    #[link(name = "c")]
    extern "C" {
        fn getuid() -> u32;
        fn getpwuid(uid: u32) -> *const Passwd;
    }

    let pw = unsafe { getpwuid(getuid()) };
    if pw.is_null() { return None; }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    let s = dir.to_string_lossy().into_owned();
    if s.is_empty() { None } else { Some(s) }
}

pub fn ensure_opsec_dir() {
    use std::os::unix::fs::PermissionsExt;
    let dir = opsec_dir();
    std::fs::create_dir_all(&dir).ok();
    // Restrict to owner-only: torrc, HMAC key, cookie, hostname backups
    // must not be readable by other users on the same machine (MED-1).
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
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
    // symlink_metadata (= lstat) does not follow symlinks - rejects a symlink
    // pointing to a legitimate SUID binary that an attacker placed at TS_HELPER.
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_file() && m.uid() == 0 && (m.mode() & 0o4000 != 0),
        Err(_) => false,
    }
}

// SHA-256 of the embedded ts_helper.c source (computed at compile time).
// If the bundle copy has been tampered with, we fall back to the embedded source.
const TS_HELPER_SRC: &str = include_str!("ts_helper.c");

pub fn ensure_helper(app: &tauri::App) {
    if helper_ok() { return; }

    // Validate bundle source against the embedded copy before compiling.
    // Prevents LPE via a tampered ts_helper.c in the app bundle (M2):
    // if the on-disk source differs from what was compiled into this binary,
    // we discard it and fall back to the embedded source (which cannot be modified
    // without recompiling the whole TorShield binary).
    let bundle_src = app.path()
        .resource_dir()
        .ok()
        .map(|d| d.join("ts_helper.c"))
        .filter(|p| p.exists())
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|s| s == TS_HELPER_SRC)
                .unwrap_or(false)
        });

    // Compile into a tempdir (0700) owned by the current user to prevent
    // TOCTOU: the dir is created first, clang writes the binary into it,
    // and the fd is never released before the osascript cp.  (HIGH-3)
    let tmp_dir = match tempfile::Builder::new()
        .prefix("ts_helper_build_")
        .tempdir_in("/tmp")
    {
        Ok(d) => d,
        Err(_) => return,
    };
    let tmp_bin_path = tmp_dir.path().join("ts_helper");

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
                .tempfile_in(tmp_dir.path())
            {
                Ok(f) => f,
                Err(_) => return,
            };
            let src_path = src_tmp.path().to_path_buf();
            if std::fs::write(&src_path, TS_HELPER_SRC).is_err() { return; }
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
    // tmp_dir drop cleans up the whole directory including the compiled binary.
}

pub fn sf_symbol_png(symbol: &str, size: u32, out: &str) -> bool {
    let src      = include_str!("gen_icon.m");
    let src_path = format!("{}/gen_icon.m", opsec_dir());
    let bin_path = format!("{}/gen_icon",   opsec_dir());
    ensure_opsec_dir();
    if std::fs::write(&src_path, src).is_err() { return false; }
    // Always recompile from the embedded source - never reuse a persisted binary.
    // lib.rs removes gen_icon at startup; this ensures no stale/replaced binary
    // is executed across calls within the same session (CRIT-2).
    std::fs::remove_file(&bin_path).ok();
    let ok = Command::new("clang")
        .args(["-framework", "AppKit", "-framework", "Foundation",
               &src_path, "-o", &bin_path, "-fobjc-arc"])
        .output().map(|o| o.status.success()).unwrap_or(false);
    if !ok { return false; }
    Command::new(&bin_path).args([symbol, out, &size.to_string()])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

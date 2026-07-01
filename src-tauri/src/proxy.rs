use std::process::Command;

use crate::helper::{opsec_dir, ensure_opsec_dir, sh, root, get_network_services};

const ENV_MARKER_BEGIN: &str = "# TorShield-env-begin";
const ENV_MARKER_END:   &str = "# TorShield-env-end";

fn env_file_path() -> String {
    format!("{}/env.sh", opsec_dir())
}

pub fn env_inject_enable() {
    let proxy = "socks5h://127.0.0.1:9050";
    let content = format!(
        "export HTTP_PROXY={proxy}\n\
         export HTTPS_PROXY={proxy}\n\
         export ALL_PROXY={proxy}\n\
         export http_proxy={proxy}\n\
         export https_proxy={proxy}\n\
         export all_proxy={proxy}\n\
         export NO_PROXY=localhost,127.0.0.1,::1,github.com,api.github.com,*.github.com,*.anthropic.com,*.claude.ai\n\
         export no_proxy=localhost,127.0.0.1,::1,github.com,api.github.com,*.github.com,*.anthropic.com,*.claude.ai\n"
    );
    ensure_opsec_dir();
    std::fs::write(env_file_path(), &content).ok();

    let hook = format!(
        "\n{ENV_MARKER_BEGIN}\n\
         [ -f \"{env}\" ] && source \"{env}\"\n\
         {ENV_MARKER_END}\n",
        env = env_file_path()
    );
    let home = std::env::var("HOME").unwrap_or_default();
    for rc in [".zshrc", ".bashrc"] {
        let path = format!("{home}/{rc}");
        if let Ok(current) = std::fs::read_to_string(&path) {
            if !current.contains(ENV_MARKER_BEGIN) {
                let mut f = std::fs::OpenOptions::new()
                    .append(true).create(true).open(&path);
                if let Ok(ref mut f) = f {
                    use std::io::Write;
                    f.write_all(hook.as_bytes()).ok();
                }
            }
        } else {
            std::fs::write(&path, hook.trim_start()).ok();
        }
    }
}

pub fn env_inject_disable() {
    std::fs::remove_file(env_file_path()).ok();
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy",
              "NO_PROXY",   "no_proxy"] {
        Command::new("launchctl").args(["unsetenv", k]).output().ok();
    }
}

pub fn proxy_enable() {
    for svc in get_network_services() {
        sh("networksetup", &["-setsocksfirewallproxy", &svc, "127.0.0.1", "9050", "off"]);
        sh("networksetup", &["-setsocksfirewallproxystate", &svc, "on"]);
        sh("networksetup", &["-setproxybypassdomains", &svc, "localhost, 127.0.0.1"]);
    }
}

pub fn proxy_disable() {
    for svc in get_network_services() {
        sh("networksetup", &["-setsocksfirewallproxystate", &svc, "off"]);
    }
}

pub fn ipv6_disable() {
    for svc in get_network_services() { sh("networksetup", &["-setv6off", &svc]); }
}

pub fn ipv6_restore() {
    for svc in get_network_services() { sh("networksetup", &["-setv6automatic", &svc]); }
}

pub fn hostname_anonymize() {
    let dir = opsec_dir();
    // Save originals only if no backup exists yet (first call at connect).
    for (key, file) in [
        ("LocalHostName",  "local_hostname.bak"),
        ("ComputerName",   "computer_name.bak"),
        ("HostName",       "hostname.bak"),
    ] {
        let bak_path = format!("{dir}/{file}");
        if !std::path::Path::new(&bak_path).exists() {
            let out = Command::new("scutil").args(["--get", key]).output().ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if !out.is_empty() { std::fs::write(&bak_path, &out).ok(); }
        }
    }
    hostname_rotate();
}

// Rotate to a new random neutral hostname without touching the saved backups.
// Safe to call repeatedly during a session (auto-rotate).
pub fn hostname_rotate() {
    let suffix = {
        let b = crate::helper::rand_bytes(3);
        format!("{:02x}{:02x}{:02x}", b[0], b[1], b[2])
    };
    let local  = format!("mac-{suffix}");
    let script = format!(
        "do shell script \
         \"scutil --set LocalHostName '{local}' && \
           scutil --set ComputerName 'MacBook' && \
           scutil --set HostName '{local}'\" \
         with administrator privileges"
    );
    Command::new("osascript").args(["-e", &script]).output().ok();
}

pub fn hostname_restore() {
    let dir = opsec_dir();
    for (key, file) in [
        ("LocalHostName",  "local_hostname.bak"),
        ("ComputerName",   "computer_name.bak"),
        ("HostName",       "hostname.bak"),
    ] {
        let path = format!("{dir}/{file}");
        if let Ok(val) = std::fs::read_to_string(&path) {
            let val = val.trim();
            if !val.is_empty() {
                let script = format!(
                    "do shell script \"scutil --set {key} '{val}'\" with administrator privileges",
                    key = key,
                    val = val.replace('\'', "'\\''"),
                );
                Command::new("osascript").args(["-e", &script]).output().ok();
            }
            std::fs::remove_file(&path).ok();
        }
    }
}

const DNSMASQ_CONF_ROOT: &str = "/etc/dnsmasq-torshield.conf";

pub fn dns_leak_enable() {
    let pid_file = format!("{}/dnsmasq.pid", opsec_dir());

    // Config written to root-owned /etc/dnsmasq-torshield.conf via ts_helper -
    // prevents local privilege escalation via dhcp-script/conf-file injection
    // in a user-writable config read by a root dnsmasq process (CRIT-1).
    // Only allowlisted options are used.
    let conf = format!(
        "no-resolv\nserver=127.0.0.1#9053\nlisten-address=127.0.0.1\nport=53\n\
         pid-file={pid_file}\n"
    );
    let mut child = Command::new(crate::helper::TS_HELPER)
        .arg("write-dnsmasq-conf")
        .stdin(std::process::Stdio::piped())
        .spawn().ok();
    if let Some(ref mut c) = child {
        if let Some(stdin) = c.stdin.take() {
            use std::io::Write;
            let mut s = stdin;
            s.write_all(conf.as_bytes()).ok();
        }
        c.wait().ok();
    }

    let dnsmasq_bin = [
        "/opt/homebrew/sbin/dnsmasq",
        "/usr/local/sbin/dnsmasq",
        "/usr/sbin/dnsmasq",
    ].iter().find(|p| std::path::Path::new(p).exists())
        .map(|s| s.to_string());

    let Some(bin) = dnsmasq_bin else { return; };

    root(&bin, &["-C", DNSMASQ_CONF_ROOT]);

    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "127.0.0.1"]);
    }
}

pub fn dns_leak_disable() {
    let pid_file = format!("{}/dnsmasq.pid", opsec_dir());
    // Kill via PID from pid-file with absolute path - avoids pkill -f pattern
    // matching against arbitrary process cmdlines (HIGH-1).
    if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
        let pid = pid_str.trim();
        if pid.chars().all(|c| c.is_ascii_digit()) && !pid.is_empty() {
            root("/bin/kill", &[pid]);
        }
        std::fs::remove_file(&pid_file).ok();
    }
    // Fallback: pkill by exact name only, no -f pattern
    root("/usr/bin/pkill", &["-x", "dnsmasq"]);
    Command::new(crate::helper::TS_HELPER).arg("rm-dnsmasq-conf").output().ok();
    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "empty"]);
    }
}

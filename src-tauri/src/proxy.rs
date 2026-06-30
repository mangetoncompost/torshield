use std::process::Command;

use crate::helper::{opsec_dir, sh, root, get_network_services};

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
    std::fs::create_dir_all(opsec_dir()).ok();
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

pub fn dns_leak_enable() {
    let dir          = opsec_dir();
    let pid_file     = format!("{}/dnsmasq.pid", dir);
    let dnsmasq_conf = format!("{}/dnsmasq.conf", dir);

    std::fs::write(&dnsmasq_conf, format!(
        "no-resolv\nserver=127.0.0.1#9053\nlisten-address=127.0.0.1\nport=53\n\
         pid-file={pid_file}\n"
    )).ok();

    let dnsmasq_bin = [
        "/opt/homebrew/sbin/dnsmasq",
        "/usr/local/sbin/dnsmasq",
        "/usr/sbin/dnsmasq",
    ].iter().find(|p| std::path::Path::new(p).exists())
        .map(|s| s.to_string());

    let Some(bin) = dnsmasq_bin else { return; };

    root(&bin, &["-C", &dnsmasq_conf]);

    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "127.0.0.1"]);
    }
}

pub fn dns_leak_disable() {
    let dir      = opsec_dir();
    let pid_file = format!("{}/dnsmasq.pid", dir);
    if let Ok(pid) = std::fs::read_to_string(&pid_file) {
        root("kill", &[pid.trim()]);
        std::fs::remove_file(&pid_file).ok();
    }
    let dnsmasq_conf = format!("{}/dnsmasq.conf", dir);
    root("/usr/bin/pkill", &["-f", &format!("dnsmasq.*{}", dnsmasq_conf)]);
    root("/usr/bin/pkill", &["-x", "dnsmasq"]);
    for svc in get_network_services() {
        sh("networksetup", &["-setdnsservers", &svc, "empty"]);
    }
}

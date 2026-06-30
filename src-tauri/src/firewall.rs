use std::process::Command;

use crate::helper::{root, primary_interface, TS_HELPER};

const PF_ANCHOR: &str = "com.torshield.killswitch";
const PF_ANCHOR_PATH: &str = "/etc/pf.anchors/com.torshield.killswitch";
const WATCHDOG_PLIST: &str = "/Library/LaunchDaemons/com.torshield.watchdog.plist";
const WATCHDOG_SCRIPT: &str = "/usr/local/bin/torshield-watchdog";

// Tables in anchors cause silent boot failures on macOS (OpenBSD behaviour not ported).
// Table must live in /etc/pf.conf, not in the anchor file.
const PF_TABLE_MARKER: &str = "# TorShield-apple-relay-table";
const PF_TABLE_DEF: &str =
    "# TorShield-apple-relay-table\n\
     table <apple_relay> const { 17.0.0.0/8 }\n";

fn build_pf_anchor_rules(iface: &str) -> String {
    format!(
        "# TorShield kill switch anchor\n\
         set skip on lo0\n\
         block drop out quick on {iface} to <apple_relay>\n\
         block drop out quick on {iface} all\n\
         block drop out quick on {iface} proto udp all\n\
         pass out quick on {iface} proto tcp to any port 9050 keep state\n\
         pass in quick on {iface} proto tcp keep state\n"
    )
}

fn pf_anchor_reference() -> String {
    format!("anchor \"{PF_ANCHOR}\"\nload anchor \"{PF_ANCHOR}\" from \"{PF_ANCHOR_PATH}\"\n")
}

fn write_pf_conf(content: &str) {
    let mut child = Command::new(TS_HELPER)
        .arg("write-pf-conf")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn().ok();
    if let Some(ref mut c) = child {
        if let Some(stdin) = c.stdin.take() {
            use std::io::Write;
            let mut s = stdin;
            s.write_all(content.as_bytes()).ok();
        }
        c.wait().ok();
    }
}

pub fn pf_enable() {
    let iface = primary_interface();
    let anchor_rules = build_pf_anchor_rules(&iface);

    std::fs::write(PF_ANCHOR_PATH, &anchor_rules).ok();

    let pf_conf = std::fs::read_to_string("/etc/pf.conf").unwrap_or_default();
    let needs_table  = !pf_conf.contains(PF_TABLE_MARKER);
    let needs_anchor = !pf_conf.contains(PF_ANCHOR);
    if needs_table || needs_anchor {
        let mut patched = pf_conf.trim_end().to_string();
        if needs_table  { patched.push_str(&format!("\n{}", PF_TABLE_DEF)); }
        if needs_anchor { patched.push_str(&format!("\n{}", pf_anchor_reference())); }
        write_pf_conf(&patched);
    }

    root("/sbin/pfctl", &["-e"]);
    root("/sbin/pfctl", &["-a", PF_ANCHOR, "-f", PF_ANCHOR_PATH]);
}

pub fn pf_disable() {
    root("/sbin/pfctl", &["-a", PF_ANCHOR, "-F", "all"]);
    let _ = std::fs::remove_file(PF_ANCHOR_PATH);
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        let _ = write!(out, "{}", b64_chars[b0 >> 2] as char);
        let _ = write!(out, "{}", b64_chars[((b0 & 3) << 4) | (b1 >> 4)] as char);
        let _ = write!(out, "{}", if chunk.len() > 1 { b64_chars[((b1 & 0xf) << 2) | (b2 >> 6)] as char } else { '=' });
        let _ = write!(out, "{}", if chunk.len() > 2 { b64_chars[b2 & 0x3f] as char } else { '=' });
    }
    out
}

pub fn ensure_watchdog() {
    let script = format!(
        "#!/bin/sh\n\
         while true; do\n\
           if ! pgrep -x torshield > /dev/null 2>&1; then\n\
             /sbin/pfctl -a '{anchor}' -F all 2>/dev/null\n\
           fi\n\
           sleep 5\n\
         done\n",
        anchor = PF_ANCHOR
    );

    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
           <key>Label</key><string>com.torshield.watchdog</string>\n\
           <key>ProgramArguments</key>\n\
           <array><string>/bin/sh</string><string>{script}</string></array>\n\
           <key>RunAtLoad</key><true/>\n\
           <key>KeepAlive</key><true/>\n\
           <key>StandardErrorPath</key><string>/dev/null</string>\n\
           <key>StandardOutPath</key><string>/dev/null</string>\n\
         </dict></plist>\n",
        script = WATCHDOG_SCRIPT
    );

    let already_installed = std::path::Path::new(WATCHDOG_PLIST).exists()
        && std::path::Path::new(WATCHDOG_SCRIPT).exists();
    if already_installed { return; }

    let install_cmd = format!(
        "do shell script \
         \"printf '%s' {script_b64} | base64 -d > '{script_path}' && \
          chmod 755 '{script_path}' && \
          printf '%s' {plist_b64} | base64 -d > '{plist_path}' && \
          launchctl load '{plist_path}'\" \
         with administrator privileges",
        script_b64  = base64_encode(script.as_bytes()),
        script_path = WATCHDOG_SCRIPT,
        plist_b64   = base64_encode(plist.as_bytes()),
        plist_path  = WATCHDOG_PLIST,
    );
    Command::new("osascript").args(["-e", &install_cmd]).output().ok();
}

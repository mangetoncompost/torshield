# Changelog

## v0.8.0 - 2026-07-01

Third security audit. All findings confirmed with reference sources before implementation.

### Security - Critical

- **dnsmasq config moved to root-owned path** : `dns_leak_enable()` was writing
  `dnsmasq.conf` into `~/.config/opsec/` (user-writable), then calling ts_helper to run
  dnsmasq as root with `-C <user-file>`. A local attacker or compromised process could
  inject arbitrary dnsmasq directives (`dhcp-script`, `conf-file`, `addn-hosts`) into
  that file before dnsmasq started - gaining code execution as root on the next connect.
  Fixed: new `write-dnsmasq-conf` and `rm-dnsmasq-conf` verbs in ts_helper; config is
  written to `/etc/dnsmasq-torshield.conf` (root:wheel, O_NOFOLLOW, hardcoded path).

- **gen_icon recompiled every call, never reused** : `sf_symbol_png()` compiled the icon
  generator once and cached the binary in `~/.config/opsec/gen_icon`. Subsequent calls
  reused the cached binary without integrity verification - a binary planting attack. Fixed:
  the binary is always deleted and recompiled from the embedded source (`include_str!`) on
  every invocation. lib.rs already removes gen_icon at startup; this closes the within-session
  window.

### Security - High

- **TOCTOU in ensure_helper() closed** : the compiled ts_helper binary was written into a
  `NamedTempFile` that was `drop()`-d before clang ran. The drop releases both the file
  descriptor and the path reservation; clang then recreated the file without O_EXCL, opening
  a race between the free and the write. Fixed: compile inside a `tempdir()` (mode 0700,
  single owner) that is kept alive until the osascript `cp` completes.

- **dnsmasq kill via PID, not pkill -f** : `dns_leak_disable()` was calling
  `pkill -f dnsmasq.*<user-controlled-path>`. With root privileges, `pkill -f` pattern-
  matches against all process cmdlines; a crafted path could send SIGTERM to unrelated root
  processes. Also, `root("kill", ...)` used the bare name `"kill"` which does not match
  `/bin/kill` in the ts_helper whitelist and was silently ignored. Fixed: read PID from
  `dnsmasq.pid`, validate digits-only, kill via `/bin/kill <pid>`.

- **Watchdog integrity check** : `ensure_watchdog()` only checked for file existence
  (`Path::exists()`). A replaced or corrupted watchdog script running as a root
  LaunchDaemon is a persistent root shell. Fixed: `fs::read_to_string(WATCHDOG_SCRIPT)`
  and compare against the expected content before skipping reinstallation.

### Security - Medium

- **opsec_dir permissions restricted to 0700** : `~/.config/opsec/` was created with the
  process umask default (0755 on macOS), making the torrc, HMAC key, SAFECOOKIE, and
  hostname backups world-readable on multi-user machines. Fixed: `ensure_opsec_dir()` calls
  `set_permissions(0o700)` after `create_dir_all`. All call sites updated.

- **HOME fallback uses passwd database** : if `HOME` is unset (early-boot LaunchAgent with
  reduced environment), `opsec_dir()` fell back to `/tmp/.config/opsec/` (world-listable).
  Fixed: resolve the home directory from `getpwuid(getuid())` before falling back.

- **Tor binary resolved via absolute path** : `Command::new("tor")` relied on PATH for a
  security-critical process. A malicious binary earlier in PATH could open a listener on
  9050, pass `tor_ready()`, and silently intercept all traffic. Fixed: `tor_bin()` probes
  known Homebrew paths first (`/opt/homebrew/bin/tor`, `/usr/local/bin/tor`) and only
  falls back to `which` with an absolute-path validation.

### Security - Low

- **pf interface name validated** : `primary_interface()` output was injected verbatim
  into pf rules. Interface names on macOS are alphanumeric (`en0`, `utun2`); an unexpected
  value could corrupt the rules. Fixed: `sanitize_iface()` rejects any non-alphanumeric
  name and defaults to `en0`.

### UI

- Menu fully in English with professional labels (Mullvad/Little Snitch style):
  `Connect` / `Disconnect`, `New Identity`, `Identity Rotation`, `Kill Switch`,
  `MAC Address Randomization`, `DNS Leak Protection`, `Fingerprint Resistance`,
  `Advanced` (was `Dev / Scripts`), `[OK]` / `[!]` dependency indicators.

---


## v0.6.0 - 2026-07-01

Full security audit. All changes are backed by reference sources (MITRE CWE,
Apple Developer, Tor Project spec, GTFOBins, RustCrypto, PortSwigger).

### Security

- **SAFECOOKIE on Tor control port** : authentication now uses SAFECOOKIE
  (spec 193, HMAC-SHA256 challenge/response) instead of plain COOKIE. The
  cookie file is never sent in cleartext over the TCP socket - protects against
  replay attacks on 127.0.0.1:9051.

- **Config integrity** : torshield.json is now signed with HMAC-SHA256 using a
  key stored in the macOS Keychain. Any external alteration (user-level malware,
  malicious manual edit) is detected at load time - config is reset to defaults
  instead of being silently applied.

- **Secure PRNG** : rand_bytes() replaced by getrandom::fill() which calls
  getentropy(2) directly on macOS. The previous clock fallback produced
  predictable MAC addresses on /dev/urandom read failure.

- **ts_helper SUID - tee removed** : /usr/bin/tee was in the SUID whitelist.
  GTFOBins documents tee-SUID as an arbitrary root file write vector
  (echo DATA | tee /etc/sudoers). Replaced by an internal write-pf-conf verb
  with /etc/pf.conf hardcoded in C and O_NOFOLLOW on open().

- **ensure_helper() - symlink attack** : the helper binary was compiled into
  opsec_dir() (user-accessible). An attacker could replace the temp file
  between compilation and the osascript-driven chown root + chmod 4755.
  Fixed : compile into /tmp with an unpredictable random name (tempfile +
  O_CREAT|O_EXCL), symlink_metadata() check post-compilation before elevation.

- **pf anchor - table in the right place** : table <apple_relay> moved from the
  anchor file into /etc/pf.conf. Tables defined inside anchors cause silent boot
  failures on macOS (OpenBSD behaviour not ported).
  Source : iyanmv.medium.com/setting-up-correctly-packet-filter-pf-firewall.

- **user.js - precise strip()** : the Firefox prefs cleanup function was
  filtering by substring (.contains()), removing comments and third-party prefs
  whose name accidentally contained a blocked keyword. Fixed : exact prefix
  match on user_pref("...") lines only.

- **CanvasBlocker downloaded via Tor** : the XPI download from
  addons.mozilla.org was going direct (real IP exposed). Fixed : reqwest client
  now uses socks5h://127.0.0.1:9050 proxy.

### New dependencies

- getrandom 0.3 - RustCrypto, getentropy backend on macOS
- hmac 0.13 - RustCrypto, 448M downloads
- sha2 0.11 - RustCrypto, 718M downloads
- tempfile 3 - already in the transitive graph (tauri-bundler)
- security-framework 3 - Apple Security.framework bindings, 292M downloads

---

## v0.5.1

- Dynamic Firefox User-Agent (detects installed version)
- iCloud Private Relay blocking (17.0.0.0/8) in pf kill switch
- ts_helper SUID whitelist (first version)

## v0.5.0

- pf kill switch with Mullvad-style anchor architecture
- LaunchDaemon watchdog : flushes anchor if TorShield crashes

## v0.4.1

- Robust pf kill switch
- env_inject without launchctl (zshrc hook only)
- env_inject disabled by default
- NO_PROXY extended (github, anthropic, claude.ai)

## v0.4.0

- Env var injection (HTTP_PROXY/HTTPS_PROXY for Python, curl, Go, Node)
- SUID helper auto-install (first version)
- QUIC/HTTP3 blocking in pf
- Real-time Dependencies menu

## v0.3.0

- Firefox fingerprint hardening (resistFingerprinting, spoofOsAsWindows)
- CanvasBlocker auto-installed
- Windows User-Agent spoofing
- Language neutralization (en-US)

## v0.2.0

- English UI
- DNS leak fix via dnsmasq (Tor port 9053)
- MAC spoofing with legitimate Apple OUIs
- Automatic Tor identity rotation (5/15/30 min)

## v0.1.0

- First release : native macOS menubar app (Tauri 2)
- System-wide SOCKS5 proxy via Tor
- IPv6 disable
- System log clearing
- Exit node exclusion by country

---

## v0.7.0 - 2026-07-01

Second security audit. All findings confirmed with reference sources before implementation.

### Security - Critical

- **pf kill switch: rule order fixed** : `block drop out quick ... all` was placed
  before `pass out quick` rules. With `quick`, the first matching rule stops evaluation
  immediately (man pf.conf). The pass rules were never reached - Tor could not connect
  to relays and the kill switch was silently broken.

- **pf anchor written via ts_helper** : `pf_enable()` was calling `std::fs::write()`
  on `/etc/pf.anchors/` (root:wheel 755) and silently absorbing the `Permission denied`
  error via `.ok()`. The anchor file was never created; pfctl loaded a non-existent file
  and failed silently. The kill switch showed as active in the UI with no rules loaded.
  Fixed: new `write-pf-anchor` and `rm-pf-anchor` verbs in ts_helper with O_NOFOLLOW.

### Security - High

- **`pass in quick tcp` removed** : the rule accepted externally-initiated TCP
  connections, piercing the kill switch. Stateful tracking on `pass out ... keep state`
  handles return packets automatically without an explicit `pass in` rule.

- **Tor relay ports added to pf** : only port 9050 (SOCKS local) was allowed outbound.
  Tor connects to relays on 443, 9001 and 80 (ORPort per man tor). Without these ports,
  Tor could not bootstrap when the kill switch was active.

- **`/bin/kill` absolute path in ts_helper** : `execv("kill", ...)` fails with ENOENT
  because execv does not search PATH (man execv(2)). dnsmasq was never killed by PID;
  the pkill fallback was killing all dnsmasq instances on the system.

- **`hex_decode()` panic on odd-length input fixed** : `&s[i..i+2]` panics in release
  build when len is odd. A malformed response from a compromised Tor daemon would crash
  TorShield, triggering the watchdog to flush the pf anchor and exposing the real IP.
  Fixed: returns `Option<Vec<u8>>`, rejects odd-length input explicitly.

- **IPv6 disabled before MAC spoof** : `ifconfig down/up` triggers NDP Router
  Solicitations that may expose the fe80:: link-local address (EUI-64 derived from MAC)
  on the local segment (RFC 4861 s.6.3.7, RFC 4941). IPv6 is now disabled first.

### Security - Medium

- **No outbound request at startup** : `fetch_real_ip()` called `reqwest::no_proxy()`
  which "disables the automatic usage of the system proxy" (docs.rs/reqwest). The real
  IP was sent to api.ipify.org at every startup, before Tor was active. Replaced by
  `local_real_ip()` which reads the interface address via `ipconfig getifaddr` (no
  network request).

- **ts_helper.c bundle integrity check** : the source file in the app bundle is owned
  by the user and can be modified. `ensure_helper()` now compares the on-disk source
  against the copy embedded in the binary at compile time. A tampered bundle source is
  discarded; the embedded source is used instead, preventing LPE via recompilation.

- **torrc permissions 600** : torrc was world-readable (644). Restricted to owner-only
  to prevent local modification of ExcludeExitNodes, CookieAuthFile, or injection of
  HiddenServiceDir between activations.

- **Captive portal blocked** : `captiveagent` sends HTTP to `captive.apple.com` at
  every network connection, bypassing the SOCKS5 proxy (Apple system daemon). The
  TorShield pf kill switch now blocks this host via `/etc/hosts` (base64+osascript,
  injection-safe) when the kill switch is enabled.

- **mDNS hostname anonymized** : `mDNSResponder` broadcasts the real hostname
  (`MacBook-Pro-de-[Name].local`), exact model, and macOS version on the local network
  spontaneously (Fingerprint.com: 65% first-name identification rate). TorShield now
  sets LocalHostName/ComputerName/HostName to neutral values at enable and restores the
  originals at disable via scutil.

- **`helper_ok()` uses `symlink_metadata()`** : `std::fs::metadata()` follows symlinks,
  returning `is_file() = true` for a symlink to a file. A symlink at `/usr/local/bin/ts_helper`
  pointing to a legitimate SUID binary would have passed the check. Fixed: uses
  `symlink_metadata()` (= lstat) and checks `file_type().is_file()` directly.

### Firefox

- **DNS prefetch disabled** : `network.dns.disablePrefetch` and
  `network.dns.disablePrefetchFromHTTPS` added (the latter defaults to `false` since
  Firefox 127 - arkenfox issue #1860). Prefetch lookups bypass the SOCKS5 proxy.
  Also added: `network.prefetch-next`, `browser.send_pings`, `media.navigator.enabled`.
  All new prefs added to the cleanup list on disable.

# Changelog

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

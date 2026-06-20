<div align="center">

# TorShield

**Native macOS menubar app for one-click Tor anonymization.**

[![macOS](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

TorShield sits in your menubar. One click routes all your traffic through Tor: system-wide proxy, Firefox hardening, IPv6 disabled, MAC spoofed. Quit and everything is restored cleanly.

No window. No dock icon. Just a shield.

Useful for pentest engagements, red team operations, OSINT, and privacy research.

## Features

| Layer | What it does |
|---|---|
| **Tor SOCKS5** | Starts a local Tor daemon, routes all system traffic through it |
| **System proxy** | Configures macOS `networksetup` - covers Safari, Chrome, curl, every app |
| **Firefox hardening** | Proxy + WebRTC off + geolocation blocked + dark mode preserved |
| **IPv6 kill** | Disables IPv6 on all interfaces (prevents leak) |
| **MAC spoofing** | Randomizes your MAC address at session start |
| **DNS leak fix** | Routes DNS through Tor via dnsmasq (no mDNSResponder leaks) |
| **pf kill switch** | Blocks all non-Tor TCP outbound when enabled |
| **Identity rotation** | New Tor circuit on demand or on a timer (5 / 15 / 30 min) |
| **Exit node filter** | Exclude countries from Tor exit nodes (US, UK, AU, CA, NZ, DE, FR) |

Everything is toggleable per-layer. Config persists across restarts.

## Requirements

- macOS 13 Ventura or later
- [Tor](https://formulae.brew.sh/formula/tor): `brew install tor`
- [dnsmasq](https://formulae.brew.sh/formula/dnsmasq): `brew install dnsmasq` *(optional, for DNS leak fix)*

## Installation

### From source

```bash
git clone https://github.com/mangetoncompost/torshield
cd torshield
npm install
npm run tauri build
```

The `.app` is in `src-tauri/target/release/bundle/macos/`.

### Homebrew *(coming soon)*

```bash
brew install --cask torshield
```

## Usage

Launch TorShield - it appears in your menubar as a shield icon.

**Inactive:**
```
○  Inactive
Real IP: 82.64.x.x

Enable OPSEC
-----------
> Exit nodes
> Auto-rotation
> Protections
-----------
  Launch at login
-----------
  Quit TorShield
```

**Active:**
```
●  Active - 185.220.x.x
Real IP: 82.64.x.x  (hidden)

Disable OPSEC
New Tor identity
```

Quitting TorShield **always** restores your previous state: proxy removed, Firefox unpatched, IPv6 re-enabled, MAC restored.

## Protections

| Toggle | Default | Note |
|---|---|---|
| Firefox (proxy + WebRTC off) | on | Patches `user.js` + live `prefs.js` |
| Firefox resistFingerprinting | off | Disables WebGL/canvas - breaks some sites |
| MAC spoofing | on | Randomizes `en0` hardware address |
| DNS leak fix (dnsmasq) | on | Requires dnsmasq |
| Kill switch (pf firewall) | off | Blocks all non-Tor TCP outbound |
| Clear logs on start | on | `log erase --all` + crash reporter purge |
| User-Agent spoofing | on | Sends `Mozilla/5.0 (Windows NT 10.0...)` |
| Neutral language (en-US) | on | Overrides `Accept-Language` header |

## How it works

```
+-----------+    SOCKS5     +------------+    Tor network
| Your apps | ----------->  | Tor :9050  | ----------->  Internet
+-----------+               +------------+
      |                           |
 networksetup               DNSPort 9053
 (system-wide)              via dnsmasq
```

macOS `networksetup` sets a system-wide SOCKS5 proxy - every app that respects system proxy settings goes through Tor automatically. Firefox gets additional hardening applied directly to its profile (`user.js` for cold starts, `prefs.js` for the live session).

## Stack

- **[Tauri 2](https://tauri.app/)** - native macOS tray app, no webview
- **Rust + tokio** - async runtime, reqwest for IP resolution over SOCKS5
- **[tauri-plugin-autostart](https://github.com/tauri-apps/plugins-workspace)** - LaunchAgent-based login item
- SF Symbols rendered at runtime via ObjC + clang (no Xcode required, CLI tools only)

## Legal

Intended for **authorized penetration testing, red team operations, privacy research, and personal use**. Routing traffic through Tor is legal in most jurisdictions. You are responsible for compliance with applicable local laws and any terms of service.

Using this tool to access systems without authorization or to engage in illegal activity is prohibited.

## Contributing

Issues and PRs welcome. Zero warnings policy:

```bash
cd src-tauri && cargo check
```

## License

MIT - see [LICENSE](LICENSE).

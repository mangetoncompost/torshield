<div align="center">

# TorShield

[![macOS](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

Menubar app for macOS that routes all your traffic through Tor in one click. System proxy, Firefox hardened, IPv6 off, MAC randomized. Quit and everything goes back to normal.

Built for pentest engagements, red team ops, OSINT, and anyone who wants a clean anonymous session without configuring anything by hand.

The typical workflow: open TorShield, enable OPSEC, do your thing, quit. Your real IP never hits the network, Firefox stops leaking WebRTC, your MAC rotates, DNS goes through Tor. When you quit, the machine is back to exactly how it was.

No window. No dock icon. Just a shield in your menubar.

## Requirements

- macOS 13+
- `brew install tor`
- `brew install dnsmasq` *(optional, fixes DNS leaks)*

## Install

Download the latest DMG from [Releases](https://github.com/mangetoncompost/torshield/releases), open it and drag TorShield to `/Applications`.

### From source

Requires Rust and the [Tauri CLI](https://tauri.app/start/prerequisites/).

```bash
git clone https://github.com/mangetoncompost/torshield
cd torshield
cargo tauri build
```

App ends up in `src-tauri/target/release/bundle/macos/TorShield.app`.

## What it does

When you enable OPSEC from the menubar:

- Starts a local Tor daemon and sets it as system-wide SOCKS5 proxy via `networksetup` - covers Safari, Chrome, curl, every app that respects system proxy settings
- Disables IPv6 on all interfaces (common leak vector even with a proxy)
- Randomizes your MAC address on the primary interface
- Patches Firefox directly: proxy configured, WebRTC disabled, geolocation blocked, User-Agent and Accept-Language overridden, dark mode preserved
- Optionally routes DNS through Tor via dnsmasq so mDNSResponder never leaks your real DNS queries
- Optionally enables a `pf` kill switch that blocks all non-Tor TCP outbound

When you quit, everything is restored: proxy removed, Firefox unpatched, IPv6 back, MAC restored.

## Protections

All toggleable from the menubar. Settings persist across restarts.

| Toggle | Default | Note |
|---|---|---|
| Firefox | on | Patches both `user.js` and the live `prefs.js` |
| Firefox resistFingerprinting | off | Kills WebGL/canvas - breaks some sites |
| MAC spoofing | on | Randomizes `en0` at session start |
| DNS leak fix | on | Routes DNS through Tor via dnsmasq |
| pf kill switch | off | Blocks all non-Tor TCP outbound |
| Clear logs on start | on | `log erase --all` + crash reporter |
| User-Agent spoof | on | Generic Windows/Firefox UA |
| Language (en-US) | on | Overrides Accept-Language header |

## Exit nodes and rotation

Exclude countries from Tor exit nodes (US, UK, AU, CA, NZ, DE, FR). Set automatic identity rotation every 5, 15 or 30 minutes, or rotate manually from the menu.

## How it works

```
+-----------+    SOCKS5     +------------+    Tor network
| Your apps | ------------> | Tor :9050  | ------------>  Internet
+-----------+               +------------+
      |                           |
 networksetup               DNSPort 9053
 (system-wide)              via dnsmasq
```

Firefox is a special case because it doesn't always respect the system proxy for WebRTC and DNS. TorShield patches the profile directly (`user.js` for cold starts, `prefs.js` for the running session) so there are no gaps.

## Stack

- [Tauri 2](https://tauri.app/) - native macOS tray app, no webview shown
- Rust + tokio - async runtime, reqwest for IP checks over SOCKS5
- SF Symbols rendered at runtime via ObjC + clang (no Xcode needed, CLI tools only)
- tauri-plugin-autostart for LaunchAgent-based login item

## Legal

For authorized use only. Using this on systems you don't own or without explicit permission is illegal.

## License

MIT

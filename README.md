<div align="center">

# TorShield

[![macOS](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**One click. Full anonymity. No config.**

</div>

---

TorShield is a macOS menubar app that routes everything through Tor the moment you enable it. IP hidden, DNS through Tor, MAC address randomized, Firefox hardened, browser fingerprint randomized. When you're done, quit — the machine goes back to exactly how it was.

No window. No dock icon. Just a shield in your menubar.

Built for pentest engagements, red team ops, OSINT, and anyone who needs a clean anonymous session without spending 30 minutes configuring things by hand.

## Requirements

- macOS 13+
- `brew install tor`
- `brew install dnsmasq` *(optional — fixes DNS leaks)*

## Install

Download the latest DMG from [Releases](https://github.com/mangetoncompost/torshield/releases), open it, drag TorShield to `/Applications`.

**From source**

```bash
git clone https://github.com/mangetoncompost/torshield
cd torshield/src-tauri
cargo tauri build
```

## What happens when you enable OPSEC

- Tor starts locally and becomes the system-wide SOCKS5 proxy — covers Safari, Chrome, curl, every app that respects macOS proxy settings
- IPv6 disabled on all interfaces (it leaks even with a proxy if you leave it on)
- MAC address randomized on the primary interface using a random Apple OUI
- Firefox patched directly: proxy set, WebRTC killed, geolocation blocked, User-Agent and Accept-Language overridden
- CanvasBlocker installed automatically in all Firefox profiles — canvas, WebGL and AudioContext are randomized per domain, no manual setup
- DNS routed through Tor via dnsmasq so your real DNS resolver never sees your queries
- Everything restored on quit: proxy off, Firefox unpatched, IPv6 back, MAC back

## Protections

All toggleable from the menubar. Saved across restarts.

| Protection | Default | What it does |
|---|---|---|
| Firefox | on | Proxy, WebRTC off, geolocation blocked |
| resistFingerprinting | on | Canvas, WebGL, AudioContext, timezone, screen size randomized |
| MAC spoofing | on | New random Apple MAC every session |
| DNS leak fix | on | DNS through Tor via dnsmasq (asks for admin password once) |
| Kill switch | off | pf blocks all non-Tor TCP outbound |
| Clear logs | on | `log erase --all` + crash reporter wiped on start |
| Spoof User-Agent | on | Sends a generic Windows/Firefox UA |
| Neutral language | on | Accept-Language forced to en-US |

## Bypass

Some apps get blocked or throttled by Tor exit nodes. The Bypass submenu lets you send specific services direct while everything else stays behind Tor.

**Spotify** — enable "Spotify (direct)" and music works normally. Domains `*.spotify.com`, `*.scdn.co`, `*.spotilocal.com` and `*.pscdn.co` skip the proxy. Your browser stays on Tor.

## Exit nodes and rotation

Exclude countries from Tor exit nodes: US, UK, AU, CA, NZ, DE, FR. Rotate identity manually or automatically every 5, 15 or 30 minutes.

## How it works

```
your apps  -->  SOCKS5 :9050  -->  Tor  -->  internet
               dnsmasq :53
                    |
               Tor DNSPort :9053
```

Firefox is a special case — it doesn't always respect the system proxy for WebRTC and DNS. TorShield patches `user.js` and `prefs.js` directly so there are no gaps, then restores them on disable.

## Stack

- [Tauri 2](https://tauri.app/) - native macOS tray app, zero webview
- Rust + tokio - async runtime
- reqwest for IP checks over SOCKS5
- SF Symbols rendered at runtime via ObjC + clang (no Xcode required)
- tauri-plugin-autostart for LaunchAgent login item

## Legal

For authorized use only. Pentest engagements, red team ops, OSINT, privacy research. Using this on systems you don't own or without explicit permission is illegal.

## License

MIT

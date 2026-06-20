<div align="center">

# TorShield

[![macOS](https://img.shields.io/badge/macOS-13%2B-000000?logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

Menubar app for macOS that routes all your traffic through Tor in one click. System proxy, Firefox hardened, IPv6 off, MAC randomized. Quit and everything goes back to normal.

Useful for pentest, OSINT, red team ops, or just not wanting to be tracked.

## Requirements

- macOS 13+
- `brew install tor`
- `brew install dnsmasq` *(optional, fixes DNS leaks)*

## Install

```bash
git clone https://github.com/mangetoncompost/torshield
cd torshield
npm install
npm run tauri build
```

App ends up in `src-tauri/target/release/bundle/macos/`.

## What it does

When you enable OPSEC from the menubar:

- Starts a Tor daemon and sets it as system-wide SOCKS5 proxy
- Disables IPv6 on all interfaces
- Randomizes your MAC address
- Patches Firefox (proxy + WebRTC disabled + geolocation blocked)
- Optionally routes DNS through Tor via dnsmasq

Everything is per-toggle. Config is saved across restarts.

## Protections menu

| Toggle | Default | Note |
|---|---|---|
| Firefox | on | Patches `user.js` and the live `prefs.js` |
| Firefox resistFingerprinting | off | Kills WebGL/canvas - breaks some sites |
| MAC spoofing | on | |
| DNS leak fix | on | Needs dnsmasq |
| pf kill switch | off | Blocks all non-Tor TCP |
| Clear logs on start | on | `log erase --all` |
| User-Agent spoof | on | Sends a generic Windows/Firefox UA |
| Language (en-US) | on | Overrides Accept-Language |

## Exit nodes and rotation

You can exclude countries from Tor exit nodes (US, UK, AU, CA, NZ, DE, FR) and set automatic identity rotation every 5, 15 or 30 minutes.

## Legal

For authorized use only. Using this on systems you don't own or without permission is illegal.

## License

MIT

# Changelog

## v0.6.0 - 2026-07-01

Audit de securite complet. Toutes les modifications sont issues d'une veille
sur les sources de reference (MITRE CWE, Apple Developer, Tor Project spec,
GTFOBins, RustCrypto, PortSwigger).

### Securite

- **SAFECOOKIE Tor** : le control port utilise desormais SAFECOOKIE (spec 193,
  HMAC-SHA256 challenge/response) au lieu de COOKIE. Le fichier cookie n'est
  plus envoye en clair sur le socket TCP - protection contre les replay attacks
  sur 127.0.0.1:9051.

- **Integrite de la config** : torshield.json est maintenant signe par un
  HMAC-SHA256 dont la cle est stockee dans le Keychain macOS. Toute alteration
  externe (malware user-level, edition manuelle malveillante) est detectee au
  chargement - la config est remise aux defaults plutot que d'etre appliquee
  silencieusement.

- **PRNG securise** : rand_bytes() remplace par getrandom::fill() qui appelle
  directement getentropy(2) sur macOS. Le fallback horloge precedent produisait
  des MAC addresses predictibles en cas d'erreur /dev/urandom.

- **ts_helper SUID - tee supprime** : /usr/bin/tee etait dans la whitelist SUID.
  GTFOBins documente tee SUID comme vecteur d'ecriture arbitraire root
  (echo DATA | tee /etc/sudoers). Remplace par un verbe interne write-pf-conf
  avec chemin /etc/pf.conf hardcode dans le C et O_NOFOLLOW sur open().

- **ensure_helper() - symlink attack** : le binaire helper etait compile dans
  opsec_dir() (accessible a l'utilisateur). Un attaquant pouvait remplacer le
  fichier temporaire entre la compilation et le chown root+chmod 4755 via
  osascript. Correction : compilation dans /tmp avec nom aleatoire non
  predictible (tempfile + O_CREAT|O_EXCL), verification symlink_metadata()
  post-compilation avant l'elevation.

- **pf anchor - table au bon endroit** : table <apple_relay> deplacee de
  l'anchor file vers /etc/pf.conf. Les tables definies dans les anchors causent
  des echecs silencieux au boot sur macOS (comportement OpenBSD non porte).
  Source : iyanmv.medium.com/setting-up-correctly-packet-filter-pf-firewall.

- **user.js - strip() precise** : la fonction de nettoyage des prefs Firefox
  filtrait par substring (.contains()), supprimant les commentaires et prefs
  tierces dont le nom contenait accidentellement un mot-cle bloque. Corrige :
  filtrage par prefixe exact sur les lignes user_pref("...") uniquement.

- **CanvasBlocker via Tor** : le telechargement du XPI depuis addons.mozilla.org
  passait en direct (IP reelle exposee). Corrige : proxy socks5h://127.0.0.1:9050
  sur le client reqwest.

### Dependances ajoutees

- getrandom 0.3 - RustCrypto, backend getentropy macOS
- hmac 0.13 - RustCrypto, 448M telechargements
- sha2 0.11 - RustCrypto, 718M telechargements
- tempfile 3 - deja dans le graphe transitif (tauri-bundler)
- security-framework 3 - bindings Apple Security.framework, 292M telechargements

---

## v0.5.1 - 2026-06-xx

- User-Agent Firefox dynamique (detecte la version installee)
- Blocage iCloud Private Relay (17.0.0.0/8) dans le kill switch pf
- ts_helper securise (premiere version de la whitelist SUID)

## v0.5.0

- Kill switch pf avec architecture anchor Mullvad-style
- LaunchDaemon watchdog : flush l'anchor si TorShield crash

## v0.4.1

- Kill switch pf robuste
- env_inject sans launchctl (hook zshrc uniquement)
- env_inject desactive par defaut
- NO_PROXY etendu (github, anthropic, claude.ai)

## v0.4.0

- Injection env vars (HTTP_PROXY/HTTPS_PROXY pour Python, curl, Go, Node)
- SUID helper auto-installe (premiere version)
- Blocage QUIC/HTTP3 dans pf
- Menu Dependencies en temps reel

## v0.3.0

- Hardening fingerprint Firefox (resistFingerprinting, spoofOsAsWindows)
- CanvasBlocker installe automatiquement
- Spoofing User-Agent Windows
- Langue neutralisee (en-US)

## v0.2.0

- Interface en anglais
- DNS leak fix via dnsmasq (port 9053 Tor)
- MAC spoofing avec OUI Apple legitimes
- Rotation automatique d'identite Tor (5/15/30 min)

## v0.1.0

- Premiere version : app menubar macOS native (Tauri 2)
- Proxy SOCKS5 systeme via Tor
- Desactivation IPv6
- Effacement des logs systeme
- Exclusion de noeuds de sortie par pays

<div align="center">

<p><strong>⭐ If Wombat is useful to you, please <a href="https://github.com/ventz/wombat-wireguard-mac-app">star the repo</a>.</strong> Stars help it get into the official Homebrew catalog.</p>

<img src="docs/images/icon.png" alt="Wombat logo: a white ribbon folded into a W on a deep red rounded square" width="160">

<h1>Wombat</h1>

<p><strong>WireGuard®, AmneziaWG and Cisco AnyConnect in one app: the last VPN software you need.</strong></p>

<p>
A native, free and open-source VPN client for macOS. Secure first, easy and beautiful to use,
and powerful when you need it, with a command line developers will actually use.
</p>

<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/macOS-15%2B-black.svg" alt="macOS 15+">
<img src="https://img.shields.io/badge/Swift-SwiftUI-orange.svg" alt="Swift and SwiftUI">
<a href="https://github.com/ventz/wombat-wireguard-mac-app/stargazers"><img src="https://img.shields.io/github/stars/ventz/wombat-wireguard-mac-app?style=social" alt="GitHub stars"></a>

</div>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://wombat.vpetkov.net/screenshots/overview-dark.webp?v=6">
    <img src="https://wombat.vpetkov.net/screenshots/overview-light.webp?v=6" width="820"
         alt="Wombat's main window: a connected tunnel named Home with received and sent totals, the latest handshake, its interface and its peer">
  </picture>
</p>

## Table of Contents

- [Overview](#overview)
- [Quick Install](#quick-install)
- [Features](#features)
- [Usage](#usage)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Overview

The official WireGuard app for macOS has been effectively abandoned: its last commit was in
February 2023, and it still ships the wireguard-go of that era. The alternatives are either not
native (Electron or web views), not pretty, or not free (Passepartout, Shimo and others).

Wombat is a modern replacement that feels like part of macOS:

- **Native.** SwiftUI app, menu bar extra, and a packet tunnel that runs in Apple's Network
  Extension framework, so tunnels show up in System Settings › VPN and keep running when the
  app is closed.
- **Security first.** No root helper, no sudoers rules, no scripts run from configs, private
  keys never stored in world-readable places. See [Security](#security).
- **Developer friendly.** A complete CLI (`wombat status`, `up`, `show`, `check`, `logs -f`…),
  JSON output, a config linter with CI exit codes, and a skill that teaches coding agents to
  drive it.

Wombat speaks standard wg-quick `.conf` files and imports the official app's
**Export Tunnels to Zip** archive directly, so switching takes a minute. It also speaks
[AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go), the WireGuard variant that disguises
its traffic from deep packet inspection, so exports from the AmneziaWG app import too.

And it connects to **Cisco AnyConnect / Secure Client** gateways (ASA, Firepower, and the open
source ocserv), the VPN most universities and companies run, with sign-in by password, Duo,
single sign-on (SAML: Okta, Entra ID, Duo SSO…) or a client certificate from your keychain. One
app for your own WireGuard servers and your work or campus VPN, no Cisco client needed.

## Quick Install

1. Download **[Wombat.dmg](https://wombat.vpetkov.net/Wombat.dmg)** (always the latest version;
   also on [GitHub Releases](https://github.com/ventz/wombat-wireguard-mac-app/releases)).
2. Open it and drag **Wombat** into **Applications** (network extensions only run from there).
3. Open Wombat, then allow its network extension once: **System Settings › General › Login Items
   & Extensions** › **Extensions** › **By Category** › **ⓘ** next to **Network Extensions** ›
   under **Wombat.app**, turn on **Wombat Tunnel** › **Done**. Your first Cisco AnyConnect VPN
   asks once more: turn on **Wombat OpenConnect** there too.

Or with [Homebrew](https://brew.sh), which also puts the `wombat` command on your `PATH`:

```bash
brew trust --cask ventz/tap/wombat-wireguard
brew install --cask ventz/tap/wombat-wireguard
```

Homebrew 7 and later only load casks from third-party taps you have trusted. The first line trusts
just this cask; `brew trust --tap ventz/tap` trusts the whole tap instead. Skip it on older Homebrew.

Wombat is signed with a Developer ID, notarized by Apple, and updates itself. Requires macOS 15
or later (Apple silicon or Intel).

To build from source instead (needs a paid Apple Developer account: macOS only runs VPN system
extensions that are Developer ID signed), see [docs/DEVELOPING.md](docs/DEVELOPING.md):

```bash
brew install go xcodegen
git clone https://github.com/ventz/wombat-wireguard-mac-app && cd wombat-wireguard-mac-app
scripts/build-signed.sh --install
```

## Features

- **Import anything:** drag in `.conf` files, a zip of them, or paste from the clipboard. Every
  import shows where traffic will go and what's risky before anything is saved.
- **Cisco AnyConnect:** add a VPN by its gateway address and sign in the way your organization
  does: password, Duo (push, call or passcode), SAML single sign-on in your default browser
  (passkeys and password managers work) or inside Wombat, or a keychain certificate. The
  sign-in shows right on the VPN's Overview, with no pop-up windows. Runs on
  [OpenConnect](https://www.infradead.org/openconnect/) with DTLS, in its own system extension.
  Profiles export as `.anyconnect` files to share with colleagues. See
  [docs/OPENCONNECT.md](docs/OPENCONNECT.md).
- **QR codes:** scan a tunnel's QR code with the Mac's camera (or an iPhone as Continuity
  Camera), or import a screenshot or picture of one. Going the other way, Show QR Code puts a
  tunnel on your phone, after Touch ID.
- **AmneziaWG:** configs with AmneziaWG 1.0 to 2.0 settings (`Jc`, `S1`-`S4`, `H1`-`H4`,
  `I1`-`I5`) run on amneziawg-go and connect to AmneziaWG servers. Plain WireGuard tunnels keep
  running upstream wireguard-go; the two engines share one app.
- **Live status:** per-peer handshakes, endpoints and transfer in the window; transfer and the
  latest handshake in the menu bar.
- **Config review:** flags DNS leaks, IPv4/IPv6 leaks, overlapping AllowedIPs, DNS servers
  outside the tunnel, missing preshared keys, and ignored `PostUp`-style scripts.
- **On demand:** connect automatically on Wi-Fi and Ethernet, except on trusted networks.
  Evaluated by macOS, so it works with the app closed.
- **Kill switch:** route everything through the tunnel, also while it reconnects, with
  an option to allow the local network. On by default for full-tunnel configs.
- **Editor:** a plain-text wg-quick editor with line-numbered errors as you type. Keys stay
  hidden until you unlock with Touch ID.
- **Command line:** connect, disconnect, import, export, rename, delete, on-demand and kill
  switch, status and stats with JSON output, plus offline key and lint tools.
- **Updates itself:** signed updates through Sparkle, with the choice of an update window, only a
  dot on the Settings button, or no checks.
- **Accessible:** VoiceOver labels and announcements, keyboard navigation, status shown by shape
  as well as color.

## Usage

```bash
wombat import ~/Downloads/home.conf   # approve in the app
wombat up home
wombat import work.anyconnect         # a Cisco AnyConnect VPN
wombat up work                        # sign in in Wombat (password, Duo, SSO)
wombat show home                      # like `wg show`
wombat check *.conf --strict          # lint; exit 1 on errors or risks
(umask 077; wombat genkey > priv.key) && wombat pubkey < priv.key
wombat logs -f                        # stream app and tunnel logs
```

`wombat help` lists every command; see [docs/CLI.md](docs/CLI.md) for the reference, exit codes and
shell completion. The Homebrew cask installs the CLI; otherwise Wombat's Settings › Command Line
shows the command and whether it is installed.

Credit: the command line's scope was modeled on the `ctl` tool of
[wireguide](https://github.com/korjwl1/wireguide) by korjwl1.

## Security

Security is the first design goal, ahead of speed and convenience.

- **No privileged helper.** The tunnel runs only inside Apple's sandboxed Network Extension.
- **Keys stay private.** The app keeps each config in your login keychain. The extension
  receives its own copy over a code-signed XPC connection and stores it where only root can
  read it. Nothing secret goes into macOS's VPN preferences file, which every user can read.
- **Configs can't run code.** `PostUp`, `PreDown` and friends are parsed, flagged and ignored.
  AmneziaWG settings are checked against Wombat's own limits, so a downloaded file can't make
  the tunnel send oversized or endless junk before each handshake.
- **The CLI can't silently weaken you.** Importing, deleting, renaming, disconnecting or switching
  away from a protected tunnel, turning off on-demand or the kill switch, and exporting keys all
  need your approval (or Touch ID) in the app.
- **Fails closed.** If macOS doesn't apply the tunnel's routes and DNS, the tunnel doesn't report
  itself as connected; the address family a full tunnel leaves out is blocked, not leaked. A
  tunnel edited while the extension wasn't running never starts from its old configuration.
- **Safe on shared Macs.** VPN settings are system-wide, but each macOS user sees and starts only
  their own tunnels. (An on-demand tunnel may come up at the login window before anyone signs in,
  and stops when another account signs in.)
- **AnyConnect is walled off.** OpenConnect's C code runs in a second system extension, a
  separate sandboxed process that never holds a WireGuard key. Sign-in is Wombat's own Swift
  code: client certificates are used through the keychain (the private key never leaves it), the
  session token goes to the extension over the signed XPC connection and lives only in memory,
  and the tunnel accepts only the gateway certificate macOS trusted at sign-in. Gateways that
  demand a Cisco host scan are refused: Wombat never runs programs a server sends. The bundled
  OpenConnect library is built with every process-spawning call stubbed out and is patched for
  memory-safety bugs reachable from a hostile gateway (see
  [Vendor/openconnect/WOMBAT.md](Vendor/openconnect/WOMBAT.md)).
- **Signed end to end.** Developer ID signed and notarized; the app, extension and CLI check each
  other's signatures, and updates are EdDSA-signed on top.

Details and the threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Documentation

| Document | What's in it |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, where secrets live, trust boundaries, leak protection |
| [docs/OPENCONNECT.md](docs/OPENCONNECT.md) | Cisco AnyConnect: sign-in methods, profiles, what's supported, how it's isolated |
| [docs/CLI.md](docs/CLI.md) | Every `wombat` command, JSON output, exit codes, completion |
| [docs/DEVELOPING.md](docs/DEVELOPING.md) | Building, signing, the test peer, debugging |

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). This is a personal
project with no promise of support.

## Acknowledgements

- The tunnel engine is [wireguard-go](https://git.zx2c4.com/wireguard-go) and WireGuardKit from
  [wireguard-apple](https://git.zx2c4.com/wireguard-apple), both MIT, © WireGuard LLC.
- AmneziaWG tunnels run on [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go), MIT
  (license © WireGuard LLC); Wombat's changes to it are listed in
  [Vendor/amneziawg-go/WOMBAT.md](Vendor/amneziawg-go/WOMBAT.md).

- AnyConnect tunnels run on [OpenConnect](https://www.infradead.org/openconnect/) (libopenconnect,
  LGPL-2.1, © David Woodhouse and contributors) with [OpenSSL](https://www.openssl.org/) 3.5 LTS
  (Apache-2.0); see [Vendor/openconnect/WOMBAT.md](Vendor/openconnect/WOMBAT.md) for how they are
  built and relinked.

“WireGuard” and the “WireGuard” logo are registered trademarks of Jason A. Donenfeld. Wombat is
not affiliated with or endorsed by the WireGuard project. See [wireguard.com](https://www.wireguard.com/).
Cisco, AnyConnect and Cisco Secure Client are trademarks of Cisco Systems, Inc.; Wombat is not
affiliated with or endorsed by Cisco.

## License

[MIT](LICENSE) © Ventz Petkov

<div align="center">

<img src="docs/images/icon.png" alt="Wombat logo: a white ribbon folded into a W on a deep red rounded square" width="160">

<h1>Wombat</h1>

<p>
A native, free and open-source WireGuard® client for macOS, built security-first: SwiftUI app,
Apple Network Extension, and a <code>wombat</code> command line for developers.
</p>

<a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/macOS-15%2B-black.svg" alt="macOS 15+">
<img src="https://img.shields.io/badge/Swift-SwiftUI-orange.svg" alt="Swift and SwiftUI">

</div>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://wombat.vpetkov.net/screenshots/overview-dark.webp?v=4">
    <img src="https://wombat.vpetkov.net/screenshots/overview-light.webp?v=4" width="820"
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
**Export Tunnels to Zip** archive directly, so switching takes a minute.

## Quick Install

Wombat isn't released yet. To build it from source you need Xcode 26+, Go, XcodeGen and a paid
Apple Developer account: macOS only runs VPN system extensions that are Developer ID signed.

```bash
brew install go xcodegen
git clone https://github.com/ventz/wombat-wireguard-mac-app && cd wombat-wireguard-mac-app
scripts/build-signed.sh --install     # Developer ID signed, notarized, copied to /Applications
```

Then allow the network extension, once:

1. Open **System Settings › General › Login Items & Extensions**.
2. Scroll to **Extensions** and choose **By Category**.
3. Click **ⓘ** next to **Network Extensions**, turn on **Wombat.app**, and click **Done**.

See [docs/DEVELOPING.md](docs/DEVELOPING.md) for signing details.

## Features

- **Import anything:** drag in `.conf` files, a zip of them, or paste from the clipboard. Every
  import shows where traffic will go and what's risky before anything is saved.
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
wombat show home                      # like `wg show`
wombat check *.conf --strict          # lint; exit 1 on errors or risks
wombat genkey | tee priv.key | wombat pubkey
wombat logs -f                        # stream app and tunnel logs
```

`wombat help` lists every command; see [docs/CLI.md](docs/CLI.md) for the reference, exit codes and
shell completion. To install the CLI, Wombat's Settings › Command Line shows the one-line command.

Credit: the command line's scope was modeled on the `ctl` tool of
[wireguide](https://github.com/korjwl1/wireguide) by korjwl1.

## Security

Security is the first design goal, ahead of speed and convenience.

- **No privileged helper.** The tunnel runs only inside Apple's sandboxed Network Extension.
- **Keys stay private.** The app keeps each config in your login keychain. The extension
  receives its own copy over a code-signed XPC connection and stores it where only root can
  read it. Nothing secret goes into macOS's VPN preferences file, which every user can read.
- **Configs can't run code.** `PostUp`, `PreDown` and friends are parsed, flagged and ignored.
- **The CLI can't silently weaken you.** Importing, deleting, renaming, switching away from a
  protected tunnel, turning off on-demand or the kill switch, and exporting keys all need your
  approval (or Touch ID) in the app.
- **Fails closed.** If macOS doesn't apply the tunnel's routes and DNS, the tunnel doesn't report
  itself as connected; the address family a full tunnel leaves out is blocked, not leaked. A
  tunnel edited while the extension wasn't running never starts from its old configuration.
- **Safe on shared Macs.** VPN settings are system-wide, but each macOS user sees and starts only
  their own tunnels.
- **Signed end to end.** Developer ID signed and notarized; the app, extension and CLI check each
  other's signatures, and updates are EdDSA-signed on top.

Details and the threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). To report a
vulnerability, see [SECURITY.md](SECURITY.md).

## Documentation

| Document | What's in it |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, where secrets live, trust boundaries, leak protection |
| [docs/CLI.md](docs/CLI.md) | Every `wombat` command, JSON output, exit codes, completion |
| [docs/DEVELOPING.md](docs/DEVELOPING.md) | Building, signing, the test peer, debugging |

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). This is a personal
project with no promise of support.

## Acknowledgements

- The tunnel engine is [wireguard-go](https://git.zx2c4.com/wireguard-go) and WireGuardKit from
  [wireguard-apple](https://git.zx2c4.com/wireguard-apple), both MIT, © WireGuard LLC.

“WireGuard” and the “WireGuard” logo are registered trademarks of Jason A. Donenfeld. Wombat is
not affiliated with or endorsed by the WireGuard project. See [wireguard.com](https://www.wireguard.com/).

## License

[MIT](LICENSE) © Ventz Petkov

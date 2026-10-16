# Developing

## Contents

- [Requirements](#requirements)
- [Build](#build)
- [Release](#release)
- [Test](#test)
- [A local test peer](#a-local-test-peer)
- [Debugging](#debugging)
- [Layout](#layout)

## Requirements

- macOS 15+, Xcode 26+ (signed in to an Apple developer team), [XcodeGen](https://github.com/yonaskolb/XcodeGen), Go
- `brew install go xcodegen`

The team ID is set in `project.yml` (`DEVELOPMENT_TEAM`). Xcode creates the provisioning profiles
(Network Extension and System Extension capabilities) with `-allowProvisioningUpdates`; if it
reports "Unable to log in with account", sign out and back in under Xcode › Settings › Accounts.

**Only Developer ID builds can run tunnels.** A system extension needs the
`packet-tunnel-provider-systemextension` entitlement, which only Developer ID provisioning
profiles grant. A development-signed build installs, but macOS rejects its extension with the
misleading "NetworkExtension key must be a non-empty dictionary". Debug builds are still useful
for the UI, the CLI and demo screenshots.

## Build

A working build (Developer ID signed and notarized; needs the Developer ID Application
certificate and a `notarytool` keychain profile, `WOMBAT_NOTARY_PROFILE`):

```bash
scripts/build-signed.sh --install   # archive, Developer ID export, audit, notarize, staple, install
```

If Xcode can't create the Developer ID provisioning profiles itself (its account login fails),
`scripts/provision-profiles.py` makes them through the App Store Connect API. It needs a key
with the Admin or App Manager role (a notarization-only Developer key gets 403):

```bash
ASC_KEY_ID=<key id> ASC_ISSUER_ID=<issuer id> uv run scripts/provision-profiles.py
```

Forks: the team appears in `project.yml` (`DEVELOPMENT_TEAM`), `scripts/ExportOptions.plist`
(`teamID`) and the signing identity (`WOMBAT_SIGNING_IDENTITY`); the code reads the team from
its own signature. A fork that ships its own builds must also replace `SUFeedURL` and
`SUPublicEDKey` in `App/Info.plist` (or remove `SUFeedURL` to turn updates off); otherwise its
copies check Wombat's feed.

**Bump the build number for every signed build you install** (`CURRENT_PROJECT_VERSION` in
`project.yml`): the app only replaces an installed extension whose build number differs.

A Debug build, for UI work:

```bash
xcodegen generate                 # Wombat.xcodeproj from project.yml (not committed)
xcodebuild -project Wombat.xcodeproj -scheme Wombat -configuration Debug \
  -derivedDataPath build/DerivedData -allowProvisioningUpdates build
ditto "build/DerivedData/Build/Products/Debug/Wombat Debug.app" "/Applications/Wombat Debug.app"
```

The Debug build is **Wombat Debug** (`net.vpetkov.wombat.debug`): its own extension, app group,
keychain items and settings, so it runs beside a release copy. System extensions only activate
from `/Applications`. To allow one: System Settings › General › Login Items & Extensions, scroll
to Extensions, choose By Category, click ⓘ next to Network Extensions, turn the app on, Done.

The tunnel target's pre-build step runs `scripts/build-wg-go.sh`, which builds wireguard-go and
the vendored amneziawg-go into one universal static library (`build/wg-go/libwg-go.a`) against a
copy of the Go runtime patched so timers count sleep. It skips the rebuild when nothing changed.
`scripts/check-amneziawg-vendor.sh` shows how `Vendor/amneziawg-go` differs from upstream.

**Network Extension entitlement:** development profiles carry `packet-tunnel-provider`;
Developer ID needs `packet-tunnel-provider-systemextension`. `project.yml` sets
`NE_PACKET_TUNNEL` per configuration; `build-signed.sh` archives with the development value and
the Developer ID export rewrites it. The extension is embedded by a build-phase script, because
XcodeGen fixes the product file name from the first configuration, and a system extension's file
name must be its bundle ID.

## Release

`scripts/release.sh` cuts a release modeled on Moo's: `build-signed.sh` (archive, Developer ID
export, signature audit including Sparkle's nested code, notarize, staple), a drag-to-install DMG
(`scripts/create-dmg.sh`), DMG signing and notarization, the EdDSA-signed Sparkle appcast, upload
to the R2 bucket behind `wombat.vpetkov.net`, the stable `Wombat.dmg` download link, and a GitHub
release when `origin` is on GitHub.

```bash
scripts/release.sh --dry-run                 # build and package only
scripts/release.sh --notes notes/1.0.0.html  # publish (notes must be HTML: they're embedded)
```

One-time setup:

- **Sparkle key**, Wombat's own (never Moo's or Tardy's), in the login keychain:
  `build/DerivedDataRelease/SourcePackages/artifacts/sparkle/Sparkle/bin/generate_keys --account wombat`.
  Its public half is `SUPublicEDKey` in `App/Info.plist`; the script refuses to publish if they
  differ. Back up the private key (`generate_keys --account wombat -x <file>`): without it, no
  installed copy will ever accept another update.
- **Cloudflare:** `~/.config/cloudflare/.env` with `CLOUDFLARE_ADMIN_TOKEN`; the scripts pass only
  the token to a pinned wrangler.
- **Versions:** bump `MARKETING_VERSION` per release and `CURRENT_PROJECT_VERSION` per build.
  Sparkle orders updates by the build number, so the script refuses one that isn't above the
  published feed.

The app is sandboxed, so Sparkle downloads and installs through its own XPC services
(`SUEnableDownloaderService`, `SUEnableInstallerLauncherService`, and the `-spks`/`-spki`
mach-lookup exceptions in `App/Wombat.entitlements`). The app's own `network.client` entitlement
is for DNS: it looks up endpoint hostnames before a kill-switch tunnel starts.
Debug builds never check for updates; `open --env WOMBAT_PREVIEW_UPDATE=9.9.9 "Wombat Debug.app"`
shows the update dot.

## Test

```bash
(cd Packages/TunnelCore && swift test)
```

TunnelCore holds all the pure logic (parser, review, stats, zip, CLI protocol) and its tests.
Zip fixtures are made with `/usr/bin/zip` and the X25519 test vector was checked against Python's
`cryptography`, so the tests don't verify the code with itself.

## A local test peer

```bash
scripts/dev/test-peer.sh up      # WireGuard peer in Docker (OrbStack works), udp 51820
wombat import build/test-peer/wombat-test.conf
wombat up wombat-test && ping -c 3 10.99.0.1
docker exec wombat-test-peer wg show
scripts/dev/test-peer.sh down
```

The generated config routes only `10.99.0.0/24`, so the rest of the Mac's traffic, and any other
VPN, is untouched.

`scripts/dev/test-peer.sh up --awg` starts an AmneziaWG peer instead, built from upstream
amneziawg-go and amneziawg-tools (`scripts/dev/awg-peer`; the GPLv2 tools are only used inside
the container), and writes `build/test-peer/wombat-awg.conf` with AmneziaWG 2.0 settings. Check
it with `docker exec wombat-test-peer awg show`. To see the obfuscation on the wire, capture in
the container with `tcpdump -i eth0 -x udp port 51820`: the handshake starts with the I1 packet
and four junk packets, and no packet begins with WireGuard's `01 00 00 00` headers.

## Debugging

- `wombat doctor` first.
- `wombat logs -f`: app and extension logs. Or `/usr/bin/log stream --predicate 'subsystem == "net.vpetkov.wombat.debug"'`
  (zsh has a `log` builtin, so use the full path).
- Activation problems are logged by `sysextd`; tunnel start problems by `nesessionmanager` and the
  extension. `systemextensionsctl list` shows the installed extension and its state.
- Launch the app with a clean environment from a terminal:
  `env -i HOME="$HOME" USER="$USER" PATH=/usr/bin:/bin open "/Applications/Wombat Debug.app"`.

## Layout

| Path | What |
|---|---|
| `App/` | SwiftUI app: `Model/` (store, keychain, extension hand-over), `Control/` (CLI socket), `Views/` |
| `Tunnel/` | The packet tunnel system extension and its root-only `SecretStore` |
| `CLI/` | `wombat` |
| `Shared/` | Identifiers and code-signing requirements used by all three |
| `Packages/TunnelCore/` | Pure logic and tests |
| `Vendor/WireGuardKit/` | WireGuardKit + wireguard-go bridge (MIT), with marked changes |
| `scripts/` | Signed build and release, DMG, Go bridge, app and menu bar icons, site publishing, dev tools (`dev/`: test peer, screenshots) |

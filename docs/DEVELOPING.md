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
- For the OpenConnect extension: nothing extra. `scripts/build-openconnect.sh` (a build phase)
  downloads openconnect and OpenSSL once, checks their SHA-256 pins and builds them with the
  Xcode toolchain (a few minutes the first time; see [Vendor/openconnect/WOMBAT.md](../Vendor/openconnect/WOMBAT.md))

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
ASC_KEY_ID=<key id> ASC_ISSUER_ID=<issuer id> uv run --locked scripts/provision-profiles.py
```

The process holds that key, so every dependency, transitive ones included, is pinned in
`scripts/provision-profiles.py.lock` (`uv lock --script`, nothing newer than two weeks), and
`--locked` refuses to run when the lock and the script disagree.

Forks: the team appears in `project.yml` (`DEVELOPMENT_TEAM`), `scripts/ExportOptions.plist`
(`teamID`) and the signing identity (`WOMBAT_SIGNING_IDENTITY`); the code reads the team from
its own signature. A fork that ships its own builds must also replace `SUFeedURL` and
`SUPublicEDKey` in `App/Info.plist` (or remove `SUFeedURL` to turn updates off); otherwise its
copies check Wombat's feed.

**Bump the build number for every signed build you install** (`CURRENT_PROJECT_VERSION` in
`project.yml`): the app only replaces an installed extension with a higher build number. To go
back to an older build, remove the extension first (System Settings › General › Login Items &
Extensions), or the older app keeps running against the newer extension.

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
  Its public half is `SUPublicEDKey` in `App/Info.plist`. Back up the private key in a password
  manager (Keychain Access › the `https://sparkle-project.org` item, account `wombat` › Show
  password; Universal Clipboard can pass it to your other devices, so turn Handoff off first and
  clear the clipboard after pasting it): without it, no installed copy will ever accept another
  update.

  `release.sh` reads it **once per release** (`scripts/lib-release-signing.sh`):
  `/usr/bin/security find-generic-password -s https://sparkle-project.org -a wombat -w` into a
  shell variable, handed to `sign_update` and `generate_appcast` on stdin (`--ed-key-file -`), so
  no Sparkle tool asks the keychain itself (that was one prompt per run, about four per
  release). The key never goes into argv, a file or a trace, and is cleared after its last use.
  `generate_keys -p` would read the keychain again, so the script proves the key matches
  `SUPublicEDKey` by signing a random probe and verifying it with CryptoKit: before the build
  (against `App/Info.plist`) and after it (against the built app), which needs `/usr/bin/swift`.
  Dry runs read and check it too. The key stays in an unexported shell variable for the whole
  run (build, notarization, uploads). The guards stop accidental leaks, such as `bash -x` or a
  `PS4` from the environment; the environment itself (`BASH_ENV`, imported shell functions) is
  trusted.

  **The one prompt** reads "security wants to use your confidential information stored in
  "https://sparkle-project.org" in your keychain" (it may also ask for the login keychain
  password). Click **Allow**, not **Always Allow**. Always Allow adds `/usr/bin/security` to the
  item's access list, and after that any process running as you can read the update-signing key
  silently with the same command. If it was clicked, removing `security` from the item's Access
  Control tab in Keychain Access may not undo it all (the item's partition list isn't shown
  there): the safe undo is to delete the item and import the key again from the backup with
  `generate_keys --account wombat -f <file>`, the file made with `umask 077` in a folder that
  isn't synced or indexed (not the Desktop, Documents or this repo), deleted right after.
  codesign's prompts for the Developer ID key are separate.
- **Cloudflare:** `~/.config/cloudflare/.env` with `CLOUDFLARE_ADMIN_TOKEN`, or better a
  `WOMBAT_R2_TOKEN` limited to the R2 bucket (used first when set). The scripts pass only that
  token to wrangler, which `scripts/lib-wrangler.sh` installs from `scripts/tools/package-lock.json`
  with `npm ci --ignore-scripts` (into `build/tools`). To bump wrangler, change the version in
  `scripts/tools/package.json` and run `npm install --package-lock-only --ignore-scripts` there.
- **Sparkle** is pinned by commit in `project.yml` (`revision:`), since `Package.resolved` isn't
  committed. To bump it, use the new tag's commit (`git ls-remote https://github.com/sparkle-project/Sparkle refs/tags/<tag>`).
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

TunnelCore holds all the pure logic (parser, review, stats, zip, CLI protocol, the AnyConnect
profile, XML protocol, sign-in and network plan) and its tests.
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

### AnyConnect against a local gateway

```bash
scripts/dev/ocserv-peer.sh up            # ocserv in Docker on 127.0.0.1:4443: password + one-time code
scripts/dev/ocserv-peer.sh up --cert     # client certificate + password
scripts/dev/oc-probe.sh                  # Swift sign-in + libopenconnect tunnel phase, no NetworkExtension
(cd Packages/TunnelCore && WOMBAT_OCSERV_LIVE=1 swift test --filter AnyConnectLive)
scripts/dev/ocserv-peer.sh otp           # the current one-time code, for signing in by hand
```

The probe signs in, connects CSTP, runs the main loop on a socket pair, forces a reconnect,
stops (the gateway logs the BYE), logs off a session that never reached the main loop, and
checks that a different certificate and an untrusted one are refused. In a Developer ID build,
import `build/ocserv-peer/wombat-ocserv.anyconnect` and sign in as `test` / `test-password`.

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
| `Tunnel/` | The WireGuard packet tunnel system extension |
| `OpenConnect/` | The AnyConnect system extension: libopenconnect wrapper, provider, in-memory sessions |
| `ExtensionShared/` | Code both extensions compile: the root-only `SecretStore`, the log buffer |
| `CLI/` | `wombat` |
| `Shared/` | Identifiers and code-signing requirements used by all three |
| `Packages/TunnelCore/` | Pure logic and tests |
| `Vendor/WireGuardKit/` | WireGuardKit + wireguard-go bridge (MIT), with marked changes |
| `Vendor/openconnect/` | The no-exec stubs, license texts and notes for the libopenconnect build |
| `scripts/` | Signed build and release, DMG, Go bridge, app and menu bar icons, site publishing, dev tools (`dev/`: test peer, screenshots) |

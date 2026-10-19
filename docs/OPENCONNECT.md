# Cisco AnyConnect (OpenConnect)

Wombat connects to Cisco AnyConnect and Cisco Secure Client gateways (ASA, Firepower Threat
Defense) and to [ocserv](https://ocserv.openconnect-vpn.net/), the open-source server that speaks
the same protocol. The tunnel runs on [OpenConnect](https://www.infradead.org/openconnect/); the
sign-in is Wombat's own.

## Contents

- [Adding a VPN](#adding-a-vpn)
- [Signing in](#signing-in)
- [What's supported](#whats-supported)
- [Profile files](#profile-files)
- [How it's isolated](#how-its-isolated)
- [Kill switch and routes](#kill-switch-and-routes)
- [Troubleshooting](#troubleshooting)
- [Testing locally](#testing-locally)

## Adding a VPN

**+** › **Add AnyConnect VPN…**, then the gateway address your organization gives you
(`vpn.example.edu`, or a group URL such as `https://vpn.example.edu/staff`). Group, username and
client certificate are optional. The first AnyConnect VPN asks you to allow Wombat's second
system extension once, in System Settings › General › Login Items & Extensions › Network
Extensions (ⓘ).

From the command line: `wombat import work.anyconnect` (approved in the app), then `wombat up work`.

## Signing in

Each connect signs in, the way the gateway asks:

| Method | What you see |
|---|---|
| Password | The gateway's own form (username, password, group list) |
| Duo, RSA, OTP | A second form after the password: type a passcode, or `push` / `phone` where Duo offers them |
| SAML single sign-on (Okta, Entra ID, Duo SSO, Shibboleth…) | **In your default browser** when the gateway allows it (Cisco's "external browser" mode): passkeys, Touch ID, password managers and your identity provider's existing session work there. Otherwise inside Wombat (on the VPN's Overview), with cookies are kept per VPN, apart from Safari; **Forget Sign-In Data** in the Actions menu clears them. Edit VPN › Advanced can make it always sign in inside Wombat |
| Client certificate | Chosen once in the VPN's settings from your keychain. Smart cards aren't supported yet. macOS asks before Wombat may use the key |

The sign-in appears on the VPN's Overview, under Gateway (Wombat brings its window forward). It
always shows the gateway, and during single sign-on the bar shows which site the page is on.
Sign in only where you expect to.

If macOS doesn't trust the gateway's certificate (self-signed or a private CA), Wombat shows its
SHA-256 fingerprint and connects only if you choose to trust it; from then on it accepts exactly
that certificate for that VPN. Check the fingerprint with your IT department first. A VPN
with a pinned certificate always signs in inside Wombat, never in the default browser: a browser
can't check the pin, so it could hand the sign-in to an impostor.

## What's supported

- AnyConnect "aggregate auth" (the XML protocol of AnyConnect 3 and later), group lists and group
  URLs, multi-step forms, the pre-login banner.
- SAML in the default browser (`single-sign-on-external-browser`, with Cisco's STRAP keys) or
  inside Wombat (`single-sign-on-v2`), whichever the gateway is set to.
- TLS client certificates.
- CSTP over TLS 1.2+ and DTLS 1.2 (falls back to TLS when UDP is blocked; turn DTLS off per VPN
  under Advanced).
- Split tunnels, split DNS, IPv4 and IPv6, reconnects after sleep and network changes.

Not supported, by design or for now:

- **Cisco host scan (HostScan / CSD / posture).** A gateway that requires it is refused with a
  clear message: running a program the server sends is exactly what Wombat never does.
- Multiple-certificate (machine plus user) authentication.
- **On demand.** Each connect needs a sign-in, which macOS can't do on its own.
- Other OpenConnect protocols (GlobalProtect, Pulse, Fortinet, F5): possible later.

## Profile files

An AnyConnect VPN is stored as a small profile, which you can export (**Actions › Export
Profile…**) and share: it holds no password, key or session.

```ini
[AnyConnect]
Server = https://vpn.example.edu/staff
Group = Staff
Username = jdoe
ClientCertificate = sha256:3f2a…   # the certificate's SHA-256; the key stays in the keychain
ServerCertificate = sha256:9b1c…   # only for a gateway macOS doesn't trust
UserAgent = AnyConnect Darwin_i386 4.10.08029   # only if the gateway insists
DTLS = off                         # default on
SingleSignOn = window              # default browser: the system browser when the gateway allows it
                                   # (never with ServerCertificate: a browser can't check a pin)
```

The server must be `https://`. Keys that would run something (`CSDWrapper`, `Script`, `PostUp`
and the like) are refused. `wombat check work.anyconnect` lints a profile offline.

## How it's isolated

```
 App (sandboxed)                         OpenConnect extension (root, sandboxed, own process)
 ───────────────                         ─────────────────────────────────────────────────────
 Swift sign-in over URLSession     ──►   profile copy (0600, root-only container)
   macOS trust or your pin               session token (memory only, ≤ 10 min until used)
   keychain identity (key stays)         libopenconnect: CSTP/DTLS tunnel only
   SAML in WKWebView                     certificate = the one seen at sign-in, checked again
 session token ── signed XPC ──►         with macOS trust (or the pin)
```

- **Two processes, two sandboxes.** WireGuard keys live in the WireGuard extension; OpenConnect's
  C code runs only in the OpenConnect extension. A memory-safety bug triggered by a hostile
  gateway can't reach WireGuard keys.
- **Sign-in in Swift.** The app talks the AnyConnect XML protocol itself, with sizes capped and
  DTDs refused. libopenconnect never sees your password or certificate: as its own documentation
  notes, the tunnel needs only the session token.
- **Write-only hand-off.** The app hands the profile and the token to the extension over the
  same code-signed, root-checked XPC service as WireGuard configurations; nothing can read them
  back. The token is bound to the macOS user and the profile's revision, is used within 10
  minutes, and is logged off at the gateway when the tunnel stops.
- **The browser's answer is encrypted.** In browser mode the token comes back through a one-shot
  listener on `localhost:29786` (loopback only, gone after one request), encrypted to that
  sign-in's STRAP key (ECDH P-256, HKDF-SHA256, AES-256-GCM); the browser is redirected only to
  the gateway's own page. The STRAP signing key then binds the tunnel to the sign-in.
- **Patched where upstream trusts the gateway.** libopenconnect 9.21 trusted the gateway's MTU
  (a value near 2³¹ overwrote the extension's heap) and kept any number of its headers; Wombat's
  build bounds both ([Vendor/openconnect/WOMBAT.md](../Vendor/openconnect/WOMBAT.md)).
- **No programs, ever.** libopenconnect is compiled with every process-spawning call replaced by
  a stub that fails (`fork`, `exec*`, `posix_spawn`, `system`), and both the build and the
  release audit check the binary for it.
- **The same certificate.** The extension connects to the IP address the sign-in talked to and
  accepts only the certificate the app saw, re-evaluated with macOS trust (OpenSSL gets no trust
  store of its own).

## Kill switch and routes

The gateway decides the routes when the tunnel connects, so AnyConnect VPNs start with the kill
switch off: on a split-tunnel VPN it would send everything to a gateway that drops it. Turn it on
in the Connection tab when your gateway carries all traffic. When the gateway routes all IPv4 but
not all IPv6 (or the reverse), the other family is kept inside the tunnel, never leaked, by the
same rules as WireGuard (see "Leak protection" in ARCHITECTURE.md): routing only `8000::/1`
doesn't count as routing IPv6, and an IPv6-only gateway that routes `2000::/3` blocks IPv4.

## Troubleshooting

- `wombat doctor` shows whether the OpenConnect extension is installed and enabled.
- `wombat logs -f` streams the extension's log; the Log tab shows the same for one VPN.
- "isn't trusted by macOS" when connecting although the sign-in worked: the gateway's CA is
  trusted only in your login keychain's trust settings, which the extension (running as root)
  doesn't use. Have IT install the CA system-wide, or pin the gateway's certificate under
  Advanced.
- "requires a Cisco host scan": the gateway's policy needs HostScan; ask whether a group without
  posture checks exists.
- "certificate … changed since you signed in": the gateway presented a different certificate to
  the tunnel than at sign-in; Wombat stopped. Retry; if it persists, tell your IT department.
- "Sign in from Wombat to connect this VPN": the VPN was started from System Settings or after
  its session expired. Connect it from Wombat, the menu bar or `wombat up`.
- Some gateways only answer clients that call themselves AnyConnect: set **User agent** under
  Advanced (for example `AnyConnect Darwin_i386 4.10.08029`).
- "couldn't listen on localhost port 29786": another VPN client (Cisco Secure Client) holds the
  port the browser answers on. Quit it, or turn off browser sign-in under Advanced.

Tested against: ocserv 1.3 (password + one-time code, client certificates): sign-in and tunnel. A
Cisco ASA with Okta single sign-on answered the sign-in start and negotiated TLS 1.3; the full
sign-in there needs a real account.

## Testing locally

```bash
scripts/dev/ocserv-peer.sh up            # ocserv in Docker on 127.0.0.1: password, then a one-time code
scripts/dev/ocserv-peer.sh up --cert     # client certificate plus password
scripts/dev/oc-probe.sh                  # Swift sign-in + libopenconnect tunnel, outside NetworkExtension
(cd Packages/TunnelCore && WOMBAT_OCSERV_LIVE=1 swift test --filter AnyConnectLive)
```

Then import `build/ocserv-peer/wombat-ocserv.anyconnect` in a Developer ID build, sign in as
`test` / `test-password` with the code from `scripts/dev/ocserv-peer.sh otp`, and
`ping 10.98.0.1`.

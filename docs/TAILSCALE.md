# Tailscale and Headscale (preview)

Wombat joins [Tailscale](https://tailscale.com/) tailnets, and tailnets run by
[Headscale](https://headscale.net/), the open-source coordination server you host yourself. The
tunnel runs Tailscale's open-source client (the same Go code as the official apps' core). The app,
the sign-in flow and the checks on what the coordination server may change are Wombat's own.

New in 1.4 as a **preview**: joining a tailnet, signing in, tailnet addresses and MagicDNS work.
The items under [What the preview leaves out](#what-the-preview-leaves-out) come later.

## Contents

- [Adding a tailnet](#adding-a-tailnet)
- [Signing in and out](#signing-in-and-out)
- [MagicDNS](#magicdns)
- [What the coordination server can change](#what-the-coordination-server-can-change)
- [How it's isolated](#how-its-isolated)
- [What the preview leaves out](#what-the-preview-leaves-out)
- [Troubleshooting](#troubleshooting)
- [Testing locally with Headscale](#testing-locally-with-headscale)

## Adding a tailnet

**+** › **Add Tailnet (Preview)…**. Leave **Coordination server** empty for Tailscale's own
server, or enter your Headscale's address (`https://headscale.example.com`). **Host name** is how
this Mac appears in the tailnet; empty uses the Mac's name. The first tailnet asks you to allow
Wombat's third system extension once, in System Settings › General › Login Items & Extensions ›
Network Extensions (ⓘ): turn on **Wombat Tailnet**.

The coordination server must be on `https` with a host name. IP-address servers, loopback and
names with a trailing dot are refused, because a sign-in page could never be checked against
them.

## Signing in and out

Connect the tailnet, then click **Sign In…** on its Overview. Your coordination server's sign-in
page opens in your default browser, so your identity provider, passkeys and password manager
work as usual. The page opens only from that click, and only if it is on your coordination
server's own address (for Tailscale's server, `tailscale.com`). Wombat never shows a link that a
server pushes on its own.

With Headscale, an administrator approves the new node (`headscale auth register …`); the page
shows the command.

After that, the node signs in with its saved keys on every connect. **Sign Out** expires this
Mac's key at the coordination server. Deleting a connected tailnet signs it out first.

## MagicDNS

With **Use MagicDNS** on, your tailnet's names (`nas.example.ts.net`, `laptop.example.internal`)
resolve through the tailnet. Every other name stays on your Mac's own DNS. Use full names:
Wombat doesn't add the tailnet's domain as a search domain, so a bare `nas` stays on your normal
DNS.

The first DNS name a tailnet uses is the one it keeps. If the coordination server later names a
different one, Wombat leaves it out and says so in the Log tab. To accept the new name, remove
the tailnet and add it again.

## What the coordination server can change

Wombat treats the coordination server as able to make mistakes, or as hostile. Before macOS sees
anything the server proposes, Wombat checks it:

| The server proposes | Wombat accepts |
|---|---|
| This Mac's address | Only one IPv4 address in `100.64.0.0/10` and one IPv6 address in `fd7a:115c:a1e0::/48`. Anything else ends the connection |
| Routes | Only routes inside tailnet space and to the tailnet's resolver. Never a default route, your LAN, or another network |
| DNS servers | Only the tailnet's own resolver (`100.100.100.100`), and only when it is routed into the tunnel |
| DNS domains | Only the tailnet's reverse-lookup zones and its one MagicDNS name. Never a public suffix (`co.uk`, `github.io`) and never another domain |
| Sign-in page | Only on the server's own address, opened only by your click |

Tailnet Lock state is kept on disk, so a compromised coordination server can't turn Tailnet Lock
off between connects. Wombat also ignores two things a server can ask Tailscale's client to do:
ping an arbitrary URL from your Mac, and exit the extension.

## How it's isolated

- **Its own system extension.** The engine runs in a third extension ("Wombat Tailnet"), apart
  from your WireGuard keys and from AnyConnect.
- **Root-only keys.** The node's keys and state live in that extension's container, one folder
  per tailnet and coordination server. Keys never move between servers.
- **What the app sees.** The app gets the node's status, never its keys. The sign-in link is
  handed only to the click that asked for it.
- **Compiled out.** Tailscale SSH, Taildrop, the web interface, the local API, proxies, debug
  servers and log upload to Tailscale aren't built in. The build refuses to produce an engine
  that links them.
- **Can't start programs.** The extension can't start other programs.
- **Inbound blocked.** Peers can't open connections to this Mac (Tailscale's "shields up").

## What the preview leaves out

- **Exit nodes and subnet routes:** a tailnet carries tailnet traffic only.
- **On-demand and the kill switch.**
- **Command-line control:** `wombat up`, `down`, `list` and `export` work. Adding a tailnet and
  signing in happen in the app.
- **One VPN at a time:** macOS runs one VPN at a time, so connecting a tailnet switches off your
  other tunnel, as with any VPN app.

## Troubleshooting

- **The switch flips back off:** the Overview shows why. The **Log** tab has the extension's
  side, including anything the coordination server sent that Wombat left out.
- **"Sign In…" says the page isn't on the server's own address:** the server's `server_url`
  doesn't match the address you entered (check the host and port).
- **"The Tailnet extension didn't start":** check that **Wombat Tailnet** is on in System
  Settings › General › Login Items & Extensions › Network Extensions (ⓘ). If it is, turn it off
  and on again.

## Testing locally with Headscale

`scripts/dev/headscale-peer.sh up --https` starts a throwaway Headscale and a peer node in Docker,
at `https://headscale.wombat.test:8443` on this Mac's LAN address. Its certificate comes from a
CA made for that run, limited to that one name, and the CA's private key is deleted. The script
prints one `sudo` command that trusts the CA and maps the name, and `untrust` prints how to
remove both. After **Sign In…**, register the Mac with
`scripts/dev/headscale-peer.sh approve <auth id>`, then `ping peer.wombat-test.internal`.

# wombat CLI

`wombat` controls Wombat from the terminal and from scripts. Tunnel commands talk to the app (it
starts in the background if needed); key and lint commands work offline.

## Contents

- [Install](#install)
- [Tunnels](#tunnels)
- [Diagnostics](#diagnostics)
- [Offline tools](#offline-tools)
- [Approvals](#approvals)
- [JSON output](#json-output)
- [Exit codes](#exit-codes)
- [Shell completion](#shell-completion)
- [Coding agents](#coding-agents)

## Install

Installing with Homebrew (`brew install --cask ventz/tap/wombat-wireguard`) links it for you.
Otherwise the binary ships inside the app; link it onto your `PATH`. Settings › Command Line
shows the exact command, with a Copy button, and turns green once the link is in place:

```bash
sudo mkdir -p /usr/local/bin
sudo ln -sf "/Applications/Wombat.app/Contents/Helpers/wombat" /usr/local/bin/wombat
```

`/usr/local/bin` doesn't exist on a new Apple silicon Mac without Homebrew, hence the `mkdir`. It is
on the default `PATH` (`/etc/paths`), so no shell change is needed.

Tunnel commands go through the app, so Wombat must be running (`wombat start` opens it). Tunnels
themselves keep running when the app quits, and the offline tools work without it.

## Tunnels

| Command | Does |
|---|---|
| `wombat status [name] [--json]` | Tunnels and their state (aliases: `list`, `ls`; also the default command) |
| `wombat up <name>` | Connect (alias `connect`); waits until connected and reports. An AnyConnect VPN opens its sign-in window in Wombat first |
| `wombat down [name]` | Disconnect one tunnel, or all (alias `disconnect`) |
| `wombat toggle <name>` | Connect or disconnect |
| `wombat show [name] [--json]` | Peers, endpoints, latest handshake, transfer, like `wg show`; for AnyConnect the gateway, addresses, routes, DNS and transport |
| `wombat import <file\|-> [--name N]` | Add a tunnel (`.conf`) or an AnyConnect VPN (`.anyconnect` profile); you approve it in the app |
| `wombat export <name> [--with-keys]` | Print the config; keys need Touch ID or your password. An AnyConnect profile has no secrets |
| `wombat rename <name> <new-name>` | Rename |
| `wombat delete <name>` | Delete the tunnel and its keys; you approve it in the app |
| `wombat ondemand <name> on\|off [--no-wifi\|--wifi] [--no-ethernet\|--ethernet]` | Connect automatically (WireGuard only: AnyConnect needs a sign-in each time) |
| `wombat ondemand <name> trust\|untrust <wifi-name>` | Disconnect on (or stop trusting) a Wi-Fi network |
| `wombat killswitch <name> on\|off [--allow-lan]` | Block traffic outside the tunnel; the local network stays blocked unless `--allow-lan` |
| `wombat log <name>` | Recent log lines from the running tunnel |

## Diagnostics

| Command | Does |
|---|---|
| `wombat logs [-f] [--last 1h]` | App and extension logs from unified logging (`log stream` / `log show`) |
| `wombat routes` | Routes through tunnel interfaces (`utun*`) |
| `wombat dns` | The resolvers macOS uses now, and whether each goes through a tunnel |
| `wombat doctor` | Checks the install, the extension, the app, the socket, and macOS's VPN daemon |

`wombat doctor` also detects a known macOS failure: after weeks of uptime `nesessionmanager` can run
out of file descriptors. Extensions then fail to activate with a misleading "NetworkExtension key
must be a non-empty dictionary", and other VPNs lose on-demand. The fix is
`sudo killall nesessionmanager` (VPNs reconnect within seconds) or a restart.

## Offline tools

| Command | Does |
|---|---|
| `wombat check <file>... [--strict] [--json]` | Lint wg-quick files (AmneziaWG 1.0 to 2.0 settings included) and `.anyconnect` profiles: errors with line numbers, warnings, security review |
| `wombat genkey` | New private key (like `wg genkey`) |
| `wombat pubkey` | Public key for the private key on stdin (like `wg pubkey`) |
| `wombat genpsk` | New preshared key (like `wg genpsk`) |
| `wombat completion zsh\|bash` | Shell completion script |
| `wombat install-skill [--dir DIR]` | Write a skill that teaches coding agents to use `wombat` |

`check` in CI:

```bash
wombat check deploy/*.conf --strict   # exit 1 on any error, or any risk with --strict
```

## Approvals

The CLI is signed and the app verifies it, but any program running as you can run `wombat`. So
anything that adds a tunnel or weakens protection asks you in the app first:

- `import`, `delete` and `rename` (a rename could disguise one tunnel as another)
- `down` on a tunnel with on-demand (disconnecting turns on-demand off) or an active kill switch
  (traffic would then leave without the VPN)
- `up`, or `ondemand … on`, when another tunnel has on-demand or an active kill switch (Wombat
  runs one tunnel at a time, so that tunnel is switched off)
- turning on-demand off, connecting on fewer interfaces, trusting a Wi-Fi network (even while
  on-demand is off)
- allowing the local network through the kill switch
- turning the kill switch off and `export --with-keys` (Touch ID or password)

The command waits while the dialog is open (up to two minutes) and never sends a request twice.
"Cancel" is the default button, and after you decline (or cancel Touch ID), new prompts and
Touch ID requests are refused for 10 seconds, also across an app restart, so a script can't keep
asking. macOS's own controls (System Settings, `scutil --nc stop`) can still stop a tunnel. Before sending anything, `wombat` checks that the socket belongs to the
signed Wombat app, since an import carries a private key.

## JSON output

`--json` on `status`, `up`, `down`, `show`, `ondemand`, `import` and `check` prints JSON (dates in
ISO 8601). For example, `wombat status --json`:

```json
[
  {
    "addresses" : ["10.99.0.2/32"],
    "endpoint" : "203.0.113.10:51820",
    "name" : "home",
    "onDemand" : false,
    "protection" : { "allowLAN" : true, "killSwitch" : false },
    "protocol" : "wireguard",
    "status" : "connected"
  },
  {
    "addresses" : [],
    "endpoint" : "vpn.example.edu",
    "name" : "work",
    "onDemand" : false,
    "protection" : { "allowLAN" : true, "killSwitch" : false },
    "protocol" : "anyconnect",
    "status" : "disconnected"
  }
]
```

`onDemand` is whether macOS is running the tunnel's on-demand rules; `onDemandRules.enabled` is
the setting. They differ when another VPN configuration (another app's, or another account's)
became the enabled one: `status` then shows "on-demand (paused)".

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | The request failed (also: `check` found errors, or risks with `--strict`) |
| 2 | Usage error |
| 3 | The app can't be reached (`wombat start`, then `wombat doctor`) |

## Shell completion

```bash
wombat completion zsh > "${fpath[1]}/_wombat"     # zsh
wombat completion bash > /usr/local/etc/bash_completion.d/wombat
```

## Coding agents

`wombat install-skill` writes `~/.claude/skills/wombat/SKILL.md`, which tells Claude Code (and
other agents that read skills) which commands exist, that they must never print private keys,
and that imports wait for your approval.

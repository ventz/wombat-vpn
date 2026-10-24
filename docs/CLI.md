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
| `wombat killswitch <name> on\|off [--allow-lan]` | Block traffic outside the tunnel; the local network stays blocked unless `--allow-lan`, which also works with `off` for a split tunnel |
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
| `wombat completion install [zsh\|bash\|fish] [--dry-run] [--yes] [--force] [--dir DIR]` | Set up Tab completion for your shells (see [Shell completion](#shell-completion)) |
| `wombat completion status` / `uninstall [--dry-run]` | Show, or remove, what `install` set up |
| `wombat completion zsh\|bash\|fish` | Print a completion script |
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
- `up`, or `ondemand … on`, when none of your Wombat tunnels is the enabled VPN configuration:
  macOS enables one at a time, so another VPN app's configuration (with its on-demand rules and
  kill switch) may be switched off. Wombat can't see other apps' configurations, so it asks
  whenever that's possible. New tunnels are saved disabled for the same reason, and are enabled
  when first connected
- turning on-demand off, connecting on fewer interfaces, trusting a Wi-Fi network (even while
  on-demand is off)
- allowing the local network
- turning the kill switch off and `export --with-keys` (Touch ID or password)

The command waits while the dialog is open (up to two minutes) and never sends a request twice.
"Cancel" is the default button, and after you decline (or cancel Touch ID), new prompts and
Touch ID requests are refused for 10 seconds, doubling with each decline in a row (up to about
five minutes), also across an app restart, so a script can't keep asking. An unanswered Touch ID
request is canceled after two minutes, like a dialog. If the Wombat app is older than the
`wombat` command, the command refuses to talk to it. macOS's own controls (System Settings, `scutil --nc stop`) can still stop a tunnel. Before sending anything, `wombat` checks that the socket belongs to the
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

Completion covers commands, flags, `on`/`off` style arguments, files, and your tunnel names. The
names come from the app when it's running, and otherwise from macOS's VPN settings, so they
complete with the app closed too (`wombat` never starts the app just to complete a name). Each
name shows its state in zsh and fish. `up` offers the tunnels that aren't connected and `down`
the connected ones (all of them when none match); other commands offer every tunnel.
The scripts are in [`completions/`](../completions) and ship inside the app, in
`Wombat.app/Contents/Resources/completions`.

### Set it up with one command

```bash
wombat completion install --dry-run   # shows what it would do, changes nothing
wombat completion install             # your login shell, plus other shells you have set up
wombat completion install zsh         # or just one shell
```

It finds your shells (your login shell, then zsh, bash and fish if they are installed and have a
startup file) and puts a link to the script inside Wombat.app where each one looks:

| Setup | Where the link goes | Startup file changed? |
|---|---|---|
| zsh with oh-my-zsh | `$ZSH_CUSTOM/completions/_wombat` (usually `~/.oh-my-zsh/custom/completions`) | No: oh-my-zsh adds that folder to `$fpath` before it runs `compinit`, and `custom/` is outside its git checkout, so `omz update` leaves it alone |
| zsh, a usual folder already on `$fpath` (`~/.zsh/completions`, `~/.zfunc`, ...) | that folder | No |
| zsh, otherwise | `~/.zsh/completions/_wombat` | Yes: one `fpath` line at the top of `~/.zshrc` (plus `compinit`, at the end, if nothing turns completion on) |
| zsh with prezto, zinit, antidote, Zim and similar | nowhere: it explains what to add, then `--dir` | No |
| bash with bash-completion 2 loaded | `~/.local/share/bash-completion/completions/wombat` | No |
| bash without it (macOS's bash 3.2 too) | `~/.bash_completion.d/wombat` | Yes: one line in `~/.bashrc` if `~/.bash_profile` reads it, else in `~/.bash_profile` |
| fish | `~/.config/fish/completions/wombat.fish` | No |

- It shows any change to a startup file and asks first; `--yes` answers for you (needed when no
  one is at the terminal). The lines sit between `# >>> wombat completion >>>` markers, and the
  file is backed up first (`~/.zshrc.wombat-backup-<date>`). A startup file that is a symlink,
  into a dotfiles repository say, is edited in place, not replaced.
- When Homebrew already linked the script and the shell reads Homebrew's folder, it does nothing
  for that shell (`--force` adds a second copy anyway).
- It never replaces a file that isn't Wombat's unless you pass `--force`, which keeps it as a
  backup. A copy you saved by hand earlier is moved aside (as a backup) and replaced by a link.
- The link points into Wombat.app, so it stays current when Wombat updates itself. Run it from the
  `wombat` inside `/Applications/Wombat.app`, not from the disk image or a development build.
- `--dir DIR` puts the file in that folder for one shell and changes no startup file.
- `wombat completion status` lists what is in place; `wombat completion uninstall` removes the
  links and the marked lines it added, and nothing else.

Then open a new terminal (or run `exec zsh`). If your `~/.zshrc` runs `compinit -C`, which trusts
its cache, run `rm -f ~/.zcompdump*` once first; `install` tells you when.

### With Homebrew

The cask links the scripts into Homebrew's completion folders, so they only need the shell to
look there:

- **zsh:** Homebrew's own zsh already looks in `$(brew --prefix)/share/zsh/site-functions`. For
  macOS's `/bin/zsh`, add this to `~/.zshrc` before `compinit` runs (with oh-my-zsh: before
  `source $ZSH/oh-my-zsh.sh`, or turn on oh-my-zsh's `brew` plugin, which does the same):

  ```zsh
  FPATH="$(brew --prefix)/share/zsh/site-functions:${FPATH}"
  ```

- **bash:** install bash-completion (`brew install bash-completion@2`, which needs bash 4.2 or
  later: `brew install bash`) and load it from `~/.bash_profile`:

  ```bash
  [[ -r "$(brew --prefix)/etc/profile.d/bash_completion.sh" ]] && . "$(brew --prefix)/etc/profile.d/bash_completion.sh"
  ```

- **fish:** nothing to do.

Then open a new terminal. If zsh still doesn't complete, its cache is stale:
`rm -f ~/.zcompdump*; exec zsh`.

### By hand

`wombat completion <shell>` prints the script for zsh, bash or fish.

**zsh:** save it as `_wombat` in a folder on `$fpath`, before `compinit` runs:

```zsh
mkdir -p ~/.zsh/completions
wombat completion zsh > ~/.zsh/completions/_wombat
# in ~/.zshrc, before compinit:
fpath=(~/.zsh/completions $fpath)
```

**oh-my-zsh:** its custom folder is already on `$fpath`:

```zsh
mkdir -p "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/completions"
wombat completion zsh > "${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/completions/_wombat"
rm -f ~/.zcompdump*; exec zsh
```

Or, for any zsh, load it at startup (after `compinit`, so after oh-my-zsh):
`source <(wombat completion zsh)`.

**bash:** with bash-completion 2, save it where it looks for completions:

```bash
mkdir -p ~/.local/share/bash-completion/completions
wombat completion bash > ~/.local/share/bash-completion/completions/wombat
```

Without bash-completion, add `eval "$(wombat completion bash)"` to `~/.bashrc` (this also works in
macOS's bash 3.2, where files are completed by bash itself).

**fish:**

```fish
wombat completion fish > ~/.config/fish/completions/wombat.fish
```

Homebrew's links and `source <(wombat completion zsh)` read the script from the app, so they stay
current when Wombat updates itself. A copy saved by hand doesn't: save it again after an update.

## Coding agents

`wombat install-skill` writes `~/.claude/skills/wombat/SKILL.md`, which tells Claude Code (and
other agents that read skills) which commands exist, that they must never print private keys,
and that imports wait for your approval.

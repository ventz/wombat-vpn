# Security Policy

Security is Wombat's first design goal; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes
the threat model.

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability** button (Security tab), not in a
public issue. Include the macOS version, the Wombat version, and steps or a config that
reproduces it, **with real keys removed**.

Especially interesting: anything that leaks a private key, sends traffic or DNS outside a tunnel
that should carry it, lets the CLI or another process change tunnels without approval, or lets a
config, zip file or network packet crash or hang the app or extension (either engine:
wireguard-go, or amneziawg-go for AmneziaWG tunnels). Bugs that are amneziawg-go's own are worth
reporting upstream too; Wombat's changes to it are in
[Vendor/amneziawg-go/WOMBAT.md](Vendor/amneziawg-go/WOMBAT.md).

Known limits, not bugs:

- macOS itself can stop any VPN: System Settings, `scutil --nc stop` and the VPN menu don't go
  through Wombat, so its approval prompts can't cover them. With the kill switch on, traffic is
  blocked while a tunnel reconnects, not after someone stops it.
- macOS keeps VPN settings in a file every account on the Mac can read
  (`/Library/Preferences/com.apple.networkextension.plist`). Wombat stores no keys there and
  shows "Wombat" as every tunnel's server, but the tunnel names and the trusted Wi-Fi names of
  on-demand rules are in it.
- On a shared Mac, a WireGuard tunnel with on-demand can start at the login window before anyone
  signs in; it stops as soon as another account takes the screen, but not when someone signs in
  over SSH. A tunnel you started yourself keeps running if you switch users, as macOS VPNs do.
- On a Mac other people use, avoid combining on-demand with the kill switch: while another
  account has the screen, Wombat refuses to restart your tunnel, and with the kill switch on,
  macOS may hold their traffic while it keeps trying. Turn on-demand off before handing the Mac
  over, or stop the tunnel in System Settings › VPN.

For Cisco AnyConnect VPNs, also: a gateway or identity provider that can make Wombat accept the
wrong certificate, leak a session token, run anything, or reach WireGuard keys from the
OpenConnect extension. libopenconnect's own bugs belong upstream as well
(<https://www.infradead.org/openconnect/>); how Wombat builds it is in
[Vendor/openconnect/WOMBAT.md](Vendor/openconnect/WOMBAT.md).

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

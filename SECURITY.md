# Security Policy

Security is Wombat's first design goal; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) describes
the threat model.

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability** button (Security tab), not in a
public issue. Include the macOS version, the Wombat version, and steps or a config that
reproduces it, **with real keys removed**.

Especially interesting: anything that leaks a private key, sends traffic or DNS outside a tunnel
that should carry it, lets the CLI or another process change tunnels without approval, or lets a
config or zip file crash or hang the app or extension.

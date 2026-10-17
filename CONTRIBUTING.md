# Contributing

Thanks for helping. Build and test first ([docs/DEVELOPING.md](docs/DEVELOPING.md)):

```bash
(cd Packages/TunnelCore && swift test)
```

- **Logic goes in `Packages/TunnelCore`** with tests (Swift Testing). The app, extension and CLI
  should stay thin.
- **Security rules** ([docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) are not negotiable: no secrets
  in NE preferences or logs, never execute config hooks, no new CLI action that weakens protection
  without in-app approval, no XPC call that returns secrets.
- **Never commit real configs or keys.** `*.conf` and `*.anyconnect` are gitignored; tests use the wg(8) example keys.
- Changes to `Vendor/WireGuardKit` are marked "Wombat" in a comment; keep them minimal.
- American English in code, UI and docs.

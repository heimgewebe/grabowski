# Changelog

## Unreleased

- Initialer Repository-Bootstrap aus der laufenden Grabowski-MCP-Runtime.
- Zugriffspolicy-Contract und Beispielkonfiguration ergänzt.
- Minimaler CI- und Repository-Contract eingerichtet.

- Added reproducible repository-to-runtime deployment with isolated staging, MCP handshake, tool-list verification, health/readiness gates, source-hash verification, and automatic rollback.
- Hardened deployment with a hashed dependency lock, exclusive deployment
  lock, runtime-process identity proof, provenance reporting, and behavioral
  rollback failure tests.
- Switched DEPLOY-001 to immutable release directories activated through the
  stable runtime symlink, with a versioned `python -m` entry-point contract and
  fail-closed preflight for the current operator-profile mismatch.
- Added the bounded local operator with command execution, systemd jobs, Git/GitHub, user-service, tmux, process, and port tools.
- Added Operator v2 foundation contracts: explicit access profiles and
  capabilities, v2 typed secret/browser roots, dedicated
  `secret_inspect`/`secret_reveal`/`secret_use`/`secret_export`/
  `browser_profile_read` tools, home-wide operator example, kill switch,
  argv/output redaction, quarantined text rollback, tamper-evident audit
  verification, and unprivileged privileged-action references.
- Added typed reversible filesystem removal/restoration and a separate
  deliberate irreversible removal capability, both behind explicit capability,
  audit, protected-root and kill-switch gates.

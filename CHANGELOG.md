# Changelog

## Unreleased

- Fixed rLens stem-to-repo mapping so `-full-max-` bundles resolve to their
  base repository instead of a `<repo>-full` phantom, keeping discovery
  filters and context-pack repo gates usable for full-max bundles.
- Fixed the operator patch relay so `--three-way` also applies to the
  `git apply --check` gate; previously 3-way patches were rejected before the
  apply step could run.
- Fixed a double-close of the friction-ledger file descriptor and made
  `grabowski_friction_summary` tolerate corrupt log lines, reporting them as
  `invalid_lines` instead of failing the whole summary.
- Surfaced the failing deployment phase in the dual-service
  `PRIMARY-DEPLOY-ERROR` output.
- Made the Makefile `syntax` target compile every file under `src/` and
  `tools/` via wildcards; previously six files were silently skipped.
- Declared all runtime modules in `pyproject.toml` `py-modules` so a package
  install matches the repository module set.
- Added a read-only rLens bundle surface: discovery, per-bundle status,
  freshness check against the live repository HEAD, and a bounded context
  pack with Lenskit preflight for agent handoff.
- Added a bounded operator-friction ledger with typed record/summary tools,
  a versioned event schema and hash-free audit trail entries.
- Added the blocked-action protocol (Operator Relay v0) with routed helper
  roles, a bounded local patch relay with JSON receipts, and status surfacing
  of the operating protocol.
- Added a read-only safety observer with journal classification, severity
  rules, bounded reports and health output.
- Added operator-completion foundations: atomic resource leases, persistent
  lease-bound tasks with explicit reconcile check/refresh/resume semantics,
  hash-bound artifact transport, and isolated browser/GUI workers.
- Added component watchdogs with restart budgets for tunnel and operator
  services, plus dual-service deployment with rollback phases.
- Fixed checkout coordination so a process or task in a parent directory no
  longer blocks every descendant worktree; only working directories equal to
  or below an actual coordination root count as blockers.
- Hardened the typed read surface with streaming output bounds, single-object
  Git revision resolution, schema-visible argument limits, compact Core profile
  categories, live tool-contract fingerprints, and delayed self-deployment.
- Added a typed read surface with narrow context, Git, GitHub and user-service
  diagnostics; generic operator tools remain available, while publication
  profiles are defined as projections of the single canonical contract.
- Added a typed home fleet registry and argv-only local/SSH execution path for
  `heim-pc`, `heimserver` and `heimberry`, plus contracted operation recipes
  with preflight, action, postflight and reverse-order rollback.
- Added a fail-closed systemd-socket privileged broker with hash/TTL/replay
  validation, fixed root-owned action templates, and all examples disabled.
- Made `secret_reveal` a break-glass path requiring justification and explicit
  context-exposure acknowledgement; `secret_use` remains the default.
- Added a deterministic connector contract probe that compares live MCP tool
  names and security-critical input-schema fingerprints with the client snapshot.

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

# Changelog

## Unreleased

- Added a read-only `runtime-deploy-check` grip and a Captain-gated `runtime-deploy` executor for the registered `grabowski-self` adapter. Self-deployment is scheduled through the existing independent delayed job and reports `scheduled`, never completed, until job and runtime identity are observed separately. Identical in-flight schedules are now serialized and reused, conflicting or ambiguous jobs fail closed, and receipts distinguish local job registration from later runtime mutation.
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

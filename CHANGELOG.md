# Changelog

## Unreleased

- Juno Operator beendet interaktive Warnläufe ohne rote `SystemExit`-Ausnahme; echte Laufzeitfehler bleiben weiterhin sichtbar.

- Added Juno Operator, a standard-library-only read-only iPad dashboard with bounded storage/network collectors, local cache, self-contained HTML, notebook entry point, and hash-bound incident packages.
- Added read-only gate-evidence preparation and semantic convergence-state classification grips so repeated fail-closed friction can collect named evidence without policy bypasses, while historical defects, expected red phases, blocks, supersessions, resolutions and contradictions remain explicitly distinguishable.
- Moved the canonical typed operator blockade into a root-owned authority domain with a peer-cgroup-bound internal broker lifecycle, two-phase fail-closed legacy migration, root audit intent-before-mutation, recovery-gated engage rollback, disarm restore, unknown-outcome readback and dual canonical/legacy fail-closed observation.
- Fixed the commit-bound Rootbroker recovery-source validator to bind the explicit legacy home marker rather than the canonical root-owned marker, while retaining compatibility with pre-authority commit fixtures.
- Added an explicit task lifetime contract for local privileged power-worker tasks: persistent task records now store execution backend, systemd scope, and authoritative unit; root-scoped task start/status/log/cancel/resume route through the existing root broker without falling back to `systemctl --user` on unknown root truth. Schema migration is writer-serialized and skipped on established schema 3, active and unknown task leases are renewed with a bounded seven-day maximum, direct resume rejects unknown, freshly completed, and already terminal tasks, pre-dispatch broker failures terminate cleanly and release leases, read operations use client-safe broker timeout caps, malformed broker output remains unknown, and root-task journal output is rate-limited.
- Hardened Juno iPad storage after adversarial review: failed creates and replace temporaries are identity-classified and preserved with an explicit cleanup reference instead of a TOCTOU-prone name-based unlink, delayed descriptor-close failures are captured, descriptor lifetimes otherwise use context managers, root opens require `O_NOFOLLOW` and `O_DIRECTORY` with richer identity readback, ENOTDIR has stable validation semantics, unsupported descriptor-bound replace fails closed, directory listings reuse `scandir` metadata, and the 176 KiB transport margin is explicitly regression-tested.
- Added locally consented, security-scoped Juno iPad storage grants with an open-in-place folder picker, descriptor-pinned path traversal, transport-aligned 176 KiB read/write bounds, a bounded capability manifest, grant inventory, permission probes, exact-path stat/list/read, create-only writes, hash-bound same-directory replacement with immediate preimage recheck and post-readback, private grant records, and no delete, move, recursive traversal, sandbox bypass, or bookmark disclosure.
- Added the read-only `convergence-assess` grip as the first operational consumer of `heimgewebe/konvergenzregelkreis` v1.0.0. It binds the request SHA-256, exact protocol Git head, clean protocol checkout, evaluator identity, status/exit-code consistency and a post-evaluation identity readback; only `terminally_closed` permits completion, while missing, stale, blocked or conflicting evidence fails closed without mutation.
- Stabilized checkout-cleanup dry-run authorization across clock progress by binding the immutable archive creation time while excluding only the explicitly declared observational `archive_age_seconds` field from the schema-2 plan hash; real checkout, recovery, retention, and coordination drift remains fail-closed.
- Hardened operator-obligation attention projection with fail-closed status invariants, explicit mixed open/blocked/delegated coverage, and a documented deprecated `follow_up_required` compatibility alias while preserving explicit `state="open"` behavior.
- Added a durable operator-obligation lifecycle with bounded discovery, create-only hash-bound open and terminal records, and close-time live observation for delegated Grabowski tasks, agent workspaces, and systemd jobs. Nontrivial work remains explicitly open with `response_may_end=false` until every acceptance criterion is evidenced as passed, a concrete blocker is recorded, or live durable work is receipt-bound.
- Published deployment manifests atomically as owner-only regular files so workspace runtime cohorts retain exact release and repository identities under any process umask.
- Added Workspace Routing v2.1 with lean R0-R3 thresholds, separate concurrent-activity and parallelization-assessment inputs, R3-only contrast, explicit decision-fork competition gating, schema-1 route-evidence compatibility, and cohort-bound cost/intervention metrics without enabling parallel writers.
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

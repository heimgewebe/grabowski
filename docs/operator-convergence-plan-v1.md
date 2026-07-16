# Operator convergence plan v1

## Goal

Reduce coordination cost without weakening fail-closed safety. The operator already has sufficient execution capabilities; the immediate priority is to make active work, blocked work, and required evidence easier to distinguish from retained history.

## Truth boundaries

- Raw task, friction, audit, Chronik, Bureau, GitHub, and deployment records remain authoritative in their existing systems.
- Projections do not delete, rewrite, resume, merge, or deploy anything.
- A recommendation does not establish root cause, policy exception, execution authority, or safe mutation retry.
- Merge, deployment, recovery, secrets, and privileged execution remain immutable governor boundaries.

## Ordered implementation

### P0 — Merge and lease convergence

Bind merge dispatch to a fresh atomic snapshot of repository identity, pull-request head/base/diff, CI, review evidence, and resource leases. This work remains owned by the separate T057 stream and must not be duplicated here.

### P1 — Active-state projection

Expose named task projections through the existing `grabowski_task_list` surface:

- `active`: launching, running, or interrupted tasks;
- `attention`: interrupted, outcome-unknown, failed, timed-out, or signalled tasks;
- `terminal`: completed, failed, cancelled, timed-out, signalled, or outcome-unknown tasks.

Every response also returns exact state counts and projection counts from one SQLite read snapshot. Projections intentionally overlap and must not be summed. Unknown legacy states are counted explicitly and make the exact-state projection incomplete instead of disappearing silently. Historical rows remain in the task database.

### P1 — Gate evidence preparation

Repeated friction recommendations include a bounded repair contract:

- preferred route;
- required evidence;
- preparation steps;
- unchanged-retry policy;
- post-state readback;
- explicit non-claims.

The repair contract prepares evidence. It never bypasses a gate or starts work automatically.

### P1 — Execution learning

Record predicted-versus-actual outcomes automatically from terminal receipt-bound grips, tasks, jobs, and deployments. Promotion remains shadow-only until the ledger contains sufficient recent, reproducible evidence. High-risk and immutable boundaries remain excluded.

### P1 — Exact deployment source identity

Schedule self-deployment from an explicitly selected clean immutable source identity rather than ambient canonical-checkout state. Require exact head, clean status, provenance, lease evidence, preflight receipt, idempotent scheduling, and post-deployment readback.

### P2 — Connector snapshot handshake

Bind a bounded client declaration for tool count, sorted tool-name hash, agent-instruction hash, and release identity to server-owned values through the existing `grip_run` surface. Persist a private, expiring, self-hashed receipt. Report the verification model as `client-declared-server-compared-v1`; do not claim platform attestation or client instruction compliance.

### P2 — Source-bound operator overview

Expose `system_overview` in the existing standard and evidence status views. Project runtime integrity, connector snapshot state, task projections, bounded active leases, and operator-obligation attention from their authoritative stores. Component errors or truncation block `operator_ready`; the overview never becomes another status database or grants mutation authority.

## Acceptance criteria

1. Operators can list active or attention tasks without scanning terminal history.
2. Repeated gate friction states exactly which evidence must change before retry.
3. No projection mutates source records or grants execution authority.
4. Focused and full repository validation pass on the exact branch head.
5. Every nontrivial merge remains head/base/diff/CI/review/lease bound.
6. Connector freshness is represented by an expiring receipt bound to the current release and exact tool-name hash, with explicit non-claims.
7. The consolidated overview remains a read-only projection and fails closed when required component state is unavailable or truncated.

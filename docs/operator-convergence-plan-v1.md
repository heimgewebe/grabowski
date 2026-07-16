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

Every response also returns exact state counts and projection counts. Historical rows remain in the task database.

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

Add an honest client/server handshake for tool count, tool-name hash, agent-instruction hash, release identity, and refresh requirement. When client state is not observable, report that limitation rather than inferring freshness.

### P2 — Source-bound operator overview

Provide one compact read-only overview containing pointers and freshness metadata for Bureau, Grabowski runtime, GitHub/CI, RepoBrief, Systemkatalog, and Chronik. It must not become another status database.

## Acceptance criteria

1. Operators can list active or attention tasks without scanning terminal history.
2. Repeated gate friction states exactly which evidence must change before retry.
3. No projection mutates source records or grants execution authority.
4. Focused and full repository validation pass on the exact branch head.
5. Every nontrivial merge remains head/base/diff/CI/review/lease bound.

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

### P1a — Active-state projection

Expose named task projections through the existing `grabowski_task_list` surface:

- `active`: launching or running tasks whose execution may still be live;
- `attention`: interrupted, outcome-unknown, failed, timed-out, or signalled tasks;
- `terminal`: completed, failed, cancelled, timed-out, or signalled tasks.

`interrupted` and `outcome_unknown` are retained recovery states, not current execution truth. They remain visible through `attention` and keep fail-closed recovery semantics, but they do not inflate the active-work count.

The operational `attention` projection is decision-aware: a valid create-only, outcome-bound `closed` or `superseded` decision removes only that exact task attempt from current attention, while `deferred`, missing, stale, or invalid evidence remains visible. The underlying task state is never rewritten. `raw_projection_counts` retains the pre-decision state-derived counts so historical failure volume remains observable, while `projection_counts["attention"]` reports the current actionable projection. Task-list reads hold a shared decision-store snapshot lock from projection through cursor validation and row materialization; create-only decision writers use the same lock exclusively, so one response cannot mix two decision generations. If that lock cannot be acquired safely, decision filtering degrades to raw visibility instead of hiding work.

Every response also returns exact state counts and projection counts from one SQLite read snapshot. Projections intentionally overlap and must not be summed. Unknown legacy states are counted explicitly and make the exact-state projection incomplete instead of disappearing silently. Historical rows remain in the task database.

### P1b — Workspace liveness projection

Derive operational workspace liveness from tasks that may still execute (`launching` or `running`), live resource leases, unresolved task-start intents, and observation errors. Retained recovery states such as `interrupted` or `outcome_unknown` remain explicit reconciliation blockers without claiming that execution is still live. tmux remains a non-authoritative process UI: a surviving idle session is reported separately and does not make historical work active again. Because stale reconciliation is intentionally non-destructive, that idle session still blocks reconciliation with `workspace_idle_tmux_cleanup_required` until an explicit mutating closeout removes it. Worktree cleanup remains separately protected by checkout coordination and dirty-state checks.

### P1c — Gate evidence preparation

Repeated friction recommendations include a bounded repair contract:

- preferred route;
- required evidence;
- preparation steps;
- unchanged-retry policy;
- post-state readback;
- explicit non-claims.

The repair contract prepares evidence. It never bypasses a gate or starts work automatically.

### P1d — Execution learning

Record predicted-versus-actual outcomes automatically from terminal receipt-bound grips, tasks, jobs, and deployments. Promotion remains shadow-only until the ledger contains sufficient recent, reproducible evidence. High-risk and immutable boundaries remain excluded.

### P1e — Exact deployment source identity

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
8. An idle tmux session alone never establishes operational workspace liveness; it remains an explicit cleanup blocker until a mutating closeout removes it. Task, lease, start-intent, and checkout safety remain authoritative.

# Grabowski Operator Optimization Plan

Status: registered plan, no runtime mutation.
Date: 2026-07-01.
Owner: ChatGPT operator via Grabowski.

## These / Antithese / Synthese

These: Grabowski is operationally useful because it gives ChatGPT a local, auditable control surface for repo, terminal, service, fleet and agent work.

Antithese: The same control surface is dangerous when operational convenience is confused with durable autonomy. The live `trusted-owner` profile intentionally has broad host reach; that is acceptable for supervised operator work, but not as the default for self-directed long-running autonomy.

Synthese: Optimize Grabowski by preserving full supervised capability while routing lower-risk work through safer defaults and explicit elevation. The next phase is not less function; it is clearer mode selection, cleaner receipts, classified failures and reversible elevation paths.

## Audit basis

This plan follows the 2026-07-01 operator audit. The audit found strong positive evidence:

- live runtime is healthy and deployment-complete,
- canonical checkout matches the deployed runtime head,
- tool contract has no runtime drift,
- write audit hash chain verifies,
- repository validation is green,
- Operator Relay v0 is live in runtime status.

The same audit found optimization pressure:

- live profile is `trusted-owner`, with root-wide read and write roots,
- fleet hosts currently allow wildcard commands,
- the wider repo ecosystem has branch/worktree drift,
- failed task records need semantic classification,
- external agents need stricter receipts,
- redaction can over-redact benign operator identifiers,
- connector snapshot observability remains incomplete from the local runtime,
- resident/creative long-running workloads should be separated from repo/infra autonomy.

## Does not establish

This plan does not establish:

- a live policy change,
- automatic merge, push or deployment,
- unsupervised durable agent autonomy,
- permission to clean worktrees,
- permission to reveal or export secrets,
- permission to run fleet mutations,
- a claim that the connector snapshot is fully observable.

Every implementation slice must remain independently reviewable.

## Alternative Sinnachse

The tempting axis is "make Grabowski more autonomous". The better axis is "make every autonomous-looking step smaller, typed, receipt-bound and reversible".

Grabowski should behave less like a general servant and more like a notary with a scalpel: boring records, sharp cuts, no improvisational juggling near secrets.

## Optimization classes

### Class A: Signal quality

Purpose: make recorded operational state more useful before expanding scope.

Includes:

- failed task classification,
- friction event review,
- recurring failure grouping,
- superseded-by-green-run detection,
- operator-facing summaries that separate expected red-phase work from actionable failures.

Primary risk: false confidence from over-classification.

### Class B: Workspace hygiene

Purpose: reduce checkout and branch confusion.

Includes:

- read-only checkout inventory,
- retention ownership,
- archive-first cleanup,
- dry-run before deletion,
- no cleanup without recovery refs or explicit dirty-state decision.

Primary risk: losing useful unfinished work.

### Class C: Capability routing without functionality loss

Purpose: keep full supervised functionality available while preventing low-risk, resident or self-directed work from silently inheriting `trusted-owner` authority. `observe` is a candidate default for read-only automation, not a blanket replacement for the operator's full working mode.

Includes:

- define which workflows require `trusted-owner` to remain functional,
- define which workflows can run under `observe` or another lower-risk profile without loss,
- require explicit elevation and rollback notes for mutating, fleet, secret or service-control work,
- split coarse capabilities where one broad capability currently unlocks both read and write behavior,
- regression tests that generic tools cannot cross typed secret/browser roots,
- a parity gate: no live default change unless routine operator workflows still work or have an explicit, fast elevation path.

Primary risk: over-tightening that damages useful functionality; the counter-risk is leaving broad authority attached to autonomous or low-risk work.

### Class D: Fleet containment

Purpose: make remote host effects host-role-specific.

Includes:

- replace wildcard command assumptions with named operation allowlists where possible,
- keep diagnostic reads broad enough to be useful,
- route high-risk server and DNS actions through `operation_plan` / `operation_run`,
- require explicit receipts after each remote mutation.

Primary risk: emergency diagnosis becomes slower.

### Class E: Agent delegation control

Purpose: keep Codex, Claude, agy, Ollama and Aider helpful without making them sovereign.

Includes:

- standard micro-handoff fields,
- standard receipt fields,
- stop-after-diff/test/review defaults,
- no commit/push/merge/deploy unless explicitly requested,
- Claude as review/architecture checker, Codex as primary complex code-slice helper.

Primary risk: more process overhead for small tasks.

### Class F: Secret, browser and redaction hygiene

Purpose: keep sensitive boundaries strong while preserving useful operator evidence.

Includes:

- redaction false-positive tests for benign identifiers such as `grabowski-task-*`,
- continued exact redaction of real secret variants,
- no raw browser-profile data in generic file reads,
- `secret_use` as default and `secret_reveal` as rare break-glass.

Primary risk: loosening redaction too far while fixing false positives.

### Class G: Runtime lifecycle and observability

Purpose: make service, watchdog and connector states legible.

Includes:

- clarify which watchdogs are intentionally inactive, timer-driven or deprecated,
- document tunnel/operator health expectations,
- define connector snapshot refresh criteria,
- keep deployment identity and runtime lock validation as hard preflight inputs.

Primary risk: treating observability as permission.

### Class H: Autonomy separation

Purpose: separate repo/infra autonomy from creative or experimental resident processes.

Includes:

- autonomy classes such as `repo_operator`, `infra_operator`, `creative_autonomy`, `secret_sensitive` and `fleet_sensitive`,
- resource limits and lease ownership for every long-running process,
- explicit review cadence for resident tasks,
- no resident workload may self-promote into repo, fleet or secret mutation.

Primary risk: experimental systems become invisible because they are "only creative".

## Implementation sequence

### GOPT-001: Failure and friction signal ledger

Status: next recommended slice.

Deliverables:

- add a read-only failed-task classification helper or documented CLI recipe,
- classify recent task failures into contract error, expected red-phase, superseded, environment/tooling, platform filter, policy gate or actionable failure,
- extend `docs/operator-friction.md` with the classification loop,
- produce a bounded summary that never includes secrets or full logs.

Exit criteria:

- a current failed-task summary can identify which failures still require action,
- recurring failure classes have a documented next decision,
- no task is resumed by classification alone.

### GOPT-002: Checkout hygiene dry-run

Deliverables:

- run deterministic checkout inventory,
- mark retained, archived, dirty, obsolete and unknown checkouts,
- prefer archive and recovery refs before cleanup,
- document how Steuerboard branch-drift signal influences, but never authorizes, cleanup.

Exit criteria:

- operator can answer which Grabowski worktrees are live, retained, archived or cleanup candidates,
- every cleanup apply has a prior dry-run plan hash.

### GOPT-003: Function-preserving capability routing

Deliverables:

- audit which workflows genuinely require `trusted-owner` and which do not,
- propose a routing model where read-only/resident/self-directed work starts in the least-authority profile that preserves function,
- keep `trusted-owner` available for supervised full-power operation and make elevation explicit rather than hidden,
- define explicit elevation to `maintain`, `mutate`, `trusted-owner` and `break-glass`,
- split coarse capabilities where read and write behavior are currently tied,
- keep rollback instructions before any deployment.

Exit criteria:

- routine read-only audit tasks work without `trusted-owner`,
- routine supervised operator work is not blocked; if a lower profile blocks it, there is an explicit fast elevation path,
- mutating repo, fleet, secret and service-control work requires a visible profile/elevation decision,
- the previous trusted-owner policy can be restored with evidence.

### GOPT-004: Fleet allowlist hardening

Deliverables:

- classify fleet operations by host role: workstation, server, DNS/infrastructure,
- replace wildcard assumptions with named operation recipes where feasible,
- require tighter preflight/postflight for heimserver and heimberry mutations,
- keep broad remote shell only as explicit supervised break-glass.

Exit criteria:

- routine diagnostics still work,
- high-risk fleet mutations have operation plans and rollback notes,
- wildcard command execution is no longer the quiet default for remote infrastructure.

### GOPT-005: Agent receipt standard

Deliverables:

- define a machine-readable receipt shape for Codex/Claude/Aider runs,
- include changed files, commands run, commands not run, assumptions, risk notes and next required operator decision,
- update prompts/runbooks so helpers stop after diff, tests or review.

Exit criteria:

- every delegated code/review task returns enough evidence for ChatGPT to decide the next step,
- no helper output is treated as success without a Grabowski or Git receipt.

### GOPT-006: Redaction and sensitive-boundary tuning

Deliverables:

- add regression cases for benign task/unit/branch identifiers,
- preserve redaction for actual secret-shaped values,
- document residual false-positive behavior if full precision is unsafe.

Exit criteria:

- operator receipts remain readable enough to match task IDs,
- real secret variants remain redacted in argv, command, stdout and stderr surfaces.

### GOPT-007: Runtime lifecycle map

Deliverables:

- document operator, tunnel, watchdog, safety observer and reconcile service states,
- mark each inactive unit as intentional, timer-driven, deprecated or needs-action,
- define how runtime health, deployment identity and audit verification combine into an operator go/no-go view.

Exit criteria:

- the operator can distinguish a healthy inactive observer from a broken inactive observer,
- deployment preflight does not silently depend on stale runtime assumptions.

### GOPT-008: Autonomy class registry

Deliverables:

- document allowed autonomy classes and forbidden crossovers,
- classify the resident music composer separately from repo/infra work,
- require leases, resource limits and review cadence for every resident workload.

Exit criteria:

- no long-running task is unclassified,
- creative resident work cannot mutate repos, fleet hosts or secrets through implicit promotion.

### GOPT-009: Connector snapshot observability

Deliverables:

- define what can and cannot be proven from local runtime state,
- add a repeatable connector-refresh probe or operator checklist,
- fail closed when client-visible tool count/hash cannot be reconciled with the runtime contract for a high-risk operation.

Exit criteria:

- connector drift is observable or explicitly marked epistemically empty before high-risk work,
- runtime contract truth is not confused with client snapshot truth.

## Recommended order

1. GOPT-001 Failure and friction signal ledger.
2. GOPT-002 Checkout hygiene dry-run.
3. GOPT-005 Agent receipt standard.
4. GOPT-006 Redaction tuning.
5. GOPT-003 Function-preserving capability routing.
6. GOPT-004 Fleet allowlist hardening.
7. GOPT-007 Runtime lifecycle map.
8. GOPT-008 Autonomy class registry.
9. GOPT-009 Connector snapshot observability.

The order is intentional: improve signal before changing permissions. The moat is dug before the dragon is invited to test the drawbridge.

## Validation rules for future slices

Every slice should state:

- scope,
- does-not-establish list,
- expected files,
- tests or read-only receipts,
- rollback or stop condition,
- whether Operator-Lab Run Card is required,
- Steuerboard signal: operation, target_repo, useful_signal, changed_decision and noise.

## Success definition

Grabowski is optimized when:

- routine audits no longer require `trusted-owner`, while supervised full-function work retains an explicit elevation path,
- remote fleet effects are host-role-specific,
- failed tasks are classified instead of merely accumulated,
- worktree state is legible,
- delegated agents produce sufficient receipts,
- sensitive boundaries stay strong without destroying benign operator evidence,
- long-running autonomy is classed, limited and reviewed,
- high-risk actions still require explicit operator choice.

## Explicit non-success

Grabowski is not optimized merely because:

- more tasks run automatically,
- more tools exist,
- an agent can commit faster,
- CI is green while the live authority surface stays too broad,
- old failures are ignored instead of classified.

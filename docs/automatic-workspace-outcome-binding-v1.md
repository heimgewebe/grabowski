# Automatic workspace outcome binding v1

Agent Workspace closeout now binds complete, verified workspace evidence into the execution-governor shadow ledger automatically.

## Contract

A new schema-v3 workspace close may record one governor outcome only when all of the following are true:

- the close receipt is complete, hash-valid, present on disk and identical to the manifest reference;
- all workspace resources are verified released;
- the close-phase workspace outcome is hash-valid and belongs to the same workspace;
- route evidence is verified and deterministically replayable;
- retry command-identity measurement is frozen inside the hash-bound workspace outcome;
- elapsed time and known mutating call count fit the governor's bounded schema.

Legacy workspaces without route evidence remain closeable, but their outcome binding is explicitly `not_applicable_legacy_route`. Older outcome schemas remain closeable as `not_applicable_legacy_outcome_schema`. No historical recommendation, risk level, route or retry identity is invented.

## Deterministic idempotency

The bridge derives a SHA-256 binding identifier from the exact workspace outcome hash and mapped governor fields. The governor derives a stable outcome identifier from that binding. Repeating the same closeout returns the existing record; reusing the same binding with different evidence fails closed.

This closes the crash window between ledger append and workspace-manifest publication without permitting duplicate outcome rows.

## Measurement rules

- `operation_class` is `long_running` because an agent workspace is a durable multi-role execution.
- `risk_level` is mapped from the deterministic route-policy tier: R0→low, R1→medium, R2→high, R3→critical.
- recommended and actual routes preserve the exact workspace route names.
- first-pass success requires the writer to complete and the first tests/review attempts to pass, including a `PASS` review verdict.
- unchanged retries count only retry records whose old and new command SHA-256 values are identical. Changed-command retries are reported in the bridge receipt but excluded from that metric.
- ambiguous mutation outcomes are zero only after a valid complete close receipt, frozen Git readback and verified resource release.
- tool-call count includes only integrity-bound known mutating workspace calls. Read-only observations remain explicitly uncounted.
- elapsed time uses exact whole seconds from workspace creation to close and is not clamped.

## Stored evidence

Each bound closeout writes an immutable bridge receipt:

`execution-outcome-binding.close.<workspace-outcome-sha256>.json`

The manifest references its path, binding identifier, execution-outcome identifier and receipt hash.

## Non-claims

Automatic binding does not:

- enable live adaptive routing;
- prove general productivity improvement;
- count read-only status or observation calls;
- establish merge, deployment or external integration success;
- retrofit legacy workspaces with missing route evidence.

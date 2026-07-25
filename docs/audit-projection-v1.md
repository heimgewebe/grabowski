# Audit projection v1

`grabowski_audit_projection` is a read-only derived view over the verified tamper-evident write audit chain. It does not replace the JSONL chain and stores no second authoritative state.

## Contract

- Refuse when the audit chain is invalid.
- Read and verify the complete chain as one records-plus-status snapshot under the shared audit coordination lock, then perform one separate post-read verification to detect later growth.
- Bind every result to the snapshot record count, last record SHA-256 and a deterministic snapshot SHA-256.
- Emit a separate findings SHA-256 over complete semantic aggregate counts. It is independent of `view`, `top_limit`, `fields` and numeric window-boundary timestamps, but still changes when rolling-window membership or aggregate findings change; the projection SHA-256 remains a complete time-bound presentation receipt.
- Report a warning rather than silently rebinding when the chain advances during calculation.
- Emit fixed 24-hour, 7-day, 30-day and all-time windows. Parse every record timestamp once per projection and allow at most five minutes of forward clock skew.
- Aggregate operations, failure signals, Bureau codes, resource types, task/resource activity and mutation receipt evidence without exposing raw paths, argv, owner metadata or secrets; untrusted dimension labels outside the bounded identifier contract are redacted.
- Keep repeated-pattern output proposal-only. It cannot create Bureau tasks, change routing, weaken gates or authorize retries.
- Keep both findings and projection SHA-256 fields in every field-projected response so provenance and deduplication remain independently verifiable.
- Keep the projection stateless: no persistent derived cache or second source of truth is introduced.

## Interpretation boundaries

The projection is useful for recurrence and prioritization, not causality. Audit task-start events are not a task-success denominator. Lease events do not replace the live resource database. Friction records do not include later closeout truth; current resolution must come from `grabowski_friction_summary`. Routing effectiveness must come from `grabowski_execution_governor_summary`.

## Nightly integration

The planned `OPERATOR-INTEGRATION-LOOP-V1-T006` digest should consume this projection together with runtime health, task state, live leases, friction summary and execution-governor summary. Unchanged findings should be deduplicated by `findings_sha256`. `source_binding.snapshot_sha256` remains the provenance identity for the exact source snapshot and must not prevent deduplication when only the chain head advances. No derived pattern may create or mutate a task automatically.


## Canonical audit signals

The projection embeds one `audit-signal.v1` subprojection instead of adding another MCP tool or persistent index. It always returns the same five ordered signals over a seven-day observation window:

1. `uncertain_outcome` — direct `outcome_unknown`, `launcher_outcome_unknown`, or `recovery_required` evidence from the verified audit chain.
2. `contract_contradiction` — unresolved structured contract errors plus narrowly labelled projection/receipt mismatch friction. Heuristic matches remain explicitly marked and never decide which producer or consumer is wrong.
3. `transition_gap` — an explicit audit intent whose matching completion operation is absent after a five-minute grace period. Pairing is FIFO inside the same operation family and therefore does not claim exact cross-operation identity when no transaction identifier was logged.
4. `repeated_blockade` — at least three unresolved policy-gate friction events for the same bounded operation in the window. Repetition is evidence for improving gate preparation, not for bypassing policy.
5. `stale_attention` — an unresolved connector-snapshot friction event that predates a later fresh, matched runtime client-snapshot receipt. It is only a closeout candidate and is never resolved automatically.

Each signal is `clear`, `observed`, or `indeterminate`; carries bounded evidence references, evidence quality, explicit non-claims, and a recommended next action; and is bound to the audit snapshot, friction snapshot, and runtime client-snapshot receipt that were actually observed. Missing or invalid auxiliary evidence produces `indeterminate` rather than a false clear state.

`contracts/audit-signal.v1.schema.json` fixes the order and shape. The nested signal findings hash excludes clock-bound presentation fields but changes with semantic signal findings. The parent audit findings hash incorporates the signal findings, so nightly deduplication cannot silently ignore a changed signal state.

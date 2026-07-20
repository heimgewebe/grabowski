# Audit projection v1

`grabowski_audit_projection` is a read-only derived view over the verified tamper-evident write audit chain. It does not replace the JSONL chain and stores no second authoritative state.

## Contract

- Refuse when the audit chain is invalid.
- Read the complete chain through the existing verified chain reader.
- Bind every result to the snapshot record count, last record SHA-256 and a deterministic snapshot SHA-256.
- Emit a separate findings SHA-256 that excludes moving window boundaries, while the projection SHA-256 remains a complete time-bound receipt.
- Report a warning rather than silently rebinding when the chain advances during calculation.
- Emit fixed 24-hour, 7-day, 30-day and all-time windows.
- Aggregate operations, failure signals, Bureau codes, resource types, task/resource activity and mutation receipt evidence without exposing raw paths, argv, owner metadata or secrets; untrusted dimension labels outside the bounded identifier contract are redacted.
- Keep repeated-pattern output proposal-only. It cannot create Bureau tasks, change routing, weaken gates or authorize retries.

## Interpretation boundaries

The projection is useful for recurrence and prioritization, not causality. Audit task-start events are not a task-success denominator. Lease events do not replace the live resource database. Friction records do not include later closeout truth; current resolution must come from `grabowski_friction_summary`. Routing effectiveness must come from `grabowski_execution_governor_summary`.

## Nightly integration

The planned `OPERATOR-INTEGRATION-LOOP-V1-T006` digest should consume this projection together with runtime health, task state, live leases, friction summary and execution-governor summary. Unchanged findings should be deduplicated by `findings_sha256`. `source_binding.snapshot_sha256` remains the provenance identity for the exact source snapshot and must not prevent deduplication when only the chain head advances. No derived pattern may create or mutate a task automatically.

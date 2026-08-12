# Grabowski Identity and Time Contract v1

## Purpose

Grabowski already has the identities and clocks it needs for its current task, transport, effect and worker lifecycles. This contract names those existing roles and prevents accidental collapse of distinct namespaces. It is deliberately descriptive: it does not create a new store, lifecycle, authority or retry path.

The machine-readable companion is `contracts/identity-time-contract.v1.json`.

## Identity roles

### Semantic operation

`operation_identity_sha256` is the persisted identity of equivalent work at the task boundary. Its material is the canonical working directory, repository head, source fingerprint, normalized purpose and scope digest. Active or recent successful work may be reused under this identity. An attention-state predecessor can be superseded only with the exact predecessor task and lifecycle receipt plus an explicit force-new reason.

A semantic operation is not a task attempt. Resuming one persistent task advances `attempt`; that does not by itself define a different semantic operation.

### Operational projection identity

`grabowski_operational_truth.compute_operation_identity()` can derive a grouping identity from an explicit operation id or, when that is unavailable, from observed unit, argv and execution-envelope attributes with a task/work fallback. This is a read-only projection helper used to surface duplicate-looking current work. It is **not** the authority used by `grabowski_tasks` for task-start deduplication or retry admission.

The shared words “operation identity” therefore name two different authority levels: a persisted task semantic identity and a non-authoritative operational-truth projection identity. The projection may point to a possible duplicate; it may not manufacture semantic equivalence.

### Task and execution attempt

`task_id` identifies one durable Grabowski task. `(task_id, attempt)` identifies an execution generation of that task. Attempt is a logical generation, not a wall-clock value.

### Transport request

The transport request id exposed as `X-Grabowski-Request-Id` is HMAC-derived using the connector secret as the key plus session id, canonical JSON-RPC request id and body digest. The secret is not embedded in the request-id material or output. Repeating the same transport material produces the same id even when the signature timestamp changes. Changing the payload changes the id. Consumption is single-use and cannot be rebound to a different target.

This transport identity does **not** authorize a domain retry after an ambiguous effect.

### Effect admission request

`grabowski_effect_receipt` also contains a field named `request_id`. This is a different namespace. It correlates one effect admission with its completion. The normal effect interceptor creates a fresh admission request identity for a newly admitted mutation.

Therefore the unqualified statement “`request_id` is retry-stable” is wrong, as is the unqualified statement “`request_id` is never reused.” Both statements become correct only after the namespace is named.

### Effect and task receipts

`admission_sha256` identifies one effect-admission evidence record. `completion_sha256` identifies the completion evidence bound to that admission. `lifecycle_receipt_sha256` is task-lifecycle evidence and remains a separate domain receipt. None of these digests grants execution or retry authority by itself.

## Clock domains

### Event wall clock

Event-specific Unix timestamps such as `admitted_at_unix`, `completed_at_unix`, `created_at_unix` and `terminalized_at_unix` record event chronology. They are appropriate for audit ordering, freshness windows and cross-process correlation.

### Observation wall clock

`observed_at_unix` and `observed_at_unix_ns` mean when Grabowski sampled state. Observation time is not occurrence time. A later poll must not turn an earlier timeout, exit or effect into a different historical event.

### Source-native monotonic clock

Durations and local ordering should use a monotonic source when one exists. Worker planned-runtime classification uses systemd `ActiveEnterTimestampMonotonic` and `ActiveExitTimestampMonotonic`. Local in-process deadlines may use `time.monotonic()`.

Monotonic values must not be compared directly to Unix time or across incompatible boot/clock domains.

### Logical generations

Task `attempt` and the lease-generation work tracked by `GRABOWSKI-OPERATOR-SURFACE-V1-T049` are logical generations, not clocks. A “monotonic generation” in this sense must not be confused with `time.monotonic()`.

## Compatibility rule

Version 1 introduces no persisted-field rename. Existing wire and database names remain compatible. Any future rename of an overloaded name such as `request_id` requires a separate compatibility/versioning decision; aliases must not silently change meaning.

## Existing authority boundaries

This contract does not absorb or replace:

- `GRABOWSKI-OPERATOR-SURFACE-V1-T032`, which owns operation deduplication and safe result reuse;
- `GRABOWSKI-OPERATOR-SURFACE-V1-T049`, which owns exact lease-generation identity;
- `OPERATOR-MACHINE-READABILITY-V1-T020`, which owns the typed operation-lifecycle vertical slice;
- task state and persisted semantic-operation identity in `grabowski_tasks`;
- operational grouping projections in `grabowski_operational_truth`;
- lease ownership in `grabowski_resources`;
- effect evidence in `grabowski_effect_receipt`;
- transport replay state in `grabowski_transport_assertion`.

## Change rule

A later implementation may add a correlation field only when a concrete trace cannot be reconstructed deterministically from existing identities and receipts. The burden is on the new field: it must close a demonstrated trace gap without creating a second mutable truth.

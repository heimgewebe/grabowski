# Audit Query / Trace v1.1

## Purpose

The Grabowski audit chain remains the immutable, tamper-evident evidence layer. Audit Query / Trace v1.1 exposes only a disposable read-only projection derived from a verified audit snapshot. The projection has no independent authority and can be rebuilt from the audit chain.

## Authority and capability model

Audit integrity verification and audit content reading are separate authorities:

- `audit_verify` permits verification of the tamper-evident audit chain.
- `audit_read` permits bounded projection, query, trace and descriptive analysis of safe audit fields.

The three public audit-read tools require `audit_read`. Possessing `audit_verify` alone does not authorize structured audit-content access.
Legacy policy fallback does not implicitly grant `audit_read`; modern profiles must list it explicitly.

## Verified snapshot model

1. The active audit chain and predecessor bindings are verified under the shared audit coordination lock.
2. Immutable archived segments may reuse the existing identity-bound verification cache.
3. The active segment bytes are captured while the lock is held because the active file may change after lock release.
4. Archived segment contents are loaded lazily after lock release and must still match the verified snapshot SHA-256, record count and last-record hash.
5. Record parsing, projection, filtering, tracing and analysis happen outside the shared coordination lock.
6. No second persistent index or database is written.

A cold verification cache can still require a complete historical verification pass while the shared lock is held. Warm verified segments avoid repeated historical verification work. Lazy archived reads never trust cache metadata alone: bytes are read through the hardened descriptor contract and re-bound to the snapshot digest before parsing, without redundantly re-running the already verified record hash chain.

## Evidence identity

Each projected record retains:

- `audit_ref`,
- record evidence SHA-256,
- segment path and segment SHA-256,
- segment and record ordinal,
- global record ordinal,
- allowlist-based record projection,
- projection-schema mismatch evidence when an allowlisted field has an unsupported shape.

Two chain identities are exposed:

- `chain_content_sha256`: binds ordered segment ordinals and segment content hashes.
- `chain_materialization_sha256`: additionally binds segment paths.

The legacy `chain_fingerprint_sha256` field remains as a compatibility alias for the materialization fingerprint and declares that semantic explicitly.

For legacy records without a stored `record_sha256`, the verified raw line SHA-256 is used as the evidence reference. V2 stored record hashes are accepted only after the base audit verifier has checked hash shape, previous-hash linkage, sequence and recomputed record hash.

## Bounded work

Public query, trace and analyze operations scan at most `100000` records per invocation. Result limits are independent from scan limits.

Responses expose:

- scanned record count,
- scan limit,
- whether the scan is complete,
- scanned global-ordinal range,
- whether match/seed totals are globally known.

When the chain exceeds the scan budget, the response explicitly states that matches outside the scanned window are unknown. v1.1 intentionally does not provide a continuation cursor; this is a bounded-work safety choice, not evidence of absence outside the scan window.

Segment metadata is also bounded. At most eight segment descriptors are returned, together with exact segment count, first/last segment evidence, truncation state and omission count.

## `grabowski_audit_query`

Bounded safe-field search over the verified snapshot.

Supported filters:

- `operation`
- `operation_prefix`
- `task_id`
- `owner_id`
- `transaction_id`
- `host`
- `unit`
- `authoritative_unit`
- `path`
- `repo`
- `service`
- `branch`
- `resource_key`
- `held_resource_key`
- `requested_resource_key`
- `record_sha256`
- `since_unix`
- `until_unix`
- `has_failure_signal`

`resource_key` remains a compatibility alias matching either held or requested resources. New consumers should prefer the typed filters:

- `held_resource_key` matches `resource_keys` only.
- `requested_resource_key` matches `requested_resource_keys` only.

Inputs are validated once before scanning. Static filter values are not repeatedly revalidated for every record.

## `grabowski_audit_trace`

Produces a bounded one-hop correlation view from one exact anchor.

Supported anchors:

- `record_sha256`
- `task_id`
- `owner_id`
- `transaction_id`
- `resource_key`
- `held_resource_key`
- `requested_resource_key`
- `unit`
- `path`

Direct anchor matches are distinguished from correlated records. Held and requested resource relations remain separate during token derivation and correlation.

Broad anchors are bounded:

- at most 256 seed records contribute correlation tokens,
- at most 64 values are retained per correlation field,
- omitted seed and token counts are disclosed,
- `correlation_incomplete` is true whenever scan, seed or token truncation can make the graph incomplete.

Direct matches within the scanned window remain visible even when seed-token derivation is truncated.

Trace results do not establish causality.

## `grabowski_audit_analyze`

Computes bounded-memory descriptive statistics over the bounded verified scan:

- top operations,
- top held resource keys,
- top requested resource keys,
- top task IDs,
- top owner IDs,
- selected-record time range,
- failure-signal counts and bounded evidence samples,
- `launcher_outcome_unknown`,
- `recovery_required`.

High-cardinality top-value tracking uses a bounded Space-Saving counter. Each returned top value includes an `error_upper_bound`. The response declares whether each counter is exact or approximate and reports capacity, tracked values and evictions.

The analysis does not establish root cause, causality or future failure probability.

## Safe projection and schema drift

Public records expose only explicitly allowlisted scalar fields and the two explicitly typed string-list resource fields. Unknown fields are not projected.

If an allowlisted field changes to an unsupported shape, the field is not silently treated as absent. Record evidence reports:

- `projection_schema_mismatch: true`,
- `projection_omitted_fields` with the affected allowlisted field names.

The unsupported value itself is not exposed.

## Fail-closed behavior

No query, trace or analysis is produced from an unverified chain. Invalid JSON, invalid UTF-8, hash drift, predecessor mismatch, sequence mismatch, segment manifest mismatch or lazy archived-segment identity drift aborts the operation.

Verified-record decode failures after snapshot creation are treated as internal invariant violations and are never skipped.

## Non-goals

Audit Query / Trace v1.1 is not:

- a second audit database,
- a persistent search index,
- a policy engine,
- a root-cause engine,
- a permission proof for future actions,
- a substitute for Task, Lease, Receipt, GitHub, Chronik or Bureau authority,
- a complete cross-store evidence graph.

Cross-store evidence remains the scope of the separately planned follow-up. External sources must retain their own authority, immutable evidence references and freshness identity rather than being copied into the audit projection.

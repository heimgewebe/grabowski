# Resource lease contract v1

## Purpose

The resource SQLite database has two independent compatibility axes:

- `metadata.schema_version` versions Grabowski's aggregate store layout;
- `metadata.resource_lease_contract_version` versions the lease projection consumed by other runtimes.

Consumers must not infer lease compatibility from the aggregate schema number. Contract version `1` guarantees the `metadata` and `leases` projection required for exact owner, expiry and metadata-hash validation. Additional unrelated tables, indexes or aggregate schema versions do not change that contract.

## Contract metadata

A compatible store contains exactly one metadata row:

```text
key   = resource_lease_contract_version
value = 1
```

The value is a bounded decimal version. Missing, malformed or unsupported values fail closed for consumers before lease rows are read.

## Producer lifecycle

New stores publish aggregate schema `3` and lease contract `1` in the same transaction. Schema-1 and schema-2 migrations publish contract `1` while preserving all existing leases and lifecycle state.

An existing valid schema-3 store from an older runtime may lack the lease-contract row. The current runtime reports `lease_contract_metadata_required` through the schema-only resource inventory. On the next write-capable open it:

1. holds the exclusive resource-store directory lock;
2. validates SQLite integrity and the complete schema-3 structure;
3. creates and verifies a content-bound read-only backup;
4. inserts only `resource_lease_contract_version=1` inside `BEGIN IMMEDIATE`;
5. validates aggregate schema `3`, lease contract `1` and integrity before commit.

The aggregate schema version is not changed. Existing leases remain byte-for-byte represented by the same `leases` rows.

## Mutation semantics

A live lease is one identity, not merely one resource key and owner string. Its identity includes the normalized resource key, owner, purpose and semantic metadata.

- Repeating `acquire` with the same live owner, purpose and semantic metadata is idempotent. It may extend expiry, but it never shortens expiry and does not advance `updated_at_unix` when no state changes.
- Repeating `acquire` with the same live owner but a different purpose or semantic metadata fails closed. The caller must release the old identity and acquire a new one explicitly.
- Server-generated admission evidence is not caller-controlled metadata. A caller cannot provide `work_admission`, and same-owner reentry preserves the original admission generation rather than rerunning or rewriting it.
- Reclaiming an expired lease starts a new acquisition time and records the previous owner. A later idempotent call preserves that reclaim provenance.
- `renew` never shortens expiry. It reports the requested expiry separately from the effective minimum expiry of the renewed set.
- `renew` and `release` may be bound to exact public lease snapshots. A changed, replaced or disappeared lease aborts the complete atomic mutation.
- A force release may bind a foreign-owner snapshot. Force authority does not disable snapshot comparison.
- A lease carrying a non-conflict exception cannot be extended through either `renew` or same-owner `acquire`. The caller must reassess and acquire a fresh exception after the old generation expires or is explicitly released.

Missing and expired renewals use distinct typed failures. Only these two states are eligible for an explicit reacquisition path; ownership, integrity, policy and snapshot failures are not downgraded to expiry.

## Durable task reconciliation

A persistent task resume or live-task maintenance first renews the complete lease set. If one or more leases are missing or expired, Grabowski reconciles the set in one resource-store transaction:

- every still-live same-owner lease keeps its original acquisition time, raw metadata JSON, metadata hash, purpose and reclaim provenance;
- only missing or expired leases receive a new generation with the current task attempt and `recovered_after_expiry=true`;
- all reconciled leases receive an expiry that is at least as late as the requested expiry;
- any foreign owner, metadata-integrity failure, semantic identity mismatch, policy failure or non-conflict exception aborts the entire transaction.

The internal preservation mode is restricted to durable task owners. It is not exposed by the public resource-acquire tool. A mixed operation reports `reconciled`; a set containing no preserved live generation reports `reacquired`.

A resume therefore does not rewrite a live lease with a new attempt number. This keeps the lease identity stable across execution attempts and prevents a task retry from silently changing ownership evidence.

## Fail-closed boundary

Grabowski refuses to open a store carrying a malformed or unsupported lease-contract version. It does not rewrite, downgrade or infer compatibility from table shape. Schema inventory exposes the observed, current and supported contract versions without mutating the store.

The v1 snapshot is a compare-and-swap binding over owner, acquisition time, update time, expiry and metadata hash. It is not a monotonic lease-generation counter. A future contract version may add an explicit generation field without changing the meaning of v1 rows.

This contract does not grant lease ownership, deployment authority, migration authority or compatibility with future lease semantics.

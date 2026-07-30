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

## Fail-closed boundary

Grabowski refuses to open a store carrying a malformed or unsupported lease-contract version. It does not rewrite, downgrade or infer compatibility from table shape. Schema inventory exposes the observed, current and supported contract versions without mutating the store.

This contract does not grant lease ownership, deployment authority, migration authority or compatibility with future lease semantics.

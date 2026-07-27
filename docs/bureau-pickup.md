# Coordinated Bureau pickup

## Truth boundaries

Bureau remains authoritative for task eligibility, run identity, reservations, worktree identity and terminal state. Grabowski remains authoritative for live resource leases. The adapter does not claim distributed ACID semantics; it implements a bounded two-phase transition with append-only private evidence, authoritative readback and compensation.

Every request is bound to one existing absolute Bureau registry root. The default is the canonical clean Bureau repository root. Claim intent, claim commit, recovery status, terminal status and release reuse that same normalized root, and the operator mutation gate is evaluated against it. The root is stored in the private request journal so an exact retry cannot silently switch Registry truth. Journals created before this field existed remain bound to the canonical default root.

## Integration state

The module declares three canonical MCP tools: `grabowski_bureau_pickup_execute`, `grabowski_bureau_pickup_status` and `grabowski_bureau_pickup_release`. The production runtime imports the module for registration, the deployment manifest includes the module and tools, and the capability catalogue classifies execute and release as operator-gated effects while status remains read-only. These source declarations do not establish that a particular runtime release has already been deployed; deployment identity and live tool readback remain separate evidence.

## Machine-readable execute request

The MCP input remains one top-level `request` object, preserving existing Python and Grip callers. Its generated schema requires `worker_id`, `task_id` and the non-empty `capabilities` list enforced by runtime normalization. It exposes `resource`, `kind`, `base_dir`, `approval_source`, `lease_ttl_seconds`, `create_workspace`, `repository_scope_manifests`, `nonconflict_proofs` and `registry_root` as optional properties. Unknown request properties are forbidden by the MCP schema and remain rejected by the authoritative `_normalize_request` path for direct callers. Value bounds, path checks, defaults and normalization remain runtime checks and are not weakened by the published structural schema.

## Execute path

`grabowski_bureau_pickup_execute`:

1. normalizes the exact Bureau registry root and checks operator mutation authority for that path;
2. requests a read-only, approved Bureau `claim-intent` against that root;
3. validates task, worker, run, owner, expiry and exact resource keys;
4. writes immutable private request and intent artifacts;
5. acquires Bureau resources, broad repository resources and remaining resources in explicit groups under `bureau-run:<run_id>`;
6. binds every lease metadata set to `task_id`, `run_id` and `claim_intent_sha256`;
7. requires a complete Grabowski scope manifest for every broad repository lease;
8. commits the exact intent and live lease binding through the same Bureau root, optionally creating the planned workspace;
9. reads the canonical Bureau run through the same root after any unclear commit result;
10. compensates all acquired leases when the commit is authoritatively known not to have started or Bureau authoritatively reports that the run does not exist;
11. compensates the current acquisition group as well when snapshot validation or immutable journaling fails after the lease database commit.

A transport timeout never proves that the claim was absent. Ambiguous states retain their leases and raise `claim-commit-recovery-required` with the structured recovery result. A definitely unapplied commit compensates its own acquisitions and raises `claim-commit-not-applied`. An exact retry may recover an existing assignment only when the stored request, registry root, intent digest and acquisition journal all match; an unjournaled assignment remains foreign and fails closed.

## Status and release

`grabowski_bureau_pickup_status` reads Bureau coordination state without creating or changing private journal paths. It uses the registry root stored for the run, or the canonical default for historical journals and runs without local journal evidence.

`grabowski_bureau_pickup_release` requires:

- a terminal Bureau run read through the root bound to the run;
- an intact acquisition journal digest;
- exact owner, resource-set and claim-intent binding;
- unchanged lease metadata identity for every lease still present.

It releases only the owner-bound keys recorded by the adapter. Missing leases are accepted as already released; foreign ownership or metadata drift fails closed.

## Private journal

Each run is stored below `~/.local/state/grabowski/bureau-pickup/runs/<run_id>/` with mode `0700`; files use mode `0600`. Every directory component is opened through directory file descriptors with `O_DIRECTORY|O_NOFOLLOW`, bound to the current user, exact private mode and stable inode identity. Artifact reads and create-only writes remain bound to the opened run directory, detect path replacement, and accept a concurrent winner only when its immutable bytes are identical.

## Non-claims

The adapter does not establish:

- automatic task completion or verification;
- merge or deployment authority;
- permission to release foreign leases;
- workspace cleanup authority;
- safety of retrying an ambiguous commit without a fresh readback;
- absence of resource conflicts outside the live Grabowski lease database;
- validity or mutability of a caller-selected Registry root beyond the separate Bureau and operator gates.

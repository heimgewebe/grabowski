# Coordinated Bureau pickup

## Truth boundaries

Bureau remains authoritative for task eligibility, run identity, reservations, worktree identity and terminal state. Grabowski remains authoritative for live resource leases. The adapter does not claim distributed ACID semantics; it implements a bounded two-phase transition with append-only private evidence, authoritative readback and compensation.

Every request is bound to one existing absolute Bureau registry root. Without an explicit `registry_root`, the adapter resolves the immutable canonical Registry snapshot from the installed Bureau deployment manifest and verifies its source commit, inventory, tracked-tree, launcher and manifest digests. It never falls back to `~/repos/bureau` or another conventional checkout. Registry truth and operational run state are separate authorities: the adapter explicitly binds one private coordination root. Its default is Bureau's existing `~/.local/state/bureau`, preserving all prior runs, overlays and receipts without copying or splitting state. An operator may configure a different root only through `GRABOWSKI_BUREAU_COORDINATION_ROOT`; callers cannot select or override it. Claim intent, claim commit, recovery status, terminal status and release reuse the same normalized Registry and coordination roots, and the operator mutation gate is evaluated against both effect paths. Both roots are stored in the private request journal so an exact retry cannot silently switch either truth source.

Historical journals without a `coordination_root` remain bound to Bureau's implicit state location. With the default configuration this is byte-for-byte the same directory, so exact retries retain continuity. After an operator-configured cutover to another root, old assignments are not silently adopted and require status/recovery instead of execute retry. A status lookup without local journal evidence probes the configured root first and retries the implicit legacy state only after an authoritative `unknown-run` result; transport failures and ambiguous responses never trigger fallback.

## Integration state

The module declares three canonical MCP tools: `grabowski_bureau_pickup_execute`, `grabowski_bureau_pickup_status` and `grabowski_bureau_pickup_release`. The production runtime imports the module for registration, the deployment manifest includes the module and tools, and the capability catalogue classifies execute and release as operator-gated effects while status remains read-only. These source declarations do not establish that a particular runtime release has already been deployed; deployment identity and live tool readback remain separate evidence.

## Machine-readable execute request

The MCP input remains one top-level `request` object, preserving existing Python and Grip callers. Its generated schema requires `worker_id`, `task_id` and the non-empty `capabilities` list enforced by runtime normalization. It exposes `resource`, `kind`, `base_dir`, `approval_source`, `lease_ttl_seconds`, `create_workspace`, `repository_scope_manifests`, `nonconflict_proofs` and `registry_root` as optional properties. `coordination_root` is deliberately absent from the public schema and is accepted only when re-reading an adapter-owned private journal. Unknown request properties are forbidden by the MCP schema and remain rejected by the authoritative `_normalize_request` path for direct callers. Value bounds, path checks, defaults and normalization remain runtime checks and are not weakened by the published structural schema.

## Execute path

`grabowski_bureau_pickup_execute`:

1. normalizes the exact Bureau registry root, derives the adapter-owned coordination root and checks operator mutation authority for both paths;
2. creates or reopens the configured coordination directory through descriptor-bound `O_DIRECTORY|O_NOFOLLOW` traversal, requiring current ownership and mode `0700`;
3. requests a read-only, approved Bureau `claim-intent` against the Registry root and the same explicit coordination root;
4. validates task, worker, run, owner, expiry and exact resource keys;
5. writes immutable private request and intent artifacts;
6. acquires Bureau resources, broad repository resources and remaining resources in explicit groups under `bureau-run:<run_id>`;
7. binds every lease metadata set to `task_id`, `run_id` and `claim_intent_sha256`;
8. requires a complete Grabowski scope manifest for every broad repository lease;
9. commits the exact intent and live lease binding through the same Bureau root, optionally creating the planned workspace;
10. reads the canonical Bureau run through the same root after any unclear commit result;
11. compensates all acquired leases when the commit is authoritatively known not to have started or Bureau authoritatively reports that the run does not exist;
12. compensates the current acquisition group as well when snapshot validation or immutable journaling fails after the lease database commit.

A transport timeout never proves that the claim was absent. Ambiguous states retain their leases and raise `claim-commit-recovery-required` with the structured recovery result. A definitely unapplied commit compensates its own acquisitions and raises `claim-commit-not-applied`. An exact retry may recover an existing assignment only when the stored request, Registry root, coordination root, intent digest and acquisition journal all match; an unjournaled assignment remains foreign and fails closed. Legacy assignments lacking the explicit coordination-root field may be recovered by execute only while the configured root still equals Bureau's implicit legacy state. After a configured root cutover they are read through status/recovery and are not adopted by execute.

## Status and release

`grabowski_bureau_pickup_status` reads Bureau coordination state without creating or changing private journal paths. It uses both roots stored for the run. Historical journals without the newer field use Bureau's implicit legacy state; runs without local journal evidence use the configured root first and, only when it differs, fall back to the implicit state after a definite missing-run result. The response exposes `root_binding_source` so the selected authority remains visible.

`grabowski_bureau_pickup_release` requires:

- a terminal Bureau run read through the Registry and coordination roots bound to the run;
- an intact acquisition journal digest;
- exact owner, resource-set and claim-intent binding;
- unchanged lease metadata identity for every lease still present.

It releases only the owner-bound keys recorded by the adapter. Missing leases are accepted as already released; foreign ownership or metadata drift fails closed.

## Private journal

Each run is stored below `~/.local/state/grabowski/bureau-pickup/runs/<run_id>/` with mode `0700`; files use mode `0600`. The coordination database remains in the explicitly bound private Bureau state directory; the default is `~/.local/state/bureau/bureau.sqlite3`. Every directory component is opened through directory file descriptors with `O_DIRECTORY|O_NOFOLLOW`, bound to the current user, exact private mode and stable inode identity. Artifact reads and create-only writes remain bound to the opened run directory, detect path replacement, and accept a concurrent winner only when its immutable bytes are identical.

## Non-claims

The adapter does not establish:

- automatic task completion or verification;
- merge or deployment authority;
- permission to release foreign leases;
- workspace cleanup authority;
- safety of retrying an ambiguous commit without a fresh readback;
- absence of resource conflicts outside the live Grabowski lease database;
- validity or mutability of a caller-selected Registry root beyond the separate Bureau and operator gates.

## Claim refusal diagnostics

The pickup adapter preserves the Bureau envelope runtime identity for the claim-intent read and converts refusals into stable, specific error codes such as `claim-intent-no-eligible-task` and `claim-intent-approval-required`. A typed approval refusal retains the bounded required level and submitted evidence level, but never grants or upgrades approval. Against an older Bureau launcher that exits nonzero with empty stdout and human-readable stderr, the intake adapter reports `bureau-command-rejected` with return code and output digests rather than misclassifying the response as malformed; raw stderr is not exposed. Structured rejection detail, adapter retry metadata and a bounded runtime-identity summary remain attached to the error. Any individual refusal value above 16 KiB is replaced by its type, byte size and SHA-256 digest, so oversized upstream diagnostics cannot inflate MCP error metadata. This distinguishes approval denial, task-state rejection and stale release/Registry identity without acquiring any lease or starting a workspace.

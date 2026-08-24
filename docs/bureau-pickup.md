# Coordinated Bureau pickup

## Truth boundaries

Bureau remains authoritative for task eligibility, run identity, reservations, worktree identity and terminal state. Grabowski remains authoritative for live resource leases. The adapter does not claim distributed ACID semantics; it implements a bounded two-phase transition with append-only private evidence, authoritative readback and compensation.

Every request is bound to one existing absolute Bureau registry root. Without an explicit `registry_root`, the adapter resolves the immutable canonical Registry snapshot from the installed Bureau deployment manifest and verifies its source commit, inventory, tracked-tree, launcher and manifest digests. It never falls back to `~/repos/bureau` or another conventional checkout. Registry truth and operational run state are separate authorities: the adapter explicitly binds one private coordination root. Its default is Bureau's existing `~/.local/state/bureau`, preserving all prior runs, overlays and receipts without copying or splitting state. An operator may configure a different root only through `GRABOWSKI_BUREAU_COORDINATION_ROOT`; callers cannot select or override it. Claim intent, claim commit, recovery status, terminal status and release reuse the same normalized Registry and coordination roots, and the operator mutation gate is evaluated against both effect paths. Both roots are stored in the private request journal so an exact retry cannot silently switch either truth source.

Historical journals without a `coordination_root` remain bound to Bureau's implicit state location. With the default configuration this is byte-for-byte the same directory, so exact retries retain continuity. After an operator-configured cutover to another root, old assignments are not silently adopted and require status/recovery instead of execute retry. A status lookup without local journal evidence probes the configured root first and retries the implicit legacy state only after an authoritative `unknown-run` result; transport failures and ambiguous responses never trigger fallback.

## Integration state

The module declares three canonical MCP tools: `grabowski_bureau_pickup_execute`, `grabowski_bureau_pickup_status` and `grabowski_bureau_pickup_release`. The production runtime imports the module for registration, the deployment manifest includes the module and tools, and the capability catalogue classifies execute and release as operator-gated effects while status remains read-only. These source declarations do not establish that a particular runtime release has already been deployed; deployment identity and live tool readback remain separate evidence.

## Machine-readable execute request

The MCP input remains one top-level `request` object, preserving existing Python and Grip callers. Its generated schema requires `worker_id` and the non-empty `capabilities` list enforced by runtime normalization; `task_id` is optional. When `task_id` is omitted, Bureau selects the next eligible task for the same worker/capability request, while an explicit `task_id` remains a strict selection constraint. It exposes `resource`, `kind`, `base_dir`, `approval_source`, `approval_level`, `lease_ttl_seconds`, `create_workspace`, `repository_scope_manifests`, `nonconflict_proofs` and `registry_root` as optional properties. `approval_level` is the strict enum `operator | break_glass`; it defaults to `operator`. Break-glass is transported only when the caller explicitly selects it, never inferred from a task requirement or an approval refusal. `coordination_root` is deliberately absent from the public schema and is accepted only when re-reading an adapter-owned private journal. Unknown request properties are forbidden by the MCP schema and remain rejected by the authoritative `_normalize_request` path for direct callers. Value bounds, path checks, defaults and normalization remain runtime checks and are not weakened by the published structural schema.

## Execute path

`grabowski_bureau_pickup_execute`:

1. normalizes the exact Bureau registry root, derives the adapter-owned coordination root and checks operator mutation authority for both paths;
2. creates or reopens the configured coordination directory through descriptor-bound `O_DIRECTORY|O_NOFOLLOW` traversal, requiring current ownership and mode `0700`;
3. requests a read-only Bureau `claim-intent` against the Registry root and the same explicit coordination root, selecting the requested task strictly or the next eligible task when `task_id` is omitted; the default `approval_level=operator` emits `--approve`, while only explicit `approval_level=break_glass` emits `--break-glass`;
4. validates task, worker, run, owner, expiry and exact resource keys;
5. precomputes and validates the effect-free acquisition-group plan, including broad-repository scope manifests and every supplied non-conflict proof's shape, owner, resource set, purpose, requested scope binding and requested lease lifetime;
6. writes immutable private request and intent artifacts only after that preflight succeeds;
7. acquires Bureau resources, broad repository resources and remaining resources from that exact validated plan under `bureau-run:<run_id>`;
8. binds every lease metadata set to `task_id`, `run_id` and `claim_intent_sha256`;
9. requires a complete Grabowski scope manifest for every broad repository lease, while self-scoped `repo:<checkout>:branch:<name>`, `repo:<checkout>:operation:<name>` and `repo:<checkout>:tag:<name>` keys remain authoritative and carry no scope manifest;
10. commits the exact intent and live lease binding through the same Bureau root, optionally creating the planned workspace;
11. reads the canonical Bureau run through the same root after any unclear commit result;
12. compensates all acquired leases when the commit is authoritatively known not to have started or Bureau authoritatively reports that the run does not exist;
13. compensates the current acquisition group as well when snapshot validation or immutable journaling fails after the lease database commit.

A deterministic preflight refusal, such as a missing broad-repository scope, proof scope drift, or a lease lifetime exceeding its proof, reports `effect_started: false` and leaves no immutable request or intent artifact that could collide with a corrected retry. Live blocker identity, lease snapshot, existing scope and conflict-axis revalidation remain atomic inside resource acquisition. A transport timeout never proves that the claim was absent. Ambiguous states retain their leases and raise `claim-commit-recovery-required` with the structured recovery result. A definitely unapplied commit compensates its own acquisitions and raises `claim-commit-not-applied`. An exact retry may recover an existing assignment only when the stored request, Registry root, coordination root, intent digest and acquisition journal all match; an unjournaled assignment remains foreign and fails closed. Legacy assignments lacking the explicit coordination-root field may be recovered by execute only while the configured root still equals Bureau's implicit legacy state. After a configured root cutover they are read through status/recovery and are not adopted by execute.

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

## Machine-complete closeout latch

Before starting a claim, creating coordination state or acquiring a lease, the adapter reads the exact canonical task document inside the already bound Registry snapshot. A non-terminal task produces the normal terminal result `closeout-only` only when its machine completion is explicitly `verified`, every declared acceptance item has one corresponding successful result, and completion plus verification repeat the same strong commit or SHA-256 identity. The result is bound to the complete task-document digest and is invalidated by any later document change. It suppresses repeated code, deployment and connector work for that unchanged evidence, but it does not change the Bureau task state or replace Bureau lifecycle closeout.

## Claim refusal diagnostics

The pickup adapter preserves the Bureau envelope runtime identity for the claim-intent read and converts refusals into stable, specific error codes such as `claim-intent-no-eligible-task` and `claim-intent-approval-required`. A typed approval refusal retains the bounded required level and submitted evidence level, but never grants or upgrades approval. In particular, a `required_level=break_glass` refusal cannot cause automatic escalation; a later break-glass attempt must be a new explicit request value and therefore a new request digest. Against an older Bureau launcher that exits nonzero with empty stdout and human-readable stderr, the intake adapter reports `bureau-command-rejected` with return code and output digests rather than misclassifying the response as malformed; raw stderr is not exposed. Structured rejection detail, adapter retry metadata and a bounded runtime-identity summary remain attached to the error. Any individual refusal value above 16 KiB is replaced by its type, byte size and SHA-256 digest, so oversized upstream diagnostics cannot inflate MCP error metadata. This distinguishes approval denial, task-state rejection and stale release/Registry identity without acquiring any lease or starting a workspace.

## Checkout-binding terminal reconciliation grips

The stable Grip surface exposes the existing checkout terminal-reconciliation implementation without adding a generic execute path. `checkout-binding-terminal-preview` is read-only and accepts only `checkout_key`. It supports two bounded modes: an already missing managed checkout may be prepared for `externally_terminal_missing`, while a still-present checkout may be prepared for `active -> completed_retained` only when its source is a terminal Work Lane, `lease_release_ready=true`, the checkout is clean and coordination-free, and its head is remotely recoverable. Current-format Work Lane receipts additionally require an exact `terminal_head_sha`; legacy receipts without that field remain subject to the stricter historical recovery proof. Checkout absence or retention age alone never makes the preview safe. Missing or inaccessible repository state is surfaced as a structured blocked preflight rather than escaping the Grip boundary.

`checkout-binding-terminal-apply` is separately mutating and requires `allow_mutation=true` plus `checkout_key`, durable `owner_id`, the exact `expected_preview_sha256`, `preview_created_at_unix` and the existing exact terminal-reconciliation confirmation. The runner delegates to `grabowski_checkout_binding_terminal_apply`, which revalidates source evidence, live coordination, preview freshness and lifecycle CAS state. Missing mode changes only the lifecycle phase to `externally_terminal_missing`; present Work Lane mode changes only `active -> completed_retained`, preserving the physical checkout and retention while releasing its active creation-capacity slot. A retained checkout that later disappears may run a new missing-mode reconciliation; its prior receipt is exposed and hash-bound as the predecessor so post-mutation readback can still recover the exact earlier apply result. Neither mode archives or removes a worktree, deletes a branch/ref, drops retention state, or infers terminality from a missing path. If the delegated apply raises after a mutation may already have committed, the Grip performs one exact preview readback and accepts either a matching `already_applied` receipt or the matching predecessor receipt from a missing-follow-up preview; otherwise it returns `outcome_unknown` with an explicit required readback and no retry authority.

# Coordinated Bureau pickup

## Truth boundaries

Bureau remains authoritative for task eligibility, run identity, reservations, worktree identity and terminal state. Grabowski remains authoritative for live resource leases. The adapter does not claim distributed ACID semantics; it implements a bounded two-phase transition with append-only private evidence, authoritative readback and compensation.

## Integration state

The module declares three canonical MCP tools: `grabowski_bureau_pickup_execute`, `grabowski_bureau_pickup_status` and `grabowski_bureau_pickup_release`. The production runtime imports the module for registration, the deployment manifest includes the module and tools, and the capability catalogue classifies execute and release as operator-gated effects while status remains read-only. These source declarations do not establish that a particular runtime release has already been deployed; deployment identity and live tool readback remain separate evidence.

## Execute path

`grabowski_bureau_pickup_execute`:

1. requests a read-only, approved Bureau `claim-intent`;
2. validates task, worker, run, owner, expiry and exact resource keys;
3. writes immutable private request and intent artifacts;
4. acquires Bureau resources, broad repository resources and remaining resources in explicit groups under `bureau-run:<run_id>`;
5. binds every lease metadata set to `task_id`, `run_id` and `claim_intent_sha256`;
6. requires a complete Grabowski scope manifest for every broad repository lease;
7. commits the exact intent and live lease binding through Bureau, optionally creating the planned workspace;
8. reads the canonical Bureau run after any unclear commit result;
9. compensates acquired leases only when Bureau authoritatively reports that the run does not exist;
10. compensates the current acquisition group as well when snapshot validation or immutable journaling fails after the lease database commit.

A transport timeout never proves that the claim was absent. Ambiguous states retain their leases and return `recovery-required`. An exact retry may recover an existing assignment only when the stored request, intent digest and acquisition journal all match; an unjournaled assignment remains foreign and fails closed.

## Status and release

`grabowski_bureau_pickup_status` reads Bureau coordination state without creating or changing private journal paths.

`grabowski_bureau_pickup_release` requires:

- a terminal Bureau run;
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
- absence of resource conflicts outside the live Grabowski lease database.

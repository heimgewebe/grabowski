# Checkout lifecycle policy

Grabowski-managed automated checkouts use an explicit lifecycle binding. The binding is additive: unmanaged legacy or foreign worktrees remain observable but are not silently adopted, reset, archived or removed.

## Creation contract

Before a managed worktree is created, the caller must provide and Grabowski must durably bind:

- owner;
- purpose;
- source kind and source identity;
- artifact class;
- retention deadline;
- expected branch and exact head;
- repository common directory and checkout path.

`worktree-ensure` requires these fields from the caller. Agent Workspace derives them from its verified Bureau-task or thread-focus binding. Missing or conflicting fields fail before `git worktree add`.

## Per-repository limits

Limits apply to explicitly managed physical lifecycle rows in `active` or `completed_retained` for one Git common directory:

- at most **8 active** managed checkouts;
- at most **4 completed-retained** managed checkouts.

Expiry alone does not stop a row from counting. It stops counting only after the lifecycle transitions to `archived`. The limit is a growth gate. It never authorizes deletion of an existing checkout and never counts an unmanaged foreign checkout as owned. A completed-retained transition that would exceed the limit fails closed and preserves the checkout in its prior active state.

## Completion and immediate cleanup eligibility

Closing an Agent Workspace records the final writer head and transitions its managed checkout from `active` to `completed_retained`. Cleanup remains a separate explicit operation.

Cleanup is two-stage and uses two explicit top-level attempts, but is no longer time-delayed:

1. create a durable recovery archive, retain the linked checkout and return `archived_ready_for_cleanup`;
2. immediately create a fresh exact cleanup plan and, in a separate invocation, apply it only if all blockers remain clear.

A matching fresh archive is reported as `cleanup_candidate` unless active coordination blocks it. The archive and destructive removal are never performed in the same top-level attempt. Recovery paths and direct callers still cannot bypass the archive, exact checkout identity, clean-state, owner, recovery-ref, coordination, dry-run and plan-hash checks.

Cleanup-plan schema 2 keeps `archive_age_seconds` visible as a compatibility observation but does not treat the continuously changing age as authorization material. `archive_grace_seconds` remains present with value `0`, and `archive_grace_elapsed` remains `true`, so existing consumers can migrate without a schema break. The plan hash binds the immutable `archive_created_at_unix`, the declared exclusion list and every other plan field, including checkout identity, archive, recovery refs, retention, coordination blockers, command and rollback data. Any change outside the single declared observational age field invalidates the dry-run. Schema-1 dry-runs are intentionally stale after the upgrade and must be recreated.

## Hard blockers

Cleanup remains blocked by:

- the repository main worktree;
- a dirty linked checkout (dirty state is never deleted);
- active tasks whose exact cwd is inside the checkout or repository main worktree;
- live processes inside those scopes;
- relevant path or repository resource leases;
- retention ownership;
- head neither present on local remote-tracking refs nor, during an explicit cleanup dry-run, verified as the exact `headRefOid` and `refs/pull/<n>/head` of a merged pull request on the strictly bound GitHub `origin` (`remote_secured=false`);
- head, branch, archive or dry-run drift.

Cleanup inventory and dry-run therefore require terminal + clean + remote-secured + lease/process/retention-free evidence together. Disjoint source-path leases do not globally block an unrelated checkout. No cleanup is automatic; archive creation, dry-run and apply remain separate evidenced actions.

## Non-claims

This policy does not clean legacy worktrees, reclaim foreign ownership, infer a source binding from directory names, bypass repository-specific coordination, or authorize removal merely because a limit is reached. Limits are local policy constants, not evidence that every historical checkout has been migrated.
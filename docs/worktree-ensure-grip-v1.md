# Worktree Ensure Grip v1

`worktree-ensure` creates or verifies one exact Git worktree through the existing Grabowski grip surface. It is a normal mutating grip, not a generic shell wrapper.

## Required binding

The call binds these normalized values into one immutable idempotency identity:

- repository top-level path;
- exact 40-character base commit;
- branch name;
- absolute target path below the repository parent;
- lease owner;
- explicit purpose;
- exact retention deadline;
- source kind and source identity (for example a Bureau task or PR);
- artifact class;
- caller-supplied idempotency key.

Both `repo:<repo>` and `path:<target>` leases must be live and owned by the declared owner before a new mutation. The grip never creates, renews, steals or force-releases leases. Before `git worktree add`, it also reserves an owner-bound lifecycle record. Missing source/purpose/retention/artifact fields, a conflicting existing binding, or the per-repository active-checkout limit reject the request before Git mutation. Existing foreign or legacy checkouts are never removed to make room.

## Result states

- `CREATED`: the exact clean worktree state was verified after mutation, or an interrupted intent was recovered by exact readback.
- `ALREADY_CORRECT`: a fresh call found the exact clean state already present.
- `CONFLICT`: target, branch, current head, cleanliness or receipt binding disagrees with the request.
- `REJECTED_BY_LEASE`: a new mutation lacks both required live owner-bound leases.
- `NOT_ACCEPTED`: Git returned without producing the requested verified state, or the lifecycle contract rejected new growth before Git mutation.

Every terminal result is written atomically to an owner-only durable receipt. Receipt and lock files are bounded regular files opened without symlink following. The receipt carries an integrity digest, normalized-input digest, lease observation, lifecycle source/artifact/limit evidence, bounded command outcome and exact post-state.

## Interruption recovery

The intent receipt is durable before `git worktree add`. Repeating the same key serializes on the receipt lock and reads the actual Git state before deciding. If the exact state already exists, replay finalizes `CREATED` without a second mutation, even when the initiating lease has since expired; that exception is read-only and is recorded explicitly. If the state is absent, replay still requires live owner-bound leases before retrying. Conflicts fail closed and are never cleaned automatically.

## Non-claims

The grip does not provide exactly-once execution, connector-response delivery, conflict cleanup, branch deletion, lease management or universal command execution. Exact cross-operation deduplication and validation isolation remain the separate T032 scope.

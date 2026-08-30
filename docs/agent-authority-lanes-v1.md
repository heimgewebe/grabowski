# Agent Authority Lanes v1

## Purpose

Grabowski is not an autonomous decision-maker. A user mandate is interpreted by a controller agent. Grabowski supplies local execution, authority delegation, collision control and evidence.

The canonical actor chain is:

```text
user mandate
→ controller decision
→ Grabowski work lane
→ controller or scoped writer effect
→ Grabowski receipt and reconciliation
→ controller integration and closeout
```

## Canonical roles

- `controller`: authoritative for planning, delegation, integration, merge, deployment and closeout.
- `scoped_writer`: authoritative only inside one explicit work lane. It may implement, test, commit, push and create or update a pull request. Merge, deployment, Bureau terminalization and closeout remain controller-only; granting any of those effects requires a different authority role, not merely a scoped-writer lane.
- `reviewer`: read-only and advisory.
- `observer`: read-only evidence collection.

Model identity affects route selection and quality estimates. It does not define authority.

## Work lanes

`grabowski_work_acquire` atomically prepares one direct or Bureau-bound lane by:

1. binding the source mandate and controller,
2. binding an exact repository, base commit, branch and worktree path,
3. acquiring the narrow requested resources plus the target path and branch resource,
4. reusing or creating the exact isolated worktree through the existing worktree contract,
5. persisting a private integrity-bound lane receipt.

For a direct owner-authorized mandate, the original `direct` source remains in the lane identity. The checkout lifecycle is bound internally to `work_lane:<lane_id>`, a server-generated durable source. It is not a ChatGPT thread, MCP session or model identity. Checkout terminal reconciliation accepts that source only after an explicit terminal closeout assessment is bound into the integrity-checked lane receipt; until then cleanup remains fail-closed. Existing Bureau, operator-obligation, thread-focus and GitHub-issue sources keep their own lifecycle binding unchanged.

A missing owner lease or worktree is an auto-preparation condition, not a reason for an unchanged retry. A live foreign overlap remains fail-closed.

The resource store, worktree lifecycle store, task store and audit chain remain authoritative. The lane receipt references them and does not create a second lifecycle truth.

## Decisions

The surface returns one of these operational decisions:

- `EXECUTE`: the exact lane already exists.
- `AUTO_PREPARE_AND_EXECUTE`: Grabowski prepared the exact lane.
- `ISOLATE_AND_EXECUTE`: the requested worktree lane is exact and locally conflict-free while unrelated dirty or foreign live work remains protected outside that lane. The decision is accepted only with integrity-bound isolation evidence from repository admission and never grants cleanup or override authority over that unrelated work.
- `AUTO_PREPARE_FAILED`: no effect was attempted and acquired leases were compensated.
- `HARD_BLOCK`: a real conflict or an uncertain post-effect outcome requires reconciliation.

When a worktree mutation may have started, leases remain bound and the lane becomes `outcome_unknown`. Blind retries are forbidden until post-state reconciliation.

## Writer concurrency

The writer invariant is scoped to overlapping resources, not to the whole system:

```text
one authoritative mutating writer per overlapping-resource lane
```

Disjoint lanes may run in parallel. Controller integration remains authoritative even when implementation is delegated.

### Same-owner branch mutation attempts

A branch/path lease proves the logical owner and resource scope, but it does not by itself distinguish two concurrent controller attempts that reuse that same owner. Local branch or index mutation through `grabowski_git` therefore requires a `branch_attempt` binding containing the owner, operation id, attempt id, attached branch and the exact pre-effect Git preimage. The preimage binds HEAD, the staged index and in-progress merge/cherry-pick/revert/rebase refs.
Unclassified local Git subcommands fail closed. Beyond `push`, `grabowski_git` accepts only explicitly classified branch/index mutators or a conservative read-only set; new Git subcommands must be classified deliberately or routed through a typed operation before use. The read-only Git environment pins `GIT_OPTIONAL_LOCKS=0` so commands such as `status` cannot perform optional index refreshes as a side effect.

The existing branch resource remains the only serialization point. When the same owner already holds that branch through a Work Lane or another live lease, the attempt CAS overlays only an ephemeral attempt marker: it preserves the lease purpose, acquisition time, expiry and prior metadata. A different attempt from the same owner fails before the Git effect with `reconcile_required`; a changed branch or Git preimage also reconciles before effect. Disjoint branch resources remain independent, so this does not create a repository-wide lock.

After terminal Git readback, an overlaid attempt marker is removed and the prior lease metadata identity is restored. A branch lease created only for the mutation attempt is released through its exact snapshot instead. Cleanup failure keeps the mutation receipt non-terminal (`outcome_unknown`) and forbids a blind retry. Every attempted branch effect emits a receipt that binds owner, operation, attempt, expected and observed preimage, the branch-attempt lease binding, cleanup evidence and the post-effect Git observation.

## Operational truth and hygiene

`grabowski_current_work` treats current tasks, leases, checkouts, workers and processes as operational truth. Historical checkout-binding reconciliation without any current physical or authoritative surface is classified as `hygiene` and remains visible without displacing current work.

## Implemented delegation boundary

Direct owner-authorized work does not require a pre-existing Bureau task. `grabowski_work_acquire` can also start a durable scoped-writer process when a writer command is explicitly supplied. The lane identity, resource scope and controller binding remain authoritative; starting a process does not transfer merge, deployment, Bureau terminalization or closeout authority.

Single-call connector authorization is provided by the owner-bound transport contract. Neither transport identity nor model identity creates a work role by itself.

## Deferred slices

This contract does not claim completion of:

- automatic PR and dirty-state rescue closeout,
- automatic selection of a replacement branch/worktree when the caller-supplied target itself is occupied or conflicting,
- implicit transfer of controller-only effects to a writer,
- cleanup without terminal lane evidence.

Blue-green runtime deployment cutover protocol v1 lives in
`docs/blue-green-deploy-cutover-v1.md` and the bound `src/grabowski_*` modules.
Host dual-service wiring that starts a second operator process remains a
separate runtime integration step; the protocol already classifies pre-cutover
rollback versus post-cutover `outcome_unknown` recovery.

Those are separate follow-up slices built on the lane authority introduced here.

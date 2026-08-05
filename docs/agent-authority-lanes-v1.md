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
- `scoped_writer`: authoritative only inside one explicit work lane. It may implement, test, commit, push and create or update a pull request. Merge, deployment and Bureau terminalization require separate delegation.
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

A missing owner lease or worktree is an auto-preparation condition, not a reason for an unchanged retry. A live foreign overlap remains fail-closed.

The resource store, worktree lifecycle store, task store and audit chain remain authoritative. The lane receipt references them and does not create a second lifecycle truth.

## Decisions

The surface returns one of these operational decisions:

- `EXECUTE`: the exact lane already exists.
- `AUTO_PREPARE_AND_EXECUTE`: Grabowski prepared the exact lane.
- `AUTO_PREPARE_FAILED`: no effect was attempted and acquired leases were compensated.
- `HARD_BLOCK`: a real conflict or an uncertain post-effect outcome requires reconciliation.

When a worktree mutation may have started, leases remain bound and the lane becomes `outcome_unknown`. Blind retries are forbidden until post-state reconciliation.

## Writer concurrency

The writer invariant is scoped to overlapping resources, not to the whole system:

```text
one authoritative mutating writer per overlapping-resource lane
```

Disjoint lanes may run in parallel. Controller integration remains authoritative even when implementation is delegated.

## Operational truth and hygiene

`grabowski_current_work` treats current tasks, leases, checkouts, workers and processes as operational truth. Historical checkout-binding reconciliation without any current physical or authoritative surface is classified as `hygiene` and remains visible without displacing current work.

## Deferred slices

This contract does not claim completion of:

- single-call connector authorization,
- blue-green runtime deployment,
- automatic PR and dirty-state rescue closeout,
- scoped-writer process start and lane-lease handoff.

The P0 contract prepares and binds the lane. Starting a delegated writer process and transferring or delegating the lane leases to that process remains a separate follow-up; this document does not claim that launcher path is complete.

Those are separate follow-up slices built on the lane authority introduced here.

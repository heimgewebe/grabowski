# OPERATOR-ECOSYSTEM-REDUNDANCY-V1-T002 Proof

Status: complete

Observed at: 2026-07-10T07:55:00+02:00

## Phase

This phase reconciles local Grabowski checkout and transient-unit residue. It does not delete branches, discard dirty state, resume failed tasks, or infer that unmerged work is obsolete.

## Live classification

The canonical repository and all linked worktrees were checked against:

- `git worktree list --porcelain`;
- `git status --porcelain=v1` per checkout;
- ancestry against `origin/main`;
- open GitHub pull-request head branches;
- Grabowski task records and process scopes;
- retention and archive records.

Before cleanup, 49 worktrees were classified:

| Class | Count | Decision |
|---|---:|---|
| active or special | 3 | retained |
| dirty | 10 | retained; no mutation |
| clean but unmerged | 33 | retained; external purpose not disproven |
| clean and fully contained in `origin/main` | 3 | archive-first cleanup |

## Applied checkout cleanup

All three targets were clean, had no task/process coordination blocker and were fully contained in `origin/main`.

| Checkout | Head | Archive | Result |
|---|---|---|---|
| `/home/alex/grabowski-workspace/checkout-process-scope-v1` | `775f8603b79936e079e1e6e81bde97f5d3818b5a` | `20260710T055521Z-3a106bfcd955` | removed after bound dry run |
| `/home/alex/repos/.grabowski-worktrees/branch-publish-v1` | `6c0de58b029a09455aa3dd831c63a8f0ccffb174` | `20260710T055527Z-cd5f56584b12` | removed after bound dry run |
| `/home/alex/repos/.grabowski-worktrees/runtime-refresh-main` | `5a20323e781d3d3afaa04e0c800e1e61912eff21` | `20260710T055533Z-bdb23a970b24` | removed after bound dry run |

Each archive created a durable `refs/grabowski/checkouts/.../head` recovery ref and a rollback command before `git worktree remove` ran. No `--force` cleanup was used.

Post-condition: worktree count changed from 49 to 46.

## Transient-unit reconciliation

Twenty-three `grabowski-task-*.service` units were in systemd failed state. Every unit matched a persistent task record whose state was already `failed`; none was a running or queued task. `systemctl --user reset-failed` cleared only the stale systemd failure projection.

Post-condition:

- failed Grabowski task units: `23 -> 0`;
- persistent failed task records: `115`, unchanged;
- non-terminal task records: `1`, not modified;
- no task was resumed or deleted.

## Retained risk

Ten dirty worktrees and thirty-three clean but unmerged worktrees remain. Their local state does not prove obsolescence. Existing retention ownership remains binding. A later cleanup requires a separate purpose/PR review and archive-first plan.

## Non-claims

This proof does not establish branch obsolescence, permission to delete branches, semantic correctness of retained changes, task retry safety, or safety of automatic bulk cleanup.

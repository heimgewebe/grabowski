# Grip Mechanic/Captain Boundary v1

Status: implementation slice
Date: 2026-07-07

## Boundary

`mechanic-loop` is the normal-action role. It may dispatch only known normal grips, and every action must carry a target object, scope object and relative receipt path. Unknown actions, recursive dispatch, Captain-only grips, missing target, missing scope, missing receipt path, target/parameter mismatch and high-impact actions fail closed. If any child action is blocked, the parent `mechanic-loop` receipt is blocked as well; `continue_on_blocked` only controls sequencing, not success semantics.

`captain-preflight` is a Captain-only seam. It recognizes high-impact action envelopes, validates target, scope, recovery or irreversibility, and target-change records. In this slice it is a read-only preflight and authority **skeleton**: it evaluates the Captain authority gates listed below and never executes anything.

## Captain authority gates (v1 skeleton)

`captain-preflight` evaluates a structured gate list per request: `high-impact-marked`, `target-bound`, `scope-bound`, `target-change-record`, `recovery-or-irreversibility`, `status-projection-fresh`, `execution-authority-present`, `review-evidence-present`, `diff-bound`, `ci-green`, `human-authorization-present`. Every gate reports `id`, `status` (`pass`/`blocked`), `reason` and optional `details`. Missing safety evidence blocks; the evaluation is fail-closed.

Target binding is action-specific: `pr-merge` requires one `owner/repo` and a positive integer `pr`; `runtime-deploy` requires `repo` or `service` plus `environment` or `runtime_target`; `service-restart` requires `host` and one concrete non-wildcard `unit`; `fleet-mutation` requires a concrete `fleet_target` and an explicit non-generic `operation`; `cleanup-apply` requires `cleanup_target` plus `repo` or `checkout_path`. Target changes require an explicit non-empty `target_change` record; silent target switches are rejected.

Status projection is mandatory evidence: `status_projection` must be a non-empty object with `status_projection_fresh=true`, a non-empty `status_projection_source` and a `status_projection_sha256` that matches the deterministic JSON hash of the projection object. A missing, stale, unhashed or drifted projection blocks. The projection is evidence about observed state, never runtime truth.

Decision semantics are deliberately narrow. The only decisions are `blocked` and `ready_for_manual_captain_decision`. There is no `authorized`, `executed`, `merged`, `deployed`, `restarted`, `cleaned` or `mutated`. Even when every gate passes, `status` and `receipt_status` stay `blocked` with the reason `captain_execution_not_implemented_in_this_slice`, because no real Captain execution authority exists yet. `allow_execution=true` or any other single parameter never releases execution; execution authority, review evidence, diff binding, CI evidence and human authorization are documented evidence and gates, not semantic guarantees and not automatic releases.

Recovery and irreversibility records are preconditions for any later mutation. They do not prove that a later execution would be safe.

## Current normal actions

- `repo-orient`
- `worktree-orient`
- `situation`
- `scout`
- `pr-check-readiness`
- `post-merge-sync`
- `branch-publish`
- `pr-create-or-update`

## Current high-impact preflight actions

- `pr-merge`
- `runtime-deploy`
- `service-restart`
- `fleet-mutation`
- `cleanup-apply`

## Does not establish

This slice does not establish automatic merge authority, automatic deploy authority, service restart safety, fleet mutation safety, cleanup safety, runtime correctness, semantic correctness, review completeness, production safety, or privileged execution. Runner extraction and further Captain follow-ups (orchestration runner split, real execution authority, webhook or dispatcher integration) are separate future tasks, not part of this slice.

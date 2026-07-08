# Grip Mechanic/Captain Boundary v1

Status: implementation slice
Date: 2026-07-07

## Boundary

`mechanic-loop` is the normal-action role. It may dispatch only known normal grips, and every action must carry a target object, scope object and relative receipt path. Unknown actions, recursive dispatch, Captain-only grips, missing target, missing scope, missing receipt path, target/parameter mismatch and high-impact actions fail closed. If any child action is blocked, the parent `mechanic-loop` receipt is blocked as well; `continue_on_blocked` only controls sequencing, not success semantics.

`captain-preflight` is a Captain-only seam. It recognizes high-impact action envelopes, validates target, scope, recovery or irreversibility, and target-change records. It remains read-only: it evaluates the Captain authority gates listed below and never executes anything.

`captain-run` is the execution seam for action-specific Captain operations. In this slice it executes exactly one action per invocation, only `pr-merge`, and only after the same Captain gates pass, `allow_execution=true` is present, the target is bound to a reviewed `expected_head` and concrete base branch, and GitHub verifies the PR state before and after the command. Other high-impact actions remain explicitly blocked until they receive dedicated executors.

## Captain authority gates

`captain-preflight` and `captain-run` evaluate a structured gate list per request: `high-impact-marked`, `target-bound`, `scope-bound`, `target-change-record`, `recovery-or-irreversibility`, `status-projection-fresh`, `execution-authority-present`, `review-evidence-present`, `diff-bound`, `ci-green`, `autonomy-policy`, `human-authorization-present`. Every gate reports `id`, `status` (`pass`/`blocked`), `reason` and optional `details`. Missing safety evidence blocks; the evaluation is fail-closed.

Target binding is action-specific: `pr-merge` requires exactly one syntactically bounded `owner/repo` slug, a positive integer `pr`, and a concrete non-wildcard `base`; `runtime-deploy` requires exactly one concrete `repo` or `service` plus exactly one concrete `environment` or `runtime_target`; `service-restart` requires one concrete non-wildcard `host` and one concrete non-wildcard `unit`; `fleet-mutation` requires a concrete `fleet_target` and an explicit non-generic `operation`; `cleanup-apply` requires one concrete `cleanup_target` plus a bounded `repo` or concrete `checkout_path`, and any provided optional target field must be typed and concrete. Target changes require an explicit non-empty `target_change` record when present or required; silent target switches and empty target-change records are rejected.

Status projection is mandatory evidence: `status_projection` must be a non-empty object with `status_projection_fresh=true`, a non-empty `status_projection_source` and a `status_projection_sha256` that matches the deterministic JSON hash of the projection object. A missing, stale, unhashed or drifted projection blocks. Captain evidence must be bound to an explicit `expected_head`; review and CI evidence must match that head. The projection is evidence about observed state, never runtime truth.

Decision semantics are split by grip. `captain-preflight` always keeps top-level `decision`, `status`, and `receipt_status` as `blocked` because it is observational. When all gates pass in manual mode, `gate_decision` becomes `ready_for_manual_captain_decision`. When `trusted_owner_mode=true` and `autonomy_policy=act_unless_irreversible_or_ambiguous` are present for actions that explicitly declare `risk.irreversibility=reversible` and have an implemented Captain executor, `gate_decision` becomes `ready_for_autonomous_captain_execution`; per-action `execution_authority` and `human_authorization` evidence are then not required. Missing or ambiguous irreversibility records and irreversible actions are never covered by trusted-owner autonomy and still require explicit authorization evidence.

`captain-run` may return `decision=executed`, `status=passed`, and `receipt_status=passed` only for implemented executors whose post-action verification passes. The current executable action allowlist is deliberately narrow: `pr-merge`. `captain-run` v1 rejects multiple actions because review, diff, CI and status-projection evidence are still top-level and not per action. The PR merge executor first observes the PR with `gh pr view`, requires all required PR fields to be present, allows a bounded preflight settle loop for transient view failures or `UNKNOWN` mergeability / merge-state values, then requires `state=OPEN`, `isDraft=false`, matching `headRefOid`, matching `baseRefName`, `mergeable=MERGEABLE`, and `mergeStateStatus=CLEAN`. The settle loop only retries transient observation or UNKNOWN-state errors; hard blockers such as mismatched head, mismatched base, draft state, non-open state, already-merged state, or missing required fields stop before any merge command. It then uses `gh pr merge --merge --match-head-commit <expected_head>` against the bound `owner/repo`, and finally verifies `state=MERGED`, the same `headRefOid`, the same base, and a valid `mergeCommit.oid` using a bounded post-merge observation loop. A PR that is already merged before execution is blocked in this slice instead of being treated as already satisfied. If the merge command fails, raises through the runner, succeeds unclearly, or post-merge verification fails after bounded retries, `captain-run` returns a failed receipt that still preserves the invocation record, command-return state, bounded command output digests/previews, and emits `execution-preflight`, `execution-attempted`, and `post-execution-verification` checks. A nonzero merge command is always a primary failure even if a later observation sees the PR as merged. Pre-execution drift returns a blocked receipt with no merge attempt. `allow_execution=true` alone still never releases execution; it is only one execution precondition after the evidence gates pass.

The execution receipt separates invocation, command return and verified mutation. `execution_invoked=true` means the bounded merge command runner was called. `command_returned=true` means the runner returned a command result object. `execution_attempted=true` means the merge command returned and was therefore observable as a command attempt. `remote_mutation_observed=true` means post-execution observation verified the PR as merged; it does not prove that the merge command returned successfully. Top-level `execution_counts` reports `invoked_count`, `command_returned_count`, `attempted_count`, and `verified_count` separately. `preflight_view_summary` records bounded pre-merge observation attempts, and `verify_view_summary` records bounded post-merge verification attempts.

Recovery and irreversibility records are preconditions for any later mutation. Reversible actions require a non-empty `recovery_path`; irreversible actions require a non-empty `irreversibility_record`. These records do not prove that a later execution would be safe. Scope must contain a concrete effect or boundary record; `max_targets` alone is only a quantity limit and is not a sufficient scope boundary.

## Current normal actions

- `repo-orient`
- `worktree-orient`
- `situation`
- `scout`
- `pr-check-readiness`
- `post-merge-sync`
- `branch-publish`
- `pr-create-or-update`

## Current high-impact actions

- `pr-merge`
- `runtime-deploy`
- `service-restart`
- `fleet-mutation`
- `cleanup-apply`

## Does not establish

This slice does not establish automatic deploy authority, service restart safety, fleet mutation safety, cleanup safety, runtime correctness, semantic correctness, review completeness, production safety, or privileged execution outside the bound `captain-run` receipt. It also does not bind every evidence object to action or target digests yet. Further Captain follow-ups (deploy/restart/fleet/cleanup executors, action/target evidence digests, gate-native validation errors, webhook or dispatcher integration) are separate future tasks, not part of this slice.

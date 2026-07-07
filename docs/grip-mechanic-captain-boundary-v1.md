# Grip Mechanic/Captain Boundary v1

Status: implementation slice
Date: 2026-07-07

## Boundary

`mechanic-loop` is the normal-action role. It may dispatch only known normal grips, and every action must carry a target object, scope object and relative receipt path. Unknown actions, recursive dispatch, Captain-only grips, missing target, missing scope, missing receipt path, target/parameter mismatch and high-impact actions fail closed. If any child action is blocked, the parent `mechanic-loop` receipt is blocked as well; `continue_on_blocked` only controls sequencing, not success semantics.

`captain-preflight` is a Captain-only seam. It recognizes high-impact action envelopes, validates target, scope, recovery or irreversibility, and target-change records. In this slice it is read-only preflight: it returns `blocked` without a fresh status projection or when privileged execution is disabled.

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

This slice does not establish automatic merge authority, automatic deploy authority, service restart safety, fleet mutation safety, cleanup safety, runtime correctness, semantic correctness, or review completeness.

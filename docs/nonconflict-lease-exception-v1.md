# Same-repository non-conflict lease exception v1

Grabowski may continue a second execution in the same repository only after a short, machine-readable proof shows that its exact effects are disjoint from the owner of the broad repository lease. This is a narrow exception to the one-ball default, not a release, transfer, renewal or sharing of the existing lease.

## Two-step protocol

1. The broad repository owner acquires `repo:/absolute/repository` with a strict `metadata.scope_manifest` and `scope_manifest_complete=true`.
2. The second owner calls `grabowski_resource_nonconflict_assess` with exact resource keys, purpose, scope manifest and `requested_scope_complete=true`. The assessment appends a hash-only audit record.
3. Only when every conflict axis is disjoint does the assessor return a SHA-256-bound proof valid for 30 to 300 seconds and never longer than the blocking lease.
4. The second owner passes that unchanged proof to `grabowski_resource_acquire`, requests only exact non-repository keys and chooses a lease TTL no longer than the proof.
5. The broker starts `BEGIN IMMEDIATE`, re-reads the blocker and exact keys, revalidates the full proof against the live lease and scopes, then acquires all exact keys atomically or none.

The governor may validate the public proof and recommend a bounded route. It remains proposal-only and never grants execution authority. Only atomic resource acquisition can consume the proof.

## Required scope manifest

Schema version 1 declares repository, task ID, common base commit, current head, branch, physical worktree, effects and all conflict axes. Both executions must declare the same base commit; otherwise the audit cannot establish disjointness. A secondary worktree must be a distinct sibling below the repository parent, never a nested directory of the main checkout.

- exact paths and generated artifacts;
- components and runtime resources;
- processes, deployments and migration domains;
- shared gates for repository-wide operations.

Resource keys and manifest axes must match exactly in both directions. Normal and generated files both use canonical `path:` resources in the logical repository namespace so the same target cannot be hidden behind separate worktree locations or key kinds. `component`, `process`, `deployment`, `migration` and `gate` map to their corresponding axes. `service`, `port`, `display` and `browser-profile` map to `runtime_resources`.

Filesystem checks cover ancestor and descendant overlap across logical paths and generated artifacts. Physical worktree equality is checked separately. Symlink aliases, nested secondary worktrees, wildcards, unknown fields, omitted axes, out-of-repository paths and contradictory effects are rejected.

Repository-wide effects require canonical shared gates:

- deploy: `repository-runtime-deploy`;
- migrate: `repository-migration`;
- merge: `repository-merge`;
- worktree administration: `repository-worktree-admin`.

## Fail-closed rules

The exception is denied when:

- task, branch, worktree, path, component, runtime resource, process, deployment, migration, generated artifact or shared gate overlaps;
- either manifest is missing, malformed, broad, unattested, based on another commit, incomplete or inconsistent with its resource keys;
- the blocking lease lacks a scope manifest, belongs to the requester, changed, expired or has less than 30 seconds remaining;
- the blocker is marked `lease_mode=emergency-recovery`;
- owner, purpose, exact resources or requested scope changed after assessment;
- the proof is stale, future-dated, tampered with, carries non-canonical axis evidence, is ambiguous or shorter than the requested lease;
- an exact resource key is already held by another owner;
- no live blocker or more than one plausible blocker exists;
- Bureau and non-Bureau keys are mixed, or the dedicated Bureau always-open contract applies instead.

Exception leases are non-renewable. Continuing work requires a fresh assessment and atomic reacquisition.

## Preserved boundaries

A successful proof does not authorize merge, deploy or migration. It does not release, shorten, rewrite or transfer the foreign lease. It does not permit changes to the foreign worktree, branch or process. High-impact authorization, recovery, review, CI and post-state-readback gates remain independent.

## Obsolete exact-path lease reconciliation

An exact `path:` lease is never treated as disjoint from the same path. `grabowski_resource_nonconflict_assess` now returns a stable denial with code `exact-path-owner-release-required`, the current public lease snapshot and the named reconciliation tool instead of a generic validation error. An absent or expired blocker returns `blocked-path-lease-absent-or-expired`; unsupported resource kinds return `unsupported-blocker-type`.

`grabowski_resource_reconcile_obsolete_path_leases` is a repair path, not a non-conflict exception. It accepts only exact path keys and requires all of the following:

- the lease owner named by the terminal source;
- one complete expected public snapshot per requested lease;
- a hash-valid Agent Workspace close receipt in state `complete` or `resource_release_incomplete`, with all tasks terminal, an explicit `successful` or `abandoned_failed_roles` outcome, exact declared lease keys, canonical workspace-plan lease metadata and no lease update after close began; or
- a hash-valid durable-task outcome receipt for the current successful `completed` attempt, with matching unit, command hash, owner, exact declared resource keys, canonical task-attempt lease metadata and no lease update after the terminal observation.

The broker verifies terminal evidence before the resource transaction; Workspace evidence is verified while holding the canonical Workspace lock. It binds every requested snapshot to the source owner, source-specific lease metadata and terminal timestamp. It then starts `BEGIN IMMEDIATE`, re-reads every lease and deletes only rows whose resource key, owner, acquisition time, update time, expiry and metadata SHA-256 still match the expected snapshot. A resumed task changes the attempt metadata or update time before it can proceed, so an old receipt cannot release that lease. Receipt files are read descriptor-first and must be private, owner-held, regular, singly linked and within the byte limit. Missing, changed or newly owned rows are retained with a machine-readable reason. Mixed outcomes produce `partial`; a second reconciliation after successful release produces `no_change` with `already_absent`, which is idempotent observation and is never counted as a release.

Lease expiry, process absence, inferred completion, task titles, non-conflict proofs and caller-supplied hashes are not terminal authority. Raw failed, cancelled, timed-out or unknown Durable Tasks, uncollected Workspace work, active workspaces, stale task attempts, `outcome_unknown`, changed snapshots and genuine exact overlap remain fail-closed. Failed Workspace roles become terminal only through an explicit, integrity-bound `abandon_failed_roles` closeout after complete collection. The reconciliation receipt grants no write, retry, merge, deploy, migration or policy-bypass authority.

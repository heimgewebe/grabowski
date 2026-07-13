# Same-repository non-conflict lease exception v1

Grabowski may continue a second execution in the same repository only after a short, machine-readable proof shows that its exact effects are disjoint from the owner of the broad repository lease. This is a narrow exception to the one-ball default, not a release, transfer, renewal or sharing of the existing lease.

## Two-step protocol

1. The broad repository owner acquires `repo:/absolute/repository` with a strict `metadata.scope_manifest`.
2. The second owner calls `grabowski_resource_nonconflict_assess` with its exact resource keys, purpose and scope manifest. The assessment appends a hash-only audit record.
3. Only when every conflict axis is disjoint does the assessor return a SHA-256-bound proof valid for 30 to 300 seconds and never longer than the blocking lease.
4. The second owner passes that unchanged proof to `grabowski_resource_acquire`, requests only exact non-repository keys and chooses a lease TTL no longer than the proof.
5. The broker starts `BEGIN IMMEDIATE`, re-reads the blocker and exact keys, revalidates the full proof against the live lease and scopes, then acquires all exact keys atomically or none.

The governor may validate the public proof and recommend a bounded route. It remains proposal-only and never grants execution authority. Only atomic resource acquisition can consume the proof.

## Required scope manifest

Schema version 1 declares repository, task ID, head, branch, isolated worktree, effects and all conflict axes:

- exact paths and generated artifacts;
- components and runtime resources;
- processes, deployments and migration domains;
- shared gates for repository-wide operations.

Resource keys and manifest axes must match exactly in both directions. `path`, `artifact`, `component`, `process`, `deployment`, `migration` and `gate` map to their corresponding axes. `service`, `port`, `display` and `browser-profile` map to `runtime_resources`.

Filesystem checks cover ancestor and descendant overlap across paths, generated artifacts and foreign worktree roots. Wildcards, unknown fields, omitted axes, out-of-scope paths and contradictory effects are rejected.

Repository-wide effects require canonical shared gates:

- deploy: `repository-runtime-deploy`;
- migrate: `repository-migration`;
- merge: `repository-merge`;
- worktree administration: `repository-worktree-admin`.

## Fail-closed rules

The exception is denied when:

- task, branch, worktree, path, component, runtime resource, process, deployment, migration, generated artifact or shared gate overlaps;
- either manifest is missing, malformed, broad, incomplete or inconsistent with its resource keys;
- the blocking lease lacks a scope manifest, belongs to the requester, changed, expired or has less than 30 seconds remaining;
- the blocker is marked `lease_mode=emergency-recovery`;
- owner, purpose, exact resources or requested scope changed after assessment;
- the proof is stale, future-dated, tampered with, ambiguous or shorter than the requested lease;
- an exact resource key is already held by another owner;
- no live blocker or more than one plausible blocker exists;
- the dedicated Bureau always-open contract applies instead.

Exception leases are non-renewable. Continuing work requires a fresh assessment and atomic reacquisition.

## Preserved boundaries

A successful proof does not authorize merge, deploy or migration. It does not release, shorten, rewrite or transfer the foreign lease. It does not permit changes to the foreign worktree, branch or process. High-impact authorization, recovery, review, CI and post-state-readback gates remain independent.

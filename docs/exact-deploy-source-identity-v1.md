# Exact deployment source identity v1

## Problem

The previous self-deploy scheduler always read `/home/alex/repos/grabowski`. A clean, fully validated deployment worktree could therefore not be selected when the canonical checkout was legitimately dirty or occupied. Copying or synchronizing the canonical checkout would risk overwriting unrelated work.

## Contract

`grabowski_runtime_deploy_schedule` accepts an optional exact source repository and an optional expected lease owner.

The default remains the canonical checkout. It is accepted only when all of the following are true:

- the path is absolute, real, and not a symlink;
- it is the canonical repository path;
- `HEAD` and `origin/main` equal the requested commit;
- the checkout is on `main`;
- the working tree is clean;
- no active path lease exists unless its exact owner is supplied.

An explicit noncanonical source is accepted only when all of the following are true:

- the path is absolute, real, and not a symlink;
- it shares the exact Git common directory with the canonical repository;
- it is detached at the requested commit;
- `origin/main` equals the requested commit;
- the working tree is clean;
- an active path lease exists and its exact owner is supplied;
- the scheduled deployment runner is a regular file inside that source.

A topic branch, standalone clone, foreign Git object store, dirty checkout, stale commit, missing lease, wrong lease owner, or symlinked path is rejected before a job is scheduled.

## Bound identity

The scheduler hashes a versioned source identity containing:

- source kind;
- source and canonical paths;
- Git common directory;
- exact `HEAD` and `origin/main`;
- clean-state assertion;
- path lease snapshot, including owner, timestamps, expiry, and metadata hash.

The source identity hash is included in the immutable delayed-runner command. The durable job command hash and finalization receipt therefore bind the deployment to the exact scheduling evidence. An in-flight deployment is reusable only when source path, canonical path, source kind, source identity hash, and commit all match.

## Delayed readback

Immediately before validation and again immediately before deployment, the delayed runner verifies:

- source and canonical paths are still exact real directories;
- both still share the same Git common directory;
- source kind still matches canonical-main or detached-worktree;
- `HEAD` and `origin/main` still match the expected commit;
- the working tree is still clean.

Any drift fails closed before deployment.

## Usage

`make deploy` passes the current checkout as the explicit source. A detached deployment worktree must also expose its current path-lease owner through `GRABOWSKI_DEPLOY_SOURCE_LEASE_OWNER_ID`.

The typed tool may be called directly with:

- `expected_head`;
- `source_repository`;
- `source_lease_owner_id`;
- optional bounded delay.

## Nonclaims

This contract does not:

- authorize merge or deployment by itself;
- bypass recovery, review, CI, kill-switch, or privileged-execution gates;
- hold the scheduling lease forever;
- prove that no same-user process can modify files between filesystem operations;
- permit deployment from a topic branch or unrelated clone;
- make the canonical dirty state disposable.

The lease snapshot establishes scheduling ownership. The repeated Git readbacks establish source-state continuity. Both are required for detached sources; neither replaces the normal deployment preflight or post-deployment manifest verification.

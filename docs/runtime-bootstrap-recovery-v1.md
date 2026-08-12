# Runtime Bootstrap Recovery v1

## Purpose

`runtime-bootstrap-recover` closes the first-bootstrap deadlock tracked by GitHub issue #626.
It is deliberately installed outside the active Grabowski release, so recovery does not
require the currently deployed MCP/operator modules to import successfully.

This is not a second deployment engine. The recovery path terminates in the existing
`tools/deploy_runtime_dual.py --apply` implementation and adds only an exact
`--expected-head` compare-and-swap assertion at that engine's source-snapshot boundary.

## Authority model

The durable root of recovery is the root-owned privileged broker installation and the
root-owned helper `/usr/local/libexec/grabowski-runtime-bootstrap-recover`.

The broker catalog exposes exactly one additional template action:

- action: `runtime_bootstrap_recover`
- accepted target: strict JSON, bounded by the broker and revalidated by the helper
- executable: the fixed root-owned bootstrap helper
- no caller-selected executable, argv, repository or target host

The target contract contains only:

- `schema_version=1`
- `expected_head=<exact Git object id>`
- `target_runtime=heim-pc`

The canonical repository, origin URL, deploy user, worktree root, runtime manifest,
locks and helper paths are constants of the installed helper. They are not supplied by
the caller.

## Root phase

`root-execute`:

1. requires effective UID 0;
2. validates the exact target shape and `target_runtime=heim-pc`;
3. validates the installed helper is a root-owned, non-writable, single-link executable;
4. checks the canonical and legacy operator kill switches;
5. constructs one fixed transient systemd service running as UID/GID 1000;
6. checks the kill switches again immediately before dispatch;
7. invokes only the same root-owned helper in `user-execute` mode;
8. accepts one structured JSON result bound to the requested `expected_head`;
9. exposes hashes and structured receipts rather than raw deployment stdout/stderr.

Root never runs Git, Make, the candidate runtime or a caller-controlled shell.

## User phase

`user-execute` runs as UID/GID 1000 and:

1. checks the canonical and legacy operator kill switches fail-closed;
2. acquires the same `runtime-deploy-schedule.lock` used by normal self-deploy;
3. validates `/home/alex/repos/grabowski`, its canonical common Git directory and the
   exact configured origin URL;
4. requires `origin/main == expected_head` and the exact commit to exist locally;
5. requires the canonical checkout to be clean;
6. disables system/global Git configuration, terminal prompts, hooks, fsmonitor and
   local file transport for recovery Git commands;
7. rejects configured local clean/smudge/process filters;
8. creates a unique detached recovery worktree below
   `/home/alex/repos/.grabowski-deploy-worktrees`;
9. revalidates detached HEAD, common-dir, origin/main, origin URL and cleanliness;
10. builds the normal deploy-tooling environment;
11. checks the kill switches again immediately before the deployment effect;
12. invokes the existing dual deploy engine with `--apply --bootstrap-recovery --expected-head`;
    this mode uses normal admission/drain semantics when the predecessor is coherently active;
    when the operator is confirmed inactive, it treats the active release as unavailable and
    quiesces any still-active tunnel/signed-ingress services itself; unreadable service state
    and mixed state with a still-active operator fail closed;
13. after out-of-band quiescence, proves that all relevant predecessor services are inactive
    immediately before pointer activation, then uses the ordinary activation/start/readback
    sequence without depending on the unavailable predecessor's admission endpoint;
14. revalidates the recovery worktree after the effect;
15. requires the installed deployment manifest to be complete and bound to the exact
    `expected_head`;
16. removes the worktree without force only after proven success; otherwise it is
    retained for forensic readback.

## Failure semantics

The recovery operation is fail-closed. It refuses wrong or stale heads, dirty sources,
origin drift, configured Git filters, competing deployment schedule locks, unsafe path
ownership/modes, malformed broker targets, kill switches and runtime-manifest drift. A
kill-switch marker that cannot be read safely is treated as a blockade, never as absence.

Once deployment has started, any non-proven-success path retains the exact recovery
checkout rather than force-cleaning it. An unknown result must be reconciled from the
runtime manifest and retained source evidence before another effect is attempted.

## Installation

`tools/grabowski_rootbroker_cutover.py` installs the helper from the exact reviewed
commit alongside the existing broker artifacts. The cutover also merges only the exact
commit-bound template action into `/etc/grabowski/privileged-actions.json`; a differing
pre-existing action is rejected instead of overwritten.

## Acceptance for issue #626

Issue #626 is not complete merely because the helper is installed. Closure requires a
live proof that:

1. the active Grabowski release is unavailable as an in-band recovery authority;
2. the root-installed helper and broker remain usable;
3. a clean exact `origin/main` commit is deployed through this bootstrap path;
4. the resulting deployment manifest and runtime readback are bound to that exact
   commit;
5. no duplicate effect, foreign lease override or forced checkout cleanup occurs.

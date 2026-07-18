# Grabowski Operator Grip Foundation Plan v1

Status: draft plan
Date: 2026-07-04
Owner: ChatGPT operator via Grabowski
Scope: make Grabowski more handlungsfaehig and flexible by adding better operator grips, not by adding heavier approval machinery.

## These / Antithese / Synthese

These: Grabowski is already powerful enough at the runtime and capability layer. The live system has a healthy runtime, valid audit and a matching tool contract.

Antithese: Power alone does not make the operator hand useful. Repeated work still hits blocked Git/GitHub/repo paths, unclear checkout orientation, missing high-level operations and too many raw command chains.

Synthese: Optimize Grabowski by building a grip library: named, repeatable operations with light preflight, direct action and concise receipts. Keep only the limits that prevent real outages: kill switch, audit, secret boundaries, protected-main force-push guard, dirty-worktree awareness, recovery awareness for irreversible actions, explicit target/scope and receipts.

## Leitlinie

Grabowski should not be made smaller. Grabowski should get better hands.

Do not ask first: "What must Grabowski be forbidden to do?"

Ask instead: "Which legitimate operator grips fail too often, require too much manual replanning, or produce too little evidence?"

Core formula:

```text
Ziel klar.
Scope klar.
Receipt danach.
```

For high-impact grips:

```text
Grip:
Ziel:
Scope:
Risiko:
Recovery/Irreversibilitaet:
Receipt:
```

## What stays hard

These are outage brakes, not bureaucracy:

1. Kill switch stops mutations.
2. Audit remains active.
3. Secrets must not accidentally enter chat, logs or generic receipts.
4. No force-push to protected main/master branches.
5. Do not overwrite an unknown dirty worktree.
6. Do not perform irreversible delete/cleanup without recovery or explicit irreversibility awareness.
7. Durable runs must not silently change their target.
8. Relevant grips must leave receipts.

Everything else should bias toward action.

## What should stop being dogma

The following are not absolute prohibitions. They are high-impact grips that need visible target, scope and receipt:

- merge
- deploy
- push
- force-with-lease on work branches
- service restart
- fleet mutation
- cleanup apply
- secret use or break-glass reveal
- external agent involvement
- durable operation

A high-impact grip is allowed when it is the actual task, the target is clear, the relevant preflight is satisfied and the receipt records the result.

## Target architecture

```text
Grabowski Core
  Runtime, tools, audit, filesystem, Git, GitHub, fleet, services.

Grip Registry
  Named operation recipes instead of raw repeated tool chains.

Grip Runner
  plan/preflight -> action -> postflight -> receipt.

Durable Roles
  Scout, Mechanic, Captain.

Friction Loop
  Repeated blocked work becomes a new grip.

Agent Loop
  Codex, Claude, agy, Ollama and Aider provide review, patch or reasoning.
  Grabowski integrates and records evidence.
```

## Durable roles

### Scout

Allowed to run durably. Reads and reports changes only.

Examples:

- open PR state
- check drift
- stale review evidence
- runtime/main drift
- unpushed branches
- repeated friction classes
- missing receipts

Scout should be terse: report changes, not wallpaper.

### Mechanic

Allowed to run normal operator grips when target and scope are clear.

Examples:

- run tests
- create branch
- commit bounded fixes
- publish work branch
- create or update PR
- request reviews
- run post-merge sync
- generate friction triage

### Captain

Allowed to run high-impact grips when the grip itself is the intended target.

Examples:

- merge PR
- deploy runtime
- restart service
- mutate fleet host
- apply cleanup
- use or reveal a secret through the appropriate secret path

Captain does not need a long approval ritual, but the grip must be visible and receipt-bound. Captain may act; Captain may not silently change mission.

## Bureau and Cabinet fit

Bureau is useful when work is task-shaped, parallel, claim-sensitive or long-running. If Bureau owns an active task/run, Grabowski must not bypass it.

Bureau is not required for every single repo grip.

Cabinet remains meaning, map and decision memory. Cabinet helps orient the operatorium. Cabinet is not a gate for every action.

Steuerboard remains a read-only repo-state signal. Chronik/Plexer may provide event trace and transport. Event equals evidence; event does not equal command.

## Grip registry priorities

### Wave 1: Orientation and PR flow

Build these first because they reduce the most repeated friction.

1. `repo-orient`
   - report repo, branch, head, origin/main, dirty state, upstream, ahead/behind, open PR, checks, runtime match and next safe grip.

2. `worktree-orient`
   - report canonical checkout, runtime-matching worktree, feature worktrees, dirty worktrees and stale candidates.

3. `pr-check-readiness`
   - report PR head, base, checks, review state, self-review depth, optional external diagnostics, findings, merge risk and verdict.

4. `post-merge-sync`
   - after merge, report local/main/runtime relationship, deployment need and follow-up branch/worktree action.

5. `branch-publish`
   - structured push to a work branch with expected head, remote verification and receipt.

6. `pr-create-or-update`
   - create or update a PR with exact title/body/base/head and requested draft state, then verify branch, base, head and `isDraft` from GitHub. Omitting `draft` preserves an existing PR's state and defaults only a newly created PR to ready.

### Wave 2: High-impact grips

Build after the foundation.

1. `pr-merge`
   - merge a ready PR with recorded head, checks, review evidence, merge result and recovery note.

2. `runtime-deploy-check`
   - read-only deploy readiness.

3. `runtime-deploy`
   - deploy expected head and record previous release, new release, health and rollback data.

4. `service-restart`
   - restart one known unit with status/log/health receipt.

5. `fleet-mutate`
   - run one host-scoped mutation with host role, command intent and postflight receipt.

6. `cleanup-apply`
   - apply known cleanup with target, dirty-state awareness, recovery/ref/quarantine or irreversibility note.

### Wave 3: Agent grips

1. `agent-review-request`
   - ask Codex/Claude/other agent for review with prompt hash, scope and stop condition.

2. `agent-patch-request`
   - request patch from Codex/Aider/agy/local model with bounded scope.

3. `agent-result-integrate`
   - integrate review or patch with scope check, tests and receipt.

### Wave 4: Friction-to-grip loop

1. `friction-triage`
   - cluster recent friction into platform filter, operator bug, contract error, missing grip, auth gap, stale checkout or no-action.

2. `grip-suggest`
   - turn repeated friction into proposed grip schema.

3. `grip-promote`
   - when a pattern repeats, turn it into an implemented grip.

## Implementation sequence

### PR 1: `feat: add operator grip foundation`

Implement:

- grip spec model
- grip receipt model
- grip runner skeleton
- `repo-orient`
- `pr-check-readiness`
- `post-merge-sync`
- tests

Do not implement yet:

- durable runner
- merge
- deploy
- cleanup apply
- fleet mutation
- Bureau bridge
- Plexer coupling
- new capability profiles

### PR 2: `feat: add branch and pr publishing grips`

Implement:

- `branch-publish`
- `pr-create-or-update`
- `agent-review-request`
- friction recording for blocked publishing/review paths

### PR 3: `feat: add privileged grip receipts`

Implement:

- high-impact receipt shape
- `pr-merge`
- `runtime-deploy-check`
- `runtime-deploy`
- `service-restart`

### PR 4: `feat: add worktree navigation grips`

Implement:

- `worktree-orient`
- `checkout-classify`
- `cleanup-plan`
- `cleanup-apply`

### PR 5: `feat: add durable grabowski scout`

Implement a small durable observer that reports only changes:

- stale PR review
- failing or pending checks
- runtime/main drift
- unpushed work branch
- missing receipt
- repeated friction class

### PR 6: `feat: add mechanic durable actions`

Allow durable execution of normal grips when target and scope are clear:

- tests
- branch publish
- PR update
- review request
- post-merge sync
- friction triage

### PR 7: `feat: add captain privileged actions`

Allow durable execution of marked high-impact grips:

- merge
- deploy
- service restart
- fleet mutation
- cleanup apply

### PR 8: `docs: replace restrictive autonomy language`

Only after the mechanics are clearer, update broad doctrine:

- no blanket anti-merge dogma
- no blanket anti-deploy dogma
- no blanket anti-durable-autonomy dogma
- replace with no silent target change, no hidden scope drift and receipt after relevant grips

## Data model

### Grip result states

```text
completed
blocked
failed
partial
rolled_back
noop
```

### Failure classes

```text
blocked_by_platform
preflight_failed
dirty_scope_unclear
remote_rejected
checks_failed
review_findings
secret_boundary
recovery_unclear
postflight_failed
unknown
```

### Recovery classes

```text
read_only
git_revert_possible
remote_head_recorded
backup_created
quarantine_created
service_restart_only
rollback_release_known
irreversible_acknowledged
```

## Receipt location

Start local and simple:

```text
~/.local/state/grabowski/grip-receipts/
```

Optional later:

- Chronik event outbox
- Bureau receipt when Bureau owns the task
- PR comment/body summary for PR-specific grips

Do not make event transport a prerequisite for grips.

## CLI shape

Target CLI:

```bash
grabowski grip repo-orient --repo /home/alex/repos/grabowski
grabowski grip pr-check-readiness --repo /home/alex/repos/grabowski --pr 74
grabowski grip post-merge-sync --repo /home/alex/repos/grabowski --pr 74
grabowski grip branch-publish --repo /home/alex/repos/foo --branch fix/x --expected-head abc...
grabowski grip pr-merge --repo /home/alex/repos/foo --pr 12
grabowski grip runtime-deploy --expected-head abc...
```

MCP tools can follow later:

- `grabowski_grip_list`
- `grabowski_grip_plan`
- `grabowski_grip_run`
- `grabowski_grip_receipt_read`
- `grabowski_grip_friction_triage`

## What not to build first

Do not start with:

- full dashboard
- heavy capability profile system
- mandatory Bureau bridge
- Plexer-first architecture
- eventbus queue semantics
- large metric platform
- new organ called Sentinel
- rigid approval framework

Those may become useful later. They are not the current bottleneck.

## Success criteria

Grabowski is better when:

1. standard repo flows use grips instead of raw tool chains,
2. repeated platform-filter friction decreases,
3. PR readiness is one grip,
4. post-merge sync is one grip,
5. branch publish is one grip,
6. runtime deploy check is one grip,
7. high-impact actions are allowed and receipt-bound,
8. durable scout reports only meaningful changes,
9. normal durable actions do not require repeated user steering,
10. friction becomes implementation input.

Initial target:

- five core grips productive,
- 80 percent of standard repo/PR flows routed through grips,
- top three friction patterns classified,
- no new heavy governance for normal grips,
- receipts stay concise and useful.

## Open gaps before implementation

Need to verify in the target checkout before PR 1:

- clean/dirty Git state,
- correct branch base,
- current operation registry tests,
- best module location for grip runner,
- expected CLI naming,
- receipt storage path.

These are implementation checks, not reasons to redesign the plan.

## Essence

Grabowski wird besser durch bessere Griffe, nicht durch mehr Fesseln.

```text
Operation Registry = Griffbibliothek.
Receipts = Gedaechtnis.
Friction = Lernsignal.
Durable Scout = Wahrnehmung.
Mechanic = normale Ausfuehrung.
Captain = markierte Hochwirkung.
```

First implementation slice:

```text
feat: add operator grip foundation
```

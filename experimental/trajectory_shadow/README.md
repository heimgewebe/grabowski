# Trajectory shadow pilot (experimental)

Status: **STOP / do not promote** (2026-08-28).

This directory contains a read-only, post-hoc pilot owned by the existing Bureau scope
`GRABOWSKI-OPERATOR-SURFACE-V1-T047`. It is not a public runtime contract, does not
intervene in live work, and does not replace `attention_trace_v1`.

## Question

Does provider-session trajectory evidence add actionable information beyond existing
Grabowski evidence early enough to improve diagnosis or recovery?

The pilot deliberately does **not** measure code quality, agent understanding, merge
readiness, review completeness, deployment readiness, task success, or a global agent
score. Outcome evidence remains authoritative for those questions.

## Live source audit

The audit used local live state on 2026-08-28:

- Grabowski repo and Runtime were healthy; the experimental lane was isolated from
  active unrelated work.
- `attention_trace_v1` still reproduced the historical inventory: 59 Agent Workspaces,
  57 event logs, 552 events, 129 lifecycle events mappable to attention categories, and
  48 workspaces with any attention signal. It still has no direct search/read/edit/discover
  observation.
- Claude session logs were present under `~/.claude/projects`; Codex session logs were
  present under `~/.codex/sessions`; Pi was not present locally.
- Mindwalk was neither installed as an executable nor importable as a Python module. No
  dependency was added solely for this pilot because the local adapters were sufficient
  to answer the utility question.

## Attribution gate

Direct `Agent Workspace writer_worktree -> provider session cwd` attribution produced no
matches. The pilot therefore does not use repository+time-window guesses.

Accepted attribution requires:

1. exact Work Lane `target_path == session cwd`;
2. the target path must identify exactly one Work Lane; and
3. branch equality and/or exact base-revision equality.

Target-only and ambiguous matches are excluded. All exactly bound provider sessions for
a lane are merged chronologically rather than selecting only the largest session.

Final inventory:

- 1,355 Work Lane receipts indexed;
- 141 Claude sessions indexed;
- 812 Codex sessions indexed;
- 41 exactly attributable Work Lanes;
- 90 exact session bindings across those lanes;
- 32 Work Lanes with actual tool actions, used as the pilot cohort.

The 32-run cohort contains 10 baseline-success runs, 4 blocked runs, and 18 runs whose
local Work Lane closeout baseline is incomplete/unknown. It includes 3 runs with observed
tool failures and 2 runs with delegation/handoff events.

## Normalized trace

Only minimized metadata is persisted:

- sequence/time;
- actor;
- operation;
- repo-relative target when it can be established;
- outcome;
- source adapter;
- hashed evidence reference;
- attribution/confidence;
- state epoch;
- mutation/result digests where required for equality checks.

The pilot does not persist Chain-of-Thought, prompts, commands, file contents, credentials,
secret values, or raw tool outputs. Raw result material is consumed transiently only to
produce SHA-256 equality digests.

## Exactly four detectors

1. `repeated_failure_without_state_delta`
   - same action fingerprint + same failure-result fingerprint;
   - same state epoch;
   - no successful read/search/discover/context evidence between attempts.

2. `verification_gap`
   - only considered at an evidenced Work Lane closeout boundary;
   - a successful repo mutation occurs after the last successful verification.

3. `mutation_without_evidenced_localization`
   - target-bound mutation without prior read/search/discover/context evidence;
   - intentionally advisory at confidence 0.55 because task-supplied prompt context is
     not read and therefore cannot be disproved.

4. `action_oscillation_without_progress`
   - either A-B-A-B with equal repeated results and no state delta, or the stricter
     edit -> failed verify -> inverse edit -> same edit -> same failed verify pattern.

## Calibration finding that prevented a false promotion

The first implementation produced one apparent high-confidence `verification_gap` with
about 28,861 seconds of apparent lead time. Manual baseline validation showed that this
was a false positive:

- the final "mutation" was actually a Claude `Write` to `~/.claude/plans/...`, outside
  the repository worktree;
- the corresponding Grabowski PR #951 was merged at exact terminal head
  `2cd16612a9dd6eb9f91577bad9efd778ac149896`;
- repository validation and CodeQL completed successfully, and the Codex review
  settlement was green.

The adapter was hardened so external Read/Grep/Glob/Edit/Write targets cannot establish
repo localization or repo mutation. A regression test covers this case. The pilot was then
rerun from the full local sources.

## Final pilot result

The hardened 32-run cohort produced:

- 2,843 normalized tool events;
- 149 reads, 70 searches, 13 discovers, 15 repo edits, 1 other repo mutation, 30 verifies,
  35 delegates, and 2,530 other executions;
- 9 observed tool failures across 3 runs;
- `repeated_failure_without_state_delta`: **0**;
- `verification_gap`: **0**;
- `action_oscillation_without_progress`: **0**;
- `mutation_without_evidenced_localization`: **11**, all advisory/non-promotable;
- promotion-grade high-confidence findings: **0**;
- actionable incremental findings: **0**;
- recoverable cases made earlier/better by trajectory evidence: **0**;
- evidence-supported redundant actions saved: **0**;
- evidence-supported runtime saved: **0 seconds**;
- measurable lead time: **none**;
- token/compute savings: **not determinable**.

The success-cohort "any finding" rate is 1/10 (10%). This is only a conservative
false-positive proxy, not empirical precision: the remaining finding is detector C, for
which task-supplied localization evidence is intentionally unobservable. The cohort has no
labeled ground truth from which a defensible precision percentage could be computed.

## Baseline limitation

Local Work Lane closeout receipts provide lane state, terminal closeout class, reason codes
and terminal observation time. They do not by themselves reconstruct every historical
diff/test/review/acceptance fact. Therefore any future promotion-grade candidate would
need a second join against existing PR/CI/review/outcome evidence before it could count as
`actionable_incremental_information`.

That broader baseline join is intentionally not built now: after adapter hardening there
are no high-confidence candidates to validate, so adding more machinery cannot change the
current STOP decision.

## Decision

Do **not** create `trajectory_evidence_v1`, an online shadow path, a recovery advisory, a
Mindwalk runtime dependency, a visualization, or a merge gate from this pilot.

The evidence currently says that richer provider traces exist and can be attributed for a
bounded cohort, but the four requested detectors did not demonstrate incremental,
actionable information over the existing outcome/control-plane evidence. More telemetry
alone is not a product improvement.

Revisit only if new real failure cases appear whose existing Grabowski evidence is too late
or insufficient, and use those cases as labeled counterexamples. T047 remains the existing
owner for any such future behavior-observability work; do not open a parallel Bureau task.

## Reproduce

```bash
python3 experimental/trajectory_shadow/trajectory_shadow.py \
  --limit 48 \
  --report experimental/trajectory_shadow/pilot_report_2026-08-28.json

python3 -m pytest -q tests/test_trajectory_shadow.py
```

The CLI is read-only with respect to Grabowski runtime/workspaces/sessions. `--report` and
optional `--output-root` only write sanitized experimental artifacts chosen by the caller.

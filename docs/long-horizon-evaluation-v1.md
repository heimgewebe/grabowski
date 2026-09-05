# Long-Horizon Evaluation v1

Status: experimental, offline, no runtime activation

## Purpose

This slice turns one useful CivBench idea into a domain-neutral operator metric without pretending that Civilization scores transfer to software work.

The target failure classes are different from ordinary reasoning failure:

1. **Monitoring allocation failure**: a relevant state is available and a monitoring obligation is known, but the agent does not perform the check on time.
2. **Commitment follow-through failure**: the agent declares a concrete near-term intention but neither completes it nor explicitly abandons it before the evaluation horizon.

The evaluator is deliberately explicit. It never infers a monitoring obligation or a commitment from prose, prompts, model chain-of-thought, argv text, or outcome summaries.

## Why existing Grabowski history is not enough

Grabowski already has useful `agent.run.*` lifecycle events in the Chronik-compatible history seam. Those events can establish that a coding/review run started, completed, or became blocked. They do **not** currently establish, at action-step resolution:

- which nonlocal state the agent was obliged to re-check;
- when that exact check happened;
- which concrete short-horizon commitment was active;
- whether a missing commitment was consciously abandoned or merely forgotten.

Therefore current Chronik lifecycle history must not be relabelled as a CivBench-style PMR/RAG score. Doing so would manufacture precision from missing evidence.

## Trace contract

Input is UTF-8 JSONL. Every record has:

```json
{
  "schema_version": "grabowski.long-horizon-trace.v1",
  "run_id": "run-123",
  "step": 0,
  "kind": "run.started"
}
```

`step` is a monotone logical action index supplied by the producer. Wall-clock time is intentionally not used as a substitute for action count.

Supported event kinds:

### `run.started`

Optional lifecycle marker.

### `run.terminal`

Marks the terminal logical step. At most one is allowed per run. Events after it are invalid.

### `monitor.requirement`

Declares a monitoring channel and its expected maximum gap:

```json
{
  "schema_version": "grabowski.long-horizon-trace.v1",
  "run_id": "run-123",
  "step": 0,
  "kind": "monitor.requirement",
  "monitor_id": "pr-ci-mergeability",
  "cadence_steps": 20,
  "grace_steps": 0
}
```

This is the key epistemic boundary: the evaluator only calls a check overdue if a requirement was explicitly recorded first.

### `monitor.check`

Records that the exact monitoring channel was queried:

```json
{
  "schema_version": "grabowski.long-horizon-trace.v1",
  "run_id": "run-123",
  "step": 17,
  "kind": "monitor.check",
  "monitor_id": "pr-ci-mergeability"
}
```

A check without a matching requirement is rejected.

### `commitment.declared`

Declares a concrete commitment. Default horizon is 10 steps:

```json
{
  "schema_version": "grabowski.long-horizon-trace.v1",
  "run_id": "run-123",
  "step": 5,
  "kind": "commitment.declared",
  "commitment_id": "rerun-focused-tests",
  "horizon_steps": 10
}
```

### `commitment.completed`

Records completion of a declared commitment.

### `commitment.abandoned`

Records an explicit decision to stop pursuing a declared commitment. `reason` is mandatory; `evidence_refs` is optional:

```json
{
  "schema_version": "grabowski.long-horizon-trace.v1",
  "run_id": "run-123",
  "step": 9,
  "kind": "commitment.abandoned",
  "commitment_id": "rerun-focused-tests",
  "reason": "the reviewed head changed; the old test target is no longer authoritative",
  "evidence_refs": ["pr-head:abc123"]
}
```

Explicit abandonment is **not** counted as completion. It is reported separately so that a strategic plan change is not confused with silent forgetting. The evaluator also does not claim that an abandonment was correct merely because it had a reason.

## Metrics

### Monitoring

Per monitoring channel:

- check count;
- initial check delay;
- mean/max interval between actual checks;
- deadline segments and deadline breaches;
- total steps strictly beyond the configured cadence plus grace;
- tail steps since the last check;
- whether the trailing deadline was reached without a check;
- whether the final terminal window contained a check.

A check exactly on its cadence-plus-grace deadline is compliant. If the trace reaches that same deadline without the required check, the deadline is missed even though `overdue_steps_total` remains zero; that field measures only how far beyond an already missed deadline the trace continued.

The aggregate `monitoring_segment_compliance_rate` is the share of observed check/deadline segments that did not breach the explicit maximum gap.

This is inspired by the same failure class as CivBench monitoring analysis, but it is not named or asserted to be CivBench PMR without a validated CivBench adapter.

### Commitments

For each declaration the evaluator classifies the state at its horizon as:

- `completed`: completion at or before the due step;
- `abandoned`: explicit abandonment at or before the due step;
- `missed`: the horizon was fully observed but neither occurred in time;
- `censored`: the trace ended before the full horizon was observable.

Aggregate rates:

- `commitment_completion_at_horizon_rate`: completed / eligible;
- `commitment_accounted_for_at_horizon_rate`: (completed + explicitly abandoned) / eligible;
- `commitment_silent_drop_rate`: missed / eligible.

Censored commitments are excluded from the denominator.

A completion after the horizon remains `missed` for the horizon metric while retaining its later resolution metadata. This prevents late cleanup from rewriting earlier execution discipline.

## CLI

```text
python3 tools/grabowski_long_horizon_eval.py TRACE.jsonl --pretty
```

Use `-` instead of a path for stdin. `--terminal-window-steps N` changes only the final-window diagnostic; it does not change monitoring cadence or commitment horizons.

The evaluator emits deterministic JSON and exits `2` for invalid traces.

## Current evidence status

### Belegt today

- Grabowski has lifecycle-level `agent.run.*` history that can establish start/completion/blocking for some historical coding runs.
- That history alone lacks the typed monitoring-requirement/check and short-horizon commitment events required by this evaluator.
- The evaluator can measure these properties once a producer emits the explicit trace contract.

### Plausible next adapter

A future adapter can bind selected Grabowski audit/tool events to `monitor.check` **only** where the task already has an explicit monitoring requirement. Tool-name frequency alone is not enough: the same tool invocation can answer different questions.

### Not yet established

- historical PMR-like values for existing Grabowski runs;
- historical commitment follow-through@10 from free-form planning text;
- causal improvement from any monitoring or commitment mechanism;
- equivalence to CivBench metrics or model rankings.

## Recommended experiment

After a trace producer exists, run matched A/B tasks with the same model and task fixture:

1. baseline operator policy;
2. persistent monitoring/commitment policy.

Hold tool availability, task fixture, model, and action budget constant. Compare monitoring breach rate, completion-at-horizon rate, accounted-for rate, silent-drop rate, and external task outcome separately.

Do not promote a mechanism merely because it improves a proxy metric while degrading task completion, latency, or correctness.

## Follow-up boundary

This v1 intentionally does **not** modify the public MCP tool surface or activate new always-on telemetry. The next useful implementation slice is a bounded trace producer/adapter for real Grabowski runs, with explicit privacy, retention, source-authority, and replay semantics before activation.

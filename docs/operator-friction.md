# Grabowski Operator Friction Ledger

Grabowski work can fail for different reasons. This ledger records those events in one local JSONL file instead of leaving them only in chat history.

## Event location

`~/.local/state/grabowski/friction/events.jsonl`

Each line follows `contracts/operator-friction-event.v1.schema.json`.

## Kinds

- `platform_filter`: ChatGPT/OpenAI refused or blocked a tool call before the host executed it.
- `connector_snapshot`: Local runtime and the ChatGPT tool snapshot disagreed.
- `fail_closed_gate`: A Grabowski safety gate intentionally stopped execution.
- `execution_context`: Different shell, agent, SSH or environment context changed behavior.
- `ci_contract`: CI or repository contract rejected a change.
- `operator_bug`: Grabowski implementation defect.
- `user_input`: Placeholder or malformed instruction.
- `network`: external network or host reachability issue.
- `unknown`: not classified yet.

## Surfaces

`chat_tool`, `connector`, `runtime`, `terminal`, `local_shell`, `github`, `ci`, `fleet`, `recovery`, `filesystem`, `unknown`.

## Recording rule

Record one event when an attempted operation is stopped or forced onto a fallback path. Keep the record bounded. Do not paste secrets, tokens or full logs. Use a short symptom, suspected trigger and fallback.

Example:

```json
{"kind":"platform_filter","surface":"chat_tool","operation":"make validate","symptom":"tool call rejected before execution","suspected_trigger":"broad shell plus recovery terms","fallback":"use typed checks and CI","resolved":true,"notes":[]}
```

## Review loop

Periodically run `grabowski_friction_summary`. Recurring `platform_filter` entries should become typed tools or smaller workflows. Recurring `connector_snapshot` entries require a connector refresh gate. Recurring `fail_closed_gate` entries usually mean the gate is doing its job; improve the runbook, not the permission surface.

## Task failure classification loop

`docs/operator-optimization-plan.md` makes failure signal quality the first optimization slice. Failed persistent tasks are not automatically friction events: a failed task can be an expected red-phase test, a superseded repair attempt, a command-shape error, an environment/tooling problem or a live actionable failure.

A periodic review should classify failed task records without resuming them. Minimum fields:

```json
{
  "task_id": "task id",
  "repo": "repo or cwd",
  "failure_class": "expected_red_phase|superseded|contract_error|environment_tooling|platform_filter|policy_gate|actionable|unknown",
  "still_relevant": true,
  "superseded_by_green_run": false,
  "next_action": "inspect|ignore_with_reason|create_followup|tighten_tool|stop"
}
```

Classification is a read-only signal operation. It does not authorize resume, cleanup, commit, push, merge, deploy or policy elevation.

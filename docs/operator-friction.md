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

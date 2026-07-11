# Grabowski Operator Friction Ledger

Grabowski work can fail for different reasons. This ledger records those events in one local JSONL file instead of leaving them only in chat history.

## Event location

`~/.local/state/grabowski/friction/events.jsonl`

Each line follows `contracts/operator-friction-event.v1.schema.json`.

## Kinds

- `platform_filter`: ChatGPT/OpenAI refused or blocked a tool call before the host executed it.
- `connector_snapshot`: Local runtime and the ChatGPT tool snapshot disagreed.
- `connector_transport`: ChatGPT-to-Grabowski connector transport failed, for example 502 upstream errors, MCP stream exceptions or connector-side timeouts.
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

Periodically run `grabowski_friction_summary`. Recurring `platform_filter` entries should become typed tools or smaller workflows. Recurring `connector_snapshot` entries require a connector refresh gate. Recurring `connector_transport` entries require bounded transport diagnostics and narrower call shapes, not blind retry loops. Recurring `fail_closed_gate` entries usually mean the gate is doing its job; improve the runbook, not the permission surface.

The summary also emits `next_grip_proposals`. These are proposal-only, read-only recommendations. They group repeated command-chain, blocked-gate, stale-snapshot, review-loop and missing-receipt-field patterns, link recommendations to bounded unresolved `event_id` evidence, and state what the evidence does not prove. Matching is heuristic: one event can support multiple proposal groups, unmatched events do not prove the absence of friction, and recommendations do not prove root cause or implementation readiness. They do not create Bureau tasks, change queue priority, execute grips, resume tasks, merge, deploy or authorize policy exceptions.

## Connector transport failures

Treat 502 upstream errors, `streamable_http` exceptions, `Received exception from stream`, MCP `POST /mcp` stream failures and connector-side timeouts as `connector_transport`, not as command return codes and not as policy-gate results.

Minimum bounded probe after a connector transport failure:

1. Read `grabowski_status` to check runtime contract and client snapshot visibility.
2. Read `grabowski_service_status` for `grabowski-operator.service` and `tunnel-client-grabowski.service`.
3. Parse only bounded recent journal records as JSON. Count explicit HTTP status fields, structured error objects and warning/error domains; record ordinary MCP forwarding separately as activity. A bare digit sequence such as `.502` inside a timestamp is not an HTTP status.
4. Run one adjacent small typed read-only call to see whether the transport path is still failing.

Retry policy:

- Read-only work may be retried once, but only as smaller typed or single-purpose calls.
- Mutating work must not be retried after a transport failure until the target state is re-read.
- A successful retry does not prove the first failure was harmless. Keep or record the friction event when it changed the operator path.
- Do not loop on the same broad command. Split, narrow, or stop and document.

`grabowski_friction_summary` includes `connector_transport_diagnostics`. This is diagnostic guidance only. It does not prove root cause, command success, safe mutation retry, connector vendor repair or transport reliability.

`grabowski_connector_transport_diagnostics` turns the same guidance into a bounded read-only diagnostic receipt. It reads recent friction events, `grabowski_status`, fixed user-service status for `grabowski-operator.service` and `tunnel-client-grabowski.service`, and JSON journal records from bounded recent samples. Schema version 3 separates normal `activity_counts`, genuine `transport_error_count` and `planned_lifecycle_issue_count`. A cleanup issue is classified as planned lifecycle only when its exact known shutdown message, expected component, complete, timestamp-ordered `OnStop hook executing`/`executed` sequence and process invocation are bound to the same later successful systemd stop record through `MESSAGE_ID`, `USER_UNIT`, `USER_INVOCATION_ID`, `JOB_TYPE=stop` and `JOB_RESULT=done`. Missing, mismatched or failed stop evidence remains a transport error.

For genuine errors, `window_state` distinguishes `no_errors`, `errors_without_later_activity` and `errors_followed_by_activity`; an output-truncated journal is reported as `indeterminate_truncated`; failed, timed-out or partially unparsable probes are `indeterminate_incomplete`. Neither state can establish absence of errors or later recovery. `post_error_activity_counts` shows bounded forwarding or control-plane acknowledgements after the last error. This is recovery evidence, not proof that the earlier error was harmless or that the transport is currently reliable. The compatibility field `live_transport_errors_observed` therefore means only that an error exists in the bounded journal window; its explicit semantics field prevents interpreting it as current-outage proof. HTTP codes still come only from explicit structured fields or explicit status syntax. Samples contain only bounded timestamp, invocation, level, component, status and error-domain fields; raw log messages are not returned. This remains diagnostic evidence only and does not authorize retry, mutation, merge, deploy or policy exceptions.

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

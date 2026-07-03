# Agent Run Events Runbook

Status: experimental
Scope: optional Grabowski task lifecycle events for Chronik

## These / Antithese / Synthese

**These:** Grabowski can now write `agent.run.*` events into a local Chronik-compatible outbox.

**Antithese:** Enabling this globally would turn a useful observation seam into quiet infrastructure coupling.

**Synthese:** Use the writer only as an explicit opt-in experiment. Keep it local, reversible, and off by default.

## Preconditions

Before any activation experiment:

- Runtime identity is healthy.
- `grabowski_chronik` is present in the deployed runtime source set.
- `tests.test_chronik_agent_outbox` passes as a direct unittest module.
- Chronik demo view can read a generated event.
- The production writer switch is not set in the user manager environment.

## Switches

The writer is off unless this variable is set to a truthy value:

```text
GRABOWSKI_CHRONIK_AGENT_RUN_OUTBOX=1
```

Optional temporary state root:

```text
GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT=/tmp/grabowski-chronik-smoke
```

If no state root is given, events use the normal Grabowski state root. Do not use the normal state root for smoke tests.

## Activation model

The global environment switches are still available for isolated writer smoke tests, but they are not the preferred path for real tasks. A real `grabowski_task_start` smoke should use task-local opt-in parameters so the writer decision is persisted with the task record and does not depend on service-level environment.

Use these task parameters for a real smoke:

```text
chronik_outbox=True
chronik_outbox_state_root=/tmp/grabowski-chronik-smoke
```

The state root is accepted only when `chronik_outbox` is true. This prevents accidental path configuration without activation.

## Safe temporary smoke

Use a temporary state root and the deployed runtime interpreter.

```bash
tmp=$(mktemp -d)
release="$HOME/.local/share/grabowski-mcp"
GRABOWSKI_CHRONIK_AGENT_RUN_OUTBOX=1 \
GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT="$tmp" \
"$release/.venv/bin/python" -c 'import grabowski_chronik as c; r=c.record_task_state_safely({"task_id":"dddddddddddddddddddddddd","unit":"u","attempt":1}, "completed"); print(r)'
find "$tmp" -name '*.jsonl' -print
rm -rf "$tmp"
```

Expected result:

- one JSONL file exists in the temporary root
- event kind is `agent.run.completed`
- no files are written to the normal production outbox

## Demo-view check

A generated event must be readable by Chronik's demo view.

```bash
/home/alex/repos/chronik/.venv/bin/python -c 'import sys; sys.path.insert(0,"/home/alex/repos/chronik"); import grabowski_chronik as c; from tools import agent_ledger_view as v; e=c.build_event({"task_id":"eeeeeeeeeeeeeeeeeeeeeeee","unit":"u","attempt":1}, "completed"); rows=v.build_view([e]); print(len(rows), rows[0].repo, rows[0].result)'
```

Expected result:

```text
1 heimgewebe/grabowski completed
```

## Production non-activation check

Check that the switch is not globally exported for user services:

```bash
systemctl --user show-environment | sed -n '/GRABOWSKI_CHRONIK/p'
```

Expected result: no output.

Check that the default outbox is still empty unless a deliberate experiment has just run:

```bash
find "$HOME/.local/state/grabowski/chronik-outbox" -type f -name '*.jsonl' 2>/dev/null | wc -l
```

Expected result for normal operation: `0`.

## Explicit non-goals

This runbook does not authorize:

- permanent user-manager environment changes
- systemd drop-ins that turn the writer on by default
- automatic flush to Chronik
- Bureau task creation from events
- Leitstand, semantAH, heimlern, or hausKI consumers
- additional event kinds outside `agent.run.started`, `agent.run.completed`, and `agent.run.blocked`

## Escalation rule

A real `grabowski_task_start` activation smoke is allowed only with `chronik_outbox=True` and a temporary `chronik_outbox_state_root`. Do not use service-level environment for this smoke unless the task-local seam is broken and the service-level path has its own explicit revert plan.

## Exit criteria

Stop the experiment if any of these happen:

- event writing blocks a task state change
- event payload includes raw logs, prompts, or tool outputs
- more than one file is written for the same task attempt without a clear reason
- the demo view cannot read the event
- the switch remains globally enabled after the test

## Current decision

Default state remains off. The writer is a diagnostic seam, not a dependency.

# Agent Run Events Runbook

Status: experimental
Scope: optional Grabowski task lifecycle events for Chronik

## These / Antithese / Synthese

**These:** Grabowski can now write `agent.run.*` events into a local Chronik-compatible outbox.

**Antithese:** Enabling this globally would turn a useful observation seam into quiet infrastructure coupling.

**Synthese:** Use the writer as an explicit, local observation seam. Target identity comes from canonical task resource claims, never from parsing argv or logs.

## Preconditions

Before any activation experiment:

- Runtime identity is healthy.
- `grabowski_chronik` is present in the deployed runtime source set.
- `tests.test_chronik_agent_outbox` passes as a direct unittest module.
- The Chronik checkout used for the demo contains the merged scoped-event contract from `heimgewebe/chronik#219`; a stale feature checkout is not valid proof.
- Chronik demo view can read a generated repository-scoped event.
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
chronik_operation=implement
chronik_component=task-runner
chronik_bureau_task_id=CCM-V1-T002
chronik_pr_number=306
```

The state root is accepted only when `chronik_outbox` is true. This prevents accidental path configuration without activation.

## Target identity and privacy

For a local task with exactly one canonical `repo:/absolute/path` resource claim, Grabowski reads that repository's `origin` URL and records a repository-scoped subject only when it resolves to a bounded `heimgewebe/<repo>` identity. Otherwise the subject is explicitly host-scoped. Multiple claims, foreign remotes, missing remotes and remote-host tasks never fabricate a repository.

Every new event carries bounded `operation` and `task_class` fields. `chronik_operation` accepts only `implement`, `review`, `merge`, `deploy`, `runtime_verify`, `recovery` or `other`; the task class is derived deterministically from that value. When the caller knows them, `chronik_component`, `chronik_bureau_task_id` and `chronik_pr_number` add bounded target-component, Bureau-task and pull-request references to the persisted subject. These references are accepted only with an enabled task-local outbox; the PR number must be a positive bounded integer. Non-`other` operations also require an enabled task-local outbox. Events never contain raw argv, cwd, environment variables, secrets or private filesystem paths.

Event payloads are deterministic for one persisted task transition. `agent.run.started` uses the task creation timestamp; terminal events use the terminalization timestamp, falling back to the persisted update timestamp for legacy rows. The `event_id` is the SHA-256 of the complete canonical payload without the ID itself. Re-emitting the same transition therefore recreates byte-identical evidence, while changed timestamps, subjects or data receive a different ID. An existing ID with different payload fails closed.

## Safe temporary smoke

Use a temporary state root and the deployed runtime interpreter.

```bash
tmp=$(mktemp -d)
release="$HOME/.local/share/grabowski-mcp"
GRABOWSKI_CHRONIK_AGENT_RUN_OUTBOX=1 \
GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT="$tmp" \
"$release/.venv/bin/python" -c 'import grabowski_chronik as c; r=c.record_task_state_safely({"task_id":"dddddddddddddddddddddddd","unit":"u","attempt":1,"created_at_unix":1700000000,"updated_at_unix":1700000100,"terminalized_at_unix":1700000200}, "completed"); print(r)'
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
/home/alex/repos/chronik/.venv/bin/python -c 'import sys; sys.path.insert(0,"/home/alex/.local/share/grabowski-mcp/inputs/src"); sys.path.insert(0,"/home/alex/repos/chronik"); import grabowski_chronik as c; from tools import agent_ledger_view as v; e=c.build_event({"task_id":"eeeeeeeeeeeeeeeeeeeeeeee","unit":"u","attempt":1,"created_at_unix":1700000000,"updated_at_unix":1700000100,"terminalized_at_unix":1700000200,"chronik_context_json":{"subject_scope":"repository","repo":"heimgewebe/chronik","operation":"implement","task_class":"coding"}}, "completed"); rows=v.build_view([e]); print(len(rows), rows[0].repo, rows[0].result)'
```

Expected result for this explicit repository-scoped demo: `1 heimgewebe/chronik completed`. Host-scoped events remain valid for import but are not rendered by this legacy repo-only demo view.

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
- event payload includes raw logs, prompts, argv, cwd, environment values or tool outputs
- more than one file is written for the same task attempt without a clear reason
- the demo view cannot read the event
- the switch remains globally enabled after the test

## Current decision

Default state remains off. The writer is a diagnostic seam, not a dependency.

## Explicit coding-memory import and history

The task-local `chronik_context_json` remains the persisted context truth. It is derived by `grabowski_task_start` from canonical resource claims plus `chronik_operation` and the optional bounded `chronik_component`, `chronik_bureau_task_id` and `chronik_pr_number` fields; callers do not provide a second context object or migration-only compatibility field.

Two typed tools expose the optional local coding-memory seam:

- `grabowski_chronik_outbox_import(path)` imports exactly one existing `grabowski_*.jsonl` directly below `chronik-outbox`. The source must contain only hash-valid, redacted `agent-run-event.v0` records from Grabowski. The adapter calls Chronik's existing positional `import INPUT` command, verifies that the source identity is unchanged afterwards, and returns a SHA-256-bound receipt. Re-import is delegated to Chronik's idempotent event-ID contract; the source is never deleted or compacted by this tool.
- `grabowski_chronik_history(...)` calls Chronik's bounded `query` command for exactly one repository or host target. The adapter verifies that Chronik's returned query envelope is exactly bound to the requested repository/host and filters before exposing events. Every response is historical-only and explicitly does not establish current Git state, current CI state, current runtime state, or safe retry.

The optional checkout and data directory are configured with:

```text
GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT=/home/alex/.local/state
GRABOWSKI_CHRONIK_CODING_MEMORY_REPO=/home/alex/repos/chronik
GRABOWSKI_CHRONIK_CODING_MEMORY_DATA_DIR=/home/alex/.local/state/chronik
```

A missing or stale checkout, missing `tools/coding_memory.py`, invalid CLI output, timeout, or non-zero exit is returned as a bounded unavailable result. These failures do not affect normal task creation, execution, reconciliation, or lifecycle event writing.

# Long-Horizon Trace Producer v1

Status: experimental, opt-in, local evaluation evidence only

## Purpose

This producer binds the long-horizon evaluation contract to one real Grabowski persistent task without inferring monitoring obligations or commitments from prose, prompts, model reasoning, argv text, tool frequency, stdout, stderr, or generic task lifecycle events.

It exists only to create explicit evaluation evidence for `tools/grabowski_long_horizon_eval.py`.

It does not modify task routing, Bureau truth, merge decisions, deployment decisions, or operator policy.

## Opt-in boundary

No trace exists unless an operator explicitly runs:

```text
python3 tools/grabowski_long_horizon_trace.py \
  --state-root /ABSOLUTE/PRIVATE/DIRECTORY \
  open --task-id TASK_ID --retention-mode ephemeral
```

The producer reads one immutable source snapshot from the Grabowski persistent task store at open time. The snapshot contains only:

- task id;
- attempt number;
- task creation timestamp;
- authoritative systemd unit name for that attempt.

It never stores raw argv, an argv digest, cwd, environment, prompts, chain-of-thought, stdout, stderr, secrets, tokens, or passwords.

The resulting `run_id` is deterministic for the task attempt:

```text
grabowski-task:TASK_ID:attempt:N
```

Historical producer output is not current task truth. Later task-state changes do not rewrite the source snapshot.

## Explicit logical steps

Every recorded event supplies an explicit non-negative logical `step`. The producer requires steps to be monotone non-decreasing and never derives them from wall-clock time or tool-call frequency.

This means the caller owns the action-step convention for the experiment. A matched experiment must use the same step convention for control and treatment runs.

Supported record kinds are exactly:

- `monitor.requirement`;
- `monitor.check`;
- `commitment.declared`;
- `commitment.completed`;
- `commitment.abandoned`.

`open` emits `run.started` at step 0. `close` emits `run.terminal` at the explicitly supplied terminal step.

A monitor check is rejected unless its exact monitor id was previously declared. A commitment resolution is rejected unless its exact commitment id was previously declared, and a commitment can be resolved only once.

## Privacy boundary

Monitor ids, commitment ids and evidence refs are bounded opaque tokens. They cannot contain spaces or arbitrary prose.

`commitment.abandoned` does not accept a free-form explanation. Its `reason` must be one of the bounded codes:

- `blocked`;
- `invalidated`;
- `not_needed`;
- `other_explicit`;
- `superseded`;
- `target_changed`.

This records that a decision was explicit without collecting private reasoning.

## Retention

The state root is always supplied explicitly. Two declared modes exist:

- `ephemeral`: caller-selected ephemeral storage, suitable for bounded pilots;
- `operator-managed-local`: local evidence retained until explicit operator cleanup.

v1 performs no hidden automatic deletion. Each trace is nevertheless hard bounded to 512 events and 512 KiB. Session directories and files must be private and owned by the current user.

The retention mode and these bounds are written into `manifest.json`.

## Replay and integrity

Each event is written as canonical JSONL under an exclusive file lock and fsynced before success is returned. Reads bind the path observed before `open()` to the same opened inode and reject identity or content drift. Writes drain the full buffer and reject zero/short progress instead of assuming one `os.write()` call is complete.

An exact canonical event replay is idempotent: it is reported as a replay and is not appended twice. A distinct event is evaluated normally. Invalid ordering, duplicate declarations, events after `run.terminal`, non-canonical persisted records, unsafe path types, or manifest digest drift fail closed.

`close` writes a create-only `closeout.json` bound to:

- manifest SHA-256;
- final trace SHA-256;
- event count;
- terminal step.

## Source authority

`open` resolves the task from Grabowski's persistent task store using a read-only row lookup. The trace therefore establishes that the producer was bound to one recorded Grabowski task attempt and one authoritative unit identity at open time.

It does not establish:

- current task state;
- current Git or CI state;
- safe retry;
- routing authority;
- merge or deployment authority;
- policy authority;
- strategic correctness of an abandonment.

## Example

```text
python3 tools/grabowski_long_horizon_trace.py --state-root /tmp/lh-proof \
  open --task-id 0123456789abcdef01234567 --retention-mode ephemeral

python3 tools/grabowski_long_horizon_trace.py --state-root /tmp/lh-proof \
  record --task-id 0123456789abcdef01234567 --attempt 1 --step 0 \
  --kind monitor.requirement --monitor-id pr-ci-mergeability --cadence-steps 2

python3 tools/grabowski_long_horizon_trace.py --state-root /tmp/lh-proof \
  record --task-id 0123456789abcdef01234567 --attempt 1 --step 1 \
  --kind monitor.check --monitor-id pr-ci-mergeability

python3 tools/grabowski_long_horizon_trace.py --state-root /tmp/lh-proof \
  record --task-id 0123456789abcdef01234567 --attempt 1 --step 1 \
  --kind commitment.declared --commitment-id rerun-focused-tests --horizon-steps 2

python3 tools/grabowski_long_horizon_trace.py --state-root /tmp/lh-proof \
  record --task-id 0123456789abcdef01234567 --attempt 1 --step 2 \
  --kind commitment.completed --commitment-id rerun-focused-tests

python3 tools/grabowski_long_horizon_trace.py --state-root /tmp/lh-proof \
  close --task-id 0123456789abcdef01234567 --attempt 1 --step 3
```

Evaluate the emitted `trace.jsonl` with:

```text
python3 tools/grabowski_long_horizon_eval.py TRACE.jsonl --pretty
```

## Experiment boundary

The producer is not itself a reminder system. It provides measurement only.

A later control/treatment experiment may compare a baseline operator policy with a persistent monitoring/commitment policy, but neither the producer nor evaluator may route work, create tasks, block merges, or promote policy based on the metrics.

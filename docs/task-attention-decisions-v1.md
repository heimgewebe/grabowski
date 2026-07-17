# Task Attention Decisions v1

Status: implemented contract
Date: 2026-07-17

## Purpose

Task state and operator closeout decisions are different truths. The task database and its terminal outcome receipts describe technical execution state. They do not by themselves establish that an operator has closed, deferred, or superseded the corresponding follow-up.

Task Attention Decisions v1 therefore adds append-only decision evidence without rewriting task records or outcome receipts. It is exposed through two grips on the existing `grip_run` surface, so the public MCP tool count does not grow:

- `task-attention-decision` records one create-only decision for the current task attempt;
- `task-attention-reconciliation` classifies one bounded attention-task snapshot from authoritative task, outcome, and decision evidence.

## Decision binding

A decision may be `closed`, `deferred`, or `superseded`. The mutating grip requires the caller to bind:

- exact `task_id` and current positive attempt;
- both task unit and authoritative unit;
- task `argv_sha256` and optional execution-envelope SHA-256;
- the valid current terminal outcome receipt SHA-256;
- one bounded named authority;
- one bounded evidence reference.

The server re-reads the current task, validates the terminal outcome receipt descriptor-first, compares all bindings, and re-reads the task before publication. Only technical attention outcomes `failed`, `timed_out`, and `signalled` are decision-eligible. `interrupted` and `outcome_unknown` cannot be converted into a closeout decision because no valid terminal outcome is established.

The decision record additionally binds the byte-level SHA-256 of the outcome receipt file, its own deterministic material SHA-256, and a self-hash. Publication is create-only. An identical replay is idempotent; different material for the same task attempt is a conflict and never replaces the winner.

## Private-file contract

Outcome and decision records are read with `O_NOFOLLOW` when available and must be owner-held, mode `0600`, singly linked regular files within the byte limit. State directories must be exact owner-held mode-`0700` directories. Publication uses the shared descriptor-bound create-only private JSON primitive under a private lock.

A symlink, unsafe mode, owner drift, hardlink, oversized file, malformed JSON, changed inode metadata, invalid schema, bad self-hash, stale task binding, or missing receipt fails closed. The implementation never rewrites task or outcome records.

## Reconciliation semantics

The read-only reconciliation grip opens one bounded task-database read snapshot and keyset-paginates the existing `attention` state projection. It performs no systemd or Fleet observation, no task refresh, no retry, and no mutation.

Each returned record receives exactly one conservative classification:

- `actionable`: technical attention exists and no valid decision closes it;
- `outcome_unknown`: the execution result remains unknown;
- `decision_closed`, `decision_deferred`, or `decision_superseded`: a valid current-attempt decision and outcome binding exists;
- `invalid_evidence`: a required outcome or decision artifact is missing, unsafe, malformed, contradictory, or stale.

Classification counts apply only to the returned page. `total_attention` is the exact count in the same database snapshot. Cursor order is `created_at_unix DESC, task_id DESC`.

## Non-claims

This contract does not establish:

- task output correctness;
- automatic retry safety;
- closeout without a valid current terminal outcome receipt;
- completion of later attempts;
- current systemd or Fleet post-state;
- task or outcome-receipt mutation;
- business authority beyond the named authority and evidence reference stored in the decision.

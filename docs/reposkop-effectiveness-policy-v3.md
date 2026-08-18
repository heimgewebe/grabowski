# Reposkop effectiveness policy v3

## Why v3 exists

The first fully reviewed production cohort contained 38 Reposkop decisions: 37 were classified `neutral` and one as `operational_failure`; none was classified `confirmed_prevention`, `beneficial_context`, `false_positive` or `false_negative`. That evidence is not proof that Reposkop has no value, but it is insufficient justification for running it synchronously on every local writer.

Policy v3 therefore changes the question from “did Reposkop run?” to “when does Reposkop change an outcome enough to justify its cost?”

## Safety boundary

Reposkop does not replace Grabowski repository work admission. A writer can enter the prospective cohort only after its broad repository lease has independently passed the existing read-only repository admission contract. That admission continues to reject dirty or unobservable target state, foreign live coordination, ambiguous lifecycle ownership and blocking reconciliation evidence.

The control arm is additionally limited to a real Git commit on a named non-default branch. `main`, `master`, detached/unversioned workspaces, exact-path-only writers and explicit `repository_write` tasks remain Reposkop-required. If the independent admission evidence is missing or malformed, the writer remains in the required cohort.

## Prospective cohorts

Eligible `workspace_write` starts are assigned deterministically from the server-generated task identity. The assignment is hash-bound and recorded without exposing a new caller-controlled selection surface.

- bucket `0` of modulus `4`: `prospective_sample`; Reposkop remains required and fail-closed before launch.
- buckets `1`–`3`: `prospective_control`; the independent repository admission is retained, decision-path Reposkop execution is skipped, and the skip is recorded as an explicit decision rather than pretending an evaluation ran.
- non-eligible workspace writers: `risk_required`.
- explicit repository-wide writers: `repository_write_required`.

A control decision carries an evaluation identity, cohort/sampling evidence, the digest of the admission evidence and a lightweight execution binding. Terminal task outcomes therefore remain correlatable with the control decision.

Independently of that decision path, eligible local repository writers have a best-effort checkout-continuity shadow. It records a purpose-bound canonical Reposkop BEFORE observation before launch. When the task terminalizes, Grabowski asks Reposkop for the canonical continuity artifact while the task still owns its workspace leases and persists that artifact create-only; only then may authoritative terminalization revoke those leases. After terminalization, the prepared artifact hash is bound to the authoritative terminalization and lifecycle receipt. This applies to both prospective sample and control cohorts. Shadow failure is recorded as unavailable but never changes task start, terminal state, leases, resume authority, publication, merge, deployment or recovery. The private evidence is hash-bound; public audit contains only bounded identifiers, artifact digests, canonical state/reason/anomaly codes and `decision_effect=false`.

## Review and measurement

A prospective control may later be reviewed as `neutral`, `false_negative`, `unresolved` or `confirmed_unique_value`. It cannot be labelled `confirmed_prevention`, `beneficial_context`, `false_positive` or `operational_failure`, because no decision-path Reposkop execution occurred in that arm. `confirmed_unique_value` is an explicit later semantic review classification that requires correlated completed identity-break shadow evidence; an `identity_break` never assigns the classification automatically.

The effectiveness projection includes sample/control counts, reviewed controls, control false negatives, control terminal outcomes and confirmed preventions in the sample arm. It separately reports checkout shadow attempts, completions, unavailable captures, canonical continuity states, measurement classes and manually reviewed `confirmed_unique_value` cases. Existing required-attestation coverage remains a separate metric; skipping decision-path Reposkop under the explicit control contract is not counted as a missing required attestation.

The experiment does not establish causality by itself. A later policy change should be based on correlated reviews and enough observations to compare concrete prevention/false-negative evidence and runtime cost, not merely task success rates.

## Durable cohort projection

The effectiveness projection no longer depends on the newest raw audit window. Reposkop-relevant audit records are copied into a private SQLite derivation only after they have been read from a verified audit snapshot. The index checkpoint is bound to the exact global audit ordinal and record digest. Each public effectiveness call advances that checkpoint by at most the requested `limit` verified audit records; it never performs an unbounded catch-up to the current tail. Audit segment rotation is harmless as long as the verified logical chain still contains the checkpoint record.

While a cold, repaired or lagging index has not reached the verified tail, the projection reports `index_complete=false`, `evaluation_status=incomplete_audit_catchup`, `scan_truncated=true` and the remaining record count. The public source provenance exposes both `indexed_through_global_ordinal` and the exact `checkpoint_audit_ref`; before any checkpoint record exists the latter is explicitly `null`. Metrics may be shown as bounded partial observations, but the response explicitly does not establish a complete effectiveness evaluation. Repeated bounded calls advance the same checkpoint. Once it reaches the tail, an immediate unchanged follow-up performs zero incremental audit-record scans.

The index is not a second authority. Every cached row retains its audit reference and a local payload-integrity digest. For modern audit records, cache reads recompute Grabowski's canonical record hash and require it to match both the embedded `record_sha256` and the audit reference. Legacy records without that embedded binding are compared with the exact record at the same global ordinal in the verified snapshot. Checkpoint drift, a missing cached row, payload tampering or coherent `record_json` plus local-hash tampering causes the derivation to be discarded and rebuilt only within the same call's remaining scan budget; if that budget is exhausted, the projection stays explicitly incomplete. Structural SQLite corruption still fails closed.

Steady-state storage is bounded to the newest 100,000 Reposkop-relevant records, not the newest 100,000 arbitrary audit events. When that retention bound eventually drops relevant history, the projection exposes `retention_truncated`, `dropped_records`, `dropped_max_timestamp_unix` and `since_truncated`; it does not silently claim complete history. `since_unix` continues to filter the retained verified cohort and distinguishes a requested window that is still fully covered from one intersecting discarded history. Dropped relevant records without `timestamp_unix` keep that coverage fail-closed via `dropped_unknown_timestamps` and force `since_truncated=true`. Physical catch-up work is exposed as `incremental_scanned_records`.

This design lets sparse real sample/control decisions, semantic reviews and measured Reposkop durations survive high unrelated audit throughput long enough to reach the existing statistical gates, including the minimum of 60 real duration samples for p95-regression evaluation. It does not synthesize workload or evidence.

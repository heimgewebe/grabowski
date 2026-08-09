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

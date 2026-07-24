# Operator recall boundary

`grabowski_operator_recall_export` is a read-only export surface for derived operator recall records. It builds bounded recall items from caller-supplied source records for receipts, pull requests, Bureau tasks and friction records.

The export requires concrete evidence references, but this slice does not verify source authenticity, current GitHub truth, Bureau truth, receipt freshness or friction-log freshness. The top-level export therefore reports `source_trust=caller_supplied_unverified` and `evidence_binding=requires_concrete_ref_but_does_not_verify_source`.

Recall items are not free chat memory. Each item must have a topic, situation, attempt, result, learned rule and at least one evidence reference. `free_form_chat_memory` and `policy_oracle` remain explicit non-claims.

`learned_rule` is a caller-supplied, unverified hint. Consumers must preserve `learned_rule_trust`, `source_trust`, `evidence_binding` and `does_not_establish` before using recall exports. A learned rule does not grant policy change, operator instruction authority, merge authority, task completion or routing authority.

The export does not establish root cause, task completion, merge readiness, source record completeness, evidence authenticity, source record authenticity or current truth. Unsupported source keys are surfaced for operator debugging rather than silently becoming recall.

Recall text fields reject ASCII control characters and are intended to be bounded single-line records. Multiline source text must be normalized by the caller before export.

Heimlern use is `offline_proposal_only`. Recall exports may be consumed later for offline learning proposals, but this tool does not change live routing, merge policy, Bureau state or task completion.

## Chronik-backed historical recall

`grabowski_operator_historical_recall` is the canonical read-only operator surface for historical coding outcomes stored in Chronik. It calls the validated `grabowski_chronik_history` provider internally and converts only hash-bound Chronik events into bounded evidence-ref-bound recall items.

The direct `grabowski_chronik_history` tool remains a lower-level provider and diagnostic surface. Normal operator consumers should prefer `grabowski_operator_historical_recall` so Chronik history is not treated as a separate control plane.

Chronik-backed recall reports `source_trust=grabowski_validated_chronik_history`, `evidence_binding=hash_bound_chronik_event` and `historical_only=true`. Its learned-rule field is explicitly `historical_observation_not_rule`: it summarizes an observed historical outcome and does not create policy or operator instruction authority.

Historical recall never establishes current Git state, CI state, runtime state, safe retry, merge readiness, task completion, routing authority or policy authority. Any effect still requires fresh live preflight evidence and the normal current authorization gates.

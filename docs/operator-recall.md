# Operator recall boundary

`grabowski_operator_recall_export` is a read-only export surface for derived operator recall records. It builds bounded recall items from caller-supplied source records for receipts, pull requests, Bureau tasks and friction records.

The export requires concrete evidence references, but this slice does not verify source authenticity, current GitHub truth, Bureau truth, receipt freshness or friction-log freshness. The top-level export therefore reports `source_trust=caller_supplied_unverified` and `evidence_binding=requires_concrete_ref_but_does_not_verify_source`.

Recall items are not free chat memory. Each item must have a topic, situation, attempt, result, learned rule and at least one evidence reference. `free_form_chat_memory` and `policy_oracle` remain explicit non-claims.

The export does not establish root cause, task completion, merge readiness, source record completeness, evidence authenticity, source record authenticity or current truth. Unsupported source keys are surfaced for operator debugging rather than silently becoming recall.

Heimlern use is `offline_proposal_only`. Recall exports may be consumed later for offline learning proposals, but this tool does not change live routing, merge policy, Bureau state or task completion.

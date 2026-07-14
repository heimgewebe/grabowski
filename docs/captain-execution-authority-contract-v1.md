# Captain execution authority contract v1

This contract separates Captain authority terms that were previously easy to blur in receipts and operator discussion.

Runtime source of truth: `src/grabowski_grips.py::_captain_authority_contract`. The generated output also exposes `required_gates` from `CAPTAIN_GATE_IDS` and `executable_action_allowlist` from `CAPTAIN_EXECUTABLE_ACTIONS` to reduce drift.

## Terms

- **Evaluation authority** means permission to evaluate Captain evidence gates and emit a receipt. `captain-preflight` has only this authority and never mutates.
- **Execution authority** is one explicit prerequisite for an implemented `captain-run` executor. In the v1 JSON contract the evidence field is still named `execution_authority`, but that field is never sufficient by itself.
- **Execution intent** is a fresh structured `execution_intent` object that `captain-run` requires before any executor call. It binds the single requested action name, the canonical target digest (`target_sha256`), the lowercase `expected_head`, the action-specific `expected_base` (PR base branch for `pr-merge`; bound `environment`/`runtime_target` for `runtime-deploy`), the decisive evidence digests plus a deterministic `authorization_sha256` over execution authority, human authorization and trusted-owner policy state (`actions_sha256`, `status_projection_sha256`, `diff_sha256`, `review_evidence_sha256`, `ci_evidence_sha256`, `authorization_sha256`), a non-empty `actor` object with an `id`, a non-empty `context` object, and a timezone-aware `issued_at` UTC timestamp that must be at most 600 seconds old and at most 120 seconds in the future. `captain-preflight` does not require an intent because it never executes.

## Release conditions

`captain-run` may invoke an implemented executor only when all of the following are true:

1. `allow_execution=true` is present.
2. The same Captain evidence gates pass.
3. Exactly one action is requested.
4. The action is present in `executable_action_allowlist`.
5. Target, expected head, reviewed diff, CI, review evidence, status projection and authorization evidence remain bound.
6. A fresh `execution_intent` binds the action, canonical target digest, expected head, expected base and decisive evidence digests plus a deterministic `authorization_sha256` over execution authority, human authorization and trusted-owner policy state. Missing, malformed, non-canonical, stale, future-dated or drifting intents block fail-closed before any GitHub or deployment runner is invoked.
7. The executor performs target-specific preflight and post-execution verification.

## Non-claims

This contract does not make merge, deploy, restart, fleet mutation or cleanup default. The executable allowlist currently contains `pr-merge` and `runtime-deploy`; runtime deployment is further restricted to the registered `grabowski-self` adapter, and a successful scheduling receipt does not claim deployment completion. Under the exact trusted-owner autonomy policy, a reversible self-deploy may be scheduled without a separate human-authorization object after all review, diff, CI, status, target, scope and recovery gates pass. Identical in-flight schedules are serialized and reused rather than duplicated. It does not allow `allow_execution`, `execution_authority` evidence or a valid `execution_intent` to bypass gates; each is one necessary condition and none is sufficient alone. Trusted-owner autonomy remains limited to reversible, target-bound actions with implemented executors, still requires a fresh `execution_intent`, and still fails closed for ambiguous or irreversible actions. Receipts never echo raw `execution_intent`, actor or context values: they carry only fixed error codes, normalized verified fields and digests (`intent_sha256`, `actor_sha256`, `context_sha256`, evidence digests), and each per-action Captain receipt binds `execution_intent_sha256` when an intent was presented.

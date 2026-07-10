# Captain execution authority contract v1

This contract separates Captain authority terms that were previously easy to blur in receipts and operator discussion.

Runtime source of truth: `src/grabowski_grips.py::_captain_authority_contract`. The generated output also exposes `required_gates` from `CAPTAIN_GATE_IDS` and `executable_action_allowlist` from `CAPTAIN_EXECUTABLE_ACTIONS` to reduce drift.

## Terms

- **Evaluation authority** means permission to evaluate Captain evidence gates and emit a receipt. `captain-preflight` has only this authority and never mutates.
- **Execution authority** is one explicit prerequisite for an implemented `captain-run` executor. In the v1 JSON contract the evidence field is still named `execution_authority`, but that field is never sufficient by itself.

## Release conditions

`captain-run` may invoke an implemented executor only when all of the following are true:

1. `allow_execution=true` is present.
2. The same Captain evidence gates pass.
3. Exactly one action is requested.
4. The action is present in `executable_action_allowlist`.
5. Target, expected head, reviewed diff, CI, review evidence, status projection and authorization evidence remain bound.
6. The executor performs target-specific preflight and post-execution verification.

## Non-claims

This contract does not make merge, deploy, restart, fleet mutation or cleanup default. The executable allowlist currently contains `pr-merge` and `runtime-deploy`; runtime deployment is further restricted to the registered `grabowski-self` adapter, and a successful scheduling receipt does not claim deployment completion. Under the exact trusted-owner autonomy policy, a reversible self-deploy may be scheduled without a separate human-authorization object after all review, diff, CI, status, target, scope and recovery gates pass. Identical in-flight schedules are serialized and reused rather than duplicated. It does not allow `allow_execution` or `execution_authority` evidence to bypass gates. Trusted-owner autonomy remains limited to reversible, target-bound actions with implemented executors and still fails closed for ambiguous or irreversible actions.

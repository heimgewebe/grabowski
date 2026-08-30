# Operator Sagas v1

Status: implementation merged; live acceptance is receipt-bound and must not be inferred from this document alone.

## Decision

`decision = implement`

The live frequency sample justifies two named saga families:

- **PR settlement**: 81 `heimgewebe/grabowski` pull requests merged in the trailing 7 days and 13 in the trailing 24 hours at the 2026-08-21 observation.
- **Runtime deployment**: the verified Grabowski audit chain contains 62 `runtime-deploy-schedule-intent` and 62 matching `runtime-deploy-scheduled` records in the trailing 7 days; the trailing 24 hours contain 7/7. Existing-schedule observations are counted separately and do not inflate the scheduled total.

These are repeated operator sequences rather than hypothetical conveniences. Bureau pickup can participate in PR preparation when an exact run is supplied, but its observed frequency is not used as a primary pilot-selection claim.

## Contract

Every saga has exactly five explicit phases:

1. **Prepare** — normal read-only or ordinary Mechanic grips.
2. **Plan** — bind saga kind, target, scope, expected identities and idempotency key to `OperatorSagaPlan.v1`.
3. **Apply** — external `captain-run` handoff for exactly one high-impact action.
4. **Readback** — target-specific typed live observation.
5. **Settle** — read-only reconciliation of the exact plan, run receipt, Captain receipt and readback.

The saga is deliberately **not** a cross-system transaction. A successful Prepare does not imply Apply. A successful Captain scheduling receipt does not imply a converged runtime. No later phase retroactively changes an earlier effect.

### Stable receipts

- `OperatorSagaPlan.v1` binds the normalized target, phase order, Mechanic actions, Captain handoff, readback contract and retry contract.
- `OperatorSagaRunReceipt.v1` binds the exact plan hash, Mechanic plan hash, outer Mechanic receipt, every executed child receipt and the Captain handoff.
- `VerifiedCaptainAuditBinding.v1` binds one real server-side Captain intent/completion pair from the verified Grabowski audit chain to the saga target, expected revision, Captain receipt and Captain output.
- `OperatorSagaSettlementReceipt.v1` binds the plan, run, verified Captain audit binding, exact Captain receipt and typed readback.

Receipt hashes are recomputed before trust. An embedded grip result whose receipt digest, output digest, top-level digest or status disagrees is rejected.

The runtime implementation lives in the already deployed `grabowski_grip_orchestration` source set. `grabowski_sagas.py` is a source/test compatibility re-export only; `grabowski_grips` does not import it at runtime. This avoids creating a new deployment-source dependency and keeps concurrent runtime-entrypoint work isolated.

A self-consistent caller-supplied Captain JSON object is **not** sufficient settlement evidence. `saga-settle` requires the exact `captain-run-audit-intent` and `captain-run-audit-completion` records that the server emitted for the real Captain call. It reads both records from one verified immutable audit snapshot, checks their hash-chain identities, actor/context/request continuity and exact action/target/head/base/receipt/output/status bindings, then derives `VerifiedCaptainAuditBinding.v1`. A missing or mismatching audit record fails closed.

The audit lookup is intentionally bounded to the newest 100,000 verified records. If a Captain result is so old that its records are outside that window, the saga does not infer authenticity and does not gain retry authority; the caller must obtain fresh authoritative evidence or use the normal recovery path.

## Saga: PR settlement

### Prepare

If `bureau_run_id` is provided:

- `bureau-pickup-status` for the exact run.

Always:

- `pr-check-readiness` for the exact repository checkout.

These are executed through `mechanic-loop`. `saga-run` validates that the child set is an exact ordered prefix of the planned actions and that returned target/scope/receipt bindings match the plan. It cannot dispatch `captain-run`.

### Apply boundary

The returned handoff names only:

- profile: `captain`
- grip: `captain-run`
- action: `pr-merge`
- exact repository, PR, base branch and optional merge method

The existing Captain contract still owns current base/head, diff, review, CI, status projection, lease delegation, merge-method and execution-intent gates. The saga does not mint any of those evidences or permissions.

### Readback and Settle

A terminal PR settlement requires live readback with all of:

- `state == MERGED`
- exact `headRefOid`
- exact `baseRefName`
- exact PR number
- a valid merge commit SHA

Missing or drifting identity produces `recovery_required`; it does not authorize a second merge attempt.

## Saga: Runtime deployment

### Prepare

- `runtime-deploy-check` for the registered `grabowski-self` adapter, `heimgewebe/grabowski`, target `heim-pc` and exact expected head.

The optional source repository and source lease owner must be supplied together and remain bound through the normal runtime-deploy contract.

### Apply boundary

The handoff names only `captain-run: runtime-deploy`. Captain remains the only high-impact executor. `saga-run` is structurally unable to call the Captain executor.

A successful Captain deploy action can legitimately mean **scheduled**, not complete.

### Readback and Settle

The typed deployment-identity readback is terminal only when:

- `identity.repo_head` equals the exact expected head;
- `identity.completion_status == complete`;
- the `integrity` object is non-empty and every reported integrity predicate is exactly `true`;
- the serving process matches the deployed manifest;
- the serving process serves that deployed release.

If the runtime still reports another head, settlement is `readback_pending`. Only the read-only deployment identity readback and `saga-settle` may be repeated. An integrity or serving mismatch is `recovery_required`.

## Failure truth

The public states are intentionally small and machine-readable:

- `captain_required` — Prepare passed; a fresh Captain decision/effect is still required.
- `prepare_blocked` — a planned normal step did not pass; no Captain handoff is usable.
- `apply_blocked` — Captain did not invoke the high-impact effect.
- `readback_pending` — Captain verified scheduling/execution in its scope, but the target has not yet converged.
- `recovery_required` — an effect may have happened or post-effect truth disagrees; perform authoritative readback/repair and never blind-retry Captain.
- `settled` — exact target readback agrees with the plan, verified Captain receipt and verified Captain audit binding.

No state called `outcome_unknown` is hidden inside success. An invoked-but-unverified Captain action maps to `recovery_required`.

## Authority preservation

`mechanic-loop` remains the ordinary-action composition primitive. `captain-run` remains the high-impact authority boundary. The saga layer:

- does not expose shell command composition;
- does not call Captain from `saga-run`;
- does not accept unauthenticated Captain JSON as effect evidence;
- does not weaken review, CI, merge, deployment, lease, recovery or kill-switch gates;
- does not infer merge/deploy permission from frequency data;
- does not convert a scheduled deployment into a completion claim;
- does not add an independently mutable state store.

## Public grip surface

- `saga-plan` — read-only immutable plan construction.
- `saga-run` — bounded Mechanic preparation; mutating only because it composes the standard `mechanic-loop`, though the two v1 pilots use read-only children.
- `saga-settle` — read-only settlement from receipt-bound evidence plus the verified server Captain audit chain.

`saga-plan` and `saga-settle` are observer-visible. `saga-run` requires an operator/captain mutation-capable profile. Captain-only grips remain unavailable to operator and observer profiles.

## Pilots and measurement

Focused unit and grip integration tests are required before publication. Bureau acceptance additionally requires two live end-to-end pilots after the implementation has landed:

1. use the PR-settlement saga to prepare a necessary T121 closeout PR, execute the existing Captain merge under its normal gates, read GitHub back, verify the Captain intent/completion pair from the audit chain, and settle the exact merge;
2. use the runtime-deployment saga for the resulting merge commit, execute the existing Captain deploy under its normal gates, read `grabowski_deployment_identity` until exact convergence, verify the Captain audit pair, and settle the deployment.

This ordering avoids replaying historical high-impact effects solely for testing. Live pilot receipts, before/after call counts, operator decisions, blocks, partial failures and elapsed times belong to the T121 closeout evidence and must be revision-bound to the final implementation head.

### Live acceptance checkpoint — 2026-08-22

The first real PR-settlement attempt exposed a Prepare-contract defect before any Captain effect: `saga-plan` could include `bureau-pickup-status`, while `mechanic-loop` did not admit that read-only child, and the resulting Mechanic preflight block was projected as a hard Saga error instead of `prepare_blocked`.

PR #890 repaired that contract, added the corresponding regression coverage, and was merged only after exact-head validation, Captain gates and authoritative GitHub readback. The repair is a bootstrap prerequisite, not a substitute for the two required end-to-end Saga pilots. Pilot settlement and measured-effect evidence remain external, receipt-bound acceptance evidence so this repository document cannot claim success merely by being merged.

### Live acceptance execution — 2026-08-27

PR #962 merged the staging documentation as protected commit `fd3b130ad967898586605f94f3e2dbc840fc8b0e`, but a fresh bounded receipt readback after that merge found no `OperatorSagaPlan.v1`, `OperatorSagaRunReceipt.v1`, or `OperatorSagaSettlementReceipt.v1` evidence for the attempt. PR #962 therefore remains a staging checkpoint and must not be retroactively counted as a live Saga pilot.

The current terminal acceptance attempt is bound before effect to Bureau run `BUR-RUN-20260827T151132Z-35a64bfe0d`, authoritative T121 TaskSpec digest `633456e6dfa0c2774f4ded0a3da5a38256f0cf0069581278d766701aea9c7db7`, and protected baseline `fd3b130ad967898586605f94f3e2dbc840fc8b0e`. PR #894 remains historical for the same reason: no receipt-bound Saga execution may be inferred from its already completed merge.

The follow-up documentation change carrying this paragraph is the **new** PR-settlement pilot target. Before invoking Captain, execution must produce a fresh `saga-plan` and receipt-bound `saga-run` for the exact PR/head/base identity. Only after the normal Captain merge succeeds may the pilot perform authoritative GitHub readback, verify the Captain audit binding, and require `saga-settle == settled`. Only that settled protected merge commit may become the target of the runtime-deployment pilot.

### Live acceptance continuation — 2026-08-28

The 2026-08-27 attempt is historical execution evidence, not current authority. The current continuation is bound before effect to Bureau run `BUR-RUN-20260828T101305Z-1ee4a63d84`, the unchanged authoritative T121 TaskSpec digest `633456e6dfa0c2774f4ded0a3da5a38256f0cf0069581278d766701aea9c7db7`, and protected baseline `171713083ba40231f0002e4f40589e63d9dfba6c`.

This continuation change is the new PR-settlement pilot target. It claims no pilot success before a fresh `saga-plan`, receipt-bound `saga-run`, normal Captain merge, authoritative GitHub readback and `saga-settle == settled` all agree on the exact PR/head/base identity. Only that settled merge commit may become the runtime-deployment pilot target.

For each pilot, closeout evidence records the real start/end timestamps, top-level operator/Saga calls, caller decisions, prepare/apply/readback blocks, partial failures, terminal state, plan/run/Captain/settlement receipt digests, and the exact target identity. The before/after comparison uses the same target's unbundled required public surfaces as the comparator; no historical call-count estimate is promoted to evidence. The sample remains descriptive and does not by itself authorize policy or further automation changes.

### Terminal live acceptance continuation — 2026-08-28 18:42Z

The earlier 2026-08-28 continuation bound to `BUR-RUN-20260828T101305Z-1ee4a63d84` is now historical execution context, not current authority. The current coordinated Bureau assignment is `BUR-RUN-20260828T184138Z-158e4937ed`, bound to the unchanged authoritative T121 TaskSpec digest `633456e6dfa0c2774f4ded0a3da5a38256f0cf0069581278d766701aea9c7db7` and protected baseline `8bf15e8ec07bd2a4eddfb4b2bf29ce2fd99bfb7e`.

A fresh verified audit query for T121 over the newest 100,000 records returns only Bureau pickup events. A separate bounded scan of the audit material covering the 2026-08-27/28 attempts contains no `OperatorSagaPlan.v1`, `OperatorSagaRunReceipt.v1`, or `OperatorSagaSettlementReceipt.v1` marker. Those earlier attempts therefore remain non-settled and are not promoted to pilot evidence. This absence claim is bounded to the inspected recent audit material; it does not rewrite older history.

This continuation commit is the new PR-settlement pilot target. It must first be published as an exact-head PR. Before any merge effect, the current attempt must create a fresh PR-settlement `saga-plan` and receipt-bound `saga-run` for that exact PR/head/base identity. The existing Captain merge path then remains responsible for review, CI and merge gates. Only an authoritative GitHub readback plus `saga-settle == settled` may establish the PR pilot.

Only the exact merge commit proven by that settlement may become the runtime-deployment pilot target. The deployment pilot must independently produce a fresh deployment `saga-plan`, receipt-bound `saga-run`, normal Captain deployment result, exact deployment-identity readback and `saga-settle == settled`. No staging commit, scheduled deployment or historical receipt is substituted for those proofs.

### Terminal live acceptance continuation — 2026-08-30

PR #980 merged at `2026-08-30T07:27:17Z` with final PR head `eb7702363febb0a9164b06012496dec5cba954b4` as merge commit `30ccbe9b49f794fc4ffe1cbb2062e5d9fbf0dfca`. The pre-merge Saga evidence retained from that attempt was bound to an earlier PR head, not to the final merged head. A fresh read of the verified Grabowski audit material from the merge through this continuation contains neither a `saga-settle` invocation nor the final PR-head/merge identities. PR #980 is therefore historical merge context, not the required settled PR pilot. This absence claim is bounded to the verified audit material inspected for that interval; it does not infer facts outside that evidence window.

This follow-up documentation change is the next PR-settlement pilot target because it records the newly established live truth rather than fabricating a retrospective settlement. Before its merge effect, execution must create a fresh PR-settlement `saga-plan` and receipt-bound `saga-run` for the exact new PR/head/base identity. The existing Captain path must then pass its normal review, CI and merge gates. Only an authoritative GitHub readback plus `saga-settle == settled` may establish pilot 1.

Only the exact merge commit proven by that settlement may become the runtime-deployment pilot target. Pilot 2 must independently create a fresh runtime-deployment `saga-plan` and receipt-bound `saga-run`, execute the existing Captain deployment action, read the deployed identity to exact convergence, verify the Captain audit pair, and require `saga-settle == settled`. No merge, scheduled deployment or historical receipt is promoted to acceptance evidence without those bindings.

## Non-claims

This document does not by itself establish successful live pilots or Bureau acceptance. It also does not establish automatic post-`integration_ready` controller custody. The latter requires a separate bounded-autonomy decision after the Saga primitive is proven; T121 itself preserves the current Captain boundary by design.

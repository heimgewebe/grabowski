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

The Captain-result recovery path accepts only `VerifiedCaptainAuditResultRef.v1` pointing at an exact verified completion record. Resolution scans the verified immutable audit segments backward and may cheaply skip segments that cannot contain the requested record; it is not limited to the newest 100,000 records. The referenced completion and its paired intent must still satisfy the exact Saga binding, otherwise settlement fails closed and gains no retry authority.

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

Only the exact merge commit proven by that settlement may become the runtime-deployment pilot target. Pilot 2 must independently create a fresh runtime-deployment `saga-plan`, receipt-bound `saga-run`, execute the existing Captain deployment action, read the deployed identity to exact convergence, verify the Captain audit pair, and require `saga-settle == settled`. No merge, scheduled deployment or historical receipt is promoted to acceptance evidence without those bindings.

### Final live acceptance reset — 2026-08-31

PR #997 merged as `4dd58cf9ec0320296affcd800375eabaaf0de3f1` and the currently serving Grabowski runtime is on protected `main` head `225bed296d08c87ef557b954059a8de754b1639e`, so the durable Captain-result recovery fix is now active in production. The deployment that established that runtime was a normal `grabowski_runtime_deploy_schedule` execution, not a runtime-deployment Saga, and is not promoted to pilot evidence.

PR #995 remains useful historical effect evidence: its Captain merge and exact verified Captain audit completion are still recoverable. However, the full historical `OperatorSagaRunReceipt.v1` body required for a fresh settlement replay has not been recovered from durable operator state. Its known run digest is not substituted for that missing structured receipt, and no historical effect is replayed solely to manufacture acceptance.

This documentation-only change is therefore the new PR-settlement pilot target, bound to protected baseline `225bed296d08c87ef557b954059a8de754b1639e`. Before any merge effect, the exact PR head/base/diff must receive a fresh `saga-plan` and receipt-bound `saga-run`; the existing Captain path must then pass its normal gates, GitHub must be read back authoritatively, and `saga-settle` must reach `settled` using the verified Captain audit chain. Only the exact merge commit established by that settlement becomes pilot 2's runtime-deployment target.

Pilot 2 must then start fresh from that exact merge commit: new runtime-deployment plan and run receipt, normal Captain deployment, exact deployment-identity convergence, verified Captain audit binding and `saga-settle == settled`. A concurrent `main` advance may not be silently substituted for the bound merge identity; any identity drift requires a new plan rather than retrospective rebinding.

### Prospective durability acceptance — 2026-09-01

PR #1004 produced a real pre-effect `saga-run` and a verified Captain merge, but it could not be settled after caller-context loss because the full `OperatorSagaRunReceipt.v1` existed only in the transient caller response. The known run digest was insufficient to reconstruct the structured receipt, so #1004 remains failure/recovery evidence and is not promoted to pilot success.

PR #1007 merged as `a06790d1e48fe45aa43e13738af458498357be8f`, and the serving Grabowski runtime now reports that exact protected commit with complete manifest/integrity convergence. That release persists each validated Saga run receipt into the existing verified Grabowski audit chain before Captain handoff and returns a compact `VerifiedSagaRunReceiptRef.v1`. If the durability append fails, `saga-run` fails before Captain. `saga-settle` may recover the exact run from that verified reference and independently recover Captain evidence from `VerifiedCaptainAuditResultRef.v1`; both references remain bound to the exact plan/action identities. The normal deployment used to activate #1007 is a prerequisite only and is not counted as either T121 pilot.

This documentation change is the first prospective acceptance target under the durable contract. Before any merge effect, its exact PR/head/base/diff must receive a fresh `saga-plan` and `saga-run`, and the returned `run_receipt_ref` must resolve from the verified audit chain. After the normal Captain merge and authoritative GitHub readback, settlement must be executed with that durable run reference rather than relying on the inline caller copy and must reach `settled`. Only the exact merge commit established by that settlement may become the runtime-deployment pilot target.

Pilot 2 must then produce its own fresh runtime-deployment plan, durable run reference, Captain deployment result, exact deployment-identity convergence and reference-based `saga-settle == settled`. Historical merges, prerequisite deployments, inline-only receipts and later `main` identities are not substitutes for those prospective proofs.

### Prospective identity-freeze retry — 2026-09-01

PR #1014 proved that durable run-receipt recovery alone is insufficient when the PR identity changes after `saga-run`. Its verified durable Saga run was bound to head `329e245fc97ead824ffe7b15ef5c09c044f2570b` on base `a06790d1e48fe45aa43e13738af458498357be8f`, while the eventual merge used head `a1e54222e9ffe0c192d09ac433eb77b837b7f27a` on base `ec705f2d44b525c23cb6da2ad4ec3aa55628945c`. No later verified Saga run in the inspected audit material targets that final #1014 identity, so #1014 is not promoted to pilot success.

The next prospective attempt changes the order of operations. The PR must first converge to current `main`, complete its required CI/review gates, and reach a mergeable exact head/base/diff. Only then may `saga-plan` and `saga-run` be created. Once `saga-run` returns its verified durable run reference, the PR head and base are frozen: no update-branch, rebase, force-push, new commit, or other identity-changing action is permitted. Any later base drift invalidates that attempt and requires a new plan/run before Captain rather than rebinding the existing receipt.

Captain execution must therefore occur in the same stable identity window as the post-CI Saga run. Settlement must use the resulting `VerifiedSagaRunReceiptRef.v1` plus the exact verified Captain completion reference and authoritative GitHub readback. Only `saga-settle == settled` for that unchanged identity establishes pilot 1 and releases its exact merge commit as the sole deployment target for pilot 2.

### Final post-fix acceptance pairing — 2026-09-02

PR #1024 subsequently achieved a real prospective PR-settlement Saga with a durable `VerifiedSagaRunReceiptRef.v1`, verified Captain merge, authoritative GitHub readback and reference-based `saga-settle == settled`; its exact settled merge commit was `b56f6997dac48ead915d05c2e9bcf3ea9817bb33`. The immediately paired runtime-deployment Saga then exposed a distinct production defect before selector switch: Green was ready, but the agent-instruction transition incorrectly required the scheduler deployment-source identity to equal the separate runtime-snapshot identity. The deployment rolled back with Blue preserved and therefore did not establish pilot 2.

PR #1025 repaired that identity-domain mixup and merged as `46a0394d6f2e3940e8226a2b066e348aeb5f9ce7`. A normal prerequisite deployment of that exact commit completed successfully through Blue-Green cutover, and the serving runtime now reports the same commit with complete integrity and manifest/process convergence. That deployment proves the regression is fixed in production, but it is not promoted to T121 Saga acceptance because it was not the runtime-deployment Saga paired with a newly settled PR pilot.

Final T121 acceptance therefore requires one fresh post-fix pair. This documentation change is the new PR-settlement target. It must first converge to current protected `main` and complete required CI/review gates; only then may a new `saga-plan` and `saga-run` freeze the exact PR head/base/diff. From that run onward, no identity-changing branch action is permitted. Captain merge, authoritative GitHub readback and `saga-settle` must use the durable run reference and verified Captain completion reference and reach `settled`.

Only that newly settled merge commit may become the runtime-deployment target. Pilot 2 must then create its own fresh plan and durable run reference, execute Captain deployment against that exact commit, observe deployment identity to complete manifest/process convergence, and settle from the durable run and Captain references. A prerequisite deployment, an older settled PR, or a later concurrent `main` head is not a substitute for this paired proof.

### Final settlement-recovery reset — 2026-09-02

PR #1026 produced a valid durable PR-settlement Saga run for exact head `c1ddfef27aaca0b4b272304dbc58e8adb0a861bd` and Captain merged that unchanged identity as `49e78e25a6a329959157bfb04bb5dd1078353153`. Its paired runtime-deployment Saga for that exact merge commit subsequently reached reference-based `saga-settle == settled` with complete deployment-identity and serving-process convergence. The runtime half of the pair is therefore valid.

PR #1026 itself is not promoted to the final PR pilot because the historical plan can no longer be reconstructed byte-for-byte from durable state: the run receipt preserves its plan hash, but the dynamic `self_review_audit` value used to build that plan was not persisted as a recoverable plan input. The already completed merge is never replayed and a guessed plan is never substituted. This is recovery evidence, not pilot success.

This documentation-only change is the final fresh PR-settlement target. After CI/review and base convergence, its exact PR head/base/diff receives a new plan and durable run reference; no identity-changing action is allowed afterward. Captain merge and `saga-settle` must complete in that same frozen identity window. Only the resulting settled merge commit may be used for one final runtime-deployment Saga and reference-based settlement. The missing durable reconstruction of historical PR plan inputs is tracked separately and does not weaken the current settlement contract.

### Final protected pilot reset — 2026-09-02

PR #1029 preserved the intended exact head `329ba95fbad93fd06ec39c84af84f1117660da15` on base `49e78e25a6a329959157bfb04bb5dd1078353153` and merged as `d5b2ce89205657e52cb73820df8a285f07531ae0`, but the verified Grabowski audit chain contains no Captain or Saga record bound to either exact identity. The merge is therefore useful historical evidence only and is not promoted to the final PR-settlement pilot. No completed merge is replayed solely to manufacture acceptance.

This documentation-only change is the next and final protected pilot target, created from the then-current protected `main`. It remains draft while CI and review converge. Immediately before the Saga run, the PR must be non-draft, mergeable, current with `main`, and bound to one exact head/base/diff plus a passing high-critical self-review audit. `saga-plan` and durable `saga-run` then freeze that identity. From that point until Captain completion no branch, base, diff or review-bound identity may change.

Only a verified Captain merge and reference-based `saga-settle == settled` for that frozen identity establish pilot 1. The exact resulting merge commit must still be current protected `main` when pilot 2 starts; otherwise the attempt stops rather than deploying an older repository state. Pilot 2 then requires its own fresh runtime-deployment plan and durable run reference, Captain deployment of exactly that merge commit, authoritative deployment-identity convergence and reference-based `saga-settle == settled`.

### Post-bootstrap terminal pairing — 2026-09-03

PR #1040 merged the bootstrap-authority compatibility repair as `a263b3e7fb6d68225b3f1aa794a95439a4cb52f4`, and PR #1041 subsequently repaired operator-exec settling during bootstrap deployment and merged as `e29ab7903a70453ba1681c162d0dc2dd85235663`. The serving Grabowski runtime now reports that latter protected `main` commit with complete manifest, integrity and serving-process convergence. Both changes are infrastructure prerequisites only: neither is promoted to the final T121 pair because neither was prospectively frozen and settled as the required PR-settlement plus runtime-deployment Saga pair.

The documentation-only PR created from protected baseline `e29ab7903a70453ba1681c162d0dc2dd85235663` is therefore the new prospective PR-settlement target. It may receive `saga-plan` and durable `saga-run` only after its CI, review and base have converged to one exact head/base/diff. Any later `main` or PR identity drift invalidates that attempt before Captain. If pilot 1 settles, pilot 2 may target only its exact settled merge commit and only while that commit is still protected `main`; bootstrap deployments, prerequisite deployments and later unrelated `main` heads remain non-substitutable evidence.

### Current terminal pairing — 2026-09-06

PR #1043 merged the preceding post-bootstrap reset as `2508e0c7a1c5c395b02880f342bea3889bc0072f`. That merge alone does not establish the required pair, and unrelated recent Saga receipts are not promoted to T121 evidence unless they bind the exact T121 PR-settlement and its immediately paired runtime-deployment identity.

The current coordinated attempt began as Bureau run `BUR-RUN-20260906T122836Z-1b9d32c9cf`, created from protected `main` baseline `e354278c5abdfeea7a9a3c06dc688061870b86c0`. PR #1106 first reached green CI and a diff-bound high-critical self-review on exact head `5b11fac44de68e32b97b4dd1b92edda94f3716fd`. Its prospective `saga-run` then exposed a new fail-closed defect before any Captain effect: `bureau-pickup-status` successfully read the run but reported that the run had already been orphan-reconciled to `failed`, its required leases were released or expired, and its execution binding was stale. Because Saga semantic readiness only interpreted `pr-check-readiness`, the successful read wrapper was incorrectly promoted to `captain_required`. No merge was attempted from that receipt; its plan, run receipt and durable reference are failure evidence only and are never promoted to pilot acceptance.

PR #1106 now repairs that semantic boundary. When a PR-settlement plan explicitly includes `bureau-pickup-status`, Prepare is ready only while the exact Bureau run remains in an active state, coordination is non-blocking, the required lease binding is `active-bound`, and the execution binding is still `actively_bound`. A caller that does not require Bureau participation may omit `bureau_run_id`; the Saga then has no Bureau-liveness dependency. The corrected PR head must complete fresh CI and high-critical self-review before a new `saga-plan` and durable `saga-run` freeze its exact head/base/diff. No identity-changing branch action is allowed after that new run and before Captain completion.

Only verified Captain merge, authoritative GitHub readback and reference-based `saga-settle == settled` for that corrected frozen identity establish pilot 1. Pilot 2 may then target only that exact settled merge commit while it remains protected `main`; it requires a fresh runtime-deployment plan and durable run reference, Captain deployment of exactly that commit, authoritative deployment-identity convergence and reference-based `saga-settle == settled`. If protected `main` advances first, the attempt blocks instead of deploying a stale commit.

## Non-claims

This document does not by itself establish successful live pilots or Bureau acceptance. It also does not establish automatic post-`integration_ready` controller custody. The latter requires a separate bounded-autonomy decision after the Saga primitive is proven; T121 itself preserves the current Captain boundary by design.
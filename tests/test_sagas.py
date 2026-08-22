from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_sagas as sagas


HEAD = "a" * 40
BASE = "b" * 40
RUN_ID = "BUR-RUN-20260821T130302Z-9eb40cfeb0"


class SagaContractTests(unittest.TestCase):
    def pr_target(self) -> dict[str, object]:
        return {
            "repository_path": str(ROOT),
            "repository": "heimgewebe/grabowski",
            "pr": 876,
            "base": "main",
            "expected_head": HEAD,
            "expected_base_sha": BASE,
            "bureau_run_id": RUN_ID,
            "merge_method": "squash",
        }

    def runtime_target(self, expected_head: str = HEAD) -> dict[str, object]:
        return {
            "repository_path": str(ROOT),
            "repository": "heimgewebe/grabowski",
            "adapter": "grabowski-self",
            "runtime_target": "heim-pc",
            "expected_head": expected_head,
        }

    def grip_result(
        self, name: str, status: str, output: dict[str, object]
    ) -> dict[str, object]:
        receipt: dict[str, object] = {
            "kind": "grabowski.operator_grip_receipt",
            "schema_version": 1,
            "grip": {"name": name},
            "status": status,
            "output_sha256": sagas.sha256_json(output),
        }
        receipt["receipt_sha256"] = sagas.sha256_json(receipt)
        return {
            "status": status,
            "receipt_sha256": receipt["receipt_sha256"],
            "receipt": receipt,
            "output": output,
        }

    def captain_result(
        self,
        plan: dict[str, object],
        *,
        passed: bool = True,
        invoked: bool = True,
    ) -> dict[str, object]:
        handoff = plan["captain_handoff"]
        assert isinstance(handoff, dict)
        status = "passed" if passed else "failed" if invoked else "blocked"
        decision = (
            "scheduled"
            if passed and plan["saga_kind"] == "runtime-deployment"
            else "executed"
            if passed
            else "verification_failed_after_execution"
            if invoked
            else "blocked"
        )
        output: dict[str, object] = {
            "decision": decision,
            "actions": [
                {
                    "action": handoff["action"],
                    "target": copy.deepcopy(handoff["target"]),
                }
            ],
            "executions": [
                {
                    "execution_invoked": invoked,
                    "execution_attempted": invoked,
                    "verification_passed": passed,
                    "deployment_scheduled": (
                        passed and plan["saga_kind"] == "runtime-deployment"
                    ),
                    "deployment_completion_verified": False,
                }
            ],
        }
        return self.grip_result("captain-run", status, output)

    def audit_binding(
        self, plan: dict[str, object], captain: dict[str, object]
    ) -> dict[str, object]:
        receipt = captain["receipt"]
        assert isinstance(receipt, dict)
        expected = plan["expected_identity"]
        assert isinstance(expected, dict)
        handoff = plan["captain_handoff"]
        assert isinstance(handoff, dict)
        body: dict[str, object] = {
            "schema_version": 1,
            "kind": sagas.CAPTAIN_AUDIT_BINDING_KIND,
            "authority": "verified_grabowski_audit_chain",
            "intent_record_sha256": "c" * 64,
            "completion_record_sha256": "d" * 64,
            "action": handoff["action"],
            "target_sha256": sagas.sha256_json(handoff["target"]),
            "expected_head": expected["expected_head"],
            "expected_base": expected.get("base") if plan["saga_kind"] == "pr-settlement" else None,
            "expected_base_sha": expected.get("expected_base_sha") if plan["saga_kind"] == "pr-settlement" else None,
            "receipt_sha256": receipt["receipt_sha256"],
            "output_sha256": receipt["output_sha256"],
            "status": receipt["status"],
        }
        return {**body, "binding_sha256": sagas.sha256_json(body)}

    def settle(
        self,
        *,
        plan_value: dict[str, object],
        run_receipt_value: dict[str, object],
        captain_result_value: dict[str, object],
        readback_value: dict[str, object],
    ) -> dict[str, object]:
        return sagas.settle(
            plan_value=plan_value,
            run_receipt_value=run_receipt_value,
            captain_result_value=captain_result_value,
            captain_audit_binding_value=self.audit_binding(
                plan_value, captain_result_value
            ),
            readback_value=readback_value,
        )

    def mechanic_result(
        self, plan: dict[str, object], *, passed: bool = True
    ) -> dict[str, object]:
        actions = plan["mechanic_actions"]
        assert isinstance(actions, list)
        status = "passed" if passed else "blocked"
        selected = actions if passed else actions[:1]
        records: list[dict[str, object]] = []
        for index, planned in enumerate(selected):
            assert isinstance(planned, dict)
            child_status = "passed" if passed else "blocked"
            child_output: dict[str, object] = {"fixture": index}
            child = self.grip_result(str(planned["action"]), child_status, child_output)
            records.append(
                {
                    "index": index,
                    "action": planned["action"],
                    "grip": planned["action"],
                    "target": copy.deepcopy(planned["target"]),
                    "scope": copy.deepcopy(planned["scope"]),
                    "receipt_path": planned["receipt_path"],
                    "allow_mutation": planned["allow_mutation"],
                    "child_receipt_sha256": child["receipt_sha256"],
                    "receipt_status": child_status,
                    "receipt": child["receipt"],
                    "output": child_output,
                }
            )
        output: dict[str, object] = {
            "requested_action_count": len(actions),
            "executed_action_count": len(records),
            "complete": passed,
            "actions": records,
        }
        return self.grip_result("mechanic-loop", status, output)

    def test_pr_plan_binds_five_phases_mechanic_bureau_and_captain(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        self.assertEqual(
            ["prepare", "plan", "apply", "readback", "settle"],
            [item["name"] for item in plan["phases"]],
        )
        self.assertEqual(
            ["bureau-pickup-status", "pr-check-readiness"],
            [item["action"] for item in plan["mechanic_actions"]],
        )
        self.assertEqual("captain-run", plan["captain_handoff"]["grip"])
        self.assertEqual("pr-merge", plan["captain_handoff"]["action"])
        self.assertEqual(HEAD, plan["expected_identity"]["expected_head"])
        readiness = plan["mechanic_actions"][1]
        self.assertEqual("pr-check-readiness", readiness["action"])
        self.assertEqual(HEAD, readiness["parameters"]["expected_head"])
        self.assertEqual(plan, sagas.validate_plan(plan))
        self.assertIn("cross-system-atomicity", plan["does_not_establish"])

    def test_runtime_plan_uses_registered_adapter_and_runtime_readback(self) -> None:
        plan = sagas.build_plan(
            "runtime-deployment", self.runtime_target(), "t121-deploy-pilot"
        )
        self.assertEqual(["runtime-deploy-check"], [item["action"] for item in plan["mechanic_actions"]])
        self.assertEqual("runtime-deploy", plan["captain_handoff"]["action"])
        self.assertEqual("grabowski_deployment_identity", plan["readback_contract"]["surface"])
        self.assertEqual("heim-pc", plan["captain_handoff"]["target"]["runtime_target"])
        self.assertEqual(plan, sagas.validate_plan(plan))

    def test_runtime_plan_rejects_other_adapter_repository_or_target(self) -> None:
        for field, value in (
            ("adapter", "free-shell"),
            ("repository", "other/repo"),
            ("runtime_target", "somewhere-else"),
        ):
            target = self.runtime_target()
            target[field] = value
            with self.subTest(field=field), self.assertRaises(sagas.SagaError):
                sagas.build_plan("runtime-deployment", target, "t121-deploy-pilot")

    def test_plan_rejects_tampering_and_unknown_target_fields(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        drifted = copy.deepcopy(plan)
        drifted["captain_handoff"]["target"]["pr"] = 999
        with self.assertRaisesRegex(sagas.SagaError, "identity drifted"):
            sagas.validate_plan(drifted)
        target = self.pr_target()
        target["shell"] = "rm"
        with self.assertRaisesRegex(sagas.SagaError, "target shape is invalid"):
            sagas.build_plan("pr-settlement", target, "t121-pr-pilot")

    def test_run_receipt_exposes_captain_handoff_only_after_prepare_pass(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        passed = sagas.build_run_receipt(plan, self.mechanic_result(plan, passed=True))
        self.assertEqual("captain_required", passed["state"])
        self.assertTrue(passed["captain_ready"])
        self.assertEqual("passed", passed["phase_status"]["prepare"])
        self.assertEqual("required", passed["phase_status"]["apply"])
        self.assertIsNotNone(passed["captain_handoff"])
        self.assertEqual(passed, sagas.validate_run_receipt(passed, plan_value=plan))

        blocked = sagas.build_run_receipt(plan, self.mechanic_result(plan, passed=False))
        self.assertEqual("prepare_blocked", blocked["state"])
        self.assertFalse(blocked["captain_ready"])
        self.assertIsNone(blocked["captain_handoff"])
        self.assertEqual("blocked", blocked["receipt_status"])

    def test_run_receipt_digest_and_plan_binding_are_fail_closed(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        drifted = copy.deepcopy(run)
        drifted["phase_status"]["apply"] = "passed"
        with self.assertRaisesRegex(sagas.SagaError, "digest mismatch"):
            sagas.validate_run_receipt(drifted, plan_value=plan)

        other = sagas.build_plan("pr-settlement", self.pr_target(), "other-pilot")
        with self.assertRaisesRegex(sagas.SagaError, "another saga plan"):
            sagas.validate_run_receipt(run, plan_value=other)

    def test_pr_settlement_pass_requires_exact_merged_head(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        captain = self.captain_result(plan)
        settled = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=captain,
            readback_value={
                "number": 876,
                "state": "MERGED",
                "baseRefName": "main",
                "headRefOid": HEAD,
                "mergeCommit": {"oid": "e" * 40},
            },
        )
        self.assertEqual("settled", settled["state"])
        self.assertEqual("passed", settled["phase_status"]["settle"])
        self.assertFalse(settled["retry_allowed"])

        mismatch = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=captain,
            readback_value={
                "number": 876,
                "state": "MERGED",
                "baseRefName": "main",
                "headRefOid": "f" * 40,
            },
        )
        self.assertEqual("recovery_required", mismatch["state"])
        self.assertIn("pr_head_mismatch", mismatch["reasons"])
        self.assertFalse(mismatch["retry_allowed"])

    def test_captain_block_is_known_but_invoked_failure_requires_recovery(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        blocked = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=self.captain_result(plan, passed=False, invoked=False),
            readback_value={"state": "OPEN", "headRefOid": HEAD},
        )
        self.assertEqual("apply_blocked", blocked["state"])
        self.assertIn("captain_blocked", blocked["reasons"][0])

        unknown = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=self.captain_result(plan, passed=False, invoked=True),
            readback_value={"state": "MERGED", "headRefOid": HEAD},
        )
        self.assertEqual("recovery_required", unknown["state"])
        self.assertIn("captain_outcome_unknown", unknown["reasons"][0])
        self.assertIn("never blind-retry Captain", unknown["required_next_action"])

    def test_runtime_settlement_is_pending_until_exact_runtime_converges(self) -> None:
        plan = sagas.build_plan(
            "runtime-deployment", self.runtime_target(), "t121-deploy-pilot"
        )
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        captain = self.captain_result(plan)
        pending = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=captain,
            readback_value={
                "identity": {"repo_head": "f" * 40, "completion_status": "complete"},
                "integrity": {"manifest_schema_valid": True},
                "serving_process": {
                    "matches_deployed_manifest": True,
                    "serves_deployed_release": True,
                },
            },
        )
        self.assertEqual("readback_pending", pending["state"])
        self.assertTrue(pending["retry_allowed"])
        self.assertEqual("pending", pending["phase_status"]["settle"])

        complete = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=captain,
            readback_value={
                "identity": {"repo_head": HEAD, "completion_status": "complete"},
                "integrity": {
                    "manifest_schema_valid": True,
                    "runtime_pointer_valid": True,
                    "artifact_integrity_valid": True,
                },
                "serving_process": {
                    "matches_deployed_manifest": True,
                    "serves_deployed_release": True,
                },
            },
        )
        self.assertEqual("settled", complete["state"])

    def test_runtime_integrity_failure_is_recovery_required(self) -> None:
        plan = sagas.build_plan(
            "runtime-deployment", self.runtime_target(), "t121-deploy-pilot"
        )
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        result = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=self.captain_result(plan),
            readback_value={
                "identity": {"repo_head": HEAD, "completion_status": "complete"},
                "integrity": {"manifest_schema_valid": True, "artifact_integrity_valid": False},
                "serving_process": {
                    "matches_deployed_manifest": True,
                    "serves_deployed_release": True,
                },
            },
        )
        self.assertEqual("recovery_required", result["state"])
        self.assertIn("runtime_integrity_not_fully_valid", result["reasons"])

    def test_settle_rejects_captain_target_drift(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        captain = self.captain_result(plan)
        captain["output"]["actions"][0]["target"]["pr"] = 999
        captain = self.grip_result("captain-run", "passed", captain["output"])
        with self.assertRaisesRegex(sagas.SagaError, "target differs"):
            self.settle(
                plan_value=plan,
                run_receipt_value=run,
                captain_result_value=captain,
                readback_value={"state": "MERGED", "headRefOid": HEAD},
            )

    def test_mechanic_result_must_match_exact_planned_child_scope(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        mechanic = self.mechanic_result(plan)
        mechanic["output"]["actions"][0]["target"]["bureau_run_id"] = (
            "BUR-RUN-20260821T000000Z-0000000000"
        )
        mechanic = self.grip_result("mechanic-loop", "passed", mechanic["output"])
        with self.assertRaisesRegex(sagas.SagaError, "differs from saga plan"):
            sagas.build_run_receipt(plan, mechanic)

    def test_child_and_captain_receipt_tampering_is_rejected(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        mechanic = self.mechanic_result(plan)
        mechanic["output"]["actions"][0]["receipt"]["status"] = "blocked"
        mechanic = self.grip_result("mechanic-loop", "passed", mechanic["output"])
        with self.assertRaisesRegex(sagas.SagaError, "child receipt digest mismatch"):
            sagas.build_run_receipt(plan, mechanic)

        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        captain = self.captain_result(plan)
        captain["receipt"]["status"] = "blocked"
        with self.assertRaisesRegex(sagas.SagaError, "receipt digest mismatch"):
            self.settle(
                plan_value=plan,
                run_receipt_value=run,
                captain_result_value=captain,
                readback_value={
                    "number": 876,
                    "state": "MERGED",
                    "baseRefName": "main",
                    "headRefOid": HEAD,
                    "mergeCommit": {"oid": "e" * 40},
                },
            )

    def test_runtime_empty_integrity_is_not_a_vacuous_pass(self) -> None:
        plan = sagas.build_plan(
            "runtime-deployment", self.runtime_target(), "t121-deploy-pilot"
        )
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        result = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=self.captain_result(plan),
            readback_value={
                "identity": {"repo_head": HEAD, "completion_status": "complete"},
                "integrity": {},
                "serving_process": {
                    "matches_deployed_manifest": True,
                    "serves_deployed_release": True,
                },
            },
        )
        self.assertEqual("recovery_required", result["state"])
        self.assertIn("runtime_integrity_not_fully_valid", result["reasons"])

    def test_pr_readback_requires_target_identity_and_merge_commit(self) -> None:
        plan = sagas.build_plan("pr-settlement", self.pr_target(), "t121-pr-pilot")
        run = sagas.build_run_receipt(plan, self.mechanic_result(plan))
        result = self.settle(
            plan_value=plan,
            run_receipt_value=run,
            captain_result_value=self.captain_result(plan),
            readback_value={"state": "MERGED", "headRefOid": HEAD},
        )
        self.assertEqual("recovery_required", result["state"])
        self.assertIn("pr_base_mismatch", result["reasons"])
        self.assertIn("pr_number_mismatch", result["reasons"])
        self.assertIn("pr_merge_commit_missing", result["reasons"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_agent_workspace as workspace
import grabowski_operator_routing_shadow_capture as capture

TASK_ID = "a" * 24
FROZEN_AT = "2026-07-23T05:20:00Z"
LATER_FROZEN_AT = "2026-07-23T05:21:00Z"
CAPTURED_AT = "2026-07-23T05:30:00Z"


def route_evidence_v2() -> dict:
    facts = {
        "task_kind": "code",
        "changed_file_estimate": 7,
        "expected_duration_minutes": 120,
        "novelty": "high",
        "risk_flags": ["concurrency", "schema"],
        "connector_instability": True,
        "concurrent_external_activity": True,
        "parallelization_candidate": False,
        "decision_fork": False,
        "architecture_hypotheses": 1,
        "user_requested_external": True,
        "available_external_agents": ["claude"],
    }
    decision = workspace._route_decision(facts)
    recommendation = {
        "schema_version": 2,
        "route_policy_version": decision["route_policy_version"],
        "risk_tier": decision["risk_tier"],
        "score": decision["score"],
        "execution_mode": decision["execution_mode"],
        "input_facts": facts,
        "external_candidates": decision["external_candidates"],
        "parallel_writer_pilot": decision["parallel_writer_pilot"],
    }
    return {
        "schema_version": 2,
        "route_policy_version": decision["route_policy_version"],
        "risk_tier": decision["risk_tier"],
        "parallel_writer_pilot": decision["parallel_writer_pilot"],
        "recommendation_id": workspace._sha256_json(recommendation),
        "score": decision["score"],
        "recommended_route": decision["execution_mode"],
        "actual_route": "workspace_with_contrast",
        "input_facts": facts,
        "external_candidates": decision["external_candidates"],
        "deviation_reason": "explicit advisory contrast workspace requested after direct operator planning",
    }


def route_evidence_v1() -> dict:
    facts = {
        "task_kind": "code",
        "changed_file_estimate": 4,
        "expected_duration_minutes": 30,
        "novelty": "low",
        "risk_flags": [],
        "connector_instability": False,
        "parallel_work": False,
        "user_requested_external": False,
        "available_external_agents": [],
    }
    decision = workspace._route_decision_v1(facts)
    recommendation = {
        "schema_version": 1,
        "score": decision["score"],
        "execution_mode": decision["execution_mode"],
        "input_facts": facts,
        "external_candidates": decision["external_candidates"],
    }
    return {
        "schema_version": 1,
        "recommendation_id": workspace._sha256_json(recommendation),
        "score": decision["score"],
        "recommended_route": decision["execution_mode"],
        "actual_route": decision["execution_mode"],
        "input_facts": facts,
        "external_candidates": decision["external_candidates"],
        "deviation_reason": None,
    }


def pre_task_manifest(
    route: dict | None = None, *, workspace_id: str = "gaw-test-shadow-1234"
) -> dict:
    return {
        "workspace_id": workspace_id,
        "plan_sha256": "b" * 64,
        "tasks": {"writer": None, "tests": None, "review": None},
        "route_evidence": route if route is not None else route_evidence_v2(),
        "private_note": "must-never-appear-in-cohort",
        "commands": {"writer": ["agent", "--prompt", "must-never-leak"]},
    }


def bound_manifest(
    route: dict | None = None, *, workspace_id: str = "gaw-test-shadow-1234"
) -> dict:
    result = pre_task_manifest(route, workspace_id=workspace_id)
    result["tasks"] = {"writer": TASK_ID, "tests": None, "review": None}
    return result


def reviewed_outcome() -> dict:
    return {
        "status": "reviewed",
        "kind": "task_correctness",
        "label": "success",
        "observed_at": "2026-07-23T05:29:00Z",
        "review_authority": "ci_and_review",
    }


def stored_prospective(
    root: Path,
    manifest: dict | None = None,
    *,
    frozen_at: str = FROZEN_AT,
) -> dict:
    candidate = manifest if manifest is not None else pre_task_manifest()
    result = capture.capture_workspace_eligibility_best_effort(
        candidate, root=root, frozen_at=frozen_at
    )
    if result["status"] not in {"created", "duplicate"}:
        raise AssertionError(f"failed to store prospective receipt: {result}")
    path = root / "prospective" / f"{result['workspace_case_id']}.json"
    return json.loads(path.read_text(encoding="utf-8"))


class OperatorRoutingShadowCohortTests(unittest.TestCase):
    def test_prospective_freeze_requires_no_bound_tasks(self) -> None:
        with self.assertRaisesRegex(
            capture.ShadowCaptureError, "before workspace tasks"
        ):
            capture.build_prospective_eligibility(bound_manifest(), frozen_at=FROZEN_AT)

    def test_prospective_freeze_preserves_route_schema_v1_and_v2(self) -> None:
        v1 = capture.build_prospective_eligibility(
            pre_task_manifest(route_evidence_v1()), frozen_at=FROZEN_AT
        )
        v2 = capture.build_prospective_eligibility(
            pre_task_manifest(route_evidence_v2()), frozen_at=FROZEN_AT
        )
        self.assertEqual(v1["canonical_route_evidence"]["schema_version"], 1)
        self.assertIn("parallel_work", v1["features"])
        self.assertNotIn("risk_tier", v1["features"])
        self.assertEqual(v2["canonical_route_evidence"]["schema_version"], 2)
        self.assertIn("risk_tier", v2["features"])
        self.assertNotIn("parallel_work", v2["features"])

    def test_workspace_hook_is_before_writer_task_start(self) -> None:
        source = inspect.getsource(workspace.grabowski_agent_workspace_create)
        self.assertLess(
            source.index(
                "_capture_routing_shadow_prospective_best_effort(manifest)"
            ),
            source.index("tasks.grabowski_task_start("),
        )

    def test_hook_failure_never_raises_into_workspace_execution(self) -> None:
        with mock.patch.object(
            workspace.base, "_append_audit", side_effect=RuntimeError("audit down")
        ):
            result = workspace._capture_routing_shadow_prospective_best_effort(
                {"workspace_id": "not-valid"}
            )
        self.assertIn(result["status"], {"rejected", "error"})
        self.assertEqual(result["no_effect"], capture.NO_EFFECT)

    def test_attempt_audit_failure_does_not_undo_valid_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            with mock.patch.object(
                capture,
                "write_new_capture_idempotent",
                side_effect=capture.ShadowCaptureError("audit storage unavailable"),
            ):
                result = capture.capture_workspace_eligibility_best_effort(
                    pre_task_manifest(), root=root, frozen_at=FROZEN_AT
                )
            self.assertEqual(result["status"], "created")
            self.assertIsNone(result["attempt_id"])
            self.assertEqual(result["attempt_audit_status"], "unavailable")
            self.assertEqual(len(list((root / "prospective").glob("*.json"))), 1)

    def test_best_effort_capture_rejects_incomplete_route_and_audits_attempt(
        self,
    ) -> None:
        candidate = pre_task_manifest()
        candidate["route_evidence"] = None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            result = capture.capture_workspace_eligibility_best_effort(
                candidate, root=root, frozen_at=FROZEN_AT
            )
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(result["reason_code"], "ineligible_route_evidence")
            self.assertEqual(result["attempt_audit_status"], "created")
            attempts = list((root / "attempts").glob("*.json"))
            self.assertEqual(len(attempts), 1)

    def test_restart_reuses_first_freeze_for_same_case(self) -> None:
        manifest = pre_task_manifest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            first = capture.capture_workspace_eligibility_best_effort(
                manifest, root=root, frozen_at=FROZEN_AT
            )
            second = capture.capture_workspace_eligibility_best_effort(
                manifest, root=root, frozen_at=LATER_FROZEN_AT
            )
            self.assertEqual(first["status"], "created")
            self.assertEqual(second["status"], "duplicate")
            self.assertEqual(
                first["prospective_eligibility_id"],
                second["prospective_eligibility_id"],
            )
            receipts = list((root / "prospective").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            stored = json.loads(receipts[0].read_text())
            self.assertEqual(stored["frozen_at"], FROZEN_AT)

    def test_restart_reuses_first_freeze_when_manifest_metadata_changes(self) -> None:
        first_manifest = pre_task_manifest()
        first_manifest["updated_at"] = "2026-07-23T05:19:58Z"
        second_manifest = pre_task_manifest()
        second_manifest["updated_at"] = "2026-07-23T05:20:30Z"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            first = capture.capture_workspace_eligibility_best_effort(
                first_manifest, root=root, frozen_at=FROZEN_AT
            )
            second = capture.capture_workspace_eligibility_best_effort(
                second_manifest, root=root, frozen_at=LATER_FROZEN_AT
            )
            self.assertEqual(first["status"], "created")
            self.assertEqual(second["status"], "duplicate")
            self.assertEqual(
                first["prospective_eligibility_id"],
                second["prospective_eligibility_id"],
            )
            stored = json.loads(
                next((root / "prospective").glob("*.json")).read_text(encoding="utf-8")
            )
            self.assertEqual(stored["frozen_at"], FROZEN_AT)
            self.assertEqual(
                stored["canonical_route_evidence"]["manifest_sha256"],
                capture._sha256_json(first_manifest),
            )

    def test_case_identity_binds_full_route_evidence_not_only_recommendation(
        self,
    ) -> None:
        baseline_route = route_evidence_v1()
        deviated_route = route_evidence_v1()
        deviated_route["actual_route"] = "workspace_with_contrast"
        deviated_route["deviation_reason"] = "manual no-effect contrast route"
        baseline = capture.build_prospective_eligibility(
            pre_task_manifest(baseline_route), frozen_at=FROZEN_AT
        )
        deviated = capture.build_prospective_eligibility(
            pre_task_manifest(deviated_route), frozen_at=FROZEN_AT
        )
        self.assertEqual(
            baseline["canonical_route_evidence"]["recommendation_id"],
            deviated["canonical_route_evidence"]["recommendation_id"],
        )
        self.assertNotEqual(
            baseline["canonical_route_evidence"]["route_evidence_sha256"],
            deviated["canonical_route_evidence"]["route_evidence_sha256"],
        )
        self.assertNotEqual(
            baseline["workspace_case"]["case_id"],
            deviated["workspace_case"]["case_id"],
        )

    def test_seal_rejects_valid_but_unstored_prospective_receipt(self) -> None:
        receipt = capture.build_prospective_eligibility(
            pre_task_manifest(), frozen_at=FROZEN_AT
        )
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                capture.ShadowCaptureError,
                "not present in the create-only cohort store",
            ):
                capture.seal_prospective_case(
                    receipt,
                    bound_manifest(),
                    eligible_task_id=TASK_ID,
                    outcome=reviewed_outcome(),
                    primary_evidence_refs=["github-ci:run:123"],
                    root=Path(tmp) / "cohort",
                    captured_at=CAPTURED_AT,
                )

    def test_tampered_prospective_eligibility_is_rejected(self) -> None:
        receipt = capture.build_prospective_eligibility(
            pre_task_manifest(), frozen_at=FROZEN_AT
        )
        receipt["features"]["changed_file_estimate"] += 1
        with self.assertRaisesRegex(
            capture.ShadowCaptureError, "prospective_eligibility_id"
        ):
            capture.validate_prospective_eligibility(receipt)

    def test_route_evidence_change_after_freeze_is_rejected(self) -> None:
        receipt = capture.build_prospective_eligibility(
            pre_task_manifest(), frozen_at=FROZEN_AT
        )
        changed = bound_manifest()
        changed["route_evidence"]["actual_route"] = "workspace_with_competition"
        with self.assertRaises(capture.ShadowCaptureError):
            capture.build_bound_eligibility_v2(
                receipt, changed, eligible_task_id=TASK_ID
            )

    def test_reviewed_outcome_without_primary_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            receipt = stored_prospective(root)
            with self.assertRaisesRegex(
                capture.ShadowCaptureError, "require at least one"
            ):
                capture.seal_prospective_case(
                    receipt,
                    bound_manifest(),
                    eligible_task_id=TASK_ID,
                    outcome=reviewed_outcome(),
                    primary_evidence_refs=[],
                    root=root,
                    captured_at=CAPTURED_AT,
                )

    def test_abstention_remains_abstention(self) -> None:
        outcome = {
            "status": "abstained",
            "reason_code": "no_semantic_review",
            "observed_at": "2026-07-23T05:29:00Z",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            receipt = stored_prospective(root)
            result = capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=outcome,
                primary_evidence_refs=[],
                root=root,
                captured_at=CAPTURED_AT,
            )
            record = json.loads(
                (root / "records" / f"{result['case_id']}.json").read_text()
            )
            self.assertEqual(record["outcome"], outcome)
            self.assertEqual(record["primary_evidence_refs"], [])

    def test_private_manifest_data_never_enters_receipt_or_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            receipt = stored_prospective(root)
            serialized_receipt = json.dumps(receipt, sort_keys=True)
            self.assertNotIn("must-never-appear-in-cohort", serialized_receipt)
            self.assertNotIn("must-never-leak", serialized_receipt)
            result = capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                root=root,
                captured_at=CAPTURED_AT,
            )
            record = (root / "records" / f"{result['case_id']}.json").read_text()
            self.assertNotIn("must-never-appear-in-cohort", record)
            self.assertNotIn("must-never-leak", record)
            self.assertNotIn("commands", record)

    def test_no_effect_tampering_is_rejected(self) -> None:
        receipt = capture.build_prospective_eligibility(
            pre_task_manifest(), frozen_at=FROZEN_AT
        )
        eligibility = capture.build_bound_eligibility_v2(
            receipt, bound_manifest(), eligible_task_id=TASK_ID
        )
        record = capture.build_shadow_record_v2(
            eligibility,
            outcome=reviewed_outcome(),
            primary_evidence_refs=["github-ci:run:123"],
            captured_at=CAPTURED_AT,
        )
        record["no_effect"]["routing"] = True
        with self.assertRaisesRegex(capture.ShadowCaptureError, "no_effect"):
            capture.validate_shadow_record_v2(record)

    def test_symlinked_cohort_root_is_rejected_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            real = parent / "real"
            real.mkdir(mode=0o700)
            link = parent / "cohort"
            link.symlink_to(real, target_is_directory=True)
            result = capture.capture_workspace_eligibility_best_effort(
                pre_task_manifest(), root=link, frozen_at=FROZEN_AT
            )
            self.assertIn(result["status"], {"rejected", "error"})
            self.assertEqual(list(real.iterdir()), [])

    def test_parallel_workspaces_get_distinct_case_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            first = capture.capture_workspace_eligibility_best_effort(
                pre_task_manifest(workspace_id="gaw-parallel-one-1234"),
                root=root,
                frozen_at=FROZEN_AT,
            )
            second = capture.capture_workspace_eligibility_best_effort(
                pre_task_manifest(workspace_id="gaw-parallel-two-1234"),
                root=root,
                frozen_at=FROZEN_AT,
            )
            self.assertNotEqual(first["workspace_case_id"], second["workspace_case_id"])
            self.assertEqual(len(list((root / "prospective").glob("*.json"))), 2)

    def test_seal_restart_does_not_create_duplicate_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            receipt = stored_prospective(root)
            first = capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                root=root,
                captured_at=CAPTURED_AT,
            )
            second = capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                root=root,
            )
            self.assertEqual(first["status"], "created")
            self.assertEqual(second["status"], "duplicate")
            self.assertEqual(first["record_id"], second["record_id"])
            self.assertEqual(len(list((root / "records").glob("*.json"))), 1)

    def test_new_artifacts_validate_against_draft_2020_12_schemas(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ModuleNotFoundError:
            self.skipTest("optional jsonschema runtime dependency is unavailable")
        receipt = capture.build_prospective_eligibility(
            pre_task_manifest(), frozen_at=FROZEN_AT
        )
        eligibility = capture.build_bound_eligibility_v2(
            receipt, bound_manifest(), eligible_task_id=TASK_ID
        )
        record = capture.build_shadow_record_v2(
            eligibility,
            outcome=reviewed_outcome(),
            primary_evidence_refs=["github-ci:run:123"],
            captured_at=CAPTURED_AT,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            capture.capture_workspace_eligibility_best_effort(
                pre_task_manifest(), root=root, frozen_at=FROZEN_AT
            )
            attempt = json.loads(next((root / "attempts").glob("*.json")).read_text())
        samples = {
            "operator-routing-shadow-prospective-eligibility.v1.schema.json": receipt,
            "operator-routing-shadow-eligibility.v2.schema.json": eligibility,
            "operator-routing-shadow-record.v2.schema.json": record,
            "operator-routing-shadow-capture-attempt.v1.schema.json": attempt,
        }
        for filename, sample in samples.items():
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1] / "contracts" / filename
                ).read_text()
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(sample)

    def test_conflicting_reseal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cohort"
            receipt = stored_prospective(root)
            capture.seal_prospective_case(
                receipt,
                bound_manifest(),
                eligible_task_id=TASK_ID,
                outcome=reviewed_outcome(),
                primary_evidence_refs=["github-ci:run:123"],
                root=root,
                captured_at=CAPTURED_AT,
            )
            changed = reviewed_outcome()
            changed["label"] = "failure"
            with self.assertRaisesRegex(capture.ShadowCaptureError, "conflicts"):
                capture.seal_prospective_case(
                    receipt,
                    bound_manifest(),
                    eligible_task_id=TASK_ID,
                    outcome=changed,
                    primary_evidence_refs=["github-ci:run:123"],
                    root=root,
                )


if __name__ == "__main__":
    unittest.main()

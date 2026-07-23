from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_workspace as workspace

TOOL_PATH = ROOT / "tools" / "operator_routing_shadow_capture.py"
SPEC = importlib.util.spec_from_file_location("operator_routing_shadow_capture", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)

TASK_ID = "a" * 24
FROZEN_AT = "2026-07-23T05:20:00Z"
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
        "user_requested_external": False,
        "available_external_agents": [],
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
        "actual_route": "full_workspace",
        "input_facts": facts,
        "external_candidates": decision["external_candidates"],
        "deviation_reason": None,
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


def manifest(route: dict | None = None) -> dict:
    return {
        "workspace_id": "gaw-test-shadow",
        "tasks": {"writer": TASK_ID, "tests": None, "review": None},
        "route_evidence": route if route is not None else route_evidence_v2(),
        "private_note": "must-never-appear-in-shadow-record",
        "writer_argv": ["secret-agent", "--prompt", "must-never-leak"],
    }


def reviewed_outcome() -> dict:
    return {
        "status": "reviewed",
        "kind": "task_correctness",
        "label": "success",
        "observed_at": "2026-07-23T05:29:00Z",
        "review_authority": "ci_and_review",
    }


class OperatorRoutingShadowCaptureTests(unittest.TestCase):
    def freeze(self, route: dict | None = None, *, frozen_at: str = FROZEN_AT):
        return capture.build_eligibility_receipt(
            manifest(route),
            eligible_task_id=TASK_ID,
            frozen_at=frozen_at,
        )

    def build(
        self, route: dict | None = None, *, outcome: dict | None = None, refs=None,
        frozen_at: str = FROZEN_AT, captured_at: str = CAPTURED_AT,
    ):
        return capture.build_shadow_record(
            self.freeze(route, frozen_at=frozen_at),
            outcome=outcome or reviewed_outcome(),
            primary_evidence_refs=["github-ci:heimgewebe/grabowski/actions/123"] if refs is None else refs,
            captured_at=captured_at,
        )

    def test_v2_route_evidence_is_reused_and_record_is_deterministic(self) -> None:
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        self.assertEqual(first["canonical_route_evidence"]["schema_version"], 2)
        self.assertEqual(first["features"]["task_kind"], "code")
        self.assertIn("risk_tier", first["features"])
        self.assertEqual(first["no_effect"], capture.NO_EFFECT)
        self.assertEqual(capture.validate_shadow_record(first), first)

    def test_v1_route_evidence_preserves_legacy_feature_shape_without_inference(self) -> None:
        record = self.build(route_evidence_v1())
        self.assertEqual(record["canonical_route_evidence"]["schema_version"], 1)
        self.assertEqual(record["features"]["parallel_work"], False)
        self.assertNotIn("risk_tier", record["features"])
        self.assertNotIn("concurrent_external_activity", record["features"])
        self.assertEqual(capture.validate_shadow_record(record), record)

    def test_persisted_normalized_route_evidence_is_replayed_exactly(self) -> None:
        persisted = workspace._normalize_route_evidence(route_evidence_v1())
        record = self.build(persisted)
        self.assertEqual(record["canonical_route_evidence"]["schema_version"], 1)
        self.assertEqual(capture.validate_shadow_record(record), record)

    def test_persisted_route_derived_field_tampering_fails_closed(self) -> None:
        persisted = workspace._normalize_route_evidence(route_evidence_v2())
        persisted["evidence_complete"] = False
        with self.assertRaisesRegex(capture.ShadowCaptureError, "missing or incomplete"):
            self.build(persisted)

    def test_missing_route_evidence_fails_closed(self) -> None:
        candidate = manifest(route_evidence_v2())
        candidate["route_evidence"] = None
        with self.assertRaisesRegex(capture.ShadowCaptureError, "missing or incomplete"):
            capture.build_eligibility_receipt(
                candidate, eligible_task_id=TASK_ID, frozen_at=FROZEN_AT
            )

    def test_task_must_be_referenced_by_manifest(self) -> None:
        with self.assertRaisesRegex(capture.ShadowCaptureError, "not referenced"):
            capture.build_eligibility_receipt(
                manifest(), eligible_task_id="b" * 24, frozen_at=FROZEN_AT
            )

    def test_eligibility_is_hash_bound_and_final_record_references_it(self) -> None:
        eligibility = self.freeze()
        self.assertEqual(capture.validate_eligibility_receipt(eligibility), eligibility)
        record = capture.build_shadow_record(
            eligibility,
            outcome=reviewed_outcome(),
            primary_evidence_refs=["github-ci:run:123"],
            captured_at=CAPTURED_AT,
        )
        self.assertEqual(record["eligibility"]["eligibility_id"], eligibility["eligibility_id"])
        self.assertEqual(record["eligibility"]["frozen_at"], FROZEN_AT)

    def test_tampered_eligibility_receipt_fails_closed(self) -> None:
        eligibility = self.freeze()
        eligibility["features"]["changed_file_estimate"] += 1
        with self.assertRaisesRegex(capture.ShadowCaptureError, "eligibility_id"):
            capture.validate_eligibility_receipt(eligibility)

    def test_outcome_before_eligibility_freeze_is_rejected(self) -> None:
        with self.assertRaisesRegex(capture.ShadowCaptureError, "frozen before outcome"):
            self.build(frozen_at="2026-07-23T05:29:30Z")

    def test_outcome_after_capture_sealing_is_rejected(self) -> None:
        with self.assertRaisesRegex(capture.ShadowCaptureError, "after capture sealing"):
            self.build(captured_at="2026-07-23T05:28:00Z")

    def test_reviewed_outcome_requires_primary_evidence(self) -> None:
        with self.assertRaisesRegex(capture.ShadowCaptureError, "require at least one"):
            self.build(refs=[])

    def test_abstention_is_explicit_and_may_have_no_primary_evidence(self) -> None:
        outcome = {
            "status": "abstained",
            "reason_code": "no_semantic_review",
            "observed_at": "2026-07-23T05:29:00Z",
        }
        record = self.build(outcome=outcome, refs=[])
        self.assertEqual(record["outcome"], outcome)
        self.assertEqual(record["primary_evidence_refs"], [])

    def test_record_excludes_raw_manifest_private_content(self) -> None:
        serialized = json.dumps(self.build(), sort_keys=True)
        self.assertNotIn("must-never-appear-in-shadow-record", serialized)
        self.assertNotIn("must-never-leak", serialized)
        self.assertNotIn("writer_argv", serialized)
        self.assertNotIn("private_note", serialized)

    def test_record_tampering_fails_hash_validation(self) -> None:
        record = self.build()
        record["no_effect"]["routing"] = True
        with self.assertRaisesRegex(capture.ShadowCaptureError, "no_effect"):
            capture.validate_shadow_record(record)

    def test_unknown_top_level_field_fails_closed(self) -> None:
        record = self.build()
        record["raw_prompt"] = "forbidden"
        with self.assertRaisesRegex(capture.ShadowCaptureError, "shape"):
            capture.validate_shadow_record(record)

    def test_unhashable_risk_flag_fails_closed_with_capture_error(self) -> None:
        eligibility = self.freeze()
        eligibility["features"]["risk_flags"] = [{}]
        with self.assertRaisesRegex(capture.ShadowCaptureError, "risk_flags"):
            capture.validate_eligibility_receipt(eligibility)

    def test_create_only_writer_refuses_overwrite(self) -> None:
        record = self.build()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "record.json"
            capture.write_create_only(output, record)
            self.assertEqual(json.loads(output.read_text()), record)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(capture.ShadowCaptureError, "overwrite"):
                capture.write_create_only(output, record)

    def test_symlinked_output_parent_is_rejected(self) -> None:
        record = self.build()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(capture.ShadowCaptureError, "not a real directory"):
                capture.write_create_only(link / "record.json", record)

    def test_symlinked_input_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.json"
            real.write_text("{}\n", encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(capture.ShadowCaptureError, "regular non-symlink"):
                capture._read_regular_json(link, label="manifest")

    def test_operational_cli_rejects_caller_supplied_timestamps(self) -> None:
        parser = capture._build_parser()
        with self.assertRaises(SystemExit) as freeze_exit:
            parser.parse_args([
                "freeze",
                "--manifest", "/tmp/does-not-matter.json",
                "--task-id", TASK_ID,
                "--output", "/tmp/does-not-matter-output.json",
                "--frozen-at", FROZEN_AT,
            ])
        self.assertEqual(freeze_exit.exception.code, 2)

        parser = capture._build_parser()
        with self.assertRaises(SystemExit) as seal_exit:
            parser.parse_args([
                "seal",
                "--eligibility", "/tmp/does-not-matter.json",
                "--outcome", "/tmp/does-not-matter-outcome.json",
                "--output", "/tmp/does-not-matter-output.json",
                "--captured-at", CAPTURED_AT,
            ])
        self.assertEqual(seal_exit.exception.code, 2)

    def test_generated_artifacts_validate_against_draft_2020_12_schemas(self) -> None:
        if importlib.util.find_spec("jsonschema") is None:
            self.skipTest("optional jsonschema runtime dependency is unavailable")
        from jsonschema import Draft202012Validator

        eligibility_schema = json.loads(
            (ROOT / "contracts" / "operator-routing-shadow-eligibility.v1.schema.json").read_text()
        )
        record_schema = json.loads(
            (ROOT / "contracts" / "operator-routing-shadow-record.v1.schema.json").read_text()
        )
        Draft202012Validator.check_schema(eligibility_schema)
        Draft202012Validator.check_schema(record_schema)
        eligibility = self.freeze()
        record = capture.build_shadow_record(
            eligibility,
            outcome=reviewed_outcome(),
            primary_evidence_refs=["github-ci:run:123"],
            captured_at=CAPTURED_AT,
        )
        Draft202012Validator(eligibility_schema).validate(eligibility)
        Draft202012Validator(record_schema).validate(record)

    def test_optional_draft_schema_validation_skips_without_jsonschema(self) -> None:
        with mock.patch("importlib.util.find_spec", return_value=None):
            with self.assertRaises(unittest.SkipTest):
                self.test_generated_artifacts_validate_against_draft_2020_12_schemas()

    def test_schema_contract_is_fail_closed_and_shadow_only(self) -> None:
        schema = json.loads(
            (ROOT / "contracts" / "operator-routing-shadow-record.v1.schema.json").read_text()
        )
        eligibility_schema = json.loads(
            (ROOT / "contracts" / "operator-routing-shadow-eligibility.v1.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(eligibility_schema["additionalProperties"])
        self.assertIn("eligibility", schema["required"])
        self.assertEqual(len(schema["properties"]["features"]["oneOf"]), 2)
        self.assertEqual(len(eligibility_schema["properties"]["features"]["oneOf"]), 2)
        no_effect = schema["properties"]["no_effect"]["properties"]
        self.assertEqual(no_effect["proposal_only"]["const"], True)
        for field in ("routing", "policy", "queue", "merge", "runtime"):
            self.assertEqual(no_effect[field]["const"], False)


if __name__ == "__main__":
    unittest.main()

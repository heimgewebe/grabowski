from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_agent_workspace as workspace  # noqa: E402
import grabowski_operator_routing_shadow_capture as capture  # noqa: E402


def direct_route_evidence() -> dict[str, object]:
    facts = {
        "task_kind": "code",
        "changed_file_estimate": 2,
        "expected_duration_minutes": 30,
        "novelty": "medium",
        "risk_flags": [],
        "connector_instability": False,
        "concurrent_external_activity": False,
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
        "recommended_route": "direct_operator",
        "actual_route": "direct_operator",
        "input_facts": facts,
        "external_candidates": [],
        "deviation_reason": None,
    }


class DirectTaskRoutingShadowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "cohort"
        self.task_id = "1" * 24
        self.route = direct_route_evidence()
        self.frozen_at = "2026-07-24T17:30:00Z"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _capture(self, *, frozen_at: str | None = None) -> dict[str, object]:
        return capture.capture_direct_task_start_best_effort(
            task_id=self.task_id,
            route_evidence=self.route,
            host="heim-pc",
            argv_sha256="2" * 64,
            cwd="/private/operator/worktree",
            resource_keys=["repo:/private/operator/worktree"],
            runtime_seconds=60,
            root=self.root,
            frozen_at=frozen_at or self.frozen_at,
        )

    def test_direct_route_replay_is_surface_bound(self) -> None:
        normalized = workspace._normalize_route_evidence(
            self.route, execution_surface="direct_task"
        )
        self.assertEqual("verified", normalized["status"])
        self.assertTrue(normalized["evidence_complete"])
        workspace_route = dict(self.route)
        workspace_route["actual_route"] = "workspace_with_contrast"
        with self.assertRaisesRegex(
            workspace.AgentWorkspaceError, "actual_route=direct_operator"
        ):
            workspace._normalize_route_evidence(
                workspace_route, execution_surface="direct_task"
            )
        external = direct_route_evidence()
        external["input_facts"] = dict(external["input_facts"])
        external["input_facts"]["user_requested_external"] = True
        with self.assertRaises(workspace.AgentWorkspaceError):
            workspace._normalize_route_evidence(
                external, execution_surface="direct_task"
            )

    def test_direct_task_capture_is_private_bounded_and_idempotent(self) -> None:
        first = self._capture()
        second = self._capture(frozen_at="2026-07-24T17:31:00Z")
        self.assertEqual("created", first["status"])
        self.assertEqual("created", first["binding_status"])
        self.assertEqual("duplicate", second["status"])
        self.assertEqual("duplicate", second["binding_status"])
        self.assertEqual(first["binding_id"], second["binding_id"])
        binding = capture.read_direct_task_binding(self.task_id, root=self.root)
        self.assertEqual(self.frozen_at, binding["created_at"])
        self.assertEqual("direct_operator", binding["route_evidence"]["actual_route"])
        prospective_path = (
            self.root
            / "prospective"
            / f"{binding['prospective']['workspace_case_id']}.json"
        )
        prospective = json.loads(prospective_path.read_text())
        self.assertEqual(
            "direct-task-start", prospective["canonical_route_evidence"]["source"]
        )
        self.assertEqual(
            {
                "case_origin": "production",
                "capture_path": "direct_task_prestart",
            },
            prospective["case_provenance"],
        )
        serialized = json.dumps(binding, sort_keys=True)
        self.assertNotIn("heim-pc", serialized)
        self.assertNotIn("/private/operator/worktree", serialized)
        self.assertNotIn("repo:/private/operator/worktree", serialized)
        self.assertNotIn("argv", serialized.replace("argv_sha256", ""))
        self.assertEqual(capture.NO_EFFECT, binding["no_effect"])

    def test_untrusted_direct_capture_cannot_claim_production(self) -> None:
        route = capture._validated_route_evidence(
            self.route, execution_surface="direct_task"
        )
        identity = capture._direct_task_identity(
            host="heim-pc",
            argv_sha256="2" * 64,
            cwd="/private/operator/worktree",
            resource_keys=[],
            runtime_seconds=60,
        )
        plan_sha256 = capture._direct_task_plan_sha256(self.task_id, identity, route)
        manifest = capture._direct_task_manifest(
            task_id=self.task_id,
            plan_sha256=plan_sha256,
            route=route,
            writer_bound=False,
        )
        result = capture.capture_workspace_eligibility_best_effort(
            manifest,
            root=self.root,
            frozen_at=self.frozen_at,
            case_origin="production",
        )
        self.assertEqual("created", result["status"])
        prospective = json.loads(
            (
                self.root / "prospective" / f"{result['workspace_case_id']}.json"
            ).read_text()
        )
        self.assertEqual("quarantined", prospective["case_provenance"]["case_origin"])
        self.assertEqual(
            "direct_capture", prospective["case_provenance"]["capture_path"]
        )

    def test_direct_task_artifacts_validate_against_current_schemas(self) -> None:
        try:
            from jsonschema import Draft202012Validator, FormatChecker
        except ModuleNotFoundError:
            self.skipTest("optional jsonschema runtime dependency is unavailable")
        self._capture()
        binding = capture.read_direct_task_binding(self.task_id, root=self.root)
        prospective = json.loads(
            (
                self.root
                / "prospective"
                / f"{binding['prospective']['workspace_case_id']}.json"
            ).read_text()
        )
        sealed = capture.seal_direct_task_case(
            task_id=self.task_id,
            outcome={
                "status": "abstained",
                "reason_code": "no_semantic_review",
                "observed_at": "2026-07-24T17:31:00Z",
            },
            primary_evidence_refs=[],
            execution_provenance={
                "status": "completed",
                "observed_at": "2026-07-24T17:30:30Z",
                "evidence_refs": ["artifact:task-finalization"],
            },
            semantic_assessments=[],
            root=self.root,
            captured_at="2026-07-24T17:32:00Z",
        )
        eligibility = json.loads(
            (self.root / "eligibility" / f"{sealed['case_id']}.json").read_text()
        )
        record = json.loads(
            (self.root / "records" / f"{sealed['case_id']}.json").read_text()
        )
        samples = {
            "operator-routing-shadow-direct-task-binding.v1.schema.json": binding,
            "operator-routing-shadow-prospective-eligibility.v2.schema.json": prospective,
            "operator-routing-shadow-eligibility.v3.schema.json": eligibility,
            "operator-routing-shadow-record.v3.schema.json": record,
        }
        format_checker = FormatChecker()
        for filename, sample in samples.items():
            schema = json.loads((ROOT / "contracts" / filename).read_text())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema, format_checker=format_checker).validate(sample)

    def test_reviewed_direct_task_case_requires_independent_assessments(self) -> None:
        self._capture()
        with self.assertRaisesRegex(
            capture.ShadowCaptureError, "requires at least 2 independent"
        ):
            capture.seal_direct_task_case(
                task_id=self.task_id,
                outcome={
                    "status": "reviewed",
                    "kind": "task_correctness",
                    "label": "success",
                    "observed_at": "2026-07-24T17:31:00Z",
                    "review_authority": "ci_and_review",
                },
                primary_evidence_refs=["artifact:review"],
                execution_provenance={
                    "status": "completed",
                    "observed_at": "2026-07-24T17:30:30Z",
                    "evidence_refs": ["artifact:task-finalization"],
                },
                semantic_assessments=[],
                root=self.root,
                captured_at="2026-07-24T17:32:00Z",
            )
        self.assertEqual([], list((self.root / "records").iterdir()))

    def test_direct_task_case_seals_only_explicit_outcome(self) -> None:
        self._capture()
        sealed = capture.seal_direct_task_case(
            task_id=self.task_id,
            outcome={
                "status": "abstained",
                "reason_code": "no_semantic_review",
                "observed_at": "2026-07-24T17:31:00Z",
            },
            primary_evidence_refs=[],
            execution_provenance={
                "status": "completed",
                "observed_at": "2026-07-24T17:30:30Z",
                "evidence_refs": ["artifact:task-finalization"],
            },
            semantic_assessments=[],
            root=self.root,
            captured_at="2026-07-24T17:32:00Z",
        )
        self.assertEqual("created", sealed["status"])
        self.assertEqual(
            capture.RECORD_V3_SCHEMA_VERSION, sealed["record_schema_version"]
        )
        record = json.loads(
            (self.root / "records" / f"{sealed['case_id']}.json").read_text()
        )
        self.assertEqual("abstained", record["outcome"]["status"])
        self.assertEqual("completed", record["execution_provenance"]["status"])
        self.assertEqual([], record["semantic_assessments"])
        self.assertEqual(capture.NO_EFFECT, record["no_effect"])


if __name__ == "__main__":
    unittest.main()

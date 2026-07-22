from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_convergence as convergence
import grabowski_grips as grips


class FakeRunner:
    def __init__(
        self,
        *,
        head: str,
        status: str = "terminally_closed",
        dirty: bool = False,
        schema_version: int = 1,
    ):
        self.head = head
        self.status = status
        self.dirty = dirty
        self.schema_version = schema_version
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, cwd: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv == ["rev-parse", "HEAD"]:
            return {"returncode": 0, "stdout": self.head + "\n", "stderr": ""}
        if argv == ["status", "--porcelain=v1", "--untracked-files=normal"]:
            return {"returncode": 0, "stdout": " M src/core.py\n" if self.dirty else "", "stderr": ""}
        if len(argv) == 3 and argv[1] == "evaluate":
            exit_codes = {
                "transition_allowed": 0,
                "terminally_closed": 0,
                "evidence_missing": 2,
                "conflicting_evidence": 4,
                "source_stale": 5,
                "blocked": 6,
            }
            assessment = {
                "assessment_id": f"assessment-test-v{self.schema_version}",
                "blocked_by": [],
                "conflicts": ["effect:deployment:subject_sha256"] if self.status == "conflicting_evidence" else [],
                "missing_evidence": [],
                "profile_sha256": "b" * 64,
                "schema_version": self.schema_version,
                "status": self.status,
            }
            if self.schema_version == 1:
                assessment["risk_level"] = "R2"
            elif self.schema_version == 2:
                assessment.update(
                    {
                        "change_risk": "R2",
                        "target_criticality": "foundational",
                        "profile_id": "resilience-matrix-v2",
                        "profile_cell_id": "R2-foundational",
                    }
                )
            return {
                "returncode": exit_codes[self.status],
                "stdout": json.dumps(assessment, sort_keys=True) + "\n",
                "stderr": "",
            }
        raise AssertionError(argv)


class ConvergenceTests(unittest.TestCase):
    def _fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        repo = root / "protocol"
        executable = repo / ".venv" / "bin" / "regelkreis"
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        executable.chmod(0o700)
        request = root / "request.json"
        request.write_text("{}\n", encoding="utf-8")
        digest = hashlib.sha256(request.read_bytes()).hexdigest()
        return temporary, repo, executable, request, digest

    def test_terminal_assessment_allows_closure(self):
        temporary, repo, executable, request, digest = self._fixture()
        self.addCleanup(temporary.cleanup)
        head = "a" * 40
        runner = FakeRunner(head=head)
        with patch.dict(
            os.environ,
            {
                "GRABOWSKI_CONVERGENCE_PROTOCOL_REPO": str(repo),
                "GRABOWSKI_CONVERGENCE_EXECUTABLE": str(executable),
            },
            clear=False,
        ):
            result = convergence.assess(
                {
                    "request_path": str(request),
                    "expected_request_sha256": digest,
                    "expected_protocol_head": head,
                },
                runner,
                runner,
            )
        self.assertTrue(result["closure_allowed"])
        self.assertEqual(result["decision"], "allow_closure")
        self.assertEqual(result["assessment"]["status"], "terminally_closed")
        self.assertEqual(result["protocol_head"], head)
        self.assertEqual(result["request_sha256"], digest)

    def test_v2_terminal_assessment_allows_closure(self):
        temporary, repo, executable, request, digest = self._fixture()
        self.addCleanup(temporary.cleanup)
        head = "a" * 40
        runner = FakeRunner(head=head, schema_version=2)
        with patch.dict(
            os.environ,
            {
                "GRABOWSKI_CONVERGENCE_PROTOCOL_REPO": str(repo),
                "GRABOWSKI_CONVERGENCE_EXECUTABLE": str(executable),
            },
            clear=False,
        ):
            result = convergence.assess(
                {
                    "request_path": str(request),
                    "expected_request_sha256": digest,
                    "expected_protocol_head": head,
                },
                runner,
                runner,
            )
        self.assertTrue(result["closure_allowed"])
        self.assertEqual(result["decision"], "allow_closure")
        self.assertEqual(result["assessment"]["schema_version"], 2)
        self.assertEqual(result["assessment"]["change_risk"], "R2")
        self.assertEqual(result["assessment"]["target_criticality"], "foundational")

    def test_v2_assessment_rejects_v1_shape(self):
        assessment = {
            "assessment_id": "assessment-test-v2",
            "blocked_by": [],
            "conflicts": [],
            "missing_evidence": [],
            "profile_sha256": "b" * 64,
            "risk_level": "R2",
            "schema_version": 2,
            "status": "terminally_closed",
        }
        with self.assertRaisesRegex(
            convergence.ConvergenceExecutionError, "unexpected assessment shape"
        ):
            convergence._validate_assessment(assessment, 0)

    def test_conflict_blocks_closure_without_execution_error(self):
        temporary, repo, executable, request, digest = self._fixture()
        self.addCleanup(temporary.cleanup)
        head = "a" * 40
        runner = FakeRunner(head=head, status="conflicting_evidence")
        with patch.dict(
            os.environ,
            {
                "GRABOWSKI_CONVERGENCE_PROTOCOL_REPO": str(repo),
                "GRABOWSKI_CONVERGENCE_EXECUTABLE": str(executable),
            },
            clear=False,
        ):
            result = convergence.assess(
                {
                    "request_path": str(request),
                    "expected_request_sha256": digest,
                    "expected_protocol_head": head,
                },
                runner,
                runner,
            )
        self.assertFalse(result["closure_allowed"])
        self.assertEqual(result["decision"], "block_closure")
        self.assertEqual(result["assessment"]["status"], "conflicting_evidence")

    def test_request_hash_and_protocol_cleanliness_fail_closed(self):
        temporary, repo, executable, request, digest = self._fixture()
        self.addCleanup(temporary.cleanup)
        head = "a" * 40
        environment = {
            "GRABOWSKI_CONVERGENCE_PROTOCOL_REPO": str(repo),
            "GRABOWSKI_CONVERGENCE_EXECUTABLE": str(executable),
        }
        with patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesRegex(convergence.ConvergenceInputError, "SHA-256"):
                convergence.assess(
                    {
                        "request_path": str(request),
                        "expected_request_sha256": "0" * 64,
                        "expected_protocol_head": head,
                    },
                    FakeRunner(head=head),
                )
            with self.assertRaisesRegex(convergence.ConvergenceInputError, "dirty"):
                convergence.assess(
                    {
                        "request_path": str(request),
                        "expected_request_sha256": digest,
                        "expected_protocol_head": head,
                    },
                    FakeRunner(head=head, dirty=True),
                )

    def test_grip_exposes_terminal_gate(self):
        terminal = {
            "schema_version": 1,
            "kind": "grabowski.convergence_assessment",
            "request_path": "/tmp/request.json",
            "request_sha256": "c" * 64,
            "protocol_repo": "/tmp/protocol",
            "protocol_head": "a" * 40,
            "executable_sha256": "d" * 64,
            "assessment": {
                "assessment_id": "assessment-test-v1",
                "status": "terminally_closed",
            },
            "closure_allowed": True,
            "decision": "allow_closure",
            "does_not_establish": [],
        }
        with patch.object(grips.grabowski_convergence, "assess", return_value=terminal):
            result = grips.run_grip(
                "convergence-assess",
                {
                    "request_path": "/tmp/request.json",
                    "expected_request_sha256": "c" * 64,
                    "expected_protocol_head": "a" * 40,
                },
            )
        self.assertEqual(result["receipt"]["status"], "passed")
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual(checks["terminal-closure-gate"], "pass")

        blocked = dict(terminal)
        blocked["closure_allowed"] = False
        blocked["decision"] = "block_closure"
        blocked["assessment"] = {
            "assessment_id": "assessment-test-v1",
            "status": "evidence_missing",
        }
        with patch.object(grips.grabowski_convergence, "assess", return_value=blocked):
            result = grips.run_grip(
                "convergence-assess",
                {
                    "request_path": "/tmp/request.json",
                    "expected_request_sha256": "c" * 64,
                    "expected_protocol_head": "a" * 40,
                },
            )
        self.assertEqual(result["receipt"]["status"], "blocked")
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual(checks["terminal-closure-gate"], "fail")

    def test_build_pr_closure_request_complete_evidence(self):
        effects = [
            {"schema_version": 1, "kind": "merge", "evidence_ref": "github-pr:heimgewebe/grabowski#235@0b09e6d7dfdb", "subject_sha256": "a" * 64},
            {"schema_version": 1, "kind": "deployment", "evidence_ref": "grabowski-release:rel-123", "subject_sha256": "b" * 64},
        ]
        verifications = [
            {"schema_version": 1, "kind": v, "result": "pass", "evidence_ref": f"ref-{v}", "subject_sha256": "c" * 64}
            for v in ["tests", "review", "ci", "deployment_identity", "runtime_identity", "service_health", "smoke_test", "negative_control"]
        ]
        evidence = {
            "effects": effects,
            "verifications": verifications,
            "closure": {
                "schema_version": 1,
                "closure_id": "cls-test-1",
                "status": "closed",
                "bureau_task_ref": "bureau:task:T001:verified",
                "chronik_event_ref": "chronik:event:E123",
                "cleanup_evidence": ["grabowski:checkout:chk-main"],
                "residual_risks": [],
            },
        }
        req_dict, req_bytes, req_sha256 = convergence.build_pr_closure_request(
            evidence,
            risk_level="R2",
            assessment_id="pr-closure-test-1",
            observed_at="2026-07-22T22:00:00Z",
            evidence_authority="authoritative_receipts",
            source_state="current",
        )
        self.assertEqual(req_dict["schema_version"], 1)
        self.assertEqual(req_dict["risk_level"], "R2")
        self.assertEqual(req_dict["classification"]["change_class"], "lifecycle")
        self.assertEqual(req_dict["classification"]["blocked_by"], [])
        self.assertEqual(req_dict["observation"]["source_state"], "current")
        self.assertEqual(req_dict["observation"]["observed_at"], "2026-07-22T22:00:00Z")
        self.assertIn("closure", req_dict)
        self.assertEqual(req_dict["closure"]["status"], "closed")
        self.assertEqual(hashlib.sha256(req_bytes).hexdigest(), req_sha256)

    def test_build_pr_closure_request_missing_and_conflicting_evidence(self):
        evidence = {
            "pr_merge": {
                "status": "conflicted",
                "repository": "heimgewebe/grabowski",
                "pr_number": 235,
                "subject_sha256": "a" * 64,
            },
            "checkout": {
                "status": "dirty",
                "dirty": True,
                "checkout_key": "chk-dirty",
                "subject_sha256": "b" * 64,
            },
        }
        req_dict, req_bytes, req_sha256 = convergence.build_pr_closure_request(
            evidence, observed_at="2026-07-22T22:00:00Z"
        )
        self.assertEqual(req_dict["observation"]["source_state"], "unknown")
        self.assertIn("conflicting_evidence:pr_merge", req_dict["classification"]["blocked_by"])
        self.assertIn("checkout_dirty", req_dict["classification"]["blocked_by"])
        self.assertIn("evidence_missing:deployment_live", req_dict["classification"]["blocked_by"])
        self.assertIn("evidence_missing:obligation", req_dict["classification"]["blocked_by"])
        self.assertNotIn("closure", req_dict)
        self.assertEqual(hashlib.sha256(req_bytes).hexdigest(), req_sha256)

    def test_missing_or_invalid_observed_at_fails_input(self):
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "observed_at"):
            convergence.build_pr_closure_request({}, observed_at=None)
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "observed_at"):
            convergence.build_pr_closure_request({}, observed_at="invalid-date")

    def test_invalid_subject_sha256_fails_input(self):
        bad_evidence = {
            "pr_merge": {
                "status": "merged",
                "subject_sha256": "NotALowercaseSha256"
            }
        }
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "subject_sha256"):
            convergence.build_pr_closure_request(bad_evidence, observed_at="2026-07-22T22:00:00Z")

    def test_invalid_change_class_fails_input(self):
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "change_class"):
            convergence.build_pr_closure_request(
                {}, observed_at="2026-07-22T22:00:00Z", change_class="invalid_class"
            )

    def test_source_state_never_partial_or_missing(self):
        req_dict, _, _ = convergence.build_pr_closure_request(
            {"pr_merge": {"status": "stale", "subject_sha256": "a" * 64}},
            observed_at="2026-07-22T22:00:00Z",
        )
        self.assertEqual(req_dict["observation"]["source_state"], "stale")
        self.assertNotIn(req_dict["observation"]["source_state"], ("partial", "missing"))

    def test_supplied_category_strings_do_not_synthesize_closure_or_effects(self):
        evidence = {
            "pr_merge": {"status": "merged", "subject_sha256": "a" * 64},
            "deployment_live": {"status": "live", "subject_sha256": "b" * 64},
            "obligation": {"status": "completed", "subject_sha256": "c" * 64},
            "checkout": {"status": "cleaned", "subject_sha256": "d" * 64},
        }
        req_dict, _, _ = convergence.build_pr_closure_request(evidence, observed_at="2026-07-22T22:00:00Z")
        self.assertEqual(req_dict["effects"], [])
        self.assertEqual(req_dict["verifications"], [])
        self.assertEqual(req_dict["observation"]["source_state"], "unknown")
        self.assertNotIn("closure", req_dict)

    def test_invalid_effect_or_verification_kinds_fail_before_evaluator(self):
        bad_effect = {
            "effects": [
                {"schema_version": 1, "kind": "invalid_kind", "evidence_ref": "ref", "subject_sha256": "a" * 64}
            ]
        }
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "not a valid v1 effect kind"):
            convergence.build_pr_closure_request(bad_effect, observed_at="2026-07-22T22:00:00Z")

        bad_verification = {
            "verifications": [
                {"schema_version": 1, "kind": "invalid_kind", "result": "pass", "evidence_ref": "ref", "subject_sha256": "a" * 64}
            ]
        }
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "not a valid v1 verification kind"):
            convergence.build_pr_closure_request(bad_verification, observed_at="2026-07-22T22:00:00Z")

    def test_no_invented_source_refs_uses_input_binding_ref(self):
        req_dict, _, _ = convergence.build_pr_closure_request({}, observed_at="2026-07-22T22:00:00Z")
        source_refs = req_dict["observation"]["source_refs"]
        self.assertEqual(len(source_refs), 1)
        self.assertEqual(source_refs[0]["kind"], "assessment_input")
        self.assertIn("input-binding reference only", req_dict["observation"]["claims"][-1])
        self.assertIn("source_truth_from_input_binding", req_dict["observation"]["does_not_establish"])

    def test_authoritative_receipts_requires_explicit_source_state(self):
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "authoritative_receipts requires an explicit source_state"):
            convergence.build_pr_closure_request(
                {},
                observed_at="2026-07-22T22:00:00Z",
                evidence_authority="authoritative_receipts",
            )
        with self.assertRaisesRegex(convergence.ConvergenceInputError, "evidence_authority must be"):
            convergence.build_pr_closure_request(
                {},
                observed_at="2026-07-22T22:00:00Z",
                evidence_authority="invalid_authority",
            )

    def test_real_regelkreis_conformance_and_evaluation(self):
        candidate = next(
            (
                parent / "konvergenzregelkreis"
                for parent in Path(__file__).resolve().parents
                if (parent / "konvergenzregelkreis").is_dir()
            ),
            None,
        )
        if candidate is None:
            self.skipTest("local konvergenzregelkreis checkout unavailable")
        executable = candidate / ".venv" / "bin" / "regelkreis"
        if not executable.is_file():
            self.skipTest("local regelkreis evaluator unavailable")

        def evaluate_with_real_cli(request: dict[str, object]) -> tuple[int, dict[str, object]]:
            with tempfile.TemporaryDirectory() as temp_dir:
                request_path = Path(temp_dir) / "assessment-request.json"
                request_path.write_text(
                    json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                result = convergence._default_evaluator_runner(
                    candidate,
                    [str(executable), "evaluate", str(request_path)],
                )
            self.assertIn(result["returncode"], {0, 2, 4, 5, 6})
            return int(result["returncode"]), json.loads(str(result["stdout"]))

        effects = [
            {"schema_version": 1, "kind": "merge", "evidence_ref": "github-pr:repo#1@sha", "subject_sha256": "a" * 64},
            {"schema_version": 1, "kind": "deployment", "evidence_ref": "release:rel-1", "subject_sha256": "b" * 64},
        ]
        verifications = [
            {"schema_version": 1, "kind": v, "result": "pass", "evidence_ref": f"ref-{v}", "subject_sha256": "c" * 64}
            for v in ["tests", "review", "ci", "deployment_identity", "runtime_identity", "service_health", "smoke_test", "negative_control"]
        ]
        closure = {
            "schema_version": 1,
            "closure_id": "cls-001",
            "status": "closed",
            "bureau_task_ref": "bureau:task:T123",
            "chronik_event_ref": "chronik:event:E123",
            "cleanup_evidence": ["grabowski:checkout:chk1"],
            "residual_risks": [],
        }
        evidence = {"effects": effects, "verifications": verifications, "closure": closure}

        req_supplied, _, _ = convergence.build_pr_closure_request(
            evidence,
            risk_level="R2",
            assessment_id="pr-closure-conf-supplied",
            observed_at="2026-07-22T22:00:00Z",
        )
        self.assertEqual(req_supplied["observation"]["source_state"], "unknown")
        self.assertIn(
            "supplied_evidence_requires_authoritative_read",
            req_supplied["classification"]["blocked_by"],
        )
        supplied_rc, eval_supplied = evaluate_with_real_cli(req_supplied)
        self.assertIn(supplied_rc, {5, 6})
        self.assertIn(eval_supplied["status"], {"source_stale", "blocked"})

        req_dict, _, _ = convergence.build_pr_closure_request(
            evidence,
            risk_level="R2",
            assessment_id="pr-closure-conf-1",
            observed_at="2026-07-22T22:00:00Z",
            evidence_authority="authoritative_receipts",
            source_state="current",
        )
        authoritative_rc, eval_res = evaluate_with_real_cli(req_dict)
        self.assertEqual(authoritative_rc, 0)
        self.assertEqual(eval_res["status"], "terminally_closed")

        req_no_closure, _, _ = convergence.build_pr_closure_request(
            {"effects": effects, "verifications": verifications},
            risk_level="R2",
            assessment_id="pr-closure-conf-2",
            observed_at="2026-07-22T22:00:00Z",
            evidence_authority="authoritative_receipts",
            source_state="current",
        )
        self.assertNotIn("closure", req_no_closure)
        missing_rc, eval_no_closure = evaluate_with_real_cli(req_no_closure)
        self.assertIn(missing_rc, {2, 6})
        self.assertIn(eval_no_closure["status"], {"evidence_missing", "blocked"})


if __name__ == "__main__":
    unittest.main()


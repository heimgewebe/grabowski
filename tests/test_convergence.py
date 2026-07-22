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
        evidence = {
            "pr_merge": {
                "status": "merged",
                "repository": "heimgewebe/grabowski",
                "pr_number": 235,
                "evidence_ref": "github-pr:heimgewebe/grabowski#235@0b09e6d7dfdb",
                "subject_sha256": "a" * 64,
            },
            "deployment_live": {
                "status": "live",
                "release_id": "rel-123",
                "evidence_ref": "grabowski-release:rel-123",
                "subject_sha256": "b" * 64,
            },
            "obligation": {
                "status": "completed",
                "obligation_id": "goo-12345678",
                "bureau_task_ref": "bureau:task:T001:verified",
                "subject_sha256": "c" * 64,
            },
            "checkout": {
                "status": "cleaned",
                "checkout_key": "chk-main",
                "evidence_ref": "grabowski:checkout:chk-main",
                "subject_sha256": "d" * 64,
            },
        }
        req_dict, req_bytes, req_sha256 = convergence.build_pr_closure_request(
            evidence, risk_level="R2", assessment_id="pr-closure-test-1"
        )
        self.assertEqual(req_dict["schema_version"], 1)
        self.assertEqual(req_dict["risk_level"], "R2")
        self.assertEqual(req_dict["classification"]["change_class"], "pr_closure")
        self.assertEqual(req_dict["classification"]["blocked_by"], [])
        self.assertEqual(req_dict["observation"]["source_state"], "current")
        self.assertIn("closure", req_dict)
        self.assertEqual(req_dict["closure"]["status"], "closed")
        self.assertEqual(hashlib.sha256(req_bytes).hexdigest(), req_sha256)

    def test_build_pr_closure_request_missing_and_conflicting_evidence(self):
        evidence = {
            "pr_merge": {
                "status": "conflicted",
                "repository": "heimgewebe/grabowski",
                "pr_number": 235,
            },
            "checkout": {
                "status": "dirty",
                "dirty": True,
                "checkout_key": "chk-dirty",
            },
        }
        req_dict, req_bytes, req_sha256 = convergence.build_pr_closure_request(evidence)
        self.assertEqual(req_dict["observation"]["source_state"], "partial")
        self.assertIn("conflicting_evidence:pr_merge", req_dict["classification"]["blocked_by"])
        self.assertIn("checkout_dirty", req_dict["classification"]["blocked_by"])
        self.assertIn("evidence_missing:deployment_live", req_dict["classification"]["blocked_by"])
        self.assertIn("evidence_missing:obligation", req_dict["classification"]["blocked_by"])
        self.assertNotIn("closure", req_dict)
        self.assertEqual(hashlib.sha256(req_bytes).hexdigest(), req_sha256)


if __name__ == "__main__":
    unittest.main()


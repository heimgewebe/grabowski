from __future__ import annotations
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock
ROOT = Path(__file__).resolve().parents[1]
def _load_gate():
    spec = importlib.util.spec_from_file_location("grabowski_pr_review_gate_redaction_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
pr_review_gate = _load_gate()
class PrReviewGateRedactionTests(unittest.TestCase):
    def test_json_output_redacts_diagnostics_without_mutating_gate_result(self) -> None:
        password = "correct-horse-battery-staple"
        github_token = "ghp_" + "A" * 32
        head = "a" * 40
        result = {"schema_version": 1, "verdict": "BLOCK", "failures": [f"password={password}"], "warnings": [f"Authorization: Bearer {github_token}"], "repo_pr": {"head_sha": head}}
        state = {"repoName": "heimgewebe/grabowski", "pr": {"headRefOid": head, "baseRefOid": "b" * 40}}
        stdout = io.StringIO()
        with (
            mock.patch.object(pr_review_gate, "load_self_review", return_value=None),
            mock.patch.object(pr_review_gate, "load_claude_evidence", return_value=None),
            mock.patch.object(pr_review_gate, "load_external_review_evidence", return_value=None),
            mock.patch.object(pr_review_gate, "load_policy_waiver", return_value=None),
            mock.patch.object(pr_review_gate, "load_pr_state", return_value=state),
            mock.patch.object(pr_review_gate, "expected_check_names_for_repo", return_value=()),
            mock.patch.object(pr_review_gate, "evaluate_review_gate", return_value=result),
            contextlib.redirect_stdout(stdout),
        ):
            rc = pr_review_gate.main(["--pr", "880", "--json"])
        self.assertEqual(rc, 2)
        output = stdout.getvalue()
        payload = json.loads(output)
        self.assertEqual(payload["failures"], ["[REDACTED]"])
        self.assertEqual(payload["warnings"], ["[REDACTED]"])
        self.assertEqual(payload["repo_pr"]["head_sha"], head)
        self.assertNotIn(password, output)
        self.assertNotIn(github_token, output)
        self.assertEqual(result["failures"], [f"password={password}"])
        self.assertEqual(result["warnings"], [f"Authorization: Bearer {github_token}"])

class PrReviewGateSourceHardeningTests(unittest.TestCase):
    def test_text_command_failure_does_not_forward_stderr(self) -> None:
        sensitive_value = "SENTINEL_PAYLOAD_123"
        completed = mock.Mock(returncode=1, stdout="", stderr=sensitive_value)
        with (
            mock.patch.object(pr_review_gate.shutil, "which", return_value="/usr/bin/gh"),
            mock.patch.object(pr_review_gate.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(
                RuntimeError, r"^command failed: gh pr view 880$"
            ) as raised:
                pr_review_gate._run_text(ROOT, ["gh", "pr", "view", "880"])
        self.assertNotIn(sensitive_value, str(raised.exception))

    def test_binary_command_failure_does_not_forward_stderr(self) -> None:
        sensitive_value = b"SENTINEL_PAYLOAD_456"
        completed = mock.Mock(returncode=1, stdout=b"", stderr=sensitive_value)
        with (
            mock.patch.object(pr_review_gate.shutil, "which", return_value="/usr/bin/gh"),
            mock.patch.object(pr_review_gate.subprocess, "run", return_value=completed),
        ):
            with self.assertRaisesRegex(
                RuntimeError, r"^command failed: gh pr diff 880$"
            ) as raised:
                pr_review_gate._run_bytes(ROOT, ["gh", "pr", "diff", "880"])
        self.assertNotIn(sensitive_value.decode(), str(raised.exception))

    def test_unexpected_exception_is_not_serialized(self) -> None:
        sensitive_value = "SENTINEL_PAYLOAD_789"
        stdout = io.StringIO()
        with (
            mock.patch.object(pr_review_gate, "load_self_review", return_value=None),
            mock.patch.object(pr_review_gate, "load_claude_evidence", return_value=None),
            mock.patch.object(
                pr_review_gate, "load_external_review_evidence", return_value=None
            ),
            mock.patch.object(pr_review_gate, "load_policy_waiver", return_value=None),
            mock.patch.object(
                pr_review_gate, "load_pr_state", side_effect=RuntimeError(sensitive_value)
            ),
            contextlib.redirect_stdout(stdout),
        ):
            rc = pr_review_gate.main(["--pr", "880", "--json"])
        self.assertEqual(rc, 2)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["failures"], ["review gate evaluation failed"])
        self.assertNotIn(sensitive_value, stdout.getvalue())

if __name__ == "__main__":
    unittest.main()

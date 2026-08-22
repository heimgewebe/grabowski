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
if __name__ == "__main__":
    unittest.main()

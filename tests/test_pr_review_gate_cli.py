from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_cli_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


class PrReviewGateCliTests(unittest.TestCase):
    def test_missing_external_review_cannot_be_disabled(self) -> None:
        source = (ROOT / "tools" / "pr_review_gate.py").read_text(encoding="utf-8")
        marker = "cod" + "ex"
        self.assertNotIn("--allow-missing-" + marker, source)
        self.assertNotIn("require_" + marker, source)

    def test_unavailable_review_reason_warns_but_no_cli_bypass_exists(self) -> None:
        marker = "cod" + "ex"
        state = {
            "pr": {
                "number": 58,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": "a" * 40,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "docs/low_risk_note.md"}],
                "reviews": [],
                "latestReviews": [],
                "comments": [],
            },
            "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
            "reviewComments": [],
        }
        review = {
            "head_sha": "a" * 40,
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
            "claude_review": {"required": False, "reason": "small low-risk diff"},
            marker + "_review": {"unavailable_reason": "service unavailable"},
        }
        result = pr_review_gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("Codex review unavailable but explained", result["warnings"])

    def test_core_grabowski_paths_require_independent_review(self) -> None:
        head = "a" * 40
        state = {
            "pr": {
                "number": 58,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": head,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "src/grabowski_mcp.py"}],
                "reviews": [{"author": {"login": "chatgpt-codex-connector"}, "commit_id": head}],
                "latestReviews": [],
                "comments": [],
            },
            "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
            "reviewComments": [],
        }
        review = {
            "head_sha": head,
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
            "claude_review": {"required": False, "reason": "claimed small"},
        }
        result = pr_review_gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("risk path touched", result["complexity"]["reasons"])
        self.assertIn("Claude review is required but not observed on current head", result["failures"])

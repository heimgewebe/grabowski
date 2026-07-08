from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_risk_paths_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


def _state(path: str) -> dict:
    return {
        "repoName": "heimgewebe/grabowski",
        "pr": {
            "number": 58,
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 3,
            "deletions": 1,
            "files": [{"path": path}],
            "reviews": [{"author": {"login": "chatgpt-codex-connector"}, "commit_id": HEAD}],
            "latestReviews": [],
            "comments": [],
        },
        "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
        "reviewComments": [],
    }


def _self_review(path: str) -> dict:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "repo": "heimgewebe/grabowski",
        "pr": 58,
        "head_sha": HEAD,
        "reviewed_files": [path],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "claude_review": {"required": False, "reason": "claimed small diff"},
    }


class PrReviewGateRiskPathExpansionTests(unittest.TestCase):
    def test_mutating_runtime_support_modules_require_independent_review(self) -> None:
        for path in (
            "src/grabowski_tasks.py",
            "src/grabowski_checkouts.py",
            "src/grabowski_operations.py",
            "src/grabowski_artifacts.py",
        ):
            with self.subTest(path=path):
                result = pr_review_gate.evaluate_review_gate(_state(path), self_review=_self_review(path))
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertTrue(result["complexity"]["high_critical"])
                self.assertTrue(
                    any("high-critical Grabowski operator path touched" in reason for reason in result["complexity"]["reasons"]),
                    result["complexity"]["reasons"],
                )
                self.assertIn(
                    "External review evidence invalid: external review is required but evidence is missing",
                    result["failures"],
                )


if __name__ == "__main__":
    unittest.main()

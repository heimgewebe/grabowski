from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
DIFF_SHA = "0" * 64
OTHER_DIFF_SHA = "1" * 64


def _load_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_self_diff_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _state(*, diff_sha: str | None = DIFF_SHA, diff_error: str | None = None) -> dict[str, object]:
    state: dict[str, object] = {
        "repoName": "heimgewebe/grabowski",
        "pr_diff_required": True,
        "pr": {
            "number": 88,
            "title": "docs: example",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": "b" * 40,
            "changedFiles": 1,
            "additions": 1,
            "deletions": 0,
            "files": [{"path": "docs/example.md"}],
            "reviews": [{"author": {"login": "chatgpt-codex-connector"}, "state": "APPROVED", "commit_id": HEAD}],
            "latestReviews": [],
            "comments": [],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }
    if diff_sha is not None:
        state["pr_diff_sha256"] = diff_sha
    if diff_error is not None:
        state["pr_diff_error"] = diff_error
    return state


def _self_review(*, diff_sha: str | None = DIFF_SHA) -> dict[str, object]:
    review: dict[str, object] = {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "repo": "heimgewebe/grabowski",
        "pr": 88,
        "head_sha": HEAD,
        "reviewed_files": ["docs/example.md"],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "current diff reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "small non-risk diff"},
    }
    if diff_sha is not None:
        review["diff_sha256"] = diff_sha
    return review


def _has_failure(result: dict[str, object], needle: str) -> bool:
    return any(needle in str(item) for item in result.get("failures", []))


class SelfReviewDiffBindingTests(unittest.TestCase):
    def test_matching_self_review_diff_hash_passes(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_diff_bound"])

    def test_missing_self_review_diff_hash_blocks(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review diff_sha256 is missing or invalid"), result["failures"])

    def test_mismatching_self_review_diff_hash_blocks(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review(diff_sha=OTHER_DIFF_SHA))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review diff_sha256 mismatch"), result["failures"])

    def test_unavailable_current_diff_hash_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state(diff_sha=None, diff_error="gh pr diff failed"),
            self_review=_self_review(),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "current PR diff hash is unavailable: gh pr diff failed"), result["failures"])

    def test_state_without_required_flag_still_enforces_diff_binding(self) -> None:
        state = _state()
        state.pop("pr_diff_required")
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review diff_sha256 is missing or invalid"), result["failures"])

    def test_explicit_bypass_requires_reason(self) -> None:
        state = _state(diff_sha=None)
        state["pr_diff_bypass"] = True
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "self-review diff binding bypass requires pr_diff_bypass_reason='legacy unit seam without live PR diff'"),
            result["failures"],
        )

    def test_explicit_bypass_with_reason_passes_legacy_unit_seam(self) -> None:
        state = _state(diff_sha=None)
        state["pr_diff_bypass"] = True
        state["pr_diff_bypass_reason"] = "legacy unit seam without live PR diff"
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["self_review_diff_bound"])

    def test_self_review_diff_hash_accepts_uppercase_and_whitespace(self) -> None:
        result = gate.evaluate_review_gate(
            _state(diff_sha=DIFF_SHA),
            self_review=_self_review(diff_sha=f"  {DIFF_SHA.upper()}\n"),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_diff_bound"])

    def test_explicit_bypass_is_reported(self) -> None:
        state = _state(diff_sha=None)
        state["pr_diff_bypass"] = True
        state["pr_diff_bypass_reason"] = "legacy unit seam without live PR diff"
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_diff_bypass_used"])
        self.assertIn("Self-review diff binding bypass was requested", result["warnings"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
DIFF_SHA = "c" * 64


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_trusted_actors_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


def _self_review() -> dict:
    return {
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "head_sha": HEAD,
        "reviewed_files": ["docs/low_risk_note.md"],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_sha256": DIFF_SHA,
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "claude_review": {"required": False, "reason": "small low-risk diff"},
    }


def _state(*, actor: str = "chatgpt-codex-connector", merge_state: str = "CLEAN", mergeable: str = "MERGEABLE") -> dict:
    return {
        "pr": {
            "number": 58,
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": merge_state,
            "mergeable": mergeable,
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 1,
            "deletions": 0,
            "files": [{"path": "docs/low_risk_note.md"}],
            "reviews": [{"author": {"login": actor}, "commit_id": HEAD}],
            "latestReviews": [],
            "comments": [],
        },
        "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
        "reviewComments": [],
        "pr_diff_sha256": DIFF_SHA,
    }


class PrReviewGateTrustedActorsTests(unittest.TestCase):
    def test_merge_state_status_must_be_clean(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_state(merge_state="BLOCKED"), self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeStateStatus is BLOCKED, not CLEAN", result["failures"])


    def test_mergeable_must_be_mergeable(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_state(mergeable="UNKNOWN"), self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeable is UNKNOWN, not MERGEABLE", result["failures"])


    def test_optional_skipped_check_does_not_block_when_expected_checks_pass(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "skipping", "name": "claude"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "PASS")

    def test_skipped_expected_check_blocks(self) -> None:
        state = _state()
        state["checks"] = [
            {"bucket": "skipping", "name": "validate (3.10)"},
            {"bucket": "pass", "name": "validate (3.12)"},
        ]

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "expected check(s) missing or non-green: validate (3.10)",
            result["failures"],
        )

    def test_optional_failed_check_still_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "fail", "name": "claude"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_unknown_skipped_check_still_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "skipping", "name": "unknown-required"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_non_green_duplicate_expected_check_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "fail", "name": "validate (3.10)"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "expected check(s) missing or non-green: validate (3.10)",
            result["failures"],
        )
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_skipped_duplicate_expected_check_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "skipping", "name": "validate (3.12)"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "expected check(s) missing or non-green: validate (3.12)",
            result["failures"],
        )
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_untrusted_codex_substring_actor_does_not_satisfy_explicit_codex_requirement(self) -> None:
        state = _state(actor="friendly-codex-bot")
        state["pr_diff_bypass"] = True
        state["pr_diff_bypass_reason"] = "legacy unit seam without live PR diff"
        review = _self_review()
        review["codex_review"] = {"required": True, "reason": "explicit check"}
        result = pr_review_gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("Codex review is explicitly required but not observed on current head", result["failures"])


if __name__ == "__main__":
    unittest.main()

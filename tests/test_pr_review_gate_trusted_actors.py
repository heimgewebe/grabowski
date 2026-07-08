from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40


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
        "head_sha": HEAD,
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

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40


def _load_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _review(actor: str, *, state: str = "APPROVED", head: str = HEAD) -> dict[str, object]:
    return {"author": {"login": actor}, "state": state, "commit_id": head}


def _state(*, files: list[str] | None = None, additions: int = 3, deletions: int = 1) -> dict[str, object]:
    paths = files or ["README.md"]
    return {
        "repoName": "heimgewebe/grabowski",
        "pr": {
            "number": 7,
            "title": "Gate test",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": "b" * 40,
            "url": "https://example.test/pull/7",
            "changedFiles": len(paths),
            "additions": additions,
            "deletions": deletions,
            "files": [{"path": path} for path in paths],
            "reviews": [
                _review("chatgpt-codex-connector"),
                _review("claude[bot]"),
            ],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }


def _self_review(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "head_sha": HEAD,
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "diff reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "small non-risk diff"},
        "external_review": {"required": False, "reason": "small non-risk diff"},
    }
    payload.update(overrides)
    return payload


def _external_review(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "required": True,
        "diff_prompt_provided": True,
        "prompt_head_sha": HEAD,
        "prompt_includes_diff": True,
        "external_reviews_triaged": True,
        "reviews_received": 1,
        "findings": [],
    }
    payload.update(overrides)
    return payload


class ExternalReviewGateTests(unittest.TestCase):
    def test_complex_change_requires_external_review_evidence(self) -> None:
        review = _self_review(external_review=None)
        result = gate.evaluate_review_gate(_state(files=["tools/pr_review_gate.py"]), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "External review evidence invalid: external review is required but evidence is missing",
            result["failures"],
        )

    def test_complex_change_accepts_external_review_evidence(self) -> None:
        review = _self_review(external_review=_external_review())
        result = gate.evaluate_review_gate(_state(files=["tools/pr_review_gate.py"]), self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["external_review_required"])
        self.assertEqual(result["review_sources"]["external_reviews_received"], 1)

    def test_required_external_review_rejects_untriaged_findings(self) -> None:
        review = _self_review(
            external_review=_external_review(
                findings=[
                    {
                        "status": "accepted",
                        "severity": "p1",
                        "materiality": "blocking",
                        "reason": "left for later",
                    }
                ]
            )
        )
        result = gate.evaluate_review_gate(_state(files=["tools/pr_review_gate.py"]), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "External review evidence invalid: external_review finding 0 is not terminally triaged",
            result["failures"],
        )

    def test_optional_external_review_still_rejects_untriaged_findings(self) -> None:
        review = _self_review(
            external_review={
                "required": False,
                "reason": "small non-risk diff",
                "findings": [
                    {
                        "status": "accepted",
                        "severity": "p1",
                        "materiality": "blocking",
                        "reason": "left for later",
                    }
                ],
            }
        )
        result = gate.evaluate_review_gate(_state(), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "External review evidence invalid: external_review finding 0 is not terminally triaged",
            result["failures"],
        )

    def test_trivial_change_can_record_external_review_not_required(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["external_review_required"])


if __name__ == "__main__":
    unittest.main()

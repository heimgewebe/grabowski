from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
DIFF_SHA = "0" * 64
PROMPT_SHA = "1" * 64
REVIEW_SHA = "2" * 64


def _load_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _state(path: str = "README.md", *, diff_sha: str | None = DIFF_SHA) -> dict[str, object]:
    state: dict[str, object] = {
        "repoName": "heimgewebe/grabowski",
        "pr": {
            "number": 7,
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": "b" * 40,
            "changedFiles": 1,
            "additions": 3,
            "deletions": 1,
            "files": [{"path": path}],
            "reviews": [
                {"author": {"login": "chatgpt-codex-connector"}, "state": "APPROVED", "commit_id": HEAD},
                {"author": {"login": "claude[bot]"}, "state": "APPROVED", "commit_id": HEAD},
            ],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }
    if diff_sha is not None:
        state["pr_diff_sha256"] = diff_sha
    return state


def _self_review() -> dict[str, object]:
    return {
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
    }


def _external(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema_version": 1,
        "kind": "external_review",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "prompt_sha256": PROMPT_SHA,
        "prompt_includes_diff": True,
        "reviews": [{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 0}],
        "external_reviews_triaged": True,
        "findings": [],
    }
    data.update(overrides)
    return data


def _has_failure(result: dict[str, object], needle: str) -> bool:
    return any(needle in str(item) for item in result.get("failures", []))


class ExternalReviewGateTests(unittest.TestCase):
    def test_complex_risk_path_without_external_evidence_blocks(self) -> None:
        result = gate.evaluate_review_gate(_state("tools/pr_review_gate.py"), self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])

    def test_complex_risk_path_with_valid_external_evidence_passes(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["external_review_required"])
        self.assertEqual(result["review_sources"]["external_reviews_received"], 1)

    def test_invalid_external_evidence_cases_block(self) -> None:
        cases = [
            ("required false", _state("tools/pr_review_gate.py"), _external(required=False), "required=false cannot disable"),
            ("wrong head", _state("tools/pr_review_gate.py"), _external(head_sha="b" * 40), "head_sha mismatch"),
            ("wrong diff", _state("tools/pr_review_gate.py"), _external(diff_sha256="3" * 64), "diff_sha256 mismatch"),
            ("missing diff", _state("tools/pr_review_gate.py", diff_sha=None), _external(), "current PR diff hash is unavailable"),
            ("invalid prompt", _state("tools/pr_review_gate.py"), _external(prompt_sha256="not-a-sha"), "prompt_sha256 is missing or invalid"),
            ("empty reviews", _state("tools/pr_review_gate.py"), _external(reviews=[]), "reviews must be non-empty"),
            ("reviews not list", _state("tools/pr_review_gate.py"), _external(reviews={"source": "chatgpt"}), "reviews is not a list"),
            ("bool finding count", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": True}]), "finding_count must be an integer"),
            ("not triaged", _state("tools/pr_review_gate.py"), _external(external_reviews_triaged=False), "external_reviews_triaged is not true"),
            ("findings not list", _state("tools/pr_review_gate.py"), _external(findings={"status": "fixed"}), "findings is not a list"),
            ("untriaged finding", _state("tools/pr_review_gate.py"), _external(findings=[{"status": "open", "severity": "low"}]), "external_review finding 0 is not terminally triaged"),
        ]
        for name, state, evidence, needle in cases:
            with self.subTest(name=name):
                result = gate.evaluate_review_gate(state, self_review=_self_review(), external_review_evidence=evidence)
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertTrue(_has_failure(result, needle), result["failures"])

    def test_trivial_change_without_external_evidence_passes(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["external_review_required"])

    def test_trivial_change_with_voluntary_untriaged_external_finding_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state(),
            self_review=_self_review(),
            external_review_evidence=_external(findings=[{"status": "open", "severity": "low"}]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external_review finding 0 is not terminally triaged"), result["failures"])


if __name__ == "__main__":
    unittest.main()

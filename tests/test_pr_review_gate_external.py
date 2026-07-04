from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
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


def _terminal_external_finding() -> dict[str, object]:
    return {
        "status": "fixed",
        "severity": "p2",
        "materiality": "material",
        "reason": "addressed in follow-up patch",
    }


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


    def test_complex_risk_path_block_verdict_without_terminal_finding_coverage_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "BLOCK", "finding_count": 0}],
                external_reviews_triaged=True,
                findings=[],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review 0 verdict is BLOCK without terminal finding coverage"), result["failures"])

    def test_complex_risk_path_needs_change_without_terminal_finding_coverage_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "NEEDS_CHANGE", "finding_count": 0}],
                external_reviews_triaged=True,
                findings=[],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review 0 verdict is NEEDS_CHANGE without terminal finding coverage"), result["failures"])

    def test_complex_risk_path_pass_with_reported_finding_without_terminal_finding_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 1}],
                external_reviews_triaged=True,
                findings=[],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external reviews report 1 finding(s) but only 0 terminal finding(s) are recorded"), result["failures"])

    def test_complex_risk_path_reported_finding_with_matching_terminal_finding_passes(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 1}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_complex_risk_path_two_reported_findings_with_one_terminal_finding_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 2}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external reviews report 2 finding(s) but only 1 terminal finding(s) are recorded"), result["failures"])

    def test_complex_risk_path_needs_change_requires_matching_terminal_finding_count(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "NEEDS_CHANGE", "finding_count": 2}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external reviews report 2 finding(s) but only 1 terminal finding(s) are recorded"), result["failures"])

        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "NEEDS_CHANGE", "finding_count": 2}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding(), _terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_complex_risk_path_block_zero_count_passes_with_one_terminal_finding(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "BLOCK", "finding_count": 0}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_sha256_normalization_accepts_uppercase_and_whitespace(self) -> None:
        diff_sha = "ab" * 32
        prompt_sha = "cd" * 32
        review_sha = "ef" * 32
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py", diff_sha=diff_sha),
            self_review=_self_review(),
            external_review_evidence=_external(
                diff_sha256=f"  {diff_sha.upper()}\n",
                prompt_sha256=f"\t{prompt_sha.upper()}  ",
                reviews=[
                    {
                        "source": "chatgpt",
                        "review_sha256": f"  {review_sha.upper()}\t",
                        "verdict": "PASS",
                        "finding_count": 0,
                    }
                ],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_mixed_review_counts_require_two_terminal_findings(self) -> None:
        reviews = [
            {"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 1},
            {"source": "claude", "review_sha256": "3" * 64, "verdict": "BLOCK", "finding_count": 0},
        ]
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(reviews=reviews, findings=[_terminal_external_finding()]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "external reviews report 2 finding(s) but only 1 terminal finding(s) are recorded"),
            result["failures"],
        )

        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(
                reviews=reviews,
                findings=[_terminal_external_finding(), _terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_deprecated_embedded_external_review_does_not_satisfy_complex_path(self) -> None:
        self_review = _self_review()
        self_review["external_review"] = _external()
        result = gate.evaluate_review_gate(_state("tools/pr_review_gate.py"), self_review=self_review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])
        self.assertIn(
            "Deprecated self_review.external_review ignored; pass --external-review-evidence instead",
            result["warnings"],
        )
        self.assertIsNone(result["review_sources"]["external_reviews_received"])

    def test_trivial_embedded_external_review_is_ignored_with_warning(self) -> None:
        self_review = _self_review()
        self_review["external_review"] = _external()
        result = gate.evaluate_review_gate(_state(), self_review=self_review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "Deprecated self_review.external_review ignored; pass --external-review-evidence instead",
            result["warnings"],
        )
        self.assertIsNone(result["review_sources"]["external_reviews_received"])

    def test_json_evidence_file_size_limit_blocks_all_loaders(self) -> None:
        loaders = [
            ("self-review", gate.load_self_review, "self-review.json"),
            ("Claude evidence", gate.load_claude_evidence, "claude.json"),
            ("external review evidence", gate.load_external_review_evidence, "external-review.json"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            for label, loader, filename in loaders:
                with self.subTest(label=label):
                    path = Path(tmpdir) / filename
                    path.write_text("{" + (" " * gate.MAX_JSON_EVIDENCE_BYTES) + "}", encoding="utf-8")
                    with self.assertRaisesRegex(gate.GateInputError, f"{label} file exceeds"):
                        loader(path)

    def test_missing_current_diff_hash_reports_error_detail(self) -> None:
        state = _state("tools/pr_review_gate.py", diff_sha=None)
        state["pr_diff_error"] = "gh pr diff failed"
        result = gate.evaluate_review_gate(state, self_review=_self_review(), external_review_evidence=_external())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "current PR diff hash is unavailable: gh pr diff failed"),
            result["failures"],
        )

    def test_invalid_external_evidence_cases_block(self) -> None:
        cases = [
            ("required false", _state("tools/pr_review_gate.py"), _external(required=False), "required=false cannot disable"),
            ("required string false", _state("tools/pr_review_gate.py"), _external(required="false"), "external_review.required must be a bool"),
            ("required zero", _state("tools/pr_review_gate.py"), _external(required=0), "external_review.required must be a bool"),
            ("bool schema version", _state("tools/pr_review_gate.py"), _external(schema_version=True), "schema_version is not integer 1"),
            ("bool pr number", _state("tools/pr_review_gate.py"), _external(pr=True), "pr number mismatch"),
            ("string pr number", _state("tools/pr_review_gate.py"), _external(pr="7"), "pr number mismatch"),
            ("wrong head", _state("tools/pr_review_gate.py"), _external(head_sha="b" * 40), "head_sha mismatch"),
            ("wrong diff", _state("tools/pr_review_gate.py"), _external(diff_sha256="3" * 64), "diff_sha256 mismatch"),
            ("missing diff", _state("tools/pr_review_gate.py", diff_sha=None), _external(), "current PR diff hash is unavailable"),
            ("invalid prompt", _state("tools/pr_review_gate.py"), _external(prompt_sha256="not-a-sha"), "prompt_sha256 is missing or invalid"),
            ("empty reviews", _state("tools/pr_review_gate.py"), _external(reviews=[]), "reviews must be non-empty"),
            ("reviews not list", _state("tools/pr_review_gate.py"), _external(reviews={"source": "chatgpt"}), "reviews is not a list"),
            ("bool finding count", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": True}]), "finding_count must be an integer"),
            ("non-string source", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": 123, "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 0}]), "source is missing"),
            ("non-string verdict", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": 123, "finding_count": 0}]), "verdict is invalid"),
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

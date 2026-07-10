from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
DIFF_SHA = "0" * 64
REVIEW_FOCUS = ["correctness", "regression_risk", "tests", "security", "integration"]


def _load_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_self_depth_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _state(
    path: str = "docs/example.md",
    *,
    repo: str = "heimgewebe/grabowski",
    additions: int = 1,
    deletions: int = 0,
    changed_files: int = 1,
) -> dict[str, object]:
    return {
        "repoName": repo,
        "pr_diff_sha256": DIFF_SHA,
        "pr_diff_text": "diff --git a/x b/x\n",
        "pr": {
            "number": 7,
            "title": "test change",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": changed_files,
            "additions": additions,
            "deletions": deletions,
            "files": [{"path": path}],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }


def _iterations(count: int, *, first_material: int = 0) -> list[dict[str, object]]:
    return [
        {
            "n": n,
            "summary": f"review pass {n}",
            "material_findings": first_material if n == 1 else 0,
        }
        for n in range(1, count + 1)
    ]


def _self_review(
    path: str = "docs/example.md",
    *,
    repo: str = "heimgewebe/grabowski",
    iterations: int = 1,
    uncertainty: float = 0.1,
    material_after_first: int = 0,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "reviewer": "grabowski-self",
        "repo": repo,
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "diff_reviewed": True,
        "reviewed_files": [path],
        "review_focus": REVIEW_FOCUS,
        "verdict": "PASS",
        "review_iterations": _iterations(
            iterations, first_material=material_after_first
        ),
        "all_findings_triaged": True,
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": material_after_first,
        "uncertainty": uncertainty,
        "stop_reason": "clean_pass",
        "residual_risk": {"accepted": False, "reason": ""},
    }


def _has_failure(result: dict[str, object], needle: str) -> bool:
    return any(needle in str(item) for item in result.get("failures", []))


class SelfReviewDepthPolicyTests(unittest.TestCase):
    def test_documentation_change_requires_one_self_review_iteration(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["review_tier"], "documentation")
        self.assertEqual(result["complexity"]["minimum_self_review_iterations"], 1)
        self.assertFalse(result["review_sources"]["external_review_required"])
        self.assertFalse(result["review_sources"]["claude_cli_required"])

    def test_large_documentation_change_requires_two_iterations(self) -> None:
        state = _state("docs/large-guide.md", additions=600)
        blocked = gate.evaluate_review_gate(
            state,
            self_review=_self_review("docs/large-guide.md", iterations=1),
        )
        self.assertEqual(blocked["verdict"], "BLOCK")
        self.assertEqual(blocked["complexity"]["review_tier"], "standard")
        self.assertTrue(blocked["complexity"]["large_documentation_change"])
        self.assertTrue(_has_failure(blocked, "minimum 2"), blocked["failures"])

    def test_very_small_code_change_requires_one_iteration(self) -> None:
        state = _state("src/tiny_feature.py", additions=4, deletions=1)
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review("src/tiny_feature.py"),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["review_tier"], "very_small")
        self.assertEqual(result["complexity"]["minimum_self_review_iterations"], 1)

    def test_standard_change_requires_two_iterations(self) -> None:
        state = _state("src/feature.py", additions=45)
        blocked = gate.evaluate_review_gate(
            state,
            self_review=_self_review("src/feature.py", iterations=1),
        )
        self.assertEqual(blocked["verdict"], "BLOCK")
        self.assertTrue(_has_failure(blocked, "minimum 2"), blocked["failures"])
        passed = gate.evaluate_review_gate(
            state,
            self_review=_self_review("src/feature.py", iterations=2),
        )
        self.assertEqual(passed["verdict"], "PASS")
        self.assertEqual(passed["complexity"]["review_tier"], "standard")

    def test_important_repository_requires_three_iterations_without_external_review(self) -> None:
        state = _state(
            "src/tiny_feature.py",
            repo="heimgewebe/weltgewebe",
            additions=4,
            deletions=1,
        )
        blocked = gate.evaluate_review_gate(
            state,
            self_review=_self_review(
                "src/tiny_feature.py",
                repo="heimgewebe/weltgewebe",
                iterations=2,
            ),
        )
        self.assertEqual(blocked["verdict"], "BLOCK")
        self.assertTrue(_has_failure(blocked, "minimum 3"), blocked["failures"])
        passed = gate.evaluate_review_gate(
            state,
            self_review=_self_review(
                "src/tiny_feature.py",
                repo="heimgewebe/weltgewebe",
                iterations=3,
            ),
        )
        self.assertEqual(passed["verdict"], "PASS")
        self.assertEqual(passed["complexity"]["review_tier"], "important_repo")
        self.assertFalse(passed["review_sources"]["external_review_required"])

    def test_high_critical_path_requires_four_iterations(self) -> None:
        state = _state("tools/pr_review_gate.py")
        blocked = gate.evaluate_review_gate(
            state,
            self_review=_self_review("tools/pr_review_gate.py", iterations=3),
        )
        self.assertEqual(blocked["verdict"], "BLOCK")
        self.assertTrue(_has_failure(blocked, "minimum 4"), blocked["failures"])
        passed = gate.evaluate_review_gate(
            state,
            self_review=_self_review("tools/pr_review_gate.py", iterations=4),
        )
        self.assertEqual(passed["verdict"], "PASS")
        self.assertEqual(passed["complexity"]["review_tier"], "high_critical")

    def test_multiple_critical_signals_raise_depth_to_five(self) -> None:
        state = _state("tools/pr_review_gate.py", additions=700, changed_files=16)
        state["pr"]["files"] = [
            {"path": "tools/pr_review_gate.py"},
            *[{"path": f"src/file_{n}.py"} for n in range(15)],
        ]
        review = _self_review("tools/pr_review_gate.py", iterations=5)
        review["reviewed_files"] = [
            "tools/pr_review_gate.py",
            *[f"src/file_{n}.py" for n in range(15)],
        ]
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["minimum_self_review_iterations"], 5)

    def test_uncertainty_can_raise_standard_change_to_high_critical(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=4, uncertainty=0.5)
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["review_tier"], "high_critical")
        self.assertIn("high review uncertainty", result["complexity"]["reasons"])

    def test_many_first_pass_findings_raise_depth(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review(
            "src/feature.py",
            iterations=4,
            material_after_first=4,
        )
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "many material findings after first review",
            result["complexity"]["reasons"],
        )

    def test_iteration_numbers_must_be_consecutive(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=2)
        review["review_iterations"] = [
            {"n": 1, "summary": "first", "material_findings": 0},
            {"n": 3, "summary": "third", "material_findings": 0},
        ]
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "consecutive from 1"), result["failures"])

    def test_invalid_uncertainty_blocks_audit_quality(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=2)
        review["uncertainty"] = 1.2
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "uncertainty must be a finite number from 0 to 1"),
            result["failures"],
        )

    def test_first_pass_metric_must_match_first_iteration(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=2)
        review["material_findings_after_first_review"] = 1
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "does not match iteration 1"), result["failures"]
        )

    def test_duplicate_iteration_summaries_do_not_count_as_distinct_loops(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=2)
        review["review_iterations"] = [
            {"n": 1, "summary": "same pass", "material_findings": 0},
            {"n": 2, "summary": "  SAME   PASS  ", "material_findings": 0},
        ]
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "summaries must be distinct"), result["failures"])

    def test_external_review_is_optional_and_missing_evidence_does_not_block(self) -> None:
        state = _state("tools/pr_review_gate.py")
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review("tools/pr_review_gate.py", iterations=4),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["external_review_required"])

    def test_invalid_optional_external_evidence_warns_but_does_not_block(self) -> None:
        state = _state("tools/pr_review_gate.py")
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review("tools/pr_review_gate.py", iterations=4),
            external_review_evidence={"kind": "broken"},
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(
            any("Optional external review evidence invalid and ignored" in item for item in result["warnings"]),
            result["warnings"],
        )

    def test_optional_external_head_and_triage_errors_are_warnings_only(self) -> None:
        state = _state("tools/pr_review_gate.py")
        evidence = {
            "schema_version": 1,
            "kind": "external_review",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": "f" * 40,
            "diff_sha256": DIFF_SHA,
            "prompt_sha256": "1" * 64,
            "prompt_includes_diff": True,
            "prompt_transmitted": True,
            "reviews": [
                {
                    "source": "optional-reviewer",
                    "review_sha256": "2" * 64,
                    "verdict": "PASS",
                    "finding_count": 0,
                }
            ],
            "external_reviews_triaged": False,
            "findings": [],
        }
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review("tools/pr_review_gate.py", iterations=4),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "PASS")
        warnings = "\n".join(result["warnings"])
        self.assertIn("head_sha mismatch", warnings)
        self.assertIn("external_reviews_triaged is not true", warnings)

    def test_legacy_policy_waiver_is_ignored(self) -> None:
        state = _state("tools/pr_review_gate.py")
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review("tools/pr_review_gate.py", iterations=4),
            policy_waiver={"kind": "obsolete"},
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(
            any("Deprecated Claude policy waiver ignored" in item for item in result["warnings"]),
            result["warnings"],
        )


class SelfReviewAuditTests(unittest.TestCase):
    def test_build_audit_records_depth_and_outcome(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=2)
        result = gate.evaluate_review_gate(state, self_review=review)
        audit = gate.build_self_review_audit(state, result, review)
        self.assertEqual(audit["kind"], "grabowski_self_review_audit")
        self.assertEqual(audit["minimum_review_iterations"], 2)
        self.assertEqual(audit["actual_review_iterations"], 2)
        self.assertEqual(audit["gate_verdict"], "PASS")
        self.assertEqual(audit["tuning_signal"], "observe")

    def test_failed_depth_audit_recommends_increase(self) -> None:
        state = _state("tools/pr_review_gate.py")
        review = _self_review("tools/pr_review_gate.py", iterations=1)
        result = gate.evaluate_review_gate(state, self_review=review)
        audit = gate.build_self_review_audit(state, result, review)
        self.assertEqual(audit["gate_verdict"], "BLOCK")
        self.assertEqual(audit["tuning_signal"], "increase_depth")

    def test_invalid_measurement_recommends_evidence_repair_not_more_loops(self) -> None:
        state = _state("src/feature.py", additions=45)
        review = _self_review("src/feature.py", iterations=2)
        review["uncertainty"] = 2.0
        result = gate.evaluate_review_gate(state, self_review=review)
        audit = gate.build_self_review_audit(state, result, review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(audit["self_review_gate_valid"])
        self.assertEqual(audit["actual_review_iterations"], 2)
        self.assertEqual(audit["minimum_review_iterations"], 2)
        self.assertEqual(audit["tuning_signal"], "repair_evidence")

    def test_unrelated_ci_failure_does_not_recommend_more_review_depth(self) -> None:
        state = _state("src/feature.py", additions=45)
        state["checks"] = [
            {"name": "validate (3.10)", "bucket": "fail"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ]
        review = _self_review("src/feature.py", iterations=2)
        result = gate.evaluate_review_gate(state, self_review=review)
        audit = gate.build_self_review_audit(state, result, review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(audit["self_review_gate_valid"])
        self.assertEqual(audit["tuning_signal"], "observe")

    def test_write_audit_is_immutable(self) -> None:
        state = _state()
        review = _self_review()
        result = gate.evaluate_review_gate(state, self_review=review)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.json"
            written = gate.write_self_review_audit(path, state, result, review)
            self.assertEqual(written["path"], str(path))
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["kind"], "grabowski_self_review_audit")
            with self.assertRaises(gate.GateInputError):
                gate.write_self_review_audit(path, state, result, review)


if __name__ == "__main__":
    unittest.main()

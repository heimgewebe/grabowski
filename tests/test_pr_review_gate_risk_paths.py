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
        "base_sha": BASE,
        "reviewed_files": [path],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
            "material_findings_after_first_review": 0,
            "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "claimed small diff"},
    }


class PrReviewGateRiskPathExpansionTests(unittest.TestCase):
    def test_mutating_runtime_support_modules_require_deep_self_review(self) -> None:
        for path in (
            "src/grabowski_tasks.py",
            "src/grabowski_checkouts.py",
            "src/grabowski_physical_checkout.py",
            "src/grabowski_agent_role.py",
            "src/grabowski_operations.py",
            "src/grabowski_artifacts.py",
            "src/grabowski_merge_guard.py",
            "src/grabowski_decision_reviews.py",
            "src/grabowski_release_admission.py",
        ):
            with self.subTest(path=path):
                result = pr_review_gate.evaluate_review_gate(_state(path), self_review=_self_review(path))
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertTrue(result["complexity"]["high_critical"])
                self.assertTrue(
                    any("high-critical Grabowski operator path touched" in reason for reason in result["complexity"]["reasons"]),
                    result["complexity"]["reasons"],
                )
                self.assertEqual(result["complexity"]["minimum_self_review_iterations"], 4)
                self.assertTrue(
                    any("minimum 4" in failure for failure in result["failures"]),
                    result["failures"],
                )
                self.assertFalse(result["review_sources"]["external_review_required"])
                self.assertTrue(result["review_sources"]["independent_review_required"])
                self.assertTrue(result["complexity"]["independent_review_required"])

    def test_dot_github_workflows_and_actions_require_high_critical_review(self) -> None:
        # The real heim-pc #225 GitHub changed-file path begins with a dot.
        # str.lstrip("./") must not strip that dot or downgrade CI authority.
        for path in (
            ".github/workflows/heim-pc-nix-cache-publish.yml",
            "./.github/workflows/ci.yml",
            ".github/actions/identity/action.yml",
        ):
            with self.subTest(path=path):
                state = _state(path)
                complexity = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name="heimgewebe/heim-pc"
                )
                self.assertEqual("high_critical", complexity["review_tier"])
                self.assertTrue(complexity["independent_review_required"])
                self.assertGreaterEqual(complexity["minimum_self_review_iterations"], 4)
                self.assertTrue(
                    any("high-critical path touched" in reason
                        for reason in complexity["high_critical_reasons"]),
                    complexity["high_critical_reasons"],
                )
                self.assertEqual(
                    "BLOCK",
                    pr_review_gate.evaluate_review_gate(
                        state, self_review=_self_review(path)
                    )["verdict"],
                    "a one-pass standard self-review cannot satisfy this gate",
                )

    def test_dot_github_lookalikes_are_not_silently_rewritten(self) -> None:
        for path in (
            "github/workflows/ci.yml",
            ".githubish/workflows/ci.yml",
            "/.github/workflows/ci.yml",
            "../../.github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                complexity = pr_review_gate.classify_complexity(
                    _state(path)["pr"], None, repo_name="heimgewebe/heim-pc"
                )
                self.assertFalse(complexity["high_critical"], complexity)

    def test_unrelated_plain_python_module_keeps_standard_review_floor(self) -> None:
        state = _state("src/grabowski_plain_helper.py")
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertFalse(complexity["high_critical"])
        self.assertFalse(complexity["independent_review_required"])

    def test_documentation_does_not_gain_independent_review_floor(self) -> None:
        state = _state("docs/usage.md")
        state["repoName"] = "heimgewebe/example"
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )

        self.assertEqual("documentation", complexity["review_tier"])
        self.assertFalse(complexity["independent_review_required"])
        self.assertFalse(complexity["external_review_required"])

    def test_self_review_audit_transports_independent_review_policy(self) -> None:
        state = _state("src/grabowski_physical_checkout.py")
        state["pr_diff_sha256"] = "0" * 64
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        review = _self_review("src/grabowski_physical_checkout.py")
        review["review_iterations"] = [
            {"n": index, "summary": "reviewed", "material_findings": 0}
            for index in range(1, complexity["minimum_self_review_iterations"] + 1)
        ]
        result = {
            "complexity": complexity,
            "review_sources": {"self_review_gate_valid": True},
        }

        audit = pr_review_gate.build_self_review_audit(state, result, review)

        self.assertEqual("high_critical", audit["review_tier"])
        self.assertTrue(audit["independent_review_required"])
        self.assertEqual(HEAD, audit["head_sha"])
        self.assertEqual(BASE, audit["base_sha"])
        self.assertEqual("0" * 64, audit["diff_sha256"])


if __name__ == "__main__":
    unittest.main()

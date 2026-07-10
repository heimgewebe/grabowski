from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_target_matrix_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


class PrReviewGateTargetMatrixTests(unittest.TestCase):
    def test_reads_block_python_matrix_from_target_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            workflow = repo / ".github" / "workflows" / "validate.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                """name: validate
jobs:
  validate:
    strategy:
      matrix:
        python-version:
          - \"3.11\"
          - \"3.12\"
""",
                encoding="utf-8",
            )
            self.assertEqual(
                pr_review_gate.expected_check_names_for_repo(repo),
                ("validate (3.11)", "validate (3.12)"),
            )

    def test_reads_inline_python_matrix_from_target_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            workflow = repo / ".github" / "workflows" / "validate.yaml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "python-version: [\"3.11\", \"3.13\"]\n",
                encoding="utf-8",
            )
            self.assertEqual(
                pr_review_gate.expected_check_names_for_repo(repo),
                ("validate (3.11)", "validate (3.13)"),
            )

    def test_falls_back_only_for_grabowski_when_matrix_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertEqual(
                pr_review_gate.expected_check_names_for_repo(
                    Path(raw), repo_name="heimgewebe/grabowski"
                ),
                ("validate (3.10)", "validate (3.12)"),
            )

    def test_foreign_repo_without_matrix_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaisesRegex(
                pr_review_gate.GateInputError, "cannot derive expected checks"
            ):
                pr_review_gate.expected_check_names_for_repo(
                    Path(raw), repo_name="heimgewebe/schauwerk"
                )

    def test_invalid_or_duplicate_matrix_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            workflow = repo / ".github" / "workflows" / "validate.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                'python-version: ["3.11", "${{ matrix.python }}"]\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                pr_review_gate.GateInputError, "invalid Python matrix"
            ):
                pr_review_gate.expected_check_names_for_repo(
                    repo, repo_name="heimgewebe/schauwerk"
                )

    def test_evaluation_uses_supplied_target_check_names(self) -> None:
        state = {
            "repoName": "heimgewebe/schauwerk",
            "pr_diff_bypass": True,
            "pr_diff_bypass_reason": "legacy unit seam without live PR diff",
            "pr": {
                "number": 72,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": "a" * 40,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "docs/note.md"}],
                "reviews": [],
                "latestReviews": [],
                "comments": [],
            },
            "checks": [
                {"bucket": "pass", "name": "validate (3.11)"},
                {"bucket": "pass", "name": "validate (3.12)"},
            ],
            "reviewComments": [],
        }
        review = {
            "schema_version": 1,
            "kind": "grabowski_self_review",
            "review_mode": "critical_diff_review",
            "verdict": "PASS",
            "repo": "heimgewebe/schauwerk",
            "pr": 72,
            "head_sha": "a" * 40,
            "reviewed_files": ["docs/note.md"],
            "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
        }
        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=review,
            expected_check_names=("validate (3.11)", "validate (3.12)"),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(
            result["check_policy"]["expected_check_names"],
            ["validate (3.11)", "validate (3.12)"],
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


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
    def test_reads_block_python_matrix_from_validate_job(self) -> None:
        text = """name: validate
jobs:
  docs:
    strategy:
      matrix:
        python-version: ["3.9"]
  validate:
    strategy:
      matrix:
        python-version:
          - "3.11"
          - "3.12"
"""
        self.assertEqual(
            pr_review_gate._python_versions_from_validate_workflow(text),
            ("3.11", "3.12"),
        )

    def test_ignores_nested_validate_and_step_python_version(self) -> None:
        text = """jobs:
  docs:
    steps:
      - with:
          validate:
            python-version: ["3.9"]
  validate:
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "${{ matrix.python-version }}"
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
"""
        self.assertEqual(
            pr_review_gate._python_versions_from_validate_workflow(text),
            ("3.11", "3.12"),
        )

    def test_reads_inline_python_matrix_from_validate_job(self) -> None:
        text = """jobs:
  validate:
    strategy:
      matrix:
        python-version: ["3.11", "3.13"]
"""
        self.assertEqual(
            pr_review_gate._python_versions_from_validate_workflow(text),
            ("3.11", "3.13"),
        )

    def test_custom_validate_job_name_fails_closed(self) -> None:
        text = """jobs:
  validate:
    name: Tests (${{ matrix.python-version }})
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
"""
        with self.assertRaisesRegex(
            pr_review_gate.GateInputError, "custom name"
        ):
            pr_review_gate._python_versions_from_validate_workflow(text)

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
            with mock.patch.object(
                pr_review_gate,
                "_workflow_text_at_head",
                return_value='''jobs:
  validate:
    strategy:
      matrix:
        python-version: ["3.11", "${{ matrix.python }}"]
''',
            ):
                with self.assertRaisesRegex(
                    pr_review_gate.GateInputError, "invalid Python matrix"
                ):
                    pr_review_gate.expected_check_names_for_repo(
                        repo,
                        repo_name="heimgewebe/schauwerk",
                        head_sha="a" * 40,
                    )

    def test_workflow_is_read_from_exact_pr_head(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            with mock.patch.object(
                pr_review_gate,
                "_run_text",
                side_effect=[
                    '''jobs:
  validate:
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
''',
                ],
            ) as run:
                result = pr_review_gate.expected_check_names_for_repo(
                    repo,
                    repo_name="heimgewebe/schauwerk",
                    head_sha="a" * 40,
                )
            self.assertEqual(result, ("validate (3.11)", "validate (3.12)"))
            run.assert_called_once_with(
                repo,
                [
                    "git",
                    "show",
                    f"{'a' * 40}:.github/workflows/validate.yml",
                ],
                allow_nonzero=True,
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

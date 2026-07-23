from __future__ import annotations

import importlib.util
import json
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
    def test_base_catalog_governs_current_pr_and_head_catalog_is_only_validated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            head_catalog = '{"schema_version":1,"required_checks":["weak"]}'
            base_catalog = '{"schema_version":1,"required_checks":["ci","Web E2E"]}'
            with mock.patch.object(
                pr_review_gate,
                "_required_check_catalog_text_at_revision",
                side_effect=[head_catalog, base_catalog],
            ) as read_catalog:
                result = pr_review_gate.expected_check_names_for_repo(
                    repo,
                    repo_name="heimgewebe/weltgewebe",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                )
            self.assertEqual(result, ("ci", "Web E2E"))
            self.assertEqual(
                read_catalog.call_args_list,
                [mock.call(repo, "a" * 40), mock.call(repo, "b" * 40)],
            )

    def test_invalid_head_catalog_blocks_even_when_base_policy_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            with mock.patch.object(
                pr_review_gate,
                "_required_check_catalog_text_at_revision",
                side_effect=["not-json", '{"schema_version":1,"required_checks":["ci"]}'],
            ) as read_catalog:
                with self.assertRaisesRegex(
                    pr_review_gate.GateInputError, "not valid JSON"
                ):
                    pr_review_gate.expected_check_names_for_repo(
                        repo,
                        repo_name="heimgewebe/weltgewebe",
                        head_sha="a" * 40,
                        base_sha="b" * 40,
                    )
            self.assertEqual(read_catalog.call_count, 1)

    def test_weltgewebe_bootstrap_applies_when_base_has_no_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            with mock.patch.object(
                pr_review_gate,
                "_required_check_catalog_text_at_revision",
                return_value=None,
            ) as read_catalog:
                result = pr_review_gate.expected_check_names_for_repo(
                    repo,
                    repo_name="heimgewebe/weltgewebe",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                )
            self.assertEqual(result, ("Detect docs updates", "Core Guard Tests"))
            self.assertEqual(read_catalog.call_count, 2)

    def test_mitschreiber_bootstrap_applies_when_base_has_no_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            with mock.patch.object(pr_review_gate, "_required_check_catalog_text_at_revision", return_value=None) as read_catalog:
                result = pr_review_gate.expected_check_names_for_repo(repo, repo_name="heimgewebe/mitschreiber", head_sha="a" * 40, base_sha="b" * 40)
            self.assertEqual(result, ("ci / reusable-ci",))
            self.assertEqual(read_catalog.call_count, 2)

    def test_direct_cutover_bootstrap_mappings_apply_when_base_has_no_catalog(self) -> None:
        cases = {
            "heimgewebe/hausKI": ("Detect changes",),
            "heimgewebe/hausKI-audio": ("scan",),
            "heimgewebe/metarepo": ("ci (ubuntu-latest)", "ci (macos-latest)"),
        }
        for repo_name, expected in cases.items():
            with self.subTest(repo_name=repo_name), tempfile.TemporaryDirectory() as raw:
                repo = Path(raw)
                with mock.patch.object(
                    pr_review_gate,
                    "_required_check_catalog_text_at_revision",
                    return_value=None,
                ) as read_catalog:
                    result = pr_review_gate.expected_check_names_for_repo(
                        repo,
                        repo_name=repo_name,
                        head_sha="a" * 40,
                        base_sha="b" * 40,
                    )
                self.assertEqual(result, expected)
                self.assertEqual(read_catalog.call_count, 2)

    def test_required_check_catalog_rejects_invalid_duplicate_and_oversized_entries(self) -> None:
        too_many = {
            "schema_version": 1,
            "required_checks": [f"check-{index}" for index in range(65)],
        }
        invalid = (
            '{}',
            '{"schema_version":2,"required_checks":["ci"]}',
            '{"schema_version":1,"required_checks":[]}',
            '{"schema_version":1,"required_checks":["ci"," ci "]}',
            '{"schema_version":1,"required_checks":[1]}',
            '{"schema_version":1,"required_checks":["ci"],"typo":true}',
            json.dumps(too_many),
            json.dumps({"schema_version": 1, "required_checks": ["x" * 201]}),
        )
        for text in invalid:
            with self.subTest(text=text[:80]):
                with self.assertRaises(pr_review_gate.GateInputError):
                    pr_review_gate._required_check_names_from_catalog(text)

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
                "_required_check_catalog_text_at_revision",
                return_value=None,
            ), mock.patch.object(
                pr_review_gate,
                "_workflow_text_at_revision",
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

    def test_workflow_is_read_from_exact_policy_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            workflow = '''jobs:
  validate:
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
'''
            with mock.patch.object(
                pr_review_gate,
                "_required_check_catalog_text_at_revision",
                return_value=None,
            ) as read_catalog, mock.patch.object(
                pr_review_gate,
                "_workflow_text_at_revision",
                return_value=workflow,
            ) as read_workflow:
                result = pr_review_gate.expected_check_names_for_repo(
                    repo,
                    repo_name="heimgewebe/schauwerk",
                    head_sha="a" * 40,
                    base_sha="b" * 40,
                )
            self.assertEqual(result, ("validate (3.11)", "validate (3.12)"))
            self.assertEqual(
                read_catalog.call_args_list,
                [mock.call(repo, "a" * 40), mock.call(repo, "b" * 40)],
            )
            read_workflow.assert_called_once_with(repo, "b" * 40)

    def test_tracked_text_distinguishes_missing_file_from_read_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            with mock.patch.object(pr_review_gate, "_run_bytes", return_value=b""):
                self.assertIsNone(
                    pr_review_gate._tracked_text_at_revision(
                        repo, "a" * 40, ".github/example.json"
                    )
                )
            with mock.patch.object(
                pr_review_gate, "_run_bytes", return_value=b"100644 blob deadbeef\t.github/example.json\0"
            ), mock.patch.object(
                pr_review_gate, "_run_text", side_effect=RuntimeError("git read failed")
            ):
                with self.assertRaisesRegex(RuntimeError, "git read failed"):
                    pr_review_gate._tracked_text_at_revision(
                        repo, "a" * 40, ".github/example.json"
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
            "material_findings_after_first_review": 0,
            "uncertainty": 0.1,
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

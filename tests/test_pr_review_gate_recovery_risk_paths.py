from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "tools" / "pr_review_gate.py"
SPEC = importlib.util.spec_from_file_location("recovery_risk_gate_test", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load review gate")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

RECOVERY_REPO = "heimgewebe/recovery-evidence-authority"


def complexity(paths: list[str], *, repo: str = RECOVERY_REPO) -> dict:
    pr = {
        "number": 2,
        "state": "OPEN",
        "changedFiles": len(paths),
        "additions": 8,
        "deletions": 2,
        "files": [{"path": path, "changeType": "MODIFIED"} for path in paths],
    }
    return gate.classify_complexity(pr, None, repo_name=repo)


class RecoveryEvidenceAuthorityRiskTests(unittest.TestCase):
    def assert_high_critical(self, paths: list[str]) -> None:
        result = complexity(paths)
        self.assertEqual(result["review_tier"], "high_critical", result)
        self.assertTrue(result["high_critical"], result)
        self.assertTrue(result["independent_review_required"], result)
        self.assertGreaterEqual(result["minimum_self_review_iterations"], 4)

    def test_actual_recovery_authority_pr2_file_set_requires_independent_review(self) -> None:
        self.assert_high_critical(["ci_selftest.py", "tests/test_validator.py", "validator.py"])

    def test_actual_recovery_authority_pr3_ci_selftest_requires_independent_review(self) -> None:
        self.assert_high_critical(["ci_selftest.py"])

    def test_signer_root_and_attestation_workflow_are_high_critical(self) -> None:
        for path in ("keys/allowed_signers", "keys/new_public_signer.pub",
                     ".github/workflows/attestation-verify.yml", "tests/test_validator.py"):
            with self.subTest(path=path):
                self.assert_high_critical([path])

    def test_noncanonical_recovery_paths_fail_closed(self) -> None:
        for path in ("../validator.py", "/validator.py",
                     "validator.py/../docs/notes.md",
                     "keys//allowed_signers", "keys\\allowed_signers"):
            with self.subTest(path=path):
                self.assert_high_critical([path])

    def test_repository_scoping_does_not_expand_unrelated_python_reviews(self) -> None:
        for path in ("validator.py", "ci_selftest.py", "tests/test_validator.py"):
            with self.subTest(path=path):
                result = complexity([path], repo="heimgewebe/unrelated-tool")
                self.assertFalse(result["high_critical"], result)
                self.assertFalse(result["independent_review_required"], result)

    def test_ordinary_recovery_docs_keep_documentation_policy(self) -> None:
        result = complexity(["docs/overview.md"])
        self.assertEqual(result["review_tier"], "documentation", result)
        self.assertFalse(result["independent_review_required"], result)

    def test_rename_from_validator_remains_high_critical(self) -> None:
        pr = {
            "changedFiles": 1, "additions": 1, "deletions": 1,
            "files": [{
                "path": "docs/overview.md",
                "status": "renamed",
                "previous_filename": "validator.py",
            }],
        }
        result = gate.classify_complexity(pr, None, repo_name=RECOVERY_REPO)
        self.assertEqual(result["review_tier"], "high_critical", result)
        self.assertTrue(result["independent_review_required"], result)

    def test_rename_without_previous_filename_fails_closed(self) -> None:
        pr = {
            "changedFiles": 1, "additions": 1, "deletions": 1,
            "files": [{"path": "docs/overview.md", "status": "renamed"}],
        }
        result = gate.classify_complexity(pr, None, repo_name=RECOVERY_REPO)
        self.assertEqual(result["review_tier"], "high_critical", result)

    def test_graphql_change_type_renamed_without_source_path_fails_closed(self) -> None:
        # The authoritative gh pr view --json files projection uses changeType,
        # not REST's status. A renamed validator can appear as ordinary docs.
        pr = {
            "changedFiles": 1, "additions": 1, "deletions": 1,
            "files": [{"path": "docs/overview.md", "changeType": "RENAMED"}],
        }
        result = gate.classify_complexity(pr, None, repo_name=RECOVERY_REPO)
        self.assertEqual(result["review_tier"], "high_critical", result)
        self.assertTrue(result["independent_review_required"], result)

    def test_graphql_change_type_without_verified_origin_stays_high_critical(self) -> None:
        for value in ({}, {"changeType": "UNKNOWN"}, {"changeType": 0}):
            with self.subTest(value=value):
                pr = {
                    "changedFiles": 1, "additions": 1, "deletions": 1,
                    "files": [{"path": "docs/overview.md", **value}],
                }
                result = gate.classify_complexity(pr, None, repo_name=RECOVERY_REPO)
                self.assertEqual(result["review_tier"], "high_critical", result)

    def test_missing_or_incomplete_path_list_is_explicitly_rejected(self) -> None:
        for pr in (
            {"changedFiles": 1, "files": []},
            {"changedFiles": 2, "files": [{"path": "validator.py"}]},
        ):
            with self.subTest(pr=pr):
                _paths, failures = gate._current_pr_paths_failures(pr)
                self.assertTrue(failures)


if __name__ == "__main__":
    unittest.main()
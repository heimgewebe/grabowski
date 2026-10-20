from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery_review_gate", ROOT / "tools" / "pr_review_gate.py")
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class RecoveryRequiredCheckTests(unittest.TestCase):
    def expected(self, *, head=None, base=None, repo_name="heimgewebe/recovery-evidence-authority"):
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            gate, "_required_check_catalog_text_at_revision", side_effect=[head, base]
        ) as catalog, mock.patch.object(gate, "_workflow_text_at_revision", return_value=None):
            value = gate.expected_check_names_for_repo(
                Path(raw), repo_name=repo_name, head_sha="a"*40, base_sha="b"*40
            )
            self.assertEqual(catalog.call_count, 2)
        return value

    def test_exact_protected_base_bootstrap(self):
        self.assertEqual(self.expected(), ("security-selftest",))
        self.assertEqual(self.expected(repo_name="Heimgewebe/Recovery-Evidence-Authority"), ("security-selftest",))

    def test_unmerged_head_catalog_does_not_replace_bootstrap(self):
        self.assertEqual(
            self.expected(head='{"schema_version":1,"required_checks":["fake-green-check"]}'),
            ("security-selftest",),
        )

    def test_authoritative_base_catalog_overrides_bootstrap(self):
        self.assertEqual(
            self.expected(base='{"schema_version":1,"required_checks":["security-selftest","extra-base-check"]}'),
            ("security-selftest", "extra-base-check"),
        )

    def test_missing_wrong_failed_skipped_pending_and_duplicate_check_block(self):
        state = {
            "repoName": "heimgewebe/recovery-evidence-authority",
            "pr_diff_bypass": True,
            "pr_diff_bypass_reason": "isolated required-check evaluator fixture",
            "pr": {
                "number": 2, "state": "OPEN", "isDraft": False, "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE", "headRefOid": "a"*40, "baseRefOid": "b"*40,
                "changedFiles": 1, "additions": 1, "deletions": 0,
                "files": [{"path":"docs/note.md"}], "reviews": [], "latestReviews": [], "comments": [],
            },
            "checks": [], "reviewComments": [],
        }
        cases = [
            [], [{"name":"fake-green-check","bucket":"pass"}],
            [{"name":"security-selftest","bucket":"failure"}],
            [{"name":"security-selftest","bucket":"skipping"}],
            [{"name":"security-selftest","bucket":"pending"}],
            [{"name":"security-selftest","bucket":"pass"},{"name":"security-selftest","bucket":"failure"}],
        ]
        for checks in cases:
            with self.subTest(checks=checks):
                state["checks"] = checks
                result = gate.evaluate_review_gate(state, expected_check_names=("security-selftest",))
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn("expected check(s) missing or non-green: security-selftest", result["failures"])
        state["checks"] = [{"name":"security-selftest","bucket":"pass"}]
        result = gate.evaluate_review_gate(state, expected_check_names=("security-selftest",))
        self.assertNotIn("expected check(s) missing or non-green: security-selftest", result["failures"])

if __name__ == "__main__":
    unittest.main()

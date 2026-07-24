from __future__ import annotations

import unittest

from grabowski_checkout_binding_reconciler import reconcile_binding, reconcile_bindings


REPO = "/home/alex/repos/grabowski"
COMMON = "/home/alex/repos/grabowski/.git"
CHECKOUT = "/home/alex/repos/.worktrees/example"
HEAD = "a" * 40


def binding(**overrides):
    value = {
        "checkout_key": "key-a",
        "repo_common_dir": COMMON,
        "repo_path": REPO,
        "checkout_path": CHECKOUT,
        "expected_branch": "topic",
        "expected_head": HEAD,
        "owner_id": "operator:test",
        "phase": "active",
        "retention": {
            "owner_id": "operator:test",
            "retention_until_unix": 9999999999,
            "expected_head": HEAD,
        },
        "latest_archive": None,
    }
    value.update(overrides)
    return value


def worktree(**overrides):
    value = {
        "checkout_key": "key-a",
        "repo_common_dir": COMMON,
        "repo_path": REPO,
        "path": CHECKOUT,
        "branch": "topic",
        "head": HEAD,
    }
    value.update(overrides)
    return value


class CheckoutBindingReconcilerTests(unittest.TestCase):
    def test_exact_binding_is_bound_present(self) -> None:
        result = reconcile_binding(binding(), worktree(), repository_observable=True)
        self.assertEqual(result["state"], "bound_present")
        self.assertFalse(result["blocking"])
        self.assertEqual(result["reasons"], [])

    def test_missing_worktree_is_orphaned_and_blocking(self) -> None:
        result = reconcile_binding(binding(), None, repository_observable=True)
        self.assertEqual(result["state"], "orphaned_binding")
        self.assertTrue(result["blocking"])
        self.assertIn("checkout_absence_as_cleanup_proof", result["does_not_establish"])

    def test_unobservable_repository_precedes_absence_classification(self) -> None:
        result = reconcile_binding(binding(), None, repository_observable=False)
        self.assertEqual(result["state"], "repository_unobservable")
        self.assertIn("repository-state-unobservable", result["reasons"])

    def test_identity_drift_is_explicit(self) -> None:
        result = reconcile_binding(
            binding(),
            worktree(repo_common_dir="/tmp/other", path="/tmp/checkout", branch="other"),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertEqual(
            result["reasons"],
            ["checkout-path-mismatch", "expected-branch-mismatch", "repo-common-dir-mismatch"],
        )

    def test_terminal_head_drift_is_blocking(self) -> None:
        result = reconcile_binding(
            binding(phase="completed_retained"),
            worktree(head="b" * 40),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertIn("terminal-head-mismatch", result["reasons"])

    def test_active_head_movement_is_not_identity_drift(self) -> None:
        result = reconcile_binding(
            binding(phase="active"),
            worktree(head="b" * 40),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "bound_present")

    def test_projection_is_deterministic_and_deduplicates_existing_checkout(self) -> None:
        result = reconcile_bindings(
            [binding(checkout_key="z"), binding(checkout_key="a", checkout_path="/tmp/missing")],
            [worktree(checkout_key="z")],
            observable_repo_paths=[REPO],
        )
        self.assertEqual([row["checkout_key"] for row in result["bindings"]], ["a", "z"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["summary"]["bound_present"], 1)
        self.assertEqual(result["summary"]["orphaned_binding"], 1)
        self.assertEqual(result["blocking_count"], 1)
        self.assertTrue(result["read_only"])

    def test_retention_and_archive_are_evidence_only(self) -> None:
        result = reconcile_binding(
            binding(
                latest_archive={
                    "archive_id": "20260724T000000Z-aaaaaaaaaaaa",
                    "owner_id": "operator:test",
                    "created_at_unix": 1,
                    "cleaned_at_unix": None,
                }
            ),
            None,
            repository_observable=True,
        )
        self.assertEqual(result["state"], "orphaned_binding")
        self.assertEqual(result["evidence"]["archive"]["archive_id"], "20260724T000000Z-aaaaaaaaaaaa")
        self.assertIn("permission_to_archive", result["does_not_establish"])


if __name__ == "__main__":
    unittest.main()

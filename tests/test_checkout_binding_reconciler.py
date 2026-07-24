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

    def test_missing_binding_identity_is_blocking_drift(self) -> None:
        for field in (
            "checkout_key",
            "repo_common_dir",
            "repo_path",
            "checkout_path",
            "owner_id",
        ):
            with self.subTest(field=field):
                result = reconcile_binding(
                    binding(**{field: None}),
                    worktree(),
                    repository_observable=True,
                )
                self.assertEqual(result["state"], "binding_identity_drift")
                self.assertIn(
                    f"missing-binding-{field.replace('_', '-')}",
                    result["reasons"],
                )

    def test_unknown_binding_phase_is_blocking_drift(self) -> None:
        result = reconcile_binding(
            binding(phase="future_phase"),
            worktree(),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertIn("binding-phase-invalid", result["reasons"])

    def test_missing_worktree_identity_is_blocking_drift(self) -> None:
        result = reconcile_binding(
            binding(),
            worktree(repo_path=None, head=None),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertIn("missing-worktree-repo-path", result["reasons"])
        self.assertIn("missing-worktree-head", result["reasons"])

    def test_nullable_branch_is_valid_when_both_sides_are_unborn(self) -> None:
        result = reconcile_binding(
            binding(expected_branch=None),
            worktree(branch=None),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "bound_present")

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

    def test_duplicate_worktree_keys_are_blocking_and_order_independent(self) -> None:
        first = worktree(path="/tmp/first")
        second = worktree(path="/tmp/second")
        forward = reconcile_bindings(
            [binding()],
            [first, second],
            observable_repo_paths=[REPO],
        )
        reverse = reconcile_bindings(
            [binding()],
            [second, first],
            observable_repo_paths=[REPO],
        )
        self.assertEqual(forward, reverse)
        row = forward["bindings"][0]
        self.assertEqual(row["state"], "binding_identity_drift")
        self.assertEqual(row["worktree_identity"], None)
        self.assertIn("duplicate-worktree-checkout-key", row["reasons"])

    def test_duplicate_binding_keys_are_blocking_and_order_independent(self) -> None:
        first = binding(owner_id="operator:z")
        second = binding(owner_id="operator:a")
        forward = reconcile_bindings(
            [first, second],
            [worktree()],
            observable_repo_paths=[REPO],
        )
        reverse = reconcile_bindings(
            [second, first],
            [worktree()],
            observable_repo_paths=[REPO],
        )
        self.assertEqual(forward, reverse)
        self.assertEqual(forward["blocking_count"], 2)
        for row in forward["bindings"]:
            self.assertEqual(row["state"], "binding_identity_drift")
            self.assertIn("duplicate-binding-checkout-key", row["reasons"])

    def test_unkeyed_worktree_record_blocks_absence_classification(self) -> None:
        result = reconcile_bindings(
            [binding()],
            [worktree(checkout_key=None)],
            observable_repo_paths=[REPO],
        )
        row = result["bindings"][0]
        self.assertEqual(row["state"], "binding_identity_drift")
        self.assertIn("worktree-checkout-key-missing", row["reasons"])
        self.assertNotIn(
            "binding-has-no-current-git-worktree-record", row["reasons"]
        )

    def test_terminal_binding_requires_expected_head(self) -> None:
        result = reconcile_binding(
            binding(phase="archived", expected_head=None),
            worktree(),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertIn("missing-binding-expected-head", result["reasons"])

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

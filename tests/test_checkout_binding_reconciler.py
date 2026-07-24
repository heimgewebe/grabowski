from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import grabowski_sqlite_store as sqlite_store
from grabowski_checkout_binding_reconciler import (
    CheckoutBindingCursorError,
    CheckoutBindingDatabaseError,
    collect_lifecycle_bindings_from_db,
    reconcile_binding,
    reconcile_bindings,
    reconcile_checkout_bindings,
)


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
            "repo_common_dir": COMMON,
            "repo_path": REPO,
            "checkout_path": CHECKOUT,
            "owner_id": "operator:test",
            "retention_until_unix": 9999999999,
            "expected_head": HEAD,
            "expected_branch": "topic",
        },
        "latest_archive": None,
    }
    value.update(overrides)
    if "retention" not in overrides:
        retention = dict(value["retention"])
        for field in (
            "repo_common_dir",
            "repo_path",
            "checkout_path",
            "owner_id",
            "expected_head",
            "expected_branch",
        ):
            retention[field] = value[field]
        value["retention"] = retention
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

    def test_retention_owner_drift_is_blocking(self) -> None:
        retention = dict(binding()["retention"])
        retention["owner_id"] = "operator:other"
        result = reconcile_binding(
            binding(retention=retention),
            worktree(),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertIn("binding-retention-owner-mismatch", result["reasons"])

    def test_archived_owner_drift_is_blocking(self) -> None:
        result = reconcile_binding(
            binding(
                phase="archived",
                latest_archive={
                    "repo_common_dir": COMMON,
                    "repo_path": REPO,
                    "checkout_path": CHECKOUT,
                    "owner_id": "operator:other",
                    "head": HEAD,
                    "branch": "topic",
                },
            ),
            worktree(),
            repository_observable=True,
        )
        self.assertEqual(result["state"], "binding_identity_drift")
        self.assertIn("binding-archive-owner-mismatch", result["reasons"])

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


def create_checkout_db(path: Path, *, schema_version: str = "1") -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE retention (
            checkout_key TEXT PRIMARY KEY,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            retention_until_unix INTEGER NOT NULL,
            expected_head TEXT,
            expected_branch TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE TABLE lifecycle_bindings (
            checkout_key TEXT PRIMARY KEY,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            artifact_class TEXT NOT NULL,
            phase TEXT NOT NULL,
            retention_until_unix INTEGER,
            expected_head TEXT,
            expected_branch TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            terminal_at_unix INTEGER,
            archived_at_unix INTEGER
        );
        CREATE TABLE archives (
            archive_id TEXT PRIMARY KEY,
            checkout_key TEXT NOT NULL,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            head TEXT NOT NULL,
            branch TEXT,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            retention_until_unix INTEGER NOT NULL,
            recovery_refs_json TEXT NOT NULL,
            manifest_path TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            cleaned_at_unix INTEGER,
            cleanup_plan_id TEXT
        );
        """
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
        (schema_version,),
    )
    connection.commit()
    connection.close()


def insert_binding(
    path: Path,
    *,
    checkout_key: str,
    checkout_path: str,
    phase: str = "active",
    expected_head: str = HEAD,
) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        """
        INSERT INTO lifecycle_bindings(
            checkout_key, repo_common_dir, repo_path, checkout_path,
            owner_id, purpose, source_kind, source_id, artifact_class, phase,
            retention_until_unix, expected_head, expected_branch,
            created_at_unix, updated_at_unix, terminal_at_unix, archived_at_unix
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            checkout_key,
            COMMON,
            REPO,
            checkout_path,
            "operator:test",
            "test",
            "bureau-task",
            "T096",
            "operator-worktree",
            phase,
            9999999999,
            expected_head,
            "topic",
            1,
            2,
            None,
            None,
        ),
    )
    connection.execute(
        """
        INSERT INTO retention(
            checkout_key, repo_common_dir, repo_path, checkout_path,
            owner_id, purpose, retention_until_unix, expected_head,
            expected_branch, created_at_unix, updated_at_unix
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            checkout_key,
            COMMON,
            REPO,
            checkout_path,
            "operator:test",
            "test",
            9999999999,
            expected_head,
            "topic",
            1,
            2,
        ),
    )
    connection.commit()
    connection.close()


def observed_repo(*records: dict) -> dict:
    return {
        "top_level": REPO,
        "repo_common_dir": COMMON,
        "worktrees": list(records),
        "read_only": True,
    }


class CheckoutBindingLiveIntegrationTests(unittest.TestCase):
    def test_missing_database_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.sqlite3"
            with self.assertRaises(CheckoutBindingDatabaseError):
                collect_lifecycle_bindings_from_db(missing)

    def test_corrupt_database_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            path.write_bytes(b"not-a-sqlite-database")
            with self.assertRaises(CheckoutBindingDatabaseError):
                collect_lifecycle_bindings_from_db(path)

    def test_wal_snapshot_preserves_source_database_and_wal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            keeper = sqlite3.connect(path)
            try:
                self.assertEqual(keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                keeper.execute("PRAGMA wal_autocheckpoint=0")
                keeper.execute(
                    """
                    INSERT INTO lifecycle_bindings(
                        checkout_key, repo_common_dir, repo_path, checkout_path,
                        owner_id, purpose, source_kind, source_id, artifact_class, phase,
                        retention_until_unix, expected_head, expected_branch,
                        created_at_unix, updated_at_unix, terminal_at_unix, archived_at_unix
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "key-wal", COMMON, REPO, CHECKOUT, "operator:test", "test",
                        "bureau-task", "T096", "operator-worktree", "active",
                        9999999999, HEAD, "topic", 1, 2, None, None,
                    ),
                )
                keeper.commit()
                wal_path = Path(str(path) + "-wal")
                self.assertTrue(wal_path.is_file())
                database_before = path.read_bytes()
                wal_before = wal_path.read_bytes()
                result = collect_lifecycle_bindings_from_db(path)
                self.assertEqual(result["snapshot_mode"], "copied-database-and-wal")
                self.assertEqual(result["bindings"][0]["checkout_key"], "key-wal")
                self.assertEqual(path.read_bytes(), database_before)
                self.assertEqual(wal_path.read_bytes(), wal_before)
            finally:
                keeper.close()

    def test_wrong_schema_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path, schema_version="2")
            with self.assertRaisesRegex(
                CheckoutBindingDatabaseError,
                "unsupported checkout database schema version",
            ):
                collect_lifecycle_bindings_from_db(path)

    def test_missing_required_table_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema_version', '1')"
            )
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(
                CheckoutBindingDatabaseError,
                "checkout database tables missing",
            ):
                collect_lifecycle_bindings_from_db(path)

    def test_database_collection_is_byte_for_byte_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            insert_binding(path, checkout_key="key-a", checkout_path=CHECKOUT)
            before = path.read_bytes()
            result = collect_lifecycle_bindings_from_db(path)
            after = path.read_bytes()
            self.assertEqual(before, after)
            self.assertTrue(result["read_only"])
            self.assertEqual(result["database_schema_version"], "1")
            self.assertEqual(len(result["snapshot_sha256"]), 64)
            self.assertEqual(result["bindings"][0]["retention"]["owner_id"], "operator:test")

    def test_database_collection_uses_full_integrity_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            with mock.patch(
                "grabowski_checkout_binding_reconciler.sqlite_store.sqlite_integrity",
                wraps=sqlite_store.sqlite_integrity,
            ) as integrity:
                collect_lifecycle_bindings_from_db(path)
            integrity.assert_called_once()
            self.assertIs(integrity.call_args.kwargs["quick"], False)

    def test_collection_selects_only_latest_archive_for_bound_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            insert_binding(path, checkout_key="key-a", checkout_path=CHECKOUT)
            connection = sqlite3.connect(path)
            try:
                for archive_id, created_at in (("archive-old", 10), ("archive-new", 20)):
                    connection.execute(
                        """
                        INSERT INTO archives(
                            archive_id, checkout_key, repo_common_dir, repo_path,
                            checkout_path, head, branch, owner_id, purpose,
                            retention_until_unix, recovery_refs_json, manifest_path,
                            created_at_unix, cleaned_at_unix, cleanup_plan_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            archive_id, "key-a", COMMON, REPO, CHECKOUT, HEAD,
                            "topic", "operator:test", "test", 9999999999,
                            "[]", f"/tmp/{archive_id}.json", created_at, None, None,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO archives(
                        archive_id, checkout_key, repo_common_dir, repo_path,
                        checkout_path, head, branch, owner_id, purpose,
                        retention_until_unix, recovery_refs_json, manifest_path,
                        created_at_unix, cleaned_at_unix, cleanup_plan_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "archive-unbound", "key-without-binding", COMMON, REPO,
                        "/tmp/unbound", HEAD, "topic", "operator:test", "test",
                        9999999999, "[]", "/tmp/unbound.json", 30, None, None,
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            result = collect_lifecycle_bindings_from_db(path)
            self.assertEqual(len(result["bindings"]), 1)
            self.assertEqual(
                result["bindings"][0]["latest_archive"]["archive_id"],
                "archive-new",
            )

    def test_live_reconciliation_uses_canonical_observer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            insert_binding(path, checkout_key="key-a", checkout_path=CHECKOUT)
            with mock.patch(
                "grabowski_checkout_binding_reconciler.checkouts.observe_worktree_records",
                return_value=observed_repo(worktree()),
            ) as observer:
                result = reconcile_checkout_bindings(db_path=path)
            observer.assert_called_once_with(REPO)
            self.assertEqual(result["bindings"][0]["state"], "bound_present")
            self.assertEqual(result["attention"], [])
            self.assertTrue(result["pagination"]["snapshot_bound"])

    def test_repository_observation_failure_is_blocking_not_orphaned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            insert_binding(path, checkout_key="key-a", checkout_path=CHECKOUT)
            with mock.patch(
                "grabowski_checkout_binding_reconciler.checkouts.observe_worktree_records",
                side_effect=RuntimeError("offline"),
            ):
                result = reconcile_checkout_bindings(db_path=path)
            row = result["bindings"][0]
            self.assertEqual(row["state"], "repository_unobservable")
            self.assertEqual(result["attention"][0]["checkout_key"], "key-a")
            self.assertEqual(
                result["source_snapshot"]["repository_errors"][0]["error"],
                "RuntimeError",
            )

    def test_pagination_cursor_is_bound_to_full_live_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkouts.sqlite3"
            create_checkout_db(path)
            insert_binding(path, checkout_key="key-a", checkout_path="/tmp/a")
            insert_binding(path, checkout_key="key-b", checkout_path="/tmp/b")
            records = [
                worktree(checkout_key="key-a", path="/tmp/a"),
                worktree(checkout_key="key-b", path="/tmp/b"),
            ]
            with mock.patch(
                "grabowski_checkout_binding_reconciler.checkouts.observe_worktree_records",
                return_value=observed_repo(*records),
            ):
                first = reconcile_checkout_bindings(db_path=path, limit=1)
                second = reconcile_checkout_bindings(
                    db_path=path,
                    limit=1,
                    cursor=first["pagination"]["next_cursor"],
                )
                self.assertEqual(first["bindings"][0]["checkout_key"], "key-a")
                self.assertEqual(second["bindings"][0]["checkout_key"], "key-b")
                connection = sqlite3.connect(path)
                connection.execute(
                    "UPDATE lifecycle_bindings SET updated_at_unix=3 WHERE checkout_key='key-b'"
                )
                connection.commit()
                connection.close()
                with self.assertRaises(CheckoutBindingCursorError):
                    reconcile_checkout_bindings(
                        db_path=path,
                        limit=1,
                        cursor=first["pagination"]["next_cursor"],
                    )


if __name__ == "__main__":
    unittest.main()

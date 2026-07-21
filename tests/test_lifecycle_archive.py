from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import grabowski_lifecycle_archive as lifecycle


class LifecycleClassificationTests(unittest.TestCase):
    def test_active_task_wins_over_nonterminal_default(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-a",
                kind="task",
                state="running",
                active_task=True,
            )
        )
        self.assertEqual(result["classification"], "active")
        self.assertFalse(result["safe_to_archive"])

    def test_unknown_observation_fails_closed_as_ambiguous(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="workspace-a",
                kind="workspace",
                closed=True,
                active_process=None,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn("observation_unknown:active_process", result["reason_codes"])

    def test_foreign_retention_is_untouchable(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="checkout-a",
                kind="checkout",
                closed=True,
                foreign_retention=True,
            )
        )
        self.assertEqual(result["classification"], "untouchable")
        self.assertIn("foreign_retention", result["reason_codes"])

    def test_dirty_checkout_is_untouchable(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="checkout-b",
                kind="checkout",
                closed=True,
                dirty=True,
            )
        )
        self.assertEqual(result["classification"], "untouchable")

    def test_recovery_state_requires_recovery(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-b",
                kind="task",
                state="outcome_unknown",
            )
        )
        self.assertEqual(result["classification"], "recovery_required")

    def test_terminal_with_valid_receipt_is_archivable(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-c",
                kind="task",
                state="completed",
                receipt_integrity_valid=True,
            )
        )
        self.assertEqual(result["classification"], "terminal_archivable")
        self.assertTrue(result["safe_to_archive"])

    def test_terminal_with_invalid_receipt_requires_recovery(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-d",
                kind="task",
                state="completed",
                receipt_integrity_valid=False,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")

    def test_archived_with_live_activity_is_ambiguous(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-e",
                kind="task",
                state="completed",
                archived=True,
                active_process=True,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")

    def test_archived_with_invalid_receipt_requires_recovery(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-f",
                kind="task",
                state="completed",
                archived=True,
                receipt_integrity_valid=False,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")


class LifecycleProjectionTests(unittest.TestCase):
    def test_bounded_current_projection_hides_only_archive_history(self) -> None:
        records = [
            {"task_id": "a", "state": "running"},
            {"task_id": "b", "state": "completed"},
            {"task_id": "c", "state": "completed"},
            {"task_id": "d", "state": "failed"},
        ]
        classifications = {
            "a": {"classification": "active"},
            "b": {"classification": "terminal_archivable"},
            "c": {"classification": "archived"},
            "d": {"classification": "recovery_required"},
        }
        current = lifecycle.bounded_current_projection(records, classifications)
        self.assertEqual([record["task_id"] for record in current], ["a", "d"])

    def test_projection_requires_classification_for_every_record(self) -> None:
        with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
            lifecycle.bounded_current_projection(
                [{"task_id": "a", "state": "completed"}],
                {},
            )


class TaskArchivePlanTests(unittest.TestCase):
    @staticmethod
    def task(task_id: str, *, updated_at: int, receipt: str = "a" * 64) -> dict:
        return {
            "task_id": task_id,
            "state": "completed",
            "created_at_unix": updated_at - 10,
            "updated_at_unix": updated_at,
            "terminalized_at_unix": updated_at,
            "lifecycle_receipt_sha256": receipt,
        }

    def test_plan_selects_only_old_archivable_records(self) -> None:
        records = [
            self.task("old", updated_at=100),
            self.task("fresh", updated_at=950),
            self.task("blocked", updated_at=100),
        ]
        classifications = {
            "old": {"classification": "terminal_archivable"},
            "fresh": {"classification": "terminal_archivable"},
            "blocked": {"classification": "untouchable"},
        }
        plan = lifecycle.build_task_archive_plan(
            records,
            classifications,
            now_unix=1000,
            minimum_age_seconds=100,
        )
        self.assertEqual(plan["eligible_task_ids"], ["old"])
        self.assertEqual(
            {entry["task_id"] for entry in plan["blocked"]},
            {"fresh", "blocked"},
        )
        self.assertEqual(len(plan["plan_sha256"]), 64)

    def test_plan_digest_changes_when_source_record_changes(self) -> None:
        record = self.task("old", updated_at=100)
        classifications = {"old": {"classification": "terminal_archivable"}}
        first = lifecycle.build_task_archive_plan(
            [record], classifications, now_unix=1000, minimum_age_seconds=100
        )
        changed = {**record, "updated_at_unix": 99, "terminalized_at_unix": 99}
        second = lifecycle.build_task_archive_plan(
            [changed], classifications, now_unix=1000, minimum_age_seconds=100
        )
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])


class TaskArchiveSegmentTests(unittest.TestCase):
    @staticmethod
    def task(task_id: str, created_at: int) -> dict:
        return {
            "task_id": task_id,
            "state": "completed",
            "created_at_unix": created_at,
            "updated_at_unix": created_at + 5,
            "terminalized_at_unix": created_at + 5,
            "lifecycle_receipt_sha256": "b" * 64,
        }

    def test_write_verify_and_idempotent_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            records = [self.task("task-b", 20), self.task("task-a", 10)]
            first = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            self.assertEqual(first["status"], "verified")
            self.assertFalse(first["idempotent_replay"])
            self.assertEqual(
                [record["task_id"] for record in first["records"]],
                ["task-a", "task-b"],
            )
            manifest = first["manifest"]
            self.assertEqual(manifest["record_count"], 2)
            self.assertEqual(manifest["first_task_id"], "task-a")
            self.assertEqual(manifest["last_task_id"], "task-b")
            second = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(second["manifest"], manifest)

    def test_same_records_with_different_plan_get_distinct_segment_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            records = [self.task("task-a", 10)]
            first = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            second = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="e" * 64,
            )
            self.assertNotEqual(first["segment_dir"], second["segment_dir"])
            self.assertNotEqual(
                first["manifest"]["segment_identity_sha256"],
                second["manifest"]["segment_identity_sha256"],
            )

    def test_tampered_segment_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            segment_dir = Path(result["segment_dir"])
            records_path = segment_dir / "records.jsonl"
            payload = json.loads(records_path.read_text(encoding="utf-8"))
            payload["state"] = "failed"
            records_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(segment_dir)

    def test_segment_rejects_record_without_lifecycle_receipt(self) -> None:
        record = self.task("task-a", 10)
        record["lifecycle_receipt_sha256"] = None
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(lifecycle.LifecycleArchiveError):
                lifecycle.write_task_archive_segment(
                    [record],
                    archive_root=Path(directory) / "archives",
                    source_store_sha256="c" * 64,
                    source_schema_version="5",
                    plan_sha256="d" * 64,
                )


    def test_segment_verification_respects_explicit_records_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(
                    Path(result["segment_dir"]),
                    max_records_bytes=1,
                )

    def test_segment_verification_respects_explicit_manifest_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(
                    Path(result["segment_dir"]),
                    max_manifest_bytes=1,
                )

    def test_segment_verification_rejects_invalid_records_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            with self.assertRaises(ValueError):
                lifecycle.verify_task_archive_segment(
                    Path(result["segment_dir"]),
                    max_records_bytes=-1,
                )


if __name__ == "__main__":
    unittest.main()

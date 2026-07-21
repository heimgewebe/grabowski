from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_lifecycle_archive as lifecycle
import grabowski_lifecycle_read_surface as read_surface


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def task(task_id: str, created: int) -> dict:
    return {
        "task_id": task_id,
        "state": "completed",
        "created_at_unix": created,
        "updated_at_unix": created + 5,
        "terminalized_at_unix": created + 5,
        "lifecycle_receipt_sha256": DIGEST_A,
        "payload": {"note": task_id},
    }


class LifecycleReadSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "task-archives"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_segment(self, records, *, source=DIGEST_B, plan=DIGEST_C):
        return lifecycle.write_task_archive_segment(
            records,
            archive_root=self.root,
            source_store_sha256=source,
            source_schema_version="v1",
            plan_sha256=plan,
        )

    def test_absent_archive_root_is_empty(self) -> None:
        result = read_surface.task_archive_list(archive_root=self.root)
        self.assertFalse(result["archive_root_exists"])
        self.assertEqual(result["segment_count"], 0)
        self.assertEqual(result["segments"], [])
        self.assertEqual(
            result["integrity_state"],
            "catalog_manifests_verified_records_unverified",
        )

    def test_catalog_paginates_verified_segment_manifests(self) -> None:
        self.write_segment([task("task-a", 10)], source=DIGEST_A, plan=DIGEST_B)
        self.write_segment([task("task-b", 20)], source=DIGEST_B, plan=DIGEST_C)
        first = read_surface.task_archive_list(
            archive_root=self.root,
            limit=1,
            view="evidence",
        )
        self.assertEqual(first["segment_count"], 2)
        self.assertEqual(len(first["segments"]), 1)
        self.assertEqual(
            first["segments"][0]["integrity_state"],
            "manifest_verified_records_unverified",
        )
        self.assertTrue(first["pagination"]["has_more"])
        second = read_surface.task_archive_list(
            archive_root=self.root,
            limit=1,
            cursor=first["pagination"]["next_cursor"],
            view="evidence",
        )
        self.assertEqual(len(second["segments"]), 1)
        self.assertFalse(second["pagination"]["has_more"])
        self.assertNotEqual(
            first["segments"][0]["segment_id"],
            second["segments"][0]["segment_id"],
        )

    def test_segment_read_fully_verifies_then_paginates_records(self) -> None:
        written = self.write_segment([task("task-a", 10), task("task-b", 20)])
        segment_id = written["manifest"]["segment_id"]
        first = read_surface.task_archive_read(
            segment_id,
            archive_root=self.root,
            limit=1,
            view="evidence",
        )
        self.assertEqual(first["integrity_state"], "segment_verified")
        self.assertEqual(first["record_count"], 2)
        self.assertEqual(first["records"][0]["task_id"], "task-a")
        self.assertEqual(first["manifest"]["segment_id"], segment_id)
        records_path = Path(written["segment_dir"]) / "records.jsonl"
        self.assertEqual(first["records_bytes"], records_path.stat().st_size)
        self.assertEqual(
            first["record_hash_sequence_sha256"],
            lifecycle.sha256_json(first["manifest"]["record_sha256s"]),
        )
        second = read_surface.task_archive_read(
            segment_id,
            archive_root=self.root,
            limit=1,
            cursor=first["pagination"]["next_cursor"],
            view="evidence",
        )
        self.assertEqual(second["records"][0]["task_id"], "task-b")
        minimal = read_surface.task_archive_read(
            segment_id,
            archive_root=self.root,
            limit=1,
            view="minimal",
        )
        self.assertEqual(
            set(minimal["records"][0]),
            {
                "task_id",
                "state",
                "created_at_unix",
                "terminalized_at_unix",
                "lifecycle_receipt_sha256",
            },
        )

    def test_catalog_cursor_invalidates_when_manifest_catalog_changes(self) -> None:
        self.write_segment([task("task-a", 10)], source=DIGEST_A, plan=DIGEST_B)
        self.write_segment([task("task-b", 20)], source=DIGEST_B, plan=DIGEST_C)
        first = read_surface.task_archive_list(archive_root=self.root, limit=1)
        cursor = first["pagination"]["next_cursor"]
        self.write_segment([task("task-c", 30)], source=DIGEST_C, plan=DIGEST_A)
        with self.assertRaises(ValueError):
            read_surface.task_archive_list(
                archive_root=self.root,
                limit=1,
                cursor=cursor,
            )

    def test_tampered_manifest_fails_catalog_read(self) -> None:
        written = self.write_segment([task("task-a", 10)])
        manifest_path = Path(written["segment_dir"]) / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["record_count"] = 2
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_list(archive_root=self.root)

    def test_record_tamper_is_not_claimed_verified_by_catalog_but_blocks_read(self) -> None:
        written = self.write_segment([task("task-a", 10)])
        segment_dir = Path(written["segment_dir"])
        records_path = segment_dir / "records.jsonl"
        payload = records_path.read_text(encoding="utf-8")
        records_path.write_text(payload.replace("task-a", "task-z"), encoding="utf-8")
        catalog = read_surface.task_archive_list(archive_root=self.root)
        self.assertEqual(
            catalog["integrity_state"],
            "catalog_manifests_verified_records_unverified",
        )
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_read(
                written["manifest"]["segment_id"],
                archive_root=self.root,
            )

    def test_full_verify_integrity_error_is_translated_at_surface_boundary(self) -> None:
        written = self.write_segment([task("task-a", 10)])
        with mock.patch.object(
            lifecycle,
            "verify_task_archive_segment",
            side_effect=lifecycle.LifecycleArchiveIntegrityError("full verify failed"),
        ):
            with self.assertRaisesRegex(
                read_surface.LifecycleReadSurfaceIntegrityError,
                "full verify failed",
            ):
                read_surface.task_archive_read(
                    written["manifest"]["segment_id"],
                    archive_root=self.root,
                )

    def test_read_cursor_rejects_cross_view_and_tampering(self) -> None:
        written = self.write_segment([task("task-a", 10), task("task-b", 20)])
        segment_id = written["manifest"]["segment_id"]
        first = read_surface.task_archive_read(
            segment_id,
            archive_root=self.root,
            limit=1,
            view="standard",
        )
        cursor = first["pagination"]["next_cursor"]
        self.assertIsInstance(cursor, str)
        with self.assertRaises(ValueError):
            read_surface.task_archive_read(
                segment_id,
                archive_root=self.root,
                limit=1,
                cursor=cursor,
                view="evidence",
            )
        tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        with self.assertRaises(ValueError):
            read_surface.task_archive_read(
                segment_id,
                archive_root=self.root,
                limit=1,
                cursor=tampered,
                view="standard",
            )

    def test_unexpected_hidden_root_entry_fails_closed(self) -> None:
        self.root.mkdir(parents=True)
        (self.root / ".partial").mkdir()
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_list(archive_root=self.root)

    def test_symlink_segment_fails_closed(self) -> None:
        self.root.mkdir(parents=True)
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.root / ("segment-" + "a" * 24)).symlink_to(outside, target_is_directory=True)
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_list(archive_root=self.root)

    def test_manifest_file_symlink_fails_closed(self) -> None:
        written = self.write_segment([task("task-a", 10)])
        segment_dir = Path(written["segment_dir"])
        manifest_path = segment_dir / "manifest.json"
        outside = Path(self.temp.name) / "outside-manifest.json"
        outside.write_bytes(manifest_path.read_bytes())
        manifest_path.unlink()
        manifest_path.symlink_to(outside)
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_list(archive_root=self.root)
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_read(
                written["manifest"]["segment_id"],
                archive_root=self.root,
            )

    def test_records_file_symlink_fails_closed(self) -> None:
        written = self.write_segment([task("task-a", 10)])
        segment_dir = Path(written["segment_dir"])
        records_path = segment_dir / "records.jsonl"
        outside = Path(self.temp.name) / "outside-records.jsonl"
        outside.write_bytes(records_path.read_bytes())
        records_path.unlink()
        records_path.symlink_to(outside)
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_list(archive_root=self.root)
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_read(
                written["manifest"]["segment_id"],
                archive_root=self.root,
            )

    def test_symlink_archive_root_fails_closed(self) -> None:
        actual = Path(self.temp.name) / "actual"
        actual.mkdir()
        self.root.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
            read_surface.task_archive_list(archive_root=self.root)

    def test_invalid_segment_identifier_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            read_surface.task_archive_read("../segment-evil", archive_root=self.root)
        with self.assertRaises(ValueError):
            read_surface.task_archive_read("segment-xyz", archive_root=self.root)

    def test_full_verified_read_allows_exact_bound_and_rejects_plus_one(self) -> None:
        written = self.write_segment([task("task-a", 10)])
        records_path = Path(written["segment_dir"]) / "records.jsonl"
        records_bytes = records_path.stat().st_size
        with mock.patch.object(read_surface, "MAX_RECORDS_BYTES", records_bytes):
            result = read_surface.task_archive_read(
                written["manifest"]["segment_id"],
                archive_root=self.root,
                view="evidence",
            )
        self.assertEqual(result["records_bytes"], records_bytes)
        with mock.patch.object(read_surface, "MAX_RECORDS_BYTES", records_bytes - 1):
            with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
                read_surface.task_archive_read(
                    written["manifest"]["segment_id"],
                    archive_root=self.root,
                )

    def test_catalog_respects_aggregate_manifest_bound(self) -> None:
        self.write_segment([task("task-a", 10)])
        with mock.patch.object(read_surface, "MAX_CATALOG_MANIFEST_BYTES", 1):
            with self.assertRaises(read_surface.LifecycleReadSurfaceIntegrityError):
                read_surface.task_archive_list(archive_root=self.root)

    def test_top_level_field_projection_preserves_safety_fields(self) -> None:
        self.write_segment([task("task-a", 10)])
        result = read_surface.task_archive_list(
            archive_root=self.root,
            fields=["segments"],
        )
        self.assertIn("segments", result)
        self.assertIn("schema_version", result)
        self.assertIn("view", result)
        self.assertIn("integrity_state", result)
        self.assertIn("does_not_establish", result)
        self.assertNotIn("archive_root", result)


if __name__ == "__main__":
    unittest.main()

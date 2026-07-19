from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_operator_v2_runtime import grabowski_mcp


def _concurrent_segment_writer(start_event, worker: int, count: int) -> None:
    start_event.wait()
    for index in range(count):
        grabowski_mcp._append_audit(
            {
                "operation": "concurrent-segment-test",
                "worker": worker,
                "index": index,
                "payload": "c" * 96,
            }
        )


class AuditSegmentLifecycleTests(unittest.TestCase):
    def _patches(self, state: Path):
        audit = state / "write-audit.jsonl"
        return audit, (
            patch.object(grabowski_mcp, "STATE_DIR", state),
            patch.object(grabowski_mcp, "AUDIT_LOG", audit),
            patch.object(grabowski_mcp, "QUARANTINE_DIR", state / "quarantine"),
            patch.object(
                grabowski_mcp,
                "KILL_SWITCH_PATH",
                state / "operator-kill-switch",
            ),
            patch.object(grabowski_mcp, "MAX_AUDIT_BYTES", 8192),
            patch.object(grabowski_mcp, "MAX_AUDIT_RECORD_BYTES", 1024),
            patch.object(grabowski_mcp, "AUDIT_ROTATION_RESERVE_BYTES", 512),
        )

    def test_rotation_preserves_complete_chain_and_historical_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(30):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "segment-test",
                            "transaction_id": f"20260719T000000.{index:06d}Z-{index:012x}",
                            "payload": "x" * 80,
                        }
                    )
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)
                self.assertTrue(status["chain_valid"], status)
                self.assertGreater(status["archived_segment_count"], 0)
                self.assertEqual(
                    status["total_records"],
                    30 + status["archived_segment_count"],
                )
                records = grabowski_mcp._audit_records()
                operations = [item.get("operation") for item in records]
                self.assertEqual(operations.count("segment-test"), 30)
                first = grabowski_mcp._find_transaction_record(
                    "20260719T000000.000000Z-000000000000"
                )
                self.assertEqual(first["payload"], "x" * 80)
                self.assertTrue(status["audit_writable"], status)

    def test_archived_segment_tamper_invalidates_complete_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(20):
                    grabowski_mcp._append_audit(
                        {"operation": "tamper-test", "index": index, "payload": "y" * 120}
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                before = segment.read_bytes()
                segment.write_bytes(before[:-1] + (b"X" if before[-1:] != b"X" else b"Y"))
                os.chmod(segment, 0o600)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(status["valid"], status)
                self.assertIn("segment", status["error"])
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    grabowski_mcp._append_audit({"operation": "blocked"})

    def test_failure_before_active_replace_keeps_previous_active_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(8):
                    grabowski_mcp._append_audit(
                        {"operation": "pre-rotation", "index": index, "payload": "z" * 120}
                    )
                real_replace = grabowski_mcp.os.replace
                before_replace = None

                def fail_rotation(source, destination):
                    nonlocal before_replace
                    if Path(destination) == audit:
                        before_replace = audit.read_bytes()
                        raise OSError("injected replace failure")
                    return real_replace(source, destination)

                with patch.object(grabowski_mcp.os, "replace", side_effect=fail_rotation):
                    with self.assertRaisesRegex(OSError, "injected replace failure"):
                        for _index in range(30):
                            grabowski_mcp._append_audit(
                                {"operation": "trigger", "payload": "q" * 300}
                            )
                self.assertIsNotNone(before_replace)
                self.assertEqual(audit.read_bytes(), before_replace)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)

    def test_concurrent_rotation_preserves_all_records(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("requires fork semantics")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                context = multiprocessing.get_context("fork")
                start_event = context.Event()
                workers = 4
                records_per_worker = 15
                processes = [
                    context.Process(
                        target=_concurrent_segment_writer,
                        args=(start_event, worker, records_per_worker),
                    )
                    for worker in range(workers)
                ]
                for process in processes:
                    process.start()
                start_event.set()
                for process in processes:
                    process.join(20)
                for process in processes:
                    self.assertEqual(process.exitcode, 0)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)
                self.assertGreater(status["archived_segment_count"], 0)
                records = grabowski_mcp._audit_records()
                observed = [
                    item
                    for item in records
                    if item.get("operation") == "concurrent-segment-test"
                ]
                self.assertEqual(len(observed), workers * records_per_worker)
                self.assertEqual(
                    len({(item["worker"], item["index"]) for item in observed}),
                    workers * records_per_worker,
                )

    def test_unchanged_sealed_segment_uses_identity_bound_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "cache-test", "index": index, "payload": "k" * 120}
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                first = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(first["valid"], first)
                with patch.object(
                    grabowski_mcp,
                    "_read_audit_file",
                    wraps=grabowski_mcp._read_audit_file,
                ) as reader:
                    second = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(second["valid"], second)
                self.assertEqual(reader.call_count, 1)
                self.assertEqual(reader.call_args.args[0], audit)

    def test_manifest_tamper_invalidates_complete_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "manifest-test", "index": index, "payload": "m" * 120}
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                manifest = Path(first["segment_manifest_path"])
                raw = manifest.read_bytes()
                manifest.write_bytes(raw[:-1] + (b"X" if raw[-1:] != b"X" else b"Y"))
                os.chmod(manifest, 0o600)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(status["valid"], status)
                self.assertIn("manifest", status["error"])

    def test_hardlinked_archived_segment_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "hardlink-test", "index": index, "payload": "h" * 120}
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                second_link = state / "segment-second-link.jsonl"
                os.link(segment, second_link)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(status["valid"], status)
                self.assertIn("contract", status["error"])

    def test_rotation_commit_without_followup_record_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(5):
                    grabowski_mcp._append_audit(
                        {"operation": "before-direct-rotation", "index": index}
                    )
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=True):
                    descriptor, _created = grabowski_mcp._open_audit_append_target(audit)
                    try:
                        status = grabowski_mcp._verify_audit_descriptor(audit, descriptor)
                        grabowski_mcp._rotate_audit_segment(
                            audit,
                            descriptor,
                            status,
                            next_record_bytes=256,
                        )
                    finally:
                        grabowski_mcp._close_audit_descriptor(descriptor)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)
                self.assertEqual(status["records"], 1)
                first = json.loads(audit.read_text(encoding="utf-8"))
                self.assertEqual(first["operation"], "audit-segment-genesis-v1")
                self.assertEqual(status["total_records"], 6)

    def test_oversized_record_is_rejected_before_audit_content_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                grabowski_mcp._append_audit({"operation": "before-oversize"})
                before = audit.read_bytes()
                with self.assertRaisesRegex(ValueError, "record.*byte limit"):
                    grabowski_mcp._append_audit(
                        {"operation": "oversized", "payload": "o" * 5000}
                    )
                self.assertEqual(audit.read_bytes(), before)

    def test_manual_rotation_shape_is_verified_as_compatibility_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            archive = state / "audit-archive"
            archive.mkdir(mode=0o700)
            old = archive / "old.jsonl"
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                grabowski_mcp._append_audit({"operation": "old"})
                old.write_bytes(audit.read_bytes())
                os.chmod(old, 0o600)
                old_data = old.read_bytes()
                old_status = grabowski_mcp._verify_audit_bytes(old, old_data, exists=True)
                genesis = {
                    "operation": "audit-capacity-rotation-v1",
                    "archived_audit_path": str(old),
                    "archived_audit_sha256": hashlib.sha256(old_data).hexdigest(),
                    "archived_audit_bytes": len(old_data),
                    "archived_audit_records": old_status["records"],
                    "archived_last_record_sha256": old_status["last_record_sha256"],
                    "audit_schema_version": 2,
                    "sequence": 1,
                    "previous_record_sha256": None,
                    "timestamp": "2026-07-19T00:00:00+00:00",
                }
                genesis["record_sha256"] = grabowski_mcp._audit_record_hash(genesis)
                audit.write_bytes(grabowski_mcp._canonical_json_line(genesis))
                os.chmod(audit, 0o600)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)
                self.assertTrue(status["legacy_rotation_compatibility"])
                self.assertEqual(status["archived_segment_count"], 1)


if __name__ == "__main__":
    unittest.main()

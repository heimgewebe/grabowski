from __future__ import annotations

from contextlib import contextmanager
import fcntl
import importlib.util
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import types
import tempfile
import unittest
from unittest.mock import patch

from test_operator_v2_runtime import grabowski_mcp


def _load_audit_query():
    fake_operator = types.ModuleType("grabowski_operator_core")

    class FakeMCP:
        def tool(self, *args, **kwargs):
            return lambda function: function

    fake_operator.mcp = FakeMCP()
    fake_operator.READ_ONLY = {}
    module_name = "grabowski_audit_query_segments_test"
    spec = importlib.util.spec_from_file_location(
        module_name, Path(__file__).resolve().parents[1] / "src" / "grabowski_audit_query.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_audit_query")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "grabowski_mcp": grabowski_mcp,
            "grabowski_operator_core": fake_operator,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


grabowski_audit_query = _load_audit_query()


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

    def test_snapshot_parser_propagates_exact_legacy_raw_line_digest(self) -> None:
        legacy_line = (
            b'{"operation": "legacy-evidence", "plan_sha256": "'
            + b"a" * 64
            + b'", "attempt": 1}'
        )
        v2_line = json.dumps(
            {
                "operation": "v2-evidence",
                "record_sha256": "b" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        records = grabowski_mcp._audit_records_from_components(
            [
                (
                    Path("/tmp/verified-audit-component.jsonl"),
                    legacy_line + b"\n" + v2_line + b"\n",
                    {},
                )
            ]
        )
        self.assertEqual(len(records), 2)
        self.assertNotIn("record_sha256", records[0])
        self.assertEqual(
            records[0][grabowski_mcp._AUDIT_EVIDENCE_RECORD_SHA256_FIELD],
            hashlib.sha256(legacy_line).hexdigest(),
        )
        self.assertNotIn(
            grabowski_mcp._AUDIT_EVIDENCE_RECORD_SHA256_FIELD,
            records[1],
        )
        self.assertEqual(records[1]["record_sha256"], "b" * 64)

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
                records, snapshot_status = grabowski_mcp._audit_records_snapshot()
                self.assertEqual(snapshot_status["total_records"], len(records))
                self.assertEqual(
                    snapshot_status["last_record_sha256"],
                    records[-1]["record_sha256"],
                )
                self.assertEqual(
                    snapshot_status["archived_segment_count"],
                    status["archived_segment_count"],
                )
                operations = [item.get("operation") for item in records]
                self.assertEqual(operations.count("segment-test"), 30)
                first = grabowski_mcp._find_transaction_record(
                    "20260719T000000.000000Z-000000000000"
                )
                self.assertEqual(first["payload"], "x" * 80)
                self.assertTrue(status["audit_writable"], status)

    def test_archived_segment_tamper_blocks_append_and_preserves_active_head(self) -> None:
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
                active_before = audit.read_bytes()
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(status["valid"], status)
                self.assertIn("segment", status["error"])
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    grabowski_mcp._append_audit({"operation": "blocked"})
                self.assertEqual(audit.read_bytes(), active_before)

    def test_predecessor_tamper_between_external_verify_and_append_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(20):
                    grabowski_mcp._append_audit(
                        {"operation": "toctou-test", "index": index, "payload": "t" * 120}
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                active_before = audit.read_bytes()
                real_verify = grabowski_mcp._verify_bound_audit_predecessors
                calls = 0

                def verify_then_tamper(path, predecessor):
                    nonlocal calls
                    calls += 1
                    snapshot = real_verify(path, predecessor)
                    if calls == 1:
                        data = segment.read_bytes()
                        segment.write_bytes(
                            data[:-1] + (b"X" if data[-1:] != b"X" else b"Y")
                        )
                        os.chmod(segment, 0o600)
                    return snapshot

                with patch.object(
                    grabowski_mcp,
                    "_verify_bound_audit_predecessors",
                    side_effect=verify_then_tamper,
                ):
                    with self.assertRaisesRegex(RuntimeError, "verification failed"):
                        grabowski_mcp._append_audit(
                            {"operation": "must-not-append-after-toctou-tamper"}
                        )

                self.assertEqual(calls, 1)
                self.assertEqual(audit.read_bytes(), active_before)

    def test_append_retries_after_predecessor_change_then_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "predecessor-retry-setup",
                            "index": index,
                            "payload": "r" * 120,
                        }
                    )
                before = grabowski_mcp._verify_audit_log(audit)
                original_head = grabowski_mcp._read_audit_head_unlocked
                head_reads = 0

                def change_predecessor_once(path):
                    nonlocal head_reads
                    result = original_head(path)
                    head_reads += 1
                    if head_reads == 2:
                        current_head, current_predecessor = result
                        self.assertIsNotNone(current_predecessor)
                        changed = dict(current_predecessor)
                        changed["sha256"] = "f" * 64
                        return current_head, changed
                    return result

                with patch.object(
                    grabowski_mcp,
                    "_read_audit_head_unlocked",
                    side_effect=change_predecessor_once,
                ):
                    grabowski_mcp._append_audit(
                        {"operation": "predecessor-retry-success"}
                    )

                self.assertGreaterEqual(head_reads, 4)
                after = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(after["valid"], after)
                self.assertEqual(
                    after["total_records"],
                    before["total_records"] + 1,
                )

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

    def test_deferred_predecessor_verification_matches_full_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "deferred-chain-test",
                            "index": index,
                            "payload": "d" * 120,
                        }
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    head, predecessor = grabowski_mcp._read_audit_head_unlocked(audit)
                self.assertIsNotNone(predecessor)
                assert predecessor is not None

                deferred, deferred_compatibility = grabowski_mcp._read_audit_chain_unlocked(
                    audit,
                    use_segment_cache=True,
                    retain_verified_segment_data=False,
                    initial_expected=predecessor,
                )
                self.assertTrue(deferred)

                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    full, full_compatibility = grabowski_mcp._read_audit_chain_unlocked(audit)

                combined = [head, *deferred]
                self.assertEqual(
                    [item[0] for item in combined],
                    [item[0] for item in full],
                )
                self.assertEqual(
                    [item[2]["segment_sha256"] for item in combined],
                    [item[2]["segment_sha256"] for item in full],
                )
                self.assertEqual(deferred_compatibility, full_compatibility)

                wrong_binding = dict(predecessor)
                wrong_binding["sha256"] = (
                    "0" * 64 if predecessor.get("sha256") != "0" * 64 else "1" * 64
                )
                with self.assertRaisesRegex(ValueError, "audit-segment-sha256-mismatch"):
                    grabowski_mcp._read_audit_chain_unlocked(
                        audit,
                        initial_expected=wrong_binding,
                    )

    def test_deferred_chain_preserves_full_chain_segment_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(40):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "deferred-limit-test",
                            "index": index,
                            "payload": "l" * 160,
                        }
                    )
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertGreaterEqual(status["archived_segment_count"], 2)
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    _head, predecessor = grabowski_mcp._read_audit_head_unlocked(audit)
                self.assertIsNotNone(predecessor)
                assert predecessor is not None
                with patch.object(grabowski_mcp, "MAX_AUDIT_SEGMENTS", 1):
                    with self.assertRaisesRegex(ValueError, "audit-segment-limit-exceeded"):
                        grabowski_mcp._read_audit_chain_unlocked(audit)
                    with self.assertRaisesRegex(ValueError, "audit-segment-limit-exceeded"):
                        grabowski_mcp._read_audit_chain_unlocked(
                            audit,
                            initial_expected=predecessor,
                        )

    def test_capture_verified_snapshot_matches_real_full_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(30):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "snapshot-real-chain-test",
                            "index": index,
                            "payload": "r" * 120,
                        }
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                snapshot = grabowski_audit_query.capture_verified_audit_snapshot(audit)
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    full, compatibility = grabowski_mcp._read_audit_chain_unlocked(
                        audit,
                        use_segment_cache=False,
                    )
                chronological = list(reversed(full))
                self.assertEqual(
                    [segment.path for segment in snapshot.segments],
                    [item[0] for item in chronological],
                )
                self.assertEqual(
                    [segment.segment_sha256 for segment in snapshot.segments],
                    [item[2]["segment_sha256"] for item in chronological],
                )
                self.assertEqual(
                    snapshot.total_records,
                    sum(item[2]["records"] for item in full),
                )
                self.assertEqual(snapshot.archived_segment_count, len(full) - 1)
                self.assertEqual(snapshot.legacy_rotation_compatibility, compatibility)
                self.assertTrue(snapshot.segments[-1].active)
                self.assertIsNotNone(snapshot.segments[-1].captured_data)

    def test_capture_snapshot_excludes_rotation_after_head_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "snapshot-race-before",
                            "index": index,
                            "payload": "b" * 120,
                        }
                    )
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    before_components, before_compatibility = (
                        grabowski_mcp._read_audit_chain_unlocked(
                            audit,
                            use_segment_cache=False,
                        )
                    )
                before_paths = [item[0] for item in reversed(before_components)]
                before_hashes = [
                    item[2]["segment_sha256"]
                    for item in reversed(before_components)
                ]
                before_total = sum(item[2]["records"] for item in before_components)
                real_lock = grabowski_mcp._audit_coordination_lock
                race_armed = True

                @contextmanager
                def lock_then_race(path, *, exclusive):
                    nonlocal race_armed
                    with real_lock(path, exclusive=exclusive):
                        yield
                    if race_armed and not exclusive:
                        race_armed = False
                        for index in range(30):
                            grabowski_mcp._append_audit(
                                {
                                    "operation": "snapshot-race-after",
                                    "index": index,
                                    "payload": "a" * 180,
                                }
                            )

                with patch.object(
                    grabowski_mcp,
                    "_audit_coordination_lock",
                    lock_then_race,
                ):
                    snapshot = grabowski_audit_query.capture_verified_audit_snapshot(audit)

                after = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(race_armed)
                self.assertGreater(after["total_records"], before_total)
                self.assertEqual(snapshot.total_records, before_total)
                self.assertEqual(snapshot.legacy_rotation_compatibility, before_compatibility)
                self.assertEqual([segment.path for segment in snapshot.segments], before_paths)
                self.assertEqual(
                    [segment.segment_sha256 for segment in snapshot.segments],
                    before_hashes,
                )

    def test_metadata_only_chain_read_retains_verified_segment_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "metadata-only-test", "index": index, "payload": "s" * 120}
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    warm, _compatibility = grabowski_mcp._read_audit_chain_unlocked(
                        audit,
                        use_segment_cache=True,
                    )
                self.assertGreater(len(warm), 1)
                with grabowski_mcp._audit_coordination_lock(audit, exclusive=False):
                    metadata_only, _compatibility = grabowski_mcp._read_audit_chain_unlocked(
                        audit,
                        use_segment_cache=True,
                        retain_verified_segment_data=False,
                    )
                self.assertTrue(metadata_only[0][1])
                for segment_path, data, status in metadata_only[1:]:
                    self.assertEqual(data, b"")
                    self.assertEqual(len(status["segment_sha256"]), 64)
                    archived_data = segment_path.read_bytes()
                    self.assertEqual(
                        hashlib.sha256(archived_data).hexdigest(),
                        status["segment_sha256"],
                    )

    def test_cached_segment_tamper_is_detected_even_when_mtime_is_restored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "cache-tamper-test", "index": index, "payload": "c" * 120}
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                warmed = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(warmed["valid"], warmed)
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                before = segment.stat()
                data = segment.read_bytes()
                segment.write_bytes(
                    data[:-1] + (b"X" if data[-1:] != b"X" else b"Y")
                )
                os.chmod(segment, 0o600)
                os.utime(
                    segment,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                )
                after = segment.stat()
                self.assertEqual(after.st_size, before.st_size)
                self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
                self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
                active_before = audit.read_bytes()
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    grabowski_mcp._append_audit(
                        {"operation": "must-not-trust-stale-cache"}
                    )
                self.assertEqual(audit.read_bytes(), active_before)

    def test_preappend_snapshot_drift_is_detected_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "snapshot-race", "index": index, "payload": "l" * 120}
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                original = grabowski_mcp._verify_audit_predecessor_snapshot
                tampered = False

                def tamper_then_verify(predecessor, snapshot):
                    nonlocal tampered
                    if not tampered:
                        data = segment.read_bytes()
                        segment.write_bytes(
                            data[:-1] + (b"X" if data[-1:] != b"X" else b"Y")
                        )
                        os.chmod(segment, 0o600)
                        tampered = True
                    return original(predecessor, snapshot)

                active_before = audit.read_bytes()
                with patch.object(
                    grabowski_mcp,
                    "_verify_audit_predecessor_snapshot",
                    side_effect=tamper_then_verify,
                ):
                    with self.assertRaisesRegex(RuntimeError, "verification failed"):
                        grabowski_mcp._append_audit(
                            {"operation": "must-not-append-snapshot-race"}
                        )
                self.assertTrue(tampered)
                self.assertEqual(audit.read_bytes(), active_before)

    def test_preappend_snapshot_recheck_preserves_file_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "snapshot-contract-test",
                            "index": index,
                            "payload": "m" * 120,
                        }
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                original = grabowski_mcp._verify_audit_predecessor_snapshot
                broadened = False

                def broaden_then_verify(predecessor, snapshot):
                    nonlocal broadened
                    if not broadened:
                        os.chmod(segment, 0o644)
                        broadened = True
                    return original(predecessor, snapshot)

                active_before = audit.read_bytes()
                with patch.object(
                    grabowski_mcp,
                    "_verify_audit_predecessor_snapshot",
                    side_effect=broaden_then_verify,
                ):
                    with self.assertRaisesRegex(
                        PermissionError,
                        "file contract",
                    ):
                        grabowski_mcp._append_audit(
                            {"operation": "must-not-append-broad-evidence"}
                        )

                self.assertTrue(broadened)
                self.assertEqual(audit.read_bytes(), active_before)

    def test_preappend_snapshot_recheck_rejects_symlink_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "snapshot-symlink-test",
                            "index": index,
                            "payload": "s" * 120,
                        }
                    )
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                original = grabowski_mcp._verify_audit_predecessor_snapshot
                replaced = False

                def replace_with_symlink_then_verify(predecessor, snapshot):
                    nonlocal replaced
                    if not replaced:
                        preserved = segment.with_name(segment.name + ".preserved")
                        segment.rename(preserved)
                        segment.symlink_to(preserved)
                        replaced = True
                    return original(predecessor, snapshot)

                active_before = audit.read_bytes()
                with patch.object(
                    grabowski_mcp,
                    "_verify_audit_predecessor_snapshot",
                    side_effect=replace_with_symlink_then_verify,
                ):
                    with self.assertRaisesRegex(
                        PermissionError,
                        "file contract",
                    ):
                        grabowski_mcp._append_audit(
                            {"operation": "must-not-append-symlink-evidence"}
                        )

                self.assertTrue(replaced)
                self.assertEqual(audit.read_bytes(), active_before)

    def test_postappend_predecessor_tamper_rolls_back_active_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "postappend-race", "index": index, "payload": "p" * 120}
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                warmed = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(warmed["valid"], warmed)
                first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
                segment = Path(first["archived_audit_path"])
                original_append = grabowski_mcp._append_payload
                tampered = False

                def append_then_tamper(descriptor, path, payload):
                    nonlocal tampered
                    original_append(descriptor, path, payload)
                    data = segment.read_bytes()
                    segment.write_bytes(
                        data[:-1] + (b"X" if data[-1:] != b"X" else b"Y")
                    )
                    os.chmod(segment, 0o600)
                    tampered = True

                active_before = audit.read_bytes()
                with patch.object(
                    grabowski_mcp,
                    "_append_payload",
                    side_effect=append_then_tamper,
                ):
                    with self.assertRaisesRegex(RuntimeError, "verification failed"):
                        grabowski_mcp._append_audit(
                            {"operation": "must-rollback-after-history-drift"}
                        )
                self.assertTrue(tampered)
                self.assertEqual(audit.read_bytes(), active_before)

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
                self.assertEqual(reader.call_count, 2)
                self.assertTrue(
                    all(call.args[0] == audit for call in reader.call_args_list)
                )

    def test_append_rejects_invalid_predecessor_status_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {"operation": "invalid-success-test", "index": index, "payload": "i" * 120}
                    )
                original = grabowski_mcp._read_audit_chain_unlocked
                injected = False

                def invalid_success(path, *args, **kwargs):
                    nonlocal injected
                    components, compatibility = original(path, *args, **kwargs)
                    if (
                        not injected
                        and kwargs.get("initial_expected") is not None
                        and components
                    ):
                        injected = True
                        segment_path, segment_data, segment_status = components[0]
                        invalid_status = dict(segment_status)
                        invalid_status["valid"] = False
                        invalid_status["error"] = "injected-invalid-segment"
                        components = list(components)
                        components[0] = (
                            segment_path,
                            segment_data,
                            invalid_status,
                        )
                    return components, compatibility

                active_before = audit.read_bytes()
                with patch.object(
                    grabowski_mcp,
                    "_read_audit_chain_unlocked",
                    side_effect=invalid_success,
                ):
                    with self.assertRaisesRegex(RuntimeError, "verification failed"):
                        grabowski_mcp._append_audit(
                            {"operation": "must-not-append-invalid-success"}
                        )
                self.assertTrue(injected)
                self.assertEqual(audit.read_bytes(), active_before)

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

    def test_rotation_close_error_is_not_masked_by_double_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                index = 0
                while not audit.exists() or audit.stat().st_size < 6900:
                    grabowski_mcp._append_audit(
                        {"operation": "close-error-prefill", "index": index, "payload": "x" * 220}
                    )
                    index += 1
                real_rotate = grabowski_mcp._rotate_audit_segment
                real_close = grabowski_mcp._close_audit_descriptor
                after_rotation = False
                post_rotation_close_calls = 0

                def rotate_then_arm(*args, **kwargs):
                    nonlocal after_rotation
                    result = real_rotate(*args, **kwargs)
                    after_rotation = True
                    return result

                def close_then_fail(descriptor):
                    nonlocal after_rotation, post_rotation_close_calls
                    if after_rotation:
                        after_rotation = False
                        post_rotation_close_calls += 1
                        real_close(descriptor)
                        raise RuntimeError("synthetic-close-error-after-real-close")
                    return real_close(descriptor)

                with (
                    patch.object(
                        grabowski_mcp,
                        "_rotate_audit_segment",
                        side_effect=rotate_then_arm,
                    ),
                    patch.object(
                        grabowski_mcp,
                        "_close_audit_descriptor",
                        side_effect=close_then_fail,
                    ),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "synthetic-close-error-after-real-close",
                    ):
                        grabowski_mcp._append_audit(
                            {"operation": "trigger-close-error", "payload": "y" * 500}
                        )
                self.assertEqual(post_rotation_close_calls, 1)
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)

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
                snapshot = grabowski_audit_query.capture_verified_audit_snapshot(audit)
                self.assertTrue(snapshot.legacy_rotation_compatibility)
                self.assertEqual(snapshot.archived_segment_count, 1)


    def test_verify_reuses_history_when_only_active_head_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                index = 0
                while True:
                    grabowski_mcp._append_audit(
                        {
                            "operation": "verify-race-before",
                            "index": index,
                            "payload": "r" * 240,
                        }
                    )
                    before = grabowski_mcp._verify_audit_log(audit)
                    if before["archived_segment_count"] > 0:
                        break
                    index += 1

                original = grabowski_mcp._read_audit_chain_unlocked
                race_armed = True
                writer_active = False
                history_scans = 0

                def scan_then_change_head(path, *args, **kwargs):
                    nonlocal race_armed, writer_active, history_scans
                    result = original(path, *args, **kwargs)
                    if (
                        kwargs.get("initial_expected") is not None
                        and not writer_active
                    ):
                        history_scans += 1
                        if race_armed:
                            race_armed = False
                            writer_active = True
                            try:
                                grabowski_mcp._append_audit(
                                    {"operation": "verify-race-after"}
                                )
                            finally:
                                writer_active = False
                    return result

                with patch.object(
                    grabowski_mcp,
                    "_read_audit_chain_unlocked",
                    side_effect=scan_then_change_head,
                ):
                    status = grabowski_mcp._verify_audit_log(audit)

                self.assertFalse(race_armed)
                self.assertEqual(history_scans, 1)
                self.assertTrue(status["valid"], status)
                self.assertEqual(
                    status["total_records"],
                    before["total_records"] + 1,
                )

    def test_verify_scans_immutable_segments_outside_coordination_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
            ):
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "snapshot-lock-test",
                            "index": index,
                            "payload": "v" * 120,
                        }
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                original = grabowski_mcp._read_audit_chain_unlocked
                lock_observations = []
                payload_sizes = []
                lock_path = grabowski_mcp._audit_storage_paths(audit)[
                    "coordination_lock"
                ]

                def observe(path, *args, **kwargs):
                    if kwargs.get("initial_expected") is not None:
                        fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
                        try:
                            try:
                                fcntl.flock(
                                    fd,
                                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                                )
                            except BlockingIOError:
                                lock_observations.append(False)
                            else:
                                lock_observations.append(True)
                                fcntl.flock(fd, fcntl.LOCK_UN)
                        finally:
                            os.close(fd)
                    result = original(path, *args, **kwargs)
                    if kwargs.get("initial_expected") is not None:
                        payload_sizes.extend(
                            len(data)
                            for _segment, data, _status in result[0]
                        )
                    return result

                with patch.object(
                    grabowski_mcp,
                    "_read_audit_chain_unlocked",
                    side_effect=observe,
                ):
                    status = grabowski_mcp._verify_audit_log(audit)

                self.assertTrue(status["valid"], status)
                self.assertTrue(lock_observations)
                self.assertTrue(all(lock_observations))
                self.assertTrue(payload_sizes)
                self.assertEqual(set(payload_sizes), {0})

    def test_append_snapshot_recheck_avoids_evidence_reopens_under_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "snapshot-reopen-test",
                            "index": index,
                            "payload": "o" * 120,
                        }
                    )
                warmed = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(warmed["valid"], warmed)
                original_full = grabowski_mcp._private_evidence_identity
                original_path = grabowski_mcp._private_evidence_path_identity
                full_checks = []
                path_checks_under_lock = []
                lock_path = grabowski_mcp._audit_storage_paths(audit)[
                    "coordination_lock"
                ]

                def coordination_lock_is_free() -> bool:
                    fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
                    try:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            return False
                        fcntl.flock(fd, fcntl.LOCK_UN)
                        return True
                    finally:
                        os.close(fd)

                def observe_full(path, *, max_bytes):
                    full_checks.append(str(path))
                    return original_full(path, max_bytes=max_bytes)

                def observe_path(path, *, max_bytes):
                    if not coordination_lock_is_free():
                        path_checks_under_lock.append(str(path))
                    return original_path(path, max_bytes=max_bytes)

                with (
                    patch.object(
                        grabowski_mcp,
                        "_private_evidence_identity",
                        side_effect=observe_full,
                    ),
                    patch.object(
                        grabowski_mcp,
                        "_private_evidence_path_identity",
                        side_effect=observe_path,
                    ),
                ):
                    grabowski_mcp._append_audit(
                        {"operation": "snapshot-reopen-measure"}
                    )

                self.assertEqual(full_checks, [])
                self.assertTrue(path_checks_under_lock)

    def test_append_snapshot_is_independent_of_global_cache_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
                patch.object(
                    grabowski_mcp,
                    "MAX_AUDIT_SEGMENT_CACHE_ENTRIES",
                    2,
                ),
            ):
                for index in range(120):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "cache-capacity-lock-test",
                            "index": index,
                            "payload": "c" * 260,
                        }
                    )
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertGreater(status["archived_segment_count"], 2)
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                original_file = grabowski_mcp._read_audit_file
                archived_reads_under_lock = []
                lock_path = grabowski_mcp._audit_storage_paths(audit)[
                    "coordination_lock"
                ]

                def coordination_lock_is_free() -> bool:
                    fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
                    try:
                        try:
                            fcntl.flock(
                                fd,
                                fcntl.LOCK_EX | fcntl.LOCK_NB,
                            )
                        except BlockingIOError:
                            return False
                        fcntl.flock(fd, fcntl.LOCK_UN)
                        return True
                    finally:
                        os.close(fd)

                def observe_file(path):
                    if path != audit and not coordination_lock_is_free():
                        archived_reads_under_lock.append(str(path))
                    return original_file(path)

                with patch.object(
                    grabowski_mcp,
                    "_read_audit_file",
                    side_effect=observe_file,
                ):
                    grabowski_mcp._append_audit(
                        {"operation": "after-cache-capacity-overflow"}
                    )

                self.assertEqual(archived_reads_under_lock, [])
                verified = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(verified["valid"], verified)

    def test_append_verifies_predecessors_outside_then_snapshot_inside_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._patches(state)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
            ):
                for index in range(25):
                    grabowski_mcp._append_audit(
                        {
                            "operation": "append-lock-test",
                            "index": index,
                            "payload": "a" * 120,
                        }
                    )
                grabowski_mcp.AUDIT_SEGMENT_VERIFICATION_CACHE.clear()
                original_chain = grabowski_mcp._read_audit_chain_unlocked
                original_snapshot = (
                    grabowski_mcp._verify_audit_predecessor_snapshot
                )
                original_file = grabowski_mcp._read_audit_file
                chain_lock_observations = []
                snapshot_lock_observations = []
                archived_reads_under_lock = []
                lock_path = grabowski_mcp._audit_storage_paths(audit)[
                    "coordination_lock"
                ]

                def coordination_lock_is_free() -> bool:
                    fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC)
                    try:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            return False
                        fcntl.flock(fd, fcntl.LOCK_UN)
                        return True
                    finally:
                        os.close(fd)

                def observe_chain(path, *args, **kwargs):
                    if kwargs.get("initial_expected") is not None:
                        chain_lock_observations.append(
                            coordination_lock_is_free()
                        )
                    return original_chain(path, *args, **kwargs)

                def observe_snapshot(predecessor, snapshot):
                    snapshot_lock_observations.append(
                        coordination_lock_is_free()
                    )
                    return original_snapshot(predecessor, snapshot)

                def observe_file(path):
                    if path != audit and not coordination_lock_is_free():
                        archived_reads_under_lock.append(str(path))
                    return original_file(path)

                with (
                    patch.object(
                        grabowski_mcp,
                        "_read_audit_chain_unlocked",
                        side_effect=observe_chain,
                    ),
                    patch.object(
                        grabowski_mcp,
                        "_verify_audit_predecessor_snapshot",
                        side_effect=observe_snapshot,
                    ),
                    patch.object(
                        grabowski_mcp,
                        "_read_audit_file",
                        side_effect=observe_file,
                    ),
                ):
                    grabowski_mcp._append_audit(
                        {"operation": "append-after-unlocked-predecessor-scan"}
                    )

                self.assertEqual(chain_lock_observations, [True])
                self.assertEqual(snapshot_lock_observations, [False, False])
                self.assertEqual(archived_reads_under_lock, [])
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)

if __name__ == "__main__":
    unittest.main()

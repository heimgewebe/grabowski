from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_operator_v2_runtime import grabowski_mcp


def _append_worker(start_event, worker: int, count: int) -> None:
    start_event.wait()
    for index in range(count):
        grabowski_mcp._append_audit(
            {
                "operation": "parallel-test",
                "worker": worker,
                "worker_index": index,
            }
        )


class AuditInterprocessLockTests(unittest.TestCase):
    def _state_patches(self, state: Path):
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
        )

    def test_missing_audit_verification_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._state_patches(state)
            with patches[0], patches[1], patches[2], patches[3]:
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertTrue(status["valid"], status)
                self.assertFalse(status["exists"])
                self.assertEqual(list(state.iterdir()), [])

    def test_parallel_processes_append_one_valid_monotonic_chain(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("requires fork semantics")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._state_patches(state)
            with patches[0], patches[1], patches[2], patches[3]:
                context = multiprocessing.get_context("fork")
                start_event = context.Event()
                workers = 8
                records_per_worker = 12
                processes = [
                    context.Process(
                        target=_append_worker,
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
                expected_records = workers * records_per_worker
                self.assertTrue(status["valid"], status)
                self.assertEqual(status["records"], expected_records)
                records = [
                    json.loads(line)
                    for line in audit.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(
                    [record["sequence"] for record in records],
                    list(range(1, expected_records + 1)),
                )
                self.assertEqual(
                    len({record["record_sha256"] for record in records}),
                    expected_records,
                )

    def test_symlink_audit_is_rejected_without_target_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._state_patches(state)
            outside = root / "outside.jsonl"
            outside.write_bytes(b"")
            os.chmod(outside, 0o600)
            audit.symlink_to(outside)
            with patches[0], patches[1], patches[2], patches[3]:
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(status["valid"])
                with self.assertRaisesRegex(PermissionError, "symlink"):
                    grabowski_mcp._append_audit({"operation": "blocked"})
                self.assertEqual(outside.read_bytes(), b"")

    def test_hardlinked_or_broad_audit_is_rejected(self) -> None:
        for unsafe_kind in ("hardlink", "mode"):
            with self.subTest(unsafe_kind=unsafe_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / "state"
                state.mkdir(mode=0o700)
                audit, patches = self._state_patches(state)
                if unsafe_kind == "hardlink":
                    source = root / "shared.jsonl"
                    source.write_bytes(b"")
                    os.chmod(source, 0o600)
                    os.link(source, audit)
                else:
                    audit.write_bytes(b"")
                    os.chmod(audit, 0o644)
                with patches[0], patches[1], patches[2], patches[3]:
                    with self.assertRaisesRegex(PermissionError, "file contract"):
                        grabowski_mcp._append_audit({"operation": "blocked"})
                    self.assertEqual(audit.read_bytes(), b"")

    def test_lock_timeout_fails_closed_without_hanging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._state_patches(state)
            audit.write_bytes(b"")
            os.chmod(audit, 0o600)
            holder = os.open(audit, os.O_RDWR | os.O_CLOEXEC)
            try:
                fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patch.object(grabowski_mcp, "AUDIT_LOCK_TIMEOUT_SECONDS", 0.05),
                ):
                    status = grabowski_mcp._verify_audit_log(audit)
                    self.assertFalse(status["valid"])
                    self.assertIn("timed out", status["error"])
                    with self.assertRaisesRegex(RuntimeError, "timed out"):
                        grabowski_mcp._append_audit({"operation": "blocked"})
                    self.assertEqual(audit.read_bytes(), b"")
            finally:
                fcntl.flock(holder, fcntl.LOCK_UN)
                os.close(holder)

    def test_audit_path_rebind_during_append_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._state_patches(state)
            with patches[0], patches[1], patches[2], patches[3]:
                grabowski_mcp._append_audit({"operation": "first"})
                original_write_all = grabowski_mcp._write_all

                def replace_before_write(descriptor: int, payload: bytes) -> None:
                    displaced = state / "displaced-audit.jsonl"
                    os.replace(audit, displaced)
                    audit.write_bytes(b"")
                    os.chmod(audit, 0o600)
                    original_write_all(descriptor, payload)

                with patch.object(
                    grabowski_mcp,
                    "_write_all",
                    side_effect=replace_before_write,
                ):
                    with self.assertRaisesRegex(
                        PermissionError,
                        "file contract",
                    ):
                        grabowski_mcp._append_audit({"operation": "blocked"})
                self.assertEqual(audit.read_bytes(), b"")

    def test_append_refuses_to_cross_audit_byte_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            audit, patches = self._state_patches(state)
            with patches[0], patches[1], patches[2], patches[3]:
                grabowski_mcp._append_audit({"operation": "first"})
                before = audit.read_bytes()
                with patch.object(
                    grabowski_mcp,
                    "MAX_AUDIT_BYTES",
                    len(before) + 1,
                ):
                    with self.assertRaisesRegex(ValueError, "byte limit"):
                        grabowski_mcp._append_audit({"operation": "blocked"})
                self.assertEqual(audit.read_bytes(), before)

    def test_shared_audit_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o755)
            os.chmod(state, 0o755)
            audit, patches = self._state_patches(state)
            with patches[0], patches[1], patches[2], patches[3]:
                status = grabowski_mcp._verify_audit_log(audit)
                self.assertFalse(status["valid"])
                self.assertIn("parent directory", status["error"])
                with self.assertRaisesRegex(PermissionError, "parent directory"):
                    grabowski_mcp._append_audit({"operation": "blocked"})
                self.assertFalse(audit.exists())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "grabowski_transport_assertion_filter_test_module",
    ROOT / "src/grabowski_transport_assertion.py",
)
assert SPEC is not None and SPEC.loader is not None
assertion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assertion)

SECRET = "A" * 43
SCOPE = "1" * 64
RUNTIME = "2" * 64
ARGS = assertion.canonical_arguments_sha256({"argv": ["true"]})


def _evidence(index: int, *, now: int = 100) -> dict[str, object]:
    request_id = f"{index + 1:032x}"
    body = hashlib.sha256(f"body-{index}".encode()).hexdigest()
    mac = assertion.assertion_mac(
        secret=SECRET,
        request_id=request_id,
        issued_at_unix=now,
        audience=assertion.ASSERTION_AUDIENCE,
        tool_name="grabowski_terminal_run",
        arguments_sha256=ARGS,
        body_sha256=body,
        runtime_binding_sha256=RUNTIME,
    )
    return {
        "secret": SECRET,
        "client_scope_sha256": SCOPE,
        "runtime_binding_sha256": RUNTIME,
        "asserted_runtime_binding_sha256": RUNTIME,
        "request_id": request_id,
        "issued_at_unix": now,
        "audience": assertion.ASSERTION_AUDIENCE,
        "tool_name": "grabowski_terminal_run",
        "arguments_sha256": ARGS,
        "body_sha256": body,
        "mac_sha256": mac,
    }


class ReplayFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "state"
        assertion.STATE_ROOT = root
        assertion.LOCK_PATH = root / ".lock"

    def test_fixed_size_bounded_files_and_replay(self) -> None:
        for index in range(256):
            assertion.consume_assertion(**_evidence(index), now_unix=101)
        path = assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME
        self.assertEqual(path.stat().st_size, assertion.REPLAY_FILTER_TOTAL_BYTES)
        self.assertEqual(
            sorted(item.name for item in assertion.STATE_ROOT.iterdir()),
            [
                ".lock",
                assertion.REPLAY_FILTER_INTEGRITY_MARKER_FILENAME,
                assertion.REPLAY_FILTER_FILENAME,
                assertion.REPLAY_FILTER_INTEGRITY_FILENAME,
                assertion.REPLAY_FILTER_INTEGRITY_ROOT_FILENAME,
            ],
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**_evidence(17, now=5000), now_unix=5001)

    def test_replay_filter_survives_client_scope_restart(self) -> None:
        first = _evidence(4)
        assertion.consume_assertion(**first, now_unix=101)
        restarted = dict(first)
        restarted["client_scope_sha256"] = "3" * 64
        restarted["issued_at_unix"] = 5000
        restarted["mac_sha256"] = assertion.assertion_mac(
            secret=SECRET,
            request_id=str(restarted["request_id"]),
            issued_at_unix=5000,
            audience=assertion.ASSERTION_AUDIENCE,
            tool_name="grabowski_terminal_run",
            arguments_sha256=ARGS,
            body_sha256=str(restarted["body_sha256"]),
            runtime_binding_sha256=RUNTIME,
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**restarted, now_unix=5001)

    def test_legacy_tombstone_remains_authoritative(self) -> None:
        item = _evidence(2)
        assertion.STATE_ROOT.mkdir(mode=0o700)
        scope_dir = assertion.STATE_ROOT / SCOPE
        scope_dir.mkdir(mode=0o700)
        receipt = {
            "request_id": item["request_id"],
            "client_scope_sha256": SCOPE,
            "tool_name": item["tool_name"],
            "arguments_sha256": item["arguments_sha256"],
            "body_sha256": item["body_sha256"],
            "runtime_binding_sha256": RUNTIME,
        }
        path = scope_dir / f"{item['request_id']}.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**item, now_unix=101)
        self.assertFalse(
            (assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME).exists()
        )

    def test_legacy_tombstone_survives_client_scope_restart(self) -> None:
        item = _evidence(3)
        assertion.STATE_ROOT.mkdir(mode=0o700)
        old_scope = "9" * 64
        scope_dir = assertion.STATE_ROOT / old_scope
        scope_dir.mkdir(mode=0o700)
        receipt = {
            "request_id": item["request_id"],
            "client_scope_sha256": old_scope,
            "tool_name": item["tool_name"],
            "arguments_sha256": item["arguments_sha256"],
            "body_sha256": item["body_sha256"],
            "runtime_binding_sha256": RUNTIME,
        }
        path = scope_dir / f"{item['request_id']}.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**item, now_unix=101)
        self.assertFalse(
            (assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME).exists()
        )

    def test_legacy_tombstone_survives_secret_rotation(self) -> None:
        item = _evidence(14)
        session_id = "legacy-connector-session"
        rpc_request_id = "legacy-rpc-14"
        item["request_id"] = assertion.derive_request_id(
            secret=SECRET,
            session_id=session_id,
            rpc_request_id=rpc_request_id,
            body_sha256=str(item["body_sha256"]),
        )
        item["mac_sha256"] = assertion.assertion_mac(
            secret=SECRET,
            request_id=str(item["request_id"]),
            issued_at_unix=int(item["issued_at_unix"]),
            audience=assertion.ASSERTION_AUDIENCE,
            tool_name=str(item["tool_name"]),
            arguments_sha256=str(item["arguments_sha256"]),
            body_sha256=str(item["body_sha256"]),
            runtime_binding_sha256=RUNTIME,
        )
        assertion.STATE_ROOT.mkdir(mode=0o700)
        old_scope = "8" * 64
        scope_dir = assertion.STATE_ROOT / old_scope
        scope_dir.mkdir(mode=0o700)
        receipt = {
            "request_id": item["request_id"],
            "client_scope_sha256": old_scope,
            "tool_name": item["tool_name"],
            "arguments_sha256": item["arguments_sha256"],
            "body_sha256": item["body_sha256"],
            "runtime_binding_sha256": RUNTIME,
        }
        path = scope_dir / f"{item['request_id']}.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)

        rotated_secret = "B" * 43
        rotated = dict(item)
        rotated["secret"] = rotated_secret
        rotated["client_scope_sha256"] = "7" * 64
        rotated["request_id"] = assertion.derive_request_id(
            secret=rotated_secret,
            session_id=session_id,
            rpc_request_id=rpc_request_id,
            body_sha256=str(rotated["body_sha256"]),
        )
        self.assertNotEqual(item["request_id"], rotated["request_id"])
        rotated["mac_sha256"] = assertion.assertion_mac(
            secret=rotated_secret,
            request_id=str(rotated["request_id"]),
            issued_at_unix=int(rotated["issued_at_unix"]),
            audience=assertion.ASSERTION_AUDIENCE,
            tool_name=str(rotated["tool_name"]),
            arguments_sha256=str(rotated["arguments_sha256"]),
            body_sha256=str(rotated["body_sha256"]),
            runtime_binding_sha256=RUNTIME,
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**rotated, now_unix=101)
        self.assertFalse(
            (assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME).exists()
        )

    def test_existing_v1_filter_is_migrated_without_losing_replay_bits(self) -> None:
        item = _evidence(5)
        assertion.STATE_ROOT.mkdir(mode=0o700)
        path = assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.ftruncate(fd, assertion.REPLAY_FILTER_TOTAL_BYTES)
            os.pwrite(fd, assertion.REPLAY_FILTER_HEADER, 0)
            replay_scope = assertion._replay_scope_sha256(SECRET)
            for bit in assertion._replay_filter_positions(
                replay_scope, str(item["request_id"])
            ):
                offset = assertion.REPLAY_FILTER_HEADER_BYTES + bit // 8
                current = os.pread(fd, 1, offset)[0]
                os.pwrite(fd, bytes((current | (1 << (bit % 8)),)), offset)
            os.fsync(fd)
        finally:
            os.close(fd)
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**item, now_unix=101)
        self.assertTrue(
            (
                assertion.STATE_ROOT
                / assertion.REPLAY_FILTER_INTEGRITY_MARKER_FILENAME
            ).is_file()
        )

    def test_data_page_corruption_fails_closed(self) -> None:
        item = _evidence(6)
        assertion.consume_assertion(**item, now_unix=101)
        replay_scope = assertion._replay_scope_sha256(SECRET)
        bit = assertion._replay_filter_positions(
            replay_scope, str(item["request_id"])
        )[0]
        offset = assertion.REPLAY_FILTER_HEADER_BYTES + bit // 8
        fd = os.open(assertion._replay_filter_path(), os.O_RDWR)
        try:
            current = os.pread(fd, 1, offset)[0]
            os.pwrite(fd, bytes((current & ~(1 << (bit % 8)),)), offset)
            os.fsync(fd)
        finally:
            os.close(fd)
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "integrity mismatch"
        ):
            assertion.consume_assertion(**item, now_unix=101)

    def test_crash_window_after_data_fsync_fails_closed(self) -> None:
        assertion.consume_assertion(**_evidence(7), now_unix=101)
        interrupted = _evidence(8)
        original = assertion._pwrite_exact

        def fail_integrity_write(
            fd: int, value: bytes, offset: int, label: str
        ) -> None:
            if label == "transport replay integrity digest":
                raise OSError("simulated crash before integrity durability")
            original(fd, value, offset, label)

        with mock.patch.object(
            assertion, "_pwrite_exact", side_effect=fail_integrity_write
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                assertion.consume_assertion(**interrupted, now_unix=101)
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "mutation was interrupted"
        ):
            assertion.consume_assertion(**_evidence(14), now_unix=101)

    def test_integrity_metadata_cannot_be_silently_recreated(self) -> None:
        assertion.consume_assertion(**_evidence(9), now_unix=101)
        assertion._replay_filter_integrity_path().unlink()
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "required but missing"
        ):
            assertion.consume_assertion(**_evidence(10), now_unix=101)

    def test_integrity_root_cannot_be_silently_recreated(self) -> None:
        assertion.consume_assertion(**_evidence(15), now_unix=101)
        assertion._replay_filter_integrity_root_path().unlink()
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "required but missing"
        ):
            assertion.consume_assertion(**_evidence(16), now_unix=101)

    def test_digest_table_corruption_blocks_an_unrelated_request(self) -> None:
        assertion.consume_assertion(**_evidence(17), now_unix=101)
        integrity_path = assertion._replay_filter_integrity_path()
        fd = os.open(integrity_path, os.O_RDWR)
        try:
            offset = assertion.REPLAY_FILTER_INTEGRITY_TOTAL_BYTES - 1
            current = os.pread(fd, 1, offset)
            os.pwrite(fd, bytes((current[0] ^ 1,)), offset)
            os.fsync(fd)
        finally:
            os.close(fd)
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "integrity root mismatch"
        ):
            assertion.consume_assertion(**_evidence(18), now_unix=101)

    def test_secret_rotation_retains_stable_scope_replay(self) -> None:
        item = _evidence(11)
        session_id = "connector-session"
        rpc_request_id = "rpc-11"
        item["request_id"] = assertion.derive_request_id(
            secret=SECRET,
            session_id=session_id,
            rpc_request_id=rpc_request_id,
            body_sha256=str(item["body_sha256"]),
        )
        item["mac_sha256"] = assertion.assertion_mac(
            secret=SECRET,
            request_id=str(item["request_id"]),
            issued_at_unix=int(item["issued_at_unix"]),
            audience=assertion.ASSERTION_AUDIENCE,
            tool_name=str(item["tool_name"]),
            arguments_sha256=str(item["arguments_sha256"]),
            body_sha256=str(item["body_sha256"]),
            runtime_binding_sha256=RUNTIME,
        )
        assertion.consume_assertion(**item, now_unix=101)
        rotated_secret = "B" * 43
        rotated = dict(item)
        rotated["secret"] = rotated_secret
        rotated["request_id"] = assertion.derive_request_id(
            secret=rotated_secret,
            session_id=session_id,
            rpc_request_id=rpc_request_id,
            body_sha256=str(rotated["body_sha256"]),
        )
        self.assertNotEqual(item["request_id"], rotated["request_id"])
        rotated["mac_sha256"] = assertion.assertion_mac(
            secret=rotated_secret,
            request_id=str(rotated["request_id"]),
            issued_at_unix=int(rotated["issued_at_unix"]),
            audience=assertion.ASSERTION_AUDIENCE,
            tool_name=str(rotated["tool_name"]),
            arguments_sha256=str(rotated["arguments_sha256"]),
            body_sha256=str(rotated["body_sha256"]),
            runtime_binding_sha256=RUNTIME,
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**rotated, now_unix=101)

    def test_parent_and_filter_metadata_fsync_order(self) -> None:
        parent = assertion.STATE_ROOT.parent
        directory_fsyncs: list[Path] = []
        real_directory_fsync = assertion._fsync_directory

        def record_directory_fsync(path: Path) -> None:
            directory_fsyncs.append(path)
            real_directory_fsync(path)

        with mock.patch.object(
            assertion, "_fsync_directory", side_effect=record_directory_fsync
        ):
            assertion.consume_assertion(**_evidence(12), now_unix=101)
        self.assertIn(parent, directory_fsyncs)
        self.assertLess(
            directory_fsyncs.index(parent),
            directory_fsyncs.index(assertion.STATE_ROOT),
        )

        fsync_targets: list[str] = []
        real_fsync = os.fsync

        def record_fsync(fd: int) -> None:
            fsync_targets.append(os.readlink(f"/proc/self/fd/{fd}"))
            real_fsync(fd)

        with mock.patch.object(assertion.os, "fsync", side_effect=record_fsync):
            assertion.consume_assertion(**_evidence(13), now_unix=101)
        filter_path = str(assertion._replay_filter_path())
        integrity_path = str(assertion._replay_filter_integrity_path())
        self.assertLess(
            max(index for index, path in enumerate(fsync_targets) if path == filter_path),
            max(
                index
                for index, path in enumerate(fsync_targets)
                if path == integrity_path
            ),
        )

    def test_corrupt_existing_filter_fails_closed(self) -> None:
        assertion.STATE_ROOT.mkdir(mode=0o700)
        path = assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME
        with path.open("wb") as handle:
            handle.truncate(assertion.REPLAY_FILTER_TOTAL_BYTES)
        path.chmod(0o600)
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "header mismatch"
        ):
            assertion.consume_assertion(**_evidence(9), now_unix=101)


if __name__ == "__main__":
    unittest.main()

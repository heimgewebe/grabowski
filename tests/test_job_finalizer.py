from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_job_finalizer as finalizer  # noqa: E402


class JobFinalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "jobs"
        self.root.mkdir(mode=0o700)
        self.job_id = "0123456789ab"
        self.unit = f"grabowski-job-{self.job_id}"
        self.directory = self.root / self.unit
        self.directory.mkdir(mode=0o700)
        self.metadata = {
            "schema_version": 1,
            "job_id": self.job_id,
            "unit": self.unit,
            "owner": "uid:1000",
            "scope": {"cwd": "/tmp", "runtime_seconds": 60},
            "argv_sha256": "a" * 64,
            "notify_on_done": {
                "requested": True,
                "channels": ["operator_outbox"],
                "note": "done",
            },
        }
        self._write_metadata(self.metadata)
        self.patcher = mock.patch.object(finalizer, "JOBS_ROOT", self.root)
        self.patcher.start()

    def tearDown(self) -> None:
        self.patcher.stop()
        self.temporary.cleanup()

    def _write_metadata(self, value: dict, *, mode: int = 0o600) -> Path:
        path = self.directory / "metadata.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(mode)
        return path

    def _environment(self, result: str = "success", status: str = "0") -> dict[str, str]:
        return {
            "SERVICE_RESULT": result,
            "EXIT_CODE": "exited",
            "EXIT_STATUS": status,
        }

    def test_finalize_creates_private_hash_bound_receipt_and_is_idempotent(self) -> None:
        first = finalizer.finalize(self.directory, self._environment())
        second = finalizer.finalize(self.directory, self._environment())

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(second["reason"], "already_exists")
        receipt = first["receipt"]
        expected_hash = receipt["receipt_sha256"]
        unhashed = dict(receipt)
        unhashed.pop("receipt_sha256")
        self.assertEqual(
            expected_hash,
            hashlib.sha256(finalizer._canonical(unhashed)).hexdigest(),
        )
        metadata = (self.directory / "notification.json").lstat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(receipt["terminal_status"], "succeeded")
        self.assertEqual(receipt["delivery_state"], "queued")
        self.assertIn("external_push_delivery", receipt["does_not_establish"])
        self.assertEqual(list(self.directory.glob(".notification.json.*.tmp")), [])

    def test_no_receipt_when_notification_not_requested(self) -> None:
        self.metadata["notify_on_done"]["requested"] = False
        self._write_metadata(self.metadata)
        result = finalizer.finalize(self.directory, self._environment())
        self.assertEqual(result, {"created": False, "reason": "notification_not_requested"})
        self.assertFalse((self.directory / "notification.json").exists())

    def test_service_result_mapping(self) -> None:
        cases = {
            ("success", "0"): "succeeded",
            ("timeout", "1"): "timed_out",
            ("signal", "9"): "signalled",
            ("core-dump", "11"): "signalled",
            ("exit-code", "2"): "failed",
            ("", ""): "terminated_unclear",
        }
        for index, ((service_result, exit_status), expected) in enumerate(cases.items()):
            with self.subTest(service_result=service_result, exit_status=exit_status):
                directory = self.root / f"grabowski-job-{index:012x}"
                directory.mkdir(mode=0o700)
                value = dict(self.metadata)
                value["job_id"] = f"{index:012x}"
                value["unit"] = directory.name
                path = directory / "metadata.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
                result = finalizer.finalize(
                    directory,
                    {
                        "SERVICE_RESULT": service_result,
                        "EXIT_CODE": "exited",
                        "EXIT_STATUS": exit_status,
                    },
                )
                self.assertEqual(result["receipt"]["terminal_status"], expected)

    def test_rejects_path_escape_and_symlink_job_directory(self) -> None:
        outside = Path(self.temporary.name) / self.unit
        outside.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError, "outside"):
            finalizer.finalize(outside, self._environment())

        target = self.root / "grabowski-job-111111111111"
        target.mkdir(mode=0o700)
        link = self.root / "grabowski-job-222222222222"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "non-symlink"):
            finalizer.finalize(link, self._environment())

    def test_rejects_symlink_hardlink_public_mode_and_oversize_metadata(self) -> None:
        metadata = self.directory / "metadata.json"
        original = metadata.read_bytes()

        metadata.unlink()
        target = self.directory / "target.json"
        target.write_bytes(original)
        target.chmod(0o600)
        metadata.symlink_to(target.name)
        with self.assertRaises((RuntimeError, OSError)):
            finalizer.finalize(self.directory, self._environment())

        metadata.unlink()
        os.link(target, metadata)
        with self.assertRaisesRegex(RuntimeError, "private regular file"):
            finalizer.finalize(self.directory, self._environment())

        metadata.unlink()
        target.unlink()
        self._write_metadata(self.metadata, mode=0o644)
        with self.assertRaisesRegex(RuntimeError, "private regular file"):
            finalizer.finalize(self.directory, self._environment())

        metadata.write_bytes(b"{" + b" " * finalizer.MAX_METADATA_BYTES + b"}")
        metadata.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "private regular file|too large"):
            finalizer.finalize(self.directory, self._environment())

    def test_rejects_unit_binding_and_invalid_argv_hash(self) -> None:
        self.metadata["unit"] = "grabowski-job-ffffffffffff"
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "unit binding"):
            finalizer.finalize(self.directory, self._environment())

        self.metadata["unit"] = self.unit
        self.metadata["argv_sha256"] = "bad"
        self._write_metadata(self.metadata)
        with self.assertRaisesRegex(RuntimeError, "argv hash"):
            finalizer.finalize(self.directory, self._environment())

    def test_conflicting_existing_receipt_is_preserved(self) -> None:
        target = self.directory / "notification.json"
        target.write_text('{"other":true}\n', encoding="utf-8")
        target.chmod(0o600)
        before = target.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "conflicts"):
            finalizer.finalize(self.directory, self._environment())
        self.assertEqual(target.read_bytes(), before)

    def test_create_only_publish_race_accepts_identical_winner_and_cleans_temp(self) -> None:
        expected = finalizer.finalize(self.directory, self._environment())["receipt"]
        target = self.directory / "notification.json"
        target.unlink()
        real_link = os.link

        def competing_link(source, destination, *, follow_symlinks=True):
            destination = Path(destination)
            destination.write_text(
                json.dumps(expected, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            destination.chmod(0o600)
            raise FileExistsError(destination)

        with mock.patch.object(finalizer.os, "link", side_effect=competing_link):
            result = finalizer.finalize(self.directory, self._environment())
        self.assertFalse(result["created"])
        self.assertEqual(result["receipt"], expected)
        self.assertEqual(list(self.directory.glob(".notification.json.*.tmp")), [])
        self.assertEqual(target.lstat().st_nlink, 1)
        self.assertIsNotNone(real_link)

    def test_detects_metadata_identity_drift(self) -> None:
        path = self.directory / "metadata.json"
        other = self.directory / "other.json"
        other.write_text("{}", encoding="utf-8")
        other.chmod(0o600)
        real = path.lstat()
        drifted = other.lstat()
        with mock.patch.object(Path, "lstat", side_effect=[real, drifted]):
            with self.assertRaisesRegex(RuntimeError, "changed while reading"):
                finalizer._read_private_json(path, max_bytes=finalizer.MAX_METADATA_BYTES)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import grabowski_private_io as private_io


class PrivateCreateOnlyJsonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.target = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self, payload: dict) -> bool:
        return private_io.publish_private_create_only_json(
            self.root,
            self.target,
            payload,
            max_bytes=4096,
            label="test receipt",
        )

    def test_create_only_publication_is_private_durable_and_single_link(self) -> None:
        self.assertTrue(self.publish({"value": 1}))
        self.assertEqual(json.loads(self.target.read_text(encoding="utf-8")), {"value": 1})
        metadata = self.target.lstat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(list(self.root.glob(".receipt.json.*.tmp")), [])

    def test_existing_target_is_not_replaced(self) -> None:
        self.target.write_text('{"winner":true}\n', encoding="utf-8")
        self.target.chmod(0o600)
        before = self.target.read_bytes()
        self.assertFalse(self.publish({"value": 2}))
        self.assertEqual(self.target.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".receipt.json.*.tmp")), [])

    def test_rejects_path_escape_public_directory_and_symlink_directory(self) -> None:
        outside = self.root.parent / "outside.json"
        with self.assertRaisesRegex(ValueError, "direct child"):
            private_io.publish_private_create_only_json(
                self.root,
                outside,
                {},
                max_bytes=4096,
                label="test receipt",
            )

        self.root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "directory identity is unsafe"):
            self.publish({})
        self.root.chmod(0o700)

        real = self.root / "real"
        real.mkdir(mode=0o700)
        linked = self.root / "linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            private_io.publish_private_create_only_json(
                linked,
                linked / "receipt.json",
                {},
                max_bytes=4096,
                label="test receipt",
            )

    def test_size_bound_and_temporary_cleanup_on_link_failure(self) -> None:
        with self.assertRaisesRegex(ValueError, "too large"):
            private_io.publish_private_create_only_json(
                self.root,
                self.target,
                {"value": "x" * 5000},
                max_bytes=100,
                label="test receipt",
            )

        with mock.patch.object(private_io.os, "link", side_effect=OSError("link failed")):
            with self.assertRaisesRegex(OSError, "link failed"):
                self.publish({"value": 3})
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.glob(".receipt.json.*.tmp")), [])

    def test_temporary_unlink_failure_rolls_back_visible_target(self) -> None:
        real_unlink = private_io.os.unlink
        failures = 0

        def fail_temporary_unlink(path, *, dir_fd=None):
            nonlocal failures
            if str(path).startswith(".receipt.json.") and failures < 1:
                failures += 1
                raise OSError("unlink failed")
            return real_unlink(path, dir_fd=dir_fd)

        with mock.patch.object(private_io.os, "unlink", side_effect=fail_temporary_unlink):
            with self.assertRaisesRegex(OSError, "unlink failed"):
                self.publish({"value": 4})
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.glob(".receipt.json.*.tmp")), [])

    def test_directory_identity_drift_fails_before_publication(self) -> None:
        real_fstat = private_io.os.fstat
        calls = 0

        def drifted_fstat(descriptor: int):
            nonlocal calls
            result = real_fstat(descriptor)
            calls += 1
            if calls == 1:
                values = list(result)
                values[1] += 1
                return os.stat_result(values)
            return result

        with mock.patch.object(private_io.os, "fstat", side_effect=drifted_fstat):
            with self.assertRaisesRegex(RuntimeError, "directory identity is unsafe"):
                self.publish({"value": 4})
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()

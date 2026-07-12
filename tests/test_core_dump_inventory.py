from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import core_dump_inventory as inventory_module  # noqa: E402


class CoreDumpInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "root"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_inventory_hashes_regular_files_and_does_not_mutate(self) -> None:
        core = self.root / "core.1"
        core.write_bytes(b"core-data")
        ordinary = self.root / "notes.txt"
        ordinary.write_text("keep", encoding="utf-8")
        before = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) for path in self.root.iterdir()}

        result = inventory_module.inventory([self.root], max_depth=0, hash_max_bytes=1024)

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["files"][0]["path"], str(core))
        self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(b"core-data").hexdigest())
        self.assertEqual(result["error_count"], 0)
        self.assertFalse(result["errors_truncated"])
        after = {path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) for path in self.root.iterdir()}
        self.assertEqual(after, before)

    def test_max_depth_and_symlink_entries(self) -> None:
        (self.root / "core.root").write_bytes(b"root")
        level_one = self.root / "one"
        level_one.mkdir()
        (level_one / "core.one").write_bytes(b"one")
        level_two = level_one / "two"
        level_two.mkdir()
        (level_two / "core.two").write_bytes(b"two")
        (self.root / "core.link").symlink_to(self.root / "core.root")
        linked_directory = self.root / "linked"
        linked_directory.symlink_to(level_one, target_is_directory=True)

        depth_zero = inventory_module.inventory([self.root], max_depth=0, hash_max_bytes=1024)
        depth_one = inventory_module.inventory([self.root], max_depth=1, hash_max_bytes=1024)

        self.assertEqual([Path(item["path"]).name for item in depth_zero["files"]], ["core.root"])
        self.assertEqual(
            [Path(item["path"]).name for item in depth_one["files"]],
            ["core.root", "core.one"],
        )
        self.assertNotIn("core.link", [Path(item["path"]).name for item in depth_one["files"]])

    def test_sparse_file_and_hash_limit(self) -> None:
        sparse = self.root / "core.sparse"
        with sparse.open("wb") as handle:
            handle.seek(1024 * 1024)
            handle.write(b"x")
        result = inventory_module.inventory(
            [self.root],
            max_depth=0,
            hash_max_bytes=1024,
        )
        record = result["files"][0]
        self.assertEqual(record["apparent_bytes"], 1024 * 1024 + 1)
        self.assertLessEqual(record["allocated_bytes"], record["apparent_bytes"])
        self.assertIsNone(record["sha256"])
        self.assertEqual(record["hash_omitted_reason"], "file_exceeds_hash_max_bytes")

    def test_rejects_symlink_root_and_invalid_limits(self) -> None:
        link = Path(self.temporary.name) / "root-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            inventory_module.inventory([link], max_depth=0, hash_max_bytes=1)
        with self.assertRaisesRegex(ValueError, "max-depth"):
            inventory_module.inventory([self.root], max_depth=21, hash_max_bytes=1)
        with self.assertRaisesRegex(ValueError, "hash-max"):
            inventory_module.inventory([self.root], max_depth=0, hash_max_bytes=-1)

    def test_errors_are_bounded_and_counted(self) -> None:
        for index in range(inventory_module.MAX_ERRORS + 5):
            (self.root / f"core.{index}").write_bytes(b"x")
        with mock.patch.object(
            inventory_module,
            "_hash_regular",
            side_effect=OSError("bounded failure"),
        ):
            result = inventory_module.inventory(
                [self.root],
                max_depth=0,
                hash_max_bytes=1024,
            )
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["error_count"], inventory_module.MAX_ERRORS + 5)
        self.assertEqual(len(result["errors"]), inventory_module.MAX_ERRORS)
        self.assertTrue(result["errors_truncated"])
        self.assertTrue(all(len(item["error"]) <= 240 for item in result["errors"]))

    def test_hash_detects_inode_rebinding(self) -> None:
        path = self.root / "core.race"
        path.write_bytes(b"first")
        expected = path.lstat()
        replacement = self.root / "replacement"
        replacement.write_bytes(b"second")
        os.replace(replacement, path)
        with self.assertRaisesRegex(OSError, "changed"):
            inventory_module._hash_regular(path, expected)


if __name__ == "__main__":
    unittest.main()

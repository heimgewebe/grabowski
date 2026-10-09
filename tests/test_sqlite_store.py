from __future__ import annotations

from pathlib import Path
import sqlite3
import os
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import grabowski_sqlite_store as sqlite_store


class InventoryChanged(RuntimeError):
    pass


class SQLiteStoreTests(unittest.TestCase):
    def test_copy_regular_file_preserves_bytes_and_private_mode(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.sqlite3"
            target = root / "snapshot.sqlite3"
            payload = b"sqlite-snapshot" * 4096
            source.write_bytes(payload)

            identity = sqlite_store.copy_regular_file(
                source,
                target,
                error_type=InventoryChanged,
            )

            self.assertEqual(payload, target.read_bytes())
            self.assertEqual(len(payload), identity[2])
            self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))

    def test_copy_regular_file_rejects_truncated_target(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.sqlite3"
            target = root / "snapshot.sqlite3"
            source.write_bytes(b"sqlite-snapshot" * 4096)
            original_chmod = sqlite_store.os.chmod

            def truncate_after_copy(path: str | bytes | Path, mode: int) -> None:
                original_chmod(path, mode)
                Path(path).write_bytes(b"")

            with patch.object(
                sqlite_store.os,
                "chmod",
                side_effect=truncate_after_copy,
            ):
                with self.assertRaisesRegex(
                    InventoryChanged,
                    "Store changed while schema inventory was read",
                ):
                    sqlite_store.copy_regular_file(
                        source,
                        target,
                        error_type=InventoryChanged,
                    )

    def test_strict_observer_rejects_live_wal_without_any_copy(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            database = root / "active.sqlite3"
            keeper = sqlite3.connect(database)
            try:
                self.assertEqual("wal", keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0])
                keeper.execute("PRAGMA wal_autocheckpoint=0")
                keeper.execute("CREATE TABLE sample(value INTEGER)")
                keeper.execute("INSERT INTO sample VALUES (42)")
                keeper.commit()
                self.assertTrue(Path(str(database) + "-wal").is_file())
                before = {item.name: item.read_bytes() for item in root.iterdir()}
                with patch.object(
                    sqlite_store.tempfile, "TemporaryDirectory",
                    side_effect=AssertionError("tempfile creation is a write"),
                ) as temp_copy:
                    with self.assertRaisesRegex(InventoryChanged, "Strict read-only"):
                        with sqlite_store.inventory_readonly_sqlite(
                            database,
                            temporary_prefix="must-not-copy-",
                            error_type=InventoryChanged,
                            allow_wal_copy=False,
                        ):
                            self.fail("WAL reader must not be opened")
                temp_copy.assert_not_called()
                self.assertEqual(
                    before, {item.name: item.read_bytes() for item in root.iterdir()}
                )
            finally:
                keeper.close()

    def test_strict_observer_reads_quiescent_database_on_readonly_media(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            database = root / "quiescent.sqlite3"
            with sqlite3.connect(database) as writer:
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.execute("INSERT INTO sample VALUES (42)")
            before = sorted(item.name for item in root.iterdir())
            os.chmod(database, 0o400)
            os.chmod(root, 0o500)
            try:
                with sqlite_store.inventory_readonly_sqlite(
                    database,
                    temporary_prefix="must-not-copy-",
                    error_type=InventoryChanged,
                    allow_wal_copy=False,
                ) as reader:
                    self.assertEqual(42, reader.execute("SELECT value FROM sample").fetchone()[0])
                self.assertEqual(before, sorted(item.name for item in root.iterdir()))
            finally:
                os.chmod(root, 0o700)


if __name__ == "__main__":
    unittest.main()

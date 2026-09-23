from __future__ import annotations

from pathlib import Path
import os
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_sqlite_store as sqlite_store  # noqa: E402


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

    def test_connect_pinned_sqlite_binds_connection_across_aba_replacement(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            database = root / "state.sqlite3"
            replacement = root / "replacement.sqlite3"
            parked_original = root / "parked-original.sqlite3"
            parked_replacement = root / "parked-replacement.sqlite3"
            for path, marker in ((database, "original"), (replacement, "replacement")):
                with sqlite3.connect(path) as connection:
                    connection.execute("CREATE TABLE marker(value TEXT NOT NULL)")
                    connection.execute("INSERT INTO marker(value) VALUES(?)", (marker,))
            expected = database.stat()
            real_connect = sqlite_store.sqlite3.connect

            def aba_connect(*args, **kwargs):
                os.replace(database, parked_original)
                os.replace(replacement, database)
                connection = real_connect(*args, **kwargs)
                os.replace(database, parked_replacement)
                os.replace(parked_original, database)
                return connection

            with patch.object(sqlite_store.sqlite3, "connect", side_effect=aba_connect):
                connection, identity = sqlite_store.connect_pinned_sqlite(
                    database,
                    mode="rw",
                    timeout=1,
                    label="Test database",
                )
            try:
                self.assertEqual(
                    "original",
                    connection.execute("SELECT value FROM marker").fetchone()[0],
                )
                self.assertEqual((expected.st_dev, expected.st_ino), identity)
            finally:
                connection.close()

    def test_connect_pinned_sqlite_preserves_wal_sidecar_visibility(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "wal.sqlite3"
            writer = sqlite3.connect(database)
            try:
                self.assertEqual(
                    "wal",
                    writer.execute("PRAGMA journal_mode=WAL").fetchone()[0],
                )
                writer.execute("CREATE TABLE marker(value INTEGER NOT NULL)")
                writer.commit()
                writer.execute("INSERT INTO marker(value) VALUES(42)")
                writer.commit()
                wal_path = Path(str(database) + "-wal")
                self.assertTrue(wal_path.is_file())
                self.assertGreater(wal_path.stat().st_size, 0)

                connection, _identity = sqlite_store.connect_pinned_sqlite(
                    database,
                    mode="rw",
                    timeout=1,
                    label="Test database",
                )
                try:
                    self.assertEqual(
                        str(database),
                        connection.execute("PRAGMA database_list").fetchone()[2],
                    )
                    self.assertEqual(
                        42,
                        connection.execute("SELECT value FROM marker").fetchone()[0],
                    )
                    self.assertEqual(
                        "wal",
                        connection.execute("PRAGMA journal_mode").fetchone()[0],
                    )
                finally:
                    connection.close()
            finally:
                writer.close()

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


if __name__ == "__main__":
    unittest.main()

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

    def test_copy_regular_file_stops_streaming_at_byte_budget(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.sqlite3"
            payload = b"w" * 12288
            source.write_bytes(payload)
            with patch.object(sqlite_store, "COPY_CHUNK_BYTES", 4096):
                with self.assertRaises(InventoryChanged):
                    sqlite_store.copy_regular_file(
                        source,
                        root / "over.sqlite3",
                        error_type=InventoryChanged,
                        max_bytes=8192,
                    )
                # Nothing past the budget reaches the private copy.
                self.assertEqual(8192, (root / "over.sqlite3").stat().st_size)
                identity = sqlite_store.copy_regular_file(
                    source,
                    root / "exact.sqlite3",
                    error_type=InventoryChanged,
                    max_bytes=len(payload),
                )
            self.assertEqual(len(payload), identity[2])
            self.assertEqual(payload, (root / "exact.sqlite3").read_bytes())

    def test_inventory_wal_copy_enforces_combined_byte_budget(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "store.sqlite3"
            writer = sqlite3.connect(database)
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("CREATE TABLE items(value TEXT)")
            writer.execute("INSERT INTO items VALUES ('wal-only')")
            writer.commit()
            try:
                wal = Path(f"{database}-wal")
                total = database.stat().st_size + wal.stat().st_size
                with self.assertRaises(InventoryChanged):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="budget-test-",
                        error_type=InventoryChanged,
                        max_copy_bytes=total - 1,
                    ):
                        pass
                with sqlite_store.inventory_readonly_sqlite(
                    database,
                    temporary_prefix="budget-test-",
                    error_type=InventoryChanged,
                    max_copy_bytes=total,
                ) as connection:
                    self.assertEqual(
                        [("wal-only",)],
                        [tuple(row) for row in connection.execute("SELECT value FROM items")],
                    )
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

    def test_wal_mode_quiescent_strict_reader_uses_immutable_uri_without_sidecars(self) -> None:
        from contextlib import closing

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            database = root / "wal-mode.sqlite3"
            with closing(sqlite3.connect(database)) as writer, writer:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.execute("INSERT INTO sample VALUES (42)")
            before = sorted(item.name for item in root.iterdir())
            self.assertEqual([database.name], before)
            original_connect = sqlite3.connect
            called_uris: list[str] = []

            def capture(*args, **kwargs):
                called_uris.append(str(args[0]))
                return original_connect(*args, **kwargs)

            with patch.object(sqlite_store.sqlite3, "connect", side_effect=capture):
                with sqlite_store.inventory_readonly_sqlite(
                    database,
                    temporary_prefix="must-not-copy-",
                    error_type=InventoryChanged,
                    allow_wal_copy=False,
                ) as connection:
                    self.assertEqual(
                        42, connection.execute("SELECT value FROM sample").fetchone()[0]
                    )
                    self.assertEqual(before, sorted(item.name for item in root.iterdir()))
            self.assertEqual(1, len(called_uris))
            self.assertTrue(called_uris[0].endswith("?mode=ro&immutable=1"))
            self.assertEqual(before, sorted(item.name for item in root.iterdir()))

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


    def test_strict_observer_reads_checkpointed_empty_wal_with_existing_shm(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "checkpointed.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE sample(value TEXT)")
                writer.execute("INSERT INTO sample VALUES ('checkpointed')")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                wal = Path(str(database) + "-wal")
                shm = Path(str(database) + "-shm")
                self.assertTrue(shm.is_file())
                self.assertTrue(wal.is_file())
                self.assertEqual(0, wal.stat().st_size)
                before = {item.name: item.read_bytes() for item in root.iterdir()}
                with patch.object(
                    sqlite_store.tempfile,
                    "TemporaryDirectory",
                    side_effect=AssertionError("zero-frame WAL must not be copied"),
                ) as temporary:
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="not-allowed-to-copy-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_checkpointed_empty_wal=True,
                    ) as reader:
                        self.assertEqual(
                            "checkpointed",
                            reader.execute("SELECT value FROM sample").fetchone()[0],
                        )
                temporary.assert_not_called()
                self.assertEqual(
                    before, {item.name: item.read_bytes() for item in root.iterdir()},
                )
            finally:
                writer.close()

    def test_strict_observer_rejects_empty_wal_modified_during_observation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "changed.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                wal = Path(str(database) + "-wal")
                self.assertEqual(0, wal.stat().st_size)
                with self.assertRaises(InventoryChanged):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="not-allowed-to-copy-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_checkpointed_empty_wal=True,
                    ) as reader:
                        reader.execute("SELECT count(*) FROM sample").fetchone()
                        wal.write_bytes(b"unsafe-new-wal-content")
            finally:
                writer.close()

    def test_strict_observer_rejects_new_wal_commit_during_immutable_read(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "racing.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                self.assertEqual(0, Path(str(database) + "-wal").stat().st_size)
                with self.assertRaises(InventoryChanged):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="not-allowed-to-copy-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_checkpointed_empty_wal=True,
                    ) as reader:
                        self.assertEqual(
                            0, reader.execute("SELECT count(*) FROM sample").fetchone()[0],
                        )
                        writer.execute("INSERT INTO sample VALUES (1)")
                        writer.commit()
            finally:
                writer.close()

    def test_strict_observer_rejects_symlinked_empty_wal(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "linked.sqlite3"
            with sqlite3.connect(database) as writer:
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.commit()
            target = Path(directory) / "empty-wal"
            target.write_bytes(b"")
            Path(str(database) + "-wal").symlink_to(target)
            with self.assertRaises(InventoryChanged):
                with sqlite_store.inventory_readonly_sqlite(
                    database,
                    temporary_prefix="not-allowed-to-copy-",
                    error_type=InventoryChanged,
                    allow_wal_copy=False,
                    allow_checkpointed_empty_wal=True,
                ):
                    self.fail("symlinked sidecars must never be trusted")


    def test_strict_observer_rejects_orphaned_shm_without_wal(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "orphaned.sqlite3"
            with sqlite3.connect(database) as writer:
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.commit()
            orphaned = Path(str(database) + "-shm")
            orphaned.write_bytes(b"former-shm-without-wal")
            before = orphaned.read_bytes()
            with self.assertRaisesRegex(InventoryChanged, "Strict read-only"):
                with sqlite_store.inventory_readonly_sqlite(
                    database,
                    temporary_prefix="not-allowed-to-copy-",
                    error_type=InventoryChanged,
                    allow_wal_copy=False,
                    allow_checkpointed_empty_wal=True,
                ):
                    self.fail("orphaned SHM does not prove successful WAL checkpoint")
            self.assertEqual(before, orphaned.read_bytes())

    def test_strict_observer_default_denies_zero_length_wal_and_shm(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "denied.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE sample(value INTEGER)")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                self.assertEqual(0, Path(str(database) + "-wal").stat().st_size)
                with self.assertRaisesRegex(InventoryChanged, "Strict read-only snapshot unavailable"):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="no-implicit-wal0-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                    ):
                        self.fail("Zero-length WAL alone cannot grant global strict-read permission")
            finally:
                writer.close()

if __name__ == "__main__":
    unittest.main()

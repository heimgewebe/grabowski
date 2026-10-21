from __future__ import annotations

from pathlib import Path
from io import StringIO
from types import SimpleNamespace
import sqlite3
import os
import subprocess
import sys
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

    def test_copy_regular_file_copies_verified_bounded_prefix_only(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source.wal", root / "private-prefix.wal"
            original = b"A" * 8192 + b"stale-inactive-physical-tail" * 1024
            source.write_bytes(original)
            identity = sqlite_store.copy_regular_file(
                source, target, error_type=InventoryChanged,
                max_bytes=8192, copy_bytes=8192,
            )
            self.assertEqual(len(original), identity[2])
            self.assertEqual(original, source.read_bytes())
            self.assertEqual(original[:8192], target.read_bytes())
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


    def test_private_wal_opt_in_does_not_admit_checkpointed_zero_wal_with_shm(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "zero-wal.sqlite3"
            keeper = sqlite3.connect(database)
            try:
                keeper.execute("PRAGMA journal_mode=WAL")
                keeper.execute("CREATE TABLE content(value TEXT)")
                keeper.execute("INSERT INTO content VALUES ('base')")
                keeper.commit()
                keeper.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                wal = Path(str(database) + "-wal")
                shm = Path(str(database) + "-shm")
                self.assertEqual(0, wal.stat().st_size)
                self.assertTrue(shm.is_file())
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        side_effect=AssertionError("WAL0 must not enter private WAL replay"),
                    ) as ram_check,
                    self.assertRaisesRegex(InventoryChanged, "Strict read-only snapshot unavailable"),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="private-wal0-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as connection:
                        self.fail("A private WAL opt-in cannot admit checkpointed WAL0")
                ram_check.assert_not_called()
                self.assertEqual(
                    before, {p.name: p.read_bytes() for p in root.iterdir()}
                )
            finally:
                keeper.close()

    def test_private_wal_opt_in_does_not_admit_orphaned_shm(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "orphan-shm.sqlite3"
            with sqlite3.connect(database) as writer:
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (1)")
            shm = Path(str(database) + "-shm")
            shm.write_bytes(b"orphaned-shm")
            self.assertFalse(Path(str(database) + "-wal").exists())
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            with (
                patch.object(
                    sqlite_store, "_strict_wal_memory_root",
                    side_effect=AssertionError("Orphaned SHM must fail before any replay"),
                ) as ram_check,
                self.assertRaisesRegex(InventoryChanged, "Strict read-only snapshot unavailable"),
            ):
                with sqlite_store.inventory_readonly_sqlite(
                    database,
                    temporary_prefix="private-orphan-",
                    error_type=InventoryChanged,
                    allow_wal_copy=False,
                    allow_private_wal_snapshot=True,
                ):
                    self.fail("Orphaned SHM must not be ignored")
            ram_check.assert_not_called()
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_strict_ram_root_rejects_non_tmpfs_overmount(self) -> None:
        # An older tmpfs entry cannot bless a newer disk-backed /dev/shm mount.
        actual_open = sqlite_store.Path.open
        mounts = (
            "32 20 0:44 / /dev/shm rw - tmpfs tmpfs rw\n"
            "33 20 8:1 / /dev/shm rw - ext4 /dev/sda rw\n"
        )

        def fake_open(path, *args, **kwargs):
            if str(path) == "/proc/self/mountinfo":
                return StringIO(mounts)
            return actual_open(path, *args, **kwargs)

        with (
            patch.object(sqlite_store.Path, "open", fake_open),
            self.assertRaises(InventoryChanged),
        ):
            sqlite_store._strict_wal_memory_root(
                error_type=InventoryChanged,
                message="untrusted mount",
            )

    def test_strict_ram_root_rejects_zram_disk_writeback(self) -> None:
        actual_open = sqlite_store.Path.open
        actual_stat = sqlite_store.os.stat
        mounts = "32 20 0:44 / /dev/shm rw - tmpfs tmpfs rw\n"
        swaps = "Filename Type Size Used Priority\n/dev/zram0 partition 16384 0 100\n"

        def fake_open(path, *args, **kwargs):
            if str(path) == "/proc/self/mountinfo":
                return StringIO(mounts)
            if str(path) == "/proc/swaps":
                return StringIO(swaps)
            return actual_open(path, *args, **kwargs)

        def fake_stat(path, *args, **kwargs):
            if str(path) == "/dev/zram0":
                return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600)
            return actual_stat(path, *args, **kwargs)

        with (
            patch.object(sqlite_store.Path, "open", fake_open),
            patch.object(sqlite_store.os, "stat", fake_stat),
            patch.object(
                sqlite_store.Path, "read_text", return_value="/dev/sda\n",
            ) as backing,
            self.assertRaises(InventoryChanged),
        ):
            sqlite_store._strict_wal_memory_root(
                error_type=InventoryChanged,
                message="zram writeback must reject",
            )
        backing.assert_called_once()

    def test_strict_private_wal_snapshot_sees_uncheckpointed_commits_without_source_writes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "wal-only.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE wal_only(value TEXT)")
                writer.execute("INSERT INTO wal_only VALUES ('committed')")
                writer.commit()
                before = {
                    p.name: (p.read_bytes(), sqlite_store.status_identity(os.lstat(p)))
                    for p in root.iterdir()
                }
                self.assertIn("wal-only.sqlite3-shm", before)
                # The CI runner may not expose the trusted production tmpfs
                # layout. Verify the replay algorithm in this private fixture;
                # host admission remains covered by separate fail-closed tests.
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root", return_value=root,
                    ),
                    sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader,
                ):
                    self.assertEqual(
                        "committed",
                        reader.execute("SELECT value FROM wal_only").fetchone()[0],
                    )
                self.assertEqual(
                    before,
                    {
                        p.name: (p.read_bytes(), sqlite_store.status_identity(os.lstat(p)))
                        for p in root.iterdir()
                    },
                )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_accepts_restarted_wal_with_stale_tail(self) -> None:
        # SQLite may checkpoint and reuse the WAL without truncating it.
        # Physical trailing frames then have obsolete salts, but mxFrame in
        # the unchanged wal-index identifies the current committed prefix.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "restarted.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE inventory(value TEXT)")
                writer.executemany(
                    "INSERT INTO inventory VALUES (?)",
                    [("payload-" + "x" * 4000,) for _ in range(1400)],
                )
                writer.commit()
                wal = Path(str(database) + "-wal")
                size_before = wal.stat().st_size
                self.assertGreater(size_before, 32 + 1000 * (4096 + 24))
                writer.execute("INSERT INTO inventory VALUES ('restarted-commit')")
                writer.commit()
                self.assertEqual(size_before, wal.stat().st_size)
                self.assertEqual(
                    1401,
                    writer.execute("SELECT count(*) FROM inventory").fetchone()[0],
                )
                with patch.object(
                    sqlite_store, "_strict_wal_memory_root", return_value=root,
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="restarted-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        self.assertEqual(
                            1401,
                            reader.execute("SELECT count(*) FROM inventory").fetchone()[0],
                        )
                        self.assertEqual(
                            "restarted-commit",
                            reader.execute(
                                "SELECT value FROM inventory ORDER BY rowid DESC LIMIT 1"
                            ).fetchone()[0],
                        )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_accepts_large_inactive_wal_tail(self) -> None:
        # The 32-MiB limit must apply to *active committed bytes*, not to
        # stale physical frames left behind after checkpoint/restart.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "large-tail.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE inventory(value TEXT)")
                writer.executemany(
                    "INSERT INTO inventory VALUES (?)",
                    [("physical-tail-" + "z" * 4000,) for _ in range(9000)],
                )
                writer.commit()
                wal = Path(str(database) + "-wal")
                large_size = wal.stat().st_size
                self.assertGreater(
                    large_size, sqlite_store.STRICT_PRIVATE_WAL_MAX_WAL_BYTES,
                )
                writer.execute("INSERT INTO inventory VALUES ('latest') ")
                writer.commit()
                self.assertEqual(large_size, wal.stat().st_size)
                with patch.object(
                    sqlite_store, "_strict_wal_memory_root", return_value=root,
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="large-physical-tail-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        self.assertEqual(
                            9001,
                            reader.execute("SELECT count(*) FROM inventory").fetchone()[0],
                        )
                        self.assertEqual(
                            "latest",
                            reader.execute(
                                "SELECT value FROM inventory ORDER BY rowid DESC LIMIT 1"
                            ).fetchone()[0],
                        )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_forged_wal_index_header(self) -> None:
        # A forged wal-index mxFrame is never permission to hide committed
        # frames. The two copies AND their unkeyed header checksums must match.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "index-fraud.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE inventory(value TEXT)")
                writer.execute("INSERT INTO inventory VALUES ('committed')")
                writer.commit()
                wal = Path(str(database) + "-wal")
                shm = Path(str(database) + "-shm")
                standalone = root / "standalone-wal-for-validator"
                standalone.write_bytes(wal.read_bytes())
                header = shm.read_bytes()[:96]
                self.assertEqual(96, len(header))
                self.assertEqual(header[:48], header[48:])
                for offsets in ((16,), (16, 64)):
                    bad = bytearray(header)
                    for offset in offsets:
                        bad[offset] ^= 1
                    with self.subTest(offsets=offsets), self.assertRaises(
                        InventoryChanged
                    ):
                        sqlite_store._strict_validate_copied_wal(
                            standalone,
                            error_type=InventoryChanged,
                            message="forged active frame count",
                            wal_index_header=bytes(bad),
                        )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_preserves_existing_sqlite_wal_write_lock(self) -> None:
        # POSIX process-scoped fcntl locks disappear when *any* descriptor
        # for the locked -shm inode is closed by the SQLite owning process.
        # Observe lock ownership from another process, never this process.
        probe = (
            "import sqlite3,sys\n"
            "db=sqlite3.connect(sys.argv[1],timeout=0,isolation_level=None)\n"
            "try:\n"
            " db.execute('BEGIN IMMEDIATE')\n"
            "except sqlite3.OperationalError:\n"
            " print('BLOCKED')\n"
            "else:\n"
            " print('ACQUIRED')\n"
            "finally:\n"
            " db.close()\n"
        )
        with TemporaryDirectory() as directory:
            database = Path(directory) / "live-lock.sqlite3"
            keeper = sqlite3.connect(database, timeout=0, isolation_level=None)
            try:
                keeper.execute("PRAGMA journal_mode=WAL")
                keeper.execute("PRAGMA wal_autocheckpoint=0")
                keeper.execute("CREATE TABLE inventory(value TEXT)")
                keeper.execute("INSERT INTO inventory VALUES ('committed')")
                keeper.execute("BEGIN IMMEDIATE")

                def probe_lock() -> str:
                    result = subprocess.run(
                        [sys.executable, "-I", "-c", probe, str(database)],
                        check=True, text=True, capture_output=True, timeout=5,
                    )
                    return result.stdout.strip()

                self.assertEqual("BLOCKED", probe_lock())
                with patch.object(
                    sqlite_store, "_strict_wal_memory_root",
                    return_value=Path(directory),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="lock-preservation-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        self.assertEqual(
                            "committed",
                            reader.execute("SELECT value FROM inventory").fetchone()[0],
                        )
                self.assertEqual(
                    "BLOCKED", probe_lock(),
                    "strict READ_ONLY dropped the live SQLite writer's fcntl lock",
                )
            finally:
                keeper.rollback()
                keeper.close()

    def test_strict_private_wal_snapshot_fails_closed_when_ram_root_unavailable(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "no-secure-ram.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE test(value INTEGER)")
                writer.execute("INSERT INTO test VALUES (1)")
                writer.commit()
                before = {
                    p.name: p.read_bytes()
                    for p in Path(directory).iterdir()
                }
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        side_effect=InventoryChanged("untrusted memory root"),
                    ),
                    patch.object(
                        sqlite_store.tempfile, "TemporaryDirectory",
                        side_effect=AssertionError("no insecure scratch creation"),
                    ) as temp,
                ):
                    with self.assertRaisesRegex(InventoryChanged, "untrusted memory root"):
                        with sqlite_store.inventory_readonly_sqlite(
                            database,
                            temporary_prefix="must-not-copy-",
                            error_type=InventoryChanged,
                            allow_wal_copy=False,
                            allow_private_wal_snapshot=True,
                        ):
                            self.fail("Untrusted scratch root must block")
                temp.assert_not_called()
                self.assertEqual(
                    before,
                    {p.name: p.read_bytes() for p in Path(directory).iterdir()},
                )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_concurrent_commit(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "race.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE wal_only(value INTEGER)")
                writer.execute("INSERT INTO wal_only VALUES (1)")
                writer.commit()
                entered = False
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        return_value=Path(directory),
                    ),
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        entered = True
                        self.assertEqual(1, reader.execute("SELECT count(*) FROM wal_only").fetchone()[0])
                        writer.execute("INSERT INTO wal_only VALUES (2)")
                        writer.commit()
                self.assertTrue(entered, "race test must reach the live reader")
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_shm_content_mutation(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "shm-race.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE wal_only(value INTEGER)")
                writer.commit()
                shm = Path(str(database) + "-shm")
                entered = False
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        return_value=Path(directory),
                    ),
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        entered = True
                        self.assertEqual(0, reader.execute("SELECT count(*) FROM wal_only").fetchone()[0])
                        with shm.open("r+b") as handle:
                            handle.seek(100)
                            before_byte = handle.read(1)
                            handle.seek(100)
                            handle.write(bytes([before_byte[0] ^ 1]))
                self.assertTrue(entered, "tamper test must reach the live reader")
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_budget_before_private_copy(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "budget.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE wal_only(value INTEGER)")
                writer.commit()
                # Even the minimum possible committed WAL frame cannot fit.
                # A large physical stale tail is not itself a memory budget.
                budget = database.stat().st_size + 31
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_file_fingerprint",
                        side_effect=AssertionError("oversize must reject before hashing"),
                    ) as hashing,
                    patch.object(
                        sqlite_store.tempfile,
                        "TemporaryDirectory",
                        side_effect=AssertionError("oversize must reject before scratch creation"),
                    ) as scratch,
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                        max_copy_bytes=budget,
                    ):
                        pass
                hashing.assert_not_called()
                scratch.assert_not_called()
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_symlink_sidecar(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "symlink.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE wal_only(value INTEGER)")
                writer.commit()
                shm = Path(str(database) + "-shm")
                shm.rename(Path(str(shm) + ".held"))
                shm.symlink_to(database)
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=Path(directory)),
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ):
                        pass
            finally:
                writer.close()


    def test_strict_private_wal_snapshot_rejects_corrupt_header_checksum(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "bad-header.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE rows(value INTEGER)")
                writer.execute("INSERT INTO rows VALUES (1)")
                writer.commit()
                wal = Path(str(database) + "-wal")
                with wal.open("r+b") as stream:
                    stream.seek(24)
                    value = stream.read(1)
                    stream.seek(24)
                    stream.write(bytes([value[0] ^ 1]))
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        return_value=Path(directory),
                    ),
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        reader.execute("SELECT count(*) FROM rows").fetchone()
                # Original validation now runs in an isolated child, not via
                # a patch of the parent function. Check a disposable WAL copy
                # directly to prove checksum rejection, without touching a
                # live SQLite sidecar fd in the assertion.
                corrupted = Path(directory) / "corrupt-standalone.wal"
                corrupted.write_bytes(wal.read_bytes())
                with self.assertRaises(InventoryChanged):
                    sqlite_store._strict_validate_copied_wal(
                        corrupted, error_type=InventoryChanged,
                        message="invalid WAL checksum",
                    )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_corrupt_committed_frame(self) -> None:
        with TemporaryDirectory() as directory:
            database = Path(directory) / "bad-frame.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE rows(value INTEGER)")
                writer.execute("INSERT INTO rows VALUES (1)")
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                writer.execute("INSERT INTO rows VALUES (2)")
                writer.commit()
                wal = Path(str(database) + "-wal")
                with wal.open("r+b") as stream:
                    stream.seek(-1, os.SEEK_END)
                    value = stream.read(1)
                    stream.seek(-1, os.SEEK_END)
                    stream.write(bytes([value[0] ^ 1]))
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        return_value=Path(directory),
                    ),
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database,
                        temporary_prefix="strict-private-wal-test-",
                        error_type=InventoryChanged,
                        allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        reader.execute("SELECT count(*) FROM rows").fetchone()
                # Original validation now runs in an isolated child, not via
                # a patch of the parent function. Check a disposable WAL copy
                # directly to prove checksum rejection, without touching a
                # live SQLite sidecar fd in the assertion.
                corrupted = Path(directory) / "corrupt-standalone.wal"
                corrupted.write_bytes(wal.read_bytes())
                with self.assertRaises(InventoryChanged):
                    sqlite_store._strict_validate_copied_wal(
                        corrupted, error_type=InventoryChanged,
                        message="invalid WAL checksum",
                    )
            finally:
                writer.close()

if __name__ == "__main__":
    unittest.main()

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


def _original_sqlite_bytes_in_child(path: Path) -> bytes:
    """Keep raw SQLite/WAL/SHM descriptors out of the SQLite-owning process.

    Closing any descriptor on a SQLite file in the keeper process can release
    that process's POSIX locks, invalidating otherwise-positive race tests.
    """
    result = subprocess.run(
        [
            sys.executable, "-I", "-c",
            "import sys; from pathlib import Path; "
            "sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())",
            str(path),
        ],
        capture_output=True, check=True, timeout=10,
    )
    return result.stdout


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
                before = {item.name: _original_sqlite_bytes_in_child(item) for item in root.iterdir()}
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
                    before, {item.name: _original_sqlite_bytes_in_child(item) for item in root.iterdir()}
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
                before = {item.name: _original_sqlite_bytes_in_child(item) for item in root.iterdir()}
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
                    before, {item.name: _original_sqlite_bytes_in_child(item) for item in root.iterdir()},
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
                before = {p.name: _original_sqlite_bytes_in_child(p) for p in root.iterdir()}
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
                    before, {p.name: _original_sqlite_bytes_in_child(p) for p in root.iterdir()}
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
            before = {p.name: _original_sqlite_bytes_in_child(p) for p in root.iterdir()}
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
            self.assertEqual(before, {p.name: _original_sqlite_bytes_in_child(p) for p in root.iterdir()})

    def test_strict_ram_root_rejects_non_tmpfs_overmount(self) -> None:
        # An older tmpfs entry cannot bless a newer disk-backed /dev/shm mount.
        actual_open = sqlite_store.Path.open
        actual_lstat = sqlite_store.os.lstat
        actual_resolve = sqlite_store.Path.resolve
        mounts = (
            "32 20 0:44 / /dev/shm rw - tmpfs tmpfs rw\n"
            "33 20 8:1 / /dev/shm rw - ext4 /dev/sda rw\n"
        )
        mount_reads = [0]

        def fake_lstat(path, *args, **kwargs):
            if str(path) == "/dev/shm":
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
            return actual_lstat(path, *args, **kwargs)

        def fake_resolve(path, *args, **kwargs):
            if str(path) == "/dev/shm":
                return Path("/dev/shm")
            return actual_resolve(path, *args, **kwargs)

        def fake_open(path, *args, **kwargs):
            if str(path) == "/proc/self/mountinfo":
                mount_reads[0] += 1
                return StringIO(mounts)
            return actual_open(path, *args, **kwargs)

        with (
            patch.object(sqlite_store.Path, "open", fake_open),
            patch.object(sqlite_store.os, "lstat", fake_lstat),
            patch.object(sqlite_store.Path, "resolve", fake_resolve),
            self.assertRaises(InventoryChanged),
        ):
            sqlite_store._strict_wal_memory_root(
                error_type=InventoryChanged,
                message="untrusted mount",
            )
        self.assertEqual(1, mount_reads[0], "test must reach mount validation")

    def test_strict_ram_root_rejects_zram_disk_writeback(self) -> None:
        actual_open = sqlite_store.Path.open
        actual_stat = sqlite_store.os.stat
        actual_lstat = sqlite_store.os.lstat
        actual_resolve = sqlite_store.Path.resolve
        mounts = "32 20 0:44 / /dev/shm rw - tmpfs tmpfs rw\n"

        def fake_lstat(path, *args, **kwargs):
            if str(path) == "/dev/shm":
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
            return actual_lstat(path, *args, **kwargs)

        def fake_resolve(path, *args, **kwargs):
            if str(path) == "/dev/shm":
                return Path("/dev/shm")
            return actual_resolve(path, *args, **kwargs)
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
            patch.object(sqlite_store.os, "lstat", fake_lstat),
            patch.object(sqlite_store.Path, "resolve", fake_resolve),
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
                    p.name: (_original_sqlite_bytes_in_child(p), sqlite_store.status_identity(os.lstat(p)))
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
                        p.name: (_original_sqlite_bytes_in_child(p), sqlite_store.status_identity(os.lstat(p)))
                        for p in root.iterdir()
                    },
                )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_rejects_unreapable_long_database_name(self) -> None:
        # A SQLite file name may be valid for -wal but longer than the
        # orphan-recovery marker bound. Reject it before copying cleartext.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / (("d" * 241) + ".db")
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (44)")
                writer.commit()
                self.assertTrue(Path(str(database) + "-wal").is_file())
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    self.assertRaisesRegex(InventoryChanged, "Store changed"),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="too-long-name-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ):
                        self.fail("unreappable copied database name must fail closed")
                self.assertEqual(
                    [], list(root.glob("grabowski-strict-wal-*")),
                    "failed admission must never retain plaintext",
                )
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_sigkill_recovers_only_owned_orphan(self) -> None:
        # The copied plaintext must not live forever when SIGKILL prevents
        # TemporaryDirectory.__exit__. A later genuine reader reclaims only
        # marker-attested copies under the existing exclusive owner flock.
        import select
        import signal

        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "kill-orphan.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (7)")
                writer.commit()
                program = (
                    "import sys,time\n"
                    "from pathlib import Path\n"
                    "from unittest.mock import patch\n"
                    "sys.path.insert(0,sys.argv[1])\n"
                    "import grabowski_sqlite_store as store\n"
                    "db,scratch=Path(sys.argv[2]),Path(sys.argv[3])\n"
                    "with patch.object(store,'_strict_wal_memory_root',return_value=scratch):\n"
                    " with store.inventory_readonly_sqlite(db,temporary_prefix='sigkill-',"
                    "error_type=RuntimeError,allow_wal_copy=False,"
                    "allow_private_wal_snapshot=True) as conn:\n"
                    "  assert conn.execute('SELECT value FROM content').fetchone()[0]==7\n"
                    "  print('READY',flush=True)\n"
                    "  time.sleep(30)\n"
                )
                child = subprocess.Popen(
                    [
                        sys.executable, "-I", "-B", "-c", program,
                        str(Path(sqlite_store.__file__).resolve().parent),
                        str(database), str(root),
                    ],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    ready, _, _ = select.select([child.stdout], [], [], 12)
                    self.assertTrue(ready, "child did not enter strict snapshot")
                    self.assertEqual("READY", child.stdout.readline().strip())
                    os.kill(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                    if child.stdout is not None:
                        child.stdout.close()
                    if child.stderr is not None:
                        child.stderr.close()

                old_copies = list(root.glob("grabowski-strict-wal-*"))
                self.assertEqual(1, len(old_copies))
                orphan = old_copies[0]
                self.assertTrue(orphan.is_dir())
                # A similarly named unrelated directory is not deletion
                # authority, even when user-owned and mode 0700.
                unrelated = root / "grabowski-strict-wal-unrelated"
                unrelated.mkdir(mode=0o700)
                (unrelated / "valuable").write_bytes(b"must remain")
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="sigkill-retry-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as connection,
                ):
                    self.assertEqual(
                        7, connection.execute("SELECT value FROM content").fetchone()[0],
                    )
                    self.assertFalse(orphan.exists(), "SIGKILL snapshot was not reaped")
                    self.assertTrue((unrelated / "valuable").is_file())
                self.assertTrue((unrelated / "valuable").is_file())
            finally:
                writer.close()

    def test_strict_wal_copy_worker_inherits_owner_flock_until_exit(self) -> None:
        # If the parent dies while an exec-ed source worker still copies,
        # inherited flock ownership prevents another reader deleting its files.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "copy-owner.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (27)")
                writer.commit()
                original_run = subprocess.run
                inherited = []

                def capture_run(argv, **kwargs):
                    if "--strict-wal-source-worker" in argv:
                        fds = kwargs.get("pass_fds", ())
                        self.assertEqual(1, len(fds))
                        self.assertTrue(stat.S_ISDIR(os.fstat(fds[0]).st_mode))
                        inherited.append(tuple(fds))
                    return original_run(argv, **kwargs)

                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    patch.object(sqlite_store.subprocess, "run", side_effect=capture_run),
                    sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="copy-owner-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader,
                ):
                    self.assertEqual(
                        27, reader.execute("SELECT value FROM content").fetchone()[0],
                    )
                self.assertGreaterEqual(len(inherited), 2)
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_nested_reader_does_not_reap_live_outer(self) -> None:
        # A nested reader shares the owner flock and MUST preserve the live
        # outer snapshot instead of treating its marker as an orphan.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "nested.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (17)")
                writer.commit()
                with patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root):
                    with sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="outer-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as outer:
                        outer_dir = next(root.glob("grabowski-strict-wal-*"))
                        with sqlite_store.inventory_readonly_sqlite(
                            database, temporary_prefix="inner-",
                            error_type=InventoryChanged, allow_wal_copy=False,
                            allow_private_wal_snapshot=True,
                        ) as inner:
                            self.assertEqual(17, inner.execute(
                                "SELECT value FROM content"
                            ).fetchone()[0])
                            self.assertTrue(outer_dir.is_dir())
                            self.assertEqual(2, len(list(root.glob("grabowski-strict-wal-*"))))
                        self.assertEqual(
                            17, outer.execute("SELECT value FROM content").fetchone()[0],
                        )
                        self.assertTrue(outer_dir.is_dir())
                self.assertEqual([], list(root.glob("grabowski-strict-wal-*")))
            finally:
                writer.close()

    def test_strict_private_wal_reaper_tolerates_foreign_prefix_disappearing_before_stat(self) -> None:
        # The shared tmpfs is not owned by the inventory reader. A foreign
        # prefix entry may disappear after scandir and before stat. That
        # optional cleanup race cannot deny a valid committed WAL read.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            decoy = root / "grabowski-strict-wal-foreign-vanishing"
            decoy.write_bytes(b"not a snapshot")
            database = root / "stat-race.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE witness(value INTEGER)")
                writer.execute("INSERT INTO witness VALUES (83)")
                writer.commit()
                original_stat = sqlite_store.os.stat
                witnessed = []

                def disappeared(name, *args, **kwargs):
                    if name == decoy.name and kwargs.get("dir_fd") is not None:
                        witnessed.append(name)
                        raise FileNotFoundError(2, "foreign prefix entry disappeared", name)
                    return original_stat(name, *args, **kwargs)

                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    patch.object(sqlite_store.os, "stat", side_effect=disappeared),
                    sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="untrusted-stat-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader,
                ):
                    self.assertEqual(
                        83, reader.execute("SELECT value FROM witness").fetchone()[0],
                    )
                self.assertEqual([decoy.name], witnessed)
                self.assertEqual(b"not a snapshot", decoy.read_bytes())
            finally:
                writer.close()

    def test_strict_private_wal_orphan_reaper_ignores_foreign_prefix_flood(self) -> None:
        # A shared /dev/shm allows arbitrary other-user prefix entries.
        # Neither those names nor unmarked own directories are reaping
        # authority or a reason to deny a valid strict READ_ONLY request.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            decoys = []
            for index in range(70):
                prefix = f"grabowski-strict-wal-decoy-{index:03d}"
                file_decoy = root / (prefix + "-file")
                file_decoy.write_bytes(b"unrelated")
                directory_decoy = root / (prefix + "-public")
                directory_decoy.mkdir()
                directory_decoy.chmod(0o755)
                unmarked = root / (prefix + "-unmarked")
                unmarked.mkdir(mode=0o700)
                decoys.extend((file_decoy, directory_decoy, unmarked))
            orphan = root / "grabowski-strict-wal-valid-orphan"
            orphan.mkdir(mode=0o700)
            sqlite_store._strict_wal_mark_private_snapshot(orphan, "old.sqlite3")
            old_bytes = orphan / "old.sqlite3"
            old_bytes.write_bytes(b"orphaned private bytes")
            old_bytes.chmod(0o600)

            database = root / "prefix-flood.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE witness(value INTEGER)")
                writer.execute("INSERT INTO witness VALUES (59)")
                writer.commit()
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="prefix-flood-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader,
                ):
                    self.assertEqual(
                        59, reader.execute("SELECT value FROM witness").fetchone()[0],
                    )
                self.assertFalse(orphan.exists(), "verified orphan was starved by decoys")
                self.assertTrue(all(item.exists() for item in decoys))
                self.assertEqual(b"unrelated", decoys[0].read_bytes())
            finally:
                writer.close()

    def test_strict_private_wal_orphan_reaper_defers_over_cap_without_denial(self) -> None:
        # Cleanup is bounded, but more than 64 previously marker-attested
        # SIGKILL orphans must never permanently deny public READ_ONLY.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            orphan_names = []
            for index in range(sqlite_store._STRICT_PRIVATE_WAL_MAX_ORPHAN_ENTRIES + 1):
                candidate = root / f"grabowski-strict-wal-owned-{index:03d}"
                candidate.mkdir(mode=0o700)
                sqlite_store._strict_wal_mark_private_snapshot(candidate, "old.sqlite3")
                contents = candidate / "old.sqlite3"
                contents.write_bytes(b"disposable")
                contents.chmod(0o600)
                orphan_names.append(candidate)
            database = root / "orphan-budget.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE witness(value INTEGER)")
                writer.execute("INSERT INTO witness VALUES (71)")
                writer.commit()
                for _ in range(2):
                    with (
                        patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                        sqlite_store.inventory_readonly_sqlite(
                            database, temporary_prefix="orphan-budget-",
                            error_type=InventoryChanged, allow_wal_copy=False,
                            allow_private_wal_snapshot=True,
                        ) as reader,
                    ):
                        self.assertEqual(
                            71, reader.execute("SELECT value FROM witness").fetchone()[0],
                        )
                self.assertFalse(any(item.exists() for item in orphan_names))
            finally:
                writer.close()

    def test_strict_private_wal_orphan_reaper_does_not_follow_malicious_entries(self) -> None:
        # Even with a valid marker an unexpected symlink means the entire
        # directory is left intact; marker/prefix alone are not cleanup authority.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "keep"
            victim.write_bytes(b"valuable")
            forged = root / "grabowski-strict-wal-foreign"
            forged.mkdir(mode=0o700)
            sqlite_store._strict_wal_mark_private_snapshot(forged, "database.sqlite3")
            (forged / "database.sqlite3").symlink_to(victim)
            other_link = root / "grabowski-strict-wal-symlink"
            other_link.symlink_to(victim)
            database = root / "safe.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (9)")
                writer.commit()
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="no-follow-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader,
                ):
                    self.assertEqual(
                        9, reader.execute("SELECT value FROM content").fetchone()[0],
                    )
                self.assertTrue(forged.is_dir())
                self.assertTrue(other_link.is_symlink())
                self.assertEqual(b"valuable", victim.read_bytes())
            finally:
                writer.close()

    def test_private_wal_checkpoint_restart_must_not_publish_stale_bytes(self) -> None:
        # A checkpoint RESTART may be safely readable or fail closed,
        # depending on the actual SHM/WAL state. A stale value is never valid.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "restart.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value INTEGER)")
                writer.execute("INSERT INTO content VALUES (7)")
                writer.commit()
                checkpoint = writer.execute("PRAGMA wal_checkpoint(RESTART)").fetchone()
                self.assertEqual(0, checkpoint[0])
                files = [database, Path(str(database) + "-wal"), Path(str(database) + "-shm")]
                before = [_original_sqlite_bytes_in_child(p) for p in files]
                value = None
                try:
                    with (
                        patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                        sqlite_store.inventory_readonly_sqlite(
                            database, temporary_prefix="restart-shm-",
                            error_type=InventoryChanged, allow_wal_copy=False,
                            allow_private_wal_snapshot=True,
                        ) as reader,
                    ):
                        value = reader.execute("SELECT value FROM content").fetchone()[0]
                except InventoryChanged:
                    pass  # The uncertain checkpoint state is intentionally denied.
                if value is not None:
                    self.assertEqual(7, value)
                self.assertEqual(before, [_original_sqlite_bytes_in_child(p) for p in files])
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_preserves_caller_sqlite_error(self) -> None:
        # Caller schema mistakes must remain diagnostic, not retryable inventory drift.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "caller-sqlite-error.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE existing(value TEXT)")
                writer.execute("INSERT INTO existing VALUES ('present')")
                writer.commit()
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    self.assertRaisesRegex(sqlite3.OperationalError, "no such table"),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="caller-error-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        reader.execute("SELECT * FROM missing_table").fetchall()
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_does_not_mask_caller_error_on_source_change(self) -> None:
        # Original caller error has diagnostic priority over post-error drift.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "caller-error-drift.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE existing(value TEXT)")
                writer.execute("INSERT INTO existing VALUES ('before')")
                writer.commit()
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    self.assertRaisesRegex(ValueError, "original caller diagnostic"),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="caller-drift-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        self.assertEqual(
                            "before",
                            reader.execute("SELECT value FROM existing").fetchone()[0],
                        )
                        writer.execute("INSERT INTO existing VALUES ('after')")
                        writer.commit()
                        raise ValueError("original caller diagnostic")
            finally:
                writer.close()

    def test_strict_private_wal_snapshot_verifies_source_after_connection_close(self) -> None:
        # A writer may commit after the last query, while rollback/close of
        # the private reader still runs. No successful READ_ONLY result may
        # escape without a fresh source check after that cleanup.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "cleanup-race.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE content(value TEXT)")
                writer.execute("INSERT INTO content VALUES ('before')")
                writer.commit()
                real_connect = sqlite3.connect
                closed = []

                class CommitOnClose:
                    def __init__(self, inner):
                        object.__setattr__(self, "_inner", inner)

                    def __getattr__(self, name):
                        return getattr(self._inner, name)

                    def __setattr__(self, name, value):
                        setattr(self._inner, name, value)

                    def close(self):
                        self._inner.close()
                        writer.execute("INSERT INTO content VALUES ('during-close')")
                        writer.commit()
                        closed.append(True)

                def connect(database_arg, *args, **kwargs):
                    result = real_connect(database_arg, *args, **kwargs)
                    if isinstance(database_arg, str) and database_arg.endswith("?mode=ro"):
                        return CommitOnClose(result)
                    return result

                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=root),
                    patch.object(sqlite_store.sqlite3, "connect", side_effect=connect),
                    self.assertRaisesRegex(InventoryChanged, "Store changed"),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="post-close-race-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ) as reader:
                        self.assertEqual(
                            "before",
                            reader.execute("SELECT value FROM content LIMIT 1").fetchone()[0],
                        )
                self.assertEqual([True], closed)
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

    def test_wal_index_cannot_hide_valid_later_committed_frames(self) -> None:
        # A correctly checksummed earlier mxFrame from the *same* WAL
        # epoch must not let a reader ignore later committed WAL frames.
        # This test exercises only a disposable validator copy.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "hidden-commit.sqlite3"
            writer = sqlite3.connect(database)
            try:
                self.assertEqual(
                    "wal", writer.execute("PRAGMA journal_mode=WAL").fetchone()[0],
                )
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE inventory(value TEXT)")
                writer.execute("INSERT INTO inventory VALUES ('first')")
                writer.commit()
                wal = Path(str(database) + "-wal")
                shm = Path(str(database) + "-shm")
                old_index = _original_sqlite_bytes_in_child(shm)[:96]
                old_size = wal.stat().st_size
                writer.execute("INSERT INTO inventory VALUES ('second')")
                writer.commit()
                self.assertGreater(wal.stat().st_size, old_size)
                private_wal = root / "private-validator.wal"
                private_wal.write_bytes(_original_sqlite_bytes_in_child(wal))
                current_index = _original_sqlite_bytes_in_child(shm)[:96]
                self.assertGreater(
                    sqlite_store._strict_validate_copied_wal(
                        private_wal, error_type=InventoryChanged,
                        message="fresh WalIndex", wal_index_header=current_index,
                    ), old_size,
                )
                with self.assertRaises(InventoryChanged):
                    sqlite_store._strict_validate_copied_wal(
                        private_wal, error_type=InventoryChanged,
                        message="stale-but-checksummed WalIndex",
                        wal_index_header=old_index,
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
                standalone.write_bytes(_original_sqlite_bytes_in_child(wal))
                header = _original_sqlite_bytes_in_child(shm)[:96]
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
                    p.name: _original_sqlite_bytes_in_child(p)
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
                    {p.name: _original_sqlite_bytes_in_child(p) for p in Path(directory).iterdir()},
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
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        side_effect=AssertionError("budget must reject before mount check"),
                    ) as mount,
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
                mount.assert_not_called()
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
                corrupted.write_bytes(_original_sqlite_bytes_in_child(wal))
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
                corrupted.write_bytes(_original_sqlite_bytes_in_child(wal))
                with self.assertRaises(InventoryChanged):
                    sqlite_store._strict_validate_copied_wal(
                        corrupted, error_type=InventoryChanged,
                        message="invalid WAL checksum",
                    )
            finally:
                writer.close()

    def test_strict_wal_owner_flock_is_same_for_different_home_environments(self) -> None:
        # The uid account-root remains stable for two independent processes
        # with different HOME values. Both use the same synthetic passwd home,
        # never the developer's production config directory.
        with TemporaryDirectory() as directory:
            account = Path(directory) / "account"
            owner_lock = account / ".config" / "grabowski"
            owner_lock.mkdir(parents=True, mode=0o700)
            owner_lock.chmod(0o700)
            roots = [Path(directory) / name for name in ("home-a", "home-b")]
            for root in roots:
                lock_dir = root / ".config" / "grabowski"
                lock_dir.mkdir(parents=True, mode=0o700)
                lock_dir.chmod(0o700)
            probe = (
                "import sys\n"
                "from types import SimpleNamespace\n"
                "from unittest.mock import patch\n"
                "sys.path.insert(0,sys.argv[1])\n"
                "import grabowski_sqlite_store as store\n"
                "store.STRICT_PRIVATE_WAL_LOCK_TIMEOUT_SECONDS=0.5\n"
                "with patch.object(store.pwd, 'getpwuid', "
                "return_value=SimpleNamespace(pw_dir=sys.argv[2])):\n"
                " try:\n"
                "  fd=store._strict_wal_owner_lock_acquire("
                "error_type=RuntimeError,message='blocked')\n"
                " except RuntimeError:\n"
                "  print('BLOCKED')\n"
                " else:\n"
                "  store._strict_wal_owner_lock_release(fd)\n"
                "  print('ACQUIRED')\n"
            )
            with (
                patch.object(
                    sqlite_store.pwd, "getpwuid",
                    return_value=SimpleNamespace(pw_dir=str(account)),
                ),
                patch.dict(os.environ, {"HOME": str(roots[0])}),
            ):
                held = sqlite_store._strict_wal_owner_lock_acquire(
                    error_type=InventoryChanged, message="outer lock",
                )
                try:
                    result = subprocess.run(
                        [
                            sys.executable, "-I", "-B", "-c", probe,
                            str(Path(sqlite_store.__file__).resolve().parent),
                            str(account),
                        ],
                        env={**os.environ, "HOME": str(roots[1])},
                        capture_output=True, text=True, check=True, timeout=8,
                    )
                    self.assertEqual("BLOCKED", result.stdout.strip())
                finally:
                    sqlite_store._strict_wal_owner_lock_release(held)

    def test_strict_wal_nested_owner_lock(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            first = sqlite_store._strict_wal_owner_lock_acquire(
                error_type=InventoryChanged, message="test lock",
                private_scratch_root=root,
            )
            try:
                second = sqlite_store._strict_wal_owner_lock_acquire(
                    error_type=InventoryChanged, message="nested test lock",
                    private_scratch_root=root,
                )
                self.assertEqual(first, second)
                sqlite_store._strict_wal_owner_lock_release(second)
            finally:
                sqlite_store._strict_wal_owner_lock_release(first)

    def test_strict_wal_owner_lock_releases_non_lifo_without_fd_leak(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            def acquire(message: str) -> int:
                return sqlite_store._strict_wal_owner_lock_acquire(
                    error_type=InventoryChanged, message=message,
                    private_scratch_root=root,
                )
            first = acquire("outer lock")
            second = acquire("inner lock")
            self.assertEqual(first, second)
            # The outer context may finish first; the remaining caller must
            # still hold the original flock and its valid descriptor.
            sqlite_store._strict_wal_owner_lock_release(first)
            os.fstat(second)
            third = acquire("third nested lock")
            self.assertEqual(second, third)
            sqlite_store._strict_wal_owner_lock_release(third)
            os.fstat(second)
            sqlite_store._strict_wal_owner_lock_release(second)
            with self.assertRaises(OSError):
                os.fstat(second)
            again = acquire("fresh lock")
            sqlite_store._strict_wal_owner_lock_release(again)

    def test_strict_private_wal_rejects_large_physical_tail_before_hash(self) -> None:
        with TemporaryDirectory() as directory:
            db = Path(directory) / "large-tail.sqlite3"
            db.write_bytes(b"placeholder")
            with Path(str(db) + "-wal").open("wb") as wal:
                wal.truncate(
                    sqlite_store.STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES + 1
                )
            with patch.object(
                sqlite_store, "_strict_wal_memory_root",
                side_effect=AssertionError("tail must be rejected before mount check"),
            ):
                with self.assertRaises(InventoryChanged):
                    with sqlite_store._strict_private_wal_snapshot(
                        db, error_type=InventoryChanged,
                        message="oversize source WAL", max_copy_bytes=None,
                    ):
                        self.fail("oversize WAL must not be replayed")

    def test_strict_wal_worker_cannot_copy_more_than_preflight_headroom(self) -> None:
        # Reproduce a genuine SQLite commit/checkpoint between the parent's
        # memory proof and the isolated worker. The old worker copied the
        # larger database before the parent noticed changed source identities.
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "growing.sqlite3"
            writer = sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute("CREATE TABLE items (payload BLOB)")
                writer.execute("INSERT INTO items VALUES (?)", (b"initial",))
                writer.commit()
                wal = Path(str(database) + "-wal")
                approved_bytes = database.stat().st_size + min(
                    wal.stat().st_size, sqlite_store.STRICT_PRIVATE_WAL_MAX_WAL_BYTES
                )
                observed_private_copies = []
                original_worker = sqlite_store._strict_wal_source_worker

                def grow_at_prepare(action, **kwargs):
                    if action != "prepare":
                        return original_worker(action, **kwargs)
                    writer.execute(
                        "INSERT INTO items VALUES (?)", (b"x" * (1024 * 1024),)
                    )
                    writer.commit()
                    writer.execute("PRAGMA wal_checkpoint(PASSIVE)")
                    writer.execute("INSERT INTO items VALUES (?)", (b"new tail",))
                    writer.commit()
                    self.assertGreater(database.stat().st_size, approved_bytes)
                    try:
                        return original_worker(action, **kwargs)
                    finally:
                        copied = kwargs["scratch"] / database.name
                        if copied.exists():
                            observed_private_copies.append(copied.stat().st_size)

                # Advertise only enough free memory for the ORIGINAL source
                # size. A later real source growth must fail in the worker
                # before even the first plaintext byte is copied.
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root", return_value=root,
                    ),
                    patch.object(
                        sqlite_store, "_strict_wal_available_memory",
                        return_value=(
                            2 * approved_bytes
                            + sqlite_store.STRICT_PRIVATE_WAL_MEMORY_RESERVE_BYTES
                        ),
                    ),
                    patch.object(
                        sqlite_store, "_strict_wal_source_worker",
                        side_effect=grow_at_prepare,
                    ),
                    self.assertRaises(InventoryChanged),
                ):
                    with sqlite_store.inventory_readonly_sqlite(
                        database, temporary_prefix="headroom-race-",
                        error_type=InventoryChanged, allow_wal_copy=False,
                        allow_private_wal_snapshot=True,
                    ):
                        self.fail("raced source must not yield a reader")
                self.assertEqual(
                    observed_private_copies, [],
                    "worker must not copy bytes beyond preflight-approved headroom",
                )
            finally:
                writer.close()

    def test_strict_private_wal_memory_headroom_blocks_before_copy(self) -> None:
        with TemporaryDirectory() as directory:
            db = Path(directory) / "low-memory.sqlite3"
            writer = sqlite3.connect(db)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE committed (value INTEGER)")
                writer.execute("INSERT INTO committed VALUES (17)")
                writer.commit()
                with (
                    patch.object(
                        sqlite_store, "_strict_wal_memory_root",
                        return_value=Path(directory),
                    ),
                    patch.object(
                        sqlite_store, "_strict_wal_available_memory",
                        return_value=0,
                    ) as headroom,
                    patch.object(
                        sqlite_store.tempfile, "TemporaryDirectory",
                        side_effect=AssertionError("no copy when memory unavailable"),
                    ) as scratch,
                ):
                    with self.assertRaises(InventoryChanged):
                        with sqlite_store.inventory_readonly_sqlite(
                            db, temporary_prefix="memory-preflight-",
                            error_type=InventoryChanged, allow_wal_copy=False,
                            allow_private_wal_snapshot=True,
                        ):
                            self.fail("memory limit must deny")
                headroom.assert_called_once()
                scratch.assert_not_called()
            finally:
                writer.close()

    def test_strict_wal_cgroup_v2_headroom_is_minimum_of_ancestor_limits(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            service = root / "system.slice" / "grabowski.service"
            service.mkdir(parents=True)
            (root / "cgroup.controllers").write_text("memory cpu\n")
            (service / "memory.max").write_text("20000\n")
            (service / "memory.current").write_text("14000\n")
            parent = service.parent
            (parent / "memory.max").write_text("8000\n")
            (parent / "memory.current").write_text("5000\n")
            process_cgroup = Path(directory) / "self-cgroup"
            process_cgroup.write_text("0::/system.slice/grabowski.service\n")
            self.assertEqual(3000, sqlite_store._strict_wal_cgroup_memory_headroom(
                error_type=InventoryChanged, message="cgroup budget",
                cgroup_file=process_cgroup, mount_root=root,
            ))
            (parent / "memory.max").write_text("max\n")
            self.assertEqual(6000, sqlite_store._strict_wal_cgroup_memory_headroom(
                error_type=InventoryChanged, message="cgroup budget",
                cgroup_file=process_cgroup, mount_root=root,
            ))
            (service / "memory.max").write_text("max\n")
            self.assertIsNone(sqlite_store._strict_wal_cgroup_memory_headroom(
                error_type=InventoryChanged, message="cgroup budget",
                cgroup_file=process_cgroup, mount_root=root,
            ))

    def test_strict_wal_hybrid_v1_memory_controller_with_v2_mount_fails_closed(self) -> None:
        # A unified mount does not prove that memory is controlled by v2.
        # A parallel v1 memory controller may impose a much smaller limit.
        with TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            service = root / "system.slice" / "service"
            service.mkdir(parents=True)
            (root / "cgroup.controllers").write_text("cpu memory\n")
            (service / "memory.max").write_text("max\n")
            (service / "memory.current").write_text("100\n")
            process_cgroup = Path(directory) / "self-cgroup"
            process_cgroup.write_text(
                "0::/system.slice/service\n"
                "5:memory:/system.slice/service\n",
                encoding="ascii",
            )
            with self.assertRaises(InventoryChanged):
                sqlite_store._strict_wal_cgroup_memory_headroom(
                    error_type=InventoryChanged, message="hybrid memory not proven",
                    cgroup_file=process_cgroup, mount_root=root,
                )

    def test_strict_wal_cgroup_v1_memory_or_unmounted_v2_fails_closed(self) -> None:
        # A v1 memory controller can impose an OOM limit hidden from host
        # MemAvailable. Fail closed until its memory hierarchy is verified.
        with TemporaryDirectory() as directory:
            root = Path(directory) / "not-a-v2-mount"
            root.mkdir()
            cgroup = Path(directory) / "self-cgroup"
            for value in ("5:memory:/system.slice/service\n",
                          "0::/system.slice/service\n",
                          "5:cpu,cpuacct:/slice\n4:memory:/slice\n"):
                with self.subTest(cgroup=value):
                    cgroup.write_text(value, encoding="ascii")
                    with self.assertRaises(InventoryChanged):
                        sqlite_store._strict_wal_cgroup_memory_headroom(
                            error_type=InventoryChanged, message="unverified memory",
                            cgroup_file=cgroup, mount_root=root,
                        )
            cgroup.write_text("5:cpu,cpuacct:/slice\n", encoding="ascii")
            self.assertIsNone(sqlite_store._strict_wal_cgroup_memory_headroom(
                error_type=InventoryChanged, message="no memory controller",
                cgroup_file=cgroup, mount_root=root,
            ))

    def test_strict_wal_cgroup_v2_invalid_or_incomplete_limits_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "cgroup"
            service = root / "scope"
            service.mkdir(parents=True)
            (root / "cgroup.controllers").write_text("memory\n")
            process_cgroup = Path(directory) / "self-cgroup"
            process_cgroup.write_text("0::/scope\n")
            (service / "memory.max").write_text("4096\n")
            with self.assertRaises(InventoryChanged):
                sqlite_store._strict_wal_cgroup_memory_headroom(
                    error_type=InventoryChanged, message="missing current",
                    cgroup_file=process_cgroup, mount_root=root,
                )
            (service / "memory.current").write_text("5000\n")
            self.assertEqual(0, sqlite_store._strict_wal_cgroup_memory_headroom(
                error_type=InventoryChanged, message="over limit",
                cgroup_file=process_cgroup, mount_root=root,
            ))
            for invalid in ("not-a-limit", "-1", "9" * 80):
                (service / "memory.max").write_text(invalid + "\n")
                with self.subTest(invalid=invalid):
                    with self.assertRaises(InventoryChanged):
                        sqlite_store._strict_wal_cgroup_memory_headroom(
                            error_type=InventoryChanged, message="invalid limit",
                            cgroup_file=process_cgroup, mount_root=root,
                        )
            process_cgroup.write_text("0::/../scope\n")
            with self.assertRaises(InventoryChanged):
                sqlite_store._strict_wal_cgroup_memory_headroom(
                    error_type=InventoryChanged, message="escape",
                    cgroup_file=process_cgroup, mount_root=root,
                )

    def test_strict_private_wal_cgroup_budget_rejects_before_copy(self) -> None:
        with TemporaryDirectory() as directory:
            db = Path(directory) / "limited.sqlite3"
            writer = sqlite3.connect(db)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("CREATE TABLE committed (value INTEGER)")
                writer.execute("INSERT INTO committed VALUES (17)")
                writer.commit()
                with (
                    patch.object(sqlite_store, "_strict_wal_memory_root", return_value=Path(directory)),
                    patch.object(sqlite_store, "_strict_wal_cgroup_memory_headroom",
                                 return_value=0) as headroom,
                    patch.object(sqlite_store.tempfile, "TemporaryDirectory",
                                 side_effect=AssertionError("no copy over cgroup budget")) as scratch,
                ):
                    with self.assertRaises(InventoryChanged):
                        with sqlite_store.inventory_readonly_sqlite(
                            db, temporary_prefix="cgroup-budget-",
                            error_type=InventoryChanged, allow_wal_copy=False,
                            allow_private_wal_snapshot=True,
                        ):
                            self.fail("cgroup memory limit must deny")
                headroom.assert_called_once()
                scratch.assert_not_called()
            finally:
                writer.close()

    def test_strict_wal_fingerprint_caps_fd_size_before_read(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "large-wal"
            source.write_bytes(b"x" * 11)
            with patch.object(
                sqlite_store.os, "read",
                side_effect=AssertionError("oversize must reject before read"),
            ) as reading:
                with self.assertRaises(InventoryChanged):
                    sqlite_store._strict_wal_file_fingerprint(
                        source, error_type=InventoryChanged,
                        message="over-budget source", max_bytes=10,
                    )
            reading.assert_not_called()

    def test_strict_wal_fingerprint_rejects_concurrent_growth_without_following_tail(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "growing-wal"
            source.write_bytes(b"stable initial bytes")
            original_read = sqlite_store.os.read
            reads = [0]

            def grow_after_first_read(descriptor, count):
                data = original_read(descriptor, count)
                reads[0] += 1
                if reads[0] == 1:
                    with source.open("ab") as changed:
                        changed.write(b"changed after initial stat" * 20)
                return data

            with patch.object(sqlite_store.os, "read", grow_after_first_read):
                with self.assertRaises(InventoryChanged):
                    sqlite_store._strict_wal_file_fingerprint(
                        source, error_type=InventoryChanged,
                        message="source changed", max_bytes=4096,
                    )
            self.assertEqual(1, reads[0], "source growth must not extend hashing")

    def test_strict_wal_worker_caps_sparse_sidecar_before_hash(self) -> None:
        with TemporaryDirectory() as directory:
            db = Path(directory) / "worker.sqlite3"
            db.write_bytes(b"source")
            wal = Path(str(db) + "-wal")
            with wal.open("wb") as stream:
                stream.truncate(
                    sqlite_store.STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES + 1
                )
            shm = Path(str(db) + "-shm")
            shm.write_bytes(b"shm")
            with patch.object(
                sqlite_store, "_strict_validate_copied_wal",
                side_effect=AssertionError("worker must reject before replay"),
            ) as validation:
                self.assertEqual(
                    1, sqlite_store._strict_wal_worker_main([
                        "--strict-wal-source-worker", "fingerprint",
                        str(db), str(wal), str(shm),
                    ]),
                )
            validation.assert_not_called()

if __name__ == "__main__":
    unittest.main()
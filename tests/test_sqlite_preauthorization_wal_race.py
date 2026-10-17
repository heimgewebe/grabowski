"""Fail-closed regression for WAL appearing during preauthorization inspection."""

from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_sqlite_store as sqlite_store


class SqlitePreauthorizationWalRaceTests(unittest.TestCase):
    def test_appearing_wal_never_creates_host_snapshot_before_gate(self) -> None:
        """A second-check WAL cannot enter the host-copy fallback."""
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "preauth-new-wal.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE values_test (value INTEGER)")
                connection.commit()
            wal = Path(f"{database}-wal")
            self.assertFalse(wal.exists())
            real_exists = Path.exists
            checks = 0
            writer = None

            def appear_between_checks(candidate: Path) -> bool:
                nonlocal checks, writer
                if candidate == wal:
                    checks += 1
                    if checks == 2:
                        writer = sqlite3.connect(database)
                        writer.execute("PRAGMA journal_mode=WAL")
                        writer.execute("INSERT INTO values_test VALUES (1)")
                        writer.commit()
                return real_exists(candidate)

            class StaleStore(RuntimeError):
                pass

            try:
                with (
                    patch.object(Path, "exists", appear_between_checks),
                    patch.object(
                        sqlite_store.tempfile, "TemporaryDirectory",
                        side_effect=AssertionError("pre-gate host snapshot attempted"),
                    ) as host_copy,
                ):
                    with self.assertRaises(StaleStore):
                        with sqlite_store.preauthorization_readonly_sqlite(
                            database, error_type=StaleStore,
                        ) as connection:
                            connection.execute("SELECT value FROM values_test").fetchall()
                    host_copy.assert_not_called()
                self.assertGreaterEqual(checks, 2)
            finally:
                if writer is not None:
                    writer.close()


if __name__ == "__main__":
    unittest.main()

"""Resource SQLite connection lifetime and WAL-lock release regressions."""

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import test_resources as fixture

resources = fixture.resources


class ResourceSqliteLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.database = Path(self.tempdir.name) / "state" / "resources.sqlite3"
        guard = patch.object(resources, "RESOURCE_DB", self.database)
        guard.start()
        self.addCleanup(guard.stop)

    def test_database_context_always_closes_retained_connection(self) -> None:
        with resources._database() as connection:
            self.assertEqual("3", resources._resource_schema_version(connection))
            self.assertEqual("wal", connection.execute("PRAGMA journal_mode").fetchone()[0])
        # sqlite3.Connection.__exit__ commits but does not close by default.
        # Keeping an external reference must not pin WAL locks after return.
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with closing(sqlite3.connect(self.database, timeout=1, isolation_level=None)) as verify:
            self.assertEqual("delete", verify.execute("PRAGMA journal_mode=DELETE").fetchone()[0])

    def test_exception_rolls_back_and_closes_connection(self) -> None:
        connection = None
        with self.assertRaisesRegex(RuntimeError, "abort after SQL write"):
            with resources._database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("INSERT INTO metadata(key, value) VALUES('lifecycle-test', 'uncommitted')")
                raise RuntimeError("abort after SQL write")
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
        with resources._database() as verify:
            self.assertIsNone(verify.execute("SELECT value FROM metadata WHERE key='lifecycle-test'").fetchone())

    def test_explicit_direct_connection_remains_usable_until_closed(self) -> None:
        direct = resources._database()
        try:
            self.assertEqual("3", resources._resource_schema_version(direct))
            self.assertEqual(1, direct.execute("SELECT 1").fetchone()[0])
        finally:
            direct.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            direct.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()

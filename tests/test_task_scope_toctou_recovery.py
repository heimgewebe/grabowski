"""Fail-first P1 regression: terminalization must authorize the row it mutates.

Task-status and batch recovery preauthorize a snapshot. A same-UID actor can
replace the SQLite pathname after that snapshot, making the writable row differ.
A projection must not mutate a row that is blocked under its current scope.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import test_tasks as fixture


tasks = fixture.tasks


class TaskScopeToctouRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = fixture.TaskTests(
            "test_native_task_effect_classification_covers_local_and_remote_agents"
        )
        self.fixtures.setUp()
        self.addCleanup(self.fixtures.tearDown)

    def test_projection_reauthorizes_current_writable_task_row(self) -> None:
        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        before_scope = tasks._row_scope_identity_readonly(task_id)
        blocked_path = str(self.fixtures.root / "blocked-replacement-workspace")
        self.assertNotEqual(before_scope["cwd"], blocked_path)

        # Model the second DB image after the preauthorization path swap.
        # Only this disposable fixture database is touched.
        with tasks._database_connection() as connection:
            connection.execute(
                "UPDATE tasks SET cwd=? WHERE task_id=?",
                (blocked_path, task_id),
            )
        blocked_row = tasks._row_raw(task_id)
        gate_calls = []

        def scoped_gate(_capability: str, **scope: object) -> None:
            gate_calls.append(dict(scope))
            if scope.get("path") == blocked_path:
                raise PermissionError("blocked writable task row")

        with (
            patch.object(tasks.operator, "_require_operator_mutation",
                         side_effect=scoped_gate),
            self.assertRaisesRegex(PermissionError, "blocked writable task row"),
        ):
            tasks._apply_terminalization_projection(transition, recovered=True)

        # Neither the durable task projection nor the pending resource record
        # may be finalized on a row whose actual authority was denied.
        self.assertTrue(any(scope.get("path") == blocked_path for scope in gate_calls))
        self.assertEqual(tasks._row_raw(task_id), blocked_row)
        self.assertEqual(
            "leases_revoked",
            tasks.resources.task_terminalization_record(task_id)["phase"],
        )


    def test_projection_rechecks_successor_service_in_transaction(self) -> None:
        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        record_before = tasks._row_raw(task_id)
        next_service = tasks._task_unit(task_id, int(record_before["attempt"]) + 9)
        self.assertNotEqual(next_service, tasks._authoritative_unit(record_before))
        projection = {**transition["task_projection"], "unit": next_service}
        changed = {**transition, "task_projection": projection}
        checked_services = []

        def scoped_gate(_capability: str, **scope: object) -> None:
            checked_services.append(scope.get("service"))
            if scope.get("service") == next_service:
                raise PermissionError("blocked successor service")

        with (
            patch.object(tasks.operator, "_require_operator_mutation",
                         side_effect=scoped_gate),
            self.assertRaisesRegex(PermissionError, "blocked successor service"),
        ):
            tasks._apply_terminalization_projection(changed, recovered=True)

        self.assertIn(next_service, checked_services)
        self.assertEqual(tasks._row_raw(task_id), record_before)
        self.assertEqual(
            "leases_revoked",
            tasks.resources.task_terminalization_record(task_id)["phase"],
        )

    def test_batch_denial_after_preflight_aborts_without_cursor_mutation(self) -> None:
        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        blocked_path = str(self.fixtures.root / "blocked-late-batch-workspace")
        page = {
            "terminalizations": [transition],
            "examined": 1,
            "cycle_completed": True,
            "cursor_after": None,
            "high_water": None,
        }
        original_apply = tasks._apply_terminalization_projection

        def late_switch(terminalization: dict, *, recovered: bool = False) -> dict:
            # Simulate the database pathname changing *after* the page-wide
            # read-only preflight but just before the first writable row read.
            with tasks._database_connection() as connection:
                connection.execute(
                    "UPDATE tasks SET cwd=? WHERE task_id=?",
                    (blocked_path, task_id),
                )
            return original_apply(terminalization, recovered=recovered)

        def scoped_gate(_capability: str, **scope: object) -> None:
            if scope.get("path") == blocked_path:
                raise PermissionError("late batch row blockade")

        with (
            patch.object(tasks.resources, "pending_task_terminalizations",
                         return_value=page),
            patch.object(tasks, "_load_terminalization_recovery_cycle",
                         return_value=None),
            patch.object(tasks, "_apply_terminalization_projection",
                         side_effect=late_switch),
            patch.object(tasks, "_save_terminalization_recovery_cycle") as save,
            patch.object(tasks.operator, "_require_operator_mutation",
                         side_effect=scoped_gate),
            self.assertRaisesRegex(PermissionError, "late batch row blockade"),
        ):
            tasks._recover_pending_task_terminalizations(limit=1)
        save.assert_not_called()
        self.assertEqual(
            "leases_revoked",
            tasks.resources.task_terminalization_record(task_id)["phase"],
        )

    def test_scoped_denial_precedes_sqlite_chmod_and_wal_open(self) -> None:
        """Denied projection may not repair permissions or mutate the DB first."""
        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        db = tasks.TASK_DB
        original_mode = db.stat().st_mode & 0o777
        scoped_calls = []

        try:
            db.chmod(0o640)
            before_db = db.read_bytes()
            before_wal = (
                (tasks.Path(str(db) + "-wal")).read_bytes()
                if tasks.Path(str(db) + "-wal").exists() else None
            )

            def deny_scope(_capability: str, **scope: object) -> None:
                scoped_calls.append(dict(scope))
                if scope.get("path") == str(self.fixtures.root):
                    raise PermissionError("scoped projection denied")

            with (
                patch.object(tasks.operator, "_require_operator_mutation",
                             side_effect=deny_scope),
                self.assertRaisesRegex(PermissionError, "scoped projection denied"),
            ):
                tasks._apply_terminalization_projection(transition, recovered=True)

            self.assertTrue(any(s.get("path") == str(self.fixtures.root)
                                for s in scoped_calls))
            self.assertEqual(db.stat().st_mode & 0o777, 0o640)
            self.assertEqual(db.read_bytes(), before_db)
            wal_path = tasks.Path(str(db) + "-wal")
            self.assertEqual(wal_path.read_bytes() if wal_path.exists() else None, before_wal)
            self.assertEqual(
                "leases_revoked",
                tasks.resources.task_terminalization_record(task_id)["phase"],
            )
        finally:
            db.chmod(original_mode)


    def test_path_swap_does_not_repair_denied_replacement_database(self) -> None:
        """Gate the opened DB row before chmod/WAL when the path is exchanged."""
        import os
        import sqlite3
        from contextlib import closing

        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        database = tasks.TASK_DB
        original = database.with_name(database.name + ".original")
        replacement = database.with_name(database.name + ".replacement")
        blocked_path = str(self.fixtures.root / "blocked-swapped-workspace")
        with (
            closing(sqlite3.connect(database)) as source,
            closing(sqlite3.connect(replacement)) as clone,
        ):
            source.backup(clone)
            clone.execute(
                "UPDATE tasks SET cwd=? WHERE task_id=?", (blocked_path, task_id)
            )
            clone.commit()
        replacement.chmod(0o640)
        blocked_db_bytes = replacement.read_bytes()
        original_readonly = tasks._row_scope_identity_readonly
        swapped = False

        def swap_after_read(identifier: str) -> dict:
            nonlocal swapped
            record = original_readonly(identifier)
            if not swapped:
                os.replace(database, original)
                os.replace(replacement, database)
                swapped = True
            return record

        def deny_replaced_scope(_capability: str, **scope: object) -> None:
            if scope.get("path") == blocked_path:
                raise PermissionError("swapped database is denied")

        try:
            with (
                patch.object(tasks, "_row_scope_identity_readonly",
                             side_effect=swap_after_read),
                patch.object(tasks.operator, "_require_operator_mutation",
                             side_effect=deny_replaced_scope),
                self.assertRaisesRegex(tasks.TaskSchemaInventoryChanged, "changed after scoped preauthorization"),
            ):
                tasks._apply_terminalization_projection(transition, recovered=True)
            self.assertTrue(swapped)
            self.assertEqual(
                database.stat().st_mode & 0o777, 0o640,
                "denied replacement DB must not be chmod-repaired before its gate",
            )
            self.assertEqual(database.read_bytes(), blocked_db_bytes)
            self.assertEqual(
                "leases_revoked",
                tasks.resources.task_terminalization_record(task_id)["phase"],
            )
        finally:
            if swapped:
                os.replace(database, replacement)
                os.replace(original, database)


    def test_late_wal_scope_denial_does_not_create_shared_memory_file(self) -> None:
        """A newly appearing WAL must not create host SHM before scoped denial."""
        import os
        import sqlite3
        import subprocess
        import sys
        from contextlib import closing

        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        database = tasks.TASK_DB
        wal = tasks.Path(str(database) + "-wal")
        shm = tasks.Path(str(database) + "-shm")
        denied_scope = str(self.fixtures.root / "denied-wal-scope")
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(
                "delete",
                connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0],
            )
        original_read = tasks._row_scope_identity_readonly
        raced = False

        def read_then_race(identifier: str) -> dict:
            nonlocal raced
            allowed = original_read(identifier)
            if not raced:
                child = (
                    "import os,sqlite3,sys\n"
                    "c=sqlite3.connect(sys.argv[1])\n"
                    "c.execute('PRAGMA journal_mode=WAL')\n"
                    "c.execute('UPDATE tasks SET cwd=? WHERE task_id=?',"
                    "(sys.argv[2],sys.argv[3]))\n"
                    "c.commit()\n"
                    "os._exit(0)\n"
                )
                subprocess.run(
                    [sys.executable, "-B", "-c", child, str(database),
                     denied_scope, task_id],
                    check=True, timeout=15, capture_output=True,
                )
                self.assertTrue(wal.exists())
                if shm.exists():
                    shm.unlink()
                raced = True
            return allowed

        def deny_changed_scope(_capability: str, **scope: object) -> None:
            if scope.get("path") == denied_scope:
                self.assertFalse(
                    shm.exists(), "untrusted SQLite WAL created SHM before authorization"
                )
                raise PermissionError("late WAL identity denied")

        with (
            patch.object(tasks, "_row_scope_identity_readonly",
                         side_effect=read_then_race),
            patch.object(tasks.operator, "_require_operator_mutation",
                         side_effect=deny_changed_scope),
            self.assertRaisesRegex(tasks.TaskSchemaInventoryChanged, "changed after scoped preauthorization"),
        ):
            tasks._apply_terminalization_projection(transition, recovered=True)
        self.assertTrue(raced)
        self.assertFalse(shm.exists(), "no host -shm may be created on late WAL denial")


    def test_wal_appears_after_last_snapshot_identity_check_before_sqlite_read(self) -> None:
        """A WAL added after second source preflight must not be read before authorization."""
        import os
        import sqlite3
        import subprocess
        import sys
        from contextlib import closing

        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        database = tasks.TASK_DB
        wal = tasks.Path(str(database) + "-wal")
        shm = tasks.Path(str(database) + "-shm")
        denied_scope = str(self.fixtures.root / "denied-wal-scope")
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(
                "delete",
                connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0],
            )
        original_identity = tasks._terminalization_source_identity
        identity_calls = 0
        raced = False

        def checked_identity_then_race() -> tuple:
            nonlocal raced, identity_calls
            seen = original_identity()
            identity_calls += 1
            if identity_calls == 2:
                child = (
                    "import os,sqlite3,sys\n"
                    "c=sqlite3.connect(sys.argv[1])\n"
                    "c.execute('PRAGMA journal_mode=WAL')\n"
                    "c.execute('UPDATE tasks SET cwd=? WHERE task_id=?',"
                    "(sys.argv[2],sys.argv[3]))\n"
                    "c.commit()\n"
                    "os._exit(0)\n"
                )
                subprocess.run(
                    [sys.executable, "-B", "-c", child, str(database),
                     denied_scope, task_id],
                    check=True, timeout=15, capture_output=True,
                )
                self.assertTrue(wal.exists())
                if shm.exists():
                    shm.unlink()
                raced = True
            return seen

        def deny_changed_scope(_capability: str, **scope: object) -> None:
            if scope.get("path") == denied_scope:
                self.assertFalse(
                    shm.exists(), "untrusted SQLite WAL created SHM before authorization"
                )
                raise PermissionError("late WAL identity denied")

        with (
            patch.object(tasks, "_terminalization_source_identity",
                         side_effect=checked_identity_then_race),
            patch.object(tasks.operator, "_require_operator_mutation",
                         side_effect=deny_changed_scope),
            self.assertRaisesRegex(tasks.TaskSchemaInventoryChanged, "changed after scoped preauthorization"),
        ):
            tasks._apply_terminalization_projection(transition, recovered=True)
        self.assertTrue(raced)
        self.assertGreaterEqual(identity_calls, 3)
        self.assertFalse(shm.exists(), "no host -shm may be created on late WAL denial")


    def test_authorized_projection_retains_existing_recovery_behavior(self) -> None:
        transition = self.fixtures._prepare_pending_terminalization()
        task_id = str(transition["task_id"])
        observed_scopes = []
        with patch.object(
            tasks.operator, "_require_operator_mutation",
            side_effect=lambda _capability, **scope: observed_scopes.append(scope),
        ):
            updated = tasks._apply_terminalization_projection(
                transition, recovered=True
            )
        self.assertEqual(updated["task_id"], task_id)
        self.assertEqual(updated["state"], transition["terminal_state"])
        self.assertTrue(observed_scopes)
        self.assertTrue(all(scope.get("path") == str(self.fixtures.root)
                            for scope in observed_scopes))
        self.assertEqual(
            "projected",
            tasks.resources.task_terminalization_record(task_id)["phase"],
        )


if __name__ == "__main__":
    unittest.main()

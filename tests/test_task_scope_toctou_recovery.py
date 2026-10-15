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

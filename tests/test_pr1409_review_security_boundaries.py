"""Regression tests for reviewer-discovered hidden SQLite effect gates in PR #1409."""
from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest
from unittest import mock

import grabowski_resources as resources
import grabowski_tasks as tasks


class EffectGateBoundaryTests(unittest.TestCase):
    def test_supported_task_updates_do_not_mutate_task_scope_columns(self) -> None:
        # P2-A/B threat-model invariant: official UPDATE paths must not alter
        # cwd, host or lease_owner_id after INSERT. This is a review tripwire
        # if new write paths are introduced; external same-UID SQLite tampering
        # is not an authorized Grabowski task operation.
        tree = ast.parse(Path(tasks.__file__).read_text())
        # JoinedStr literal fragments are also AST Constant children; count
        # their full f-string once rather than counting the SQL prefix twice.
        joined_literal_ids = {
            id(part) for joined in ast.walk(tree)
            if isinstance(joined, ast.JoinedStr)
            for part in joined.values if isinstance(part, ast.Constant)
        }
        updates = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and id(node) not in joined_literal_ids
                and isinstance(node.value, str)
            ):
                if re.search(r"\bUPDATE\s+tasks\s+SET\b", node.value, re.I):
                    updates.append((node.lineno, node.value))
            elif isinstance(node, ast.JoinedStr):
                literals = "".join(
                    part.value for part in node.values
                    if isinstance(part, ast.Constant) and isinstance(part.value, str)
                )
                if re.search(r"\bUPDATE\s+tasks\s+SET\b", literals, re.I):
                    updates.append((node.lineno, literals))
        self.assertEqual(7, len(updates), "review any new tasks UPDATE writer")
        scope_columns = ("cwd", "host", "lease_owner_id")
        for line, statement in updates:
            set_clause = re.split(r"\bWHERE\b", statement, 1, re.I)[0]
            for column in scope_columns:
                self.assertNotRegex(
                    set_clause,
                    rf"\b{column}\s*=",
                    f"task scope changed in UPDATE at {line}",
                )
        # The sole dynamic assignment list is statically enumerated and
        # excludes the three scope columns. Any new update item needs review.
        state_tree = ast.parse(
            Path(tasks.__file__).read_text()
        )
        functions = [
            node for node in state_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_set_state"
        ]
        self.assertEqual(1, len(functions))
        permitted = {
            "state=?", "updated_at_unix=?", "launcher_json=?",
            "last_observation_json=?", "unit=?", "authoritative_unit=?",
            "attempt=?",
        }
        collected = set()
        for node in ast.walk(functions[0]):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "updates"
            ):
                self.assertEqual("append", node.func.attr)
                self.assertEqual(1, len(node.args))
                self.assertIsInstance(node.args[0], ast.Constant)
                collected.add(node.args[0].value)
        self.assertTrue(collected)
        self.assertLessEqual(collected, permitted)

    def test_stale_scope_blockade_happens_before_current_mutable_row(self) -> None:
        # A stale denied snapshot may conservatively refuse an operation,
        # but it must NEVER open the mutable SQLite store first. Scope is
        # immutable through supported writers, so no supported safe update
        # depends on accepting a changed scope here.
        task_id = "a" * 24
        stale = {
            "task_id": task_id,
            "cwd": "/srv/blocked",
            "host": "blocked-host",
            "lease_owner_id": "blocked-owner",
        }
        with (
            mock.patch.object(tasks, "_task_scope_snapshot", return_value=stale),
            mock.patch.object(
                tasks.operator, "_require_operator_mutation",
                side_effect=PermissionError("scope blocked"),
            ),
            mock.patch.object(tasks, "_row_raw") as row,
            mock.patch.object(tasks, "_database_connection") as writable,
        ):
            with self.assertRaisesRegex(PermissionError, "scope blocked"):
                tasks._task_row_after_scoped_gate(task_id)
        row.assert_not_called()
        writable.assert_not_called()

    def test_resource_schema_only_denied_before_inventory(self) -> None:
        with (
            mock.patch.object(resources.operator, "_require_operator_capability"),
            mock.patch.object(
                resources.operator, "_require_operator_mutation",
                side_effect=PermissionError("resource mutation forbidden"),
            ) as admit,
            mock.patch.object(resources, "_resource_schema_inventory") as inventory,
        ):
            with self.assertRaisesRegex(PermissionError, "resource mutation forbidden"):
                resources.grabowski_resource_list(schema_only=True)
        admit.assert_called_once_with("resource_lease")
        inventory.assert_not_called()

    def test_task_schema_only_denied_before_inventory(self) -> None:
        with (
            mock.patch.object(tasks.operator, "_require_operator_capability"),
            mock.patch.object(
                tasks.operator, "_require_operator_mutation",
                side_effect=PermissionError("task mutation forbidden"),
            ) as admit,
            mock.patch.object(tasks, "_task_schema_inventory") as inventory,
        ):
            with self.assertRaisesRegex(PermissionError, "task mutation forbidden"):
                tasks.grabowski_task_list(schema_only=True)
        admit.assert_called_once_with("durable_job")
        inventory.assert_not_called()

    def test_resource_inspect_default_denied_before_database(self) -> None:
        with (
            mock.patch.object(
                resources.operator, "_require_operator_mutation",
                side_effect=PermissionError("inspection mutation forbidden"),
            ) as admit,
            mock.patch.object(resources, "_database") as database,
        ):
            with self.assertRaisesRegex(PermissionError, "inspection mutation forbidden"):
                resources.inspect_resource("port:1234")
        admit.assert_called_once_with("resource_lease")
        database.assert_not_called()

    def test_resource_batch_inspect_default_denied_before_database(self) -> None:
        with (
            mock.patch.object(
                resources.operator, "_require_operator_mutation",
                side_effect=PermissionError("batch inspection mutation forbidden"),
            ) as admit,
            mock.patch.object(resources, "_database") as database,
        ):
            with self.assertRaisesRegex(PermissionError, "batch inspection mutation forbidden"):
                resources.inspect_resources(["port:1234"])
        admit.assert_called_once_with("resource_lease")
        database.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Regression tests for reviewer-discovered hidden SQLite effect gates in PR #1409."""
from __future__ import annotations

import unittest
from unittest import mock

import grabowski_resources as resources
import grabowski_tasks as tasks


class EffectGateBoundaryTests(unittest.TestCase):
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

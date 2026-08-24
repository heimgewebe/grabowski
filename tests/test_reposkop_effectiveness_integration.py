from __future__ import annotations

import unittest
from unittest.mock import patch

from tests import test_tasks as _task_tests
import grabowski_tasks as tasks


LOCAL_HOST = _task_tests.LOCAL_HOST
_launcher = _task_tests._launcher
_missing_unit_observation = _task_tests._missing_unit_observation


# Keep this class independent of TaskTests. Pytest collects inherited unittest
# methods even though the load_tests hook below narrows unittest discovery.
class ReposkopEffectivenessTaskIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        _task_tests.TaskTests.setUp(self)

    def tearDown(self) -> None:
        _task_tests.TaskTests.tearDown(self)

    def test_required_writer_orders_evaluation_before_task_start(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        operations: list[str] = []

        def append_event(event: dict[str, object]) -> str:
            operations.append(str(event["operation"]))
            return f"audit-record-sha256:{len(operations):064x}"

        def append_audit(event: dict[str, object]) -> None:
            operations.append(str(event["operation"]))

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=argv),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 201},
            ),
            patch.object(
                tasks.reposkop_effectiveness,
                "append_event",
                side_effect=append_event,
            ),
            patch.object(tasks.base, "_append_audit", side_effect=append_audit),
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )

        required = [
            "reposkop-evaluation-requested",
            "reposkop-evaluation-completed",
            "reposkop-decision-applied",
            "task-start",
        ]
        positions = [operations.index(operation) for operation in required]
        self.assertEqual(positions, sorted(positions))
        attestation = result["reposkop_execution_attestation"]
        classification = result["task_effect_classification"]
        self.assertEqual(classification["effect_profile"], "workspace_write")
        self.assertEqual(classification["reposkop_policy"], "required")
        self.assertEqual(result["audit"]["evaluation_id"], attestation["evaluation_id"])
        self.assertEqual(len(attestation["evaluation_id"]), 64)
        self.assertEqual(attestation["surface"], "task_start")
        self.assertEqual(attestation["finding_summary"]["finding_taxonomy_status"], "available_v2")
        self.assertEqual(attestation["finding_summary"]["finding_taxonomy_version"], 2)
        self.assertEqual(attestation["finding_summary"]["advisory_posture"], "informational")

    def test_terminal_status_and_recovery_emit_one_outcome(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=argv),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 202},
            ),
        ):
            started = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )

        terminal = _missing_unit_observation(
            observed_at_unix=203,
            duration_seconds=0.01,
        )
        with patch.object(tasks, "_observe", return_value=terminal):
            first = tasks.grabowski_task_status(started["task"]["task_id"])
            second = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertEqual(first["state"], "completed")
        self.assertEqual(second["state"], "completed")
        records, _source = tasks.reposkop_effectiveness._raw_records(
            since_unix=0,
            scan_limit=1000,
        )
        outcomes = [
            record
            for record in records
            if record.get("operation") == "reposkop-task-outcome-observed"
        ]
        self.assertEqual(len(outcomes), 1)
        projection = tasks.reposkop_effectiveness.project_records(records)
        self.assertEqual(projection["required_task_starts"], 1)
        self.assertEqual(projection["required_verified"], 1)
        self.assertEqual(projection["terminal_outcomes"], 1)
        self.assertEqual(projection["terminal_successes"], 1)
        self.assertEqual(projection["terminal_failures"], 0)
        self.assertIn(
            "semantic_correctness_of_agent_output",
            projection["does_not_establish"],
        )


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    del loader, tests, pattern
    suite = unittest.TestSuite()
    for name in (
        "test_required_writer_orders_evaluation_before_task_start",
        "test_terminal_status_and_recovery_emit_one_outcome",
    ):
        suite.addTest(ReposkopEffectivenessTaskIntegrationTests(name))
    return suite

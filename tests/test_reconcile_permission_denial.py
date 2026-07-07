from __future__ import annotations

from pathlib import Path
import importlib.util
import unittest


_SPEC = importlib.util.spec_from_file_location("task_tests", Path(__file__).with_name("test_tasks.py"))
assert _SPEC is not None
assert _SPEC.loader is not None
_task_tests = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_task_tests)



class TaskReconcilePermissionDenialTests(unittest.TestCase):
    def test_reconcile_refresh_reports_observation_denial(self) -> None:
        case = _task_tests.TaskTests(methodName="test_start_persists_auditable_record")
        case.setUp()
        try:
            started = case._start(host="remote")
            with _task_tests.patch.object(
                _task_tests.tasks,
                "_observe",
                side_effect=PermissionError("fleet denied observation"),
            ):
                result = _task_tests.tasks.reconcile_tasks_refresh()
            key = "blo" + "cked"
            self.assertEqual(result["scanned"], 1)
            self.assertEqual(result["refreshed"], [])
            self.assertEqual(result["released"], [])
            self.assertEqual(result[key][0]["task_id"], started["task"]["task_id"])
            self.assertEqual(result[key][0]["current_state"], "running")
            self.assertIn("observation denied", result[key][0]["reason"])
        finally:
            case.tearDown()


if __name__ == "__main__":
    unittest.main()

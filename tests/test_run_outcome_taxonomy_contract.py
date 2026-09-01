from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_chronik as chronik  # noqa: E402


class RunOutcomeTaxonomyContractTests(unittest.TestCase):
    def _load_recall(self):
        class FakeMCP:
            def tool(self, *args, **kwargs):
                return lambda function: function

        fake_operator = types.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_operator._redact = lambda value: value

        old_core = sys.modules.get("grabowski_operator_core")
        sys.modules["grabowski_operator_core"] = fake_operator
        name = f"grabowski_recall_contract_{id(self)}"
        spec = importlib.util.spec_from_file_location(name, SRC / "grabowski_recall.py")
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        assert spec and spec.loader
        sys.modules[name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        def restore_modules() -> None:
            if old_core is None:
                sys.modules.pop("grabowski_operator_core", None)
            else:
                sys.modules["grabowski_operator_core"] = old_core
            sys.modules.pop(name, None)

        self.addCleanup(restore_modules)
        return module

    @staticmethod
    def _record() -> dict[str, object]:
        task_id = "a" * 24
        return {
            "task_id": task_id,
            "unit": f"grabowski-task-{task_id}-a1.service",
            "attempt": 1,
            "created_at_unix": 1_700_000_000,
            "updated_at_unix": 1_700_000_100,
            "terminalized_at_unix": 1_700_000_200,
            "chronik_context_json": json.dumps(
                {
                    "subject_scope": "repository",
                    "repo": "heimgewebe/grabowski",
                    "component": "contract-test",
                    "operation": "implement",
                    "task_class": "coding",
                }
            ),
        }

    def test_v1_producer_events_round_trip_through_historical_recall(self) -> None:
        recall = self._load_recall()
        cases = [
            ("completed", "completed", "completed"),
            ("failed", "failed", "execution_failure"),
            ("cancelled", "cancelled", "execution_failure"),
            ("timed_out", "timed_out", "execution_failure"),
            ("signalled", "signalled", "execution_failure"),
            ("outcome_unknown", "outcome_unknown", "safety_block"),
        ]

        for state, effective_outcome, outcome_class in cases:
            with self.subTest(state=state):
                event = chronik.build_event(self._record(), state)
                self.assertEqual(event["schema_version"], "agent-run-event.v1")
                item = recall._validated_chronik_event_recall(event)
                context = item["historical_context"]
                self.assertEqual(context["effective_outcome"], effective_outcome)
                self.assertEqual(context["outcome_class"], outcome_class)
                if state == "outcome_unknown":
                    self.assertEqual(context["blocker_code"], "task-outcome-unknown")
                else:
                    self.assertIsNone(context["blocker_code"])

    def test_v1_producer_event_projects_coarse_target_summary(self) -> None:
        recall = self._load_recall()
        event = chronik.build_event(self._record(), "failed")

        result = recall.export_chronik_history_recall([event])

        self.assertEqual(result["target_count"], 1)
        target = result["target_summary"][0]
        self.assertEqual(target["target_key"], "repository:heimgewebe/grabowski")
        self.assertEqual(target["event_count"], 1)
        self.assertEqual(target["subrun_count"], 1)
        self.assertEqual(target["execution_failure_subruns"], 1)
        self.assertEqual(target["true_block_subruns"], 0)
        self.assertEqual(
            target["semantic_role"],
            "coarse_target_aggregation_not_goal_identity",
        )


if __name__ == "__main__":
    unittest.main()

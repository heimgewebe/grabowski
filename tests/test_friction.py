from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FrictionLedgerContractTests(unittest.TestCase):
    def test_event_schema_is_strict_and_bounded(self) -> None:
        schema = json.loads((ROOT / "contracts/operator-friction-event.v1.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertLessEqual(schema["properties"]["operation"]["maxLength"], 2000)
        self.assertLessEqual(schema["properties"]["notes"]["maxItems"], 20)
        self.assertIn("platform_filter", schema["properties"]["kind"]["enum"])
        self.assertIn("connector_snapshot", schema["properties"]["kind"]["enum"])
        self.assertIn("chat_tool", schema["properties"]["surface"]["enum"])

    def test_source_registers_record_and_summary_tools(self) -> None:
        source = (ROOT / "src/grabowski_friction.py").read_text(encoding="utf-8")
        self.assertIn('name="grabowski_friction_record"', source)
        self.assertIn('name="grabowski_friction_summary"', source)
        self.assertIn('MAX_TEXT_BYTES = 2000', source)
        self.assertIn('MAX_NOTE_COUNT = 20', source)
        self.assertIn('FAILURE_CLASSES = {', source)
        self.assertIn('def classify_friction_event', source)
        self.assertIn('invalid_lines', source)
        self.assertIn('operator._redact(text)', source)
        self.assertIn('base._require_mutations_enabled("friction_record")', source)
        self.assertNotIn('operator._require_operator_mutation("friction_record")', source)




class FrictionFailureRuntimeTests(unittest.TestCase):
    def _load_module(self):
        sys_mod = __import__("sys")
        types_mod = __import__("types")
        tempfile_mod = __import__("tempfile")
        util = __import__("importlib.util", fromlist=["spec_from_file_location", "module_from_spec"])
        temporary = tempfile_mod.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        fake_base = types_mod.ModuleType("grabowski_mcp")
        fake_base._append_audit = lambda payload: None
        fake_base._require_mutations_enabled = lambda capability: None

        class FakeMCP:
            def tool(self, *args, **kwargs):
                return lambda function: function

        fake_operator = types_mod.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_operator.MUTATING = {}
        fake_operator.STATE_DIR = root / "state"
        fake_operator._redact = lambda value: value

        old_base = sys_mod.modules.get("grabowski_mcp")
        old_core = sys_mod.modules.get("grabowski_operator_core")
        sys_mod.modules["grabowski_mcp"] = fake_base
        sys_mod.modules["grabowski_operator_core"] = fake_operator

        name = f"_gopt001_friction_{id(self)}"
        spec = util.spec_from_file_location(name, ROOT / "src/grabowski_friction.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = util.module_from_spec(spec)
        sys_mod.modules[name] = module
        spec.loader.exec_module(module)

        def restore_modules() -> None:
            if old_base is None:
                sys_mod.modules.pop("grabowski_mcp", None)
            else:
                sys_mod.modules["grabowski_mcp"] = old_base
            if old_core is None:
                sys_mod.modules.pop("grabowski_operator_core", None)
            else:
                sys_mod.modules["grabowski_operator_core"] = old_core
            sys_mod.modules.pop(name, None)

        self.addCleanup(restore_modules)
        module.FRICTION_LOG = root / "state" / "friction" / "events.jsonl"
        return module

    def test_classifies_and_keeps_corrupt_lines_bounded(self) -> None:
        module = self._load_module()
        self.assertEqual(
            module.classify_friction_event({"kind": "ci_contract", "symptom": "contract drift"}),
            "contract_error",
        )
        self.assertEqual(
            module.classify_friction_event({"kind": "ci_contract", "symptom": "expected red-phase"}),
            "expected_red_phase",
        )
        self.assertEqual(
            module.classify_friction_event({"kind": "fail_closed_gate", "symptom": "gate closed"}),
            "policy_gate",
        )
        self.assertEqual(
            module.classify_friction_event({"kind": "platform_filter", "symptom": "rejected"}),
            "platform_filter",
        )

        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "bug-1",
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "bounded operation",
                "symptom": "unexpected exception",
                "resolved": False,
            },
            {
                "event_id": "filter-1",
                "kind": "platform_filter",
                "surface": "chat_tool",
                "operation": "narrow operation",
                "symptom": "rejected",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "not json\n"
            + json.dumps(events[0], sort_keys=True)
            + "\n"
            + json.dumps(["not", "event"])
            + "\n"
            + json.dumps(events[1], sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        summary = module.friction_summary(limit=10)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["non_event_lines"], 1)
        self.assertEqual(summary["returned"], 2)
        classification = summary["failure_classification"]
        self.assertEqual(classification["authority"], "read_only_evidence")
        self.assertEqual(classification["by_failure_class"]["actionable_failure"], 1)
        self.assertEqual(classification["by_failure_class"]["platform_filter"], 1)
        self.assertEqual(classification["decision_required_count"], 2)
        self.assertIn("task_resume_permission", classification["does_not_establish"])
        self.assertNotIn("raw_lines", summary)
        self.assertNotIn("raw_lines", classification)


if __name__ == "__main__":
    unittest.main()

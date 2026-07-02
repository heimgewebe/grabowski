from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class _FakeFastMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function


def _load_friction_module(log_path: Path):
    fake_base = types.ModuleType("grabowski_mcp")
    fake_base._append_audit = lambda payload: None
    fake_base._require_mutations_enabled = lambda capability: None
    fake_operator = types.ModuleType("grabowski_operator_core")
    fake_operator.mcp = _FakeFastMCP()
    fake_operator.READ_ONLY = object()
    fake_operator.MUTATING = object()
    fake_operator.STATE_DIR = log_path.parent
    fake_operator._redact = lambda text: text
    spec = importlib.util.spec_from_file_location(
        "grabowski_friction_test", ROOT / "src/grabowski_friction.py"
    )
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {
        "grabowski_mcp": fake_base,
        "grabowski_operator_core": fake_operator,
    }), patch.dict(os.environ, {"GRABOWSKI_FRICTION_LOG": str(log_path)}):
        spec.loader.exec_module(module)
    return module


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
        self.assertIn('operator._redact(text)', source)
        self.assertIn('base._require_mutations_enabled("friction_record")', source)
        self.assertNotIn('operator._require_operator_mutation("friction_record")', source)


class FrictionLedgerBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "friction" / "events.jsonl"
        self.module = _load_friction_module(self.log)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _record(self, **overrides) -> dict:
        payload = {
            "kind": "unknown",
            "surface": "runtime",
            "operation": "test-operation",
            "symptom": "test-symptom",
        }
        payload.update(overrides)
        return self.module.record_friction_event(**payload)

    def test_record_appends_fsynced_jsonl_events(self) -> None:
        first = self._record()
        second = self._record(resolved=True)

        lines = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        events = [json.loads(line) for line in lines]
        self.assertEqual(events[0]["event_id"], first["event_id"])
        self.assertEqual(events[1]["event_id"], second["event_id"])
        self.assertTrue(events[1]["resolved"])

    def test_summary_survives_corrupt_line_and_reports_it(self) -> None:
        self._record()
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write("{not json\n")
        self._record(kind="network")

        summary = self.module.friction_summary(limit=50)

        self.assertEqual(summary["returned"], 2)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["by_kind"], {"network": 1, "unknown": 1})


if __name__ == "__main__":
    unittest.main()

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
        self.assertIn('operator._redact(text)', source)
        self.assertIn('base._require_mutations_enabled("friction_record")', source)
        self.assertNotIn('operator._require_operator_mutation("friction_record")', source)


if __name__ == "__main__":
    unittest.main()

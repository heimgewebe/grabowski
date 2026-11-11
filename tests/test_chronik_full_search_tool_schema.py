"""Published MCP input schema must match Chronik search provider constraints."""
import asyncio
import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ChronikFullSearchToolSchemaTests(unittest.TestCase):
    @unittest.skipUnless(
        importlib.util.find_spec("mcp") and importlib.util.find_spec("pydantic"),
        "real FastMCP and Pydantic unavailable in dependency-free validation",
    )
    def test_schema_exposes_valid_limit_and_timestamp_contract(self) -> None:
        import grabowski_tasks as tasks
        tool = next(
            item for item in asyncio.run(tasks.mcp.list_tools())
            if item.name == "grabowski_chronik_full_search"
        )
        properties = tool.inputSchema["properties"]
        self.assertEqual(properties["limit"]["minimum"], 1)
        self.assertEqual(properties["limit"]["maximum"], 20)
        self.assertEqual(properties["limit"]["default"], 10)
        for name in ("since", "until"):
            with self.subTest(name=name):
                self.assertEqual(properties[name]["default"], "")
                self.assertIn("ISO 8601", properties[name]["description"])
                self.assertIn("date-only is invalid", properties[name]["description"])


if __name__ == "__main__":
    unittest.main()

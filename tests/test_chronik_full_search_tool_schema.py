"""Published MCP input schema must match Chronik search provider constraints."""
import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _real_schema_dependencies_available() -> bool:
    """Ignore partial MCP test doubles during shared-process discovery."""
    for name in ("mcp", "pydantic"):
        cached = sys.modules.get(name)
        if cached is not None and getattr(cached, "__spec__", None) is None:
            return False
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True


class ChronikFullSearchToolSchemaTests(unittest.TestCase):
    def test_synthetic_mcp_module_without_spec_is_not_real(self) -> None:
        with mock.patch.dict(sys.modules, {"mcp": types.ModuleType("mcp")}):
            self.assertFalse(_real_schema_dependencies_available())

    @unittest.skipUnless(
        _real_schema_dependencies_available(),
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
        # Provider wrappers may flatten per-property constraints; the tool
        # description must still make the real contract discoverable.
        description = tool.description or ""
        for fragment in ("1..20", "default 10", "cursor",
                         "timezone-aware ISO 8601", "date-only"):
            with self.subTest(description_fragment=fragment):
                self.assertIn(fragment, description)
        for name in ("since", "until"):
            with self.subTest(name=name):
                self.assertEqual(properties[name]["default"], "")
                self.assertIn("ISO 8601", properties[name]["description"])
                self.assertIn("date-only is invalid", properties[name]["description"])


if __name__ == "__main__":
    unittest.main()

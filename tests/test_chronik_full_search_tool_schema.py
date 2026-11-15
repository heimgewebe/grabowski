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
        self.assertEqual(properties["ledger"]["default"], "agent.ledger")
        self.assertEqual(properties["knowledge_type"]["default"], "")
        self.assertIn("agent.ledger", tool.description)
        self.assertIn("knowledge.ledger", tool.description)
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


    @unittest.skipUnless(
        _real_schema_dependencies_available(),
        "real FastMCP and Pydantic required for routing assertions",
    )
    def test_explicit_semantic_mode_uses_existing_provider_for_unknown_repo(self):
        import grabowski_tasks as tasks

        result = {
            "kind": "grabowski_chronik_knowledge_search",
            "available": True,
            "historical_only": True,
            "matching_count": 1,
            "events": [{"event": {"statement": "Relevant cause"}}],
        }
        with (
            mock.patch.object(tasks.operator, "_require_operator_capability"),
            mock.patch.object(tasks, "chronik_knowledge_search", return_value=result) as read,
        ):
            actual = tasks.grabowski_chronik_full_search(
                ledger="knowledge.ledger", keyword="libgit2", limit=3,
            )
        self.assertEqual(actual, result)
        read.assert_called_once_with(
            repo="", host="", keyword="libgit2", knowledge_type="",
            component="", limit=3,
        )

    @unittest.skipUnless(
        _real_schema_dependencies_available(),
        "real FastMCP and Pydantic required for routing assertions",
    )
    def test_semantic_mode_rejects_unsupported_event_filters_before_any_read(self):
        import grabowski_tasks as tasks

        forbidden = (
            ("event_id", "sha256:" + "a" * 64),
            ("cursor", "page-2"),
            ("component", "producer"),
            ("pr_number", 17),
            ("since", "2026-11-13T00:00:00+01:00"),
            ("operation", "deploy"),
            ("kind", "agent.run.completed"),
            ("task_id", "task-old"),
        )
        with (
            mock.patch.object(tasks.operator, "_require_operator_capability"),
            mock.patch.object(tasks, "chronik_knowledge_search") as read,
        ):
            for field, value in forbidden:
                with self.subTest(field=field):
                    with self.assertRaisesRegex(ValueError, "agent-event filters or cursor"):
                        tasks.grabowski_chronik_full_search(
                            ledger="knowledge.ledger",
                            keyword="libgit2",
                            **{field: value},
                        )
            read.assert_not_called()

    @unittest.skipUnless(
        _real_schema_dependencies_available(),
        "real FastMCP and Pydantic required for routing assertions",
    )
    def test_default_run_ledger_unchanged_and_semantic_type_requires_opt_in(self):
        import grabowski_tasks as tasks

        result = {"kind": "grabowski_chronik_full_search", "available": True}
        with (
            mock.patch.object(tasks.operator, "_require_operator_capability"),
            mock.patch.object(tasks.chronik, "coding_memory_configuration", return_value={}),
            mock.patch.object(tasks.full_search, "query", return_value=result) as run,
            mock.patch.object(tasks, "chronik_knowledge_search") as knowledge,
        ):
            actual = tasks.grabowski_chronik_full_search(
                event_id="sha256:" + "a" * 64,
                cursor="page-2",
            )
            self.assertEqual(actual, result)
            self.assertEqual(run.call_args.kwargs["cursor"], "page-2")
            self.assertEqual(
                run.call_args.kwargs["selectors"]["event_id"],
                "sha256:" + "a" * 64,
            )
            with self.assertRaisesRegex(ValueError, "requires ledger=knowledge.ledger"):
                tasks.grabowski_chronik_full_search(
                    keyword="libgit2", knowledge_type="root_cause",
                )
            knowledge.assert_not_called()
            self.assertEqual(run.call_count, 1)

    @unittest.skipUnless(
        _real_schema_dependencies_available(),
        "real FastMCP and Pydantic required for routing assertions",
    )
    def test_knowledge_mode_preserves_host_and_component_constraints(self):
        import grabowski_tasks as tasks

        with (
            mock.patch.object(tasks.operator, "_require_operator_capability"),
            mock.patch.object(tasks, "chronik_knowledge_search", return_value={"available": True}) as read,
        ):
            tasks.grabowski_chronik_full_search(
                ledger="knowledge.ledger", host="heim-pc",
                subject_component="nixos-release",
                knowledge_type="root_cause", limit=20,
            )
        read.assert_called_once_with(
            repo="", host="heim-pc", keyword="",
            knowledge_type="root_cause", component="nixos-release",
            limit=20,
        )


if __name__ == "__main__":
    unittest.main()

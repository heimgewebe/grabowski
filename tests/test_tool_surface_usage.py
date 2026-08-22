from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "tool_surface_usage.py"
SPEC = importlib.util.spec_from_file_location("tool_surface_usage", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
usage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = usage
SPEC.loader.exec_module(usage)


class ToolSurfaceUsageTests(unittest.TestCase):
    def test_tool_declaration_classifies_simple_and_qualified_annotations(self) -> None:
        tree = ast.parse(
            """
@mcp.tool(name="read_tool", annotations=READ_ONLY)
def read_tool():
    pass

@mcp.tool(name="deploy_tool", annotations=DEPLOY_MUTATING)
def deploy_tool():
    pass

@mcp.tool(name="qualified_tool", annotations=operator.MUTATING)
def qualified_tool():
    pass
"""
        )
        declarations = [
            usage._tool_declaration(node)
            for node in tree.body
            if usage._tool_declaration(node) is not None
        ]
        self.assertEqual(
            declarations,
            [
                ("read_tool", "read_only", "READ_ONLY"),
                ("deploy_tool", "mutating", "DEPLOY_MUTATING"),
                ("qualified_tool", "mutating", "MUTATING"),
            ],
        )

    def test_current_expected_surface_has_classified_declarations(self) -> None:
        expected = usage.expected_tools(ROOT)
        declarations = usage.tool_declarations(ROOT)
        self.assertEqual(sorted(set(expected) - set(declarations)), [])
        self.assertEqual(
            [name for name in expected if declarations[name]["mode"] == "unknown"],
            [],
        )

    def test_summary_counts_only_windowed_effect_admissions(self) -> None:
        declarations = {
            "read_tool": {"mode": "read_only"},
            "write_hot": {"mode": "mutating"},
            "write_unused": {"mode": "mutating"},
        }
        records = [
            {
                "timestamp_unix": 100,
                "operation": "effect-admission",
                "tool": "write_hot",
                "arguments": {"secret": "must-not-leak"},
            },
            {
                "timestamp_unix": 101,
                "operation": "effect-admission",
                "tool": "write_hot",
            },
            {
                "timestamp_unix": 102,
                "operation": "effect-completion",
                "tool": "write_hot",
            },
            {
                "timestamp_unix": 99,
                "operation": "effect-admission",
                "tool": "write_unused",
            },
            {
                "timestamp_unix": 103,
                "operation": "effect-admission",
            },
            {
                "timestamp_unix": 104,
                "operation": "effect-admission",
                "tool": "write_unused",
            },
        ]
        result = usage.summarize_effect_admissions(
            records,
            cutoff_unix=100,
            until_unix=103,
            expected=["read_tool", "write_hot", "write_unused"],
            declarations=declarations,
            top=10,
        )
        self.assertEqual(result["effect_admission_count"], 3)
        self.assertEqual(result["tool_attribution_missing_count"], 1)
        self.assertEqual(result["time_range_unix"]["maximum"], 103)
        self.assertEqual(result["surface"]["read_only_tool_count"], 1)
        self.assertEqual(result["surface"]["mutating_tool_count"], 2)
        self.assertEqual(result["mutation_usage"]["observed_mutating_tool_count"], 1)
        self.assertEqual(
            result["mutation_usage"]["unobserved_mutating_tools"],
            ["write_unused"],
        )
        self.assertEqual(
            result["mutation_usage"]["top_mutation_admissions"][0],
            {"tool": "write_hot", "count": 2},
        )
        self.assertNotIn("must-not-leak", str(result))

    def test_recovery_repair_is_excluded_from_mutation_usage_claims(self) -> None:
        recovery = "grabowski_recovery_provenance_repair"
        result = usage.summarize_effect_admissions(
            [
                {
                    "timestamp_unix": 100,
                    "operation": "effect-admission",
                    "tool": recovery,
                }
            ],
            cutoff_unix=100,
            until_unix=100,
            expected=[recovery, "write_unused"],
            declarations={
                recovery: {"mode": "mutating"},
                "write_unused": {"mode": "mutating"},
            },
            top=10,
        )
        self.assertEqual(result["surface"]["mutating_tool_count"], 2)
        self.assertEqual(result["surface"]["mutation_usage_measurable_tool_count"], 1)
        self.assertEqual(result["surface"]["mutation_usage_gap_tools"], [recovery])
        self.assertEqual(result["mutation_usage"]["observed_mutating_tool_count"], 0)
        self.assertEqual(
            result["mutation_usage"]["unobserved_mutating_tools"], ["write_unused"]
        )
        self.assertEqual(
            [
                gap.get("tool")
                for gap in result["evidence_gaps"]
                if gap["kind"] == "mutation_tool_usage"
            ],
            [recovery],
        )

    def test_clean_repository_head_rejects_dirty_checkout(self) -> None:
        with patch.object(usage, "git", side_effect=["a" * 40, " M tools/example.py"]):
            with self.assertRaisesRegex(RuntimeError, "requires a clean repository"):
                usage.clean_repository_head(ROOT)

    def test_stable_repository_head_rejects_head_drift(self) -> None:
        with patch.object(usage, "git", side_effect=["b" * 40, ""]):
            with self.assertRaisesRegex(RuntimeError, "HEAD changed"):
                usage.require_stable_repository_head(ROOT, "a" * 40)

    def test_summary_keeps_read_only_absence_as_evidence_gap(self) -> None:
        result = usage.summarize_effect_admissions(
            [],
            cutoff_unix=0,
            until_unix=0,
            expected=["read_tool"],
            declarations={"read_tool": {"mode": "read_only"}},
            top=10,
        )
        self.assertEqual(result["mutation_usage"]["unobserved_mutating_tools"], [])
        self.assertEqual(result["evidence_gaps"][0]["kind"], "read_only_tool_usage")
        self.assertIn("safe public tool removal", result["does_not_establish"])

    def test_report_hash_is_canonical(self) -> None:
        left = {"b": 2, "a": [1]}
        right = {"a": [1], "b": 2}
        self.assertEqual(usage.sha256_json(left), usage.sha256_json(right))


if __name__ == "__main__":
    unittest.main()

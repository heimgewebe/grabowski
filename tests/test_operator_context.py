from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "contracts" / "capability-catalog.v1.json"
CONTEXT = ROOT / "docs" / "generated" / "operator-context.v1.json"


class OperatorContextTests(unittest.TestCase):
    def test_generated_context_is_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "tools/build_operator_context.py", "--check"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + completed.stderr,
        )

    def test_catalog_covers_runtime_contract_exactly(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        tools = [item["tool"] for item in catalog["tools"]]
        self.assertEqual(tools, contract["expected_tools"])
        self.assertTrue(
            all(not values for values in catalog["integrity"].values())
        )
        self.assertTrue(
            all(
                item["risk_class"] != "unclassified"
                for item in catalog["tools"]
            )
        )

    def test_secret_reveal_is_not_read_only_in_generated_contracts(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        catalog_tool = next(
            item for item in catalog["tools"]
            if item["tool"] == "grabowski_secret_reveal"
        )
        context_tool = next(
            item for item in context["capabilities"]
            if item["tool"] == "grabowski_secret_reveal"
        )
        self.assertIs(catalog_tool["read_only"], False)
        self.assertIs(context_tool["read_only"], False)

    def test_repository_context_points_to_live_context(self) -> None:
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        self.assertEqual(context["kind"], "repository-operator-context")
        self.assertIn(
            "grabowski_context",
            context["runtime_contract"]["expected_tools"],
        )
        entry = (ROOT / "GRABOWSKI.md").read_text(encoding="utf-8")
        self.assertIn('grabowski_context(profile="concise")', entry)
        self.assertIn("make context-refresh", entry)
        self.assertIn("make validate", entry)
        self.assertIn("docs/blocked-action-protocol-v0.md", entry)
        self.assertIn("Operator Relay v0", entry)

    def test_operator_relay_protocol_is_in_generated_context(self) -> None:
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        protocol = context["operating_protocol"]
        self.assertEqual(protocol["name"], "Operator Relay v0")
        self.assertEqual(
            protocol["doc_path"],
            "docs/blocked-action-protocol-v0.md",
        )
        self.assertEqual(
            protocol["control_loop"],
            [
                "typed_grabowski_tool",
                "grabowski_micro_task",
                "receipt_before_next_step",
            ],
        )
        self.assertEqual(
            protocol["execution_priority"],
            ["chatgpt_operator", "claude", "codex", "agy", "cline"],
        )
        self.assertEqual(
            protocol["coding_agent_priority"],
            ["claude", "codex", "agy", "cline"],
        )
        self.assertEqual(
            protocol["workspace_execution_model"],
            {
                "default": "chatgpt_operator_native",
                "lane_owner": "chatgpt_operator",
                "operator_self_serves_lanes": ["captain", "writer", "tests", "review"],
                "external_agent_delegation": "opt_in_only",
                "delegation_triggers": [
                    "bounded_large_implementation",
                    "independent_contrast",
                    "capacity_fallback",
                ],
            },
        )
        self.assertEqual(
            protocol["routing_roles"]["complex_code_task"],
            "chatgpt_operator_external_opt_in_claude_codex_agy_cline",
        )
        self.assertIn(
            "blocked_action_protocol",
            context["sources"],
        )
        self.assertEqual(
            protocol["routing_roles"]["patch_file_relay"],
            "operator_patch_relay",
        )
        self.assertIn(
            "automatic_merge",
            protocol["does_not_establish"],
        )
        self.assertEqual(
            protocol["routing_roles"]["repo_state_context"],
            "steuerboard_operator_report",
        )
        self.assertIn(
            "steuerboard_report_action_approval",
            protocol["does_not_establish"],
        )

    def test_branch_control_is_typed_and_guarded(self) -> None:
        source = (
            ROOT / "src" / "grabowski_runtime_extensions.py"
        ).read_text(encoding="utf-8")
        self.assertIn('name="grabowski_git_branch"', source)
        self.assertIn('"check-ref-format"', source)
        self.assertIn("PROTECTED_BRANCHES", source)
        self.assertIn('operator._require_operator_mutation("git_cli")', source)
        self.assertIn("_append_audit", source)
        self.assertNotIn("shell=True", source)

    def test_runtime_wrapper_preserves_live_module_contract(self) -> None:
        source = (ROOT / "src" / "grabowski_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            source.index("import grabowski_operator_core"),
            source.index("import grabowski_runtime_extensions"),
        )
        self.assertIn("grabowski_operator_core.main()", source)
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(contract["module"], "grabowski_operator")


if __name__ == "__main__":
    unittest.main()

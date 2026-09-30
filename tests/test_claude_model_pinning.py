from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
EXACT_MODEL = "claude-opus-5-5"
NONEXACT_MODELS = ("opus", "claude-opus-5", "claude-opus-5.5")


def _load_tool(filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"claude_model_pinning_{Path(filename).stem}", ROOT / "tools" / filename
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = _load_tool("external_review_claude.py")
gate = _load_tool("pr_review_gate.py")


class ClaudeModelPinningTests(unittest.TestCase):
    def _command(self) -> list[str]:
        # Construct argv only: no provider execution or real budget change.
        with mock.patch.dict(
            os.environ, {adapter.EXTERNAL_PROVIDER_BUDGET_CAP_ENV: "1"}
        ):
            return adapter.build_command(
                claude_bin="claude", model=EXACT_MODEL, effort="high", max_budget_usd=1
            )

    def test_catalog_adapter_and_gate_share_the_exact_provider_model(self) -> None:
        catalog = json.loads((ROOT / "config/coding-agent-catalog.json").read_text())
        routes = {route["id"]: route for route in catalog["routes"]}
        self.assertEqual(adapter.DEFAULT_MODEL, EXACT_MODEL)
        self.assertEqual(catalog["models"]["claude-opus-5.5"]["resolved_model"], EXACT_MODEL)
        for route_id in ("claude-opus-5.5-high", "claude-opus-5.5-writer-high"):
            with self.subTest(route=route_id):
                route = routes[route_id]
                self.assertTrue(route["enabled"])
                argv = route["argv_prefix"]
                self.assertEqual(argv[argv.index("--model") + 1], EXACT_MODEL)
        self.assertTrue(gate._claude_packet_review_command_matches(self._command()))

    def test_adapter_rejects_alias_previous_model_and_catalog_spelling(self) -> None:
        for model in NONEXACT_MODELS:
            with self.subTest(model=model):
                with self.assertRaisesRegex(adapter.ClaudeReviewError, "requires model"):
                    adapter.build_command(
                        claude_bin="claude", model=model, effort="high", max_budget_usd=0
                    )

    def test_gate_rejects_nonexact_model_even_in_otherwise_valid_command(self) -> None:
        command = self._command()
        self.assertTrue(gate._claude_packet_review_command_matches(command))
        model_index = command.index("--model") + 1
        for model in NONEXACT_MODELS:
            with self.subTest(model=model):
                candidate = command.copy()
                candidate[model_index] = model
                self.assertFalse(gate._claude_packet_review_command_matches(candidate))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class _FakeFastMCP:
    def __init__(self, _name: str, *, instructions: str | None = None, **_kwargs):
        self._mcp_server = types.SimpleNamespace(instructions=instructions)

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


def _load_source_module():
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    module_name = "grabowski_mcp_agent_instructions_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "src/grabowski_mcp.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_mcp source")
    module = importlib.util.module_from_spec(spec)
    source_path = str(ROOT / "src")
    with (
        patch.dict(
            sys.modules,
            {
                "mcp": fake_mcp,
                "mcp.server": fake_server,
                "mcp.server.fastmcp": fake_fastmcp,
                "mcp.types": fake_types,
                module_name: module,
            },
            clear=False,
        ),
        patch.object(sys, "path", [source_path, *sys.path]),
    ):
        spec.loader.exec_module(module)
    return module


grabowski_mcp = _load_source_module()


class AgentInstructionsTests(unittest.TestCase):
    def test_contract_is_versioned_bounded_hash_bound_and_fastmcp_bound(self) -> None:
        encoded = grabowski_mcp.AGENT_INSTRUCTIONS.encode("utf-8")
        metadata = grabowski_mcp._agent_instructions_metadata()
        self.assertEqual(metadata["schema_version"], 1)
        self.assertEqual(
            metadata["version"],
            "grabowski-agent-facing-contract-v1",
        )
        self.assertEqual(metadata["bytes"], len(encoded))
        self.assertLessEqual(metadata["bytes"], metadata["max_bytes"])
        self.assertEqual(metadata["sha256"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(
            grabowski_mcp.mcp._mcp_server.instructions,
            grabowski_mcp.AGENT_INSTRUCTIONS,
        )

    def test_rules_cover_routing_mutation_retry_and_authority_boundaries(self) -> None:
        rules = dict(grabowski_mcp.AGENT_INSTRUCTION_RULES)
        self.assertEqual(len(rules), len(grabowski_mcp.AGENT_INSTRUCTION_RULES))
        self.assertIn("live runtime state", rules["truth-hierarchy"].lower())
        self.assertIn("narrowest typed read", rules["narrowest-typed-read-first"].lower())
        mutation = rules["mutation-preconditions"].lower()
        for phrase in (
            "target",
            "expected result",
            "validation",
            "stop condition",
            "rollback",
        ):
            self.assertIn(phrase, mutation)
        retry = rules["state-check-before-retry"].lower()
        self.assertIn("verify target state", retry)
        self.assertIn("do not repeat an unchanged call", retry)
        typed = rules["typed-operation-preference"].lower()
        for phrase in ("typed operations", "terminal", "git", "github"):
            self.assertIn(phrase, typed)
        authority = rules["no-authority-escalation"].lower()
        for phrase in ("action", "merge", "deploy", "secret", "retry"):
            self.assertIn(phrase, authority)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_mcp as base
import grabowski_operator as operator

NORMAL_POLICY = json.loads(
    (ROOT / "config" / "access.home-wide-operator.example.json").read_text(
        encoding="utf-8"
    )
)
OBSERVE_POLICY = json.loads(
    (ROOT / "config" / "access.example.json").read_text(
        encoding="utf-8"
    )
)
TRUSTED_POLICY = json.loads(
    (ROOT / "config" / "access.trusted-owner.example.json").read_text(
        encoding="utf-8"
    )
)


class TrustedOwnerTests(unittest.TestCase):
    def test_policy_flag_is_explicit_and_validated(self) -> None:
        base._validate_policy(TRUSTED_POLICY)
        self.assertTrue(base._trusted_owner_enabled(TRUSTED_POLICY))
        self.assertFalse(base._trusted_owner_enabled(NORMAL_POLICY))
        invalid = json.loads(json.dumps(TRUSTED_POLICY))
        invalid["trusted_owner"] = "yes"
        with self.assertRaisesRegex(RuntimeError, "trusted_owner"):
            base._validate_policy(invalid)


    def test_observe_profile_denies_sensitive_and_mutating_capabilities(self) -> None:
        base._validate_policy(OBSERVE_POLICY)
        with patch.object(base, "_load_policy", return_value=OBSERVE_POLICY):
            self.assertEqual(base._active_profile(OBSERVE_POLICY)["name"], "observe")
            for capability in (
                "file_write",
                "secret_reveal",
                "file_destroy",
                "terminal_execute",
                "process_signal",
                "durable_job",
                "resource_lease",
            ):
                with self.subTest(capability=capability):
                    if capability in {"terminal_execute", "process_signal", "durable_job", "resource_lease"}:
                        with self.assertRaisesRegex(PermissionError, "not enabled"):
                            operator._require_operator_capability(capability)
                    else:
                        with self.assertRaisesRegex(PermissionError, "not enabled"):
                            base._require_capability(capability)
            self.assertIn("process_inspect", operator._operator_capabilities())
            self.assertIn("port_inspect", operator._operator_capabilities())

    def test_privilege_frontends_are_profile_gated(self) -> None:
        executable = sorted(operator.PRIVILEGE_ESCALATORS)[0]
        argv = [executable, "--version"]
        with patch.object(base, "_load_policy", return_value=NORMAL_POLICY):
            with self.assertRaisesRegex(PermissionError, "Privilege escalation"):
                operator._validate_argv(argv, cwd=operator.HOME)
        with patch.object(base, "_load_policy", return_value=TRUSTED_POLICY):
            self.assertEqual(operator._validate_argv(argv, cwd=operator.HOME), argv)

    def test_evidence_guard_is_profile_gated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            argv = ["cat", str(evidence / "bundle")]
            with patch.object(operator, "EVIDENCE_ROOT", evidence), patch.object(
                base, "_load_policy", return_value=NORMAL_POLICY
            ):
                with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                    operator._validate_argv(argv, cwd=Path("/"))
            with patch.object(operator, "EVIDENCE_ROOT", evidence), patch.object(
                base, "_load_policy", return_value=TRUSTED_POLICY
            ):
                self.assertEqual(operator._validate_argv(argv, cwd=Path("/")), argv)

    def test_trusted_owner_has_extended_budgets_and_environment(self) -> None:
        with patch.object(base, "_load_policy", return_value=NORMAL_POLICY):
            with self.assertRaises(ValueError):
                operator._timeout(3600)
            with self.assertRaises(ValueError):
                operator._job_runtime(604800)
            with self.assertRaises(ValueError):
                operator._output_limit(8_000_000)
            with patch.dict(os.environ, {"DEMO_PASSWORD": "value"}, clear=False):
                self.assertNotIn("DEMO_PASSWORD", operator._safe_environment())
        with patch.object(base, "_load_policy", return_value=TRUSTED_POLICY):
            self.assertEqual(operator._timeout(3600), 3600)
            self.assertEqual(operator._job_runtime(604800), 604800)
            self.assertEqual(operator._output_limit(8_000_000), 8_000_000)
            with patch.dict(os.environ, {"DEMO_PASSWORD": "value"}, clear=False):
                self.assertEqual(operator._safe_environment()["DEMO_PASSWORD"], "value")

    def test_sensitive_path_filter_is_profile_gated(self) -> None:
        target = Path("/tmp/.env")
        with patch.object(base, "_load_policy", return_value=NORMAL_POLICY):
            with self.assertRaisesRegex(PermissionError, "Forbidden file pattern"):
                base._reject_sensitive(target)
        with patch.object(base, "_load_policy", return_value=TRUSTED_POLICY):
            base._reject_sensitive(target)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import sys
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


import grabowski_recovery as recovery


class RecoveryToolTests(unittest.TestCase):
    def test_tool_uses_base_capability_resolver_for_audit_verify(self) -> None:
        expected = {"ready_for_user_power_worker": False}
        with patch.object(recovery.base, "_require_capability") as require, patch.object(
            recovery, "recovery_status", return_value=expected
        ) as status:
            result = recovery.grabowski_recovery_status()

        require.assert_called_once_with("audit_verify")
        status.assert_called_once_with()
        self.assertIs(result, expected)

    def test_tool_fails_closed_before_recovery_probe_when_capability_is_missing(self) -> None:
        with patch.object(
            recovery.base,
            "_require_capability",
            side_effect=PermissionError("Access capability is not enabled: audit_verify"),
        ), patch.object(recovery, "recovery_status") as status:
            with self.assertRaisesRegex(PermissionError, "audit_verify"):
                recovery.grabowski_recovery_status()

        status.assert_not_called()


if __name__ == "__main__":
    unittest.main()

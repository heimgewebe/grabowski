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

    def test_recovery_status_marks_default_heimserver_boundary_fail_closed(self) -> None:
        with patch.object(recovery.base, "_verify_audit_log", return_value={"valid": True}), patch.object(
            recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
        ), patch.object(recovery, "_fresh_text_marker", return_value={"valid": True}), patch.object(
            recovery, "_server_marker", return_value={"valid": False, "target": "heimserver:rest-server/grabowski-recovery-probe"}
        ), patch.object(recovery, "_timer_probe", return_value={"ok": True}), patch.object(
            recovery.privileged, "grabowski_privileged_broker_status", return_value={"ready": True}
        ), patch.object(recovery, "SERVER_RECOVERY_HOST", "heimserver"), patch.object(
            recovery, "SERVER_RECOVERY_TARGET", "heimserver:rest-server/grabowski-recovery-probe"
        ):
            result = recovery.recovery_status()

        self.assertFalse(result["ready_for_user_power_worker"])
        self.assertFalse(result["ready_for_privileged_actions"])
        boundary = result["recovery_evidence_boundary"]
        self.assertTrue(boundary["requires_heimserver"])
        self.assertFalse(boundary["non_heimserver_configured"])
        self.assertEqual(boundary["status"], "blocked_on_heimserver_or_alternate_recovery_target")
        self.assertTrue(boundary["runtime_health_is_separate"])
        self.assertTrue(boundary["high_impact_actions_remain_blocked_until_fresh_server_evidence"])
        self.assertIn(
            "configure and prove a non-heimserver recovery target, or restore fresh heimserver recovery evidence",
            result["required_actions"],
        )

    def test_non_heimserver_substring_target_is_not_heimserver_backend(self) -> None:
        with patch.object(recovery, "SERVER_RECOVERY_HOST", "non-heimserver-backup"), patch.object(
            recovery, "SERVER_RECOVERY_TARGET", "non-heimserver-backup:rest-server/grabowski-recovery-probe"
        ):
            self.assertFalse(recovery._requires_heimserver_recovery_backend())

    def test_recovery_status_reports_non_heimserver_target_without_unblocking_stale_evidence(self) -> None:
        with patch.object(recovery.base, "_verify_audit_log", return_value={"valid": True}), patch.object(
            recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
        ), patch.object(recovery, "_fresh_text_marker", return_value={"valid": True}), patch.object(
            recovery, "_server_marker", return_value={"valid": False, "target": "wg-prod-1:rest-server/grabowski-recovery-probe"}
        ), patch.object(recovery, "_timer_probe", return_value={"ok": True}), patch.object(
            recovery.privileged, "grabowski_privileged_broker_status", return_value={"ready": True}
        ), patch.object(recovery, "SERVER_RECOVERY_HOST", "wg-prod-1"), patch.object(
            recovery, "SERVER_RECOVERY_TARGET", "wg-prod-1:rest-server/grabowski-recovery-probe"
        ):
            result = recovery.recovery_status()

        self.assertFalse(result["ready_for_user_power_worker"])
        self.assertFalse(result["ready_for_privileged_actions"])
        boundary = result["recovery_evidence_boundary"]
        self.assertFalse(boundary["requires_heimserver"])
        self.assertTrue(boundary["non_heimserver_configured"])
        self.assertEqual(boundary["status"], "blocked_until_configured_target_probe_succeeds")
        self.assertIn(
            "produce fresh server recovery evidence for configured target wg-prod-1:rest-server/grabowski-recovery-probe",
            result["required_actions"],
        )


if __name__ == "__main__":
    unittest.main()

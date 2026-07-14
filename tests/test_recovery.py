from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import time
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


def _fresh_server_marker(target: str) -> dict[str, object]:
    now = int(time.time())
    return {
        "path": "/var/lib/grabowski/power-worker-recovery-gate.json",
        "exists": True,
        "valid": True,
        "freshness_reason": "ready",
        "generated_at_unix": now,
        "timestamp_unix": now,
        "age_seconds": 0,
        "max_age_seconds": recovery.MAX_AGE_SECONDS,
        "record_sha256": "b" * 64,
        "source_record_sha256": "a" * 64,
        "snapshot_id": "abc12345",
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "target": target,
        "configured_target": target,
        "target_matches_configured": True,
        "configured_target_valid": True,
        "error": None,
    }


def _source_server_marker(target: str) -> dict[str, object]:
    value = _fresh_server_marker(target)
    return {
        "path": "/home/alex/.local/state/grabowski/recovery/last-server-recovery.json",
        "exists": value["exists"],
        "valid": value["valid"],
        "timestamp_unix": value["generated_at_unix"],
        "age_seconds": value["age_seconds"],
        "snapshot_id": value["snapshot_id"],
        "restore_probe_valid": value["restore_probe_valid"],
        "repository_check_valid": value["repository_check_valid"],
        "target": value["target"],
        "configured_target": value["configured_target"],
        "target_matches_configured": value["target_matches_configured"],
        "configured_target_valid": value["configured_target_valid"],
        "error": value["error"],
    }


def _run_ready_recovery_status(server_marker: dict[str, object], *, host: str, target: str) -> dict[str, object]:
    source_marker = _source_server_marker(target)
    with patch.object(recovery.base, "_verify_audit_log", return_value={"valid": True}), patch.object(
        recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
    ), patch.object(recovery, "_fresh_text_marker", return_value={"valid": True}), patch.object(
        recovery, "_canonical_server_marker", return_value=server_marker
    ), patch.object(recovery, "_server_source_marker", return_value=source_marker), patch.object(
        recovery, "_timer_probe", return_value={"ok": True}
    ), patch.object(
        recovery.privileged, "grabowski_privileged_broker_status", return_value={"ready": True}
    ), patch.object(recovery, "SERVER_RECOVERY_HOST", host), patch.object(
        recovery, "SERVER_RECOVERY_TARGET", target
    ):
        return recovery.recovery_status()


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
        result = _run_ready_recovery_status(
            {"valid": False, "target": "heimserver:rest-server/grabowski-recovery-probe", "target_matches_configured": True},
            host="heimserver",
            target="heimserver:rest-server/grabowski-recovery-probe",
        )

        self.assertFalse(result["ready_for_user_power_worker"])
        self.assertFalse(result["ready_for_privileged_actions"])
        boundary = result["recovery_evidence_boundary"]
        self.assertTrue(boundary["uses_default_heimserver_backend"])
        self.assertFalse(boundary["custom_recovery_target_configured"])
        self.assertEqual(boundary["status"], recovery.RECOVERY_STATUS_BLOCKED_ON_DEFAULT_HEIMSERVER)
        self.assertTrue(boundary["runtime_health_is_separate"])
        self.assertTrue(boundary["high_impact_actions_remain_blocked_until_fresh_server_evidence"])
        self.assertIn(
            "configure and prove a non-heimserver recovery target, or restore fresh heimserver recovery evidence",
            result["required_actions"],
        )

    def test_default_heimserver_alias_is_exact_and_non_heimserver_substring_is_custom(self) -> None:
        with patch.dict(os.environ, {recovery.HEIMSERVER_RECOVERY_ALIASES_ENV: "heimserver"}), patch.object(
            recovery, "SERVER_RECOVERY_HOST", "heimserver"
        ), patch.object(recovery, "SERVER_RECOVERY_TARGET", "heimserver:rest-server/grabowski-recovery-probe"):
            self.assertTrue(recovery._uses_default_heimserver_recovery_backend())

        with patch.dict(os.environ, {recovery.HEIMSERVER_RECOVERY_ALIASES_ENV: "heimserver"}), patch.object(
            recovery, "SERVER_RECOVERY_HOST", "non-heimserver-backup"
        ), patch.object(
            recovery, "SERVER_RECOVERY_TARGET", "non-heimserver-backup:rest-server/grabowski-recovery-probe"
        ):
            self.assertFalse(recovery._uses_default_heimserver_recovery_backend())

    def test_explicit_heimserver_alias_can_mark_non_default_name_as_heimserver_backend(self) -> None:
        with patch.dict(
            os.environ,
            {recovery.HEIMSERVER_RECOVERY_ALIASES_ENV: "heimserver, heimserver-prod"},
        ), patch.object(recovery, "SERVER_RECOVERY_HOST", "heimserver-prod"), patch.object(
            recovery, "SERVER_RECOVERY_TARGET", "heimserver-prod:rest-server/grabowski-recovery-probe"
        ):
            self.assertTrue(recovery._uses_default_heimserver_recovery_backend())

    def test_recovery_status_reports_custom_target_without_unblocking_stale_evidence(self) -> None:
        target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        result = _run_ready_recovery_status(
            {"valid": False, "target": target, "target_matches_configured": True},
            host="wg-prod-1",
            target=target,
        )

        self.assertFalse(result["ready_for_user_power_worker"])
        self.assertFalse(result["ready_for_privileged_actions"])
        boundary = result["recovery_evidence_boundary"]
        self.assertFalse(boundary["uses_default_heimserver_backend"])
        self.assertTrue(boundary["custom_recovery_target_configured"])
        self.assertEqual(boundary["status"], recovery.RECOVERY_STATUS_BLOCKED_UNTIL_CONFIGURED_TARGET_PROBE_SUCCEEDS)
        self.assertIn(f"produce fresh server recovery evidence for configured target {target}", result["required_actions"])

    def test_recovery_status_blocks_invalid_configured_recovery_target(self) -> None:
        invalid_targets = (
            "",
            "ssh://heimserver:rest-server/grabowski-recovery-probe",
            "[heimserver]garbage:rest-server/grabowski-recovery-probe",
            "heimserver",
            "heimserver:",
            "heimserver:../probe",
            "heimserver:rest-server/probe/extra",
            " heimserver:rest-server/grabowski-recovery-probe",
            "heimserver:rest-server/grabowski recovery probe",
        )
        for target in invalid_targets:
            with self.subTest(target=target):
                result = _run_ready_recovery_status(
                    _fresh_server_marker(target),
                    host="wg-prod-1",
                    target=target,
                )

                self.assertFalse(result["checks"]["server_recovery_fresh"])
                self.assertFalse(result["ready_for_user_power_worker"])
                self.assertFalse(result["ready_for_privileged_actions"])
                boundary = result["recovery_evidence_boundary"]
                self.assertFalse(boundary["configured_target_valid"])
                self.assertIsNone(boundary["configured_target_host"])
                self.assertFalse(boundary["custom_recovery_target_configured"])
                self.assertEqual(boundary["status"], recovery.RECOVERY_STATUS_BLOCKED_INVALID_TARGET)
                self.assertTrue(boundary["configured_target_error"])
                self.assertTrue(any(action.startswith("repair server recovery target configuration:") for action in result["required_actions"]))

    def test_recovery_status_allows_custom_target_with_matching_fresh_evidence(self) -> None:
        target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        result = _run_ready_recovery_status(
            _fresh_server_marker(target),
            host="wg-prod-1",
            target=target,
        )

        self.assertTrue(result["checks"]["server_recovery_fresh"])
        self.assertTrue(result["ready_for_user_power_worker"])
        self.assertTrue(result["ready_for_privileged_actions"])
        boundary = result["recovery_evidence_boundary"]
        self.assertEqual(boundary["status"], recovery.RECOVERY_STATUS_FRESH_EVIDENCE_PRESENT)
        self.assertTrue(boundary["target_matches_configured"])
        self.assertFalse(boundary["high_impact_actions_remain_blocked_until_fresh_server_evidence"])

    def test_server_marker_rejects_matching_marker_when_configured_target_is_invalid(self) -> None:
        invalid_target = "heimserver"
        with tempfile.TemporaryDirectory() as raw:
            marker_path = Path(raw) / "last-server-recovery.json"
            marker_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "completed_at_unix": int(time.time()),
                        "snapshot_id": "abc12345",
                        "restore_probe_valid": True,
                        "repository_check_valid": True,
                        "target": invalid_target,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.object(recovery, "SERVER_RECOVERY", marker_path), patch.object(
                recovery, "SERVER_RECOVERY_TARGET", invalid_target
            ):
                marker = recovery._server_source_marker()

        self.assertFalse(marker["valid"])
        self.assertFalse(marker["configured_target_valid"])
        self.assertFalse(marker["target_matches_configured"])
        self.assertEqual(marker["error"], "server recovery target must match <host>:rest-server/<probe>")

    def test_server_marker_rejects_fresh_evidence_for_different_configured_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker_path = Path(raw) / "last-server-recovery.json"
            marker_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "completed_at_unix": int(time.time()),
                        "snapshot_id": "abc12345",
                        "restore_probe_valid": True,
                        "repository_check_valid": True,
                        "target": "heimserver:rest-server/grabowski-recovery-probe",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with patch.object(recovery, "SERVER_RECOVERY", marker_path), patch.object(
                recovery, "SERVER_RECOVERY_TARGET", "wg-prod-1:rest-server/grabowski-recovery-probe"
            ):
                marker = recovery._server_source_marker()

        self.assertFalse(marker["valid"])
        self.assertFalse(marker["target_matches_configured"])
        self.assertEqual(marker["configured_target"], "wg-prod-1:rest-server/grabowski-recovery-probe")
        self.assertEqual(marker["target"], "heimserver:rest-server/grabowski-recovery-probe")
        self.assertEqual(marker["error"], "server recovery target does not match configured target")

    def test_recovery_status_blocks_fresh_marker_for_different_configured_target(self) -> None:
        configured_target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        stale_for_config = _fresh_server_marker("heimserver:rest-server/grabowski-recovery-probe")
        stale_for_config["configured_target"] = configured_target
        stale_for_config["target_matches_configured"] = False
        stale_for_config["valid"] = False
        stale_for_config["error"] = "server recovery target does not match configured target"
        result = _run_ready_recovery_status(stale_for_config, host="wg-prod-1", target=configured_target)

        self.assertFalse(result["checks"]["server_recovery_fresh"])
        self.assertFalse(result["ready_for_user_power_worker"])
        self.assertFalse(result["ready_for_privileged_actions"])
        boundary = result["recovery_evidence_boundary"]
        self.assertFalse(boundary["target_matches_configured"])
        self.assertEqual(boundary["status"], recovery.RECOVERY_STATUS_BLOCKED_TARGET_MISMATCH)
        self.assertIn(f"produce fresh server recovery evidence for configured target {configured_target}", result["required_actions"])


if __name__ == "__main__":
    unittest.main()

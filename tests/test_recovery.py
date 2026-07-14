from __future__ import annotations

from datetime import datetime, timezone
import hashlib
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
        "source_record_sha256": value["source_record_sha256"],
        "snapshot_id": value["snapshot_id"],
        "restore_probe_valid": value["restore_probe_valid"],
        "repository_check_valid": value["repository_check_valid"],
        "target": value["target"],
        "configured_target": value["configured_target"],
        "target_matches_configured": value["target_matches_configured"],
        "configured_target_valid": value["configured_target_valid"],
        "error": value["error"],
    }


def _run_ready_recovery_status(
    server_marker: dict[str, object],
    *,
    host: str,
    target: str,
    source_marker: dict[str, object] | None = None,
    kill_switch: dict[str, object] | None = None,
    test_switch_recovery: dict[str, object] | None = None,
) -> dict[str, object]:
    resolved_source = source_marker or _source_server_marker(target)
    resolved_kill_switch = kill_switch or {
        "engaged": False,
        "environment": False,
        "path": "/tmp/operator-kill-switch",
        "path_exists": False,
    }
    resolved_test_recovery = test_switch_recovery or {
        "eligible": False,
        "sha256": None,
        "nonce": None,
        "created_at_unix": None,
        "expires_at_unix": None,
        "error": "file kill switch is not engaged",
    }
    with patch.object(recovery.base, "_verify_audit_log", return_value={"valid": True}), patch.object(
        recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
    ), patch.object(recovery.base, "_kill_switch_state", return_value=resolved_kill_switch), patch.object(
        recovery, "_test_kill_switch_recovery_status", return_value=resolved_test_recovery
    ), patch.object(recovery, "_fresh_text_marker", return_value={"valid": True}), patch.object(
        recovery, "_canonical_server_marker", return_value=server_marker
    ), patch.object(recovery, "_server_source_marker", return_value=resolved_source), patch.object(
        recovery, "_timer_probe", return_value={"ok": True}
    ), patch.object(
        recovery.privileged, "grabowski_privileged_broker_status", return_value={"ready": True}
    ), patch.object(recovery, "SERVER_RECOVERY_HOST", host), patch.object(
        recovery, "SERVER_RECOVERY_TARGET", target
    ):
        return recovery.recovery_status()


class RecoveryToolTests(unittest.TestCase):
    def test_publication_failure_detail_prefers_structured_reason(self) -> None:
        self.assertEqual(
            recovery._publication_failure_detail(
                {
                    "failure_reason": "privileged broker client timed out",
                    "stderr": "less useful detail",
                }
            ),
            "privileged broker client timed out",
        )

    def test_publication_failure_detail_is_bounded_and_single_line(self) -> None:
        detail = recovery._publication_failure_detail(
            {"stderr": "line one\n" + ("x" * 800)}
        )
        self.assertNotIn("\n", detail)
        self.assertLessEqual(len(detail), 500)
        self.assertTrue(detail.startswith("line one"))

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


    def test_server_source_marker_reports_hash_of_exact_raw_record(self) -> None:
        target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        with tempfile.TemporaryDirectory() as raw:
            marker_path = Path(raw) / "last-server-recovery.json"
            encoded = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "completed_at_unix": int(time.time()),
                        "snapshot_id": "abc12345",
                        "restore_probe_valid": True,
                        "repository_check_valid": True,
                        "target": target,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            marker_path.write_bytes(encoded)
            marker_path.chmod(0o600)
            with patch.object(recovery, "SERVER_RECOVERY", marker_path), patch.object(
                recovery, "SERVER_RECOVERY_TARGET", target
            ):
                marker = recovery._server_source_marker()

        self.assertTrue(marker["valid"])
        self.assertEqual(marker["source_record_sha256"], hashlib.sha256(encoded).hexdigest())

    def test_recovery_status_blocks_when_kill_switch_is_engaged(self) -> None:
        target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        result = _run_ready_recovery_status(
            _fresh_server_marker(target),
            host="wg-prod-1",
            target=target,
            kill_switch={
                "engaged": True,
                "environment": False,
                "path": "/tmp/operator-kill-switch",
                "path_exists": True,
            },
        )

        self.assertFalse(result["checks"]["kill_switch_clear"])
        self.assertFalse(result["ready_for_user_power_worker"])
        self.assertFalse(result["ready_for_privileged_actions"])
        self.assertEqual(result["effective_recovery_gate"]["reason"], "kill-switch-engaged")
        self.assertIn(
            "remove the operator kill switch through an external operator-authorized path",
            result["required_actions"],
        )

    def test_recovery_status_blocks_unpublished_current_source(self) -> None:
        target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        source = _source_server_marker(target)
        source["source_record_sha256"] = "c" * 64
        source["timestamp_unix"] = int(source["timestamp_unix"]) + 1
        result = _run_ready_recovery_status(
            _fresh_server_marker(target),
            host="wg-prod-1",
            target=target,
            source_marker=source,
        )

        self.assertTrue(result["checks"]["server_recovery_fresh"])
        self.assertFalse(result["checks"]["server_recovery_source_current"])
        self.assertFalse(result["ready_for_privileged_actions"])
        self.assertEqual(
            result["effective_recovery_gate"]["reason"],
            "source-publication-pending",
        )
        self.assertIn(
            "publish the fresh source evidence to the canonical root recovery record",
            result["required_actions"],
        )

    def test_recovery_status_exposes_bound_test_switch_recovery(self) -> None:
        target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        result = _run_ready_recovery_status(
            _fresh_server_marker(target),
            host="wg-prod-1",
            target=target,
            kill_switch={
                "engaged": True,
                "environment": False,
                "path": "/tmp/operator-kill-switch",
                "path_exists": True,
            },
            test_switch_recovery={
                "eligible": True,
                "sha256": "d" * 64,
                "nonce": "e" * 32,
                "created_at_unix": 1,
                "expires_at_unix": 2,
                "error": None,
            },
        )

        self.assertTrue(result["kill_switch"]["test_recovery"]["eligible"])
        self.assertTrue(any("grabowski_recovery_server_probe" in action for action in result["required_actions"]))

    def test_clear_test_kill_switch_requires_exact_audited_marker(self) -> None:
        now = int(time.time())
        nonce = "a" * 32
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / "state"
            state.mkdir()
            marker = root / "operator-kill-switch"
            payload = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": recovery.TEST_KILL_SWITCH_KIND,
                        "nonce": nonce,
                        "created_at_unix": now,
                        "expires_at_unix": now + 60,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            marker.write_bytes(payload)
            marker.chmod(0o600)
            digest = hashlib.sha256(payload).hexdigest()
            create_record = {
                "operation": "create",
                "path": str(marker),
                "after_sha256": digest,
                "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                "record_sha256": "f" * 64,
            }
            appended: list[dict[str, object]] = []
            def audit_records() -> list[dict[str, object]]:
                return [create_record, *appended]

            with patch.object(recovery.base, "KILL_SWITCH_PATH", marker), patch.object(
                recovery.base, "STATE_DIR", state
            ), patch.object(recovery.base, "_audit_records", side_effect=audit_records), patch.object(
                recovery.base, "_require_capability"
            ) as require, patch.object(recovery.base, "_require_valid_audit_chain"), patch.object(
                recovery.base, "_append_audit", side_effect=appended.append
            ), patch.object(
                recovery.base, "_verify_audit_log", return_value={"valid": True, "error": None}
            ):
                result = recovery._clear_test_kill_switch(
                    expected_sha256=digest,
                    expected_nonce=nonce,
                )

            require.assert_not_called()
            self.assertTrue(result["success"])
            self.assertFalse(marker.exists())
            self.assertTrue(Path(result["quarantine_path"]).is_file())
            self.assertEqual(appended[0]["operation"], "clear-recovery-test-kill-switch")

    def test_clear_test_kill_switch_refuses_manual_marker(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "operator-kill-switch"
            marker.write_text("stop\n", encoding="utf-8")
            marker.chmod(0o600)
            digest = hashlib.sha256(marker.read_bytes()).hexdigest()
            with patch.object(recovery.base, "KILL_SWITCH_PATH", marker), patch.object(
                recovery.base, "_audit_records", return_value=[]
            ), patch.object(recovery.base, "_require_capability"), patch.object(
                recovery.base, "_require_valid_audit_chain"
            ):
                with self.assertRaisesRegex(ValueError, "eligible"):
                    recovery._clear_test_kill_switch(
                        expected_sha256=digest,
                        expected_nonce="a" * 32,
                    )

            self.assertTrue(marker.exists())

    def test_clear_test_kill_switch_restores_marker_when_audit_append_fails(self) -> None:
        now = int(time.time())
        nonce = "b" * 32
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / "state"
            state.mkdir()
            marker = root / "operator-kill-switch"
            payload = (
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": recovery.TEST_KILL_SWITCH_KIND,
                        "nonce": nonce,
                        "created_at_unix": now,
                        "expires_at_unix": now + 60,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            marker.write_bytes(payload)
            marker.chmod(0o600)
            digest = hashlib.sha256(payload).hexdigest()
            create_record = {
                "operation": "create",
                "path": str(marker),
                "after_sha256": digest,
                "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                "record_sha256": "c" * 64,
            }
            with patch.object(recovery.base, "KILL_SWITCH_PATH", marker), patch.object(
                recovery.base, "STATE_DIR", state
            ), patch.object(recovery.base, "_audit_records", return_value=[create_record]), patch.object(
                recovery.base, "_require_capability"
            ), patch.object(recovery.base, "_require_valid_audit_chain"), patch.object(
                recovery.base, "_append_audit", side_effect=RuntimeError("audit failed")
            ):
                with self.assertRaisesRegex(RuntimeError, "audit failed"):
                    recovery._clear_test_kill_switch(
                        expected_sha256=digest,
                        expected_nonce=nonce,
                    )

            self.assertTrue(marker.is_file())
            self.assertEqual(marker.read_bytes(), payload)

    def test_probe_cleanup_mode_is_separate_from_backup_probe(self) -> None:
        expected = {"success": True}
        with patch.object(
            recovery.base,
            "_kill_switch_state",
            return_value={"engaged": True, "environment": False, "path_exists": True},
        ), patch.object(
            recovery,
            "_test_kill_switch_recovery_status",
            return_value={"eligible": True, "sha256": "a" * 64, "nonce": "b" * 32},
        ), patch.object(recovery, "_clear_test_kill_switch", return_value=expected) as clear, patch.object(
            recovery, "server_recovery_probe"
        ) as probe, patch.object(recovery.base, "_require_capability") as require:
            result = recovery.grabowski_recovery_server_probe()

        self.assertIs(result, expected)
        clear.assert_called_once_with(expected_sha256="a" * 64, expected_nonce="b" * 32)
        probe.assert_not_called()
        self.assertEqual(
            [call.args[0] for call in require.call_args_list],
            ["secret_use", "file_write", "terminal_execute"],
        )

    def test_probe_refuses_manual_or_environment_kill_switch(self) -> None:
        with patch.object(
            recovery.base,
            "_kill_switch_state",
            return_value={"engaged": True, "environment": True, "path_exists": False},
        ), patch.object(
            recovery,
            "_test_kill_switch_recovery_status",
            return_value={"eligible": False, "error": "environment kill switch cannot be self-cleared"},
        ), patch.object(recovery, "server_recovery_probe") as probe:
            with self.assertRaisesRegex(PermissionError, "not an eligible"):
                recovery.grabowski_recovery_server_probe()

        probe.assert_not_called()

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
            marker_path.chmod(0o600)
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
            marker_path.chmod(0o600)
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

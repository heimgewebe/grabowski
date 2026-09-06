from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

operations = importlib.import_module("grabowski_operations")


class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent = b""
        self.connected_to = None
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, value):
        self.timeout = value

    def connect(self, value):
        self.connected_to = value

    def sendall(self, value: bytes):
        self.sent += value

    def shutdown(self, _how):
        return None

    def recv(self, _size: int) -> bytes:
        if self.response:
            value = self.response
            self.response = b""
            return value
        return b""


class BackupNtfsOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        operations._BACKUP_NTFS_LAST_CHECK = None
        self.addCleanup(setattr, operations, "_BACKUP_NTFS_LAST_CHECK", None)

    def _audit(self, *, action: str, returncode: int, request_id: str = "a" * 32) -> dict[str, object]:
        return {
            "request_id": request_id,
            "reference_sha256": "b" * 64,
            "action": action,
            "mode": "template",
            "returncode": returncode,
            "timed_out": False,
            "peer_uid": 1000,
            "peer_unit": "grabowski-operator.service",
        }

    def _reference(self, *, action: str, target: str, justification: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "action": action,
            "target": target,
            "justification": justification,
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
        }

    def test_list_exposes_reserved_typed_operations_and_rejects_shadowing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "operations.json"
            path.write_text(
                json.dumps({"schema_version": 1, "operations": {}}),
                encoding="utf-8",
            )
            with patch.object(operations, "OPERATIONS_CONFIG", path), patch.object(
                operations.operator, "_require_operator_capability"
            ):
                result = operations.grabowski_operation_list()
            self.assertEqual(
                result["operations"][operations.BACKUP_NTFS_CHECK_OPERATION]["effect"],
                "read_only",
            )
            self.assertEqual(
                result["operations"][operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION]["effect"],
                "filesystem_repair_write",
            )
            self.assertEqual(
                result["operations"][operations.BACKUP_SMART_READ_OPERATION]["effect"],
                "read_only",
            )
            self.assertEqual(
                result["operations"][operations.BACKUP_SMART_READ_OPERATION]["parameters"],
                [],
            )
            self.assertEqual(
                result["operations"][operations.BLOCKADE_AUTHORITY_HARDEN_OPERATION]["effect"],
                "authority_mode_write",
            )
            self.assertEqual(
                result["operations"][operations.BLOCKADE_AUTHORITY_HARDEN_OPERATION]["parameters"],
                [],
            )

            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "operations": {
                            operations.BACKUP_NTFS_CHECK_OPERATION: {
                                "description": "shadow",
                                "parameters": {},
                                "steps": [
                                    {
                                        "phase": "action",
                                        "target": "local",
                                        "argv": ["/bin/true"],
                                    }
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(operations, "OPERATIONS_CONFIG", path), patch.object(
                operations.operator, "_require_operator_capability"
            ):
                with self.assertRaisesRegex(ValueError, "shadows reserved typed operation"):
                    operations.grabowski_operation_list()

    def test_plans_are_parameterless_and_exactly_action_bound(self) -> None:
        check = operations._backup_storage_operation_plan(
            operations.BACKUP_NTFS_CHECK_OPERATION, None
        )
        clear = operations._backup_storage_operation_plan(
            operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
            {"check_response_sha256": "e" * 64},
        )
        smart = operations._backup_storage_operation_plan(
            operations.BACKUP_SMART_READ_OPERATION, None
        )
        harden = operations._blockade_authority_harden_operation_plan(None)
        self.assertEqual(check["privileged_action"], "local_backup_ntfs_check")
        self.assertEqual(check["target"], "check")
        self.assertEqual(clear["privileged_action"], "local_backup_ntfs_clear_dirty")
        self.assertEqual(clear["target"], "clear-dirty")
        self.assertEqual(check["execution"], "operator-mainpid-direct-rootbroker")
        self.assertEqual(clear["parameter_names"], ["check_response_sha256"])
        self.assertEqual(clear["effect"], "filesystem_repair_write")
        self.assertIn("ntfsfix -d repair/clear-dirty", clear["description"])
        self.assertEqual(smart["privileged_action"], "local_backup_smart_read")
        self.assertEqual(smart["target"], "smart-read")
        self.assertEqual(smart["parameter_names"], [])
        self.assertEqual(smart["effect"], "read_only")
        self.assertEqual(harden["parameter_names"], [])
        self.assertEqual(harden["effect"], "authority_mode_write")
        self.assertEqual(
            harden["privileged_action"], operations.privileged.BLOCKADE_LIFECYCLE_ACTION
        )
        with self.assertRaisesRegex(ValueError, "parameter mismatch"):
            operations._backup_storage_operation_plan(
                operations.BACKUP_NTFS_CHECK_OPERATION, {"device": "/dev/sda1"}
            )
        with self.assertRaisesRegex(ValueError, "parameter mismatch"):
            operations._backup_storage_operation_plan(
                operations.BACKUP_SMART_READ_OPERATION, {"device": "/dev/sda"}
            )
        with self.assertRaisesRegex(ValueError, "accepts no parameters"):
            operations._blockade_authority_harden_operation_plan(
                {"path": "/tmp/not-authorized"}
            )

    def test_blockade_authority_harden_uses_one_lifecycle_call_and_exact_readback(self) -> None:
        before = {
            "directory_path": "/var/lib/grabowski/operator-blockade",
            "mode": operations.blockade_authority.LEGACY_MARKER_DIRECTORY_MODE,
            "uid": 0,
            "gid": 0,
            "record_sha256": "a" * 64,
            "marker_file_sha256": "b" * 64,
        }
        after = {
            **before,
            "mode": operations.blockade_authority.MARKER_DIRECTORY_MODE,
        }
        invocation = {
            "success": True,
            "outcome": "succeeded",
            "request_id": "c" * 32,
            "reference_sha256": "d" * 64,
            "lifecycle": {"receipt_sha256": "e" * 64},
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations, "_blockade_authority_state", side_effect=[before, after]
        ), patch.object(
            operations.privileged,
            "run_blockade_lifecycle_reference",
            return_value=invocation,
        ) as lifecycle, patch.object(operations.base, "_append_audit"):
            result = operations._run_blockade_authority_harden_operation(None)
        self.assertTrue(result["success"])
        self.assertEqual(result["reconciliation"], "effect_applied")
        self.assertFalse(result["retry_performed"])
        lifecycle.assert_called_once()
        payload = lifecycle.call_args.args[0]
        self.assertEqual(payload["operation"], "harden-authority")
        self.assertEqual(payload["expected_record_sha256"], "a" * 64)
        self.assertEqual(payload["expected_marker_file_sha256"], "b" * 64)

    def test_blockade_authority_harden_unknown_not_applied_does_not_retry(self) -> None:
        state = {
            "directory_path": "/var/lib/grabowski/operator-blockade",
            "mode": operations.blockade_authority.LEGACY_MARKER_DIRECTORY_MODE,
            "uid": 0,
            "gid": 0,
            "record_sha256": "a" * 64,
            "marker_file_sha256": "b" * 64,
        }
        invocation = {
            "success": False,
            "outcome": "unknown",
            "request_id": "c" * 32,
            "reference_sha256": "d" * 64,
            "lifecycle": None,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations, "_blockade_authority_state", side_effect=[state, dict(state)]
        ), patch.object(
            operations.privileged,
            "run_blockade_lifecycle_reference",
            return_value=invocation,
        ) as lifecycle, patch.object(operations.base, "_append_audit"):
            result = operations._run_blockade_authority_harden_operation(None)
        self.assertFalse(result["success"])
        self.assertEqual(result["reconciliation"], "effect_not_applied")
        self.assertFalse(result["retry_performed"])
        lifecycle.assert_called_once()

    def test_blockade_authority_harden_helper_exception_reconciles_applied_effect(self) -> None:
        before = {
            "directory_path": "/var/lib/grabowski/operator-blockade",
            "mode": operations.blockade_authority.LEGACY_MARKER_DIRECTORY_MODE,
            "uid": 0,
            "gid": 0,
            "record_sha256": "a" * 64,
            "marker_file_sha256": "b" * 64,
        }
        after = {
            **before,
            "mode": operations.blockade_authority.MARKER_DIRECTORY_MODE,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations, "_blockade_authority_state", side_effect=[before, after]
        ), patch.object(
            operations.privileged,
            "run_blockade_lifecycle_reference",
            side_effect=RuntimeError("local audit projection failed"),
        ) as lifecycle, patch.object(operations.base, "_append_audit"):
            result = operations._run_blockade_authority_harden_operation(None)
        self.assertTrue(result["success"])
        self.assertEqual(result["reconciliation"], "effect_applied")
        self.assertIsNone(result["root_invocation"])
        self.assertEqual(result["root_invocation_error_type"], "RuntimeError")
        self.assertIsNone(result["post_readback_error_type"])
        self.assertFalse(result["retry_performed"])
        lifecycle.assert_called_once()

    def test_blockade_authority_harden_readback_failure_is_structured_unknown(self) -> None:
        before = {
            "directory_path": "/var/lib/grabowski/operator-blockade",
            "mode": operations.blockade_authority.LEGACY_MARKER_DIRECTORY_MODE,
            "uid": 0,
            "gid": 0,
            "record_sha256": "a" * 64,
            "marker_file_sha256": "b" * 64,
        }
        invocation = {
            "success": False,
            "outcome": "unknown",
            "request_id": "c" * 32,
            "reference_sha256": "d" * 64,
            "lifecycle": None,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations,
            "_blockade_authority_state",
            side_effect=[before, PermissionError("readback unavailable")],
        ), patch.object(
            operations.privileged,
            "run_blockade_lifecycle_reference",
            return_value=invocation,
        ) as lifecycle, patch.object(operations.base, "_append_audit"):
            result = operations._run_blockade_authority_harden_operation(None)
        self.assertFalse(result["success"])
        self.assertEqual(result["reconciliation"], "outcome_unknown")
        self.assertIsNone(result["after"])
        self.assertIsNone(result["root_invocation_error_type"])
        self.assertEqual(result["post_readback_error_type"], "PermissionError")
        self.assertFalse(result["retry_performed"])
        lifecycle.assert_called_once()

    def test_blockade_authority_harden_already_0711_is_readback_only(self) -> None:
        state = {
            "directory_path": "/var/lib/grabowski/operator-blockade",
            "mode": operations.blockade_authority.MARKER_DIRECTORY_MODE,
            "uid": 0,
            "gid": 0,
            "record_sha256": "a" * 64,
            "marker_file_sha256": "b" * 64,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations, "_blockade_authority_state", return_value=state
        ), patch.object(
            operations.privileged, "run_blockade_lifecycle_reference"
        ) as lifecycle, patch.object(operations.base, "_append_audit"):
            result = operations._run_blockade_authority_harden_operation(None)
        self.assertTrue(result["success"])
        self.assertEqual(result["reconciliation"], "already_hardened")
        self.assertIsNone(result["root_invocation"])
        self.assertFalse(result["retry_performed"])
        lifecycle.assert_not_called()

    def test_direct_invocation_uses_main_process_socket_and_structured_response(self) -> None:
        response = json.dumps(
            {
                "request_id": "a" * 32,
                "action": "local_backup_ntfs_check",
                "returncode": 0,
                "timed_out": False,
                "mode": "template",
                "stdout": "Mounting volume... OK\n",
                "stderr": "",
                "audit": self._audit(action="local_backup_ntfs_check", returncode=0),
            },
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        fake = FakeSocket(response)
        with patch.object(
            operations.privileged,
            "_privileged_broker_status",
            return_value={"ready": True},
        ), patch.object(
            operations.privileged,
            "_create_privileged_reference",
            side_effect=self._reference,
        ), patch.object(
            operations.privileged, "_redact_text", side_effect=lambda value: value
        ), patch.object(operations.socket, "socket", return_value=fake):
            result = operations._invoke_mainpid_privileged_action(
                action="local_backup_ntfs_check",
                target="check",
                justification="read-only diagnostic",
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(fake.connected_to, str(operations.privileged.BROKER_SOCKET))
        payload = json.loads(fake.sent.decode("utf-8"))
        self.assertEqual(payload["action"], "local_backup_ntfs_check")
        self.assertEqual(payload["target"], "check")

    def test_direct_invocation_preserves_nonzero_root_check_evidence(self) -> None:
        response = json.dumps(
            {
                "request_id": "a" * 32,
                "action": "local_backup_ntfs_check",
                "returncode": 1,
                "timed_out": False,
                "mode": "template",
                "stdout": "Volume is scheduled for check.\n",
                "stderr": "",
                "audit": self._audit(action="local_backup_ntfs_check", returncode=1),
            },
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        fake = FakeSocket(response)
        with patch.object(
            operations.privileged,
            "_privileged_broker_status",
            return_value={"ready": True},
        ), patch.object(
            operations.privileged,
            "_create_privileged_reference",
            side_effect=self._reference,
        ), patch.object(
            operations.privileged, "_redact_text", side_effect=lambda value: value
        ), patch.object(operations.socket, "socket", return_value=fake):
            result = operations._invoke_mainpid_privileged_action(
                action="local_backup_ntfs_check",
                target="check",
                justification="read-only diagnostic",
            )
        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["broker_response"]["returncode"], 1)
        self.assertIn("scheduled for check", result["broker_response"]["stdout"])

    def test_typed_run_binds_exact_action_and_audits_without_rollback(self) -> None:
        invocation = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "local_backup_ntfs_clear_dirty",
            "target": "clear-dirty",
            "success": True,
            "outcome": "succeeded",
            "timed_out": False,
            "transport_error": None,
            "broker_response": {"returncode": 0, "audit": {"record_sha256": "c" * 64}},
            "response_sha256": "d" * 64,
        }
        operations._BACKUP_NTFS_LAST_CHECK = {
            "checked_at_unix": 1000,
            "response_sha256": "e" * 64,
            "reference_sha256": "f" * 64,
            "root_audit_sha256": "1" * 64,
            "write_admissible": True,
            "check_returncode": 0,
        }
        with patch.object(
            operations.time, "time", return_value=1001
        ), patch.object(
            operations.operator, "_require_operator_capability"
        ) as capability, patch.object(
            operations.operator, "_require_operator_mutation"
        ) as mutation, patch.object(
            operations, "_invoke_mainpid_privileged_action", return_value=invocation
        ) as invoke, patch.object(operations.base, "_append_audit") as append:
            result = operations._run_backup_storage_operation(
                operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
                {"check_response_sha256": "e" * 64},
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["effect"], "filesystem_repair_write")
        self.assertFalse(result["rollback"]["attempted"])
        capability.assert_called_once_with("privileged_reference")
        mutation.assert_called_once_with("terminal_execute", opaque_command=False)
        self.assertEqual(invoke.call_args.kwargs["action"], "local_backup_ntfs_clear_dirty")
        self.assertEqual(invoke.call_args.kwargs["target"], "clear-dirty")
        append.assert_called_once()

    def test_clear_dirty_requires_exact_latest_check_before_root_invocation(self) -> None:
        with patch.object(operations, "_invoke_mainpid_privileged_action") as invoke:
            with self.assertRaisesRegex(PermissionError, "exact latest BACKUP NTFS check"):
                operations._run_backup_storage_operation(
                    operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
                    {"check_response_sha256": "e" * 64},
                )
        invoke.assert_not_called()

        operations._BACKUP_NTFS_LAST_CHECK = {
            "checked_at_unix": 1000,
            "response_sha256": "d" * 64,
            "reference_sha256": "f" * 64,
            "root_audit_sha256": "1" * 64,
            "write_admissible": True,
            "check_returncode": 0,
        }
        with patch.object(operations.time, "time", return_value=1001), patch.object(
            operations, "_invoke_mainpid_privileged_action"
        ) as invoke:
            with self.assertRaisesRegex(PermissionError, "exact latest BACKUP NTFS check"):
                operations._run_backup_storage_operation(
                    operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
                    {"check_response_sha256": "e" * 64},
                )
        invoke.assert_not_called()
        self.assertIsNone(operations._BACKUP_NTFS_LAST_CHECK)

    def test_failed_check_evidence_cannot_authorize_repair_write(self) -> None:
        operations._BACKUP_NTFS_LAST_CHECK = {
            "checked_at_unix": 1000,
            "response_sha256": "e" * 64,
            "reference_sha256": "f" * 64,
            "root_audit_sha256": "1" * 64,
            "write_admissible": False,
            "check_returncode": 1,
        }
        with patch.object(operations.time, "time", return_value=1001), patch.object(
            operations, "_invoke_mainpid_privileged_action"
        ) as invoke:
            with self.assertRaisesRegex(PermissionError, "did not authorize repair write"):
                operations._run_backup_storage_operation(
                    operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
                    {"check_response_sha256": "e" * 64},
                )
        invoke.assert_not_called()
        self.assertIsNone(operations._BACKUP_NTFS_LAST_CHECK)

    def test_smart_root_audit_binds_exact_public_output(self) -> None:
        stdout = "SMART data\n"
        stderr = ""
        audit = {
            **self._audit(action="local_backup_smart_read", returncode=4),
            "stdout_truncated": False,
            "stderr_truncated": False,
            "smart_stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "smart_stdout_bytes": len(stdout.encode("utf-8")),
            "smart_stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            "smart_stderr_bytes": 0,
        }
        invocation = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "local_backup_smart_read",
            "broker_response": {
                "returncode": 4,
                "stdout": stdout,
                "stderr": stderr,
                "audit": audit,
            },
        }
        self.assertRegex(operations._root_audit_sha256(invocation) or "", r"[0-9a-f]{64}")
        invocation["broker_response"]["stdout"] = "tampered\n"
        self.assertIsNone(operations._root_audit_sha256(invocation))

    def test_smart_read_is_parameterless_and_does_not_touch_ntfs_check_evidence(self) -> None:
        invocation = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "local_backup_smart_read",
            "target": "smart-read",
            "success": True,
            "outcome": "succeeded",
            "timed_out": False,
            "transport_error": None,
            "broker_response": {"returncode": 0},
            "response_sha256": "d" * 64,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations, "_invoke_mainpid_privileged_action", return_value=invocation
        ) as invoke, patch.object(operations.base, "_append_audit"):
            result = operations._run_backup_storage_operation(
                operations.BACKUP_SMART_READ_OPERATION, None
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["effect"], "read_only")
        self.assertIsNone(result["check_evidence"])
        self.assertIsNone(result["consumed_check_evidence"])
        self.assertIsNone(operations._BACKUP_NTFS_LAST_CHECK)
        self.assertEqual(invoke.call_args.kwargs["action"], "local_backup_smart_read")
        self.assertEqual(invoke.call_args.kwargs["target"], "smart-read")
        self.assertIn("no caller-selected device or flags", invoke.call_args.kwargs["justification"])

    def test_direct_invocation_rejects_non_backup_action_before_broker(self) -> None:
        with patch.object(operations.privileged, "_privileged_broker_status") as broker:
            with self.assertRaisesRegex(ValueError, "outside the BACKUP storage allowlist"):
                operations._invoke_mainpid_privileged_action(
                    action="operator_power_argv",
                    target="anything",
                    justification="must be rejected",
                )
        broker.assert_not_called()

    def test_direct_invocation_rejects_mismatched_broker_binding(self) -> None:
        response = json.dumps(
            {
                "request_id": "f" * 32,
                "action": "local_backup_ntfs_check",
                "returncode": 0,
                "timed_out": False,
                "mode": "template",
                "stdout": "OK\n",
                "stderr": "",
                "audit": self._audit(
                    action="local_backup_ntfs_check", returncode=0, request_id="f" * 32
                ),
            },
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        fake = FakeSocket(response)
        with patch.object(
            operations.privileged,
            "_privileged_broker_status",
            return_value={"ready": True},
        ), patch.object(
            operations.privileged,
            "_create_privileged_reference",
            side_effect=self._reference,
        ), patch.object(
            operations.privileged, "_redact_text", side_effect=lambda value: value
        ), patch.object(operations.socket, "socket", return_value=fake):
            result = operations._invoke_mainpid_privileged_action(
                action="local_backup_ntfs_check",
                target="check",
                justification="read-only diagnostic",
            )
        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "failed")

    def test_secondary_audit_failure_does_not_hide_root_success(self) -> None:
        invocation = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "local_backup_ntfs_check",
            "target": "check",
            "success": True,
            "outcome": "succeeded",
            "timed_out": False,
            "transport_error": None,
            "broker_response": {
                "returncode": 0,
                "audit": self._audit(action="local_backup_ntfs_check", returncode=0),
            },
            "response_sha256": "d" * 64,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations, "_invoke_mainpid_privileged_action", return_value=invocation
        ), patch.object(
            operations.base, "_append_audit", side_effect=RuntimeError("audit unavailable")
        ):
            result = operations._run_backup_storage_operation(
                operations.BACKUP_NTFS_CHECK_OPERATION, None
            )
        self.assertTrue(result["success"])
        self.assertEqual(result["check_evidence"]["response_sha256"], "d" * 64)
        self.assertRegex(result["check_evidence"]["root_audit_sha256"], r"[0-9a-f]{64}")
        self.assertTrue(result["check_evidence"]["write_admissible"])
        self.assertEqual(result["check_evidence"]["check_returncode"], 0)
        self.assertFalse(result["audit"]["secondary_audit_recorded"])
        self.assertEqual(result["audit"]["secondary_audit_error_type"], "RuntimeError")

    def test_direct_invocation_fails_closed_on_unstructured_response(self) -> None:
        fake = FakeSocket(b"not-json\n")
        with patch.object(
            operations.privileged,
            "_privileged_broker_status",
            return_value={"ready": True},
        ), patch.object(
            operations.privileged,
            "_create_privileged_reference",
            side_effect=self._reference,
        ), patch.object(
            operations.privileged, "_redact_text", side_effect=lambda value: value
        ), patch.object(operations.socket, "socket", return_value=fake):
            result = operations._invoke_mainpid_privileged_action(
                action="local_backup_ntfs_check",
                target="check",
                justification="read-only diagnostic",
            )
        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "unknown")


class BackupMountRecoveryOperationTests(unittest.TestCase):
    def test_mount_reconcile_and_authority_refresh_plans_are_exact(self) -> None:
        mount = operations._backup_storage_operation_plan(
            operations.BACKUP_MOUNT_RECONCILE_OPERATION, None
        )
        refresh = operations._rootbroker_authority_refresh_plan(
            {"expected_head": "a" * 40}
        )
        self.assertEqual(mount["privileged_action"], "local_backup_mount_reconcile")
        self.assertEqual(mount["target"], "reconcile")
        self.assertEqual(mount["effect"], "mount_reconcile_write")
        self.assertEqual(refresh["effect"], "authority_contract_refresh")
        with self.assertRaisesRegex(ValueError, "full SHA-1"):
            operations._rootbroker_authority_refresh_plan({"expected_head": "main"})

    def test_authority_refresh_forces_same_head_cutover(self) -> None:
        outcome = {
            "success": True,
            "outcome": "succeeded",
            "attested_head": "a" * 40,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations.privileged,
            "ensure_rootbroker_authority",
            return_value=outcome,
        ) as ensure, patch.object(operations.base, "_append_audit"):
            result = operations._run_rootbroker_authority_refresh_operation(
                {"expected_head": "a" * 40}
            )
        self.assertTrue(result["success"])
        ensure.assert_called_once_with("a" * 40, force_refresh=True)

    def test_mount_reconcile_uses_only_fixed_root_action(self) -> None:
        invocation = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "local_backup_mount_reconcile",
            "target": "reconcile",
            "success": True,
            "outcome": "succeeded",
            "timed_out": False,
            "transport_error": None,
            "broker_response": {"returncode": 0, "audit": {}},
            "response_sha256": "d" * 64,
        }
        with patch.object(
            operations.operator, "_require_operator_capability"
        ), patch.object(
            operations.operator, "_require_operator_mutation"
        ), patch.object(
            operations,
            "_invoke_mainpid_privileged_action",
            return_value=invocation,
        ) as invoke, patch.object(operations.base, "_append_audit"):
            result = operations._run_backup_storage_operation(
                operations.BACKUP_MOUNT_RECONCILE_OPERATION, None
            )
        self.assertTrue(result["success"])
        self.assertEqual(
            invoke.call_args.kwargs["action"], "local_backup_mount_reconcile"
        )
        self.assertEqual(invoke.call_args.kwargs["target"], "reconcile")
        self.assertIn(
            "vanished-device stale", invoke.call_args.kwargs["justification"]
        )


if __name__ == "__main__":
    unittest.main()

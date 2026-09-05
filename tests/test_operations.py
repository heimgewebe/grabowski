from __future__ import annotations

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
        check = operations._backup_ntfs_operation_plan(
            operations.BACKUP_NTFS_CHECK_OPERATION, None
        )
        clear = operations._backup_ntfs_operation_plan(
            operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
            {"check_response_sha256": "e" * 64},
        )
        self.assertEqual(check["privileged_action"], "local_backup_ntfs_check")
        self.assertEqual(check["target"], "check")
        self.assertEqual(clear["privileged_action"], "local_backup_ntfs_clear_dirty")
        self.assertEqual(clear["target"], "clear-dirty")
        self.assertEqual(check["execution"], "operator-mainpid-direct-rootbroker")
        self.assertEqual(clear["parameter_names"], ["check_response_sha256"])
        self.assertEqual(clear["effect"], "filesystem_repair_write")
        self.assertIn("ntfsfix -d repair/clear-dirty", clear["description"])
        with self.assertRaisesRegex(ValueError, "parameter mismatch"):
            operations._backup_ntfs_operation_plan(
                operations.BACKUP_NTFS_CHECK_OPERATION, {"device": "/dev/sda1"}
            )

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
            result = operations._run_backup_ntfs_operation(
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
                operations._run_backup_ntfs_operation(
                    operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
                    {"check_response_sha256": "e" * 64},
                )
        invoke.assert_not_called()

        operations._BACKUP_NTFS_LAST_CHECK = {
            "checked_at_unix": 1000,
            "response_sha256": "d" * 64,
            "reference_sha256": "f" * 64,
            "root_audit_sha256": "1" * 64,
        }
        with patch.object(operations.time, "time", return_value=1001), patch.object(
            operations, "_invoke_mainpid_privileged_action"
        ) as invoke:
            with self.assertRaisesRegex(PermissionError, "exact latest BACKUP NTFS check"):
                operations._run_backup_ntfs_operation(
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
                operations._run_backup_ntfs_operation(
                    operations.BACKUP_NTFS_CLEAR_DIRTY_OPERATION,
                    {"check_response_sha256": "e" * 64},
                )
        invoke.assert_not_called()
        self.assertIsNone(operations._BACKUP_NTFS_LAST_CHECK)

    def test_direct_invocation_rejects_non_backup_action_before_broker(self) -> None:
        with patch.object(operations.privileged, "_privileged_broker_status") as broker:
            with self.assertRaisesRegex(ValueError, "outside the BACKUP NTFS allowlist"):
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
            result = operations._run_backup_ntfs_operation(
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


if __name__ == "__main__":
    unittest.main()

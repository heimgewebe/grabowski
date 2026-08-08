from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


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

import grabowski_juno_bluetooth as bluetooth  # noqa: E402


DEVICE_ID = "C93BEBF5-6DC1-3A40-DB50-02757584ED91"


def scan_device() -> dict[str, object]:
    return {
        "id": DEVICE_ID,
        "name": None,
        "local_name": None,
        "rssi_last": -61,
        "rssi_max": -61,
        "seen": 2,
        "tx_power": None,
        "connectable": True,
        "service_uuids": [],
        "overflow_service_uuids": [],
        "solicited_service_uuids": [],
        "manufacturer_data": None,
        "service_data": "{ FCF1 = data; }",
    }


def scan_result() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "ipad_bluetooth_scan",
        "operation": "scan",
        "application_state": 0,
        "central_state": 5,
        "bluetooth_powered_on": True,
        "scan_seconds": 5,
        "allow_duplicates": True,
        "device_count": 1,
        "devices": [scan_device()],
        "truncated": False,
        "writes_attempted": False,
        "pairing_requested_by_tool": False,
    }


def read_result() -> dict[str, object]:
    payloads = {"FFF3": b"alpha", "FFF4": b"", "FFF5": bytes(range(8))}
    values = []
    for uuid, payload in payloads.items():
        values.append(
            {
                "uuid": uuid,
                "status": "read",
                "properties": 58 if uuid != "FFF5" else 62,
                "value_b64": base64.b64encode(payload).decode("ascii"),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return {
        "schema_version": 1,
        "kind": "ipad_bluetooth_read",
        "operation": "read",
        "application_state": 0,
        "central_state": 5,
        "bluetooth_powered_on": True,
        "device_id": DEVICE_ID,
        "found": True,
        "advertisement": scan_device(),
        "connected": True,
        "disconnected": True,
        "service_uuid": "FFF0",
        "characteristic_uuids": ["FFF3", "FFF4", "FFF5"],
        "values": values,
        "read_attempted_count": 3,
        "subscriptions_attempted": False,
        "errors": [],
        "writes_attempted": False,
        "pairing_api_called_by_tool": False,
        "system_pairing_prompt_possible": True,
        "system_pairing_risk_acknowledged": True,
    }


def inspect_result() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "ipad_bluetooth_inspect",
        "operation": "inspect",
        "application_state": 0,
        "central_state": 5,
        "bluetooth_powered_on": True,
        "device_id": DEVICE_ID,
        "found": True,
        "advertisement": scan_device(),
        "connected": True,
        "disconnected": True,
        "services": [
            {
                "uuid": "1849",
                "characteristics": [
                    {
                        "uuid": "2B93",
                        "properties": 18,
                        "readable": True,
                        "writable_without_response": False,
                        "writable": False,
                        "notifiable": True,
                        "indicatable": False,
                    }
                ],
            }
        ],
        "errors": [],
        "writes_attempted": False,
        "pairing_requested_by_tool": False,
    }


class JunoBluetoothHostTests(unittest.TestCase):
    def test_scan_result_is_bounded_and_no_write_bound(self) -> None:
        request = {
            "schema_version": 1,
            "operation": "scan",
            "scan_seconds": 5,
            "limit": 8,
            "allow_duplicates": True,
            "class_suffix": "a" * 12,
        }
        result = scan_result()
        self.assertIs(bluetooth._validate_device_result(request, result), result)

        changed = copy.deepcopy(result)
        changed["writes_attempted"] = True
        with self.assertRaisesRegex(RuntimeError, "no-write"):
            bluetooth._validate_device_result(request, changed)

        changed = copy.deepcopy(result)
        changed["pairing_requested_by_tool"] = True
        with self.assertRaisesRegex(RuntimeError, "no-pairing"):
            bluetooth._validate_device_result(request, changed)

    def test_inspect_result_is_exact_target_and_metadata_only(self) -> None:
        request = {
            "schema_version": 1,
            "operation": "inspect",
            "device_id": DEVICE_ID,
            "scan_seconds": 5,
            "discovery_seconds": 7,
            "class_suffix": "b" * 12,
        }
        result = inspect_result()
        self.assertIs(bluetooth._validate_device_result(request, result), result)

        changed = copy.deepcopy(result)
        changed["device_id"] = "77EC9A57-0889-57E5-D8CF-600EF39D88C3"
        with self.assertRaisesRegex(RuntimeError, "target mismatch"):
            bluetooth._validate_device_result(request, changed)

    def test_fixed_device_source_has_bounded_value_read_but_no_write_or_subscription_call(self) -> None:
        source = bluetooth._BLUETOOTH_JOB_SOURCE
        self.assertIn("discoverServices_", source)
        self.assertIn("discoverCharacteristics_forService_", source)
        self.assertIn("readValueForCharacteristic_", source)
        self.assertIn('target_service = next(', source)
        self.assertIn('_mark_unresolved_reads("discovery_timeout")', source)
        self.assertIn("cancelPeripheralConnection_", source)
        self.assertNotIn("writeValue", source)
        self.assertNotIn("setNotifyValue", source)

    def test_read_discovery_targets_requested_uuids_before_output_caps(self) -> None:
        source = bluetooth._BLUETOOTH_JOB_SOURCE
        self.assertIn('CBUUID = ObjCClass("CBUUID")', source)
        self.assertIn('_gatt_uuid_array([_REQUEST["service_uuid"]])', source)
        self.assertIn('_gatt_uuid_array(_REQUEST["characteristic_uuids"])', source)

        target_lookup = source.index("target_service = next(")
        service_cap = source.index("services = services[:MAX_SERVICES]", target_lookup)
        self.assertLess(target_lookup, service_cap)

        requested_selection = source.index(
            'requested_characteristics = set(_REQUEST["characteristic_uuids"])'
        )
        characteristic_cap = source.index(
            "selected_values = values[:MAX_CHARACTERISTICS_PER_SERVICE]",
            requested_selection,
        )
        self.assertLess(requested_selection, characteristic_cap)

    def test_read_result_is_exact_target_bounded_and_digest_bound(self) -> None:
        request = {
            "schema_version": 1,
            "operation": "read",
            "device_id": DEVICE_ID,
            "service_uuid": "FFF0",
            "characteristic_uuids": ["FFF3", "FFF4", "FFF5"],
            "acknowledge_system_pairing_risk": True,
            "scan_seconds": 5,
            "discovery_seconds": 7,
            "class_suffix": "d" * 12,
        }
        result = read_result()
        self.assertIs(bluetooth._validate_device_result(request, result), result)

        changed = copy.deepcopy(result)
        changed["subscriptions_attempted"] = True
        with self.assertRaisesRegex(RuntimeError, "no-subscription"):
            bluetooth._validate_device_result(request, changed)

        changed = copy.deepcopy(result)
        changed["system_pairing_risk_acknowledged"] = False
        with self.assertRaisesRegex(RuntimeError, "pairing risk acknowledgement"):
            bluetooth._validate_device_result(request, changed)

        changed = copy.deepcopy(result)
        changed["values"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
            bluetooth._validate_device_result(request, changed)

        timeout_result = copy.deepcopy(result)
        timeout_result["read_attempted_count"] = 0
        timeout_result["values"] = [
            {"uuid": uuid, "status": "discovery_timeout", "properties": None}
            for uuid in request["characteristic_uuids"]
        ]
        self.assertIs(
            bluetooth._validate_device_result(request, timeout_result),
            timeout_result,
        )

    def test_input_bounds_and_uuid_normalization(self) -> None:
        self.assertEqual(bluetooth._validate_uuid(DEVICE_ID.lower()), DEVICE_ID)
        with self.assertRaises(ValueError):
            bluetooth._validate_uuid("not-a-device")
        self.assertEqual(bluetooth._validate_gatt_uuid("fff0", label="service_uuid"), "FFF0")
        self.assertEqual(
            bluetooth._validate_characteristic_uuids(["fff3", "FFF4", "fff5"]),
            ["FFF3", "FFF4", "FFF5"],
        )
        with self.assertRaises(ValueError):
            bluetooth._validate_characteristic_uuids(["FFF3", "fff3"])
        self.assertEqual(
            bluetooth._bounded_int(5, minimum=1, maximum=12, label="scan_seconds"),
            5,
        )
        for value in (0, 13, True):
            with self.assertRaises(ValueError):
                bluetooth._bounded_int(value, minimum=1, maximum=12, label="scan_seconds")

    def test_typed_read_normalizes_exact_targets_and_uses_read_operation(self) -> None:
        with (
            patch.object(bluetooth.operator, "_require_operator_capability"),
            patch.object(bluetooth, "_run_typed_bluetooth_job", return_value={"ok": True}) as run,
        ):
            result = bluetooth.ipad_bluetooth_read(
                DEVICE_ID.lower(),
                "fff0",
                ["fff3", "fff4", "fff5"],
                "2026-08-08T08:51:10.881206+00:00",
                {"target": "ipad-10th-gen-wifi"},
                True,
            )
        self.assertEqual(result, {"ok": True})
        request = run.call_args.kwargs["request"]
        self.assertEqual(request["operation"], "read")
        self.assertEqual(request["device_id"], DEVICE_ID)
        self.assertEqual(request["service_uuid"], "FFF0")
        self.assertEqual(request["characteristic_uuids"], ["FFF3", "FFF4", "FFF5"])
        self.assertIs(request["acknowledge_system_pairing_risk"], True)

        with (
            patch.object(bluetooth.operator, "_require_operator_capability"),
            self.assertRaisesRegex(ValueError, "system pairing UI"),
        ):
            bluetooth.ipad_bluetooth_read(
                DEVICE_ID,
                "FFF0",
                ["FFF3"],
                "2026-08-08T08:51:10.881206+00:00",
                {"target": "ipad-10th-gen-wifi"},
                False,
            )

    def test_code_is_digest_bound_and_delegate_name_is_unique_per_request(self) -> None:
        first_request = {
            "schema_version": 1,
            "operation": "scan",
            "scan_seconds": 5,
            "limit": 8,
            "allow_duplicates": True,
            "class_suffix": "1" * 12,
        }
        second_request = {**first_request, "class_suffix": "2" * 12}
        first_code, first_digest = bluetooth._bluetooth_code(first_request)
        second_code, second_digest = bluetooth._bluetooth_code(second_request)
        self.assertEqual(hashlib.sha256(first_code.encode()).hexdigest(), first_digest)
        self.assertEqual(hashlib.sha256(second_code.encode()).hexdigest(), second_digest)
        self.assertNotEqual(first_code, second_code)
        self.assertIn("GrabowskiBLEDelegate_" + "1" * 12, first_code)
        self.assertIn("GrabowskiBLEDelegate_" + "2" * 12, second_code)

    def test_typed_runner_semantically_validates_and_receipts_result(self) -> None:
        request = {
            "schema_version": 1,
            "operation": "scan",
            "scan_seconds": 5,
            "limit": 8,
            "allow_duplicates": True,
            "class_suffix": "c" * 12,
        }
        execution = {
            "job_id": "job-test",
            "status": {"state": "succeeded", "result": scan_result()},
        }
        with (
            patch.object(bluetooth.bridge, "grabowski_juno_run", return_value=execution) as run,
            patch.object(
                bluetooth.bridge,
                "_write_receipt",
                return_value={"path": "/tmp/receipt", "sha256": "d" * 64},
            ) as receipt,
        ):
            result = bluetooth._run_typed_bluetooth_job(
                request=request,
                purpose="test",
                expected_started_at="2026-08-08T05:23:41.756921+00:00",
                session_escalation={"target": "ipad-10th-gen-wifi"},
            )
        self.assertEqual(result["job_id"], "job-test")
        self.assertEqual(result["status"]["state"], "succeeded")
        run.assert_called_once()
        receipt.assert_called_once()
        self.assertEqual(
            run.call_args.kwargs["code_sha256"],
            hashlib.sha256(run.call_args.kwargs["code"].encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()

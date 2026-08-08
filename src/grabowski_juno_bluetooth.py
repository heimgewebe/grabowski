from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from typing import Any

import grabowski_juno as bridge

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
MUTATING = operator.MUTATING

SCHEMA_VERSION = 1
UUID_RE = re.compile(
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)
CLASS_SUFFIX_RE = re.compile(r"^[0-9a-f]{12}$")
MIN_SCAN_SECONDS = 1
MAX_SCAN_SECONDS = 12
MAX_INSPECT_SCAN_SECONDS = 8
MAX_DISCOVERY_SECONDS = 8
MAX_DEVICES = 128
MAX_SERVICES = 64
MAX_CHARACTERISTICS_PER_SERVICE = 128
MAX_DESCRIPTION_BYTES = 4_096
MAX_DEVICE_RESULT_BYTES = 256 * 1024
MAX_EXPECTED_STARTED_AT_BYTES = 128

_BLUETOOTH_JOB_SOURCE = r'''\
from __future__ import annotations

import base64
import ctypes
import json
import time

from rubicon.objc import NSObject, ObjCClass, objc_method


SCHEMA_VERSION = 1
MAX_SERVICES = 64
MAX_CHARACTERISTICS_PER_SERVICE = 128
MAX_DESCRIPTION_BYTES = 4096

_REQUEST = json.loads(base64.b64decode("__REQUEST_B64__").decode("utf-8"))


def _bounded_text(value):
    if value is None:
        return None
    try:
        text = str(value)
    except Exception:
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_DESCRIPTION_BYTES:
        return text
    return encoded[:MAX_DESCRIPTION_BYTES].decode("utf-8", errors="ignore")


def _uuid(peripheral):
    try:
        return str(peripheral.identifier.UUIDString).upper()
    except Exception:
        return _bounded_text(peripheral)


def _adv(adv, key):
    try:
        return adv.objectForKey_(key)
    except Exception:
        return None


def _number(value):
    if value is None:
        return None
    for attr in ("integerValue", "intValue"):
        try:
            return int(getattr(value, attr))
        except Exception:
            pass
    try:
        return int(value)
    except Exception:
        return None


def _boolean(value):
    if value is None:
        return None
    try:
        return bool(value.boolValue)
    except Exception:
        return bool(value)


def _uuid_list(value):
    if value is None:
        return []
    try:
        return [str(item) for item in list(value)][:MAX_SERVICES]
    except Exception:
        return []


def _device_row(peripheral, adv, rssi):
    return {
        "id": _uuid(peripheral),
        "name": _bounded_text(getattr(peripheral, "name", None)),
        "local_name": _bounded_text(_adv(adv, "kCBAdvDataLocalName")),
        "rssi_last": _number(rssi),
        "rssi_max": _number(rssi),
        "seen": 1,
        "tx_power": _number(_adv(adv, "kCBAdvDataTxPowerLevel")),
        "connectable": _boolean(_adv(adv, "kCBAdvDataIsConnectable")),
        "service_uuids": _uuid_list(_adv(adv, "kCBAdvDataServiceUUIDs")),
        "overflow_service_uuids": _uuid_list(_adv(adv, "kCBAdvDataOverflowServiceUUIDs")),
        "solicited_service_uuids": _uuid_list(_adv(adv, "kCBAdvDataSolicitedServiceUUIDs")),
        "manufacturer_data": _bounded_text(_adv(adv, "kCBAdvDataManufacturerData")),
        "service_data": _bounded_text(_adv(adv, "kCBAdvDataServiceData")),
        "_peripheral": peripheral,
    }


def _merge_device(row, peripheral, adv, rssi):
    value = _number(rssi)
    row["seen"] += 1
    row["rssi_last"] = value
    if value is not None and (row["rssi_max"] is None or value > row["rssi_max"]):
        row["rssi_max"] = value
    for key, adv_key in (
        ("local_name", "kCBAdvDataLocalName"),
        ("manufacturer_data", "kCBAdvDataManufacturerData"),
        ("service_data", "kCBAdvDataServiceData"),
    ):
        candidate = _bounded_text(_adv(adv, adv_key))
        if candidate:
            row[key] = candidate
    name = _bounded_text(getattr(peripheral, "name", None))
    if name:
        row["name"] = name
    connectable = _boolean(_adv(adv, "kCBAdvDataIsConnectable"))
    if connectable is not None:
        row["connectable"] = connectable
    tx_power = _number(_adv(adv, "kCBAdvDataTxPowerLevel"))
    if tx_power is not None:
        row["tx_power"] = tx_power
    for key, adv_key in (
        ("service_uuids", "kCBAdvDataServiceUUIDs"),
        ("overflow_service_uuids", "kCBAdvDataOverflowServiceUUIDs"),
        ("solicited_service_uuids", "kCBAdvDataSolicitedServiceUUIDs"),
    ):
        values = _uuid_list(_adv(adv, adv_key))
        if values:
            row[key] = values


def _public_device(row):
    return {key: value for key, value in row.items() if key != "_peripheral"}


def _sort_devices(devices):
    return sorted(
        devices,
        key=lambda row: row.get("rssi_max") if row.get("rssi_max") is not None else -999,
        reverse=True,
    )


ctypes.cdll.LoadLibrary(
    "/System/Library/Frameworks/CoreBluetooth.framework/CoreBluetooth"
)
CBCentralManager = ObjCClass("CBCentralManager")
UIApplication = ObjCClass("UIApplication")

_devices = {}
_inspect = {
    "target": None,
    "connected": False,
    "disconnected": False,
    "finished": False,
    "services": [],
    "errors": [],
}


class __DELEGATE_CLASS__(NSObject):
    @objc_method
    def centralManagerDidUpdateState_(self, central):
        pass

    @objc_method
    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self, central, peripheral, advertisement, rssi
    ):
        identifier = _uuid(peripheral)
        if identifier is None:
            return
        if identifier not in _devices:
            _devices[identifier] = _device_row(peripheral, advertisement, rssi)
        else:
            _merge_device(_devices[identifier], peripheral, advertisement, rssi)

    @objc_method
    def centralManager_didConnectPeripheral_(self, central, peripheral):
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        _inspect["connected"] = True
        _inspect["target"] = peripheral
        peripheral.delegate = self
        try:
            peripheral.discoverServices_(None)
        except Exception as exc:
            _inspect["errors"].append("discover_services:" + _bounded_text(exc))
            _inspect["finished"] = True

    @objc_method
    def centralManager_didFailToConnectPeripheral_error_(self, central, peripheral, error):
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        _inspect["errors"].append("connect:" + (_bounded_text(error) or "unknown"))
        _inspect["finished"] = True

    @objc_method
    def centralManager_didDisconnectPeripheral_error_(self, central, peripheral, error):
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        _inspect["disconnected"] = True
        if error is not None:
            _inspect["errors"].append("disconnect:" + (_bounded_text(error) or "unknown"))

    @objc_method
    def peripheral_didDiscoverServices_(self, peripheral, error):
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        if error is not None:
            _inspect["errors"].append("services:" + (_bounded_text(error) or "unknown"))
            _inspect["finished"] = True
            return
        try:
            services = list(peripheral.services) if peripheral.services is not None else []
        except Exception as exc:
            _inspect["errors"].append("services_list:" + _bounded_text(exc))
            _inspect["finished"] = True
            return
        services = services[:MAX_SERVICES]
        _inspect["services"] = [
            {"uuid": _bounded_text(service.UUID), "characteristics": None}
            for service in services
        ]
        if not services:
            _inspect["finished"] = True
            return
        for service in services:
            try:
                peripheral.discoverCharacteristics_forService_(None, service)
            except Exception as exc:
                _inspect["errors"].append(
                    "discover_characteristics:"
                    + (_bounded_text(service.UUID) or "unknown")
                    + ":"
                    + (_bounded_text(exc) or "unknown")
                )

    @objc_method
    def peripheral_didDiscoverCharacteristicsForService_error_(
        self, peripheral, service, error
    ):
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        service_uuid = _bounded_text(service.UUID)
        characteristics = []
        if error is not None:
            _inspect["errors"].append(
                "characteristics:"
                + (service_uuid or "unknown")
                + ":"
                + (_bounded_text(error) or "unknown")
            )
        else:
            try:
                values = (
                    list(service.characteristics)
                    if service.characteristics is not None
                    else []
                )
            except Exception as exc:
                _inspect["errors"].append(
                    "characteristics_list:"
                    + (service_uuid or "unknown")
                    + ":"
                    + (_bounded_text(exc) or "unknown")
                )
                values = []
            for characteristic in values[:MAX_CHARACTERISTICS_PER_SERVICE]:
                try:
                    properties = int(characteristic.properties)
                except Exception:
                    properties = None
                characteristics.append(
                    {
                        "uuid": _bounded_text(characteristic.UUID),
                        "properties": properties,
                        "readable": bool(properties & 0x02) if properties is not None else None,
                        "writable_without_response": bool(properties & 0x04)
                        if properties is not None
                        else None,
                        "writable": bool(properties & 0x08) if properties is not None else None,
                        "notifiable": bool(properties & 0x10) if properties is not None else None,
                        "indicatable": bool(properties & 0x20) if properties is not None else None,
                    }
                )
        for row in _inspect["services"]:
            if row["uuid"] == service_uuid:
                row["characteristics"] = characteristics
                break
        if _inspect["services"] and all(
            row["characteristics"] is not None for row in _inspect["services"]
        ):
            _inspect["finished"] = True


def _manager_ready(manager, seconds=0.8):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if int(manager.state) != 0:
            break
        time.sleep(0.05)
    return int(manager.state)


def _scan(manager, seconds, allow_duplicates):
    options = {"CBCentralManagerScanOptionAllowDuplicatesKey": bool(allow_duplicates)}
    manager.scanForPeripheralsWithServices_options_(None, options)
    time.sleep(seconds)
    manager.stopScan()


def _run(request):
    operation = request.get("operation")
    delegate = __DELEGATE_CLASS__.alloc().init()
    manager = CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)
    central_state = _manager_ready(manager)
    application_state = int(UIApplication.sharedApplication.applicationState)
    if central_state != 5:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_" + operation,
            "operation": operation,
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": False,
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }

    if operation == "scan":
        seconds = int(request["scan_seconds"])
        limit = int(request["limit"])
        _scan(manager, seconds, bool(request["allow_duplicates"]))
        ordered = _sort_devices(list(_devices.values()))
        rows = [_public_device(row) for row in ordered[:limit]]
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_scan",
            "operation": "scan",
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": True,
            "scan_seconds": seconds,
            "allow_duplicates": bool(request["allow_duplicates"]),
            "device_count": len(ordered),
            "devices": rows,
            "truncated": len(ordered) > len(rows),
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }

    device_id = request["device_id"]
    _scan(manager, int(request["scan_seconds"]), True)
    row = _devices.get(device_id)
    if row is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_inspect",
            "operation": "inspect",
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": True,
            "device_id": device_id,
            "found": False,
            "connected": False,
            "disconnected": False,
            "services": [],
            "errors": [],
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }

    public = _public_device(row)
    if row.get("connectable") is not True:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_inspect",
            "operation": "inspect",
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": True,
            "device_id": device_id,
            "found": True,
            "advertisement": public,
            "connected": False,
            "disconnected": False,
            "services": [],
            "errors": ["device_not_connectable"],
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }

    peripheral = row["_peripheral"]
    _inspect["target"] = peripheral
    try:
        manager.connectPeripheral_options_(peripheral, None)
        deadline = time.time() + int(request["discovery_seconds"])
        while time.time() < deadline and not _inspect["finished"]:
            time.sleep(0.05)
    except Exception as exc:
        _inspect["errors"].append("connect_start:" + (_bounded_text(exc) or "unknown"))
    finally:
        try:
            manager.cancelPeripheralConnection_(peripheral)
        except Exception as exc:
            _inspect["errors"].append("disconnect_start:" + (_bounded_text(exc) or "unknown"))
        time.sleep(0.25)

    services = []
    for service in _inspect["services"][:MAX_SERVICES]:
        services.append(
            {
                "uuid": service["uuid"],
                "characteristics": service["characteristics"] or [],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "ipad_bluetooth_inspect",
        "operation": "inspect",
        "application_state": application_state,
        "central_state": central_state,
        "bluetooth_powered_on": True,
        "device_id": device_id,
        "found": True,
        "advertisement": public,
        "connected": bool(_inspect["connected"]),
        "disconnected": bool(_inspect["disconnected"]),
        "services": services,
        "errors": _inspect["errors"][:32],
        "writes_attempted": False,
        "pairing_requested_by_tool": False,
    }


GRABOWSKI_RESULT = _run(_REQUEST)
'''


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_expected_started_at(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected_started_at must be non-empty")
    if len(value.encode("utf-8")) > MAX_EXPECTED_STARTED_AT_BYTES:
        raise ValueError("expected_started_at exceeds size limit")
    return value


def _validate_uuid(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("device_id must be a UUID string")
    normalized = value.strip().upper()
    if UUID_RE.fullmatch(normalized) is None:
        raise ValueError("device_id must be a canonical UUID")
    return normalized


def _bounded_int(value: int, *, minimum: int, maximum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _bluetooth_code(request: dict[str, Any]) -> tuple[str, str]:
    suffix = request.get("class_suffix")
    if not isinstance(suffix, str) or CLASS_SUFFIX_RE.fullmatch(suffix) is None:
        raise ValueError("class_suffix is invalid")
    encoded = base64.b64encode(_canonical_json_bytes(request)).decode("ascii")
    code = _BLUETOOTH_JOB_SOURCE.replace("__REQUEST_B64__", encoded).replace(
        "__DELEGATE_CLASS__", f"GrabowskiBLEDelegate_{suffix}"
    )
    return code, _sha256_bytes(code.encode("utf-8"))


def _validate_device_row(row: Any) -> None:
    if not isinstance(row, dict):
        raise RuntimeError("Bluetooth device row is not an object")
    identifier = row.get("id")
    if not isinstance(identifier, str) or UUID_RE.fullmatch(identifier) is None:
        raise RuntimeError("Bluetooth device row has invalid identifier")
    for key in ("name", "local_name", "manufacturer_data", "service_data"):
        value = row.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise RuntimeError(f"Bluetooth device {key} is not text")
            if len(value.encode("utf-8")) > MAX_DESCRIPTION_BYTES:
                raise RuntimeError(f"Bluetooth device {key} exceeds size limit")
    for key in ("rssi_last", "rssi_max", "tx_power"):
        value = row.get(key)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise RuntimeError(f"Bluetooth device {key} is invalid")
    seen = row.get("seen")
    if not isinstance(seen, int) or isinstance(seen, bool) or seen < 1:
        raise RuntimeError("Bluetooth device seen count is invalid")
    connectable = row.get("connectable")
    if connectable is not None and not isinstance(connectable, bool):
        raise RuntimeError("Bluetooth device connectable flag is invalid")
    for key in ("service_uuids", "overflow_service_uuids", "solicited_service_uuids"):
        values = row.get(key)
        if not isinstance(values, list) or len(values) > MAX_SERVICES:
            raise RuntimeError(f"Bluetooth device {key} is invalid")
        if any(not isinstance(item, str) or len(item.encode("utf-8")) > 128 for item in values):
            raise RuntimeError(f"Bluetooth device {key} contains invalid UUID text")


def _validate_service_row(row: Any) -> None:
    if not isinstance(row, dict):
        raise RuntimeError("Bluetooth service row is not an object")
    service_uuid = row.get("uuid")
    if not isinstance(service_uuid, str) or not service_uuid:
        raise RuntimeError("Bluetooth service UUID is invalid")
    characteristics = row.get("characteristics")
    if not isinstance(characteristics, list) or len(characteristics) > MAX_CHARACTERISTICS_PER_SERVICE:
        raise RuntimeError("Bluetooth characteristic list is invalid")
    for characteristic in characteristics:
        if not isinstance(characteristic, dict):
            raise RuntimeError("Bluetooth characteristic row is invalid")
        uuid_value = characteristic.get("uuid")
        if not isinstance(uuid_value, str) or not uuid_value:
            raise RuntimeError("Bluetooth characteristic UUID is invalid")
        properties = characteristic.get("properties")
        if properties is not None and (
            not isinstance(properties, int) or isinstance(properties, bool) or properties < 0
        ):
            raise RuntimeError("Bluetooth characteristic properties are invalid")
        for key in (
            "readable",
            "writable_without_response",
            "writable",
            "notifiable",
            "indicatable",
        ):
            flag = characteristic.get(key)
            if flag is not None and not isinstance(flag, bool):
                raise RuntimeError(f"Bluetooth characteristic {key} is invalid")


def _validate_device_result(request: dict[str, Any], result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise RuntimeError("Bluetooth device result is not an object")
    if len(_canonical_json_bytes(result)) > MAX_DEVICE_RESULT_BYTES:
        raise RuntimeError("Bluetooth device result exceeds transport bound")
    operation = request["operation"]
    if result.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("Bluetooth device result schema mismatch")
    if result.get("operation") != operation:
        raise RuntimeError("Bluetooth device result operation mismatch")
    if result.get("kind") != f"ipad_bluetooth_{operation}":
        raise RuntimeError("Bluetooth device result kind mismatch")
    if result.get("writes_attempted") is not False:
        raise RuntimeError("Bluetooth device result does not prove no-write execution")
    if result.get("pairing_requested_by_tool") is not False:
        raise RuntimeError("Bluetooth device result does not prove no-pairing intent")
    if not isinstance(result.get("central_state"), int):
        raise RuntimeError("Bluetooth central state is invalid")
    if not isinstance(result.get("application_state"), int):
        raise RuntimeError("Bluetooth application state is invalid")
    powered = result.get("bluetooth_powered_on")
    if not isinstance(powered, bool):
        raise RuntimeError("Bluetooth powered state is invalid")
    if not powered:
        return result

    if operation == "scan":
        devices = result.get("devices")
        if not isinstance(devices, list) or len(devices) > request["limit"]:
            raise RuntimeError("Bluetooth scan device list exceeds request bound")
        for row in devices:
            _validate_device_row(row)
        count = result.get("device_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < len(devices):
            raise RuntimeError("Bluetooth scan device count is invalid")
        if result.get("scan_seconds") != request["scan_seconds"]:
            raise RuntimeError("Bluetooth scan duration mismatch")
        if result.get("allow_duplicates") is not request["allow_duplicates"]:
            raise RuntimeError("Bluetooth duplicate-scan mode mismatch")
        if result.get("truncated") is not (count > len(devices)):
            raise RuntimeError("Bluetooth scan truncation projection is invalid")
        return result

    if result.get("device_id") != request["device_id"]:
        raise RuntimeError("Bluetooth inspect target mismatch")
    for key in ("found", "connected", "disconnected"):
        if not isinstance(result.get(key), bool):
            raise RuntimeError(f"Bluetooth inspect {key} flag is invalid")
    if result.get("found"):
        advertisement = result.get("advertisement")
        if not isinstance(advertisement, dict):
            raise RuntimeError("Bluetooth inspect advertisement is missing")
        _validate_device_row(advertisement)
        if advertisement.get("id") != request["device_id"]:
            raise RuntimeError("Bluetooth inspect advertisement target mismatch")
    services = result.get("services")
    if not isinstance(services, list) or len(services) > MAX_SERVICES:
        raise RuntimeError("Bluetooth inspect service list is invalid")
    for row in services:
        _validate_service_row(row)
    errors = result.get("errors")
    if not isinstance(errors, list) or len(errors) > 32 or any(not isinstance(item, str) for item in errors):
        raise RuntimeError("Bluetooth inspect errors are invalid")
    return result


def _run_typed_bluetooth_job(
    *,
    request: dict[str, Any],
    purpose: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    _validate_expected_started_at(expected_started_at)
    code, code_sha256 = _bluetooth_code(request)
    execution = bridge.grabowski_juno_run(
        code=code,
        code_sha256=code_sha256,
        purpose=purpose,
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
        timeout_seconds=20,
    )
    status = execution.get("status")
    terminal = isinstance(status, dict) and status.get("state") == "succeeded"
    result = status.get("result") if isinstance(status, dict) else None
    semantic_valid: bool | None = None
    semantic_error_type = None
    semantic_error = None
    if terminal:
        try:
            _validate_device_result(request, result)
            semantic_valid = True
        except Exception as exc:
            semantic_valid = False
            semantic_error_type = type(exc).__name__
            semantic_error = operator._redact(str(exc)[:300])
    receipt = bridge._write_receipt(
        "grabowski_juno_bluetooth_receipt",
        {
            "agent_id": bridge.AGENT_ID,
            "started_at": expected_started_at,
            "operation": request["operation"],
            "request_sha256": _sha256_bytes(_canonical_json_bytes(request)),
            "job_id": execution.get("job_id"),
            "code_sha256": code_sha256,
            "terminal_succeeded": terminal,
            "semantic_validation": {
                "valid": semantic_valid,
                "error_type": semantic_error_type,
                "error": semantic_error,
                "error_sha256": (
                    _sha256_bytes((semantic_error or "").encode("utf-8"))
                    if semantic_error is not None
                    else None
                ),
            },
            "result_sha256": (
                _sha256_bytes(_canonical_json_bytes(result)) if result is not None else None
            ),
            "does_not_establish": [
                "ownership of discovered Bluetooth devices",
                "Bluetooth MAC addresses",
                "precise physical distance from RSSI",
                "background Bluetooth scan entitlement",
                "characteristic value read authority",
                "characteristic write or device-control authority",
                "pairing or authentication bypass",
            ],
        },
    )
    if terminal and semantic_valid is not True:
        raise RuntimeError(
            "Juno Bluetooth result failed host semantic validation; "
            f"receipt_sha256={receipt.get('sha256')}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": bridge.AGENT_ID,
        "started_at": expected_started_at,
        "operation": request["operation"],
        "job_id": execution.get("job_id"),
        "status": status,
        "receipt": receipt,
    }


def _new_suffix() -> str:
    return secrets.token_hex(6)


@mcp.tool(name="ipad_bluetooth_scan", annotations=MUTATING)
def ipad_bluetooth_scan(
    expected_started_at: str,
    session_escalation: dict[str, Any],
    scan_seconds: int = 8,
    limit: int = 64,
    allow_duplicates: bool = True,
) -> dict[str, Any]:
    """Scan nearby BLE advertisements through the foreground-capable paired Juno iPad."""
    operator._require_operator_capability("terminal_execute")
    scan_seconds = _bounded_int(
        scan_seconds,
        minimum=MIN_SCAN_SECONDS,
        maximum=MAX_SCAN_SECONDS,
        label="scan_seconds",
    )
    limit = _bounded_int(limit, minimum=1, maximum=MAX_DEVICES, label="limit")
    if not isinstance(allow_duplicates, bool):
        raise ValueError("allow_duplicates must be boolean")
    request = {
        "schema_version": SCHEMA_VERSION,
        "operation": "scan",
        "scan_seconds": scan_seconds,
        "limit": limit,
        "allow_duplicates": allow_duplicates,
        "class_suffix": _new_suffix(),
    }
    return _run_typed_bluetooth_job(
        request=request,
        purpose="Scan bounded nearby BLE advertisements on the paired Juno iPad.",
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
    )


@mcp.tool(name="ipad_bluetooth_inspect", annotations=MUTATING)
def ipad_bluetooth_inspect(
    device_id: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    scan_seconds: int = 5,
    discovery_seconds: int = 7,
) -> dict[str, Any]:
    """Connect read-only to one discovered BLE identifier and enumerate GATT metadata."""
    operator._require_operator_capability("terminal_execute")
    device_id = _validate_uuid(device_id)
    scan_seconds = _bounded_int(
        scan_seconds,
        minimum=MIN_SCAN_SECONDS,
        maximum=MAX_INSPECT_SCAN_SECONDS,
        label="scan_seconds",
    )
    discovery_seconds = _bounded_int(
        discovery_seconds,
        minimum=1,
        maximum=MAX_DISCOVERY_SECONDS,
        label="discovery_seconds",
    )
    request = {
        "schema_version": SCHEMA_VERSION,
        "operation": "inspect",
        "device_id": device_id,
        "scan_seconds": scan_seconds,
        "discovery_seconds": discovery_seconds,
        "class_suffix": _new_suffix(),
    }
    return _run_typed_bluetooth_job(
        request=request,
        purpose=(
            "Inspect one exact BLE identifier on the paired Juno iPad by connecting, "
            "enumerating GATT services and characteristic metadata, and disconnecting "
            "without reading values, writing characteristics, subscribing, or pairing."
        ),
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
    )

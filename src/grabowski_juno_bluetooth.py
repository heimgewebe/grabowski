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
GATT_UUID_RE = re.compile(
    r"^(?:[0-9A-F]{4}|[0-9A-F]{8}|[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})$"
)
CLASS_SUFFIX_RE = re.compile(r"^[0-9a-f]{12}$")
MIN_SCAN_SECONDS = 1
MAX_SCAN_SECONDS = 12
MAX_INSPECT_SCAN_SECONDS = 8
MAX_DISCOVERY_SECONDS = 8
MAX_DEVICES = 128
MAX_SERVICES = 64
MAX_CHARACTERISTICS_PER_SERVICE = 128
MAX_READ_CHARACTERISTICS = 8
MAX_VALUE_BYTES = 4_096
MAX_TOTAL_VALUE_BYTES = 16 * 1024
MAX_DESCRIPTION_BYTES = 4_096
MAX_DEVICE_RESULT_BYTES = 256 * 1024
MAX_EXPECTED_STARTED_AT_BYTES = 128

_BLUETOOTH_JOB_SOURCE = r'''\
from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import time

from rubicon.objc import NSObject, ObjCClass, objc_method


SCHEMA_VERSION = 1
MAX_SERVICES = 64
MAX_CHARACTERISTICS_PER_SERVICE = 128
MAX_READ_CHARACTERISTICS = 8
MAX_VALUE_BYTES = 4096
MAX_TOTAL_VALUE_BYTES = 16384
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


def _mark_unresolved_reads(status, error=None):
    if _REQUEST.get("operation") != "read":
        return
    for characteristic_uuid in _REQUEST.get("characteristic_uuids", []):
        if characteristic_uuid in _inspect["read_values"]:
            continue
        row = {
            "uuid": characteristic_uuid,
            "status": status,
            "properties": None,
        }
        if error:
            row["error"] = _bounded_text(error) or "unknown"
        _inspect["read_values"][characteristic_uuid] = row


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
    "discovery_complete": False,
    "services": [],
    "characteristic_objects": {},
    "read_started": False,
    "read_pending": set(),
    "read_values": {},
    "read_attempted_count": 0,
    "read_bytes_total": 0,
    "errors": [],
}


def _start_characteristic_reads(peripheral):
    if _REQUEST.get("operation") != "read" or _inspect["read_started"]:
        return
    _inspect["read_started"] = True
    service_uuid = _REQUEST["service_uuid"]
    targets = []
    for characteristic_uuid in list(_REQUEST["characteristic_uuids"])[:MAX_READ_CHARACTERISTICS]:
        characteristic = _inspect["characteristic_objects"].get(
            (service_uuid, characteristic_uuid)
        )
        if characteristic is None:
            _inspect["read_values"][characteristic_uuid] = {
                "uuid": characteristic_uuid,
                "status": "not_found",
                "properties": None,
            }
            continue
        try:
            properties = int(characteristic.properties)
        except Exception:
            properties = None
        if properties is None or not bool(properties & 0x02):
            _inspect["read_values"][characteristic_uuid] = {
                "uuid": characteristic_uuid,
                "status": "not_readable",
                "properties": properties,
            }
            continue
        _inspect["read_values"][characteristic_uuid] = {
            "uuid": characteristic_uuid,
            "status": "pending",
            "properties": properties,
        }
        _inspect["read_pending"].add(characteristic_uuid)
        targets.append((characteristic_uuid, characteristic))

    _inspect["read_attempted_count"] = len(targets)
    for characteristic_uuid, characteristic in targets:
        try:
            peripheral.readValueForCharacteristic_(characteristic)
        except Exception as exc:
            _inspect["read_values"][characteristic_uuid] = {
                "uuid": characteristic_uuid,
                "status": "read_start_error",
                "properties": _inspect["read_values"][characteristic_uuid]["properties"],
                "error": _bounded_text(exc) or "unknown",
            }
            _inspect["read_pending"].discard(characteristic_uuid)
    if not _inspect["read_pending"]:
        _inspect["finished"] = True


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
            detail = _bounded_text(exc) or "unknown"
            _inspect["errors"].append("discover_services:" + detail)
            _mark_unresolved_reads("discovery_error", detail)
            _inspect["finished"] = True

    @objc_method
    def centralManager_didFailToConnectPeripheral_error_(self, central, peripheral, error):
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        detail = _bounded_text(error) or "unknown"
        _inspect["errors"].append("connect:" + detail)
        _mark_unresolved_reads("connect_error", detail)
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
            detail = _bounded_text(error) or "unknown"
            _inspect["errors"].append("services:" + detail)
            _mark_unresolved_reads("discovery_error", detail)
            _inspect["finished"] = True
            return
        try:
            services = list(peripheral.services) if peripheral.services is not None else []
        except Exception as exc:
            detail = _bounded_text(exc) or "unknown"
            _inspect["errors"].append("services_list:" + detail)
            _mark_unresolved_reads("discovery_error", detail)
            _inspect["finished"] = True
            return
        services = services[:MAX_SERVICES]
        if _REQUEST.get("operation") == "read":
            target_uuid = _REQUEST["service_uuid"]
            target_service = next(
                (
                    service
                    for service in services
                    if _bounded_text(service.UUID) == target_uuid
                ),
                None,
            )
            if target_service is None:
                _inspect["services"] = []
                _inspect["discovery_complete"] = True
                _mark_unresolved_reads("not_found")
                _inspect["finished"] = True
                return
            _inspect["services"] = [
                {"uuid": target_uuid, "characteristics": None}
            ]
            try:
                peripheral.discoverCharacteristics_forService_(None, target_service)
            except Exception as exc:
                detail = _bounded_text(exc) or "unknown"
                _inspect["errors"].append(
                    "discover_characteristics:" + target_uuid + ":" + detail
                )
                _inspect["discovery_complete"] = True
                _mark_unresolved_reads("discovery_error", detail)
                _inspect["finished"] = True
            return

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
            detail = _bounded_text(error) or "unknown"
            _inspect["errors"].append(
                "characteristics:"
                + (service_uuid or "unknown")
                + ":"
                + detail
            )
            if (
                _REQUEST.get("operation") == "read"
                and service_uuid == _REQUEST.get("service_uuid")
            ):
                for row in _inspect["services"]:
                    if row["uuid"] == service_uuid:
                        row["characteristics"] = []
                        break
                _inspect["discovery_complete"] = True
                _mark_unresolved_reads("discovery_error", detail)
                _inspect["finished"] = True
                return
        else:
            try:
                values = (
                    list(service.characteristics)
                    if service.characteristics is not None
                    else []
                )
            except Exception as exc:
                detail = _bounded_text(exc) or "unknown"
                _inspect["errors"].append(
                    "characteristics_list:"
                    + (service_uuid or "unknown")
                    + ":"
                    + detail
                )
                if (
                    _REQUEST.get("operation") == "read"
                    and service_uuid == _REQUEST.get("service_uuid")
                ):
                    for row in _inspect["services"]:
                        if row["uuid"] == service_uuid:
                            row["characteristics"] = []
                            break
                    _inspect["discovery_complete"] = True
                    _mark_unresolved_reads("discovery_error", detail)
                    _inspect["finished"] = True
                    return
                values = []
            for characteristic in values[:MAX_CHARACTERISTICS_PER_SERVICE]:
                characteristic_uuid = _bounded_text(characteristic.UUID)
                try:
                    properties = int(characteristic.properties)
                except Exception:
                    properties = None
                characteristics.append(
                    {
                        "uuid": characteristic_uuid,
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
                if service_uuid and characteristic_uuid:
                    _inspect["characteristic_objects"][
                        (service_uuid, characteristic_uuid)
                    ] = characteristic
        for row in _inspect["services"]:
            if row["uuid"] == service_uuid:
                row["characteristics"] = characteristics
                break
        if _inspect["services"] and all(
            row["characteristics"] is not None for row in _inspect["services"]
        ):
            _inspect["discovery_complete"] = True
            if _REQUEST.get("operation") == "read":
                _start_characteristic_reads(peripheral)
            else:
                _inspect["finished"] = True

    @objc_method
    def peripheral_didUpdateValueForCharacteristic_error_(
        self, peripheral, characteristic, error
    ):
        if _REQUEST.get("operation") != "read":
            return
        if _uuid(peripheral) != _REQUEST.get("device_id"):
            return
        characteristic_uuid = _bounded_text(characteristic.UUID)
        if characteristic_uuid not in _inspect["read_pending"]:
            return
        current = _inspect["read_values"].get(characteristic_uuid, {})
        properties = current.get("properties")
        if error is not None:
            _inspect["read_values"][characteristic_uuid] = {
                "uuid": characteristic_uuid,
                "status": "read_error",
                "properties": properties,
                "error": _bounded_text(error) or "unknown",
            }
        else:
            try:
                value = characteristic.value
                encoded = "" if value is None else str(value.base64EncodedStringWithOptions_(0))
                payload = base64.b64decode(encoded, validate=True) if encoded else b""
            except Exception as exc:
                _inspect["read_values"][characteristic_uuid] = {
                    "uuid": characteristic_uuid,
                    "status": "encode_error",
                    "properties": properties,
                    "error": _bounded_text(exc) or "unknown",
                }
            else:
                projected_total = _inspect["read_bytes_total"] + len(payload)
                if len(payload) > MAX_VALUE_BYTES or projected_total > MAX_TOTAL_VALUE_BYTES:
                    _inspect["read_values"][characteristic_uuid] = {
                        "uuid": characteristic_uuid,
                        "status": "value_too_large",
                        "properties": properties,
                        "size": len(payload),
                    }
                else:
                    _inspect["read_bytes_total"] = projected_total
                    _inspect["read_values"][characteristic_uuid] = {
                        "uuid": characteristic_uuid,
                        "status": "read",
                        "properties": properties,
                        "value_b64": encoded,
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
        _inspect["read_pending"].discard(characteristic_uuid)
        if _inspect["discovery_complete"] and not _inspect["read_pending"]:
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
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_" + operation,
            "operation": operation,
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": True,
            "device_id": device_id,
            "found": False,
            "connected": False,
            "disconnected": False,
            "errors": [],
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }
        if operation == "read":
            result.update({
                "service_uuid": request["service_uuid"],
                "characteristic_uuids": list(request["characteristic_uuids"]),
                "values": [
                    {"uuid": item, "status": "not_found", "properties": None}
                    for item in request["characteristic_uuids"]
                ],
                "read_attempted_count": 0,
                "subscriptions_attempted": False,
            })
        else:
            result["services"] = []
        return result

    public = _public_device(row)
    if row.get("connectable") is not True:
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_" + operation,
            "operation": operation,
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": True,
            "device_id": device_id,
            "found": True,
            "advertisement": public,
            "connected": False,
            "disconnected": False,
            "errors": ["device_not_connectable"],
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }
        if operation == "read":
            result.update({
                "service_uuid": request["service_uuid"],
                "characteristic_uuids": list(request["characteristic_uuids"]),
                "values": [
                    {"uuid": item, "status": "not_connectable", "properties": None}
                    for item in request["characteristic_uuids"]
                ],
                "read_attempted_count": 0,
                "subscriptions_attempted": False,
            })
        else:
            result["services"] = []
        return result

    peripheral = row["_peripheral"]
    _inspect["target"] = peripheral
    try:
        manager.connectPeripheral_options_(peripheral, None)
        deadline = time.time() + int(request["discovery_seconds"])
        while time.time() < deadline and not _inspect["finished"]:
            time.sleep(0.05)
        if operation == "read" and not _inspect["finished"]:
            if _inspect["read_pending"]:
                for characteristic_uuid in list(_inspect["read_pending"]):
                    current = _inspect["read_values"].get(characteristic_uuid, {})
                    _inspect["read_values"][characteristic_uuid] = {
                        "uuid": characteristic_uuid,
                        "status": "read_timeout",
                        "properties": current.get("properties"),
                    }
                _inspect["read_pending"].clear()
            if not _inspect["read_started"]:
                _mark_unresolved_reads("discovery_timeout")
            _inspect["finished"] = True
    except Exception as exc:
        detail = _bounded_text(exc) or "unknown"
        _inspect["errors"].append("connect_start:" + detail)
        _mark_unresolved_reads("connect_error", detail)
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
    if operation == "read":
        values = [
            _inspect["read_values"].get(
                characteristic_uuid,
                {"uuid": characteristic_uuid, "status": "unknown", "properties": None},
            )
            for characteristic_uuid in request["characteristic_uuids"]
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_bluetooth_read",
            "operation": "read",
            "application_state": application_state,
            "central_state": central_state,
            "bluetooth_powered_on": True,
            "device_id": device_id,
            "found": True,
            "advertisement": public,
            "connected": bool(_inspect["connected"]),
            "disconnected": bool(_inspect["disconnected"]),
            "service_uuid": request["service_uuid"],
            "characteristic_uuids": list(request["characteristic_uuids"]),
            "values": values,
            "read_attempted_count": int(_inspect["read_attempted_count"]),
            "subscriptions_attempted": False,
            "errors": _inspect["errors"][:32],
            "writes_attempted": False,
            "pairing_requested_by_tool": False,
        }
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


def _validate_gatt_uuid(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a UUID string")
    normalized = value.strip().upper()
    if GATT_UUID_RE.fullmatch(normalized) is None:
        raise ValueError(f"{label} must be a 16-bit, 32-bit, or canonical 128-bit UUID")
    return normalized


def _validate_characteristic_uuids(value: list[str]) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_READ_CHARACTERISTICS:
        raise ValueError(
            f"characteristic_uuids must contain between 1 and {MAX_READ_CHARACTERISTICS} UUIDs"
        )
    normalized = [
        _validate_gatt_uuid(item, label="characteristic_uuid") for item in value
    ]
    if len(normalized) != len(set(normalized)):
        raise ValueError("characteristic_uuids must be unique")
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
    if operation == "read":
        if result.get("service_uuid") != request["service_uuid"]:
            raise RuntimeError("Bluetooth read service target mismatch")
        if result.get("characteristic_uuids") != request["characteristic_uuids"]:
            raise RuntimeError("Bluetooth read characteristic target mismatch")
        if result.get("subscriptions_attempted") is not False:
            raise RuntimeError("Bluetooth read result does not prove no-subscription execution")
        attempted = result.get("read_attempted_count")
        if (
            not isinstance(attempted, int)
            or isinstance(attempted, bool)
            or attempted < 0
            or attempted > len(request["characteristic_uuids"])
        ):
            raise RuntimeError("Bluetooth read attempted count is invalid")
        values = result.get("values")
        if not isinstance(values, list):
            raise RuntimeError("Bluetooth read values are invalid")
        if result.get("found") and len(values) != len(request["characteristic_uuids"]):
            raise RuntimeError("Bluetooth read values do not cover exact requested characteristics")
        if [item.get("uuid") for item in values] != request["characteristic_uuids"]:
            raise RuntimeError("Bluetooth read value ordering or target identity is invalid")
        total = 0
        statuses = {
            "read",
            "not_found",
            "not_readable",
            "not_connectable",
            "connect_error",
            "discovery_error",
            "discovery_timeout",
            "read_error",
            "read_timeout",
            "read_start_error",
            "encode_error",
            "value_too_large",
            "unknown",
        }
        for item in values:
            if not isinstance(item, dict) or item.get("status") not in statuses:
                raise RuntimeError("Bluetooth read value row is invalid")
            properties = item.get("properties")
            if properties is not None and (
                not isinstance(properties, int) or isinstance(properties, bool) or properties < 0
            ):
                raise RuntimeError("Bluetooth read characteristic properties are invalid")
            if item["status"] == "read":
                encoded = item.get("value_b64")
                size = item.get("size")
                digest = item.get("sha256")
                if not isinstance(encoded, str) or not isinstance(size, int) or isinstance(size, bool):
                    raise RuntimeError("Bluetooth read payload metadata is invalid")
                try:
                    payload = base64.b64decode(encoded, validate=True)
                except Exception as exc:
                    raise RuntimeError("Bluetooth read payload encoding is invalid") from exc
                if size != len(payload) or size > MAX_VALUE_BYTES:
                    raise RuntimeError("Bluetooth read payload size is invalid")
                if digest != _sha256_bytes(payload):
                    raise RuntimeError("Bluetooth read payload digest mismatch")
                total += size
                if total > MAX_TOTAL_VALUE_BYTES:
                    raise RuntimeError("Bluetooth read total payload exceeds bound")
        errors = result.get("errors")
        if not isinstance(errors, list) or len(errors) > 32 or any(not isinstance(item, str) for item in errors):
            raise RuntimeError("Bluetooth read errors are invalid")
        return result

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
                "characteristic value read authority beyond the exact requested one-shot read",
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


@mcp.tool(name="ipad_bluetooth_read", annotations=MUTATING)
def ipad_bluetooth_read(
    device_id: str,
    service_uuid: str,
    characteristic_uuids: list[str],
    expected_started_at: str,
    session_escalation: dict[str, Any],
    scan_seconds: int = 5,
    discovery_seconds: int = 7,
) -> dict[str, Any]:
    """Read bounded values from exact readable BLE characteristics and disconnect."""
    operator._require_operator_capability("terminal_execute")
    device_id = _validate_uuid(device_id)
    service_uuid = _validate_gatt_uuid(service_uuid, label="service_uuid")
    characteristic_uuids = _validate_characteristic_uuids(characteristic_uuids)
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
        "operation": "read",
        "device_id": device_id,
        "service_uuid": service_uuid,
        "characteristic_uuids": characteristic_uuids,
        "scan_seconds": scan_seconds,
        "discovery_seconds": discovery_seconds,
        "class_suffix": _new_suffix(),
    }
    return _run_typed_bluetooth_job(
        request=request,
        purpose=(
            "Read bounded raw values from exact readable BLE characteristics on one exact "
            "paired-Juno-visible peripheral, then disconnect without writing, subscribing, "
            "requesting pairing, bypassing authentication, or interpreting values as commands."
        ),
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
    )

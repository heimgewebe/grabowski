#!/usr/bin/env python3
"""Bounded native iPad access bridge for the Grabowski Juno agent.

The module is deliberately import-safe on non-iOS Python.  It imports Juno's
Objective-C bridge only after dispatching an operation that needs native APIs.
No private content is read at import time or by the ``capabilities`` operation.
"""

from __future__ import annotations

import ctypes
from datetime import datetime
import hashlib
import os
import json
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any
from urllib.parse import quote, urlparse
import uuid

SCHEMA_VERSION = 1
MAX_TEXT_BYTES = 16 * 1024
MAX_QUERY_BYTES = 512
MAX_URL_BYTES = 4096
MAX_NOTIFICATION_TEXT_BYTES = 2048
MAX_RESULTS = 25
MAX_SCAN_SECONDS = 10.0
MAX_MOTION_TIMEOUT_SECONDS = 5.0
MAX_LOCATION_TIMEOUT_SECONDS = 8.0
MAX_MIC_SECONDS = 15.0
RETENTION_LIMIT = 128
ALLOWED_URL_SCHEMES = frozenset({"https", "http", "mailto", "maps", "shortcuts", "rm-juno"})
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_RETAINED: list[Any] = []
_RETAINED_LOCK = threading.Lock()

OPERATIONS = {
    "capabilities": {"private": False, "foreground": False},
    "status": {"private": False, "foreground": False},
    "clipboard_get_text": {"private": True, "foreground": False},
    "clipboard_set_text": {"private": False, "foreground": False},
    "open_url": {"private": False, "foreground": True},
    "notification_schedule": {"private": False, "foreground": False},
    "notification_remove": {"private": False, "foreground": False},
    "motion_sample": {"private": True, "foreground": True},
    "bluetooth_scan": {"private": True, "foreground": False},
    "contacts_search": {"private": True, "foreground": False},
    "reminders_list": {"private": True, "foreground": False},
    "reminder_create": {"private": False, "foreground": False},
    "location_one_shot": {"private": True, "foreground": True},
    "photos_latest_metadata": {"private": True, "foreground": False},
    "mic_record_short": {"private": True, "foreground": True},
    "replaykit_status": {"private": False, "foreground": False},
    "camera_photo_workspace": {"private": True, "foreground": True},
    "vision_ocr_workspace_image": {"private": True, "foreground": False},
    "vision_barcodes_workspace_image": {"private": True, "foreground": False},
    "shortcut_run": {"private": False, "foreground": True},
    "share_workspace_file": {"private": True, "foreground": True},
    "share_text": {"private": False, "foreground": True},
}


def _result(operation: str, **payload: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_juno_access_bridge",
        "operation": operation,
        **payload,
    }


def _require_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    if request.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported schema_version")
    operation = request.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ValueError("unsupported operation")
    return request


def _private_ack(request: dict[str, Any]) -> None:
    if request.get("private_content_ack") is not True:
        raise ValueError("private_content_ack=true is required for this operation")


def _string(
    request: dict[str, Any],
    name: str,
    *,
    required: bool = True,
    max_bytes: int = MAX_TEXT_BYTES,
    allow_empty: bool = False,
) -> str:
    value = request.get(name)
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{name} must be non-empty")
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"{name} exceeds byte bound")
    return value


def _integer(
    request: dict[str, Any],
    name: str,
    *,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int:
    value = request.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is out of range")
    return value


def _number(
    request: dict[str, Any],
    name: str,
    *,
    minimum: float,
    maximum: float,
    default: float | None = None,
) -> float:
    value = request.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    value = float(value)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is out of range")
    return value


def _identifier(request: dict[str, Any], name: str = "identifier") -> str:
    value = _string(request, name, max_bytes=128)
    if not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"{name} has invalid characters")
    return value


def _bind_objc_delegate_method(function: Any, objc: Any) -> Any:
    # Rubicon derives Objective-C method signatures from annotations.
    # typing.Any is not a ctypes-compatible native type, so dynamic delegate
    # methods are rebound to ObjCInstance only at runtime.
    argument_names = function.__code__.co_varnames[: function.__code__.co_argcount]
    function.__annotations__ = {name: objc.ObjCInstance for name in argument_names}
    function.__annotations__["return"] = type(None)
    return function


def _retain(value: Any) -> Any:
    with _RETAINED_LOCK:
        if len(_RETAINED) >= RETENTION_LIMIT:
            raise RuntimeError("native retention bound exhausted")
        _RETAINED.append(value)
    return value


def _release(value: Any) -> None:
    with _RETAINED_LOCK:
        for index, item in enumerate(_RETAINED):
            if item is value:
                del _RETAINED[index]
                return


def _objc() -> Any:
    import importlib
    return importlib.import_module("juno.objc")


def _zero(value: Any) -> Any:
    return value() if callable(value) else value


def _obj(value: Any) -> Any:
    if isinstance(value, int):
        return _objc().ObjCInstance(value)
    return value


def _on_main(function: Any) -> Any:
    decorated = _objc().on_main_thread(function)
    return decorated()


def _foreground_state() -> int:
    objc = _objc()
    app = _zero(objc.ObjCClass("UIApplication").sharedApplication)
    return int(_zero(app.applicationState))


def _require_foreground() -> None:
    state = _foreground_state()
    if state != 0:
        raise RuntimeError(f"Juno must be foreground; applicationState={state}")


def _array_items(value: Any, limit: int) -> list[Any]:
    value = _obj(value)
    try:
        count = len(value)
        return [value[index] for index in range(min(count, limit))]
    except (TypeError, AttributeError, KeyError):
        pass
    count = int(_zero(value.count))
    return [value.objectAtIndex_(index) for index in range(min(count, limit))]


def _date_text(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(value)
    except Exception:
        return None


def _class_available(name: str) -> bool:
    try:
        _objc().ObjCClass(name)
        return True
    except Exception:
        return False


def _capabilities(_request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    return _result(
        "capabilities",
        operations={
            name: {
                "private_content_ack_required": bool(meta["private"]),
                "foreground_required": bool(meta["foreground"]),
            }
            for name, meta in sorted(OPERATIONS.items())
        },
        bounds={
            "max_text_bytes": MAX_TEXT_BYTES,
            "max_query_bytes": MAX_QUERY_BYTES,
            "max_url_bytes": MAX_URL_BYTES,
            "max_results": MAX_RESULTS,
            "max_bluetooth_scan_seconds": MAX_SCAN_SECONDS,
            "max_mic_seconds": MAX_MIC_SECONDS,
        },
        guarantees=[
            "no native permission is requested implicitly",
            "no private content is read at import",
            "bluetooth scan does not connect or perform GATT",
            "photo operation returns metadata only",
            "replaykit operation is status-only",
        ],
    )


def _status(_request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    objc = _objc()
    ObjCClass = objc.ObjCClass
    status: dict[str, Any] = {"application_state": _foreground_state(), "classes": {}}
    for name in (
        "UIPasteboard",
        "UNUserNotificationCenter",
        "CMMotionManager",
        "CBCentralManager",
        "CNContactStore",
        "EKEventStore",
        "CLLocationManager",
        "PHPhotoLibrary",
        "AVAudioRecorder",
        "RPScreenRecorder",
        "AVCaptureDevice",
        "ARSession",
        "VNRecognizeTextRequest",
        "VNDetectBarcodesRequest",
    ):
        status["classes"][name] = _class_available(name)
    permissions: dict[str, Any] = {}
    try:
        permissions["contacts"] = int(ObjCClass("CNContactStore").authorizationStatusForEntityType_(0))
    except Exception:
        pass
    try:
        permissions["reminders"] = int(ObjCClass("EKEventStore").authorizationStatusForEntityType_(1))
    except Exception:
        pass
    try:
        permissions["motion"] = int(_zero(ObjCClass("CMMotionActivityManager").authorizationStatus))
    except Exception:
        pass
    try:
        permissions["bluetooth"] = int(_zero(ObjCClass("CBManager").authorization))
    except Exception:
        try:
            permissions["bluetooth"] = int(_zero(ObjCClass("CBCentralManager").authorization))
        except Exception:
            pass
    try:
        manager = ObjCClass("CLLocationManager")
        permissions["location"] = {
            "authorization": int(_zero(manager.authorizationStatus)),
            "services_enabled": bool(_zero(manager.locationServicesEnabled)),
        }
    except Exception:
        pass
    try:
        permissions["photos"] = int(ObjCClass("PHPhotoLibrary").authorizationStatusForAccessLevel_(2))
    except Exception:
        pass
    try:
        permissions["camera"] = int(ObjCClass("AVCaptureDevice").authorizationStatusForMediaType_("vide"))
        permissions["microphone"] = int(ObjCClass("AVCaptureDevice").authorizationStatusForMediaType_("soun"))
    except Exception:
        pass
    status["permissions"] = permissions
    return _result("status", status=status)


def _clipboard_get(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    objc = _objc()
    pasteboard = _zero(objc.ObjCClass("UIPasteboard").generalPasteboard)
    value = _zero(pasteboard.string)
    if value is None:
        return _result("clipboard_get_text", present=False, text="")
    text = str(value)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_TEXT_BYTES:
        raise RuntimeError("clipboard text exceeds bridge bound")
    return _result("clipboard_get_text", present=True, text=text, size=len(encoded))


def _clipboard_set(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    text = _string(request, "text", allow_empty=True)
    objc = _objc()
    def apply() -> None:
        pasteboard = _zero(objc.ObjCClass("UIPasteboard").generalPasteboard)
        pasteboard.setString_(text)
    _on_main(apply)
    return _result("clipboard_set_text", size=len(text.encode("utf-8")))


def _open_url(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    url_text = _string(request, "url", max_bytes=MAX_URL_BYTES)
    scheme = urlparse(url_text).scheme.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise ValueError("URL scheme is not allowlisted")
    _require_foreground()
    objc = _objc()
    NSURL = objc.ObjCClass("NSURL")
    native_url = NSURL.URLWithString_(url_text)
    if native_url is None:
        raise ValueError("URL could not be parsed")
    app = _zero(objc.ObjCClass("UIApplication").sharedApplication)
    can_open = bool(app.canOpenURL_(native_url))
    if not can_open:
        return _result("open_url", scheme=scheme, can_open=False, opened=False)
    holder = {"opened": False}
    done = threading.Event()
    def completed(opened: bool) -> None:
        holder["opened"] = bool(opened)
        done.set()
        _release(block)
    block = _retain(objc.Block(completed, None, ctypes.c_bool))
    def invoke() -> None:
        app.openURL_options_completionHandler_(native_url, objc.ns({}), block)
    try:
        _on_main(invoke)
    except Exception:
        _release(block)
        raise
    if not done.wait(5.0):
        raise RuntimeError("openURL callback timed out")
    return _result("open_url", scheme=scheme, can_open=True, opened=holder["opened"])


def _notification_schedule(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    identifier = _identifier(request)
    title = _string(request, "title", max_bytes=MAX_NOTIFICATION_TEXT_BYTES)
    body = _string(request, "body", required=False, allow_empty=True, max_bytes=MAX_NOTIFICATION_TEXT_BYTES)
    delay = _number(request, "delay_seconds", minimum=1.0, maximum=7 * 86400.0)
    objc = _objc()
    content = objc.ObjCClass("UNMutableNotificationContent").alloc().init()
    content.setTitle_(title)
    content.setBody_(body)
    trigger = objc.ObjCClass("UNTimeIntervalNotificationTrigger").triggerWithTimeInterval_repeats_(delay, False)
    native_request = objc.ObjCClass("UNNotificationRequest").requestWithIdentifier_content_trigger_(
        identifier, content, trigger
    )
    center = _zero(objc.ObjCClass("UNUserNotificationCenter").currentNotificationCenter)
    done = threading.Event()
    holder = {"error": False}
    def completed(error_ptr: int) -> None:
        holder["error"] = bool(error_ptr)
        done.set()
        _release(block)
    block = _retain(objc.Block(completed, None, ctypes.c_void_p))
    center.addNotificationRequest_withCompletionHandler_(native_request, block)
    if not done.wait(5.0):
        raise RuntimeError("notification scheduling callback timed out")
    if holder["error"]:
        raise RuntimeError("notification scheduling returned an error")
    return _result("notification_schedule", identifier=identifier, delay_seconds=delay)


def _notification_remove(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    identifier = _identifier(request)
    objc = _objc()
    center = _zero(objc.ObjCClass("UNUserNotificationCenter").currentNotificationCenter)
    identifiers = objc.ns([identifier])
    center.removePendingNotificationRequestsWithIdentifiers_(identifiers)
    center.removeDeliveredNotificationsWithIdentifiers_(identifiers)
    return _result("notification_remove", identifier=identifier)


def _motion_sample(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    timeout = _number(
        request, "timeout_seconds", minimum=0.2, maximum=MAX_MOTION_TIMEOUT_SECONDS, default=2.0
    )
    _require_foreground()
    objc = _objc()
    auth = int(_zero(objc.ObjCClass("CMMotionActivityManager").authorizationStatus))
    if auth != 3:
        raise RuntimeError(f"motion authorization is not granted; status={auth}")
    manager = _retain(objc.ObjCClass("CMMotionManager").alloc().init())
    if not _native_bool_property(manager, "accelerometerAvailable", "isAccelerometerAvailable"):
        _release(manager)
        raise RuntimeError("accelerometer is unavailable")
    try:
        _on_main(manager.startAccelerometerUpdates)
        deadline = time.monotonic() + timeout
        data = None
        while time.monotonic() < deadline:
            data = _zero(manager.accelerometerData)
            if data is not None:
                break
            time.sleep(0.05)
        if data is None:
            raise RuntimeError("motion sample timed out")
        acceleration = _zero(data.acceleration)
        return _result(
            "motion_sample",
            sample={
                "x": float(acceleration.field_0),
                "y": float(acceleration.field_1),
                "z": float(acceleration.field_2),
                "timestamp": float(_zero(data.timestamp)),
            },
        )
    finally:
        try:
            _on_main(manager.stopAccelerometerUpdates)
        finally:
            _release(manager)


def _bluetooth_scan(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    duration = _number(request, "duration_seconds", minimum=0.5, maximum=MAX_SCAN_SECONDS, default=3.0)
    limit = _integer(request, "max_results", minimum=1, maximum=MAX_RESULTS, default=10)
    objc = _objc()
    try:
        auth = int(_zero(objc.ObjCClass("CBManager").authorization))
    except Exception:
        auth = int(_zero(objc.ObjCClass("CBCentralManager").authorization))
    if auth != 3:
        raise RuntimeError(f"bluetooth authorization is not granted; status={auth}")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    done = threading.Event()

    def centralManagerDidUpdateState_(self: Any, central: Any) -> None:
        return None

    def centralManager_didDiscoverPeripheral_advertisementData_RSSI_(
        self: Any, central: Any, peripheral: Any, advertisement: Any, rssi: Any
    ) -> None:
        if len(results) >= limit:
            return
        try:
            identifier_obj = _zero(peripheral.identifier)
            identifier = str(_zero(identifier_obj.UUIDString))
        except Exception:
            identifier = ""
        if not identifier or identifier in seen:
            return
        seen.add(identifier)
        try:
            name_value = _zero(peripheral.name)
            name = None if name_value is None else str(name_value)[:256]
        except Exception:
            name = None
        try:
            rssi_value = int(_zero(rssi.intValue))
        except Exception:
            try:
                rssi_value = int(rssi)
            except Exception:
                rssi_value = None
        results.append({"identifier": identifier[:128], "name": name, "rssi": rssi_value})
        if len(results) >= limit:
            done.set()

    Delegate = objc.create_objc_class(
        "GrabowskiBluetoothDelegate_" + uuid.uuid4().hex,
        superclass=objc.ObjCClass("NSObject"),
        methods=[
            _bind_objc_delegate_method(centralManagerDidUpdateState_, objc),
            _bind_objc_delegate_method(
                centralManager_didDiscoverPeripheral_advertisementData_RSSI_, objc
            ),
        ],
    )
    delegate = _retain(Delegate.alloc().init())
    manager_holder: dict[str, Any] = {}
    def create_manager() -> None:
        manager_holder["manager"] = _retain(
            objc.ObjCClass("CBCentralManager").alloc().initWithDelegate_queue_options_(
                delegate, None, None
            )
        )
    _on_main(create_manager)
    manager = manager_holder["manager"]
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and int(_zero(manager.state)) != 5:
        time.sleep(0.1)
    if int(_zero(manager.state)) != 5:
        _release(manager)
        _release(delegate)
        raise RuntimeError(f"bluetooth central is not powered on; state={int(_zero(manager.state))}")
    def start() -> None:
        manager.scanForPeripheralsWithServices_options_(None, None)
    def stop() -> None:
        manager.stopScan()
    try:
        _on_main(start)
        done.wait(duration)
    finally:
        try:
            _on_main(stop)
        finally:
            _release(manager)
            _release(delegate)
    return _result("bluetooth_scan", duration_seconds=duration, devices=results)


def _contact_value_items(array: Any, *, phone: bool, limit: int = 8) -> list[str]:
    values: list[str] = []
    for labeled in _array_items(array, limit):
        try:
            value = _zero(labeled.value)
            if phone:
                value = _zero(value.stringValue)
            text = str(value)
        except Exception:
            continue
        if text and text not in values:
            values.append(text[:512])
    return values


def _contacts_search(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    query = _string(request, "query", max_bytes=MAX_QUERY_BYTES)
    limit = _integer(request, "max_results", minimum=1, maximum=MAX_RESULTS, default=10)
    objc = _objc()
    Store = objc.ObjCClass("CNContactStore")
    auth = int(Store.authorizationStatusForEntityType_(0))
    if auth != 3:
        raise RuntimeError(f"contacts authorization is not granted; status={auth}")
    store = Store.alloc().init()
    predicate = objc.ObjCClass("CNContact").predicateForContactsMatchingName_(query)
    keys = objc.ns(["givenName", "familyName", "organizationName", "emailAddresses", "phoneNumbers"])
    contacts = store.unifiedContactsMatchingPredicate_keysToFetch_error_(predicate, keys, None)
    if isinstance(contacts, tuple):
        contacts = contacts[0]
    output: list[dict[str, Any]] = []
    for contact in _array_items(contacts, limit):
        given = str(_zero(contact.givenName) or "")
        family = str(_zero(contact.familyName) or "")
        organization = str(_zero(contact.organizationName) or "")
        output.append(
            {
                "given_name": given[:256],
                "family_name": family[:256],
                "organization": organization[:256],
                "emails": _contact_value_items(_zero(contact.emailAddresses), phone=False),
                "phones": _contact_value_items(_zero(contact.phoneNumbers), phone=True),
            }
        )
    return _result("contacts_search", query=query, contacts=output)


def _reminders_list(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    limit = _integer(request, "max_results", minimum=1, maximum=MAX_RESULTS, default=10)
    objc = _objc()
    Store = objc.ObjCClass("EKEventStore")
    auth = int(Store.authorizationStatusForEntityType_(1))
    if auth != 3:
        raise RuntimeError(f"reminders authorization is not granted; status={auth}")
    store = _retain(Store.alloc().init())
    predicate = store.predicateForRemindersInCalendars_(None)
    done = threading.Event()
    holder: dict[str, Any] = {}
    def completed(reminders_ptr: int) -> None:
        holder["reminders"] = _obj(reminders_ptr) if reminders_ptr else None
        done.set()
        _release(block)
    block = _retain(objc.Block(completed, None, ctypes.c_void_p))
    store.fetchRemindersMatchingPredicate_completion_(predicate, block)
    if not done.wait(5.0):
        raise RuntimeError("reminder fetch callback timed out")
    output: list[dict[str, Any]] = []
    reminders = holder.get("reminders")
    if reminders is not None:
        for reminder in _array_items(reminders, limit):
            output.append(
                {
                    "identifier": str(_zero(reminder.calendarItemIdentifier) or "")[:256],
                    "title": str(_zero(reminder.title) or "")[:1024],
                    "completed": bool(_zero(reminder.completed)),
                    "due": _date_text(_zero(reminder.dueDateComponents)),
                }
            )
    _release(store)
    return _result("reminders_list", reminders=output)


def _reminder_create(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    title = _string(request, "title", max_bytes=MAX_NOTIFICATION_TEXT_BYTES)
    due_text = _string(request, "due", required=False, allow_empty=True, max_bytes=128)
    objc = _objc()
    Store = objc.ObjCClass("EKEventStore")
    auth = int(Store.authorizationStatusForEntityType_(1))
    if auth != 3:
        raise RuntimeError(f"reminders authorization is not granted; status={auth}")
    store = Store.alloc().init()
    reminder = objc.ObjCClass("EKReminder").reminderWithEventStore_(store)
    reminder.setTitle_(title)
    calendar = _zero(store.defaultCalendarForNewReminders)
    if calendar is None:
        raise RuntimeError("no default reminders calendar is available")
    reminder.setCalendar_(calendar)
    if due_text:
        try:
            due = datetime.fromisoformat(due_text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("due must be ISO-8601") from exc
        components = objc.ObjCClass("NSDateComponents").alloc().init()
        components.setYear_(due.year)
        components.setMonth_(due.month)
        components.setDay_(due.day)
        components.setHour_(due.hour)
        components.setMinute_(due.minute)
        reminder.setDueDateComponents_(components)
    saved = store.saveReminder_commit_error_(reminder, True, None)
    if isinstance(saved, tuple):
        saved = saved[0]
    if not bool(saved):
        raise RuntimeError("reminder save failed")
    return _result(
        "reminder_create",
        identifier=str(_zero(reminder.calendarItemIdentifier) or "")[:256],
        title=title,
    )


def _location_one_shot(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    timeout = _number(
        request, "timeout_seconds", minimum=1.0, maximum=MAX_LOCATION_TIMEOUT_SECONDS, default=5.0
    )
    _require_foreground()
    objc = _objc()
    Manager = objc.ObjCClass("CLLocationManager")
    auth = int(_zero(Manager.authorizationStatus))
    if auth not in {3, 4}:
        raise RuntimeError(f"location authorization is not granted; status={auth}")
    manager = _retain(Manager.alloc().init())
    try:
        try:
            manager.setDesiredAccuracy_(100.0)
        except Exception:
            pass
        _on_main(manager.startUpdatingLocation)
        deadline = time.monotonic() + timeout
        location = None
        while time.monotonic() < deadline:
            candidate = _zero(manager.location)
            if candidate is not None:
                try:
                    if float(_zero(candidate.horizontalAccuracy)) >= 0:
                        location = candidate
                        break
                except Exception:
                    location = candidate
                    break
            time.sleep(0.1)
        if location is None:
            raise RuntimeError("location request timed out")
        coordinate = _zero(location.coordinate)
        return _result(
            "location_one_shot",
            location={
                "latitude": round(float(coordinate.field_0), 6),
                "longitude": round(float(coordinate.field_1), 6),
                "horizontal_accuracy_m": round(float(_zero(location.horizontalAccuracy)), 2),
                "altitude_m": round(float(_zero(location.altitude)), 2),
                "timestamp": _date_text(_zero(location.timestamp)),
            },
        )
    finally:
        try:
            _on_main(manager.stopUpdatingLocation)
        finally:
            _release(manager)


def _photos_latest_metadata(request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    limit = _integer(request, "max_results", minimum=1, maximum=MAX_RESULTS, default=10)
    objc = _objc()
    Library = objc.ObjCClass("PHPhotoLibrary")
    auth = int(Library.authorizationStatusForAccessLevel_(2))
    if auth not in {3, 4}:
        raise RuntimeError(f"photo authorization is not granted; status={auth}")
    options = objc.ObjCClass("PHFetchOptions").alloc().init()
    newest_first = objc.ObjCClass("NSSortDescriptor").sortDescriptorWithKey_ascending_(
        "creationDate", False
    )
    options.setSortDescriptors_(objc.ns([newest_first]))
    options.setFetchLimit_(limit)
    assets = objc.ObjCClass("PHAsset").fetchAssetsWithOptions_(options)
    count = min(int(_zero(assets.count)), limit)
    output: list[dict[str, Any]] = []
    for index in range(count):
        asset = assets.objectAtIndex_(index)
        output.append(
            {
                "local_identifier": str(_zero(asset.localIdentifier) or "")[:256],
                "media_type": int(_zero(asset.mediaType)),
                "width": int(_zero(asset.pixelWidth)),
                "height": int(_zero(asset.pixelHeight)),
                "duration_seconds": round(float(_zero(asset.duration)), 3),
                "favorite": bool(_zero(asset.favorite)),
                "hidden": bool(_zero(asset.hidden)),
                "creation_date": _date_text(_zero(asset.creationDate)),
            }
        )
    return _result("photos_latest_metadata", assets=output)


def _safe_workspace_path(workspace: Path | None, relative_text: str) -> Path:
    if workspace is None:
        raise RuntimeError("operation requires an explicit Grabowski workspace")
    root = Path(workspace).resolve(strict=False)
    relative = Path(relative_text)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("relative_path must stay within the Grabowski workspace")
    target = (root / relative).resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("relative_path escapes the Grabowski workspace") from exc
    return target


def _mic_record_short(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    duration = _number(request, "duration_seconds", minimum=0.2, maximum=MAX_MIC_SECONDS, default=5.0)
    relative_path = _string(request, "relative_path", max_bytes=512)
    target = _safe_workspace_path(workspace, relative_path)
    if target.suffix.lower() != ".caf":
        raise ValueError("relative_path must end in .caf")
    _require_foreground()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError("recording target already exists")
    objc = _objc()
    auth = int(objc.ObjCClass("AVCaptureDevice").authorizationStatusForMediaType_("soun"))
    if auth != 3:
        raise RuntimeError(f"microphone authorization is not granted; status={auth}")
    audio_session = _zero(objc.ObjCClass("AVAudioSession").sharedInstance)

    def bool_result(value: Any) -> bool:
        if isinstance(value, tuple):
            value = value[0]
        return bool(value)

    if not bool_result(audio_session.setCategory_error_("AVAudioSessionCategoryRecord", None)):
        raise RuntimeError("audio session record category could not be set")
    if not bool_result(audio_session.setActive_error_(True, None)):
        raise RuntimeError("audio session could not be activated")
    try:
        url = objc.ObjCClass("NSURL").fileURLWithPath_(str(target))
        settings = objc.ns(
            {
                "AVFormatIDKey": 1819304813,
                "AVSampleRateKey": 44100.0,
                "AVNumberOfChannelsKey": 1,
                "AVLinearPCMBitDepthKey": 16,
                "AVLinearPCMIsFloatKey": False,
                "AVLinearPCMIsBigEndianKey": False,
            }
        )
        recorder = objc.ObjCClass("AVAudioRecorder").alloc().initWithURL_settings_error_(url, settings, None)
        if isinstance(recorder, tuple):
            recorder = recorder[0]
        if recorder is None:
            raise RuntimeError("AVAudioRecorder could not be created")
        if not bool(recorder.prepareToRecord()):
            raise RuntimeError("audio recorder preparation failed")
        started = {"ok": False}

        def start() -> None:
            started["ok"] = bool(recorder.recordForDuration_(duration))

        _on_main(start)
        if not started["ok"]:
            raise RuntimeError("audio recorder did not start")
        deadline = time.monotonic() + duration + 2.0
        while time.monotonic() < deadline and _native_bool_property(
            recorder, "recording", "isRecording"
        ):
            time.sleep(0.1)
        if _native_bool_property(recorder, "recording", "isRecording"):
            recorder.stop()
            raise RuntimeError("audio recorder exceeded duration bound")
        if not target.is_file():
            raise RuntimeError("audio recorder produced no file")
        return _result(
            "mic_record_short",
            relative_path=relative_path,
            size=target.stat().st_size,
            duration_seconds=duration,
        )
    finally:
        try:
            audio_session.setActive_error_(False, None)
        except Exception:
            pass


def _write_bytes_create_only(target: Path, payload: bytes) -> None:
    if len(payload) > 64 * 1024 * 1024:
        raise RuntimeError("binary payload exceeds bridge bound")
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def _camera_photo_workspace(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    relative_path = _string(request, "relative_path", max_bytes=512)
    target = _safe_workspace_path(workspace, relative_path)
    if target.suffix.lower() not in {".jpg", ".jpeg"}:
        raise ValueError("relative_path must end in .jpg or .jpeg")
    timeout = _number(request, "timeout_seconds", minimum=2.0, maximum=12.0, default=8.0)
    _require_foreground()
    if target.exists():
        raise FileExistsError("camera target already exists")
    objc = _objc()
    Device = objc.ObjCClass("AVCaptureDevice")
    auth = int(Device.authorizationStatusForMediaType_("vide"))
    if auth != 3:
        raise RuntimeError(f"camera authorization is not granted; status={auth}")
    device = Device.defaultDeviceWithMediaType_("vide")
    if device is None:
        raise RuntimeError("default camera is unavailable")
    capture_input = objc.ObjCClass("AVCaptureDeviceInput").deviceInputWithDevice_error_(device, None)
    if isinstance(capture_input, tuple):
        capture_input = capture_input[0]
    if capture_input is None:
        raise RuntimeError("camera input could not be created")
    session = _retain(objc.ObjCClass("AVCaptureSession").alloc().init())
    output = _retain(objc.ObjCClass("AVCapturePhotoOutput").alloc().init())
    if not bool(session.canAddInput_(capture_input)):
        _release(output)
        _release(session)
        raise RuntimeError("capture session rejected camera input")
    session.addInput_(capture_input)
    if not bool(session.canAddOutput_(output)):
        _release(output)
        _release(session)
        raise RuntimeError("capture session rejected photo output")
    session.addOutput_(output)
    done = threading.Event()
    holder: dict[str, Any] = {}

    def captureOutput_didFinishProcessingPhoto_error_(
        self: Any, capture_output: Any, photo: Any, error: Any
    ) -> None:
        try:
            if error:
                holder["error"] = "capture_error"
                return
            photo = _obj(photo)
            data = _zero(photo.fileDataRepresentation)
            if data is None:
                holder["error"] = "empty_photo_data"
                return
            payload = objc.nsdata_to_bytes(data)
            if not payload:
                holder["error"] = "empty_photo_payload"
                return
            holder["payload"] = bytes(payload)
        except Exception as exc:
            holder["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        finally:
            done.set()

    options: dict[str, Any] = {}
    protocol = getattr(objc, "ObjCProtocol", None)
    if protocol is not None:
        try:
            options["protocols"] = [protocol("AVCapturePhotoCaptureDelegate")]
        except Exception:
            pass
    Delegate = objc.create_objc_class(
        "GrabowskiPhotoCaptureDelegate_" + uuid.uuid4().hex,
        superclass=objc.ObjCClass("NSObject"),
        methods=[
            _bind_objc_delegate_method(captureOutput_didFinishProcessingPhoto_error_, objc)
        ],
        **options,
    )
    delegate = _retain(Delegate.alloc().init())
    settings = _zero(objc.ObjCClass("AVCapturePhotoSettings").photoSettings)
    try:
        session.startRunning()
        output.capturePhotoWithSettings_delegate_(settings, delegate)
        if not done.wait(timeout):
            raise RuntimeError("camera photo capture timed out")
        payload = holder.get("payload")
        if not isinstance(payload, bytes):
            raise RuntimeError(f"camera photo capture failed: {holder.get('error', 'unknown')}")
        _write_bytes_create_only(target, payload)
        return _result(
            "camera_photo_workspace",
            relative_path=relative_path,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            format="jpeg",
        )
    finally:
        try:
            session.stopRunning()
        finally:
            _release(delegate)
            _release(output)
            _release(session)


def _workspace_image_path(request: dict[str, Any], workspace: Path | None) -> tuple[Path, str]:
    relative_path = _string(request, "relative_path", max_bytes=512)
    target = _safe_workspace_path(workspace, relative_path)
    if target.suffix.lower() not in {".jpg", ".jpeg", ".png", ".heic", ".tif", ".tiff"}:
        raise ValueError("relative_path is not an allowlisted image type")
    if not target.is_file():
        raise FileNotFoundError("workspace image does not exist")
    size = target.stat().st_size
    if size <= 0 or size > 64 * 1024 * 1024:
        raise RuntimeError("workspace image size is outside the bridge bound")
    return target, relative_path


def _perform_vision_request(target: Path, request_object: Any) -> None:
    objc = _objc()
    url = objc.ObjCClass("NSURL").fileURLWithPath_(str(target))
    handler = objc.ObjCClass("VNImageRequestHandler").alloc().initWithURL_options_(url, objc.ns({}))
    result = handler.performRequests_error_(objc.ns([request_object]), None)
    if isinstance(result, tuple):
        result = result[0]
    if not bool(result):
        raise RuntimeError("Vision request failed")


def _vision_ocr_workspace_image(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    target, relative_path = _workspace_image_path(request, workspace)
    max_results = _integer(request, "max_results", minimum=1, maximum=MAX_RESULTS, default=25)
    objc = _objc()
    recognition = objc.ObjCClass("VNRecognizeTextRequest").alloc().init()
    if hasattr(recognition, "setRecognitionLevel_"):
        recognition.setRecognitionLevel_(1)
    if hasattr(recognition, "setUsesLanguageCorrection_"):
        recognition.setUsesLanguageCorrection_(True)
    _perform_vision_request(target, recognition)
    observations = _zero(recognition.results)
    output: list[dict[str, Any]] = []
    if observations is not None:
        for observation in _array_items(observations, max_results):
            candidates = observation.topCandidates_(1)
            items = _array_items(candidates, 1)
            if not items:
                continue
            candidate = items[0]
            text = str(_zero(candidate.string) or "")
            if not text:
                continue
            confidence = None
            try:
                confidence = round(float(_zero(candidate.confidence)), 4)
            except Exception:
                pass
            output.append({"text": text[:4096], "confidence": confidence})
    return _result(
        "vision_ocr_workspace_image",
        relative_path=relative_path,
        observations=output,
    )


def _vision_barcodes_workspace_image(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    target, relative_path = _workspace_image_path(request, workspace)
    max_results = _integer(request, "max_results", minimum=1, maximum=MAX_RESULTS, default=25)
    objc = _objc()
    detection = objc.ObjCClass("VNDetectBarcodesRequest").alloc().init()
    _perform_vision_request(target, detection)
    observations = _zero(detection.results)
    output: list[dict[str, Any]] = []
    if observations is not None:
        for observation in _array_items(observations, max_results):
            payload = _zero(observation.payloadStringValue)
            symbology = _zero(observation.symbology)
            confidence = None
            try:
                confidence = round(float(_zero(observation.confidence)), 4)
            except Exception:
                pass
            output.append(
                {
                    "payload": None if payload is None else str(payload)[:4096],
                    "symbology": None if symbology is None else str(symbology)[:128],
                    "confidence": confidence,
                }
            )
    return _result(
        "vision_barcodes_workspace_image",
        relative_path=relative_path,
        observations=output,
    )


def _shortcut_run(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    name = _string(request, "name", max_bytes=256)
    text = _string(request, "text", required=False, allow_empty=True, max_bytes=4096)
    _require_foreground()
    url = "shortcuts://run-shortcut?name=" + quote(name, safe="")
    if text:
        url += "&input=text&text=" + quote(text, safe="")
    opened = _open_url({"schema_version": 1, "operation": "open_url", "url": url}, workspace)
    return _result(
        "shortcut_run",
        name=name,
        can_open=bool(opened.get("can_open")),
        opened=bool(opened.get("opened")),
        input_kind="text" if text else "none",
    )


def _top_presenter() -> Any:
    objc = _objc()
    app = _zero(objc.ObjCClass("UIApplication").sharedApplication)
    connected = _zero(app.connectedScenes)
    try:
        scenes = _array_items(_zero(connected.allObjects), 16)
    except Exception:
        scenes = _array_items(connected, 16)
    windows: list[Any] = []
    for scene in scenes:
        try:
            if int(_zero(scene.activationState)) not in {0, 1}:
                continue
            windows.extend(_array_items(_zero(scene.windows), 32))
        except Exception:
            continue
    visible = [
        window
        for window in windows
        if not _native_bool_property(window, "hidden", "isHidden")
        and float(_zero(window.alpha)) > 0
    ]
    key_windows = [
        window
        for window in visible
        if _native_bool_property(window, "keyWindow", "isKeyWindow")
    ]
    chosen = key_windows[0] if key_windows else (visible[0] if visible else (windows[0] if windows else None))
    if chosen is None:
        raise RuntimeError("Juno has no active iPadOS window for presentation")
    controller = _zero(chosen.rootViewController)
    if controller is None:
        raise RuntimeError("Juno active window has no root view controller")
    for _ in range(20):
        presented = _zero(controller.presentedViewController)
        if presented is None:
            return controller
        controller = presented
    raise RuntimeError("Juno presentation stack exceeds safety bound")


def _present_share_sheet(items: list[Any]) -> dict[str, Any]:
    objc = _objc()
    controller_holder: dict[str, Any] = {}

    def present() -> None:
        presenter = _top_presenter()
        Activity = objc.ObjCClass("UIActivityViewController")
        controller = Activity.alloc().initWithActivityItems_applicationActivities_(objc.ns(items), None)
        if controller is None:
            raise RuntimeError("share sheet could not be created")
        popover = _zero(controller.popoverPresentationController)
        if popover is not None:
            source_view = _zero(presenter.view)
            popover.setSourceView_(source_view)
            try:
                popover.setSourceRect_(_zero(source_view.bounds))
            except Exception:
                pass
            if hasattr(popover, "setPermittedArrowDirections_"):
                popover.setPermittedArrowDirections_(0)
        retained_controller = _retain(controller)

        def completed(_activity_type: int, _completed: bool, _returned_items: int, _error: int) -> None:
            _release(retained_controller)
            _release(completion_block)

        completion_block = _retain(
            objc.Block(
                completed,
                None,
                ctypes.c_void_p,
                ctypes.c_bool,
                ctypes.c_void_p,
                ctypes.c_void_p,
            )
        )
        controller.setCompletionWithItemsHandler_(completion_block)
        try:
            presenter.presentViewController_animated_completion_(controller, True, None)
        except Exception:
            _release(completion_block)
            _release(retained_controller)
            raise
        controller_holder["controller"] = retained_controller

    _on_main(present)
    return {"presented": True, "retained_until_completion": True}


def _share_workspace_file(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    _private_ack(request)
    relative_path = _string(request, "relative_path", max_bytes=512)
    target = _safe_workspace_path(workspace, relative_path)
    _require_foreground()
    if not target.is_file():
        raise FileNotFoundError("workspace file does not exist")
    size = target.stat().st_size
    if size < 0 or size > 512 * 1024 * 1024:
        raise RuntimeError("workspace file exceeds share bound")
    objc = _objc()
    url = objc.ObjCClass("NSURL").fileURLWithPath_(str(target))
    evidence = _present_share_sheet([url])
    return _result(
        "share_workspace_file",
        relative_path=relative_path,
        size=size,
        **evidence,
    )


def _share_text(request: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    text = _string(request, "text", max_bytes=MAX_TEXT_BYTES, allow_empty=False)
    _require_foreground()
    evidence = _present_share_sheet([text])
    return _result(
        "share_text",
        size=len(text.encode("utf-8")),
        **evidence,
    )


def _native_bool_property(value: Any, *names: str) -> bool:
    last_error: Exception | None = None
    for name in names:
        try:
            return bool(_zero(getattr(value, name)))
        except (AttributeError, TypeError) as exc:
            last_error = exc
    raise RuntimeError(f"native boolean property unavailable: {names}") from last_error


def _replaykit_status(_request: dict[str, Any], _workspace: Path | None) -> dict[str, Any]:
    objc = _objc()
    recorder = _zero(objc.ObjCClass("RPScreenRecorder").sharedRecorder)
    return _result(
        "replaykit_status",
        available=_native_bool_property(recorder, "available", "isAvailable"),
        recording=_native_bool_property(recorder, "recording", "isRecording"),
        microphone_enabled=_native_bool_property(
            recorder, "microphoneEnabled", "isMicrophoneEnabled"
        ),
        capture_start_exposed=False,
    )


_HANDLERS = {
    "capabilities": _capabilities,
    "status": _status,
    "clipboard_get_text": _clipboard_get,
    "clipboard_set_text": _clipboard_set,
    "open_url": _open_url,
    "notification_schedule": _notification_schedule,
    "notification_remove": _notification_remove,
    "motion_sample": _motion_sample,
    "bluetooth_scan": _bluetooth_scan,
    "contacts_search": _contacts_search,
    "reminders_list": _reminders_list,
    "reminder_create": _reminder_create,
    "location_one_shot": _location_one_shot,
    "photos_latest_metadata": _photos_latest_metadata,
    "mic_record_short": _mic_record_short,
    "replaykit_status": _replaykit_status,
    "camera_photo_workspace": _camera_photo_workspace,
    "vision_ocr_workspace_image": _vision_ocr_workspace_image,
    "vision_barcodes_workspace_image": _vision_barcodes_workspace_image,
    "shortcut_run": _shortcut_run,
    "share_workspace_file": _share_workspace_file,
    "share_text": _share_text,
}


def dispatch(request: dict[str, Any], *, workspace: Path | str | None = None) -> dict[str, Any]:
    checked = _require_request(request)
    operation = checked["operation"]
    if OPERATIONS[operation]["private"]:
        _private_ack(checked)
    resolved_workspace = None if workspace is None else Path(workspace)
    result = _HANDLERS[operation](checked, resolved_workspace)
    try:
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        raise RuntimeError("bridge result is not JSON-serializable") from exc
    if len(encoded) > 128 * 1024:
        raise RuntimeError("bridge result exceeds output bound")
    return result


def _main(argv: list[str]) -> int:
    if len(argv) > 2:
        raise SystemExit("usage: juno_access_bridge.py [JSON_REQUEST]")
    if len(argv) == 2:
        request_text = argv[1]
    else:
        request_text = sys.stdin.read()
    if not request_text.strip():
        raise SystemExit("JSON request required")
    request = json.loads(request_text)
    result = dispatch(request, workspace=Path.cwd())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))

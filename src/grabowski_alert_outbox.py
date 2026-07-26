from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

import grabowski_private_io as private_io


SCHEMA_VERSION = 1
ALERT_KIND = "grabowski_ntfy_alert"
ACK_KIND = "grabowski_ntfy_alert_ack"
EVENT_CLASSES = frozenset(
    {
        "blocked_operation",
        "recovery",
        "service_failure",
        "long_run_completed",
        "owner_decision",
    }
)
ALERT_NON_CLAIMS = [
    "external_push_delivery",
    "user_has_seen_alert",
    "primary_operation_success",
    "authorization_to_retry_or_mutate",
    "root_cause",
]
ACK_NON_CLAIMS = [
    "user_has_seen_alert",
    "primary_operation_success",
    "authorization_to_retry_or_mutate",
]
MAX_RECORD_BYTES = 16 * 1024
MAX_IDENTITY_BYTES = 2_048
MAX_FIELD_COUNT = 8
MAX_FIELD_BYTES = 160
MAX_LIST_LIMIT = 100
MAX_LIST_SCAN = 1_000
CODE_RE = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
ID_RE = re.compile(r"[0-9a-f]{32}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
FIELD_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:=@/+\-\[\]]{0,159}\Z")
ALERT_FILE_RE = re.compile(r"(?P<alert_id>[0-9a-f]{32})\.json\Z")
ACK_FILE_RE = re.compile(r"(?P<alert_id>[0-9a-f]{32})\.ack\.json\Z")
PRIVATE_IO_TEMP_RE = re.compile(
    r"\.(?:[0-9a-f]{32}\.json|[0-9a-f]{32}\.ack\.json)"
    r"\.[1-9][0-9]*\.[0-9a-f]{32}\.tmp\Z"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)"
    r"\s*[:=]\s*[^\s,;]+"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


class AlertOutboxError(RuntimeError):
    pass


class AlertOutboxInputError(ValueError):
    pass


class AlertOutboxIntegrityError(AlertOutboxError):
    pass


class AlertOutboxConflictError(AlertOutboxError):
    pass


def _root() -> Path:
    configured = os.environ.get("GRABOWSKI_ALERT_OUTBOX_ROOT")
    root = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".local/state/grabowski/alert-outbox"
    )
    if not root.is_absolute():
        raise AlertOutboxIntegrityError("alert outbox root must be absolute")
    return root


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _deterministic_id(namespace: str, material: dict[str, Any]) -> str:
    return hashlib.sha256(
        namespace.encode("ascii") + b"\0" + _canonical(material)
    ).hexdigest()[:32]


def _validate_code(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or CODE_RE.fullmatch(value) is None:
        raise AlertOutboxInputError(f"{label} must be a bounded lowercase code")
    return value


def _validate_identity(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AlertOutboxInputError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_IDENTITY_BYTES:
        raise AlertOutboxInputError(f"{label} exceeds the size bound")
    return value


def _redact_field(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise AlertOutboxInputError(f"{label} must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AlertOutboxInputError(f"{label} contains control characters")
    normalized = " ".join(value.split())
    normalized = SECRET_ASSIGNMENT_RE.sub(r"\1=[redacted]", normalized)
    normalized = BEARER_RE.sub("Bearer [redacted]", normalized)
    if not normalized or len(normalized.encode("utf-8")) > MAX_FIELD_BYTES:
        raise AlertOutboxInputError(f"{label} is empty or exceeds the size bound")
    if FIELD_VALUE_RE.fullmatch(normalized) is None:
        raise AlertOutboxInputError(f"{label} contains unsafe characters")
    return normalized


def _validate_timestamp(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise AlertOutboxIntegrityError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise AlertOutboxIntegrityError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc:
        raise AlertOutboxIntegrityError(f"{label} is invalid")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise AlertOutboxIntegrityError(f"{label} is not canonical")
    return value


def _normalize_fields(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_FIELD_COUNT:
        raise AlertOutboxInputError("fields must be a bounded object")
    normalized: dict[str, str] = {}
    for key, item in sorted(value.items()):
        safe_key = _validate_code(key, label="field name")
        normalized[safe_key] = _redact_field(item, label=f"fields.{safe_key}")
    return normalized


def _ensure_private_directory(path: Path, *, create: bool) -> None:
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AlertOutboxIntegrityError(f"unsafe private directory: {path}")


def _read_private_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_RECORD_BYTES
        ):
            raise AlertOutboxIntegrityError(f"unsafe {label}: {path}")
        raw = b""
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(raw))
            if not chunk:
                raise AlertOutboxIntegrityError(f"short {label} read: {path}")
            raw += chunk
        after = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if tuple(getattr(before, key) for key in identity_fields) != tuple(
            getattr(after, key) for key in identity_fields
        ):
            raise AlertOutboxIntegrityError(f"{label} changed during read: {path}")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AlertOutboxIntegrityError(f"invalid {label} JSON: {path}") from exc
    if not isinstance(value, dict):
        raise AlertOutboxIntegrityError(f"{label} must be an object: {path}")
    return value, hashlib.sha256(raw).hexdigest()


def _validate_alert(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "kind",
        "alert_id",
        "correlation_id",
        "event_class",
        "producer",
        "subject",
        "fields",
        "requested_channels",
        "delivery_mode",
        "delivery_state",
        "created_at",
        "material_sha256",
        "does_not_establish",
        "receipt_sha256",
    }
    if set(value) != required:
        raise AlertOutboxIntegrityError("alert receipt fields are invalid")
    if value["schema_version"] != SCHEMA_VERSION or value["kind"] != ALERT_KIND:
        raise AlertOutboxIntegrityError("alert receipt schema is invalid")
    if (
        not isinstance(value["alert_id"], str)
        or ID_RE.fullmatch(value["alert_id"]) is None
    ):
        raise AlertOutboxIntegrityError("alert id is invalid")
    if (
        not isinstance(value["correlation_id"], str)
        or ID_RE.fullmatch(value["correlation_id"]) is None
    ):
        raise AlertOutboxIntegrityError("alert correlation id is invalid")
    if value["event_class"] not in EVENT_CLASSES:
        raise AlertOutboxIntegrityError("alert event class is invalid")
    try:
        _validate_code(value["producer"], label="producer")
        _validate_code(value["subject"], label="subject")
        normalized_fields = _normalize_fields(value["fields"])
    except AlertOutboxInputError as exc:
        raise AlertOutboxIntegrityError("alert bounded fields are invalid") from exc
    if normalized_fields != value["fields"]:
        raise AlertOutboxIntegrityError("alert fields are not canonical")
    if (
        value["requested_channels"] != ["ntfy"]
        or value["delivery_mode"] != "append_only_outbox"
        or value["delivery_state"] != "queued"
        or value["does_not_establish"] != ALERT_NON_CLAIMS
    ):
        raise AlertOutboxIntegrityError("alert delivery boundary is invalid")
    _validate_timestamp(value["created_at"], label="alert created_at")
    material = {
        key: value[key]
        for key in (
            "schema_version",
            "kind",
            "alert_id",
            "correlation_id",
            "event_class",
            "producer",
            "subject",
            "fields",
            "requested_channels",
            "delivery_mode",
            "delivery_state",
            "does_not_establish",
        )
    }
    if value["material_sha256"] != _sha256(material):
        raise AlertOutboxIntegrityError("alert material hash is invalid")
    receipt = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if value["receipt_sha256"] != _sha256(receipt):
        raise AlertOutboxIntegrityError("alert receipt hash is invalid")
    return value


def _validate_ack(
    value: dict[str, Any],
    *,
    alert: dict[str, Any],
    alert_file_sha256: str,
) -> dict[str, Any]:
    required = {
        "schema_version",
        "kind",
        "alert_id",
        "correlation_id",
        "alert_receipt_sha256",
        "alert_file_sha256",
        "http_status",
        "acknowledged_at",
        "does_not_establish",
        "ack_sha256",
    }
    if set(value) != required:
        raise AlertOutboxIntegrityError("alert acknowledgement fields are invalid")
    if (
        value["schema_version"] != SCHEMA_VERSION
        or value["kind"] != ACK_KIND
        or value["alert_id"] != alert["alert_id"]
        or value["correlation_id"] != alert["correlation_id"]
        or value["alert_receipt_sha256"] != alert["receipt_sha256"]
        or value["alert_file_sha256"] != alert_file_sha256
        or value["does_not_establish"] != ACK_NON_CLAIMS
    ):
        raise AlertOutboxIntegrityError("alert acknowledgement binding is invalid")
    status = value["http_status"]
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 200 <= status < 300
    ):
        raise AlertOutboxIntegrityError("alert acknowledgement HTTP status is invalid")
    _validate_timestamp(value["acknowledged_at"], label="alert acknowledged_at")
    payload = {key: item for key, item in value.items() if key != "ack_sha256"}
    if value["ack_sha256"] != _sha256(payload):
        raise AlertOutboxIntegrityError("alert acknowledgement hash is invalid")
    return value


def enqueue_alert(
    *,
    event_class: str,
    producer: str,
    correlation_key: str,
    deduplication_key: str,
    subject: str,
    fields: dict[str, str] | None = None,
) -> dict[str, Any]:
    if event_class not in EVENT_CLASSES:
        raise AlertOutboxInputError(f"unsupported event class: {event_class}")
    producer = _validate_code(producer, label="producer")
    subject = _validate_code(subject, label="subject")
    correlation_key = _validate_identity(correlation_key, label="correlation_key")
    deduplication_key = _validate_identity(
        deduplication_key,
        label="deduplication_key",
    )
    normalized_fields = _normalize_fields(fields)
    correlation_id = _deterministic_id(
        "grabowski-alert-correlation-v1",
        {"producer": producer, "subject": subject, "key": correlation_key},
    )
    identity = {
        "event_class": event_class,
        "producer": producer,
        "correlation_id": correlation_id,
        "deduplication_key": deduplication_key,
    }
    alert_id = _deterministic_id("grabowski-alert-v1", identity)
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": ALERT_KIND,
        "alert_id": alert_id,
        "correlation_id": correlation_id,
        "event_class": event_class,
        "producer": producer,
        "subject": subject,
        "fields": normalized_fields,
        "requested_channels": ["ntfy"],
        "delivery_mode": "append_only_outbox",
        "delivery_state": "queued",
        "does_not_establish": ALERT_NON_CLAIMS,
    }
    payload = {
        **material,
        "created_at": _utc_now(),
        "material_sha256": _sha256(material),
    }
    payload["receipt_sha256"] = _sha256(payload)
    root = _root()
    _ensure_private_directory(root, create=True)
    target = root / f"{alert_id}.json"
    created = private_io.publish_private_create_only_json(
        root,
        target,
        payload,
        max_bytes=MAX_RECORD_BYTES,
        label="ntfy alert receipt",
    )
    winner, file_sha256 = _read_private_json(target, label="ntfy alert receipt")
    winner = _validate_alert(winner)
    if winner["material_sha256"] != payload["material_sha256"]:
        raise AlertOutboxConflictError(
            "deterministic alert identity is already bound to different material"
        )
    return {
        "created": created,
        "replayed": not created,
        "alert": winner,
        "file_sha256": file_sha256,
    }


def acknowledge_alert(
    alert_id: str,
    receipt_sha256: str,
    http_status: int,
) -> dict[str, Any]:
    if not isinstance(alert_id, str) or ID_RE.fullmatch(alert_id) is None:
        raise AlertOutboxInputError("alert_id is invalid")
    if (
        not isinstance(receipt_sha256, str)
        or SHA256_RE.fullmatch(receipt_sha256) is None
    ):
        raise AlertOutboxInputError("receipt_sha256 is invalid")
    if (
        isinstance(http_status, bool)
        or not isinstance(http_status, int)
        or not 200 <= http_status < 300
    ):
        raise AlertOutboxInputError("an alert may only be acknowledged after HTTP 2xx")
    root = _root()
    _ensure_private_directory(root, create=False)
    alert, alert_file_sha256 = _read_private_json(
        root / f"{alert_id}.json",
        label="ntfy alert receipt",
    )
    alert = _validate_alert(alert)
    if alert["receipt_sha256"] != receipt_sha256:
        raise AlertOutboxConflictError("alert receipt changed")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": ACK_KIND,
        "alert_id": alert_id,
        "correlation_id": alert["correlation_id"],
        "alert_receipt_sha256": receipt_sha256,
        "alert_file_sha256": alert_file_sha256,
        "http_status": http_status,
        "acknowledged_at": _utc_now(),
        "does_not_establish": ACK_NON_CLAIMS,
    }
    payload["ack_sha256"] = _sha256(payload)
    target = root / f"{alert_id}.ack.json"
    created = private_io.publish_private_create_only_json(
        root,
        target,
        payload,
        max_bytes=MAX_RECORD_BYTES,
        label="ntfy alert acknowledgement",
    )
    winner, file_sha256 = _read_private_json(
        target,
        label="ntfy alert acknowledgement",
    )
    winner = _validate_ack(
        winner,
        alert=alert,
        alert_file_sha256=alert_file_sha256,
    )
    return {
        "created": created,
        "replayed": not created,
        "acknowledgement": winner,
        "file_sha256": file_sha256,
    }


def list_alerts(*, state: str = "queued", limit: int = 50) -> dict[str, Any]:
    if state not in {"queued", "acknowledged", "all"}:
        raise AlertOutboxInputError("state must be queued, acknowledged, or all")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_LIST_LIMIT
    ):
        raise AlertOutboxInputError(f"limit must be from 1 to {MAX_LIST_LIMIT}")
    root = _root()
    try:
        _ensure_private_directory(root, create=False)
    except FileNotFoundError:
        return {"alerts": [], "invalid_receipts": [], "state": state}
    alerts: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    entries: list[Path] = []
    for index, path in enumerate(root.iterdir()):
        if index >= MAX_LIST_SCAN:
            invalid.append({"name": "scan", "error": "scan_truncated"})
            break
        entries.append(path)
    entries.sort(key=lambda item: item.name)
    alert_ids = {
        match.group("alert_id")
        for path in entries
        if (match := ALERT_FILE_RE.fullmatch(path.name)) is not None
    }
    for path in entries:
        match = ALERT_FILE_RE.fullmatch(path.name)
        if match is None:
            ack_match = ACK_FILE_RE.fullmatch(path.name)
            if ack_match is None:
                # The create-only private-I/O primitive publishes through a
                # short-lived, exact-format temporary file in this directory.
                # A concurrent producer must not make a valid queue appear
                # corrupt while that file is being fsynced and linked.
                if PRIVATE_IO_TEMP_RE.fullmatch(path.name) is not None:
                    continue
                invalid.append({"name": path.name, "error": "unexpected_entry"})
            elif ack_match.group("alert_id") not in alert_ids:
                invalid.append({"name": path.name, "error": "orphan_acknowledgement"})
            continue
        alert_id = match.group("alert_id")
        try:
            alert, alert_file_sha256 = _read_private_json(
                path,
                label="ntfy alert receipt",
            )
            alert = _validate_alert(alert)
            if alert["alert_id"] != alert_id:
                raise AlertOutboxIntegrityError("alert filename binding is invalid")
            acknowledgement = None
            try:
                acknowledgement, _ack_file_sha256 = _read_private_json(
                    root / f"{alert_id}.ack.json",
                    label="ntfy alert acknowledgement",
                )
                acknowledgement = _validate_ack(
                    acknowledgement,
                    alert=alert,
                    alert_file_sha256=alert_file_sha256,
                )
            except FileNotFoundError:
                pass
        except (OSError, AlertOutboxError, AlertOutboxInputError) as exc:
            invalid.append({"name": path.name, "error": type(exc).__name__})
            continue
        acknowledged = acknowledgement is not None
        if state == "queued" and acknowledged:
            continue
        if state == "acknowledged" and not acknowledged:
            continue
        if len(alerts) < limit:
            alerts.append({**alert, "file_sha256": alert_file_sha256})
    return {"alerts": alerts, "invalid_receipts": invalid, "state": state}


def validate_alert(alert: dict[str, Any]) -> dict[str, Any]:
    candidate = dict(alert)
    candidate.pop("file_sha256", None)
    return _validate_alert(candidate)


def schedule_dispatch(alert_id: str) -> bool:
    if not isinstance(alert_id, str) or ID_RE.fullmatch(alert_id) is None:
        raise AlertOutboxInputError("alert_id is invalid")
    unit = f"grabowski-ntfy-alert-{alert_id}.service"
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemd-run",
                "--user",
                "--collect",
                "--quiet",
                "--no-block",
                f"--unit={unit}",
                "--property=Type=exec",
                "--property=NoNewPrivileges=yes",
                "--",
                sys.executable,
                "-I",
                "-m",
                "grabowski_ntfy_dispatch",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def enqueue_and_schedule(**parameters: Any) -> dict[str, Any]:
    queued = enqueue_alert(**parameters)
    alert = queued["alert"]
    return {
        **queued,
        "dispatch_scheduled": schedule_dispatch(str(alert["alert_id"])),
        "does_not_establish": [
            "dispatcher_started",
            "external_push_delivery",
            "user_has_seen_alert",
        ],
    }

#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import importlib
import json
import os
import re
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

import grabowski_operator_core as operator

try:
    alert_outbox = importlib.import_module("grabowski_alert_outbox")
except ModuleNotFoundError as exc:
    if exc.name != "grabowski_alert_outbox":
        raise
    alert_outbox = None

TOPIC_PATH = Path.home() / ".config/grabowski/ntfy-topic"
SERVER = "https://ntfy.sh"
CHANNEL = "ntfy"
EVENT_CLASSES = frozenset(
    {
        "blocked_operation",
        "recovery",
        "service_failure",
        "long_run_completed",
        "owner_decision",
    }
)
SAFE_TOKEN_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:@+-]*\Z")
MAX_CORRELATION_ID_CHARS = 128
MAX_STATUS_CHARS = 64
MAX_SERVICE_CHARS = 96
LOCK_PATH = Path.home() / ".local/state/grabowski/ntfy-dispatch.lock"


class NotificationContractError(ValueError):
    pass


def load_topic(path: Path = TOPIC_PATH) -> str:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("ntfy topic path is not a regular file")
    if metadata.st_mode & 0o077:
        raise RuntimeError("ntfy topic file must not be accessible by group or others")
    topic = path.read_text(encoding="utf-8").strip()
    if len(topic) < 32 or not topic.isalnum():
        raise RuntimeError("ntfy topic is invalid")
    return topic


def _safe_token(value: Any, *, field: str, fallback: str, max_length: int) -> str:
    text = str(value or fallback).strip()
    if len(text) > max_length or SAFE_TOKEN_RE.fullmatch(text) is None:
        raise NotificationContractError(f"invalid_{field}")
    return text


def event_class(row: dict[str, Any]) -> str:
    raw = row.get("event_class")
    if raw is None or not str(raw).strip():
        return "long_run_completed"
    declared = str(raw).strip()
    if declared not in EVENT_CLASSES:
        raise NotificationContractError("unsupported_event_class")
    return declared


def render_notification(row: dict[str, Any]) -> dict[str, str]:
    kind = event_class(row)
    correlation_id = _safe_token(
        row.get("correlation_id") or row.get("notification_id") or row.get("job_id"),
        field="correlation_id",
        fallback="unknown",
        max_length=MAX_CORRELATION_ID_CHARS,
    )
    short_id = correlation_id[-8:]
    status = ""
    if kind != "owner_decision":
        status = _safe_token(
            row.get("terminal_status") or row.get("status"),
            field="status",
            fallback="unknown",
            max_length=MAX_STATUS_CHARS,
        )
    service = ""
    if kind == "service_failure":
        service = _safe_token(
            row.get("service"),
            field="service",
            fallback="unknown",
            max_length=MAX_SERVICE_CHARS,
        )
    titles = {
        "blocked_operation": "Grabowski: operation blocked",
        "recovery": "Grabowski: recovery",
        "service_failure": "Grabowski: service failure",
        "long_run_completed": "Grabowski: run completed",
        "owner_decision": "Grabowski: decision required",
    }
    messages = {
        "blocked_operation": f"Operation {short_id} blocked: {status}",
        "recovery": f"Recovery {short_id}: {status}",
        "service_failure": f"Service {service} failed: {status}",
        "long_run_completed": f"Grabowski job {short_id} finished: {status}",
        "owner_decision": f"Owner decision required: {short_id}",
    }
    priorities = {
        "blocked_operation": "4",
        "recovery": "4",
        "service_failure": "5",
        "long_run_completed": "3",
        "owner_decision": "4",
    }
    tags = {
        "blocked_operation": "warning,robot",
        "recovery": "lifebuoy,robot",
        "service_failure": "rotating_light,robot",
        "long_run_completed": "white_check_mark,robot",
        "owner_decision": "question,robot",
    }
    return {
        "event_class": kind,
        "correlation_id": correlation_id,
        "title": titles[kind],
        "body": messages[kind],
        "priority": priorities[kind],
        "tags": tags[kind],
    }


def _publish_rendered(
    topic: str,
    rendered: dict[str, str],
    *,
    server: str,
) -> int:
    request = urllib.request.Request(
        f"{server}/{topic}",
        data=rendered["body"].encode("utf-8"),
        method="POST",
        headers={
            "Title": rendered["title"],
            "Priority": rendered["priority"],
            "Tags": rendered["tags"],
            "X-Grabowski-Event-Class": rendered["event_class"],
            "X-Grabowski-Correlation-Id": rendered["correlation_id"],
            "User-Agent": "grabowski-ntfy-dispatch/2",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return int(response.status)


def publish(topic: str, row: dict[str, Any], *, server: str = SERVER) -> int:
    return _publish_rendered(topic, render_notification(row), server=server)


def _alert_render_row(row: dict[str, Any]) -> dict[str, Any]:
    if alert_outbox is None:
        raise RuntimeError("alert outbox support is unavailable")
    candidate = dict(row)
    candidate.pop("file_sha256", None)
    alert_outbox.notification_payload(candidate)
    fields = candidate.get("fields")
    if not isinstance(fields, dict):
        raise NotificationContractError("invalid_alert_fields")
    kind = str(candidate.get("event_class") or "")
    status_by_class = {
        "blocked_operation": fields.get("outcome") or "blocked",
        "recovery": fields.get("operation") or "completed",
        "service_failure": fields.get("error_type") or "failed",
        "long_run_completed": fields.get("outcome") or "completed",
    }
    return {
        "event_class": kind,
        "correlation_id": candidate.get("correlation_id"),
        "status": status_by_class.get(kind, "recorded"),
        "service": candidate.get("subject") or "grabowski",
    }


def publish_alert(topic: str, row: dict[str, Any], *, server: str = SERVER) -> int:
    return _publish_rendered(
        topic,
        render_notification(_alert_render_row(row)),
        server=server,
    )


def _notification_list(*, limit: int, state: str) -> dict[str, Any]:
    return operator.grabowski_job_notification_list(limit=limit, state=state)


def _notification_ack(unit: str, receipt_sha256: str) -> Any:
    return operator.grabowski_job_notification_ack(unit, receipt_sha256)


def dispatch(
    *,
    topic: str,
    publisher: Callable[[str, dict[str, Any]], int] = publish,
    limit: int = 50,
) -> dict[str, Any]:
    listed = _notification_list(limit=limit, state="queued")
    if listed.get("invalid_receipts"):
        return {"status": "blocked", "reason": "invalid_outbox_receipts"}

    delivered = 0
    skipped = 0
    failures: list[dict[str, Any]] = []
    for row in listed.get("notifications", []):
        channels = row.get("requested_channels") or []
        if CHANNEL not in channels:
            skipped += 1
            continue

        receipt_sha256 = str(row.get("receipt_sha256") or "")
        unit = str(row.get("unit") or "")
        try:
            status = publisher(topic, row)
        except NotificationContractError as exc:
            failures.append(
                {
                    "unit": unit,
                    "error_type": type(exc).__name__,
                    "reason": str(exc),
                }
            )
            continue
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            failures.append(
                {
                    "unit": unit,
                    "error_type": type(exc).__name__,
                }
            )
            continue
        if status < 200 or status >= 300:
            failures.append({"unit": unit, "http_status": status})
            continue

        _notification_ack(unit, receipt_sha256)
        delivered += 1

    if failures:
        result: dict[str, Any] = {
            "status": "delivery_failed",
            "delivered": delivered,
            "skipped": skipped,
            "failed": len(failures),
        }
        result.update(failures[0])
        return result
    return {"status": "ok", "delivered": delivered, "skipped": skipped}


def dispatch_alerts(
    *,
    topic: str,
    publisher: Callable[[str, dict[str, Any]], int] = publish_alert,
    limit: int = 50,
) -> dict[str, Any]:
    if alert_outbox is None:
        return {
            "status": "ok",
            "delivered": 0,
            "reason": "alert_outbox_unavailable",
            "does_not_establish": ["alert_outbox_empty"],
        }
    listed = alert_outbox.list_alerts(limit=limit, state="queued")
    if listed.get("invalid_receipts"):
        return {"status": "blocked", "reason": "invalid_alert_outbox_receipts"}

    delivered = 0
    failures: list[dict[str, Any]] = []
    contract_errors = (
        NotificationContractError,
        alert_outbox.AlertOutboxError,
        alert_outbox.AlertOutboxInputError,
    )
    for row in listed.get("alerts", []):
        alert_id = str(row.get("alert_id") or "")
        receipt_sha256 = str(row.get("receipt_sha256") or "")
        try:
            status = publisher(topic, row)
        except contract_errors as exc:
            failure = {
                "alert_id": alert_id,
                "error_type": type(exc).__name__,
            }
            if isinstance(exc, NotificationContractError):
                failure["reason"] = str(exc)
            failures.append(failure)
            continue
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            failures.append(
                {
                    "alert_id": alert_id,
                    "error_type": type(exc).__name__,
                }
            )
            continue
        if status < 200 or status >= 300:
            failures.append({"alert_id": alert_id, "http_status": status})
            continue

        alert_outbox.acknowledge_alert(alert_id, receipt_sha256, status)
        delivered += 1

    if failures:
        result: dict[str, Any] = {
            "status": "delivery_failed",
            "delivered": delivered,
            "failed": len(failures),
        }
        result.update(failures[0])
        return result
    return {"status": "ok", "delivered": delivered}


def _combined_status(*results: dict[str, Any]) -> str:
    statuses = {str(result.get("status") or "delivery_failed") for result in results}
    if "blocked" in statuses:
        return "blocked"
    if statuses == {"ok"}:
        return "ok"
    return "delivery_failed"


def main() -> int:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        topic = load_topic()
        job_result = dispatch(topic=topic)
        alert_result = dispatch_alerts(topic=topic)
        result = {
            "status": _combined_status(job_result, alert_result),
            "job_notifications": job_result,
            "alerts": alert_result,
        }
    finally:
        os.close(descriptor)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())

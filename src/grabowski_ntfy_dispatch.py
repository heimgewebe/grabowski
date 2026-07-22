#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import json
import os
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

import grabowski_operator_core as operator

TOPIC_PATH = Path.home() / ".config/grabowski/ntfy-topic"
SERVER = "https://ntfy.sh"
CHANNEL = "ntfy"
LOCK_PATH = Path.home() / ".local/state/grabowski/ntfy-dispatch.lock"


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


def publish(topic: str, row: dict[str, Any], *, server: str = SERVER) -> int:
    job_id = str(row.get("job_id") or "unknown")
    terminal_status = str(row.get("terminal_status") or "unknown")
    body = f"Grabowski job {job_id[-8:]} finished: {terminal_status}".encode("utf-8")
    request = urllib.request.Request(
        f"{server}/{topic}",
        data=body,
        method="POST",
        headers={
            "Title": "Grabowski",
            "Priority": "3",
            "Tags": "robot",
            "User-Agent": "grabowski-ntfy-dispatch/1",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return int(response.status)


def dispatch(
    *,
    topic: str,
    publisher: Callable[[str, dict[str, Any]], int] = publish,
    limit: int = 50,
) -> dict[str, Any]:
    listed = operator.grabowski_job_notification_list(limit=limit, state="queued")
    if listed.get("invalid_receipts"):
        return {"status": "blocked", "reason": "invalid_outbox_receipts"}

    delivered = 0
    skipped = 0
    for row in listed.get("notifications", []):
        channels = row.get("requested_channels") or []
        if CHANNEL not in channels:
            skipped += 1
            continue

        receipt_sha256 = str(row.get("receipt_sha256") or "")
        unit = str(row.get("unit") or "")
        try:
            status = publisher(topic, row)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            return {
                "status": "delivery_failed",
                "unit": unit,
                "error_type": type(exc).__name__,
            }
        if status < 200 or status >= 300:
            return {"status": "delivery_failed", "unit": unit, "http_status": status}

        operator.grabowski_job_notification_ack(unit, receipt_sha256)
        delivered += 1

    return {"status": "ok", "delivered": delivered, "skipped": skipped}


def main() -> int:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        result = dispatch(topic=load_topic())
    finally:
        os.close(descriptor)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())

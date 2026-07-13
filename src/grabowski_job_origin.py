from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from grabowski_consumer_surface import canonical_json_bytes

ORIGIN_SCHEMA_VERSION = 1
ORIGIN_KIND = "grabowski_job_origin"
ORIGIN_INVOCATION_RE = re.compile(r"grabowski_[a-z0-9_]{1,80}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})")
OWNER_RE = re.compile(r"uid:[0-9]+")
STARTED_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_ORIGIN_FIELDS = {
    "schema_version",
    "kind",
    "invoker_tool",
    "unit",
    "job_id",
    "owner",
    "argv_sha256",
    "scope",
    "notify_on_done",
    "created_at_unix",
    "started_at",
}
_NOTIFY_FIELDS = {"requested", "channels", "note"}


def notification_request(value: dict[str, Any]) -> dict[str, Any]:
    requested = value.get("requested")
    channels = value.get("channels")
    if not isinstance(requested, bool):
        raise ValueError("origin notification request flag is invalid")
    if (
        not isinstance(channels, list)
        or len(channels) > 5
        or not all(isinstance(item, str) and 0 < len(item) <= 40 for item in channels)
    ):
        raise ValueError("origin notification channels are invalid")
    result: dict[str, Any] = {"requested": requested, "channels": list(channels)}
    if "note" in value:
        note = value["note"]
        if not isinstance(note, str) or not note or len(note) > 200:
            raise ValueError("origin notification note is invalid")
        result["note"] = note
    return result


def build_origin(
    *,
    unit: str,
    owner: str,
    argv_sha256: str,
    scope: dict[str, Any],
    notify_on_done: dict[str, Any],
    created_at_unix: int,
    started_at: str,
    invoker_tool: str,
) -> tuple[dict[str, Any], str]:
    match = UNIT_RE.fullmatch(unit) if isinstance(unit, str) else None
    if match is None:
        raise ValueError("origin unit is invalid")
    if not isinstance(owner, str) or OWNER_RE.fullmatch(owner) is None:
        raise ValueError("origin owner is invalid")
    if not isinstance(argv_sha256, str) or SHA256_RE.fullmatch(argv_sha256) is None:
        raise ValueError("origin argv hash is invalid")
    if not isinstance(scope, dict):
        raise ValueError("origin scope is invalid")
    if isinstance(created_at_unix, bool) or not isinstance(created_at_unix, int) or created_at_unix < 0:
        raise ValueError("origin creation time is invalid")
    if not isinstance(started_at, str) or STARTED_AT_RE.fullmatch(started_at) is None:
        raise ValueError("origin start time is invalid")
    if not isinstance(invoker_tool, str) or ORIGIN_INVOCATION_RE.fullmatch(invoker_tool) is None:
        raise ValueError("origin invoker tool is invalid")
    origin = {
        "schema_version": ORIGIN_SCHEMA_VERSION,
        "kind": ORIGIN_KIND,
        "invoker_tool": invoker_tool,
        "unit": unit,
        "job_id": match.group(1),
        "owner": owner,
        "argv_sha256": argv_sha256,
        "scope": scope,
        "notify_on_done": notification_request(notify_on_done),
        "created_at_unix": created_at_unix,
        "started_at": started_at,
    }
    return origin, hashlib.sha256(canonical_json_bytes(origin)).hexdigest()


def validate_origin(
    origin: Any,
    origin_sha256: Any,
    *,
    expected_unit: str | None = None,
    expected_invoker_tool: str | None = None,
    expected_origin_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(origin, dict) or set(origin) != _ORIGIN_FIELDS:
        raise ValueError("job origin schema is invalid")
    rebuilt, calculated = build_origin(
        unit=origin.get("unit"),
        owner=origin.get("owner"),
        argv_sha256=origin.get("argv_sha256"),
        scope=origin.get("scope"),
        notify_on_done=origin.get("notify_on_done"),
        created_at_unix=origin.get("created_at_unix"),
        started_at=origin.get("started_at"),
        invoker_tool=origin.get("invoker_tool"),
    )
    if rebuilt != origin:
        raise ValueError("job origin normalization mismatch")
    if not isinstance(origin_sha256, str) or SHA256_RE.fullmatch(origin_sha256) is None:
        raise ValueError("job origin hash is invalid")
    if not hmac.compare_digest(origin_sha256, calculated):
        raise ValueError("job origin hash mismatch")
    if expected_origin_sha256 is not None and not hmac.compare_digest(
        origin_sha256,
        expected_origin_sha256,
    ):
        raise ValueError("job origin does not match the launcher precondition")
    if expected_unit is not None and origin.get("unit") != expected_unit:
        raise ValueError("job origin unit binding mismatch")
    if expected_invoker_tool is not None and origin.get("invoker_tool") != expected_invoker_tool:
        raise ValueError("job origin invoker binding mismatch")
    notify = origin.get("notify_on_done")
    if not isinstance(notify, dict) or not set(notify).issubset(_NOTIFY_FIELDS):
        raise ValueError("job origin notification request is invalid")
    return origin

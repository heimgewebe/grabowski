from __future__ import annotations

import json
import os
from pathlib import Path
import time
import uuid
from typing import Any

import grabowski_mcp as base
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

FRICTION_LOG = Path(os.environ.get(
    "GRABOWSKI_FRICTION_LOG",
    str(operator.STATE_DIR / "friction/events.jsonl"),
)).expanduser()

FRICTION_KINDS = {
    "platform_filter",
    "connector_snapshot",
    "fail_closed_gate",
    "execution_context",
    "ci_contract",
    "operator_bug",
    "user_input",
    "network",
    "unknown",
}
FRICTION_SURFACES = {
    "chat_tool",
    "connector",
    "runtime",
    "terminal",
    "local_shell",
    "github",
    "ci",
    "fleet",
    "recovery",
    "filesystem",
    "unknown",
}
MAX_TEXT_BYTES = 2000
MAX_NOTE_COUNT = 20


def _clean_text(value: str, *, label: str, required: bool = True, max_bytes: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{label} must be non-empty")
    if "\x00" in text:
        raise ValueError(f"{label} must not contain NUL")
    if len(text.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} is too large")
    redacted = operator._redact(text)
    if redacted != text:
        raise ValueError(f"{label} appears to contain secret material")
    return text


def _clean_notes(notes: list[str] | None) -> list[str]:
    if notes is None:
        return []
    if not isinstance(notes, list):
        raise ValueError("notes must be a list of strings")
    if len(notes) > MAX_NOTE_COUNT:
        raise ValueError("notes has too many entries")
    return [
        _clean_text(item, label="notes[]", required=False, max_bytes=500)
        for item in notes
    ]


def _validate_enum(value: str, *, label: str, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}")
    return value


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def record_friction_event(
    *,
    kind: str,
    surface: str,
    operation: str,
    symptom: str,
    suspected_trigger: str = "",
    fallback: str = "",
    resolved: bool = False,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    event = {
        "schema_version": 1,
        "event_id": uuid.uuid4().hex,
        "recorded_at_unix": int(time.time()),
        "kind": _validate_enum(kind, label="kind", allowed=FRICTION_KINDS),
        "surface": _validate_enum(surface, label="surface", allowed=FRICTION_SURFACES),
        "operation": _clean_text(operation, label="operation"),
        "symptom": _clean_text(symptom, label="symptom"),
        "suspected_trigger": _clean_text(suspected_trigger, label="suspected_trigger", required=False),
        "fallback": _clean_text(fallback, label="fallback", required=False),
        "resolved": bool(resolved),
        "notes": _clean_notes(notes),
    }
    _append_jsonl(FRICTION_LOG, event)
    base._append_audit({
        "timestamp_unix": event["recorded_at_unix"],
        "operation": "friction-record",
        "event_id": event["event_id"],
        "kind": event["kind"],
        "surface": event["surface"],
        "resolved": event["resolved"],
    })
    return {
        "recorded": True,
        "event_id": event["event_id"],
        "path": str(FRICTION_LOG),
        "kind": event["kind"],
        "surface": event["surface"],
        "resolved": event["resolved"],
    }


def _load_events(limit: int) -> list[dict[str, Any]]:
    if not FRICTION_LOG.exists():
        return []
    if FRICTION_LOG.is_symlink() or not FRICTION_LOG.is_file():
        raise RuntimeError("friction log is not a regular file")
    lines = FRICTION_LOG.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            events.append(value)
    return events


def friction_summary(*, limit: int = 50) -> dict[str, Any]:
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    events = _load_events(limit)
    by_kind: dict[str, int] = {}
    by_surface: dict[str, int] = {}
    unresolved = 0
    for event in events:
        kind = str(event.get("kind", "unknown"))
        surface = str(event.get("surface", "unknown"))
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_surface[surface] = by_surface.get(surface, 0) + 1
        if event.get("resolved") is not True:
            unresolved += 1
    return {
        "schema_version": 1,
        "path": str(FRICTION_LOG),
        "exists": FRICTION_LOG.exists(),
        "limit": limit,
        "returned": len(events),
        "unresolved": unresolved,
        "by_kind": dict(sorted(by_kind.items())),
        "by_surface": dict(sorted(by_surface.items())),
        "events": events,
    }


@mcp.tool(name="grabowski_friction_record", annotations=MUTATING)
def grabowski_friction_record(
    kind: str,
    surface: str,
    operation: str,
    symptom: str,
    suspected_trigger: str = "",
    fallback: str = "",
    resolved: bool = False,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """Record one bounded operator-friction event for later analysis."""
    operator._require_operator_mutation("file_write")
    return record_friction_event(
        kind=kind,
        surface=surface,
        operation=operation,
        symptom=symptom,
        suspected_trigger=suspected_trigger,
        fallback=fallback,
        resolved=resolved,
        notes=notes,
    )


@mcp.tool(name="grabowski_friction_summary", annotations=READ_ONLY)
def grabowski_friction_summary(limit: int = 50) -> dict[str, Any]:
    """Summarize recent bounded operator-friction events."""
    return friction_summary(limit=limit)

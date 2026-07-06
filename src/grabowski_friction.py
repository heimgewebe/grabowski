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
FAILURE_CLASSES = {
    "contract_error",
    "expected_red_phase",
    "superseded",
    "environment_tooling",
    "platform_filter",
    "policy_gate",
    "actionable_failure",
    "unknown",
}
FAILURE_CLASS_DECISIONS = {
    "contract_error": (
        "Inspect contract drift and decide whether producer or consumer must change."
    ),
    "expected_red_phase": (
        "Confirm the red phase is bound to an active implementation slice; "
        "no task resume follows from this class alone."
    ),
    "superseded": (
        "Bind the signal to its replacing issue, pull request, or receipt before "
        "closing the old thread."
    ),
    "environment_tooling": (
        "Decide whether to harden the environment, document a fallback, "
        "or defer as transient tooling noise."
    ),
    "platform_filter": (
        "Use a narrower allowed surface or document the blocked operation; "
        "do not retry the same blocked call unchanged."
    ),
    "policy_gate": (
        "Identify the gate owner and decide whether to satisfy gate evidence "
        "or change the policy deliberately."
    ),
    "actionable_failure": (
        "Assign a concrete owner and next patch or test step before attempting "
        "another run."
    ),
    "unknown": "Gather bounded context and reclassify before treating the signal as actionable.",
}
CLASSIFICATION_DOES_NOT_ESTABLISH = [
    "task_resume_permission",
    "root_cause",
    "merge_readiness",
    "policy_exception",
    "raw_log_safety",
]
ACTION_REQUIRED_FAILURE_CLASSES = {
    "contract_error",
    "environment_tooling",
    "platform_filter",
    "policy_gate",
    "actionable_failure",
    "unknown",
}
EXPECTED_RED_PHASE_TERMS = (
    "expected red-phase",
    "expected red phase",
    "red-phase",
    "red phase",
    "red test",
    "red first",
    "failing first",
)
SUPERSEDED_TERMS = (
    "superseded",
    "obsolete",
    "closed by",
    "replaced by",
    "merged elsewhere",
    "already fixed",
)
MAX_TEXT_BYTES = 2000
MAX_NOTE_COUNT = 20


def _clean_text(
    value: str,
    *,
    label: str,
    required: bool = True,
    max_bytes: int = MAX_TEXT_BYTES,
) -> str:
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


def _redacted_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return operator._redact(value).strip()


def _bounded_summary_text(value: Any, *, max_chars: int = 240) -> str:
    text = _redacted_string(value)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"


def _event_haystack(event: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "kind",
        "surface",
        "operation",
        "symptom",
        "suspected_trigger",
        "fallback",
    ):
        value = _redacted_string(event.get(key))
        if value:
            parts.append(value)
    notes = event.get("notes")
    if isinstance(notes, list):
        for note in notes:
            value = _redacted_string(note)
            if value:
                parts.append(value)
    return " ".join(parts).lower()


def classify_friction_event(event: dict[str, Any]) -> str:
    """Classify one friction event as read-only failure evidence.

    The class is a routing hint for the next decision, not a root-cause claim and
    not permission to resume a task.
    """
    if not isinstance(event, dict):
        return "unknown"
    haystack = _event_haystack(event)
    if any(term in haystack for term in SUPERSEDED_TERMS):
        return "superseded"
    if any(term in haystack for term in EXPECTED_RED_PHASE_TERMS):
        return "expected_red_phase"

    kind = str(event.get("kind", "unknown"))
    if kind == "platform_filter":
        return "platform_filter"
    if kind == "fail_closed_gate":
        return "policy_gate"
    if kind in {"connector_snapshot", "execution_context", "network"}:
        return "environment_tooling"
    if kind == "ci_contract":
        return "contract_error"
    if kind in {"operator_bug", "user_input"}:
        return "actionable_failure"
    return "unknown"


def _decision_event(event: dict[str, Any], failure_class: str) -> dict[str, Any]:
    return {
        "event_id": _bounded_summary_text(event.get("event_id"), max_chars=80),
        "failure_class": failure_class,
        "kind": _bounded_summary_text(event.get("kind"), max_chars=80) or "unknown",
        "surface": _bounded_summary_text(event.get("surface"), max_chars=80) or "unknown",
        "operation": _bounded_summary_text(event.get("operation"), max_chars=160),
        "symptom": _bounded_summary_text(event.get("symptom")),
        "next_decision": FAILURE_CLASS_DECISIONS[failure_class],
    }


def classify_failure_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    by_failure_class: dict[str, int] = {}
    unresolved_by_failure_class: dict[str, int] = {}
    decision_required_events: list[dict[str, Any]] = []

    for event in events:
        failure_class = classify_friction_event(event)
        by_failure_class[failure_class] = by_failure_class.get(failure_class, 0) + 1
        unresolved = event.get("resolved") is not True
        if unresolved:
            unresolved_by_failure_class[failure_class] = unresolved_by_failure_class.get(failure_class, 0) + 1
        if unresolved and failure_class in ACTION_REQUIRED_FAILURE_CLASSES:
            decision_required_events.append(_decision_event(event, failure_class))

    recurring_failure_classes = [
        {
            "failure_class": failure_class,
            "unresolved": count,
            "next_decision": FAILURE_CLASS_DECISIONS[failure_class],
        }
        for failure_class, count in sorted(unresolved_by_failure_class.items())
        if count > 1
    ]

    return {
        "schema_version": 1,
        "authority": "read_only_evidence",
        "does_not_establish": CLASSIFICATION_DOES_NOT_ESTABLISH,
        "by_failure_class": dict(sorted(by_failure_class.items())),
        "unresolved_by_failure_class": dict(sorted(unresolved_by_failure_class.items())),
        "decision_required_count": len(decision_required_events),
        "decision_required_events": decision_required_events[:20],
        "decision_required_events_truncated": len(decision_required_events) > 20,
        "recurring_failure_classes": recurring_failure_classes,
        "next_decisions_by_class": dict(sorted(FAILURE_CLASS_DECISIONS.items())),
    }


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


def _load_event_records(limit: int) -> dict[str, Any]:
    if not FRICTION_LOG.exists():
        return {
            "events": [],
            "scanned_lines": 0,
            "invalid_lines": 0,
            "non_event_lines": 0,
        }
    if FRICTION_LOG.is_symlink() or not FRICTION_LOG.is_file():
        raise RuntimeError("friction log is not a regular file")
    lines = FRICTION_LOG.read_text(encoding="utf-8").splitlines()
    events: list[dict[str, Any]] = []
    scanned_lines = 0
    invalid_lines = 0
    non_event_lines = 0
    for line in lines[-limit:]:
        if not line.strip():
            continue
        scanned_lines += 1
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        if isinstance(value, dict):
            events.append(value)
        else:
            non_event_lines += 1
    return {
        "events": events,
        "scanned_lines": scanned_lines,
        "invalid_lines": invalid_lines,
        "non_event_lines": non_event_lines,
    }


def _load_events(limit: int) -> list[dict[str, Any]]:
    return list(_load_event_records(limit)["events"])


def friction_summary(*, limit: int = 50) -> dict[str, Any]:
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    records = _load_event_records(limit)
    events = list(records["events"])
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
        "scanned_lines": records["scanned_lines"],
        "invalid_lines": records["invalid_lines"],
        "non_event_lines": records["non_event_lines"],
        "returned": len(events),
        "unresolved": unresolved,
        "by_kind": dict(sorted(by_kind.items())),
        "by_surface": dict(sorted(by_surface.items())),
        "failure_classification": classify_failure_events(events),
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
    base._require_mutations_enabled("friction_record")
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

from __future__ import annotations

from collections import Counter
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
FAILURE_CLASSES = frozenset({
    "contract_error",
    "expected_red_phase",
    "superseded",
    "environment_tooling",
    "platform_filter",
    "policy_gate",
    "actionable_failure",
    "unknown",
})
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
    "unknown": (
        "Gather bounded context and reclassify before treating the signal "
        "as actionable."
    ),
}
CLASSIFICATION_DOES_NOT_ESTABLISH = (
    "task_resume_permission",
    "root_cause",
    "merge_readiness",
    "policy_exception",
    "raw_log_safety",
)
ACTION_REQUIRED_FAILURE_CLASSES = frozenset({
    "contract_error",
    "environment_tooling",
    "platform_filter",
    "policy_gate",
    "actionable_failure",
    "unknown",
})
PROPOSAL_DOES_NOT_ESTABLISH = (
    "bureau_queue_mutation",
    "task_creation",
    "priority_change",
    "root_cause",
    "implementation_readiness",
    "merge_readiness",
)
PATTERN_EVIDENCE_THRESHOLD = 2
MAX_PROPOSAL_EVIDENCE_IDS = 20
FRICTION_PROPOSAL_PATTERNS: dict[str, dict[str, Any]] = {
    "command_chains": {
        "terms": (
            "command chain",
            "command-chain",
            "shell chain",
            "broad shell",
            "command shape",
            "command-shape",
            "argv shape",
            "argv-only",
            "command too broad",
            "split command",
            "split commands",
        ),
        "recommendation_type": "next_grip",
        "title": "Extract a narrower typed command grip",
        "rationale": (
            "Repeated command-chain friction indicates the operator is using broad "
            "shell sequences where a typed grip or smaller command helper would "
            "be easier to validate and resume."
        ),
    },
    "blocked_gates": {
        "terms": (
            "blocked gate",
            "gate blocked",
            "fail closed",
            "fail-closed",
            "policy gate",
            "gate evidence",
        ),
        "recommendation_type": "next_grip",
        "title": "Add a gate-evidence preparation grip",
        "rationale": (
            "Repeated gate friction should become better evidence preparation "
            "or clearer runbook steps, not an automatic policy bypass."
        ),
    },
    "stale_snapshots": {
        "terms": (
            "stale snapshot",
            "snapshot stale",
            "connector snapshot",
            "runtime snapshot",
            "client snapshot",
            "contract drift",
        ),
        "recommendation_type": "next_grip",
        "title": "Add a snapshot refresh or drift preflight",
        "rationale": (
            "Repeated stale snapshot friction means the operator should refresh "
            "or compare observable contracts before choosing a mutation path."
        ),
    },
    "review_loops": {
        "terms": (
            "review loop",
            "external review",
            "self-review",
            "codex review loop",
            "stale codex review",
            "claude review evidence",
            "stale claude review",
            "diff hash",
            "review gate",
        ),
        "recommendation_type": "small_bureau_task",
        "title": "Create a review-evidence workflow task",
        "rationale": (
            "Repeated review-loop friction should become a bounded checklist "
            "or Bureau task for evidence collection and stale-review triage."
        ),
    },
    "missing_receipt_fields": {
        "terms": (
            "missing receipt",
            "receipt missing",
            "missing field",
            "missing fields",
            "receipt field",
            "receipt schema",
        ),
        "recommendation_type": "small_bureau_task",
        "title": "Tighten receipt schema coverage",
        "rationale": (
            "Repeated missing receipt fields should become schema/test work "
            "for the emitting grip or task adapter."
        ),
    },
}
EXPECTED_RED_PHASE_TERMS = frozenset({
    "expected red-phase",
    "expected red phase",
    "red-phase",
    "red phase",
    "red test",
    "red first",
    "failing first",
})
SUPERSEDED_TERMS = frozenset({
    "superseded",
    "obsolete",
    "closed by",
    "replaced by",
    "merged elsewhere",
    "already fixed",
})
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


def _known_enum_value(value: Any, allowed: set[str]) -> str:
    if isinstance(value, str) and value in allowed:
        return value
    return "unknown"


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
                parts.append(value[:500])
    return " ".join(parts).lower()


def _bounded_event(event: dict[str, Any]) -> dict[str, Any]:
    notes = event.get("notes")
    return {
        "event_id": _bounded_summary_text(event.get("event_id"), max_chars=80),
        "recorded_at_unix": (
            event.get("recorded_at_unix")
            if isinstance(event.get("recorded_at_unix"), int)
            else None
        ),
        "kind": _known_enum_value(event.get("kind"), FRICTION_KINDS),
        "surface": _known_enum_value(event.get("surface"), FRICTION_SURFACES),
        "operation": _bounded_summary_text(event.get("operation"), max_chars=160),
        "symptom": _bounded_summary_text(event.get("symptom")),
        "suspected_trigger": _bounded_summary_text(event.get("suspected_trigger")),
        "fallback": _bounded_summary_text(event.get("fallback")),
        "resolved": event.get("resolved") is True,
        "notes_count": len(notes) if isinstance(notes, list) else 0,
    }


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

    kind = _known_enum_value(event.get("kind"), FRICTION_KINDS)
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
        "kind": _known_enum_value(event.get("kind"), FRICTION_KINDS),
        "surface": _known_enum_value(event.get("surface"), FRICTION_SURFACES),
        "operation": _bounded_summary_text(event.get("operation"), max_chars=160),
        "symptom": _bounded_summary_text(event.get("symptom")),
        "next_decision": FAILURE_CLASS_DECISIONS[failure_class],
    }


def _event_id(event: dict[str, Any]) -> str:
    value = _bounded_summary_text(event.get("event_id", ""), max_chars=80)
    return value or "unknown"


def _has_event_id(event: dict[str, Any]) -> bool:
    return bool(_bounded_summary_text(event.get("event_id", ""), max_chars=80))


def _proposal_event_ids(events: list[dict[str, Any]]) -> list[str]:
    return [_event_id(event) for event in events[:MAX_PROPOSAL_EVIDENCE_IDS]]


def _proposal_pattern_hits(event: dict[str, Any], failure_class: str) -> list[str]:
    hits: set[str] = set()
    haystack = _event_haystack(event)
    kind = _known_enum_value(event.get("kind"), FRICTION_KINDS)
    if kind == "fail_closed_gate" or failure_class == "policy_gate":
        hits.add("blocked_gates")
    if kind == "connector_snapshot":
        hits.add("stale_snapshots")
    for pattern, rule in FRICTION_PROPOSAL_PATTERNS.items():
        if pattern in hits:
            continue
        terms = rule.get("terms", ())
        if isinstance(terms, tuple) and any(term in haystack for term in terms):
            hits.add(pattern)
    return [pattern for pattern in FRICTION_PROPOSAL_PATTERNS if pattern in hits]


def _proposal_group(pattern: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    unresolved_events = [event for event in events if event.get("resolved") is not True]
    failure_classes: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    surfaces: Counter[str] = Counter()
    for event in events:
        failure_class = classify_friction_event(event)
        failure_classes[failure_class] += 1
        kind = _known_enum_value(event.get("kind"), FRICTION_KINDS)
        surface = _known_enum_value(event.get("surface"), FRICTION_SURFACES)
        kinds[kind] += 1
        surfaces[surface] += 1
    return {
        "pattern": pattern,
        "count": len(events),
        "unresolved": len(unresolved_events),
        "repeated": len(events) >= PATTERN_EVIDENCE_THRESHOLD,
        "actionable_repeated": len(unresolved_events) >= PATTERN_EVIDENCE_THRESHOLD,
        "evidence_event_ids": _proposal_event_ids(events),
        "evidence_event_ids_truncated": len(events) > MAX_PROPOSAL_EVIDENCE_IDS,
        "unresolved_evidence_event_ids": _proposal_event_ids(unresolved_events),
        "unresolved_evidence_event_ids_truncated": len(unresolved_events) > MAX_PROPOSAL_EVIDENCE_IDS,
        "missing_event_id_count": sum(1 for event in events if not _has_event_id(event)),
        "unresolved_missing_event_id_count": sum(1 for event in unresolved_events if not _has_event_id(event)),
        "by_failure_class": dict(sorted(failure_classes.items())),
        "by_kind": dict(sorted(kinds.items())),
        "by_surface": dict(sorted(surfaces.items())),
    }


def _recommendation_for_group(group: dict[str, Any]) -> dict[str, Any] | None:
    if group.get("actionable_repeated") is not True:
        return None
    pattern = str(group.get("pattern", ""))
    rule = FRICTION_PROPOSAL_PATTERNS.get(pattern)
    if not rule:
        return None
    return {
        "pattern": pattern,
        "recommendation_type": rule["recommendation_type"],
        "title": rule["title"],
        "rationale": rule["rationale"],
        "count": group["count"],
        "unresolved": group["unresolved"],
        "evidence_threshold": PATTERN_EVIDENCE_THRESHOLD,
        "by_failure_class": group["by_failure_class"],
        "by_kind": group["by_kind"],
        "by_surface": group["by_surface"],
        "evidence_event_ids": list(group.get("unresolved_evidence_event_ids", [])),
        "evidence_event_ids_truncated": group.get("unresolved_evidence_event_ids_truncated") is True,
        "missing_event_id_count": group["unresolved_missing_event_id_count"],
        "inherits_does_not_establish": True,
    }


def propose_next_grip_from_friction(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Group repeated friction into proposal-only next-action hints.

    This is read-only evidence synthesis. It never mutates Bureau, never starts a
    grip and never promotes a recommendation into a task. One event may support
    multiple proposal groups; that is not evidence for multiple root causes.
    """
    grouped: dict[str, list[dict[str, Any]]] = {
        pattern: [] for pattern in FRICTION_PROPOSAL_PATTERNS
    }
    matched_event_count = 0
    for event in events:
        failure_class = classify_friction_event(event)
        patterns = _proposal_pattern_hits(event, failure_class)
        if patterns:
            matched_event_count += 1
        for pattern in patterns:
            grouped[pattern].append(event)

    groups = [
        _proposal_group(pattern, grouped_events)
        for pattern, grouped_events in grouped.items()
        if grouped_events
    ]
    recommendations = [
        recommendation
        for group in groups
        if (recommendation := _recommendation_for_group(group)) is not None
    ]
    no_action = not recommendations
    return {
        "schema_version": 1,
        "authority": "proposal_only",
        "evidence_scope": "recent_valid_events",
        "evidence_threshold": PATTERN_EVIDENCE_THRESHOLD,
        "max_evidence_event_ids": MAX_PROPOSAL_EVIDENCE_IDS,
        "does_not_establish": list(PROPOSAL_DOES_NOT_ESTABLISH),
        "matched_event_count": matched_event_count,
        "unmatched_event_count": len(events) - matched_event_count,
        "groups": groups,
        "recommendations": recommendations,
        "recommendation_count": len(recommendations),
        "has_recommendations": bool(recommendations),
        "no_action": {
            "recommended": no_action,
            "reason": (
                "no configured proposal pattern met the unresolved evidence threshold"
                if no_action
                else "one or more configured proposal patterns met the unresolved evidence threshold"
            ),
        },
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
        "does_not_establish": list(CLASSIFICATION_DOES_NOT_ESTABLISH),
        "by_failure_class": dict(sorted(by_failure_class.items())),
        "unresolved_by_failure_class": dict(sorted(unresolved_by_failure_class.items())),
        "decision_required_count": len(decision_required_events),
        "decision_required_events": decision_required_events[:20],
        "decision_required_events_truncated": len(decision_required_events) > 20,
        "recurring_failure_classes": recurring_failure_classes,
        "recurring_scope": "recent_valid_events",
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
    reversed_events: list[dict[str, Any]] = []
    scanned_lines = 0
    invalid_lines = 0
    non_event_lines = 0
    for line in reversed(lines):
        if len(reversed_events) >= limit:
            break
        if not line.strip():
            continue
        scanned_lines += 1
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        if isinstance(value, dict):
            reversed_events.append(value)
        else:
            non_event_lines += 1
    events = list(reversed(reversed_events))
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
        kind = _known_enum_value(event.get("kind"), FRICTION_KINDS)
        surface = _known_enum_value(event.get("surface"), FRICTION_SURFACES)
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_surface[surface] = by_surface.get(surface, 0) + 1
        if event.get("resolved") is not True:
            unresolved += 1
    return {
        "schema_version": 1,
        "path": str(FRICTION_LOG),
        "exists": FRICTION_LOG.exists(),
        "limit": limit,
        "limit_scope": "recent_valid_events",
        "scanned_lines": records["scanned_lines"],
        "invalid_lines": records["invalid_lines"],
        "non_event_lines": records["non_event_lines"],
        "returned": len(events),
        "unresolved": unresolved,
        "by_kind": dict(sorted(by_kind.items())),
        "by_surface": dict(sorted(by_surface.items())),
        "failure_classification": classify_failure_events(events),
        "next_grip_proposals": propose_next_grip_from_friction(events),
        "events": [_bounded_event(event) for event in events],
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

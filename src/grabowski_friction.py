from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import subprocess
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
    "connector_transport",
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
    "connector_transport",
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
    "connector_transport": (
        "Capture bounded operator and tunnel service state, recent MCP stream "
        "errors, and adjacent successful calls; retry read-only work at most once "
        "as smaller typed calls, and never treat the retry as proof that the "
        "first failure was harmless."
    ),
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
    "connector_transport",
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
    "connector_transport": {
        "terms": (
            "502",
            "upstream or external service",
            "upstream/external service",
            "external service error",
            "streamable_http",
            "received exception from stream",
            "mcp stream",
            "post /mcp",
            "connector timeout",
            "connector timed out",
            "transport timeout",
        ),
        "recommendation_type": "next_grip",
        "title": "Add connector transport diagnostics",
        "rationale": (
            "Repeated connector transport failures should become bounded "
            "diagnostics and split/retry policy, not broad terminal retries or "
            "false-green conclusions after a successful retry."
        ),
    },
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
MAX_CONNECTOR_DIAGNOSTIC_LOG_LINES = 500
CONNECTOR_DIAGNOSTIC_SAMPLE_LIMIT = 10
CONNECTOR_DIAGNOSTIC_UNITS = (
    "grabowski-operator.service",
    "tunnel-client-grabowski.service",
)
CONNECTOR_TRANSPORT_LOG_MARKERS = (
    ("502", "502"),
    ("upstream_or_external_service", "upstream or external service"),
    ("upstream_external_service", "upstream/external service"),
    ("external_service_error", "external service error"),
    ("streamable_http", "streamable_http"),
    ("received_exception_from_stream", "received exception from stream"),
    ("mcp_stream", "mcp stream"),
    ("post_mcp", "post /mcp"),
    ("connector_timeout", "connector timeout"),
    ("transport_timeout", "transport timeout"),
    ("timeout", "timeout"),
)
CONNECTOR_TRANSPORT_TERMS = frozenset({
    "502",
    "upstream or external service",
    "upstream/external service",
    "external service error",
    "streamable_http",
    "received exception from stream",
    "mcp stream",
    "post /mcp",
    "connector timeout",
    "connector timed out",
    "transport timeout",
})
CONNECTOR_TRANSPORT_DOES_NOT_ESTABLISH = (
    "root_cause_proof",
    "connector_vendor_fix",
    "runtime_policy_change",
    "command_success_or_failure",
    "safe_mutation_retry",
    "transport_reliability_proof",
)


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


def _looks_like_connector_transport(event: dict[str, Any], haystack: str) -> bool:
    kind = _known_enum_value(event.get("kind"), FRICTION_KINDS)
    surface = _known_enum_value(event.get("surface"), FRICTION_SURFACES)
    if kind == "connector_transport":
        return True
    if not any(term in haystack for term in CONNECTOR_TRANSPORT_TERMS):
        return False
    return surface == "connector" or "streamable_http" in haystack or "post /mcp" in haystack


def connector_transport_diagnostics(events: list[dict[str, Any]]) -> dict[str, Any]:
    transport_events = [
        event
        for event in events
        if classify_friction_event(event) == "connector_transport"
    ]
    unresolved_events = [event for event in transport_events if event.get("resolved") is not True]
    return {
        "schema_version": 1,
        "authority": "read_only_diagnostic_guidance",
        "event_count": len(transport_events),
        "unresolved_event_count": len(unresolved_events),
        "recent_event_ids": _proposal_event_ids(transport_events),
        "recent_event_ids_truncated": len(transport_events) > MAX_PROPOSAL_EVIDENCE_IDS,
        "recommended_bounded_probe": [
            "grabowski_status for runtime contract and client snapshot visibility",
            "grabowski_service_status for grabowski-operator.service and tunnel-client-grabowski.service",
            "bounded recent journal search for streamable_http, Received exception from stream, POST /mcp, timeout and 502",
            "one adjacent small typed read-only call to determine whether the transport failure is still active",
        ],
        "split_retry_policy": {
            "read_only_retry_limit": 1,
            "retry_shape": "split broad terminal calls into smaller typed or single-purpose read-only calls",
            "mutation_rule": "do not retry mutating work after a transport failure until target state is re-read",
            "record_rule": "record friction when a connector transport failure changes the operator path",
            "false_green_warning": "a successful retry does not prove the first failure was harmless",
        },
        "does_not_establish": list(CONNECTOR_TRANSPORT_DOES_NOT_ESTABLISH),
    }



def _diagnostic_environment() -> dict[str, str]:
    environment = operator._safe_environment()
    for key in (
        "PAGER",
        "LESS",
        "SYSTEMD_PAGER",
        "SYSTEMD_LESS",
    ):
        environment.pop(key, None)
    environment.update({"PAGER": "cat", "SYSTEMD_PAGER": "cat", "NO_COLOR": "1"})
    return environment


def _run_diagnostic_command(
    argv: list[str],
    *,
    timeout_seconds: int = 30,
    max_output_bytes: int = 131_072,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=operator.HOME,
        env=_diagnostic_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    (
        stdout_raw,
        stderr_raw,
        timed_out,
        stdout_pipe_truncated,
        stderr_pipe_truncated,
    ) = base._read_limited_process_pipes(
        process,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    stdout = operator._redact(stdout_raw.decode("utf-8", errors="replace"))
    stderr = operator._redact(stderr_raw.decode("utf-8", errors="replace"))
    stdout, stdout_late_truncated = operator._limit(stdout, max_output_bytes)
    stderr, stderr_late_truncated = operator._limit(stderr, max_output_bytes)
    return {
        "argv": operator._redact_argv(argv),
        "argv_sha256": operator._argv_hash(argv),
        "command": operator._redacted_command(argv),
        "cwd": str(operator.HOME),
        "returncode": process.returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_pipe_truncated or stdout_late_truncated,
        "stderr_truncated": stderr_pipe_truncated or stderr_late_truncated,
    }


def _service_status_probe(unit: str) -> dict[str, Any]:
    name = operator._validate_unit(unit)
    result = _run_diagnostic_command(
        [
            "systemctl",
            "--user",
            "show",
            name,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--property=Result",
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
            "--property=NRestarts",
        ],
        timeout_seconds=30,
        max_output_bytes=32_768,
    )
    return {
        "unit": name,
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
        "stderr_preview": _bounded_summary_text(result.get("stderr"), max_chars=240),
        "properties": operator._parse_show(result.get("stdout", "")),
    }


def _journal_marker_probe(unit: str, max_lines: int) -> dict[str, Any]:
    name = operator._validate_unit(unit)
    result = _run_diagnostic_command(
        [
            "journalctl",
            "--user",
            "--unit",
            name,
            "--no-pager",
            "--output=short-iso",
            "--lines",
            str(max_lines),
        ],
        timeout_seconds=30,
        max_output_bytes=131_072,
    )
    marker_counts = {marker_id: 0 for marker_id, _ in CONNECTOR_TRANSPORT_LOG_MARKERS}
    samples: list[dict[str, Any]] = []
    match_count = 0
    for index, line in enumerate(str(result.get("stdout", "")).splitlines(), start=1):
        lowered = line.lower()
        markers = [
            marker_id
            for marker_id, marker_text in CONNECTOR_TRANSPORT_LOG_MARKERS
            if marker_text in lowered
        ]
        if not markers:
            continue
        match_count += 1
        for marker in markers:
            marker_counts[marker] += 1
        if len(samples) < CONNECTOR_DIAGNOSTIC_SAMPLE_LIMIT:
            parts = line.split(maxsplit=2)
            samples.append({
                "line_index": index,
                "timestamp": parts[0] if parts else "",
                "markers": markers,
            })
    return {
        "unit": name,
        "max_lines": max_lines,
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
        "marker_counts": marker_counts,
        "match_count": match_count,
        "matched_line_samples": samples,
        "matched_line_samples_truncated": match_count > len(samples),
        "stderr_preview": _bounded_summary_text(result.get("stderr"), max_chars=240),
    }


def _runtime_status_probe() -> dict[str, Any]:
    status_func = getattr(base, "grabowski_status", None)
    if not callable(status_func):
        return {"available": False, "reason": "grabowski_status_unavailable"}
    try:
        status = status_func()
    except Exception as exc:  # pragma: no cover - defensive runtime receipt path
        return {
            "available": False,
            "reason": "grabowski_status_failed",
            "error_type": exc.__class__.__name__,
        }
    deployment = status.get("deployment") if isinstance(status, dict) else {}
    tool_contract = status.get("tool_contract") if isinstance(status, dict) else {}
    kill_switch = status.get("kill_switch") if isinstance(status, dict) else {}
    if not isinstance(deployment, dict):
        deployment = {}
    if not isinstance(tool_contract, dict):
        tool_contract = {}
    if not isinstance(kill_switch, dict):
        kill_switch = {}
    return {
        "available": True,
        "deployment": {
            "completion_status": deployment.get("completion_status"),
            "repo_head": deployment.get("repo_head"),
            "source_identity_valid": deployment.get("source_identity_valid"),
            "runtime_binding_valid": deployment.get("runtime_binding_valid"),
            "environment_compatibility_valid": deployment.get("environment_compatibility_valid"),
            "provenance_valid": deployment.get("provenance_valid"),
        },
        "tool_contract": {
            "registered_tool_count": tool_contract.get("registered_tool_count"),
            "expected_tool_count": tool_contract.get("expected_tool_count"),
            "runtime_matches_deployment_contract": tool_contract.get("runtime_matches_deployment_contract"),
            "client_snapshot_observable": tool_contract.get("client_snapshot_observable"),
        },
        "kill_switch_engaged": kill_switch.get("engaged"),
    }


def connector_transport_live_diagnostics(
    *,
    limit: int = 50,
    max_log_lines: int = 120,
) -> dict[str, Any]:
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    if not isinstance(max_log_lines, int) or max_log_lines < 1 or max_log_lines > MAX_CONNECTOR_DIAGNOSTIC_LOG_LINES:
        raise ValueError(
            f"max_log_lines must be between 1 and {MAX_CONNECTOR_DIAGNOSTIC_LOG_LINES}"
        )
    operator._require_operator_capability("user_service_control")
    records = _load_event_records(limit)
    events = list(records["events"])
    history = connector_transport_diagnostics(events)
    service_statuses = {
        unit: _service_status_probe(unit)
        for unit in CONNECTOR_DIAGNOSTIC_UNITS
    }
    journal_probes = {
        unit: _journal_marker_probe(unit, max_log_lines)
        for unit in CONNECTOR_DIAGNOSTIC_UNITS
    }
    marker_match_count = sum(
        probe["match_count"] for probe in journal_probes.values()
    )
    return {
        "schema_version": 1,
        "authority": "read_only_transport_diagnostic_receipt",
        "source": "friction-log-and-local-user-systemd",
        "limit": limit,
        "max_log_lines": max_log_lines,
        "friction_log": {
            "path": str(FRICTION_LOG),
            "exists": FRICTION_LOG.exists(),
            "scanned_lines": records["scanned_lines"],
            "invalid_lines": records["invalid_lines"],
            "non_event_lines": records["non_event_lines"],
            "returned": len(events),
            "connector_transport_diagnostics": history,
        },
        "runtime_status": _runtime_status_probe(),
        "service_statuses": service_statuses,
        "journal_marker_probes": journal_probes,
        "live_transport_markers_observed": marker_match_count > 0,
        "marker_match_count": marker_match_count,
        "recommended_next_policy": history["split_retry_policy"],
        "does_not_establish": list(CONNECTOR_TRANSPORT_DOES_NOT_ESTABLISH),
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
    if _looks_like_connector_transport(event, haystack):
        return "connector_transport"

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
    if failure_class == "connector_transport":
        hits.add("connector_transport")
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
        "connector_transport_diagnostics": connector_transport_diagnostics(events),
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


@mcp.tool(name="grabowski_connector_transport_diagnostics", annotations=READ_ONLY)
def grabowski_connector_transport_diagnostics(
    limit: int = 50,
    max_log_lines: int = 120,
) -> dict[str, Any]:
    """Run bounded read-only diagnostics for connector transport failures."""
    operator._require_operator_capability("user_service_control")
    return connector_transport_live_diagnostics(
        limit=limit,
        max_log_lines=max_log_lines,
    )

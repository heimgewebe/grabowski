from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat as statmod
import subprocess
import time
import uuid
from typing import Any

import grabowski_mcp as base
import grabowski_consumer_surface as consumer_surface
import grabowski_nonconflict as nonconflict
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
FRICTION_DECISION_LOG = Path(os.environ.get(
    "GRABOWSKI_FRICTION_DECISION_LOG",
    str(operator.STATE_DIR / "friction/decisions.jsonl"),
)).expanduser()
FRICTION_CLOSEOUT_STATUSES = frozenset({
    "resolved",
    "superseded",
    "deferred",
    "accepted_risk",
    "wont_fix",
    "linked_to_task",
})
FRICTION_CLOSEOUT_NON_CLAIMS = (
    "does_not_prove_root_cause",
    "does_not_authorize_task_resume",
    "does_not_establish_merge_readiness",
    "does_not_rewrite_raw_friction_history",
    "does_not_make_a_linked_bureau_task_ready",
)
FRICTION_EVENT_ID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.:-]{0,127}$")
FRICTION_CLOSEOUT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
FRICTION_CLOSED_AT_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
BUREAU_TASK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,199}$")
MAX_FRICTION_RECORDS = 10000
MAX_FRICTION_LEDGER_BYTES = 16 * 1024 * 1024
MAX_FRICTION_CLOSEOUT_BATCH = 100


def _consumer_view(value: str, *, default: str = "minimal") -> str:
    return consumer_surface.normalize_view(value, default=default)


def _consumer_decode_cursor(
    cursor: str | None,
    scope: str,
    *,
    snapshot_scope: str | None = None,
) -> dict[str, Any] | None:
    return consumer_surface.decode_cursor(
        cursor,
        scope,
        snapshot_scope=snapshot_scope,
    )


def _consumer_encode_cursor(scope: str, position: dict[str, Any]) -> str:
    return consumer_surface.encode_cursor(scope, position)


def _consumer_project(
    payload: dict[str, Any],
    *,
    fields: list[str] | None,
    required: tuple[str, ...],
) -> dict[str, Any]:
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=required,
    )

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
FRICTION_REPAIR_CONTRACTS: dict[str, dict[str, Any]] = {
    "connector_transport": {
        "preferred_route": "split_read",
        "required_evidence": [
            "bounded operator and tunnel service status",
            "bounded transport journal window",
            "adjacent successful or failed typed calls",
        ],
        "preparation_steps": [
            "run connector transport diagnostics",
            "split the original read into smaller typed calls",
            "classify any possible mutation outcome before retry",
        ],
        "retry_policy": "retry read-only work at most once after narrowing; never retry a possible mutation unchanged",
        "post_state_readback": "required whenever the failed call may have mutated state",
    },
    "command_chains": {
        "preferred_route": "grip",
        "required_evidence": [
            "exact command intents and order",
            "bounded target and resource scope",
            "post-state readback for every mutating step",
        ],
        "preparation_steps": [
            "split independent reads",
            "extract repeated mutation into a typed grip",
            "bind each mutation to one receipt",
        ],
        "retry_policy": "do not repeat the same broad command chain; retry only the failed bounded step after readback",
        "post_state_readback": "required after each mutating step",
    },
    "blocked_gates": {
        "preferred_route": "explicit_preflight",
        "required_evidence": [
            "gate owner and immutable policy boundary",
            "exact target, scope and expected identity",
            "live leases, dirty state and running work",
            "missing receipt or acceptance evidence",
            "defined post-state readback method",
        ],
        "preparation_steps": [
            "run the narrow read-only preflight",
            "collect only the missing evidence",
            "choose a narrower typed route when available",
            "re-read the gate immediately before effect",
        ],
        "retry_policy": "no unchanged retry; retry only after a named evidence or target-state change",
        "post_state_readback": "mandatory and bound to the same target identity",
    },
    "stale_snapshots": {
        "preferred_route": "typed_tool",
        "required_evidence": [
            "runtime release identity",
            "server tool-contract identity",
            "observable client or connector snapshot identity",
        ],
        "preparation_steps": [
            "refresh observable contracts",
            "compare tool count and identity hashes",
            "block when client snapshot freshness is unobservable",
        ],
        "retry_policy": "retry only after a proven snapshot or release change",
        "post_state_readback": "re-read runtime and contract drift after refresh",
    },
    "review_loops": {
        "preferred_route": "explicit_preflight",
        "required_evidence": [
            "current base and head commit",
            "full diff hash",
            "current CI and review receipts",
        ],
        "preparation_steps": [
            "invalidate evidence after every head change",
            "collect the smallest missing review artifact",
            "re-run readiness against current base and head",
        ],
        "retry_policy": "do not reuse stale review evidence after a push or base change",
        "post_state_readback": "re-read head, base, diff and checks before merge",
    },
    "missing_receipt_fields": {
        "preferred_route": "explicit_preflight",
        "required_evidence": [
            "emitter identity and receipt schema version",
            "missing field semantics and consumer requirement",
            "success and failure path examples",
        ],
        "preparation_steps": [
            "bind the schema change to the emitting component",
            "add positive and negative contract tests",
            "verify old receipts fail or migrate explicitly",
        ],
        "retry_policy": "do not infer missing fields from surrounding state",
        "post_state_readback": "validate the emitted receipt against the exact schema",
    },
}
FRICTION_REPAIR_NON_CLAIMS = (
    "execution_authority",
    "policy_bypass",
    "safe_mutation_retry",
    "root_cause",
)
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
CONNECTOR_HTTP_STATUS_KEYS = (
    "status",
    "status_code",
    "http_status",
    "http_status_code",
    "response_status",
    "response_code",
)
CONNECTOR_ACTIVITY_MESSAGES = {
    "dispatcher forwarded command to MCP server": "forwarded_to_mcp",
    "dispatcher acknowledged notification with control plane": "control_plane_ack",
}
CONNECTOR_ERROR_MESSAGE_TERMS = {
    "received exception from stream": "stream_exception",
    "streamable_http": "stream_exception",
    "upstream or external service": "upstream_error",
    "upstream/external service": "upstream_error",
    "external service error": "upstream_error",
}
CONNECTOR_STRONG_TIMEOUT_TERMS = ("timed out", "deadline exceeded")
SYSTEMD_STOP_COMPLETED_MESSAGE_ID = "9d1aaa27d60140bd96365438aad20286"
CONNECTOR_PLANNED_STOP_ISSUE_COMPONENTS = {
    "failed to release dispatcher worker pool": "dispatcher",
    "harpoon server stopped": "",
}
CONNECTOR_PLANNED_STOP_SEQUENCE_MESSAGES = frozenset({
    "OnStop hook executing",
    "OnStop hook executed",
})

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


def _require_private_regular_fd(fd: int, *, label: str) -> None:
    metadata = os.fstat(fd)
    if (
        not statmod.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise RuntimeError(f"{label} must be a private owner-controlled regular file")


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        _require_private_regular_fd(fd, label=path.name)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


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
    closeout = event.get("closeout") if isinstance(event.get("closeout"), dict) else None
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
        "resolution_status": (
            _bounded_summary_text(closeout.get("status"), max_chars=40)
            if closeout is not None
            else ("legacy_resolved" if event.get("resolved") is True else "unresolved")
        ),
        "closeout": (
            {
                "decision": _bounded_summary_text(closeout.get("decision")),
                "evidence_ref": _bounded_summary_text(closeout.get("evidence_ref")),
                "resolved_by": _bounded_summary_text(closeout.get("resolved_by"), max_chars=120),
                "closed_at": _bounded_summary_text(closeout.get("closed_at"), max_chars=40),
                "bureau_task_id": _bounded_summary_text(closeout.get("bureau_task_id"), max_chars=200),
            }
            if closeout is not None
            else None
        ),
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


def _journal_record_payload(record: dict[str, Any]) -> dict[str, Any]:
    message = record.get("MESSAGE")
    if isinstance(message, str):
        try:
            nested = json.loads(message)
        except json.JSONDecodeError:
            nested = None
        if isinstance(nested, dict):
            payload = dict(nested)
        else:
            payload = {"msg": message}
        payload["_journal_priority"] = record.get("PRIORITY")
        return payload
    return {}


def _coerce_http_status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        status = value
    elif isinstance(value, str) and value.isdigit():
        status = int(value)
    else:
        return None
    return status if 100 <= status <= 599 else None


def _explicit_http_statuses(payload: dict[str, Any]) -> list[int]:
    statuses: set[int] = set()
    candidates = [payload]
    for key in ("error", "response", "http"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            candidates.append(nested)
    for candidate in candidates:
        for key in CONNECTOR_HTTP_STATUS_KEYS:
            status = _coerce_http_status(candidate.get(key))
            if status is not None:
                statuses.add(status)
    message = payload.get("msg")
    if isinstance(message, str):
        explicit_patterns = (
            r"(?:status|status_code|http_status|response_status|response_code|code)\s*[=:]\s*(\d{3})(?!\d)",
            r"HTTP/\d(?:\.\d)?\s+(\d{3})(?!\d)",
            r"received exception from stream\s*:\s*([45]\d{2})(?=\s+(?:upstream|external|http|bad gateway|service error))",
            r"(?:upstream(?: or|/)external service|external service error)[^0-9]{0,32}([45]\d{2})(?!\d)",
        )
        for pattern in explicit_patterns:
            for match in re.finditer(pattern, message, flags=re.IGNORECASE):
                status = _coerce_http_status(match.group(1))
                if status is not None:
                    statuses.add(status)
    return sorted(statuses)


def _journal_realtime_microseconds(record: dict[str, Any]) -> int | None:
    value = record.get("__REALTIME_TIMESTAMP")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _journal_invocation_id(record: dict[str, Any]) -> str | None:
    for key in ("_SYSTEMD_INVOCATION_ID", "USER_INVOCATION_ID"):
        value = record.get(key)
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value):
            return value
    return None


def _stop_invocation_context(
    records: list[dict[str, Any]],
    *,
    unit: str,
) -> tuple[set[str], dict[str, int]]:
    completed: set[str] = set()
    completed_at: dict[str, int] = {}
    stop_sequence_messages: dict[str, set[str]] = {}
    stop_sequence_latest_at: dict[str, int] = {}
    for record in records:
        invocation = _journal_invocation_id(record)
        realtime = _journal_realtime_microseconds(record)
        payload = _journal_record_payload(record)
        message = payload.get("msg") if isinstance(payload.get("msg"), str) else ""
        if (
            invocation
            and realtime is not None
            and message in CONNECTOR_PLANNED_STOP_SEQUENCE_MESSAGES
            and str(payload.get("component", "")) == ""
        ):
            stop_sequence_messages.setdefault(invocation, set()).add(message)
            stop_sequence_latest_at[invocation] = max(
                stop_sequence_latest_at.get(invocation, realtime),
                realtime,
            )
        if (
            record.get("MESSAGE_ID") != SYSTEMD_STOP_COMPLETED_MESSAGE_ID
            or record.get("USER_UNIT") != unit
            or record.get("JOB_TYPE") != "stop"
            or record.get("JOB_RESULT") != "done"
        ):
            continue
        user_invocation = record.get("USER_INVOCATION_ID")
        if isinstance(user_invocation, str) and re.fullmatch(r"[0-9a-f]{32}", user_invocation):
            completed.add(user_invocation)
            if realtime is not None:
                completed_at[user_invocation] = realtime
    qualified = {
        invocation: completion_time
        for invocation, completion_time in completed_at.items()
        if stop_sequence_messages.get(invocation) == set(CONNECTOR_PLANNED_STOP_SEQUENCE_MESSAGES)
        and stop_sequence_latest_at.get(invocation, completion_time + 1) <= completion_time
    }
    return completed, qualified


def _journal_transport_event(
    record: dict[str, Any],
    *,
    completed_stop_invocations: dict[str, int] | None = None,
) -> dict[str, Any]:
    payload = _journal_record_payload(record)
    message = payload.get("msg") if isinstance(payload.get("msg"), str) else ""
    lowered = message.lower()
    level = str(payload.get("level", "")).upper()
    if not level:
        priority = str(payload.get("_journal_priority", ""))
        if priority in {"0", "1", "2", "3"}:
            level = "ERROR"
        elif priority == "4":
            level = "WARNING"
    statuses = _explicit_http_statuses(payload)
    domains: set[str] = set()
    for status in statuses:
        if status >= 500:
            domains.add("upstream_http")
        elif status >= 400:
            domains.add("client_http")
    error_level = level in {"ERROR", "WARN", "WARNING", "CRITICAL"}
    if (
        any(term in lowered for term in CONNECTOR_STRONG_TIMEOUT_TERMS)
        or (error_level and "timeout" in lowered)
    ):
        domains.add("timeout")
    if error_level:
        for term, domain in CONNECTOR_ERROR_MESSAGE_TERMS.items():
            if term in lowered:
                domains.add(domain)
    error_value = payload.get("error")
    if isinstance(error_value, str) and error_value.strip():
        domains.add("reported_error")
    elif isinstance(error_value, dict) and error_value:
        domains.add("reported_error")
    invocation_id = _journal_invocation_id(record)
    expected_stop_component = CONNECTOR_PLANNED_STOP_ISSUE_COMPONENTS.get(message)
    completed_stop_at = (
        completed_stop_invocations.get(invocation_id)
        if completed_stop_invocations and invocation_id
        else None
    )
    realtime_microseconds = _journal_realtime_microseconds(record)
    planned_lifecycle_issue = bool(
        domains
        and expected_stop_component is not None
        and str(payload.get("component", "")) == expected_stop_component
        and invocation_id
        and completed_stop_at is not None
        and realtime_microseconds is not None
        and realtime_microseconds <= completed_stop_at
    )
    activity = CONNECTOR_ACTIVITY_MESSAGES.get(message)
    return {
        "timestamp": str(payload.get("time") or record.get("__REALTIME_TIMESTAMP") or "")[:80],
        "realtime_microseconds": realtime_microseconds,
        "invocation_id": invocation_id,
        "level": level[:16],
        "component": str(payload.get("component", ""))[:80],
        "http_statuses": statuses,
        "error_domains": sorted(domains),
        "activity": activity,
        "planned_lifecycle_issue": planned_lifecycle_issue,
    }


def _journal_transport_probe(unit: str, max_lines: int) -> dict[str, Any]:
    name = operator._validate_unit(unit)
    result = _run_diagnostic_command(
        [
            "journalctl",
            "--user",
            "--unit",
            name,
            "--no-pager",
            "--output=json",
            "--lines",
            str(max_lines),
        ],
        timeout_seconds=30,
        max_output_bytes=131_072,
    )
    parsed: list[dict[str, Any]] = []
    invalid_json_records = 0
    for line in str(result.get("stdout", "")).splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            invalid_json_records += 1
            continue
        if not isinstance(record, dict):
            invalid_json_records += 1
            continue
        parsed.append(record)

    completed_stop_invocations, qualified_stop_invocations = _stop_invocation_context(
        parsed,
        unit=name,
    )
    error_domains: Counter[str] = Counter()
    http_statuses: Counter[str] = Counter()
    activity_counts: Counter[str] = Counter()
    planned_lifecycle_domains: Counter[str] = Counter()
    planned_lifecycle_http_statuses: Counter[str] = Counter()
    post_error_activity_counts: Counter[str] = Counter()
    samples: list[dict[str, Any]] = []
    planned_lifecycle_samples: list[dict[str, Any]] = []
    transport_error_count = 0
    planned_lifecycle_issue_count = 0
    last_transport_error_microseconds: int | None = None
    activity_events: list[tuple[int | None, str]] = []

    for record in parsed:
        event = _journal_transport_event(
            record,
            completed_stop_invocations=qualified_stop_invocations,
        )
        if event["activity"]:
            activity_counts[event["activity"]] += 1
            activity_events.append((event["realtime_microseconds"], event["activity"]))
        if event["planned_lifecycle_issue"]:
            planned_lifecycle_issue_count += 1
            for domain in event["error_domains"]:
                planned_lifecycle_domains[domain] += 1
            for status in event["http_statuses"]:
                planned_lifecycle_http_statuses[str(status)] += 1
            if len(planned_lifecycle_samples) < CONNECTOR_DIAGNOSTIC_SAMPLE_LIMIT:
                planned_lifecycle_samples.append({
                    "timestamp": event["timestamp"],
                    "invocation_id": event["invocation_id"],
                    "level": event["level"],
                    "component": event["component"],
                    "http_statuses": event["http_statuses"],
                    "error_domains": event["error_domains"],
                })
            continue
        for status in event["http_statuses"]:
            http_statuses[str(status)] += 1
        if not event["error_domains"]:
            continue
        transport_error_count += 1
        event_microseconds = event["realtime_microseconds"]
        if event_microseconds is not None:
            last_transport_error_microseconds = max(
                last_transport_error_microseconds or event_microseconds,
                event_microseconds,
            )
        for domain in event["error_domains"]:
            error_domains[domain] += 1
        if len(samples) < CONNECTOR_DIAGNOSTIC_SAMPLE_LIMIT:
            samples.append({
                "timestamp": event["timestamp"],
                "invocation_id": event["invocation_id"],
                "level": event["level"],
                "component": event["component"],
                "http_statuses": event["http_statuses"],
                "error_domains": event["error_domains"],
            })

    if last_transport_error_microseconds is not None:
        for timestamp, activity in activity_events:
            if timestamp is not None and timestamp > last_transport_error_microseconds:
                post_error_activity_counts[activity] += 1
    journal_window_complete = bool(
        result["returncode"] == 0
        and not result["timed_out"]
        and not result["stdout_truncated"]
        and not result["stderr_truncated"]
        and invalid_json_records == 0
    )
    if not journal_window_complete:
        window_state = (
            "indeterminate_truncated"
            if result["stdout_truncated"]
            else "indeterminate_incomplete"
        )
    elif transport_error_count == 0:
        window_state = "no_errors"
    elif post_error_activity_counts:
        window_state = "errors_followed_by_activity"
    else:
        window_state = "errors_without_later_activity"

    return {
        "unit": name,
        "max_lines": max_lines,
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
        "parsed_records": len(parsed),
        "invalid_json_records": invalid_json_records,
        "transport_error_count": transport_error_count,
        "journal_window_complete": journal_window_complete,
        "window_state": window_state,
        "post_error_activity_counts": dict(sorted(post_error_activity_counts.items())),
        "error_domain_counts": dict(sorted(error_domains.items())),
        "http_status_counts": dict(sorted(http_statuses.items())),
        "activity_counts": dict(sorted(activity_counts.items())),
        "error_samples": samples,
        "error_samples_truncated": transport_error_count > len(samples),
        "completed_stop_invocation_count": len(completed_stop_invocations),
        "qualified_planned_stop_invocation_count": len(qualified_stop_invocations),
        "planned_lifecycle_issue_count": planned_lifecycle_issue_count,
        "planned_lifecycle_error_domain_counts": dict(
            sorted(planned_lifecycle_domains.items())
        ),
        "planned_lifecycle_http_status_counts": dict(
            sorted(planned_lifecycle_http_statuses.items())
        ),
        "planned_lifecycle_samples": planned_lifecycle_samples,
        "planned_lifecycle_samples_truncated": (
            planned_lifecycle_issue_count > len(planned_lifecycle_samples)
        ),
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
        unit: _journal_transport_probe(unit, max_log_lines)
        for unit in CONNECTOR_DIAGNOSTIC_UNITS
    }
    transport_error_count = sum(
        probe["transport_error_count"] for probe in journal_probes.values()
    )
    planned_lifecycle_issue_count = sum(
        probe["planned_lifecycle_issue_count"] for probe in journal_probes.values()
    )
    post_error_activity_counts: Counter[str] = Counter()
    for probe in journal_probes.values():
        post_error_activity_counts.update(probe["post_error_activity_counts"])
    window_states = {unit: probe["window_state"] for unit, probe in journal_probes.items()}
    if "errors_without_later_activity" in window_states.values():
        transport_window_state = "errors_without_later_activity"
    elif "errors_followed_by_activity" in window_states.values():
        transport_window_state = "errors_followed_by_activity"
    elif "indeterminate_truncated" in window_states.values():
        transport_window_state = "indeterminate_truncated"
    elif "indeterminate_incomplete" in window_states.values():
        transport_window_state = "indeterminate_incomplete"
    else:
        transport_window_state = "no_errors"
    return {
        "schema_version": 3,
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
        "journal_transport_probes": journal_probes,
        "transport_errors_observed_in_window": transport_error_count > 0,
        "live_transport_errors_observed": transport_error_count > 0,
        "live_transport_errors_observed_semantics": (
            "transport_error_present_in_bounded_journal_window_not_current_outage_proof"
        ),
        "transport_error_count": transport_error_count,
        "transport_window_state": transport_window_state,
        "transport_window_state_by_unit": window_states,
        "post_error_activity_counts": dict(sorted(post_error_activity_counts.items())),
        "planned_lifecycle_issue_count": planned_lifecycle_issue_count,
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


def _repair_contract_for_pattern(pattern: str) -> dict[str, Any]:
    repair = FRICTION_REPAIR_CONTRACTS.get(pattern)
    if repair is None:
        raise RuntimeError(f"friction proposal pattern lacks repair contract: {pattern}")
    required_keys = {
        "preferred_route",
        "required_evidence",
        "preparation_steps",
        "retry_policy",
        "post_state_readback",
    }
    if set(repair) != required_keys:
        raise RuntimeError(f"friction repair contract has invalid fields: {pattern}")
    scalar_keys = ("preferred_route", "retry_policy", "post_state_readback")
    if any(not isinstance(repair[key], str) or not repair[key] for key in scalar_keys):
        raise RuntimeError(f"friction repair contract has invalid scalar fields: {pattern}")
    list_keys = ("required_evidence", "preparation_steps")
    if any(
        not isinstance(repair[key], list)
        or not repair[key]
        or any(not isinstance(item, str) or not item for item in repair[key])
        for key in list_keys
    ):
        raise RuntimeError(f"friction repair contract has invalid list fields: {pattern}")
    return {
        "schema_version": 1,
        "authority": "evidence_preparation_only",
        "preferred_route": repair["preferred_route"],
        "required_evidence": list(repair["required_evidence"]),
        "preparation_steps": list(repair["preparation_steps"]),
        "retry_policy": repair["retry_policy"],
        "post_state_readback": repair["post_state_readback"],
        "does_not_establish": list(FRICTION_REPAIR_NON_CLAIMS),
    }


def _recommendation_for_group(group: dict[str, Any]) -> dict[str, Any] | None:
    if group.get("actionable_repeated") is not True:
        return None
    pattern = str(group.get("pattern", ""))
    rule = FRICTION_PROPOSAL_PATTERNS.get(pattern)
    if not rule:
        return None
    repair_contract = _repair_contract_for_pattern(pattern)
    return {
        "pattern": pattern,
        "recommendation_type": rule["recommendation_type"],
        "title": rule["title"],
        "rationale": rule["rationale"],
        "repair_contract": repair_contract,
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


def _validate_event_id(value: str) -> str:
    text = _clean_text(value, label="event_id", max_bytes=128)
    if not FRICTION_EVENT_ID_RE.fullmatch(text):
        raise ValueError("event_id has invalid format")
    return text


def _validate_bureau_task_id(value: str) -> str:
    text = _clean_text(value, label="bureau_task_id", max_bytes=200)
    if not BUREAU_TASK_ID_RE.fullmatch(text):
        raise ValueError("bureau_task_id has invalid format")
    return text


def _read_private_text(path: Path, *, max_bytes: int, require_private: bool = False) -> str | None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(fd)
        if not statmod.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{path.name} is not a regular file")
        if require_private:
            _require_private_regular_fd(fd, label=path.name)
        size_bytes = metadata.st_size
        if size_bytes > max_bytes:
            raise RuntimeError(f"{path.name} exceeds bounded byte limit")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            payload = handle.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise RuntimeError(f"{path.name} exceeds bounded byte limit")
        return payload.decode("utf-8")
    finally:
        if fd >= 0:
            os.close(fd)


def _load_jsonl_records(
    path: Path,
    *,
    maximum: int = MAX_FRICTION_RECORDS,
    require_private: bool = False,
) -> dict[str, Any]:
    text = _read_private_text(
        path,
        max_bytes=MAX_FRICTION_LEDGER_BYTES,
        require_private=require_private,
    )
    if text is None:
        return {"records": [], "scanned_lines": 0, "invalid_lines": 0, "non_object_lines": 0}
    records: list[dict[str, Any]] = []
    scanned_lines = 0
    invalid_lines = 0
    non_object_lines = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        scanned_lines += 1
        if scanned_lines > maximum:
            raise RuntimeError(f"{path.name} exceeds bounded line limit")
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        if not isinstance(value, dict):
            non_object_lines += 1
            continue
        records.append(value)
    return {
        "records": records,
        "scanned_lines": scanned_lines,
        "invalid_lines": invalid_lines,
        "non_object_lines": non_object_lines,
    }


@contextmanager
def _decision_log_lock(*, exclusive: bool):
    lock_path = Path(f"{FRICTION_DECISION_LOG}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        _require_private_regular_fd(fd, label=lock_path.name)
        with os.fdopen(fd, "a+", encoding="utf-8") as handle:
            fd = -1
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        if fd >= 0:
            os.close(fd)


def _valid_closeout_record(record: dict[str, Any]) -> bool:
    required = {
        "schema_version", "closeout_id", "event_id", "failure_class", "decision",
        "status", "evidence_ref", "resolved_by", "closed_at", "closed_at_unix",
        "reason", "bureau_task_id", "non_claims",
    }
    if set(record) != required or record.get("schema_version") != 1:
        return False
    if not isinstance(record.get("closeout_id"), str) or not FRICTION_CLOSEOUT_ID_RE.fullmatch(record["closeout_id"]):
        return False
    if not isinstance(record.get("event_id"), str) or not FRICTION_EVENT_ID_RE.fullmatch(record["event_id"]):
        return False
    if record.get("failure_class") not in FAILURE_CLASSES or record.get("status") not in FRICTION_CLOSEOUT_STATUSES:
        return False
    for key, maximum in (("decision", MAX_TEXT_BYTES), ("evidence_ref", MAX_TEXT_BYTES), ("resolved_by", 200), ("reason", MAX_TEXT_BYTES), ("bureau_task_id", 200)):
        value = record.get(key)
        if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
            return False
    if not record["decision"].strip() or not record["evidence_ref"].strip() or not record["resolved_by"].strip():
        return False
    if record["status"] == "deferred" and not record["reason"].strip():
        return False
    if record["bureau_task_id"] and not BUREAU_TASK_ID_RE.fullmatch(record["bureau_task_id"]):
        return False
    if record["status"] == "linked_to_task" and not record["bureau_task_id"]:
        return False
    if not isinstance(record.get("closed_at"), str) or not FRICTION_CLOSED_AT_RE.fullmatch(record["closed_at"]):
        return False
    closed_at_unix = record.get("closed_at_unix")
    if isinstance(closed_at_unix, bool) or not isinstance(closed_at_unix, int) or closed_at_unix < 0:
        return False
    return record.get("non_claims") == list(FRICTION_CLOSEOUT_NON_CLAIMS)


def _closeout_index() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    loaded = _load_jsonl_records(FRICTION_DECISION_LOG, require_private=True)
    index: dict[str, dict[str, Any]] = {}
    invalid_record_count = 0
    duplicate_event_ids: set[str] = set()
    conflicting_event_ids: set[str] = set()
    for record in loaded["records"]:
        if not _valid_closeout_record(record):
            invalid_record_count += 1
            continue
        event_id = record["event_id"]
        existing = index.get(event_id)
        if existing is not None:
            duplicate_event_ids.add(event_id)
            if _closeout_signature(existing) != _closeout_signature(record):
                conflicting_event_ids.add(event_id)
            continue
        index[event_id] = record
    for event_id in conflicting_event_ids:
        index.pop(event_id, None)
    integrity_valid = not any((
        loaded["invalid_lines"],
        loaded["non_object_lines"],
        invalid_record_count,
        duplicate_event_ids,
        conflicting_event_ids,
    ))
    return index, {
        "path": str(FRICTION_DECISION_LOG),
        "exists": FRICTION_DECISION_LOG.exists(),
        "records": len(loaded["records"]),
        "scanned_lines": loaded["scanned_lines"],
        "valid_records": len(index),
        "invalid_lines": loaded["invalid_lines"],
        "non_object_lines": loaded["non_object_lines"],
        "invalid_record_count": invalid_record_count,
        "invalid_records": invalid_record_count,
        "duplicate_event_ids": sorted(duplicate_event_ids)[:20],
        "duplicate_event_ids_truncated": len(duplicate_event_ids) > 20,
        "conflicting_event_ids": sorted(conflicting_event_ids)[:20],
        "conflicting_event_ids_truncated": len(conflicting_event_ids) > 20,
        "integrity_valid": integrity_valid,
    }


def _closeout_signature(record: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(record.get(key) for key in (
        "event_id",
        "status",
        "decision",
        "evidence_ref",
        "resolved_by",
        "reason",
        "bureau_task_id",
    ))


def _closeout_binding_mismatch_ids(
    events: list[dict[str, Any]],
    closeouts: dict[str, dict[str, Any]],
) -> list[str]:
    mismatches: set[str] = set()
    for event in events:
        if not _has_event_id(event):
            continue
        event_id = _event_id(event)
        closeout = closeouts.get(event_id)
        if closeout is not None and closeout.get("failure_class") != classify_friction_event(event):
            mismatches.add(event_id)
    return sorted(mismatches)


def resolve_friction(
    *,
    status: str,
    decision: str,
    evidence_ref: str,
    resolved_by: str,
    event_id: str = "",
    failure_class: str = "",
    reason: str = "",
    bureau_task_id: str = "",
) -> dict[str, Any]:
    event_selector = _clean_text(event_id, label="event_id", required=False, max_bytes=128)
    class_selector = _clean_text(failure_class, label="failure_class", required=False, max_bytes=80)
    if bool(event_selector) == bool(class_selector):
        raise ValueError("exactly one of event_id or failure_class is required")
    if event_selector:
        event_selector = _validate_event_id(event_selector)
    if class_selector and class_selector not in FAILURE_CLASSES:
        raise ValueError(f"failure_class must be one of {sorted(FAILURE_CLASSES)}")
    closeout_status = _validate_enum(status, label="status", allowed=set(FRICTION_CLOSEOUT_STATUSES))
    clean_decision = _clean_text(decision, label="decision")
    clean_evidence_ref = _clean_text(evidence_ref, label="evidence_ref")
    clean_resolved_by = _clean_text(resolved_by, label="resolved_by", max_bytes=200)
    clean_reason = _clean_text(reason, label="reason", required=False)
    clean_task_id = _validate_bureau_task_id(bureau_task_id) if bureau_task_id else ""
    if closeout_status == "deferred" and not clean_reason:
        raise ValueError("deferred closeout requires reason")
    if closeout_status == "linked_to_task" and not clean_task_id:
        raise ValueError("linked_to_task closeout requires bureau_task_id")

    raw = _load_jsonl_records(FRICTION_LOG)
    events = [record for record in raw["records"] if _has_event_id(record)]
    event_ids = [_event_id(event) for event in events]
    duplicate_raw_ids = sorted(event_id for event_id, count in Counter(event_ids).items() if count > 1)
    if duplicate_raw_ids:
        raise RuntimeError("friction ledger contains duplicate event_id values")
    by_id = {_event_id(event): event for event in events}
    now_unix = int(time.time())
    closed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_unix))
    appended: list[dict[str, Any]] = []
    already_recorded: list[str] = []

    with _decision_log_lock(exclusive=True):
        closeouts, closeout_meta = _closeout_index()
        if closeout_meta["duplicate_event_ids"]:
            raise RuntimeError("friction decision log contains duplicate closeouts")
        if not closeout_meta["integrity_valid"]:
            raise RuntimeError("friction decision log integrity is invalid")
        binding_mismatches = _closeout_binding_mismatch_ids(events, closeouts)
        if binding_mismatches:
            raise RuntimeError(
                "friction decision log closeout binding mismatch: " + ",".join(binding_mismatches[:20])
            )
        if event_selector:
            if event_selector not in by_id:
                raise ValueError("event_id not found in friction ledger")
            targets = [by_id[event_selector]]
        else:
            matching_targets = [
                event
                for event in events
                if classify_friction_event(event) == class_selector
                and event.get("resolved") is not True
                and _event_id(event) not in closeouts
            ]
            targets = matching_targets[:MAX_FRICTION_CLOSEOUT_BATCH]

        matched_target_count = len(targets) if event_selector else len(matching_targets)
        targets_truncated = matched_target_count > len(targets)
        remaining_target_count = matched_target_count - len(targets)

        for event in targets:
            target_event_id = _event_id(event)
            candidate = {
                "schema_version": 1,
                "closeout_id": uuid.uuid4().hex,
                "event_id": target_event_id,
                "failure_class": classify_friction_event(event),
                "decision": clean_decision,
                "status": closeout_status,
                "evidence_ref": clean_evidence_ref,
                "resolved_by": clean_resolved_by,
                "closed_at": closed_at,
                "closed_at_unix": now_unix,
                "reason": clean_reason,
                "bureau_task_id": clean_task_id,
                "non_claims": list(FRICTION_CLOSEOUT_NON_CLAIMS),
            }
            existing = closeouts.get(target_event_id)
            if existing is not None:
                if _closeout_signature(existing) == _closeout_signature(candidate):
                    already_recorded.append(target_event_id)
                    continue
                raise ValueError(f"event_id already has a different closeout: {target_event_id}")
            _append_jsonl(FRICTION_DECISION_LOG, candidate)
            closeouts[target_event_id] = candidate
            appended.append(candidate)

    base._append_audit({
        "timestamp_unix": now_unix,
        "operation": "friction-resolve",
        "selector": event_selector or class_selector,
        "selector_kind": "event_id" if event_selector else "failure_class",
        "status": closeout_status,
        "appended_count": len(appended),
        "already_recorded_count": len(already_recorded),
        "event_ids": [record["event_id"] for record in appended][:20],
    })
    return {
        "schema_version": 1,
        "path": str(FRICTION_DECISION_LOG),
        "selector": {
            "event_id": event_selector or None,
            "failure_class": class_selector or None,
        },
        "status": closeout_status,
        "target_count": len(targets),
        "matched_target_count": matched_target_count,
        "targets_truncated": targets_truncated,
        "remaining_target_count": remaining_target_count,
        "max_batch_size": MAX_FRICTION_CLOSEOUT_BATCH,
        "appended_count": len(appended),
        "already_recorded_count": len(already_recorded),
        "closeout_ids": [record["closeout_id"] for record in appended],
        "event_ids": [record["event_id"] for record in appended],
        "already_recorded_event_ids": already_recorded,
        "decision_log_before": closeout_meta,
        "non_claims": list(FRICTION_CLOSEOUT_NON_CLAIMS),
    }


def _friction_snapshot_sha256() -> str:
    parts: list[dict[str, Any]] = []
    for path in (FRICTION_LOG, FRICTION_DECISION_LOG):
        try:
            metadata = path.stat()
        except FileNotFoundError:
            parts.append({"path": str(path), "exists": False})
            continue
        if path.is_symlink() or not statmod.S_ISREG(metadata.st_mode):
            raise OSError(f"friction ledger must be a regular file: {path}")
        parts.append({
            "path": str(path),
            "exists": True,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
        })
    return hashlib.sha256(
        json.dumps(parts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_event_records(limit: int, *, offset: int = 0) -> dict[str, Any]:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    text = _read_private_text(FRICTION_LOG, max_bytes=MAX_FRICTION_LEDGER_BYTES)
    if text is None:
        return {
            "events": [],
            "scanned_lines": 0,
            "invalid_lines": 0,
            "non_event_lines": 0,
            "skipped_valid_events": 0,
        }
    lines = text.splitlines()
    reversed_events: list[dict[str, Any]] = []
    scanned_lines = 0
    invalid_lines = 0
    non_event_lines = 0
    skipped_valid_events = 0
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
            if skipped_valid_events < offset:
                skipped_valid_events += 1
                continue
            reversed_events.append(value)
        else:
            non_event_lines += 1
    events = list(reversed(reversed_events))
    return {
        "events": events,
        "scanned_lines": scanned_lines,
        "invalid_lines": invalid_lines,
        "non_event_lines": non_event_lines,
        "skipped_valid_events": skipped_valid_events,
    }


def _load_events(limit: int) -> list[dict[str, Any]]:
    return list(_load_event_records(limit)["events"])


def _compact_friction_event(event: dict[str, Any]) -> dict[str, Any]:
    bounded = _bounded_event(event)
    result = {
        key: bounded.get(key)
        for key in (
            "event_id",
            "recorded_at",
            "recorded_at_unix",
            "kind",
            "surface",
            "operation",
            "symptom",
            "resolved",
            "resolution_status",
            "notes_count",
        )
        if key in bounded
    }
    result["failure_class"] = classify_friction_event(event)
    if isinstance(bounded.get("closeout"), dict):
        result["closeout"] = {
            key: bounded["closeout"].get(key)
            for key in ("status", "evidence_ref", "bureau_task_id", "closed_at")
            if bounded["closeout"].get(key) not in (None, "")
        }
    return result


def friction_summary(
    *,
    limit: int = 20,
    view: str = "minimal",
    cursor: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    selected_view = _consumer_view(view)
    max_limit = 500 if selected_view == "evidence" else 100
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > max_limit:
        raise ValueError(f"limit must be between 1 and {max_limit} for view={selected_view}")
    snapshot_sha256 = _friction_snapshot_sha256()
    scope = f"friction-summary:{selected_view}:{snapshot_sha256}"
    position = _consumer_decode_cursor(
        cursor,
        scope,
        snapshot_scope=f"friction-summary:{selected_view}",
    )
    offset = 0 if position is None else position.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("cursor offset is invalid")
    records = _load_event_records(limit + 1, offset=offset)
    raw_events = list(records["events"])
    has_more = len(raw_events) > limit
    events = raw_events[-limit:] if has_more else raw_events
    # _load_event_records returns chronological order. When limit+1 was read,
    # the oldest item is the page-overflow marker and must be excluded.
    if has_more:
        events = raw_events[1:]
    event_ids = [_event_id(event) for event in events if _has_event_id(event)]
    duplicate_event_ids = sorted(
        event_id for event_id, count in Counter(event_ids).items() if count > 1
    )
    with _decision_log_lock(exclusive=False):
        closeouts, closeout_meta = _closeout_index()
    closeout_binding_mismatch_event_ids: list[str] = []
    if not closeout_meta["integrity_valid"]:
        closeouts = {}
    else:
        for event_id in duplicate_event_ids:
            closeouts.pop(event_id, None)
        closeout_binding_mismatch_event_ids = _closeout_binding_mismatch_ids(events, closeouts)
        for event_id in closeout_binding_mismatch_event_ids:
            closeouts.pop(event_id, None)
    event_log_integrity = {
        "duplicate_event_ids": duplicate_event_ids[:20],
        "duplicate_event_ids_truncated": len(duplicate_event_ids) > 20,
        "integrity_valid": not duplicate_event_ids and not closeout_binding_mismatch_event_ids,
        "scope": "returned_recent_valid_events",
        "closeout_policy": "ignore closeouts for duplicate event ids or failure-class binding mismatches",
        "closeout_binding_mismatch_event_ids": sorted(closeout_binding_mismatch_event_ids)[:20],
        "closeout_binding_mismatch_event_ids_truncated": len(closeout_binding_mismatch_event_ids) > 20,
    }
    by_kind: dict[str, int] = {}
    by_surface: dict[str, int] = {}
    resolution_counts: Counter[str] = Counter()
    overlaid_events: list[dict[str, Any]] = []
    for original in events:
        event = dict(original)
        event_id = _event_id(event) if _has_event_id(event) else ""
        closeout = closeouts.get(event_id)
        if closeout is not None:
            event["closeout"] = closeout
            event["resolved"] = True
            resolution_counts[str(closeout.get("status") or "unknown")] += 1
        elif event.get("resolved") is True:
            resolution_counts["legacy_resolved"] += 1
        else:
            resolution_counts["unresolved"] += 1
        kind = _known_enum_value(event.get("kind"), FRICTION_KINDS)
        surface = _known_enum_value(event.get("surface"), FRICTION_SURFACES)
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_surface[surface] = by_surface.get(surface, 0) + 1
        overlaid_events.append(event)
    unresolved = resolution_counts["unresolved"]
    classification = classify_failure_events(overlaid_events)
    diagnostics = connector_transport_diagnostics(overlaid_events)
    proposals = propose_next_grip_from_friction(overlaid_events)
    next_offset = offset + len(events)
    next_cursor = (
        _consumer_encode_cursor(scope, {"offset": next_offset})
        if has_more
        else None
    )
    warnings: list[dict[str, Any]] = []
    if not event_log_integrity["integrity_valid"]:
        warnings.append({"code": "friction_event_log_integrity_invalid"})
    if not closeout_meta.get("integrity_valid", False):
        warnings.append({"code": "friction_decision_log_integrity_invalid"})
    if unresolved:
        warnings.append({"code": "unresolved_friction", "count": unresolved})
    payload: dict[str, Any] = {
        "schema_version": 2,
        "decision_overlay_schema_version": 1,
        "view": selected_view,
        "event_log_integrity": event_log_integrity,
        "decision_log": {
            key: closeout_meta.get(key)
            for key in (
                "exists",
                "integrity_valid",
                "record_count",
                "invalid_record_count",
                "duplicate_event_ids",
                "conflicting_event_ids",
            )
            if key in closeout_meta
        },
        "limit": limit,
        "limit_scope": "recent_valid_events",
        "scanned_lines": records["scanned_lines"],
        "invalid_lines": records["invalid_lines"],
        "non_event_lines": records["non_event_lines"],
        "returned": len(overlaid_events),
        "unresolved": unresolved,
        "resolution_counts": dict(sorted(resolution_counts.items())),
        "by_kind": dict(sorted(by_kind.items())),
        "by_surface": dict(sorted(by_surface.items())),
        "failure_classification": {
            "by_failure_class": classification.get("by_failure_class", {}),
            "unresolved_by_failure_class": classification.get(
                "unresolved_by_failure_class", {}
            ),
            "decision_required_count": classification.get("decision_required_count", 0),
            "authority": classification.get("authority"),
            "does_not_establish": classification.get("does_not_establish", []),
        },
        "next_grip_proposals": {
            "has_recommendations": proposals.get("has_recommendations", False),
            "recommendations": [
                {
                    key: item.get(key)
                    for key in (
                        "pattern",
                        "title",
                        "recommendation_type",
                        "unresolved",
                        "evidence_event_ids",
                        "repair_contract",
                    )
                }
                for item in proposals.get("recommendations", [])[:5]
                if isinstance(item, dict)
            ],
            "authority": proposals.get("authority"),
            "does_not_establish": proposals.get("does_not_establish", []),
        },
        "events": [_compact_friction_event(event) for event in overlaid_events],
        "pagination": {
            "limit": limit,
            "returned": len(overlaid_events),
            "offset": offset,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "snapshot_sha256": snapshot_sha256,
        },
        "warnings": warnings,
        "recommended_next_action": (
            "resolve log integrity before automation"
            if any("integrity" in item["code"] for item in warnings)
            else (
                "inspect the highest repeated unresolved failure class"
                if unresolved
                else "none"
            )
        ),
        "does_not_establish": [
            "root_cause",
            "task_creation_authority",
            "safe_unchanged_mutation_retry",
        ],
    }
    if selected_view in {"standard", "evidence"}:
        payload["connector_transport_diagnostics"] = diagnostics
    if selected_view == "evidence":
        payload.update({
            "failure_classification": classification,
            "next_grip_proposals": proposals,
            "path": str(FRICTION_LOG),
            "exists": FRICTION_LOG.exists(),
            "decision_log": closeout_meta,
            "events": [_bounded_event(event) for event in overlaid_events],
        })
    return _consumer_project(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "view",
            "warnings",
            "recommended_next_action",
            "does_not_establish",
        ),
    )


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


@mcp.tool(name="grabowski_friction_resolve", annotations=MUTATING)
def grabowski_friction_resolve(
    status: str,
    decision: str,
    evidence_ref: str,
    resolved_by: str,
    event_id: str = "",
    failure_class: str = "",
    reason: str = "",
    bureau_task_id: str = "",
) -> dict[str, Any]:
    """Append evidence-bound friction closeout decisions without rewriting history."""
    base._require_mutations_enabled("friction_record")
    return resolve_friction(
        status=status,
        decision=decision,
        evidence_ref=evidence_ref,
        resolved_by=resolved_by,
        event_id=event_id,
        failure_class=failure_class,
        reason=reason,
        bureau_task_id=bureau_task_id,
    )


@mcp.tool(name="grabowski_friction_summary", annotations=READ_ONLY)
def grabowski_friction_summary(
    limit: int = 20,
    view: str = "minimal",
    cursor: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Summarize recent friction with compact default output and pagination."""
    return friction_summary(limit=limit, view=view, cursor=cursor, fields=fields)


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

EXECUTION_OUTCOME_LOG = Path(os.environ.get(
    "GRABOWSKI_EXECUTION_OUTCOME_LOG",
    str(operator.STATE_DIR / "friction/execution-outcomes.jsonl"),
)).expanduser()
EXECUTION_OPERATION_CLASSES = frozenset({
    "read",
    "broad_read",
    "mutation",
    "external_mutation",
    "long_running",
    "high_impact",
})
EXECUTION_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
EXECUTION_LEASE_STATES = frozenset({"free", "owned", "conflict", "unknown"})
EXECUTION_ROUTES = frozenset({
    "typed_tool",
    "grip",
    "durable_task",
    "split_read",
    "isolated_mutation",
    "explicit_preflight",
    "stop_resource_conflict",
    "stop_missing_readback",
    "operator_stop",
    "state_readback",
    "manual_fallback",
    "direct_operator",
    "isolated_worktree",
    "full_workspace",
    "workspace_with_contrast",
    "workspace_with_competition",
})
EXECUTION_GOVERNOR_MIN_EVIDENCE = 5
EXECUTION_GOVERNOR_DECAY_SECONDS = 7 * 24 * 60 * 60
EXECUTION_GOVERNOR_MAX_OUTCOME_BYTES = 16 * 1024 * 1024
EXECUTION_GOVERNOR_MAX_EVENT_IDS = 20
EXECUTION_GOVERNOR_MAX_RECORDS = 10000
EXECUTION_GOVERNOR_IMMUTABLE_BOUNDARIES = (
    "user_intent",
    "authorization",
    "secret_handling",
    "recovery",
    "kill_switch",
    "review",
    "merge",
    "deployment",
    "privileged_execution",
)
EXECUTION_GOVERNOR_NON_CLAIMS = (
    "automatic_task_creation_authority",
    "automatic_policy_mutation_authority",
    "merge_or_deploy_permission",
    "root_cause_proof",
    "safe_unchanged_mutation_retry",
    "live_routing_promotion",
    "caller_supplied_outcome_correctness",
)
EXECUTION_RECOMMENDATION_ID_RE = re.compile(r"^[0-9a-f]{64}$")
EXECUTION_OUTCOME_ID_RE = re.compile(r"^[0-9a-f]{32}$")
EXECUTION_EVIDENCE_REF_RE = re.compile(
    r"^(?:receipt|task|run|pr|artifact|event):[0-9A-Za-z][0-9A-Za-z_./:@#-]{0,399}$"
)
EXECUTION_OUTCOME_RECORD_KEYS = frozenset({
    "schema_version",
    "outcome_id",
    "recorded_at_unix",
    "recommendation_id",
    "operation_class",
    "risk_level",
    "recommended_route",
    "actual_route",
    "first_pass_success",
    "unchanged_retries",
    "ambiguous_mutation_outcomes",
    "tool_call_count",
    "elapsed_ms",
    "regression_signal",
    "friction_event_ids",
    "evidence_ref",
})


def _execution_enum(value: str, *, label: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}")
    return value


def _execution_int(value: int, *, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _execution_bool(value: bool, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _execution_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _execution_event_ids(values: list[str] | None) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("friction_event_ids must be a list")
    if len(values) > EXECUTION_GOVERNOR_MAX_EVENT_IDS:
        raise ValueError("friction_event_ids has too many entries")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        event_id = _validate_event_id(value)
        if event_id not in seen:
            result.append(event_id)
            seen.add(event_id)
    return result


def _execution_friction_evidence(*, limit: int, prior_failure_class: str) -> dict[str, Any]:
    summary = friction_summary(limit=limit, view="evidence")
    classification = summary["failure_classification"]
    unresolved = dict(classification.get("unresolved_by_failure_class", {}))
    decision_events = classification.get("decision_required_events", [])
    evidence_ids = [
        str(event.get("event_id"))
        for event in decision_events
        if isinstance(event, dict)
        and event.get("failure_class") in {prior_failure_class, "connector_transport", "platform_filter"}
        and isinstance(event.get("event_id"), str)
        and event.get("event_id")
    ][:EXECUTION_GOVERNOR_MAX_EVENT_IDS]
    event_invalid_lines = int(summary.get("invalid_lines", 0))
    event_non_event_lines = int(summary.get("non_event_lines", 0))
    fingerprint_payload = {
        "unresolved_by_failure_class": dict(sorted(unresolved.items())),
        "evidence_event_ids": evidence_ids,
        "event_invalid_lines": event_invalid_lines,
        "event_non_event_lines": event_non_event_lines,
        "event_log_integrity_valid": (
            summary.get("event_log_integrity", {}).get("integrity_valid") is True
            and event_invalid_lines == 0
            and event_non_event_lines == 0
        ),
        "decision_log_integrity_valid": summary.get("decision_log", {}).get("integrity_valid") is True,
    }
    return {
        **fingerprint_payload,
        "fingerprint_sha256": _execution_sha256(fingerprint_payload),
    }


def execution_shape_recommendation(
    *,
    operation_class: str,
    risk_level: str,
    may_mutate: bool,
    command_count: int = 1,
    expected_output_bytes: int = 0,
    resource_keys_count: int = 1,
    typed_tool_available: bool = False,
    grip_available: bool = False,
    durable_task_available: bool = False,
    lease_state: str = "unknown",
    prior_failure_class: str = "unknown",
    transport_sensitive: bool = False,
    post_state_read_available: bool = True,
    friction_limit: int = 100,
    nonconflict_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    operation_class = _execution_enum(
        operation_class,
        label="operation_class",
        allowed=EXECUTION_OPERATION_CLASSES,
    )
    risk_level = _execution_enum(
        risk_level,
        label="risk_level",
        allowed=EXECUTION_RISK_LEVELS,
    )
    lease_state = _execution_enum(
        lease_state,
        label="lease_state",
        allowed=EXECUTION_LEASE_STATES,
    )
    prior_failure_class = _execution_enum(
        prior_failure_class,
        label="prior_failure_class",
        allowed=FAILURE_CLASSES,
    )
    may_mutate = _execution_bool(may_mutate, label="may_mutate")
    typed_tool_available = _execution_bool(
        typed_tool_available,
        label="typed_tool_available",
    )
    grip_available = _execution_bool(grip_available, label="grip_available")
    durable_task_available = _execution_bool(
        durable_task_available,
        label="durable_task_available",
    )
    transport_sensitive = _execution_bool(
        transport_sensitive,
        label="transport_sensitive",
    )
    post_state_read_available = _execution_bool(
        post_state_read_available,
        label="post_state_read_available",
    )
    command_count = _execution_int(
        command_count,
        label="command_count",
        minimum=1,
        maximum=100,
    )
    expected_output_bytes = _execution_int(
        expected_output_bytes,
        label="expected_output_bytes",
        minimum=0,
        maximum=16 * 1024 * 1024,
    )
    resource_keys_count = _execution_int(
        resource_keys_count,
        label="resource_keys_count",
        minimum=0,
        maximum=100,
    )
    friction_limit = _execution_int(
        friction_limit,
        label="friction_limit",
        minimum=1,
        maximum=500,
    )

    mutating_classes = {"mutation", "external_mutation", "high_impact"}
    if operation_class in mutating_classes and not may_mutate:
        raise ValueError("mutating operation_class requires may_mutate=true")
    if operation_class in {"read", "broad_read"} and may_mutate:
        raise ValueError("read operation_class requires may_mutate=false")

    nonconflict_evidence: dict[str, Any] | None = None
    nonconflict_error: str | None = None
    if nonconflict_proof is not None:
        try:
            nonconflict_evidence = nonconflict.validate_governor_proof(nonconflict_proof)
        except (ValueError, nonconflict.NonConflictDenied) as exc:
            nonconflict_error = getattr(exc, "code", "invalid-nonconflict-proof")

    friction = _execution_friction_evidence(
        limit=friction_limit,
        prior_failure_class=prior_failure_class,
    )
    unresolved = friction["unresolved_by_failure_class"]
    recurring_transport = int(unresolved.get("connector_transport", 0)) >= 2
    recurring_filter = int(unresolved.get("platform_filter", 0)) >= 2
    high_impact = operation_class == "high_impact" or risk_level in {"high", "critical"}
    broad_read = (
        operation_class == "broad_read"
        or command_count > 1
        or expected_output_bytes > 65_536
        or resource_keys_count > 3
        or transport_sensitive
        or prior_failure_class in {"connector_transport", "platform_filter"}
    )

    reasons: list[str] = []
    preflight: list[str] = []
    route_feasible = True
    route: str
    friction_integrity_valid = (
        friction["event_log_integrity_valid"] is True
        and friction["decision_log_integrity_valid"] is True
    )

    if not friction_integrity_valid:
        route = "operator_stop"
        route_feasible = False
        reasons.append("friction_evidence_integrity_invalid")
        preflight.append("repair or isolate the friction evidence before routing")
    elif may_mutate and lease_state == "conflict" and nonconflict_evidence is None:
        route = "stop_resource_conflict"
        route_feasible = False
        reasons.append("resource_lease_conflict")
        if nonconflict_error is not None:
            reasons.append("resource_lease_nonconflict_proof_invalid")
        preflight.append("wait for or deliberately resolve the current resource owner")
    elif may_mutate and not post_state_read_available:
        route = "stop_missing_readback"
        route_feasible = False
        reasons.append("mutation_without_post_state_readback")
        preflight.append("add a bounded target-state read before mutation")
    elif may_mutate and prior_failure_class == "connector_transport":
        route = "state_readback"
        reasons.append("possible_mutation_outcome_unknown")
        preflight.append("read the exact target state before considering another mutation")
    elif prior_failure_class == "platform_filter":
        route = "operator_stop"
        route_feasible = False
        reasons.append("platform_filter_requires_alternative_surface")
        preflight.append("select a narrower allowed surface; do not retry unchanged")
    elif prior_failure_class == "policy_gate":
        route = "operator_stop"
        route_feasible = False
        reasons.append("policy_gate_requires_deliberate_evidence_or_policy_decision")
        preflight.append("satisfy the gate evidence or change policy deliberately")
    elif high_impact:
        route = "explicit_preflight"
        route_feasible = False
        reasons.append("immutable_high_impact_boundary")
        preflight.extend([
            "bind target and scope",
            "verify authorization and recovery evidence",
            "verify current review and validation evidence",
            "execute at most one mutation",
            "read back the target state and retain a receipt",
        ])
    elif operation_class == "long_running" and durable_task_available:
        route = "durable_task"
        reasons.append("long_running_work_requires_durable_identity")
        if may_mutate:
            preflight.extend(["verify resource lease", "bind expected post-state readback"])
    elif may_mutate:
        if grip_available:
            route = "grip"
            reasons.append("receipt_bound_grip_available")
        elif typed_tool_available:
            route = "typed_tool"
            reasons.append("typed_mutation_surface_available")
        else:
            route = "isolated_mutation"
            reasons.append("no_narrower_typed_surface_available")
        preflight.extend(["verify target and resource lease", "capture current target state"])
    elif broad_read:
        route = "split_read"
        reasons.append("broad_or_transport_sensitive_read")
        if typed_tool_available:
            reasons.append("prefer_single_purpose_typed_reads")
    elif typed_tool_available:
        route = "typed_tool"
        reasons.append("typed_read_surface_available")
    elif grip_available:
        route = "grip"
        reasons.append("read_only_grip_available")
    else:
        route = "split_read"
        reasons.append("fallback_to_bounded_single_purpose_reads")

    if lease_state == "conflict" and nonconflict_evidence is not None:
        reasons.append("resource_lease_nonconflict_proof_valid")
        preflight.append(
            "atomically revalidate the live repository lease and acquire only the exact proven resource keys"
        )

    if prior_failure_class == "platform_filter" and recurring_filter:
        reasons.append("recurring_platform_filter_evidence")
    if (prior_failure_class == "connector_transport" or transport_sensitive) and recurring_transport:
        reasons.append("recurring_connector_transport_evidence")
    if lease_state == "unknown" and may_mutate:
        preflight.append("resolve resource lease state")

    retry_limit = 0 if may_mutate or prior_failure_class == "platform_filter" else 1
    if route.startswith("stop_") or route in {"explicit_preflight", "operator_stop"}:
        retry_limit = 0

    typed_input = {
        "operation_class": operation_class,
        "risk_level": risk_level,
        "may_mutate": may_mutate,
        "command_count": command_count,
        "expected_output_bytes": expected_output_bytes,
        "resource_keys_count": resource_keys_count,
        "typed_tool_available": typed_tool_available,
        "grip_available": grip_available,
        "durable_task_available": durable_task_available,
        "lease_state": lease_state,
        "prior_failure_class": prior_failure_class,
        "transport_sensitive": transport_sensitive,
        "post_state_read_available": post_state_read_available,
        "friction_fingerprint_sha256": friction["fingerprint_sha256"],
        "nonconflict_proof_sha256": (
            None if nonconflict_evidence is None else nonconflict_evidence["proof_sha256"]
        ),
    }
    recommendation_id = _execution_sha256(typed_input)

    return {
        "schema_version": 1,
        "authority": "proposal_only_shadow_mode",
        "mode": "shadow",
        "recommendation_id": recommendation_id,
        "execution_authorized": False,
        "route_feasible": route_feasible,
        "recommended_route": route,
        "reason_codes": reasons,
        "action_shape": {
            "batch_reads": route in {"typed_tool", "grip"} and not may_mutate,
            "split_reads": route == "split_read",
            "isolated_mutation": route in {"typed_tool", "grip", "isolated_mutation"}
            and may_mutate,
            "one_mutation_per_attempt": may_mutate,
            "durable_identity": route == "durable_task",
            "state_readback_only": route == "state_readback",
            "stop": route.startswith("stop_") or route == "operator_stop",
        },
        "preflight_required": preflight,
        "retry_policy": {
            "retry_limit": retry_limit,
            "unchanged_retry_allowed": False,
            "platform_filter_rule": "do not retry the same blocked call unchanged",
            "read_only_transport_rule": "retry at most once as smaller typed or single-purpose reads",
            "possible_mutation_transport_rule": "classify outcome as unknown and read target state before any retry",
        },
        "post_state_readback": {
            "required": may_mutate,
            "available": post_state_read_available,
            "unknown_outcome_until_readback": (
                may_mutate and prior_failure_class == "connector_transport"
            ),
        },
        "friction_evidence": friction,
        "nonconflict_evidence": {
            "provided": nonconflict_proof is not None,
            "valid": nonconflict_evidence is not None,
            "error_code": nonconflict_error,
            "proof_sha256": (
                None if nonconflict_evidence is None else nonconflict_evidence["proof_sha256"]
            ),
            "blocked_lease_resource_key": (
                None
                if nonconflict_evidence is None
                else nonconflict_evidence["blocked_lease_resource_key"]
            ),
            "expires_at_unix": (
                None if nonconflict_evidence is None else nonconflict_evidence["expires_at_unix"]
            ),
            "requires_atomic_resource_revalidation": nonconflict_evidence is not None,
        },
        "promotion": {
            "applied": False,
            "authority": "none_in_shadow_mode",
            "eligible_risk_levels": ["low", "medium"],
            "minimum_evidence": EXECUTION_GOVERNOR_MIN_EVIDENCE,
            "time_decay_seconds": EXECUTION_GOVERNOR_DECAY_SECONDS,
        },
        "immutable_boundaries": list(EXECUTION_GOVERNOR_IMMUTABLE_BOUNDARIES),
        "does_not_establish": list(EXECUTION_GOVERNOR_NON_CLAIMS),
    }


def _execution_evidence_ref(value: str) -> str:
    text = _clean_text(value, label="evidence_ref", max_bytes=400)
    if not EXECUTION_EVIDENCE_REF_RE.fullmatch(text):
        raise ValueError(
            "evidence_ref must use receipt:, task:, run:, pr:, artifact: or event:"
        )
    return text


def _validated_execution_outcome_record(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or set(value) != EXECUTION_OUTCOME_RECORD_KEYS:
        return None
    try:
        if value.get("schema_version") != 1:
            return None
        outcome_id = value.get("outcome_id")
        recommendation_id = value.get("recommendation_id")
        if not isinstance(outcome_id, str) or not EXECUTION_OUTCOME_ID_RE.fullmatch(outcome_id):
            return None
        if (
            not isinstance(recommendation_id, str)
            or not EXECUTION_RECOMMENDATION_ID_RE.fullmatch(recommendation_id)
        ):
            return None
        recorded_at_unix = _execution_int(
            value.get("recorded_at_unix"),
            label="recorded_at_unix",
            minimum=0,
            maximum=4_102_444_800,
        )
        operation_class = _execution_enum(
            value.get("operation_class"),
            label="operation_class",
            allowed=EXECUTION_OPERATION_CLASSES,
        )
        risk_level = _execution_enum(
            value.get("risk_level"),
            label="risk_level",
            allowed=EXECUTION_RISK_LEVELS,
        )
        recommended_route = _execution_enum(
            value.get("recommended_route"),
            label="recommended_route",
            allowed=EXECUTION_ROUTES,
        )
        actual_route = _execution_enum(
            value.get("actual_route"),
            label="actual_route",
            allowed=EXECUTION_ROUTES,
        )
        first_pass_success = _execution_bool(
            value.get("first_pass_success"),
            label="first_pass_success",
        )
        unchanged_retries = _execution_int(
            value.get("unchanged_retries"),
            label="unchanged_retries",
            minimum=0,
            maximum=20,
        )
        ambiguous_mutation_outcomes = _execution_int(
            value.get("ambiguous_mutation_outcomes"),
            label="ambiguous_mutation_outcomes",
            minimum=0,
            maximum=20,
        )
        tool_call_count = _execution_int(
            value.get("tool_call_count"),
            label="tool_call_count",
            minimum=1,
            maximum=1000,
        )
        elapsed_ms = _execution_int(
            value.get("elapsed_ms"),
            label="elapsed_ms",
            minimum=0,
            maximum=86_400_000,
        )
        regression_signal = _execution_bool(
            value.get("regression_signal"),
            label="regression_signal",
        )
        friction_event_ids = _execution_event_ids(value.get("friction_event_ids"))
        evidence_ref = _execution_evidence_ref(value.get("evidence_ref"))
    except (TypeError, ValueError):
        return None
    return {
        "schema_version": 1,
        "outcome_id": outcome_id,
        "recorded_at_unix": recorded_at_unix,
        "recommendation_id": recommendation_id,
        "operation_class": operation_class,
        "risk_level": risk_level,
        "recommended_route": recommended_route,
        "actual_route": actual_route,
        "first_pass_success": first_pass_success,
        "unchanged_retries": unchanged_retries,
        "ambiguous_mutation_outcomes": ambiguous_mutation_outcomes,
        "tool_call_count": tool_call_count,
        "elapsed_ms": elapsed_ms,
        "regression_signal": regression_signal,
        "friction_event_ids": friction_event_ids,
        "evidence_ref": evidence_ref,
    }


@contextmanager
def _execution_outcome_log_lock(*, exclusive: bool):
    lock_path = Path(f"{EXECUTION_OUTCOME_LOG}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        _require_private_regular_fd(fd, label=lock_path.name)
        with os.fdopen(fd, "a+", encoding="utf-8") as handle:
            fd = -1
            fcntl.flock(
                handle.fileno(),
                fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
            )
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        if fd >= 0:
            os.close(fd)


def _execution_load_outcomes(*, limit: int) -> dict[str, Any]:
    text = _read_private_text(
        EXECUTION_OUTCOME_LOG,
        max_bytes=EXECUTION_GOVERNOR_MAX_OUTCOME_BYTES,
        require_private=True,
    )
    if text is None:
        return {
            "records": [],
            "scanned_lines": 0,
            "valid_records_total": 0,
            "recorded_at_unix_values": [],
            "invalid_lines": 0,
            "duplicate_outcome_ids": [],
            "duplicate_outcome_ids_truncated": False,
            "integrity_valid": True,
        }
    records: list[dict[str, Any]] = []
    invalid_lines = 0
    scanned_lines = 0
    valid_records_total = 0
    recorded_at_unix_values: list[int] = []
    outcome_id_counts: Counter[str] = Counter()
    for line in text.splitlines():
        if not line.strip():
            continue
        scanned_lines += 1
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        record = _validated_execution_outcome_record(value)
        if record is None:
            invalid_lines += 1
            continue
        valid_records_total += 1
        recorded_at_unix_values.append(record["recorded_at_unix"])
        outcome_id_counts[record["outcome_id"]] += 1
        records.append(record)
    if len(records) > limit:
        records = records[-limit:]
    duplicate_outcome_ids = sorted(
        outcome_id
        for outcome_id, count in outcome_id_counts.items()
        if count > 1
    )
    return {
        "records": records,
        "scanned_lines": scanned_lines,
        "valid_records_total": valid_records_total,
        "recorded_at_unix_values": recorded_at_unix_values,
        "invalid_lines": invalid_lines,
        "duplicate_outcome_ids": duplicate_outcome_ids[:20],
        "duplicate_outcome_ids_truncated": len(duplicate_outcome_ids) > 20,
        "integrity_valid": not invalid_lines and not duplicate_outcome_ids,
    }

def _execution_outcome_fields(
    *,
    recommendation_id: str,
    operation_class: str,
    risk_level: str,
    recommended_route: str,
    actual_route: str,
    first_pass_success: bool,
    unchanged_retries: int,
    ambiguous_mutation_outcomes: int,
    tool_call_count: int,
    elapsed_ms: int,
    evidence_ref: str,
    regression_signal: bool,
    friction_event_ids: list[str] | None,
) -> dict[str, Any]:
    if not isinstance(recommendation_id, str) or not EXECUTION_RECOMMENDATION_ID_RE.fullmatch(
        recommendation_id
    ):
        raise ValueError("recommendation_id must be a lowercase SHA-256 hex digest")
    return {
        "recommendation_id": recommendation_id,
        "operation_class": _execution_enum(
            operation_class, label="operation_class", allowed=EXECUTION_OPERATION_CLASSES
        ),
        "risk_level": _execution_enum(
            risk_level, label="risk_level", allowed=EXECUTION_RISK_LEVELS
        ),
        "recommended_route": _execution_enum(
            recommended_route, label="recommended_route", allowed=EXECUTION_ROUTES
        ),
        "actual_route": _execution_enum(
            actual_route, label="actual_route", allowed=EXECUTION_ROUTES
        ),
        "first_pass_success": _execution_bool(
            first_pass_success, label="first_pass_success"
        ),
        "unchanged_retries": _execution_int(
            unchanged_retries, label="unchanged_retries", minimum=0, maximum=20
        ),
        "ambiguous_mutation_outcomes": _execution_int(
            ambiguous_mutation_outcomes,
            label="ambiguous_mutation_outcomes",
            minimum=0,
            maximum=20,
        ),
        "tool_call_count": _execution_int(
            tool_call_count, label="tool_call_count", minimum=1, maximum=1000
        ),
        "elapsed_ms": _execution_int(
            elapsed_ms, label="elapsed_ms", minimum=0, maximum=86_400_000
        ),
        "regression_signal": _execution_bool(
            regression_signal, label="regression_signal"
        ),
        "friction_event_ids": _execution_event_ids(friction_event_ids),
        "evidence_ref": _execution_evidence_ref(evidence_ref),
    }


def _record_execution_outcome_with_id(
    *,
    outcome_id: str,
    binding_id: str | None,
    fields: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(outcome_id, str) or not EXECUTION_OUTCOME_ID_RE.fullmatch(outcome_id):
        raise ValueError("outcome_id must be a lowercase 128-bit hex identifier")
    if binding_id is not None and (
        not isinstance(binding_id, str)
        or not EXECUTION_RECOMMENDATION_ID_RE.fullmatch(binding_id)
    ):
        raise ValueError("binding_id must be a lowercase SHA-256 hex digest")
    record = {
        "schema_version": 1,
        "outcome_id": outcome_id,
        "recorded_at_unix": 0,
        **fields,
    }
    idempotent = False
    with _execution_outcome_log_lock(exclusive=True):
        now = int(time.time())
        existing = _execution_load_outcomes(limit=EXECUTION_GOVERNOR_MAX_RECORDS)
        if existing["integrity_valid"] is not True:
            raise RuntimeError("execution outcome ledger integrity is invalid")
        matches = [
            item for item in existing["records"]
            if item.get("outcome_id") == outcome_id
        ]
        if matches:
            if len(matches) != 1:
                raise RuntimeError("execution outcome ledger integrity is invalid")
            existing_record = matches[0]
            expected = dict(record)
            expected["recorded_at_unix"] = existing_record["recorded_at_unix"]
            if existing_record != expected:
                raise RuntimeError(
                    "execution outcome binding already exists with different evidence"
                )
            record = existing_record
            idempotent = True
        else:
            record["recorded_at_unix"] = now
            if any(
                recorded_at_unix > now + 60
                for recorded_at_unix in existing["recorded_at_unix_values"]
            ):
                raise RuntimeError("execution outcome ledger integrity is invalid")
            if existing["valid_records_total"] >= EXECUTION_GOVERNOR_MAX_RECORDS:
                raise RuntimeError("execution outcome ledger record limit reached")
            _append_jsonl(EXECUTION_OUTCOME_LOG, record)
    if not idempotent:
        base._append_audit({
            "timestamp_unix": record["recorded_at_unix"],
            "operation": "execution-governor-outcome-record",
            "outcome_id": record["outcome_id"],
            "recommendation_id": record["recommendation_id"],
            "risk_level": record["risk_level"],
            "recommended_route": record["recommended_route"],
            "actual_route": record["actual_route"],
            "regression_signal": record["regression_signal"],
            "binding_id": binding_id,
        })
    return {
        "recorded": True,
        "idempotent": idempotent,
        "outcome_id": record["outcome_id"],
        "recommendation_id": record["recommendation_id"],
        "binding_id": binding_id,
        "path": str(EXECUTION_OUTCOME_LOG),
        "shadow_mode": True,
        "promotion_applied": False,
    }


def record_execution_outcome_once(
    *,
    binding_id: str,
    recommendation_id: str,
    operation_class: str,
    risk_level: str,
    recommended_route: str,
    actual_route: str,
    first_pass_success: bool,
    unchanged_retries: int,
    ambiguous_mutation_outcomes: int,
    tool_call_count: int,
    elapsed_ms: int,
    evidence_ref: str,
    regression_signal: bool = False,
    friction_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(binding_id, str) or not EXECUTION_RECOMMENDATION_ID_RE.fullmatch(
        binding_id
    ):
        raise ValueError("binding_id must be a lowercase SHA-256 hex digest")
    outcome_id = hashlib.sha256(
        f"execution-outcome-binding-v1:{binding_id}".encode("utf-8")
    ).hexdigest()[:32]
    fields = _execution_outcome_fields(
        recommendation_id=recommendation_id,
        operation_class=operation_class,
        risk_level=risk_level,
        recommended_route=recommended_route,
        actual_route=actual_route,
        first_pass_success=first_pass_success,
        unchanged_retries=unchanged_retries,
        ambiguous_mutation_outcomes=ambiguous_mutation_outcomes,
        tool_call_count=tool_call_count,
        elapsed_ms=elapsed_ms,
        evidence_ref=evidence_ref,
        regression_signal=regression_signal,
        friction_event_ids=friction_event_ids,
    )
    return _record_execution_outcome_with_id(
        outcome_id=outcome_id,
        binding_id=binding_id,
        fields=fields,
    )


def record_execution_outcome(
    *,
    recommendation_id: str,
    operation_class: str,
    risk_level: str,
    recommended_route: str,
    actual_route: str,
    first_pass_success: bool,
    unchanged_retries: int,
    ambiguous_mutation_outcomes: int,
    tool_call_count: int,
    elapsed_ms: int,
    evidence_ref: str,
    regression_signal: bool = False,
    friction_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    fields = _execution_outcome_fields(
        recommendation_id=recommendation_id,
        operation_class=operation_class,
        risk_level=risk_level,
        recommended_route=recommended_route,
        actual_route=actual_route,
        first_pass_success=first_pass_success,
        unchanged_retries=unchanged_retries,
        ambiguous_mutation_outcomes=ambiguous_mutation_outcomes,
        tool_call_count=tool_call_count,
        elapsed_ms=elapsed_ms,
        evidence_ref=evidence_ref,
        regression_signal=regression_signal,
        friction_event_ids=friction_event_ids,
    )
    return _record_execution_outcome_with_id(
        outcome_id=uuid.uuid4().hex,
        binding_id=None,
        fields=fields,
    )


def execution_governor_summary(
    *,
    limit: int = 200,
    now_unix: int | None = None,
) -> dict[str, Any]:
    limit = _execution_int(limit, label="limit", minimum=1, maximum=500)
    if now_unix is None:
        now = int(time.time())
    else:
        now = _execution_int(
            now_unix,
            label="now_unix",
            minimum=0,
            maximum=4_102_444_800,
        )
    with _execution_outcome_log_lock(exclusive=False):
        loaded = _execution_load_outcomes(limit=limit)
    decayed_before = now - EXECUTION_GOVERNOR_DECAY_SECONDS
    expired_records = [
        record
        for record in loaded["records"]
        if record["recorded_at_unix"] < decayed_before
    ]
    future_dated_total = sum(
        recorded_at_unix > now + 60
        for recorded_at_unix in loaded["recorded_at_unix_values"]
    )
    active_records = [
        record
        for record in loaded["records"]
        if decayed_before <= record["recorded_at_unix"] <= now + 60
    ]
    ledger_integrity_valid = (
        loaded["integrity_valid"] is True and future_dated_total == 0
    )
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in active_records:
        key = (
            str(record.get("operation_class", "unknown")),
            str(record.get("risk_level", "unknown")),
            str(record.get("recommended_route", "unknown")),
        )
        groups.setdefault(key, []).append(record)

    candidates: list[dict[str, Any]] = []
    for (operation_class, risk_level, route), records in sorted(groups.items()):
        count = len(records)
        successes = sum(record.get("first_pass_success") is True for record in records)
        retries = sum(
            int(record.get("unchanged_retries", 0))
            for record in records
            if isinstance(record.get("unchanged_retries", 0), int)
        )
        ambiguous = sum(
            int(record.get("ambiguous_mutation_outcomes", 0))
            for record in records
            if isinstance(record.get("ambiguous_mutation_outcomes", 0), int)
        )
        regressions = sum(record.get("regression_signal") is True for record in records)
        success_rate = successes / count if count else 0.0
        average_unchanged_retries = retries / count if count else 0.0
        circuit_breaker_open = (
            not ledger_integrity_valid
            or regressions >= 2
            or ambiguous > 0
            or (count >= EXECUTION_GOVERNOR_MIN_EVIDENCE and success_rate < 0.60)
        )
        eligible_risk = risk_level in {"low", "medium"}
        eligible = (
            eligible_risk
            and count >= EXECUTION_GOVERNOR_MIN_EVIDENCE
            and success_rate >= 0.80
            and average_unchanged_retries <= 0.20
            and ambiguous == 0
            and regressions == 0
            and not circuit_breaker_open
        )
        if not ledger_integrity_valid:
            status = "disabled_by_integrity_gate"
        elif not eligible_risk:
            status = "excluded_high_risk"
        elif circuit_breaker_open:
            status = "disabled_by_circuit_breaker"
        elif eligible:
            status = "eligible_shadow_candidate"
        else:
            status = "insufficient_or_unproven_evidence"
        candidates.append({
            "operation_class": operation_class,
            "risk_level": risk_level,
            "route": route,
            "active_evidence_count": count,
            "minimum_evidence": EXECUTION_GOVERNOR_MIN_EVIDENCE,
            "first_pass_success_rate": round(success_rate, 4),
            "average_unchanged_retries": round(average_unchanged_retries, 4),
            "ambiguous_mutation_outcomes": ambiguous,
            "regression_signals": regressions,
            "circuit_breaker_open": circuit_breaker_open,
            "status": status,
            "promotion_eligible": eligible,
            "promotion_applied": False,
            "reversible": True,
            "rollback_state": "not_applicable_shadow_only",
        })

    summary_core = {
        "schema_version": 1,
        "authority": "shadow_evaluation_only",
        "path": str(EXECUTION_OUTCOME_LOG),
        "exists": EXECUTION_OUTCOME_LOG.exists(),
        "limit": limit,
        "scanned_lines": loaded["scanned_lines"],
        "valid_records_total": loaded["valid_records_total"],
        "invalid_lines": loaded["invalid_lines"],
        "duplicate_outcome_ids": loaded["duplicate_outcome_ids"],
        "duplicate_outcome_ids_truncated": loaded["duplicate_outcome_ids_truncated"],
        "ledger_integrity_valid": ledger_integrity_valid,
        "returned": len(loaded["records"]),
        "active_after_decay": len(active_records),
        "expired_by_decay": len(expired_records),
        "future_dated": future_dated_total,
        "decay_seconds": EXECUTION_GOVERNOR_DECAY_SECONDS,
        "minimum_evidence": EXECUTION_GOVERNOR_MIN_EVIDENCE,
        "candidates": candidates,
        "live_promotions": [],
        "automatic_live_routing_enabled": False,
        "immutable_boundaries": list(EXECUTION_GOVERNOR_IMMUTABLE_BOUNDARIES),
        "does_not_establish": list(EXECUTION_GOVERNOR_NON_CLAIMS),
    }
    return {
        **summary_core,
        "summary_sha256": _execution_sha256(summary_core),
    }


@mcp.tool(name="grabowski_execution_shape", annotations=READ_ONLY)
def grabowski_execution_shape(
    operation_class: str,
    risk_level: str,
    may_mutate: bool,
    command_count: int = 1,
    expected_output_bytes: int = 0,
    resource_keys_count: int = 1,
    typed_tool_available: bool = False,
    grip_available: bool = False,
    durable_task_available: bool = False,
    lease_state: str = "unknown",
    prior_failure_class: str = "unknown",
    transport_sensitive: bool = False,
    post_state_read_available: bool = True,
    friction_limit: int = 100,
    nonconflict_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recommend one bounded execution shape from typed inputs and friction evidence."""
    return execution_shape_recommendation(
        operation_class=operation_class,
        risk_level=risk_level,
        may_mutate=may_mutate,
        command_count=command_count,
        expected_output_bytes=expected_output_bytes,
        resource_keys_count=resource_keys_count,
        typed_tool_available=typed_tool_available,
        grip_available=grip_available,
        durable_task_available=durable_task_available,
        lease_state=lease_state,
        prior_failure_class=prior_failure_class,
        transport_sensitive=transport_sensitive,
        post_state_read_available=post_state_read_available,
        friction_limit=friction_limit,
        nonconflict_proof=nonconflict_proof,
    )


@mcp.tool(name="grabowski_execution_outcome_record", annotations=MUTATING)
def grabowski_execution_outcome_record(
    recommendation_id: str,
    operation_class: str,
    risk_level: str,
    recommended_route: str,
    actual_route: str,
    first_pass_success: bool,
    unchanged_retries: int,
    ambiguous_mutation_outcomes: int,
    tool_call_count: int,
    elapsed_ms: int,
    evidence_ref: str,
    regression_signal: bool = False,
    friction_event_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Record bounded predicted-versus-actual execution evidence in shadow mode."""
    base._require_mutations_enabled("friction_record")
    return record_execution_outcome(
        recommendation_id=recommendation_id,
        operation_class=operation_class,
        risk_level=risk_level,
        recommended_route=recommended_route,
        actual_route=actual_route,
        first_pass_success=first_pass_success,
        unchanged_retries=unchanged_retries,
        ambiguous_mutation_outcomes=ambiguous_mutation_outcomes,
        tool_call_count=tool_call_count,
        elapsed_ms=elapsed_ms,
        evidence_ref=evidence_ref,
        regression_signal=regression_signal,
        friction_event_ids=friction_event_ids,
    )


@mcp.tool(name="grabowski_execution_governor_summary", annotations=READ_ONLY)
def grabowski_execution_governor_summary(limit: int = 200) -> dict[str, Any]:
    """Summarize shadow outcomes, decay and circuit-breaker candidates."""
    return execution_governor_summary(limit=limit)

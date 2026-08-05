from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any, Literal, cast, get_args

import grabowski_audit_query as audit_query
import grabowski_mcp as base
import grabowski_operator_core as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

EffectProfile = Literal[
    "read_only",
    "workspace_write",
    "repository_write",
    "host_write",
    "remote_write",
    "unknown",
]
ReposkopPolicy = Literal["required", "not_required"]
EFFECT_PROFILES = frozenset(get_args(EffectProfile))
REPOSKOP_POLICIES = frozenset(get_args(ReposkopPolicy))
AGENT_EXECUTABLES = frozenset(
    {"agy", "claude", "cline", "codex", "grok", "grok-cli", "opencode", "openhands"}
)
READ_ONLY_AGENT_MODES = frozenset({"plan", "read-only"})
POLICY_VERSION = 2
SURFACE = "task_start"
MAX_SCAN_LIMIT = 50_000
DEFAULT_SCAN_LIMIT = 10_000
MAX_SAMPLE_REFS = 20
MIN_OPERATIONAL_FAILURE_SAMPLE = 3
MIN_RUNTIME_REGRESSION_SAMPLE = 60
RUNTIME_REGRESSION_FACTOR = 1.5


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def validate_effect_profile(value: str | None) -> EffectProfile | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in EFFECT_PROFILES:
        raise ValueError(f"effect_profile must be one of {sorted(EFFECT_PROFILES)}")
    return cast(EffectProfile, value)


def _argument_value(argv: list[str], *names: str) -> str | None:
    for index, item in enumerate(argv):
        if item in names:
            return argv[index + 1] if index + 1 < len(argv) else None
        for name in names:
            prefix = f"{name}="
            if item.startswith(prefix):
                return item[len(prefix) :]
    return None


def _agent_read_only(argv: list[str], executable: str) -> bool:
    if "--read-only" in argv:
        return True
    if executable == "codex":
        return _argument_value(argv, "--sandbox", "-s") in READ_ONLY_AGENT_MODES
    return _argument_value(argv, "--permission-mode") in READ_ONLY_AGENT_MODES


def classify_task_effect(
    *,
    transport: str,
    argv: list[str],
    mutating_workspace: str | None,
    explicit_effect_profile: str | None = None,
) -> dict[str, Any]:
    explicit = validate_effect_profile(explicit_effect_profile)
    executable = Path(argv[0]).name.lower()
    declared_agent = executable in AGENT_EXECUTABLES
    read_only_mode = declared_agent and _agent_read_only(argv, executable)

    if declared_agent and explicit == "unknown":
        raise ValueError("declared local or remote agents may not use effect_profile=unknown")

    if not declared_agent:
        profile: EffectProfile = explicit or "unknown"
        return {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "surface": SURFACE,
            "effect_profile": profile,
            "reposkop_policy": "not_required",
            "agent_executable": None,
            "classification_source": "explicit" if explicit is not None else "legacy_default_unknown",
        }

    if transport != "local":
        derived: EffectProfile = "read_only" if read_only_mode else "remote_write"
        if explicit is not None and explicit != derived:
            raise ValueError(
                f"effect_profile={explicit} conflicts with derived agent profile {derived}"
            )
        return {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "surface": SURFACE,
            "effect_profile": derived,
            "reposkop_policy": "not_required",
            "agent_executable": executable,
            "classification_source": "explicit" if explicit is not None else "agent_command",
        }

    if read_only_mode:
        if explicit is not None and explicit != "read_only":
            raise ValueError(
                f"effect_profile={explicit} conflicts with read-only agent mode"
            )
        return {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "surface": SURFACE,
            "effect_profile": "read_only",
            "reposkop_policy": "not_required",
            "agent_executable": executable,
            "classification_source": "explicit" if explicit is not None else "agent_command",
        }

    if mutating_workspace is None:
        raise RuntimeError("write-capable local agent classification has no workspace")
    if explicit is not None and explicit not in {"workspace_write", "repository_write"}:
        raise ValueError(
            f"effect_profile={explicit} conflicts with write-capable local agent"
        )
    profile = explicit or "workspace_write"
    return {
        "schema_version": 1,
        "policy_version": POLICY_VERSION,
        "surface": SURFACE,
        "effect_profile": profile,
        "reposkop_policy": "required",
        "agent_executable": executable,
        "classification_source": "explicit" if explicit is not None else "agent_command",
    }


def evaluation_id(
    *,
    task_id: str,
    execution_identity_sha256: str,
    checkout_binding_sha256: str,
    argv_sha256: str,
    policy_version: int = POLICY_VERSION,
) -> str:
    return _sha256_json(
        {
            "schema_version": 1,
            "kind": "grabowski.reposkop_evaluation_identity",
            "policy_version": policy_version,
            "surface": SURFACE,
            "task_id": task_id,
            "execution_identity_sha256": execution_identity_sha256,
            "checkout_binding_sha256": checkout_binding_sha256,
            "argv_sha256": argv_sha256,
        }
    )


def finding_summary() -> dict[str, Any]:
    return {
        "finding_taxonomy_status": "not_available_v1",
        "finding_count": None,
        "finding_counts": {},
        "finding_categories": {},
    }


def append_event(record: dict[str, Any]) -> str:
    forbidden = {"argv", "command", "prompt", "raw_report", "error", "stderr", "stdout"}
    present = forbidden & set(record)
    if present:
        raise ValueError(f"Reposkop public audit event contains forbidden fields: {sorted(present)}")
    digest = base._append_audit_with_digest(record)
    return f"audit-record-sha256:{digest}"


def enrich_attestation(
    attestation: dict[str, Any],
    *,
    evaluation: str,
    classification: dict[str, Any],
    checkout_binding_sha256: str,
    duration_ms: int,
) -> dict[str, Any]:
    material = {
        key: value
        for key, value in attestation.items()
        if key != "execution_binding_sha256"
    }
    material.update(
        {
            "evaluation_id": evaluation,
            "effect_profile": classification["effect_profile"],
            "reposkop_policy": classification["reposkop_policy"],
            "surface": classification["surface"],
            "agent_executable": classification["agent_executable"],
            "checkout_binding_sha256": checkout_binding_sha256,
            "duration_ms": duration_ms,
            "finding_summary": finding_summary(),
        }
    )
    return {**material, "execution_binding_sha256": _sha256_json(material)}


def _raw_records(
    *,
    since_unix: int,
    scan_limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    snapshot = audit_query.capture_verified_audit_snapshot()
    records: list[dict[str, Any]] = []
    scanned = 0
    for segment in reversed(snapshot.segments):
        data = audit_query._load_snapshot_segment(segment)
        lines = data.splitlines()
        if len(lines) != segment.records:
            raise RuntimeError("verified audit segment changed during Reposkop projection")
        for raw_line in reversed(lines):
            if scanned >= scan_limit:
                break
            scanned += 1
            parsed = json.loads(raw_line.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise RuntimeError("verified audit record is not an object")
            timestamp = parsed.get("timestamp_unix")
            if isinstance(timestamp, int) and timestamp < since_unix:
                continue
            digest = parsed.get("record_sha256")
            if not isinstance(digest, str):
                digest = hashlib.sha256(raw_line).hexdigest()
            records.append({**parsed, "_audit_ref": f"audit-record-sha256:{digest}"})
        if scanned >= scan_limit:
            break
    return records, {
        "chain_content_sha256": snapshot.chain_content_sha256,
        "chain_materialization_sha256": snapshot.chain_materialization_sha256,
        "total_records": snapshot.total_records,
        "scanned_records": scanned,
        "scan_limit": scan_limit,
        "scan_truncated": snapshot.total_records > scanned,
    }


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def _candidate(
    metric: str,
    *,
    status: str,
    threshold: Any,
    observed: Any,
    sample_size: int,
    evidence_refs: list[str],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    binding = {
        "metric": metric,
        "policy_version": POLICY_VERSION,
        "threshold": threshold,
        "context": context or {},
    }
    return {
        "metric": metric,
        "status": status,
        "threshold": threshold,
        "observed": observed,
        "sample_size": sample_size,
        "evidence_refs": evidence_refs[:MAX_SAMPLE_REFS],
        "deduplication_key": _sha256_json(binding),
        "context": context or {},
    }


def project_records(
    records: list[dict[str, Any]],
    *,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    relevant = {
        "reposkop-evaluation-requested",
        "reposkop-evaluation-completed",
        "reposkop-decision-applied",
        "reposkop-execution-attestation-blocked",
        "reposkop-task-outcome-observed",
        "task-start",
    }
    requested: dict[str, dict[str, Any]] = {}
    completed: dict[str, dict[str, Any]] = {}
    decisions: dict[str, dict[str, Any]] = {}
    blocked: dict[str, dict[str, Any]] = {}
    outcomes: dict[str, dict[str, Any]] = {}
    classified_starts: list[dict[str, Any]] = []
    legacy_unclassified = 0

    for record in records:
        operation = record.get("operation")
        if operation == "task-start":
            if record.get("effect_profile") in EFFECT_PROFILES:
                classified_starts.append(record)
            else:
                legacy_unclassified += 1
            continue
        if operation not in relevant:
            continue
        evaluation = record.get("evaluation_id")
        if not isinstance(evaluation, str) or len(evaluation) != 64:
            continue
        if operation == "reposkop-evaluation-requested":
            requested.setdefault(evaluation, record)
        elif operation == "reposkop-evaluation-completed":
            completed.setdefault(evaluation, record)
        elif operation == "reposkop-decision-applied":
            decisions.setdefault(evaluation, record)
        elif operation == "reposkop-execution-attestation-blocked":
            blocked.setdefault(evaluation, record)
        elif operation == "reposkop-task-outcome-observed":
            outcomes.setdefault(evaluation, record)

    attempts: dict[str, dict[str, Any]] = dict(requested)
    for start in classified_starts:
        if start.get("reposkop_policy") != "required":
            continue
        evaluation = start.get("evaluation_id")
        key = evaluation if isinstance(evaluation, str) and evaluation else f"task:{start.get('task_id')}"
        attempts.setdefault(key, start)
    for evaluation, record in blocked.items():
        attempts.setdefault(evaluation, record)

    required_ids = set(attempts)
    allowed_decisions = {
        evaluation
        for evaluation, value in decisions.items()
        if value.get("final_decision") == "allow"
    }
    verified_ids = required_ids & set(completed) & allowed_decisions
    blocked_ids = required_ids & set(blocked)
    missing_ids = required_ids - verified_ids - blocked_ids
    terminal_ids = verified_ids & set(outcomes)
    terminal_successes = {
        value for value in terminal_ids if outcomes[value].get("terminal_state") == "completed"
    }
    terminal_failures = terminal_ids - terminal_successes

    group_counts: dict[str, dict[str, int]] = {
        "effect_profile": {},
        "surface": {},
        "agent": {},
        "policy_version": {},
    }
    for value in attempts.values():
        dimensions = {
            "effect_profile": str(value.get("effect_profile") or "unknown"),
            "surface": str(value.get("surface") or "unknown"),
            "agent": str(value.get("agent_executable") or "non_agent"),
            "policy_version": str(value.get("policy_version") or "legacy"),
        }
        for dimension, member in dimensions.items():
            group_counts[dimension][member] = group_counts[dimension].get(member, 0) + 1

    durations_with_time = sorted(
        (
            (int(value.get("timestamp_unix") or 0), int(value["duration_ms"]))
            for value in completed.values()
            if isinstance(value.get("duration_ms"), int)
            and not isinstance(value.get("duration_ms"), bool)
            and int(value["duration_ms"]) >= 0
        ),
        key=lambda item: item[0],
    )
    durations = [value for _timestamp, value in durations_with_time]
    p50 = _percentile(durations, 0.50)
    p95 = _percentile(durations, 0.95)

    refs = [
        str(value.get("_audit_ref"))
        for mapping in (requested, completed, blocked, outcomes)
        for value in mapping.values()
        if isinstance(value.get("_audit_ref"), str)
    ][:MAX_SAMPLE_REFS]
    missing_refs = [
        str(attempts[value].get("_audit_ref"))
        for value in sorted(missing_ids)
        if isinstance(attempts[value].get("_audit_ref"), str)
    ]
    blocked_refs = [
        str(blocked[value].get("_audit_ref"))
        for value in sorted(blocked_ids)
        if isinstance(blocked[value].get("_audit_ref"), str)
    ]

    improvement_candidates = [
        _candidate(
            "missing_required_attestation",
            status="active" if missing_ids else "clear",
            threshold=0,
            observed=len(missing_ids),
            sample_size=len(required_ids),
            evidence_refs=missing_refs,
        ),
        _candidate(
            "repeated_operational_failure",
            status=(
                "active"
                if len(blocked_ids) >= MIN_OPERATIONAL_FAILURE_SAMPLE
                else "insufficient_sample"
            ),
            threshold=MIN_OPERATIONAL_FAILURE_SAMPLE,
            observed=len(blocked_ids),
            sample_size=len(required_ids),
            evidence_refs=blocked_refs,
        ),
    ]
    if len(durations) >= MIN_RUNTIME_REGRESSION_SAMPLE:
        midpoint = len(durations_with_time) // 2
        baseline = [value for _timestamp, value in durations_with_time[:midpoint]]
        recent = [value for _timestamp, value in durations_with_time[midpoint:]]
        baseline_p95 = _percentile(baseline, 0.95) or 0
        recent_p95 = _percentile(recent, 0.95) or 0
        threshold = int(baseline_p95 * RUNTIME_REGRESSION_FACTOR)
        runtime_status = "active" if baseline_p95 > 0 and recent_p95 > threshold else "clear"
        improvement_candidates.append(
            _candidate(
                "p95_runtime_regression",
                status=runtime_status,
                threshold={"factor": RUNTIME_REGRESSION_FACTOR, "baseline_p95_ms": baseline_p95},
                observed={"recent_p95_ms": recent_p95},
                sample_size=len(durations),
                evidence_refs=refs,
            )
        )
    else:
        improvement_candidates.append(
            _candidate(
                "p95_runtime_regression",
                status="insufficient_sample",
                threshold={"minimum_sample": MIN_RUNTIME_REGRESSION_SAMPLE},
                observed={"p95_ms": p95},
                sample_size=len(durations),
                evidence_refs=refs,
            )
        )

    required_count = len(required_ids)
    covered_count = len(verified_ids | blocked_ids)
    technical_denominator = len(verified_ids) + len(blocked_ids)
    return {
        "schema_version": 1,
        "kind": "grabowski_reposkop_effectiveness_projection",
        "authority": "derived_from_verified_audit_chain",
        "policy_version": POLICY_VERSION,
        "source": source or {},
        "classified_task_starts": len(classified_starts),
        "legacy_unclassified_task_starts": legacy_unclassified,
        "required_task_starts": required_count,
        "required_verified": len(verified_ids),
        "required_blocked": len(blocked_ids),
        "required_missing": len(missing_ids),
        "coverage_ratio": covered_count / required_count if required_count else None,
        "technical_success_ratio": (
            len(verified_ids) / technical_denominator if technical_denominator else None
        ),
        "terminal_outcomes": len(terminal_ids),
        "terminal_successes": len(terminal_successes),
        "terminal_failures": len(terminal_failures),
        "unresolved": len(verified_ids - terminal_ids),
        "groups": group_counts,
        "duration_ms": {
            "sample_size": len(durations),
            "p50": p50,
            "p95": p95,
        },
        "sample_evidence_refs": refs,
        "improvement_candidates": improvement_candidates,
        "does_not_establish": [
            "causality_between_reposkop_and_task_outcome",
            "semantic_correctness_of_agent_output",
            "false_positive_or_false_negative_classification_without_review",
            "future_failure_probability",
        ],
    }


def build_reposkop_effectiveness(
    *,
    since_unix: int = 0,
    limit: int = DEFAULT_SCAN_LIMIT,
) -> dict[str, Any]:
    if isinstance(since_unix, bool) or not isinstance(since_unix, int) or since_unix < 0:
        raise ValueError("since_unix must be a non-negative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SCAN_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_SCAN_LIMIT}")
    records, source = _raw_records(since_unix=since_unix, scan_limit=limit)
    return project_records(records, source=source)


def _marker_payload(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Reposkop outcome marker is invalid")
    unsigned = {key: item for key, item in value.items() if key != "marker_sha256"}
    if value.get("marker_sha256") != _sha256_json(unsigned):
        raise RuntimeError("Reposkop outcome marker integrity is invalid")
    return value


def _write_marker(path: Path, value: dict[str, Any], *, exclusive: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {**value, "marker_sha256": _sha256_json(value)}
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _find_existing_outcome(evaluation: str, event_sha256: str) -> str | None:
    records, _source = _raw_records(since_unix=0, scan_limit=MAX_SCAN_LIMIT)
    for record in records:
        if (
            record.get("operation") == "reposkop-task-outcome-observed"
            and record.get("evaluation_id") == evaluation
            and record.get("outcome_event_sha256") == event_sha256
        ):
            return str(record.get("_audit_ref"))
    return None


def record_task_outcome(
    *,
    marker_root: Path,
    attestation: dict[str, Any] | None,
    task_id: str,
    terminal_state: str,
    lifecycle_receipt_sha256: str,
    terminalized_at_unix: int,
    observation: dict[str, Any] | None,
) -> str | None:
    if not isinstance(attestation, dict):
        return None
    evaluation = attestation.get("evaluation_id")
    if not isinstance(evaluation, str) or len(evaluation) != 64:
        return None
    properties = (observation or {}).get("properties")
    if not isinstance(properties, dict):
        properties = {}
    event_material = {
        "operation": "reposkop-task-outcome-observed",
        "timestamp_unix": terminalized_at_unix,
        "transaction_id": evaluation,
        "evaluation_id": evaluation,
        "task_id": task_id,
        "effect_profile": attestation.get("effect_profile"),
        "reposkop_policy": attestation.get("reposkop_policy"),
        "surface": attestation.get("surface"),
        "agent_executable": attestation.get("agent_executable"),
        "policy_version": attestation.get("policy_version"),
        "terminal_state": terminal_state,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "unit_result": properties.get("Result"),
        "exec_main_code": properties.get("ExecMainCode"),
        "exec_main_status": properties.get("ExecMainStatus"),
        "terminal_success": terminal_state == "completed",
    }
    event_sha256 = _sha256_json(event_material)
    event = {**event_material, "outcome_event_sha256": event_sha256}
    marker = marker_root / f"{evaluation}.json"
    existing = _marker_payload(marker)
    created_pending = False
    if existing is not None:
        if existing.get("outcome_event_sha256") != event_sha256:
            raise RuntimeError("Reposkop outcome marker belongs to another terminal outcome")
        if existing.get("status") == "completed":
            return cast(str, existing["audit_ref"])
    else:
        try:
            _write_marker(
                marker,
                {
                    "schema_version": 1,
                    "kind": "grabowski.reposkop_outcome_marker",
                    "status": "pending",
                    "evaluation_id": evaluation,
                    "task_id": task_id,
                    "outcome_event_sha256": event_sha256,
                },
                exclusive=True,
            )
            created_pending = True
        except FileExistsError:
            existing = _marker_payload(marker)
            if existing is None or existing.get("outcome_event_sha256") != event_sha256:
                raise RuntimeError("Reposkop outcome marker race changed identity")
    audit_ref = (
        None
        if created_pending
        else _find_existing_outcome(evaluation, event_sha256)
    )
    if audit_ref is None:
        audit_ref = append_event(event)
    completed_marker = {
        "schema_version": 1,
        "kind": "grabowski.reposkop_outcome_marker",
        "status": "completed",
        "evaluation_id": evaluation,
        "task_id": task_id,
        "outcome_event_sha256": event_sha256,
        "audit_ref": audit_ref,
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{evaluation}.", dir=marker_root)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        _write_marker(temporary, completed_marker, exclusive=False)
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    return audit_ref


@mcp.tool(name="grabowski_reposkop_effectiveness", annotations=READ_ONLY)
async def grabowski_reposkop_effectiveness(
    since_unix: int = 0,
    limit: int = DEFAULT_SCAN_LIMIT,
) -> dict[str, Any]:
    """Project bounded Reposkop coverage, technical outcomes and improvement signals."""
    base._require_capability("audit_read")
    return await asyncio.to_thread(
        build_reposkop_effectiveness,
        since_unix=since_unix,
        limit=limit,
    )

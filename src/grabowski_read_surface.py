from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field

import grabowski_capabilities as capabilities
import grabowski_mcp as base
import grabowski_consumer_surface as consumer_surface
import grabowski_operator_core as operator
import grabowski_runtime_extensions as runtime_extensions


mcp = operator.mcp

LOCAL_READ = ToolAnnotations(
    title="Read bounded local state",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
REMOTE_READ = ToolAnnotations(
    title="Read bounded GitHub state",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

DEFAULT_OUTPUT_BYTES = 250_000
MAX_OUTPUT_BYTES = 2_000_000
MAX_LOG_LINES = 2_000
MAX_GIT_COMMITS = 100
MAX_WORKTREES = 100
MAX_REVISION_LENGTH = 200
MAX_AUDIT_PROJECTION_TOP = 25
AUDIT_PROJECTION_WINDOWS = (("24h", 86_400), ("7d", 604_800), ("30d", 2_592_000))
AUDIT_PROJECTION_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}")
AUDIT_EFFECT_OPERATIONS = frozenset(
    {
        "create",
        "replace",
        "remove",
        "destroy",
        "git-branch",
        "checkout-archive",
        "checkout-cleanup-apply",
        "bureau-task-publish",
        "runtime-deploy-scheduled",
    }
)
AUDIT_BUREAU_FAILURE_STATUSES = frozenset(
    {
        "failed",
        "stale-runtime-blocked",
        "publication-unclear",
    }
)
REVISION_RE = re.compile(r"[A-Za-z0-9_./@{}^~:+-]+")
OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
DEPLOYMENT_IDENTITY_FIELDS = (
    "schema_version",
    "release_id",
    "repo_head",
    "entrypoint_contract_sha256",
    "source_sha256",
    "runtime_input_sha256",
    "runtime_lock_sha256",
    "mcp_protocol_version",
    "python_version",
    "python_implementation",
    "platform",
    "completion_status",
)
DEPLOYMENT_INTEGRITY_FIELDS = (
    "manifest_parse_valid",
    "manifest_schema_valid",
    "release_path_valid",
    "release_id_valid",
    "repo_head_valid",
    "stable_runtime_manifest_valid",
    "runtime_pointer_valid",
    "runtime_input_identity_valid",
    "lock_identity_valid",
    "source_snapshot_identity_valid",
    "source_identity_valid",
    "embedded_contract_valid",
    "entrypoint_contract_identity_valid",
    "entrypoint_path_valid",
    "release_python_identity_valid",
    "executable_identity_valid",
    "pip_identity_valid",
    "protocol_identity_valid",
    "python_runtime_identity_valid",
    "platform_identity_valid",
    "artifact_integrity_valid",
    "runtime_binding_valid",
    "environment_compatibility_valid",
    "provenance_valid",
)
SERVICE_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "NRestarts",
)
GITHUB_PR_FIELDS = (
    "number",
    "title",
    "state",
    "isDraft",
    "mergeable",
    "headRefName",
    "baseRefName",
    "url",
    "reviewDecision",
    "updatedAt",
)
GITHUB_CHECK_FIELDS = (
    "bucket",
    "completedAt",
    "description",
    "event",
    "link",
    "name",
    "startedAt",
    "state",
    "workflow",
)


def _read_environment() -> dict[str, str]:
    environment = operator._safe_environment()
    for key in (
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "PAGER",
        "LESS",
        "EDITOR",
        "VISUAL",
        "GH_PAGER",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GH_PROMPT_DISABLED": "1",
            "GH_PAGER": "cat",
            "NO_COLOR": "1",
        }
    )
    return environment


RepositoryPath = Annotated[str, Field(min_length=1, max_length=4096)]
RevisionInput = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_REVISION_LENGTH,
        pattern=REVISION_RE.pattern,
    ),
]
OutputBytes = Annotated[int, Field(ge=1_024, le=MAX_OUTPUT_BYTES)]
GitCommitCount = Annotated[int, Field(ge=1, le=MAX_GIT_COMMITS)]
PullRequestNumber = Annotated[int, Field(ge=1, le=2_147_483_647)]
SystemdUnit = Annotated[str, Field(min_length=1, max_length=255)]
LogLineCount = Annotated[int, Field(ge=1, le=MAX_LOG_LINES)]
AuditProjectionTopLimit = Annotated[int, Field(ge=1, le=MAX_AUDIT_PROJECTION_TOP)]


def _run_read(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int = 60,
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
) -> dict[str, Any]:
    if max_output_bytes < 1_024 or max_output_bytes > MAX_OUTPUT_BYTES:
        raise ValueError(
            f"max_output_bytes must be between 1024 and {MAX_OUTPUT_BYTES}"
        )
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=_read_environment(),
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
    returncode: int | None = process.returncode

    stdout = operator._redact(stdout_raw.decode("utf-8", errors="replace"))
    stderr = operator._redact(stderr_raw.decode("utf-8", errors="replace"))
    stdout, stdout_late_truncated = operator._limit(stdout, max_output_bytes)
    stderr, stderr_late_truncated = operator._limit(stderr, max_output_bytes)
    stdout_truncated = stdout_pipe_truncated or stdout_late_truncated
    stderr_truncated = stderr_pipe_truncated or stderr_late_truncated
    return {
        "argv": operator._redact_argv(argv),
        "argv_sha256": operator._argv_hash(argv),
        "command": operator._redacted_command(argv),
        "cwd": str(cwd),
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def _resolve_repository(raw: str) -> Path:
    path = base._resolve_existing(raw, "read")
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    probe = _run_read(
        _git_command(path, "rev-parse", "--is-inside-work-tree"),
        cwd=path,
        timeout_seconds=20,
        max_output_bytes=16_384,
    )
    if probe["returncode"] != 0 or probe["stdout"].strip() != "true":
        raise ValueError(probe["stderr"].strip() or f"Not a Git worktree: {path}")
    return path


def _git_command(repo: Path, *arguments: str) -> list[str]:
    return [
        "git",
        "-c",
        "core.pager=cat",
        "-c",
        "pager.status=false",
        "-c",
        "pager.diff=false",
        "-c",
        "pager.log=false",
        "-c",
        "pager.show=false",
        "-c",
        "diff.external=",
        "-c",
        "diff.trustExitCode=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(repo),
        *arguments,
    ]


def _validate_revision(revision: str) -> str:
    if (
        not revision
        or len(revision) > MAX_REVISION_LENGTH
        or revision.startswith("-")
        or not REVISION_RE.fullmatch(revision)
    ):
        raise ValueError("Invalid Git revision")
    return revision


def _resolve_revision(repository: Path, revision: str) -> str:
    selected = _validate_revision(revision)
    result = _run_read(
        _git_command(
            repository,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{selected}^{{object}}",
        ),
        cwd=repository,
        timeout_seconds=20,
        max_output_bytes=16_384,
    )
    object_ids = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    if (
        result["returncode"] != 0
        or result["timed_out"]
        or result["stdout_truncated"]
        or len(object_ids) != 1
        or not OBJECT_ID_RE.fullmatch(object_ids[0])
    ):
        message = result["stderr"].strip() or "Revision does not resolve to exactly one Git object"
        raise ValueError(message)
    return object_ids[0]


def _validate_pr(pr: int) -> int:
    if isinstance(pr, bool) or pr < 1 or pr > 2_147_483_647:
        raise ValueError("pr must be a positive integer")
    return pr


def _audit_timestamp_unix(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        return int(parsed.timestamp())
    except (OverflowError, OSError, ValueError):
        return None


def _audit_label(value: Any, *, fallback: str) -> str:
    if not isinstance(value, str) or not value:
        return fallback
    if AUDIT_PROJECTION_LABEL_RE.fullmatch(value) is None:
        return "<redacted>"
    return value


def _audit_top(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [
        {"key": key, "count": count}
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[
            :limit
        ]
    ]


def _audit_failure_reasons(record: dict[str, Any]) -> set[str]:
    reasons: set[str] = set()
    returncode = record.get("returncode")
    if (
        isinstance(returncode, int)
        and not isinstance(returncode, bool)
        and returncode != 0
    ):
        reasons.add("nonzero_returncode")
    if record.get("outcome_unknown") is True:
        reasons.add("outcome_unknown")
    if record.get("launcher_outcome_unknown") is True:
        reasons.add("launcher_outcome_unknown")
    if record.get("effect_started") is False:
        reasons.add("effect_not_started")
    if record.get("bureau_status") in AUDIT_BUREAU_FAILURE_STATUSES:
        reasons.add("bureau_failure_status")
    if record.get("error") not in (None, ""):
        reasons.add("recorded_error")
    return reasons


def _audit_resource_type(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "invalid"
    return _audit_label(value.split(":", 1)[0], fallback="invalid")


def _audit_window_projection(
    records: list[dict[str, Any]],
    *,
    start_unix: int | None,
    end_unix: int,
    label: str,
    top_limit: int,
    view: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    operation_counts: Counter[str] = Counter()
    failure_reason_counts: Counter[str] = Counter()
    bureau_code_counts: Counter[str] = Counter()
    resource_type_counts: Counter[str] = Counter()
    friction_kind_counts: Counter[str] = Counter()
    friction_surface_counts: Counter[str] = Counter()
    task_activity: Counter[str] = Counter()
    resource_activity: Counter[str] = Counter()
    bureau_activity: Counter[str] = Counter()
    mutation_evidence: Counter[str] = Counter()
    timestamp_quality: Counter[str] = Counter()
    failure_signal_count = 0
    reclaimed_resource_count = 0
    resource_reclamation_event_count = 0
    selected_count = 0

    for record in records:
        timestamp_unix = _audit_timestamp_unix(record.get("timestamp"))
        if timestamp_unix is None:
            timestamp_quality["invalid_or_missing"] += 1
            if start_unix is not None:
                continue
        elif timestamp_unix > end_unix + 300:
            timestamp_quality["future_dated"] += 1
            if start_unix is not None:
                continue
        elif start_unix is not None and timestamp_unix < start_unix:
            continue
        else:
            timestamp_quality["valid"] += 1

        selected_count += 1
        operation = record.get("operation")
        operation_key = _audit_label(operation, fallback="<missing>")
        operation_counts[operation_key] += 1

        reasons = _audit_failure_reasons(record)
        if reasons:
            failure_signal_count += 1
            failure_reason_counts.update(reasons)

        bureau_code = record.get("bureau_code")
        if isinstance(bureau_code, str) and bureau_code:
            bureau_code_counts[_audit_label(bureau_code, fallback="unknown")] += 1

        resource_keys = record.get("resource_keys")
        if isinstance(resource_keys, list):
            resource_type_counts.update(
                _audit_resource_type(item) for item in resource_keys
            )

        reclaimed = record.get("reclaimed_count")
        if (
            isinstance(reclaimed, int)
            and not isinstance(reclaimed, bool)
            and reclaimed > 0
        ):
            reclaimed_resource_count += reclaimed
            resource_reclamation_event_count += 1

        if operation_key.startswith("task-"):
            task_activity[operation_key] += 1
        if operation_key.startswith("resource-"):
            resource_activity[operation_key] += 1
        if operation_key.startswith("bureau-"):
            bureau_activity[operation_key] += 1

        if operation_key == "friction-record":
            kind = record.get("kind")
            surface = record.get("surface")
            friction_kind_counts[_audit_label(kind, fallback="unknown")] += 1
            friction_surface_counts[_audit_label(surface, fallback="unknown")] += 1

        if operation_key in AUDIT_EFFECT_OPERATIONS:
            mutation_evidence["selected_operation_receipts"] += 1
            if "before_sha256" in record or "after_sha256" in record:
                mutation_evidence["state_hash_receipts"] += 1
            rollback = record.get("rollback")
            if isinstance(rollback, dict):
                mutation_evidence["rollback_declared"] += 1
                if rollback.get("available") is True:
                    mutation_evidence["rollback_available"] += 1
                elif rollback.get("available") is False:
                    mutation_evidence["rollback_unavailable"] += 1
            recovery_refs = record.get("recovery_refs")
            if isinstance(recovery_refs, list) and recovery_refs:
                mutation_evidence["recovery_reference_receipts"] += 1

    public: dict[str, Any] = {
        "label": label,
        "start_unix": start_unix,
        "end_unix": end_unix,
        "record_count": selected_count,
        "failure_signal_count": failure_signal_count,
        "top_operations": _audit_top(operation_counts, top_limit),
        "task_activity": dict(sorted(task_activity.items())),
        "resource_activity": {
            **dict(sorted(resource_activity.items())),
            "resource_reclamation_event_count": resource_reclamation_event_count,
            "reclaimed_resource_count": reclaimed_resource_count,
        },
        "bureau_activity": dict(sorted(bureau_activity.items())),
        "mutation_evidence": dict(sorted(mutation_evidence.items())),
    }
    if view in {"standard", "evidence"}:
        public.update(
            {
                "top_failure_reasons": _audit_top(failure_reason_counts, top_limit),
                "top_bureau_failure_codes": _audit_top(bureau_code_counts, top_limit),
                "top_resource_types": _audit_top(resource_type_counts, top_limit),
                "friction_activity": {
                    "by_kind": dict(sorted(friction_kind_counts.items())),
                    "by_surface": dict(sorted(friction_surface_counts.items())),
                    "current_resolution_requires_friction_summary": True,
                },
            }
        )
    if view == "evidence":
        public.update(
            {
                "operation_counts": dict(sorted(operation_counts.items())),
                "failure_reason_counts": dict(sorted(failure_reason_counts.items())),
                "bureau_failure_code_counts": dict(sorted(bureau_code_counts.items())),
                "resource_type_counts": dict(sorted(resource_type_counts.items())),
                "timestamp_quality": dict(sorted(timestamp_quality.items())),
            }
        )
    private = {
        "failure_reason_counts": failure_reason_counts,
        "bureau_code_counts": bureau_code_counts,
        "resource_reclamation_event_count": resource_reclamation_event_count,
        "reclaimed_resource_count": reclaimed_resource_count,
        "failure_signal_count": failure_signal_count,
        "timestamp_quality": timestamp_quality,
    }
    return public, private


def _audit_projection_candidates(
    seven_day: dict[str, Any],
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    bureau_codes: Counter[str] = seven_day["bureau_code_counts"]
    repeated_codes = [
        (code, count)
        for code, count in sorted(
            bureau_codes.items(), key=lambda item: (-item[1], item[0])
        )
        if count >= 3
    ]
    if repeated_codes:
        candidates.append(
            {
                "pattern": "repeated_bureau_contract_failures",
                "count_7d": sum(count for _code, count in repeated_codes),
                "top_codes": [
                    {"code": code, "count": count} for code, count in repeated_codes[:5]
                ],
                "recommendation": "Inspect caller/runtime schema compatibility and group only evidence with the same contract identity.",
                "authority": "proposal_only",
                "does_not_establish": ["shared_root_cause", "bureau_task_readiness"],
            }
        )
    failure_reasons: Counter[str] = seven_day["failure_reason_counts"]
    unknown_count = (
        failure_reasons["outcome_unknown"] + failure_reasons["launcher_outcome_unknown"]
    )
    if unknown_count:
        candidates.append(
            {
                "pattern": "ambiguous_execution_outcome",
                "count_7d": unknown_count,
                "recommendation": "Read the exact target state before any unchanged mutation retry.",
                "authority": "proposal_only",
                "does_not_establish": ["mutation_failed", "safe_retry"],
            }
        )
    reclamation_events = int(seven_day["resource_reclamation_event_count"])
    reclaimed_resources = int(seven_day["reclaimed_resource_count"])
    if reclamation_events >= 3:
        candidates.append(
            {
                "pattern": "repeated_resource_reclamation",
                "event_count_7d": reclamation_events,
                "reclaimed_resource_count_7d": reclaimed_resources,
                "recommendation": "Compare lease lifetime, terminalization and release timing before changing lease policy.",
                "authority": "proposal_only",
                "does_not_establish": ["lease_bug", "owner_failure"],
            }
        )
    return candidates[:limit]


def _audit_findings_sha256(
    windows: list[dict[str, Any]],
    all_time: dict[str, Any],
    candidates: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> str:
    def semantic_window(value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item
            for key, item in value.items()
            if key not in {"start_unix", "end_unix"}
        }

    payload = {
        "windows": [semantic_window(item) for item in windows],
        "all_time": semantic_window(all_time),
        "candidate_patterns": candidates,
        "warnings": [
            item
            for item in warnings
            if item.get("code") != "audit_advanced_during_projection"
        ],
    }
    return hashlib.sha256(
        consumer_surface.canonical_json_bytes(payload)
    ).hexdigest()


def _audit_snapshot_binding(records: list[dict[str, Any]]) -> dict[str, Any]:
    first_timestamp = next(
        (
            record.get("timestamp")
            for record in records
            if isinstance(record.get("timestamp"), str)
        ),
        None,
    )
    last_timestamp = next(
        (
            record.get("timestamp")
            for record in reversed(records)
            if isinstance(record.get("timestamp"), str)
        ),
        None,
    )
    last_record_sha256 = next(
        (
            record.get("record_sha256")
            for record in reversed(records)
            if isinstance(record.get("record_sha256"), str)
        ),
        None,
    )
    identity = {
        "record_count": len(records),
        "last_record_sha256": last_record_sha256,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
    }
    return {
        **identity,
        "snapshot_sha256": hashlib.sha256(
            consumer_surface.canonical_json_bytes(identity)
        ).hexdigest(),
    }


def _parse_json_result(result: dict[str, Any]) -> dict[str, Any]:
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or not stdout.strip():
        return result
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        if result.get("returncode") != 0:
            return result
        return {**result, "json_valid": False, "json_error": str(exc)}
    return {**result, "json_valid": True, "data": payload, "stdout": ""}


@mcp.tool(name="grabowski_runtime_health", annotations=LOCAL_READ)
def grabowski_runtime_health() -> dict[str, Any]:
    """Return minimal Grabowski deployment, audit and kill-switch health."""
    deployment = base._deployment_metadata()
    audit = base._verify_audit_log(base.AUDIT_LOG)
    integrity = {
        key: bool(deployment.get(key))
        for key in DEPLOYMENT_INTEGRITY_FIELDS
    }
    audit_writable = bool(audit.get("audit_writable"))
    return {
        "service": runtime_extensions.LOGICAL_RUNTIME_SERVICE,
        "service_model": runtime_extensions.runtime_service_model(deployment),
        "healthy": (
            deployment.get("completion_status") == "complete"
            and all(integrity.values())
            and bool(audit.get("valid"))
            and audit_writable
            and not bool(base._kill_switch_state().get("engaged"))
        ),
        "deployment_complete": deployment.get("completion_status") == "complete",
        "deployment_integrity_valid": all(integrity.values()),
        "audit_valid": bool(audit.get("valid")),
        "audit_writable": audit_writable,
        "audit_state": audit.get("audit_state"),
        "audit_active_bytes": audit.get("active_bytes"),
        "audit_max_bytes": audit.get("max_bytes"),
        "audit_remaining_bytes": audit.get("remaining_bytes"),
        "audit_reserve_bytes": audit.get("reserve_bytes"),
        "audit_rotation_required": audit.get("rotation_required"),
        "audit_archived_segment_count": audit.get("archived_segment_count"),
        "audit_total_records": audit.get("total_records"),
        "kill_switch_engaged": bool(base._kill_switch_state().get("engaged")),
        "release_id": deployment.get("release_id"),
        "repo_head": deployment.get("repo_head"),
    }


@mcp.tool(name="grabowski_audit_projection", annotations=LOCAL_READ)
def grabowski_audit_projection(
    view: str = "minimal",
    top_limit: AuditProjectionTopLimit = 10,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Project verified audit-chain records into bounded operational trends."""
    selected_view = consumer_surface.normalize_view(view)
    if isinstance(top_limit, bool) or not 1 <= top_limit <= MAX_AUDIT_PROJECTION_TOP:
        raise ValueError(f"top_limit must be between 1 and {MAX_AUDIT_PROJECTION_TOP}")
    before = base._verify_audit_log(base.AUDIT_LOG)
    if not before.get("valid"):
        raise RuntimeError(
            f"Audit log verification failed: {before.get('error') or 'unknown'}"
        )
    records = base._audit_records()
    binding = _audit_snapshot_binding(records)
    after = base._verify_audit_log(base.AUDIT_LOG)
    if not after.get("valid"):
        raise RuntimeError(
            f"Audit log verification failed after projection: {after.get('error') or 'unknown'}"
        )

    as_of_unix = int(time.time())
    windows: list[dict[str, Any]] = []
    private_windows: dict[str, dict[str, Any]] = {}
    for label, seconds in AUDIT_PROJECTION_WINDOWS:
        public, private = _audit_window_projection(
            records,
            start_unix=as_of_unix - seconds,
            end_unix=as_of_unix,
            label=label,
            top_limit=top_limit,
            view=selected_view,
        )
        windows.append(public)
        private_windows[label] = private
    all_time, all_time_private = _audit_window_projection(
        records,
        start_unix=None,
        end_unix=as_of_unix,
        label="all_time",
        top_limit=top_limit,
        view=selected_view,
    )
    candidates = _audit_projection_candidates(private_windows["7d"])
    advanced = (
        after.get("last_record_sha256") != binding["last_record_sha256"]
        or after.get("total_records") != binding["record_count"]
    )
    warnings: list[dict[str, Any]] = []
    if advanced:
        warnings.append(
            {
                "code": "audit_advanced_during_projection",
                "snapshot_last_record_sha256": binding["last_record_sha256"],
                "current_last_record_sha256": after.get("last_record_sha256"),
            }
        )
    legacy_records = int(after.get("total_legacy_records") or 0)
    if legacy_records:
        warnings.append(
            {"code": "legacy_audit_records_present", "count": legacy_records}
        )
    invalid_timestamps = int(
        all_time_private["timestamp_quality"]["invalid_or_missing"]
    )
    if invalid_timestamps:
        warnings.append(
            {
                "code": "audit_records_without_valid_timestamp",
                "count": invalid_timestamps,
            }
        )
    future_dated = int(all_time_private["timestamp_quality"]["future_dated"])
    if future_dated:
        warnings.append({"code": "future_dated_audit_records", "count": future_dated})

    payload: dict[str, Any] = {
        "schema_version": 1,
        "projection_kind": "audit_projection.v1",
        "authority": "derived_read_only_projection",
        "view": selected_view,
        "as_of_unix": as_of_unix,
        "source_binding": {
            **binding,
            "snapshot_chain_valid": True,
            "post_read_chain_valid": True,
            "post_read_total_records": after.get("total_records"),
            "post_read_last_record_sha256": after.get("last_record_sha256"),
            "archived_segment_count": after.get("archived_segment_count"),
            "audit_writable": after.get("audit_writable"),
            "advanced_during_projection": advanced,
        },
        "windows": windows,
        "all_time": all_time,
        "candidate_patterns": candidates,
        "warnings": warnings,
        "recommended_next_action": (
            "inspect ambiguous execution outcomes before retries"
            if any(
                item.get("pattern") == "ambiguous_execution_outcome"
                for item in candidates
            )
            else (
                "inspect the highest repeated proposal-only pattern"
                if candidates
                else "none"
            )
        ),
        "does_not_establish": [
            "causality",
            "task_success_rate",
            "operator_productivity",
            "current_lease_truth",
            "current_friction_resolution",
            "safe_mutation_retry",
            "bureau_task_readiness",
            "automatic_task_creation_authority",
            "live_routing_promotion",
        ],
    }
    payload["findings_sha256"] = _audit_findings_sha256(
        windows, all_time, candidates, warnings
    )
    payload["projection_sha256"] = hashlib.sha256(
        consumer_surface.canonical_json_bytes(payload)
    ).hexdigest()
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "projection_kind",
            "authority",
            "view",
            "source_binding",
            "warnings",
            "recommended_next_action",
            "does_not_establish",
        ),
    )


@mcp.tool(name="grabowski_deployment_identity", annotations=LOCAL_READ)
def grabowski_deployment_identity() -> dict[str, Any]:
    """Return bounded runtime identity and integrity flags without local paths."""
    deployment = base._deployment_metadata()
    return {
        "identity": {
            key: deployment.get(key)
            for key in DEPLOYMENT_IDENTITY_FIELDS
        },
        "integrity": {
            key: bool(deployment.get(key))
            for key in DEPLOYMENT_INTEGRITY_FIELDS
        },
        "source_identity_by_module": deployment.get("source_identity_by_module", {}),
        "source_snapshot_identity_by_module": deployment.get(
            "source_snapshot_identity_by_module", {}
        ),
    }


@mcp.tool(name="grabowski_contract_drift", annotations=LOCAL_READ)
def grabowski_contract_drift() -> dict[str, Any]:
    """Return bounded runtime-contract and capability-catalog drift."""
    snapshot = runtime_extensions._runtime_contract_snapshot()
    expected = snapshot["contract"].get("expected_tools", [])
    if not isinstance(expected, list):
        expected = []
    classification = capabilities.classify_contract(expected)
    normalized = {
        key: sorted(str(value) for value in values)[:200]
        for key, values in classification.items()
    }
    return {
        "contract_source": snapshot["source"],
        "expected_tool_count": len(expected),
        "catalog_matches_contract": not any(normalized.values()),
        "drift": normalized,
        "connector_snapshot_observable": False,
    }


@mcp.tool(name="grabowski_checkout_summary", annotations=LOCAL_READ)
def grabowski_checkout_summary(
    view: str = "minimal",
    limit: int = 20,
    cursor: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Return a paginated consumer-shaped summary of Grabowski worktrees."""
    selected_view = consumer_surface.normalize_view(view)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_WORKTREES:
        raise ValueError(f"limit must be between 1 and {MAX_WORKTREES}")
    deployment = base._deployment_metadata()
    runtime_head = deployment.get("repo_head")
    context = runtime_extensions._worktree_context(
        runtime_head if isinstance(runtime_head, str) else None
    )
    raw_worktrees = context.get("worktrees", [])
    if not isinstance(raw_worktrees, list):
        raw_worktrees = []
    worktrees = sorted(
        (item for item in raw_worktrees if isinstance(item, dict)),
        key=lambda item: str(item.get("path", "")),
    )
    snapshot_digest = hashlib.sha256(
        consumer_surface.canonical_json_bytes([
            {
                "path": item.get("path"),
                "head": item.get("head"),
                "branch": item.get("branch"),
                "prunable": bool(item.get("prunable")),
            }
            for item in worktrees
        ])
    ).hexdigest()
    scope = f"checkout-summary:{selected_view}:{snapshot_digest}"
    position = consumer_surface.decode_cursor(
        cursor,
        scope,
        snapshot_scope=f"checkout-summary:{selected_view}",
    )
    offset = 0 if position is None else position.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("cursor offset is invalid")
    page = worktrees[offset : offset + limit]
    item_fields = (
        "path",
        "head",
        "branch",
        "matches_runtime",
        "prunable",
    )
    if selected_view in {"standard", "evidence"}:
        item_fields = (
            "path",
            "head",
            "branch",
            "detached",
            "bare",
            "prunable",
            "matches_runtime",
        )
    selected = [
        {key: item.get(key) for key in item_fields if key in item}
        for item in page
    ]
    next_offset = offset + len(page)
    next_cursor = (
        consumer_surface.encode_cursor(scope, {"offset": next_offset})
        if next_offset < len(worktrees)
        else None
    )
    warnings: list[dict[str, Any]] = []
    if not bool(context.get("canonical_matches_runtime")):
        warnings.append({"code": "canonical_runtime_head_mismatch"})
    prunable_count = sum(bool(item.get("prunable")) for item in worktrees)
    if prunable_count:
        warnings.append({"code": "prunable_worktrees", "count": prunable_count})
    payload: dict[str, Any] = {
        "schema_version": 2,
        "view": selected_view,
        "repository": context.get("repository"),
        "exists": bool(context.get("exists")),
        "canonical_checkout": context.get("canonical_checkout"),
        "canonical_matches_runtime": bool(context.get("canonical_matches_runtime")),
        "runtime_matching_worktree_count": len(
            context.get("runtime_matching_worktrees", [])
        ),
        "worktree_count": len(worktrees),
        "worktrees": selected,
        "pagination": {
            "limit": limit,
            "returned": len(selected),
            "offset": offset,
            "has_more": next_cursor is not None,
            "next_cursor": next_cursor,
            "snapshot_sha256": snapshot_digest,
        },
        "warnings": warnings,
        "recommended_next_action": (
            "inspect prunable or mismatched worktrees" if warnings else "none"
        ),
        "does_not_establish": [
            "worktree_safe_to_delete",
            "branch_merged",
            "process_or_lease_absence",
        ],
    }
    if selected_view == "evidence":
        payload["command_returncode"] = context.get("command_returncode")
        payload["runtime_matching_worktrees"] = context.get(
            "runtime_matching_worktrees", []
        )
    return consumer_surface.project_fields(
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


@mcp.tool(name="grabowski_git_status", annotations=LOCAL_READ)
def grabowski_git_status(repo: RepositoryPath) -> dict[str, Any]:
    """Read fixed short Git status for one allowed repository."""
    repository = _resolve_repository(repo)
    return _run_read(
        _git_command(repository, "status", "--short", "--branch", "--untracked-files=normal"),
        cwd=repository,
    )


@mcp.tool(name="grabowski_git_diff", annotations=LOCAL_READ)
def grabowski_git_diff(
    repo: RepositoryPath,
    staged: bool = False,
    max_output_bytes: OutputBytes = DEFAULT_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Read a bounded unstaged or staged Git diff without external helpers."""
    repository = _resolve_repository(repo)
    arguments = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    ]
    if staged:
        arguments.append("--cached")
    arguments.append("--")
    return _run_read(
        _git_command(repository, *arguments),
        cwd=repository,
        max_output_bytes=max_output_bytes,
    )


@mcp.tool(name="grabowski_git_log", annotations=LOCAL_READ)
def grabowski_git_log(
    repo: RepositoryPath,
    max_count: GitCommitCount = 20,
) -> dict[str, Any]:
    """Read a bounded fixed-format Git commit log."""
    if isinstance(max_count, bool) or max_count < 1 or max_count > MAX_GIT_COMMITS:
        raise ValueError(f"max_count must be between 1 and {MAX_GIT_COMMITS}")
    repository = _resolve_repository(repo)
    return _run_read(
        _git_command(
            repository,
            "log",
            f"--max-count={max_count}",
            "--date=iso-strict",
            "--decorate=short",
            "--no-show-signature",
            "--format=%H%x09%ad%x09%D%x09%s",
        ),
        cwd=repository,
    )


@mcp.tool(name="grabowski_git_show", annotations=LOCAL_READ)
def grabowski_git_show(
    repo: RepositoryPath,
    revision: RevisionInput = "HEAD",
    max_output_bytes: OutputBytes = DEFAULT_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Read one bounded Git revision without external diff or textconv helpers."""
    repository = _resolve_repository(repo)
    selected = _resolve_revision(repository, revision)
    return _run_read(
        _git_command(
            repository,
            "show",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--no-show-signature",
            "--date=iso-strict",
            "--format=fuller",
            selected,
            "--",
        ),
        cwd=repository,
        max_output_bytes=max_output_bytes,
    )


@mcp.tool(name="grabowski_github_pr_view", annotations=REMOTE_READ)
def grabowski_github_pr_view(
    repo: RepositoryPath,
    pr: PullRequestNumber,
) -> dict[str, Any]:
    """Read bounded GitHub pull-request metadata without body or comments."""
    operator._require_operator_capability("github_cli")
    repository = _resolve_repository(repo)
    result = _run_read(
        [
            "gh",
            "pr",
            "view",
            str(_validate_pr(pr)),
            "--json",
            ",".join(GITHUB_PR_FIELDS),
        ],
        cwd=repository,
        timeout_seconds=60,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    return _parse_json_result(result)


@mcp.tool(name="grabowski_github_checks", annotations=REMOTE_READ)
def grabowski_github_checks(
    repo: RepositoryPath,
    pr: PullRequestNumber,
) -> dict[str, Any]:
    """Read bounded GitHub pull-request check results."""
    operator._require_operator_capability("github_cli")
    repository = _resolve_repository(repo)
    result = _run_read(
        [
            "gh",
            "pr",
            "checks",
            str(_validate_pr(pr)),
            "--json",
            ",".join(GITHUB_CHECK_FIELDS),
        ],
        cwd=repository,
        timeout_seconds=60,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    return _parse_json_result(result)


@mcp.tool(name="grabowski_service_status", annotations=LOCAL_READ)
def grabowski_service_status(unit: SystemdUnit) -> dict[str, Any]:
    """Read a fixed property set for one user-level systemd unit."""
    operator._require_operator_capability("user_service_control")
    name = operator._validate_unit(unit)
    result = _run_read(
        [
            "systemctl",
            "--user",
            "show",
            name,
            "--no-pager",
            *[f"--property={field}" for field in SERVICE_PROPERTIES],
        ],
        cwd=operator.HOME,
        timeout_seconds=30,
    )
    return {
        **result,
        "properties": operator._parse_show(result["stdout"]),
        "stdout": "",
    }


@mcp.tool(name="grabowski_service_logs", annotations=LOCAL_READ)
def grabowski_service_logs(
    unit: SystemdUnit,
    max_lines: LogLineCount = 200,
) -> dict[str, Any]:
    """Read bounded recent journal lines for one user-level systemd unit."""
    operator._require_operator_capability("user_service_control")
    name = operator._validate_unit(unit)
    if isinstance(max_lines, bool) or max_lines < 1 or max_lines > MAX_LOG_LINES:
        raise ValueError(f"max_lines must be between 1 and {MAX_LOG_LINES}")
    return _run_read(
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
        cwd=operator.HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )

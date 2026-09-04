from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import http.client
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Annotated, Any
from urllib.parse import quote

from mcp.types import ToolAnnotations
from pydantic import Field

import grabowski_capabilities as capabilities
import grabowski_checkouts as checkouts
import grabowski_mcp as base
import grabowski_audit_signal as audit_signal
import grabowski_consumer_surface as consumer_surface
import grabowski_git_preimage
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
MAX_GITHUB_RESPONSE_BYTES = 1_000_000
MAX_TAILSCALE_RESPONSE_BYTES = 512_000
MAX_TAILSCALE_PEERS = 256
MAX_PROJECTED_TEXT = 500
MAX_PROJECTED_URL = 1_000
MAX_WORKTREES = 100
MAX_REVISION_LENGTH = 200
MAX_AUDIT_PROJECTION_TOP = 25
AUDIT_FUTURE_TOLERANCE_SECONDS = 300
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
GITHUB_OWNER_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
)
GITHUB_REPOSITORY_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
GITHUB_REST_PATH_RE = re.compile(
    r"/repos/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/"
    r"(?!\.{1,2}/)[A-Za-z0-9._-]{1,100}/"
    r"(?:pulls/[1-9][0-9]*|commits/[0-9a-f]{40,64}/(?:check-runs|status)\?per_page=100)\Z"
)
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
GitHubRepository = Annotated[
    str,
    Field(
        min_length=3,
        max_length=4096,
        description="Absolute local Git worktree path or canonical GitHub owner/repository identifier.",
    ),
]
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


def _canonical_github_repository(raw: str) -> str:
    parts = raw.split("/")
    valid_identifier = (
        len(parts) == 2
        and GITHUB_OWNER_RE.fullmatch(parts[0]) is not None
        and GITHUB_REPOSITORY_NAME_RE.fullmatch(parts[1]) is not None
        and parts[1] not in {".", ".."}
    )
    if not valid_identifier:
        raise ValueError("repo must be a canonical GitHub owner/repository identifier")
    return f"{parts[0]}/{parts[1]}"


def _github_rest_path(
    repository: str, *segments: str, query: str | None = None
) -> str:
    owner, name = _canonical_github_repository(repository).split("/", 1)
    if not segments or any(
        not segment or "/" in segment or segment in {".", ".."}
        for segment in segments
    ):
        raise ValueError("Invalid GitHub REST path segment")
    encoded = [
        quote(owner, safe=""),
        quote(name, safe=""),
        *(quote(segment, safe="") for segment in segments),
    ]
    if query not in {None, "per_page=100"}:
        raise ValueError("Invalid GitHub REST query")
    path = "/repos/" + "/".join(encoded)
    return f"{path}?{query}" if query is not None else path


def _resolve_github_repository(raw: str) -> tuple[Path, list[str]]:
    candidate = Path(raw)
    if candidate.is_absolute():
        return _resolve_repository(raw), []
    try:
        repository = _canonical_github_repository(raw)
    except ValueError as exc:
        raise ValueError(
            "repo must be an absolute local Git worktree path or a canonical "
            "GitHub owner/repository identifier"
        ) from exc
    return operator.HOME, ["--repo", repository]


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


def _prepare_audit_records(
    records: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], int | None]]:
    return [
        (record, _audit_timestamp_unix(record.get("timestamp")))
        for record in records
    ]


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


def _audit_identity_sha256(value: dict[str, Any]) -> str:
    raw = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _audit_digest(value: Any, *, length: int = 64) -> str | None:
    if (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    ):
        return value
    return None


def _audit_contract_schema_identity(
    value: Any,
    *,
    command: str,
    mode: str,
    direction: str,
    schema_version: int,
) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    expected_id = (
        f"grabowski_bureau_intake.{command}.{mode}.{direction}.v{schema_version}"
    )
    material = {
        "schema_version": schema_version,
        "surface": "grabowski_bureau_intake",
        "command": command,
        "mode": mode,
        "direction": direction,
    }
    expected_sha = _audit_identity_sha256(material)
    if value.get("id") != expected_id or value.get("sha256") != expected_sha:
        return None
    return {"id": expected_id, "sha256": expected_sha}


def _audit_result_payload_schema_identity(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    schema_version = value.get("schema_version")
    if (
        not isinstance(kind, str)
        or AUDIT_PROJECTION_LABEL_RE.fullmatch(kind) is None
        or not (
            schema_version is None
            or (
                isinstance(schema_version, int)
                and not isinstance(schema_version, bool)
                and 0 < schema_version <= 2_147_483_647
            )
        )
    ):
        return None
    material = {"kind": kind, "schema_version": schema_version}
    expected_sha = _audit_identity_sha256(material)
    if value.get("sha256") != expected_sha:
        return None
    return {**material, "sha256": expected_sha}


def _audit_runtime_contract_identity(value: Any) -> dict[str, Any] | None:
    if value == {"status": "unknown"}:
        return {"status": "unknown"}
    if not isinstance(value, dict) or value.get("status") != "observed":
        return None
    source_commit = _audit_digest(value.get("source_commit"), length=40)
    registry_tree = _audit_digest(value.get("registry_tree_sha256"))
    launcher = _audit_digest(value.get("launcher_sha256"))
    manifest = _audit_digest(value.get("manifest_sha256"))
    inventory = _audit_digest(value.get("inventory_sha256"))
    if None in {source_commit, registry_tree, launcher, manifest, inventory}:
        return None
    material = {
        "status": "observed",
        "source_commit": source_commit,
        "registry_tree_sha256": registry_tree,
        "launcher_sha256": launcher,
        "manifest_sha256": manifest,
        "inventory_sha256": inventory,
    }
    expected_sha = _audit_identity_sha256(material)
    if value.get("identity_sha256") != expected_sha:
        return None
    return {**material, "identity_sha256": expected_sha}


def _audit_bureau_failure_identity(
    record: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    identity = record.get("bureau_contract_identity")
    if not isinstance(identity, dict):
        return "unknown", None
    if (
        identity.get("schema_version") != 1
        or identity.get("kind") != "grabowski_bureau_contract_identity"
        or identity.get("completeness") not in {"complete", "partial"}
    ):
        return "unknown", None
    adapter = identity.get("adapter")
    if not isinstance(adapter, dict):
        return "unknown", None
    surface = adapter.get("surface")
    command = adapter.get("command")
    mode = adapter.get("mode")
    adapter_schema = adapter.get("schema_version")
    if (
        surface != "grabowski_bureau_intake"
        or adapter_schema != 1
        or not isinstance(command, str)
        or AUDIT_PROJECTION_LABEL_RE.fullmatch(command) is None
        or mode not in {"call", "preview", "apply"}
    ):
        return "unknown", None
    runtime = _audit_runtime_contract_identity(identity.get("runtime"))
    if runtime is None:
        return "unknown", None
    request_schema = _audit_contract_schema_identity(
        identity.get("request_schema"),
        command=command,
        mode=mode,
        direction="request",
        schema_version=adapter_schema,
    )
    result_schema = _audit_contract_schema_identity(
        identity.get("result_schema"),
        command=command,
        mode=mode,
        direction="result",
        schema_version=adapter_schema,
    )
    if request_schema is None or result_schema is None:
        return "unknown", None
    completeness = identity["completeness"]
    expected_completeness = (
        "complete"
        if command != "unknown" and runtime.get("status") == "observed"
        else "partial"
    )
    if completeness != expected_completeness:
        return "unknown", None
    material = {
        "schema_version": 1,
        "kind": "grabowski_bureau_contract_identity",
        "completeness": completeness,
        "adapter": {
            "surface": surface,
            "schema_version": adapter_schema,
            "command": command,
            "mode": mode,
        },
        "runtime": runtime,
        "request_schema": request_schema,
        "result_schema": result_schema,
    }
    contract_sha = _audit_identity_sha256(material)
    if identity.get("identity_sha256") != contract_sha:
        return "unknown", None
    caller_surface = record.get("bureau_caller_surface")
    operation = record.get("operation")
    if (
        not isinstance(caller_surface, str)
        or caller_surface != operation
        or AUDIT_PROJECTION_LABEL_RE.fullmatch(caller_surface) is None
    ):
        return "unknown", None
    result_payload_schema = _audit_result_payload_schema_identity(
        record.get("bureau_result_schema_identity")
    )
    if result_payload_schema is None:
        return "unknown", None
    failure_material = {
        "schema_version": 1,
        "caller_surface": caller_surface,
        "contract_identity_sha256": contract_sha,
        "result_schema_identity_sha256": result_payload_schema["sha256"],
    }
    failure_sha = _audit_identity_sha256(failure_material)
    if (
        record.get("bureau_failure_identity_schema_version") != 1
        or record.get("bureau_failure_identity_sha256") != failure_sha
    ):
        return "unknown", None
    safe = {
        "identity_sha256": failure_sha,
        "contract_identity_sha256": contract_sha,
        "caller_surface": caller_surface,
        "completeness": completeness,
        "adapter": material["adapter"],
        "runtime": runtime,
        "request_schema": request_schema,
        "result_schema": result_schema,
        "result_payload_schema": result_payload_schema,
    }
    return completeness, safe


_AUDIT_BUREAU_FAILURE_REASON_EXACT_CLASSES = {
    "candidate request contains unknown fields": "candidate request contains unknown fields",
    "candidate request schema_version must be 1": "candidate request schema unsupported",
    "live register repo must be a repo.* resource": "live register repo resource invalid",
    "candidate task cannot change across supersession": "candidate task supersession mismatch",
    "candidate repo cannot change across supersession": "candidate repo supersession mismatch",
    "idempotency_key already identifies different candidate input": "idempotency conflict",
    "idempotency_key contains unsupported characters": "idempotency key invalid",
    "source_sha256 must be a lowercase SHA-256 digest": "source digest invalid",
    "candidate assessment found an exact duplicate": "candidate exact duplicate",
    "TaskSpec revision candidate must explicitly bind the exact existing task_id": "task revision identity mismatch",
    "nonterminal task proposals must use exact Bureau resources or an explicit reviewed repository-wide exception": "bureau task scope too broad",
}


def _audit_bureau_failure_reason_class(reason: Any, code: Any) -> str | None:
    if not isinstance(reason, str) or not reason:
        return None
    exact = _AUDIT_BUREAU_FAILURE_REASON_EXACT_CLASSES.get(reason)
    if exact is not None:
        return exact
    if reason.startswith("unknown live register task "):
        return "live register task unknown"
    if (
        reason.startswith("publishing task ")
        and reason.endswith(" is not in the authoritative StateStore")
    ):
        return "publishing task unknown"
    if reason.startswith("unknown initiative "):
        return "initiative unknown"
    if reason.startswith(
        "task JSON does not have an executable typed acceptance contract:"
    ):
        return "task acceptance contract invalid"
    if isinstance(code, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", code):
        return f"bureau code: {code}"
    return "bureau failure other"


def _audit_bureau_identity_public_group(
    group: dict[str, Any],
    *,
    reason_limit: int,
) -> dict[str, Any]:
    reason_counts = Counter(group.get("failure_reason_counts", {}))
    attributed = sum(reason_counts.values())
    unknown = int(group.get("failure_reason_unknown_count", 0))
    total = attributed + unknown
    public = {
        key: value
        for key, value in group.items()
        if key not in {"failure_reason_counts", "failure_reason_unknown_count"}
    }
    public.update(
        {
            "failure_reason_class_count": len(reason_counts),
            "failure_reason_attributed_count": attributed,
            "failure_reason_unknown_count": unknown,
            "failure_reason_coverage": round(attributed / total, 6) if total else 0.0,
            "top_failure_reason_classes": [
                {"reason": item["key"], "count": item["count"]}
                for item in _audit_top(reason_counts, reason_limit)
            ],
        }
    )
    return public


def _audit_bureau_identity_summary(
    quality: Counter[str],
    groups: dict[str, dict[str, Any]],
    *,
    top_limit: int,
    include_groups: bool,
) -> dict[str, Any]:
    complete = int(quality.get("complete", 0))
    partial = int(quality.get("partial", 0))
    unknown = int(quality.get("unknown", 0))
    total = complete + partial + unknown
    exact_groups = [
        group for group in groups.values() if group.get("completeness") == "complete"
    ]
    payload: dict[str, Any] = {
        "failure_record_count": total,
        "complete_identity_count": complete,
        "partial_identity_count": partial,
        "unknown_identity_count": unknown,
        "exact_identity_coverage": round(complete / total, 6) if total else 0.0,
        "identity_group_count": len(groups),
        "exact_identity_group_count": len(exact_groups),
    }
    if include_groups:
        selected = sorted(
            exact_groups,
            key=lambda item: (-int(item["count"]), str(item["identity_sha256"])),
        )[:top_limit]
        payload["top_exact_identity_groups"] = [
            _audit_bureau_identity_public_group(group, reason_limit=min(top_limit, 5))
            for group in selected
        ]
    return payload


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
    if record.get("recovery_required") is True:
        reasons.add("recovery_required")
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
    records: list[tuple[dict[str, Any], int | None]],
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
    bureau_identity_quality: Counter[str] = Counter()
    bureau_identity_groups: dict[str, dict[str, Any]] = {}
    mutation_evidence: Counter[str] = Counter()
    timestamp_quality: Counter[str] = Counter()
    failure_signal_count = 0
    reclaimed_resource_count = 0
    resource_reclamation_event_count = 0
    reclamation_self_resource_count = 0
    reclamation_foreign_resource_count = 0
    reclamation_unattributed_resource_count = 0
    selected_count = 0

    for record, timestamp_unix in records:
        if timestamp_unix is None:
            timestamp_quality["invalid_or_missing"] += 1
            if start_unix is not None:
                continue
        elif timestamp_unix > end_unix + AUDIT_FUTURE_TOLERANCE_SECONDS:
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

        if "bureau_failure_status" in reasons:
            bureau_code = record.get("bureau_code")
            if isinstance(bureau_code, str) and bureau_code:
                bureau_code_counts[
                    _audit_label(bureau_code, fallback="unknown")
                ] += 1
            retryable = record.get("bureau_retryable")
            if retryable is True:
                bureau_activity["failure_retryable_count"] += 1
            elif retryable is False:
                bureau_activity["failure_nonretryable_count"] += 1
            else:
                bureau_activity["failure_retryability_unknown_count"] += 1

            identity_quality, identity = _audit_bureau_failure_identity(record)
            bureau_identity_quality[identity_quality] += 1
            if identity is not None:
                identity_key = identity["identity_sha256"]
                group = bureau_identity_groups.get(identity_key)
                if group is None:
                    group = {
                        **identity,
                        "count": 0,
                        "failure_code_counts": {},
                        "failure_reason_counts": {},
                        "failure_reason_unknown_count": 0,
                        "failure_retryable_count": 0,
                        "failure_nonretryable_count": 0,
                        "failure_retryability_unknown_count": 0,
                    }
                    bureau_identity_groups[identity_key] = group
                group["count"] += 1
                code_key = _audit_label(record.get("bureau_code"), fallback="unknown")
                code_counts = group["failure_code_counts"]
                code_counts[code_key] = int(code_counts.get(code_key, 0)) + 1
                failure_reason_class = _audit_bureau_failure_reason_class(
                    record.get("bureau_failure_reason"), record.get("bureau_code")
                )
                if failure_reason_class is not None:
                    reason_counts = group["failure_reason_counts"]
                    reason_counts[failure_reason_class] = (
                        int(reason_counts.get(failure_reason_class, 0)) + 1
                    )
                else:
                    group["failure_reason_unknown_count"] += 1
                if retryable is True:
                    group["failure_retryable_count"] += 1
                elif retryable is False:
                    group["failure_nonretryable_count"] += 1
                else:
                    group["failure_retryability_unknown_count"] += 1

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
            attributed = 0
            seen_indexes: set[int] = set()
            owner_id = record.get("owner_id")
            evidence = record.get("reclamation_evidence")
            if isinstance(owner_id, str) and owner_id and isinstance(evidence, list):
                for item in evidence:
                    if not isinstance(item, dict):
                        continue
                    index = item.get("resource_index")
                    previous_owner_id = item.get("previous_owner_id")
                    if (
                        not isinstance(index, int)
                        or isinstance(index, bool)
                        or index < 0
                        or not isinstance(resource_keys, list)
                        or index >= len(resource_keys)
                        or index in seen_indexes
                        or not isinstance(previous_owner_id, str)
                        or not previous_owner_id
                        or attributed >= reclaimed
                    ):
                        continue
                    seen_indexes.add(index)
                    attributed += 1
                    if previous_owner_id == owner_id:
                        reclamation_self_resource_count += 1
                    else:
                        reclamation_foreign_resource_count += 1
            reclamation_unattributed_resource_count += reclaimed - attributed

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
            "reclamation_self_resource_count": reclamation_self_resource_count,
            "reclamation_foreign_resource_count": reclamation_foreign_resource_count,
            "reclamation_unattributed_resource_count": reclamation_unattributed_resource_count,
        },
        "bureau_activity": dict(sorted(bureau_activity.items())),
        "bureau_failure_identity": _audit_bureau_identity_summary(
            bureau_identity_quality,
            bureau_identity_groups,
            top_limit=top_limit,
            include_groups=view in {"standard", "evidence"},
        ),
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
        "label": label,
        "record_count": selected_count,
        "operation_counts": operation_counts,
        "failure_reason_counts": failure_reason_counts,
        "bureau_code_counts": bureau_code_counts,
        "resource_type_counts": resource_type_counts,
        "friction_kind_counts": friction_kind_counts,
        "friction_surface_counts": friction_surface_counts,
        "task_activity": task_activity,
        "resource_activity": resource_activity,
        "bureau_activity": bureau_activity,
        "bureau_identity_quality": bureau_identity_quality,
        "bureau_identity_groups": bureau_identity_groups,
        "mutation_evidence": mutation_evidence,
        "resource_reclamation_event_count": resource_reclamation_event_count,
        "reclaimed_resource_count": reclaimed_resource_count,
        "reclamation_self_resource_count": reclamation_self_resource_count,
        "reclamation_foreign_resource_count": reclamation_foreign_resource_count,
        "reclamation_unattributed_resource_count": reclamation_unattributed_resource_count,
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
    repeated_codes = sorted(
        (
            (code, count)
            for code, count in bureau_codes.items()
            if count >= 3
        ),
        key=lambda item: (-item[1], item[0]),
    )
    if repeated_codes:
        retryable_count = int(seven_day["bureau_activity"].get("failure_retryable_count", 0))
        nonretryable_count = int(
            seven_day["bureau_activity"].get("failure_nonretryable_count", 0)
        )
        retryability_unknown_count = int(
            seven_day["bureau_activity"].get("failure_retryability_unknown_count", 0)
        )
        retryability_total = retryable_count + nonretryable_count + retryability_unknown_count
        retryability_attributed = retryable_count + nonretryable_count
        identity_summary = _audit_bureau_identity_summary(
            seven_day["bureau_identity_quality"],
            seven_day["bureau_identity_groups"],
            top_limit=5,
            include_groups=True,
        )
        candidates.append(
            {
                "pattern": "repeated_bureau_contract_failures",
                "count_7d": sum(count for _code, count in repeated_codes),
                "top_codes": [
                    {"code": code, "count": count} for code, count in repeated_codes[:5]
                ],
                "failure_retryable_count_7d": retryable_count,
                "failure_nonretryable_count_7d": nonretryable_count,
                "failure_retryability_unknown_count_7d": retryability_unknown_count,
                "failure_retryability_coverage": (
                    round(retryability_attributed / retryability_total, 6)
                    if retryability_total
                    else 0.0
                ),
                "failure_identity_complete_count_7d": identity_summary[
                    "complete_identity_count"
                ],
                "failure_identity_partial_count_7d": identity_summary[
                    "partial_identity_count"
                ],
                "failure_identity_unknown_count_7d": identity_summary[
                    "unknown_identity_count"
                ],
                "failure_identity_coverage": identity_summary["exact_identity_coverage"],
                "failure_identity_group_count_7d": identity_summary[
                    "exact_identity_group_count"
                ],
                "top_identity_groups": identity_summary["top_exact_identity_groups"],
                "recommendation": "Inspect only complete caller/runtime/schema identity groups as homogeneous candidates; keep partial or unknown historical records separate and never infer retryability where attribution is absent.",
                "authority": "proposal_only",
                "does_not_establish": [
                    "shared_root_cause",
                    "bureau_task_readiness",
                    "partial_identity_equivalence",
                    "unknown_identity_equivalence",
                ],
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
    self_reclaimed = int(seven_day["reclamation_self_resource_count"])
    foreign_reclaimed = int(seven_day["reclamation_foreign_resource_count"])
    unattributed_reclaimed = int(seven_day["reclamation_unattributed_resource_count"])
    attributed_reclaimed = self_reclaimed + foreign_reclaimed
    if reclamation_events >= 3:
        if unattributed_reclaimed:
            recommendation = (
                "Separate provenance-attributed same-owner and foreign-owner reclaims; "
                "do not infer lease-policy defects from unattributed aggregate history."
            )
        elif foreign_reclaimed:
            recommendation = (
                "Inspect foreign-owner reclaims against expiry, terminal and release timing; "
                "treat same-owner reacquisition as separate resume behavior before changing "
                "lease policy."
            )
        else:
            recommendation = (
                "Attributed reclamation is same-owner only; inspect renewal and resume "
                "semantics before changing lease policy."
            )
        candidates.append(
            {
                "pattern": "repeated_resource_reclamation",
                "event_count_7d": reclamation_events,
                "reclaimed_resource_count_7d": reclaimed_resources,
                "same_owner_reclaimed_resource_count_7d": self_reclaimed,
                "foreign_owner_reclaimed_resource_count_7d": foreign_reclaimed,
                "unattributed_reclaimed_resource_count_7d": unattributed_reclaimed,
                "reclamation_attribution_coverage": (
                    round(attributed_reclaimed / reclaimed_resources, 6)
                    if reclaimed_resources
                    else 0.0
                ),
                "recommendation": recommendation,
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
    signal_projection: dict[str, Any],
) -> str:
    def semantic_window(value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: dict(sorted(item.items())) if isinstance(item, Counter) else item
            for key, item in sorted(value.items())
        }

    payload = {
        "windows": [semantic_window(item) for item in windows],
        "all_time": semantic_window(all_time),
        "candidate_patterns": candidates,
        "signal_projection": audit_signal.findings_payload(signal_projection),
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


def _github_cli_enabled() -> bool:
    """Return whether the active profile grants the authenticated GitHub CLI lane."""
    try:
        operator._require_operator_capability("github_cli")
    except PermissionError:
        return False
    return True


def _github_rate_limit_projection(response: http.client.HTTPResponse) -> dict[str, Any]:
    def _header_int(name: str) -> int | None:
        raw = response.getheader(name)
        if not isinstance(raw, str) or not raw.isdigit():
            return None
        return int(raw)

    resource = response.getheader("X-RateLimit-Resource")
    return {
        "limit": _header_int("X-RateLimit-Limit"),
        "remaining": _header_int("X-RateLimit-Remaining"),
        "reset_unix": _header_int("X-RateLimit-Reset"),
        "resource": resource[:64] if isinstance(resource, str) else None,
    }


def _github_rest_json(path: str) -> dict[str, Any]:
    """Read one fixed-origin bounded anonymous GitHub REST resource."""
    if GITHUB_REST_PATH_RE.fullmatch(path) is None:
        raise ValueError(
            "GitHub REST path is outside the fixed typed-read allowlist"
        )
    started = time.monotonic()
    connection = http.client.HTTPSConnection("api.github.com", timeout=20)
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "grabowski-typed-read",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response = connection.getresponse()
        raw = response.read(MAX_GITHUB_RESPONSE_BYTES + 1)
        status = response.status
        rate_limit = _github_rate_limit_projection(response)
    except (OSError, http.client.HTTPException) as exc:
        return {
            "transport": "github-rest-anonymous",
            "origin": "https://api.github.com",
            "request_path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
            "returncode": 1,
            "http_status": None,
            "timed_out": isinstance(exc, TimeoutError),
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": "",
            "stderr": str(exc),
            "stdout_truncated": False,
            "stderr_truncated": False,
            "json_valid": False,
        }
    finally:
        connection.close()
    truncated = len(raw) > MAX_GITHUB_RESPONSE_BYTES
    raw = raw[:MAX_GITHUB_RESPONSE_BYTES]
    result = {
        "transport": "github-rest-anonymous",
        "origin": "https://api.github.com",
        "request_path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
        "returncode": 0 if 200 <= status < 300 else 1,
        "http_status": status,
        "timed_out": False,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": "",
        "stderr": "",
        "stdout_truncated": truncated,
        "stderr_truncated": False,
        "rate_limit": rate_limit,
    }
    if truncated:
        return {
            **result,
            "json_valid": False,
            "json_error": "GitHub REST response exceeded bounded read limit",
        }
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {**result, "json_valid": False, "json_error": str(exc)}
    if result["returncode"] != 0:
        return {
            **result,
            "json_valid": True,
            "data": None,
            "error_kind": "github_rest_http_error",
        }
    return {**result, "json_valid": True, "data": payload}


def _bounded_str(value: Any, limit: int = MAX_PROJECTED_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    return value[:limit]


def _github_pr_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("GitHub pull-request response is not an object")
    head = payload.get("head") if isinstance(payload.get("head"), dict) else {}
    base_ref = payload.get("base") if isinstance(payload.get("base"), dict) else {}
    raw_state = payload.get("state")
    if isinstance(payload.get("merged_at"), str) and bool(payload.get("merged_at")):
        state = "MERGED"
    elif isinstance(raw_state, str):
        state = raw_state.upper()
    else:
        state = None
    raw_mergeable = payload.get("mergeable")
    mergeable = (
        "MERGEABLE" if raw_mergeable is True else
        "CONFLICTING" if raw_mergeable is False else
        "UNKNOWN"
    )
    return {
        "number": payload.get("number"),
        "title": _bounded_str(payload.get("title")),
        "state": state,
        "isDraft": payload.get("draft"),
        "mergeable": mergeable,
        "headRefName": _bounded_str(head.get("ref"), 255),
        "baseRefName": _bounded_str(base_ref.get("ref"), 255),
        "url": _bounded_str(payload.get("html_url"), MAX_PROJECTED_URL),
        "reviewDecision": None,
        "updatedAt": _bounded_str(payload.get("updated_at"), 64),
    }


def _github_check_bucket(status: Any, conclusion: Any) -> str:
    if status != "completed":
        return "pending"
    if conclusion in {"success", "neutral"}:
        return "pass"
    if conclusion in {"skipped"}:
        return "skipping"
    if conclusion in {"cancelled"}:
        return "cancel"
    return "fail"


def _github_check_state(status: Any, conclusion: Any) -> str | None:
    if status != "completed":
        return "PENDING"
    if isinstance(conclusion, str):
        return conclusion.upper()
    return None


def _github_check_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("GitHub check-run response is not an object")
    output = payload.get("output") if isinstance(payload.get("output"), dict) else {}
    status = payload.get("status")
    conclusion = payload.get("conclusion")
    return {
        "bucket": _github_check_bucket(status, conclusion),
        "completedAt": _bounded_str(payload.get("completed_at"), 64),
        "description": _bounded_str(output.get("title")),
        "event": None,
        "link": _bounded_str(payload.get("details_url"), MAX_PROJECTED_URL),
        "name": _bounded_str(payload.get("name"), 255),
        "startedAt": _bounded_str(payload.get("started_at"), 64),
        "state": _github_check_state(status, conclusion),
        "workflow": None,
    }


def _github_status_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("GitHub commit-status response is not an object")
    raw_state = payload.get("state")
    state = raw_state.lower() if isinstance(raw_state, str) else None
    bucket = (
        "pass"
        if state == "success"
        else "pending"
        if state == "pending"
        else "fail"
    )
    return {
        "bucket": bucket,
        "completedAt": (
            _bounded_str(payload.get("updated_at"), 64)
            if state != "pending"
            else None
        ),
        "description": _bounded_str(payload.get("description")),
        "event": None,
        "link": _bounded_str(payload.get("target_url"), MAX_PROJECTED_URL),
        "name": _bounded_str(payload.get("context"), 255),
        "startedAt": _bounded_str(payload.get("created_at"), 64),
        "state": state.upper() if isinstance(state, str) else None,
        "workflow": None,
    }


def _github_checks_semantic_returncode(rows: list[dict[str, Any]]) -> int:
    buckets = {row.get("bucket") for row in rows}
    if buckets & {"fail", "cancel"}:
        return 1
    if "pending" in buckets:
        return 8
    return 0


def _tailscale_failure_projection(
    result: dict[str, Any], *, reason: str, json_valid: bool | None
) -> dict[str, Any]:
    """Return only non-content execution metadata for a failed Tailscale read."""
    return {
        "available": False,
        "executable_present": True,
        "status_readable": False,
        "returncode": result.get("returncode"),
        "timed_out": bool(result.get("timed_out")),
        "duration_seconds": result.get("duration_seconds"),
        "stdout_truncated": bool(result.get("stdout_truncated")),
        "stderr_truncated": bool(result.get("stderr_truncated")),
        "json_valid": json_valid,
        "reason": reason,
        "data": None,
    }


def _tailscale_node_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {
        "OS": _bounded_str(payload.get("OS"), 64),
        "Online": (
            payload.get("Online") if isinstance(payload.get("Online"), bool) else None
        ),
        "Active": (
            payload.get("Active") if isinstance(payload.get("Active"), bool) else None
        ),
        "ExitNode": (
            payload.get("ExitNode")
            if isinstance(payload.get("ExitNode"), bool)
            else None
        ),
    }


def _tailscale_status_projection(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Tailscale status response is not an object")
    raw_peers = payload.get("Peer") if isinstance(payload.get("Peer"), dict) else {}
    peer_count = len(raw_peers)
    peers: list[dict[str, Any]] = []
    for index, value in enumerate(raw_peers.values()):
        if index >= MAX_TAILSCALE_PEERS:
            break
        peers.append(_tailscale_node_projection(value))
    health = payload.get("Health") if isinstance(payload.get("Health"), list) else []
    return {
        "Version": _bounded_str(payload.get("Version"), 64),
        "TUN": payload.get("TUN") if isinstance(payload.get("TUN"), bool) else None,
        "BackendState": _bounded_str(payload.get("BackendState"), 64),
        "HaveNodeKey": (
            payload.get("HaveNodeKey")
            if isinstance(payload.get("HaveNodeKey"), bool)
            else None
        ),
        "Self": _tailscale_node_projection(payload.get("Self")),
        "health_issue_count": len(health),
        "Peers": peers,
        "peer_count": peer_count,
        "peers_truncated": peer_count > MAX_TAILSCALE_PEERS,
    }


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
    if (
        isinstance(top_limit, bool)
        or not isinstance(top_limit, int)
        or not 1 <= top_limit <= MAX_AUDIT_PROJECTION_TOP
    ):
        raise ValueError(f"top_limit must be between 1 and {MAX_AUDIT_PROJECTION_TOP}")
    try:
        records, snapshot_status = base._audit_records_snapshot()
    except (OSError, PermissionError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"Audit log verification failed: {exc}") from exc
    binding = _audit_snapshot_binding(records)
    if (
        snapshot_status.get("total_records") != binding["record_count"]
        or snapshot_status.get("last_record_sha256")
        != binding["last_record_sha256"]
    ):
        raise RuntimeError("Audit snapshot binding mismatch")
    prepared_records = _prepare_audit_records(records)
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
            prepared_records,
            start_unix=as_of_unix - seconds,
            end_unix=as_of_unix,
            label=label,
            top_limit=top_limit,
            view=selected_view,
        )
        windows.append(public)
        private_windows[label] = private
    all_time, all_time_private = _audit_window_projection(
        prepared_records,
        start_unix=None,
        end_unix=as_of_unix,
        label="all_time",
        top_limit=top_limit,
        view=selected_view,
    )
    candidates = _audit_projection_candidates(private_windows["7d"])
    signal_projection = audit_signal.build_projection(
        prepared_records,
        as_of_unix=as_of_unix,
        audit_source_binding=binding,
        runtime_status_provider=getattr(base, "grabowski_status", None),
    )
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
    legacy_records = int(snapshot_status.get("total_legacy_records") or 0)
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
            "archived_segment_count": snapshot_status.get(
                "archived_segment_count"
            ),
            "audit_writable": snapshot_status.get("audit_writable"),
            "advanced_during_projection": advanced,
        },
        "windows": windows,
        "all_time": all_time,
        "candidate_patterns": candidates,
        "signal_projection": signal_projection,
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
        [
            private_windows[label]
            for label, _seconds in AUDIT_PROJECTION_WINDOWS
        ],
        all_time_private,
        candidates,
        warnings,
        signal_projection,
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
            "findings_sha256",
            "projection_sha256",
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
        "serving_process": base.serving_process_identity(),
        "source_identity_by_module": deployment.get("source_identity_by_module", {}),
        "source_snapshot_identity_by_module": deployment.get(
            "source_snapshot_identity_by_module", {}
        ),
    }


@mcp.tool(name="grabowski_contract_drift", annotations=LOCAL_READ)
def grabowski_contract_drift() -> dict[str, Any]:
    """Return bounded structural and semantic runtime-contract drift."""
    snapshot = runtime_extensions._runtime_contract_snapshot()
    expected = snapshot["contract"].get("expected_tools", [])
    if not isinstance(expected, list):
        expected = []
    classification = capabilities.classify_contract(expected)
    normalized = {
        key: sorted(str(value) for value in values)[:200]
        for key, values in classification.items()
    }
    structural_ready = not any(normalized.values())
    try:
        import grabowski_coding_agent_router as coding_agent_router

        coding_agent_catalog = coding_agent_router.coding_agent_catalog_health()
    except Exception as exc:  # pragma: no cover - defensive read boundary
        coding_agent_catalog = {
            "ready": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:512],
        }
    semantic_ready = coding_agent_catalog.get("ready") is True
    tool_contract = base._runtime_tool_contract_summary()
    return {
        "contract_source": snapshot["source"],
        "expected_tool_count": len(expected),
        "capability_catalog_matches_contract": structural_ready,
        "semantic_catalog_ready": semantic_ready,
        "catalog_matches_contract": structural_ready and semantic_ready,
        "drift": normalized,
        "coding_agent_catalog": coding_agent_catalog,
        "connector_snapshot_observable": bool(
            tool_contract.get("client_schema_snapshot_observable")
        ),
        "connector_name_snapshot_observable": bool(
            tool_contract.get("client_snapshot_observable")
        ),
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
    repository = context.get("repository")
    try:
        active_capacity = (
            checkouts.active_capacity_projection(Path(repository))
            if isinstance(repository, str) and repository
            else {
                "available": False,
                "does_not_establish": ["absence_of_active_bindings"],
            }
        )
    except Exception as exc:  # pragma: no cover - defensive read boundary
        active_capacity = {
            "available": False,
            "error_type": type(exc).__name__,
            "does_not_establish": [
                "absence_of_active_bindings",
                "checkout_terminality",
                "checkout_cleanup_eligibility",
            ],
        }
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
        "active_capacity": active_capacity,
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


def _git_preimage_probe(
    repository: Path, arguments: list[str]
) -> subprocess.CompletedProcess[bytes]:
    environment = _read_environment()
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_EXEC_PATH",
        "GIT_CONFIG",
    ):
        environment.pop(key, None)
    for key in tuple(environment):
        if key.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    return subprocess.run(
        _git_command(repository, *arguments),
        cwd=repository,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


@mcp.tool(name="grabowski_git_status", annotations=LOCAL_READ)
def grabowski_git_status(
    repo: RepositoryPath, include_branch_preimage: bool = False
) -> dict[str, Any]:
    """Read fixed short Git status and optionally the exact CAS branch preimage."""
    repository = _resolve_repository(repo)
    result = _run_read(
        _git_command(repository, "status", "--short", "--branch", "--untracked-files=normal"),
        cwd=repository,
    )
    if include_branch_preimage:
        result["branch_preimage"] = {
            "kind": "grabowski_git_branch_preimage",
            **grabowski_git_preimage.capture_branch_preimage(
                repository,
                lambda checkout_root, arguments: _git_preimage_probe(checkout_root, arguments),
            ),
        }
    return result


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
    requested = _validate_revision(revision)
    selected = _resolve_revision(repository, requested)
    result = _run_read(
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
    try:
        readback = _resolve_revision(repository, requested)
    except ValueError:
        readback = None
    stable = readback == selected
    return {
        **result,
        "revision_binding": {
            "requested_revision": requested,
            "output_object_id": selected,
            "readback_object_id": readback,
            "readback_status": (
                "stable"
                if stable
                else "unresolvable"
                if readback is None
                else "moved"
            ),
            "stable": stable,
        },
    }


@mcp.tool(name="grabowski_github_pr_view", annotations=REMOTE_READ)
def grabowski_github_pr_view(
    repo: GitHubRepository,
    pr: PullRequestNumber,
) -> dict[str, Any]:
    """Read bounded GitHub pull-request metadata without body or comments."""
    repository, repository_args = _resolve_github_repository(repo)
    validated_pr = _validate_pr(pr)
    if not _github_cli_enabled():
        if not repository_args:
            raise PermissionError(
                "github_cli is required for absolute-worktree GitHub reads; "
                "anonymous reads require canonical owner/repository"
            )
        canonical_repo = repository_args[-1]
        result = _github_rest_json(
            _github_rest_path(canonical_repo, "pulls", str(validated_pr))
        )
        if result.get("returncode") != 0 or result.get("json_valid") is not True:
            return result
        try:
            data = _github_pr_projection(result.get("data"))
        except ValueError as exc:
            return {**result, "json_valid": False, "json_error": str(exc), "data": None}
        return {
            **result,
            "data": data,
            "field_availability": {"reviewDecision": "unavailable_anonymous_rest"},
        }
    result = _run_read(
        [
            "gh",
            "pr",
            "view",
            str(validated_pr),
            *repository_args,
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
    repo: GitHubRepository,
    pr: PullRequestNumber,
) -> dict[str, Any]:
    """Read bounded GitHub pull-request check results."""
    repository, repository_args = _resolve_github_repository(repo)
    validated_pr = _validate_pr(pr)
    if not _github_cli_enabled():
        if not repository_args:
            raise PermissionError(
                "github_cli is required for absolute-worktree GitHub reads; "
                "anonymous reads require canonical owner/repository"
            )
        canonical_repo = repository_args[-1]
        pull = _github_rest_json(
            _github_rest_path(canonical_repo, "pulls", str(validated_pr))
        )
        if pull.get("returncode") != 0 or pull.get("json_valid") is not True:
            return {**pull, "stage": "pull_request"}
        pull_data = pull.get("data")
        head = pull_data.get("head") if isinstance(pull_data, dict) else None
        head_sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(head_sha, str) or OBJECT_ID_RE.fullmatch(head_sha) is None:
            return {
                **pull,
                "json_valid": False,
                "json_error": "GitHub pull-request response lacks a valid head SHA",
                "data": None,
                "stage": "pull_request",
            }
        result = _github_rest_json(
            _github_rest_path(
                canonical_repo, "commits", head_sha, "check-runs", query="per_page=100"
            )
        )
        if result.get("returncode") != 0 or result.get("json_valid") is not True:
            return {**result, "stage": "check_runs", "head_sha": head_sha}
        payload = result.get("data")
        runs = payload.get("check_runs") if isinstance(payload, dict) else None
        if not isinstance(runs, list):
            return {
                **result,
                "json_valid": False,
                "json_error": "GitHub check-runs response lacks check_runs",
                "data": None,
                "stage": "check_runs",
                "head_sha": head_sha,
            }
        check_total = payload.get("total_count")
        bounded_runs = runs[:100]
        checks_truncated = (
            isinstance(check_total, int) and check_total > len(bounded_runs)
        )
        check_rows = [_github_check_projection(item) for item in bounded_runs]

        status_result = _github_rest_json(
            _github_rest_path(
                canonical_repo, "commits", head_sha, "status", query="per_page=100"
            )
        )
        if (
            status_result.get("returncode") != 0
            or status_result.get("json_valid") is not True
        ):
            return {
                "transport": status_result.get("transport"),
                "origin": status_result.get("origin"),
                "http_status": status_result.get("http_status"),
                "rate_limit": status_result.get("rate_limit"),
                "transport_returncode": status_result.get("returncode"),
                "returncode": 1,
                "json_valid": status_result.get("json_valid"),
                "stage": "commit_status",
                "head_sha": head_sha,
                "data": check_rows,
                "check_run_count": len(check_rows),
                "status_context_count": None,
                "total_count": len(check_rows),
                "reported_check_run_count": (
                    check_total if isinstance(check_total, int) else None
                ),
                "checks_truncated": checks_truncated,
                "complete": False,
                "semantic_scope": "check_runs_and_commit_statuses_only",
                "field_availability": {
                    "commit_status": "unavailable",
                    "event": "unavailable_anonymous_rest",
                    "workflow": "unavailable_anonymous_rest",
                },
            }
        status_payload = status_result.get("data")
        statuses = (
            status_payload.get("statuses")
            if isinstance(status_payload, dict)
            else None
        )
        if not isinstance(statuses, list):
            return {
                "transport": status_result.get("transport"),
                "origin": status_result.get("origin"),
                "http_status": status_result.get("http_status"),
                "rate_limit": status_result.get("rate_limit"),
                "transport_returncode": status_result.get("returncode"),
                "returncode": 1,
                "json_valid": False,
                "json_error": "GitHub combined-status response lacks statuses",
                "stage": "commit_status",
                "head_sha": head_sha,
                "data": check_rows,
                "check_run_count": len(check_rows),
                "status_context_count": None,
                "reported_check_run_count": (
                    check_total if isinstance(check_total, int) else None
                ),
                "checks_truncated": checks_truncated,
                "complete": False,
                "semantic_scope": "check_runs_and_commit_statuses_only",
                "field_availability": {
                    "commit_status": "invalid_shape",
                    "event": "unavailable_anonymous_rest",
                    "workflow": "unavailable_anonymous_rest",
                },
            }
        status_total = status_payload.get("total_count")
        bounded_statuses = statuses[:100]
        status_contexts_truncated = (
            isinstance(status_total, int) and status_total > len(bounded_statuses)
        )

        status_rows = [_github_status_projection(item) for item in bounded_statuses]
        projected_rows = [*check_rows, *status_rows]
        complete = not checks_truncated and not status_contexts_truncated
        semantic_returncode = _github_checks_semantic_returncode(projected_rows)
        return {
            **result,
            "rate_limit": status_result.get("rate_limit"),
            "transport_returncode": status_result.get("returncode"),
            "returncode": semantic_returncode if complete else 1,
            "data": projected_rows,
            "head_sha": head_sha,
            "total_count": len(projected_rows),
            "check_run_count": len(check_rows),
            "status_context_count": len(status_rows),
            "reported_check_run_count": (
                check_total if isinstance(check_total, int) else None
            ),
            "reported_status_context_count": (
                status_total if isinstance(status_total, int) else None
            ),
            "checks_truncated": checks_truncated,
            "status_contexts_truncated": status_contexts_truncated,
            "complete": complete,
            "semantic_scope": "check_runs_and_commit_statuses_only",
            "field_availability": {
                "event": "unavailable_anonymous_rest",
                "workflow": "unavailable_anonymous_rest",
            },
        }
    result = _run_read(
        [
            "gh",
            "pr",
            "checks",
            str(validated_pr),
            *repository_args,
            "--json",
            ",".join(GITHUB_CHECK_FIELDS),
        ],
        cwd=repository,
        timeout_seconds=60,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    return _parse_json_result(result)


@mcp.tool(name="grabowski_tailscale_status", annotations=LOCAL_READ)
def grabowski_tailscale_status() -> dict[str, Any]:
    """Read bounded local Tailscale node and peer health without account records or mutation controls."""
    executable = shutil.which("tailscale")
    if not executable:
        return {
            "available": False,
            "executable_present": False,
            "status_readable": False,
            "reason": "tailscale executable is not installed",
            "data": None,
        }
    raw = _run_read(
        [executable, "status", "--json"],
        cwd=operator.HOME,
        timeout_seconds=20,
        max_output_bytes=MAX_TAILSCALE_RESPONSE_BYTES,
    )
    if raw.get("returncode") != 0:
        return _tailscale_failure_projection(
            raw,
            reason="tailscale_status_command_failed",
            json_valid=None,
        )
    parsed = _parse_json_result(raw)
    if parsed.get("json_valid") is not True:
        return _tailscale_failure_projection(
            parsed,
            reason="tailscale_status_invalid_json",
            json_valid=False,
        )
    try:
        data = _tailscale_status_projection(parsed.get("data"))
    except ValueError:
        return _tailscale_failure_projection(
            parsed,
            reason="tailscale_status_unexpected_shape",
            json_valid=False,
        )
    return {
        "available": True,
        "executable_present": True,
        "status_readable": True,
        "returncode": parsed.get("returncode"),
        "timed_out": bool(parsed.get("timed_out")),
        "duration_seconds": parsed.get("duration_seconds"),
        "stdout_truncated": bool(parsed.get("stdout_truncated")),
        "stderr_truncated": bool(parsed.get("stderr_truncated")),
        "json_valid": True,
        "data": data,
    }


def _validate_service_read_unit(unit: str) -> str:
    name = operator._validate_unit(unit)
    if name.startswith("-"):
        raise ValueError("Invalid systemd unit name")
    return name


@mcp.tool(name="grabowski_service_status", annotations=LOCAL_READ)
def grabowski_service_status(unit: SystemdUnit) -> dict[str, Any]:
    """Read a fixed property set for one user-level systemd unit."""
    name = _validate_service_read_unit(unit)
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
    name = _validate_service_read_unit(unit)
    if isinstance(max_lines, bool) or max_lines < 1 or max_lines > MAX_LOG_LINES:
        raise ValueError(f"max_lines must be between 1 and {MAX_LOG_LINES}")
    operator._require_operator_capability("user_service_logs_read")
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

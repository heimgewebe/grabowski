from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any

from mcp.types import ToolAnnotations

import grabowski_capabilities as capabilities
import grabowski_mcp as base
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
REVISION_RE = re.compile(r"[A-Za-z0-9_./@{}^~:+-]+")
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


def _terminate(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    return operator._terminate_process_group(process)


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
    try:
        stdout_raw, stderr_raw = process.communicate(timeout=timeout_seconds)
        timed_out = False
        returncode: int | None = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout_raw, stderr_raw = _terminate(process)
        returncode = process.returncode

    stdout = operator._redact(stdout_raw.decode("utf-8", errors="replace"))
    stderr = operator._redact(stderr_raw.decode("utf-8", errors="replace"))
    stdout, stdout_truncated = operator._limit(stdout, max_output_bytes)
    stderr, stderr_truncated = operator._limit(stderr, max_output_bytes)
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


def _validate_pr(pr: int) -> int:
    if isinstance(pr, bool) or pr < 1 or pr > 2_147_483_647:
        raise ValueError("pr must be a positive integer")
    return pr


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
    return {
        "service": "grabowski-mcp",
        "healthy": (
            deployment.get("completion_status") == "complete"
            and all(integrity.values())
            and bool(audit.get("valid"))
            and not bool(base._kill_switch_state().get("engaged"))
        ),
        "deployment_complete": deployment.get("completion_status") == "complete",
        "deployment_integrity_valid": all(integrity.values()),
        "audit_valid": bool(audit.get("valid")),
        "kill_switch_engaged": bool(base._kill_switch_state().get("engaged")),
        "release_id": deployment.get("release_id"),
        "repo_head": deployment.get("repo_head"),
    }


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
def grabowski_checkout_summary() -> dict[str, Any]:
    """Return a bounded summary of Grabowski repository worktrees."""
    deployment = base._deployment_metadata()
    runtime_head = deployment.get("repo_head")
    context = runtime_extensions._worktree_context(
        runtime_head if isinstance(runtime_head, str) else None
    )
    worktrees = context.get("worktrees", [])
    if not isinstance(worktrees, list):
        worktrees = []
    selected = []
    for item in worktrees[:MAX_WORKTREES]:
        if not isinstance(item, dict):
            continue
        selected.append(
            {
                key: item.get(key)
                for key in (
                    "path",
                    "head",
                    "branch",
                    "detached",
                    "bare",
                    "prunable",
                    "matches_runtime",
                )
                if key in item
            }
        )
    canonical = context.get("canonical_checkout")
    return {
        "repository": context.get("repository"),
        "exists": bool(context.get("exists")),
        "canonical_checkout": canonical,
        "canonical_matches_runtime": bool(context.get("canonical_matches_runtime")),
        "runtime_matching_worktree_count": len(
            context.get("runtime_matching_worktrees", [])
        ),
        "worktree_count": len(worktrees),
        "worktrees": selected,
        "truncated": len(worktrees) > MAX_WORKTREES,
    }


@mcp.tool(name="grabowski_git_status", annotations=LOCAL_READ)
def grabowski_git_status(repo: str) -> dict[str, Any]:
    """Read fixed short Git status for one allowed repository."""
    repository = _resolve_repository(repo)
    return _run_read(
        _git_command(repository, "status", "--short", "--branch", "--untracked-files=normal"),
        cwd=repository,
    )


@mcp.tool(name="grabowski_git_diff", annotations=LOCAL_READ)
def grabowski_git_diff(
    repo: str,
    staged: bool = False,
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
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
def grabowski_git_log(repo: str, max_count: int = 20) -> dict[str, Any]:
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
    repo: str,
    revision: str = "HEAD",
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Read one bounded Git revision without external diff or textconv helpers."""
    repository = _resolve_repository(repo)
    selected = _validate_revision(revision)
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
def grabowski_github_pr_view(repo: str, pr: int) -> dict[str, Any]:
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
def grabowski_github_checks(repo: str, pr: int) -> dict[str, Any]:
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
def grabowski_service_status(unit: str) -> dict[str, Any]:
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
def grabowski_service_logs(unit: str, max_lines: int = 200) -> dict[str, Any]:
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

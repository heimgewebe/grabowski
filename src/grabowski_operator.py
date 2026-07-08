#!/usr/bin/env python3

from __future__ import annotations

import argparse

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time
from typing import Any
import uuid

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

import grabowski_mcp as base


HOME = Path.home().resolve()
EVIDENCE_ROOT = (HOME / "repos" / "merges").resolve()
STATE_DIR = (HOME / ".local" / "state" / "grabowski").resolve()
JOBS_DIR = STATE_DIR / "jobs"
JOB_PREFIX = "grabowski-job-"
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 120
TRUSTED_MAX_TIMEOUT = 86_400
DEFAULT_JOB_RUNTIME = 7_200
MAX_JOB_RUNTIME = 86_400
TRUSTED_MAX_JOB_RUNTIME = 2_592_000
DEFAULT_OUTPUT_BYTES = 250_000
MAX_OUTPUT_BYTES = 2_000_000
TRUSTED_MAX_OUTPUT_BYTES = 33_554_432

READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
MUTATING = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

SENSITIVE_ENV_PARTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "COOKIE",
    "CREDENTIAL",
    "AUTHORIZATION",
    "API_KEY",
    "APIKEY",
)
PRIVILEGE_ESCALATORS = {"sudo", "su", "pkexec", "doas"}
PROTECTED_BRANCHES = {"main", "master"}
PRIVILEGED_REFERENCE_TTL_SECONDS = 900
PRIVILEGED_REFERENCE_REPLAY_POLICY = "single-use-external-broker"
_SECRET_KEY_PREFIX = "s" + "k-"
_OPENAI_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"(?:(?:proj|svcacct|admin)-[A-Za-z0-9._-]{20,}|[A-Za-z0-9]{24,})(?![A-Za-z0-9._-])"
)
_ANTHROPIC_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"ant-[A-Za-z0-9._-]{20,}(?![A-Za-z0-9._-])"
)
OPERATOR_CAPABILITIES = (
    "terminal_execute",
    "durable_job",
    "git_cli",
    "github_cli",
    "user_service_control",
    "tmux_interaction",
    "process_inspect",
    "process_signal",
    "port_inspect",
    "privileged_reference",
    "resource_lease",
    "artifact_transfer",
    "browser_worker",
    "gui_worker",
)
PRIVILEGED_REFERENCE_ACTIONS = {
    "install_system_package",
    "edit_system_service",
    "bind_privileged_port",
    "change_file_owner",
    "mount_filesystem",
    "reset_failed_systemd_unit",
}

REDACTIONS = (
    (_OPENAI_SECRET_PATTERN, "<REDACTED_OPENAI_KEY>"),
    (_ANTHROPIC_SECRET_PATTERN, "<REDACTED_ANTHROPIC_KEY>"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.I),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?"
            r"-----END [^-]*PRIVATE KEY-----",
            re.S,
        ),
        "<REDACTED_PRIVATE_KEY>",
    ),
    (
        re.compile(
            r"(?im)^([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY)"
            r"[A-Z0-9_]*\s*=\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
)


def _find_server() -> FastMCP:
    servers = [
        value
        for value in vars(base).values()
        if isinstance(value, FastMCP)
    ]
    unique = []
    for server in servers:
        if all(server is not existing for existing in unique):
            unique.append(server)

    if len(unique) != 1:
        raise RuntimeError(
            f"Expected exactly one FastMCP instance, found {len(unique)}"
        )
    return unique[0]


mcp = _find_server()


def _redact(text: str, extra_secrets: list[str] | None = None) -> str:
    result = text
    for pattern, replacement in REDACTIONS:
        result = pattern.sub(replacement, result)
    for secret in sorted(set(extra_secrets or []), key=len, reverse=True):
        if secret:
            result = result.replace(secret, "<REDACTED>")
    return result


def _argv_hash(argv: list[str]) -> str:
    encoded = json.dumps(
        argv,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for item in argv:
        if hide_next:
            redacted.append("<REDACTED>")
            hide_next = False
            continue

        key = item.split("=", 1)[0].lstrip("-").replace("-", "_").upper()
        if any(part in key for part in SENSITIVE_ENV_PARTS):
            if "=" in item:
                redacted.append(f"{item.split('=', 1)[0]}=<REDACTED>")
            else:
                redacted.append(item)
                hide_next = True
            continue
        redacted.append(_redact(item))
    return redacted


def _argv_secret_values(argv: list[str]) -> list[str]:
    values: list[str] = []
    hide_next = False
    for item in argv:
        if hide_next:
            values.append(item)
            hide_next = False
            continue

        key = item.split("=", 1)[0].lstrip("-").replace("-", "_").upper()
        if not any(part in key for part in SENSITIVE_ENV_PARTS):
            continue
        if "=" in item:
            values.append(item.split("=", 1)[1])
        else:
            hide_next = True
    return values


def _redacted_command(argv: list[str]) -> str:
    return shlex.join(_redact_argv(argv))


def _operator_capabilities() -> set[str]:
    policy = base._load_policy()
    forbidden = set(policy.get("forbidden_capabilities", []))
    profiles = policy.get("profiles")
    if isinstance(profiles, dict):
        profile = base._active_profile(policy)
        raw = profile.get("capabilities", [])
        capabilities = {item for item in raw if isinstance(item, str)}
    else:
        capabilities = set(OPERATOR_CAPABILITIES)
    return {
        capability
        for capability in capabilities
        if capability in OPERATOR_CAPABILITIES and capability not in forbidden
    }


def _trusted_owner_mode() -> bool:
    predicate = getattr(base, "_trusted_owner_enabled", None)
    if predicate is None:
        return False
    return bool(predicate(base._load_policy()))


def _require_operator_capability(capability: str) -> None:
    if capability not in _operator_capabilities():
        raise PermissionError(f"Operator capability is not enabled: {capability}")


def _require_operator_mutation(capability: str) -> None:
    _require_operator_capability(capability)
    state = base._kill_switch_state()
    if state["engaged"]:
        raise PermissionError(
            "Grabowski operator kill switch is engaged; mutating tools are disabled."
        )
    base._require_valid_audit_chain()


def _limit(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    clipped = encoded[:limit].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _safe_environment() -> dict[str, str]:
    if _trusted_owner_mode():
        environment = dict(os.environ)
    else:
        environment = {}
        for key, value in os.environ.items():
            upper = key.upper()
            if any(part in upper for part in SENSITIVE_ENV_PARTS):
                continue
            environment[key] = value
    environment["GRABOWSKI_EVIDENCE_ROOT"] = str(EVIDENCE_ROOT)
    environment["GRABOWSKI_TRUSTED_OWNER"] = "1" if _trusted_owner_mode() else "0"
    return environment


def _resolve_cwd(cwd: str | None) -> Path:
    path = HOME if cwd is None else Path(cwd).expanduser()
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Working directory is not a directory: {resolved}")
    if (
        resolved == EVIDENCE_ROOT or EVIDENCE_ROOT in resolved.parents
    ) and not _trusted_owner_mode():
        raise PermissionError(
            f"Commands may not run inside immutable evidence: {resolved}"
        )
    return resolved


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _path_like_argument(value: str) -> bool:
    if "://" in value:
        return False
    return value.startswith(("/", ".", "~")) or "/" in value


def _argument_path_candidates(value: str) -> list[str]:
    candidates = [value]
    if "=" in value:
        candidates.append(value.split("=", 1)[1])
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        tokens = []
    for token in tokens:
        candidates.append(token)
        if "=" in token:
            candidates.append(token.split("=", 1)[1])
    return candidates


def _expand_home_references(value: str) -> str:
    return re.sub(r"\$\{HOME\}|\$HOME\b", str(HOME), value)


def _argument_targets_evidence(value: str, cwd: Path) -> bool:
    if str(EVIDENCE_ROOT) in _expand_home_references(value):
        return True
    for candidate in _argument_path_candidates(value):
        candidate = _expand_home_references(candidate)
        if str(EVIDENCE_ROOT) in candidate:
            return True
        if not _path_like_argument(candidate):
            continue
        path = Path(candidate).expanduser()
        if not path.is_absolute():
            path = cwd / path
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            resolved = path.absolute()
        if _path_inside(resolved, EVIDENCE_ROOT):
            return True
    return False


def _validate_argv(argv: list[str], *, cwd: Path | None = None) -> list[str]:
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")

    trusted_owner = _trusted_owner_mode()
    executable = Path(argv[0]).name
    if executable in PRIVILEGE_ESCALATORS and not trusted_owner:
        raise PermissionError(
            f"Privilege escalation is not available through Grabowski: "
            f"{executable}"
        )

    working_directory = HOME if cwd is None else cwd
    if not trusted_owner:
        for item in argv:
            if _argument_targets_evidence(item, working_directory):
                raise PermissionError(
                    "Direct command arguments may not target immutable evidence."
                )

    return argv


def _timeout(value: int) -> int:
    maximum = TRUSTED_MAX_TIMEOUT if _trusted_owner_mode() else MAX_TIMEOUT
    if value < 1 or value > maximum:
        raise ValueError(
            f"timeout_seconds must be between 1 and {maximum}"
        )
    return value


def _job_runtime(value: int) -> int:
    maximum = TRUSTED_MAX_JOB_RUNTIME if _trusted_owner_mode() else MAX_JOB_RUNTIME
    if value < 1 or value > maximum:
        raise ValueError(f"runtime_seconds must be between 1 and {maximum}")
    return value


def _output_limit(value: int) -> int:
    maximum = TRUSTED_MAX_OUTPUT_BYTES if _trusted_owner_mode() else MAX_OUTPUT_BYTES
    if value < 1 or value > maximum:
        raise ValueError(
            f"max_output_bytes must be between 1 and {maximum}"
        )
    return value


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float = 3.0,
) -> tuple[bytes, bytes]:
    if process.poll() is not None:
        return process.communicate()
    os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        return process.communicate()


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=_safe_environment(),
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
        stdout_raw, stderr_raw = _terminate_process_group(process)
        returncode = process.returncode

    argv_secrets = _argv_secret_values(argv)
    stdout = _redact(
        stdout_raw.decode("utf-8", errors="replace"),
        argv_secrets,
    )
    stderr = _redact(
        stderr_raw.decode("utf-8", errors="replace"),
        argv_secrets,
    )
    stdout, stdout_truncated = _limit(stdout, max_output_bytes)
    stderr, stderr_truncated = _limit(stderr, max_output_bytes)

    return {
        "argv": _redact_argv(argv),
        "argv_sha256": _argv_hash(argv),
        "command": _redacted_command(argv),
        "cwd": str(cwd),
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def _parse_show(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _validate_unit(unit: str, *, job_only: bool = False) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,200}", unit):
        raise ValueError("Invalid systemd unit name")
    if job_only and not unit.startswith(JOB_PREFIX):
        raise PermissionError(
            f"Only {JOB_PREFIX}* units are valid job targets."
        )
    return unit


def _systemd_safe_description(
    kind: str,
    unit: str,
    argv_sha256: str | None = None,
) -> str:
    """Return a bounded single-line Description= value for systemd-run."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", kind):
        raise ValueError("Invalid systemd description kind")
    name = _validate_unit(unit)
    parts = ["Grabowski", kind, name]
    if argv_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", argv_sha256):
            raise ValueError("Invalid argv sha256")
        parts.append(f"argv={argv_sha256[:12]}")
    value = " ".join(parts)
    if any(item in value for item in ("\n", "\r", "\x00")):
        raise ValueError("Invalid systemd description")
    if len(value.encode("utf-8")) > 200:
        raise ValueError("Systemd description is too large")
    return value


def _jobs_root() -> Path:
    if JOBS_DIR.is_symlink():
        raise PermissionError(f"Jobs directory may not be a symlink: {JOBS_DIR}")
    JOBS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = JOBS_DIR.resolve(strict=True)
    if root.parent != STATE_DIR:
        raise PermissionError(f"Jobs directory escaped state root: {root}")
    return root


def _job_directory(unit: str, *, create: bool = False) -> Path:
    name = _validate_unit(unit, job_only=True)
    root = _jobs_root()
    path = root / name
    if path.is_symlink():
        raise PermissionError(f"Job directory may not be a symlink: {path}")
    if create:
        path.mkdir(mode=0o700)
    elif not path.is_dir():
        raise ValueError(f"Job metadata does not exist: {name}")
    resolved = path.resolve(strict=True)
    if resolved.parent != root:
        raise PermissionError(f"Job directory escaped jobs root: {resolved}")
    return resolved


def _write_job_metadata(directory: Path, payload: dict[str, Any]) -> Path:
    path = directory / "metadata.json"
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _read_job_metadata(unit: str) -> dict[str, Any]:
    directory = _job_directory(unit)
    path = directory / "metadata.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Job metadata is missing: {unit}")
    if path.stat().st_size > 64 * 1024:
        raise ValueError(f"Job metadata is too large: {unit}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("unit") != unit:
        raise ValueError(f"Job metadata is invalid: {unit}")
    return payload


def _read_job_log(path: Path, max_lines: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        return {"text": "", "truncated": False, "bytes": 0}
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > MAX_OUTPUT_BYTES:
            handle.seek(-MAX_OUTPUT_BYTES, os.SEEK_END)
        data = handle.read(MAX_OUTPUT_BYTES)
    decoded = _redact(data.decode("utf-8", errors="replace"))
    lines = decoded.splitlines()
    line_truncated = len(lines) > max_lines
    text = "\n".join(lines[-max_lines:])
    return {
        "text": text,
        "truncated": size > MAX_OUTPUT_BYTES or line_truncated,
        "bytes": size,
    }


def _git_branch(repo: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), "branch", "--show-current"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "Not a Git repository")
    return completed.stdout.strip()


def _force_push_requested(arguments: list[str]) -> bool:
    return any(
        item in {"-f", "--force", "--force-with-lease"}
        or item.startswith("--force=")
        or item.startswith("--force-with-lease=")
        or item.startswith("+")
        for item in arguments[1:]
    )


def _aggregate_push_requested(arguments: list[str]) -> bool:
    return any(
        item in {"--all", "--mirror", "--tags"}
        or "*" in item
        for item in arguments[1:]
    )


def _mirror_push_requested(arguments: list[str]) -> bool:
    return "--mirror" in arguments[1:]


def _normal_branch_name(ref: str) -> str:
    value = ref.removeprefix("+")
    if ":" in value:
        value = value.rsplit(":", 1)[1]
    value = value.removeprefix("refs/heads/")
    return value


def _push_mentions_protected_branch(arguments: list[str]) -> bool:
    for item in arguments[1:]:
        if not item or item.startswith("-"):
            continue
        if _normal_branch_name(item) in PROTECTED_BRANCHES:
            return True
    return False


def _guard_git(arguments: list[str], repo: Path) -> None:
    if not arguments:
        raise ValueError("Git arguments must not be empty")
    if _trusted_owner_mode():
        return

    if arguments[0] != "push":
        return

    force = _force_push_requested(arguments)
    if _aggregate_push_requested(arguments) and (
        force or _mirror_push_requested(arguments)
    ):
        raise PermissionError("Forced aggregate Git pushes are blocked.")
    if force and (
        _git_branch(repo) in PROTECTED_BRANCHES
        or _push_mentions_protected_branch(arguments)
    ):
        raise PermissionError(
            "Force-push to a protected main branch is blocked."
        )


@mcp.tool(name="grabowski_terminal_run", annotations=MUTATING)
def grabowski_terminal_run(
    argv: list[str],
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT,
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Run one non-interactive command and return redacted output."""
    _require_operator_mutation("terminal_execute")
    working_directory = _resolve_cwd(cwd)
    return _run(
        _validate_argv(argv, cwd=working_directory),
        cwd=working_directory,
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=_output_limit(max_output_bytes),
    )


@mcp.tool(name="grabowski_job_start", annotations=MUTATING)
def grabowski_job_start(
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = DEFAULT_JOB_RUNTIME,
) -> dict[str, Any]:
    """Start a durable background command as a transient user systemd unit."""
    _require_operator_mutation("durable_job")
    working_directory = _resolve_cwd(cwd)
    command = _validate_argv(argv, cwd=working_directory)
    runtime = _job_runtime(runtime_seconds)
    unit = JOB_PREFIX + uuid.uuid4().hex[:12]
    directory = _job_directory(unit, create=True)
    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    for path in (stdout_path, stderr_path):
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        os.close(descriptor)

    metadata = {
        "schema_version": 1,
        "unit": unit,
        "argv": _redact_argv(command),
        "argv_sha256": _argv_hash(command),
        "command": _redacted_command(command),
        "cwd": str(working_directory),
        "runtime_seconds": runtime,
        "created_at_unix": int(time.time()),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }
    metadata_path = _write_job_metadata(directory, metadata)

    result = _run(
        [
            "systemd-run",
            "--user",
            f"--description={_systemd_safe_description('job', unit, metadata['argv_sha256'])}",
            "--unit",
            unit,
            "--property=Type=exec",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=10s",
            f"--property=RuntimeMaxSec={runtime}s",
            f"--property=WorkingDirectory={working_directory}",
            f"--property=StandardOutput=append:{stdout_path}",
            f"--property=StandardError=append:{stderr_path}",
            "--",
            *command,
        ],
        cwd=HOME,
        timeout_seconds=60,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or result["stdout"])

    return {
        **metadata,
        "metadata_path": str(metadata_path),
        "launcher": result,
    }


@mcp.tool(name="grabowski_job_status", annotations=READ_ONLY)
def grabowski_job_status(unit: str) -> dict[str, Any]:
    """Return durable metadata and current systemd status for one job."""
    _require_operator_capability("durable_job")
    name = _validate_unit(unit, job_only=True)
    metadata = _read_job_metadata(name)
    result = _run(
        [
            "systemctl",
            "--user",
            "show",
            name,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
            "--property=RuntimeMaxUSec",
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    properties = _parse_show(result["stdout"])
    return {
        "unit": name,
        "metadata": metadata,
        "systemd_visible": (
            result["returncode"] == 0
            and properties.get("LoadState") != "not-found"
        ),
        "returncode": result["returncode"],
        "properties": properties,
        "stderr": result["stderr"],
    }


@mcp.tool(name="grabowski_job_logs", annotations=READ_ONLY)
def grabowski_job_logs(
    unit: str,
    max_lines: int = 200,
) -> dict[str, Any]:
    """Read persistent stdout and stderr for one Grabowski job."""
    _require_operator_capability("durable_job")
    name = _validate_unit(unit, job_only=True)
    if max_lines < 1 or max_lines > 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    metadata = _read_job_metadata(name)
    directory = _job_directory(name)
    expected = {
        "stdout_path": directory / "stdout.log",
        "stderr_path": directory / "stderr.log",
    }
    for key, path in expected.items():
        if metadata.get(key) != str(path):
            raise ValueError(f"Job metadata path mismatch: {key}")
    return {
        "unit": name,
        "metadata": metadata,
        "stdout": _read_job_log(expected["stdout_path"], max_lines),
        "stderr": _read_job_log(expected["stderr_path"], max_lines),
    }


@mcp.tool(name="grabowski_job_cancel", annotations=MUTATING)
def grabowski_job_cancel(unit: str) -> dict[str, Any]:
    """Stop one Grabowski background job."""
    _require_operator_mutation("durable_job")
    name = _validate_unit(unit, job_only=True)
    return _run(
        ["systemctl", "--user", "stop", name],
        cwd=HOME,
        timeout_seconds=60,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_git", annotations=MUTATING)
def grabowski_git(
    repo: str,
    arguments: list[str],
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run Git in one repository with protected-main force-push guard."""
    _require_operator_mutation("git_cli")
    path = Path(repo).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    if (path == EVIDENCE_ROOT or EVIDENCE_ROOT in path.parents) and not _trusted_owner_mode():
        raise PermissionError("Git mutation of immutable evidence is blocked.")
    _guard_git(arguments, path)
    command = _validate_argv(["git", "-C", str(path), *arguments], cwd=path)
    return _run(
        command,
        cwd=path,
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_github", annotations=MUTATING)
def grabowski_github(
    arguments: list[str],
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run GitHub CLI with redacted output."""
    _require_operator_mutation("github_cli")
    if not arguments:
        raise ValueError("GitHub CLI arguments must not be empty")
    working_directory = _resolve_cwd(cwd)
    command = _validate_argv(["gh", *arguments], cwd=working_directory)
    return _run(
        command,
        cwd=working_directory,
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_user_service", annotations=MUTATING)
def grabowski_user_service(
    unit: str,
    action: str,
    max_lines: int = 200,
) -> dict[str, Any]:
    """Inspect or control one user-level systemd service."""
    _require_operator_capability("user_service_control")
    name = _validate_unit(unit)
    allowed = {
        "status",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
        "logs",
    }
    if action not in allowed:
        raise ValueError(f"action must be one of {sorted(allowed)}")
    if action not in {"status", "logs"}:
        _require_operator_mutation("user_service_control")

    if action == "logs":
        if max_lines < 1 or max_lines > 2000:
            raise ValueError("max_lines must be between 1 and 2000")
        argv = [
            "journalctl",
            "--user",
            "--unit",
            name,
            "--no-pager",
            "--lines",
            str(max_lines),
        ]
    elif action == "status":
        argv = [
            "systemctl",
            "--user",
            "status",
            name,
            "--no-pager",
            "--full",
        ]
    else:
        argv = ["systemctl", "--user", action, name]

    return _run(
        argv,
        cwd=HOME,
        timeout_seconds=120,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_tmux_list", annotations=READ_ONLY)
def grabowski_tmux_list() -> dict[str, Any]:
    """List tmux sessions visible to the current user."""
    _require_operator_capability("tmux_interaction")
    return _run(
        [
            "tmux",
            "list-sessions",
            "-F",
            "#{session_name}\t#{session_windows}\t"
            "#{session_attached}\t#{session_activity}",
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_tmux_capture", annotations=READ_ONLY)
def grabowski_tmux_capture(
    target: str,
    start_line: int = -300,
) -> dict[str, Any]:
    """Capture text from one tmux pane."""
    _require_operator_capability("tmux_interaction")
    if not target or len(target) > 200:
        raise ValueError("Invalid tmux target")
    if start_line > 0 or start_line < -10000:
        raise ValueError("start_line must be between -10000 and 0")
    return _run(
        [
            "tmux",
            "capture-pane",
            "-p",
            "-t",
            target,
            "-S",
            str(start_line),
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_tmux_send", annotations=MUTATING)
def grabowski_tmux_send(
    target: str,
    text: str,
    press_enter: bool = True,
) -> dict[str, Any]:
    """Send literal text to one tmux pane, optionally followed by Enter."""
    _require_operator_mutation("tmux_interaction")
    if not target or len(target) > 200:
        raise ValueError("Invalid tmux target")
    if len(text.encode("utf-8")) > 100_000:
        raise ValueError("tmux text exceeds 100000 bytes")

    first = _run(
        ["tmux", "send-keys", "-t", target, "-l", "--", text],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    if first["returncode"] != 0 or not press_enter:
        return first

    second = _run(
        ["tmux", "send-keys", "-t", target, "Enter"],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    return {
        "target": target,
        "text_bytes": len(text.encode("utf-8")),
        "press_enter": press_enter,
        "send_text": first,
        "send_enter": second,
    }


@mcp.tool(name="grabowski_process_list", annotations=READ_ONLY)
def grabowski_process_list(pattern: str | None = None) -> dict[str, Any]:
    """List current-user processes, optionally filtered by a regex."""
    _require_operator_capability("process_inspect")
    result = _run(
        [
            "ps",
            "-u",
            str(os.getuid()),
            "-o",
            "pid=,ppid=,stat=,etimes=,comm=,args=",
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    lines = result["stdout"].splitlines()
    if pattern:
        regex = re.compile(pattern)
        lines = [line for line in lines if regex.search(line)]
    return {"pattern": pattern, "lines": lines, "count": len(lines)}


@mcp.tool(name="grabowski_process_signal", annotations=MUTATING)
def grabowski_process_signal(
    pid: int,
    signal_name: str = "TERM",
) -> dict[str, Any]:
    """Send TERM, INT, HUP or KILL to one process owned by the current user."""
    _require_operator_mutation("process_signal")
    allowed = {
        "TERM": signal.SIGTERM,
        "INT": signal.SIGINT,
        "HUP": signal.SIGHUP,
        "KILL": signal.SIGKILL,
    }
    name = signal_name.upper()
    if name not in allowed:
        raise ValueError(f"signal_name must be one of {sorted(allowed)}")
    if pid in {0, 1, os.getpid(), os.getppid()}:
        raise PermissionError("Protected process identifier")

    stat = Path(f"/proc/{pid}/status")
    if not stat.is_file():
        raise ValueError(f"Process does not exist: {pid}")
    owner_line = next(
        (
            line
            for line in stat.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            if line.startswith("Uid:")
        ),
        None,
    )
    if owner_line is None:
        raise RuntimeError("Could not determine process owner")
    real_uid = int(owner_line.split()[1])
    if real_uid != os.getuid():
        raise PermissionError("Process is not owned by the current user")

    os.kill(pid, allowed[name])
    return {"pid": pid, "signal": name, "sent": True}


@mcp.tool(name="grabowski_ports", annotations=READ_ONLY)
def grabowski_ports() -> dict[str, Any]:
    """List listening TCP and UDP sockets."""
    _require_operator_capability("port_inspect")
    return _run(
        ["ss", "-lntup"],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_privileged_action_reference", annotations=READ_ONLY)
def grabowski_privileged_action_reference(
    action: str,
    target: str,
    justification: str,
) -> dict[str, Any]:
    """Create a strict reference for a future privileged action without executing it."""
    _require_operator_capability("privileged_reference")
    if action not in PRIVILEGED_REFERENCE_ACTIONS:
        raise ValueError(
            f"action must be one of {sorted(PRIVILEGED_REFERENCE_ACTIONS)}"
        )
    for label, value in {
        "target": target,
        "justification": justification,
    }.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
        if len(value.encode("utf-8")) > 1000 or "\x00" in value:
            raise ValueError(f"{label} is too large or contains NUL")
        if _redact(value) != value:
            raise ValueError(f"{label} appears to contain secret material")

    created_at = int(time.time())
    payload = {
        "schema_version": 1,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_privileged_agent": True,
        "replay_policy": PRIVILEGED_REFERENCE_REPLAY_POLICY,
        "action": action,
        "target": target,
        "justification": justification,
        "request_id": uuid.uuid4().hex,
        "created_at_unix": created_at,
        "expires_at_unix": created_at + PRIVILEGED_REFERENCE_TTL_SECONDS,
    }
    payload["reference_sha256"] = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return payload


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Grabowski MCP operator."
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18181)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.transport == "streamable-http":
        if args.host != "127.0.0.1":
            raise SystemExit(
                "Grabowski HTTP transport must bind to 127.0.0.1"
            )
        if not 1024 <= args.port <= 65535:
            raise SystemExit("port must be between 1024 and 65535")
        mcp.settings.host = args.host
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()

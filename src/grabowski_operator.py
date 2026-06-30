#!/usr/bin/env python3

from __future__ import annotations

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
JOB_PREFIX = "grabowski-job-"
DEFAULT_TIMEOUT = 900
MAX_TIMEOUT = 7200
DEFAULT_OUTPUT_BYTES = 250_000
MAX_OUTPUT_BYTES = 2_000_000

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

REDACTIONS = (
    (
        re.compile(r"sk-[A-Za-z0-9._-]{16,}"),
        "<REDACTED_OPENAI_KEY>",
    ),
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


def _redact(text: str) -> str:
    result = text
    for pattern, replacement in REDACTIONS:
        result = pattern.sub(replacement, result)
    return result


def _limit(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    clipped = encoded[:limit].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _safe_environment() -> dict[str, str]:
    environment: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if any(part in upper for part in SENSITIVE_ENV_PARTS):
            continue
        environment[key] = value
    environment["GRABOWSKI_EVIDENCE_ROOT"] = str(EVIDENCE_ROOT)
    return environment


def _resolve_cwd(cwd: str | None) -> Path:
    path = HOME if cwd is None else Path(cwd).expanduser()
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Working directory is not a directory: {resolved}")
    if resolved == EVIDENCE_ROOT or EVIDENCE_ROOT in resolved.parents:
        raise PermissionError(
            f"Commands may not run inside immutable evidence: {resolved}"
        )
    return resolved


def _validate_argv(argv: list[str]) -> list[str]:
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")

    executable = Path(argv[0]).name
    if executable in PRIVILEGE_ESCALATORS:
        raise PermissionError(
            f"Privilege escalation is not available through Grabowski: "
            f"{executable}"
        )

    evidence = str(EVIDENCE_ROOT)
    for item in argv:
        if evidence in item:
            raise PermissionError(
                "Direct command arguments may not target immutable evidence."
            )

    return argv


def _timeout(value: int) -> int:
    if value < 1 or value > MAX_TIMEOUT:
        raise ValueError(
            f"timeout_seconds must be between 1 and {MAX_TIMEOUT}"
        )
    return value


def _output_limit(value: int) -> int:
    if value < 1 or value > MAX_OUTPUT_BYTES:
        raise ValueError(
            f"max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}"
        )
    return value


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=_safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        timed_out = False
        returncode: int | None = completed.returncode
        stdout_raw = completed.stdout
        stderr_raw = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b""

    stdout = _redact(
        stdout_raw.decode("utf-8", errors="replace")
    )
    stderr = _redact(
        stderr_raw.decode("utf-8", errors="replace")
    )
    stdout, stdout_truncated = _limit(stdout, max_output_bytes)
    stderr, stderr_truncated = _limit(stderr, max_output_bytes)

    return {
        "argv": argv,
        "command": shlex.join(argv),
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


def _guard_git(arguments: list[str], repo: Path) -> None:
    if not arguments:
        raise ValueError("Git arguments must not be empty")

    if arguments[0] != "push":
        return

    force = any(
        item in {"-f", "--force", "--force-with-lease"}
        or item.startswith("--force=")
        or item.startswith("--force-with-lease=")
        for item in arguments[1:]
    )
    if force and _git_branch(repo) in PROTECTED_BRANCHES:
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
    return _run(
        _validate_argv(argv),
        cwd=_resolve_cwd(cwd),
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=_output_limit(max_output_bytes),
    )


@mcp.tool(name="grabowski_job_start", annotations=MUTATING)
def grabowski_job_start(
    argv: list[str],
    cwd: str | None = None,
) -> dict[str, Any]:
    """Start a background command as a transient user systemd unit."""
    command = _validate_argv(argv)
    working_directory = _resolve_cwd(cwd)
    unit = JOB_PREFIX + uuid.uuid4().hex[:12]

    result = _run(
        [
            "systemd-run",
            "--user",
            "--unit",
            unit,
            "--collect",
            "--property=Type=exec",
            f"--property=WorkingDirectory={working_directory}",
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
        "unit": unit,
        "argv": command,
        "cwd": str(working_directory),
        "launcher": result,
    }


@mcp.tool(name="grabowski_job_status", annotations=READ_ONLY)
def grabowski_job_status(unit: str) -> dict[str, Any]:
    """Return status fields for one Grabowski background job."""
    name = _validate_unit(unit, job_only=True)
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
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    return {
        "unit": name,
        "returncode": result["returncode"],
        "properties": _parse_show(result["stdout"]),
        "stderr": result["stderr"],
    }


@mcp.tool(name="grabowski_job_logs", annotations=READ_ONLY)
def grabowski_job_logs(
    unit: str,
    max_lines: int = 200,
) -> dict[str, Any]:
    """Read recent journal output for one Grabowski background job."""
    name = _validate_unit(unit, job_only=True)
    if max_lines < 1 or max_lines > 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    result = _run(
        [
            "journalctl",
            "--user",
            "--unit",
            name,
            "--no-pager",
            "--lines",
            str(max_lines),
        ],
        cwd=HOME,
        timeout_seconds=60,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    return {"unit": name, **result}


@mcp.tool(name="grabowski_job_cancel", annotations=MUTATING)
def grabowski_job_cancel(unit: str) -> dict[str, Any]:
    """Stop one Grabowski background job."""
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
    path = Path(repo).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    if path == EVIDENCE_ROOT or EVIDENCE_ROOT in path.parents:
        raise PermissionError("Git mutation of immutable evidence is blocked.")
    _guard_git(arguments, path)
    return _run(
        ["git", "-C", str(path), *arguments],
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
    if not arguments:
        raise ValueError("GitHub CLI arguments must not be empty")
    return _run(
        ["gh", *arguments],
        cwd=_resolve_cwd(cwd),
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
    return _run(
        ["ss", "-lntup"],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
MAX_CAPTURE_BYTES = 65_536
RUNNER_RELATIVE_PATH = Path("tools/run_scheduled_deploy.py")


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


def git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "NO_COLOR": "1",
        }
    )
    for key in ("GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_ASKPASS", "SSH_ASKPASS"):
        environment.pop(key, None)
    return environment


def run_capture(argv: list[str], *, cwd: Path, timeout: int = 30) -> str:
    process = subprocess.run(
        argv,
        cwd=cwd,
        env=git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    stdout_raw = process.stdout[:MAX_CAPTURE_BYTES]
    stderr_raw = process.stderr[:MAX_CAPTURE_BYTES]
    stdout = stdout_raw.decode("utf-8", errors="replace")
    stderr = stderr_raw.decode("utf-8", errors="replace")
    if len(process.stdout) > MAX_CAPTURE_BYTES or len(process.stderr) > MAX_CAPTURE_BYTES:
        raise RuntimeError("command output exceeded the preflight bound")
    if process.returncode != 0:
        raise RuntimeError(stderr.strip() or stdout.strip() or "command failed")
    return stdout.strip()


def verify_repository(repo: Path) -> tuple[Path, str, Path]:
    if not repo.is_absolute():
        raise RuntimeError("repo must be an absolute path")
    if repo.is_symlink() or not repo.is_dir():
        raise RuntimeError(f"repository is unavailable: {repo}")
    resolved = repo.resolve(strict=True)
    if resolved != repo:
        raise RuntimeError("repository path must not traverse a symlink")
    git_prefix = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(repo),
    ]
    head = run_capture([*git_prefix, "rev-parse", "--verify", "HEAD"], cwd=repo)
    branch = run_capture([*git_prefix, "symbolic-ref", "--short", "HEAD"], cwd=repo)
    origin_main = run_capture([*git_prefix, "rev-parse", "--verify", "refs/remotes/origin/main"], cwd=repo)
    status = run_capture(
        [*git_prefix, "status", "--porcelain=v1", "--untracked-files=normal"],
        cwd=repo,
    )
    if not OBJECT_ID_RE.fullmatch(head):
        raise RuntimeError("HEAD is not a lowercase Git object ID")
    if branch != "main":
        raise RuntimeError(f"checkout is not on main: {branch}")
    if origin_main != head:
        raise RuntimeError(f"origin/main drift: expected {head}, found {origin_main}")
    if status:
        raise RuntimeError("checkout is dirty")
    runner = repo / RUNNER_RELATIVE_PATH
    if runner.is_symlink() or not runner.is_file():
        raise RuntimeError(f"scheduled deployment runner is unavailable: {runner}")
    return repo, head, runner


def unit_name(head: str, now: int) -> str:
    return f"grabowski-scheduled-deploy-{head[:12]}-{now}"


def build_systemd_run_argv(repo: Path, runner: Path, expected_head: str, delay_seconds: int, *, now: int) -> list[str]:
    return [
        "systemd-run",
        "--user",
        f"--description=Grabowski scheduled deploy {expected_head[:12]}",
        "--unit",
        unit_name(expected_head, now),
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=RuntimeMaxSec=3600s",
        "--property=UMask=0077",
        f"--property=WorkingDirectory={repo}",
        "--",
        "/usr/bin/python3",
        str(runner),
        "--repo",
        str(repo),
        "--expected-head",
        expected_head,
        "--delay-seconds",
        str(delay_seconds),
    ]


def run_systemd_run(argv: list[str], *, cwd: Path) -> dict[str, Any]:
    process = subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    stdout = process.stdout.decode("utf-8", errors="replace")
    stderr = process.stderr.decode("utf-8", errors="replace")
    if len(process.stdout) > MAX_CAPTURE_BYTES or len(process.stderr) > MAX_CAPTURE_BYTES:
        raise RuntimeError("systemd-run output exceeded the preflight bound")
    return {
        "returncode": process.returncode,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
    }


def schedule(repo: Path, delay_seconds: int) -> dict[str, Any]:
    if not 5 <= delay_seconds <= 60:
        raise ValueError("delay_seconds must be between 5 and 60")
    verified_repo, head, runner = verify_repository(repo)
    now = int(time.time())
    argv = build_systemd_run_argv(verified_repo, runner, head, delay_seconds, now=now)
    result = run_systemd_run(argv, cwd=verified_repo)
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or result["stdout"] or "systemd-run failed")
    return {
        "scheduled": True,
        "repo": str(verified_repo),
        "expected_head": head,
        "delay_seconds": delay_seconds,
        "unit": unit_name(head, now),
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "status_command": ["systemctl", "--user", "status", unit_name(head, now)],
        "logs_command": ["journalctl", "--user", "--unit", unit_name(head, now), "--no-pager"],
        "expected_connector_disconnect": True,
        "runner": str(runner),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--delay-seconds", type=int, default=8)
    args = parser.parse_args()
    try:
        emit(schedule(args.repo, args.delay_seconds))
        return 0
    except Exception as exc:
        emit({"scheduled": False, "error_type": type(exc).__name__, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

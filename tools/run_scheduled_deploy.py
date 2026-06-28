#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from typing import Any

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
MAX_CAPTURE_BYTES = 65_536
MAX_MANIFEST_BYTES = 2_000_000


def emit(phase: str, **fields: Any) -> None:
    print(json.dumps({"timestamp_unix": int(time.time()), "phase": phase, **fields}, ensure_ascii=False, sort_keys=True), flush=True)


def git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "PAGER": "cat", "NO_COLOR": "1"})
    for key in ("GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_ASKPASS", "SSH_ASKPASS"):
        environment.pop(key, None)
    return environment


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def read_limited_process_pipes(process: subprocess.Popen[bytes], *, timeout_seconds: int, max_output_bytes: int) -> tuple[bytes, bytes, bool, bool, bool]:
    started = time.monotonic()
    timed_out = False
    stdout_truncated = False
    stderr_truncated = False
    buffers: dict[Any, bytearray] = {}
    selector = selectors.DefaultSelector()

    def append_limited(pipe: Any, chunk: bytes) -> None:
        nonlocal stdout_truncated, stderr_truncated
        if not chunk or pipe not in buffers:
            return
        buffer = buffers[pipe]
        keep = 0
        if len(buffer) < max_output_bytes:
            keep = min(len(chunk), max_output_bytes - len(buffer))
            buffer.extend(chunk[:keep])
        if len(chunk) > keep:
            if pipe is process.stdout:
                stdout_truncated = True
            else:
                stderr_truncated = True

    for pipe in (process.stdout, process.stderr):
        if pipe is None:
            continue
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
        buffers[pipe] = bytearray()

    while selector.get_map():
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            timed_out = True
            terminate_process_group(process)
            break
        for key, _events in selector.select(timeout=min(0.2, remaining)):
            pipe = key.fileobj
            chunk = os.read(pipe.fileno(), 8192)
            if not chunk:
                selector.unregister(pipe)
                continue
            append_limited(pipe, chunk)

    if process.poll() is None and not timed_out:
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_group(process)
    elif process.poll() is not None:
        process.wait(timeout=0)

    stdout = bytes(buffers.get(process.stdout, b""))
    stderr = bytes(buffers.get(process.stderr, b""))
    selector.close()
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    return stdout, stderr, timed_out, stdout_truncated, stderr_truncated


def run_capture(argv: list[str], *, cwd: Path, timeout: int = 30) -> str:
    process = subprocess.Popen(argv, cwd=cwd, env=git_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    stdout_raw, stderr_raw, timed_out, stdout_truncated, stderr_truncated = read_limited_process_pipes(process, timeout_seconds=timeout, max_output_bytes=MAX_CAPTURE_BYTES)
    stdout = stdout_raw.decode("utf-8", errors="replace")
    stderr = stderr_raw.decode("utf-8", errors="replace")
    if timed_out:
        raise RuntimeError("command timed out")
    if stdout_truncated or stderr_truncated:
        raise RuntimeError("command output exceeded the preflight bound")
    if process.returncode != 0:
        raise RuntimeError(stderr.strip() or stdout.strip() or "command failed")
    return stdout.strip()


def verify_repository(repo: Path, expected_head: str) -> None:
    if not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")
    if repo.is_symlink() or not repo.is_dir():
        raise RuntimeError(f"canonical repository is unavailable: {repo}")
    resolved = repo.resolve(strict=True)
    if resolved != repo:
        raise RuntimeError("canonical repository path must not traverse a symlink")
    git_prefix = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=never", "-C", str(repo)]
    head = run_capture([*git_prefix, "rev-parse", "--verify", "HEAD"], cwd=repo)
    branch = run_capture([*git_prefix, "symbolic-ref", "--short", "HEAD"], cwd=repo)
    origin_main = run_capture([*git_prefix, "rev-parse", "--verify", "refs/remotes/origin/main"], cwd=repo)
    status = run_capture([*git_prefix, "status", "--porcelain=v1", "--untracked-files=normal"], cwd=repo)
    if head != expected_head:
        raise RuntimeError(f"HEAD drift: expected {expected_head}, found {head}")
    if branch != "main":
        raise RuntimeError(f"canonical checkout is not on main: {branch}")
    if origin_main != expected_head:
        raise RuntimeError(f"origin/main drift: expected {expected_head}, found {origin_main}")
    if status:
        raise RuntimeError("canonical checkout is dirty")


def run_streamed(argv: list[str], *, cwd: Path, timeout_seconds: int, phase: str) -> None:
    emit(f"{phase}-start", argv=argv)
    process = subprocess.Popen(argv, cwd=cwd, env=git_environment(), stdin=subprocess.DEVNULL, stdout=None, stderr=None, start_new_session=True)
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        emit(f"{phase}-timeout", timeout_seconds=timeout_seconds)
        raise RuntimeError(f"{phase} timed out")
    emit(f"{phase}-complete", returncode=returncode)
    if returncode != 0:
        raise RuntimeError(f"{phase} failed with return code {returncode}")


def verify_live_manifest(expected_head: str) -> dict[str, Any]:
    manifest = Path.home() / ".local/share/grabowski-mcp/deployment-manifest.json"
    if not manifest.is_file():
        raise RuntimeError("live deployment manifest is missing")
    if manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise RuntimeError("live deployment manifest exceeds its size bound")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if payload.get("repo_head") != expected_head:
        raise RuntimeError("live deployment manifest does not match expected head")
    if payload.get("completion_status") != "complete":
        raise RuntimeError("live deployment is not complete")
    return {"release_id": payload.get("release_id"), "repo_head": payload.get("repo_head"), "completion_status": payload.get("completion_status")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--delay-seconds", type=int, required=True)
    args = parser.parse_args()
    repo = args.repo
    if not 5 <= args.delay_seconds <= 60:
        raise ValueError("delay_seconds must be between 5 and 60")
    try:
        emit("scheduled", repo=str(repo), expected_head=args.expected_head, delay_seconds=args.delay_seconds)
        time.sleep(args.delay_seconds)
        verify_repository(repo, args.expected_head)
        emit("repository-preflight-complete", expected_head=args.expected_head)
        run_streamed(["make", "validate"], cwd=repo, timeout_seconds=1_200, phase="validate")
        verify_repository(repo, args.expected_head)
        run_streamed(["make", "deploy"], cwd=repo, timeout_seconds=1_800, phase="deploy")
        live = verify_live_manifest(args.expected_head)
        emit("complete", **live)
        return 0
    except Exception as exc:
        emit("failed", error_type=type(exc).__name__, error=str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import stat
import sys
from typing import Any

from grabowski_agent_sandbox import minimal_sandbox_argv, prepare_external_agent_command, runtime_sandbox_argv, safe_git_environment, run_bounded_capture

SHA40 = __import__("re").compile(r"^[0-9a-f]{40}$")
LAUNCH_NONCE = __import__("re").compile(r"^[0-9a-f]{24}$")
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        timeout=30,
        check=False,
        env=safe_git_environment(),
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "git failed").strip())
    return completed.stdout.strip()


def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise PermissionError("writer receipt target must be one owner-controlled regular file")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        try:
            handle = os.fdopen(descriptor, "w", encoding="utf-8")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        with handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _allowed_path(repo: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.parts[0] == ".git"
    ):
        raise RuntimeError(f"invalid writer allowed path: {value}")
    target = repo.joinpath(*relative.parts)
    if target.is_symlink() or not target.exists():
        raise RuntimeError(f"writer allowed path must exist and may not be a symlink: {value}")
    resolved = target.resolve(strict=True)
    try:
        resolved.relative_to(repo)
    except ValueError as exc:
        raise RuntimeError(f"writer allowed path escapes worktree: {value}") from exc
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-base-head", required=True)
    parser.add_argument("--expected-branch", required=True)
    parser.add_argument("--allowed-path", action="append", default=[])
    parser.add_argument("--output", required=True)
    parser.add_argument("--launch-nonce")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command or SHA40.fullmatch(args.expected_base_head) is None or not args.allowed_path:
        parser.error("invalid command, base binding or writable scope")
    if args.launch_nonce is not None and LAUNCH_NONCE.fullmatch(args.launch_nonce) is None:
        parser.error("invalid launch nonce")
    repo = Path(args.repository).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    writable_paths = [_allowed_path(repo, item) for item in args.allowed_path]
    before_head = _git(repo, "rev-parse", "HEAD").lower()
    before_branch = _git(repo, "branch", "--show-current")
    before_status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if before_head != args.expected_base_head or before_branch != args.expected_branch or before_status:
        raise RuntimeError("writer worktree does not match its clean base and branch binding")
    common_raw = _git(repo, "rev-parse", "--git-common-dir")
    common = Path(common_raw)
    if not common.is_absolute():
        common = (repo / common).resolve(strict=True)
    prepared = prepare_external_agent_command(command)
    completed = run_bounded_capture(
        runtime_sandbox_argv(
            minimal_sandbox_argv(
                workspace=repo,
                command=list(prepared.command),
                workspace_writable=True,
                writable_paths=writable_paths,
                git_common_dir=common,
                extra_read_only=prepared.extra_read_only,
                extra_directories=prepared.extra_directories,
            )
        ),
        stdout_limit=MAX_OUTPUT_BYTES,
        stderr_limit=MAX_OUTPUT_BYTES,
    )
    payload: dict[str, Any] = {
        "schema_version": 1,
        "role": "writer",
        "expected_base_head": args.expected_base_head,
        "expected_branch": args.expected_branch,
        "allowed_paths": list(args.allowed_path),
        "allowed_paths_sha256": _digest(list(args.allowed_path)),
        "head_before": before_head,
        "branch_before": before_branch,
        "command_sha256": _digest(command),
        "launch_nonce": args.launch_nonce,
        "returncode": completed.returncode,
        "stdout_bytes": completed.stdout_bytes,
        "stderr_bytes": completed.stderr_bytes,
        "stdout_sha256": completed.stdout_sha256,
        "stderr_sha256": completed.stderr_sha256,
        "stdout_tail": completed.stdout_tail,
        "stderr_tail": completed.stderr_tail,
        "sandbox": "bubblewrap-minimal-root-bounded-writable-paths-v1",
        "external_agent_profile": prepared.profile,
        "worktree_scope": str(repo),
        "git_common_dir_mode": "read_only",
        "output_limit_bytes": MAX_OUTPUT_BYTES,
    }
    after_head = _git(repo, "rev-parse", "HEAD").lower()
    after_branch = _git(repo, "branch", "--show-current")
    after_status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    payload.update(
        {
            "head_after": after_head,
            "branch_after": after_branch,
            "dirty_after": bool(after_status),
            "status_after_count": 0 if not after_status else len(after_status.splitlines()),
            "status_after_sha256": hashlib.sha256(
                after_status.encode("utf-8", errors="surrogateescape")
            ).hexdigest(),
        }
    )
    if completed.output_limit_exceeded:
        payload["returncode"] = 124
        payload["error"] = "writer stdout or stderr exceeded the bounded capture limit"
    if after_head != before_head or after_branch != before_branch:
        payload["returncode"] = 125
        payload["error"] = "writer changed Git head or branch despite read-only Git metadata"
    stable = dict(payload)
    payload["receipt_sha256"] = _digest(stable)
    _write_receipt(output, payload)
    if payload["stdout_tail"]:
        print(payload["stdout_tail"], end="" if payload["stdout_tail"].endswith("\n") else "\n")
    if payload["stderr_tail"]:
        print(payload["stderr_tail"], file=sys.stderr, end="" if payload["stderr_tail"].endswith("\n") else "\n")
    return int(payload["returncode"])


if __name__ == "__main__":
    raise SystemExit(main())

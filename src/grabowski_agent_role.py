from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
from typing import Any

from grabowski_agent_sandbox import minimal_sandbox_argv, runtime_sandbox_argv, safe_git_environment, run_bounded_capture

SHA40 = __import__("re").compile(r"^[0-9a-f]{40}$")
SHA256 = __import__("re").compile(r"^[0-9a-f]{64}$")
MAX_ROLE_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_REVIEW_JSON_BYTES = 1024 * 1024
MAX_UNTRACKED_FILE_BYTES = 16 * 1024 * 1024
MAX_UNTRACKED_TOTAL_BYTES = 64 * 1024 * 1024


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        stderr=subprocess.STDOUT,
        timeout=30,
        env=safe_git_environment(),
    )


def git_text(repo: Path, *args: str) -> str:
    return git(repo, *args).decode("utf-8", errors="surrogateescape").strip()


def safe_untracked_file(root: Path, relative: PurePosixPath) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeError(f"unsafe untracked path: {relative}")
    current = root
    for part in relative.parts:
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"untracked path crosses a symlink: {relative}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError(f"untracked path must be one regular non-hardlinked file: {relative}")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"untracked path escapes repository: {relative}") from exc
    return resolved


def current_binding(repo: Path, base: str) -> tuple[str, str, bool]:
    head = git_text(repo, "rev-parse", "HEAD").lower()
    committed = git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", f"{base}...{head}")
    working = git(repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD")
    raw = git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    untracked: list[dict[str, Any]] = []
    dirty = bool(working)
    total = 0
    for raw_relative in [item for item in raw.split(b"\x00") if item]:
        relative = PurePosixPath(os.fsdecode(raw_relative))
        target = safe_untracked_file(repo, relative)
        size = target.stat().st_size
        if size > MAX_UNTRACKED_FILE_BYTES:
            raise RuntimeError(f"untracked file exceeds safety boundary: {relative}")
        total += size
        if total > MAX_UNTRACKED_TOTAL_BYTES:
            raise RuntimeError("untracked files exceed aggregate safety boundary")
        untracked.append(
            {
                "path": relative.as_posix(),
                "size": size,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
        dirty = True
    return head, digest(
        {
            "base_head": base,
            "head": head,
            "branch": git_text(repo, "branch", "--show-current"),
            "committed_diff_sha256": hashlib.sha256(committed).hexdigest(),
            "working_diff_sha256": hashlib.sha256(working).hexdigest(),
            "untracked": untracked,
        }
    ), dirty


def write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise PermissionError("role receipt target must be one owner-controlled regular file")
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


def sandbox_argv(repo: Path, command: list[str]) -> list[str]:
    common_raw = git_text(repo, "rev-parse", "--git-common-dir")
    common = Path(common_raw)
    if not common.is_absolute():
        common = (repo / common).resolve(strict=True)
    return minimal_sandbox_argv(
        workspace=repo,
        command=command,
        workspace_writable=False,
        git_common_dir=common,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("tests", "review"), required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-base-head", required=True)
    parser.add_argument("--expected-diff-sha256", required=True)
    parser.add_argument("--expected-dirty", choices=("true", "false"), required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    repo = Path(args.repository).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    if (
        not command
        or SHA40.fullmatch(args.expected_head) is None
        or SHA40.fullmatch(args.expected_base_head) is None
        or SHA256.fullmatch(args.expected_diff_sha256) is None
    ):
        parser.error("invalid command or binding")
    expected_dirty = args.expected_dirty == "true"
    before_head, before_diff, before_dirty = current_binding(repo, args.expected_base_head)
    if (
        before_head != args.expected_head
        or before_diff != args.expected_diff_sha256
        or before_dirty != expected_dirty
    ):
        raise RuntimeError("writer binding changed before read-only role start")
    completed = run_bounded_capture(
        runtime_sandbox_argv(sandbox_argv(repo, command)),
        stdout_limit=MAX_ROLE_OUTPUT_BYTES,
        stderr_limit=MAX_ROLE_OUTPUT_BYTES,
        stdout_content_limit=MAX_REVIEW_JSON_BYTES if args.role == "review" else 0,
    )
    after_head, after_diff, after_dirty = current_binding(repo, args.expected_base_head)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "role": args.role,
        "expected_head": args.expected_head,
        "expected_base_head": args.expected_base_head,
        "expected_diff_sha256": args.expected_diff_sha256,
        "expected_dirty": expected_dirty,
        "head_before": before_head,
        "head_after": after_head,
        "diff_after": after_diff,
        "worktree_dirty_after": after_dirty,
        "argv_sha256": digest(command),
        "returncode": completed.returncode,
        "stdout_sha256": completed.stdout_sha256,
        "stderr_sha256": completed.stderr_sha256,
        "stdout_bytes": completed.stdout_bytes,
        "stderr_bytes": completed.stderr_bytes,
        "stdout_tail": completed.stdout_tail,
        "stderr_tail": completed.stderr_tail,
        "output_limit_bytes": MAX_ROLE_OUTPUT_BYTES,
        "sandbox": "bubblewrap-minimal-root-read-only-worktree-v1",
    }
    if completed.output_limit_exceeded:
        payload["returncode"] = 124
        payload["error"] = "role stdout or stderr exceeded the bounded capture limit"
    if after_head != before_head or after_diff != before_diff or after_dirty != before_dirty:
        payload["returncode"] = 125
        payload["error"] = "read-only role observed writer mutation"
    if args.role == "review":
        review_stdout: str | None = None
        review_decode_error: str | None = None
        if completed.stdout_content_exceeded or completed.stdout_content is None:
            review_decode_error = f"review stdout exceeds {MAX_REVIEW_JSON_BYTES} bytes"
        else:
            try:
                review_stdout = completed.stdout_content.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                review_decode_error = str(exc)
        if review_decode_error is not None or review_stdout is None:
            payload["returncode"] = 126
            payload["verdict"] = "INVALID"
            payload["findings"] = []
            payload["error"] = f"review stdout is unavailable: {review_decode_error}"
        else:
            try:
                review = json.loads(review_stdout)
            except json.JSONDecodeError as exc:
                payload["returncode"] = 126
                payload["verdict"] = "INVALID"
                payload["findings"] = []
                payload["error"] = f"review stdout is not one JSON object: {exc}"
            else:
                verdict = review.get("verdict") if isinstance(review, dict) else None
                findings = review.get("findings") if isinstance(review, dict) else None
                if (
                    verdict not in {"PASS", "NEEDS_CHANGE", "BLOCK"}
                    or not isinstance(findings, list)
                    or any(not isinstance(item, dict) for item in findings)
                ):
                    payload["returncode"] = 126
                    payload["verdict"] = "INVALID"
                    payload["findings"] = []
                    payload["error"] = "review object must contain verdict and object findings"
                else:
                    payload["verdict"] = verdict
                    payload["findings"] = findings
                    if verdict == "PASS" and findings:
                        payload["returncode"] = 126
                        payload["error"] = "PASS review may not contain findings"
                    elif verdict != "PASS" and not findings:
                        payload["returncode"] = 126
                        payload["error"] = "non-PASS review must contain findings"
    stable = dict(payload)
    payload["receipt_sha256"] = digest(stable)
    write_receipt(output, payload)
    return int(payload["returncode"])


if __name__ == "__main__":
    raise SystemExit(main())

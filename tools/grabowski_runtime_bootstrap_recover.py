#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Iterator


ACTION = "runtime_bootstrap_recover"
TARGET_RUNTIME = "heim-pc"
SCHEMA_VERSION = 1
REFERENCE_TTL_SECONDS = 900
DEFAULT_SOCKET = Path("/run/grabowski/privileged-broker.sock")
CANONICAL_REPOSITORY = Path("/home/alex/repos/grabowski")
CANONICAL_ORIGIN_URL = "git@github.com:heimgewebe/grabowski.git"
RECOVERY_WORKTREE_ROOT = Path("/home/alex/repos/.grabowski-deploy-worktrees")
RUNTIME_MANIFEST = Path("/home/alex/.local/share/grabowski-mcp/deployment-manifest.json")
SCHEDULE_LOCK = Path("/home/alex/.local/state/grabowski/runtime-deploy-schedule.lock")
ROOT_HELPER = Path("/usr/local/libexec/grabowski-runtime-bootstrap-recover")
ROOT_KILL_SWITCH = Path("/var/lib/grabowski/operator-blockade/operator-kill-switch")
LEGACY_KILL_SWITCH = Path("/home/alex/.local/state/grabowski/operator-kill-switch")
DEPLOY_UID = 1000
DEPLOY_GID = 1000
DEPLOY_HOME = Path("/home/alex")
DEPLOY_RUNTIME_DIR = Path("/run/user/1000")
DEPLOY_USER_BUS = "unix:path=/run/user/1000/bus"
MAX_RESPONSE_BYTES = 512 * 1024
MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
GIT_TIMEOUT_SECONDS = 20
DEPLOY_TIMEOUT_SECONDS = 3540
SCHEDULE_LOCK_TIMEOUT_SECONDS = 10.0
SCHEDULE_LOCK_POLL_SECONDS = 0.05
_HEAD_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_EXECUTION_ID_RE = re.compile(r"[0-9a-f]{24}\Z")
SAFE_ROOT_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
SAFE_USER_ENV = {
    "PATH": "/home/alex/.local/bin:/usr/local/bin:/usr/bin:/bin",
    "HOME": str(DEPLOY_HOME),
    "XDG_RUNTIME_DIR": str(DEPLOY_RUNTIME_DIR),
    "DBUS_SESSION_BUS_ADDRESS": DEPLOY_USER_BUS,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


class BootstrapRecoveryError(RuntimeError):
    pass


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _validate_head(value: Any) -> str:
    if not isinstance(value, str) or _HEAD_RE.fullmatch(value) is None:
        raise BootstrapRecoveryError("expected_head must be a lowercase Git object ID")
    return value


def _bounded_output(raw: bytes) -> tuple[str, bool]:
    truncated = len(raw) > MAX_COMMAND_OUTPUT_BYTES
    selected = raw[:MAX_COMMAND_OUTPUT_BYTES]
    return selected.decode("utf-8", errors="replace"), truncated


def _command_result(
    argv: list[str],
    *,
    cwd: Path | str = "/",
    env: dict[str, str],
    timeout_seconds: int,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        argv,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
        env=env,
    )
    if completed.returncode not in accepted_returncodes:
        stderr = completed.stderr[:MAX_COMMAND_OUTPUT_BYTES]
        raise BootstrapRecoveryError(
            "command failed: "
            f"argv_sha256={hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest()} "
            f"returncode={completed.returncode} "
            f"stderr_sha256={hashlib.sha256(stderr).hexdigest()}"
        )
    return completed


def _git(
    repository: Path,
    *arguments: str,
    accepted_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[bytes]:
    return _command_result(
        [
            "/usr/bin/git",
            "-c",
            f"safe.directory={repository}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.file.allow=never",
            "-C",
            str(repository),
            *arguments,
        ],
        env=SAFE_USER_ENV,
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        accepted_returncodes=accepted_returncodes,
    )


def _stdout_text(completed: subprocess.CompletedProcess[bytes]) -> str:
    try:
        return completed.stdout.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise BootstrapRecoveryError("command output is not UTF-8") from exc


def _safe_user_directory(path: Path, *, require_private: bool = False) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BootstrapRecoveryError(f"required directory is unavailable: {path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise BootstrapRecoveryError(f"required path is not a safe directory: {path}")
    if metadata.st_uid != DEPLOY_UID or metadata.st_mode & 0o022:
        raise BootstrapRecoveryError(f"directory owner or mode is unsafe: {path}")
    if require_private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise BootstrapRecoveryError(f"directory must be private: {path}")
    return path.resolve(strict=True)


def _ensure_recovery_worktree_root() -> Path:
    _safe_user_directory(RECOVERY_WORKTREE_ROOT.parent)
    try:
        RECOVERY_WORKTREE_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    root = _safe_user_directory(RECOVERY_WORKTREE_ROOT, require_private=True)
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        os.chmod(root, 0o700)
    return root


def _canonical_repo_evidence(expected_head: str) -> dict[str, str]:
    repository = _safe_user_directory(CANONICAL_REPOSITORY)
    common_raw = _stdout_text(_git(repository, "rev-parse", "--git-common-dir"))
    common_candidate = Path(common_raw)
    if not common_candidate.is_absolute():
        common_candidate = repository / common_candidate
    try:
        common = common_candidate.resolve(strict=True)
    except OSError as exc:
        raise BootstrapRecoveryError("canonical Git common directory is unavailable") from exc
    expected_common = (repository / ".git").resolve(strict=True)
    if common != expected_common:
        raise BootstrapRecoveryError("canonical Git common directory is unexpected")
    origin = _stdout_text(_git(repository, "config", "--get", "remote.origin.url"))
    if origin != CANONICAL_ORIGIN_URL:
        raise BootstrapRecoveryError("canonical origin URL does not match recovery contract")
    origin_main = _stdout_text(
        _git(repository, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    )
    if origin_main != expected_head:
        raise BootstrapRecoveryError("origin/main differs from expected_head")
    _git(repository, "cat-file", "-e", f"{expected_head}^{{commit}}")
    status = _stdout_text(
        _git(repository, "status", "--porcelain=v1", "--untracked-files=normal")
    )
    if status:
        raise BootstrapRecoveryError("canonical repository is dirty")
    filters = _git(
        repository,
        "config",
        "--local",
        "--get-regexp",
        r"^filter\..*\.(clean|smudge|process)$",
        accepted_returncodes=(0, 1),
    )
    filter_text = _stdout_text(filters)
    if filters.returncode == 0 and filter_text:
        raise BootstrapRecoveryError("external Git clean/smudge/process filters are configured")
    return {
        "repository": str(repository),
        "git_common_directory": str(common),
        "origin_main": origin_main,
        "origin_url": origin,
    }


def _validate_recovery_worktree(
    path: Path,
    *,
    expected_head: str,
    expected_common: Path,
) -> None:
    worktree = _safe_user_directory(path, require_private=True)
    head = _stdout_text(_git(worktree, "rev-parse", "--verify", "HEAD^{commit}"))
    if head != expected_head:
        raise BootstrapRecoveryError("recovery worktree HEAD differs from expected_head")
    branch = _git(
        worktree,
        "symbolic-ref",
        "-q",
        "HEAD",
        accepted_returncodes=(0, 1),
    )
    if branch.returncode == 0:
        raise BootstrapRecoveryError("recovery worktree must remain detached")
    common_raw = _stdout_text(_git(worktree, "rev-parse", "--git-common-dir"))
    common_candidate = Path(common_raw)
    if not common_candidate.is_absolute():
        common_candidate = worktree / common_candidate
    try:
        common = common_candidate.resolve(strict=True)
    except OSError as exc:
        raise BootstrapRecoveryError("recovery worktree common directory is unavailable") from exc
    if common != expected_common:
        raise BootstrapRecoveryError("recovery worktree escaped canonical Git metadata")
    origin_main = _stdout_text(
        _git(worktree, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    )
    if origin_main != expected_head:
        raise BootstrapRecoveryError("recovery worktree origin/main differs from expected_head")
    origin = _stdout_text(_git(worktree, "config", "--get", "remote.origin.url"))
    if origin != CANONICAL_ORIGIN_URL:
        raise BootstrapRecoveryError("recovery worktree origin URL is unexpected")
    status = _stdout_text(
        _git(worktree, "status", "--porcelain=v1", "--untracked-files=normal")
    )
    if status:
        raise BootstrapRecoveryError("recovery worktree is dirty")


def _runtime_manifest_readback(expected_head: str) -> dict[str, Any]:
    try:
        resolved = RUNTIME_MANIFEST.resolve(strict=True)
        metadata = resolved.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != DEPLOY_UID
            or metadata.st_mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > 2 * 1024 * 1024
        ):
            raise BootstrapRecoveryError("runtime deployment manifest identity is unsafe")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapRecoveryError("runtime deployment manifest is unavailable") from exc
    if not isinstance(value, dict):
        raise BootstrapRecoveryError("runtime deployment manifest is invalid")
    if value.get("completion_status") != "complete":
        raise BootstrapRecoveryError("runtime deployment manifest is incomplete")
    if value.get("repo_head") != expected_head:
        raise BootstrapRecoveryError("runtime deployment manifest is not bound to expected_head")
    release_id = value.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise BootstrapRecoveryError("runtime deployment manifest release_id is invalid")
    return {
        "repo_head": expected_head,
        "release_id": release_id,
        "manifest_sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


@contextmanager
def _schedule_lock() -> Iterator[None]:
    parent = _safe_user_directory(SCHEDULE_LOCK.parent, require_private=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent / SCHEDULE_LOCK.name, flags, 0o600)
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != DEPLOY_UID
            or metadata.st_nlink != 1
        ):
            raise BootstrapRecoveryError("runtime deploy schedule lock identity is unsafe")
        os.fchmod(descriptor, 0o600)
        deadline = time.monotonic() + SCHEDULE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BootstrapRecoveryError(
                        "runtime deploy schedule lock is held by another deployment"
                    ) from exc
                time.sleep(min(SCHEDULE_LOCK_POLL_SECONDS, remaining))
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _create_recovery_worktree(expected_head: str, execution_id: str) -> tuple[Path, Path]:
    if _EXECUTION_ID_RE.fullmatch(execution_id) is None:
        raise BootstrapRecoveryError("recovery execution_id is invalid")
    evidence = _canonical_repo_evidence(expected_head)
    expected_common = Path(evidence["git_common_directory"])
    root = _ensure_recovery_worktree_root()
    path = root / f"runtime-bootstrap-{expected_head[:12]}-{execution_id}"
    if os.path.lexists(path):
        raise BootstrapRecoveryError("recovery worktree path already exists")
    _git(CANONICAL_REPOSITORY, "worktree", "add", "--detach", str(path), expected_head)
    os.chmod(path, 0o700)
    try:
        _validate_recovery_worktree(
            path,
            expected_head=expected_head,
            expected_common=expected_common,
        )
    except BaseException:
        # Preserve ambiguous or invalid bootstrap worktrees for inspection. A
        # recovery path must never force-remove state whose exact contents are
        # not yet trusted.
        raise
    return path, expected_common


def _deploy_exact(worktree: Path, expected_head: str) -> dict[str, Any]:
    _command_result(
        ["/usr/bin/make", "-C", str(worktree), "context-check", "deploy-tooling"],
        env=SAFE_USER_ENV,
        timeout_seconds=600,
    )
    deploy_python = worktree / "build/deploy-tooling/.venv/bin/python"
    deploy_script = worktree / "tools/deploy_runtime_dual.py"
    if not deploy_python.exists() or not os.access(deploy_python, os.X_OK):
        raise BootstrapRecoveryError("deploy tooling Python is unavailable")
    if deploy_script.is_symlink() or not deploy_script.is_file():
        raise BootstrapRecoveryError("dual deploy engine is unavailable")
    completed = _command_result(
        [
            str(deploy_python),
            str(deploy_script),
            "--repo",
            str(worktree),
            "--apply",
            "--bootstrap-recovery",
            "--expected-head",
            expected_head,
        ],
        cwd=worktree,
        env=SAFE_USER_ENV,
        timeout_seconds=DEPLOY_TIMEOUT_SECONDS,
    )
    return {
        "returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stdout_truncated": len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES,
        "stderr_truncated": len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES,
    }


def user_execute(expected_head: str, execution_id: str) -> dict[str, Any]:
    if os.geteuid() != DEPLOY_UID or os.getegid() != DEPLOY_GID:
        raise BootstrapRecoveryError("user-execute must run as the configured deploy UID/GID")
    expected = _validate_head(expected_head)
    _require_kill_switch_clear()
    with _schedule_lock():
        worktree, common = _create_recovery_worktree(expected, execution_id)
        deployment_started = False
        cleanup = "retained"
        try:
            _validate_recovery_worktree(
                worktree,
                expected_head=expected,
                expected_common=common,
            )
            _require_kill_switch_clear()
            deployment_started = True
            deploy = _deploy_exact(worktree, expected)
            _validate_recovery_worktree(
                worktree,
                expected_head=expected,
                expected_common=common,
            )
            manifest = _runtime_manifest_readback(expected)
            remove = _git(
                CANONICAL_REPOSITORY,
                "worktree",
                "remove",
                str(worktree),
                accepted_returncodes=(0, 1),
            )
            if remove.returncode == 0 and not os.path.lexists(worktree):
                cleanup = "removed"
            else:
                cleanup = "retained-clean"
            return {
                "schema_version": 1,
                "state": "completed",
                "expected_head": expected,
                "worktree_cleanup": cleanup,
                "deploy": deploy,
                "runtime": manifest,
            }
        except BaseException:
            if deployment_started:
                # Once the deploy command has started, retain the exact source
                # checkout on every non-proven-success path for forensic readback.
                pass
            raise


def _parse_target(raw: str) -> dict[str, str | int]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BootstrapRecoveryError("bootstrap target is not valid JSON") from exc
    required = {"schema_version", "expected_head", "target_runtime"}
    if not isinstance(value, dict) or set(value) != required:
        raise BootstrapRecoveryError("bootstrap target contract is invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise BootstrapRecoveryError("bootstrap target schema is unsupported")
    if value.get("target_runtime") != TARGET_RUNTIME:
        raise BootstrapRecoveryError("bootstrap target_runtime is not allowed")
    return {
        "schema_version": SCHEMA_VERSION,
        "expected_head": _validate_head(value.get("expected_head")),
        "target_runtime": TARGET_RUNTIME,
    }


def _require_root_helper_identity() -> None:
    try:
        metadata = ROOT_HELPER.lstat()
    except OSError as exc:
        raise BootstrapRecoveryError("installed bootstrap helper is unavailable") from exc
    if (
        ROOT_HELPER.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or metadata.st_nlink != 1
        or not metadata.st_mode & 0o111
    ):
        raise BootstrapRecoveryError("installed bootstrap helper identity is unsafe")


def _marker_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise BootstrapRecoveryError(
            "runtime bootstrap kill-switch state is unreadable"
        ) from exc
    return True


def _require_kill_switch_clear() -> None:
    if _marker_present(ROOT_KILL_SWITCH) or _marker_present(LEGACY_KILL_SWITCH):
        raise BootstrapRecoveryError(
            "runtime bootstrap recovery is blocked by the operator kill switch"
        )


def _root_systemd_argv(expected_head: str, execution_id: str) -> list[str]:
    expected = _validate_head(expected_head)
    if _EXECUTION_ID_RE.fullmatch(execution_id) is None:
        raise BootstrapRecoveryError("recovery execution_id is invalid")
    unit = f"grabowski-runtime-bootstrap-{expected[:12]}-{execution_id}.service"
    return [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--pipe",
        "--quiet",
        "--collect",
        "--description=Grabowski exact runtime bootstrap recovery",
        "--unit",
        unit,
        f"--uid={DEPLOY_UID}",
        f"--gid={DEPLOY_GID}",
        f"--working-directory={DEPLOY_HOME}",
        f"--setenv=HOME={DEPLOY_HOME}",
        f"--setenv=XDG_RUNTIME_DIR={DEPLOY_RUNTIME_DIR}",
        f"--setenv=DBUS_SESSION_BUS_ADDRESS={DEPLOY_USER_BUS}",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=30s",
        "--property=RuntimeMaxSec=3500s",
        "--property=LimitCORE=0",
        "--property=NoNewPrivileges=yes",
        "--property=UMask=0077",
        "--",
        str(ROOT_HELPER),
        "user-execute",
        "--expected-head",
        expected,
        "--execution-id",
        execution_id,
    ]


def _single_json_stdout(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BootstrapRecoveryError("bootstrap child output is not UTF-8 JSON") from exc
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise BootstrapRecoveryError("bootstrap child output is not one JSON result")
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise BootstrapRecoveryError("bootstrap child output is not valid JSON") from exc
    if not isinstance(value, dict):
        raise BootstrapRecoveryError("bootstrap child result must be a JSON object")
    return value


def root_execute(target_raw: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise BootstrapRecoveryError("root-execute requires the root-owned broker")
    target = _parse_target(target_raw)
    _require_root_helper_identity()
    _require_kill_switch_clear()
    execution_id = secrets.token_hex(12)
    argv = _root_systemd_argv(str(target["expected_head"]), execution_id)
    _require_kill_switch_clear()
    completed = subprocess.run(
        argv,
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=DEPLOY_TIMEOUT_SECONDS,
        check=False,
        env=SAFE_ROOT_ENV,
    )
    if completed.returncode != 0:
        raise BootstrapRecoveryError(
            "bootstrap deploy unit failed: "
            f"returncode={completed.returncode} "
            f"stdout_sha256={hashlib.sha256(completed.stdout).hexdigest()} "
            f"stderr_sha256={hashlib.sha256(completed.stderr).hexdigest()}"
        )
    user_result = _single_json_stdout(completed.stdout)
    if (
        user_result.get("state") != "completed"
        or user_result.get("expected_head") != target["expected_head"]
    ):
        raise BootstrapRecoveryError("bootstrap child result is not bound to expected_head")
    return {
        "schema_version": 1,
        "state": "completed",
        "expected_head": target["expected_head"],
        "target_runtime": TARGET_RUNTIME,
        "execution_id": execution_id,
        "systemd_returncode": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stdout_truncated": len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES,
        "stderr_truncated": len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES,
        "user_result": user_result,
    }


def create_reference(expected_head: str, *, now_unix: int | None = None) -> dict[str, Any]:
    expected = _validate_head(expected_head)
    created_at = int(time.time()) if now_unix is None else now_unix
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 0:
        raise BootstrapRecoveryError("reference timestamp is invalid")
    request_id = secrets.token_hex(16)
    if _REQUEST_ID_RE.fullmatch(request_id) is None:
        raise BootstrapRecoveryError("reference request_id generation failed")
    target = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "expected_head": expected,
            "target_runtime": TARGET_RUNTIME,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    reference: dict[str, Any] = {
        "schema_version": 1,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_privileged_agent": True,
        "replay_policy": "single-use-external-broker",
        "action": ACTION,
        "target": target,
        "justification": "Recover the exact canonical Grabowski runtime from origin/main",
        "request_id": request_id,
        "created_at_unix": created_at,
        "expires_at_unix": created_at + REFERENCE_TTL_SECONDS,
    }
    reference["reference_sha256"] = _canonical_sha256(reference)
    return reference


def submit_reference(
    expected_head: str,
    *,
    socket_path: Path = DEFAULT_SOCKET,
) -> dict[str, Any]:
    reference = create_reference(expected_head)
    payload = (json.dumps(reference, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3660)
        client.connect(os.fspath(socket_path))
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = client.recv(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise BootstrapRecoveryError("broker response exceeds output limit")
            chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapRecoveryError("broker response is not valid UTF-8 JSON") from exc
    if not isinstance(response, dict):
        raise BootstrapRecoveryError("broker response must be a JSON object")
    return response


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bootstrap one exact Grabowski runtime without importing the active release."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    request = subparsers.add_parser("request")
    request.add_argument("--expected-head", required=True)
    request.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    root = subparsers.add_parser("root-execute")
    root.add_argument("target_json")
    user = subparsers.add_parser("user-execute")
    user.add_argument("--expected-head", required=True)
    user.add_argument("--execution-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "request":
            result = submit_reference(args.expected_head, socket_path=args.socket)
        elif args.command == "root-execute":
            result = root_execute(args.target_json)
        elif args.command == "user-execute":
            result = user_execute(args.expected_head, args.execution_id)
        else:  # pragma: no cover - argparse owns this boundary
            raise BootstrapRecoveryError("unsupported bootstrap recovery command")
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        if args.command == "request":
            broker_code = result.get("returncode")
            return 0 if broker_code == 0 else 1
        return 0
    except BootstrapRecoveryError as exc:
        print(
            json.dumps(
                {"schema_version": 1, "state": "error", "reason": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {"schema_version": 1, "state": "error", "reason": type(exc).__name__},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

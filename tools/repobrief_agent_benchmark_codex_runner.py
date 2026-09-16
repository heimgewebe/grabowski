#!/usr/bin/env python3
"""Fail-closed Codex runner for RepoBrief Agent Benchmark v1.

The runner is intentionally separate from the Claude runner.  It reuses only
provider-neutral request/receipt helpers, binds one exact Codex execution
contract, persists raw provider stdout/stderr *before* interpreting either
stream, and classifies stderr through an explicit policy.

A live provider call requires ``--allow-live-provider`` plus an absolute,
SHA-256-bound Codex executable.  Synthetic fixtures never authorize a provider
call and are the supported way to qualify the contract before a one-shot run.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import selectors
import signal
import shlex
import shutil
import stat
import subprocess
import tempfile
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any

BASE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_runner.py")
_spec = importlib.util.spec_from_file_location("repobrief_agent_benchmark_base", BASE_PATH)
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load RepoBrief benchmark base helpers")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

PROVIDER = "openai-codex-cli"
MODEL = "gpt-5.3-codex-spark"
EXECUTION_CONTRACT = "grabowski-codex-cli-live-v1"
SAMPLING = {"reasoning_effort": "medium"}
STDERR_POLICY_VERSION = "codex-stderr-v1"
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_PROVIDER_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_AUTH_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
PERMISSION_PROFILE = "rab-benchmark"
CHATGPT_LOGIN_LINE = "Logged in using ChatGPT"
ALLOWED_MCP = {"ask_context", "grounding_verify", "live_freshness", "repobrief_resource_read"}
UPSTREAM_MCP = {"ask_context", "grounding_verify", "live_freshness"}
MCP_CLIENT_METHODS = {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call"}
MAX_FROZEN_RESOURCES = 512

# Exact benign stderr qualified on 2026-09-15 against the current standalone
# Codex CLI and OpenAI's arg0 implementation.  The upstream implementation
# deliberately warns and continues when helper PATH-alias creation fails.  Keep
# this exact: broader warning families remain unqualified and fail closed.
# Source: https://github.com/openai/codex/blob/main/codex-rs/arg0/src/lib.rs
QUALIFIED_BENIGN_STDERR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"WARNING: proceeding, even though we could not create PATH aliases: "
        r"Read-only file system \(os error 30\)"
    ),
)

RunnerError = base.RunnerError


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def validate_request(request: Mapping[str, Any]) -> None:
    """Validate provider-neutral invariants, then bind the exact Codex contract."""

    shadow = json.loads(json.dumps(request))
    shadow["runner"] = {
        "execution_contract": base.EXECUTION_CONTRACT,
        "provider": base.PROVIDER,
        "model": "claude-haiku-4-5-20251001",
        "sampling": {},
    }
    base.validate_request(shadow)
    expected = {
        "execution_contract": EXECUTION_CONTRACT,
        "provider": PROVIDER,
        "model": MODEL,
        "sampling": SAMPLING,
    }
    if request.get("runner") != expected:
        raise RunnerError("Codex runner contract mismatch")


def validate_executable(
    path_text: str, expected_sha256: str, *, require_read_only_mount: bool = False
) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise RunnerError("codex command SHA-256 is invalid")
    path = Path(path_text)
    if not path.is_absolute():
        raise RunnerError("Codex executable path must be absolute")
    try:
        source_metadata = path.lstat()
        if stat.S_ISLNK(source_metadata.st_mode):
            raise RunnerError("Codex executable path must not be a symlink")
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except RunnerError:
        raise
    except OSError as exc:
        raise RunnerError("Codex executable unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise RunnerError("Codex executable must resolve to a regular file")
    if (
        metadata.st_size <= 0
        or metadata.st_size > MAX_PROVIDER_EXECUTABLE_BYTES
        or metadata.st_mode & 0o111 == 0
    ):
        raise RunnerError("Codex executable metadata invalid")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise RunnerError("Codex executable could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    try:
        after = resolved.lstat()
    except OSError as exc:
        raise RunnerError("Codex executable disappeared during validation") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or digest.hexdigest() != expected_sha256
    ):
        raise RunnerError("Codex executable changed or SHA-256 mismatched")
    if require_read_only_mount:
        try:
            mount_flags = os.statvfs(resolved).f_flag
        except OSError as exc:
            raise RunnerError("Codex executable filesystem could not be verified") from exc
        if not (mount_flags & getattr(os, "ST_RDONLY", 1)):
            raise RunnerError(
                "live Codex executable must reside on a read-only filesystem"
            )
    return str(resolved)


def _validate_support_executable(
    path: Path, *, owner_uid: int | None = None, require_read_only_mount: bool = False
) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerError(f"required Codex support executable is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RunnerError(f"required Codex support executable is unsafe: {path}")
    if metadata.st_mode & 0o111 == 0 or metadata.st_mode & 0o022:
        raise RunnerError(f"required Codex support executable permissions are unsafe: {path}")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise RunnerError(f"required Codex support executable owner is unsafe: {path}")
    if require_read_only_mount and not (os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1)):
        raise RunnerError(f"required Codex support executable is not read-only: {path}")
    return str(path)


def validate_toolchain(codex: str) -> str:
    bundled_rg = Path(codex).parent.parent / "codex-path" / "rg"
    _validate_support_executable(bundled_rg, require_read_only_mount=True)
    for path in (Path("/usr/bin/cat"), Path("/usr/bin/sed"), Path("/usr/bin/bash")):
        _validate_support_executable(path, owner_uid=0)
    return f"{bundled_rg.parent}:/usr/bin:/bin"


def provider_env(
    *, codex: str | None = None, codex_home: Path | None = None
) -> dict[str, str]:
    keep = {"HOME", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR"}
    environment = {key: value for key, value in os.environ.items() if key in keep}
    environment["PATH"] = validate_toolchain(codex) if codex is not None else "/usr/bin:/bin"
    if codex_home is not None:
        environment["CODEX_HOME"] = str(codex_home)
    for key in (
        "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
        "XAI_API_KEY", "CODEX_ACCESS_TOKEN",
    ):
        environment.pop(key, None)
    return environment


def _read_chatgpt_auth_file(home: Path) -> bytes:
    path = home / ".codex" / "auth.json"
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError("Codex ChatGPT auth file is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError("Codex ChatGPT auth file must be a regular non-symlink file")
    if linked.st_uid != os.geteuid() or linked.st_mode & 0o077:
        raise RunnerError("Codex ChatGPT auth file permissions are unsafe")
    if linked.st_size <= 0 or linked.st_size > MAX_AUTH_BYTES:
        raise RunnerError("Codex ChatGPT auth file size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunnerError("Codex ChatGPT auth file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = b""
        while len(data) <= MAX_AUTH_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_AUTH_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise RunnerError("Codex ChatGPT auth file disappeared during validation") from exc
    initial_identity = (linked.st_dev, linked.st_ino, linked.st_size, linked.st_mode, linked.st_uid)
    opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode, opened.st_uid)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid)
    if initial_identity != opened_identity or opened_identity != after_identity:
        raise RunnerError("Codex ChatGPT auth file changed during validation")
    if len(data) != opened.st_size or len(data) > MAX_AUTH_BYTES:
        raise RunnerError("Codex ChatGPT auth file changed or exceeds its bound")
    return data


def _read_bound_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    if not path.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if linked.st_size < 0 or linked.st_size > max_bytes:
        raise RunnerError(f"{label} size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunnerError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} disappeared during validation") from exc
    initial_identity = (linked.st_dev, linked.st_ino, linked.st_size, linked.st_mode)
    opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
    if initial_identity != opened_identity or opened_identity != after_identity:
        raise RunnerError(f"{label} changed during validation")
    if len(data) != opened.st_size or len(data) > max_bytes:
        raise RunnerError(f"{label} changed or exceeds its bound")
    return bytes(data)


def validate_chatgpt_subscription(codex: str) -> bytes:
    environment = provider_env(codex=codex)
    try:
        completed = subprocess.run(
            [codex, "login", "status"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            shell=False, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError("Codex ChatGPT login status could not be verified") from exc
    try:
        text = completed.stdout.decode("utf-8") + "\n" + completed.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunnerError("Codex ChatGPT login status was not UTF-8") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    status_lines = [line for line in lines if not any(
        pattern.fullmatch(line) for pattern in QUALIFIED_BENIGN_STDERR_PATTERNS
    )]
    if completed.returncode != 0 or status_lines != [CHATGPT_LOGIN_LINE]:
        raise RunnerError("Codex must be logged in using the ChatGPT subscription")
    home_text = environment.get("HOME")
    if not home_text or not Path(home_text).is_absolute():
        raise RunnerError("HOME is unavailable for Codex ChatGPT authentication")
    return _read_chatgpt_auth_file(Path(home_text))


def stage_codex_home(state_root: Path, auth_data: bytes) -> Path:
    parent_path, parent_fd = _open_private_directory(state_root / "codex-runtime")
    child_fd: int | None = None
    runtime_name: str | None = None
    try:
        for _attempt in range(4):
            candidate = "session-" + sha_bytes(os.urandom(32))[:24]
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            runtime_name = candidate
            break
        if runtime_name is None:
            raise RunnerError("could not allocate unique Codex runtime home")
        child_fd = os.open(runtime_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        child = os.fstat(child_fd)
        if child.st_uid != os.geteuid() or stat.S_IMODE(child.st_mode) != 0o700:
            raise RunnerError("Codex runtime home permissions are unsafe")
        _write_private_dirfd(child_fd, "auth.json", auth_data)
        _directory_fd_matches(parent_path, parent_fd)
        os.fsync(parent_fd)
        return parent_path / runtime_name
    except BaseException:
        if child_fd is not None:
            try:
                os.unlink("auth.json", dir_fd=child_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if runtime_name is not None:
            try:
                os.rmdir(runtime_name, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        raise
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)


def cleanup_codex_home(path: Path) -> str | None:
    try:
        shutil.rmtree(path)
    except OSError as exc:
        return type(exc).__name__
    return None


def _validated_live_mode(
    *,
    stream_fixture: Path | None,
    stderr_fixture: Path | None,
    fixture_returncode: int,
    allow_live_provider: bool,
    codex_command_sha256: str | None,
) -> None:
    if stream_fixture is not None:
        if allow_live_provider or codex_command_sha256 is not None:
            raise RunnerError("synthetic fixture must not carry live-provider authorization")
        return
    if stderr_fixture is not None or fixture_returncode != 0:
        raise RunnerError("live execution must not carry synthetic fixture controls")
    if not allow_live_provider:
        raise RunnerError("live execution requires explicit allow_live_provider")
    if codex_command_sha256 is None:
        raise RunnerError("live execution requires codex_command_sha256")


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)

def _open_private_directory(path: Path, *, create_final: bool = True) -> tuple[Path, int]:
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise RunnerError("private output directory must be an absolute normalized path")
    parts = path.parts
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for index, component in enumerate(parts[1:], start=1):
            final = index == len(parts) - 1
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not final or not create_final:
                    raise RunnerError("private output directory parent is unavailable")
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise RunnerError("private output directory contains an unsafe component") from exc
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise RunnerError("private output directory ownership is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_nlink < 1:
            raise RunnerError("private output directory permissions are unsafe")
        return path, descriptor
    except BaseException:
        os.close(descriptor)
        raise

def _directory_fd_matches(path: Path, descriptor: int) -> None:
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError("private output directory identity disappeared") from exc
    opened = os.fstat(descriptor)
    if stat.S_ISLNK(linked.st_mode) or (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid) != (linked.st_dev, linked.st_ino, linked.st_mode, linked.st_uid):
        raise RunnerError("private output directory identity changed")

def _write_private_dirfd(descriptor: int, name: str, data: bytes) -> None:
    if Path(name).name != name or not name:
        raise RunnerError("private artifact name is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(name, flags, 0o600, dir_fd=descriptor)
    except FileExistsError as exc:
        raise RunnerError("provider evidence artifact already exists") from exc
    write_error: BaseException | None = None
    try:
        view = memoryview(data)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError("short private artifact write")
            view = view[written:]
        os.fsync(file_descriptor)
    except BaseException as exc:
        write_error = exc
        try:
            os.fsync(file_descriptor)
        except OSError:
            pass
    finally:
        os.close(file_descriptor)
    try:
        os.fsync(descriptor)
    except OSError:
        if write_error is None:
            raise
    if write_error is not None:
        raise write_error


def _assert_absent(descriptor: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise RunnerError("provider evidence artifact already exists")

def prepare_provider_evidence(request: Mapping[str, Any], transcript_root: Path, evidence_root: Path) -> dict[str, Any]:
    names = _provider_artifact_names(request)
    transcript_path, transcript_fd = _open_private_directory(transcript_root)
    try:
        evidence_path, evidence_fd = _open_private_directory(evidence_root)
    except BaseException:
        os.close(transcript_fd)
        raise
    try:
        _directory_fd_matches(transcript_path, transcript_fd)
        _directory_fd_matches(evidence_path, evidence_fd)
        _assert_absent(transcript_fd, names["stdout"])
        for key in ("stderr", "diagnostics", "stderr_policy"):
            _assert_absent(evidence_fd, names[key])
        return {"names": names, "transcript_root": transcript_path, "evidence_root": evidence_path, "transcript_fd": transcript_fd, "evidence_fd": evidence_fd}
    except BaseException:
        os.close(transcript_fd); os.close(evidence_fd)
        raise

def close_provider_evidence_plan(plan: Mapping[str, Any]) -> None:
    for key in ("transcript_fd", "evidence_fd"):
        try:
            os.close(int(plan[key]))
        except OSError:
            pass


def create_checkout(request: Mapping[str, Any], source: Path, state_root: Path) -> Path:
    workspace_id = str(request["workspace_id"])
    workspace_name = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
    parent_path, parent_fd = _open_private_directory(state_root / "codex-workspaces")
    try:
        try:
            os.mkdir(workspace_name, 0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise RunnerError("Codex workspace identity was already used") from exc
        child_fd = os.open(workspace_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            child = os.fstat(child_fd)
            if child.st_uid != os.geteuid() or stat.S_IMODE(child.st_mode) != 0o700:
                raise RunnerError("Codex workspace directory is unsafe")
        finally:
            os.close(child_fd)
        os.fsync(parent_fd)
        _directory_fd_matches(parent_path, parent_fd)
    finally:
        os.close(parent_fd)
    workspace = parent_path / workspace_name
    checkout = workspace / "repo"
    commit = str(request["repository"]["commit"])
    base._run_checked(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(source),
            str(checkout),
        ]
    )
    base._run_checked(
        ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", commit],
        cwd=checkout,
    )
    if base._run_checked(["git", "rev-parse", "HEAD"], cwd=checkout) != commit:
        raise RunnerError("isolated Codex checkout HEAD mismatch")
    if base._run_checked(["git", "status", "--porcelain"], cwd=checkout):
        raise RunnerError("isolated Codex checkout is dirty before execution")
    return checkout


def prompt_for(request: Mapping[str, Any]) -> str:
    vocabulary = ", ".join(base.CLAIM_VOCABULARY)
    extra = ""
    if request["condition"] == "treatment":
        extra = (
            " You may additionally use only these RepoGround MCP tools: ask_context, "
            "grounding_verify, live_freshness, repobrief_resource_read."
        )
    return (
        str(request["prompt"])
        + "\n\nBenchmark rules: work read-only. For direct repository inspection use ONLY "
        "one single command per tool call and ONLY these forms: rg --files ... ; "
        "rg ... ; sed -n 'START,ENDp' PATH ; cat PATH. Do not use ls, find, git, "
        "python, shell pipes, redirections, command chaining, web search, subagents, "
        "or file edits. Any such use invalidates the run."
        + extra
        + " Return only the JSON object required by the provided output schema. Paths "
        "must be repository-relative; citations use exact inclusive line ranges. Use "
        "only these claim labels when supported: "
        + vocabulary
        + ". Do not guess missing evidence."
    )


def _proxy_write(message: Mapping[str, Any], lock: threading.Lock) -> None:
    raw = canonical(message).encode("utf-8") + b"\n"
    with lock:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()


def _freeze_resource_result(value: Any) -> tuple[dict[str, Any], set[str]]:
    if not isinstance(value, dict) or not isinstance(value.get("resources"), list):
        raise RunnerError("RepoGround resource list is malformed")
    if value.get("nextCursor") not in {None, ""}:
        raise RunnerError("RepoGround resource list is paginated")
    resources = value["resources"]
    if len(resources) > MAX_FROZEN_RESOURCES:
        raise RunnerError("RepoGround resource list exceeds its bound")
    uris: set[str] = set()
    frozen: list[dict[str, Any]] = []
    for item in resources:
        if not isinstance(item, dict) or not isinstance(item.get("uri"), str) or not item["uri"]:
            raise RunnerError("RepoGround resource list contains an invalid URI")
        uri = item["uri"]
        if uri in uris or len(uri.encode("utf-8")) > 4096:
            raise RunnerError("RepoGround resource URI is duplicate or oversized")
        uris.add(uri)
        frozen.append(json.loads(json.dumps(item)))
    return {"resources": frozen}, uris


def _proxy_error(identifier: Any, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32601, "message": message}}


def _filtered_treatment_tools(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("tools"), list):
        raise RunnerError("RepoGround tools/list result is missing a tools array")
    counts = {name: 0 for name in UPSTREAM_MCP}
    filtered: list[dict[str, Any]] = []
    for item in value["tools"]:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name in counts:
            counts[str(name)] += 1
            filtered.append(item)
    invalid = [f"{name}={counts[name]}" for name in sorted(counts) if counts[name] != 1]
    if invalid:
        raise RunnerError(
            "RepoGround tools/list must expose every required treatment tool exactly once: "
            + ", ".join(invalid)
        )
    filtered.append(
        {
            "name": "repobrief_resource_read",
            "description": "List frozen RepoGround resources or read one exact frozen resource URI.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["action"],
                "properties": {
                    "action": {"enum": ["list", "read"]},
                    "uri": {"type": "string"},
                },
            },
        }
    )
    return filtered


def run_mcp_proxy(upstream: Sequence[str]) -> int:
    if not upstream or any(not isinstance(item, str) or not item for item in upstream):
        raise RunnerError("invalid MCP upstream argv")
    try:
        process = subprocess.Popen(
            list(upstream), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=provider_env(), shell=False,
        )
    except OSError as exc:
        raise RunnerError("MCP upstream could not be started") from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise RunnerError("MCP upstream pipes unavailable")
    output_lock = threading.Lock()
    state_lock = threading.Lock()
    initialize_ids: set[Any] = set()
    tools_list_ids: set[Any] = set()
    resource_calls: dict[Any, tuple[str, str | None]] = {}
    frozen_resources: dict[str, Any] | None = None
    frozen_uris: set[str] = set()
    errors: list[BaseException] = []
    upstream_stderr = bytearray()
    upstream_stderr_overflow = False

    def send(message: Mapping[str, Any]) -> None:
        raw = canonical(message).encode("utf-8") + b"\n"
        process.stdin.write(raw)
        process.stdin.flush()

    def drain_stderr() -> None:
        nonlocal upstream_stderr_overflow
        try:
            while True:
                chunk = process.stderr.read(65536)
                if not chunk:
                    break
                room = MAX_STDERR_BYTES + 1 - len(upstream_stderr)
                upstream_stderr.extend(chunk[: max(room, 0)])
                if len(upstream_stderr) > MAX_STDERR_BYTES:
                    upstream_stderr_overflow = True
        except BaseException as exc:
            errors.append(exc)

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()

    def client_to_upstream() -> None:
        try:
            for raw in sys.stdin.buffer:
                if len(raw) > base.MAX_MCP_MESSAGE_BYTES:
                    raise RunnerError("MCP client message too large")
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise RunnerError("MCP client message must be an object")
                method = message.get("method")
                identifier = message.get("id")
                if method not in MCP_CLIENT_METHODS:
                    if identifier is not None:
                        _proxy_write(_proxy_error(identifier, "benchmark MCP method is not authorized"), output_lock)
                    continue
                if method == "initialize" and identifier is not None:
                    with state_lock:
                        initialize_ids.add(identifier)
                elif method == "tools/list" and identifier is not None:
                    with state_lock:
                        tools_list_ids.add(identifier)
                elif method == "tools/call":
                    params = message.get("params") if isinstance(message.get("params"), dict) else {}
                    name = params.get("name")
                    if name == "repobrief_resource_read":
                        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
                        action = arguments.get("action")
                        uri = arguments.get("uri")
                        if identifier is None or action not in {"list", "read"}:
                            if identifier is not None:
                                _proxy_write(_proxy_error(identifier, "invalid resource request"), output_lock)
                            continue
                        with state_lock:
                            if action == "list" and frozen_resources is not None:
                                cached = canonical(frozen_resources)
                            else:
                                cached = None
                            if action == "read" and frozen_resources is None:
                                error = "list frozen resources before reading"
                            elif action == "read" and (not isinstance(uri, str) or uri not in frozen_uris):
                                error = "resource URI is not in the frozen list"
                            else:
                                error = None
                        if cached is not None:
                            _proxy_write({"jsonrpc":"2.0","id":identifier,"result":{"content":[{"type":"text","text":cached}],"isError":False}}, output_lock)
                            continue
                        if error is not None:
                            _proxy_write({"jsonrpc":"2.0","id":identifier,"result":{"content":[{"type":"text","text":error}],"isError":True}}, output_lock)
                            continue
                        with state_lock:
                            resource_calls[identifier] = (str(action), str(uri) if uri is not None else None)
                        if action == "list":
                            send({"jsonrpc":"2.0","id":identifier,"method":"resources/list","params":{}})
                        else:
                            send({"jsonrpc":"2.0","id":identifier,"method":"resources/read","params":{"uri":uri}})
                        continue
                    if name not in UPSTREAM_MCP:
                        if identifier is not None:
                            _proxy_write(_proxy_error(identifier, "benchmark MCP tool is not authorized"), output_lock)
                        continue
                send(message)
        except BaseException as exc:
            errors.append(exc)
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    client_thread = threading.Thread(target=client_to_upstream, daemon=True)
    client_thread.start()
    try:
        for raw in process.stdout:
            message = json.loads(raw)
            if not isinstance(message, dict):
                raise RunnerError("MCP upstream message must be an object")
            identifier = message.get("id")
            if identifier is None:
                continue
            with state_lock:
                is_initialize = identifier in initialize_ids
                is_tools_list = identifier in tools_list_ids
                resource_call = resource_calls.pop(identifier, None)
                initialize_ids.discard(identifier)
                tools_list_ids.discard(identifier)
            if is_initialize and "result" in message:
                result = message.get("result") if isinstance(message.get("result"), dict) else {}
                caps = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
                filtered = {key: result[key] for key in ("protocolVersion", "serverInfo") if key in result}
                filtered["capabilities"] = {"tools": caps.get("tools", {}) if isinstance(caps.get("tools", {}), dict) else {}}
                message = {"jsonrpc":"2.0","id":identifier,"result":filtered}
            elif is_tools_list and "result" in message:
                tools = _filtered_treatment_tools(message.get("result"))
                message = {"jsonrpc":"2.0","id":identifier,"result":{"tools":tools}}
            elif resource_call is not None:
                action, _uri = resource_call
                if "error" in message:
                    text = canonical(message["error"]); is_error = True
                elif action == "list":
                    try:
                        frozen, uris = _freeze_resource_result(message.get("result"))
                    except RunnerError as exc:
                        text = str(exc); is_error = True
                    else:
                        with state_lock:
                            frozen_resources = frozen
                            frozen_uris = uris
                        text = canonical(frozen); is_error = False
                else:
                    text = canonical(message.get("result")); is_error = False
                message = {"jsonrpc":"2.0","id":identifier,"result":{"content":[{"type":"text","text":text}],"isError":is_error}}
            _proxy_write(message, output_lock)
        returncode = process.wait(timeout=5)
    finally:
        process.stdout.close()
        stderr_thread.join(timeout=5)
    if errors:
        raise RunnerError("benchmark MCP proxy stream failed") from errors[0]
    if upstream_stderr:
        sys.stderr.buffer.write(bytes(upstream_stderr)); sys.stderr.buffer.flush()
    if upstream_stderr_overflow or returncode != 0 or upstream_stderr:
        raise RunnerError("benchmark MCP upstream failed or emitted diagnostics")
    return returncode


def write_schema(path: Path) -> None:
    base._write_private_exclusive(
        path,
        (json.dumps(base.ANSWER_SCHEMA, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def build_command(
    request: Mapping[str, Any], codex: str, checkout: Path, schema: Path, codex_home: Path
) -> list[str]:
    filesystem = (
        '{":minimal"="read",":workspace_roots"={"."="read"},'
        + _toml_string(str(codex_home / "tmp")) + '="read",'
        + _toml_string(str(Path(codex).parent)) + '="read"}'
    )
    command = [
        codex, "exec",
        "-c", f'default_permissions="{PERMISSION_PROFILE}"',
        "-c", "features.network_proxy=true",
        "-c", f"permissions.{PERMISSION_PROFILE}.filesystem={filesystem}",
        "-c", f'permissions.{PERMISSION_PROFILE}.network={{enabled=true,mode="limited",allow_local_binding=false,domains={{}}}}',
        "--ephemeral", "--ignore-user-config", "--ignore-rules", "--strict-config",
        "--color", "never", "--json", "--model", MODEL,
        "-c", 'model_reasoning_effort="medium"',
        "-c", 'web_search="disabled"',
        "--cd", str(checkout), "--output-schema", str(schema), "-",
    ]
    if request["condition"] == "treatment":
        upstream = [str(item) for item in request["repobrief"]["mcp_command"]]
        proxy_args = [str(Path(__file__).resolve()), "--codex-mcp-proxy", canonical(upstream)]
        command[2:2] = [
            "-c", 'mcp_servers.repobrief.command="/usr/bin/python3"',
            "-c", "mcp_servers.repobrief.args=" + canonical(proxy_args),
        ]
    return command


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    stdin_data: bytes,
    environment: Mapping[str, str] | None = None,
    stdout_limit: int = MAX_TRANSCRIPT_BYTES,
    stderr_limit: int = MAX_STDERR_BYTES,
) -> dict[str, Any]:
    """Capture a bounded provider process without interpreting its streams.

    Before ``Popen`` succeeds, setup errors may raise normally.  After the
    provider process exists, every catchable capture/cleanup failure is converted
    into ``capture_error`` so already-observed stdout/stderr can be persisted by
    the caller before the benchmark arm fails.
    """

    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(environment) if environment is not None else provider_env(),
            shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise RunnerError("Codex process could not be started") from exc

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    overflow = {"stdout": False, "stderr": False}
    capture_error: str | None = None
    selector: selectors.BaseSelector | None = None

    def note_error(marker: str) -> None:
        nonlocal capture_error
        if capture_error is None:
            capture_error = marker
        elif marker not in capture_error.split(";"):
            capture_error += ";" + marker

    def kill_process_tree() -> None:
        group_killed = False
        try:
            os.killpg(process.pid, signal.SIGKILL)
            group_killed = True
        except ProcessLookupError:
            return
        except OSError as exc:
            note_error(f"process_group_kill_failed:{type(exc).__name__}")
        if group_killed or process.poll() is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:
            return
        except OSError as exc:
            note_error(f"process_kill_failed:{type(exc).__name__}")

    def store(label: str, chunk: bytes) -> None:
        if not chunk or overflow[label]:
            return
        limit = limits[label]
        room = max(limit + 1 - len(buffers[label]), 0)
        buffers[label].extend(chunk[:room])
        if len(buffers[label]) > limit:
            overflow[label] = True
            note_error(f"{label}_limit_exceeded")
            kill_process_tree()

    streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
    if process.stdin is None or process.stdout is None or process.stderr is None:
        note_error("capture_pipe_unavailable")
        kill_process_tree()
    else:
        try:
            selector = selectors.DefaultSelector()
            for stream, label in streams:
                assert stream is not None
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
        except BaseException as exc:
            note_error(f"capture_setup_failed:{type(exc).__name__}")
            kill_process_tree()

    if capture_error is None:
        assert process.stdin is not None
        try:
            process.stdin.write(stdin_data)
            process.stdin.close()
        except OSError as exc:
            note_error(f"stdin_write_failed:{type(exc).__name__}")
            try:
                process.stdin.close()
            except OSError:
                pass
            kill_process_tree()

    deadline = time.monotonic() + timeout_seconds
    if selector is not None and capture_error is None:
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 and capture_error is None:
                    note_error("timeout")
                    kill_process_tree()
                wait_for = 0 if process.poll() is not None else max(min(remaining, 0.25), 0)
                events = selector.select(wait_for)
                if not events and process.poll() is not None:
                    for key in list(selector.get_map().values()):
                        try:
                            chunk = os.read(key.fileobj.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            store(str(key.data), chunk)
                    continue
                for key, _mask in events:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    store(str(key.data), chunk)
        except BaseException as exc:
            note_error(f"capture_stream_failed:{type(exc).__name__}")
            kill_process_tree()

    if selector is not None:
        try:
            selector.close()
        except BaseException as exc:
            note_error(f"selector_cleanup_failed:{type(exc).__name__}")

    if capture_error is not None:
        kill_process_tree()
    try:
        returncode = process.wait(timeout=5)
    except BaseException as exc:
        note_error(f"process_wait_failed:{type(exc).__name__}")
        kill_process_tree()
        try:
            process.wait(timeout=5)
        except BaseException as followup:
            note_error(f"process_reap_failed:{type(followup).__name__}")
        returncode = process.returncode if isinstance(process.returncode, int) else -1

    # After a capture fault, drain whatever bytes the terminated process left in
    # its pipes.  This is best-effort and bounded; failures themselves become
    # evidence-bearing capture errors rather than escaping past the caller.
    if capture_error is not None:
        for stream, label in streams:
            if stream is None:
                continue
            try:
                os.set_blocking(stream.fileno(), False)
            except (OSError, ValueError) as exc:
                note_error(f"capture_drain_setup_failed:{type(exc).__name__}")
                continue
            while True:
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    break
                except (OSError, ValueError) as exc:
                    note_error(f"capture_drain_failed:{type(exc).__name__}")
                    break
                if not chunk:
                    break
                store(label, chunk)

    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is None or stream.closed:
            continue
        try:
            stream.close()
        except OSError as exc:
            note_error(f"stream_cleanup_failed:{type(exc).__name__}")

    return {
        "returncode": returncode,
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "capture_error": capture_error,
        "stdout_overflow": overflow["stdout"],
        "stderr_overflow": overflow["stderr"],
    }


def classify_stderr(raw: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "policy": STDERR_POLICY_VERSION,
        "sha256": sha_bytes(raw),
        "bytes": len(raw),
        "allowed": False,
        "classification": "unclassified",
        "meaningful_line_count": 0,
        "line_sha256": [],
    }
    if not raw:
        result.update({"allowed": True, "classification": "empty"})
        return result
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        result["classification"] = "non_utf8_unqualified"
        return result
    meaningful = [line for line in text.splitlines() if line.strip()]
    result["meaningful_line_count"] = len(meaningful)
    result["line_sha256"] = [sha_bytes(line.encode("utf-8")) for line in meaningful]
    if not meaningful:
        result.update({"allowed": True, "classification": "whitespace_only"})
        return result
    if QUALIFIED_BENIGN_STDERR_PATTERNS and all(
        any(pattern.fullmatch(line) for pattern in QUALIFIED_BENIGN_STDERR_PATTERNS)
        for line in meaningful
    ):
        result.update({"allowed": True, "classification": "qualified_benign_text"})
        return result
    result["classification"] = "text_unqualified"
    return result


def _provider_artifact_names(request: Mapping[str, Any]) -> dict[str, str]:
    stem = hashlib.sha256(str(request["request_id"]).encode("utf-8")).hexdigest()
    return {
        "stdout": f"{stem}.jsonl",
        "stderr": f"{stem}.stderr",
        "diagnostics": f"{stem}.provider.json",
        "stderr_policy": f"{stem}.stderr-policy.json",
    }


def persist_provider_capture(
    request: Mapping[str, Any], *, transcript_root: Path, evidence_root: Path,
    capture: Mapping[str, Any], started_at: datetime, ended_at: datetime,
    synthetic_fixture: bool, evidence_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist raw capture facts through pre-opened create-only directories."""
    owned_plan = evidence_plan is None
    plan = evidence_plan or prepare_provider_evidence(request, transcript_root, evidence_root)
    try:
        names = dict(plan["names"])
        transcript_path = Path(plan["transcript_root"])
        evidence_path = Path(plan["evidence_root"])
        transcript_fd = int(plan["transcript_fd"]); evidence_fd = int(plan["evidence_fd"])
        _directory_fd_matches(transcript_path, transcript_fd)
        _directory_fd_matches(evidence_path, evidence_fd)
        stdout = bytes(capture.get("stdout") or b"")
        stderr = bytes(capture.get("stderr") or b"")
        stdout_path = transcript_path / names["stdout"]
        stderr_path = evidence_path / names["stderr"]
        diagnostics_path = evidence_path / names["diagnostics"]
        stderr_policy_path = evidence_path / names["stderr_policy"]
        raw_write_errors: list[BaseException] = []
        for descriptor, name, data in (
            (transcript_fd, names["stdout"], stdout),
            (evidence_fd, names["stderr"], stderr),
        ):
            try:
                _write_private_dirfd(descriptor, name, data)
            except BaseException as exc:
                raw_write_errors.append(exc)
        if raw_write_errors:
            raise RunnerError("raw provider evidence could not be persisted completely") from raw_write_errors[0]
        diagnostics = {
            "kind":"repobrief.codex_provider_capture", "version":base.VERSION,
            "request_id":request["request_id"], "request_sha256":base._sha256_json(request),
            "provider":PROVIDER, "model":MODEL, "synthetic_fixture":synthetic_fixture,
            "stderr_policy_version":STDERR_POLICY_VERSION,
            "started_at":iso(started_at), "ended_at":iso(ended_at),
            "returncode":capture.get("returncode"), "capture_error":capture.get("capture_error"),
            "stdout":{"artifact":names["stdout"],"sha256":sha_bytes(stdout),"bytes":len(stdout),"overflow":bool(capture.get("stdout_overflow"))},
            "stderr":{"artifact":names["stderr"],"sha256":sha_bytes(stderr),"bytes":len(stderr),"overflow":bool(capture.get("stderr_overflow"))},
            "semantic_interpretation":"not_performed",
            "does_not_establish":["provider_success","stderr_policy_acceptance","benchmark_receipt_validity","answer_correctness","retry_authority"],
        }
        raw=(json.dumps(diagnostics,sort_keys=True,indent=2)+"\n").encode()
        _write_private_dirfd(evidence_fd,names["diagnostics"],raw)
        stderr_classification=classify_stderr(stderr)
        stderr_policy={
            "kind":"repobrief.codex_stderr_policy","version":base.VERSION,
            "request_id":request["request_id"],"request_sha256":base._sha256_json(request),
            "provider":PROVIDER,"model":MODEL,"synthetic_fixture":synthetic_fixture,
            "started_at":iso(started_at),"ended_at":iso(ended_at),
            "returncode":capture.get("returncode"),"capture_error":capture.get("capture_error"),
            "stdout":diagnostics["stdout"],
            "stderr":{"artifact":names["stderr"],**stderr_classification,"overflow":bool(capture.get("stderr_overflow"))},
            "capture_diagnostics_sha256":sha_bytes(raw),
            "does_not_establish":["provider_success","benchmark_receipt_validity","answer_correctness","retry_authority"],
        }
        policy_raw=(json.dumps(stderr_policy,sort_keys=True,indent=2)+"\n").encode()
        _write_private_dirfd(evidence_fd,names["stderr_policy"],policy_raw)
        _directory_fd_matches(transcript_path, transcript_fd)
        _directory_fd_matches(evidence_path, evidence_fd)
        return {
            "stdout_path":stdout_path,"stderr_path":stderr_path,
            "diagnostics_path":diagnostics_path,"diagnostics_sha256":sha_bytes(raw),
            "diagnostics":diagnostics,"stderr_policy_path":stderr_policy_path,
            "stderr_policy_sha256":sha_bytes(policy_raw),"stderr_policy":stderr_policy,
            "stdout_artifact":names["stdout"],
        }
    finally:
        if owned_plan:
            close_provider_evidence_plan(plan)


def parse_events(raw: bytes) -> list[dict[str, Any]]:
    if not raw or len(raw) > MAX_TRANSCRIPT_BYTES:
        raise RunnerError("Codex transcript empty or oversized")
    result: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError(f"Codex transcript line {number} invalid JSON") from exc
        if not isinstance(value, dict):
            raise RunnerError(f"Codex transcript line {number} not object")
        result.append(value)
    if not result:
        raise RunnerError("Codex transcript contains no events")
    return result


_RG_SAFE_SWITCHES = {
    "--files",
    "--hidden",
    "--no-heading",
    "--no-ignore",
    "--no-ignore-vcs",
    "--no-messages",
    "--with-filename",
    "--fixed-strings",
    "--ignore-case",
    "--line-number",
    "--smart-case",
    "--word-regexp",
    "-F",
    "-H",
    "-i",
    "-n",
    "-S",
    "-w",
}
_RG_SAFE_VALUE_OPTIONS = {
    "--after-context",
    "--before-context",
    "--context",
    "--glob",
    "--iglob",
    "--max-count",
    "--max-depth",
    "--regexp",
    "--type",
    "--type-not",
    "-A",
    "-B",
    "-C",
    "-e",
    "-g",
    "-m",
    "-t",
    "-T",
}


def _split_shell_words(text: str) -> list[str]:
    if "$(" in text or "`" in text:
        raise RunnerError("command substitution is not allowed")
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        parts = list(lexer)
    except ValueError as exc:
        raise RunnerError("unparseable Codex command") from exc
    if any(part in {";", "&", "&&", "|", "||", ">", ">>", "<", "<<"} for part in parts):
        raise RunnerError("chained, piped, or redirected command is not allowed")
    return parts


def _repository_relative_path(value: str) -> str:
    if not value or value.startswith("-") or value.startswith("~") or os.path.isabs(value):
        raise RunnerError("benchmark path must be repository-relative")
    if any(char in value for char in ("$", "*", "?", "[", "]", "{", "}", "!", "\n", "\r", "\x00")):
        raise RunnerError("benchmark path contains shell expansion syntax")
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../"):
        raise RunnerError("benchmark path escapes the repository")
    return normalized


def _rg_kind(parts: Sequence[str]) -> str:
    if not parts or parts[0] != "rg":
        raise RunnerError("invalid rg command")
    files_mode = False
    explicit_pattern = False
    operands: list[str] = []
    index = 1
    while index < len(parts):
        item = parts[index]
        if item == "--":
            operands.extend(parts[index + 1 :])
            break
        if item in _RG_SAFE_SWITCHES:
            files_mode = files_mode or item == "--files"
            index += 1
            continue
        if item in _RG_SAFE_VALUE_OPTIONS:
            if index + 1 >= len(parts):
                raise RunnerError(f"rg option requires a value: {item}")
            explicit_pattern = explicit_pattern or item in {"-e", "--regexp"}
            index += 2
            continue
        matched_value_option = next((
            option for option in _RG_SAFE_VALUE_OPTIONS
            if option.startswith("--") and item.startswith(option + "=")
        ), None)
        if matched_value_option is not None:
            explicit_pattern = explicit_pattern or matched_value_option == "--regexp"
            index += 1
            continue
        if item.startswith("-"):
            raise RunnerError(f"unapproved rg option: {item}")
        operands.append(item)
        index += 1
    if files_mode:
        if explicit_pattern:
            raise RunnerError("rg --files must not carry a search expression")
        for path in operands:
            _repository_relative_path(path)
        return "glob"
    if not explicit_pattern:
        if not operands:
            raise RunnerError("rg grep form requires a search expression")
        path_operands = operands[1:]
    else:
        path_operands = operands
    for path in path_operands:
        _repository_relative_path(path)
    return "grep"


def _cat_kind(parts: Sequence[str]) -> str:
    if not parts or parts[0] != "cat":
        raise RunnerError("invalid cat command")
    operands = list(parts[1:])
    if operands[:1] == ["--"]:
        operands = operands[1:]
    if len(operands) != 1:
        raise RunnerError("cat benchmark form requires exactly one repository path")
    _repository_relative_path(operands[0])
    return "read_file"


def _sed_kind(parts: Sequence[str]) -> str:
    if not parts or parts[0] != "sed" or len(parts) not in {4, 5} or parts[1] != "-n":
        raise RunnerError("sed benchmark form must be: sed -n START,ENDp PATH")
    range_expression = parts[2]
    path_index = 3
    if len(parts) == 5:
        if parts[3] != "--":
            raise RunnerError("sed benchmark form has unexpected arguments")
        path_index = 4
    if re.fullmatch(r"[0-9]+(?:,[0-9]+)?p", range_expression) is None:
        raise RunnerError("sed benchmark range is not a bounded line read")
    _repository_relative_path(parts[path_index])
    return "read_file"


def command_kind(command: str) -> str:
    parts = _split_shell_words(command.strip())
    if len(parts) >= 3 and parts[0] == "bash" and parts[1] == "-lc":
        if len(parts) != 3:
            raise RunnerError("complex shell wrapper is not allowed")
        parts = _split_shell_words(parts[2].strip())
    if not parts:
        raise RunnerError("empty Codex command")
    executable = parts[0]
    if executable == "rg":
        return _rg_kind(parts)
    if executable == "cat":
        return _cat_kind(parts)
    if executable == "sed":
        return _sed_kind(parts)
    raise RunnerError(f"unapproved Codex command: {executable}")


def normalize(
    request: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> tuple[int, int, list[dict[str, Any]], dict[str, Any]]:
    completed = [event for event in events if event.get("type") == "turn.completed"]
    if len(completed) != 1:
        raise RunnerError("Codex transcript requires one turn.completed")
    if any(event.get("type") in {"turn.failed", "error"} for event in events):
        raise RunnerError("Codex emitted terminal error")
    usage = completed[0].get("usage") if isinstance(completed[0].get("usage"), dict) else {}
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if (
        not isinstance(input_tokens, int)
        or input_tokens < 0
        or not isinstance(output_tokens, int)
        or output_tokens < 0
    ):
        raise RunnerError("Codex usage is invalid")
    budgets = request["budgets"]
    if input_tokens > budgets["input_tokens"] or output_tokens > budgets["output_tokens"]:
        raise RunnerError("Codex token budget exceeded")

    calls: list[dict[str, Any]] = []
    answers: list[str] = []
    total_input = 0
    total_output = 0
    allowed = set(request["allowed_tools"])
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item") if isinstance(event.get("item"), dict) else {}
        item_type = item.get("type")
        if item_type == "agent_message":
            if isinstance(item.get("text"), str):
                answers.append(item["text"])
            continue
        if item_type in {"reasoning", "todo_list"}:
            continue
        if item_type == "command_execution":
            name = command_kind(str(item.get("command", "")))
            input_bytes = len(str(item.get("command", "")).encode("utf-8"))
            output_bytes = len(str(item.get("aggregated_output", "")).encode("utf-8"))
            status = (
                "success"
                if item.get("status") == "completed" and item.get("exit_code") == 0
                else "failed"
            )
        elif item_type == "mcp_tool_call":
            if (
                request["condition"] != "treatment"
                or item.get("server") != "repobrief"
                or item.get("tool") not in ALLOWED_MCP
            ):
                raise RunnerError("unapproved Codex MCP tool call")
            name = str(item["tool"])
            input_bytes = len(canonical(item.get("arguments")).encode("utf-8"))
            output_value = item.get("result") if item.get("result") is not None else item.get("error")
            output_bytes = len(canonical(output_value).encode("utf-8"))
            status = (
                "success"
                if item.get("status") == "completed" and item.get("error") is None
                else "failed"
            )
        elif item_type in {"file_change", "web_search", "collab_tool_call", "error"}:
            raise RunnerError(f"unapproved Codex item type: {item_type}")
        else:
            raise RunnerError(f"unknown Codex completed item type: {item_type}")
        if name not in allowed:
            raise RunnerError(f"normalized tool not allowed: {name}")
        total_input += input_bytes
        total_output += output_bytes
        calls.append(
            {
                "sequence": len(calls) + 1,
                "name": name,
                "status": status,
                "duration_ms": 0,
                "input_bytes": input_bytes,
                "output_bytes": output_bytes,
            }
        )
    if (
        len(calls) > budgets["max_tool_calls"]
        or total_input > budgets["max_tool_input_bytes"]
        or total_output > budgets["max_tool_output_bytes"]
    ):
        raise RunnerError("Codex tool budget exceeded")
    if not answers:
        raise RunnerError("Codex produced no final agent message")
    try:
        answer_raw = json.loads(answers[-1])
    except json.JSONDecodeError as exc:
        raise RunnerError("Codex final message is not structured JSON") from exc
    return input_tokens, output_tokens, calls, base.validate_answer(answer_raw)


def receipt(
    request: Mapping[str, Any],
    raw: bytes,
    artifact: str,
    returncode: int,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    if returncode != 0:
        raise RunnerError(f"Codex exited nonzero: {returncode}")
    events = parse_events(raw)
    input_tokens, output_tokens, calls, answer = normalize(request, events)
    elapsed = max(0, int((ended_at - started_at).total_seconds() * 1000))
    if elapsed > int(request["budgets"]["wall_seconds"]) * 1000:
        raise RunnerError("Codex wall budget exceeded")
    return {
        "kind": base.RECEIPT_KIND,
        "version": base.VERSION,
        "request_id": request["request_id"],
        "request_sha256": base._sha256_json(request),
        "status": "success",
        "provider": {
            "name": PROVIDER,
            "model": MODEL,
            "sampling": SAMPLING,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "token_source": "provider_reported",
        },
        "started_at": iso(started_at),
        "ended_at": iso(ended_at),
        "duration_ms": elapsed,
        "exit_code": 0,
        "tool_calls": calls,
        "answer": answer,
        "transcript": {
            "storage": "artifact",
            "sha256": sha_bytes(raw),
            "bytes": len(raw),
            "inline": None,
            "artifact": artifact,
        },
        "error": None,
        "does_not_establish": list(base.DOES_NOT_ESTABLISH),
    }


def _fixture_capture(
    stream_fixture: Path, stderr_fixture: Path | None, fixture_returncode: int
) -> dict[str, Any]:
    return {
        "returncode": fixture_returncode,
        "stdout": stream_fixture.read_bytes(),
        "stderr": stderr_fixture.read_bytes() if stderr_fixture is not None else b"",
        "capture_error": None,
        "stdout_overflow": False,
        "stderr_overflow": False,
    }


def execute(request: Mapping[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    validate_request(request)
    _validated_live_mode(
        stream_fixture=args.stream_fixture,
        stderr_fixture=args.stderr_fixture,
        fixture_returncode=args.fixture_returncode,
        allow_live_provider=args.allow_live_provider,
        codex_command_sha256=args.codex_command_sha256,
    )
    base.load_planned_request(request, args.request_root)
    source = base.load_repository_root(request, args.repository_map)
    synthetic = args.stream_fixture is not None

    # Bind every static live input before consuming the create-only workspace id.
    # A typo in an executable digest or frozen Treatment manifest must not burn a
    # one-shot workspace even though it has not yet contacted the provider.
    if request["condition"] == "treatment":
        binding = request["repobrief"]
        manifest = Path(binding["manifest"])
        manifest_bytes = _read_bound_regular_file(
            manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
        )
        if sha_bytes(manifest_bytes) != binding["manifest_sha256"]:
            raise RunnerError("RepoGround manifest SHA mismatch")
    codex: str | None = None
    auth_data: bytes | None = None
    if not synthetic:
        codex = validate_executable(
            args.codex_command, args.codex_command_sha256, require_read_only_mount=True
        )
        validate_toolchain(codex)
        auth_data = validate_chatgpt_subscription(codex)

    state_path, state_fd = _open_private_directory(args.state_root)
    try:
        _directory_fd_matches(state_path, state_fd)
    finally:
        os.close(state_fd)
    evidence_plan = prepare_provider_evidence(
        request, args.transcript_root, args.provider_evidence_root
    )
    try:
        checkout = create_checkout(request, source, args.state_root)
        schema = checkout.parent / "answer-schema.json"
        write_schema(schema)
        started = utc_now()
        if synthetic:
            capture = _fixture_capture(
                args.stream_fixture, args.stderr_fixture, args.fixture_returncode
            )
        else:
            assert codex is not None and auth_data is not None
            codex_home = stage_codex_home(args.state_root, auth_data)
            try:
                command = build_command(request, codex, checkout, schema, codex_home)
                capture = run_bounded(
                    command, cwd=checkout,
                    timeout_seconds=int(request["budgets"]["wall_seconds"]),
                    stdin_data=(prompt_for(request) + "\n").encode("utf-8"),
                    environment=provider_env(codex=codex, codex_home=codex_home),
                )
            except BaseException as exc:
                cleanup_error = cleanup_codex_home(codex_home)
                if cleanup_error is not None:
                    raise RunnerError(
                        f"Codex failed before capture completion and runtime-home cleanup failed: {cleanup_error}"
                    ) from exc
                raise
            cleanup_error = cleanup_codex_home(codex_home)
            if cleanup_error is not None:
                capture = dict(capture)
                cleanup_marker = f"codex_home_cleanup_failed:{cleanup_error}"
                previous = capture.get("capture_error")
                capture["capture_error"] = (
                    cleanup_marker if previous is None else f"{previous};{cleanup_marker}"
                )
        ended = utc_now()
        evidence = persist_provider_capture(
            request, transcript_root=args.transcript_root,
            evidence_root=args.provider_evidence_root, capture=capture,
            started_at=started, ended_at=ended, synthetic_fixture=synthetic,
            evidence_plan=evidence_plan,
        )
    finally:
        close_provider_evidence_plan(evidence_plan)
    stderr_policy = evidence["stderr_policy"]

    if capture.get("capture_error") is not None:
        raise RunnerError(
            "Codex capture failed after evidence persistence: "
            f"{capture['capture_error']} diagnostics={evidence['diagnostics_sha256']} "
            f"stderr_policy={evidence['stderr_policy_sha256']}"
        )
    if not stderr_policy["stderr"]["allowed"]:
        raise RunnerError(
            "Codex stderr is not qualified by the fail-closed policy after evidence "
            f"persistence: classification={stderr_policy['stderr']['classification']} "
            f"sha256={stderr_policy['stderr']['sha256']} "
            f"bytes={stderr_policy['stderr']['bytes']} "
            f"diagnostics={evidence['diagnostics_sha256']} "
            f"stderr_policy={evidence['stderr_policy_sha256']}"
        )

    if not synthetic:
        validate_executable(
            args.codex_command,
            args.codex_command_sha256,
            require_read_only_mount=True,
        )
    if base._run_checked(["git", "status", "--porcelain"], cwd=checkout):
        raise RunnerError("Codex changed read-only checkout")

    normalized = receipt(
        request,
        bytes(capture["stdout"]),
        evidence["stdout_artifact"],
        int(capture["returncode"]),
        started,
        ended,
    )
    if synthetic:
        return base.build_fixture_report(request, normalized)
    return normalized


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Run one isolated read-only RepoBrief Codex benchmark request."
    )
    result.add_argument("--request-root", required=True, type=Path)
    result.add_argument("--repository-map", required=True, type=Path)
    result.add_argument("--state-root", required=True, type=Path)
    result.add_argument("--transcript-root", required=True, type=Path)
    result.add_argument("--provider-evidence-root", required=True, type=Path)
    result.add_argument("--codex-command", default="codex")
    result.add_argument("--codex-command-sha256")
    result.add_argument("--allow-live-provider", action="store_true")
    result.add_argument("--stream-fixture", type=Path)
    result.add_argument("--stderr-fixture", type=Path)
    result.add_argument("--fixture-returncode", type=int, default=0)
    return result


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "--codex-mcp-proxy":
        try:
            if len(raw) != 2:
                raise RunnerError("codex MCP proxy requires one encoded upstream argv")
            upstream = json.loads(raw[1])
            if not isinstance(upstream, list):
                raise RunnerError("codex MCP proxy upstream argv must be a list")
            return run_mcp_proxy(upstream)
        except Exception as exc:
            print(f"codex MCP proxy failed: {exc}", file=sys.stderr)
            return 2
    args = parser().parse_args(raw)
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise RunnerError("stdin request must be one JSON object")
        result = execute(request, args)
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

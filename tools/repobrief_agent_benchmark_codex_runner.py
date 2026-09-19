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
import ctypes
import fcntl
from datetime import datetime, timezone
import hashlib
import hmac
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

SOURCE_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024

ENTRYPOINT_BOOTSTRAP_KIND = "grabowski.python_c_source_bootstrap"
ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION = 1
ENTRYPOINT_BOOTSTRAP_NAME = "repobrief_agent_benchmark_source_bootstrap.py"
ENTRYPOINT_BOOTSTRAP_PATH = Path(__file__).with_name(ENTRYPOINT_BOOTSTRAP_NAME)


def _read_source_snapshot(path: Path) -> tuple[bytes, dict[str, Any]]:
    requested = path.expanduser()
    before = requested.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"cannot safely load {path.name}")
    if before.st_size <= 0 or before.st_size > SOURCE_SNAPSHOT_MAX_BYTES:
        raise RuntimeError(f"cannot safely load {path.name}")
    descriptor = os.open(
        requested, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev, before.st_ino, before.st_size
        ):
            raise RuntimeError(f"{path.name} changed before load")
        data = bytearray()
        while len(data) <= SOURCE_SNAPSHOT_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, SOURCE_SNAPSHOT_MAX_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    after = requested.lstat()
    if (
        len(data) != opened.st_size
        or len(data) > SOURCE_SNAPSHOT_MAX_BYTES
        or (after.st_dev, after.st_ino, after.st_size)
        != (opened.st_dev, opened.st_ino, opened.st_size)
    ):
        raise RuntimeError(f"{path.name} changed during load")
    resolved = requested.resolve()
    return bytes(data), {
        "path": str(resolved),
        "name": resolved.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


_CAPTURED_ENTRYPOINT_ACTIVE = (
    globals().get("__grabowski_captured_entrypoint_active__") is True
)
_CAPTURED_ENTRYPOINT_RAW = globals().get("__grabowski_captured_entrypoint_raw__")
_CAPTURED_ENTRYPOINT_IDENTITY = globals().get(
    "__grabowski_captured_entrypoint_identity__"
)
_ENTRYPOINT_BOOTSTRAP_RAW = globals().get("__grabowski_entrypoint_bootstrap_raw__")
_ENTRYPOINT_BOOTSTRAP_IDENTITY = globals().get(
    "__grabowski_entrypoint_bootstrap_identity__"
)


def _validated_captured_self_source(
    raw: Any, identity: Any, source: Path
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(identity, dict):
        raise RuntimeError("captured Codex runner source binding is invalid")
    data = bytes(raw)
    resolved = source.expanduser().resolve()
    expected = {
        "path": str(resolved),
        "name": resolved.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if identity != expected:
        raise RuntimeError("captured Codex runner source identity mismatch")
    return data, expected


def _validated_entrypoint_bootstrap_context(
    raw: Any, identity: Any
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(identity, dict):
        raise RuntimeError("immutable Codex bootstrap binding is missing")
    data = bytes(raw)
    expected = {
        "schema_version": ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION,
        "kind": ENTRYPOINT_BOOTSTRAP_KIND,
        "name": ENTRYPOINT_BOOTSTRAP_NAME,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if identity != expected:
        raise RuntimeError("immutable Codex bootstrap identity mismatch")
    return data, expected


if __name__ == "__main__":
    if not _CAPTURED_ENTRYPOINT_ACTIVE:
        raise RuntimeError(
            "Codex runner must be started through the immutable source bootstrap"
        )
    _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY = (
        _validated_entrypoint_bootstrap_context(
            _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY
        )
    )
    _SELF_SOURCE_RAW, _SELF_SOURCE_IDENTITY = _validated_captured_self_source(
        _CAPTURED_ENTRYPOINT_RAW,
        _CAPTURED_ENTRYPOINT_IDENTITY,
        Path(__file__),
    )
else:
    _SELF_SOURCE_RAW, _SELF_SOURCE_IDENTITY = _read_source_snapshot(Path(__file__))

def _load_captured_module(name: str, path: Path) -> Any:
    raw, identity = _read_source_snapshot(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
        _after_raw, after_identity = _read_source_snapshot(path)
        if after_identity != identity:
            raise RuntimeError(f"{path.name} changed while being loaded")
    except BaseException:
        sys.modules.pop(name, None)
        raise
    module.__grabowski_source_identity__ = dict(identity)
    return module


BASE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_runner.py")
base = _load_captured_module("repobrief_agent_benchmark_base", BASE_PATH)

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
MAX_DISPATCH_AUTHORIZATION_BYTES = 16 * 1024 * 1024
MAX_PREFLIGHT_REPORT_BYTES = 16 * 1024 * 1024
MAX_PREFLIGHT_REPORT_DIGEST_BYTES = 512
PREFLIGHT_AUTHORIZATION_REPORT_KIND = (
    "repobrief.agent_benchmark_preflight_dispatch_authorization"
)
PREFLIGHT_LEDGER_KIND = "repobrief.agent_benchmark_preflight_dispatch_ledger"
PREFLIGHT_LEDGER_VERSION = "1.0"
PREFLIGHT_EVENT_KIND = "repobrief.agent_benchmark_preflight_dispatch_event"
DISPATCH_INTENT_LOCK_NAME = ".codex-dispatch-intent.lock"
MAX_DISPATCH_EVENT_BYTES = 1024 * 1024
PERMISSION_PROFILE = "rab-benchmark"
CHATGPT_LOGIN_LINE = "Logged in using ChatGPT"
CODEX_CREDENTIAL_COMMITMENT_KIND = "grabowski.codex_credential_commitment"
CODEX_CREDENTIAL_COMMITMENT_DOMAIN = "grabowski.codex-credential-commitment.v1"
ALLOWED_MCP = {"ask_context", "grounding_verify", "live_freshness", "repobrief_resource_read"}
UPSTREAM_MCP = {"ask_context", "grounding_verify", "live_freshness"}
REPOGROUND_MCP_SCHEMA_CONTRACT_COMMIT = "9c24c2887b4b5724686a5051e5feb8aa54783019"
EXPECTED_REPOGROUND_READ_ONLY_KIND = "repobrief.mcp.read_only_frontdoor"
EXPECTED_REPOGROUND_READ_ONLY_VERSION = "v1"
EXPECTED_REPOGROUND_FRESHNESS_VALUES = ("fresh", "stale", "unknown", "not_comparable")
EXPECTED_REPOGROUND_FRESHNESS_DOES_NOT_ESTABLISH = (
    "freshness_against_remote",
    "remote_branch_state",
    "pull_request_diff_current",
    "runtime_correctness",
    "repo_understood",
    "merge_readiness",
)
EXPECTED_REPOGROUND_FRONTDOOR_DOES_NOT_ESTABLISH = (
    "truth",
    "correctness",
    "completeness",
    "runtime_behavior",
    "test_sufficiency",
    "regression_absence",
    "repo_understood",
    "claims_true",
    "forensic_ready",
    "review_complete",
    "pr_mergeable",
    "mcp_server_available",
)
EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH = (
    "actual_reading_proven",
    "answer_correct",
    "repo_understood",
    "all_relevant_context_used",
    "claims_true",
    "test_sufficiency",
    "regression_absence",
    "runtime_behavior",
    "forensic_ready",
    "merge_readiness",
    "security_correctness",
)
EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS = (
    "implicit_refresh",
    "git_mutation",
    "snapshot_creation_on_read",
    "patch_application",
    "pull_request_mutation",
    "shell_execution",
    "merge_authorization",
)
EXPECTED_ASK_CONTEXT_PACK_KIND = "repobrief.ask_context_pack"
EXPECTED_ASK_CONTEXT_PACK_VERSION = "1.0"
EXPECTED_GROUNDING_VERDICT_KIND = "repobrief.answer_grounding_verdict"
EXPECTED_GROUNDING_VERDICT_VERSION = "1.0"
EXPECTED_GROUNDING_VERDICT_STATUSES = frozenset(
    {"pass", "fail", "warn", "degraded", "not_applicable"}
)
_REPOGROUND_SELECTOR_PROPERTIES: dict[str, Any] = {
    "bundle_manifest": {
        "type": ["string", "null"],
        "description": "Optional exact manifest path inside the startup bundle root.",
    },
    "repo": {
        "type": ["string", "null"],
        "description": "Repository identity such as owner/repository or repository name.",
    },
    "stem": {
        "type": ["string", "null"],
        "description": "Optional exact snapshot stem.",
    },
}


def _repoground_schema(
    properties: Mapping[str, Any], required: Sequence[str] = ()
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {**_REPOGROUND_SELECTOR_PROPERTIES, **dict(properties)},
        "required": list(required),
        "additionalProperties": False,
    }


EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "ask_context": _repoground_schema(
        {
            "query": {"type": "string"},
            "task_profile": {"type": "string", "default": "basic_repo_question"},
            "max_context_tokens": {"type": "integer", "minimum": 1, "default": 8000},
            "max_answer_tokens": {"type": "integer", "minimum": 1, "default": 1200},
            "k": {"type": "integer", "minimum": 1, "maximum": 100, "default": 5},
            "verbose": {"type": "boolean", "default": False},
        },
        ("query",),
    ),
    "grounding_verify": _repoground_schema(
        {
            "declaration": {"type": "object"},
            "citation_map": {"type": ["string", "null"]},
            "task_profile": {"type": ["string", "null"]},
            "verbose": {"type": "boolean", "default": False},
        },
        ("declaration",),
    ),
    "live_freshness": _repoground_schema({}),
}
_REPOGROUND_READ_ANNOTATIONS: dict[str, bool] = {
    'readOnlyHint': True,
    'destructiveHint': False,
    'idempotentHint': True,
}
EXPECTED_UPSTREAM_MCP_DESCRIPTORS: dict[str, dict[str, Any]] = {
    'ask_context': {'name': 'ask_context', 'title': 'RepoGround context pack', 'description': 'Build a cited context pack from one existing RepoGround bundle.', 'inputSchema': EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS['ask_context'], 'annotations': _REPOGROUND_READ_ANNOTATIONS},
    'grounding_verify': {'name': 'grounding_verify', 'title': 'RepoGround grounding verifier', 'description': 'Verify declared citations and ranges against an existing RepoGround bundle.', 'inputSchema': EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS['grounding_verify'], 'annotations': _REPOGROUND_READ_ANNOTATIONS},
    'live_freshness': {'name': 'live_freshness', 'title': 'RepoGround live freshness', 'description': 'Compare snapshot Git provenance with the configured local checkout without refreshing it.', 'inputSchema': EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS['live_freshness'], 'annotations': _REPOGROUND_READ_ANNOTATIONS},
}
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


def _credential_commitment_sha256(credential_data: bytes, nonce: str) -> str:
    credential_sha256 = sha_bytes(credential_data)
    payload = canonical(
        {
            "domain": CODEX_CREDENTIAL_COMMITMENT_DOMAIN,
            "nonce": nonce,
            "credential_sha256": credential_sha256,
        }
    ).encode("utf-8")
    return sha_bytes(payload)


def _validated_authorized_authentication(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "mode", "credential_digest_public", "credential_bytes", "commitment"
    }:
        raise RunnerError("preflight dispatch authorization authentication is invalid")
    commitment = value.get("commitment")
    if (
        value.get("mode") != "chatgpt_subscription"
        or value.get("credential_digest_public") is not False
        or not isinstance(value.get("credential_bytes"), int)
        or isinstance(value.get("credential_bytes"), bool)
        or value.get("credential_bytes") <= 0
        or not isinstance(commitment, dict)
        or set(commitment) != {
            "schema_version", "kind", "nonce", "commitment_sha256"
        }
        or commitment.get("schema_version") != 1
        or commitment.get("kind") != CODEX_CREDENTIAL_COMMITMENT_KIND
        or not isinstance(commitment.get("nonce"), str)
        or re.fullmatch(r"[0-9a-f]{32}", commitment["nonce"]) is None
        or not isinstance(commitment.get("commitment_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", commitment["commitment_sha256"]) is None
    ):
        raise RunnerError("preflight dispatch authorization authentication is invalid")
    return json.loads(json.dumps(value))


def _assert_authorized_chatgpt_auth(
    auth_data: bytes, expected: Mapping[str, Any]
) -> None:
    if len(auth_data) != expected.get("credential_bytes"):
        raise RunnerError("ChatGPT credential does not match preflight authorization")
    commitment = expected.get("commitment")
    if not isinstance(commitment, Mapping):
        raise RunnerError("ChatGPT credential authorization is unavailable")
    nonce = commitment.get("nonce")
    expected_digest = commitment.get("commitment_sha256")
    if not isinstance(nonce, str) or not isinstance(expected_digest, str):
        raise RunnerError("ChatGPT credential authorization is unavailable")
    actual = _credential_commitment_sha256(auth_data, nonce)
    if not hmac.compare_digest(actual, expected_digest):
        raise RunnerError("ChatGPT credential does not match preflight authorization")


def _valid_jsonrpc_request_id(value: Any) -> bool:
    return isinstance(value, str) or (
        isinstance(value, int) and not isinstance(value, bool)
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _preflight_request_projection(request: Mapping[str, Any]) -> dict[str, Any]:
    """Legacy Claude projection retained only for negative authorization regression tests."""

    shadow = json.loads(json.dumps(request))
    shadow["runner"] = {
        "execution_contract": base.EXECUTION_CONTRACT,
        "provider": base.PROVIDER,
        "model": "claude-haiku-4-5-20251001",
        "sampling": {},
    }
    return shadow


def validate_request(request: Mapping[str, Any]) -> None:
    """Validate provider-neutral invariants, then bind the exact Codex contract."""

    base._validate_request_common(request)
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
    source_environment = provider_env(codex=codex)
    home_text = source_environment.get("HOME")
    if not home_text or not Path(home_text).is_absolute():
        raise RunnerError("HOME is unavailable for Codex ChatGPT authentication")
    auth_data = _read_chatgpt_auth_file(Path(home_text))

    # Snapshot the exact credential bytes before asking Codex what login mode
    # they represent.  The real run later stages these returned bytes again, so
    # status validation and provider execution are byte-identical even if the
    # user's mutable ~/.codex/auth.json changes concurrently.
    with tempfile.TemporaryDirectory(prefix="grabowski-codex-auth-") as temporary:
        snapshot_root = Path(temporary)
        snapshot_root.chmod(0o700)
        snapshot_home = stage_codex_home(snapshot_root, auth_data)
        try:
            environment = provider_env(codex=codex, codex_home=snapshot_home)
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
            staged = _read_bound_regular_file(
                snapshot_home / "auth.json",
                label="staged Codex ChatGPT auth file",
                max_bytes=MAX_AUTH_BYTES,
            )
            if staged != auth_data:
                raise RunnerError("staged Codex ChatGPT auth bytes changed during validation")
        except BaseException:
            cleanup_codex_home(snapshot_home)
            raise
        cleanup_error = cleanup_codex_home(snapshot_home)
        if cleanup_error is not None:
            raise RunnerError("Codex ChatGPT auth snapshot cleanup failed")
    return auth_data

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

def _write_private_dirfd(
    descriptor: int, name: str, data: bytes, *, mode: int = 0o600
) -> None:
    if Path(name).name != name or not name:
        raise RunnerError("private artifact name is unsafe")
    if mode not in {0o600, 0o700}:
        raise RunnerError("private artifact mode is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(name, flags, mode, dir_fd=descriptor)
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


def _validated_resource_read_result(value: Any, *, expected_uri: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"contents", "_meta"}:
        raise RunnerError("RepoGround resource read result is malformed")
    contents = value.get("contents")
    if not isinstance(contents, list) or len(contents) != 1:
        raise RunnerError("RepoGround resource read result must contain exactly one item")
    item = contents[0]
    if not isinstance(item, dict) or set(item) != {"uri", "mimeType", "text"}:
        raise RunnerError("RepoGround resource read content item is malformed")
    if item.get("uri") != expected_uri:
        raise RunnerError("RepoGround resource read URI does not match the frozen request")
    mime_type = item.get("mimeType")
    if (
        not isinstance(mime_type, str)
        or not mime_type
        or len(mime_type.encode("utf-8")) > 256
    ):
        raise RunnerError("RepoGround resource read mimeType is invalid")
    if not isinstance(item.get("text"), str):
        raise RunnerError("RepoGround resource read text is invalid")
    if not isinstance(value.get("_meta"), dict):
        raise RunnerError("RepoGround resource read metadata is malformed")
    return json.loads(json.dumps(value))


def _validated_live_freshness_payload(
    value: Any, *, expected_manifest: Path
) -> dict[str, Any]:
    common = {
        "kind", "version", "status", "reason", "bundle_manifest", "repo_root",
        "read_only_git_probe", "implicit_refresh", "does_not_establish",
    }
    extended = common | {"freshness_values", "snapshot_provenance", "current_provenance"}
    if not isinstance(value, dict) or frozenset(value) not in {frozenset(common), frozenset(extended)}:
        raise RunnerError("RepoGround live_freshness payload is malformed")
    if (
        value.get("kind") != "repobrief.live_freshness"
        or value.get("version") != "v1"
        or value.get("status") not in EXPECTED_REPOGROUND_FRESHNESS_VALUES
        or not isinstance(value.get("reason"), str)
        or not value.get("reason")
        or value.get("bundle_manifest") != str(expected_manifest)
        or (value.get("repo_root") is not None and not isinstance(value.get("repo_root"), str))
        or not isinstance(value.get("read_only_git_probe"), bool)
        or value.get("implicit_refresh") is not False
        or value.get("does_not_establish") != list(EXPECTED_REPOGROUND_FRESHNESS_DOES_NOT_ESTABLISH)
    ):
        raise RunnerError("RepoGround live_freshness payload is malformed")
    if set(value) == extended:
        if (
            value.get("freshness_values") != list(EXPECTED_REPOGROUND_FRESHNESS_VALUES)
            or (value.get("snapshot_provenance") is not None and not isinstance(value.get("snapshot_provenance"), dict))
            or (value.get("current_provenance") is not None and not isinstance(value.get("current_provenance"), dict))
        ):
            raise RunnerError("RepoGround live_freshness payload is malformed")
    return json.loads(json.dumps(value))


def _validated_read_only_frontdoor_projection(value: Mapping[str, Any]) -> None:
    boundary = value.get("mutation_boundary")
    if not isinstance(boundary, dict) or boundary.get("writes") != []:
        raise RunnerError("RepoGround treatment tool read-only boundary is malformed")
    guarded_booleans = {
        "read_only": True,
        "read_paths_do_not_refresh": True,
        "not_reachable_from_snapshot_create": True,
        "explicit_write_tool": False,
    }
    for field, expected in guarded_booleans.items():
        if field in boundary and boundary.get(field) is not expected:
            raise RunnerError("RepoGround treatment tool read-only boundary is malformed")
    forbidden = boundary.get("forbidden_operations")
    if forbidden is not None and (
        not isinstance(forbidden, list)
        or not {"secret_read", "snapshot_create_side_effect"}.issubset(set(forbidden))
    ):
        raise RunnerError("RepoGround treatment tool read-only boundary is malformed")
    dne = value.get("does_not_establish")
    expected_items = list(EXPECTED_REPOGROUND_FRONTDOOR_DOES_NOT_ESTABLISH)
    if isinstance(dne, list):
        valid_dne = dne == expected_items
    elif isinstance(dne, dict):
        valid_dne = (
            set(dne) == {"ref", "items"}
            and dne.get("ref") == "repobrief.does_not_establish.default.v1"
            and dne.get("items") == expected_items
        )
    else:
        valid_dne = False
    if not valid_dne:
        raise RunnerError("RepoGround treatment tool non-claim projection is malformed")


def _validated_ask_context_pack(value: Any) -> dict[str, Any]:
    base_keys = {
        "kind", "version", "request_id", "snapshot_ref", "freshness",
        "availability", "required_reading", "retrieval",
        "retrieval_infrastructure", "retrieval_hits", "resolved_ranges",
        "answer_scaffold", "budget", "forbidden_operations",
        "does_not_establish",
    }
    if not isinstance(value, dict) or frozenset(value) not in {
        frozenset(base_keys), frozenset(base_keys | {"structured_evidence"})
    }:
        raise RunnerError("RepoGround ask_context context pack is malformed")
    request_id = value.get("request_id")
    if (
        value.get("kind") != EXPECTED_ASK_CONTEXT_PACK_KIND
        or value.get("version") != EXPECTED_ASK_CONTEXT_PACK_VERSION
        or not isinstance(request_id, str)
        or re.fullmatch(r"[0-9a-f]{16}", request_id) is None
        or not all(isinstance(value.get(name), dict) for name in (
            "snapshot_ref", "freshness", "availability", "required_reading",
            "retrieval", "retrieval_infrastructure", "answer_scaffold", "budget"
        ))
        or not isinstance(value.get("retrieval_hits"), list)
        or not isinstance(value.get("resolved_ranges"), list)
        or value.get("forbidden_operations") != list(EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS)
        or value.get("does_not_establish") != list(EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH)
        or ("structured_evidence" in value and not isinstance(value.get("structured_evidence"), dict))
    ):
        raise RunnerError("RepoGround ask_context context pack is malformed")
    freshness = value["freshness"]
    availability = value["availability"]
    infrastructure = value["retrieval_infrastructure"]
    if (
        freshness.get("status") not in {"fresh", "stale", "unknown", "not_comparable", "not_applicable"}
        or availability.get("status") not in {"available", "partial", "missing", "unknown"}
        or infrastructure.get("status") not in {"available", "missing", "invalid", "unknown"}
    ):
        raise RunnerError("RepoGround ask_context context pack is malformed")
    scaffold = value["answer_scaffold"]
    if (
        set(scaffold) != {"citation_obligations", "caveats_to_surface", "non_claims_to_surface"}
        or not isinstance(scaffold.get("citation_obligations"), list)
        or not isinstance(scaffold.get("caveats_to_surface"), list)
        or scaffold.get("non_claims_to_surface") != list(EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH)
    ):
        raise RunnerError("RepoGround ask_context context pack is malformed")
    budget = value["budget"]
    budget_keys = {
        "max_context_tokens", "token_derived_byte_ceiling", "max_context_bytes",
        "max_answer_tokens", "context_bytes_used",
        "context_unicode_characters_used", "approx_context_chars_used",
        "byte_budget_is_hard", "unit", "accounting", "omissions",
        "truncated", "does_not_establish_quality",
    }
    integer_fields = (
        "max_context_tokens", "token_derived_byte_ceiling", "max_context_bytes",
        "max_answer_tokens", "context_bytes_used",
        "context_unicode_characters_used", "approx_context_chars_used",
    )
    if (
        set(budget) != budget_keys
        or any(
            isinstance(budget.get(name), bool)
            or not isinstance(budget.get(name), int)
            or budget.get(name) < 0
            for name in integer_fields
        )
        or budget.get("byte_budget_is_hard") is not True
        or budget.get("unit") != "utf8_bytes"
        or not isinstance(budget.get("accounting"), str)
        or not budget.get("accounting")
        or not isinstance(budget.get("omissions"), list)
        or not isinstance(budget.get("truncated"), bool)
        or budget.get("does_not_establish_quality") is not True
    ):
        raise RunnerError("RepoGround ask_context context pack is malformed")
    return json.loads(json.dumps(value))


def _validated_grounding_verdict(value: Any) -> dict[str, Any]:
    expected_keys = {
        "kind", "version", "status", "checked_declaration", "snapshot_ref",
        "citation_checks", "range_checks", "required_reading_checks",
        "diagnostics", "freshness_caveats", "availability_caveats",
        "does_not_establish",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("kind") != EXPECTED_GROUNDING_VERDICT_KIND
        or value.get("version") != EXPECTED_GROUNDING_VERDICT_VERSION
        or value.get("status") not in EXPECTED_GROUNDING_VERDICT_STATUSES
        or not isinstance(value.get("checked_declaration"), dict)
        or not isinstance(value.get("snapshot_ref"), dict)
        or any(
            not isinstance(value.get(name), list)
            for name in (
                "citation_checks", "range_checks", "required_reading_checks",
                "diagnostics", "freshness_caveats", "availability_caveats"
            )
        )
        or any(
            not isinstance(item, dict)
            for name in ("citation_checks", "range_checks", "required_reading_checks", "diagnostics")
            for item in value.get(name, [])
        )
        or value.get("does_not_establish") != list(EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH)
    ):
        raise RunnerError("RepoGround grounding_verify verdict is malformed")
    return json.loads(json.dumps(value))


def _validated_treatment_structured_payload(
    value: Any, *, tool_name: str, expected_manifest: Path, is_error: bool
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError("RepoGround treatment tool structured payload is malformed")
    if is_error:
        if (
            set(value) != {"status", "tool", "error"}
            or value.get("status") != "error"
            or value.get("tool") != tool_name
            or not isinstance(value.get("error"), str)
            or not value.get("error")
        ):
            raise RunnerError("RepoGround treatment tool structured payload is malformed")
        return json.loads(json.dumps(value))
    if tool_name == "live_freshness":
        return _validated_live_freshness_payload(value, expected_manifest=expected_manifest)
    common = {
        "kind", "version", "tool", "status", "mutation_boundary",
        "does_not_establish", "live_freshness",
    }
    if tool_name == "ask_context":
        expected_keys = common | {"context_pack", "request_semantics", "context_pack_semantics"}
        valid = (
            set(value) == expected_keys
            and value.get("kind") == EXPECTED_REPOGROUND_READ_ONLY_KIND
            and value.get("version") == EXPECTED_REPOGROUND_READ_ONLY_VERSION
            and value.get("tool") == "ask_context"
            and value.get("status") == "ok"
            and value.get("request_semantics") == "repobrief.ask_request.v1"
            and value.get("context_pack_semantics") == "repobrief.ask_context_pack.v1"
        )
    elif tool_name == "grounding_verify":
        expected_keys = common | {"verdict", "declaration_semantics", "verdict_semantics"}
        verdict = _validated_grounding_verdict(value.get("verdict"))
        verdict_status = verdict["status"]
        valid = (
            set(value) == expected_keys
            and value.get("kind") == EXPECTED_REPOGROUND_READ_ONLY_KIND
            and value.get("version") == EXPECTED_REPOGROUND_READ_ONLY_VERSION
            and value.get("tool") == "grounding_verify"
            and isinstance(value.get("status"), str)
            and value.get("status") == verdict_status
            and value.get("declaration_semantics") == "repobrief.answer_grounding_declaration.v1"
            and value.get("verdict_semantics") == "repobrief.answer_grounding_verdict.v1"
        )
    else:
        raise RunnerError("RepoGround treatment tool response is not authorized")
    if not valid:
        raise RunnerError("RepoGround treatment tool structured payload is malformed")
    _validated_read_only_frontdoor_projection(value)
    if tool_name == "ask_context":
        _validated_ask_context_pack(value.get("context_pack"))
    _validated_live_freshness_payload(
        value.get("live_freshness"), expected_manifest=expected_manifest
    )
    return json.loads(json.dumps(value))


def _validated_treatment_tool_result(
    value: Any, *, tool_name: str, expected_manifest: Path
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"content", "structuredContent", "isError"}:
        raise RunnerError("RepoGround treatment tool result is malformed")
    content = value.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise RunnerError("RepoGround treatment tool result is malformed")
    item = content[0]
    if (
        not isinstance(item, dict)
        or set(item) != {"type", "text"}
        or item.get("type") != "text"
        or not isinstance(item.get("text"), str)
        or not item.get("text")
    ):
        raise RunnerError("RepoGround treatment tool result is malformed")
    is_error = value.get("isError")
    if not isinstance(is_error, bool):
        raise RunnerError("RepoGround treatment tool result is malformed")
    structured = _validated_treatment_structured_payload(
        value.get("structuredContent"),
        tool_name=tool_name,
        expected_manifest=expected_manifest,
        is_error=is_error,
    )
    return {
        "content": [{"type": "text", "text": canonical(structured)}],
        "structuredContent": structured,
        "isError": is_error,
    }


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
            expected_schema = EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS[str(name)]
            if canonical(item.get("inputSchema")) != canonical(expected_schema):
                raise RunnerError(
                    f"RepoGround treatment tool inputSchema drifted for {name}"
                )
            expected_descriptor = EXPECTED_UPSTREAM_MCP_DESCRIPTORS[str(name)]
            if canonical(item) != canonical(expected_descriptor):
                raise RunnerError(f'RepoGround treatment tool descriptor drifted for {name}')
            counts[str(name)] += 1
            filtered.append(json.loads(json.dumps(expected_descriptor)))
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


def _read_bounded_mcp_line(stream: Any, *, peer: str) -> bytes:
    raw = stream.readline(base.MAX_MCP_MESSAGE_BYTES + 1)
    if len(raw) > base.MAX_MCP_MESSAGE_BYTES:
        raise RunnerError(f"MCP {peer} message too large")
    if raw and not raw.endswith(b'\n'):
        raise RunnerError(f'MCP {peer} message must be newline terminated')
    return raw



def _normalized_authorized_mcp_files(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RunnerError("preflight MCP command file authorization is missing")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected_keys = {"path", "bytes", "sha256", "mode"}
    for item in value:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise RunnerError("preflight MCP command file authorization is invalid")
        path_text = item.get("path")
        size = item.get("bytes")
        digest = item.get("sha256")
        mode = item.get("mode")
        if (
            not isinstance(path_text, str)
            or not Path(path_text).is_absolute()
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > MAX_PROVIDER_EXECUTABLE_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(mode, str)
            or re.fullmatch(r"0o[0-7]{3}", mode) is None
            or path_text in seen
        ):
            raise RunnerError("preflight MCP command file authorization is invalid")
        seen.add(path_text)
        result.append({"path": path_text, "bytes": size, "sha256": digest, "mode": mode})
    return result


def _mcp_authorization_identity(binding: Mapping[str, Any]) -> dict[str, Any]:
    identity = binding.get("identity")
    digest = binding.get("sha256")
    path = binding.get("path")
    if (
        not isinstance(identity, tuple)
        or len(identity) != 4
        or not isinstance(path, Path)
        or not isinstance(digest, str)
    ):
        raise RunnerError("MCP runtime file binding is invalid")
    return {
        "path": str(path.resolve(strict=True)),
        "bytes": int(identity[2]),
        "sha256": digest,
        "mode": oct(stat.S_IMODE(int(identity[3]))),
    }


def _require_private_ledger_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        raise RunnerError(f"{label} is unsafe")


_AUTHORIZED_RUNTIME_CODE_NAMES = (
    "repobrief_agent_benchmark_preflight_core.py",
    "repobrief_agent_benchmark_codex_preflight.py",
    "repobrief_agent_benchmark_runner.py",
    ENTRYPOINT_BOOTSTRAP_NAME,
    Path(__file__).name,
)


def _runtime_code_path(name: str) -> Path:
    if name not in _AUTHORIZED_RUNTIME_CODE_NAMES:
        raise RunnerError("preflight dispatch authorization code identity is unexpected")
    try:
        path = Path(__file__).with_name(name).resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"authorized runtime code is unavailable: {name}") from exc
    return path


def _validated_authorized_runtime_code(code: Any) -> dict[str, dict[str, Any]]:
    files = code.get("files") if isinstance(code, dict) else None
    bundle_sha256 = code.get("bundle_sha256") if isinstance(code, dict) else None
    if (
        not isinstance(files, list)
        or len(files) != len(_AUTHORIZED_RUNTIME_CODE_NAMES)
        or not isinstance(bundle_sha256, str)
        or bundle_sha256 != base._sha256_json(files)
    ):
        raise RunnerError("preflight dispatch authorization code identity is invalid")
    executed_identities = {
        Path(__file__).name: globals().get(
            "__grabowski_source_identity__", _SELF_SOURCE_IDENTITY
        ),
        BASE_PATH.name: getattr(base, "__grabowski_source_identity__", None),
        ENTRYPOINT_BOOTSTRAP_NAME: _ENTRYPOINT_BOOTSTRAP_IDENTITY,
    }
    by_name: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise RunnerError("preflight dispatch authorization code identity is invalid")
        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or name in by_name
            or name not in _AUTHORIZED_RUNTIME_CODE_NAMES
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise RunnerError("preflight dispatch authorization code identity is invalid")
        executed = executed_identities.get(name)
        if executed is not None:
            executed_projection = (
                {
                    "name": executed.get("name"),
                    "bytes": executed.get("bytes"),
                    "sha256": executed.get("sha256"),
                }
                if isinstance(executed, dict)
                else None
            )
            if executed_projection != {
                "name": name,
                "bytes": size,
                "sha256": digest,
            }:
                raise RunnerError(
                    f"authorized runtime code differs from executed bytes: {name}"
                )
        path = _runtime_code_path(name)
        current = _read_bound_regular_file(
            path, label=f"authorized runtime code {name}",
            max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES,
        )
        if len(current) != size or sha_bytes(current) != digest:
            raise RunnerError(f"authorized runtime code changed after preflight: {name}")
        by_name[name] = {"name": name, "bytes": size, "sha256": digest}
    if set(by_name) != set(_AUTHORIZED_RUNTIME_CODE_NAMES):
        raise RunnerError("preflight dispatch authorization code identity is incomplete")
    return by_name


def _validated_authorized_codex_provider(
    provider: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    codex = provider.get("codex") if isinstance(provider, dict) else None
    authentication = (
        provider.get("authentication") if isinstance(provider, dict) else None
    )
    if not isinstance(codex, dict):
        raise RunnerError("preflight dispatch authorization Codex identity is missing")
    path = codex.get("path")
    size = codex.get("bytes")
    digest = codex.get("sha256")
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise RunnerError("preflight dispatch authorization Codex identity is invalid")
    return (
        {"path": path, "bytes": size, "sha256": digest},
        _validated_authorized_authentication(authentication),
    )


def _assert_authorized_codex_executable(
    codex: str, codex_command_sha256: str, expected: Mapping[str, Any]
) -> None:
    path = Path(codex)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RunnerError("Codex executable disappeared after validation") from exc
    current = {
        "path": str(resolved),
        "bytes": metadata.st_size,
        "sha256": codex_command_sha256,
    }
    if canonical(current) != canonical(dict(expected)):
        raise RunnerError("Codex executable does not match preflight authorization")


def _runtime_file_snapshot(
    path: Path, *, label: str, max_bytes: int
) -> tuple[dict[str, Any], bytes]:
    requested = path.expanduser()
    if not requested.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    try:
        linked = requested.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if linked.st_size < 0 or linked.st_size > max_bytes:
        raise RunnerError(f"{label} size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(requested, flags)
    except OSError as exc:
        raise RunnerError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(
                descriptor, min(1024 * 1024, max_bytes + 1 - len(data))
            )
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    try:
        after = requested.lstat()
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"{label} disappeared during validation") from exc
    initial_identity = (linked.st_dev, linked.st_ino, linked.st_size, linked.st_mode)
    opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
    if initial_identity != opened_identity or opened_identity != after_identity:
        raise RunnerError(f"{label} changed during validation")
    if len(data) != opened.st_size or len(data) > max_bytes:
        raise RunnerError(f"{label} changed or exceeds its bound")
    raw = bytes(data)
    return (
        {
            "path": str(resolved),
            "bytes": len(raw),
            "sha256": sha_bytes(raw),
            "mode": oct(opened.st_mode & 0o777),
        },
        raw,
    )


def _runtime_file_identity(path: Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    identity, _raw = _runtime_file_snapshot(path, label=label, max_bytes=max_bytes)
    return identity


def _repository_root_from_authorized_map_bytes(
    request: Mapping[str, Any], raw: bytes
) -> Path:
    document = base._load_object_bytes(raw, label="authorized repository map")
    repository = base._mapping(request.get("repository"))
    repository_id = str(repository.get("id"))
    entry = base._mapping(document.get(repository_id))
    if set(entry) != {"repository", "root"}:
        raise RunnerError(f"repository map misses strict entry for {repository_id}")
    if entry.get("repository") != repository.get("repository"):
        raise RunnerError("repository map owner/name mismatch")
    root = Path(
        base._require_string(entry.get("root"), "repository map root")
    ).expanduser().resolve()
    if not root.is_dir() or not (root / ".git").exists():
        raise RunnerError("repository map root is not a Git checkout")
    return root

def _assert_all_authorized_request_files(
    binding: Mapping[str, Any], request_root: Path
) -> None:
    requests = binding.get("requests")
    if not isinstance(requests, dict) or set(requests) != {"baseline", "treatment"}:
        raise RunnerError("preflight dispatch authorization request bindings are incomplete")
    root = request_root.expanduser().resolve()
    for condition in ("baseline", "treatment"):
        expected_request = requests.get(condition)
        expected_file = (
            expected_request.get("file")
            if isinstance(expected_request, dict)
            else None
        )
        if (
            not isinstance(expected_file, dict)
            or not isinstance(expected_file.get("path"), str)
        ):
            raise RunnerError(
                f"preflight dispatch authorization {condition} request file identity is missing"
            )
        expected_path = Path(expected_file["path"])
        try:
            expected_path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise RunnerError(
                f"preflight dispatch authorization {condition} request file escapes request root"
            ) from exc
        current = _runtime_file_identity(
            expected_path,
            label=f"{condition} request",
            max_bytes=base.MAX_REQUEST_BYTES,
        )
        if canonical(expected_file) != canonical(current):
            raise RunnerError(
                f"preflight dispatch authorization {condition} request file identity mismatch"
            )


def _assert_authorized_runtime_binding(
    binding: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
) -> bytes:
    actual_paths = {
        "request_root": str(request_root.expanduser().resolve()),
        "state_root": str(state_root.expanduser().resolve()),
        "transcript_root": str(transcript_root.expanduser().resolve()),
        "evidence_root": str(evidence_root.expanduser().resolve()),
    }
    for field, actual in actual_paths.items():
        if binding.get(field) != actual:
            raise RunnerError(f"preflight dispatch authorization runtime binding mismatch: {field}")

    expected_map = binding.get("repository_map")
    if not isinstance(expected_map, dict):
        raise RunnerError("preflight dispatch authorization repository map identity is missing")
    current_map, repository_map_bytes = _runtime_file_snapshot(
        repository_map.expanduser(), label="repository map", max_bytes=base.MAX_REQUEST_BYTES
    )
    if canonical(expected_map) != canonical(current_map):
        raise RunnerError("preflight dispatch authorization repository map identity mismatch")

    _assert_all_authorized_request_files(binding, request_root)

    condition = request.get("condition")
    requests = binding.get("requests")
    expected_request = requests.get(condition) if isinstance(requests, dict) else None
    if not isinstance(condition, str) or not isinstance(expected_request, dict):
        raise RunnerError("preflight dispatch authorization request binding is missing")
    if (
        expected_request.get("request_id") != request.get("request_id")
        or expected_request.get("sha256") != base._sha256_json(request)
    ):
        raise RunnerError(
            f"preflight dispatch authorization does not bind this {condition} request"
        )
    return repository_map_bytes


def _preflight_report_evidence_projection(
    report: Mapping[str, Any],
) -> dict[str, Any]:
    projected = json.loads(canonical(report))
    ledger = projected.get("dispatch_ledger")
    if not isinstance(ledger, dict):
        raise RunnerError("preflight report ledger is invalid")
    ledger["authorization_sha256"] = None
    return projected


def _assert_preflight_report_evidence(
    authorization: Mapping[str, Any],
    binding: Mapping[str, Any],
    authorization_path: Path,
) -> None:
    report_evidence_sha256 = authorization.get("report_evidence_sha256")
    if (
        not isinstance(report_evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", report_evidence_sha256) is None
    ):
        raise RunnerError("preflight dispatch authorization report binding is invalid")

    report_text = binding.get("report_out")
    digest_text = binding.get("report_digest_out")
    if not isinstance(report_text, str) or not isinstance(digest_text, str):
        raise RunnerError("preflight report binding is unavailable")
    report_path = Path(report_text)
    digest_path = Path(digest_text)
    if (
        not report_path.is_absolute()
        or not digest_path.is_absolute()
        or digest_path != Path(str(report_path) + ".sha256")
    ):
        raise RunnerError("preflight report binding is invalid")

    report_raw = _read_bound_regular_file(
        report_path,
        label="preflight report",
        max_bytes=MAX_PREFLIGHT_REPORT_BYTES,
    )
    digest_raw = _read_bound_regular_file(
        digest_path,
        label="preflight report digest",
        max_bytes=MAX_PREFLIGHT_REPORT_DIGEST_BYTES,
    )
    for candidate, label in (
        (report_path, "preflight report"),
        (digest_path, "preflight report digest"),
    ):
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise RunnerError(f"{label} disappeared") from exc
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise RunnerError(f"{label} permissions are unsafe")

    expected_digest = (
        f"{sha_bytes(report_raw)}  {report_path.name}\n".encode("ascii")
    )
    if not hmac.compare_digest(digest_raw, expected_digest):
        raise RunnerError("preflight report digest mismatch")

    report = base._load_object_bytes(report_raw, label="preflight report")
    ledger = report.get("dispatch_ledger")
    requests = binding.get("requests")
    expected_request_sha256 = (
        {
            condition: value.get("sha256")
            for condition, value in requests.items()
        }
        if isinstance(requests, dict)
        and set(requests) == {"baseline", "treatment"}
        and all(isinstance(value, dict) for value in requests.values())
        else None
    )
    snapshot = report.get("snapshot")
    authorization_sha256 = base._sha256_json(authorization)
    if (
        report.get("kind") != PREFLIGHT_AUTHORIZATION_REPORT_KIND
        or report.get("version") != "1.0"
        or report.get("status") != "authorized"
        or report.get("pair_id") != binding.get("pair_id")
        or report.get("synthetic_fixture") is not False
        or report.get("default_promoted") is not False
        or expected_request_sha256 is None
        or report.get("request_sha256") != expected_request_sha256
        or canonical(report.get("provider")) != canonical(binding.get("provider"))
        or not isinstance(snapshot, dict)
        or snapshot.get("status") != "fresh"
        or not isinstance(ledger, dict)
        or ledger.get("authorization") != str(authorization_path)
        or ledger.get("authorization_sha256") != authorization_sha256
        or ledger.get("contract_sha256") != authorization.get("contract_sha256")
        or ledger.get("retry_permitted") is not False
    ):
        raise RunnerError("preflight report does not prove this dispatch authorization")

    actual_evidence_sha256 = base._sha256_json(
        _preflight_report_evidence_projection(report)
    )
    if not hmac.compare_digest(actual_evidence_sha256, report_evidence_sha256):
        raise RunnerError("preflight report evidence binding mismatch")


def _load_preflight_dispatch_authorization(
    request: Mapping[str, Any],
    state_root: Path,
    *,
    runtime_binding: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    condition = request.get("condition")
    if condition not in {"baseline", "treatment"}:
        raise RunnerError("preflight dispatch authorization condition is invalid")
    pair_id = request.get("pair_id")
    if not isinstance(pair_id, str) or not pair_id:
        raise RunnerError("preflight dispatch authorization pair ID is invalid")
    pair_digest = hashlib.sha256(pair_id.encode("utf-8")).hexdigest()
    ledger_root = state_root / "preflight-dispatch-ledger"
    pair_root = ledger_root / pair_digest
    _require_private_ledger_directory(ledger_root, label="preflight dispatch ledger")
    _require_private_ledger_directory(pair_root, label="preflight dispatch pair ledger")
    authorization_path = pair_root / "authorization.json"
    raw = _read_bound_regular_file(
        authorization_path,
        label="preflight dispatch authorization",
        max_bytes=MAX_DISPATCH_AUTHORIZATION_BYTES,
    )
    try:
        metadata = authorization_path.lstat()
    except OSError as exc:
        raise RunnerError("preflight dispatch authorization disappeared") from exc
    if metadata.st_mode & 0o077:
        raise RunnerError("preflight dispatch authorization permissions are unsafe")
    authorization = base._load_object_bytes(raw, label="preflight dispatch authorization")
    if (
        authorization.get("kind") != PREFLIGHT_LEDGER_KIND
        or authorization.get("version") != PREFLIGHT_LEDGER_VERSION
        or authorization.get("retry_permitted") is not False
    ):
        raise RunnerError("preflight dispatch authorization contract is invalid")
    binding = authorization.get("binding")
    contract_sha256 = authorization.get("contract_sha256")
    if (
        not isinstance(binding, dict)
        or not isinstance(contract_sha256, str)
        or contract_sha256 != base._sha256_json(binding)
    ):
        raise RunnerError("preflight dispatch authorization binding is invalid")
    if binding.get("pair_id") != pair_id or binding.get("state_root") != str(state_root.resolve()):
        raise RunnerError("preflight dispatch authorization does not bind this pair/state root")

    requests = binding.get("requests")
    selected = requests.get(condition) if isinstance(requests, dict) else None
    if (
        not isinstance(selected, dict)
        or selected.get("request_id") != request.get("request_id")
        or selected.get("sha256") != base._sha256_json(request)
    ):
        raise RunnerError(
            f"preflight dispatch authorization does not bind this {condition} request"
        )

    _assert_preflight_report_evidence(authorization, binding, authorization_path)

    repository_map_bytes: bytes | None = None
    if runtime_binding is not None:
        required = {"request_root", "repository_map", "transcript_root", "evidence_root"}
        if set(runtime_binding) != required or not all(
            isinstance(runtime_binding[name], Path) for name in required
        ):
            raise RunnerError("runtime dispatch binding inputs are incomplete")
        repository_map_bytes = _assert_authorized_runtime_binding(
            binding,
            request,
            request_root=runtime_binding["request_root"],
            repository_map=runtime_binding["repository_map"],
            state_root=state_root,
            transcript_root=runtime_binding["transcript_root"],
            evidence_root=runtime_binding["evidence_root"],
        )

    code_files = _validated_authorized_runtime_code(binding.get("code"))
    provider_codex, provider_authentication = _validated_authorized_codex_provider(
        binding.get("provider")
    )
    result: dict[str, Any] = {
        "authorization": dict(authorization),
        "mcp_files": [],
        "proxy_code": None,
        "proxy_base_code": None,
        "manifest": None,
        "provider_codex": provider_codex,
        "provider_authentication": provider_authentication,
        "code_files": [dict(code_files[name]) for name in _AUTHORIZED_RUNTIME_CODE_NAMES],
        "binding": dict(binding),
        "repository_map_bytes": repository_map_bytes,
    }
    if condition == "baseline":
        return result

    repobrief = request.get("repobrief")
    if not isinstance(repobrief, dict):
        raise RunnerError("treatment RepoGround binding is invalid")
    command = repobrief.get("mcp_command")
    if binding.get("mcp_command_sha256") != base._sha256_json(command):
        raise RunnerError("preflight dispatch authorization MCP command mismatch")
    manifest = Path(str(repobrief.get("manifest")))
    current_manifest = _runtime_file_identity(
        manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if (
        current_manifest["sha256"] != repobrief.get("manifest_sha256")
        or canonical(binding.get("manifest")) != canonical(current_manifest)
    ):
        raise RunnerError("preflight dispatch authorization manifest mismatch")
    result.update(
        {
            "mcp_files": _normalized_authorized_mcp_files(binding.get("mcp_command_files")),
            "proxy_code": dict(code_files[Path(__file__).name]),
            "proxy_base_code": dict(code_files[BASE_PATH.name]),
            "manifest": dict(current_manifest),
        }
    )
    return result



def _validated_dispatch_event_state(
    request: Mapping[str, Any], state_root: Path, authorization: Mapping[str, Any]
) -> dict[str, Any]:
    pair_id = str(request["pair_id"])
    pair_root = state_root / "preflight-dispatch-ledger" / hashlib.sha256(pair_id.encode()).hexdigest()
    events_root = pair_root / "events"
    _require_private_ledger_directory(events_root, label="preflight dispatch event ledger")
    entries = sorted(events_root.iterdir(), key=lambda path: path.name)
    if not 1 <= len(entries) <= 3:
        raise RunnerError("preflight dispatch event ledger cardinality is invalid")
    binding = authorization.get("binding")
    contract = authorization.get("contract_sha256")
    if not isinstance(binding, dict) or not isinstance(contract, str):
        raise RunnerError("preflight dispatch authorization binding is invalid")
    report_raw = _read_bound_regular_file(
        Path(str(binding.get("report_out"))),
        label="preflight report",
        max_bytes=MAX_PREFLIGHT_REPORT_BYTES,
    )
    report = base._load_object_bytes(report_raw, label="preflight report")
    ledger = report.get("dispatch_ledger")
    if (
        not isinstance(ledger, dict)
        or ledger.get("event_count") != 1
        or ledger.get("condition_intents") != []
        or ledger.get("provider_process_intents") != 0
        or ledger.get("retry_permitted") is not False
    ):
        raise RunnerError("preflight report initial dispatch ledger is invalid")
    previous = contract
    intents: list[str] = []
    authorized_sha256: str | None = None
    for sequence, path in enumerate(entries):
        event = base._load_object_bytes(
            _read_bound_regular_file(path, label="preflight dispatch event", max_bytes=MAX_DISPATCH_EVENT_BYTES),
            label="preflight dispatch event",
        )
        event_type = event.get("event")
        if (
            path.name != f"{sequence:04d}-{event_type}.json"
            or event.get("kind") != PREFLIGHT_EVENT_KIND
            or event.get("version") != PREFLIGHT_LEDGER_VERSION
            or event.get("sequence") != sequence
            or event.get("pair_id") != pair_id
            or event.get("contract_sha256") != contract
            or event.get("previous_event_sha256") != previous
        ):
            raise RunnerError("preflight dispatch event chain is invalid")
        event_sha256 = base._sha256_json(event)
        payload = event.get("payload")
        if sequence == 0:
            if (
                event_type != "authorized"
                or not isinstance(payload, dict)
                or payload.get("synthetic_fixture") is not False
                or payload.get("max_provider_processes") != 2
            ):
                raise RunnerError("preflight authorized event is invalid")
            authorized_sha256 = event_sha256
        else:
            condition = payload.get("condition") if isinstance(payload, dict) else None
            expected = binding.get("requests", {}).get(condition)
            if (
                event_type != "dispatch-intent"
                or condition not in {"baseline", "treatment"}
                or condition in intents
                or not isinstance(expected, dict)
                or payload.get("request_id") != expected.get("request_id")
                or payload.get("request_sha256") != expected.get("sha256")
                or payload.get("process_index") != len(intents) + 1
                or payload.get("synthetic_fixture") is not False
                or payload.get("max_cost_usd") != binding.get("max_cost_usd")
            ):
                raise RunnerError("preflight dispatch intent event is invalid")
            intents.append(str(condition))
        previous = event_sha256
    if authorized_sha256 != ledger.get("final_event_sha256"):
        raise RunnerError("preflight authorized event does not match durable report")
    return {"pair_root": pair_root, "events_root": events_root, "next_sequence": len(entries),
            "previous_event_sha256": previous, "condition_intents": intents}


def _record_preflight_dispatch_intent(
    request: Mapping[str, Any],
    state_root: Path,
    authorization: Mapping[str, Any],
) -> str:
    pair_id = str(request["pair_id"])
    pair_root = state_root / "preflight-dispatch-ledger" / hashlib.sha256(pair_id.encode()).hexdigest()
    pair_path, pair_fd = _open_private_directory(pair_root, create_final=False)
    lock_fd: int | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(DISPATCH_INTENT_LOCK_NAME, flags, 0o600, dir_fd=pair_fd)
        lock_stat = os.fstat(lock_fd)
        linked = os.stat(DISPATCH_INTENT_LOCK_NAME, dir_fd=pair_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
            or lock_stat.st_nlink != 1
            or (lock_stat.st_dev, lock_stat.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RunnerError("preflight dispatch intent lock is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _directory_fd_matches(pair_path, pair_fd)
        current_raw = _read_bound_regular_file(
            pair_root / "authorization.json",
            label="preflight dispatch authorization",
            max_bytes=MAX_DISPATCH_AUTHORIZATION_BYTES,
        )
        current = base._load_object_bytes(current_raw, label="preflight dispatch authorization")
        if canonical(current) != canonical(dict(authorization)):
            raise RunnerError("preflight dispatch authorization changed before intent")
        _assert_preflight_report_evidence(current, current["binding"], pair_root / "authorization.json")
        state = _validated_dispatch_event_state(request, state_root, current)
        condition = str(request.get("condition"))
        intents = list(state["condition_intents"])
        if condition in intents:
            raise RunnerError(f"preflight dispatch intent already exists for {condition}")
        if len(intents) >= 2:
            raise RunnerError("preflight dispatch ledger refuses a third provider process")
        sequence = int(state["next_sequence"])
        binding = current["binding"]
        event = {
            "kind": PREFLIGHT_EVENT_KIND,
            "version": PREFLIGHT_LEDGER_VERSION,
            "sequence": sequence,
            "event": "dispatch-intent",
            "recorded_at": iso(utc_now()),
            "pair_id": pair_id,
            "contract_sha256": current["contract_sha256"],
            "previous_event_sha256": state["previous_event_sha256"],
            "payload": {
                "condition": condition,
                "request_id": request["request_id"],
                "request_sha256": base._sha256_json(request),
                "process_index": len(intents) + 1,
                "synthetic_fixture": False,
                "max_cost_usd": binding.get("max_cost_usd"),
            },
        }
        events_path, events_fd = _open_private_directory(state["events_root"], create_final=False)
        try:
            _write_private_dirfd(
                events_fd,
                f"{sequence:04d}-dispatch-intent.json",
                (json.dumps(event, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"),
            )
            _directory_fd_matches(events_path, events_fd)
        finally:
            os.close(events_fd)
        return base._sha256_json(event)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(pair_fd)

def _load_preflight_mcp_authorization(
    request: Mapping[str, Any], state_root: Path
) -> list[dict[str, Any]]:
    return list(_load_preflight_dispatch_authorization(request, state_root)["mcp_files"])

def _bind_mcp_file(path: Path, *, label: str, executable: bool) -> dict[str, Any]:
    if not path.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if executable and linked.st_mode & 0o111 == 0:
        raise RunnerError(f"{label} is not executable")
    data = _read_bound_regular_file(path, label=label, max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES)
    after = path.lstat()
    return {
        "path": path,
        "identity": (after.st_dev, after.st_ino, after.st_size, after.st_mode),
        "sha256": sha_bytes(data),
    }


def _revalidate_mcp_file(binding: Mapping[str, Any], *, label: str) -> None:
    current = _bind_mcp_file(
        Path(binding["path"]), label=label, executable=label == "MCP executable"
    )
    if current["identity"] != binding["identity"] or current["sha256"] != binding["sha256"]:
        raise RunnerError(f"{label} changed during execution")


def _create_private_stage_directory(parent: Path, *, prefix: str) -> tuple[Path, int]:
    parent_path, parent_fd = _open_private_directory(parent)
    child_fd: int | None = None
    runtime_name: str | None = None
    try:
        for _attempt in range(4):
            candidate = prefix + sha_bytes(os.urandom(32))[:24]
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            runtime_name = candidate
            break
        if runtime_name is None:
            raise RunnerError("could not allocate unique private runtime stage")
        child_fd = os.open(runtime_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        child = os.fstat(child_fd)
        if child.st_uid != os.geteuid() or stat.S_IMODE(child.st_mode) != 0o700:
            raise RunnerError("private runtime stage permissions are unsafe")
        _directory_fd_matches(parent_path, parent_fd)
        os.fsync(parent_fd)
        return parent_path / runtime_name, child_fd
    except BaseException:
        if child_fd is not None:
            try:
                os.close(child_fd)
            except OSError:
                pass
            child_fd = None
        if runtime_name is not None:
            try:
                os.rmdir(runtime_name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_fd)


def _write_private_relative_file(
    root_fd: int, relative: Path, data: bytes, *, mode: int = 0o600
) -> None:
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise RunnerError("private relative artifact path is unsafe")
    descriptor = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            metadata = os.fstat(child)
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                os.close(child)
                raise RunnerError("private artifact directory permissions are unsafe")
            os.close(descriptor)
            descriptor = child
        _write_private_dirfd(descriptor, relative.name, data, mode=mode)
    finally:
        os.close(descriptor)


def _manifest_artifact_paths(
    source: Path, raw: bytes
) -> list[tuple[Path, Path, int, str]]:
    document = base._load_object_bytes(raw, label="RepoGround manifest")
    artifacts = document.get("artifacts")
    if artifacts is None:
        artifacts = []
    if not isinstance(artifacts, list):
        raise RunnerError("RepoGround manifest artifacts contract is invalid")
    manifest_source = source.resolve(strict=True)
    root = manifest_source.parent
    result: list[tuple[Path, Path, int, str]] = []
    seen: dict[Path, tuple[int, str]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise RunnerError("RepoGround manifest artifact entry is invalid")
        raw_path = artifact.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise RunnerError("RepoGround manifest artifact path is invalid")
        expected_bytes = artifact.get("bytes")
        expected_sha256 = artifact.get("sha256")
        if (
            isinstance(expected_bytes, bool)
            or not isinstance(expected_bytes, int)
            or expected_bytes < 0
            or not isinstance(expected_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
        ):
            raise RunnerError("RepoGround manifest artifact identity is invalid")
        relative = Path(raw_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part == ".." for part in relative.parts)
        ):
            raise RunnerError("RepoGround manifest artifact path is not safely stageable")
        candidate = root / relative
        try:
            normalized = candidate.resolve(strict=False).relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise RunnerError(
                "RepoGround manifest artifact path escapes the bundle root"
            ) from exc
        if normalized != relative:
            raise RunnerError(
                "RepoGround manifest artifact path changes through filesystem indirection"
            )
        if candidate.resolve(strict=False) == manifest_source:
            raise RunnerError("RepoGround manifest cannot declare itself as an artifact")
        identity = (expected_bytes, expected_sha256)
        previous_identity = seen.get(relative)
        if previous_identity is not None:
            if previous_identity != identity:
                raise RunnerError(
                    "RepoGround manifest artifact path has conflicting identities"
                )
            continue
        seen[relative] = identity
        result.append((relative, candidate, expected_bytes, expected_sha256))
    return result


def _stage_code_source(
    source: Path, expected_code: Mapping[str, Any], *, label: str
) -> bytes:
    raw = _read_bound_regular_file(
        source, label=label, max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES
    )
    if (
        expected_code.get("name") != source.name
        or expected_code.get("bytes") != len(raw)
        or expected_code.get("sha256") != sha_bytes(raw)
    ):
        raise RunnerError(f"{label} does not match preflight authorization")
    return raw


def _private_directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid)


def _revalidate_private_stage_tree(
    binding: Mapping[str, Any], file_bindings: Sequence[Mapping[str, Any]]
) -> None:
    runtime_dir = Path(binding["runtime_dir"])
    opened_path, descriptor = _open_private_directory(runtime_dir, create_final=False)
    try:
        _directory_fd_matches(opened_path, descriptor)
        current_identity = _private_directory_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    expected_identity = tuple(binding["runtime_identity"])
    if current_identity != expected_identity:
        raise RunnerError("private runtime stage changed during execution")

    expected_files: set[Path] = set()
    expected_directories: set[Path] = set()
    for file_binding in file_bindings:
        candidate = Path(file_binding["path"])
        try:
            relative = candidate.relative_to(runtime_dir)
        except ValueError as exc:
            raise RunnerError("private runtime stage file escapes its root") from exc
        if not relative.parts:
            raise RunnerError("private runtime stage file path is invalid")
        expected_files.add(relative)
        for parent in relative.parents:
            if parent != Path("."):
                expected_directories.add(parent)

    actual_files: set[Path] = set()
    actual_directories: set[Path] = set()
    for directory, dirnames, filenames in os.walk(runtime_dir, followlinks=False):
        root = Path(directory)
        relative_root = root.relative_to(runtime_dir)
        for name in dirnames:
            candidate = root / name
            metadata = candidate.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise RunnerError("private runtime stage directory is unsafe")
            actual_directories.add(relative_root / name)
        for name in filenames:
            candidate = root / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RunnerError("private runtime stage file is unsafe")
            actual_files.add(relative_root / name)

    if actual_files != expected_files or actual_directories != expected_directories:
        raise RunnerError("private runtime stage contains unexpected entries")

    reopened_path, descriptor = _open_private_directory(runtime_dir, create_final=False)
    try:
        _directory_fd_matches(reopened_path, descriptor)
        final_identity = _private_directory_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    if final_identity != expected_identity:
        raise RunnerError("private runtime stage changed during validation")


def stage_mcp_proxy(
    state_root: Path,
    expected_code: Mapping[str, Any],
    expected_base_code: Mapping[str, Any],
) -> dict[str, Any]:
    source = Path(__file__).resolve()
    base_source = BASE_PATH.resolve(strict=True)
    raw = _stage_code_source(
        source, expected_code, label="Codex MCP proxy source"
    )
    base_raw = _stage_code_source(
        base_source, expected_base_code, label="RepoBrief benchmark base source"
    )
    stage_root: Path | None = None
    stage_fd: int | None = None
    try:
        stage_root, stage_fd = _create_private_stage_directory(
            state_root / "codex-mcp-proxy-runtime", prefix="stage-"
        )
        _write_private_dirfd(stage_fd, source.name, raw)
        _write_private_dirfd(stage_fd, base_source.name, base_raw)
        _directory_fd_matches(stage_root, stage_fd)
        staged = stage_root / source.name
        staged_base = stage_root / base_source.name
        bound = _bind_mcp_file(
            staged, label="Codex MCP proxy stage", executable=False
        )
        bound_base = _bind_mcp_file(
            staged_base, label="RepoBrief benchmark base stage", executable=False
        )
        if bound["sha256"] != expected_code.get("sha256"):
            raise RunnerError("staged Codex MCP proxy SHA mismatch")
        if bound_base["sha256"] != expected_base_code.get("sha256"):
            raise RunnerError("staged RepoBrief benchmark base SHA mismatch")
        bound["expected_code"] = dict(expected_code)
        bound["runtime_dir"] = stage_root
        bound["runtime_identity"] = _private_directory_identity(os.fstat(stage_fd))
        bound["base_path"] = bound_base["path"]
        bound["base_identity"] = bound_base["identity"]
        bound["base_sha256"] = bound_base["sha256"]
        bound["expected_base_code"] = dict(expected_base_code)
        return bound
    except BaseException:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
            stage_fd = None
        if stage_root is not None:
            shutil.rmtree(stage_root, ignore_errors=True)
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _revalidate_staged_mcp_proxy(binding: Mapping[str, Any]) -> None:
    current = _bind_mcp_file(
        Path(binding["path"]), label="Codex MCP proxy stage", executable=False
    )
    if current["identity"] != binding["identity"] or current["sha256"] != binding["sha256"]:
        raise RunnerError("Codex MCP proxy stage changed during execution")
    current_base = _bind_mcp_file(
        Path(binding["base_path"]),
        label="RepoBrief benchmark base stage",
        executable=False,
    )
    if (
        current_base["identity"] != binding["base_identity"]
        or current_base["sha256"] != binding["base_sha256"]
    ):
        raise RunnerError("RepoBrief benchmark base stage changed during execution")
    _revalidate_private_stage_tree(
        binding,
        (
            {"path": binding["path"]},
            {"path": binding["base_path"]},
        ),
    )


def cleanup_staged_mcp_proxy(binding: Mapping[str, Any]) -> str | None:
    try:
        _revalidate_staged_mcp_proxy(binding)
        runtime_dir = Path(binding["runtime_dir"])
        if Path(binding["path"]).parent != runtime_dir or Path(binding["base_path"]).parent != runtime_dir:
            raise RunnerError("Codex MCP proxy runtime binding is inconsistent")
        shutil.rmtree(runtime_dir)
    except BaseException as exc:
        return type(exc).__name__
    return None


def stage_repoground_manifest(
    state_root: Path, expected_manifest: Mapping[str, Any]
) -> dict[str, Any]:
    source = Path(str(expected_manifest.get("path"))).expanduser()
    current, raw = _runtime_file_snapshot(
        source, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if canonical(current) != canonical(dict(expected_manifest)):
        raise RunnerError("RepoGround manifest changed after preflight authorization")
    artifact_paths = _manifest_artifact_paths(source, raw)
    stage_root: Path | None = None
    stage_fd: int | None = None
    try:
        stage_root, stage_fd = _create_private_stage_directory(
            state_root / "repoground-manifest-runtime", prefix="bundle-"
        )
        artifact_bindings: list[dict[str, Any]] = []
        for relative, candidate, expected_bytes, expected_sha256 in artifact_paths:
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise RunnerError("RepoGround bundle artifact is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RunnerError(
                    "RepoGround bundle artifact must be a regular non-symlink file"
                )
            _snapshot, artifact_raw = _runtime_file_snapshot(
                candidate,
                label=f"RepoGround bundle artifact {relative}",
                max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES,
            )
            if (
                len(artifact_raw) != expected_bytes
                or sha_bytes(artifact_raw) != expected_sha256
            ):
                raise RunnerError(
                    "RepoGround bundle artifact changed after preflight authorization"
                )
            _write_private_relative_file(stage_fd, relative, artifact_raw)
            staged_artifact = stage_root / relative
            artifact_bound = _bind_mcp_file(
                staged_artifact,
                label=f"staged RepoGround bundle artifact {relative}",
                executable=False,
            )
            artifact_bindings.append(
                {
                    "path": artifact_bound["path"],
                    "identity": artifact_bound["identity"],
                    "sha256": artifact_bound["sha256"],
                }
            )
        manifest_name = source.resolve(strict=True).name
        _write_private_dirfd(stage_fd, manifest_name, raw)
        _directory_fd_matches(stage_root, stage_fd)
        staged = stage_root / manifest_name
        bound = _bind_mcp_file(
            staged, label="RepoGround manifest stage", executable=False
        )
        if bound["sha256"] != expected_manifest.get("sha256"):
            raise RunnerError("staged RepoGround manifest SHA mismatch")
        bound["expected_manifest"] = dict(expected_manifest)
        bound["runtime_dir"] = stage_root
        bound["runtime_identity"] = _private_directory_identity(os.fstat(stage_fd))
        bound["artifact_bindings"] = artifact_bindings
        return bound
    except BaseException:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
            stage_fd = None
        if stage_root is not None:
            shutil.rmtree(stage_root, ignore_errors=True)
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _revalidate_staged_repoground_manifest(binding: Mapping[str, Any]) -> None:
    current = _bind_mcp_file(
        Path(binding["path"]), label="RepoGround manifest stage", executable=False
    )
    if current["identity"] != binding["identity"] or current["sha256"] != binding["sha256"]:
        raise RunnerError("RepoGround manifest stage changed during execution")
    for artifact in binding.get("artifact_bindings", []):
        current_artifact = _bind_mcp_file(
            Path(artifact["path"]),
            label="staged RepoGround bundle artifact",
            executable=False,
        )
        if (
            current_artifact["identity"] != artifact["identity"]
            or current_artifact["sha256"] != artifact["sha256"]
        ):
            raise RunnerError("RepoGround bundle artifact stage changed during execution")
    _revalidate_private_stage_tree(
        binding,
        (binding, *binding.get("artifact_bindings", [])),
    )


def cleanup_staged_repoground_manifest(binding: Mapping[str, Any]) -> str | None:
    try:
        _revalidate_staged_repoground_manifest(binding)
        runtime_dir = Path(binding["runtime_dir"])
        if Path(binding["path"]).parent != runtime_dir:
            raise RunnerError("RepoGround manifest runtime binding is inconsistent")
        shutil.rmtree(runtime_dir)
    except BaseException as exc:
        return type(exc).__name__
    return None


def _bind_mcp_upstream(
    upstream: Sequence[str],
    manifest: Path,
    authorized_files: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    executable = Path(upstream[0])
    if not executable.is_absolute():
        resolved = shutil.which(upstream[0], path=provider_env().get("PATH"))
        if resolved is None:
            raise RunnerError("MCP executable is unavailable")
        executable = Path(resolved)
    try:
        executable = executable.resolve(strict=True)
    except OSError as exc:
        raise RunnerError("MCP executable is unavailable") from exc
    executable_binding = _bind_mcp_file(executable, label="MCP executable", executable=True)
    expected = _normalized_authorized_mcp_files(list(authorized_files))
    argv = [str(executable), *upstream[1:]]
    bindings = [executable_binding]
    if len(argv) > 1 and Path(executable).name.startswith("python"):
        script = Path(argv[1]).expanduser()
        if not script.is_absolute():
            if len(expected) < 2:
                raise RunnerError("relative MCP script lacks a preflight-authorized file identity")
            authorized_script = Path(expected[1]["path"])
            relative_parts = script.parts
            if (
                not relative_parts
                or ".." in relative_parts
                or tuple(authorized_script.parts[-len(relative_parts):]) != relative_parts
            ):
                raise RunnerError("relative MCP script does not match preflight-authorized path")
            script = authorized_script
        try:
            script = script.resolve(strict=True)
        except OSError as exc:
            raise RunnerError("MCP script is unavailable") from exc
        script_binding = _bind_mcp_file(script, label="MCP script", executable=False)
        argv[1] = str(script)
        bindings.append(script_binding)
    current = [_mcp_authorization_identity(binding) for binding in bindings]
    if canonical(current) != canonical(expected):
        raise RunnerError("MCP program does not match preflight-authorized file identities")
    if "--bundle-root" not in argv:
        raise RunnerError("MCP upstream must declare --bundle-root")
    index = argv.index("--bundle-root")
    if index + 1 >= len(argv) or argv.count("--bundle-root") != 1:
        raise RunnerError("MCP upstream bundle root is invalid")
    argv[index + 1] = str(manifest)
    return argv, bindings


def stage_mcp_upstream(
    state_root: Path,
    upstream: Sequence[str],
    manifest: Path,
    authorized_files: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    bound_argv, source_bindings = _bind_mcp_upstream(
        upstream, manifest, authorized_files
    )
    stage_root: Path | None = None
    stage_fd: int | None = None
    try:
        stage_root, stage_fd = _create_private_stage_directory(
            state_root / "repoground-mcp-upstream-runtime", prefix="upstream-"
        )
        staged_argv = list(bound_argv)
        staged_bindings: list[dict[str, Any]] = []
        for index, source_binding in enumerate(source_bindings):
            label = "MCP executable" if index == 0 else "MCP script"
            source = Path(source_binding["path"])
            raw = _read_bound_regular_file(
                source, label=label, max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES
            )
            current = _bind_mcp_file(
                source, label=label, executable=index == 0
            )
            if (
                current["identity"] != source_binding["identity"]
                or current["sha256"] != source_binding["sha256"]
                or sha_bytes(raw) != source_binding["sha256"]
            ):
                raise RunnerError(f"{label} changed before private staging")
            relative = Path("executable" if index == 0 else "script") / source.name
            _write_private_relative_file(
                stage_fd,
                relative,
                raw,
                mode=0o700 if index == 0 else 0o600,
            )
            staged_path = stage_root / relative
            staged = _bind_mcp_file(
                staged_path,
                label=f"staged {label}",
                executable=index == 0,
            )
            if staged["sha256"] != source_binding["sha256"]:
                raise RunnerError(f"staged {label} SHA mismatch")
            staged_bindings.append(staged)
            staged_argv[index] = str(staged_path)
        _directory_fd_matches(stage_root, stage_fd)
        return {
            "argv": staged_argv,
            "bindings": staged_bindings,
            "runtime_dir": stage_root,
            "runtime_identity": _private_directory_identity(os.fstat(stage_fd)),
        }
    except BaseException:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
            stage_fd = None
        if stage_root is not None:
            shutil.rmtree(stage_root, ignore_errors=True)
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _revalidate_staged_mcp_upstream(binding: Mapping[str, Any]) -> None:
    bindings = binding.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        raise RunnerError("staged MCP upstream binding is invalid")
    for index, file_binding in enumerate(bindings):
        label = "MCP executable" if index == 0 else "MCP script"
        current = _bind_mcp_file(
            Path(file_binding["path"]),
            label=f"staged {label}",
            executable=index == 0,
        )
        if (
            current["identity"] != file_binding["identity"]
            or current["sha256"] != file_binding["sha256"]
        ):
            raise RunnerError(f"staged {label} changed during execution")
    _revalidate_private_stage_tree(binding, bindings)


def cleanup_staged_mcp_upstream(binding: Mapping[str, Any]) -> str | None:
    try:
        _revalidate_staged_mcp_upstream(binding)
        runtime_dir = Path(binding["runtime_dir"])
        for file_binding in binding["bindings"]:
            Path(file_binding["path"]).relative_to(runtime_dir)
        shutil.rmtree(runtime_dir)
    except BaseException as exc:
        return type(exc).__name__
    return None


def _pin_treatment_arguments(message: dict[str, Any], manifest: Path) -> None:
    params = message.get("params")
    if not isinstance(params, dict):
        raise RunnerError("MCP tools/call params must be an object")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
        params["arguments"] = arguments
    expected = str(manifest)
    supplied = arguments.get("bundle_manifest")
    if supplied not in (None, expected):
        raise RunnerError("MCP bundle_manifest conflicts with the bound manifest")
    for selector in ("repo", "stem"):
        if arguments.get(selector) is not None:
            raise RunnerError(f"MCP {selector} selector conflicts with the bound manifest")
    arguments["bundle_manifest"] = expected
    arguments["repo"] = None
    arguments["stem"] = None


def run_mcp_proxy(
    upstream: Sequence[str], manifest_text: str, manifest_sha256: str,
    authorized_files: Sequence[Mapping[str, Any]], runtime_root_text: str,
) -> int:
    if not upstream or any(not isinstance(item, str) or not item for item in upstream):
        raise RunnerError("invalid MCP upstream argv")
    manifest = Path(manifest_text)
    manifest_data = _read_bound_regular_file(
        manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if sha_bytes(manifest_data) != manifest_sha256:
        raise RunnerError("RepoGround manifest SHA mismatch")
    manifest_metadata = manifest.lstat()
    manifest_identity = (
        manifest_metadata.st_dev, manifest_metadata.st_ino,
        manifest_metadata.st_size, manifest_metadata.st_mode,
    )
    upstream_stage = stage_mcp_upstream(
        Path(runtime_root_text), upstream, manifest, authorized_files
    )
    bound_upstream = [str(item) for item in upstream_stage["argv"]]
    try:
        process = subprocess.Popen(
            bound_upstream, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=provider_env(), shell=False,
        )
    except OSError as exc:
        stage_cleanup_error = cleanup_staged_mcp_upstream(upstream_stage)
        if stage_cleanup_error is not None:
            raise RunnerError(
                "MCP upstream could not be started and private runtime cleanup failed"
            ) from exc
        raise RunnerError("MCP upstream could not be started") from exc
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("MCP upstream could not be reaped") from exc
        stage_cleanup_error = cleanup_staged_mcp_upstream(upstream_stage)
        if stage_cleanup_error is not None:
            raise RunnerError(
                "MCP upstream pipes unavailable and private runtime cleanup failed"
            )
        raise RunnerError("MCP upstream pipes unavailable")
    output_lock = threading.Lock()
    state_lock = threading.Lock()
    pending_requests: dict[Any, str] = {}
    pending_treatment_tools: dict[Any, str] = {}
    tools_inventory_validated = False
    resource_calls: dict[Any, tuple[str, str | None]] = {}
    frozen_resources: dict[str, Any] | None = None
    frozen_uris: set[str] = set()
    resource_list_upstream_id: Any | None = None
    resource_list_waiters: list[Any] = []
    errors: list[BaseException] = []
    upstream_stderr = bytearray()
    upstream_stderr_overflow = False

    # Keep the upstream in the inherited provider process group. The outer
    # runner can therefore still kill Codex, this proxy, and RepoGround as one
    # containment unit. Proxy-local failures additionally own/reap this child.
    def terminate_upstream() -> None:
        if process.poll() is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:
            return
        except OSError as exc:
            errors.append(exc)

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
            terminate_upstream()

    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
    stderr_thread.start()

    def client_to_upstream() -> None:
        nonlocal resource_list_upstream_id
        try:
            while True:
                raw = _read_bounded_mcp_line(sys.stdin.buffer, peer="client")
                if not raw:
                    break
                message = json.loads(raw)
                if not isinstance(message, dict):
                    raise RunnerError("MCP client message must be an object")
                if message.get("jsonrpc") != "2.0":
                    raise RunnerError("MCP client JSON-RPC version is invalid")
                if "params" in message and not isinstance(message.get("params"), (dict, list)):
                    raise RunnerError("MCP client JSON-RPC params are invalid")
                method = message.get("method")
                has_identifier = "id" in message
                identifier = message.get("id")
                if has_identifier and not _valid_jsonrpc_request_id(identifier):
                    raise RunnerError("MCP client request ID is invalid")
                if method == "tools/call" and not has_identifier:
                    raise RunnerError("MCP tools/call request ID is required")
                if method not in MCP_CLIENT_METHODS:
                    if identifier is not None:
                        _proxy_write(_proxy_error(identifier, "benchmark MCP method is not authorized"), output_lock)
                    continue
                pending_kind: str | None = None
                pending_treatment_tool: str | None = None
                if method == "initialize":
                    pending_kind = "initialize"
                elif method == "tools/list":
                    pending_kind = "tools/list"
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
                        coalesced = False
                        with state_lock:
                            if identifier in pending_requests:
                                raise RunnerError("MCP client reused a pending request ID")
                            if action == "list" and frozen_resources is not None:
                                cached = canonical(frozen_resources)
                            else:
                                cached = None
                            if action == "list" and frozen_resources is None and resource_list_upstream_id is not None:
                                pending_requests[identifier] = "resource-list-waiter"
                                resource_list_waiters.append(identifier)
                                coalesced = True
                            if action == "read" and frozen_resources is None:
                                error = "list frozen resources before reading"
                            elif action == "read" and (not isinstance(uri, str) or uri not in frozen_uris):
                                error = "resource URI is not in the frozen list"
                            else:
                                error = None
                        if cached is not None:
                            _proxy_write({"jsonrpc":"2.0","id":identifier,"result":{"content":[{"type":"text","text":cached}],"isError":False}}, output_lock)
                            continue
                        if coalesced:
                            continue
                        if error is not None:
                            _proxy_write({"jsonrpc":"2.0","id":identifier,"result":{"content":[{"type":"text","text":error}],"isError":True}}, output_lock)
                            continue
                        with state_lock:
                            pending_requests[identifier] = "resource"
                            resource_calls[identifier] = (str(action), str(uri) if uri is not None else None)
                            if action == "list":
                                resource_list_upstream_id = identifier
                        if action == "list":
                            send({"jsonrpc":"2.0","id":identifier,"method":"resources/list","params":{}})
                        else:
                            send({"jsonrpc":"2.0","id":identifier,"method":"resources/read","params":{"uri":uri}})
                        continue
                    if name not in UPSTREAM_MCP:
                        if identifier is not None:
                            _proxy_write(_proxy_error(identifier, "benchmark MCP tool is not authorized"), output_lock)
                        continue
                    _pin_treatment_arguments(message, manifest)
                    pending_kind = "tools/call"
                    pending_treatment_tool = str(name)
                elif identifier is not None:
                    pending_kind = "passthrough"
                if identifier is not None:
                    with state_lock:
                        if identifier in pending_requests:
                            raise RunnerError("MCP client reused a pending request ID")
                        pending_requests[identifier] = pending_kind or "passthrough"
                        if pending_treatment_tool is not None:
                            pending_treatment_tools[identifier] = pending_treatment_tool
                send(message)
        except BaseException as exc:
            errors.append(exc)
            terminate_upstream()
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    client_thread = threading.Thread(target=client_to_upstream, daemon=True)
    client_thread.start()
    returncode: int | None = None
    try:
        while True:
            raw = _read_bounded_mcp_line(process.stdout, peer="upstream")
            if not raw:
                break
            message = json.loads(raw)
            if not isinstance(message, dict):
                raise RunnerError("MCP upstream message must be an object")
            has_identifier = "id" in message
            identifier = message.get("id")
            if not has_identifier and "result" not in message and "error" not in message:
                continue
            if not has_identifier or not _valid_jsonrpc_request_id(identifier):
                raise RunnerError("MCP upstream response envelope is invalid")
            with state_lock:
                pending_kind = pending_requests.get(identifier)
                if (
                    message.get("jsonrpc") != "2.0"
                    or pending_kind is None
                    or (("result" in message) == ("error" in message))
                ):
                    raise RunnerError("MCP upstream response envelope is invalid")
                if "error" in message:
                    error = message["error"]
                    if (
                        not isinstance(error, dict)
                        or isinstance(error.get("code"), bool)
                        or not isinstance(error.get("code"), int)
                        or not isinstance(error.get("message"), str)
                    ):
                        raise RunnerError("MCP upstream error response is invalid")
                elif pending_kind == "tools/call":
                    treatment_tool = pending_treatment_tools.get(identifier)
                    if treatment_tool not in UPSTREAM_MCP:
                        raise RunnerError("MCP treatment tool response binding is missing")
                    message["result"] = _validated_treatment_tool_result(
                        message["result"],
                        tool_name=treatment_tool,
                        expected_manifest=manifest,
                    )
                pending_requests.pop(identifier, None)
                pending_treatment_tools.pop(identifier, None)
                resource_call = resource_calls.pop(identifier, None)
                is_initialize = pending_kind == "initialize"
                is_tools_list = pending_kind == "tools/list"
            if is_initialize and "result" in message:
                result = message.get("result") if isinstance(message.get("result"), dict) else {}
                caps = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
                filtered = {key: result[key] for key in ("protocolVersion", "serverInfo") if key in result}
                # The benchmark exposes a frozen tool inventory. Do not advertise
                # upstream listChanged support because upstream notifications are
                # intentionally outside the deterministic benchmark surface.
                filtered["capabilities"] = {"tools": {}}
                message = {"jsonrpc":"2.0","id":identifier,"result":filtered}
            elif is_tools_list:
                if "error" in message or "result" not in message:
                    raise RunnerError("MCP tools/list response must contain a successful result")
                tools = _filtered_treatment_tools(message.get("result"))
                tools_inventory_validated = True
                message = {"jsonrpc":"2.0","id":identifier,"result":{"tools":tools}}
            elif resource_call is not None:
                action, _uri = resource_call
                waiter_ids: list[Any] = []
                if "error" in message:
                    text = canonical(message["error"]); is_error = True
                elif action == "list":
                    try:
                        frozen, uris = _freeze_resource_result(message.get("result"))
                    except RunnerError as exc:
                        text = str(exc); is_error = True
                    else:
                        with state_lock:
                            if resource_list_upstream_id != identifier:
                                raise RunnerError("MCP resource-list response identity is inconsistent")
                            if frozen_resources is None:
                                frozen_resources = frozen
                                frozen_uris = uris
                            text = canonical(frozen_resources)
                        is_error = False
                else:
                    if not isinstance(_uri, str):
                        raise RunnerError("MCP resource-read request URI is unavailable")
                    validated_read = _validated_resource_read_result(
                        message.get("result"), expected_uri=_uri
                    )
                    text = canonical(validated_read); is_error = False
                if action == "list":
                    with state_lock:
                        if resource_list_upstream_id != identifier:
                            raise RunnerError("MCP resource-list response identity is inconsistent")
                        resource_list_upstream_id = None
                        waiter_ids = list(resource_list_waiters)
                        resource_list_waiters.clear()
                        for waiter_id in waiter_ids:
                            if pending_requests.pop(waiter_id, None) != "resource-list-waiter":
                                raise RunnerError("MCP resource-list waiter state is inconsistent")
                message = {"jsonrpc":"2.0","id":identifier,"result":{"content":[{"type":"text","text":text}],"isError":is_error}}
                for waiter_id in waiter_ids:
                    _proxy_write({"jsonrpc":"2.0","id":waiter_id,"result":message["result"]}, output_lock)
            _proxy_write(message, output_lock)
        client_thread.join(timeout=1)
        if client_thread.is_alive():
            raise RunnerError("MCP client intake remained active at upstream EOF")
        if errors:
            raise RunnerError("benchmark MCP proxy stream failed") from errors[0]
        with state_lock:
            pending_kinds = tuple(pending_requests.values())
            pending_treatment = tuple(pending_treatment_tools.values())
        if pending_treatment:
            raise RunnerError("MCP treatment tool response bindings remained pending at upstream EOF")
        if "tools/list" in pending_kinds or not tools_inventory_validated:
            raise RunnerError("MCP tools/list inventory was not validated before upstream EOF")
        if pending_kinds:
            raise RunnerError("MCP upstream responses remained pending at upstream EOF")
        returncode = process.wait(timeout=5)
    finally:
        if process.poll() is None:
            terminate_upstream()
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            errors.append(exc)
            terminate_upstream()
            try:
                returncode = process.wait(timeout=5)
            except subprocess.TimeoutExpired as followup:
                errors.append(followup)
                returncode = process.returncode if isinstance(process.returncode, int) else -1
        process.stdout.close()
        stderr_thread.join(timeout=5)
        if upstream_stderr:
            sys.stderr.buffer.write(bytes(upstream_stderr)); sys.stderr.buffer.flush()
        upstream_cleanup_error = cleanup_staged_mcp_upstream(upstream_stage)
        if upstream_cleanup_error is not None:
            raise RunnerError(
                f"MCP upstream private runtime cleanup failed: {upstream_cleanup_error}"
            )
        current_manifest = _read_bound_regular_file(
            manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
        )
        current_metadata = manifest.lstat()
        current_identity = (
            current_metadata.st_dev, current_metadata.st_ino,
            current_metadata.st_size, current_metadata.st_mode,
        )
        if current_identity != manifest_identity or sha_bytes(current_manifest) != manifest_sha256:
            raise RunnerError("RepoGround manifest changed during execution")
    if errors:
        raise RunnerError("benchmark MCP proxy stream failed") from errors[0]
    if returncode is None or upstream_stderr_overflow or returncode != 0 or upstream_stderr:
        raise RunnerError("benchmark MCP upstream failed or emitted diagnostics")
    return returncode


def write_schema(path: Path) -> None:
    base._write_private_exclusive(
        path,
        (json.dumps(base.ANSWER_SCHEMA, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _bootstrap_program_text() -> str:
    if (
        _ENTRYPOINT_BOOTSTRAP_RAW is not None
        and _ENTRYPOINT_BOOTSTRAP_IDENTITY is not None
    ):
        raw, _identity = _validated_entrypoint_bootstrap_context(
            _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY
        )
    else:
        raw = _read_bound_regular_file(
            ENTRYPOINT_BOOTSTRAP_PATH,
            label="Codex immutable source bootstrap",
            max_bytes=SOURCE_SNAPSHOT_MAX_BYTES,
        )
        identity = {
            "schema_version": ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION,
            "kind": ENTRYPOINT_BOOTSTRAP_KIND,
            "name": ENTRYPOINT_BOOTSTRAP_NAME,
            "bytes": len(raw),
            "sha256": sha_bytes(raw),
        }
        raw, _identity = _validated_entrypoint_bootstrap_context(raw, identity)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunnerError("Codex immutable source bootstrap is not UTF-8") from exc


def build_command(
    request: Mapping[str, Any], codex: str, checkout: Path, schema: Path, codex_home: Path,
    *, authorized_mcp_files: Sequence[Mapping[str, Any]] | None = None,
    proxy_path: Path | None = None,
    manifest_path: Path | None = None,
    mcp_runtime_root: Path | None = None,
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
        if authorized_mcp_files is None:
            raise RunnerError("treatment requires preflight-authorized MCP file identities")
        if proxy_path is None or not proxy_path.is_absolute():
            raise RunnerError("treatment requires a bound absolute MCP proxy path")
        if manifest_path is None or not manifest_path.is_absolute():
            raise RunnerError("treatment requires a staged absolute RepoGround manifest path")
        if mcp_runtime_root is None or not mcp_runtime_root.is_absolute():
            raise RunnerError("treatment requires a private absolute MCP runtime root")
        upstream = [str(item) for item in request["repobrief"]["mcp_command"]]
        binding = request["repobrief"]
        proxy_args = [
            "-I", "-c", _bootstrap_program_text(), str(proxy_path),
            "--codex-mcp-proxy", canonical(upstream),
            str(manifest_path), str(binding["manifest_sha256"]),
            canonical(list(authorized_mcp_files)),
            str(mcp_runtime_root),
        ]
        command[2:2] = [
            "-c", 'mcp_servers.repobrief.command="/usr/bin/python3"',
            "-c", "mcp_servers.repobrief.args=" + canonical(proxy_args),
        ]
    return command


def _enable_child_subreaper() -> None:
    """Adopt orphaned provider descendants so this runner can reap them."""
    if not sys.platform.startswith("linux"):
        raise RunnerError("provider containment requires Linux child-subreaper support")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
    except (OSError, AttributeError) as exc:
        raise RunnerError("provider containment cannot access prctl") from exc
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise RunnerError(
            f"provider containment cannot enable child subreaper: {os.strerror(error)}"
        )


def _scan_proc_direct_child_pids(parent_pid: int) -> set[int]:
    """Fallback for Linux procfs mounts without task ``children`` files."""
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise RunnerError("provider containment cannot enumerate /proc") from exc
    children: set[int] = set()
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            status = (entry / "status").read_text(encoding="ascii", errors="replace")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        except OSError:
            continue
        for line in status.splitlines():
            if not line.startswith("PPid:"):
                continue
            try:
                ppid = int(line.split(":", 1)[1].strip())
            except ValueError:
                break
            if ppid == parent_pid:
                children.add(int(entry.name))
            break
    return children


def _direct_child_pids() -> set[int]:
    """Return this process' direct Linux children for descendant containment."""
    parent_pid = os.getpid()
    path = Path(f"/proc/self/task/{parent_pid}/children")
    try:
        payload = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return _scan_proc_direct_child_pids(parent_pid)
    except (OSError, UnicodeError) as exc:
        raise RunnerError("provider containment cannot enumerate child processes") from exc
    if not payload:
        return set()
    try:
        return {int(value) for value in payload.split()}
    except ValueError as exc:
        raise RunnerError("provider containment received invalid child process data") from exc

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

    _enable_child_subreaper()
    baseline_children = _direct_child_pids()

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

    deadline = time.monotonic() + timeout_seconds
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

    def process_group_exists() -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except OSError as exc:
            note_error(f"process_group_probe_failed:{type(exc).__name__}")
            return True
        return True

    def adopted_provider_children() -> set[int]:
        try:
            return _direct_child_pids() - baseline_children
        except RunnerError:
            note_error("provider_child_scan_failed")
            return set()

    def kill_adopted_children(children: set[int]) -> None:
        for child_pid in sorted(children):
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except OSError as exc:
                note_error(f"adopted_child_kill_failed:{type(exc).__name__}")

    def reap_adopted_children(children: set[int]) -> None:
        for child_pid in sorted(children):
            try:
                os.waitpid(child_pid, os.WNOHANG)
            except ChildProcessError:
                continue
            except OSError as exc:
                note_error(f"adopted_child_reap_failed:{type(exc).__name__}")

    def contain_surviving_process_group() -> None:
        group_present = process_group_exists()
        adopted = adopted_provider_children()
        if not group_present and not adopted:
            return
        if group_present:
            note_error("process_group_survived_provider_exit")
            kill_process_tree()
        if adopted:
            note_error("adopted_descendant_survived_provider_exit")
            kill_adopted_children(adopted)
        cleanup_deadline = time.monotonic() + 1.0
        while time.monotonic() < cleanup_deadline:
            adopted = adopted_provider_children()
            if adopted:
                kill_adopted_children(adopted)
                reap_adopted_children(adopted)
            group_present = process_group_exists()
            adopted = adopted_provider_children()
            if not group_present and not adopted:
                return
            if group_present:
                kill_process_tree()
            time.sleep(0.01)
        adopted = adopted_provider_children()
        if adopted:
            kill_adopted_children(adopted)
            reap_adopted_children(adopted)
        if process_group_exists() or adopted_provider_children():
            note_error("process_group_cleanup_failed")
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

    stdin_pending = memoryview(stdin_data)
    if selector is not None and capture_error is None:
        assert process.stdin is not None
        try:
            os.set_blocking(process.stdin.fileno(), False)
            if stdin_pending:
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
        except BaseException as exc:
            note_error(f"stdin_setup_failed:{type(exc).__name__}")
            kill_process_tree()

    if selector is not None and capture_error is None:
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    note_error("timeout")
                    kill_process_tree()
                    break
                wait_for = 0 if process.poll() is not None else max(min(remaining, 0.25), 0)
                events = selector.select(wait_for)
                if not events and process.poll() is not None:
                    for key in list(selector.get_map().values()):
                        if key.data == "stdin":
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
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
                    if key.data == "stdin":
                        try:
                            written = os.write(key.fileobj.fileno(), stdin_pending)
                        except BlockingIOError:
                            continue
                        except OSError as exc:
                            note_error(f"stdin_write_failed:{type(exc).__name__}")
                            kill_process_tree()
                            selector.unregister(key.fileobj)
                            continue
                        if written <= 0:
                            note_error("stdin_write_failed:short_write")
                            kill_process_tree()
                            selector.unregister(key.fileobj)
                            continue
                        stdin_pending = stdin_pending[written:]
                        if not stdin_pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
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

    if capture_error is None and process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            note_error("timeout")
            kill_process_tree()
        else:
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                note_error("timeout")
                kill_process_tree()
            except BaseException as exc:
                note_error(f"process_wait_failed:{type(exc).__name__}")
                kill_process_tree()

    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except BaseException as followup:
            note_error(f"process_reap_failed:{type(followup).__name__}")
    returncode = process.returncode if isinstance(process.returncode, int) else -1
    if process.poll() is not None:
        contain_surviving_process_group()

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
        raw_write_errors: list[tuple[str, BaseException]] = []
        raw_persisted = {"stdout": False, "stderr": False}
        for label, descriptor, name, data in (
            ("stdout", transcript_fd, names["stdout"], stdout),
            ("stderr", evidence_fd, names["stderr"], stderr),
        ):
            try:
                _write_private_dirfd(descriptor, name, data)
                raw_persisted[label] = True
            except BaseException as exc:
                raw_write_errors.append((label, exc))
        if raw_write_errors:
            failure_diagnostics = {
                "kind": "repobrief.codex_provider_capture_persistence_failure",
                "version": base.VERSION,
                "request_id": request["request_id"],
                "request_sha256": base._sha256_json(request),
                "provider": PROVIDER,
                "model": MODEL,
                "synthetic_fixture": synthetic_fixture,
                "started_at": iso(started_at),
                "ended_at": iso(ended_at),
                "returncode": capture.get("returncode"),
                "capture_error": capture.get("capture_error"),
                "raw_persistence_complete": False,
                "raw_persisted": dict(raw_persisted),
                "write_errors": [
                    {"artifact": label, "error_type": type(exc).__name__}
                    for label, exc in raw_write_errors
                ],
                "stdout": {"artifact": names["stdout"], "sha256": sha_bytes(stdout), "bytes": len(stdout)},
                "stderr": {"artifact": names["stderr"], "sha256": sha_bytes(stderr), "bytes": len(stderr)},
                "semantic_interpretation": "not_performed",
                "does_not_establish": [
                    "provider_success", "stderr_policy_acceptance",
                    "benchmark_receipt_validity", "answer_correctness", "retry_authority",
                ],
            }
            failure_raw = (
                json.dumps(failure_diagnostics, sort_keys=True, indent=2) + "\n"
            ).encode()
            try:
                _write_private_dirfd(evidence_fd, names["diagnostics"], failure_raw)
            except BaseException as diagnostics_exc:
                raise RunnerError(
                    "raw provider evidence and failure diagnostics could not be persisted completely"
                ) from diagnostics_exc
            raise RunnerError(
                "raw provider evidence could not be persisted completely; "
                f"failure_diagnostics_sha256={sha_bytes(failure_raw)}"
            ) from raw_write_errors[0][1]
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


def _reject_unquoted_shell_expansion(text: str) -> None:
    quote: str | None = None
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == "\\":
            escaped = True
            continue
        if quote == '"':
            if char == '"':
                quote = None
            elif char in {"$", "`"}:
                raise RunnerError("shell expansion is not allowed")
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {"$", "`", "*", "?", "[", "]", "{", "}", "~", "!", "(", ")"}:
            raise RunnerError("shell expansion is not allowed")


def _split_shell_words(text: str) -> list[str]:
    if "\n" in text or "\r" in text:
        raise RunnerError("command line breaks are not allowed")
    _reject_unquoted_shell_expansion(text)
    if "$(" in text or "`" in text:
        raise RunnerError("command substitution is not allowed")
    try:
        lexer = shlex.shlex(text.strip(), posix=True, punctuation_chars=";&|<>")
        lexer.commenters = ""
        lexer.whitespace_split = True
        parts = list(lexer)
    except ValueError as exc:
        raise RunnerError("unparseable Codex command") from exc
    if any(re.fullmatch(r"[;&|<>]+", part) is not None for part in parts):
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
    parts = _split_shell_words(command)
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
        or isinstance(input_tokens, bool)
        or input_tokens < 0
        or not isinstance(output_tokens, int)
        or isinstance(output_tokens, bool)
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
            result_value = item.get("result")
            output_value = result_value if result_value is not None else item.get("error")
            output_bytes = len(canonical(output_value).encode("utf-8"))
            result_is_success = (
                isinstance(result_value, dict)
                and result_value.get("isError") is False
            )
            status = (
                "success"
                if (
                    item.get("status") == "completed"
                    and item.get("error") is None
                    and result_is_success
                )
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
    if request["condition"] == "treatment" and not any(
        call["name"] in ALLOWED_MCP and call["status"] == "success"
        for call in calls
    ):
        raise RunnerError("treatment used no successful RepoBrief tool or resource")
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

    state_path, state_fd = _open_private_directory(args.state_root)
    try:
        _directory_fd_matches(state_path, state_fd)
    finally:
        os.close(state_fd)
    authorized_mcp_files: list[dict[str, Any]] | None = None
    authorized_proxy_code: dict[str, Any] | None = None
    authorized_proxy_base_code: dict[str, Any] | None = None
    authorized_manifest: dict[str, Any] | None = None
    dispatch_authorization: dict[str, Any] | None = None
    if not synthetic:
        assert codex is not None
        dispatch_authorization = _load_preflight_dispatch_authorization(
            request,
            state_path,
            runtime_binding={
                "request_root": args.request_root,
                "repository_map": args.repository_map,
                "transcript_root": args.transcript_root,
                "evidence_root": args.provider_evidence_root,
            },
        )
        _assert_authorized_codex_executable(
            codex, str(args.codex_command_sha256), dispatch_authorization["provider_codex"]
        )
        validate_toolchain(codex)
        auth_data = validate_chatgpt_subscription(codex)
        _assert_authorized_chatgpt_auth(
            auth_data, dispatch_authorization["provider_authentication"]
        )
        if request["condition"] == "treatment":
            authorized_mcp_files = list(dispatch_authorization["mcp_files"])
            proxy_code = dispatch_authorization["proxy_code"]
            proxy_base_code = dispatch_authorization["proxy_base_code"]
            manifest_authorization = dispatch_authorization["manifest"]
            if (
                not isinstance(proxy_code, dict)
                or not isinstance(proxy_base_code, dict)
                or not isinstance(manifest_authorization, dict)
            ):
                raise RunnerError("treatment runtime authorization is incomplete")
            authorized_proxy_code = dict(proxy_code)
            authorized_proxy_base_code = dict(proxy_base_code)
            authorized_manifest = dict(manifest_authorization)

    if dispatch_authorization is None:
        source = base.load_repository_root(request, args.repository_map)
    else:
        repository_map_bytes = dispatch_authorization.get("repository_map_bytes")
        if not isinstance(repository_map_bytes, bytes):
            raise RunnerError("authorized repository map snapshot is unavailable")
        source = _repository_root_from_authorized_map_bytes(request, repository_map_bytes)
        _assert_authorized_runtime_binding(
            dispatch_authorization["binding"],
            request,
            request_root=args.request_root,
            repository_map=args.repository_map,
            state_root=state_path,
            transcript_root=args.transcript_root,
            evidence_root=args.provider_evidence_root,
        )
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
            proxy_binding: dict[str, Any] | None = None
            manifest_binding: dict[str, Any] | None = None
            try:
                if request["condition"] == "treatment":
                    if (
                        authorized_proxy_code is None
                        or authorized_proxy_base_code is None
                        or authorized_manifest is None
                    ):
                        raise RunnerError("treatment runtime authorization is incomplete")
                    proxy_binding = stage_mcp_proxy(
                        args.state_root,
                        authorized_proxy_code,
                        authorized_proxy_base_code,
                    )
                    manifest_binding = stage_repoground_manifest(
                        args.state_root, authorized_manifest
                    )
                command = build_command(
                    request, codex, checkout, schema, codex_home,
                    authorized_mcp_files=authorized_mcp_files,
                    proxy_path=None if proxy_binding is None else Path(proxy_binding["path"]),
                    manifest_path=None if manifest_binding is None else Path(manifest_binding["path"]),
                    mcp_runtime_root=state_path,
                )
                if dispatch_authorization is None:
                    raise RunnerError("live dispatch authorization is unavailable before provider intent")
                _record_preflight_dispatch_intent(
                    request, state_path, dispatch_authorization["authorization"]
                )
                capture = run_bounded(
                    command, cwd=checkout,
                    timeout_seconds=int(request["budgets"]["wall_seconds"]),
                    stdin_data=(prompt_for(request) + "\n").encode("utf-8"),
                    environment=provider_env(codex=codex, codex_home=codex_home),
                )
            except BaseException as exc:
                manifest_cleanup_error = (
                    None if manifest_binding is None
                    else cleanup_staged_repoground_manifest(manifest_binding)
                )
                proxy_cleanup_error = None if proxy_binding is None else cleanup_staged_mcp_proxy(proxy_binding)
                cleanup_error = cleanup_codex_home(codex_home)
                if (
                    manifest_cleanup_error is not None
                    or proxy_cleanup_error is not None
                    or cleanup_error is not None
                ):
                    raise RunnerError(
                        "Codex failed before capture completion and private runtime cleanup failed: "
                        f"manifest={manifest_cleanup_error} proxy={proxy_cleanup_error} home={cleanup_error}"
                    ) from exc
                raise
            capture = dict(capture)
            if manifest_binding is not None:
                try:
                    _revalidate_staged_repoground_manifest(manifest_binding)
                except BaseException as exc:
                    marker = f"manifest_revalidate_failed:{type(exc).__name__}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = marker if previous is None else f"{previous};{marker}"
                manifest_cleanup_error = cleanup_staged_repoground_manifest(manifest_binding)
                if manifest_cleanup_error is not None:
                    marker = f"manifest_cleanup_failed:{manifest_cleanup_error}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = marker if previous is None else f"{previous};{marker}"
            if proxy_binding is not None:
                try:
                    _revalidate_staged_mcp_proxy(proxy_binding)
                except BaseException as exc:
                    marker = f"mcp_proxy_revalidate_failed:{type(exc).__name__}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = marker if previous is None else f"{previous};{marker}"
                proxy_cleanup_error = cleanup_staged_mcp_proxy(proxy_binding)
                if proxy_cleanup_error is not None:
                    marker = f"mcp_proxy_cleanup_failed:{proxy_cleanup_error}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = marker if previous is None else f"{previous};{marker}"
            cleanup_error = cleanup_codex_home(codex_home)
            if cleanup_error is not None:
                cleanup_marker = f"codex_home_cleanup_failed:{cleanup_error}"
                previous = capture.get("capture_error")
                capture["capture_error"] = cleanup_marker if previous is None else f"{previous};{cleanup_marker}"
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
            if len(raw) != 6:
                raise RunnerError(
                    "codex MCP proxy requires upstream argv, manifest, SHA, authorized files, and runtime root"
                )
            upstream = json.loads(raw[1])
            authorized_files = json.loads(raw[4])
            if not isinstance(upstream, list):
                raise RunnerError("codex MCP proxy upstream argv must be a list")
            if not isinstance(authorized_files, list):
                raise RunnerError("codex MCP proxy authorized files must be a list")
            return run_mcp_proxy(
                upstream, raw[2], raw[3], authorized_files, raw[5]
            )
        except Exception as exc:
            print(f"codex MCP proxy failed: {exc}", file=sys.stderr)
            return 2
    args = parser().parse_args(raw)
    try:
        request = base._load_object_bytes(
            base._bounded_stdin(), label="stdin request"
        )
        result = execute(request, args)
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

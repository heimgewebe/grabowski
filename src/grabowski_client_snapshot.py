from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Iterator


SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_KIND = "grabowski_connector_client_snapshot"
SNAPSHOT_TTL_SECONDS = 3_600
SNAPSHOT_CLOCK_SKEW_SECONDS = 120
MAX_SNAPSHOT_BYTES = 32 * 1024
STATE_ROOT = Path.home() / ".local/state/grabowski/client-snapshot"
SNAPSHOT_PATH = STATE_ROOT / "current.json"
LOCK_PATH = STATE_ROOT / ".lock"
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class ClientSnapshotError(RuntimeError):
    """Raised when a connector snapshot receipt cannot be trusted."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_identifier(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ClientSnapshotError(f"{label} must be a bounded identifier")
    return value


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ClientSnapshotError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_release_id(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 512
        or "\x00" in value
        or value.strip() != value
    ):
        raise ClientSnapshotError(f"{label} must be a bounded canonical string")
    return value


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ClientSnapshotError("client snapshot state directory is unsafe")


def _validate_private_file(metadata: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ClientSnapshotError(f"{label} is not a private regular file")


@contextmanager
def _state_lock() -> Iterator[None]:
    _ensure_private_directory(STATE_ROOT)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(LOCK_PATH, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        _validate_private_file(metadata, label="client snapshot lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_private_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        _validate_private_file(before, label="client snapshot receipt")
        if before.st_size > MAX_SNAPSHOT_BYTES:
            raise ClientSnapshotError("client snapshot receipt exceeds size limit")
        chunks: list[bytes] = []
        remaining = MAX_SNAPSHOT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ClientSnapshotError("client snapshot receipt changed while reading")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientSnapshotError("client snapshot receipt is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ClientSnapshotError("client snapshot receipt must be an object")
    return value


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ClientSnapshotError("client snapshot receipt exceeds size limit")
    if path.exists() or path.is_symlink():
        existing = path.lstat()
        _validate_private_file(existing, label="existing client snapshot receipt")
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_private_file(temporary.lstat(), label="temporary client snapshot receipt")
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _validate_private_file(path.lstat(), label="published client snapshot receipt")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _server_contract(parameters: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
    contract = parameters.get("_server_tool_contract")
    runtime = parameters.get("_server_runtime")
    instructions_sha256 = parameters.get("_server_agent_instructions_sha256")
    if not isinstance(contract, dict) or not isinstance(runtime, dict):
        raise ClientSnapshotError("server snapshot context is unavailable")
    if contract.get("runtime_matches_deployment_contract") is not True:
        raise ClientSnapshotError("server tool contract is not internally consistent")
    registered_count = contract.get("registered_tool_count")
    if isinstance(registered_count, bool) or not isinstance(registered_count, int) or registered_count < 1:
        raise ClientSnapshotError("server registered tool count is invalid")
    registered_hash = _validate_sha256(
        contract.get("registered_names_sha256"),
        label="server registered names hash",
    )
    release_id = _validate_release_id(runtime.get("release_id"), label="server release id")
    repo_head = runtime.get("repo_head")
    if not isinstance(repo_head, str) or re.fullmatch(r"[0-9a-f]{40}", repo_head) is None:
        raise ClientSnapshotError("server repository head is invalid")
    instructions = _validate_sha256(
        instructions_sha256,
        label="server agent instructions hash",
    )
    return (
        {
            "registered_tool_count": registered_count,
            "registered_names_sha256": registered_hash,
            "runtime_matches_deployment_contract": True,
        },
        {"release_id": release_id, "repo_head": repo_head},
        instructions,
    )


def bind_snapshot(parameters: dict[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    allowed = {
        "client_id",
        "session_id",
        "observed_tool_count",
        "observed_names_sha256",
        "observed_release_id",
        "observed_agent_instructions_sha256",
        "_server_tool_contract",
        "_server_runtime",
        "_server_agent_instructions_sha256",
    }
    unknown = sorted(set(parameters) - allowed)
    if unknown:
        raise ClientSnapshotError(f"unknown client snapshot field(s): {', '.join(unknown)}")
    client_id = _validate_identifier(parameters.get("client_id"), label="client_id")
    session_id = _validate_identifier(parameters.get("session_id"), label="session_id")
    observed_count = parameters.get("observed_tool_count")
    if (
        isinstance(observed_count, bool)
        or not isinstance(observed_count, int)
        or not 1 <= observed_count <= 1_000
    ):
        raise ClientSnapshotError("observed_tool_count must be an integer from 1 to 1000")
    observed_names_sha256 = _validate_sha256(
        parameters.get("observed_names_sha256"),
        label="observed_names_sha256",
    )
    observed_release_id = _validate_release_id(
        parameters.get("observed_release_id"),
        label="observed_release_id",
    )
    observed_instructions_sha256 = _validate_sha256(
        parameters.get("observed_agent_instructions_sha256"),
        label="observed_agent_instructions_sha256",
    )
    contract, runtime, instructions_sha256 = _server_contract(parameters)
    mismatches: list[str] = []
    if observed_count != contract["registered_tool_count"]:
        mismatches.append("tool_count")
    if observed_names_sha256 != contract["registered_names_sha256"]:
        mismatches.append("tool_names_sha256")
    if observed_release_id != runtime["release_id"]:
        mismatches.append("release_id")
    if observed_instructions_sha256 != instructions_sha256:
        mismatches.append("agent_instructions_sha256")
    timestamp = int(time.time()) if now_unix is None else now_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ClientSnapshotError("snapshot timestamp is invalid")
    declaration = {
        "client_id": client_id,
        "session_id": session_id,
        "observed_tool_count": observed_count,
        "observed_names_sha256": observed_names_sha256,
        "observed_release_id": observed_release_id,
        "observed_agent_instructions_sha256": observed_instructions_sha256,
    }
    receipt: dict[str, Any] = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "kind": SNAPSHOT_KIND,
        "created_at_unix": timestamp,
        "expires_at_unix": timestamp + SNAPSHOT_TTL_SECONDS,
        "client_declaration": declaration,
        "client_declaration_sha256": _sha256_json(declaration),
        "server_binding": {
            "registered_tool_count": contract["registered_tool_count"],
            "registered_names_sha256": contract["registered_names_sha256"],
            "release_id": runtime["release_id"],
            "repo_head": runtime["repo_head"],
            "agent_instructions_sha256": instructions_sha256,
        },
        "verified": not mismatches,
        "mismatches": mismatches,
        "verification_model": "client-declared-server-compared-v1",
        "does_not_establish": [
            "platform-enforced client snapshot identity",
            "that the client invoked every declared tool",
            "client instruction compliance",
            "resistance to compromised same-uid code",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    with _state_lock():
        _write_private_json(SNAPSHOT_PATH, receipt)
    return {
        "schema_version": 1,
        "state": "matched" if not mismatches else "mismatch",
        "verified": not mismatches,
        "mismatches": mismatches,
        "created_at_unix": timestamp,
        "expires_at_unix": receipt["expires_at_unix"],
        "client_declaration_sha256": receipt["client_declaration_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "verification_model": receipt["verification_model"],
        "recommended_next_action": (
            "none" if not mismatches else "refresh the connector tool snapshot and bind it again"
        ),
        "does_not_establish": list(receipt["does_not_establish"]),
    }


def _validate_receipt(receipt: dict[str, Any]) -> None:
    if receipt.get("schema_version") != SNAPSHOT_SCHEMA_VERSION or receipt.get("kind") != SNAPSHOT_KIND:
        raise ClientSnapshotError("client snapshot receipt contract mismatch")
    declared_hash = receipt.get("receipt_sha256")
    _validate_sha256(declared_hash, label="receipt_sha256")
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    if _sha256_json(unsigned) != declared_hash:
        raise ClientSnapshotError("client snapshot receipt hash mismatch")
    declaration = receipt.get("client_declaration")
    binding = receipt.get("server_binding")
    if not isinstance(declaration, dict) or not isinstance(binding, dict):
        raise ClientSnapshotError("client snapshot receipt binding is missing")
    if _sha256_json(declaration) != receipt.get("client_declaration_sha256"):
        raise ClientSnapshotError("client snapshot declaration hash mismatch")


def snapshot_status(
    *,
    expected_tool_count: int,
    expected_names_sha256: str,
    expected_release_id: str,
    expected_repo_head: str,
    expected_agent_instructions_sha256: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    base = {
        "observable": False,
        "fresh": False,
        "matched": False,
        "verification_model": "client-declared-server-compared-v1",
        "does_not_establish": [
            "platform-enforced client snapshot identity",
            "that the client invoked every declared tool",
            "client instruction compliance",
            "resistance to compromised same-uid code",
        ],
    }
    try:
        with _state_lock():
            receipt = _read_private_json(SNAPSHOT_PATH)
        _validate_receipt(receipt)
    except FileNotFoundError:
        return {**base, "state": "missing", "recommended_next_action": "bind the current connector snapshot"}
    except (OSError, ValueError, ClientSnapshotError) as exc:
        return {
            **base,
            "state": "invalid",
            "error": type(exc).__name__,
            "recommended_next_action": "inspect or replace the invalid connector snapshot receipt",
        }
    created_at = receipt.get("created_at_unix")
    expires_at = receipt.get("expires_at_unix")
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at < created_at
    ):
        return {**base, "state": "invalid", "error": "timestamp_contract", "recommended_next_action": "replace the invalid connector snapshot receipt"}
    binding = receipt["server_binding"]
    declaration = receipt["client_declaration"]
    expected = {
        "registered_tool_count": expected_tool_count,
        "registered_names_sha256": expected_names_sha256,
        "release_id": expected_release_id,
        "repo_head": expected_repo_head,
        "agent_instructions_sha256": expected_agent_instructions_sha256,
    }
    binding_matches = all(binding.get(key) == value for key, value in expected.items())
    declaration_matches = (
        declaration.get("observed_tool_count") == expected_tool_count
        and declaration.get("observed_names_sha256") == expected_names_sha256
        and declaration.get("observed_release_id") == expected_release_id
        and declaration.get("observed_agent_instructions_sha256")
        == expected_agent_instructions_sha256
    )
    fresh = created_at - SNAPSHOT_CLOCK_SKEW_SECONDS <= timestamp <= expires_at
    matched = receipt.get("verified") is True and not receipt.get("mismatches") and binding_matches and declaration_matches
    observable = fresh and matched
    if not fresh:
        state = "stale"
        next_action = "bind the current connector snapshot again"
    elif not matched:
        state = "mismatch"
        next_action = "refresh the connector tool snapshot and bind it again"
    else:
        state = "matched"
        next_action = "none"
    return {
        **base,
        "state": state,
        "observable": observable,
        "fresh": fresh,
        "matched": matched,
        "created_at_unix": created_at,
        "expires_at_unix": expires_at,
        "age_seconds": max(0, timestamp - created_at),
        "client_id_sha256": hashlib.sha256(
            str(declaration.get("client_id", "")).encode("utf-8")
        ).hexdigest(),
        "session_id_sha256": hashlib.sha256(
            str(declaration.get("session_id", "")).encode("utf-8")
        ).hexdigest(),
        "client_declaration_sha256": receipt.get("client_declaration_sha256"),
        "receipt_sha256": receipt.get("receipt_sha256"),
        "recommended_next_action": next_action,
    }

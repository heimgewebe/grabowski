from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any, Iterator
from urllib.parse import urlsplit


SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_KIND = "grabowski_connector_client_snapshot"
SNAPSHOT_TTL_SECONDS = 3_600
SNAPSHOT_CLOCK_SKEW_SECONDS = 120
MAX_SNAPSHOT_BYTES = 32 * 1024
STATE_ROOT = Path.home() / ".local/state/grabowski/client-snapshot"
SNAPSHOT_PATH = STATE_ROOT / "current.json"
OBSERVER_STATE_PATH = STATE_ROOT / "observer.json"
LOCK_PATH = STATE_ROOT / ".lock"
AUTO_REFRESH_CLIENT_ID = "grabowski-tunnel-watchdog-observer-v1"
AUTO_REFRESH_MCP_URL = "http://127.0.0.1:18181/mcp"
AUTO_REFRESH_RENEW_MARGIN_SECONDS = 900
AUTO_REFRESH_TIMEOUT_SECONDS = 8.0
MAX_DEPLOYMENT_MANIFEST_BYTES = 2 * 1024 * 1024
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


def connector_session_id(pid: int, start_ticks: int) -> str:
    """Return a bounded identity for one concrete tunnel-client process lifetime."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ClientSnapshotError("connector pid must be a positive integer")
    if isinstance(start_ticks, bool) or not isinstance(start_ticks, int) or start_ticks < 0:
        raise ClientSnapshotError("connector start ticks must be a non-negative integer")
    digest = hashlib.sha256(f"{pid}:{start_ticks}".encode("ascii")).hexdigest()
    return f"tunnel-{digest[:40]}"


def _runtime_release_id(runtime_root: Path) -> str:
    try:
        root = runtime_root.expanduser().resolve(strict=True)
        manifest = root / "deployment-manifest.json"
        metadata = manifest.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DEPLOYMENT_MANIFEST_BYTES:
            raise ClientSnapshotError("runtime deployment manifest is unavailable")
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClientSnapshotError("runtime deployment manifest is unavailable") from exc
    if not isinstance(payload, dict):
        raise ClientSnapshotError("runtime deployment manifest is invalid")
    return _validate_release_id(payload.get("release_id"), label="runtime release id")


def _snapshot_refresh_reason(
    *,
    session_id: str,
    expected_release_id: str,
    now_unix: int,
    renewal_margin_seconds: int = AUTO_REFRESH_RENEW_MARGIN_SECONDS,
    last_observed_session_id: str | None = None,
    observer_state_invalid: bool = False,
) -> str | None:
    _validate_identifier(session_id, label="session_id")
    _validate_release_id(expected_release_id, label="expected_release_id")
    if (
        isinstance(now_unix, bool)
        or not isinstance(now_unix, int)
        or now_unix < 0
        or isinstance(renewal_margin_seconds, bool)
        or not isinstance(renewal_margin_seconds, int)
        or not 0 <= renewal_margin_seconds < SNAPSHOT_TTL_SECONDS
    ):
        raise ClientSnapshotError("snapshot refresh timing is invalid")
    try:
        with _state_lock():
            receipt = _read_private_json(SNAPSHOT_PATH)
        _validate_receipt(receipt)
    except FileNotFoundError:
        return "snapshot-missing"
    except (OSError, ValueError, ClientSnapshotError):
        return "snapshot-invalid"

    declaration = receipt.get("client_declaration")
    binding = receipt.get("server_binding")
    if not isinstance(declaration, dict) or not isinstance(binding, dict):
        return "snapshot-invalid"
    if receipt.get("verified") is not True or receipt.get("mismatches"):
        return "snapshot-unverified"
    created_at = receipt.get("created_at_unix")
    expires_at = receipt.get("expires_at_unix")
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at < created_at
        or created_at > now_unix + SNAPSHOT_CLOCK_SKEW_SECONDS
    ):
        return "snapshot-time-invalid"
    if binding.get("release_id") != expected_release_id:
        return "runtime-release-changed"
    if now_unix >= expires_at - renewal_margin_seconds:
        return "renewal-window"
    if observer_state_invalid:
        return "observer-state-invalid"
    if last_observed_session_id is not None:
        _validate_identifier(last_observed_session_id, label="last_observed_session_id")
        if last_observed_session_id != session_id:
            return "connector-session-changed"
    # A fresh externally supplied connector declaration is stronger than the
    # local observer and is deliberately preserved until it needs renewal. The
    # separate observer marker still lets a later tunnel process lifetime change
    # trigger renewal without weakening that external receipt immediately.
    if declaration.get("client_id") != AUTO_REFRESH_CLIENT_ID:
        return None
    if declaration.get("session_id") != session_id:
        return "connector-session-changed"
    return None


def _observer_session_state() -> tuple[str | None, bool]:
    try:
        with _state_lock():
            payload = _read_private_json(OBSERVER_STATE_PATH)
    except FileNotFoundError:
        return None, False
    except (OSError, ValueError, ClientSnapshotError):
        return None, True
    if payload.get("schema_version") != 1:
        return None, True
    try:
        session_id = _validate_identifier(payload.get("session_id"), label="observer session_id")
        _validate_release_id(payload.get("release_id"), label="observer release_id")
    except ClientSnapshotError:
        return None, True
    return session_id, False


def _write_observer_state(*, session_id: str, release_id: str, now_unix: int) -> None:
    payload = {
        "schema_version": 1,
        "session_id": _validate_identifier(session_id, label="observer session_id"),
        "release_id": _validate_release_id(release_id, label="observer release_id"),
        "updated_at_unix": now_unix,
    }
    with _state_lock():
        _write_private_json(OBSERVER_STATE_PATH, payload)


def _tool_names_sha256(names: list[str]) -> str:
    if (
        not names
        or len(names) > 1_000
        or any(not isinstance(name, str) or not name or len(name.encode("utf-8")) > 512 for name in names)
        or len(set(names)) != len(names)
    ):
        raise ClientSnapshotError("observed MCP tool names are invalid")
    return hashlib.sha256(
        json.dumps(sorted(names), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _mcp_tool_payload(result: Any, *, label: str) -> dict[str, Any]:
    if getattr(result, "isError", False) is True:
        raise ClientSnapshotError(f"{label} returned an MCP tool error")
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content", None)
    if not isinstance(content, list):
        raise ClientSnapshotError(f"{label} returned no bounded JSON payload")
    for item in content:
        text = getattr(item, "text", None)
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ClientSnapshotError(f"{label} returned no bounded JSON payload")


def _validate_loopback_mcp_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048:
        raise ClientSnapshotError("MCP URL is invalid")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp"
    ):
        raise ClientSnapshotError("MCP snapshot observer requires the exact loopback /mcp endpoint")
    return url


async def _list_all_tool_names(client: Any) -> list[str]:
    names: list[str] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    while True:
        page = await client.list_tools(cursor=cursor)
        tools = getattr(page, "tools", None)
        if not isinstance(tools, list):
            raise ClientSnapshotError("tools/list returned an invalid page")
        names.extend(getattr(tool, "name", None) for tool in tools)
        if len(names) > 1_000:
            raise ClientSnapshotError("observed MCP tool count exceeds the snapshot contract")
        next_cursor = getattr(page, "nextCursor", None)
        if next_cursor is None:
            return names
        if (
            not isinstance(next_cursor, str)
            or not next_cursor
            or len(next_cursor.encode("utf-8")) > 1024
            or next_cursor in seen_cursors
        ):
            raise ClientSnapshotError("tools/list returned an invalid pagination cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


async def _observe_and_bind_snapshot(
    *,
    mcp_url: str,
    session_id: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
    except ImportError as exc:
        raise ClientSnapshotError("MCP client runtime is unavailable") from exc

    async def observe() -> dict[str, Any]:
        async with streamablehttp_client(mcp_url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                names = await _list_all_tool_names(client)
                names_sha256 = _tool_names_sha256(names)
                status_result = await client.call_tool("grabowski_status", {"view": "minimal"})
                status = _mcp_tool_payload(status_result, label="grabowski_status")
                runtime = status.get("runtime")
                instructions = status.get("agent_instructions")
                contract = status.get("tool_contract")
                if not isinstance(runtime, dict) or not isinstance(instructions, dict) or not isinstance(contract, dict):
                    raise ClientSnapshotError("observed Grabowski status is incomplete")
                release_id = _validate_release_id(runtime.get("release_id"), label="observed release id")
                instructions_sha256 = _validate_sha256(
                    instructions.get("sha256"), label="observed agent instructions hash"
                )
                if (
                    contract.get("registered_tool_count") != len(names)
                    or contract.get("registered_names_sha256") != names_sha256
                    or contract.get("runtime_matches_deployment_contract") is not True
                ):
                    raise ClientSnapshotError("observed MCP tool list disagrees with the runtime contract")
                declaration = {
                    "client_id": AUTO_REFRESH_CLIENT_ID,
                    "session_id": session_id,
                    "observed_tool_count": len(names),
                    "observed_names_sha256": names_sha256,
                    "observed_release_id": release_id,
                    "observed_agent_instructions_sha256": instructions_sha256,
                }
                bind_result = await client.call_tool(
                    "grip_run",
                    {
                        "name": "connector-snapshot-bind",
                        "parameters": declaration,
                        "profile": "operator",
                        "allow_mutation": True,
                    },
                )
                grip = _mcp_tool_payload(bind_result, label="connector-snapshot-bind grip")
                output = grip.get("output")
                if (
                    grip.get("status") != "passed"
                    or not isinstance(output, dict)
                    or output.get("verified") is not True
                    or output.get("state") != "matched"
                ):
                    raise ClientSnapshotError("connector snapshot bind did not pass verification")
                return {
                    "state": "renewed",
                    "tool_count": len(names),
                    "names_sha256": names_sha256,
                    "release_id": release_id,
                    "receipt_sha256": output.get("receipt_sha256"),
                }

    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise ClientSnapshotError("snapshot observer timeout is invalid") from exc
    if not 0.1 <= timeout <= 60.0:
        raise ClientSnapshotError("snapshot observer timeout is invalid")
    try:
        return await asyncio.wait_for(observe(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ClientSnapshotError("connector snapshot MCP observation timed out") from exc


def refresh_connector_snapshot_if_needed(
    *,
    runtime_root: Path,
    mcp_url: str,
    connector_pid: int,
    connector_start_ticks: int,
    renewal_margin_seconds: int = AUTO_REFRESH_RENEW_MARGIN_SECONDS,
    timeout_seconds: float = AUTO_REFRESH_TIMEOUT_SECONDS,
    now_unix: int | None = None,
) -> dict[str, Any]:
    observed_at = int(time.time()) if now_unix is None else now_unix
    session_id = connector_session_id(connector_pid, connector_start_ticks)
    expected_release_id = _runtime_release_id(runtime_root)
    last_observed_session_id, observer_state_invalid = _observer_session_state()
    reason = _snapshot_refresh_reason(
        session_id=session_id,
        expected_release_id=expected_release_id,
        now_unix=observed_at,
        renewal_margin_seconds=renewal_margin_seconds,
        last_observed_session_id=last_observed_session_id,
        observer_state_invalid=observer_state_invalid,
    )
    if reason is None:
        if last_observed_session_id is None:
            _write_observer_state(
                session_id=session_id,
                release_id=expected_release_id,
                now_unix=observed_at,
            )
        return {
            "state": "not_due",
            "session_id_sha256": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
        }
    result = asyncio.run(
        _observe_and_bind_snapshot(
            mcp_url=_validate_loopback_mcp_url(mcp_url),
            session_id=session_id,
            timeout_seconds=timeout_seconds,
        )
    )
    _write_observer_state(
        session_id=session_id,
        release_id=str(result["release_id"]),
        now_unix=observed_at,
    )
    return {
        **result,
        "reason": reason,
        "session_id_sha256": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
    }


def _auto_refresh_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Grabowski connector snapshot maintenance")
    subparsers = parser.add_subparsers(dest="command", required=True)
    refresh = subparsers.add_parser("refresh-if-needed")
    refresh.add_argument("--runtime-root", type=Path, required=True)
    refresh.add_argument("--mcp-url", default=AUTO_REFRESH_MCP_URL)
    refresh.add_argument("--connector-pid", type=int, required=True)
    refresh.add_argument("--connector-start-ticks", type=int, required=True)
    refresh.add_argument(
        "--renewal-margin-seconds", type=int, default=AUTO_REFRESH_RENEW_MARGIN_SECONDS
    )
    refresh.add_argument("--timeout-seconds", type=float, default=AUTO_REFRESH_TIMEOUT_SECONDS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _auto_refresh_parser().parse_args(argv)
    try:
        if args.command != "refresh-if-needed":
            raise ClientSnapshotError("unsupported snapshot maintenance command")
        result = refresh_connector_snapshot_if_needed(
            runtime_root=args.runtime_root,
            mcp_url=args.mcp_url,
            connector_pid=args.connector_pid,
            connector_start_ticks=args.connector_start_ticks,
            renewal_margin_seconds=args.renewal_margin_seconds,
            timeout_seconds=args.timeout_seconds,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    except ClientSnapshotError as exc:
        print(
            json.dumps(
                {"state": "error", "reason": str(exc)},
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {"state": "error", "reason": type(exc).__name__},
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())

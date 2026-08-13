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

import grabowski_connector_contract as connector_contract


SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_KIND = "grabowski_connector_client_snapshot"
SNAPSHOT_TTL_SECONDS = 3_600
SNAPSHOT_CLOCK_SKEW_SECONDS = 120
MAX_SNAPSHOT_BYTES = 32 * 1024
STATE_ROOT = Path.home() / ".local/state/grabowski/client-snapshot"
SNAPSHOT_PATH = STATE_ROOT / "current.json"
OBSERVER_STATE_PATH = STATE_ROOT / "observer.json"
LOCK_PATH = STATE_ROOT / ".lock"
PLATFORM_SNAPSHOT_SCHEMA_VERSION = 1
PLATFORM_SNAPSHOT_KIND = "grabowski_platform_connector_snapshot"
PLATFORM_SNAPSHOT_PATH = Path("/run/grabowski/platform-connector-snapshot.json")
PLATFORM_SNAPSHOT_TRUSTED_UID = 0
PLATFORM_SNAPSHOT_TTL_SECONDS = 3_600
MAX_PLATFORM_SNAPSHOT_BYTES = 64 * 1024
PLATFORM_SOURCE_KIND = "chatgpt_connector_catalog"
AUTO_REFRESH_CLIENT_ID = "grabowski-tunnel-watchdog-observer-v1"
OBSERVATION_SCOPE_EXTERNAL_CLIENT = "external_client_declared"
OBSERVATION_SCOPE_SERVER_LOOPBACK = "server_loopback_watchdog"
AUTO_REFRESH_MCP_URL = "http://127.0.0.1:18181/mcp"
AUTO_REFRESH_CONNECTOR_TOKEN_PATH = (
    Path.home() / ".local/state/grabowski/transport-connectors/primary.token"
)
TRANSPORT_CONNECTOR_CAPABILITY_HEADER = "X-Grabowski-Connector-Capability"
AUTO_REFRESH_RENEW_MARGIN_SECONDS = 900
AUTO_REFRESH_TIMEOUT_SECONDS = 8.0
MAX_DEPLOYMENT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TRANSPORT_CONNECTOR_TOKEN_BYTES = 256
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_TRANSPORT_CONNECTOR_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")


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


def _client_observation_scope(client_id: str) -> str:
    if client_id == AUTO_REFRESH_CLIENT_ID:
        return OBSERVATION_SCOPE_SERVER_LOOPBACK
    return OBSERVATION_SCOPE_EXTERNAL_CLIENT


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


def _read_transport_connector_capability(path: Path) -> str:
    target = Path(path).expanduser()
    try:
        linked = target.lstat()
    except OSError as exc:
        raise ClientSnapshotError(
            "transport connector capability is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
        or linked.st_nlink != 1
        or linked.st_size <= 0
        or linked.st_size > MAX_TRANSPORT_CONNECTOR_TOKEN_BYTES
    ):
        raise ClientSnapshotError("transport connector capability file is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise ClientSnapshotError(
            "transport connector capability cannot be opened safely"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            before.st_dev != linked.st_dev
            or before.st_ino != linked.st_ino
            or before.st_mode != linked.st_mode
            or before.st_uid != linked.st_uid
            or before.st_nlink != linked.st_nlink
        ):
            raise ClientSnapshotError(
                "transport connector capability changed during open"
            )
        payload = os.read(descriptor, MAX_TRANSPORT_CONNECTOR_TOKEN_BYTES + 1)
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
            raise ClientSnapshotError(
                "transport connector capability changed while reading"
            )
    finally:
        os.close(descriptor)
    if len(payload) > MAX_TRANSPORT_CONNECTOR_TOKEN_BYTES:
        raise ClientSnapshotError("transport connector capability exceeds size limit")
    try:
        token = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ClientSnapshotError(
            "transport connector capability must be ASCII"
        ) from exc
    if token.endswith("\n"):
        token = token[:-1]
    if _TRANSPORT_CONNECTOR_TOKEN_RE.fullmatch(token) is None:
        raise ClientSnapshotError("transport connector capability is invalid")
    return token


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


def _validate_platform_snapshot_file(
    metadata: os.stat_result, *, label: str
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != PLATFORM_SNAPSHOT_TRUSTED_UID
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_nlink != 1
    ):
        raise ClientSnapshotError(
            f"{label} is not a trusted root-owned regular file"
        )


def _read_platform_snapshot(path: Path | None = None) -> dict[str, Any]:
    target = PLATFORM_SNAPSHOT_PATH if path is None else path
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags)
    try:
        before = os.fstat(descriptor)
        _validate_platform_snapshot_file(before, label="platform connector snapshot")
        if before.st_size > MAX_PLATFORM_SNAPSHOT_BYTES:
            raise ClientSnapshotError("platform connector snapshot exceeds size limit")
        chunks: list[bytes] = []
        remaining = MAX_PLATFORM_SNAPSHOT_BYTES + 1
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
            raise ClientSnapshotError(
                "platform connector snapshot changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClientSnapshotError(
            "platform connector snapshot is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise ClientSnapshotError("platform connector snapshot must be an object")
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


def _contract_error(exc: Exception) -> ClientSnapshotError:
    return ClientSnapshotError(str(exc))


def _empty_schema_probe() -> dict[str, Any]:
    return {
        "matches": False,
        "name_contract_matches": False,
        "runtime_contract_matches": False,
        "schema_contract_matches": False,
        "schema_coverage_count": 0,
        "required_schema_sentinels": sorted(
            connector_contract.REQUIRED_SCHEMA_SENTINELS
        ),
        "missing_schema_sentinels": sorted(
            connector_contract.REQUIRED_SCHEMA_SENTINELS
        ),
        "unexpected_schema_tools": [],
        "required_schema_properties": {
            name: sorted(properties)
            for name, properties in sorted(
                connector_contract.REQUIRED_SCHEMA_PROPERTIES.items()
            )
        },
        "required_schema_property_mismatches": [],
        "schema_mismatches": [],
        "missing_from_connector": [],
        "unexpected_in_connector": [],
        "contract_missing_from_runtime": [],
        "runtime_unexpected_from_contract": [],
    }


def bind_snapshot(parameters: dict[str, Any], *, now_unix: int | None = None) -> dict[str, Any]:
    allowed = {
        "client_id",
        "session_id",
        "observed_tool_count",
        "observed_names_sha256",
        "observed_release_id",
        "observed_agent_instructions_sha256",
        "observed_tools",
        "cutover_id",
        "cutover_generation",
        "_server_tool_contract",
        "_server_runtime",
        "_server_agent_instructions_sha256",
        "_server_observed_tools",
    }
    unknown = sorted(set(parameters) - allowed)
    if unknown:
        raise ClientSnapshotError(f"unknown client snapshot field(s): {', '.join(unknown)}")
    client_id = _validate_identifier(parameters.get("client_id"), label="client_id")
    observation_scope = _client_observation_scope(client_id)
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

    schema_evidence: dict[str, Any] | None = None
    schema_probe = _empty_schema_probe()
    observed_tools = parameters.get("observed_tools")
    if observed_tools is not None:
        try:
            observed_names, observed_schemas, observed_metadata = (
                connector_contract.parse_observed_artifact(
                    observed_tools, label="client observed artifact"
                )
            )
            server_names, server_schemas, server_metadata = (
                connector_contract.parse_observed_artifact(
                    parameters.get("_server_observed_tools"),
                    label="server runtime artifact",
                )
            )
        except connector_contract.ConnectorContractError as exc:
            raise _contract_error(exc) from exc
        if observed_metadata["name_count"] != observed_count:
            mismatches.append("observed_artifact_tool_count")
        if observed_metadata["names_sha256"] != observed_names_sha256:
            mismatches.append("observed_artifact_names_sha256")
        if server_metadata["name_count"] != contract["registered_tool_count"]:
            mismatches.append("server_artifact_tool_count")
        if server_metadata["names_sha256"] != contract["registered_names_sha256"]:
            mismatches.append("server_artifact_names_sha256")
        schema_probe = connector_contract.probe_contract(
            observed_names,
            observed_schemas,
            server_names,
            server_schemas,
            server_names,
        )
        if schema_probe["matches"] is not True:
            mismatches.append("schema_contract")
        schema_evidence = {
            "schema_version": 1,
            "observed_artifact": observed_metadata,
            "server_artifact": server_metadata,
            "probe": schema_probe,
        }

    timestamp = int(time.time()) if now_unix is None else now_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ClientSnapshotError("snapshot timestamp is invalid")
    declaration = {
        "client_id": client_id,
        "session_id": session_id,
        "observation_scope": observation_scope,
        "observed_tool_count": observed_count,
        "observed_names_sha256": observed_names_sha256,
        "observed_release_id": observed_release_id,
        "observed_agent_instructions_sha256": observed_instructions_sha256,
    }
    if schema_evidence is not None:
        declaration.update(
            {
                "observed_tools_artifact_sha256": schema_evidence[
                    "observed_artifact"
                ]["artifact_sha256"],
                "observed_schema_coverage_count": schema_evidence[
                    "observed_artifact"
                ]["schema_coverage_count"],
                "observed_schema_tools": schema_evidence["observed_artifact"][
                    "schema_tools"
                ],
            }
        )
    cutover_binding = _optional_cutover_binding(parameters)
    verification_model = (
        "client-declared-server-schema-compared-v2"
        if schema_evidence is not None
        else "client-declared-server-compared-v1"
    )
    if observation_scope == OBSERVATION_SCOPE_SERVER_LOOPBACK:
        verification_model = (
            "server-loopback-schema-compared-v1"
            if schema_evidence is not None
            else "server-loopback-contract-compared-v1"
        )
    if cutover_binding is not None:
        verification_model = f"{verification_model}+cutover-rebind-v1"
    does_not_establish = [
        "platform-enforced client snapshot identity",
        "that the client invoked every declared tool",
        "client instruction compliance",
        "resistance to compromised same-uid code",
        "deployment success without a bound cutover receipt",
    ]
    if observation_scope == OBSERVATION_SCOPE_SERVER_LOOPBACK:
        does_not_establish.extend(
            [
                "platform connector catalog publication",
                "tool schema visibility in ChatGPT",
            ]
        )
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
        "schema_evidence": schema_evidence,
        "cutover_binding": cutover_binding,
        "verified": not mismatches,
        "mismatches": mismatches,
        "verification_model": verification_model,
        "does_not_establish": does_not_establish,
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    with _state_lock():
        _write_private_json(SNAPSHOT_PATH, receipt)
    return {
        "schema_version": 1,
        "state": "matched" if not mismatches else "mismatch",
        "verified": not mismatches,
        "observation_scope": observation_scope,
        "mismatches": mismatches,
        "created_at_unix": timestamp,
        "expires_at_unix": receipt["expires_at_unix"],
        "client_declaration_sha256": receipt["client_declaration_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "verification_model": verification_model,
        "schema_evidence_observed": schema_evidence is not None,
        "cutover_binding": cutover_binding,
        **schema_probe,
        "recommended_next_action": (
            "none" if not mismatches else "refresh the connector tool snapshot and bind it again"
        ),
        "does_not_establish": list(receipt["does_not_establish"]),
    }


def _optional_cutover_binding(parameters: dict[str, Any]) -> dict[str, Any] | None:
    cutover_id = parameters.get("cutover_id")
    cutover_generation = parameters.get("cutover_generation")
    if cutover_id is None and cutover_generation is None:
        return None
    if cutover_id is None or cutover_generation is None:
        raise ClientSnapshotError(
            "cutover rebind requires both cutover_id and cutover_generation"
        )
    cutover_id_text = _validate_identifier(cutover_id, label="cutover_id")
    if (
        isinstance(cutover_generation, bool)
        or not isinstance(cutover_generation, int)
        or cutover_generation < 1
        or cutover_generation > 1_000_000
    ):
        raise ClientSnapshotError(
            "cutover_generation must be an integer from 1 to 1000000"
        )
    return {
        "cutover_id": cutover_id_text,
        "cutover_generation": cutover_generation,
        "rebind_role": "blue-green-cutover",
    }


def rebind_for_cutover(
    parameters: dict[str, Any],
    *,
    cutover_id: str,
    cutover_generation: int,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Bind the connector snapshot as an atomic step of blue-green cutover.

    Snapshot rebind belongs to the cutover, not to a later best-effort refresh.
    A mismatch remains fail-closed and does not claim connector delivery.
    """
    bound_parameters = dict(parameters)
    bound_parameters["cutover_id"] = cutover_id
    bound_parameters["cutover_generation"] = cutover_generation
    result = bind_snapshot(bound_parameters, now_unix=now_unix)
    if result.get("verified") is not True or result.get("state") != "matched":
        raise ClientSnapshotError(
            "cutover snapshot rebind did not match the green runtime contract: "
            + ",".join(result.get("mismatches") or ["unspecified"])
        )
    if not isinstance(result.get("cutover_binding"), dict):
        raise ClientSnapshotError("cutover snapshot rebind missing cutover binding")
    return {
        **result,
        "cutover_rebind": True,
        "recommended_next_action": "none",
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


def platform_snapshot_status(
    *,
    expected_tool_count: int,
    expected_names_sha256: str,
    expected_release_id: str,
    expected_repo_head: str,
    expected_agent_instructions_sha256: str,
    expected_runtime_tools: dict[str, Any] | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    authority = {
        "source_kind": PLATFORM_SOURCE_KIND,
        "trusted_path": str(PLATFORM_SNAPSHOT_PATH),
        "trusted_owner_uid": PLATFORM_SNAPSHOT_TRUSTED_UID,
        "requires_regular_file": True,
        "requires_single_link": True,
        "forbids_group_or_world_write": True,
        "ttl_seconds": PLATFORM_SNAPSHOT_TTL_SECONDS,
    }
    base: dict[str, Any] = {
        "observable": False,
        "schema_observable": False,
        "fresh": False,
        "matched": False,
        "authority": authority,
        "source": None,
        "runtime_binding_matches": False,
        "schema_contract_matches": False,
        "required_schema_property_mismatches": [],
        "recommended_next_action": (
            "capture a trusted platform connector catalog snapshot from ChatGPT "
            "connector discovery at the configured root-owned path"
        ),
        "does_not_establish": [
            "platform behavior outside the captured catalog revision",
            "future platform connector publication",
            "a platform signature when the platform does not provide one",
        ],
    }
    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
        or timestamp < 0
    ):
        return {
            **base,
            "state": "invalid",
            "error": "timestamp_contract",
            "recommended_next_action": "repair platform snapshot clock inputs",
        }
    try:
        document = _read_platform_snapshot()
    except FileNotFoundError:
        return {**base, "state": "missing"}
    except (OSError, ValueError, ClientSnapshotError) as exc:
        return {
            **base,
            "state": "invalid",
            "error": type(exc).__name__,
            "recommended_next_action": (
                "replace the untrusted or invalid platform connector snapshot "
                "through the platform evidence integration"
            ),
        }
    try:
        required_keys = {
            "schema_version",
            "kind",
            "source",
            "runtime_binding",
            "observed_tools",
            "snapshot_sha256",
        }
        if set(document) != required_keys:
            raise ClientSnapshotError(
                "platform connector snapshot has unexpected fields"
            )
        if (
            document.get("schema_version") != PLATFORM_SNAPSHOT_SCHEMA_VERSION
            or document.get("kind") != PLATFORM_SNAPSHOT_KIND
        ):
            raise ClientSnapshotError(
                "platform connector snapshot contract mismatch"
            )
        declared_snapshot_sha256 = _validate_sha256(
            document.get("snapshot_sha256"),
            label="platform snapshot_sha256",
        )
        unsigned = dict(document)
        unsigned.pop("snapshot_sha256", None)
        if _sha256_json(unsigned) != declared_snapshot_sha256:
            raise ClientSnapshotError(
                "platform connector snapshot hash mismatch"
            )
        source = document.get("source")
        binding = document.get("runtime_binding")
        if not isinstance(source, dict) or set(source) != {
            "kind",
            "connector",
            "reference",
            "observed_at_unix",
            "catalog_sha256",
        }:
            raise ClientSnapshotError(
                "platform connector snapshot source contract mismatch"
            )
        if source.get("kind") != PLATFORM_SOURCE_KIND:
            raise ClientSnapshotError(
                "platform connector snapshot source is not authoritative"
            )
        if source.get("connector") != "grabowski":
            raise ClientSnapshotError(
                "platform connector snapshot targets another connector"
            )
        reference = source.get("reference")
        if (
            not isinstance(reference, str)
            or not reference
            or reference.strip() != reference
            or len(reference.encode("utf-8")) > 1024
        ):
            raise ClientSnapshotError(
                "platform connector snapshot source reference is invalid"
            )
        observed_at = source.get("observed_at_unix")
        if (
            isinstance(observed_at, bool)
            or not isinstance(observed_at, int)
            or observed_at < 0
        ):
            raise ClientSnapshotError(
                "platform connector snapshot observation time is invalid"
            )
        catalog_sha256 = _validate_sha256(
            source.get("catalog_sha256"),
            label="platform catalog_sha256",
        )
        if not isinstance(binding, dict) or set(binding) != {
            "registered_tool_count",
            "registered_names_sha256",
            "release_id",
            "repo_head",
            "agent_instructions_sha256",
        }:
            raise ClientSnapshotError(
                "platform connector snapshot runtime binding mismatch"
            )
        registered_count = binding.get("registered_tool_count")
        if (
            isinstance(registered_count, bool)
            or not isinstance(registered_count, int)
            or not 1 <= registered_count <= connector_contract.MAX_OBSERVED_TOOLS
        ):
            raise ClientSnapshotError(
                "platform connector snapshot tool count is invalid"
            )
        _validate_sha256(
            binding.get("registered_names_sha256"),
            label="platform registered_names_sha256",
        )
        _validate_release_id(
            binding.get("release_id"), label="platform release id"
        )
        repo_head = binding.get("repo_head")
        if (
            not isinstance(repo_head, str)
            or re.fullmatch(r"[0-9a-f]{40}", repo_head) is None
        ):
            raise ClientSnapshotError(
                "platform connector snapshot repository head is invalid"
            )
        _validate_sha256(
            binding.get("agent_instructions_sha256"),
            label="platform agent instructions sha256",
        )
        observed_names, observed_schemas, observed_metadata = (
            connector_contract.parse_observed_artifact(
                document.get("observed_tools"),
                label="platform connector catalog artifact",
            )
        )
        if observed_metadata["artifact_sha256"] != catalog_sha256:
            raise ClientSnapshotError(
                "platform connector catalog content hash mismatch"
            )
        if expected_runtime_tools is None:
            return {
                **base,
                "state": "runtime_schema_unavailable",
                "source": dict(source),
                "recommended_next_action": (
                    "restore runtime schema observability before evaluating "
                    "the platform connector snapshot"
                ),
            }
        runtime_names, runtime_schemas, runtime_metadata = (
            connector_contract.parse_observed_artifact(
                expected_runtime_tools,
                label="runtime connector artifact",
            )
        )
        if (
            runtime_metadata["name_count"] != expected_tool_count
            or runtime_metadata["names_sha256"] != expected_names_sha256
        ):
            return {
                **base,
                "state": "runtime_schema_invalid",
                "source": dict(source),
                "recommended_next_action": (
                    "repair runtime schema observability before evaluating "
                    "platform publication"
                ),
            }
        probe = connector_contract.probe_contract(
            observed_names,
            observed_schemas,
            runtime_names,
            runtime_schemas,
            runtime_names,
            observed_source="platform",
        )
    except (TypeError, ValueError, ClientSnapshotError, connector_contract.ConnectorContractError) as exc:
        return {
            **base,
            "state": "invalid",
            "error": type(exc).__name__,
            "recommended_next_action": (
                "replace the invalid platform connector snapshot with a fresh "
                "platform-primary observation"
            ),
        }

    expected_binding = {
        "registered_tool_count": expected_tool_count,
        "registered_names_sha256": expected_names_sha256,
        "release_id": expected_release_id,
        "repo_head": expected_repo_head,
        "agent_instructions_sha256": expected_agent_instructions_sha256,
    }
    binding_mismatches = sorted(
        key
        for key, expected_value in expected_binding.items()
        if binding.get(key) != expected_value
    )
    if observed_metadata["name_count"] != expected_tool_count:
        binding_mismatches.append("observed_tool_count")
    if observed_metadata["names_sha256"] != expected_names_sha256:
        binding_mismatches.append("observed_names_sha256")
    binding_matches = not binding_mismatches
    future_clock_drift = observed_at > timestamp + SNAPSHOT_CLOCK_SKEW_SECONDS
    fresh = (
        not future_clock_drift
        and timestamp <= observed_at + PLATFORM_SNAPSHOT_TTL_SECONDS
    )
    matched = binding_matches and probe.get("matches") is True
    observable = fresh and matched
    if future_clock_drift:
        state = "clock_drift"
        next_action = (
            "replace the future-dated platform connector snapshot with a "
            "current platform observation"
        )
    elif not fresh:
        state = "stale"
        next_action = "capture a fresh platform connector catalog snapshot"
    elif not matched:
        state = "mismatch"
        next_action = (
            "capture the exact current platform connector catalog after "
            "repairing reported schema or revision drift"
        )
    else:
        state = "matched"
        next_action = "none"
    return {
        **base,
        "state": state,
        "observable": observable,
        "schema_observable": observable and probe.get("schema_contract_matches") is True,
        "fresh": fresh,
        "matched": matched,
        "source": dict(source),
        "snapshot_sha256": declared_snapshot_sha256,
        "runtime_binding": dict(binding),
        "runtime_binding_matches": binding_matches,
        "binding_mismatches": sorted(set(binding_mismatches)),
        "catalog": observed_metadata,
        "schema_contract_matches": probe.get("schema_contract_matches") is True,
        "required_schema_property_mismatches": probe.get(
            "required_schema_property_mismatches", []
        ),
        "probe": probe,
        "missing_from_platform": probe.get("missing_from_connector", []),
        "unexpected_in_platform": probe.get("unexpected_in_connector", []),
        "age_seconds": max(0, timestamp - observed_at),
        "recommended_next_action": next_action,
    }


def snapshot_status(
    *,
    expected_tool_count: int,
    expected_names_sha256: str,
    expected_release_id: str,
    expected_repo_head: str,
    expected_agent_instructions_sha256: str,
    expected_runtime_tools: dict[str, Any] | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    platform_snapshot = platform_snapshot_status(
        expected_tool_count=expected_tool_count,
        expected_names_sha256=expected_names_sha256,
        expected_release_id=expected_release_id,
        expected_repo_head=expected_repo_head,
        expected_agent_instructions_sha256=expected_agent_instructions_sha256,
        expected_runtime_tools=expected_runtime_tools,
        now_unix=timestamp,
    )
    platform_snapshot_observable = bool(platform_snapshot.get("observable"))
    platform_schema_observable = bool(
        platform_snapshot.get("schema_observable")
    )
    base = {
        "observable": False,
        "observation_scope": None,
        "schema_observable": False,
        "schema_evidence_observed": False,
        "schema_contract_matches": False,
        "external_client_snapshot_observable": False,
        "external_client_schema_observable": False,
        "platform_connector_snapshot_observable": platform_snapshot_observable,
        "platform_connector_schema_observable": platform_schema_observable,
        "platform_connector_snapshot_fresh": bool(platform_snapshot.get("fresh")),
        "platform_connector_snapshot_matched": bool(platform_snapshot.get("matched")),
        "platform_evidence_state": platform_snapshot.get("state"),
        "platform_snapshot": platform_snapshot,
        "server_loopback_observable": False,
        "server_loopback_schema_observable": False,
        "server_loopback_schema_contract_matches": False,
        "fresh": False,
        "matched": False,
        "verification_model": "client-declared-server-compared-v1",
        "does_not_establish": [
            "platform-enforced client snapshot identity",
            "that the client invoked every declared tool",
            "client instruction compliance",
            "resistance to compromised same-uid code",
            "platform publication from a client declaration alone",
        ],
    }
    try:
        with _state_lock():
            receipt = _read_private_json(SNAPSHOT_PATH)
        _validate_receipt(receipt)
    except FileNotFoundError:
        return {
            **base,
            "state": "missing",
            "recommended_next_action": "bind the current connector snapshot",
        }
    except (OSError, ValueError, ClientSnapshotError) as exc:
        return {
            **base,
            "state": "invalid",
            "error": type(exc).__name__,
            "recommended_next_action": (
                "inspect or replace the invalid connector snapshot receipt"
            ),
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
        return {
            **base,
            "state": "invalid",
            "error": "timestamp_contract",
            "recommended_next_action": (
                "replace the invalid connector snapshot receipt"
            ),
        }
    binding = receipt["server_binding"]
    declaration = receipt["client_declaration"]
    expected = {
        "registered_tool_count": expected_tool_count,
        "registered_names_sha256": expected_names_sha256,
        "release_id": expected_release_id,
        "repo_head": expected_repo_head,
        "agent_instructions_sha256": expected_agent_instructions_sha256,
    }
    binding_matches = all(
        binding.get(key) == value for key, value in expected.items()
    )
    declaration_matches = (
        declaration.get("observed_tool_count") == expected_tool_count
        and declaration.get("observed_names_sha256") == expected_names_sha256
        and declaration.get("observed_release_id") == expected_release_id
        and declaration.get("observed_agent_instructions_sha256")
        == expected_agent_instructions_sha256
    )
    observation_scope = declaration.get("observation_scope")
    if observation_scope not in {
        OBSERVATION_SCOPE_EXTERNAL_CLIENT,
        OBSERVATION_SCOPE_SERVER_LOOPBACK,
    }:
        observation_scope = _client_observation_scope(
            str(declaration.get("client_id", ""))
        )
    fresh = created_at - SNAPSHOT_CLOCK_SKEW_SECONDS <= timestamp <= expires_at
    matched = (
        receipt.get("verified") is True
        and not receipt.get("mismatches")
        and binding_matches
        and declaration_matches
    )
    observable = fresh and matched
    schema_evidence = receipt.get("schema_evidence")
    schema_probe = (
        schema_evidence.get("probe")
        if isinstance(schema_evidence, dict)
        and isinstance(schema_evidence.get("probe"), dict)
        else {}
    )
    schema_evidence_observed = bool(schema_probe)
    observed_schema_contract_matches = (
        schema_evidence_observed
        and schema_probe.get("matches") is True
        and schema_probe.get("schema_contract_matches") is True
    )
    external_client_snapshot_observable = (
        observable and observation_scope == OBSERVATION_SCOPE_EXTERNAL_CLIENT
    )
    server_loopback_observable = (
        observable and observation_scope == OBSERVATION_SCOPE_SERVER_LOOPBACK
    )
    external_client_schema_contract_matches = (
        observed_schema_contract_matches
        and observation_scope == OBSERVATION_SCOPE_EXTERNAL_CLIENT
    )
    server_loopback_schema_contract_matches = (
        observed_schema_contract_matches
        and observation_scope == OBSERVATION_SCOPE_SERVER_LOOPBACK
    )
    external_client_schema_observable = (
        external_client_snapshot_observable
        and external_client_schema_contract_matches
    )
    server_loopback_schema_observable = (
        server_loopback_observable
        and server_loopback_schema_contract_matches
    )
    if not fresh:
        state = "stale"
        next_action = "bind the current connector snapshot again"
    elif not matched:
        state = "mismatch"
        next_action = "refresh the connector tool snapshot and bind it again"
    else:
        state = "matched"
        next_action = (
            "none"
            if platform_snapshot_observable
            else str(
                platform_snapshot.get(
                    "recommended_next_action",
                    "capture authoritative platform connector publication evidence",
                )
            )
        )
    does_not_establish = list(
        receipt.get("does_not_establish") or base["does_not_establish"]
    )
    for limitation in (
        "platform connector catalog publication from the client receipt alone",
        "tool schema visibility in ChatGPT from the client receipt alone",
    ):
        if limitation not in does_not_establish:
            does_not_establish.append(limitation)
    return {
        **base,
        "state": state,
        "observable": observable,
        "observation_scope": observation_scope,
        "schema_observable": external_client_schema_observable,
        "schema_evidence_observed": schema_evidence_observed,
        "schema_contract_matches": external_client_schema_contract_matches,
        "external_client_snapshot_observable": (
            external_client_snapshot_observable
        ),
        "external_client_schema_observable": external_client_schema_observable,
        "platform_connector_snapshot_observable": platform_snapshot_observable,
        "platform_connector_schema_observable": platform_schema_observable,
        "platform_connector_snapshot_fresh": bool(platform_snapshot.get("fresh")),
        "platform_connector_snapshot_matched": bool(platform_snapshot.get("matched")),
        "platform_evidence_state": platform_snapshot.get("state"),
        "platform_snapshot": platform_snapshot,
        "server_loopback_observable": server_loopback_observable,
        "server_loopback_schema_observable": server_loopback_schema_observable,
        "server_loopback_schema_contract_matches": (
            server_loopback_schema_contract_matches
        ),
        "schema_probe": schema_probe,
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
        "verification_model": receipt.get(
            "verification_model", base["verification_model"]
        ),
        "recommended_next_action": next_action,
        "does_not_establish": does_not_establish,
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
        or parsed.hostname != "127.0.0.1"
        or parsed.port != 18181
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp"
    ):
        raise ClientSnapshotError(
            "MCP snapshot observer requires the bound loopback operator endpoint"
        )
    return AUTO_REFRESH_MCP_URL


async def _list_all_tools(client: Any) -> list[Any]:
    observed: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    while True:
        page = await client.list_tools(cursor=cursor)
        tools = getattr(page, "tools", None)
        if not isinstance(tools, list):
            raise ClientSnapshotError("tools/list returned an invalid page")
        observed.extend(tools)
        if len(observed) > connector_contract.MAX_OBSERVED_TOOLS:
            raise ClientSnapshotError("observed MCP tool count exceeds the snapshot contract")
        next_cursor = getattr(page, "nextCursor", None)
        if next_cursor is None:
            return observed
        if (
            not isinstance(next_cursor, str)
            or not next_cursor
            or len(next_cursor.encode("utf-8")) > 1024
            or next_cursor in seen_cursors
        ):
            raise ClientSnapshotError("tools/list returned an invalid pagination cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


def _mixed_observed_tool_artifact(tools: list[Any]) -> dict[str, Any]:
    runtime_tools = [
        {
            "name": getattr(tool, "name", None),
            "inputSchema": getattr(tool, "inputSchema", None),
        }
        for tool in tools
    ]
    try:
        return connector_contract.mixed_artifact_from_runtime_tools(runtime_tools)
    except connector_contract.ConnectorContractError as exc:
        raise _contract_error(exc) from exc


async def _list_all_tool_names(client: Any) -> list[str]:
    return [getattr(tool, "name", None) for tool in await _list_all_tools(client)]


async def _observe_and_bind_snapshot(
    *,
    mcp_url: str,
    session_id: str,
    connector_capability: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
    except ImportError as exc:
        raise ClientSnapshotError("MCP client runtime is unavailable") from exc

    mcp_url = _validate_loopback_mcp_url(mcp_url)
    if (
        not isinstance(connector_capability, str)
        or _TRANSPORT_CONNECTOR_TOKEN_RE.fullmatch(connector_capability) is None
    ):
        raise ClientSnapshotError("transport connector capability is invalid")

    async def observe() -> dict[str, Any]:
        async with streamablehttp_client(
            mcp_url,
            headers={
                TRANSPORT_CONNECTOR_CAPABILITY_HEADER: connector_capability,
            },
        ) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                tools = await _list_all_tools(client)
                observed_tools = _mixed_observed_tool_artifact(tools)
                names, _schemas, observed_metadata = (
                    connector_contract.parse_observed_artifact(
                        observed_tools,
                        label="connector tools/list artifact",
                    )
                )
                names_sha256 = observed_metadata["names_sha256"]
                request_meta = {"client_id": AUTO_REFRESH_CLIENT_ID}
                status_result = await client.call_tool(
                    "grabowski_status",
                    {"view": "minimal"},
                    meta=request_meta,
                )
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
                # The exact bind call has to exist before the handshake, because
                # the verification is bound to this tool name and this argument
                # digest and admits nothing else.
                declaration = {
                    "client_id": AUTO_REFRESH_CLIENT_ID,
                    "session_id": session_id,
                    "observed_tool_count": len(names),
                    "observed_names_sha256": names_sha256,
                    "observed_release_id": release_id,
                    "observed_agent_instructions_sha256": instructions_sha256,
                    "observed_tools": observed_tools,
                }
                bind_arguments = {
                    "name": "connector-snapshot-bind",
                    "parameters": declaration,
                    "profile": "operator",
                    "allow_mutation": True,
                }
                transport_begin_result = await client.call_tool(
                    "grip_run",
                    {
                        "name": "transport-roundtrip",
                        "parameters": {
                            "action": "begin",
                            "target_tool_name": "grip_run",
                            "target_arguments": bind_arguments,
                        },
                        "profile": "operator",
                        "allow_mutation": True,
                    },
                    meta=request_meta,
                )
                transport_begin = _mcp_tool_payload(
                    transport_begin_result,
                    label="transport roundtrip begin grip",
                )
                transport_begin_output = transport_begin.get("output")
                if (
                    transport_begin.get("status") != "passed"
                    or not isinstance(transport_begin_output, dict)
                ):
                    raise ClientSnapshotError(
                        "transport roundtrip begin did not return a valid receipt"
                    )
                transport_verification_receipt_sha256 = (
                    transport_begin_output.get(
                        "verification_receipt_sha256"
                    )
                )
                if (
                    transport_begin_output.get("state") == "verified"
                    and transport_begin_output.get("mutation_gate_open") is True
                    and isinstance(
                        transport_verification_receipt_sha256, str
                    )
                    and _SHA256_RE.fullmatch(
                        transport_verification_receipt_sha256
                    )
                    is not None
                ):
                    pass
                else:
                    challenge_receipt_sha256 = (
                        transport_begin_output.get(
                            "challenge_receipt_sha256"
                        )
                    )
                    if (
                        transport_begin_output.get("state")
                        != "challenge_pending"
                        or not isinstance(challenge_receipt_sha256, str)
                        or _SHA256_RE.fullmatch(
                            challenge_receipt_sha256
                        )
                        is None
                    ):
                        raise ClientSnapshotError(
                            "transport roundtrip begin did not return a valid challenge"
                        )
                    transport_ack_result = await client.call_tool(
                        "grip_run",
                        {
                            "name": "transport-roundtrip",
                            "parameters": {
                                "action": "ack",
                                "challenge_receipt_sha256": (
                                    challenge_receipt_sha256
                                ),
                            },
                            "profile": "operator",
                            "allow_mutation": True,
                        },
                        meta=request_meta,
                    )
                    transport_ack = _mcp_tool_payload(
                        transport_ack_result,
                        label="transport roundtrip ack grip",
                    )
                    transport_ack_output = transport_ack.get("output")
                    transport_verification_receipt_sha256 = (
                        transport_ack_output.get(
                            "verification_receipt_sha256"
                        )
                        if isinstance(transport_ack_output, dict)
                        else None
                    )
                    if (
                        transport_ack.get("status") != "passed"
                        or not isinstance(transport_ack_output, dict)
                        or transport_ack_output.get("state") != "verified"
                        or transport_ack_output.get(
                            "mutation_gate_open"
                        )
                        is not True
                        or not isinstance(
                            transport_verification_receipt_sha256, str
                        )
                        or _SHA256_RE.fullmatch(
                            transport_verification_receipt_sha256
                        )
                        is None
                    ):
                        raise ClientSnapshotError(
                            "transport roundtrip acknowledgement did not verify"
                        )
                # Exactly the arguments the verification was bound to; any
                # deviation would be refused by the gate.
                bind_result = await client.call_tool(
                    "grip_run",
                    bind_arguments,
                    meta=request_meta,
                )
                grip = _mcp_tool_payload(bind_result, label="connector-snapshot-bind grip")
                output = grip.get("output")
                if (
                    grip.get("status") != "passed"
                    or not isinstance(output, dict)
                    or output.get("verified") is not True
                    or output.get("state") != "matched"
                    or output.get("schema_contract_matches") is not True
                ):
                    raise ClientSnapshotError("connector snapshot bind did not pass verification")
                return {
                    "state": "renewed",
                    "tool_count": len(names),
                    "names_sha256": names_sha256,
                    "release_id": release_id,
                    "receipt_sha256": output.get("receipt_sha256"),
                    "transport_verification_receipt_sha256": (
                        transport_verification_receipt_sha256
                    ),
                    "schema_coverage_count": observed_metadata[
                        "schema_coverage_count"
                    ],
                    "observed_tools_artifact_sha256": observed_metadata[
                        "artifact_sha256"
                    ],
                    "schema_contract_matches": True,
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
    connector_token_path: Path = AUTO_REFRESH_CONNECTOR_TOKEN_PATH,
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
    connector_capability = _read_transport_connector_capability(
        connector_token_path
    )
    result = asyncio.run(
        _observe_and_bind_snapshot(
            mcp_url=_validate_loopback_mcp_url(mcp_url),
            session_id=session_id,
            connector_capability=connector_capability,
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


def _runtime_platform_binding(runtime_root: Path) -> tuple[dict[str, Any], list[str]]:
    try:
        root = runtime_root.expanduser().resolve(strict=True)
        manifest_path = root / "deployment-manifest.json"
        metadata = manifest_path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_DEPLOYMENT_MANIFEST_BYTES
        ):
            raise ClientSnapshotError("runtime deployment manifest is unavailable")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClientSnapshotError("runtime deployment manifest is unavailable") from exc
    if not isinstance(payload, dict) or payload.get("completion_status") != "complete":
        raise ClientSnapshotError("runtime deployment manifest is incomplete")
    entrypoint = payload.get("entrypoint_contract")
    instructions = payload.get("agent_instructions")
    if not isinstance(entrypoint, dict) or not isinstance(instructions, dict):
        raise ClientSnapshotError("runtime deployment manifest contract is incomplete")
    expected_tools = entrypoint.get("expected_tools")
    if (
        not isinstance(expected_tools, list)
        or not expected_tools
        or len(expected_tools) > connector_contract.MAX_OBSERVED_TOOLS
        or any(
            not isinstance(name, str)
            or not name
            or len(name.encode("utf-8")) > 512
            for name in expected_tools
        )
        or len(set(expected_tools)) != len(expected_tools)
    ):
        raise ClientSnapshotError("runtime deployment manifest tool contract is invalid")
    release_id = _validate_release_id(
        payload.get("release_id"), label="runtime release id"
    )
    repo_head = payload.get("repo_head")
    if (
        not isinstance(repo_head, str)
        or re.fullmatch(r"[0-9a-f]{40}", repo_head) is None
    ):
        raise ClientSnapshotError("runtime repository head is invalid")
    instructions_sha256 = _validate_sha256(
        instructions.get("sha256"), label="runtime agent instructions sha256"
    )
    return (
        {
            "registered_tool_count": len(expected_tools),
            "registered_names_sha256": connector_contract.fingerprint(expected_tools),
            "release_id": release_id,
            "repo_head": repo_head,
            "agent_instructions_sha256": instructions_sha256,
        },
        list(expected_tools),
    )


def _validate_platform_source_reference(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > 1024
    ):
        raise ClientSnapshotError("platform connector source reference is invalid")
    return value


def _build_platform_connector_snapshot_with_runtime_names(
    *,
    observed_tools: dict[str, Any],
    runtime_root: Path,
    source_reference: str,
    observed_at_unix: int | None = None,
) -> tuple[dict[str, Any], list[str]]:
    timestamp = int(time.time()) if observed_at_unix is None else observed_at_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ClientSnapshotError("platform connector observation time is invalid")
    reference = _validate_platform_source_reference(source_reference)
    try:
        _observed_names, _observed_schemas, observed_metadata = (
            connector_contract.parse_observed_artifact(
                observed_tools,
                label="platform connector catalog artifact",
            )
        )
    except connector_contract.ConnectorContractError as exc:
        raise ClientSnapshotError(str(exc)) from exc
    runtime_binding, runtime_names = _runtime_platform_binding(runtime_root)
    document: dict[str, Any] = {
        "schema_version": PLATFORM_SNAPSHOT_SCHEMA_VERSION,
        "kind": PLATFORM_SNAPSHOT_KIND,
        "source": {
            "kind": PLATFORM_SOURCE_KIND,
            "connector": "grabowski",
            "reference": reference,
            "observed_at_unix": timestamp,
            "catalog_sha256": observed_metadata["artifact_sha256"],
        },
        "runtime_binding": runtime_binding,
        "observed_tools": observed_tools,
    }
    document["snapshot_sha256"] = _sha256_json(document)
    encoded = _canonical_bytes(document)
    if len(encoded) > MAX_PLATFORM_SNAPSHOT_BYTES:
        raise ClientSnapshotError("platform connector snapshot exceeds size limit")
    return document, runtime_names


def build_platform_connector_snapshot(
    *,
    observed_tools: dict[str, Any],
    runtime_root: Path,
    source_reference: str,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    document, _runtime_names = _build_platform_connector_snapshot_with_runtime_names(
        observed_tools=observed_tools,
        runtime_root=runtime_root,
        source_reference=source_reference,
        observed_at_unix=observed_at_unix,
    )
    return document


def _validate_platform_snapshot_parent(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ClientSnapshotError(
            "platform connector snapshot parent is unavailable"
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != PLATFORM_SNAPSHOT_TRUSTED_UID
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ClientSnapshotError(
            "platform connector snapshot parent is not a trusted root-owned directory"
        )


def _persist_platform_snapshot(document: dict[str, Any]) -> None:
    if os.geteuid() != PLATFORM_SNAPSHOT_TRUSTED_UID:
        raise ClientSnapshotError(
            "platform connector snapshot capture requires the trusted root authority"
        )
    target = PLATFORM_SNAPSHOT_PATH
    parent = target.parent
    _validate_platform_snapshot_parent(parent)
    try:
        current = target.lstat()
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise ClientSnapshotError(
            "platform connector snapshot destination cannot be inspected safely"
        ) from exc
    if current is not None:
        _validate_platform_snapshot_file(
            current, label="existing platform connector snapshot"
        )

    encoded = _canonical_bytes(document)
    if len(encoded) > MAX_PLATFORM_SNAPSHOT_BYTES:
        raise ClientSnapshotError("platform connector snapshot exceeds size limit")
    temporary = parent / (
        f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise OSError("platform connector snapshot write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, target)
        directory_fd = os.open(
            parent,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise ClientSnapshotError(
            "platform connector snapshot persistence failed"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    persisted = _read_platform_snapshot(target)
    if persisted != document:
        raise ClientSnapshotError(
            "platform connector snapshot readback does not match the captured document"
        )


def capture_platform_connector_snapshot(
    *,
    observed_tools: dict[str, Any],
    runtime_root: Path,
    source_reference: str,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    document, runtime_names = _build_platform_connector_snapshot_with_runtime_names(
        observed_tools=observed_tools,
        runtime_root=runtime_root,
        source_reference=source_reference,
        observed_at_unix=observed_at_unix,
    )
    _persist_platform_snapshot(document)
    try:
        observed_names, _observed_schemas, observed_metadata = (
            connector_contract.parse_observed_artifact(
                observed_tools,
                label="platform connector catalog artifact",
            )
        )
    except connector_contract.ConnectorContractError as exc:
        raise ClientSnapshotError(str(exc)) from exc
    missing_from_platform = sorted(set(runtime_names) - set(observed_names))
    unexpected_in_platform = sorted(set(observed_names) - set(runtime_names))
    return {
        "state": "captured",
        "snapshot_sha256": document["snapshot_sha256"],
        "catalog_sha256": observed_metadata["artifact_sha256"],
        "observed_tool_count": len(observed_names),
        "runtime_tool_count": len(runtime_names),
        "name_contract_matches": (
            not missing_from_platform and not unexpected_in_platform
        ),
        "missing_from_platform": missing_from_platform,
        "unexpected_in_platform": unexpected_in_platform,
        "schema_coverage_count": observed_metadata["schema_coverage_count"],
        "source_reference": document["source"]["reference"],
    }


def _auto_refresh_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Grabowski connector snapshot maintenance")
    subparsers = parser.add_subparsers(dest="command", required=True)
    refresh = subparsers.add_parser("refresh-if-needed")
    refresh.add_argument("--runtime-root", type=Path, required=True)
    refresh.add_argument("--mcp-url", default=AUTO_REFRESH_MCP_URL)
    refresh.add_argument(
        "--connector-token-file",
        type=Path,
        default=AUTO_REFRESH_CONNECTOR_TOKEN_PATH,
    )
    refresh.add_argument("--connector-pid", type=int, required=True)
    refresh.add_argument("--connector-start-ticks", type=int, required=True)
    refresh.add_argument(
        "--renewal-margin-seconds", type=int, default=AUTO_REFRESH_RENEW_MARGIN_SECONDS
    )
    refresh.add_argument("--timeout-seconds", type=float, default=AUTO_REFRESH_TIMEOUT_SECONDS)
    capture = subparsers.add_parser(
        "capture-platform",
        help="Persist one controller-observed ChatGPT connector catalog as root-owned evidence.",
    )
    capture.add_argument("--runtime-root", type=Path, required=True)
    capture.add_argument("--source-reference", required=True)
    capture.add_argument("--observed-tools-json", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _auto_refresh_parser().parse_args(argv)
    try:
        if args.command == "refresh-if-needed":
            result = refresh_connector_snapshot_if_needed(
                runtime_root=args.runtime_root,
                mcp_url=args.mcp_url,
                connector_pid=args.connector_pid,
                connector_start_ticks=args.connector_start_ticks,
                connector_token_path=args.connector_token_file,
                renewal_margin_seconds=args.renewal_margin_seconds,
                timeout_seconds=args.timeout_seconds,
            )
        elif args.command == "capture-platform":
            try:
                observed_tools = json.loads(args.observed_tools_json)
            except json.JSONDecodeError as exc:
                raise ClientSnapshotError(
                    "platform connector catalog artifact is not valid JSON"
                ) from exc
            if not isinstance(observed_tools, dict):
                raise ClientSnapshotError(
                    "platform connector catalog artifact must be a JSON object"
                )
            result = capture_platform_connector_snapshot(
                observed_tools=observed_tools,
                runtime_root=args.runtime_root,
                source_reference=args.source_reference,
            )
        else:
            raise ClientSnapshotError("unsupported snapshot maintenance command")
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

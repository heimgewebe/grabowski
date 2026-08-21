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
PLATFORM_SNAPSHOT_V2_SCHEMA_VERSION = 2
PLATFORM_SNAPSHOT_KIND = "grabowski_platform_connector_snapshot"
PLATFORM_SNAPSHOT_PATH = Path("/run/grabowski/platform-connector-snapshot.json")
PLATFORM_SNAPSHOT_TRUSTED_UID = 0
PLATFORM_SNAPSHOT_MODE = 0o644
PLATFORM_SNAPSHOT_TTL_SECONDS = 3_600
MAX_PLATFORM_SNAPSHOT_BYTES = 64 * 1024
PLATFORM_SOURCE_KIND = "chatgpt_connector_catalog"
PLATFORM_PUBLICATION_ROOT = STATE_ROOT / "platform-publication"
PLATFORM_PUBLICATION_REQUEST_ROOT = PLATFORM_PUBLICATION_ROOT / "requests"
PLATFORM_PUBLICATION_ATTEMPT_ROOT = PLATFORM_PUBLICATION_ROOT / "attempts"
PLATFORM_PUBLICATION_RECEIPT_ROOT = PLATFORM_PUBLICATION_ROOT / "receipts"
PLATFORM_PUBLICATION_RESOLUTION_ROOT = PLATFORM_PUBLICATION_ROOT / "resolutions"
PLATFORM_PUBLICATION_CURRENT_PATH = PLATFORM_PUBLICATION_ROOT / "current.json"
BLUE_GREEN_RECEIPT_ROOT = (
    Path.home() / ".local/state/grabowski/blue-green-deployment-receipts"
)
PLATFORM_PUBLICATION_REQUEST_KIND = "grabowski_platform_publication_request"
PLATFORM_PUBLICATION_ATTEMPT_KIND = "grabowski_platform_publication_attempt"
PLATFORM_PUBLICATION_RECEIPT_KIND = "grabowski_platform_publication_convergence_receipt"
PLATFORM_PUBLICATION_RESOLUTION_KIND = "grabowski_platform_publication_resolution"
PLATFORM_PUBLICATION_CURRENT_KIND = "grabowski_platform_publication_current"
PLATFORM_PUBLICATION_ACTION = "refresh_or_republish_chatgpt_connector_catalog"
PLATFORM_OBSERVATION_SCOPES = frozenset(
    {"connector_catalog", "new_chat_catalog", "chat_session_catalog"}
)
PLATFORM_CONVERGENCE_SCOPES = frozenset({"connector_catalog", "new_chat_catalog"})
PLATFORM_PUBLICATION_CURRENT_STATES = frozenset(
    {
        "no_current",
        "pending_activation",
        "publication_pending",
        "awaiting_platform_observation",
        "outcome_unknown",
        "platform_converged",
    }
)
PLATFORM_PUBLICATION_ATTEMPT_OUTCOMES = frozenset(
    {"submitted", "outcome_unknown", "failed"}
)
AUTO_REFRESH_CLIENT_ID = "grabowski-tunnel-watchdog-observer-v1"
OBSERVATION_SCOPE_EXTERNAL_CLIENT = "external_client_declared"
OBSERVATION_SCOPE_SERVER_LOOPBACK = "server_loopback_watchdog"
AUTO_REFRESH_MCP_URL = "http://127.0.0.1:18181/mcp"
AUTO_REFRESH_CONNECTOR_TOKEN_PATH = (
    Path.home() / ".local/state/grabowski/transport-connectors/primary.token"
)
TRANSPORT_CONNECTOR_CAPABILITY_HEADER = "X-Grabowski-Connector-Capability"
TRANSPORT_INGRESS_AUTH_HEADER = "X-Grabowski-Ingress-Auth"
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
            or before.st_size != linked.st_size
            or before.st_mtime_ns != linked.st_mtime_ns
            or before.st_ctime_ns != linked.st_ctime_ns
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
    token = token.rstrip("\r\n")
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
        complete_schema_evidence_present = (
            observed_metadata.get("complete_schema_observable") is True
            or server_metadata.get("complete_schema_observable") is True
        )
        complete_schema_matches = (
            observed_metadata.get("complete_schema_observable") is True
            and server_metadata.get("complete_schema_observable") is True
            and observed_metadata.get("complete_schema_count")
            == server_metadata.get("complete_schema_count")
            == contract["registered_tool_count"]
            and observed_metadata.get("complete_schema_sha256")
            == server_metadata.get("complete_schema_sha256")
        )
        if complete_schema_evidence_present and not complete_schema_matches:
            mismatches.append("complete_schema_identity")
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
                "observed_complete_schema_count": schema_evidence[
                    "observed_artifact"
                ].get("complete_schema_count"),
                "observed_complete_schema_sha256": schema_evidence[
                    "observed_artifact"
                ].get("complete_schema_sha256"),
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


def _require_authentic_digest(value: Any, *, label: str) -> str:
    digest = _validate_sha256(value, label=label)
    if len(set(digest)) == 1:
        raise ClientSnapshotError(f"{label} is synthetic and cannot prove cutover")
    return digest


def _require_schema_identity(
    value: Any, *, label: str
) -> tuple[dict[str, str], str]:
    required = set(connector_contract.REQUIRED_SCHEMA_SENTINELS)
    if not isinstance(value, dict) or set(value) != required:
        raise ClientSnapshotError(
            f"{label} must cover exactly the required schema sentinels"
        )
    normalized = {
        name: _validate_sha256(value[name], label=f"{label}.{name}")
        for name in sorted(required)
    }
    return normalized, _sha256_json(normalized)


#: Publication-v2 states in which the green tool contract is already the
#: authorised one.  ``publication_pending`` is the first such state: the request
#: has been activated against the live runtime and the platform refresh is what
#: is still outstanding.  Every later state only adds observation evidence on
#: top of that same authorisation.
PUBLICATION_REBIND_AUTHORIZED_STATES = frozenset(
    {
        "publication_pending",
        "awaiting_platform_observation",
        "outcome_unknown",
        "convergence_observed_unreconciled",
        "platform_converged",
    }
)
#: Durable current states that are *not* an activation, whatever the lifecycle
#: projection reports.  ``pending_activation`` projects as ``outcome_unknown``
#: because the active runtime has not been read back yet -- which is the correct
#: thing to tell an operator, and exactly the wrong thing to accept as
#: authorisation. The durable state is checked separately for that reason.
PUBLICATION_REBIND_FORBIDDEN_CURRENT_STATES = frozenset({"pending_activation"})

SNAPSHOT_BINDING_PREDECESSOR = "bound_to_predecessor"
SNAPSHOT_BINDING_REBOUND = "rebound_by_this_lineage"
SNAPSHOT_BINDING_FOREIGN = "foreign"
SNAPSHOT_BINDING_UNREADABLE = "unreadable"


def _historical_snapshot_freshness(
    receipt: dict[str, Any], *, source_evidence_time: int
) -> tuple[int, int]:
    """Validate source freshness on the historical evidence clock.

    Recovery time controls the lifetime of the newly written receipt.  It must
    never be substituted for the time at which the predecessor observation was
    actually made: doing so would both expire legitimate legacy evidence and
    create a general stale-snapshot bypass.
    """
    if (
        isinstance(source_evidence_time, bool)
        or not isinstance(source_evidence_time, int)
        or source_evidence_time < 0
    ):
        raise ClientSnapshotError("source evidence time is invalid")
    created = receipt.get("created_at_unix")
    expires = receipt.get("expires_at_unix")
    if (
        isinstance(created, bool)
        or not isinstance(created, int)
        or isinstance(expires, bool)
        or not isinstance(expires, int)
        or not (
            created - SNAPSHOT_CLOCK_SKEW_SECONDS
            <= source_evidence_time
            <= expires
        )
    ):
        raise ClientSnapshotError(
            "authentic connector snapshot was not fresh at source evidence time"
        )
    return created, expires


def _authorized_publication_schema_transition(
    *,
    cutover_id: str,
    source_tool_count: int,
    source_names_sha256: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    green_complete_schema_count: Any,
    green_complete_schema_sha256: str,
    source_schema_identity_sha256: str,
    source_complete_schema_sha256: str,
    target_schema_identity_sha256: str,
    green_readiness: dict[str, Any],
    schema_changed: bool,
    now_unix: int,
    expected_publication_request_id: str | None = None,
) -> dict[str, Any]:
    """Authorise a *changed* green tool surface against durable Publication-v2.

    Continuity of the connector surface is the ordinary case, and for it no
    authorisation is required at all.  A schema change is different: the client
    that produced the prior declaration observed a surface that no longer
    exists.  Refusing every such change -- the old behaviour -- made an
    authorised schema rollout impossible; accepting it silently would let the
    rebind assert an observation nobody made.

    So the change must be authorised by evidence that already exists and was
    written before the rebind: an activated publication request naming this
    exact cutover and this exact green tool contract.  Nothing is derived from
    the caller: every value is recomputed and compared against the durable
    request, the durable current projection and the lifecycle projection.
    """
    if (
        isinstance(source_tool_count, bool)
        or not isinstance(source_tool_count, int)
        or source_tool_count < 1
    ):
        raise ClientSnapshotError("source publication tool count is invalid")
    source_names_sha256 = _require_authentic_digest(
        source_names_sha256, label="source publication names hash"
    )
    if type(schema_changed) is not bool:
        raise ClientSnapshotError("schema_changed must be a boolean")
    target_contract = _platform_publication_contract(
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        complete_schema_count=green_complete_schema_count,
        complete_schema_sha256=green_complete_schema_sha256,
    )
    try:
        current = _read_publication_current()
    except (OSError, ClientSnapshotError) as exc:
        raise ClientSnapshotError(
            "connector schema changed but the platform publication projection is unreadable"
        ) from exc
    if current is None or current.get("state") == "no_current":
        raise ClientSnapshotError(
            "connector schema changed but no platform publication request authorises "
            "the green tool contract"
        )
    request_id = current["request_id"]
    if (
        expected_publication_request_id is not None
        and request_id != expected_publication_request_id
    ):
        raise ClientSnapshotError(
            "platform publication current does not name the cutover activation request"
        )
    try:
        request = _read_publication_request(request_id)
    except (OSError, ClientSnapshotError) as exc:
        raise ClientSnapshotError(
            "connector schema changed but the platform publication request evidence is unreadable"
        ) from exc
    if request["cutover_id"] != cutover_id:
        raise ClientSnapshotError(
            "platform publication request authorises a different cutover"
        )
    expected_contract = request["expected_contract"]
    for label, observed, expected in (
        ("tool count", expected_contract["tool_count"], registered_tool_count),
        (
            "tool names hash",
            expected_contract["tool_names_sha256"],
            registered_names_sha256,
        ),
        (
            "complete schema count",
            expected_contract["tool_schemas_count"],
            green_complete_schema_count,
        ),
        (
            "complete schema hash",
            expected_contract["tool_schemas_sha256"],
            green_complete_schema_sha256,
        ),
        (
            "tool contract hash",
            expected_contract["tool_contract_sha256"],
            target_contract["tool_contract_sha256"],
        ),
        (
            "current contract hash",
            current["contract_sha256"],
            target_contract["tool_contract_sha256"],
        ),
    ):
        if observed != expected:
            raise ClientSnapshotError(
                f"platform publication {label} does not authorise the green surface"
            )
    projection = _publication_projection_for_contract(
        target_contract, now_unix=now_unix
    )
    state = projection.get("state")
    if projection.get("request_id") != request_id:
        raise ClientSnapshotError(
            "platform publication projection binds a different request"
        )
    durable_state = current["state"]
    if (
        durable_state in PUBLICATION_REBIND_FORBIDDEN_CURRENT_STATES
        or state not in PUBLICATION_REBIND_AUTHORIZED_STATES
    ):
        raise ClientSnapshotError(
            "platform publication request is not activated for the green tool "
            f"contract (state {durable_state!r}/{state!r})"
        )
    material = {
        "schema_version": 1,
        "kind": "grabowski_connector_schema_transition",
        "schema_changed": schema_changed,
        "surface_changed": True,
        "cutover_id": cutover_id,
        "source_tool_count": source_tool_count,
        "source_names_sha256": source_names_sha256,
        "target_tool_count": registered_tool_count,
        "target_names_sha256": registered_names_sha256,
        "source_schema_identity_sha256": source_schema_identity_sha256,
        "source_complete_schema_sha256": source_complete_schema_sha256,
        "target_schema_identity_sha256": target_schema_identity_sha256,
        "target_complete_schema_sha256": green_complete_schema_sha256,
        "green_readiness_sha256": _sha256_json(green_readiness),
        "publication_request_id": request_id,
        "publication_request_sha256": request["request_sha256"],
        "publication_contract_sha256": target_contract["tool_contract_sha256"],
        "publication_state": state,
        "publication_current_state": durable_state,
        "authorized_at_unix": now_unix,
        "does_not_establish": [
            "that any client has observed the changed green surface",
            "platform connector catalog publication",
        ],
    }
    return {**material, "transition_sha256": _sha256_json(material)}


def _rebind_snapshot_for_cutover(
    *,
    cutover_id: str,
    cutover_generation: int,
    current_release_id: str,
    current_repo_head: str,
    green_release_id: str,
    green_repo_head: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    observation_scope: str,
    verification_model: str,
    recommended_next_action: str,
    scope_error: str,
    additional_nonclaims: tuple[str, ...],
    source_evidence_time: int | None = None,
    publication_request_id: str | None = None,
    now_unix: int | None = None,
    expected_source_snapshot_receipt_sha256: str | None = None,
    expected_source_client_declaration_sha256: str | None = None,
    expected_classified_snapshot_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    """Rebind one prior blue declaration to independently verified Green.

    The source observation scope is explicit. This proves surface continuity
    only; a server-loopback source never upgrades platform publication evidence.
    """
    if observation_scope not in {
        OBSERVATION_SCOPE_EXTERNAL_CLIENT,
        OBSERVATION_SCOPE_SERVER_LOOPBACK,
    }:
        raise ClientSnapshotError("cutover snapshot source scope is invalid")
    timestamp = int(time.time()) if now_unix is None else now_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ClientSnapshotError("snapshot timestamp is invalid")
    cutover_binding = _optional_cutover_binding(
        {
            "cutover_id": cutover_id,
            "cutover_generation": cutover_generation,
        }
    )
    assert cutover_binding is not None
    if (
        isinstance(registered_tool_count, bool)
        or not isinstance(registered_tool_count, int)
        or not 1 <= registered_tool_count <= 1_000
    ):
        raise ClientSnapshotError("registered tool count is invalid")
    names_sha256 = _require_authentic_digest(
        registered_names_sha256, label="registered_names_sha256"
    )
    instructions_sha256 = _require_authentic_digest(
        agent_instructions_sha256, label="agent_instructions_sha256"
    )
    expected_snapshot_identity = (
        expected_source_snapshot_receipt_sha256,
        expected_source_client_declaration_sha256,
        expected_classified_snapshot_receipt_sha256,
    )
    if any(value is not None for value in expected_snapshot_identity):
        if any(value is None for value in expected_snapshot_identity):
            raise ClientSnapshotError(
                "classified snapshot identity must be supplied as one complete binding"
            )
        expected_source_snapshot_receipt_sha256 = _require_authentic_digest(
            expected_source_snapshot_receipt_sha256,
            label="expected source snapshot receipt_sha256",
        )
        expected_source_client_declaration_sha256 = _require_authentic_digest(
            expected_source_client_declaration_sha256,
            label="expected source client_declaration_sha256",
        )
        expected_classified_snapshot_receipt_sha256 = _require_authentic_digest(
            expected_classified_snapshot_receipt_sha256,
            label="expected classified snapshot receipt_sha256",
        )
    current_release = _validate_release_id(
        current_release_id, label="current release id"
    )
    green_release = _validate_release_id(
        green_release_id, label="green release id"
    )
    for label, head in (
        ("current repository head", current_repo_head),
        ("green repository head", green_repo_head),
    ):
        if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40,64}", head) is None:
            raise ClientSnapshotError(f"{label} is invalid")
    if (
        not isinstance(green_readiness, dict)
        or green_readiness.get("ready") is not True
        or green_readiness.get("release_id") != green_release
        or green_readiness.get("repo_head") != green_repo_head
        or green_readiness.get("names_sha256") != names_sha256
        or green_readiness.get("agent_instructions_sha256")
        != instructions_sha256
    ):
        raise ClientSnapshotError(
            "green readiness is not bound to the requested snapshot transition"
        )

    with _state_lock():
        try:
            source = _read_private_json(SNAPSHOT_PATH)
        except FileNotFoundError as exc:
            raise ClientSnapshotError(
                "authentic connector snapshot is unavailable"
            ) from exc
        _validate_receipt(source)
        source_receipt_sha256 = _require_authentic_digest(
            source.get("receipt_sha256"), label="source receipt_sha256"
        )
        source_declaration_sha256 = _require_authentic_digest(
            source.get("client_declaration_sha256"),
            label="source client_declaration_sha256",
        )
        if expected_source_snapshot_receipt_sha256 is not None and (
            source_receipt_sha256
            != expected_source_snapshot_receipt_sha256
            or source_receipt_sha256
            != expected_classified_snapshot_receipt_sha256
            or source_declaration_sha256
            != expected_source_client_declaration_sha256
        ):
            raise ClientSnapshotError(
                "classified predecessor snapshot identity changed before rebind"
            )
        historical_time = (
            timestamp if source_evidence_time is None else source_evidence_time
        )
        created, expires = _historical_snapshot_freshness(
            source, source_evidence_time=historical_time
        )
        declaration = source.get("client_declaration")
        source_binding = source.get("server_binding")
        schema_evidence = source.get("schema_evidence")
        if (
            source.get("verified") is not True
            or source.get("mismatches")
            or not isinstance(declaration, dict)
            or declaration.get("observation_scope") != observation_scope
            or not isinstance(source_binding, dict)
            or not isinstance(schema_evidence, dict)
            or not isinstance(schema_evidence.get("probe"), dict)
            or schema_evidence["probe"].get("matches") is not True
            or schema_evidence["probe"].get("schema_contract_matches") is not True
        ):
            raise ClientSnapshotError(scope_error)
        source_tool_count = declaration.get("observed_tool_count")
        if (
            isinstance(source_tool_count, bool)
            or not isinstance(source_tool_count, int)
            or not 1 <= source_tool_count <= 1_000
        ):
            raise ClientSnapshotError("source connector tool count is invalid")
        source_names_sha256 = _require_authentic_digest(
            declaration.get("observed_names_sha256"),
            label="source observed names hash",
        )
        source_instructions_sha256 = _require_authentic_digest(
            declaration.get("observed_agent_instructions_sha256"),
            label="source observed instructions hash",
        )
        if (
            source_binding.get("release_id") != current_release
            or source_binding.get("repo_head") != current_repo_head
            or declaration.get("observed_release_id") != current_release
            or source_binding.get("registered_tool_count") != source_tool_count
            or source_binding.get("registered_names_sha256") != source_names_sha256
            or source_binding.get("agent_instructions_sha256")
            != source_instructions_sha256
        ):
            raise ClientSnapshotError(
                "authentic connector snapshot source binding is internally inconsistent"
            )
        # Publication-v2 binds the target tool contract (count, names and schemas),
        # but it does not bind agent instructions.  Keep that dimension on strict
        # historical continuity instead of silently widening publication authority.
        if source_instructions_sha256 != instructions_sha256:
            raise ClientSnapshotError(
                "green agent instructions differ from the authentic blue declaration"
            )
        for label, value in (
            ("observed names hash", declaration.get("observed_names_sha256")),
            (
                "observed instructions hash",
                declaration.get("observed_agent_instructions_sha256"),
            ),
            (
                "observed artifact hash",
                declaration.get("observed_tools_artifact_sha256"),
            ),
        ):
            _require_authentic_digest(value, label=label)

        observed_artifact = schema_evidence.get("observed_artifact")
        if not isinstance(observed_artifact, dict):
            raise ClientSnapshotError(
                "bound source connector schema identity is unavailable"
            )
        source_schema_hashes, source_schema_identity_sha256 = (
            _require_schema_identity(
                observed_artifact.get("schema_sha256_by_tool"),
                label="source sentinel schema identity",
            )
        )
        green_schema_hashes, green_schema_identity_sha256 = _require_schema_identity(
            green_readiness.get("schema_sha256_by_tool"),
            label="green sentinel schema identity",
        )
        source_complete_schema_count = observed_artifact.get("complete_schema_count")
        source_complete_schema_sha256 = observed_artifact.get("complete_schema_sha256")
        green_complete_schema_count = green_readiness.get("complete_schema_count")
        green_complete_schema_sha256 = green_readiness.get("complete_schema_sha256")
        if (
            observed_artifact.get("complete_schema_observable") is not True
            or isinstance(source_complete_schema_count, bool)
            or source_complete_schema_count != source_tool_count
            or green_complete_schema_count != registered_tool_count
        ):
            raise ClientSnapshotError(
                "complete source connector schema identity is unavailable"
            )
        source_complete_schema_sha256 = _require_authentic_digest(
            source_complete_schema_sha256,
            label="source complete schema identity",
        )
        green_complete_schema_sha256 = _require_authentic_digest(
            green_complete_schema_sha256,
            label="green complete schema identity",
        )
        if (
            green_readiness.get("schema_identity_sha256")
            != green_schema_identity_sha256
        ):
            # Readiness that disagrees with its own schema hashes proves nothing
            # about green, changed schema or not.
            raise ClientSnapshotError(
                "green readiness schema identity is not internally consistent"
            )
        schema_changed = (
            source_schema_hashes != green_schema_hashes
            or source_schema_identity_sha256 != green_schema_identity_sha256
            or source_complete_schema_sha256 != green_complete_schema_sha256
        )
        surface_changed = (
            schema_changed
            or source_tool_count != registered_tool_count
            or source_names_sha256 != names_sha256
        )
        schema_transition: dict[str, Any] | None = None
        if surface_changed:
            schema_transition = _authorized_publication_schema_transition(
                cutover_id=cutover_binding["cutover_id"],
                source_tool_count=source_tool_count,
                source_names_sha256=source_names_sha256,
                registered_tool_count=registered_tool_count,
                registered_names_sha256=names_sha256,
                green_complete_schema_count=green_complete_schema_count,
                green_complete_schema_sha256=green_complete_schema_sha256,
                source_schema_identity_sha256=source_schema_identity_sha256,
                source_complete_schema_sha256=source_complete_schema_sha256,
                target_schema_identity_sha256=green_schema_identity_sha256,
                green_readiness=green_readiness,
                schema_changed=schema_changed,
                now_unix=timestamp,
                expected_publication_request_id=publication_request_id,
            )

        server_binding = {
            "registered_tool_count": registered_tool_count,
            "registered_names_sha256": names_sha256,
            "release_id": green_release,
            "repo_head": green_repo_head,
            "agent_instructions_sha256": instructions_sha256,
        }
        transition = {
            "source_receipt_sha256": source_receipt_sha256,
            "source_client_declaration_sha256": source_declaration_sha256,
            "from_release_id": current_release,
            "from_repo_head": current_repo_head,
            "to_release_id": green_release,
            "to_repo_head": green_repo_head,
            "source_evidence_time": historical_time,
            "source_created_at_unix": created,
            "source_expires_at_unix": expires,
            # The source values stay the source values. A rebind moves the
            # binding forward; it never rewrites what was historically observed.
            "schema_identity_sha256": source_schema_identity_sha256,
            "complete_schema_sha256": source_complete_schema_sha256,
            "target_schema_identity_sha256": green_schema_identity_sha256,
            "target_complete_schema_sha256": green_complete_schema_sha256,
            "schema_changed": schema_changed,
            "surface_changed": surface_changed,
            "surface_continuity_sha256": _sha256_json(
                {
                    "registered_tool_count": source_tool_count,
                    "registered_names_sha256": source_names_sha256,
                    "agent_instructions_sha256": source_instructions_sha256,
                    "schema_identity_sha256": source_schema_identity_sha256,
                    "complete_schema_sha256": source_complete_schema_sha256,
                }
            ),
            "green_readiness_sha256": _sha256_json(green_readiness),
            "publication_schema_transition": schema_transition,
        }
        nonclaims = list(additional_nonclaims)
        if surface_changed:
            model = f"{verification_model}+publication-v2-schema-transition-v1"
            for limitation in (
                "that any client has observed the changed green tool surface",
                "current green schema observability from the preserved historical evidence",
            ):
                if limitation not in nonclaims:
                    nonclaims.append(limitation)
        else:
            model = verification_model
        receipt = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "kind": SNAPSHOT_KIND,
            "created_at_unix": timestamp,
            "expires_at_unix": timestamp + SNAPSHOT_TTL_SECONDS,
            "client_declaration": declaration,
            "client_declaration_sha256": source_declaration_sha256,
            "server_binding": server_binding,
            "schema_evidence": schema_evidence,
            "cutover_binding": cutover_binding,
            "cutover_transition": transition,
            "verified": True,
            "mismatches": [],
            "verification_model": model,
            "does_not_establish": nonclaims,
        }
        receipt["receipt_sha256"] = _sha256_json(receipt)
        _write_private_json(SNAPSHOT_PATH, receipt)
        readback = _read_private_json(SNAPSHOT_PATH)
        _validate_receipt(readback)
        if readback.get("receipt_sha256") != receipt["receipt_sha256"]:
            raise ClientSnapshotError("cutover snapshot rebind readback mismatch")
    return {
        "schema_version": 1,
        "state": "matched",
        "verified": True,
        "cutover_rebind": True,
        "observation_scope": observation_scope,
        "client_declaration_sha256": source_declaration_sha256,
        "source_receipt_sha256": source_receipt_sha256,
        "source_snapshot_receipt_sha256": source_receipt_sha256,
        "source_client_declaration_sha256": source_declaration_sha256,
        "classified_snapshot_receipt_sha256": source_receipt_sha256,
        "source_release_id": current_release,
        "source_repo_head": current_repo_head,
        "target_release_id": green_release,
        "target_repo_head": green_repo_head,
        "receipt_sha256": receipt["receipt_sha256"],
        "cutover_binding": cutover_binding,
        "cutover_transition": transition,
        "verification_model": receipt["verification_model"],
        # A changed schema means the preserved observation describes the
        # predecessor surface. Reporting a contract match here would be the
        # false claim this transition exists to avoid.
        "schema_contract_matches": not surface_changed,
        "schema_changed": schema_changed,
        "surface_changed": surface_changed,
        "publication_schema_transition": schema_transition,
        "recommended_next_action": (
            "capture a fresh client observation of the changed green surface"
            if surface_changed
            else recommended_next_action
        ),
        "does_not_establish": list(receipt["does_not_establish"]),
    }


def _platform_publication_contract(
    *,
    registered_tool_count: int,
    registered_names_sha256: str,
    complete_schema_count: int,
    complete_schema_sha256: str,
) -> dict[str, Any]:
    if (
        isinstance(registered_tool_count, bool)
        or not isinstance(registered_tool_count, int)
        or registered_tool_count < 1
    ):
        raise ClientSnapshotError("platform publication tool count is invalid")
    if (
        isinstance(complete_schema_count, bool)
        or not isinstance(complete_schema_count, int)
        or complete_schema_count != registered_tool_count
    ):
        raise ClientSnapshotError(
            "platform publication complete schema count must equal the tool count"
        )
    material = {
        "schema_version": 2,
        "tool_count": registered_tool_count,
        "tool_names_sha256": _validate_sha256(
            registered_names_sha256, label="platform publication names hash"
        ),
        "tool_schemas_count": complete_schema_count,
        "tool_schemas_sha256": _validate_sha256(
            complete_schema_sha256, label="platform publication complete schema hash"
        ),
    }
    return {**material, "tool_contract_sha256": _sha256_json(material)}


def _validate_platform_publication_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "tool_count",
        "tool_names_sha256",
        "tool_schemas_count",
        "tool_schemas_sha256",
        "tool_contract_sha256",
    }:
        raise ClientSnapshotError("platform publication contract fields are invalid")
    count = value.get("tool_count")
    schema_count = value.get("tool_schemas_count")
    if (
        value.get("schema_version") != 2
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 1
        or isinstance(schema_count, bool)
        or not isinstance(schema_count, int)
        or schema_count != count
    ):
        raise ClientSnapshotError("platform publication contract counts are invalid")
    names_sha256 = _validate_sha256(
        value.get("tool_names_sha256"), label="platform publication names hash"
    )
    schemas_sha256 = _validate_sha256(
        value.get("tool_schemas_sha256"), label="platform publication schema hash"
    )
    contract_sha256 = _validate_sha256(
        value.get("tool_contract_sha256"), label="platform publication contract hash"
    )
    material = {
        "schema_version": 2,
        "tool_count": count,
        "tool_names_sha256": names_sha256,
        "tool_schemas_count": schema_count,
        "tool_schemas_sha256": schemas_sha256,
    }
    if _sha256_json(material) != contract_sha256:
        raise ClientSnapshotError("platform publication contract hash mismatch")
    return {**material, "tool_contract_sha256": contract_sha256}


def _platform_contract_from_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    try:
        _names, _schemas, metadata = connector_contract.parse_observed_artifact(
            artifact, label="platform publication runtime artifact"
        )
    except connector_contract.ConnectorContractError as exc:
        raise ClientSnapshotError(str(exc)) from exc
    if metadata.get("complete_schema_observable") is not True:
        raise ClientSnapshotError(
            "platform publication requires complete runtime schema identity"
        )
    return _platform_publication_contract(
        registered_tool_count=metadata["name_count"],
        registered_names_sha256=metadata["names_sha256"],
        complete_schema_count=metadata["complete_schema_count"],
        complete_schema_sha256=metadata["complete_schema_sha256"],
    )


def _create_private_json(path: Path, payload: dict[str, Any]) -> bool:
    _ensure_private_directory(path.parent)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ClientSnapshotError("platform publication record exceeds size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        existing = _read_private_json(path)
        if existing != payload:
            raise ClientSnapshotError(
                "platform publication immutable record conflicts with existing evidence"
            )
        return False
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_private_file(path.lstat(), label="platform publication record")
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return True


def _publication_request_path(request_id: str) -> Path:
    request_id = _validate_identifier(request_id, label="publication request id")
    return PLATFORM_PUBLICATION_REQUEST_ROOT / f"{request_id}.json"


def _publication_attempt_path(request_id: str, attempt_id: str) -> Path:
    request_id = _validate_identifier(request_id, label="publication request id")
    attempt_id = _validate_identifier(attempt_id, label="publication attempt id")
    token = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()[:24]
    return PLATFORM_PUBLICATION_ATTEMPT_ROOT / f"{request_id}--{token}.json"


def _publication_receipt_path(request_id: str) -> Path:
    request_id = _validate_identifier(request_id, label="publication request id")
    return PLATFORM_PUBLICATION_RECEIPT_ROOT / f"{request_id}.json"


def _publication_resolution_path(request_id: str) -> Path:
    request_id = _validate_identifier(request_id, label="publication request id")
    return PLATFORM_PUBLICATION_RESOLUTION_ROOT / f"{request_id}.json"


def _read_publication_current() -> dict[str, Any] | None:
    try:
        value = _read_private_json(PLATFORM_PUBLICATION_CURRENT_PATH)
    except FileNotFoundError:
        return None
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "request_id",
        "contract_sha256",
        "state",
        "attempt_id",
        "updated_at_unix",
        "current_sha256",
    }:
        raise ClientSnapshotError("platform publication current projection is invalid")
    if value.get("schema_version") != 1 or value.get("kind") != PLATFORM_PUBLICATION_CURRENT_KIND:
        raise ClientSnapshotError("platform publication current projection contract mismatch")
    state = value.get("state")
    if state not in PLATFORM_PUBLICATION_CURRENT_STATES:
        raise ClientSnapshotError("platform publication current state is invalid")
    request_id = value.get("request_id")
    contract_sha256 = value.get("contract_sha256")
    attempt_id = value.get("attempt_id")
    if state == "no_current":
        if request_id is not None or contract_sha256 is not None or attempt_id is not None:
            raise ClientSnapshotError("empty platform publication projection is malformed")
    else:
        _validate_identifier(request_id, label="publication current request id")
        _validate_sha256(contract_sha256, label="publication current contract hash")
        if attempt_id is not None:
            _validate_identifier(attempt_id, label="publication current attempt id")
    updated_at = value.get("updated_at_unix")
    if isinstance(updated_at, bool) or not isinstance(updated_at, int) or updated_at < 0:
        raise ClientSnapshotError("platform publication current timestamp is invalid")
    declared = _validate_sha256(
        value.get("current_sha256"), label="platform publication current hash"
    )
    unsigned = dict(value)
    unsigned.pop("current_sha256", None)
    if _sha256_json(unsigned) != declared:
        raise ClientSnapshotError("platform publication current hash mismatch")
    return dict(value)


def _write_publication_current(
    *,
    request_id: str | None,
    contract_sha256: str | None,
    state: str,
    attempt_id: str | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    if state not in PLATFORM_PUBLICATION_CURRENT_STATES:
        raise ClientSnapshotError("platform publication current state is invalid")
    if state == "no_current":
        request_id = None
        contract_sha256 = None
        attempt_id = None
    else:
        request_id = _validate_identifier(request_id, label="publication current request id")
        contract_sha256 = _validate_sha256(
            contract_sha256, label="publication current contract hash"
        )
        if attempt_id is not None:
            attempt_id = _validate_identifier(
                attempt_id, label="publication current attempt id"
            )
    material: dict[str, Any] = {
        "schema_version": 1,
        "kind": PLATFORM_PUBLICATION_CURRENT_KIND,
        "request_id": request_id,
        "contract_sha256": contract_sha256,
        "state": state,
        "attempt_id": attempt_id,
        "updated_at_unix": timestamp,
    }
    document = {**material, "current_sha256": _sha256_json(material)}
    _ensure_private_directory(PLATFORM_PUBLICATION_ROOT)
    _write_private_json(PLATFORM_PUBLICATION_CURRENT_PATH, document)
    return document


def _validate_publication_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "request_id",
        "platform",
        "connector_id",
        "action",
        "cutover_id",
        "requested_at_unix",
        "expected_contract",
        "required_observation_scopes",
        "previous_current",
        "request_sha256",
    }:
        raise ClientSnapshotError("platform publication request fields are invalid")
    if value.get("schema_version") != 1 or value.get("kind") != PLATFORM_PUBLICATION_REQUEST_KIND:
        raise ClientSnapshotError("platform publication request contract mismatch")
    request_id = _validate_identifier(value.get("request_id"), label="publication request id")
    if value.get("platform") != "chatgpt" or value.get("connector_id") != "grabowski":
        raise ClientSnapshotError("platform publication request target is invalid")
    if value.get("action") != PLATFORM_PUBLICATION_ACTION:
        raise ClientSnapshotError("platform publication request action is invalid")
    cutover_id = _validate_identifier(value.get("cutover_id"), label="publication cutover id")
    requested_at = value.get("requested_at_unix")
    if isinstance(requested_at, bool) or not isinstance(requested_at, int) or requested_at < 0:
        raise ClientSnapshotError("platform publication request timestamp is invalid")
    contract = _validate_platform_publication_contract(value.get("expected_contract"))
    scopes = value.get("required_observation_scopes")
    if scopes != sorted(PLATFORM_CONVERGENCE_SCOPES):
        raise ClientSnapshotError("platform publication request observation scopes are invalid")
    previous = value.get("previous_current")
    if previous is not None:
        if not isinstance(previous, dict) or set(previous) != {
            "request_id", "contract_sha256", "state", "attempt_id"
        }:
            raise ClientSnapshotError("platform publication request predecessor is invalid")
        if previous.get("state") == "no_current":
            previous = None
        else:
            _validate_identifier(previous.get("request_id"), label="publication predecessor request id")
            _validate_sha256(previous.get("contract_sha256"), label="publication predecessor contract hash")
            if previous.get("state") not in PLATFORM_PUBLICATION_CURRENT_STATES - {"no_current"}:
                raise ClientSnapshotError("platform publication predecessor state is invalid")
            if previous.get("attempt_id") is not None:
                _validate_identifier(previous.get("attempt_id"), label="publication predecessor attempt id")
    declared = _validate_sha256(value.get("request_sha256"), label="publication request hash")
    unsigned = dict(value)
    unsigned.pop("request_sha256", None)
    if _sha256_json(unsigned) != declared:
        raise ClientSnapshotError("platform publication request hash mismatch")
    return {
        **unsigned,
        "request_sha256": declared,
        "request_id": request_id,
        "cutover_id": cutover_id,
        "expected_contract": contract,
        "previous_current": previous,
    }


def _read_publication_request(request_id: str) -> dict[str, Any]:
    return _validate_publication_request(
        _read_private_json(_publication_request_path(request_id))
    )


def _validate_publication_attempt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "request_id",
        "request_sha256",
        "attempt_id",
        "outcome",
        "reference",
        "previous_current_sha256",
        "previous_attempt_id",
        "recorded_at_unix",
        "attempt_sha256",
    }:
        raise ClientSnapshotError("platform publication attempt fields are invalid")
    if value.get("schema_version") != 1 or value.get("kind") != PLATFORM_PUBLICATION_ATTEMPT_KIND:
        raise ClientSnapshotError("platform publication attempt contract mismatch")
    _validate_identifier(value.get("request_id"), label="publication attempt request id")
    _validate_sha256(value.get("request_sha256"), label="publication attempt request hash")
    _validate_identifier(value.get("attempt_id"), label="publication attempt id")
    if value.get("outcome") not in PLATFORM_PUBLICATION_ATTEMPT_OUTCOMES:
        raise ClientSnapshotError("platform publication attempt outcome is invalid")
    _validate_platform_source_reference(value.get("reference"))
    _validate_sha256(
        value.get("previous_current_sha256"),
        label="publication attempt previous current hash",
    )
    previous_attempt_id = value.get("previous_attempt_id")
    if previous_attempt_id is not None:
        _validate_identifier(
            previous_attempt_id, label="publication attempt previous attempt id"
        )
        if previous_attempt_id == value.get("attempt_id"):
            raise ClientSnapshotError(
                "platform publication attempt cannot name itself as predecessor"
            )
    recorded_at = value.get("recorded_at_unix")
    if isinstance(recorded_at, bool) or not isinstance(recorded_at, int) or recorded_at < 0:
        raise ClientSnapshotError("platform publication attempt timestamp is invalid")
    declared = _validate_sha256(value.get("attempt_sha256"), label="publication attempt hash")
    unsigned = dict(value)
    unsigned.pop("attempt_sha256", None)
    if _sha256_json(unsigned) != declared:
        raise ClientSnapshotError("platform publication attempt hash mismatch")
    return dict(value)


def _read_publication_attempt(request_id: str, attempt_id: str) -> dict[str, Any]:
    return _validate_publication_attempt(
        _read_private_json(_publication_attempt_path(request_id, attempt_id))
    )


def _validate_publication_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "request_id",
        "request_sha256",
        "contract_sha256",
        "snapshot_sha256",
        "observation_id",
        "observation_scope",
        "observed_at_unix",
        "reconciled_at_unix",
        "receipt_sha256",
    }:
        raise ClientSnapshotError("platform publication receipt fields are invalid")
    if value.get("schema_version") != 1 or value.get("kind") != PLATFORM_PUBLICATION_RECEIPT_KIND:
        raise ClientSnapshotError("platform publication receipt contract mismatch")
    _validate_identifier(value.get("request_id"), label="publication receipt request id")
    _validate_sha256(value.get("request_sha256"), label="publication receipt request hash")
    _validate_sha256(value.get("contract_sha256"), label="publication receipt contract hash")
    _validate_sha256(value.get("snapshot_sha256"), label="publication receipt snapshot hash")
    _validate_identifier(value.get("observation_id"), label="publication receipt observation id")
    if value.get("observation_scope") not in PLATFORM_CONVERGENCE_SCOPES:
        raise ClientSnapshotError("platform publication receipt observation scope is invalid")
    for field in ("observed_at_unix", "reconciled_at_unix"):
        timestamp = value.get(field)
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            raise ClientSnapshotError(f"platform publication receipt {field} is invalid")
    declared = _validate_sha256(value.get("receipt_sha256"), label="publication receipt hash")
    unsigned = dict(value)
    unsigned.pop("receipt_sha256", None)
    if _sha256_json(unsigned) != declared:
        raise ClientSnapshotError("platform publication receipt hash mismatch")
    return dict(value)


def _read_publication_receipt(request_id: str) -> dict[str, Any]:
    return _validate_publication_receipt(
        _read_private_json(_publication_receipt_path(request_id))
    )


def _validate_publication_resolution(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "kind",
        "request_id",
        "outcome",
        "successor_request_id",
        "resolved_at_unix",
        "resolution_sha256",
    }:
        raise ClientSnapshotError("platform publication resolution fields are invalid")
    if value.get("schema_version") != 1 or value.get("kind") != PLATFORM_PUBLICATION_RESOLUTION_KIND:
        raise ClientSnapshotError("platform publication resolution contract mismatch")
    request_id = _validate_identifier(
        value.get("request_id"), label="publication resolution request id"
    )
    outcome = value.get("outcome")
    successor = value.get("successor_request_id")
    if outcome == "superseded":
        successor = _validate_identifier(
            successor, label="publication resolution successor request id"
        )
        if successor == request_id:
            raise ClientSnapshotError("platform publication resolution cannot supersede itself")
    elif outcome == "rolled_back":
        if successor is not None:
            raise ClientSnapshotError("rolled-back publication resolution cannot name a successor")
    else:
        raise ClientSnapshotError("platform publication resolution outcome is invalid")
    resolved_at = value.get("resolved_at_unix")
    if isinstance(resolved_at, bool) or not isinstance(resolved_at, int) or resolved_at < 0:
        raise ClientSnapshotError("platform publication resolution timestamp is invalid")
    declared = _validate_sha256(
        value.get("resolution_sha256"), label="publication resolution hash"
    )
    unsigned = dict(value)
    unsigned.pop("resolution_sha256", None)
    if _sha256_json(unsigned) != declared:
        raise ClientSnapshotError("platform publication resolution hash mismatch")
    return dict(value)


def _read_publication_resolution(request_id: str) -> dict[str, Any]:
    return _validate_publication_resolution(
        _read_private_json(_publication_resolution_path(request_id))
    )


def _persist_publication_resolution(
    *,
    request_id: str,
    outcome: str,
    successor_request_id: str | None,
    now_unix: int,
) -> dict[str, Any]:
    request_id = _validate_identifier(request_id, label="publication resolution request id")
    try:
        existing = _read_publication_resolution(request_id)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if (
            existing["outcome"] != outcome
            or existing["successor_request_id"] != successor_request_id
        ):
            raise ClientSnapshotError(
                "platform publication resolution conflicts with existing immutable evidence"
            )
        return existing
    material = {
        "schema_version": 1,
        "kind": PLATFORM_PUBLICATION_RESOLUTION_KIND,
        "request_id": request_id,
        "outcome": outcome,
        "successor_request_id": successor_request_id,
        "resolved_at_unix": now_unix,
    }
    resolution = {
        **material,
        "resolution_sha256": _sha256_json(material),
    }
    _create_private_json(_publication_resolution_path(request_id), resolution)
    return resolution


def _persist_publication_receipt(
    *,
    request: dict[str, Any],
    contract: dict[str, Any],
    observation: dict[str, Any],
    now_unix: int,
) -> dict[str, Any]:
    request = _validate_publication_request(request)
    contract = _validate_platform_publication_contract(contract)
    request_id = request["request_id"]
    expected = {
        "request_id": request_id,
        "request_sha256": request["request_sha256"],
        "contract_sha256": contract["tool_contract_sha256"],
        "snapshot_sha256": observation["snapshot_sha256"],
        "observation_id": observation["observation_id"],
        "observation_scope": observation["observation_scope"],
        "observed_at_unix": observation["observed_at_unix"],
    }
    try:
        existing = _read_publication_receipt(request_id)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if any(existing.get(key) != value for key, value in expected.items()):
            raise ClientSnapshotError(
                "platform convergence receipt conflicts with existing immutable evidence"
            )
        return existing
    material = {
        "schema_version": 1,
        "kind": PLATFORM_PUBLICATION_RECEIPT_KIND,
        **expected,
        "reconciled_at_unix": now_unix,
    }
    receipt = {**material, "receipt_sha256": _sha256_json(material)}
    _create_private_json(_publication_receipt_path(request_id), receipt)
    return receipt


def _request_id_for_contract(*, cutover_id: str, contract_sha256: str) -> str:
    cutover_id = _validate_identifier(cutover_id, label="publication cutover id")
    contract_sha256 = _validate_sha256(contract_sha256, label="publication contract hash")
    digest = hashlib.sha256(
        f"{cutover_id}:{contract_sha256}".encode("utf-8")
    ).hexdigest()
    return f"gpp-{digest[:32]}"


def _platform_source_projection(document: dict[str, Any]) -> dict[str, Any]:
    schema_version = document.get("schema_version")
    source = document.get("source")
    if not isinstance(source, dict):
        raise ClientSnapshotError("platform publication snapshot source is invalid")
    if schema_version == PLATFORM_SNAPSHOT_SCHEMA_VERSION:
        expected = {
            "kind", "connector", "reference", "observed_at_unix", "catalog_sha256"
        }
        if set(source) != expected or source.get("kind") != PLATFORM_SOURCE_KIND or source.get("connector") != "grabowski":
            raise ClientSnapshotError("legacy platform publication source is invalid")
        return {
            "legacy": True,
            "kind": source["kind"],
            "platform": "chatgpt",
            "connector_id": source["connector"],
            "observation_scope": "unknown",
            "observation_id": None,
            "publication_request_id": None,
            "requested_contract_sha256": None,
            "reference": source.get("reference"),
            "observed_at_unix": source.get("observed_at_unix"),
            "catalog_sha256": source.get("catalog_sha256"),
        }
    if schema_version != PLATFORM_SNAPSHOT_V2_SCHEMA_VERSION:
        raise ClientSnapshotError("platform publication snapshot schema version is unsupported")
    expected = {
        "kind",
        "platform",
        "connector_id",
        "observation_scope",
        "observation_id",
        "publication_request_id",
        "requested_contract_sha256",
        "reference",
        "observed_at_unix",
        "catalog_sha256",
    }
    if set(source) != expected or source.get("kind") != PLATFORM_SOURCE_KIND:
        raise ClientSnapshotError("platform publication source contract mismatch")
    if source.get("platform") != "chatgpt" or source.get("connector_id") != "grabowski":
        raise ClientSnapshotError("platform publication observation targets another connector")
    scope = source.get("observation_scope")
    if scope not in PLATFORM_OBSERVATION_SCOPES:
        raise ClientSnapshotError("platform publication observation scope is invalid")
    observation_id = _validate_identifier(
        source.get("observation_id"), label="platform observation id"
    )
    request_id = source.get("publication_request_id")
    contract_sha256 = source.get("requested_contract_sha256")
    if (request_id is None) != (contract_sha256 is None):
        raise ClientSnapshotError(
            "platform publication observation request id and contract hash must be supplied together"
        )
    if request_id is None:
        contract_sha256 = None
    else:
        request_id = _validate_identifier(request_id, label="platform observation request id")
        contract_sha256 = _validate_sha256(
            contract_sha256, label="platform observation contract hash"
        )
    return {
        "legacy": False,
        "kind": source["kind"],
        "platform": "chatgpt",
        "connector_id": "grabowski",
        "observation_scope": scope,
        "observation_id": observation_id,
        "publication_request_id": request_id,
        "requested_contract_sha256": contract_sha256,
        "reference": source.get("reference"),
        "observed_at_unix": source.get("observed_at_unix"),
        "catalog_sha256": source.get("catalog_sha256"),
    }


def _platform_publication_observation(
    document: dict[str, Any],
    contract: dict[str, Any],
    *,
    now_unix: int,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    contract = _validate_platform_publication_contract(contract)
    if not isinstance(document, dict) or set(document) != {
        "schema_version", "kind", "source", "runtime_binding", "observed_tools", "snapshot_sha256"
    }:
        raise ClientSnapshotError("platform publication snapshot fields are invalid")
    if document.get("kind") != PLATFORM_SNAPSHOT_KIND:
        raise ClientSnapshotError("platform publication snapshot kind is invalid")
    declared_snapshot_sha256 = _validate_sha256(
        document.get("snapshot_sha256"), label="platform snapshot sha256"
    )
    unsigned = dict(document)
    unsigned.pop("snapshot_sha256", None)
    if _sha256_json(unsigned) != declared_snapshot_sha256:
        raise ClientSnapshotError("platform publication snapshot hash mismatch")
    source = _platform_source_projection(document)
    reference = _validate_platform_source_reference(source.get("reference"))
    observed_at = source.get("observed_at_unix")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise ClientSnapshotError("platform publication observation time is invalid")
    catalog_sha256 = _validate_sha256(
        source.get("catalog_sha256"), label="platform publication catalog hash"
    )
    try:
        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            document.get("observed_tools"), label="platform publication catalog"
        )
    except connector_contract.ConnectorContractError as exc:
        raise ClientSnapshotError(str(exc)) from exc
    if metadata["artifact_sha256"] != catalog_sha256:
        raise ClientSnapshotError("platform publication catalog hash mismatch")
    full_schema_observable = metadata.get("complete_schema_observable") is True
    surface_matches = bool(
        not source["legacy"]
        and full_schema_observable
        and len(names) == contract["tool_count"]
        and metadata["names_sha256"] == contract["tool_names_sha256"]
        and metadata.get("complete_schema_count") == contract["tool_schemas_count"]
        and metadata.get("complete_schema_sha256") == contract["tool_schemas_sha256"]
    )
    future_clock_drift = observed_at > now_unix + SNAPSHOT_CLOCK_SKEW_SECONDS
    fresh = not future_clock_drift and now_unix <= observed_at + PLATFORM_SNAPSHOT_TTL_SECONDS
    request_bound = False
    post_request = False
    scope_authoritative = source["observation_scope"] in PLATFORM_CONVERGENCE_SCOPES
    if request is not None:
        request = _validate_publication_request(request)
        request_bound = bool(
            source["publication_request_id"] == request["request_id"]
            and source["requested_contract_sha256"]
            == request["expected_contract"]["tool_contract_sha256"]
        )
        post_request = observed_at >= request["requested_at_unix"]
    return {
        "snapshot_sha256": declared_snapshot_sha256,
        "source_reference": reference,
        "observed_at_unix": observed_at,
        "observed_tool_count": len(names),
        "observed_names_sha256": metadata["names_sha256"],
        "complete_schema_observable": full_schema_observable,
        "complete_schema_count": metadata.get("complete_schema_count"),
        "complete_schema_sha256": metadata.get("complete_schema_sha256"),
        "observation_scope": source["observation_scope"],
        "observation_id": source["observation_id"],
        "publication_request_id": source["publication_request_id"],
        "requested_contract_sha256": source["requested_contract_sha256"],
        "legacy": source["legacy"],
        "surface_matches": surface_matches,
        "fresh": fresh,
        "future_clock_drift": future_clock_drift,
        "request_bound": request_bound,
        "post_request": post_request,
        "scope_authoritative": scope_authoritative,
        "converged": bool(
            surface_matches
            and fresh
            and request_bound
            and post_request
            and scope_authoritative
        ),
    }


def _publication_projection_for_contract(
    contract: dict[str, Any],
    *,
    document: dict[str, Any] | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    contract = _validate_platform_publication_contract(contract)
    try:
        current = _read_publication_current()
    except (OSError, ClientSnapshotError) as exc:
        return {
            "state": "invalid",
            "publication_pending": True,
            "error": type(exc).__name__,
            "request_id": None,
            "contract_sha256": contract["tool_contract_sha256"],
            "recommended_next_action": "repair the platform publication current projection before relying on convergence",
        }
    if current is None or current["state"] == "no_current":
        return {
            "state": "untracked",
            "publication_pending": False,
            "request_id": None,
            "contract_sha256": contract["tool_contract_sha256"],
            "recommended_next_action": "create a publication request only if platform evidence does not already match the semantic runtime contract",
        }
    request_id = current["request_id"]
    try:
        request = _read_publication_request(request_id)
    except (OSError, ClientSnapshotError) as exc:
        return {
            "state": "invalid",
            "publication_pending": True,
            "request_id": request_id,
            "contract_sha256": contract["tool_contract_sha256"],
            "error": type(exc).__name__,
            "recommended_next_action": "repair the immutable platform publication request evidence",
        }
    if current["contract_sha256"] != request["expected_contract"]["tool_contract_sha256"]:
        return {
            "state": "invalid",
            "publication_pending": True,
            "request_id": request_id,
            "contract_sha256": contract["tool_contract_sha256"],
            "recommended_next_action": "repair publication request/current contract binding",
        }
    if current["contract_sha256"] != contract["tool_contract_sha256"]:
        return {
            "state": "runtime_contract_changed",
            "publication_pending": True,
            "request_id": request_id,
            "request_contract_sha256": current["contract_sha256"],
            "contract_sha256": contract["tool_contract_sha256"],
            "recommended_next_action": "prepare a new publication request for the current semantic runtime contract",
        }
    attempt = None
    attempt_id = current.get("attempt_id")
    if attempt_id is not None:
        try:
            attempt = _read_publication_attempt(request_id, attempt_id)
        except (OSError, ClientSnapshotError) as exc:
            return {
                "state": "invalid",
                "publication_pending": True,
                "request_id": request_id,
                "contract_sha256": contract["tool_contract_sha256"],
                "error": type(exc).__name__,
                "recommended_next_action": "repair the immutable platform publication attempt evidence",
            }
        if (
            attempt["request_sha256"] != request["request_sha256"]
            or attempt["request_id"] != request_id
        ):
            return {
                "state": "invalid",
                "publication_pending": True,
                "request_id": request_id,
                "contract_sha256": contract["tool_contract_sha256"],
                "recommended_next_action": "repair publication attempt/request binding",
            }
        expected_attempt_state = {
            "submitted": "awaiting_platform_observation",
            "outcome_unknown": "outcome_unknown",
            "failed": "publication_pending",
        }[attempt["outcome"]]
        if (
            current["state"] != "platform_converged"
            and current["state"] != expected_attempt_state
        ):
            return {
                "state": "invalid",
                "publication_pending": True,
                "request_id": request_id,
                "contract_sha256": contract["tool_contract_sha256"],
                "recommended_next_action": "repair publication attempt/current lifecycle binding",
            }
    convergence_receipt = None
    if current["state"] == "platform_converged":
        try:
            convergence_receipt = _read_publication_receipt(request_id)
        except (OSError, ClientSnapshotError) as exc:
            return {
                "state": "invalid",
                "publication_pending": True,
                "request_id": request_id,
                "contract_sha256": contract["tool_contract_sha256"],
                "error": type(exc).__name__,
                "recommended_next_action": "repair the immutable platform convergence receipt before claiming convergence",
            }
        if (
            convergence_receipt["request_sha256"] != request["request_sha256"]
            or convergence_receipt["contract_sha256"] != contract["tool_contract_sha256"]
            or convergence_receipt["request_id"] != request_id
        ):
            return {
                "state": "invalid",
                "publication_pending": True,
                "request_id": request_id,
                "contract_sha256": contract["tool_contract_sha256"],
                "recommended_next_action": "repair convergence receipt/request/contract binding",
            }
    observation = None
    if document is None:
        try:
            document = _read_platform_snapshot()
        except (FileNotFoundError, OSError, ClientSnapshotError):
            document = None
    if document is not None:
        try:
            observation = _platform_publication_observation(
                document, contract, now_unix=timestamp, request=request
            )
        except ClientSnapshotError:
            observation = None
    state = current["state"]
    if state == "pending_activation":
        publication_state = "outcome_unknown"
        next_action = "read back the active runtime contract, then recover or roll back the prepared publication request"
    elif state == "platform_converged":
        publication_state = "platform_converged"
        next_action = "none"
    elif observation is not None and observation["converged"]:
        publication_state = "convergence_observed_unreconciled"
        next_action = "run the user-owned platform publication reconciliation to persist the convergence receipt"
    elif state == "outcome_unknown":
        publication_state = "outcome_unknown"
        next_action = "obtain a bound platform observation or reconcile the publication attempt outcome"
    elif state == "awaiting_platform_observation":
        publication_state = "awaiting_platform_observation"
        next_action = "capture a fresh request-bound platform catalog from connector settings or a new ChatGPT chat"
    else:
        publication_state = "publication_pending"
        next_action = "perform the requested ChatGPT connector refresh or republish action, then capture a fresh request-bound platform catalog"
    return {
        "state": publication_state,
        "publication_pending": publication_state != "platform_converged",
        "request_id": request_id,
        "request_sha256": request["request_sha256"],
        "contract_sha256": contract["tool_contract_sha256"],
        "current_state": state,
        "attempt_id": current.get("attempt_id"),
        "attempt": attempt,
        "convergence_receipt": convergence_receipt,
        "observation": observation,
        "requested_at_unix": request["requested_at_unix"],
        "action": request["action"],
        "platform": request["platform"],
        "connector_id": request["connector_id"],
        "required_observation_scopes": request["required_observation_scopes"],
        "recommended_next_action": next_action,
    }


def prepare_platform_publication_for_runtime(
    *,
    registered_tool_count: int,
    registered_names_sha256: str,
    complete_schema_count: int,
    complete_schema_sha256: str,
    cutover_id: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    contract = _platform_publication_contract(
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        complete_schema_count=complete_schema_count,
        complete_schema_sha256=complete_schema_sha256,
    )
    cutover_id = _validate_identifier(cutover_id, label="publication cutover id")
    with _state_lock():
        _ensure_private_directory(PLATFORM_PUBLICATION_ROOT)
        current = _read_publication_current()
        if (
            current is not None
            and current["state"] != "no_current"
            and current["contract_sha256"] == contract["tool_contract_sha256"]
        ):
            request = _read_publication_request(current["request_id"])
            if current["state"] == "pending_activation":
                raise ClientSnapshotError(
                    "an earlier platform publication request is still pending activation; reconcile the active runtime before another cutover"
                )
            if current.get("attempt_id") is not None:
                try:
                    attempt = _read_publication_attempt(
                        current["request_id"], current["attempt_id"]
                    )
                except (OSError, ClientSnapshotError) as exc:
                    raise ClientSnapshotError(
                        "existing platform publication attempt evidence is unavailable or invalid"
                    ) from exc
                if attempt["request_sha256"] != request["request_sha256"]:
                    raise ClientSnapshotError(
                        "existing platform publication attempt does not bind the current request"
                    )
            if current["state"] == "platform_converged":
                try:
                    receipt = _read_publication_receipt(current["request_id"])
                except (OSError, ClientSnapshotError) as exc:
                    raise ClientSnapshotError(
                        "existing platform convergence receipt is unavailable or invalid"
                    ) from exc
                if (
                    receipt["request_sha256"] != request["request_sha256"]
                    or receipt["contract_sha256"] != contract["tool_contract_sha256"]
                ):
                    raise ClientSnapshotError(
                        "existing platform convergence receipt does not bind the current request contract"
                    )
            return {
                "state": current["state"],
                "request_id": current["request_id"],
                "request_sha256": request["request_sha256"],
                "contract": contract,
                "reused": True,
                "recommended_next_action": "continue the existing semantic publication lifecycle",
            }
        request_id = _request_id_for_contract(
            cutover_id=cutover_id,
            contract_sha256=contract["tool_contract_sha256"],
        )
        request_path = _publication_request_path(request_id)
        try:
            existing_request = _read_publication_request(request_id)
        except FileNotFoundError:
            previous = None
            if current is not None and current["state"] != "no_current":
                previous = {
                    "request_id": current["request_id"],
                    "contract_sha256": current["contract_sha256"],
                    "state": current["state"],
                    "attempt_id": current.get("attempt_id"),
                }
            material: dict[str, Any] = {
                "schema_version": 1,
                "kind": PLATFORM_PUBLICATION_REQUEST_KIND,
                "request_id": request_id,
                "platform": "chatgpt",
                "connector_id": "grabowski",
                "action": PLATFORM_PUBLICATION_ACTION,
                "cutover_id": cutover_id,
                "requested_at_unix": timestamp,
                "expected_contract": contract,
                "required_observation_scopes": sorted(PLATFORM_CONVERGENCE_SCOPES),
                "previous_current": previous,
            }
            request = {**material, "request_sha256": _sha256_json(material)}
            _create_private_json(request_path, request)
        else:
            request = existing_request
            if request["expected_contract"] != contract or request["cutover_id"] != cutover_id:
                raise ClientSnapshotError("publication request replay conflicts with existing request")
        _write_publication_current(
            request_id=request_id,
            contract_sha256=contract["tool_contract_sha256"],
            state="pending_activation",
            now_unix=timestamp,
        )
        return {
            "state": "pending_activation",
            "request_id": request_id,
            "request_sha256": request["request_sha256"],
            "contract": contract,
            "reused": False,
            "recommended_next_action": "activate this durable publication request only after the connector switch succeeds",
        }


def activate_platform_publication_request(
    *, request_id: str, now_unix: int | None = None
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    request_id = _validate_identifier(request_id, label="publication request id")
    with _state_lock():
        current = _read_publication_current()
        if current is None or current["request_id"] != request_id:
            raise ClientSnapshotError("publication request is not the prepared current request")
        request = _read_publication_request(request_id)
        if current["contract_sha256"] != request["expected_contract"]["tool_contract_sha256"]:
            raise ClientSnapshotError(
                "publication current projection no longer binds the immutable request contract"
            )
        if current["state"] in {
            "publication_pending", "awaiting_platform_observation", "outcome_unknown", "platform_converged"
        }:
            if current.get("attempt_id") is not None:
                try:
                    attempt = _read_publication_attempt(request_id, current["attempt_id"])
                except (OSError, ClientSnapshotError) as exc:
                    raise ClientSnapshotError(
                        "publication activation replay lacks valid attempt evidence"
                    ) from exc
                if attempt["request_sha256"] != request["request_sha256"]:
                    raise ClientSnapshotError(
                        "publication activation replay attempt does not bind the request"
                    )
            if current["state"] == "platform_converged":
                try:
                    receipt = _read_publication_receipt(request_id)
                except (OSError, ClientSnapshotError) as exc:
                    raise ClientSnapshotError(
                        "publication activation replay lacks a valid convergence receipt"
                    ) from exc
                if (
                    receipt["request_sha256"] != request["request_sha256"]
                    or receipt["contract_sha256"] != current["contract_sha256"]
                ):
                    raise ClientSnapshotError(
                        "publication activation replay convergence receipt does not bind current state"
                    )
            return {"state": current["state"], "request_id": request_id, "idempotent": True}
        if current["state"] != "pending_activation":
            raise ClientSnapshotError("publication request is not awaiting activation")
        previous = request.get("previous_current")
        if previous is not None and previous["contract_sha256"] != current["contract_sha256"]:
            _persist_publication_resolution(
                request_id=previous["request_id"],
                outcome="superseded",
                successor_request_id=request_id,
                now_unix=timestamp,
            )
        updated = _write_publication_current(
            request_id=request_id,
            contract_sha256=current["contract_sha256"],
            state="publication_pending",
            now_unix=timestamp,
        )
        return {
            "state": "publication_pending",
            "request_id": request_id,
            "current_sha256": updated["current_sha256"],
            "idempotent": False,
        }


def rollback_platform_publication_request(
    *,
    request_id: str,
    active_contract: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    request_id = _validate_identifier(request_id, label="publication request id")
    active_contract = _validate_platform_publication_contract(active_contract)
    with _state_lock():
        current = _read_publication_current()
        if current is None or current["request_id"] != request_id:
            return {"state": "not_current", "request_id": request_id, "idempotent": True}
        request = _read_publication_request(request_id)
        if request["expected_contract"]["tool_contract_sha256"] == active_contract["tool_contract_sha256"]:
            updated = _write_publication_current(
                request_id=request_id,
                contract_sha256=current["contract_sha256"],
                state="publication_pending",
                attempt_id=current.get("attempt_id"),
                now_unix=timestamp,
            )
            return {
                "state": "publication_pending",
                "request_id": request_id,
                "reason": "rolled-back runtime has the same semantic tool contract",
                "current_sha256": updated["current_sha256"],
            }
        resolution = _persist_publication_resolution(
            request_id=request_id,
            outcome="rolled_back",
            successor_request_id=None,
            now_unix=timestamp,
        )
        previous = request.get("previous_current")
        if previous is None:
            restored = _write_publication_current(
                request_id=None,
                contract_sha256=None,
                state="no_current",
                now_unix=timestamp,
            )
        else:
            restored = _write_publication_current(
                request_id=previous["request_id"],
                contract_sha256=previous["contract_sha256"],
                state=previous["state"],
                attempt_id=previous.get("attempt_id"),
                now_unix=timestamp,
            )
        return {
            "state": "rolled_back",
            "request_id": request_id,
            "restored_request_id": restored.get("request_id"),
            "resolution_sha256": resolution["resolution_sha256"],
        }


def record_platform_publication_attempt(
    *,
    request_id: str,
    attempt_id: str,
    outcome: str,
    reference: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    request_id = _validate_identifier(request_id, label="publication request id")
    attempt_id = _validate_identifier(attempt_id, label="publication attempt id")
    if outcome not in PLATFORM_PUBLICATION_ATTEMPT_OUTCOMES:
        raise ClientSnapshotError("platform publication attempt outcome is invalid")
    reference = _validate_platform_source_reference(reference)
    with _state_lock():
        current = _read_publication_current()
        if current is None or current["request_id"] != request_id:
            raise ClientSnapshotError("platform publication attempt targets a non-current request")
        request = _read_publication_request(request_id)
        if current["state"] == "pending_activation":
            raise ClientSnapshotError(
                "platform publication attempt cannot be recorded before request activation"
            )
        if current["state"] == "platform_converged":
            receipt = _read_publication_receipt(request_id)
            return {
                "state": "platform_converged",
                "request_id": request_id,
                "attempt_id": current.get("attempt_id"),
                "receipt_sha256": receipt["receipt_sha256"],
                "idempotent": True,
            }
        state = {
            "submitted": "awaiting_platform_observation",
            "outcome_unknown": "outcome_unknown",
            "failed": "publication_pending",
        }[outcome]
        try:
            existing = _read_publication_attempt(request_id, attempt_id)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (
                existing["request_sha256"] != request["request_sha256"]
                or existing["outcome"] != outcome
                or existing["reference"] != reference
            ):
                raise ClientSnapshotError(
                    "platform publication attempt id already binds different evidence"
                )
            if current.get("attempt_id") == attempt_id and current["state"] == state:
                return {
                    "state": state,
                    "request_id": request_id,
                    "attempt_id": attempt_id,
                    "attempt_sha256": existing["attempt_sha256"],
                    "current_sha256": current["current_sha256"],
                    "idempotent": True,
                    "recovered_projection": False,
                }
            if (
                existing["previous_current_sha256"] == current["current_sha256"]
                and existing["previous_attempt_id"] == current.get("attempt_id")
                and current["state"] != "platform_converged"
            ):
                repaired = _write_publication_current(
                    request_id=request_id,
                    contract_sha256=current["contract_sha256"],
                    state=state,
                    attempt_id=attempt_id,
                    now_unix=timestamp,
                )
                return {
                    "state": state,
                    "request_id": request_id,
                    "attempt_id": attempt_id,
                    "attempt_sha256": existing["attempt_sha256"],
                    "current_sha256": repaired["current_sha256"],
                    "idempotent": True,
                    "recovered_projection": True,
                }
            raise ClientSnapshotError(
                "platform publication attempt replay conflicts with a newer or different current projection"
            )
        material = {
            "schema_version": 1,
            "kind": PLATFORM_PUBLICATION_ATTEMPT_KIND,
            "request_id": request_id,
            "request_sha256": request["request_sha256"],
            "attempt_id": attempt_id,
            "outcome": outcome,
            "reference": reference,
            "previous_current_sha256": current["current_sha256"],
            "previous_attempt_id": current.get("attempt_id"),
            "recorded_at_unix": timestamp,
        }
        attempt = {**material, "attempt_sha256": _sha256_json(material)}
        _create_private_json(_publication_attempt_path(request_id, attempt_id), attempt)
        updated = _write_publication_current(
            request_id=request_id,
            contract_sha256=current["contract_sha256"],
            state=state,
            attempt_id=attempt_id,
            now_unix=timestamp,
        )
        return {
            "state": state,
            "request_id": request_id,
            "attempt_id": attempt_id,
            "attempt_sha256": attempt["attempt_sha256"],
            "current_sha256": updated["current_sha256"],
            "idempotent": False,
        }


def reconcile_platform_publication_for_runtime(
    *,
    registered_tool_count: int,
    registered_names_sha256: str,
    complete_schema_count: int,
    complete_schema_sha256: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    timestamp = int(time.time()) if now_unix is None else now_unix
    contract = _platform_publication_contract(
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        complete_schema_count=complete_schema_count,
        complete_schema_sha256=complete_schema_sha256,
    )
    with _state_lock():
        current = _read_publication_current()
        if current is None or current["state"] == "no_current":
            return {
                "state": "no_current_request",
                "contract": contract,
                "recommended_next_action": "no publication request exists for reconciliation",
            }
        request = _read_publication_request(current["request_id"])
        request_contract_sha256 = request["expected_contract"]["tool_contract_sha256"]
        runtime_contract_sha256 = contract["tool_contract_sha256"]
        if current["state"] == "pending_activation":
            if request_contract_sha256 == runtime_contract_sha256:
                updated = _write_publication_current(
                    request_id=current["request_id"],
                    contract_sha256=current["contract_sha256"],
                    state="publication_pending",
                    attempt_id=current.get("attempt_id"),
                    now_unix=timestamp,
                )
                return {
                    "state": "publication_pending",
                    "request_id": current["request_id"],
                    "current_sha256": updated["current_sha256"],
                    "recovered_pending_activation": True,
                    "recommended_next_action": "perform the requested ChatGPT connector refresh or republish action, then capture a fresh request-bound platform catalog",
                }
            return {
                "state": "runtime_contract_changed",
                "request_id": current["request_id"],
                "request_contract_sha256": request_contract_sha256,
                "runtime_contract_sha256": runtime_contract_sha256,
                "recommended_next_action": "roll back or supersede the prepared publication request for the actually active runtime contract",
            }
        if request_contract_sha256 != runtime_contract_sha256:
            return {
                "state": "runtime_contract_changed",
                "request_id": current["request_id"],
                "request_contract_sha256": request_contract_sha256,
                "runtime_contract_sha256": runtime_contract_sha256,
                "recommended_next_action": "prepare a publication request for the active runtime contract",
            }
        if current["state"] == "platform_converged":
            receipt = _read_publication_receipt(current["request_id"])
            if (
                receipt["request_sha256"] != request["request_sha256"]
                or receipt["contract_sha256"] != contract["tool_contract_sha256"]
            ):
                raise ClientSnapshotError(
                    "platform convergence receipt no longer binds the current request contract"
                )
            return {
                "state": "platform_converged",
                "request_id": current["request_id"],
                "request_sha256": request["request_sha256"],
                "receipt_sha256": receipt["receipt_sha256"],
                "contract": contract,
                "idempotent": True,
                "current_sha256": current["current_sha256"],
            }
        try:
            document = _read_platform_snapshot()
        except FileNotFoundError:
            document = None
        except (OSError, ClientSnapshotError) as exc:
            return {
                "state": current["state"],
                "request_id": current["request_id"],
                "error": type(exc).__name__,
                "recommended_next_action": "repair the trusted platform observation before reconciliation",
            }
        observation = None
        if document is not None:
            try:
                observation = _platform_publication_observation(
                    document, contract, now_unix=timestamp, request=request
                )
            except ClientSnapshotError as exc:
                return {
                    "state": current["state"],
                    "request_id": current["request_id"],
                    "error": type(exc).__name__,
                    "recommended_next_action": "replace invalid platform evidence with a fresh request-bound observation",
                }
        if observation is None or not observation["converged"]:
            if observation is not None and observation["request_bound"] is False:
                reason = "historical_or_unbound_observation"
            elif observation is not None and observation["observation_scope"] == "chat_session_catalog":
                reason = "session_observation_not_connector_authority"
            elif observation is not None and not observation["fresh"]:
                reason = "stale_platform_observation"
            elif observation is not None and not observation["surface_matches"]:
                reason = "platform_surface_mismatch"
            else:
                reason = "platform_observation_missing"
            return {
                "state": current["state"],
                "request_id": current["request_id"],
                "reason": reason,
                "observation": observation,
                "recommended_next_action": "capture a fresh request-bound connector_catalog or new_chat_catalog observation after the publication action",
            }
        receipt = _persist_publication_receipt(
            request=request,
            contract=contract,
            observation=observation,
            now_unix=timestamp,
        )
        updated = _write_publication_current(
            request_id=request["request_id"],
            contract_sha256=contract["tool_contract_sha256"],
            state="platform_converged",
            attempt_id=current.get("attempt_id"),
            now_unix=timestamp,
        )
        return {
            "state": "platform_converged",
            "request_id": request["request_id"],
            "request_sha256": request["request_sha256"],
            "receipt_sha256": receipt["receipt_sha256"],
            "snapshot_sha256": observation["snapshot_sha256"],
            "contract": contract,
            "observation": observation,
            "current_sha256": updated["current_sha256"],
        }


def rebind_authentic_snapshot_for_cutover(
    *,
    cutover_id: str,
    cutover_generation: int,
    current_release_id: str,
    current_repo_head: str,
    green_release_id: str,
    green_repo_head: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Preserve a fresh external-client Blue declaration across cutover."""
    return _rebind_snapshot_for_cutover(
        cutover_id=cutover_id,
        cutover_generation=cutover_generation,
        current_release_id=current_release_id,
        current_repo_head=current_repo_head,
        green_release_id=green_release_id,
        green_repo_head=green_repo_head,
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        agent_instructions_sha256=agent_instructions_sha256,
        green_readiness=green_readiness,
        observation_scope=OBSERVATION_SCOPE_EXTERNAL_CLIENT,
        verification_model=(
            "external-client-prior-observation+green-runtime-readiness+"
            "cutover-rebind-v2"
        ),
        recommended_next_action="refresh external client publication evidence",
        scope_error="authentic external connector schema receipt is required",
        additional_nonclaims=(
            "that the external client has refreshed against green",
            "platform connector catalog publication",
            "application success of any tool call",
            "resistance to compromised same-uid code",
        ),
        now_unix=now_unix,
    )


def rebind_server_loopback_snapshot_for_cutover(
    *,
    cutover_id: str,
    cutover_generation: int,
    current_release_id: str,
    current_repo_head: str,
    green_release_id: str,
    green_repo_head: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Preserve verified server-loopback continuity without claiming platform refresh."""
    return _rebind_snapshot_for_cutover(
        cutover_id=cutover_id,
        cutover_generation=cutover_generation,
        current_release_id=current_release_id,
        current_repo_head=current_repo_head,
        green_release_id=green_release_id,
        green_repo_head=green_repo_head,
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        agent_instructions_sha256=agent_instructions_sha256,
        green_readiness=green_readiness,
        observation_scope=OBSERVATION_SCOPE_SERVER_LOOPBACK,
        verification_model=(
            "server-loopback-prior-observation+green-runtime-readiness+"
            "cutover-rebind-v1"
        ),
        recommended_next_action="refresh external client and platform publication evidence",
        scope_error="verified server-loopback schema receipt is required",
        additional_nonclaims=(
            "that an external client has refreshed against green",
            "platform connector catalog publication",
            "tool schema visibility in ChatGPT",
            "application success of any tool call",
            "resistance to compromised same-uid code",
        ),
        now_unix=now_unix,
    )


def rebind_snapshot_for_midcutover_recovery(
    *,
    cutover_id: str,
    cutover_generation: int,
    current_release_id: str,
    current_repo_head: str,
    green_release_id: str,
    green_repo_head: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    observation_scope: str,
    source_snapshot_receipt_sha256: str,
    source_client_declaration_sha256: str,
    classified_snapshot_receipt_sha256: str,
    receipt_root: Path | None = None,
) -> dict[str, Any]:
    """Rebind stale legacy evidence only from its durable cutover receipt.

    The ordinary rebind entry points deliberately use the current clock and do
    not expose a historical-time override.  Recovery is the one narrow case in
    which an expired source snapshot may still be valid, so this entry point
    reads the owner-controlled ``bgc`` receipt itself, validates the complete
    receipt and its unique activation observation, and derives both the source
    clock and Publication-v2 request from that durable evidence.  A caller can
    choose the lineage it wants inspected; it cannot supply the time that makes
    the source snapshot fresh.
    """
    # Imported lazily to avoid a module-load cycle: midcutover uses the
    # canonical snapshot inspector from this module.  At effect time both
    # modules are fully initialised.
    import grabowski_midcutover_resume as midcutover

    root = BLUE_GREEN_RECEIPT_ROOT if receipt_root is None else receipt_root
    loaded = midcutover.load_receipts(root)
    if loaded.get("unreadable"):
        raise ClientSnapshotError(
            "blue-green recovery receipt authority contains unreadable evidence"
        )
    candidates = [
        value
        for value in loaded.get("receipts", [])
        if value.get("kind") == midcutover.CUTOVER_RECEIPT_KIND
        and value.get("cutover_id") == cutover_id
    ]
    if len(candidates) != 1:
        raise ClientSnapshotError(
            "mid-cutover recovery requires exactly one durable cutover receipt"
        )
    receipt = midcutover.validate_cutover_receipt(candidates[0])
    try:
        activation = midcutover.activation_observation(receipt)
    except midcutover.MidCutoverEvidenceError as exc:
        raise ClientSnapshotError(str(exc)) from exc
    durable_green_readiness = receipt.get("green_readiness")
    readiness_identity_fields = (
        "ready",
        "release_id",
        "repo_head",
        "names_sha256",
        "agent_instructions_sha256",
        "schema_sha256_by_tool",
        "schema_identity_sha256",
        "complete_schema_count",
        "complete_schema_sha256",
    )
    if (
        receipt.get("cutover_generation") != cutover_generation
        or receipt.get("blue_release_id") != current_release_id
        or receipt.get("green_release_id") != green_release_id
        or receipt.get("expected_head") != green_repo_head
        or receipt.get("names_sha256") != registered_names_sha256
        or receipt.get("agent_instructions_sha256")
        != agent_instructions_sha256
        or not isinstance(durable_green_readiness, dict)
        or not isinstance(green_readiness, dict)
        or any(
            durable_green_readiness.get(field) != green_readiness.get(field)
            for field in readiness_identity_fields
        )
    ):
        raise ClientSnapshotError(
            "durable cutover receipt does not bind the requested snapshot recovery"
        )

    if observation_scope == OBSERVATION_SCOPE_EXTERNAL_CLIENT:
        verification_model = (
            "external-client-prior-observation+green-runtime-readiness+"
            "cutover-rebind-v2"
        )
        recommended_next_action = "refresh external client publication evidence"
        scope_error = "authentic external connector schema receipt is required"
        nonclaims = (
            "that the external client has refreshed against green",
            "platform connector catalog publication",
            "application success of any tool call",
            "resistance to compromised same-uid code",
        )
    elif observation_scope == OBSERVATION_SCOPE_SERVER_LOOPBACK:
        verification_model = (
            "server-loopback-prior-observation+green-runtime-readiness+"
            "cutover-rebind-v1"
        )
        recommended_next_action = (
            "refresh external client and platform publication evidence"
        )
        scope_error = "verified server-loopback schema receipt is required"
        nonclaims = (
            "that an external client has refreshed against green",
            "platform connector catalog publication",
            "tool schema visibility in ChatGPT",
            "application success of any tool call",
            "resistance to compromised same-uid code",
        )
    else:
        raise ClientSnapshotError("cutover snapshot source scope is invalid")

    source_snapshot_receipt_sha256 = _require_authentic_digest(
        source_snapshot_receipt_sha256,
        label="source snapshot receipt_sha256",
    )
    source_client_declaration_sha256 = _require_authentic_digest(
        source_client_declaration_sha256,
        label="source client_declaration_sha256",
    )
    classified_snapshot_receipt_sha256 = _require_authentic_digest(
        classified_snapshot_receipt_sha256,
        label="classified snapshot receipt_sha256",
    )
    if classified_snapshot_receipt_sha256 != source_snapshot_receipt_sha256:
        raise ClientSnapshotError(
            "S0 classification is not bound to its predecessor snapshot"
        )

    return _rebind_snapshot_for_cutover(
        cutover_id=cutover_id,
        cutover_generation=cutover_generation,
        current_release_id=current_release_id,
        current_repo_head=current_repo_head,
        green_release_id=green_release_id,
        green_repo_head=green_repo_head,
        registered_tool_count=registered_tool_count,
        registered_names_sha256=registered_names_sha256,
        agent_instructions_sha256=agent_instructions_sha256,
        green_readiness=durable_green_readiness,
        observation_scope=observation_scope,
        verification_model=verification_model,
        recommended_next_action=recommended_next_action,
        scope_error=scope_error,
        additional_nonclaims=nonclaims,
        source_evidence_time=activation["source_evidence_time"],
        publication_request_id=activation["publication_request_id"],
        expected_source_snapshot_receipt_sha256=source_snapshot_receipt_sha256,
        expected_source_client_declaration_sha256=source_client_declaration_sha256,
        expected_classified_snapshot_receipt_sha256=(
            classified_snapshot_receipt_sha256
        ),
    )


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


def inspect_cutover_snapshot_binding(
    *,
    cutover_id: str,
    cutover_generation: int,
    source_release_id: str,
    source_repo_head: str,
    target_release_id: str,
    target_repo_head: str,
    source_evidence_time: int,
    publication_request_id: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    path: Path = SNAPSHOT_PATH,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Inspect the durable snapshot using the canonical receipt contract.

    This is deliberately a semantic projection, not another receipt parser.
    Every returned predecessor/rebound state has first passed the same private
    file, receipt-hash and declaration-hash validation used by the normal
    snapshot path.  Authentic evidence that names some other lineage is
    ``foreign``; evidence that cannot be authenticated is ``unreadable``.
    """
    observation: dict[str, Any] = {
        "path": str(path),
        "state": SNAPSHOT_BINDING_UNREADABLE,
        "bound_release_id": None,
        "bound_repo_head": None,
        "observation_scope": None,
        "snapshot_receipt_sha256": None,
        "source_receipt_sha256": None,
        "source_snapshot_receipt_sha256": None,
        "source_client_declaration_sha256": None,
        "classified_snapshot_receipt_sha256": None,
        "source_release_id": None,
        "source_repo_head": None,
        "target_release_id": None,
        "target_repo_head": None,
        "source_evidence_time": source_evidence_time,
        "publication_request_id": publication_request_id,
        "publication_transition_sha256": None,
        "schema_changed": None,
        "error": None,
    }
    try:
        receipt = _read_private_json(path)
        _validate_receipt(receipt)
        _validate_identifier(cutover_id, label="cutover_id")
        if (
            isinstance(cutover_generation, bool)
            or not isinstance(cutover_generation, int)
            or cutover_generation < 1
        ):
            raise ClientSnapshotError("cutover_generation is invalid")
        source_release = _validate_release_id(
            source_release_id, label="source release id"
        )
        target_release = _validate_release_id(
            target_release_id, label="target release id"
        )
        for label, head in (
            ("source repository head", source_repo_head),
            ("target repository head", target_repo_head),
        ):
            if not isinstance(head, str) or re.fullmatch(r"[0-9a-f]{40,64}", head) is None:
                raise ClientSnapshotError(f"{label} is invalid")
        if (
            isinstance(registered_tool_count, bool)
            or not isinstance(registered_tool_count, int)
            or registered_tool_count < 1
        ):
            raise ClientSnapshotError("registered tool count is invalid")
        names_sha256 = _require_authentic_digest(
            registered_names_sha256, label="registered_names_sha256"
        )
        instructions_sha256 = _require_authentic_digest(
            agent_instructions_sha256, label="agent_instructions_sha256"
        )
        _validate_identifier(
            publication_request_id, label="publication_request_id"
        )
        if (
            not isinstance(green_readiness, dict)
            or green_readiness.get("ready") is not True
            or green_readiness.get("release_id") != target_release
            or green_readiness.get("repo_head") != target_repo_head
            or green_readiness.get("names_sha256") != names_sha256
            or green_readiness.get("agent_instructions_sha256")
            != instructions_sha256
        ):
            raise ClientSnapshotError("green readiness does not bind the target")

        declaration = receipt["client_declaration"]
        binding = receipt["server_binding"]
        schema_evidence = receipt.get("schema_evidence")
        observation_scope = declaration.get("observation_scope")
        if (
            receipt.get("verified") is not True
            or receipt.get("mismatches") != []
            or observation_scope
            not in {
                OBSERVATION_SCOPE_EXTERNAL_CLIENT,
                OBSERVATION_SCOPE_SERVER_LOOPBACK,
            }
            or not isinstance(schema_evidence, dict)
            or not isinstance(schema_evidence.get("probe"), dict)
            or schema_evidence["probe"].get("matches") is not True
            or schema_evidence["probe"].get("schema_contract_matches") is not True
        ):
            raise ClientSnapshotError("client snapshot verification contract is invalid")
        for label, value in (
            ("observed names hash", declaration.get("observed_names_sha256")),
            (
                "observed instructions hash",
                declaration.get("observed_agent_instructions_sha256"),
            ),
            ("observed artifact hash", declaration.get("observed_tools_artifact_sha256")),
        ):
            _require_authentic_digest(value, label=label)
        source_tool_count = declaration.get("observed_tool_count")
        if (
            isinstance(source_tool_count, bool)
            or not isinstance(source_tool_count, int)
            or not 1 <= source_tool_count <= 1_000
        ):
            raise ClientSnapshotError("source connector tool count is invalid")
        source_names_sha256 = _require_authentic_digest(
            declaration.get("observed_names_sha256"),
            label="source observed names hash",
        )
        source_instructions_sha256 = _require_authentic_digest(
            declaration.get("observed_agent_instructions_sha256"),
            label="source observed instructions hash",
        )
        if declaration.get("observed_release_id") != source_release:
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "client snapshot source declaration names another release"
            return observation
        source_binding_selected = (
            binding.get("release_id") == source_release
            and binding.get("repo_head") == source_repo_head
        )
        target_binding_selected = (
            binding.get("release_id") == target_release
            and binding.get("repo_head") == target_repo_head
        )
        if source_binding_selected:
            binding_surface_matches = (
                binding.get("registered_tool_count") == source_tool_count
                and binding.get("registered_names_sha256") == source_names_sha256
                and binding.get("agent_instructions_sha256")
                == source_instructions_sha256
            )
        elif target_binding_selected:
            binding_surface_matches = (
                binding.get("registered_tool_count") == registered_tool_count
                and binding.get("registered_names_sha256") == names_sha256
                and binding.get("agent_instructions_sha256") == instructions_sha256
            )
        else:
            binding_surface_matches = False
        if not binding_surface_matches:
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "client snapshot server binding names another surface"
            return observation
        if source_instructions_sha256 != instructions_sha256:
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "green agent instructions differ from the blue declaration"
            return observation

        observed_artifact = schema_evidence.get("observed_artifact")
        if not isinstance(observed_artifact, dict):
            raise ClientSnapshotError("source schema artifact is unavailable")
        source_hashes, source_identity = _require_schema_identity(
            observed_artifact.get("schema_sha256_by_tool"),
            label="source sentinel schema identity",
        )
        target_hashes, target_identity = _require_schema_identity(
            green_readiness.get("schema_sha256_by_tool"),
            label="green sentinel schema identity",
        )
        source_complete = _require_authentic_digest(
            observed_artifact.get("complete_schema_sha256"),
            label="source complete schema identity",
        )
        target_complete = _require_authentic_digest(
            green_readiness.get("complete_schema_sha256"),
            label="green complete schema identity",
        )
        if (
            observed_artifact.get("complete_schema_observable") is not True
            or observed_artifact.get("complete_schema_count") != source_tool_count
            or green_readiness.get("complete_schema_count") != registered_tool_count
            or green_readiness.get("schema_identity_sha256") != target_identity
        ):
            raise ClientSnapshotError("complete schema identity is invalid")
        schema_changed = (
            source_hashes != target_hashes
            or source_identity != target_identity
            or source_complete != target_complete
        )
        surface_changed = (
            schema_changed
            or source_tool_count != registered_tool_count
            or source_names_sha256 != names_sha256
        )
        current_authorization = None
        if surface_changed:
            current_authorization = _authorized_publication_schema_transition(
                cutover_id=cutover_id,
                source_tool_count=source_tool_count,
                source_names_sha256=source_names_sha256,
                registered_tool_count=registered_tool_count,
                registered_names_sha256=names_sha256,
                green_complete_schema_count=registered_tool_count,
                green_complete_schema_sha256=target_complete,
                source_schema_identity_sha256=source_identity,
                source_complete_schema_sha256=source_complete,
                target_schema_identity_sha256=target_identity,
                green_readiness=green_readiness,
                schema_changed=schema_changed,
                now_unix=int(time.time()) if now_unix is None else now_unix,
                expected_publication_request_id=publication_request_id,
            )

        observation.update(
            {
                "bound_release_id": binding.get("release_id"),
                "bound_repo_head": binding.get("repo_head"),
                "observation_scope": observation_scope,
                "snapshot_receipt_sha256": receipt.get("receipt_sha256"),
                "classified_snapshot_receipt_sha256": receipt.get(
                    "receipt_sha256"
                ),
                "schema_changed": schema_changed,
                "surface_changed": surface_changed,
                "current_publication_authorized": current_authorization is not None
                if surface_changed
                else True,
            }
        )
        cutover_binding = receipt.get("cutover_binding")
        transition = receipt.get("cutover_transition")
        if binding.get("release_id") == source_release and binding.get(
            "repo_head"
        ) == source_repo_head:
            if cutover_binding is not None or transition is not None:
                observation["state"] = SNAPSHOT_BINDING_FOREIGN
                observation["error"] = "predecessor snapshot carries a cutover transition"
                return observation
            _historical_snapshot_freshness(
                receipt, source_evidence_time=source_evidence_time
            )
            observation["state"] = SNAPSHOT_BINDING_PREDECESSOR
            observation["source_receipt_sha256"] = receipt.get("receipt_sha256")
            observation["source_snapshot_receipt_sha256"] = receipt.get(
                "receipt_sha256"
            )
            observation["source_client_declaration_sha256"] = receipt.get(
                "client_declaration_sha256"
            )
            observation["source_release_id"] = source_release
            observation["source_repo_head"] = source_repo_head
            return observation

        if binding.get("release_id") != target_release or binding.get(
            "repo_head"
        ) != target_repo_head:
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "snapshot binds neither predecessor nor target"
            return observation
        if (
            not isinstance(cutover_binding, dict)
            or set(cutover_binding)
            != {"cutover_id", "cutover_generation", "rebind_role"}
            or cutover_binding.get("cutover_id") != cutover_id
            or cutover_binding.get("cutover_generation") != cutover_generation
            or cutover_binding.get("rebind_role") != "blue-green-cutover"
            or not isinstance(transition, dict)
            or transition.get("from_release_id") != source_release
            or transition.get("from_repo_head") != source_repo_head
            or transition.get("to_release_id") != target_release
            or transition.get("to_repo_head") != target_repo_head
            or transition.get("source_evidence_time") != source_evidence_time
            or transition.get("schema_identity_sha256") != source_identity
            or transition.get("complete_schema_sha256") != source_complete
            or transition.get("target_schema_identity_sha256") != target_identity
            or transition.get("target_complete_schema_sha256") != target_complete
            or transition.get("schema_changed") is not schema_changed
            or (
                transition.get("surface_changed", transition.get("schema_changed"))
                is not surface_changed
            )
            or transition.get("green_readiness_sha256") != _sha256_json(green_readiness)
            or transition.get("surface_continuity_sha256")
            != _sha256_json(
                {
                    "registered_tool_count": source_tool_count,
                    "registered_names_sha256": source_names_sha256,
                    "agent_instructions_sha256": source_instructions_sha256,
                    "schema_identity_sha256": source_identity,
                    "complete_schema_sha256": source_complete,
                }
            )
        ):
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "snapshot transition does not bind this lineage"
            return observation
        source_created = transition.get("source_created_at_unix")
        source_expires = transition.get("source_expires_at_unix")
        if (
            isinstance(source_created, bool)
            or not isinstance(source_created, int)
            or isinstance(source_expires, bool)
            or not isinstance(source_expires, int)
            or not (
                source_created - SNAPSHOT_CLOCK_SKEW_SECONDS
                <= source_evidence_time
                <= source_expires
            )
        ):
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "snapshot transition historical freshness is invalid"
            return observation
        source_receipt_sha256 = _require_authentic_digest(
            transition.get("source_receipt_sha256"),
            label="source receipt_sha256",
        )
        source_declaration_sha256 = _require_authentic_digest(
            transition.get("source_client_declaration_sha256"),
            label="source client_declaration_sha256",
        )
        if source_declaration_sha256 != receipt.get("client_declaration_sha256"):
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = (
                "snapshot transition source declaration does not match the receipt"
            )
            return observation
        rebound_created = receipt.get("created_at_unix")
        rebound_expires = receipt.get("expires_at_unix")
        inspection_time = int(time.time()) if now_unix is None else now_unix
        if (
            isinstance(rebound_created, bool)
            or not isinstance(rebound_created, int)
            or isinstance(rebound_expires, bool)
            or not isinstance(rebound_expires, int)
            or rebound_expires != rebound_created + SNAPSHOT_TTL_SECONDS
            or rebound_created < source_evidence_time
            or rebound_created > inspection_time + SNAPSHOT_CLOCK_SKEW_SECONDS
        ):
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "snapshot rebind recovery-time contract is invalid"
            return observation
        persisted_publication = transition.get("publication_schema_transition")
        if surface_changed:
            stable_fields = (
                "cutover_id",
                "source_schema_identity_sha256",
                "source_complete_schema_sha256",
                "target_schema_identity_sha256",
                "target_complete_schema_sha256",
                "green_readiness_sha256",
                "publication_request_id",
                "publication_request_sha256",
                "publication_contract_sha256",
            )
            if isinstance(persisted_publication, dict) and "surface_changed" in persisted_publication:
                stable_fields += (
                    "source_tool_count",
                    "source_names_sha256",
                    "target_tool_count",
                    "target_names_sha256",
                    "surface_changed",
                    "schema_changed",
                )
            if not isinstance(persisted_publication, dict) or any(
                persisted_publication.get(key) != current_authorization.get(key)
                for key in stable_fields
            ):
                observation["state"] = SNAPSHOT_BINDING_FOREIGN
                observation["error"] = "snapshot publication transition is not currently authorized"
                return observation
            expected_transition_nonclaims = [
                (
                    "that any client has observed the changed green surface"
                    if "surface_changed" in persisted_publication
                    else "that any client has observed the changed green schema"
                ),
                "platform connector catalog publication",
            ]
            if (
                persisted_publication.get("schema_version") != 1
                or persisted_publication.get("kind")
                != "grabowski_connector_schema_transition"
                or (
                    persisted_publication.get(
                        "surface_changed", persisted_publication.get("schema_changed")
                    )
                    is not True
                )
                or persisted_publication.get("schema_changed") is not schema_changed
                or persisted_publication.get("publication_state")
                not in PUBLICATION_REBIND_AUTHORIZED_STATES
                or persisted_publication.get("publication_current_state")
                not in (
                    PLATFORM_PUBLICATION_CURRENT_STATES
                    - PUBLICATION_REBIND_FORBIDDEN_CURRENT_STATES
                    - {"no_current"}
                )
                or persisted_publication.get("authorized_at_unix")
                != rebound_created
                or persisted_publication.get("does_not_establish")
                != expected_transition_nonclaims
            ):
                observation["state"] = SNAPSHOT_BINDING_FOREIGN
                observation["error"] = (
                    "snapshot publication transition historical authorization is invalid"
                )
                return observation
            declared_transition = persisted_publication.get("transition_sha256")
            unsigned_transition = dict(persisted_publication)
            unsigned_transition.pop("transition_sha256", None)
            if (
                _validate_sha256(
                    declared_transition, label="publication transition_sha256"
                )
                != _sha256_json(unsigned_transition)
            ):
                observation["state"] = SNAPSHOT_BINDING_FOREIGN
                observation["error"] = "snapshot publication transition hash mismatch"
                return observation
            observation["publication_transition_sha256"] = declared_transition
        elif persisted_publication is not None:
            observation["state"] = SNAPSHOT_BINDING_FOREIGN
            observation["error"] = "unchanged schema carries a publication transition"
            return observation
        observation["state"] = SNAPSHOT_BINDING_REBOUND
        observation["source_receipt_sha256"] = source_receipt_sha256
        observation["source_snapshot_receipt_sha256"] = source_receipt_sha256
        observation["source_client_declaration_sha256"] = (
            source_declaration_sha256
        )
        observation["source_release_id"] = source_release
        observation["source_repo_head"] = source_repo_head
        observation["target_release_id"] = target_release
        observation["target_repo_head"] = target_repo_head
        return observation
    except (ClientSnapshotError, OSError, ValueError) as exc:
        observation["state"] = SNAPSHOT_BINDING_UNREADABLE
        observation["error"] = str(exc)
        return observation


@contextmanager
def cutover_snapshot_effect_guard(
    *,
    cutover_id: str,
    cutover_generation: int,
    source_release_id: str,
    source_repo_head: str,
    target_release_id: str,
    target_repo_head: str,
    source_evidence_time: int,
    publication_request_id: str,
    registered_tool_count: int,
    registered_names_sha256: str,
    agent_instructions_sha256: str,
    green_readiness: dict[str, Any],
    expected_state: str,
    source_snapshot_receipt_sha256: str,
    source_client_declaration_sha256: str,
    classified_snapshot_receipt_sha256: str,
    path: Path = SNAPSHOT_PATH,
) -> Iterator[dict[str, Any]]:
    """Hold the snapshot lock from exact identity readback through one effect.

    Classification authorises one immutable receipt, not a merely equivalent
    surface.  The caller supplies only identities already present in its
    hash-bound resume binding; this guard reuses the canonical inspection while
    holding the same lock every snapshot writer must acquire.
    """
    if expected_state not in {
        SNAPSHOT_BINDING_PREDECESSOR,
        SNAPSHOT_BINDING_REBOUND,
    }:
        raise ClientSnapshotError("expected snapshot binding state is invalid")
    expected_source_receipt = _require_authentic_digest(
        source_snapshot_receipt_sha256,
        label="source snapshot receipt_sha256",
    )
    expected_declaration = _require_authentic_digest(
        source_client_declaration_sha256,
        label="source client_declaration_sha256",
    )
    expected_classified_receipt = _require_authentic_digest(
        classified_snapshot_receipt_sha256,
        label="classified snapshot receipt_sha256",
    )
    with _state_lock():
        observed = inspect_cutover_snapshot_binding(
            cutover_id=cutover_id,
            cutover_generation=cutover_generation,
            source_release_id=source_release_id,
            source_repo_head=source_repo_head,
            target_release_id=target_release_id,
            target_repo_head=target_repo_head,
            source_evidence_time=source_evidence_time,
            publication_request_id=publication_request_id,
            registered_tool_count=registered_tool_count,
            registered_names_sha256=registered_names_sha256,
            agent_instructions_sha256=agent_instructions_sha256,
            green_readiness=green_readiness,
            path=path,
        )
        if (
            observed.get("state") != expected_state
            or observed.get("source_snapshot_receipt_sha256")
            != expected_source_receipt
            or observed.get("source_client_declaration_sha256")
            != expected_declaration
            or observed.get("classified_snapshot_receipt_sha256")
            != expected_classified_receipt
        ):
            raise ClientSnapshotError(
                "classified snapshot identity changed before recovery effect"
            )
        yield observed


def _runtime_publication_contract_for_status(
    *,
    expected_tool_count: int,
    expected_names_sha256: str,
    expected_runtime_tools: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if expected_runtime_tools is None:
        return None
    try:
        _names, _schemas, metadata = connector_contract.parse_observed_artifact(
            expected_runtime_tools,
            label="runtime connector artifact",
        )
    except connector_contract.ConnectorContractError:
        return None
    if (
        metadata.get("name_count") != expected_tool_count
        or metadata.get("names_sha256") != expected_names_sha256
        or metadata.get("complete_schema_observable") is not True
        or metadata.get("complete_schema_count") != expected_tool_count
    ):
        return None
    try:
        return _platform_publication_contract(
            registered_tool_count=expected_tool_count,
            registered_names_sha256=expected_names_sha256,
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
        )
    except ClientSnapshotError:
        return None


def _normalized_publication_projection(
    contract: dict[str, Any],
    *,
    document: dict[str, Any] | None = None,
    now_unix: int,
) -> tuple[dict[str, Any], str, bool, str]:
    projection = _publication_projection_for_contract(
        contract,
        document=document,
        now_unix=now_unix,
    )
    state = str(projection.get("state") or "invalid")
    pending = bool(projection.get("publication_pending"))
    next_action = str(
        projection.get("recommended_next_action")
        or "repair the platform publication lifecycle"
    )
    if state == "untracked":
        state = "publication_request_required"
        pending = True
        next_action = (
            "create an immutable publication request for the current semantic tool contract, "
            "then refresh or republish the ChatGPT connector"
        )
    return projection, state, pending, next_action


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
        "surface_matches": False,
        "authority": authority,
        "source": None,
        "observation_scope": None,
        "observation_id": None,
        "runtime_binding_matches": False,
        "provenance_matches": False,
        "provenance_mismatches": [],
        "publication_contract_matches": False,
        "publication_pending": False,
        "publication_state": "unavailable",
        "publication_request_id": None,
        "publication_contract_sha256": None,
        "runtime_publication_contract": None,
        "publication_projection": None,
        "publication_mismatches": [],
        "schema_contract_matches": False,
        "schema_mismatches": [],
        "required_schema_property_mismatches": [],
        "recommended_next_action": (
            "capture a trusted platform connector catalog snapshot from ChatGPT "
            "using an explicit observation scope and observation id"
        ),
        "does_not_establish": [
            "platform behavior outside the captured catalog revision",
            "future platform connector publication",
            "a platform signature when the platform does not provide one",
        ],
    }
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        return {
            **base,
            "state": "invalid",
            "error": "timestamp_contract",
            "recommended_next_action": "repair platform snapshot clock inputs",
        }
    status_contract = _runtime_publication_contract_for_status(
        expected_tool_count=expected_tool_count,
        expected_names_sha256=expected_names_sha256,
        expected_runtime_tools=expected_runtime_tools,
    )
    if status_contract is not None:
        (
            durable_projection,
            durable_state,
            durable_pending,
            durable_next_action,
        ) = _normalized_publication_projection(
            status_contract, now_unix=timestamp
        )
        base.update(
            {
                "publication_pending": durable_pending,
                "publication_state": durable_state,
                "publication_request_id": durable_projection.get("request_id"),
                "publication_contract_sha256": status_contract["tool_contract_sha256"],
                "runtime_publication_contract": status_contract,
                "publication_projection": durable_projection,
                "recommended_next_action": durable_next_action,
            }
        )
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
                base["recommended_next_action"]
                if base.get("publication_projection") is not None
                else "replace the untrusted or invalid platform connector snapshot through the platform evidence integration"
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
        if set(document) != required_keys or document.get("kind") != PLATFORM_SNAPSHOT_KIND:
            raise ClientSnapshotError("platform connector snapshot contract mismatch")
        if document.get("schema_version") not in {
            PLATFORM_SNAPSHOT_SCHEMA_VERSION,
            PLATFORM_SNAPSHOT_V2_SCHEMA_VERSION,
        }:
            raise ClientSnapshotError("platform connector snapshot schema version is unsupported")
        declared_snapshot_sha256 = _validate_sha256(
            document.get("snapshot_sha256"), label="platform snapshot_sha256"
        )
        unsigned = dict(document)
        unsigned.pop("snapshot_sha256", None)
        if _sha256_json(unsigned) != declared_snapshot_sha256:
            raise ClientSnapshotError("platform connector snapshot hash mismatch")
        source_projection = _platform_source_projection(document)
        reference = _validate_platform_source_reference(source_projection.get("reference"))
        observed_at = source_projection.get("observed_at_unix")
        if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
            raise ClientSnapshotError("platform connector snapshot observation time is invalid")
        catalog_sha256 = _validate_sha256(
            source_projection.get("catalog_sha256"), label="platform catalog_sha256"
        )
        binding = document.get("runtime_binding")
        if not isinstance(binding, dict) or set(binding) != {
            "registered_tool_count",
            "registered_names_sha256",
            "release_id",
            "repo_head",
            "agent_instructions_sha256",
        }:
            raise ClientSnapshotError("platform connector snapshot runtime binding mismatch")
        registered_count = binding.get("registered_tool_count")
        if (
            isinstance(registered_count, bool)
            or not isinstance(registered_count, int)
            or not 1 <= registered_count <= connector_contract.MAX_OBSERVED_TOOLS
        ):
            raise ClientSnapshotError("platform connector snapshot tool count is invalid")
        _validate_sha256(
            binding.get("registered_names_sha256"),
            label="platform registered_names_sha256",
        )
        _validate_release_id(binding.get("release_id"), label="platform release id")
        repo_head = binding.get("repo_head")
        if not isinstance(repo_head, str) or re.fullmatch(r"[0-9a-f]{40}", repo_head) is None:
            raise ClientSnapshotError("platform connector snapshot repository head is invalid")
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
            raise ClientSnapshotError("platform connector catalog content hash mismatch")
        if expected_runtime_tools is None:
            return {
                **base,
                "state": "runtime_schema_unavailable",
                "source": source_projection,
                "recommended_next_action": (
                    "restore runtime schema observability before evaluating the platform connector snapshot"
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
            or runtime_metadata.get("complete_schema_observable") is not True
            or runtime_metadata.get("complete_schema_count") != expected_tool_count
        ):
            return {
                **base,
                "state": "runtime_schema_invalid",
                "source": source_projection,
                "recommended_next_action": (
                    "repair complete runtime schema observability before evaluating platform publication"
                ),
            }
        runtime_contract = _platform_publication_contract(
            registered_tool_count=expected_tool_count,
            registered_names_sha256=expected_names_sha256,
            complete_schema_count=runtime_metadata["complete_schema_count"],
            complete_schema_sha256=runtime_metadata["complete_schema_sha256"],
        )
        probe = connector_contract.probe_contract(
            observed_names,
            observed_schemas,
            runtime_names,
            runtime_schemas,
            runtime_names,
            observed_source="platform",
        )
        complete_schema_matches = bool(
            observed_metadata.get("complete_schema_observable") is True
            and observed_metadata.get("complete_schema_count") == expected_tool_count
            and observed_metadata.get("complete_schema_sha256")
            == runtime_contract["tool_schemas_sha256"]
        )
    except (TypeError, ValueError, ClientSnapshotError, connector_contract.ConnectorContractError) as exc:
        return {
            **base,
            "state": "invalid",
            "error": type(exc).__name__,
            "recommended_next_action": (
                "replace the invalid platform connector snapshot with a fresh platform-primary observation"
            ),
        }

    expected_provenance = {
        "registered_tool_count": expected_tool_count,
        "registered_names_sha256": expected_names_sha256,
        "release_id": expected_release_id,
        "repo_head": expected_repo_head,
        "agent_instructions_sha256": expected_agent_instructions_sha256,
    }
    provenance_mismatches = sorted(
        key
        for key, expected_value in expected_provenance.items()
        if binding.get(key) != expected_value
    )
    provenance_matches = not provenance_mismatches
    publication_mismatches: list[str] = []
    if observed_metadata["name_count"] != expected_tool_count:
        publication_mismatches.append("observed_tool_count")
    if observed_metadata["names_sha256"] != expected_names_sha256:
        publication_mismatches.append("observed_tool_names")
    if probe.get("matches") is not True:
        publication_mismatches.append("tool_or_schema_contract")
    if not complete_schema_matches:
        publication_mismatches.append("complete_schema_identity")
    surface_matches = not publication_mismatches
    future_clock_drift = observed_at > timestamp + SNAPSHOT_CLOCK_SKEW_SECONDS
    fresh = not future_clock_drift and timestamp <= observed_at + PLATFORM_SNAPSHOT_TTL_SECONDS

    # Backward compatibility: legacy matched/state retain their historical
    # provenance-sensitive meaning. Publication convergence is a separate,
    # stricter full-schema lifecycle below.
    legacy_complete_requirement = (
        observed_metadata.get("complete_schema_observable") is not True
        or complete_schema_matches
    )
    matched = bool(
        provenance_matches
        and probe.get("matches") is True
        and legacy_complete_requirement
    )
    observable = fresh and matched
    schema_observable = bool(
        observable
        and probe.get("schema_contract_matches") is True
        and legacy_complete_requirement
    )
    if future_clock_drift:
        state = "clock_drift"
        legacy_next_action = "replace the future-dated platform connector snapshot with a current platform observation"
    elif not fresh:
        state = "stale"
        legacy_next_action = "capture a fresh platform connector catalog snapshot"
    elif not matched:
        state = "mismatch"
        legacy_next_action = "repair reported platform catalog or provenance drift and capture a fresh platform-primary observation"
    else:
        state = "matched"
        legacy_next_action = "none"

    (
        publication_projection,
        publication_state,
        publication_pending,
        publication_next_action,
    ) = _normalized_publication_projection(
        runtime_contract,
        document=document,
        now_unix=timestamp,
    )
    return {
        **base,
        "state": state,
        "observable": observable,
        "schema_observable": schema_observable,
        "fresh": fresh,
        "matched": matched,
        "surface_matches": surface_matches,
        "source": source_projection,
        "observation_scope": source_projection.get("observation_scope"),
        "observation_id": source_projection.get("observation_id"),
        "snapshot_sha256": declared_snapshot_sha256,
        "runtime_binding": dict(binding),
        "runtime_binding_matches": provenance_matches,
        "binding_mismatches": provenance_mismatches,
        "provenance_matches": provenance_matches,
        "provenance_mismatches": provenance_mismatches,
        "publication_contract_matches": surface_matches,
        "publication_pending": publication_pending,
        "publication_state": publication_state,
        "publication_request_id": publication_projection.get("request_id"),
        "publication_contract_sha256": runtime_contract["tool_contract_sha256"],
        "runtime_publication_contract": runtime_contract,
        "publication_projection": publication_projection,
        "publication_mismatches": sorted(set(publication_mismatches)),
        "catalog": observed_metadata,
        "schema_contract_matches": bool(
            probe.get("schema_contract_matches") is True and complete_schema_matches
        ),
        "schema_mismatches": probe.get("schema_mismatches", []),
        "complete_schema_identity_matches": complete_schema_matches,
        "complete_schema_sha256": observed_metadata.get("complete_schema_sha256"),
        "required_schema_property_mismatches": probe.get(
            "required_schema_property_mismatches", []
        ),
        "probe": probe,
        "missing_from_platform": probe.get("missing_from_connector", []),
        "unexpected_in_platform": probe.get("unexpected_in_connector", []),
        "age_seconds": max(0, timestamp - observed_at),
        "recommended_next_action": (
            publication_next_action
            if publication_pending or publication_state == "platform_converged"
            else legacy_next_action
        ),
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
        "historical_schema_evidence_only": False,
        "fresh_client_observation_required": False,
        "runtime_fault_indicated": False,
        "connector_schema_transition": None,
        "external_client_snapshot_observable": False,
        "external_client_schema_observable": False,
        "platform_connector_snapshot_observable": platform_snapshot_observable,
        "platform_connector_schema_observable": platform_schema_observable,
        "platform_connector_snapshot_fresh": bool(platform_snapshot.get("fresh")),
        "platform_connector_snapshot_matched": bool(platform_snapshot.get("matched")),
        "platform_publication_contract_matches": bool(
            platform_snapshot.get("publication_contract_matches")
        ),
        "platform_publication_pending": bool(platform_snapshot.get("publication_pending")),
        "platform_publication_state": platform_snapshot.get("publication_state"),
        "platform_publication_request_id": platform_snapshot.get("publication_request_id"),
        "platform_publication_contract_sha256": platform_snapshot.get("publication_contract_sha256"),
        "platform_observation_scope": platform_snapshot.get("observation_scope"),
        "platform_observation_id": platform_snapshot.get("observation_id"),
        "platform_schema_mismatches": platform_snapshot.get("schema_mismatches", []),
        "platform_missing_tools": platform_snapshot.get("missing_from_platform", []),
        "platform_extra_tools": platform_snapshot.get("unexpected_in_platform", []),
        "platform_evidence_state": platform_snapshot.get("state"),
        "platform_snapshot": platform_snapshot,
        "server_loopback_observable": False,
        "server_loopback_schema_observable": False,
        "server_loopback_schema_contract_matches": False,
        "server_loopback_complete_schema_observable": False,
        "server_loopback_complete_schema_count": None,
        "server_loopback_complete_schema_sha256": None,
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
    transition = receipt.get("cutover_transition")
    transition_matches = (
        isinstance(transition, dict)
        and transition.get("source_client_declaration_sha256")
        == receipt.get("client_declaration_sha256")
        and transition.get("from_release_id")
        == declaration.get("observed_release_id")
        and transition.get("to_release_id") == expected_release_id
        and transition.get("to_repo_head") == expected_repo_head
        and isinstance(transition.get("source_receipt_sha256"), str)
        and _SHA256_RE.fullmatch(transition["source_receipt_sha256"]) is not None
        and len(set(transition["source_receipt_sha256"])) > 1
    )
    publication_transition = (
        transition.get("publication_schema_transition")
        if isinstance(transition, dict)
        and isinstance(transition.get("publication_schema_transition"), dict)
        else None
    )
    publication_transition_hash_valid = False
    if isinstance(publication_transition, dict):
        declared_transition_sha256 = publication_transition.get("transition_sha256")
        unsigned_transition = dict(publication_transition)
        unsigned_transition.pop("transition_sha256", None)
        publication_transition_hash_valid = (
            isinstance(declared_transition_sha256, str)
            and _SHA256_RE.fullmatch(declared_transition_sha256) is not None
            and _sha256_json(unsigned_transition) == declared_transition_sha256
        )
    historical_surface_matches = (
        transition_matches
        and publication_transition_hash_valid
        and publication_transition.get("surface_changed") is True
        and publication_transition.get("source_tool_count")
        == declaration.get("observed_tool_count")
        and publication_transition.get("source_names_sha256")
        == declaration.get("observed_names_sha256")
        and publication_transition.get("target_tool_count") == expected_tool_count
        and publication_transition.get("target_names_sha256") == expected_names_sha256
    )
    declaration_matches = (
        declaration.get("observed_agent_instructions_sha256")
        == expected_agent_instructions_sha256
        and (
            (
                declaration.get("observed_tool_count") == expected_tool_count
                and declaration.get("observed_names_sha256") == expected_names_sha256
                and (
                    declaration.get("observed_release_id") == expected_release_id
                    or transition_matches
                )
            )
            or historical_surface_matches
        )
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
    observed_artifact_metadata = (
        schema_evidence.get("observed_artifact")
        if isinstance(schema_evidence, dict)
        and isinstance(schema_evidence.get("observed_artifact"), dict)
        else {}
    )
    complete_schema_count = observed_artifact_metadata.get("complete_schema_count")
    complete_schema_sha256 = observed_artifact_metadata.get("complete_schema_sha256")
    # After an authorised schema transition the preserved evidence describes the
    # predecessor surface.  It stays in the receipt as history, but it must not
    # be reported as an observation of what is running now: no client has seen
    # the changed schema until one actually looks.
    historical_schema_evidence_only = bool(
        isinstance(transition, dict)
        and transition.get("surface_changed", transition.get("schema_changed")) is True
    )
    complete_schema_observable = (
        not historical_schema_evidence_only
        and observed_artifact_metadata.get("complete_schema_observable") is True
        and complete_schema_count == expected_tool_count
        and declaration.get("observed_complete_schema_count") == expected_tool_count
        and declaration.get("observed_complete_schema_sha256") == complete_schema_sha256
        and isinstance(complete_schema_sha256, str)
        and _SHA256_RE.fullmatch(complete_schema_sha256) is not None
    )
    observed_schema_contract_matches = (
        schema_evidence_observed
        and not historical_schema_evidence_only
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
    elif historical_schema_evidence_only:
        # The runtime is fine and the binding holds; what is missing is a look at
        # the new surface.  Saying that plainly matters: an operator who reads
        # this as a runtime fault will start debugging a healthy deployment.
        state = "matched"
        next_action = (
            "capture a fresh client observation of the changed green tool schema, "
            "bind it, then reconcile the platform publication; the runtime itself "
            "is bound and healthy and needs no repair"
        )
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
        "client_observed_release_id": declaration.get("observed_release_id"),
        "schema_observable": external_client_schema_observable,
        "schema_evidence_observed": schema_evidence_observed,
        "historical_schema_evidence_only": historical_schema_evidence_only,
        "fresh_client_observation_required": historical_schema_evidence_only,
        "runtime_fault_indicated": False,
        "connector_schema_transition": (
            transition.get("publication_schema_transition")
            if historical_schema_evidence_only and isinstance(transition, dict)
            else None
        ),
        "schema_contract_matches": external_client_schema_contract_matches,
        "external_client_snapshot_observable": (
            external_client_snapshot_observable
        ),
        "external_client_schema_observable": external_client_schema_observable,
        "external_client_complete_schema_observable": (
            external_client_schema_observable and complete_schema_observable
        ),
        "external_client_complete_schema_count": (
            complete_schema_count if complete_schema_observable else None
        ),
        "external_client_complete_schema_sha256": (
            complete_schema_sha256 if complete_schema_observable else None
        ),
        "platform_connector_snapshot_observable": platform_snapshot_observable,
        "platform_connector_schema_observable": platform_schema_observable,
        "platform_connector_snapshot_fresh": bool(platform_snapshot.get("fresh")),
        "platform_connector_snapshot_matched": bool(platform_snapshot.get("matched")),
        "platform_publication_contract_matches": bool(
            platform_snapshot.get("publication_contract_matches")
        ),
        "platform_publication_pending": bool(platform_snapshot.get("publication_pending")),
        "platform_publication_state": platform_snapshot.get("publication_state"),
        "platform_publication_request_id": platform_snapshot.get("publication_request_id"),
        "platform_publication_contract_sha256": platform_snapshot.get("publication_contract_sha256"),
        "platform_observation_scope": platform_snapshot.get("observation_scope"),
        "platform_observation_id": platform_snapshot.get("observation_id"),
        "platform_schema_mismatches": platform_snapshot.get("schema_mismatches", []),
        "platform_missing_tools": platform_snapshot.get("missing_from_platform", []),
        "platform_extra_tools": platform_snapshot.get("unexpected_in_platform", []),
        "platform_evidence_state": platform_snapshot.get("state"),
        "platform_snapshot": platform_snapshot,
        "server_loopback_observable": server_loopback_observable,
        "server_loopback_schema_observable": server_loopback_schema_observable,
        "server_loopback_schema_contract_matches": (
            server_loopback_schema_contract_matches
        ),
        "server_loopback_complete_schema_observable": (
            server_loopback_schema_observable and complete_schema_observable
        ),
        "server_loopback_complete_schema_count": (
            complete_schema_count
            if server_loopback_schema_observable and complete_schema_observable
            else None
        ),
        "server_loopback_complete_schema_sha256": (
            complete_schema_sha256
            if server_loopback_schema_observable and complete_schema_observable
            else None
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
    if declaration.get("observed_release_id") != expected_release_id:
        return "runtime-release-changed"
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
    if isinstance(result, dict):
        if (
            isinstance(result.get("status"), str)
            and isinstance(result.get("output"), dict)
        ):
            return result
        is_error = result.get("isError", False)
        structured = result.get("structuredContent")
        content = result.get("content")
    else:
        is_error = getattr(result, "isError", False)
        structured = getattr(result, "structuredContent", None)
        content = getattr(result, "content", None)
    if is_error is True:
        raise ClientSnapshotError(f"{label} returned an MCP tool error")
    if isinstance(structured, dict):
        return structured
    if not isinstance(content, list):
        raise ClientSnapshotError(f"{label} returned no bounded JSON payload")
    for item in content:
        text = (
            item.get("text")
            if isinstance(item, dict)
            else getattr(item, "text", None)
        )
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
    return url


def _validate_runtime_probe_mcp_url(url: str, *, auth_mode: str) -> str:
    """Bind productive readiness probes to their exact loopback authority."""
    if auth_mode not in {"connector", "ingress"}:
        raise ClientSnapshotError("runtime probe auth mode is invalid")
    if not isinstance(url, str) or len(url) > 2048:
        raise ClientSnapshotError("runtime probe MCP URL is invalid")
    parsed = urlsplit(url)
    expected_port = 18182 if auth_mode == "connector" else 18180
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != expected_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp"
    ):
        raise ClientSnapshotError(
            "runtime readiness probe is outside its bound loopback endpoint"
        )
    return url


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


def probe_runtime_readiness(
    *,
    runtime_root: Path,
    mcp_url: str,
    connector_token_path: Path,
    auth_mode: str,
    expected_release_id: str,
    expected_repo_head: str,
    expected_agent_instructions_sha256: str,
    timeout_seconds: float = AUTO_REFRESH_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Observe one real fixed loopback runtime without mutating snapshot state."""
    if auth_mode not in {"connector", "ingress"}:
        raise ClientSnapshotError("runtime probe auth mode is invalid")
    token = _read_transport_connector_capability(connector_token_path)
    url = _validate_runtime_probe_mcp_url(mcp_url, auth_mode=auth_mode)
    runtime_binding, contract_names = _runtime_platform_binding(runtime_root)
    if (
        runtime_binding.get("release_id") != expected_release_id
        or runtime_binding.get("repo_head") != expected_repo_head
        or runtime_binding.get("agent_instructions_sha256")
        != expected_agent_instructions_sha256
    ):
        raise ClientSnapshotError(
            "runtime probe expectations do not match the immutable manifest"
        )
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise ClientSnapshotError("runtime probe timeout is invalid") from exc
    if not 0.1 <= timeout <= 60.0:
        raise ClientSnapshotError("runtime probe timeout is invalid")

    async def observe() -> dict[str, Any]:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError as exc:
            raise ClientSnapshotError("MCP client runtime is unavailable") from exc
        header = (
            TRANSPORT_CONNECTOR_CAPABILITY_HEADER
            if auth_mode == "connector"
            else TRANSPORT_INGRESS_AUTH_HEADER
        )
        async with streamablehttp_client(
            url,
            headers={header: token},
        ) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                tools = await _list_all_tools(client)
                observed_artifact = _mixed_observed_tool_artifact(tools)
                observed_names, observed_schemas, observed_metadata = (
                    connector_contract.parse_observed_artifact(
                        observed_artifact,
                        label="runtime readiness tools/list artifact",
                    )
                )
                status_result = await client.call_tool(
                    "grabowski_status",
                    {"view": "minimal"},
                    meta={"client_id": AUTO_REFRESH_CLIENT_ID},
                )
                status = _mcp_tool_payload(
                    status_result, label="runtime readiness grabowski_status"
                )
                runtime = status.get("runtime")
                instructions = status.get("agent_instructions")
                tool_contract = status.get("tool_contract")
                if (
                    not isinstance(runtime, dict)
                    or not isinstance(instructions, dict)
                    or not isinstance(tool_contract, dict)
                ):
                    raise ClientSnapshotError(
                        "runtime readiness status is incomplete"
                    )
                observed_release = _validate_release_id(
                    runtime.get("release_id"), label="observed release id"
                )
                observed_head = runtime.get("repo_head")
                if (
                    not isinstance(observed_head, str)
                    or re.fullmatch(r"[0-9a-f]{40}", observed_head) is None
                ):
                    raise ClientSnapshotError(
                        "observed runtime repository head is invalid"
                    )
                observed_instructions = _validate_sha256(
                    instructions.get("sha256"),
                    label="observed agent instructions hash",
                )
                if (
                    tool_contract.get("registered_tool_count")
                    != len(observed_names)
                    or tool_contract.get("registered_names_sha256")
                    != observed_metadata["names_sha256"]
                    or tool_contract.get("runtime_matches_deployment_contract")
                    is not True
                ):
                    raise ClientSnapshotError(
                        "runtime readiness tools/list disagrees with status contract"
                    )
                readiness = connector_contract.evaluate_green_readiness(
                    observed_names=observed_names,
                    observed_schemas=observed_schemas,
                    runtime_names=observed_names,
                    runtime_schemas=observed_schemas,
                    contract_names=contract_names,
                    observed_release_id=observed_release,
                    expected_release_id=expected_release_id,
                    observed_repo_head=observed_head,
                    expected_repo_head=expected_repo_head,
                    observed_agent_instructions_sha256=observed_instructions,
                    expected_agent_instructions_sha256=(
                        expected_agent_instructions_sha256
                    ),
                )
                return {
                    **readiness,
                    "observation_endpoint": url,
                    "observation_auth_mode": auth_mode,
                    "observed_tool_count": len(observed_names),
                    "observed_tools_artifact_sha256": observed_metadata[
                        "artifact_sha256"
                    ],
                    "schema_coverage_count": observed_metadata[
                        "schema_coverage_count"
                    ],
                    "schema_sha256_by_tool": observed_metadata[
                        "schema_sha256_by_tool"
                    ],
                    "schema_identity_sha256": _sha256_json(
                        observed_metadata["schema_sha256_by_tool"]
                    ),
                    "complete_schema_count": observed_metadata.get(
                        "complete_schema_count"
                    ),
                    "complete_schema_sha256": observed_metadata.get(
                        "complete_schema_sha256"
                    ),
                }

    try:
        return asyncio.run(asyncio.wait_for(observe(), timeout=timeout))
    except asyncio.TimeoutError as exc:
        raise ClientSnapshotError("runtime readiness probe timed out") from exc


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
                bind_result: Any | None = None
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
                    transport_execute_result = await client.call_tool(
                        "grip_run",
                        {
                            "name": "transport-roundtrip",
                            "parameters": {
                                "action": "execute",
                                "challenge_receipt_sha256": (
                                    challenge_receipt_sha256
                                ),
                                "target_tool_name": "grip_run",
                                "target_arguments": bind_arguments,
                            },
                            "profile": "operator",
                            "allow_mutation": True,
                        },
                        meta=request_meta,
                    )
                    transport_execute = _mcp_tool_payload(
                        transport_execute_result,
                        label="transport roundtrip execute grip",
                    )
                    transport_execute_output = transport_execute.get("output")
                    transport_verification_receipt_sha256 = (
                        transport_execute_output.get(
                            "verification_receipt_sha256"
                        )
                        if isinstance(transport_execute_output, dict)
                        else None
                    )
                    if (
                        transport_execute.get("status") != "passed"
                        or not isinstance(transport_execute_output, dict)
                        or transport_execute_output.get("state") != "executed"
                        or transport_execute_output.get("target_error") is not None
                        or not isinstance(
                            transport_verification_receipt_sha256, str
                        )
                        or _SHA256_RE.fullmatch(
                            transport_verification_receipt_sha256
                        )
                        is None
                        or not isinstance(
                            transport_execute_output.get("target_result"), dict
                        )
                    ):
                        raise ClientSnapshotError(
                            "transport roundtrip execution did not execute the snapshot bind"
                        )
                    bind_result = transport_execute_output["target_result"]
                # Exactly the arguments the verification was bound to; any
                # deviation would be refused by the gate.
                if bind_result is None:
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
    observation_scope: str,
    observation_id: str,
    publication_request_id: str | None = None,
    requested_contract_sha256: str | None = None,
    observed_at_unix: int | None = None,
) -> tuple[dict[str, Any], list[str]]:
    timestamp = int(time.time()) if observed_at_unix is None else observed_at_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ClientSnapshotError("platform connector observation time is invalid")
    reference = _validate_platform_source_reference(source_reference)
    if observation_scope not in PLATFORM_OBSERVATION_SCOPES:
        raise ClientSnapshotError("platform connector observation scope is invalid")
    observation_id = _validate_identifier(
        observation_id, label="platform connector observation id"
    )
    if (publication_request_id is None) != (requested_contract_sha256 is None):
        raise ClientSnapshotError(
            "platform connector publication request id and contract hash must be supplied together"
        )
    if publication_request_id is not None:
        publication_request_id = _validate_identifier(
            publication_request_id, label="platform connector publication request id"
        )
        requested_contract_sha256 = _validate_sha256(
            requested_contract_sha256,
            label="platform connector requested contract hash",
        )
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
        "schema_version": PLATFORM_SNAPSHOT_V2_SCHEMA_VERSION,
        "kind": PLATFORM_SNAPSHOT_KIND,
        "source": {
            "kind": PLATFORM_SOURCE_KIND,
            "platform": "chatgpt",
            "connector_id": "grabowski",
            "observation_scope": observation_scope,
            "observation_id": observation_id,
            "publication_request_id": publication_request_id,
            "requested_contract_sha256": requested_contract_sha256,
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
    observation_scope: str,
    observation_id: str,
    publication_request_id: str | None = None,
    requested_contract_sha256: str | None = None,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    document, _runtime_names = _build_platform_connector_snapshot_with_runtime_names(
        observed_tools=observed_tools,
        runtime_root=runtime_root,
        source_reference=source_reference,
        observation_scope=observation_scope,
        observation_id=observation_id,
        publication_request_id=publication_request_id,
        requested_contract_sha256=requested_contract_sha256,
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
        descriptor = os.open(temporary, flags, PLATFORM_SNAPSHOT_MODE)
        os.fchmod(descriptor, PLATFORM_SNAPSHOT_MODE)
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
    observation_scope: str,
    observation_id: str,
    publication_request_id: str | None = None,
    requested_contract_sha256: str | None = None,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    document, runtime_names = _build_platform_connector_snapshot_with_runtime_names(
        observed_tools=observed_tools,
        runtime_root=runtime_root,
        source_reference=source_reference,
        observation_scope=observation_scope,
        observation_id=observation_id,
        publication_request_id=publication_request_id,
        requested_contract_sha256=requested_contract_sha256,
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
        "complete_schema_count": observed_metadata.get("complete_schema_count"),
        "complete_schema_sha256": observed_metadata.get("complete_schema_sha256"),
        "source_reference": document["source"]["reference"],
        "observation_scope": document["source"]["observation_scope"],
        "observation_id": document["source"]["observation_id"],
        "publication_request_id": document["source"]["publication_request_id"],
        "requested_contract_sha256": document["source"]["requested_contract_sha256"],
        "platform_publication": {
            "state": "captured_unreconciled",
            "recommended_next_action": (
                "run the user-owned platform publication reconciliation; root capture does not mutate user publication state"
            ),
        },
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
    capture.add_argument(
        "--observation-scope",
        choices=sorted(PLATFORM_OBSERVATION_SCOPES),
        required=True,
    )
    capture.add_argument("--observation-id", required=True)
    capture.add_argument("--publication-request-id")
    capture.add_argument("--requested-contract-sha256")
    capture.add_argument("--observed-tools-json", required=True)
    reconcile = subparsers.add_parser(
        "reconcile-platform-publication",
        help="Reconcile user-owned publication state from one trusted platform snapshot.",
    )
    reconcile.add_argument("--registered-tool-count", type=int, required=True)
    reconcile.add_argument("--registered-names-sha256", required=True)
    reconcile.add_argument("--complete-schema-count", type=int, required=True)
    reconcile.add_argument("--complete-schema-sha256", required=True)
    attempt = subparsers.add_parser(
        "record-platform-publication-attempt",
        help="Persist one immutable external platform publication attempt outcome.",
    )
    attempt.add_argument("--request-id", required=True)
    attempt.add_argument("--attempt-id", required=True)
    attempt.add_argument(
        "--outcome", choices=sorted(PLATFORM_PUBLICATION_ATTEMPT_OUTCOMES), required=True
    )
    attempt.add_argument("--reference", required=True)
    probe = subparsers.add_parser(
        "probe-runtime",
        help="Read one fixed loopback runtime and emit bounded green readiness evidence.",
    )
    probe.add_argument("--runtime-root", type=Path, required=True)
    probe.add_argument("--mcp-url", required=True)
    probe.add_argument(
        "--connector-token-file",
        type=Path,
        default=AUTO_REFRESH_CONNECTOR_TOKEN_PATH,
    )
    probe.add_argument("--auth-mode", choices=("connector", "ingress"), required=True)
    probe.add_argument("--expected-release-id", required=True)
    probe.add_argument("--expected-repo-head", required=True)
    probe.add_argument("--expected-agent-instructions-sha256", required=True)
    probe.add_argument("--timeout-seconds", type=float, default=AUTO_REFRESH_TIMEOUT_SECONDS)
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
                observation_scope=args.observation_scope,
                observation_id=args.observation_id,
                publication_request_id=args.publication_request_id,
                requested_contract_sha256=args.requested_contract_sha256,
            )
        elif args.command == "reconcile-platform-publication":
            if os.geteuid() == 0:
                raise ClientSnapshotError(
                    "platform publication reconciliation must run as the runtime user, not root"
                )
            result = reconcile_platform_publication_for_runtime(
                registered_tool_count=args.registered_tool_count,
                registered_names_sha256=args.registered_names_sha256,
                complete_schema_count=args.complete_schema_count,
                complete_schema_sha256=args.complete_schema_sha256,
            )
        elif args.command == "record-platform-publication-attempt":
            if os.geteuid() == 0:
                raise ClientSnapshotError(
                    "platform publication attempt recording must run as the runtime user, not root"
                )
            result = record_platform_publication_attempt(
                request_id=args.request_id,
                attempt_id=args.attempt_id,
                outcome=args.outcome,
                reference=args.reference,
            )
        elif args.command == "probe-runtime":
            result = probe_runtime_readiness(
                runtime_root=args.runtime_root,
                mcp_url=args.mcp_url,
                connector_token_path=args.connector_token_file,
                auth_mode=args.auth_mode,
                expected_release_id=args.expected_release_id,
                expected_repo_head=args.expected_repo_head,
                expected_agent_instructions_sha256=(
                    args.expected_agent_instructions_sha256
                ),
                timeout_seconds=args.timeout_seconds,
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

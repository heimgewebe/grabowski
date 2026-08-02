from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any


CONTRACT_SCHEMA_VERSION = 1
CONTRACT_KIND = "grabowski_runtime_deploy_observer_contract"
ACTIVATION_SCHEMA_VERSION = 1
ACTIVATION_KIND = "grabowski_runtime_deploy_observer_activation"
OPERATION = "grabowski_job_status"
CAPABILITY_LIFETIME_SECONDS = 3_600
MAX_FILE_BYTES = 4_096
ACTIVATION_FILENAME = "deployment-observer-binding.json"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
HEAD_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
UNIT_RE = re.compile(r"grabowski-job-[0-9a-f]{12}\Z")
CAPABILITY_RE = re.compile(r"[0-9a-f]{64}\Z")
CONTRACT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "unit",
        "operation",
        "capability_sha256",
        "client_id_sha256",
        "expected_head",
        "source_identity_sha256",
        "argv_sha256",
        "origin_sha256",
        "issued_at_unix",
        "expires_at_unix",
        "contract_sha256",
    }
)
ACTIVATION_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "unit",
        "operation",
        "contract_sha256",
        "marker_token_sha256",
        "expected_head",
        "source_identity_sha256",
        "created_at_unix",
        "expires_at_unix",
        "binding_sha256",
    }
)
MARKER_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "token",
        "expected_head",
        "source_identity_sha256",
        "created_at_unix",
        "expires_at_unix",
    }
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def issue_capability() -> str:
    return secrets.token_hex(32)


def _client_id_sha256(client_id: str | None) -> str | None:
    if client_id is None:
        return None
    if not isinstance(client_id, str) or not client_id.strip():
        raise ValueError("deployment observer client_id must be non-empty when present")
    return hashlib.sha256(client_id.encode("utf-8")).hexdigest()


def _argv_option(argv: Any, option: str) -> str | None:
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return None
    positions = [index for index, item in enumerate(argv) if item == option]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        return None
    return argv[positions[0] + 1]


def build_contract(
    *,
    unit: str,
    capability: str,
    client_id: str | None,
    expected_head: str,
    source_identity_sha256: str,
    argv_sha256: str,
    origin_sha256: str,
    issued_at_unix: int | None = None,
) -> dict[str, Any]:
    if UNIT_RE.fullmatch(unit) is None:
        raise ValueError("deployment observer unit is invalid")
    if CAPABILITY_RE.fullmatch(capability) is None:
        raise ValueError("deployment observer capability is invalid")
    if HEAD_RE.fullmatch(expected_head) is None:
        raise ValueError("deployment observer expected_head is invalid")
    for label, value in (
        ("source_identity_sha256", source_identity_sha256),
        ("argv_sha256", argv_sha256),
        ("origin_sha256", origin_sha256),
    ):
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"deployment observer {label} is invalid")
    issued = int(time.time()) if issued_at_unix is None else int(issued_at_unix)
    material: dict[str, Any] = {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "kind": CONTRACT_KIND,
        "unit": unit,
        "operation": OPERATION,
        "capability_sha256": hashlib.sha256(capability.encode("ascii")).hexdigest(),
        "client_id_sha256": _client_id_sha256(client_id),
        "expected_head": expected_head,
        "source_identity_sha256": source_identity_sha256,
        "argv_sha256": argv_sha256,
        "origin_sha256": origin_sha256,
        "issued_at_unix": issued,
        "expires_at_unix": issued + CAPABILITY_LIFETIME_SECONDS,
    }
    return {**material, "contract_sha256": sha256_json(material)}


def validate_contract(
    value: Any,
    *,
    metadata: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CONTRACT_KEYS:
        raise ValueError("deployment observer contract shape is invalid")
    if value.get("schema_version") != CONTRACT_SCHEMA_VERSION:
        raise ValueError("deployment observer contract schema is invalid")
    if value.get("kind") != CONTRACT_KIND or value.get("operation") != OPERATION:
        raise ValueError("deployment observer contract kind is invalid")
    unit = value.get("unit")
    if not isinstance(unit, str) or UNIT_RE.fullmatch(unit) is None:
        raise ValueError("deployment observer contract unit is invalid")
    if metadata.get("unit") != unit:
        raise ValueError("deployment observer contract unit drifted")
    for key in (
        "capability_sha256",
        "source_identity_sha256",
        "argv_sha256",
        "origin_sha256",
        "contract_sha256",
    ):
        field = value.get(key)
        if not isinstance(field, str) or SHA256_RE.fullmatch(field) is None:
            raise ValueError(f"deployment observer contract {key} is invalid")
    client_digest = value.get("client_id_sha256")
    if client_digest is not None and (
        not isinstance(client_digest, str) or SHA256_RE.fullmatch(client_digest) is None
    ):
        raise ValueError("deployment observer client binding is invalid")
    expected_head = value.get("expected_head")
    if not isinstance(expected_head, str) or HEAD_RE.fullmatch(expected_head) is None:
        raise ValueError("deployment observer expected_head is invalid")
    issued = value.get("issued_at_unix")
    expires = value.get("expires_at_unix")
    if type(issued) is not int or type(expires) is not int:
        raise ValueError("deployment observer lifetime is invalid")
    if expires - issued != CAPABILITY_LIFETIME_SECONDS:
        raise ValueError("deployment observer lifetime is not canonical")
    current = int(time.time()) if now_unix is None else int(now_unix)
    if issued > current + 5 or expires < current:
        raise ValueError("deployment observer contract is not current")
    material = {key: value[key] for key in value if key != "contract_sha256"}
    if value["contract_sha256"] != sha256_json(material):
        raise ValueError("deployment observer contract digest mismatch")
    if metadata.get("argv_sha256") != value["argv_sha256"]:
        raise ValueError("deployment observer argv binding drifted")
    if metadata.get("origin_sha256") != value["origin_sha256"]:
        raise ValueError("deployment observer origin binding drifted")
    finalization = metadata.get("finalization_contract")
    if not isinstance(finalization, dict):
        raise ValueError("deployment observer finalization contract is missing")
    if finalization.get("unit") != unit or finalization.get("expected_head") != expected_head:
        raise ValueError("deployment observer finalization binding drifted")
    if finalization.get("argv_sha256") != value["argv_sha256"]:
        raise ValueError("deployment observer finalization argv drifted")
    if _argv_option(metadata.get("argv"), "--expected-head") != expected_head:
        raise ValueError("deployment observer expected-head argv drifted")
    if (
        _argv_option(metadata.get("argv"), "--source-identity-sha256")
        != value["source_identity_sha256"]
    ):
        raise ValueError("deployment observer source argv drifted")
    return value


def authorize_request(
    value: Any,
    *,
    metadata: dict[str, Any],
    capability: str,
    client_id: str | None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    contract = validate_contract(value, metadata=metadata, now_unix=now_unix)
    if not isinstance(capability, str) or CAPABILITY_RE.fullmatch(capability) is None:
        raise ValueError("deployment observer capability is invalid")
    observed_capability = hashlib.sha256(capability.encode("ascii")).hexdigest()
    if not hmac.compare_digest(observed_capability, contract["capability_sha256"]):
        raise ValueError("deployment observer capability does not match")
    expected_client = contract["client_id_sha256"]
    observed_client = _client_id_sha256(client_id)
    if expected_client is not None and not hmac.compare_digest(
        expected_client,
        observed_client or "",
    ):
        raise ValueError("deployment observer client binding does not match")
    return {
        "schema_version": 1,
        "kind": "grabowski_runtime_deploy_observer_evidence",
        "unit": contract["unit"],
        "operation": OPERATION,
        "expected_head": contract["expected_head"],
        "source_identity_sha256": contract["source_identity_sha256"],
        "contract_sha256": contract["contract_sha256"],
        "client_id_bound": expected_client is not None,
        "expires_at_unix": contract["expires_at_unix"],
    }


def build_activation_binding(
    contract_value: Any,
    *,
    metadata: dict[str, Any],
    marker: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now_unix is None else int(now_unix)
    contract = validate_contract(contract_value, metadata=metadata, now_unix=current)
    if not isinstance(marker, dict) or set(marker) != MARKER_KEYS:
        raise ValueError("deployment admission marker shape is invalid")
    token = marker.get("token")
    if (
        marker.get("schema_version") != 1
        or marker.get("kind") != "grabowski_deployment_admission_drain"
        or not isinstance(token, str)
        or SHA256_RE.fullmatch(token) is None
        or marker.get("expected_head") != contract["expected_head"]
        or marker.get("source_identity_sha256")
        != contract["source_identity_sha256"]
    ):
        raise ValueError("deployment admission marker does not match observer contract")
    marker_expires = marker.get("expires_at_unix")
    if type(marker_expires) is not int or marker_expires <= current:
        raise ValueError("deployment admission marker is not current")
    material = {
        "schema_version": ACTIVATION_SCHEMA_VERSION,
        "kind": ACTIVATION_KIND,
        "unit": contract["unit"],
        "operation": OPERATION,
        "contract_sha256": contract["contract_sha256"],
        "marker_token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "expected_head": contract["expected_head"],
        "source_identity_sha256": contract["source_identity_sha256"],
        "created_at_unix": current,
        "expires_at_unix": min(marker_expires, contract["expires_at_unix"]),
    }
    if material["expires_at_unix"] <= current:
        raise ValueError("deployment observer activation has no valid lifetime")
    return {**material, "binding_sha256": sha256_json(material)}


def validate_activation_binding(
    value: Any,
    *,
    contract_value: Any,
    metadata: dict[str, Any],
    marker: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now_unix is None else int(now_unix)
    contract = validate_contract(contract_value, metadata=metadata, now_unix=current)
    if not isinstance(value, dict) or set(value) != ACTIVATION_KEYS:
        raise ValueError("deployment observer activation shape is invalid")
    if (
        value.get("schema_version") != ACTIVATION_SCHEMA_VERSION
        or value.get("kind") != ACTIVATION_KIND
        or value.get("unit") != contract["unit"]
        or value.get("operation") != OPERATION
        or value.get("contract_sha256") != contract["contract_sha256"]
        or value.get("expected_head") != contract["expected_head"]
        or value.get("source_identity_sha256")
        != contract["source_identity_sha256"]
    ):
        raise ValueError("deployment observer activation binding drifted")
    created = value.get("created_at_unix")
    expires = value.get("expires_at_unix")
    if type(created) is not int or type(expires) is not int or created > current + 5 or expires < current:
        raise ValueError("deployment observer activation is not current")
    material = {key: value[key] for key in value if key != "binding_sha256"}
    if value.get("binding_sha256") != sha256_json(material):
        raise ValueError("deployment observer activation digest mismatch")
    expected = build_activation_binding(
        contract,
        metadata=metadata,
        marker=marker,
        now_unix=created,
    )
    for key in (
        "unit",
        "operation",
        "contract_sha256",
        "marker_token_sha256",
        "expected_head",
        "source_identity_sha256",
        "expires_at_unix",
    ):
        if value.get(key) != expected.get(key):
            raise ValueError(f"deployment observer activation {key} drifted")
    return value


def activation_path(job_directory: Path) -> Path:
    return job_directory / ACTIVATION_FILENAME


def read_activation(path: Path) -> dict[str, Any] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_FILE_BYTES
        ):
            raise PermissionError("deployment observer activation file is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("deployment observer activation file is too large")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("deployment observer activation file is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("deployment observer activation file is invalid")
    return value


def create_activation(path: Path, value: dict[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("deployment observer activation payload is too large")
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(path.parent, parent_flags)
    descriptor = -1
    try:
        parent_linked = path.parent.lstat()
        parent_opened = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_opened.st_mode)
            or stat.S_ISLNK(parent_linked.st_mode)
            or parent_opened.st_uid != os.getuid()
            or parent_opened.st_nlink < 1
            or (stat.S_IMODE(parent_opened.st_mode) & 0o077) != 0
            or (parent_linked.st_dev, parent_linked.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
        ):
            raise PermissionError("deployment observer activation parent is unsafe")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("deployment observer activation write was incomplete")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise PermissionError("deployment observer activation binding drifted")
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)

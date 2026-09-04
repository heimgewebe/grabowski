#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any, Iterable


SCHEMA_VERSION = 1
ENFORCEMENT_MARKER_NAME = "require-tool-policy"
ENFORCEMENT_MARKER_PAYLOAD = b"required-v1"
POLICY_SUFFIX = ".tools.json"
MAX_POLICY_BYTES = 64 * 1024
MAX_TOOL_NAME_BYTES = 256
MAX_ALLOWED_TOOLS = 512


class ConnectorPolicyError(RuntimeError):
    pass


def _validate_private_root(root: Path) -> Path:
    try:
        linked = os.lstat(root)
    except FileNotFoundError as exc:
        raise ConnectorPolicyError("connector identity root is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
    ):
        raise ConnectorPolicyError(
            "connector identity root must be private and owner-controlled"
        )
    resolved = root.resolve(strict=True)
    if resolved != root:
        raise ConnectorPolicyError("connector identity root must be an exact real path")
    return resolved


def _read_private_file(path: Path, *, maximum_bytes: int) -> bytes:
    _validate_private_root(path.parent)
    try:
        linked = os.lstat(path)
    except FileNotFoundError:
        raise
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
        or linked.st_nlink != 1
        or linked.st_size > maximum_bytes
    ):
        raise ConnectorPolicyError(
            f"connector policy file is unsafe: {path.name}"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
            or opened.st_uid != linked.st_uid
            or opened.st_gid != linked.st_gid
            or opened.st_nlink != linked.st_nlink
        ):
            raise ConnectorPolicyError(
                f"connector policy changed while opening: {path.name}"
            )
        payload = os.read(descriptor, maximum_bytes + 1)
        if len(payload) > maximum_bytes or os.read(descriptor, 1):
            raise ConnectorPolicyError(
                f"connector policy exceeds size bound: {path.name}"
            )
        return payload
    finally:
        os.close(descriptor)


def enforcement_required(root: Path) -> bool:
    try:
        payload = _read_private_file(
            root / ENFORCEMENT_MARKER_NAME,
            maximum_bytes=64,
        )
    except FileNotFoundError:
        return False
    if payload != ENFORCEMENT_MARKER_PAYLOAD:
        raise ConnectorPolicyError("connector tool-policy enforcement marker is invalid")
    return True


def _validate_tool_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value.encode("utf-8")) > MAX_TOOL_NAME_BYTES
        or any(character in value for character in ("\x00", "\r", "\n"))
    ):
        raise ConnectorPolicyError("connector policy contains an invalid tool name")
    return value


def _normalize_registered_tools(registered_tools: Iterable[str] | None) -> set[str] | None:
    if registered_tools is None:
        return None
    return {_validate_tool_name(item) for item in registered_tools}


def load_policy(
    root: Path,
    connector_id: str,
    *,
    registered_tools: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Load one principal policy when the global fail-closed marker is active.

    Before migration is activated, callers retain legacy behavior. Once the
    marker exists, every enrolled connector must have an explicit policy file;
    absence or malformed content fails closed.
    """

    if not isinstance(connector_id, str) or not connector_id:
        raise ConnectorPolicyError("connector id is invalid")
    if not enforcement_required(root):
        return {
            "schema_version": SCHEMA_VERSION,
            "connector_id": connector_id,
            "mode": "legacy-unrestricted",
            "allowed_tools": None,
            "read_only_only": False,
            "enforced": False,
        }

    path = root / f"{connector_id}{POLICY_SUFFIX}"
    try:
        payload = _read_private_file(path, maximum_bytes=MAX_POLICY_BYTES)
    except FileNotFoundError as exc:
        raise ConnectorPolicyError(
            f"connector tool policy is required but missing: {connector_id}"
        ) from exc
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorPolicyError("connector tool policy is invalid JSON") from exc
    required_keys = {"schema_version", "connector_id", "mode", "allowed_tools", "read_only_only"}
    if not isinstance(value, dict) or set(value) != required_keys:
        raise ConnectorPolicyError("connector tool policy shape is invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ConnectorPolicyError("connector tool policy schema is unsupported")
    if value.get("connector_id") != connector_id:
        raise ConnectorPolicyError("connector tool policy identity mismatch")
    mode = value.get("mode")
    read_only_only = value.get("read_only_only")
    if not isinstance(read_only_only, bool):
        raise ConnectorPolicyError("connector read-only policy flag is invalid")
    if mode not in {"unrestricted", "allowlist"}:
        raise ConnectorPolicyError("connector tool policy mode is invalid")
    allowed_raw = value.get("allowed_tools")
    if not isinstance(allowed_raw, list) or len(allowed_raw) > MAX_ALLOWED_TOOLS:
        raise ConnectorPolicyError("connector tool allowlist is invalid")
    allowed = [_validate_tool_name(item) for item in allowed_raw]
    if len(allowed) != len(set(allowed)):
        raise ConnectorPolicyError("connector tool allowlist contains duplicates")
    if mode == "unrestricted" and allowed:
        raise ConnectorPolicyError(
            "unrestricted connector policy must not carry an allowlist"
        )
    if mode == "allowlist" and not allowed:
        raise ConnectorPolicyError("connector tool allowlist must not be empty")
    registered = _normalize_registered_tools(registered_tools)
    if registered is not None:
        unknown = sorted(set(allowed) - registered)
        if unknown:
            raise ConnectorPolicyError(
                "connector tool policy references unknown tools: " + ", ".join(unknown)
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "connector_id": connector_id,
        "mode": mode,
        "allowed_tools": allowed,
        "read_only_only": read_only_only,
        "enforced": True,
    }


def tool_allowed(policy: dict[str, Any], tool_name: str) -> bool:
    name = _validate_tool_name(tool_name)
    mode = policy.get("mode")
    if mode in {"legacy-unrestricted", "unrestricted"}:
        return True
    if mode != "allowlist":
        raise ConnectorPolicyError("connector tool policy mode is invalid")
    allowed = policy.get("allowed_tools")
    if not isinstance(allowed, list):
        raise ConnectorPolicyError("connector tool allowlist is invalid")
    return name in allowed

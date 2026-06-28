#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import signal
import stat as statmod
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

APP_NAME = "Grabowski"
HOME = Path.home().resolve()
STATE_DIR = HOME / ".local" / "state" / "grabowski"
POLICY_PATH = HOME / ".config" / "grabowski" / "access.json"
AUDIT_LOG = STATE_DIR / "write-audit.jsonl"
QUARANTINE_DIR = STATE_DIR / "quarantine"
KILL_SWITCH_PATH = STATE_DIR / "operator-kill-switch"
BUNDLE_REGISTRY = STATE_DIR / "rlens-latest-complete-bundles.tsv"
AUDIT_SCHEMA_VERSION = 2
MAX_AUDIT_BYTES = 16 * 1024 * 1024
AUDIT_APPEND_LOCK = threading.RLock()
BASE_CAPABILITIES = (
    "file_read",
    "file_write",
    "audit_verify",
    "rollback_text",
    "bundle_registry",
)
SECRET_CAPABILITIES = (
    "secret_inspect",
    "secret_reveal",
    "secret_use",
    "secret_export",
    "browser_profile_read",
)
OPERATOR_CAPABILITIES = (
    "terminal_execute",
    "durable_job",
    "git_cli",
    "github_cli",
    "user_service_control",
    "tmux_interaction",
    "process_inspect",
    "process_signal",
    "port_inspect",
    "privileged_reference",
    "resource_lease",
    "artifact_transfer",
    "browser_worker",
    "gui_worker",
)
RESERVED_DISABLED_CAPABILITIES = (
    "file_delete",
    "file_destroy",
    "file_move",
    "chmod",
    "chown",
    "secret_read",
)
ALL_CAPABILITIES = (
    BASE_CAPABILITIES
    + SECRET_CAPABILITIES
    + OPERATOR_CAPABILITIES
    + RESERVED_DISABLED_CAPABILITIES
)
DEFAULT_SECRET_USE_TIMEOUT_SECONDS = 30
DEFAULT_SECRET_USE_OUTPUT_BYTES = 250_000
SECRET_FD_PLACEHOLDER = "{SECRET_FD_PATH}"
SHELL_EXECUTABLES = {"sh", "bash", "dash", "zsh", "ksh", "fish"}
SECRET_USE_ENV_ALLOWLIST = {
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "TERM",
    "TZ",
}
SENSITIVE_ENV_PARTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "COOKIE",
    "CREDENTIAL",
    "AUTHORIZATION",
    "API_KEY",
    "APIKEY",
)
TOP_LEVEL_POLICY_FIELDS = {
    "version",
    "mode",
    "active_profile",
    "read_roots",
    "write_roots",
    "write_excluded_roots",
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
    "max_read_bytes",
    "max_write_bytes",
    "max_list_entries",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
    "forbid_symlinks",
    "forbidden_components",
    "forbidden_file_patterns",
    "forbidden_capabilities",
    "capability_definitions",
    "profiles",
    "trusted_owner",
}
PROFILE_POLICY_FIELDS = {
    "description",
    "read_roots",
    "write_roots",
    "write_excluded_roots",
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
    "max_read_bytes",
    "max_write_bytes",
    "max_list_entries",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
    "capabilities",
    "trusted_owner",
}
ROOT_LIST_FIELDS = {
    "read_roots",
    "write_roots",
    "write_excluded_roots",
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
}
V2_ONLY_POLICY_FIELDS = {
    "secret_roots",
    "browser_profile_roots",
    "secret_export_roots",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
}
LIMIT_FIELDS = {
    "max_read_bytes",
    "max_write_bytes",
    "max_list_entries",
    "max_secret_use_output_bytes",
    "max_secret_use_seconds",
}
SECRET_REDACTIONS = (
    (
        re.compile(r"sk-[A-Za-z0-9._-]{16,}"),
        "<REDACTED_OPENAI_KEY>",
    ),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.I),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.S,
        ),
        "<REDACTED_PRIVATE_KEY>",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "<REDACTED_AWS_ACCESS_KEY_ID>",
    ),
    (
        re.compile(
            r"(?im)^(\s*[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|"
            r"PRIVATE_KEY|CLIENT_KEY_DATA|AWS_ACCESS_KEY_ID|"
            r"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)"
            r"[A-Z0-9_]*\s*[:=]\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
    (
        re.compile(
            r"(?im)^(\s*(?:token|password|client-key-data|client-certificate-data|"
            r"aws_access_key_id|aws_secret_access_key|aws_session_token)"
            r"\s*[:=]\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
)

def _deployment_manifest_path() -> Path:
    executable = Path(sys.executable)
    if executable.parent.name == "bin" and executable.parent.parent.name == ".venv":
        return executable.parent.parent.parent / "deployment-manifest.json"
    return Path(__file__).resolve().parent / "deployment-manifest.json"


DEPLOYMENT_MANIFEST = _deployment_manifest_path()
EXPECTED_STABLE_RUNTIME = HOME / ".local" / "share" / "grabowski-mcp"
DEPLOYMENT_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONTRACT_BYTES = 64 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

mcp = FastMCP(APP_NAME)

READ_ANNOTATIONS = ToolAnnotations(
    title="Read local data",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
SECRET_REVEAL_ANNOTATIONS = ToolAnnotations(
    title="Reveal secret content",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
CREATE_ANNOTATIONS = ToolAnnotations(
    title="Create local text file",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=False,
)
REPLACE_ANNOTATIONS = ToolAnnotations(
    title="Replace local text file",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)
REMOVE_ANNOTATIONS = ToolAnnotations(
    title="Remove local filesystem entry",
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=False,
)


def _load_policy() -> dict[str, Any]:
    try:
        raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Access policy missing: {POLICY_PATH}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Access policy is invalid JSON: {exc}") from exc

    _validate_policy(raw)
    return raw


def _validate_string_list(
    value: Any,
    *,
    label: str,
    unique: bool = True,
) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError(f"Access policy {label} must be a list of strings")
    if any(not item for item in value):
        raise RuntimeError(f"Access policy {label} contains an empty string")
    if unique and len(value) != len(set(value)):
        raise RuntimeError(f"Access policy {label} contains duplicates")
    return value


def _validate_root_values(value: Any, *, label: str) -> None:
    roots = _validate_string_list(value, label=label)
    for root in roots:
        path = _policy_path(root)
        if not path.is_absolute():
            raise RuntimeError(
                f"Access policy {label} root must be absolute after expansion: {root}"
            )


def _validate_limit_value(value: Any, *, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError(f"Invalid access policy limit: {label}")


def _validate_capability_list(value: Any, *, label: str) -> None:
    capabilities = _validate_string_list(value, label=label)
    unknown = sorted(set(capabilities) - set(ALL_CAPABILITIES))
    if unknown:
        raise RuntimeError(f"Unknown access capabilities in {label}: {unknown}")


def _validate_policy(policy: Any) -> None:
    if not isinstance(policy, dict):
        raise RuntimeError("Access policy must be an object")

    unknown = sorted(set(policy) - TOP_LEVEL_POLICY_FIELDS)
    if unknown:
        raise RuntimeError(f"Unknown access policy fields: {unknown}")

    version = policy.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version not in {1, 2}:
        raise RuntimeError("Access policy version must be 1 or 2")
    if version == 1 and V2_ONLY_POLICY_FIELDS & set(policy):
        raise RuntimeError("Typed secret/browser policy fields require version 2")

    required = {"read_roots", "write_roots", "max_read_bytes", "max_write_bytes"}
    if version == 2:
        required.update(
            {
                "write_excluded_roots",
                "secret_roots",
                "browser_profile_roots",
                "secret_export_roots",
                "max_list_entries",
                "forbid_symlinks",
                "forbidden_components",
                "forbidden_file_patterns",
                "forbidden_capabilities",
            }
        )
    missing = sorted(required.difference(policy))
    if missing:
        raise RuntimeError(f"Access policy missing keys: {missing}")

    if "mode" in policy and not isinstance(policy["mode"], str):
        raise RuntimeError("Access policy mode must be a string")
    if "active_profile" in policy and not isinstance(policy["active_profile"], str):
        raise RuntimeError("Access policy active_profile must be a string")
    if "trusted_owner" in policy and not isinstance(policy["trusted_owner"], bool):
        raise RuntimeError("Access policy trusted_owner must be a boolean")

    for key in ROOT_LIST_FIELDS:
        if key in policy:
            _validate_root_values(policy[key], label=key)

    for key in LIMIT_FIELDS:
        if key in policy:
            _validate_limit_value(policy[key], label=key)

    if "forbid_symlinks" in policy and not isinstance(policy["forbid_symlinks"], bool):
        raise RuntimeError("Access policy forbid_symlinks must be a boolean")

    for key in ("forbidden_components", "forbidden_file_patterns"):
        if key in policy:
            _validate_string_list(policy[key], label=key)

    if "forbidden_capabilities" in policy:
        _validate_capability_list(
            policy["forbidden_capabilities"],
            label="forbidden_capabilities",
        )

    definitions = policy.get("capability_definitions", {})
    if definitions is not None:
        if not isinstance(definitions, dict):
            raise RuntimeError("Access policy capability_definitions must be an object")
        unknown_definitions = sorted(set(definitions) - set(ALL_CAPABILITIES))
        if unknown_definitions:
            raise RuntimeError(
                f"Unknown capability definitions: {unknown_definitions}"
            )
        if not all(isinstance(value, str) and value for value in definitions.values()):
            raise RuntimeError("Capability definitions must be non-empty strings")

    profiles = policy.get("profiles")
    if profiles is None:
        return
    if not isinstance(profiles, dict) or not profiles:
        raise RuntimeError("Access policy profiles must be a non-empty object")
    active = policy.get("active_profile", policy.get("mode"))
    if not isinstance(active, str) or active not in profiles:
        raise RuntimeError(f"Active access profile is not defined: {active!r}")

    for name, profile in profiles.items():
        if not isinstance(name, str) or not name:
            raise RuntimeError("Access profile names must be non-empty strings")
        if not isinstance(profile, dict):
            raise RuntimeError(f"Access profile is not an object: {name}")
        unknown_profile = sorted(set(profile) - PROFILE_POLICY_FIELDS)
        if unknown_profile:
            raise RuntimeError(
                f"Unknown access profile fields in {name}: {unknown_profile}"
            )
        if version == 1 and V2_ONLY_POLICY_FIELDS & set(profile):
            raise RuntimeError(
                f"Typed secret/browser profile fields require version 2: {name}"
            )
        if version == 2:
            profile_required = {
                "description",
                "read_roots",
                "write_roots",
                "write_excluded_roots",
                "secret_roots",
                "browser_profile_roots",
                "secret_export_roots",
                "capabilities",
            }
            missing_profile = sorted(profile_required.difference(profile))
            if missing_profile:
                raise RuntimeError(
                    f"Access profile {name} missing fields: {missing_profile}"
                )
        if "description" in profile and not isinstance(profile["description"], str):
            raise RuntimeError(f"Access profile {name} description must be a string")
        if "trusted_owner" in profile and not isinstance(profile["trusted_owner"], bool):
            raise RuntimeError(f"Access profile {name} trusted_owner must be a boolean")
        for key in ROOT_LIST_FIELDS:
            if key in profile:
                _validate_root_values(profile[key], label=f"profile {name} {key}")
        for key in LIMIT_FIELDS:
            if key in profile:
                _validate_limit_value(profile[key], label=f"profile {name} {key}")
        if "capabilities" in profile:
            _validate_capability_list(
                profile["capabilities"],
                label=f"profile {name} capabilities",
            )
            capabilities = set(profile["capabilities"])
            if capabilities & {"secret_inspect", "secret_reveal", "secret_use", "secret_export"}:
                if not _profile_root_values(policy, profile, "secret_roots"):
                    raise RuntimeError(
                        f"Access profile {name} enables secret capabilities "
                        "without secret_roots"
                    )
            if "secret_export" in capabilities and not _profile_root_values(
                policy,
                profile,
                "secret_export_roots",
            ):
                raise RuntimeError(
                    f"Access profile {name} enables secret_export without "
                    "secret_export_roots"
                )
            if "browser_profile_read" in capabilities and not _profile_root_values(
                policy,
                profile,
                "browser_profile_roots",
            ):
                raise RuntimeError(
                    f"Access profile {name} enables browser_profile_read without "
                    "browser_profile_roots"
                )


def _profile_root_values(
    policy: dict[str, Any],
    profile: dict[str, Any],
    key: str,
) -> list[str]:
    value = profile.get(key, policy.get(key, []))
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _legacy_profile(policy: dict[str, Any]) -> dict[str, Any]:
    forbidden = set(policy.get("forbidden_capabilities", []))
    return {
        "name": policy.get("mode", "bounded-read-write"),
        "read_roots": policy.get("read_roots", []),
        "write_roots": policy.get("write_roots", []),
        "write_excluded_roots": policy.get("write_excluded_roots", []),
        "secret_roots": policy.get("secret_roots", []),
        "browser_profile_roots": policy.get("browser_profile_roots", []),
        "secret_export_roots": policy.get("secret_export_roots", []),
        "max_read_bytes": policy.get("max_read_bytes"),
        "max_write_bytes": policy.get("max_write_bytes"),
        "max_list_entries": policy.get("max_list_entries"),
        "max_secret_use_output_bytes": policy.get(
            "max_secret_use_output_bytes",
            DEFAULT_SECRET_USE_OUTPUT_BYTES,
        ),
        "max_secret_use_seconds": policy.get(
            "max_secret_use_seconds",
            DEFAULT_SECRET_USE_TIMEOUT_SECONDS,
        ),
        "capabilities": [
            capability
            for capability in BASE_CAPABILITIES
            if capability not in forbidden
        ],
        "trusted_owner": bool(policy.get("trusted_owner", False)),
    }


def _active_profile(policy: dict[str, Any]) -> dict[str, Any]:
    profiles = policy.get("profiles")
    if not isinstance(profiles, dict):
        return _legacy_profile(policy)

    active = policy.get("active_profile", policy.get("mode"))
    if not isinstance(active, str) or active not in profiles:
        raise RuntimeError(f"Active access profile is not defined: {active!r}")
    profile = profiles[active]
    if not isinstance(profile, dict):
        raise RuntimeError(f"Access profile is not an object: {active}")
    return {"name": active, **profile}


def _trusted_owner_enabled(policy: dict[str, Any] | None = None) -> bool:
    source = _load_policy() if policy is None else policy
    profile = _active_profile(source)
    return bool(profile.get("trusted_owner", source.get("trusted_owner", False)))


def _profile_values(policy: dict[str, Any], key: str) -> Any:
    profile = _active_profile(policy)
    if key in profile:
        return profile[key]
    return policy.get(key)


def _policy_limit(policy: dict[str, Any], key: str) -> int:
    value = _profile_values(policy, key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError(f"Invalid access policy limit: {key}")
    return value


def _effective_capabilities(policy: dict[str, Any]) -> set[str]:
    profile = _active_profile(policy)
    capabilities = profile.get("capabilities")
    if not isinstance(capabilities, list):
        capabilities = _legacy_profile(policy)["capabilities"]
    forbidden = set(policy.get("forbidden_capabilities", []))
    return {
        capability
        for capability in capabilities
        if isinstance(capability, str) and capability not in forbidden
    }


def _root_values(policy: dict[str, Any], key: str) -> list[str]:
    values = _profile_values(policy, key) or []
    if not isinstance(values, list):
        raise RuntimeError(f"Access policy {key} must be a list")
    return [value for value in values if isinstance(value, str) and value]


def _configured_roots(key: str, policy: dict[str, Any] | None = None) -> list[Path]:
    source = _load_policy() if policy is None else policy
    return [
        _policy_path(value).resolve(strict=False)
        for value in _root_values(source, key)
    ]


def _secret_root_values(policy: dict[str, Any]) -> list[str]:
    return _root_values(policy, "secret_roots")


def _browser_profile_root_values(policy: dict[str, Any]) -> list[str]:
    return _root_values(policy, "browser_profile_roots")


def _secret_export_root_values(policy: dict[str, Any]) -> list[str]:
    return _root_values(policy, "secret_export_roots")


def _secret_roots(policy: dict[str, Any] | None = None) -> list[Path]:
    return _configured_roots("secret_roots", policy)


def _browser_profile_roots(policy: dict[str, Any] | None = None) -> list[Path]:
    return _configured_roots("browser_profile_roots", policy)


def _secret_export_roots(policy: dict[str, Any] | None = None) -> list[Path]:
    return _configured_roots("secret_export_roots", policy)


def _path_is_secret(path: Path, policy: dict[str, Any] | None = None) -> bool:
    return _is_within(path, _secret_roots(policy))


def _path_is_browser_profile(path: Path, policy: dict[str, Any] | None = None) -> bool:
    return _is_within(path, _browser_profile_roots(policy))


def _path_is_sensitive(path: Path, policy: dict[str, Any] | None = None) -> bool:
    return _path_is_secret(path, policy) or _path_is_browser_profile(path, policy)


def _require_capability(capability: str) -> None:
    policy = _load_policy()
    if capability not in _effective_capabilities(policy):
        raise PermissionError(f"Access capability is not enabled: {capability}")


def _kill_switch_state() -> dict[str, Any]:
    env_value = os.environ.get("GRABOWSKI_OPERATOR_KILL_SWITCH", "")
    env_engaged = env_value.lower() in {"1", "true", "yes", "on"}
    file_engaged = KILL_SWITCH_PATH.is_file()
    return {
        "engaged": env_engaged or file_engaged,
        "environment": env_engaged,
        "path": str(KILL_SWITCH_PATH),
        "path_exists": file_engaged,
    }


def _require_valid_audit_chain() -> None:
    audit = _verify_audit_log(AUDIT_LOG)
    if not audit["valid"]:
        raise RuntimeError(f"Audit log verification failed: {audit['error']}")


def _require_mutations_enabled(capability: str) -> None:
    _require_capability(capability)
    state = _kill_switch_state()
    if state["engaged"]:
        raise PermissionError(
            "Grabowski operator kill switch is engaged; mutating tools are disabled."
        )
    _require_valid_audit_chain()


def _policy_path(value: str) -> Path:
    if not isinstance(value, str) or not value:
        raise RuntimeError("Configured policy path must be a non-empty string")
    return Path(value.replace("${HOME}", str(HOME))).expanduser()


def _roots(kind: str, *, ignore_missing: bool = False) -> list[Path]:
    policy = _load_policy()
    values = _profile_values(policy, f"{kind}_roots")
    roots: list[Path] = []
    for value in values:
        configured = _policy_path(value)
        try:
            root = configured.resolve(strict=True)
        except FileNotFoundError:
            if ignore_missing:
                continue
            raise
        if not root.is_dir():
            raise RuntimeError(f"Configured {kind} root is not a directory: {root}")
        roots.append(root)
    return roots


def _is_within(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _excluded_roots(kind: str) -> list[Path]:
    policy = _load_policy()
    values = _profile_values(policy, f"{kind}_excluded_roots") or []
    roots: list[Path] = []

    for value in values:
        root = _policy_path(value).resolve(strict=True)
        if not root.is_dir():
            raise RuntimeError(
                f"Configured {kind} excluded root is not a directory: {root}"
            )
        roots.append(root)

    return roots


def _reject_sensitive(path: Path) -> None:
    policy = _load_policy()
    if _trusted_owner_enabled(policy):
        return
    forbidden_components = set(policy.get("forbidden_components", []))
    forbidden_patterns = list(policy.get("forbidden_file_patterns", []))

    for component in path.parts:
        if component in forbidden_components:
            raise PermissionError(f"Forbidden path component: {component}")

    name = path.name
    for pattern in forbidden_patterns:
        if fnmatch(name, pattern):
            raise PermissionError(f"Forbidden file pattern: {pattern}")


def _reject_symlink_components(path: Path, allow_missing_leaf: bool = False) -> None:
    policy = _load_policy()
    if not policy.get("forbid_symlinks", True):
        return

    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        is_leaf = index == len(parts) - 1
        if current.is_symlink():
            raise PermissionError(f"Symlink paths are forbidden: {current}")
        if not current.exists():
            if allow_missing_leaf and is_leaf:
                return
            raise FileNotFoundError(str(current))


def _absolute_candidate(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Path must be absolute")
    _reject_sensitive(candidate)
    return candidate


def _resolve_existing(raw_path: str, kind: str) -> Path:
    candidate = _absolute_candidate(raw_path)
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not _is_within(resolved, _roots(kind)):
        raise PermissionError(f"Path is outside configured {kind} roots: {resolved}")
    if _path_is_sensitive(resolved) and not _trusted_owner_enabled():
        raise PermissionError(
            "Path is inside configured secret/browser roots; use dedicated tools."
        )
    return resolved


def _resolve_write_target(raw_path: str) -> tuple[Path, bool]:
    candidate = _absolute_candidate(raw_path)
    if candidate.exists() or candidate.is_symlink():
        _reject_symlink_components(candidate)
        resolved = candidate.resolve(strict=True)
        exists = True
    else:
        _reject_symlink_components(candidate, allow_missing_leaf=True)
        parent = candidate.parent.resolve(strict=True)
        resolved = parent / candidate.name
        exists = False

    if not _is_within(resolved, _roots("write")):
        raise PermissionError(f"Path is outside configured write roots: {resolved}")

    trusted_owner = _trusted_owner_enabled()
    if _is_within(resolved, _excluded_roots("write")) and not trusted_owner:
        raise PermissionError(f"Path is explicitly read-only: {resolved}")

    if _path_is_sensitive(resolved) and not trusted_owner:
        raise PermissionError(
            "Path is inside configured secret/browser roots; use dedicated tools."
        )

    if _protected_generic_write_target(resolved) and not trusted_owner:
        raise PermissionError(f"Path is protected from generic mutation: {resolved}")

    return resolved, exists


def _validate_removal_type(expected_type: str) -> str:
    if expected_type not in {"file", "empty_directory"}:
        raise ValueError("expected_type must be 'file' or 'empty_directory'")
    return expected_type


def _removal_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
    )


def _verify_same_removal_target(target: Path, identity: tuple[int, int, int, int, int]) -> None:
    current = os.stat(target, follow_symlinks=False)
    if _removal_identity(current) != identity:
        raise RuntimeError("Removal target changed before mutation")


def _removal_snapshot(
    target: Path,
    expected_type: str,
    expected_sha256: str | None,
) -> dict[str, Any]:
    expected = _validate_removal_type(expected_type)
    info = os.stat(target, follow_symlinks=False)
    mode = info.st_mode
    if expected == "file":
        if not statmod.S_ISREG(mode):
            raise ValueError(f"Removal target is not a regular file: {target}")
        if expected_sha256 is None:
            raise ValueError("expected_sha256 is required for file removal")
        _validate_sha256(expected_sha256, "expected_sha256")
        policy = _load_policy()
        snapshot = _read_bound_regular_bytes(
            target,
            _policy_limit(policy, "max_read_bytes"),
        )
        if snapshot["sha256"] != expected_sha256:
            raise RuntimeError(
                "SHA-256 precondition failed: "
                f"expected {expected_sha256}, current {snapshot['sha256']}"
            )
        return {
            "type": "file",
            "sha256": snapshot["sha256"],
            "bytes": snapshot["size"],
            "mode": statmod.S_IMODE(info.st_mode),
            "identity": _removal_identity(info),
        }

    if not statmod.S_ISDIR(mode):
        raise ValueError(f"Removal target is not a directory: {target}")
    if expected_sha256 is not None:
        raise ValueError("expected_sha256 must be omitted for empty_directory removal")
    if any(target.iterdir()):
        raise ValueError(f"Directory is not empty: {target}")
    return {
        "type": "empty_directory",
        "sha256": None,
        "bytes": 0,
        "mode": statmod.S_IMODE(info.st_mode),
        "identity": _removal_identity(info),
    }


def _new_holding_path(target: Path) -> Path:
    for _attempt in range(20):
        candidate = (
            target.parent
            / f".{target.name}.grabowski-remove-{uuid.uuid4().hex[:12]}"
        )
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise RuntimeError(f"Could not allocate removal holding path for {target}")


def _move_to_holding(target: Path, snapshot: dict[str, Any]) -> Path:
    holding = _new_holding_path(target)
    os.replace(target, holding)
    _fsync_directory(target.parent)
    try:
        _verify_same_removal_target(holding, snapshot["identity"])
        if snapshot["type"] == "file":
            if _sha256(holding) != snapshot["sha256"]:
                raise RuntimeError("Removal target hash changed before mutation")
        elif any(holding.iterdir()):
            raise RuntimeError("Directory changed before removal")
    except Exception:
        try:
            if not target.exists() and not target.is_symlink():
                os.replace(holding, target)
                _fsync_directory(target.parent)
        finally:
            pass
        raise
    return holding


def _quarantine_removed_entry(
    holding: Path,
    snapshot: dict[str, Any],
    transaction_dir: Path,
) -> Path:
    if snapshot["type"] == "file":
        quarantine = transaction_dir / f"removed-{snapshot['sha256'][:12]}"
        shutil.copy2(holding, quarantine, follow_symlinks=False)
        os.chmod(quarantine, 0o600)
        if _sha256(quarantine) != snapshot["sha256"]:
            raise RuntimeError("Quarantined removal hash mismatch")
        return quarantine

    quarantine = transaction_dir / "removed-empty-directory"
    quarantine.mkdir(mode=0o700)
    return quarantine


def _remove_holding_entry(holding: Path, snapshot: dict[str, Any]) -> None:
    if snapshot["type"] == "file":
        holding.unlink()
    else:
        holding.rmdir()
    _fsync_directory(holding.parent)


def _audit_quarantine_path(raw_path: Any, expected_type: str) -> Path:
    if not isinstance(raw_path, str):
        raise ValueError("Audit transaction has no quarantine preimage")
    path = Path(raw_path)
    if path.is_symlink():
        raise ValueError(f"Quarantine preimage is a symlink: {path}")
    if expected_type == "file" and not path.is_file():
        raise ValueError(f"Quarantine preimage is not a regular file: {path}")
    if expected_type == "empty_directory" and not path.is_dir():
        raise ValueError(f"Quarantine preimage is not a directory: {path}")
    quarantine_root = _state_subdir(QUARANTINE_DIR)
    resolved = path.resolve(strict=True)
    if not _path_inside(resolved, quarantine_root):
        raise PermissionError("Quarantine preimage is outside Grabowski state")
    return resolved


def _protected_generic_write_target(path: Path) -> bool:
    protected = [
        POLICY_PATH,
        STATE_DIR,
        AUDIT_LOG,
        QUARANTINE_DIR,
        HOME / "repos" / "merges",
        HOME / ".config" / "tunnel-client",
        DEPLOYMENT_MANIFEST,
        EXPECTED_STABLE_RUNTIME / "inputs" / "runtime-entrypoint.json",
    ]
    candidate = path.resolve(strict=False)
    return any(_path_inside(candidate, root.resolve(strict=False)) for root in protected)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_regular_text_file(path: Path, max_bytes: int) -> bytes:
    st = path.stat()
    if not statmod.S_ISREG(st.st_mode):
        raise ValueError(f"Not a regular file: {path}")
    if st.st_size > max_bytes:
        raise ValueError(f"File exceeds byte limit ({st.st_size} > {max_bytes})")
    data = path.read_bytes()
    if b"\x00" in data:
        raise ValueError("Binary/NUL-containing files are not allowed")
    return data


def _validate_sha256(value: str, label: str = "sha256") -> str:
    if not (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _redact_sensitive_text(
    text: str,
    extra_secrets: list[str] | None = None,
) -> tuple[str, int]:
    result = text
    redactions = 0
    for pattern, replacement in SECRET_REDACTIONS:
        result, count = pattern.subn(replacement, result)
        redactions += count

    for secret in sorted(set(extra_secrets or []), key=len, reverse=True):
        if not secret:
            continue
        count = result.count(secret)
        if count:
            result = result.replace(secret, "<REDACTED>")
            redactions += count

    return result, redactions


def _nofollow_kind_and_size(path: Path) -> tuple[str, int | None]:
    info = os.stat(path, follow_symlinks=False)
    mode = info.st_mode
    if statmod.S_ISLNK(mode):
        return "symlink-blocked", None
    if statmod.S_ISDIR(mode):
        return "directory", None
    if statmod.S_ISREG(mode):
        return "file", info.st_size
    return "other", None


def _nofollow_metadata(path: Path) -> os.stat_result:
    return os.stat(path, follow_symlinks=False)


def _validate_opened_regular(
    opened: os.stat_result,
    linked: os.stat_result,
    max_bytes: int,
) -> None:
    if not statmod.S_ISREG(opened.st_mode):
        raise ValueError("Not a regular file")
    if not statmod.S_ISREG(linked.st_mode):
        raise PermissionError("Path is not bound to a regular file")
    if opened.st_dev != linked.st_dev or opened.st_ino != linked.st_ino:
        raise PermissionError("Path changed while opening file")
    if opened.st_nlink != 1:
        raise PermissionError("Hard-linked sensitive files are not supported")
    if opened.st_size > max_bytes:
        raise ValueError(f"File exceeds byte limit ({opened.st_size} > {max_bytes})")


def _validate_same_regular_snapshot(
    before: os.stat_result,
    after_open: os.stat_result,
    after_link: os.stat_result,
) -> None:
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_size,
        after_open.st_mtime_ns,
        after_open.st_ctime_ns,
    )
    linked_identity = (
        after_link.st_dev,
        after_link.st_ino,
        after_link.st_size,
        after_link.st_mtime_ns,
        after_link.st_ctime_ns,
    )
    if before_identity != after_identity or before_identity != linked_identity:
        raise RuntimeError("File changed while being read")


def _read_bound_regular_bytes(path: Path, max_bytes: int) -> dict[str, Any]:
    fd: int | None = None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        linked = os.stat(path, follow_symlinks=False)
        _validate_opened_regular(opened, linked, max_bytes)

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValueError(f"File exceeds byte limit ({len(data)} > {max_bytes})")

        after_open = os.fstat(fd)
        after_link = os.stat(path, follow_symlinks=False)
        _validate_same_regular_snapshot(opened, after_open, after_link)
        digest = hashlib.sha256(data).hexdigest()
        return {
            "data": data,
            "sha256": digest,
            "size": len(data),
            "mode": statmod.S_IMODE(opened.st_mode),
            "mtime_ns": opened.st_mtime_ns,
            "ctime_ns": opened.st_ctime_ns,
            "dev": opened.st_dev,
            "ino": opened.st_ino,
        }
    finally:
        if fd is not None:
            os.close(fd)


def _minimum_policy_limit(policy: dict[str, Any], *keys: str) -> int:
    return min(_policy_limit(policy, key) for key in keys)


def _policy_limit_or_default(
    policy: dict[str, Any],
    key: str,
    default: int,
) -> int:
    value = _profile_values(policy, key)
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RuntimeError(f"Invalid access policy limit: {key}")
    return value


def _resolve_rooted_existing(raw_path: str, roots: list[Path], label: str) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Path must be absolute")
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not _is_within(resolved, roots):
        raise PermissionError(f"Path is outside configured {label} roots: {resolved}")
    return resolved


def _resolve_secret_existing(raw_path: str) -> Path:
    return _resolve_rooted_existing(raw_path, _secret_roots(), "secret")


def _resolve_browser_profile_existing(raw_path: str) -> Path:
    return _resolve_rooted_existing(
        raw_path,
        _browser_profile_roots(),
        "browser profile",
    )


def _remote_destination_syntax(raw_path: str) -> bool:
    if "://" in raw_path:
        return True
    if raw_path.startswith("/"):
        return False
    return re.match(r"^[A-Za-z0-9_.-]+(?:@[A-Za-z0-9_.-]+)?:", raw_path) is not None


def _resolve_secret_export_target(raw_path: str) -> Path:
    if _remote_destination_syntax(raw_path):
        raise ValueError("Secret export destination must be a local filesystem path")
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Secret export destination must be absolute")
    if candidate.exists() or candidate.is_symlink():
        _reject_symlink_components(candidate)
        raise FileExistsError(f"Refusing to overwrite existing path: {candidate}")
    _reject_symlink_components(candidate, allow_missing_leaf=True)
    parent = candidate.parent.resolve(strict=True)
    resolved = parent / candidate.name
    policy = _load_policy()
    if not _is_within(resolved, _secret_export_roots(policy)):
        raise PermissionError(
            f"Destination is outside configured secret export roots: {resolved}"
        )
    return resolved


def _atomic_create_bytes(target: Path, data: bytes, mode: int = 0o600) -> None:
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
        _fsync_directory(target.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secret_text_snapshot(
    path: Path,
    *,
    expected_sha256: str | None = None,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    policy = _load_policy()
    byte_limit = _policy_limit(policy, "max_read_bytes")
    if max_bytes is not None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        byte_limit = min(byte_limit, max_bytes)
    snapshot = _read_bound_regular_bytes(path, byte_limit)
    if expected_sha256 is not None:
        _validate_sha256(expected_sha256, "expected_sha256")
        if snapshot["sha256"] != expected_sha256:
            raise RuntimeError(
                "SHA-256 precondition failed: "
                f"expected {expected_sha256}, current {snapshot['sha256']}"
            )
    data = snapshot["data"]
    if b"\x00" in data:
        raise ValueError("Binary/NUL-containing secret files are not revealable")
    text = data.decode("utf-8")
    redacted, redaction_count = _redact_sensitive_text(text)
    return {
        **snapshot,
        "text": text,
        "redacted_text": redacted,
        "redaction_count": redaction_count,
    }


def _secret_redaction_values(data: bytes) -> list[str]:
    decoded = data.decode("utf-8", errors="replace")
    values = {decoded}
    stripped = decoded.strip()
    if stripped:
        values.add(stripped)
    for line in decoded.splitlines():
        stripped_line = line.strip()
        if stripped_line:
            values.add(stripped_line)
    if data:
        b64 = base64.b64encode(data).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(data).decode("ascii")
        values.update({b64, b64.rstrip("="), urlsafe, urlsafe.rstrip("=")})
        values.add(urllib.parse.quote_from_bytes(data, safe=""))
    return sorted((value for value in values if value), key=len, reverse=True)


def _redact_secret_output(text: str, secret_data: bytes) -> tuple[str, int]:
    return _redact_sensitive_text(text, _secret_redaction_values(secret_data))


def _limit_text(text: str, max_output_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_output_bytes:
        return text, False
    clipped = encoded[:max_output_bytes].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _contains_secret_variant(text: str, secret_data: bytes) -> bool:
    return any(secret and secret in text for secret in _secret_redaction_values(secret_data))


def _reject_secret_variants_in_text(text: str, secret_data: bytes, label: str) -> None:
    if _contains_secret_variant(text, secret_data):
        raise PermissionError(f"Secret value or encoded secret value may not appear in {label}")


def _argv_sha256(argv: list[str]) -> str:
    encoded = json.dumps(
        argv,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolve_secret_use_cwd(cwd: str | None) -> Path:
    candidate = HOME if cwd is None else Path(cwd).expanduser()
    if not candidate.is_absolute():
        raise ValueError("cwd must be absolute")
    _reject_symlink_components(candidate)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"cwd is not a directory: {resolved}")
    if not _is_within(resolved, _roots("read")):
        raise PermissionError(f"cwd is outside configured read roots: {resolved}")
    if _path_is_sensitive(resolved):
        raise PermissionError("cwd may not be inside secret/browser roots")
    if _protected_generic_write_target(resolved):
        raise PermissionError("cwd may not be inside protected operator roots")
    return resolved


def _resolve_executable(value: str, cwd: Path) -> str:
    candidate = Path(value).expanduser()
    if "/" in value:
        if not candidate.is_absolute():
            candidate = cwd / candidate
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise PermissionError(f"Executable is not runnable: {resolved}")
        return str(resolved)
    resolved = shutil.which(value)
    if resolved is None:
        raise FileNotFoundError(f"Executable not found: {value}")
    path = Path(resolved).resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise PermissionError(f"Executable is not runnable: {path}")
    return str(path)


def _looks_like_shell_c_flag(value: str) -> bool:
    return value.startswith("-") and "c" in value[1:]


def _validate_secret_use_argv(
    argv: Any,
    *,
    cwd: Path,
    secret_data: bytes,
) -> list[str]:
    if isinstance(argv, str):
        raise ValueError("argv must be a list, not a shell string")
    if not isinstance(argv, list) or not argv:
        raise ValueError("argv must be a non-empty list")
    if not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must contain non-empty strings")
    if not any(SECRET_FD_PLACEHOLDER in item for item in argv):
        raise ValueError(f"argv must include {SECRET_FD_PLACEHOLDER}")
    for index, item in enumerate(argv):
        _reject_secret_variants_in_text(item, secret_data, f"argv[{index}]")
    executable_name = Path(argv[0]).name
    if executable_name == "eval" or "eval" in argv:
        raise PermissionError("eval is not allowed for secret_use")
    if executable_name in SHELL_EXECUTABLES:
        if any(_looks_like_shell_c_flag(item) for item in argv[1:]):
            raise PermissionError("shell command mode is not allowed for secret_use")
    if executable_name == "env":
        for item in argv[1:]:
            if "=" in item and not item.startswith("-"):
                continue
            nested_name = Path(item).name
            if nested_name in SHELL_EXECUTABLES:
                raise PermissionError("env-to-shell is not allowed for secret_use")
            if nested_name == "eval":
                raise PermissionError("eval is not allowed for secret_use")
            if item == "--":
                continue
            break
    command = [_resolve_executable(argv[0], cwd), *argv[1:]]
    return command


def _secret_use_environment(
    extra_environment: dict[str, str] | None,
    secret_data: bytes,
) -> dict[str, str]:
    environment: dict[str, str] = {}
    for key in SECRET_USE_ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value is not None:
            _reject_secret_variants_in_text(value, secret_data, f"environment[{key}]")
            environment[key] = value
    environment["HOME"] = str(HOME)
    if extra_environment is None:
        return environment
    if not isinstance(extra_environment, dict):
        raise ValueError("environment must be an object")
    redaction_values = _secret_redaction_values(secret_data)
    for key, value in extra_environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("environment keys and values must be strings")
        if key not in SECRET_USE_ENV_ALLOWLIST:
            raise PermissionError(f"Environment key is not allowlisted: {key}")
        if any(part in key.upper() for part in SENSITIVE_ENV_PARTS):
            raise PermissionError(f"Sensitive environment key is not allowed: {key}")
        if any(secret and secret in value for secret in redaction_values):
            raise PermissionError(
                "Secret value or encoded secret value may not be placed in environment"
            )
        environment[key] = value
    return environment


def _materialize_secret_reference(data: bytes) -> dict[str, Any]:
    memfd_create = getattr(os, "memfd_create", None)
    if callable(memfd_create):
        fd = memfd_create("grabowski-secret", getattr(os, "MFD_CLOEXEC", 0))
        try:
            os.write(fd, data)
            os.lseek(fd, 0, os.SEEK_SET)
        except BaseException:
            os.close(fd)
            raise
        return {
            "fd": fd,
            "path": f"/proc/self/fd/{fd}",
            "temporary": None,
            "transport": "memfd",
        }

    root = _state_subdir(STATE_DIR / "secret-use")
    fd, temporary_name = tempfile.mkstemp(prefix="secret-", dir=str(root))
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {
        "fd": None,
        "path": str(temporary),
        "temporary": temporary,
        "transport": "temporary-file",
    }


def _cleanup_secret_reference(reference: dict[str, Any]) -> None:
    fd = reference.get("fd")
    if isinstance(fd, int):
        try:
            os.close(fd)
        except OSError:
            pass
    temporary = reference.get("temporary")
    if isinstance(temporary, Path):
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float = 3.0,
) -> tuple[bytes, bytes]:
    if process.poll() is not None:
        return process.communicate()
    os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        return process.communicate()


def _read_limited_process_pipes(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> tuple[bytes, bytes, bool, bool, bool]:
    import selectors

    started = time.monotonic()
    timed_out = False
    stdout_truncated = False
    stderr_truncated = False
    buffers: dict[Any, bytearray] = {}
    selector = selectors.DefaultSelector()

    def append_limited(pipe: Any, chunk: bytes) -> None:
        nonlocal stdout_truncated, stderr_truncated
        if not chunk or pipe not in buffers:
            return
        buf = buffers[pipe]
        keep = 0
        if len(buf) < max_output_bytes:
            keep = min(len(chunk), max_output_bytes - len(buf))
            buf.extend(chunk[:keep])
        if len(chunk) > keep:
            if pipe is process.stdout:
                stdout_truncated = True
            else:
                stderr_truncated = True

    for pipe in (process.stdout, process.stderr):
        if pipe is None:
            continue
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
        buffers[pipe] = bytearray()

    while selector.get_map():
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            timed_out = True
            stdout_tail, stderr_tail = _terminate_process_group(process)
            append_limited(process.stdout, stdout_tail)
            append_limited(process.stderr, stderr_tail)
            break
        for key, _events in selector.select(timeout=min(0.2, remaining)):
            pipe = key.fileobj
            chunk = os.read(pipe.fileno(), 8192)
            if not chunk:
                selector.unregister(pipe)
                continue
            append_limited(pipe, chunk)
        if process.poll() is not None:
            continue
    if process.poll() is None and not timed_out:
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(process)
    else:
        process.wait(timeout=0)
    stdout = bytes(buffers.get(process.stdout, b""))
    stderr = bytes(buffers.get(process.stderr, b""))
    selector.close()
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    return stdout, stderr, timed_out, stdout_truncated, stderr_truncated


def _run_secret_command(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    pass_fd: int | None,
    timeout_seconds: int,
    max_output_bytes: int,
    secret_data: bytes,
) -> dict[str, Any]:
    started = time.monotonic()
    pass_fds = () if pass_fd is None else (pass_fd,)
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    stdout_raw, stderr_raw, timed_out, stdout_truncated, stderr_truncated = (
        _read_limited_process_pipes(
            process,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    )

    stdout_text, stdout_redactions = _redact_secret_output(
        stdout_raw.decode("utf-8", errors="replace"),
        secret_data,
    )
    stderr_text, stderr_redactions = _redact_secret_output(
        stderr_raw.decode("utf-8", errors="replace"),
        secret_data,
    )
    stdout_text, stdout_late_truncated = _limit_text(stdout_text, max_output_bytes)
    stderr_text, stderr_late_truncated = _limit_text(stderr_text, max_output_bytes)
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_truncated": stdout_truncated or stdout_late_truncated,
        "stderr_truncated": stderr_truncated or stderr_late_truncated,
        "redaction_count": stdout_redactions + stderr_redactions,
    }


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _state_root() -> Path:
    if STATE_DIR.is_symlink():
        raise PermissionError(f"State directory may not be a symlink: {STATE_DIR}")
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = STATE_DIR.resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError(f"State root is not a directory: {root}")
    return root


def _state_subdir(path: Path) -> Path:
    root = _state_root()
    if path.is_symlink():
        raise PermissionError(f"State subdirectory may not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = path.resolve(strict=True)
    if not _path_inside(resolved, root):
        raise PermissionError(f"State subdirectory escaped state root: {resolved}")
    return resolved


def _new_transaction_dir(operation: str, target: Path) -> tuple[str, Path]:
    root = _state_subdir(QUARANTINE_DIR)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    transaction_id = f"{stamp}-{uuid.uuid4().hex[:12]}"
    directory = root / transaction_id
    directory.mkdir(mode=0o700)
    _write_json_evidence(
        directory / "intent.json",
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "operation": operation,
            "path": str(target),
            "created_at": _utc_timestamp(),
        },
    )
    return transaction_id, directory


def _write_json_evidence(path: Path, payload: dict[str, Any]) -> None:
    data = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _audit_record_hash(record: dict[str, Any]) -> str:
    material = {
        key: value
        for key, value in record.items()
        if key != "record_sha256"
    }
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _raw_line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _verify_audit_log(path: Path = AUDIT_LOG) -> dict[str, Any]:
    if not path.exists():
        return {
            "valid": True,
            "path": str(path),
            "exists": False,
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "error": None,
        }
    if path.is_symlink():
        return {
            "valid": False,
            "path": str(path),
            "exists": True,
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "error": "audit-log-is-symlink",
        }
    try:
        info = path.stat()
        if not statmod.S_ISREG(info.st_mode):
            raise ValueError("audit-log-is-not-regular")
        if info.st_size > MAX_AUDIT_BYTES:
            raise ValueError("audit-log-too-large")
        lines = path.read_bytes().splitlines()
    except (OSError, ValueError) as exc:
        return {
            "valid": False,
            "path": str(path),
            "exists": True,
            "records": 0,
            "legacy_records": 0,
            "v2_records": 0,
            "last_record_sha256": None,
            "error": str(exc),
        }

    previous: str | None = None
    legacy_records = 0
    v2_records = 0
    records = 0
    seen_v2_record = False
    for index, line in enumerate(lines, start=1):
        if not line:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"blank-line-{index}",
            }
        records += 1
        try:
            parsed = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"line-{index}:{type(exc).__name__}",
            }
        if not isinstance(parsed, dict):
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"line-{index}:not-object",
            }
        stored_hash = parsed.get("record_sha256")
        if stored_hash is None:
            if seen_v2_record:
                return {
                    "valid": False,
                    "path": str(path),
                    "exists": True,
                    "records": records,
                    "legacy_records": legacy_records,
                    "v2_records": v2_records,
                    "last_record_sha256": previous,
                    "error": f"line-{index}:legacy-record-after-v2",
                }
            legacy_records += 1
            previous = _raw_line_hash(line)
            continue
        if not (
            isinstance(stored_hash, str)
            and len(stored_hash) == 64
            and all(char in "0123456789abcdef" for char in stored_hash)
        ):
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"line-{index}:invalid-record-hash",
            }
        if parsed.get("previous_record_sha256") != previous:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"line-{index}:previous-hash-mismatch",
            }
        if parsed.get("sequence") != records:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"line-{index}:sequence-mismatch",
            }
        expected_hash = _audit_record_hash(parsed)
        if expected_hash != stored_hash:
            return {
                "valid": False,
                "path": str(path),
                "exists": True,
                "records": records,
                "legacy_records": legacy_records,
                "v2_records": v2_records,
                "last_record_sha256": previous,
                "error": f"line-{index}:record-hash-mismatch",
            }
        v2_records += 1
        seen_v2_record = True
        previous = stored_hash

    return {
        "valid": True,
        "path": str(path),
        "exists": True,
        "records": records,
        "legacy_records": legacy_records,
        "v2_records": v2_records,
        "last_record_sha256": previous,
        "error": None,
    }


def _append_audit(record: dict[str, Any]) -> None:
    with AUDIT_APPEND_LOCK:
        _state_root()
        if AUDIT_LOG.is_symlink():
            raise PermissionError(f"Audit log may not be a symlink: {AUDIT_LOG}")
        status = _verify_audit_log(AUDIT_LOG)
        if not status["valid"]:
            raise RuntimeError(f"Audit log verification failed: {status['error']}")

        enriched = {**record}
        enriched.setdefault("timestamp", _utc_timestamp())
        enriched["audit_schema_version"] = AUDIT_SCHEMA_VERSION
        enriched["sequence"] = int(status["records"]) + 1
        enriched["previous_record_sha256"] = status["last_record_sha256"]
        enriched["record_sha256"] = _audit_record_hash(enriched)
        payload = (
            json.dumps(enriched, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        )
        fd = os.open(
            AUDIT_LOG,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


def _audit_records() -> list[dict[str, Any]]:
    status = _verify_audit_log(AUDIT_LOG)
    if not status["valid"]:
        raise RuntimeError(f"Audit log verification failed: {status['error']}")
    if not AUDIT_LOG.exists():
        return []
    records = []
    for line in AUDIT_LOG.read_bytes().splitlines():
        parsed = json.loads(line.decode("utf-8"))
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def _find_transaction_record(transaction_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"\d{8}T\d{6}\.\d{6}Z-[0-9a-f]{12}", transaction_id):
        raise ValueError("Invalid transaction_id")
    for record in reversed(_audit_records()):
        if record.get("transaction_id") == transaction_id:
            return record
    raise ValueError(f"Transaction not found in audit log: {transaction_id}")


_DEPLOYMENT_IDENTITY_KEYS = (
    "manifest_parse_valid",
    "manifest_schema_valid",
    "release_path_valid",
    "release_id_valid",
    "repo_head_valid",
    "stable_runtime_manifest_valid",
    "runtime_pointer_valid",
    "runtime_input_identity_valid",
    "lock_identity_valid",
    "source_snapshot_identity_valid",
    "source_identity_valid",
    "embedded_contract_valid",
    "entrypoint_contract_identity_valid",
    "entrypoint_path_valid",
    "release_python_identity_valid",
    "executable_identity_valid",
    "pip_identity_valid",
    "protocol_identity_valid",
    "python_runtime_identity_valid",
    "platform_identity_valid",
    "artifact_integrity_valid",
    "runtime_binding_valid",
    "environment_compatibility_valid",
)


def _false_deployment_metadata(base: dict[str, Any], **extra: Any) -> dict[str, Any]:
    result = {**base}
    for key in _DEPLOYMENT_IDENTITY_KEYS:
        result[key] = False
    result["provenance_valid"] = False
    result.update(extra)
    return result


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value)
    )


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and path.as_posix() != "."


def _manifest_schema_valid(raw: dict[str, Any]) -> bool:
    required = {
        "schema_version": int,
        "release_id": str,
        "repo_head": str,
        "entrypoint_contract": dict,
        "entrypoint_contract_sha256": str,
        "source_sha256": str,
        "source_sha256s": dict,
        "runtime_input_sha256": str,
        "runtime_lock_sha256": str,
        "snapshot_paths": dict,
        "immutable_release_path": str,
        "expected_stable_runtime_path": str,
        "release_python_path": str,
        "entrypoint_path": str,
        "module_paths": dict,
        "platform": str,
        "python_version": str,
        "python_implementation": str,
        "mcp_protocol_version": str,
        "created_at_unix": int,
        "completion_status": str,
        "executable": str,
        "pip_version": str,
    }
    for key, kind in required.items():
        value = raw.get(key)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            return False
    if raw.get("schema_version") != 4 or raw.get("completion_status") != "complete":
        return False
    if not _is_hex(raw.get("repo_head"), 40):
        return False
    for key in (
        "entrypoint_contract_sha256",
        "source_sha256",
        "runtime_input_sha256",
        "runtime_lock_sha256",
    ):
        if not _is_hex(raw.get(key), 64):
            return False
    contract = raw.get("entrypoint_contract")
    if not isinstance(contract, dict):
        return False
    schema_version = contract.get("schema_version")
    expected_keys = {"schema_version", "mode", "module", "source", "expected_tools"}
    if schema_version == 2:
        expected_keys.add("supporting_sources")
    if schema_version not in {1, 2} or set(contract) != expected_keys:
        return False
    module = contract.get("module")
    source = contract.get("source")
    if (
        contract.get("mode") != "module"
        or not isinstance(module, str)
        or MODULE_RE.fullmatch(module) is None
        or not _safe_relative_path(source)
    ):
        return False
    tools = contract.get("expected_tools")
    if (
        not isinstance(tools, list)
        or not tools
        or not all(isinstance(item, str) and item for item in tools)
        or len(set(tools)) != len(tools)
    ):
        return False
    modules = {module}
    sources = {source}
    supporting_modules: set[str] = set()
    supporting = contract.get("supporting_sources", [])
    if not isinstance(supporting, list):
        return False
    for item in supporting:
        if not isinstance(item, dict) or set(item) != {"module", "source"}:
            return False
        item_module = item.get("module")
        item_source = item.get("source")
        if (
            not isinstance(item_module, str)
            or MODULE_RE.fullmatch(item_module) is None
            or item_module in modules
            or not _safe_relative_path(item_source)
            or item_source in sources
        ):
            return False
        modules.add(item_module)
        supporting_modules.add(item_module)
        sources.add(item_source)
    hashes = raw.get("source_sha256s")
    if (
        not isinstance(hashes, dict)
        or set(hashes) != modules
        or not all(_is_hex(value, 64) for value in hashes.values())
        or hashes.get(module) != raw.get("source_sha256")
    ):
        return False
    module_paths = raw.get("module_paths")
    if (
        not isinstance(module_paths, dict)
        or set(module_paths) != modules
        or not all(isinstance(value, str) and value for value in module_paths.values())
        or module_paths.get(module) != raw.get("entrypoint_path")
    ):
        return False
    snapshot_paths = raw.get("snapshot_paths")
    if not isinstance(snapshot_paths, dict) or set(snapshot_paths) != {
        "runtime_entrypoint", "runtime_input", "runtime_lock", "source",
        "supporting_sources",
    }:
        return False
    if not all(
        isinstance(snapshot_paths.get(key), str) and snapshot_paths.get(key)
        for key in ("runtime_entrypoint", "runtime_input", "runtime_lock", "source")
    ):
        return False
    support_paths = snapshot_paths.get("supporting_sources")
    if (
        not isinstance(support_paths, dict)
        or set(support_paths) != supporting_modules
        or not all(isinstance(value, str) and value for value in support_paths.values())
    ):
        return False
    created = raw.get("created_at_unix")
    return isinstance(created, int) and not isinstance(created, bool) and created > 0


def _read_bound_regular_file(
    recorded: Any,
    expected: Path,
    release_root: Path,
    *,
    max_bytes: int,
) -> bytes | None:
    """Read only the exact expected regular file after binding path and inode."""
    if not isinstance(recorded, str) or Path(recorded) != expected:
        return None
    fd: int | None = None
    try:
        release_real = release_root.resolve(strict=True)
        parent_real = expected.parent.resolve(strict=True)
        if not _path_inside(parent_real, release_real):
            return None
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(expected, flags)
        opened = os.fstat(fd)
        linked = os.stat(expected, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or not statmod.S_ISREG(linked.st_mode)
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_nlink != 1
            or opened.st_size > max_bytes
        ):
            return None
        resolved = expected.resolve(strict=True)
        if not _path_inside(resolved, release_real):
            return None
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        return data if len(data) <= max_bytes else None
    except (OSError, RuntimeError, ValueError):
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _deployment_metadata() -> dict[str, Any]:
    """Return fail-closed deployment evidence without leaking manifest errors."""
    try:
        return _deployment_metadata_impl()
    except Exception as exc:  # pragma: no cover - final status containment
        try:
            manifest_exists = DEPLOYMENT_MANIFEST.is_file()
        except OSError:
            manifest_exists = False
        return _false_deployment_metadata(
            {
                "manifest_path": str(DEPLOYMENT_MANIFEST),
                "manifest_exists": manifest_exists,
            },
            error_type=type(exc).__name__,
        )


def _deployment_metadata_impl() -> dict[str, Any]:
    manifest_path = DEPLOYMENT_MANIFEST
    base: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "manifest_exists": manifest_path.is_file(),
    }
    if not manifest_path.is_file():
        return _false_deployment_metadata(base)
    try:
        info = manifest_path.stat()
        if not statmod.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            return _false_deployment_metadata(base, error_type="UnsafeManifest")
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _false_deployment_metadata(base, error_type=type(exc).__name__)
    if not isinstance(raw, dict):
        return _false_deployment_metadata(base, manifest_parse_valid=True)

    schema_valid = _manifest_schema_valid(raw)
    release_root = manifest_path.parent.resolve()
    snapshot_paths = raw.get("snapshot_paths") if isinstance(raw.get("snapshot_paths"), dict) else {}
    canonical_runtime = EXPECTED_STABLE_RUNTIME
    canonical_releases = canonical_runtime.parent / "grabowski-mcp-releases"

    stable_runtime_manifest_valid = (
        isinstance(raw.get("expected_stable_runtime_path"), str)
        and Path(raw["expected_stable_runtime_path"]) == canonical_runtime
    )
    release_path_valid = False
    try:
        release_path_valid = (
            isinstance(raw.get("immutable_release_path"), str)
            and Path(raw["immutable_release_path"]).resolve(strict=True) == release_root
            and release_root.parent == canonical_releases.resolve(strict=True)
        )
    except (OSError, RuntimeError):
        release_path_valid = False
    release_id_valid = isinstance(raw.get("release_id"), str) and raw.get("release_id") == release_root.name
    repo_head_valid = _is_hex(raw.get("repo_head"), 40)
    runtime_pointer_valid = False
    try:
        runtime_pointer_valid = (
            canonical_runtime.is_symlink()
            and canonical_runtime.resolve(strict=True) == release_root
        )
    except (OSError, RuntimeError):
        runtime_pointer_valid = False

    def snapshot_bytes(key: str, relative: str, limit: int = MAX_SNAPSHOT_BYTES) -> bytes | None:
        return _read_bound_regular_file(
            snapshot_paths.get(key), release_root / relative, release_root, max_bytes=limit
        )

    runtime_input_data = snapshot_bytes("runtime_input", "inputs/runtime.in")
    runtime_lock_data = snapshot_bytes("runtime_lock", "inputs/runtime.lock.txt")
    runtime_input_identity_valid = (
        runtime_input_data is not None
        and hashlib.sha256(runtime_input_data).hexdigest() == raw.get("runtime_input_sha256")
    )
    lock_identity_valid = (
        runtime_lock_data is not None
        and hashlib.sha256(runtime_lock_data).hexdigest() == raw.get("runtime_lock_sha256")
    )

    expected_contract = release_root / "inputs/runtime-entrypoint.json"
    contract_data = _read_bound_regular_file(
        snapshot_paths.get("runtime_entrypoint"),
        expected_contract,
        release_root,
        max_bytes=MAX_CONTRACT_BYTES,
    )
    contract_raw: dict[str, Any] | None = None
    if contract_data is not None:
        try:
            parsed = json.loads(contract_data.decode("utf-8"))
            if isinstance(parsed, dict):
                contract_raw = parsed
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    entrypoint_contract_identity_valid = (
        contract_data is not None
        and contract_raw is not None
        and hashlib.sha256(contract_data).hexdigest() == raw.get("entrypoint_contract_sha256")
        and _manifest_schema_valid({**raw, "entrypoint_contract": contract_raw})
    )
    embedded_contract_valid = isinstance(raw.get("entrypoint_contract"), dict) and raw.get("entrypoint_contract") == contract_raw

    contract_sources: list[tuple[str, str]] = []
    if contract_raw is not None:
        main_module = contract_raw.get("module")
        main_source = contract_raw.get("source")
        if (
            isinstance(main_module, str)
            and MODULE_RE.fullmatch(main_module) is not None
            and _safe_relative_path(main_source)
        ):
            contract_sources.append((main_module, main_source))
        supporting = contract_raw.get("supporting_sources", [])
        if isinstance(supporting, list):
            for item in supporting:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("module"), str)
                    and MODULE_RE.fullmatch(item["module"]) is not None
                    and _safe_relative_path(item.get("source"))
                ):
                    contract_sources.append((item["module"], item["source"]))

    source_hashes = raw.get("source_sha256s")
    module_paths = raw.get("module_paths")
    supporting_snapshot_paths = snapshot_paths.get("supporting_sources")
    snapshot_identity_by_module: dict[str, bool] = {}
    module_identity_by_module: dict[str, bool] = {}
    module_origins: dict[str, Path] = {}

    for index, (module_name, source_name) in enumerate(contract_sources):
        recorded_snapshot = (
            snapshot_paths.get("source")
            if index == 0
            else (
                supporting_snapshot_paths.get(module_name)
                if isinstance(supporting_snapshot_paths, dict)
                else None
            )
        )
        snapshot_data = _read_bound_regular_file(
            recorded_snapshot,
            release_root / "inputs" / source_name,
            release_root,
            max_bytes=MAX_SNAPSHOT_BYTES,
        )
        expected_hash = (
            source_hashes.get(module_name)
            if isinstance(source_hashes, dict)
            else None
        )
        snapshot_identity_by_module[module_name] = (
            snapshot_data is not None
            and hashlib.sha256(snapshot_data).hexdigest() == expected_hash
        )

        origin: Path | None = None
        if module_name == "grabowski_mcp":
            try:
                origin = Path(__file__).resolve(strict=True)
            except (OSError, RuntimeError):
                origin = None
        else:
            try:
                spec = importlib.util.find_spec(module_name)
                if spec is not None and isinstance(spec.origin, str):
                    origin = Path(spec.origin).resolve(strict=True)
            except (ImportError, OSError, RuntimeError, ValueError):
                origin = None
        if origin is not None:
            module_origins[module_name] = origin
        recorded_module = (
            module_paths.get(module_name)
            if isinstance(module_paths, dict)
            else None
        )
        module_data = (
            _read_bound_regular_file(
                recorded_module,
                origin,
                release_root,
                max_bytes=MAX_SNAPSHOT_BYTES,
            )
            if origin is not None
            else None
        )
        module_identity_by_module[module_name] = (
            module_data is not None
            and hashlib.sha256(module_data).hexdigest() == expected_hash
        )

    source_snapshot_identity_valid = (
        bool(contract_sources)
        and len(snapshot_identity_by_module) == len(contract_sources)
        and all(snapshot_identity_by_module.values())
    )
    source_identity_valid = (
        bool(contract_sources)
        and len(module_identity_by_module) == len(contract_sources)
        and all(module_identity_by_module.values())
    )
    entrypoint_module = contract_sources[0][0] if contract_sources else None
    entrypoint_origin = (
        module_origins.get(entrypoint_module)
        if entrypoint_module is not None
        else None
    )
    entrypoint_path_valid = (
        entrypoint_origin is not None
        and raw.get("entrypoint_path") == str(entrypoint_origin)
        and isinstance(module_paths, dict)
        and module_paths.get(entrypoint_module) == str(entrypoint_origin)
        and module_identity_by_module.get(entrypoint_module, False)
    )

    release_python_identity_valid = False
    executable_identity_valid = False
    try:
        release_python = Path(str(raw.get("release_python_path")))
        expected_python = release_root / ".venv/bin/python"
        current_python = Path(sys.executable)
        release_python_identity_valid = (
            release_python == expected_python
            and release_python.exists()
            and release_python.resolve(strict=True) == current_python.resolve(strict=True)
        )
        executable_identity_valid = (
            isinstance(raw.get("executable"), str)
            and Path(raw["executable"]) == release_python
            and Path(raw["executable"]).resolve(strict=True) == current_python.resolve(strict=True)
        )
    except (OSError, RuntimeError, ValueError):
        pass

    try:
        pip_identity_valid = raw.get("pip_version") == f"pip {importlib.metadata.version('pip')}"
    except importlib.metadata.PackageNotFoundError:
        pip_identity_valid = False
    protocol_identity_valid = raw.get("mcp_protocol_version") in DEPLOYMENT_PROTOCOL_VERSIONS
    python_runtime_identity_valid = (
        raw.get("python_version") == platform.python_version()
        and raw.get("python_implementation") == platform.python_implementation()
    )
    platform_identity_valid = raw.get("platform") == platform.platform()

    artifact_integrity_valid = all((
        schema_valid,
        repo_head_valid,
        runtime_input_identity_valid,
        lock_identity_valid,
        source_snapshot_identity_valid,
        embedded_contract_valid,
        entrypoint_contract_identity_valid,
        protocol_identity_valid,
    ))
    runtime_binding_valid = all((
        release_path_valid,
        release_id_valid,
        stable_runtime_manifest_valid,
        runtime_pointer_valid,
        source_identity_valid,
        entrypoint_path_valid,
        release_python_identity_valid,
        executable_identity_valid,
        pip_identity_valid,
    ))
    environment_compatibility_valid = all((
        python_runtime_identity_valid,
        platform_identity_valid,
    ))
    provenance_valid = all((
        artifact_integrity_valid,
        runtime_binding_valid,
        environment_compatibility_valid,
    ))

    allowed = {
        key: raw.get(key)
        for key in (
            "schema_version", "release_id", "repo_head",
            "entrypoint_contract_sha256", "source_sha256",
            "source_sha256s", "runtime_input_sha256", "runtime_lock_sha256",
            "mcp_protocol_version", "python_version",
            "python_implementation", "platform", "executable",
            "pip_version", "created_at_unix", "completion_status",
        )
    }
    return {
        **base,
        "manifest_parse_valid": True,
        "manifest_schema_valid": schema_valid,
        "release_path_valid": release_path_valid,
        "release_id_valid": release_id_valid,
        "repo_head_valid": repo_head_valid,
        "stable_runtime_manifest_valid": stable_runtime_manifest_valid,
        "runtime_pointer_valid": runtime_pointer_valid,
        "runtime_input_identity_valid": runtime_input_identity_valid,
        "lock_identity_valid": lock_identity_valid,
        "source_snapshot_identity_valid": source_snapshot_identity_valid,
        "source_snapshot_identity_by_module": snapshot_identity_by_module,
        "source_identity_valid": source_identity_valid,
        "source_identity_by_module": module_identity_by_module,
        "embedded_contract_valid": embedded_contract_valid,
        "entrypoint_contract_identity_valid": entrypoint_contract_identity_valid,
        "entrypoint_path_valid": entrypoint_path_valid,
        "release_python_identity_valid": release_python_identity_valid,
        "executable_identity_valid": executable_identity_valid,
        "pip_identity_valid": pip_identity_valid,
        "protocol_identity_valid": protocol_identity_valid,
        "python_runtime_identity_valid": python_runtime_identity_valid,
        "platform_identity_valid": platform_identity_valid,
        "artifact_integrity_valid": artifact_integrity_valid,
        "runtime_binding_valid": runtime_binding_valid,
        "environment_compatibility_valid": environment_compatibility_valid,
        "provenance_valid": provenance_valid,
        **allowed,
    }


def _runtime_tool_contract_summary() -> dict[str, Any]:
    expected: list[str] = []
    manifest_error: str | None = None
    try:
        payload = json.loads(
            _ensure_regular_text_file(DEPLOYMENT_MANIFEST, 2_000_000).decode(
                "utf-8"
            )
        )
        contract = payload.get("entrypoint_contract", {})
        raw_expected = contract.get("expected_tools", [])
        if not isinstance(raw_expected, list) or not all(
            isinstance(item, str) for item in raw_expected
        ):
            raise ValueError("deployment manifest expected_tools is not a string list")
        expected = sorted(set(raw_expected))
    except Exception as exc:
        manifest_error = f"{type(exc).__name__}: {exc}"

    manager = getattr(mcp, "_tool_manager", None)
    raw_registered = getattr(manager, "_tools", {})
    registered = (
        sorted(str(name) for name in raw_registered)
        if isinstance(raw_registered, dict)
        else []
    )

    def names_sha256(names: list[str]) -> str:
        return hashlib.sha256(
            json.dumps(
                names,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    expected_set = set(expected)
    registered_set = set(registered)
    return {
        "expected_tool_count": len(expected),
        "registered_tool_count": len(registered),
        "name_hash_contract": "sha256-json-sorted-utf8-v1",
        "expected_names_sha256": names_sha256(expected),
        "registered_names_sha256": names_sha256(registered),
        "runtime_matches_deployment_contract": (
            manifest_error is None and expected_set == registered_set
        ),
        "missing_from_runtime": sorted(expected_set - registered_set)[:50],
        "unexpected_in_runtime": sorted(registered_set - expected_set)[:50],
        "manifest_error": manifest_error,
        "client_snapshot_observable": False,
        "refresh_required_when_client_count_or_hash_differs": True,
    }


@mcp.tool(name="grabowski_status", annotations=READ_ANNOTATIONS)
def grabowski_status() -> dict[str, Any]:
    """Return Grabowski's bounded read/write policy and current local state."""
    policy = _load_policy()
    active_profile = _active_profile(policy)
    return {
        "service": "grabowski-mcp",
        "mode": policy.get("mode", "bounded-read-write"),
        "active_profile": active_profile["name"],
        "trusted_owner": _trusted_owner_enabled(policy),
        "access_profiles": sorted(policy.get("profiles", {})),
        "capabilities": sorted(_effective_capabilities(policy)),
        "state_dir": str(STATE_DIR),
        "policy_path": str(POLICY_PATH),
        "read_roots": _profile_values(policy, "read_roots"),
        "write_roots": _profile_values(policy, "write_roots"),
        "write_excluded_roots": _profile_values(
            policy,
            "write_excluded_roots",
        ) or [],
        "secret_roots": _secret_root_values(policy),
        "browser_profile_roots": _browser_profile_root_values(policy),
        "secret_export_roots": _secret_export_root_values(policy),
        "latest_complete_bundles_path": str(BUNDLE_REGISTRY),
        "latest_complete_bundles_exists": BUNDLE_REGISTRY.is_file(),
        "deployment": _deployment_metadata(),
        "tool_contract": _runtime_tool_contract_summary(),
        "forbidden_capabilities": policy.get("forbidden_capabilities", []),
        "kill_switch": _kill_switch_state(),
        "audit": _verify_audit_log(AUDIT_LOG),
    }


@mcp.tool(name="grabowski_list_directory", annotations=READ_ANNOTATIONS)
def grabowski_list_directory(path: str, max_entries: int = 200) -> dict[str, Any]:
    """List one allowed directory without recursion or symlink traversal."""
    _require_capability("file_read")
    directory = _resolve_existing(path, "read")
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    policy = _load_policy()
    hard_limit = _policy_limit(policy, "max_list_entries")
    limit = min(max(1, int(max_entries)), hard_limit)
    entries: list[dict[str, Any]] = []

    for child in sorted(directory.iterdir(), key=lambda p: p.name):
        if len(entries) >= limit:
            break
        try:
            _reject_sensitive(child)
        except PermissionError:
            continue

        kind, size = _nofollow_kind_and_size(child)
        if kind != "symlink-blocked":
            if _path_is_secret(child.resolve(strict=False)):
                kind = "secret-root"
                size = None
            elif _path_is_browser_profile(child.resolve(strict=False)):
                kind = "browser-profile-root"
                size = None

        entries.append({"name": child.name, "type": kind, "size": size})

    return {
        "path": str(directory),
        "entries": entries,
        "returned": len(entries),
        "limit": limit,
    }


@mcp.tool(name="grabowski_stat", annotations=READ_ANNOTATIONS)
def grabowski_stat(path: str) -> dict[str, Any]:
    """Return metadata and SHA-256 for one allowed regular file."""
    _require_capability("file_read")
    target = _resolve_existing(path, "read")
    st = _nofollow_metadata(target)
    kind = "directory" if statmod.S_ISDIR(st.st_mode) else "file" if statmod.S_ISREG(st.st_mode) else "other"
    result: dict[str, Any] = {
        "path": str(target),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
    }
    if kind == "file":
        result["sha256"] = _sha256(target)
    return result


@mcp.tool(name="grabowski_read_text", annotations=READ_ANNOTATIONS)
def grabowski_read_text(path: str, start_line: int = 1, max_lines: int = 400) -> dict[str, Any]:
    """Read UTF-8 text from an allowed file and return a concurrency hash."""
    _require_capability("file_read")
    target = _resolve_existing(path, "read")
    policy = _load_policy()
    data = _ensure_regular_text_file(
        target,
        _policy_limit(policy, "max_read_bytes"),
    )
    text = data.decode("utf-8")
    lines = text.splitlines()

    start = max(1, int(start_line))
    count = min(max(1, int(max_lines)), 2000)
    selected = lines[start - 1 : start - 1 + count]

    return {
        "path": str(target),
        "sha256": hashlib.sha256(data).hexdigest(),
        "start_line": start,
        "end_line": start + len(selected) - 1 if selected else start - 1,
        "total_lines": len(lines),
        "text": "\n".join(selected),
    }


@mcp.tool(name="grabowski_secret_inspect", annotations=READ_ANNOTATIONS)
def grabowski_secret_inspect(path: str, max_entries: int = 100) -> dict[str, Any]:
    """Inspect one configured secret path without returning file content."""
    _require_capability("secret_inspect")
    target = _resolve_secret_existing(path)
    st = _nofollow_metadata(target)
    kind = "directory" if statmod.S_ISDIR(st.st_mode) else "file" if statmod.S_ISREG(st.st_mode) else "other"
    result: dict[str, Any] = {
        "path": str(target),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
        "content_returned": False,
    }
    if kind == "file":
        policy = _load_policy()
        snapshot = _read_bound_regular_bytes(
            target,
            _policy_limit(policy, "max_read_bytes"),
        )
        result.update(
            {
                "sha256": snapshot["sha256"],
                "race_checked": True,
            }
        )
        return result

    if kind != "directory":
        return result

    policy = _load_policy()
    hard_limit = _policy_limit(policy, "max_list_entries")
    limit = min(max(1, int(max_entries)), hard_limit)
    entries: list[dict[str, Any]] = []
    for child in sorted(target.iterdir(), key=lambda p: p.name):
        if len(entries) >= limit:
            break
        child_kind, size = _nofollow_kind_and_size(child)
        entries.append(
            {
                "name": child.name,
                "type": child_kind,
                "size": size,
            }
        )

    result.update(
        {
            "entries": entries,
            "returned": len(entries),
            "limit": limit,
        }
    )
    return result


@mcp.tool(name="grabowski_secret_reveal", annotations=SECRET_REVEAL_ANNOTATIONS)
def grabowski_secret_reveal(
    path: str,
    expected_sha256: str,
    max_bytes: int | None = None,
    justification: str = "",
    acknowledge_context_exposure: bool = False,
) -> dict[str, Any]:
    """Break-glass reveal after hash, justification and exposure acknowledgement."""
    _require_capability("secret_reveal")
    _require_valid_audit_chain()
    _validate_sha256(expected_sha256, "expected_sha256")
    target = _resolve_secret_existing(path)
    snapshot = _secret_text_snapshot(
        target,
        expected_sha256=expected_sha256,
        max_bytes=max_bytes,
    )
    trusted_owner = _trusted_owner_enabled()
    if not trusted_owner and not acknowledge_context_exposure:
        raise PermissionError("Secret reveal requires explicit context-exposure acknowledgement")
    if trusted_owner and not justification.strip():
        justification = "trusted-owner implicit reveal"
    if not isinstance(justification, str) or not justification.strip():
        raise ValueError("Secret reveal requires a non-empty justification")
    if len(justification.encode("utf-8")) > 1000 or "\x00" in justification:
        raise ValueError("Secret reveal justification is too large or contains NUL")
    if _redact_sensitive_text(justification)[0] != justification:
        raise ValueError("Secret reveal justification appears to contain secret material")
    justification_sha256 = hashlib.sha256(justification.encode("utf-8")).hexdigest()
    exposure_mode = "trusted-owner-policy" if trusted_owner else "explicit-acknowledgement"
    transaction_id, transaction_dir = _new_transaction_dir("secret-reveal", target)
    active_profile = _active_profile(_load_policy())
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "secret-reveal",
        "path": str(target),
        "sha256": snapshot["sha256"],
        "size": snapshot["size"],
        "profile": active_profile["name"],
        "capability": "secret_reveal",
        "justification_sha256": justification_sha256,
        "context_exposure_acknowledged": bool(acknowledge_context_exposure),
        "exposure_mode": exposure_mode,
        "postflight": {
            "sha256_precondition_valid": True,
            "race_checked": True,
            "content_returned": True,
        },
    }
    _write_json_evidence(transaction_dir / "reveal.json", evidence)
    _append_audit({
        "timestamp": _utc_timestamp(),
        "operation": "secret-reveal",
        "transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": None,
        "after_sha256": snapshot["sha256"],
        "bytes": snapshot["size"],
        "backup": None,
        "profile": active_profile["name"],
        "capability": "secret_reveal",
        "justification_sha256": justification_sha256,
        "context_exposure_acknowledged": bool(acknowledge_context_exposure),
        "exposure_mode": exposure_mode,
        "postflight": evidence["postflight"],
        "quarantine": {"directory": str(transaction_dir), "preimage_path": None},
        "rollback": {
            "available": False,
            "reason": "secret reveal has no rollback artifact",
            "created_sha256": None,
        },
    })
    return {
        "path": str(target),
        "sha256": snapshot["sha256"],
        "size": snapshot["size"],
        "race_checked": True,
        "content_returned": True,
        "transaction_id": transaction_id,
        "text": snapshot["text"],
        "audit_record_sha256": _verify_audit_log(AUDIT_LOG)["last_record_sha256"],
    }


@mcp.tool(name="grabowski_secret_use", annotations=CREATE_ANNOTATIONS)
def grabowski_secret_use(
    source_path: str,
    expected_source_sha256: str,
    argv: list[str],
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_SECRET_USE_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_SECRET_USE_OUTPUT_BYTES,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run one argv-only command with a secret exposed only through an fd/path."""
    _require_mutations_enabled("secret_use")
    _validate_sha256(expected_source_sha256, "expected_source_sha256")
    source = _resolve_secret_existing(source_path)
    policy = _load_policy()
    snapshot = _read_bound_regular_bytes(
        source,
        _policy_limit(policy, "max_read_bytes"),
    )
    if snapshot["sha256"] != expected_source_sha256:
        raise RuntimeError(
            "SHA-256 precondition failed: "
            f"expected {expected_source_sha256}, current {snapshot['sha256']}"
        )

    hard_timeout = _policy_limit_or_default(
        policy,
        "max_secret_use_seconds",
        DEFAULT_SECRET_USE_TIMEOUT_SECONDS,
    )
    hard_output = _policy_limit_or_default(
        policy,
        "max_secret_use_output_bytes",
        DEFAULT_SECRET_USE_OUTPUT_BYTES,
    )
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds < 1
        or timeout_seconds > hard_timeout
    ):
        raise ValueError(f"timeout_seconds must be between 1 and {hard_timeout}")
    if (
        not isinstance(max_output_bytes, int)
        or isinstance(max_output_bytes, bool)
        or max_output_bytes < 1
        or max_output_bytes > hard_output
    ):
        raise ValueError(f"max_output_bytes must be between 1 and {hard_output}")

    working_directory = _resolve_secret_use_cwd(cwd)
    command_template = _validate_secret_use_argv(
        argv,
        cwd=working_directory,
        secret_data=snapshot["data"],
    )
    child_environment = _secret_use_environment(environment, snapshot["data"])
    reference = _materialize_secret_reference(snapshot["data"])
    command = [
        item.replace(SECRET_FD_PLACEHOLDER, str(reference["path"]))
        for item in command_template
    ]
    try:
        result = _run_secret_command(
            command,
            cwd=working_directory,
            environment=child_environment,
            pass_fd=reference["fd"],
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            secret_data=snapshot["data"],
        )
    finally:
        _cleanup_secret_reference(reference)

    transaction_id, transaction_dir = _new_transaction_dir("secret-use", source)
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "secret-use",
        "source_path": str(source),
        "source_sha256": snapshot["sha256"],
        "source_size": snapshot["size"],
        "argv_sha256": _argv_sha256(command_template),
        "cwd": str(working_directory),
        "secret_transport": reference["transport"],
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "stdout_truncated": result["stdout_truncated"],
        "stderr_truncated": result["stderr_truncated"],
        "redaction_count": result["redaction_count"],
    }
    _write_json_evidence(transaction_dir / "use.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "secret-use",
        "transaction_id": transaction_id,
        "path": str(source),
        "source_path": str(source),
        "before_sha256": None,
        "after_sha256": snapshot["sha256"],
        "bytes": snapshot["size"],
        "backup": None,
        "argv_sha256": _argv_sha256(command_template),
        "cwd": str(working_directory),
        "returncode": result["returncode"],
        "timed_out": result["timed_out"],
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
        },
        "rollback": {
            "available": False,
            "reason": "secret use has no rollback artifact",
            "created_sha256": None,
        },
    }
    _append_audit(record)
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "source_path": str(source),
        "source_sha256": snapshot["sha256"],
        "source_size": snapshot["size"],
        "argv_sha256": _argv_sha256(command_template),
        "cwd": str(working_directory),
        "secret_transport": reference["transport"],
        **result,
        "audit_record_sha256": _verify_audit_log(AUDIT_LOG)["last_record_sha256"],
    }


@mcp.tool(name="grabowski_secret_export", annotations=CREATE_ANNOTATIONS)
def grabowski_secret_export(
    source_path: str,
    destination_path: str,
    expected_source_sha256: str,
) -> dict[str, Any]:
    """Atomically export one secret to a configured local destination root."""
    _require_mutations_enabled("secret_export")
    _validate_sha256(expected_source_sha256, "expected_source_sha256")
    source = _resolve_secret_existing(source_path)
    target = _resolve_secret_export_target(destination_path)
    policy = _load_policy()
    snapshot = _read_bound_regular_bytes(
        source,
        _minimum_policy_limit(policy, "max_read_bytes", "max_write_bytes"),
    )
    if snapshot["sha256"] != expected_source_sha256:
        raise RuntimeError(
            "SHA-256 precondition failed: "
            f"expected {expected_source_sha256}, current {snapshot['sha256']}"
        )

    transaction_id, transaction_dir = _new_transaction_dir(
        "secret-export",
        target,
    )
    created_target = False
    try:
        _atomic_create_bytes(target, snapshot["data"], mode=0o600)
        created_target = True
        written = _read_bound_regular_bytes(
            target,
            _minimum_policy_limit(policy, "max_read_bytes", "max_write_bytes"),
        )
        if written["sha256"] != snapshot["sha256"]:
            raise RuntimeError("Secret export hash mismatch")
        mode = statmod.S_IMODE(os.stat(target, follow_symlinks=False).st_mode)
        if mode != 0o600:
            raise RuntimeError(f"Secret export mode mismatch: {oct(mode)}")
    except Exception:
        if created_target:
            try:
                target.unlink()
                _fsync_directory(target.parent)
            except FileNotFoundError:
                pass
        raise

    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "secret-export",
        "source_path": str(source),
        "destination_path": str(target),
        "source_sha256": snapshot["sha256"],
        "destination_sha256": written["sha256"],
        "bytes": written["size"],
        "mode": oct(mode),
    }
    _write_json_evidence(transaction_dir / "export.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "secret-export",
        "transaction_id": transaction_id,
        "path": str(target),
        "source_path": str(source),
        "before_sha256": None,
        "after_sha256": written["sha256"],
        "bytes": written["size"],
        "backup": None,
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
        },
        "rollback": {
            "available": False,
            "reason": "secret export is create-only",
            "created_sha256": written["sha256"],
        },
    }
    _append_audit(record)
    return {
        **evidence,
        "audit_record_sha256": _verify_audit_log(AUDIT_LOG)["last_record_sha256"],
    }


@mcp.tool(name="grabowski_browser_profile_read", annotations=READ_ANNOTATIONS)
def grabowski_browser_profile_read(
    path: str,
    start_line: int = 1,
    max_lines: int = 200,
    max_entries: int = 100,
) -> dict[str, Any]:
    """Read bounded metadata/text under configured browser profile roots."""
    _require_capability("browser_profile_read")
    target = _resolve_browser_profile_existing(path)
    st = _nofollow_metadata(target)
    kind = "directory" if statmod.S_ISDIR(st.st_mode) else "file" if statmod.S_ISREG(st.st_mode) else "other"
    result: dict[str, Any] = {
        "path": str(target),
        "type": kind,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "mode": oct(statmod.S_IMODE(st.st_mode)),
    }
    if kind == "directory":
        policy = _load_policy()
        hard_limit = _policy_limit(policy, "max_list_entries")
        limit = min(max(1, int(max_entries)), hard_limit)
        entries: list[dict[str, Any]] = []
        for child in sorted(target.iterdir(), key=lambda p: p.name):
            if len(entries) >= limit:
                break
            child_kind, size = _nofollow_kind_and_size(child)
            entries.append({"name": child.name, "type": child_kind, "size": size})
        result.update(
            {
                "entries": entries,
                "returned": len(entries),
                "limit": limit,
                "content_returned": False,
            }
        )
        return result
    if kind != "file":
        result["content_returned"] = False
        return result

    policy = _load_policy()
    snapshot = _read_bound_regular_bytes(
        target,
        _policy_limit(policy, "max_read_bytes"),
    )
    result.update({"sha256": snapshot["sha256"], "race_checked": True})
    binary_suffixes = {
        ".db",
        ".sqlite",
        ".sqlite3",
        ".ldb",
        ".log",
        ".pma",
        ".ico",
        ".png",
        ".jpg",
        ".jpeg",
    }
    if target.suffix.lower() in binary_suffixes or b"\x00" in snapshot["data"]:
        result.update(
            {
                "content_returned": False,
                "metadata_only_reason": "binary-browser-profile-file",
            }
        )
        return result
    try:
        text = snapshot["data"].decode("utf-8")
    except UnicodeDecodeError:
        result.update(
            {
                "content_returned": False,
                "metadata_only_reason": "non-utf8-browser-profile-file",
            }
        )
        return result
    lines = text.splitlines()
    start = max(1, int(start_line))
    count = min(max(1, int(max_lines)), 1000)
    selected = lines[start - 1 : start - 1 + count]
    selected_text, redaction_count = _redact_sensitive_text("\n".join(selected))
    result.update(
        {
            "content_returned": True,
            "start_line": start,
            "end_line": start + len(selected) - 1 if selected else start - 1,
            "total_lines": len(lines),
            "text": selected_text,
            "redaction_count": redaction_count,
        }
    )
    return result


@mcp.tool(name="grabowski_create_text", annotations=CREATE_ANNOTATIONS)
def grabowski_create_text(path: str, content: str) -> dict[str, Any]:
    """Use this when a new UTF-8 text file must be created inside an allowed write root. It fails if the path already exists."""
    _require_mutations_enabled("file_write")
    target, exists = _resolve_write_target(path)
    if exists:
        raise FileExistsError(f"Refusing to overwrite existing path: {target}")

    policy = _load_policy()
    encoded = content.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL-containing content is not allowed")
    if len(encoded) > _policy_limit(policy, "max_write_bytes"):
        raise ValueError("Content exceeds configured write limit")

    transaction_id, transaction_dir = _new_transaction_dir("create", target)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, 0o600)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    after_sha = _sha256(target)
    rollback = {
        "available": False,
        "reason": "create rollback would require file_delete capability",
        "created_sha256": after_sha,
    }
    _write_json_evidence(
        transaction_dir / "rollback.json",
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "operation": "create",
            "path": str(target),
            "after_sha256": after_sha,
            "rollback": rollback,
        },
    )
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "create",
        "transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": None,
        "after_sha256": after_sha,
        "bytes": len(encoded),
        "backup": None,
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
        },
        "rollback": rollback,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_replace_text", annotations=REPLACE_ANNOTATIONS)
def grabowski_replace_text(path: str, content: str, expected_sha256: str) -> dict[str, Any]:
    """Use this when an existing allowed UTF-8 text file must be replaced atomically. The exact SHA-256 returned by grabowski_read_text or grabowski_stat is required."""
    _require_mutations_enabled("file_write")
    target, exists = _resolve_write_target(path)
    if not exists:
        raise FileNotFoundError(f"Use grabowski_create_text for new files: {target}")

    policy = _load_policy()
    encoded = content.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL-containing content is not allowed")
    if len(encoded) > _policy_limit(policy, "max_write_bytes"):
        raise ValueError("Content exceeds configured write limit")

    _ensure_regular_text_file(target, _policy_limit(policy, "max_read_bytes"))
    before_sha = _sha256(target)
    if expected_sha256 != before_sha:
        raise RuntimeError(
            f"SHA-256 precondition failed: expected {expected_sha256}, current {before_sha}"
        )

    mode = statmod.S_IMODE(target.stat().st_mode)
    transaction_id, transaction_dir = _new_transaction_dir("replace", target)
    quarantine = transaction_dir / f"before-{before_sha[:12]}.txt"
    shutil.copy2(target, quarantine, follow_symlinks=False)
    os.chmod(quarantine, 0o600)
    if _sha256(quarantine) != before_sha:
        raise RuntimeError("Quarantine preimage hash mismatch")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    after_sha = _sha256(target)
    rollback = {
        "available": True,
        "tool": "grabowski_rollback_text",
        "transaction_id": transaction_id,
        "expected_current_sha256": after_sha,
        "restore_sha256": before_sha,
        "quarantine_path": str(quarantine),
    }
    _write_json_evidence(
        transaction_dir / "rollback.json",
        {
            "schema_version": 1,
            "transaction_id": transaction_id,
            "operation": "replace",
            "path": str(target),
            "before_sha256": before_sha,
            "after_sha256": after_sha,
            "rollback": rollback,
        },
    )
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "replace",
        "transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "bytes": len(encoded),
        "backup": str(quarantine),
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": str(quarantine),
            "preimage_sha256": before_sha,
        },
        "rollback": rollback,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_remove_path", annotations=REMOVE_ANNOTATIONS)
def grabowski_remove_path(
    path: str,
    expected_type: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Remove one allowed regular file or empty directory into quarantine for audit-backed restoration."""
    _require_mutations_enabled("file_delete")
    target, exists = _resolve_write_target(path)
    if not exists:
        raise FileNotFoundError(f"Removal target is missing: {target}")
    snapshot = _removal_snapshot(target, expected_type, expected_sha256)
    transaction_id, transaction_dir = _new_transaction_dir("remove", target)

    holding: Path | None = None
    try:
        holding = _move_to_holding(target, snapshot)
        quarantine = _quarantine_removed_entry(holding, snapshot, transaction_dir)
        _remove_holding_entry(holding, snapshot)
        holding = None
    except Exception:
        if holding is not None and holding.exists() and not target.exists():
            os.replace(holding, target)
            _fsync_directory(target.parent)
        raise

    rollback = {
        "available": True,
        "tool": "grabowski_restore_removed_path",
        "transaction_id": transaction_id,
        "expected_current_absent": True,
        "restore_sha256": snapshot["sha256"],
        "restore_type": snapshot["type"],
        "quarantine_path": str(quarantine),
    }
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "remove",
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "rollback": rollback,
    }
    _write_json_evidence(transaction_dir / "remove.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "remove",
        "transaction_id": transaction_id,
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "backup": str(quarantine),
        "capability": "file_delete",
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": str(quarantine),
            "preimage_sha256": snapshot["sha256"],
            "path_type": snapshot["type"],
            "mode": oct(snapshot["mode"]),
        },
        "rollback": rollback,
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_restore_removed_path", annotations=REMOVE_ANNOTATIONS)
def grabowski_restore_removed_path(transaction_id: str) -> dict[str, Any]:
    """Restore one path from a reversible audited filesystem removal transaction."""
    _require_mutations_enabled("file_delete")
    source = _find_transaction_record(transaction_id)
    if source.get("operation") != "remove":
        raise ValueError("Only remove transactions can be restored")

    raw_path = source.get("path")
    if not isinstance(raw_path, str):
        raise ValueError("Audit transaction has no target path")
    target, exists = _resolve_write_target(raw_path)
    if exists:
        raise FileExistsError(f"Restore target already exists: {target}")

    path_type = _validate_removal_type(str(source.get("path_type")))
    quarantine_info = source.get("quarantine")
    if not isinstance(quarantine_info, dict):
        raise ValueError("Audit transaction has no quarantine metadata")
    quarantine = _audit_quarantine_path(
        quarantine_info.get("preimage_path"),
        path_type,
    )
    before_sha = source.get("before_sha256")
    if path_type == "file":
        if not isinstance(before_sha, str):
            raise ValueError("Audit transaction has no file preimage hash")
        _validate_sha256(before_sha, "before_sha256")
        if _sha256(quarantine) != before_sha:
            raise RuntimeError("Quarantine preimage hash mismatch")
    elif any(quarantine.iterdir()):
        raise RuntimeError("Quarantine directory preimage is not empty")

    mode_text = quarantine_info.get("mode", source.get("mode"))
    if not isinstance(mode_text, str) or not re.fullmatch(r"0o[0-7]{3,4}", mode_text):
        raise ValueError("Audit transaction has invalid restore mode")
    restore_mode = int(mode_text, 8)

    restore_id, restore_dir = _new_transaction_dir("restore-remove", target)
    if path_type == "file":
        data = quarantine.read_bytes()
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.grabowski-restore.",
            dir=str(target.parent),
        )
        try:
            os.fchmod(fd, restore_mode)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_name, target)
            os.chmod(target, restore_mode)
            _fsync_directory(target.parent)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
        restored_sha = _sha256(target)
        if restored_sha != before_sha:
            raise RuntimeError("Restored file hash mismatch")
        restored_bytes = target.stat().st_size
    else:
        target.mkdir(mode=restore_mode)
        os.chmod(target, restore_mode)
        _fsync_directory(target.parent)
        restored_sha = None
        restored_bytes = 0

    record = {
        "timestamp": _utc_timestamp(),
        "operation": "restore-remove",
        "transaction_id": restore_id,
        "restored_transaction_id": transaction_id,
        "path": str(target),
        "path_type": path_type,
        "before_sha256": None,
        "after_sha256": restored_sha,
        "bytes": restored_bytes,
        "mode": oct(restore_mode),
        "backup": None,
        "capability": "file_delete",
        "quarantine": {
            "directory": str(restore_dir),
            "preimage_path": None,
            "path_type": path_type,
        },
        "rollback": {
            "available": False,
            "reason": "restored removals require a new explicit remove operation",
            "created_sha256": restored_sha,
        },
    }
    _write_json_evidence(
        restore_dir / "restore.json",
        {
            "schema_version": 1,
            "transaction_id": restore_id,
            "operation": "restore-remove",
            "restored_transaction_id": transaction_id,
            "path": str(target),
            "path_type": path_type,
            "after_sha256": restored_sha,
            "bytes": restored_bytes,
        },
    )
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_destroy_path", annotations=REMOVE_ANNOTATIONS)
def grabowski_destroy_path(
    path: str,
    expected_type: str,
    confirmation: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Irreversibly remove one allowed regular file or empty directory with a separate explicit capability."""
    _require_mutations_enabled("file_destroy")
    if confirmation != "permanently-delete":
        raise ValueError("confirmation must be exactly 'permanently-delete'")
    target, exists = _resolve_write_target(path)
    if not exists:
        raise FileNotFoundError(f"Destroy target is missing: {target}")
    snapshot = _removal_snapshot(target, expected_type, expected_sha256)
    transaction_id, transaction_dir = _new_transaction_dir("destroy", target)

    holding: Path | None = None
    try:
        holding = _move_to_holding(target, snapshot)
        _remove_holding_entry(holding, snapshot)
        holding = None
    except Exception:
        if holding is not None and holding.exists() and not target.exists():
            os.replace(holding, target)
            _fsync_directory(target.parent)
        raise

    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": "destroy",
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "rollback": {
            "available": False,
            "reason": "irreversible removal was explicitly requested",
            "destroyed_sha256": snapshot["sha256"],
        },
    }
    _write_json_evidence(transaction_dir / "destroy.json", evidence)
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "destroy",
        "transaction_id": transaction_id,
        "path": str(target),
        "path_type": snapshot["type"],
        "before_sha256": snapshot["sha256"],
        "after_sha256": None,
        "bytes": snapshot["bytes"],
        "mode": oct(snapshot["mode"]),
        "backup": None,
        "capability": "file_destroy",
        "quarantine": {
            "directory": str(transaction_dir),
            "preimage_path": None,
            "path_type": snapshot["type"],
        },
        "rollback": evidence["rollback"],
    }
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_rollback_text", annotations=REPLACE_ANNOTATIONS)
def grabowski_rollback_text(transaction_id: str) -> dict[str, Any]:
    """Restore the quarantined preimage for one audited replace transaction."""
    _require_mutations_enabled("rollback_text")
    source = _find_transaction_record(transaction_id)
    if source.get("operation") != "replace":
        raise ValueError("Only replace transactions can be rolled back")

    raw_path = source.get("path")
    if not isinstance(raw_path, str):
        raise ValueError("Audit transaction has no target path")
    target, exists = _resolve_write_target(raw_path)
    if not exists:
        raise FileNotFoundError(f"Rollback target is missing: {target}")

    before_sha = source.get("before_sha256")
    after_sha = source.get("after_sha256")
    if not isinstance(before_sha, str) or not isinstance(after_sha, str):
        raise ValueError("Audit transaction has invalid hashes")
    current_sha = _sha256(target)
    if current_sha != after_sha:
        raise RuntimeError(
            f"Rollback precondition failed: expected current {after_sha}, "
            f"found {current_sha}"
        )

    quarantine_info = source.get("quarantine")
    quarantine_path: Path | None = None
    if isinstance(quarantine_info, dict) and isinstance(
        quarantine_info.get("preimage_path"),
        str,
    ):
        quarantine_path = Path(quarantine_info["preimage_path"])
    elif isinstance(source.get("backup"), str):
        quarantine_path = Path(str(source["backup"]))
    if quarantine_path is None:
        raise ValueError("Audit transaction has no quarantine preimage")
    if quarantine_path.is_symlink() or not quarantine_path.is_file():
        raise ValueError(f"Quarantine preimage is not a regular file: {quarantine_path}")
    quarantine_root = _state_subdir(QUARANTINE_DIR)
    if not _path_inside(quarantine_path.resolve(strict=True), quarantine_root):
        raise PermissionError("Quarantine preimage is outside Grabowski state")
    if _sha256(quarantine_path) != before_sha:
        raise RuntimeError("Quarantine preimage hash mismatch")

    mode = statmod.S_IMODE(target.stat().st_mode)
    rollback_id, rollback_dir = _new_transaction_dir("rollback", target)
    postimage = rollback_dir / f"rolled-back-current-{after_sha[:12]}.txt"
    shutil.copy2(target, postimage, follow_symlinks=False)
    os.chmod(postimage, 0o600)

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.grabowski.",
        dir=str(target.parent),
    )
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(quarantine_path.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
        os.chmod(target, mode)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    restored_sha = _sha256(target)
    if restored_sha != before_sha:
        raise RuntimeError("Rollback restore hash mismatch")
    record = {
        "timestamp": _utc_timestamp(),
        "operation": "rollback",
        "transaction_id": rollback_id,
        "rolled_back_transaction_id": transaction_id,
        "path": str(target),
        "before_sha256": after_sha,
        "after_sha256": restored_sha,
        "bytes": target.stat().st_size,
        "backup": str(postimage),
        "quarantine": {
            "directory": str(rollback_dir),
            "preimage_path": str(postimage),
            "preimage_sha256": after_sha,
        },
        "rollback": {
            "available": True,
            "tool": "grabowski_rollback_text",
            "transaction_id": rollback_id,
            "expected_current_sha256": restored_sha,
            "restore_sha256": after_sha,
            "quarantine_path": str(postimage),
        },
    }
    _write_json_evidence(
        rollback_dir / "rollback.json",
        {
            "schema_version": 1,
            "transaction_id": rollback_id,
            "operation": "rollback",
            "rolled_back_transaction_id": transaction_id,
            "path": str(target),
            "before_sha256": after_sha,
            "after_sha256": restored_sha,
        },
    )
    _append_audit(record)
    return record


@mcp.tool(name="grabowski_verify_audit", annotations=READ_ANNOTATIONS)
def grabowski_verify_audit() -> dict[str, Any]:
    """Verify the tamper-evident write audit hash chain."""
    _require_capability("audit_verify")
    return _verify_audit_log(AUDIT_LOG)


@mcp.tool(name="latest_complete_bundles", annotations=READ_ANNOTATIONS)
def latest_complete_bundles() -> dict[str, Any]:
    """Return the curated latest-complete Lens/repoLens bundle registry."""
    _require_capability("bundle_registry")
    if not BUNDLE_REGISTRY.is_file():
        return {
            "path": str(BUNDLE_REGISTRY),
            "exists": False,
            "rows": [],
        }

    data = _ensure_regular_text_file(BUNDLE_REGISTRY, 2_000_000)
    rows = []
    for line in data.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        rows.append(line.split("\t"))

    return {
        "path": str(BUNDLE_REGISTRY),
        "exists": True,
        "sha256": hashlib.sha256(data).hexdigest(),
        "rows": rows,
    }


if __name__ == "__main__":
    mcp.run()

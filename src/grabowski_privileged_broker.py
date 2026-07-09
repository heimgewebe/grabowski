from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

MAX_INPUT_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 512 * 1024
MAX_TTL_SECONDS = 900
MAX_ARGV_ITEMS = 128
MAX_ARG_BYTES = 32 * 1024
MAX_TARGET_BYTES = 48 * 1024
MAX_GATE_MARKER_BYTES = 64 * 1024
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
SHELL_EXECUTABLES = {
    "/bin/bash", "/usr/bin/bash",
    "/bin/sh", "/usr/bin/sh",
    "/usr/bin/env", "/bin/env",
}


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_root_config(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("broker config must be a regular non-symlink file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("broker config must be root-owned and not group/world writable")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise RuntimeError("broker config exceeds size limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema_version", "actions"}:
        raise RuntimeError("broker config has invalid top-level keys")
    if value["schema_version"] not in (1, 2) or not isinstance(value["actions"], dict):
        raise RuntimeError("broker config has unsupported schema")
    return value


def parse_reference(data: bytes, *, now: int | None = None) -> dict[str, Any]:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("privileged reference exceeds input limit")
    value = json.loads(data.decode("utf-8"))
    required = {
        "schema_version", "execution", "may_execute",
        "requires_external_privileged_agent", "replay_policy", "action",
        "target", "justification", "request_id", "created_at_unix",
        "expires_at_unix", "reference_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("privileged reference has invalid keys")
    reference_hash = value["reference_sha256"]
    unsigned = dict(value)
    unsigned.pop("reference_sha256")
    if not isinstance(reference_hash, str) or canonical_sha256(unsigned) != reference_hash:
        raise ValueError("privileged reference hash is invalid")
    if value["schema_version"] != 1:
        raise ValueError("privileged reference schema is unsupported")
    if value["execution"] != "unprivileged-reference-only" or value["may_execute"] is not False:
        raise ValueError("privileged reference execution contract is invalid")
    if value["requires_external_privileged_agent"] is not True:
        raise ValueError("privileged reference does not require a broker")
    if value["replay_policy"] != "single-use-external-broker":
        raise ValueError("privileged reference replay policy is invalid")
    if not isinstance(value["request_id"], str) or not REQUEST_ID.fullmatch(value["request_id"]):
        raise ValueError("privileged reference request_id is invalid")
    if not all(isinstance(value[key], str) and value[key].strip()
               for key in ("action", "target", "justification")):
        raise ValueError("privileged reference strings must be non-empty")
    if len(value["target"].encode("utf-8")) > MAX_TARGET_BYTES:
        raise ValueError("privileged target exceeds size limit")
    current = int(time.time()) if now is None else now
    created = value["created_at_unix"]
    expires = value["expires_at_unix"]
    if not isinstance(created, int) or not isinstance(expires, int):
        raise ValueError("privileged reference timestamps are invalid")
    if created > current + 30 or expires < current:
        raise PermissionError("privileged reference is not currently valid")
    if expires <= created or expires - created > MAX_TTL_SECONDS:
        raise ValueError("privileged reference TTL is invalid")
    return value


def _resolve_template_action(
    candidate: dict[str, Any],
    reference: dict[str, Any],
) -> dict[str, Any]:
    required = {"enabled", "target_pattern", "argv", "timeout_seconds"}
    if set(candidate) not in (required, required | {"mode"}):
        raise PermissionError("privileged action is disabled or malformed")
    if candidate.get("enabled") is not True:
        raise PermissionError("privileged action is disabled or malformed")
    if candidate.get("mode", "template") != "template":
        raise PermissionError("privileged action is disabled or malformed")
    pattern = candidate["target_pattern"]
    if not isinstance(pattern, str) or len(pattern) > 500:
        raise ValueError("privileged target pattern is invalid")
    if re.fullmatch(pattern, reference["target"]) is None:
        raise PermissionError("privileged target does not match its contract")
    template = candidate["argv"]
    timeout = candidate["timeout_seconds"]
    if not isinstance(template, list) or not template:
        raise ValueError("privileged argv template is invalid")
    if not all(isinstance(token, str) and token for token in template):
        raise ValueError("privileged argv template is invalid")
    if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise ValueError("privileged timeout is invalid")
    argv = [reference["target"] if token == "{target}" else token for token in template]
    if any("{" in token or "}" in token for token in argv):
        raise ValueError("privileged argv contains an unknown placeholder")
    if not Path(argv[0]).is_absolute():
        raise ValueError("privileged executable must be an absolute path")
    return {
        "mode": "template",
        "argv": argv,
        "cwd": None,
        "timeout_seconds": timeout,
    }


def _validate_power_argv(value: Any, *, max_argv: int, allow_shell: bool) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("power argv must be a non-empty list")
    if len(value) > max_argv or len(value) > MAX_ARGV_ITEMS:
        raise ValueError("power argv exceeds item limit")
    argv: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ValueError("power argv items must be non-empty strings")
        if "\x00" in item or len(item.encode("utf-8")) > MAX_ARG_BYTES:
            raise ValueError("power argv item is invalid")
        argv.append(item)
    if not Path(argv[0]).is_absolute():
        raise ValueError("power executable must be an absolute path")
    if not allow_shell and argv[0] in SHELL_EXECUTABLES:
        raise PermissionError("power shell execution is disabled by broker config")
    return argv


def _validate_power_cwd(value: Any, *, pattern: str) -> str:
    if value is None:
        value = "/"
    if not isinstance(value, str) or not value:
        raise ValueError("power cwd must be a non-empty string")
    if "\x00" in value or len(value.encode("utf-8")) > 1000:
        raise ValueError("power cwd is invalid")
    if not Path(value).is_absolute():
        raise ValueError("power cwd must be absolute")
    if len(pattern) > 500 or re.fullmatch(pattern, value) is None:
        raise PermissionError("power cwd does not match its contract")
    return value


def _validate_gate_path(value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if "\x00" in value or len(value.encode("utf-8")) > 1000:
        raise ValueError(f"{label} is invalid")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    return path


def _validate_power_gate(value: Any, *, now: int | None = None) -> dict[str, Any]:
    required = {
        "kill_switch_path",
        "recovery_marker_path",
        "max_recovery_age_seconds",
        "require_root_owned_gate_files",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PermissionError("power gate is disabled or malformed")
    kill_switch = _validate_gate_path(value["kill_switch_path"], label="kill_switch_path")
    if kill_switch.exists():
        raise PermissionError("power kill-switch is engaged")
    marker = _validate_gate_path(value["recovery_marker_path"], label="recovery_marker_path")
    max_age = value["max_recovery_age_seconds"]
    if not isinstance(max_age, int) or not 1 <= max_age <= 7 * 24 * 3600:
        raise ValueError("power max_recovery_age_seconds is invalid")
    require_root_owned = value["require_root_owned_gate_files"]
    if not isinstance(require_root_owned, bool):
        raise ValueError("power require_root_owned_gate_files is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker, flags)
    except FileNotFoundError as exc:
        raise PermissionError("power recovery marker does not exist") from exc
    except OSError as exc:
        raise PermissionError("power recovery marker cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PermissionError("power recovery marker must be a regular file")
        if metadata.st_mode & 0o022:
            raise PermissionError("power recovery marker must not be group/world writable")
        if require_root_owned and metadata.st_uid != 0:
            raise PermissionError("power recovery marker must be root-owned")
        if metadata.st_size <= 0 or metadata.st_size > MAX_GATE_MARKER_BYTES:
            raise ValueError("power recovery marker size is invalid")
        raw = os.read(descriptor, metadata.st_size)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size:
        raise ValueError("power recovery marker changed while being read")
    try:
        marker_json = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("power recovery marker JSON is invalid") from exc
    if not isinstance(marker_json, dict):
        raise ValueError("power recovery marker must be a JSON object")
    timestamp = marker_json.get("timestamp_unix")
    current = int(time.time()) if now is None else now
    if not isinstance(timestamp, int) or timestamp > current + 30:
        raise PermissionError("power recovery marker timestamp is invalid")
    if current - timestamp > max_age:
        raise PermissionError("power recovery marker is stale")
    for key in (
        "restore_probe_valid",
        "repository_check_valid",
        "configured_target_valid",
        "target_matches_configured",
    ):
        if marker_json.get(key) is not True:
            raise PermissionError(f"power recovery marker missing {key}=true")
    return {
        "recovery_marker_path": str(marker),
        "recovery_marker_sha256": hashlib.sha256(raw).hexdigest(),
        "recovery_marker_timestamp_unix": timestamp,
    }


def _validate_power_timeout(value: Any, *, configured_max: int) -> int:
    if not isinstance(value, int) or not 1 <= value <= 3600:
        raise ValueError("power timeout_seconds is invalid")
    if value > configured_max:
        raise PermissionError("power timeout_seconds exceeds configured maximum")
    return value


def _resolve_power_argv_action(
    candidate: dict[str, Any],
    reference: dict[str, Any],
) -> dict[str, Any]:
    required = {
        "enabled", "mode", "target_pattern", "timeout_seconds",
        "cwd_pattern", "max_argv", "allow_shell", "gate",
    }
    if set(candidate) != required or candidate["enabled"] is not True:
        raise PermissionError("privileged action is disabled or malformed")
    if candidate["mode"] != "argv-json":
        raise PermissionError("privileged action is disabled or malformed")
    pattern = candidate["target_pattern"]
    if not isinstance(pattern, str) or len(pattern) > 500:
        raise ValueError("privileged target pattern is invalid")
    if re.fullmatch(pattern, reference["target"]) is None:
        raise PermissionError("privileged target does not match its contract")
    timeout = candidate["timeout_seconds"]
    if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise ValueError("privileged timeout is invalid")
    max_argv = candidate["max_argv"]
    if not isinstance(max_argv, int) or not 1 <= max_argv <= MAX_ARGV_ITEMS:
        raise ValueError("power max_argv is invalid")
    allow_shell = candidate["allow_shell"]
    if not isinstance(allow_shell, bool):
        raise ValueError("power allow_shell is invalid")
    cwd_pattern = candidate["cwd_pattern"]
    if not isinstance(cwd_pattern, str):
        raise ValueError("power cwd_pattern is invalid")
    gate = _validate_power_gate(candidate["gate"])
    try:
        payload = json.loads(reference["target"])
    except json.JSONDecodeError as exc:
        raise ValueError("power target payload JSON is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"argv", "cwd", "timeout_seconds"}:
        raise ValueError("power target payload is invalid")
    argv = _validate_power_argv(
        payload["argv"],
        max_argv=max_argv,
        allow_shell=allow_shell,
    )
    cwd = _validate_power_cwd(payload["cwd"], pattern=cwd_pattern)
    requested_timeout = _validate_power_timeout(
        payload["timeout_seconds"],
        configured_max=timeout,
    )
    return {
        "mode": "argv-json",
        "argv": argv,
        "cwd": cwd,
        "timeout_seconds": requested_timeout,
        "configured_timeout_seconds": timeout,
        "gate": gate,
    }


def resolve_execution(config: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    candidate = config["actions"].get(reference["action"])
    if not isinstance(candidate, dict):
        raise PermissionError("privileged action is not configured")
    mode = candidate.get("mode", "template")
    if mode == "template":
        return _resolve_template_action(candidate, reference)
    if mode == "argv-json":
        return _resolve_power_argv_action(candidate, reference)
    raise PermissionError("privileged action mode is disabled or malformed")


def resolve_action(config: dict[str, Any], reference: dict[str, Any]) -> tuple[list[str], int]:
    """Resolve the legacy template-compatible argv and timeout tuple."""
    execution = resolve_execution(config, reference)
    return execution["argv"], execution["timeout_seconds"]


def claim_once(state_root: Path, request_id: str) -> Path:
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = state_root / request_id
    descriptor = os.open(
        marker,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    os.close(descriptor)
    return marker

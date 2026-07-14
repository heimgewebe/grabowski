from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Any

MAX_INPUT_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 512 * 1024
MAX_TTL_SECONDS = 900
MAX_ARGV_ITEMS = 128
MAX_ARG_BYTES = 32 * 1024
MAX_TARGET_BYTES = 48 * 1024
MAX_GATE_MARKER_BYTES = 64 * 1024
MAX_RECOVERY_AGE_SECONDS = 7 * 24 * 3600
RECOVERY_LOCK_TIMEOUT_SECONDS = 2.0
RECOVERY_LOCK_POLL_SECONDS = 0.02
RECOVERY_SOURCE_SCHEMA_VERSION = 1
RECOVERY_RECORD_SCHEMA_VERSION = 2
RECOVERY_RECORD_KIND = "grabowski_recovery_freshness"
RECOVERY_SOURCE_KEYS = frozenset({
    "schema_version", "completed_at_unix", "snapshot_id",
    "restore_probe_valid", "repository_check_valid", "target",
})
RECOVERY_RECORD_KEYS = frozenset({
    "schema_version", "kind", "generated_at_unix", "max_age_seconds",
    "snapshot_id", "restore_probe_valid", "repository_check_valid",
    "target", "configured_target", "configured_target_valid",
    "target_matches_configured", "source_record_sha256", "source_owner_uid",
})
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
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


def _validate_power_argv_prefixes(
    value: Any,
    *,
    max_argv: int,
    allow_shell: bool,
) -> list[list[str]]:
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        raise ValueError("power allowed_argv_prefixes must be a non-empty list when supplied")
    if len(value) > 256:
        raise ValueError("power allowed_argv_prefixes exceeds item limit")
    prefixes: list[list[str]] = []
    for prefix in value:
        normalized = _validate_power_argv(
            prefix,
            max_argv=max_argv,
            allow_shell=allow_shell,
        )
        prefixes.append(normalized)
    return prefixes


def _validate_power_policy_intent(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("power policy_intent must be a non-empty string when supplied")
    if len(value.encode("utf-8")) > 200:
        raise ValueError("power policy_intent exceeds size limit")
    return value


def _power_argv_matches_prefix(argv: list[str], prefix: list[str]) -> bool:
    return len(argv) >= len(prefix) and argv[: len(prefix)] == prefix


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



def _read_safe_regular_file(
    path: Path,
    *,
    label: str,
    expected_uid: int | None = None,
    require_root_owned: bool = False,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PermissionError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PermissionError(f"{label} must be a regular file")
        if before.st_mode & 0o022:
            raise PermissionError(f"{label} must not be group/world writable")
        if before.st_nlink != 1:
            raise PermissionError(f"{label} must not have multiple hard links")
        if require_root_owned and before.st_uid != 0:
            raise PermissionError(f"{label} must be root-owned")
        if expected_uid is not None and before.st_uid != expected_uid:
            raise PermissionError(f"{label} owner does not match its contract")
        if before.st_size <= 0 or before.st_size > MAX_GATE_MARKER_BYTES:
            raise ValueError(f"{label} size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    identity_before = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns, before.st_mode, before.st_uid, before.st_gid,
        before.st_nlink,
    )
    identity_after = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid,
        after.st_nlink,
    )
    if len(raw) != before.st_size or identity_before != identity_after:
        raise ValueError(f"{label} changed while being read")
    return raw, before


def _decode_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _canonical_recovery_payload(
    source: dict[str, Any],
    *,
    source_record_sha256: str,
    source_owner_uid: int,
    max_age_seconds: int,
    configured_target: str,
) -> dict[str, Any]:
    return {
        "schema_version": RECOVERY_RECORD_SCHEMA_VERSION,
        "kind": RECOVERY_RECORD_KIND,
        "generated_at_unix": source["completed_at_unix"],
        "max_age_seconds": max_age_seconds,
        "snapshot_id": source["snapshot_id"],
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "target": source["target"],
        "configured_target": configured_target,
        "configured_target_valid": True,
        "target_matches_configured": True,
        "source_record_sha256": source_record_sha256,
        "source_owner_uid": source_owner_uid,
    }


def _validate_recovery_source_record(
    raw: bytes,
    *,
    source_owner_uid: int,
    max_age_seconds: int,
    configured_target: str,
    now: int,
) -> dict[str, Any]:
    value = _decode_json_object(raw, label="recovery source record")
    if set(value) != RECOVERY_SOURCE_KEYS or value.get("schema_version") != RECOVERY_SOURCE_SCHEMA_VERSION:
        raise ValueError("recovery source record contract is invalid")
    generated_at = value.get("completed_at_unix")
    if isinstance(generated_at, bool) or not isinstance(generated_at, int):
        raise PermissionError("recovery source record timestamp is invalid")
    if generated_at > now:
        raise PermissionError("recovery source record is future-dated")
    if now - generated_at > max_age_seconds:
        raise PermissionError("recovery source record is stale")
    snapshot_id = value.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        raise PermissionError("recovery source record snapshot is invalid")
    for key in ("restore_probe_valid", "repository_check_valid"):
        if value.get(key) is not True:
            raise PermissionError(f"recovery source record missing {key}=true")
    if value.get("target") != configured_target:
        raise PermissionError("recovery source record target does not match configured target")
    source_sha256 = hashlib.sha256(raw).hexdigest()
    return {
        "source": value,
        "source_record_sha256": source_sha256,
        "canonical_record": _canonical_recovery_payload(
            value,
            source_record_sha256=source_sha256,
            source_owner_uid=source_owner_uid,
            max_age_seconds=max_age_seconds,
            configured_target=configured_target,
        ),
    }


def inspect_canonical_recovery_record(
    path: Path,
    *,
    now: int | None = None,
    expected_max_age_seconds: int | None = None,
    expected_target: str | None = None,
    require_root_owned: bool = True,
) -> dict[str, Any]:
    current = int(time.time()) if now is None else now
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "valid": False,
        "freshness_reason": "missing",
        "generated_at_unix": None,
        "age_seconds": None,
        "max_age_seconds": None,
        "record_sha256": None,
        "source_record_sha256": None,
        "snapshot_id": None,
        "target": None,
        "configured_target": None,
        "error": None,
    }
    try:
        raw, _metadata = _read_safe_regular_file(
            path,
            label="canonical recovery record",
            require_root_owned=require_root_owned,
        )
    except FileNotFoundError:
        result["error"] = "canonical recovery record is missing"
        return result
    except (OSError, PermissionError, ValueError) as exc:
        result.update({"freshness_reason": "unsafe-file", "error": str(exc)})
        return result
    result["exists"] = True
    result["record_sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        value = _decode_json_object(raw, label="canonical recovery record")
    except ValueError as exc:
        result.update({"freshness_reason": "malformed", "error": str(exc)})
        return result
    if set(value) != RECOVERY_RECORD_KEYS:
        result.update({"freshness_reason": "contract-mismatch", "error": "canonical recovery record keys are invalid"})
        return result
    if value.get("schema_version") != RECOVERY_RECORD_SCHEMA_VERSION or value.get("kind") != RECOVERY_RECORD_KIND:
        result.update({"freshness_reason": "contract-mismatch", "error": "canonical recovery record schema is invalid"})
        return result
    generated_at = value.get("generated_at_unix")
    max_age = value.get("max_age_seconds")
    result.update({
        "generated_at_unix": generated_at,
        "max_age_seconds": max_age,
        "source_record_sha256": value.get("source_record_sha256"),
        "snapshot_id": value.get("snapshot_id"),
        "target": value.get("target"),
        "configured_target": value.get("configured_target"),
    })
    if isinstance(generated_at, bool) or not isinstance(generated_at, int):
        result.update({"freshness_reason": "malformed", "error": "canonical recovery record timestamp is invalid"})
        return result
    if generated_at > current:
        result.update({"freshness_reason": "future-dated", "age_seconds": generated_at - current, "error": "canonical recovery record is future-dated"})
        return result
    age = current - generated_at
    result["age_seconds"] = age
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= MAX_RECOVERY_AGE_SECONDS:
        result.update({"freshness_reason": "malformed", "error": "canonical recovery record max-age is invalid"})
        return result
    if expected_max_age_seconds is not None and max_age != expected_max_age_seconds:
        result.update({"freshness_reason": "max-age-mismatch", "error": "canonical recovery max-age does not match configured gate"})
        return result
    if age > max_age:
        result.update({"freshness_reason": "stale", "error": "canonical recovery record is stale"})
        return result
    if value.get("restore_probe_valid") is not True or value.get("repository_check_valid") is not True:
        result.update({"freshness_reason": "incomplete", "error": "canonical recovery evidence is incomplete"})
        return result
    if value.get("configured_target_valid") is not True or value.get("target_matches_configured") is not True:
        result.update({"freshness_reason": "target-mismatch", "error": "canonical recovery target flags are invalid"})
        return result
    target = value.get("target")
    configured_target = value.get("configured_target")
    if not isinstance(target, str) or not target or target != configured_target:
        result.update({"freshness_reason": "target-mismatch", "error": "canonical recovery target contract is invalid"})
        return result
    if expected_target is not None and configured_target != expected_target:
        result.update({"freshness_reason": "target-mismatch", "error": "canonical recovery target differs from runtime configuration"})
        return result
    source_sha = value.get("source_record_sha256")
    if not isinstance(source_sha, str) or SHA256_RE.fullmatch(source_sha) is None:
        result.update({"freshness_reason": "malformed", "error": "canonical recovery source digest is invalid"})
        return result
    source_uid = value.get("source_owner_uid")
    if isinstance(source_uid, bool) or not isinstance(source_uid, int) or source_uid < 0:
        result.update({"freshness_reason": "malformed", "error": "canonical recovery source owner is invalid"})
        return result
    snapshot_id = value.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        result.update({"freshness_reason": "malformed", "error": "canonical recovery snapshot is invalid"})
        return result
    result.update({"valid": True, "freshness_reason": "ready", "error": None, "record": value})
    return result


def _atomic_write_recovery_record(
    destination: Path,
    value: dict[str, Any],
    *,
    require_root_owned_destination: bool,
) -> str:
    parent = destination.parent
    metadata = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError("recovery destination parent must be a regular directory")
    if require_root_owned_destination and metadata.st_uid != 0:
        raise PermissionError("recovery destination parent must be root-owned")
    if metadata.st_mode & 0o022:
        raise PermissionError("recovery destination parent must not be group/world writable")
    parent_identity = (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid)
    if destination.exists() or destination.is_symlink():
        existing = destination.lstat()
        if destination.is_symlink() or not stat.S_ISREG(existing.st_mode):
            raise PermissionError("recovery destination must be a regular non-symlink file")
        if require_root_owned_destination and existing.st_uid != 0:
            raise PermissionError("recovery destination must be root-owned")
        if existing.st_nlink != 1:
            raise PermissionError("recovery destination must not have multiple hard links")

    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".grabowski-recovery-", dir=parent)
    temporary = Path(temporary_name)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        current_parent = parent.lstat()
        current_identity = (
            current_parent.st_dev, current_parent.st_ino, current_parent.st_mode,
            current_parent.st_uid, current_parent.st_gid,
        )
        if current_identity != parent_identity:
            raise PermissionError("recovery destination parent changed before replace")
        os.replace(temporary, destination)
        readback = destination.lstat()
        if destination.is_symlink() or not stat.S_ISREG(readback.st_mode):
            raise RuntimeError("recovery destination readback is not a regular file")
        if stat.S_IMODE(readback.st_mode) != 0o644:
            raise RuntimeError("recovery destination readback mode is invalid")
        if require_root_owned_destination and readback.st_uid != 0:
            raise RuntimeError("recovery destination readback is not root-owned")
        if readback.st_nlink != 1:
            raise RuntimeError("recovery destination readback has multiple hard links")
        directory_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()


def _resolve_recovery_marker_publish_action(
    candidate: dict[str, Any],
    reference: dict[str, Any],
    *,
    now: int | None = None,
) -> dict[str, Any]:
    required = {
        "enabled", "mode", "source_path", "destination_path",
        "expected_source_uid", "max_recovery_age_seconds", "configured_target",
        "kill_switch_path", "require_root_owned_destination",
    }
    if not isinstance(candidate, dict) or set(candidate) != required or candidate.get("enabled") is not True:
        raise PermissionError("recovery marker publisher is disabled or malformed")
    if candidate.get("mode") != "recovery-marker-publish":
        raise PermissionError("recovery marker publisher mode is invalid")
    source_path = _validate_gate_path(candidate["source_path"], label="source_path")
    destination_path = _validate_gate_path(candidate["destination_path"], label="destination_path")
    kill_switch = _validate_gate_path(candidate["kill_switch_path"], label="kill_switch_path")
    if kill_switch.exists():
        raise PermissionError("power kill-switch is engaged")
    expected_uid = candidate["expected_source_uid"]
    max_age = candidate["max_recovery_age_seconds"]
    configured_target = candidate["configured_target"]
    require_root_destination = candidate["require_root_owned_destination"]
    if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) or expected_uid < 0:
        raise ValueError("recovery expected_source_uid is invalid")
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= MAX_RECOVERY_AGE_SECONDS:
        raise ValueError("recovery max_recovery_age_seconds is invalid")
    if not isinstance(configured_target, str) or not configured_target:
        raise ValueError("recovery configured_target is invalid")
    if not isinstance(require_root_destination, bool):
        raise ValueError("recovery require_root_owned_destination is invalid")
    try:
        target = json.loads(reference["target"])
    except json.JSONDecodeError as exc:
        raise ValueError("recovery publish target JSON is invalid") from exc
    if not isinstance(target, dict) or set(target) != {"source_record_sha256", "generated_at_unix"}:
        raise ValueError("recovery publish target contract is invalid")
    expected_sha = target.get("source_record_sha256")
    expected_generated = target.get("generated_at_unix")
    if not isinstance(expected_sha, str) or SHA256_RE.fullmatch(expected_sha) is None:
        raise ValueError("recovery publish source digest is invalid")
    if isinstance(expected_generated, bool) or not isinstance(expected_generated, int):
        raise ValueError("recovery publish generated_at_unix is invalid")
    current = int(time.time()) if now is None else now
    raw, metadata = _read_safe_regular_file(
        source_path,
        label="recovery source record",
        expected_uid=expected_uid,
    )
    validated = _validate_recovery_source_record(
        raw,
        source_owner_uid=metadata.st_uid,
        max_age_seconds=max_age,
        configured_target=configured_target,
        now=current,
    )
    if validated["source_record_sha256"] != expected_sha:
        raise PermissionError("recovery source digest changed before publication")
    if validated["source"]["completed_at_unix"] != expected_generated:
        raise PermissionError("recovery source generation changed before publication")
    return {
        "mode": "recovery-marker-publish",
        "internal_action": "publish-recovery-marker",
        "source_path": str(source_path),
        "destination_path": str(destination_path),
        "expected_source_uid": expected_uid,
        "expected_source_record_sha256": expected_sha,
        "expected_generated_at_unix": expected_generated,
        "max_recovery_age_seconds": max_age,
        "configured_target": configured_target,
        "kill_switch_path": str(kill_switch),
        "require_root_owned_destination": require_root_destination,
    }


def _require_kill_switch_clear(path: Path) -> None:
    if path.exists():
        raise PermissionError("power kill-switch is engaged")


def _acquire_recovery_lock(
    descriptor: int,
    *,
    timeout_seconds: float | None = None,
) -> None:
    timeout = RECOVERY_LOCK_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PermissionError(
                    "canonical recovery marker is currently locked by another process"
                ) from exc
            time.sleep(min(RECOVERY_LOCK_POLL_SECONDS, remaining))


def _validated_recovery_source_for_execution(
    execution: dict[str, Any],
    *,
    now: int,
) -> dict[str, Any]:
    source_path = Path(execution["source_path"])
    raw, metadata = _read_safe_regular_file(
        source_path,
        label="recovery source record",
        expected_uid=execution["expected_source_uid"],
    )
    validated = _validate_recovery_source_record(
        raw,
        source_owner_uid=metadata.st_uid,
        max_age_seconds=execution["max_recovery_age_seconds"],
        configured_target=execution["configured_target"],
        now=now,
    )
    source_sha = validated["source_record_sha256"]
    generated_at = validated["source"]["completed_at_unix"]
    if (
        source_sha != execution["expected_source_record_sha256"]
        or generated_at != execution["expected_generated_at_unix"]
    ):
        raise PermissionError("recovery source changed after reference validation")
    return validated


def publish_recovery_marker(execution: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
    if execution.get("mode") != "recovery-marker-publish" or execution.get("internal_action") != "publish-recovery-marker":
        raise ValueError("recovery marker execution contract is invalid")
    current = int(time.time()) if now is None else now
    kill_switch = Path(execution["kill_switch_path"])
    _require_kill_switch_clear(kill_switch)
    destination = Path(execution["destination_path"])
    max_age = execution["max_recovery_age_seconds"]
    configured_target = execution["configured_target"]
    require_root_destination = execution["require_root_owned_destination"]
    lock_path = destination.with_name(destination.name + ".lock")
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    locked = False
    try:
        lock_metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_metadata.st_mode):
            raise PermissionError("canonical recovery lock must be a regular file")
        if lock_metadata.st_nlink != 1:
            raise PermissionError("canonical recovery lock must not have multiple hard links")
        if require_root_destination and lock_metadata.st_uid != 0:
            raise PermissionError("canonical recovery lock must be root-owned")
        os.fchmod(lock_fd, 0o600)
        _acquire_recovery_lock(lock_fd)
        locked = True
        _require_kill_switch_clear(kill_switch)

        validated = _validated_recovery_source_for_execution(execution, now=current)
        source_sha = validated["source_record_sha256"]
        generated_at = validated["source"]["completed_at_unix"]
        existing = inspect_canonical_recovery_record(
            destination,
            now=current,
            expected_max_age_seconds=max_age,
            expected_target=configured_target,
            require_root_owned=require_root_destination,
        )
        existing_generated = existing.get("generated_at_unix")
        if isinstance(existing_generated, int):
            if existing_generated > generated_at:
                raise PermissionError("recovery generation rollback is forbidden")
            if existing_generated == generated_at:
                if existing.get("source_record_sha256") == source_sha and existing.get("record_sha256"):
                    return {
                        "published": False,
                        "idempotent": True,
                        "record_sha256": existing["record_sha256"],
                        "source_record_sha256": source_sha,
                        "generated_at_unix": generated_at,
                        "freshness_reason": existing.get("freshness_reason"),
                    }
                raise PermissionError("recovery generation collision is forbidden")

        _require_kill_switch_clear(kill_switch)
        final_source = _validated_recovery_source_for_execution(execution, now=current)
        if final_source["source_record_sha256"] != source_sha:
            raise PermissionError("recovery source changed before canonical replace")
        _atomic_write_recovery_record(
            destination,
            final_source["canonical_record"],
            require_root_owned_destination=require_root_destination,
        )
        readback = inspect_canonical_recovery_record(
            destination,
            now=current,
            expected_max_age_seconds=max_age,
            expected_target=configured_target,
            require_root_owned=require_root_destination,
        )
        if not readback.get("valid") or readback.get("source_record_sha256") != source_sha:
            raise RuntimeError("canonical recovery record readback failed")
        return {
            "published": True,
            "idempotent": False,
            "record_sha256": readback["record_sha256"],
            "source_record_sha256": source_sha,
            "generated_at_unix": generated_at,
            "freshness_reason": readback["freshness_reason"],
        }
    finally:
        if locked:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _validate_power_gate(value: Any, *, now: int | None = None) -> dict[str, Any]:
    required = {
        "kill_switch_path",
        "recovery_marker_path",
        "max_recovery_age_seconds",
        "require_root_owned_gate_files",
        "configured_target",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise PermissionError("power gate is disabled or malformed")
    kill_switch = _validate_gate_path(value["kill_switch_path"], label="kill_switch_path")
    if kill_switch.exists():
        raise PermissionError("power kill-switch is engaged")
    marker = _validate_gate_path(value["recovery_marker_path"], label="recovery_marker_path")
    max_age = value["max_recovery_age_seconds"]
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= MAX_RECOVERY_AGE_SECONDS:
        raise ValueError("power max_recovery_age_seconds is invalid")
    require_root_owned = value["require_root_owned_gate_files"]
    if not isinstance(require_root_owned, bool):
        raise ValueError("power require_root_owned_gate_files is invalid")
    configured_target = value["configured_target"]
    if not isinstance(configured_target, str) or not configured_target:
        raise ValueError("power configured_target is invalid")
    inspected = inspect_canonical_recovery_record(
        marker,
        now=now,
        expected_max_age_seconds=max_age,
        expected_target=configured_target,
        require_root_owned=require_root_owned,
    )
    if not inspected.get("valid"):
        reason = inspected.get("freshness_reason")
        if reason == "missing":
            raise PermissionError("power recovery marker does not exist")
        if reason == "stale":
            raise PermissionError("power recovery marker is stale")
        if reason == "future-dated":
            raise PermissionError("power recovery marker timestamp is invalid")
        if reason == "unsafe-file":
            raise PermissionError("power recovery marker cannot be opened safely")
        if reason == "malformed":
            raise ValueError("power recovery marker JSON is invalid")
        if reason == "max-age-mismatch":
            raise PermissionError("power recovery marker max-age contract mismatch")
        if reason in {"target-mismatch", "incomplete", "contract-mismatch"}:
            raise PermissionError(f"power recovery marker is not ready: {reason}")
        raise PermissionError("power recovery marker is not ready")
    return {
        "recovery_marker_path": str(marker),
        "recovery_marker_sha256": inspected["record_sha256"],
        "recovery_marker_source_sha256": inspected["source_record_sha256"],
        "recovery_marker_timestamp_unix": inspected["generated_at_unix"],
        "recovery_marker_age_seconds": inspected["age_seconds"],
        "recovery_marker_max_age_seconds": inspected["max_age_seconds"],
        "recovery_marker_freshness_reason": inspected["freshness_reason"],
        "recovery_marker_configured_target": inspected["configured_target"],
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
    optional = {"allowed_argv_prefixes", "policy_intent"}
    candidate_keys = set(candidate)
    if not required.issubset(candidate_keys) or candidate_keys - required - optional or candidate["enabled"] is not True:
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
    policy_intent = _validate_power_policy_intent(candidate.get("policy_intent"))
    allowed_argv_prefixes = _validate_power_argv_prefixes(
        candidate.get("allowed_argv_prefixes"),
        max_argv=max_argv,
        allow_shell=allow_shell,
    )
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
    matched_argv_prefix: list[str] | None = None
    if allowed_argv_prefixes:
        for prefix in allowed_argv_prefixes:
            if _power_argv_matches_prefix(argv, prefix):
                matched_argv_prefix = prefix
                break
        if matched_argv_prefix is None:
            raise PermissionError("power argv is not allowed by configured catalog")
    cwd = _validate_power_cwd(payload["cwd"], pattern=cwd_pattern)
    requested_timeout = _validate_power_timeout(
        payload["timeout_seconds"],
        configured_max=timeout,
    )
    execution = {
        "mode": "argv-json",
        "argv": argv,
        "cwd": cwd,
        "timeout_seconds": requested_timeout,
        "configured_timeout_seconds": timeout,
        "gate": gate,
    }
    if policy_intent is not None:
        execution["policy_intent"] = policy_intent
    if allowed_argv_prefixes:
        execution["argv_catalog_sha256"] = canonical_sha256(allowed_argv_prefixes)
        execution["matched_argv_prefix_sha256"] = canonical_sha256(matched_argv_prefix)
    return execution


def resolve_execution(config: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    candidate = config["actions"].get(reference["action"])
    if not isinstance(candidate, dict):
        raise PermissionError("privileged action is not configured")
    mode = candidate.get("mode", "template")
    if mode == "template":
        return _resolve_template_action(candidate, reference)
    if mode == "argv-json":
        return _resolve_power_argv_action(candidate, reference)
    if mode == "recovery-marker-publish":
        return _resolve_recovery_marker_publish_action(candidate, reference)
    raise PermissionError("privileged action mode is disabled or malformed")


def resolve_action(config: dict[str, Any], reference: dict[str, Any]) -> tuple[list[str], int]:
    """Resolve the legacy template-compatible argv and timeout tuple."""
    execution = resolve_execution(config, reference)
    if "argv" not in execution or "timeout_seconds" not in execution:
        raise PermissionError("internal privileged action has no argv contract")
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

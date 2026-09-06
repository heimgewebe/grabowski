from __future__ import annotations

from datetime import datetime
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any

import grabowski_mcp as base
import grabowski_privileged as privileged
import grabowski_privileged_broker as broker_contract
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

try:
    alert_outbox = importlib.import_module("grabowski_alert_outbox")
except ModuleNotFoundError as exc:
    if exc.name != "grabowski_alert_outbox":
        raise
    alert_outbox = None


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
BACKUP_SUCCESS = Path(os.environ.get(
    "GRABOWSKI_BACKUP_SUCCESS_MARKER",
    str(operator.HOME / ".local/state/heim-pc-priorities/last-restic-backup-success.txt"),
)).expanduser()
SERVER_RECOVERY = Path(os.environ.get(
    "GRABOWSKI_SERVER_RECOVERY_MARKER",
    str(operator.STATE_DIR / "recovery/last-server-recovery.json"),
)).expanduser()
CANONICAL_RECOVERY = Path(os.environ.get(
    "GRABOWSKI_CANONICAL_RECOVERY_MARKER",
    "/var/lib/grabowski/power-worker-recovery-gate.json",
)).expanduser()
BACKUP_TIMER = os.environ.get("GRABOWSKI_BACKUP_TIMER", "restic-backup-1930.timer")
MAX_AGE_SECONDS = int(os.environ.get("GRABOWSKI_RECOVERY_MAX_AGE_SECONDS", str(24 * 60 * 60)))
DEFAULT_SERVER_RECOVERY_HOST = "heimberry"
DEFAULT_SERVER_RECOVERY_TARGET = "local-backup-disk:UUID=249180DA265E8DE0/restic/heim-pc"
SERVER_RECOVERY_HOST = os.environ.get("GRABOWSKI_SERVER_RECOVERY_HOST", DEFAULT_SERVER_RECOVERY_HOST)
SERVER_RECOVERY_REMOTE_PORT = int(os.environ.get("GRABOWSKI_SERVER_RECOVERY_REMOTE_PORT", "18081"))
SERVER_RECOVERY_REST_USER = os.environ.get("GRABOWSKI_SERVER_RECOVERY_REST_USER", "grabowski")
SERVER_RECOVERY_REPO_PATH = os.environ.get("GRABOWSKI_SERVER_RECOVERY_REPO_PATH", "grabowski-recovery-probe")
SERVER_RECOVERY_TARGET = os.environ.get("GRABOWSKI_SERVER_RECOVERY_TARGET", DEFAULT_SERVER_RECOVERY_TARGET)
SERVER_RECOVERY_HTTP_PASSWORD = Path(os.environ.get(
    "GRABOWSKI_SERVER_RECOVERY_HTTP_PASSWORD_FILE",
    str(operator.HOME / ".config/restic/heimserver-recovery-http-password"),
)).expanduser()
SERVER_RECOVERY_REPOSITORY_PASSWORD = Path(os.environ.get(
    "GRABOWSKI_SERVER_RECOVERY_REPOSITORY_PASSWORD_FILE",
    str(operator.HOME / ".config/restic/heimserver-recovery-repository-password"),
)).expanduser()
RESTIC_BIN = os.environ.get("GRABOWSKI_RESTIC_BIN", "/usr/bin/restic")
SSH_BIN = os.environ.get("GRABOWSKI_SSH_BIN", "/usr/bin/ssh")
LOCAL_RECOVERY_MOUNT = Path(os.environ.get("GRABOWSKI_LOCAL_RECOVERY_MOUNT", "/mnt/backup")).expanduser()
LOCAL_RECOVERY_REPOSITORY_ID = os.environ.get(
    "GRABOWSKI_LOCAL_RECOVERY_REPOSITORY_ID",
    "d107caf1705b0d0a1b2b36751e7d0a5e01f8108eede760fc646c7b9f8f128f4d",
)
LOCAL_RECOVERY_RUN_MAX_SECONDS = int(
    os.environ.get("GRABOWSKI_LOCAL_RECOVERY_RUN_MAX_SECONDS", "7200")
)
LOCAL_RECOVERY_PASSWORD_FILE = Path(os.environ.get(
    "GRABOWSKI_LOCAL_RECOVERY_PASSWORD_FILE",
    str(operator.HOME / ".config/restic/heim-pc-password"),
)).expanduser()
LOCAL_RECOVERY_DURABILITY_EVIDENCE = Path(os.environ.get(
    "GRABOWSKI_LOCAL_RECOVERY_DURABILITY_EVIDENCE",
    str(operator.HOME / ".local/state/schauwerk/fundus/durability/current.json"),
)).expanduser()
SERVER_RECOVERY_CHECK_SUBSET = os.environ.get("GRABOWSKI_SERVER_RECOVERY_CHECK_SUBSET", "1/100")
SERVER_RECOVERY_TIMEOUT_SECONDS = int(os.environ.get("GRABOWSKI_SERVER_RECOVERY_TIMEOUT_SECONDS", "300"))
SERVER_RECOVERY_TUNNEL_OUTPUT_MAX_BYTES = int(os.environ.get("GRABOWSKI_SERVER_RECOVERY_TUNNEL_OUTPUT_MAX_BYTES", "4096"))
HEIMSERVER_RECOVERY_ALIASES_ENV = "GRABOWSKI_HEIMSERVER_RECOVERY_ALIASES"
DEFAULT_HEIMSERVER_RECOVERY_ALIASES = "heimserver"
RECOVERY_STATUS_FRESH_EVIDENCE_PRESENT = "fresh_evidence_present"
RECOVERY_STATUS_BLOCKED_ON_DEFAULT_HEIMSERVER = "blocked_on_default_heimserver_or_alternate_recovery_target"
RECOVERY_STATUS_BLOCKED_UNTIL_CONFIGURED_TARGET_PROBE_SUCCEEDS = "blocked_until_configured_target_probe_succeeds"
RECOVERY_STATUS_BLOCKED_TARGET_MISMATCH = "blocked_on_recovery_target_mismatch"
RECOVERY_STATUS_BLOCKED_INVALID_TARGET = "blocked_on_invalid_recovery_target_configuration"
RECOVERY_TARGET_RE = re.compile(r"^(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{0,127}):rest-server/(?P<probe>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
LOCAL_RECOVERY_TARGET_RE = re.compile(
    r"^local-backup-disk:UUID=(?P<uuid>[A-Fa-f0-9][A-Fa-f0-9-]{3,63})/restic/(?P<repository>[A-Za-z0-9][A-Za-z0-9._-]{0,127})$"
)
TEST_KILL_SWITCH_KIND = "grabowski_operator_kill_switch_test"
TEST_KILL_SWITCH_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
TEST_KILL_SWITCH_MAX_LIFETIME_SECONDS = 5 * 60
TEST_KILL_SWITCH_CLEAR_MAX_AGE_SECONDS = 24 * 60 * 60
TEST_KILL_SWITCH_CLOCK_SKEW_SECONDS = 15
TEST_KILL_SWITCH_MAX_BYTES = 4096


def _normalize_recovery_host(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    if not text or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in text):
        return ""
    if any(char in text for char in ("/", "\\", "@", "[", "]")):
        return ""
    return text


def _recovery_target_info(value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target": value if isinstance(value, str) else None,
        "valid": False,
        "kind": None,
        "host": None,
        "probe": None,
        "backup_uuid": None,
        "repository_name": None,
        "error": None,
    }
    if not isinstance(value, str):
        result["error"] = "recovery target must be a string"
        return result
    if value != value.strip():
        result["error"] = "recovery target must not contain surrounding whitespace"
        return result
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        result["error"] = "recovery target must not be empty or contain whitespace/control characters"
        return result
    server_match = RECOVERY_TARGET_RE.fullmatch(value)
    if server_match is not None:
        host = _normalize_recovery_host(server_match.group("host"))
        if not host:
            result["error"] = "server recovery target host is invalid"
            return result
        result.update({
            "valid": True,
            "kind": "rest_server",
            "host": host,
            "probe": server_match.group("probe"),
            "error": None,
        })
        return result
    local_match = LOCAL_RECOVERY_TARGET_RE.fullmatch(value)
    if local_match is not None:
        result.update({
            "valid": True,
            "kind": "local_backup_disk",
            "backup_uuid": local_match.group("uuid"),
            "repository_name": local_match.group("repository"),
            "error": None,
        })
        return result
    result["error"] = (
        "recovery target must match <host>:rest-server/<probe> or "
        "local-backup-disk:UUID=<uuid>/restic/<repository>"
    )
    return result


def _configured_recovery_target_info() -> dict[str, Any]:
    return _recovery_target_info(SERVER_RECOVERY_TARGET)


def _configured_recovery_target_host() -> str:
    info = _configured_recovery_target_info()
    host = info.get("host")
    return str(host) if isinstance(host, str) else ""


def _heimserver_recovery_aliases() -> frozenset[str]:
    raw = os.environ.get(HEIMSERVER_RECOVERY_ALIASES_ENV, DEFAULT_HEIMSERVER_RECOVERY_ALIASES)
    aliases = {_normalize_recovery_host(part) for part in raw.split(",")}
    aliases.discard("")
    return frozenset(aliases or {"heimserver"})


def _uses_default_heimserver_recovery_backend() -> bool:
    target_info = _configured_recovery_target_info()
    if target_info.get("kind") != "rest_server":
        return False
    aliases = _heimserver_recovery_aliases()
    host = _normalize_recovery_host(SERVER_RECOVERY_HOST)
    target_host = _configured_recovery_target_host()
    return host in aliases or target_host in aliases


def _server_recovery_target_matches_configured(server_marker: dict[str, Any]) -> bool:
    target_info = _configured_recovery_target_info()
    return bool(target_info.get("valid")) and server_marker.get("target") == SERVER_RECOVERY_TARGET


def _server_recovery_evidence_fresh(server_marker: dict[str, Any]) -> bool:
    return bool(server_marker.get("valid")) and _server_recovery_target_matches_configured(server_marker)


def _server_recovery_evidence_boundary(server_marker: dict[str, Any]) -> dict[str, Any]:
    target_info = _configured_recovery_target_info()
    configured_target_valid = bool(target_info.get("valid"))
    uses_default_heimserver_backend = _uses_default_heimserver_recovery_backend()
    target_matches_configured = _server_recovery_target_matches_configured(server_marker)
    server_fresh = _server_recovery_evidence_fresh(server_marker)
    if not configured_target_valid:
        status = RECOVERY_STATUS_BLOCKED_INVALID_TARGET
    elif server_fresh:
        status = RECOVERY_STATUS_FRESH_EVIDENCE_PRESENT
    elif bool(server_marker.get("target")) and not target_matches_configured:
        status = RECOVERY_STATUS_BLOCKED_TARGET_MISMATCH
    elif uses_default_heimserver_backend:
        status = RECOVERY_STATUS_BLOCKED_ON_DEFAULT_HEIMSERVER
    else:
        status = RECOVERY_STATUS_BLOCKED_UNTIL_CONFIGURED_TARGET_PROBE_SUCCEEDS
    boundary_kind = (
        "local_restic_backup_restore_check"
        if target_info.get("kind") == "local_backup_disk"
        else "ssh_tunnelled_restic_backup_restore_check"
    )
    return {
        "schema_version": 1,
        "kind": boundary_kind,
        "target_kind": target_info.get("kind"),
        "server_recovery_host": (
            SERVER_RECOVERY_HOST if target_info.get("kind") == "rest_server" else None
        ),
        "server_recovery_target": SERVER_RECOVERY_TARGET,
        "marker_target": server_marker.get("target"),
        "configured_target": SERVER_RECOVERY_TARGET,
        "configured_target_valid": configured_target_valid,
        "configured_target_host": target_info.get("host"),
        "configured_target_probe": target_info.get("probe"),
        "configured_target_backup_uuid": target_info.get("backup_uuid"),
        "configured_target_repository": target_info.get("repository_name"),
        "configured_target_error": target_info.get("error"),
        "target_matches_configured": target_matches_configured,
        "heimserver_recovery_aliases": sorted(_heimserver_recovery_aliases()),
        "uses_default_heimserver_backend": uses_default_heimserver_backend,
        "custom_recovery_target_configured": configured_target_valid and not uses_default_heimserver_backend,
        "status": status,
        "runtime_health_is_separate": True,
        "high_impact_actions_remain_blocked_until_fresh_server_evidence": not server_fresh,
        "does_not_establish": [
            "runtime health does not prove restore readiness",
            "stale recovery markers do not authorize privileged or power-worker actions",
            "a configured recovery target is sufficient only after backup, restore and repository checks pass",
            "recovery evidence for one target authorizes no other configured target",
        ],
    }


def _bounded_file(path: Path) -> bool:
    return not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536


def _iso_timestamp_unix(value: str) -> int:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    extended_fraction = re.fullmatch(
        r"(?P<prefix>.*\.\d{6})\d+(?P<offset>[+-]\d{2}:\d{2})",
        normalized,
    )
    if extended_fraction is not None:
        normalized = (
            extended_fraction.group("prefix")
            + extended_fraction.group("offset")
        )
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return int(parsed.timestamp())


def _timestamp(value: str) -> int:
    text = value.strip()
    try:
        return int(text)
    except ValueError:
        return _iso_timestamp_unix(text)


def _fresh_text_marker(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "valid": False,
        "timestamp_unix": None,
        "age_seconds": None,
        "error": None,
    }
    if not _bounded_file(path):
        result["error"] = "marker is missing or invalid"
        return result
    try:
        stamp = _timestamp(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        result["error"] = str(exc)
        return result
    delta = int(time.time()) - stamp
    age = max(0, delta)
    result["timestamp_unix"] = stamp
    result["age_seconds"] = age
    result["valid"] = 0 <= delta <= MAX_AGE_SECONDS
    if delta < 0:
        result["error"] = "marker is future-dated"
    elif not result["valid"]:
        result["error"] = "marker is stale"
    return result


def _server_source_marker() -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(SERVER_RECOVERY), "exists": SERVER_RECOVERY.exists(),
        "valid": False, "timestamp_unix": None, "age_seconds": None,
        "source_record_sha256": None,
        "snapshot_id": None, "restore_probe_valid": False,
        "repository_check_valid": False, "target": None,
        "configured_target": SERVER_RECOVERY_TARGET,
        "configured_target_valid": _configured_recovery_target_info()["valid"],
        "target_matches_configured": False,
        "error": None,
    }
    try:
        snapshot = base._read_bound_regular_bytes(SERVER_RECOVERY, 65536)
        linked = os.stat(SERVER_RECOVERY, follow_symlinks=False)
        if (linked.st_dev, linked.st_ino) != (snapshot["dev"], snapshot["ino"]):
            raise RuntimeError("server marker changed during validation")
        if linked.st_uid != os.getuid() or stat.S_IMODE(linked.st_mode) != 0o600:
            raise PermissionError("server marker owner or mode is invalid")
        raw = snapshot["data"]
        value = json.loads(raw.decode("utf-8"))
    except (OSError, PermissionError, RuntimeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
        return result
    required = {"schema_version", "completed_at_unix", "snapshot_id", "restore_probe_valid", "repository_check_valid", "target"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1:
        result["error"] = "server marker contract is invalid"
        return result
    stamp = value["completed_at_unix"]
    if not isinstance(stamp, int):
        result["error"] = "server marker timestamp is invalid"
        return result
    delta = int(time.time()) - stamp
    age = max(0, delta)
    marker_target = value["target"]
    target_info = _configured_recovery_target_info()
    configured_target_valid = bool(target_info.get("valid"))
    target_matches_configured = configured_target_valid and marker_target == SERVER_RECOVERY_TARGET
    result.update({
        "timestamp_unix": stamp, "age_seconds": age,
        "source_record_sha256": hashlib.sha256(raw).hexdigest(),
        "snapshot_id": value["snapshot_id"],
        "restore_probe_valid": value["restore_probe_valid"] is True,
        "repository_check_valid": value["repository_check_valid"] is True,
        "target": marker_target,
        "configured_target": SERVER_RECOVERY_TARGET,
        "configured_target_valid": configured_target_valid,
        "target_matches_configured": target_matches_configured,
    })
    base_valid = all((
        0 <= delta <= MAX_AGE_SECONDS,
        isinstance(result["snapshot_id"], str) and bool(result["snapshot_id"]),
        result["restore_probe_valid"], result["repository_check_valid"],
        isinstance(result["target"], str) and bool(result["target"]),
    ))
    result["valid"] = base_valid and target_matches_configured
    if not configured_target_valid:
        result["error"] = str(target_info.get("error") or "server recovery target configuration is invalid")
    elif delta < 0:
        result["error"] = "server recovery evidence is future-dated"
    elif not base_valid:
        result["error"] = "server recovery evidence is incomplete or stale"
    elif not target_matches_configured:
        result["error"] = "server recovery target does not match configured target"
    return result



def _canonical_server_marker() -> dict[str, Any]:
    return broker_contract.inspect_canonical_recovery_record(
        CANONICAL_RECOVERY,
        expected_max_age_seconds=MAX_AGE_SECONDS,
        expected_target=SERVER_RECOVERY_TARGET,
        require_root_owned=True,
    )


def _source_publication_state(
    canonical: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    source_digest = source.get("source_record_sha256")
    canonical_digest = canonical.get("source_record_sha256")
    source_valid = bool(source.get("valid"))
    digest_valid = (
        isinstance(source_digest, str)
        and len(source_digest) == 64
        and all(character in "0123456789abcdef" for character in source_digest)
    )
    aligned = (
        source_valid
        and digest_valid
        and bool(canonical.get("valid"))
        and source_digest == canonical_digest
        and source.get("timestamp_unix") == canonical.get("generated_at_unix")
        and source.get("snapshot_id") == canonical.get("snapshot_id")
        and source.get("target") == canonical.get("target")
    )
    if aligned:
        reason = "published-current-source"
    elif not source_valid or not digest_valid:
        reason = "source-evidence-unavailable"
    elif not canonical.get("valid"):
        reason = "canonical-record-not-ready"
    else:
        reason = "source-publication-pending"
    return {
        "current": aligned,
        "reason": reason,
        "source_record_sha256": source_digest,
        "canonical_source_record_sha256": canonical_digest,
        "source_generated_at_unix": source.get("timestamp_unix"),
        "canonical_generated_at_unix": canonical.get("generated_at_unix"),
        "source_snapshot_id": source.get("snapshot_id"),
        "canonical_snapshot_id": canonical.get("snapshot_id"),
    }


def _audit_timestamp_unix(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.timestamp())


def _test_kill_switch_snapshot(
    *,
    expected_sha256: str | None = None,
    expected_nonce: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    path = base.KILL_SWITCH_PATH
    checked_at = int(time.time()) if now is None else int(now)
    snapshot = base._read_bound_regular_bytes(path, TEST_KILL_SWITCH_MAX_BYTES)
    linked = os.stat(path, follow_symlinks=False)
    if (linked.st_dev, linked.st_ino) != (snapshot["dev"], snapshot["ino"]):
        raise RuntimeError("kill-switch path changed during validation")
    if not stat.S_ISREG(linked.st_mode) or linked.st_nlink != 1:
        raise PermissionError("test kill switch must be one regular single-link file")
    if linked.st_uid != os.getuid() or stat.S_IMODE(linked.st_mode) != 0o600:
        raise PermissionError("test kill switch owner or mode is invalid")
    digest = snapshot["sha256"]
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeError("test kill switch SHA-256 precondition failed")
    try:
        value = json.loads(snapshot["data"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("kill switch is not an eligible Grabowski test marker") from exc
    required = {
        "schema_version",
        "kind",
        "nonce",
        "created_at_unix",
        "expires_at_unix",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("kill switch is not an eligible Grabowski test marker")
    nonce = value.get("nonce")
    created_at = value.get("created_at_unix")
    expires_at = value.get("expires_at_unix")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != TEST_KILL_SWITCH_KIND
        or not isinstance(nonce, str)
        or TEST_KILL_SWITCH_NONCE_RE.fullmatch(nonce) is None
        or not isinstance(created_at, int)
        or isinstance(created_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
    ):
        raise ValueError("kill switch is not an eligible Grabowski test marker")
    if expected_nonce is not None and nonce != expected_nonce:
        raise RuntimeError("test kill switch nonce precondition failed")
    if created_at > checked_at + TEST_KILL_SWITCH_CLOCK_SKEW_SECONDS:
        raise ValueError("test kill switch is future-dated")
    if expires_at < created_at or expires_at - created_at > TEST_KILL_SWITCH_MAX_LIFETIME_SECONDS:
        raise ValueError("test kill switch lifetime is invalid")
    if checked_at - created_at > TEST_KILL_SWITCH_CLEAR_MAX_AGE_SECONDS:
        raise ValueError("test kill switch recovery window has expired")
    ctime_unix = snapshot["ctime_ns"] // 1_000_000_000
    if abs(ctime_unix - created_at) > TEST_KILL_SWITCH_CLOCK_SKEW_SECONDS:
        raise PermissionError("test kill switch filesystem identity is not creation-bound")

    latest_path_record: dict[str, Any] | None = None
    for record in reversed(base._audit_records()):
        if record.get("path") == str(path):
            latest_path_record = record
            break
    if (
        latest_path_record is None
        or latest_path_record.get("operation") != "create"
        or latest_path_record.get("after_sha256") != digest
    ):
        raise PermissionError("test kill switch has no matching latest Grabowski create receipt")
    audit_timestamp = _audit_timestamp_unix(latest_path_record.get("timestamp"))
    if audit_timestamp is None or abs(audit_timestamp - created_at) > TEST_KILL_SWITCH_CLOCK_SKEW_SECONDS:
        raise PermissionError("test kill switch create receipt is not time-bound")
    return {
        "path": str(path),
        "sha256": digest,
        "nonce": nonce,
        "created_at_unix": created_at,
        "expires_at_unix": expires_at,
        "age_seconds": max(0, checked_at - created_at),
        "expired_for_test_execution": checked_at > expires_at,
        "dev": snapshot["dev"],
        "ino": snapshot["ino"],
        "create_record_sha256": latest_path_record.get("record_sha256"),
    }


def _test_kill_switch_recovery_status() -> dict[str, Any]:
    state = base._kill_switch_state()
    result: dict[str, Any] = {
        "eligible": False,
        "sha256": None,
        "nonce": None,
        "created_at_unix": None,
        "expires_at_unix": None,
        "error": None,
    }
    if state.get("environment"):
        result["error"] = "environment kill switch cannot be self-cleared"
        return result
    if not state.get("path_exists"):
        result["error"] = "file kill switch is not engaged"
        return result
    try:
        snapshot = _test_kill_switch_snapshot()
    except Exception as exc:
        result["error"] = str(exc)[:500]
        return result
    result.update({
        "eligible": True,
        "sha256": snapshot["sha256"],
        "nonce": snapshot["nonce"],
        "created_at_unix": snapshot["created_at_unix"],
        "expires_at_unix": snapshot["expires_at_unix"],
        "error": None,
    })
    return result


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _clear_test_kill_switch(*, expected_sha256: str, expected_nonce: str) -> dict[str, Any]:
    base._require_valid_audit_chain()
    state = base._kill_switch_state()
    if state.get("environment"):
        raise PermissionError("environment kill switch cannot be self-cleared")
    snapshot = _test_kill_switch_snapshot(
        expected_sha256=expected_sha256,
        expected_nonce=expected_nonce,
    )
    path = base.KILL_SWITCH_PATH
    quarantine_root = base._state_subdir(
        base.STATE_DIR / "recovery" / "cleared-test-kill-switches"
    )
    quarantine_metadata = os.stat(quarantine_root, follow_symlinks=False)
    if (
        not stat.S_ISDIR(quarantine_metadata.st_mode)
        or quarantine_metadata.st_uid != os.getuid()
        or stat.S_IMODE(quarantine_metadata.st_mode) & 0o077
    ):
        raise PermissionError("test kill switch quarantine directory is unsafe")
    clear_id = os.urandom(16).hex()
    quarantine = quarantine_root / f"{clear_id}.json"
    if quarantine.exists() or quarantine.is_symlink():
        raise FileExistsError("test kill switch quarantine target already exists")
    os.replace(path, quarantine)
    _fsync_directory(path.parent)
    _fsync_directory(quarantine_root)
    restored = False
    try:
        moved = base._read_bound_regular_bytes(quarantine, TEST_KILL_SWITCH_MAX_BYTES)
        if (
            moved["sha256"] != expected_sha256
            or moved["dev"] != snapshot["dev"]
            or moved["ino"] != snapshot["ino"]
        ):
            raise RuntimeError("test kill switch identity changed during quarantine")
        record = {
            "timestamp": datetime.now().astimezone().isoformat(),
            "operation": "clear-recovery-test-kill-switch",
            "clear_id": clear_id,
            "path": str(path),
            "before_sha256": expected_sha256,
            "after_sha256": None,
            "quarantine_path": str(quarantine),
            "create_record_sha256": snapshot["create_record_sha256"],
        }
        base._append_audit(record)
        audit_status = base._verify_audit_log(base.AUDIT_LOG)
        if not audit_status.get("valid"):
            raise RuntimeError(
                f"audit verification failed after test kill switch clear: {audit_status.get('error')}"
            )
        matching = [
            item
            for item in base._audit_records()
            if item.get("operation") == "clear-recovery-test-kill-switch"
            and item.get("clear_id") == clear_id
            and item.get("path") == str(path)
            and item.get("before_sha256") == expected_sha256
            and item.get("create_record_sha256") == snapshot["create_record_sha256"]
        ]
        if len(matching) != 1:
            raise RuntimeError("test kill switch clear receipt readback is missing or ambiguous")
    except Exception:
        if not path.exists() and not path.is_symlink() and quarantine.exists():
            os.replace(quarantine, path)
            _fsync_directory(path.parent)
            _fsync_directory(quarantine_root)
            restored = True
        raise
    return {
        "schema_version": 1,
        "success": True,
        "path": str(path),
        "cleared_sha256": expected_sha256,
        "clear_id": clear_id,
        "quarantine_path": str(quarantine),
        "create_record_sha256": snapshot["create_record_sha256"],
        "rollback_performed": restored,
        "environment_kill_switch_clearable": False,
        "manual_kill_switch_clearable": False,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_secret_text(path: Path) -> str:
    if not _bounded_file(path):
        raise RuntimeError(f"secret file is missing or invalid: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value or chr(0) in value or "\n" in value or "\r" in value:
        raise RuntimeError(f"secret file has an invalid shape: {path}")
    return value


def _pick_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _BoundedPipeCapture:
    def __init__(self, *, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.total_bytes = 0
        self.stored_bytes = 0
        self.truncated = False
        self._chunks: list[bytes] = []
        self._thread: threading.Thread | None = None

    def start(self, stream: Any) -> None:
        self._thread = threading.Thread(target=self._drain, args=(stream,), daemon=True)
        self._thread.start()

    def _drain(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(1024)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                remaining = max(0, self.max_bytes - self.stored_bytes)
                if remaining:
                    kept = chunk[:remaining]
                    self._chunks.append(kept)
                    self.stored_bytes += len(kept)
                if len(chunk) > remaining:
                    self.truncated = True
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def finish(self, *, timeout_seconds: float = 5.0) -> bytes:
        if self._thread is not None:
            self._thread.join(timeout=timeout_seconds)
        if self.total_bytes > self.stored_bytes:
            self.truncated = True
        return b"".join(self._chunks)

    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", errors="replace")

    def metadata(self) -> dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "stored_bytes": self.stored_bytes,
            "truncated": self.truncated,
        }


def _wait_for_tcp(
    port: int,
    process: subprocess.Popen[bytes],
    *,
    stderr_capture: _BoundedPipeCapture | None = None,
    timeout_seconds: float = 10.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            details = _process_error_details(process, stderr_capture=stderr_capture)
            raise RuntimeError(f"ssh recovery tunnel exited before becoming ready: {details}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    details = _process_error_details(process, stderr_capture=stderr_capture)
    raise RuntimeError(f"ssh recovery tunnel did not become ready: {details}")


def _process_error_details(process: subprocess.Popen[bytes], *, stderr_capture: _BoundedPipeCapture | None) -> dict[str, Any]:
    if stderr_capture is not None:
        stderr_capture.finish(timeout_seconds=1.0)
    return {
        "returncode": process.poll(),
        "stderr": stderr_capture.text() if stderr_capture is not None else "",
        "stderr_capture": stderr_capture.metadata() if stderr_capture is not None else None,
    }


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _run_logged(argv: list[str], *, env: dict[str, str], log: Path, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    with log.open("a", encoding="utf-8") as handle:
        handle.write("$ " + " ".join(argv) + "\n")
    result = subprocess.run(
        argv,
        cwd=str(operator.HOME),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    with log.open("a", encoding="utf-8") as handle:
        if result.stdout:
            handle.write(result.stdout)
            if not result.stdout.endswith("\n"):
                handle.write("\n")
        if result.stderr:
            handle.write(result.stderr)
            if not result.stderr.endswith("\n"):
                handle.write("\n")
        handle.write(f"returncode={result.returncode}\n")
    if result.returncode != 0:
        command = " ".join(argv[:2]) if len(argv) > 1 else argv[0]
        raise RuntimeError(f"command failed: {command}")
    return result


def _snapshot_from_backup_output(output: str) -> str:
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("message_type") == "summary" and isinstance(value.get("snapshot_id"), str):
            return value["snapshot_id"]
    raise RuntimeError("restic backup did not report a snapshot id")


def _write_server_marker(*, completed_at_unix: int, snapshot_id: str) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "completed_at_unix": completed_at_unix,
        "snapshot_id": snapshot_id,
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "target": SERVER_RECOVERY_TARGET,
    }
    SERVER_RECOVERY.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".server-recovery-",
        dir=SERVER_RECOVERY.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, SERVER_RECOVERY)
        directory_fd = os.open(SERVER_RECOVERY.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return {
        "path": str(SERVER_RECOVERY),
        "source_record_sha256": hashlib.sha256(raw).hexdigest(),
        "generated_at_unix": completed_at_unix,
    }


def _publication_failure_detail(publication: dict[str, Any]) -> str:
    candidates = (
        publication.get("failure_reason"),
        publication.get("stderr"),
    )
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return " ".join(candidate.split())[:500]
    response = publication.get("broker_response")
    if isinstance(response, dict):
        for key in ("error", "message"):
            candidate = response.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return " ".join(candidate.split())[:500]
    return "no structured failure reason was returned"


def _schedule_recovery_alert(
    *,
    event_class: str,
    operation: str,
    deduplication_key: str,
    error_type: str | None = None,
) -> None:
    if alert_outbox is None:
        return
    fields = {"operation": operation}
    if error_type is not None:
        fields["error_type"] = error_type
    try:
        alert_outbox.enqueue_and_schedule(
            event_class=event_class,
            producer="recovery",
            correlation_key=f"{operation}:{SERVER_RECOVERY_TARGET}",
            deduplication_key=deduplication_key,
            subject="recovery",
            fields=fields,
        )
    except Exception:
        # Alerting is outside the recovery evidence authority. Its failure must
        # neither turn success into failure nor replace the primary exception.
        return


def _local_recovery_durability_evidence(*, now: int) -> dict[str, Any]:
    if not _bounded_file(LOCAL_RECOVERY_DURABILITY_EVIDENCE):
        raise RuntimeError("local recovery durability evidence is missing or invalid")
    evidence_meta = LOCAL_RECOVERY_DURABILITY_EVIDENCE.stat()
    if (
        evidence_meta.st_uid != os.geteuid()
        or evidence_meta.st_nlink != 1
        or evidence_meta.st_mode & 0o077
    ):
        raise RuntimeError("local recovery durability evidence permissions are unsafe")
    try:
        value = json.loads(LOCAL_RECOVERY_DURABILITY_EVIDENCE.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("local recovery durability evidence is unreadable") from exc
    if not isinstance(value, dict):
        raise RuntimeError("local recovery durability evidence is malformed")
    required = {
        "schema_version",
        "evidence_ref",
        "producer",
        "verification",
        "verified_at",
        "receipt_digest",
        "inventory_algorithm",
        "inventory_sha256",
        "file_count",
        "total_bytes",
    }
    if set(value) != required:
        raise RuntimeError("local recovery durability evidence contract is invalid")
    if value.get("schema_version") != "schauwerk-fundus-durability-evidence.v1":
        raise RuntimeError("local recovery durability evidence schema mismatch")
    if value.get("producer") != "infra:heim-pc-restic-backup":
        raise RuntimeError("local recovery durability evidence producer mismatch")
    if value.get("verification") != "staged_restore_exact_snapshot":
        raise RuntimeError("local recovery durability verification mismatch")
    if value.get("inventory_algorithm") != "schauwerk-fundus-inventory.v1":
        raise RuntimeError("local recovery durability inventory algorithm mismatch")
    inventory_sha256 = value.get("inventory_sha256")
    if not isinstance(inventory_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", inventory_sha256) is None:
        raise RuntimeError("local recovery durability inventory digest is invalid")
    for field in ("file_count", "total_bytes"):
        number = value.get(field)
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise RuntimeError(f"local recovery durability {field} is invalid")
    evidence_ref = value.get("evidence_ref")
    match = re.fullmatch(r"snapshot:([0-9a-f]{64})", evidence_ref if isinstance(evidence_ref, str) else "")
    if match is None:
        raise RuntimeError("local recovery durability snapshot binding is invalid")
    digest = value.get("receipt_digest")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RuntimeError("local recovery durability receipt digest is invalid")
    body = dict(value)
    body.pop("receipt_digest", None)
    expected_digest = hashlib.sha256(
        json.dumps(
            body,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if digest != expected_digest:
        raise RuntimeError("local recovery durability receipt digest mismatch")
    verified_at = value.get("verified_at")
    if not isinstance(verified_at, str):
        raise RuntimeError("local recovery durability timestamp is invalid")
    try:
        verified_at_unix = _iso_timestamp_unix(verified_at)
    except ValueError as exc:
        raise RuntimeError("local recovery durability timestamp is invalid") from exc
    age_seconds = now - verified_at_unix
    if age_seconds < 0 or age_seconds > MAX_AGE_SECONDS:
        raise RuntimeError("local recovery durability evidence is stale or future-dated")
    return {
        "snapshot_id": match.group(1),
        "verified_at_unix": verified_at_unix,
        "age_seconds": age_seconds,
        "receipt_digest": digest,
        "inventory_algorithm": value["inventory_algorithm"],
        "inventory_sha256": inventory_sha256,
        "file_count": value["file_count"],
        "total_bytes": value["total_bytes"],
    }


def _local_recovery_repository(
    target_info: dict[str, Any],
    *,
    log_path: Path,
) -> tuple[Path, dict[str, str], str]:
    if target_info.get("kind") != "local_backup_disk":
        raise RuntimeError("local recovery target kind mismatch")
    backup_uuid = target_info.get("backup_uuid")
    repository_name = target_info.get("repository_name")
    if not isinstance(backup_uuid, str) or not isinstance(repository_name, str):
        raise RuntimeError("local recovery target is incomplete")
    if not LOCAL_RECOVERY_MOUNT.is_absolute() or LOCAL_RECOVERY_MOUNT.is_symlink():
        raise RuntimeError("local recovery mount path is unsafe")
    env = dict(os.environ)
    findmnt = _run_logged(
        [
            "/usr/bin/findmnt",
            "-rn",
            "-T",
            str(LOCAL_RECOVERY_MOUNT),
            "-t",
            "ntfs3",
            "-o",
            "TARGET,SOURCE,FSTYPE",
        ],
        env=env,
        log=log_path,
        timeout_seconds=30,
    )
    rows = [line.split() for line in findmnt.stdout.splitlines() if line.strip()]
    if len(rows) != 1 or len(rows[0]) != 3:
        raise RuntimeError("local recovery mount identity is ambiguous")
    mount_target, mount_source, mount_fstype = rows[0]
    if (
        mount_target != str(LOCAL_RECOVERY_MOUNT)
        or not mount_source.startswith("/dev/")
        or mount_fstype != "ntfs3"
    ):
        raise RuntimeError("local recovery mount identity mismatch")
    observed_uuid = _run_logged(
        ["/usr/bin/lsblk", "-ndo", "UUID", mount_source],
        env=env,
        log=log_path,
        timeout_seconds=30,
    ).stdout.strip()
    if observed_uuid != backup_uuid:
        raise RuntimeError("local recovery backup UUID mismatch")
    repository = LOCAL_RECOVERY_MOUNT / "restic" / repository_name
    if not repository.is_dir() or repository.is_symlink():
        raise RuntimeError("local recovery repository is missing or unsafe")
    try:
        resolved_repository = repository.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("local recovery repository cannot be resolved") from exc
    if resolved_repository != repository:
        raise RuntimeError("local recovery repository path traverses a symlink")
    if not _bounded_file(LOCAL_RECOVERY_PASSWORD_FILE):
        raise RuntimeError("local recovery repository password file is missing or invalid")
    password_meta = LOCAL_RECOVERY_PASSWORD_FILE.stat()
    if password_meta.st_uid != os.geteuid() or password_meta.st_mode & 0o077:
        raise RuntimeError("local recovery repository password file permissions are unsafe")
    restic_env = dict(env)
    restic_env.update(
        {
            "RESTIC_REPOSITORY": str(repository),
            "RESTIC_PASSWORD_FILE": str(LOCAL_RECOVERY_PASSWORD_FILE),
        }
    )
    config = _run_logged(
        [RESTIC_BIN, "cat", "config", "--no-cache", "--no-lock"],
        env=restic_env,
        log=log_path,
        timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
    )
    try:
        config_value = json.loads(config.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("local recovery repository config is invalid") from exc
    observed_repository_id = (
        config_value.get("id") if isinstance(config_value, dict) else None
    )
    if observed_repository_id != LOCAL_RECOVERY_REPOSITORY_ID:
        raise RuntimeError("local recovery repository ID mismatch")
    return repository, restic_env, mount_source


def _local_recovery_snapshot_metadata(
    *,
    snapshot_id: str,
    restic_env: dict[str, str],
    log_path: Path,
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{64}", snapshot_id) is None:
        raise RuntimeError("local recovery snapshot id is invalid")
    snapshots = _run_logged(
        [RESTIC_BIN, "snapshots", "--json", "--no-cache", "--no-lock", snapshot_id],
        env=restic_env,
        log=log_path,
        timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
    )
    try:
        rows = json.loads(snapshots.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("local recovery snapshot metadata is invalid") from exc
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError("local recovery snapshot identity is ambiguous")
    row = rows[0]
    if row.get("id") != snapshot_id:
        raise RuntimeError("local recovery snapshot identity mismatch")
    if row.get("hostname") != "heim-pc":
        raise RuntimeError("local recovery snapshot host mismatch")
    tags = row.get("tags")
    if (
        not isinstance(tags, list)
        or not all(isinstance(tag, str) for tag in tags)
        or "daily" not in tags
    ):
        raise RuntimeError("local recovery snapshot daily tag is missing")
    snapshot_time = row.get("time")
    if not isinstance(snapshot_time, str):
        raise RuntimeError("local recovery snapshot time is invalid")
    try:
        snapshot_time_unix = _iso_timestamp_unix(snapshot_time)
    except ValueError as exc:
        raise RuntimeError("local recovery snapshot time is invalid") from exc
    paths = row.get("paths")
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
        raise RuntimeError("local recovery snapshot paths are invalid")
    expected_paths = {
        str(operator.HOME / "repos"),
        str(operator.HOME / "artifacts/merges"),
        str(operator.HOME / ".local/share/schauwerk/fundus"),
        str(operator.HOME / ".local/state/heim-pc-priorities/backup-sentinel.txt"),
    }
    if not expected_paths.issubset(set(paths)):
        raise RuntimeError("local recovery snapshot source contract mismatch")
    return {
        "snapshot_id": snapshot_id,
        "hostname": "heim-pc",
        "tags": sorted(tags),
        "paths": sorted(paths),
        "time": snapshot_time,
        "time_unix": snapshot_time_unix,
    }


def _local_recovery_inventory(root: Path) -> dict[str, Any]:
    try:
        root_meta = os.lstat(root)
    except OSError as exc:
        raise RuntimeError("local recovery restored Fundus is unavailable") from exc
    if not stat.S_ISDIR(root_meta.st_mode) or stat.S_ISLNK(root_meta.st_mode):
        raise RuntimeError("local recovery restored Fundus root is unsafe")
    files: list[dict[str, Any]] = []

    def walk(directory: Path, prefix: Path) -> None:
        try:
            with os.scandir(directory) as handle:
                entries = sorted(handle, key=lambda item: item.name)
        except OSError as exc:
            raise RuntimeError("local recovery restored Fundus cannot be enumerated") from exc
        for entry in entries:
            relative = prefix / entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(
                    f"local recovery restored Fundus cannot stat {relative.as_posix()}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(
                    f"local recovery restored Fundus contains symlink: {relative.as_posix()}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                walk(Path(entry.path), relative)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(
                    f"local recovery restored Fundus contains special file: {relative.as_posix()}"
                )
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(entry.path, flags)
            except OSError as exc:
                raise RuntimeError(
                    f"local recovery restored Fundus cannot open {relative.as_posix()}"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                ):
                    raise RuntimeError(
                        f"local recovery restored Fundus path changed: {relative.as_posix()}"
                    )
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                after = os.fstat(descriptor)
                if (
                    after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                    or total != after.st_size
                ):
                    raise RuntimeError(
                        f"local recovery restored Fundus file changed: {relative.as_posix()}"
                    )
            finally:
                os.close(descriptor)
            files.append(
                {
                    "path": relative.as_posix(),
                    "bytes": total,
                    "sha256": digest.hexdigest(),
                }
            )

    walk(root, Path())
    inventory = {
        "schema_version": "schauwerk-fundus-inventory.v1",
        "files": files,
    }
    raw = json.dumps(
        inventory,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "inventory_sha256": hashlib.sha256(raw).hexdigest(),
        "file_count": len(files),
        "total_bytes": sum(int(item["bytes"]) for item in files),
    }


def _local_recovery_restore_probe(
    *,
    snapshot_id: str,
    restic_env: dict[str, str],
    durability: dict[str, Any],
    log_path: Path,
) -> dict[str, Any]:
    fundus = operator.HOME / ".local/share/schauwerk/fundus"
    with tempfile.TemporaryDirectory(prefix="grabowski-local-recovery-") as raw:
        target = Path(raw)
        _run_logged(
            [
                RESTIC_BIN,
                "restore",
                "--no-cache",
                "--no-lock",
                snapshot_id,
                "--target",
                str(target),
                "--include",
                str(fundus),
                "--verify",
            ],
            env=restic_env,
            log=log_path,
            timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
        )
        restored_fundus = target / str(fundus).lstrip("/")
        inventory = _local_recovery_inventory(restored_fundus)
    if inventory["inventory_sha256"] != durability["inventory_sha256"]:
        raise RuntimeError("local recovery restored Fundus inventory digest mismatch")
    if inventory["file_count"] != durability["file_count"]:
        raise RuntimeError("local recovery restored Fundus file count mismatch")
    if inventory["total_bytes"] != durability["total_bytes"]:
        raise RuntimeError("local recovery restored Fundus byte count mismatch")
    return inventory


def _local_recovery_probe(target_info: dict[str, Any]) -> dict[str, Any]:
    completed_at_unix = int(time.time())
    durability = _local_recovery_durability_evidence(now=completed_at_unix)
    log_dir = operator.STATE_DIR / "recovery"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"local-recovery-{completed_at_unix}.log"
    repository, restic_env, mount_source = _local_recovery_repository(
        target_info,
        log_path=log_path,
    )
    snapshot = _local_recovery_snapshot_metadata(
        snapshot_id=durability["snapshot_id"],
        restic_env=restic_env,
        log_path=log_path,
    )
    snapshot_age_at_verification = (
        durability["verified_at_unix"] - snapshot["time_unix"]
    )
    if (
        snapshot_age_at_verification < 0
        or snapshot_age_at_verification > LOCAL_RECOVERY_RUN_MAX_SECONDS
    ):
        raise RuntimeError(
            "local recovery snapshot and durability evidence are not from one bounded run"
        )
    restore_probe = _local_recovery_restore_probe(
        snapshot_id=durability["snapshot_id"],
        restic_env=restic_env,
        durability=durability,
        log_path=log_path,
    )
    _run_logged(
        [
            RESTIC_BIN,
            "check",
            "--no-cache",
            "--no-lock",
            f"--read-data-subset={SERVER_RECOVERY_CHECK_SUBSET}",
        ],
        env=restic_env,
        log=log_path,
        timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
    )
    repository_after, restic_env_after, mount_source_after = _local_recovery_repository(
        target_info,
        log_path=log_path,
    )
    durability_after = _local_recovery_durability_evidence(now=int(time.time()))
    snapshot_after = _local_recovery_snapshot_metadata(
        snapshot_id=durability_after["snapshot_id"],
        restic_env=restic_env_after,
        log_path=log_path,
    )
    if repository_after != repository or mount_source_after != mount_source:
        raise RuntimeError("local recovery repository identity changed before publication")
    if (
        durability_after["receipt_digest"] != durability["receipt_digest"]
        or durability_after["snapshot_id"] != durability["snapshot_id"]
    ):
        raise RuntimeError("local recovery durability evidence changed before publication")
    if snapshot_after != snapshot:
        raise RuntimeError("local recovery snapshot identity changed before publication")
    source_write = _write_server_marker(
        completed_at_unix=completed_at_unix,
        snapshot_id=durability["snapshot_id"][:8],
    )
    publication = privileged.publish_recovery_marker_reference(
        source_record_sha256=source_write["source_record_sha256"],
        generated_at_unix=source_write["generated_at_unix"],
    )
    if not publication.get("success"):
        raise RuntimeError(
            "canonical root recovery publication failed: "
            + _publication_failure_detail(publication)
        )
    log_sha256 = _sha256_file(log_path) if log_path.exists() else None
    source_marker = _server_source_marker()
    canonical_marker = _canonical_server_marker()
    if not canonical_marker.get("valid"):
        raise RuntimeError("canonical recovery record readback is not ready")
    if (
        canonical_marker.get("source_record_sha256")
        != source_write.get("source_record_sha256")
    ):
        raise RuntimeError("canonical recovery record source digest mismatch")
    audit_record = {
        "timestamp_unix": completed_at_unix,
        "operation": "local-recovery-probe",
        "snapshot_id": canonical_marker.get("snapshot_id"),
        "snapshot_full_id": durability["snapshot_id"],
        "target": SERVER_RECOVERY_TARGET,
        "backup_uuid": target_info.get("backup_uuid"),
        "repository_id": LOCAL_RECOVERY_REPOSITORY_ID,
        "durability_receipt_digest": durability["receipt_digest"],
        "snapshot_age_at_verification_seconds": snapshot_age_at_verification,
        "durability_inventory_sha256": durability["inventory_sha256"],
        "durability_file_count": durability["file_count"],
        "durability_total_bytes": durability["total_bytes"],
        "restore_inventory_sha256": restore_probe["inventory_sha256"],
        "canonical_record_sha256": canonical_marker.get("record_sha256"),
        "source_record_sha256": canonical_marker.get("source_record_sha256"),
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "log_sha256": log_sha256,
    }
    base._append_audit(audit_record)
    return {
        "schema_version": 1,
        "completed_at_unix": completed_at_unix,
        "snapshot_id": canonical_marker.get("snapshot_id"),
        "snapshot_full_id": durability["snapshot_id"],
        "target": SERVER_RECOVERY_TARGET,
        "target_kind": "local_backup_disk",
        "backup_mount": str(LOCAL_RECOVERY_MOUNT),
        "backup_source": mount_source,
        "backup_uuid": target_info.get("backup_uuid"),
        "repository": str(repository),
        "repository_id": LOCAL_RECOVERY_REPOSITORY_ID,
        "durability_receipt_digest": durability["receipt_digest"],
        "snapshot_age_at_verification_seconds": snapshot_age_at_verification,
        "durability_inventory_sha256": durability["inventory_sha256"],
        "durability_file_count": durability["file_count"],
        "durability_total_bytes": durability["total_bytes"],
        "restore_inventory_sha256": restore_probe["inventory_sha256"],
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "marker_valid": canonical_marker.get("valid"),
        "marker_path": str(CANONICAL_RECOVERY),
        "canonical_recovery": canonical_marker,
        "source_recovery": source_marker,
        "publication": publication,
        "log_path": str(log_path),
        "log_sha256": log_sha256,
    }


def server_recovery_probe() -> dict[str, Any]:
    target_info = _configured_recovery_target_info()
    if not target_info.get("valid"):
        raise RuntimeError(f"recovery target configuration is invalid: {target_info.get('error')}")
    if target_info.get("kind") == "local_backup_disk":
        return _local_recovery_probe(target_info)
    http_password = _read_secret_text(SERVER_RECOVERY_HTTP_PASSWORD)
    if not _bounded_file(SERVER_RECOVERY_REPOSITORY_PASSWORD):
        raise RuntimeError("repository password file is missing or invalid")
    completed_at_unix = int(time.time())
    log_dir = operator.STATE_DIR / "recovery"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"server-recovery-{completed_at_unix}.log"
    port = _pick_local_port()
    tunnel_stdout_path = log_dir / f"server-recovery-{completed_at_unix}.tunnel.stdout"
    tunnel_stderr_path = log_dir / f"server-recovery-{completed_at_unix}.tunnel.stderr"
    tunnel = subprocess.Popen(
        [
            SSH_BIN,
            "-o", "BatchMode=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-N",
            "-L", f"127.0.0.1:{port}:127.0.0.1:{SERVER_RECOVERY_REMOTE_PORT}",
            SERVER_RECOVERY_HOST,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tunnel_stdout_capture = _BoundedPipeCapture(max_bytes=SERVER_RECOVERY_TUNNEL_OUTPUT_MAX_BYTES)
    tunnel_stderr_capture = _BoundedPipeCapture(max_bytes=SERVER_RECOVERY_TUNNEL_OUTPUT_MAX_BYTES)
    tunnel_stdout_capture.start(tunnel.stdout)
    tunnel_stderr_capture.start(tunnel.stderr)
    try:
        _wait_for_tcp(port, tunnel, stderr_capture=tunnel_stderr_capture)
        with tempfile.TemporaryDirectory(prefix="grabowski-server-recovery-") as work_raw, tempfile.TemporaryDirectory(prefix="grabowski-server-restore-") as restore_raw:
            work = Path(work_raw)
            restore = Path(restore_raw)
            probe = work / "probe"
            probe.mkdir(mode=0o700)
            sentinel = probe / "sentinel.txt"
            sentinel.write_text(f"grabowski server recovery probe {completed_at_unix}\n", encoding="utf-8")
            sentinel_sha256 = _sha256_file(sentinel)
            env = dict(os.environ)
            env.update({
                "RESTIC_REPOSITORY": f"rest:http://127.0.0.1:{port}/{SERVER_RECOVERY_REPO_PATH}",
                "RESTIC_REST_USERNAME": SERVER_RECOVERY_REST_USER,
                "RESTIC_REST_PASSWORD": http_password,
                "RESTIC_PASSWORD_FILE": str(SERVER_RECOVERY_REPOSITORY_PASSWORD),
            })
            backup = _run_logged(
                [RESTIC_BIN, "backup", str(probe), "--tag", "grabowski-recovery-probe", "--json"],
                env=env,
                log=log_path,
                timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
            )
            snapshot_id = _snapshot_from_backup_output(backup.stdout)
            _run_logged(
                [RESTIC_BIN, "restore", snapshot_id, "--target", str(restore)],
                env=env,
                log=log_path,
                timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
            )
            restored = next(restore.rglob("sentinel.txt"), None)
            if restored is None:
                raise RuntimeError("restored sentinel is missing")
            if _sha256_file(restored) != sentinel_sha256:
                raise RuntimeError("restored sentinel hash mismatch")
            _run_logged(
                [RESTIC_BIN, "check", f"--read-data-subset={SERVER_RECOVERY_CHECK_SUBSET}"],
                env=env,
                log=log_path,
                timeout_seconds=SERVER_RECOVERY_TIMEOUT_SECONDS,
            )
            source_write = _write_server_marker(
                completed_at_unix=completed_at_unix,
                snapshot_id=snapshot_id[:8],
            )
            publication = privileged.publish_recovery_marker_reference(
                source_record_sha256=source_write["source_record_sha256"],
                generated_at_unix=source_write["generated_at_unix"],
            )
            if not publication.get("success"):
                raise RuntimeError(
                    "canonical root recovery publication failed: "
                    + _publication_failure_detail(publication)
                )
    finally:
        _terminate_process(tunnel)
        tunnel_stdout_path.write_bytes(tunnel_stdout_capture.finish())
        tunnel_stderr_path.write_bytes(tunnel_stderr_capture.finish())
    log_sha256 = _sha256_file(log_path) if log_path.exists() else None
    source_marker = _server_source_marker()
    canonical_marker = _canonical_server_marker()
    if not canonical_marker.get("valid"):
        raise RuntimeError("canonical recovery record readback is not ready")
    if canonical_marker.get("source_record_sha256") != source_write.get("source_record_sha256"):
        raise RuntimeError("canonical recovery record source digest mismatch")
    audit_record = {
        "timestamp_unix": completed_at_unix,
        "operation": "server-recovery-probe",
        "snapshot_id": canonical_marker.get("snapshot_id"),
        "target": SERVER_RECOVERY_TARGET,
        "canonical_record_sha256": canonical_marker.get("record_sha256"),
        "source_record_sha256": canonical_marker.get("source_record_sha256"),
        "canonical_generated_at_unix": canonical_marker.get("generated_at_unix"),
        "canonical_max_age_seconds": canonical_marker.get("max_age_seconds"),
        "canonical_freshness_reason": canonical_marker.get("freshness_reason"),
        "publication_request_id": publication.get("request_id"),
        "publication_reference_sha256": publication.get("reference_sha256"),
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "log_sha256": log_sha256,
        "tunnel_stderr_sha256": _sha256_file(tunnel_stderr_path) if tunnel_stderr_path.exists() else None,
        "tunnel_stderr_capture": tunnel_stderr_capture.metadata(),
    }
    base._append_audit(audit_record)
    return {
        "schema_version": 1,
        "completed_at_unix": completed_at_unix,
        "snapshot_id": canonical_marker.get("snapshot_id"),
        "target": SERVER_RECOVERY_TARGET,
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "marker_valid": canonical_marker.get("valid"),
        "marker_path": str(CANONICAL_RECOVERY),
        "canonical_recovery": canonical_marker,
        "source_recovery": source_marker,
        "publication": publication,
        "log_path": str(log_path),
        "log_sha256": log_sha256,
        "tunnel_stderr_path": str(tunnel_stderr_path),
        "tunnel_stderr_sha256": _sha256_file(tunnel_stderr_path) if tunnel_stderr_path.exists() else None,
        "tunnel_stdout_capture": tunnel_stdout_capture.metadata(),
        "tunnel_stderr_capture": tunnel_stderr_capture.metadata(),
    }


def _timer_probe(action: str) -> dict[str, Any]:
    result = operator._run(
        ["systemctl", "--user", action, BACKUP_TIMER],
        cwd=operator.HOME, timeout_seconds=30,
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )
    return {"action": action, "ok": result["returncode"] == 0, "result": result}


def recovery_status() -> dict[str, Any]:
    audit = base._verify_audit_log(base.AUDIT_LOG)
    deployment = base._deployment_metadata()
    local_backup = _fresh_text_marker(BACKUP_SUCCESS)
    server_backup = _canonical_server_marker()
    server_source = _server_source_marker()
    source_publication = _source_publication_state(server_backup, server_source)
    kill_switch = base._kill_switch_state()
    test_switch_recovery = _test_kill_switch_recovery_status()
    timer_enabled = _timer_probe("is-enabled")
    timer_active = _timer_probe("is-active")
    broker = privileged.grabowski_privileged_broker_status()
    checks = {
        "audit_chain": bool(audit.get("valid")),
        "deployment_provenance": bool(deployment.get("provenance_valid")),
        "local_backup_fresh": bool(local_backup["valid"]),
        "backup_timer_enabled": bool(timer_enabled["ok"]),
        "backup_timer_active": bool(timer_active["ok"]),
        "server_recovery_fresh": _server_recovery_evidence_fresh(server_backup),
        "server_recovery_source_current": bool(source_publication["current"]),
        "kill_switch_clear": not bool(kill_switch.get("engaged")),
        "privileged_broker_ready": bool(broker.get("ready")),
    }
    user_gate = all(checks[name] for name in (
        "audit_chain", "deployment_provenance", "local_backup_fresh",
        "backup_timer_enabled", "backup_timer_active",
        "server_recovery_fresh", "server_recovery_source_current",
        "kill_switch_clear",
    ))
    if not checks["kill_switch_clear"]:
        effective_reason = "kill-switch-engaged"
    elif not checks["server_recovery_fresh"]:
        effective_reason = str(server_backup.get("freshness_reason") or "canonical-record-not-ready")
    elif not checks["server_recovery_source_current"]:
        effective_reason = str(source_publication["reason"])
    else:
        effective_reason = "ready"
    actions: list[str] = []
    if not checks["kill_switch_clear"]:
        if test_switch_recovery.get("eligible"):
            actions.append(
                "clear the audit-bound Grabowski test kill switch through "
                "grabowski_recovery_server_probe; the tool revalidates the reported SHA-256 and nonce"
            )
        else:
            actions.append("remove the operator kill switch through an external operator-authorized path")
    if not checks["local_backup_fresh"]:
        actions.append("produce a fresh local backup and restore sentinel")
    if not checks["backup_timer_enabled"] or not checks["backup_timer_active"]:
        actions.append(f"enable and start {BACKUP_TIMER}")
    if not checks["server_recovery_fresh"]:
        target_info = _configured_recovery_target_info()
        if server_source.get("valid") and server_source.get("target") == SERVER_RECOVERY_TARGET:
            actions.append("publish the fresh source evidence to the canonical root recovery record")
        if not bool(target_info.get("valid")):
            actions.append(f"repair server recovery target configuration: {target_info.get('error')}")
        elif bool(server_backup.get("target")) and not _server_recovery_target_matches_configured(server_backup):
            actions.append(f"produce fresh server recovery evidence for configured target {SERVER_RECOVERY_TARGET}")
        elif _uses_default_heimserver_recovery_backend():
            actions.append("configure and prove a non-heimserver recovery target, or restore fresh heimserver recovery evidence")
        else:
            actions.append(f"produce fresh server recovery evidence for configured target {SERVER_RECOVERY_TARGET}")
    if checks["server_recovery_fresh"] and not checks["server_recovery_source_current"]:
        if server_source.get("valid") and server_source.get("target") == SERVER_RECOVERY_TARGET:
            actions.append("publish the fresh source evidence to the canonical root recovery record")
        else:
            actions.append(f"produce fresh server recovery evidence for configured target {SERVER_RECOVERY_TARGET}")
    if not checks["deployment_provenance"]:
        actions.append("repair deployment provenance")
    if not checks["privileged_broker_ready"]:
        actions.append("install and verify the privileged broker")
    return {
        "schema_version": 2, "checked_at_unix": int(time.time()),
        "ready_for_user_power_worker": user_gate,
        "ready_for_privileged_actions": user_gate and checks["privileged_broker_ready"],
        "checks": checks, "audit": audit, "deployment": deployment,
        "local_backup": local_backup,
        "backup_timer": {"unit": BACKUP_TIMER, "enabled": timer_enabled, "active": timer_active},
        "server_recovery": server_backup,
        "server_recovery_source": server_source,
        "server_recovery_source_publication": source_publication,
        "kill_switch": {**kill_switch, "test_recovery": test_switch_recovery},
        "effective_recovery_gate": {
            "ready": user_gate,
            "reason": effective_reason,
            "canonical_record_sha256": server_backup.get("record_sha256"),
            "canonical_source_record_sha256": server_backup.get("source_record_sha256"),
            "current_source_record_sha256": server_source.get("source_record_sha256"),
        },
        "canonical_recovery_record_identity": {
            "record_sha256": server_backup.get("record_sha256"),
            "source_record_sha256": server_backup.get("source_record_sha256"),
            "generated_at_unix": server_backup.get("generated_at_unix"),
            "age_seconds": server_backup.get("age_seconds"),
            "max_age_seconds": server_backup.get("max_age_seconds"),
            "freshness_reason": server_backup.get("freshness_reason"),
        },
        "recovery_evidence_boundary": _server_recovery_evidence_boundary(server_backup),
        "privileged_broker": broker,
        "required_actions": actions,
    }


@mcp.tool(name="grabowski_recovery_status", annotations=READ_ONLY)
def grabowski_recovery_status() -> dict[str, Any]:
    """Evaluate the fail-closed recovery gate for power-worker activation."""
    base._require_capability("audit_verify")
    return recovery_status()


@mcp.tool(name="grabowski_recovery_server_probe", annotations=MUTATING)
def grabowski_recovery_server_probe() -> dict[str, Any]:
    """Produce fresh server recovery evidence, or recover from one audit-bound Grabowski test kill switch."""
    base._require_capability("secret_use")
    base._require_capability("file_write")
    base._require_capability("terminal_execute")
    kill_switch = base._kill_switch_state()
    if kill_switch.get("engaged"):
        test_recovery = _test_kill_switch_recovery_status()
        if not test_recovery.get("eligible"):
            raise PermissionError(
                "operator kill switch is engaged and is not an eligible Grabowski test marker"
            )
        operation = "test_kill_switch_recovery"
        try:
            result = _clear_test_kill_switch(
                expected_sha256=str(test_recovery["sha256"]),
                expected_nonce=str(test_recovery["nonce"]),
            )
        except Exception as exc:
            _schedule_recovery_alert(
                event_class="service_failure",
                operation=operation,
                deduplication_key=type(exc).__name__,
                error_type=type(exc).__name__,
            )
            raise
        _schedule_recovery_alert(
            event_class="recovery",
            operation=operation,
            deduplication_key=str(
                result.get("cleared_sha256") or test_recovery["sha256"]
            ),
        )
        return result

    operation = "server_recovery_probe"
    try:
        result = server_recovery_probe()
    except Exception as exc:
        _schedule_recovery_alert(
            event_class="service_failure",
            operation=operation,
            deduplication_key=type(exc).__name__,
            error_type=type(exc).__name__,
        )
        raise
    source = result.get("source_recovery")
    source = source if isinstance(source, dict) else {}
    identity = source.get("source_record_sha256") or result.get("snapshot_id")
    _schedule_recovery_alert(
        event_class="recovery",
        operation=operation,
        deduplication_key=str(identity or "completed"),
    )
    return result

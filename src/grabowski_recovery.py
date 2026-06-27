from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import time
from typing import Any

import grabowski_mcp as base
import grabowski_privileged as privileged
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
BACKUP_SUCCESS = Path(os.environ.get(
    "GRABOWSKI_BACKUP_SUCCESS_MARKER",
    str(operator.HOME / ".local/state/heim-pc-priorities/last-restic-backup-success.txt"),
)).expanduser()
SERVER_RECOVERY = Path(os.environ.get(
    "GRABOWSKI_SERVER_RECOVERY_MARKER",
    str(operator.STATE_DIR / "recovery/last-server-recovery.json"),
)).expanduser()
BACKUP_TIMER = os.environ.get("GRABOWSKI_BACKUP_TIMER", "restic-backup-1930.timer")
MAX_AGE_SECONDS = int(os.environ.get("GRABOWSKI_RECOVERY_MAX_AGE_SECONDS", str(36 * 60 * 60)))


def _bounded_file(path: Path) -> bool:
    return not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536


def _timestamp(value: str) -> int:
    text = value.strip()
    try:
        return int(text)
    except ValueError:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        return int(parsed.timestamp())


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
    age = max(0, int(time.time()) - stamp)
    result["timestamp_unix"] = stamp
    result["age_seconds"] = age
    result["valid"] = age <= MAX_AGE_SECONDS
    if not result["valid"]:
        result["error"] = "marker is stale"
    return result


def _server_marker() -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(SERVER_RECOVERY), "exists": SERVER_RECOVERY.exists(),
        "valid": False, "timestamp_unix": None, "age_seconds": None,
        "snapshot_id": None, "restore_probe_valid": False,
        "repository_check_valid": False, "target": None, "error": None,
    }
    if not _bounded_file(SERVER_RECOVERY):
        result["error"] = "server marker is missing or invalid"
        return result
    try:
        value = json.loads(SERVER_RECOVERY.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    age = max(0, int(time.time()) - stamp)
    result.update({
        "timestamp_unix": stamp, "age_seconds": age,
        "snapshot_id": value["snapshot_id"],
        "restore_probe_valid": value["restore_probe_valid"] is True,
        "repository_check_valid": value["repository_check_valid"] is True,
        "target": value["target"],
    })
    result["valid"] = all((
        age <= MAX_AGE_SECONDS,
        isinstance(result["snapshot_id"], str) and bool(result["snapshot_id"]),
        result["restore_probe_valid"], result["repository_check_valid"],
        isinstance(result["target"], str) and bool(result["target"]),
    ))
    if not result["valid"]:
        result["error"] = "server recovery evidence is incomplete or stale"
    return result


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
    server_backup = _server_marker()
    timer_enabled = _timer_probe("is-enabled")
    timer_active = _timer_probe("is-active")
    broker = privileged.grabowski_privileged_broker_status()
    checks = {
        "audit_chain": bool(audit.get("valid")),
        "deployment_provenance": bool(deployment.get("provenance_valid")),
        "local_backup_fresh": bool(local_backup["valid"]),
        "backup_timer_enabled": bool(timer_enabled["ok"]),
        "backup_timer_active": bool(timer_active["ok"]),
        "server_recovery_fresh": bool(server_backup["valid"]),
        "privileged_broker_ready": bool(broker.get("ready")),
    }
    user_gate = all(checks[name] for name in (
        "audit_chain", "deployment_provenance", "local_backup_fresh",
        "backup_timer_enabled", "backup_timer_active",
        "server_recovery_fresh",
    ))
    actions: list[str] = []
    if not checks["local_backup_fresh"]:
        actions.append("produce a fresh local backup and restore sentinel")
    if not checks["backup_timer_enabled"] or not checks["backup_timer_active"]:
        actions.append(f"enable and start {BACKUP_TIMER}")
    if not checks["server_recovery_fresh"]:
        actions.append("produce fresh server recovery evidence")
    if not checks["deployment_provenance"]:
        actions.append("repair deployment provenance")
    if not checks["privileged_broker_ready"]:
        actions.append("install and verify the privileged broker")
    return {
        "schema_version": 1, "checked_at_unix": int(time.time()),
        "ready_for_user_power_worker": user_gate,
        "ready_for_privileged_actions": user_gate and checks["privileged_broker_ready"],
        "checks": checks, "audit": audit, "deployment": deployment,
        "local_backup": local_backup,
        "backup_timer": {"unit": BACKUP_TIMER, "enabled": timer_enabled, "active": timer_active},
        "server_recovery": server_backup, "privileged_broker": broker,
        "required_actions": actions,
    }


@mcp.tool(name="grabowski_recovery_status", annotations=READ_ONLY)
def grabowski_recovery_status() -> dict[str, Any]:
    """Evaluate the fail-closed recovery gate for power-worker activation."""
    base._require_capability("audit_verify")
    return recovery_status()

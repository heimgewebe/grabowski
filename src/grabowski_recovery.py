from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
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
MUTATING = operator.MUTATING
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
SERVER_RECOVERY_HOST = os.environ.get("GRABOWSKI_SERVER_RECOVERY_HOST", "heimserver")
SERVER_RECOVERY_REMOTE_PORT = int(os.environ.get("GRABOWSKI_SERVER_RECOVERY_REMOTE_PORT", "18081"))
SERVER_RECOVERY_REST_USER = os.environ.get("GRABOWSKI_SERVER_RECOVERY_REST_USER", "grabowski")
SERVER_RECOVERY_REPO_PATH = os.environ.get("GRABOWSKI_SERVER_RECOVERY_REPO_PATH", "grabowski-recovery-probe")
SERVER_RECOVERY_TARGET = os.environ.get("GRABOWSKI_SERVER_RECOVERY_TARGET", "heimserver:rest-server/grabowski-recovery-probe")
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
SERVER_RECOVERY_CHECK_SUBSET = os.environ.get("GRABOWSKI_SERVER_RECOVERY_CHECK_SUBSET", "1/100")
SERVER_RECOVERY_TIMEOUT_SECONDS = int(os.environ.get("GRABOWSKI_SERVER_RECOVERY_TIMEOUT_SECONDS", "300"))
SERVER_RECOVERY_TUNNEL_OUTPUT_MAX_BYTES = int(os.environ.get("GRABOWSKI_SERVER_RECOVERY_TUNNEL_OUTPUT_MAX_BYTES", "4096"))
HEIMSERVER_RECOVERY_ALIASES_ENV = "GRABOWSKI_HEIMSERVER_RECOVERY_ALIASES"
DEFAULT_HEIMSERVER_RECOVERY_ALIASES = "heimserver"
RECOVERY_STATUS_FRESH_EVIDENCE_PRESENT = "fresh_evidence_present"
RECOVERY_STATUS_BLOCKED_ON_DEFAULT_HEIMSERVER = "blocked_on_default_heimserver_or_alternate_recovery_target"
RECOVERY_STATUS_BLOCKED_UNTIL_CONFIGURED_TARGET_PROBE_SUCCEEDS = "blocked_until_configured_target_probe_succeeds"
RECOVERY_STATUS_BLOCKED_TARGET_MISMATCH = "blocked_until_configured_target_matches_marker"


def _normalize_recovery_host(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    if not text or any(ord(char) < 32 for char in text):
        return ""
    return text


def _configured_recovery_target_host() -> str:
    target = SERVER_RECOVERY_TARGET.strip().lower()
    if not target or any(ord(char) < 32 for char in target):
        return ""
    if target.startswith("["):
        closing = target.find("]")
        if closing <= 1:
            return ""
        return _normalize_recovery_host(target[1:closing])
    return _normalize_recovery_host(target.split(":", 1)[0])


def _heimserver_recovery_aliases() -> frozenset[str]:
    raw = os.environ.get(HEIMSERVER_RECOVERY_ALIASES_ENV, DEFAULT_HEIMSERVER_RECOVERY_ALIASES)
    aliases = {_normalize_recovery_host(part) for part in raw.split(",")}
    aliases.discard("")
    return frozenset(aliases or {"heimserver"})


def _uses_default_heimserver_recovery_backend() -> bool:
    aliases = _heimserver_recovery_aliases()
    host = _normalize_recovery_host(SERVER_RECOVERY_HOST)
    target_host = _configured_recovery_target_host()
    return host in aliases or target_host in aliases


def _server_recovery_target_matches_configured(server_marker: dict[str, Any]) -> bool:
    return server_marker.get("target") == SERVER_RECOVERY_TARGET


def _server_recovery_evidence_fresh(server_marker: dict[str, Any]) -> bool:
    return bool(server_marker.get("valid")) and _server_recovery_target_matches_configured(server_marker)


def _server_recovery_evidence_boundary(server_marker: dict[str, Any]) -> dict[str, Any]:
    uses_default_heimserver_backend = _uses_default_heimserver_recovery_backend()
    target_matches_configured = _server_recovery_target_matches_configured(server_marker)
    server_fresh = _server_recovery_evidence_fresh(server_marker)
    if server_fresh:
        status = RECOVERY_STATUS_FRESH_EVIDENCE_PRESENT
    elif bool(server_marker.get("target")) and not target_matches_configured:
        status = RECOVERY_STATUS_BLOCKED_TARGET_MISMATCH
    elif uses_default_heimserver_backend:
        status = RECOVERY_STATUS_BLOCKED_ON_DEFAULT_HEIMSERVER
    else:
        status = RECOVERY_STATUS_BLOCKED_UNTIL_CONFIGURED_TARGET_PROBE_SUCCEEDS
    return {
        "schema_version": 1,
        "kind": "ssh_tunnelled_restic_backup_restore_check",
        "server_recovery_host": SERVER_RECOVERY_HOST,
        "server_recovery_target": SERVER_RECOVERY_TARGET,
        "marker_target": server_marker.get("target"),
        "configured_target": SERVER_RECOVERY_TARGET,
        "target_matches_configured": target_matches_configured,
        "heimserver_recovery_aliases": sorted(_heimserver_recovery_aliases()),
        "uses_default_heimserver_backend": uses_default_heimserver_backend,
        "custom_recovery_target_configured": not uses_default_heimserver_backend,
        "status": status,
        "runtime_health_is_separate": True,
        "high_impact_actions_remain_blocked_until_fresh_server_evidence": not server_fresh,
        "does_not_establish": [
            "runtime health does not prove restore readiness",
            "stale server recovery markers do not authorize privileged or power-worker actions",
            "a configured non-heimserver target is only sufficient after backup, restore and repository checks pass",
            "server recovery evidence for one target authorizes no other configured target",
        ],
    }


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
        "repository_check_valid": False, "target": None,
        "configured_target": SERVER_RECOVERY_TARGET,
        "target_matches_configured": False,
        "error": None,
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
    marker_target = value["target"]
    target_matches_configured = marker_target == SERVER_RECOVERY_TARGET
    result.update({
        "timestamp_unix": stamp, "age_seconds": age,
        "snapshot_id": value["snapshot_id"],
        "restore_probe_valid": value["restore_probe_valid"] is True,
        "repository_check_valid": value["repository_check_valid"] is True,
        "target": marker_target,
        "configured_target": SERVER_RECOVERY_TARGET,
        "target_matches_configured": target_matches_configured,
    })
    base_valid = all((
        age <= MAX_AGE_SECONDS,
        isinstance(result["snapshot_id"], str) and bool(result["snapshot_id"]),
        result["restore_probe_valid"], result["repository_check_valid"],
        isinstance(result["target"], str) and bool(result["target"]),
    ))
    result["valid"] = base_valid and target_matches_configured
    if not base_valid:
        result["error"] = "server recovery evidence is incomplete or stale"
    elif not target_matches_configured:
        result["error"] = "server recovery target does not match configured target"
    return result


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


def _write_server_marker(*, completed_at_unix: int, snapshot_id: str) -> None:
    payload = {
        "schema_version": 1,
        "completed_at_unix": completed_at_unix,
        "snapshot_id": snapshot_id,
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "target": SERVER_RECOVERY_TARGET,
    }
    SERVER_RECOVERY.parent.mkdir(parents=True, exist_ok=True)
    SERVER_RECOVERY.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def server_recovery_probe() -> dict[str, Any]:
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
            _write_server_marker(completed_at_unix=completed_at_unix, snapshot_id=snapshot_id[:8])
    finally:
        _terminate_process(tunnel)
        tunnel_stdout_path.write_bytes(tunnel_stdout_capture.finish())
        tunnel_stderr_path.write_bytes(tunnel_stderr_capture.finish())
    log_sha256 = _sha256_file(log_path) if log_path.exists() else None
    marker = _server_marker()
    audit_record = {
        "timestamp_unix": completed_at_unix,
        "operation": "server-recovery-probe",
        "snapshot_id": marker.get("snapshot_id"),
        "target": SERVER_RECOVERY_TARGET,
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
        "snapshot_id": marker.get("snapshot_id"),
        "target": SERVER_RECOVERY_TARGET,
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "marker_valid": marker.get("valid"),
        "marker_path": str(SERVER_RECOVERY),
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
        "server_recovery_fresh": _server_recovery_evidence_fresh(server_backup),
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
        if bool(server_backup.get("target")) and not bool(server_backup.get("target_matches_configured")):
            actions.append(f"produce fresh server recovery evidence for configured target {SERVER_RECOVERY_TARGET}")
        elif _uses_default_heimserver_recovery_backend():
            actions.append("configure and prove a non-heimserver recovery target, or restore fresh heimserver recovery evidence")
        else:
            actions.append(f"produce fresh server recovery evidence for configured target {SERVER_RECOVERY_TARGET}")
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
        "server_recovery": server_backup,
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
    """Produce fresh server recovery evidence through a fixed SSH-tunnelled restic probe."""
    base._require_capability("secret_use")
    base._require_capability("file_write")
    base._require_capability("terminal_execute")
    return server_recovery_probe()

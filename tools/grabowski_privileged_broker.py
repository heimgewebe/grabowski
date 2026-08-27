#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

LIB_DIR = Path("/usr/local/lib/grabowski")
sys.path.insert(0, str(LIB_DIR))

from grabowski_blockade_authority import execute_lifecycle
from grabowski_privileged_broker import (
    MAX_INPUT_BYTES,
    canonical_sha256,
    claim_once,
    load_root_config,
    parse_reference,
    publish_recovery_marker,
    resolve_execution,
)

CONFIG = Path("/etc/grabowski/privileged-actions.json")
STATE = Path("/var/lib/grabowski/privileged-broker")
AUDIT = STATE / "audit.jsonl"
OUTPUT_EVIDENCE_ROOT = Path("/run/grabowski/privileged-broker-evidence")
OUTPUT_EVIDENCE_KIND = "grabowski_privileged_output_evidence"
MAX_OUTPUT_BYTES = 250_000
POWER_ACTION = "operator_power_argv"
BLOCKADE_LIFECYCLE_ACTION = "operator_blockade_marker_lifecycle"
ROOTBROKER_CUTOVER_ACTION = "operator_rootbroker_cutover"
ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS = 900
CGROUP_ROOT = Path("/sys/fs/cgroup")
RUN_USER_ROOT = Path("/run/user")
MAX_PEER_CGROUP_PROCESSES = 256
MAX_SYSTEMD_SHOW_BYTES = 16 * 1024
SYSTEMCTL = "/usr/bin/systemctl"
OPERATOR_UNIT_PATH = Path("/etc/systemd/system/grabowski-operator.service")
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def append_audit(record: dict[str, object]) -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_metadata = STATE.lstat()
    if (
        STATE.is_symlink()
        or not stat.S_ISDIR(state_metadata.st_mode)
        or state_metadata.st_uid != 0
        or stat.S_IMODE(state_metadata.st_mode) != 0o700
    ):
        raise PermissionError("privileged broker audit state is unsafe")
    line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(AUDIT, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PermissionError("privileged broker audit file is unsafe")
        written = os.write(descriptor, line)
        if written != len(line):
            raise OSError("privileged broker audit append was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        STATE,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_output_evidence(record: dict[str, object]) -> dict[str, str]:
    """Publish non-secret root-owned evidence for exact broker stdout bytes."""
    request_id = record.get("request_id")
    if not isinstance(request_id, str) or len(request_id) != 32 or any(
        character not in "0123456789abcdef" for character in request_id
    ):
        raise ValueError("privileged output evidence request_id is invalid")
    if record.get("action") != POWER_ACTION:
        raise ValueError("privileged output evidence is only defined for operator power argv")
    if not isinstance(record.get("peer_uid"), int) or not isinstance(record.get("peer_unit"), str):
        raise ValueError("privileged output evidence peer identity is invalid")
    required = {
        "reference_sha256", "action", "mode", "argv_sha256", "cwd_sha256",
        "returncode", "timed_out", "stdout_sha256", "stdout_bytes",
        "stdout_truncated", "timestamp_unix",
    }
    if any(key not in record for key in required):
        raise ValueError("privileged output evidence source record is incomplete")

    try:
        OUTPUT_EVIDENCE_ROOT.mkdir(parents=False, mode=0o700)
    except FileExistsError:
        pass
    metadata = OUTPUT_EVIDENCE_ROOT.lstat()
    if (
        OUTPUT_EVIDENCE_ROOT.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise PermissionError("privileged output evidence directory is unsafe")
    os.chmod(OUTPUT_EVIDENCE_ROOT, 0o755)
    metadata = OUTPUT_EVIDENCE_ROOT.lstat()
    if stat.S_IMODE(metadata.st_mode) != 0o755:
        raise PermissionError("privileged output evidence directory mode is unsafe")

    evidence: dict[str, object] = {
        "schema_version": 1,
        "kind": OUTPUT_EVIDENCE_KIND,
        "request_id": request_id,
        "reference_sha256": record["reference_sha256"],
        "action": record["action"],
        "mode": record["mode"],
        "argv_sha256": record["argv_sha256"],
        "cwd_sha256": record["cwd_sha256"],
        "peer_uid": record.get("peer_uid"),
        "peer_unit": record.get("peer_unit"),
        "returncode": record["returncode"],
        "timed_out": record["timed_out"],
        "stdout_sha256": record["stdout_sha256"],
        "stdout_bytes": record["stdout_bytes"],
        "stdout_truncated": record["stdout_truncated"],
        "timestamp_unix": record["timestamp_unix"],
    }
    evidence["evidence_sha256"] = canonical_sha256(evidence)
    raw = (json.dumps(evidence, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    destination = OUTPUT_EVIDENCE_ROOT / f"{request_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("privileged output evidence write was incomplete")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o644)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1
        ):
            raise PermissionError("privileged output evidence file is unsafe")
    finally:
        os.close(descriptor)
    directory = os.open(
        OUTPUT_EVIDENCE_ROOT,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": str(destination), "sha256": str(evidence["evidence_sha256"])}


def _base_audit_record(
    reference: dict[str, object],
    execution: dict[str, object],
    started: float,
) -> dict[str, object]:
    argv = execution.get("argv")
    cwd = execution.get("cwd")
    record = {
        "schema_version": 1,
        "timestamp_unix": int(time.time()),
        "request_id": str(reference["request_id"]),
        "reference_sha256": str(reference["reference_sha256"]),
        "action": str(reference["action"]),
        "mode": str(execution.get("mode", "template")),
        "target_sha256": hashlib.sha256(str(reference["target"]).encode("utf-8")).hexdigest(),
        "cwd_sha256": hashlib.sha256(str(cwd or "").encode("utf-8")).hexdigest(),
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if isinstance(argv, list):
        record["argv_sha256"] = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    if execution.get("internal_action") is not None:
        record["internal_action"] = str(execution["internal_action"])
    gate = execution.get("gate")
    if isinstance(gate, dict):
        record["gate_recovery_marker_sha256"] = gate.get("recovery_marker_sha256")
        record["gate_recovery_marker_source_sha256"] = gate.get("recovery_marker_source_sha256")
        record["gate_recovery_marker_timestamp_unix"] = gate.get("recovery_marker_timestamp_unix")
        record["gate_recovery_marker_age_seconds"] = gate.get("recovery_marker_age_seconds")
        record["gate_recovery_marker_max_age_seconds"] = gate.get("recovery_marker_max_age_seconds")
        record["gate_recovery_marker_freshness_reason"] = gate.get("recovery_marker_freshness_reason")
    for optional_key in (
        "policy_intent",
        "argv_catalog_sha256",
        "matched_argv_prefix_sha256",
    ):
        optional_value = execution.get(optional_key)
        if optional_value is not None:
            record[optional_key] = optional_value
    return record



def _run_recovery_publication(
    reference: dict[str, object],
    execution: dict[str, object],
) -> int:
    claim_once(STATE / "used", str(reference["request_id"]))
    started = time.monotonic()
    published = publish_recovery_marker(execution)
    record = {
        **_base_audit_record(reference, execution, started),
        "returncode": 0,
        "timed_out": False,
        "published": published.get("published"),
        "idempotent": published.get("idempotent"),
        "recovery_record_sha256": published.get("record_sha256"),
        "recovery_source_record_sha256": published.get("source_record_sha256"),
        "recovery_generated_at_unix": published.get("generated_at_unix"),
        "recovery_freshness_reason": published.get("freshness_reason"),
    }
    append_audit(record)
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution["mode"],
        "returncode": 0,
        "timed_out": False,
        "publication": published,
        "audit": record,
    }, ensure_ascii=False, sort_keys=True))
    return 0

def _socket_peer_credentials(descriptor: int = 0) -> tuple[int, int, int]:
    duplicate = os.dup(descriptor)
    try:
        with socket.socket(fileno=duplicate) as connection:
            raw = connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer is not observable") from exc
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise PermissionError("blockade lifecycle peer credentials are invalid")
    return pid, uid, gid


def _unified_cgroup_path(pid: int, *, proc_root: Path) -> str:
    try:
        cgroup_raw = (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8")
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer cgroup is not observable") from exc
    unified_paths: list[str] = []
    for line in cgroup_raw.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            unified_paths.append(fields[2])
    if len(unified_paths) != 1 or not unified_paths[0].startswith("/"):
        raise PermissionError("blockade lifecycle peer cgroup is not canonical")
    return unified_paths[0]


def _process_identity(pid: int, *, proc_root: Path) -> tuple[int, int]:
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer process identity is not observable") from exc
    closing = raw.rfind(")")
    if closing <= 0 or not raw.startswith(f"{pid} ("):
        raise PermissionError("blockade lifecycle peer process identity is malformed")
    fields = raw[closing + 1 :].strip().split()
    if len(fields) < 20:
        raise PermissionError("blockade lifecycle peer process identity is incomplete")
    try:
        parent_pid = int(fields[1])
        starttime_ticks = int(fields[19])
    except ValueError as exc:
        raise PermissionError("blockade lifecycle peer process identity is invalid") from exc
    if parent_pid <= 0 or starttime_ticks <= 0:
        raise PermissionError("blockade lifecycle peer process identity is invalid")
    return parent_pid, starttime_ticks


def _cgroup_processes(
    unified_path: str,
    *,
    cgroup_root: Path,
) -> tuple[int, ...]:
    relative = Path(unified_path.lstrip("/"))
    if not relative.parts or ".." in relative.parts:
        raise PermissionError("blockade lifecycle service cgroup path is invalid")
    try:
        raw = (cgroup_root / relative / "cgroup.procs").read_text(encoding="utf-8")
    except OSError as exc:
        raise PermissionError("blockade lifecycle service process set is not observable") from exc
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines or len(lines) > MAX_PEER_CGROUP_PROCESSES:
        raise PermissionError("blockade lifecycle service process set is invalid")
    try:
        processes = tuple(sorted({int(line) for line in lines}))
    except ValueError as exc:
        raise PermissionError("blockade lifecycle service process set is malformed") from exc
    if len(processes) != len(lines) or any(pid <= 0 for pid in processes):
        raise PermissionError("blockade lifecycle service process set is invalid")
    return processes


def _operator_system_unit_identity(uid: int, unit: str) -> dict[str, object]:
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise PermissionError("blockade lifecycle operator account is unavailable") from exc
    username = account.pw_name
    if (
        not username
        or len(username) > 64
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in username
        )
    ):
        raise PermissionError("blockade lifecycle operator account is invalid")
    completed = subprocess.run(
        [
            SYSTEMCTL,
            "show",
            unit,
            "--property=MainPID",
            "--property=ControlGroup",
            "--property=ActiveState",
            "--property=SubState",
            "--property=User",
            "--property=FragmentPath",
            "--no-pager",
        ],
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
        env=SAFE_ENV,
    )
    if completed.returncode != 0 or len(completed.stdout) > MAX_SYSTEMD_SHOW_BYTES:
        raise PermissionError("blockade lifecycle operator system unit identity is unavailable")
    try:
        text = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PermissionError("blockade lifecycle operator system unit identity is malformed") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise PermissionError("blockade lifecycle operator system unit identity is malformed")
        values[key] = value
    required = {
        "MainPID",
        "ControlGroup",
        "ActiveState",
        "SubState",
        "User",
        "FragmentPath",
    }
    if set(values) != required:
        raise PermissionError("blockade lifecycle operator system unit identity is incomplete")
    try:
        main_pid = int(values["MainPID"])
    except ValueError as exc:
        raise PermissionError("blockade lifecycle operator MainPID is invalid") from exc
    control_group = values["ControlGroup"]
    fragment = Path(values["FragmentPath"])
    if (
        main_pid <= 1
        or not control_group.startswith("/system.slice/")
        or values["ActiveState"] != "active"
        or values["SubState"] != "running"
        or values["User"] != username
        or fragment != OPERATOR_UNIT_PATH
    ):
        raise PermissionError("blockade lifecycle operator system unit is not authoritative")
    try:
        fragment_meta = fragment.lstat()
    except OSError as exc:
        raise PermissionError("blockade lifecycle operator system unit fragment is unavailable") from exc
    if (
        fragment.is_symlink()
        or not stat.S_ISREG(fragment_meta.st_mode)
        or fragment_meta.st_uid != 0
        or fragment_meta.st_mode & 0o022
    ):
        raise PermissionError("blockade lifecycle operator system unit fragment is unsafe")
    return {
        "main_pid": main_pid,
        "control_group": control_group,
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
        "username": username,
        "home": account.pw_dir,
        "fragment_path": str(fragment),
    }


def _validate_system_cgroup_authority(
    unified_path: str, *, cgroup_root: Path
) -> None:
    relative = Path(unified_path.lstrip("/"))
    if not relative.parts or ".." in relative.parts:
        raise PermissionError("blockade lifecycle operator system cgroup path is invalid")
    target = cgroup_root / relative
    try:
        metadata = target.lstat()
        procs = (target / "cgroup.procs").lstat()
    except OSError as exc:
        raise PermissionError("blockade lifecycle operator system cgroup is unavailable") from exc
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not stat.S_ISREG(procs.st_mode)
        or procs.st_uid != 0
        or procs.st_mode & 0o022
    ):
        raise PermissionError("blockade lifecycle operator system cgroup is not root-controlled")


def _operator_expected_argv(home: str) -> tuple[str, ...]:
    if not isinstance(home, str) or not home.startswith("/") or "\x00" in home:
        raise PermissionError("blockade lifecycle operator home is invalid")
    python = str(Path(home) / ".local/share/grabowski-mcp/.venv/bin/python")
    return (
        python,
        "-m",
        "grabowski_operator",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "18181",
    )


def _process_cmdline(pid: int, *, proc_root: Path) -> tuple[str, ...]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer command identity is not observable") from exc
    if not raw or len(raw) > 16 * 1024 or not raw.endswith(b"\x00"):
        raise PermissionError("blockade lifecycle peer command identity is malformed")
    try:
        argv = tuple(item.decode("utf-8", errors="strict") for item in raw[:-1].split(b"\x00"))
    except UnicodeDecodeError as exc:
        raise PermissionError("blockade lifecycle peer command identity is malformed") from exc
    if not argv or any(not item or "\x00" in item for item in argv):
        raise PermissionError("blockade lifecycle peer command identity is invalid")
    return argv


def _validate_blockade_lifecycle_peer(
    execution: dict[str, object],
    *,
    descriptor: int = 0,
    proc_root: Path = Path("/proc"),
    cgroup_root: Path = CGROUP_ROOT,
    unit_identity: dict[str, object] | None = None,
    expected_argv: tuple[str, ...] | None = None,
) -> dict[str, object]:
    pid, uid, gid = _socket_peer_credentials(descriptor)
    expected_uid = execution.get("allowed_peer_uid")
    expected_unit = execution.get("allowed_peer_unit")
    if (
        isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or uid != expected_uid
    ):
        raise PermissionError("blockade lifecycle peer UID is not authorized")
    if not isinstance(expected_unit, str) or not expected_unit:
        raise PermissionError("blockade lifecycle peer unit is not configured")
    observed_unit = (
        _operator_system_unit_identity(expected_uid, expected_unit)
        if unit_identity is None
        else dict(unit_identity)
    )
    systemd_main_pid = observed_unit.get("main_pid")
    systemd_control_group = observed_unit.get("control_group")
    if systemd_main_pid != pid:
        raise PermissionError("blockade lifecycle peer is not systemd MainPID")
    if not isinstance(systemd_control_group, str) or not systemd_control_group:
        raise PermissionError("blockade lifecycle operator ControlGroup is invalid")

    unified_path = _unified_cgroup_path(pid, proc_root=proc_root)
    expected_suffix = "/" + expected_unit
    if (
        not unified_path.endswith(expected_suffix)
        or unified_path != systemd_control_group
    ):
        raise PermissionError("blockade lifecycle peer is outside the operator service")
    _validate_system_cgroup_authority(
        unified_path, cgroup_root=cgroup_root
    )
    effective_expected_argv = (
        _operator_expected_argv(str(observed_unit.get("home", "")))
        if expected_argv is None
        else tuple(expected_argv)
    )
    if _process_cmdline(pid, proc_root=proc_root) != effective_expected_argv:
        raise PermissionError("blockade lifecycle peer command identity is unauthorized")

    members_before = _cgroup_processes(unified_path, cgroup_root=cgroup_root)
    if pid not in members_before:
        raise PermissionError("blockade lifecycle peer is absent from the operator service cgroup")
    identities = {
        member: _process_identity(member, proc_root=proc_root)
        for member in members_before
    }
    oldest_starttime = min(identity[1] for identity in identities.values())
    oldest_members = tuple(
        member
        for member in members_before
        if identities[member][1] == oldest_starttime
    )
    if len(oldest_members) != 1:
        raise PermissionError(
            "blockade lifecycle operator service main process is ambiguous"
        )
    parent_pid, starttime_ticks = identities[pid]
    if oldest_members[0] != pid:
        raise PermissionError(
            "blockade lifecycle peer is not the operator service main process"
        )
    try:
        parent_cgroup = _unified_cgroup_path(parent_pid, proc_root=proc_root)
    except PermissionError as exc:
        raise PermissionError("blockade lifecycle peer parent is not observable") from exc
    if parent_cgroup == unified_path:
        raise PermissionError("blockade lifecycle peer is a child of the operator service")
    members_after = _cgroup_processes(unified_path, cgroup_root=cgroup_root)
    if members_after != members_before:
        raise PermissionError("blockade lifecycle service process set changed during validation")
    return {
        "pid": pid,
        "uid": uid,
        "gid": gid,
        "cgroup": unified_path,
        "unit": expected_unit,
        "starttime_ticks": starttime_ticks,
        "cgroup_process_count": len(members_before),
        "systemd_main_pid": systemd_main_pid,
        "systemd_control_group": systemd_control_group,
    }


def _operator_peer_audit_fields(peer: dict[str, object]) -> dict[str, object]:
    return {
        "peer_pid": peer["pid"],
        "peer_uid": peer["uid"],
        "peer_gid": peer["gid"],
        "peer_cgroup": peer["cgroup"],
        "peer_unit": peer["unit"],
        "peer_starttime_ticks": peer.get("starttime_ticks"),
        "peer_cgroup_process_count": peer.get("cgroup_process_count"),
        "peer_systemd_main_pid": peer.get("systemd_main_pid"),
        "peer_systemd_control_group": peer.get("systemd_control_group"),
    }


def _lifecycle_audit_base(
    reference: dict[str, object],
    execution: dict[str, object],
    started: float,
    peer: dict[str, object],
) -> dict[str, object]:
    record = {
        **_base_audit_record(reference, execution, started),
        **_operator_peer_audit_fields(peer),
        "lifecycle_operation": execution.get("operation"),
    }
    gate = execution.get("recovery_gate")
    if isinstance(gate, dict):
        record["gate_recovery_marker_sha256"] = gate.get(
            "recovery_marker_sha256"
        )
        record["gate_recovery_marker_source_sha256"] = gate.get(
            "recovery_marker_source_sha256"
        )
    return record


def _append_lifecycle_audit(record: dict[str, object]) -> dict[str, object]:
    enriched = dict(record)
    enriched["record_sha256"] = canonical_sha256(enriched)
    append_audit(enriched)
    return enriched


def _run_blockade_lifecycle(
    reference: dict[str, object],
    execution: dict[str, object],
    *,
    peer: dict[str, object],
) -> int:
    claim_once(STATE / "used", str(reference["request_id"]))
    started = time.monotonic()
    intent = _append_lifecycle_audit(
        {
            **_lifecycle_audit_base(reference, execution, started, peer),
            "phase": "intent",
            "returncode": None,
            "timed_out": False,
        }
    )
    try:
        lifecycle = execute_lifecycle(execution)
    except BaseException as lifecycle_failure:
        failure = {
            **_lifecycle_audit_base(reference, execution, started, peer),
            "phase": "failure",
            "returncode": 1,
            "timed_out": False,
            "intent_record_sha256": intent["record_sha256"],
            "error_type": type(lifecycle_failure).__name__,
            "error": str(lifecycle_failure)[:500],
        }
        try:
            _append_lifecycle_audit(failure)
        except BaseException as audit_failure:
            raise RuntimeError(
                "blockade lifecycle failed after intent and failure audit could not be written"
            ) from audit_failure
        raise
    completion = _append_lifecycle_audit(
        {
            **_lifecycle_audit_base(reference, execution, started, peer),
            "phase": "complete",
            "returncode": 0,
            "timed_out": False,
            "intent_record_sha256": intent["record_sha256"],
            "lifecycle_sha256": canonical_sha256(lifecycle),
            "lifecycle_receipt_sha256": lifecycle.get("receipt_sha256"),
        }
    )
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution["mode"],
        "returncode": 0,
        "timed_out": False,
        "lifecycle": lifecycle,
        "audit_intent": intent,
        "audit": completion,
    }, ensure_ascii=False, sort_keys=True))
    return 0


def _communicate_after_timeout(
    *,
    action: object,
    process: object,
) -> tuple[bytes, bytes]:
    if action == ROOTBROKER_CUTOVER_ACTION:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return process.communicate(
                timeout=ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS
            )
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.communicate()


def main() -> int:
    if os.geteuid() != 0:
        raise PermissionError("privileged broker must run as root")
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    reference = parse_reference(data)
    config = load_root_config(CONFIG)
    execution = resolve_execution(config, reference)
    operator_peer: dict[str, object] | None = None
    if (
        reference.get("action") in {
            POWER_ACTION,
            BLOCKADE_LIFECYCLE_ACTION,
            ROOTBROKER_CUTOVER_ACTION,
        }
        or execution.get("allowed_peer_uid") is not None
        or execution.get("allowed_peer_unit") is not None
    ):
        operator_peer = _validate_blockade_lifecycle_peer(execution)
    if execution.get("mode") == "recovery-marker-publish":
        return _run_recovery_publication(reference, execution)
    if execution.get("mode") == "blockade-marker-lifecycle":
        assert operator_peer is not None
        return _run_blockade_lifecycle(
            reference, execution, peer=operator_peer
        )
    argv = execution["argv"]
    timeout = execution["timeout_seconds"]
    cwd = execution.get("cwd")
    if cwd is not None and not Path(str(cwd)).is_dir():
        raise ValueError("privileged cwd is not an existing directory")
    claim_once(STATE / "used", str(reference["request_id"]))
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SAFE_ENV,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout_bytes, stderr_bytes = _communicate_after_timeout(
            action=reference.get("action"),
            process=process,
        )
    stdout = stdout_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    stderr = stderr_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    record = {
        **_base_audit_record(reference, execution, started),
        **(
            _operator_peer_audit_fields(operator_peer)
            if operator_peer is not None
            else {}
        ),
        "returncode": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "stdout_truncated": len(stdout_bytes) > MAX_OUTPUT_BYTES,
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "stdout_bytes": len(stdout_bytes),
        "stderr_truncated": len(stderr_bytes) > MAX_OUTPUT_BYTES,
        "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "stderr_bytes": len(stderr_bytes),
    }
    append_audit(record)
    output_evidence = (
        _write_output_evidence(record) if reference["action"] == POWER_ACTION else None
    )
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution.get("mode", "template"),
        "returncode": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "audit": record,
        "output_evidence": output_evidence,
    }, ensure_ascii=False, sort_keys=True))
    # The socket client returns non-zero for non-zero action returncodes. The
    # broker process itself exits successfully after a structured response so a
    # handled request failure does not leave a failed transient systemd unit.
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(0)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)

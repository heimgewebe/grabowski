#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
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
MAX_OUTPUT_BYTES = 250_000
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


def _validate_blockade_lifecycle_peer(
    execution: dict[str, object],
    *,
    descriptor: int = 0,
    proc_root: Path = Path("/proc"),
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
    cgroup_path = proc_root / str(pid) / "cgroup"
    try:
        cgroup_raw = cgroup_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer cgroup is not observable") from exc
    expected_suffix = "/" + expected_unit
    unified_paths = []
    for line in cgroup_raw.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            unified_paths.append(fields[2])
    if len(unified_paths) != 1 or not unified_paths[0].endswith(expected_suffix):
        raise PermissionError("blockade lifecycle peer is outside the operator service")
    return {
        "pid": pid,
        "uid": uid,
        "gid": gid,
        "cgroup": unified_paths[0],
        "unit": expected_unit,
    }


def _lifecycle_audit_base(
    reference: dict[str, object],
    execution: dict[str, object],
    started: float,
    peer: dict[str, object],
) -> dict[str, object]:
    record = {
        **_base_audit_record(reference, execution, started),
        "lifecycle_operation": execution.get("operation"),
        "peer_uid": peer["uid"],
        "peer_gid": peer["gid"],
        "peer_cgroup": peer["cgroup"],
        "peer_unit": peer["unit"],
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
) -> int:
    peer = _validate_blockade_lifecycle_peer(execution)
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


def main() -> int:
    if os.geteuid() != 0:
        raise PermissionError("privileged broker must run as root")
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    reference = parse_reference(data)
    config = load_root_config(CONFIG)
    execution = resolve_execution(config, reference)
    if execution.get("mode") == "recovery-marker-publish":
        return _run_recovery_publication(reference, execution)
    if execution.get("mode") == "blockade-marker-lifecycle":
        return _run_blockade_lifecycle(reference, execution)
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
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout_bytes, stderr_bytes = process.communicate()
    stdout = stdout_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    stderr = stderr_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    record = {
        **_base_audit_record(reference, execution, started),
        "returncode": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "stdout_truncated": len(stdout_bytes) > MAX_OUTPUT_BYTES,
        "stderr_truncated": len(stderr_bytes) > MAX_OUTPUT_BYTES,
    }
    append_audit(record)
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution.get("mode", "template"),
        "returncode": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "audit": record,
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

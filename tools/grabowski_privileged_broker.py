#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

LIB_DIR = Path("/usr/local/lib/grabowski")
sys.path.insert(0, str(LIB_DIR))

from grabowski_privileged_broker import (
    MAX_INPUT_BYTES,
    claim_once,
    load_root_config,
    parse_reference,
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
    line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        AUDIT,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, line)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _base_audit_record(
    reference: dict[str, object],
    execution: dict[str, object],
    started: float,
) -> dict[str, object]:
    argv = execution["argv"]
    cwd = execution.get("cwd")
    record = {
        "schema_version": 1,
        "timestamp_unix": int(time.time()),
        "request_id": str(reference["request_id"]),
        "reference_sha256": str(reference["reference_sha256"]),
        "action": str(reference["action"]),
        "mode": str(execution.get("mode", "template")),
        "target_sha256": hashlib.sha256(str(reference["target"]).encode("utf-8")).hexdigest(),
        "argv_sha256": hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "cwd_sha256": hashlib.sha256(str(cwd or "").encode("utf-8")).hexdigest(),
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    gate = execution.get("gate")
    if isinstance(gate, dict):
        record["gate_recovery_marker_sha256"] = gate.get("recovery_marker_sha256")
        record["gate_recovery_marker_timestamp_unix"] = gate.get("recovery_marker_timestamp_unix")
    return record


def main() -> int:
    if os.geteuid() != 0:
        raise PermissionError("privileged broker must run as root")
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    reference = parse_reference(data)
    config = load_root_config(CONFIG)
    execution = resolve_execution(config, reference)
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
    except (FileExistsError, PermissionError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(0)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)

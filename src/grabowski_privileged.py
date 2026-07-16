from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any
import uuid

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
BROKER = Path(os.environ.get(
    "GRABOWSKI_PRIVILEGED_BROKER",
    "/usr/local/libexec/grabowski-privileged-broker",
))
BROKER_CONFIG = Path(os.environ.get(
    "GRABOWSKI_PRIVILEGED_BROKER_CONFIG",
    "/etc/grabowski/privileged-actions.json",
))
BROKER_SOCKET = Path(os.environ.get(
    "GRABOWSKI_PRIVILEGED_BROKER_SOCKET",
    "/run/grabowski/privileged-broker.sock",
))


def _root_file(path: Path, executable: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path), "exists": False, "regular": False,
        "root_owned": False, "not_group_or_world_writable": False,
        "executable": False, "valid": False,
    }
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return result
    result["exists"] = True
    result["regular"] = stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
    result["root_owned"] = metadata.st_uid == 0
    result["not_group_or_world_writable"] = not bool(metadata.st_mode & 0o022)
    result["executable"] = bool(metadata.st_mode & 0o111)
    result["valid"] = bool(
        result["regular"] and result["root_owned"]
        and result["not_group_or_world_writable"]
        and (result["executable"] if executable else True)
    )
    return result


def _socket(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path), "exists": False, "socket": False,
        "owner_uid": None, "owner_gid": None, "mode": None, "valid": False,
    }
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return result
    result.update({
        "exists": True,
        "socket": stat.S_ISSOCK(metadata.st_mode),
        "owner_uid": metadata.st_uid,
        "owner_gid": metadata.st_gid,
        "mode": oct(stat.S_IMODE(metadata.st_mode)),
    })
    result["valid"] = bool(result["socket"] and not (metadata.st_mode & 0o007))
    return result


def _privileged_broker_status() -> dict[str, Any]:
    broker = _root_file(BROKER, True)
    config = _root_file(BROKER_CONFIG, False)
    broker_socket = _socket(BROKER_SOCKET)
    command = shutil.which("grabowski-privileged-request")
    return {
        "broker": broker,
        "config": config,
        "socket": broker_socket,
        "request_client": command,
        "ready": bool(
            broker["valid"] and config["valid"]
            and broker_socket["valid"] and command
        ),
        "execution_model": "root-owned-systemd-socket-template-broker",
        "reference_tool": "grabowski_privileged_action_reference",
        "fail_closed": True,
    }


@mcp.tool(name="grabowski_privileged_broker_status", annotations=READ_ONLY)
def grabowski_privileged_broker_status() -> dict[str, Any]:
    """Inspect the fail-closed root-owned privileged broker installation."""
    operator._require_operator_capability("privileged_reference")
    return _privileged_broker_status()

POWER_ACTION = "operator_power_argv"
RECOVERY_PUBLISH_ACTION = "publish_recovery_marker"
BLOCKADE_LIFECYCLE_ACTION = "operator_blockade_marker_lifecycle"
ROOT_TASK_SYSTEMD_ACTION = "operator_root_task_systemd_unit"
POWER_REFERENCE_TTL_SECONDS = 900
POWER_MAX_TARGET_BYTES = 48 * 1024
POWER_REFERENCE_DIR = Path(os.environ.get(
    "GRABOWSKI_POWER_REFERENCE_DIR",
    str(Path.home() / ".local" / "state" / "grabowski" / "power-references"),
))


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _redact_text(value: str, extra_secrets: list[str] | None = None) -> str:
    redactor = getattr(operator, "_redact", None)
    if redactor is None:
        return value
    return redactor(value, extra_secrets)


def _append_operator_audit(record: dict[str, Any]) -> None:
    backend = getattr(operator, "base", None)
    append = getattr(backend, "_append_audit", None)
    if not callable(append):
        raise RuntimeError("operator audit backend is unavailable")
    append(record)


def _limit_text(value: str, limit: int) -> tuple[str, bool]:
    limiter = getattr(operator, "_limit", None)
    if limiter is not None:
        return limiter(value, limit)
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="replace") + "\n<OUTPUT_TRUNCATED>", True


def _normalize_power_argv(argv: list[str]) -> list[str]:
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")
    if len(argv) > 128:
        raise ValueError("argv exceeds item limit")
    normalized = []
    for item in argv:
        if "\x00" in item or len(item.encode("utf-8")) > 32 * 1024:
            raise ValueError("argv item is invalid")
        if _redact_text(item) != item:
            raise ValueError("argv appears to contain secret material")
        normalized.append(item)
    if not Path(normalized[0]).is_absolute():
        raise ValueError("argv[0] must be an absolute executable path")
    return normalized


def _normalize_power_cwd(cwd: str | None) -> str:
    value = "/" if cwd is None else cwd
    if not isinstance(value, str) or not value:
        raise ValueError("cwd must be a non-empty string when supplied")
    if "\x00" in value or len(value.encode("utf-8")) > 1000:
        raise ValueError("cwd is invalid")
    if _redact_text(value) != value:
        raise ValueError("cwd appears to contain secret material")
    if not Path(value).is_absolute():
        raise ValueError("cwd must be absolute for privileged execution")
    return value


def _normalize_power_timeout(timeout_seconds: int) -> int:
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 3600:
        raise ValueError("timeout_seconds must be between 1 and 3600")
    return timeout_seconds


def _normalize_power_output_limit(max_output_bytes: int) -> int:
    if not isinstance(max_output_bytes, int) or not 1 <= max_output_bytes <= 2_000_000:
        raise ValueError("max_output_bytes must be between 1 and 2000000")
    return max_output_bytes


def _normalize_power_justification(justification: str) -> str:
    if not isinstance(justification, str) or not justification.strip():
        raise ValueError("justification must be a non-empty string")
    if "\x00" in justification or len(justification.encode("utf-8")) > 2000:
        raise ValueError("justification is invalid")
    if _redact_text(justification) != justification:
        raise ValueError("justification appears to contain secret material")
    return justification.strip()


def _power_recovery_status() -> dict[str, Any]:
    import grabowski_recovery as recovery
    return recovery.grabowski_recovery_status()


def _create_privileged_reference(
    *,
    action: str,
    target: str,
    justification: str,
) -> dict[str, Any]:
    if len(target.encode("utf-8")) > POWER_MAX_TARGET_BYTES:
        raise ValueError("privileged target exceeds size limit")
    created_at = int(time.time())
    payload: dict[str, Any] = {
        "schema_version": 1,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_privileged_agent": True,
        "replay_policy": "single-use-external-broker",
        "action": action,
        "target": target,
        "justification": justification,
        "request_id": uuid.uuid4().hex,
        "created_at_unix": created_at,
        "expires_at_unix": created_at + POWER_REFERENCE_TTL_SECONDS,
    }
    payload["reference_sha256"] = _canonical_sha256(payload)
    return payload


def _create_power_reference(target: str, justification: str) -> dict[str, Any]:
    return _create_privileged_reference(
        action=POWER_ACTION,
        target=target,
        justification=justification,
    )

def _write_power_reference(reference: dict[str, Any]) -> Path:
    POWER_REFERENCE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(
        prefix="power-",
        suffix=".json",
        dir=POWER_REFERENCE_DIR,
        text=True,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(reference, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    path = Path(name)
    path.chmod(0o600)
    return path


def _invoke_privileged_reference(
    *,
    action: str,
    target: str,
    justification: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    broker = _privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    reference = _create_privileged_reference(
        action=action,
        target=target,
        justification=justification,
    )
    reference_path = _write_power_reference(reference)
    client = str(broker["request_client"])
    client_timed_out = False
    broker_client_returncode: int | None
    try:
        completed = subprocess.run(
            [client, str(reference_path)],
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds + 15,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        broker_client_returncode = completed.returncode
        stdout_raw = completed.stdout
        stderr_raw = completed.stderr
    except subprocess.TimeoutExpired as exc:
        client_timed_out = True
        broker_client_returncode = None
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b"privileged broker client timed out"
    finally:
        try:
            reference_path.unlink(missing_ok=True)
        except OSError:
            pass

    stdout_full = _redact_text(stdout_raw.decode("utf-8", errors="replace"))
    stderr_full = _redact_text(stderr_raw.decode("utf-8", errors="replace"))
    stdout, stdout_truncated = _limit_text(stdout_full, max_output_bytes)
    stderr, stderr_truncated = _limit_text(stderr_full, max_output_bytes)
    try:
        parsed = json.loads(stdout_full) if stdout_full.strip() else None
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        for key in ("stdout", "stderr"):
            if isinstance(parsed.get(key), str):
                parsed[key], parsed[f"{key}_truncated_by_client"] = _limit_text(
                    _redact_text(parsed[key]),
                    max_output_bytes,
                )
    return {
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "broker_client_returncode": broker_client_returncode,
        "broker_client_timed_out": client_timed_out,
        "broker_response": parsed,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def root_task_systemd_request(
    payload: dict[str, Any],
    *,
    timeout_seconds: int = 60,
    max_output_bytes: int = 250_000,
) -> dict[str, Any]:
    target = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    invoked = _invoke_privileged_reference(
        action=ROOT_TASK_SYSTEMD_ACTION,
        target=target,
        justification="Operate one Grabowski root-owned systemd task unit",
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    parsed = invoked["broker_response"]
    broker_returncode = parsed.get("returncode") if isinstance(parsed, dict) else None
    broker_timed_out = bool(parsed.get("timed_out")) if isinstance(parsed, dict) else False
    root_truth_observable = (
        not invoked["broker_client_timed_out"]
        and not broker_timed_out
        and isinstance(broker_returncode, int)
    )
    stdout = parsed.get("stdout") if isinstance(parsed, dict) and isinstance(parsed.get("stdout"), str) else invoked["stdout"]
    stderr = parsed.get("stderr") if isinstance(parsed, dict) and isinstance(parsed.get("stderr"), str) else invoked["stderr"]
    return {
        "returncode": broker_returncode if isinstance(broker_returncode, int) else 1,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": bool(invoked["broker_client_timed_out"] or broker_timed_out),
        "stdout_truncated": bool(
            invoked["stdout_truncated"]
            or (isinstance(parsed, dict) and parsed.get("stdout_truncated"))
            or (isinstance(parsed, dict) and parsed.get("stdout_truncated_by_client"))
        ),
        "stderr_truncated": bool(
            invoked["stderr_truncated"]
            or (isinstance(parsed, dict) and parsed.get("stderr_truncated"))
            or (isinstance(parsed, dict) and parsed.get("stderr_truncated_by_client"))
        ),
        "root_truth_observable": root_truth_observable,
        "outcome_unknown": not root_truth_observable,
        "privileged_broker": invoked,
    }


def publish_recovery_marker_reference(
    *,
    source_record_sha256: str,
    generated_at_unix: int,
) -> dict[str, Any]:
    if (
        not isinstance(source_record_sha256, str)
        or len(source_record_sha256) != 64
        or any(character not in "0123456789abcdef" for character in source_record_sha256)
    ):
        raise ValueError("source_record_sha256 must be a lowercase SHA-256 digest")
    if isinstance(generated_at_unix, bool) or not isinstance(generated_at_unix, int):
        raise ValueError("generated_at_unix must be an integer")
    broker = grabowski_privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    target = json.dumps(
        {
            "source_record_sha256": source_record_sha256,
            "generated_at_unix": generated_at_unix,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    reference = _create_privileged_reference(
        action=RECOVERY_PUBLISH_ACTION,
        target=target,
        justification="Publish one validated recovery record to the root-owned canonical gate",
    )
    reference_path = _write_power_reference(reference)
    client = str(broker["request_client"])
    client_timed_out = False
    broker_client_returncode: int | None
    try:
        completed = subprocess.run(
            [client, str(reference_path)],
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        broker_client_returncode = completed.returncode
        stdout_raw = completed.stdout
        stderr_raw = completed.stderr
    except subprocess.TimeoutExpired as exc:
        client_timed_out = True
        broker_client_returncode = None
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b"privileged broker client timed out"
    finally:
        try:
            reference_path.unlink(missing_ok=True)
        except OSError:
            pass

    stdout = _redact_text(stdout_raw.decode("utf-8", errors="replace"))
    stderr = _redact_text(stderr_raw.decode("utf-8", errors="replace"))
    try:
        parsed = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        parsed = None
    publication = parsed.get("publication") if isinstance(parsed, dict) else None
    success = bool(
        broker_client_returncode == 0
        and not client_timed_out
        and isinstance(parsed, dict)
        and parsed.get("returncode") == 0
        and isinstance(publication, dict)
        and publication.get("freshness_reason") == "ready"
    )
    failure_reason: str | None = None
    if client_timed_out:
        failure_reason = "privileged broker client timed out"
    elif broker_client_returncode != 0:
        failure_reason = f"privileged broker client exited with {broker_client_returncode}"
    elif isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        failure_reason = parsed["error"]
    elif not success:
        failure_reason = stderr.strip() or "privileged broker returned no valid publication receipt"

    audit_record = {
        "tool": "publish_recovery_marker_reference",
        "action": RECOVERY_PUBLISH_ACTION,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "source_record_sha256": source_record_sha256,
        "generated_at_unix": generated_at_unix,
        "broker_client_returncode": broker_client_returncode,
        "broker_client_timed_out": client_timed_out,
        "failure_reason": failure_reason,
        "success": success,
    }
    _append_operator_audit(audit_record)
    return {
        "success": success,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "broker_client_returncode": broker_client_returncode,
        "broker_client_timed_out": client_timed_out,
        "failure_reason": failure_reason,
        "broker_response": parsed,
        "publication": publication,
        "stderr": stderr,
    }


def run_blockade_lifecycle_reference(
    payload: dict[str, Any],
    *,
    justification: str,
) -> dict[str, Any]:
    """Submit one marker lifecycle operation without automatic retry.

    A timeout or malformed broker response is ``unknown`` because the root
    mutation may already have committed. The caller must classify that state
    through exact marker readback.
    """
    if not isinstance(payload, dict) or not payload:
        raise ValueError("blockade lifecycle payload must be a non-empty object")
    reason = _normalize_power_justification(justification)
    broker = grabowski_privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    target = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    reference = _create_privileged_reference(
        action=BLOCKADE_LIFECYCLE_ACTION,
        target=target,
        justification=reason,
    )
    reference_path = _write_power_reference(reference)
    client = str(broker["request_client"])
    timed_out = False
    returncode: int | None
    try:
        completed = subprocess.run(
            [client, str(reference_path)],
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        returncode = completed.returncode
        stdout_raw = completed.stdout
        stderr_raw = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b"privileged broker client timed out"
    finally:
        try:
            reference_path.unlink(missing_ok=True)
        except OSError:
            pass

    stdout = _redact_text(stdout_raw.decode("utf-8", errors="replace"))
    stderr = _redact_text(stderr_raw.decode("utf-8", errors="replace"))
    try:
        parsed = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        parsed = None
    lifecycle = parsed.get("lifecycle") if isinstance(parsed, dict) else None
    success = bool(
        returncode == 0
        and not timed_out
        and isinstance(parsed, dict)
        and parsed.get("returncode") == 0
        and isinstance(lifecycle, dict)
    )
    if success:
        outcome = "succeeded"
        failure_reason = None
    else:
        # The root broker claims the request before entering the internal
        # lifecycle and may mutate before its own audit or response fails. No
        # client-visible error shape proves that the filesystem is unchanged.
        outcome = "unknown"
        if timed_out:
            failure_reason = "privileged broker client timed out"
        elif isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
            failure_reason = parsed["error"]
        elif returncode not in {0, None}:
            failure_reason = f"privileged broker client exited with {returncode}"
        else:
            failure_reason = (
                stderr.strip()
                or "privileged broker outcome requires exact root readback"
            )
    audit_record = {
        "tool": "run_blockade_lifecycle_reference",
        "action": BLOCKADE_LIFECYCLE_ACTION,
        "operation": payload.get("operation"),
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "target_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        "broker_client_returncode": returncode,
        "broker_client_timed_out": timed_out,
        "outcome": outcome,
        "failure_reason": failure_reason,
    }
    _append_operator_audit(audit_record)
    return {
        "success": success,
        "outcome": outcome,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "target_sha256": audit_record["target_sha256"],
        "broker_client_returncode": returncode,
        "broker_client_timed_out": timed_out,
        "failure_reason": failure_reason,
        "broker_response": parsed,
        "lifecycle": lifecycle,
        "stderr": stderr,
    }


@mcp.tool(name="grabowski_power_run", annotations=MUTATING)
def grabowski_power_run(
    argv: list[str],
    cwd: str | None = None,
    timeout_seconds: int = 300,
    justification: str = "",
    max_output_bytes: int = 250_000,
) -> dict[str, Any]:
    """Run one audited root command through the recovery-gated power broker."""
    operator._require_operator_mutation("power_execute")
    command = _normalize_power_argv(argv)
    working_directory = _normalize_power_cwd(cwd)
    timeout = _normalize_power_timeout(timeout_seconds)
    output_limit = _normalize_power_output_limit(max_output_bytes)
    reason = _normalize_power_justification(justification)

    broker = grabowski_privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    recovery = _power_recovery_status()
    if not (
        recovery.get("ready_for_user_power_worker")
        and recovery.get("ready_for_privileged_actions")
    ):
        raise PermissionError("recovery gate is not ready for power-worker execution")

    target = json.dumps(
        {"argv": command, "cwd": working_directory, "timeout_seconds": timeout},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    reference = _create_power_reference(target, reason)
    reference_path = _write_power_reference(reference)
    client = str(broker["request_client"])
    started = time.monotonic()
    client_timed_out = False
    broker_client_returncode: int | None
    try:
        completed = subprocess.run(
            [client, str(reference_path)],
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 15,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        broker_client_returncode = completed.returncode
        stdout_raw = completed.stdout
        stderr_raw = completed.stderr
    except subprocess.TimeoutExpired as exc:
        client_timed_out = True
        broker_client_returncode = None
        stdout_raw = exc.stdout or b""
        stderr_raw = exc.stderr or b"privileged broker client timed out"
    finally:
        try:
            reference_path.unlink(missing_ok=True)
        except OSError:
            pass

    stdout = stdout_raw.decode("utf-8", errors="replace")
    stderr = stderr_raw.decode("utf-8", errors="replace")
    stdout = _redact_text(stdout)
    stderr = _redact_text(stderr)
    stdout, stdout_truncated = _limit_text(stdout, output_limit)
    stderr, stderr_truncated = _limit_text(stderr, output_limit)
    parsed: dict[str, Any] | None = None
    try:
        value = json.loads(stdout) if stdout.strip() else None
        if isinstance(value, dict):
            parsed = value
            if isinstance(parsed.get("stdout"), str):
                parsed["stdout"], parsed["stdout_truncated_by_client"] = _limit_text(
                    _redact_text(parsed["stdout"]), output_limit
                )
            if isinstance(parsed.get("stderr"), str):
                parsed["stderr"], parsed["stderr_truncated_by_client"] = _limit_text(
                    _redact_text(parsed["stderr"]), output_limit
                )
    except json.JSONDecodeError:
        parsed = None

    broker_returncode = parsed.get("returncode") if isinstance(parsed, dict) else None
    success = broker_client_returncode == 0 and broker_returncode == 0 and not client_timed_out
    audit_record = {
        "tool": "grabowski_power_run",
        "action": POWER_ACTION,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "argv_sha256": getattr(operator, "_argv_hash", lambda value: _canonical_sha256(value))(command),
        "cwd_sha256": hashlib.sha256(working_directory.encode("utf-8")).hexdigest(),
        "broker_client_returncode": broker_client_returncode,
        "broker_client_timed_out": client_timed_out,
        "broker_returncode": broker_returncode,
        "success": success,
        "duration_seconds": round(time.monotonic() - started, 3),
        "recovery_checked_at_unix": recovery.get("checked_at_unix"),
    }
    _append_operator_audit(audit_record)
    return {
        "success": success,
        "execution_model": "recovery-gated-root-power-worker",
        "action": POWER_ACTION,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "argv_sha256": audit_record["argv_sha256"],
        "cwd_sha256": audit_record["cwd_sha256"],
        "broker_client_returncode": broker_client_returncode,
        "broker_client_timed_out": client_timed_out,
        "broker_response": parsed,
        "stdout": None if parsed is not None else stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "recovery_gate": {
            "ready_for_user_power_worker": recovery.get("ready_for_user_power_worker"),
            "ready_for_privileged_actions": recovery.get("ready_for_privileged_actions"),
            "checked_at_unix": recovery.get("checked_at_unix"),
        },
    }

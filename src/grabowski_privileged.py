from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
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
import grabowski_merge_authority as merge_authority

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
    return _privileged_broker_status()

POWER_ACTION = "operator_power_argv"
RECOVERY_PUBLISH_ACTION = "publish_recovery_marker"
PROCESS_REFERENCE_ACTION = "observe_process_references"
PROCESS_REFERENCE_KIND = "grabowski_process_reference_observation"
PROCESS_REFERENCE_ALLOWED_ROOTS = (
    Path("/home/alex/repos/.weltgewebe-audit-implementation"),
    Path("/home/alex/repos/.weltgewebe-audit-main-20260717"),
    Path("/home/alex/repos/.weltgewebe-release-worktrees"),
    Path("/home/alex/repos/.weltgewebe-standalone"),
    Path("/home/alex/repos/.weltgewebe-worktrees"),
    Path("/home/alex/worktrees"),
    Path("/home/alex/repos/.semantah-standalone"),
    Path("/home/alex/repos/.semantah-worktrees"),
    Path("/home/alex/repos/.heimlern-worktrees"),
    Path("/home/alex/repos/.operator-redundancy-worktrees"),
    Path("/home/alex/repos/.audio-standalone"),
    Path("/home/alex/repos/.audio-worktrees"),
    Path("/home/alex/repos/.hauski-worktrees"),
    Path("/home/alex/repos/.hauski-audio-worktrees"),
    Path("/home/alex/repos/.grabowski-deploy-worktrees"),
    Path("/home/alex/repos/.grabowski-standalone"),
    Path("/home/alex/repos/.grabowski-worktrees"),
    Path("/home/alex/repos/.heim-pc-standalone"),
    Path("/home/alex/repos/.heim-pc-worktrees"),
    Path("/home/alex/repos/.bureau-audit-clones"),
    Path("/home/alex/repos/.bureau-audits"),
    Path("/home/alex/repos/.bureau-standalone"),
    Path("/home/alex/repos/.bureau-task-worktrees"),
    Path("/home/alex/repos/.bureau-worktrees"),
    Path("/home/alex/repos/.repoground-audits"),
    Path("/home/alex/repos/.repoground-standalone"),
    Path("/home/alex/repos/.repoground-task-worktrees"),
    Path("/home/alex/repos/.repoground-worktrees"),
    Path("/home/alex/repos/.commonworld-audits"),
    Path("/home/alex/repos/.commonworld-standalone"),
    Path("/home/alex/repos/.commonworld-worktrees"),
    Path("/home/alex/repos/.plexer-worktrees"),
    Path("/home/alex/repos/.worktree-target-quarantine"),
    Path("/home/alex/.cache/heim-pc/managed-builds"),
    Path("/home/alex/.cache/pip"),
    Path("/home/alex/.cache/uv"),
    Path("/home/alex/.cache/ms-playwright"),
    Path("/home/alex/.local/share/Trash"),
    Path("/home/alex/.local/share/grabowski-mcp-releases"),
    Path("/home/alex/.local/state/heim-pc/cache-maintenance/plans"),
    Path("/home/alex/.local/state/heim-pc/cache-maintenance/receipts"),
)
# Fixed Heim-PC cleanup roots are matched lexically only.  They never need
# filesystem visibility inside the rootbroker namespace, and descendants are
# deliberately not accepted through these entries.
PROCESS_REFERENCE_LEXICAL_ROOTS = (
    Path("/home/alex/.cache/heim-pc/managed-builds"),
    Path("/home/alex/.cache/pip"),
    Path("/home/alex/.cache/uv"),
    Path("/home/alex/.cache/ms-playwright"),
    Path("/home/alex/.local/share/Trash"),
    Path("/home/alex/.local/share/grabowski-mcp-releases"),
    Path("/home/alex/.local/state/heim-pc/cache-maintenance/plans"),
    Path("/home/alex/.local/state/heim-pc/cache-maintenance/receipts"),
)
BLOCKADE_LIFECYCLE_ACTION = "operator_blockade_marker_lifecycle"
ROOT_TASK_SYSTEMD_ACTION = "operator_root_task_systemd_unit"
ROOTBROKER_CUTOVER_ACTION = "operator_rootbroker_cutover"
CRITICAL_USER_DATA_INVENTORY_ACTION = "critical_user_data_inventory"
CRITICAL_USER_DATA_INVENTORY_READ_ACTION = "critical_user_data_inventory_read"
OPERATOR_AUTHORITY_ATTESTATION_PATH = Path(
    "/var/lib/grabowski/operator-authority-attestation.v1.json"
)
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
    merge_bypass_reason = merge_authority.direct_merge_bypass_reason(normalized)
    if merge_bypass_reason is not None:
        raise PermissionError(
            "direct pull-request merge through privileged command execution is blocked "
            f"({merge_bypass_reason}); use Captain pr-merge so review reconciliation "
            "cannot be bypassed"
        )
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


def _invoke_mainpid_privileged_reference(
    *,
    action: str,
    target: str,
    justification: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Invoke one inventory Rootbroker action directly from the operator MainPID."""
    if action not in {
        CRITICAL_USER_DATA_INVENTORY_ACTION,
        CRITICAL_USER_DATA_INVENTORY_READ_ACTION,
    }:
        raise ValueError("MainPID privileged inventory action is not allowed")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 120
    ):
        raise ValueError("MainPID privileged inventory timeout is invalid")
    broker = _privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    reference = _create_privileged_reference(
        action=action,
        target=target,
        justification=justification,
    )
    payload = (
        json.dumps(reference, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if not payload or len(payload) > 64 * 1024:
        raise ValueError("privileged reference exceeds broker input limit")

    client_timed_out = False
    transport_error: str | None = None
    chunks: list[bytes] = []
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds + 15)
            client.connect(str(BROKER_SOCKET))
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            total = 0
            while True:
                chunk = client.recv(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 512 * 1024:
                    raise RuntimeError(
                        "privileged broker response exceeds output limit"
                    )
                chunks.append(chunk)
    except (socket.timeout, TimeoutError) as exc:
        client_timed_out = True
        transport_error = str(exc) or "privileged broker request timed out"
    except (OSError, RuntimeError) as exc:
        transport_error = f"{type(exc).__name__}: {exc}"

    stdout_full = _redact_text(
        b"".join(chunks).decode("utf-8", errors="replace")
    )
    stderr_full = _redact_text(transport_error or "")
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
        "broker_client_returncode": None,
        "broker_client_timed_out": client_timed_out,
        "broker_client_transport_error": transport_error,
        "broker_response": parsed,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def _operator_authority_attestation_head() -> str | None:
    path = OPERATOR_AUTHORITY_ATTESTATION_PATH
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) != 0o644
            or before.st_size <= 0
            or before.st_size > 64 * 1024
        ):
            return None
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
    identity_before = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns, before.st_mode, before.st_uid, before.st_gid, before.st_nlink,
    )
    identity_after = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid, after.st_nlink,
    )
    data = b"".join(chunks)
    if len(data) != before.st_size or identity_before != identity_after:
        return None
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != "grabowski_operator_authority_attestation"
    ):
        return None
    expected_head = value.get("expected_head")
    if (
        not isinstance(expected_head, str)
        or len(expected_head) != 40
        or any(character not in "0123456789abcdef" for character in expected_head)
    ):
        return None
    observed_hash = value.get("attestation_sha256")
    unsigned = dict(value)
    unsigned.pop("attestation_sha256", None)
    expected_hash = hashlib.sha256(
        (
            json.dumps(
                unsigned,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    if observed_hash != expected_hash:
        return None
    return expected_head


class RootbrokerAuthorityFailureAfterObservedEffect(RuntimeError):
    """Rootbroker refresh failed after the request/effect boundary was observed."""

    def __init__(self, message: str, *, authority: dict[str, Any]) -> None:
        super().__init__(message)
        self.authority = dict(authority)


def ensure_rootbroker_authority(
    expected_head: str, *, force_refresh: bool = False
) -> dict[str, Any]:
    """Advance root-owned operator authority to exact main without user interaction."""
    operator._require_operator_capability("privileged_reference")
    if not isinstance(force_refresh, bool):
        raise ValueError("force_refresh must be a boolean")
    if (
        not isinstance(expected_head, str)
        or len(expected_head) != 40
        or any(character not in "0123456789abcdef" for character in expected_head)
    ):
        raise ValueError("expected_head must be one full SHA-1 commit id")
    before = _operator_authority_attestation_head()
    if before == expected_head and not force_refresh:
        return {
            "success": True,
            "outcome": "already_current",
            "expected_head": expected_head,
            "attested_head": before,
            "effect_started": False,
            "force_refresh": False,
        }
    broker = _privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    reference = _create_privileged_reference(
        action=ROOTBROKER_CUTOVER_ACTION,
        target=expected_head,
        justification="Automatic exact-main Rootbroker authority refresh before runtime deployment",
    )
    reference_bytes = (
        json.dumps(reference, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if not reference_bytes or len(reference_bytes) > 64 * 1024:
        raise ValueError("Rootbroker cutover reference exceeds broker input limit")
    timed_out = False
    response_raw = b""
    error = ""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3615)
            client.connect(str(BROKER_SOCKET))
            client.sendall(reference_bytes)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > 512 * 1024:
                    raise RuntimeError("Rootbroker cutover response exceeds output limit")
                chunks.append(chunk)
            response_raw = b"".join(chunks)
    except (socket.timeout, TimeoutError) as exc:
        timed_out = True
        error = str(exc) or "Rootbroker cutover timed out"
    except (OSError, RuntimeError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    response_text = _redact_text(response_raw.decode("utf-8", errors="replace"))
    try:
        response = json.loads(response_text) if response_text.strip() else None
    except json.JSONDecodeError:
        response = None
    after = _operator_authority_attestation_head()
    success = after == expected_head
    if success:
        outcome = "succeeded" if not timed_out else "readback_confirmed"
        failure_reason = None
    else:
        outcome = "unknown" if timed_out or response is None else "failed"
        failure_reason = (
            error
            or (response.get("stderr") if isinstance(response, dict) else None)
            or "Rootbroker authority did not advance to expected_head"
        )
    audit_record = {
        "tool": "ensure_rootbroker_authority",
        "action": ROOTBROKER_CUTOVER_ACTION,
        "expected_head": expected_head,
        "attested_head_before": before,
        "attested_head_after": after,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "outcome": outcome,
        "failure_reason": failure_reason,
        "force_refresh": force_refresh,
    }
    authority = {
        "success": success,
        "outcome": outcome,
        "expected_head": expected_head,
        "attested_head": after,
        "effect_started": True,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "failure_reason": failure_reason,
        "broker_response": response,
        "force_refresh": force_refresh,
    }
    try:
        _append_operator_audit(audit_record)
    except Exception as exc:
        raise RootbrokerAuthorityFailureAfterObservedEffect(
            "Rootbroker authority audit failed after the broker effect boundary",
            authority=authority,
        ) from exc
    return authority


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
    # The blockade lifecycle is the one privileged path that must preserve the
    # kernel identity of the long-lived operator process.  Spawning the generic
    # request client would replace SO_PEERCRED with a same-cgroup child and make
    # that child indistinguishable from arbitrary terminal execution.  Send the
    # immutable reference directly from the MCP process instead.
    reference_bytes = (
        json.dumps(reference, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if not reference_bytes or len(reference_bytes) > 64 * 1024:
        raise ValueError("blockade lifecycle reference exceeds broker input limit")
    timed_out = False
    returncode: int | None = None
    stdout_raw = b""
    stderr_raw = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(45)
            client.connect(str(BROKER_SOCKET))
            client.sendall(reference_bytes)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > 250_000:
                    raise RuntimeError("privileged broker response exceeds output limit")
                chunks.append(chunk)
            stdout_raw = b"".join(chunks)
    except (socket.timeout, TimeoutError) as exc:
        timed_out = True
        stderr_raw = str(exc).encode("utf-8", errors="replace") or b"privileged broker direct socket timed out"
    except (OSError, RuntimeError) as exc:
        stderr_raw = f"{type(exc).__name__}: {exc}".encode("utf-8", errors="replace")

    stdout = _redact_text(stdout_raw.decode("utf-8", errors="replace"))
    stderr = _redact_text(stderr_raw.decode("utf-8", errors="replace"))
    try:
        parsed = json.loads(stdout) if stdout.strip() else None
    except json.JSONDecodeError:
        parsed = None
    if not timed_out and isinstance(parsed, dict):
        returncode = 0 if parsed.get("returncode") == 0 else 1
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


def _normalize_process_reference_roots(roots: list[str]) -> list[str]:
    if not isinstance(roots, list) or not 1 <= len(roots) <= 256:
        raise ValueError("roots must be a non-empty bounded list")
    allowed = PROCESS_REFERENCE_ALLOWED_ROOTS
    lexical_only = PROCESS_REFERENCE_LEXICAL_ROOTS
    mounted_prefixes = tuple(prefix for prefix in allowed if prefix not in lexical_only)
    normalized: list[str] = []
    for raw in roots:
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise ValueError("root must be a non-empty path")
        path = Path(raw)
        if not path.is_absolute() or os.path.normpath(raw) != raw:
            raise ValueError("root must be canonical and absolute")
        if path.resolve(strict=True) != path or path.is_symlink() or not path.is_dir():
            raise ValueError("root must be a canonical non-symlink directory")
        if path in lexical_only:
            pass
        elif any(
            os.path.commonpath((str(path), str(prefix))) == str(prefix)
            for prefix in mounted_prefixes
        ):
            pass
        else:
            raise ValueError("root is outside the allowed prefixes")
        normalized.append(str(path))
    if len(set(normalized)) != len(normalized):
        raise ValueError("roots must not contain duplicates")
    return sorted(normalized)


def _validate_process_reference_observation(
    value: Any,
    *,
    roots: list[str],
    target_uid: int,
    max_processes: int,
    max_file_descriptors: int,
) -> dict[str, Any]:
    required = {
        "kind", "schema_version", "complete", "target_uid", "roots",
        "process_count", "open_file_descriptors_checked", "path_references",
        "errors", "observation_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimeError("process reference observation keys are invalid")
    digest = value.get("observation_sha256")
    material = dict(value)
    material.pop("observation_sha256", None)
    if not isinstance(digest, str) or digest != _canonical_sha256(material):
        raise RuntimeError("process reference observation hash is invalid")
    if value.get("kind") != PROCESS_REFERENCE_KIND or value.get("schema_version") != 1:
        raise RuntimeError("process reference observation contract is invalid")
    if value.get("target_uid") != target_uid or value.get("roots") != roots:
        raise RuntimeError("process reference observation request binding is invalid")
    if not isinstance(value.get("complete"), bool):
        raise RuntimeError("process reference observation completeness is invalid")
    process_count = value.get("process_count")
    fd_count = value.get("open_file_descriptors_checked")
    if isinstance(process_count, bool) or not isinstance(process_count, int) or not 0 <= process_count <= max_processes:
        raise RuntimeError("process reference observation process count is invalid")
    if isinstance(fd_count, bool) or not isinstance(fd_count, int) or not 0 <= fd_count <= max_file_descriptors:
        raise RuntimeError("process reference observation descriptor count is invalid")
    errors = value.get("errors")
    if not isinstance(errors, list) or errors != sorted(set(errors)) or not all(isinstance(item, str) and item for item in errors):
        raise RuntimeError("process reference observation errors are invalid")
    if value["complete"] != (errors == []):
        raise RuntimeError("process reference observation completeness contradicts errors")
    references = value.get("path_references")
    if not isinstance(references, list) or len(references) > 64:
        raise RuntimeError("process reference observation references are invalid")
    normalized_refs: list[tuple[int, int, str, str, str]] = []
    for item in references:
        if not isinstance(item, dict) or set(item) != {"pid", "uid", "kind", "root", "path"}:
            raise RuntimeError("process reference item is invalid")
        pid, uid = item["pid"], item["uid"]
        kind, root, path = item["kind"], item["root"], item["path"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise RuntimeError("process reference pid is invalid")
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
            raise RuntimeError("process reference uid is invalid")
        if kind not in {"cwd", "exe", "root", "fd"} or root not in roots:
            raise RuntimeError("process reference classification is invalid")
        if not isinstance(path, str) or not path.startswith("/"):
            raise RuntimeError("process reference path is invalid")
        try:
            if os.path.commonpath((path, root)) != root:
                raise RuntimeError("process reference path escapes its root")
        except ValueError as exc:
            raise RuntimeError("process reference path is invalid") from exc
        normalized_refs.append((pid, uid, kind, root, path))
    if normalized_refs != sorted(set(normalized_refs)):
        raise RuntimeError("process reference observations are not stable and unique")
    return value


def observe_process_references(
    roots: list[str],
    *,
    target_uid: int,
    max_processes: int = 4096,
    max_file_descriptors: int = 32768,
) -> dict[str, Any]:
    normalized_roots = _normalize_process_reference_roots(roots)
    if isinstance(target_uid, bool) or not isinstance(target_uid, int) or target_uid != os.getuid():
        raise ValueError("target_uid must match the requesting workstation owner")
    if isinstance(max_processes, bool) or not isinstance(max_processes, int) or not 1 <= max_processes <= 65536:
        raise ValueError("max_processes is invalid")
    if isinstance(max_file_descriptors, bool) or not isinstance(max_file_descriptors, int) or not 1 <= max_file_descriptors <= 1_000_000:
        raise ValueError("max_file_descriptors is invalid")
    broker = grabowski_privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    target = json.dumps(
        {
            "schema_version": 1,
            "target_uid": target_uid,
            "roots": normalized_roots,
            "max_processes": max_processes,
            "max_file_descriptors": max_file_descriptors,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    reference = _create_privileged_reference(
        action=PROCESS_REFERENCE_ACTION,
        target=target,
        justification="Observe bounded process path references before worktree target maintenance",
    )
    reference_path = _write_power_reference(reference)
    try:
        completed = subprocess.run(
            [str(broker["request_client"]), str(reference_path)],
            cwd="/",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    finally:
        reference_path.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise RuntimeError("process reference broker request failed")
    try:
        outer = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("process reference broker response is invalid") from exc
    if not isinstance(outer, dict) or outer.get("returncode") != 0 or outer.get("timed_out") is not False:
        raise RuntimeError("process reference broker execution failed")
    inner_raw = outer.get("stdout")
    if not isinstance(inner_raw, str):
        raise RuntimeError("process reference broker omitted observer output")
    try:
        inner = json.loads(inner_raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("process reference observer output is invalid") from exc
    observation = _validate_process_reference_observation(
        inner,
        roots=normalized_roots,
        target_uid=target_uid,
        max_processes=max_processes,
        max_file_descriptors=max_file_descriptors,
    )
    _append_operator_audit({
        "tool": "observe_process_references",
        "action": PROCESS_REFERENCE_ACTION,
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "observation_sha256": observation["observation_sha256"],
        "complete": observation["complete"],
        "reference_count": len(observation["path_references"]),
    })
    return observation


def _critical_inventory_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be one lowercase SHA-256 digest")
    return value


def _critical_inventory_projection(
    value: Any,
    *,
    scanner_sha256: str,
    contract_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RuntimeError("critical-user-data inventory response is invalid")
    kind = value.get("kind")
    status = value.get("status")
    if not isinstance(status, str):
        raise RuntimeError("critical-user-data inventory status is invalid")
    observed_scanner = value.get("scanner_sha256")
    observed_contract = value.get("contract_sha256")
    if observed_scanner is not None and observed_scanner != scanner_sha256:
        raise RuntimeError("critical-user-data inventory scanner binding drifted")
    if observed_contract is not None and observed_contract != contract_sha256:
        raise RuntimeError("critical-user-data inventory contract binding drifted")

    base: dict[str, Any] = {
        "schema_version": 1,
        "kind": kind,
        "status": status,
        "scanner_sha256": scanner_sha256,
        "contract_sha256": contract_sha256,
    }
    common_keys = {
        "schema_version",
        "kind",
        "status",
        "scanner_sha256",
        "contract_sha256",
    }
    if kind == "grabowski.critical_user_data_inventory_error.v1":
        if (
            status != "blocked"
            or not {"schema_version", "kind", "status"}.issubset(value)
            or not set(value).issubset(common_keys)
        ):
            raise RuntimeError("critical-user-data inventory error is malformed")
        return base

    if kind == "grabowski.critical_user_data_inventory_start.v1":
        expected = common_keys | {"unit", "runtime_seconds"}
        if set(value) != expected or status != "started":
            raise RuntimeError("critical-user-data inventory start is malformed")
        runtime_seconds = value.get("runtime_seconds")
        unit = value.get("unit")
        if (
            isinstance(runtime_seconds, bool)
            or not isinstance(runtime_seconds, int)
            or runtime_seconds <= 0
            or not isinstance(unit, str)
            or not unit
        ):
            raise RuntimeError("critical-user-data inventory start metadata is invalid")
        return {**base, "unit": unit, "runtime_seconds": runtime_seconds}

    if kind == "grabowski.critical_user_data_inventory_status.v1":
        expected = common_keys | {"unit", "unit_state", "result_sha256"}
        if (
            set(value) != expected
            or status not in {"running", "not-started", "outcome-unknown", "passed", "failed"}
        ):
            raise RuntimeError("critical-user-data inventory status is malformed")
        unit = value.get("unit")
        unit_state = value.get("unit_state")
        result_sha256 = value.get("result_sha256")
        if (
            not isinstance(unit, str)
            or not unit
            or not isinstance(unit_state, dict)
            or set(unit_state) != {"load", "active", "sub", "result"}
            or not all(isinstance(item, str) for item in unit_state.values())
        ):
            raise RuntimeError("critical-user-data inventory unit state is invalid")
        if result_sha256 is not None:
            _critical_inventory_digest(result_sha256, "result_sha256")
        return {
            **base,
            "unit": unit,
            "unit_state": dict(unit_state),
            "result_sha256": result_sha256,
        }

    if kind != "grabowski.critical_user_data_inventory_result.v1":
        raise RuntimeError("critical-user-data inventory response kind is invalid")
    result_sha256 = _critical_inventory_digest(
        value.get("result_sha256"), "result_sha256"
    )
    completed_at = value.get("completed_at_unix")
    unit = value.get("unit")
    if (
        isinstance(completed_at, bool)
        or not isinstance(completed_at, int)
        or completed_at < 0
        or not isinstance(unit, str)
        or not unit
        or status not in {"passed", "failed"}
    ):
        raise RuntimeError("critical-user-data inventory result metadata is invalid")

    if status == "failed":
        expected = common_keys | {
            "unit",
            "completed_at_unix",
            "result_sha256",
            "failure_code",
            "returncode",
            "stdout_sha256",
            "stdout_bytes",
            "stderr_sha256",
            "stderr_bytes",
        }
        if set(value) != expected:
            raise RuntimeError("critical-user-data inventory failure fields are invalid")
        failure_code = value.get("failure_code")
        returncode = value.get("returncode")
        if (
            not isinstance(failure_code, str)
            or not failure_code
            or isinstance(returncode, bool)
            or not isinstance(returncode, int)
        ):
            raise RuntimeError("critical-user-data inventory failure is malformed")
        digests: dict[str, Any] = {}
        for key in ("stdout_sha256", "stderr_sha256"):
            digests[key] = _critical_inventory_digest(value.get(key), key)
        for key in ("stdout_bytes", "stderr_bytes"):
            item = value.get(key)
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise RuntimeError("critical-user-data inventory failure size is invalid")
            digests[key] = item
        return {
            **base,
            "completed_at_unix": completed_at,
            "result_sha256": result_sha256,
            "failure_code": failure_code,
            "returncode": returncode,
            **digests,
        }

    expected_result = common_keys | {
        "unit",
        "completed_at_unix",
        "result_sha256",
        "inventory",
    }
    if set(value) != expected_result:
        raise RuntimeError("critical-user-data inventory result fields are invalid")
    inventory = value.get("inventory")
    required_inventory = {
        "schema_version",
        "kind",
        "scope",
        "scope_semantics",
        "algorithm",
        "critical_scope_sha256",
        "contract_sha256",
        "authoritative_inventory",
        "inventory_sha256",
        "member_count",
        "members",
        "record_count",
        "regular_file_bytes",
        "exclusion_boundary_count",
        "production_effects_authorized",
    }
    if not isinstance(inventory, dict) or set(inventory) != required_inventory:
        raise RuntimeError("critical-user-data inventory aggregate is invalid")
    members = inventory.get("members")
    if (
        inventory.get("schema_version") != 1
        or inventory.get("kind")
        != "heim_pc.critical_user_data_aggregate_inventory.v1"
        or inventory.get("scope") != "critical-user-data"
        or inventory.get("scope_semantics") != "explicit-positive-selection"
        or inventory.get("algorithm") != "member-inventory-sha256-v1"
        or inventory.get("critical_scope_sha256") != contract_sha256
        or inventory.get("contract_sha256") != contract_sha256
        or inventory.get("authoritative_inventory") is not True
        or inventory.get("production_effects_authorized") is not False
        or inventory.get("member_count") != 1
        or not isinstance(members, list)
        or len(members) != 1
        or not isinstance(members[0], dict)
        or set(members[0])
        != {
            "id",
            "scope",
            "contract_sha256",
            "inventory_sha256",
            "record_count",
            "regular_file_bytes",
            "exclusion_boundary_count",
        }
        or members[0].get("id") != "home"
        or members[0].get("scope") != "critical-user-data-home"
    ):
        raise RuntimeError("critical-user-data inventory aggregate binding is invalid")
    inventory_sha256 = _critical_inventory_digest(
        inventory.get("inventory_sha256"), "inventory_sha256"
    )
    member_inventory_sha = _critical_inventory_digest(
        members[0].get("inventory_sha256"), "home inventory_sha256"
    )
    _critical_inventory_digest(
        members[0].get("contract_sha256"), "home contract_sha256"
    )
    counts: dict[str, int] = {}
    for key in ("record_count", "regular_file_bytes", "exclusion_boundary_count"):
        aggregate_item = inventory.get(key)
        member_item = members[0].get(key)
        if (
            isinstance(aggregate_item, bool)
            or not isinstance(aggregate_item, int)
            or aggregate_item < 0
            or aggregate_item != member_item
        ):
            raise RuntimeError(f"critical-user-data inventory {key} is invalid")
        counts[key] = aggregate_item
    expected_inventory_sha = hashlib.sha256(
        (
            json.dumps(
                {
                    "id": "home",
                    "contract_sha256": members[0]["contract_sha256"],
                    "inventory_sha256": member_inventory_sha,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    if inventory_sha256 != expected_inventory_sha:
        raise RuntimeError("critical-user-data inventory aggregate digest is invalid")
    return {
        **base,
        "completed_at_unix": completed_at,
        "result_sha256": result_sha256,
        "inventory_sha256": inventory_sha256,
        **counts,
    }


def _critical_inventory_target(
    operation: str,
    scanner: str,
    contract: str,
) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": operation,
            "scanner_sha256": scanner,
            "contract_sha256": contract,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _critical_inventory_broker_call(
    operation: str,
    scanner: str,
    contract: str,
    *,
    action: str,
    ambiguous_on_invalid: bool = False,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    target = _critical_inventory_target(operation, scanner, contract)
    invoked = _invoke_mainpid_privileged_reference(
        action=action,
        target=target,
        justification=(
            "Operate the fixed-path SHA-pinned read-only Heim-PC "
            "critical-user-data authoritative inventory"
        ),
        timeout_seconds=90,
        max_output_bytes=128 * 1024,
    )
    if invoked.get("broker_client_timed_out") is True:
        return invoked, None
    try:
        outer = invoked.get("broker_response")
        if not isinstance(outer, dict):
            raise RuntimeError(
                "critical-user-data inventory broker response is invalid"
            )
        broker_error = outer.get("error")
        if broker_error is not None:
            if not isinstance(broker_error, str) or not broker_error:
                raise RuntimeError(
                    "critical-user-data inventory broker error response is invalid"
                )
            raise RuntimeError(
                "critical-user-data inventory broker rejected request: "
                + broker_error[:500]
            )
        timed_out = outer.get("timed_out")
        if timed_out is True:
            return invoked, None
        if timed_out is not False:
            raise RuntimeError(
                "critical-user-data inventory broker timed_out flag is invalid"
            )
        raw = outer.get("stdout")
        if not isinstance(raw, str) or not raw:
            raise RuntimeError(
                "critical-user-data inventory broker omitted safe output"
            )
        try:
            inner = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "critical-user-data inventory broker output is invalid"
            ) from exc
        result = _critical_inventory_projection(
            inner,
            scanner_sha256=scanner,
            contract_sha256=contract,
        )
        broker_returncode = outer.get("returncode")
        if isinstance(broker_returncode, bool) or not isinstance(
            broker_returncode, int
        ):
            raise RuntimeError(
                "critical-user-data inventory broker returncode is invalid"
            )
    except (RuntimeError, OSError, ValueError):
        if ambiguous_on_invalid:
            return invoked, None
        raise
    return invoked, {
        "broker_returncode": broker_returncode,
        "result": result,
    }


def _critical_inventory_response(
    operation: str,
    scanner: str,
    contract: str,
    invoked: dict[str, Any],
    parsed: dict[str, Any],
    *,
    outcome: str | None = None,
) -> dict[str, Any]:
    result = parsed["result"]
    value = {
        "success": (
            parsed["broker_returncode"] == 0
            and result["status"] != "blocked"
            and result["status"] != "failed"
            and result["status"] != "outcome-unknown"
        ),
        "operation": operation,
        "scanner_sha256": scanner,
        "contract_sha256": contract,
        "request_id": invoked["request_id"],
        "reference_sha256": invoked["reference_sha256"],
        "broker_returncode": parsed["broker_returncode"],
        "result": result,
    }
    if outcome is not None:
        value["outcome"] = outcome
    return value


def _critical_inventory_unknown_start(
    scanner: str,
    contract: str,
    invoked: dict[str, Any],
    *,
    readback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "success": False,
        "operation": "start",
        "scanner_sha256": scanner,
        "contract_sha256": contract,
        "request_id": invoked["request_id"],
        "reference_sha256": invoked["reference_sha256"],
        "broker_returncode": None,
        "outcome": "outcome_unknown",
        "readback_required": True,
        "retry_safe": False,
    }
    if readback is not None:
        value["readback"] = readback
    return value


def _critical_inventory_terminal_readback(
    scanner: str,
    contract: str,
    *,
    start_invoked: dict[str, Any],
    status_invoked: dict[str, Any],
    status_parsed: dict[str, Any],
    preflight_result_sha256: str | None = None,
) -> dict[str, Any]:
    status_result = status_parsed["result"]
    state = status_result["status"]
    if (
        preflight_result_sha256 is not None
        and state in {"passed", "failed"}
        and status_result.get("result_sha256") == preflight_result_sha256
    ):
        return _critical_inventory_unknown_start(
            scanner,
            contract,
            start_invoked,
            readback=status_result,
        )
    if state == "running":
        return {
            **_critical_inventory_response(
                "start",
                scanner,
                contract,
                start_invoked,
                {
                    "broker_returncode": 0,
                    "result": status_result,
                },
                outcome="readback_reconciled",
            ),
            "readback_required": False,
            "retry_safe": False,
        }
    if state in {"passed", "failed"}:
        result_invoked, result_parsed = _critical_inventory_broker_call(
            "result",
            scanner,
            contract,
            action=CRITICAL_USER_DATA_INVENTORY_READ_ACTION,
            ambiguous_on_invalid=True,
        )
        if result_parsed is not None:
            status_result_sha256 = status_result.get("result_sha256")
            result_result_sha256 = result_parsed["result"].get("result_sha256")
            if (
                not isinstance(status_result_sha256, str)
                or result_result_sha256 != status_result_sha256
            ):
                return _critical_inventory_unknown_start(
                    scanner,
                    contract,
                    start_invoked,
                    readback=status_result,
                )
            return {
                **_critical_inventory_response(
                    "start",
                    scanner,
                    contract,
                    start_invoked,
                    result_parsed,
                    outcome="readback_reconciled",
                ),
                "readback_required": False,
                "retry_safe": False,
                "readback_request_id": result_invoked["request_id"],
                "readback_reference_sha256": result_invoked["reference_sha256"],
            }
    return _critical_inventory_unknown_start(
        scanner,
        contract,
        start_invoked,
        readback=status_result,
    )


@mcp.tool(name="grabowski_critical_user_data_inventory", annotations=MUTATING)
def grabowski_critical_user_data_inventory(
    operation: str,
    scanner_sha256: str,
    contract_sha256: str,
) -> dict[str, Any]:
    """Start one fixed SHA-pinned authoritative critical-user-data inventory."""
    if operation != "start":
        raise ValueError(
            "operation must be start; use grabowski_critical_user_data_inventory_read "
            "for status or result"
        )
    scanner = _critical_inventory_digest(scanner_sha256, "scanner_sha256")
    contract = _critical_inventory_digest(contract_sha256, "contract_sha256")

    pre_invoked, pre_parsed = _critical_inventory_broker_call(
        "status",
        scanner,
        contract,
        action=CRITICAL_USER_DATA_INVENTORY_READ_ACTION,
    )
    if pre_parsed is None:
        return {
            "success": False,
            "operation": "start",
            "scanner_sha256": scanner,
            "contract_sha256": contract,
            "request_id": pre_invoked["request_id"],
            "reference_sha256": pre_invoked["reference_sha256"],
            "broker_returncode": None,
            "outcome": "preflight_readback_unavailable",
            "readback_required": True,
            "retry_safe": True,
        }
    pre_status = pre_parsed["result"]["status"]
    if pre_status == "passed":
        preflight_result_sha256 = pre_parsed["result"].get("result_sha256")
        if not isinstance(preflight_result_sha256, str):
            return _critical_inventory_unknown_start(
                scanner,
                contract,
                pre_invoked,
                readback=pre_parsed["result"],
            )
        result_invoked, result_parsed = _critical_inventory_broker_call(
            "result",
            scanner,
            contract,
            action=CRITICAL_USER_DATA_INVENTORY_READ_ACTION,
            ambiguous_on_invalid=True,
        )
        if (
            result_parsed is not None
            and result_parsed["result"].get("result_sha256")
            == preflight_result_sha256
        ):
            return {
                **_critical_inventory_response(
                    "start",
                    scanner,
                    contract,
                    result_invoked,
                    result_parsed,
                    outcome="existing_result",
                ),
                "readback_required": False,
                "retry_safe": False,
            }
        return _critical_inventory_unknown_start(
            scanner,
            contract,
            pre_invoked,
            readback=pre_parsed["result"],
        )
    if pre_status == "running":
        return {
            **_critical_inventory_response(
                "start",
                scanner,
                contract,
                pre_invoked,
                pre_parsed,
                outcome="already_running",
            ),
            "readback_required": False,
            "retry_safe": False,
        }
    if pre_status not in {"not-started", "failed"}:
        return _critical_inventory_unknown_start(
            scanner,
            contract,
            pre_invoked,
            readback=pre_parsed["result"],
        )

    # Terminal failed results may be retried explicitly. An outcome-unknown
    # preflight never reaches this mutation path; it remains blocked until an
    # administrative recovery transition outside this start operation resolves it.
    preflight_result_sha256: str | None = None
    if pre_status == "failed":
        observed_preflight_sha = pre_parsed["result"].get("result_sha256")
        if not isinstance(observed_preflight_sha, str):
            return _critical_inventory_unknown_start(
                scanner,
                contract,
                pre_invoked,
                readback=pre_parsed["result"],
            )
        preflight_result_sha256 = observed_preflight_sha

    operator._require_operator_mutation("power_execute")
    invoked, parsed = _critical_inventory_broker_call(
        "start",
        scanner,
        contract,
        action=CRITICAL_USER_DATA_INVENTORY_ACTION,
        ambiguous_on_invalid=True,
    )
    if parsed is not None and parsed["result"]["status"] != "blocked":
        direct_result = parsed["result"]
        if (
            preflight_result_sha256 is not None
            and direct_result.get("result_sha256") == preflight_result_sha256
        ):
            return _critical_inventory_unknown_start(
                scanner,
                contract,
                invoked,
                readback=direct_result,
            )
        return _critical_inventory_response(
            "start",
            scanner,
            contract,
            invoked,
            parsed,
        )

    status_invoked, status_parsed = _critical_inventory_broker_call(
        "status",
        scanner,
        contract,
        action=CRITICAL_USER_DATA_INVENTORY_READ_ACTION,
        ambiguous_on_invalid=True,
    )
    if status_parsed is None:
        return _critical_inventory_unknown_start(scanner, contract, invoked)
    return _critical_inventory_terminal_readback(
        scanner,
        contract,
        start_invoked=invoked,
        status_invoked=status_invoked,
        status_parsed=status_parsed,
        preflight_result_sha256=preflight_result_sha256,
    )


@mcp.tool(name="grabowski_critical_user_data_inventory_read", annotations=READ_ONLY)
def grabowski_critical_user_data_inventory_read(
    operation: str,
    scanner_sha256: str,
    contract_sha256: str,
) -> dict[str, Any]:
    """Read status or result for the fixed SHA-pinned critical-data inventory."""
    if operation not in {"status", "result"}:
        raise ValueError("operation must be status or result")
    scanner = _critical_inventory_digest(scanner_sha256, "scanner_sha256")
    contract = _critical_inventory_digest(contract_sha256, "contract_sha256")
    invoked, parsed = _critical_inventory_broker_call(
        operation,
        scanner,
        contract,
        action=CRITICAL_USER_DATA_INVENTORY_READ_ACTION,
    )
    if parsed is None:
        return {
            "success": False,
            "operation": operation,
            "scanner_sha256": scanner,
            "contract_sha256": contract,
            "request_id": invoked["request_id"],
            "reference_sha256": invoked["reference_sha256"],
            "broker_returncode": None,
            "outcome": "read_timeout",
            "readback_required": True,
            "retry_safe": True,
        }
    return _critical_inventory_response(
        operation,
        scanner,
        contract,
        invoked,
        parsed,
    )


@mcp.tool(name="grabowski_power_run", annotations=MUTATING)
def grabowski_power_run(
    argv: list[str],
    cwd: str | None = None,
    timeout_seconds: int = 300,
    justification: str = "",
    max_output_bytes: int = 250_000,
) -> dict[str, Any]:
    """Run one audited root command through the canonical root-owned broker."""
    operator._require_operator_mutation("power_execute")
    command = _normalize_power_argv(argv)
    working_directory = _normalize_power_cwd(cwd)
    timeout = _normalize_power_timeout(timeout_seconds)
    output_limit = _normalize_power_output_limit(max_output_bytes)
    reason = _normalize_power_justification(justification)

    broker = grabowski_privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")

    target = json.dumps(
        {"argv": command, "cwd": working_directory, "timeout_seconds": timeout},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    reference = _create_power_reference(target, reason)
    reference_bytes = (
        json.dumps(reference, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if not reference_bytes or len(reference_bytes) > 64 * 1024:
        raise ValueError("power reference exceeds broker input limit")
    started = time.monotonic()
    client_timed_out = False
    broker_client_returncode: int | None = None
    stdout_raw = b""
    stderr_raw = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout + 15)
            client.connect(str(BROKER_SOCKET))
            client.sendall(reference_bytes)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = client.recv(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > 512 * 1024:
                    raise RuntimeError("privileged broker response exceeds output limit")
                chunks.append(chunk)
            stdout_raw = b"".join(chunks)
    except (socket.timeout, TimeoutError) as exc:
        client_timed_out = True
        stderr_raw = (
            str(exc).encode("utf-8", errors="replace")
            or b"privileged broker direct socket timed out"
        )
    except (OSError, RuntimeError) as exc:
        stderr_raw = f"{type(exc).__name__}: {exc}".encode(
            "utf-8", errors="replace"
        )

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
    if not client_timed_out and isinstance(broker_returncode, int):
        broker_client_returncode = 0 if broker_returncode == 0 else 1
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
    }
    _append_operator_audit(audit_record)
    return {
        "success": success,
        "execution_model": "canonical-root-broker",
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
    }

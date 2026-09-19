from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import stat
import time
from typing import Callable

from grabowski_privileged_broker import (
    claim_once,
    load_root_config,
    parse_reference,
    parse_transport_request,
    resolve_secret_pty_execution,
    validate_secret_pty_session_authority,
    _require_kill_switch_clear,
)

SECRET_PTY_MAX_TRANSCRIPT_BYTES = 512 * 1024
SECRET_PTY_TERMINATE_GRACE_SECONDS = 2.0
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def _process_identity(pid: int, *, proc_root: Path) -> tuple[int, int]:
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PermissionError("secret PTY peer process identity is not observable") from exc
    closing = raw.rfind(")")
    if closing <= 0 or not raw.startswith(f"{pid} ("):
        raise PermissionError("secret PTY peer process identity is malformed")
    fields = raw[closing + 1 :].strip().split()
    if len(fields) < 20:
        raise PermissionError("secret PTY peer process identity is incomplete")
    try:
        parent_pid = int(fields[1])
        starttime_ticks = int(fields[19])
    except ValueError as exc:
        raise PermissionError("secret PTY peer process identity is invalid") from exc
    if parent_pid <= 0 or starttime_ticks <= 0:
        raise PermissionError("secret PTY peer process identity is invalid")
    return parent_pid, starttime_ticks


def _read_peer_bound_secret(
    transport: dict[str, object] | None,
    peer: dict[str, object],
    execution: dict[str, object],
    *,
    proc_root: Path = Path("/proc"),
) -> bytearray:
    if transport is None or transport.get("kind") != "peer-fd-v1":
        raise PermissionError("secret PTY requires peer-bound FD transport")
    peer_pid = peer.get("pid")
    peer_uid = peer.get("uid")
    peer_parent = peer.get("parent_pid")
    peer_starttime = peer.get("starttime_ticks")
    secret_fd = transport.get("secret_fd")
    expected_hash = transport.get("secret_sha256")
    max_secret_bytes = execution.get("max_secret_bytes")
    if (
        not isinstance(peer_pid, int)
        or not isinstance(peer_uid, int)
        or not isinstance(peer_parent, int)
        or not isinstance(peer_starttime, int)
        or isinstance(secret_fd, bool)
        or not isinstance(secret_fd, int)
        or not isinstance(expected_hash, str)
        or isinstance(max_secret_bytes, bool)
        or not isinstance(max_secret_bytes, int)
    ):
        raise PermissionError("secret PTY transport binding is malformed")
    path = proc_root / str(peer_pid) / "fd" / str(secret_fd)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != peer_uid
            or metadata.st_size <= 0
            or metadata.st_size > max_secret_bytes
        ):
            raise PermissionError("secret PTY descriptor is not an allowed bounded secret")
        parent_after, starttime_after = _process_identity(peer_pid, proc_root=proc_root)
        if parent_after != peer_parent or starttime_after != peer_starttime:
            raise PermissionError("secret PTY peer changed before secret read")
        raw = os.pread(descriptor, metadata.st_size + 1, 0)
        if len(raw) != metadata.st_size or hashlib.sha256(raw).hexdigest() != expected_hash:
            raise PermissionError("secret PTY descriptor hash does not match its binding")
        return bytearray(raw)
    finally:
        os.close(descriptor)


def _claim_secret_pty_authority(
    reference: dict[str, object],
    session_authority: dict[str, object],
    *,
    state: Path,
) -> None:
    request_id = reference.get("request_id")
    session_id = session_authority.get("session_id")
    if not isinstance(request_id, str) or not isinstance(session_id, str):
        raise PermissionError("secret PTY replay identity is invalid")
    claim_once(state / "used-secret-pty-sessions", session_id)
    claim_once(state / "used", request_id)


def _terminate_secret_pty_child(pid: int) -> int | None:
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + SECRET_PTY_TERMINATE_GRACE_SECONDS
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.02)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        _waited, status = os.waitpid(pid, 0)
        return status
    except ChildProcessError:
        return None


def _secret_pty_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _secret_pty_reified_result(result: dict[str, object]) -> dict[str, object]:
    complete = (
        result.get("outcome") == "COMPLETED"
        and result.get("returncode") == 0
        and result.get("timed_out") is False
        and result.get("readback_required") is False
        and result.get("prompt_count") == 2
        and result.get("expected_prompt_count") == 2
        and result.get("failure_reason") is None
    )
    if complete:
        return {
            "outcome": "COMPLETED",
            "returncode": 0,
            "timed_out": False,
            "retry_safe": False,
            "readback_required": False,
            "prompt_count": 2,
            "expected_prompt_count": 2,
            "failure_reason": None,
        }

    raw_reason = result.get("failure_reason")
    allowed_reasons = {
        "timeout",
        "peer-disconnected",
        "authority-lost",
        "output-limit",
        "secret-echo",
        "prompt-out-of-order",
        "prompt-repeated",
    }
    failure_reason = raw_reason if raw_reason in allowed_reasons else "other-failure"
    raw_prompt_count = result.get("prompt_count")
    prompt_count = raw_prompt_count if raw_prompt_count in {1, 2} else 0
    return {
        "outcome": "UNCLEAR",
        "returncode": 1,
        "timed_out": raw_reason == "timeout",
        "retry_safe": False,
        "readback_required": True,
        "prompt_count": prompt_count,
        "expected_prompt_count": 2,
        "failure_reason": failure_reason,
    }


def _secret_pty_audit_record(
    *,
    reference: dict[str, object],
    execution: dict[str, object],
    session_authority: dict[str, object],
    secret_transport: dict[str, object],
    result: dict[str, object],
    operator_peer: dict[str, object],
    started: float,
) -> dict[str, object]:
    safe_result = _secret_pty_reified_result(result)
    transport_binding = {
        "secret_sha256": secret_transport.get("secret_sha256"),
        "transport_sha256": secret_transport.get("transport_sha256"),
    }
    return {
        "schema_version": 1,
        "timestamp_unix": int(time.time()),
        "request_id": str(reference["request_id"]),
        "mode": "secret-pty",
        "reference_binding_sha256": _secret_pty_digest(reference),
        "execution_binding_sha256": _secret_pty_digest(execution),
        "session_authority_binding_sha256": _secret_pty_digest(session_authority),
        "transport_binding_sha256": _secret_pty_digest(transport_binding),
        "peer_binding_sha256": _secret_pty_digest(operator_peer),
        "duration_seconds": round(time.monotonic() - started, 3),
        **safe_result,
    }


def _require_execution_kill_switch_clear(execution: dict[str, object]) -> None:
    kill_switch_value = execution.get("kill_switch_path")
    legacy_switch_value = execution.get("legacy_kill_switch_path")
    if kill_switch_value is None:
        if legacy_switch_value is not None:
            raise PermissionError(
                "power legacy kill-switch path requires canonical kill-switch path"
            )
        return
    if not isinstance(kill_switch_value, str) or not kill_switch_value:
        raise PermissionError("power kill-switch path is invalid")
    _require_kill_switch_clear(Path(kill_switch_value))
    if legacy_switch_value is not None:
        if not isinstance(legacy_switch_value, str) or not legacy_switch_value:
            raise PermissionError("power legacy kill-switch path is invalid")
        _require_kill_switch_clear(Path(legacy_switch_value))


def _run_secret_pty_process(
    *,
    execution: dict[str, object],
    secret: bytearray,
    peer_alive: Callable[[], bool],
) -> dict[str, object]:
    argv = execution["argv"]
    cwd = execution["cwd"]
    timeout = execution["timeout_seconds"]
    prompts = execution["prompt_sequence"]
    output_limit = execution.get("max_output_bytes")
    assert isinstance(argv, list) and all(isinstance(item, str) for item in argv)
    assert isinstance(cwd, str) and isinstance(timeout, int)
    assert isinstance(prompts, list) and all(isinstance(item, str) for item in prompts)
    if (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or not 1 <= output_limit <= SECRET_PTY_MAX_TRANSCRIPT_BYTES
    ):
        raise PermissionError("secret PTY output bound is invalid")
    prompt_bytes = [item.encode("utf-8") for item in prompts]
    started = time.monotonic()
    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(cwd)
            os.execve(argv[0], argv, SAFE_ENV)
        except BaseException:
            os._exit(127)
    os.set_blocking(master_fd, False)
    prompt_index = 0
    bytes_seen = 0
    failure_reason: str | None = None
    timed_out = False
    status: int | None = None
    window = bytearray()
    try:
        while status is None:
            if time.monotonic() - started >= timeout:
                timed_out = True
                failure_reason = "timeout"
                break
            try:
                if not peer_alive():
                    failure_reason = "peer-disconnected"
                    break
                _require_execution_kill_switch_clear(execution)
            except (OSError, PermissionError, RuntimeError, ValueError):
                failure_reason = "authority-lost"
                break
            ready, _write_ready, _errors = select.select([master_fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master_fd, 8192)
                except BlockingIOError:
                    chunk = b""
                except OSError as exc:
                    if exc.errno == 5:
                        chunk = b""
                    else:
                        raise
                if chunk:
                    bytes_seen += len(chunk)
                    if bytes_seen > output_limit:
                        failure_reason = "output-limit"
                        break
                    window.extend(chunk)
                    if bytes(secret) in window:
                        failure_reason = "secret-echo"
                        break
                    while prompt_index < len(prompt_bytes):
                        positions = [
                            (index, window.find(prompt))
                            for index, prompt in enumerate(prompt_bytes)
                            if window.find(prompt) >= 0
                        ]
                        if not positions:
                            break
                        observed_index, position = min(positions, key=lambda item: item[1])
                        if observed_index != prompt_index:
                            failure_reason = "prompt-out-of-order"
                            break
                        prompt = prompt_bytes[prompt_index]
                        os.write(master_fd, secret + b"\n")
                        prompt_index += 1
                        del window[: position + len(prompt)]
                    if failure_reason is not None:
                        break
                    if prompt_index == len(prompt_bytes) and any(
                        prompt in window for prompt in prompt_bytes
                    ):
                        failure_reason = "prompt-repeated"
                        break
                    if len(window) > 64 * 1024:
                        del window[: len(window) - 4096]
            waited, child_status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                status = child_status
        if status is None:
            status = _terminate_secret_pty_child(pid)
    finally:
        os.close(master_fd)
    returncode = os.waitstatus_to_exitcode(status) if status is not None else None
    complete = (
        failure_reason is None
        and not timed_out
        and prompt_index == len(prompt_bytes)
        and returncode == 0
    )
    return {
        "outcome": "COMPLETED" if complete else "UNCLEAR",
        "returncode": returncode,
        "timed_out": timed_out,
        "retry_safe": False,
        "readback_required": not complete,
        "prompt_count": prompt_index,
        "expected_prompt_count": len(prompt_bytes),
        "prompt_contract_sha256": execution.get("prompt_contract_sha256"),
        "pty_bytes_observed": bytes_seen,
        "failure_reason": failure_reason,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def run_secret_transport_request(
    data: bytes,
    *,
    config_path: Path,
    state: Path,
    validate_peer: Callable[[dict[str, object]], dict[str, object]],
    append_audit: Callable[[dict[str, object]], None],
) -> int:
    reference, secret_transport = parse_transport_request(
        data, reference_parser=parse_reference
    )
    if secret_transport is None:
        raise PermissionError("secret PTY transport envelope is required")
    config = load_root_config(config_path)
    execution = resolve_secret_pty_execution(config, reference)
    operator_peer = validate_peer(execution)
    session_authority = validate_secret_pty_session_authority(
        secret_transport.get("session_authority"), execution
    )
    cwd_value = execution.get("cwd")
    if not isinstance(cwd_value, str) or not Path(cwd_value).is_dir():
        raise ValueError("secret PTY cwd is not an existing directory")
    _claim_secret_pty_authority(reference, session_authority, state=state)
    identity_keys = (
        "mode", "argv", "cwd", "timeout_seconds", "prompt_sequence",
        "max_secret_bytes", "max_output_bytes", "kill_switch_path",
        "legacy_kill_switch_path", "allowed_peer_uid", "allowed_peer_unit",
        "allowed_peer_executable", "authority_task_id", "authority_host",
        "action_schema", "privilege_context", "required_resource_keys",
        "redaction_contract_sha256", "prompt_contract_sha256",
    )
    refreshed = resolve_secret_pty_execution(config, reference)
    if any(refreshed.get(key) != execution.get(key) for key in identity_keys):
        raise PermissionError("secret PTY execution contract changed before spawn")
    first_gate = execution.get("gate")
    refreshed_gate = refreshed.get("gate")
    if not isinstance(first_gate, dict) or not isinstance(refreshed_gate, dict):
        raise PermissionError("secret PTY recovery gate is unavailable")
    for key in ("recovery_marker_sha256", "recovery_marker_source_sha256"):
        if refreshed_gate.get(key) != first_gate.get(key):
            raise PermissionError("secret PTY recovery authority changed before spawn")
    execution = refreshed
    session_authority = validate_secret_pty_session_authority(
        session_authority, execution
    )
    refreshed_peer = validate_peer(execution)
    if (
        refreshed_peer.get("pid") != operator_peer.get("pid")
        or refreshed_peer.get("starttime_ticks") != operator_peer.get("starttime_ticks")
    ):
        raise PermissionError("secret PTY peer identity changed before spawn")
    operator_peer = refreshed_peer
    secret = _read_peer_bound_secret(secret_transport, operator_peer, execution)
    peer_pid = int(operator_peer["pid"])
    peer_parent = int(operator_peer["parent_pid"])
    peer_starttime = int(operator_peer["starttime_ticks"])

    def peer_alive() -> bool:
        try:
            parent_now, start_now = _process_identity(peer_pid, proc_root=Path("/proc"))
        except PermissionError:
            return False
        return parent_now == peer_parent and start_now == peer_starttime

    started = time.monotonic()
    try:
        result = _run_secret_pty_process(
            execution=execution,
            secret=secret,
            peer_alive=peer_alive,
        )
    finally:
        for index in range(len(secret)):
            secret[index] = 0
    record = _secret_pty_audit_record(
        reference=reference,
        execution=execution,
        session_authority=session_authority,
        secret_transport=secret_transport,
        result=result,
        operator_peer=operator_peer,
        started=started,
    )
    append_audit(record)
    public_result = {
        "schema_version": 1,
        "mode": "secret-pty",
        **_secret_pty_reified_result(result),
    }
    print(json.dumps(public_result, ensure_ascii=False, sort_keys=True))
    return 0
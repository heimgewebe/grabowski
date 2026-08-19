from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any

import grabowski_fleet as fleet

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


HOME = operator.HOME
STATE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_STATE_ROOT",
        str(HOME / ".local" / "state" / "grabowski"),
    )
).expanduser()
MUTATION_STATE_DIRECTORY_NAME = "fleet-registry-mutations"
LOCK_NAME = "registry.lock"
RECEIPT_DIRECTORY_NAME = "receipts"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
MUTATION_OPERATIONS = frozenset({"add", "update", "disable", "remove"})
MAX_HOST_SPEC_BYTES = 16 * 1024
MAX_REGISTRY_BYTES = 512 * 1024


class FleetRegistryMutationError(RuntimeError):
    """Raised when a typed Fleet registry mutation cannot be proven safe."""


class FleetRegistryConflict(FleetRegistryMutationError):
    """Raised when the bound Fleet registry preimage changed."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256(payload)


def _read_registry(path: Path) -> tuple[bytes, dict[str, Any]]:
    if path.is_symlink():
        raise PermissionError(f"Fleet registry may not be a symlink: {path}")
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise FleetRegistryMutationError(f"Fleet registry missing: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REGISTRY_BYTES:
        raise FleetRegistryMutationError(
            f"Fleet registry is not a bounded regular file: {path}"
        )
    try:
        data = path.read_bytes()
        text = data.decode("utf-8")
        raw = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FleetRegistryMutationError(
            f"Fleet registry is not valid UTF-8 JSON: {path}"
        ) from exc
    if not isinstance(raw, dict):
        raise FleetRegistryMutationError("Fleet registry must contain one JSON object")
    fleet.validate_fleet(raw)
    return data, raw


def _validate_host_spec(host: str, value: Any) -> dict[str, Any]:
    if not isinstance(host, str) or fleet.HOST_NAME.fullmatch(host) is None:
        raise ValueError("Invalid Fleet host key")
    if not isinstance(value, dict):
        raise ValueError("host_spec_json must contain one JSON object")
    required = {
        "transport",
        "target",
        "enabled",
        "roles",
        "command_allowlist",
        "connect_timeout_seconds",
        "remote_command_mode",
    }
    if set(value) != required:
        raise ValueError("Fleet mutation host spec must supply the complete v1 host contract")
    # Reuse the canonical Fleet parser contract rather than maintaining a second
    # SSH/role/allowlist validator in the mutator.
    validated = fleet.validate_fleet(
        {"schema_version": 1, "hosts": {host: copy.deepcopy(value)}}
    )
    candidate = validated["hosts"][host]
    return candidate


def _parse_request(parameters: dict[str, str] | None) -> dict[str, Any]:
    supplied = parameters or {}
    if not isinstance(supplied, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in supplied.items()
    ):
        raise ValueError("parameters must be an object of strings")
    common = {"operation", "host", "expected_registry_sha256"}
    operation = supplied.get("operation")
    if operation not in MUTATION_OPERATIONS:
        raise ValueError("Fleet mutation operation must be add, update, disable or remove")
    expected_keys = common | ({"host_spec_json"} if operation in {"add", "update"} else set())
    if set(supplied) != expected_keys:
        raise ValueError(
            "Fleet mutation parameter mismatch; "
            f"missing={sorted(expected_keys - set(supplied))}, "
            f"unknown={sorted(set(supplied) - expected_keys)}"
        )
    host = supplied["host"]
    if fleet.HOST_NAME.fullmatch(host) is None:
        raise ValueError("Invalid Fleet host key")
    expected = supplied["expected_registry_sha256"]
    if SHA256_RE.fullmatch(expected) is None:
        raise ValueError("expected_registry_sha256 must be a lowercase SHA-256")
    request: dict[str, Any] = {
        "schema_version": 1,
        "request_id": secrets.token_hex(16),
        "operation": operation,
        "host": host,
        "expected_registry_sha256": expected,
    }
    if operation in {"add", "update"}:
        encoded_spec = supplied["host_spec_json"].encode("utf-8")
        if len(encoded_spec) > MAX_HOST_SPEC_BYTES:
            raise ValueError("host_spec_json is too large")
        if operator._redact(supplied["host_spec_json"]) != supplied["host_spec_json"]:
            raise ValueError("host_spec_json appears to contain secret material")
        try:
            parsed = json.loads(supplied["host_spec_json"])
        except json.JSONDecodeError as exc:
            raise ValueError("host_spec_json is not valid JSON") from exc
        request["host_spec"] = _validate_host_spec(host, parsed)
    return request


def plan_registry_mutation(parameters: dict[str, str] | None) -> dict[str, Any]:
    request = _parse_request(parameters)
    before_bytes, before = _read_registry(fleet.FLEET_CONFIG)
    observed = _sha256(before_bytes)
    if observed != request["expected_registry_sha256"]:
        raise FleetRegistryConflict(
            "Fleet registry preimage changed before mutation planning"
        )
    host = request["host"]
    operation = request["operation"]
    hosts = before["hosts"]
    if operation == "add" and host in hosts:
        current = fleet.validate_fleet(before)["hosts"][host]
        if current != request["host_spec"]:
            raise FleetRegistryMutationError(f"Fleet host already exists with different state: {host}")
    elif operation == "update" and host not in hosts:
        raise FleetRegistryMutationError(f"Fleet host does not exist: {host}")
    elif operation == "disable" and host not in hosts:
        raise FleetRegistryMutationError(f"Fleet host does not exist: {host}")
    public = {
        "name": "fleet-registry-mutate",
        "description": "Atomically mutate one validated Fleet host with CAS, audit receipt and readback.",
        "operation": operation,
        "host": host,
        "request_id": request["request_id"],
        "expected_registry_sha256": request["expected_registry_sha256"],
        "host_spec_sha256": (
            _canonical_sha256(request["host_spec"])
            if "host_spec" in request
            else None
        ),
        "current_host_present": host in hosts,
        "registry_host_count": len(hosts),
    }
    return {
        "public": public,
        "request": request,
        "preimage": copy.deepcopy(before),
        "preimage_bytes": before_bytes,
    }


def _serialize_registry(raw: dict[str, Any]) -> bytes:
    return (json.dumps(raw, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _write_file_atomic(path: Path, payload: bytes, *, mode: int) -> None:
    parent = path.parent
    temporary = parent / f".{path.name}.tmp-{os.getpid()}-{time.time_ns():x}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode & 0o777,
        )
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("Fleet mutation atomic write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_receipt(state_root: Path, receipt: dict[str, Any]) -> Path:
    directory = state_root / RECEIPT_DIRECTORY_NAME
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = (
        f"{receipt['timestamp_unix_ns']}-{receipt['host']}-"
        f"{receipt['operation']}-{receipt['before_registry_sha256'][:12]}.json"
    )
    destination = directory / name
    payload = (
        json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    _write_file_atomic(destination, payload, mode=0o600)
    return destination


def _assert_postflight(
    *,
    path: Path,
    host: str,
    operation: str,
    expected_host: dict[str, Any] | None,
    unaffected_hosts: dict[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    data, raw = _read_registry(path)
    normalized = fleet.validate_fleet(raw)
    if {
        key: value for key, value in raw["hosts"].items() if key != host
    } != unaffected_hosts:
        raise FleetRegistryMutationError("Postflight changed a non-target Fleet host")
    if operation == "remove":
        if host in raw["hosts"]:
            raise FleetRegistryMutationError("Postflight remove readback still contains host")
    elif operation == "disable":
        if host not in normalized["hosts"] or normalized["hosts"][host]["enabled"]:
            raise FleetRegistryMutationError("Postflight disable readback is not disabled")
    elif normalized["hosts"].get(host) != expected_host:
        raise FleetRegistryMutationError("Postflight host readback differs from requested state")
    return data, raw


def mutate_registry(
    request: dict[str, Any],
    *,
    path: Path | None = None,
    state_root: Path | None = None,
) -> dict[str, Any]:
    target_path = fleet.FLEET_CONFIG if path is None else path
    base_state_root = STATE_ROOT if state_root is None else state_root
    target_state_root = base_state_root / MUTATION_STATE_DIRECTORY_NAME
    if not isinstance(request, dict) or request.get("schema_version") != 1:
        raise ValueError("Invalid Fleet mutation request")
    operation = request.get("operation")
    host = request.get("host")
    expected = request.get("expected_registry_sha256")
    if operation not in MUTATION_OPERATIONS:
        raise ValueError("Invalid Fleet mutation operation")
    if not isinstance(host, str) or fleet.HOST_NAME.fullmatch(host) is None:
        raise ValueError("Invalid Fleet host key")
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        raise ValueError("Invalid Fleet mutation preimage hash")
    required_keys = {
        "schema_version",
        "operation",
        "host",
        "expected_registry_sha256",
    }
    allowed_keys = set(required_keys) | {"request_id"}
    expected_host = None
    if operation in {"add", "update"}:
        required_keys.add("host_spec")
        allowed_keys.add("host_spec")
    missing = required_keys - set(request)
    unknown = set(request) - allowed_keys
    if missing or unknown:
        raise ValueError(
            f"Fleet mutation request key mismatch; missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )
    request_id = request.get("request_id")
    if request_id is not None and (
        not isinstance(request_id, str) or REQUEST_ID_RE.fullmatch(request_id) is None
    ):
        raise ValueError("Invalid Fleet mutation request id")
    if operation in {"add", "update"}:
        expected_host = _validate_host_spec(host, request.get("host_spec"))

    target_state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = target_state_root / LOCK_NAME
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise FleetRegistryMutationError("Fleet mutation lock is not a regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        before_bytes, before = _read_registry(target_path)
        before_hash = _sha256(before_bytes)
        if before_hash != expected:
            raise FleetRegistryConflict("Fleet registry preimage changed")
        file_mode = stat.S_IMODE(target_path.stat().st_mode)
        unaffected = {
            key: copy.deepcopy(value)
            for key, value in before["hosts"].items()
            if key != host
        }
        current_normalized = fleet.validate_fleet(before)["hosts"].get(host)
        desired = copy.deepcopy(before)
        no_change = False
        if operation == "add":
            if host in before["hosts"]:
                if current_normalized != expected_host:
                    raise FleetRegistryMutationError(
                        f"Fleet host already exists with different state: {host}"
                    )
                no_change = True
            else:
                desired["hosts"][host] = copy.deepcopy(expected_host)
        elif operation == "update":
            if host not in before["hosts"]:
                raise FleetRegistryMutationError(f"Fleet host does not exist: {host}")
            if current_normalized == expected_host:
                no_change = True
            else:
                desired["hosts"][host] = copy.deepcopy(expected_host)
        elif operation == "disable":
            if host not in before["hosts"]:
                raise FleetRegistryMutationError(f"Fleet host does not exist: {host}")
            if current_normalized is not None and not current_normalized["enabled"]:
                no_change = True
            else:
                desired["hosts"][host] = copy.deepcopy(before["hosts"][host])
                desired["hosts"][host]["enabled"] = False
        else:
            if host not in before["hosts"]:
                no_change = True
            else:
                del desired["hosts"][host]

        fleet.validate_fleet(desired)
        after_bytes = before_bytes if no_change else _serialize_registry(desired)
        after_hash = _sha256(after_bytes)
        rollback_attempted = False
        rollback_success = True
        effect_applied = False
        try:
            if not no_change:
                current_bytes, _ = _read_registry(target_path)
                if _sha256(current_bytes) != before_hash:
                    raise FleetRegistryConflict(
                        "Fleet registry changed during mutation preflight"
                    )
                _write_file_atomic(target_path, after_bytes, mode=file_mode)
                effect_applied = True
            post_bytes, _ = _assert_postflight(
                path=target_path,
                host=host,
                operation=operation,
                expected_host=expected_host,
                unaffected_hosts=unaffected,
            )
            if _sha256(post_bytes) != after_hash:
                raise FleetRegistryMutationError("Postflight registry hash mismatch")
            success = True
            error = None
        except Exception as exc:
            success = False
            error = f"{type(exc).__name__}: {exc}"
            if effect_applied:
                rollback_attempted = True
                try:
                    current_bytes, _ = _read_registry(target_path)
                    if _sha256(current_bytes) != after_hash:
                        raise FleetRegistryConflict(
                            "Postimage changed before rollback; refusing to overwrite"
                        )
                    _write_file_atomic(target_path, before_bytes, mode=file_mode)
                    restored_bytes, _ = _read_registry(target_path)
                    rollback_success = _sha256(restored_bytes) == before_hash
                    if not rollback_success:
                        raise FleetRegistryMutationError("Rollback readback hash mismatch")
                except Exception as rollback_exc:
                    rollback_success = False
                    error = (
                        f"{error}; rollback={type(rollback_exc).__name__}: {rollback_exc}"
                    )
        final_bytes, final_raw = _read_registry(target_path)
        final_hash = _sha256(final_bytes)
        normalized_final = fleet.validate_fleet(final_raw)
        if success:
            readback_ok = final_hash == after_hash
        elif rollback_attempted and rollback_success:
            readback_ok = final_hash == before_hash
        else:
            readback_ok = False
        receipt = {
            "schema_version": 1,
            "request_id": request.get("request_id"),
            "request_sha256": _canonical_sha256(request),
            "timestamp_unix": int(time.time()),
            "timestamp_unix_ns": time.time_ns(),
            "operation": operation,
            "host": host,
            "before_registry_sha256": before_hash,
            "after_registry_sha256": after_hash if success else final_hash,
            "result": "success" if success else "failed",
            "idempotent_no_change": no_change,
            "effect_applied": effect_applied,
            "readback": {
                "ok": readback_ok,
                "schema_valid": True,
                "host_present": host in normalized_final["hosts"],
                "host_enabled": (
                    normalized_final["hosts"][host]["enabled"]
                    if host in normalized_final["hosts"]
                    else None
                ),
                "unaffected_hosts_preserved": {
                    key: value for key, value in final_raw["hosts"].items() if key != host
                } == unaffected,
            },
            "rollback": {
                "attempted": rollback_attempted,
                "success": rollback_success,
            },
            "host_spec_sha256": (
                _canonical_sha256(expected_host) if expected_host is not None else None
            ),
            "error": error,
        }
        receipt_path = _write_receipt(target_state_root, receipt)
        receipt["receipt_path"] = str(receipt_path)
        return receipt
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _worker_payload(request: dict[str, Any]) -> str:
    encoded = json.dumps(
        request, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > 32 * 1024:
        raise ValueError("Fleet mutation request is too large")
    return base64.b64encode(encoded).decode("ascii")


def _decode_worker_payload(payload: str) -> dict[str, Any]:
    if len(payload) > 64 * 1024:
        raise ValueError("Fleet mutation worker payload is too large")
    try:
        decoded = base64.b64decode(payload.encode("ascii"), validate=True)
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid Fleet mutation worker payload") from exc
    if not isinstance(value, dict):
        raise ValueError("Fleet mutation worker payload must be an object")
    return value


def _validate_worker_receipt(
    receipt: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise FleetRegistryMutationError("Fleet mutation worker returned invalid receipt")
    if receipt.get("request_sha256") != _canonical_sha256(request):
        raise FleetRegistryMutationError("Fleet mutation worker receipt request binding mismatch")
    if receipt.get("request_id") != request.get("request_id"):
        raise FleetRegistryMutationError("Fleet mutation worker receipt request id mismatch")
    if receipt.get("operation") != request.get("operation"):
        raise FleetRegistryMutationError("Fleet mutation worker receipt operation mismatch")
    if receipt.get("host") != request.get("host"):
        raise FleetRegistryMutationError("Fleet mutation worker receipt host mismatch")
    if receipt.get("before_registry_sha256") != request.get("expected_registry_sha256"):
        raise FleetRegistryMutationError("Fleet mutation worker receipt preimage mismatch")
    return receipt


def _recover_worker_receipt(request: dict[str, Any]) -> dict[str, Any] | None:
    directory = STATE_ROOT / MUTATION_STATE_DIRECTORY_NAME / RECEIPT_DIRECTORY_NAME
    if directory.is_symlink() or not directory.is_dir():
        return None
    expected_request_sha256 = _canonical_sha256(request)
    candidates = sorted(directory.iterdir(), key=lambda item: item.name, reverse=True)[:256]
    for candidate in candidates:
        try:
            if candidate.is_symlink():
                continue
            metadata = candidate.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 64 * 1024:
                continue
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        if value.get("request_sha256") != expected_request_sha256:
            continue
        value = _validate_worker_receipt(value, request)
        value["receipt_path"] = str(candidate)
        return value
    return None


def _terminal_state_readback(
    request: dict[str, Any],
    preimage: dict[str, Any],
) -> dict[str, Any]:
    try:
        current_bytes, current_raw = _read_registry(fleet.FLEET_CONFIG)
        current = fleet.validate_fleet(current_raw)
    except Exception as exc:
        return {
            "ok": False,
            "state": "parent_readback_failed",
            "error_type": type(exc).__name__,
            "retry_safe": False,
        }
    host = request["host"]
    operation = request["operation"]
    current_hash = _sha256(current_bytes)
    preimage_hosts = preimage["hosts"]
    unaffected_hosts_preserved = {
        key: value for key, value in current_raw["hosts"].items() if key != host
    } == {
        key: value for key, value in preimage_hosts.items() if key != host
    }
    if operation in {"add", "update"}:
        target_satisfied = current["hosts"].get(host) == request["host_spec"]
    elif operation == "disable":
        expected_disabled = copy.deepcopy(preimage_hosts.get(host))
        if expected_disabled is None:
            target_satisfied = False
        else:
            expected_disabled["enabled"] = False
            target_satisfied = (
                current_raw["hosts"].get(host) == expected_disabled
                and not current["hosts"][host]["enabled"]
            )
    else:
        target_satisfied = host not in current_raw["hosts"]
    terminal_state_satisfied = bool(target_satisfied and unaffected_hosts_preserved)
    return {
        "ok": True,
        "state": "terminal_state_satisfied" if terminal_state_satisfied else "terminal_state_not_satisfied",
        "current_registry_sha256": current_hash,
        "expected_preimage_sha256": request["expected_registry_sha256"],
        "preimage_unchanged": current_hash == request["expected_registry_sha256"],
        "target_satisfied": bool(target_satisfied),
        "unaffected_hosts_preserved": unaffected_hosts_preserved,
        "terminal_state_satisfied": terminal_state_satisfied,
        "retry_safe": False,
    }


def _write_parent_reconciliation_receipt(
    request: dict[str, Any],
    readback: dict[str, Any],
    *,
    transport_error_type: str | None,
) -> dict[str, Any]:
    success = bool(readback.get("terminal_state_satisfied"))
    receipt = {
        "schema_version": 1,
        "request_id": request.get("request_id"),
        "request_sha256": _canonical_sha256(request),
        "timestamp_unix": int(time.time()),
        "timestamp_unix_ns": time.time_ns(),
        "operation": request["operation"],
        "host": request["host"],
        "before_registry_sha256": request["expected_registry_sha256"],
        "after_registry_sha256": readback.get("current_registry_sha256"),
        "result": "success" if success else "failed",
        "idempotent_no_change": bool(success and readback.get("preimage_unchanged")),
        "effect_applied": None if not readback.get("preimage_unchanged") else False,
        "readback": dict(readback),
        "rollback": {"attempted": False, "success": False},
        "host_spec_sha256": (
            _canonical_sha256(request["host_spec"])
            if "host_spec" in request
            else None
        ),
        "error": transport_error_type,
        "receipt_source": "parent-reconciliation",
    }
    state_root = STATE_ROOT / MUTATION_STATE_DIRECTORY_NAME
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipt_path = _write_receipt(state_root, receipt)
    receipt["receipt_path"] = str(receipt_path)
    return receipt


def _launch_worker(request: dict[str, Any]) -> dict[str, Any]:
    payload = _worker_payload(request)
    unit_hash = _canonical_sha256(request)[:12]
    unit = f"grabowski-fleet-mutation-{unit_hash}-{time.time_ns() & 0xFFFFFF:x}"
    config_parent = fleet.FLEET_CONFIG.parent
    if config_parent.is_symlink() or not config_parent.is_dir():
        raise FleetRegistryMutationError("Fleet config parent must be a real directory")
    mutation_state_root = STATE_ROOT / MUTATION_STATE_DIRECTORY_NAME
    mutation_state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    protected_config_paths = [
        item
        for item in sorted(config_parent.iterdir(), key=lambda candidate: candidate.name)
        if item != fleet.FLEET_CONFIG
    ]
    argv = [
        "systemd-run",
        "--user",
        "--quiet",
        "--wait",
        "--collect",
        "--pipe",
        "--unit",
        unit,
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=5s",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=full",
        "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=UMask=0077",
        "--property=RuntimeMaxSec=15s",
        "--property=MemoryMax=128M",
        f"--property=ReadWritePaths={config_parent}",
        f"--property=ReadWritePaths={mutation_state_root}",
        *[
            f"--property=ReadOnlyPaths={path}" for path in protected_config_paths
        ],
        "--",
        sys.executable,
        "-m",
        "grabowski_fleet_mutation",
        "worker",
        payload,
    ]
    result = operator._run(
        argv,
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=64 * 1024,
    )
    stdout = result.get("stdout", "")
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise FleetRegistryMutationError(
            f"Fleet mutation worker returned no receipt; rc={result.get('returncode')}"
        )
    try:
        receipt = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise FleetRegistryMutationError("Fleet mutation worker returned invalid JSON") from exc
    receipt = _validate_worker_receipt(receipt, request)
    if result.get("returncode") != 0 and receipt.get("result") == "success":
        raise FleetRegistryMutationError("Fleet mutation worker exit status contradicts receipt")
    return {"worker_result": result, "receipt": receipt}


def execute_registry_mutation(plan: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, dict) or set(plan) != {
        "public", "request", "preimage", "preimage_bytes"
    }:
        raise ValueError("Invalid Fleet mutation plan")
    request = plan["request"]
    public = plan["public"]
    preimage = plan["preimage"]
    preimage_bytes = plan["preimage_bytes"]
    if public.get("expected_registry_sha256") != request.get("expected_registry_sha256"):
        raise FleetRegistryMutationError("Fleet mutation plan/request binding mismatch")
    if public.get("request_id") != request.get("request_id"):
        raise FleetRegistryMutationError("Fleet mutation plan request id mismatch")
    if not isinstance(preimage_bytes, bytes):
        raise FleetRegistryMutationError("Fleet mutation private preimage bytes are invalid")
    if _sha256(preimage_bytes) != request.get("expected_registry_sha256"):
        raise FleetRegistryMutationError("Fleet mutation private preimage hash mismatch")
    try:
        parsed_preimage = json.loads(preimage_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FleetRegistryMutationError("Fleet mutation private preimage is invalid") from exc
    if parsed_preimage != preimage:
        raise FleetRegistryMutationError("Fleet mutation private preimage snapshot mismatch")
    fleet.validate_fleet(preimage)
    receipt: dict[str, Any] | None = None
    worker_returncode: int | None = None
    transport_error_type: str | None = None
    receipt_recovered = False
    try:
        launch = _launch_worker(request)
        receipt = launch["receipt"]
        worker_returncode = launch["worker_result"].get("returncode")
    except Exception as exc:
        transport_error_type = type(exc).__name__
        try:
            receipt = _recover_worker_receipt(request)
            receipt_recovered = receipt is not None
        except Exception as recovery_exc:
            transport_error_type = (
                f"{transport_error_type}+{type(recovery_exc).__name__}"
            )
            receipt = None
            receipt_recovered = False
    readback = _terminal_state_readback(request, preimage)
    if receipt is None or not receipt.get("receipt_path"):
        receipt = _write_parent_reconciliation_receipt(
            request, readback, transport_error_type=transport_error_type
        )
    receipt_success = (
        receipt.get("result") == "success"
        and bool(receipt.get("readback", {}).get("ok"))
    )
    receipt_after = receipt.get("after_registry_sha256")
    hash_matches_receipt = (
        isinstance(receipt_after, str)
        and readback.get("current_registry_sha256") == receipt_after
    )
    terminal_state_satisfied = bool(readback.get("terminal_state_satisfied"))
    success = bool(terminal_state_satisfied and (receipt_success or receipt.get("receipt_source") == "parent-reconciliation"))
    if success and receipt_success and not hash_matches_receipt:
        # A later writer changed the registry after the worker receipt. Even if
        # the target happens to look right, the exact mutation postimage is no
        # longer current, so do not claim this run as successful.
        success = False
    if success:
        outcome_state = (
            "parent_readback_reconciled"
            if receipt.get("receipt_source") == "parent-reconciliation"
            else "worker_receipt_confirmed"
        )
    elif readback.get("ok"):
        outcome_state = "post_mutation_state_diverged"
    else:
        outcome_state = "parent_readback_failed"
    return {
        "success": success,
        "plan": public,
        "receipt": receipt,
        "worker_returncode": worker_returncode,
        "receipt_recovered": receipt_recovered,
        "transport_error_type": transport_error_type,
        "reconciliation": {
            **readback,
            "outcome_state": outcome_state,
            "receipt_after_hash_matches_current": hash_matches_receipt,
            "retry_safe": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Typed Grabowski Fleet registry mutator worker")
    subparsers = parser.add_subparsers(dest="command", required=True)
    worker = subparsers.add_parser("worker")
    worker.add_argument("payload")
    args = parser.parse_args()
    request: dict[str, Any] | None = None
    try:
        request = _decode_worker_payload(args.payload)
        receipt = mutate_registry(request)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 0 if receipt["result"] == "success" else 2
    except Exception as exc:
        fallback: dict[str, Any] | None = None
        if request is not None:
            try:
                current_bytes, current_raw = _read_registry(fleet.FLEET_CONFIG)
                current = fleet.validate_fleet(current_raw)
                current_hash = _sha256(current_bytes)
                host = request.get("host")
                readback = {
                    "ok": True,
                    "state": "worker_exception_readback",
                    "current_registry_sha256": current_hash,
                    "expected_preimage_sha256": request.get("expected_registry_sha256"),
                    "preimage_unchanged": current_hash == request.get("expected_registry_sha256"),
                    "target_satisfied": None,
                    "unaffected_hosts_preserved": None,
                    "terminal_state_satisfied": False,
                    "host_present": host in current["hosts"] if isinstance(host, str) else None,
                    "retry_safe": False,
                }
                fallback = _write_parent_reconciliation_receipt(
                    request,
                    readback,
                    transport_error_type=type(exc).__name__,
                )
            except Exception:
                fallback = None
        if fallback is None:
            fallback = {
                "schema_version": 1,
                "request_id": None if request is None else request.get("request_id"),
                "request_sha256": None if request is None else _canonical_sha256(request),
                "operation": None if request is None else request.get("operation"),
                "host": None if request is None else request.get("host"),
                "before_registry_sha256": (
                    None if request is None else request.get("expected_registry_sha256")
                ),
                "result": "failed",
                "error": type(exc).__name__,
            }
        print(json.dumps(fallback, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

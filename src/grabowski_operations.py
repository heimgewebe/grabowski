from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import time
from typing import Any
import uuid

import grabowski_blockade_authority as blockade_authority
import grabowski_fleet as fleet
import grabowski_fleet_mutation as fleet_mutation
import grabowski_mcp as base
import grabowski_privileged as privileged
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
HOME = operator.HOME
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
OPERATIONS_CONFIG = Path(os.environ.get(
    "GRABOWSKI_OPERATIONS_CONFIG",
    str(HOME / ".config" / "grabowski" / "operations.json"),
)).expanduser()
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
PARAMETER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
PLACEHOLDER = re.compile(r"\$\{([A-Za-z][A-Za-z0-9_]{0,63})\}\Z")
PHASES = {"preflight": 0, "action": 1, "postflight": 2, "rollback": 3}
FLEET_MUTATION_OPERATION = "fleet-registry-mutate"
BACKUP_NTFS_CHECK_OPERATION = "backup-ntfs-check"
BACKUP_NTFS_CLEAR_DIRTY_OPERATION = "backup-ntfs-clear-dirty"
BACKUP_SMART_READ_OPERATION = "backup-smart-read"
SEAGATE_BACKUP_SMART_READ_OPERATION = "seagate-backup-smart-read"
BACKUP_MOUNT_RECONCILE_OPERATION = "backup-mount-reconcile"
ROOTBROKER_AUTHORITY_REFRESH_OPERATION = "rootbroker-authority-refresh"
BLOCKADE_AUTHORITY_HARDEN_OPERATION = "blockade-authority-harden"
PLATFORM_CONNECTOR_CAPTURE_OPERATION = "platform-connector-capture"
PLATFORM_CONNECTOR_CAPTURE_ACTION = "platform_connector_capture"
PLATFORM_CAPTURE_STAGE_ROOT = Path("/home/alex/worktrees")
PLATFORM_CAPTURE_SOURCE_PREFIX = ".grabowski-platform-observed-"
MAULWURF_RECOVERY_STATUS_OPERATION = "maulwurf-recovery-status"
MAULWURF_RECOVERY_ON_OPERATION = "maulwurf-recovery-on"
MAULWURF_RECOVERY_OFF_OPERATION = "maulwurf-recovery-off"
MAULWURF_RECOVERY_TYPED_OPERATIONS = frozenset(
    {
        MAULWURF_RECOVERY_STATUS_OPERATION,
        MAULWURF_RECOVERY_ON_OPERATION,
        MAULWURF_RECOVERY_OFF_OPERATION,
    }
)
BACKUP_STORAGE_TYPED_OPERATIONS = {
    BACKUP_NTFS_CHECK_OPERATION: {
        "description": "Run the fixed root-read-only ntfsfix check for the configured BACKUP volume.",
        "action": "local_backup_ntfs_check",
        "target": "check",
        "effect": "read_only",
        "parameters": (),
    },
    BACKUP_NTFS_CLEAR_DIRTY_OPERATION: {
        "description": "Run the fixed ntfsfix -d repair/clear-dirty path on the configured BACKUP volume after an exact successful check.",
        "action": "local_backup_ntfs_clear_dirty",
        "target": "clear-dirty",
        "effect": "filesystem_repair_write",
        "parameters": ("check_response_sha256",),
    },
    BACKUP_SMART_READ_OPERATION: {
        "description": "Read SMART data from the fixed configured BACKUP disk through the exact SAT/by-id rootbroker action.",
        "action": "local_backup_smart_read",
        "target": "smart-read",
        "effect": "read_only",
        "parameters": (),
    },
    SEAGATE_BACKUP_SMART_READ_OPERATION: {
        "description": "Read SMART data from the fixed Seagate Game Drive PS4 NZ0DRYBD through the exact SAT/by-id rootbroker action.",
        "action": "seagate_backup_smart_read",
        "target": "smart-read",
        "effect": "read_only",
        "parameters": (),
    },
    BACKUP_MOUNT_RECONCILE_OPERATION: {
        "description": "Remove only a vanished-device stale /mnt/backup NTFS mount after exact UUID, stability and busy-state checks; preserve the UUID-bound automount for the next access.",
        "action": "local_backup_mount_reconcile",
        "target": "reconcile",
        "effect": "mount_reconcile_write",
        "parameters": (),
    },
}
RESERVED_TYPED_OPERATIONS = frozenset(
    {
        FLEET_MUTATION_OPERATION,
        BLOCKADE_AUTHORITY_HARDEN_OPERATION,
        ROOTBROKER_AUTHORITY_REFRESH_OPERATION,
        PLATFORM_CONNECTOR_CAPTURE_OPERATION,
        *MAULWURF_RECOVERY_TYPED_OPERATIONS,
        *BACKUP_STORAGE_TYPED_OPERATIONS,
    }
)
BACKUP_NTFS_CHECK_EVIDENCE_TTL_SECONDS = 600
_BACKUP_NTFS_LAST_CHECK: dict[str, Any] | None = None


def _hash(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _load() -> dict[str, Any]:
    path = OPERATIONS_CONFIG
    if path.is_symlink():
        raise PermissionError(f"Operations registry may not be a symlink: {path}")
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Operations registry missing: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 512 * 1024:
        raise ValueError(f"Operations registry is not a bounded regular file: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Operations registry is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "operations"}:
        raise ValueError("Operations registry has invalid top-level keys")
    if raw["schema_version"] != 1 or not isinstance(raw["operations"], dict):
        raise ValueError("Operations registry must use schema_version 1")
    return raw


def _validated(name: str) -> dict[str, Any]:
    raw = _load()
    if not NAME.fullmatch(name) or name not in raw["operations"]:
        raise ValueError(f"Unknown operation: {name}")
    operation = raw["operations"][name]
    if not isinstance(operation, dict) or set(operation) != {"description", "parameters", "steps"}:
        raise ValueError(f"Operation {name} has invalid keys")
    description = operation["description"]
    parameters = operation["parameters"]
    steps = operation["steps"]
    if not isinstance(description, str) or not description.strip():
        raise ValueError(f"Operation {name} has invalid description")
    if not isinstance(parameters, dict) or not isinstance(steps, list) or not steps:
        raise ValueError(f"Operation {name} has invalid parameters or steps")
    for key, pattern in parameters.items():
        if not isinstance(key, str) or not PARAMETER.fullmatch(key):
            raise ValueError(f"Operation {name} has invalid parameter")
        if not isinstance(pattern, str) or len(pattern) > 500:
            raise ValueError(f"Operation {name} has invalid parameter pattern")
        re.compile(pattern)
    previous = -1
    actions = 0
    clean_steps: list[dict[str, Any]] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError(f"Operation {name} step {index} is invalid")
        required = {"phase", "target", "argv"}
        optional = {"timeout_seconds", "allow_failure"}
        if required - set(step) or set(step) - required - optional:
            raise ValueError(f"Operation {name} step {index} has invalid keys")
        phase = step["phase"]
        if phase not in PHASES or PHASES[phase] < previous:
            raise ValueError(f"Operation {name} has invalid phase order")
        previous = PHASES[phase]
        actions += phase == "action"
        target = step["target"]
        argv = step["argv"]
        timeout = step.get("timeout_seconds", operator.DEFAULT_TIMEOUT)
        allow_failure = step.get("allow_failure", False)
        if not isinstance(target, str) or not target:
            raise ValueError(f"Operation {name} step {index} has invalid target")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise ValueError(f"Operation {name} step {index} has invalid argv")
        if not isinstance(timeout, int) or not 1 <= timeout <= operator.MAX_TIMEOUT:
            raise ValueError(f"Operation {name} step {index} has invalid timeout")
        if not isinstance(allow_failure, bool):
            raise ValueError(f"Operation {name} step {index} has invalid allow_failure")
        for token in [target, *argv]:
            match = PLACEHOLDER.fullmatch(token)
            if "${" in token and not match:
                raise ValueError("Only exact-token placeholders are allowed")
            if match and match.group(1) not in parameters:
                raise ValueError(f"Operation {name} uses an unknown parameter")
        clean_steps.append({"phase": phase, "target": target, "argv": argv,
                            "timeout_seconds": timeout, "allow_failure": allow_failure})
    if not actions:
        raise ValueError(f"Operation {name} has no action phase")
    return {"description": description, "parameters": parameters, "steps": clean_steps}


def _render(name: str, parameters: dict[str, str] | None) -> dict[str, Any]:
    operation = _validated(name)
    supplied = parameters or {}
    if not isinstance(supplied, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                  for k, v in supplied.items()):
        raise ValueError("parameters must be an object of strings")
    expected = set(operation["parameters"])
    if set(supplied) != expected:
        raise ValueError(f"Parameter mismatch; missing={sorted(expected - set(supplied))}, "
                         f"unknown={sorted(set(supplied) - expected)}")
    for key, value in supplied.items():
        if len(value.encode("utf-8")) > 4096 or "\x00" in value:
            raise ValueError(f"Parameter {key} is too large or contains NUL")
        if operator._redact(value) != value:
            raise ValueError(f"Parameter {key} appears to contain secret material")
        if re.fullmatch(operation["parameters"][key], value) is None:
            raise ValueError(f"Parameter {key} does not match its contract")
    rendered = []
    for step in operation["steps"]:
        def substitute(token: str) -> str:
            match = PLACEHOLDER.fullmatch(token)
            return supplied[match.group(1)] if match else token
        target = substitute(step["target"])
        argv = [substitute(token) for token in step["argv"]]
        argv = operator._validate_argv(argv, cwd=HOME)
        if operator._redact_argv(argv) != argv:
            raise ValueError("Rendered argv appears to contain secret material")
        if target != "local":
            fleet.fleet_host(target)
        rendered.append({**step, "target": target, "argv": argv})
    return {"name": name, "description": operation["description"],
            "parameter_names": sorted(supplied), "parameters_sha256": _hash(supplied),
            "steps": rendered}


def _run_step(step: dict[str, Any]) -> dict[str, Any]:
    if step["target"] == "local":
        result = operator._run(step["argv"], cwd=HOME,
                               timeout_seconds=step["timeout_seconds"],
                               max_output_bytes=operator.DEFAULT_OUTPUT_BYTES)
        return {"target": "local", "result": result}
    return fleet.run_fleet_host(step["target"], step["argv"],
                                timeout_seconds=step["timeout_seconds"],
                                max_output_bytes=operator.DEFAULT_OUTPUT_BYTES)


def _maulwurf_recovery_operation_plan(
    operation: str, parameters: dict[str, str] | None
) -> dict[str, Any]:
    if not operator._maulwurf_runtime_active():
        raise RuntimeError("Maulwurf recovery operations are available only on the mole runtime")
    supplied = parameters or {}
    if not isinstance(supplied, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in supplied.items()
    ):
        raise ValueError("parameters must be an object of strings")
    if operation == MAULWURF_RECOVERY_ON_OPERATION:
        if set(supplied) != {"reason"}:
            raise ValueError("maulwurf-recovery-on requires exactly the reason parameter")
        reason = supplied["reason"].strip()
        if not reason or len(reason) > 240:
            raise ValueError("recovery reason must contain 1..240 characters")
        if operator._redact(reason) != reason:
            raise ValueError("recovery reason must not contain secret material")
    elif supplied:
        raise ValueError(f"{operation} accepts no parameters")
    import der_kleine_maulwurf_operator as mole

    return {
        "operation": operation,
        "typed_builtin": True,
        "effect": (
            "read_only"
            if operation == MAULWURF_RECOVERY_STATUS_OPERATION
            else "recovery_mode_write"
        ),
        "parameters": (["reason"] if operation == MAULWURF_RECOVERY_ON_OPERATION else []),
        "current_status": mole.recovery_mode_status(),
    }


def _run_maulwurf_recovery_operation(
    operation: str, parameters: dict[str, str] | None
) -> dict[str, Any]:
    plan = _maulwurf_recovery_operation_plan(operation, parameters)
    import der_kleine_maulwurf_operator as mole
    if operation in {MAULWURF_RECOVERY_ON_OPERATION, MAULWURF_RECOVERY_OFF_OPERATION}:
        operator._require_operator_capability("maulwurf_recovery_control")

    if operation == MAULWURF_RECOVERY_STATUS_OPERATION:
        status = mole.recovery_mode_status()
    elif operation == MAULWURF_RECOVERY_ON_OPERATION:
        status = mole.enable_recovery_mode((parameters or {})["reason"])
    elif operation == MAULWURF_RECOVERY_OFF_OPERATION:
        status = mole.disable_recovery_mode()
    else:
        raise ValueError(f"Unknown Maulwurf recovery operation: {operation}")
    expected_mode = {
        MAULWURF_RECOVERY_ON_OPERATION: "recovery",
        MAULWURF_RECOVERY_OFF_OPERATION: "normal",
    }.get(operation)
    success = status.get("valid") is True and (
        expected_mode is None or status.get("mode") == expected_mode
    )
    if expected_mode is not None:
        success = success and status.get("write_outcome") == "confirmed"
    return {
        "operation": operation,
        "success": success,
        "effect": plan["effect"],
        "status": status,
    }


def _append_fleet_mutation_audit(audit: dict[str, Any]) -> dict[str, Any]:
    response = dict(audit)
    try:
        base._append_audit(audit)
        response["secondary_audit_recorded"] = True
    except Exception as exc:
        # The dedicated mutation receipt is authoritative. Failure of this
        # secondary projection must not make an already-proven effect appear
        # unknown to the caller.
        response["secondary_audit_recorded"] = False
        response["secondary_audit_error_type"] = type(exc).__name__
    return response


def _backup_storage_operation_plan(
    operation: str, parameters: dict[str, str] | None
) -> dict[str, Any]:
    if operation not in BACKUP_STORAGE_TYPED_OPERATIONS:
        raise ValueError(f"Unknown typed BACKUP storage operation: {operation}")
    supplied = parameters or {}
    if not isinstance(supplied, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in supplied.items()
    ):
        raise ValueError("parameters must be an object of strings")
    spec = BACKUP_STORAGE_TYPED_OPERATIONS[operation]
    expected_parameters = set(spec["parameters"])
    if set(supplied) != expected_parameters:
        raise ValueError(
            f"Operation {operation} parameter mismatch; "
            f"missing={sorted(expected_parameters - set(supplied))}, "
            f"unknown={sorted(set(supplied) - expected_parameters)}"
        )
    if supplied and re.fullmatch(r"[0-9a-f]{64}", supplied["check_response_sha256"]) is None:
        raise ValueError("check_response_sha256 is invalid")
    return {
        "name": operation,
        "description": spec["description"],
        "parameter_names": sorted(supplied),
        "parameters_sha256": _hash(supplied),
        "typed_builtin": True,
        "execution": "operator-mainpid-direct-rootbroker",
        "privileged_action": spec["action"],
        "target": spec["target"],
        "effect": spec["effect"],
        "rollback": (
            "none; a successful stale-mount unmount is intentionally not reversed; "
            "the UUID-bound automount may remount on next access, and any failed or "
            "uncertain outcome must be read back before another reconcile intent"
            if operation == BACKUP_MOUNT_RECONCILE_OPERATION
            else "none; read-only diagnostics have no rollback and NTFS repair is separately operator-gated"
        ),
    }


def _platform_capture_path(value: Any, expected_sha256: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("observed_artifact_path is invalid")
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise ValueError("observed_artifact_path must be canonical and absolute")
    expected_name = f"{PLATFORM_CAPTURE_SOURCE_PREFIX}{expected_sha256}.json"
    if path.parent != PLATFORM_CAPTURE_STAGE_ROOT or path.name != expected_name:
        raise ValueError("observed artifact path is outside the fixed platform capture inbox")
    return path


def _platform_connector_capture_plan(
    parameters: dict[str, str] | None,
) -> dict[str, Any]:
    supplied = parameters or {}
    expected = {
        "observed_artifact_path",
        "expected_artifact_sha256",
        "source_reference",
        "observation_scope",
        "observation_id",
        "publication_request_id",
        "requested_contract_sha256",
        "observed_at_unix",
    }
    if (
        not isinstance(supplied, dict)
        or set(supplied) != expected
        or any(not isinstance(value, str) for value in supplied.values())
    ):
        raise ValueError("platform connector capture parameters do not match the fixed contract")
    artifact_sha256 = supplied["expected_artifact_sha256"]
    contract_sha256 = supplied["requested_contract_sha256"]
    if re.fullmatch(r"[0-9a-f]{64}", artifact_sha256) is None:
        raise ValueError("expected_artifact_sha256 is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", contract_sha256) is None:
        raise ValueError("requested_contract_sha256 is invalid")
    artifact_path = _platform_capture_path(
        supplied["observed_artifact_path"], artifact_sha256
    )
    if supplied["observation_scope"] not in {"connector_catalog", "new_chat_catalog"}:
        raise ValueError("platform observation scope is not publication-authoritative")
    identifier = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
    for key in ("observation_id", "publication_request_id"):
        if identifier.fullmatch(supplied[key]) is None:
            raise ValueError(f"{key} is invalid")
    reference = supplied["source_reference"]
    if (
        not reference
        or reference.strip() != reference
        or len(reference.encode("utf-8")) > 1024
        or operator._redact(reference) != reference
    ):
        raise ValueError("source_reference is invalid or secret-adjacent")
    observed_at = supplied["observed_at_unix"]
    if re.fullmatch(r"[0-9]{1,12}", observed_at) is None:
        raise ValueError("observed_at_unix is invalid")
    return {
        "name": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
        "description": (
            "Validate one hash-bound ChatGPT-observed complete connector catalog, bind it "
            "to the active runtime, publish only the prepared snapshot through the fixed "
            "Rootbroker action, then reconcile the existing platform publication request."
        ),
        "parameter_names": sorted(expected),
        "parameters_sha256": _hash(supplied),
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_sha256,
        "source_reference": reference,
        "observation_scope": supplied["observation_scope"],
        "observation_id": supplied["observation_id"],
        "publication_request_id": supplied["publication_request_id"],
        "requested_contract_sha256": contract_sha256,
        "observed_at_unix": int(observed_at),
        "typed_builtin": True,
        "execution": "controller-observation-to-fixed-rootbroker-publisher",
        "effect": "platform_observation_publish_and_reconcile",
        "rollback": (
            "none; root publication is content-addressed and later reconciliation accepts only "
            "a fresh request-bound exact contract. Unknown broker outcomes require exact platform "
            "snapshot readback before another publish intent."
        ),
    }


def _read_platform_capture_artifact(path: Path, expected_sha256: str) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("observed platform artifact cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > base.grabowski_connector_contract.MAX_COMPLETE_OBSERVED_ARTIFACT_BYTES
        ):
            raise ValueError("observed platform artifact metadata violates the capture contract")
        data = b""
        while len(data) < metadata.st_size:
            chunk = os.read(descriptor, min(64 * 1024, metadata.st_size - len(data)))
            if not chunk:
                raise ValueError("observed platform artifact ended early")
            data += chunk
        if os.read(descriptor, 1):
            raise ValueError("observed platform artifact grew while being read")
        final = os.fstat(descriptor)
        if final.st_dev != metadata.st_dev or final.st_ino != metadata.st_ino or final.st_size != metadata.st_size:
            raise ValueError("observed platform artifact changed while being read")
    finally:
        os.close(descriptor)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("observed platform artifact SHA-256 mismatch")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("observed platform artifact is not valid UTF-8 JSON") from exc
    return base.grabowski_connector_contract.compact_complete_observed_artifact(
        payload,
        label="ChatGPT-observed complete connector catalog",
    )


def _write_platform_capture_stage(document: dict[str, Any]) -> tuple[Path, str]:
    root = PLATFORM_CAPTURE_STAGE_ROOT
    metadata = root.lstat()
    if (
        root.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022
    ):
        raise PermissionError("platform capture staging root is unsafe")
    data = json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if not data or len(data) > base.grabowski_client_snapshot.MAX_PLATFORM_SNAPSHOT_BYTES:
        raise ValueError("prepared platform snapshot exceeds the bounded rootbroker contract")
    path = root / f".grabowski-platform-snapshot-{uuid.uuid4().hex}.json"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("prepared platform snapshot write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
    except Exception:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as cleanup_exc:
            raise RuntimeError(
                "prepared platform snapshot cleanup failed after construction failure"
            ) from cleanup_exc
        raise
    return path, hashlib.sha256(data).hexdigest()


def _platform_runtime_context() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    binding, _runtime_names = base.grabowski_client_snapshot._runtime_platform_binding(
        base.DEPLOYMENT_MANIFEST.parent
    )
    runtime_tools = base._runtime_connector_observed_tools()
    _names, _schemas, metadata = base.grabowski_connector_contract.parse_observed_artifact(
        runtime_tools, label="active runtime connector artifact"
    )
    return binding, runtime_tools, metadata


def _platform_capture_publication_binding(
    plan: dict[str, Any],
    binding: dict[str, Any],
    runtime_metadata: dict[str, Any],
) -> dict[str, Any]:
    current = base.grabowski_client_snapshot._read_publication_current()
    if not isinstance(current, dict) or current.get("state") == "no_current":
        raise ValueError("platform capture requires one current publication request")
    if current.get("request_id") != plan["publication_request_id"]:
        raise ValueError("platform capture publication request is not current")
    if current.get("state") == "pending_activation":
        raise ValueError("platform capture requires the publication action to be activated first")
    request = base.grabowski_client_snapshot._read_publication_request(
        plan["publication_request_id"]
    )
    request_contract_sha256 = request["expected_contract"]["tool_contract_sha256"]
    if current.get("contract_sha256") != request_contract_sha256:
        raise ValueError("platform publication current/request contract mismatch")
    if plan["requested_contract_sha256"] != request_contract_sha256:
        raise ValueError("platform capture requested contract is not the current request contract")
    if plan["observed_at_unix"] < request["requested_at_unix"]:
        raise ValueError("platform observation predates the publication request")
    now_unix = int(time.time())
    if (
        plan["observed_at_unix"]
        > now_unix + base.grabowski_client_snapshot.SNAPSHOT_CLOCK_SKEW_SECONDS
    ):
        raise ValueError("platform observation is too far in the future")
    runtime_contract = base.grabowski_client_snapshot._platform_publication_contract(
        registered_tool_count=binding["registered_tool_count"],
        registered_names_sha256=binding["registered_names_sha256"],
        complete_schema_count=runtime_metadata["complete_schema_count"],
        complete_schema_sha256=runtime_metadata["complete_schema_sha256"],
    )
    if runtime_contract["tool_contract_sha256"] != request_contract_sha256:
        raise ValueError("active runtime contract differs from the publication request")
    if (
        plan["observed_at_unix"]
        < now_unix - base.grabowski_client_snapshot.SNAPSHOT_TTL_SECONDS
    ):
        raise ValueError("platform observation is stale")
    return {
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "current_sha256": current["current_sha256"],
        "current_state": current["state"],
        "contract_sha256": request_contract_sha256,
        "runtime_contract_sha256": runtime_contract["tool_contract_sha256"],
    }


def _platform_runtime_identity(
    binding: dict[str, Any], runtime_metadata: dict[str, Any]
) -> dict[str, Any]:
    return {
        "binding": dict(binding),
        "complete_schema_count": runtime_metadata["complete_schema_count"],
        "complete_schema_sha256": runtime_metadata["complete_schema_sha256"],
    }


def _platform_snapshot_readback(
    binding: dict[str, Any], runtime_tools: dict[str, Any]
) -> dict[str, Any]:
    return base.grabowski_client_snapshot.platform_snapshot_status(
        expected_tool_count=binding["registered_tool_count"],
        expected_names_sha256=binding["registered_names_sha256"],
        expected_release_id=binding["release_id"],
        expected_repo_head=binding["repo_head"],
        expected_agent_instructions_sha256=binding["agent_instructions_sha256"],
        expected_runtime_tools=runtime_tools,
    )


def _platform_capture_root_target(target: str) -> dict[str, str]:
    try:
        payload = json.loads(target)
    except json.JSONDecodeError as exc:
        raise ValueError("platform capture root target is invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"source_path", "expected_file_sha256"}:
        raise ValueError("platform capture root target fields are invalid")
    path = payload.get("source_path")
    sha256 = payload.get("expected_file_sha256")
    if (
        not isinstance(path, str)
        or re.fullmatch(r"/home/alex/worktrees/\.grabowski-platform-snapshot-[0-9a-f]{32}\.json", path) is None
        or not isinstance(sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
    ):
        raise ValueError("platform capture root target binding is invalid")
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if target != canonical:
        raise ValueError("platform capture root target must be canonical JSON")
    return {"source_path": path, "expected_file_sha256": sha256}


def _run_platform_connector_capture_operation(
    parameters: dict[str, str] | None,
) -> dict[str, Any]:
    plan = _platform_connector_capture_plan(parameters)
    operator._require_operator_capability("privileged_reference")
    operator._require_operator_mutation("terminal_execute", opaque_command=False)
    observed_tools = _read_platform_capture_artifact(
        Path(plan["artifact_path"]), plan["artifact_sha256"]
    )
    binding, runtime_tools, runtime_metadata = _platform_runtime_context()
    runtime_identity = _platform_runtime_identity(binding, runtime_metadata)
    publication_binding = _platform_capture_publication_binding(
        plan, binding, runtime_metadata
    )
    document = base.grabowski_client_snapshot.build_platform_connector_snapshot(
        observed_tools=observed_tools,
        runtime_root=base.DEPLOYMENT_MANIFEST.parent,
        source_reference=plan["source_reference"],
        observation_scope=plan["observation_scope"],
        observation_id=plan["observation_id"],
        publication_request_id=plan["publication_request_id"],
        requested_contract_sha256=plan["requested_contract_sha256"],
        observed_at_unix=plan["observed_at_unix"],
    )
    if document.get("runtime_binding") != binding:
        raise ValueError("active runtime changed while building the platform snapshot")
    before = _platform_snapshot_readback(binding, runtime_tools)
    expected_snapshot_sha256 = document["snapshot_sha256"]
    invocation: dict[str, Any] | None = None
    staged_path: Path | None = None
    if before.get("snapshot_sha256") != expected_snapshot_sha256:
        latest_binding, _latest_tools, latest_metadata = _platform_runtime_context()
        latest_publication_binding = _platform_capture_publication_binding(
            plan, latest_binding, latest_metadata
        )
        if (
            latest_publication_binding["request_sha256"]
            != publication_binding["request_sha256"]
        ):
            raise ValueError("platform publication request changed before root capture")
        if _platform_runtime_identity(latest_binding, latest_metadata) != runtime_identity:
            raise ValueError("active runtime changed before root capture")
        staged_path, staged_sha256 = _write_platform_capture_stage(document)
        target = json.dumps(
            {"source_path": str(staged_path), "expected_file_sha256": staged_sha256},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        try:
            invocation = _invoke_mainpid_privileged_action(
                action=PLATFORM_CONNECTOR_CAPTURE_ACTION,
                target=target,
                justification="publish one hash-bound request-scoped ChatGPT connector catalog observation",
                timeout_seconds=120,
            )
        except Exception:
            staged_path.unlink(missing_ok=True)
            raise
    try:
        post_binding, post_runtime_tools, post_metadata = _platform_runtime_context()
        post_runtime_identity = _platform_runtime_identity(post_binding, post_metadata)
        after_root = _platform_snapshot_readback(post_binding, post_runtime_tools)
    except Exception as exc:
        if invocation is not None and invocation.get("outcome") == "unknown":
            return {
                "operation": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
                "success": False,
                "outcome": "unknown",
                "effect": plan["effect"],
                "expected_snapshot_sha256": expected_snapshot_sha256,
                "root_effect_confirmed": False,
                "staged_snapshot_path": str(staged_path) if staged_path is not None else None,
                "staged_snapshot_retained": staged_path is not None,
                "postflight_error_class": type(exc).__name__,
                "recommended_next_action": "read the exact platform snapshot before any new publish intent",
            }
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)
        raise
    root_effect_confirmed = after_root.get("snapshot_sha256") == expected_snapshot_sha256
    post_runtime_stable = post_runtime_identity == runtime_identity
    runtime_binding_matches = after_root.get("runtime_binding_matches") is True
    publication_contract_matches = after_root.get("publication_contract_matches") is True
    if invocation is not None and invocation.get("outcome") == "unknown" and not root_effect_confirmed:
        return {
            "operation": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "success": False,
            "outcome": "unknown",
            "effect": plan["effect"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": False,
            "staged_snapshot_path": str(staged_path) if staged_path is not None else None,
            "staged_snapshot_retained": True,
            "recommended_next_action": "read the exact platform snapshot before any new publish intent",
        }
    if invocation is not None and invocation.get("outcome") == "failed" and not root_effect_confirmed:
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)
        return {
            "operation": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "success": False,
            "outcome": "failed",
            "effect": plan["effect"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": False,
            "root_response_sha256": invocation.get("response_sha256"),
        }
    if staged_path is not None:
        staged_path.unlink(missing_ok=True)
    if not root_effect_confirmed:
        return {
            "operation": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "success": False,
            "outcome": "failed",
            "effect": plan["effect"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": False,
        }
    if not (post_runtime_stable and runtime_binding_matches and publication_contract_matches):
        audit = {
            "timestamp_unix": int(time.time()),
            "operation": "named-operation-run",
            "recipe": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "parameters_sha256": plan["parameters_sha256"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": True,
            "root_audit_sha256": (
                _root_audit_sha256(invocation) if invocation is not None else None
            ),
            "publication_state": after_root.get("publication_state"),
            "post_runtime_stable": post_runtime_stable,
            "runtime_binding_matches": runtime_binding_matches,
            "publication_contract_matches": publication_contract_matches,
            "success": False,
        }
        base._append_audit(audit)
        return {
            "operation": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "success": False,
            "outcome": "failed",
            "effect": plan["effect"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": True,
            "root_audit_sha256": audit["root_audit_sha256"],
            "post_runtime_stable": post_runtime_stable,
            "runtime_binding_matches": runtime_binding_matches,
            "publication_contract_matches": publication_contract_matches,
            "recommended_next_action": "capture a fresh platform observation bound to the current runtime before reconciliation",
            "audit": audit,
        }
    try:
        reconciliation = base.grabowski_client_snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=post_binding["registered_tool_count"],
            registered_names_sha256=post_binding["registered_names_sha256"],
            complete_schema_count=post_metadata["complete_schema_count"],
            complete_schema_sha256=post_metadata["complete_schema_sha256"],
        )
    except Exception as exc:
        audit = {
            "timestamp_unix": int(time.time()),
            "operation": "named-operation-run",
            "recipe": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "parameters_sha256": plan["parameters_sha256"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": True,
            "root_audit_sha256": (
                _root_audit_sha256(invocation) if invocation is not None else None
            ),
            "publication_state": after_root.get("publication_state"),
            "post_runtime_stable": post_runtime_stable,
            "runtime_binding_matches": runtime_binding_matches,
            "publication_contract_matches": publication_contract_matches,
            "reconciliation_error_class": type(exc).__name__,
            "success": False,
        }
        base._append_audit(audit)
        raise
    try:
        final_binding, final_runtime_tools, final_metadata = _platform_runtime_context()
        final = _platform_snapshot_readback(final_binding, final_runtime_tools)
    except Exception as exc:
        audit = {
            "timestamp_unix": int(time.time()),
            "operation": "named-operation-run",
            "recipe": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
            "parameters_sha256": plan["parameters_sha256"],
            "expected_snapshot_sha256": expected_snapshot_sha256,
            "root_effect_confirmed": True,
            "root_audit_sha256": (
                _root_audit_sha256(invocation) if invocation is not None else None
            ),
            "publication_state": reconciliation.get("state"),
            "post_runtime_stable": post_runtime_stable,
            "runtime_binding_matches": runtime_binding_matches,
            "publication_contract_matches": publication_contract_matches,
            "final_readback_error_class": type(exc).__name__,
            "success": False,
        }
        base._append_audit(audit)
        raise
    final_runtime_stable = (
        _platform_runtime_identity(final_binding, final_metadata) == runtime_identity
    )
    success = bool(
        reconciliation.get("state") == "platform_converged"
        and final_runtime_stable
        and final.get("fresh") is True
        and final.get("state") == "matched"
        and final.get("runtime_binding_matches") is True
        and final.get("publication_contract_matches") is True
        and final.get("publication_state") == "platform_converged"
    )
    audit = {
        "timestamp_unix": int(time.time()),
        "operation": "named-operation-run",
        "recipe": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
        "parameters_sha256": plan["parameters_sha256"],
        "expected_snapshot_sha256": expected_snapshot_sha256,
        "root_effect_confirmed": root_effect_confirmed,
        "root_audit_sha256": _root_audit_sha256(invocation) if invocation is not None else None,
        "publication_state": reconciliation.get("state"),
        "success": success,
    }
    base._append_audit(audit)
    return {
        "operation": PLATFORM_CONNECTOR_CAPTURE_OPERATION,
        "success": success,
        "outcome": "succeeded" if success else "failed",
        "effect": plan["effect"],
        "snapshot_sha256": expected_snapshot_sha256,
        "source_artifact_sha256": plan["artifact_sha256"],
        "root_effect_confirmed": root_effect_confirmed,
        "root_audit_sha256": audit["root_audit_sha256"],
        "reconciliation": reconciliation,
        "platform_state": final.get("state"),
        "platform_publication_state": final.get("publication_state"),
        "platform_publication_contract_matches": final.get("publication_contract_matches"),
        "does_not_establish": [
            "cryptographic platform origin",
            "future connector catalog stability",
            "benchmark execution authority",
        ],
        "audit": audit,
    }


def _rootbroker_authority_refresh_plan(
    parameters: dict[str, str] | None,
) -> dict[str, Any]:
    supplied = parameters or {}
    if not isinstance(supplied, dict) or set(supplied) != {"expected_head"}:
        raise ValueError("rootbroker authority refresh requires only expected_head")
    expected_head = supplied.get("expected_head")
    if (
        not isinstance(expected_head, str)
        or re.fullmatch(r"[0-9a-f]{40}", expected_head) is None
    ):
        raise ValueError("expected_head must be one full SHA-1 commit id")
    return {
        "name": ROOTBROKER_AUTHORITY_REFRESH_OPERATION,
        "description": (
            "Force one exact-main Rootbroker authority refresh even when the current "
            "attestation already names that commit; this exists only for controlled "
            "same-commit capability bootstrap."
        ),
        "parameter_names": ["expected_head"],
        "parameters_sha256": _hash(supplied),
        "expected_head": expected_head,
        "typed_builtin": True,
        "execution": "operator-mainpid-direct-rootbroker",
        "effect": "authority_contract_refresh",
        "rollback": (
            "Rootbroker cutover owns atomic backup, rollback and exact post-readback; "
            "an unknown outcome requires authority readback before another intent."
        ),
    }


def _run_rootbroker_authority_refresh_operation(
    parameters: dict[str, str] | None,
) -> dict[str, Any]:
    plan = _rootbroker_authority_refresh_plan(parameters)
    operator._require_operator_capability("privileged_reference")
    operator._require_operator_mutation("terminal_execute", opaque_command=False)
    result = privileged.ensure_rootbroker_authority(
        plan["expected_head"], force_refresh=True
    )
    success = result.get("success") is True
    audit = {
        "timestamp_unix": int(time.time()),
        "operation": "named-operation-run",
        "recipe": ROOTBROKER_AUTHORITY_REFRESH_OPERATION,
        "parameters_sha256": plan["parameters_sha256"],
        "expected_head": plan["expected_head"],
        "success": success,
        "root_outcome": result.get("outcome"),
        "attested_head": result.get("attested_head"),
        "force_refresh": True,
    }
    try:
        base._append_audit(audit)
        audit["secondary_audit_recorded"] = True
    except Exception as exc:
        audit["secondary_audit_recorded"] = False
        audit["secondary_audit_error_type"] = type(exc).__name__
    return {
        "operation": ROOTBROKER_AUTHORITY_REFRESH_OPERATION,
        "success": success,
        "failed_phase": None if success else "action",
        "typed_builtin": True,
        "effect": plan["effect"],
        "result": result,
        "rollback": {"attempted": False, "success": True, "reason": plan["rollback"]},
        "audit": audit,
    }


def _invoke_mainpid_privileged_action(
    *, action: str, target: str, justification: str, timeout_seconds: int = 120
) -> dict[str, Any]:
    allowed = {
        (str(spec["action"]), str(spec["target"]))
        for spec in BACKUP_STORAGE_TYPED_OPERATIONS.values()
    }
    platform_capture = action == PLATFORM_CONNECTOR_CAPTURE_ACTION
    if platform_capture:
        _platform_capture_root_target(target)
    elif (action, target) not in allowed:
        raise ValueError("MainPID privileged action is outside the BACKUP storage allowlist")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= 120
    ):
        raise ValueError("MainPID privileged timeout is invalid")
    broker = privileged._privileged_broker_status()
    if not broker.get("ready"):
        raise PermissionError("privileged broker is not ready")
    reference = privileged._create_privileged_reference(
        action=action, target=target, justification=justification
    )
    payload = (
        json.dumps(reference, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    if not payload or len(payload) > 64 * 1024:
        raise ValueError("privileged reference exceeds broker input limit")
    timed_out = False
    transport_error: str | None = None
    raw = b""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds + 15)
            client.connect(str(privileged.BROKER_SOCKET))
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = client.recv(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 512 * 1024:
                    raise RuntimeError("privileged broker response exceeds output limit")
                chunks.append(chunk)
            raw = b"".join(chunks)
    except (socket.timeout, TimeoutError) as exc:
        timed_out = True
        transport_error = str(exc) or "privileged broker request timed out"
    except (OSError, RuntimeError) as exc:
        transport_error = f"{type(exc).__name__}: {exc}"
    text = privileged._redact_text(raw.decode("utf-8", errors="replace"))
    try:
        response = json.loads(text) if text.strip() else None
    except json.JSONDecodeError:
        response = None
    response_error = response.get("error") if isinstance(response, dict) else None
    command_returncode = response.get("returncode") if isinstance(response, dict) else None
    response_audit = response.get("audit") if isinstance(response, dict) else None
    audit_binding_valid = (
        isinstance(response_audit, dict)
        and response_audit.get("request_id") == reference["request_id"]
        and response_audit.get("reference_sha256") == reference["reference_sha256"]
        and response_audit.get("action") == action
        and response_audit.get("mode") == "template"
        and response_audit.get("returncode") == command_returncode
        and response_audit.get("timed_out") is False
        and response_audit.get("peer_uid") == 1000
        and response_audit.get("peer_unit") == "grabowski-operator.service"
    )
    structured = (
        isinstance(response, dict)
        and response_error is None
        and response.get("request_id") == reference["request_id"]
        and response.get("action") == action
        and response.get("timed_out") is False
        and response.get("mode") == "template"
        and audit_binding_valid
    )
    success = (
        structured
        and timed_out is False
        and transport_error is None
        and command_returncode == 0
    )
    outcome = (
        "succeeded"
        if success
        else "unknown"
        if timed_out or response is None
        else "failed"
    )
    return {
        "request_id": reference["request_id"],
        "reference_sha256": reference["reference_sha256"],
        "action": action,
        "target": target,
        "success": success,
        "outcome": outcome,
        "timed_out": timed_out,
        "transport_error": transport_error,
        "broker_response": response,
        "response_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _root_audit_sha256(invocation: dict[str, Any]) -> str | None:
    response = invocation.get("broker_response")
    if not isinstance(response, dict):
        return None
    audit = response.get("audit")
    if not isinstance(audit, dict):
        return None
    if (
        audit.get("request_id") != invocation.get("request_id")
        or audit.get("reference_sha256") != invocation.get("reference_sha256")
        or audit.get("action") != invocation.get("action")
        or audit.get("mode") != "template"
        or audit.get("returncode") != response.get("returncode")
        or audit.get("timed_out") is not False
        or audit.get("peer_uid") != 1000
        or audit.get("peer_unit") != "grabowski-operator.service"
    ):
        return None
    if invocation.get("action") in {"local_backup_smart_read", "seagate_backup_smart_read"}:
        stdout = response.get("stdout")
        stderr = response.get("stderr")
        if not isinstance(stdout, str) or not isinstance(stderr, str):
            return None
        stdout_bytes = stdout.encode("utf-8")
        stderr_bytes = stderr.encode("utf-8")
        if (
            audit.get("stdout_truncated") is not False
            or audit.get("stderr_truncated") is not False
            or audit.get("smart_stdout_sha256") != hashlib.sha256(stdout_bytes).hexdigest()
            or audit.get("smart_stdout_bytes") != len(stdout_bytes)
            or audit.get("smart_stderr_sha256") != hashlib.sha256(stderr_bytes).hexdigest()
            or audit.get("smart_stderr_bytes") != len(stderr_bytes)
        ):
            return None
    return _hash(audit)


def _record_backup_ntfs_check_evidence(invocation: dict[str, Any]) -> dict[str, Any] | None:
    global _BACKUP_NTFS_LAST_CHECK
    audit_sha256 = _root_audit_sha256(invocation)
    if invocation.get("outcome") == "unknown" or audit_sha256 is None:
        _BACKUP_NTFS_LAST_CHECK = None
        return None
    evidence = {
        "checked_at_unix": int(time.time()),
        "response_sha256": invocation["response_sha256"],
        "reference_sha256": invocation["reference_sha256"],
        "root_audit_sha256": audit_sha256,
        "write_admissible": invocation.get("success") is True,
        "check_returncode": (
            invocation["broker_response"].get("returncode")
            if isinstance(invocation.get("broker_response"), dict)
            else None
        ),
    }
    _BACKUP_NTFS_LAST_CHECK = dict(evidence)
    return evidence


def _consume_backup_ntfs_check_evidence(parameters: dict[str, str] | None) -> dict[str, Any]:
    global _BACKUP_NTFS_LAST_CHECK
    supplied = parameters or {}
    expected = supplied.get("check_response_sha256")
    evidence = _BACKUP_NTFS_LAST_CHECK
    _BACKUP_NTFS_LAST_CHECK = None
    if not isinstance(evidence, dict) or expected != evidence.get("response_sha256"):
        raise PermissionError("clear-dirty requires the exact latest BACKUP NTFS check evidence")
    if evidence.get("write_admissible") is not True:
        raise PermissionError("BACKUP NTFS check did not authorize repair write")
    checked_at = evidence.get("checked_at_unix")
    now = int(time.time())
    if (
        isinstance(checked_at, bool)
        or not isinstance(checked_at, int)
        or checked_at > now + 5
        or now - checked_at > BACKUP_NTFS_CHECK_EVIDENCE_TTL_SECONDS
    ):
        raise PermissionError("BACKUP NTFS check evidence is stale")
    return evidence


def _run_backup_storage_operation(
    operation: str, parameters: dict[str, str] | None
) -> dict[str, Any]:
    plan = _backup_storage_operation_plan(operation, parameters)
    consumed_check_evidence = (
        _consume_backup_ntfs_check_evidence(parameters)
        if operation == BACKUP_NTFS_CLEAR_DIRTY_OPERATION
        else None
    )
    operator._require_operator_capability("privileged_reference")
    operator._require_operator_mutation("terminal_execute", opaque_command=False)
    if operation == BACKUP_NTFS_CHECK_OPERATION:
        justification = "Root-read-only ntfsfix check for the exact configured BACKUP volume before any filesystem metadata mutation."
    elif operation == BACKUP_NTFS_CLEAR_DIRTY_OPERATION:
        justification = "Run the fixed ntfsfix -d repair/clear-dirty path on the exact configured BACKUP volume after an exact successful root check; no force mount."
    elif operation == BACKUP_MOUNT_RECONCILE_OPERATION:
        justification = "Remove only a vanished-device stale /mnt/backup NTFS mount after root-side UUID, stability and busy-state checks; preserve the UUID-bound automount."
    elif operation == SEAGATE_BACKUP_SMART_READ_OPERATION:
        justification = "Root-read-only SMART diagnostic for the exact Seagate Game Drive PS4 serial NZ0DRYBD through the fixed SAT/by-id action; no caller-selected device or flags."
    else:
        justification = "Root-read-only SMART diagnostic for the exact configured BACKUP disk through the fixed SAT/by-id action; no caller-selected device or flags."
    invocation = _invoke_mainpid_privileged_action(
        action=str(plan["privileged_action"]),
        target=str(plan["target"]),
        justification=justification,
    )
    check_evidence = (
        _record_backup_ntfs_check_evidence(invocation)
        if operation == BACKUP_NTFS_CHECK_OPERATION
        else None
    )
    audit = {
        "timestamp_unix": int(time.time()),
        "operation": "named-operation-run",
        "recipe": operation,
        "typed_builtin": True,
        "parameters_sha256": plan["parameters_sha256"],
        "privileged_action": invocation["action"],
        "reference_sha256": invocation["reference_sha256"],
        "request_id": invocation["request_id"],
        "success": invocation["success"],
        "outcome": invocation["outcome"],
        "timed_out": invocation["timed_out"],
        "broker_returncode": (
            invocation["broker_response"].get("returncode")
            if isinstance(invocation["broker_response"], dict)
            else None
        ),
        "response_sha256": invocation["response_sha256"],
    }
    try:
        base._append_audit(audit)
        audit["secondary_audit_recorded"] = True
    except Exception as exc:
        audit["secondary_audit_recorded"] = False
        audit["secondary_audit_error_type"] = type(exc).__name__
    return {
        "operation": operation,
        "success": invocation["success"],
        "failed_phase": None if invocation["success"] else "action",
        "typed_builtin": True,
        "effect": plan["effect"],
        "check_evidence": check_evidence,
        "consumed_check_evidence": consumed_check_evidence,
        "results": [{
            "phase": "action",
            "target": "local",
            "typed_action": invocation["action"],
            "outcome": invocation,
        }],
        "rollback": {"attempted": False, "success": True, "reason": plan["rollback"]},
        "audit": audit,
    }


def _blockade_authority_harden_operation_plan(
    parameters: dict[str, str] | None,
) -> dict[str, Any]:
    supplied = parameters or {}
    if not isinstance(supplied, dict) or supplied:
        raise ValueError("blockade authority hardening accepts no parameters")
    return {
        "name": BLOCKADE_AUTHORITY_HARDEN_OPERATION,
        "description": (
            "Converge only the canonical root-owned Grabowski blockade authority "
            "directory from historical mode 0715 to production mode 0711."
        ),
        "parameter_names": [],
        "parameters_sha256": _hash({}),
        "typed_builtin": True,
        "execution": "operator-mainpid-direct-blockade-lifecycle",
        "privileged_action": privileged.BLOCKADE_LIFECYCLE_ACTION,
        "effect": "authority_mode_write",
        "rollback": (
            "no automatic rollback to the weaker 0715 mode; exact post-state "
            "readback classifies applied, not-applied or unknown"
        ),
    }


def _blockade_authority_state() -> dict[str, Any]:
    if base.KILL_SWITCH_PATH != base.CANONICAL_KILL_SWITCH_PATH:
        raise PermissionError(
            "blockade authority hardening requires the canonical marker path"
        )
    authority_uid, marker_mode, require_private = base._canonical_marker_contract()
    if (
        authority_uid != 0
        or marker_mode != blockade_authority.MARKER_MODE
        or require_private
    ):
        raise PermissionError("canonical blockade marker contract is not root-owned")
    directory = base.KILL_SWITCH_PATH.parent
    metadata = directory.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & 0o022
        or mode
        not in {
            blockade_authority.LEGACY_MARKER_DIRECTORY_MODE,
            blockade_authority.MARKER_DIRECTORY_MODE,
        }
    ):
        raise PermissionError(
            "canonical blockade authority directory preimage is invalid"
        )
    snapshot = blockade_authority.read_authority_marker(
        base.KILL_SWITCH_PATH,
        authority_uid=authority_uid,
    )
    return {
        "directory_path": str(directory),
        "mode": mode,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "record_sha256": snapshot.record_sha256,
        "marker_file_sha256": snapshot.file_sha256,
    }


def _run_blockade_authority_harden_operation(
    parameters: dict[str, str] | None,
) -> dict[str, Any]:
    plan = _blockade_authority_harden_operation_plan(parameters)
    operator._require_operator_capability("privileged_reference")
    operator._require_operator_mutation("terminal_execute", opaque_command=False)
    before = _blockade_authority_state()
    invocation_error_type: str | None = None
    readback_error_type: str | None = None
    if before["mode"] == blockade_authority.MARKER_DIRECTORY_MODE:
        invocation = None
        after = dict(before)
        reconciliation = "already_hardened"
        success = True
    else:
        payload = {
            "operation": "harden-authority",
            "transaction_id": uuid.uuid4().hex,
            "expected_record_sha256": before["record_sha256"],
            "expected_marker_file_sha256": before["marker_file_sha256"],
        }
        invocation = None
        try:
            invocation = privileged.run_blockade_lifecycle_reference(
                payload,
                justification=(
                    "Converge only the canonical root-owned Grabowski blockade "
                    "authority directory from exact historical mode 0715 to 0711; "
                    "preserve the exact blockade marker."
                ),
            )
        except Exception as exc:
            # The helper may fail after the root effect has committed,
            # for example while projecting its local audit. Never retry;
            # reconcile the only authorized effect from exact readback.
            invocation_error_type = type(exc).__name__
        try:
            after = _blockade_authority_state()
        except Exception as exc:
            after = None
            readback_error_type = type(exc).__name__
        if after is None:
            reconciliation = "outcome_unknown"
            success = False
        else:
            marker_unchanged = (
                after["record_sha256"] == before["record_sha256"]
                and after["marker_file_sha256"]
                == before["marker_file_sha256"]
            )
            if not marker_unchanged:
                reconciliation = "outcome_unknown"
                success = False
            elif after["mode"] == blockade_authority.MARKER_DIRECTORY_MODE:
                reconciliation = "effect_applied"
                success = True
            elif after["mode"] == blockade_authority.LEGACY_MARKER_DIRECTORY_MODE:
                reconciliation = "effect_not_applied"
                success = False
            else:
                reconciliation = "outcome_unknown"
                success = False

    audit = {
        "timestamp_unix": int(time.time()),
        "operation": "named-operation-run",
        "recipe": BLOCKADE_AUTHORITY_HARDEN_OPERATION,
        "parameters_sha256": plan["parameters_sha256"],
        "success": success,
        "effect": plan["effect"],
        "before_mode": format(before["mode"], "04o"),
        "after_mode": (
            format(after["mode"], "04o") if isinstance(after, dict) else None
        ),
        "record_sha256": (
            after.get("record_sha256") if isinstance(after, dict) else None
        ),
        "marker_file_sha256": (
            after.get("marker_file_sha256") if isinstance(after, dict) else None
        ),
        "reconciliation": reconciliation,
        "root_request_id": (
            invocation.get("request_id") if isinstance(invocation, dict) else None
        ),
        "root_reference_sha256": (
            invocation.get("reference_sha256")
            if isinstance(invocation, dict)
            else None
        ),
        "root_outcome": (
            invocation.get("outcome") if isinstance(invocation, dict) else None
        ),
        "root_invocation_error_type": invocation_error_type,
        "post_readback_error_type": readback_error_type,
    }
    try:
        base._append_audit(audit)
        audit["secondary_audit_recorded"] = True
    except Exception as exc:
        audit["secondary_audit_recorded"] = False
        audit["secondary_audit_error_type"] = type(exc).__name__
    return {
        "operation": BLOCKADE_AUTHORITY_HARDEN_OPERATION,
        "success": success,
        "failed_phase": None if success else "action",
        "typed_builtin": True,
        "effect": plan["effect"],
        "reconciliation": reconciliation,
        "before": before,
        "after": after,
        "root_invocation": invocation,
        "root_invocation_error_type": invocation_error_type,
        "post_readback_error_type": readback_error_type,
        "rollback": {
            "attempted": False,
            "success": True,
            "reason": plan["rollback"],
        },
        "audit": audit,
        "retry_performed": False,
    }


def _run_fleet_registry_mutation(parameters: dict[str, str] | None) -> dict[str, Any]:
    plan = fleet_mutation.plan_registry_mutation(parameters)
    public = plan["public"]
    parameters_sha256 = _hash(parameters or {})
    operator._require_operator_mutation(
        "terminal_execute",
        opaque_command=False,
    )
    try:
        outcome = fleet_mutation.execute_registry_mutation(plan)
    except Exception as exc:
        audit = {
            "timestamp_unix": int(time.time()),
            "operation": "named-operation-run",
            "recipe": FLEET_MUTATION_OPERATION,
            "parameters_sha256": parameters_sha256,
            "success": False,
            "failed_phase": "action",
            "rollback_attempted": False,
            "rollback_success": False,
            "fleet_host": public["host"],
            "registry_before_sha256": public["expected_registry_sha256"],
            "error_type": type(exc).__name__,
        }
        _append_fleet_mutation_audit(audit)
        raise
    receipt = outcome["receipt"]
    success = bool(outcome["success"])
    rollback = receipt.get("rollback", {})
    audit = {
        "timestamp_unix": int(time.time()),
        "operation": "named-operation-run",
        "recipe": FLEET_MUTATION_OPERATION,
        "parameters_sha256": parameters_sha256,
        "success": success,
        "failed_phase": None if success else "action",
        "rollback_attempted": bool(rollback.get("attempted")),
        "rollback_success": bool(rollback.get("success")),
        "fleet_host": public["host"],
        "registry_before_sha256": receipt.get("before_registry_sha256"),
        "registry_after_sha256": receipt.get("after_registry_sha256"),
        "receipt_path": receipt.get("receipt_path"),
        "readback_ok": bool(receipt.get("readback", {}).get("ok")),
    }
    audit = _append_fleet_mutation_audit(audit)
    return {
        "operation": FLEET_MUTATION_OPERATION,
        "success": success,
        "failed_phase": None if success else "action",
        "results": [{
            "phase": "action",
            "target": "local",
            "typed_action": FLEET_MUTATION_OPERATION,
            "outcome": outcome,
        }],
        "rollback": {
            "attempted": bool(rollback.get("attempted")),
            "success": bool(rollback.get("success")),
            "receipt_path": receipt.get("receipt_path"),
        },
        "audit": audit,
    }


def _maulwurf_recovery_operation_catalog() -> dict[str, dict[str, Any]]:
    return {
        MAULWURF_RECOVERY_STATUS_OPERATION: {
            "description": "Read the local Maulwurf NORMAL/RECOVERY mode.",
            "parameters": [],
            "step_count": 1,
            "typed_builtin": True,
            "effect": "read_only",
        },
        MAULWURF_RECOVERY_ON_OPERATION: {
            "description": "Enable local Maulwurf recovery mutations.",
            "parameters": ["reason"],
            "step_count": 1,
            "typed_builtin": True,
            "effect": "recovery_mode_write",
        },
        MAULWURF_RECOVERY_OFF_OPERATION: {
            "description": "Return the Maulwurf to NORMAL read-only mode.",
            "parameters": [],
            "step_count": 1,
            "typed_builtin": True,
            "effect": "recovery_mode_write",
        },
    }


def _maulwurf_recovery_operation_list() -> dict[str, Any]:
    if not operator._maulwurf_runtime_active():
        raise PermissionError("Maulwurf recovery operation listing is unavailable")
    operator._require_operator_capability("maulwurf_recovery_control")
    return {
        "path": str(OPERATIONS_CONFIG),
        "operations": _maulwurf_recovery_operation_catalog(),
    }


@mcp.tool(name="grabowski_operation_list", annotations=READ_ONLY)
def grabowski_operation_list() -> dict[str, Any]:
    """List validated named operations."""
    try:
        operator._require_operator_capability("terminal_execute")
    except PermissionError:
        return _maulwurf_recovery_operation_list()
    raw = _load()
    shadowed = RESERVED_TYPED_OPERATIONS.intersection(raw["operations"])
    if shadowed:
        raise ValueError(
            "Operations registry shadows reserved typed operation: "
            + ", ".join(sorted(shadowed))
        )
    operations = {}
    for name in sorted(raw["operations"]):
        operation = _validated(name)
        operations[name] = {"description": operation["description"],
                            "parameters": sorted(operation["parameters"]),
                            "step_count": len(operation["steps"])}
    operations[FLEET_MUTATION_OPERATION] = {
        "description": "Atomically mutate one validated Fleet host with CAS, receipt and readback.",
        "parameters": [
            "operation",
            "host",
            "expected_registry_sha256",
            "host_spec_json (add/update only)",
        ],
        "step_count": 1,
        "typed_builtin": True,
    }
    operations[ROOTBROKER_AUTHORITY_REFRESH_OPERATION] = {
        "description": _rootbroker_authority_refresh_plan({"expected_head": "0" * 40})["description"],
        "parameters": ["expected_head"],
        "step_count": 1,
        "typed_builtin": True,
        "effect": "authority_contract_refresh",
    }
    operations[PLATFORM_CONNECTOR_CAPTURE_OPERATION] = {
        "description": _platform_connector_capture_plan({
            "observed_artifact_path": "/home/alex/worktrees/.grabowski-platform-observed-" + "0" * 64 + ".json",
            "expected_artifact_sha256": "0" * 64,
            "source_reference": "chatgpt-tool-catalog:preview",
            "observation_scope": "connector_catalog",
            "observation_id": "preview",
            "publication_request_id": "preview",
            "requested_contract_sha256": "0" * 64,
            "observed_at_unix": "0",
        })["description"],
        "parameters": sorted(_platform_connector_capture_plan({
            "observed_artifact_path": "/home/alex/worktrees/.grabowski-platform-observed-" + "0" * 64 + ".json",
            "expected_artifact_sha256": "0" * 64,
            "source_reference": "chatgpt-tool-catalog:preview",
            "observation_scope": "connector_catalog",
            "observation_id": "preview",
            "publication_request_id": "preview",
            "requested_contract_sha256": "0" * 64,
            "observed_at_unix": "0",
        })["parameter_names"]),
        "step_count": 1,
        "typed_builtin": True,
        "effect": "platform_observation_publish_and_reconcile",
    }
    operations[BLOCKADE_AUTHORITY_HARDEN_OPERATION] = {
        "description": _blockade_authority_harden_operation_plan(None)["description"],
        "parameters": [],
        "step_count": 1,
        "typed_builtin": True,
        "effect": "authority_mode_write",
    }
    if operator._maulwurf_runtime_active():
        operations.update(_maulwurf_recovery_operation_catalog())
    for name, spec in BACKUP_STORAGE_TYPED_OPERATIONS.items():
        operations[name] = {
            "description": spec["description"],
            "parameters": list(spec["parameters"]),
            "step_count": 1,
            "typed_builtin": True,
            "effect": spec["effect"],
        }
    return {"path": str(OPERATIONS_CONFIG), "operations": operations}


@mcp.tool(name="grabowski_operation_plan", annotations=READ_ONLY)
def grabowski_operation_plan(operation: str,
                              parameters: dict[str, str] | None = None) -> dict[str, Any]:
    """Render one operation and its rollback path without executing it."""
    if operation in MAULWURF_RECOVERY_TYPED_OPERATIONS:
        return _maulwurf_recovery_operation_plan(operation, parameters)
    operator._require_operator_capability("terminal_execute")
    if operation == FLEET_MUTATION_OPERATION:
        return fleet_mutation.plan_registry_mutation(parameters)["public"]
    if operation == BLOCKADE_AUTHORITY_HARDEN_OPERATION:
        return _blockade_authority_harden_operation_plan(parameters)
    if operation == ROOTBROKER_AUTHORITY_REFRESH_OPERATION:
        return _rootbroker_authority_refresh_plan(parameters)
    if operation == PLATFORM_CONNECTOR_CAPTURE_OPERATION:
        return _platform_connector_capture_plan(parameters)
    if operation in BACKUP_STORAGE_TYPED_OPERATIONS:
        return _backup_storage_operation_plan(operation, parameters)
    return _render(operation, parameters)


@mcp.tool(name="grabowski_operation_run", annotations=MUTATING)
def grabowski_operation_run(operation: str,
                             parameters: dict[str, str] | None = None) -> dict[str, Any]:
    """Run preflight, action and postflight, then rollback after a failure."""
    if operation == FLEET_MUTATION_OPERATION:
        return _run_fleet_registry_mutation(parameters)
    if operation == BLOCKADE_AUTHORITY_HARDEN_OPERATION:
        return _run_blockade_authority_harden_operation(parameters)
    if operation == ROOTBROKER_AUTHORITY_REFRESH_OPERATION:
        return _run_rootbroker_authority_refresh_operation(parameters)
    if operation == PLATFORM_CONNECTOR_CAPTURE_OPERATION:
        return _run_platform_connector_capture_operation(parameters)
    if operation in MAULWURF_RECOVERY_TYPED_OPERATIONS:
        return _run_maulwurf_recovery_operation(operation, parameters)
    if operation in BACKUP_STORAGE_TYPED_OPERATIONS:
        return _run_backup_storage_operation(operation, parameters)
    plan = _render(operation, parameters)
    for target in sorted({step["target"] for step in plan["steps"]}):
        operator._require_operator_mutation(
            "terminal_execute",
            host=(target if target != "local" else None),
            opaque_command=True,
        )
    forward = [step for step in plan["steps"] if step["phase"] != "rollback"]
    rollback = [step for step in plan["steps"] if step["phase"] == "rollback"]
    results = []
    failed_phase = None
    action_started = False
    for step in forward:
        action_started = action_started or step["phase"] == "action"
        outcome = _run_step(step)
        results.append({"phase": step["phase"], "target": step["target"],
                        "argv": step["argv"], "allow_failure": step["allow_failure"],
                        "outcome": outcome})
        if outcome["result"]["returncode"] != 0 and not step["allow_failure"]:
            failed_phase = step["phase"]
            break
    rollback_results = []
    if failed_phase and action_started:
        for step in reversed(rollback):
            outcome = _run_step(step)
            rollback_results.append({"target": step["target"], "argv": step["argv"],
                                     "allow_failure": step["allow_failure"],
                                     "outcome": outcome})
    rollback_ok = all(item["allow_failure"] or item["outcome"]["result"]["returncode"] == 0
                      for item in rollback_results)
    audit = {"timestamp_unix": int(time.time()), "operation": "named-operation-run",
             "recipe": plan["name"], "parameters_sha256": plan["parameters_sha256"],
             "success": failed_phase is None, "failed_phase": failed_phase,
             "rollback_attempted": bool(rollback_results), "rollback_success": rollback_ok}
    base._append_audit(audit)
    return {"operation": plan["name"], "success": failed_phase is None,
            "failed_phase": failed_phase, "results": results,
            "rollback": {"attempted": bool(rollback_results), "success": rollback_ok,
                         "results": rollback_results}, "audit": audit}

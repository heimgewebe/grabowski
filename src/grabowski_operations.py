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
BACKUP_NTFS_TYPED_OPERATIONS = {
    BACKUP_NTFS_CHECK_OPERATION: {
        "description": "Run the fixed root-read-only ntfsfix check for the configured BACKUP volume.",
        "action": "local_backup_ntfs_check",
        "target": "check",
        "effect": "read_only",
    },
    BACKUP_NTFS_CLEAR_DIRTY_OPERATION: {
        "description": "Clear only the dirty flag on the fixed configured BACKUP volume after separate check evidence.",
        "action": "local_backup_ntfs_clear_dirty",
        "target": "clear-dirty",
        "effect": "filesystem_metadata_write",
    },
}
RESERVED_TYPED_OPERATIONS = frozenset({FLEET_MUTATION_OPERATION, *BACKUP_NTFS_TYPED_OPERATIONS})
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


def _backup_ntfs_operation_plan(
    operation: str, parameters: dict[str, str] | None
) -> dict[str, Any]:
    if operation not in BACKUP_NTFS_TYPED_OPERATIONS:
        raise ValueError(f"Unknown typed BACKUP NTFS operation: {operation}")
    supplied = parameters or {}
    if not isinstance(supplied, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in supplied.items()
    ):
        raise ValueError("parameters must be an object of strings")
    expected_parameters = (
        set()
        if operation == BACKUP_NTFS_CHECK_OPERATION
        else {"check_response_sha256"}
    )
    if set(supplied) != expected_parameters:
        raise ValueError(
            f"Operation {operation} parameter mismatch; "
            f"missing={sorted(expected_parameters - set(supplied))}, "
            f"unknown={sorted(set(supplied) - expected_parameters)}"
        )
    if supplied and re.fullmatch(r"[0-9a-f]{64}", supplied["check_response_sha256"]) is None:
        raise ValueError("check_response_sha256 is invalid")
    spec = BACKUP_NTFS_TYPED_OPERATIONS[operation]
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
        "rollback": "none; the check is read-only and clear-dirty is separately operator-gated",
    }


def _invoke_mainpid_privileged_action(
    *, action: str, target: str, justification: str, timeout_seconds: int = 120
) -> dict[str, Any]:
    allowed = {
        (str(spec["action"]), str(spec["target"]))
        for spec in BACKUP_NTFS_TYPED_OPERATIONS.values()
    }
    if (action, target) not in allowed:
        raise ValueError("MainPID privileged action is outside the BACKUP NTFS allowlist")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 120:
        raise ValueError("BACKUP NTFS privileged timeout is invalid")
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


def _run_backup_ntfs_operation(
    operation: str, parameters: dict[str, str] | None
) -> dict[str, Any]:
    plan = _backup_ntfs_operation_plan(operation, parameters)
    consumed_check_evidence = (
        _consume_backup_ntfs_check_evidence(parameters)
        if operation == BACKUP_NTFS_CLEAR_DIRTY_OPERATION
        else None
    )
    operator._require_operator_capability("privileged_reference")
    operator._require_operator_mutation("terminal_execute", opaque_command=False)
    justification = (
        "Root-read-only ntfsfix check for the exact configured BACKUP volume before any filesystem metadata mutation."
        if operation == BACKUP_NTFS_CHECK_OPERATION
        else "Clear only the NTFS dirty flag on the exact configured BACKUP volume after separate root check evidence; no force mount."
    )
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


@mcp.tool(name="grabowski_operation_list", annotations=READ_ONLY)
def grabowski_operation_list() -> dict[str, Any]:
    """List validated named operations."""
    operator._require_operator_capability("terminal_execute")
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
    for name, spec in BACKUP_NTFS_TYPED_OPERATIONS.items():
        operations[name] = {
            "description": spec["description"],
            "parameters": (
                []
                if name == BACKUP_NTFS_CHECK_OPERATION
                else ["check_response_sha256"]
            ),
            "step_count": 1,
            "typed_builtin": True,
            "effect": spec["effect"],
        }
    return {"path": str(OPERATIONS_CONFIG), "operations": operations}


@mcp.tool(name="grabowski_operation_plan", annotations=READ_ONLY)
def grabowski_operation_plan(operation: str,
                              parameters: dict[str, str] | None = None) -> dict[str, Any]:
    """Render one operation and its rollback path without executing it."""
    operator._require_operator_capability("terminal_execute")
    if operation == FLEET_MUTATION_OPERATION:
        return fleet_mutation.plan_registry_mutation(parameters)["public"]
    if operation in BACKUP_NTFS_TYPED_OPERATIONS:
        return _backup_ntfs_operation_plan(operation, parameters)
    return _render(operation, parameters)


@mcp.tool(name="grabowski_operation_run", annotations=MUTATING)
def grabowski_operation_run(operation: str,
                             parameters: dict[str, str] | None = None) -> dict[str, Any]:
    """Run preflight, action and postflight, then rollback after a failure."""
    if operation == FLEET_MUTATION_OPERATION:
        return _run_fleet_registry_mutation(parameters)
    if operation in BACKUP_NTFS_TYPED_OPERATIONS:
        return _run_backup_ntfs_operation(operation, parameters)
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

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

import grabowski_fleet as fleet
import grabowski_mcp as base
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


@mcp.tool(name="grabowski_operation_list", annotations=READ_ONLY)
def grabowski_operation_list() -> dict[str, Any]:
    """List validated named operations."""
    operator._require_operator_capability("terminal_execute")
    raw = _load()
    operations = {}
    for name in sorted(raw["operations"]):
        operation = _validated(name)
        operations[name] = {"description": operation["description"],
                            "parameters": sorted(operation["parameters"]),
                            "step_count": len(operation["steps"])}
    return {"path": str(OPERATIONS_CONFIG), "operations": operations}


@mcp.tool(name="grabowski_operation_plan", annotations=READ_ONLY)
def grabowski_operation_plan(operation: str,
                              parameters: dict[str, str] | None = None) -> dict[str, Any]:
    """Render one operation and its rollback path without executing it."""
    operator._require_operator_capability("terminal_execute")
    return _render(operation, parameters)


@mcp.tool(name="grabowski_operation_run", annotations=MUTATING)
def grabowski_operation_run(operation: str,
                             parameters: dict[str, str] | None = None) -> dict[str, Any]:
    """Run preflight, action and postflight, then rollback after a failure."""
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

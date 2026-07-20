from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "tool-surface-budget.v1.json"
SCHEMA_PATH = ROOT / "contracts" / "tool-surface-budget.v1.schema.json"
RUNTIME_ENTRYPOINT_PATH = ROOT / "config" / "runtime-entrypoint.json"
CAPABILITY_CATALOG_PATH = ROOT / "contracts" / "capability-catalog.v1.json"
OPERATIONS_CATALOG_PATH = ROOT / "config" / "operations.example.json"
OPERATION_METADATA_PATH = ROOT / "contracts" / "operation-catalog.v1.json"
SCHEMA_VERSION = 1
CONTRACT_ID = "grabowski-tool-surface-budget-v1"
BASELINE_TOOL_COUNT = 125
BASELINE_TOOL_NAMES_SHA256 = "a84638ec397aa635aa55546d579f009c237f64ffed39eafe2bff525762f46418"
BASELINE_TOOL_SEMANTICS_SHA256 = "29683f3dd745a9045bd4410b535abaa533a5ddc8aa7e177b72a60a5952a4e2f1"
TOOL_SURFACE_SCHEMA_SHA256 = (
    "44e47b96f6adc2d0015dfdf9fd65db18f05d150c1bf7436297e7d1247121f534"
)
ADDITION_KINDS = frozenset(
    {
        "distinct_authority_boundary",
        "material_call_shape",
        "measured_selection_advantage",
    }
)
TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
TOOL = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
OPERATION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class ToolSurfaceBudgetError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _load_json(path: Path, *, max_bytes: int = 4_000_000) -> dict[str, Any]:
    if path.is_symlink():
        raise ToolSurfaceBudgetError(f"contract path may not be a symlink: {path}")
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ToolSurfaceBudgetError(f"contract exceeds byte limit: {path}")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolSurfaceBudgetError(f"invalid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ToolSurfaceBudgetError(f"top-level value must be an object: {path}")
    return value


def _text(value: Any, *, label: str, minimum: int = 1, maximum: int = 4096) -> str:
    if not isinstance(value, str):
        raise ToolSurfaceBudgetError(f"{label} must be text")
    text = value.strip()
    if len(text) < minimum or len(text.encode("utf-8")) > maximum or "\x00" in text:
        raise ToolSurfaceBudgetError(f"{label} is empty, too short, too large or contains NUL")
    return text


def _tool_name(value: Any, *, label: str = "tool") -> str:
    text = _text(value, label=label, maximum=128)
    if TOOL.fullmatch(text) is None:
        raise ToolSurfaceBudgetError(f"{label} has invalid characters")
    return text


def _token(value: Any, *, label: str) -> str:
    text = _text(value, label=label, maximum=64)
    if TOKEN.fullmatch(text) is None:
        raise ToolSurfaceBudgetError(f"{label} must be a lowercase token")
    return text


def _operation_name(value: Any, *, label: str = "operation") -> str:
    text = _text(value, label=label, maximum=64)
    if OPERATION_NAME.fullmatch(text) is None:
        raise ToolSurfaceBudgetError(f"{label} has invalid characters")
    return text


def _string_list(value: Any, *, label: str, maximum: int = 128) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ToolSurfaceBudgetError(f"{label} must be a bounded list")
    result = sorted({_text(item, label=f"{label} entry", maximum=512) for item in value})
    if len(result) != len(value):
        raise ToolSurfaceBudgetError(f"{label} must be unique and sorted")
    return result


def _authority_class(capability: Mapping[str, Any]) -> str:
    tool = str(capability.get("tool", ""))
    category = str(capability.get("category", ""))
    effects = {str(item) for item in capability.get("effects", []) if isinstance(item, str)}
    reversibility = str(capability.get("reversibility", ""))
    if category == "secret":
        return "secret"
    if category in {"privileged", "power"} or tool == "grabowski_power_run":
        return "privileged"
    if "process-signal" in effects or tool == "grabowski_process_signal":
        return "process-control"
    if category in {"deployment", "deploy"} or "deployment" in tool:
        return "deployment"
    if "delete" in tool or reversibility == "irreversible":
        return "destructive"
    if bool(capability.get("read_only")):
        return "read"
    return "mutation"


def capability_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "tool",
        "category",
        "effects",
        "read_only",
        "reversibility",
        "risk_class",
    }
    missing = sorted(required - set(value))
    if missing:
        raise ToolSurfaceBudgetError(f"capability declaration missing fields: {missing}")
    tool = _tool_name(value["tool"])
    category = _token(value["category"], label=f"{tool}.category")
    risk = _token(value["risk_class"], label=f"{tool}.risk_class")
    reversibility = _text(value["reversibility"], label=f"{tool}.reversibility", maximum=128)
    effects = _string_list(value["effects"], label=f"{tool}.effects")
    read_only = value["read_only"]
    if read_only is not None and not isinstance(read_only, bool):
        raise ToolSurfaceBudgetError(f"{tool}.read_only must be boolean or null")
    return {
        "tool": tool,
        "category": category,
        "authority_class": _authority_class(value),
        "risk_class": risk,
        "read_only": read_only,
        "effects": effects,
        "reversibility": reversibility,
    }


def _runtime_tools(payload: Mapping[str, Any]) -> list[str]:
    schema_version = payload.get("schema_version")
    if schema_version not in {2, 3}:
        raise ToolSurfaceBudgetError(
            "runtime entrypoint must use schema_version 2 or 3"
        )
    runtime_assets = payload.get("runtime_assets", [])
    if schema_version == 2 and runtime_assets:
        raise ToolSurfaceBudgetError("runtime_assets requires schema_version 3")
    if not isinstance(runtime_assets, list):
        raise ToolSurfaceBudgetError("runtime_assets must be a list")
    for index, item in enumerate(runtime_assets):
        if not isinstance(item, dict) or set(item) != {"source", "destination"}:
            raise ToolSurfaceBudgetError(
                f"runtime_assets[{index}] must declare source and destination"
            )
        _text(
            item.get("source"),
            label=f"runtime_assets[{index}].source",
            maximum=500,
        )
        _text(
            item.get("destination"),
            label=f"runtime_assets[{index}].destination",
            maximum=500,
        )
    raw = payload.get("expected_tools")
    if not isinstance(raw, list):
        raise ToolSurfaceBudgetError("runtime expected_tools must be a list")
    tools = [_tool_name(item, label="runtime tool") for item in raw]
    if len(tools) != len(set(tools)):
        raise ToolSurfaceBudgetError("runtime expected_tools contains duplicates")
    return sorted(tools)


def _capabilities(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if payload.get("schema_version") != 1 or not isinstance(payload.get("tools"), list):
        raise ToolSurfaceBudgetError("capability catalog must use schema_version 1")
    result: dict[str, dict[str, Any]] = {}
    for raw in payload["tools"]:
        if not isinstance(raw, dict):
            raise ToolSurfaceBudgetError("capability entries must be objects")
        projected = capability_projection(raw)
        tool = projected["tool"]
        if tool in result:
            raise ToolSurfaceBudgetError(f"duplicate capability declaration: {tool}")
        result[tool] = projected
    return result


def _operation_projection(
    name: str,
    value: Mapping[str, Any],
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    operation = _operation_name(name, label="operation name")
    if set(value) != {"description", "parameters", "steps"}:
        raise ToolSurfaceBudgetError(f"{operation} has invalid operation keys")
    if set(metadata) != {"execution_authorities", "effects", "reversibility"}:
        raise ToolSurfaceBudgetError(f"{operation} has invalid metadata keys")
    description = _text(
        value.get("description"), label=f"{operation}.description", minimum=12
    )
    parameters = value.get("parameters")
    steps = value.get("steps")
    if not isinstance(parameters, dict) or not isinstance(steps, list) or not steps:
        raise ToolSurfaceBudgetError(f"{operation} requires typed parameters and steps")
    parameter_names = sorted(parameters)
    for parameter_name, pattern in parameters.items():
        _text(parameter_name, label=f"{operation}.parameter", maximum=64)
        expression = _text(
            pattern, label=f"{operation}.{parameter_name}.pattern", maximum=500
        )
        try:
            re.compile(expression)
        except re.error as exc:
            raise ToolSurfaceBudgetError(
                f"{operation}.{parameter_name} has invalid regex"
            ) from exc
    phases: list[str] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ToolSurfaceBudgetError(f"{operation}.steps[{index}] must be an object")
        required = {"phase", "target", "argv"}
        optional = {"timeout_seconds", "allow_failure"}
        if required - set(step) or set(step) - required - optional:
            raise ToolSurfaceBudgetError(f"{operation}.steps[{index}] has invalid keys")
        phase = _text(
            step.get("phase"), label=f"{operation}.steps[{index}].phase", maximum=32
        )
        if phase not in {"preflight", "action", "postflight", "rollback"}:
            raise ToolSurfaceBudgetError(f"{operation}.steps[{index}] has invalid phase")
        phases.append(phase)
    if "action" not in phases:
        raise ToolSurfaceBudgetError(f"{operation} requires an action phase")
    execution_authorities = _string_list(
        metadata.get("execution_authorities"),
        label=f"{operation}.execution_authorities",
    )
    if not execution_authorities:
        raise ToolSurfaceBudgetError(
            f"{operation}.execution_authorities may not be empty"
        )
    effects = _string_list(metadata.get("effects"), label=f"{operation}.effects")
    if not effects:
        raise ToolSurfaceBudgetError(f"{operation}.effects may not be empty")
    reversibility = _text(
        metadata.get("reversibility"),
        label=f"{operation}.reversibility",
        maximum=128,
    )
    return {
        "operation": operation,
        "description": description,
        "execution_authorities": execution_authorities,
        "effects": effects,
        "reversibility": reversibility,
        "parameter_names": parameter_names,
        "phases": phases,
    }


def _operations(
    payload: Mapping[str, Any], metadata_payload: Mapping[str, Any]
) -> tuple[int, dict[str, dict[str, Any]]]:
    raw = payload.get("operations")
    if payload.get("schema_version") != 1 or not isinstance(raw, dict):
        raise ToolSurfaceBudgetError("runtime operation catalog must use schema_version 1")
    metadata_raw = metadata_payload.get("operations")
    if (
        set(metadata_payload) != {"schema_version", "source", "operations"}
        or metadata_payload.get("schema_version") != 1
        or metadata_payload.get("source")
        != str(OPERATIONS_CATALOG_PATH.relative_to(ROOT))
        or not isinstance(metadata_raw, dict)
    ):
        raise ToolSurfaceBudgetError("operation metadata contract is invalid")
    if set(raw) != set(metadata_raw):
        raise ToolSurfaceBudgetError(
            "operation catalog and metadata names differ; "
            f"missing_metadata={sorted(set(raw)-set(metadata_raw))} "
            f"orphan_metadata={sorted(set(metadata_raw)-set(raw))}"
        )
    result: dict[str, dict[str, Any]] = {}
    for name in sorted(raw):
        value = raw[name]
        metadata = metadata_raw[name]
        if not isinstance(name, str) or not isinstance(value, dict) or not isinstance(metadata, dict):
            raise ToolSurfaceBudgetError("operation entries must be named objects")
        projected = _operation_projection(name, value, metadata)
        result[projected["operation"]] = projected
    return 1, result


def _baseline_from_capabilities(
    runtime_tools: list[str], capabilities: Mapping[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    missing = sorted(set(runtime_tools) - set(capabilities))
    if missing:
        raise ToolSurfaceBudgetError(f"runtime tools missing capability declarations: {missing}")
    return [copy.deepcopy(capabilities[name]) for name in runtime_tools]


def build_initial_contract(
    runtime_payload: Mapping[str, Any],
    capability_payload: Mapping[str, Any],
    operations_payload: Mapping[str, Any],
    operation_metadata_payload: Mapping[str, Any],
) -> dict[str, Any]:
    runtime_tools = _runtime_tools(runtime_payload)
    capabilities = _capabilities(capability_payload)
    baseline = _baseline_from_capabilities(runtime_tools, capabilities)
    if (
        len(baseline) != BASELINE_TOOL_COUNT
        or _sha256(runtime_tools) != BASELINE_TOOL_NAMES_SHA256
        or _sha256(baseline) != BASELINE_TOOL_SEMANTICS_SHA256
    ):
        raise ToolSurfaceBudgetError(
            "initial baseline does not match the code-bound historical anchor"
        )
    operation_schema, operations = _operations(
        operations_payload, operation_metadata_payload
    )
    operation_values = [operations[name] for name in sorted(operations)]
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_id": CONTRACT_ID,
        "sources": {
            "runtime_entrypoint": str(RUNTIME_ENTRYPOINT_PATH.relative_to(ROOT)),
            "capability_catalog": str(CAPABILITY_CATALOG_PATH.relative_to(ROOT)),
            "operation_catalog": str(OPERATIONS_CATALOG_PATH.relative_to(ROOT)),
            "operation_metadata": str(OPERATION_METADATA_PATH.relative_to(ROOT)),
        },
        "baseline": {
            "tool_count": len(baseline),
            "tool_names_sha256": _sha256(runtime_tools),
            "tool_semantics_sha256": _sha256(baseline),
            "tools": baseline,
        },
        "accepted_additions": {},
        "retired_tools": {},
        "operation_catalog": {
            "schema_version": operation_schema,
            "operation_count": len(operation_values),
            "operations_sha256": _sha256(operation_values),
            "operations": operation_values,
        },
        "policy": {
            "accepted_addition_kinds": sorted(ADDITION_KINDS),
            "legacy_baseline_is_closed": True,
            "fixed_tool_cap": None,
            "default_route": "typed-operation",
            "security_boundaries_may_remain_tools": True,
        },
        "migration_candidates": [],
        "does_not_establish": [
            "smaller_tool_count_is_always_better",
            "client_tool_choice_improvement_without_measurement",
            "permission_to_collapse_distinct_security_boundaries",
            "runtime_client_snapshot_observability",
        ],
    }


def _validate_sources(contract: Mapping[str, Any]) -> None:
    expected = {
        "runtime_entrypoint": str(RUNTIME_ENTRYPOINT_PATH.relative_to(ROOT)),
        "capability_catalog": str(CAPABILITY_CATALOG_PATH.relative_to(ROOT)),
        "operation_catalog": str(OPERATIONS_CATALOG_PATH.relative_to(ROOT)),
        "operation_metadata": str(OPERATION_METADATA_PATH.relative_to(ROOT)),
    }
    if contract.get("sources") != expected:
        raise ToolSurfaceBudgetError("contract source paths do not match canonical repository paths")


def _validate_addition(name: str, value: Any, capability: Mapping[str, Any]) -> dict[str, Any]:
    tool = _tool_name(name, label="accepted addition")
    if not isinstance(value, dict):
        raise ToolSurfaceBudgetError(f"accepted addition {tool} must be an object")
    required = {
        "tool_contract",
        "justification_kind",
        "rationale",
        "evidence_refs",
        "operation_alternative_considered",
        "exception_detail",
    }
    if set(value) != required:
        raise ToolSurfaceBudgetError(
            f"accepted addition {tool} keys invalid; missing={sorted(required-set(value))} extra={sorted(set(value)-required)}"
        )
    projected = capability_projection(capability)
    if value["tool_contract"] != projected:
        raise ToolSurfaceBudgetError(f"accepted addition {tool} capability projection drift")
    kind = _text(
        value["justification_kind"],
        label=f"{tool}.justification_kind",
        maximum=64,
    )
    if kind not in ADDITION_KINDS:
        raise ToolSurfaceBudgetError(f"accepted addition {tool} uses unsupported justification {kind}")
    _text(value["rationale"], label=f"{tool}.rationale", minimum=24)
    refs = _string_list(value["evidence_refs"], label=f"{tool}.evidence_refs", maximum=32)
    if not refs:
        raise ToolSurfaceBudgetError(f"accepted addition {tool} requires evidence_refs")
    _text(
        value["operation_alternative_considered"],
        label=f"{tool}.operation_alternative_considered",
        minimum=16,
    )
    detail = value["exception_detail"]
    if not isinstance(detail, dict) or set(detail) != {"claim", "evidence"}:
        raise ToolSurfaceBudgetError(f"accepted addition {tool} exception_detail is invalid")
    _text(detail["claim"], label=f"{tool}.exception_detail.claim", minimum=16)
    _text(detail["evidence"], label=f"{tool}.exception_detail.evidence", minimum=8)
    return projected


def _validate_retirement(name: str, value: Any) -> None:
    tool = _tool_name(name, label="retired tool")
    if not isinstance(value, dict) or set(value) != {"reason", "evidence_refs", "compatibility"}:
        raise ToolSurfaceBudgetError(f"retired tool {tool} metadata is invalid")
    _text(value["reason"], label=f"{tool}.reason", minimum=16)
    refs = _string_list(value["evidence_refs"], label=f"{tool}.evidence_refs", maximum=32)
    if not refs:
        raise ToolSurfaceBudgetError(f"retired tool {tool} requires evidence_refs")
    _text(value["compatibility"], label=f"{tool}.compatibility", minimum=12)


def validate_contract(
    contract: Mapping[str, Any],
    runtime_payload: Mapping[str, Any],
    capability_payload: Mapping[str, Any],
    operations_payload: Mapping[str, Any],
    operation_metadata_payload: Mapping[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        required_top = {
            "schema_version",
            "contract_id",
            "sources",
            "baseline",
            "accepted_additions",
            "retired_tools",
            "operation_catalog",
            "policy",
            "migration_candidates",
            "does_not_establish",
        }
        if set(contract) != required_top:
            raise ToolSurfaceBudgetError(
                f"top-level keys invalid; missing={sorted(required_top-set(contract))} extra={sorted(set(contract)-required_top)}"
            )
        if contract.get("schema_version") != SCHEMA_VERSION or contract.get("contract_id") != CONTRACT_ID:
            raise ToolSurfaceBudgetError("unsupported tool-surface budget contract identity")
        _validate_sources(contract)
        runtime_tools = _runtime_tools(runtime_payload)
        capabilities = _capabilities(capability_payload)
        missing_capabilities = sorted(set(runtime_tools) - set(capabilities))
        if missing_capabilities:
            raise ToolSurfaceBudgetError(
                f"runtime tools missing capability declarations: {missing_capabilities}"
            )

        baseline_raw = contract.get("baseline")
        if not isinstance(baseline_raw, dict) or set(baseline_raw) != {
            "tool_count",
            "tool_names_sha256",
            "tool_semantics_sha256",
            "tools",
        }:
            raise ToolSurfaceBudgetError("baseline structure is invalid")
        raw_tools = baseline_raw["tools"]
        if not isinstance(raw_tools, list):
            raise ToolSurfaceBudgetError("baseline.tools must be a list")
        baseline_tools: dict[str, dict[str, Any]] = {}
        for raw in raw_tools:
            if not isinstance(raw, dict):
                raise ToolSurfaceBudgetError("baseline tool entries must be objects")
            projected = capability_projection(raw)
            tool = projected["tool"]
            if projected != raw:
                raise ToolSurfaceBudgetError(f"baseline tool {tool} contains noncanonical fields")
            if tool in baseline_tools:
                raise ToolSurfaceBudgetError(f"duplicate baseline tool: {tool}")
            baseline_tools[tool] = projected
        baseline_names = sorted(baseline_tools)
        if baseline_raw["tool_count"] != len(baseline_names):
            raise ToolSurfaceBudgetError("baseline tool_count mismatch")
        if baseline_raw["tool_names_sha256"] != _sha256(baseline_names):
            raise ToolSurfaceBudgetError("baseline tool_names_sha256 mismatch")
        baseline_values = [baseline_tools[name] for name in baseline_names]
        if baseline_raw["tool_semantics_sha256"] != _sha256(baseline_values):
            raise ToolSurfaceBudgetError("baseline tool_semantics_sha256 mismatch")
        if (
            baseline_raw["tool_count"] != BASELINE_TOOL_COUNT
            or baseline_raw["tool_names_sha256"] != BASELINE_TOOL_NAMES_SHA256
            or baseline_raw["tool_semantics_sha256"]
            != BASELINE_TOOL_SEMANTICS_SHA256
        ):
            raise ToolSurfaceBudgetError(
                "baseline anchor drift: historical tools must not be grandfathered"
            )

        additions_raw = contract.get("accepted_additions")
        retirements_raw = contract.get("retired_tools")
        if not isinstance(additions_raw, dict) or not isinstance(retirements_raw, dict):
            raise ToolSurfaceBudgetError("accepted_additions and retired_tools must be objects")
        additions: dict[str, dict[str, Any]] = {}
        for name, value in additions_raw.items():
            if name in baseline_tools:
                raise ToolSurfaceBudgetError(f"baseline tool cannot be re-added: {name}")
            if name not in capabilities:
                raise ToolSurfaceBudgetError(f"accepted addition lacks capability declaration: {name}")
            additions[name] = _validate_addition(name, value, capabilities[name])
        for name, value in retirements_raw.items():
            if name not in baseline_tools:
                raise ToolSurfaceBudgetError(f"only baseline tools may be retired: {name}")
            _validate_retirement(name, value)

        expected_current = (set(baseline_tools) - set(retirements_raw)) | set(additions)
        actual_current = set(runtime_tools)
        unbudgeted = sorted(actual_current - expected_current)
        missing = sorted(expected_current - actual_current)
        if unbudgeted:
            raise ToolSurfaceBudgetError(f"unbudgeted-public-tools: {unbudgeted}")
        if missing:
            raise ToolSurfaceBudgetError(f"budgeted-tools-missing-from-runtime: {missing}")
        for name in sorted(actual_current):
            expected_projection = baseline_tools.get(name) or additions.get(name)
            if expected_projection != capabilities[name]:
                raise ToolSurfaceBudgetError(f"tool capability semantics drift: {name}")

        policy = contract.get("policy")
        if not isinstance(policy, dict) or policy.get("accepted_addition_kinds") != sorted(ADDITION_KINDS):
            raise ToolSurfaceBudgetError("policy accepted_addition_kinds drift")
        if policy.get("legacy_baseline_is_closed") is not True:
            raise ToolSurfaceBudgetError("legacy baseline must remain closed")
        if policy.get("fixed_tool_cap") is not None:
            raise ToolSurfaceBudgetError("fixed_tool_cap must remain null")
        if policy.get("default_route") != "typed-operation":
            raise ToolSurfaceBudgetError("default route must be typed-operation")
        if policy.get("security_boundaries_may_remain_tools") is not True:
            raise ToolSurfaceBudgetError("security boundary preservation must remain explicit")

        operation_schema, operations = _operations(
            operations_payload, operation_metadata_payload
        )
        operation_contract = contract.get("operation_catalog")
        if not isinstance(operation_contract, dict) or set(operation_contract) != {
            "schema_version",
            "operation_count",
            "operations_sha256",
            "operations",
        }:
            raise ToolSurfaceBudgetError("operation_catalog structure is invalid")
        operation_values = [operations[name] for name in sorted(operations)]
        if operation_contract["schema_version"] != operation_schema:
            raise ToolSurfaceBudgetError("operation catalog schema_version drift")
        if operation_contract["operation_count"] != len(operation_values):
            raise ToolSurfaceBudgetError("operation catalog count drift")
        if operation_contract["operations"] != operation_values:
            raise ToolSurfaceBudgetError("operation catalog projection drift")
        if operation_contract["operations_sha256"] != _sha256(operation_values):
            raise ToolSurfaceBudgetError("operation catalog hash drift")

        migration_candidates = contract.get("migration_candidates")
        if not isinstance(migration_candidates, list):
            raise ToolSurfaceBudgetError("migration_candidates must be a list")
        seen_candidates: set[str] = set()
        for candidate in migration_candidates:
            if not isinstance(candidate, dict) or set(candidate) != {
                "tool",
                "reason",
                "target_operation_family",
            }:
                raise ToolSurfaceBudgetError("migration candidate structure is invalid")
            tool = _tool_name(candidate["tool"], label="migration candidate tool")
            if tool not in actual_current or tool in seen_candidates:
                raise ToolSurfaceBudgetError(f"invalid migration candidate: {tool}")
            seen_candidates.add(tool)
            _text(candidate["reason"], label=f"{tool}.migration reason", minimum=16)
            _token(candidate["target_operation_family"], label=f"{tool}.target_operation_family")

        _string_list(
            contract.get("does_not_establish"),
            label="does_not_establish",
            maximum=32,
        )
        report = {
            "valid": True,
            "baseline_tool_count": len(baseline_tools),
            "current_tool_count": len(actual_current),
            "accepted_addition_count": len(additions),
            "retired_tool_count": len(retirements_raw),
            "operation_count": len(operation_values),
            "migration_candidate_count": len(migration_candidates),
            "growth": len(actual_current) - len(baseline_tools) + len(retirements_raw),
            "tool_names_sha256": _sha256(runtime_tools),
            "operation_catalog_sha256": _sha256(operation_values),
            "errors": [],
        }
        return report
    except (OSError, ToolSurfaceBudgetError) as exc:
        errors.append(str(exc))
        return {"valid": False, "errors": errors}


def _schema_location(path: tuple[str | int, ...]) -> str:
    return "/".join(str(item) for item in path) or "<root>"


def _schema_value_equal(left: Any, right: Any) -> bool:
    try:
        return _canonical_json(left) == _canonical_json(right)
    except (TypeError, ValueError):
        return False


def _schema_type_matches(value: Any, expected: str) -> bool:
    checks = {
        "array": lambda item: isinstance(item, list),
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "null": lambda item: item is None,
        "object": lambda item: isinstance(item, dict),
        "string": lambda item: isinstance(item, str),
    }
    check = checks.get(expected)
    if check is None:
        raise ToolSurfaceBudgetError(f"unsupported schema type: {expected}")
    return check(value)


def _resolve_schema_reference(
    schema: Mapping[str, Any], reference: Any
) -> Mapping[str, Any]:
    if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
        raise ToolSurfaceBudgetError("schema reference must target one local definition")
    name = reference.removeprefix("#/$defs/")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or not isinstance(definitions.get(name), dict):
        raise ToolSurfaceBudgetError(f"schema reference is unresolved: {reference}")
    return definitions[name]


def _validate_schema_value(
    value: Any,
    node: Mapping[str, Any],
    root_schema: Mapping[str, Any],
    path: tuple[str | int, ...],
) -> list[str]:
    errors: list[str] = []
    location = _schema_location(path)
    if "$ref" in node:
        if set(node) != {"$ref"}:
            return [f"schema:{location}: referenced node contains sibling keywords"]
        try:
            target = _resolve_schema_reference(root_schema, node["$ref"])
        except ToolSurfaceBudgetError as exc:
            return [f"schema:{location}: {exc}"]
        return _validate_schema_value(value, target, root_schema, path)

    if "const" in node and not _schema_value_equal(value, node["const"]):
        errors.append(f"schema:{location}: value does not match const")
    enum = node.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not any(
            _schema_value_equal(value, candidate) for candidate in enum
        ):
            errors.append(f"schema:{location}: value is not in enum")

    expected_types = node.get("type")
    if expected_types is not None:
        if isinstance(expected_types, str):
            candidates = [expected_types]
        elif isinstance(expected_types, list) and all(
            isinstance(item, str) for item in expected_types
        ):
            candidates = expected_types
        else:
            return [f"schema:{location}: schema type declaration is invalid"]
        try:
            type_matches = any(
                _schema_type_matches(value, candidate) for candidate in candidates
            )
        except ToolSurfaceBudgetError as exc:
            return [f"schema:{location}: {exc}"]
        if not type_matches:
            return [f"schema:{location}: value has wrong type"]

    if isinstance(value, str):
        minimum = node.get("minLength")
        maximum = node.get("maxLength")
        if isinstance(minimum, int) and not isinstance(minimum, bool) and len(value) < minimum:
            errors.append(f"schema:{location}: string is shorter than minLength")
        if isinstance(maximum, int) and not isinstance(maximum, bool) and len(value) > maximum:
            errors.append(f"schema:{location}: string exceeds maxLength")
        pattern = node.get("pattern")
        if pattern is not None:
            try:
                matches = isinstance(pattern, str) and re.search(pattern, value) is not None
            except re.error:
                matches = False
            if not matches:
                errors.append(f"schema:{location}: string does not match pattern")

    if isinstance(value, int) and not isinstance(value, bool):
        minimum = node.get("minimum")
        if isinstance(minimum, int) and not isinstance(minimum, bool) and value < minimum:
            errors.append(f"schema:{location}: integer is below minimum")

    if isinstance(value, list):
        minimum_items = node.get("minItems")
        if (
            isinstance(minimum_items, int)
            and not isinstance(minimum_items, bool)
            and len(value) < minimum_items
        ):
            errors.append(f"schema:{location}: array has fewer than minItems")
        if node.get("uniqueItems") is True:
            identities = [_canonical_json(item) for item in value]
            if len(identities) != len(set(identities)):
                errors.append(f"schema:{location}: array items are not unique")
        item_schema = node.get("items")
        if item_schema is not None:
            if not isinstance(item_schema, dict):
                errors.append(f"schema:{location}: items schema is invalid")
            else:
                for index, item in enumerate(value):
                    errors.extend(
                        _validate_schema_value(
                            item, item_schema, root_schema, (*path, index)
                        )
                    )

    if isinstance(value, dict):
        required = node.get("required", [])
        if not isinstance(required, list) or not all(
            isinstance(item, str) for item in required
        ):
            errors.append(f"schema:{location}: required declaration is invalid")
        else:
            for key in required:
                if key not in value:
                    errors.append(
                        f"schema:{location}: missing required property: {key}"
                    )
        properties = node.get("properties", {})
        if not isinstance(properties, dict):
            errors.append(f"schema:{location}: properties declaration is invalid")
            properties = {}
        property_names = node.get("propertyNames")
        if property_names is not None and not isinstance(property_names, dict):
            errors.append(f"schema:{location}: propertyNames schema is invalid")
            property_names = None
        additional = node.get("additionalProperties", True)
        if (
            additional is not True
            and additional is not False
            and not isinstance(additional, dict)
        ):
            errors.append(f"schema:{location}: additionalProperties is invalid")
            additional = False
        for key, item in value.items():
            if not isinstance(key, str):
                errors.append(f"schema:{location}: object key is not text")
                continue
            if property_names is not None:
                errors.extend(
                    _validate_schema_value(
                        key, property_names, root_schema, (*path, key, "<name>")
                    )
                )
            child = properties.get(key)
            if isinstance(child, dict):
                errors.extend(
                    _validate_schema_value(item, child, root_schema, (*path, key))
                )
            elif key not in properties:
                if additional is False:
                    errors.append(f"schema:{location}: additional property: {key}")
                elif isinstance(additional, dict):
                    errors.extend(
                        _validate_schema_value(
                            item, additional, root_schema, (*path, key)
                        )
                    )
            elif child is not None:
                errors.append(f"schema:{location}: property schema for {key} is invalid")
    return errors


def validate_schema(contract: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    """Validate this repository-bound schema without third-party dependencies."""
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        return ["invalid tool-surface JSON schema dialect"]
    if schema.get("$id") != (
        "https://heimgewebe.org/contracts/grabowski-tool-surface-budget-v1.schema.json"
    ):
        return ["invalid tool-surface JSON schema identity"]
    if _sha256(schema) != TOOL_SURFACE_SCHEMA_SHA256:
        return ["invalid tool-surface JSON schema: code-bound schema hash drift"]
    return sorted(_validate_schema_value(contract, schema, schema, ()))


def validate_repository(root: Path = ROOT) -> dict[str, Any]:
    contract = _load_json(root / CONTRACT_PATH.relative_to(ROOT))
    schema = _load_json(root / SCHEMA_PATH.relative_to(ROOT))
    schema_errors = validate_schema(contract, schema)
    if schema_errors:
        return {"valid": False, "errors": schema_errors}
    runtime = _load_json(root / RUNTIME_ENTRYPOINT_PATH.relative_to(ROOT))
    capabilities = _load_json(root / CAPABILITY_CATALOG_PATH.relative_to(ROOT))
    operations = _load_json(root / OPERATIONS_CATALOG_PATH.relative_to(ROOT))
    operation_metadata = _load_json(root / OPERATION_METADATA_PATH.relative_to(ROOT))
    report = validate_contract(
        contract, runtime, capabilities, operations, operation_metadata
    )
    if report.get("valid"):
        report["schema_valid"] = True
        report["schema_id"] = schema.get("$id")
    return report


def initialize_contract(root: Path = ROOT) -> dict[str, Any]:
    path = root / CONTRACT_PATH.relative_to(ROOT)
    if path.exists():
        raise ToolSurfaceBudgetError(
            "tool-surface baseline is already initialized; edit accepted_additions or retired_tools explicitly"
        )
    runtime = _load_json(root / RUNTIME_ENTRYPOINT_PATH.relative_to(ROOT))
    capabilities = _load_json(root / CAPABILITY_CATALOG_PATH.relative_to(ROOT))
    operations = _load_json(root / OPERATIONS_CATALOG_PATH.relative_to(ROOT))
    operation_metadata = _load_json(root / OPERATION_METADATA_PATH.relative_to(ROOT))
    contract = build_initial_contract(
        runtime, capabilities, operations, operation_metadata
    )
    path.write_text(json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return contract


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Grabowski public tool-surface growth")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--report", action="store_true")
    mode.add_argument("--initialize", action="store_true")
    args = parser.parse_args(argv)
    if args.initialize:
        contract = initialize_contract()
        print(json.dumps({"initialized": True, "tool_count": contract["baseline"]["tool_count"]}, sort_keys=True))
        return 0
    report = validate_repository()
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())

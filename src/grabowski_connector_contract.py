from __future__ import annotations

import hashlib
import json
from typing import Any


OBSERVED_ARTIFACT_SCHEMA_VERSION = 1
MAX_OBSERVED_ARTIFACT_BYTES = 32 * 1024
MAX_OBSERVED_TOOLS = 1_000
REQUIRED_SCHEMA_PROPERTIES = {
    "grabowski_bureau_candidate_assess": {
        "candidate_id",
        "event_id",
        "idempotency_key",
        "expected_initiative",
        "expected_task_id",
        "initiative",
        "selector",
        "task_id",
    },
    "grabowski_task_start": {
        "force_new_reason",
        "operation_identity",
        "supersedes_receipt_sha256",
        "supersedes_task_id",
    },
}
REQUIRED_SCHEMA_SENTINELS = frozenset(
    {"grabowski_secret_reveal", *REQUIRED_SCHEMA_PROPERTIES}
)
SCHEMA_METADATA_KEYS = frozenset({"title", "description"})


class ConnectorContractError(ValueError):
    """Raised when a connector tools/list artifact violates its bounded contract."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def fingerprint(names: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def normalize_schema(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize_schema(item)
            for key, item in sorted(value.items())
            if key not in SCHEMA_METADATA_KEYS
        }
    if isinstance(value, list):
        return [normalize_schema(item) for item in value]
    return value


def schema_fingerprint(schema: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(normalize_schema(schema))).hexdigest()


def parse_observed_artifact(
    value: Any,
    *,
    label: str = "observed artifact",
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "tools"}:
        raise ConnectorContractError(
            f"{label} must contain exactly schema_version and tools"
        )
    if value.get("schema_version") != OBSERVED_ARTIFACT_SCHEMA_VERSION:
        raise ConnectorContractError(
            f"{label} must use schema_version {OBSERVED_ARTIFACT_SCHEMA_VERSION}"
        )
    encoded = canonical_bytes(value)
    if len(encoded) > MAX_OBSERVED_ARTIFACT_BYTES:
        raise ConnectorContractError(f"{label} exceeds the 32-KiB size limit")
    tools = value.get("tools")
    if not isinstance(tools, list) or not tools or len(tools) > MAX_OBSERVED_TOOLS:
        raise ConnectorContractError(
            f"{label} must contain 1..{MAX_OBSERVED_TOOLS} tools"
        )
    names: list[str] = []
    schemas: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for index, item in enumerate(tools):
        if isinstance(item, str):
            name = item
            schema = None
        elif isinstance(item, dict):
            if set(item) != {"name", "inputSchema"}:
                raise ConnectorContractError(
                    f"{label} tools[{index}] must contain exactly name and inputSchema"
                )
            name = item.get("name")
            schema = item.get("inputSchema")
            if not isinstance(schema, dict):
                raise ConnectorContractError(
                    f"{label} schema for {name!r} must be an object"
                )
        else:
            raise ConnectorContractError(f"{label} tools[{index}] is invalid")
        if (
            not isinstance(name, str)
            or not name
            or len(name.encode("utf-8")) > 512
        ):
            raise ConnectorContractError(
                f"{label} tools[{index}] has an invalid name"
            )
        if name in seen:
            raise ConnectorContractError(f"duplicate {label} tool: {name}")
        seen.add(name)
        names.append(name)
        if schema is not None:
            schemas[name] = schema
    metadata = {
        "artifact_bytes": len(encoded),
        "artifact_sha256": hashlib.sha256(encoded).hexdigest(),
        "name_count": len(names),
        "names_sha256": fingerprint(names),
        "schema_coverage_count": len(schemas),
        "schema_tools": sorted(schemas),
        "schema_sha256_by_tool": {
            name: schema_fingerprint(schema)
            for name, schema in sorted(schemas.items())
        },
    }
    return names, schemas, metadata


def probe_contract(
    observed_names: list[str],
    observed_schemas: dict[str, dict[str, Any]],
    runtime_names: list[str],
    runtime_schemas: dict[str, dict[str, Any]],
    contract_names: list[str],
) -> dict[str, Any]:
    runtime_names = sorted(runtime_names)
    contract_names = sorted(contract_names)
    schema_mismatches: list[dict[str, Any]] = []
    for name, observed_schema in sorted(observed_schemas.items()):
        runtime_schema = runtime_schemas.get(name)
        if not isinstance(runtime_schema, dict):
            schema_mismatches.append(
                {"tool": name, "reason": "runtime schema missing"}
            )
            continue
        observed_hash = schema_fingerprint(observed_schema)
        runtime_hash = schema_fingerprint(runtime_schema)
        if observed_hash != runtime_hash:
            schema_mismatches.append(
                {
                    "tool": name,
                    "observed_sha256": observed_hash,
                    "runtime_sha256": runtime_hash,
                }
            )

    required_schema_property_mismatches: list[dict[str, Any]] = []
    for name, required_properties in sorted(REQUIRED_SCHEMA_PROPERTIES.items()):
        for source, schema in (
            ("connector", observed_schemas.get(name)),
            ("runtime", runtime_schemas.get(name)),
        ):
            properties = schema.get("properties") if isinstance(schema, dict) else None
            missing = sorted(
                required_properties - set(properties)
                if isinstance(properties, dict)
                else required_properties
            )
            if missing:
                required_schema_property_mismatches.append(
                    {
                        "tool": name,
                        "source": source,
                        "missing_properties": missing,
                    }
                )

    missing_schema_sentinels = sorted(
        REQUIRED_SCHEMA_SENTINELS - set(observed_schemas)
    )
    unexpected_schema_tools = sorted(
        set(observed_schemas) - REQUIRED_SCHEMA_SENTINELS
    )
    missing_from_connector = sorted(set(runtime_names) - set(observed_names))
    unexpected_in_connector = sorted(set(observed_names) - set(runtime_names))
    contract_missing_from_runtime = sorted(set(contract_names) - set(runtime_names))
    runtime_unexpected_from_contract = sorted(set(runtime_names) - set(contract_names))
    matches = not any(
        (
            missing_from_connector,
            unexpected_in_connector,
            contract_missing_from_runtime,
            runtime_unexpected_from_contract,
            schema_mismatches,
            missing_schema_sentinels,
            unexpected_schema_tools,
            required_schema_property_mismatches,
        )
    )
    return {
        "matches": matches,
        "name_contract_matches": (
            not missing_from_connector and not unexpected_in_connector
        ),
        "runtime_contract_matches": (
            not contract_missing_from_runtime
            and not runtime_unexpected_from_contract
        ),
        "schema_contract_matches": (
            not schema_mismatches
            and not missing_schema_sentinels
            and not unexpected_schema_tools
            and not required_schema_property_mismatches
        ),
        "runtime_count": len(runtime_names),
        "observed_count": len(observed_names),
        "runtime_names_sha256": fingerprint(runtime_names),
        "observed_names_sha256": fingerprint(observed_names),
        "schema_coverage_count": len(observed_schemas),
        "required_schema_sentinels": sorted(REQUIRED_SCHEMA_SENTINELS),
        "missing_schema_sentinels": missing_schema_sentinels,
        "unexpected_schema_tools": unexpected_schema_tools,
        "required_schema_properties": {
            name: sorted(properties)
            for name, properties in sorted(REQUIRED_SCHEMA_PROPERTIES.items())
        },
        "required_schema_property_mismatches": (
            required_schema_property_mismatches
        ),
        "schema_mismatches": schema_mismatches,
        "missing_from_connector": missing_from_connector,
        "unexpected_in_connector": unexpected_in_connector,
        "contract_missing_from_runtime": contract_missing_from_runtime,
        "runtime_unexpected_from_contract": runtime_unexpected_from_contract,
    }


def mixed_artifact_from_runtime_tools(
    tools: list[dict[str, Any]],
) -> dict[str, Any]:
    by_name: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(tools):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ConnectorContractError(
                f"runtime tools[{index}] must be a named tool object"
            )
        name = item["name"]
        if name in by_name:
            raise ConnectorContractError(f"duplicate runtime tool: {name}")
        by_name[name] = item
    entries: list[Any] = []
    for name, item in sorted(by_name.items()):
        if name in REQUIRED_SCHEMA_SENTINELS:
            schema = item.get("inputSchema")
            if not isinstance(schema, dict):
                raise ConnectorContractError(
                    f"runtime schema for sentinel {name} is unavailable"
                )
            entries.append({"name": name, "inputSchema": schema})
        else:
            entries.append(name)
    artifact = {
        "schema_version": OBSERVED_ARTIFACT_SCHEMA_VERSION,
        "tools": entries,
    }
    parse_observed_artifact(artifact, label="runtime artifact")
    return artifact


def _require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ConnectorContractError(f"{label} must be a lowercase SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ConnectorContractError(f"{label} must be a lowercase SHA-256") from exc
    if value != value.lower():
        raise ConnectorContractError(f"{label} must be a lowercase SHA-256")
    return value


def _require_release_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ConnectorContractError(f"{label} must be a non-empty release id")
    if len(value) > 512:
        raise ConnectorContractError(f"{label} exceeds the release id bound")
    return value


def _require_repo_head(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 40:
        raise ConnectorContractError(f"{label} must be a 40-character Git head")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ConnectorContractError(f"{label} must be a 40-character Git head") from exc
    if value != value.lower():
        raise ConnectorContractError(f"{label} must be a 40-character Git head")
    return value


def evaluate_green_readiness(
    *,
    observed_names: list[str],
    observed_schemas: dict[str, dict[str, Any]],
    runtime_names: list[str],
    runtime_schemas: dict[str, dict[str, Any]],
    contract_names: list[str],
    observed_release_id: str,
    expected_release_id: str,
    observed_repo_head: str,
    expected_repo_head: str,
    observed_agent_instructions_sha256: str,
    expected_agent_instructions_sha256: str,
) -> dict[str, Any]:
    """Evaluate a parallel green runtime against manifest/tools/schemas/sentinel/Bedienvertrag.

    The result is readiness evidence for the blue-green cutover. It does not
    mutate connector state and does not authorize the cutover itself.
    """
    observed_release = _require_release_id(
        observed_release_id, label="observed_release_id"
    )
    expected_release = _require_release_id(
        expected_release_id, label="expected_release_id"
    )
    observed_head = _require_repo_head(observed_repo_head, label="observed_repo_head")
    expected_head = _require_repo_head(expected_repo_head, label="expected_repo_head")
    observed_instructions = _require_sha256(
        observed_agent_instructions_sha256,
        label="observed_agent_instructions_sha256",
    )
    expected_instructions = _require_sha256(
        expected_agent_instructions_sha256,
        label="expected_agent_instructions_sha256",
    )
    probe = probe_contract(
        observed_names,
        observed_schemas,
        runtime_names,
        runtime_schemas,
        contract_names,
    )
    release_matches = observed_release == expected_release
    head_matches = observed_head == expected_head
    bedienvertrag_matches = observed_instructions == expected_instructions
    ready = (
        probe["matches"] is True
        and release_matches
        and head_matches
        and bedienvertrag_matches
    )
    mismatches: list[str] = []
    if not release_matches:
        mismatches.append("release_id")
    if not head_matches:
        mismatches.append("repo_head")
    if not bedienvertrag_matches:
        mismatches.append("agent_instructions_sha256")
    if probe["name_contract_matches"] is not True:
        mismatches.append("tool_names")
    if probe["runtime_contract_matches"] is not True:
        mismatches.append("runtime_contract")
    if probe["schema_contract_matches"] is not True:
        mismatches.append("schemas_or_sentinels")
    return {
        "schema_version": 1,
        "kind": "grabowski_blue_green_green_readiness",
        "ready": ready,
        "mismatches": mismatches,
        "release_id": expected_release if release_matches else None,
        "repo_head": expected_head if head_matches else None,
        "agent_instructions_sha256": (
            expected_instructions if bedienvertrag_matches else None
        ),
        "observed_release_id": observed_release,
        "expected_release_id": expected_release,
        "observed_repo_head": observed_head,
        "expected_repo_head": expected_head,
        "observed_agent_instructions_sha256": observed_instructions,
        "expected_agent_instructions_sha256": expected_instructions,
        "bedienvertrag_matches": bedienvertrag_matches,
        "manifest_identity_matches": release_matches and head_matches,
        "probe": probe,
        "names_sha256": probe["runtime_names_sha256"],
        "schema_sentinels": sorted(REQUIRED_SCHEMA_SENTINELS),
        "recommended_next_action": (
            "proceed to connector cutover"
            if ready
            else "repair green readiness mismatches before cutover"
        ),
        "does_not_establish": [
            "cutover authority",
            "connector delivery of the green surface",
            "live pointer mutation",
        ],
    }


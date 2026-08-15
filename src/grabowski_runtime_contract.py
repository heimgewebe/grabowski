"""Canonical runtime entry-point contract schema.

This module is the single semantic truth for the shape of
``config/runtime-entrypoint.json`` and of the ``entrypoint_contract`` object
embedded in a deployment manifest.

It is imported by every layer that has an opinion about contract validity:

* ``tools/deploy_runtime.py``          -- the deployment builder
* ``src/grabowski_mcp.py``             -- the runtime provenance validator
* ``src/grabowski_tool_surface_budget.py`` -- the tool-surface budget validator

Before this module existed each of those layers carried its own hand-maintained
list of permitted contract fields.  The lists drifted: the builder accepted a
contract that the runtime it produced then rejected, which deadlocked every
mutation, deployment and recovery path behind an integrity gate that could no
longer be repaired.  Adding a contract field must therefore be a single edit
*here*; nothing downstream may keep a competing field list.

Validation is fail-closed in both directions:

* unknown top-level contract fields are rejected,
* unknown nested fields inside a structured field are rejected,
* structurally invalid values are rejected.

That strictness is only safe because there is exactly one definition.  The
release-lifecycle regression test in ``tests/test_release_lifecycle.py`` proves
that a manifest built by the deployment builder is accepted by the runtime
validator, so build/runtime drift is a test failure rather than a production
deadlock.
"""

from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any, Iterable, Mapping, NoReturn, Sequence

__all__ = [
    "CANONICAL_VALIDATOR_MODULE",
    "DEPLOYMENT_MANIFEST_SCHEMA_VERSION",
    "CONTRACT_SCHEMA_VERSIONS",
    "LATEST_CONTRACT_SCHEMA_VERSION",
    "MODULE_RE",
    "RESERVED_SNAPSHOT_INPUT_NAMES",
    "RESERVED_ASSET_DESTINATIONS",
    "RESERVED_ASSET_DESTINATION_ROOTS",
    "RuntimeContractError",
    "contract_error",
    "contract_is_valid",
    "contract_module_sources",
    "contract_modules",
    "contract_runtime_asset_destinations",
    "manifest_errors",
    "manifest_is_valid",
    "optional_contract_fields",
    "required_contract_fields",
    "valid_agent_instructions_identity",
    "validate_contract",
]


#: The runtime cannot validate its own manifest unless this module is part of
#: the deployed source set, so the deployment builder requires the contract to
#: declare it.
CANONICAL_VALIDATOR_MODULE = "grabowski_runtime_contract"

MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

#: Snapshot inputs the deployment writes itself; a runtime asset may not claim
#: one of these source names because the copy would be ambiguous.
RESERVED_SNAPSHOT_INPUT_NAMES = frozenset(
    {
        "runtime-entrypoint.json",
        "runtime.in",
        "runtime.lock.txt",
    }
)

#: Release-root entries owned by the deployment itself.
RESERVED_ASSET_DESTINATIONS = frozenset(
    {
        "deployment-manifest.json",
        "deployment-incomplete.json",
    }
)

#: Release-root directories owned by the deployment itself.
RESERVED_ASSET_DESTINATION_ROOTS = frozenset({".venv", "inputs"})

CONTRACT_SCHEMA_VERSIONS = (1, 2, 3, 4)
LATEST_CONTRACT_SCHEMA_VERSION = 4

_BASE_REQUIRED = ("schema_version", "mode", "module", "source", "expected_tools")

# Required fields per contract schema version.  A version's required set is
# exactly what ``RuntimeContract.to_manifest`` emits for that version, so the
# serialized form of a contract validates identically to its source file.
_REQUIRED_FIELDS: dict[int, frozenset[str]] = {
    1: frozenset(_BASE_REQUIRED),
    2: frozenset(_BASE_REQUIRED + ("supporting_sources",)),
    3: frozenset(_BASE_REQUIRED + ("supporting_sources", "runtime_assets")),
    4: frozenset(
        _BASE_REQUIRED
        + ("supporting_sources", "runtime_assets", "spawn_dependencies")
    ),
}

# Optional fields per contract schema version.  These may be absent, but when
# present they are validated structurally -- never merely tolerated.
_OPTIONAL_FIELDS: dict[int, frozenset[str]] = {
    1: frozenset(),
    2: frozenset(),
    3: frozenset(),
    4: frozenset({"browser_operator_default"}),
}

BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSIONS = (1, 2)
BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSION = 2

_LOOPBACK_ENDPOINTS = frozenset({"127.0.0.1", "::1", "localhost"})

_MAX_TEXT = 512
_MAX_LIST = 256


class RuntimeContractError(ValueError):
    """A runtime entry-point contract violated the canonical schema."""


def required_contract_fields(schema_version: int) -> frozenset[str]:
    """Return the fields a contract of ``schema_version`` must declare."""

    try:
        return _REQUIRED_FIELDS[schema_version]
    except KeyError:
        raise RuntimeContractError(
            f"unsupported contract schema_version: {schema_version!r}"
        ) from None


def optional_contract_fields(schema_version: int) -> frozenset[str]:
    """Return the fields a contract of ``schema_version`` may declare."""

    try:
        return _OPTIONAL_FIELDS[schema_version]
    except KeyError:
        raise RuntimeContractError(
            f"unsupported contract schema_version: {schema_version!r}"
        ) from None


def _fail(message: str) -> NoReturn:
    raise RuntimeContractError(message)


def _require_text(value: Any, *, label: str, maximum: int = _MAX_TEXT) -> str:
    # No bool guard here: unlike int, bool does not subclass str.
    if not isinstance(value, str):
        _fail(f"{label} must be a string")
    if not value or len(value) > maximum:
        _fail(f"{label} must be a non-empty string of at most {maximum} characters")
    return value


def _require_bool(value: Any, *, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} must be a boolean")
    return value


def _require_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    for key in value:
        if not isinstance(key, str):
            _fail(f"{label} must use string keys")
    return value


def _require_list(value: Any, *, label: str, maximum: int = _MAX_LIST) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{label} must be a list")
    if len(value) > maximum:
        _fail(f"{label} must contain at most {maximum} entries")
    return value


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    label: str,
    required: Iterable[str],
    optional: Iterable[str] = (),
) -> None:
    required_set = frozenset(required)
    optional_set = frozenset(optional)
    present = frozenset(value)
    missing = sorted(required_set - present)
    if missing:
        _fail(f"{label} is missing required field(s): {', '.join(missing)}")
    unknown = sorted(present - required_set - optional_set)
    if unknown:
        _fail(
            f"{label} declares unknown field(s): {', '.join(unknown)}; "
            "add the field to grabowski_runtime_contract so build and runtime "
            "accept it together"
        )


def _require_relative_path(value: Any, *, label: str) -> str:
    """Validate a repository-relative path and require it to be *already* canonical.

    Normalising silently would be a trap: the builder serialises contracts back
    out through ``PurePosixPath``, so a contract written as ``./src/x.py`` would
    be accepted, stored as ``src/x.py`` in the manifest, and then differ from the
    snapshotted contract file it came from.  That makes ``embedded_contract_valid``
    false and takes ``provenance_valid`` down with it -- the same build/runtime
    disagreement this module exists to prevent, just reached by a different road.

    So the check is identity, not normalisation: a path that is not already in
    canonical POSIX form is rejected rather than quietly rewritten.
    """
    text = _require_text(value, label=label)
    if "\\" in text:
        _fail(f"{label} must use POSIX separators: {text}")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("/"):
        _fail(f"{label} must be a repository-relative path without '..': {text}")
    canonical = path.as_posix()
    if canonical in {".", ""}:
        _fail(f"{label} must name a path")
    if text != canonical:
        _fail(
            f"{label} must already be canonical; {text!r} normalises to "
            f"{canonical!r}, and accepting it would let the manifest disagree "
            "with the contract it was built from"
        )
    return canonical


def _require_module(value: Any, *, label: str) -> str:
    text = _require_text(value, label=label, maximum=200)
    if MODULE_RE.fullmatch(text) is None:
        _fail(f"{label} is not a valid python module name: {text}")
    return text


def _validate_expected_tools(value: Any) -> list[str]:
    tools = _require_list(value, label="expected_tools", maximum=1024)
    if not tools:
        _fail("expected_tools must not be empty")
    for index, item in enumerate(tools):
        _require_text(item, label=f"expected_tools[{index}]", maximum=200)
    if len(set(tools)) != len(tools):
        _fail("expected_tools contains duplicate entries")
    return list(tools)


def _validate_supporting_sources(
    value: Any, *, module: str, source: str
) -> tuple[list[str], list[str]]:
    items = _require_list(value, label="supporting_sources")
    modules = [module]
    sources = [source]
    for index, item in enumerate(items):
        label = f"supporting_sources[{index}]"
        entry = _require_mapping(item, label=label)
        _require_exact_keys(entry, label=label, required=("module", "source"))
        entry_module = _require_module(entry["module"], label=f"{label}.module")
        entry_source = _require_relative_path(entry["source"], label=f"{label}.source")
        if entry_module in modules:
            _fail(f"{label} repeats runtime module {entry_module}")
        if entry_source in sources:
            _fail(f"{label} repeats runtime source path {entry_source}")
        modules.append(entry_module)
        sources.append(entry_source)
    return modules, sources


def _validate_spawn_dependencies(value: Any, *, modules: Sequence[str]) -> None:
    items = _require_list(value, label="spawn_dependencies")
    known = frozenset(modules)
    seen: set[tuple[str, str, str]] = set()
    for index, item in enumerate(items):
        label = f"spawn_dependencies[{index}]"
        entry = _require_mapping(item, label=label)
        _require_exact_keys(
            entry,
            label=label,
            required=("kind", "launcher_module", "spawned_module"),
        )
        kind = _require_text(entry["kind"], label=f"{label}.kind", maximum=80)
        if kind != "python_module":
            _fail(f"{label}.kind must be 'python_module': {kind}")
        launcher = _require_module(
            entry["launcher_module"], label=f"{label}.launcher_module"
        )
        spawned = _require_module(
            entry["spawned_module"], label=f"{label}.spawned_module"
        )
        if launcher not in known:
            _fail(f"{label}.launcher_module is not deployed: {launcher}")
        if spawned not in known:
            _fail(f"{label}.spawned_module is not deployed: {spawned}")
        identity = (kind, launcher, spawned)
        if identity in seen:
            _fail(f"{label} repeats a spawn dependency")
        seen.add(identity)


def _validate_runtime_assets(value: Any, *, sources: Sequence[str]) -> list[str]:
    items = _require_list(value, label="runtime_assets")
    known_sources = set(sources)
    asset_sources: set[str] = set()
    destinations: list[str] = []
    for index, item in enumerate(items):
        label = f"runtime_assets[{index}]"
        entry = _require_mapping(item, label=label)
        _require_exact_keys(entry, label=label, required=("source", "destination"))
        asset_source = _require_relative_path(
            entry["source"], label=f"{label}.source"
        )
        destination = _require_relative_path(
            entry["destination"], label=f"{label}.destination"
        )
        if PurePosixPath(asset_source).name in RESERVED_SNAPSHOT_INPUT_NAMES:
            _fail(f"{label}.source uses a reserved snapshot input name: {asset_source}")
        if asset_source in known_sources:
            _fail(f"{label}.source repeats a runtime source path: {asset_source}")
        if asset_source in asset_sources:
            _fail(f"{label}.source repeats a runtime asset source: {asset_source}")
        destination_path = PurePosixPath(destination)
        if destination_path.parts[0] in RESERVED_ASSET_DESTINATION_ROOTS:
            _fail(f"{label}.destination uses a reserved release directory: {destination}")
        if destination in RESERVED_ASSET_DESTINATIONS:
            _fail(f"{label}.destination uses a reserved release file: {destination}")
        if destination in destinations:
            _fail(f"{label}.destination repeats a runtime asset destination: {destination}")
        for existing in destinations:
            existing_path = PurePosixPath(existing)
            if (
                destination_path in existing_path.parents
                or existing_path in destination_path.parents
            ):
                _fail(
                    f"{label}.destination overlaps runtime asset destination {existing}"
                )
        asset_sources.add(asset_source)
        destinations.append(destination)
    return destinations


def _validate_browser_operator_default(value: Any) -> None:
    """Validate the canonical browser operator default.

    The load-bearing safety properties -- loopback-only CDP transport, an
    ephemeral profile by default, an exclusive profile lease, and a named
    lifecycle that includes an explicit stop -- are validated as values, not
    merely as types, because the browser control plane derives its default
    posture from them.
    """

    label = "browser_operator_default"
    contract = _require_mapping(value, label=label)
    schema_version = contract.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSIONS
    ):
        _fail(
            f"{label}.schema_version must be one of "
            f"{list(BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSIONS)}"
        )
    _require_exact_keys(
        contract,
        label=label,
        required=(
            "schema_version",
            "authority",
            "decision_rule",
            "canonical_browser",
            "transport",
            "profile",
            "lifecycle",
            *(("semantic_gateway",) if schema_version >= 2 else ()),
        ),
        optional=("human_browser_default", "future_adapter", "evidence_anchor"),
    )
    _require_text(contract["authority"], label=f"{label}.authority", maximum=200)
    _require_text(contract["decision_rule"], label=f"{label}.decision_rule", maximum=1024)

    browser_label = f"{label}.canonical_browser"
    browser = _require_mapping(contract["canonical_browser"], label=browser_label)
    _require_exact_keys(
        browser,
        label=browser_label,
        required=(
            "family",
            "vendor",
            "executable",
            "adapter",
            "protocol",
            "selection_role",
        ),
    )
    for key in ("family", "vendor", "adapter", "protocol", "selection_role"):
        _require_text(browser[key], label=f"{browser_label}.{key}", maximum=200)
    executable = _require_text(
        browser["executable"], label=f"{browser_label}.executable"
    )
    if not executable.startswith("/") or ".." in PurePosixPath(executable).parts:
        _fail(
            f"{browser_label}.executable must be an absolute path without '..': "
            f"{executable}"
        )

    transport_label = f"{label}.transport"
    transport = _require_mapping(contract["transport"], label=transport_label)
    _require_exact_keys(
        transport,
        label=transport_label,
        required=(
            "primary",
            "endpoint_address",
            "loopback_only",
            "vendor_mcp_role",
        ),
    )
    primary = _require_text(
        transport["primary"], label=f"{transport_label}.primary", maximum=200
    )
    if schema_version >= 2 and primary != "direct-cdp":
        _fail(
            f"{transport_label}.primary must remain 'direct-cdp' for schema 2"
        )
    _require_text(
        transport["vendor_mcp_role"],
        label=f"{transport_label}.vendor_mcp_role",
        maximum=200,
    )
    endpoint = _require_text(
        transport["endpoint_address"], label=f"{transport_label}.endpoint_address"
    )
    if endpoint not in _LOOPBACK_ENDPOINTS:
        _fail(
            f"{transport_label}.endpoint_address must be loopback "
            f"({', '.join(sorted(_LOOPBACK_ENDPOINTS))}): {endpoint}"
        )
    if _require_bool(
        transport["loopback_only"], label=f"{transport_label}.loopback_only"
    ) is not True:
        _fail(f"{transport_label}.loopback_only must be true")

    if schema_version >= 2:
        semantic_label = f"{label}.semantic_gateway"
        semantic = _require_mapping(
            contract["semantic_gateway"], label=semantic_label
        )
        _require_exact_keys(
            semantic,
            label=semantic_label,
            required=(
                "coverage",
                "tool",
                "operations",
                "supported_intents",
                "uncovered_intents",
                "public_target_contract",
                "implemented_effect_classes",
                "fail_closed_effect_classes",
                "ambiguous_effect_retry_authorized",
                "authoritative_readback_required_before_new_intent",
                "readback_grants_retry_authority",
            ),
        )
        coverage = _require_text(
            semantic["coverage"],
            label=f"{semantic_label}.coverage",
            maximum=64,
        )
        if coverage != "partial":
            _fail(f"{semantic_label}.coverage must remain 'partial'")
        tool_name = _require_text(
            semantic["tool"],
            label=f"{semantic_label}.tool",
            maximum=200,
        )
        if tool_name != "grabowski_browser_worker_semantic":
            _fail(
                f"{semantic_label}.tool must be "
                "'grabowski_browser_worker_semantic'"
            )
        semantic_operations = _require_list(
            semantic["operations"],
            label=f"{semantic_label}.operations",
            maximum=8,
        )
        if semantic_operations != ["observe", "act"]:
            _fail(f"{semantic_label}.operations must be ['observe', 'act']")
        supported_intents = _require_list(
            semantic["supported_intents"],
            label=f"{semantic_label}.supported_intents",
            maximum=8,
        )
        if supported_intents != ["read_state", "navigate", "scroll_into_view"]:
            _fail(
                f"{semantic_label}.supported_intents must be "
                "['read_state', 'navigate', 'scroll_into_view']"
            )
        uncovered_intents = _require_mapping(
            semantic["uncovered_intents"],
            label=f"{semantic_label}.uncovered_intents",
        )
        _require_exact_keys(
            uncovered_intents,
            label=f"{semantic_label}.uncovered_intents",
            required=(),
        )
        public_target_contract = _require_text(
            semantic["public_target_contract"],
            label=f"{semantic_label}.public_target_contract",
            maximum=200,
        )
        if (
            public_target_contract
            != "opaque-handles-and-validated-navigation-targets"
        ):
            _fail(
                f"{semantic_label}.public_target_contract must expose only opaque "
                "handles and validated navigation targets"
            )
        implemented = _require_list(
            semantic["implemented_effect_classes"],
            label=f"{semantic_label}.implemented_effect_classes",
            maximum=8,
        )
        if implemented != ["read", "local_ui"]:
            _fail(
                f"{semantic_label}.implemented_effect_classes must remain "
                "['read', 'local_ui']"
            )
        fail_closed = _require_list(
            semantic["fail_closed_effect_classes"],
            label=f"{semantic_label}.fail_closed_effect_classes",
            maximum=8,
        )
        if fail_closed != [
            "reversible_external",
            "external_mutation",
            "high_impact",
        ]:
            _fail(
                f"{semantic_label}.fail_closed_effect_classes must keep all "
                "external and high-impact classes blocked"
            )
        if _require_bool(
            semantic["ambiguous_effect_retry_authorized"],
            label=f"{semantic_label}.ambiguous_effect_retry_authorized",
        ) is not False:
            _fail(
                f"{semantic_label}.ambiguous_effect_retry_authorized must be false"
            )
        if _require_bool(
            semantic["authoritative_readback_required_before_new_intent"],
            label=(
                f"{semantic_label}.authoritative_readback_required_before_new_intent"
            ),
        ) is not True:
            _fail(
                f"{semantic_label}.authoritative_readback_required_before_new_intent "
                "must be true"
            )
        if _require_bool(
            semantic["readback_grants_retry_authority"],
            label=f"{semantic_label}.readback_grants_retry_authority",
        ) is not False:
            _fail(f"{semantic_label}.readback_grants_retry_authority must be false")

    profile_label = f"{label}.profile"
    profile = _require_mapping(contract["profile"], label=profile_label)
    _require_exact_keys(
        profile,
        label=profile_label,
        required=(
            "default",
            "human_profile_reuse",
            "persistent_profile_policy",
            "exclusive_profile_lease",
        ),
    )
    profile_default = _require_text(
        profile["default"], label=f"{profile_label}.default", maximum=64
    )
    if profile_default != "ephemeral":
        _fail(f"{profile_label}.default must be 'ephemeral': {profile_default}")
    if _require_bool(
        profile["human_profile_reuse"], label=f"{profile_label}.human_profile_reuse"
    ) is not False:
        _fail(f"{profile_label}.human_profile_reuse must be false")
    if _require_bool(
        profile["exclusive_profile_lease"],
        label=f"{profile_label}.exclusive_profile_lease",
    ) is not True:
        _fail(f"{profile_label}.exclusive_profile_lease must be true")
    _require_text(
        profile["persistent_profile_policy"],
        label=f"{profile_label}.persistent_profile_policy",
        maximum=200,
    )

    lifecycle_label = f"{label}.lifecycle"
    lifecycle = _require_list(contract["lifecycle"], label=lifecycle_label, maximum=64)
    if not lifecycle:
        _fail(f"{lifecycle_label} must not be empty")
    for index, item in enumerate(lifecycle):
        _require_text(item, label=f"{lifecycle_label}[{index}]", maximum=200)
    if len(set(lifecycle)) != len(lifecycle):
        _fail(f"{lifecycle_label} contains duplicate steps")
    for required_step in ("grabowski_browser_worker_start", "grabowski_browser_worker_stop"):
        if required_step not in lifecycle:
            _fail(f"{lifecycle_label} must include {required_step}")
    if schema_version >= 2:
        direct_cdp_steps = (
            "grabowski_browser_worker_start",
            "direct_cdp_action",
            "direct_cdp_readback",
            "grabowski_browser_worker_stop",
        )
        for required_step in direct_cdp_steps:
            if required_step not in lifecycle:
                _fail(f"{lifecycle_label} must include {required_step}")
        direct_cdp_positions = [lifecycle.index(step) for step in direct_cdp_steps]
        if direct_cdp_positions != sorted(direct_cdp_positions):
            _fail(f"{lifecycle_label} must order direct CDP action and readback")

    if "human_browser_default" in contract:
        human_label = f"{label}.human_browser_default"
        human = _require_mapping(contract["human_browser_default"], label=human_label)
        _require_exact_keys(
            human,
            label=human_label,
            required=("browser", "preserve", "agent_primary"),
        )
        _require_text(human["browser"], label=f"{human_label}.browser", maximum=200)
        if _require_bool(human["preserve"], label=f"{human_label}.preserve") is not True:
            _fail(f"{human_label}.preserve must be true")
        if (
            _require_bool(human["agent_primary"], label=f"{human_label}.agent_primary")
            is not False
        ):
            _fail(f"{human_label}.agent_primary must be false")

    if "future_adapter" in contract:
        adapter_label = f"{label}.future_adapter"
        adapter = _require_mapping(contract["future_adapter"], label=adapter_label)
        _require_exact_keys(
            adapter,
            label=adapter_label,
            required=("id", "browser_family", "status"),
        )
        for key in ("id", "browser_family"):
            _require_text(adapter[key], label=f"{adapter_label}.{key}", maximum=200)
        status = _require_text(
            adapter["status"], label=f"{adapter_label}.status", maximum=64
        )
        if status not in {"not-implemented", "experimental", "implemented"}:
            _fail(
                f"{adapter_label}.status must be one of "
                f"not-implemented, experimental, implemented: {status}"
            )

    if "evidence_anchor" in contract:
        anchor_label = f"{label}.evidence_anchor"
        anchor = _require_mapping(contract["evidence_anchor"], label=anchor_label)
        _require_exact_keys(
            anchor,
            label=anchor_label,
            required=(
                "bureau_task_id",
                "completion_receipt_sha256",
                "validated_at",
            ),
            optional=("does_not_establish",),
        )
        _require_text(
            anchor["bureau_task_id"], label=f"{anchor_label}.bureau_task_id", maximum=200
        )
        _require_text(
            anchor["validated_at"], label=f"{anchor_label}.validated_at", maximum=64
        )
        receipt = _require_text(
            anchor["completion_receipt_sha256"],
            label=f"{anchor_label}.completion_receipt_sha256",
            maximum=64,
        )
        if len(receipt) != 64 or any(
            char not in "0123456789abcdef" for char in receipt
        ):
            _fail(
                f"{anchor_label}.completion_receipt_sha256 must be lowercase hex "
                "of length 64"
            )
        if "does_not_establish" in anchor:
            caveats = _require_list(
                anchor["does_not_establish"],
                label=f"{anchor_label}.does_not_establish",
                maximum=64,
            )
            for index, item in enumerate(caveats):
                _require_text(
                    item,
                    label=f"{anchor_label}.does_not_establish[{index}]",
                    maximum=200,
                )


def validate_contract(raw: Any) -> None:
    """Validate a runtime entry-point contract, fail-closed.

    Raises :class:`RuntimeContractError` with a diagnostic message naming the
    offending field.  Accepts both the on-disk ``config/runtime-entrypoint.json``
    form and the ``entrypoint_contract`` object serialized into a deployment
    manifest -- they are required to be identical.
    """

    contract = _require_mapping(raw, label="runtime entrypoint contract")

    schema_version = contract.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in CONTRACT_SCHEMA_VERSIONS
    ):
        _fail(
            "runtime entrypoint contract requires schema_version in "
            f"{list(CONTRACT_SCHEMA_VERSIONS)}: {schema_version!r}"
        )

    # Mode is checked before the key set so an unsupported entry-point mode is
    # reported as such, rather than as a pile of missing module-mode fields.
    mode = _require_text(contract.get("mode"), label="mode", maximum=64)
    if mode != "module":
        _fail(f"unsupported runtime entry-point mode: {mode}")

    # A field that belongs to a later schema version is a version mismatch, not
    # an unknown field; saying so is the difference between "bump the contract
    # schema_version" and "go hunting for a typo".
    permitted = required_contract_fields(schema_version) | optional_contract_fields(
        schema_version
    )
    for key in sorted(frozenset(contract) - permitted):
        versions = sorted(
            version
            for version in CONTRACT_SCHEMA_VERSIONS
            if key in _REQUIRED_FIELDS[version] | _OPTIONAL_FIELDS[version]
        )
        if versions:
            _fail(
                f"{key} requires contract schema_version "
                f"{' or '.join(str(item) for item in versions)}, "
                f"not {schema_version}"
            )

    _require_exact_keys(
        contract,
        label="runtime entrypoint contract",
        required=required_contract_fields(schema_version),
        optional=optional_contract_fields(schema_version),
    )

    module = _require_module(contract["module"], label="module")
    source = _require_relative_path(contract["source"], label="source")
    _validate_expected_tools(contract["expected_tools"])

    modules, sources = _validate_supporting_sources(
        contract.get("supporting_sources", []), module=module, source=source
    )
    _validate_runtime_assets(contract.get("runtime_assets", []), sources=sources)
    _validate_spawn_dependencies(
        contract.get("spawn_dependencies", []), modules=modules
    )

    if "browser_operator_default" in contract:
        _validate_browser_operator_default(contract["browser_operator_default"])


DEPLOYMENT_MANIFEST_SCHEMA_VERSION = 6
AGENT_INSTRUCTIONS_SCHEMA_VERSION = 1
AGENT_INSTRUCTIONS_MAX_BYTES = 4_096
AGENT_INSTRUCTIONS_HEADER_RE = re.compile(
    r"^Grabowski agent-facing contract "
    r"(?P<version>[a-z0-9][a-z0-9-]{0,127}) "
    r"\(schema (?P<schema>[1-9][0-9]*)\)\.$"
)

_MANIFEST_REQUIRED_TYPES: dict[str, type | tuple[type, ...]] = {
    "schema_version": int,
    "release_id": str,
    "repo_head": str,
    "entrypoint_contract": dict,
    "entrypoint_contract_sha256": str,
    "agent_instructions": dict,
    "source_sha256": str,
    "source_sha256s": dict,
    "runtime_asset_sha256s": dict,
    "runtime_asset_paths": dict,
    "runtime_input_sha256": str,
    "runtime_lock_sha256": str,
    "snapshot_paths": dict,
    "immutable_release_path": str,
    "expected_stable_runtime_path": str,
    "release_python_path": str,
    "entrypoint_path": str,
    "module_paths": dict,
    "platform": str,
    "python_version": str,
    "python_implementation": str,
    "mcp_protocol_version": str,
    "created_at_unix": int,
    "completion_status": str,
    "executable": str,
    "pip_version": str,
}

_SNAPSHOT_PATH_KEYS = frozenset(
    {
        "runtime_entrypoint",
        "runtime_input",
        "runtime_lock",
        "source",
        "supporting_sources",
        "runtime_assets",
    }
)


def _is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value)
    )


def valid_agent_instructions_identity(value: Any) -> bool:
    """Validate the *shape* of the agent-instructions identity block.

    Deliberately structural: which exact contract version a release must carry
    is a runtime identity question, checked separately against the deployed
    AGENTS.md.  Pinning a version here as well would let a perfectly consistent
    release be judged schema-invalid, which is the failure mode this module
    exists to prevent.
    """
    if not isinstance(value, dict):
        return False
    if set(value) != {"schema_version", "version", "sha256", "bytes", "max_bytes"}:
        return False
    schema_version = value.get("schema_version")
    version = value.get("version")
    if (
        schema_version != AGENT_INSTRUCTIONS_SCHEMA_VERSION
        or not isinstance(version, str)
        or AGENT_INSTRUCTIONS_HEADER_RE.fullmatch(
            f"Grabowski agent-facing contract {version} (schema {schema_version})."
        )
        is None
    ):
        return False
    size = value.get("bytes")
    return (
        _is_lower_hex(value.get("sha256"), 64)
        and isinstance(size, int)
        and not isinstance(size, bool)
        and 0 < size <= AGENT_INSTRUCTIONS_MAX_BYTES
        and value.get("max_bytes") == AGENT_INSTRUCTIONS_MAX_BYTES
    )


def manifest_errors(raw: Any) -> list[str]:
    """Return the manifest fields that violate the deployment manifest schema.

    This is the single definition used by the deployment builder, the runtime
    provenance validator and the watchdog, so none of them can judge the same
    release differently.  It validates structure and internal consistency only;
    identity questions that require reading the release from disk (hashes of
    installed files, python/platform binding) stay with their callers.
    """
    if not isinstance(raw, dict):
        return ["manifest"]

    errors: list[str] = []
    for key, kind in _MANIFEST_REQUIRED_TYPES.items():
        value = raw.get(key)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            errors.append(key)

    if raw.get("schema_version") != DEPLOYMENT_MANIFEST_SCHEMA_VERSION:
        errors.append("schema_version")
    if raw.get("completion_status") != "complete":
        errors.append("completion_status")
    if not _is_lower_hex(raw.get("repo_head"), 40):
        errors.append("repo_head")
    for key in (
        "entrypoint_contract_sha256",
        "source_sha256",
        "runtime_input_sha256",
        "runtime_lock_sha256",
    ):
        if not _is_lower_hex(raw.get(key), 64):
            errors.append(key)
    if not valid_agent_instructions_identity(raw.get("agent_instructions")):
        errors.append("agent_instructions")

    contract = raw.get("entrypoint_contract")
    modules: set[str] = set()
    main_module: str | None = None
    supporting_modules: set[str] = set()
    destinations: set[str] = set()
    if contract_error(contract) is not None:
        errors.append("entrypoint_contract")
    else:
        main_module = str(contract["module"])
        modules = set(contract_modules(contract))
        supporting_modules = modules - {main_module}
        destinations = set(contract_runtime_asset_destinations(contract))

    source_hashes = raw.get("source_sha256s")
    if (
        not isinstance(source_hashes, dict)
        or set(source_hashes) != modules
        or not all(_is_lower_hex(value, 64) for value in source_hashes.values())
        or (
            main_module is not None
            and source_hashes.get(main_module) != raw.get("source_sha256")
        )
    ):
        errors.append("source_sha256s")

    asset_hashes = raw.get("runtime_asset_sha256s")
    if (
        not isinstance(asset_hashes, dict)
        or set(asset_hashes) != destinations
        or not all(_is_lower_hex(value, 64) for value in asset_hashes.values())
    ):
        errors.append("runtime_asset_sha256s")

    asset_paths = raw.get("runtime_asset_paths")
    if (
        not isinstance(asset_paths, dict)
        or set(asset_paths) != destinations
        or not all(isinstance(value, str) and value for value in asset_paths.values())
    ):
        errors.append("runtime_asset_paths")

    module_paths = raw.get("module_paths")
    if (
        not isinstance(module_paths, dict)
        or set(module_paths) != modules
        or not all(isinstance(value, str) and value for value in module_paths.values())
        or (
            main_module is not None
            and module_paths.get(main_module) != raw.get("entrypoint_path")
        )
    ):
        errors.append("module_paths")

    snapshot_paths = raw.get("snapshot_paths")
    if not isinstance(snapshot_paths, dict) or set(snapshot_paths) != _SNAPSHOT_PATH_KEYS:
        errors.append("snapshot_paths")
    else:
        supporting_paths = snapshot_paths.get("supporting_sources")
        asset_snapshot_paths = snapshot_paths.get("runtime_assets")
        if (
            not all(
                isinstance(snapshot_paths.get(key), str) and snapshot_paths.get(key)
                for key in ("runtime_entrypoint", "runtime_input", "runtime_lock", "source")
            )
            or not isinstance(supporting_paths, dict)
            or set(supporting_paths) != supporting_modules
            or not all(
                isinstance(value, str) and value for value in supporting_paths.values()
            )
            or not isinstance(asset_snapshot_paths, dict)
            or set(asset_snapshot_paths) != destinations
            or not all(
                isinstance(value, str) and value
                for value in asset_snapshot_paths.values()
            )
        ):
            errors.append("snapshot_paths")

    created = raw.get("created_at_unix")
    if not isinstance(created, int) or isinstance(created, bool) or created <= 0:
        errors.append("created_at_unix")

    return sorted(set(errors))


def manifest_is_valid(raw: Any) -> bool:
    """Return whether ``raw`` satisfies the deployment manifest schema."""

    return not manifest_errors(raw)


def contract_error(raw: Any) -> str | None:
    """Return the first schema violation of ``raw``, or ``None`` when valid."""

    try:
        validate_contract(raw)
    except RuntimeContractError as exc:
        return str(exc)
    return None


def contract_is_valid(raw: Any) -> bool:
    """Return whether ``raw`` satisfies the canonical contract schema."""

    return contract_error(raw) is None


def contract_modules(raw: Mapping[str, Any]) -> list[str]:
    """Return every python module a valid contract deploys, entry point first."""

    validate_contract(raw)
    modules = [str(raw["module"])]
    for item in raw.get("supporting_sources", []):
        modules.append(str(item["module"]))
    return modules


def contract_module_sources(raw: Mapping[str, Any]) -> dict[str, str]:
    """Return ``{module: repository-relative source}`` for a valid contract."""

    validate_contract(raw)
    sources = {str(raw["module"]): str(raw["source"])}
    for item in raw.get("supporting_sources", []):
        sources[str(item["module"])] = str(item["source"])
    return sources


def contract_runtime_asset_destinations(raw: Mapping[str, Any]) -> list[str]:
    """Return the release-relative runtime asset destinations of a contract."""

    validate_contract(raw)
    return [str(item["destination"]) for item in raw.get("runtime_assets", [])]

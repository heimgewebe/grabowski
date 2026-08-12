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
    "optional_contract_fields",
    "required_contract_fields",
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

BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSION = 1

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
    if not isinstance(value, str) or isinstance(value, bool):
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
    text = _require_text(value, label=label)
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("/"):
        _fail(f"{label} must be a repository-relative path without '..': {text}")
    if path.as_posix() in {".", ""}:
        _fail(f"{label} must name a path")
    if "\\" in text:
        _fail(f"{label} must use POSIX separators: {text}")
    return path.as_posix()


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
        ),
        optional=("human_browser_default", "future_adapter", "evidence_anchor"),
    )
    schema_version = contract["schema_version"]
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSION
    ):
        _fail(
            f"{label}.schema_version must be "
            f"{BROWSER_OPERATOR_DEFAULT_SCHEMA_VERSION}"
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
    _require_text(transport["primary"], label=f"{transport_label}.primary", maximum=200)
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

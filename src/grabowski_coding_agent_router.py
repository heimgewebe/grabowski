from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
from typing import Any

import grabowski_operator_core as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

CATALOG_ENV = "GRABOWSKI_CODING_AGENT_CATALOG"
CATALOG_OVERRIDE_ENV = "GRABOWSKI_CODING_AGENT_CATALOG_OVERRIDE"
STATE_ENV = "GRABOWSKI_CODING_AGENT_ROUTER_STATE"
MAX_CATALOG_BYTES = 512 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
CATALOG_FRESHNESS_SECONDS = 3600
QUALITY_DIMENSIONS = (
    "coding",
    "debugging",
    "review",
    "architecture",
    "reliability",
    "speed",
    "context",
    "autonomy",
)
CLAUDE_PLAN_TYPES = {"pro", "max", "team", "enterprise"}
QUALITY_CLASSES = {"S", "A", "B", "C", "HARNESS", "CONTROLLER"}
EFFORT_LEVELS = {"low", "medium", "high", "xhigh", "max"}
POOL_STATUSES = {
    "unknown",
    "available",
    "constrained",
    "cooldown",
    "exhausted",
    "blocked",
}
DYNAMIC_POOL_FIELDS = frozenset(
    {
        "status",
        "remaining_ratio",
        "reset_at",
        "cooldown_until",
        "active_sessions",
        "used_tasks",
        "verified_at",
        "updated_at",
        "last_success_at",
        "blocked_reason",
    }
)
DYNAMIC_POOL_TIME_FIELDS = frozenset(
    {"reset_at", "cooldown_until", "verified_at", "updated_at", "last_success_at"}
)


class CodingAgentRouterError(ValueError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise CodingAgentRouterError(f"{label} must be boolean")
    return value


def _read_json_object(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    required: bool = True,
) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if required:
            raise CodingAgentRouterError(f"{label} does not exist") from None
        return {}
    except OSError as exc:
        raise CodingAgentRouterError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CodingAgentRouterError(f"{label} must be a regular file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise CodingAgentRouterError(f"{label} exceeds the size limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CodingAgentRouterError(f"{label} ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CodingAgentRouterError(f"{label} grew while being read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise CodingAgentRouterError(f"{label} changed while being read")
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodingAgentRouterError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise CodingAgentRouterError(f"{label} root must be an object")
    return value


def _deployment_catalog_path() -> Path:
    module_path = Path(__file__).resolve()
    environment_prefix = Path(sys.prefix).resolve()
    if (
        sys.prefix != sys.base_prefix
        and module_path.is_relative_to(environment_prefix)
    ):
        return environment_prefix.parent / "config" / "coding-agent-catalog.json"
    return module_path.parent.parent / "config" / "coding-agent-catalog.json"


def _catalog_selection() -> tuple[Path, str]:
    configured = os.environ.get(CATALOG_ENV)
    override_enabled = os.environ.get(CATALOG_OVERRIDE_ENV) == "1"
    if configured and override_enabled:
        return Path(configured).expanduser(), "environment-override"
    return _deployment_catalog_path(), "deployment_catalog"


def _catalog_path() -> Path:
    return _catalog_selection()[0]


def _state_path() -> Path:
    configured = os.environ.get(STATE_ENV)
    if configured:
        return Path(configured).expanduser()
    return (
        Path.home()
        / ".local"
        / "state"
        / "grabowski"
        / "coding-agent-router"
        / "state.json"
    )


def _route_map(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {route["id"]: route for route in catalog["routes"]}


_PERMISSION_MODE_FLAGS = ("--permission-mode", "--approval-mode")


def _validated_route_argv_prefix(route: dict[str, Any]) -> list[str]:
    argv = route.get("argv_prefix")
    identifier = route.get("id")
    label = identifier if isinstance(identifier, str) and identifier else "route"
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(argument, str) or not argument for argument in argv)
    ):
        raise CodingAgentRouterError(f"{label}: invalid argv_prefix")
    return argv


def _route_permission_mode(route: dict[str, Any]) -> str | None:
    raw_argv = route.get("argv_prefix")
    if route.get("controller") is True and (raw_argv is None or raw_argv == []):
        return None
    argv = _validated_route_argv_prefix(route)
    identifier = route.get("id")
    label = identifier if isinstance(identifier, str) and identifier else "route"
    modes: list[str] = []
    for index, argument in enumerate(argv):
        for flag in _PERMISSION_MODE_FLAGS:
            if argument == flag:
                if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                    raise CodingAgentRouterError(f"{label}: {flag} is missing a value")
                modes.append(argv[index + 1])
            elif argument.startswith(f"{flag}="):
                value = argument.split("=", 1)[1]
                if not value:
                    raise CodingAgentRouterError(f"{label}: {flag} has an empty value")
                modes.append(value)
    distinct_modes = set(modes)
    if len(distinct_modes) > 1:
        raise CodingAgentRouterError(f"{label}: conflicting permission modes")
    return modes[0] if modes else None


def _route_uses_plan_mode(route: dict[str, Any]) -> bool:
    return _route_permission_mode(route) == "plan"


def _review_task_class_set(catalog: dict[str, Any]) -> frozenset[str]:
    return frozenset(
        task_class
        for task_class, task in catalog["task_classes"].items()
        if isinstance(task, dict) and task.get("independent_review") is True
    )


def _route_task_partitions(
    route: dict[str, Any],
    catalog: dict[str, Any],
    review_task_classes: frozenset[str] | None = None,
) -> tuple[list[str], list[str]]:
    review_classes = (
        _review_task_class_set(catalog)
        if review_task_classes is None
        else review_task_classes
    )
    task_classes = route.get("task_classes", [])
    contrast_capabilities = [
        task_class for task_class in task_classes if task_class not in review_classes
    ]
    review_capabilities = [
        task_class for task_class in task_classes if task_class in review_classes
    ]
    return contrast_capabilities, review_capabilities


def _route_capabilities_from_partitions(
    route: dict[str, Any],
    contrast_capabilities: list[str],
    review_capabilities: list[str],
) -> dict[str, Any]:
    controller = route.get("controller") is True
    contrast_only = route.get("contrast_only") is True
    review_only = route.get("review_only") is True
    direct_capable = controller
    contrast_capable = bool(contrast_capabilities) and not controller and not review_only
    review_capable = bool(review_capabilities) and not controller and not contrast_only
    if direct_capable:
        route_role = "direct-operator"
    elif contrast_capable and review_capable:
        route_role = "contrast-reviewer"
    elif contrast_capable:
        route_role = "contrast"
    elif review_capable:
        route_role = "reviewer"
    else:
        route_role = "none"
    agent_roles = []
    if contrast_capable:
        agent_roles.append("contrast")
    if review_capable:
        agent_roles.append("review")
    return {
        "route_role": route_role,
        "agent_roles": agent_roles,
        "contrast_only": contrast_only,
        "review_only": review_only,
        "direct_capable": direct_capable,
        "writer_capable": direct_capable,
        "contrast_capable": contrast_capable,
        "review_capable": review_capable,
        "writer_capabilities": list(route.get("task_classes", [])) if direct_capable else [],
        "contrast_capabilities": contrast_capabilities if contrast_capable else [],
        "review_capabilities": review_capabilities if review_capable else [],
    }


def _route_capabilities(
    route: dict[str, Any],
    catalog: dict[str, Any],
    review_task_classes: frozenset[str] | None = None,
) -> dict[str, Any]:
    contrast_capabilities, review_capabilities = _route_task_partitions(
        route, catalog, review_task_classes
    )
    return _route_capabilities_from_partitions(
        route, contrast_capabilities, review_capabilities
    )

def _route_derivations(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    review_task_classes = _review_task_class_set(catalog)
    return {
        route["id"]: {
            "permission_mode": _route_permission_mode(route),
            "capabilities": _route_capabilities(
                route, catalog, review_task_classes
            ),
        }
        for route in catalog["routes"]
    }


def _validate_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    if catalog.get("schema_version") != 2:
        raise CodingAgentRouterError("catalog schema_version must be 2")
    if catalog.get("kind") != "coding-agent-catalog":
        raise CodingAgentRouterError("catalog kind is invalid")
    required_types = {
        "policy": dict,
        "models": dict,
        "harnesses": dict,
        "quota_pools": dict,
        "task_classes": dict,
        "routes": list,
    }
    for key, expected_type in required_types.items():
        if not isinstance(catalog.get(key), expected_type):
            raise CodingAgentRouterError(f"catalog {key} has an invalid type")
    route_ids: set[str] = set()
    allowed_route_task_classes = (
        set(catalog["task_classes"])
        | set(catalog["policy"].get("controller_owned_task_classes", []))
        | {"general"}
    )
    review_task_classes = _review_task_class_set(catalog)
    route_capabilities_by_id: dict[str, dict[str, Any]] = {}
    for route in catalog["routes"]:
        if not isinstance(route, dict):
            raise CodingAgentRouterError("catalog route must be an object")
        identifier = route.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in route_ids:
            raise CodingAgentRouterError("catalog route id is invalid or duplicated")
        route_ids.add(identifier)
        if route.get("model") not in catalog["models"]:
            raise CodingAgentRouterError(f"{identifier}: unknown model")
        if route.get("harness") not in catalog["harnesses"]:
            raise CodingAgentRouterError(f"{identifier}: unknown harness")
        pools = route.get("quota_pools")
        if (
            not isinstance(pools, list)
            or not pools
            or any(pool not in catalog["quota_pools"] for pool in pools)
        ):
            raise CodingAgentRouterError(f"{identifier}: invalid quota pools")
        route_task_classes = route.get("task_classes")
        if not isinstance(route_task_classes, list) or any(
            not isinstance(task_class, str)
            or task_class not in allowed_route_task_classes
            for task_class in route_task_classes
        ):
            raise CodingAgentRouterError(f"{identifier}: invalid task classes")
        if not isinstance(route.get("independence_group"), str):
            raise CodingAgentRouterError(f"{identifier}: missing independence group")
        permission_mode = _route_permission_mode(route)
        if "writer_only" in route:
            raise CodingAgentRouterError(
                f"{identifier}: writer_only is retired; use contrast_only or review_only"
            )
        for role_flag in ("contrast_only", "review_only"):
            if role_flag in route and not isinstance(route[role_flag], bool):
                raise CodingAgentRouterError(
                    f"{identifier}: {role_flag} must be a boolean"
                )
        if route.get("contrast_only") is True and route.get("review_only") is True:
            raise CodingAgentRouterError(
                f"{identifier}: contrast_only and review_only are mutually exclusive"
            )
        if route.get("contrast_only") is True and permission_mode == "plan":
            raise CodingAgentRouterError(
                f"{identifier}: contrast-only route cannot use plan mode"
            )
        if permission_mode == "plan" and route.get("review_only") is not True:
            raise CodingAgentRouterError(
                f"{identifier}: plan-mode route must be review_only"
            )
        contrast_task_classes, route_review_task_classes = _route_task_partitions(
            route, catalog, review_task_classes
        )
        capabilities = _route_capabilities_from_partitions(
            route, contrast_task_classes, route_review_task_classes
        )
        route_capabilities_by_id[identifier] = capabilities
        if route.get("controller") is True and (
            route.get("contrast_only") is True or route.get("review_only") is True
        ):
            raise CodingAgentRouterError(
                f"{identifier}: controller route cannot be contrast_only or review_only"
            )
        if route.get("contrast_only") is True and (
            not contrast_task_classes or route_review_task_classes
        ):
            raise CodingAgentRouterError(
                f"{identifier}: contrast_only route must have contrast tasks and no review tasks"
            )
        if route.get("review_only") is True and (
            not route_review_task_classes or contrast_task_classes
        ):
            raise CodingAgentRouterError(
                f"{identifier}: review_only route must have review tasks and no contrast tasks"
            )
        if (
            route.get("enabled") is True
            and route.get("controller") is not True
            and not (capabilities["contrast_capable"] or capabilities["review_capable"])
        ):
            raise CodingAgentRouterError(
                f"{identifier}: enabled external route has no review or contrast capability"
            )

        quality_class = route.get("quality_class")
        if quality_class not in QUALITY_CLASSES:
            raise CodingAgentRouterError(f"{identifier}: invalid quality class")
        base_quality_rank = route.get("base_quality_rank")
        if (
            isinstance(base_quality_rank, bool)
            or not isinstance(base_quality_rank, (int, float))
            or not math.isfinite(float(base_quality_rank))
        ):
            raise CodingAgentRouterError(f"{identifier}: invalid base quality rank")
        effort = route.get("effort")
        if effort is not None and effort not in EFFORT_LEVELS:
            raise CodingAgentRouterError(f"{identifier}: invalid effort")
        affinity = route.get("task_affinity", {})
        if not isinstance(affinity, dict):
            raise CodingAgentRouterError(f"{identifier}: invalid task affinity")
        for task_class, weight in affinity.items():
            if task_class not in catalog["task_classes"]:
                raise CodingAgentRouterError(
                    f"{identifier}: unknown affinity task class"
                )
            if (
                isinstance(weight, bool)
                or not isinstance(weight, (int, float))
                or not math.isfinite(float(weight))
            ):
                raise CodingAgentRouterError(f"{identifier}: invalid affinity weight")
    for model_id, model in catalog["models"].items():
        if not isinstance(model, dict):
            raise CodingAgentRouterError(f"{model_id}: model must be an object")
        quality = model.get("quality")
        if not isinstance(quality, dict):
            raise CodingAgentRouterError(f"{model_id}: quality is missing")
        for dimension in QUALITY_DIMENSIONS:
            value = quality.get(dimension)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 10
            ):
                raise CodingAgentRouterError(
                    f"{model_id}: invalid quality dimension {dimension}"
                )
    for pool_id, pool in catalog["quota_pools"].items():
        if not isinstance(pool, dict):
            raise CodingAgentRouterError(f"{pool_id}: pool must be an object")
        parent = pool.get("parent_pool")
        if parent is not None and parent not in catalog["quota_pools"]:
            raise CodingAgentRouterError(f"{pool_id}: unknown parent pool")
        marginal_cost = pool.get("marginal_cost_usd")
        if marginal_cost is not None and (
            isinstance(marginal_cost, bool)
            or not isinstance(marginal_cost, (int, float))
            or not math.isfinite(float(marginal_cost))
            or float(marginal_cost) < 0
        ):
            raise CodingAgentRouterError(f"{pool_id}: invalid marginal cost")
        if not isinstance(pool.get("cost_mode"), str) or not pool["cost_mode"]:
            raise CodingAgentRouterError(f"{pool_id}: invalid cost mode")
        if not isinstance(pool.get("payg_fallback_allowed"), bool):
            raise CodingAgentRouterError(f"{pool_id}: invalid PAYG policy")
        max_concurrency = pool.get("max_concurrency")
        if (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or max_concurrency < 0
        ):
            raise CodingAgentRouterError(f"{pool_id}: invalid max concurrency")
        reserve_floor = pool.get("reserve_floor")
        if reserve_floor is not None and (
            isinstance(reserve_floor, bool)
            or not isinstance(reserve_floor, (int, float))
            or not math.isfinite(float(reserve_floor))
            or not 0 <= float(reserve_floor) <= 1
        ):
            raise CodingAgentRouterError(f"{pool_id}: invalid reserve floor")
        freshness = pool.get("freshness_seconds")
        if freshness is not None and (
            isinstance(freshness, bool)
            or not isinstance(freshness, int)
            or freshness <= 0
        ):
            raise CodingAgentRouterError(f"{pool_id}: invalid freshness window")
        owner_enabled = pool.get("owner_enabled")
        if owner_enabled is not None and not isinstance(owner_enabled, bool):
            raise CodingAgentRouterError(f"{pool_id}: invalid owner-enabled policy")
        blocked_reason = pool.get("blocked_reason")
        if blocked_reason is not None and (
            not isinstance(blocked_reason, str) or not blocked_reason.strip()
        ):
            raise CodingAgentRouterError(f"{pool_id}: invalid blocked reason")
    for pool_id in catalog["quota_pools"]:
        seen: set[str] = set()
        current: str | None = pool_id
        while current is not None:
            if current in seen:
                raise CodingAgentRouterError(f"{pool_id}: cyclic parent pool")
            seen.add(current)
            current = catalog["quota_pools"][current].get("parent_pool")
    controller = catalog["policy"].get("controller_route")
    routes = _route_map(catalog)
    if controller not in routes or routes[controller].get("controller") is not True:
        raise CodingAgentRouterError("catalog controller route is invalid")
    direct_policy = catalog["policy"].get("direct_work_policy")
    if not isinstance(direct_policy, dict):
        raise CodingAgentRouterError("catalog direct_work_policy is missing")
    if direct_policy.get("canonical_primary") != controller:
        raise CodingAgentRouterError(
            "catalog direct_work_policy canonical_primary must equal controller_route"
        )
    required_direct_booleans = {
        "direct_implementation_required": True,
        "applies_to_all_implementation_sizes": True,
        "external_primary_writer_forbidden": True,
        "external_primary_reviewer_forbidden": True,
        "capacity_fallback_to_external_writer": False,
        "contrast_requires_explicit_request": True,
    }
    for key, expected in required_direct_booleans.items():
        if direct_policy.get(key) is not expected:
            raise CodingAgentRouterError(
                f"catalog direct_work_policy {key} must be {str(expected).lower()}"
            )
    if direct_policy.get("external_agent_roles") != ["review", "contrast"]:
        raise CodingAgentRouterError(
            "catalog direct_work_policy external_agent_roles must be review and contrast"
        )
    if direct_policy.get("contrast_authority") != "advisory_only":
        raise CodingAgentRouterError(
            "catalog direct_work_policy contrast authority must be advisory_only"
        )
    if direct_policy.get("review_authority") != "advisory_until_operator_verification":
        raise CodingAgentRouterError(
            "catalog direct_work_policy review authority is invalid"
        )
    required_operator_ownership = {
        "state-inspection",
        "planning",
        "implementation",
        "tests",
        "review",
        "integration",
        "merge",
        "deployment",
        "closeout",
    }
    operator_owns = direct_policy.get("operator_owns")
    if (
        not isinstance(operator_owns, list)
        or set(operator_owns) != required_operator_ownership
        or len(operator_owns) != len(required_operator_ownership)
    ):
        raise CodingAgentRouterError(
            "catalog direct_work_policy operator_owns is incomplete or duplicated"
        )
    if set(routes[controller].get("task_classes", [])) != allowed_route_task_classes:
        raise CodingAgentRouterError(
            "catalog controller route must own every authoritative task class"
        )
    top_contrast_routes = catalog["policy"].get("frontier_model_policy", {}).get(
        "top_contrast_routes"
    )
    if not isinstance(top_contrast_routes, list) or not top_contrast_routes:
        raise CodingAgentRouterError("catalog top_contrast_routes is missing")
    for route_id in top_contrast_routes:
        route = routes.get(route_id)
        if (
            route is None
            or route.get("enabled") is not True
            or not route_capabilities_by_id.get(route_id, {}).get(
                "contrast_capable", False
            )
        ):
            raise CodingAgentRouterError(
                f"catalog top contrast route {route_id} is invalid"
            )
    return {
        "valid": True,
        "catalog_sha256": _canonical_sha256(catalog),
        "model_count": len(catalog["models"]),
        "harness_count": len(catalog["harnesses"]),
        "quota_pool_count": len(catalog["quota_pools"]),
        "route_count": len(catalog["routes"]),
        "enabled_external_route_count": sum(
            1
            for route in catalog["routes"]
            if route.get("enabled") and not route.get("controller")
        ),
    }


def _load_catalog_selection(
    path: Path, source: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    catalog = _read_json_object(
        path,
        label="coding-agent catalog",
        max_bytes=MAX_CATALOG_BYTES,
    )
    validation = _validate_catalog(catalog)
    validation["catalog_source"] = source
    validation["catalog_path"] = str(path)
    return catalog, validation


def _load_catalog() -> tuple[dict[str, Any], dict[str, Any]]:
    return _load_catalog_selection(*_catalog_selection())


def coding_agent_catalog_health() -> dict[str, Any]:
    """Return bounded semantic health for the exact catalog selected by the router."""
    path, source = _catalog_selection()
    try:
        _catalog, validation = _load_catalog_selection(path, source)
    except (OSError, CodingAgentRouterError) as exc:
        return {
            "ready": False,
            "source": source,
            "path": str(path),
            "error_type": type(exc).__name__,
            "error": str(exc)[:512],
        }
    return {
        "ready": True,
        "source": validation["catalog_source"],
        "path": validation["catalog_path"],
        **validation,
    }

def _load_state() -> dict[str, Any]:
    state = _read_json_object(
        _state_path(),
        label="coding-agent router state",
        max_bytes=MAX_STATE_BYTES,
        required=False,
    )
    if not state:
        return {}
    if state.get("schema_version") != 2:
        raise CodingAgentRouterError("router state schema_version must be 2")
    for key in ("catalog", "pools", "routes", "history"):
        if not isinstance(state.get(key, {}), dict):
            raise CodingAgentRouterError(f"router state {key} must be an object")
    for collection in ("pools", "routes"):
        for entry_id, entry in state.get(collection, {}).items():
            if not isinstance(entry_id, str) or not isinstance(entry, dict):
                raise CodingAgentRouterError(
                    f"router state {collection} entries must be named objects"
                )
    return state


def _load_optional_advisory_state() -> tuple[dict[str, Any], str | None]:
    try:
        return _load_state(), None
    except (OSError, CodingAgentRouterError) as exc:
        return {}, type(exc).__name__


def _state_catalog_fresh(state: dict[str, Any]) -> bool:
    observed = _parse_time(state.get("catalog", {}).get("observed_at"))
    if observed is None:
        return False
    age = (_utc_now() - observed).total_seconds()
    return 0 <= age <= CATALOG_FRESHNESS_SECONDS


def _effective_pool(
    pool_id: str,
    catalog: dict[str, Any],
    state: dict[str, Any],
) -> dict[str, Any]:
    static_pool = dict(catalog["quota_pools"][pool_id])
    runtime_pool = state.get("pools", {}).get(pool_id, {})
    if not isinstance(runtime_pool, dict):
        return {**static_pool, "_state_error": "pool state must be an object"}
    unexpected = sorted(set(runtime_pool) - DYNAMIC_POOL_FIELDS)
    if unexpected:
        return {
            **static_pool,
            "_state_error": f"pool state contains forbidden fields: {unexpected}",
        }
    pool = dict(static_pool)
    for field in DYNAMIC_POOL_FIELDS - {"blocked_reason"}:
        if field in runtime_pool:
            pool[field] = runtime_pool[field]
    runtime_blocked_reason = runtime_pool.get("blocked_reason")
    if runtime_blocked_reason is not None:
        if (
            not isinstance(runtime_blocked_reason, str)
            or not runtime_blocked_reason.strip()
        ):
            return {**static_pool, "_state_error": "runtime blocked reason is invalid"}
        pool["runtime_blocked_reason"] = runtime_blocked_reason.strip()
    status = pool.get("status", "unknown")
    if status not in POOL_STATUSES:
        return {**static_pool, "_state_error": "pool status is invalid"}
    for field in DYNAMIC_POOL_TIME_FIELDS:
        if field in runtime_pool and _parse_time(runtime_pool[field]) is None:
            return {**static_pool, "_state_error": f"{field} is not valid RFC3339 time"}
    active_sessions = pool.get("active_sessions", 0)
    if (
        isinstance(active_sessions, bool)
        or not isinstance(active_sessions, int)
        or active_sessions < 0
    ):
        return {**static_pool, "_state_error": "active_sessions is invalid"}
    pool["active_sessions"] = active_sessions
    used_tasks = pool.get("used_tasks")
    if used_tasks is not None and (
        isinstance(used_tasks, bool)
        or not isinstance(used_tasks, int)
        or used_tasks < 0
    ):
        return {**static_pool, "_state_error": "used_tasks is invalid"}
    remaining = pool.get("remaining_ratio")
    if remaining is not None and (
        isinstance(remaining, bool)
        or not isinstance(remaining, (int, float))
        or not math.isfinite(float(remaining))
        or not 0 <= float(remaining) <= 1
    ):
        return {**static_pool, "_state_error": "remaining_ratio is invalid"}
    boundary = _parse_time(
        pool.get("reset_at") if status == "exhausted" else pool.get("cooldown_until")
    )
    if (
        status in {"exhausted", "cooldown"}
        and boundary is not None
        and boundary <= _utc_now()
    ):
        status = "unknown"
    pool["status"] = status
    return pool


def _pool_gate(
    pool_id: str,
    catalog: dict[str, Any],
    state: dict[str, Any],
    *,
    critical: bool,
) -> tuple[bool, list[str], float, bool]:
    pool = _effective_pool(pool_id, catalog, state)
    reasons: list[str] = []
    execution_eligible = True
    if pool.get("_state_error"):
        return False, [f"invalid pool state: {pool['_state_error']}"], 0.0, False
    marginal_cost = pool.get("marginal_cost_usd")
    if (
        isinstance(marginal_cost, bool)
        or not isinstance(marginal_cost, (int, float))
        or float(marginal_cost) != 0
    ):
        return False, ["cost is unknown or non-zero"], 0.0, False
    if pool.get("payg_fallback_allowed") is not False:
        return False, ["PAYG fallback is not forbidden"], 0.0, False
    if pool.get("blocked_reason"):
        return False, [str(pool["blocked_reason"])], 0.0, False
    if pool.get("runtime_blocked_reason"):
        return False, [str(pool["runtime_blocked_reason"])], 0.0, False
    if pool.get("owner_enabled") is False:
        return False, ["owner disabled this pool"], 0.0, False
    if pool.get("status") in {"blocked", "exhausted", "cooldown"}:
        return False, [f"pool status {pool.get('status')}"], 0.0, False
    if pool["active_sessions"] >= int(pool.get("max_concurrency", 1)):
        return False, ["pool concurrency is saturated"], 0.0, False
    if pool.get("cost_mode") == "temporary-free-account":
        verified = _parse_time(pool.get("verified_at")) or _parse_time(
            state.get("catalog", {}).get("observed_at")
        )
        freshness = int(pool.get("freshness_seconds", 86400))
        age = (_utc_now() - verified).total_seconds() if verified is not None else None
        if age is None or not 0 <= age <= freshness:
            return (
                False,
                ["temporary-free evidence is stale or future-dated"],
                0.0,
                False,
            )
    remaining = pool.get("remaining_ratio")
    if (
        isinstance(remaining, (int, float))
        and not isinstance(remaining, bool)
        and 0 <= float(remaining) <= 1
    ):
        floor = float(pool.get("reserve_floor", 0))
        if float(remaining) <= floor and not critical:
            return False, [f"reserve floor reached ({floor:.2f})"], 0.0, False
        reasons.append(f"remaining={float(remaining):.2f}")
        return True, reasons, 1.0 - float(remaining), execution_eligible
    reasons.append("quota is opaque")
    if pool.get("unknown_execution") == "advisory-only":
        execution_eligible = False
    return True, reasons, 0.55, execution_eligible


def _configured_model_arg(route: dict[str, Any]) -> str | None:
    argv = route.get("argv_prefix", [])
    if not isinstance(argv, list):
        return None
    for index, item in enumerate(argv[:-1]):
        if item in {"--model", "-m"}:
            return str(argv[index + 1])
    return None


def _route_available(
    route: dict[str, Any],
    catalog: dict[str, Any],
    state: dict[str, Any],
) -> tuple[bool, str]:
    harness = route["harness"]
    live_catalog = state.get("catalog", {})
    harness_state = live_catalog.get("harnesses", {}).get(harness, {})
    if harness_state.get("available") is not True:
        return False, "harness is unavailable"
    providers = live_catalog.get("providers", {})
    model_id = route["model"]
    model_arg = _configured_model_arg(route)
    if harness == "codex" and model_id not in providers.get("codex", {}).get(
        "models", []
    ):
        return False, "Codex model is absent"
    if harness == "claude":
        auth = providers.get("claude", {}).get("auth", {})
        if not (
            auth.get("logged_in") is True
            and auth.get("auth_method") == "claude.ai"
            and auth.get("subscription_type") in CLAUDE_PLAN_TYPES
        ):
            return False, "Claude plan authentication is unavailable"
    if harness == "agy" and model_arg not in providers.get("agy", {}).get("models", []):
        return False, "Agy model is absent"
    if harness == "grok":
        grok = providers.get("grok", {})
        if grok.get("logged_in") is not True:
            return False, "Grok authentication is unavailable"
        if model_arg not in grok.get("models", []):
            return False, "Grok model is absent"
    if (
        harness == "jules"
        and providers.get("jules", {}).get("authenticated") is not True
    ):
        return False, "Jules authentication is unavailable"
    if (
        harness == "cline"
        and providers.get("cline", {})
        .get("config", {})
        .get("free_entitlement_verified")
        is not True
    ):
        return False, "Cline free entitlement is unverified"
    if harness in {"qwen-code", "aider", "goose"}:
        local_names = providers.get("ollama", {}).get("models", [])
        expected = {
            "qwen2.5-coder-14b": "qwen2.5-coder:14b",
            "qwen2.5-coder-7b-32k": "qwen2.5-coder-32k:7b",
            "qwen2.5-coder-7b": "qwen2.5-coder:7b",
        }.get(model_id)
        if expected is not None and expected not in local_names:
            return False, "local model is absent"
    return True, "live catalog route is available"


def _bounded_number(value: Any, *, default: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    numeric = float(value)
    return numeric if math.isfinite(numeric) else default


def _scoped_route_history(
    route_id: str,
    task_class: str,
    state: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    route_state = state.get("routes", {}).get(route_id, {})
    by_task = route_state.get("by_task_class", {})
    if isinstance(by_task, dict) and isinstance(by_task.get(task_class), dict):
        return by_task[task_class], "route+task-class"
    return route_state if isinstance(route_state, dict) else {}, "route-aggregate"


def _outcome_adjustment(
    route_id: str,
    task_class: str,
    state: dict[str, Any],
    learning: dict[str, Any],
) -> tuple[float, list[str]]:
    history, scope = _scoped_route_history(route_id, task_class, state)
    runs = history.get("runs", 0)
    if isinstance(runs, bool) or not isinstance(runs, int) or runs < 0:
        return 0.0, []
    minimum = int(learning.get("minimum_comparable_runs", 5))
    if runs < minimum:
        if runs:
            return 0.0, [f"learning pending {runs}/{minimum} comparable runs ({scope})"]
        return 0.0, []

    first_pass = history.get("first_pass_successes", history.get("successes", 0))
    failures = history.get("failures")
    if (
        failures is None
        and isinstance(first_pass, int)
        and not isinstance(first_pass, bool)
    ):
        failures = runs - first_pass
    if (
        not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (first_pass, failures)
        )
        or first_pass + failures != runs
    ):
        return 0.0, ["outcome history rejected: inconsistent counters"]
    prior_strength = max(
        0.0, _bounded_number(learning.get("prior_strength"), default=8.0)
    )
    posterior = (first_pass + 0.5 * prior_strength) / (runs + prior_strength)
    full_at = max(minimum, int(learning.get("confidence_full_at_runs", 20)))
    confidence = min(1.0, (runs - minimum + 1) / max(1, full_at - minimum + 1))
    positive_cap = _bounded_number(
        learning.get("max_positive_adjustment"), default=10.0
    )
    negative_cap = _bounded_number(
        learning.get("max_negative_adjustment"), default=14.0
    )
    signed_cap = positive_cap if posterior >= 0.5 else negative_cap
    adjustment = (posterior - 0.5) * 2 * signed_cap * confidence
    reasons = [
        f"evidenced outcome posterior {posterior:.2f}",
        f"learning confidence {confidence:.2f} from {runs} runs ({scope})",
    ]

    average_rework = _bounded_number(history.get("average_rework_minutes"))
    if average_rework <= 0 and runs:
        average_rework = _bounded_number(history.get("rework_minutes_total")) / runs
    if average_rework > 0:
        penalty = (
            min(
                _bounded_number(learning.get("max_rework_penalty"), default=8.0),
                average_rework / 10.0,
            )
            * confidence
        )
        adjustment -= penalty
        reasons.append(f"rework penalty -{penalty:.2f} ({average_rework:.1f}m average)")

    for key, policy_key, label in (
        ("false_claims", "max_false_claim_penalty", "false-claim"),
        ("scope_violations", "max_scope_penalty", "scope"),
        ("rollbacks", "max_rollback_penalty", "rollback"),
    ):
        count = history.get(key, 0)
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            cap = _bounded_number(learning.get(policy_key), default=8.0)
            penalty = min(cap, cap * count / runs) * confidence
            adjustment -= penalty
            reasons.append(f"{label} penalty -{penalty:.2f}")
    return adjustment, reasons


def _harness_quality(route: dict[str, Any], catalog: dict[str, Any]) -> float:
    explicit = route.get("harness_quality")
    if isinstance(explicit, (int, float)) and not isinstance(explicit, bool):
        return float(explicit)
    harness = catalog["harnesses"][route["harness"]]
    return float(
        5
        + 2 * bool(harness.get("structured_output"))
        + bool(harness.get("isolated_worktree"))
        + bool(harness.get("plan_mode"))
    )


def _route_quota_pools(
    route: dict[str, Any],
    catalog: dict[str, Any],
) -> list[str]:
    """Expand declared pools to their full parent chain, preserving first use."""
    expanded: list[str] = []
    seen: set[str] = set()
    for pool_id in route["quota_pools"]:
        current: str | None = pool_id
        while current is not None:
            if current not in seen:
                expanded.append(current)
                seen.add(current)
            current = catalog["quota_pools"][current].get("parent_pool")
    return expanded


def _score_route(
    route: dict[str, Any],
    task_class: str,
    catalog: dict[str, Any],
    state: dict[str, Any],
    *,
    changed_files: int,
    duration_minutes: int,
    novelty: str,
    risk_flags: list[str],
    latency_priority: bool,
    reviewer: bool,
    previous_group: str | None,
    previous_provider: str | None,
    capabilities: dict[str, Any] | None = None,
) -> tuple[float | None, float, float, list[str], list[str], bool]:
    reasons: list[str] = []
    if capabilities is None:
        capabilities = _route_capabilities(route, catalog)
    if route.get("enabled") is not True or route.get("controller") is True:
        return None, 0.0, 0.0, reasons, ["disabled or controller route"], False
    available, availability_reason = _route_available(route, catalog, state)
    if not available:
        return None, 0.0, 0.0, reasons, [availability_reason], False
    reasons.append(availability_reason)
    if task_class not in route.get("task_classes", []):
        return None, 0.0, 0.0, reasons, ["task class is outside route affinity"], False
    escalation_flags = {"security-sensitive", "high-risk", "prior-attempt-failed"}
    if (
        route.get("escalation_only") is True
        and task_class not in {"critical-review", "security-review"}
        and escalation_flags.isdisjoint(risk_flags)
    ):
        return (
            None,
            0.0,
            0.0,
            reasons,
            ["escalation route lacks an escalation trigger"],
            False,
        )
    task = catalog["task_classes"][task_class]
    model = catalog["models"][route["model"]]
    quality = model["quality"]
    primary_dimension = task["primary"]
    if quality[primary_dimension] < int(task["minimum"]):
        return (
            None,
            0.0,
            0.0,
            reasons,
            [f"quality floor failed for {primary_dimension}"],
            False,
        )
    critical_eligible = (
        route.get("critical_eligible") is True or route.get("tier") == "critical"
    )
    if task.get("critical") and not critical_eligible:
        return (
            None,
            0.0,
            0.0,
            reasons,
            ["critical task requires an explicitly critical-eligible route"],
            False,
        )
    if reviewer and not capabilities["review_capable"]:
        return None, 0.0, 0.0, reasons, ["route is not reviewer-capable"], False
    if not reviewer and not capabilities["contrast_capable"]:
        return None, 0.0, 0.0, reasons, ["route is not contrast-capable"], False
    if duration_minutes < int(route.get("min_duration_minutes", 0)):
        return None, 0.0, 0.0, reasons, ["delegation overhead exceeds task size"], False
    if latency_priority and route.get("remote"):
        return (
            None,
            0.0,
            0.0,
            reasons,
            ["remote asynchronous route conflicts with latency priority"],
            False,
        )
    if (
        reviewer
        and previous_group
        and route.get("independence_group") == previous_group
    ):
        return (
            None,
            0.0,
            0.0,
            reasons,
            ["reviewer shares the primary model lineage"],
            False,
        )
    if (
        reviewer
        and previous_provider
        and model.get("provider_family") == previous_provider
    ):
        return (
            None,
            0.0,
            0.0,
            reasons,
            ["reviewer shares the primary provider family"],
            False,
        )

    scarcity = 0.0
    execution_eligible = True
    for pool_id in _route_quota_pools(route, catalog):
        allowed, pool_reasons, pool_scarcity, pool_execution = _pool_gate(
            pool_id, catalog, state, critical=bool(task.get("critical"))
        )
        reasons.extend(f"{pool_id}: {reason}" for reason in pool_reasons)
        scarcity = max(scarcity, pool_scarcity)
        execution_eligible = execution_eligible and pool_execution
        if not allowed:
            return (
                None,
                0.0,
                0.0,
                reasons,
                [f"{pool_id}: {reason}" for reason in pool_reasons],
                False,
            )

    weights = catalog["policy"]["scoring"]
    effort_levels = catalog["policy"].get("effort_levels", {})
    effort_score = float(effort_levels.get(route.get("effort"), 0))
    affinity = float(route.get("task_affinity", {}).get(task_class, 0))
    risk_affinity = route.get("risk_affinity", {})
    risk_bonus = sum(float(risk_affinity.get(flag, 0)) for flag in risk_flags)
    quality_score = (
        float(route.get("base_quality_rank", 0))
        + quality[primary_dimension] * float(weights["quality"])
        + quality["reliability"] * float(weights["reliability"])
        + quality["context"] * float(weights["context"])
        + quality["autonomy"] * float(weights["autonomy"])
        + effort_score * float(weights["effort"])
        + _harness_quality(route, catalog) * float(weights["harness_quality"])
        + affinity * float(weights["task_affinity"])
        + risk_bonus * float(weights.get("risk_affinity", 1.0))
    )
    if route.get("tier") in task.get("preferred_tiers", []):
        quality_score += float(weights.get("preferred_tier_bonus", 0))
        reasons.append("preferred tier for task class")
    if changed_files >= 20 or duration_minutes >= 120:
        quality_score += quality["context"] + quality["autonomy"]
    if novelty == "high":
        quality_score += quality["architecture"]
    elif novelty == "low":
        quality_score += quality["speed"] * 0.5
    if affinity:
        reasons.append(f"task affinity +{affinity:g}")
    if risk_bonus:
        reasons.append(f"risk/profile affinity +{risk_bonus:g}")

    burn = float(route.get("burn_weight", 1))
    quota_penalty = scarcity * float(weights["quota_scarcity"]) * burn
    if scarcity >= 0.5:
        quota_penalty += float(weights["unknown_quota_penalty"]) * burn
    quota_penalty = min(quota_penalty, float(weights.get("max_quota_penalty", 20)))
    overhead_penalty = float(route.get("delegation_overhead_minutes", 0)) * float(
        weights["delegation_overhead"]
    )
    latency_adjustment = quality["speed"] * 2.0 if latency_priority else 0.0
    if (
        route.get("async_route")
        and task_class in {"long-agent", "isolated-pr"}
        and duration_minutes >= 120
    ):
        latency_adjustment += 14.0
        reasons.append("asynchronous isolated-task fit")
    learning = catalog["policy"].get("adaptive_learning", {})
    outcome_adjustment, outcome_reasons = _outcome_adjustment(
        route["id"], task_class, state, learning
    )
    adaptive_score = (
        outcome_adjustment + latency_adjustment - quota_penalty - overhead_penalty
    )
    reasons.extend(outcome_reasons)
    reasons.append(f"quota adjustment -{quota_penalty:.2f}")
    reasons.append(f"delegation adjustment -{overhead_penalty:.2f}")
    total = quality_score + adaptive_score
    return (
        round(total, 3),
        round(quality_score, 3),
        round(adaptive_score, 3),
        reasons,
        [],
        execution_eligible,
    )


def _recommendation(
    route: dict[str, Any],
    score: float,
    quality_score: float,
    adaptive_score: float,
    reasons: list[str],
    catalog: dict[str, Any],
    execution_eligible: bool,
    derivation: dict[str, Any],
) -> dict[str, Any]:
    model = catalog["models"][route["model"]]
    return {
        "route": route["id"],
        "model": route["model"],
        "model_name": model["name"],
        "model_family": model["family"],
        "provider_family": model["provider_family"],
        "harness": route["harness"],
        "tier": route["tier"],
        "quality_class": route.get("quality_class"),
        "base_quality_rank": route.get("base_quality_rank"),
        "effort": route.get("effort"),
        "independence_group": route["independence_group"],
        "quota_pools": route["quota_pools"],
        "burn_weight": route.get("burn_weight", 1),
        "quality_score": quality_score,
        "adaptive_score": adaptive_score,
        "score": score,
        "argv_prefix": route["argv_prefix"],
        "permission_mode": derivation["permission_mode"],
        "reasons": reasons,
        "quality_evidence": model.get("evidence"),
        "execution_eligible_if_separately_authorized": execution_eligible,
        **derivation["capabilities"],
    }


def _rank_routes(
    task_class: str,
    catalog: dict[str, Any],
    state: dict[str, Any],
    route_derivations: dict[str, dict[str, Any]] | None = None,
    **inputs: Any,
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    ranked: list[dict[str, Any]] = []
    excluded: dict[str, list[str]] = {}
    derivations = (
        _route_derivations(catalog)
        if route_derivations is None
        else route_derivations
    )
    for route in catalog["routes"]:
        derivation = derivations[route["id"]]
        capabilities = derivation["capabilities"]
        score, quality_score, adaptive_score, reasons, exclusion, execution_eligible = (
            _score_route(
                route,
                task_class,
                catalog,
                state,
                capabilities=capabilities,
                **inputs,
            )
        )
        if score is None:
            excluded[route["id"]] = exclusion
            continue
        ranked.append(
            _recommendation(
                route,
                score,
                quality_score,
                adaptive_score,
                reasons,
                catalog,
                execution_eligible,
                derivation,
            )
        )
    if not ranked:
        return [], excluded
    best_quality = max(item["quality_score"] for item in ranked)
    max_gap = float(
        catalog["policy"]["scoring"].get("adaptive_reorder_max_quality_gap", 10)
    )
    for item in ranked:
        item["adaptive_reorder_eligible"] = (
            best_quality - item["quality_score"] <= max_gap
        )
    ranked.sort(
        key=lambda item: (
            item["adaptive_reorder_eligible"],
            item["score"]
            if item["adaptive_reorder_eligible"]
            else item["quality_score"],
            item["quality_score"],
            item["route"],
        ),
        reverse=True,
    )
    return ranked, excluded


def _validate_request(
    task_class: Any,
    changed_files: Any,
    duration_minutes: Any,
    novelty: Any,
    risk_flags: Any,
    latency_priority: Any,
    need_review: Any,
    catalog: dict[str, Any],
) -> tuple[str, int, int, str, list[str], bool, bool]:
    if not isinstance(task_class, str) or not task_class or len(task_class) > 64:
        raise CodingAgentRouterError("task_class must be a non-empty string")
    known = set(catalog["task_classes"])
    controller_owned = set(catalog["policy"].get("controller_owned_task_classes", []))
    if task_class not in known | controller_owned:
        raise CodingAgentRouterError("task_class is unknown")
    if (
        isinstance(changed_files, bool)
        or not isinstance(changed_files, int)
        or not 0 <= changed_files <= 10000
    ):
        raise CodingAgentRouterError("changed_files must be between 0 and 10000")
    if (
        isinstance(duration_minutes, bool)
        or not isinstance(duration_minutes, int)
        or not 0 <= duration_minutes <= 10080
    ):
        raise CodingAgentRouterError("duration_minutes must be between 0 and 10080")
    if not isinstance(novelty, str) or novelty not in {"low", "medium", "high"}:
        raise CodingAgentRouterError("novelty must be low, medium or high")
    flags = [] if risk_flags is None else risk_flags
    if not isinstance(flags, list) or len(flags) > 20:
        raise CodingAgentRouterError(
            "risk_flags must be a list with at most 20 entries"
        )
    normalized_flags: list[str] = []
    for flag in flags:
        if not isinstance(flag, str) or not flag or len(flag) > 64:
            raise CodingAgentRouterError("risk flag is invalid")
        normalized_flags.append(flag)
    return (
        task_class,
        changed_files,
        duration_minutes,
        novelty,
        sorted(set(normalized_flags)),
        _strict_bool(latency_priority, "latency_priority"),
        _strict_bool(need_review, "need_review"),
    )


@mcp.tool(name="grabowski_coding_agent_catalog", annotations=READ_ONLY)
def grabowski_coding_agent_catalog(include_disabled: bool = False) -> dict[str, Any]:
    """Read the validated canonical coding-model, harness, route and quota inventory."""
    include_disabled_value = _strict_bool(include_disabled, "include_disabled")
    catalog, validation = _load_catalog()
    state, state_error_type = _load_optional_advisory_state()
    route_derivations = _route_derivations(catalog)
    routes_by_model: dict[str, list[dict[str, Any]]] = {
        model_id: [] for model_id in catalog["models"]
    }
    for route in catalog["routes"]:
        if not include_disabled_value and route.get("enabled") is not True:
            continue
        routes_by_model[route["model"]].append(
            {
                "route": route["id"],
                "harness": route["harness"],
                "enabled": route.get("enabled") is True,
                "tier": route.get("tier"),
                "quota_pools": route["quota_pools"],
                "disabled_reason": route.get("disabled_reason"),
                "permission_mode": route_derivations[route["id"]][
                    "permission_mode"
                ],
                **route_derivations[route["id"]]["capabilities"],
            }
        )
    models = []
    for model_id, model in sorted(catalog["models"].items()):
        if not include_disabled_value and not routes_by_model[model_id]:
            continue
        models.append(
            {
                "id": model_id,
                "name": model.get("name"),
                "family": model.get("family"),
                "provider_family": model.get("provider_family"),
                "availability": model.get("availability"),
                "quality_prior_class": model.get("quality_prior_class"),
                "quality_evidence": model.get("evidence"),
                "routes": routes_by_model[model_id],
            }
        )
    body = {
        "schema_version": 2,
        "catalog_version": catalog.get("catalog_version"),
        "catalog_path": validation["catalog_path"],
        "validation": validation,
        "catalog_fresh": _state_catalog_fresh(state),
        "state_available": bool(state),
        "state_status": (
            "invalid"
            if state_error_type is not None
            else "current"
            if state
            else "unavailable"
        ),
        "state_error_type": state_error_type,
        "frontier_model_policy": catalog["policy"].get("frontier_model_policy"),
        "provider_peer_balance": catalog["policy"].get("provider_peer_balance"),
        "quality_classes": catalog["policy"].get("quality_classes"),
        "adaptive_learning": catalog["policy"].get("adaptive_learning"),
        "direct_work_policy": catalog["policy"].get("direct_work_policy"),
        "models": models,
        "harnesses": catalog["harnesses"],
        "quota_pools": catalog["quota_pools"],
        "task_classes": catalog["task_classes"],
        "automatic_execution_authorized": False,
        "does_not_establish": [
            "execution_authority",
            "model_benchmark_superiority",
            "exact_provider_quota",
            "merge_readiness",
        ],
    }
    return {**body, "inventory_sha256": _canonical_sha256(body)}


@mcp.tool(name="grabowski_coding_agent_route", annotations=READ_ONLY)
def grabowski_coding_agent_route(
    task_class: str,
    changed_files: int = 1,
    duration_minutes: int = 30,
    novelty: str = "medium",
    risk_flags: list[str] | None = None,
    latency_priority: bool = False,
    need_review: bool = False,
) -> dict[str, Any]:
    """Keep all authoritative work direct; rank agents only as advisory reviewers."""
    catalog, validation = _load_catalog()
    (
        task_value,
        changed_value,
        duration_value,
        novelty_value,
        flags,
        latency_value,
        review_value,
    ) = _validate_request(
        task_class,
        changed_files,
        duration_minutes,
        novelty,
        risk_flags,
        latency_priority,
        need_review,
        catalog,
    )
    controller_id = catalog["policy"]["controller_route"]
    controller_route = _route_map(catalog)[controller_id]
    controller_model = catalog["models"][controller_route["model"]]
    controller_owned = set(catalog["policy"].get("controller_owned_task_classes", []))
    task = catalog["task_classes"].get(task_value)
    direct_review_task = bool(task and task.get("independent_review") is True)
    external_review_requested = direct_review_task or review_value
    review_task_class = task_value if direct_review_task else "independent-review"
    common = {
        "changed_files": changed_value,
        "duration_minutes": duration_value,
        "novelty": novelty_value,
        "risk_flags": flags,
        "latency_priority": latency_value,
    }
    input_value = {
        **common,
        "need_review": review_value,
    }

    reviewers: list[dict[str, Any]] = []
    review_fallbacks: list[dict[str, Any]] = []
    excluded: dict[str, list[str]] = {}
    review_status = "not-requested"
    review_state_error_type: str | None = None
    if external_review_requested:
        state, review_state_error_type = _load_optional_advisory_state()
        if review_state_error_type is not None:
            review_status = "router-state-invalid"
            excluded["reviewer:state"] = [review_state_error_type]
        elif not state:
            review_status = "router-state-unavailable"
        elif state.get("catalog_sha256") != validation["catalog_sha256"]:
            review_status = "router-state-catalog-mismatch"
        elif not _state_catalog_fresh(state):
            review_status = "router-state-stale"
        else:
            try:
                route_derivations = _route_derivations(catalog)
                ranked, review_excluded = _rank_routes(
                    review_task_class,
                    catalog,
                    state,
                    reviewer=True,
                    previous_group=controller_route["independence_group"],
                    previous_provider=controller_model["provider_family"],
                    route_derivations=route_derivations,
                    **common,
                )
            except (
                AttributeError,
                CodingAgentRouterError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                review_state_error_type = type(exc).__name__
                review_status = "router-state-invalid"
                excluded["reviewer:state"] = [review_state_error_type]
            else:
                excluded.update(
                    {
                        f"reviewer:{route_id}": reasons
                        for route_id, reasons in review_excluded.items()
                    }
                )
                if ranked:
                    reviewers.append(ranked[0])
                    review_fallbacks = ranked[1:6]
                    review_status = "recommended"
                else:
                    review_status = "no-independent-review-route"

    primary_role = "direct-reviewer" if direct_review_task else "direct-writer"
    if direct_review_task:
        reason = "direct operator review is canonical; external review is supplementary"
    elif task_value in controller_owned:
        reason = "controller-owned task class"
    else:
        reason = "direct implementation is canonical for every task size"
    body = {
        "schema_version": 2,
        "decision": "controller",
        "catalog_sha256": validation["catalog_sha256"],
        "task_class": task_value,
        "primary_role": primary_role,
        "controller": controller_id,
        "reason": reason,
        "input": input_value,
        "direct_work_required": True,
        "direct_review_required": direct_review_task,
        "direct_implementation_required": True,
        "external_primary_writer_forbidden": True,
        "external_primary_reviewer_forbidden": True,
        "capacity_fallback_to_external_writer": False,
        "operator_owns": catalog["policy"]["direct_work_policy"]["operator_owns"],
        "reviewers": reviewers,
        "review_fallbacks": review_fallbacks,
        "review_status": review_status,
        "review_state_error_type": review_state_error_type,
        "review_gap": max(0, (1 if external_review_requested else 0) - len(reviewers)),
        "review_quorum": {
            "direct_operator": 1,
            "external_advisory_target": 1 if external_review_requested else 0,
        },
        "contrast_programming": {
            "allowed": not direct_review_task,
            "requires_explicit_request": True,
            "route_tool": "grabowski_agent_execution_route",
            "authority": "advisory_only",
            "automatic_patch_apply": False,
        },
        "single_mutating_writer": True,
        "single_authoritative_mutating_writer": True,
        "authoritative_implementation_remains_direct": True,
        "final_integrator": catalog["policy"]["final_integrator"],
        "automatic_execution_authorized": False,
        "external_results_advisory": True,
        "excluded": excluded,
        "does_not_establish": [
            "execution_authority",
            "candidate_correctness",
            "merge_readiness",
            "need_for_external_agents",
            "external_primary_authority",
        ],
    }
    return {**body, "recommendation_sha256": _canonical_sha256(body)}

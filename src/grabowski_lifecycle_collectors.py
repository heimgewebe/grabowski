from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import grabowski_lifecycle_archive as lifecycle
import grabowski_lifecycle_evidence as lifecycle_evidence


SCHEMA_VERSION = 1
ACTIVE_TASK_STATES = frozenset({"launching", "running"})
TERMINAL_TASK_STATES = lifecycle.TERMINAL_TASK_STATES
REQUIRED_SOURCES = lifecycle_evidence.REQUIRED_SOURCES


class LifecycleCollectorError(RuntimeError):
    pass


@dataclass(frozen=True)
class SourceReadback:
    """One typed readback already performed by an operator-facing surface.

    ``observed=True`` with ``payload=None`` means explicit absence. ``observed=False``
    means the source was not checked and therefore must fail closed.
    """

    observed: bool
    payload: Mapping[str, Any] | None = None
    error: str | None = None


@dataclass(frozen=True)
class LifecycleCollectorRequest:
    identity: str
    kind: str
    observed_at_unix: int
    sources: Mapping[str, SourceReadback]
    exact_resource_keys: tuple[str, ...] = ()
    expected_owner_id: str | None = None
    checkout_path: str | None = None
    process_scope: str | None = None


def _error(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _source_body(name: str, *, present: bool, value: Any, errors: list[str]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_lifecycle_source_projection",
        "source": name,
        "present": present,
        "value": value,
        "errors": sorted(set(errors)),
    }


def _task_record(payload: Mapping[str, Any], identity: str) -> Mapping[str, Any] | None:
    tasks = payload.get("tasks")
    if isinstance(tasks, list):
        matches = [item for item in tasks if isinstance(item, Mapping) and item.get("task_id") == identity]
        if len(matches) > 1:
            raise LifecycleCollectorError("task readback contains duplicate task identity")
        return matches[0] if matches else None
    if payload.get("task_id") == identity:
        return payload
    return None


def _project_task(payload: Mapping[str, Any] | None, identity: str) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    record: Mapping[str, Any] | None = None
    if payload is not None:
        try:
            record = _task_record(payload, identity)
        except LifecycleCollectorError as exc:
            errors.append(str(exc))
    if record is None:
        if payload is not None and isinstance(payload.get("tasks"), list):
            pagination = payload.get("pagination")
            complete_absence = bool(
                payload.get("snapshot_complete") is True
                and isinstance(pagination, Mapping)
                and pagination.get("has_more") is False
            )
            if not complete_absence:
                errors.append("task_absence_not_proven_by_complete_snapshot")
        body = _source_body("task", present=False, value={"task_id": identity}, errors=errors)
        return body, {"state": None, "active_task": False}
    state = record.get("state")
    if not isinstance(state, str) or not state:
        errors.append("task_state_invalid")
        state = None
    resource_keys = record.get("resource_keys")
    if not isinstance(resource_keys, list) or any(not isinstance(item, str) for item in resource_keys):
        errors.append("task_resource_keys_invalid")
        resource_keys = []
    terminalization_integrity_valid = True
    if state in TERMINAL_TASK_STATES:
        terminalization_integrity_valid = bool(
            isinstance(record.get("terminalized_at_unix"), int)
            and not isinstance(record.get("terminalized_at_unix"), bool)
            and isinstance(record.get("terminalization_sha256"), str)
            and lifecycle.SHA256.fullmatch(record.get("terminalization_sha256")) is not None
        )
    value = {
        "task_id": identity,
        "state": state,
        "updated_at_unix": record.get("updated_at_unix"),
        "terminalized_at_unix": record.get("terminalized_at_unix"),
        "terminalization_sha256": record.get("terminalization_sha256"),
        "lifecycle_receipt_sha256": record.get("lifecycle_receipt_sha256"),
        "resource_keys": sorted(resource_keys),
        "lease_owner_id": record.get("lease_owner_id"),
        "terminalization_integrity_valid": terminalization_integrity_valid,
        "last_observation_state": (
            record.get("last_observation", {}).get("state")
            if isinstance(record.get("last_observation"), Mapping)
            else None
        ),
    }
    body = _source_body("task", present=True, value=value, errors=errors)
    return body, {"state": state, "active_task": state in ACTIVE_TASK_STATES if state is not None else None}


def _project_workspace_tasks(
    payload: Mapping[str, Any] | None, identity: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    raw_tasks = (
        payload.get("tasks")
        if isinstance(payload, Mapping) and isinstance(payload.get("tasks"), Mapping)
        else None
    )
    if raw_tasks is None:
        body = _source_body(
            "task",
            present=False,
            value={"workspace_id": identity, "roles": {}},
            errors=["workspace_task_readback_missing"],
        )
        return body, {"state": None, "active_task": None}
    roles: dict[str, dict[str, Any]] = {}
    active_task = False
    present = False
    for role in sorted(raw_tasks):
        raw = raw_tasks[role]
        if not isinstance(raw, Mapping):
            errors.append(f"workspace_task_role_invalid:{role}")
            continue
        task_id = raw.get("task_id")
        if task_id is not None and (not isinstance(task_id, str) or not task_id):
            errors.append(f"workspace_task_id_invalid:{role}")
            task_id = None
        state = raw.get("state")
        terminal = raw.get("terminal")
        error = raw.get("error")
        if task_id is not None:
            present = True
            if not isinstance(state, str) or not state:
                errors.append(f"workspace_task_state_invalid:{role}")
            if not isinstance(terminal, bool):
                errors.append(f"workspace_task_terminal_invalid:{role}")
            if error:
                errors.append(f"workspace_task_observation_error:{role}")
            if state in ACTIVE_TASK_STATES:
                active_task = True
        roles[str(role)] = {
            "task_id": task_id,
            "state": state,
            "terminal": terminal,
            "error": error,
        }
    body = _source_body(
        "task",
        present=present,
        value={"workspace_id": identity, "roles": roles},
        errors=errors,
    )
    return body, {"state": None, "active_task": active_task}


def _project_workspace(payload: Mapping[str, Any] | None, identity: str) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    if payload is None:
        body = _source_body("workspace", present=False, value={"workspace_id": identity}, errors=[])
        return body, {"closed": None, "open_task_role": False, "shared_reference": False}
    status = payload.get("status") if isinstance(payload.get("status"), Mapping) else payload
    cleanup = payload.get("cleanup_plan") if isinstance(payload.get("cleanup_plan"), Mapping) else None
    if cleanup is None:
        errors.append("workspace_cleanup_plan_missing")
    workspace_id = status.get("workspace_id") if isinstance(status, Mapping) else None
    if workspace_id is not None and workspace_id != identity:
        errors.append("workspace_identity_mismatch")
    closed = status.get("closed") if isinstance(status, Mapping) else None
    if closed is not None and not isinstance(closed, bool):
        errors.append("workspace_closed_invalid")
        closed = None
    open_roles: list[str] = []
    active_roles: list[str] = []
    tasks = status.get("tasks") if isinstance(status, Mapping) else None
    if isinstance(tasks, Mapping):
        for role in sorted(tasks):
            task = tasks[role]
            if not isinstance(task, Mapping):
                errors.append(f"workspace_role_invalid:{role}")
                continue
            if task.get("task_id") is None:
                continue
            if task.get("terminal") is not True:
                open_roles.append(str(role))
            if task.get("state") in ACTIVE_TASK_STATES:
                active_roles.append(str(role))
    elif tasks is not None:
        errors.append("workspace_tasks_invalid")
    shared_reference = False
    reference_ids: list[str] = []
    reference_errors: list[Any] = []
    if cleanup is not None:
        references = cleanup.get("workspace_references")
        if isinstance(references, list):
            for item in references:
                if not isinstance(item, Mapping):
                    errors.append("workspace_reference_invalid")
                    continue
                if item.get("current") is False and item.get("closed") is not True:
                    shared_reference = True
                    if isinstance(item.get("workspace_id"), str):
                        reference_ids.append(item["workspace_id"])
        elif references is not None:
            errors.append("workspace_references_invalid")
        raw_reference_errors = cleanup.get("workspace_reference_scan_errors")
        if isinstance(raw_reference_errors, list):
            reference_errors = list(raw_reference_errors)
            if reference_errors:
                errors.append("workspace_reference_inventory_incomplete")
        elif raw_reference_errors is not None:
            errors.append("workspace_reference_scan_errors_invalid")
    cleanup_workspace_id = cleanup.get("workspace_id") if cleanup is not None else None
    if cleanup_workspace_id is not None and cleanup_workspace_id != identity:
        errors.append("workspace_cleanup_identity_mismatch")
    cleanup_closed = cleanup.get("closed") if cleanup is not None else None
    if isinstance(closed, bool) and isinstance(cleanup_closed, bool) and closed != cleanup_closed:
        errors.append("workspace_closed_state_mismatch")
    liveness = cleanup.get("liveness") if cleanup is not None and isinstance(cleanup.get("liveness"), Mapping) else {}
    live_resource_keys = liveness.get("live_resource_keys") if isinstance(liveness, Mapping) else []
    if not isinstance(live_resource_keys, list):
        errors.append("workspace_live_resource_keys_invalid")
        live_resource_keys = []
    resource_observation_error = liveness.get("resource_observation_error") if isinstance(liveness, Mapping) else None
    if _error(resource_observation_error):
        errors.append("workspace_resource_observation_error")
    execution_live_roles = liveness.get("execution_live_roles") if isinstance(liveness, Mapping) else []
    if not isinstance(execution_live_roles, list):
        errors.append("workspace_execution_live_roles_invalid")
        execution_live_roles = []
    cleanup_checkout = cleanup.get("checkout") if cleanup is not None and isinstance(cleanup.get("checkout"), Mapping) else {}
    cleanup_coordination = cleanup_checkout.get("coordination") if isinstance(cleanup_checkout, Mapping) else None
    cleanup_processes = (
        cleanup_coordination.get("processes")
        if isinstance(cleanup_coordination, Mapping) and isinstance(cleanup_coordination.get("processes"), list)
        else []
    )
    value = {
        "workspace_id": identity,
        "closed": closed,
        "open_roles": sorted(open_roles),
        "active_roles": sorted(active_roles),
        "close_integrity_valid": (
            status.get("close_integrity", {}).get("valid")
            if isinstance(status.get("close_integrity"), Mapping)
            else None
        ),
        "shared_reference": shared_reference,
        "shared_reference_workspace_ids": sorted(reference_ids),
        "reference_scan_errors": reference_errors,
        "cleanup_plan_sha256": cleanup.get("plan_sha256") if cleanup is not None else None,
        "cleanup_close_integrity_valid": (
            cleanup.get("close_receipt_integrity", {}).get("valid")
            if cleanup is not None and isinstance(cleanup.get("close_receipt_integrity"), Mapping)
            else None
        ),
        "live_resource_keys": sorted(str(item) for item in live_resource_keys),
        "resource_observation_error": _error(resource_observation_error),
        "execution_live_roles": sorted(str(item) for item in execution_live_roles),
        "cleanup_process_count": len(cleanup_processes),
    }
    body = _source_body("workspace", present=True, value=value, errors=errors)
    return body, {
        "closed": closed,
        "open_task_role": bool(open_roles),
        "active_task": bool(active_roles or execution_live_roles),
        "active_process": bool(cleanup_processes),
        "active_lease": None if _error(resource_observation_error) else bool(live_resource_keys),
        "shared_reference": shared_reference,
    }


def _lease_inspections(payload: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if payload is None:
        return []
    inspections = payload.get("inspections")
    if inspections is None and "resource_key" in payload and "lease" in payload:
        inspections = [payload]
    if inspections is None:
        return []
    if not isinstance(inspections, list):
        raise LifecycleCollectorError("lease readback inspections must be a list")
    if any(not isinstance(item, Mapping) for item in inspections):
        raise LifecycleCollectorError("lease readback contains a non-object inspection")
    return list(inspections)


def _project_lease(
    payload: Mapping[str, Any] | None,
    resource_keys: tuple[str, ...],
    observed_at_unix: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    inspections: list[Mapping[str, Any]] = []
    try:
        inspections = _lease_inspections(payload)
    except LifecycleCollectorError as exc:
        errors.append(str(exc))
    required = sorted(set(resource_keys))
    by_key: dict[str, Mapping[str, Any]] = {}
    for inspection in inspections:
        key = inspection.get("resource_key")
        if not isinstance(key, str) or not key:
            errors.append("lease_inspection_resource_key_invalid")
            continue
        if key in by_key:
            errors.append(f"lease_inspection_duplicate:{key}")
            continue
        by_key[key] = inspection
    active: bool | None = False
    selected: list[dict[str, Any]] = []
    for key in required:
        inspection = by_key.get(key)
        if inspection is None:
            errors.append(f"lease_exact_inspection_missing:{key}")
            active = None
            continue
        lease = inspection.get("lease")
        if lease is None:
            selected.append({"resource_key": key, "lease": None})
            continue
        if not isinstance(lease, Mapping):
            errors.append(f"lease_inspection_payload_invalid:{key}")
            active = None
            continue
        if lease.get("resource_key") != key:
            errors.append(f"lease_inspection_identity_mismatch:{key}")
            active = None
        expires = lease.get("expires_at_unix")
        if not isinstance(expires, int) or isinstance(expires, bool):
            errors.append(f"lease_expiry_invalid:{key}")
            active = None
        elif active is not None and expires > observed_at_unix:
            active = True
        selected.append(
            {
                "resource_key": key,
                "lease": {
                    "owner_id": lease.get("owner_id"),
                    "expires_at_unix": expires,
                    "metadata_sha256": lease.get("metadata_sha256"),
                },
            }
        )
    body = _source_body(
        "lease",
        present=any(item.get("lease") is not None for item in selected),
        value={
            "observed_at_unix": observed_at_unix,
            "required_resource_keys": required,
            "exact_inspections": selected,
        },
        errors=errors,
    )
    return body, {"active_lease": active}

def _find_checkout(payload: Mapping[str, Any] | None, identity: str, checkout_path: str | None) -> Mapping[str, Any] | None:
    if payload is None:
        return None
    worktrees = payload.get("worktrees")
    if not isinstance(worktrees, list):
        if payload.get("checkout_key") == identity or (checkout_path and payload.get("path") == checkout_path):
            return payload
        return None
    matches = [
        item
        for item in worktrees
        if isinstance(item, Mapping)
        and (item.get("checkout_key") == identity or (checkout_path and item.get("path") == checkout_path))
    ]
    if len(matches) > 1:
        raise LifecycleCollectorError("checkout inventory contains duplicate target")
    return matches[0] if matches else None


def _project_checkout(
    payload: Mapping[str, Any] | None,
    identity: str,
    checkout_path: str | None,
    expected_owner_id: str | None,
    observed_at_unix: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    try:
        record = _find_checkout(payload, identity, checkout_path)
    except LifecycleCollectorError as exc:
        errors.append(str(exc))
        record = None
    if record is None:
        body = _source_body("checkout", present=False, value={"identity": identity, "path": checkout_path}, errors=errors)
        return body, {
            "closed": None,
            "dirty": False,
            "foreign_retention": False,
            "retention_expired": False,
            "retention_recovery_archived": False,
            "archived": False,
        }
    status = record.get("status")
    dirty: bool | None = None
    if isinstance(status, Mapping) and isinstance(status.get("dirty"), bool):
        dirty = status["dirty"]
    else:
        errors.append("checkout_dirty_observation_invalid")
    lifecycle_data = record.get("lifecycle") if isinstance(record.get("lifecycle"), Mapping) else {}
    decision = record.get("lifecycle_decision") if isinstance(record.get("lifecycle_decision"), Mapping) else {}
    retention = lifecycle_data.get("retention") if isinstance(lifecycle_data, Mapping) else None
    archive = lifecycle_data.get("latest_archive") if isinstance(lifecycle_data, Mapping) else None
    foreign_retention: bool | None = False
    retention_expired: bool | None = False
    retention_owner = None
    retention_until = None
    if isinstance(retention, Mapping):
        retention_owner = retention.get("owner_id")
        retention_until = retention.get("retention_until_unix")
        if not isinstance(retention_owner, str) or not retention_owner:
            errors.append("checkout_retention_owner_invalid")
            foreign_retention = None
        else:
            foreign_retention = expected_owner_id is None or retention_owner != expected_owner_id
        if not isinstance(retention_until, int) or isinstance(retention_until, bool):
            errors.append("checkout_retention_expiry_invalid")
            retention_expired = None
        else:
            retention_expired = retention_until <= observed_at_unix
    archive_matches = decision.get("archive_matches_checkout") is True
    archive_present = isinstance(archive, Mapping) and decision.get("archive_present") is True
    recovery_archived = bool(archive_present and archive_matches)
    lifecycle_state = record.get("lifecycle_state")
    closed = lifecycle_state in {"cleanup_candidate", "archived_grace"}
    # A matching checkout archive is recovery evidence for retention convergence.
    # It is not proof that the lifecycle object itself has already been archived.
    archived = False
    coordination = record.get("coordination")
    coordination_processes: list[Any] = []
    coordination_tasks: list[Any] = []
    coordination_leases: list[Any] = []
    if isinstance(coordination, Mapping):
        for field, target in (
            ("processes", coordination_processes),
            ("tasks", coordination_tasks),
            ("resource_leases", coordination_leases),
        ):
            raw_items = coordination.get(field)
            if isinstance(raw_items, list):
                target.extend(raw_items)
            elif raw_items is not None:
                errors.append(f"checkout_coordination_{field}_invalid")
    else:
        errors.append("checkout_coordination_missing")
    value = {
        "observed_at_unix": observed_at_unix,
        "checkout_key": record.get("checkout_key"),
        "path": record.get("path"),
        "head": record.get("head"),
        "branch": record.get("branch"),
        "dirty": dirty,
        "lifecycle_state": lifecycle_state,
        "retention_owner_id": retention_owner,
        "retention_until_unix": retention_until,
        "retention_active": decision.get("retention_active"),
        "archive_present": archive_present,
        "archive_matches_checkout": archive_matches,
        "coordination_blocking": decision.get("coordination_blocking"),
        "coordination_process_count": len(coordination_processes),
        "coordination_task_count": len(coordination_tasks),
        "coordination_lease_count": len(coordination_leases),
    }
    body = _source_body("checkout", present=True, value=value, errors=errors)
    return body, {
        "closed": closed,
        "dirty": dirty,
        "foreign_retention": foreign_retention,
        "retention_expired": retention_expired,
        "retention_recovery_archived": recovery_archived,
        "archived": archived,
        "active_process": bool(coordination_processes),
        "active_task": bool(coordination_tasks),
        "active_lease": bool(coordination_leases),
    }


def _project_process(payload: Mapping[str, Any] | None, process_scope: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    if payload is None:
        body = _source_body("process", present=False, value={"count": 0}, errors=[])
        return body, {"active_process": False}
    processes = payload.get("processes")
    if isinstance(processes, list):
        count = len(processes)
        value = {"count": count, "processes": processes, "scope": payload.get("scope")}
    else:
        count = payload.get("count")
        lines = payload.get("lines")
        pattern = payload.get("pattern")
        if not isinstance(process_scope, str) or not process_scope:
            errors.append("process_scope_missing_for_process_list")
        elif pattern != process_scope:
            errors.append("process_scope_mismatch")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            errors.append("process_count_invalid")
            count = None
        if lines is not None and not isinstance(lines, list):
            errors.append("process_lines_invalid")
            lines = None
        value = {"count": count, "lines": lines, "pattern": pattern, "scope": process_scope}
    body = _source_body("process", present=bool(count) if isinstance(count, int) else False, value=value, errors=errors)
    return body, {"active_process": (count > 0) if isinstance(count, int) else None}


def _project_tmux(payload: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    if payload is None:
        body = _source_body("tmux", present=False, value={"live": False, "role_bound": False}, errors=[])
        return body, {"tmux_session_present": False, "tmux_role_bound": False}
    tmux = payload.get("tmux") if isinstance(payload.get("tmux"), Mapping) else payload
    live = tmux.get("live")
    if not isinstance(live, bool):
        errors.append("tmux_live_invalid")
        live = None
    role_bound = tmux.get("role_bound")
    if role_bound is None:
        role_bound = False
    if not isinstance(role_bound, bool):
        errors.append("tmux_role_bound_invalid")
        role_bound = None
    if _error(tmux.get("error")):
        errors.append("tmux_observation_error")
    value = {
        "session_name": tmux.get("session_name"),
        "live": live,
        "role_bound": role_bound,
        "error": _error(tmux.get("error")),
    }
    body = _source_body("tmux", present=live is True, value=value, errors=errors)
    return body, {"tmux_session_present": live, "tmux_role_bound": role_bound}


def _project_receipt(
    payload: Mapping[str, Any] | None,
    kind: str,
    state: str | None,
    closed: bool | None,
    *,
    task_receipt_sha256: Any = None,
    task_terminalization_integrity_valid: Any = None,
    workspace_close_integrity_valid: Any = None,
    workspace_cleanup_close_integrity_valid: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    valid: bool | None = True
    value: dict[str, Any]
    if kind == "task":
        digest = payload.get("lifecycle_receipt_sha256") if payload is not None else None
        required = state in TERMINAL_TASK_STATES
        digest_valid = isinstance(digest, str) and lifecycle.SHA256.fullmatch(digest) is not None
        matches_task = digest == task_receipt_sha256
        valid = bool(
            digest_valid
            and matches_task
            and task_terminalization_integrity_valid is True
        ) if required else True
        value = {
            "required": required,
            "lifecycle_receipt_sha256": digest,
            "matches_task_observation": matches_task,
            "task_terminalization_integrity_valid": task_terminalization_integrity_valid,
        }
    elif kind == "workspace":
        integrity = payload.get("close_integrity") if payload is not None else None
        required = closed is True
        receipt_valid = isinstance(integrity, Mapping) and integrity.get("valid") is True
        matches_workspace = bool(
            workspace_close_integrity_valid is True
            and workspace_cleanup_close_integrity_valid is True
        )
        if required:
            valid = bool(receipt_valid and matches_workspace)
        value = {
            "required": required,
            "close_integrity": integrity,
            "matches_workspace_observation": matches_workspace,
        }
    else:
        valid = True
        value = {"required": False}
    # Invalid required receipts are lifecycle evidence and must classify as
    # recovery_required; they are not an observation-transport error.
    body = _source_body("receipt", present=payload is not None, value=value, errors=errors)
    return body, {"receipt_integrity_valid": valid}


def collect_lifecycle_classification(request: LifecycleCollectorRequest) -> dict[str, Any]:
    if not request.identity:
        raise ValueError("identity must not be empty")
    if not request.kind:
        raise ValueError("kind must not be empty")
    if not isinstance(request.observed_at_unix, int) or isinstance(request.observed_at_unix, bool):
        raise ValueError("observed_at_unix must be an integer")
    unknown_sources = set(request.sources) - REQUIRED_SOURCES
    if unknown_sources:
        raise ValueError(f"unknown source keys: {sorted(unknown_sources)}")
    if len(request.exact_resource_keys) != len(set(request.exact_resource_keys)):
        raise ValueError("exact_resource_keys must not contain duplicates")
    if any(not isinstance(key, str) or not key for key in request.exact_resource_keys):
        raise ValueError("exact_resource_keys must contain non-empty strings")

    observed_sources: set[str] = set()
    source_sha256s: dict[str, str] = {}
    source_errors: list[str] = []
    projections: dict[str, dict[str, Any]] = {}
    facts: dict[str, Any] = {
        "state": None,
        "closed": None,
        "archived": False,
        "dirty": False,
        "active_task": False,
        "active_process": False,
        "active_lease": False,
        "foreign_retention": False,
        "retention_expired": False,
        "retention_recovery_archived": False,
        "shared_reference": False,
        "open_task_role": False,
        "tmux_session_present": False,
        "tmux_role_bound": False,
        "receipt_integrity_valid": True,
    }

    def readback(name: str) -> SourceReadback:
        raw = request.sources.get(name)
        if raw is None:
            return SourceReadback(observed=False)
        if not isinstance(raw, SourceReadback):
            raise ValueError(f"sources[{name}] must be SourceReadback")
        return raw

    projectors = {
        "task": (
            lambda payload: _project_workspace_tasks(payload, request.identity)
            if request.kind == "workspace"
            else _project_task(payload, request.identity)
        ),
        "workspace": lambda payload: _project_workspace(payload, request.identity),
        "lease": lambda payload: _project_lease(payload, request.exact_resource_keys, request.observed_at_unix),
        "checkout": lambda payload: _project_checkout(
            payload,
            request.identity,
            request.checkout_path,
            request.expected_owner_id,
            request.observed_at_unix,
        ),
        "process": lambda payload: _project_process(payload, request.process_scope),
        "tmux": _project_tmux,
    }

    for name in sorted(REQUIRED_SOURCES - {"receipt"}):
        source = readback(name)
        if not source.observed:
            continue
        observed_sources.add(name)
        if source.error:
            source_errors.append(f"{name}:{source.error}")
        projection, derived = projectors[name](source.payload)
        projections[name] = projection
        source_sha256s[name] = lifecycle.sha256_json(projection)
        source_errors.extend(f"{name}:{error}" for error in projection["errors"])
        for key, value in derived.items():
            if key in {"active_task", "active_process", "active_lease"}:
                current = facts[key]
                facts[key] = None if current is None or value is None else bool(current or value)
            elif value is not None:
                # Source-specific explicit absence must not erase a fact already
                # established by the authoritative source for this object kind.
                facts[key] = value

    task_projection_value = projections.get("task", {}).get("value", {})
    if request.kind == "task" and isinstance(task_projection_value, Mapping):
        observed_task_resources = task_projection_value.get("resource_keys")
        if isinstance(observed_task_resources, list) and sorted(observed_task_resources) != sorted(request.exact_resource_keys):
            source_errors.append("lease:task_resource_scope_mismatch")

    receipt_source = readback("receipt")
    if receipt_source.observed:
        observed_sources.add("receipt")
        if receipt_source.error:
            source_errors.append(f"receipt:{receipt_source.error}")
        task_projection = projections.get("task", {}).get("value", {})
        workspace_projection = projections.get("workspace", {}).get("value", {})
        projection, derived = _project_receipt(
            receipt_source.payload,
            request.kind,
            facts["state"],
            facts["closed"],
            task_receipt_sha256=(
                task_projection.get("lifecycle_receipt_sha256")
                if isinstance(task_projection, Mapping)
                else None
            ),
            task_terminalization_integrity_valid=(
                task_projection.get("terminalization_integrity_valid")
                if isinstance(task_projection, Mapping)
                else None
            ),
            workspace_close_integrity_valid=(
                workspace_projection.get("close_integrity_valid")
                if isinstance(workspace_projection, Mapping)
                else None
            ),
            workspace_cleanup_close_integrity_valid=(
                workspace_projection.get("cleanup_close_integrity_valid")
                if isinstance(workspace_projection, Mapping)
                else None
            ),
        )
        projections["receipt"] = projection
        source_sha256s["receipt"] = lifecycle.sha256_json(projection)
        source_errors.extend(f"receipt:{error}" for error in projection["errors"])
        facts.update(derived)

    bundle = lifecycle_evidence.LifecycleObservationBundle(
        identity=request.identity,
        kind=request.kind,
        observed_sources=frozenset(observed_sources),
        source_sha256s=source_sha256s,
        source_errors=tuple(sorted(set(source_errors))),
        **facts,
    )
    classified = lifecycle_evidence.classify_observation_bundle(bundle)
    return {
        **classified,
        "collector_schema_version": SCHEMA_VERSION,
        "observed_at_unix": request.observed_at_unix,
        "source_projections": projections,
        "mutation_performed": False,
        "does_not_establish": [
            "source_freshness_after_collection",
            "effect_execution_authority",
            "physical_deletion_authority",
        ],
    }

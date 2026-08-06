from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

import grabowski_current_work as current_work
import grabowski_task_attention as task_attention

SCHEMA_VERSION = 1
DEFAULT_LIMIT = 20
MAX_LIMIT = 50
MAX_CURSOR = 128

OT_CURSOR_RE = re.compile(r"ot1\.([0-9a-f]{32})\.([0-9]{1,6})\Z")

OPERATIONAL_TRUTH_VIEWS = frozenset({"current", "history", "actionable", "hygiene"})

OPERATIONAL_BLOCKER_CLASSES = frozenset(
    {
        "active_task",
        "active_exact_lease",
        "relevant_overlapping_checkout",
        "bound_running_process",
        "open_bound_pr",
        "active_deployment_effect",
    }
)

HYGIENE_CLASSES = frozenset(
    {
        "historical_binding_deviation",
        "vanished_old_worktree",
        "expired_retention",
        "archived_branch_drift",
        "old_deploy_source",
        "unbound_historical_attention",
        "unbound_physical_process",
        "unbound_tmux_session",
        "non_overlapping_foreign_dirty",
    }
)

ATTENTION_ACTIONABLE_CLASSIFICATIONS = frozenset(
    {
        "actionable",
        "needs_operator_action",
        "outcome_unknown",
        "decision_deferred",
        "invalid_evidence",
    }
)

ATTENTION_EVIDENCE_EXCLUDED_CLASSIFICATIONS = frozenset(
    {
        "superseded",
        "superseded_by_verified_retry",
        "retry_succeeded",
        "expected_red",
        "expected_red_phase",
        "historical_environment_failure",
        "already_decided",
        "decision_closed",
        "decision_superseded",
        "already_satisfied",
    }
)

DOES_NOT_ESTABLISH = [
    "a second mutable lifecycle, attention, checkout or task truth",
    "authority from path or repository heuristics alone",
    "permission to cleanup dirty checkouts without proof of resource overlap",
    "automatic deployment or merge execution",
]


class OperationalTruthError(RuntimeError):
    pass


class OperationalTruthInputError(ValueError):
    pass


class OperationalTruthIntegrityError(OperationalTruthError):
    pass


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_cursor_offset(cursor: str | None, snapshot_sha256: str) -> int:
    if cursor in {None, ""}:
        return 0
    if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR:
        raise OperationalTruthInputError("cursor is invalid")
    match = OT_CURSOR_RE.fullmatch(cursor)
    if not match:
        raise OperationalTruthInputError("cursor is invalid")
    if match.group(1) != snapshot_sha256[:32]:
        raise OperationalTruthInputError("cursor is bound to another live snapshot")
    return int(match.group(2))


def compute_operation_identity(
    item: Mapping[str, Any],
    tasks_lookup: Mapping[str, Mapping[str, Any]] | None = None,
) -> str:
    """Derive deterministic SHA-256 operation identity from execution attributes."""
    if not isinstance(item, Mapping):
        raise OperationalTruthInputError("item must be a mapping")
    explicit = item.get("operation_identity") or item.get("operation_id")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    unit = str(item.get("unit") or item.get("authoritative_unit") or "")
    argv_sha256 = str(item.get("argv_sha256") or "")
    envelope = str(item.get("execution_envelope_sha256") or "")
    task_id = str(item.get("task_id") or "")

    if not task_id and isinstance(item.get("work_id"), str) and item["work_id"].startswith("task:"):
        task_id = item["work_id"].removeprefix("task:")

    authority_refs = item.get("authority_refs")
    if isinstance(authority_refs, list):
        for ref in authority_refs:
            if isinstance(ref, dict):
                if not task_id and ref.get("task_id"):
                    task_id = str(ref["task_id"])
                if not unit:
                    unit = str(ref.get("unit") or ref.get("authoritative_unit") or "")
                if not argv_sha256:
                    argv_sha256 = str(ref.get("argv_sha256") or "")
                if not envelope:
                    envelope = str(ref.get("execution_envelope_sha256") or "")

    if tasks_lookup and task_id in tasks_lookup:
        raw_task = tasks_lookup[task_id]
        if isinstance(raw_task, Mapping):
            if not unit:
                unit = str(raw_task.get("unit") or raw_task.get("authoritative_unit") or "")
            if not argv_sha256:
                argv_sha256 = str(raw_task.get("argv_sha256") or "")
            if not envelope:
                envelope = str(raw_task.get("execution_envelope_sha256") or "")

    if not unit and not argv_sha256 and not envelope:
        tid = task_id or str(item.get("work_id") or "")
        return _sha256_json({"identity": tid})

    return _sha256_json(
        {"unit": unit, "argv_sha256": argv_sha256, "execution_envelope_sha256": envelope}
    )


def find_reusable_operation_identity(
    active_or_recent_operations: Iterable[Mapping[str, Any]],
    candidate_identity: str,
    tasks_lookup: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Find an active or recently successful operation matching candidate_identity."""
    if not isinstance(candidate_identity, str) or not candidate_identity:
        raise OperationalTruthInputError("candidate_identity must be a non-empty string")
    for item in active_or_recent_operations:
        if not isinstance(item, Mapping):
            continue
        identity = compute_operation_identity(item, tasks_lookup=tasks_lookup)
        if identity != candidate_identity:
            continue
        state = str(item.get("state") or item.get("projection_state") or "")
        source_states = item.get("source_states") or []
        outcome = str(item.get("outcome") or item.get("classification") or "")
        is_active = state in {"launching", "running", "active"} or any(
            s in {"task:launching", "task:running"} for s in source_states
        )
        is_recent_success = (
            state in {"completed", "terminal_archived"}
            or outcome in {"success", "retry_succeeded", "already_satisfied"}
        )
        if is_active or is_recent_success:
            return {
                "reused": True,
                "operation_identity_sha256": candidate_identity,
                "existing_work_id": str(
                    item.get("task_id") or item.get("work_id") or identity
                ),
                "state": state,
                "outcome": outcome,
            }
    return None


def _checkout_dirty_has_resource_overlap(checkout_item: dict[str, Any]) -> bool:
    coordination_blocking = bool(checkout_item.get("coordination_blocking"))
    leases = checkout_item.get("resource_leases") or []
    processes = checkout_item.get("processes") or []
    return bool(coordination_blocking or leases or processes)


def classify_operational_surface(group: Mapping[str, Any]) -> dict[str, Any]:
    """Classify a work group into an operative blocker or a hygiene projection item.

    Operative Blocker Criteria:
    - Active task (state in launching, running, active task)
    - Active exact lease (lease count > 0, unexpired)
    - Relevant overlapping workspace/checkout (exact resource overlap, live leases/processes, open bound PRs, active deployment)
    - Bound running process
    - Open bound PR
    - Active deployment effect

    Hygiene Projection Criteria:
    - Historical binding deviation (managed-lifecycle-drift without live active surface, binding reconciliation drift)
    - Vanished old worktree (externally_terminal_missing without live surface)
    - Expired retention
    - Archived branch drift
    - Old deploy source
    - Unbound historical attention
    - Unbound physical process / tmux session
    - Foreign dirty state without exact resource overlap
    """
    if not isinstance(group, Mapping):
        raise OperationalTruthInputError("group must be a mapping")

    work_id = str(group.get("work_id") or "")
    projection_state = str(group.get("projection_state") or "unknown")
    source_states = set(group.get("source_states") or [])
    action_reasons = set(group.get("action_reasons") or [])
    lease_summary = group.get("lease_summary") or {}
    lease_count = int(lease_summary.get("count") or 0)
    checkout_refs = group.get("checkout_refs") or []
    physical_refs = group.get("physical_refs") or {}
    processes = physical_refs.get("processes") or []
    pr_refs = group.get("pr_refs") or []
    deployment_refs = group.get("deployment_refs") or []

    has_active_task = bool(
        group.get("binding", {}).get("kind") == "task"
        and ("task:launching" in source_states or "task:running" in source_states)
    )
    has_active_lease = lease_count > 0
    has_bound_process = bool(processes and group.get("binding_status") in {"authority-bound", "lease-bound", "checkout-bound"})
    has_open_bound_pr = any(pr.get("state") == "open" for pr in pr_refs if isinstance(pr, dict))
    has_active_deployment = any(d.get("status") == "active" for d in deployment_refs if isinstance(d, dict))

    # Resource overlap check for checkouts
    exact_resource_overlap = False
    is_foreign_dirty = False
    for checkout_item in checkout_refs:
        if isinstance(checkout_item, dict):
            if checkout_item.get("dirty"):
                if _checkout_dirty_has_resource_overlap(checkout_item):
                    exact_resource_overlap = True
                else:
                    is_foreign_dirty = True
            if checkout_item.get("coordination_blocking"):
                exact_resource_overlap = True

    is_operative_blocker = bool(
        has_active_task
        or has_active_lease
        or exact_resource_overlap
        or has_bound_process
        or has_open_bound_pr
        or has_active_deployment
    )

    if is_operative_blocker:
        kind = (
            "active_task"
            if has_active_task
            else "active_exact_lease"
            if has_active_lease
            else "relevant_overlapping_checkout"
            if exact_resource_overlap
            else "bound_running_process"
            if has_bound_process
            else "open_bound_pr"
            if has_open_bound_pr
            else "active_deployment_effect"
        )
        return {
            "work_id": work_id,
            "work_class": "operational_blocker",
            "is_blocker": True,
            "kind": kind,
            "projection_state": projection_state,
            "reason": f"operative blocker: {kind}",
        }

    # Otherwise classify as hygiene
    if is_foreign_dirty:
        hygiene_kind = "non_overlapping_foreign_dirty"
        reason = "foreign dirty checkout without exact resource overlap"
    elif "managed-lifecycle-drift" in action_reasons or any("checkout-binding" in s for s in source_states):
        hygiene_kind = "historical_binding_deviation"
        reason = "historical lifecycle binding deviation without live active surface"
    elif "closed-not-cleaned" in action_reasons or any(
        c.get("binding_phase") == "externally_terminal_missing" for c in checkout_refs if isinstance(c, dict)
    ):
        hygiene_kind = "vanished_old_worktree"
        reason = "vanished or terminal worktree candidate for hygiene cleanup"
    elif any("retention" in r for r in action_reasons):
        hygiene_kind = "expired_retention"
        reason = "expired retention window without active lease"
    elif work_id.startswith("physical-process-rescue") or "unbound-process-rescue-candidate" in action_reasons:
        hygiene_kind = "unbound_physical_process"
        reason = "unbound historical process observed for hygiene"
    elif work_id.startswith("physical-tmux-rescue") or "unbound-tmux-rescue-candidate" in action_reasons:
        hygiene_kind = "unbound_tmux_session"
        reason = "unbound tmux session observed for hygiene"
    elif any(d.get("status") == "historical" for d in deployment_refs if isinstance(d, dict)):
        hygiene_kind = "old_deploy_source"
        reason = "historical deployment source without active effect"
    else:
        hygiene_kind = "unbound_historical_attention"
        reason = "historical or unbound attention item"

    return {
        "work_id": work_id,
        "work_class": "hygiene",
        "is_blocker": False,
        "kind": hygiene_kind,
        "projection_state": "hygiene",
        "reason": reason,
    }


def partition_operational_truth_and_hygiene(
    groups: Iterable[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Partition work groups into operational blockers vs hygiene projection items."""
    blockers: list[dict[str, Any]] = []
    hygiene: list[dict[str, Any]] = []
    for raw in groups:
        if not isinstance(raw, Mapping):
            continue
        group = dict(raw)
        classification = classify_operational_surface(group)
        annotated = {**group, "operational_classification": classification}
        if classification["is_blocker"]:
            blockers.append(annotated)
        else:
            annotated["projection_state"] = "hygiene"
            hygiene.append(annotated)
    return blockers, hygiene


def build_operational_truth_projection(
    *,
    tasks_payload: dict[str, Any] | None = None,
    attention_payload: dict[str, Any] | None = None,
    resources_payload: dict[str, Any] | None = None,
    checkout_payloads: list[dict[str, Any]] | None = None,
    repository_filters: list[str] | None = None,
    tmux_payload: dict[str, Any] | None = None,
    process_payload: dict[str, Any] | None = None,
    browser_payload: dict[str, Any] | None = None,
    gui_payload: dict[str, Any] | None = None,
    reconciliation_payload: dict[str, Any] | None = None,
    deployments_payload: dict[str, Any] | None = None,
    prs_payload: dict[str, Any] | None = None,
    source_errors: list[dict[str, Any]] | None = None,
    generated_at_unix: int = 0,
    view: str = "current",
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Build canonical operational truth projection and hygiene projection.

    - Strictly separates operational blockers from hygiene.
    - Decision-cleanses standard attention projection (actionable attention).
    - Reuses identical active/recently successful operation identities.
    - Restricts process/tmux blocking to exact task/lane bindings.
    """
    if repository_filters is None:
        repository_filters = ["/home/alex/repos/grabowski"]
    if not (1 <= limit <= MAX_LIMIT):
        raise OperationalTruthInputError(f"limit must be between 1 and {MAX_LIMIT}")

    cw_projection = current_work.build_current_work_projection(
        tasks_payload=tasks_payload,
        attention_payload=attention_payload,
        resources_payload=resources_payload,
        checkout_payloads=checkout_payloads,
        repository_filters=repository_filters,
        tmux_payload=tmux_payload,
        process_payload=process_payload,
        browser_payload=browser_payload,
        gui_payload=gui_payload,
        source_errors=source_errors,
        generated_at_unix=generated_at_unix,
        reconciliation_payload=reconciliation_payload,
        view=view if view in {"current", "history"} else "current",
        limit=50,
        cursor=None,
    )

    all_groups = cw_projection.get("work", [])
    blockers, hygiene_items = partition_operational_truth_and_hygiene(all_groups)

    # Build tasks_lookup dictionary for resolving raw task attributes if needed
    tasks_lookup: dict[str, dict[str, Any]] = {}
    if tasks_payload and isinstance(tasks_payload.get("tasks"), list):
        for t in tasks_payload["tasks"]:
            if isinstance(t, dict) and t.get("task_id"):
                tasks_lookup[str(t["task_id"])] = t
    if attention_payload and isinstance(attention_payload.get("tasks"), list):
        for t in attention_payload["tasks"]:
            if isinstance(t, dict) and t.get("task_id") and str(t["task_id"]) not in tasks_lookup:
                tasks_lookup[str(t["task_id"])] = t

    # Process attention records (deduplicated by task_id and attempt)
    seen_attention_keys: set[tuple[str, int]] = set()
    attention_records: list[dict[str, Any]] = []

    raw_attention_rows: list[dict[str, Any]] = []
    if attention_payload and isinstance(attention_payload.get("tasks"), list):
        raw_attention_rows.extend(attention_payload["tasks"])
    if tasks_payload and isinstance(tasks_payload.get("tasks"), list):
        raw_attention_rows.extend(tasks_payload["tasks"])

    for r in raw_attention_rows:
        if isinstance(r, dict) and r.get("state") in task_attention.ATTENTION_STATES:
            tid = str(r.get("task_id") or "")
            att_num = int(r.get("attempt") or 1)
            key = (tid, att_num)
            if key not in seen_attention_keys:
                seen_attention_keys.add(key)
                attention_records.append(dict(r))
            else:
                # Merge details into existing record if current dict has extra fields
                for idx, rec in enumerate(attention_records):
                    if (str(rec.get("task_id") or ""), int(rec.get("attempt") or 1)) == key:
                        for k, v in r.items():
                            if k not in rec or rec[k] is None or rec[k] == "":
                                rec[k] = v
                        break

    actionable_attention_projection = (
        task_attention.current_attention_projection(
            attention_records,
            include_decisions=True,
        )
        if attention_records
        else {
            "status": "verified",
            "raw_attention_count": 0,
            "current_attention_count": 0,
            "excluded_attention_count": 0,
            "excluded_classification_counts": {},
        }
    )

    # Operation identity reuse tracking
    seen_identities: set[str] = set()
    reused_identities: list[dict[str, Any]] = []
    for item in blockers:
        identity = compute_operation_identity(item, tasks_lookup=tasks_lookup)
        if identity in seen_identities:
            reuse_info = find_reusable_operation_identity(blockers, identity, tasks_lookup=tasks_lookup)
            if reuse_info:
                reused_identities.append(reuse_info)
        else:
            seen_identities.add(identity)

    # Separate hygiene projection structure
    hygiene_by_kind: dict[str, list[dict[str, Any]]] = {
        "historical_binding_deviations": [],
        "vanished_worktrees": [],
        "expired_retentions": [],
        "archived_branch_drifts": [],
        "old_deploy_sources": [],
        "unbound_historical_attentions": [],
        "non_overlapping_foreign_dirty_states": [],
    }

    for item in hygiene_items:
        kind = item.get("operational_classification", {}).get("kind", "")
        if kind == "historical_binding_deviation":
            hygiene_by_kind["historical_binding_deviations"].append(item)
        elif kind == "vanished_old_worktree":
            hygiene_by_kind["vanished_worktrees"].append(item)
        elif kind == "expired_retention":
            hygiene_by_kind["expired_retentions"].append(item)
        elif kind == "archived_branch_drift":
            hygiene_by_kind["archived_branch_drifts"].append(item)
        elif kind == "old_deploy_source":
            hygiene_by_kind["old_deploy_sources"].append(item)
        elif kind == "non_overlapping_foreign_dirty":
            hygiene_by_kind["non_overlapping_foreign_dirty_states"].append(item)
        else:
            hygiene_by_kind["unbound_historical_attentions"].append(item)

    hygiene_projection_payload = {
        "schema_version": SCHEMA_VERSION,
        "projection": "hygiene-projection",
        "count": len(hygiene_items),
        "categories": hygiene_by_kind,
        "unbound_physical_surfaces": cw_projection.get("unbound_physical", {}),
    }

    # Target list selection for view
    target_list = hygiene_items if view == "hygiene" else blockers if view == "actionable" else all_groups
    snapshot_material = {
        "view": view,
        "blockers": blockers,
        "hygiene": hygiene_items,
        "reused_identities": reused_identities,
        "source_errors": cw_projection.get("source_errors", []),
    }
    snapshot_sha256 = _sha256_json(snapshot_material)

    offset = _parse_cursor_offset(cursor, snapshot_sha256)
    page = target_list[offset : offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < len(target_list)

    return {
        "schema_version": SCHEMA_VERSION,
        "projection": "operational-truth",
        "view": view,
        "generated_at_unix": generated_at_unix,
        "snapshot_sha256": snapshot_sha256,
        "count": len(page),
        "total_operational_blockers": len(blockers),
        "total_hygiene_items": len(hygiene_items),
        "work": page,
        "operational_blockers": blockers[:limit] if view == "actionable" else blockers,
        "actionable_attention": actionable_attention_projection,
        "hygiene_projection": hygiene_projection_payload,
        "reused_operation_identities": reused_identities,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_cursor": f"ot1.{snapshot_sha256[:32]}.{next_offset}" if has_more else None,
            "snapshot_bound": True,
        },
        "state_counts": {
            "operational_blockers": len(blockers),
            "hygiene": len(hygiene_items),
            "actionable_attention": actionable_attention_projection.get("current_attention_count", 0),
        },
        "source_authority": cw_projection.get("source_authority", {}),
        "source_counts": cw_projection.get("source_counts", {}),
        "source_truncation": cw_projection.get("source_truncation", {}),
        "source_errors": cw_projection.get("source_errors", []),
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }


def build_hygiene_projection(
    *,
    tasks_payload: dict[str, Any] | None = None,
    attention_payload: dict[str, Any] | None = None,
    resources_payload: dict[str, Any] | None = None,
    checkout_payloads: list[dict[str, Any]] | None = None,
    repository_filters: list[str] | None = None,
    tmux_payload: dict[str, Any] | None = None,
    process_payload: dict[str, Any] | None = None,
    reconciliation_payload: dict[str, Any] | None = None,
    generated_at_unix: int = 0,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Dedicated entry point for building hygiene projection view."""
    return build_operational_truth_projection(
        tasks_payload=tasks_payload,
        attention_payload=attention_payload,
        resources_payload=resources_payload,
        checkout_payloads=checkout_payloads,
        repository_filters=repository_filters,
        tmux_payload=tmux_payload,
        process_payload=process_payload,
        reconciliation_payload=reconciliation_payload,
        generated_at_unix=generated_at_unix,
        view="hygiene",
        limit=limit,
        cursor=cursor,
    )


def reconcile_operational_truth(
    parameters: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Main reconciliation entry point for operational truth and hygiene."""
    params = dict(parameters or {})
    view = str(params.get("view") or "current")
    if view not in OPERATIONAL_TRUTH_VIEWS:
        raise OperationalTruthInputError(f"unsupported view: {view}")
    limit = int(params.get("limit") or DEFAULT_LIMIT)
    cursor = params.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
        raise OperationalTruthInputError("cursor must be a string when provided")

    return build_operational_truth_projection(
        view=view,
        limit=limit,
        cursor=cursor,
    )

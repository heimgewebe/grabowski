from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 1
MAX_WORKTREES = 256
MAX_RECONCILIATIONS = 100

InventoryLoader = Callable[[str], dict[str, Any]]
ReconciliationLoader = Callable[[str], dict[str, Any]]

CONVERGENCE_STATES = frozenset(
    {
        "cleanup_candidate",
        "completed_retained",
        "archived_blocked",
        "archived_grace",
        "archived_retained",
        "managed_active_attention",
        "managed_lifecycle_drift",
        "archive_drifted",
        "archive_closed",
        "blocked_unarchived",
        "prunable_or_missing",
        "unclassified_clean",
        "unobservable",
    }
)
HARD_BLOCK_CODES = frozenset(
    {
        "dirty-worktree",
        "dirty-state-unobservable",
        "foreign-live-coordination",
        "inventory-unobservable",
        "reconciliation-unobservable",
        "bounded-inventory-exceeded",
        "bounded-reconciliation-exceeded",
    }
)


class WorkAdmissionBlocked(RuntimeError):
    def __init__(self, assessment: dict[str, Any]):
        self.assessment = assessment
        codes = ", ".join(assessment.get("blocker_codes", [])) or "unknown"
        super().__init__(f"repository work admission blocked: {codes}")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _default_inventory(repo: str) -> dict[str, Any]:
    import grabowski_checkouts

    return grabowski_checkouts.checkout_inventory(
        repo,
        include_processes=True,
        include_tasks=True,
        include_resources=True,
    )


def _default_reconciliation(repo: str) -> dict[str, Any]:
    import grabowski_checkout_binding_reconciler
    import grabowski_checkouts

    if not grabowski_checkouts.CHECKOUT_DB.exists():
        material = {
            "bindings": [],
            "repository_filters": [repo],
            "source": "absent_checkout_database",
        }
        return {
            **material,
            "snapshot_sha256": _digest(material),
            "pagination": {"has_more": False},
            "source_snapshot": {"repository_errors": []},
        }
    return grabowski_checkout_binding_reconciler.reconcile_checkout_bindings(
        db_path=grabowski_checkouts.CHECKOUT_DB,
        repository_filters=[repo],
        limit=MAX_RECONCILIATIONS,
    )


def _owner_from_lifecycle(item: dict[str, Any]) -> str | None:
    lifecycle = item.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return None
    owners: set[str] = set()
    for key in ("retention", "binding", "latest_archive"):
        record = lifecycle.get(key)
        owner = record.get("owner_id") if isinstance(record, dict) else None
        if isinstance(owner, str) and owner:
            owners.add(owner)
    return next(iter(owners)) if len(owners) == 1 else None


def _source_binding(item: dict[str, Any]) -> tuple[str | None, str | None]:
    lifecycle = item.get("lifecycle")
    binding = lifecycle.get("binding") if isinstance(lifecycle, dict) else None
    if not isinstance(binding, dict):
        return None, None
    kind = binding.get("source_kind")
    identifier = binding.get("source_id")
    return (
        kind if isinstance(kind, str) and kind else None,
        identifier if isinstance(identifier, str) and identifier else None,
    )


def _foreign_coordination(item: dict[str, Any], owner_id: str) -> list[dict[str, Any]]:
    coordination = item.get("coordination")
    if not isinstance(coordination, dict):
        return []
    blockers: list[dict[str, Any]] = []
    for lease in coordination.get("resource_leases", []):
        if not isinstance(lease, dict) or not lease.get("blocking"):
            continue
        if lease.get("owner_id") == owner_id:
            continue
        blockers.append(
            {
                "kind": "resource_lease",
                "resource_key": lease.get("resource_key"),
                "owner_id": lease.get("owner_id"),
            }
        )
    for task in coordination.get("tasks", []):
        if not isinstance(task, dict):
            continue
        if task.get("lease_owner_id") == owner_id:
            continue
        blockers.append(
            {
                "kind": "task",
                "task_id": task.get("task_id"),
                "lease_owner_id": task.get("lease_owner_id"),
            }
        )
    current_pid = os.getpid()
    for process in coordination.get("processes", []):
        if not isinstance(process, dict) or process.get("pid") == current_pid:
            continue
        blockers.append({"kind": "process", "pid": process.get("pid")})
    return blockers


def assess_repository_admission(
    *,
    repo: str,
    owner_id: str,
    operation: str,
    requested_scope: dict[str, Any] | None = None,
    target_path: str | None = None,
    branch: str | None = None,
    source_kind: str | None = None,
    source_id: str | None = None,
    inventory_loader: InventoryLoader | None = None,
    reconciliation_loader: ReconciliationLoader | None = None,
) -> dict[str, Any]:
    repository = str(Path(repo).expanduser().resolve(strict=True))
    if not isinstance(owner_id, str) or not owner_id:
        raise ValueError("owner_id must be a non-empty string")
    if not isinstance(operation, str) or not operation:
        raise ValueError("operation must be a non-empty string")

    inventory_error: str | None = None
    reconciliation_error: str | None = None
    try:
        inventory = (inventory_loader or _default_inventory)(repository)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        inventory = {}
        inventory_error = f"{type(exc).__name__}: {exc}"
    try:
        reconciliation = (reconciliation_loader or _default_reconciliation)(repository)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        reconciliation = {}
        reconciliation_error = f"{type(exc).__name__}: {exc}"
    worktrees = inventory.get("worktrees") if isinstance(inventory, dict) else None
    bindings = reconciliation.get("bindings") if isinstance(reconciliation, dict) else None
    blockers: list[dict[str, Any]] = []

    if inventory_error is not None:
        blockers.append(
            {
                "code": "inventory-unobservable",
                "detail": inventory_error,
            }
        )
    if reconciliation_error is not None:
        blockers.append(
            {
                "code": "reconciliation-unobservable",
                "detail": reconciliation_error,
            }
        )

    if not isinstance(worktrees, list):
        blockers.append({"code": "inventory-unobservable", "detail": "worktree inventory is unavailable"})
        worktrees = []
    elif len(worktrees) > MAX_WORKTREES:
        blockers.append(
            {
                "code": "bounded-inventory-exceeded",
                "detail": f"worktree inventory exceeds {MAX_WORKTREES}",
            }
        )
        worktrees = worktrees[:MAX_WORKTREES]

    if not isinstance(bindings, list):
        blockers.append(
            {"code": "reconciliation-unobservable", "detail": "binding reconciliation is unavailable"}
        )
        bindings = []
    elif len(bindings) > MAX_RECONCILIATIONS:
        blockers.append(
            {
                "code": "bounded-reconciliation-exceeded",
                "detail": f"binding reconciliation exceeds {MAX_RECONCILIATIONS}",
            }
        )
        bindings = bindings[:MAX_RECONCILIATIONS]

    pagination = reconciliation.get("pagination") if isinstance(reconciliation, dict) else None
    source_snapshot = reconciliation.get("source_snapshot") if isinstance(reconciliation, dict) else None
    if isinstance(pagination, dict) and pagination.get("has_more"):
        blockers.append(
            {
                "code": "reconciliation-unobservable",
                "detail": "binding reconciliation is truncated",
            }
        )
    if isinstance(source_snapshot, dict) and source_snapshot.get("repository_errors"):
        blockers.append(
            {
                "code": "reconciliation-unobservable",
                "detail": "one or more repository observations failed",
            }
        )

    for item in worktrees:
        if not isinstance(item, dict):
            blockers.append({"code": "inventory-unobservable", "detail": "malformed worktree row"})
            continue
        path = str(item.get("path") or "")
        status = item.get("status") if isinstance(item.get("status"), dict) else {}
        dirty = status.get("dirty")
        if dirty is True:
            blockers.append({"code": "dirty-worktree", "path": path})
        elif dirty is not False:
            blockers.append({"code": "dirty-state-unobservable", "path": path})

        foreign = _foreign_coordination(item, owner_id)
        if foreign:
            blockers.append(
                {
                    "code": "foreign-live-coordination",
                    "path": path,
                    "coordination": foreign[:16],
                }
            )

        if item.get("is_main"):
            continue
        state = str(item.get("lifecycle_state") or "unobservable")
        lifecycle_owner = _owner_from_lifecycle(item)
        if state == "retained":
            if lifecycle_owner != owner_id:
                blockers.append(
                    {
                        "code": "foreign-retained-worktree",
                        "path": path,
                        "owner_id": lifecycle_owner,
                    }
                )
        elif state in CONVERGENCE_STATES:
            blockers.append(
                {
                    "code": "worktree-convergence-required",
                    "path": path,
                    "state": state,
                    "owner_id": lifecycle_owner,
                }
            )

        existing_source_kind, existing_source_id = _source_binding(item)
        if (
            source_id
            and existing_source_id == source_id
            and (source_kind is None or existing_source_kind == source_kind)
            and (target_path is None or path != target_path)
        ):
            blockers.append(
                {
                    "code": "similar-active-source-binding",
                    "path": path,
                    "source_kind": existing_source_kind,
                    "source_id": existing_source_id,
                }
            )
        if branch and item.get("branch") == branch and (target_path is None or path != target_path):
            blockers.append(
                {
                    "code": "branch-already-bound",
                    "path": path,
                    "branch": branch,
                }
            )

    for row in bindings:
        if not isinstance(row, dict):
            blockers.append(
                {"code": "reconciliation-unobservable", "detail": "malformed reconciliation row"}
            )
            continue
        if row.get("blocking"):
            blockers.append(
                {
                    "code": "binding-reconciliation-blocking",
                    "checkout_key": row.get("checkout_key"),
                    "state": row.get("state"),
                    "reasons": list(row.get("reasons") or [])[:16],
                }
            )

    blocker_codes = sorted({str(item["code"]) for item in blockers})
    hard_blocked = any(code in HARD_BLOCK_CODES or code.startswith("foreign-") for code in blocker_codes)
    decision = "blocked" if hard_blocked else "converge_first" if blockers else "allow"
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski.repository_work_admission",
        "repository": repository,
        "owner_id": owner_id,
        "operation": operation,
        "requested_scope": requested_scope,
        "target_path": target_path,
        "branch": branch,
        "source": {"kind": source_kind, "id": source_id},
        "decision": decision,
        "blocker_codes": blocker_codes,
        "blockers": blockers,
        "inventory_sha256": inventory.get("inventory_sha256") if isinstance(inventory, dict) else None,
        "reconciliation_sha256": reconciliation.get("snapshot_sha256") if isinstance(reconciliation, dict) else None,
        "read_only": True,
        "next_action": (
            "run bounded worktree lifecycle convergence before opening the broad lane"
            if decision == "converge_first"
            else "resolve dirty, unobservable or foreign live overlap before retry"
            if decision == "blocked"
            else "admission preflight passed"
        ),
        "does_not_establish": [
            "mutation authority",
            "cleanup authority",
            "permission to override foreign ownership",
            "global one-lane serialization for exact disjoint resource keys",
        ],
    }
    return {**material, "assessment_sha256": _digest(material)}


def require_repository_admission(
    *,
    mode: str = "normal",
    **kwargs: Any,
) -> dict[str, Any]:
    if mode not in {"normal", "convergence"}:
        raise ValueError("work admission mode must be normal or convergence")
    assessment = assess_repository_admission(**kwargs)
    decision = assessment["decision"]
    if decision == "blocked" or (decision == "converge_first" and mode != "convergence"):
        raise WorkAdmissionBlocked(assessment)
    return assessment

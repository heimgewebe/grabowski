from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable

import grabowski_convergence as convergence
import grabowski_nonconflict as nonconflict

SCHEMA_VERSION = 1
MAX_WORKTREES = 256
MAX_RECONCILIATIONS = 100

InventoryLoader = Callable[[str], dict[str, Any]]
ReconciliationLoader = Callable[[str], dict[str, Any]]
ReposkopContextLoader = Callable[[str, str], dict[str, Any]]
ConvergencePlanner = Callable[[dict[str, Any] | None], dict[str, Any]]

CONVERGENCE_STATES = frozenset(
    {
        "cleanup_candidate",
        "completed_retained",
        "completed_retained_blocked",
        "archived_blocked",
        "archived_grace",
        "archived_retained",
        "archived_not_remote_secured",
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
TERMINAL_NONBLOCKING_STATES = frozenset({"externally_terminal_missing"})
HARD_BLOCK_CODES = frozenset(
    {
        "dirty-worktree",
        "dirty-state-unobservable",
        "foreign-live-coordination",
        "inventory-unobservable",
        "reconciliation-unobservable",
        "bounded-inventory-exceeded",
        "bounded-reconciliation-exceeded",
        "lifecycle-owner-ambiguous",
        "reposkop-context-unavailable",
    }
)
SOURCE_CACHE_ROOT_NAMES = frozenset({".repobrief-sources", ".repoground-sources"})
SOURCE_CACHE_OWNER_PREFIXES = (
    "system:repobrief-source-cache:",
    "system:repoground-source-cache:",
)
SCOPED_CHECKOUT_OPERATIONS = frozenset(
    {"worktree_create", "agent_workspace_create", "broad_repository_lease"}
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


def plan_system_convergence(
    context: dict[str, Any] | None,
    *,
    planner: ConvergencePlanner | None = None,
) -> dict[str, Any]:
    try:
        return (planner or convergence.build_system_convergence_plan)(context)
    except convergence.ConvergenceExecutionError as exc:
        material = {
            "schema_version": 1,
            "kind": "grabowski.system_convergence_plan",
            "status": "unavailable",
            "change_risk": (context or {}).get("change_risk") if isinstance(context, dict) else None,
            "target_criticality": (context or {}).get("target_criticality") if isinstance(context, dict) else None,
            "protocol_head": (context or {}).get("expected_protocol_head") if isinstance(context, dict) else None,
            "profile_id": None,
            "profile_cell_id": None,
            "profile_sha256": None,
            "protocol_source": None,
            "required_effects": [],
            "required_verifications": [],
            "required_closure_fields": [],
            "requires_resilience_evidence": None,
            "requires_independent_recovery": None,
            "systemic_closure_gate": "unavailable",
            "hard_gate_required": None,
            "criticality_resolution_required": bool(
                isinstance(context, dict)
                and context.get("change_risk") in {"R2", "R3"}
                and context.get("target_criticality") == "unknown"
            ),
            "admission_blocking": False,
            "planning_error": f"{type(exc).__name__}: {exc}"[:2048],
            "next_action": "restore the pinned convergence bundle before claiming systemic convergence",
            "does_not_establish": [
                "task state",
                "execution authority",
                "merge authorization",
                "deployment truth",
                "systemic convergence",
            ],
        }
        return {**material, "plan_sha256": _digest(material)}


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



def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _reposkop_purpose(operation: str) -> str:
    operation_sha256 = hashlib.sha256(operation.encode("utf-8")).hexdigest()
    readable = re.sub(
        r"[^a-z0-9._-]+",
        "-",
        operation.strip().lower(),
    ).strip("-._")
    return (
        f"grabowski-work-admission:{(readable or 'operation')[:32]}:"
        f"{operation_sha256[:8]}"
    )


def _default_reposkop_context(repo: str, purpose: str) -> dict[str, Any]:
    import grabowski_reposkop_context

    return grabowski_reposkop_context.grabowski_reposkop_context(repo, purpose)


def _reposkop_context_evidence(
    result: Any,
    *,
    repository: str,
    purpose: str,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ValueError("Reposkop context result must be an object")
    if (
        result.get("schema_version") != 2
        or result.get("kind") != "grabowski_reposkop_context"
        or result.get("effect_authorized") is not False
    ):
        raise ValueError("Reposkop context result contract mismatch")

    target = result.get("target")
    if not isinstance(target, dict) or target != {
        "path": repository,
        "purpose": purpose,
    }:
        raise ValueError("Reposkop context target binding mismatch")

    executable = result.get("reposkop")
    report = result.get("report")
    usage_receipt = result.get("usage_receipt")
    if not isinstance(executable, dict) or not _is_sha256(executable.get("sha256")):
        raise ValueError("Reposkop executable identity is missing")
    if (
        not isinstance(report, dict)
        or report.get("kind") != "reposkop_coherence_report"
        or report.get("schema_version") != 2
        or report.get("effect_authorized") is not False
        or not _is_sha256(report.get("report_sha256"))
    ):
        raise ValueError("Reposkop report contract mismatch")

    observation = report.get("observation")
    projection = report.get("projection")
    identities = observation.get("identities") if isinstance(observation, dict) else None
    if (
        not isinstance(observation, dict)
        or observation.get("observation_complete") is not True
        or not _is_sha256(observation.get("observation_sha256"))
        or not isinstance(identities, dict)
        or identities.get("path") != repository
        or identities.get("purpose") != purpose
        or not _is_sha256(identities.get("repository_identity_sha256"))
        or not _is_sha256(identities.get("checkout_identity_sha256"))
    ):
        raise ValueError("Reposkop observation identity mismatch")
    if (
        not isinstance(projection, dict)
        or projection.get("effect_authorized") is not False
        or not _is_sha256(projection.get("projection_sha256"))
    ):
        raise ValueError("Reposkop projection contract mismatch")
    if (
        not isinstance(usage_receipt, dict)
        or not isinstance(usage_receipt.get("path"), str)
        or not usage_receipt["path"]
        or not _is_sha256(usage_receipt.get("sha256"))
        or not _is_sha256(usage_receipt.get("usage_key_sha256"))
        or not isinstance(usage_receipt.get("audit_ref"), str)
        or not usage_receipt["audit_ref"]
    ):
        raise ValueError("Reposkop usage receipt contract mismatch")

    return {
        "required": True,
        "status": "verified",
        "purpose": purpose,
        "reposkop_executable_sha256": executable["sha256"],
        "report_sha256": report["report_sha256"],
        "observation_sha256": observation["observation_sha256"],
        "projection_sha256": projection["projection_sha256"],
        "repository_identity_sha256": identities["repository_identity_sha256"],
        "checkout_identity_sha256": identities["checkout_identity_sha256"],
        "usage_receipt_path": usage_receipt["path"],
        "usage_receipt_sha256": usage_receipt["sha256"],
        "usage_key_sha256": usage_receipt["usage_key_sha256"],
        "audit_ref": usage_receipt["audit_ref"],
        "effect_authorized": False,
    }


def _with_reposkop_context(
    assessment: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    material = {
        key: value
        for key, value in assessment.items()
        if key != "assessment_sha256"
    }
    material.update(
        {
            "read_only": False,
            "evidence_mutation_only": True,
            "reposkop_context": evidence,
            "next_action": "admission preflight and Reposkop evidence binding passed",
        }
    )
    return {**material, "assessment_sha256": _digest(material)}


def _bounded_upstream_admission(assessment: Any) -> dict[str, Any]:
    if not isinstance(assessment, dict):
        return {"assessment_present": False}
    evidence: dict[str, Any] = {"assessment_present": True}
    for key, limit in (
        ("kind", 128),
        ("repository", 1024),
        ("operation", 256),
        ("decision", 64),
    ):
        value = assessment.get(key)
        if isinstance(value, str) and value:
            evidence[key] = value[:limit]
    schema_version = assessment.get("schema_version")
    if isinstance(schema_version, int) and not isinstance(schema_version, bool):
        evidence["schema_version"] = schema_version
    assessment_sha256 = assessment.get("assessment_sha256")
    if _is_sha256(assessment_sha256):
        evidence["assessment_sha256"] = assessment_sha256
    blocker_codes = assessment.get("blocker_codes")
    if isinstance(blocker_codes, list):
        evidence["blocker_codes"] = [
            value[:128]
            for value in blocker_codes[:16]
            if isinstance(value, str) and value
        ]
    blockers: list[dict[str, str]] = []
    raw_blockers = assessment.get("blockers")
    if isinstance(raw_blockers, list):
        for raw in raw_blockers[:8]:
            if not isinstance(raw, dict):
                continue
            bounded: dict[str, str] = {}
            for key, limit in (
                ("code", 128),
                ("detail", 1024),
                ("path", 1024),
                ("state", 128),
                ("checkout_key", 256),
            ):
                value = raw.get(key)
                if isinstance(value, str) and value:
                    bounded[key] = value[:limit]
            if bounded:
                blockers.append(bounded)
    if blockers:
        evidence["blockers"] = blockers
    return evidence


def _reposkop_blocked_assessment(
    assessment: dict[str, Any],
    *,
    purpose: str,
    error: BaseException,
    upstream_admission: dict[str, Any] | None = None,
) -> dict[str, Any]:
    material = {
        key: value
        for key, value in assessment.items()
        if key != "assessment_sha256"
    }
    blocker = {
        "code": "reposkop-context-unavailable",
        "detail": f"{type(error).__name__}: {error}"[:2048],
    }
    reposkop_context: dict[str, Any] = {
        "required": True,
        "status": "blocked",
        "purpose": purpose,
        "effect_authorized": False,
    }
    if upstream_admission is not None:
        reposkop_context["upstream_admission"] = upstream_admission
    material.update(
        {
            "decision": "blocked",
            "blocker_codes": sorted(
                set(material.get("blocker_codes", [])) | {blocker["code"]}
            ),
            "blockers": [*material.get("blockers", []), blocker],
            "read_only": False,
            "evidence_mutation_only": True,
            "reposkop_context": reposkop_context,
            "next_action": "restore a valid target-bound Reposkop context before retry",
        }
    )
    return {**material, "assessment_sha256": _digest(material)}


def _lifecycle_owners(item: dict[str, Any]) -> set[str]:
    lifecycle = item.get("lifecycle")
    if not isinstance(lifecycle, dict):
        return set()
    owners: set[str] = set()
    for key in ("retention", "binding", "latest_archive"):
        record = lifecycle.get(key)
        owner = record.get("owner_id") if isinstance(record, dict) else None
        if isinstance(owner, str) and owner:
            owners.add(owner)
    return owners


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


def _inert_checkout_for_admission(item: dict[str, Any], *, state: str) -> bool:
    """Ignore only clean checkouts whose lifecycle cannot represent live work."""
    status = item.get("status")
    if not isinstance(status, dict) or status.get("dirty") is not False:
        return False
    coordination = item.get("coordination")
    if not isinstance(coordination, dict) or coordination.get("blocking") is True:
        return False
    for key in ("resource_leases", "tasks", "processes"):
        value = coordination.get(key)
        if not isinstance(value, list) or value:
            return False
    lifecycle = item.get("lifecycle")
    if not isinstance(lifecycle, dict) or isinstance(lifecycle.get("binding"), dict):
        return False
    owners = _lifecycle_owners(item)
    if len(owners) > 1:
        return False

    archive = lifecycle.get("latest_archive")
    archive_open = (
        isinstance(archive, dict)
        and archive.get("cleaned_at_unix") is None
        and isinstance(archive.get("archive_id"), str)
        and bool(archive["archive_id"])
    )
    if state in {
        "archived_grace",
        "archived_retained",
        "archived_not_remote_secured",
    }:
        return archive_open

    path = item.get("path")
    source_cache = (
        item.get("detached") is True
        and item.get("branch") is None
        and isinstance(path, str)
        and bool(SOURCE_CACHE_ROOT_NAMES.intersection(Path(path).parts))
    )
    if not source_cache:
        return False
    if state == "unclassified_clean":
        return not owners
    if state != "retained":
        return False
    retention = lifecycle.get("retention")
    owner_id = retention.get("owner_id") if isinstance(retention, dict) else None
    return isinstance(owner_id, str) and owner_id.startswith(
        SOURCE_CACHE_OWNER_PREFIXES
    )


def _canonical_checkout_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        path = Path(value).expanduser()
        if not path.is_absolute():
            return None
        return str(path.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return None


def _same_checkout_path(left: Any, right: Any) -> bool:
    canonical_left = _canonical_checkout_path(left)
    canonical_right = _canonical_checkout_path(right)
    return (
        canonical_left is not None
        and canonical_right is not None
        and canonical_left == canonical_right
    )


def _checkout_paths_overlap(left: Any, right: Any) -> bool:
    canonical_left = _canonical_checkout_path(left)
    canonical_right = _canonical_checkout_path(right)
    if canonical_left is None or canonical_right is None:
        return False
    left_path = Path(canonical_left)
    right_path = Path(canonical_right)
    return (
        left_path == right_path
        or left_path in right_path.parents
        or right_path in left_path.parents
    )


def _safe_relative_paths(value: Any, *, require_nonempty: bool) -> bool:
    if not isinstance(value, list) or (require_nonempty and not value):
        return False
    for item in value:
        if not isinstance(item, str) or not item:
            return False
        path = Path(item)
        if path == Path(".") or path.is_absolute() or ".." in path.parts:
            return False
    return True


def _exact_checkout_scope(
    *,
    repository: str,
    operation: str,
    requested_scope: dict[str, Any] | None,
    target_path: str | None,
    branch: str | None,
) -> dict[str, str] | None:
    if operation not in SCOPED_CHECKOUT_OPERATIONS or not isinstance(
        requested_scope, dict
    ):
        return None

    scope_contract = requested_scope
    if operation == "broad_repository_lease":
        try:
            scope_contract = nonconflict.normalize_scope_manifest(requested_scope)
        except ValueError:
            return None
        effects = set(scope_contract["effects"])
        nonlocal_axes = (
            "components",
            "runtime_resources",
            "processes",
            "deployments",
            "migrations",
            "shared_gates",
        )
        if (
            scope_contract["repository"] != repository
            or not effects
            or not effects <= {"read", "write", "generate"}
            or any(scope_contract[axis] for axis in nonlocal_axes)
            or (
                bool(effects - {"read"})
                and not (
                    scope_contract["paths"]
                    or scope_contract["generated_artifacts"]
                )
            )
        ):
            return None
        scope_target = scope_contract["worktree"]
        scope_branch = scope_contract["branch"]
    else:
        scope_target = target_path
        scope_branch = branch

    if (
        not isinstance(scope_branch, str)
        or not scope_branch
        or scope_contract.get("branch") != scope_branch
        or (branch is not None and branch != scope_branch)
    ):
        return None
    canonical_target = _canonical_checkout_path(scope_target)
    if (
        canonical_target is None
        or (target_path is not None and not _same_checkout_path(target_path, canonical_target))
        or _checkout_paths_overlap(repository, canonical_target)
    ):
        return None

    if operation == "worktree_create":
        paths = scope_contract.get("paths")
        if not (
            isinstance(paths, list)
            and len(paths) == 1
            and _same_checkout_path(paths[0], canonical_target)
        ):
            return None
    elif operation == "agent_workspace_create":
        if not (
            _safe_relative_paths(
                scope_contract.get("allowed_paths"), require_nonempty=True
            )
            and _safe_relative_paths(
                scope_contract.get("forbidden_paths"), require_nonempty=False
            )
        ):
            return None

    return {"target_path": canonical_target, "branch": scope_branch}


def _normalized_source_kind(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.strip().lower().replace("_", "-")


def _reconciliation_overlaps_scope(
    row: dict[str, Any],
    *,
    target_path: str | None,
    branch: str | None,
    source_kind: str | None,
    source_id: str | None,
) -> bool:
    observed_checkout_path = False
    for key in ("binding_identity", "worktree_identity"):
        identity = row.get(key)
        if identity is None:
            continue
        if not isinstance(identity, dict):
            return True
        raw_path = identity.get("checkout_path")
        if raw_path is not None:
            observed_path = _canonical_checkout_path(raw_path)
            if observed_path is None:
                return True
            observed_checkout_path = True
            if target_path is not None and _checkout_paths_overlap(
                observed_path, target_path
            ):
                return True
        for observed_branch in (
            identity.get("expected_branch"),
            identity.get("branch"),
        ):
            if observed_branch is None:
                continue
            if not isinstance(observed_branch, str) or not observed_branch:
                return True
            if branch and observed_branch == branch:
                return True

    evidence = row.get("evidence")
    if evidence is not None and not isinstance(evidence, dict):
        return True
    source = evidence.get("source") if isinstance(evidence, dict) else None
    if source is not None and not isinstance(source, dict):
        return True
    if isinstance(source, dict):
        observed_source_id = source.get("id")
        observed_kind = _normalized_source_kind(source.get("kind"))
        if isinstance(observed_source_id, str) and observed_source_id:
            if source_id and observed_source_id == source_id:
                requested_kind = _normalized_source_kind(source_kind)
                return (
                    requested_kind is None
                    or observed_kind is None
                    or requested_kind == observed_kind
                )
        elif observed_source_id is not None:
            return True

    return not observed_checkout_path


def _foreign_coordination(item: dict[str, Any], owner_id: str) -> list[dict[str, Any]]:
    coordination = item.get("coordination")
    if not isinstance(coordination, dict):
        return []
    blockers: list[dict[str, Any]] = []
    same_owner_units: set[str] = set()
    same_owner_pids: set[int] = set()
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
            same_owner_units.update(
                unit
                for unit in (
                    task.get("unit"),
                    task.get("authoritative_unit"),
                )
                if isinstance(unit, str) and unit
            )
            for key in ("pid", "main_pid", "worker_pid"):
                pid = task.get(key)
                if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
                    same_owner_pids.add(pid)
            pids = task.get("pids")
            if isinstance(pids, list):
                same_owner_pids.update(
                    pid
                    for pid in pids
                    if isinstance(pid, int)
                    and not isinstance(pid, bool)
                    and pid > 0
                )
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
        if not isinstance(process, dict):
            continue
        pid = process.get("pid")
        if pid == current_pid or pid in same_owner_pids:
            continue
        process_units: set[str] = set()
        systemd_unit = process.get("systemd_unit")
        if isinstance(systemd_unit, str) and systemd_unit:
            process_units.add(systemd_unit)
        systemd_units = process.get("systemd_units")
        if isinstance(systemd_units, list):
            process_units.update(
                unit
                for unit in systemd_units
                if isinstance(unit, str) and unit
            )
        if process_units & same_owner_units:
            continue
        blockers.append({"kind": "process", "pid": pid})
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
    system_convergence: dict[str, Any] | None = None,
    convergence_planner: ConvergencePlanner | None = None,
) -> dict[str, Any]:
    repository = str(Path(repo).expanduser().resolve(strict=True))
    if not isinstance(owner_id, str) or not owner_id:
        raise ValueError("owner_id must be a non-empty string")
    if not isinstance(operation, str) or not operation:
        raise ValueError("operation must be a non-empty string")
    system_convergence_plan = plan_system_convergence(
        system_convergence, planner=convergence_planner
    )
    exact_checkout_scope = _exact_checkout_scope(
        repository=repository,
        operation=operation,
        requested_scope=requested_scope,
        target_path=target_path,
        branch=branch,
    )
    effective_target_path = (
        exact_checkout_scope["target_path"]
        if exact_checkout_scope is not None
        else target_path
    )
    effective_branch = (
        exact_checkout_scope["branch"]
        if exact_checkout_scope is not None
        else branch
    )

    inventory_error: str | None = None
    reconciliation_error: str | None = None
    try:
        inventory = (inventory_loader or _default_inventory)(repository)
    except (
        ImportError, OSError, RuntimeError, ValueError, sqlite3.Error
    ) as exc:
        inventory = {}
        inventory_error = f"{type(exc).__name__}: {exc}"
    try:
        reconciliation = (reconciliation_loader or _default_reconciliation)(repository)
    except (
        ImportError, OSError, RuntimeError, ValueError, sqlite3.Error
    ) as exc:
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
    elif len(worktrees) > MAX_WORKTREES and exact_checkout_scope is None:
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
        canonical_path = _canonical_checkout_path(path)
        if exact_checkout_scope is not None and canonical_path is None:
            blockers.append(
                {
                    "code": "inventory-unobservable",
                    "detail": "worktree path is not an absolute observable path",
                    "path": path,
                }
            )
            continue
        scope_relevant = (
            exact_checkout_scope is None
            or _checkout_paths_overlap(canonical_path, effective_target_path)
        )
        status = item.get("status") if isinstance(item.get("status"), dict) else {}
        dirty = status.get("dirty")
        if scope_relevant:
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
        lifecycle_owners = _lifecycle_owners(item)
        lifecycle_owner = (
            next(iter(lifecycle_owners)) if len(lifecycle_owners) == 1 else None
        )
        requested_target_checkout = (
            source_kind == "expired_same_owner_lease"
            and isinstance(source_id, str)
            and len(source_id) == 64
            and effective_target_path is not None
            and _same_checkout_path(path, effective_target_path)
            and isinstance(requested_scope, dict)
            and requested_scope.get("repository") == repository
            and requested_scope.get("worktree") == path
            and requested_scope.get("branch") == effective_branch
            and item.get("branch") == effective_branch
            and requested_scope.get("head") == item.get("head")
        )
        inert_checkout = _inert_checkout_for_admission(item, state=state)
        if scope_relevant and not inert_checkout and not requested_target_checkout:
            if len(lifecycle_owners) > 1:
                blockers.append(
                    {
                        "code": "lifecycle-owner-ambiguous",
                        "path": path,
                        "state": state,
                        "owner_ids": sorted(lifecycle_owners),
                    }
                )
            if state == "retained":
                if lifecycle_owner != owner_id:
                    blockers.append(
                        {
                            "code": "foreign-retained-worktree",
                            "path": path,
                            "owner_id": lifecycle_owner,
                        }
                    )
            elif state in TERMINAL_NONBLOCKING_STATES:
                # Source- and CAS-bound terminal evidence is not live work and
                # creates no cleanup authority. Dirty state, ambiguous ownership
                # and live coordination remain independently blocking above.
                pass
            elif state in CONVERGENCE_STATES:
                if lifecycle_owner is not None and lifecycle_owner != owner_id:
                    blockers.append(
                        {
                            "code": "foreign-lifecycle-owner",
                            "path": path,
                            "state": state,
                            "owner_id": lifecycle_owner,
                        }
                    )
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
            and (
                effective_target_path is None
                or not _same_checkout_path(path, effective_target_path)
            )
            and state not in TERMINAL_NONBLOCKING_STATES
        ):
            blockers.append(
                {
                    "code": "similar-active-source-binding",
                    "path": path,
                    "source_kind": existing_source_kind,
                    "source_id": existing_source_id,
                }
            )
        if (
            effective_branch
            and item.get("branch") == effective_branch
            and (
                effective_target_path is None
                or not _same_checkout_path(path, effective_target_path)
            )
        ):
            blockers.append(
                {
                    "code": "branch-already-bound",
                    "path": path,
                    "branch": effective_branch,
                }
            )

    for row in bindings:
        if not isinstance(row, dict):
            blockers.append(
                {"code": "reconciliation-unobservable", "detail": "malformed reconciliation row"}
            )
            continue
        if row.get("blocking") and (
            exact_checkout_scope is None
            or _reconciliation_overlaps_scope(
                row,
                target_path=effective_target_path,
                branch=effective_branch,
                source_kind=source_kind,
                source_id=source_id,
            )
        ):
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
        "scope_mode": (
            "exact_checkout" if exact_checkout_scope is not None else "repository"
        ),
        "scope_identity": exact_checkout_scope,
        "requested_scope": requested_scope,
        "target_path": target_path,
        "branch": branch,
        "source": {"kind": source_kind, "id": source_id},
        "system_convergence_plan": system_convergence_plan,
        "decision": decision,
        "blocker_codes": blocker_codes,
        "blockers": blockers,
        "inventory_sha256": inventory.get("inventory_sha256") if isinstance(inventory, dict) else None,
        "reconciliation_sha256": reconciliation.get("snapshot_sha256") if isinstance(reconciliation, dict) else None,
        "read_only": True,
        "next_action": (
            "resolve target, branch or source overlap before retry"
            if exact_checkout_scope is not None and decision != "allow"
            else "run bounded worktree lifecycle convergence before opening the broad lane"
            if decision == "converge_first"
            else "resolve dirty, unobservable or foreign live overlap before retry"
            if decision == "blocked"
            else "exact checkout scope is disjoint; unrelated repository hygiene remains outside this lane"
            if exact_checkout_scope is not None
            else "admission preflight passed"
        ),
        "does_not_establish": [
            "mutation authority",
            "cleanup authority",
            "permission to override foreign ownership",
            "global one-lane serialization for exact disjoint resource keys",
            "absence of later semantic or merge conflicts between isolated branches",
            "systemic convergence completion",
        ],
    }
    return {**material, "assessment_sha256": _digest(material)}


def require_repository_admission(
    *,
    mode: str = "normal",
    reposkop_required: bool = False,
    reposkop_context_loader: ReposkopContextLoader | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if mode not in {"normal", "convergence"}:
        raise ValueError("work admission mode must be normal or convergence")
    if not isinstance(reposkop_required, bool):
        raise ValueError("reposkop_required must be a boolean")
    assessment = assess_repository_admission(**kwargs)
    decision = assessment["decision"]
    if decision == "blocked" or (
        decision == "converge_first" and mode != "convergence"
    ):
        raise WorkAdmissionBlocked(assessment)
    if not reposkop_required:
        return assessment

    purpose = _reposkop_purpose(str(assessment["operation"]))
    try:
        result = (reposkop_context_loader or _default_reposkop_context)(
            str(assessment["repository"]),
            purpose,
        )
        evidence = _reposkop_context_evidence(
            result,
            repository=str(assessment["repository"]),
            purpose=purpose,
        )
    except WorkAdmissionBlocked as exc:
        blocked = _reposkop_blocked_assessment(
            assessment,
            purpose=purpose,
            error=exc,
            upstream_admission=_bounded_upstream_admission(exc.assessment),
        )
        raise WorkAdmissionBlocked(blocked) from exc
    except Exception as exc:
        blocked = _reposkop_blocked_assessment(
            assessment,
            purpose=purpose,
            error=exc,
        )
        raise WorkAdmissionBlocked(blocked) from exc
    return _with_reposkop_context(assessment, evidence)

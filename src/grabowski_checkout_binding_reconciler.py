from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


RECONCILER_SCHEMA_VERSION = 1
RECONCILER_STATES = frozenset(
    {
        "bound_present",
        "orphaned_binding",
        "repository_unobservable",
        "binding_identity_drift",
    }
)
MAX_EVIDENCE = 32


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _identity(record: Mapping[str, Any]) -> dict[str, str | None]:
    return {
        "checkout_key": _text(record.get("checkout_key")),
        "repo_common_dir": _text(record.get("repo_common_dir")),
        "repo_path": _text(record.get("repo_path")),
        "checkout_path": _text(record.get("checkout_path") or record.get("path")),
        "expected_branch": _text(record.get("expected_branch") or record.get("branch")),
    }


def _evidence(binding: Mapping[str, Any]) -> dict[str, Any]:
    retention = binding.get("retention")
    archive = binding.get("latest_archive")
    return {
        "owner_id": _text(binding.get("owner_id")),
        "phase": _text(binding.get("phase")),
        "expected_head": _text(binding.get("expected_head")),
        "retention": (
            {
                "owner_id": _text(retention.get("owner_id")),
                "retention_until_unix": _integer(retention.get("retention_until_unix")),
                "expected_head": _text(retention.get("expected_head")),
            }
            if isinstance(retention, Mapping)
            else None
        ),
        "archive": (
            {
                "archive_id": _text(archive.get("archive_id")),
                "owner_id": _text(archive.get("owner_id")),
                "created_at_unix": _integer(archive.get("created_at_unix")),
                "cleaned_at_unix": _integer(archive.get("cleaned_at_unix")),
            }
            if isinstance(archive, Mapping)
            else None
        ),
    }


def reconcile_binding(
    binding: Mapping[str, Any],
    worktree: Mapping[str, Any] | None,
    *,
    repository_observable: bool,
) -> dict[str, Any]:
    """Classify one durable binding without granting repair or cleanup authority."""
    binding_identity = _identity(binding)
    reasons: list[str] = []

    if not repository_observable:
        state = "repository_unobservable"
        reasons.append("repository-state-unobservable")
    elif worktree is None:
        state = "orphaned_binding"
        reasons.append("binding-has-no-current-git-worktree-record")
    else:
        worktree_identity = _identity(worktree)
        for field in (
            "checkout_key",
            "repo_common_dir",
            "repo_path",
            "checkout_path",
            "expected_branch",
        ):
            if binding_identity[field] != worktree_identity[field]:
                reasons.append(f"{field.replace('_', '-')}-mismatch")
        phase = _text(binding.get("phase"))
        expected_head = _text(binding.get("expected_head"))
        current_head = _text(worktree.get("head"))
        if phase in {"completed_retained", "archived"} and expected_head != current_head:
            reasons.append("terminal-head-mismatch")
        state = "binding_identity_drift" if reasons else "bound_present"

    blocking = state != "bound_present"
    return {
        "schema_version": RECONCILER_SCHEMA_VERSION,
        "checkout_key": binding_identity["checkout_key"],
        "state": state,
        "blocking": blocking,
        "reasons": sorted(set(reasons))[:MAX_EVIDENCE],
        "binding_identity": binding_identity,
        "worktree_identity": _identity(worktree) if worktree is not None else None,
        "evidence": _evidence(binding),
        "recommended_next_step": {
            "bound_present": "use_existing_checkout_lifecycle_projection",
            "orphaned_binding": "inspect_git_and_binding_history_without_mutation",
            "repository_unobservable": "restore_repository_observability_before_decision",
            "binding_identity_drift": "reconcile_binding_identity_before_lifecycle_action",
        }[state],
        "does_not_establish": [
            "permission_to_archive",
            "permission_to_cleanup",
            "permission_to_delete_binding",
            "permission_to_delete_branch",
            "permission_to_terminalize",
            "checkout_absence_as_cleanup_proof",
        ],
    }


def reconcile_bindings(
    bindings: Iterable[Mapping[str, Any]],
    worktrees: Iterable[Mapping[str, Any]],
    *,
    observable_repo_paths: Iterable[str],
) -> dict[str, Any]:
    """Return a deterministic, bounded reconciliation projection."""
    worktree_by_key = {
        key: row
        for row in worktrees
        if (key := _text(row.get("checkout_key"))) is not None
    }
    observable = set(observable_repo_paths)
    rows = []
    for binding in bindings:
        repo_path = _text(binding.get("repo_path"))
        key = _text(binding.get("checkout_key"))
        rows.append(
            reconcile_binding(
                binding,
                worktree_by_key.get(key) if key is not None else None,
                repository_observable=repo_path in observable if repo_path is not None else False,
            )
        )
    rows.sort(key=lambda row: (str(row.get("checkout_key") or ""), row["state"]))
    summary = {state: 0 for state in sorted(RECONCILER_STATES)}
    for row in rows:
        summary[row["state"]] += 1
    return {
        "schema_version": RECONCILER_SCHEMA_VERSION,
        "kind": "grabowski_checkout_binding_reconciliation",
        "count": len(rows),
        "summary": summary,
        "blocking_count": sum(1 for row in rows if row["blocking"]),
        "bindings": rows,
        "read_only": True,
        "does_not_establish": [
            "permission_to_repair",
            "permission_to_archive",
            "permission_to_cleanup",
            "permission_to_delete_binding",
            "permission_to_delete_branch",
        ],
    }

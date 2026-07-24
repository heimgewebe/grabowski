from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
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
LIFECYCLE_PHASES = frozenset({"active", "completed_retained", "archived"})
REQUIRED_BINDING_FIELDS = (
    "checkout_key",
    "repo_common_dir",
    "repo_path",
    "checkout_path",
    "owner_id",
)
REQUIRED_WORKTREE_FIELDS = (
    "checkout_key",
    "repo_common_dir",
    "repo_path",
    "checkout_path",
    "head",
)


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
        "owner_id": _text(record.get("owner_id")),
        "expected_branch": _text(record.get("expected_branch") or record.get("branch")),
        "head": _text(record.get("expected_head") or record.get("head")),
    }


def _missing_fields(
    identity: Mapping[str, str | None], required_fields: Iterable[str]
) -> list[str]:
    return sorted(field for field in required_fields if identity.get(field) is None)


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
    ambiguity_reasons: Iterable[str] = (),
) -> dict[str, Any]:
    """Classify one durable binding without granting repair or cleanup authority."""
    binding_identity = _identity(binding)
    reasons = [
        f"missing-binding-{field.replace('_', '-')}"
        for field in _missing_fields(binding_identity, REQUIRED_BINDING_FIELDS)
    ]
    phase = _text(binding.get("phase"))
    if phase not in LIFECYCLE_PHASES:
        reasons.append("binding-phase-invalid")
    reasons.extend(reason for reason in ambiguity_reasons if isinstance(reason, str) and reason)

    worktree_identity = _identity(worktree) if worktree is not None else None
    if reasons:
        state = "binding_identity_drift"
    elif not repository_observable:
        state = "repository_unobservable"
        reasons.append("repository-state-unobservable")
    elif worktree is None:
        state = "orphaned_binding"
        reasons.append("binding-has-no-current-git-worktree-record")
    else:
        assert worktree_identity is not None
        reasons.extend(
            f"missing-worktree-{field.replace('_', '-')}"
            for field in _missing_fields(worktree_identity, REQUIRED_WORKTREE_FIELDS)
        )
        for field in (
            "checkout_key",
            "repo_common_dir",
            "repo_path",
            "checkout_path",
            "expected_branch",
        ):
            if binding_identity[field] != worktree_identity[field]:
                reasons.append(f"{field.replace('_', '-')}-mismatch")
        if phase in {"completed_retained", "archived"}:
            expected_head = _text(binding.get("expected_head"))
            current_head = _text(worktree.get("head"))
            if expected_head is None:
                reasons.append("missing-binding-expected-head")
            elif current_head is not None and expected_head != current_head:
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
        "worktree_identity": worktree_identity,
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
    worktrees_by_key: dict[str, list[Mapping[str, Any]]] = {}
    unkeyed_worktrees: list[Mapping[str, Any]] = []
    for worktree in worktrees:
        key = _text(worktree.get("checkout_key"))
        if key is None:
            unkeyed_worktrees.append(worktree)
        else:
            worktrees_by_key.setdefault(key, []).append(worktree)
    binding_rows = list(bindings)
    binding_key_counts: dict[str, int] = {}
    for binding in binding_rows:
        key = _text(binding.get("checkout_key"))
        if key is not None:
            binding_key_counts[key] = binding_key_counts.get(key, 0) + 1
    observable = set(observable_repo_paths)
    rows = []
    for binding in binding_rows:
        repo_path = _text(binding.get("repo_path"))
        key = _text(binding.get("checkout_key"))
        matching_worktrees = worktrees_by_key.get(key, []) if key is not None else []
        ambiguity_reasons = []
        if key is not None and binding_key_counts.get(key, 0) > 1:
            ambiguity_reasons.append("duplicate-binding-checkout-key")
        if len(matching_worktrees) > 1:
            ambiguity_reasons.append("duplicate-worktree-checkout-key")
        if any(
            _text(worktree.get("repo_path")) in {None, repo_path}
            for worktree in unkeyed_worktrees
        ):
            ambiguity_reasons.append("worktree-checkout-key-missing")
        rows.append(
            reconcile_binding(
                binding,
                matching_worktrees[0] if len(matching_worktrees) == 1 else None,
                repository_observable=repo_path in observable if repo_path is not None else False,
                ambiguity_reasons=ambiguity_reasons,
            )
        )
    rows.sort(
        key=lambda row: (
            str(row.get("checkout_key") or ""),
            row["state"],
            json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        )
    )
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

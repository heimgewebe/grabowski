from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any

import grabowski_checkouts as checkouts
import grabowski_consumer_surface as consumer_surface
import grabowski_sqlite_store as sqlite_store


class CheckoutBindingReconcilerError(RuntimeError):
    """Base exception for checkout-binding reconciliation failures."""


class CheckoutBindingDatabaseError(CheckoutBindingReconcilerError):
    """The durable checkout database cannot be trusted read-only."""


class CheckoutBindingCursorError(CheckoutBindingReconcilerError):
    """The pagination cursor is malformed or bound to another snapshot."""


RECONCILER_SCHEMA_VERSION = 1
CHECKOUT_DATABASE_SCHEMA_VERSION = "1"
RECONCILER_STATES = frozenset(
    {
        "bound_present",
        "orphaned_binding",
        "repository_unobservable",
        "binding_identity_drift",
    }
)
MAX_EVIDENCE = 32
MAX_PAGE_LIMIT = 100
MAX_BINDINGS = 10_000
MAX_REPOSITORY_ERRORS = 100
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
REQUIRED_TABLE_COLUMNS = {
    "metadata": {"key", "value"},
    "retention": {
        "checkout_key", "repo_common_dir", "repo_path", "checkout_path",
        "owner_id", "purpose", "retention_until_unix", "expected_head",
        "expected_branch", "created_at_unix", "updated_at_unix",
    },
    "lifecycle_bindings": {
        "checkout_key", "repo_common_dir", "repo_path", "checkout_path",
        "owner_id", "purpose", "source_kind", "source_id",
        "artifact_class", "phase", "retention_until_unix", "expected_head",
        "expected_branch", "created_at_unix", "updated_at_unix",
        "terminal_at_unix", "archived_at_unix",
    },
    "archives": {
        "archive_id", "checkout_key", "repo_common_dir", "repo_path",
        "checkout_path", "head", "branch", "owner_id", "purpose",
        "retention_until_unix", "recovery_refs_json", "manifest_path",
        "created_at_unix", "cleaned_at_unix", "cleanup_plan_id",
    },
}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _normalize_path(value: str) -> str:
    return str(Path(value).expanduser().resolve(strict=False))


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


def _retention_evidence(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "owner_id": _text(value.get("owner_id")),
        "retention_until_unix": _integer(value.get("retention_until_unix")),
        "expected_head": _text(value.get("expected_head")),
        "expected_branch": _text(value.get("expected_branch")),
        "updated_at_unix": _integer(value.get("updated_at_unix")),
    }


def _archive_evidence(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        "archive_id": _text(value.get("archive_id")),
        "owner_id": _text(value.get("owner_id")),
        "head": _text(value.get("head")),
        "branch": _text(value.get("branch")),
        "created_at_unix": _integer(value.get("created_at_unix")),
        "cleaned_at_unix": _integer(value.get("cleaned_at_unix")),
        "cleanup_plan_id": _text(value.get("cleanup_plan_id")),
    }


def _evidence(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "owner_id": _text(binding.get("owner_id")),
        "source": dict(binding.get("source")) if isinstance(binding.get("source"), Mapping) else None,
        "artifact_class": _text(binding.get("artifact_class")),
        "phase": _text(binding.get("phase")),
        "expected_head": _text(binding.get("expected_head")),
        "expected_branch": _text(binding.get("expected_branch")),
        "retention": _retention_evidence(binding.get("retention")),
        "archive": _archive_evidence(binding.get("latest_archive")),
    }


def _durable_evidence_drift_reasons(
    binding: Mapping[str, Any],
    phase: str | None,
) -> list[str]:
    """Check identity continuity across durable retention and archive evidence."""
    reasons: list[str] = []
    retention = binding.get("retention")
    if isinstance(retention, Mapping):
        retention_checks = (
            ("repo_common_dir", "repo_common_dir", "binding-retention-repo-common-dir-mismatch"),
            ("repo_path", "repo_path", "binding-retention-repo-path-mismatch"),
            ("checkout_path", "checkout_path", "binding-retention-checkout-path-mismatch"),
            ("owner_id", "owner_id", "binding-retention-owner-mismatch"),
            ("expected_head", "expected_head", "binding-retention-head-mismatch"),
            ("expected_branch", "expected_branch", "binding-retention-branch-mismatch"),
        )
        for binding_field, retention_field, reason in retention_checks:
            if _text(binding.get(binding_field)) != _text(retention.get(retention_field)):
                reasons.append(reason)

    archive = binding.get("latest_archive")
    if phase == "archived" and isinstance(archive, Mapping):
        archive_checks = (
            ("repo_common_dir", "repo_common_dir", "binding-archive-repo-common-dir-mismatch"),
            ("repo_path", "repo_path", "binding-archive-repo-path-mismatch"),
            ("checkout_path", "checkout_path", "binding-archive-checkout-path-mismatch"),
            ("owner_id", "owner_id", "binding-archive-owner-mismatch"),
            ("expected_head", "head", "binding-archive-head-mismatch"),
            ("expected_branch", "branch", "binding-archive-branch-mismatch"),
        )
        for binding_field, archive_field, reason in archive_checks:
            if _text(binding.get(binding_field)) != _text(archive.get(archive_field)):
                reasons.append(reason)
    return reasons


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
    reasons.extend(_durable_evidence_drift_reasons(binding, phase))
    reasons.extend(
        reason for reason in ambiguity_reasons if isinstance(reason, str) and reason
    )

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
    """Return a deterministic and bounded reconciliation projection."""
    worktrees_by_key: dict[str, list[Mapping[str, Any]]] = {}
    unkeyed_worktrees: list[Mapping[str, Any]] = []
    for worktree in worktrees:
        key = _text(worktree.get("checkout_key"))
        if key is None:
            unkeyed_worktrees.append(worktree)
        else:
            worktrees_by_key.setdefault(key, []).append(worktree)
    binding_rows = list(bindings)
    if len(binding_rows) > MAX_BINDINGS:
        raise CheckoutBindingReconcilerError(
            f"binding count exceeds bounded maximum of {MAX_BINDINGS}"
        )
    binding_key_counts: dict[str, int] = {}
    for binding in binding_rows:
        key = _text(binding.get("checkout_key"))
        if key is not None:
            binding_key_counts[key] = binding_key_counts.get(key, 0) + 1
    observable = {_normalize_path(path) for path in observable_repo_paths}
    rows: list[dict[str, Any]] = []
    for binding in binding_rows:
        repo_path = _text(binding.get("repo_path"))
        key = _text(binding.get("checkout_key"))
        matching_worktrees = worktrees_by_key.get(key, []) if key is not None else []
        ambiguity_reasons: list[str] = []
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
                repository_observable=(
                    _normalize_path(repo_path) in observable if repo_path is not None else False
                ),
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
            "permission_to_terminalize",
        ],
    }


def _database_path(db_path: Path | str | None) -> Path:
    raw = (
        db_path
        if db_path is not None
        else os.environ.get("GRABOWSKI_CHECKOUT_DB", str(checkouts.CHECKOUT_DB))
    )
    path = Path(raw).expanduser()
    if not path.exists():
        raise CheckoutBindingDatabaseError(f"checkout database does not exist: {path}")
    if not path.is_file():
        raise CheckoutBindingDatabaseError(f"checkout database is not a regular file: {path}")
    if path.is_symlink() or path.parent.is_symlink():
        raise CheckoutBindingDatabaseError("checkout database path may not traverse a symlink")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise CheckoutBindingDatabaseError("checkout database path is not resolvable") from exc


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error as exc:
        raise CheckoutBindingDatabaseError(f"cannot inspect checkout table {table}") from exc
    return {str(row["name"]) for row in rows}


def _validate_database(connection: sqlite3.Connection) -> None:
    try:
        sqlite_store.sqlite_integrity(
            connection,
            "checkout database",
            quick=False,
        )
    except RuntimeError as exc:
        raise CheckoutBindingDatabaseError(
            "checkout database integrity_check failed"
        ) from exc
    try:
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        }
    except sqlite3.Error as exc:
        raise CheckoutBindingDatabaseError(
            "checkout database schema cannot be inspected"
        ) from exc
    missing_tables = sorted(set(REQUIRED_TABLE_COLUMNS) - tables)
    if missing_tables:
        raise CheckoutBindingDatabaseError(
            f"checkout database tables missing: {', '.join(missing_tables)}"
        )
    for table, required in REQUIRED_TABLE_COLUMNS.items():
        missing = sorted(required - _table_columns(connection, table))
        if missing:
            raise CheckoutBindingDatabaseError(
                f"checkout database columns missing in {table}: {', '.join(missing)}"
            )
    try:
        version_rows = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchall()
    except sqlite3.Error as exc:
        raise CheckoutBindingDatabaseError("checkout schema version cannot be read") from exc
    if len(version_rows) != 1 or str(version_rows[0]["value"]) != CHECKOUT_DATABASE_SCHEMA_VERSION:
        value = str(version_rows[0]["value"]) if version_rows else "missing"
        raise CheckoutBindingDatabaseError(
            f"unsupported checkout database schema version: {value}"
        )


def _binding_public(row: sqlite3.Row) -> dict[str, Any]:
    record = dict(row)
    return {
        "checkout_key": record["checkout_key"],
        "repo_common_dir": record["repo_common_dir"],
        "repo_path": record["repo_path"],
        "checkout_path": record["checkout_path"],
        "owner_id": record["owner_id"],
        "purpose": record["purpose"],
        "source": {"kind": record["source_kind"], "id": record["source_id"]},
        "artifact_class": record["artifact_class"],
        "phase": record["phase"],
        "retention_until_unix": record["retention_until_unix"],
        "expected_head": record["expected_head"],
        "expected_branch": record["expected_branch"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "terminal_at_unix": record["terminal_at_unix"],
        "archived_at_unix": record["archived_at_unix"],
    }


def collect_lifecycle_bindings_from_db(
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Read every durable lifecycle binding from one pinned read-only transaction."""
    path = _database_path(db_path)
    try:
        with sqlite_store.inventory_readonly_sqlite(
            path,
            temporary_prefix="grabowski-checkout-binding-snapshot.",
            error_type=CheckoutBindingDatabaseError,
            message="checkout database changed during reconciliation snapshot",
        ) as connection:
            _validate_database(connection)
            try:
                binding_rows = connection.execute(
                    "SELECT * FROM lifecycle_bindings "
                    "ORDER BY checkout_key LIMIT ?",
                    (MAX_BINDINGS + 1,),
                ).fetchall()
                if len(binding_rows) > MAX_BINDINGS:
                    raise CheckoutBindingDatabaseError(
                        f"checkout binding count exceeds bounded maximum of {MAX_BINDINGS}"
                    )
                retention_rows = connection.execute(
                    "SELECT retention.* FROM retention "
                    "INNER JOIN lifecycle_bindings "
                    "ON lifecycle_bindings.checkout_key = retention.checkout_key "
                    "ORDER BY retention.checkout_key LIMIT ?",
                    (MAX_BINDINGS + 1,),
                ).fetchall()
                archive_rows = connection.execute(
                    "SELECT archives.* FROM archives "
                    "INNER JOIN lifecycle_bindings "
                    "ON lifecycle_bindings.checkout_key = archives.checkout_key "
                    "WHERE archives.archive_id = ("
                    "SELECT candidate.archive_id FROM archives AS candidate "
                    "WHERE candidate.checkout_key = archives.checkout_key "
                    "ORDER BY candidate.created_at_unix DESC, "
                    "candidate.archive_id DESC LIMIT 1"
                    ") ORDER BY archives.checkout_key LIMIT ?",
                    (MAX_BINDINGS + 1,),
                ).fetchall()
            except CheckoutBindingDatabaseError:
                raise
            except sqlite3.Error as exc:
                raise CheckoutBindingDatabaseError(
                    "checkout binding snapshot cannot be read"
                ) from exc
            if len(retention_rows) > MAX_BINDINGS or len(archive_rows) > MAX_BINDINGS:
                raise CheckoutBindingDatabaseError(
                    "checkout evidence exceeds the bounded binding maximum"
                )
            retentions = {
                str(row["checkout_key"]): dict(row) for row in retention_rows
            }
            archives = {
                str(row["checkout_key"]): dict(row) for row in archive_rows
            }
            bindings: list[dict[str, Any]] = []
            for row in binding_rows:
                record = _binding_public(row)
                key = str(record["checkout_key"])
                record["retention"] = retentions.get(key)
                record["latest_archive"] = archives.get(key)
                bindings.append(record)
            snapshot_material = {
                "database_schema_version": CHECKOUT_DATABASE_SCHEMA_VERSION,
                "bindings": bindings,
            }
            snapshot_sha256 = hashlib.sha256(
                consumer_surface.canonical_json_bytes(snapshot_material)
            ).hexdigest()
            return {
                "database_path": str(path),
                "database_schema_version": CHECKOUT_DATABASE_SCHEMA_VERSION,
                "snapshot_sha256": snapshot_sha256,
                "bindings": bindings,
                "read_only": True,
                "snapshot_mode": (
                    "immutable-file"
                    if not Path(str(path) + "-wal").exists()
                    else "copied-database-and-wal"
                ),
            }
    except CheckoutBindingDatabaseError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise CheckoutBindingDatabaseError(
            "checkout database snapshot cannot be opened read-only"
        ) from exc


def collect_git_worktrees_for_repos(
    repo_paths: Iterable[str | Path],
) -> dict[str, Any]:
    """Reuse the canonical Git worktree observer and expose failures explicitly."""
    worktrees: list[dict[str, Any]] = []
    observable_repo_paths: set[str] = set()
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in sorted(str(item) for item in repo_paths):
        normalized = _normalize_path(raw)
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            observation = checkouts.observe_worktree_records(raw)
        except Exception as exc:
            if len(errors) < MAX_REPOSITORY_ERRORS:
                errors.append(
                    {
                        "repo_path": normalized,
                        "error": type(exc).__name__,
                    }
                )
            continue
        top_level = _normalize_path(str(observation["top_level"]))
        common_dir = _normalize_path(str(observation["repo_common_dir"]))
        observable_repo_paths.update({normalized, top_level})
        records = [dict(item) for item in observation["worktrees"]]
        worktrees.extend(records)
        observations.append(
            {
                "requested_repo_path": normalized,
                "repo_path": top_level,
                "repo_common_dir": common_dir,
                "worktree_count": len(records),
            }
        )
    observations.sort(key=lambda item: (item["repo_path"], item["requested_repo_path"]))
    worktrees.sort(key=lambda item: (str(item.get("checkout_key") or ""), str(item.get("path") or "")))
    errors.sort(key=lambda item: (item["repo_path"], item["error"]))
    return {
        "worktrees": worktrees,
        "observable_repo_paths": sorted(observable_repo_paths),
        "observations": observations,
        "errors": errors,
        "errors_truncated": len(seen) - len(observations) > len(errors),
    }


def _normalize_filters(repository_filters: list[str] | None) -> list[str] | None:
    if repository_filters is None:
        return None
    if not isinstance(repository_filters, list) or not 1 <= len(repository_filters) <= 32:
        raise ValueError("repository_filters must contain between 1 and 32 paths")
    normalized: list[str] = []
    for value in repository_filters:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("repository_filters entries must be non-empty paths")
        path = _normalize_path(value)
        if path in normalized:
            raise ValueError("repository_filters must be unique")
        normalized.append(path)
    return normalized


def reconcile_checkout_bindings(
    *,
    db_path: Path | str | None = None,
    repository_filters: list[str] | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Compare the pinned durable binding snapshot with current Git observations."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PAGE_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
    filters = _normalize_filters(repository_filters)
    database = collect_lifecycle_bindings_from_db(db_path)
    bindings = list(database["bindings"])
    if filters is not None:
        allowed = set(filters)
        bindings = [
            binding
            for binding in bindings
            if _normalize_path(str(binding["repo_path"])) in allowed
        ]
    candidate_repositories = sorted(
        {_normalize_path(str(binding["repo_path"])) for binding in bindings}
    )
    git = collect_git_worktrees_for_repos(candidate_repositories)
    full_projection = reconcile_bindings(
        bindings,
        git["worktrees"],
        observable_repo_paths=git["observable_repo_paths"],
    )
    snapshot_material = {
        "database_snapshot_sha256": database["snapshot_sha256"],
        "repository_filters": filters,
        "git_observations": git["observations"],
        "git_errors": git["errors"],
        "bindings": full_projection["bindings"],
    }
    snapshot_sha256 = hashlib.sha256(
        consumer_surface.canonical_json_bytes(snapshot_material)
    ).hexdigest()
    scope = f"checkout-binding-reconciliation:{snapshot_sha256}"
    try:
        position = consumer_surface.decode_cursor(
            cursor,
            scope,
            snapshot_scope="checkout-binding-reconciliation",
        )
    except ValueError as exc:
        raise CheckoutBindingCursorError(str(exc)) from exc
    offset = 0 if position is None else position.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise CheckoutBindingCursorError("cursor offset is invalid")
    all_bindings = full_projection["bindings"]
    if offset > len(all_bindings):
        raise CheckoutBindingCursorError("cursor offset exceeds reconciliation snapshot")
    page_rows = all_bindings[offset : offset + limit]
    next_offset = offset + len(page_rows)
    has_more = next_offset < len(all_bindings)
    next_cursor = (
        consumer_surface.encode_cursor(scope, {"offset": next_offset})
        if has_more
        else None
    )
    attention = [
        {
            "schema_version": RECONCILER_SCHEMA_VERSION,
            "kind": "checkout_binding_reconciliation_attention",
            "checkout_key": row["checkout_key"],
            "state": row["state"],
            "classification": "actionable",
            "reasons": row["reasons"],
            "recommended_next_step": row["recommended_next_step"],
            "authority": "read_only_projection",
        }
        for row in page_rows
        if row["blocking"]
    ]
    return {
        "schema_version": RECONCILER_SCHEMA_VERSION,
        "kind": "grabowski_checkout_binding_reconciliation",
        "count": len(page_rows),
        "total_count": len(all_bindings),
        "summary": full_projection["summary"],
        "blocking_count": full_projection["blocking_count"],
        "bindings": page_rows,
        "attention": attention,
        "attention_total_count": full_projection["blocking_count"],
        "pagination": {
            "limit": limit,
            "offset": offset,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "snapshot_bound": True,
        },
        "snapshot_sha256": snapshot_sha256,
        "source_snapshot": {
            "database_snapshot_sha256": database["snapshot_sha256"],
            "database_schema_version": database["database_schema_version"],
            "repository_observations": git["observations"],
            "repository_errors": git["errors"],
            "repository_errors_truncated": git["errors_truncated"],
        },
        "read_only": True,
        "does_not_establish": full_projection["does_not_establish"],
    }

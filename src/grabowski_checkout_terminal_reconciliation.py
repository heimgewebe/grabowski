from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import stat
from typing import Any
import uuid

import grabowski_checkouts as checkouts
import grabowski_checkout_terminal_sources as sources


SCHEMA_VERSION = checkouts.TERMINAL_RECONCILIATION_SCHEMA_VERSION
PREVIEW_TTL_SECONDS = checkouts.TERMINAL_RECONCILIATION_PREVIEW_TTL_SECONDS
CONFIRMATION = checkouts.TERMINAL_RECONCILIATION_CONFIRMATION
_ALLOWED_SOURCE_PHASES = frozenset({"active", "completed_retained"})


def _checkout_key(value: str) -> str:
    if not isinstance(value, str) or checkouts.SHA256_RE.fullmatch(value) is None:
        raise ValueError("checkout_key must be a lowercase SHA-256")
    return value


def _record(checkout_key: str) -> dict[str, Any] | None:
    connection = checkouts._readonly_connection(checkouts.CHECKOUT_DB)
    if connection is None:
        return None
    try:
        row = connection.execute(
            "SELECT * FROM terminal_reconciliations WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    finally:
        connection.close()
    if row is None:
        return None
    result = dict(row)
    try:
        receipt = json.loads(result["receipt_json"])
        source_evidence = json.loads(result["source_evidence_json"])
    except json.JSONDecodeError as exc:
        raise RuntimeError("terminal reconciliation record contains invalid JSON") from exc
    if not isinstance(receipt, dict) or not isinstance(source_evidence, dict):
        raise RuntimeError("terminal reconciliation record shape is invalid")
    receipt_core = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if (
        receipt.get("receipt_sha256") != result["receipt_sha256"]
        or result["receipt_sha256"] != checkouts._sha256_json(receipt_core)
        or source_evidence.get("evidence_sha256") != result["source_evidence_sha256"]
    ):
        raise RuntimeError("terminal reconciliation record digest is invalid")
    return {**result, "receipt": receipt, "source_evidence": source_evidence}


def _snapshot(checkout_key: str) -> dict[str, Any]:
    connection = checkouts._readonly_connection(checkouts.CHECKOUT_DB)
    if connection is None:
        raise RuntimeError("checkout lifecycle database is unavailable")
    try:
        binding_row = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
        retention_row = connection.execute(
            "SELECT * FROM retention WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
        archive_count = connection.execute(
            "SELECT count(*) FROM archives WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()[0]
    finally:
        connection.close()
    if binding_row is None:
        raise RuntimeError("checkout lifecycle binding is missing")
    if retention_row is None:
        raise RuntimeError("checkout retention binding is missing")
    binding = checkouts._lifecycle_public(binding_row)
    retention = checkouts._retention_public(retention_row)
    identity_fields = (
        "checkout_key",
        "repo_common_dir",
        "repo_path",
        "checkout_path",
        "owner_id",
        "expected_head",
        "expected_branch",
    )
    mismatched = [field for field in identity_fields if binding.get(field) != retention.get(field)]
    if mismatched:
        raise RuntimeError(
            "checkout binding and retention identity differ: " + ",".join(mismatched)
        )
    if not isinstance(binding.get("expected_head"), str) or not isinstance(
        binding.get("expected_branch"), str
    ):
        raise RuntimeError("terminal reconciliation requires exact stored head and branch")
    return {
        "binding": binding,
        "binding_sha256": checkouts._sha256_json(binding),
        "retention": retention,
        "retention_sha256": checkouts._sha256_json(retention),
        "archive_count": int(archive_count),
    }


def _lexical_checkout_path_observation(
    raw_path: str,
) -> tuple[Path, bool, list[str]]:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        raise RuntimeError("checkout binding path is not absolute")
    current = Path(path.anchor)
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return path, False, []
        except OSError:
            return path, True, ["checkout-path-unobservable"]
        if stat.S_ISLNK(metadata.st_mode):
            return path, True, ["checkout-path-symlink"]
        if index < len(parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            return path, True, ["checkout-path-parent-not-directory"]
    return path, True, []


def _branch_head_relation(
    repo: Path, expected_head: str, branch_head: str | None
) -> tuple[str, list[str]]:
    if branch_head is None:
        return "missing", ["branch-ref-missing"]
    if branch_head == expected_head:
        return "exact", []
    ancestry = checkouts._git_read(
        repo,
        ["merge-base", "--is-ancestor", expected_head, branch_head],
        check=False,
    )
    if ancestry.returncode == 0:
        return "descendant", []
    if ancestry.returncode == 1:
        return "diverged", ["branch-head-drift"]
    return "unobservable", ["branch-head-ancestry-unobservable"]


def _missing_checkout_observation(binding: dict[str, Any]) -> dict[str, Any]:
    repo = checkouts._resolve_repo(binding["repo_path"])
    common_dir = checkouts._git_common_dir(repo)
    top_level, observed_common, records = checkouts._worktree_records(repo)
    bound_checkout_path, checkout_exists, path_blockers = (
        _lexical_checkout_path_observation(binding["checkout_path"])
    )
    checkout_path = checkouts._safe_path(bound_checkout_path, must_exist=False)
    blockers: list[str] = list(path_blockers)
    if str(top_level) != binding["repo_path"]:
        blockers.append("repository-path-drift")
    if common_dir != observed_common or str(common_dir) != binding["repo_common_dir"]:
        blockers.append("repository-common-dir-drift")
    matches = [
        record
        for record in records
        if Path(record["path"]).resolve(strict=False) == checkout_path
    ]
    if len(matches) > 1:
        blockers.append("checkout-record-ambiguous")
    record = matches[0] if len(matches) == 1 else None
    if checkout_exists:
        blockers.append("checkout-path-present")
    if record is not None:
        if not record.get("prunable"):
            blockers.append("checkout-record-not-prunable")
        if record.get("head") != binding["expected_head"]:
            blockers.append("checkout-record-head-drift")
        if record.get("branch") != binding["expected_branch"]:
            blockers.append("checkout-record-branch-drift")
    branch_ref = f"refs/heads/{binding['expected_branch']}"
    branch_read = checkouts._git_read(
        repo,
        ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"],
        check=False,
    )
    branch_head = branch_read.stdout.strip() if branch_read.returncode == 0 else None
    branch_head_relation, branch_blockers = _branch_head_relation(
        repo, binding["expected_head"], branch_head
    )
    blockers.extend(branch_blockers)
    return {
        "repository": str(top_level),
        "repo_common_dir": str(common_dir),
        "checkout_path": str(bound_checkout_path),
        "checkout_exists": checkout_exists,
        "worktree_record_present": record is not None,
        "worktree_record": record,
        "branch_ref": branch_ref,
        "branch_head": branch_head,
        "branch_head_relation": branch_head_relation,
        "expected_head": binding["expected_head"],
        "expected_branch": binding["expected_branch"],
        "blockers": sorted(set(blockers)),
    }


def _branch_task_records(checkout_path: Path, branch_key: str) -> list[dict[str, Any]]:
    records = checkouts._task_records([checkout_path])
    known = {record["task_id"] for record in records}
    connection = checkouts._readonly_connection(checkouts.tasks.TASK_DB)
    if connection is None:
        return records
    try:
        rows = connection.execute(
            "SELECT task_id,host,unit,state,cwd,resource_keys_json,lease_owner_id "
            "FROM tasks WHERE state IN ('launching','running') ORDER BY task_id"
        ).fetchall()
    except sqlite3.OperationalError:
        return records
    finally:
        connection.close()
    for row in rows:
        if row["task_id"] in known:
            continue
        try:
            keys = json.loads(row["resource_keys_json"] or "[]")
        except json.JSONDecodeError:
            continue
        if not isinstance(keys, list) or branch_key not in keys:
            continue
        records.append(
            {
                "task_id": row["task_id"],
                "host": row["host"],
                "unit": row["unit"],
                "state": row["state"],
                "cwd": row["cwd"],
                "resource_keys": sorted(item for item in keys if isinstance(item, str)),
                "lease_owner_id": row["lease_owner_id"],
            }
        )
    return sorted(records, key=lambda item: item["task_id"])


def _coordination(
    binding: dict[str, Any], *, ignore_lease_owner: str | None = None
) -> dict[str, Any]:
    checkout_path = Path(binding["checkout_path"])
    repo_path = Path(binding["repo_path"])
    branch_key = f"repo:{repo_path}:branch:{binding['expected_branch']}"
    broad_repo_key = f"repo:{repo_path}"
    leases: list[dict[str, Any]] = []
    for lease in checkouts._read_resource_leases():
        if ignore_lease_owner is not None and lease["owner_id"] == ignore_lease_owner:
            continue
        key = lease["resource_key"]
        if key in {branch_key, broad_repo_key} or checkouts._resource_related(
            key, [checkout_path]
        ):
            leases.append({**lease, "blocking": True})
    tasks = _branch_task_records(checkout_path, branch_key)
    processes = checkouts._processes_under([checkout_path])
    return checkouts._coordination_result(leases, tasks, processes)


def _preview_state(
    checkout_key: str, *, ignore_lease_owner: str | None = None
) -> dict[str, Any]:
    key = _checkout_key(checkout_key)
    existing = _record(key)
    snapshot = _snapshot(key)
    binding = snapshot["binding"]
    if existing is not None:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "checkout_terminal_reconciliation_preview",
            "status": "already_applied",
            "checkout_key": key,
            "safe_to_apply": False,
            "existing_receipt": existing["receipt"],
            "does_not_establish": [
                "archive_or_cleanup_authority",
                "branch_or_ref_deletion_authority",
            ],
        }
    if binding["phase"] not in _ALLOWED_SOURCE_PHASES:
        raise RuntimeError("only active or completed-retained bindings may be reconciled")
    source_evidence = sources.source_terminal_evidence(binding)
    checkout = _missing_checkout_observation(binding)
    coordination = _coordination(binding, ignore_lease_owner=ignore_lease_owner)
    blockers = list(checkout["blockers"])
    if snapshot["archive_count"]:
        blockers.append("archive-record-present")
    if coordination["blocking"]:
        blockers.append("active-coordination")
    stable = {
        "schema_version": SCHEMA_VERSION,
        "kind": "checkout_terminal_reconciliation_preview",
        "status": "ready" if not blockers else "blocked",
        "checkout_key": key,
        "binding": binding,
        "binding_sha256": snapshot["binding_sha256"],
        "retention": snapshot["retention"],
        "retention_sha256": snapshot["retention_sha256"],
        "source_evidence": source_evidence,
        "checkout_observation": checkout,
        "coordination": coordination,
        "blockers": sorted(set(blockers)),
        "safe_to_apply": not blockers,
        "does_not_establish": [
            "archive_or_cleanup_authority",
            "branch_or_ref_deletion_authority",
            "historical_checkout_content",
            "permission_to_remove_retention_or_binding_rows",
        ],
    }
    return stable


def _bind_preview(state: dict[str, Any], created_at_unix: int) -> dict[str, Any]:
    if state.get("status") == "already_applied":
        return state
    material = {
        **state,
        "preview_created_at_unix": created_at_unix,
        "preview_expires_at_unix": created_at_unix + PREVIEW_TTL_SECONDS,
    }
    return {**material, "preview_sha256": checkouts._sha256_json(material)}


def preview(
    checkout_key: str, *, ignore_lease_owner: str | None = None
) -> dict[str, Any]:
    return _bind_preview(
        _preview_state(checkout_key, ignore_lease_owner=ignore_lease_owner),
        checkouts._now(),
    )


def _replay(
    checkout_key: str, owner_id: str, expected_preview_sha256: str
) -> dict[str, Any] | None:
    existing = _record(checkout_key)
    if existing is None:
        return None
    if existing["owner_id"] != owner_id:
        raise PermissionError("terminal reconciliation belongs to another owner")
    if existing["preview_sha256"] != expected_preview_sha256:
        raise RuntimeError("terminal reconciliation replay preview digest drift")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "checkout_terminal_reconciliation_result",
        "status": "already_applied",
        "idempotent_replay": True,
        "receipt": existing["receipt"],
    }


def apply(
    checkout_key: str,
    owner_id: str,
    expected_preview_sha256: str,
    preview_created_at_unix: int,
    confirmation: str,
) -> dict[str, Any]:
    key = _checkout_key(checkout_key)
    owner = checkouts._owner(owner_id)
    preview_sha256 = checkouts._validate_sha256(
        expected_preview_sha256, "expected_preview_sha256"
    )
    if confirmation != CONFIRMATION:
        raise ValueError(f"confirmation must be exactly {CONFIRMATION!r}")
    if (
        isinstance(preview_created_at_unix, bool)
        or not isinstance(preview_created_at_unix, int)
        or preview_created_at_unix < 0
    ):
        raise ValueError("preview_created_at_unix must be a non-negative integer")
    now = checkouts._now()
    if not preview_created_at_unix <= now <= preview_created_at_unix + PREVIEW_TTL_SECONDS:
        raise RuntimeError("terminal reconciliation preview is expired or from the future")
    replay = _replay(key, owner, preview_sha256)
    if replay is not None:
        return replay
    planned = _bind_preview(_preview_state(key), preview_created_at_unix)
    if planned.get("preview_sha256") != preview_sha256:
        raise RuntimeError("terminal reconciliation preview is stale")
    if planned.get("safe_to_apply") is not True:
        raise RuntimeError(
            "terminal reconciliation is blocked: " + ",".join(planned.get("blockers", []))
        )
    if planned["binding"]["owner_id"] != owner:
        raise PermissionError("checkout lifecycle binding is owned by another owner")
    operation_owner = f"checkout-terminal:{uuid.uuid4().hex[:20]}"
    resource_keys = sorted(
        {
            f"path:{planned['binding']['checkout_path']}",
            f"repo:{planned['binding']['repo_path']}:branch:{planned['binding']['expected_branch']}",
        }
    )
    lease = checkouts.resources.acquire_resources(
        operation_owner,
        resource_keys,
        purpose=f"terminal reconciliation for missing checkout {key}",
        ttl_seconds=checkouts.OPERATION_LEASE_TTL_SECONDS,
        metadata={
            "checkout_key": key,
            "durable_owner_id": owner,
            "preview_sha256": preview_sha256,
            "source_evidence_sha256": planned["source_evidence"]["evidence_sha256"],
        },
    )
    result: dict[str, Any] | None = None
    try:
        current = _bind_preview(
            _preview_state(key, ignore_lease_owner=operation_owner),
            preview_created_at_unix,
        )
        if current.get("preview_sha256") != preview_sha256:
            raise RuntimeError("terminal reconciliation changed after lease acquisition")
        applied_at = checkouts._now()
        with checkouts._operation_lock(), checkouts._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM terminal_reconciliations WHERE checkout_key=?",
                (key,),
            ).fetchone() is not None:
                connection.rollback()
                replay = _replay(key, owner, preview_sha256)
                if replay is None:
                    raise RuntimeError("terminal reconciliation replay disappeared")
                return replay
            binding_row = connection.execute(
                "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
                (key,),
            ).fetchone()
            retention_row = connection.execute(
                "SELECT * FROM retention WHERE checkout_key=?",
                (key,),
            ).fetchone()
            if binding_row is None or retention_row is None:
                raise RuntimeError("checkout lifecycle state disappeared before apply")
            binding_before = checkouts._lifecycle_public(binding_row)
            retention_before = checkouts._retention_public(retention_row)
            if (
                checkouts._sha256_json(binding_before) != planned["binding_sha256"]
                or checkouts._sha256_json(retention_before) != planned["retention_sha256"]
            ):
                raise RuntimeError("checkout lifecycle CAS preimage changed")
            checkout_observation = planned["checkout_observation"]
            relation = checkout_observation.get("branch_head_relation")
            rebind_head = (
                checkout_observation.get("branch_head")
                if relation == "descendant"
                else binding_before["expected_head"]
            )
            if not isinstance(rebind_head, str):
                raise RuntimeError("terminal reconciliation lacks an exact terminal head")
            updated = connection.execute(
                """
                UPDATE lifecycle_bindings
                SET phase='externally_terminal_missing',
                    expected_head=?,
                    terminal_at_unix=COALESCE(terminal_at_unix, ?),
                    archived_at_unix=NULL,
                    updated_at_unix=?
                WHERE checkout_key=? AND owner_id=? AND phase=?
                  AND expected_head=? AND updated_at_unix=?
                """,
                (
                    rebind_head,
                    applied_at,
                    applied_at,
                    key,
                    owner,
                    binding_before["phase"],
                    binding_before["expected_head"],
                    binding_before["updated_at_unix"],
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("checkout lifecycle CAS transition was not applied exactly")
            if rebind_head != retention_before["expected_head"]:
                retention_updated = connection.execute(
                    """
                    UPDATE retention
                    SET expected_head=?, updated_at_unix=?
                    WHERE checkout_key=? AND owner_id=? AND expected_head=?
                      AND updated_at_unix=?
                    """,
                    (
                        rebind_head,
                        applied_at,
                        key,
                        owner,
                        retention_before["expected_head"],
                        retention_before["updated_at_unix"],
                    ),
                )
                if retention_updated.rowcount != 1:
                    raise RuntimeError("checkout retention head rebind was not applied exactly")
            binding_after_row = connection.execute(
                "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
                (key,),
            ).fetchone()
            retention_after_row = connection.execute(
                "SELECT * FROM retention WHERE checkout_key=?",
                (key,),
            ).fetchone()
            if binding_after_row is None or retention_after_row is None:
                raise RuntimeError("checkout lifecycle post-state disappeared")
            binding_after = checkouts._lifecycle_public(binding_after_row)
            retention_after = checkouts._retention_public(retention_after_row)
            branch_head_rebind = (
                {
                    "relation": "descendant",
                    "from_head": binding_before["expected_head"],
                    "to_head": rebind_head,
                }
                if rebind_head != binding_before["expected_head"]
                else None
            )
            effects = ["lifecycle_phase_transition"]
            if branch_head_rebind is not None:
                effects.append("terminal_head_rebind")
            receipt_core = {
                "schema_version": SCHEMA_VERSION,
                "kind": "checkout_terminal_reconciliation_receipt",
                "checkout_key": key,
                "owner_id": owner,
                "binding_before": binding_before,
                "binding_before_sha256": planned["binding_sha256"],
                "binding_after": binding_after,
                "binding_after_sha256": checkouts._sha256_json(binding_after),
                "retention_before": retention_before,
                "retention_sha256": planned["retention_sha256"],
                "retention_before_sha256": planned["retention_sha256"],
                "retention_after": retention_after,
                "retention_after_sha256": checkouts._sha256_json(retention_after),
                "branch_head_rebind": branch_head_rebind,
                "source_evidence": planned["source_evidence"],
                "source_evidence_sha256": planned["source_evidence"]["evidence_sha256"],
                "preview_sha256": preview_sha256,
                "preview_created_at_unix": preview_created_at_unix,
                "applied_at_unix": applied_at,
                "resource_keys": resource_keys,
                "effects": effects,
                "does_not_establish": [
                    "archive_or_cleanup_authority",
                    "branch_or_ref_deletion_authority",
                    "historical_checkout_content",
                    "permission_to_delete_binding_or_retention_rows",
                ],
            }
            receipt = {**receipt_core, "receipt_sha256": checkouts._sha256_json(receipt_core)}
            connection.execute(
                """
                INSERT INTO terminal_reconciliations(
                    checkout_key, owner_id, binding_before_sha256,
                    retention_sha256, source_evidence_json,
                    source_evidence_sha256, preview_sha256,
                    preview_created_at_unix, applied_at_unix,
                    receipt_json, receipt_sha256
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    owner,
                    planned["binding_sha256"],
                    planned["retention_sha256"],
                    checkouts._canonical_json(planned["source_evidence"]),
                    planned["source_evidence"]["evidence_sha256"],
                    preview_sha256,
                    preview_created_at_unix,
                    applied_at,
                    checkouts._canonical_json(receipt),
                    receipt["receipt_sha256"],
                ),
            )
            connection.commit()
        readback = _record(key)
        if (
            readback is None
            or readback["receipt_sha256"] != receipt["receipt_sha256"]
            or readback["receipt"]["binding_after"]["phase"] != "externally_terminal_missing"
        ):
            raise RuntimeError("terminal reconciliation post-state readback failed")
        audit = {
            "timestamp_unix": applied_at,
            "operation": "checkout-binding-terminal-reconciliation",
            "checkout_key": key,
            "owner_id": owner,
            "source_kind": planned["source_evidence"]["kind"],
            "source_evidence_sha256": planned["source_evidence"]["evidence_sha256"],
            "preview_sha256": preview_sha256,
            "receipt_sha256": receipt["receipt_sha256"],
            "resource_keys": resource_keys,
        }
        checkouts.base._append_audit(audit)
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "checkout_terminal_reconciliation_result",
            "status": "applied",
            "idempotent_replay": False,
            "receipt": receipt,
            "audit": audit,
            "lease": lease,
        }
    finally:
        lease_release = checkouts.resources.release_resources(operation_owner, resource_keys)
    if result is None:
        raise RuntimeError("terminal reconciliation produced no result")
    result["lease_release"] = lease_release
    return result

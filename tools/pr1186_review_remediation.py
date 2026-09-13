from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_between(path: str, start: str, end: str, replacement: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if text.count(start) != 1:
        raise SystemExit(f"{path}: start marker is not unique: {start!r}")
    start_at = text.index(start)
    end_at = text.index(end, start_at)
    target.write_text(text[:start_at] + replacement + text[end_at:], encoding="utf-8")


CHECKOUTS = "src/grabowski_checkouts.py"
WORKSPACE = "src/grabowski_agent_workspace.py"
TESTS = "tests/test_checkouts.py"

schema_marker = '''    current = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
'''
schema_insert = '''    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS operation_uncertainty (
            fence_id TEXT PRIMARY KEY,
            checkout_key TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            lease_owner_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            resource_keys_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            evidence_sha256 TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            cleared_at_unix INTEGER,
            clearance_json TEXT,
            clearance_sha256 TEXT,
            UNIQUE(operation, operation_id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS operation_uncertainty_active_idx "
        "ON operation_uncertainty(cleared_at_unix, checkout_key)"
    )
''' + schema_marker
replace_once(CHECKOUTS, schema_marker, schema_insert)

helper_marker = '''def _acquire_checkout_resources(
'''
helper_code = '''def _operation_uncertainty_public(
    row: sqlite3.Row | dict[str, Any],
) -> dict[str, Any]:
    record = dict(row)
    evidence = json.loads(record["evidence_json"])
    if _sha256_json(evidence) != record["evidence_sha256"]:
        raise RuntimeError("Checkout operation uncertainty evidence integrity failed")
    clearance = None
    if record.get("clearance_json") is not None:
        clearance = json.loads(record["clearance_json"])
        if _sha256_json(clearance) != record.get("clearance_sha256"):
            raise RuntimeError("Checkout operation uncertainty clearance integrity failed")
    return {
        "fence_id": record["fence_id"],
        "checkout_key": record["checkout_key"],
        "owner_id": record["owner_id"],
        "lease_owner_id": record["lease_owner_id"],
        "operation": record["operation"],
        "operation_id": record["operation_id"],
        "resource_keys": json.loads(record["resource_keys_json"]),
        "evidence": evidence,
        "evidence_sha256": record["evidence_sha256"],
        "created_at_unix": record["created_at_unix"],
        "cleared_at_unix": record["cleared_at_unix"],
        "clearance": clearance,
        "clearance_sha256": record["clearance_sha256"],
    }


def _active_checkout_operation_uncertainties(
    resource_keys: Iterable[str] = (),
) -> list[dict[str, Any]]:
    wanted = set(resources.normalize_resource_keys(resource_keys))
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        return []
    try:
        rows = connection.execute(
            """
            SELECT * FROM operation_uncertainty
            WHERE cleared_at_unix IS NULL
            ORDER BY created_at_unix ASC, fence_id ASC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        connection.close()
    fences = [_operation_uncertainty_public(row) for row in rows]
    if not wanted:
        return fences
    return [
        fence
        for fence in fences
        if wanted.intersection(fence["resource_keys"])
    ]


def _load_checkout_operation_uncertainty(fence_id: str) -> dict[str, Any]:
    if not isinstance(fence_id, str) or re.fullmatch(r"[0-9a-f]{32}", fence_id) is None:
        raise ValueError("fence_id must be a 32-character lowercase hex identifier")
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        raise ValueError(f"Unknown checkout uncertainty fence: {fence_id}")
    try:
        row = connection.execute(
            "SELECT * FROM operation_uncertainty WHERE fence_id=?",
            (fence_id,),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        raise ValueError(f"Unknown checkout uncertainty fence: {fence_id}") from exc
    finally:
        connection.close()
    if row is None:
        raise ValueError(f"Unknown checkout uncertainty fence: {fence_id}")
    return _operation_uncertainty_public(row)


def _require_no_checkout_operation_uncertainty(resource_keys: Iterable[str]) -> None:
    blockers = _active_checkout_operation_uncertainties(resource_keys)
    if not blockers:
        return
    blocker = blockers[0]
    raise RuntimeError(
        "Checkout resources are durably fenced by an uncertain "
        f"{blocker['operation']} outcome: {blocker['fence_id']}"
    )


def _persist_checkout_operation_uncertainty(
    *,
    lease: dict[str, Any],
    checkout_key: str,
    owner_id: str,
    operation: str,
    operation_id: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    checkout_identity = _validate_sha256(checkout_key, "checkout_key")
    owner = _owner(owner_id)
    if operation not in {"archive", "cleanup"}:
        raise ValueError("Checkout uncertainty operation must be archive or cleanup")
    if (
        not isinstance(operation_id, str)
        or not operation_id
        or len(operation_id.encode("utf-8")) > 128
        or "\\x00" in operation_id
    ):
        raise ValueError("Checkout uncertainty operation_id is invalid")
    lease_owner = _owner(str(lease.get("owner_id")))
    resource_keys = sorted(
        {
            resources.normalize_resource_key(str(item["resource_key"]))
            for item in lease.get("leases", [])
            if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
        }
    )
    evidence_value = dict(evidence)
    evidence_sha256 = _sha256_json(evidence_value)
    fence_id = uuid.uuid4().hex
    created = _now()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        active_rows = connection.execute(
            "SELECT * FROM operation_uncertainty WHERE cleared_at_unix IS NULL"
        ).fetchall()
        for active_row in active_rows:
            active = _operation_uncertainty_public(active_row)
            if set(active["resource_keys"]).intersection(resource_keys):
                raise RuntimeError(
                    "Checkout operation uncertainty already fences requested resources"
                )
        connection.execute(
            """
            INSERT INTO operation_uncertainty(
                fence_id, checkout_key, owner_id, lease_owner_id,
                operation, operation_id, resource_keys_json,
                evidence_json, evidence_sha256, created_at_unix,
                cleared_at_unix, clearance_json, clearance_sha256
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
            """,
            (
                fence_id,
                checkout_identity,
                owner,
                lease_owner,
                operation,
                operation_id,
                _canonical_json(resource_keys),
                _canonical_json(evidence_value),
                evidence_sha256,
                created,
            ),
        )
        connection.commit()
    return _load_checkout_operation_uncertainty(fence_id)


def _clear_checkout_operation_uncertainty(
    fence_id: str,
    *,
    outcome: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    if outcome not in {"confirmed_success", "confirmed_no_effect", "reconciled_success"}:
        raise ValueError("Checkout uncertainty clearance outcome is invalid")
    clearance = {
        "outcome": outcome,
        "evidence": dict(evidence),
        "cleared_at_unix": _now(),
    }
    clearance_sha256 = _sha256_json(clearance)
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM operation_uncertainty WHERE fence_id=?",
            (fence_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown checkout uncertainty fence: {fence_id}")
        current = _operation_uncertainty_public(row)
        if current["cleared_at_unix"] is not None:
            return current
        connection.execute(
            """
            UPDATE operation_uncertainty
            SET cleared_at_unix=?, clearance_json=?, clearance_sha256=?
            WHERE fence_id=? AND cleared_at_unix IS NULL
            """,
            (
                clearance["cleared_at_unix"],
                _canonical_json(clearance),
                clearance_sha256,
                fence_id,
            ),
        )
        connection.commit()
    return _load_checkout_operation_uncertainty(fence_id)


''' + helper_marker
replace_once(CHECKOUTS, helper_marker, helper_code)

keys_marker = '''    bureau_keys = resources.bureau_leases.bureau_resource_keys(keys)
'''
replace_once(
    CHECKOUTS,
    keys_marker,
    '''    _require_no_checkout_operation_uncertainty(keys)\n''' + keys_marker,
)

release_marker = '''def _release_checkout_resources(lease: dict[str, Any]) -> dict[str, Any]:
    keys = [item["resource_key"] for item in lease["leases"]]
    return resources.release_resources(lease["owner_id"], keys)


'''
reconcile_code = release_marker + '''def _release_uncertainty_fence_resources(fence: dict[str, Any]) -> dict[str, Any]:
    return resources.release_resources(
        str(fence["lease_owner_id"]), list(fence["resource_keys"])
    )


def _archive_uncertainty_readback(fence: dict[str, Any]) -> dict[str, Any]:
    evidence = fence["evidence"]
    repo = _resolve_repo(str(evidence["repo"]))
    checkout = Path(str(evidence["checkout_path"]))
    archive_id = _validate_archive_id(str(evidence["archive_id"]))
    planned_refs = list(evidence.get("planned_recovery_refs") or [])
    verified_refs = _verify_recovery_refs(repo, planned_refs)
    try:
        archive = _load_archive(archive_id)
    except ValueError:
        archive = None
    archive_dir = ARCHIVE_ROOT.expanduser() / archive_id
    if archive is not None:
        lifecycle = _lifecycle_bindings([str(evidence["checkout_key"])]).get(
            str(evidence["checkout_key"])
        )
        if (
            verified_refs
            and all(bool(item["present"]) for item in verified_refs)
            and archive.get("checkout_key") == evidence["checkout_key"]
            and archive.get("repo_path") == evidence["repo"]
            and archive.get("checkout_path") == evidence["checkout_path"]
            and archive.get("head") == evidence["expected_head"]
            and archive.get("branch") == evidence["expected_branch"]
            and archive.get("owner_id") == evidence["owner_id"]
            and Path(str(archive["manifest_path"])).is_file()
            and isinstance(lifecycle, dict)
            and lifecycle.get("phase") == "archived"
            and lifecycle.get("owner_id") == evidence["owner_id"]
        ):
            return {
                "state": "confirmed_success",
                "archive_id": archive_id,
                "verified_recovery_refs": verified_refs,
            }
        return {
            "state": "still_fenced",
            "reason": "archive-readback-mismatch",
            "verified_recovery_refs": verified_refs,
        }
    if any(bool(item["present"]) for item in verified_refs) or archive_dir.exists():
        return {
            "state": "still_fenced",
            "reason": "partial-archive-effects-observed",
            "verified_recovery_refs": verified_refs,
        }
    try:
        _, _, record = _worktree_for_path(repo, checkout)
        _require_expected(
            record,
            str(evidence["expected_head"]),
            evidence.get("expected_branch"),
        )
        physical = evidence.get("expected_physical_identity")
        if isinstance(physical, dict):
            _verify_expected_physical_checkout_identity(checkout, physical)
    except Exception as exc:
        return {
            "state": "still_fenced",
            "reason": f"archive-no-effect-not-provable:{type(exc).__name__}",
            "verified_recovery_refs": verified_refs,
        }
    return {
        "state": "confirmed_no_effect",
        "archive_id": archive_id,
        "verified_recovery_refs": verified_refs,
    }


def _cleanup_uncertainty_readback(fence: dict[str, Any]) -> dict[str, Any]:
    evidence = fence["evidence"]
    repo = _resolve_repo(str(evidence["repo"]))
    checkout = Path(str(evidence["checkout_path"]))
    archive_id = _validate_archive_id(str(evidence["archive_id"]))
    plan_id = _validate_plan_id(str(evidence["plan_id"]))
    plan_sha256 = _validate_sha256(str(evidence["plan_sha256"]), "plan_sha256")
    stored = _load_dry_run(plan_id)
    archive = _load_archive(archive_id)
    if (
        stored.get("archive_id") != archive_id
        or stored.get("checkout_key") != evidence["checkout_key"]
        or stored.get("owner_id") != evidence["owner_id"]
        or stored.get("plan_sha256") != plan_sha256
    ):
        return {"state": "still_fenced", "reason": "cleanup-plan-readback-mismatch"}
    _, _, records = _worktree_records(repo)
    matching = [record for record in records if record.get("path") == str(checkout)]
    verified_refs = _verify_recovery_refs(
        repo, list(evidence.get("recovery_refs") or [])
    )
    refs_ok = bool(verified_refs) and all(bool(item["present"]) for item in verified_refs)
    if (
        not matching
        and stored.get("applied_at_unix") is not None
        and archive.get("cleaned_at_unix") is not None
        and archive.get("cleanup_plan_id") == plan_id
        and refs_ok
    ):
        return {
            "state": "confirmed_success",
            "archive_id": archive_id,
            "plan_id": plan_id,
            "verified_recovery_refs": verified_refs,
        }
    if (
        len(matching) == 1
        and stored.get("applied_at_unix") is None
        and archive.get("cleaned_at_unix") is None
        and refs_ok
    ):
        try:
            _require_expected(
                matching[0],
                str(evidence["expected_head"]),
                evidence.get("expected_branch"),
            )
            physical = evidence.get("expected_physical_identity")
            if isinstance(physical, dict):
                _verify_expected_physical_checkout_identity(checkout, physical)
        except Exception as exc:
            return {
                "state": "still_fenced",
                "reason": f"cleanup-no-effect-not-provable:{type(exc).__name__}",
            }
        return {
            "state": "confirmed_no_effect",
            "archive_id": archive_id,
            "plan_id": plan_id,
            "verified_recovery_refs": verified_refs,
        }
    if (
        not matching
        and stored.get("applied_at_unix") is None
        and archive.get("cleaned_at_unix") is None
        and refs_ok
    ):
        applied = _now()
        with _operation_lock():
            with _database() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current_dry = connection.execute(
                    "SELECT * FROM dry_runs WHERE plan_id=?", (plan_id,)
                ).fetchone()
                current_archive = connection.execute(
                    "SELECT * FROM archives WHERE archive_id=?", (archive_id,)
                ).fetchone()
                if (
                    current_dry is None
                    or current_archive is None
                    or current_dry["applied_at_unix"] is not None
                    or current_archive["cleaned_at_unix"] is not None
                    or current_archive["cleanup_plan_id"] is not None
                ):
                    raise RuntimeError(
                        "Cleanup reconciliation state changed during atomic readback"
                    )
                connection.execute(
                    "UPDATE dry_runs SET applied_at_unix=? WHERE plan_id=?",
                    (applied, plan_id),
                )
                connection.execute(
                    "UPDATE archives SET cleaned_at_unix=?, cleanup_plan_id=? WHERE archive_id=?",
                    (applied, plan_id, archive_id),
                )
                connection.commit()
        return {
            "state": "reconciled_success",
            "archive_id": archive_id,
            "plan_id": plan_id,
            "applied_at_unix": applied,
            "verified_recovery_refs": verified_refs,
        }
    return {
        "state": "still_fenced",
        "reason": "cleanup-outcome-remains-ambiguous",
        "verified_recovery_refs": verified_refs,
    }


@mcp.tool(name="grabowski_checkout_uncertainty_status", annotations=READ_ONLY)
def grabowski_checkout_uncertainty_status(fence_id: str = "") -> dict[str, Any]:
    """Read durable unknown-outcome fences for checkout lifecycle effects."""
    if fence_id:
        fence = _load_checkout_operation_uncertainty(fence_id)
        return {"fences": [fence], "count": 1}
    fences = _active_checkout_operation_uncertainties()
    return {"fences": fences[:256], "count": len(fences), "truncated": len(fences) > 256}


@mcp.tool(name="grabowski_checkout_uncertainty_reconcile", annotations=MUTATING)
def grabowski_checkout_uncertainty_reconcile(
    fence_id: str,
    confirmation: str,
) -> dict[str, Any]:
    """Read back one unknown checkout effect and release its fence only when proven."""
    operator._require_operator_mutation("resource_lease")
    operator._require_operator_capability("git_cli")
    if confirmation != "reconcile-checkout-operation-outcome":
        raise ValueError(
            "confirmation must be exactly 'reconcile-checkout-operation-outcome'"
        )
    fence = _load_checkout_operation_uncertainty(fence_id)
    if fence["cleared_at_unix"] is not None:
        return {"state": "already_reconciled", "fence": fence}
    wanted = set(fence["resource_keys"])
    live = [
        item
        for item in _read_resource_leases()
        if item.get("owner_id") == fence["lease_owner_id"]
        and item.get("resource_key") in wanted
    ]
    if live:
        return {
            "state": "still_fenced",
            "reason": "operation-lease-still-live",
            "fence": fence,
            "live_lease_count": len(live),
        }
    readback = (
        _archive_uncertainty_readback(fence)
        if fence["operation"] == "archive"
        else _cleanup_uncertainty_readback(fence)
    )
    outcome = str(readback.get("state"))
    if outcome == "still_fenced":
        return {"state": "still_fenced", "fence": fence, "readback": readback}
    if outcome not in {"confirmed_success", "confirmed_no_effect", "reconciled_success"}:
        raise RuntimeError("Checkout uncertainty readback returned an invalid state")
    audit = {
        "timestamp_unix": _now(),
        "operation": "checkout-operation-uncertainty-reconcile",
        "fence_id": fence["fence_id"],
        "checkout_key": fence["checkout_key"],
        "owner_id": fence["owner_id"],
        "effect_operation": fence["operation"],
        "effect_operation_id": fence["operation_id"],
        "outcome": outcome,
        "readback": readback,
    }
    base._append_audit(audit)
    lease_release = _release_uncertainty_fence_resources(fence)
    cleared = _clear_checkout_operation_uncertainty(
        fence["fence_id"],
        outcome=outcome,
        evidence={"readback": readback, "audit_timestamp_unix": audit["timestamp_unix"]},
    )
    return {
        "state": "reconciled",
        "outcome": outcome,
        "fence": cleared,
        "lease_release": lease_release,
        "readback": readback,
        "audit": audit,
    }


'''
replace_once(CHECKOUTS, release_marker, reconcile_code)

ref_start = '''def _create_recovery_ref(repo: Path, ref: str, target: str) -> dict[str, Any]:
'''
ref_end = '''def _verify_recovery_refs(repo: Path, recovery_refs: list[dict[str, str]]) -> list[dict[str, Any]]:
'''
ref_code = '''def _create_recovery_ref(
    repo: Path,
    ref: str,
    target: str,
    *,
    expected_physical_identity: dict[str, Any] | None = None,
    expected_physical_checkout: Path | None = None,
) -> dict[str, Any]:
    _check_ref_format(repo, ref)
    result = _git_mutate(
        repo,
        ["update-ref", "--create-reflog", ref, target],
        expected_physical_identity=expected_physical_identity,
        expected_physical_checkout=expected_physical_checkout,
    )
    verified = _git_read(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"]).stdout.strip()
    if verified != target:
        raise RuntimeError(f"Recovery ref verification failed: {ref}")
    return {"ref": ref, "target": target, "result": result}


'''
replace_between(CHECKOUTS, ref_start, ref_end, ref_code)

archive_sig_old = '''    expected_head: str,
    expected_branch: str | None = None,
) -> dict[str, Any]:
'''
archive_sig_new = '''    expected_head: str,
    expected_branch: str | None = None,
    expected_physical_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
'''
# This signature occurs on archive only in the exact current file.
archive_source = Path(CHECKOUTS).read_text(encoding="utf-8")
archive_start_at = archive_source.index('@mcp.tool(name="grabowski_checkout_archive", annotations=MUTATING)')
archive_end_at = archive_source.index('@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)', archive_start_at)
archive_block = archive_source[archive_start_at:archive_end_at]
if archive_block.count(archive_sig_old) != 1:
    raise SystemExit("archive signature marker is not unique inside archive function")
archive_block = archive_block.replace(archive_sig_old, archive_sig_new, 1)
Path(CHECKOUTS).write_text(
    archive_source[:archive_start_at] + archive_block + archive_source[archive_end_at:],
    encoding="utf-8",
)

archive_identity_marker = '''    _require_retention_owner(record["checkout_key"], owner)
    lifecycle_before = _lifecycle_bindings([record["checkout_key"]]).get(
'''
archive_identity_insert = '''    _require_retention_owner(record["checkout_key"], owner)
    if expected_physical_identity is None:
        archive_physical_identity = physical_checkout.capture_physical_checkout_identity(checkout)
    else:
        archive_physical_identity = _verify_expected_physical_checkout_identity(
            checkout, expected_physical_identity
        )
    lifecycle_before = _lifecycle_bindings([record["checkout_key"]]).get(
'''
replace_once(CHECKOUTS, archive_identity_marker, archive_identity_insert)

archive_fence_init_old = '''    result: dict[str, Any] | None = None
    try:
'''
archive_fence_init_new = '''    result: dict[str, Any] | None = None
    uncertainty_fence: dict[str, Any] | None = None
    try:
'''
archive_source = Path(CHECKOUTS).read_text(encoding="utf-8")
archive_start_at = archive_source.index('@mcp.tool(name="grabowski_checkout_archive", annotations=MUTATING)')
archive_end_at = archive_source.index('@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)', archive_start_at)
archive_block = archive_source[archive_start_at:archive_end_at]
if archive_block.count(archive_fence_init_old) != 1:
    raise SystemExit("archive fence-init marker is not unique inside archive function")
archive_block = archive_block.replace(archive_fence_init_old, archive_fence_init_new, 1)
Path(CHECKOUTS).write_text(
    archive_source[:archive_start_at] + archive_block + archive_source[archive_end_at:],
    encoding="utf-8",
)

archive_refs_old = '''        archive_id = _new_archive_id()
        path_hash = record["checkout_key"][:16]
        ref_base = f"{ARCHIVE_REF_ROOT}/{path_hash}/{archive_id}"
        recovery_refs = [
            _create_recovery_ref(top_level, f"{ref_base}/head", expected_head)
        ]
        branch_head = None
        if record.get("branch"):
            branch_ref = f"refs/heads/{record['branch']}"
            branch_head = _git_read(
                top_level,
                ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"],
            ).stdout.strip()
            recovery_refs.append(
                _create_recovery_ref(
                    top_level,
                    f"{ref_base}/branch-head",
                    branch_head,
                )
            )
'''
archive_refs_new = '''        archive_id = _new_archive_id()
        path_hash = record["checkout_key"][:16]
        ref_base = f"{ARCHIVE_REF_ROOT}/{path_hash}/{archive_id}"
        branch_head = None
        planned_refs = [{"ref": f"{ref_base}/head", "target": expected_head}]
        if record.get("branch"):
            branch_ref = f"refs/heads/{record['branch']}"
            branch_head = _git_read(
                top_level,
                ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"],
            ).stdout.strip()
            planned_refs.append(
                {"ref": f"{ref_base}/branch-head", "target": branch_head}
            )
        uncertainty_fence = _persist_checkout_operation_uncertainty(
            lease=lease,
            checkout_key=record["checkout_key"],
            owner_id=owner,
            operation="archive",
            operation_id=archive_id,
            evidence={
                "repo": str(top_level),
                "git_common_dir": str(common_dir),
                "checkout_path": str(checkout),
                "checkout_key": record["checkout_key"],
                "owner_id": owner,
                "archive_id": archive_id,
                "expected_head": expected_head,
                "expected_branch": record.get("branch"),
                "expected_physical_identity": archive_physical_identity,
                "planned_recovery_refs": planned_refs,
            },
        )
        recovery_refs = [
            _create_recovery_ref(
                top_level,
                item["ref"],
                item["target"],
                expected_physical_identity=archive_physical_identity,
                expected_physical_checkout=checkout,
            )
            for item in planned_refs
        ]
'''
replace_once(CHECKOUTS, archive_refs_old, archive_refs_new)

archive_tail_old = '''    finally:
        lease_release = _release_checkout_resources(lease)
    if result is None:
        raise RuntimeError("Checkout archive did not produce a result")
    result["lease_release"] = lease_release
    return result
'''
archive_tail_new = '''    except Exception:
        if uncertainty_fence is None:
            _release_checkout_resources(lease)
        raise
    if result is None or uncertainty_fence is None:
        raise RuntimeError("Checkout archive did not produce a result")
    lease_release = _release_checkout_resources(lease)
    fence_clearance = _clear_checkout_operation_uncertainty(
        uncertainty_fence["fence_id"],
        outcome="confirmed_success",
        evidence={
            "archive_id": result["archive"]["archive_id"],
            "audit_timestamp_unix": result["audit"]["timestamp_unix"],
        },
    )
    result["lease_release"] = lease_release
    result["uncertainty_fence"] = fence_clearance
    return result
'''
replace_once(CHECKOUTS, archive_tail_old, archive_tail_new)

cleanup_lease_marker = '''    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=Path(current_plan["git_common_dir"]),
        checkout_path=checkout,
        purpose="apply linked checkout cleanup",
        retention_until_unix=retention_until_unix,
        repo_path=Path(current_plan["repo"]),
        branch=current_plan.get("branch"),
        metadata={
            "plan_id": plan_id,
            "archive_id": stored["archive_id"],
            "checkout_path": str(checkout),
        },
    )
    try:
        result = _git_mutate(
'''
cleanup_lease_new = '''    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=Path(current_plan["git_common_dir"]),
        checkout_path=checkout,
        purpose="apply linked checkout cleanup",
        retention_until_unix=retention_until_unix,
        repo_path=Path(current_plan["repo"]),
        branch=current_plan.get("branch"),
        metadata={
            "plan_id": plan_id,
            "archive_id": stored["archive_id"],
            "checkout_path": str(checkout),
        },
    )
    try:
        uncertainty_fence = _persist_checkout_operation_uncertainty(
            lease=lease,
            checkout_key=current_plan["checkout_key"],
            owner_id=owner,
            operation="cleanup",
            operation_id=plan_id,
            evidence={
                "repo": current_plan["repo"],
                "git_common_dir": current_plan["git_common_dir"],
                "checkout_path": str(checkout),
                "checkout_key": current_plan["checkout_key"],
                "owner_id": owner,
                "archive_id": stored["archive_id"],
                "plan_id": plan_id,
                "plan_sha256": expected_hash,
                "expected_head": stored_plan["head"],
                "expected_branch": stored_plan["branch"],
                "expected_physical_identity": stored_physical_identity,
                "recovery_refs": current_plan["recovery_refs"],
            },
        )
    except Exception:
        _release_checkout_resources(lease)
        raise
    try:
        result = _git_mutate(
'''
replace_once(CHECKOUTS, cleanup_lease_marker, cleanup_lease_new)

cleanup_precondition_old = '''    except CheckoutPhysicalIdentityPreconditionError:
        _release_checkout_resources(lease)
        raise
'''
cleanup_precondition_new = '''    except CheckoutPhysicalIdentityPreconditionError:
        lease_release = _release_checkout_resources(lease)
        _clear_checkout_operation_uncertainty(
            uncertainty_fence["fence_id"],
            outcome="confirmed_no_effect",
            evidence={
                "reason": "physical-identity-precondition-failed-before-git-mutation",
                "lease_release": lease_release,
            },
        )
        raise
'''
replace_once(CHECKOUTS, cleanup_precondition_old, cleanup_precondition_new)

cleanup_release_before_audit = '''    lease_release = _release_checkout_resources(lease)
    audit = {
'''
cleanup_source = Path(CHECKOUTS).read_text(encoding="utf-8")
cleanup_start_at = cleanup_source.index('@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)')
cleanup_block = cleanup_source[cleanup_start_at:]
if cleanup_block.count(cleanup_release_before_audit) != 1:
    raise SystemExit("cleanup release marker is not unique inside cleanup function")
cleanup_block = cleanup_block.replace(cleanup_release_before_audit, "    audit = {\n", 1)
Path(CHECKOUTS).write_text(
    cleanup_source[:cleanup_start_at] + cleanup_block,
    encoding="utf-8",
)

cleanup_return_old = '''    base._append_audit(audit)
    return {
        "dry_run": False,
        "applied_at_unix": applied,
        "plan": current_plan,
        "lease": lease,
        "lease_release": lease_release,
        "result": result,
        "audit": audit,
    }
'''
cleanup_return_new = '''    base._append_audit(audit)
    lease_release = _release_checkout_resources(lease)
    fence_clearance = _clear_checkout_operation_uncertainty(
        uncertainty_fence["fence_id"],
        outcome="confirmed_success",
        evidence={
            "plan_id": plan_id,
            "applied_at_unix": applied,
            "audit_timestamp_unix": audit["timestamp_unix"],
        },
    )
    return {
        "dry_run": False,
        "applied_at_unix": applied,
        "plan": current_plan,
        "lease": lease,
        "lease_release": lease_release,
        "uncertainty_fence": fence_clearance,
        "result": result,
        "audit": audit,
    }
'''
replace_once(CHECKOUTS, cleanup_return_old, cleanup_return_new)

workspace_call_old = '''                        expected_head=str(plan["checkout"]["head"]),
                        expected_branch=str(plan["checkout"]["branch"]),
                    )
'''
workspace_call_new = '''                        expected_head=str(plan["checkout"]["head"]),
                        expected_branch=str(plan["checkout"]["branch"]),
                        expected_physical_identity=intent["checkout_physical_identity"],
                    )
'''
replace_once(WORKSPACE, workspace_call_old, workspace_call_new)

test_marker = '''    def test_cleanup_plan_remains_valid_when_only_archive_age_advances(self) -> None:
'''
test_code = '''    def test_archive_rechecks_physical_identity_after_resource_acquisition(self) -> None:
        expected_identity = checkouts.physical_checkout.capture_physical_checkout_identity(
            self.checkout
        )
        real_acquire = checkouts._acquire_checkout_resources
        real_verify = checkouts.physical_checkout.verify_physical_checkout_identity
        acquired = [False]

        def acquire_then_mark(*args, **kwargs):
            lease = real_acquire(*args, **kwargs)
            acquired[0] = True
            return lease

        def verify_then_drift(expected):
            if not acquired[0]:
                return real_verify(expected)
            raise checkouts.physical_checkout.PhysicalCheckoutIdentityError(
                "simulated replacement after resource acquisition"
            )

        with (
            patch.object(checkouts, "_acquire_checkout_resources", side_effect=acquire_then_mark),
            patch.object(
                checkouts.physical_checkout,
                "verify_physical_checkout_identity",
                side_effect=verify_then_drift,
            ) as verify_mock,
            patch.object(
                checkouts.operator,
                "_run",
                side_effect=AssertionError("archive Git mutation must not run"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "physical identity precondition failed"):
                checkouts.grabowski_checkout_archive(
                    str(self.repo),
                    str(self.checkout),
                    "owner-a",
                    "identity-bound archive",
                    int(time.time()) + 3600,
                    self.head,
                    "topic",
                    expected_physical_identity=expected_identity,
                )

        self.assertTrue(self.checkout.exists())
        self.assertGreaterEqual(verify_mock.call_count, 2)
        fences = checkouts._active_checkout_operation_uncertainties()
        self.assertEqual(len(fences), 1)
        self.assertEqual(fences[0]["operation"], "archive")

    def test_partial_archive_failure_remains_durably_fenced_after_lease_expiry(self) -> None:
        expected_identity = checkouts.physical_checkout.capture_physical_checkout_identity(
            self.checkout
        )
        original_create_ref = checkouts._create_recovery_ref
        calls = [0]

        def create_first_then_fail(repo, ref, target, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                return original_create_ref(repo, ref, target, **kwargs)
            raise RuntimeError("simulated second archive ref failure")

        with patch.object(
            checkouts, "_create_recovery_ref", side_effect=create_first_then_fail
        ):
            with self.assertRaisesRegex(RuntimeError, "second archive ref failure"):
                checkouts.grabowski_checkout_archive(
                    str(self.repo),
                    str(self.checkout),
                    "owner-a",
                    "partial archive",
                    int(time.time()) + 3600,
                    self.head,
                    "topic",
                    expected_physical_identity=expected_identity,
                )

        fences = checkouts._active_checkout_operation_uncertainties()
        self.assertEqual(len(fences), 1)
        fence = fences[0]
        with checkouts.resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=? WHERE owner_id=?",
                (int(time.time()) - 1, fence["lease_owner_id"]),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "durably fenced"):
            checkouts._acquire_checkout_resources(
                owner_id="owner-a",
                repo_common_dir=self._common_dir(),
                checkout_path=self.checkout,
                purpose="must remain blocked",
                retention_until_unix=int(time.time()) + 3600,
                repo_path=self.repo,
                branch="topic",
                metadata={"test": "durable-archive-fence"},
            )

    def test_cleanup_unknown_outcome_remains_durably_fenced_after_lease_expiry(self) -> None:
        archive = self._archive()["archive"]
        expected_identity = checkouts.physical_checkout.capture_physical_checkout_identity(
            self.checkout
        )
        dry_run = checkouts.grabowski_checkout_cleanup(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            dry_run=True,
            archive_id=archive["archive_id"],
            expected_head=self.head,
            expected_branch="topic",
            expected_physical_identity=expected_identity,
        )
        with patch.object(
            checkouts,
            "_git_mutate",
            side_effect=RuntimeError("simulated ambiguous cleanup mutation"),
        ):
            with self.assertRaisesRegex(RuntimeError, "ambiguous cleanup mutation"):
                checkouts.grabowski_checkout_cleanup(
                    str(self.repo),
                    str(self.checkout),
                    "owner-a",
                    dry_run=False,
                    plan_id=dry_run["dry_run_record"]["plan_id"],
                    expected_plan_sha256=dry_run["plan"]["plan_sha256"],
                    expected_physical_identity=expected_identity,
                    confirmation="remove-linked-checkout",
                )

        fences = checkouts._active_checkout_operation_uncertainties()
        self.assertEqual(len(fences), 1)
        fence = fences[0]
        self.assertEqual(fence["operation"], "cleanup")
        with checkouts.resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=? WHERE owner_id=?",
                (int(time.time()) - 1, fence["lease_owner_id"]),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "durably fenced"):
            checkouts._acquire_checkout_resources(
                owner_id="owner-a",
                repo_common_dir=self._common_dir(),
                checkout_path=self.checkout,
                purpose="must remain blocked",
                retention_until_unix=int(time.time()) + 3600,
                repo_path=self.repo,
                branch="topic",
                metadata={"test": "durable-cleanup-fence"},
            )

''' + test_marker
replace_once(TESTS, test_marker, test_code)

workspace_source = Path(WORKSPACE).read_text(encoding="utf-8")
if workspace_source.count(workspace_call_new) != 1:
    raise SystemExit("workspace archive call is not exactly identity-bound")

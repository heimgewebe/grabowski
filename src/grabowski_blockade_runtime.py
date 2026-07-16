"""Typed runtime adapter for scoped, evidence-bound operator blockades."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import uuid
from typing import Any

import grabowski_blockades as policy
import grabowski_blockade_store as store
import grabowski_mcp as base
import grabowski_privileged as privileged
import grabowski_recovery as recovery

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
QUARANTINE_ROOT = base.STATE_DIR / "recovery" / "blockade-quarantine"


def _timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("expires_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def _scope_action(record: policy.BlockadeRecord, **values: Any) -> policy.ActionContext:
    context: dict[str, Any] = {
        "action_class": values.pop("action_class"),
        **values,
    }
    field = {
        "path": "path",
        "capability": "capability",
        "task": "task_id",
        "owner": "owner_id",
        "repo": "repo",
        "service": "service",
        "host": "host",
        "global": None,
    }[record.scope.kind]
    if field is not None and context.get(field) is None:
        context[field] = record.scope.value
    return policy.ActionContext(**context)


def _matching_engage_audit(
    snapshot: store.MarkerSnapshot,
) -> dict[str, Any]:
    for item in reversed(base._audit_records()):
        if item.get("path") != str(base.KILL_SWITCH_PATH):
            continue
        if (
            item.get("operation") in {
                "operator-blockade-engage",
                "operator-blockade-migration-complete",
            }
            and item.get("blockade_id") == snapshot.record.blockade_id
            and item.get("blockade_record_sha256") == snapshot.record_sha256
            and item.get("after_sha256") == snapshot.file_sha256
        ):
            return item
        raise PermissionError(
            "latest canonical marker audit record is not the matching typed engagement"
        )
    raise PermissionError(
        "typed blockade marker has no matching engagement audit record"
    )


def _append_verified_audit(record: dict[str, Any]) -> dict[str, Any]:
    appended = base._append_audit(record)
    status = base._verify_audit_log(base.AUDIT_LOG)
    if not status.get("valid"):
        raise RuntimeError(
            f"audit verification failed after blockade transaction: {status.get('error')}"
        )
    matches = [
        item
        for item in base._audit_records()
        if item.get("operation") == record.get("operation")
        and item.get("transaction_id") == record.get("transaction_id")
        and item.get("path") == record.get("path")
    ]
    if len(matches) != 1:
        raise RuntimeError("blockade audit readback is missing or ambiguous")
    return {"append": appended, "verification": status, "record": matches[0]}


def _recovery_evidence() -> tuple[dict[str, Any], bool, bool, bool]:
    status = recovery.recovery_status()
    checks = status.get("checks", {})
    deployment_valid = bool(checks.get("deployment_provenance"))
    canonical_fresh = all(
        bool(checks.get(name))
        for name in (
            "audit_chain",
            "local_backup_fresh",
            "backup_timer_enabled",
            "backup_timer_active",
            "server_recovery_fresh",
            "server_recovery_source_current",
        )
    )
    broker_ready = bool(checks.get("privileged_broker_ready"))
    return status, deployment_valid, canonical_fresh, broker_ready


def _canonical_snapshot() -> store.MarkerSnapshot:
    expected_uid, expected_mode, require_private = base._canonical_marker_contract()
    return store.read_blockade_marker(
        base.KILL_SWITCH_PATH,
        expected_marker_path=base.KILL_SWITCH_PATH,
        expected_uid=expected_uid,
        expected_mode=expected_mode,
        require_private_parent=require_private,
    )


def _exact_marker_readback(
    *,
    record_sha256: str,
    marker_file_sha256: str,
) -> store.MarkerSnapshot | None:
    if not (base.KILL_SWITCH_PATH.exists() or base.KILL_SWITCH_PATH.is_symlink()):
        return None
    snapshot = _canonical_snapshot()
    if (
        snapshot.record_sha256 != record_sha256
        or snapshot.file_sha256 != marker_file_sha256
    ):
        raise PermissionError("canonical marker readback differs from requested hashes")
    return snapshot


def _lifecycle_call(payload: dict[str, Any], *, justification: str) -> dict[str, Any]:
    try:
        return privileged.run_blockade_lifecycle_reference(
            payload,
            justification=justification,
        )
    except BaseException as exc:
        return {
            "success": False,
            "outcome": "unknown",
            "failure_reason": f"{type(exc).__name__}: {exc}",
            "lifecycle": None,
            "broker_response": None,
        }


def _observe_lifecycle(
    *,
    transaction_id: str,
    record_sha256: str,
    marker_file_sha256: str,
) -> dict[str, Any]:
    observed = _lifecycle_call(
        {
            "operation": "observe",
            "transaction_id": transaction_id,
            "expected_record_sha256": record_sha256,
            "expected_marker_file_sha256": marker_file_sha256,
        },
        justification="Observe one exact blockade marker lifecycle transaction",
    )
    lifecycle = observed.get("lifecycle")
    if not observed.get("success") or not isinstance(lifecycle, dict):
        raise RuntimeError(
            "blockade lifecycle outcome remains unknown after root readback: "
            + str(observed.get("failure_reason"))
        )
    return lifecycle


def _ensure_private_quarantine_root() -> Path:
    root = base._state_subdir(QUARANTINE_ROOT)
    metadata = os.stat(root, follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PermissionError("blockade quarantine root is unsafe")
    return root


@mcp.tool(name="grabowski_operator_blockade_status", annotations=READ_ONLY)
def grabowski_operator_blockade_status(
    action_class: str = "status",
    path: str | None = None,
    capability: str | None = None,
    task_id: str | None = None,
    owner_id: str | None = None,
    repo: str | None = None,
    service: str | None = None,
    host: str | None = None,
    fresh_preflight: bool = False,
) -> dict[str, Any]:
    """Evaluate current typed, legacy and environment blockades for one action."""
    base._require_capability("audit_verify")
    records, diagnostics = base._operator_blockade_records()
    action = policy.ActionContext(
        action_class=action_class,
        path=path,
        capability=capability,
        task_id=task_id,
        owner_id=owner_id,
        repo=repo,
        service=service,
        host=host,
        fresh_preflight=fresh_preflight,
    )
    decision = policy.evaluate_blockades(records, action)
    return {
        "schema_version": 1,
        "marker_path": str(base.KILL_SWITCH_PATH),
        "records": [record.to_mapping() for record in records],
        "record_sha256s": [record.sha256 for record in records],
        "decision": decision.to_mapping(),
        "diagnostics": diagnostics,
        "does_not_establish": [
            "future_action_authority",
            "fresh_preflight_completion",
            "recovery_disarm_authority",
            "kernel_isolation_from_same_uid_out_of_band_execution",
            "complete_prevention_of_arbitrary_indirect_marker_mutation",
        ],
    }


@mcp.tool(name="grabowski_operator_blockade_engage", annotations=MUTATING)
def grabowski_operator_blockade_engage(
    blockade_id: str,
    posture: str,
    scope_kind: str,
    scope_value: str,
    reason: str,
    trigger_class: str,
    evidence_refs: list[str],
    request_id: str,
    session_id: str,
    task_id: str,
    owner_id: str,
    expires_at: str | None = None,
    fresh_preflight: bool = False,
) -> dict[str, Any]:
    """Create one root-owned typed blockade through the narrow broker."""
    base._require_capability("audit_verify")
    base._require_mutations_enabled(
        "file_write",
        path=str(base.KILL_SWITCH_PATH),
        fresh_preflight=fresh_preflight,
        allow_blockade_lifecycle=True,
    )
    state = base._kill_switch_state()
    if state.get("environment"):
        raise PermissionError("external environment stop is engaged")
    if (
        base.LEGACY_KILL_SWITCH_PATH.exists()
        or base.LEGACY_KILL_SWITCH_PATH.is_symlink()
    ):
        raise PermissionError("legacy marker requires exact broker migration first")
    record = policy.BlockadeRecord(
        blockade_id=blockade_id,
        posture=posture,
        scope=policy.Scope(scope_kind, scope_value),
        reason=reason,
        trigger_class=trigger_class,
        engaged_at=datetime.now(timezone.utc),
        expires_at=_timestamp(expires_at),
        evidence_refs=tuple(evidence_refs),
        provenance=policy.Provenance(
            tool="grabowski_operator_blockade_engage",
            request_id=request_id,
            session_id=session_id,
            task_id=task_id,
            owner_id=owner_id,
        ),
    )
    marker_bytes = policy.canonical_json(record.to_mapping())
    transaction_id = uuid.uuid4().hex
    marker_file_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    broker = _lifecycle_call(
        {
            "operation": "engage",
            "transaction_id": transaction_id,
            "record": record.to_mapping(),
            "record_sha256": record.sha256,
            "marker_file_sha256": marker_file_sha256,
        },
        justification="Create one exact root-owned operator blockade marker",
    )
    readback = _exact_marker_readback(
        record_sha256=record.sha256,
        marker_file_sha256=marker_file_sha256,
    )
    if readback is None:
        raise RuntimeError(
            "blockade engagement did not produce the exact canonical marker: "
            + str(broker.get("failure_reason"))
        )
    lifecycle = broker.get("lifecycle")
    receipt = (
        lifecycle.get("receipt")
        if isinstance(lifecycle, dict) and isinstance(lifecycle.get("receipt"), dict)
        else store.EngageReceipt(
            transaction_id=transaction_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            marker_path=str(base.KILL_SWITCH_PATH),
            marker_file_sha256=marker_file_sha256,
            record_sha256=record.sha256,
            record=record,
        ).to_mapping()
    )
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "operator-blockade-engage",
        "transaction_id": transaction_id,
        "path": str(base.KILL_SWITCH_PATH),
        "before_sha256": None,
        "after_sha256": marker_file_sha256,
        "blockade_id": record.blockade_id,
        "blockade_record_sha256": record.sha256,
        "posture": record.posture,
        "scope": record.scope.to_mapping(),
        "evidence_refs": list(record.evidence_refs),
        "provenance": record.provenance.to_mapping(),
        "broker_outcome": broker.get("outcome"),
    }
    try:
        audit = _append_verified_audit(audit_record)
    except BaseException as audit_failure:
        rollback = _lifecycle_call(
            {
                "operation": "rollback-engage",
                "transaction_id": transaction_id,
                "expected_record_sha256": record.sha256,
                "expected_marker_file_sha256": marker_file_sha256,
            },
            justification="Rollback one exact unaudited root-owned blockade engagement",
        )
        if base.KILL_SWITCH_PATH.exists() or base.KILL_SWITCH_PATH.is_symlink():
            raise store.BlockadeRollbackError(
                "engagement audit failed and broker rollback was not verified: "
                + str(rollback.get("failure_reason"))
            ) from audit_failure
        raise store.BlockadeRollbackError(
            "engagement audit failed; exact root-owned marker was rolled back"
        ) from audit_failure
    return {
        "schema_version": 2,
        "operation": "engage",
        "receipt": receipt,
        "record_sha256": readback.record_sha256,
        "marker_file_sha256": readback.file_sha256,
        "broker": broker,
        "audit": audit,
        "kill_switch": base._kill_switch_state(),
    }


@mcp.tool(name="grabowski_operator_blockade_migrate_legacy", annotations=MUTATING)
def grabowski_operator_blockade_migrate_legacy(
    blockade_id: str,
    expected_record_sha256: str,
    expected_marker_file_sha256: str,
) -> dict[str, Any]:
    """Move one exact typed legacy marker into the root-owned authority domain."""
    base._require_capability("audit_verify")
    base._require_capability("file_move")
    base._require_valid_audit_chain()
    if base._kill_switch_state().get("environment"):
        raise PermissionError("external environment stop is engaged")
    if base.KILL_SWITCH_PATH.exists() or base.KILL_SWITCH_PATH.is_symlink():
        raise FileExistsError("canonical blockade marker already exists")
    legacy = store.read_blockade_marker(
        base.LEGACY_KILL_SWITCH_PATH,
        expected_marker_path=base.LEGACY_KILL_SWITCH_PATH,
        expected_uid=os.getuid(),
        expected_mode=0o600,
        require_private_parent=True,
    )
    if legacy.record.blockade_id != blockade_id:
        raise PermissionError("legacy blockade_id precondition failed")
    if legacy.record_sha256 != expected_record_sha256:
        raise PermissionError("legacy record SHA-256 precondition failed")
    if legacy.file_sha256 != expected_marker_file_sha256:
        raise PermissionError("legacy marker SHA-256 precondition failed")
    transaction_id = uuid.uuid4().hex
    intent = _append_verified_audit(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": "operator-blockade-migration-intent",
            "transaction_id": transaction_id,
            "path": str(base.LEGACY_KILL_SWITCH_PATH),
            "destination_path": str(base.KILL_SWITCH_PATH),
            "before_sha256": legacy.file_sha256,
            "after_sha256": None,
            "blockade_id": legacy.record.blockade_id,
            "blockade_record_sha256": legacy.record_sha256,
        }
    )
    broker = _lifecycle_call(
        {
            "operation": "migrate",
            "transaction_id": transaction_id,
            "expected_record_sha256": legacy.record_sha256,
            "expected_marker_file_sha256": legacy.file_sha256,
        },
        justification="Migrate one exact typed legacy blockade into root authority",
    )
    canonical = _exact_marker_readback(
        record_sha256=legacy.record_sha256,
        marker_file_sha256=legacy.file_sha256,
    )
    legacy_present = (
        base.LEGACY_KILL_SWITCH_PATH.exists()
        or base.LEGACY_KILL_SWITCH_PATH.is_symlink()
    )
    if canonical is None and legacy_present:
        raise RuntimeError(
            "legacy blockade migration did not publish the canonical marker: "
            + str(broker.get("failure_reason"))
        )
    if canonical is None:
        raise store.BlockadeRollbackError(
            "legacy blockade migration outcome is ambiguous; no exact marker is observable"
        )
    try:
        legacy_readback = store.read_blockade_marker(
            base.LEGACY_KILL_SWITCH_PATH,
            expected_marker_path=base.LEGACY_KILL_SWITCH_PATH,
            expected_uid=os.getuid(),
            expected_mode=0o600,
            require_private_parent=True,
        )
        if (
            legacy_readback.record.blockade_id != blockade_id
            or legacy_readback.record_sha256 != expected_record_sha256
            or legacy_readback.file_sha256 != expected_marker_file_sha256
        ):
            raise PermissionError("legacy marker changed after canonical publication")
        legacy_receipt = store.EngageReceipt(
            transaction_id=transaction_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            marker_path=str(base.LEGACY_KILL_SWITCH_PATH),
            marker_file_sha256=legacy_readback.file_sha256,
            record_sha256=legacy_readback.record_sha256,
            record=legacy_readback.record,
        )
        legacy_removal = store.rollback_engaged_marker(
            legacy_receipt,
            base.LEGACY_KILL_SWITCH_PATH,
            expected_marker_path=base.LEGACY_KILL_SWITCH_PATH,
            expected_uid=os.getuid(),
            marker_mode=0o600,
            require_private_parent=True,
        )
    except BaseException as legacy_failure:
        # Never remove the canonical marker here. Keeping both copies engaged
        # preserves the blockade while making the incomplete migration visible.
        raise store.BlockadeRollbackError(
            "canonical marker is engaged but exact legacy removal failed"
        ) from legacy_failure
    canonical = _exact_marker_readback(
        record_sha256=legacy.record_sha256,
        marker_file_sha256=legacy.file_sha256,
    )
    if canonical is None or (
        base.LEGACY_KILL_SWITCH_PATH.exists()
        or base.LEGACY_KILL_SWITCH_PATH.is_symlink()
    ):
        raise store.BlockadeRollbackError(
            "legacy migration post-state is not exact; canonical blockade remains fail-closed"
        )
    completion = _append_verified_audit(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation": "operator-blockade-migration-complete",
            "transaction_id": transaction_id,
            "path": str(base.KILL_SWITCH_PATH),
            "legacy_path": str(base.LEGACY_KILL_SWITCH_PATH),
            "before_sha256": legacy.file_sha256,
            "after_sha256": canonical.file_sha256,
            "blockade_id": canonical.record.blockade_id,
            "blockade_record_sha256": canonical.record_sha256,
            "legacy_removal_sha256": hashlib.sha256(
                policy.canonical_json(legacy_removal)
            ).hexdigest(),
            "migration_intent_record_sha256": intent.get("record_sha256"),
            "broker_outcome": broker.get("outcome"),
        }
    )
    return {
        "schema_version": 2,
        "operation": "migrate-legacy",
        "transaction_id": transaction_id,
        "record_sha256": canonical.record_sha256,
        "marker_file_sha256": canonical.file_sha256,
        "legacy_removal": legacy_removal,
        "intent_audit": intent,
        "completion_audit": completion,
        "broker": broker,
        "kill_switch": base._kill_switch_state(),
    }


@mcp.tool(name="grabowski_operator_blockade_disarm", annotations=MUTATING)
def grabowski_operator_blockade_disarm(
    blockade_id: str,
    expected_record_sha256: str,
    expected_marker_file_sha256: str,
) -> dict[str, Any]:
    """Quarantine one exact root-owned blockade after recovery evidence passes."""
    base._require_capability("audit_verify")
    base._require_capability("file_move")
    base._require_valid_audit_chain()
    if (
        base.LEGACY_KILL_SWITCH_PATH.exists()
        or base.LEGACY_KILL_SWITCH_PATH.is_symlink()
    ):
        raise PermissionError("legacy marker remains present; disarm is ambiguous")
    snapshot = _canonical_snapshot()
    if snapshot.record.blockade_id != blockade_id:
        raise PermissionError("blockade_id precondition failed")
    if snapshot.record_sha256 != expected_record_sha256:
        raise PermissionError("record SHA-256 precondition failed")
    if snapshot.file_sha256 != expected_marker_file_sha256:
        raise PermissionError("marker file SHA-256 precondition failed")
    engage_audit = _matching_engage_audit(snapshot)
    state = base._kill_switch_state()
    recovery_status, deployment_valid, canonical_fresh, broker_ready = (
        _recovery_evidence()
    )
    authority_uid, _mode, _private = base._canonical_marker_contract()
    evidence = policy.DisarmEvidence(
        blockade_id=blockade_id,
        record_sha256=expected_record_sha256,
        scope=snapshot.record.scope,
        marker_path=str(base.KILL_SWITCH_PATH),
        marker_present=True,
        marker_regular=True,
        marker_nlink=snapshot.nlink,
        marker_mode=snapshot.mode,
        marker_owner_matches=snapshot.uid == authority_uid,
        environment_switch_off=not bool(state.get("environment")),
        audit_valid=True,
        deployment_provenance_valid=deployment_valid,
        canonical_recovery_fresh=canonical_fresh,
        root_broker_ready=broker_ready,
    )
    records, diagnostics = base._operator_blockade_records()
    action = _scope_action(
        snapshot.record,
        action_class="recovery_disarm",
        expected_marker_path=str(base.KILL_SWITCH_PATH),
        disarm_evidence=evidence,
    )
    decision = policy.evaluate_blockades(records, action)
    if not decision.allowed:
        raise PermissionError("blockade disarm denied: " + ",".join(decision.reasons))
    transaction_id = uuid.uuid4().hex
    broker = _lifecycle_call(
        {
            "operation": "disarm",
            "transaction_id": transaction_id,
            "blockade_id": blockade_id,
            "expected_record_sha256": expected_record_sha256,
            "expected_marker_file_sha256": expected_marker_file_sha256,
        },
        justification="Quarantine one exact root-owned blockade after recovery validation",
    )
    lifecycle = broker.get("lifecycle")
    if not broker.get("success") or not isinstance(lifecycle, dict):
        lifecycle = _observe_lifecycle(
            transaction_id=transaction_id,
            record_sha256=expected_record_sha256,
            marker_file_sha256=expected_marker_file_sha256,
        )
    if lifecycle.get("state") == "engaged":
        raise RuntimeError(
            "blockade disarm did not commit: " + str(broker.get("failure_reason"))
        )
    receipt = lifecycle.get("receipt")
    receipt_sha256 = lifecycle.get("receipt_sha256")
    if not isinstance(receipt, dict) or not isinstance(receipt_sha256, str):
        raise RuntimeError("blockade disarm has no exact root receipt")
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "operator-blockade-disarm",
        "transaction_id": transaction_id,
        "path": str(base.KILL_SWITCH_PATH),
        "before_sha256": snapshot.file_sha256,
        "after_sha256": None,
        "blockade_id": snapshot.record.blockade_id,
        "blockade_record_sha256": snapshot.record_sha256,
        "quarantine_path": receipt.get("quarantine_path"),
        "receipt_path": receipt.get("receipt_path"),
        "receipt_sha256": receipt_sha256,
        "engage_audit_record_sha256": engage_audit.get("record_sha256"),
        "broker_outcome": broker.get("outcome"),
    }
    try:
        audit = _append_verified_audit(audit_record)
    except BaseException as audit_failure:
        restore = _lifecycle_call(
            {
                "operation": "restore-disarm",
                "transaction_id": transaction_id,
                "expected_record_sha256": expected_record_sha256,
                "expected_marker_file_sha256": expected_marker_file_sha256,
                "expected_disarm_receipt_sha256": receipt_sha256,
            },
            justification="Restore one exact unaudited root-owned blockade disarm",
        )
        restored = _exact_marker_readback(
            record_sha256=expected_record_sha256,
            marker_file_sha256=expected_marker_file_sha256,
        )
        if restored is None:
            raise store.BlockadeRollbackError(
                "disarm audit failed and exact root restore was not verified: "
                + str(restore.get("failure_reason"))
            ) from audit_failure
        raise store.BlockadeRollbackError(
            "disarm audit failed; exact root-owned marker was restored"
        ) from audit_failure
    if base.KILL_SWITCH_PATH.exists() or base.KILL_SWITCH_PATH.is_symlink():
        raise RuntimeError("canonical marker reappeared after verified disarm")
    return {
        "schema_version": 2,
        "operation": "disarm",
        "receipt": receipt,
        "receipt_sha256": receipt_sha256,
        "decision": decision.to_mapping(),
        "diagnostics": diagnostics,
        "recovery": recovery_status,
        "broker": broker,
        "audit": audit,
        "kill_switch": base._kill_switch_state(),
    }

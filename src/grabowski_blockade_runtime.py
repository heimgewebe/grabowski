"""Typed runtime adapter for scoped, evidence-bound operator blockades."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import stat
from typing import Any

import grabowski_blockades as policy
import grabowski_blockade_store as store
import grabowski_mcp as base
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
            item.get("operation") == "operator-blockade-engage"
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
    """Create one canonical typed blockade marker without replacing any entry."""
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
    receipt = store.engage_blockade_marker(
        record,
        base.KILL_SWITCH_PATH,
        expected_marker_path=base.KILL_SWITCH_PATH,
    )
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "operator-blockade-engage",
        "transaction_id": receipt.transaction_id,
        "path": str(base.KILL_SWITCH_PATH),
        "before_sha256": None,
        "after_sha256": receipt.marker_file_sha256,
        "blockade_id": record.blockade_id,
        "blockade_record_sha256": record.sha256,
        "posture": record.posture,
        "scope": record.scope.to_mapping(),
        "evidence_refs": list(record.evidence_refs),
        "provenance": record.provenance.to_mapping(),
    }
    try:
        audit = _append_verified_audit(audit_record)
    except BaseException as audit_failure:
        try:
            rollback = store.rollback_engaged_marker(
                receipt,
                base.KILL_SWITCH_PATH,
                expected_marker_path=base.KILL_SWITCH_PATH,
            )
        except BaseException as rollback_failure:
            raise store.BlockadeRollbackError(
                "blockade engagement audit failed and exact marker rollback was not verified"
            ) from rollback_failure
        raise store.BlockadeRollbackError(
            "blockade engagement audit failed; exact marker was removed: "
            f"{rollback['removed_marker_file_sha256']}"
        ) from audit_failure
    readback = store.read_blockade_marker(
        base.KILL_SWITCH_PATH,
        expected_marker_path=base.KILL_SWITCH_PATH,
    )
    return {
        "schema_version": 1,
        "operation": "engage",
        "receipt": receipt.to_mapping(),
        "record_sha256": readback.record_sha256,
        "marker_file_sha256": readback.file_sha256,
        "audit": audit,
        "kill_switch": base._kill_switch_state(),
    }


@mcp.tool(name="grabowski_operator_blockade_disarm", annotations=MUTATING)
def grabowski_operator_blockade_disarm(
    blockade_id: str,
    expected_record_sha256: str,
    expected_marker_file_sha256: str,
) -> dict[str, Any]:
    """Quarantine one exact typed blockade after live recovery evidence passes."""
    base._require_capability("audit_verify")
    base._require_valid_audit_chain()
    snapshot = store.read_blockade_marker(
        base.KILL_SWITCH_PATH,
        expected_marker_path=base.KILL_SWITCH_PATH,
    )
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
    evidence = policy.DisarmEvidence(
        blockade_id=blockade_id,
        record_sha256=expected_record_sha256,
        scope=snapshot.record.scope,
        marker_path=str(base.KILL_SWITCH_PATH),
        marker_present=True,
        marker_regular=True,
        marker_nlink=snapshot.nlink,
        marker_mode=snapshot.mode,
        marker_owner_matches=snapshot.uid == os.getuid(),
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
    quarantine_root = _ensure_private_quarantine_root()
    receipt = store.disarm_blockade_marker(
        snapshot.record,
        evidence,
        base.KILL_SWITCH_PATH,
        quarantine_root,
        expected_marker_path=base.KILL_SWITCH_PATH,
        expected_quarantine_root=quarantine_root,
    )
    audit_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "operator-blockade-disarm",
        "transaction_id": receipt.transaction_id,
        "path": str(base.KILL_SWITCH_PATH),
        "before_sha256": snapshot.file_sha256,
        "after_sha256": None,
        "blockade_id": snapshot.record.blockade_id,
        "blockade_record_sha256": snapshot.record_sha256,
        "quarantine_path": receipt.quarantine_path,
        "receipt_path": receipt.receipt_path,
        "receipt_sha256": receipt.receipt_sha256,
        "engage_audit_record_sha256": engage_audit.get("record_sha256"),
    }
    try:
        audit = _append_verified_audit(audit_record)
    except BaseException as exc:
        store.restore_disarmed_marker(
            receipt.transaction_id,
            base.KILL_SWITCH_PATH,
            quarantine_root,
            expected_marker_path=base.KILL_SWITCH_PATH,
            expected_quarantine_root=quarantine_root,
            expected_record_sha256=receipt.record_sha256,
            expected_marker_file_sha256=receipt.marker_file_sha256,
            expected_disarm_receipt_sha256=receipt.receipt_sha256,
        )
        raise store.BlockadeRollbackError(
            "disarm audit publication failed; exact marker was restored"
        ) from exc
    if base.KILL_SWITCH_PATH.exists() or base.KILL_SWITCH_PATH.is_symlink():
        raise RuntimeError("canonical marker reappeared after verified disarm")
    return {
        "schema_version": 1,
        "operation": "disarm",
        "receipt": receipt.to_mapping(),
        "receipt_sha256": receipt.receipt_sha256,
        "decision": decision.to_mapping(),
        "diagnostics": diagnostics,
        "recovery": recovery_status,
        "audit": audit,
        "kill_switch": base._kill_switch_state(),
    }

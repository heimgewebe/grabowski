from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TERMINAL_TASK_STATES = frozenset({"completed", "failed", "cancelled", "timed_out", "signalled"})
ATTENTION_GATED_TASK_STATES = frozenset({"failed", "timed_out", "signalled"})
RECOVERY_TASK_STATES = frozenset({"interrupted", "outcome_unknown"})
ACTIVE_TASK_STATES = frozenset({"launching", "running"})
CURRENT_CLASSIFICATIONS = frozenset(
    {"active", "blocking", "recovery_required", "ambiguous", "untouchable"}
)
LIFECYCLE_CLASSIFICATIONS = frozenset(
    {*CURRENT_CLASSIFICATIONS, "terminal_archivable", "archived"}
)


class LifecycleArchiveError(RuntimeError):
    pass


class LifecycleArchiveIntegrityError(LifecycleArchiveError):
    pass


@dataclass(frozen=True)
class LifecycleEvidence:
    identity: str
    kind: str
    state: str | None = None
    closed: bool | None = None
    archived: bool = False
    dirty: bool | None = False
    active_task: bool | None = False
    active_process: bool | None = False
    active_lease: bool | None = False
    foreign_retention: bool | None = False
    shared_reference: bool | None = False
    open_task_role: bool | None = False
    retention_recovery_required: bool | None = False
    tmux_session_only: bool | None = False
    receipt_integrity_valid: bool | None = True
    observation_errors: tuple[str, ...] = ()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _unknown_boolean_fields(evidence: LifecycleEvidence) -> list[str]:
    fields = (
        "dirty",
        "active_task",
        "active_process",
        "active_lease",
        "foreign_retention",
        "shared_reference",
        "open_task_role",
        "retention_recovery_required",
        "tmux_session_only",
        "receipt_integrity_valid",
    )
    return [name for name in fields if getattr(evidence, name) is None]


def classify_lifecycle(evidence: LifecycleEvidence) -> dict[str, Any]:
    """Classify one live-observed lifecycle object without creating cleanup authority."""
    if not evidence.identity:
        raise ValueError("identity must not be empty")
    if not evidence.kind:
        raise ValueError("kind must not be empty")

    reasons: list[str] = []
    unknown_fields = _unknown_boolean_fields(evidence)
    if evidence.observation_errors:
        reasons.extend(f"observation_error:{value}" for value in evidence.observation_errors)
    if unknown_fields:
        reasons.extend(f"observation_unknown:{value}" for value in unknown_fields)
    if reasons:
        classification = "ambiguous"
    elif evidence.archived:
        if evidence.receipt_integrity_valid is not True:
            classification = "recovery_required"
            reasons.append("archive_receipt_integrity_missing_or_invalid")
        elif evidence.retention_recovery_required:
            classification = "recovery_required"
            reasons.append("retention_recovery_archive_required")
        elif evidence.tmux_session_only:
            classification = "ambiguous"
            reasons.append("tmux_session_without_live_role_or_process")
        else:
            contradictory = any(
                (
                    evidence.active_task,
                    evidence.active_process,
                    evidence.active_lease,
                    evidence.dirty,
                    evidence.foreign_retention,
                    evidence.shared_reference,
                    evidence.open_task_role,
                )
            )
            if contradictory or evidence.state in ACTIVE_TASK_STATES | RECOVERY_TASK_STATES:
                classification = "ambiguous"
                reasons.append("archived_state_conflicts_with_live_evidence")
            else:
                classification = "archived"
                reasons.append("archive_receipt_present")
    elif evidence.foreign_retention:
        classification = "untouchable"
        reasons.append("foreign_retention")
    elif evidence.dirty:
        classification = "untouchable"
        reasons.append("dirty_checkout")
    elif evidence.shared_reference:
        classification = "untouchable"
        reasons.append("shared_reference")
    elif evidence.open_task_role:
        classification = "active"
        reasons.append("open_task_role")
    elif evidence.active_task or evidence.state in ACTIVE_TASK_STATES:
        classification = "active"
        reasons.append("active_task")
    elif evidence.active_process:
        classification = "active"
        reasons.append("active_process")
    elif evidence.active_lease:
        classification = "blocking"
        reasons.append("active_lease")
    elif evidence.retention_recovery_required:
        classification = "recovery_required"
        reasons.append("retention_recovery_archive_required")
    elif evidence.tmux_session_only:
        classification = "ambiguous"
        reasons.append("tmux_session_without_live_role_or_process")
    elif evidence.state in RECOVERY_TASK_STATES:
        classification = "recovery_required"
        reasons.append(f"task_state:{evidence.state}")
    elif evidence.state in TERMINAL_TASK_STATES or evidence.closed is True:
        if evidence.receipt_integrity_valid is not True:
            classification = "recovery_required"
            reasons.append("terminal_receipt_integrity_missing_or_invalid")
        else:
            classification = "terminal_archivable"
            reasons.append("terminal_and_unblocked")
    else:
        classification = "blocking"
        reasons.append("not_terminal")

    return {
        "schema_version": SCHEMA_VERSION,
        "identity": evidence.identity,
        "kind": evidence.kind,
        "classification": classification,
        "reason_codes": reasons,
        "safe_to_archive": classification == "terminal_archivable",
        "does_not_establish": [
            "deletion_authority",
            "absence_of_future_activity",
            "permission_to_override_foreign_ownership",
        ],
    }


def bounded_current_projection(
    records: Iterable[Mapping[str, Any]],
    classifications: Mapping[str, Mapping[str, Any]],
    *,
    identity_field: str = "task_id",
) -> list[dict[str, Any]]:
    """Keep only handlungsrelevante records in the default current projection."""
    current: list[dict[str, Any]] = []
    for record in records:
        identity = record.get(identity_field)
        if not isinstance(identity, str):
            raise ValueError(f"record is missing string {identity_field}")
        lifecycle = classifications.get(identity)
        if lifecycle is None:
            raise LifecycleArchiveIntegrityError(
                f"missing lifecycle classification for {identity}"
            )
        classification = lifecycle.get("classification")
        if classification not in LIFECYCLE_CLASSIFICATIONS:
            raise LifecycleArchiveIntegrityError(
                f"invalid lifecycle classification for {identity}: {classification}"
            )
        if classification in CURRENT_CLASSIFICATIONS:
            current.append(dict(record))
    return current


def _record_sort_key(record: Mapping[str, Any]) -> tuple[int, str]:
    created = record.get("created_at_unix")
    identity = record.get("task_id")
    if not isinstance(created, int):
        raise ValueError("task record created_at_unix must be an integer")
    if not isinstance(identity, str) or not identity:
        raise ValueError("task record task_id must be a non-empty string")
    return created, identity


def _validated_task_record(record: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(record)
    _record_sort_key(value)
    state = value.get("state")
    if state not in TERMINAL_TASK_STATES:
        raise LifecycleArchiveError(f"task {value['task_id']} is not terminal")
    receipt = value.get("lifecycle_receipt_sha256")
    if not isinstance(receipt, str) or SHA256.fullmatch(receipt) is None:
        raise LifecycleArchiveError(
            f"task {value['task_id']} lacks a valid lifecycle receipt digest"
        )
    return value


def build_task_archive_plan(
    records: Iterable[Mapping[str, Any]],
    classifications: Mapping[str, Mapping[str, Any]],
    *,
    now_unix: int,
    minimum_age_seconds: int,
) -> dict[str, Any]:
    if minimum_age_seconds < 0:
        raise ValueError("minimum_age_seconds must be non-negative")
    cutoff = now_unix - minimum_age_seconds
    eligible: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for raw in records:
        record = dict(raw)
        identity = record.get("task_id")
        if not isinstance(identity, str):
            raise ValueError("task record task_id must be a string")
        lifecycle = classifications.get(identity)
        if lifecycle is None:
            raise LifecycleArchiveIntegrityError(
                f"missing lifecycle classification for {identity}"
            )
        classification = lifecycle.get("classification")
        terminalized_at = record.get("terminalized_at_unix")
        updated_at = record.get("updated_at_unix")
        age_anchor = terminalized_at if isinstance(terminalized_at, int) else updated_at
        reason_codes: list[str] = []
        if classification != "terminal_archivable":
            reason_codes.append(f"classification:{classification}")
        if not isinstance(age_anchor, int):
            reason_codes.append("age_anchor_missing")
        elif age_anchor > cutoff:
            reason_codes.append("minimum_retention_not_met")
        receipt = record.get("lifecycle_receipt_sha256")
        if not isinstance(receipt, str) or SHA256.fullmatch(receipt) is None:
            reason_codes.append("lifecycle_receipt_missing_or_invalid")
        state = record.get("state")
        if state in ATTENTION_GATED_TASK_STATES:
            import grabowski_task_attention as task_attention
            import grabowski_tasks as task_store

            try:
                authoritative_record = task_store._row_raw(identity)
                if (
                    authoritative_record.get("state") != state
                    or authoritative_record.get("lifecycle_receipt_sha256") != receipt
                ):
                    reason_codes.append("attention_authority_binding_mismatch")
                else:
                    closeout = task_attention.terminal_closeout_plan(authoritative_record)
                    if not closeout.get("archive_ready"):
                        reason_codes.append(
                            f"attention_closeout:{closeout.get('closeout_state') or 'invalid'}"
                        )
            except Exception:
                reason_codes.append("attention_authority_unavailable")
        if reason_codes:
            blocked.append({"task_id": identity, "reason_codes": reason_codes})
        else:
            eligible.append(_validated_task_record(record))
    eligible.sort(key=_record_sort_key)
    plan_body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_task_archive_plan",
        "now_unix": now_unix,
        "minimum_age_seconds": minimum_age_seconds,
        "cutoff_unix": cutoff,
        "eligible_task_ids": [record["task_id"] for record in eligible],
        "eligible_record_sha256s": [sha256_json(record) for record in eligible],
        "blocked": sorted(blocked, key=lambda value: value["task_id"]),
        "attention_gate": {
            "required_states": sorted(ATTENTION_GATED_TASK_STATES),
            "authority": "grabowski_task_attention.terminal_closeout_plan",
            "binding": ["task_id", "state", "lifecycle_receipt_sha256"],
            "fail_closed": True,
        },
        "mutation_performed": False,
        "does_not_establish": [
            "permission_to_delete_task_rows",
            "workspace_cleanup_authority",
            "checkout_cleanup_authority",
        ],
    }
    return {**plan_body, "plan_sha256": sha256_json(plan_body)}


def _validate_archive_write_root(path: Path, *, label: str) -> None:
    if path.is_symlink():
        raise LifecycleArchiveIntegrityError(f"{label} may not be a symlink")
    if path.exists() and not path.is_dir():
        raise LifecycleArchiveIntegrityError(f"{label} must be a directory")


def _task_archive_effect_resource_key(path: Path) -> str:
    return f"path:{path.expanduser().resolve()}"


def _now_unix() -> int:
    return int(time.time())


def _validate_task_archive_effect_binding(
    records: Iterable[Mapping[str, Any]],
    *,
    archive_root: Path,
    effect_root: Path,
    archive_plan: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import grabowski_lifecycle_effect_plan as effect_plan

    _validate_archive_write_root(archive_root, label="task archive root")
    _validate_archive_write_root(effect_root, label="task archive effect root")
    try:
        validated_plan = effect_plan._validate_plan(plan)
    except (ValueError, effect_plan.LifecycleEffectPlanError) as exc:
        raise LifecycleArchiveIntegrityError(str(exc)) from exc
    if validated_plan.get("effect_kind") != "task_archive":
        raise LifecycleArchiveIntegrityError(
            "task archive execution requires task_archive effect plan"
        )
    required = validated_plan.get("required_resource_keys")
    archive_resource = _task_archive_effect_resource_key(archive_root)
    effect_resource = _task_archive_effect_resource_key(effect_root)
    if archive_resource == effect_resource:
        raise LifecycleArchiveIntegrityError(
            "task archive and effect roots must be distinct"
        )
    expected_resources = {archive_resource, effect_resource}
    if not isinstance(required, list) or set(required) != expected_resources:
        raise LifecycleArchiveIntegrityError(
            "task archive effect plan lacks exact archive and effect resources"
        )
    value = dict(archive_plan)
    if value.get("kind") != "grabowski_task_archive_plan":
        raise LifecycleArchiveIntegrityError("task archive dry-run plan kind is invalid")
    expected_plan_sha256 = value.get("plan_sha256")
    if not isinstance(expected_plan_sha256, str) or SHA256.fullmatch(expected_plan_sha256) is None:
        raise LifecycleArchiveIntegrityError("task archive dry-run plan digest is invalid")
    plan_body = {key: item for key, item in value.items() if key != "plan_sha256"}
    if sha256_json(plan_body) != expected_plan_sha256:
        raise LifecycleArchiveIntegrityError("task archive dry-run plan digest mismatch")
    if value.get("mutation_performed") is not False:
        raise LifecycleArchiveIntegrityError("task archive dry-run plan is not mutation-free")
    blocked = value.get("blocked")
    if not isinstance(blocked, list) or blocked:
        raise LifecycleArchiveError("task archive dry-run plan contains blocked records")
    ordered = sorted(
        (_validated_task_record(record) for record in records),
        key=_record_sort_key,
    )
    if not ordered:
        raise ValueError("task archive effect requires at least one task record")
    task_ids = [record["task_id"] for record in ordered]
    record_sha256s = [sha256_json(record) for record in ordered]
    if value.get("eligible_task_ids") != task_ids:
        raise LifecycleArchiveIntegrityError(
            "task archive dry-run identities do not match effect records"
        )
    if value.get("eligible_record_sha256s") != record_sha256s:
        raise LifecycleArchiveIntegrityError(
            "task archive dry-run record digests do not match effect records"
        )
    entries = validated_plan.get("entries")
    if not isinstance(entries, list):
        raise LifecycleArchiveIntegrityError("task archive effect plan entries are invalid")
    effect_ids = sorted(
        entry.get("identity") for entry in entries if isinstance(entry, Mapping)
    )
    if len(effect_ids) != len(entries) or effect_ids != sorted(task_ids):
        raise LifecycleArchiveIntegrityError(
            "task archive effect plan identities do not match archive records"
        )
    if any(entry.get("lifecycle_kind") != "task" for entry in entries):
        raise LifecycleArchiveIntegrityError(
            "task archive effect plan contains non-task lifecycle entries"
        )
    return ordered, validated_plan


def _task_archive_segment_dir_for_effect(
    records: Sequence[Mapping[str, Any]],
    *,
    archive_root: Path,
    source_store_sha256: str,
    source_schema_version: str,
    archive_plan_sha256: str,
) -> Path:
    payload, _record_hashes = _segment_payload(records)
    segment_sha256 = hashlib.sha256(payload).hexdigest()
    identity_sha256 = sha256_json(
        {
            "source_store_sha256": source_store_sha256,
            "source_schema_version": source_schema_version,
            "plan_sha256": archive_plan_sha256,
            "segment_sha256": segment_sha256,
        }
    )
    return archive_root / f"segment-{identity_sha256[:24]}"


def _existing_task_archive_effect_result(
    records: Sequence[Mapping[str, Any]],
    *,
    archive_root: Path,
    effect_root: Path,
    source_store_sha256: str,
    source_schema_version: str,
    archive_plan: Mapping[str, Any],
    plan: Mapping[str, Any],
    execution_id: str,
) -> dict[str, Any] | None:
    import grabowski_lifecycle_effect_plan as effect_plan

    receipt_path = effect_root / "receipts" / (
        f"receipt-{effect_plan._execution_id_sha256(execution_id)}.json"
    )
    if not receipt_path.exists():
        return None
    try:
        payload = _read_regular_bytes(
            receipt_path,
            max_bytes=effect_plan.MAX_EFFECT_RECEIPT_BYTES,
        )
        raw_receipt = json.loads(payload.decode("utf-8"))
    except (LifecycleArchiveIntegrityError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleArchiveIntegrityError(
            "existing task archive effect receipt is unreadable"
        ) from exc
    if not isinstance(raw_receipt, Mapping):
        raise LifecycleArchiveIntegrityError(
            "existing task archive effect receipt is invalid"
        )
    revalidation_sha256 = raw_receipt.get("revalidation_sha256")
    if not isinstance(revalidation_sha256, str) or SHA256.fullmatch(revalidation_sha256) is None:
        raise LifecycleArchiveIntegrityError(
            "existing task archive effect receipt revalidation digest is invalid"
        )
    persisted_plan = effect_plan.verify_effect_plan(
        effect_root / "plans" / f"plan-{plan['plan_sha256']}.json"
    )
    if persisted_plan["plan"] != dict(plan):
        raise LifecycleArchiveIntegrityError(
            "existing task archive effect plan conflicts with requested plan"
        )
    persisted_revalidation = effect_plan.verify_effect_revalidation(
        effect_root
        / "revalidations"
        / f"revalidation-{revalidation_sha256}.json",
        plan=plan,
    )
    receipt_result = effect_plan.verify_effect_execution_receipt(
        receipt_path,
        plan=plan,
        revalidation=persisted_revalidation["revalidation"],
    )
    receipt = receipt_result["receipt"]
    if receipt["status"] == "recovery_required":
        raise LifecycleArchiveError(
            "existing task archive execution requires recovery; blind retry is forbidden"
        )
    if receipt["status"] != "succeeded":
        raise LifecycleArchiveError(
            "existing task archive execution is not reusable; use a new execution identity"
        )
    segment_dir = _task_archive_segment_dir_for_effect(
        records,
        archive_root=archive_root,
        source_store_sha256=source_store_sha256,
        source_schema_version=source_schema_version,
        archive_plan_sha256=str(archive_plan["plan_sha256"]),
    )
    archived = verify_task_archive_segment(segment_dir)
    manifest = archived["manifest"]
    expected_post_state = {
        "archive_manifest": str(manifest["manifest_sha256"]),
        "archive_segment": str(manifest["segment_sha256"]),
        "task_archive_plan": str(archive_plan["plan_sha256"]),
    }
    if receipt["post_state_sha256s"] != expected_post_state:
        raise LifecycleArchiveIntegrityError(
            "existing task archive effect receipt post-state does not match archive"
        )
    return {
        **archived,
        "idempotent_replay": True,
        "effect_plan_path": persisted_plan["plan_path"],
        "effect_revalidation_path": persisted_revalidation["revalidation_path"],
        "effect_receipt": {**receipt_result, "idempotent_replay": True},
        "post_state_sha256s": expected_post_state,
    }


def execute_task_archive_effect(
    records: Iterable[Mapping[str, Any]],
    *,
    archive_root: Path,
    effect_root: Path,
    source_store_sha256: str,
    source_schema_version: str,
    archive_plan: Mapping[str, Any],
    plan: Mapping[str, Any],
    current_classifications: Mapping[str, Mapping[str, Any]],
    lease_observations: Iterable[Any],
    execution_id: str,
) -> dict[str, Any]:
    import grabowski_lifecycle_effect_plan as effect_plan

    ordered, validated_plan = _validate_task_archive_effect_binding(
        records,
        archive_root=archive_root,
        effect_root=effect_root,
        archive_plan=archive_plan,
        plan=plan,
    )
    existing = _existing_task_archive_effect_result(
        ordered,
        archive_root=archive_root,
        effect_root=effect_root,
        source_store_sha256=source_store_sha256,
        source_schema_version=source_schema_version,
        archive_plan=archive_plan,
        plan=validated_plan,
        execution_id=execution_id,
    )
    if existing is not None:
        return existing
    revalidation = effect_plan.revalidate_effect_plan(
        validated_plan,
        current_classifications,
        lease_observations,
        now_unix=_now_unix(),
    )
    if revalidation["ready_for_effect"] is not True:
        raise LifecycleArchiveError(
            "task archive effect revalidation is not ready: "
            + ", ".join(revalidation["errors"])
        )
    plan_root = effect_root / "plans"
    revalidation_root = effect_root / "revalidations"
    receipt_root = effect_root / "receipts"
    _validate_archive_write_root(plan_root, label="task archive effect plan root")
    _validate_archive_write_root(
        revalidation_root,
        label="task archive effect revalidation root",
    )
    _validate_archive_write_root(receipt_root, label="task archive effect receipt root")
    persisted_plan = effect_plan.write_effect_plan(
        validated_plan,
        plan_root=plan_root,
    )
    persisted_revalidation = effect_plan.write_effect_revalidation(
        revalidation,
        revalidation_root=revalidation_root,
        plan=validated_plan,
    )
    started_at_unix = _now_unix()
    if started_at_unix >= effect_plan._earliest_revalidation_lease_expiry(
        revalidation
    ):
        raise LifecycleArchiveError("task archive effect is not covered by bound leases")
    try:
        archived = write_task_archive_segment(
            ordered,
            archive_root=archive_root,
            source_store_sha256=source_store_sha256,
            source_schema_version=source_schema_version,
            plan_sha256=str(archive_plan["plan_sha256"]),
        )
    except Exception:
        completed_at_unix = max(started_at_unix, _now_unix())
        recovery_receipt = effect_plan.build_effect_execution_receipt(
            validated_plan,
            revalidation,
            execution_id=execution_id,
            started_at_unix=started_at_unix,
            completed_at_unix=completed_at_unix,
            transport_outcome="unknown",
            mutation_state="unknown",
            post_state_status="unavailable",
            recovery_refs=[str(archive_root.expanduser().resolve())],
        )
        effect_plan.write_effect_execution_receipt(
            recovery_receipt,
            receipt_root=receipt_root,
            plan=validated_plan,
            revalidation=revalidation,
        )
        raise
    manifest = archived["manifest"]
    post_state_sha256s = {
        "archive_manifest": str(manifest["manifest_sha256"]),
        "archive_segment": str(manifest["segment_sha256"]),
        "task_archive_plan": str(archive_plan["plan_sha256"]),
    }
    completed_at_unix = _now_unix()
    receipt = effect_plan.build_effect_execution_receipt(
        validated_plan,
        revalidation,
        execution_id=execution_id,
        started_at_unix=started_at_unix,
        completed_at_unix=completed_at_unix,
        transport_outcome="confirmed_success",
        mutation_state=(
            "not_performed" if archived["idempotent_replay"] else "performed"
        ),
        post_state_status="verified",
        post_state_sha256s=post_state_sha256s,
    )
    receipt_path = receipt_root / (
        f"receipt-{effect_plan._execution_id_sha256(execution_id)}.json"
    )
    try:
        receipt_result = effect_plan.write_effect_execution_receipt(
            receipt,
            receipt_root=receipt_root,
            plan=validated_plan,
            revalidation=revalidation,
        )
    except Exception as receipt_error:
        try:
            receipt_readback = effect_plan.verify_effect_execution_receipt(
                receipt_path,
                plan=validated_plan,
                revalidation=revalidation,
            )
        except Exception:
            receipt_readback = None
        if receipt_readback is not None and receipt_readback["receipt"] == receipt:
            receipt_result = {**receipt_readback, "idempotent_replay": True}
        else:
            recovery_execution_id = (
                execution_id
                if not receipt_path.exists()
                else "task-archive-recovery:"
                + hashlib.sha256(execution_id.encode("utf-8")).hexdigest()
            )
            recovery_receipt = effect_plan.build_effect_execution_receipt(
                validated_plan,
                revalidation,
                execution_id=recovery_execution_id,
                started_at_unix=started_at_unix,
                completed_at_unix=max(completed_at_unix, _now_unix()),
                transport_outcome="unknown",
                mutation_state="unknown",
                post_state_status="unavailable",
                recovery_refs=[
                    str(archive_root.expanduser().resolve()),
                    str(receipt_path),
                ],
            )
            effect_plan.write_effect_execution_receipt(
                recovery_receipt,
                receipt_root=receipt_root,
                plan=validated_plan,
                revalidation=revalidation,
            )
            raise LifecycleArchiveError(
                "task archive segment is verified but success receipt outcome is ambiguous; recovery required"
            ) from receipt_error
    return {
        **archived,
        "effect_plan_path": persisted_plan["plan_path"],
        "effect_revalidation_path": persisted_revalidation["revalidation_path"],
        "effect_receipt": receipt_result,
        "post_state_sha256s": post_state_sha256s,
    }


def _write_create_only(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _segment_payload(records: Sequence[Mapping[str, Any]]) -> tuple[bytes, list[str]]:
    lines: list[bytes] = []
    record_hashes: list[str] = []
    for raw in records:
        record = _validated_task_record(raw)
        encoded = canonical_json_bytes(record)
        record_hashes.append(hashlib.sha256(encoded).hexdigest())
        lines.append(encoded + b"\n")
    return b"".join(lines), record_hashes


def write_task_archive_segment(
    records: Iterable[Mapping[str, Any]],
    *,
    archive_root: Path,
    source_store_sha256: str,
    source_schema_version: str,
    plan_sha256: str,
) -> dict[str, Any]:
    _validate_archive_write_root(archive_root, label="task archive root")
    if SHA256.fullmatch(source_store_sha256) is None:
        raise ValueError("source_store_sha256 must be a lowercase SHA-256 digest")
    if SHA256.fullmatch(plan_sha256) is None:
        raise ValueError("plan_sha256 must be a lowercase SHA-256 digest")
    ordered = sorted((_validated_task_record(record) for record in records), key=_record_sort_key)
    if not ordered:
        raise ValueError("archive segment requires at least one task record")
    payload, record_hashes = _segment_payload(ordered)
    segment_sha256 = hashlib.sha256(payload).hexdigest()
    segment_identity_body = {
        "source_store_sha256": source_store_sha256,
        "source_schema_version": source_schema_version,
        "plan_sha256": plan_sha256,
        "segment_sha256": segment_sha256,
    }
    segment_identity_sha256 = sha256_json(segment_identity_body)
    segment_id = f"segment-{segment_identity_sha256[:24]}"
    segment_dir = archive_root / segment_id
    manifest_body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_task_archive_segment",
        "segment_id": segment_id,
        "segment_identity_sha256": segment_identity_sha256,
        "source_store_sha256": source_store_sha256,
        "source_schema_version": source_schema_version,
        "plan_sha256": plan_sha256,
        "record_count": len(ordered),
        "first_task_id": ordered[0]["task_id"],
        "last_task_id": ordered[-1]["task_id"],
        "first_created_at_unix": ordered[0]["created_at_unix"],
        "last_created_at_unix": ordered[-1]["created_at_unix"],
        "first_record_sha256": record_hashes[0],
        "last_record_sha256": record_hashes[-1],
        "record_sha256s": record_hashes,
        "segment_sha256": segment_sha256,
        "records_file": "records.jsonl",
        "does_not_establish": [
            "permission_to_delete_source_records",
            "source_store_unchanged_after_archive",
        ],
    }
    manifest = {**manifest_body, "manifest_sha256": sha256_json(manifest_body)}
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(archive_root, 0o700)
    if segment_dir.exists():
        verified = verify_task_archive_segment(segment_dir)
        if verified["manifest"] != manifest:
            raise LifecycleArchiveIntegrityError(
                "existing archive segment identity conflicts with requested segment"
            )
        return {**verified, "idempotent_replay": True}
    segment_dir.mkdir(mode=0o700)
    try:
        _write_create_only(segment_dir / "records.jsonl", payload)
        manifest_payload = json.dumps(
            manifest,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ).encode("utf-8") + b"\n"
        _write_create_only(segment_dir / "manifest.json", manifest_payload)
        _fsync_directory(segment_dir)
        _fsync_directory(archive_root)
        verified = verify_task_archive_segment(segment_dir)
    except Exception:
        for candidate in (segment_dir / "manifest.json", segment_dir / "records.jsonl"):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
        try:
            segment_dir.rmdir()
        except OSError:
            pass
        raise
    return {**verified, "idempotent_replay": False}


def _read_regular_bytes(
    path: Path,
    *,
    max_bytes: int | None = None,
) -> bytes:
    if max_bytes is not None and (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a non-negative integer or None")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LifecycleArchiveIntegrityError(
            f"archive file is missing or unsafe: {path.name}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LifecycleArchiveIntegrityError(
                f"archive file is missing or unsafe: {path.name}"
            )
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise LifecycleArchiveIntegrityError(
                f"archive file exceeds server-owned read bound: {path.name}"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read() if max_bytes is None else handle.read(max_bytes + 1)
        if max_bytes is not None and len(payload) > max_bytes:
            raise LifecycleArchiveIntegrityError(
                f"archive file exceeds server-owned read bound: {path.name}"
            )
        return payload
    finally:
        os.close(descriptor)


def _validate_task_archive_manifest(
    segment_dir: Path,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    expected_manifest_sha256 = manifest.get("manifest_sha256")
    if (
        not isinstance(expected_manifest_sha256, str)
        or SHA256.fullmatch(expected_manifest_sha256) is None
    ):
        raise LifecycleArchiveIntegrityError("archive manifest digest is missing or invalid")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if sha256_json(body) != expected_manifest_sha256:
        raise LifecycleArchiveIntegrityError("archive manifest digest mismatch")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleArchiveIntegrityError("unsupported archive manifest schema")
    if manifest.get("kind") != "grabowski_task_archive_segment":
        raise LifecycleArchiveIntegrityError("archive manifest kind mismatch")
    if manifest.get("segment_id") != segment_dir.name:
        raise LifecycleArchiveIntegrityError("archive segment identity mismatch")

    for key in (
        "source_store_sha256",
        "plan_sha256",
        "segment_sha256",
        "segment_identity_sha256",
    ):
        value = manifest.get(key)
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise LifecycleArchiveIntegrityError(f"archive manifest {key} is invalid")
    identity_body = {
        "source_store_sha256": manifest["source_store_sha256"],
        "source_schema_version": manifest.get("source_schema_version"),
        "plan_sha256": manifest["plan_sha256"],
        "segment_sha256": manifest["segment_sha256"],
    }
    if sha256_json(identity_body) != manifest["segment_identity_sha256"]:
        raise LifecycleArchiveIntegrityError("archive segment identity digest mismatch")
    if segment_dir.name != f"segment-{manifest['segment_identity_sha256'][:24]}":
        raise LifecycleArchiveIntegrityError("archive segment directory name mismatch")

    record_count = manifest.get("record_count")
    record_sha256s = manifest.get("record_sha256s")
    if isinstance(record_count, bool) or not isinstance(record_count, int) or record_count < 1:
        raise LifecycleArchiveIntegrityError("archive record count is invalid")
    if not isinstance(record_sha256s, list) or len(record_sha256s) != record_count:
        raise LifecycleArchiveIntegrityError("archive record hash sequence is invalid")
    if any(
        not isinstance(value, str) or SHA256.fullmatch(value) is None
        for value in record_sha256s
    ):
        raise LifecycleArchiveIntegrityError(
            "archive record hash sequence contains invalid digest"
        )
    if manifest.get("first_record_sha256") != record_sha256s[0]:
        raise LifecycleArchiveIntegrityError("archive first record digest mismatch")
    if manifest.get("last_record_sha256") != record_sha256s[-1]:
        raise LifecycleArchiveIntegrityError("archive last record digest mismatch")

    return {
        "manifest_sha256": expected_manifest_sha256,
        "record_hash_sequence_sha256": sha256_json(record_sha256s),
    }


def verify_task_archive_segment(
    segment_dir: Path,
    *,
    max_manifest_bytes: int | None = None,
    max_records_bytes: int | None = None,
) -> dict[str, Any]:
    if segment_dir.is_symlink() or not segment_dir.is_dir():
        raise LifecycleArchiveIntegrityError("archive segment must be a regular directory")
    manifest_path = segment_dir / "manifest.json"
    records_path = segment_dir / "records.jsonl"
    try:
        manifest_payload = _read_regular_bytes(
            manifest_path,
            max_bytes=max_manifest_bytes,
        )
        manifest = json.loads(manifest_payload.decode("utf-8"))
    except LifecycleArchiveIntegrityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleArchiveIntegrityError("archive manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise LifecycleArchiveIntegrityError("archive manifest must be an object")
    manifest_evidence = _validate_task_archive_manifest(segment_dir, manifest)
    payload = _read_regular_bytes(
        records_path,
        max_bytes=max_records_bytes,
    )
    if hashlib.sha256(payload).hexdigest() != manifest.get("segment_sha256"):
        raise LifecycleArchiveIntegrityError("archive segment digest mismatch")
    raw_lines = payload.splitlines()
    if len(raw_lines) != manifest.get("record_count"):
        raise LifecycleArchiveIntegrityError("archive record count mismatch")
    record_hashes = [hashlib.sha256(line).hexdigest() for line in raw_lines]
    if record_hashes != manifest.get("record_sha256s"):
        raise LifecycleArchiveIntegrityError("archive record hash sequence mismatch")
    records: list[dict[str, Any]] = []
    for line in raw_lines:
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LifecycleArchiveIntegrityError("archive record is invalid JSON") from exc
        records.append(_validated_task_record(value))
    if not records:
        raise LifecycleArchiveIntegrityError("archive segment is empty")
    if records != sorted(records, key=_record_sort_key):
        raise LifecycleArchiveIntegrityError("archive record order is not canonical")
    if records[0]["task_id"] != manifest.get("first_task_id"):
        raise LifecycleArchiveIntegrityError("archive first task identity mismatch")
    if records[-1]["task_id"] != manifest.get("last_task_id"):
        raise LifecycleArchiveIntegrityError("archive last task identity mismatch")
    if record_hashes[0] != manifest.get("first_record_sha256"):
        raise LifecycleArchiveIntegrityError("archive first record digest mismatch")
    if record_hashes[-1] != manifest.get("last_record_sha256"):
        raise LifecycleArchiveIntegrityError("archive last record digest mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "verified",
        "segment_dir": str(segment_dir),
        "manifest": manifest,
        "records": records,
        "records_bytes": len(payload),
        "record_hash_sequence_sha256": manifest_evidence[
            "record_hash_sequence_sha256"
        ],
    }

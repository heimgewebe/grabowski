from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TERMINAL_TASK_STATES = frozenset({"completed", "failed", "cancelled", "timed_out", "signalled"})
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
        "mutation_performed": False,
        "does_not_establish": [
            "permission_to_delete_task_rows",
            "workspace_cleanup_authority",
            "checkout_cleanup_authority",
        ],
    }
    return {**plan_body, "plan_sha256": sha256_json(plan_body)}


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
    for path in (manifest_path, records_path):
        if path.is_symlink() or not path.is_file():
            raise LifecycleArchiveIntegrityError(f"archive file is missing or unsafe: {path.name}")
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
    expected_manifest_sha256 = manifest.get("manifest_sha256")
    if not isinstance(expected_manifest_sha256, str):
        raise LifecycleArchiveIntegrityError("archive manifest digest is missing")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if sha256_json(body) != expected_manifest_sha256:
        raise LifecycleArchiveIntegrityError("archive manifest digest mismatch")
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
    }

"""Root-owned authority boundary for the canonical operator blockade marker."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable

from grabowski_blockades import BlockadeRecord, DisarmEvidence, canonical_json
from grabowski_blockade_store import (
    BlockadeRollbackError,
    EngageReceipt,
    MarkerSnapshot,
    disarm_blockade_marker,
    engage_blockade_marker,
    read_blockade_marker,
    read_disarm_receipt,
    restore_disarmed_marker,
    rollback_engaged_marker,
)

MARKER_MODE = 0o644
MARKER_DIRECTORY_MODE = 0o711
QUARANTINE_DIRECTORY_MODE = 0o700
MAX_TARGET_BYTES = 48 * 1024


def _sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _nonempty(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} is invalid")
    return value


def _absolute_path(value: Any, *, label: str) -> Path:
    path = Path(_nonempty(value, label=label))
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    return path


def _uid(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} is invalid")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_authority_directory(path: Path, *, uid: int, mode: int) -> None:
    parent = path.parent
    parent_meta = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(parent_meta.st_mode):
        raise PermissionError("authority directory parent is unsafe")
    if parent_meta.st_uid != uid or parent_meta.st_mode & 0o022:
        raise PermissionError("authority directory parent is not authority-owned")
    created = False
    try:
        os.mkdir(path, mode=0o700)
        created = True
    except FileExistsError:
        pass
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if created:
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            _fsync_directory(parent)
        metadata = os.fstat(descriptor)
        visible = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_mode & 0o022
            or (metadata.st_dev, metadata.st_ino)
            != (visible.st_dev, visible.st_ino)
        ):
            raise PermissionError("authority directory ownership or mode is invalid")
    finally:
        os.close(descriptor)


def read_authority_marker(path: Path, *, authority_uid: int = 0) -> MarkerSnapshot:
    return read_blockade_marker(
        path,
        expected_marker_path=path,
        expected_uid=authority_uid,
        expected_mode=MARKER_MODE,
        require_private_parent=False,
    )


def _decode_target(target_text: str) -> dict[str, Any]:
    if not isinstance(target_text, str):
        raise ValueError("blockade lifecycle target must be text")
    if len(target_text.encode("utf-8")) > MAX_TARGET_BYTES:
        raise ValueError("blockade lifecycle target exceeds byte limit")
    try:
        target = json.loads(target_text)
    except json.JSONDecodeError as exc:
        raise ValueError("blockade lifecycle target is not valid JSON") from exc
    if not isinstance(target, dict):
        raise ValueError("blockade lifecycle target must be an object")
    return target


def _base_execution(candidate: dict[str, Any], operation: str) -> dict[str, Any]:
    marker = _absolute_path(candidate["marker_path"], label="marker_path")
    legacy = _absolute_path(
        candidate["legacy_marker_path"], label="legacy_marker_path"
    )
    quarantine = _absolute_path(
        candidate["quarantine_root"], label="quarantine_root"
    )
    if marker == legacy or marker.parent == legacy.parent:
        raise PermissionError("canonical and legacy marker domains are not separated")
    if quarantine.parent != marker.parent:
        raise PermissionError("quarantine must be inside the canonical authority domain")
    return {
        "mode": "blockade-marker-lifecycle",
        "internal_action": f"blockade-marker-{operation}",
        "operation": operation,
        "marker_path": str(marker),
        "legacy_marker_path": str(legacy),
        "quarantine_root": str(quarantine),
        "authority_uid": _uid(candidate["authority_uid"], label="authority_uid"),
        "legacy_uid": _uid(candidate["legacy_uid"], label="legacy_uid"),
        "allowed_peer_unit": _nonempty(
            candidate["allowed_peer_unit"], label="allowed_peer_unit"
        ),
        "allowed_peer_uid": _uid(
            candidate["allowed_peer_uid"], label="allowed_peer_uid"
        ),
    }


def resolve_lifecycle(
    candidate: dict[str, Any],
    target_text: str,
    *,
    recovery_gate_validator: Callable[[Any], dict[str, Any]],
) -> dict[str, Any]:
    required = {
        "enabled",
        "mode",
        "marker_path",
        "legacy_marker_path",
        "quarantine_root",
        "authority_uid",
        "legacy_uid",
        "allowed_peer_unit",
        "allowed_peer_uid",
        "recovery_gate",
    }
    if (
        not isinstance(candidate, dict)
        or set(candidate) != required
        or candidate.get("enabled") is not True
        or candidate.get("mode") != "blockade-marker-lifecycle"
    ):
        raise PermissionError("blockade marker authority is disabled or malformed")
    target = _decode_target(target_text)
    operation = target.get("operation")
    if operation not in {
        "engage",
        "disarm",
        "migrate",
        "rollback-engage",
        "restore-disarm",
        "observe",
    }:
        raise PermissionError("blockade lifecycle operation is not enabled")
    base = _base_execution(candidate, operation)
    transaction_id = _nonempty(target.get("transaction_id"), label="transaction_id")

    if operation == "engage":
        expected = {
            "operation",
            "record",
            "record_sha256",
            "marker_file_sha256",
            "transaction_id",
        }
        if set(target) != expected:
            raise ValueError("blockade engage target keys are invalid")
        record = BlockadeRecord.from_mapping(target["record"])
        record_sha = _sha256(target["record_sha256"], label="record_sha256")
        file_sha = _sha256(
            target["marker_file_sha256"], label="marker_file_sha256"
        )
        payload = canonical_json(record.to_mapping())
        if (
            record.sha256 != record_sha
            or hashlib.sha256(payload).hexdigest() != file_sha
        ):
            raise PermissionError("blockade engage hashes do not match canonical record")
        return {
            **base,
            "transaction_id": transaction_id,
            "record": record.to_mapping(),
            "record_sha256": record_sha,
            "marker_file_sha256": file_sha,
        }

    if operation == "disarm":
        expected = {
            "operation",
            "blockade_id",
            "expected_record_sha256",
            "expected_marker_file_sha256",
            "transaction_id",
        }
        if set(target) != expected:
            raise ValueError("blockade disarm target keys are invalid")
        return {
            **base,
            "transaction_id": transaction_id,
            "blockade_id": _nonempty(target["blockade_id"], label="blockade_id"),
            "expected_record_sha256": _sha256(
                target["expected_record_sha256"],
                label="expected_record_sha256",
            ),
            "expected_marker_file_sha256": _sha256(
                target["expected_marker_file_sha256"],
                label="expected_marker_file_sha256",
            ),
            "recovery_gate": recovery_gate_validator(candidate["recovery_gate"]),
        }

    if operation in {"migrate", "rollback-engage", "observe"}:
        expected = {
            "operation",
            "expected_record_sha256",
            "expected_marker_file_sha256",
            "transaction_id",
        }
        if set(target) != expected:
            raise ValueError(f"blockade {operation} target keys are invalid")
        resolved = {
            **base,
            "transaction_id": transaction_id,
            "expected_record_sha256": _sha256(
                target["expected_record_sha256"],
                label="expected_record_sha256",
            ),
            "expected_marker_file_sha256": _sha256(
                target["expected_marker_file_sha256"],
                label="expected_marker_file_sha256",
            ),
        }
        if operation == "rollback-engage":
            # Removing a canonical marker is a disarm-equivalent effect. The
            # rollback path therefore requires the same root-owned recovery
            # gate as an ordinary disarm; exact hashes alone are insufficient.
            resolved["recovery_gate"] = recovery_gate_validator(
                candidate["recovery_gate"]
            )
        return resolved

    expected = {
        "operation",
        "expected_record_sha256",
        "expected_marker_file_sha256",
        "expected_disarm_receipt_sha256",
        "transaction_id",
    }
    if set(target) != expected:
        raise ValueError("blockade restore-disarm target keys are invalid")
    return {
        **base,
        "transaction_id": transaction_id,
        "expected_record_sha256": _sha256(
            target["expected_record_sha256"], label="expected_record_sha256"
        ),
        "expected_marker_file_sha256": _sha256(
            target["expected_marker_file_sha256"],
            label="expected_marker_file_sha256",
        ),
        "expected_disarm_receipt_sha256": _sha256(
            target["expected_disarm_receipt_sha256"],
            label="expected_disarm_receipt_sha256",
        ),
    }


def _engage_receipt_from_snapshot(
    execution: dict[str, Any], snapshot: MarkerSnapshot
) -> EngageReceipt:
    return EngageReceipt(
        transaction_id=execution["transaction_id"],
        created_at=datetime.now(timezone.utc).isoformat(),
        marker_path=execution["marker_path"],
        marker_file_sha256=snapshot.file_sha256,
        record_sha256=snapshot.record_sha256,
        record=snapshot.record,
    )


def _validate_snapshot(execution: dict[str, Any], snapshot: MarkerSnapshot) -> None:
    if (
        snapshot.record_sha256 != execution["expected_record_sha256"]
        or snapshot.file_sha256 != execution["expected_marker_file_sha256"]
    ):
        raise PermissionError("marker changed before lifecycle operation")


def execute_lifecycle(execution: dict[str, Any]) -> dict[str, Any]:
    uid = int(execution["authority_uid"])
    if os.geteuid() != uid:
        raise PermissionError("blockade lifecycle must run as the configured authority")
    marker = Path(execution["marker_path"])
    legacy = Path(execution["legacy_marker_path"])
    quarantine = Path(execution["quarantine_root"])
    _ensure_authority_directory(
        marker.parent, uid=uid, mode=MARKER_DIRECTORY_MODE
    )
    _ensure_authority_directory(
        quarantine, uid=uid, mode=QUARANTINE_DIRECTORY_MODE
    )
    operation = execution["operation"]

    if operation == "engage":
        if legacy.exists() or legacy.is_symlink():
            raise PermissionError(
                "legacy marker must be migrated before canonical engagement"
            )
        record = BlockadeRecord.from_mapping(execution["record"])
        receipt = engage_blockade_marker(
            record,
            marker,
            expected_marker_path=marker,
            expected_uid=uid,
            marker_mode=MARKER_MODE,
            require_private_parent=False,
            transaction_id=execution["transaction_id"],
        )
        if (
            receipt.record_sha256 != execution["record_sha256"]
            or receipt.marker_file_sha256 != execution["marker_file_sha256"]
        ):
            raise BlockadeRollbackError("engage receipt differs from requested hashes")
        mapping = receipt.to_mapping()
        return {
            "operation": operation,
            "receipt": mapping,
            "receipt_sha256": hashlib.sha256(canonical_json(mapping)).hexdigest(),
        }

    if operation == "rollback-engage":
        snapshot = read_authority_marker(marker, authority_uid=uid)
        _validate_snapshot(execution, snapshot)
        removed = rollback_engaged_marker(
            _engage_receipt_from_snapshot(execution, snapshot),
            marker,
            expected_marker_path=marker,
            expected_uid=uid,
            marker_mode=MARKER_MODE,
            require_private_parent=False,
        )
        return {"operation": operation, "rollback": removed}

    if operation == "disarm":
        snapshot = read_authority_marker(marker, authority_uid=uid)
        _validate_snapshot(execution, snapshot)
        if snapshot.record.blockade_id != execution["blockade_id"]:
            raise PermissionError("blockade_id precondition failed")
        evidence = DisarmEvidence(
            blockade_id=snapshot.record.blockade_id,
            record_sha256=snapshot.record_sha256,
            scope=snapshot.record.scope,
            marker_path=str(marker),
            marker_present=True,
            marker_regular=True,
            marker_nlink=snapshot.nlink,
            marker_mode=snapshot.mode,
            marker_owner_matches=snapshot.uid == uid,
            environment_switch_off=True,
            audit_valid=True,
            deployment_provenance_valid=True,
            canonical_recovery_fresh=True,
            root_broker_ready=True,
        )
        receipt = disarm_blockade_marker(
            snapshot.record,
            evidence,
            marker,
            quarantine,
            expected_marker_path=marker,
            expected_quarantine_root=quarantine,
            expected_uid=uid,
            marker_mode=MARKER_MODE,
            require_private_marker_parent=False,
            transaction_id=execution["transaction_id"],
        )
        return {
            "operation": operation,
            "receipt": receipt.to_mapping(),
            "receipt_sha256": receipt.receipt_sha256,
            "recovery_gate": execution["recovery_gate"],
        }

    if operation == "restore-disarm":
        receipt = restore_disarmed_marker(
            execution["transaction_id"],
            marker,
            quarantine,
            expected_marker_path=marker,
            expected_quarantine_root=quarantine,
            expected_record_sha256=execution["expected_record_sha256"],
            expected_marker_file_sha256=execution[
                "expected_marker_file_sha256"
            ],
            expected_disarm_receipt_sha256=execution[
                "expected_disarm_receipt_sha256"
            ],
            expected_uid=uid,
            marker_mode=MARKER_MODE,
            require_private_marker_parent=False,
            require_private_quarantine_root=True,
        )
        mapping = receipt.to_mapping()
        return {
            "operation": operation,
            "receipt": mapping,
            "receipt_sha256": hashlib.sha256(canonical_json(mapping)).hexdigest(),
        }

    if operation == "observe":
        if marker.exists() or marker.is_symlink():
            snapshot = read_authority_marker(marker, authority_uid=uid)
            _validate_snapshot(execution, snapshot)
            return {
                "operation": operation,
                "state": "engaged",
                "record": snapshot.record.to_mapping(),
                "record_sha256": snapshot.record_sha256,
                "marker_file_sha256": snapshot.file_sha256,
            }
        try:
            receipt, receipt_sha256 = read_disarm_receipt(
                execution["transaction_id"],
                quarantine,
                expected_quarantine_root=quarantine,
                expected_marker_path=marker,
                expected_record_sha256=execution["expected_record_sha256"],
                expected_marker_file_sha256=execution[
                    "expected_marker_file_sha256"
                ],
                expected_uid=uid,
            )
        except FileNotFoundError:
            return {
                "operation": operation,
                "state": "absent_unproven",
                "record_sha256": execution["expected_record_sha256"],
                "marker_file_sha256": execution[
                    "expected_marker_file_sha256"
                ],
            }
        return {
            "operation": operation,
            "state": "disarmed",
            "receipt": receipt,
            "receipt_sha256": receipt_sha256,
        }

    if operation == "migrate":
        if marker.exists() or marker.is_symlink():
            raise FileExistsError("canonical marker already exists")
        legacy_snapshot = read_blockade_marker(
            legacy,
            expected_marker_path=legacy,
            expected_uid=execution["legacy_uid"],
        )
        _validate_snapshot(execution, legacy_snapshot)
        canonical_receipt = engage_blockade_marker(
            legacy_snapshot.record,
            marker,
            expected_marker_path=marker,
            expected_uid=uid,
            marker_mode=MARKER_MODE,
            require_private_parent=False,
            transaction_id=execution["transaction_id"],
        )
        # The root broker deliberately does not remove the user-owned legacy
        # marker. The unprivileged operator first verifies this exact canonical
        # publication and then removes the legacy marker through the local,
        # hash-bound store primitive. If that second phase fails, both markers
        # remain visible and therefore fail closed.
        return {
            "operation": operation,
            "canonical_receipt": canonical_receipt.to_mapping(),
            "legacy_preserved": True,
            "legacy_record_sha256": legacy_snapshot.record_sha256,
            "legacy_marker_file_sha256": legacy_snapshot.file_sha256,
        }

    raise ValueError("blockade lifecycle execution operation is invalid")

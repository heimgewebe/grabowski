"""Safe filesystem transactions for typed Grabowski blockade records.

This module is deliberately not an MCP surface.  It provides a narrow storage
primitive for a future typed adapter: create-only engagement, exact readback,
hash-bound quarantine disarm, and reversible restore.  All caller-visible paths
must be supplied separately as trusted runtime configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
from typing import Any, Mapping

from grabowski_blockades import (
    BlockadeRecord,
    DisarmEvidence,
    canonical_json,
    validate_disarm,
)


STORE_SCHEMA_VERSION = 1
MAX_MARKER_BYTES = 16 * 1024
MAX_RECEIPT_BYTES = 32 * 1024
_MARKER_RECEIPT_NAME = "disarm-receipt.json"
_RESTORE_RECEIPT_NAME = "restore-receipt.json"
_PREIMAGE_NAME = "operator-kill-switch.preimage"


class BlockadeStoreError(RuntimeError):
    """Base class for storage contract failures."""


class BlockadeAlreadyEngaged(BlockadeStoreError):
    """Raised when create-only engagement observes an existing target."""


class BlockadeRecoveryDenied(PermissionError):
    """Raised before mutation when evidence-bound recovery is not authorized."""


class BlockadeRollbackError(BlockadeStoreError):
    """Raised when a failed transaction cannot prove rollback completion."""


@dataclass(frozen=True)
class MarkerSnapshot:
    path: str
    file_sha256: str
    record_sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    nlink: int
    device: int
    inode: int
    record: BlockadeRecord

    def to_mapping(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "file_sha256": self.file_sha256,
            "record_sha256": self.record_sha256,
            "size": self.size,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "nlink": self.nlink,
            "device": self.device,
            "inode": self.inode,
            "record": self.record.to_mapping(),
        }


@dataclass(frozen=True)
class EngageReceipt:
    transaction_id: str
    created_at: str
    marker_path: str
    marker_file_sha256: str
    record_sha256: str
    record: BlockadeRecord

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": STORE_SCHEMA_VERSION,
            "operation": "engage",
            "transaction_id": self.transaction_id,
            "created_at": self.created_at,
            "marker_path": self.marker_path,
            "marker_file_sha256": self.marker_file_sha256,
            "record_sha256": self.record_sha256,
            "record": self.record.to_mapping(),
            "create_only": True,
            "readback_valid": True,
            "does_not_establish": [
                "audit_append_complete",
                "runtime_tool_registration",
                "caller_provenance_authenticity",
            ],
        }


@dataclass(frozen=True)
class DisarmReceipt:
    transaction_id: str
    created_at: str
    marker_path: str
    quarantine_directory: str
    quarantine_path: str
    receipt_path: str
    marker_file_sha256: str
    record_sha256: str
    record: BlockadeRecord

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": STORE_SCHEMA_VERSION,
            "operation": "disarm",
            "transaction_id": self.transaction_id,
            "created_at": self.created_at,
            "marker_path": self.marker_path,
            "quarantine_directory": self.quarantine_directory,
            "quarantine_path": self.quarantine_path,
            "receipt_path": self.receipt_path,
            "marker_file_sha256": self.marker_file_sha256,
            "record_sha256": self.record_sha256,
            "record": self.record.to_mapping(),
            "source_absent_readback": True,
            "quarantine_readback_valid": True,
            "rollback": {
                "available": True,
                "operation": "restore",
                "expected_source_absent": True,
                "expected_preimage_sha256": self.marker_file_sha256,
            },
            "does_not_establish": [
                "audit_append_complete",
                "external_environment_stop_clear",
                "future_mutation_authority",
            ],
        }

    @property
    def receipt_sha256(self) -> str:
        return hashlib.sha256(_receipt_bytes(self.to_mapping())).hexdigest()


@dataclass(frozen=True)
class RestoreReceipt:
    transaction_id: str
    restored_at: str
    marker_path: str
    quarantine_path: str
    receipt_path: str
    marker_file_sha256: str
    record_sha256: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": STORE_SCHEMA_VERSION,
            "operation": "restore",
            "transaction_id": self.transaction_id,
            "restored_at": self.restored_at,
            "marker_path": self.marker_path,
            "quarantine_path": self.quarantine_path,
            "receipt_path": self.receipt_path,
            "marker_file_sha256": self.marker_file_sha256,
            "record_sha256": self.record_sha256,
            "source_readback_valid": True,
            "quarantine_preimage_absent": True,
            "does_not_establish": [
                "blockade_resolution",
                "audit_append_complete",
                "ordinary_mutation_authority",
            ],
        }


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _full_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_absolute_path(value: Path | str, *, label: str) -> Path:
    text = str(value)
    if not text or "\x00" in text:
        raise ValueError(f"{label} must be a non-empty path")
    candidate = PurePosixPath(text)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if str(candidate) != text:
        raise ValueError(f"{label} must be canonical")
    if any(part in {".", ".."} for part in text.split("/")):
        raise ValueError(f"{label} contains dot traversal")
    return Path(text)


def _safe_component(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or len(value) > 255
    ):
        raise ValueError(f"{label} is not a safe path component")
    return value


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _positive_max_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("max_bytes must be a positive integer")
    return value


def _expected_uid(value: int | None) -> int:
    if value is None:
        return os.getuid()
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("expected_uid must be a non-negative integer")
    return value


def _sha256_value(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be lowercase SHA-256")
    return value


def _transaction_id(value: str | None, *, now: datetime | None) -> str:
    if value is not None:
        return _safe_component(value, label="transaction_id")
    prefix = _timestamp(now).replace(":", "").replace("-", "")
    return f"{prefix}-{secrets.token_hex(8)}"


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _create_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_directory_chain(
    path: Path,
    *,
    expected_uid: int,
    require_private: bool,
    label: str,
) -> int:
    path = _canonical_absolute_path(path, label=label)
    descriptor = os.open("/", _directory_flags())
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        _assert_directory_binding(
            descriptor,
            path,
            expected_uid=expected_uid,
            require_private=require_private,
            label=label,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _assert_directory_binding(
    directory_fd: int,
    path: Path,
    *,
    expected_uid: int,
    require_private: bool,
    label: str,
) -> None:
    opened = os.fstat(directory_fd)
    linked = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(opened.st_mode) or _full_identity(opened) != _full_identity(
        linked
    ):
        raise BlockadeStoreError(f"{label} directory identity changed")
    if opened.st_uid != expected_uid:
        raise PermissionError(f"{label} directory owner is unexpected")
    if require_private and stat.S_IMODE(opened.st_mode) & 0o077:
        raise PermissionError(f"{label} directory is not private")


def _stat_at(directory_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)


def _path_absent_at(directory_fd: int, name: str) -> bool:
    try:
        _stat_at(directory_fd, name)
    except FileNotFoundError:
        return True
    return False


def _unlink_same_inode(
    directory_fd: int,
    name: str,
    expected_inode: tuple[int, int],
) -> bool:
    try:
        current = _stat_at(directory_fd, name)
    except FileNotFoundError:
        return False
    if _identity(current) != expected_inode:
        return False
    os.unlink(name, dir_fd=directory_fd)
    return True


def _read_all(descriptor: int, *, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("blockade marker exceeds byte limit")
    return b"".join(chunks)


def _strict_json(data: bytes) -> Mapping[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("blockade marker is not UTF-8") from exc

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError("blockade marker is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("blockade marker must contain one JSON object")
    return value


def _snapshot_from_open_file(
    directory_fd: int,
    name: str,
    *,
    path: Path,
    expected_uid: int,
    max_bytes: int,
) -> MarkerSnapshot:
    descriptor = os.open(name, _file_flags(), dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PermissionError("blockade marker is not a regular file")
        if before.st_uid != expected_uid:
            raise PermissionError("blockade marker owner is unexpected")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise PermissionError("blockade marker mode must be 0600")
        if before.st_nlink != 1:
            raise PermissionError("blockade marker must be single-link")
        data = _read_all(descriptor, max_bytes=max_bytes)
        after = os.fstat(descriptor)
        linked = _stat_at(directory_fd, name)
        if _full_identity(before) != _full_identity(after) or _identity(
            after
        ) != _identity(linked):
            raise BlockadeStoreError("blockade marker identity changed during read")
    finally:
        os.close(descriptor)

    record = BlockadeRecord.from_mapping(_strict_json(data))
    expected = canonical_json(record.to_mapping())
    if data != expected:
        raise ValueError("blockade marker is not canonical JSON")
    return MarkerSnapshot(
        path=str(path),
        file_sha256=hashlib.sha256(data).hexdigest(),
        record_sha256=record.sha256,
        size=len(data),
        mode=stat.S_IMODE(after.st_mode),
        uid=after.st_uid,
        gid=after.st_gid,
        nlink=after.st_nlink,
        device=after.st_dev,
        inode=after.st_ino,
        record=record,
    )


def _publish_create_only_bytes_at(
    directory_fd: int,
    target_name: str,
    data: bytes,
    *,
    label: str,
) -> tuple[int, int]:
    target_name = _safe_component(target_name, label=f"{label} target")
    temporary_name = _safe_component(
        f".{target_name}.{os.getpid()}.{secrets.token_hex(16)}.tmp",
        label=f"{label} temporary target",
    )
    descriptor = -1
    temporary_present = False
    target_linked = False
    temporary_inode: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            temporary_name, _create_flags(), 0o600, dir_fd=directory_fd
        )
        temporary_present = True
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise BlockadeStoreError(f"temporary {label} is unsafe")
        temporary_inode = _identity(opened)
        owned_descriptor = descriptor
        descriptor = -1
        with os.fdopen(owned_descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary = _stat_at(directory_fd, temporary_name)
        if (
            not stat.S_ISREG(temporary.st_mode)
            or stat.S_IMODE(temporary.st_mode) != 0o600
            or temporary.st_nlink != 1
            or _identity(temporary) != temporary_inode
        ):
            raise BlockadeStoreError(f"temporary {label} changed before publication")
        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise BlockadeAlreadyEngaged(f"{label} already exists") from exc
        target_linked = True
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_present = False
        published = _stat_at(directory_fd, target_name)
        if (
            not stat.S_ISREG(published.st_mode)
            or stat.S_IMODE(published.st_mode) != 0o600
            or published.st_nlink != 1
            or _identity(published) != temporary_inode
        ):
            raise BlockadeStoreError(f"published {label} failed readback")
        os.fsync(directory_fd)
        return temporary_inode
    except BaseException as failure:
        rollback_errors: list[str] = []
        if temporary_inode is not None:
            try:
                try:
                    target_metadata = _stat_at(directory_fd, target_name)
                except FileNotFoundError:
                    target_metadata = None
                if (
                    target_metadata is not None
                    and _identity(target_metadata) == temporary_inode
                ):
                    if not _unlink_same_inode(
                        directory_fd, target_name, temporary_inode
                    ):
                        raise BlockadeStoreError(
                            f"could not remove published {label} target"
                        )
                    os.fsync(directory_fd)
                elif target_linked and target_metadata is not None:
                    raise BlockadeStoreError(
                        f"published {label} target changed before rollback"
                    )
                if target_linked and not _path_absent_at(directory_fd, target_name):
                    raise BlockadeStoreError(
                        f"published {label} target remains after rollback"
                    )
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"target cleanup failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
            if temporary_present:
                try:
                    if not _unlink_same_inode(
                        directory_fd, temporary_name, temporary_inode
                    ) and not _path_absent_at(directory_fd, temporary_name):
                        raise BlockadeStoreError(
                            f"temporary {label} changed before rollback"
                        )
                    os.fsync(directory_fd)
                    if not _path_absent_at(directory_fd, temporary_name):
                        raise BlockadeStoreError(
                            f"temporary {label} remains after rollback"
                        )
                except BaseException as rollback_failure:
                    rollback_errors.append(
                        f"temporary cleanup failed: "
                        f"{type(rollback_failure).__name__}: {rollback_failure}"
                    )
        if rollback_errors:
            raise BlockadeRollbackError(
                f"{label} publication failed and rollback could not be verified: "
                + "; ".join(rollback_errors)
            ) from failure
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _receipt_bytes(payload: Mapping[str, Any]) -> bytes:
    data = canonical_json(dict(payload))
    if len(data) > MAX_RECEIPT_BYTES:
        raise ValueError("blockade receipt exceeds byte limit")
    return data


def _require_exact_runtime_path(
    path: Path | str,
    *,
    expected_path: Path | str,
    label: str,
) -> Path:
    actual = _canonical_absolute_path(path, label=label)
    expected = _canonical_absolute_path(expected_path, label=f"expected {label}")
    if actual != expected:
        raise PermissionError(f"{label} does not match trusted runtime path")
    return actual


def read_blockade_marker(
    marker_path: Path | str,
    *,
    expected_marker_path: Path | str,
    expected_uid: int | None = None,
    max_bytes: int = MAX_MARKER_BYTES,
) -> MarkerSnapshot:
    """Read and strictly validate one canonical blockade marker."""

    path = _require_exact_runtime_path(
        marker_path,
        expected_path=expected_marker_path,
        label="marker_path",
    )
    uid = _expected_uid(expected_uid)
    max_bytes = _positive_max_bytes(max_bytes)
    parent_fd = _open_directory_chain(
        path.parent,
        expected_uid=uid,
        require_private=True,
        label="marker parent",
    )
    try:
        snapshot = _snapshot_from_open_file(
            parent_fd,
            _safe_component(path.name, label="marker name"),
            path=path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        _assert_directory_binding(
            parent_fd,
            path.parent,
            expected_uid=uid,
            require_private=True,
            label="marker parent",
        )
        return snapshot
    finally:
        os.close(parent_fd)


def engage_blockade_marker(
    record: BlockadeRecord,
    marker_path: Path | str,
    *,
    expected_marker_path: Path | str,
    expected_uid: int | None = None,
    transaction_id: str | None = None,
    now: datetime | None = None,
    max_bytes: int = MAX_MARKER_BYTES,
) -> EngageReceipt:
    """Create a canonical marker without replacing any existing path."""

    if not isinstance(record, BlockadeRecord):
        raise TypeError("record must be BlockadeRecord")
    path = _require_exact_runtime_path(
        marker_path,
        expected_path=expected_marker_path,
        label="marker_path",
    )
    uid = _expected_uid(expected_uid)
    max_bytes = _positive_max_bytes(max_bytes)
    payload = canonical_json(record.to_mapping())
    if len(payload) > max_bytes:
        raise ValueError("blockade marker exceeds byte limit")
    txid = _transaction_id(transaction_id, now=now)
    created_at = _timestamp(now)
    parent_fd = _open_directory_chain(
        path.parent,
        expected_uid=uid,
        require_private=True,
        label="marker parent",
    )
    published_inode: tuple[int, int] | None = None
    marker_name = _safe_component(path.name, label="marker name")
    try:
        published_inode = _publish_create_only_bytes_at(
            parent_fd,
            marker_name,
            payload,
            label="blockade marker",
        )
        snapshot = _snapshot_from_open_file(
            parent_fd,
            marker_name,
            path=path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        if snapshot.record != record or snapshot.record_sha256 != record.sha256:
            raise BlockadeStoreError(
                "engaged blockade record changed during publication"
            )
        _assert_directory_binding(
            parent_fd,
            path.parent,
            expected_uid=uid,
            require_private=True,
            label="marker parent",
        )
        return EngageReceipt(
            transaction_id=txid,
            created_at=created_at,
            marker_path=str(path),
            marker_file_sha256=snapshot.file_sha256,
            record_sha256=snapshot.record_sha256,
            record=snapshot.record,
        )
    except BaseException as failure:
        if published_inode is not None:
            rollback_errors: list[str] = []
            try:
                try:
                    current = _stat_at(parent_fd, marker_name)
                except FileNotFoundError:
                    current = None
                if current is not None and _identity(current) == published_inode:
                    if not _unlink_same_inode(parent_fd, marker_name, published_inode):
                        raise BlockadeStoreError(
                            "engage rollback could not unlink marker"
                        )
                    os.fsync(parent_fd)
                elif current is not None:
                    raise BlockadeStoreError("engage marker changed before rollback")
                if not _path_absent_at(parent_fd, marker_name):
                    raise BlockadeStoreError("engage marker remains after rollback")
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"marker cleanup failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
            if rollback_errors:
                raise BlockadeRollbackError(
                    "engage failed and rollback could not be verified: "
                    + "; ".join(rollback_errors)
                ) from failure
        raise
    finally:
        os.close(parent_fd)


def rollback_engaged_marker(
    receipt: EngageReceipt,
    marker_path: Path | str,
    *,
    expected_marker_path: Path | str,
    expected_uid: int | None = None,
    max_bytes: int = MAX_MARKER_BYTES,
) -> dict[str, Any]:
    """Remove only the exact marker created by one uncommitted engagement."""

    if not isinstance(receipt, EngageReceipt):
        raise TypeError("receipt must be EngageReceipt")
    path = _require_exact_runtime_path(
        marker_path,
        expected_path=expected_marker_path,
        label="marker_path",
    )
    if receipt.marker_path != str(path):
        raise BlockadeRecoveryDenied("engage receipt marker path mismatch")
    uid = _expected_uid(expected_uid)
    max_bytes = _positive_max_bytes(max_bytes)
    parent_fd = _open_directory_chain(
        path.parent,
        expected_uid=uid,
        require_private=True,
        label="marker parent",
    )
    marker_name = _safe_component(path.name, label="marker name")
    unlinked = False
    try:
        snapshot = _snapshot_from_open_file(
            parent_fd,
            marker_name,
            path=path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        if (
            snapshot.file_sha256 != receipt.marker_file_sha256
            or snapshot.record_sha256 != receipt.record_sha256
            or snapshot.record != receipt.record
        ):
            raise BlockadeRecoveryDenied(
                "live marker does not match the uncommitted engage receipt"
            )
        inode = (snapshot.device, snapshot.inode)
        if not _unlink_same_inode(parent_fd, marker_name, inode):
            raise BlockadeRollbackError(
                "engage rollback could not unlink the exact marker inode"
            )
        unlinked = True
        os.fsync(parent_fd)
        if not _path_absent_at(parent_fd, marker_name):
            raise BlockadeRollbackError(
                "engage rollback marker remains after exact unlink"
            )
        _assert_directory_binding(
            parent_fd,
            path.parent,
            expected_uid=uid,
            require_private=True,
            label="marker parent",
        )
        return {
            "schema_version": STORE_SCHEMA_VERSION,
            "operation": "rollback-engage",
            "transaction_id": receipt.transaction_id,
            "marker_path": str(path),
            "removed_marker_file_sha256": receipt.marker_file_sha256,
            "removed_record_sha256": receipt.record_sha256,
            "source_absent_readback": True,
            "does_not_establish": [
                "audit_append_complete",
                "future_mutation_authority",
                "external_environment_stop_clear",
            ],
        }
    except BlockadeRecoveryDenied:
        raise
    except BaseException as failure:
        if unlinked and _path_absent_at(parent_fd, marker_name):
            raise BlockadeRollbackError(
                "engage rollback removed the marker but completion could not be fully verified"
            ) from failure
        raise BlockadeRollbackError(
            "engage rollback failed before exact marker absence was verified"
        ) from failure
    finally:
        os.close(parent_fd)


def _create_private_transaction_directory(
    root_fd: int,
    root_path: Path,
    transaction_id: str,
    *,
    expected_uid: int,
) -> tuple[Path, int]:
    name = _safe_component(transaction_id, label="transaction_id")
    os.mkdir(name, mode=0o700, dir_fd=root_fd)
    try:
        directory_fd = os.open(name, _directory_flags(), dir_fd=root_fd)
    except BaseException:
        os.rmdir(name, dir_fd=root_fd)
        raise
    path = root_path / name
    try:
        _assert_directory_binding(
            directory_fd,
            path,
            expected_uid=expected_uid,
            require_private=True,
            label="transaction",
        )
        os.fsync(root_fd)
        return path, directory_fd
    except BaseException:
        os.close(directory_fd)
        os.rmdir(name, dir_fd=root_fd)
        raise


def _remove_empty_transaction_directory(
    root_fd: int,
    transaction_id: str,
) -> None:
    try:
        os.rmdir(transaction_id, dir_fd=root_fd)
        os.fsync(root_fd)
    except FileNotFoundError:
        pass


def disarm_blockade_marker(
    record: BlockadeRecord,
    evidence: DisarmEvidence,
    marker_path: Path | str,
    quarantine_root: Path | str,
    *,
    expected_marker_path: Path | str,
    expected_quarantine_root: Path | str,
    expected_uid: int | None = None,
    transaction_id: str | None = None,
    now: datetime | None = None,
    max_bytes: int = MAX_MARKER_BYTES,
) -> DisarmReceipt:
    """Move one exact marker into private quarantine and write a durable receipt.

    Any failure after the source unlink attempts an inode-bound rollback before
    returning.  The caller still owns audit append and runtime authorization.
    """

    if not isinstance(record, BlockadeRecord):
        raise TypeError("record must be BlockadeRecord")
    if not isinstance(evidence, DisarmEvidence):
        raise TypeError("evidence must be DisarmEvidence")
    path = _require_exact_runtime_path(
        marker_path,
        expected_path=expected_marker_path,
        label="marker_path",
    )
    quarantine = _require_exact_runtime_path(
        quarantine_root,
        expected_path=expected_quarantine_root,
        label="quarantine_root",
    )
    validation = validate_disarm(
        record,
        evidence,
        expected_marker_path=str(path),
    )
    if not validation.allowed:
        raise BlockadeRecoveryDenied(
            "blockade disarm denied: " + ",".join(validation.reasons)
        )
    uid = _expected_uid(expected_uid)
    max_bytes = _positive_max_bytes(max_bytes)
    txid = _transaction_id(transaction_id, now=now)
    created_at = _timestamp(now)
    marker_parent_fd = _open_directory_chain(
        path.parent,
        expected_uid=uid,
        require_private=True,
        label="marker parent",
    )
    quarantine_root_fd = -1
    transaction_fd = -1
    transaction_path: Path | None = None
    linked_preimage = False
    source_unlinked = False
    preimage_inode: tuple[int, int] | None = None
    source_snapshot: MarkerSnapshot | None = None
    try:
        quarantine_root_fd = _open_directory_chain(
            quarantine,
            expected_uid=uid,
            require_private=True,
            label="quarantine root",
        )
        if os.fstat(marker_parent_fd).st_dev != os.fstat(quarantine_root_fd).st_dev:
            raise BlockadeStoreError("marker and quarantine must share a filesystem")
        marker_name = _safe_component(path.name, label="marker name")
        snapshot = _snapshot_from_open_file(
            marker_parent_fd,
            marker_name,
            path=path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        source_snapshot = snapshot
        if snapshot.record != record:
            raise BlockadeRecoveryDenied("marker record does not match disarm target")
        if snapshot.record_sha256 != evidence.record_sha256:
            raise BlockadeRecoveryDenied("marker record hash changed before disarm")
        transaction_path, transaction_fd = _create_private_transaction_directory(
            quarantine_root_fd,
            quarantine,
            txid,
            expected_uid=uid,
        )
        preimage_name = _safe_component(_PREIMAGE_NAME, label="preimage name")
        preimage_path = transaction_path / preimage_name
        source_inode = (snapshot.device, snapshot.inode)
        os.link(
            marker_name,
            preimage_name,
            src_dir_fd=marker_parent_fd,
            dst_dir_fd=transaction_fd,
            follow_symlinks=False,
        )
        linked_preimage = True
        linked = _stat_at(transaction_fd, preimage_name)
        preimage_inode = _identity(linked)
        source_after_link = _stat_at(marker_parent_fd, marker_name)
        if (
            preimage_inode != source_inode
            or _identity(source_after_link) != source_inode
            or linked.st_nlink != 2
            or source_after_link.st_nlink != 2
        ):
            raise BlockadeStoreError("quarantine link identity validation failed")
        if not _unlink_same_inode(marker_parent_fd, marker_name, source_inode):
            raise BlockadeStoreError("source marker changed before unlink")
        source_unlinked = True
        os.fsync(marker_parent_fd)
        os.fsync(transaction_fd)
        if not _path_absent_at(marker_parent_fd, marker_name):
            raise BlockadeStoreError("source marker remains after quarantine")
        moved = _snapshot_from_open_file(
            transaction_fd,
            preimage_name,
            path=preimage_path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        if moved.file_sha256 != snapshot.file_sha256 or moved.record != record:
            raise BlockadeStoreError("quarantine preimage changed during move")
        receipt_path = transaction_path / _MARKER_RECEIPT_NAME
        receipt = DisarmReceipt(
            transaction_id=txid,
            created_at=created_at,
            marker_path=str(path),
            quarantine_directory=str(transaction_path),
            quarantine_path=str(preimage_path),
            receipt_path=str(receipt_path),
            marker_file_sha256=snapshot.file_sha256,
            record_sha256=snapshot.record_sha256,
            record=snapshot.record,
        )
        receipt_mapping = receipt.to_mapping()
        receipt_bytes = _receipt_bytes(receipt_mapping)
        _publish_create_only_bytes_at(
            transaction_fd,
            _MARKER_RECEIPT_NAME,
            receipt_bytes,
            label="disarm receipt",
        )
        receipt_readback, receipt_readback_sha256 = _read_receipt_at(
            transaction_fd, _MARKER_RECEIPT_NAME
        )
        if dict(receipt_readback) != receipt_mapping:
            raise BlockadeStoreError("disarm receipt failed exact readback")
        if receipt_readback_sha256 != receipt.receipt_sha256:
            raise BlockadeStoreError("disarm receipt hash readback failed")
        os.fsync(transaction_fd)
        os.fsync(quarantine_root_fd)
        _assert_directory_binding(
            marker_parent_fd,
            path.parent,
            expected_uid=uid,
            require_private=True,
            label="marker parent",
        )
        _assert_directory_binding(
            quarantine_root_fd,
            quarantine,
            expected_uid=uid,
            require_private=True,
            label="quarantine root",
        )
        if not _path_absent_at(marker_parent_fd, marker_name):
            raise BlockadeStoreError("source marker reappeared after disarm")
        final_preimage = _snapshot_from_open_file(
            transaction_fd,
            preimage_name,
            path=preimage_path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        if final_preimage.file_sha256 != snapshot.file_sha256:
            raise BlockadeStoreError("final quarantine readback failed")
        return receipt
    except BaseException as failure:
        rollback_errors: list[str] = []
        marker_name = _safe_component(path.name, label="marker name")
        if source_unlinked and transaction_fd >= 0 and preimage_inode is not None:
            try:
                if _path_absent_at(marker_parent_fd, marker_name):
                    os.link(
                        _PREIMAGE_NAME,
                        marker_name,
                        src_dir_fd=transaction_fd,
                        dst_dir_fd=marker_parent_fd,
                        follow_symlinks=False,
                    )
                restored_metadata = _stat_at(marker_parent_fd, marker_name)
                if _identity(restored_metadata) != preimage_inode:
                    raise BlockadeStoreError(
                        "rollback marker inode does not match quarantine preimage"
                    )
                if not _unlink_same_inode(
                    transaction_fd, _PREIMAGE_NAME, preimage_inode
                ):
                    raise BlockadeStoreError(
                        "rollback could not remove quarantine preimage"
                    )
                linked_preimage = False
                os.fsync(marker_parent_fd)
                os.fsync(transaction_fd)
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"marker restore failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
        elif linked_preimage and transaction_fd >= 0 and preimage_inode is not None:
            try:
                if not _unlink_same_inode(
                    transaction_fd, _PREIMAGE_NAME, preimage_inode
                ):
                    raise BlockadeStoreError(
                        "rollback could not remove linked quarantine preimage"
                    )
                linked_preimage = False
                os.fsync(transaction_fd)
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"preimage cleanup failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
        if transaction_fd >= 0:
            try:
                if not _path_absent_at(transaction_fd, _MARKER_RECEIPT_NAME):
                    os.unlink(_MARKER_RECEIPT_NAME, dir_fd=transaction_fd)
                    os.fsync(transaction_fd)
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"receipt cleanup failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
        if source_snapshot is not None:
            try:
                restored_snapshot = _snapshot_from_open_file(
                    marker_parent_fd,
                    marker_name,
                    path=path,
                    expected_uid=uid,
                    max_bytes=max_bytes,
                )
                if (
                    restored_snapshot.file_sha256 != source_snapshot.file_sha256
                    or restored_snapshot.record_sha256 != source_snapshot.record_sha256
                    or restored_snapshot.record != source_snapshot.record
                ):
                    raise BlockadeStoreError(
                        "rollback marker readback differs from source snapshot"
                    )
                if transaction_fd >= 0 and not _path_absent_at(
                    transaction_fd, _PREIMAGE_NAME
                ):
                    raise BlockadeStoreError(
                        "rollback quarantine preimage remains present"
                    )
                if transaction_fd >= 0 and not _path_absent_at(
                    transaction_fd, _MARKER_RECEIPT_NAME
                ):
                    raise BlockadeStoreError("rollback disarm receipt remains present")
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"rollback readback failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
        if rollback_errors:
            raise BlockadeRollbackError(
                "disarm failed and rollback could not be verified: "
                + "; ".join(rollback_errors)
            ) from failure
        raise
    finally:
        if transaction_fd >= 0:
            os.close(transaction_fd)
        if transaction_path is not None and quarantine_root_fd >= 0:
            try:
                _remove_empty_transaction_directory(quarantine_root_fd, txid)
            except OSError:
                pass
        if quarantine_root_fd >= 0:
            os.close(quarantine_root_fd)
        os.close(marker_parent_fd)


def _read_receipt_at(directory_fd: int, name: str) -> tuple[Mapping[str, Any], str]:
    descriptor = os.open(name, _file_flags(), dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PermissionError("blockade receipt is unsafe")
        data = _read_all(descriptor, max_bytes=MAX_RECEIPT_BYTES)
        if _full_identity(os.fstat(descriptor)) != _full_identity(metadata):
            raise BlockadeStoreError("blockade receipt changed during read")
    finally:
        os.close(descriptor)
    payload = _strict_json(data)
    if data != canonical_json(dict(payload)):
        raise ValueError("blockade receipt is not canonical JSON")
    return payload, hashlib.sha256(data).hexdigest()


def restore_disarmed_marker(
    transaction_id: str,
    marker_path: Path | str,
    quarantine_root: Path | str,
    *,
    expected_marker_path: Path | str,
    expected_quarantine_root: Path | str,
    expected_record_sha256: str,
    expected_marker_file_sha256: str,
    expected_disarm_receipt_sha256: str,
    expected_uid: int | None = None,
    now: datetime | None = None,
    max_bytes: int = MAX_MARKER_BYTES,
) -> RestoreReceipt:
    """Restore one exact quarantined preimage when the source remains absent."""

    path = _require_exact_runtime_path(
        marker_path,
        expected_path=expected_marker_path,
        label="marker_path",
    )
    quarantine = _require_exact_runtime_path(
        quarantine_root,
        expected_path=expected_quarantine_root,
        label="quarantine_root",
    )
    txid = _safe_component(transaction_id, label="transaction_id")
    expected_record_sha256 = _sha256_value(
        expected_record_sha256, label="expected_record_sha256"
    )
    expected_marker_file_sha256 = _sha256_value(
        expected_marker_file_sha256, label="expected_marker_file_sha256"
    )
    expected_disarm_receipt_sha256 = _sha256_value(
        expected_disarm_receipt_sha256, label="expected_disarm_receipt_sha256"
    )
    uid = _expected_uid(expected_uid)
    max_bytes = _positive_max_bytes(max_bytes)
    marker_parent_fd = _open_directory_chain(
        path.parent,
        expected_uid=uid,
        require_private=True,
        label="marker parent",
    )
    quarantine_root_fd = -1
    transaction_fd = -1
    source_linked = False
    preimage_unlinked = False
    preimage_inode: tuple[int, int] | None = None
    preimage_snapshot: MarkerSnapshot | None = None
    try:
        quarantine_root_fd = _open_directory_chain(
            quarantine,
            expected_uid=uid,
            require_private=True,
            label="quarantine root",
        )
        if os.fstat(marker_parent_fd).st_dev != os.fstat(quarantine_root_fd).st_dev:
            raise BlockadeStoreError("marker and quarantine must share a filesystem")
        transaction_path = quarantine / txid
        transaction_fd = os.open(txid, _directory_flags(), dir_fd=quarantine_root_fd)
        _assert_directory_binding(
            transaction_fd,
            transaction_path,
            expected_uid=uid,
            require_private=True,
            label="transaction",
        )
        receipt, receipt_sha256 = _read_receipt_at(transaction_fd, _MARKER_RECEIPT_NAME)
        if receipt_sha256 != expected_disarm_receipt_sha256:
            raise BlockadeRecoveryDenied("disarm receipt SHA-256 mismatch")
        expected_receipt_keys = {
            "schema_version",
            "operation",
            "transaction_id",
            "created_at",
            "marker_path",
            "quarantine_directory",
            "quarantine_path",
            "receipt_path",
            "marker_file_sha256",
            "record_sha256",
            "record",
            "source_absent_readback",
            "quarantine_readback_valid",
            "rollback",
            "does_not_establish",
        }
        if set(receipt) != expected_receipt_keys:
            raise BlockadeRecoveryDenied("disarm receipt key set is invalid")
        required_receipt = {
            "schema_version": STORE_SCHEMA_VERSION,
            "operation": "disarm",
            "transaction_id": txid,
            "marker_path": str(path),
            "quarantine_directory": str(transaction_path),
            "quarantine_path": str(transaction_path / _PREIMAGE_NAME),
            "receipt_path": str(transaction_path / _MARKER_RECEIPT_NAME),
            "marker_file_sha256": expected_marker_file_sha256,
            "record_sha256": expected_record_sha256,
        }
        for key, expected in required_receipt.items():
            if receipt.get(key) != expected:
                raise BlockadeRecoveryDenied(f"disarm receipt mismatch: {key}")
        if receipt.get("source_absent_readback") is not True:
            raise BlockadeRecoveryDenied("disarm receipt source readback is invalid")
        if receipt.get("quarantine_readback_valid") is not True:
            raise BlockadeRecoveryDenied(
                "disarm receipt quarantine readback is invalid"
            )
        expected_rollback = {
            "available": True,
            "operation": "restore",
            "expected_source_absent": True,
            "expected_preimage_sha256": expected_marker_file_sha256,
        }
        if receipt.get("rollback") != expected_rollback:
            raise BlockadeRecoveryDenied("disarm receipt rollback contract is invalid")
        try:
            receipt_record = BlockadeRecord.from_mapping(receipt.get("record"))
        except (TypeError, ValueError) as exc:
            raise BlockadeRecoveryDenied("disarm receipt record is invalid") from exc
        if receipt_record.sha256 != expected_record_sha256:
            raise BlockadeRecoveryDenied("disarm receipt record hash mismatch")
        marker_name = _safe_component(path.name, label="marker name")
        if not _path_absent_at(marker_parent_fd, marker_name):
            raise BlockadeRecoveryDenied("marker path is not absent")
        preimage_path = transaction_path / _PREIMAGE_NAME
        preimage = _snapshot_from_open_file(
            transaction_fd,
            _PREIMAGE_NAME,
            path=preimage_path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        preimage_snapshot = preimage
        if preimage.file_sha256 != expected_marker_file_sha256:
            raise BlockadeRecoveryDenied("quarantine file hash mismatch")
        if preimage.record_sha256 != expected_record_sha256:
            raise BlockadeRecoveryDenied("quarantine record hash mismatch")
        if preimage.record != receipt_record:
            raise BlockadeRecoveryDenied("receipt and quarantine records differ")
        preimage_inode = (preimage.device, preimage.inode)
        os.link(
            _PREIMAGE_NAME,
            marker_name,
            src_dir_fd=transaction_fd,
            dst_dir_fd=marker_parent_fd,
            follow_symlinks=False,
        )
        source_linked = True
        linked = _stat_at(marker_parent_fd, marker_name)
        if _identity(linked) != preimage_inode or linked.st_nlink != 2:
            raise BlockadeStoreError("restore link identity validation failed")
        if not _unlink_same_inode(transaction_fd, _PREIMAGE_NAME, preimage_inode):
            raise BlockadeStoreError("quarantine preimage changed before restore")
        preimage_unlinked = True
        os.fsync(transaction_fd)
        os.fsync(marker_parent_fd)
        restored = _snapshot_from_open_file(
            marker_parent_fd,
            marker_name,
            path=path,
            expected_uid=uid,
            max_bytes=max_bytes,
        )
        if (
            restored.file_sha256 != expected_marker_file_sha256
            or restored.record_sha256 != expected_record_sha256
        ):
            raise BlockadeStoreError("restored marker failed readback")
        if not _path_absent_at(transaction_fd, _PREIMAGE_NAME):
            raise BlockadeStoreError("quarantine preimage remains after restore")
        restore_receipt_path = transaction_path / _RESTORE_RECEIPT_NAME
        restore_receipt = RestoreReceipt(
            transaction_id=txid,
            restored_at=_timestamp(now),
            marker_path=str(path),
            quarantine_path=str(preimage_path),
            receipt_path=str(restore_receipt_path),
            marker_file_sha256=expected_marker_file_sha256,
            record_sha256=expected_record_sha256,
        )
        restore_mapping = restore_receipt.to_mapping()
        _publish_create_only_bytes_at(
            transaction_fd,
            _RESTORE_RECEIPT_NAME,
            _receipt_bytes(restore_mapping),
            label="restore receipt",
        )
        restore_readback, restore_readback_sha256 = _read_receipt_at(
            transaction_fd, _RESTORE_RECEIPT_NAME
        )
        if dict(restore_readback) != restore_mapping:
            raise BlockadeStoreError("restore receipt failed exact readback")
        if (
            restore_readback_sha256
            != hashlib.sha256(_receipt_bytes(restore_mapping)).hexdigest()
        ):
            raise BlockadeStoreError("restore receipt hash readback failed")
        os.fsync(transaction_fd)
        os.fsync(quarantine_root_fd)
        return restore_receipt
    except BaseException as failure:
        rollback_errors: list[str] = []
        marker_name = _safe_component(path.name, label="marker name")
        if transaction_fd >= 0:
            try:
                if not _path_absent_at(transaction_fd, _RESTORE_RECEIPT_NAME):
                    os.unlink(_RESTORE_RECEIPT_NAME, dir_fd=transaction_fd)
                    os.fsync(transaction_fd)
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"restore receipt cleanup failed: "
                    f"{type(rollback_failure).__name__}: {rollback_failure}"
                )
        if preimage_inode is not None:
            if preimage_unlinked and transaction_fd >= 0:
                try:
                    if _path_absent_at(transaction_fd, _PREIMAGE_NAME):
                        source_metadata = _stat_at(marker_parent_fd, marker_name)
                        if _identity(source_metadata) != preimage_inode:
                            raise BlockadeStoreError(
                                "rollback source inode does not match preimage"
                            )
                        os.link(
                            marker_name,
                            _PREIMAGE_NAME,
                            src_dir_fd=marker_parent_fd,
                            dst_dir_fd=transaction_fd,
                            follow_symlinks=False,
                        )
                    preimage_metadata = _stat_at(transaction_fd, _PREIMAGE_NAME)
                    if _identity(preimage_metadata) != preimage_inode:
                        raise BlockadeStoreError(
                            "rollback quarantine inode does not match preimage"
                        )
                    if not _unlink_same_inode(
                        marker_parent_fd, marker_name, preimage_inode
                    ):
                        raise BlockadeStoreError(
                            "rollback could not remove restored marker"
                        )
                    os.fsync(marker_parent_fd)
                    os.fsync(transaction_fd)
                except BaseException as rollback_failure:
                    rollback_errors.append(
                        f"quarantine restore failed: "
                        f"{type(rollback_failure).__name__}: {rollback_failure}"
                    )
            elif source_linked:
                try:
                    if not _unlink_same_inode(
                        marker_parent_fd, marker_name, preimage_inode
                    ):
                        raise BlockadeStoreError(
                            "rollback could not remove temporary source link"
                        )
                    os.fsync(marker_parent_fd)
                except BaseException as rollback_failure:
                    rollback_errors.append(
                        f"source link cleanup failed: "
                        f"{type(rollback_failure).__name__}: {rollback_failure}"
                    )
        if preimage_snapshot is not None and transaction_fd >= 0:
            try:
                if not _path_absent_at(marker_parent_fd, marker_name):
                    raise BlockadeStoreError("rollback source marker remains present")
                restored_preimage = _snapshot_from_open_file(
                    transaction_fd,
                    _PREIMAGE_NAME,
                    path=quarantine / txid / _PREIMAGE_NAME,
                    expected_uid=uid,
                    max_bytes=max_bytes,
                )
                if (
                    restored_preimage.file_sha256 != preimage_snapshot.file_sha256
                    or restored_preimage.record_sha256
                    != preimage_snapshot.record_sha256
                    or restored_preimage.record != preimage_snapshot.record
                ):
                    raise BlockadeStoreError(
                        "rollback quarantine readback differs from preimage snapshot"
                    )
                if not _path_absent_at(transaction_fd, _RESTORE_RECEIPT_NAME):
                    raise BlockadeStoreError("rollback restore receipt remains present")
            except BaseException as rollback_failure:
                rollback_errors.append(
                    f"rollback readback failed: {type(rollback_failure).__name__}: "
                    f"{rollback_failure}"
                )
        if rollback_errors:
            raise BlockadeRollbackError(
                "restore failed and rollback could not be verified: "
                + "; ".join(rollback_errors)
            ) from failure
        raise
    finally:
        if transaction_fd >= 0:
            os.close(transaction_fd)
        if quarantine_root_fd >= 0:
            os.close(quarantine_root_fd)
        os.close(marker_parent_fd)

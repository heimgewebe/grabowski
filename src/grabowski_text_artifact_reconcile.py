from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import uuid
from typing import Any

import grabowski_artifacts as artifacts


SCHEMA_VERSION = 1
INVENTORY_KIND = "grabowski_text_artifact_reconciliation_inventory"
STORE_INVENTORY_KIND = "grabowski_text_artifact_store_inventory"
RECEIPT_KIND = "grabowski_text_artifact_quarantine_receipt"
TEXT_ARTIFACT_QUARANTINE_ROOT = (
    Path.home() / ".local/state/grabowski/text-artifact-quarantine"
)
_ALLOWED_LEGACY_MODES = {0o600, 0o640, 0o644}
_MAX_UNMANAGED_ENTRIES = 256
_MAX_UNMANAGED_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_QUARANTINE_DIRECTORIES = 4096
_MAX_QUARANTINE_TOTAL_BYTES = 512 * 1024 * 1024
_COPY_CHUNK_BYTES = 1024 * 1024
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_INVENTORY_NONCLAIMS = [
    "safe deletion authority",
    "transport-file authorship",
    "review correctness",
    "merge authority",
]


class TextArtifactReconciliationError(RuntimeError):
    """Fail-closed text-artifact reconciliation failure."""


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _safe_entry_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or len(name.encode("utf-8")) > 255
    ):
        raise TextArtifactReconciliationError(
            "Text artifact unmanaged entry name is invalid"
        )
    return name


def _entry_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "link_count": metadata.st_nlink,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "byte_size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _open_legacy_regular_file_at(
    directory_descriptor: int,
    name: str,
) -> tuple[int, os.stat_result]:
    checked_name = _safe_entry_name(name)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(checked_name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        raise TextArtifactReconciliationError(
            "Text artifact unmanaged entry open failed"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(
            checked_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or _entry_identity(opened) != _entry_identity(linked)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or mode not in _ALLOWED_LEGACY_MODES
            or opened.st_size > artifacts.MAX_TEXT_ARTIFACT_BYTES
        ):
            raise TextArtifactReconciliationError(
                "Text artifact unmanaged entry is not one bounded owner-controlled regular file"
            )
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _hash_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def _inspect_entry(
    directory_descriptor: int,
    name: str,
) -> dict[str, Any]:
    descriptor, before = _open_legacy_regular_file_at(directory_descriptor, name)
    try:
        sha256 = _hash_descriptor(descriptor)
        after = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if (
            _entry_identity(before) != _entry_identity(after)
            or _entry_identity(before) != _entry_identity(linked)
        ):
            raise TextArtifactReconciliationError(
                "Text artifact unmanaged entry changed while hashing"
            )
        return {
            "name": name,
            **_entry_identity(before),
            "sha256": sha256,
        }
    finally:
        os.close(descriptor)


def _inventory_entry(artifact_id: str, entry: dict[str, Any]) -> dict[str, Any]:
    name = _safe_entry_name(str(entry["name"]))
    return {
        "path": f"{artifact_id}/{name}",
        "file_type": "regular",
        **entry,
    }


def _validate_managed_artifact(
    artifact_descriptor: int,
    *,
    artifact_id: str,
) -> tuple[dict[str, Any], str, str, int]:
    receipt_bytes, receipt_sha256, _ = artifacts._read_private_regular_file_at(
        artifact_descriptor,
        "receipt.json",
        max_bytes=artifacts.MAX_TEXT_ARTIFACT_RECEIPT_BYTES,
    )
    receipt = artifacts._validated_text_artifact_receipt(
        receipt_bytes,
        artifact_id=artifact_id,
    )
    artifact_sha256, artifact_size, _ = (
        artifacts._hash_and_read_private_regular_file_at(
            artifact_descriptor,
            receipt["filename"],
            max_bytes=artifacts.MAX_TEXT_ARTIFACT_BYTES,
            offset=0,
            chunk_size=0,
        )
    )
    if (
        artifact_sha256 != receipt["diff_sha256"]
        or artifact_size != receipt["byte_size"]
    ):
        raise TextArtifactReconciliationError(
            "Text artifact managed payload failed integrity verification"
        )
    return receipt, receipt_sha256, artifact_sha256, artifact_size


def _inspect_locked(
    root_descriptor: int,
    root_identity: tuple[int, ...],
    artifact_id: str,
) -> dict[str, Any]:
    identity = artifacts._validate_artifact_id(artifact_id)
    artifact_descriptor, artifact_identity = artifacts._open_private_directory_at(
        root_descriptor,
        identity,
    )
    try:
        receipt, receipt_sha256, artifact_sha256, artifact_size = (
            _validate_managed_artifact(
                artifact_descriptor,
                artifact_id=identity,
            )
        )
        expected_entries = {"receipt.json", receipt["filename"]}
        names = sorted(set(os.listdir(artifact_descriptor)) - expected_entries)
        if len(names) > _MAX_UNMANAGED_ENTRIES:
            raise TextArtifactReconciliationError(
                "Text artifact unmanaged entry count exceeds the reconciliation limit"
            )
        entries = [
            _inventory_entry(identity, _inspect_entry(artifact_descriptor, name))
            for name in names
        ]
        if sum(item["byte_size"] for item in entries) > _MAX_UNMANAGED_TOTAL_BYTES:
            raise TextArtifactReconciliationError(
                "Text artifact unmanaged bytes exceed the reconciliation limit"
            )
        artifacts._verify_private_directory_at(
            root_descriptor,
            identity,
            artifact_descriptor,
            artifact_identity,
        )
    finally:
        os.close(artifact_descriptor)
    artifacts._verify_private_directory_path(
        root_descriptor,
        artifacts.TEXT_ARTIFACT_ROOT,
        root_identity,
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": INVENTORY_KIND,
        "artifact_id": identity,
        "managed": {
            "filename": receipt["filename"],
            "artifact_sha256": artifact_sha256,
            "artifact_size": artifact_size,
            "receipt_sha256": receipt_sha256,
        },
        "unmanaged_entries": entries,
        "does_not_establish": list(_INVENTORY_NONCLAIMS),
    }
    return {**payload, "inventory_sha256": _digest(payload)}


def inspect_text_artifact_store(artifact_id: str) -> dict[str, Any]:
    root_descriptor, root_identity = artifacts._open_private_directory_path(
        artifacts.TEXT_ARTIFACT_ROOT
    )
    try:
        try:
            fcntl.flock(root_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TextArtifactReconciliationError(
                "Text artifact store is busy"
            ) from exc
        return _inspect_locked(root_descriptor, root_identity, artifact_id)
    finally:
        os.close(root_descriptor)


def inspect_text_artifact_store_root() -> dict[str, Any]:
    root_descriptor, root_identity = artifacts._open_private_directory_path(
        artifacts.TEXT_ARTIFACT_ROOT
    )
    try:
        try:
            fcntl.flock(root_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TextArtifactReconciliationError(
                "Text artifact store is busy"
            ) from exc
        names = sorted(os.listdir(root_descriptor))
        if len(names) > artifacts.MAX_RETAINED_TEXT_ARTIFACTS:
            raise TextArtifactReconciliationError(
                "Text artifact store exceeds the bounded inventory count"
            )
        anomalies: list[dict[str, Any]] = []
        for name in names:
            if artifacts.ARTIFACT_ID_RE.fullmatch(name) is None:
                raise TextArtifactReconciliationError(
                    "Text artifact root contains an unmanaged entry"
                )
            inventory = _inspect_locked(root_descriptor, root_identity, name)
            if inventory["unmanaged_entries"]:
                anomalies.append(inventory)
        artifacts._verify_private_directory_path(
            root_descriptor, artifacts.TEXT_ARTIFACT_ROOT, root_identity
        )
    finally:
        os.close(root_descriptor)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": STORE_INVENTORY_KIND,
        "artifact_count": len(names),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "does_not_establish": list(_INVENTORY_NONCLAIMS)
        + ["future store health"],
    }
    return {**payload, "store_inventory_sha256": _digest(payload)}


def _verify_current_private_directory_at(
    parent_descriptor: int,
    name: str,
    descriptor: int,
) -> None:
    try:
        opened = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise TextArtifactReconciliationError(
            "Text artifact directory changed during reconciliation"
        ) from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(linked.st_mode)
        or artifacts._private_identity(opened) != artifacts._private_identity(linked)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise TextArtifactReconciliationError(
            "Text artifact directory binding changed during reconciliation"
        )


def _verify_current_private_directory_path(
    path: Path,
    descriptor: int,
) -> None:
    try:
        opened = os.fstat(descriptor)
        linked = os.lstat(path)
    except OSError as exc:
        raise TextArtifactReconciliationError(
            "Text artifact directory changed during reconciliation"
        ) from exc
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(linked.st_mode)
        or artifacts._private_identity(opened) != artifacts._private_identity(linked)
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise TextArtifactReconciliationError(
            "Text artifact directory binding changed during reconciliation"
        )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine copy stopped unexpectedly"
            )
        view = view[written:]


def _copy_entry(
    source_descriptor: int,
    destination_descriptor: int,
    expected: dict[str, Any],
    *,
    artifact_id: str,
) -> None:
    name = _safe_entry_name(str(expected["name"]))
    source, before = _open_legacy_regular_file_at(source_descriptor, name)
    destination = -1
    try:
        observed = _inventory_entry(
            artifact_id,
            {
                "name": name,
                **_entry_identity(before),
                "sha256": _hash_descriptor(source),
            },
        )
        if observed != expected:
            raise TextArtifactReconciliationError(
                "Text artifact unmanaged entry no longer matches the reviewed inventory"
            )
        os.lseek(source, 0, os.SEEK_SET)
        destination = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_descriptor,
        )
        while True:
            chunk = os.read(source, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            _write_all(destination, chunk)
        os.fsync(destination)
    finally:
        if destination >= 0:
            os.close(destination)
        os.close(source)
    copied = _inspect_entry(destination_descriptor, name)
    if (
        copied["sha256"] != expected["sha256"]
        or copied["byte_size"] != expected["byte_size"]
        or copied["mode"] != 0o600
    ):
        raise TextArtifactReconciliationError(
            "Text artifact quarantine copy failed verification"
        )


def _verify_source_entry(
    source_descriptor: int,
    expected: dict[str, Any],
    *,
    artifact_id: str,
) -> None:
    observed = _inventory_entry(
        artifact_id,
        _inspect_entry(source_descriptor, str(expected["name"])),
    )
    if observed != expected:
        raise TextArtifactReconciliationError(
            "Text artifact unmanaged entry changed before source cleanup"
        )


def _managed_binding(
    receipt: dict[str, Any],
    receipt_sha256: str,
    artifact_sha256: str,
    artifact_size: int,
) -> dict[str, Any]:
    return {
        "filename": receipt["filename"],
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "receipt_sha256": receipt_sha256,
    }


def _validate_quarantine_receipt(
    receipt_bytes: bytes,
    *,
    artifact_id: str,
    inventory_sha256: str,
    expected_managed: dict[str, Any],
) -> dict[str, Any]:
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine receipt is invalid"
        ) from exc
    if not isinstance(receipt, dict) or receipt_bytes != _canonical_bytes(receipt):
        raise TextArtifactReconciliationError(
            "Text artifact quarantine receipt is not canonical JSON"
        )
    required = {
        "schema_version",
        "kind",
        "inventory_sha256",
        "artifact_id",
        "managed",
        "quarantined_entries",
        "created_at_unix",
        "does_not_establish",
    }
    if set(receipt) != required:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine receipt fields are invalid"
        )
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("kind") != RECEIPT_KIND
        or receipt.get("artifact_id") != artifact_id
        or receipt.get("inventory_sha256") != inventory_sha256
        or receipt.get("managed") != expected_managed
    ):
        raise TextArtifactReconciliationError(
            "Text artifact quarantine receipt binding is invalid"
        )
    entries = receipt.get("quarantined_entries")
    if (
        not isinstance(entries, list)
        or not entries
        or len(entries) > _MAX_UNMANAGED_ENTRIES
        or not all(isinstance(entry, dict) for entry in entries)
    ):
        raise TextArtifactReconciliationError(
            "Text artifact quarantine entry inventory is invalid"
        )
    names = [entry.get("name") for entry in entries]
    if (
        any(not isinstance(name, str) for name in names)
        or len(set(names)) != len(names)
        or names != sorted(names)
    ):
        raise TextArtifactReconciliationError(
            "Text artifact quarantine entry names are invalid"
        )
    entry_fields = {
        "path",
        "file_type",
        "name",
        "device",
        "inode",
        "mode",
        "link_count",
        "uid",
        "gid",
        "byte_size",
        "mtime_ns",
        "ctime_ns",
        "sha256",
    }
    integer_fields = entry_fields - {"path", "file_type", "name", "sha256"}
    total_bytes = 0
    for entry in entries:
        if set(entry) != entry_fields:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine entry fields are invalid"
            )
        if any(
            isinstance(entry[field], bool)
            or not isinstance(entry[field], int)
            or entry[field] < 0
            for field in integer_fields
        ):
            raise TextArtifactReconciliationError(
                "Text artifact quarantine entry metadata is invalid"
            )
        name = _safe_entry_name(str(entry["name"]))
        if (
            entry["path"] != f"{artifact_id}/{name}"
            or entry["file_type"] != "regular"
            or entry["mode"] not in _ALLOWED_LEGACY_MODES
            or entry["link_count"] != 1
            or entry["uid"] != os.geteuid()
            or entry["byte_size"] > artifacts.MAX_TEXT_ARTIFACT_BYTES
        ):
            raise TextArtifactReconciliationError(
                "Text artifact quarantine entry contract is invalid"
            )
        try:
            artifacts._validate_sha256(
                entry["sha256"], "quarantine_entry_sha256"
            )
        except artifacts.ArtifactTransferError as exc:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine entry digest is invalid"
            ) from exc
        total_bytes += entry["byte_size"]
    if total_bytes > _MAX_UNMANAGED_TOTAL_BYTES:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine bytes exceed the reconciliation limit"
        )
    created_at = receipt.get("created_at_unix")
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 1:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine timestamp is invalid"
        )
    reconstructed_inventory = {
        "schema_version": SCHEMA_VERSION,
        "kind": INVENTORY_KIND,
        "artifact_id": artifact_id,
        "managed": expected_managed,
        "unmanaged_entries": entries,
        "does_not_establish": list(_INVENTORY_NONCLAIMS),
    }
    if _digest(reconstructed_inventory) != inventory_sha256:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine receipt does not match the inventory hash"
        )
    return receipt


def _load_quarantine_locked(
    quarantine_root_descriptor: int,
    *,
    inventory_sha256: str,
    artifact_id: str,
    expected_managed: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    descriptor, identity = artifacts._open_private_directory_at(
        quarantine_root_descriptor,
        inventory_sha256,
    )
    try:
        receipt_bytes, receipt_sha256, _ = artifacts._read_private_regular_file_at(
            descriptor,
            "receipt.json",
            max_bytes=artifacts.MAX_TEXT_ARTIFACT_RECEIPT_BYTES,
        )
        receipt = _validate_quarantine_receipt(
            receipt_bytes,
            artifact_id=artifact_id,
            inventory_sha256=inventory_sha256,
            expected_managed=expected_managed,
        )
        expected_names = {"receipt.json"} | {
            str(entry["name"]) for entry in receipt["quarantined_entries"]
        }
        if set(os.listdir(descriptor)) != expected_names:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine directory contains unmanaged entries"
            )
        total_bytes = 0
        for entry in receipt["quarantined_entries"]:
            copied = _inspect_entry(descriptor, str(entry["name"]))
            if (
                copied["sha256"] != entry.get("sha256")
                or copied["byte_size"] != entry.get("byte_size")
                or copied["mode"] != 0o600
            ):
                raise TextArtifactReconciliationError(
                    "Text artifact quarantine payload failed verification"
                )
            total_bytes += copied["byte_size"]
        if total_bytes > _MAX_UNMANAGED_TOTAL_BYTES:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine bytes exceed the reconciliation limit"
            )
        artifacts._verify_private_directory_at(
            quarantine_root_descriptor,
            inventory_sha256,
            descriptor,
            identity,
        )
        return receipt, receipt_sha256
    finally:
        os.close(descriptor)


def _build_quarantine_receipt(
    inventory: dict[str, Any],
    *,
    created_at_unix: int,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "inventory_sha256": inventory["inventory_sha256"],
        "artifact_id": inventory["artifact_id"],
        "managed": inventory["managed"],
        "quarantined_entries": inventory["unmanaged_entries"],
        "created_at_unix": created_at_unix,
        "does_not_establish": [
            "safe deletion beyond the reviewed inventory",
            "transport-file authorship",
            "review correctness",
            "merge authority",
        ],
    }


def _quarantine_directory_usage_locked(
    quarantine_root_descriptor: int,
    name: str,
) -> int:
    descriptor, identity = artifacts._open_private_directory_at(
        quarantine_root_descriptor,
        name,
    )
    try:
        entries = sorted(os.listdir(descriptor))
        if len(entries) > _MAX_UNMANAGED_ENTRIES + 1:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine directory exceeds the bounded entry count"
            )
        total_bytes = 0
        for entry_name in entries:
            file_descriptor, before = _open_legacy_regular_file_at(
                descriptor,
                entry_name,
            )
            try:
                after = os.fstat(file_descriptor)
                linked = os.stat(
                    entry_name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if (
                    _entry_identity(before) != _entry_identity(after)
                    or _entry_identity(before) != _entry_identity(linked)
                    or stat.S_IMODE(before.st_mode) != 0o600
                ):
                    raise TextArtifactReconciliationError(
                        "Text artifact quarantine usage changed while reading"
                    )
                total_bytes += before.st_size
            finally:
                os.close(file_descriptor)
        artifacts._verify_private_directory_at(
            quarantine_root_descriptor,
            name,
            descriptor,
            identity,
        )
        return total_bytes
    finally:
        os.close(descriptor)


def _quarantine_usage_locked(
    quarantine_root_descriptor: int,
) -> dict[str, Any]:
    names = sorted(os.listdir(quarantine_root_descriptor))
    if len(names) > _MAX_QUARANTINE_DIRECTORIES:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine directory count exceeds the retention limit"
        )
    total_bytes = 0
    for name in names:
        if artifacts.SHA256_RE.fullmatch(name) is None:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine root contains an unmanaged entry"
            )
        total_bytes += _quarantine_directory_usage_locked(
            quarantine_root_descriptor,
            name,
        )
        if total_bytes > _MAX_QUARANTINE_TOTAL_BYTES:
            raise TextArtifactReconciliationError(
                "Text artifact quarantine bytes exceed the retention limit"
            )
    return {
        "names": names,
        "directory_count": len(names),
        "byte_size": total_bytes,
    }


def _require_quarantine_capacity(
    usage: dict[str, Any],
    *,
    additional_bytes: int,
) -> None:
    if usage["directory_count"] + 1 > _MAX_QUARANTINE_DIRECTORIES:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine directory capacity is exhausted"
        )
    if usage["byte_size"] + additional_bytes > _MAX_QUARANTINE_TOTAL_BYTES:
        raise TextArtifactReconciliationError(
            "Text artifact quarantine byte capacity is exhausted"
        )


def _entry_matches_bound_source(
    observed: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    fields = {
        "path",
        "file_type",
        "name",
        "device",
        "inode",
        "mode",
        "link_count",
        "uid",
        "gid",
        "byte_size",
        "mtime_ns",
        "sha256",
    }
    return all(observed.get(field) == expected.get(field) for field in fields)


def _renameat2(
    source_descriptor: int,
    source_name: str,
    destination_descriptor: int,
    destination_name: str,
    *,
    flags: int,
    operation: str,
) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise TextArtifactReconciliationError(
            f"Text artifact {operation} rename is unavailable"
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_descriptor,
        os.fsencode(_safe_entry_name(source_name)),
        destination_descriptor,
        os.fsencode(_safe_entry_name(destination_name)),
        flags,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if flags == _RENAME_NOREPLACE and error == errno.EEXIST:
        raise TextArtifactReconciliationError(
            f"Text artifact {operation} destination already exists"
        )
    if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise TextArtifactReconciliationError(
            f"Text artifact {operation} rename is unavailable"
        )
    raise TextArtifactReconciliationError(
        f"Text artifact {operation} rename failed"
    ) from OSError(error, os.strerror(error))


def _rename_directory_noreplace(
    parent_descriptor: int,
    source_name: str,
    destination_name: str,
) -> None:
    _renameat2(
        parent_descriptor,
        source_name,
        parent_descriptor,
        destination_name,
        flags=_RENAME_NOREPLACE,
        operation="quarantine",
    )


def _rename_entry_noreplace(
    source_descriptor: int,
    source_name: str,
    destination_descriptor: int,
    destination_name: str,
) -> None:
    _renameat2(
        source_descriptor,
        source_name,
        destination_descriptor,
        destination_name,
        flags=_RENAME_NOREPLACE,
        operation="source isolation",
    )


def _rename_entry_exchange(
    source_descriptor: int,
    source_name: str,
    destination_descriptor: int,
    destination_name: str,
) -> None:
    _renameat2(
        source_descriptor,
        source_name,
        destination_descriptor,
        destination_name,
        flags=_RENAME_EXCHANGE,
        operation="verified source exchange",
    )


def _create_quarantine_locked(
    quarantine_root_descriptor: int,
    *,
    inventory: dict[str, Any],
    receipt: dict[str, Any],
    source_descriptor: int,
) -> tuple[dict[str, Any], str, Path]:
    inventory_sha256 = str(inventory["inventory_sha256"])
    temporary_name = f".{inventory_sha256}.{uuid.uuid4().hex}.tmp"
    temporary_path = TEXT_ARTIFACT_QUARANTINE_ROOT / temporary_name
    final_path = TEXT_ARTIFACT_QUARANTINE_ROOT / inventory_sha256
    os.mkdir(temporary_name, 0o700, dir_fd=quarantine_root_descriptor)
    temporary_descriptor, _ = artifacts._open_private_directory_at(
        quarantine_root_descriptor,
        temporary_name,
    )
    try:
        for entry in inventory["unmanaged_entries"]:
            _copy_entry(
                source_descriptor,
                temporary_descriptor,
                entry,
                artifact_id=str(inventory["artifact_id"]),
            )
        receipt_path = temporary_path / "receipt.json"
        artifacts._atomic_write(receipt_path, _canonical_bytes(receipt))
        quarantine_receipt_sha256 = hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest()
        os.fsync(temporary_descriptor)
        _verify_current_private_directory_at(
            quarantine_root_descriptor,
            temporary_name,
            temporary_descriptor,
        )
    except Exception:
        os.close(temporary_descriptor)
        shutil.rmtree(temporary_path, ignore_errors=True)
        raise
    os.close(temporary_descriptor)
    try:
        _rename_directory_noreplace(
            quarantine_root_descriptor,
            temporary_name,
            inventory_sha256,
        )
    except Exception:
        shutil.rmtree(temporary_path, ignore_errors=True)
        raise
    os.fsync(quarantine_root_descriptor)
    return receipt, quarantine_receipt_sha256, final_path


def _clean_source_locked(
    root_descriptor: int,
    quarantine_root_descriptor: int,
    *,
    artifact_id: str,
    inventory_sha256: str,
    quarantine_receipt: dict[str, Any],
) -> int:
    artifact_descriptor, _ = artifacts._open_private_directory_at(
        root_descriptor,
        artifact_id,
    )
    cleanup_name = f".{inventory_sha256}.{uuid.uuid4().hex}.source-cleanup"
    cleanup_descriptor: int | None = None
    quarantine_descriptor: int | None = None
    preserve_cleanup = False
    try:
        receipt, receipt_sha256, artifact_sha256, artifact_size = (
            _validate_managed_artifact(
                artifact_descriptor,
                artifact_id=artifact_id,
            )
        )
        managed = _managed_binding(
            receipt,
            receipt_sha256,
            artifact_sha256,
            artifact_size,
        )
        if managed != quarantine_receipt["managed"]:
            raise TextArtifactReconciliationError(
                "Text artifact source managed binding changed"
            )
        expected_entries = {
            str(entry["name"]): entry
            for entry in quarantine_receipt["quarantined_entries"]
        }
        managed_names = {"receipt.json", receipt["filename"]}
        source_names = set(os.listdir(artifact_descriptor))
        remaining_names = sorted(source_names - managed_names)
        unknown = sorted(set(remaining_names) - set(expected_entries))
        if unknown:
            raise TextArtifactReconciliationError(
                "Text artifact source contains entries outside the reviewed quarantine"
            )
        if not remaining_names:
            _verify_current_private_directory_at(
                root_descriptor,
                artifact_id,
                artifact_descriptor,
            )
            return 0

        os.mkdir(cleanup_name, 0o700, dir_fd=quarantine_root_descriptor)
        cleanup_descriptor, _ = artifacts._open_private_directory_at(
            quarantine_root_descriptor,
            cleanup_name,
        )
        quarantine_descriptor, _ = artifacts._open_private_directory_at(
            quarantine_root_descriptor,
            inventory_sha256,
        )
        try:
            for name in remaining_names:
                expected = expected_entries[name]
                _verify_source_entry(
                    artifact_descriptor,
                    expected,
                    artifact_id=artifact_id,
                )
                _rename_entry_noreplace(
                    artifact_descriptor,
                    name,
                    cleanup_descriptor,
                    name,
                )
                isolated = _inventory_entry(
                    artifact_id,
                    _inspect_entry(cleanup_descriptor, name),
                )
                if not _entry_matches_bound_source(isolated, expected):
                    preserve_cleanup = True
                    raise TextArtifactReconciliationError(
                        "Text artifact source entry changed before atomic isolation"
                    )
                _rename_entry_exchange(
                    cleanup_descriptor,
                    name,
                    quarantine_descriptor,
                    name,
                )
                quarantined = _inventory_entry(
                    artifact_id,
                    _inspect_entry(quarantine_descriptor, name),
                )
                if not _entry_matches_bound_source(quarantined, expected):
                    preserve_cleanup = True
                    raise TextArtifactReconciliationError(
                        "Text artifact isolated source entry changed during exchange"
                    )
                os.chmod(
                    name,
                    0o600,
                    dir_fd=quarantine_descriptor,
                    follow_symlinks=False,
                )
                stored = _inspect_entry(quarantine_descriptor, name)
                if (
                    stored["sha256"] != expected["sha256"]
                    or stored["byte_size"] != expected["byte_size"]
                    or stored["mode"] != 0o600
                ):
                    preserve_cleanup = True
                    raise TextArtifactReconciliationError(
                        "Text artifact exchanged quarantine payload failed verification"
                    )
                os.unlink(name, dir_fd=cleanup_descriptor)
            os.fsync(artifact_descriptor)
            os.fsync(quarantine_descriptor)
            os.fsync(cleanup_descriptor)
            if set(os.listdir(artifact_descriptor)) != managed_names:
                raise TextArtifactReconciliationError(
                    "Text artifact source cleanup did not restore the managed entry set"
                )
            if os.listdir(cleanup_descriptor):
                preserve_cleanup = True
                raise TextArtifactReconciliationError(
                    "Text artifact source cleanup staging is not empty"
                )
            _verify_current_private_directory_at(
                root_descriptor,
                artifact_id,
                artifact_descriptor,
            )
            _verify_current_private_directory_at(
                quarantine_root_descriptor,
                inventory_sha256,
                quarantine_descriptor,
            )
        except Exception:
            if cleanup_descriptor is not None and os.listdir(cleanup_descriptor):
                preserve_cleanup = True
            raise
        return len(remaining_names)
    finally:
        if quarantine_descriptor is not None:
            os.close(quarantine_descriptor)
        if cleanup_descriptor is not None:
            os.close(cleanup_descriptor)
            if not preserve_cleanup:
                try:
                    os.rmdir(cleanup_name, dir_fd=quarantine_root_descriptor)
                    os.fsync(quarantine_root_descriptor)
                except FileNotFoundError:
                    pass
        os.close(artifact_descriptor)


def reconcile_text_artifact_store(
    artifact_id: str,
    expected_inventory_sha256: str,
    expected_artifact_sha256: str,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    identity = artifacts._validate_artifact_id(artifact_id)
    inventory_sha256 = artifacts._validate_sha256(
        expected_inventory_sha256,
        "expected_inventory_sha256",
    )
    artifact_sha256 = artifacts._validate_sha256(
        expected_artifact_sha256,
        "expected_artifact_sha256",
    )
    receipt_sha256 = artifacts._validate_sha256(
        expected_receipt_sha256,
        "expected_receipt_sha256",
    )
    root_descriptor, root_identity = artifacts._open_private_directory_path(
        artifacts.TEXT_ARTIFACT_ROOT
    )
    try:
        try:
            fcntl.flock(root_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TextArtifactReconciliationError(
                "Text artifact store is busy"
            ) from exc
        try:
            os.lstat(TEXT_ARTIFACT_QUARANTINE_ROOT)
            quarantine_preexisting = True
        except FileNotFoundError:
            quarantine_preexisting = False
        prevalidated_inventory: dict[str, Any] | None = None
        if not quarantine_preexisting:
            prevalidated_inventory = _inspect_locked(
                root_descriptor, root_identity, identity
            )
            if prevalidated_inventory["inventory_sha256"] != inventory_sha256:
                raise TextArtifactReconciliationError(
                    "Text artifact inventory hash precondition failed"
                )
            if (
                prevalidated_inventory["managed"]["artifact_sha256"]
                != artifact_sha256
                or prevalidated_inventory["managed"]["receipt_sha256"]
                != receipt_sha256
            ):
                raise TextArtifactReconciliationError(
                    "Text artifact managed hash precondition failed"
                )
            if not prevalidated_inventory["unmanaged_entries"]:
                raise TextArtifactReconciliationError(
                    "Text artifact has no unmanaged entries to reconcile"
                )
        artifacts._ensure_private_directory(TEXT_ARTIFACT_QUARANTINE_ROOT)
        quarantine_root_descriptor, _ = artifacts._open_private_directory_path(
            TEXT_ARTIFACT_QUARANTINE_ROOT
        )
        try:
            try:
                fcntl.flock(
                    quarantine_root_descriptor,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as exc:
                raise TextArtifactReconciliationError(
                    "Text artifact quarantine store is busy"
                ) from exc
            quarantine_usage = _quarantine_usage_locked(
                quarantine_root_descriptor
            )
            quarantine_names = set(quarantine_usage["names"])
            quarantine_reused = inventory_sha256 in quarantine_names
            if quarantine_reused:
                artifact_descriptor, _ = artifacts._open_private_directory_at(
                    root_descriptor,
                    identity,
                )
                try:
                    receipt, observed_receipt_sha256, observed_artifact_sha256, artifact_size = (
                        _validate_managed_artifact(
                            artifact_descriptor,
                            artifact_id=identity,
                        )
                    )
                finally:
                    os.close(artifact_descriptor)
                managed = _managed_binding(
                    receipt,
                    observed_receipt_sha256,
                    observed_artifact_sha256,
                    artifact_size,
                )
                if (
                    observed_artifact_sha256 != artifact_sha256
                    or observed_receipt_sha256 != receipt_sha256
                ):
                    raise TextArtifactReconciliationError(
                        "Text artifact managed hash precondition failed"
                    )
                quarantine_receipt, quarantine_receipt_sha256 = (
                    _load_quarantine_locked(
                        quarantine_root_descriptor,
                        inventory_sha256=inventory_sha256,
                        artifact_id=identity,
                        expected_managed=managed,
                    )
                )
                final_path = TEXT_ARTIFACT_QUARANTINE_ROOT / inventory_sha256
            else:
                inventory = prevalidated_inventory or _inspect_locked(
                    root_descriptor, root_identity, identity
                )
                if inventory["inventory_sha256"] != inventory_sha256:
                    raise TextArtifactReconciliationError(
                        "Text artifact inventory hash precondition failed"
                    )
                if (
                    inventory["managed"]["artifact_sha256"] != artifact_sha256
                    or inventory["managed"]["receipt_sha256"] != receipt_sha256
                ):
                    raise TextArtifactReconciliationError(
                        "Text artifact managed hash precondition failed"
                    )
                if not inventory["unmanaged_entries"]:
                    raise TextArtifactReconciliationError(
                        "Text artifact has no unmanaged entries to reconcile"
                    )
                quarantine_receipt = _build_quarantine_receipt(
                    inventory,
                    created_at_unix=int(time.time()),
                )
                additional_bytes = sum(
                    int(entry["byte_size"])
                    for entry in inventory["unmanaged_entries"]
                ) + len(_canonical_bytes(quarantine_receipt))
                _require_quarantine_capacity(
                    quarantine_usage,
                    additional_bytes=additional_bytes,
                )
                artifact_descriptor, _ = artifacts._open_private_directory_at(
                    root_descriptor,
                    identity,
                )
                try:
                    quarantine_receipt, quarantine_receipt_sha256, final_path = (
                        _create_quarantine_locked(
                            quarantine_root_descriptor,
                            inventory=inventory,
                            receipt=quarantine_receipt,
                            source_descriptor=artifact_descriptor,
                        )
                    )
                finally:
                    os.close(artifact_descriptor)
                artifacts.base._append_audit(
                    {
                        "timestamp_unix": int(time.time()),
                        "operation": "text-artifact-quarantine-created",
                        "artifact_id": identity,
                        "inventory_sha256": inventory_sha256,
                        "entry_count": len(inventory["unmanaged_entries"]),
                        "quarantine_path_sha256": hashlib.sha256(
                            str(final_path).encode("utf-8")
                        ).hexdigest(),
                        "quarantine_receipt_sha256": quarantine_receipt_sha256,
                    }
                )
            cleaned_count = _clean_source_locked(
                root_descriptor,
                quarantine_root_descriptor,
                artifact_id=identity,
                inventory_sha256=inventory_sha256,
                quarantine_receipt=quarantine_receipt,
            )
            artifacts.base._append_audit(
                {
                    "timestamp_unix": int(time.time()),
                    "operation": (
                        "text-artifact-source-cleaned"
                        if cleaned_count
                        else "text-artifact-reconciliation-readback"
                    ),
                    "artifact_id": identity,
                    "inventory_sha256": inventory_sha256,
                    "entry_count": cleaned_count,
                    "quarantine_receipt_sha256": quarantine_receipt_sha256,
                    "quarantine_reused": quarantine_reused,
                }
            )
            _verify_current_private_directory_path(
                TEXT_ARTIFACT_QUARANTINE_ROOT,
                quarantine_root_descriptor,
            )
        finally:
            os.close(quarantine_root_descriptor)
        artifacts._verify_private_directory_path(
            root_descriptor,
            artifacts.TEXT_ARTIFACT_ROOT,
            root_identity,
        )
    finally:
        os.close(root_descriptor)
    moved_entry_count = len(quarantine_receipt["quarantined_entries"])
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_text_artifact_reconciliation_result",
        "status": "reconciled",
        "artifact_id": identity,
        "inventory_sha256": inventory_sha256,
        "quarantine_path": str(final_path),
        "quarantine_receipt_sha256": quarantine_receipt_sha256,
        "moved_entry_count": moved_entry_count,
        "cleaned_entry_count": cleaned_count,
        "idempotent_replay": quarantine_reused and cleaned_count == 0,
        "publisher_retry_allowed": True,
        "does_not_establish": [
            "review correctness",
            "merge authority",
            "future store health",
        ],
    }

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grabowski-text-artifact-reconcile")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("inspect-store")
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--artifact-id", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--artifact-id", required=True)
    apply_parser.add_argument("--expected-inventory-sha256", required=True)
    apply_parser.add_argument("--expected-artifact-sha256", required=True)
    apply_parser.add_argument("--expected-receipt-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in {"inspect", "inspect-store"}:
            artifacts.operator._require_operator_capability("artifact_transfer")
            result = (
                inspect_text_artifact_store_root()
                if args.command == "inspect-store"
                else inspect_text_artifact_store(args.artifact_id)
            )
        else:
            artifacts.operator._require_operator_mutation(
                "artifact_transfer",
                path=str(artifacts.TEXT_ARTIFACT_ROOT),
                host="heim-pc",
            )
            result = reconcile_text_artifact_store(
                args.artifact_id,
                args.expected_inventory_sha256,
                args.expected_artifact_sha256,
                args.expected_receipt_sha256,
            )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "grabowski_text_artifact_reconciliation_failure",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                    "does_not_establish": ["effect absence", "safe retry"],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

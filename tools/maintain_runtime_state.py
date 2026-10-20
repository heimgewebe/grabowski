#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
STATE_ROOT = Path.home() / ".local/state/grabowski"
JOBS_ROOT = STATE_ROOT / "jobs"
ARCHIVE_ROOT = STATE_ROOT / "job-archive"
RECEIPT_ROOT = STATE_ROOT / "retention-receipts"
TASK_DB = STATE_ROOT / "tasks.sqlite3"
WORKER_DB = STATE_ROOT / "workers" / "workers.sqlite3"
RESOURCE_DB = STATE_ROOT / "resources.sqlite3"
# Match grabowski_job_origin.UNIT_RE without importing the packaged runtime:
# this standalone retention tool also runs before a runtime environment exists.
JOB_ID_SUFFIX = r"(?:[0-9a-f]{12}|rgpm-[0-9a-f]{16}-[0-9]{2})"
JOB_NAME = re.compile(rf"grabowski-job-{JOB_ID_SUFFIX}\Z")
JOB_UNIT = re.compile(rf"grabowski-job-{JOB_ID_SUFFIX}\.service\Z")
TASK_UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
WORKER_UNIT = re.compile(
    r"grabowski-(browser|gui)-worker-([0-9a-f]{20})\.service\Z"
)
LEGACY_SELF_DEPLOY_COLLECTION = re.compile(
    r"legacy-self-deploy-without-finalization-([0-9]{10})\Z"
)
TERMINAL_TASK_STATES = {
    "completed",
    "failed",
    "cancelled",
    "timed_out",
    "signalled",
}
MAX_FAILED_UNITS = 2_000
MAX_JOB_SCAN_ENTRIES = 2_000
MAX_JOB_REGISTRY_ENTRIES = 100_000
MAX_ARCHIVE_JOBS_PER_PLAN = 128
MAX_JOB_RUNTIME_SECONDS = 2_592_000
JOB_RUNTIME_GRACE_SECONDS = 300
SYSTEMD_SHOW_CHUNK_SIZE = 100
MAX_ARCHIVE_FILES = 32
MAX_ARCHIVE_ENTRIES = 256
MAX_RETAINED_JSON_TEMPS = 64
MAX_ARCHIVE_FILE_BYTES = 128 * 1024 * 1024
MAX_JSON_BYTES = 128 * 1024
MAX_WORKER_LEASE_KEYS = 32
MAX_WORKER_LEASE_JSON_BYTES = 16 * 1024
MAX_WORKER_OBSERVATION_JSON_BYTES = 128 * 1024
WORKER_EVIDENCE_CLOCK_SKEW_SECONDS = 300
MAX_RETENTION_RECEIPT_ATTEMPTS = 16
MAX_RETENTION_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_LEGACY_ARCHIVE_COLLECTIONS = 64
MAX_LEGACY_ARCHIVE_ROOT_ENTRIES = 4_000
MAX_LEGACY_ARCHIVE_ENTRIES = 512
MAX_WORKTREE_HYGIENE_REPOSITORIES = 8
MAX_WORKTREE_HYGIENE_ACTIONS_PER_CYCLE = 8
MAX_WORKTREE_HYGIENE_ROOTS = 16
MAX_LEGACY_COLLECTION_BYTES = 256 * 1024 * 1024
LEGACY_SELF_DEPLOY_REASON = (
    "legacy self-deploy completed and superseded, but lacks finalization receipt"
)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short write while publishing retention evidence")
        offset += written


def _fsync_directory(path: Path) -> None:
    directory = _private_directory(path)
    descriptor = os.open(
        directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_directory(path: Path, *, create: bool = False) -> Path:
    if path.is_symlink():
        raise RuntimeError(f"private directory may not be a symlink: {path}")
    if create:
        parent = _private_directory(path.parent)
        path = parent / path.name
        path.mkdir(mode=0o700, exist_ok=True)
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"private directory is unavailable: {path}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError(f"directory must be private and owner-controlled: {path}")
    return path.resolve(strict=True)


def _open_private_regular(path: Path, *, max_bytes: int) -> tuple[int, os.stat_result]:
    if path.is_symlink():
        raise RuntimeError(f"private file may not be a symlink: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"private file is unavailable: {path}") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size > max_bytes
    ):
        os.close(descriptor)
        raise RuntimeError(f"file must be one bounded private owner-controlled regular file: {path}")
    return descriptor, metadata


def _read_private_bytes(path: Path, *, max_bytes: int) -> bytes:
    descriptor, _ = _open_private_regular(path, max_bytes=max_bytes)
    try:
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > max_bytes:
            raise RuntimeError(f"file exceeds retention bound: {path}")
        return bytes(data)
    finally:
        os.close(descriptor)


def _private_file_digest(path: Path, *, max_bytes: int) -> tuple[int, str]:
    descriptor, metadata = _open_private_regular(path, max_bytes=max_bytes)
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return metadata.st_size, digest.hexdigest()

def _archive_internal_manifest_shape_preflight(
    path: Path, *, metadata: os.stat_result | None = None
) -> None:
    """Count exemption is not an exemption from evidence safety checks.

    Retryable archive-manifest.json must be a small, private regular file.
    Check its shape without opening a FIFO or following a symlink.
    """
    if metadata is None:
        metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size > MAX_JSON_BYTES
    ):
        raise RuntimeError(
            f"archive internal manifest must be one bounded private "
            f"owner-controlled regular file: {path}"
        )


def _archive_internal_manifest_entry(
    path: Path, *, metadata: os.stat_result
) -> bool:
    """Recognize bounded private internal metadata, not archive payload.

    An atomic EXCHANGE retaining a prior archive-manifest.json leaves its
    displaced inode at .archive-manifest.json.<pid>.<time_ns>.tmp. It is
    preserved as untrusted history, never treated as a verified archive
    receipt or silently deleted. Limit names and sizes; entry-count bounds
    still include this metadata.
    """
    if path.name != "archive-manifest.json" and re.fullmatch(
        r"\.archive-manifest\.json\.[1-9][0-9]{0,11}\.[1-9][0-9]{0,19}\.tmp",
        path.name,
    ) is None:
        return False
    _archive_internal_manifest_shape_preflight(path, metadata=metadata)
    return True


def _archive_open_private_root(directory: Path) -> int:
    """Pin a private job-directory inode; never follow its final symlink."""
    try:
        fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise RuntimeError(f"archive source directory is unavailable: {directory}") from exc
    metadata = os.fstat(fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(fd)
        raise RuntimeError(f"archive source directory is not private: {directory}")
    return fd


def _archive_open_child_root(parent_fd: int, name: str, path: Path) -> int:
    """Open a private directory through the held parent, never by path."""
    if not name or "/" in name or name in {".", ".."}:
        raise RuntimeError("private child root has invalid basename")
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise RuntimeError(f"private child root is not owner-controlled: {path}")
    return descriptor


def _archive_require_child_bound(
    parent_fd: int, name: str, child_fd: int, path: Path
) -> None:
    """A final-component rename must not silently retarget our FD."""
    expected = os.fstat(child_fd)
    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(f"private child disappeared: {path}") from exc
    if (
        not stat.S_ISDIR(observed.st_mode)
        or (observed.st_dev, observed.st_ino)
        != (expected.st_dev, expected.st_ino)
    ):
        raise RuntimeError(f"private child root changed: {path}")


def _pinned_output_root_fd(plan: "_PinnedRetentionPlan", kind: str) -> int:
    """Pin archive/receipt root before first use; never adopt a new pathname."""
    if kind not in {"archive", "receipt"}:
        raise RuntimeError("invalid retention output root type")
    root = Path(plan[f"{kind}_root"])
    parent_fd = getattr(plan, f"{kind}_parent_fd")
    _archive_require_unchanged_root(root.parent, parent_fd)
    descriptor = getattr(plan, f"{kind}_fd")
    if descriptor < 0:
        # A foreign directory appearing since planning cannot acquire custody.
        try:
            os.mkdir(root.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise RuntimeError(
                f"{kind} root appeared since planning; explicit retry required"
            ) from exc
        descriptor = _archive_open_child_root(parent_fd, root.name, root)
        setattr(plan, f"{kind}_fd", descriptor)
    _archive_require_child_bound(parent_fd, root.name, descriptor, root)
    return descriptor


def _archive_root_fd_for_plan(plan: "_PinnedRetentionPlan") -> int:
    return _pinned_output_root_fd(plan, "archive")


def _receipt_root_fd_for_plan(plan: "_PinnedRetentionPlan") -> int:
    return _pinned_output_root_fd(plan, "receipt")


def _archive_require_unchanged_root(directory: Path, fd: int) -> None:
    """Reject an archive root renamed or replaced during a pinned read."""
    expected = os.fstat(fd)
    try:
        actual = directory.lstat()
    except OSError as exc:
        raise RuntimeError(f"archive source directory changed during inspection: {directory}") from exc
    if (
        not stat.S_ISDIR(actual.st_mode)
        or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        raise RuntimeError(f"archive source directory changed during inspection: {directory}")


def _archive_bounded_entries(directory: Path, directory_fd: int) -> list[Path]:
    """Enumerate a pinned flat job directory, never recursive path traversal.

    Live and archived job inventories have only root-level files. Reject any
    unexpected nested directory rather than introducing a symlinkable parent
    whose contents could be opened outside the verified archive inode.
    """
    entries: list[Path] = []
    with os.scandir(directory_fd) as scan:
        for child in scan:
            path = directory / child.name
            entries.append(path)
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise RuntimeError("archive source exceeds the entry-count bound")
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(f"archive source contains a symlink: {path}")
            if stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError(f"archive source contains nested directory: {path}")
    return sorted(entries)


def _archive_private_file_digest(
    directory_fd: int, path: Path, *, max_bytes: int
) -> tuple[int, str]:
    """Hash a root-level file by its pinned parent fd, not a racy path."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path.name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise RuntimeError(f"archive source file is unavailable: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > max_bytes
        ):
            raise RuntimeError(
                f"file must be one bounded private owner-controlled regular file: {path}"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(f"archive file exceeds retention bound: {path}")
            digest.update(chunk)
        return metadata.st_size, digest.hexdigest()
    finally:
        os.close(fd)


def _archive_file_shape_preflight(
    directory: Path, *, jobs_root_fd: int | None = None
) -> None:
    """Classify unsafe archive shapes under the originally pinned jobs root."""
    fd = (
        _archive_open_child_root(jobs_root_fd, directory.name, directory)
        if jobs_root_fd is not None
        else _archive_open_private_root(directory)
    )
    try:
        files = 0
        for path in _archive_bounded_entries(directory, fd):
            metadata = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            if _archive_internal_manifest_entry(path, metadata=metadata):
                continue
            files += 1
            if files > MAX_ARCHIVE_FILES:
                raise RuntimeError("archive source exceeds the file-count bound")
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size > MAX_ARCHIVE_FILE_BYTES
            ):
                raise RuntimeError(
                    f"file must be one bounded private owner-controlled regular file: {path}"
                )
        if jobs_root_fd is not None:
            _archive_require_child_bound(
                jobs_root_fd, directory.name, fd, directory
            )
        else:
            _archive_require_unchanged_root(directory, fd)
    finally:
        os.close(fd)


def _failed_units() -> list[str]:
    result = _run(["systemctl", "--user", "--failed", "--no-legend", "--plain"])
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stderr.strip() or "failed-unit inventory failed")
    units = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields:
            units.append(fields[0])
    if len(units) > MAX_FAILED_UNITS:
        raise RuntimeError("failed-unit inventory exceeds the bounded scan")
    return sorted(set(units))


def _parse_systemd_show(stdout: str) -> dict[str, dict[str, str]]:
    states: dict[str, dict[str, str]] = {}
    for block in stdout.strip().split("\n\n") if stdout.strip() else []:
        properties: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                properties[key] = value
        unit = properties.get("Id")
        if not unit or not (
            JOB_UNIT.fullmatch(unit)
            or TASK_UNIT.fullmatch(unit)
            or WORKER_UNIT.fullmatch(unit)
        ):
            raise RuntimeError("systemd show returned an unbound unit block")
        if unit in states:
            raise RuntimeError(f"systemd show returned a duplicate unit block: {unit}")
        states[unit] = properties
    return states


def _systemd_unit_states(units: list[str]) -> dict[str, dict[str, str]]:
    normalized = sorted(set(units))
    if len(normalized) > MAX_JOB_SCAN_ENTRIES + MAX_FAILED_UNITS:
        raise RuntimeError("systemd unit inventory exceeds the bounded scan")
    states: dict[str, dict[str, str]] = {}
    for offset in range(0, len(normalized), SYSTEMD_SHOW_CHUNK_SIZE):
        chunk = normalized[offset : offset + SYSTEMD_SHOW_CHUNK_SIZE]
        if not chunk:
            continue
        result = _run([
            "systemctl",
            "--user",
            "show",
            *chunk,
            "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus",
            "--no-pager",
        ])
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "systemd job-state inventory failed")
        if len(result.stdout.encode("utf-8", errors="replace")) > 2 * 1024 * 1024:
            raise RuntimeError("systemd job-state inventory exceeded its output bound")
        states.update(_parse_systemd_show(result.stdout))
    missing = sorted(set(normalized) - set(states))
    if missing:
        raise RuntimeError(f"systemd job-state inventory omitted units: {', '.join(missing[:5])}")
    return states


def _read_json_file(
    path: Path,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> tuple[dict[str, Any], str]:
    raw = _read_private_bytes(path, max_bytes=max_bytes)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON file: {path}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON file is not an object: {path}")
    return payload, hashlib.sha256(raw).hexdigest()


def _task_state(unit: str, task_db: Path) -> str | None:
    if task_db.is_symlink() or not task_db.is_file():
        return None
    metadata = task_db.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        return None
    connection = sqlite3.connect(f"file:{task_db}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT state FROM tasks WHERE unit=?",
            (unit,),
        ).fetchone()
    finally:
        connection.close()
    return row[0] if row and isinstance(row[0], str) else None



def _private_sqlite_file(path: Path) -> Path:
    parent = _private_directory(path.parent)
    candidate = parent / path.name
    descriptor, _ = _open_private_regular(candidate, max_bytes=512 * 1024 * 1024)
    os.close(descriptor)
    for suffix, max_bytes in (("-wal", 512 * 1024 * 1024), ("-shm", 64 * 1024 * 1024)):
        sidecar = Path(str(candidate) + suffix)
        if not sidecar.exists() and not sidecar.is_symlink():
            continue
        sidecar_descriptor, _ = _open_private_regular(sidecar, max_bytes=max_bytes)
        os.close(sidecar_descriptor)
    return candidate.resolve(strict=True)


def _sqlite_schema_version(connection: sqlite3.Connection, *, expected: str) -> None:
    try:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
    except sqlite3.Error as exc:
        raise RuntimeError("state database metadata is unavailable") from exc
    if row is None or row[0] != expected:
        raise RuntimeError("state database schema is unsupported")


def _worker_unit_parts(unit: str) -> tuple[str, str]:
    match = WORKER_UNIT.fullmatch(unit)
    if match is None:
        raise RuntimeError("worker reset requires a typed worker unit")
    return match.group(1), match.group(2)


def _worker_reset_evidence(
    unit: str,
    *,
    worker_db: Path,
    resource_db: Path,
    now: int,
    systemd_state: dict[str, str],
) -> dict[str, Any]:
    kind, worker_id = _worker_unit_parts(unit)
    worker_path = _private_sqlite_file(worker_db)
    connection = sqlite3.connect(f"file:{worker_path}?mode=ro", uri=True)
    try:
        _sqlite_schema_version(connection, expected="1")
        rows = connection.execute(
            """
            SELECT worker_id, kind, unit, state, lease_keys_json,
                   updated_at_unix, last_observation_json
            FROM workers WHERE unit=? LIMIT 2
            """,
            (unit,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"worker state lookup failed: {unit}") from exc
    finally:
        connection.close()
    if len(rows) != 1:
        raise RuntimeError(f"worker unit does not have exactly one state record: {unit}")
    row = rows[0]
    if row[0] != worker_id or row[1] != kind or row[2] != unit:
        raise RuntimeError(f"worker state identity is not bound to its unit: {unit}")
    if row[3] != "failed":
        raise RuntimeError(f"worker state is not terminal failed: {unit}")
    updated_at = row[5]
    if (
        isinstance(updated_at, bool)
        or not isinstance(updated_at, int)
        or updated_at < 0
        or updated_at > now + WORKER_EVIDENCE_CLOCK_SKEW_SECONDS
    ):
        raise RuntimeError(f"worker update time is invalid: {unit}")
    lease_keys_raw = row[4]
    observation_raw = row[6]
    if (
        not isinstance(lease_keys_raw, str)
        or len(lease_keys_raw.encode("utf-8")) > MAX_WORKER_LEASE_JSON_BYTES
        or not isinstance(observation_raw, str)
        or len(observation_raw.encode("utf-8")) > MAX_WORKER_OBSERVATION_JSON_BYTES
    ):
        raise RuntimeError(f"worker state JSON is invalid or exceeds its bound: {unit}")
    try:
        lease_keys = json.loads(lease_keys_raw)
        observation = json.loads(observation_raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"worker state JSON is invalid: {unit}") from exc
    if (
        not isinstance(lease_keys, list)
        or len(lease_keys) > MAX_WORKER_LEASE_KEYS
        or any(
            not isinstance(key, str)
            or not key
            or len(key.encode("utf-8")) > 512
            or "\x00" in key
            for key in lease_keys
        )
        or len(lease_keys) != len(set(lease_keys))
    ):
        raise RuntimeError(f"worker lease-key evidence is invalid: {unit}")
    if not isinstance(observation, dict) or observation.get("state") != "failed":
        raise RuntimeError(f"worker terminal observation is unavailable: {unit}")
    observed_properties = observation.get("properties")
    if not isinstance(observed_properties, dict):
        raise RuntimeError(f"worker terminal properties are unavailable: {unit}")
    if (
        observed_properties.get("ActiveState") != "failed"
        or observed_properties.get("Result") in {None, "", "success"}
    ):
        raise RuntimeError(f"worker terminal observation is not failed: {unit}")
    if (
        systemd_state.get("Id") != unit
        or systemd_state.get("ActiveState") != "failed"
        or systemd_state.get("Result") in {None, "", "success"}
    ):
        raise RuntimeError(f"worker systemd terminality is not proven: {unit}")
    for key in ("LoadState", "ActiveState", "SubState", "Result", "ExecMainStatus"):
        if str(observed_properties.get(key, "")) != str(systemd_state.get(key, "")):
            raise RuntimeError(f"worker observation drifted from systemd state: {unit}")

    resource_path = _private_sqlite_file(resource_db)
    resource_connection = sqlite3.connect(f"file:{resource_path}?mode=ro", uri=True)
    try:
        _sqlite_schema_version(resource_connection, expected="1")
        clauses = ["owner_id=?"]
        parameters: list[Any] = [f"worker:{worker_id}"]
        if lease_keys:
            clauses.append(f"resource_key IN ({','.join('?' for _ in lease_keys)})")
            parameters.extend(lease_keys)
        parameters.append(now)
        live_rows = resource_connection.execute(
            "SELECT resource_key, owner_id, expires_at_unix FROM leases "
            f"WHERE ({' OR '.join(clauses)}) AND expires_at_unix>? LIMIT 2",
            parameters,
        ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"worker resource lookup failed: {unit}") from exc
    finally:
        resource_connection.close()
    if live_rows:
        raise RuntimeError(f"worker still owns or references live resource leases: {unit}")

    systemd_projection = {
        key: systemd_state.get(key, "")
        for key in (
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "Result",
            "ExecMainCode",
            "ExecMainStatus",
        )
    }
    record_material = {
        "worker_id": worker_id,
        "kind": kind,
        "unit": unit,
        "state": row[3],
        "lease_keys": lease_keys,
        "updated_at_unix": updated_at,
        "last_observation": observation,
    }
    return {
        "unit": unit,
        "worker_id": worker_id,
        "kind": kind,
        "worker_record_sha256": _sha256(record_material),
        "declared_lease_keys": lease_keys,
        "systemd_state": systemd_projection,
        "terminal_evidence": "worker_db_and_systemd_failed_without_live_leases",
    }


def _validate_legacy_self_deploy_collection(
    collection: Path,
    *,
    jobs_root: Path,
) -> dict[str, Any]:
    directory = _private_directory(collection)
    collection_match = LEGACY_SELF_DEPLOY_COLLECTION.fullmatch(directory.name)
    if collection_match is None:
        raise RuntimeError("legacy collection name is outside the typed contract")
    manifest, manifest_file_sha256 = _read_json_file(directory / "manifest.json")
    expected_manifest_keys = {
        "schema_version",
        "created_at_unix",
        "repo_head",
        "operation",
        "reversible",
        "entries",
    }
    if set(manifest) != expected_manifest_keys or manifest.get("schema_version") != 1:
        raise RuntimeError("legacy collection manifest shape is invalid")
    created_at = manifest.get("created_at_unix")
    repo_head = manifest.get("repo_head")
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, int)
        or created_at < 0
        or not isinstance(repo_head, str)
        or re.fullmatch(r"[0-9a-f]{40}", repo_head) is None
        or created_at != int(collection_match.group(1))
        or manifest.get("operation") != "archive_legacy_self_deploy_jobs"
        or manifest.get("reversible") is not True
    ):
        raise RuntimeError("legacy collection manifest identity is invalid")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_LEGACY_ARCHIVE_ENTRIES:
        raise RuntimeError("legacy collection entry list is invalid")
    expected_entry_keys = {
        "destination",
        "expected_head",
        "metadata_sha256",
        "reason",
        "source",
        "stdout_sha256",
        "unit",
    }
    names: list[str] = []
    verified: list[dict[str, Any]] = []
    observed_collection_bytes = (directory / "manifest.json").stat().st_size
    if observed_collection_bytes > MAX_LEGACY_COLLECTION_BYTES:
        raise RuntimeError("legacy collection exceeds its total byte bound")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise RuntimeError("legacy collection entry shape is invalid")
        unit = entry.get("unit")
        expected_head = entry.get("expected_head")
        if (
            not isinstance(unit, str)
            or JOB_NAME.fullmatch(unit) is None
            or not isinstance(expected_head, str)
            or re.fullmatch(r"[0-9a-f]{40}", expected_head) is None
            or entry.get("reason") != LEGACY_SELF_DEPLOY_REASON
        ):
            raise RuntimeError("legacy collection entry identity is invalid")
        destination = directory / unit
        if entry.get("destination") != str(destination):
            raise RuntimeError(f"legacy collection destination is unbound: {unit}")
        if entry.get("source") != str(jobs_root / unit):
            raise RuntimeError(f"legacy collection source is unbound: {unit}")
        child = _private_directory(destination)
        if child.parent != directory:
            raise RuntimeError(f"legacy collection child escaped its root: {unit}")
        child_entries = []
        for path in child.iterdir():
            child_entries.append(path)
            if len(child_entries) > 4:
                raise RuntimeError(f"legacy collection child file set is invalid: {unit}")
        actual_files = sorted(path.name for path in child_entries)
        allowed_file_sets = {
            ("metadata.json", "stderr.log", "stdout.log"),
            ("finalization.json", "metadata.json", "stderr.log", "stdout.log"),
        }
        if tuple(actual_files) not in allowed_file_sets:
            raise RuntimeError(f"legacy collection child file set is invalid: {unit}")
        metadata, metadata_file_sha256 = _read_json_file(child / "metadata.json")
        metadata_size = (child / "metadata.json").stat().st_size
        stdout_size, stdout_sha256 = _private_file_digest(
            child / "stdout.log", max_bytes=MAX_ARCHIVE_FILE_BYTES
        )
        stderr_size, stderr_sha256 = _private_file_digest(
            child / "stderr.log", max_bytes=MAX_ARCHIVE_FILE_BYTES
        )
        observed_collection_bytes += metadata_size + stdout_size + stderr_size
        if observed_collection_bytes > MAX_LEGACY_COLLECTION_BYTES:
            raise RuntimeError("legacy collection exceeds its total byte bound")
        if (
            metadata_file_sha256 != entry.get("metadata_sha256")
            or stdout_sha256 != entry.get("stdout_sha256")
        ):
            raise RuntimeError(f"legacy collection content hash mismatch: {unit}")
        argv = metadata.get("argv")
        expected_head_positions = (
            [
                index
                for index in range(len(argv) - 1)
                if argv[index] == "--expected-head"
            ]
            if isinstance(argv, list)
            and 1 <= len(argv) <= 128
            and all(
                isinstance(value, str)
                and "\x00" not in value
                and len(value.encode("utf-8")) <= 4096
                for value in argv
            )
            else []
        )
        expected_head_bound = (
            len(expected_head_positions) == 1
            and argv[expected_head_positions[0] + 1] == expected_head
        )
        if metadata.get("unit") != unit or not expected_head_bound:
            raise RuntimeError(f"legacy collection metadata binding is invalid: {unit}")
        finalization_projection: dict[str, Any] | None = None
        if "finalization.json" in actual_files:
            finalization, finalization_file_sha256 = _read_json_file(
                child / "finalization.json"
            )
            observed_collection_bytes += (child / "finalization.json").stat().st_size
            if observed_collection_bytes > MAX_LEGACY_COLLECTION_BYTES:
                raise RuntimeError("legacy collection exceeds its total byte bound")
            expected_finalization_keys = {
                "argv_sha256",
                "completion_status",
                "expected_head",
                "failure_type",
                "final_status",
                "job_id",
                "kind",
                "payload_sha256",
                "receipt_paths",
                "release_id",
                "repo_head",
                "schema_version",
                "timestamp_unix",
                "unit",
            }
            payload_sha256 = finalization.get("payload_sha256")
            payload_material = {
                key: value
                for key, value in finalization.items()
                if key != "payload_sha256"
            }
            receipt_paths = finalization.get("receipt_paths")
            expected_receipt_paths = {
                "finalization": str(jobs_root / unit / "finalization.json"),
                "metadata": str(jobs_root / unit / "metadata.json"),
                "stderr": str(jobs_root / unit / "stderr.log"),
                "stdout": str(jobs_root / unit / "stdout.log"),
            }
            timestamp_unix = finalization.get("timestamp_unix")
            release_id = finalization.get("release_id")
            if (
                set(finalization) != expected_finalization_keys
                or finalization.get("schema_version") != 1
                or finalization.get("kind") != "grabowski_runtime_deploy_finalization"
                or finalization.get("unit") != unit
                or finalization.get("job_id") != unit.removeprefix("grabowski-job-")
                or finalization.get("expected_head") != expected_head
                or finalization.get("repo_head") != expected_head
                or finalization.get("completion_status") != "complete"
                or finalization.get("final_status") != "completed"
                or finalization.get("failure_type") is not None
                or finalization.get("argv_sha256") != metadata.get("argv_sha256")
                or receipt_paths != expected_receipt_paths
                or isinstance(timestamp_unix, bool)
                or not isinstance(timestamp_unix, int)
                or timestamp_unix < 0
                or not isinstance(release_id, str)
                or not release_id
                or len(release_id.encode("utf-8")) > 512
                or not isinstance(payload_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", payload_sha256) is None
                or _sha256(payload_material) != payload_sha256
            ):
                raise RuntimeError(
                    f"legacy collection finalization binding is invalid: {unit}"
                )
            finalization_projection = {
                "file_sha256": finalization_file_sha256,
                "payload_sha256": payload_sha256,
                "release_id": finalization.get("release_id"),
            }
        names.append(unit)
        verified.append({
            "unit": unit,
            "expected_head": expected_head,
            "metadata_sha256": metadata_file_sha256,
            "stdout_sha256": stdout_sha256,
            "stderr_sha256": stderr_sha256,
            "finalization": finalization_projection,
        })
    if len(names) != len(set(names)):
        raise RuntimeError("legacy collection contains duplicate units")
    collection_entries = []
    for path in directory.iterdir():
        collection_entries.append(path)
        if len(collection_entries) > MAX_LEGACY_ARCHIVE_ENTRIES + 1:
            raise RuntimeError("legacy collection directory membership exceeds its bound")
    actual_directories = sorted(path.name for path in collection_entries if path.is_dir())
    actual_non_directories = sorted(
        path.name for path in collection_entries if not path.is_dir()
    )
    if actual_directories != sorted(names) or actual_non_directories != ["manifest.json"]:
        raise RuntimeError("legacy collection directory membership is invalid")
    return {
        "collection": directory.name,
        "valid": True,
        "entry_count": len(verified),
        "observed_bytes": observed_collection_bytes,
        "created_at_unix": created_at,
        "repo_head": repo_head,
        "manifest_file_sha256": manifest_file_sha256,
        "observed_entries_sha256": _sha256(verified),
        "reversible": True,
        "bound_files_per_entry": ["metadata.json", "stdout.log"],
        "self_bound_optional_files": ["finalization.json"],
        "self_bound_finalization_count": sum(
            1 for item in verified if item["finalization"] is not None
        ),
        "observed_unbound_files_per_entry": ["stderr.log"],
    }


def _legacy_archive_collection_statuses(
    archive_root: Path,
    *,
    jobs_root: Path,
) -> list[dict[str, Any]]:
    if not archive_root.exists() and not archive_root.is_symlink():
        return []
    root = _private_directory(archive_root)
    candidates: list[Path] = []
    root_entry_count = 0
    for path in root.iterdir():
        root_entry_count += 1
        if root_entry_count > MAX_LEGACY_ARCHIVE_ROOT_ENTRIES:
            raise RuntimeError("legacy archive root scan exceeds its bound")
        if path.name.startswith("legacy-self-deploy-without-finalization-"):
            candidates.append(path)
            if len(candidates) > MAX_LEGACY_ARCHIVE_COLLECTIONS:
                raise RuntimeError("legacy archive collection scan exceeds its bound")
    candidates.sort()
    statuses: list[dict[str, Any]] = []
    for candidate in candidates:
        match = LEGACY_SELF_DEPLOY_COLLECTION.fullmatch(candidate.name)
        if match is None:
            statuses.append({
                "collection": candidate.name,
                "valid": False,
                "error": "legacy collection name is outside the typed contract",
            })
            continue
        try:
            statuses.append(
                _validate_legacy_self_deploy_collection(
                    candidate,
                    jobs_root=jobs_root,
                )
            )
        except RuntimeError as exc:
            statuses.append({
                "collection": candidate.name,
                "valid": False,
                "error": str(exc)[:240],
            })
    return statuses


def legacy_archive_status(
    *,
    archive_root: Path = ARCHIVE_ROOT,
    jobs_root: Path = JOBS_ROOT,
    now: int | None = None,
) -> dict[str, Any]:
    jobs = _private_directory(jobs_root)
    collections = _legacy_archive_collection_statuses(
        archive_root,
        jobs_root=jobs,
    )
    observed_at = int(time.time()) if now is None else now
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise ValueError("now must be a non-negative integer")
    material = {
        "schema_version": 1,
        "authority": "read_only_legacy_archive_evidence",
        "observed_at_unix": observed_at,
        "jobs_root": str(jobs),
        "archive_root": str(archive_root),
        "collection_count": len(collections),
        "valid_collection_count": sum(1 for item in collections if item.get("valid") is True),
        "invalid_collection_count": sum(1 for item in collections if item.get("valid") is not True),
        "collections": collections,
        "does_not_establish": [
            "job_completion_outside_bound_legacy_evidence",
            "safe_cleanup_or_deletion",
            "runtime_health",
            "mutation_authority",
            "migration_authority",
        ],
    }
    return {**material, "status_sha256": _sha256(material)}


def _job_record(
    unit: str,
    jobs_root: Path,
    *,
    now: int,
    minimum_age_seconds: int,
    systemd_state: dict[str, str],
    jobs_root_fd: int | None = None,
) -> dict[str, Any]:
    job_name = unit.removesuffix(".service")
    directory = jobs_root / job_name
    if jobs_root_fd is None:
        directory = _private_directory(directory)
        if directory.parent != jobs_root:
            raise RuntimeError(f"job directory escaped jobs root: {job_name}")
        metadata, metadata_sha256 = _read_json_file(directory / "metadata.json")
    else:
        directory_fd = _archive_open_child_root(jobs_root_fd, job_name, directory)
        try:
            raw, preimage = _archive_pinned_json_preimage(directory_fd, "metadata.json")
            try:
                metadata = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid JSON file: {directory / 'metadata.json'}") from exc
            if not isinstance(metadata, dict):
                raise RuntimeError(f"JSON file is not an object: {directory / 'metadata.json'}")
            metadata_sha256 = preimage[-1]
            _archive_require_child_bound(
                jobs_root_fd, job_name, directory_fd, directory
            )
        finally:
            os.close(directory_fd)
    if metadata.get("unit") != job_name:
        raise RuntimeError(f"job metadata is not bound to its unit: {job_name}")
    created = metadata.get("created_at_unix")
    runtime_seconds = metadata.get("runtime_seconds")
    if isinstance(created, bool) or not isinstance(created, int) or created < 0:
        raise RuntimeError(f"job creation time is invalid: {job_name}")
    if (
        isinstance(runtime_seconds, bool)
        or not isinstance(runtime_seconds, int)
        or not 1 <= runtime_seconds <= MAX_JOB_RUNTIME_SECONDS
    ):
        raise RuntimeError(f"job runtime bound is invalid: {job_name}")
    age = max(0, now - created)
    active_state = systemd_state.get("ActiveState", "")
    load_state = systemd_state.get("LoadState", "")
    result = systemd_state.get("Result", "")
    if active_state in {"active", "activating", "reloading", "deactivating"}:
        terminal = False
        terminal_evidence = "systemd_nonterminal"
    elif active_state == "failed":
        terminal = True
        terminal_evidence = "systemd_failed"
    elif active_state == "inactive" and load_state == "loaded" and result:
        terminal = True
        terminal_evidence = "systemd_inactive"
    elif age >= runtime_seconds + JOB_RUNTIME_GRACE_SECONDS:
        terminal = True
        terminal_evidence = "runtime_bound_expired"
    else:
        terminal = False
        terminal_evidence = "terminality_unproven"
    return {
        "unit": unit,
        "job_name": job_name,
        "created_at_unix": created,
        "runtime_seconds": runtime_seconds,
        "metadata_sha256": metadata_sha256,
        "terminal": terminal,
        "terminal_evidence": terminal_evidence,
        "systemd_state": {
            key: systemd_state.get(key, "")
            for key in (
                "LoadState",
                "ActiveState",
                "SubState",
                "Result",
                "ExecMainCode",
                "ExecMainStatus",
            )
        },
        "archive": terminal and age >= minimum_age_seconds,
    }


def _archived_job_receipt(
    unit: str,
    jobs_root: Path,
    archive_root: Path,
) -> dict[str, Any] | None:
    if not JOB_UNIT.fullmatch(unit):
        raise RuntimeError("archived job lookup requires a typed job unit")
    job_name = unit.removesuffix(".service")
    destination = archive_root / job_name
    if not destination.exists() and not destination.is_symlink():
        return None
    if archive_root.is_symlink():
        raise RuntimeError("archive root may not be a symlink")
    directory = _private_directory(destination)
    resolved_root = _private_directory(archive_root)
    if directory.parent != resolved_root:
        raise RuntimeError(f"archived job escaped archive root: {job_name}")
    manifest, _ = _read_json_file(directory / "archive-manifest.json")
    expected_keys = {
        "schema_version",
        "unit",
        "job_name",
        "source",
        "archived_at_unix",
        "plan_sha256",
        "terminal_evidence",
        "files",
        "manifest_sha256",
    }
    if set(manifest) != expected_keys or manifest.get("schema_version") != 1:
        raise RuntimeError(f"archive manifest shape is invalid: {job_name}")
    if (
        manifest.get("unit") != unit
        or manifest.get("job_name") != job_name
        or manifest.get("source") != str(jobs_root / job_name)
    ):
        raise RuntimeError(f"archive manifest identity is invalid: {job_name}")
    archived_at = manifest.get("archived_at_unix")
    terminal_evidence = manifest.get("terminal_evidence")
    plan_sha256 = manifest.get("plan_sha256")
    if (
        isinstance(archived_at, bool)
        or not isinstance(archived_at, int)
        or archived_at < 0
        or not isinstance(terminal_evidence, str)
        or not terminal_evidence
        or not isinstance(plan_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", plan_sha256)
    ):
        raise RuntimeError(f"archive manifest evidence is invalid: {job_name}")
    digest = manifest.get("manifest_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError(f"archive manifest digest is invalid: {job_name}")
    material = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if _sha256(material) != digest:
        raise RuntimeError(f"archive manifest hash mismatch: {job_name}")
    files = manifest.get("files")
    if not isinstance(files, list) or files != _archive_file_manifest(directory):
        raise RuntimeError(f"archived job file manifest mismatch: {job_name}")
    return {
        "unit": unit,
        "job_name": job_name,
        "manifest_sha256": digest,
        "destination": str(directory),
    }


class _PinnedRetentionPlan(dict):
    """A plan with in-process root custody; JSON rehydration never grants it.

    This closes only descriptors owned by this plan, not externally supplied
    descriptors. A copied/rehashed plain dictionary deliberately loses custody.
    """

    jobs_fd: int = -1
    archive_fd: int = -1
    archive_parent_fd: int = -1
    receipt_fd: int = -1
    receipt_parent_fd: int = -1
    authorized_sha256: str | None = None

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        from copy import deepcopy
        return deepcopy(dict(self), memo)

    def __del__(self) -> None:
        for field in (
            "jobs_fd", "archive_fd", "archive_parent_fd",
            "receipt_fd", "receipt_parent_fd",
        ):
            descriptor = getattr(self, field, -1)
            if isinstance(descriptor, int) and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, field, -1)


def build_plan(
    *,
    minimum_job_age_seconds: int = 86_400,
    max_archive_jobs: int = MAX_ARCHIVE_JOBS_PER_PLAN,
    now: int | None = None,
    jobs_root: Path = JOBS_ROOT,
    archive_root: Path = ARCHIVE_ROOT,
    receipt_root: Path = RECEIPT_ROOT,
    task_db: Path = TASK_DB,
    worker_db: Path = WORKER_DB,
    resource_db: Path = RESOURCE_DB,
    failed_units: list[str] | None = None,
    unit_states: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    if (
        isinstance(minimum_job_age_seconds, bool)
        or not 0 <= minimum_job_age_seconds <= 31_536_000
    ):
        raise ValueError("minimum_job_age_seconds must be between 0 and 31536000")
    if (
        isinstance(max_archive_jobs, bool)
        or not 1 <= max_archive_jobs <= MAX_ARCHIVE_JOBS_PER_PLAN
    ):
        raise ValueError(
            f"max_archive_jobs must be between 1 and {MAX_ARCHIVE_JOBS_PER_PLAN}"
        )
    # Keep the authentic file descriptors with the plan object until apply.
    # The serializable plan SHA is drift detection, never root authority.
    pinned = _PinnedRetentionPlan()
    pinned.jobs_fd = _archive_open_private_root(jobs_root)
    root_stat = os.fstat(pinned.jobs_fd)
    planned_jobs_root_identity = (root_stat.st_dev, root_stat.st_ino)
    jobs_root = _private_directory(jobs_root)
    _archive_require_unchanged_root(jobs_root, pinned.jobs_fd)
    if archive_root.is_symlink() or receipt_root.is_symlink():
        raise RuntimeError("retention output roots may not be symlinks")
    pinned.archive_parent_fd = _archive_open_private_root(archive_root.parent)
    _archive_require_unchanged_root(archive_root.parent, pinned.archive_parent_fd)
    try:
        pinned.archive_fd = os.open(
            archive_root.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=pinned.archive_parent_fd,
        )
    except FileNotFoundError:
        pinned.archive_fd = -1
    else:
        archive_stat = os.fstat(pinned.archive_fd)
        if (
            not stat.S_ISDIR(archive_stat.st_mode)
            or archive_stat.st_uid != os.getuid()
            or stat.S_IMODE(archive_stat.st_mode) & 0o077
        ):
            raise RuntimeError("retention archive root is not private")
        _archive_require_unchanged_root(archive_root, pinned.archive_fd)
    pinned.receipt_parent_fd = _archive_open_private_root(receipt_root.parent)
    _archive_require_unchanged_root(receipt_root.parent, pinned.receipt_parent_fd)
    try:
        pinned.receipt_fd = _archive_open_child_root(
            pinned.receipt_parent_fd, receipt_root.name, receipt_root
        )
    except FileNotFoundError:
        pinned.receipt_fd = -1
    else:
        _archive_require_unchanged_root(receipt_root, pinned.receipt_fd)
    observed_now = int(time.time()) if now is None else now
    failed = _failed_units() if failed_units is None else sorted(set(failed_units))
    if len(failed) > MAX_FAILED_UNITS:
        raise RuntimeError("failed-unit inventory exceeds the bounded scan")

    registry_entries: list[Path] = []
    with os.scandir(pinned.jobs_fd) as scan:
        for discovered_count, child in enumerate(scan, start=1):
            if discovered_count > MAX_JOB_REGISTRY_ENTRIES:
                raise RuntimeError("job registry exceeds the bounded discovery limit")
            if child.name.startswith("grabowski-job-"):
                registry_entries.append(jobs_root / child.name)
    registry_entries.sort(key=lambda entry: entry.name)
    # A missing index is not positive evidence that no deployment is active.
    # Keep archive and job-reset actions out of the plan until the deployment
    # owner has recovered its canonical registry; other independent classes
    # of maintenance may continue without producing partial receipt storms.
    index_root_stat = os.fstat(pinned.jobs_fd)
    if (index_root_stat.st_dev, index_root_stat.st_ino) != planned_jobs_root_identity:
        raise RuntimeError("jobs root identity changed before plan index read")
    deploy_index = _archive_read_deploy_index_pinned(
        jobs_root, pinned.jobs_fd, None
    )
    _archive_require_unchanged_root(jobs_root, pinned.jobs_fd)
    missing_deploy_index = deploy_index is None
    pending_deploy_job = (
        deploy_index["pending_unit"] if deploy_index is not None else None
    )
    primary_entries = registry_entries[:MAX_JOB_SCAN_ENTRIES]
    failed_job_names = {
        unit.removesuffix(".service")
        for unit in failed
        if JOB_UNIT.fullmatch(unit)
    }
    selected_by_name = {entry.name: entry for entry in primary_entries}
    for entry in registry_entries[MAX_JOB_SCAN_ENTRIES:]:
        if entry.name in failed_job_names:
            selected_by_name[entry.name] = entry
    entries = sorted(selected_by_name.values(), key=lambda entry: entry.name)
    job_scan_truncated = len(registry_entries) > len(entries)
    job_scan_deferred_count = len(registry_entries) - len(entries)
    typed_entries = [entry for entry in entries if JOB_NAME.fullmatch(entry.name)]
    job_units = [entry.name + ".service" for entry in typed_entries]
    worker_units = [unit for unit in failed if WORKER_UNIT.fullmatch(unit)]
    observed_units = sorted(set(job_units + worker_units))
    states = _systemd_unit_states(observed_units) if unit_states is None else unit_states
    missing_states = sorted(set(observed_units) - set(states))
    if missing_states:
        raise RuntimeError(
            f"job-state inventory omitted units: {', '.join(missing_states[:5])}"
        )

    blocked: list[dict[str, str]] = []
    blocked_keys: set[tuple[str, str]] = set()

    def block(unit: str, reason: str) -> None:
        key = (unit, reason)
        if key not in blocked_keys:
            blocked_keys.add(key)
            blocked.append({"unit": unit, "reason": reason})

    records: list[dict[str, Any]] = []
    records_by_unit: dict[str, dict[str, Any]] = {}
    protected_nonterminal: list[dict[str, str]] = []
    for entry in entries:
        if not JOB_NAME.fullmatch(entry.name):
            block(entry.name, "legacy job registry name is outside the typed contract")
            continue
        unit = entry.name + ".service"
        try:
            entry_stat = os.stat(
                entry.name, dir_fd=pinned.jobs_fd, follow_symlinks=False
            )
        except OSError:
            block(unit, "job registry entry is missing from the pinned root")
            continue
        if not stat.S_ISDIR(entry_stat.st_mode):
            block(unit, "job registry entry is not a real directory")
            continue
        try:
            record = _job_record(
                unit,
                jobs_root,
                now=observed_now,
                minimum_age_seconds=minimum_job_age_seconds,
                systemd_state=states[unit],
                jobs_root_fd=pinned.jobs_fd,
            )
        except RuntimeError as exc:
            block(unit, str(exc))
            continue
        records.append(record)
        records_by_unit[unit] = record
        if not record["terminal"]:
            protected_nonterminal.append({
                "unit": unit,
                "reason": record["terminal_evidence"],
                "active_state": record["systemd_state"]["ActiveState"],
            })

    eligible = sorted(
        (record for record in records if record["archive"]),
        key=lambda record: (record["created_at_unix"], record["unit"]),
    )
    archive_candidates: list[dict[str, Any]] = []
    archive_blocked_units: set[str] = set()
    for record in eligible:
        if missing_deploy_index:
            archive_blocked_units.add(record["unit"])
            block(record["unit"], "canonical deployment index absent; explicit recovery required")
            continue
        if record["job_name"] == pending_deploy_job:
            archive_blocked_units.add(record["unit"])
            block(record["unit"], "pending deployment reservation blocks archive")
            continue
        if record["job_name"] in deploy_index["units"]:
            # Retention cannot atomically compare-and-replace an existing
            # canonical index inode in the face of a same-UID writer. Leave
            # indexed archives for explicit deployment-owner reconciliation;
            # independently safe jobs in the same batch still proceed.
            archive_blocked_units.add(record["unit"])
            block(record["unit"], "indexed deployment requires manual archival recovery")
            continue
        destination = archive_root / record["job_name"]
        if pinned.archive_fd >= 0:
            try:
                os.stat(
                    record["job_name"], dir_fd=pinned.archive_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                archive_blocked_units.add(record["unit"])
                block(record["unit"], "archive destination already exists")
                continue
        try:
            source_dir = jobs_root / record["job_name"]
            _archive_file_shape_preflight(
                source_dir, jobs_root_fd=pinned.jobs_fd
            )
            # The future archive-manifest publication must be possible for
            # this source. A blocked job must not starve the whole batch.
            source_fd = _archive_open_child_root(
                pinned.jobs_fd, source_dir.name, source_dir
            )
            try:
                _archive_require_json_temp_capacity(source_fd)
                _archive_require_child_bound(
                    pinned.jobs_fd, source_dir.name, source_fd, source_dir
                )
            finally:
                os.close(source_fd)
        except (RuntimeError, OSError) as exc:
            archive_blocked_units.add(record["unit"])
            block(record["unit"], f"archive source preflight blocked: {exc}")
            continue
        archive_candidates.append(record)
    archive_jobs = archive_candidates[:max_archive_jobs]
    archive_deferred_count = max(0, len(archive_candidates) - len(archive_jobs))

    selected_archive_units = {record["unit"] for record in archive_jobs}
    reset_units: list[str] = []
    deferred_failed_units: list[dict[str, str]] = []
    recovered_archived_failed_units: list[dict[str, Any]] = []
    worker_reset_evidence: list[dict[str, Any]] = []
    for unit in failed:
        if JOB_UNIT.fullmatch(unit):
            if missing_deploy_index:
                block(unit, "canonical deployment index absent; explicit recovery required")
                continue
            if unit.removesuffix(".service") == pending_deploy_job:
                block(unit, "pending deployment reservation blocks reset")
                continue
            record = records_by_unit.get(unit)
            if record is None:
                try:
                    recovered = _archived_job_receipt(
                        unit,
                        jobs_root,
                        archive_root,
                    )
                except RuntimeError as exc:
                    block(unit, str(exc))
                    continue
                if recovered is None:
                    block(unit, "failed job has no valid registry or archive record")
                    continue
                recovered_archived_failed_units.append(recovered)
                # A historical self-hashed manifest is diagnostic evidence,
                # not authority for a reset after an interrupted move. Never
                # enqueue this unit as a retryable automatic reset: it has
                # no live source to revalidate and would exhaust the finite
                # partial-receipt chain on every periodic invocation.
                block(unit, "archived failed job requires manual recovery before reset")
                continue
            if not record["terminal"]:
                block(unit, "failed job terminality is not proven")
                continue
            if unit in archive_blocked_units:
                continue
            if record["archive"] and unit not in selected_archive_units:
                deferred_failed_units.append({
                    "unit": unit,
                    "reason": "archive deferred by bounded batch",
                })
                continue
            # Configured archive ages may exceed one day, but a failed job
            # already beyond the intrinsic safe-reset age must remain failed
            # until it is actually archive-eligible. Otherwise a legitimate
            # long retention configuration creates an endlessly failing
            # apply/reset receipt, or a self-hashed plan can widen the age.
            if (
                not record["archive"]
                and observed_now - record["created_at_unix"] >= 86_400
            ):
                block(unit, "failed job awaits configured archive age before reset")
                continue
            reset_units.append(unit)
            continue
        if TASK_UNIT.fullmatch(unit):
            state = _task_state(unit, task_db)
            if state in TERMINAL_TASK_STATES:
                reset_units.append(unit)
            else:
                block(unit, f"task state is not proven terminal: {state}")
            continue
        if WORKER_UNIT.fullmatch(unit):
            try:
                evidence = _worker_reset_evidence(
                    unit,
                    worker_db=worker_db,
                    resource_db=resource_db,
                    now=observed_now,
                    systemd_state=states[unit],
                )
            except RuntimeError as exc:
                block(unit, str(exc))
                continue
            worker_reset_evidence.append(evidence)
            reset_units.append(unit)
            continue
        block(unit, "unit class has no retention contract")

    material = {
        "schema_version": 3,
        "minimum_job_age_seconds": minimum_job_age_seconds,
        "max_archive_jobs": max_archive_jobs,
        "jobs_root": str(jobs_root),
        "jobs_root_identity": list(planned_jobs_root_identity),
        "archive_root": str(archive_root),
        "receipt_root": str(receipt_root),
        "task_db": str(task_db),
        "worker_db": str(worker_db),
        "resource_db": str(resource_db),
        "job_registry_entry_count": len(registry_entries),
        "job_scan_count": len(entries),
        "job_scan_truncated": job_scan_truncated,
        "job_scan_deferred_count": job_scan_deferred_count,
        "archive_inventory_complete": not job_scan_truncated,
        "archive_eligible_count": len(eligible),
        "archive_deferred_count": archive_deferred_count,
        "protected_nonterminal_jobs": sorted(
            protected_nonterminal,
            key=lambda item: item["unit"],
        ),
        "recovered_archived_failed_units": sorted(
            recovered_archived_failed_units,
            key=lambda item: item["unit"],
        ),
        "deferred_failed_units": sorted(
            deferred_failed_units,
            key=lambda item: item["unit"],
        ),
        "reset_failed_units": sorted(set(reset_units)),
        "worker_reset_evidence": sorted(
            worker_reset_evidence,
            key=lambda item: item["unit"],
        ),
        "archive_jobs": archive_jobs,
        "blocked": sorted(blocked, key=lambda item: (item["unit"], item["reason"])),
    }
    pinned.update({**material, "plan_sha256": _sha256(material)})
    pinned.authorized_sha256 = pinned["plan_sha256"]
    return pinned


def _archive_file_manifest_on_fd(directory: Path, fd: int) -> list[dict[str, Any]]:
    """Hash files below the previously opened job directory, never by a new path."""
    files: list[dict[str, Any]] = []
    for path in _archive_bounded_entries(directory, fd):
        metadata = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if _archive_internal_manifest_entry(path, metadata=metadata):
            continue
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"archive source contains a symlink: {path}")
        if stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError(f"archive source contains nested directory: {path}")
        if len(files) >= MAX_ARCHIVE_FILES:
            raise RuntimeError("archive source exceeds the file-count bound")
        size, digest = _archive_private_file_digest(
            fd, path, max_bytes=MAX_ARCHIVE_FILE_BYTES
        )
        files.append({"path": path.name, "bytes": size, "sha256": digest})
    return files


def _archive_file_manifest(directory: Path) -> list[dict[str, Any]]:
    fd = _archive_open_private_root(directory)
    try:
        result = _archive_file_manifest_on_fd(directory, fd)
        _archive_require_unchanged_root(directory, fd)
        return result
    finally:
        os.close(fd)


def _archive_require_pinned_identity(
    directory: Path, expected_identity: tuple[int, int]
) -> None:
    """Reject same-UID source replacement even with identical file bytes."""
    fd = _archive_open_private_root(directory)
    try:
        metadata = os.fstat(fd)
        if (metadata.st_dev, metadata.st_ino) != expected_identity:
            raise RuntimeError(f"archive source identity changed: {directory}")
        _archive_require_unchanged_root(directory, fd)
    finally:
        os.close(fd)


def _archive_rename_noreplace(
    source_fd: int, source_name: str, destination_fd: int, destination_name: str
) -> None:
    """Linux atomic rename without silently unlinking an existing archive slot."""
    try:
        syscall = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise RuntimeError("renameat2(NO_REPLACE) is unavailable") from exc
    syscall.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    ]
    syscall.restype = ctypes.c_int
    ctypes.set_errno(0)
    if syscall(
        source_fd, os.fsencode(source_name),
        destination_fd, os.fsencode(destination_name), 1,
    ) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(
                code, "archive destination already exists", destination_name
            )
        raise OSError(code, os.strerror(code), destination_name)


def _archive_rename_exchange(
    directory_fd: int, incoming_name: str, target_name: str
) -> None:
    """Atomically exchange two entries without deleting the displaced inode."""
    try:
        syscall = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise RuntimeError("renameat2(EXCHANGE) is unavailable") from exc
    syscall.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    ]
    syscall.restype = ctypes.c_int
    ctypes.set_errno(0)
    if syscall(
        directory_fd, os.fsencode(incoming_name),
        directory_fd, os.fsencode(target_name), 2,
    ) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), target_name)




def _archive_quarantine_mismatched_move(
    archive_fd: int, name: str, observed_identity: tuple[int, int]
) -> None:
    """Fail closed: Linux has no atomic rename-if-inode primitive.

    Quarantining a same-UID-controlled basename by check-then-rename can move
    genuine evidence if a peer swaps the entry between stat and renameat2.
    Preserve all directory entries and require an explicit recovery decision.
    """
    try:
        current = os.stat(name, dir_fd=archive_fd, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(
            "unverified archive basename disappeared; manual recovery required"
        ) from exc
    if (current.st_dev, current.st_ino) != observed_identity:
        raise RuntimeError(
            "unverified archive basename changed; manual recovery required"
        )
    raise RuntimeError(
        "unverified archive basename cannot be quarantined atomically; "
        "manual recovery required"
    )

def _archive_move_job_pinned(
    source: Path,
    destination: Path,
    *,
    source_identity: tuple[int, int],
    jobs_root_identity: tuple[int, int],
    archive_root_identity: tuple[int, int],
    expected_files: list[dict[str, Any]],
    jobs_root_fd: int | None = None,
    archive_root_fd: int | None = None,
) -> None:
    """Verify the inode before moving; no overwrite, quarantine wrong children."""
    jobs_fd = (
        os.dup(jobs_root_fd) if jobs_root_fd is not None
        else _archive_open_private_root(source.parent)
    )
    try:
        archive_fd = (
            os.dup(archive_root_fd) if archive_root_fd is not None
            else _archive_open_private_root(destination.parent)
        )
        try:
            for directory, fd, identity in (
                (source.parent, jobs_fd, jobs_root_identity),
                (destination.parent, archive_fd, archive_root_identity),
            ):
                metadata = os.fstat(fd)
                if (metadata.st_dev, metadata.st_ino) != identity:
                    raise RuntimeError(f"archive root identity changed: {directory}")
                _archive_require_unchanged_root(directory, fd)
            if jobs_root_fd is None:
                _archive_require_pinned_identity(source, source_identity)
            # Narrow the basename-swap window with one final openat/fstat.
            source_fd = os.open(
                source.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=jobs_fd,
            )
            try:
                source_metadata = os.fstat(source_fd)
                if (source_metadata.st_dev, source_metadata.st_ino) != source_identity:
                    raise RuntimeError(f"archive source inode changed: {source}")
            finally:
                os.close(source_fd)
            try:
                os.stat(destination.name, dir_fd=archive_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError(f"archive destination appeared before move: {destination}")
            _archive_rename_noreplace(
                jobs_fd, source.name, archive_fd, destination.name,
            )
            # Keep the exact moved inode open until all post-move hashes and
            # parent checks complete. No pathname-based archive remanifest.
            try:
                moved_fd = os.open(
                    destination.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=archive_fd,
                )
            except OSError as exc:
                try:
                    wrong = os.stat(
                        destination.name, dir_fd=archive_fd, follow_symlinks=False
                    )
                except OSError:
                    raise RuntimeError(
                        f"archive basename vanished after move: {destination}"
                    ) from exc
                if (wrong.st_dev, wrong.st_ino) != source_identity:
                    _archive_quarantine_mismatched_move(
                        archive_fd, destination.name,
                        (wrong.st_dev, wrong.st_ino),
                    )
                raise RuntimeError(
                    f"archive destination is not the moved private job: {destination}"
                ) from exc
            try:
                moved = os.fstat(moved_fd)
                if (moved.st_dev, moved.st_ino) != source_identity:
                    _archive_quarantine_mismatched_move(
                        archive_fd, destination.name,
                        (moved.st_dev, moved.st_ino),
                    )
                    raise RuntimeError(
                        f"archived job identity changed during move: {destination}"
                    )
                os.fsync(jobs_fd)
                os.fsync(archive_fd)
                _archive_require_unchanged_root(source.parent, jobs_fd)
                _archive_require_unchanged_root(destination.parent, archive_fd)
                if _archive_file_manifest_on_fd(destination, moved_fd) != expected_files:
                    raise RuntimeError(
                        f"archived job files changed during move: {source.name}"
                    )
                _archive_require_unchanged_root(source.parent, jobs_fd)
                _archive_require_unchanged_root(destination.parent, archive_fd)
                # A verified, still-open inode is not sufficient if another
                # writer detached that inode from the published archive name.
                current = os.stat(
                    destination.name, dir_fd=archive_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != source_identity:
                    _archive_quarantine_mismatched_move(
                        archive_fd, destination.name,
                        (current.st_dev, current.st_ino),
                    )
                    raise RuntimeError(
                        f"archive basename changed after hashing: {destination}"
                    )
            finally:
                os.close(moved_fd)

        finally:
            os.close(archive_fd)
    finally:
        os.close(jobs_fd)



def _archive_pinned_json_preimage(
    directory_fd: int, name: str, *, max_bytes: int = MAX_JSON_BYTES
) -> tuple[bytes, tuple[int, int, int, int, str]]:
    """Read private JSON bytes and their inode/digest through a pinned root."""
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > max_bytes
        ):
            raise RuntimeError("pinned JSON index must be one private regular file")
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(
                descriptor, min(64 * 1024, max_bytes + 1 - len(data))
            )
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > max_bytes:
            raise RuntimeError("pinned JSON index exceeds its size bound")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise RuntimeError("pinned JSON index changed during read")
        on_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (on_path.st_dev, on_path.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("pinned JSON index basename changed during read")
        contents = bytes(data)
        return contents, (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, hashlib.sha256(contents).hexdigest(),
        )
    finally:
        os.close(descriptor)


def _archive_require_json_temp_capacity(directory_fd: int) -> None:
    """Refuse an irreversible move when the future index write lacks space.

    Count EVERY retained JSON temp in this pinned directory. Same-UID
    substitutions are never silently unlinked; the bound is fail-closed.
    """
    retained_temps = 0
    scanned_entries = 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            scanned_entries += 1
            if scanned_entries > MAX_JOB_REGISTRY_ENTRIES:
                raise RuntimeError("retained atomic temp scan bound exceeded")
            if re.fullmatch(
                r"\..+\.[1-9][0-9]{0,11}\.[1-9][0-9]{0,19}\.tmp",
                entry.name,
            ):
                retained_temps += 1
                if retained_temps >= MAX_RETAINED_JSON_TEMPS:
                    raise RuntimeError("retained atomic temp bound exceeded")


def _archive_restore_exchanged_target(
    directory_fd: int, temp_name: str, target_name: str, *,
    incoming_identity: tuple[int, int], displaced_identity: tuple[int, int],
) -> None:
    """Try to undo a mismatched EXCHANGE without deleting displaced evidence.

    This is recovery, not an inode-conditional CAS primitive. A hostile writer
    able to race the reverse exchange still requires fail-closed handling.
    """
    try:
        published = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        displaced = os.stat(temp_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            (published.st_dev, published.st_ino) != incoming_identity
            or (displaced.st_dev, displaced.st_ino) != displaced_identity
        ):
            raise RuntimeError("exchange recovery identities changed; manual recovery required")
        _archive_rename_exchange(directory_fd, temp_name, target_name)
        os.fsync(directory_fd)
        restored = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        retained = os.stat(temp_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            (restored.st_dev, restored.st_ino) != displaced_identity
            or (retained.st_dev, retained.st_ino) != incoming_identity
        ):
            raise RuntimeError("exchange recovery raced; manual recovery required")
    except OSError as exc:
        raise RuntimeError("exchange recovery failed; manual recovery required") from exc


def _write_json_atomic(
    path: Path,
    payload: dict[str, Any],
    *,
    replace_existing: bool = False,
    expected_parent_identity: tuple[int, int] | None = None,
    expected_existing_preimage: tuple[int, int, int, int, str] | None = None,
    pinned_parent_fd: int | None = None,
) -> Path:
    if path.name == "runtime-deploy-index.json":
        # Linux has no atomic rename-if-inode. An EXCHANGE followed by a
        # post-check can briefly publish a stale canonical deployment index.
        # Only the deployment owner may write this control-plane record.
        raise RuntimeError("retention may not publish deployment index")
    parent = (
        path.parent if pinned_parent_fd is not None
        else _private_directory(path.parent, create=True)
    )
    path = parent / path.name
    # All writes and exchanges are relative to the authenticated directory FD.
    # The caller-owned FD is duplicated so a failed write cannot close custody.
    directory_fd = (
        os.dup(pinned_parent_fd) if pinned_parent_fd is not None
        else _archive_open_private_root(parent)
    )
    temporary_name: str | None = None
    try:
        if expected_parent_identity is not None:
            metadata = os.fstat(directory_fd)
            if (metadata.st_dev, metadata.st_ino) != expected_parent_identity:
                raise RuntimeError(f"archive source identity changed: {parent}")
        _archive_require_unchanged_root(parent, directory_fd)
        try:
            existing = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (
                not stat.S_ISREG(existing.st_mode)
                or existing.st_nlink != 1
                or existing.st_uid != os.getuid()
                or stat.S_IMODE(existing.st_mode) & 0o077
                or (replace_existing and existing.st_size > MAX_JSON_BYTES)
            ):
                raise RuntimeError(f"existing evidence is not owner-controlled: {path}")
            if not replace_existing:
                raise FileExistsError(f"retention evidence already exists: {path}")
        if expected_existing_preimage is not None:
            if not replace_existing or existing is None:
                raise RuntimeError("runtime deploy index snapshot changed before update")
            try:
                _, verified = _archive_pinned_json_preimage(
                    directory_fd, path.name
                )
            except OSError as exc:
                raise RuntimeError("runtime deploy index identity changed before update") from exc
            if verified != expected_existing_preimage:
                raise RuntimeError("runtime deploy index snapshot changed before update")
        data = (
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
            + b"\n"
        )
        _archive_require_json_temp_capacity(directory_fd)
        _archive_require_unchanged_root(parent, directory_fd)
        candidate_name = f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        descriptor = os.open(
            candidate_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        # Only unlink an actually created temp. O_EXCL failure must preserve
        # an existing private file, even if an attacker predicts the name.
        temporary_name = candidate_name
        try:
            incoming = os.fstat(descriptor)
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _archive_require_unchanged_root(parent, directory_fd)
        if replace_existing and existing is not None:
            if expected_existing_preimage is not None:
                # A peer can replace the index AFTER the initial validated
                # read and before publication. Revalidate against that exact
                # authenticated inode+content, not merely a new private inode.
                try:
                    _, verified = _archive_pinned_json_preimage(
                        directory_fd, path.name
                    )
                except OSError as exc:
                    raise RuntimeError(
                        "runtime deploy index identity changed before exchange"
                    ) from exc
                if verified != expected_existing_preimage:
                    raise RuntimeError(
                        "runtime deploy index snapshot changed before exchange"
                    )
            # os.replace would silently delete a foreign index/manifest
            # swapped into this pathname after the earlier stat. Linux offers
            # no rename-if-inode; exchange the two entries atomically instead.
            # Even on success retain the displaced private prior revision:
            # unlink(temp_name) is itself vulnerable to same-UID replacement.
            _archive_rename_exchange(directory_fd, temporary_name, path.name)
            try:
                published = os.stat(
                    path.name, dir_fd=directory_fd, follow_symlinks=False
                )
                displaced = os.stat(
                    temporary_name, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError as exc:
                raise RuntimeError(
                    "atomic replacement identity unavailable; manual recovery required"
                ) from exc
            changed = (
                (published.st_dev, published.st_ino) !=
                (incoming.st_dev, incoming.st_ino)
                or (displaced.st_dev, displaced.st_ino) !=
                (existing.st_dev, existing.st_ino)
                or displaced.st_size != existing.st_size
                or displaced.st_mtime_ns != existing.st_mtime_ns
            )
            if not changed and expected_existing_preimage is not None:
                # Also catch in-place changes of a pinned preimage; fstat
                # identity, size and mtime alone are not a content proof.
                try:
                    _, displaced_preimage = _archive_pinned_json_preimage(
                        directory_fd, temporary_name
                    )
                except OSError:
                    changed = True
                else:
                    changed = displaced_preimage != expected_existing_preimage
            if changed:
                # No pathname may be unlinked. Restore the displaced inode
                # when both exchange participants are still identifiable.
                # If another peer races the restoration, retain all evidence
                # and require explicit manual recovery.
                _archive_restore_exchanged_target(
                    directory_fd, temporary_name, path.name,
                    incoming_identity=(incoming.st_dev, incoming.st_ino),
                    displaced_identity=(displaced.st_dev, displaced.st_ino),
                )
                raise RuntimeError(
                    "atomic replacement target identity changed; prior canonical restored"
                )
        else:
            # Even replace_existing=True may NOT clobber a target that was
            # absent during the earlier pinned-dirfd observation.
            _archive_rename_noreplace(
                directory_fd, temporary_name, directory_fd, path.name
            )
            temporary_name = None
        os.fsync(directory_fd)
        _archive_require_unchanged_root(parent, directory_fd)
    finally:
        # Never unlink a temporary pathname: after failed publication it may
        # belong to a racing same-UID peer, and after a successful exchange it
        # intentionally retains the prior target inode for exact recovery.
        os.close(directory_fd)
    return path


def _reset_failed(unit: str) -> dict[str, Any]:
    if not (
        JOB_UNIT.fullmatch(unit)
        or TASK_UNIT.fullmatch(unit)
        or WORKER_UNIT.fullmatch(unit)
    ):
        raise RuntimeError(f"retention reset unit is outside the typed contract: {unit}")
    result = _run(["systemctl", "--user", "reset-failed", unit])
    return {
        "unit": unit,
        "returncode": result.returncode,
        "stderr_sha256": hashlib.sha256(
            result.stderr.encode("utf-8", errors="replace")
        ).hexdigest(),
    }


def _redacted_reset_failure(
    *, unit: str, stage: str, error: BaseException
) -> dict[str, str]:
    if stage not in {"worker_revalidation", "reset_command", "deployment_index_recovery"}:
        raise RuntimeError("retention reset failure stage is invalid")
    return {
        "unit": unit,
        "stage": stage,
        "error_type": type(error).__name__,
        "error_sha256": hashlib.sha256(
            str(error).encode("utf-8", errors="replace")
        ).hexdigest(),
    }


def _validated_plan(plan: dict[str, Any], expected_plan_sha256: str) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise RuntimeError("retention plan is not an object")
    actual = plan.get("plan_sha256")
    if not isinstance(actual, str) or not re.fullmatch(r"[0-9a-f]{64}", actual):
        raise RuntimeError("retention plan hash is invalid")
    material = {key: value for key, value in plan.items() if key != "plan_sha256"}
    if _sha256(material) != actual or expected_plan_sha256 != actual:
        raise RuntimeError("retention plan hash mismatch")
    # A self-hash is drift evidence, not a credential. Detached/rehashed plans
    # never authorize filesystem moves or systemd reset effects.
    if (
        not isinstance(plan, _PinnedRetentionPlan)
        or plan.authorized_sha256 != actual
        or plan.jobs_fd < 0
        or plan.archive_parent_fd < 0
        or plan.receipt_parent_fd < 0
    ):
        raise RuntimeError("retention plan lacks trusted in-process root custody")
    if plan.get("schema_version") != 3:
        raise RuntimeError("retention plan schema is unsupported")
    jobs_identity = plan.get("jobs_root_identity")
    if (
        not isinstance(jobs_identity, list)
        or len(jobs_identity) != 2
        or any(type(value) is not int or value < 0 for value in jobs_identity)
    ):
        raise RuntimeError("retention plan jobs root identity is invalid")
    minimum_job_age_seconds = plan.get("minimum_job_age_seconds")
    if type(minimum_job_age_seconds) is not int or not 0 <= minimum_job_age_seconds <= 31_536_000:
        raise RuntimeError("retention plan age bound is invalid")
    max_archive_jobs = plan.get("max_archive_jobs")
    if (
        isinstance(max_archive_jobs, bool)
        or not isinstance(max_archive_jobs, int)
        or not 1 <= max_archive_jobs <= MAX_ARCHIVE_JOBS_PER_PLAN
    ):
        raise RuntimeError("retention plan archive bound is invalid")
    reset_units = plan.get("reset_failed_units")
    archive_jobs = plan.get("archive_jobs")
    worker_evidence = plan.get("worker_reset_evidence")
    if (
        not isinstance(reset_units, list)
        or not isinstance(archive_jobs, list)
        or not isinstance(worker_evidence, list)
    ):
        raise RuntimeError("retention plan action lists are invalid")
    if len(reset_units) != len(set(reset_units)):
        raise RuntimeError("retention plan contains duplicate reset units")
    if len(archive_jobs) > max_archive_jobs:
        raise RuntimeError("retention plan exceeds its archive batch bound")
    for unit in reset_units:
        if not isinstance(unit, str) or not (
            JOB_UNIT.fullmatch(unit)
            or TASK_UNIT.fullmatch(unit)
            or WORKER_UNIT.fullmatch(unit)
        ):
            raise RuntimeError("retention plan contains an invalid reset unit")
    if not isinstance(plan.get("worker_db"), str) or not plan["worker_db"]:
        raise RuntimeError("retention plan worker database path is invalid")
    if not isinstance(plan.get("resource_db"), str) or not plan["resource_db"]:
        raise RuntimeError("retention plan resource database path is invalid")
    evidence_units: list[str] = []
    expected_worker_keys = {
        "unit",
        "worker_id",
        "kind",
        "worker_record_sha256",
        "declared_lease_keys",
        "systemd_state",
        "terminal_evidence",
    }
    for evidence in worker_evidence:
        if not isinstance(evidence, dict) or set(evidence) != expected_worker_keys:
            raise RuntimeError("retention plan worker evidence shape is invalid")
        unit = evidence.get("unit")
        match = WORKER_UNIT.fullmatch(unit) if isinstance(unit, str) else None
        if match is None:
            raise RuntimeError("retention plan worker evidence unit is invalid")
        if (
            evidence.get("kind") != match.group(1)
            or evidence.get("worker_id") != match.group(2)
            or not isinstance(evidence.get("worker_record_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", evidence["worker_record_sha256"]) is None
            or evidence.get("terminal_evidence")
            != "worker_db_and_systemd_failed_without_live_leases"
            or not isinstance(evidence.get("declared_lease_keys"), list)
            or not isinstance(evidence.get("systemd_state"), dict)
            or evidence["systemd_state"].get("Id") != unit
            or evidence["systemd_state"].get("ActiveState") != "failed"
        ):
            raise RuntimeError("retention plan worker evidence binding is invalid")
        evidence_units.append(unit)
    if len(evidence_units) != len(set(evidence_units)):
        raise RuntimeError("retention plan contains duplicate worker evidence")
    reset_worker_units = sorted(
        unit for unit in reset_units if isinstance(unit, str) and WORKER_UNIT.fullmatch(unit)
    )
    if sorted(evidence_units) != reset_worker_units:
        raise RuntimeError("retention plan worker evidence is not bound to reset units")
    return plan



def _prepare_worker_resets(
    plan: dict[str, Any],
    *,
    units: list[str] | None = None,
) -> None:
    selected = None if units is None else set(units)
    expected = {
        item["unit"]: item
        for item in plan["worker_reset_evidence"]
        if selected is None or item["unit"] in selected
    }
    if not expected:
        return
    states = _systemd_unit_states(sorted(expected))
    now = int(time.time())
    for unit, prior in expected.items():
        current = _worker_reset_evidence(
            unit,
            worker_db=Path(plan["worker_db"]),
            resource_db=Path(plan["resource_db"]),
            now=now,
            systemd_state=states[unit],
        )
        if current != prior:
            raise RuntimeError(f"worker reset evidence drifted before apply: {unit}")

def _prepare_archives(
    plan: dict[str, Any],
    *,
    expected_archive_root_identity: tuple[int, int] | None = None,
    jobs_root_fd: int | None = None,
    archive_root_fd: int | None = None,
    source_pins: ExitStack | None = None,
) -> tuple[Path, Path, Path, list[dict[str, Any]], tuple[int, int]]:
    # Authenticate both roots BEFORE the record/manifest preflight. The old
    # late first open allowed a foreign same-UID tree to become the authority.
    requested_jobs_root = Path(plan["jobs_root"])
    held = isinstance(plan, _PinnedRetentionPlan)
    own_jobs = not held and jobs_root_fd is None
    jobs_pin_fd = (
        jobs_root_fd if jobs_root_fd is not None
        else plan.jobs_fd if held
        else _archive_open_private_root(requested_jobs_root)
    )
    try:
        start_jobs_stat = os.fstat(jobs_pin_fd)
        initial_jobs_identity = (start_jobs_stat.st_dev, start_jobs_stat.st_ino)
        if initial_jobs_identity != tuple(plan["jobs_root_identity"]):
            raise RuntimeError("jobs root identity changed since planning")
        jobs_root = _private_directory(requested_jobs_root)
        _archive_require_unchanged_root(jobs_root, jobs_pin_fd)
    finally:
        if own_jobs:
            os.close(jobs_pin_fd)
    own_archive = not held and archive_root_fd is None
    archive_root = Path(plan["archive_root"])
    archive_pin_fd = (
        archive_root_fd if archive_root_fd is not None
        else _archive_root_fd_for_plan(plan) if held
        else _archive_open_private_root(_private_directory(archive_root, create=True))
    )
    try:
        start_archive_stat = os.fstat(archive_pin_fd)
        initial_archive_identity = (start_archive_stat.st_dev, start_archive_stat.st_ino)
        if (
            expected_archive_root_identity is not None
            and initial_archive_identity != expected_archive_root_identity
        ):
            raise RuntimeError("archive root identity changed before preparation")
        _archive_require_unchanged_root(archive_root, archive_pin_fd)
    finally:
        if own_archive:
            os.close(archive_pin_fd)
    receipt_root = Path(plan["receipt_root"])
    if held:
        _receipt_root_fd_for_plan(plan)
    else:
        receipt_root = _private_directory(receipt_root, create=True)
    archive_records = plan["archive_jobs"]
    prepared: list[dict[str, Any]] = []
    expected_keys = {
        "unit",
        "job_name",
        "created_at_unix",
        "runtime_seconds",
        "metadata_sha256",
        "terminal",
        "terminal_evidence",
        "systemd_state",
        "archive",
    }
    validated_records: list[dict[str, Any]] = []
    units: list[str] = []
    for record in archive_records:
        if not isinstance(record, dict):
            raise RuntimeError("archive job record is not an object")
        if (
            set(record) != expected_keys
            or record.get("archive") is not True
            or record.get("terminal") is not True
        ):
            raise RuntimeError("archive job record shape is invalid")
        unit = record.get("unit")
        job_name = record.get("job_name")
        if (
            not isinstance(unit, str)
            or not JOB_UNIT.fullmatch(unit)
            or unit.removesuffix(".service") != job_name
        ):
            raise RuntimeError("archive job record identity is invalid")
        validated_records.append(record)
        units.append(unit)
    if len(units) != len(set(units)):
        raise RuntimeError("archive job records contain duplicate units")
    fresh_states = _systemd_unit_states(units)
    for record in validated_records:
        unit = record["unit"]
        job_name = record["job_name"]
        fresh_record = _job_record(
            unit,
            jobs_root,
            now=int(time.time()),
            minimum_age_seconds=plan["minimum_job_age_seconds"],
            systemd_state=fresh_states[unit],
            jobs_root_fd=jobs_pin_fd,
        )
        if not fresh_record["terminal"] or not fresh_record["archive"]:
            raise RuntimeError(f"job is no longer archive-eligible: {job_name}")
        if fresh_record["metadata_sha256"] != record["metadata_sha256"]:
            raise RuntimeError(f"job metadata drift before archive: {job_name}")
        source_dir = jobs_root / job_name
        destination = archive_root / job_name
        try:
            os.stat(job_name, dir_fd=archive_pin_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError(f"archive destination appeared before apply: {job_name}")
        # All metadata and file hashes must come from one child of the
        # authenticated jobs-root FD; path ABA cannot change that parent.
        source_fd = _archive_open_child_root(
            jobs_pin_fd, job_name, source_dir
        )
        if source_pins is not None:
            source_pins.callback(os.close, source_fd)
        try:
            # The metadata used for terminal/age authorization must be from
            # THIS source inode. A same-UID peer can rename the basename
            # between the earlier record read and this source open.
            _, metadata_digest = _archive_private_file_digest(
                source_fd, source_dir / "metadata.json",
                max_bytes=MAX_JSON_BYTES,
            )
            if metadata_digest != fresh_record["metadata_sha256"]:
                raise RuntimeError("archive source metadata inode drift before move")
            files = _archive_file_manifest_on_fd(source_dir, source_fd)
            _archive_require_child_bound(
                jobs_pin_fd, job_name, source_fd, source_dir
            )
            source_stat = os.fstat(source_fd)
            source_identity = (source_stat.st_dev, source_stat.st_ino)
        finally:
            if source_pins is None:
                os.close(source_fd)
        prepared.append(
            {
                "record": record,
                "source_dir": source_dir,
                "source_identity": source_identity,
                "destination": destination,
                "files": files,
                **({"source_fd": source_fd} if source_pins is not None else {}),
            }
        )
    # Capture the two root inodes before releasing preflight. The subsequent
    # move must use verified dir_fds, never path-based source/destination roots.
    _archive_require_unchanged_root(jobs_root, jobs_pin_fd)
    _archive_require_unchanged_root(archive_root, archive_pin_fd)
    jobs_stat, archive_stat = os.fstat(jobs_pin_fd), os.fstat(archive_pin_fd)
    jobs_identity = (jobs_stat.st_dev, jobs_stat.st_ino)
    archive_identity = (archive_stat.st_dev, archive_stat.st_ino)
    if jobs_identity != initial_jobs_identity:
        raise RuntimeError("jobs root identity changed during preparation")
    if archive_identity != initial_archive_identity:
        raise RuntimeError("archive root identity changed during preparation")
    for item in prepared:
        item["jobs_root_identity"] = jobs_identity
        item["archive_root_identity"] = archive_identity
    return jobs_root, archive_root, receipt_root, prepared, jobs_identity


def _append_audit_record(record: dict[str, Any]) -> dict[str, Any]:
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    import grabowski_mcp as base

    base._append_audit(record)
    return record


def _append_intent_audit(
    plan: dict[str, Any],
    *,
    attempt: int,
    previous_receipt_sha256: str | None,
) -> dict[str, Any]:
    return _append_audit_record({
        "timestamp_unix": int(time.time()),
        "operation": "runtime-state-retention-intent",
        "plan_sha256": plan["plan_sha256"],
        "attempt": attempt,
        "previous_receipt_sha256": previous_receipt_sha256,
        "reset_failed_count": len(plan["reset_failed_units"]),
        "archive_job_count": len(plan["archive_jobs"]),
        "archive_deferred_count": plan.get("archive_deferred_count", 0),
    })


def _append_completion_audit(receipt: dict[str, Any]) -> dict[str, Any]:
    return _append_audit_record({
        "timestamp_unix": int(time.time()),
        "operation": "runtime-state-retention-complete",
        "plan_sha256": receipt["plan_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "attempt": receipt["attempt"],
        "previous_receipt_sha256": receipt["previous_receipt_sha256"],
        "reset_failed_count": len(receipt["reset_failed"]),
        "reset_failure_count": len(receipt.get("reset_failures", [])),
        "archived_job_count": len(receipt["archived_jobs"]),
        "completed": receipt["completed"],
    })



RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION = (
    "runtime-state-retention-completion-audit-reconciled"
)


def _canonical_retention_receipt_path(
    *,
    plan_sha256: str,
    attempt: int,
    receipt_root: Path | None = None,
) -> Path:
    if re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is None:
        raise RuntimeError("retention reconciliation plan hash is invalid")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt < 1
        or attempt > MAX_RETENTION_RECEIPT_ATTEMPTS
    ):
        raise RuntimeError("retention reconciliation attempt is invalid")
    root = _private_directory(
        RECEIPT_ROOT if receipt_root is None else receipt_root
    )
    name = (
        f"{plan_sha256}.json"
        if attempt == 1
        else f"{plan_sha256}.retry-{attempt:02d}.json"
    )
    return root / name


def _verified_terminal_retention_receipt(
    path: Path,
    *,
    plan_sha256: str,
    attempt: int,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    canonical_path = _canonical_retention_receipt_path(
        plan_sha256=plan_sha256,
        attempt=attempt,
    )
    if path != canonical_path:
        raise RuntimeError(
            "retention reconciliation receipt path is not the canonical receipt target"
        )
    if re.fullmatch(r"[0-9a-f]{64}", expected_receipt_sha256) is None:
        raise RuntimeError("retention reconciliation receipt hash is invalid")
    payload, _ = _read_json_file(path, max_bytes=MAX_RETENTION_RECEIPT_BYTES)
    receipt_sha256 = payload.get("receipt_sha256")
    if (
        receipt_sha256 != expected_receipt_sha256
        or _sha256(
            {key: value for key, value in payload.items() if key != "receipt_sha256"}
        )
        != receipt_sha256
    ):
        raise RuntimeError(f"retention terminal receipt integrity is invalid: {path}")
    expected_previous_receipt_sha256: str | None = None
    for previous_attempt in range(1, attempt):
        previous_path = _canonical_retention_receipt_path(
            plan_sha256=plan_sha256,
            attempt=previous_attempt,
            receipt_root=canonical_path.parent,
        )
        expected_previous_receipt_sha256 = _verified_partial_receipt(
            previous_path,
            plan_sha256=plan_sha256,
            expected_attempt=previous_attempt,
            expected_previous_receipt_sha256=expected_previous_receipt_sha256,
        )
    retry = payload.get("retry")
    if (
        payload.get("schema_version") != 3
        or payload.get("operation") != "grabowski-runtime-state-retention"
        or payload.get("plan_sha256") != plan_sha256
        or payload.get("attempt") != attempt
        or payload.get("previous_receipt_sha256")
        != expected_previous_receipt_sha256
        or payload.get("completed") is not True
        or not isinstance(retry, dict)
        or retry.get("required") is not False
        or not isinstance(payload.get("reset_failed"), list)
        or not isinstance(payload.get("reset_failures"), list)
        or not isinstance(payload.get("archived_jobs"), list)
    ):
        raise RuntimeError(f"retention terminal receipt binding is invalid: {path}")
    return payload


def _retention_audit_reconciliation_state(
    *,
    intent_record_sha256: str,
    plan_sha256: str,
    attempt: int,
    receipt_sha256: str,
) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{64}", intent_record_sha256) is None:
        raise RuntimeError("retention reconciliation intent hash is invalid")
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    import grabowski_audit_query as audit_query

    snapshot = audit_query.capture_verified_audit_snapshot()
    open_intents: dict[str, dict[str, Any]] = {}
    target_seen = False
    receipt_consumer_digest: str | None = None
    receipt_consumer_kind: str | None = None
    receipt_conflict = False
    original_completion: dict[str, Any] | None = None
    existing_reconciliation: dict[str, Any] | None = None

    for item in audit_query._iter_snapshot_items(snapshot, order="asc"):
        evidence = item.get("evidence", {})
        record = item.get("record", {})
        if not isinstance(evidence, dict) or not isinstance(record, dict):
            continue
        record_digest = evidence.get("record_sha256")
        operation = record.get("operation")
        same_identity = (
            record.get("plan_sha256") == plan_sha256
            and not isinstance(record.get("attempt"), bool)
            and isinstance(record.get("attempt"), int)
            and record.get("attempt") == attempt
        )
        if (
            record.get("receipt_sha256") == receipt_sha256
            and operation
            in (
                "runtime-state-retention-complete",
                RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
            )
            and not same_identity
        ):
            # Receipt occupancy is global, not identity-version-specific. A
            # verified legacy or foreign completion/reconciliation that already
            # cites this terminal receipt prevents a second completion claim.
            receipt_conflict = True
            continue
        if record_digest == intent_record_sha256 and (
            operation != "runtime-state-retention-intent" or not same_identity
        ):
            raise RuntimeError("retention reconciliation intent binding is invalid")

        if operation == "runtime-state-retention-intent" and same_identity:
            if (
                not isinstance(record_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", record_digest) is None
            ):
                raise RuntimeError(
                    "retention reconciliation intent evidence digest is invalid"
                )
            open_intents.setdefault(record_digest, record)
            if record_digest == intent_record_sha256:
                target_seen = True
            continue

        if operation == "runtime-state-retention-complete" and same_identity:
            if record.get("receipt_sha256") != receipt_sha256:
                raise RuntimeError(
                    "retention completion audit receipt binding conflicts"
                )
            # The canonical terminal receipt represents one retention execution.
            # Once that execution has already been bound by a prior completion or
            # reconciliation, later audit repair evidence must not consume another
            # duplicate intent.
            if receipt_consumer_digest is not None:
                continue
            if not open_intents:
                # A completion that precedes every eligible intent still occupies
                # this terminal receipt. It cannot later be rebound to a newer intent.
                receipt_conflict = True
                continue
            consumed_digest = next(reversed(open_intents))
            open_intents.pop(consumed_digest)
            receipt_consumer_digest = consumed_digest
            receipt_consumer_kind = "completion"
            if consumed_digest == intent_record_sha256:
                original_completion = {
                    "record_sha256": record_digest,
                    "record": record,
                }
            continue

        if (
            operation == RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION
            and same_identity
        ):
            claimed_intent_digest = record.get("intent_record_sha256")
            if (
                not isinstance(claimed_intent_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", claimed_intent_digest) is None
                or record.get("receipt_sha256") != receipt_sha256
                or record.get("reconciliation_kind") != "completion_audit_gap"
                or record.get("completed") is not True
                or record.get("retention_effect_retried") is not False
            ):
                raise RuntimeError(
                    "retention completion reconciliation binding conflicts"
                )

            if receipt_consumer_digest is not None:
                if receipt_consumer_digest != claimed_intent_digest:
                    raise RuntimeError(
                        "retention terminal receipt is already bound to another intent"
                    )
                # A completion appended after reconciliation is redundant repair
                # evidence for the same execution. It must not change which intent
                # the terminal receipt consumed.
                if (
                    receipt_consumer_kind == "reconciliation"
                    and claimed_intent_digest == intent_record_sha256
                    and existing_reconciliation is None
                ):
                    existing_reconciliation = {
                        "record_sha256": record_digest,
                        "record": record,
                    }
                continue

            if not open_intents:
                raise RuntimeError(
                    "retention reconciliation has no eligible open intent"
                )
            eligible_intent_digest = next(reversed(open_intents))
            if claimed_intent_digest != eligible_intent_digest:
                raise RuntimeError(
                    "retention reconciliation intent is ambiguous among duplicate intents"
                )
            open_intents.pop(claimed_intent_digest)
            receipt_consumer_digest = claimed_intent_digest
            receipt_consumer_kind = "reconciliation"
            if claimed_intent_digest == intent_record_sha256:
                existing_reconciliation = {
                    "record_sha256": record_digest,
                    "record": record,
                }

    if not target_seen:
        raise RuntimeError(
            "retention reconciliation intent record was not found in verified audit"
        )
    if receipt_conflict:
        raise RuntimeError(
            "retention terminal receipt is already bound to another intent"
        )
    if original_completion is not None or existing_reconciliation is not None:
        return {
            "original_completion": original_completion,
            "existing_reconciliation": existing_reconciliation,
        }

    if receipt_consumer_digest is not None:
        raise RuntimeError(
            "retention terminal receipt is already bound to another intent"
        )
    if intent_record_sha256 not in open_intents:
        raise RuntimeError("retention reconciliation intent is no longer open")
    if next(reversed(open_intents)) != intent_record_sha256:
        raise RuntimeError(
            "retention reconciliation intent is ambiguous among duplicate intents"
        )
    return {
        "original_completion": None,
        "existing_reconciliation": None,
    }


def _require_reconciliation_mutation_authority() -> None:
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    import grabowski_mcp as base

    base._require_mutations_enabled(
        "file_write",
        path=str(base.AUDIT_LOG),
        fresh_preflight=True,
    )


def _retention_coordination_lock():
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    import grabowski_self_deploy as self_deploy

    return self_deploy._deploy_schedule_lock()


def reconcile_retention_completion_audit(
    *,
    intent_record_sha256: str,
    plan_sha256: str,
    attempt: int,
    receipt_path: Path,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    _require_reconciliation_mutation_authority()
    with _retention_coordination_lock():
        return _reconcile_retention_completion_audit_locked(
            intent_record_sha256=intent_record_sha256,
            plan_sha256=plan_sha256,
            attempt=attempt,
            receipt_path=receipt_path,
            expected_receipt_sha256=expected_receipt_sha256,
        )


def _reconcile_retention_completion_audit_locked(
    *,
    intent_record_sha256: str,
    plan_sha256: str,
    attempt: int,
    receipt_path: Path,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    receipt = _verified_terminal_retention_receipt(
        receipt_path,
        plan_sha256=plan_sha256,
        attempt=attempt,
        expected_receipt_sha256=expected_receipt_sha256,
    )
    state = _retention_audit_reconciliation_state(
        intent_record_sha256=intent_record_sha256,
        plan_sha256=plan_sha256,
        attempt=attempt,
        receipt_sha256=expected_receipt_sha256,
    )
    if state["original_completion"] is not None:
        return {
            "schema_version": 1,
            "operation": RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
            "status": "already-complete",
            "idempotent": True,
            "plan_sha256": plan_sha256,
            "attempt": attempt,
            "receipt_sha256": expected_receipt_sha256,
            "intent_record_sha256": intent_record_sha256,
            "completion_record_sha256": state["original_completion"]["record_sha256"],
            "retention_effect_retried": False,
        }
    if state["existing_reconciliation"] is not None:
        return {
            "schema_version": 1,
            "operation": RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
            "status": "already-reconciled",
            "idempotent": True,
            "plan_sha256": plan_sha256,
            "attempt": attempt,
            "receipt_sha256": expected_receipt_sha256,
            "intent_record_sha256": intent_record_sha256,
            "reconciliation_record_sha256": state["existing_reconciliation"]["record_sha256"],
            "retention_effect_retried": False,
        }
    reconciliation = _append_audit_record({
        "timestamp_unix": int(time.time()),
        "operation": RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
        "reconciliation_kind": "completion_audit_gap",
        "plan_sha256": plan_sha256,
        "attempt": attempt,
        "receipt_sha256": expected_receipt_sha256,
        "intent_record_sha256": intent_record_sha256,
        "completed": True,
        "reset_failed_count": len(receipt["reset_failed"]),
        "reset_failure_count": len(receipt["reset_failures"]),
        "archived_job_count": len(receipt["archived_jobs"]),
        "retention_effect_retried": False,
    })
    return {
        "schema_version": 1,
        "operation": RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
        "status": "reconciled",
        "idempotent": False,
        "plan_sha256": plan_sha256,
        "attempt": attempt,
        "receipt_sha256": expected_receipt_sha256,
        "intent_record_sha256": intent_record_sha256,
        "retention_effect_retried": False,
        "audit": reconciliation,
    }


def _verified_partial_receipt(
    path: Path,
    *,
    plan_sha256: str,
    expected_attempt: int,
    expected_previous_receipt_sha256: str | None,
    receipt_fd: int | None = None,
) -> str:
    if receipt_fd is None:
        payload, _ = _read_json_file(path, max_bytes=MAX_RETENTION_RECEIPT_BYTES)
    else:
        raw, _ = _archive_pinned_json_preimage(
            receipt_fd, path.name, max_bytes=MAX_RETENTION_RECEIPT_BYTES
        )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid retention receipt JSON: {path}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"invalid retention receipt object: {path}")
    receipt_sha256 = payload.get("receipt_sha256")
    if (
        not isinstance(receipt_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt_sha256) is None
        or _sha256(
            {key: value for key, value in payload.items() if key != "receipt_sha256"}
        )
        != receipt_sha256
    ):
        raise RuntimeError(f"retention receipt integrity is invalid: {path}")
    if (
        payload.get("schema_version") != 3
        or payload.get("operation") != "grabowski-runtime-state-retention"
        or payload.get("plan_sha256") != plan_sha256
        or payload.get("attempt") != expected_attempt
        or payload.get("previous_receipt_sha256")
        != expected_previous_receipt_sha256
    ):
        raise RuntimeError(f"retention receipt chain binding is invalid: {path}")
    retry = payload.get("retry")
    if payload.get("completed") is not False or not isinstance(retry, dict):
        raise RuntimeError(f"retention plan already has terminal receipt: {path}")
    if (
        retry.get("required") is not True
        or retry.get("strategy")
        != "rebuild_live_plan_and_chain_partial_receipt"
    ):
        raise RuntimeError(f"retention partial receipt is not retryable: {path}")
    return receipt_sha256


def _select_receipt_target(
    receipt_root: Path,
    *,
    plan_sha256: str,
    receipt_fd: int | None = None,
) -> tuple[Path, int, str | None]:
    previous_receipt_sha256: str | None = None
    for attempt in range(1, MAX_RETENTION_RECEIPT_ATTEMPTS + 1):
        name = (
            f"{plan_sha256}.json"
            if attempt == 1
            else f"{plan_sha256}.retry-{attempt:02d}.json"
        )
        path = receipt_root / name
        if receipt_fd is None:
            exists = path.exists() or path.is_symlink()
        else:
            try:
                os.stat(name, dir_fd=receipt_fd, follow_symlinks=False)
            except FileNotFoundError:
                exists = False
            else:
                exists = True
        if not exists:
            return path, attempt, previous_receipt_sha256
        previous_receipt_sha256 = _verified_partial_receipt(
            path,
            plan_sha256=plan_sha256,
            expected_attempt=attempt,
            expected_previous_receipt_sha256=previous_receipt_sha256,
            receipt_fd=receipt_fd,
        )
    raise RuntimeError("retention receipt retry bound exhausted")

def _archive_read_deploy_index_pinned(
    jobs_root: Path, root_fd: int, self_deploy: Any
) -> dict[str, Any] | None:
    """Read the canonical index from the pinned jobs-root inode, not its path."""
    name = getattr(self_deploy, "DEPLOY_INDEX_FILENAME", "runtime-deploy-index.json")
    if name != "runtime-deploy-index.json":
        raise RuntimeError("unexpected runtime deploy index name")
    try:
        data, preimage = _archive_pinned_json_preimage(root_fd, name)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeError("runtime deploy index is unreadable") from exc
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime deploy index is unreadable") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "units", "pending_unit", "updated_at_unix"
    }:
        raise RuntimeError("runtime deploy index shape is invalid")
    if value["schema_version"] != 1:
        raise RuntimeError("runtime deploy index schema is unsupported")
    units = value["units"]
    max_entries = getattr(self_deploy, "MAX_DEPLOY_INDEX_ENTRIES", 512)
    if not isinstance(units, list) or len(units) > max_entries:
        raise RuntimeError("runtime deploy index entry count is invalid")
    validate = getattr(self_deploy, "_validate_index_unit", None)
    for entry in [*units, value["pending_unit"]]:
        if entry is None:
            continue
        if callable(validate):
            validate(entry)
        elif not isinstance(entry, str) or JOB_NAME.fullmatch(entry) is None:
            raise RuntimeError("runtime deploy index contains invalid unit")
    if len(units) != len(set(units)):
        raise RuntimeError("runtime deploy index has duplicate units")
    stamp = value["updated_at_unix"]
    if type(stamp) is not int or stamp < 0:
        raise RuntimeError("runtime deploy index timestamp is invalid")
    _archive_require_unchanged_root(jobs_root, root_fd)
    return {**value, "units": sorted(units), "_source_preimage": preimage}


def apply_plan(plan: dict[str, Any], *, expected_plan_sha256: str) -> dict[str, Any]:
    plan = _validated_plan(plan, expected_plan_sha256)
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    import grabowski_mcp as base

    base._require_mutations_enabled("user_service_control")
    base._require_capability("durable_job")
    for evidence in plan["worker_reset_evidence"]:
        base._require_capability(
            "browser_worker" if evidence["kind"] == "browser" else "gui_worker"
        )

    import grabowski_self_deploy as self_deploy

    with self_deploy._deploy_schedule_lock(), ExitStack() as root_pins:
        # These descriptors stay open until all archive moves and reset
        # actions finish, so inode reuse cannot substitute a foreign root.
        jobs_root_pin_fd = os.dup(plan.jobs_fd)
        root_pins.callback(os.close, jobs_root_pin_fd)
        pinned_jobs_stat = os.fstat(jobs_root_pin_fd)
        pinned_jobs_identity = (pinned_jobs_stat.st_dev, pinned_jobs_stat.st_ino)
        if pinned_jobs_identity != tuple(plan["jobs_root_identity"]):
            raise RuntimeError("jobs root identity changed since planning")
        _archive_require_unchanged_root(Path(plan["jobs_root"]), jobs_root_pin_fd)
        archive_root_pin_fd = os.dup(_archive_root_fd_for_plan(plan))
        root_pins.callback(os.close, archive_root_pin_fd)
        pinned_archive_stat = os.fstat(archive_root_pin_fd)
        pinned_archive_identity = (pinned_archive_stat.st_dev, pinned_archive_stat.st_ino)
        (
            jobs_root, archive_root, receipt_root, prepared,
            prepared_jobs_root_identity,
        ) = _prepare_archives(
            plan, expected_archive_root_identity=pinned_archive_identity,
            jobs_root_fd=jobs_root_pin_fd, archive_root_fd=archive_root_pin_fd,
            source_pins=root_pins,
        )
        _prepare_worker_resets(plan)
        receipt_pin_fd = os.dup(_receipt_root_fd_for_plan(plan))
        root_pins.callback(os.close, receipt_pin_fd)
        receipt_target, attempt, previous_receipt_sha256 = _select_receipt_target(
            receipt_root, plan_sha256=plan["plan_sha256"],
            receipt_fd=receipt_pin_fd,
        )
        intent_audit = _append_intent_audit(
            plan,
            attempt=attempt,
            previous_receipt_sha256=previous_receipt_sha256,
        )

        archived: list[dict[str, Any]] = []
        index_root_fd = os.dup(jobs_root_pin_fd)
        try:
            # Preparation pins the jobs root even for reset-only plans with no
            # archive candidates. Never derive root authority from a later,
            # attacker-substituted index FD.
            root_stat = os.fstat(index_root_fd)
            if (root_stat.st_dev, root_stat.st_ino) != prepared_jobs_root_identity:
                raise RuntimeError(
                    "jobs root identity changed before index read"
                )
            index = _archive_read_deploy_index_pinned(
                jobs_root, index_root_fd, self_deploy
            )
            _archive_require_unchanged_root(jobs_root, index_root_fd)
            index_root_stat = os.fstat(index_root_fd)
            index_root_identity = (index_root_stat.st_dev, index_root_stat.st_ino)
            if index is None and prepared:
                # Linux has no rename-if-inode primitive. A missing canonical
                # index cannot prove historical nonmembership, and publishing
                # an empty or pathname-bootstrapped index could hide active
                # deploy/resume jobs. Abort before ANY archive move; recovery
                # must establish the index through the deployment owner.
                raise RuntimeError(
                    "canonical deployment index absent; explicit recovery required"
                )
            if (
                prepared
                and index is not None
                and any(
                    item["record"]["job_name"] == index["pending_unit"]
                    for item in prepared
                )
            ):
                # A pending deployment reservation is as live as a published
                # index member; an archived source would strand promotion.
                raise RuntimeError("pending deployment job cannot be archived")
            if (
                prepared
                and index is not None
                and any(
                    item["record"]["job_name"] in index["units"]
                    for item in prepared
                )
            ):
                # Do not publish a stale index preimage even transiently.
                raise RuntimeError(
                    "indexed deployment archive requires explicit reconciliation"
                )
            _archive_require_unchanged_root(jobs_root, index_root_fd)
        finally:
            os.close(index_root_fd)
        for item in prepared:
            source_dir = item["source_dir"]
            # The originally authenticated source FD is kept open until
            # apply_plan exits, preventing inode reuse after preparation.
            source_fd = item["source_fd"]
            _archive_require_json_temp_capacity(source_fd)
            _archive_require_child_bound(
                jobs_root_pin_fd, source_dir.name, source_fd, source_dir
            )
            metadata = os.fstat(source_fd)
            if (metadata.st_dev, metadata.st_ino) != item["source_identity"]:
                raise RuntimeError("source inode changed before archive")
            current_files = _archive_file_manifest_on_fd(source_dir, source_fd)
            if current_files != item["files"]:
                raise RuntimeError(
                    f"job files drifted before archive: {item['record']['job_name']}"
                )
        for item in prepared:
            record = item["record"]
            source_dir = item["source_dir"]
            destination = item["destination"]
            archive_manifest = {
                "schema_version": 1,
                "unit": record["unit"],
                "job_name": record["job_name"],
                "source": str(source_dir),
                "archived_at_unix": int(time.time()),
                "plan_sha256": plan["plan_sha256"],
                "terminal_evidence": record["terminal_evidence"],
                "files": item["files"],
            }
            archive_manifest["manifest_sha256"] = _sha256(archive_manifest)
            # Recheck the canonical control-plane preimage immediately
            # before the irreversible rename. Retention does not modify the
            # deployment index; a changed identity/content or a newly
            # reserved unit therefore invalidates the entire archive plan.
            check_fd = os.dup(jobs_root_pin_fd)
            try:
                # The recheck must be read from the same jobs-root inode
                # authenticated at preparation. Matching index bytes/inode
                # alone cannot authenticate a foreign parent directory.
                check_stat = os.fstat(check_fd)
                if (check_stat.st_dev, check_stat.st_ino) != item[
                    "jobs_root_identity"
                ]:
                    raise RuntimeError(
                        "jobs root identity changed before per-job index recheck"
                    )
                current_index = _archive_read_deploy_index_pinned(
                    jobs_root, check_fd, self_deploy
                )
                _archive_require_unchanged_root(jobs_root, check_fd)
                if (
                    current_index is None
                    or current_index["_source_preimage"] != index["_source_preimage"]
                    or record["job_name"] in current_index["units"]
                    or record["job_name"] == current_index["pending_unit"]
                ):
                    raise RuntimeError(
                        "deployment index changed before archive move"
                    )
            finally:
                os.close(check_fd)
            # The archive manifest is only authoritative after the moved
            # inode's contents passed the post-move verification.
            _archive_move_job_pinned(
                source_dir,
                destination,
                source_identity=item["source_identity"],
                jobs_root_identity=item["jobs_root_identity"],
                archive_root_identity=item["archive_root_identity"],
                expected_files=item["files"],
                jobs_root_fd=jobs_root_pin_fd,
                archive_root_fd=archive_root_pin_fd,
            )
            # Manifest publication uses the moved inode under the authenticated
            # archive root. A competing basename swap cannot redirect writes.
            moved_fd = os.dup(item["source_fd"])
            try:
                _archive_require_child_bound(
                    archive_root_pin_fd, destination.name, moved_fd, destination
                )
                moved_stat = os.fstat(moved_fd)
                if (moved_stat.st_dev, moved_stat.st_ino) != item["source_identity"]:
                    raise RuntimeError(
                        "archive destination inode changed before manifest publication"
                    )
                _write_json_atomic(
                    destination / "archive-manifest.json",
                    archive_manifest,
                    replace_existing=True,
                    expected_parent_identity=item["source_identity"],
                    pinned_parent_fd=moved_fd,
                )
                _archive_require_child_bound(
                    archive_root_pin_fd, destination.name, moved_fd, destination
                )
            finally:
                os.close(moved_fd)
            archived.append(
                {
                    "unit": record["unit"],
                    "destination": str(destination),
                    "manifest_sha256": archive_manifest["manifest_sha256"],
                }
            )

        # Index membership is not trustworthy authority, even when a
        # one-shot pinned read showed non-membership: a same-UID peer may
        # present a different valid index and then restore the original.
        # Recovered historical archives cannot authorize reset by plan hash
        # or unsigned manifest. Only a verified move in THIS apply or a
        # positive pinned live registry can authorize reset of a job unit.
        just_archived_units = {item["unit"] for item in archived}
        reset_results: list[dict[str, Any]] = []
        reset_failures: list[dict[str, str]] = []
        for unit in plan["reset_failed_units"]:
            if JOB_UNIT.fullmatch(unit) and unit in just_archived_units:
                # A verified archive must still be the very same source inode
                # at its authenticated destination before the systemd effect.
                try:
                    item = next(
                        item for item in prepared if item["record"]["unit"] == unit
                    )
                    archive_destination = item["destination"]
                    _archive_require_child_bound(
                        archive_root_pin_fd, archive_destination.name,
                        item["source_fd"], archive_destination,
                    )
                except (RuntimeError, OSError, StopIteration) as exc:
                    reset_failures.append(
                        _redacted_reset_failure(
                            unit=unit, stage="deployment_index_recovery", error=exc
                        )
                    )
                    continue
                # A same-UID peer may hide the deployment index during the
                # first read. Even a verified move cannot justify resetting
                # a unit whose CURRENT pinned index still lists that job.
                root_fd = None
                try:
                    root_fd = os.dup(jobs_root_pin_fd)
                    root_stat = os.fstat(root_fd)
                    if (root_stat.st_dev, root_stat.st_ino) != index_root_identity:
                        raise RuntimeError(
                            "jobs root identity changed before archived-job reset index read"
                        )
                    _archive_require_pinned_identity(jobs_root, index_root_identity)
                    current_index = _archive_read_deploy_index_pinned(
                        jobs_root, root_fd, self_deploy
                    )
                    _archive_require_unchanged_root(jobs_root, root_fd)
                    # Missing canonical index is not proof of nonmembership.
                    # A pending reservation must be protected like a member.
                    job_name = unit.removesuffix(".service")
                    if (
                        current_index is None
                        or job_name in current_index["units"]
                        or current_index["pending_unit"] == job_name
                    ):
                        raise RuntimeError(
                            "verified archived job lacks a free canonical index slot"
                        )
                except (RuntimeError, OSError, KeyError, ValueError) as exc:
                    reset_failures.append(
                        _redacted_reset_failure(
                            unit=unit, stage="deployment_index_recovery", error=exc
                        )
                    )
                    continue
                finally:
                    if root_fd is not None:
                        os.close(root_fd)
            # Preserve the verified job directory inode until reset-failed.
            live_fd: int | None = None
            if JOB_UNIT.fullmatch(unit) and unit not in just_archived_units:
                job_dir = jobs_root / unit.removesuffix(".service")
                try:
                    _archive_require_pinned_identity(jobs_root, index_root_identity)
                    live_fd = _archive_open_child_root(
                        jobs_root_pin_fd, job_dir.name, job_dir
                    )
                    state = _systemd_unit_states([unit])[unit]
                    current = _job_record(
                        unit, jobs_root, now=int(time.time()),
                        # A self-hashed plan cannot widen the intrinsic day limit.
                        minimum_age_seconds=min(
                            plan["minimum_job_age_seconds"], 86_400
                        ),
                        systemd_state=state,
                        jobs_root_fd=jobs_root_pin_fd,
                    )
                    # Compare two fd-relative metadata reads under the same
                    # original jobs root, not an attacker-selected path.
                    _, pinned_metadata_sha256 = _archive_private_file_digest(
                        live_fd, job_dir / "metadata.json", max_bytes=MAX_JSON_BYTES
                    )
                    _archive_require_unchanged_root(job_dir, live_fd)
                    if pinned_metadata_sha256 != current["metadata_sha256"]:
                        raise RuntimeError("indexed job live registry inode/metadata mismatch")
                    if not current["terminal"] or current["archive"]:
                        raise RuntimeError(
                            "job is not a live, terminal, non-archive-eligible registry entry"
                        )
                except (RuntimeError, OSError, KeyError, ValueError) as exc:
                    if live_fd is not None:
                        os.close(live_fd)
                    reset_failures.append(
                        _redacted_reset_failure(
                            unit=unit, stage="deployment_index_recovery", error=exc
                        )
                    )
                    continue
            if WORKER_UNIT.fullmatch(unit):
                try:
                    _prepare_worker_resets(plan, units=[unit])
                except Exception as exc:
                    reset_failures.append(
                        _redacted_reset_failure(
                            unit=unit, stage="worker_revalidation", error=exc
                        )
                    )
                    continue
            try:
                if live_fd is not None:
                    _archive_require_unchanged_root(job_dir, live_fd)
                    _archive_require_pinned_identity(jobs_root, index_root_identity)
                    # Even a live non-archive reset must not conceal a pending
                    # deployment reservation added after plan creation.
                    live_index_fd = os.dup(jobs_root_pin_fd)
                    try:
                        root_stat = os.fstat(live_index_fd)
                        if (root_stat.st_dev, root_stat.st_ino) != index_root_identity:
                            raise RuntimeError(
                                "jobs root identity changed before live-job reset index read"
                            )
                        current_index = _archive_read_deploy_index_pinned(
                            jobs_root, live_index_fd, self_deploy
                        )
                        _archive_require_unchanged_root(jobs_root, live_index_fd)
                        if current_index is None:
                            raise RuntimeError(
                                "canonical deployment index missing before live reset"
                            )
                        if (
                            current_index["pending_unit"]
                            == unit.removesuffix(".service")
                        ):
                            raise RuntimeError(
                                "pending deployment job cannot be reset"
                            )
                    finally:
                        os.close(live_index_fd)
                if JOB_UNIT.fullmatch(unit) and unit in just_archived_units:
                    _archive_require_child_bound(
                        archive_root_pin_fd, archive_destination.name,
                        item["source_fd"], archive_destination,
                    )
                reset_results.append(_reset_failed(unit))
            except Exception as exc:
                reset_failures.append(
                    _redacted_reset_failure(
                        unit=unit, stage="reset_command", error=exc
                    )
                )
            finally:
                if live_fd is not None:
                    os.close(live_fd)
        failed_resets = [item for item in reset_results if item["returncode"] != 0]
        receipt = {
            "schema_version": 3,
            "operation": "grabowski-runtime-state-retention",
            "plan_sha256": plan["plan_sha256"],
            "attempt": attempt,
            "previous_receipt_sha256": previous_receipt_sha256,
            "reset_failed": reset_results,
            "reset_failures": reset_failures,
            "worker_reset_evidence": plan.get("worker_reset_evidence", []),
            "archived_jobs": archived,
            "preserved_blocked_units": plan.get("blocked", []),
            "archive_deferred_count": plan.get("archive_deferred_count", 0),
            "protected_nonterminal_jobs": plan.get(
                "protected_nonterminal_jobs", []
            ),
            "recovered_archived_failed_units": plan.get(
                "recovered_archived_failed_units", []
            ),
            "deferred_failed_units": plan.get("deferred_failed_units", []),
            "completed": not failed_resets and not reset_failures,
            "retry": {
                "required": bool(failed_resets or reset_failures),
                "strategy": "rebuild_live_plan_and_chain_partial_receipt",
            },
            "completed_at_unix": int(time.time()),
        }
        receipt["receipt_sha256"] = _sha256(receipt)
        receipt_path = _write_json_atomic(
            receipt_target, receipt, pinned_parent_fd=receipt_pin_fd
        )
        try:
            completion_audit = _append_completion_audit(receipt)
        except Exception as exc:
            raise RuntimeError(
                "retention mutations completed but completion audit failed; "
                f"receipt={receipt_path}"
            ) from exc

    result = {
        **receipt,
        "receipt_path": str(receipt_path),
        "audit": {
            "intent": intent_audit,
            "completion": completion_audit,
        },
    }
    if failed_resets or reset_failures:
        raise RuntimeError(
            "retention reset phase did not complete for every bound unit; "
            f"receipt={receipt_path}"
        )
    return result


def _normalize_periodic_paths(
    values: list[str] | tuple[str, ...] | None,
    *,
    label: str,
    maximum: int,
    allow_missing: bool = False,
) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, (list, tuple)) or len(values) > maximum:
        raise ValueError(f"{label} must contain at most {maximum} paths")
    normalized: list[str] = []
    for raw in values:
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise ValueError(f"{label} entries must be non-empty paths")
        candidate = Path(raw).expanduser()
        try:
            path = candidate.resolve(strict=True)
        except FileNotFoundError:
            if allow_missing:
                continue
            raise ValueError(f"{label} entries must exist") from None
        if not path.is_dir():
            raise ValueError(f"{label} entries must be directories")
        value = str(path)
        if value not in normalized:
            normalized.append(value)
    return normalized


def _apply_periodic_worktree_hygiene(
    *,
    repositories: list[str] | tuple[str, ...] | None,
    owner_id: str,
    allowed_checkout_roots: list[str] | tuple[str, ...] | None,
    max_actions: int,
    grip_runner: Any | None = None,
) -> dict[str, Any]:
    repos = _normalize_periodic_paths(
        repositories,
        label="worktree_hygiene_repositories",
        maximum=MAX_WORKTREE_HYGIENE_REPOSITORIES,
    )
    roots = _normalize_periodic_paths(
        allowed_checkout_roots,
        label="worktree_hygiene_allowed_roots",
        maximum=MAX_WORKTREE_HYGIENE_ROOTS,
        allow_missing=True,
    )
    if not repos:
        return {
            "schema_version": 1,
            "operation": "grabowski-worktree-hygiene-periodic-noop",
            "completed": True,
            "mutated": False,
            "actions": 0,
            "receipts": [],
        }
    if (
        isinstance(max_actions, bool)
        or not isinstance(max_actions, int)
        or not 1 <= max_actions <= MAX_WORKTREE_HYGIENE_ACTIONS_PER_CYCLE
    ):
        raise ValueError(
            "max_worktree_hygiene_actions must be between 1 and "
            f"{MAX_WORKTREE_HYGIENE_ACTIONS_PER_CYCLE}"
        )
    if not isinstance(owner_id, str) or not owner_id:
        raise ValueError("worktree_hygiene_owner must be a non-empty string")
    if not roots:
        if not allowed_checkout_roots:
            raise ValueError(
                "periodic worktree hygiene requires at least one allowed checkout root"
            )
        return {
            "schema_version": 1,
            "operation": "grabowski-worktree-hygiene-periodic-noop",
            "completed": True,
            "mutated": False,
            "actions": 0,
            "maximum_actions": max_actions,
            "repositories": repos,
            "allowed_checkout_roots": [],
            "owner_id": owner_id,
            "receipts": [],
            "bounded": True,
            "single_producer": "grabowski-runtime-retention.timer",
            "reason": "configured_optional_checkout_roots_absent",
        }

    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    if grip_runner is None:
        import grabowski_grips

        grip_runner = grabowski_grips.run_grip

    remaining = max_actions
    receipts: list[dict[str, Any]] = []
    action_count = 0
    for repo in repos:
        if remaining <= 0:
            break
        receipt = grip_runner(
            "worktree-hygiene-reconcile",
            {
                "repo": repo,
                "owner_id": owner_id,
                "apply_cleanup": True,
                "archive_new_candidates": True,
                "allowed_checkout_roots": roots,
                "max_actions": remaining,
                "confirmation": "reconcile-terminal-worktrees",
            },
            allow_mutation=True,
        )
        if not isinstance(receipt, dict):
            raise RuntimeError("worktree hygiene returned no structured receipt")
        status = receipt.get("status")
        if status == "failed":
            raise RuntimeError(
                f"periodic worktree hygiene failed for {repo}: "
                f"{receipt.get('output', {}).get('error', 'unknown error')}"
            )
        if status not in {"passed", "blocked"}:
            raise RuntimeError(
                f"periodic worktree hygiene returned invalid status for {repo}: {status}"
            )
        output = receipt.get("output")
        actions = output.get("actions", 0) if isinstance(output, dict) else 0
        if isinstance(actions, bool) or not isinstance(actions, int) or actions < 0:
            raise RuntimeError("worktree hygiene receipt has invalid action count")
        if actions > remaining:
            raise RuntimeError("worktree hygiene exceeded the cycle action bound")
        action_count += actions
        remaining -= actions
        receipts.append(receipt)

    return {
        "schema_version": 1,
        "operation": "grabowski-worktree-hygiene-periodic",
        "completed": True,
        "mutated": action_count > 0,
        "actions": action_count,
        "maximum_actions": max_actions,
        "repositories": repos,
        "allowed_checkout_roots": roots,
        "owner_id": owner_id,
        "receipts": receipts,
        "bounded": True,
        "single_producer": "grabowski-runtime-retention.timer",
    }


def apply_periodic_plan(
    *,
    minimum_job_age_seconds: int = 86_400,
    max_archive_jobs: int = MAX_ARCHIVE_JOBS_PER_PLAN,
    worktree_hygiene_repositories: list[str] | tuple[str, ...] | None = None,
    worktree_hygiene_owner: str = "operator:runtime-retention",
    worktree_hygiene_allowed_roots: list[str] | tuple[str, ...] | None = None,
    max_worktree_hygiene_actions: int = 2,
    worktree_hygiene_runner: Any | None = None,
) -> dict[str, Any]:
    """Apply one bounded live retention cycle after two identical snapshots.

    The periodic path deliberately keeps the existing plan-hash contract: it
    builds the live plan twice and refuses every mutation when those hashes
    differ. The normal apply path then performs its existing pre-mutation
    revalidation and receipt/audit writes. A stable actionless plan is returned
    as a successful no-op so repeated timer runs remain idempotent without
    manufacturing duplicate terminal receipts.
    """
    preview = build_plan(
        minimum_job_age_seconds=minimum_job_age_seconds,
        max_archive_jobs=max_archive_jobs,
    )
    current = build_plan(
        minimum_job_age_seconds=minimum_job_age_seconds,
        max_archive_jobs=max_archive_jobs,
    )
    if current["plan_sha256"] != preview["plan_sha256"]:
        raise RuntimeError("retention plan drifted between periodic snapshots")
    if not current["reset_failed_units"] and not current["archive_jobs"]:
        runtime_result = {
            "schema_version": 1,
            "operation": "grabowski-runtime-state-retention-periodic-noop",
            "plan_sha256": current["plan_sha256"],
            "completed": True,
            "mutated": False,
            "preserved_blocked_units": current.get("blocked", []),
        }
    else:
        runtime_result = apply_plan(
            current, expected_plan_sha256=preview["plan_sha256"]
        )
    hygiene_result = _apply_periodic_worktree_hygiene(
        repositories=worktree_hygiene_repositories,
        owner_id=worktree_hygiene_owner,
        allowed_checkout_roots=worktree_hygiene_allowed_roots,
        max_actions=max_worktree_hygiene_actions,
        grip_runner=worktree_hygiene_runner,
    )
    if not worktree_hygiene_repositories:
        return runtime_result
    return {
        "schema_version": 1,
        "operation": "grabowski-runtime-retention-convergence-periodic",
        "plan_sha256": current["plan_sha256"],
        "completed": bool(runtime_result.get("completed"))
        and bool(hygiene_result.get("completed")),
        "mutated": bool(runtime_result.get("mutated"))
        or bool(hygiene_result.get("mutated")),
        "runtime_retention": runtime_result,
        "worktree_hygiene": hygiene_result,
        "single_producer": "grabowski-runtime-retention.timer",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minimum-job-age-seconds", type=int, default=86_400)
    parser.add_argument(
        "--max-archive-jobs",
        type=int,
        default=MAX_ARCHIVE_JOBS_PER_PLAN,
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--periodic-apply", action="store_true")
    parser.add_argument("--worktree-hygiene-repo", action="append", default=[])
    parser.add_argument(
        "--worktree-hygiene-owner",
        default="operator:runtime-retention",
    )
    parser.add_argument("--worktree-hygiene-allowed-root", action="append", default=[])
    parser.add_argument(
        "--max-worktree-hygiene-actions",
        type=int,
        default=2,
    )
    parser.add_argument("--legacy-archive-status", action="store_true")
    parser.add_argument("--reconcile-completion-audit", action="store_true")
    parser.add_argument("--intent-record-sha256")
    parser.add_argument("--receipt-path")
    parser.add_argument("--expected-receipt-sha256")
    parser.add_argument("--attempt", type=int)
    args = parser.parse_args()
    try:
        if args.reconcile_completion_audit:
            if (
                args.apply
                or args.periodic_apply
                or args.legacy_archive_status
                or args.worktree_hygiene_repo
                or args.worktree_hygiene_allowed_root
            ):
                raise ValueError(
                    "--reconcile-completion-audit is incompatible with retention apply/status arguments"
                )
            missing = [
                name
                for name, value in (
                    ("--expected-plan-sha256", args.expected_plan_sha256),
                    ("--intent-record-sha256", args.intent_record_sha256),
                    ("--receipt-path", args.receipt_path),
                    ("--expected-receipt-sha256", args.expected_receipt_sha256),
                    ("--attempt", args.attempt),
                )
                if value is None
            ]
            if missing:
                raise ValueError(
                    "--reconcile-completion-audit requires " + ", ".join(missing)
                )
            result = reconcile_retention_completion_audit(
                intent_record_sha256=args.intent_record_sha256,
                plan_sha256=args.expected_plan_sha256,
                attempt=args.attempt,
                receipt_path=Path(args.receipt_path),
                expected_receipt_sha256=args.expected_receipt_sha256,
            )
            print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        if args.legacy_archive_status:
            if args.apply or args.periodic_apply or args.expected_plan_sha256:
                raise ValueError(
                    "--legacy-archive-status is incompatible with apply arguments"
                )
            print(
                json.dumps(
                    legacy_archive_status(),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
            )
            return 0
        if args.periodic_apply:
            if args.apply or args.expected_plan_sha256:
                raise ValueError(
                    "--periodic-apply is incompatible with explicit apply arguments"
                )
            receipt = apply_periodic_plan(
                minimum_job_age_seconds=args.minimum_job_age_seconds,
                max_archive_jobs=args.max_archive_jobs,
                worktree_hygiene_repositories=args.worktree_hygiene_repo,
                worktree_hygiene_owner=args.worktree_hygiene_owner,
                worktree_hygiene_allowed_roots=args.worktree_hygiene_allowed_root,
                max_worktree_hygiene_actions=args.max_worktree_hygiene_actions,
            )
            print(
                json.dumps(
                    receipt, ensure_ascii=False, sort_keys=True, indent=2
                )
            )
            return 0
        if args.worktree_hygiene_repo or args.worktree_hygiene_allowed_root:
            raise ValueError(
                "worktree hygiene arguments require --periodic-apply"
            )
        plan = build_plan(
            minimum_job_age_seconds=args.minimum_job_age_seconds,
            max_archive_jobs=args.max_archive_jobs,
        )
        if not args.apply:
            print(json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        if not args.expected_plan_sha256:
            raise ValueError("--expected-plan-sha256 is required with --apply")
        receipt = apply_plan(plan, expected_plan_sha256=args.expected_plan_sha256)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
JOB_NAME = re.compile(r"grabowski-job-[0-9a-f]{12}\Z")
JOB_UNIT = re.compile(r"grabowski-job-[0-9a-f]{12}\.service\Z")
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
MAX_ARCHIVE_JOBS_PER_PLAN = 128
MAX_JOB_RUNTIME_SECONDS = 2_592_000
JOB_RUNTIME_GRACE_SECONDS = 300
SYSTEMD_SHOW_CHUNK_SIZE = 100
MAX_ARCHIVE_FILES = 32
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
) -> dict[str, Any]:
    job_name = unit.removesuffix(".service")
    directory = _private_directory(jobs_root / job_name)
    if directory.parent != jobs_root:
        raise RuntimeError(f"job directory escaped jobs root: {job_name}")
    metadata, metadata_sha256 = _read_json_file(directory / "metadata.json")
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
    jobs_root = _private_directory(jobs_root)
    if archive_root.is_symlink() or receipt_root.is_symlink():
        raise RuntimeError("retention output roots may not be symlinks")
    observed_now = int(time.time()) if now is None else now
    failed = _failed_units() if failed_units is None else sorted(set(failed_units))
    if len(failed) > MAX_FAILED_UNITS:
        raise RuntimeError("failed-unit inventory exceeds the bounded scan")

    entries = sorted(
        (
            entry
            for entry in jobs_root.iterdir()
            if entry.name.startswith("grabowski-job-")
        ),
        key=lambda entry: entry.name,
    )
    if len(entries) > MAX_JOB_SCAN_ENTRIES:
        raise RuntimeError("job registry exceeds the bounded retention scan")
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
        if entry.is_symlink() or not entry.is_dir():
            block(unit, "job registry entry is not a real directory")
            continue
        try:
            record = _job_record(
                unit,
                jobs_root,
                now=observed_now,
                minimum_age_seconds=minimum_job_age_seconds,
                systemd_state=states[unit],
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
    archive_collisions: set[str] = set()
    for record in eligible:
        destination = archive_root / record["job_name"]
        if destination.exists() or destination.is_symlink():
            archive_collisions.add(record["unit"])
            block(record["unit"], "archive destination already exists")
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
                reset_units.append(unit)
                continue
            if not record["terminal"]:
                block(unit, "failed job terminality is not proven")
                continue
            if unit in archive_collisions:
                continue
            if record["archive"] and unit not in selected_archive_units:
                deferred_failed_units.append({
                    "unit": unit,
                    "reason": "archive deferred by bounded batch",
                })
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
        "archive_root": str(archive_root),
        "receipt_root": str(receipt_root),
        "task_db": str(task_db),
        "worker_db": str(worker_db),
        "resource_db": str(resource_db),
        "job_scan_count": len(entries),
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
    return {**material, "plan_sha256": _sha256(material)}


def _archive_file_manifest(directory: Path) -> list[dict[str, Any]]:
    directory = _private_directory(directory)
    files: list[dict[str, Any]] = []
    for path in sorted(directory.rglob("*")):
        if path == directory / "archive-manifest.json":
            continue
        if path.is_symlink():
            raise RuntimeError(f"archive source contains a symlink: {path}")
        if path.is_dir():
            _private_directory(path)
            continue
        if len(files) >= MAX_ARCHIVE_FILES:
            raise RuntimeError("archive source exceeds the file-count bound")
        size, digest = _private_file_digest(path, max_bytes=MAX_ARCHIVE_FILE_BYTES)
        files.append(
            {
                "path": str(path.relative_to(directory)),
                "bytes": size,
                "sha256": digest,
            }
        )
    return files


def _write_json_atomic(
    path: Path,
    payload: dict[str, Any],
    *,
    replace_existing: bool = False,
) -> Path:
    parent = _private_directory(path.parent, create=True)
    path = parent / path.name
    if path.is_symlink():
        raise RuntimeError(f"receipt path may not be a symlink: {path}")
    if path.exists():
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise RuntimeError(f"existing evidence is not owner-controlled: {path}")
        if not replace_existing:
            raise FileExistsError(f"retention evidence already exists: {path}")
    temporary = parent / f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    data = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        + b"\n"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
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
    if stage not in {"worker_revalidation", "reset_command"}:
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
    if plan.get("schema_version") != 3:
        raise RuntimeError("retention plan schema is unsupported")
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

def _prepare_archives(plan: dict[str, Any]) -> tuple[Path, Path, Path, list[dict[str, Any]]]:
    jobs_root = _private_directory(Path(plan["jobs_root"]))
    archive_root = _private_directory(Path(plan["archive_root"]), create=True)
    receipt_root = _private_directory(Path(plan["receipt_root"]), create=True)
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
        )
        if not fresh_record["terminal"] or not fresh_record["archive"]:
            raise RuntimeError(f"job is no longer archive-eligible: {job_name}")
        if fresh_record["metadata_sha256"] != record["metadata_sha256"]:
            raise RuntimeError(f"job metadata drift before archive: {job_name}")
        source_dir = _private_directory(jobs_root / job_name)
        if source_dir.parent != jobs_root:
            raise RuntimeError(f"archive source escaped jobs root: {job_name}")
        destination = archive_root / job_name
        if destination.exists() or destination.is_symlink():
            raise RuntimeError(f"archive destination appeared before apply: {job_name}")
        files = _archive_file_manifest(source_dir)
        prepared.append(
            {
                "record": record,
                "source_dir": source_dir,
                "destination": destination,
                "files": files,
            }
        )
    return jobs_root, archive_root, receipt_root, prepared


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



def _verified_partial_receipt(
    path: Path,
    *,
    plan_sha256: str,
    expected_attempt: int,
    expected_previous_receipt_sha256: str | None,
) -> str:
    payload, _ = _read_json_file(path, max_bytes=MAX_RETENTION_RECEIPT_BYTES)
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
) -> tuple[Path, int, str | None]:
    previous_receipt_sha256: str | None = None
    for attempt in range(1, MAX_RETENTION_RECEIPT_ATTEMPTS + 1):
        name = (
            f"{plan_sha256}.json"
            if attempt == 1
            else f"{plan_sha256}.retry-{attempt:02d}.json"
        )
        path = receipt_root / name
        if not path.exists() and not path.is_symlink():
            return path, attempt, previous_receipt_sha256
        previous_receipt_sha256 = _verified_partial_receipt(
            path,
            plan_sha256=plan_sha256,
            expected_attempt=attempt,
            expected_previous_receipt_sha256=previous_receipt_sha256,
        )
    raise RuntimeError("retention receipt retry bound exhausted")

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

    with self_deploy._deploy_schedule_lock():
        jobs_root, archive_root, receipt_root, prepared = _prepare_archives(plan)
        _prepare_worker_resets(plan)
        receipt_target, attempt, previous_receipt_sha256 = _select_receipt_target(
            receipt_root, plan_sha256=plan["plan_sha256"]
        )
        intent_audit = _append_intent_audit(
            plan,
            attempt=attempt,
            previous_receipt_sha256=previous_receipt_sha256,
        )

        archived: list[dict[str, Any]] = []
        index = self_deploy._read_deploy_index(jobs_root)
        indexed_units = set(index["units"]) if index is not None else set()
        for item in prepared:
            current_files = _archive_file_manifest(item["source_dir"])
            if current_files != item["files"]:
                raise RuntimeError(
                    f"job files drifted before archive: {item['record']['job_name']}"
                )
        for item in prepared:
            indexed_units.discard(item["record"]["job_name"])
        if index is not None:
            self_deploy._write_deploy_index(
                jobs_root,
                units=sorted(indexed_units),
                pending_unit=index["pending_unit"],
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
            _write_json_atomic(
                source_dir / "archive-manifest.json",
                archive_manifest,
                replace_existing=True,
            )
            os.replace(source_dir, destination)
            _fsync_directory(jobs_root)
            _fsync_directory(archive_root)
            if _archive_file_manifest(destination) != item["files"]:
                raise RuntimeError(
                    f"archived job files changed during move: {record['job_name']}"
                )
            archived.append(
                {
                    "unit": record["unit"],
                    "destination": str(destination),
                    "manifest_sha256": archive_manifest["manifest_sha256"],
                }
            )

        reset_results: list[dict[str, Any]] = []
        reset_failures: list[dict[str, str]] = []
        for unit in plan["reset_failed_units"]:
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
                reset_results.append(_reset_failed(unit))
            except Exception as exc:
                reset_failures.append(
                    _redacted_reset_failure(
                        unit=unit, stage="reset_command", error=exc
                    )
                )
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
        receipt_path = _write_json_atomic(receipt_target, receipt)
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
    parser.add_argument("--legacy-archive-status", action="store_true")
    args = parser.parse_args()
    try:
        if args.legacy_archive_status:
            if args.apply or args.expected_plan_sha256:
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

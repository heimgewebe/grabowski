from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time
import uuid
from typing import Any

import grabowski_fleet as fleet
import grabowski_mcp as base
import grabowski_chronik as chronik
import grabowski_privileged as privileged
import grabowski_recovery as recovery
import grabowski_resources as resources
import grabowski_nonconflict as nonconflict
import grabowski_consumer_surface as consumer_surface
import grabowski_command_identity as command_identity
import grabowski_sqlite_store as sqlite_store
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
TASK_DB = Path(
    os.environ.get(
        "GRABOWSKI_TASK_DB",
        str(operator.STATE_DIR / "tasks.sqlite3"),
    )
).expanduser()
TASK_OUTCOMES_DIR = TASK_DB.with_suffix(".outcomes")
GRABOWSKI_RUNTIME_PYTHON = operator.HOME / ".local/share/grabowski-mcp/.venv/bin/python"
GRABOWSKI_REPOSITORY_SLUG = "heimgewebe/grabowski"
MANAGED_BUILD_RESOLVER = (
    operator.HOME / ".local/lib/heim-pc/managed-build/scripts/managed_build.py"
)
MANAGED_BUILD_PYTHON = Path("/usr/bin/python3")
MANAGED_CARGO_CACHE_ROOT = operator.HOME / ".cache/heim-pc/managed-builds/cargo"
MANAGED_CARGO_PROFILE = "operator-task"
SYSTEMD_ENV_EXECUTABLE = "/usr/bin/env"
SCRIPT_EXECUTABLES = frozenset({"bash", "sh", "zsh", "fish", "python", "python3"})
CARGO_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_])cargo(?:$|[^A-Za-z0-9_])")
JUST_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_])just(?:$|[^A-Za-z0-9_])")
MAKE_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_])make(?:$|[^A-Za-z0-9_])")
MAX_BUILD_SCRIPT_INSPECTION_BYTES = 256 * 1024
DEFAULT_TASK_LIST_LIMIT = 20

TASK_ID = re.compile(r"[0-9a-f]{24}\Z")
EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Deliberately canonical: only names emitted by _task_unit are accepted.
# Manual or future-format units must never be adopted as authoritative by accident.
UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
RESUME_POLICIES = {"never", "retry-safe", "verify-then-retry", "manual"}
CHRONIK_OPERATION_TASK_CLASS = {
    "implement": "coding",
    "review": "review",
    "merge": "merge",
    "deploy": "deploy",
    "runtime_verify": "runtime_verify",
    "recovery": "recovery",
    "other": "other",
}
TASK_STATES = {
    "launching",
    "running",
    "completed",
    "failed",
    "cancelled",
    "timed_out",
    "signalled",
    "outcome_unknown",
    "interrupted",
}
TASK_STATE_PROJECTIONS: dict[str, tuple[str, ...]] = {
    # "active" is current execution truth, not retained recovery history.
    "active": ("launching", "running"),
    "attention": ("interrupted", "outcome_unknown", "failed", "timed_out", "signalled"),
    "terminal": ("completed", "failed", "cancelled", "timed_out", "signalled"),
}
MUTATING_AGENT_EXECUTABLES = frozenset({"agy", "claude", "cline", "codex"})
READ_ONLY_AGENT_MODES = frozenset({"plan", "read-only"})
TASK_EXECUTION_BACKENDS = {"systemd-user", "systemd-root-broker"}
SYSTEMD_SCOPES = {"user", "system"}
TASK_SCHEMA_V4_ADDITIVE_COLUMNS = {
    "terminalization_sha256": ("TEXT", 0, 0),
    "terminalized_at_unix": ("INTEGER", 0, 0),
    "lifecycle_receipt_sha256": ("TEXT", 0, 0),
}
TASK_SCHEMA_V5_ADDITIVE_COLUMNS = {
    **TASK_SCHEMA_V4_ADDITIVE_COLUMNS,
    "repository_scope_manifest_json": ("TEXT", 0, 0),
}
LEASE_MAINTENANCE_TASK_STATES = {"running", "outcome_unknown"}
TASK_LEASE_DELEGATION_STATES = frozenset({"running"})


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _redact_reason(text: str) -> str:
    redact_text = getattr(operator, "_redact_text", None)
    if callable(redact_text):
        return redact_text(text)
    redact = getattr(operator, "_redact", None)
    if callable(redact):
        return redact(text)
    return text


def _is_terminal_state(state: str) -> bool:
    return state in {"completed", "failed", "cancelled", "timed_out", "signalled"}


def _state_releases_resources(state: str) -> bool:
    return _is_terminal_state(state)


def _read_existing_outcome_receipt(
    path: Path,
    *,
    transition_sha256: str | None,
    allow_legacy: bool,
) -> str | None:
    existing = json.loads(path.read_text(encoding="utf-8"))
    existing_digest = existing.get("receipt_sha256")
    if not isinstance(existing_digest, str) or existing_digest != _sha256_json(
        {key: value for key, value in existing.items() if key != "receipt_sha256"}
    ):
        raise RuntimeError("Stored task lifecycle receipt integrity is invalid")
    if transition_sha256 is None:
        return existing_digest
    existing_terminalization = existing.get("terminalization")
    if (
        isinstance(existing_terminalization, dict)
        and existing_terminalization.get("transition_sha256") == transition_sha256
    ):
        return existing_digest
    if allow_legacy and existing.get("schema_version") == 1:
        return None
    raise RuntimeError("Stored task lifecycle receipt belongs to another transition")


def _write_outcome_receipt(
    record: dict[str, Any],
    state: str,
    observation: dict[str, Any] | None,
    *,
    terminalization: dict[str, Any] | None = None,
) -> str | None:
    if not _is_terminal_state(state):
        return None
    TASK_OUTCOMES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    primary_path = TASK_OUTCOMES_DIR / f"{record['task_id']}.json"
    terminalization_payload: dict[str, Any] | None = None
    transition_sha256: str | None = None
    if terminalization is not None:
        transition_sha256 = terminalization["transition_sha256"]
        terminalization_payload = {
            "kind": terminalization["kind"],
            "transition_sha256": transition_sha256,
            "task_projection_sha256": terminalization["task_projection_sha256"],
            "requested_resource_keys": terminalization["requested_resource_keys"],
            "requested_resource_keys_sha256": terminalization[
                "requested_resource_keys_sha256"
            ],
            "prior_leases": terminalization["prior_leases"],
            "prior_leases_sha256": terminalization["prior_leases_sha256"],
            "revoked_resource_keys": terminalization["revoked_resource_keys"],
            "missing_resource_keys": terminalization["missing_resource_keys"],
            "prepared_at_unix": terminalization["prepared_at_unix"],
            "leases_revoked_at_unix": terminalization["leases_revoked_at_unix"],
            "recovery_status": terminalization["recovery_status"],
        }
    payload = {
        "schema_version": 2 if terminalization is not None else 1,
        "task_id": record["task_id"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "attempt": record["attempt"],
        "state": state,
        "argv_sha256": record["argv_sha256"],
        "execution_envelope_sha256": record.get("execution_envelope_sha256"),
        "resource_keys": _record_resource_keys(record),
        "observed_at_unix": _now(),
        "observation_sha256": _sha256_json(observation or {}),
        "observation": observation or {},
    }
    if terminalization is not None:
        payload["kind"] = "grabowski_task_lifecycle_receipt"
        payload["terminalization"] = terminalization_payload
    payload["receipt_sha256"] = _sha256_json(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )

    candidates = [(primary_path, terminalization is not None)]
    if terminalization is not None:
        candidates.append(
            (TASK_OUTCOMES_DIR / f"{record['task_id']}.lifecycle.json", False)
        )
    for path, allow_legacy in candidates:
        if not path.exists():
            continue
        existing_digest = _read_existing_outcome_receipt(
            path,
            transition_sha256=transition_sha256,
            allow_legacy=allow_legacy,
        )
        if existing_digest is not None:
            return existing_digest

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{record['task_id']}.", suffix=".tmp", dir=TASK_OUTCOMES_DIR
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        for path, allow_legacy in candidates:
            try:
                os.link(tmp_name, path)
            except FileExistsError:
                existing_digest = _read_existing_outcome_receipt(
                    path,
                    transition_sha256=transition_sha256,
                    allow_legacy=allow_legacy,
                )
                if existing_digest is not None:
                    return existing_digest
                continue
            directory_fd = os.open(TASK_OUTCOMES_DIR, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return str(payload["receipt_sha256"])
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
    raise RuntimeError("Task lifecycle receipt could not be persisted")

def _classify_observation(result: dict[str, Any], properties: dict[str, str]) -> str:
    active = properties.get("ActiveState")
    load = properties.get("LoadState")
    unit_result = properties.get("Result")
    exec_code = properties.get("ExecMainCode")
    exec_status = properties.get("ExecMainStatus")
    if unit_result == "success" and exec_status in {None, "", "0"}:
        return "completed" if active not in {"active", "activating", "reloading"} else "running"
    if active in {"active", "activating", "reloading"}:
        return "running"
    if unit_result == "timeout":
        return "timed_out"
    if unit_result in {"signal", "core-dump"} or exec_code in {"2", "3"}:
        return "signalled"
    if unit_result in {"exit-code", "resources", "protocol", "watchdog"} or active == "failed":
        return "failed"
    if result["returncode"] != 0 or load in {None, "not-found"}:
        return "outcome_unknown"
    if active in {"inactive", "deactivating"}:
        return "completed" if unit_result in {None, "", "success"} else "failed"
    return "outcome_unknown"


TASK_SCHEMA_V5_COLUMN_SHAPES = {
    "task_id": ("TEXT", 0, 1),
    "host": ("TEXT", 1, 0),
    "unit": ("TEXT", 1, 0),
    "attempt": ("INTEGER", 1, 0),
    "state": ("TEXT", 1, 0),
    "resume_policy": ("TEXT", 1, 0),
    "argv_json": ("TEXT", 1, 0),
    "argv_sha256": ("TEXT", 1, 0),
    "cwd": ("TEXT", 1, 0),
    "runtime_seconds": ("INTEGER", 1, 0),
    "cpu_weight": ("INTEGER", 1, 0),
    "io_weight": ("INTEGER", 1, 0),
    "memory_max_bytes": ("INTEGER", 0, 0),
    "created_at_unix": ("INTEGER", 1, 0),
    "updated_at_unix": ("INTEGER", 1, 0),
    "launcher_json": ("TEXT", 1, 0),
    "last_observation_json": ("TEXT", 0, 0),
    "resource_keys_json": ("TEXT", 1, 0),
    "lease_owner_id": ("TEXT", 0, 0),
    "request_id": ("TEXT", 0, 0),
    "origin_ref": ("TEXT", 0, 0),
    "external_run_id": ("TEXT", 0, 0),
    "execution_envelope_sha256": ("TEXT", 0, 0),
    "acceptance_json": ("TEXT", 1, 0),
    "request_sha256": ("TEXT", 0, 0),
    "execution_backend": ("TEXT", 1, 0),
    "systemd_scope": ("TEXT", 1, 0),
    "authoritative_unit": ("TEXT", 0, 0),
    "chronik_outbox_enabled": ("INTEGER", 1, 0),
    "chronik_outbox_state_root": ("TEXT", 0, 0),
    "chronik_context_json": ("TEXT", 0, 0),
    "terminalization_sha256": ("TEXT", 0, 0),
    "terminalized_at_unix": ("INTEGER", 0, 0),
    "lifecycle_receipt_sha256": ("TEXT", 0, 0),
    "repository_scope_manifest_json": ("TEXT", 0, 0),
}
TASK_SCHEMA_V1_COLUMNS = frozenset({
    "task_id", "host", "unit", "attempt", "state", "resume_policy",
    "argv_json", "argv_sha256", "cwd", "runtime_seconds", "cpu_weight",
    "io_weight", "memory_max_bytes", "created_at_unix", "updated_at_unix",
    "launcher_json", "last_observation_json",
})
TASK_SCHEMA_V2_COLUMNS = TASK_SCHEMA_V1_COLUMNS | {
    "resource_keys_json", "lease_owner_id",
}
TASK_SCHEMA_V3_COLUMNS = frozenset(TASK_SCHEMA_V5_COLUMN_SHAPES) - {
    "terminalization_sha256", "terminalized_at_unix",
    "lifecycle_receipt_sha256", "repository_scope_manifest_json",
}
TASK_SCHEMA_V4_COLUMNS = frozenset(TASK_SCHEMA_V5_COLUMN_SHAPES) - {
    "repository_scope_manifest_json",
}
TASK_SCHEMA_REQUIRED_INDEXES = frozenset({
    "tasks_state_created_task_idx", "tasks_created_task_idx",
})
TASK_CURRENT_SCHEMA_VERSION = "5"
TASK_SUPPORTED_SCHEMA_VERSIONS = ("1", "2", "3", "4", "5")
TASK_SCHEMA_MIGRATION_PATHS = {
    version: (version, TASK_CURRENT_SCHEMA_VERSION)
    for version in TASK_SUPPORTED_SCHEMA_VERSIONS
    if version != TASK_CURRENT_SCHEMA_VERSION
}
TASK_SCHEMA_RECOVERY_INSTRUCTION = (
    "Keep the task store unchanged; use a runtime that explicitly supports the "
    "observed schema or restore a verified backup before retrying."
)

TASK_SCHEMA_ROLLING_UPGRADE = {
    "current_runtime_current_store": "supported",
    "current_runtime_supported_older_store": (
        "supported_with_exclusive_migration"
    ),
    "current_runtime_newer_store": "fail_closed_without_mutation",
    "pre_t062_runtime_overlap_with_future_schema": (
        "unsupported_require_full_runtime_drain"
    ),
}


_schema_directory_lock = sqlite_store.schema_directory_lock
_readonly_sqlite = sqlite_store.readonly_sqlite


class TaskSchemaInventoryChanged(RuntimeError):
    pass


@contextmanager
def _inventory_readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    with sqlite_store.inventory_readonly_sqlite(
        path,
        temporary_prefix="grabowski-task-schema-inventory-",
        error_type=TaskSchemaInventoryChanged,
    ) as connection:
        yield connection


_sqlite_integrity = sqlite_store.sqlite_integrity
_sqlite_fingerprint = sqlite_store.sqlite_fingerprint
_database_tables = sqlite_store.database_tables


def _metadata_shape(connection: sqlite3.Connection) -> tuple[tuple[str, str, int, int], ...]:
    return tuple(
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(metadata)")
    )


def _task_schema_version(connection: sqlite3.Connection) -> str | None:
    tables = _database_tables(connection)
    if not tables:
        return None
    if "metadata" not in tables:
        raise RuntimeError(
            "Task database schema metadata is missing; restore or inspect the store"
        )
    if _metadata_shape(connection) != (
        ("key", "TEXT", 0, 1),
        ("value", "TEXT", 1, 0),
    ):
        raise RuntimeError("Task database metadata table is malformed")
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError(
            "Task database schema_version metadata is missing or ambiguous"
        )
    return str(rows[0][0])


def _task_column_shapes(connection: sqlite3.Connection) -> dict[str, tuple[str, int, int]]:
    return {
        str(row[1]): (str(row[2]).upper(), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(tasks)")
    }


def _task_indexes(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute("PRAGMA index_list(tasks)")
    }


def _validate_task_schema_legacy(
    connection: sqlite3.Connection,
    version: str,
) -> None:
    if _database_tables(connection) != {"metadata", "tasks"}:
        raise RuntimeError(
            f"Task database schema {version} has unsupported tables"
        )
    shapes = _task_column_shapes(connection)
    expected = {
        "1": TASK_SCHEMA_V1_COLUMNS,
        "2": TASK_SCHEMA_V2_COLUMNS,
        "3": TASK_SCHEMA_V3_COLUMNS,
        "4": TASK_SCHEMA_V4_COLUMNS,
    }[version]
    names = set(shapes)
    if names != expected:
        raise RuntimeError(
            f"Task database schema {version} is incomplete or unsupported"
        )
    mismatched = sorted(
        name for name, shape in shapes.items()
        if TASK_SCHEMA_V5_COLUMN_SHAPES.get(name) != shape
    )
    if mismatched:
        raise RuntimeError(
            f"Task database schema {version} has incompatible columns: "
            + ", ".join(mismatched)
        )
    if version in {"3", "4"}:
        missing_indexes = TASK_SCHEMA_REQUIRED_INDEXES - _task_indexes(connection)
        if missing_indexes:
            raise RuntimeError(
                f"Task database schema {version} indexes are incomplete: "
                + ", ".join(sorted(missing_indexes))
            )


def _validate_task_schema_current(connection: sqlite3.Connection) -> None:
    if _database_tables(connection) != {"metadata", "tasks"}:
        raise RuntimeError("Task database schema 5 has unsupported tables")
    shapes = _task_column_shapes(connection)
    if shapes != TASK_SCHEMA_V5_COLUMN_SHAPES:
        raise RuntimeError("Task database schema 5 is incomplete or unsupported")
    missing_indexes = TASK_SCHEMA_REQUIRED_INDEXES - _task_indexes(connection)
    if missing_indexes:
        raise RuntimeError(
            "Task database schema 5 indexes are incomplete: "
            + ", ".join(sorted(missing_indexes))
        )


def _task_schema_inventory() -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "store": "tasks",
        "database": str(TASK_DB),
        "observed_version": None,
        "current_version": TASK_CURRENT_SCHEMA_VERSION,
        "supported_versions": list(TASK_SUPPORTED_SCHEMA_VERSIONS),
        "status": "uninitialized",
        "migration_required": False,
        "migration_path": [],
        "write_compatible": False,
        "mutation_performed": False,
        "required_action": "initialize_on_first_write",
        "recovery_instruction": None,
        "rolling_upgrade": dict(TASK_SCHEMA_ROLLING_UPGRADE),
    }
    if not TASK_DB.exists():
        return result
    if TASK_DB.is_symlink() or not TASK_DB.is_file():
        result.update(
            status="blocked",
            required_action="inspect_store_path",
            recovery_instruction=TASK_SCHEMA_RECOVERY_INSTRUCTION,
            error="Task database must be a regular non-symlink file",
        )
        return result
    if TASK_DB.stat().st_size == 0:
        return result
    try:
        with _inventory_readonly_sqlite(TASK_DB) as connection:
            _sqlite_integrity(connection, "Task database", quick=True)
            observed = _task_schema_version(connection)
            result["observed_version"] = observed
            if observed not in TASK_SUPPORTED_SCHEMA_VERSIONS:
                future = (
                    observed is not None
                    and observed.isdecimal()
                    and int(observed) > int(TASK_CURRENT_SCHEMA_VERSION)
                )
                result.update(
                    status="unsupported_future" if future else "unsupported_schema",
                    required_action="upgrade_runtime_or_restore_verified_backup",
                    recovery_instruction=TASK_SCHEMA_RECOVERY_INSTRUCTION,
                )
                return result
            if observed == TASK_CURRENT_SCHEMA_VERSION:
                _validate_task_schema_current(connection)
            else:
                _validate_task_schema_legacy(connection, observed)
    except TaskSchemaInventoryChanged as exc:
        result.update(
            status="blocked",
            required_action="retry_schema_inventory",
            recovery_instruction=(
                "Retry after the concurrent writer completes; do not mutate the store "
                "from this inventory result."
            ),
            error=f"{type(exc).__name__}: {exc}",
        )
        return result
    except (OSError, RuntimeError, sqlite3.DatabaseError) as exc:
        result.update(
            status="blocked",
            required_action="restore_or_inspect_store",
            recovery_instruction=TASK_SCHEMA_RECOVERY_INSTRUCTION,
            error=f"{type(exc).__name__}: {exc}",
        )
        return result
    if observed == TASK_CURRENT_SCHEMA_VERSION:
        result.update(status="current", write_compatible=True, required_action="none")
        return result
    path = TASK_SCHEMA_MIGRATION_PATHS[observed]
    result.update(
        status="migration_required",
        migration_required=True,
        migration_path=[
            {
                "from": path[0],
                "to": path[1],
                "lock": "exclusive_store_directory",
                "transaction": "immediate",
                "verified_backup_required": True,
            }
        ],
        required_action="open_with_current_runtime_to_migrate",
    )
    return result


def _validate_task_backup(
    path: Path,
    version: str,
    fingerprint: str,
) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Task migration backup may not be a symlink: {path}")
    try:
        status = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Task migration backup disappeared: {path}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeError(f"Task migration backup is not a regular file: {path}")
    mode = stat.S_IMODE(status.st_mode)
    if mode not in {0o400, 0o600}:
        raise RuntimeError(f"Task migration backup permissions are unsafe: {path}")
    with _readonly_sqlite(path) as backup:
        _sqlite_integrity(backup, "Task migration backup")
        if _task_schema_version(backup) != version:
            raise RuntimeError("Task migration backup schema version does not match")
        _validate_task_schema_legacy(backup, version)
        if _sqlite_fingerprint(backup) != fingerprint:
            raise RuntimeError("Task migration backup fingerprint does not match")


def _verified_task_migration_backup(
    version: str,
    fingerprint: str,
) -> Path:
    with _readonly_sqlite(TASK_DB) as source:
        source.execute("BEGIN")
        _sqlite_integrity(source, "Task database")
        if _sqlite_fingerprint(source) != fingerprint:
            raise RuntimeError(
                "Task database changed identity before backup; retry migration"
            )
        backup_path = TASK_DB.parent / (
            f"{TASK_DB.name}.schema-{version}-{fingerprint}.backup"
        )
        if backup_path.exists() or backup_path.is_symlink():
            _validate_task_backup(backup_path, version, fingerprint)
            return backup_path
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{TASK_DB.name}.schema-{version}-",
            suffix=".backup.tmp",
            dir=TASK_DB.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
            os.chmod(temporary, 0o400)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            _validate_task_backup(temporary, version, fingerprint)
            try:
                os.link(temporary, backup_path)
            except FileExistsError:
                pass
            else:
                temporary.unlink()
            _validate_task_backup(backup_path, version, fingerprint)
            flags = os.O_RDONLY | os.O_DIRECTORY
            directory = os.open(TASK_DB.parent, flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return backup_path
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _preflight_task_store() -> str | None:
    if not TASK_DB.exists():
        return None
    if TASK_DB.is_symlink() or not TASK_DB.is_file():
        raise PermissionError(f"Task database must be a regular file: {TASK_DB}")
    if TASK_DB.stat().st_size == 0:
        return None
    with _readonly_sqlite(TASK_DB) as connection:
        _sqlite_integrity(connection, "Task database", quick=True)
        version = _task_schema_version(connection)
        if version not in {"1", "2", "3", "4", "5"}:
            raise RuntimeError(
                "Unsupported task database schema; use a runtime that explicitly supports it"
            )
        if version == "5":
            _validate_task_schema_current(connection)
        else:
            _validate_task_schema_legacy(connection, version)
        return version


def _create_task_schema_v5(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        """
        CREATE TABLE tasks (
            task_id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            unit TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            state TEXT NOT NULL,
            resume_policy TEXT NOT NULL,
            argv_json TEXT NOT NULL,
            argv_sha256 TEXT NOT NULL,
            cwd TEXT NOT NULL,
            runtime_seconds INTEGER NOT NULL,
            cpu_weight INTEGER NOT NULL,
            io_weight INTEGER NOT NULL,
            memory_max_bytes INTEGER,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            launcher_json TEXT NOT NULL,
            last_observation_json TEXT,
            resource_keys_json TEXT NOT NULL DEFAULT '[]',
            lease_owner_id TEXT,
            request_id TEXT,
            origin_ref TEXT,
            external_run_id TEXT,
            execution_envelope_sha256 TEXT,
            acceptance_json TEXT NOT NULL DEFAULT '[]',
            request_sha256 TEXT,
            execution_backend TEXT NOT NULL DEFAULT 'systemd-user',
            systemd_scope TEXT NOT NULL DEFAULT 'user',
            authoritative_unit TEXT,
            chronik_outbox_enabled INTEGER NOT NULL DEFAULT 0,
            chronik_outbox_state_root TEXT,
            chronik_context_json TEXT,
            terminalization_sha256 TEXT,
            terminalized_at_unix INTEGER,
            lifecycle_receipt_sha256 TEXT,
            repository_scope_manifest_json TEXT
        )
        """
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES('schema_version', '5')"
    )


def _migrate_task_schema(connection: sqlite3.Connection, version: str) -> None:
    columns = set(_task_column_shapes(connection))
    additions = (
        ("resource_keys_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("lease_owner_id", "TEXT"),
        ("request_id", "TEXT"),
        ("origin_ref", "TEXT"),
        ("external_run_id", "TEXT"),
        ("execution_envelope_sha256", "TEXT"),
        ("acceptance_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("request_sha256", "TEXT"),
        ("chronik_outbox_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ("chronik_outbox_state_root", "TEXT"),
        ("chronik_context_json", "TEXT"),
        ("execution_backend", "TEXT NOT NULL DEFAULT 'systemd-user'"),
        ("systemd_scope", "TEXT NOT NULL DEFAULT 'user'"),
        ("authoritative_unit", "TEXT"),
        ("terminalization_sha256", "TEXT"),
        ("terminalized_at_unix", "INTEGER"),
        ("lifecycle_receipt_sha256", "TEXT"),
        ("repository_scope_manifest_json", "TEXT"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE tasks ADD COLUMN {name} {definition}")
    if "execution_backend" in columns:
        connection.execute(
            "UPDATE tasks SET execution_backend='systemd-user' "
            "WHERE execution_backend IS NULL OR execution_backend=''"
        )
    if "systemd_scope" in columns:
        connection.execute(
            "UPDATE tasks SET systemd_scope='user' "
            "WHERE systemd_scope IS NULL OR systemd_scope=''"
        )
    connection.execute(
        "UPDATE tasks SET authoritative_unit=unit "
        "WHERE authoritative_unit IS NULL OR authoritative_unit=''"
    )
    connection.execute(
        "UPDATE metadata SET value='5' WHERE key='schema_version'"
    )


def _connect_existing_task_database() -> sqlite3.Connection:
    if TASK_DB.is_symlink():
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")
    connection = sqlite3.connect(
        TASK_DB.absolute().as_uri() + "?mode=rw",
        uri=True,
        timeout=10,
    )
    if TASK_DB.is_symlink():
        connection.close()
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")
    return connection


def _open_current_task_database() -> sqlite3.Connection:
    connection = _connect_existing_task_database()
    connection.row_factory = sqlite3.Row
    try:
        if _task_schema_version(connection) != "5":
            raise RuntimeError(
                "Task database schema changed while opening; retry with a compatible runtime"
            )
        _validate_task_schema_current(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        if stat.S_IMODE(TASK_DB.stat().st_mode) != 0o600:
            os.chmod(TASK_DB, 0o600)
        return connection
    except Exception:
        connection.close()
        raise


def _database() -> sqlite3.Connection:
    parent = TASK_DB.parent
    if parent.is_symlink():
        raise PermissionError(f"Task state directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if TASK_DB.is_symlink():
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")

    observed = _preflight_task_store()
    if observed == "5":
        return _open_current_task_database()

    with _schema_directory_lock(parent):
        observed = _preflight_task_store()
        if observed == "5":
            return _open_current_task_database()
        connection = (
            sqlite3.connect(TASK_DB, timeout=10)
            if observed is None
            else _connect_existing_task_database()
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            version = _task_schema_version(connection)
            if version not in {None, "1", "2", "3", "4", "5"}:
                raise RuntimeError(
                    "Unsupported task database schema; use a compatible runtime"
                )
            if version is None:
                if _database_tables(connection):
                    raise RuntimeError(
                        "Task database schema metadata is missing from an existing database"
                    )
                _create_task_schema_v5(connection)
            elif version == "5":
                _validate_task_schema_current(connection)
            else:
                _validate_task_schema_legacy(connection, version)
                _sqlite_integrity(connection, "Task database")
                fingerprint = _sqlite_fingerprint(connection)
                _verified_task_migration_backup(version, fingerprint)
                _migrate_task_schema(connection, version)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS tasks_state_created_task_idx "
                "ON tasks(state, created_at_unix DESC, task_id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS tasks_created_task_idx "
                "ON tasks(created_at_unix DESC, task_id DESC)"
            )
            if _task_schema_version(connection) != "5":
                raise RuntimeError("Task database migration did not reach schema 5")
            _validate_task_schema_current(connection)
            _sqlite_integrity(connection, "Migrated task database")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if stat.S_IMODE(TASK_DB.stat().st_mode) != 0o600:
                os.chmod(TASK_DB, 0o600)
            return connection
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            raise


def _command_requires_recovery(argv: list[str]) -> bool:
    names = [Path(item).name.lower() for item in argv if isinstance(item, str)]
    if not names:
        return False
    direct = {
        "shutdown", "reboot", "poweroff", "halt", "hibernate",
        "sleep-heimserver", "sleep-heim-pc", "sleep-heimberry",
    }
    if any(name in direct for name in names[:2]):
        return True
    joined = " ".join(item.lower() for item in argv)
    power_actions = (
        "systemctl poweroff", "systemctl reboot", "systemctl suspend",
        "systemctl hibernate", "loginctl poweroff", "loginctl reboot",
        "loginctl suspend", "loginctl hibernate",
    )
    return any(action in joined for action in power_actions)


def _require_recovery_gate(argv: list[str]) -> dict[str, Any]:
    if not _command_requires_recovery(argv):
        return {"required": False, "checked_at_unix": None}
    status = recovery.recovery_status()
    if not status["ready_for_user_power_worker"]:
        actions = status.get("required_actions", [])
        detail = "; ".join(actions) if actions else "recovery evidence is incomplete"
        raise PermissionError(f"Power-worker recovery gate is not ready: {detail}")
    return {**status, "required": True}


def _validate_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID.fullmatch(task_id) is None:
        raise ValueError("Invalid task id")
    return task_id


def _validate_unit(unit: str) -> str:
    if UNIT.fullmatch(unit) is None:
        raise ValueError("Invalid task unit")
    return unit


def _validate_execution_backend(value: str) -> str:
    if value not in TASK_EXECUTION_BACKENDS:
        raise ValueError("Invalid task execution backend")
    return value


def _validate_systemd_scope(value: str) -> str:
    if value not in SYSTEMD_SCOPES:
        raise ValueError("Invalid task systemd scope")
    return value


def _execution_backend(record: dict[str, Any]) -> str:
    return _validate_execution_backend(record.get("execution_backend") or "systemd-user")


def _systemd_scope(record: dict[str, Any]) -> str:
    return _validate_systemd_scope(record.get("systemd_scope") or "user")


def _authoritative_unit(record: dict[str, Any]) -> str:
    return _validate_unit(record.get("authoritative_unit") or record["unit"])


def _is_root_systemd_backend(record: dict[str, Any]) -> bool:
    return _execution_backend(record) == "systemd-root-broker"


def _execution_contract(target: dict[str, Any], command: list[str]) -> tuple[str, str]:
    if target["transport"] == "local" and _command_requires_recovery(command):
        return "systemd-root-broker", "system"
    return "systemd-user", "user"


def _task_unit(task_id: str, attempt: int) -> str:
    if attempt < 1:
        raise ValueError("Task attempt must be positive")
    return f"grabowski-task-{task_id}-a{attempt}.service"


def _validate_cwd(host: str, raw: str | None) -> str:
    candidate = str(operator.HOME) if raw is None else raw
    if not isinstance(candidate, str) or not candidate.startswith("/"):
        raise ValueError("Task cwd must be an absolute path")
    if len(candidate.encode("utf-8")) > 4096 or "\x00" in candidate:
        raise ValueError("Task cwd is too large or contains NUL")
    target = fleet.fleet_host(host)
    if target["transport"] == "local":
        return str(operator._resolve_cwd(candidate))
    return candidate


def _normalized_github_repository_slug(remote_url: str) -> str | None:
    value = remote_url.strip()
    prefixes = (
        "git@github.com:",
        "ssh://git@github.com/",
        "https://github.com/",
        "http://github.com/",
    )
    for prefix in prefixes:
        if value.startswith(prefix):
            slug = value[len(prefix):].rstrip("/")
            if slug.endswith(".git"):
                slug = slug[:-4]
            return slug or None
    return None


def _is_local_grabowski_checkout(cwd: str) -> bool:
    result = operator._run(
        ["git", "-C", cwd, "config", "--get", "remote.origin.url"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    if result.get("returncode") != 0:
        return False
    return (
        _normalized_github_repository_slug(str(result.get("stdout", "")))
        == GRABOWSKI_REPOSITORY_SLUG
    )


def _unqualified_python_index(command: list[str]) -> int | None:
    if command[0] in {"python", "python3"}:
        return 0
    if command[0] not in {"env", "/bin/env", "/usr/bin/env"}:
        return None
    for index, item in enumerate(command[1:], start=1):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item):
            continue
        return index if item in {"python", "python3"} else None
    return None


def _bind_grabowski_runtime_python(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    enabled: bool,
) -> list[str]:
    if not isinstance(enabled, bool):
        raise ValueError("runtime_python must be boolean")
    if not enabled:
        return command
    python_index = _unqualified_python_index(command)
    if python_index is None or target["transport"] != "local":
        return command
    if not _is_local_grabowski_checkout(cwd):
        return command
    if not GRABOWSKI_RUNTIME_PYTHON.is_file() or not os.access(
        GRABOWSKI_RUNTIME_PYTHON, os.X_OK
    ):
        raise RuntimeError("Grabowski runtime Python is unavailable")
    bound = list(command)
    bound[python_index] = str(GRABOWSKI_RUNTIME_PYTHON)
    return bound


def _explicit_cargo_target_dir(command: list[str]) -> bool:
    return any("CARGO_TARGET_DIR=" in item for item in command)


def _local_git_root(cwd: str) -> Path | None:
    result = operator._run(
        ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    if result.get("returncode") != 0:
        return None
    value = str(result.get("stdout", "")).strip()
    if not value or not value.startswith("/") or "\x00" in value:
        return None
    root = Path(value)
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _regular_cargo_lock(root: Path) -> bool:
    path = root / "Cargo.lock"
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _bounded_regular_text(candidate: Path, root: Path) -> str | None:
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        info = resolved.lstat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return None
    if info.st_size > MAX_BUILD_SCRIPT_INSPECTION_BYTES:
        return None
    try:
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _wrapper_definition_mentions_cargo(executable: str, root: Path) -> bool:
    names = (
        ("Justfile", "justfile", ".justfile")
        if executable == "just"
        else ("GNUmakefile", "makefile", "Makefile")
    )
    for name in names:
        text = _bounded_regular_text(root / name, root)
        if text is not None and CARGO_TOKEN.search(text) is not None:
            return True
    return False


def _text_may_invoke_cargo(text: str, root: Path) -> bool:
    if CARGO_TOKEN.search(text) is not None:
        return True
    if JUST_TOKEN.search(text) is not None and _wrapper_definition_mentions_cargo("just", root):
        return True
    if MAKE_TOKEN.search(text) is not None and _wrapper_definition_mentions_cargo("make", root):
        return True
    return False


def _bounded_script_mentions_cargo(candidate: Path, root: Path) -> bool:
    text = _bounded_regular_text(candidate, root)
    return text is not None and _text_may_invoke_cargo(text, root)

def _command_may_invoke_cargo(command: list[str], *, cwd: str, root: Path) -> bool:
    executable = Path(command[0]).name
    if executable == "cargo":
        return True
    if executable in {"just", "make"}:
        return _wrapper_definition_mentions_cargo(executable, root)
    if executable in {"env", "command"}:
        for index, item in enumerate(command[1:], start=1):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item):
                continue
            return _command_may_invoke_cargo(command[index:], cwd=cwd, root=root)
        return False
    if executable in SCRIPT_EXECUTABLES:
        if _text_may_invoke_cargo(" ".join(command[1:]), root):
            return True
        for item in command[1:]:
            if item.startswith("-"):
                continue
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = Path(cwd) / candidate
            if _bounded_script_mentions_cargo(candidate, root):
                return True
        return False
    executable_path = Path(command[0])
    if "/" in command[0]:
        if not executable_path.is_absolute():
            executable_path = Path(cwd) / executable_path
        return _bounded_script_mentions_cargo(executable_path, root)
    return False


def _managed_cargo_profile(command: list[str]) -> str:
    current = command
    if Path(current[0]).name in {"env", "command"}:
        for index, item in enumerate(current[1:], start=1):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item):
                continue
            return _managed_cargo_profile(current[index:])
        return MANAGED_CARGO_PROFILE
    if Path(current[0]).name != "cargo":
        return MANAGED_CARGO_PROFILE
    args = current[1:]
    if "--profile" in args:
        index = args.index("--profile")
        if index + 1 < len(args):
            value = args[index + 1]
            if value.replace("-", "").replace("_", "").isalnum():
                return value
    if "--release" in args:
        return "release"
    for candidate in ("test", "bench", "check", "doc"):
        if candidate in args:
            return candidate
    return "dev"


def _resolve_managed_cargo_target_dir(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    execution_backend: str,
) -> str | None:
    if target["transport"] != "local" or execution_backend != "systemd-user":
        return None
    if _explicit_cargo_target_dir(command):
        return None
    root = _local_git_root(cwd)
    if root is None or not _regular_cargo_lock(root):
        return None
    if not _command_may_invoke_cargo(command, cwd=cwd, root=root):
        return None
    try:
        resolver_info = MANAGED_BUILD_RESOLVER.lstat()
        python_resolved = MANAGED_BUILD_PYTHON.resolve(strict=True)
        python_info = python_resolved.stat()
    except OSError as exc:
        raise RuntimeError("Managed-build resolver runtime is unavailable") from exc
    if (
        stat.S_ISLNK(resolver_info.st_mode)
        or not stat.S_ISREG(resolver_info.st_mode)
        or not stat.S_ISREG(python_info.st_mode)
        or python_resolved.parent != Path("/usr/bin")
    ):
        raise RuntimeError("Managed-build resolver runtime is unsafe")
    profile = _managed_cargo_profile(command)
    result = operator._run(
        [
            str(MANAGED_BUILD_PYTHON),
            str(MANAGED_BUILD_RESOLVER),
            "prepare-environment",
            "--repo",
            str(root),
            "--tool",
            "cargo",
            "--profile",
            profile,
            "--executable",
            "cargo",
        ],
        cwd=operator.HOME,
        timeout_seconds=10,
        max_output_bytes=16 * 1024,
    )
    if result.get("returncode") != 0:
        raise RuntimeError("Managed-build resolver failed for Cargo task")
    try:
        payload = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Managed-build resolver returned invalid JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or payload.get("kind") != "heim_pc.managed_build_environment_prepared"
        or payload.get("tool") != "cargo"
        or payload.get("profile") != profile
        or payload.get("repository_root") != str(root)
    ):
        raise RuntimeError("Managed-build resolver returned an incompatible contract")
    environment = payload.get("environment")
    if not isinstance(environment, dict) or set(environment) != {"CARGO_TARGET_DIR"}:
        raise RuntimeError("Managed-build resolver returned an invalid Cargo environment")
    raw_target = environment.get("CARGO_TARGET_DIR")
    raw_cache = payload.get("cache_path")
    prepared_paths = payload.get("prepared_paths")
    if (
        not isinstance(raw_target, str)
        or not raw_target.startswith("/")
        or "\x00" in raw_target
        or not isinstance(raw_cache, str)
        or not raw_cache.startswith("/")
        or "\x00" in raw_cache
        or not isinstance(prepared_paths, list)
        or any(not isinstance(item, str) for item in prepared_paths)
    ):
        raise RuntimeError("Managed-build resolver returned an invalid Cargo target path")
    target_dir = Path(raw_target)
    cache_path = Path(raw_cache)
    try:
        relative_cache = cache_path.relative_to(MANAGED_CARGO_CACHE_ROOT)
    except ValueError as exc:
        raise RuntimeError("Managed-build resolver Cargo cache escapes the managed cache") from exc
    if len(relative_cache.parts) != 1 or target_dir != cache_path / "target":
        raise RuntimeError("Managed-build resolver returned an invalid Cargo cache binding")
    if str(cache_path) not in prepared_paths or str(target_dir) not in prepared_paths:
        raise RuntimeError("Managed-build resolver did not prepare the Cargo cache binding")
    if target_dir == root or root in target_dir.parents:
        raise RuntimeError("Managed-build resolver Cargo target points into the worktree")
    return str(target_dir)


def _bind_managed_cargo_environment(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    execution_backend: str,
) -> list[str]:
    cargo_target_dir = _resolve_managed_cargo_target_dir(
        command,
        target=target,
        cwd=cwd,
        execution_backend=execution_backend,
    )
    if cargo_target_dir is None:
        return command
    return [
        SYSTEMD_ENV_EXECUTABLE,
        f"CARGO_TARGET_DIR={cargo_target_dir}",
        *command,
    ]


def _validate_weights(cpu_weight: int, io_weight: int) -> tuple[int, int]:
    if not isinstance(cpu_weight, int) or not 1 <= cpu_weight <= 10_000:
        raise ValueError("cpu_weight must be between 1 and 10000")
    if not isinstance(io_weight, int) or not 1 <= io_weight <= 10_000:
        raise ValueError("io_weight must be between 1 and 10000")
    return cpu_weight, io_weight


def _validate_memory(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 16 * 1024 * 1024:
        raise ValueError("memory_max_bytes must be at least 16 MiB")
    return value


def _validate_chronik_outbox(
    enabled: bool,
    state_root: str | None,
) -> tuple[int, str | None]:
    if not isinstance(enabled, bool):
        raise ValueError("chronik_outbox must be boolean")
    if state_root in {None, ""}:
        return (1 if enabled else 0), None
    if not enabled:
        raise ValueError("chronik_outbox_state_root requires chronik_outbox")
    if not isinstance(state_root, str) or not state_root.startswith("/"):
        raise ValueError("chronik_outbox_state_root must be an absolute path")
    if len(state_root.encode("utf-8")) > 4096 or "\x00" in state_root:
        raise ValueError("chronik_outbox_state_root is too large or contains NUL")
    return 1, state_root


def _validate_chronik_operation(value: str, *, enabled: bool) -> str:
    if not isinstance(value, str) or value not in CHRONIK_OPERATION_TASK_CLASS:
        raise ValueError(
            f"chronik_operation must be one of {sorted(CHRONIK_OPERATION_TASK_CLASS)}"
        )
    if value != "other" and not enabled:
        raise ValueError("chronik_operation requires chronik_outbox")
    return value


def _validate_chronik_context_metadata(
    component: str,
    bureau_task_id: str,
    pr_number: int | None,
    *,
    enabled: bool,
) -> tuple[str, str, int | None]:
    values = {
        "chronik_component": (component, 160),
        "chronik_bureau_task_id": (bureau_task_id, 160),
    }
    normalized: dict[str, str] = {}
    for label, (value, maximum) in values.items():
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        candidate = value.strip()
        if len(candidate) > maximum or any(ord(character) < 32 for character in candidate):
            raise ValueError(f"{label} is invalid")
        normalized[label] = candidate
    if pr_number is not None and (
        isinstance(pr_number, bool)
        or not isinstance(pr_number, int)
        or not 1 <= pr_number <= 2_147_483_647
    ):
        raise ValueError("chronik_pr_number must be a positive bounded integer")
    if not enabled and (
        normalized["chronik_component"]
        or normalized["chronik_bureau_task_id"]
        or pr_number is not None
    ):
        raise ValueError("Chronik context metadata requires chronik_outbox")
    return (
        normalized["chronik_component"],
        normalized["chronik_bureau_task_id"],
        pr_number,
    )


def _validate_resume_policy(value: str) -> str:
    if value not in RESUME_POLICIES:
        raise ValueError(f"resume_policy must be one of {sorted(RESUME_POLICIES)}")
    return value


def _resource_keys(values: list[str] | None) -> list[str]:
    if values is None or values == []:
        return []
    return resources.normalize_resource_keys(values)


def _argument_value(argv: list[str], *names: str) -> str | None:
    for index, item in enumerate(argv):
        if item in names:
            if index + 1 >= len(argv):
                return None
            return argv[index + 1]
        for name in names:
            prefix = f"{name}="
            if item.startswith(prefix):
                return item[len(prefix):]
    return None


def _local_workspace_path(raw: str | None, *, cwd: str) -> str:
    candidate = Path(cwd) if raw in {None, ""} else Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    resolved = Path(operator._resolve_cwd(str(candidate)))
    for current in (resolved, *resolved.parents):
        marker = current / ".git"
        if marker.is_symlink():
            continue
        if marker.is_file() or marker.is_dir():
            return str(current)
    return str(resolved)


def _mutating_agent_workspace(
    host: str,
    argv: list[str],
    *,
    cwd: str,
) -> str | None:
    if fleet.fleet_host(host)["transport"] != "local":
        return None
    executable = Path(argv[0]).name.lower()
    if executable == "codex":
        sandbox = _argument_value(argv, "--sandbox", "-s")
        if sandbox in READ_ONLY_AGENT_MODES:
            return None
        return _local_workspace_path(_argument_value(argv, "-C", "--cd"), cwd=cwd)
    if executable in MUTATING_AGENT_EXECUTABLES - {"codex"}:
        permission_mode = _argument_value(argv, "--permission-mode")
        if permission_mode in READ_ONLY_AGENT_MODES:
            return None
        return _local_workspace_path(None, cwd=cwd)
    # Framework-managed writers already hold a workspace-level lease owned by
    # their workspace lifecycle. Inferring a second task-owned lease here would
    # make the formal workspace deadlock against itself.
    return None


def _task_resource_keys(
    host: str,
    argv: list[str],
    *,
    cwd: str,
    requested: list[str],
) -> tuple[list[str], str | None]:
    workspace = _mutating_agent_workspace(host, argv, cwd=cwd)
    if workspace is None:
        return requested, None
    if any(key.startswith(("path:", "repo:")) for key in requested):
        return requested, None
    implicit = resources.normalize_resource_key(f"repo:{workspace}")
    return sorted({*requested, implicit}), implicit


def _workspace_scope_identity(workspace: str) -> tuple[str, str]:
    head_result = operator._run(
        ["git", "-C", workspace, "rev-parse", "HEAD"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    raw_head = head_result.get("stdout", "").strip().lower()
    if head_result.get("returncode") == 0 and re.fullmatch(
        r"[0-9a-f]{40}(?:[0-9a-f]{24})?", raw_head
    ):
        head = raw_head
    else:
        head = "0" * 40
    branch_result = operator._run(
        ["git", "-C", workspace, "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    raw_branch = branch_result.get("stdout", "").strip()
    if branch_result.get("returncode") == 0 and re.fullmatch(
        r"[A-Za-z0-9._:@/+\-=]{1,512}", raw_branch
    ):
        branch = raw_branch
    elif head != "0" * 40:
        branch = f"detached/{head[:12]}"
    else:
        branch = "unversioned"
    return head, branch


def _whole_repository_scope_manifest(
    resource_key: str, task_id: str
) -> dict[str, Any]:
    if not resource_key.startswith("repo:"):
        raise ValueError("repository resource must use repo:<absolute-path> syntax")
    workspace = resource_key.removeprefix("repo:")
    head, branch = _workspace_scope_identity(workspace)
    return nonconflict.normalize_scope_manifest(
        {
            "schema_version": 1,
            "repository": workspace,
            "task_id": task_id,
            "base_head": head,
            "head": head,
            "branch": branch,
            "worktree": workspace,
            "effects": ["write"],
            "paths": [workspace],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
    )


def _task_repository_resource(resource_keys: list[str]) -> str | None:
    broad_repository_keys = [
        key
        for key in resource_keys
        if key.startswith("repo:")
        and resources.scoped_repository_resource_root(key) is None
    ]
    if not broad_repository_keys:
        return None
    if len(broad_repository_keys) != 1:
        raise ValueError("tasks may lease at most one broad repository")
    return broad_repository_keys[0]


def _record_implicit_workspace_resource(
    record: dict[str, Any], repository_resource: str | None
) -> str | None:
    if repository_resource is None:
        return None
    command = json.loads(record["argv_json"])
    workspace = _mutating_agent_workspace(
        str(record["host"]), command, cwd=str(record["cwd"])
    )
    if workspace is None:
        return None
    candidate = resources.normalize_resource_key(f"repo:{workspace}")
    return repository_resource if candidate == repository_resource else None


def _record_repository_scope_manifest(
    record: dict[str, Any], repository_resource: str | None
) -> dict[str, Any] | None:
    raw = record.get("repository_scope_manifest_json")
    if raw is None or raw == "":
        if repository_resource is None:
            return None
        return resources.repository_scope_manifest_for_owner(
            str(record.get("lease_owner_id") or _lease_owner(record["task_id"])),
            repository_resource,
        )
    if repository_resource is None:
        raise RuntimeError(
            "stored repository scope manifest has no broad repository resource"
        )
    try:
        manifest = nonconflict.normalize_scope_manifest(json.loads(str(raw)))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("stored repository scope manifest is invalid") from exc
    if f"repo:{manifest['repository']}" != repository_resource:
        raise RuntimeError(
            "stored repository scope manifest does not match repository resource"
        )
    return manifest


def _task_lease_metadata(
    *,
    task_id: str,
    host: str,
    attempt: int,
    repository_resource: str | None,
    implicit_workspace_resource: str | None,
    repository_scope_manifest: dict[str, Any] | None = None,
    recovered_after_expiry: bool = False,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "task_id": task_id,
        "host": host,
        "attempt": attempt,
        "implicit_workspace_resource_key": implicit_workspace_resource,
    }
    if recovered_after_expiry:
        metadata["recovered_after_expiry"] = True
    if repository_resource is not None:
        if repository_scope_manifest is None:
            raise RuntimeError(
                "repository scope manifest evidence is required for repository lease"
            )
        manifest = nonconflict.normalize_scope_manifest(repository_scope_manifest)
        if f"repo:{manifest['repository']}" != repository_resource:
            raise ValueError("repository scope manifest must match repository resource")
        metadata["scope_manifest"] = manifest
        metadata["scope_manifest_complete"] = True
    return metadata


def _chronik_context(
    host: str,
    resource_keys: list[str],
    operation: str,
    *,
    component: str = "",
    bureau_task_id: str = "",
    pr_number: int | None = None,
) -> str:
    context: dict[str, Any] = {
        "subject_scope": "host",
        "host": host,
        "operation": operation,
        "task_class": CHRONIK_OPERATION_TASK_CLASS[operation],
    }
    if component:
        context["component"] = component
    if bureau_task_id:
        context["bureau_task_id"] = bureau_task_id
    if pr_number is not None:
        context["pr_number"] = pr_number
    if fleet.fleet_host(host)["transport"] != "local":
        return _canonical_json(context)
    repositories = [key.removeprefix("repo:") for key in resource_keys if key.startswith("repo:")]
    if len(repositories) != 1:
        return _canonical_json(context)
    result = operator._run(
        ["git", "-C", repositories[0], "config", "--get", "remote.origin.url"],
        cwd=operator.HOME, timeout_seconds=5, max_output_bytes=4096,
    )
    if result["returncode"] != 0:
        return _canonical_json(context)
    remote = result["stdout"].strip()
    match = re.search(r"(?:github\.com[:/])(?P<slug>[^/\s]+/[^/\s]+?)(?:\.git)?$", remote)
    if match is None or not match.group("slug").startswith("heimgewebe/"):
        return _canonical_json(context)
    context.pop("host", None)
    context["subject_scope"] = "repository"
    context["repo"] = match.group("slug")
    return _canonical_json(context)


def _lease_owner(task_id: str) -> str:
    return f"task:{_validate_task_id(task_id)}"


def _record_resource_keys(record: dict[str, Any]) -> list[str]:
    raw = record.get("resource_keys_json") or "[]"
    values = json.loads(raw)
    if not isinstance(values, list):
        raise RuntimeError("Stored task resource keys are invalid")
    return [resources.normalize_resource_key(value) for value in values]


def _task_lease_ttl(record: dict[str, Any], state: str) -> int:
    if state == "outcome_unknown":
        # Unknown root truth must remain protected long enough for operator
        # recovery, but the lease is still bounded and therefore not permanent.
        return resources.MAX_TTL_SECONDS
    return min(
        resources.MAX_TTL_SECONDS,
        max(
            resources.MIN_TTL_SECONDS,
            int(record["runtime_seconds"]) + 300,
        ),
    )


def _effective_observed_state(record: dict[str, Any], observed_state: str) -> str:
    """Preserve authoritative terminal truth before lease maintenance."""
    stored_state = str(record["state"])
    return stored_state if _is_terminal_state(stored_state) else observed_state


def _maintain_record_resources(
    record: dict[str, Any],
    state: str,
) -> dict[str, Any] | None:
    if state not in LEASE_MAINTENANCE_TASK_STATES:
        return None
    keys = _record_resource_keys(record)
    if not keys:
        return None
    owner = record.get("lease_owner_id") or _lease_owner(record["task_id"])
    ttl = _task_lease_ttl(record, state)
    try:
        renewed = resources.renew_resources(owner, keys, ttl_seconds=ttl)
        leases = renewed.get("leases", [])
        return {
            "maintained": True,
            "mode": "renewed",
            "expires_at_unix": (
                min(int(item["expires_at_unix"]) for item in leases)
                if leases
                else None
            ),
        }
    except (ValueError, RuntimeError):
        # A lease may have expired between observations. Reacquire only when the
        # resource is still free; a foreign owner remains a hard conflict.
        try:
            repository_resource = _task_repository_resource(keys)
            implicit_workspace_resource = _record_implicit_workspace_resource(
                record, repository_resource
            )
            repository_scope_manifest = _record_repository_scope_manifest(
                record, repository_resource
            )
            acquired = resources.acquire_resources(
                owner,
                keys,
                purpose=f"persistent task {record['task_id']} lease recovery",
                ttl_seconds=ttl,
                metadata=_task_lease_metadata(
                    task_id=str(record["task_id"]),
                    host=str(record["host"]),
                    attempt=int(record["attempt"]),
                    repository_resource=repository_resource,
                    implicit_workspace_resource=implicit_workspace_resource,
                    repository_scope_manifest=repository_scope_manifest,
                    recovered_after_expiry=True,
                ),
            )
        except Exception as exc:
            return {
                "maintained": False,
                "mode": "failed",
                "error": _redact_reason(f"{type(exc).__name__}: {exc}"),
            }
        return {
            "maintained": True,
            "mode": "reacquired",
            "expires_at_unix": acquired.get("expires_at_unix"),
        }
    except Exception as exc:
        # Ownership drift is evidence, not a reason to hide task status. Keep
        # the task observable and surface the lease failure explicitly.
        return {
            "maintained": False,
            "mode": "failed",
            "error": _redact_reason(f"{type(exc).__name__}: {exc}"),
        }


def _validate_command(argv: list[str]) -> list[str]:
    command = operator._validate_argv(argv, cwd=operator.HOME)
    if operator._redact_argv(command) != command:
        raise ValueError("Task argv appears to contain secret material")
    return command


def _dispatch(host: str, argv: list[str], *, timeout_seconds: int = 60) -> dict[str, Any]:
    target = fleet.fleet_host(host)
    if target["transport"] == "local":
        return operator._run(
            argv,
            cwd=operator.HOME,
            timeout_seconds=timeout_seconds,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    remote = fleet.run_fleet_host(
        host,
        argv,
        timeout_seconds=timeout_seconds,
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )
    return remote["result"]


def _launch_argv(record: dict[str, Any]) -> list[str]:
    command = json.loads(record["argv_json"])
    unit = _authoritative_unit(record)
    argv = [
        "systemd-run",
        "--user",
        f"--description={operator._systemd_safe_description('task', unit, record['argv_sha256'])}",
        "--unit",
        unit,
        "--slice=grabowski-tasks.slice",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=LimitCORE=0",
        "--property=NoNewPrivileges=no",
        "--property=ProtectSystem=off",
        "--property=ProtectHome=no",
        "--property=PrivateTmp=no",
        "--property=MemoryDenyWriteExecute=no",
        "--property=UMask=0077",
        f"--property=RuntimeMaxSec={record['runtime_seconds']}s",
        f"--property=WorkingDirectory={record['cwd']}",
        f"--property=CPUWeight={record['cpu_weight']}",
        f"--property=IOWeight={record['io_weight']}",
    ]
    if record["memory_max_bytes"] is not None:
        argv.append(f"--property=MemoryMax={record['memory_max_bytes']}")
    return [*argv, "--", *command_identity.systemd_escape_argv(command)]


def _root_task_start_payload(record: dict[str, Any]) -> dict[str, Any]:
    unit = _authoritative_unit(record)
    return {
        "operation": "start",
        "unit": unit,
        "argv": json.loads(record["argv_json"]),
        "cwd": record["cwd"],
        "runtime_seconds": int(record["runtime_seconds"]),
        "cpu_weight": int(record["cpu_weight"]),
        "io_weight": int(record["io_weight"]),
        "memory_max_bytes": record["memory_max_bytes"],
        "description": operator._systemd_safe_description(
            "task",
            unit,
            record["argv_sha256"],
        ),
    }


def _root_task_payload(record: dict[str, Any], operation: str, **extra: Any) -> dict[str, Any]:
    return {"operation": operation, "unit": _authoritative_unit(record), **extra}


def _launch(record: dict[str, Any]) -> dict[str, Any]:
    if _is_root_systemd_backend(record):
        try:
            return privileged.root_task_systemd_request(
                _root_task_start_payload(record),
                timeout_seconds=60,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            # These failures occur before a structured broker response exists:
            # broker readiness, local reference creation or client execution
            # failed, so no accepted root dispatch is evidenced. Mark the
            # attempt failed and release its resources instead of stranding a
            # launching record. Once the client has contacted the broker, its
            # timeout and malformed-response paths return outcome_unknown.
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": _redact_reason(f"{type(exc).__name__}: {exc}"),
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "root_truth_observable": False,
                "outcome_unknown": False,
                "launch_not_dispatched": True,
                "privileged_broker": None,
            }
    return _dispatch(record["host"], _launch_argv(record), timeout_seconds=60)


def _launch_state(result: dict[str, Any]) -> str:
    if result.get("outcome_unknown"):
        return "outcome_unknown"
    return "running" if result["returncode"] == 0 else "failed"


def _row_raw(task_id: str) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    with _database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (identifier,)
        ).fetchone()
    if row is None:
        raise ValueError(f"Unknown task: {identifier}")
    return dict(row)


def _terminal_projection(
    record: dict[str, Any],
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
    unit: str | None = None,
    authoritative_unit: str | None = None,
    attempt: int | None = None,
) -> dict[str, Any]:
    return {
        "task_id": record["task_id"],
        "state": state,
        "updated_at_unix": _now(),
        "launcher_json": (
            record["launcher_json"]
            if launcher is None
            else _canonical_json(launcher)
        ),
        "last_observation_json": (
            record.get("last_observation_json")
            if observation is None
            else _canonical_json(observation)
        ),
        "unit": record["unit"] if unit is None else _validate_unit(unit),
        "authoritative_unit": (
            _authoritative_unit(record)
            if authoritative_unit is None
            else _validate_unit(authoritative_unit)
        ),
        "attempt": int(record["attempt"] if attempt is None else attempt),
    }


def _apply_terminalization_projection(
    terminalization: dict[str, Any], *, recovered: bool = False
) -> dict[str, Any]:
    projection = terminalization.get("task_projection")
    required = {
        "task_id", "state", "updated_at_unix", "launcher_json",
        "last_observation_json", "unit", "authoritative_unit", "attempt",
    }
    if not isinstance(projection, dict) or set(projection) != required:
        raise RuntimeError("Task terminalization projection is invalid")
    task_id = _validate_task_id(projection["task_id"])
    if task_id != terminalization.get("task_id"):
        raise RuntimeError("Task terminalization projection identity drift")
    state = projection["state"]
    if not _is_terminal_state(state) or state != terminalization.get("terminal_state"):
        raise RuntimeError("Task terminalization projection state drift")
    transition_sha256 = terminalization.get("transition_sha256")
    if not isinstance(transition_sha256, str) or SHA256.fullmatch(transition_sha256) is None:
        raise RuntimeError("Task terminalization digest is invalid")
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if current is None:
            connection.rollback()
            raise ValueError(f"Unknown task: {task_id}")
        current_record = dict(current)
        existing_digest = current_record.get("terminalization_sha256")
        if existing_digest not in {None, transition_sha256}:
            connection.rollback()
            raise RuntimeError("Task row is bound to another terminalization")
        if _is_terminal_state(current_record["state"]) and current_record["state"] != state:
            connection.rollback()
            raise RuntimeError("Task row terminal state conflicts with terminalization")
        connection.execute(
            """
            UPDATE tasks SET
                state=?, updated_at_unix=?, launcher_json=?,
                last_observation_json=?, unit=?, authoritative_unit=?, attempt=?,
                terminalization_sha256=?, terminalized_at_unix=?
            WHERE task_id=?
            """,
            (
                state,
                int(projection["updated_at_unix"]),
                str(projection["launcher_json"]),
                projection["last_observation_json"],
                _validate_unit(str(projection["unit"])),
                _validate_unit(str(projection["authoritative_unit"])),
                int(projection["attempt"]),
                transition_sha256,
                int(terminalization["leases_revoked_at_unix"]),
                task_id,
            ),
        )
        connection.commit()
    updated = _row_raw(task_id)
    observation = (
        json.loads(updated["last_observation_json"])
        if updated.get("last_observation_json")
        else None
    )
    receipt_sha256 = _write_outcome_receipt(
        updated,
        state,
        observation,
        terminalization=terminalization,
    )
    if receipt_sha256 is None:
        raise RuntimeError("Task lifecycle receipt was not emitted")
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT terminalization_sha256, lifecycle_receipt_sha256 "
            "FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None or row["terminalization_sha256"] != transition_sha256:
            connection.rollback()
            raise RuntimeError("Task terminalization projection changed before receipt binding")
        if row["lifecycle_receipt_sha256"] not in {None, receipt_sha256}:
            connection.rollback()
            raise RuntimeError("Task lifecycle receipt digest drift")
        connection.execute(
            "UPDATE tasks SET lifecycle_receipt_sha256=? WHERE task_id=?",
            (receipt_sha256, task_id),
        )
        connection.commit()
    resources.complete_task_terminalization(
        task_id,
        transition_sha256,
        receipt_sha256,
        recovered=recovered,
    )
    updated = _row_raw(task_id)
    chronik.record_task_state_safely(updated, state)
    return updated


def _recover_task_terminalization(task_id: str) -> dict[str, Any] | None:
    identifier = _validate_task_id(task_id)
    transition = resources.task_terminalization_record(
        identifier, include_projection=True
    )
    if transition is not None:
        record = _row_raw(identifier)
        if (
            transition["phase"] != "projected"
            or record.get("terminalization_sha256") != transition["transition_sha256"]
            or record.get("lifecycle_receipt_sha256")
            != transition.get("lifecycle_receipt_sha256")
        ):
            return _apply_terminalization_projection(transition, recovered=True)
        return record
    record = _row_raw(identifier)
    if not _is_terminal_state(str(record["state"])):
        return None
    projection = _terminal_projection(record, str(record["state"]))
    observation = (
        json.loads(record["last_observation_json"])
        if record.get("last_observation_json")
        else {}
    )
    transition = resources.begin_task_terminalization(
        identifier,
        int(record["attempt"]),
        record.get("lease_owner_id") or _lease_owner(identifier),
        str(record["state"]),
        _record_resource_keys(record),
        task_projection=projection,
        observation_sha256=_sha256_json(observation),
        recovery_status="recovered_legacy_row_first",
    )
    return _apply_terminalization_projection(transition, recovered=True)


def _recover_pending_task_terminalizations() -> list[str]:
    recovered: list[str] = []
    for terminalization in resources.pending_task_terminalizations():
        updated = _apply_terminalization_projection(terminalization, recovered=True)
        recovered.append(str(updated["task_id"]))
    return recovered


def _row(task_id: str) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    recovered = _recover_task_terminalization(identifier)
    return recovered if recovered is not None else _row_raw(identifier)

def _public(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "attempt": record["attempt"],
        "state": record["state"],
        "resume_policy": record["resume_policy"],
        "argv": operator._redact_argv(json.loads(record["argv_json"])),
        "argv_sha256": record["argv_sha256"],
        "cwd": record["cwd"],
        "runtime_seconds": record["runtime_seconds"],
        "cpu_weight": record["cpu_weight"],
        "io_weight": record["io_weight"],
        "memory_max_bytes": record["memory_max_bytes"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "launcher": json.loads(record["launcher_json"]),
        "last_observation": (
            json.loads(record["last_observation_json"])
            if record["last_observation_json"]
            else None
        ),
        "resource_keys": _record_resource_keys(record),
        "lease_owner_id": record.get("lease_owner_id"),
        "chronik_outbox_enabled": bool(record.get("chronik_outbox_enabled")),
        "chronik_outbox_state_root": record.get("chronik_outbox_state_root"),
        "chronik_context": json.loads(record["chronik_context_json"]) if record.get("chronik_context_json") else None,
        "terminalization_sha256": record.get("terminalization_sha256"),
        "terminalized_at_unix": record.get("terminalized_at_unix"),
        "lifecycle_receipt_sha256": record.get("lifecycle_receipt_sha256"),
    }


@contextmanager
def _database_connection() -> Iterator[sqlite3.Connection]:
    connection = _database()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


@contextmanager
def _task_read_snapshot() -> Iterator[sqlite3.Connection]:
    connection = _database()
    try:
        connection.execute("BEGIN DEFERRED")
        yield connection
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def _task_filter_states(state: str | None) -> tuple[str, ...] | None:
    if state is None:
        return None
    if state in TASK_STATES:
        return (state,)
    projection = TASK_STATE_PROJECTIONS.get(state)
    if projection is None:
        allowed = sorted(TASK_STATES | set(TASK_STATE_PROJECTIONS))
        raise ValueError(f"state must be one of {allowed}")
    return projection


def _task_state_counts(
    connection: sqlite3.Connection,
) -> tuple[dict[str, int], dict[str, int], int]:
    rows = connection.execute(
        "SELECT state, COUNT(*) AS count FROM tasks GROUP BY state"
    ).fetchall()
    exact = {state: 0 for state in sorted(TASK_STATES)}
    unknown_state_count = 0
    for row in rows:
        state = str(row["state"])
        count = int(row["count"])
        if state in exact:
            exact[state] = count
        else:
            unknown_state_count += count
    projections = {
        name: sum(exact[state] for state in states)
        for name, states in sorted(TASK_STATE_PROJECTIONS.items())
    }
    return exact, projections, unknown_state_count


def _task_recommended_next_action(state: str) -> str:
    if state in {"launching", "running"}:
        return "read grabowski_task_status before deciding the next action"
    if state == "interrupted":
        return "run grabowski_task_reconcile_check and read current status before any retry"
    if state == "outcome_unknown":
        return "reconcile and read post-state before any unchanged retry"
    if state in {"failed", "timed_out", "signalled"}:
        return "inspect bounded task logs and recovery evidence"
    if state == "completed":
        return "consume the outcome receipt and close external bookkeeping"
    if state == "cancelled":
        return "confirm resource release and retained evidence"
    return "inspect task status"


def _public_for_view(record: dict[str, Any], view: str) -> dict[str, Any]:
    full = _public(record)
    if view == "evidence":
        return full
    minimal = {
        "task_id": full["task_id"],
        "host": full["host"],
        "unit": full["unit"],
        "authoritative_unit": full["authoritative_unit"],
        "execution_backend": full["execution_backend"],
        "systemd_scope": full["systemd_scope"],
        "attempt": full["attempt"],
        "state": full["state"],
        "resume_policy": full["resume_policy"],
        "argv_sha256": full["argv_sha256"],
        "created_at_unix": full["created_at_unix"],
        "updated_at_unix": full["updated_at_unix"],
        "resource_keys": full["resource_keys"],
        "recommended_next_action": _task_recommended_next_action(full["state"]),
    }
    if view == "standard":
        minimal.update({
            "argv": full["argv"],
            "cwd": full["cwd"],
            "runtime_seconds": full["runtime_seconds"],
            "memory_max_bytes": full["memory_max_bytes"],
            "last_observation": full["last_observation"],
            "lease_owner_id": full["lease_owner_id"],
            "chronik_outbox_enabled": full["chronik_outbox_enabled"],
        })
    return minimal


def _set_state(
    task_id: str,
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
    unit: str | None = None,
    authoritative_unit: str | None = None,
    attempt: int | None = None,
) -> dict[str, Any]:
    if state not in TASK_STATES:
        raise ValueError("Invalid task state")
    identifier = _validate_task_id(task_id)
    current = _row_raw(identifier)
    existing_terminalization = resources.task_terminalization_record(
        identifier, include_projection=True
    )
    if existing_terminalization is not None:
        return _apply_terminalization_projection(
            existing_terminalization,
            recovered=existing_terminalization["phase"] != "projected",
        )
    if _is_terminal_state(current["state"]):
        recovered = _recover_task_terminalization(identifier)
        return recovered if recovered is not None else _row_raw(identifier)
    if _is_terminal_state(state):
        projection = _terminal_projection(
            current,
            state,
            launcher=launcher,
            observation=observation,
            unit=unit,
            authoritative_unit=authoritative_unit,
            attempt=attempt,
        )
        observation_material = observation
        if observation_material is None:
            observation_material = (
                json.loads(current["last_observation_json"])
                if current.get("last_observation_json")
                else {}
            )
        terminalization = resources.begin_task_terminalization(
            identifier,
            int(projection["attempt"]),
            current.get("lease_owner_id") or _lease_owner(identifier),
            state,
            _record_resource_keys(current),
            task_projection=projection,
            observation_sha256=_sha256_json(observation_material),
        )
        return _apply_terminalization_projection(terminalization)
    updates = ["state=?", "updated_at_unix=?"]
    values: list[Any] = [state, _now()]
    if launcher is not None:
        updates.append("launcher_json=?")
        values.append(_canonical_json(launcher))
    if observation is not None:
        updates.append("last_observation_json=?")
        values.append(_canonical_json(observation))
    if unit is not None:
        updates.append("unit=?")
        values.append(_validate_unit(unit))
    if authoritative_unit is not None:
        updates.append("authoritative_unit=?")
        values.append(_validate_unit(authoritative_unit))
    if attempt is not None:
        updates.append("attempt=?")
        values.append(attempt)
    values.append(identifier)
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        current_row = connection.execute(
            "SELECT state, terminalization_sha256 FROM tasks WHERE task_id=?",
            (identifier,),
        ).fetchone()
        if current_row is None:
            connection.rollback()
            raise ValueError(f"Unknown task: {identifier}")
        if current_row["terminalization_sha256"] is not None or _is_terminal_state(
            current_row["state"]
        ):
            connection.rollback()
            recovered = _recover_task_terminalization(identifier)
            return recovered if recovered is not None else _row_raw(identifier)
        connection.execute(
            f"UPDATE tasks SET {', '.join(updates)} WHERE task_id=?",
            values,
        )
        connection.commit()
    updated = _row_raw(identifier)
    chronik.record_task_state_safely(updated, state)
    return updated

def _observe(record: dict[str, Any]) -> dict[str, Any]:
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(
                record,
                "show",
                properties=list(fleet.TASK_UNIT_SHOW_PROPERTIES),
            ),
            timeout_seconds=30,
            max_output_bytes=8192,
        )
        observer: dict[str, Any] = {
            "kind": "root-systemd-broker-show-v1",
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
        }
        properties: dict[str, str] = {}
        for line in result.get("stdout", "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        state = "outcome_unknown" if result.get("outcome_unknown") else _classify_observation(result, properties)
        return {
            "state": state,
            "properties": properties,
            "probe": result,
            "observer": observer,
            "observed_at_unix": _now(),
        }

    command = [
        "systemctl",
        "--user",
        "show",
        _authoritative_unit(record),
        "--no-pager",
    ]
    command.extend(f"--property={item}" for item in fleet.TASK_UNIT_SHOW_PROPERTIES)
    observer: dict[str, Any] = {
        "kind": "fleet-dispatch-v1",
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
    }
    try:
        result = _dispatch(record["host"], command, timeout_seconds=30)
    except fleet.FleetCommandDenied:
        # Production hosts intentionally do not expose generic systemctl through
        # fleet_run.  Reconcile still needs one fixed read-only observation shape
        # for Grabowski-owned task units, so fall back to the narrow fleet helper.
        observed = fleet.run_fleet_task_unit_show(
            record["host"],
            _authoritative_unit(record),
            fleet.TASK_UNIT_SHOW_PROPERTIES,
            timeout_seconds=30,
            max_output_bytes=8192,
        )
        result = observed["result"]
        observer = {
            "host": observed["host"],
            "transport": observed["transport"],
            "roles": observed["roles"],
            "kind": observed["observer"],
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
            "fallback_from": "fleet-dispatch-permission-denied",
        }
    properties: dict[str, str] = {}
    for line in result.get("stdout", "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    state = _classify_observation(result, properties)
    return {
        "state": state,
        "properties": properties,
        "probe": result,
        "observer": observer,
        "observed_at_unix": _now(),
    }


def server_task_lease_delegation_evidence(lease_owner_id: str) -> dict[str, Any]:
    """Validate one live task and its complete current lease set for server delegation."""
    if not isinstance(lease_owner_id, str):
        raise ValueError("task lease owner must be text")
    match = re.fullmatch(r"task:([0-9a-f]{24})", lease_owner_id)
    if match is None:
        raise ValueError("task lease owner is invalid")
    task_id = match.group(1)
    record = _row(task_id)
    effective_owner = record.get("lease_owner_id") or _lease_owner(task_id)
    if effective_owner != lease_owner_id:
        raise ValueError("task record lease owner mismatch")
    state = str(record.get("state", ""))
    if state not in TASK_LEASE_DELEGATION_STATES:
        raise ValueError(f"task state does not permit lease delegation: {state}")
    resource_keys = _record_resource_keys(record)
    if not resource_keys:
        raise ValueError("task has no resource leases to delegate")
    lease_evidence = resources.task_lease_delegation_evidence(
        lease_owner_id,
        task_id,
        resource_keys,
    )
    task_binding = {
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "state": state,
        "attempt": int(record["attempt"]),
        "updated_at_unix": int(record["updated_at_unix"]),
        "resource_keys_sha256": lease_evidence["resource_keys_sha256"],
        "lease_bindings_sha256": lease_evidence["lease_bindings_sha256"],
    }
    return {
        "schema_version": 1,
        "kind": "grabowski_live_task_lease_delegation_evidence",
        **task_binding,
        "task_record_sha256": _sha256_json(task_binding),
        "resource_keys": lease_evidence["resource_keys"],
        "minimum_expires_at_unix": lease_evidence["minimum_expires_at_unix"],
        "observed_at_unix": lease_evidence["observed_at_unix"],
    }


@mcp.tool(name="grabowski_task_start", annotations=MUTATING)
def grabowski_task_start(
    host: str,
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = operator.DEFAULT_JOB_RUNTIME,
    resume_policy: str = "verify-then-retry",
    cpu_weight: int = 100,
    io_weight: int = 100,
    memory_max_bytes: int | None = None,
    resource_keys: list[str] | None = None,
    chronik_outbox: bool = False,
    chronik_outbox_state_root: str | None = None,
    chronik_operation: str = "other",
    chronik_component: str = "",
    chronik_bureau_task_id: str = "",
    chronik_pr_number: int | None = None,
    runtime_python: bool = False,
) -> dict[str, Any]:
    """Start one persistent local or fleet task in its own systemd unit.

    Direct local write-capable agent CLIs receive an implicit repository lease
    unless the caller supplies an explicit path or repository scope. Every
    task-owned broad repository lease carries a complete whole-repository scope manifest.
    """
    target = fleet.fleet_host(host)
    command = _validate_command(argv)
    recovery_gate = _require_recovery_gate(command)
    working_directory = _validate_cwd(host, cwd)
    command = _bind_grabowski_runtime_python(
        command,
        target=target,
        cwd=working_directory,
        enabled=runtime_python,
    )
    runtime = operator._job_runtime(runtime_seconds)
    policy = _validate_resume_policy(resume_policy)
    cpu, io = _validate_weights(cpu_weight, io_weight)
    memory = _validate_memory(memory_max_bytes)
    chronik_enabled, chronik_state_root = _validate_chronik_outbox(
        chronik_outbox,
        chronik_outbox_state_root,
    )
    chronik_operation = _validate_chronik_operation(
        chronik_operation, enabled=bool(chronik_enabled)
    )
    chronik_component, chronik_bureau_task_id, chronik_pr_number = (
        _validate_chronik_context_metadata(
            chronik_component,
            chronik_bureau_task_id,
            chronik_pr_number,
            enabled=bool(chronik_enabled),
        )
    )
    requested_resources = _resource_keys(resource_keys)
    task_resources, implicit_workspace_resource = _task_resource_keys(
        host,
        command,
        cwd=working_directory,
        requested=requested_resources,
    )
    chronik_context_json = (
        _chronik_context(
            host,
            task_resources,
            chronik_operation,
            component=chronik_component,
            bureau_task_id=chronik_bureau_task_id,
            pr_number=chronik_pr_number,
        )
        if chronik_enabled
        else None
    )
    task_id = uuid.uuid4().hex[:24]
    lease_owner = _lease_owner(task_id)
    repository_resource = _task_repository_resource(task_resources)
    repository_scope_manifest = (
        _whole_repository_scope_manifest(repository_resource, task_id)
        if repository_resource is not None
        else None
    )
    execution_backend, systemd_scope = _execution_contract(target, command)
    if (
        execution_backend == "systemd-root-broker"
        and runtime + 300 > resources.MAX_TTL_SECONDS
    ):
        raise ValueError(
            "root task runtime must leave 300 seconds of lease and stop grace"
        )
    operator._require_operator_mutation(
        "durable_job",
        path=working_directory,
        repo=working_directory,
        task_id=task_id,
        owner_id=lease_owner,
        host=host,
        opaque_command=True,
    )
    command = _bind_managed_cargo_environment(
        command,
        target=target,
        cwd=working_directory,
        execution_backend=execution_backend,
    )
    attempt = 1
    unit = _task_unit(task_id, attempt)
    now = _now()
    record = {
        "task_id": task_id,
        "host": host,
        "unit": unit,
        "authoritative_unit": unit,
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
        "attempt": attempt,
        "state": "launching",
        "resume_policy": policy,
        "argv_json": _canonical_json(command),
        "argv_sha256": command_identity.argv_sha256(command),
        "cwd": working_directory,
        "runtime_seconds": runtime,
        "cpu_weight": cpu,
        "io_weight": io,
        "memory_max_bytes": memory,
        "created_at_unix": now,
        "updated_at_unix": now,
        "launcher_json": _canonical_json({"pending": True}),
        "last_observation_json": None,
        "resource_keys_json": _canonical_json(task_resources),
        "lease_owner_id": lease_owner,
        "chronik_outbox_enabled": chronik_enabled,
        "chronik_outbox_state_root": chronik_state_root,
        "chronik_context_json": chronik_context_json,
        "repository_scope_manifest_json": (
            _canonical_json(repository_scope_manifest)
            if repository_scope_manifest is not None
            else None
        ),
    }
    lease_result = None
    lease_metadata = None
    if task_resources:
        lease_metadata = _task_lease_metadata(
            task_id=task_id,
            host=host,
            attempt=attempt,
            repository_resource=repository_resource,
            implicit_workspace_resource=implicit_workspace_resource,
            repository_scope_manifest=repository_scope_manifest,
        )
        lease_result = resources.acquire_resources(
            lease_owner,
            task_resources,
            purpose=f"persistent task {task_id}",
            ttl_seconds=min(
                resources.MAX_TTL_SECONDS,
                max(resources.MIN_TTL_SECONDS, runtime + 300),
            ),
            metadata=lease_metadata,
        )
    try:
        with _database_connection() as connection:
            connection.execute(
            """
            INSERT INTO tasks(
                task_id, host, unit, attempt, state, resume_policy,
                argv_json, argv_sha256, cwd, runtime_seconds,
                cpu_weight, io_weight, memory_max_bytes,
                created_at_unix, updated_at_unix, launcher_json,
                last_observation_json, resource_keys_json, lease_owner_id,
                execution_backend, systemd_scope, authoritative_unit,
                chronik_outbox_enabled, chronik_outbox_state_root,
                chronik_context_json, repository_scope_manifest_json
            ) VALUES(
                :task_id, :host, :unit, :attempt, :state, :resume_policy,
                :argv_json, :argv_sha256, :cwd, :runtime_seconds,
                :cpu_weight, :io_weight, :memory_max_bytes,
                :created_at_unix, :updated_at_unix, :launcher_json,
                :last_observation_json, :resource_keys_json, :lease_owner_id,
                :execution_backend, :systemd_scope, :authoritative_unit,
                :chronik_outbox_enabled, :chronik_outbox_state_root,
                :chronik_context_json, :repository_scope_manifest_json
            )
            """,
                record,
            )
            connection.commit()
    except Exception:
        if task_resources:
            resources.release_resources(lease_owner, task_resources)
        raise
    launcher = _launch(record)
    state = _launch_state(launcher)
    stored = _set_state(task_id, state, launcher=launcher)
    lease_maintenance = _maintain_record_resources(stored, state)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-start",
        "task_id": task_id,
        "host": host,
        "transport": target["transport"],
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
        "authoritative_unit": unit,
        "argv_sha256": record["argv_sha256"],
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
        "launcher_outcome_unknown": bool(launcher.get("outcome_unknown")),
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "requested_resource_keys": requested_resources,
        "implicit_workspace_resource_key": implicit_workspace_resource,
        "repository_scope_manifest_sha256": (
            hashlib.sha256(
                _canonical_json(lease_metadata["scope_manifest"]).encode("utf-8")
            ).hexdigest()
            if lease_metadata is not None and "scope_manifest" in lease_metadata
            else None
        ),
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


@mcp.tool(name="grabowski_task_status", annotations=READ_ONLY)
def grabowski_task_status(task_id: str) -> dict[str, Any]:
    """Observe one persistent task and refresh its recorded state."""
    operator._require_operator_capability("durable_job")
    record = _row(task_id)
    observation = _observe(record)
    effective_state = _effective_observed_state(record, observation["state"])
    lease_maintenance = _maintain_record_resources(record, effective_state)
    if lease_maintenance is not None:
        observation["lease_maintenance"] = lease_maintenance
    stored = _set_state(
        task_id,
        observation["state"],
        observation=observation,
    )
    result = _public(stored)
    result["lease_maintenance"] = lease_maintenance
    return result


@mcp.tool(name="grabowski_task_logs", annotations=READ_ONLY)
def grabowski_task_logs(task_id: str, max_lines: int = 200) -> dict[str, Any]:
    """Read redacted journal output for one local or fleet task."""
    operator._require_operator_capability("durable_job")
    if not isinstance(max_lines, int) or not 1 <= max_lines <= 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    record = _row(task_id)
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(record, "journal", max_lines=max_lines),
            timeout_seconds=30,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    else:
        result = _dispatch(
            record["host"],
            [
                "journalctl",
                "--user",
                "--unit",
                _authoritative_unit(record),
                "--no-pager",
                "--output=cat",
                "--lines",
                str(max_lines),
            ],
            timeout_seconds=30,
        )
    return {
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "result": result,
    }


@mcp.tool(name="grabowski_task_cancel", annotations=MUTATING)
def grabowski_task_cancel(task_id: str) -> dict[str, Any]:
    """Stop one task process group and retain its persistent task record."""
    record = _row(task_id)
    operator._require_operator_mutation(
        "durable_job",
        path=record["cwd"],
        repo=record["cwd"],
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
    )
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(record, "stop"),
            timeout_seconds=60,
        )
    else:
        result = _dispatch(
            record["host"],
            ["systemctl", "--user", "stop", _authoritative_unit(record)],
            timeout_seconds=60,
        )
    if result.get("outcome_unknown"):
        state = "outcome_unknown"
    else:
        state = "cancelled" if result["returncode"] == 0 else record["state"]
    cancel_observation = {"cancel": result}
    effective_state = _effective_observed_state(record, state)
    lease_maintenance = _maintain_record_resources(record, effective_state)
    if lease_maintenance is not None:
        cancel_observation["lease_maintenance"] = lease_maintenance
    stored = _set_state(task_id, state, observation=cancel_observation)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-cancel",
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "returncode": result["returncode"],
        "outcome_unknown": bool(result.get("outcome_unknown")),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "result": result, "audit": audit}


@mcp.tool(name="grabowski_task_resume", annotations=MUTATING)
def grabowski_task_resume(task_id: str) -> dict[str, Any]:
    """Recreate a missing or stopped task unit from its persistent record."""
    record = _row(task_id)
    operator._require_operator_mutation(
        "durable_job",
        path=record["cwd"],
        repo=record["cwd"],
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
        opaque_command=True,
    )
    if _is_terminal_state(record["state"]):
        raise RuntimeError("Terminal task cannot be resumed")
    if record["resume_policy"] in {"never", "manual"}:
        raise PermissionError("Task resume policy does not permit automatic retry")
    command = json.loads(record["argv_json"])
    recovery_gate = _require_recovery_gate(command)
    observation = _observe(record)
    if observation["state"] == "running":
        raise RuntimeError("Task is still running")
    if observation["state"] == "completed":
        stored = _set_state(
            task_id,
            "completed",
            observation=observation,
        )
        raise RuntimeError("Task already completed; refusing retry")
    if observation["state"] == "outcome_unknown":
        _set_state(
            task_id,
            "outcome_unknown",
            observation=observation,
        )
        raise RuntimeError("Task outcome is unknown; verify the authoritative unit before retry")
    attempt = int(record["attempt"]) + 1
    unit = _task_unit(task_id, attempt)
    candidate = {**record, "attempt": attempt, "unit": unit, "authoritative_unit": unit}
    task_resources = _record_resource_keys(record)
    lease_owner = record.get("lease_owner_id") or _lease_owner(task_id)
    lease_result = None
    if task_resources:
        lease_result = resources.acquire_resources(
            lease_owner,
            task_resources,
            purpose=f"persistent task {task_id}",
            ttl_seconds=min(
                resources.MAX_TTL_SECONDS,
                max(resources.MIN_TTL_SECONDS, int(record["runtime_seconds"]) + 300),
            ),
            metadata={
                "task_id": task_id,
                "host": record["host"],
                "attempt": attempt,
            },
        )
    launcher = _launch(candidate)
    state = _launch_state(launcher)
    stored = _set_state(
        task_id,
        state,
        launcher=launcher,
        observation=observation,
        unit=unit,
        authoritative_unit=unit,
        attempt=attempt,
    )
    lease_maintenance = _maintain_record_resources(stored, state)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-resume",
        "task_id": task_id,
        "host": record["host"],
        "attempt": attempt,
        "unit": unit,
        "authoritative_unit": unit,
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "launcher_returncode": launcher["returncode"],
        "launcher_outcome_unknown": bool(launcher.get("outcome_unknown")),
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


def _reconcile_candidate_rows(task_id: str = "") -> list[dict[str, Any]]:
    if task_id:
        record = _row(task_id)
        return (
            [record]
            if record["state"] in {"launching", "running", "outcome_unknown"}
            else []
        )
    _recover_pending_task_terminalizations()
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE state IN ('launching', 'running', 'outcome_unknown') "
            "ORDER BY created_at_unix, task_id"
        ).fetchall()
    return [dict(row) for row in rows]


def _reconcile_blocker(record: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any] | None:
    if observation["state"] == "running":
        return None
    if observation["state"] == "completed":
        return {
            "task_id": record["task_id"],
            "resume_policy": record["resume_policy"],
            "reason": "completed task does not require resume",
        }
    if observation["state"] == "outcome_unknown":
        return {
            "task_id": record["task_id"],
            "resume_policy": record["resume_policy"],
            "reason": "outcome_unknown requires verification before retry",
        }
    if record["resume_policy"] != "retry-safe":
        return {
            "task_id": record["task_id"],
            "resume_policy": record["resume_policy"],
            "reason": "automatic resume requires retry-safe policy",
        }
    return None


def _reconcile_observe_denial(record: dict[str, Any], exc: PermissionError) -> dict[str, Any]:
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "current_state": record["state"],
        "resume_policy": record["resume_policy"],
        "reason": f"observation denied: {_redact_reason(str(exc))}",
    }


def reconcile_tasks_check(*, task_id: str = "") -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    rows = _reconcile_candidate_rows(task_id)
    observations: list[dict[str, Any]] = []
    would_refresh: list[dict[str, Any]] = []
    would_release: list[str] = []
    would_resume: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for record in rows:
        try:
            observation = _observe(record)
        except PermissionError as exc:
            blocked.append(_reconcile_observe_denial(record, exc))
            continue
        item = {
            "task_id": record["task_id"],
            "current_state": record["state"],
            "observed_state": observation["state"],
            "resume_policy": record["resume_policy"],
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
            "resource_keys": _record_resource_keys(record),
        }
        observations.append(item)
        if observation["state"] != record["state"]:
            would_refresh.append(item)
        if _state_releases_resources(observation["state"]):
            would_release.append(record["task_id"])
        blocker = _reconcile_blocker(record, observation)
        if blocker is not None:
            blocked.append(blocker)
        elif observation["state"] != "running":
            would_resume.append(item)
    return {
        "mode": "check",
        "task_id": task_id,
        "scanned": len(rows),
        "observations": observations,
        "would_refresh": would_refresh,
        "would_release": would_release,
        "would_resume": would_resume,
        "blocked": blocked,
        "checked_at_unix": _now(),
    }


def reconcile_tasks_refresh(*, task_id: str = "") -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    rows = _reconcile_candidate_rows(task_id)
    refreshed: list[dict[str, Any]] = []
    released: list[str] = []
    denied: list[dict[str, Any]] = []
    for record in rows:
        try:
            observation = _observe(record)
        except PermissionError as exc:
            denied.append(_reconcile_observe_denial(record, exc))
            continue
        effective_state = _effective_observed_state(record, observation["state"])
        lease_maintenance = _maintain_record_resources(record, effective_state)
        if lease_maintenance is not None:
            observation["lease_maintenance"] = lease_maintenance
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if _state_releases_resources(observation["state"]):
            released.append(stored["task_id"])
        public = _public(stored)
        public["lease_maintenance"] = lease_maintenance
        refreshed.append(public)
    return {
        "mode": "refresh",
        "task_id": task_id,
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": [],
        "blocked": denied,
        "checked_at_unix": _now(),
    }


def reconcile_tasks_resume(
    *,
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    if not isinstance(max_resumes, int) or not 1 <= max_resumes <= 50:
        raise ValueError("max_resumes must be between 1 and 50")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason is required for task reconcile resume")
    rows = _reconcile_candidate_rows(task_id)
    refreshed: list[dict[str, Any]] = []
    released: list[str] = []
    resumed: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for record in rows:
        try:
            observation = _observe(record)
        except PermissionError as exc:
            blocked.append(_reconcile_observe_denial(record, exc))
            continue
        effective_state = _effective_observed_state(record, observation["state"])
        lease_maintenance = _maintain_record_resources(record, effective_state)
        if lease_maintenance is not None:
            observation["lease_maintenance"] = lease_maintenance
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if _state_releases_resources(observation["state"]):
            released.append(stored["task_id"])
        public = _public(stored)
        public["lease_maintenance"] = lease_maintenance
        refreshed.append(public)
        if observation["state"] == "running":
            continue
        blocker = _reconcile_blocker(stored, observation)
        if blocker is not None:
            blocked.append(blocker)
            continue
        if len(resumed) >= max_resumes:
            blocked.append(
                {
                    "task_id": stored["task_id"],
                    "resume_policy": stored["resume_policy"],
                    "reason": "max_resumes reached",
                }
            )
            continue
        try:
            resumed.append(grabowski_task_resume(stored["task_id"])["task"])
        except Exception as exc:
            blocked.append(
                {
                    "task_id": stored["task_id"],
                    "resume_policy": stored["resume_policy"],
                    "reason": _redact_reason(str(exc)),
                }
            )
    return {
        "mode": "resume",
        "task_id": task_id,
        "max_resumes": max_resumes,
        "reason": _redact_reason(reason.strip()),
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": resumed,
        "blocked": blocked,
        "checked_at_unix": _now(),
    }


def reconcile_tasks(*, auto_resume: bool = False) -> dict[str, Any]:
    if not isinstance(auto_resume, bool):
        raise ValueError("auto_resume must be boolean")
    if auto_resume:
        preview = reconcile_tasks_check()
        result = reconcile_tasks_refresh()
        disabled = [
            {
                "task_id": item["task_id"],
                "resume_policy": item["resume_policy"],
                "reason": "legacy auto_resume reconcile is disabled; use explicit resume mode",
            }
            for item in preview["would_resume"]
        ]
        return {
            "auto_resume": auto_resume,
            "legacy_auto_resume_disabled": True,
            "scanned": result["scanned"],
            "refreshed": result["refreshed"],
            "resumed": [],
            "blocked": [*preview["blocked"], *disabled],
            "checked_at_unix": result["checked_at_unix"],
        }
    result = reconcile_tasks_refresh()
    return {
        "auto_resume": auto_resume,
        "scanned": result["scanned"],
        "refreshed": result["refreshed"],
        "resumed": result["resumed"],
        "blocked": result["blocked"],
        "checked_at_unix": result["checked_at_unix"],
    }


@mcp.tool(name="grabowski_task_reconcile_check", annotations=READ_ONLY)
def grabowski_task_reconcile_check(task_id: str = "") -> dict[str, Any]:
    """Read-only reconcile preview for persistent tasks."""
    operator._require_operator_capability("durable_job")
    return reconcile_tasks_check(task_id=task_id)


@mcp.tool(name="grabowski_task_reconcile_refresh", annotations=MUTATING)
def grabowski_task_reconcile_refresh(task_id: str = "") -> dict[str, Any]:
    """Refresh persistent task states without resuming processes."""
    operator._require_operator_mutation("durable_job")
    result = reconcile_tasks_refresh(task_id=task_id)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile-refresh",
            "task_id": task_id,
            "scanned": result["scanned"],
            "released_count": len(result["released"]),
        }
    )
    return result


@mcp.tool(name="grabowski_task_reconcile_resume", annotations=MUTATING)
def grabowski_task_reconcile_resume(
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    """Resume retry-safe tasks after reconcile verification."""
    operator._require_operator_mutation("durable_job")
    result = reconcile_tasks_resume(
        task_id=task_id,
        max_resumes=max_resumes,
        reason=reason,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile-resume",
            "task_id": task_id,
            "max_resumes": max_resumes,
            "reason": result["reason"],
            "scanned": result["scanned"],
            "resumed_count": len(result["resumed"]),
            "blocked_count": len(result["blocked"]),
        }
    )
    return result


@mcp.tool(name="grabowski_task_reconcile", annotations=MUTATING)
def grabowski_task_reconcile(auto_resume: bool = False) -> dict[str, Any]:
    """Reconcile persistent tasks after process loss or host restart."""
    operator._require_operator_mutation("durable_job")
    result = reconcile_tasks(auto_resume=auto_resume)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile",
            "auto_resume": auto_resume,
            "scanned": result["scanned"],
            "resumed_count": len(result["resumed"]),
            "blocked_count": len(result["blocked"]),
        }
    )
    return result


@mcp.tool(name="grabowski_task_list", annotations=READ_ONLY)
def grabowski_task_list(
    limit: int = DEFAULT_TASK_LIST_LIMIT,
    state: str | None = None,
    view: str = "minimal",
    cursor: str | None = None,
    fields: list[str] | None = None,
    schema_only: bool = False,
) -> dict[str, Any]:
    """List persistent tasks or inspect store-schema compatibility read-only."""
    operator._require_operator_capability("durable_job")
    if not isinstance(schema_only, bool):
        raise ValueError("schema_only must be boolean")
    if schema_only:
        if (
            limit != DEFAULT_TASK_LIST_LIMIT
            or state is not None
            or view != "minimal"
            or cursor is not None
            or fields is not None
        ):
            raise ValueError(
                "schema_only cannot be combined with task-list filters or projections"
            )
        return _task_schema_inventory()
    selected_view = consumer_surface.normalize_view(view)
    _recover_pending_task_terminalizations()
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    filter_states = _task_filter_states(state)
    scope = f"task-list:{selected_view}:{state or 'all'}"
    position = consumer_surface.decode_cursor(cursor, scope)
    cursor_created_at: int | None = None
    cursor_task_id: str | None = None
    if position is not None:
        cursor_created_at = position.get("created_at_unix")
        cursor_task_id = position.get("task_id")
        if (
            isinstance(cursor_created_at, bool)
            or not isinstance(cursor_created_at, int)
            or cursor_created_at < 0
            or not isinstance(cursor_task_id, str)
            or not TASK_ID.fullmatch(cursor_task_id)
        ):
            raise ValueError("cursor position is invalid")
    where: list[str] = []
    parameters: list[Any] = []
    if filter_states is not None:
        placeholders = ",".join("?" for _ in filter_states)
        where.append(f"state IN ({placeholders})")
        parameters.extend(filter_states)
    if cursor_created_at is not None and cursor_task_id is not None:
        where.append("(created_at_unix < ? OR (created_at_unix = ? AND task_id < ?))")
        parameters.extend([cursor_created_at, cursor_created_at, cursor_task_id])
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    with _task_read_snapshot() as connection:
        rows = connection.execute(
            f"SELECT * FROM tasks{where_sql} "
            "ORDER BY created_at_unix DESC, task_id DESC LIMIT ?",
            (*parameters, limit + 1),
        ).fetchall()
        state_counts, projection_counts, unknown_state_count = _task_state_counts(connection)
        if filter_states is None:
            total_matching = sum(state_counts.values()) + unknown_state_count
        else:
            total_matching = sum(state_counts[item] for item in filter_states)
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    tasks = [_public_for_view(dict(row), selected_view) for row in page_rows]
    next_cursor = None
    if has_more and page_rows:
        last = dict(page_rows[-1])
        next_cursor = consumer_surface.encode_cursor(
            scope,
            {
                "created_at_unix": int(last["created_at_unix"]),
                "task_id": str(last["task_id"]),
            },
        )
    warning_states = {
        "interrupted",
        "failed",
        "timed_out",
        "signalled",
        "outcome_unknown",
    }
    warnings: list[dict[str, Any]] = []
    if unknown_state_count:
        warnings.append({
            "code": "unknown_task_states",
            "count": unknown_state_count,
        })
    warnings.extend(
        {
            "code": "task_requires_attention",
            "task_id": task["task_id"],
            "state": task["state"],
        }
        for task in tasks
        if task.get("state") in warning_states
    )
    payload: dict[str, Any] = {
        "schema_version": 2,
        "view": selected_view,
        "count": len(tasks),
        "total_matching": total_matching,
        "state_filter": state,
        "state_filter_kind": (
            "all" if state is None else "projection" if state in TASK_STATE_PROJECTIONS else "exact"
        ),
        "state_filter_states": list(filter_states or ()),
        "state_counts": state_counts,
        "state_counts_scope": "all_tasks",
        "state_counts_complete": unknown_state_count == 0,
        "unknown_state_count": unknown_state_count,
        "projection_counts": projection_counts,
        "projection_counts_scope": "all_tasks",
        "projection_counts_overlap": True,
        "tasks": tasks,
        "pagination": {
            "limit": limit,
            "returned": len(tasks),
            "has_more": has_more,
            "next_cursor": next_cursor,
            "ordering": "created_at_unix_desc_task_id_desc",
        },
        "warnings": warnings,
        "recommended_next_action": (
            "inspect unknown task states before relying on projections"
            if unknown_state_count
            else "inspect attention tasks before retry" if warnings else "none"
        ),
        "does_not_establish": [
            "task_output_correctness",
            "safe_unchanged_retry",
            "resource_release_complete",
        ],
    }
    if selected_view == "evidence":
        payload["database"] = str(TASK_DB)
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "view",
            "warnings",
            "recommended_next_action",
            "does_not_establish",
        ),
    )


CHRONIK_CLI_TIMEOUT_SECONDS = 30
CHRONIK_CLI_MAX_OUTPUT_BYTES = 64 * 1024
CHRONIK_HISTORY_MAX_LIMIT = 100


def _chronik_bounded_text(value: str, *, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    normalized = value.strip()
    if len(normalized) > maximum or any(
        ord(character) < 32 for character in normalized
    ):
        raise ValueError(f"{label} is invalid")
    return normalized


def _chronik_cli_run(
    arguments: list[str],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    configuration = chronik.coding_memory_configuration()
    if not configuration["available"]:
        return configuration, None
    command = [
        sys.executable,
        configuration["cli"],
        "--data-dir",
        configuration["data_dir"],
        *arguments,
    ]
    try:
        result = operator._run(
            command,
            cwd=Path(configuration["repository"]),
            timeout_seconds=CHRONIK_CLI_TIMEOUT_SECONDS,
            max_output_bytes=CHRONIK_CLI_MAX_OUTPUT_BYTES,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return configuration, {
            "returncode": 1,
            "stdout": "",
            "stderr": _redact_reason(str(exc)),
            "timed_out": False,
            "launch_error": True,
        }
    return configuration, result


def _chronik_cli_json(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("returncode") != 0 or result.get("timed_out") is True:
        raise ValueError("Chronik coding-memory CLI did not complete successfully")
    raw = result.get("stdout")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Chronik coding-memory CLI returned no JSON")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Chronik coding-memory CLI returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Chronik coding-memory CLI result must be an object")
    return payload


def _chronik_receipt(payload: dict[str, Any], *, field: str) -> dict[str, Any]:
    result = dict(payload)
    result[field] = _sha256_json(result)
    return result


def _chronik_failure_details(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    stderr = result.get("stderr")
    return {
        "returncode": result.get("returncode"),
        "timed_out": result.get("timed_out") is True,
        "error": _redact_reason(stderr) if isinstance(stderr, str) and stderr else None,
    }


def _chronik_unsigned_receipt_valid(payload: dict[str, Any]) -> bool:
    claimed = payload.get("receipt_sha256")
    if not isinstance(claimed, str):
        return False
    unsigned = dict(payload)
    unsigned.pop("receipt_sha256", None)
    return claimed == _sha256_json(unsigned)


def _validate_chronik_import_result(
    source: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if payload.get("schema_version") != "chronik-import-receipt.v1":
        raise ValueError("Chronik coding-memory import contract is stale")
    if payload.get("domain") != "agent.ledger":
        raise ValueError("Chronik coding-memory import domain is invalid")
    if payload.get("event_ids") != sorted(source["event_ids"]):
        raise ValueError("Chronik coding-memory import event_ids are unbound")
    requested = payload.get("requested")
    imported = payload.get("imported")
    skipped = payload.get("skipped_existing")
    if (
        type(requested) is not int
        or requested != source["event_count"]
        or type(imported) is not int
        or imported < 0
        or type(skipped) is not int
        or skipped < 0
        or imported + skipped != requested
    ):
        raise ValueError("Chronik coding-memory import counts are invalid")
    if payload.get("source_sha256") != source["chronik_source_sha256"]:
        raise ValueError("Chronik coding-memory import source digest is unbound")
    if payload.get("historical_only") is not True:
        raise ValueError("Chronik coding-memory import is not historical-only")
    claims = payload.get("does_not_establish")
    if not isinstance(claims, list) or not set(
        chronik.CODING_MEMORY_DOES_NOT_ESTABLISH
    ).issubset(claims):
        raise ValueError("Chronik coding-memory import truth exclusions are incomplete")
    if not _chronik_unsigned_receipt_valid(payload):
        raise ValueError("Chronik coding-memory import receipt digest is invalid")
    return payload


@mcp.tool(name="grabowski_chronik_outbox_import", annotations=MUTATING)
def grabowski_chronik_outbox_import(path: str) -> dict[str, Any]:
    """Import one redacted Grabowski outbox JSONL into optional local Chronik."""
    operator._require_operator_mutation("durable_job")
    source = chronik.inspect_coding_memory_source(path)
    configuration, execution = _chronik_cli_run(["import", source["path"]])
    base_payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_chronik_outbox_import_receipt",
        "source": {
            key: source[key]
            for key in ("path", "sha256", "bytes", "event_count", "event_ids_sha256")
        },
        "cli_present": bool(configuration["available"]),
        "available": False,
        "imported": False,
        "idempotent_import_contract": True,
        "source_unchanged": True,
        "outcome_unknown": False,
        "does_not_establish": list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH),
    }
    if execution is None:
        payload = {
            **base_payload,
            "failure": {
                "code": configuration["reason"],
                "returncode": None,
                "timed_out": False,
                "error": None,
            },
        }
    else:
        source_readback_error = None
        try:
            after = chronik.inspect_coding_memory_source(source["path"])
        except ValueError as exc:
            source_unchanged = False
            source_readback_error = str(exc)
        else:
            source_unchanged = (
                after["sha256"] == source["sha256"]
                and after["bytes"] == source["bytes"]
                and after["identity"] == source["identity"]
            )
        try:
            cli_result = _validate_chronik_import_result(
                source, _chronik_cli_json(execution)
            )
        except ValueError as exc:
            payload = {
                **base_payload,
                "source_unchanged": source_unchanged,
                "outcome_unknown": True,
                "failure": {
                    "code": "chronik_coding_memory_cli_failed",
                    **_chronik_failure_details(execution),
                    "contract_error": str(exc),
                    "source_readback_error": source_readback_error,
                },
            }
        else:
            payload = {
                **base_payload,
                "available": source_unchanged,
                "imported": source_unchanged,
                "source_unchanged": source_unchanged,
                "outcome_unknown": not source_unchanged,
                "chronik_result": cli_result if source_unchanged else None,
            }
            if not source_unchanged:
                payload["failure"] = {
                    "code": "chronik_outbox_source_changed",
                    "returncode": execution.get("returncode"),
                    "timed_out": execution.get("timed_out") is True,
                    "error": source_readback_error,
                }
    receipt = _chronik_receipt(payload, field="receipt_sha256")
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "chronik-outbox-import",
            "source_sha256": source["sha256"],
            "source_event_count": source["event_count"],
            "available": receipt["available"],
            "imported": receipt["imported"],
            "outcome_unknown": receipt["outcome_unknown"],
            "receipt_sha256": receipt["receipt_sha256"],
        }
    )
    return receipt


@mcp.tool(name="grabowski_chronik_history", annotations=READ_ONLY)
def grabowski_chronik_history(
    repo: str = "",
    host: str = "",
    component: str = "",
    operation: str = "",
    task_class: str = "",
    outcome: str = "",
    since: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """Read bounded historical coding events without asserting current truth."""
    operator._require_operator_capability("durable_job")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= CHRONIK_HISTORY_MAX_LIMIT
    ):
        raise ValueError(f"limit must be between 1 and {CHRONIK_HISTORY_MAX_LIMIT}")
    normalized = {
        "repo": _chronik_bounded_text(repo, label="repo"),
        "host": _chronik_bounded_text(host, label="host"),
        "component": _chronik_bounded_text(component, label="component"),
        "operation": _chronik_bounded_text(operation, label="operation"),
        "task_class": _chronik_bounded_text(task_class, label="task_class"),
        "outcome": _chronik_bounded_text(outcome, label="outcome"),
        "since": _chronik_bounded_text(since, label="since"),
    }
    if bool(normalized["repo"]) == bool(normalized["host"]):
        raise ValueError("exactly one of repo or host is required")
    arguments = ["query"]
    target_key = "repo" if normalized["repo"] else "host"
    arguments.append(f"--{target_key}={normalized[target_key]}")
    for key in ("component", "operation", "task_class", "outcome", "since"):
        if normalized[key]:
            option = key.replace("_", "-")
            arguments.append(f"--{option}={normalized[key]}")
    arguments.append(f"--limit={limit}")
    configuration, execution = _chronik_cli_run(arguments)
    query = {key: value for key, value in normalized.items() if value}
    query["limit"] = limit
    base_payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_chronik_history",
        "query": query,
        "cli_present": bool(configuration["available"]),
        "available": False,
        "historical_only": True,
        "events": [],
        "does_not_establish": list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH),
    }
    if execution is None:
        payload = {
            **base_payload,
            "failure": {
                "code": configuration["reason"],
                "returncode": None,
                "timed_out": False,
                "error": None,
            },
        }
    else:
        try:
            history = _chronik_cli_json(execution)
            if history.get("schema_version") != "chronik-coding-history.v1":
                raise ValueError("Chronik coding-memory history contract is stale")
            if history.get("historical_only") is not True:
                raise ValueError("Chronik coding-memory history is not historical-only")
            expected_history_query = {
                "repo": normalized["repo"] or None,
                "host": normalized["host"] or None,
                "component": normalized["component"] or None,
                "operation": normalized["operation"] or None,
                "task_class": normalized["task_class"] or None,
                "outcome": normalized["outcome"] or None,
                "since": normalized["since"] or None,
                "limit": limit,
            }
            if history.get("query") != expected_history_query:
                raise ValueError("Chronik coding-memory history query is unbound")
            raw_events = history.get("events", [])
            raw_event_ids = history.get("event_ids", [])
            raw_claims = history.get("does_not_establish", [])
            if not isinstance(raw_events, list) or not all(
                isinstance(event, dict) for event in raw_events
            ):
                raise ValueError(
                    "Chronik coding-memory history events must be a list of objects"
                )
            if not isinstance(raw_event_ids, list) or not all(
                isinstance(event_id, str) for event_id in raw_event_ids
            ):
                raise ValueError(
                    "Chronik coding-memory history event_ids must be a list of text"
                )
            if raw_event_ids != [event.get("event_id") for event in raw_events]:
                raise ValueError("Chronik coding-memory history event_ids are unbound")
            if any(
                chronik._contains_forbidden_coding_memory_key(event)
                for event in raw_events
            ):
                raise ValueError("Chronik coding-memory history contains unredacted event")
            if not isinstance(raw_claims, list) or not all(
                isinstance(claim, str) for claim in raw_claims
            ):
                raise ValueError(
                    "Chronik coding-memory history does_not_establish must be a list of text"
                )
            if not set(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH).issubset(raw_claims):
                raise ValueError(
                    "Chronik coding-memory history truth exclusions are incomplete"
                )
        except ValueError as exc:
            payload = {
                **base_payload,
                "failure": {
                    "code": "chronik_coding_memory_cli_failed",
                    **_chronik_failure_details(execution),
                    "contract_error": str(exc),
                },
            }
        else:
            events = raw_events[:limit]
            history = dict(history)
            history["events"] = events
            history["event_ids"] = raw_event_ids[:limit]
            history["historical_only"] = True
            history["does_not_establish"] = sorted(
                set(raw_claims) | set(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH)
            )
            payload = {
                **base_payload,
                "available": True,
                "events": events,
                "history": history,
            }
    return _chronik_receipt(payload, field="result_sha256")

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from typing import Any, Iterable, Mapping

import grabowski_mcp as base
import grabowski_bureau_leases as bureau_leases
import grabowski_nonconflict as nonconflict
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
RESOURCE_DB = Path(
    os.environ.get(
        "GRABOWSKI_RESOURCE_DB",
        str(operator.STATE_DIR / "resources.sqlite3"),
    )
).expanduser()
RESOURCE_KINDS = {
    "repo",
    "path",
    "port",
    "service",
    "browser-profile",
    "display",
    "component",
    "process",
    "deployment",
    "migration",
    "gate",
}
OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
SERVICE_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,255}\Z")
COMPONENT_RE = re.compile(r"[A-Za-z0-9_.:@/-]{1,255}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MIN_TTL_SECONDS = 30
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_TERMINAL_RECEIPT_BYTES = 64 * 1024
OBSOLETE_PATH_RELEASE_SCHEMA_VERSION = 1
OBSOLETE_PATH_RELEASE_KIND = "grabowski_obsolete_path_lease_release"
LEASE_SNAPSHOT_KEYS = frozenset({
    "resource_key",
    "owner_id",
    "acquired_at_unix",
    "updated_at_unix",
    "expires_at_unix",
    "metadata_sha256",
})
TASK_RELEASABLE_STATES = frozenset({"completed"})
TASK_TERMINAL_STATES = frozenset({"completed", "failed", "cancelled", "timed_out", "signalled"})
TASK_TERMINALIZATION_PHASES = frozenset({"leases_revoked", "projected"})
TASK_TERMINALIZATION_SCHEMA_VERSION = 1
TASK_TERMINALIZATION_KIND = "grabowski_task_terminalization"
TASK_AUTHORITY_ADOPTION_KIND = "grabowski_task_authority_adoption"
NONRENEWABLE_CRITICAL_RESOURCE_PREFIXES = ("gate:github-merge:",)
RECONCILIATION_NON_CLAIMS = [
    "permission_to_release_changed_lease",
    "permission_to_release_other_owner",
    "permission_to_bypass_active_overlap",
    "merge_authority",
    "deploy_authority",
    "retry_authority",
    "migration_authority",
    "policy_bypass_authority",
]
RESOURCE_SCHEMA_V2_ADDITIVE_TABLES = {
    "task_authority_adoptions": (
        ("task_id", "TEXT", 0, 1),
        ("guard_owner_id", "TEXT", 1, 0),
        ("lease_owner_id", "TEXT", 1, 0),
        ("acquired_at_unix", "INTEGER", 1, 0),
        ("expires_at_unix", "INTEGER", 1, 0),
        ("binding_sha256", "TEXT", 1, 0),
    ),
    "task_terminalizations": (
        ("task_id", "TEXT", 0, 1),
        ("attempt", "INTEGER", 1, 0),
        ("lease_owner_id", "TEXT", 1, 0),
        ("terminal_state", "TEXT", 1, 0),
        ("phase", "TEXT", 1, 0),
        ("task_projection_json", "TEXT", 1, 0),
        ("task_projection_sha256", "TEXT", 1, 0),
        ("requested_resource_keys_json", "TEXT", 1, 0),
        ("requested_resource_keys_sha256", "TEXT", 1, 0),
        ("prior_leases_json", "TEXT", 1, 0),
        ("prior_leases_sha256", "TEXT", 1, 0),
        ("revoked_resource_keys_json", "TEXT", 1, 0),
        ("missing_resource_keys_json", "TEXT", 1, 0),
        ("observation_sha256", "TEXT", 1, 0),
        ("prepared_at_unix", "INTEGER", 1, 0),
        ("leases_revoked_at_unix", "INTEGER", 1, 0),
        ("projected_at_unix", "INTEGER", 0, 0),
        ("lifecycle_receipt_sha256", "TEXT", 0, 0),
        ("recovery_status", "TEXT", 1, 0),
        ("transition_sha256", "TEXT", 1, 0),
    ),
}


class ResourceConflict(RuntimeError):
    def __init__(self, resource_key: str, owner_id: str, expires_at_unix: int) -> None:
        super().__init__(
            f"Resource is leased: {resource_key} owner={owner_id} "
            f"expires_at_unix={expires_at_unix}"
        )
        self.resource_key = resource_key
        self.owner_id = owner_id
        self.expires_at_unix = expires_at_unix


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _metadata(metadata: dict[str, Any] | None) -> tuple[str, str]:
    value: dict[str, Any] = {} if metadata is None else metadata
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    encoded = _canonical_json(value)
    if len(encoded.encode("utf-8")) > 16 * 1024:
        raise ValueError("metadata is too large")
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


RESOURCE_METADATA_SHAPE = (
    ("key", "TEXT", 0, 1),
    ("value", "TEXT", 1, 0),
)
RESOURCE_LEASE_SHAPE = (
    ("resource_key", "TEXT", 0, 1),
    ("owner_id", "TEXT", 1, 0),
    ("purpose", "TEXT", 1, 0),
    ("acquired_at_unix", "INTEGER", 1, 0),
    ("updated_at_unix", "INTEGER", 1, 0),
    ("expires_at_unix", "INTEGER", 1, 0),
    ("metadata_sha256", "TEXT", 1, 0),
    ("metadata_json", "TEXT", 1, 0),
    ("reclaimed_from_owner", "TEXT", 0, 0),
)
RESOURCE_SCHEMA_V2_TABLES = frozenset({
    "metadata", "leases", "task_terminalizations", "task_authority_adoptions",
})
RESOURCE_CURRENT_SCHEMA_VERSION = "2"
RESOURCE_SUPPORTED_SCHEMA_VERSIONS = ("1", "2")
RESOURCE_SCHEMA_MIGRATION_PATHS = {"1": ("1", RESOURCE_CURRENT_SCHEMA_VERSION)}
RESOURCE_SCHEMA_RECOVERY_INSTRUCTION = (
    "Keep the resource store unchanged; use a runtime that explicitly supports "
    "the observed schema or restore a verified backup before retrying."
)


@contextmanager
def _resource_schema_directory_lock(parent: Path) -> Iterator[None]:
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(parent, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def _resource_readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(
        path.absolute().as_uri() + "?mode=ro",
        uri=True,
        timeout=1,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    try:
        yield connection
    finally:
        connection.close()


class ResourceSchemaInventoryChanged(RuntimeError):
    pass


def _inventory_file_identity(path: Path) -> tuple[int, int, int, int, int]:
    status = path.stat()
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


@contextmanager
def _resource_inventory_readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    wal_path = Path(str(path) + "-wal")
    immutable_read = not wal_path.exists()
    before_identity = _inventory_file_identity(path) if immutable_read else None
    immutable = "&immutable=1" if immutable_read else ""
    connection = sqlite3.connect(
        path.absolute().as_uri() + f"?mode=ro{immutable}",
        uri=True,
        timeout=1,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    try:
        yield connection
    finally:
        connection.close()
        if immutable_read:
            try:
                after_identity = _inventory_file_identity(path)
            except FileNotFoundError as exc:
                raise ResourceSchemaInventoryChanged(
                    "Store changed while schema inventory was read; retry inventory"
                ) from exc
            if wal_path.exists() or after_identity != before_identity:
                raise ResourceSchemaInventoryChanged(
                    "Store changed while schema inventory was read; retry inventory"
                )


def _resource_sqlite_integrity(
    connection: sqlite3.Connection,
    label: str,
    *,
    quick: bool = False,
) -> None:
    pragma = "quick_check" if quick else "integrity_check"
    try:
        rows = connection.execute(f"PRAGMA {pragma}").fetchall()
    except sqlite3.DatabaseError as exc:
        detail = str(exc).lower()
        if "locked" in detail or "busy" in detail:
            raise RuntimeError(
                f"{label} is busy; retry after the active writer completes"
            ) from exc
        raise RuntimeError(
            f"{label} is corrupt; restore a verified backup before retrying"
        ) from exc
    values = [str(row[0]).lower() for row in rows]
    if values != ["ok"]:
        detail = "; ".join(str(row[0]) for row in rows[:5])
        raise RuntimeError(
            f"{label} failed {pragma}: {detail or 'no result'}"
        )


def _resource_sqlite_fingerprint(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for statement in connection.iterdump():
        digest.update(statement.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _resource_database_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def _resource_table_shape(
    connection: sqlite3.Connection,
    table_name: str,
) -> tuple[tuple[str, str, int, int], ...]:
    return tuple(
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
        for row in connection.execute(f'PRAGMA table_info("{table_name}")')
    )


def _resource_schema_version(connection: sqlite3.Connection) -> str | None:
    tables = _resource_database_tables(connection)
    if not tables:
        return None
    if "metadata" not in tables:
        raise RuntimeError(
            "Resource database schema metadata is missing; restore or inspect the store"
        )
    if _resource_table_shape(connection, "metadata") != RESOURCE_METADATA_SHAPE:
        raise RuntimeError("Resource database metadata table is malformed")
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError(
            "Resource database schema_version metadata is missing or ambiguous"
        )
    return str(rows[0][0])


def _validate_resource_schema_legacy(connection: sqlite3.Connection) -> None:
    if _resource_database_tables(connection) != {"metadata", "leases"}:
        raise RuntimeError("Resource database schema 1 is incomplete or unsupported")
    if _resource_table_shape(connection, "metadata") != RESOURCE_METADATA_SHAPE:
        raise RuntimeError("Resource database schema 1 metadata is malformed")
    if _resource_table_shape(connection, "leases") != RESOURCE_LEASE_SHAPE:
        raise RuntimeError("Resource database schema 1 leases are malformed")


def _validate_additive_schema_v2(connection: sqlite3.Connection) -> None:
    for table_name, expected_columns in RESOURCE_SCHEMA_V2_ADDITIVE_TABLES.items():
        if _resource_table_shape(connection, table_name) != expected_columns:
            raise RuntimeError("Unsupported resource database schema")


def _validate_resource_schema_current(connection: sqlite3.Connection) -> None:
    if _resource_database_tables(connection) != RESOURCE_SCHEMA_V2_TABLES:
        raise RuntimeError("Unsupported resource database schema")
    if _resource_table_shape(connection, "metadata") != RESOURCE_METADATA_SHAPE:
        raise RuntimeError("Unsupported resource database schema")
    if _resource_table_shape(connection, "leases") != RESOURCE_LEASE_SHAPE:
        raise RuntimeError("Unsupported resource database schema")
    _validate_additive_schema_v2(connection)


def _resource_schema_inventory() -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "store": "resources",
        "database": str(RESOURCE_DB),
        "observed_version": None,
        "current_version": RESOURCE_CURRENT_SCHEMA_VERSION,
        "supported_versions": list(RESOURCE_SUPPORTED_SCHEMA_VERSIONS),
        "status": "uninitialized",
        "migration_required": False,
        "migration_path": [],
        "write_compatible": False,
        "mutation_performed": False,
        "required_action": "initialize_on_first_write",
        "recovery_instruction": None,
    }
    if not RESOURCE_DB.exists():
        return result
    if RESOURCE_DB.is_symlink() or not RESOURCE_DB.is_file():
        result.update(
            status="blocked",
            required_action="inspect_store_path",
            recovery_instruction=RESOURCE_SCHEMA_RECOVERY_INSTRUCTION,
            error="Resource database must be a regular non-symlink file",
        )
        return result
    if RESOURCE_DB.stat().st_size == 0:
        return result
    try:
        with _resource_inventory_readonly_sqlite(RESOURCE_DB) as connection:
            _resource_sqlite_integrity(connection, "Resource database", quick=True)
            observed = _resource_schema_version(connection)
            result["observed_version"] = observed
            if observed not in RESOURCE_SUPPORTED_SCHEMA_VERSIONS:
                future = (
                    observed is not None
                    and observed.isdecimal()
                    and int(observed) > int(RESOURCE_CURRENT_SCHEMA_VERSION)
                )
                result.update(
                    status="unsupported_future" if future else "unsupported_schema",
                    required_action="upgrade_runtime_or_restore_verified_backup",
                    recovery_instruction=RESOURCE_SCHEMA_RECOVERY_INSTRUCTION,
                )
                return result
            if observed == RESOURCE_CURRENT_SCHEMA_VERSION:
                _validate_resource_schema_current(connection)
            else:
                _validate_resource_schema_legacy(connection)
    except ResourceSchemaInventoryChanged as exc:
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
            recovery_instruction=RESOURCE_SCHEMA_RECOVERY_INSTRUCTION,
            error=f"{type(exc).__name__}: {exc}",
        )
        return result
    if observed == RESOURCE_CURRENT_SCHEMA_VERSION:
        result.update(status="current", write_compatible=True, required_action="none")
        return result
    path = RESOURCE_SCHEMA_MIGRATION_PATHS[observed]
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


def _validate_resource_backup(
    path: Path,
    version: str,
    fingerprint: str,
) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Resource migration backup may not be a symlink: {path}")
    try:
        status = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Resource migration backup disappeared: {path}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeError(f"Resource migration backup is not a regular file: {path}")
    if stat.S_IMODE(status.st_mode) not in {0o400, 0o600}:
        raise RuntimeError(f"Resource migration backup permissions are unsafe: {path}")
    with _resource_readonly_sqlite(path) as backup:
        _resource_sqlite_integrity(backup, "Resource migration backup")
        if _resource_schema_version(backup) != version:
            raise RuntimeError("Resource migration backup schema version does not match")
        _validate_resource_schema_legacy(backup)
        if _resource_sqlite_fingerprint(backup) != fingerprint:
            raise RuntimeError("Resource migration backup fingerprint does not match")


def _verified_resource_migration_backup(
    version: str,
    fingerprint: str,
) -> Path:
    with _resource_readonly_sqlite(RESOURCE_DB) as source:
        source.execute("BEGIN")
        _resource_sqlite_integrity(source, "Resource database")
        if _resource_sqlite_fingerprint(source) != fingerprint:
            raise RuntimeError(
                "Resource database changed identity before backup; retry migration"
            )
        backup_path = RESOURCE_DB.parent / (
            f"{RESOURCE_DB.name}.schema-{version}-{fingerprint}.backup"
        )
        if backup_path.exists() or backup_path.is_symlink():
            _validate_resource_backup(backup_path, version, fingerprint)
            return backup_path
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{RESOURCE_DB.name}.schema-{version}-",
            suffix=".backup.tmp",
            dir=RESOURCE_DB.parent,
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
            _validate_resource_backup(temporary, version, fingerprint)
            try:
                os.link(temporary, backup_path)
            except FileExistsError:
                pass
            else:
                temporary.unlink()
            _validate_resource_backup(backup_path, version, fingerprint)
            directory = os.open(RESOURCE_DB.parent, os.O_RDONLY | os.O_DIRECTORY)
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


def _preflight_resource_store() -> str | None:
    if not RESOURCE_DB.exists():
        return None
    if RESOURCE_DB.is_symlink() or not RESOURCE_DB.is_file():
        raise PermissionError(f"Resource database must be a regular file: {RESOURCE_DB}")
    if RESOURCE_DB.stat().st_size == 0:
        return None
    with _resource_readonly_sqlite(RESOURCE_DB) as connection:
        _resource_sqlite_integrity(connection, "Resource database", quick=True)
        version = _resource_schema_version(connection)
        if version not in {"1", "2"}:
            raise RuntimeError(
                "Unsupported resource database schema; use a compatible runtime"
            )
        if version == "1":
            _validate_resource_schema_legacy(connection)
        else:
            _validate_resource_schema_current(connection)
        return version


def _create_resource_additive_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE task_terminalizations (
            task_id TEXT PRIMARY KEY,
            attempt INTEGER NOT NULL,
            lease_owner_id TEXT NOT NULL,
            terminal_state TEXT NOT NULL,
            phase TEXT NOT NULL,
            task_projection_json TEXT NOT NULL,
            task_projection_sha256 TEXT NOT NULL,
            requested_resource_keys_json TEXT NOT NULL,
            requested_resource_keys_sha256 TEXT NOT NULL,
            prior_leases_json TEXT NOT NULL,
            prior_leases_sha256 TEXT NOT NULL,
            revoked_resource_keys_json TEXT NOT NULL,
            missing_resource_keys_json TEXT NOT NULL,
            observation_sha256 TEXT NOT NULL,
            prepared_at_unix INTEGER NOT NULL,
            leases_revoked_at_unix INTEGER NOT NULL,
            projected_at_unix INTEGER,
            lifecycle_receipt_sha256 TEXT,
            recovery_status TEXT NOT NULL,
            transition_sha256 TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE task_authority_adoptions (
            task_id TEXT PRIMARY KEY,
            guard_owner_id TEXT NOT NULL,
            lease_owner_id TEXT NOT NULL,
            acquired_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            binding_sha256 TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX task_authority_adoptions_expiry_idx "
        "ON task_authority_adoptions(expires_at_unix)"
    )


def _create_resource_schema_v2(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        """
        CREATE TABLE leases (
            resource_key TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            acquired_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            metadata_sha256 TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            reclaimed_from_owner TEXT
        )
        """
    )
    _create_resource_additive_tables(connection)
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES('schema_version', '2')"
    )


def _migrate_resource_schema_v1(connection: sqlite3.Connection) -> None:
    _create_resource_additive_tables(connection)
    connection.execute(
        "UPDATE metadata SET value='2' WHERE key='schema_version'"
    )


def _connect_existing_resource_database() -> sqlite3.Connection:
    if RESOURCE_DB.is_symlink():
        raise PermissionError(f"Resource database may not be a symlink: {RESOURCE_DB}")
    connection = sqlite3.connect(
        RESOURCE_DB.absolute().as_uri() + "?mode=rw",
        uri=True,
        timeout=10,
        isolation_level=None,
    )
    if RESOURCE_DB.is_symlink():
        connection.close()
        raise PermissionError(f"Resource database may not be a symlink: {RESOURCE_DB}")
    return connection


def _open_current_resource_database() -> sqlite3.Connection:
    connection = _connect_existing_resource_database()
    connection.row_factory = sqlite3.Row
    try:
        if _resource_schema_version(connection) != "2":
            raise RuntimeError(
                "Resource database schema changed while opening; retry with a compatible runtime"
            )
        _validate_resource_schema_current(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        if stat.S_IMODE(RESOURCE_DB.stat().st_mode) != 0o600:
            os.chmod(RESOURCE_DB, 0o600)
        return connection
    except Exception:
        connection.close()
        raise


def _database() -> sqlite3.Connection:
    parent = RESOURCE_DB.parent
    if parent.is_symlink():
        raise PermissionError(f"Resource state directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if RESOURCE_DB.is_symlink():
        raise PermissionError(f"Resource database may not be a symlink: {RESOURCE_DB}")

    observed = _preflight_resource_store()
    if observed == "2":
        return _open_current_resource_database()

    with _resource_schema_directory_lock(parent):
        observed = _preflight_resource_store()
        if observed == "2":
            return _open_current_resource_database()
        connection = (
            sqlite3.connect(RESOURCE_DB, timeout=10, isolation_level=None)
            if observed is None
            else _connect_existing_resource_database()
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            version = _resource_schema_version(connection)
            if version not in {None, "1", "2"}:
                raise RuntimeError(
                    "Unsupported resource database schema; use a compatible runtime"
                )
            if version is None:
                if _resource_database_tables(connection):
                    raise RuntimeError(
                        "Resource database schema metadata is missing from an existing database"
                    )
                _create_resource_schema_v2(connection)
            elif version == "1":
                _validate_resource_schema_legacy(connection)
                _resource_sqlite_integrity(connection, "Resource database")
                fingerprint = _resource_sqlite_fingerprint(connection)
                _verified_resource_migration_backup(version, fingerprint)
                _migrate_resource_schema_v1(connection)
            else:
                _validate_resource_schema_current(connection)
            if _resource_schema_version(connection) != "2":
                raise RuntimeError("Resource database migration did not reach schema 2")
            _validate_resource_schema_current(connection)
            _resource_sqlite_integrity(connection, "Migrated resource database")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if stat.S_IMODE(RESOURCE_DB.stat().st_mode) != 0o600:
                os.chmod(RESOURCE_DB, 0o600)
            return connection
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            raise


def _owner(value: str) -> str:
    if not isinstance(value, str) or OWNER_RE.fullmatch(value) is None:
        raise ValueError("owner_id must match [A-Za-z0-9._:@-]{1,128}")
    return value


def _purpose(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("purpose must be text")
    normalized = value.strip()
    if not normalized or len(normalized.encode("utf-8")) > 512 or "\x00" in normalized:
        raise ValueError("purpose is empty, too large or contains NUL")
    return normalized


def _ttl(value: int) -> int:
    if not isinstance(value, int) or not MIN_TTL_SECONDS <= value <= MAX_TTL_SECONDS:
        raise ValueError(
            f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
        )
    return value


def normalize_resource_key(raw: str) -> str:
    if not isinstance(raw, str) or ":" not in raw or "\x00" in raw:
        raise ValueError("resource key must use kind:value syntax")
    if len(raw.encode("utf-8")) > 8192:
        raise ValueError("resource key is too large")
    kind, value = raw.split(":", 1)
    kind = kind.strip().lower()
    if kind not in RESOURCE_KINDS:
        raise ValueError(f"resource kind must be one of {sorted(RESOURCE_KINDS)}")
    value = value.strip()
    if not value:
        raise ValueError("resource value may not be empty")
    if kind in {"path", "repo", "browser-profile"}:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise ValueError(f"{kind} resource must be an absolute path")
        value = os.path.normpath(str(candidate))
    elif kind == "port":
        try:
            port = int(value, 10)
        except ValueError as exc:
            raise ValueError("port resource must contain a decimal port") from exc
        if not 1 <= port <= 65535:
            raise ValueError("port resource must be between 1 and 65535")
        value = str(port)
    elif kind == "display":
        try:
            display = int(value.lstrip(":"), 10)
        except ValueError as exc:
            raise ValueError("display resource must contain a display number") from exc
        if not 1 <= display <= 4095:
            raise ValueError("display resource must be between 1 and 4095")
        value = str(display)
    elif kind == "component":
        if COMPONENT_RE.fullmatch(value) is None:
            raise ValueError("component resource contains unsupported characters")
    elif SERVICE_RE.fullmatch(value) is None:
        raise ValueError(f"{kind} resource contains unsupported characters")
    return f"{kind}:{value}"


def normalize_resource_keys(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError("resource_keys must be a list")
    normalized = sorted({normalize_resource_key(value) for value in values})
    if not normalized:
        raise ValueError("at least one resource key is required")
    if len(normalized) > 64:
        raise ValueError("at most 64 resource keys may be acquired atomically")
    return normalized


def _public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    return {
        "resource_key": record["resource_key"],
        "owner_id": record["owner_id"],
        "purpose": record["purpose"],
        "acquired_at_unix": record["acquired_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "expires_at_unix": record["expires_at_unix"],
        "metadata_sha256": record["metadata_sha256"],
        "reclaimed_from_owner": record.get("reclaimed_from_owner"),
    }


def _row_metadata(row: sqlite3.Row) -> dict[str, Any]:
    try:
        value = json.loads(row["metadata_json"])
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("resource lease metadata is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("resource lease metadata must be an object")
    return value


def _scope_manifest_from_metadata(metadata: dict[str, Any], *, required: bool) -> dict[str, Any] | None:
    value = metadata.get("scope_manifest")
    if value is None and not required:
        return None
    if value is None:
        raise nonconflict.NonConflictDenied(
            "scope-manifest-missing",
            "blocking repository lease has no exact scope manifest",
        )
    if required and metadata.get("scope_manifest_complete") is not True:
        raise nonconflict.NonConflictDenied(
            "scope-manifest-unattested",
            "blocking repository owner did not attest that the scope manifest is complete",
        )
    return nonconflict.normalize_scope_manifest(value)


def repository_scope_manifest_for_owner(
    owner_id: str, resource_key: str
) -> dict[str, Any] | None:
    """Read one owner-bound broad repository manifest, including after expiry."""
    owner = _owner(owner_id)
    key = normalize_resource_key(resource_key)
    if not key.startswith("repo:") or scoped_repository_resource_root(key) is not None:
        raise ValueError("resource_key must be one broad repository lease")
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM leases WHERE resource_key=?", (key,)
        ).fetchone()
    if row is None:
        return None
    if row["owner_id"] != owner:
        raise PermissionError("repository lease is owned by another owner")
    metadata = _row_metadata(row)
    _, observed_metadata_sha256 = _metadata(metadata)
    if row["metadata_sha256"] != observed_metadata_sha256:
        raise RuntimeError("repository lease metadata hash does not match")
    manifest = _scope_manifest_from_metadata(metadata, required=False)
    if manifest is None:
        return None
    if f"repo:{manifest['repository']}" != key:
        raise RuntimeError("repository lease scope does not match resource key")
    return manifest


def _path_is_within_repository(resource_key: str, repository: str) -> bool:
    if not resource_key.startswith("path:"):
        return False
    path = resource_key.split(":", 1)[1]
    try:
        return os.path.commonpath([path, repository]) == repository
    except ValueError:
        return False


def _blocking_repository_rows(
    connection: sqlite3.Connection,
    *,
    keys: list[str],
    requested_scope: dict[str, Any] | None,
    owner: str,
    now: int,
) -> list[sqlite3.Row]:
    rows = connection.execute(
        "SELECT * FROM leases WHERE resource_key LIKE 'repo:%' "
        "AND owner_id<>? AND expires_at_unix>? ORDER BY resource_key",
        (owner, now),
    ).fetchall()
    matches: list[sqlite3.Row] = []
    requested_repository = None if requested_scope is None else requested_scope["repository"]
    for row in rows:
        repository = row["resource_key"].split(":", 1)[1]
        if requested_repository == repository or any(
            _path_is_within_repository(key, repository) for key in keys
        ):
            matches.append(row)
    return matches


def _check_repository_semantic_conflicts(
    connection: sqlite3.Connection,
    *,
    keys: list[str],
    owner: str,
    purpose: str,
    ttl_seconds: int,
    metadata: dict[str, Any],
    nonconflict_proof: dict[str, Any] | None,
    now: int,
) -> dict[str, Any] | None:
    # Bureau has its own stricter always-open contract. Applying the generic
    # broad-repository rule here would reintroduce the deprecated global blocker.
    bureau_keys = bureau_leases.bureau_resource_keys(keys)
    if bureau_keys and len(bureau_keys) != len(keys):
        raise ValueError("Bureau and non-Bureau resources must be acquired separately")
    if bureau_keys:
        if nonconflict_proof is not None:
            raise nonconflict.NonConflictDenied(
                "bureau-contract-is-authoritative",
                "Bureau resources use the dedicated always-open lease contract",
            )
        return None
    requested_scope = _scope_manifest_from_metadata(metadata, required=False)
    repo_keys = [key for key in keys if key.startswith("repo:")]
    if requested_scope is not None and not repo_keys:
        requested_scope = nonconflict.validate_resource_scope_binding(keys, requested_scope)
    if repo_keys:
        if len(repo_keys) != 1:
            raise ValueError("repository leases must be acquired one repository at a time")
        repository = repo_keys[0].split(":", 1)[1]
        if requested_scope is not None and requested_scope["repository"] != repository:
            raise ValueError("scope_manifest repository must match repository resource key")
        rows = connection.execute(
            "SELECT * FROM leases WHERE owner_id<>? AND expires_at_unix>? ORDER BY resource_key",
            (owner, now),
        ).fetchall()
        for row in rows:
            row_scope = _scope_manifest_from_metadata(_row_metadata(row), required=False)
            same_repository = (
                _path_is_within_repository(row["resource_key"], repository)
                or (row_scope is not None and row_scope["repository"] == repository)
            )
            if same_repository:
                raise ResourceConflict(row["resource_key"], row["owner_id"], row["expires_at_unix"])
        return None

    blockers = _blocking_repository_rows(
        connection, keys=keys, requested_scope=requested_scope, owner=owner, now=now
    )
    if not blockers:
        if nonconflict_proof is not None:
            raise nonconflict.NonConflictDenied(
                "no-live-blocker",
                "non-conflict proof supplied without a live blocking repository lease",
            )
        return None
    if len(blockers) != 1:
        raise nonconflict.NonConflictDenied(
            "ambiguous-blocker",
            "more than one repository lease could block the requested resources",
        )
    blocker = blockers[0]
    if nonconflict_proof is None:
        raise ResourceConflict(
            blocker["resource_key"], blocker["owner_id"], blocker["expires_at_unix"]
        )
    if requested_scope is None:
        raise nonconflict.NonConflictDenied(
            "requested-scope-missing",
            "non-conflict exception requires metadata.scope_manifest",
        )
    requested_scope = nonconflict.validate_resource_scope_binding(keys, requested_scope)
    if metadata.get("scope_manifest_complete") is not True:
        raise nonconflict.NonConflictDenied(
            "requested-scope-unattested",
            "requesting owner did not attest that the scope manifest is complete",
        )
    blocker_metadata = _row_metadata(blocker)
    if blocker_metadata.get("lease_mode") == "emergency-recovery":
        raise nonconflict.NonConflictDenied(
            "emergency-recovery",
            "emergency recovery repository leases cannot be bypassed",
        )
    existing_scope = _scope_manifest_from_metadata(blocker_metadata, required=True)
    if existing_scope["repository"] != blocker["resource_key"].split(":", 1)[1]:
        raise nonconflict.NonConflictDenied(
            "blocking-scope-repository-mismatch",
            "blocking repository lease scope does not match its resource key",
        )
    return nonconflict.validate_proof_against_live_lease(
        nonconflict_proof,
        live_lease=blocker,
        live_existing_scope=existing_scope,
        requesting_owner=owner,
        resource_keys=keys,
        purpose=purpose,
        requested_scope=requested_scope,
        requested_ttl_seconds=ttl_seconds,
        now=now,
    )


def _release_lease_snapshot(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "resource_key": row["resource_key"],
        "owner_id": row["owner_id"],
        "acquired_at_unix": int(row["acquired_at_unix"]),
        "updated_at_unix": int(row["updated_at_unix"]),
        "expires_at_unix": int(row["expires_at_unix"]),
        "metadata_sha256": row["metadata_sha256"],
    }


def _normalize_expected_lease_snapshots(
    value: Any, *, owner_id: str, resource_keys: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(resource_keys):
        raise ValueError("expected_leases must contain one snapshot per resource key")
    snapshots: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != LEASE_SNAPSHOT_KEYS:
            raise ValueError("expected lease snapshot is malformed")
        key = normalize_resource_key(item["resource_key"])
        if not key.startswith("path:"):
            raise ValueError("obsolete lease reconciliation accepts exact path leases only")
        if item["owner_id"] != owner_id:
            raise PermissionError("expected lease snapshot is owned by another owner")
        for field in ("acquired_at_unix", "updated_at_unix", "expires_at_unix"):
            if type(item[field]) is not int:
                raise ValueError(f"expected lease {field} is invalid")
        if not (
            item["acquired_at_unix"] <= item["updated_at_unix"]
            < item["expires_at_unix"]
        ):
            raise ValueError("expected lease timestamps are inconsistent")
        if not isinstance(item["metadata_sha256"], str) or SHA256_RE.fullmatch(
            item["metadata_sha256"]
        ) is None:
            raise ValueError("expected lease metadata SHA-256 is invalid")
        snapshots.append({**item, "resource_key": key})
    snapshots.sort(key=lambda item: item["resource_key"])
    if [item["resource_key"] for item in snapshots] != resource_keys:
        raise ValueError("expected lease snapshots do not match resource_keys")
    return snapshots


def _load_private_receipt_json(path: Path) -> dict[str, Any]:
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise PermissionError("terminal receipt directory is unsafe") from exc
    descriptor = -1
    try:
        directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != os.getuid()
            or stat.S_IMODE(directory.st_mode) & 0o077
        ):
            raise PermissionError("terminal receipt directory must be private and owned")
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            raise PermissionError("terminal receipt path is unsafe") from exc
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_TERMINAL_RECEIPT_BYTES
        ):
            raise PermissionError("terminal receipt must be one bounded private regular file")
        raw = os.read(descriptor, MAX_TERMINAL_RECEIPT_BYTES + 1)
        if len(raw) > MAX_TERMINAL_RECEIPT_BYTES:
            raise PermissionError("terminal receipt exceeds the byte limit")
        value = json.loads(raw.decode("utf-8"))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)
    if not isinstance(value, dict):
        raise ValueError("terminal receipt must be a JSON object")
    return value


def _verify_workspace_terminal_source(
    terminal_source: dict[str, Any],
    *,
    owner_id: str,
    resource_keys: list[str],
    expected_leases: list[dict[str, Any]],
) -> dict[str, Any]:
    if set(terminal_source) != {"kind", "workspace_id", "close_receipt_sha256"}:
        raise ValueError("workspace terminal_source keys are invalid")
    import grabowski_agent_workspace as workspace

    workspace_id = terminal_source["workspace_id"]
    receipt_sha256 = terminal_source["close_receipt_sha256"]
    if not isinstance(workspace_id, str) or not workspace_id:
        raise ValueError("workspace_id is invalid")
    if not isinstance(receipt_sha256, str) or SHA256_RE.fullmatch(receipt_sha256) is None:
        raise ValueError("close_receipt_sha256 is invalid")
    manifest = workspace._manifest(workspace_id)
    receipt_path = workspace._workspace_dir(workspace_id) / "close-receipt.json"
    if not receipt_path.is_file():
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-missing", "workspace close receipt is absent"
        )
    receipt = workspace._load_json(receipt_path)
    if not workspace._receipt_integrity(receipt):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "workspace close receipt integrity is invalid"
        )
    if receipt.get("receipt_sha256") != receipt_sha256:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-drift", "workspace close receipt identity changed"
        )
    state = receipt.get("state")
    if state not in {"complete", "resource_release_incomplete"}:
        raise nonconflict.NonConflictDenied(
            "owner-work-nonterminal", "workspace closeout is not terminal and releasable"
        )
    if receipt.get("workspace_id") != workspace_id:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "workspace close receipt names another workspace"
        )
    closure_outcome = receipt.get("closure_outcome")
    if closure_outcome not in {"successful", "abandoned_failed_roles"}:
        raise nonconflict.NonConflictDenied(
            "owner-work-nonterminal",
            "workspace closure outcome is unknown or not explicitly terminal",
        )
    collection = manifest.get("collection")
    if (
        not isinstance(collection, dict)
        or collection.get("state") != "complete"
        or not workspace._collection_integrity_status(manifest, collection)["valid"]
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "workspace close receipt has no canonical complete collection",
        )
    canonical_failed_roles = workspace._collection_failed_roles(collection)
    failed_roles = receipt.get("failed_roles")
    if failed_roles != canonical_failed_roles:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "workspace close receipt failure roles differ from the canonical collection",
        )
    if canonical_failed_roles:
        if (
            closure_outcome != "abandoned_failed_roles"
            or receipt.get("abandon_failed_roles") is not True
        ):
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid",
                "failed workspace roles lack explicit canonical abandonment",
            )
    elif (
        closure_outcome != "successful"
        or receipt.get("abandon_failed_roles") is not False
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "successful workspace closeout has inconsistent failure evidence",
        )
    if state == "complete":
        if not workspace._close_integrity_status(manifest, receipt)["valid"]:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid",
                "workspace close receipt does not match the canonical manifest",
            )
    elif (
        receipt.get("expected_head") != collection.get("writer_head")
        or receipt.get("expected_diff_sha256") != collection.get("diff_sha256")
        or receipt.get("expected_result_sha256") != collection.get("result_sha256")
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "incomplete workspace release receipt is not collection-bound",
        )
    task_states = receipt.get("task_states")
    manifest_tasks = manifest.get("tasks")
    if not isinstance(task_states, dict) or not isinstance(manifest_tasks, dict):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "workspace task evidence is malformed"
        )
    for role in ("writer", "tests", "review"):
        recorded = task_states.get(role)
        live = workspace._task_public(manifest_tasks.get(role))
        if (
            not isinstance(recorded, dict)
            or recorded.get("terminal") is not True
            or live.get("terminal") is not True
            or recorded.get("state")
            in {"outcome_unknown", "observation_error", "interrupted"}
            or live.get("state")
            in {"outcome_unknown", "observation_error", "interrupted"}
            or any(
                recorded.get(field) != live.get(field)
                for field in ("task_id", "attempt", "state", "terminal")
            )
        ):
            raise nonconflict.NonConflictDenied(
                "owner-work-nonterminal",
                "workspace task attempt changed or is not terminal",
            )
    resources_manifest = manifest.get("resources")
    if not isinstance(resources_manifest, dict) or resources_manifest.get("owner_id") != owner_id:
        raise PermissionError("workspace terminal evidence belongs to another lease owner")
    declared_raw = resources_manifest.get("lease_keys")
    if not isinstance(declared_raw, list) or any(not isinstance(item, str) for item in declared_raw):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "workspace declared lease keys are malformed"
        )
    declared_keys = normalize_resource_keys(declared_raw)
    if not set(resource_keys).issubset(declared_keys):
        raise PermissionError("workspace did not declare every requested resource key")
    if receipt.get("state") == "resource_release_incomplete":
        remaining = receipt.get("remaining_resource_keys")
        if (
            not isinstance(remaining, list)
            or any(not isinstance(item, str) for item in remaining)
            or not set(resource_keys).issubset(normalize_resource_keys(remaining))
        ):
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-mismatch",
                "workspace close receipt does not retain every requested resource",
            )
    closed_at = receipt.get("closed_at")
    if not isinstance(closed_at, str):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "workspace close receipt has no canonical terminal timestamp",
        )
    try:
        parsed_closed_at = datetime.fromisoformat(closed_at)
        if parsed_closed_at.tzinfo is None or parsed_closed_at.utcoffset() is None:
            raise ValueError("workspace close timestamp has no UTC offset")
        terminal_at_unix = int(parsed_closed_at.timestamp())
    except (ValueError, OverflowError) as exc:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "workspace close receipt terminal timestamp is invalid",
        ) from exc
    expected_metadata_sha256 = _metadata(
        {
            "workspace_id": workspace_id,
            "binding": manifest.get("binding"),
            "base_head": manifest.get("expected_base_head"),
            "plan_sha256": manifest.get("plan_sha256"),
        }
    )[1]
    snapshots_by_key = {item["resource_key"]: item for item in expected_leases}
    for key in resource_keys:
        snapshot = snapshots_by_key[key]
        if snapshot["metadata_sha256"] != expected_metadata_sha256:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-mismatch",
                "workspace lease metadata does not bind the canonical workspace plan",
            )
        if snapshot["acquired_at_unix"] >= terminal_at_unix:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-drift",
                "workspace lease was acquired at or after the terminal closeout",
            )
        if snapshot["updated_at_unix"] >= terminal_at_unix:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-drift",
                "workspace lease was updated at or after the terminal closeout",
            )
    return {
        "kind": "agent_workspace_close",
        "workspace_id": workspace_id,
        "close_receipt_sha256": receipt_sha256,
        "closure_outcome": receipt.get("closure_outcome"),
        "state": receipt.get("state"),
        "owner_id": owner_id,
        "resource_keys": resource_keys,
    }


def _verify_task_terminal_source(
    terminal_source: dict[str, Any],
    *,
    owner_id: str,
    resource_keys: list[str],
    expected_leases: list[dict[str, Any]],
) -> dict[str, Any]:
    if set(terminal_source) != {"kind", "task_id", "outcome_receipt_sha256"}:
        raise ValueError("task terminal_source keys are invalid")
    import grabowski_tasks as tasks

    task_id = terminal_source["task_id"]
    receipt_sha256 = terminal_source["outcome_receipt_sha256"]
    if not isinstance(task_id, str) or tasks.TASK_ID.fullmatch(task_id) is None:
        raise ValueError("task_id is invalid")
    if not isinstance(receipt_sha256, str) or SHA256_RE.fullmatch(receipt_sha256) is None:
        raise ValueError("outcome_receipt_sha256 is invalid")
    record = tasks._row(task_id)
    expected_owner = record.get("lease_owner_id") or tasks._lease_owner(task_id)
    if expected_owner != owner_id:
        raise PermissionError("task terminal evidence belongs to another lease owner")
    declared_keys = sorted(tasks._record_resource_keys(record))
    if not set(resource_keys).issubset(declared_keys):
        raise PermissionError("task did not declare every requested resource key")
    receipt_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
    if not receipt_path.is_file():
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-missing", "task outcome receipt is absent"
        )
    receipt = _load_private_receipt_json(receipt_path)
    stored_sha256 = receipt.get("receipt_sha256")
    receipt_resource_keys = receipt.get("resource_keys")
    if (
        receipt.get("schema_version") != 1
        or not isinstance(receipt_resource_keys, list)
        or any(not isinstance(item, str) for item in receipt_resource_keys)
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "task outcome receipt shape is invalid"
        )
    if set(receipt) != {
        "schema_version",
        "task_id",
        "unit",
        "attempt",
        "state",
        "argv_sha256",
        "execution_envelope_sha256",
        "resource_keys",
        "observed_at_unix",
        "observation_sha256",
        "observation",
        "receipt_sha256",
    }:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "task outcome receipt is not the canonical schema-1 shape",
        )
    core = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    if (
        stored_sha256 != receipt_sha256
        or not isinstance(stored_sha256, str)
        or SHA256_RE.fullmatch(stored_sha256) is None
        or hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest() != stored_sha256
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "task outcome receipt integrity is invalid"
        )
    if (
        receipt.get("task_id") != task_id
        or receipt.get("state") not in TASK_RELEASABLE_STATES
        or record.get("state") != receipt.get("state")
        or record.get("attempt") != receipt.get("attempt")
        or record.get("unit") != receipt.get("unit")
        or record.get("argv_sha256") != receipt.get("argv_sha256")
    ):
        raise nonconflict.NonConflictDenied(
            "owner-work-nonterminal",
            "task outcome is not a current completed attempt",
        )
    if not set(resource_keys).issubset(normalize_resource_keys(receipt_resource_keys)):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-mismatch", "task receipt does not bind requested resources"
        )
    observed_at_unix = receipt.get("observed_at_unix")
    if isinstance(observed_at_unix, bool) or not isinstance(observed_at_unix, int):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "task outcome receipt terminal timestamp is invalid",
        )
    expected_metadata_sha256 = _metadata(
        {
            "task_id": task_id,
            "host": record.get("host"),
            "attempt": record.get("attempt"),
        }
    )[1]
    snapshots_by_key = {item["resource_key"]: item for item in expected_leases}
    for key in resource_keys:
        snapshot = snapshots_by_key[key]
        if snapshot["metadata_sha256"] != expected_metadata_sha256:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-mismatch",
                "task lease metadata does not bind the canonical task attempt",
            )
        if snapshot["acquired_at_unix"] >= observed_at_unix:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-drift",
                "task lease was acquired at or after the authoritative terminal observation",
            )
        if snapshot["updated_at_unix"] >= observed_at_unix:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-drift",
                "task lease was updated at or after the authoritative terminal observation",
            )
    return {
        "kind": "durable_task_outcome",
        "task_id": task_id,
        "outcome_receipt_sha256": receipt_sha256,
        "state": receipt.get("state"),
        "attempt": receipt.get("attempt"),
        "owner_id": owner_id,
        "resource_keys": resource_keys,
    }


def _verify_terminal_source(
    terminal_source: Any,
    *,
    owner_id: str,
    resource_keys: list[str],
    expected_leases: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(terminal_source, dict):
        raise ValueError("terminal_source must be an object")
    kind = terminal_source.get("kind")
    if kind == "agent_workspace_close":
        return _verify_workspace_terminal_source(
            terminal_source,
            owner_id=owner_id,
            resource_keys=resource_keys,
            expected_leases=expected_leases,
        )
    if kind == "durable_task_outcome":
        return _verify_task_terminal_source(
            terminal_source,
            owner_id=owner_id,
            resource_keys=resource_keys,
            expected_leases=expected_leases,
        )
    raise nonconflict.NonConflictDenied(
        "unsupported-terminal-source",
        "terminal_source kind must be agent_workspace_close or durable_task_outcome",
    )


def _reconcile_verified_path_leases(
    *,
    owner: str,
    keys: list[str],
    snapshots: list[dict[str, Any]],
    terminal_evidence: dict[str, Any],
) -> dict[str, Any]:
    expected_by_key = {item["resource_key"]: item for item in snapshots}
    released: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []
    now = _now()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is None:
                    retained.append({"resource_key": key, "reason": "already_absent"})
                    continue
                live = _release_lease_snapshot(row)
                if live["owner_id"] != owner:
                    retained.append({"resource_key": key, "reason": "owner_changed"})
                    continue
                if live != expected_by_key[key]:
                    retained.append({"resource_key": key, "reason": "lease_snapshot_changed"})
                    continue
                connection.execute(
                    "DELETE FROM leases WHERE resource_key=? AND owner_id=?",
                    (key, owner),
                )
                released.append(live)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    state = "complete" if len(released) == len(keys) else ("partial" if released else "no_change")
    core = {
        "schema_version": OBSOLETE_PATH_RELEASE_SCHEMA_VERSION,
        "kind": OBSOLETE_PATH_RELEASE_KIND,
        "state": state,
        "owner_id": owner,
        "resource_keys": keys,
        "expected_leases": snapshots,
        "terminal_evidence": terminal_evidence,
        "released": released,
        "retained": retained,
        "reconciled_at_unix": now,
        "does_not_establish": RECONCILIATION_NON_CLAIMS,
    }
    return {**core, "receipt_sha256": hashlib.sha256(
        _canonical_json(core).encode("utf-8")
    ).hexdigest()}


def reconcile_obsolete_path_leases(
    *,
    owner_id: str,
    resource_keys: Iterable[str],
    expected_leases: Any,
    terminal_source: Any,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    if any(not key.startswith("path:") for key in keys):
        raise ValueError("obsolete lease reconciliation accepts exact path leases only")
    snapshots = _normalize_expected_lease_snapshots(
        expected_leases, owner_id=owner, resource_keys=keys
    )
    if not isinstance(terminal_source, dict):
        raise ValueError("terminal_source must be an object")
    if terminal_source.get("kind") == "agent_workspace_close":
        import grabowski_agent_workspace as workspace

        workspace_id = terminal_source.get("workspace_id")
        if not isinstance(workspace_id, str) or not workspace_id:
            raise ValueError("workspace_id is invalid")
        with workspace._lock(workspace_id):
            terminal_evidence = _verify_terminal_source(
                terminal_source,
                owner_id=owner,
                resource_keys=keys,
                expected_leases=snapshots,
            )
            return _reconcile_verified_path_leases(
                owner=owner,
                keys=keys,
                snapshots=snapshots,
                terminal_evidence=terminal_evidence,
            )
    terminal_evidence = _verify_terminal_source(
        terminal_source,
        owner_id=owner,
        resource_keys=keys,
        expected_leases=snapshots,
    )
    return _reconcile_verified_path_leases(
        owner=owner,
        keys=keys,
        snapshots=snapshots,
        terminal_evidence=terminal_evidence,
    )


def assess_nonconflict(
    *,
    blocked_resource_key: str,
    requesting_owner: str,
    resource_keys: Iterable[str],
    purpose: str,
    requested_scope: dict[str, Any],
    requested_scope_complete: bool,
    proof_ttl_seconds: int = nonconflict.MAX_PROOF_TTL_SECONDS,
) -> dict[str, Any]:
    blocked_key = normalize_resource_key(blocked_resource_key)
    owner = _owner(requesting_owner)
    if not blocked_key.startswith("repo:"):
        now = _now()
        with _database() as connection:
            row = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (blocked_key,)
            ).fetchone()
        if blocked_key.startswith("path:"):
            if row is None or row["expires_at_unix"] <= now:
                return {
                    "blocked_resource_key": blocked_key,
                    "requesting_owner": owner,
                    "decision": "deny",
                    "code": "blocked-path-lease-absent-or-expired",
                    "blocker_type": "exact_path_lease",
                    "requires_atomic_revalidation": False,
                    "recommended_next_action": "inspect the live lease and acquire normally",
                }
            return {
                "blocked_resource_key": blocked_key,
                "requesting_owner": owner,
                "decision": "deny",
                "code": "exact-path-owner-release-required",
                "blocker_type": "exact_path_lease",
                "blocked_lease": _release_lease_snapshot(row),
                "requires_atomic_revalidation": True,
                "recommended_next_action": "use grabowski_resource_reconcile_obsolete_path_leases only with authoritative terminal evidence and the unchanged lease snapshot",
                "does_not_establish": RECONCILIATION_NON_CLAIMS,
            }
        return {
            "blocked_resource_key": blocked_key,
            "requesting_owner": owner,
            "decision": "deny",
            "code": "unsupported-blocker-type",
            "blocker_type": blocked_key.split(":", 1)[0],
            "requires_atomic_revalidation": False,
            "recommended_next_action": "inspect the blocker and use its owner-specific lifecycle",
        }
    keys = normalize_resource_keys(resource_keys)
    lease_purpose = _purpose(purpose)
    if requested_scope_complete is not True:
        raise nonconflict.NonConflictDenied(
            "requested-scope-unattested",
            "requesting owner did not attest that the scope manifest is complete",
        )
    normalized_scope = nonconflict.normalize_scope_manifest(requested_scope)
    now = _now()
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM leases WHERE resource_key=?", (blocked_key,)
        ).fetchone()
        if row is None or row["expires_at_unix"] <= now:
            raise ValueError("blocking repository lease is absent or expired")
        blocker_metadata = _row_metadata(row)
        if blocker_metadata.get("lease_mode") == "emergency-recovery":
            raise nonconflict.NonConflictDenied(
                "emergency-recovery",
                "emergency recovery repository leases cannot be bypassed",
            )
        existing_scope = _scope_manifest_from_metadata(blocker_metadata, required=True)
        if existing_scope["repository"] != blocked_key.split(":", 1)[1]:
            raise nonconflict.NonConflictDenied(
                "blocking-scope-repository-mismatch",
                "blocking repository lease scope does not match its resource key",
            )
        normalized_scope = nonconflict.validate_resource_scope_binding(keys, normalized_scope)
        proof = nonconflict.create_nonconflict_proof(
            blocked_lease=row,
            existing_scope=existing_scope,
            requesting_owner=owner,
            resource_keys=keys,
            purpose=lease_purpose,
            requested_scope=normalized_scope,
            requested_scope_complete=True,
            proof_ttl_seconds=proof_ttl_seconds,
            now=now,
        )
    return {
        "blocked_resource_key": blocked_key,
        "requesting_owner": owner,
        "proof": proof,
        "decision": "allow",
        "requires_atomic_revalidation": True,
    }


def _bureau_metadata_phase(row: sqlite3.Row) -> str | None:
    try:
        value = json.loads(row["metadata_json"])
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    phase = value.get("bureau_phase")
    return phase if isinstance(phase, str) else None


def _check_bureau_semantic_conflicts(
    connection: sqlite3.Connection,
    *,
    keys: list[str],
    owner: str,
    now: int,
    bureau_contract: dict[str, Any] | None,
) -> None:
    if bureau_contract is None:
        return
    incoming_phase = bureau_contract["phase"]
    incoming_global_recovery = (
        incoming_phase == "emergency-recovery"
        and bureau_leases.BROAD_BUREAU_REPOSITORY_KEY in keys
    )
    rows = connection.execute(
        "SELECT * FROM leases WHERE expires_at_unix>? ORDER BY resource_key",
        (now,),
    ).fetchall()
    nonrenewable_effect_keys = {
        bureau_leases.BROAD_BUREAU_REPOSITORY_KEY,
        bureau_leases.BUREAU_MERGE_GATE_KEY,
        bureau_leases.BUREAU_WORKTREE_ADMIN_KEY,
    }
    for row in rows:
        existing_key = row["resource_key"]
        if not bureau_leases.is_bureau_resource_key(existing_key):
            continue
        same_owner = row["owner_id"] == owner
        existing_global_recovery = (
            existing_key == bureau_leases.BROAD_BUREAU_REPOSITORY_KEY
            and _bureau_metadata_phase(row) == "emergency-recovery"
        )
        if incoming_global_recovery or existing_global_recovery:
            raise ResourceConflict(
                existing_key,
                row["owner_id"],
                row["expires_at_unix"],
            )
        if (
            same_owner
            and existing_key in keys
            and existing_key in nonrenewable_effect_keys
        ):
            raise ResourceConflict(
                existing_key,
                row["owner_id"],
                row["expires_at_unix"],
            )


def _merge_guard_repository_from_row(row: sqlite3.Row) -> str | None:
    metadata = _row_metadata(row)
    guard = metadata.get("merge_guard")
    if not isinstance(guard, dict):
        return None
    repository = guard.get("local_resource_repository")
    if not isinstance(repository, str):
        return None
    normalized = Path(repository).expanduser()
    if not normalized.is_absolute():
        return None
    return os.path.normpath(str(normalized))


def _absolute_paths_overlap(left: str, right: str) -> bool:
    try:
        common = os.path.commonpath([left, right])
    except ValueError:
        return False
    return common == left or common == right


_MERGE_GUARD_MAX_CHANGED_PATHS = 128
_MERGE_GUARD_MAX_CHANGED_PATH_BYTES = 8 * 1024


def _normalize_merge_guard_changed_paths(
    values: Iterable[str], *, repository: str
) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError("merge guard changed_paths must be a list")
    normalized: list[str] = []
    for raw in values:
        if not isinstance(raw, str) or not raw or "\x00" in raw:
            raise ValueError("merge guard changed path is invalid")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            raise ValueError("merge guard changed paths must be absolute")
        path = os.path.normpath(str(candidate))
        try:
            within = os.path.commonpath([path, repository]) == repository
        except ValueError:
            within = False
        if not within or path == repository:
            raise ValueError("merge guard changed path must be inside repository")
        normalized.append(path)
    result = sorted(set(normalized))
    if not result:
        raise ValueError("merge guard changed_paths may not be empty")
    if len(result) > _MERGE_GUARD_MAX_CHANGED_PATHS:
        raise ValueError("merge guard changed_paths exceeds entry limit")
    if len(_canonical_json(result).encode("utf-8")) > (
        _MERGE_GUARD_MAX_CHANGED_PATH_BYTES
    ):
        raise ValueError("merge guard changed_paths exceeds byte limit")
    return result


def _merge_guard_relative_paths(
    values: Iterable[str], *, repository: str
) -> list[str]:
    absolute = _normalize_merge_guard_changed_paths(values, repository=repository)
    relative: list[str] = []
    for path in absolute:
        value = os.path.relpath(path, repository)
        if value in {"", "."} or value.startswith("../") or value == "..":
            raise ValueError("merge guard changed path must remain inside repository")
        relative.append(value)
    result = sorted(set(relative))
    if len(_canonical_json(result).encode("utf-8")) > (
        _MERGE_GUARD_MAX_CHANGED_PATH_BYTES
    ):
        raise ValueError("merge guard changed_paths exceeds byte limit")
    return result


def _merge_guard_changed_paths_from_row(
    row: sqlite3.Row, *, repository: str
) -> list[str] | None:
    metadata = _row_metadata(row)
    guard = metadata.get("merge_guard")
    if not isinstance(guard, dict):
        return None
    values = guard.get("local_changed_paths")
    if not isinstance(values, list):
        return None
    absolute: list[str] = []
    for raw in values:
        if (
            not isinstance(raw, str)
            or not raw
            or raw.startswith("/")
            or "\x00" in raw
            or any(part in {"", ".", ".."} for part in raw.split("/"))
        ):
            return None
        absolute.append(os.path.normpath(os.path.join(repository, raw)))
    try:
        normalized = _normalize_merge_guard_changed_paths(
            absolute, repository=repository
        )
    except ValueError:
        return None
    try:
        if _merge_guard_relative_paths(normalized, repository=repository) != sorted(values):
            return None
    except ValueError:
        return None
    return normalized


def _resource_path_value(resource_key: str) -> str | None:
    if not resource_key.startswith("path:"):
        return None
    return resource_key.split(":", 1)[1]


def _repository_resource_scope(
    resource_key: str, *, repository: str
) -> dict[str, str | None] | None:
    canonical_repository = os.path.normpath(repository)
    prefix = f"repo:{canonical_repository}"
    if resource_key == prefix:
        return {
            "repository": canonical_repository,
            "scope_kind": "repository",
            "scope_value": None,
        }
    for marker, scope_kind in ((":branch:", "branch"), (":operation:", "operation")):
        scoped_prefix = prefix + marker
        if not resource_key.startswith(scoped_prefix):
            continue
        scope_value = resource_key[len(scoped_prefix) :]
        return {
            "repository": canonical_repository,
            "scope_kind": scope_kind if scope_value else "invalid",
            "scope_value": scope_value or None,
        }
    return None


def _merge_guard_branch_names(metadata: dict[str, Any]) -> set[str] | None:
    guard = metadata.get("merge_guard")
    if not isinstance(guard, dict):
        return None
    names: set[str] = set()
    for field in ("base_branch", "head_branch"):
        value = guard.get(field)
        if (
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or len(value.encode("utf-8")) > 1024
        ):
            return None
        names.add(value)
    return names


def _merge_guard_effect_resource_keys(
    metadata: dict[str, Any],
) -> set[str] | None:
    guard = metadata.get("merge_guard")
    if not isinstance(guard, dict):
        return None
    raw_keys = guard.get("effect_resource_keys")
    expected_sha256 = guard.get("effect_resource_keys_sha256")
    if not isinstance(raw_keys, list) or any(
        not isinstance(item, str) for item in raw_keys
    ):
        return None
    try:
        normalized = normalize_resource_keys(raw_keys)
    except ValueError:
        return None
    if normalized != raw_keys:
        return None
    observed_sha256 = hashlib.sha256(
        _canonical_json(normalized).encode("utf-8")
    ).hexdigest()
    if expected_sha256 != observed_sha256:
        return None
    return set(normalized)


def _repository_resource_overlaps_merge_guard(
    resource_key: str,
    *,
    repository: str,
    guarded_branches: set[str] | None,
) -> bool:
    scope = _repository_resource_scope(resource_key, repository=repository)
    if scope is None or scope["repository"] != repository:
        return False
    if scope["scope_kind"] == "branch" and guarded_branches is not None:
        return scope["scope_value"] in guarded_branches
    return True


def _scope_path_values(scope: dict[str, Any] | None) -> list[str]:
    if scope is None:
        return []
    return sorted(set(scope.get("paths", []) + scope.get("generated_artifacts", [])))


def _paths_overlap_any(paths: Iterable[str], changed_paths: Iterable[str]) -> bool:
    return any(
        _absolute_paths_overlap(path, changed)
        for path in paths
        for changed in changed_paths
    )


def _check_active_merge_guard_conflicts(
    connection: sqlite3.Connection,
    *,
    keys: list[str],
    metadata: dict[str, Any],
    now: int,
) -> None:
    requested_scope = _scope_manifest_from_metadata(metadata, required=False)
    requested_paths = [
        path for key in keys if (path := _resource_path_value(key)) is not None
    ]
    requested_paths.extend(_scope_path_values(requested_scope))
    rows = connection.execute(
        "SELECT * FROM leases WHERE resource_key LIKE 'gate:github-merge:%' "
        "AND expires_at_unix>? ORDER BY resource_key",
        (now,),
    ).fetchall()
    for row in rows:
        repository = _merge_guard_repository_from_row(row)
        row_metadata = _row_metadata(row)
        _, observed_metadata_sha256 = _metadata(row_metadata)
        if row["metadata_sha256"] != observed_metadata_sha256:
            raise ResourceConflict(
                row["resource_key"], row["owner_id"], row["expires_at_unix"]
            )
        changed_paths = (
            None
            if repository is None
            else _merge_guard_changed_paths_from_row(row, repository=repository)
        )
        guarded_branches = _merge_guard_branch_names(row_metadata)
        effect_resource_keys = _merge_guard_effect_resource_keys(row_metadata)
        if (
            repository is None
            or changed_paths is None
            or guarded_branches is None
            or effect_resource_keys is None
        ):
            raise ResourceConflict(
                row["resource_key"], row["owner_id"], row["expires_at_unix"]
            )
        if set(keys).intersection(effect_resource_keys):
            raise ResourceConflict(
                row["resource_key"], row["owner_id"], row["expires_at_unix"]
            )
        requested_repo_scopes = [
            scope
            for key in keys
            if (
                scope := _repository_resource_scope(
                    key, repository=repository
                )
            )
            is not None
        ]
        repo_scope_same_repository = bool(requested_repo_scopes)
        repo_scope_overlap = any(
            _repository_resource_overlaps_merge_guard(
                key,
                repository=repository,
                guarded_branches=guarded_branches,
            )
            for key in keys
            if key.startswith("repo:")
        )
        same_repository = (
            repo_scope_same_repository
            or (
                requested_scope is not None
                and requested_scope["repository"] == repository
            )
            or any(
                _path_is_within_repository(f"path:{path}", repository)
                for path in requested_paths
            )
        )
        if not same_repository:
            continue
        path_overlap = _paths_overlap_any(requested_paths, changed_paths)
        scope_mutating = (
            requested_scope is not None
            and bool(set(requested_scope.get("effects", [])) - {"read"})
        )
        scope_without_paths = (
            requested_scope is not None
            and requested_scope["repository"] == repository
            and not _scope_path_values(requested_scope)
            and scope_mutating
        )
        scope_unattested_mutation = (
            requested_scope is not None
            and requested_scope["repository"] == repository
            and scope_mutating
            and metadata.get("scope_manifest_complete") is not True
        )
        if (
            repo_scope_overlap
            or path_overlap
            or scope_without_paths
            or scope_unattested_mutation
        ):
            raise ResourceConflict(
                row["resource_key"], row["owner_id"], row["expires_at_unix"]
            )



def _task_identifier(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{24}", value) is None:
        raise ValueError("task_id must be 24 lowercase hex characters")
    return value


def _task_lease_owner(task_id: str, owner_id: str) -> str:
    identifier = _task_identifier(task_id)
    owner = _owner(owner_id)
    if owner != f"task:{identifier}":
        raise ValueError("task lease owner does not match task_id")
    return owner


def _optional_resource_keys(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError("resource_keys must be a list")
    raw = list(values)
    if not raw:
        return []
    return normalize_resource_keys(raw)


def _task_terminalization_public(
    row: sqlite3.Row | dict[str, Any], *, include_projection: bool = False
) -> dict[str, Any]:
    record = dict(row)
    result: dict[str, Any] = {
        "schema_version": TASK_TERMINALIZATION_SCHEMA_VERSION,
        "kind": TASK_TERMINALIZATION_KIND,
        "task_id": record["task_id"],
        "attempt": int(record["attempt"]),
        "lease_owner_id": record["lease_owner_id"],
        "terminal_state": record["terminal_state"],
        "phase": record["phase"],
        "task_projection_sha256": record["task_projection_sha256"],
        "requested_resource_keys": json.loads(record["requested_resource_keys_json"]),
        "requested_resource_keys_sha256": record["requested_resource_keys_sha256"],
        "prior_leases": json.loads(record["prior_leases_json"]),
        "prior_leases_sha256": record["prior_leases_sha256"],
        "revoked_resource_keys": json.loads(record["revoked_resource_keys_json"]),
        "missing_resource_keys": json.loads(record["missing_resource_keys_json"]),
        "observation_sha256": record["observation_sha256"],
        "prepared_at_unix": int(record["prepared_at_unix"]),
        "leases_revoked_at_unix": int(record["leases_revoked_at_unix"]),
        "projected_at_unix": (
            None if record["projected_at_unix"] is None else int(record["projected_at_unix"])
        ),
        "lifecycle_receipt_sha256": record["lifecycle_receipt_sha256"],
        "recovery_status": record["recovery_status"],
        "transition_sha256": record["transition_sha256"],
    }
    if include_projection:
        result["task_projection"] = json.loads(record["task_projection_json"])
    return result


def task_terminalization_record(
    task_id: str, *, include_projection: bool = False
) -> dict[str, Any] | None:
    identifier = _task_identifier(task_id)
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM task_terminalizations WHERE task_id=?",
            (identifier,),
        ).fetchone()
    return None if row is None else _task_terminalization_public(
        row, include_projection=include_projection
    )


def pending_task_terminalizations() -> list[dict[str, Any]]:
    with _database() as connection:
        rows = connection.execute(
            "SELECT * FROM task_terminalizations WHERE phase!='projected' "
            "ORDER BY prepared_at_unix, task_id"
        ).fetchall()
    return [
        _task_terminalization_public(row, include_projection=True) for row in rows
    ]


def begin_task_terminalization(
    task_id: str,
    attempt: int,
    lease_owner_id: str,
    terminal_state: str,
    resource_keys: Iterable[str],
    *,
    task_projection: dict[str, Any],
    observation_sha256: str,
    recovery_status: str = "not_recovered",
) -> dict[str, Any]:
    identifier = _task_identifier(task_id)
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("task attempt must be a positive integer")
    owner = _task_lease_owner(identifier, lease_owner_id)
    if terminal_state not in TASK_TERMINAL_STATES:
        raise ValueError("terminal_state is not terminal")
    requested_keys = _optional_resource_keys(resource_keys)
    if not isinstance(task_projection, dict):
        raise ValueError("task_projection must be an object")
    projection_json = _canonical_json(task_projection)
    if len(projection_json.encode("utf-8")) > 512 * 1024:
        raise ValueError("task_projection is too large")
    projection_sha256 = hashlib.sha256(projection_json.encode("utf-8")).hexdigest()
    if not isinstance(observation_sha256, str) or SHA256_RE.fullmatch(observation_sha256) is None:
        raise ValueError("observation_sha256 is invalid")
    if recovery_status not in {"not_recovered", "recovered_legacy_row_first", "recovered_after_revocation"}:
        raise ValueError("recovery_status is invalid")
    requested_json = _canonical_json(requested_keys)
    requested_sha256 = hashlib.sha256(requested_json.encode("utf-8")).hexdigest()
    now = _now()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DELETE FROM task_authority_adoptions WHERE expires_at_unix<=?",
                (now,),
            )
            adoption = connection.execute(
                "SELECT * FROM task_authority_adoptions WHERE task_id=?",
                (identifier,),
            ).fetchone()
            if adoption is not None:
                raise ResourceConflict(
                    f"gate:task-authority:{identifier}",
                    adoption["guard_owner_id"],
                    int(adoption["expires_at_unix"]),
                )
            existing = connection.execute(
                "SELECT * FROM task_terminalizations WHERE task_id=?",
                (identifier,),
            ).fetchone()
            if existing is not None:
                immutable = {
                    "attempt": attempt,
                    "lease_owner_id": owner,
                    "terminal_state": terminal_state,
                    "task_projection_sha256": projection_sha256,
                    "requested_resource_keys_sha256": requested_sha256,
                    "observation_sha256": observation_sha256,
                }
                for field, expected in immutable.items():
                    if existing[field] != expected:
                        raise ValueError(
                            f"task terminalization replay drift: {field}"
                        )
                connection.commit()
                return _task_terminalization_public(
                    existing, include_projection=True
                )
            lease_rows = connection.execute(
                "SELECT * FROM leases WHERE owner_id=? ORDER BY resource_key",
                (owner,),
            ).fetchall()
            prior_leases: list[dict[str, Any]] = []
            revoked_keys: list[str] = []
            for row in lease_rows:
                snapshot = _public(row)
                metadata_integrity_valid = False
                task_binding_valid = False
                try:
                    metadata = _row_metadata(row)
                    _, observed_metadata_sha256 = _metadata(metadata)
                    metadata_integrity_valid = (
                        row["metadata_sha256"] == observed_metadata_sha256
                    )
                    task_binding_valid = metadata.get("task_id") == identifier
                except Exception:
                    metadata_integrity_valid = False
                    task_binding_valid = False
                prior_leases.append(
                    {
                        **snapshot,
                        "metadata_integrity_valid": metadata_integrity_valid,
                        "task_binding_valid": task_binding_valid,
                    }
                )
                revoked_keys.append(str(row["resource_key"]))
            revoked_keys = sorted(revoked_keys)
            missing_keys = sorted(set(requested_keys) - set(revoked_keys))
            prior_json = _canonical_json(prior_leases)
            prior_sha256 = hashlib.sha256(prior_json.encode("utf-8")).hexdigest()
            if revoked_keys:
                connection.execute(
                    "DELETE FROM leases WHERE owner_id=?",
                    (owner,),
                )
            transition_material = {
                "schema_version": TASK_TERMINALIZATION_SCHEMA_VERSION,
                "kind": TASK_TERMINALIZATION_KIND,
                "task_id": identifier,
                "attempt": attempt,
                "lease_owner_id": owner,
                "terminal_state": terminal_state,
                "task_projection_sha256": projection_sha256,
                "requested_resource_keys_sha256": requested_sha256,
                "prior_leases_sha256": prior_sha256,
                "revoked_resource_keys": revoked_keys,
                "missing_resource_keys": missing_keys,
                "observation_sha256": observation_sha256,
                "prepared_at_unix": now,
                "leases_revoked_at_unix": now,
                "recovery_status": recovery_status,
            }
            transition_sha256 = hashlib.sha256(
                _canonical_json(transition_material).encode("utf-8")
            ).hexdigest()
            connection.execute(
                """
                INSERT INTO task_terminalizations(
                    task_id, attempt, lease_owner_id, terminal_state, phase,
                    task_projection_json, task_projection_sha256,
                    requested_resource_keys_json, requested_resource_keys_sha256,
                    prior_leases_json, prior_leases_sha256,
                    revoked_resource_keys_json, missing_resource_keys_json,
                    observation_sha256, prepared_at_unix, leases_revoked_at_unix,
                    projected_at_unix, lifecycle_receipt_sha256,
                    recovery_status, transition_sha256
                ) VALUES(?, ?, ?, ?, 'leases_revoked', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                """,
                (
                    identifier,
                    attempt,
                    owner,
                    terminal_state,
                    projection_json,
                    projection_sha256,
                    requested_json,
                    requested_sha256,
                    prior_json,
                    prior_sha256,
                    _canonical_json(revoked_keys),
                    _canonical_json(missing_keys),
                    observation_sha256,
                    now,
                    now,
                    recovery_status,
                    transition_sha256,
                ),
            )
            row = connection.execute(
                "SELECT * FROM task_terminalizations WHERE task_id=?",
                (identifier,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    if row is None:
        raise RuntimeError("task terminalization was not persisted")
    return _task_terminalization_public(row, include_projection=True)


def complete_task_terminalization(
    task_id: str,
    transition_sha256: str,
    lifecycle_receipt_sha256: str,
    *,
    recovered: bool = False,
) -> dict[str, Any]:
    identifier = _task_identifier(task_id)
    if not isinstance(transition_sha256, str) or SHA256_RE.fullmatch(transition_sha256) is None:
        raise ValueError("transition_sha256 is invalid")
    if not isinstance(lifecycle_receipt_sha256, str) or SHA256_RE.fullmatch(lifecycle_receipt_sha256) is None:
        raise ValueError("lifecycle_receipt_sha256 is invalid")
    now = _now()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT * FROM task_terminalizations WHERE task_id=?",
                (identifier,),
            ).fetchone()
            if row is None:
                raise ValueError("task terminalization is missing")
            if row["transition_sha256"] != transition_sha256:
                raise ValueError("task terminalization transition digest drift")
            existing_receipt = row["lifecycle_receipt_sha256"]
            if existing_receipt not in {None, lifecycle_receipt_sha256}:
                raise ValueError("task terminalization receipt digest drift")
            recovery_status = str(row["recovery_status"])
            if recovered and recovery_status == "not_recovered":
                recovery_status = "recovered_after_revocation"
            connection.execute(
                "UPDATE task_terminalizations SET phase='projected', "
                "projected_at_unix=COALESCE(projected_at_unix, ?), "
                "lifecycle_receipt_sha256=?, recovery_status=? WHERE task_id=?",
                (now, lifecycle_receipt_sha256, recovery_status, identifier),
            )
            updated = connection.execute(
                "SELECT * FROM task_terminalizations WHERE task_id=?",
                (identifier,),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    if updated is None:
        raise RuntimeError("task terminalization completion disappeared")
    return _task_terminalization_public(updated, include_projection=True)


def release_task_authority_adoption(
    guard_owner_id: str, task_id: str
) -> dict[str, Any]:
    guard_owner = _owner(guard_owner_id)
    identifier = _task_identifier(task_id)
    released: dict[str, Any] | None = None
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT * FROM task_authority_adoptions WHERE task_id=?",
                (identifier,),
            ).fetchone()
            if row is not None:
                if row["guard_owner_id"] != guard_owner:
                    raise PermissionError("task authority adoption belongs to another guard")
                released = dict(row)
                connection.execute(
                    "DELETE FROM task_authority_adoptions WHERE task_id=?",
                    (identifier,),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {
        "schema_version": 1,
        "kind": TASK_AUTHORITY_ADOPTION_KIND,
        "task_id": identifier,
        "guard_owner_id": guard_owner,
        "released": released is not None,
        "binding_sha256": None if released is None else released["binding_sha256"],
    }


def task_lease_delegation_evidence(
    owner_id: str,
    task_id: str,
    resource_keys: Iterable[str],
    *,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Return integrity-bound evidence for one task owner's complete live lease set."""
    owner = _owner(owner_id)
    if not isinstance(task_id, str) or re.fullmatch(r"[0-9a-f]{24}", task_id) is None:
        raise ValueError("task_id is invalid")
    if owner != f"task:{task_id}":
        raise ValueError("task lease owner does not match task_id")
    keys = normalize_resource_keys(resource_keys)
    now = _now() if now_unix is None else int(now_unix)
    bindings: list[dict[str, str]] = []
    minimum_expiry: int | None = None
    with _database() as connection:
        terminalization = connection.execute(
            "SELECT transition_sha256 FROM task_terminalizations WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if terminalization is not None:
            raise ValueError("task authority has been terminalized")
        owner_rows = connection.execute(
            "SELECT * FROM leases WHERE owner_id=? ORDER BY resource_key",
            (owner,),
        ).fetchall()
        owner_keys = [str(row["resource_key"]) for row in owner_rows]
        missing_owner_keys = sorted(set(keys) - set(owner_keys))
        if missing_owner_keys:
            raise ValueError(f"task lease is not live: {missing_owner_keys[0]}")
        if owner_keys != keys:
            raise ValueError("task lease set does not match the complete current owner lease set")
        rows = owner_rows
        by_key = {row["resource_key"]: row for row in rows}
        for key in keys:
            row = by_key.get(key)
            if row is None or row["expires_at_unix"] <= now:
                raise ValueError(f"task lease is not live: {key}")
            if row["owner_id"] != owner:
                raise ValueError(f"task lease owner mismatch: {key}")
            metadata = _row_metadata(row)
            _, observed_metadata_sha256 = _metadata(metadata)
            if row["metadata_sha256"] != observed_metadata_sha256:
                raise ValueError(f"task lease metadata integrity mismatch: {key}")
            if metadata.get("task_id") != task_id:
                raise ValueError(f"task lease metadata task mismatch: {key}")
            bindings.append(
                {
                    "resource_key": key,
                    "metadata_sha256": row["metadata_sha256"],
                }
            )
            expiry = int(row["expires_at_unix"])
            minimum_expiry = expiry if minimum_expiry is None else min(minimum_expiry, expiry)
    return {
        "schema_version": 1,
        "kind": "grabowski_live_task_lease_evidence",
        "task_id": task_id,
        "lease_owner_id": owner,
        "resource_keys": keys,
        "resource_keys_sha256": hashlib.sha256(
            _canonical_json(keys).encode("utf-8")
        ).hexdigest(),
        "lease_bindings_sha256": hashlib.sha256(
            _canonical_json(bindings).encode("utf-8")
        ).hexdigest(),
        "minimum_expires_at_unix": minimum_expiry,
        "observed_at_unix": now,
    }


def acquire_merge_guard_resources(
    guard_owner_id: str,
    lease_owner_id: str,
    resource_keys: Iterable[str],
    *,
    repository: str,
    changed_paths: Iterable[str],
    purpose: str,
    ttl_seconds: int = 300,
    metadata: dict[str, Any] | None = None,
    delegated_task: dict[str, Any] | None = None,
) -> dict[str, Any]:
    guard_owner = _owner(guard_owner_id)
    lease_owner = _owner(lease_owner_id)
    if guard_owner == lease_owner:
        raise ValueError("merge guard owner must be distinct from lease owner")
    keys = normalize_resource_keys(resource_keys)
    lease_purpose = _purpose(purpose)
    ttl = _ttl(ttl_seconds)
    delegated_task_id: str | None = None
    delegated_resource_keys: list[str] = []
    delegated_bindings_sha256: str | None = None
    delegated_expires_at_unix: int | None = None
    if delegated_task is not None:
        required = {
            "task_id",
            "lease_owner_id",
            "resource_keys",
            "resource_keys_sha256",
            "lease_bindings_sha256",
        }
        if not isinstance(delegated_task, dict) or not required.issubset(delegated_task):
            raise ValueError("delegated task binding is invalid")
        delegated_task_id = delegated_task.get("task_id")
        if (
            not isinstance(delegated_task_id, str)
            or re.fullmatch(r"[0-9a-f]{24}", delegated_task_id) is None
        ):
            raise ValueError("delegated task_id is invalid")
        if delegated_task.get("lease_owner_id") != lease_owner:
            raise ValueError("delegated task owner does not match lease owner")
        delegated_resource_keys = normalize_resource_keys(
            delegated_task.get("resource_keys")
        )
        expected_keys_sha256 = hashlib.sha256(
            _canonical_json(delegated_resource_keys).encode("utf-8")
        ).hexdigest()
        if delegated_task.get("resource_keys_sha256") != expected_keys_sha256:
            raise ValueError("delegated task resource key digest is invalid")
        delegated_bindings_sha256 = delegated_task.get("lease_bindings_sha256")
        if (
            not isinstance(delegated_bindings_sha256, str)
            or SHA256_RE.fullmatch(delegated_bindings_sha256) is None
        ):
            raise ValueError("delegated task lease binding digest is invalid")
        delegated_expiry = delegated_task.get(
            "expires_at_unix",
            delegated_task.get("minimum_expires_at_unix"),
        )
        if (
            not isinstance(delegated_expiry, int)
            or isinstance(delegated_expiry, bool)
            or delegated_expiry < 1
        ):
            raise ValueError("delegated task lease expiry is invalid")
        delegated_expires_at_unix = delegated_expiry
    repository_path = Path(repository).expanduser()
    if not repository_path.is_absolute():
        raise ValueError("merge guard repository must be absolute")
    canonical_repository = os.path.normpath(str(repository_path))
    normalized_changed_paths = _normalize_merge_guard_changed_paths(
        changed_paths, repository=canonical_repository
    )
    relative_changed_paths = _merge_guard_relative_paths(
        normalized_changed_paths, repository=canonical_repository
    )
    repository_components = [
        key for key in keys if key.startswith("component:github-repository:")
    ]
    if len(repository_components) != 1:
        raise ValueError(
            "merge guard resources must include exactly one GitHub repository component"
        )
    gate_keys = [key for key in keys if key.startswith("gate:github-merge:")]
    if len(gate_keys) != 1:
        raise ValueError("merge guard resources must include exactly one GitHub merge gate")
    normalized_metadata: dict[str, Any] = {} if metadata is None else dict(metadata)
    guard_metadata = normalized_metadata.get("merge_guard")
    if not isinstance(guard_metadata, dict):
        raise ValueError("merge guard metadata is required")
    guard_metadata = dict(guard_metadata)
    guard_metadata["effect_resource_keys"] = keys
    guard_metadata["effect_resource_keys_sha256"] = hashlib.sha256(
        _canonical_json(keys).encode("utf-8")
    ).hexdigest()
    guard_metadata["local_resource_repository"] = canonical_repository
    guard_metadata["local_changed_paths"] = relative_changed_paths
    normalized_metadata["merge_guard"] = guard_metadata
    guarded_branches = _merge_guard_branch_names(normalized_metadata)
    if guarded_branches is None:
        raise ValueError(
            "merge guard metadata must bind valid base_branch and head_branch"
        )
    if "scope_manifest" in normalized_metadata:
        normalized_metadata["scope_manifest"] = nonconflict.normalize_scope_manifest(
            normalized_metadata["scope_manifest"]
        )
    metadata_json, metadata_sha256 = _metadata(normalized_metadata)
    now = _now()
    expires = now + ttl
    if delegated_expires_at_unix is not None and delegated_expires_at_unix <= now:
        raise ValueError("delegated task lease authority is expired")
    task_adoption_expires = (
        expires
        if delegated_expires_at_unix is None
        else min(expires, delegated_expires_at_unix)
    )
    observed: list[dict[str, Any]] = []
    acquired_rows: list[sqlite3.Row] = []
    held_keys: list[str] = []
    task_adoption: dict[str, Any] | None = None
    observed_at_unix_ns = 0
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            observed_at_unix_ns = time.time_ns()
            connection.execute(
                "DELETE FROM task_authority_adoptions WHERE expires_at_unix<=?",
                (now,),
            )
            if delegated_task_id is not None:
                terminalization = connection.execute(
                    "SELECT transition_sha256 FROM task_terminalizations WHERE task_id=?",
                    (delegated_task_id,),
                ).fetchone()
                if terminalization is not None:
                    raise ValueError("delegated task authority has been terminalized")
                existing_adoption = connection.execute(
                    "SELECT * FROM task_authority_adoptions WHERE task_id=?",
                    (delegated_task_id,),
                ).fetchone()
                adoption_material = {
                    "schema_version": 1,
                    "kind": TASK_AUTHORITY_ADOPTION_KIND,
                    "task_id": delegated_task_id,
                    "guard_owner_id": guard_owner,
                    "lease_owner_id": lease_owner,
                    "resource_keys_sha256": hashlib.sha256(
                        _canonical_json(delegated_resource_keys).encode("utf-8")
                    ).hexdigest(),
                    "lease_bindings_sha256": delegated_bindings_sha256,
                    "acquired_at_unix": now,
                    "expires_at_unix": task_adoption_expires,
                }
                adoption_sha256 = hashlib.sha256(
                    _canonical_json(adoption_material).encode("utf-8")
                ).hexdigest()
                if existing_adoption is not None:
                    if existing_adoption["guard_owner_id"] != guard_owner:
                        raise ResourceConflict(
                            f"gate:task-authority:{delegated_task_id}",
                            existing_adoption["guard_owner_id"],
                            int(existing_adoption["expires_at_unix"]),
                        )
                    if existing_adoption["binding_sha256"] != adoption_sha256:
                        raise ValueError("task authority adoption replay drift")
                else:
                    connection.execute(
                        "INSERT INTO task_authority_adoptions("
                        "task_id, guard_owner_id, lease_owner_id, acquired_at_unix, "
                        "expires_at_unix, binding_sha256) VALUES(?, ?, ?, ?, ?, ?)",
                        (
                            delegated_task_id,
                            guard_owner,
                            lease_owner,
                            now,
                            task_adoption_expires,
                            adoption_sha256,
                        ),
                    )
                task_adoption = {**adoption_material, "binding_sha256": adoption_sha256}
            rows = connection.execute(
                "SELECT * FROM leases WHERE expires_at_unix>? ORDER BY resource_key",
                (now,),
            ).fetchall()
            if delegated_task_id is not None:
                delegated_rows = {
                    row["resource_key"]: row
                    for row in rows
                    if row["resource_key"] in delegated_resource_keys
                }
                bindings: list[dict[str, str]] = []
                for delegated_key in delegated_resource_keys:
                    delegated_row = delegated_rows.get(delegated_key)
                    if delegated_row is None:
                        raise ValueError(
                            f"delegated task lease is not live: {delegated_key}"
                        )
                    if delegated_row["owner_id"] != lease_owner:
                        raise ResourceConflict(
                            delegated_key,
                            delegated_row["owner_id"],
                            delegated_row["expires_at_unix"],
                        )
                    delegated_metadata = _row_metadata(delegated_row)
                    _, observed_delegated_sha256 = _metadata(delegated_metadata)
                    if delegated_row["metadata_sha256"] != observed_delegated_sha256:
                        raise ValueError(
                            f"delegated task lease metadata integrity mismatch: {delegated_key}"
                        )
                    if delegated_metadata.get("task_id") != delegated_task_id:
                        raise ValueError(
                            f"delegated task lease metadata task mismatch: {delegated_key}"
                        )
                    bindings.append(
                        {
                            "resource_key": delegated_key,
                            "metadata_sha256": delegated_row["metadata_sha256"],
                        }
                    )
                observed_bindings_sha256 = hashlib.sha256(
                    _canonical_json(bindings).encode("utf-8")
                ).hexdigest()
                if observed_bindings_sha256 != delegated_bindings_sha256:
                    raise ValueError("delegated task lease bindings changed")
            existing_owned_keys: set[str] = set()
            for row in rows:
                row_key = row["resource_key"]
                row_metadata = _row_metadata(row)
                _, observed_metadata_sha256 = _metadata(row_metadata)
                if row["metadata_sha256"] != observed_metadata_sha256:
                    raise ResourceConflict(
                        row_key, row["owner_id"], row["expires_at_unix"]
                    )
                row_scope = _scope_manifest_from_metadata(row_metadata, required=False)
                row_path = _resource_path_value(row_key)
                row_repo_scope = _repository_resource_scope(
                    row_key, repository=canonical_repository
                )
                repo_resource_relevant = (
                    row_repo_scope is not None
                    and row_repo_scope["repository"] == canonical_repository
                    and (
                        row_repo_scope["scope_kind"] != "branch"
                        or guarded_branches is None
                        or row_repo_scope["scope_value"] in guarded_branches
                    )
                )
                same_scope_repository = (
                    row_scope is not None
                    and row_scope["repository"] == canonical_repository
                )
                scoped_paths = _scope_path_values(row_scope)
                scope_is_mutating = (
                    row_scope is not None
                    and bool(set(row_scope.get("effects", [])) - {"read"})
                )
                scope_is_broad_mutation = (
                    same_scope_repository
                    and not scoped_paths
                    and scope_is_mutating
                )
                scope_is_unattested_mutation = (
                    same_scope_repository
                    and scope_is_mutating
                    and row_metadata.get("scope_manifest_complete") is not True
                )
                relevant = (
                    row_key in keys
                    or repo_resource_relevant
                    or (
                        row_path is not None
                        and _paths_overlap_any([row_path], normalized_changed_paths)
                    )
                    or (
                        same_scope_repository
                        and _paths_overlap_any(scoped_paths, normalized_changed_paths)
                    )
                    or scope_is_broad_mutation
                    or scope_is_unattested_mutation
                )
                if not relevant:
                    continue
                snapshot = _public(row)
                observed.append(snapshot)
                same_lease_owner = row["owner_id"] == lease_owner
                if same_lease_owner:
                    if row_key.startswith("gate:github-merge:"):
                        raise ResourceConflict(
                            row_key, row["owner_id"], row["expires_at_unix"]
                        )
                    if (
                        delegated_task_id is not None
                        and row_key not in delegated_resource_keys
                    ):
                        raise ResourceConflict(
                            row_key, row["owner_id"], row["expires_at_unix"]
                        )
                    if row_key in keys:
                        existing_owned_keys.add(row_key)
                    continue
                raise ResourceConflict(
                    row_key, row["owner_id"], row["expires_at_unix"]
                )

            keys_to_acquire = [
                key for key in keys if key not in existing_owned_keys
            ]
            for key in keys_to_acquire:
                connection.execute(
                    """
                    INSERT INTO leases(
                        resource_key, owner_id, purpose, acquired_at_unix,
                        updated_at_unix, expires_at_unix, metadata_sha256,
                        metadata_json, reclaimed_from_owner
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL)
                    ON CONFLICT(resource_key) DO UPDATE SET
                        owner_id=excluded.owner_id,
                        purpose=excluded.purpose,
                        acquired_at_unix=excluded.acquired_at_unix,
                        updated_at_unix=excluded.updated_at_unix,
                        expires_at_unix=excluded.expires_at_unix,
                        metadata_sha256=excluded.metadata_sha256,
                        metadata_json=excluded.metadata_json,
                        reclaimed_from_owner=leases.owner_id
                    """,
                    (
                        key,
                        guard_owner,
                        lease_purpose,
                        now,
                        now,
                        expires,
                        metadata_sha256,
                        metadata_json,
                    ),
                )
            if keys_to_acquire:
                acquired_rows = connection.execute(
                    f"SELECT * FROM leases WHERE resource_key IN ({','.join('?' for _ in keys_to_acquire)}) "
                    "ORDER BY resource_key",
                    keys_to_acquire,
                ).fetchall()
            held_keys = sorted(keys_to_acquire)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {
        "guard_owner_id": guard_owner,
        "lease_owner_id": lease_owner,
        "repository": canonical_repository,
        "changed_paths": normalized_changed_paths,
        "relative_changed_paths": relative_changed_paths,
        "changed_paths_sha256": hashlib.sha256(
            _canonical_json(relative_changed_paths).encode("utf-8")
        ).hexdigest(),
        "observed_at_unix": now,
        "observed_at_unix_ns": observed_at_unix_ns,
        "expires_at_unix": expires,
        "observed_leases": observed,
        "acquired_leases": [_public(row) for row in acquired_rows],
        "held_resource_keys": held_keys,
        "resource_keys": keys,
        "delegated_task_id": delegated_task_id,
        "delegated_task_resource_keys": delegated_resource_keys,
        "task_authority_adoption": task_adoption,
    }


def acquire_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    purpose: str,
    ttl_seconds: int = 3600,
    metadata: dict[str, Any] | None = None,
    nonconflict_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    task_owner_match = re.fullmatch(r"task:([0-9a-f]{24})", owner)
    keys = normalize_resource_keys(resource_keys)
    lease_purpose = _purpose(purpose)
    ttl = _ttl(ttl_seconds)
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    normalized_metadata: dict[str, Any] = {} if metadata is None else dict(metadata)
    if "scope_manifest" in normalized_metadata:
        normalized_metadata["scope_manifest"] = nonconflict.normalize_scope_manifest(
            normalized_metadata["scope_manifest"]
        )
    lease_mode = normalized_metadata.get("lease_mode", "normal")
    if lease_mode not in {"normal", "emergency-recovery"}:
        raise ValueError("metadata.lease_mode must be normal or emergency-recovery")
    if lease_mode == "emergency-recovery" and not any(key.startswith("repo:") for key in keys):
        raise ValueError("emergency-recovery mode requires a repository lease")
    sanitized_value = bureau_leases.sanitize_bureau_metadata(keys, normalized_metadata)
    sanitized_metadata: dict[str, Any] = {} if sanitized_value is None else sanitized_value
    bureau_contract = bureau_leases.enforce_bureau_lease_contract(
        keys, ttl_seconds=ttl, metadata=normalized_metadata
    )
    now = _now()
    expires = now + ttl
    reclaimed: list[dict[str, Any]] = []
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            if task_owner_match is not None:
                terminalization = connection.execute(
                    "SELECT transition_sha256 FROM task_terminalizations WHERE task_id=?",
                    (task_owner_match.group(1),),
                ).fetchone()
                if terminalization is not None:
                    raise ValueError("terminalized task owner cannot acquire resources")
            _check_active_merge_guard_conflicts(
                connection, keys=keys, metadata=sanitized_metadata, now=now
            )
            _check_bureau_semantic_conflicts(
                connection,
                keys=keys,
                owner=owner,
                now=now,
                bureau_contract=bureau_contract,
            )
            existing: dict[str, sqlite3.Row] = {}
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is not None:
                    existing[key] = row
                    live = row["expires_at_unix"] > now
                    critical_reentry = live and any(
                        key.startswith(prefix)
                        for prefix in NONRENEWABLE_CRITICAL_RESOURCE_PREFIXES
                    )
                    if live and (row["owner_id"] != owner or critical_reentry):
                        raise ResourceConflict(
                            key, row["owner_id"], row["expires_at_unix"]
                        )
            nonconflict_exception = _check_repository_semantic_conflicts(
                connection,
                keys=keys,
                owner=owner,
                purpose=lease_purpose,
                ttl_seconds=ttl,
                metadata=sanitized_metadata,
                nonconflict_proof=nonconflict_proof,
                now=now,
            )
            persisted_metadata = dict(sanitized_metadata)
            if nonconflict_exception is not None:
                persisted_metadata["nonconflict_exception"] = nonconflict_exception
            metadata_json, metadata_sha256 = _metadata(persisted_metadata)
            for key in keys:
                row = existing.get(key)
                acquired = now if row is None or row["owner_id"] != owner else row["acquired_at_unix"]
                previous_owner = None
                if row is not None and row["owner_id"] != owner:
                    previous_owner = row["owner_id"]
                    reclaimed.append(
                        {
                            "resource_key": key,
                            "previous_owner_id": previous_owner,
                            "previous_expires_at_unix": row["expires_at_unix"],
                        }
                    )
                connection.execute(
                    """
                    INSERT INTO leases(
                        resource_key, owner_id, purpose, acquired_at_unix,
                        updated_at_unix, expires_at_unix, metadata_sha256,
                        metadata_json, reclaimed_from_owner
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(resource_key) DO UPDATE SET
                        owner_id=excluded.owner_id,
                        purpose=excluded.purpose,
                        acquired_at_unix=excluded.acquired_at_unix,
                        updated_at_unix=excluded.updated_at_unix,
                        expires_at_unix=excluded.expires_at_unix,
                        metadata_sha256=excluded.metadata_sha256,
                        metadata_json=excluded.metadata_json,
                        reclaimed_from_owner=excluded.reclaimed_from_owner
                    """,
                    (
                        key,
                        owner,
                        lease_purpose,
                        acquired,
                        now,
                        expires,
                        metadata_sha256,
                        metadata_json,
                        previous_owner,
                    ),
                )
            rows = connection.execute(
                f"SELECT * FROM leases WHERE resource_key IN ({','.join('?' for _ in keys)}) "
                "ORDER BY resource_key",
                keys,
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {
        "owner_id": owner,
        "acquired_at_unix": now,
        "expires_at_unix": expires,
        "leases": [_public(row) for row in rows],
        "reclaimed": reclaimed,
        "bureau_contract": bureau_contract,
        "nonconflict_exception": nonconflict_exception,
    }


def renew_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    ttl = _ttl(ttl_seconds)
    bureau_contract = bureau_leases.enforce_bureau_lease_renewal(
        keys, ttl_seconds=ttl
    )
    now = _now()
    expires = now + ttl
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            _check_bureau_semantic_conflicts(
                connection,
                keys=keys,
                owner=owner,
                now=now,
                bureau_contract=bureau_contract,
            )
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?",
                    (key,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Unknown resource lease: {key}")
                if row["owner_id"] != owner:
                    raise PermissionError(f"Resource lease is owned by another owner: {key}")
                if row["expires_at_unix"] <= now:
                    raise RuntimeError(f"Resource lease has expired: {key}")
                if "nonconflict_exception" in _row_metadata(row):
                    raise RuntimeError(
                        "non-conflict exception leases are non-renewable; reassess and reacquire"
                    )
            connection.executemany(
                "UPDATE leases SET updated_at_unix=?, expires_at_unix=? "
                "WHERE resource_key=? AND owner_id=?",
                [(now, expires, key, owner) for key in keys],
            )
            rows = connection.execute(
                f"SELECT * FROM leases WHERE resource_key IN ({','.join('?' for _ in keys)}) "
                "ORDER BY resource_key",
                keys,
            ).fetchall()
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {
        "owner_id": owner,
        "leases": [_public(row) for row in rows],
        "bureau_contract": bureau_contract,
    }


def release_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    force: bool = False,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    released: list[dict[str, Any]] = []
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is None:
                    continue
                if not force and row["owner_id"] != owner:
                    raise PermissionError(f"Resource lease is owned by another owner: {key}")
                released.append(_public(row))
            if released:
                connection.executemany(
                    "DELETE FROM leases WHERE resource_key=?",
                    [(item["resource_key"],) for item in released],
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {"owner_id": owner, "force": force, "released": released}


def inspect_resource(resource_key: str) -> dict[str, Any] | None:
    key = normalize_resource_key(resource_key)
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM leases WHERE resource_key=?", (key,)
        ).fetchone()
    return None if row is None else _public(row)


def count_resources(
    *,
    owner_id: str | None = None,
    include_expired: bool = False,
) -> int:
    parameters: list[Any] = []
    clauses: list[str] = []
    if owner_id is not None:
        clauses.append("owner_id=?")
        parameters.append(_owner(owner_id))
    if not include_expired:
        clauses.append("expires_at_unix>?")
        parameters.append(_now())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with _database() as connection:
        row = connection.execute(
            f"SELECT COUNT(*) AS count FROM leases{where}",
            parameters,
        ).fetchone()
    return int(row["count"])


def list_resources(
    *,
    owner_id: str | None = None,
    include_expired: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    if not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    parameters: list[Any] = []
    clauses: list[str] = []
    if owner_id is not None:
        clauses.append("owner_id=?")
        parameters.append(_owner(owner_id))
    if not include_expired:
        clauses.append("expires_at_unix>?")
        parameters.append(_now())
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    parameters.append(limit)
    with _database() as connection:
        rows = connection.execute(
            f"SELECT * FROM leases{where} ORDER BY resource_key LIMIT ?",
            parameters,
        ).fetchall()
    return [_public(row) for row in rows]


@mcp.tool(name="grabowski_resource_nonconflict_assess", annotations=MUTATING)
def grabowski_resource_nonconflict_assess(
    blocked_resource_key: str,
    requesting_owner: str,
    resource_keys: list[str],
    purpose: str,
    requested_scope: dict[str, Any],
    requested_scope_complete: bool,
    proof_ttl_seconds: int = nonconflict.MAX_PROOF_TTL_SECONDS,
) -> dict[str, Any]:
    """Assess attested same-repository work; issue a short proof only when disjoint."""
    operator._require_operator_mutation("resource_lease")
    result = assess_nonconflict(
        blocked_resource_key=blocked_resource_key,
        requesting_owner=requesting_owner,
        resource_keys=resource_keys,
        purpose=purpose,
        requested_scope=requested_scope,
        requested_scope_complete=requested_scope_complete,
        proof_ttl_seconds=proof_ttl_seconds,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-nonconflict-assess",
            "blocked_resource_key": result["blocked_resource_key"],
            "requesting_owner": result["requesting_owner"],
            "decision": result["decision"],
            "requested_scope_complete": True,
            "proof_sha256": result["proof"]["proof_sha256"],
            "requested_scope_sha256": result["proof"]["requested_scope_sha256"],
            "existing_scope_sha256": result["proof"]["existing_scope_sha256"],
            "expires_at_unix": result["proof"]["expires_at_unix"],
        }
    )
    return result


@mcp.tool(name="grabowski_resource_reconcile_obsolete_path_leases", annotations=MUTATING)
def grabowski_resource_reconcile_obsolete_path_leases(
    owner_id: str,
    resource_keys: list[str],
    expected_leases: list[dict[str, Any]],
    terminal_source: dict[str, Any],
) -> dict[str, Any]:
    """Release only unchanged owner path leases after authoritative current terminal evidence."""
    operator._require_operator_mutation("resource_lease")
    result = reconcile_obsolete_path_leases(
        owner_id=owner_id,
        resource_keys=resource_keys,
        expected_leases=expected_leases,
        terminal_source=terminal_source,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-obsolete-path-reconcile",
            "owner_id": result["owner_id"],
            "resource_keys": result["resource_keys"],
            "state": result["state"],
            "released_count": len(result["released"]),
            "retained_count": len(result["retained"]),
            "terminal_source_kind": result["terminal_evidence"]["kind"],
            "receipt_sha256": result["receipt_sha256"],
        }
    )
    return result


def scoped_repository_resource_root(resource_key: str) -> str | None:
    """Return an existing Git root for one unambiguous scoped repo key.

    Repository paths may themselves contain ``:branch:`` or ``:operation:``.
    An existing full path is therefore always broad. A non-existing full path
    is treated as scoped only when exactly one marker split resolves to an
    existing checkout root with a .git entry; ambiguous inputs fail closed.
    """
    if not resource_key.startswith("repo:"):
        return None
    value = resource_key.removeprefix("repo:")
    if os.path.lexists(value):
        return None
    candidates: set[str] = set()
    for marker in (":branch:", ":operation:"):
        start = 0
        while True:
            index = value.find(marker, start)
            if index < 0:
                break
            repository = os.path.normpath(value[:index])
            scope_value = value[index + len(marker) :]
            if (
                scope_value
                and os.path.isabs(repository)
                and os.path.isdir(repository)
                and os.path.lexists(os.path.join(repository, ".git"))
            ):
                candidates.add(repository)
            start = index + len(marker)
    return next(iter(candidates)) if len(candidates) == 1 else None


def _public_repository_scope_keys(
    resource_keys: list[str], metadata: dict[str, Any] | None
) -> list[str]:
    """Require broad public repository leases to declare one exact scope."""
    keys = normalize_resource_keys(resource_keys)
    repository_keys = [key for key in keys if key.startswith("repo:")]
    if not repository_keys:
        return keys
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    normalized_metadata = {} if metadata is None else dict(metadata)
    if normalized_metadata.get("lease_mode") == "emergency-recovery":
        return keys
    scope = (
        nonconflict.normalize_scope_manifest(normalized_metadata["scope_manifest"])
        if "scope_manifest" in normalized_metadata
        else None
    )
    scoped_repository_keys: list[str] = []
    broad_repository_keys: list[str] = []
    for key in repository_keys:
        binding = (
            _repository_resource_scope(key, repository=scope["repository"])
            if scope is not None
            else None
        )
        manifest_scoped = (
            binding is not None
            and binding["scope_kind"] in {"branch", "operation"}
        )
        filesystem_scoped = scoped_repository_resource_root(key) is not None
        if manifest_scoped or filesystem_scoped:
            scoped_repository_keys.append(key)
            continue
        broad_repository_keys.append(key)
    if scoped_repository_keys and scope is not None:
        raise ValueError(
            "scoped repository leases must not include metadata.scope_manifest; "
            "the resource key is authoritative"
        )
    if not broad_repository_keys:
        return keys
    if normalized_metadata.get("scope_manifest_complete") is not True:
        raise ValueError(
            "public broad repository leases require metadata.scope_manifest_complete=true"
        )
    if scope is None:
        raise ValueError(
            "public broad repository leases require metadata.scope_manifest"
        )
    repository_key = f"repo:{scope['repository']}"
    for key in broad_repository_keys:
        if key == repository_key:
            continue
        raise ValueError(
            "repository resource keys must match metadata.scope_manifest repository"
        )
    return keys


@mcp.tool(name="grabowski_resource_acquire", annotations=MUTATING)
def grabowski_resource_acquire(
    owner_id: str,
    resource_keys: list[str],
    purpose: str,
    ttl_seconds: int = 3600,
    metadata: dict[str, Any] | None = None,
    nonconflict_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically acquire typed resource leases for one owner.

    Public broad repository resources require a complete exact scope manifest. An
    explicit emergency-recovery lease remains a deliberately exclusive
    fail-closed exception and cannot be used for non-conflict bypasses. Self-scoped
    branch and operation keys are authoritative and reject scope manifests.
    """
    normalized_resource_keys = _public_repository_scope_keys(resource_keys, metadata)
    operator._require_operator_mutation("resource_lease")
    result = acquire_resources(
        owner_id,
        normalized_resource_keys,
        purpose=purpose,
        ttl_seconds=ttl_seconds,
        metadata=metadata,
        nonconflict_proof=nonconflict_proof,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-acquire",
            "owner_id": result["owner_id"],
            "resource_keys": [item["resource_key"] for item in result["leases"]],
            "expires_at_unix": result["expires_at_unix"],
            "reclaimed_count": len(result["reclaimed"]),
            "bureau_contract": result.get("bureau_contract"),
            "nonconflict_exception": result.get("nonconflict_exception"),
        }
    )
    return result


@mcp.tool(name="grabowski_resource_renew", annotations=MUTATING)
def grabowski_resource_renew(
    owner_id: str,
    resource_keys: list[str],
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    """Renew live resource leases owned by one owner."""
    operator._require_operator_mutation("resource_lease")
    result = renew_resources(owner_id, resource_keys, ttl_seconds=ttl_seconds)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-renew",
            "owner_id": result["owner_id"],
            "resource_keys": [item["resource_key"] for item in result["leases"]],
            "bureau_contract": result.get("bureau_contract"),
        }
    )
    return result


@mcp.tool(name="grabowski_resource_release", annotations=MUTATING)
def grabowski_resource_release(
    owner_id: str,
    resource_keys: list[str],
    force: bool = False,
) -> dict[str, Any]:
    """Release owner-bound resource leases; force is an explicit high-risk override."""
    operator._require_operator_mutation("resource_lease")
    if not isinstance(force, bool):
        raise ValueError("force must be boolean")
    result = release_resources(owner_id, resource_keys, force=force)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-force-release" if force else "resource-release",
            "owner_id": result["owner_id"],
            "resource_keys": [item["resource_key"] for item in result["released"]],
            "force": force,
        }
    )
    return result


@mcp.tool(name="grabowski_resource_inspect", annotations=READ_ONLY)
def grabowski_resource_inspect(resource_key: str) -> dict[str, Any]:
    """Inspect one typed resource lease without returning private metadata."""
    operator._require_operator_capability("resource_lease")
    lease = inspect_resource(resource_key)
    return {"resource_key": normalize_resource_key(resource_key), "lease": lease}


@mcp.tool(name="grabowski_resource_list", annotations=READ_ONLY)
def grabowski_resource_list(
    owner_id: str | None = None,
    include_expired: bool = False,
    limit: int = 200,
    schema_only: bool = False,
) -> dict[str, Any]:
    """List bounded leases or inspect store-schema compatibility read-only."""
    operator._require_operator_capability("resource_lease")
    if not isinstance(schema_only, bool):
        raise ValueError("schema_only must be boolean")
    if schema_only:
        if owner_id is not None or include_expired or limit != 200:
            raise ValueError(
                "schema_only cannot be combined with resource-list filters"
            )
        return _resource_schema_inventory()
    leases = list_resources(
        owner_id=owner_id,
        include_expired=include_expired,
        limit=limit,
    )
    return {"database": str(RESOURCE_DB), "count": len(leases), "leases": leases}

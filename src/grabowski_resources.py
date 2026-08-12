from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
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
import grabowski_sqlite_store as sqlite_store
import grabowski_work_admission as work_admission
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
DEFAULT_RESOURCE_LIST_LIMIT = 200
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
    "host",
    "operation",
}
OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
DIRECT_OPERATOR_OWNER_RE = re.compile(r"operator:[A-Za-z0-9._:@-]{1,119}\Z")
SERVICE_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,255}\Z")
COMPONENT_RE = re.compile(r"[A-Za-z0-9_.:@/-]{1,255}\Z")
OPERATION_SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@/-]{0,255}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TASK_ID_RE = re.compile(r"[0-9a-f]{24}\Z")
MIN_TTL_SECONDS = 30
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_OPERATION_RESOURCE_VALUE_BYTES = 4096
OPERATION_SCOPE_SCHEMA_VERSION = 1
OPERATION_SCOPE_METADATA_KEY = "operation_scope"
OPERATION_SCOPE_EFFECT_CLASSES = frozenset(
    {"publication", "merge", "deploy", "worktree_admin", "unknown"}
)
OPERATION_SCOPE_CLASS_BY_EFFECT = {
    "publication": frozenset({"push", "pr-publication"}),
    "merge": frozenset({"merge"}),
    "deploy": frozenset({"deploy"}),
    "worktree_admin": frozenset({"worktree-admin"}),
    "unknown": frozenset({"unknown"}),
}
PUBLICATION_OPERATION_PREFIX_BY_CLASS = {
    "push": "branch-publish",
    "pr-publication": "pr-create-or-update",
}
MAX_TERMINAL_RECEIPT_BYTES = 64 * 1024
MAX_RUNTIME_REFRESH_RECEIPT_BYTES = 256 * 1024
BUREAU_RUNTIME_REFRESH_STATE_ROOT = Path(
    "~/.local/state/bureau/runtime-refresh"
).expanduser()
BUREAU_RUNTIME_REFRESH_RESULT_KIND = "bureau_runtime_refresh_result"
BUREAU_RUNTIME_REFRESH_START_KIND = "bureau_runtime_refresh_attempt_start"
BUREAU_RUNTIME_REFRESH_INTENT_KIND = "bureau_runtime_refresh_intent"
RUNTIME_REFRESH_RELEASABLE_STATUSES = frozenset(
    {"deployed", "already_current", "failed"}
)
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


def _is_live_lease(*, expires_at_unix: Any, now_unix: int) -> bool:
    """Return whether one persisted lease grants authority at one clock snapshot."""
    return (
        isinstance(expires_at_unix, int)
        and not isinstance(expires_at_unix, bool)
        and expires_at_unix > now_unix
    )


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


def _work_admission_metadata(
    assessments: list[dict[str, Any]],
) -> dict[str, Any]:
    decisions = {"allow": 0, "blocked": 0, "converge_first": 0}
    blocker_count = 0
    blocker_codes: set[str] = set()
    for assessment in assessments:
        decision = assessment.get("decision")
        if decision not in decisions:
            raise RuntimeError("work admission assessment decision is invalid")
        decisions[decision] += 1
        blockers = assessment.get("blockers")
        if isinstance(blockers, list):
            blocker_count += len(blockers)
        codes = assessment.get("blocker_codes")
        if isinstance(codes, list):
            blocker_codes.update(
                code
                for code in codes
                if isinstance(code, str)
                and re.fullmatch(r"[a-z0-9-]{1,64}", code) is not None
            )
    sorted_codes = sorted(blocker_codes)
    return {
        "schema_version": 1,
        "assessment_count": len(assessments),
        "assessment_sha256": hashlib.sha256(
            _canonical_json(assessments).encode("utf-8")
        ).hexdigest(),
        "decision_counts": decisions,
        "blocker_count": blocker_count,
        "blocker_codes": sorted_codes[:8],
        "blocker_codes_sha256": hashlib.sha256(
            _canonical_json(sorted_codes).encode("utf-8")
        ).hexdigest(),
        "blocker_codes_truncated": len(sorted_codes) > 8,
        "read_only": True,
    }


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
RESOURCE_SCHEMA_V3_TABLES = RESOURCE_SCHEMA_V2_TABLES
RESOURCE_SCHEMA_V3_REQUIRED_INDEXES = {
    "task_authority_adoptions_expiry_idx": (
        "task_authority_adoptions",
        ("expires_at_unix",),
    ),
    "task_terminalizations_pending_idx": (
        "task_terminalizations",
        ("phase", "prepared_at_unix", "task_id"),
    ),
}
RESOURCE_CURRENT_SCHEMA_VERSION = "3"
RESOURCE_SUPPORTED_SCHEMA_VERSIONS = ("1", "2", "3")
RESOURCE_LEASE_CONTRACT_METADATA_KEY = "resource_lease_contract_version"
RESOURCE_LEASE_CONTRACT_CURRENT_VERSION = "1"
RESOURCE_LEASE_CONTRACT_SUPPORTED_VERSIONS = ("1",)
RESOURCE_SCHEMA_MIGRATION_PATHS = {
    "1": ("1", RESOURCE_CURRENT_SCHEMA_VERSION),
    "2": ("2", RESOURCE_CURRENT_SCHEMA_VERSION),
}
RESOURCE_SCHEMA_RECOVERY_INSTRUCTION = (
    "Keep the resource store unchanged; use a runtime that explicitly supports "
    "the observed schema or restore a verified backup before retrying."
)

RESOURCE_SCHEMA_ROLLING_UPGRADE = {
    "current_runtime_current_store": "supported",
    "current_runtime_supported_older_store": (
        "supported_with_exclusive_migration"
    ),
    "current_runtime_newer_store": "fail_closed_without_mutation",
    "pre_t062_runtime_overlap_with_future_schema": (
        "unsupported_require_full_runtime_drain"
    ),
}


_resource_schema_directory_lock = sqlite_store.schema_directory_lock
_resource_readonly_sqlite = sqlite_store.readonly_sqlite


class ResourceSchemaInventoryChanged(RuntimeError):
    pass


class ResourceLeaseMissing(ValueError):
    """No lease exists for a requested resource key."""

    pass


class ResourceLeaseExpired(RuntimeError):
    """The observed lease generation is no longer live and may be reacquired."""

    pass


@contextmanager
def _resource_inventory_readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    with sqlite_store.inventory_readonly_sqlite(
        path,
        temporary_prefix="grabowski-resource-schema-inventory-",
        error_type=ResourceSchemaInventoryChanged,
    ) as connection:
        yield connection


_resource_sqlite_integrity = sqlite_store.sqlite_integrity
_resource_sqlite_fingerprint = sqlite_store.sqlite_fingerprint
_resource_database_tables = sqlite_store.database_tables


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


def _resource_lease_contract_version(
    connection: sqlite3.Connection, *, required: bool = True
) -> str | None:
    if _resource_table_shape(connection, "metadata") != RESOURCE_METADATA_SHAPE:
        raise RuntimeError("Resource database metadata table is malformed")
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key=?",
        (RESOURCE_LEASE_CONTRACT_METADATA_KEY,),
    ).fetchall()
    if not rows:
        if required:
            raise RuntimeError(
                "Resource lease contract metadata is missing; open the store with a "
                "compatible Grabowski runtime before retrying"
            )
        return None
    if len(rows) != 1:
        raise RuntimeError("Resource lease contract metadata is ambiguous")
    version = str(rows[0][0])
    if not version or len(version.encode("utf-8")) > 32 or not version.isdecimal():
        raise RuntimeError("Resource lease contract version is malformed")
    return version


def _validate_resource_lease_contract(connection: sqlite3.Connection) -> str:
    version = _resource_lease_contract_version(connection)
    if version not in RESOURCE_LEASE_CONTRACT_SUPPORTED_VERSIONS:
        raise RuntimeError(
            "Unsupported resource lease contract version; use a compatible runtime"
        )
    if _resource_table_shape(connection, "leases") != RESOURCE_LEASE_SHAPE:
        raise RuntimeError("Resource lease projection table is malformed")
    return version


def _begin_resource_lease_projection_read(
    connection: sqlite3.Connection, *, quick_integrity: bool = False
) -> str:
    connection.execute("BEGIN")
    if quick_integrity:
        _resource_sqlite_integrity(connection, "Resource database", quick=True)
    return _validate_resource_lease_contract(connection)


def _publish_resource_lease_contract(connection: sqlite3.Connection) -> None:
    observed = _resource_lease_contract_version(connection, required=False)
    if observed is None:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            (
                RESOURCE_LEASE_CONTRACT_METADATA_KEY,
                RESOURCE_LEASE_CONTRACT_CURRENT_VERSION,
            ),
        )
        return
    if observed != RESOURCE_LEASE_CONTRACT_CURRENT_VERSION:
        raise RuntimeError(
            "Resource lease contract changed while opening; use a compatible runtime"
        )


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


def _resource_indexes(
    connection: sqlite3.Connection,
    table_name: str,
) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute(f'PRAGMA index_list("{table_name}")')
    }


def _resource_index_columns(
    connection: sqlite3.Connection,
    index_name: str,
) -> tuple[str, ...]:
    return tuple(
        str(row[2])
        for row in connection.execute(f'PRAGMA index_info("{index_name}")')
    )


def _validate_resource_schema_v2(connection: sqlite3.Connection) -> None:
    if _resource_database_tables(connection) != RESOURCE_SCHEMA_V2_TABLES:
        raise RuntimeError("Unsupported resource database schema")
    if _resource_table_shape(connection, "metadata") != RESOURCE_METADATA_SHAPE:
        raise RuntimeError("Unsupported resource database schema")
    if _resource_table_shape(connection, "leases") != RESOURCE_LEASE_SHAPE:
        raise RuntimeError("Unsupported resource database schema")
    _validate_additive_schema_v2(connection)


def _validate_resource_schema_current(
    connection: sqlite3.Connection, *, require_lease_contract: bool = True
) -> None:
    if _resource_database_tables(connection) != RESOURCE_SCHEMA_V3_TABLES:
        raise RuntimeError("Unsupported resource database schema")
    _validate_resource_schema_v2(connection)
    missing = {
        index_name
        for index_name, (table_name, columns) in (
            RESOURCE_SCHEMA_V3_REQUIRED_INDEXES.items()
        )
        if index_name not in _resource_indexes(connection, table_name)
        or _resource_index_columns(connection, index_name) != columns
    }
    if missing:
        raise RuntimeError(
            "Resource database schema 3 indexes are incomplete: "
            + ", ".join(sorted(missing))
        )
    if require_lease_contract:
        _validate_resource_lease_contract(connection)


def _resource_schema_inventory() -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "store": "resources",
        "database": str(RESOURCE_DB),
        "observed_version": None,
        "current_version": RESOURCE_CURRENT_SCHEMA_VERSION,
        "supported_versions": list(RESOURCE_SUPPORTED_SCHEMA_VERSIONS),
        "lease_contract_observed_version": None,
        "lease_contract_current_version": RESOURCE_LEASE_CONTRACT_CURRENT_VERSION,
        "lease_contract_supported_versions": list(
            RESOURCE_LEASE_CONTRACT_SUPPORTED_VERSIONS
        ),
        "lease_contract_status": "uninitialized",
        "status": "uninitialized",
        "migration_required": False,
        "migration_path": [],
        "write_compatible": False,
        "mutation_performed": False,
        "required_action": "initialize_on_first_write",
        "recovery_instruction": None,
        "rolling_upgrade": dict(RESOURCE_SCHEMA_ROLLING_UPGRADE),
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
            lease_contract = _resource_lease_contract_version(
                connection, required=False
            )
            result["lease_contract_observed_version"] = lease_contract
            if (
                lease_contract is not None
                and lease_contract not in RESOURCE_LEASE_CONTRACT_SUPPORTED_VERSIONS
            ):
                future_contract = (
                    lease_contract.isdecimal()
                    and int(lease_contract)
                    > int(RESOURCE_LEASE_CONTRACT_CURRENT_VERSION)
                )
                result.update(
                    status=(
                        "unsupported_future_lease_contract"
                        if future_contract
                        else "unsupported_lease_contract"
                    ),
                    lease_contract_status="unsupported",
                    required_action="upgrade_runtime_or_restore_verified_backup",
                    recovery_instruction=RESOURCE_SCHEMA_RECOVERY_INSTRUCTION,
                )
                return result
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
                _validate_resource_schema_current(
                    connection, require_lease_contract=False
                )
            elif observed == "2":
                _validate_resource_schema_v2(connection)
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
        if lease_contract is None:
            result.update(
                status="lease_contract_metadata_required",
                lease_contract_status="missing",
                migration_required=True,
                required_action="open_with_current_runtime_to_publish_lease_contract",
                migration_path=[
                    {
                        "from": RESOURCE_CURRENT_SCHEMA_VERSION,
                        "to": RESOURCE_CURRENT_SCHEMA_VERSION,
                        "lease_contract_from": None,
                        "lease_contract_to": RESOURCE_LEASE_CONTRACT_CURRENT_VERSION,
                        "lock": "exclusive_store_directory",
                        "transaction": "immediate",
                        "verified_backup_required": True,
                    }
                ],
            )
            return result
        result.update(
            status="current",
            lease_contract_status="current",
            write_compatible=True,
            required_action="none",
        )
        return result
    path = RESOURCE_SCHEMA_MIGRATION_PATHS[observed]
    result.update(
        status="migration_required",
        lease_contract_status=("missing" if lease_contract is None else "current"),
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
        if version == "1":
            _validate_resource_schema_legacy(backup)
        elif version == "2":
            _validate_resource_schema_v2(backup)
        elif version == "3":
            _validate_resource_schema_current(
                backup, require_lease_contract=False
            )
        else:
            raise RuntimeError("Resource migration backup schema version is unsupported")
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


def _resource_store_file_ready() -> bool:
    try:
        observed = RESOURCE_DB.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise PermissionError(f"Resource database must be a regular file: {RESOURCE_DB}")
    return observed.st_size > 0


def _preflight_resource_store() -> str | None:
    if not _resource_store_file_ready():
        return None
    with _resource_readonly_sqlite(RESOURCE_DB) as connection:
        _resource_sqlite_integrity(connection, "Resource database", quick=True)
        version = _resource_schema_version(connection)
        if version not in {"1", "2", "3"}:
            raise RuntimeError(
                "Unsupported resource database schema; use a compatible runtime"
            )
        if version == "1":
            _validate_resource_schema_legacy(connection)
        elif version == "2":
            _validate_resource_schema_v2(connection)
        else:
            _validate_resource_schema_current(
                connection, require_lease_contract=False
            )
        lease_contract = _resource_lease_contract_version(
            connection, required=False
        )
        if (
            lease_contract is not None
            and lease_contract not in RESOURCE_LEASE_CONTRACT_SUPPORTED_VERSIONS
        ):
            raise RuntimeError(
                "Unsupported resource lease contract version; use a compatible runtime"
            )
        if version == RESOURCE_CURRENT_SCHEMA_VERSION and lease_contract is None:
            return f"{version}:lease-contract-missing"
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
    connection.execute(
        "CREATE INDEX task_terminalizations_pending_idx "
        "ON task_terminalizations(phase, prepared_at_unix, task_id)"
    )


def _create_resource_schema_v3(connection: sqlite3.Connection) -> None:
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
        "INSERT INTO metadata(key, value) VALUES('schema_version', '3')"
    )
    _publish_resource_lease_contract(connection)


def _migrate_resource_schema_v1(connection: sqlite3.Connection) -> None:
    _create_resource_additive_tables(connection)
    connection.execute(
        "UPDATE metadata SET value='3' WHERE key='schema_version'"
    )
    _publish_resource_lease_contract(connection)


def _migrate_resource_schema_v2(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE INDEX IF NOT EXISTS task_authority_adoptions_expiry_idx "
        "ON task_authority_adoptions(expires_at_unix)"
    )
    connection.execute(
        "CREATE INDEX task_terminalizations_pending_idx "
        "ON task_terminalizations(phase, prepared_at_unix, task_id)"
    )
    connection.execute(
        "UPDATE metadata SET value='3' WHERE key='schema_version'"
    )
    _publish_resource_lease_contract(connection)


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
        if _resource_schema_version(connection) != "3":
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
    if observed == "3":
        return _open_current_resource_database()

    with _resource_schema_directory_lock(parent):
        observed = _preflight_resource_store()
        if observed == "3":
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
            if version not in {None, "1", "2", "3"}:
                raise RuntimeError(
                    "Unsupported resource database schema; use a compatible runtime"
                )
            if version is None:
                if _resource_database_tables(connection):
                    raise RuntimeError(
                        "Resource database schema metadata is missing from an existing database"
                    )
                _create_resource_schema_v3(connection)
            elif version == "1":
                _validate_resource_schema_legacy(connection)
                _resource_sqlite_integrity(connection, "Resource database")
                fingerprint = _resource_sqlite_fingerprint(connection)
                _verified_resource_migration_backup(version, fingerprint)
                _migrate_resource_schema_v1(connection)
            elif version == "2":
                _validate_resource_schema_v2(connection)
                _resource_sqlite_integrity(connection, "Resource database")
                fingerprint = _resource_sqlite_fingerprint(connection)
                _verified_resource_migration_backup(version, fingerprint)
                _migrate_resource_schema_v2(connection)
            else:
                _validate_resource_schema_current(
                    connection, require_lease_contract=False
                )
                if _resource_lease_contract_version(
                    connection, required=False
                ) is None:
                    _resource_sqlite_integrity(connection, "Resource database")
                    fingerprint = _resource_sqlite_fingerprint(connection)
                    _verified_resource_migration_backup(version, fingerprint)
                    _publish_resource_lease_contract(connection)
                else:
                    _validate_resource_lease_contract(connection)
            if _resource_schema_version(connection) != "3":
                raise RuntimeError("Resource database migration did not reach schema 3")
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


def _normalize_operation_resource_value(value: str) -> str:
    if len(value.encode("utf-8")) > MAX_OPERATION_RESOURCE_VALUE_BYTES:
        raise ValueError("operation resource is too large")
    segments = value.split(":")
    if len(segments) < 2:
        raise ValueError(
            "operation resource must bind an operation and scoped identity"
        )
    if any(
        OPERATION_SEGMENT_RE.fullmatch(segment) is None
        for segment in segments
    ):
        raise ValueError(
            "operation resource contains unsupported or empty segments"
        )
    return ":".join(segments)


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
    elif kind == "operation":
        value = _normalize_operation_resource_value(value)
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


def _lease_identity_metadata(
    metadata: dict[str, Any], *, preserve_task_attempt: bool
) -> dict[str, Any]:
    ignored = {"work_admission"}
    if preserve_task_attempt:
        ignored.update({"attempt", "recovered_after_expiry"})
    return {key: value for key, value in metadata.items() if key not in ignored}


def _expired_same_owner_reentry_snapshot(row: sqlite3.Row) -> dict[str, Any]:
    """Capture only persisted lease identity relevant to safe reacquisition."""
    return {
        "resource_key": row["resource_key"],
        "owner_id": row["owner_id"],
        "purpose": row["purpose"],
        "expires_at_unix": int(row["expires_at_unix"]),
        "metadata_sha256": row["metadata_sha256"],
    }


def _expired_same_owner_repository_reentry(
    resource_key: str,
    *,
    owner_id: str,
    purpose: str,
    metadata: dict[str, Any],
    now: int,
) -> dict[str, Any] | None:
    """Bind an expired same-owner retry to its unchanged exact worktree scope."""
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM leases WHERE resource_key=?", (resource_key,)
        ).fetchone()
    if (
        row is None
        or row["owner_id"] != owner_id
        or int(row["expires_at_unix"]) > now
        or row["purpose"] != purpose
    ):
        return None
    observed_metadata = _row_metadata(row)
    _, observed_sha256 = _metadata(observed_metadata)
    if row["metadata_sha256"] != observed_sha256:
        raise RuntimeError(
            f"Resource lease metadata integrity mismatch: {resource_key}"
        )
    if _lease_identity_metadata(
        observed_metadata, preserve_task_attempt=False
    ) != _lease_identity_metadata(metadata, preserve_task_attempt=False):
        return None
    scope = _scope_manifest_from_metadata(metadata, required=True)
    if resource_key != f"repo:{scope['repository']}":
        return None
    return {
        "target_path": scope["worktree"],
        "branch": scope["branch"],
        "source_kind": "expired_same_owner_lease",
        "source_id": observed_sha256,
        "expected_lease": _expired_same_owner_reentry_snapshot(row),
    }


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
    if requested_scope is not None and any(
        key.startswith("operation:") for key in keys
    ):
        raise ValueError(
            "operation resources do not accept repository scope manifests"
        )
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


def _normalize_mutation_lease_snapshots(
    value: Any, *, expected_owner_id: str | None, resource_keys: list[str]
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(resource_keys):
        raise ValueError("expected_leases must contain one snapshot per resource key")
    snapshots: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != LEASE_SNAPSHOT_KEYS:
            raise ValueError("expected lease snapshot is malformed")
        key = normalize_resource_key(item["resource_key"])
        if expected_owner_id is not None and item["owner_id"] != expected_owner_id:
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


def _load_private_receipt_json(
    path: Path, *, max_bytes: int = MAX_TERMINAL_RECEIPT_BYTES
) -> dict[str, Any]:
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
            or metadata.st_size > max_bytes
        ):
            raise PermissionError("terminal receipt must be one bounded private regular file")
        raw = os.read(descriptor, max_bytes + 1)
        if len(raw) > max_bytes:
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



def _runtime_refresh_payload_digest(value: Mapping[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return hashlib.sha256((_canonical_json(payload) + "\n").encode("utf-8")).hexdigest()


def _verify_runtime_refresh_digest(
    value: Mapping[str, Any], field: str, *, label: str
) -> str:
    observed = value.get(field)
    expected = _runtime_refresh_payload_digest(value, field)
    if (
        not isinstance(observed, str)
        or SHA256_RE.fullmatch(observed) is None
        or observed != expected
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", f"{label} digest is invalid"
        )
    return observed


def _runtime_refresh_private_root() -> Path:
    root = BUREAU_RUNTIME_REFRESH_STATE_ROOT.expanduser()
    try:
        resolved = root.resolve(strict=True)
        info = root.lstat()
    except OSError as exc:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-missing", "runtime-refresh state root is unavailable"
        ) from exc
    if (
        resolved != root
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PermissionError("runtime-refresh state root is not canonical and private")
    return root


def _runtime_refresh_terminal_material(
    terminal_source: Mapping[str, Any],
) -> dict[str, Any]:
    source = dict(terminal_source)
    if set(source) != {"kind", "target_sha256", "result_sha256"}:
        raise ValueError("runtime-refresh terminal_source keys are invalid")
    if source.get("kind") != BUREAU_RUNTIME_REFRESH_RESULT_KIND:
        raise ValueError("runtime-refresh terminal_source kind is invalid")
    target_sha256 = source.get("target_sha256")
    result_sha256 = source.get("result_sha256")
    if (
        not isinstance(target_sha256, str)
        or SHA256_RE.fullmatch(target_sha256) is None
        or not isinstance(result_sha256, str)
        or SHA256_RE.fullmatch(result_sha256) is None
    ):
        raise ValueError("runtime-refresh terminal source digest is invalid")

    root = _runtime_refresh_private_root()
    attempts_root = root / "attempts"
    intents_root = root / "intents"
    observations_root = root / "observations"
    attempt_dir = attempts_root / target_sha256
    for directory, label in (
        (attempts_root, "attempts"),
        (intents_root, "intents"),
        (observations_root, "observations"),
        (attempt_dir, "attempt"),
    ):
        try:
            info = directory.lstat()
        except OSError as exc:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-missing",
                f"runtime-refresh {label} directory is unavailable",
            ) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise PermissionError(
                f"runtime-refresh {label} directory is not private and owned"
            )

    result_path = attempt_dir / "result.json"
    started_path = attempt_dir / "started.json"
    try:
        result = _load_private_receipt_json(
            result_path, max_bytes=MAX_RUNTIME_REFRESH_RECEIPT_BYTES
        )
        started = _load_private_receipt_json(
            started_path, max_bytes=MAX_RUNTIME_REFRESH_RECEIPT_BYTES
        )
    except FileNotFoundError as exc:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-missing", "runtime-refresh result or start receipt is absent"
        ) from exc
    if result.get("result_sha256") != result_sha256:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-drift", "runtime-refresh result identity changed"
        )
    _verify_runtime_refresh_digest(result, "result_sha256", label="result")
    _verify_runtime_refresh_digest(started, "start_sha256", label="attempt start")
    if (
        result.get("schema_version") != 1
        or result.get("kind") != BUREAU_RUNTIME_REFRESH_RESULT_KIND
        or started.get("schema_version") != 1
        or started.get("kind") != BUREAU_RUNTIME_REFRESH_START_KIND
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh receipt contract is invalid"
        )

    status = result.get("status")
    effect_started = result.get("effect_started")
    if status not in RUNTIME_REFRESH_RELEASABLE_STATUSES:
        raise nonconflict.NonConflictDenied(
            "owner-work-nonterminal",
            "runtime-refresh result is unclear or not explicitly terminal",
        )
    if status == "deployed" and effect_started is not True:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "deployed runtime-refresh result is inconsistent"
        )
    if status in {"already_current", "failed"} and effect_started is not False:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "pre-effect runtime-refresh result is inconsistent",
        )
    if status == "failed":
        if not isinstance(result.get("error"), dict):
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid", "failed runtime-refresh result lacks an error"
            )
    elif "error" in result:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "successful runtime-refresh result unexpectedly contains an error",
        )

    intent_sha256 = result.get("intent_sha256")
    if (
        not isinstance(intent_sha256, str)
        or SHA256_RE.fullmatch(intent_sha256) is None
        or started.get("intent_sha256") != intent_sha256
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh intent binding is invalid"
        )
    intent_path = intents_root / f"{intent_sha256}.json"
    try:
        intent = _load_private_receipt_json(
            intent_path, max_bytes=MAX_RUNTIME_REFRESH_RECEIPT_BYTES
        )
    except FileNotFoundError as exc:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-missing", "runtime-refresh intent receipt is absent"
        ) from exc
    if intent.get("intent_sha256") != intent_sha256:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-drift", "runtime-refresh intent identity changed"
        )
    _verify_runtime_refresh_digest(intent, "intent_sha256", label="intent")
    observation_sha256 = intent.get("observation_sha256")
    if (
        not isinstance(observation_sha256, str)
        or SHA256_RE.fullmatch(observation_sha256) is None
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh observation binding is invalid",
        )
    observation_candidates = sorted(
        observations_root.glob(f"*-{observation_sha256[:12]}.json")
    )
    if len(observation_candidates) != 1:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-missing",
            "runtime-refresh observation receipt is absent or ambiguous",
        )
    observation = _load_private_receipt_json(
        observation_candidates[0], max_bytes=MAX_RUNTIME_REFRESH_RECEIPT_BYTES
    )
    if observation.get("observation_sha256") != observation_sha256:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-drift",
            "runtime-refresh observation identity changed",
        )
    _verify_runtime_refresh_digest(
        observation, "observation_sha256", label="observation"
    )
    target_payload = {
        key: observation.get(key)
        for key in (
            "repository",
            "main_commit",
            "pull_request",
            "merged_at",
            "required_checks",
            "check_summary",
            "deployed_source_commit",
            "deployed_manifest_sha256",
            "lag_commits",
        )
    }
    observed_target_sha256 = hashlib.sha256(
        (_canonical_json(target_payload) + "\n").encode("utf-8")
    ).hexdigest()
    if (
        observation.get("schema_version") != 1
        or observation.get("kind") != "bureau_runtime_refresh_observation"
        or observation.get("target_sha256") != target_sha256
        or observed_target_sha256 != target_sha256
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh target digest is invalid",
        )
    if (
        intent.get("schema_version") != 1
        or intent.get("kind") != BUREAU_RUNTIME_REFRESH_INTENT_KIND
        or intent.get("target_sha256") != target_sha256
        or intent.get("repository") != "heimgewebe/bureau"
        or Path(str(intent.get("state_root", ""))).expanduser() != root
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh intent target is invalid"
        )

    if (
        observation.get("repository") != intent.get("repository")
        or observation.get("main_commit") != intent.get("main_commit")
        or observation.get("pull_request") != intent.get("pull_request")
        or observation.get("merged_at") != intent.get("merged_at")
        or observation.get("required_checks") != intent.get("required_checks")
        or observation.get("deployed_source_commit")
        != intent.get("expected_deployed_source_commit")
        or observation.get("deployed_manifest_sha256")
        != intent.get("expected_manifest_sha256")
        or observation.get("status") not in {"candidate", "alert"}
        or type(observation.get("lag_commits")) is not int
        or observation.get("lag_commits") < 1
        or not isinstance(observation.get("check_summary"), dict)
        or any(
            observation["check_summary"].get(name, {}).get("state") != "success"
            for name in observation.get("required_checks", [])
        )
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh observation and intent bindings differ",
        )
    main_commit = intent.get("main_commit")
    if (
        not isinstance(main_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", main_commit) is None
        or result.get("main_commit") != main_commit
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh main commit binding is invalid"
        )
    pull_request = intent.get("pull_request")
    if (
        not isinstance(pull_request, dict)
        or pull_request.get("merge_commit") != main_commit
        or not isinstance(pull_request.get("number"), int)
        or isinstance(pull_request.get("number"), bool)
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh merge commit binding is invalid"
        )

    if status != "already_current":
        if (
            result.get("target_sha256") != target_sha256
            or started.get("target_sha256") != target_sha256
            or started.get("main_commit") != main_commit
        ):
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid",
                "runtime-refresh attempt target differs from its intent",
            )
    elif any(key in started for key in ("target_sha256", "main_commit")) and (
        started.get("target_sha256") != target_sha256
        or started.get("main_commit") != main_commit
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "already-current attempt has inconsistent optional target bindings",
        )
    if started.get("effect_started") is not False:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh start receipt is inconsistent"
        )

    result_binding = result.get("lease_binding")
    started_binding = started.get("lease_binding")
    if not isinstance(result_binding, dict) or result_binding != started_binding:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh result and start lease bindings differ",
        )
    claimed_binding_sha256 = result_binding.get("lease_binding_sha256")
    if (
        not isinstance(claimed_binding_sha256, str)
        or SHA256_RE.fullmatch(claimed_binding_sha256) is None
        or _runtime_refresh_payload_digest(
            result_binding, "lease_binding_sha256"
        )
        != claimed_binding_sha256
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh lease binding digest is invalid"
        )
    owner_id = result_binding.get("owner_id")
    task_id = result_binding.get("task_id")
    resource_keys = result_binding.get("resource_keys")
    lease_snapshots = result_binding.get("lease_snapshots")
    if (
        not isinstance(owner_id, str)
        or OWNER_RE.fullmatch(owner_id) is None
        or not isinstance(task_id, str)
        or not task_id
        or not isinstance(resource_keys, list)
        or any(not isinstance(item, str) for item in resource_keys)
        or resource_keys != sorted(set(resource_keys))
        or not isinstance(lease_snapshots, list)
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid", "runtime-refresh lease binding shape is invalid"
        )
    path_fields = {
        field: intent.get(field)
        for field in ("state_root", "workspace", "prefix", "bin_dir")
    }
    if any(
        not isinstance(value, str)
        or not Path(value).expanduser().is_absolute()
        or Path(value).expanduser() != Path(value).expanduser().resolve(strict=False)
        for value in path_fields.values()
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh intent paths are not canonical absolute paths",
        )
    intent_resource_keys = intent.get("required_resource_keys")
    if (
        not isinstance(intent_resource_keys, list)
        or not intent_resource_keys
        or any(not isinstance(item, str) for item in intent_resource_keys)
        or intent_resource_keys != sorted(set(intent_resource_keys))
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh intent resource binding is invalid",
        )
    canonical_resource_keys: list[str] = []
    for resource_key in intent_resource_keys:
        if not resource_key.startswith("path:"):
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid",
                "runtime-refresh intent resources must be path resources",
            )
        resource_path = Path(resource_key[len("path:"):]).expanduser()
        normalized_path = Path(os.path.normpath(str(resource_path)))
        if not resource_path.is_absolute() or resource_path != normalized_path:
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid",
                "runtime-refresh intent resources are not canonical absolute paths",
            )
        canonical_resource_keys.append(f"path:{resource_path}")
    if (
        resource_keys != canonical_resource_keys
        or Path(str(intent.get("workspace", ""))).expanduser()
        != root / "workspaces" / main_commit
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh resources differ from the verified intent",
        )
    snapshots = _normalize_expected_lease_snapshots(
        lease_snapshots, owner_id=owner_id, resource_keys=resource_keys
    )
    resource_db = result_binding.get("resource_db")
    schema_version = result_binding.get("resource_db_schema_version")
    contract_version = result_binding.get("resource_lease_contract_version")
    minimum_remaining_seconds = result_binding.get("minimum_remaining_seconds")
    observed_at_unix = result_binding.get("observed_at_unix")
    required_metadata_sha256 = result_binding.get("required_metadata_sha256")
    if (
        not isinstance(resource_db, str)
        or Path(resource_db).expanduser().resolve() != RESOURCE_DB.expanduser().resolve()
        or not isinstance(schema_version, str)
        or not schema_version.isdecimal()
        or (
            contract_version != "1"
            and not (
                contract_version is None
                and "runtime_approval" not in intent
                and "approval_task_id" not in intent
                and schema_version == "3"
            )
        )
        or type(minimum_remaining_seconds) is not int
        or minimum_remaining_seconds < 30
        or type(observed_at_unix) is not int
        or result_binding.get("min_expires_at_unix")
        != min(item["expires_at_unix"] for item in snapshots)
        or (
            required_metadata_sha256 is not None
            and (
                not isinstance(required_metadata_sha256, str)
                or SHA256_RE.fullmatch(required_metadata_sha256) is None
            )
        )
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh resource database binding is invalid",
        )
    finished_at = result.get("finished_at")
    try:
        parsed_finished = datetime.fromisoformat(str(finished_at).replace("Z", "+00:00"))
        if parsed_finished.tzinfo is None or parsed_finished.utcoffset() is None:
            raise ValueError("timezone missing")
        finished_at_unix = int(parsed_finished.timestamp())
    except (TypeError, ValueError, OverflowError) as exc:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh terminal timestamp is invalid",
        ) from exc
    started_at = started.get("started_at")
    try:
        parsed_started = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        if parsed_started.tzinfo is None or parsed_started.utcoffset() is None:
            raise ValueError("timezone missing")
        started_at_unix = int(parsed_started.timestamp())
    except (TypeError, ValueError, OverflowError) as exc:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-invalid",
            "runtime-refresh start timestamp is invalid",
        ) from exc
    if (
        observed_at_unix > started_at_unix
        or started_at_unix > finished_at_unix
        or any(
            snapshot["acquired_at_unix"] > started_at_unix
            or snapshot["updated_at_unix"] > started_at_unix
            for snapshot in snapshots
        )
    ):
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-drift",
            "runtime-refresh lease changed at or after the terminal result",
        )

    if status == "deployed":
        source_identity = result.get("source_identity")
        readback = result.get("readback")
        if (
            not isinstance(source_identity, dict)
            or source_identity.get("head") != main_commit
            or source_identity.get("origin_main") != main_commit
            or source_identity.get("dirty") is not False
            or source_identity.get("detached") is not True
            or source_identity.get("root") != intent.get("workspace")
            or source_identity.get("remote_url") != intent.get("remote_url")
            or not isinstance(readback, dict)
            or readback.get("source_commit") != main_commit
            or readback.get("check_valid") is not True
            or readback.get("runtime_identity_valid") is not True
        ):
            raise nonconflict.NonConflictDenied(
                "terminal-evidence-invalid",
                "deployed runtime-refresh source or readback binding is invalid",
            )

    return {
        "terminal_evidence": {
            "kind": BUREAU_RUNTIME_REFRESH_RESULT_KIND,
            "target_sha256": target_sha256,
            "result_sha256": result_sha256,
            "status": status,
            "effect_started": effect_started,
            "intent_sha256": intent_sha256,
            "main_commit": main_commit,
            "merge_commit": pull_request["merge_commit"],
            "owner_id": owner_id,
            "task_id": task_id,
            "resource_keys": resource_keys,
            "lease_binding_sha256": claimed_binding_sha256,
            "resource_lease_contract_version": (
                contract_version if contract_version is not None else "legacy-null"
            ),
            "started_at_unix": started_at_unix,
            "finished_at_unix": finished_at_unix,
        },
        "owner_id": owner_id,
        "resource_keys": resource_keys,
        "lease_snapshots": snapshots,
    }


def _verify_runtime_refresh_terminal_source(
    terminal_source: Mapping[str, Any],
    *,
    owner_id: str,
    resource_keys: list[str],
    expected_leases: list[dict[str, Any]],
) -> dict[str, Any]:
    material = _runtime_refresh_terminal_material(terminal_source)
    if material["owner_id"] != owner_id:
        raise PermissionError("runtime-refresh terminal evidence belongs to another owner")
    if material["resource_keys"] != resource_keys:
        raise PermissionError("runtime-refresh terminal evidence names other resources")
    if material["lease_snapshots"] != expected_leases:
        raise nonconflict.NonConflictDenied(
            "terminal-evidence-drift",
            "runtime-refresh lease snapshots differ from the requested release",
        )
    return dict(material["terminal_evidence"])


def release_runtime_refresh_terminal_leases(
    *, target_sha256: str, result_sha256: str
) -> dict[str, Any]:
    terminal_source = {
        "kind": BUREAU_RUNTIME_REFRESH_RESULT_KIND,
        "target_sha256": target_sha256,
        "result_sha256": result_sha256,
    }
    material = _runtime_refresh_terminal_material(terminal_source)
    return reconcile_obsolete_path_leases(
        owner_id=material["owner_id"],
        resource_keys=material["resource_keys"],
        expected_leases=material["lease_snapshots"],
        terminal_source=terminal_source,
    )

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
    if kind == BUREAU_RUNTIME_REFRESH_RESULT_KIND:
        return _verify_runtime_refresh_terminal_source(
            terminal_source,
            owner_id=owner_id,
            resource_keys=resource_keys,
            expected_leases=expected_leases,
        )
    raise nonconflict.NonConflictDenied(
        "unsupported-terminal-source",
        "terminal_source kind must be agent_workspace_close, durable_task_outcome, or bureau_runtime_refresh_result",
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


def _normalize_operation_scope_strings(values: Any, *, label: str) -> list[str]:
    if not isinstance(values, list):
        raise ValueError(f"operation_scope.{label} must be a list")
    normalized: list[str] = []
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or "\x00" in value
            or len(value.encode("utf-8")) > 1024
        ):
            raise ValueError(f"operation_scope.{label} contains an invalid value")
        normalized.append(value)
    result = sorted(set(normalized))
    if len(result) > 32:
        raise ValueError(f"operation_scope.{label} exceeds entry limit")
    return result


def _normalize_operation_scope_pull_requests(values: Any) -> list[int]:
    if not isinstance(values, list):
        raise ValueError("operation_scope.pull_requests must be a list")
    normalized: list[int] = []
    for value in values:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 1
            or value > 2_147_483_647
        ):
            raise ValueError("operation_scope.pull_requests contains an invalid value")
        normalized.append(value)
    result = sorted(set(normalized))
    if len(result) > 32:
        raise ValueError("operation_scope.pull_requests exceeds entry limit")
    return result


def normalize_operation_scope(value: Any) -> dict[str, Any]:
    """Normalize one exact self-scoped repository operation contract.

    Only the two named publication operation classes can establish merge
    non-conflict. Other classes remain machine-readable but fail closed.
    """
    if not isinstance(value, dict):
        raise ValueError("operation_scope must be an object")
    expected = {
        "schema_version",
        "effect_class",
        "operation_class",
        "repository",
        "resource_key",
        "branches",
        "pull_requests",
        "scope_complete",
    }
    if set(value) != expected:
        raise ValueError("operation_scope fields are invalid")
    if value.get("schema_version") != OPERATION_SCOPE_SCHEMA_VERSION:
        raise ValueError("operation_scope schema_version is unsupported")
    effect_class = value.get("effect_class")
    operation_class = value.get("operation_class")
    if effect_class not in OPERATION_SCOPE_EFFECT_CLASSES:
        raise ValueError("operation_scope effect_class is invalid")
    if operation_class not in OPERATION_SCOPE_CLASS_BY_EFFECT[effect_class]:
        raise ValueError("operation_scope operation_class does not match effect_class")
    repository_value = value.get("repository")
    if not isinstance(repository_value, str):
        raise ValueError("operation_scope repository must be text")
    repository_path = Path(repository_value).expanduser()
    if not repository_path.is_absolute():
        raise ValueError("operation_scope repository must be absolute")
    repository = os.path.normpath(str(repository_path))
    resource_key = normalize_resource_key(value.get("resource_key"))
    resource_scope = _repository_resource_scope(resource_key, repository=repository)
    if (
        resource_scope is None
        or resource_scope["scope_kind"] != "operation"
        or resource_scope["repository"] != repository
    ):
        raise ValueError(
            "operation_scope resource_key must be an operation-scoped repository key"
        )
    branches = _normalize_operation_scope_strings(
        value.get("branches"), label="branches"
    )
    pull_requests = _normalize_operation_scope_pull_requests(
        value.get("pull_requests")
    )
    scope_complete = value.get("scope_complete")
    if not isinstance(scope_complete, bool):
        raise ValueError("operation_scope.scope_complete must be boolean")
    scope_value = str(resource_scope["scope_value"] or "")
    if effect_class == "publication":
        if scope_complete is not True:
            raise ValueError("publication operation_scope must be complete")
        expected_prefix = PUBLICATION_OPERATION_PREFIX_BY_CLASS[operation_class]
        if not (
            scope_value == expected_prefix
            or scope_value.startswith(expected_prefix + ":")
        ):
            raise ValueError(
                "publication operation_scope does not match the operation resource class"
            )
        if operation_class == "push":
            if not branches or pull_requests:
                raise ValueError(
                    "push operation_scope requires branches and forbids pull_requests"
                )
        elif not branches and not pull_requests:
            raise ValueError(
                "pr-publication operation_scope requires a branch or pull request"
            )
    elif branches or pull_requests:
        raise ValueError(
            "non-publication operation_scope may not declare publication scope"
        )
    return {
        "schema_version": OPERATION_SCOPE_SCHEMA_VERSION,
        "effect_class": effect_class,
        "operation_class": operation_class,
        "repository": repository,
        "resource_key": resource_key,
        "branches": branches,
        "pull_requests": pull_requests,
        "scope_complete": scope_complete,
    }


def operation_scope_contract(
    resource_key: str,
    *,
    repository: str,
    effect_class: str,
    operation_class: str,
    branches: Iterable[str] = (),
    pull_requests: Iterable[int] = (),
    scope_complete: bool = True,
) -> dict[str, Any]:
    """Build one canonical operation-scope contract for lease metadata."""
    return normalize_operation_scope(
        {
            "schema_version": OPERATION_SCOPE_SCHEMA_VERSION,
            "effect_class": effect_class,
            "operation_class": operation_class,
            "repository": repository,
            "resource_key": resource_key,
            "branches": list(branches),
            "pull_requests": list(pull_requests),
            "scope_complete": scope_complete,
        }
    )


def _operation_scope_from_metadata(
    metadata: dict[str, Any],
    *,
    resource_key: str,
    repository: str,
) -> dict[str, Any] | None:
    value = metadata.get(OPERATION_SCOPE_METADATA_KEY)
    if value is None:
        return None
    try:
        normalized = normalize_operation_scope(value)
    except ValueError:
        return None
    if (
        normalized["resource_key"] != resource_key
        or normalized["repository"] != repository
    ):
        return None
    return normalized


def _merge_guard_pull_request(metadata: dict[str, Any]) -> int | None:
    guard = metadata.get("merge_guard")
    if not isinstance(guard, dict):
        return None
    value = guard.get("pull_request")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def _operation_merge_nonconflict_evidence(
    metadata: dict[str, Any],
    *,
    resource_key: str,
    repository: str,
    guarded_branches: set[str],
    merge_pull_request: int | None,
) -> dict[str, Any] | None:
    operation_scope = _operation_scope_from_metadata(
        metadata,
        resource_key=resource_key,
        repository=repository,
    )
    if (
        operation_scope is None
        or operation_scope["effect_class"] != "publication"
        or operation_scope["scope_complete"] is not True
    ):
        return None
    operation_branches = list(operation_scope["branches"])
    operation_pull_requests = list(operation_scope["pull_requests"])
    branch_overlap = sorted(set(operation_branches).intersection(guarded_branches))
    pull_request_overlap = (
        []
        if merge_pull_request is None
        else [
            item
            for item in operation_pull_requests
            if item == merge_pull_request
        ]
    )
    if branch_overlap or pull_request_overlap:
        return None
    if operation_pull_requests and merge_pull_request is None:
        return None
    material = {
        "schema_version": 1,
        "kind": "grabowski_operation_merge_nonconflict",
        "decision": "allow",
        "reason": "complete-publication-scope-disjoint",
        "resource_key": resource_key,
        "effect_class": operation_scope["effect_class"],
        "operation_class": operation_scope["operation_class"],
        "operation_branches": operation_branches,
        "operation_pull_requests": operation_pull_requests,
        "guarded_branches": sorted(guarded_branches),
        "guarded_pull_request": merge_pull_request,
        "branch_overlap": branch_overlap,
        "pull_request_overlap": pull_request_overlap,
        "operation_scope_sha256": hashlib.sha256(
            _canonical_json(operation_scope).encode("utf-8")
        ).hexdigest(),
    }
    return {
        **material,
        "evidence_sha256": hashlib.sha256(
            _canonical_json(material).encode("utf-8")
        ).hexdigest(),
    }


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
) -> list[dict[str, Any]]:
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
    nonconflicts: list[dict[str, Any]] = []
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
        repo_scope_overlap = False
        merge_pull_request = _merge_guard_pull_request(row_metadata)
        for key in keys:
            if not key.startswith("repo:"):
                continue
            key_scope = _repository_resource_scope(key, repository=repository)
            if key_scope is not None and key_scope["scope_kind"] == "operation":
                proof = _operation_merge_nonconflict_evidence(
                    metadata,
                    resource_key=key,
                    repository=repository,
                    guarded_branches=guarded_branches,
                    merge_pull_request=merge_pull_request,
                )
                if proof is not None:
                    nonconflicts.append(
                        {
                            **proof,
                            "direction": "late-operation-to-active-merge",
                            "merge_guard_resource_key": row["resource_key"],
                            "merge_guard_owner_id": row["owner_id"],
                            "merge_guard_metadata_sha256": row["metadata_sha256"],
                        }
                    )
                    continue
                repo_scope_overlap = True
                continue
            if _repository_resource_overlaps_merge_guard(
                key,
                repository=repository,
                guarded_branches=guarded_branches,
            ):
                repo_scope_overlap = True
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
    return nonconflicts




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


def _task_terminalization_cursor(
    value: tuple[int, str] | None,
    *,
    field: str,
) -> tuple[int, str] | None:
    if value is None:
        return None
    if (
        not isinstance(value, tuple)
        or len(value) != 2
        or isinstance(value[0], bool)
        or not isinstance(value[0], int)
        or value[0] < 0
        or not isinstance(value[1], str)
        or TASK_ID_RE.fullmatch(value[1]) is None
    ):
        raise ValueError(f"{field} is invalid")
    return value


def pending_task_terminalizations(
    *,
    limit: int,
    cursor: tuple[int, str] | None = None,
    high_water: tuple[int, str] | None = None,
) -> dict[str, Any]:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 500
    ):
        raise ValueError("limit must be between 1 and 500")
    after = _task_terminalization_cursor(cursor, field="cursor")
    boundary = _task_terminalization_cursor(high_water, field="high_water")
    if after is not None and boundary is None:
        raise ValueError("cursor requires high_water")
    if after is not None and after > boundary:
        raise ValueError("cursor cannot be greater than high_water")
    with _database() as connection:
        if boundary is None:
            boundary_row = connection.execute(
                "SELECT prepared_at_unix, task_id FROM task_terminalizations "
                "WHERE phase='leases_revoked' "
                "ORDER BY prepared_at_unix DESC, task_id DESC LIMIT 1"
            ).fetchone()
            if boundary_row is None:
                return {
                    "terminalizations": [],
                    "limit": limit,
                    "examined": 0,
                    "cursor_before": after,
                    "cursor_after": None,
                    "high_water": None,
                    "cycle_completed": True,
                }
            boundary = (int(boundary_row[0]), str(boundary_row[1]))
        parameters: list[Any] = [boundary[0], boundary[0], boundary[1]]
        after_clause = ""
        if after is not None:
            after_clause = (
                "AND (prepared_at_unix > ? OR "
                "(prepared_at_unix = ? AND task_id > ?)) "
            )
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        selected = list(
            connection.execute(
                "SELECT * FROM task_terminalizations "
                "WHERE phase='leases_revoked' "
                "AND (prepared_at_unix < ? OR "
                "(prepared_at_unix = ? AND task_id <= ?)) "
                f"{after_clause}"
                "ORDER BY prepared_at_unix, task_id LIMIT ?",
                parameters,
            ).fetchmany(limit + 1)
        )
    has_more = len(selected) > limit
    examined_rows = selected[:limit]
    cursor_after = (
        (
            int(examined_rows[-1]["prepared_at_unix"]),
            str(examined_rows[-1]["task_id"]),
        )
        if examined_rows and has_more
        else None
    )
    return {
        "terminalizations": [
            _task_terminalization_public(row, include_projection=True)
            for row in examined_rows
        ],
        "limit": limit,
        "examined": len(examined_rows),
        "cursor_before": after,
        "cursor_after": cursor_after,
        "high_water": boundary,
        "cycle_completed": not has_more,
    }


def pending_task_terminalizations_exist(
    *,
    cursor: tuple[int, str] | None = None,
    high_water: tuple[int, str] | None = None,
) -> bool:
    after = _task_terminalization_cursor(cursor, field="cursor")
    boundary = _task_terminalization_cursor(high_water, field="high_water")
    if after is not None and boundary is None:
        raise ValueError("cursor requires high_water")
    if after is not None and after > boundary:
        raise ValueError("cursor cannot be greater than high_water")
    with _database() as connection:
        if boundary is None:
            return (
                connection.execute(
                    "SELECT 1 FROM task_terminalizations "
                    "WHERE phase='leases_revoked' LIMIT 1"
                ).fetchone()
                is not None
            )
        parameters: list[Any] = [boundary[0], boundary[0], boundary[1]]
        after_clause = ""
        if after is not None:
            after_clause = (
                "AND (prepared_at_unix > ? OR "
                "(prepared_at_unix = ? AND task_id > ?)) "
            )
            parameters.extend((after[0], after[0], after[1]))
        return (
            connection.execute(
                "SELECT 1 FROM task_terminalizations "
                "WHERE phase='leases_revoked' "
                "AND (prepared_at_unix < ? OR "
                "(prepared_at_unix = ? AND task_id <= ?)) "
                f"{after_clause}LIMIT 1",
                parameters,
            ).fetchone()
            is not None
        )


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



def operator_lease_delegation_evidence(
    owner_id: str,
    resource_keys: Iterable[str] | None = None,
    *,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Return the complete live lease snapshot for one direct Operator owner."""
    owner = _owner(owner_id)
    if DIRECT_OPERATOR_OWNER_RE.fullmatch(owner) is None:
        raise ValueError("direct Operator lease owner is invalid")
    now = _now() if now_unix is None else int(now_unix)
    with _database() as connection:
        rows = connection.execute(
            "SELECT * FROM leases WHERE owner_id=? AND expires_at_unix>? ORDER BY resource_key",
            (owner, now),
        ).fetchall()
    owner_keys = [str(row["resource_key"]) for row in rows]
    if not owner_keys:
        raise ValueError("direct Operator owner has no live leases")
    if len(owner_keys) > 64:
        raise ValueError("direct Operator owner has more than 64 live leases")
    if any(key.startswith("gate:operator-lease-authority:") for key in owner_keys):
        raise ValueError(
            "direct Operator owner holds a reserved delegation authority gate"
        )
    keys = owner_keys if resource_keys is None else normalize_resource_keys(resource_keys)
    if keys != owner_keys:
        raise ValueError("direct Operator lease set does not match the complete current owner lease set")
    snapshots: list[dict[str, Any]] = []
    minimum_expiry: int | None = None
    for row in rows:
        metadata = _row_metadata(row)
        _, observed_metadata_sha256 = _metadata(metadata)
        if row["metadata_sha256"] != observed_metadata_sha256:
            raise ValueError("direct Operator lease metadata integrity mismatch")
        snapshot = {key: row[key] for key in LEASE_SNAPSHOT_KEYS}
        snapshots.append(snapshot)
        expiry = int(row["expires_at_unix"])
        minimum_expiry = expiry if minimum_expiry is None else min(minimum_expiry, expiry)
    return {
        "schema_version": 1,
        "kind": "grabowski_live_operator_lease_delegation_evidence",
        "lease_owner_id": owner,
        "resource_keys": keys,
        "resource_keys_sha256": hashlib.sha256(
            _canonical_json(keys).encode("utf-8")
        ).hexdigest(),
        "lease_snapshots": snapshots,
        "lease_bindings_sha256": hashlib.sha256(
            _canonical_json(snapshots).encode("utf-8")
        ).hexdigest(),
        "minimum_expires_at_unix": minimum_expiry,
        "observed_at_unix": now,
    }


def reconcile_delegated_operator_leases(
    owner_id: str,
    expected_lease_snapshots: Iterable[Mapping[str, Any]],
    *,
    expected_lease_bindings_sha256: str,
    delegation_sha256: str,
    authority_resource_key: str,
    terminal_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Release only unchanged delegated Operator leases after exact terminal evidence."""
    owner = _owner(owner_id)
    if DIRECT_OPERATOR_OWNER_RE.fullmatch(owner) is None:
        raise ValueError("direct Operator lease owner is invalid")
    snapshots = [dict(item) for item in expected_lease_snapshots]
    if (
        not snapshots
        or len(snapshots) > 64
        or any(set(item) != LEASE_SNAPSHOT_KEYS for item in snapshots)
        or [item["resource_key"] for item in snapshots]
        != sorted({str(item["resource_key"]) for item in snapshots})
    ):
        raise ValueError("delegated Operator lease snapshots are invalid")
    if any(item["owner_id"] != owner for item in snapshots):
        raise ValueError("delegated Operator lease snapshot owner mismatch")
    for snapshot in snapshots:
        if (
            not isinstance(snapshot["resource_key"], str)
            or not isinstance(snapshot["metadata_sha256"], str)
            or SHA256_RE.fullmatch(snapshot["metadata_sha256"]) is None
        ):
            raise ValueError("delegated Operator lease snapshot digest is invalid")
        for field in ("acquired_at_unix", "updated_at_unix", "expires_at_unix"):
            value = snapshot[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(
                    f"delegated Operator lease snapshot {field} is invalid"
                )
    observed_bindings_sha256 = hashlib.sha256(
        _canonical_json(snapshots).encode("utf-8")
    ).hexdigest()
    if (
        SHA256_RE.fullmatch(expected_lease_bindings_sha256) is None
        or observed_bindings_sha256 != expected_lease_bindings_sha256
    ):
        raise ValueError("delegated Operator lease binding digest mismatch")
    if SHA256_RE.fullmatch(delegation_sha256) is None:
        raise ValueError("delegated Operator delegation digest is invalid")
    expected_authority_key = (
        "gate:operator-lease-authority:"
        + hashlib.sha256(owner.encode("utf-8")).hexdigest()
    )
    if authority_resource_key != expected_authority_key:
        raise ValueError("delegated Operator authority resource is invalid")
    source = dict(terminal_source)
    required_source_keys = {
        "schema_version",
        "kind",
        "status",
        "guard_owner_id",
        "dispatch_called",
        "execution_invoked",
        "verification_passed",
        "observed_at_unix_ns",
        "terminal_evidence_sha256",
    }
    if set(source) != required_source_keys:
        raise ValueError("delegated Operator terminal evidence shape is invalid")
    if source.get("schema_version") != 1 or source.get("kind") != "grabowski_captain_operator_lease_terminal_evidence":
        raise ValueError("delegated Operator terminal evidence contract is invalid")
    if source.get("status") not in {"success", "authoritative_abort"}:
        raise ValueError("delegated Operator terminal evidence is not authoritative")
    if source.get("status") == "success" and source.get("verification_passed") is not True:
        raise ValueError("delegated Operator success evidence is inconsistent")
    if source.get("status") == "authoritative_abort" and (
        source.get("dispatch_called") is not False
        or source.get("verification_passed") is not False
    ):
        raise ValueError("delegated Operator abort evidence is inconsistent")
    if OWNER_RE.fullmatch(str(source.get("guard_owner_id", ""))) is None:
        raise ValueError("delegated Operator terminal guard owner is invalid")
    for field in ("dispatch_called", "execution_invoked", "verification_passed"):
        if not isinstance(source.get(field), bool):
            raise ValueError(f"delegated Operator terminal {field} is invalid")
    observed_at_unix_ns = source.get("observed_at_unix_ns")
    if not isinstance(observed_at_unix_ns, int) or isinstance(observed_at_unix_ns, bool) or observed_at_unix_ns < 1:
        raise ValueError("delegated Operator terminal observation time is invalid")
    unsigned_source = {key: source[key] for key in source if key != "terminal_evidence_sha256"}
    terminal_evidence_sha256 = hashlib.sha256(
        _canonical_json(unsigned_source).encode("utf-8")
    ).hexdigest()
    if source.get("terminal_evidence_sha256") != terminal_evidence_sha256:
        raise ValueError("delegated Operator terminal evidence digest is invalid")

    released: list[dict[str, Any]] = []
    already_absent: list[str] = []
    retained: list[dict[str, str]] = []
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            current_owner_rows = connection.execute(
                "SELECT * FROM leases WHERE owner_id=? ORDER BY resource_key",
                (owner,),
            ).fetchall()
            expected_keys = [str(item["resource_key"]) for item in snapshots]
            now = _now()
            current_live_owner_keys = [
                str(row["resource_key"])
                for row in current_owner_rows
                if int(row["expires_at_unix"]) > now
            ]
            unexpected_owner_keys = sorted(
                set(current_live_owner_keys) - set(expected_keys)
            )
            if unexpected_owner_keys:
                retained.extend(
                    {"resource_key": key, "reason": "owner_lease_set_changed"}
                    for key in expected_keys
                )
                connection.commit()
                return {
                    "schema_version": 1,
                    "kind": "grabowski_delegated_operator_lease_convergence",
                    "owner_id": owner,
                    "resource_keys_sha256": hashlib.sha256(
                        _canonical_json(expected_keys).encode("utf-8")
                    ).hexdigest(),
                    "lease_bindings_sha256": observed_bindings_sha256,
                    "delegation_sha256": delegation_sha256,
                    "authority_resource_key_sha256": hashlib.sha256(
                        authority_resource_key.encode("utf-8")
                    ).hexdigest(),
                    "terminal_evidence_sha256": terminal_evidence_sha256,
                    "released": [],
                    "already_absent": [],
                    "retained": retained,
                    "unexpected_owner_resource_keys_sha256": hashlib.sha256(
                        _canonical_json(unexpected_owner_keys).encode("utf-8")
                    ).hexdigest(),
                    "converged": False,
                    "idempotent_replay": False,
                    "does_not_establish": [
                        "identity_of_original_lease_creator",
                        "permission_to_release_changed_lease",
                        "permission_to_release_foreign_lease",
                    ],
                }
            for snapshot in snapshots:
                key = str(snapshot["resource_key"])
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is None:
                    already_absent.append(key)
                    continue
                current = {field: row[field] for field in LEASE_SNAPSHOT_KEYS}
                if row["owner_id"] != owner:
                    retained.append({"resource_key": key, "reason": "owner_changed"})
                    continue
                if current != snapshot:
                    retained.append({"resource_key": key, "reason": "lease_changed"})
                    continue
                released.append(_public(row))
            if released:
                authority_row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?",
                    (authority_resource_key,),
                ).fetchone()
                if (
                    authority_row is None
                    or authority_row["owner_id"] != source["guard_owner_id"]
                    or int(authority_row["expires_at_unix"]) <= _now()
                ):
                    raise ValueError(
                        "delegated Operator authority gate is not live for the guard"
                    )
                authority_metadata = _row_metadata(authority_row)
                _, authority_metadata_sha256 = _metadata(authority_metadata)
                if authority_row["metadata_sha256"] != authority_metadata_sha256:
                    raise ValueError(
                        "delegated Operator authority gate metadata integrity mismatch"
                    )
                authority_binding = authority_metadata.get(
                    "operator_lease_delegation"
                )
                expected_authority_binding = {
                    "lease_owner_id_sha256": hashlib.sha256(
                        owner.encode("utf-8")
                    ).hexdigest(),
                    "resource_keys_sha256": hashlib.sha256(
                        _canonical_json(expected_keys).encode("utf-8")
                    ).hexdigest(),
                    "lease_bindings_sha256": observed_bindings_sha256,
                    "delegation_sha256": delegation_sha256,
                }
                if authority_binding != expected_authority_binding:
                    raise ValueError(
                        "delegated Operator authority gate binding mismatch"
                    )
                connection.executemany(
                    "DELETE FROM leases WHERE resource_key=? AND owner_id=?",
                    [(item["resource_key"], owner) for item in released],
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {
        "schema_version": 1,
        "kind": "grabowski_delegated_operator_lease_convergence",
        "owner_id": owner,
        "resource_keys_sha256": hashlib.sha256(
            _canonical_json([item["resource_key"] for item in snapshots]).encode("utf-8")
        ).hexdigest(),
        "lease_bindings_sha256": observed_bindings_sha256,
        "delegation_sha256": delegation_sha256,
        "authority_resource_key_sha256": hashlib.sha256(
            authority_resource_key.encode("utf-8")
        ).hexdigest(),
        "terminal_evidence_sha256": terminal_evidence_sha256,
        "released": released,
        "already_absent": already_absent,
        "retained": retained,
        "unexpected_owner_resource_keys_sha256": None,
        "converged": not retained,
        "idempotent_replay": not released and len(already_absent) == len(snapshots),
        "does_not_establish": [
            "identity_of_original_lease_creator",
            "permission_to_release_changed_lease",
            "permission_to_release_foreign_lease",
        ],
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
    delegated_operator: dict[str, Any] | None = None,
) -> dict[str, Any]:
    guard_owner = _owner(guard_owner_id)
    lease_owner = _owner(lease_owner_id)
    if guard_owner == lease_owner:
        raise ValueError("merge guard owner must be distinct from lease owner")
    keys = normalize_resource_keys(resource_keys)
    effect_resource_keys = list(keys)
    lease_purpose = _purpose(purpose)
    ttl = _ttl(ttl_seconds)
    delegated_task_id: str | None = None
    delegated_resource_keys: list[str] = []
    delegated_bindings_sha256: str | None = None
    delegated_expires_at_unix: int | None = None
    delegated_operator_snapshots: list[dict[str, Any]] = []
    delegated_operator_authority_key: str | None = None
    delegated_operator_delegation_sha256: str | None = None
    if delegated_task is not None and delegated_operator is not None:
        raise ValueError("task and direct Operator delegations are mutually exclusive")
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
    if delegated_operator is not None:
        required = {
            "lease_owner_id",
            "resource_keys",
            "resource_keys_sha256",
            "lease_snapshots",
            "lease_bindings_sha256",
            "delegation_sha256",
        }
        if not isinstance(delegated_operator, dict) or not required.issubset(delegated_operator):
            raise ValueError("delegated Operator binding is invalid")
        if DIRECT_OPERATOR_OWNER_RE.fullmatch(lease_owner) is None:
            raise ValueError("delegated Operator owner is invalid")
        if delegated_operator.get("lease_owner_id") != lease_owner:
            raise ValueError("delegated Operator owner does not match lease owner")
        delegated_resource_keys = normalize_resource_keys(
            delegated_operator.get("resource_keys")
        )
        expected_keys_sha256 = hashlib.sha256(
            _canonical_json(delegated_resource_keys).encode("utf-8")
        ).hexdigest()
        if delegated_operator.get("resource_keys_sha256") != expected_keys_sha256:
            raise ValueError("delegated Operator resource key digest is invalid")
        raw_snapshots = delegated_operator.get("lease_snapshots")
        if (
            not isinstance(raw_snapshots, list)
            or len(raw_snapshots) != len(delegated_resource_keys)
            or any(not isinstance(item, dict) or set(item) != LEASE_SNAPSHOT_KEYS for item in raw_snapshots)
        ):
            raise ValueError("delegated Operator lease snapshots are invalid")
        delegated_operator_snapshots = [dict(item) for item in raw_snapshots]
        if [item["resource_key"] for item in delegated_operator_snapshots] != delegated_resource_keys:
            raise ValueError("delegated Operator lease snapshot keys are invalid")
        if any(item["owner_id"] != lease_owner for item in delegated_operator_snapshots):
            raise ValueError("delegated Operator lease snapshot owner mismatch")
        delegated_operator_delegation_sha256 = delegated_operator.get(
            "delegation_sha256"
        )
        if (
            not isinstance(delegated_operator_delegation_sha256, str)
            or SHA256_RE.fullmatch(delegated_operator_delegation_sha256) is None
        ):
            raise ValueError("delegated Operator delegation digest is invalid")
        delegated_bindings_sha256 = delegated_operator.get("lease_bindings_sha256")
        if (
            not isinstance(delegated_bindings_sha256, str)
            or SHA256_RE.fullmatch(delegated_bindings_sha256) is None
            or delegated_bindings_sha256
            != hashlib.sha256(
                _canonical_json(delegated_operator_snapshots).encode("utf-8")
            ).hexdigest()
        ):
            raise ValueError("delegated Operator lease binding digest is invalid")
        delegated_expiry = delegated_operator.get(
            "expires_at_unix",
            delegated_operator.get("minimum_expires_at_unix"),
        )
        if (
            not isinstance(delegated_expiry, int)
            or isinstance(delegated_expiry, bool)
            or delegated_expiry < 1
        ):
            raise ValueError("delegated Operator lease expiry is invalid")
        delegated_expires_at_unix = delegated_expiry
        delegated_operator_authority_key = (
            "gate:operator-lease-authority:"
            + hashlib.sha256(lease_owner.encode("utf-8")).hexdigest()
        )
        keys = normalize_resource_keys([*keys, delegated_operator_authority_key])
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
    guard_metadata["effect_resource_keys"] = effect_resource_keys
    guard_metadata["effect_resource_keys_sha256"] = hashlib.sha256(
        _canonical_json(effect_resource_keys).encode("utf-8")
    ).hexdigest()
    guard_metadata["local_resource_repository"] = canonical_repository
    guard_metadata["local_changed_paths"] = relative_changed_paths
    normalized_metadata["merge_guard"] = guard_metadata
    if delegated_operator is not None:
        normalized_metadata["operator_lease_delegation"] = {
            "lease_owner_id_sha256": hashlib.sha256(
                lease_owner.encode("utf-8")
            ).hexdigest(),
            "resource_keys_sha256": hashlib.sha256(
                _canonical_json(delegated_resource_keys).encode("utf-8")
            ).hexdigest(),
            "lease_bindings_sha256": delegated_bindings_sha256,
            "delegation_sha256": delegated_operator_delegation_sha256,
        }
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
        raise ValueError("delegated lease authority is expired")
    task_adoption_expires = (
        expires
        if delegated_expires_at_unix is None
        else min(expires, delegated_expires_at_unix)
    )
    observed: list[dict[str, Any]] = []
    operation_nonconflicts: list[dict[str, Any]] = []
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
            if delegated_operator is not None:
                operator_rows = [row for row in rows if row["owner_id"] == lease_owner]
                operator_keys = [str(row["resource_key"]) for row in operator_rows]
                if operator_keys != delegated_resource_keys:
                    raise ValueError(
                        "delegated Operator lease set changed after signing"
                    )
                operator_by_key = {row["resource_key"]: row for row in operator_rows}
                observed_operator_snapshots: list[dict[str, Any]] = []
                for expected_snapshot in delegated_operator_snapshots:
                    delegated_key = str(expected_snapshot["resource_key"])
                    delegated_row = operator_by_key.get(delegated_key)
                    if delegated_row is None:
                        raise ValueError(
                            f"delegated Operator lease is not live: {delegated_key}"
                        )
                    delegated_metadata = _row_metadata(delegated_row)
                    _, observed_delegated_sha256 = _metadata(delegated_metadata)
                    if delegated_row["metadata_sha256"] != observed_delegated_sha256:
                        raise ValueError(
                            f"delegated Operator lease metadata integrity mismatch: {delegated_key}"
                        )
                    observed_snapshot = {
                        field: delegated_row[field] for field in LEASE_SNAPSHOT_KEYS
                    }
                    if observed_snapshot != expected_snapshot:
                        raise ValueError(
                            f"delegated Operator lease snapshot changed: {delegated_key}"
                        )
                    observed_operator_snapshots.append(observed_snapshot)
                observed_bindings_sha256 = hashlib.sha256(
                    _canonical_json(observed_operator_snapshots).encode("utf-8")
                ).hexdigest()
                if observed_bindings_sha256 != delegated_bindings_sha256:
                    raise ValueError("delegated Operator lease bindings changed")
            existing_owned_keys: set[str] = set()
            delegated_operator_target_keys: set[str] = set()
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
                operation_nonconflict = None
                if (
                    row_repo_scope is not None
                    and row_repo_scope["repository"] == canonical_repository
                    and row_repo_scope["scope_kind"] == "operation"
                ):
                    operation_nonconflict = _operation_merge_nonconflict_evidence(
                        row_metadata,
                        resource_key=row_key,
                        repository=canonical_repository,
                        guarded_branches=guarded_branches,
                        merge_pull_request=_merge_guard_pull_request(normalized_metadata),
                    )
                    if operation_nonconflict is not None:
                        operation_nonconflicts.append(
                            {
                                **operation_nonconflict,
                                "direction": "existing-operation-to-merge",
                                "lease_owner_id": row["owner_id"],
                                "lease_metadata_sha256": row["metadata_sha256"],
                            }
                        )
                repo_resource_relevant = (
                    row_repo_scope is not None
                    and row_repo_scope["repository"] == canonical_repository
                    and operation_nonconflict is None
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
                if (
                    delegated_operator is not None
                    and same_lease_owner
                    and row_key in delegated_resource_keys
                ):
                    delegated_operator_target_keys.add(str(row_key))
                if same_lease_owner:
                    if (
                        delegated_operator_authority_key is not None
                        and row_key == delegated_operator_authority_key
                    ):
                        raise ResourceConflict(
                            row_key, row["owner_id"], row["expires_at_unix"]
                        )
                    if row_key.startswith("gate:github-merge:"):
                        raise ResourceConflict(
                            row_key, row["owner_id"], row["expires_at_unix"]
                        )
                    if (
                        (delegated_task_id is not None or delegated_operator is not None)
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

            if delegated_operator is not None and not delegated_operator_target_keys:
                raise ValueError(
                    "delegated Operator leases do not bind the merge target"
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
        "operation_nonconflicts": operation_nonconflicts,
        "operation_nonconflicts_sha256": hashlib.sha256(
            _canonical_json(operation_nonconflicts).encode("utf-8")
        ).hexdigest(),
        "acquired_leases": [_public(row) for row in acquired_rows],
        "held_resource_keys": held_keys,
        "resource_keys": keys,
        "delegated_task_id": delegated_task_id,
        "delegated_task_resource_keys": (
            delegated_resource_keys if delegated_task_id is not None else []
        ),
        "task_authority_adoption": task_adoption,
        "delegated_operator_lease_owner_id": (
            lease_owner if delegated_operator is not None else None
        ),
        "delegated_operator_resource_keys": (
            delegated_resource_keys if delegated_operator is not None else []
        ),
        "delegated_operator_target_resource_keys": (
            sorted(delegated_operator_target_keys)
            if delegated_operator is not None
            else []
        ),
        "delegated_operator_lease_snapshots": (
            delegated_operator_snapshots if delegated_operator is not None else []
        ),
        "delegated_operator_lease_bindings_sha256": (
            delegated_bindings_sha256 if delegated_operator is not None else None
        ),
        "delegated_operator_delegation_sha256": (
            delegated_operator_delegation_sha256
            if delegated_operator is not None
            else None
        ),
        "delegated_operator_authority_key": delegated_operator_authority_key,
    }


def acquire_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    purpose: str,
    ttl_seconds: int = 3600,
    metadata: dict[str, Any] | None = None,
    nonconflict_proof: dict[str, Any] | None = None,
    admission_assessor: Any | None = None,
    _preserve_live_same_owner: bool = False,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    task_owner_match = re.fullmatch(r"task:([0-9a-f]{24})", owner)
    keys = normalize_resource_keys(resource_keys)
    lease_purpose = _purpose(purpose)
    ttl = _ttl(ttl_seconds)
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    if not isinstance(_preserve_live_same_owner, bool):
        raise ValueError("_preserve_live_same_owner must be boolean")
    if _preserve_live_same_owner and task_owner_match is None:
        raise PermissionError("live lease preservation requires a task owner")
    normalized_metadata: dict[str, Any] = {} if metadata is None else dict(metadata)
    if "lease_mode" in normalized_metadata:
        raise ValueError("metadata.lease_mode is not an authority surface")
    if "work_admission" in normalized_metadata:
        raise ValueError("metadata.work_admission is not a public authority surface")
    if "scope_manifest" in normalized_metadata:
        normalized_metadata["scope_manifest"] = nonconflict.normalize_scope_manifest(
            normalized_metadata["scope_manifest"]
        )
    if OPERATION_SCOPE_METADATA_KEY in normalized_metadata:
        normalized_operation_scope = normalize_operation_scope(
            normalized_metadata[OPERATION_SCOPE_METADATA_KEY]
        )
        if normalized_operation_scope["resource_key"] not in keys:
            raise ValueError(
                "operation_scope resource_key must be part of the acquisition"
            )
        same_repository_operations = [
            key
            for key in keys
            if (
                scope := _repository_resource_scope(
                    key,
                    repository=normalized_operation_scope["repository"],
                )
            )
            is not None
            and scope["scope_kind"] == "operation"
        ]
        if same_repository_operations != [normalized_operation_scope["resource_key"]]:
            raise ValueError(
                "operation_scope must bind the acquisition's exact operation resource"
            )
        normalized_metadata[OPERATION_SCOPE_METADATA_KEY] = normalized_operation_scope
    bureau_contract = bureau_leases.enforce_bureau_lease_contract(
        keys, ttl_seconds=ttl, metadata=normalized_metadata
    )
    contract_emergency = (
        isinstance(bureau_contract, dict)
        and bureau_contract.get("phase") == "emergency-recovery"
    )
    bureau_emergency = (
        contract_emergency
        and keys == [bureau_leases.BROAD_BUREAU_REPOSITORY_KEY]
    )
    if contract_emergency and not bureau_emergency:
        raise ValueError(
            "emergency-recovery mode requires the exact broad Bureau repository key"
        )
    lease_mode = "emergency-recovery" if bureau_emergency else "normal"
    sanitized_value = bureau_leases.sanitize_bureau_metadata(keys, normalized_metadata)
    sanitized_metadata: dict[str, Any] = {} if sanitized_value is None else sanitized_value
    if bureau_emergency:
        sanitized_metadata["lease_mode"] = "emergency-recovery"
    now = _now()
    admission_evidence: list[dict[str, Any]] = []
    expired_reentry_expectations: dict[str, dict[str, Any]] = {}
    if "work_admission_mode" in normalized_metadata:
        raise ValueError(
            "metadata.work_admission_mode is not a public authority surface"
        )
    admission_mode = "normal"
    scope = normalized_metadata.get("scope_manifest")
    broad_repository_keys = [
        key
        for key in keys
        if key.startswith("repo:")
        and scoped_repository_resource_root(key) is None
    ]
    if lease_mode != "emergency-recovery":
        for broad_key in broad_repository_keys:
            repository = broad_key.removeprefix("repo:")
            if not os.path.lexists(os.path.join(repository, ".git")):
                continue
            existing = inspect_resource(broad_key)
            if (
                isinstance(existing, dict)
                and existing.get("owner_id") == owner
                and isinstance(existing.get("expires_at_unix"), int)
                and existing["expires_at_unix"] > now
            ):
                admission_evidence.append(
                    {
                        "repository": repository,
                        "decision": "allow",
                        "reason": "same-owner-live-lease-reentry",
                        "read_only": True,
                    }
                )
            elif not (
                isinstance(existing, dict)
                and isinstance(existing.get("expires_at_unix"), int)
                and existing["expires_at_unix"] > now
                and existing.get("owner_id") != owner
            ):
                requested_repository_scope = (
                    scope
                    if isinstance(scope, dict)
                    and f"repo:{scope.get('repository')}" == broad_key
                    else None
                )
                reentry_binding = _expired_same_owner_repository_reentry(
                    broad_key,
                    owner_id=owner,
                    purpose=lease_purpose,
                    metadata=sanitized_metadata,
                    now=now,
                )
                if reentry_binding is not None:
                    expired_reentry_expectations[broad_key] = reentry_binding[
                        "expected_lease"
                    ]
                if (
                    requested_repository_scope is not None
                    and set(requested_repository_scope["effects"]) == {"read"}
                ):
                    admission_evidence.append(
                        {
                            "repository": repository,
                            "decision": "allow",
                            "reason": "attested-read-only-scope",
                            "read_only": True,
                        }
                    )
                    continue
                assessor = admission_assessor or work_admission.require_repository_admission
                assessment = assessor(
                    mode=admission_mode,
                    repo=repository,
                    owner_id=owner,
                    operation="broad_repository_lease",
                    requested_scope=requested_repository_scope,
                    **(
                        {}
                        if reentry_binding is None
                        else {
                            key: reentry_binding[key]
                            for key in (
                                "target_path",
                                "branch",
                                "source_kind",
                                "source_id",
                            )
                        }
                    ),
                )
                if not isinstance(assessment, dict):
                    raise RuntimeError("work admission assessor returned invalid evidence")
                if assessment.get("decision") != "allow":
                    raise work_admission.WorkAdmissionBlocked(assessment)
                if assessment.get("read_only") is not True:
                    raise RuntimeError(
                        "work admission assessor did not return read-only evidence"
                    )
                admission_evidence.append(assessment)
    if admission_evidence:
        sanitized_metadata["work_admission"] = _work_admission_metadata(
            admission_evidence
        )
    expires = now + ttl
    reclaimed: list[dict[str, Any]] = []
    preserved: list[str] = []
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
            merge_guard_nonconflicts = _check_active_merge_guard_conflicts(
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
                    expected_reentry = expired_reentry_expectations.get(key)
                    if (
                        expected_reentry is not None
                        and _expired_same_owner_reentry_snapshot(row)
                        != expected_reentry
                    ):
                        raise RuntimeError(
                            f"Expired same-owner lease changed before reacquisition: {key}"
                        )
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
            requested_identity_metadata = _lease_identity_metadata(
                persisted_metadata,
                preserve_task_attempt=_preserve_live_same_owner,
            )
            for key in keys:
                row = existing.get(key)
                live_same_owner = (
                    row is not None
                    and row["owner_id"] == owner
                    and int(row["expires_at_unix"]) > now
                )
                previous_owner = None
                reclaimed_from_owner = None
                stored_purpose = lease_purpose
                stored_metadata_json = metadata_json
                stored_metadata_sha256 = metadata_sha256
                if live_same_owner:
                    observed_metadata = _row_metadata(row)
                    _, observed_metadata_sha256 = _metadata(observed_metadata)
                    if row["metadata_sha256"] != observed_metadata_sha256:
                        raise RuntimeError(
                            f"Resource lease metadata integrity mismatch: {key}"
                        )
                    if "nonconflict_exception" in observed_metadata:
                        raise RuntimeError(
                            "non-conflict exception leases are non-renewable; reassess and reacquire"
                        )
                    observed_identity_metadata = _lease_identity_metadata(
                        observed_metadata,
                        preserve_task_attempt=_preserve_live_same_owner,
                    )
                    if (
                        row["purpose"] != lease_purpose
                        or observed_identity_metadata != requested_identity_metadata
                    ):
                        raise RuntimeError(
                            "Live same-owner lease identity changed; release and "
                            f"reacquire: {key}"
                        )
                    acquired = int(row["acquired_at_unix"])
                    current_expires = int(row["expires_at_unix"])
                    lease_expires = max(current_expires, expires)
                    updated = (
                        now
                        if lease_expires > current_expires
                        else int(row["updated_at_unix"])
                    )
                    reclaimed_from_owner = row["reclaimed_from_owner"]
                    stored_purpose = str(row["purpose"])
                    stored_metadata_json = str(row["metadata_json"])
                    stored_metadata_sha256 = observed_metadata_sha256
                    preserved.append(key)
                else:
                    acquired = now
                    updated = now
                    lease_expires = expires
                    if row is not None:
                        previous_owner = row["owner_id"]
                        reclaimed_from_owner = previous_owner
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
                        stored_purpose,
                        acquired,
                        updated,
                        lease_expires,
                        stored_metadata_sha256,
                        stored_metadata_json,
                        reclaimed_from_owner,
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
        "requested_expires_at_unix": expires,
        "expires_at_unix": min(int(row["expires_at_unix"]) for row in rows),
        "leases": [_public(row) for row in rows],
        "reclaimed": reclaimed,
        "preserved": preserved,
        "bureau_contract": bureau_contract,
        "nonconflict_exception": nonconflict_exception,
        "merge_guard_nonconflicts": merge_guard_nonconflicts,
        "work_admission": admission_evidence,
    }


def rebind_same_owner_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    purpose: str,
    ttl_seconds: int,
    metadata: dict[str, Any],
    expected_current_leases: list[dict[str, Any]],
    expected_original_leases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Restore an exact journaled lease identity without changing ownership."""
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    lease_purpose = _purpose(purpose)
    ttl = _ttl(ttl_seconds)
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    normalized_metadata = dict(metadata)
    if "lease_mode" in normalized_metadata:
        raise ValueError("metadata.lease_mode is not an authority surface")
    if "work_admission" in normalized_metadata:
        raise ValueError("metadata.work_admission is not a public authority surface")
    if "work_admission_mode" in normalized_metadata:
        raise ValueError(
            "metadata.work_admission_mode is not a public authority surface"
        )
    if "scope_manifest" in normalized_metadata:
        normalized_metadata["scope_manifest"] = nonconflict.normalize_scope_manifest(
            normalized_metadata["scope_manifest"]
        )
    bureau_leases.enforce_bureau_lease_contract(
        keys, ttl_seconds=ttl, metadata=normalized_metadata
    )
    sanitized_value = bureau_leases.sanitize_bureau_metadata(
        keys, normalized_metadata
    )
    persisted_metadata = {} if sanitized_value is None else sanitized_value
    metadata_json, metadata_sha256 = _metadata(persisted_metadata)
    current = _normalize_mutation_lease_snapshots(
        expected_current_leases,
        expected_owner_id=owner,
        resource_keys=keys,
    )
    original = _normalize_mutation_lease_snapshots(
        expected_original_leases,
        expected_owner_id=owner,
        resource_keys=keys,
    )
    if any(item["metadata_sha256"] != metadata_sha256 for item in original):
        raise RuntimeError("Journaled lease metadata does not match requested rebind")
    current_by_key = {item["resource_key"]: item for item in current}
    now = _now()
    requested_expires = now + ttl
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is None:
                    raise RuntimeError(f"Resource lease disappeared before rebind: {key}")
                if row["owner_id"] != owner:
                    raise ResourceConflict(key, row["owner_id"], row["expires_at_unix"])
                if _release_lease_snapshot(row) != current_by_key[key]:
                    raise RuntimeError(f"Resource lease changed before rebind: {key}")
                observed_metadata = _row_metadata(row)
                _, observed_metadata_sha256 = _metadata(observed_metadata)
                if row["metadata_sha256"] != observed_metadata_sha256:
                    raise RuntimeError(
                        f"Resource lease metadata integrity mismatch: {key}"
                    )
                lease_expires = max(int(row["expires_at_unix"]), requested_expires)
                connection.execute(
                    """
                    UPDATE leases
                    SET purpose=?, updated_at_unix=?, expires_at_unix=?,
                        metadata_sha256=?, metadata_json=?
                    WHERE resource_key=? AND owner_id=?
                    """,
                    (
                        lease_purpose,
                        now,
                        lease_expires,
                        metadata_sha256,
                        metadata_json,
                        key,
                        owner,
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
        "resource_keys": keys,
        "metadata_sha256": metadata_sha256,
        "leases": [_public(row) for row in rows],
    }


def renew_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    ttl_seconds: int = 3600,
    expected_leases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    ttl = _ttl(ttl_seconds)
    expected_by_key: dict[str, dict[str, Any]] | None = None
    if expected_leases is not None:
        snapshots = _normalize_mutation_lease_snapshots(
            expected_leases, expected_owner_id=owner, resource_keys=keys
        )
        expected_by_key = {item["resource_key"]: item for item in snapshots}
    bureau_contract = bureau_leases.enforce_bureau_lease_renewal(
        keys, ttl_seconds=ttl
    )
    now = _now()
    requested_expires = now + ttl
    updates: list[tuple[int, int, str, str]] = []
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
                    raise ResourceLeaseMissing(f"Unknown resource lease: {key}")
                if row["owner_id"] != owner:
                    raise PermissionError(f"Resource lease is owned by another owner: {key}")
                if row["expires_at_unix"] <= now:
                    raise ResourceLeaseExpired(f"Resource lease has expired: {key}")
                if expected_by_key is not None and _release_lease_snapshot(
                    row
                ) != expected_by_key[key]:
                    raise RuntimeError(f"Resource lease changed before renew: {key}")
                row_metadata = _row_metadata(row)
                if row_metadata.get("lease_mode") == "emergency-recovery":
                    raise RuntimeError(
                        "emergency-recovery leases are non-renewable; "
                        "reacquire with a new validated contract"
                    )
                if "nonconflict_exception" in row_metadata:
                    raise RuntimeError(
                        "non-conflict exception leases are non-renewable; reassess and reacquire"
                    )
                updates.append(
                    (
                        now,
                        max(int(row["expires_at_unix"]), requested_expires),
                        key,
                        owner,
                    )
                )
            connection.executemany(
                "UPDATE leases SET updated_at_unix=?, expires_at_unix=? "
                "WHERE resource_key=? AND owner_id=?",
                updates,
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
        "requested_expires_at_unix": requested_expires,
        "expires_at_unix": min(int(row["expires_at_unix"]) for row in rows),
        "snapshot_guarded": expected_by_key is not None,
        "leases": [_public(row) for row in rows],
        "bureau_contract": bureau_contract,
    }


def release_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    force: bool = False,
    expected_leases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    expected_by_key: dict[str, dict[str, Any]] | None = None
    if expected_leases is not None:
        snapshots = _normalize_mutation_lease_snapshots(
            expected_leases,
            expected_owner_id=None if force else owner,
            resource_keys=keys,
        )
        expected_by_key = {item["resource_key"]: item for item in snapshots}
    released: list[dict[str, Any]] = []
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is None:
                    if expected_by_key is not None:
                        raise RuntimeError(
                            f"Resource lease disappeared before release: {key}"
                        )
                    continue
                if not force and row["owner_id"] != owner:
                    raise PermissionError(f"Resource lease is owned by another owner: {key}")
                if expected_by_key is not None and _release_lease_snapshot(
                    row
                ) != expected_by_key[key]:
                    raise RuntimeError(f"Resource lease changed before release: {key}")
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
    return {
        "owner_id": owner,
        "force": force,
        "snapshot_guarded": expected_by_key is not None,
        "released": released,
    }


def inspect_resource(resource_key: str) -> dict[str, Any] | None:
    key = normalize_resource_key(resource_key)
    now = _now()
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM leases WHERE resource_key=?", (key,)
        ).fetchone()
    if row is None or not _is_live_lease(
        expires_at_unix=row["expires_at_unix"], now_unix=now
    ):
        return None
    return _public(row)


def inspect_resources(resource_keys: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Read a bounded exact set of current leases through one store snapshot."""
    if isinstance(resource_keys, (str, bytes)):
        raise ValueError("resource_keys must be a sequence")
    keys = sorted({normalize_resource_key(value) for value in resource_keys})
    if len(keys) > 128:
        raise ValueError("resource_keys batch exceeds 128 entries")
    if not keys:
        return {}
    now = _now()
    placeholders = ",".join("?" for _item in keys)
    with _database() as connection:
        rows = connection.execute(
            f"SELECT * FROM leases WHERE resource_key IN ({placeholders})",
            keys,
        ).fetchall()
    return {
        row["resource_key"]: _public(row)
        for row in rows
        if _is_live_lease(
            expires_at_unix=row["expires_at_unix"], now_unix=now
        )
    }


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
        now = _now()
        clauses.append("typeof(expires_at_unix)='integer' AND expires_at_unix>?")
        parameters.append(now)
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
        now = _now()
        clauses.append("typeof(expires_at_unix)='integer' AND expires_at_unix>?")
        parameters.append(now)
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
    decision = result.get("decision")
    if decision not in {"allow", "deny"}:
        raise RuntimeError("nonconflict assessment returned an invalid decision")
    audit_record: dict[str, Any] = {
        "timestamp_unix": _now(),
        "operation": "resource-nonconflict-assess",
        "blocked_resource_key": result["blocked_resource_key"],
        "requesting_owner": result["requesting_owner"],
        "decision": decision,
        "requested_scope_complete": requested_scope_complete,
    }
    if decision == "allow":
        proof = result.get("proof")
        if not isinstance(proof, Mapping):
            raise RuntimeError("allowed nonconflict assessment is missing its proof")
        required_proof_fields = (
            "proof_sha256",
            "requested_scope_sha256",
            "existing_scope_sha256",
            "expires_at_unix",
        )
        if any(field not in proof for field in required_proof_fields):
            raise RuntimeError("allowed nonconflict assessment proof is incomplete")
        audit_record.update(
            {
                "proof_sha256": proof["proof_sha256"],
                "requested_scope_sha256": proof["requested_scope_sha256"],
                "existing_scope_sha256": proof["existing_scope_sha256"],
                "expires_at_unix": proof["expires_at_unix"],
            }
        )
    else:
        if "proof" in result:
            raise RuntimeError("denied nonconflict assessment must not include a proof")
        code = result.get("code")
        blocker_type = result.get("blocker_type")
        if not isinstance(code, str) or not code or not isinstance(blocker_type, str) or not blocker_type:
            raise RuntimeError("denied nonconflict assessment is missing its stable classification")
        audit_record.update(
            {
                "code": code,
                "blocker_type": blocker_type,
                "requires_atomic_revalidation": bool(
                    result.get("requires_atomic_revalidation", False)
                ),
            }
        )
    base._append_audit(audit_record)
    return result


@mcp.tool(name="grabowski_runtime_refresh_lease_release", annotations=MUTATING)
def grabowski_runtime_refresh_lease_release(
    target_sha256: str,
    result_sha256: str,
) -> dict[str, Any]:
    """Release one terminal runtime-refresh attempt's exact unchanged path leases."""
    operator._require_operator_mutation("resource_lease")
    result = release_runtime_refresh_terminal_leases(
        target_sha256=target_sha256,
        result_sha256=result_sha256,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "runtime-refresh-lease-release",
            "owner_id": result["owner_id"],
            "resource_keys": result["resource_keys"],
            "state": result["state"],
            "released_count": len(result["released"]),
            "retained_count": len(result["retained"]),
            "target_sha256": target_sha256,
            "result_sha256": result_sha256,
            "receipt_sha256": result["receipt_sha256"],
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

    Repository paths may themselves contain ``:branch:``, ``:operation:`` or
    ``:tag:``. An existing full path is therefore always broad. A non-existing
    full path is treated as scoped only when exactly one marker split resolves
    to an existing checkout root with a .git entry; ambiguous inputs fail closed.
    """
    if not resource_key.startswith("repo:"):
        return None
    value = resource_key.removeprefix("repo:")
    if os.path.lexists(value):
        return None
    candidates: set[str] = set()
    for marker in (":branch:", ":operation:", ":tag:"):
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
    if "lease_mode" in normalized_metadata:
        raise ValueError("metadata.lease_mode is not a public authority surface")
    if (
        normalized_metadata.get("bureau_phase") == "emergency-recovery"
        and repository_keys == [bureau_leases.BROAD_BUREAU_REPOSITORY_KEY]
    ):
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

    Public broad repository resources require a complete exact scope manifest.
    Emergency-recovery mode is derived only from a validated Bureau recovery
    contract; caller-supplied lease-mode metadata is not an authority surface.
    Self-scoped branch and operation keys are authoritative and reject scope
    manifests.
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
            "merge_guard_nonconflicts": result["merge_guard_nonconflicts"],
            "merge_guard_nonconflicts_sha256": hashlib.sha256(
                _canonical_json(result["merge_guard_nonconflicts"]).encode("utf-8")
            ).hexdigest(),
        }
    )
    return result


@mcp.tool(name="grabowski_resource_renew", annotations=MUTATING)
def grabowski_resource_renew(
    owner_id: str,
    resource_keys: list[str],
    ttl_seconds: int = 3600,
    expected_leases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Renew owner leases without shortening them; optionally bind exact snapshots."""
    operator._require_operator_mutation("resource_lease")
    result = renew_resources(
        owner_id,
        resource_keys,
        ttl_seconds=ttl_seconds,
        expected_leases=expected_leases,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-renew",
            "owner_id": result["owner_id"],
            "resource_keys": [item["resource_key"] for item in result["leases"]],
            "bureau_contract": result.get("bureau_contract"),
            "snapshot_guarded": result["snapshot_guarded"],
        }
    )
    return result


@mcp.tool(name="grabowski_resource_release", annotations=MUTATING)
def grabowski_resource_release(
    owner_id: str,
    resource_keys: list[str],
    force: bool = False,
    expected_leases: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Release owner leases; exact snapshots prevent stale same-owner release."""
    operator._require_operator_mutation("resource_lease")
    if not isinstance(force, bool):
        raise ValueError("force must be boolean")
    result = release_resources(
        owner_id,
        resource_keys,
        force=force,
        expected_leases=expected_leases,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-force-release" if force else "resource-release",
            "owner_id": result["owner_id"],
            "resource_keys": [item["resource_key"] for item in result["released"]],
            "force": force,
            "snapshot_guarded": result["snapshot_guarded"],
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
    limit: int = DEFAULT_RESOURCE_LIST_LIMIT,
    schema_only: bool = False,
) -> dict[str, Any]:
    """List bounded leases or inspect store-schema compatibility read-only."""
    operator._require_operator_capability("resource_lease")
    if not isinstance(schema_only, bool):
        raise ValueError("schema_only must be boolean")
    if schema_only:
        if (
            owner_id is not None
            or include_expired
            or limit != DEFAULT_RESOURCE_LIST_LIMIT
        ):
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

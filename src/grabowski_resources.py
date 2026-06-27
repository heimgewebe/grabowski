from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Iterable

import grabowski_mcp as base
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
}
OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
SERVICE_RE = re.compile(r"[A-Za-z0-9_.:@-]{1,255}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MIN_TTL_SECONDS = 30
MAX_TTL_SECONDS = 7 * 24 * 60 * 60


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


def _database() -> sqlite3.Connection:
    parent = RESOURCE_DB.parent
    if parent.is_symlink():
        raise PermissionError(f"Resource state directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if RESOURCE_DB.is_symlink():
        raise PermissionError(f"Resource database may not be a symlink: {RESOURCE_DB}")
    connection = sqlite3.connect(RESOURCE_DB, timeout=10, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS leases (
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
    current = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    if current is None:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', '1')"
        )
        connection.commit()
    elif current["value"] != "1":
        connection.close()
        raise RuntimeError("Unsupported resource database schema")
    try:
        os.chmod(RESOURCE_DB, 0o600)
    except FileNotFoundError:
        connection.close()
        raise
    return connection


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
    elif SERVICE_RE.fullmatch(value) is None:
        raise ValueError("service resource contains unsupported characters")
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


def acquire_resources(
    owner_id: str,
    resource_keys: Iterable[str],
    *,
    purpose: str,
    ttl_seconds: int = 3600,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    keys = normalize_resource_keys(resource_keys)
    lease_purpose = _purpose(purpose)
    ttl = _ttl(ttl_seconds)
    metadata_json, metadata_sha256 = _metadata(metadata)
    now = _now()
    expires = now + ttl
    reclaimed: list[dict[str, Any]] = []
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing: dict[str, sqlite3.Row] = {}
            for key in keys:
                row = connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?", (key,)
                ).fetchone()
                if row is not None:
                    existing[key] = row
                    if row["owner_id"] != owner and row["expires_at_unix"] > now:
                        raise ResourceConflict(
                            key, row["owner_id"], row["expires_at_unix"]
                        )
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
    now = _now()
    expires = now + ttl
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            for key in keys:
                row = connection.execute(
                    "SELECT owner_id, expires_at_unix FROM leases WHERE resource_key=?",
                    (key,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"Unknown resource lease: {key}")
                if row["owner_id"] != owner:
                    raise PermissionError(f"Resource lease is owned by another owner: {key}")
                if row["expires_at_unix"] <= now:
                    raise RuntimeError(f"Resource lease has expired: {key}")
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
    return {"owner_id": owner, "leases": [_public(row) for row in rows]}


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


@mcp.tool(name="grabowski_resource_acquire", annotations=MUTATING)
def grabowski_resource_acquire(
    owner_id: str,
    resource_keys: list[str],
    purpose: str,
    ttl_seconds: int = 3600,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically acquire typed resource leases for one owner."""
    operator._require_operator_mutation("resource_lease")
    result = acquire_resources(
        owner_id,
        resource_keys,
        purpose=purpose,
        ttl_seconds=ttl_seconds,
        metadata=metadata,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "resource-acquire",
            "owner_id": result["owner_id"],
            "resource_keys": [item["resource_key"] for item in result["leases"]],
            "expires_at_unix": result["expires_at_unix"],
            "reclaimed_count": len(result["reclaimed"]),
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
) -> dict[str, Any]:
    """List bounded resource leases, optionally filtered by owner."""
    operator._require_operator_capability("resource_lease")
    leases = list_resources(
        owner_id=owner_id,
        include_expired=include_expired,
        limit=limit,
    )
    return {"database": str(RESOURCE_DB), "count": len(leases), "leases": leases}

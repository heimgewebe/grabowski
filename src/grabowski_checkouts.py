from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
import urllib.parse
import uuid
from typing import Any, Iterable

import grabowski_mcp as base
import grabowski_resources as resources
import grabowski_tasks as tasks
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
CHECKOUT_DB = Path(
    os.environ.get(
        "GRABOWSKI_CHECKOUT_DB",
        str(operator.STATE_DIR / "checkouts.sqlite3"),
    )
).expanduser()
ARCHIVE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_CHECKOUT_ARCHIVE_ROOT",
        str(operator.STATE_DIR / "checkout-archives"),
    )
).expanduser()
ARCHIVE_REF_ROOT = "refs/grabowski/checkouts"
CHECKOUT_LOCK = Path(
    os.environ.get(
        "GRABOWSKI_CHECKOUT_LOCK",
        str(operator.STATE_DIR / "checkouts.lock"),
    )
).expanduser()
DRY_RUN_TTL_SECONDS = 15 * 60
OPERATION_LEASE_TTL_SECONDS = 10 * 60
MAX_RETENTION_SECONDS = 365 * 24 * 60 * 60
CHECKOUT_CLEANUP_GRACE_SECONDS = 24 * 60 * 60
MAX_ACTIVE_CHECKOUTS_PER_REPO = 8
MAX_COMPLETED_RETAINED_CHECKOUTS_PER_REPO = 4
LIFECYCLE_PHASES = frozenset({"active", "completed_retained", "archived"})
ARTIFACT_CLASS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
SOURCE_KIND_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
SOURCE_ID_RE = re.compile(r"[^\x00-\x1f\x7f]{1,256}\Z")
OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ARCHIVE_ID_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
PLAN_ID_RE = re.compile(r"[0-9a-f]{24}\Z")


def _now() -> int:
    return int(time.time())


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _validate_sha256(value: str, label: str = "sha256") -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _validate_git_object_id(value: str, label: str = "object_id") -> str:
    if not isinstance(value, str) or GIT_OBJECT_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase Git object id")
    return value


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


def _artifact_class(value: str) -> str:
    if not isinstance(value, str) or ARTIFACT_CLASS_RE.fullmatch(value) is None:
        raise ValueError("artifact_class must be a safe non-empty identifier")
    return value


def _source_binding(source_kind: str, source_id: str) -> tuple[str, str]:
    if not isinstance(source_kind, str) or SOURCE_KIND_RE.fullmatch(source_kind) is None:
        raise ValueError("source_kind must be a safe non-empty identifier")
    if not isinstance(source_id, str) or SOURCE_ID_RE.fullmatch(source_id) is None:
        raise ValueError("source_id must be non-empty, bounded text without NUL")
    normalized = source_id.strip()
    if not normalized or normalized != source_id:
        raise ValueError("source_id must be trimmed non-empty text")
    return source_kind, normalized


def _lifecycle_phase(value: str) -> str:
    if value not in LIFECYCLE_PHASES:
        raise ValueError(f"lifecycle phase must be one of {sorted(LIFECYCLE_PHASES)}")
    return value


def _retention_until(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("retention_until_unix must be an integer timestamp")
    now = _now()
    if value <= now:
        raise ValueError("retention_until_unix must be in the future")
    if value - now > MAX_RETENTION_SECONDS:
        raise ValueError("retention_until_unix is too far in the future")
    return value


def _validate_archive_id(value: str) -> str:
    if not isinstance(value, str) or ARCHIVE_ID_RE.fullmatch(value) is None:
        raise ValueError("Invalid archive id")
    return value


def _validate_plan_id(value: str) -> str:
    if not isinstance(value, str) or PLAN_ID_RE.fullmatch(value) is None:
        raise ValueError("Invalid cleanup plan id")
    return value


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _paths_related(first: Path, second: Path) -> bool:
    return _path_inside(first, second) or _path_inside(second, first)


def _path_inside_any(path: Path, roots: Iterable[Path]) -> bool:
    """Return true only when path is equal to or below one coordination root."""
    return any(_path_inside(path, root) for root in roots)


def _safe_path(raw: str | Path, *, must_exist: bool) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError("Path must be absolute")
    return path.resolve(strict=must_exist)


def _resolve_repo(raw: str | Path) -> Path:
    repo = _safe_path(raw, must_exist=True)
    if not repo.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo}")
    if (
        repo == operator.EVIDENCE_ROOT or operator.EVIDENCE_ROOT in repo.parents
    ) and not operator._trusted_owner_mode():
        raise PermissionError("Git checkout lifecycle may not mutate immutable evidence.")
    return repo


def _reject_evidence_checkout(path: Path) -> None:
    if (
        path == operator.EVIDENCE_ROOT or operator.EVIDENCE_ROOT in path.parents
    ) and not operator._trusted_owner_mode():
        raise PermissionError("Checkout lifecycle may not target immutable evidence.")


def _git_read(
    repo: Path,
    arguments: list[str],
    *,
    check: bool = True,
    timeout_seconds: int = 30,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_seconds,
        env=operator._safe_environment(),
    )
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or f"git {' '.join(arguments)} failed")
    return completed


@contextmanager
def _operation_lock():
    parent = CHECKOUT_LOCK.parent
    if parent.is_symlink():
        raise PermissionError(f"Checkout lock directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if CHECKOUT_LOCK.is_symlink():
        raise PermissionError(f"Checkout lock may not be a symlink: {CHECKOUT_LOCK}")
    descriptor = os.open(CHECKOUT_LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _git_mutate(repo: Path, arguments: list[str], *, timeout_seconds: int = 60) -> dict[str, Any]:
    with _operation_lock():
        result = operator._run(
            ["git", "-C", str(repo), *arguments],
            cwd=repo,
            timeout_seconds=timeout_seconds,
            max_output_bytes=operator.MAX_OUTPUT_BYTES,
        )
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"] or result["stdout"] or "git command failed")
    return result


def _git_common_dir(repo: Path) -> Path:
    raw = _git_read(repo, ["rev-parse", "--git-common-dir"]).stdout.strip()
    path = Path(raw)
    if not path.is_absolute():
        path = repo / path
    return path.resolve(strict=True)


def _git_top_level(repo: Path) -> Path:
    raw = _git_read(repo, ["rev-parse", "--show-toplevel"]).stdout.strip()
    return Path(raw).resolve(strict=True)


def _checkout_key(common_dir: Path, checkout_path: Path) -> str:
    material = f"{common_dir}\0{checkout_path}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _database() -> sqlite3.Connection:
    parent = CHECKOUT_DB.parent
    if parent.is_symlink():
        raise PermissionError(f"Checkout state directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if CHECKOUT_DB.is_symlink():
        raise PermissionError(f"Checkout database may not be a symlink: {CHECKOUT_DB}")
    connection = sqlite3.connect(CHECKOUT_DB, timeout=10)
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
        CREATE TABLE IF NOT EXISTS retention (
            checkout_key TEXT PRIMARY KEY,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            retention_until_unix INTEGER NOT NULL,
            expected_head TEXT,
            expected_branch TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS lifecycle_bindings (
            checkout_key TEXT PRIMARY KEY,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_id TEXT NOT NULL,
            artifact_class TEXT NOT NULL,
            phase TEXT NOT NULL,
            retention_until_unix INTEGER NOT NULL,
            expected_head TEXT,
            expected_branch TEXT,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            terminal_at_unix INTEGER,
            archived_at_unix INTEGER
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS lifecycle_repo_phase_idx "
        "ON lifecycle_bindings(repo_common_dir, phase, retention_until_unix)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS archives (
            archive_id TEXT PRIMARY KEY,
            checkout_key TEXT NOT NULL,
            repo_common_dir TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            checkout_path TEXT NOT NULL,
            head TEXT NOT NULL,
            branch TEXT,
            owner_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            retention_until_unix INTEGER NOT NULL,
            recovery_refs_json TEXT NOT NULL,
            manifest_path TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            cleaned_at_unix INTEGER,
            cleanup_plan_id TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dry_runs (
            plan_id TEXT PRIMARY KEY,
            archive_id TEXT NOT NULL,
            checkout_key TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            plan_sha256 TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            created_at_unix INTEGER NOT NULL,
            expires_at_unix INTEGER NOT NULL,
            applied_at_unix INTEGER
        )
        """
    )
    current = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    if current is None:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', '1')"
        )
    elif current["value"] != "1":
        connection.close()
        raise RuntimeError("Unsupported checkout database schema")
    connection.commit()
    try:
        os.chmod(CHECKOUT_DB, 0o600)
    except FileNotFoundError:
        connection.close()
        raise
    return connection


def _readonly_connection(path: Path) -> sqlite3.Connection | None:
    if not path.exists():
        return None
    if path.is_symlink():
        raise PermissionError(f"SQLite database may not be a symlink: {path}")
    resolved = path.resolve(strict=True)
    uri = "file:" + urllib.parse.quote(str(resolved)) + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    return connection


def _retention_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    return {
        "checkout_key": record["checkout_key"],
        "repo_common_dir": record["repo_common_dir"],
        "repo_path": record["repo_path"],
        "checkout_path": record["checkout_path"],
        "owner_id": record["owner_id"],
        "purpose": record["purpose"],
        "retention_until_unix": record["retention_until_unix"],
        "expected_head": record["expected_head"],
        "expected_branch": record["expected_branch"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
    }


def _archive_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    return {
        "archive_id": record["archive_id"],
        "checkout_key": record["checkout_key"],
        "repo_common_dir": record["repo_common_dir"],
        "repo_path": record["repo_path"],
        "checkout_path": record["checkout_path"],
        "head": record["head"],
        "branch": record["branch"],
        "owner_id": record["owner_id"],
        "purpose": record["purpose"],
        "retention_until_unix": record["retention_until_unix"],
        "recovery_refs": json.loads(record["recovery_refs_json"]),
        "manifest_path": record["manifest_path"],
        "created_at_unix": record["created_at_unix"],
        "cleaned_at_unix": record["cleaned_at_unix"],
        "cleanup_plan_id": record["cleanup_plan_id"],
    }


def _lifecycle_public(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    return {
        "checkout_key": record["checkout_key"],
        "repo_common_dir": record["repo_common_dir"],
        "repo_path": record["repo_path"],
        "checkout_path": record["checkout_path"],
        "owner_id": record["owner_id"],
        "purpose": record["purpose"],
        "source": {"kind": record["source_kind"], "id": record["source_id"]},
        "artifact_class": record["artifact_class"],
        "phase": record["phase"],
        "retention_until_unix": record["retention_until_unix"],
        "expected_head": record["expected_head"],
        "expected_branch": record["expected_branch"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "terminal_at_unix": record["terminal_at_unix"],
        "archived_at_unix": record["archived_at_unix"],
    }


def _lifecycle_bindings(keys: Iterable[str]) -> dict[str, dict[str, Any]]:
    wanted = sorted(set(keys))
    if not wanted:
        return {}
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        return {}
    try:
        rows = connection.execute(
            f"SELECT * FROM lifecycle_bindings WHERE checkout_key IN ({','.join('?' for _ in wanted)})",
            wanted,
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        connection.close()
    return {row["checkout_key"]: _lifecycle_public(row) for row in rows}


def _phase_limit(phase: str) -> int:
    normalized = _lifecycle_phase(phase)
    if normalized == "active":
        return MAX_ACTIVE_CHECKOUTS_PER_REPO
    if normalized == "completed_retained":
        return MAX_COMPLETED_RETAINED_CHECKOUTS_PER_REPO
    raise ValueError("archived checkouts do not consume an active retention limit")


def _phase_count(
    connection: sqlite3.Connection,
    *,
    repo_common_dir: Path,
    phase: str,
    exclude_checkout_key: str,
) -> int:
    row = connection.execute(
        """
        SELECT count(*) AS total
        FROM lifecycle_bindings
        WHERE repo_common_dir=? AND phase=? AND checkout_key<>?
        """,
        (str(repo_common_dir), phase, exclude_checkout_key),
    ).fetchone()
    return int(row["total"] if row is not None else 0)


def _reserve_checkout_lifecycle(
    *,
    repo_common_dir: Path,
    repo_path: Path,
    checkout_path: Path,
    owner_id: str,
    purpose: str,
    source_kind: str,
    source_id: str,
    artifact_class: str,
    retention_until_unix: int,
    expected_head: str | None,
    expected_branch: str | None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    normalized_purpose = _purpose(purpose)
    source_kind, source_id = _source_binding(source_kind, source_id)
    artifact = _artifact_class(artifact_class)
    until = _retention_until(retention_until_unix)
    common_dir = _safe_path(repo_common_dir, must_exist=True)
    top_level = _resolve_repo(repo_path)
    checkout = _safe_path(checkout_path, must_exist=False)
    _reject_evidence_checkout(checkout)
    head = (
        _validate_git_object_id(expected_head, "expected_head")
        if expected_head is not None
        else None
    )
    branch = _expected_branch(expected_branch)
    checkout_key = _checkout_key(common_dir, checkout)
    now = _now()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
        if existing is not None and existing["owner_id"] != owner:
            raise PermissionError("Checkout lifecycle binding is owned by another owner")
        if existing is not None and existing["phase"] != "active":
            raise RuntimeError("Completed or archived checkout lifecycle cannot be reopened")
        if existing is not None:
            expected_contract = (
                normalized_purpose,
                source_kind,
                source_id,
                artifact,
                head,
                branch,
            )
            observed_contract = (
                existing["purpose"],
                existing["source_kind"],
                existing["source_id"],
                existing["artifact_class"],
                existing["expected_head"],
                existing["expected_branch"],
            )
            if observed_contract != expected_contract:
                raise RuntimeError("Checkout lifecycle source or identity binding conflicts")
        count = _phase_count(
            connection,
            repo_common_dir=common_dir,
            phase="active",
            exclude_checkout_key=checkout_key,
        )
        limit = _phase_limit("active")
        if count >= limit and existing is None:
            raise RuntimeError(
                f"Per-repository active checkout limit reached: active={count} limit={limit}"
            )
        created = now if existing is None else int(existing["created_at_unix"])
        connection.execute(
            """
            INSERT INTO lifecycle_bindings(
                checkout_key, repo_common_dir, repo_path, checkout_path,
                owner_id, purpose, source_kind, source_id, artifact_class,
                phase, retention_until_unix, expected_head, expected_branch,
                created_at_unix, updated_at_unix, terminal_at_unix, archived_at_unix
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, NULL, NULL)
            ON CONFLICT(checkout_key) DO UPDATE SET
                repo_common_dir=excluded.repo_common_dir,
                repo_path=excluded.repo_path,
                checkout_path=excluded.checkout_path,
                owner_id=excluded.owner_id,
                purpose=excluded.purpose,
                source_kind=excluded.source_kind,
                source_id=excluded.source_id,
                artifact_class=excluded.artifact_class,
                phase='active',
                retention_until_unix=excluded.retention_until_unix,
                expected_head=excluded.expected_head,
                expected_branch=excluded.expected_branch,
                updated_at_unix=excluded.updated_at_unix,
                terminal_at_unix=NULL,
                archived_at_unix=NULL
            """,
            (
                checkout_key,
                str(common_dir),
                str(top_level),
                str(checkout),
                owner,
                normalized_purpose,
                source_kind,
                source_id,
                artifact,
                until,
                head,
                branch,
                created,
                now,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
    assert row is not None
    public = _lifecycle_public(row)
    public["limit"] = {"phase": "active", "count_before": count, "maximum": limit}
    return public


def _release_checkout_lifecycle_exact(binding: dict[str, Any]) -> bool:
    required = (
        binding.get("checkout_key"),
        binding.get("owner_id"),
        binding.get("created_at_unix"),
        binding.get("updated_at_unix"),
    )
    if not isinstance(required[0], str) or not isinstance(required[1], str):
        return False
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in required[2:]):
        return False
    with _database() as connection:
        deleted = connection.execute(
            """
            DELETE FROM lifecycle_bindings
            WHERE checkout_key=? AND owner_id=?
              AND created_at_unix=? AND updated_at_unix=? AND phase='active'
            """,
            required,
        )
        connection.commit()
    return deleted.rowcount == 1


def _mark_checkout_completed_retained(
    *,
    checkout_key: str,
    owner_id: str,
    expected_head: str,
    expected_branch: str | None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    head = _validate_git_object_id(expected_head, "expected_head")
    branch = _expected_branch(expected_branch)
    now = _now()
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
        if row is None:
            raise RuntimeError("Checkout lifecycle binding is missing")
        if row["owner_id"] != owner:
            raise PermissionError("Checkout lifecycle binding is owned by another owner")
        if row["expected_branch"] != branch:
            raise RuntimeError("Checkout branch changed before lifecycle completion")
        if row["phase"] == "completed_retained":
            if row["expected_head"] != head:
                raise RuntimeError(
                    "Completed-retained checkout head changed after terminal decision"
                )
            return _lifecycle_public(row)
        if row["phase"] != "active":
            raise RuntimeError("Only an active checkout may become completed-retained")
        count = _phase_count(
            connection,
            repo_common_dir=Path(row["repo_common_dir"]),
            phase="completed_retained",
            exclude_checkout_key=checkout_key,
        )
        limit = _phase_limit("completed_retained")
        if count >= limit:
            raise RuntimeError(
                "Per-repository completed-retained checkout limit reached: "
                f"completed_retained={count} limit={limit}"
            )
        connection.execute(
            """
            UPDATE lifecycle_bindings
            SET phase='completed_retained', expected_head=?,
                terminal_at_unix=?, updated_at_unix=?
            WHERE checkout_key=?
            """,
            (head, now, now, checkout_key),
        )
        retention_update = connection.execute(
            """
            UPDATE retention
            SET expected_head=?, expected_branch=?, updated_at_unix=?
            WHERE checkout_key=? AND owner_id=?
            """,
            (head, branch, now, checkout_key, owner),
        )
        if retention_update.rowcount != 1:
            raise RuntimeError(
                "Checkout retention binding is missing at terminal transition"
            )
        connection.commit()
        updated = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
    assert updated is not None
    public = _lifecycle_public(updated)
    public["limit"] = {
        "phase": "completed_retained",
        "count_before": count,
        "maximum": limit,
    }
    return public


def _mark_checkout_archived_in_connection(
    connection: sqlite3.Connection,
    checkout_key: str,
    owner_id: str,
    archived_at: int,
) -> dict[str, Any] | None:
    owner = _owner(owner_id)
    row = connection.execute(
        "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
        (checkout_key,),
    ).fetchone()
    if row is None:
        return None
    if row["owner_id"] != owner:
        raise PermissionError("Checkout lifecycle binding is owned by another owner")
    updated = connection.execute(
        """
        UPDATE lifecycle_bindings
        SET phase='archived', archived_at_unix=?, updated_at_unix=?
        WHERE checkout_key=? AND owner_id=?
        """,
        (archived_at, archived_at, checkout_key, owner),
    )
    if updated.rowcount != 1:
        raise RuntimeError("Checkout lifecycle archive transition was not applied exactly")
    row = connection.execute(
        "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
        (checkout_key,),
    ).fetchone()
    return None if row is None else _lifecycle_public(row)


def _mark_checkout_archived(
    checkout_key: str,
    owner_id: str,
    archived_at: int,
) -> dict[str, Any] | None:
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        lifecycle = _mark_checkout_archived_in_connection(
            connection,
            checkout_key,
            owner_id,
            archived_at,
        )
        connection.commit()
    return lifecycle


def _retention_records(keys: Iterable[str]) -> dict[str, dict[str, Any]]:
    wanted = sorted(set(keys))
    if not wanted:
        return {}
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        return {}
    try:
        rows = connection.execute(
            f"SELECT * FROM retention WHERE checkout_key IN ({','.join('?' for _ in wanted)})",
            wanted,
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        connection.close()
    return {row["checkout_key"]: _retention_public(row) for row in rows}


def _latest_archives(keys: Iterable[str]) -> dict[str, dict[str, Any]]:
    wanted = sorted(set(keys))
    if not wanted:
        return {}
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        return {}
    try:
        rows = connection.execute(
            f"""
            SELECT a.* FROM archives a
            JOIN (
                SELECT checkout_key, max(created_at_unix) AS created_at_unix
                FROM archives
                WHERE checkout_key IN ({','.join('?' for _ in wanted)})
                GROUP BY checkout_key
            ) latest
            ON a.checkout_key=latest.checkout_key
            AND a.created_at_unix=latest.created_at_unix
            ORDER BY a.checkout_key, a.archive_id
            """,
            wanted,
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        connection.close()
    return {row["checkout_key"]: _archive_public(row) for row in rows}


def _load_archive(archive_id: str) -> dict[str, Any]:
    identifier = _validate_archive_id(archive_id)
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM archives WHERE archive_id=?",
            (identifier,),
        ).fetchone()
    if row is None:
        raise ValueError(f"Unknown checkout archive: {identifier}")
    return _archive_public(row)


def _latest_archive_for_key(checkout_key: str) -> dict[str, Any] | None:
    with _database() as connection:
        row = connection.execute(
            """
            SELECT * FROM archives
            WHERE checkout_key=? AND cleaned_at_unix IS NULL
            ORDER BY created_at_unix DESC, archive_id DESC
            LIMIT 1
            """,
            (checkout_key,),
        ).fetchone()
    return None if row is None else _archive_public(row)


def _upsert_retention(
    *,
    checkout_key: str,
    repo_common_dir: Path,
    repo_path: Path,
    checkout_path: Path,
    owner_id: str,
    purpose: str,
    retention_until_unix: int,
    expected_head: str | None,
    expected_branch: str | None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    retain_purpose = _purpose(purpose)
    until = _retention_until(retention_until_unix)
    now = _now()
    with _database() as connection:
        existing = connection.execute(
            "SELECT * FROM retention WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
        if (
            existing is not None
            and existing["retention_until_unix"] > now
            and existing["owner_id"] != owner
        ):
            raise PermissionError("Active checkout retention is owned by another owner")
        created_at = now if existing is None else existing["created_at_unix"]
        connection.execute(
            """
            INSERT INTO retention(
                checkout_key, repo_common_dir, repo_path, checkout_path,
                owner_id, purpose, retention_until_unix, expected_head,
                expected_branch, created_at_unix, updated_at_unix
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(checkout_key) DO UPDATE SET
                repo_common_dir=excluded.repo_common_dir,
                repo_path=excluded.repo_path,
                checkout_path=excluded.checkout_path,
                owner_id=excluded.owner_id,
                purpose=excluded.purpose,
                retention_until_unix=excluded.retention_until_unix,
                expected_head=excluded.expected_head,
                expected_branch=excluded.expected_branch,
                updated_at_unix=excluded.updated_at_unix
            """,
            (
                checkout_key,
                str(repo_common_dir),
                str(repo_path),
                str(checkout_path),
                owner,
                retain_purpose,
                until,
                expected_head,
                expected_branch,
                created_at,
                now,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM retention WHERE checkout_key=?",
            (checkout_key,),
        ).fetchone()
    assert row is not None
    return _retention_public(row)


def _lease_ttl(retention_until_unix: int) -> int:
    remaining = max(resources.MIN_TTL_SECONDS, retention_until_unix - _now())
    return min(resources.MAX_TTL_SECONDS, remaining)


def _checkout_resource_keys(repo_common_dir: Path, checkout_path: Path) -> list[str]:
    """Return the exact checkout and shared Git-metadata serialization claims."""
    return [
        resources.normalize_resource_key(f"path:{checkout_path}"),
        resources.normalize_resource_key(f"path:{repo_common_dir}"),
    ]


def _acquire_checkout_resources(
    *,
    owner_id: str,
    repo_common_dir: Path,
    checkout_path: Path,
    purpose: str,
    retention_until_unix: int,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    durable_owner = _owner(owner_id)
    lease_owner = f"checkout-op:{uuid.uuid4().hex[:20]}"
    return resources.acquire_resources(
        lease_owner,
        _checkout_resource_keys(repo_common_dir, checkout_path),
        purpose=purpose,
        ttl_seconds=OPERATION_LEASE_TTL_SECONDS,
        metadata={
            **metadata,
            "durable_owner_id": durable_owner,
            "git_common_dir": str(repo_common_dir),
        },
    )


def _release_checkout_resources(lease: dict[str, Any]) -> dict[str, Any]:
    keys = [item["resource_key"] for item in lease["leases"]]
    return resources.release_resources(lease["owner_id"], keys)


def _require_retention_owner(checkout_key: str, owner_id: str) -> None:
    owner = _owner(owner_id)
    existing = _retention_records([checkout_key]).get(checkout_key)
    if (
        existing is not None
        and existing["retention_until_unix"] > _now()
        and existing["owner_id"] != owner
    ):
        raise PermissionError("Active checkout retention is owned by another owner")


def _parse_worktree_list(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in output.splitlines() + [""]:
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            current["path"] = value
        elif key == "HEAD":
            current["head"] = value
        elif key == "branch":
            current["branch_ref"] = value
            current["branch"] = value.removeprefix("refs/heads/")
        elif key == "prunable":
            current["prunable"] = True
            current["prunable_reason"] = value
        elif key in {"bare", "detached"}:
            current[key] = True
    return records


def _worktree_records(repo: Path) -> tuple[Path, Path, list[dict[str, Any]]]:
    top_level = _git_top_level(repo)
    common_dir = _git_common_dir(repo)
    completed = _git_read(repo, ["worktree", "list", "--porcelain"])
    raw_records = _parse_worktree_list(completed.stdout)
    if not raw_records:
        raise RuntimeError("Git returned no worktree records")
    main_path = _safe_path(raw_records[0]["path"], must_exist=False)
    records: list[dict[str, Any]] = []
    for raw in raw_records:
        checkout_path = _safe_path(raw["path"], must_exist=False)
        key = _checkout_key(common_dir, checkout_path)
        record = {
            "checkout_key": key,
            "path": str(checkout_path),
            "repo_common_dir": str(common_dir),
            "head": raw.get("head"),
            "branch": raw.get("branch"),
            "branch_ref": raw.get("branch_ref"),
            "detached": bool(raw.get("detached")),
            "bare": bool(raw.get("bare")),
            "prunable": bool(raw.get("prunable")),
            "prunable_reason": raw.get("prunable_reason"),
            "is_main": checkout_path == main_path or checkout_path == top_level,
            "is_linked": not (checkout_path == main_path or checkout_path == top_level),
        }
        records.append(record)
    return top_level, common_dir, sorted(records, key=lambda item: item["path"])


def _worktree_status(record: dict[str, Any]) -> dict[str, Any]:
    path = Path(record["path"])
    if record.get("prunable") or not path.exists():
        return {
            "returncode": None,
            "dirty": None,
            "entry_count": None,
            "untracked_count": None,
            "error": "worktree is missing or prunable",
        }
    completed = _git_read(
        path,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
    )
    entries = [line for line in completed.stdout.splitlines() if line]
    if completed.returncode != 0:
        return {
            "returncode": completed.returncode,
            "dirty": None,
            "entry_count": None,
            "untracked_count": None,
            "error": (completed.stderr or completed.stdout).strip(),
        }
    return {
        "returncode": completed.returncode,
        "dirty": bool(entries),
        "entry_count": len(entries),
        "untracked_count": sum(1 for line in entries if line.startswith("??")),
        "error": None,
    }


def _read_resource_leases() -> list[dict[str, Any]]:
    connection = _readonly_connection(resources.RESOURCE_DB)
    if connection is None:
        return []
    try:
        rows = connection.execute(
            "SELECT * FROM leases WHERE expires_at_unix>? ORDER BY resource_key",
            (_now(),),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        connection.close()
    return [
        {
            "resource_key": row["resource_key"],
            "owner_id": row["owner_id"],
            "purpose": row["purpose"],
            "expires_at_unix": row["expires_at_unix"],
            "metadata_sha256": row["metadata_sha256"],
        }
        for row in rows
    ]


def _resource_related(resource_key: str, paths: list[Path]) -> bool:
    if ":" not in resource_key:
        return False
    kind, value = resource_key.split(":", 1)
    if kind not in {"path", "repo"}:
        return False
    try:
        resource_path = _safe_path(value, must_exist=False)
    except (OSError, ValueError):
        return False
    return any(_paths_related(resource_path, path) for path in paths)


def _task_records(paths: list[Path]) -> list[dict[str, Any]]:
    connection = _readonly_connection(tasks.TASK_DB)
    if connection is None:
        return []
    try:
        rows = connection.execute(
            """
            SELECT task_id, host, unit, state, cwd, resource_keys_json, lease_owner_id
            FROM tasks
            WHERE state IN ('launching', 'running')
            ORDER BY task_id
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        connection.close()
    results: list[dict[str, Any]] = []
    for row in rows:
        related = False
        cwd = row["cwd"]
        try:
            cwd_path = _safe_path(cwd, must_exist=False)
            related = _path_inside_any(cwd_path, paths)
        except (OSError, ValueError):
            pass
        resource_keys: list[str] = []
        try:
            raw_keys = json.loads(row["resource_keys_json"] or "[]")
            if isinstance(raw_keys, list):
                resource_keys = [str(item) for item in raw_keys if isinstance(item, str)]
                related = related or any(
                    _resource_related(key, paths) for key in resource_keys
                )
        except json.JSONDecodeError:
            resource_keys = []
        if related:
            results.append(
                {
                    "task_id": row["task_id"],
                    "host": row["host"],
                    "unit": row["unit"],
                    "state": row["state"],
                    "cwd": cwd,
                    "resource_keys": sorted(resource_keys),
                    "lease_owner_id": row["lease_owner_id"],
                }
            )
    return results

def _processes_under(paths: list[Path]) -> list[dict[str, Any]]:
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    current_uid = os.getuid()
    records: list[dict[str, Any]] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != current_uid:
                continue
            cwd_raw = os.readlink(entry / "cwd")
            cwd = _safe_path(cwd_raw.removesuffix(" (deleted)"), must_exist=False)
        except (FileNotFoundError, PermissionError, ProcessLookupError, OSError, ValueError):
            continue
        if not _path_inside_any(cwd, paths):
            continue
        command = ""
        try:
            command = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except (OSError, UnicodeDecodeError):
            pass
        records.append({"pid": int(entry.name), "cwd": str(cwd), "command": command})
    return sorted(records, key=lambda item: item["pid"])


def _coordination_result(
    resource_blockers: list[dict[str, Any]],
    task_blockers: list[dict[str, Any]],
    process_blockers: list[dict[str, Any]],
) -> dict[str, Any]:
    blocking_resources = [item for item in resource_blockers if item["blocking"]]
    return {
        "resource_leases": resource_blockers,
        "tasks": task_blockers,
        "processes": process_blockers,
        "blocking": bool(blocking_resources or task_blockers or process_blockers),
        "blocking_counts": {
            "resource_leases": len(blocking_resources),
            "tasks": len(task_blockers),
            "processes": len(process_blockers),
        },
    }


def _coordination(
    paths: list[Path],
    *,
    owner_id: str | None = None,
    include_processes: bool = True,
    include_tasks: bool = True,
    include_resources: bool = True,
) -> dict[str, Any]:
    if owner_id is not None:
        _owner(owner_id)
    resource_blockers: list[dict[str, Any]] = []
    if include_resources:
        for lease in _read_resource_leases():
            if not _resource_related(lease["resource_key"], paths):
                continue
            lease = {**lease, "blocking": True}
            resource_blockers.append(lease)
    task_blockers = _task_records(paths) if include_tasks else []
    process_blockers = _processes_under(paths) if include_processes else []
    return _coordination_result(resource_blockers, task_blockers, process_blockers)


def _linked_checkout_coordination(
    checkout_path: Path,
    repo_path: Path,
    repo_common_dir: Path,
    *,
    owner_id: str | None = None,
    include_processes: bool = True,
    include_tasks: bool = True,
    include_resources: bool = True,
) -> dict[str, Any]:
    if owner_id is not None:
        _owner(owner_id)
    resource_blockers: list[dict[str, Any]] = []
    if include_resources:
        for lease in _read_resource_leases():
            if not _resource_related(
                lease["resource_key"], [checkout_path, repo_common_dir]
            ):
                continue
            lease = {**lease, "blocking": True}
            resource_blockers.append(lease)
    task_blockers = _task_records([checkout_path, repo_path]) if include_tasks else []
    process_blockers = _processes_under([checkout_path]) if include_processes else []
    return _coordination_result(resource_blockers, task_blockers, process_blockers)


def _require_no_blockers(coordination: dict[str, Any]) -> None:
    if not coordination["blocking"]:
        return
    counts = coordination["blocking_counts"]
    raise RuntimeError(
        "Checkout is still coordinated by active work: "
        f"resources={counts['resource_leases']} "
        f"tasks={counts['tasks']} processes={counts['processes']}"
    )


def _retention_active(lifecycle: dict[str, Any], now: int) -> bool:
    retention = lifecycle.get("retention")
    return bool(
        isinstance(retention, dict)
        and isinstance(retention.get("retention_until_unix"), int)
        and retention["retention_until_unix"] > now
    )


def _archive_matches_checkout(
    record: dict[str, Any], lifecycle: dict[str, Any]
) -> bool:
    archive = lifecycle.get("latest_archive")
    return bool(
        isinstance(archive, dict)
        and archive.get("cleaned_at_unix") is None
        and archive.get("head") == record.get("head")
        and archive.get("branch") == record.get("branch")
    )


def _checkout_lifecycle_decision(
    record: dict[str, Any],
    status: dict[str, Any],
    lifecycle: dict[str, Any],
    coordination: dict[str, Any],
    *,
    exists: bool,
    now: int,
) -> dict[str, Any]:
    """Classify one checkout without authorizing cleanup by classification alone."""
    retention = lifecycle.get("retention")
    archive = lifecycle.get("latest_archive")
    retention_is_active = _retention_active(lifecycle, now)
    archive_present = isinstance(archive, dict)
    archive_open = archive_present and archive.get("cleaned_at_unix") is None
    archive_matches = _archive_matches_checkout(record, lifecycle)
    archive_age_seconds = (
        max(0, now - int(archive["created_at_unix"]))
        if archive_present and isinstance(archive.get("created_at_unix"), int)
        else None
    )
    archive_grace_elapsed = bool(
        archive_age_seconds is not None
        and archive_age_seconds >= CHECKOUT_CLEANUP_GRACE_SECONDS
    )
    blocking = bool(coordination.get("blocking"))
    reasons: list[str] = []
    cleanup_candidate = False
    requires_cleanup_dry_run = False

    if record["is_main"]:
        state = "main"
        hygiene_mark = "primary"
        next_step = "no_cleanup"
        reasons.append("main worktree is never a temporary checkout cleanup target")
    elif record["bare"]:
        state = "unobservable"
        hygiene_mark = "unknown"
        next_step = "inspect_bare_worktree_before_lifecycle_action"
        reasons.append("bare worktree cannot be classified as a normal linked checkout")
    elif record["prunable"] or not exists:
        state = "prunable_or_missing"
        hygiene_mark = "obsolete"
        next_step = "review_git_worktree_prune_separately"
        reasons.append("git reports the worktree as prunable or the path is missing")
    elif status["dirty"] is True:
        state = "dirty"
        hygiene_mark = "dirty"
        next_step = "review_or_retain_dirty_checkout_before_archive"
        reasons.append("checkout has staged, unstaged or untracked entries")
        if retention_is_active:
            reasons.append("active retention exists but does not make dirty state clean")
    elif status["dirty"] is not False:
        state = "unobservable"
        hygiene_mark = "unknown"
        next_step = "repair_status_observability_before_lifecycle_action"
        reasons.append("git status could not prove whether the checkout is clean")
    elif archive_present and not archive_open:
        state = "archive_closed"
        hygiene_mark = "unknown"
        next_step = "inspect_restored_or_recreated_checkout_before_cleanup"
        reasons.append("latest archive record is already marked cleaned")
    elif archive_present and not archive_matches:
        state = "archive_drifted"
        hygiene_mark = "unknown"
        next_step = "refresh_archive_or_retain_before_cleanup"
        reasons.append("latest archive does not match current checkout head or branch")
    elif archive_present and not archive_grace_elapsed:
        state = "archived_grace"
        hygiene_mark = "archived"
        next_step = "wait_for_checkout_cleanup_grace"
        reasons.append("matching recovery archive is younger than the 24-hour cleanup grace")
    elif archive_present and blocking:
        state = "archived_blocked"
        hygiene_mark = "archived"
        next_step = "resolve_coordination_blockers_before_cleanup_dry_run"
        reasons.append("checkout is archived but active coordination blocks cleanup")
    elif archive_present:
        state = "cleanup_candidate"
        hygiene_mark = "obsolete"
        cleanup_candidate = True
        requires_cleanup_dry_run = True
        next_step = "run_checkout_cleanup_dry_run_before_apply"
        reasons.append("clean linked checkout has matching open recovery archive")
    elif retention_is_active:
        state = "retained"
        hygiene_mark = "retained"
        next_step = "wait_for_retention_or_owner_review_before_archive"
        reasons.append("active retention owner protects this checkout")
    elif blocking:
        state = "blocked_unarchived"
        hygiene_mark = "unknown"
        next_step = "resolve_coordination_blockers_before_archive"
        reasons.append("active coordination exists and no recovery archive is present")
    else:
        state = "unclassified_clean"
        hygiene_mark = "unknown"
        next_step = "decide_retain_or_archive_using_external_truth"
        reasons.append(
            "clean linked checkout has no retention or archive; local inventory does not prove it is obsolete"
        )

    return {
        "state": state,
        "hygiene_mark": hygiene_mark,
        "retention_active": retention_is_active,
        "retention_owner_id": retention.get("owner_id") if isinstance(retention, dict) else None,
        "archive_present": archive_present,
        "archive_open": bool(archive_open),
        "archive_matches_checkout": bool(archive_matches),
        "archive_age_seconds": archive_age_seconds,
        "archive_grace_seconds": CHECKOUT_CLEANUP_GRACE_SECONDS,
        "archive_grace_elapsed": archive_grace_elapsed,
        "coordination_blocking": blocking,
        "cleanup_candidate": cleanup_candidate,
        "requires_cleanup_dry_run": requires_cleanup_dry_run,
        "recommended_next_step": next_step,
        "reasons": reasons,
        "does_not_establish": [
            "permission_to_cleanup",
            "branch_is_obsolete",
            "safe_to_delete_branch",
        ],
    }


def checkout_inventory(
    repo: str | Path,
    *,
    include_processes: bool = True,
    include_tasks: bool = True,
    include_resources: bool = True,
) -> dict[str, Any]:
    repo_path = _resolve_repo(repo)
    top_level, common_dir, records = _worktree_records(repo_path)
    keys = [record["checkout_key"] for record in records]
    retention = _retention_records(keys)
    bindings = _lifecycle_bindings(keys)
    archives = _latest_archives(keys)
    now = _now()
    worktrees: list[dict[str, Any]] = []
    for record in records:
        checkout_path = Path(record["path"])
        status = _worktree_status(record)
        coordination = _linked_checkout_coordination(
            checkout_path,
            top_level,
            common_dir,
            include_processes=include_processes,
            include_tasks=include_tasks,
            include_resources=include_resources,
        )
        lifecycle = {
            "retention": retention.get(record["checkout_key"]),
            "binding": bindings.get(record["checkout_key"]),
            "latest_archive": archives.get(record["checkout_key"]),
        }
        exists = checkout_path.exists()
        decision = _checkout_lifecycle_decision(
            record,
            status,
            lifecycle,
            coordination,
            exists=exists,
            now=now,
        )
        worktrees.append(
            {
                **record,
                "exists": exists,
                "status": status,
                "coordination": coordination,
                "lifecycle": lifecycle,
                "lifecycle_state": decision["state"],
                "hygiene_mark": decision["hygiene_mark"],
                "lifecycle_decision": decision,
                "cleanup_candidate": decision["cleanup_candidate"],
            }
        )
    body = {
        "schema_version": 1,
        "repository": str(top_level),
        "requested_repo": str(repo_path),
        "git_common_dir": str(common_dir),
        "worktrees": sorted(worktrees, key=lambda item: item["path"]),
    }
    return {
        **body,
        "generated_at_unix": _now(),
        "inventory_sha256": _sha256_json(body),
    }


def _worktree_for_path(repo_path: Path, checkout_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    top_level, common_dir, records = _worktree_records(repo_path)
    target = checkout_path.resolve(strict=True)
    for record in records:
        if Path(record["path"]).resolve(strict=False) == target:
            return top_level, common_dir, record
    raise ValueError(f"Path is not a linked Git worktree for this repository: {target}")


def _expected_branch(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value.startswith("-") or "\x00" in value:
        raise ValueError("expected_branch is invalid")
    return value


def _require_expected(record: dict[str, Any], expected_head: str, expected_branch: str | None) -> None:
    head = _validate_git_object_id(expected_head, "expected_head")
    branch = _expected_branch(expected_branch)
    if record.get("head") != head:
        raise RuntimeError(
            f"Checkout HEAD precondition failed: expected {head}, current {record.get('head')}"
        )
    if branch is not None and record.get("branch") != branch:
        raise RuntimeError(
            f"Checkout branch precondition failed: expected {branch}, current {record.get('branch')}"
        )


def _require_linked(record: dict[str, Any]) -> Path:
    if not record["is_linked"]:
        raise PermissionError("The main worktree is not a temporary linked checkout")
    if record["bare"] or record["prunable"]:
        raise RuntimeError("Checkout is bare or prunable and cannot be managed safely")
    path = Path(record["path"])
    if not path.is_dir():
        raise FileNotFoundError(f"Checkout path is missing: {path}")
    if (path / ".git").is_symlink():
        raise PermissionError("Symlinked checkout metadata is not allowed")
    return path


def _require_clean_linked(record: dict[str, Any]) -> dict[str, Any]:
    _require_linked(record)
    status = _worktree_status(record)
    if status["dirty"] is not False:
        raise RuntimeError("Checkout must be clean before archival or cleanup")
    return status


def _new_archive_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:12]}"


def _archive_directory(archive_id: str) -> Path:
    root = ARCHIVE_ROOT
    if root.is_symlink():
        raise PermissionError(f"Checkout archive root may not be a symlink: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = root.resolve(strict=True)
    path = resolved / _validate_archive_id(archive_id)
    path.mkdir(mode=0o700)
    return path


def _write_json_evidence(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _check_ref_format(repo: Path, ref: str) -> None:
    _git_read(repo, ["check-ref-format", ref])


def _create_recovery_ref(repo: Path, ref: str, target: str) -> dict[str, Any]:
    _check_ref_format(repo, ref)
    result = _git_mutate(repo, ["update-ref", "--create-reflog", ref, target])
    verified = _git_read(repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"]).stdout.strip()
    if verified != target:
        raise RuntimeError(f"Recovery ref verification failed: {ref}")
    return {"ref": ref, "target": target, "result": result}


def _verify_recovery_refs(repo: Path, recovery_refs: list[dict[str, str]]) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    for item in recovery_refs:
        ref = item["ref"]
        target = item["target"]
        current = _git_read(
            repo,
            ["rev-parse", "--verify", f"{ref}^{{commit}}"],
            check=False,
        )
        verified.append(
            {
                "ref": ref,
                "target": target,
                "present": current.returncode == 0 and current.stdout.strip() == target,
            }
        )
    return verified


@mcp.tool(name="grabowski_checkout_inventory", annotations=READ_ONLY)
def grabowski_checkout_inventory(
    repo: str,
    include_processes: bool = True,
    include_tasks: bool = True,
    include_resources: bool = True,
) -> dict[str, Any]:
    """Return a deterministic inventory of linked Git checkouts and lifecycle state."""
    operator._require_operator_capability("git_cli")
    return checkout_inventory(
        repo,
        include_processes=include_processes,
        include_tasks=include_tasks,
        include_resources=include_resources,
    )


@mcp.tool(name="grabowski_checkout_retain", annotations=MUTATING)
def grabowski_checkout_retain(
    repo: str,
    checkout_path: str,
    owner_id: str,
    purpose: str,
    retention_until_unix: int,
    expected_head: str,
    expected_branch: str | None = None,
) -> dict[str, Any]:
    """Assign explicit retention ownership to one temporary linked Git checkout."""
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    repo_path = _resolve_repo(repo)
    checkout = _safe_path(checkout_path, must_exist=True)
    _reject_evidence_checkout(checkout)
    top_level, common_dir, record = _worktree_for_path(repo_path, checkout)
    _require_linked(record)
    _require_expected(record, expected_head, expected_branch)
    owner = _owner(owner_id)
    until = _retention_until(retention_until_unix)
    retain_purpose = _purpose(purpose)
    _require_retention_owner(record["checkout_key"], owner)
    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=common_dir,
        checkout_path=checkout,
        purpose=f"retain linked checkout: {retain_purpose}",
        retention_until_unix=until,
        metadata={
            "checkout_path": str(checkout),
            "repo": str(top_level),
            "head": expected_head,
            "branch": expected_branch,
        },
    )
    try:
        retention = _upsert_retention(
            checkout_key=record["checkout_key"],
            repo_common_dir=common_dir,
            repo_path=top_level,
            checkout_path=checkout,
            owner_id=owner,
            purpose=retain_purpose,
            retention_until_unix=until,
            expected_head=expected_head,
            expected_branch=expected_branch,
        )
    finally:
        lease_release = _release_checkout_resources(lease)
    audit = {
        "timestamp_unix": _now(),
        "operation": "checkout-retain",
        "checkout_key": record["checkout_key"],
        "repo": str(top_level),
        "checkout_path": str(checkout),
        "owner_id": owner,
        "retention_until_unix": until,
        "head": expected_head,
        "branch": expected_branch,
        "resource_keys": [item["resource_key"] for item in lease["leases"]],
    }
    base._append_audit(audit)
    return {"retention": retention, "lease": lease, "lease_release": lease_release, "audit": audit}


@mcp.tool(name="grabowski_checkout_archive", annotations=MUTATING)
def grabowski_checkout_archive(
    repo: str,
    checkout_path: str,
    owner_id: str,
    purpose: str,
    retention_until_unix: int,
    expected_head: str,
    expected_branch: str | None = None,
) -> dict[str, Any]:
    """Archive one clean temporary linked checkout by creating durable recovery refs."""
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    repo_path = _resolve_repo(repo)
    checkout = _safe_path(checkout_path, must_exist=True)
    _reject_evidence_checkout(checkout)
    top_level, common_dir, record = _worktree_for_path(repo_path, checkout)
    status = _require_clean_linked(record)
    _require_expected(record, expected_head, expected_branch)
    owner = _owner(owner_id)
    until = _retention_until(retention_until_unix)
    archive_purpose = _purpose(purpose)
    coordination = _linked_checkout_coordination(
        checkout,
        top_level,
        common_dir,
        owner_id=owner,
        include_processes=True,
        include_tasks=True,
        include_resources=True,
    )
    _require_no_blockers(coordination)
    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=common_dir,
        checkout_path=checkout,
        purpose=f"archive linked checkout: {archive_purpose}",
        retention_until_unix=until,
        metadata={
            "checkout_path": str(checkout),
            "repo": str(top_level),
            "head": expected_head,
            "branch": expected_branch,
        },
    )
    result: dict[str, Any] | None = None
    try:
        retention = _upsert_retention(
            checkout_key=record["checkout_key"],
            repo_common_dir=common_dir,
            repo_path=top_level,
            checkout_path=checkout,
            owner_id=owner,
            purpose=archive_purpose,
            retention_until_unix=until,
            expected_head=expected_head,
            expected_branch=expected_branch,
        )
        lifecycle = _lifecycle_bindings([record["checkout_key"]]).get(
            record["checkout_key"]
        )
        if lifecycle is not None and lifecycle["owner_id"] != owner:
            raise PermissionError(
                "Checkout lifecycle binding is owned by another owner"
            )

        archive_id = _new_archive_id()
        path_hash = record["checkout_key"][:16]
        ref_base = f"{ARCHIVE_REF_ROOT}/{path_hash}/{archive_id}"
        recovery_refs = [
            _create_recovery_ref(top_level, f"{ref_base}/head", expected_head)
        ]
        branch_head = None
        if record.get("branch"):
            branch_ref = f"refs/heads/{record['branch']}"
            branch_head = _git_read(
                top_level,
                ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"],
            ).stdout.strip()
            recovery_refs.append(
                _create_recovery_ref(
                    top_level,
                    f"{ref_base}/branch-head",
                    branch_head,
                )
            )
        manifest_dir = _archive_directory(archive_id)
        public_refs = [
            {
                "role": (
                    "head" if item["ref"].endswith("/head") else "branch-head"
                ),
                "ref": item["ref"],
                "target": item["target"],
            }
            for item in recovery_refs
        ]
        manifest = {
            "schema_version": 1,
            "archive_id": archive_id,
            "checkout_key": record["checkout_key"],
            "repo": str(top_level),
            "git_common_dir": str(common_dir),
            "checkout_path": str(checkout),
            "head": expected_head,
            "branch": record.get("branch"),
            "branch_head": branch_head,
            "owner_id": owner,
            "purpose": archive_purpose,
            "retention_until_unix": until,
            "created_at": _utc_timestamp(),
            "recovery_refs": public_refs,
            "cleanup": {
                "requires_dry_run": True,
                "tool": "grabowski_checkout_cleanup",
            },
            "rollback": {
                "available": True,
                "command": [
                    "git",
                    "-C",
                    str(top_level),
                    "worktree",
                    "add",
                    str(checkout),
                    public_refs[0]["ref"],
                ],
                "branch_preserved": bool(record.get("branch")),
            },
        }
        manifest_path = manifest_dir / "manifest.json"
        _write_json_evidence(manifest_path, manifest)
        created = _now()
        with _database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO archives(
                    archive_id, checkout_key, repo_common_dir, repo_path,
                    checkout_path, head, branch, owner_id, purpose,
                    retention_until_unix, recovery_refs_json, manifest_path,
                    created_at_unix, cleaned_at_unix, cleanup_plan_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    archive_id,
                    record["checkout_key"],
                    str(common_dir),
                    str(top_level),
                    str(checkout),
                    expected_head,
                    record.get("branch"),
                    owner,
                    archive_purpose,
                    until,
                    _canonical_json(public_refs),
                    str(manifest_path),
                    created,
                ),
            )
            lifecycle_binding = _mark_checkout_archived_in_connection(
                connection,
                record["checkout_key"],
                owner,
                created,
            )
            connection.commit()
        archive = _load_archive(archive_id)
        audit = {
            "timestamp_unix": created,
            "operation": "checkout-archive",
            "archive_id": archive_id,
            "checkout_key": record["checkout_key"],
            "repo": str(top_level),
            "checkout_path": str(checkout),
            "owner_id": owner,
            "head": expected_head,
            "branch": record.get("branch"),
            "recovery_refs": public_refs,
            "branch_preserved": bool(record.get("branch")),
            "status": status,
            "coordination_checked": coordination["blocking_counts"],
            "resource_keys": [
                item["resource_key"] for item in lease["leases"]
            ],
            "rollback": manifest["rollback"],
        }
        base._append_audit(audit)
        result = {
            "archive": archive,
            "retention": retention,
            "lifecycle_binding": lifecycle_binding,
            "lease": lease,
            "manifest": manifest,
            "audit": audit,
        }
    finally:
        lease_release = _release_checkout_resources(lease)
    if result is None:
        raise RuntimeError("Checkout archive did not produce a result")
    result["lease_release"] = lease_release
    return result

def _cleanup_plan(
    *,
    repo_path: Path,
    checkout: Path,
    owner_id: str,
    archive_id: str | None,
    expected_head: str | None,
    expected_branch: str | None,
) -> dict[str, Any]:
    top_level, common_dir, record = _worktree_for_path(repo_path, checkout)
    status = _require_clean_linked(record)
    if expected_head is not None or expected_branch is not None:
        _require_expected(record, expected_head or str(record.get("head")), expected_branch)
    archive = _load_archive(archive_id) if archive_id is not None else _latest_archive_for_key(record["checkout_key"])
    if archive is None:
        raise RuntimeError("Cleanup requires a prior checkout archive")
    if archive["checkout_key"] != record["checkout_key"]:
        raise RuntimeError("Archive does not belong to this checkout")
    if archive["cleaned_at_unix"] is not None:
        raise RuntimeError("Checkout archive has already been cleaned")
    if archive["head"] != record.get("head") or archive["branch"] != record.get("branch"):
        raise RuntimeError("Checkout no longer matches its archived recovery refs")
    now = _now()
    archive_age_seconds = max(0, now - int(archive["created_at_unix"]))
    if archive_age_seconds < CHECKOUT_CLEANUP_GRACE_SECONDS:
        raise RuntimeError(
            "Checkout cleanup grace has not elapsed: "
            f"age={archive_age_seconds} required={CHECKOUT_CLEANUP_GRACE_SECONDS}"
        )
    owner = _owner(owner_id)
    retention = _retention_records([record["checkout_key"]]).get(record["checkout_key"])
    retention_active = bool(retention and retention["retention_until_unix"] > now)
    if retention_active and retention["owner_id"] != owner:
        raise PermissionError("Active checkout retention is owned by another owner")
    verified_refs = _verify_recovery_refs(top_level, archive["recovery_refs"])
    if not all(item["present"] for item in verified_refs):
        raise RuntimeError("Checkout recovery refs are missing or mismatched")
    coordination = _linked_checkout_coordination(
        checkout,
        top_level,
        common_dir,
        owner_id=owner,
        include_processes=True,
        include_tasks=True,
        include_resources=True,
    )
    command = ["git", "-C", str(top_level), "worktree", "remove", str(checkout)]
    body = {
        "schema_version": 1,
        "operation": "checkout-cleanup",
        "repo": str(top_level),
        "git_common_dir": str(common_dir),
        "checkout_path": str(checkout),
        "checkout_key": record["checkout_key"],
        "archive_id": archive["archive_id"],
        "owner_id": owner,
        "head": record.get("head"),
        "branch": record.get("branch"),
        "status": status,
        "retention": retention,
        "retention_active": retention_active,
        "archive_age_seconds": archive_age_seconds,
        "archive_grace_seconds": CHECKOUT_CLEANUP_GRACE_SECONDS,
        "recovery_refs": verified_refs,
        "coordination": coordination,
        "command": command,
        "safe_to_apply": not coordination["blocking"],
        "rollback": {
            "available": True,
            "command": ["git", "-C", str(top_level), "worktree", "add", str(checkout), archive["recovery_refs"][0]["ref"]],
            "branch_preserved": archive["branch"] is not None,
        },
    }
    return {**body, "plan_sha256": _sha256_json(body)}


def _persist_dry_run(plan: dict[str, Any]) -> dict[str, Any]:
    plan_id = uuid.uuid4().hex[:24]
    created = _now()
    expires = created + DRY_RUN_TTL_SECONDS
    with _database() as connection:
        connection.execute(
            """
            INSERT INTO dry_runs(
                plan_id, archive_id, checkout_key, owner_id, plan_sha256,
                plan_json, created_at_unix, expires_at_unix, applied_at_unix
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                plan_id,
                plan["archive_id"],
                plan["checkout_key"],
                plan["owner_id"],
                plan["plan_sha256"],
                _canonical_json(plan),
                created,
                expires,
            ),
        )
        connection.commit()
    return {"plan_id": plan_id, "created_at_unix": created, "expires_at_unix": expires}


def _load_dry_run(plan_id: str) -> dict[str, Any]:
    identifier = _validate_plan_id(plan_id)
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM dry_runs WHERE plan_id=?",
            (identifier,),
        ).fetchone()
    if row is None:
        raise ValueError(f"Unknown checkout cleanup dry-run: {identifier}")
    return dict(row)


@mcp.tool(name="grabowski_checkout_cleanup", annotations=MUTATING)
def grabowski_checkout_cleanup(
    repo: str,
    checkout_path: str,
    owner_id: str,
    dry_run: bool = True,
    archive_id: str | None = None,
    expected_head: str | None = None,
    expected_branch: str | None = None,
    plan_id: str | None = None,
    expected_plan_sha256: str | None = None,
    confirmation: str = "",
) -> dict[str, Any]:
    """Plan or apply cleanup for one archived linked checkout; apply requires a prior dry run."""
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    if not isinstance(dry_run, bool):
        raise ValueError("dry_run must be boolean")
    repo_path = _resolve_repo(repo)
    checkout = _safe_path(checkout_path, must_exist=True)
    _reject_evidence_checkout(checkout)
    owner = _owner(owner_id)
    archive = _validate_archive_id(archive_id) if archive_id is not None else None
    if dry_run:
        plan = _cleanup_plan(
            repo_path=repo_path,
            checkout=checkout,
            owner_id=owner,
            archive_id=archive,
            expected_head=expected_head,
            expected_branch=expected_branch,
        )
        persisted = _persist_dry_run(plan)
        audit = {
            "timestamp_unix": _now(),
            "operation": "checkout-cleanup-dry-run",
            "plan_id": persisted["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "archive_id": plan["archive_id"],
            "checkout_key": plan["checkout_key"],
            "repo": plan["repo"],
            "checkout_path": plan["checkout_path"],
            "owner_id": owner,
            "safe_to_apply": plan["safe_to_apply"],
            "blocking_counts": plan["coordination"]["blocking_counts"],
        }
        base._append_audit(audit)
        return {"dry_run": True, "plan": plan, "dry_run_record": persisted, "audit": audit}

    if confirmation != "remove-linked-checkout":
        raise ValueError("confirmation must be exactly 'remove-linked-checkout'")
    if plan_id is None or expected_plan_sha256 is None:
        raise ValueError("plan_id and expected_plan_sha256 are required when dry_run is false")
    stored = _load_dry_run(plan_id)
    expected_hash = _validate_sha256(expected_plan_sha256, "expected_plan_sha256")
    if stored["owner_id"] != owner:
        raise PermissionError("Cleanup dry-run is owned by another owner")
    if stored["plan_sha256"] != expected_hash:
        raise RuntimeError("Cleanup dry-run hash precondition failed")
    if stored["applied_at_unix"] is not None:
        raise RuntimeError("Cleanup dry-run was already applied")
    if stored["expires_at_unix"] <= _now():
        raise RuntimeError("Cleanup dry-run has expired")
    stored_plan = json.loads(stored["plan_json"])
    current_plan = _cleanup_plan(
        repo_path=repo_path,
        checkout=checkout,
        owner_id=owner,
        archive_id=stored["archive_id"],
        expected_head=stored_plan["head"],
        expected_branch=stored_plan["branch"],
    )
    if current_plan["plan_sha256"] != expected_hash:
        raise RuntimeError("Cleanup dry-run is stale; rerun dry_run first")
    if not current_plan["safe_to_apply"]:
        _require_no_blockers(current_plan["coordination"])
    retention_until_unix = _now() + DRY_RUN_TTL_SECONDS
    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=Path(current_plan["git_common_dir"]),
        checkout_path=checkout,
        purpose="apply linked checkout cleanup",
        retention_until_unix=retention_until_unix,
        metadata={
            "plan_id": plan_id,
            "archive_id": stored["archive_id"],
            "checkout_path": str(checkout),
        },
    )
    result = _git_mutate(
        Path(current_plan["repo"]),
        ["worktree", "remove", str(checkout)],
        timeout_seconds=120,
    )
    applied = _now()
    with _database() as connection:
        connection.execute(
            "UPDATE dry_runs SET applied_at_unix=? WHERE plan_id=?",
            (applied, plan_id),
        )
        connection.execute(
            """
            UPDATE archives
            SET cleaned_at_unix=?, cleanup_plan_id=?
            WHERE archive_id=?
            """,
            (applied, plan_id, stored["archive_id"]),
        )
        connection.commit()
    lease_release = _release_checkout_resources(lease)
    audit = {
        "timestamp_unix": applied,
        "operation": "checkout-cleanup-apply",
        "plan_id": plan_id,
        "plan_sha256": expected_hash,
        "archive_id": stored["archive_id"],
        "checkout_key": current_plan["checkout_key"],
        "repo": current_plan["repo"],
        "checkout_path": str(checkout),
        "owner_id": owner,
        "branch_preserved": True,
        "recovery_refs": current_plan["recovery_refs"],
        "resource_keys": [item["resource_key"] for item in lease["leases"]],
        "result": result,
        "rollback": current_plan["rollback"],
    }
    base._append_audit(audit)
    return {
        "dry_run": False,
        "applied_at_unix": applied,
        "plan": current_plan,
        "lease": lease,
        "lease_release": lease_release,
        "result": result,
        "audit": audit,
    }

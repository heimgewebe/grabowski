from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
import urllib.parse
import uuid
from typing import Any, Iterable, Mapping

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
OWNER_HANDOFF_PREVIEW_TTL_SECONDS = 5 * 60
OWNER_HANDOFF_CONFIRMATION = "align-checkout-owner-bindings"
BINDING_IDENTITY_REBIND_PREVIEW_TTL_SECONDS = 5 * 60
BINDING_IDENTITY_REBIND_CONFIRMATION = "rebind-checkout-lifecycle-identity"
MAX_RETENTION_SECONDS = 365 * 24 * 60 * 60
# Cleanup is deliberately delayed so recovery evidence has one full day to surface.
CHECKOUT_CLEANUP_GRACE_SECONDS = 24 * 60 * 60
CLEANUP_PLAN_SCHEMA_VERSION = 2
CLEANUP_PLAN_HASH_EXCLUDED_FIELDS = ("archive_age_seconds",)
ACTIVE_CHECKOUT_LIMIT_ENV = "GRABOWSKI_MAX_ACTIVE_CHECKOUTS_PER_REPO"
DEFAULT_MAX_ACTIVE_CHECKOUTS_PER_REPO = 16
MIN_CONFIGURABLE_ACTIVE_CHECKOUTS_PER_REPO = 16
MAX_CONFIGURABLE_ACTIVE_CHECKOUTS_PER_REPO = 256
ACTIVE_CHECKOUT_LIMITING_REASON = "configured-per-repository-active-checkout-cap"
MAX_COMPLETED_RETAINED_CHECKOUTS_PER_REPO = 4
LIFECYCLE_PHASES = frozenset(
    {"active", "completed_retained", "archived", "externally_terminal_missing"}
)
TERMINAL_RECONCILIATION_SCHEMA_VERSION = 1
TERMINAL_RECONCILIATION_PREVIEW_TTL_SECONDS = 15 * 60
TERMINAL_RECONCILIATION_CONFIRMATION = "record-external-terminal-missing"
TERMINAL_EVIDENCE_SOURCE_KINDS = frozenset({"bureau_task", "operator_obligation", "thread_focus", "github_issue", "work_lane"})
ARTIFACT_CLASS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
SOURCE_KIND_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
SOURCE_ID_RE = re.compile(r"[^\x00-\x1f\x7f]{1,256}\Z")
OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
ARCHIVE_ID_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
PLAN_ID_RE = re.compile(r"[0-9a-f]{24}\Z")
DEFAULT_GIT_READ_TIMEOUT_SECONDS = 30.0
MIN_GIT_READ_TIMEOUT_SECONDS = 0.1
MAX_GIT_READ_TIMEOUT_SECONDS = 30.0
MAX_INVENTORY_PROBE_ERRORS = 32
MAX_ACTIVE_CAPACITY_PATH_OBSERVATIONS = 64


def _configured_active_checkout_limit(
    environment: Mapping[str, str] | None = None,
) -> int:
    source = os.environ if environment is None else environment
    raw = source.get(ACTIVE_CHECKOUT_LIMIT_ENV)
    if raw is None:
        return DEFAULT_MAX_ACTIVE_CHECKOUTS_PER_REPO
    if (
        not isinstance(raw, str)
        or not raw
        or raw != raw.strip()
        or re.fullmatch(r"[0-9]+", raw) is None
    ):
        raise ValueError(
            f"{ACTIVE_CHECKOUT_LIMIT_ENV} must be a canonical positive integer"
        )
    value = int(raw)
    if not (
        MIN_CONFIGURABLE_ACTIVE_CHECKOUTS_PER_REPO
        <= value
        <= MAX_CONFIGURABLE_ACTIVE_CHECKOUTS_PER_REPO
    ):
        raise ValueError(
            f"{ACTIVE_CHECKOUT_LIMIT_ENV} must be between "
            f"{MIN_CONFIGURABLE_ACTIVE_CHECKOUTS_PER_REPO} and "
            f"{MAX_CONFIGURABLE_ACTIVE_CHECKOUTS_PER_REPO}"
        )
    return value


MAX_ACTIVE_CHECKOUTS_PER_REPO = _configured_active_checkout_limit()


def _git_timeout_seconds(value: int | float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not MIN_GIT_READ_TIMEOUT_SECONDS
        <= float(value)
        <= MAX_GIT_READ_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "git_timeout_seconds must be a finite number between "
            f"{MIN_GIT_READ_TIMEOUT_SECONDS:g} and "
            f"{MAX_GIT_READ_TIMEOUT_SECONDS:g}"
        )
    return float(value)


def _observation_budget_seconds(value: int | float | None) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.1 <= float(value) <= 120.0
    ):
        raise ValueError(
            "observation_budget_seconds must be null or a finite number "
            "between 0.1 and 120"
        )
    return float(value)


def _max_inventory_worktrees(value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1000:
        raise ValueError("max_worktrees must be null or an integer between 1 and 1000")
    return value


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
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    timeout_value = _git_timeout_seconds(timeout_seconds)
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_value,
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


def _git_common_dir(
    repo: Path,
    *,
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
) -> Path:
    raw = _git_read(
        repo,
        ["rev-parse", "--git-common-dir"],
        timeout_seconds=timeout_seconds,
    ).stdout.strip()
    path = Path(raw)
    if not path.is_absolute():
        path = repo / path
    return path.resolve(strict=True)


def _git_top_level(
    repo: Path,
    *,
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
) -> Path:
    raw = _git_read(
        repo,
        ["rev-parse", "--show-toplevel"],
        timeout_seconds=timeout_seconds,
    ).stdout.strip()
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
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS terminal_reconciliations (
            checkout_key TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            binding_before_sha256 TEXT NOT NULL,
            retention_sha256 TEXT NOT NULL,
            source_evidence_json TEXT NOT NULL,
            source_evidence_sha256 TEXT NOT NULL,
            preview_sha256 TEXT NOT NULL,
            preview_created_at_unix INTEGER NOT NULL,
            applied_at_unix INTEGER NOT NULL,
            receipt_json TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL
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


def _active_lifecycle_consumes_capacity(
    lifecycle: sqlite3.Row,
    *,
    now: int,
) -> bool:
    """Return whether an active lifecycle binding reserves creation capacity.

    Active creation capacity is a time-bounded concurrency gate.  Retention
    expiry releases only that global slot; it does not terminalize, archive,
    delete, adopt, or authorize reuse of the checkout path or branch.
    """
    return int(lifecycle["retention_until_unix"]) > now


def _active_creation_count(
    connection: sqlite3.Connection,
    *,
    repo_common_dir: Path,
    exclude_checkout_key: str,
    now: int,
) -> int:
    """Count active bindings with an effective retention-based capacity lease."""
    rows = connection.execute(
        """
        SELECT retention_until_unix
        FROM lifecycle_bindings
        WHERE repo_common_dir=? AND phase='active' AND checkout_key<>?
        """,
        (str(repo_common_dir), exclude_checkout_key),
    ).fetchall()
    return sum(1 for row in rows if int(row["retention_until_unix"]) > now)


def _active_capacity_projection_from_connection(
    connection: sqlite3.Connection,
    *,
    repo_common_dir: Path,
    now: int,
    max_path_observations: int = MAX_ACTIVE_CAPACITY_PATH_OBSERVATIONS,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Project exact slot use plus bounded, non-authorizing path telemetry."""
    if (
        isinstance(max_path_observations, bool)
        or not isinstance(max_path_observations, int)
        or not 0 <= max_path_observations <= MAX_ACTIVE_CAPACITY_PATH_OBSERVATIONS
    ):
        raise ValueError(
            "max_path_observations must be between 0 and "
            f"{MAX_ACTIVE_CAPACITY_PATH_OBSERVATIONS}"
        )
    rows = connection.execute(
        """
        SELECT checkout_path, retention_until_unix
        FROM lifecycle_bindings
        WHERE repo_common_dir=? AND phase='active'
        ORDER BY checkout_path ASC
        """,
        (str(repo_common_dir),),
    ).fetchall()
    unexpired = sum(
        1 for row in rows if int(row["retention_until_unix"]) > now
    )
    expired_rows = [
        row for row in rows if int(row["retention_until_unix"]) <= now
    ]
    expired_present = 0
    expired_missing = 0
    expired_unobservable = 0
    path_observations_attempted = 0
    for row in expired_rows:
        if path_observations_attempted >= max_path_observations:
            break
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            break
        path_observations_attempted += 1
        try:
            Path(str(row["checkout_path"])).lstat()
        except FileNotFoundError:
            expired_missing += 1
        except OSError:
            expired_unobservable += 1
        else:
            expired_present += 1
    classified_expired = (
        expired_present + expired_missing + expired_unobservable
    )
    expired_unclassified = len(expired_rows) - classified_expired
    classification_complete = expired_unclassified == 0
    limit = _phase_limit("active")
    used = unexpired
    does_not_establish = [
        "checkout_terminality",
        "checkout_cleanup_eligibility",
        "checkout_path_reuse_authority",
        "branch_reuse_authority",
        "dirty_state_safety",
    ]
    if not classification_complete:
        does_not_establish.append("complete_expired_path_presence")
    return {
        "available": True,
        "configured_limit": limit,
        "effective_capacity": limit,
        "used": used,
        "free": max(0, limit - used),
        "saturated": used >= limit,
        "limiting_reason": (
            ACTIVE_CHECKOUT_LIMITING_REASON if used >= limit else None
        ),
        "raw_active_rows": len(rows),
        "unexpired_active_rows": unexpired,
        "expired_active_rows": len(expired_rows),
        "expired_present_active_rows": expired_present,
        "expired_missing_active_rows": expired_missing,
        "expired_unobservable_active_rows": expired_unobservable,
        "expired_unclassified_active_rows": expired_unclassified,
        "path_classification_complete": classification_complete,
        "path_observations_attempted": path_observations_attempted,
        "path_observation_limit": max_path_observations,
        "capacity_semantics": "unexpired_active_retention",
        "does_not_establish": does_not_establish,
    }


def _unavailable_active_capacity_projection() -> dict[str, Any]:
    return {
        "available": False,
        "configured_limit": _phase_limit("active"),
        "effective_capacity": _phase_limit("active"),
        "used": None,
        "free": None,
        "saturated": None,
        "limiting_reason": None,
        "raw_active_rows": None,
        "unexpired_active_rows": None,
        "expired_active_rows": None,
        "expired_present_active_rows": None,
        "expired_missing_active_rows": None,
        "expired_unobservable_active_rows": None,
        "expired_unclassified_active_rows": None,
        "path_classification_complete": False,
        "path_observations_attempted": 0,
        "path_observation_limit": None,
        "capacity_semantics": "unexpired_active_retention",
        "does_not_establish": [
            "absence_of_active_bindings",
            "checkout_terminality",
            "checkout_cleanup_eligibility",
            "checkout_path_reuse_authority",
            "branch_reuse_authority",
            "dirty_state_safety",
            "complete_expired_path_presence",
        ],
    }


def _active_capacity_projection(
    repo_common_dir: Path,
    *,
    now: int,
    max_path_observations: int = MAX_ACTIVE_CAPACITY_PATH_OBSERVATIONS,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Read one repository's active capacity without creating state on absence."""
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        return _unavailable_active_capacity_projection()
    try:
        return _active_capacity_projection_from_connection(
            connection,
            repo_common_dir=repo_common_dir,
            now=now,
            max_path_observations=max_path_observations,
            deadline_monotonic=deadline_monotonic,
        )
    except sqlite3.OperationalError:
        return _unavailable_active_capacity_projection()
    finally:
        connection.close()


def active_capacity_projection(repo: Path) -> dict[str, Any]:
    """Return current per-repository active creation capacity read-only."""
    resolved_repo = repo.expanduser().resolve(strict=True)
    common_dir = _git_common_dir(resolved_repo)
    return _active_capacity_projection(common_dir, now=_now())


def _canonical_worktree_repo_path(
    repo: Path, *, expected_common_dir: Path
) -> Path:
    """Return Git's primary worktree path for one exact repository common-dir."""
    resolved_repo = _safe_path(repo, must_exist=True)
    # For the standard primary-worktree layout, the common-dir itself already
    # identifies the canonical worktree.  Bind that structural shortcut with an
    # independent Git common-dir readback; never use the caller path as fallback.
    if (
        expected_common_dir.name == ".git"
        and resolved_repo == expected_common_dir.parent
    ):
        if _git_common_dir(resolved_repo) != expected_common_dir:
            raise RuntimeError(
                "Primary repository path does not match the expected Git common-dir"
            )
        return resolved_repo
    _, observed_common_dir, records = _worktree_records(resolved_repo)
    if observed_common_dir != expected_common_dir:
        raise RuntimeError(
            "Repository common-dir does not match the checkout lifecycle binding"
        )
    canonical_paths = {
        str(record.get("repo_path"))
        for record in records
        if isinstance(record.get("repo_path"), str) and record.get("repo_path")
    }
    if len(canonical_paths) != 1:
        raise RuntimeError(
            "Git worktree inventory does not expose one canonical repository path"
        )
    canonical = _safe_path(next(iter(canonical_paths)), must_exist=True)
    if _git_common_dir(canonical) != observed_common_dir:
        raise RuntimeError(
            "Canonical repository path does not match the observed Git common-dir"
        )
    return canonical


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
    if source_kind not in TERMINAL_EVIDENCE_SOURCE_KINDS:
        raise ValueError(
            f"source_kind={source_kind} has no immutable terminal evidence observer; "
            "managed checkout creation requires an evidence-bearing source"
        )
    artifact = _artifact_class(artifact_class)
    until = _retention_until(retention_until_unix)
    common_dir = _safe_path(repo_common_dir, must_exist=True)
    requested_repo = _resolve_repo(repo_path)
    canonical_repo = _canonical_worktree_repo_path(
        requested_repo, expected_common_dir=common_dir
    )
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
            if (
                existing["repo_common_dir"] != str(common_dir)
                or existing["checkout_path"] != str(checkout)
            ):
                raise RuntimeError("Checkout lifecycle repository identity binding conflicts")
            if existing["repo_path"] != str(canonical_repo):
                raise RuntimeError(
                    "Checkout lifecycle repo_path drift requires identity rebind"
                )
        count = _active_creation_count(
            connection,
            repo_common_dir=common_dir,
            exclude_checkout_key=checkout_key,
            now=now,
        )
        limit = _phase_limit("active")
        existing_consumes_capacity = (
            existing is not None
            and _active_lifecycle_consumes_capacity(existing, now=now)
        )
        if count >= limit and not existing_consumes_capacity:
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
                str(canonical_repo),
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
        over_threshold = count >= limit
        # Completed-retained is preservation state, not active creation
        # capacity.  Its count threshold is therefore advisory hygiene
        # pressure only; a terminal transition must never stay active solely
        # because retained evidence already reached that threshold.
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
        "enforcement": "advisory_hygiene_threshold",
        "over_threshold_before_transition": over_threshold,
    }
    return public


def _mark_checkout_archived_in_connection(
    connection: sqlite3.Connection,
    checkout_key: str,
    owner_id: str,
    archived_at: int,
    expected_head: str,
    expected_branch: str | None,
) -> dict[str, Any] | None:
    owner = _owner(owner_id)
    head = _validate_git_object_id(expected_head, "expected_head")
    branch = _expected_branch(expected_branch)
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
        SET phase='archived', expected_head=?, expected_branch=?,
            terminal_at_unix=COALESCE(terminal_at_unix, ?),
            archived_at_unix=?, updated_at_unix=?
        WHERE checkout_key=? AND owner_id=?
        """,
        (head, branch, archived_at, archived_at, archived_at, checkout_key, owner),
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
    expected_head: str,
    expected_branch: str | None,
) -> dict[str, Any] | None:
    with _database() as connection:
        connection.execute("BEGIN IMMEDIATE")
        lifecycle = _mark_checkout_archived_in_connection(
            connection,
            checkout_key,
            owner_id,
            archived_at,
            expected_head,
            expected_branch,
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


def _archive_supersession_ids(connection: sqlite3.Connection) -> set[str]:
    try:
        rows = connection.execute(
            "SELECT archive_id FROM checkout_identity_archive_supersessions"
        ).fetchall()
    except sqlite3.OperationalError:
        return set()
    return {
        str(row["archive_id"])
        for row in rows
        if isinstance(row["archive_id"], str) and row["archive_id"]
    }


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
            SELECT * FROM archives
            WHERE checkout_key IN ({','.join('?' for _ in wanted)})
            ORDER BY checkout_key, created_at_unix DESC, archive_id DESC
            """,
            wanted,
        ).fetchall()
        superseded = _archive_supersession_ids(connection)
    except sqlite3.OperationalError:
        return {}
    finally:
        connection.close()
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["archive_id"] in superseded or row["checkout_key"] in latest:
            continue
        latest[row["checkout_key"]] = _archive_public(row)
    return latest


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
        rows = connection.execute(
            """
            SELECT * FROM archives
            WHERE checkout_key=? AND cleaned_at_unix IS NULL
            ORDER BY created_at_unix DESC, archive_id DESC
            """,
            (checkout_key,),
        ).fetchall()
        superseded = _archive_supersession_ids(connection)
    row = next((candidate for candidate in rows if candidate["archive_id"] not in superseded), None)
    return None if row is None else _archive_public(row)


def _upsert_retention_in_connection(
    connection: sqlite3.Connection,
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
    now: int | None = None,
) -> dict[str, Any]:
    owner = _owner(owner_id)
    retain_purpose = _purpose(purpose)
    until = _retention_until(retention_until_unix)
    observed_now = _now() if now is None else now
    existing = connection.execute(
        "SELECT * FROM retention WHERE checkout_key=?",
        (checkout_key,),
    ).fetchone()
    if (
        existing is not None
        and existing["retention_until_unix"] > observed_now
        and existing["owner_id"] != owner
    ):
        raise PermissionError("Active checkout retention is owned by another owner")
    created_at = observed_now if existing is None else existing["created_at_unix"]
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
            observed_now,
        ),
    )
    row = connection.execute(
        "SELECT * FROM retention WHERE checkout_key=?",
        (checkout_key,),
    ).fetchone()
    assert row is not None
    return _retention_public(row)


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
    with _database() as connection:
        retention = _upsert_retention_in_connection(
            connection,
            checkout_key=checkout_key,
            repo_common_dir=repo_common_dir,
            repo_path=repo_path,
            checkout_path=checkout_path,
            owner_id=owner_id,
            purpose=purpose,
            retention_until_unix=retention_until_unix,
            expected_head=expected_head,
            expected_branch=expected_branch,
        )
        connection.commit()
    return retention


def _lease_ttl(retention_until_unix: int) -> int:
    remaining = max(resources.MIN_TTL_SECONDS, retention_until_unix - _now())
    return min(resources.MAX_TTL_SECONDS, remaining)


def _checkout_resource_keys(
    repo_common_dir: Path,
    checkout_path: Path,
    *,
    repo_path: Path | None = None,
    branch: str | None = None,
) -> list[str]:
    """Return exact checkout, Git-metadata and optional branch serialization claims."""
    keys = [
        resources.normalize_resource_key(f"path:{checkout_path}"),
        resources.normalize_resource_key(f"path:{repo_common_dir}"),
    ]
    if repo_path is not None and isinstance(branch, str) and branch:
        keys.append(
            resources.normalize_resource_key(f"repo:{repo_path}:branch:{branch}")
        )
    return keys


def _acquire_checkout_resources(
    *,
    owner_id: str,
    repo_common_dir: Path,
    checkout_path: Path,
    purpose: str,
    retention_until_unix: int,
    metadata: dict[str, Any],
    repo_path: Path | None = None,
    branch: str | None = None,
) -> dict[str, Any]:
    durable_owner = _owner(owner_id)
    lease_owner = f"checkout-op:{uuid.uuid4().hex[:20]}"
    keys = _checkout_resource_keys(
        repo_common_dir,
        checkout_path,
        repo_path=repo_path,
        branch=branch,
    )
    bureau_keys = resources.bureau_leases.bureau_resource_keys(keys)
    bureau_key_set = set(bureau_keys)
    non_bureau_keys = [key for key in keys if key not in bureau_key_set]
    groups = [group for group in (bureau_keys, non_bureau_keys) if group]
    lease_metadata = {
        **metadata,
        "durable_owner_id": durable_owner,
        "git_common_dir": str(repo_common_dir),
    }
    acquisitions: list[dict[str, Any]] = []
    acquired_keys: list[str] = []
    try:
        for group in groups:
            acquired = resources.acquire_resources(
                lease_owner,
                group,
                purpose=purpose,
                ttl_seconds=OPERATION_LEASE_TTL_SECONDS,
                metadata=lease_metadata,
            )
            acquisitions.append(acquired)
            acquired_keys.extend(item["resource_key"] for item in acquired["leases"])
    except Exception:
        if acquired_keys:
            resources.release_resources(lease_owner, acquired_keys)
        raise
    return {
        "owner_id": lease_owner,
        "leases": [
            item
            for acquisition in acquisitions
            for item in acquisition["leases"]
        ],
        "acquisitions": acquisitions,
        "resource_classes": {
            "bureau": bureau_keys,
            "non_bureau": non_bureau_keys,
        },
    }


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


def _worktree_records(
    repo: Path,
    *,
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
) -> tuple[Path, Path, list[dict[str, Any]]]:
    timeout_value = _git_timeout_seconds(timeout_seconds)
    top_level = _git_top_level(repo, timeout_seconds=timeout_value)
    common_dir = _git_common_dir(repo, timeout_seconds=timeout_value)
    completed = _git_read(
        repo,
        ["worktree", "list", "--porcelain"],
        timeout_seconds=timeout_value,
    )
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
            "repo_path": str(main_path),
            "head": raw.get("head"),
            "branch": raw.get("branch"),
            "branch_ref": raw.get("branch_ref"),
            "detached": bool(raw.get("detached")),
            "bare": bool(raw.get("bare")),
            "prunable": bool(raw.get("prunable")),
            "prunable_reason": raw.get("prunable_reason"),
            "is_main": checkout_path == main_path,
            "is_linked": checkout_path != main_path,
        }
        records.append(record)
    return top_level, common_dir, sorted(records, key=lambda item: item["path"])


def observe_worktree_records(
    repo: str | Path,
    *,
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Expose canonical Git worktree records under one server-owned timeout."""
    repo_path = _resolve_repo(str(repo))
    top_level, common_dir, records = _worktree_records(
        repo_path,
        timeout_seconds=timeout_seconds,
    )
    return {
        "top_level": str(top_level),
        "repo_common_dir": str(common_dir),
        "worktrees": [dict(record) for record in records],
        "read_only": True,
    }


def _worktree_status(
    record: dict[str, Any],
    *,
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    path = Path(record["path"])
    if record.get("prunable") or not path.exists():
        return {
            "returncode": None,
            "dirty": None,
            "entry_count": None,
            "untracked_count": None,
            "error": "worktree is missing or prunable",
        }
    try:
        completed = _git_read(
            path,
            ["status", "--porcelain=v1", "--untracked-files=all"],
            check=False,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "returncode": None,
            "dirty": None,
            "entry_count": None,
            "untracked_count": None,
            "error": "git status timed out",
        }
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


def _github_repository_slug_from_remote_url(value: str) -> str | None:
    """Return owner/repository only for one strict GitHub SSH/HTTPS URL."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text != value.strip("\r\n") or "\x00" in text:
        return None
    if text.startswith("git@github.com:"):
        path = text.removeprefix("git@github.com:")
    else:
        try:
            parsed = urllib.parse.urlsplit(text)
            port = parsed.port
        except ValueError:
            return None
        if parsed.query or parsed.fragment or port not in {None, 22}:
            return None
        if parsed.scheme == "https":
            if (
                parsed.hostname != "github.com"
                or parsed.username is not None
                or parsed.password is not None
                or port is not None
            ):
                return None
        elif parsed.scheme == "ssh":
            if (
                parsed.hostname != "github.com"
                or parsed.username != "git"
                or parsed.password is not None
            ):
                return None
        else:
            return None
        path = parsed.path.lstrip("/")
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or "%" in path or "\\" in path:
        return None
    parts = path.split("/")
    if len(parts) != 2:
        return None
    if any(
        part in {".", ".."}
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", part) is None
        for part in parts
    ):
        return None
    return f"{parts[0]}/{parts[1]}"


def _github_pull_ref_secured_observation(
    repo: Path,
    *,
    branch: Any,
    head: str,
    timeout_seconds: int | float,
) -> dict[str, Any]:
    """Verify an exact merged GitHub PR head without trusting Git remote helpers."""
    if (
        not isinstance(branch, str)
        or not branch
        or branch != branch.strip()
        or branch.startswith("-")
        or len(branch.encode("utf-8")) > 1024
        or any(ord(character) < 32 or ord(character) == 127 for character in branch)
    ):
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": None,
        }
    try:
        origin = _git_read(
            repo,
            ["config", "--get-all", "remote.origin.url"],
            check=False,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": "origin identity query timed out",
        }
    if origin.returncode not in {0, 1}:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": (origin.stderr or origin.stdout).strip() or "origin identity query failed",
        }
    urls = [line.strip() for line in origin.stdout.splitlines() if line.strip()]
    if not urls:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": None,
        }
    if len(urls) != 1:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": "origin remote identity is ambiguous",
        }
    github_repo = _github_repository_slug_from_remote_url(urls[0])
    if github_repo is None:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": None,
        }

    timeout_value = _git_timeout_seconds(timeout_seconds)
    deadline = time.monotonic() + timeout_value

    def github_read(arguments: list[str]) -> dict[str, Any] | None:
        remaining = deadline - time.monotonic()
        if remaining < 1.0:
            return None
        return operator._run(
            ["gh", *arguments],
            cwd=repo,
            timeout_seconds=max(1, min(30, int(remaining))),
            max_output_bytes=64 * 1024,
        )

    listed = github_read(
        [
            "pr",
            "list",
            "--repo",
            f"github.com/{github_repo}",
            "--state",
            "merged",
            "--head",
            branch,
            "--limit",
            "20",
            "--json",
            "number,state,headRefName,headRefOid",
        ]
    )
    if listed is None or listed.get("timed_out") is True:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": "GitHub pull request query timed out",
        }
    if listed.get("returncode") != 0 or listed.get("stdout_truncated"):
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": str(listed.get("stderr") or listed.get("stdout") or "GitHub pull request query failed")[:256],
        }
    try:
        payload = json.loads(str(listed.get("stdout") or ""))
    except json.JSONDecodeError:
        payload = None
    if not isinstance(payload, list):
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": "GitHub pull request query returned invalid JSON",
        }
    matches = sorted(
        (
            item
            for item in payload
            if isinstance(item, dict)
            and item.get("state") == "MERGED"
            and item.get("headRefName") == branch
            and isinstance(item.get("headRefOid"), str)
            and GIT_OBJECT_RE.fullmatch(str(item["headRefOid"])) is not None
            and isinstance(item.get("number"), int)
            and not isinstance(item.get("number"), bool)
            and int(item["number"]) > 0
        ),
        key=lambda item: int(item["number"]),
        reverse=True,
    )
    if not matches:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": None,
        }
    # Branch names can be reused across many merged PRs. Preserve the bounded
    # verification budget while guaranteeing that exact head matches are tried
    # before ancestry-only candidates.
    exact_matches = [item for item in matches if item.get("headRefOid") == head]
    ancestor_candidates = [item for item in matches if item.get("headRefOid") != head]
    candidates = [*exact_matches, *ancestor_candidates][:4]

    last_error: str | None = None
    for item in candidates:
        number = int(item["number"])
        remote_ref = f"refs/pull/{number}/head"
        verified = github_read(
            [
                "api",
                "--hostname",
                "github.com",
                f"repos/{github_repo}/git/ref/pull/{number}/head",
                "--jq",
                ".object.sha",
            ]
        )
        if verified is None or verified.get("timed_out") is True:
            last_error = "GitHub pull head ref query timed out"
            break
        if verified.get("returncode") != 0 or verified.get("stdout_truncated"):
            last_error = str(
                verified.get("stderr")
                or verified.get("stdout")
                or "GitHub pull head ref query failed"
            )[:256]
            continue
        remote_head = str(verified.get("stdout") or "").strip()
        if remote_head != item.get("headRefOid"):
            last_error = "GitHub pull head ref differs from merged PR metadata"
            continue
        if remote_head == head:
            return {
                "remote_secured": True,
                "remote_secured_refs": [f"github:{github_repo}:{remote_ref}"],
                "remote_secured_relation": "exact_merged_pull_head",
                "remote_secured_head": remote_head,
                "error": None,
            }
        compared = github_read(
            [
                "api",
                "--hostname",
                "github.com",
                f"repos/{github_repo}/compare/{head}...{remote_head}",
                "--jq",
                "{status:.status,merge_base_sha:.merge_base_commit.sha}",
            ]
        )
        if compared is None or compared.get("timed_out") is True:
            last_error = "GitHub pull head ancestry query timed out"
            break
        if compared.get("returncode") != 0 or compared.get("stdout_truncated"):
            last_error = str(
                compared.get("stderr")
                or compared.get("stdout")
                or "GitHub pull head ancestry query failed"
            )[:256]
            continue
        try:
            ancestry = json.loads(str(compared.get("stdout") or ""))
        except json.JSONDecodeError:
            ancestry = None
        if (
            isinstance(ancestry, dict)
            and ancestry.get("status") == "ahead"
            and ancestry.get("merge_base_sha") == head
        ):
            return {
                "remote_secured": True,
                "remote_secured_refs": [f"github:{github_repo}:{remote_ref}"],
                "remote_secured_relation": "ancestor_of_merged_pull_head",
                "remote_secured_head": remote_head,
                "error": None,
            }
    return {
        "remote_secured": False,
        "remote_secured_refs": [],
        "error": last_error,
    }


def _remote_secured_observation(
    record: dict[str, Any],
    *,
    timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
    verify_github_pull_ref: bool = False,
) -> dict[str, Any]:
    """Observe durable remote evidence for the exact checkout head.

    Local remote-tracking refs remain the bounded fast path. Cleanup may opt in
    to a GitHub PR-head verification when a squash-merged source branch is no
    longer represented by a local remote-tracking ref. No fetch is performed.
    """
    path = Path(record["path"])
    head = record.get("head")
    if (
        record.get("prunable")
        or not path.exists()
        or not isinstance(head, str)
        or GIT_OBJECT_RE.fullmatch(head) is None
    ):
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": "checkout head is missing or unobservable",
        }
    # Prefer the shared repository common directory for remote-tracking visibility.
    repo_for_refs = Path(record.get("repo_path") or path)
    try:
        completed = _git_read(
            repo_for_refs,
            [
                "for-each-ref",
                "--format=%(refname)",
                f"--contains={head}",
                "refs/remotes",
            ],
            check=False,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": "remote ref query timed out",
        }
    if completed.returncode != 0:
        return {
            "remote_secured": False,
            "remote_secured_refs": [],
            "error": (completed.stderr or completed.stdout).strip() or "remote ref query failed",
        }
    refs = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip().startswith("refs/remotes/")
    ][:32]
    if refs or not verify_github_pull_ref:
        return {
            "remote_secured": bool(refs),
            "remote_secured_refs": sorted(refs),
            "error": None,
        }
    return _github_pull_ref_secured_observation(
        repo_for_refs,
        branch=record.get("branch"),
        head=head,
        timeout_seconds=timeout_seconds,
    )


def _read_resource_leases() -> list[dict[str, Any]]:
    connection = _readonly_connection(resources.RESOURCE_DB)
    if connection is None:
        return []
    try:
        resources._begin_resource_lease_projection_read(connection)
        rows = connection.execute(
            "SELECT * FROM leases WHERE expires_at_unix>? ORDER BY resource_key",
            (_now(),),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        raise RuntimeError("Resource lease projection is unavailable") from exc
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


def _task_records(
    paths: list[Path],
    *,
    resource_paths: list[Path] | None = None,
    exact_resource_keys: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Match task CWDs narrowly while retaining explicit resource-scope overlap."""
    try:
        connection = _readonly_connection(tasks.TASK_DB)
    except sqlite3.Error as exc:
        raise RuntimeError("Task inventory projection is unavailable") from exc
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
    except sqlite3.Error as exc:
        raise RuntimeError("Task inventory projection is unavailable") from exc
    finally:
        connection.close()
    effective_resource_paths = paths if resource_paths is None else resource_paths
    effective_exact_resource_keys = frozenset(
        str(item) for item in exact_resource_keys
    )
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
                    (
                        _resource_related(key, effective_resource_paths)
                        or key in effective_exact_resource_keys
                    )
                    for key in resource_keys
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


def _process_systemd_units(entry: Path) -> list[str]:
    try:
        content = (entry / "cgroup").read_text(
            encoding="utf-8", errors="strict"
        )
    except (OSError, UnicodeDecodeError):
        return []
    if len(content.encode("utf-8")) > 16 * 1024:
        return []
    units: set[str] = set()
    for line in content.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        for segment in fields[2].split("/"):
            if (
                len(segment.encode("utf-8")) <= 256
                and re.fullmatch(r"[A-Za-z0-9_.@:-]+\.(?:service|scope)", segment)
                is not None
            ):
                units.add(segment)
    return sorted(units)


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
        record: dict[str, Any] = {
            "pid": int(entry.name),
            "cwd": str(cwd),
            "command": command,
        }
        systemd_units = _process_systemd_units(entry)
        if systemd_units:
            record["systemd_units"] = systemd_units
        records.append(record)
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
    branch: str | None = None,
    owner_id: str | None = None,
    include_processes: bool = True,
    include_tasks: bool = True,
    include_resources: bool = True,
    ignored_lease_owner_ids: Iterable[str] = (),
) -> dict[str, Any]:
    if owner_id is not None:
        _owner(owner_id)
    ignored_owners = {_owner(item) for item in ignored_lease_owner_ids}
    branch_resource_key = (
        f"repo:{repo_path}:branch:{branch}" if isinstance(branch, str) and branch else None
    )
    resource_blockers: list[dict[str, Any]] = []
    if include_resources:
        for lease in _read_resource_leases():
            if lease["owner_id"] in ignored_owners:
                continue
            resource_key = lease["resource_key"]
            if not (
                _resource_related(resource_key, [checkout_path, repo_common_dir])
                or (branch_resource_key is not None and resource_key == branch_resource_key)
            ):
                continue
            lease = {**lease, "blocking": True}
            resource_blockers.append(lease)
    task_blockers = (
        _task_records(
            [checkout_path],
            resource_paths=[checkout_path, repo_common_dir],
            exact_resource_keys=(
                () if branch_resource_key is None else (branch_resource_key,)
            ),
        )
        if include_tasks
        else []
    )
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


def _binding_consistency(
    record: dict[str, Any],
    lifecycle: dict[str, Any],
    *,
    exists: bool,
) -> dict[str, Any]:
    """Validate one durable managed binding without granting lifecycle effects."""
    binding = lifecycle.get("binding")
    retention = lifecycle.get("retention")
    archive = lifecycle.get("latest_archive")
    if not isinstance(binding, dict):
        return {
            "present": False,
            "phase": None,
            "consistent": True,
            "drift_reasons": [],
        }

    reasons: list[str] = []
    phase = binding.get("phase")
    if phase not in LIFECYCLE_PHASES:
        reasons.append("binding-phase-unsupported")
    expected_identity = {
        "checkout_key": record.get("checkout_key"),
        "repo_common_dir": record.get("repo_common_dir"),
        "repo_path": record.get("repo_path"),
        "checkout_path": record.get("path"),
        "expected_branch": record.get("branch"),
    }
    for field, expected in expected_identity.items():
        if binding.get(field) != expected:
            reasons.append(f"binding-{field.replace('_', '-')}-mismatch")
    if (record.get("prunable") or not exists) and phase != "externally_terminal_missing":
        reasons.append("bound-checkout-missing-or-prunable")

    if not isinstance(retention, dict):
        reasons.append("binding-retention-missing")
    else:
        retention_identity = {
            "checkout_key": record.get("checkout_key"),
            "repo_common_dir": record.get("repo_common_dir"),
            "repo_path": record.get("repo_path"),
            "checkout_path": record.get("path"),
            "expected_branch": record.get("branch"),
        }
        for field, expected in retention_identity.items():
            if retention.get(field) != expected:
                reasons.append(f"retention-{field.replace('_', '-')}-mismatch")
        if retention.get("owner_id") != binding.get("owner_id"):
            reasons.append("binding-retention-owner-mismatch")
        if retention.get("expected_head") != binding.get("expected_head"):
            reasons.append("binding-retention-head-mismatch")

    if phase == "active":
        if binding.get("terminal_at_unix") is not None:
            reasons.append("active-binding-has-terminal-timestamp")
        if binding.get("archived_at_unix") is not None:
            reasons.append("active-binding-has-archive-timestamp")
        if isinstance(archive, dict) and archive.get("cleaned_at_unix") is None:
            reasons.append("active-binding-has-open-archive")
    elif phase == "completed_retained":
        if binding.get("expected_head") != record.get("head"):
            reasons.append("terminal-binding-head-mismatch")
        if not isinstance(binding.get("terminal_at_unix"), int):
            reasons.append("completed-retained-terminal-timestamp-missing")
        if binding.get("archived_at_unix") is not None:
            reasons.append("completed-retained-has-archive-timestamp")
        if isinstance(archive, dict) and archive.get("cleaned_at_unix") is None:
            reasons.append("completed-retained-has-open-archive")
    elif phase == "archived":
        if binding.get("expected_head") != record.get("head"):
            reasons.append("terminal-binding-head-mismatch")
        if not isinstance(binding.get("archived_at_unix"), int):
            reasons.append("archived-timestamp-missing")
        if not _archive_matches_checkout(record, lifecycle):
            reasons.append("archived-binding-without-matching-open-archive")
        elif archive.get("owner_id") != binding.get("owner_id"):
            reasons.append("binding-archive-owner-mismatch")
    elif phase == "externally_terminal_missing":
        if not isinstance(binding.get("expected_head"), str):
            reasons.append("external-terminal-head-missing")
        if not isinstance(binding.get("terminal_at_unix"), int):
            reasons.append("external-terminal-timestamp-missing")
        if binding.get("archived_at_unix") is not None:
            reasons.append("external-terminal-has-archive-timestamp")
        if exists and not record.get("prunable"):
            reasons.append("external-terminal-checkout-reappeared")
        if isinstance(archive, dict) and archive.get("cleaned_at_unix") is None:
            reasons.append("external-terminal-has-open-archive")

    return {
        "present": True,
        "phase": phase if isinstance(phase, str) else None,
        "consistent": not reasons,
        "drift_reasons": sorted(set(reasons)),
    }


def _checkout_lifecycle_decision(
    record: dict[str, Any],
    status: dict[str, Any],
    lifecycle: dict[str, Any],
    coordination: dict[str, Any],
    *,
    exists: bool,
    now: int,
    remote_secured: bool | None = None,
) -> dict[str, Any]:
    """Classify one checkout without authorizing cleanup by classification alone."""
    retention = lifecycle.get("retention")
    archive = lifecycle.get("latest_archive")
    binding = _binding_consistency(record, lifecycle, exists=exists)
    binding_present = bool(binding["present"])
    binding_phase = binding["phase"]
    binding_consistent = bool(binding["consistent"])
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
    process_count = 0
    processes = coordination.get("processes")
    if isinstance(processes, list):
        process_count = len(processes)
    reasons: list[str] = []
    cleanup_candidate = False
    requires_cleanup_dry_run = False
    remote_is_secured = bool(remote_secured)

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
        if binding_phase == "externally_terminal_missing" and binding_consistent:
            state = "externally_terminal_missing"
            hygiene_mark = "terminal"
            next_step = "no_archive_or_cleanup_without_separate_recovery_contract"
            reasons.append(
                "missing managed checkout is terminal only by a receipt-bound external source decision"
            )
        else:
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
        if blocking:
            reasons.append(
                "dirty checkout has real resource coordination overlap and is coordination-blocking"
            )
        else:
            reasons.append(
                "dirty checkout is visible hygiene; dirty state is never deleted or cleaned"
            )
    elif status["dirty"] is not False:
        state = "unobservable"
        hygiene_mark = "unknown"
        next_step = "repair_status_observability_before_lifecycle_action"
        reasons.append("git status could not prove whether the checkout is clean")
    elif binding_present and not binding_consistent:
        state = "managed_lifecycle_drift"
        hygiene_mark = "unknown"
        next_step = "reconcile_managed_lifecycle_binding_before_archive_or_cleanup"
        reasons.extend(binding["drift_reasons"])
    elif binding_phase == "active":
        if retention_is_active:
            state = "retained"
            hygiene_mark = "retained"
            next_step = "wait_for_retention_or_owner_review_before_archive"
            reasons.append("consistent active managed binding has effective retention")
        else:
            state = "managed_active_attention"
            hygiene_mark = "unknown"
            next_step = "reconcile_active_binding_retention_or_terminal_truth"
            reasons.append("active managed binding has no effective retention")
    elif binding_phase == "completed_retained":
        if blocking:
            state = "completed_retained_blocked"
            hygiene_mark = "retained"
            next_step = "resolve_coordination_blockers_before_archive"
            reasons.append("terminal-retained checkout still has active coordination")
        else:
            state = "completed_retained"
            hygiene_mark = "retained"
            next_step = "archive_completed_retained_checkout_after_external_revalidation"
            reasons.append("terminal managed checkout is retained and not yet archived")
    elif binding_phase == "archived":
        if archive_present and blocking:
            state = "archived_blocked"
            hygiene_mark = "archived"
            next_step = "resolve_coordination_blockers_before_cleanup_dry_run"
            reasons.append("checkout is archived but active coordination blocks cleanup")
        elif retention_is_active:
            state = "archived_retained"
            hygiene_mark = "archived"
            next_step = "wait_for_retention_before_cleanup_dry_run"
            reasons.append("archived checkout remains protected by active retention")
        elif not archive_grace_elapsed:
            state = "archived_grace"
            hygiene_mark = "archived"
            next_step = "wait_for_archive_grace_before_cleanup_dry_run"
            reasons.append("archived checkout is still inside the recovery grace period")
        elif not remote_is_secured:
            state = "archived_not_remote_secured"
            hygiene_mark = "archived"
            next_step = "secure_checkout_head_on_remote_before_cleanup_dry_run"
            reasons.append(
                "clean managed archive exists but head is not present on local remote-tracking refs"
            )
        else:
            state = "cleanup_candidate"
            hygiene_mark = "obsolete"
            cleanup_candidate = True
            requires_cleanup_dry_run = True
            next_step = "run_checkout_cleanup_dry_run_before_apply"
            reasons.append(
                "terminal clean remote-secured checkout is lease/process/retention-free with mature archive"
            )
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
    elif archive_present and blocking:
        state = "archived_blocked"
        hygiene_mark = "archived"
        next_step = "resolve_coordination_blockers_before_cleanup_dry_run"
        reasons.append("checkout is archived but active coordination blocks cleanup")
    elif archive_present and retention_is_active:
        state = "archived_retained"
        hygiene_mark = "archived"
        next_step = "wait_for_retention_before_cleanup_dry_run"
        reasons.append("archived checkout remains protected by active retention")
    elif archive_present and not archive_grace_elapsed:
        state = "archived_grace"
        hygiene_mark = "archived"
        next_step = "wait_for_archive_grace_before_cleanup_dry_run"
        reasons.append("archived checkout is still inside the recovery grace period")
    elif archive_present and not remote_is_secured:
        state = "archived_not_remote_secured"
        hygiene_mark = "archived"
        next_step = "secure_checkout_head_on_remote_before_cleanup_dry_run"
        reasons.append(
            "clean archive exists but head is not present on local remote-tracking refs"
        )
    elif archive_present:
        state = "cleanup_candidate"
        hygiene_mark = "obsolete"
        cleanup_candidate = True
        requires_cleanup_dry_run = True
        next_step = "run_checkout_cleanup_dry_run_before_apply"
        reasons.append(
            "terminal clean remote-secured checkout is lease/process/retention-free with mature archive"
        )
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

    # Cleanup is never authorized for dirty checkouts or while coordination remains.
    if cleanup_candidate and (
        status.get("dirty") is not False
        or blocking
        or retention_is_active
        or process_count > 0
        or not remote_is_secured
    ):
        cleanup_candidate = False
        requires_cleanup_dry_run = False

    return {
        "state": state,
        "hygiene_mark": hygiene_mark,
        "binding_present": binding_present,
        "binding_phase": binding_phase,
        "binding_consistent": binding_consistent,
        "binding_drift_reasons": binding["drift_reasons"],
        "retention_active": retention_is_active,
        "retention_owner_id": retention.get("owner_id") if isinstance(retention, dict) else None,
        "archive_present": archive_present,
        "archive_open": bool(archive_open),
        "archive_matches_checkout": bool(archive_matches),
        "archive_age_seconds": archive_age_seconds,
        "archive_grace_seconds": CHECKOUT_CLEANUP_GRACE_SECONDS,
        "archive_grace_elapsed": archive_grace_elapsed,
        "remote_secured": remote_is_secured,
        "coordination_blocking": blocking,
        "cleanup_candidate": cleanup_candidate,
        "requires_cleanup_dry_run": requires_cleanup_dry_run,
        "recommended_next_step": next_step,
        "reasons": reasons,
        "does_not_establish": [
            "permission_to_cleanup",
            "branch_is_obsolete",
            "safe_to_delete_branch",
            "terminal_external_work_truth_from_binding_alone",
            "permission_to_delete_dirty_state",
        ],
    }


def checkout_inventory(
    repo: str | Path,
    *,
    include_processes: bool = True,
    include_tasks: bool = True,
    include_resources: bool = True,
    git_timeout_seconds: int | float = DEFAULT_GIT_READ_TIMEOUT_SECONDS,
    observation_budget_seconds: int | float | None = None,
    max_worktrees: int | None = None,
) -> dict[str, Any]:
    git_timeout = _git_timeout_seconds(git_timeout_seconds)
    observation_budget = _observation_budget_seconds(
        observation_budget_seconds
    )
    worktree_limit = _max_inventory_worktrees(max_worktrees)
    bounded_observation = (
        observation_budget is not None or worktree_limit is not None
    )
    started_monotonic = time.monotonic()
    deadline_monotonic = (
        None
        if observation_budget is None
        else started_monotonic + observation_budget
    )

    repo_path = _resolve_repo(repo)
    top_level, common_dir, records = _worktree_records(
        repo_path,
        timeout_seconds=git_timeout,
    )
    keys = [record["checkout_key"] for record in records]
    retention = _retention_records(keys)
    bindings = _lifecycle_bindings(keys)
    archives = _latest_archives(keys)
    now = _now()
    active_capacity = _active_capacity_projection(
        common_dir,
        now=now,
        max_path_observations=(
            0 if bounded_observation else MAX_ACTIVE_CAPACITY_PATH_OBSERVATIONS
        ),
        deadline_monotonic=deadline_monotonic,
    )

    def observation_priority(record: dict[str, Any]) -> tuple[int, str]:
        key = str(record["checkout_key"])
        if record.get("is_main"):
            rank = 0
        elif key in bindings:
            rank = 1
        elif key in retention:
            rank = 2
        elif key in archives:
            rank = 3
        else:
            rank = 4
        return rank, str(record["path"])

    ordered_records = sorted(records, key=observation_priority)

    def remaining_git_timeout() -> float | None:
        if deadline_monotonic is None:
            return git_timeout
        remaining = deadline_monotonic - time.monotonic()
        if remaining < MIN_GIT_READ_TIMEOUT_SECONDS:
            return None
        return min(git_timeout, remaining)

    worktrees: list[dict[str, Any]] = []
    probe_errors: list[dict[str, Any]] = []
    omitted_worktree_count = 0
    attempted_worktree_count = 0
    for index, record in enumerate(ordered_records):
        if (
            worktree_limit is not None
            and attempted_worktree_count >= worktree_limit
        ) or (
            deadline_monotonic is not None
            and time.monotonic() >= deadline_monotonic
        ):
            omitted_worktree_count += len(ordered_records) - index
            break
        attempted_worktree_count += 1
        checkout_path = Path(record["path"])
        status_timeout = remaining_git_timeout()
        if status_timeout is None:
            omitted_worktree_count += len(ordered_records) - index
            break
        status = _worktree_status(
            record,
            timeout_seconds=status_timeout,
        )
        if bounded_observation and status.get("dirty") not in {True, False}:
            omitted_worktree_count += 1
            if len(probe_errors) < MAX_INVENTORY_PROBE_ERRORS:
                probe_errors.append(
                    {
                        "path": str(checkout_path),
                        "stage": "status",
                        "error": str(status.get("error") or "status unobservable")[:256],
                    }
                )
            continue
        if (
            deadline_monotonic is not None
            and time.monotonic() >= deadline_monotonic
        ):
            omitted_worktree_count += len(ordered_records) - index
            if len(probe_errors) < MAX_INVENTORY_PROBE_ERRORS:
                probe_errors.append(
                    {
                        "path": str(checkout_path),
                        "stage": "budget",
                        "error": "observation budget exhausted after status",
                    }
                )
            break
        coordination = _linked_checkout_coordination(
            checkout_path,
            top_level,
            common_dir,
            branch=record.get("branch"),
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
        remote_timeout = remaining_git_timeout()
        remote = (
            {
                "remote_secured": False,
                "remote_secured_refs": [],
                "error": "observation budget exhausted before remote ref query",
            }
            if remote_timeout is None
            else _remote_secured_observation(
                record,
                timeout_seconds=remote_timeout,
            )
        )
        if remote.get("error") and len(probe_errors) < MAX_INVENTORY_PROBE_ERRORS:
            probe_errors.append(
                {
                    "path": str(checkout_path),
                    "stage": "remote",
                    "error": str(remote["error"])[:256],
                }
            )
        decision = _checkout_lifecycle_decision(
            record,
            status,
            lifecycle,
            coordination,
            exists=exists,
            now=now,
            remote_secured=bool(remote.get("remote_secured")),
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
                "remote_secured": bool(remote.get("remote_secured")),
                "remote_secured_refs": list(remote.get("remote_secured_refs") or []),
            }
        )
    total_worktree_count = len(ordered_records)
    observed_worktree_count = len(worktrees)
    truncated = omitted_worktree_count > 0
    body = {
        "schema_version": 1,
        "repository": str(top_level),
        "requested_repo": str(repo_path),
        "git_common_dir": str(common_dir),
        "active_capacity": active_capacity,
        "worktrees": sorted(worktrees, key=lambda item: item["path"]),
        "truncated": truncated,
        "total_worktree_count": total_worktree_count,
        "observed_worktree_count": observed_worktree_count,
        "omitted_worktree_count": omitted_worktree_count,
        "probe_errors": probe_errors,
        "probe_errors_truncated": (
            omitted_worktree_count > len(probe_errors)
            and len(probe_errors) >= MAX_INVENTORY_PROBE_ERRORS
        ),
        "observation_contract": {
            "bounded": bounded_observation,
            "git_timeout_seconds": git_timeout,
            "observation_budget_seconds": observation_budget,
            "max_worktrees": worktree_limit,
            "attempted_worktree_count": attempted_worktree_count,
            "unobserved_worktrees_are_not_reported_clean": True,
        },
    }
    return {
        **body,
        "generated_at_unix": _now(),
        "inventory_sha256": _sha256_json(body),
    }


def _worktree_for_path(repo_path: Path, checkout_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    _top_level, common_dir, records = _worktree_records(repo_path)
    target = checkout_path.resolve(strict=True)
    for record in records:
        if Path(record["path"]).resolve(strict=False) == target:
            canonical_repo = _safe_path(str(record["repo_path"]), must_exist=True)
            return canonical_repo, common_dir, record
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


@mcp.tool(name="grabowski_checkout_binding_terminal_preview", annotations=READ_ONLY)
def grabowski_checkout_binding_terminal_preview(checkout_key: str) -> dict[str, Any]:
    """Preview an evidence-only terminal transition for one missing or safely retained managed checkout."""
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("github_cli")
    from grabowski_checkout_terminal_reconciliation import preview

    return preview(checkout_key)


@mcp.tool(name="grabowski_checkout_binding_terminal_apply", annotations=MUTATING)
def grabowski_checkout_binding_terminal_apply(
    checkout_key: str,
    owner_id: str,
    expected_preview_sha256: str,
    preview_created_at_unix: int,
    confirmation: str,
) -> dict[str, Any]:
    """CAS-apply one source-bound terminal state without archive or cleanup effects."""
    operator._require_operator_mutation("resource_lease")
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("github_cli")
    from grabowski_checkout_terminal_reconciliation import apply

    return apply(
        checkout_key,
        owner_id,
        expected_preview_sha256,
        preview_created_at_unix,
        confirmation,
    )



def _binding_identity_rebind_state(
    *,
    repo: str,
    checkout_path: str,
    owner_id: str,
    expected_head: str,
    expected_branch: str,
    observed_at_unix: int,
    ignored_lease_owner_ids: Iterable[str] = (),
) -> dict[str, Any]:
    owner = _owner(owner_id)
    head = _validate_git_object_id(expected_head, "expected_head")
    branch = _expected_branch(expected_branch)
    if branch is None:
        raise ValueError("checkout identity rebind requires a named branch")
    repo_path = _resolve_repo(repo)
    checkout = _safe_path(checkout_path, must_exist=True)
    _reject_evidence_checkout(checkout)
    _, common_dir, record = _worktree_for_path(repo_path, checkout)
    canonical_repo = _safe_path(str(record["repo_path"]), must_exist=True)
    if _git_common_dir(canonical_repo) != common_dir:
        raise RuntimeError(
            "Checkout canonical repository path does not match the Git common-dir"
        )
    status = _require_clean_linked(record)
    _require_expected(record, head, branch)
    coordination = _linked_checkout_coordination(
        checkout,
        canonical_repo,
        common_dir,
        branch=record.get("branch"),
        owner_id=owner,
        include_processes=True,
        include_tasks=True,
        include_resources=True,
        ignored_lease_owner_ids=ignored_lease_owner_ids,
    )
    _require_no_blockers(coordination)

    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        raise RuntimeError("Checkout lifecycle database is missing")
    try:
        lifecycle_row = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (record["checkout_key"],),
        ).fetchone()
        retention_row = connection.execute(
            "SELECT * FROM retention WHERE checkout_key=?",
            (record["checkout_key"],),
        ).fetchone()
        archive_row = connection.execute(
            "SELECT archive_id FROM archives WHERE checkout_key=? LIMIT 1",
            (record["checkout_key"],),
        ).fetchone()
    finally:
        connection.close()
    if lifecycle_row is None or retention_row is None:
        raise RuntimeError(
            "Checkout identity rebind requires lifecycle and retention rows"
        )
    lifecycle = _lifecycle_public(lifecycle_row)
    retention = _retention_public(retention_row)
    if lifecycle["owner_id"] != owner or retention["owner_id"] != owner:
        raise PermissionError(
            "Checkout identity rebind requires one unchanged owner"
        )
    if lifecycle["phase"] != "active":
        raise RuntimeError(
            "Checkout identity rebind is limited to active lifecycle bindings"
        )
    if archive_row is not None:
        raise RuntimeError(
            "Checkout identity rebind is unavailable after archive creation"
        )
    if retention["retention_until_unix"] <= observed_at_unix:
        raise RuntimeError("Checkout retention expired before identity rebind")
    if lifecycle["expected_head"] != retention["expected_head"]:
        raise RuntimeError(
            "Checkout lifecycle and retention recorded heads differ before identity rebind"
        )
    if lifecycle["expected_branch"] != retention["expected_branch"]:
        raise RuntimeError(
            "Checkout lifecycle and retention recorded branches differ before identity rebind"
        )

    static_identity = {
        "checkout_key": record["checkout_key"],
        "repo_common_dir": str(common_dir),
        "checkout_path": str(checkout),
    }
    for row_name, row in (("lifecycle", lifecycle), ("retention", retention)):
        for field, expected in static_identity.items():
            if row[field] != expected:
                raise RuntimeError(
                    f"Checkout {row_name} {field} changed before identity rebind"
                )

    consistency = _binding_consistency(
        record,
        {"binding": lifecycle, "retention": retention, "latest_archive": None},
        exists=True,
    )
    drift_reasons = consistency["drift_reasons"]
    branch_drift_reasons = [
        "binding-expected-branch-mismatch",
        "retention-expected-branch-mismatch",
    ]
    repo_path_drift_reasons = {
        "binding-repo-path-mismatch",
        "retention-repo-path-mismatch",
    }
    recorded_head = _validate_git_object_id(
        lifecycle["expected_head"], "recorded expected_head"
    )
    recorded_branch = lifecycle["expected_branch"]

    if drift_reasons == branch_drift_reasons:
        rebind_mode = "branch_rename"
        if recorded_branch == branch:
            raise RuntimeError(
                "Checkout identity rebind requires an observed branch rename"
            )
        lineage = _git_read(
            canonical_repo,
            ["merge-base", "--is-ancestor", recorded_head, head],
            check=False,
        )
        if lineage.returncode != 0:
            raise RuntimeError(
                "Checkout identity rebind current head does not descend from recorded head"
            )
        head_lineage = {
            "recorded_head": recorded_head,
            "current_head": head,
            "recorded_head_is_ancestor": True,
        }
    elif drift_reasons and set(drift_reasons).issubset(repo_path_drift_reasons):
        rebind_mode = "repo_path_canonicalization"
        if recorded_head != head or retention["expected_head"] != head:
            raise RuntimeError(
                "Checkout repo-path rebind requires unchanged recorded and current heads"
            )
        if recorded_branch != branch or retention["expected_branch"] != branch:
            raise RuntimeError(
                "Checkout repo-path rebind requires unchanged recorded and current branches"
            )
        for row_name, row in (("lifecycle", lifecycle), ("retention", retention)):
            stored_repo_path = row.get("repo_path")
            if not isinstance(stored_repo_path, str) or not stored_repo_path:
                raise RuntimeError(
                    f"Checkout {row_name} repo_path is invalid before identity rebind"
                )
            stored_repo = _resolve_repo(stored_repo_path)
            if _git_common_dir(stored_repo) != common_dir:
                raise RuntimeError(
                    f"Checkout {row_name} repo_path belongs to another Git common-dir"
                )
        head_lineage = {
            "recorded_head": recorded_head,
            "current_head": head,
            "recorded_head_is_ancestor": True,
        }
    else:
        raise RuntimeError(
            "Checkout identity rebind requires exactly one supported identity drift mode"
        )

    remote = _remote_secured_observation(
        record, verify_github_pull_ref=True
    )
    if remote.get("remote_secured") is not True:
        raise RuntimeError(
            "Checkout identity rebind requires the current head to be remote-secured"
        )
    material = {
        "schema_version": 1,
        "kind": "checkout_binding_identity_rebind_preview",
        "observed_at_unix": observed_at_unix,
        "expires_at_unix": observed_at_unix + BINDING_IDENTITY_REBIND_PREVIEW_TTL_SECONDS,
        "rebind_mode": rebind_mode,
        "checkout": {
            "checkout_key": record["checkout_key"],
            "repo_common_dir": str(common_dir),
            "repo_path": str(canonical_repo),
            "checkout_path": str(checkout),
            "head": head,
            "branch": branch,
            "dirty": status["dirty"],
            "entry_count": status["entry_count"],
        },
        "owner_id": owner,
        "lifecycle": lifecycle,
        "lifecycle_sha256": _sha256_json(lifecycle),
        "retention": retention,
        "retention_sha256": _sha256_json(retention),
        "allowed_drift_reasons": drift_reasons,
        "head_lineage": head_lineage,
        "remote": remote,
        "coordination": coordination,
        "target_identity": {
            "repo_path": str(canonical_repo),
            "expected_head": head,
            "expected_branch": branch,
        },
        "does_not_establish": [
            "permission_to_archive",
            "permission_to_cleanup",
            "permission_to_delete_checkout",
            "permission_to_delete_branch",
            "permission_to_change_checkout_branch",
            "permission_to_adopt_dirty_work",
            "permission_to_change_checkout_owner",
            "permission_to_change_git_history",
            "permission_to_move_checkout",
        ],
    }
    digest = _sha256_json(material)
    return {
        **material,
        "snapshot_sha256": digest,
        "confirmation": (
            f"{BINDING_IDENTITY_REBIND_CONFIRMATION}:{record['checkout_key']}:{digest}"
        ),
    }


def _binding_identity_rebind_state_for_key(
    checkout_key: str,
    *,
    observed_at_unix: int,
    ignored_lease_owner_ids: Iterable[str] = (),
) -> dict[str, Any]:
    key = _validate_sha256(checkout_key, "checkout_key")
    lifecycle = _lifecycle_bindings([key]).get(key)
    if not isinstance(lifecycle, dict):
        raise RuntimeError("Checkout identity rebind requires an active lifecycle binding")
    checkout_path = _safe_path(str(lifecycle["checkout_path"]), must_exist=True)
    repo_path = _resolve_repo(checkout_path)
    _, common_dir, record = _worktree_for_path(repo_path, checkout_path)
    if record["checkout_key"] != key:
        raise RuntimeError("Checkout identity rebind key no longer matches Git worktree")
    if lifecycle["repo_common_dir"] != str(common_dir):
        raise RuntimeError(
            "Checkout lifecycle common-dir no longer matches the observed worktree"
        )
    branch = record.get("branch")
    if not isinstance(branch, str) or not branch:
        raise RuntimeError("Checkout identity rebind requires a named current branch")
    head = record.get("head")
    if not isinstance(head, str):
        raise RuntimeError("Checkout identity rebind requires a current head")
    return _binding_identity_rebind_state(
        repo=str(checkout_path),
        checkout_path=str(checkout_path),
        owner_id=str(lifecycle["owner_id"]),
        expected_head=head,
        expected_branch=branch,
        observed_at_unix=observed_at_unix,
        ignored_lease_owner_ids=ignored_lease_owner_ids,
    )


@mcp.tool(name="grabowski_checkout_binding_identity_rebind_preview", annotations=READ_ONLY)
def grabowski_checkout_binding_identity_rebind_preview(
    checkout_key: str,
) -> dict[str, Any]:
    """Preview one safe lifecycle identity rebind for an existing renamed checkout."""
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("github_cli")
    return _binding_identity_rebind_state_for_key(
        checkout_key, observed_at_unix=_now()
    )


def _binding_identity_rebind_apply(
    *,
    checkout_key: str,
    owner_id: str,
    expected_snapshot_sha256: str,
    preview_created_at_unix: int,
    confirmation: str,
) -> dict[str, Any]:
    operator._require_operator_mutation("git_cli")
    owner = _owner(owner_id)
    snapshot_sha256 = _validate_sha256(
        expected_snapshot_sha256, "expected_snapshot_sha256"
    )
    if isinstance(preview_created_at_unix, bool) or not isinstance(
        preview_created_at_unix, int
    ):
        raise ValueError("preview_created_at_unix must be an integer")
    now = _now()
    if not (
        preview_created_at_unix
        <= now
        <= preview_created_at_unix + BINDING_IDENTITY_REBIND_PREVIEW_TTL_SECONDS
    ):
        raise RuntimeError("Checkout identity rebind preview expired or is future-dated")
    planned = _binding_identity_rebind_state_for_key(
        checkout_key, observed_at_unix=preview_created_at_unix
    )
    if planned["owner_id"] != owner:
        raise PermissionError("Checkout identity rebind owner mismatch")
    if planned["snapshot_sha256"] != snapshot_sha256:
        raise RuntimeError("Checkout identity rebind snapshot changed")
    if confirmation != planned["confirmation"]:
        raise PermissionError("Checkout identity rebind confirmation mismatch")
    if int(planned["retention"]["retention_until_unix"]) <= _now():
        raise RuntimeError("Checkout retention expired before identity rebind apply")

    checkout = Path(planned["checkout"]["checkout_path"])
    canonical_repo = Path(planned["checkout"]["repo_path"])
    common_dir = Path(planned["checkout"]["repo_common_dir"])
    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=common_dir,
        checkout_path=checkout,
        purpose="atomically rebind checkout lifecycle identity",
        retention_until_unix=int(planned["retention"]["retention_until_unix"]),
        repo_path=canonical_repo,
        branch=planned["checkout"]["branch"],
        metadata={
            "checkout_key": planned["checkout"]["checkout_key"],
            "snapshot_sha256": snapshot_sha256,
            "rebind_mode": planned["rebind_mode"],
        },
    )
    result: dict[str, Any] | None = None
    try:
        current = _binding_identity_rebind_state_for_key(
            checkout_key,
            observed_at_unix=preview_created_at_unix,
            ignored_lease_owner_ids=[lease["owner_id"]],
        )
        if current["snapshot_sha256"] != snapshot_sha256:
            raise RuntimeError(
                "Checkout identity rebind snapshot changed after lease acquisition"
            )
        if current["rebind_mode"] != planned["rebind_mode"]:
            raise RuntimeError(
                "Checkout identity rebind mode changed after lease acquisition"
            )
        if int(current["retention"]["retention_until_unix"]) <= _now():
            raise RuntimeError(
                "Checkout retention expired after identity rebind lease acquisition"
            )
        applied_at = _now()
        target_repo_path = planned["target_identity"]["repo_path"]
        target_head = planned["target_identity"]["expected_head"]
        target_branch = planned["target_identity"]["expected_branch"]
        with _operation_lock(), _database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            lifecycle_row = connection.execute(
                "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
                (planned["checkout"]["checkout_key"],),
            ).fetchone()
            retention_row = connection.execute(
                "SELECT * FROM retention WHERE checkout_key=?",
                (planned["checkout"]["checkout_key"],),
            ).fetchone()
            if lifecycle_row is None or retention_row is None:
                raise RuntimeError("Checkout identity rebind state disappeared")
            lifecycle_before = _lifecycle_public(lifecycle_row)
            retention_before = _retention_public(retention_row)
            if (
                _sha256_json(lifecycle_before) != planned["lifecycle_sha256"]
                or _sha256_json(retention_before) != planned["retention_sha256"]
            ):
                raise RuntimeError(
                    "Checkout identity rebind database preimage changed"
                )
            if retention_before["retention_until_unix"] <= applied_at:
                raise RuntimeError(
                    "Checkout retention expired before identity rebind apply"
                )
            lifecycle_updated_at = max(
                applied_at, int(lifecycle_before["updated_at_unix"]) + 1
            )
            retention_updated_at = max(
                applied_at, int(retention_before["updated_at_unix"]) + 1
            )
            repo_path_mode = planned["rebind_mode"] == "repo_path_canonicalization"
            lifecycle_needs_update = (
                not repo_path_mode
                or lifecycle_before["repo_path"] != target_repo_path
            )
            retention_needs_update = (
                not repo_path_mode
                or retention_before["repo_path"] != target_repo_path
            )
            if lifecycle_needs_update:
                lifecycle_update = connection.execute(
                    "UPDATE lifecycle_bindings SET repo_path=?, expected_head=?, expected_branch=?, updated_at_unix=? "
                    "WHERE checkout_key=? AND owner_id=? AND phase='active' AND repo_path=? AND expected_head=? "
                    "AND expected_branch=? AND updated_at_unix=?",
                    (
                        target_repo_path,
                        target_head,
                        target_branch,
                        lifecycle_updated_at,
                        planned["checkout"]["checkout_key"],
                        owner,
                        lifecycle_before["repo_path"],
                        lifecycle_before["expected_head"],
                        lifecycle_before["expected_branch"],
                        lifecycle_before["updated_at_unix"],
                    ),
                )
                if lifecycle_update.rowcount != 1:
                    raise RuntimeError(
                        "Checkout lifecycle identity rebind lost its exact database binding"
                    )
            if retention_needs_update:
                retention_update = connection.execute(
                    "UPDATE retention SET repo_path=?, expected_head=?, expected_branch=?, updated_at_unix=? "
                    "WHERE checkout_key=? AND owner_id=? AND repo_path=? AND expected_head=? "
                    "AND expected_branch=? AND updated_at_unix=?",
                    (
                        target_repo_path,
                        target_head,
                        target_branch,
                        retention_updated_at,
                        planned["checkout"]["checkout_key"],
                        owner,
                        retention_before["repo_path"],
                        retention_before["expected_head"],
                        retention_before["expected_branch"],
                        retention_before["updated_at_unix"],
                    ),
                )
                if retention_update.rowcount != 1:
                    raise RuntimeError(
                        "Checkout retention identity rebind lost its exact database binding"
                    )
            connection.commit()
            lifecycle_after_row = connection.execute(
                "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
                (planned["checkout"]["checkout_key"],),
            ).fetchone()
            retention_after_row = connection.execute(
                "SELECT * FROM retention WHERE checkout_key=?",
                (planned["checkout"]["checkout_key"],),
            ).fetchone()
        if lifecycle_after_row is None or retention_after_row is None:
            raise RuntimeError("Checkout identity rebind post-state disappeared")
        lifecycle_after = _lifecycle_public(lifecycle_after_row)
        retention_after = _retention_public(retention_after_row)
        for row_name, row in (("lifecycle", lifecycle_after), ("retention", retention_after)):
            if (
                row["owner_id"] != owner
                or row["repo_path"] != target_repo_path
                or row["expected_head"] != target_head
                or row["expected_branch"] != target_branch
            ):
                raise RuntimeError(
                    f"Checkout {row_name} identity did not converge after rebind"
                )
        if lifecycle_after["phase"] != lifecycle_before["phase"]:
            raise RuntimeError("Checkout identity rebind changed lifecycle phase")
        if planned["rebind_mode"] == "branch_rename":
            effects = [
                "lifecycle_expected_identity_update",
                "retention_expected_identity_update",
            ]
        elif planned["rebind_mode"] == "repo_path_canonicalization":
            effects = []
            if lifecycle_before["repo_path"] != target_repo_path:
                effects.append("lifecycle_repo_path_update")
            if retention_before["repo_path"] != target_repo_path:
                effects.append("retention_repo_path_update")
            if not effects:
                raise RuntimeError("Checkout repo-path identity rebind had no bounded effect")
        else:
            raise RuntimeError("Checkout identity rebind mode is unsupported")
        audit = {
            "schema_version": 1,
            "kind": "checkout-binding-identity-rebind",
            "timestamp_unix": applied_at,
            "operation": "checkout-binding-identity-rebind",
            "checkout_key": planned["checkout"]["checkout_key"],
            "owner_id": owner,
            "rebind_mode": planned["rebind_mode"],
            "repo_common_dir": str(common_dir),
            "repo": str(canonical_repo),
            "repo_path": str(canonical_repo),
            "checkout_path": str(checkout),
            "before_repo_path": lifecycle_before["repo_path"],
            "after_repo_path": target_repo_path,
            "before_head": lifecycle_before["expected_head"],
            "before_branch": lifecycle_before["expected_branch"],
            "after_head": target_head,
            "after_branch": target_branch,
            "snapshot_sha256": snapshot_sha256,
            "remote_secured_refs": planned["remote"]["remote_secured_refs"],
            "effects": effects,
        }
        try:
            base._append_audit(audit)
        except Exception as exc:
            raise RuntimeError(
                "Checkout identity rebind audit failed after database update; readback required"
            ) from exc
        result = {
            "schema_version": 1,
            "kind": "checkout_binding_identity_rebind_result",
            "status": "applied",
            "snapshot_sha256": snapshot_sha256,
            "rebind_mode": planned["rebind_mode"],
            "target_identity": planned["target_identity"],
            "before": {
                "lifecycle": lifecycle_before,
                "retention": retention_before,
            },
            "after": {
                "lifecycle": lifecycle_after,
                "retention": retention_after,
            },
            "audit": audit,
            "lease": lease,
            "does_not_establish": planned["does_not_establish"],
        }
    finally:
        lease_release = _release_checkout_resources(lease)
    if result is None:
        raise RuntimeError("Checkout identity rebind produced no result")
    result["lease_release"] = lease_release
    return result


@mcp.tool(name="grabowski_checkout_binding_identity_rebind_apply", annotations=MUTATING)
def grabowski_checkout_binding_identity_rebind_apply(
    checkout_key: str,
    owner_id: str,
    expected_snapshot_sha256: str,
    preview_created_at_unix: int,
    confirmation: str,
) -> dict[str, Any]:
    """CAS-rebind lifecycle and retention identity after an exact safe preview."""
    operator._require_operator_mutation("resource_lease")
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("github_cli")
    return _binding_identity_rebind_apply(
        checkout_key=checkout_key,
        owner_id=owner_id,
        expected_snapshot_sha256=expected_snapshot_sha256,
        preview_created_at_unix=preview_created_at_unix,
        confirmation=confirmation,
    )


def _owner_handoff_state(
    *,
    repo: str,
    checkout_path: str,
    source_lifecycle_owner_id: str,
    source_retention_owner_id: str,
    target_owner_id: str,
    expected_head: str,
    expected_branch: str | None,
    observed_at_unix: int,
    ignored_lease_owner_ids: Iterable[str] = (),
) -> dict[str, Any]:
    lifecycle_owner = _owner(source_lifecycle_owner_id)
    retention_owner = _owner(source_retention_owner_id)
    target_owner = _owner(target_owner_id)
    if lifecycle_owner == retention_owner:
        raise RuntimeError("checkout owner handoff requires an existing owner mismatch")
    if target_owner != retention_owner:
        raise PermissionError("target owner must equal the current retention owner")
    head = _validate_git_object_id(expected_head, "expected_head")
    branch = _expected_branch(expected_branch)
    repo_path = _resolve_repo(repo)
    checkout = _safe_path(checkout_path, must_exist=True)
    _reject_evidence_checkout(checkout)
    top_level, common_dir, record = _worktree_for_path(repo_path, checkout)
    status = _require_clean_linked(record)
    _require_expected(record, head, branch)
    coordination = _linked_checkout_coordination(
        checkout,
        top_level,
        common_dir,
        branch=record.get("branch"),
        include_processes=True,
        include_tasks=True,
        include_resources=True,
        ignored_lease_owner_ids=ignored_lease_owner_ids,
    )
    _require_no_blockers(coordination)
    connection = _readonly_connection(CHECKOUT_DB)
    if connection is None:
        raise RuntimeError("Checkout lifecycle database is missing")
    try:
        lifecycle_row = connection.execute(
            "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
            (record["checkout_key"],),
        ).fetchone()
        retention_row = connection.execute(
            "SELECT * FROM retention WHERE checkout_key=?",
            (record["checkout_key"],),
        ).fetchone()
        archive_row = connection.execute(
            "SELECT archive_id FROM archives WHERE checkout_key=? LIMIT 1",
            (record["checkout_key"],),
        ).fetchone()
    finally:
        connection.close()
    if lifecycle_row is None or retention_row is None:
        raise RuntimeError("Checkout owner handoff requires lifecycle and retention rows")
    lifecycle = _lifecycle_public(lifecycle_row)
    retention = _retention_public(retention_row)
    if lifecycle["owner_id"] != lifecycle_owner:
        raise PermissionError("Checkout lifecycle source owner changed")
    if retention["owner_id"] != retention_owner:
        raise PermissionError("Checkout retention source owner changed")
    if lifecycle["phase"] != "completed_retained":
        raise RuntimeError("Checkout owner handoff is limited to completed-retained bindings")
    if archive_row is not None:
        raise RuntimeError("Checkout owner handoff is unavailable after archive creation")
    expected_identity = {
        "repo_common_dir": str(common_dir),
        "repo_path": str(top_level),
        "checkout_path": str(checkout),
        "expected_head": head,
        "expected_branch": branch,
    }
    for row_name, row in (("lifecycle", lifecycle), ("retention", retention)):
        for field, expected in expected_identity.items():
            if row[field] != expected:
                raise RuntimeError(f"Checkout {row_name} {field} changed before owner handoff")
    if retention["retention_until_unix"] <= observed_at_unix:
        raise RuntimeError("Checkout retention expired before owner handoff")
    consistency = _binding_consistency(
        record,
        {"binding": lifecycle, "retention": retention, "latest_archive": None},
        exists=True,
    )
    if consistency["drift_reasons"] != ["binding-retention-owner-mismatch"]:
        raise RuntimeError(
            "Checkout owner handoff requires exactly binding-retention-owner-mismatch drift"
        )
    material = {
        "schema_version": 1,
        "kind": "checkout_owner_handoff_preview",
        "observed_at_unix": observed_at_unix,
        "expires_at_unix": observed_at_unix + OWNER_HANDOFF_PREVIEW_TTL_SECONDS,
        "checkout": {
            "checkout_key": record["checkout_key"],
            "repo_common_dir": str(common_dir),
            "repo_path": str(top_level),
            "checkout_path": str(checkout),
            "head": record["head"],
            "branch": record.get("branch"),
            "dirty": status["dirty"],
            "entry_count": status["entry_count"],
        },
        "owners": {
            "source_lifecycle_owner_id": lifecycle_owner,
            "source_retention_owner_id": retention_owner,
            "target_owner_id": target_owner,
        },
        "lifecycle": lifecycle,
        "lifecycle_sha256": _sha256_json(lifecycle),
        "retention": retention,
        "retention_sha256": _sha256_json(retention),
        "allowed_drift_reasons": consistency["drift_reasons"],
        "coordination": coordination,
        "does_not_establish": [
            "permission_to_archive",
            "permission_to_cleanup",
            "permission_to_delete_checkout",
            "permission_to_delete_branch",
            "permission_to_adopt_dirty_work",
        ],
    }
    digest = _sha256_json(material)
    return {
        **material,
        "snapshot_sha256": digest,
        "confirmation": f"{OWNER_HANDOFF_CONFIRMATION}:{record['checkout_key']}:{digest}",
    }


def checkout_owner_handoff_preview(
    repo: str,
    checkout_path: str,
    source_lifecycle_owner_id: str,
    source_retention_owner_id: str,
    target_owner_id: str,
    expected_head: str,
    expected_branch: str | None = None,
) -> dict[str, Any]:
    operator._require_operator_capability("git_cli")
    return _owner_handoff_state(
        repo=repo,
        checkout_path=checkout_path,
        source_lifecycle_owner_id=source_lifecycle_owner_id,
        source_retention_owner_id=source_retention_owner_id,
        target_owner_id=target_owner_id,
        expected_head=expected_head,
        expected_branch=expected_branch,
        observed_at_unix=_now(),
    )


def checkout_owner_handoff_apply(
    repo: str,
    checkout_path: str,
    source_lifecycle_owner_id: str,
    source_retention_owner_id: str,
    target_owner_id: str,
    expected_head: str,
    expected_branch: str | None,
    expected_snapshot_sha256: str,
    preview_created_at_unix: int,
    confirmation: str,
) -> dict[str, Any]:
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    snapshot_sha256 = _validate_sha256(expected_snapshot_sha256, "expected_snapshot_sha256")
    if isinstance(preview_created_at_unix, bool) or not isinstance(preview_created_at_unix, int):
        raise ValueError("preview_created_at_unix must be an integer")
    now = _now()
    if not preview_created_at_unix <= now <= preview_created_at_unix + OWNER_HANDOFF_PREVIEW_TTL_SECONDS:
        raise RuntimeError("Checkout owner handoff preview expired or is future-dated")
    planned = _owner_handoff_state(
        repo=repo,
        checkout_path=checkout_path,
        source_lifecycle_owner_id=source_lifecycle_owner_id,
        source_retention_owner_id=source_retention_owner_id,
        target_owner_id=target_owner_id,
        expected_head=expected_head,
        expected_branch=expected_branch,
        observed_at_unix=preview_created_at_unix,
    )
    if planned["snapshot_sha256"] != snapshot_sha256:
        raise RuntimeError("Checkout owner handoff snapshot changed")
    if confirmation != planned["confirmation"]:
        raise PermissionError("Checkout owner handoff confirmation mismatch")
    checkout = Path(planned["checkout"]["checkout_path"])
    top_level = Path(planned["checkout"]["repo_path"])
    common_dir = Path(planned["checkout"]["repo_common_dir"])
    target_owner = planned["owners"]["target_owner_id"]
    lease = _acquire_checkout_resources(
        owner_id=target_owner,
        repo_common_dir=common_dir,
        checkout_path=checkout,
        purpose="atomically align checkout lifecycle ownership",
        retention_until_unix=int(planned["retention"]["retention_until_unix"]),
        repo_path=top_level,
        branch=planned["checkout"]["branch"],
        metadata={
            "checkout_key": planned["checkout"]["checkout_key"],
            "snapshot_sha256": snapshot_sha256,
        },
    )
    result: dict[str, Any] | None = None
    try:
        current = _owner_handoff_state(
            repo=repo,
            checkout_path=checkout_path,
            source_lifecycle_owner_id=source_lifecycle_owner_id,
            source_retention_owner_id=source_retention_owner_id,
            target_owner_id=target_owner_id,
            expected_head=expected_head,
            expected_branch=expected_branch,
            observed_at_unix=preview_created_at_unix,
            ignored_lease_owner_ids=[lease["owner_id"]],
        )
        if current["snapshot_sha256"] != snapshot_sha256:
            raise RuntimeError("Checkout owner handoff snapshot changed after lease acquisition")
        applied_at = _now()
        with _operation_lock(), _database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            lifecycle_row = connection.execute(
                "SELECT * FROM lifecycle_bindings WHERE checkout_key=?",
                (planned["checkout"]["checkout_key"],),
            ).fetchone()
            retention_row = connection.execute(
                "SELECT * FROM retention WHERE checkout_key=?",
                (planned["checkout"]["checkout_key"],),
            ).fetchone()
            if lifecycle_row is None or retention_row is None:
                raise RuntimeError("Checkout owner handoff state disappeared")
            lifecycle_before = _lifecycle_public(lifecycle_row)
            retention_before = _retention_public(retention_row)
            if (
                _sha256_json(lifecycle_before) != planned["lifecycle_sha256"]
                or _sha256_json(retention_before) != planned["retention_sha256"]
            ):
                raise RuntimeError("Checkout owner handoff database preimage changed")
            if retention_before["owner_id"] != target_owner:
                raise RuntimeError("Checkout retention owner changed before lifecycle owner handoff")
            lifecycle_updated_at = max(applied_at, int(lifecycle_before["updated_at_unix"]) + 1)
            lifecycle_update = connection.execute(
                "UPDATE lifecycle_bindings SET owner_id=?, updated_at_unix=? "
                "WHERE checkout_key=? AND owner_id=? AND updated_at_unix=?",
                (target_owner, lifecycle_updated_at, planned["checkout"]["checkout_key"], lifecycle_before["owner_id"], lifecycle_before["updated_at_unix"]),
            )
            if lifecycle_update.rowcount != 1:
                raise RuntimeError("Checkout lifecycle owner handoff lost its exact database binding")
            effects = ["lifecycle_owner_update"]
            connection.commit()
        lifecycle_after = _lifecycle_bindings([planned["checkout"]["checkout_key"]])[planned["checkout"]["checkout_key"]]
        retention_after = _retention_records([planned["checkout"]["checkout_key"]])[planned["checkout"]["checkout_key"]]
        if lifecycle_after["owner_id"] != target_owner or retention_after["owner_id"] != target_owner:
            raise RuntimeError("Checkout owner handoff post-state owner mismatch")
        audit = {
            "timestamp_unix": applied_at,
            "operation": "checkout-owner-handoff",
            "checkout_key": planned["checkout"]["checkout_key"],
            "repo": planned["checkout"]["repo_path"],
            "checkout_path": planned["checkout"]["checkout_path"],
            "head": planned["checkout"]["head"],
            "branch": planned["checkout"]["branch"],
            "source_lifecycle_owner_id": planned["owners"]["source_lifecycle_owner_id"],
            "source_retention_owner_id": planned["owners"]["source_retention_owner_id"],
            "target_owner_id": target_owner,
            "snapshot_sha256": snapshot_sha256,
            "effects": effects,
        }
        try:
            base._append_audit(audit)
        except Exception as exc:
            raise RuntimeError(
                "Checkout owner handoff audit failed after database update; readback required"
            ) from exc
        result = {
            "schema_version": 1,
            "kind": "checkout_owner_handoff_result",
            "status": "applied",
            "snapshot_sha256": snapshot_sha256,
            "before": {"lifecycle": lifecycle_before, "retention": retention_before},
            "after": {"lifecycle": lifecycle_after, "retention": retention_after},
            "audit": audit,
            "lease": lease,
            "does_not_establish": planned["does_not_establish"],
        }
    finally:
        lease_release = _release_checkout_resources(lease)
    if result is None:
        raise RuntimeError("Checkout owner handoff produced no result")
    result["lease_release"] = lease_release
    return result


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


def _terminal_detached_archive_transition(
    repo: Path,
    record: dict[str, Any],
    lifecycle: dict[str, Any],
) -> dict[str, Any]:
    expected_branch = lifecycle.get("expected_branch")
    if record.get("branch") is not None or not isinstance(expected_branch, str):
        raise RuntimeError("Checkout lifecycle branch changed before archive")
    if lifecycle.get("phase") not in {"active", "completed_retained"}:
        raise RuntimeError(
            "Detached checkout archive requires active or completed-retained lifecycle"
        )
    expected_head = _validate_git_object_id(
        lifecycle.get("expected_head"), "lifecycle expected_head"
    )
    current_head = _validate_git_object_id(record.get("head"), "checkout head")

    # Lazy import avoids a module cycle: terminal source readers use checkout helpers.
    import grabowski_checkout_terminal_sources as terminal_sources

    source_evidence = terminal_sources.source_terminal_evidence(lifecycle)
    branch_ref = f"refs/heads/{expected_branch}"
    branch_read = _git_read(
        repo,
        ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"],
        check=False,
    )
    if branch_read.returncode != 0:
        raise RuntimeError(
            "Detached checkout archive requires the bound lifecycle branch ref"
        )
    branch_head = _validate_git_object_id(
        branch_read.stdout.strip(), "lifecycle branch head"
    )

    bound_ancestry = _git_read(
        repo,
        ["merge-base", "--is-ancestor", expected_head, branch_head],
        check=False,
    )
    if bound_ancestry.returncode != 0:
        raise RuntimeError(
            "Lifecycle branch head does not descend from the bound checkout head"
        )
    detached_ancestry = _git_read(
        repo,
        ["merge-base", "--is-ancestor", branch_head, current_head],
        check=False,
    )
    if detached_ancestry.returncode != 0:
        raise RuntimeError(
            "Detached checkout head does not descend from the lifecycle branch head"
        )

    current_remote = _remote_secured_observation(
        record, verify_github_pull_ref=True
    )
    branch_remote = _remote_secured_observation(
        {**record, "head": branch_head, "branch": expected_branch},
        verify_github_pull_ref=True,
    )
    if current_remote.get("remote_secured") is not True:
        raise RuntimeError("Detached checkout head is not remotely secured")
    if branch_remote.get("remote_secured") is not True:
        raise RuntimeError("Lifecycle branch head is not remotely secured")

    core = {
        "schema_version": 1,
        "kind": "checkout_terminal_detached_archive_transition",
        "source_evidence": source_evidence,
        "expected_head": expected_head,
        "expected_branch": expected_branch,
        "branch_head": branch_head,
        "detached_head": current_head,
        "current_remote_secured_refs": current_remote.get(
            "remote_secured_refs", []
        ),
        "branch_remote_secured_refs": branch_remote.get(
            "remote_secured_refs", []
        ),
    }
    return {**core, "evidence_sha256": _sha256_json(core)}


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
    _require_retention_owner(record["checkout_key"], owner)
    lifecycle_before = _lifecycle_bindings([record["checkout_key"]]).get(
        record["checkout_key"]
    )
    if lifecycle_before is not None and lifecycle_before["owner_id"] != owner:
        raise PermissionError("Checkout lifecycle binding is owned by another owner")
    lease_branch = record.get("branch")
    if lease_branch is None and lifecycle_before is not None:
        lease_branch = lifecycle_before.get("expected_branch")
    coordination = _linked_checkout_coordination(
        checkout,
        top_level,
        common_dir,
        branch=lease_branch,
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
        repo_path=top_level,
        branch=lease_branch,
        metadata={
            "checkout_path": str(checkout),
            "repo": str(top_level),
            "head": expected_head,
            "branch": expected_branch,
        },
    )
    result: dict[str, Any] | None = None
    try:
        lifecycle = _lifecycle_bindings([record["checkout_key"]]).get(
            record["checkout_key"]
        )
        if lifecycle != lifecycle_before:
            raise RuntimeError("Checkout lifecycle binding changed during archive preflight")
        terminal_detached_transition = None
        if lifecycle is not None:
            if lifecycle["expected_branch"] != record.get("branch"):
                terminal_detached_transition = _terminal_detached_archive_transition(
                    top_level, record, lifecycle
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
            "terminal_detached_transition": terminal_detached_transition,
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
            retention = _upsert_retention_in_connection(
                connection,
                checkout_key=record["checkout_key"],
                repo_common_dir=common_dir,
                repo_path=top_level,
                checkout_path=checkout,
                owner_id=owner,
                purpose=archive_purpose,
                retention_until_unix=until,
                expected_head=expected_head,
                expected_branch=expected_branch,
                now=created,
            )
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
                expected_head,
                record.get("branch"),
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
            "terminal_detached_transition": terminal_detached_transition,
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
            "terminal_detached_transition": terminal_detached_transition,
        }
    finally:
        lease_release = _release_checkout_resources(lease)
    if result is None:
        raise RuntimeError("Checkout archive did not produce a result")
    result["lease_release"] = lease_release
    return result


def _cleanup_plan_sha256(body: dict[str, Any]) -> str:
    excluded = body.get("plan_hash_excludes")
    expected_excluded = list(CLEANUP_PLAN_HASH_EXCLUDED_FIELDS)
    if excluded != expected_excluded:
        raise RuntimeError("Checkout cleanup plan hash exclusions are invalid")
    if any(field not in body for field in CLEANUP_PLAN_HASH_EXCLUDED_FIELDS):
        raise RuntimeError("Checkout cleanup plan is missing an excluded observation field")
    authorization_material = {
        key: value
        for key, value in body.items()
        if key not in CLEANUP_PLAN_HASH_EXCLUDED_FIELDS
    }
    return _sha256_json(authorization_material)


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
    archive_created_at_unix = int(archive["created_at_unix"])
    archive_age_seconds = max(0, now - archive_created_at_unix)
    owner = _owner(owner_id)
    retention = _retention_records([record["checkout_key"]]).get(record["checkout_key"])
    retention_active = bool(retention and retention["retention_until_unix"] > now)
    retention_owner_matches = bool(retention and retention.get("owner_id") == owner)
    archive_grace_elapsed = archive_age_seconds >= CHECKOUT_CLEANUP_GRACE_SECONDS
    verified_refs = _verify_recovery_refs(top_level, archive["recovery_refs"])
    if not all(item["present"] for item in verified_refs):
        raise RuntimeError("Checkout recovery refs are missing or mismatched")
    coordination = _linked_checkout_coordination(
        checkout,
        top_level,
        common_dir,
        branch=record.get("branch"),
        owner_id=owner,
        include_processes=True,
        include_tasks=True,
        include_resources=True,
    )
    remote = _remote_secured_observation(record, verify_github_pull_ref=True)
    remote_secured = bool(remote.get("remote_secured"))
    dirty = status.get("dirty") is not False
    command = ["git", "-C", str(top_level), "worktree", "remove", str(checkout)]
    body = {
        "schema_version": CLEANUP_PLAN_SCHEMA_VERSION,
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
        "retention_owner_matches": retention_owner_matches,
        "archive_created_at_unix": archive_created_at_unix,
        "archive_age_seconds": archive_age_seconds,
        "archive_grace_seconds": CHECKOUT_CLEANUP_GRACE_SECONDS,
        "archive_grace_elapsed": archive_grace_elapsed,
        "remote_secured": remote_secured,
        "remote_secured_refs": list(remote.get("remote_secured_refs") or []),
        "cleanup_blockers": [
            reason
            for reason, blocked in (
                ("active_retention_not_elapsed", retention_active),
                ("archive_grace_not_elapsed", not archive_grace_elapsed),
                ("active_coordination", coordination["blocking"]),
                ("dirty_checkout", dirty),
                ("head_not_remote_secured", not remote_secured),
            )
            if blocked
        ],
        "plan_hash_excludes": list(CLEANUP_PLAN_HASH_EXCLUDED_FIELDS),
        "recovery_refs": verified_refs,
        "coordination": coordination,
        "command": command,
        "safe_to_apply": bool(
            not retention_active
            and archive_grace_elapsed
            and not coordination["blocking"]
            and not dirty
            and remote_secured
        ),
        "rollback": {
            "available": True,
            "command": ["git", "-C", str(top_level), "worktree", "add", str(checkout), archive["recovery_refs"][0]["ref"]],
            "branch_preserved": archive["branch"] is not None,
        },
    }
    return {**body, "plan_sha256": _cleanup_plan_sha256(body)}


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
    if current_plan["retention_active"]:
        raise RuntimeError("Active checkout retention has not elapsed")
    if not current_plan["archive_grace_elapsed"]:
        raise RuntimeError("Checkout archive grace period has not elapsed")
    if not current_plan["safe_to_apply"]:
        _require_no_blockers(current_plan["coordination"])
    retention_until_unix = _now() + DRY_RUN_TTL_SECONDS
    lease = _acquire_checkout_resources(
        owner_id=owner,
        repo_common_dir=Path(current_plan["git_common_dir"]),
        checkout_path=checkout,
        purpose="apply linked checkout cleanup",
        retention_until_unix=retention_until_unix,
        repo_path=Path(current_plan["repo"]),
        branch=current_plan.get("branch"),
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

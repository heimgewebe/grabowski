from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from typing import Any


SCHEMA_VERSION = 1
STATUS_KIND = "grabowski.operator_fence_status"
GRANT_KIND = "grabowski.operator_fence_grant"
BEGIN_KIND = "grabowski.operator_fence_begin"
SETTLEMENT_KIND = "grabowski.operator_fence_settlement"
ANCHOR_KIND = "grabowski.operator_fence_generation_anchor"
DATABASE_SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_RE = re.compile(r"[A-Za-z0-9._:@/-]+\Z")
MAX_OWNER_BYTES = 128
MAX_SESSION_BYTES = 256
MAX_REASON_BYTES = 192
MAX_OPERATION_BYTES = 256
MAX_RECONCILER_BYTES = 128
MIN_LEASE_SECONDS = 1
MAX_LEASE_SECONDS = 600
SESSION_KEY_BYTES = 32
MAX_ANCHOR_BYTES = 4096
SQLITE_BUSY_TIMEOUT_MS = 1000
FENCING_MARK_DOES_NOT_ESTABLISH = (
    "coordinator_authenticity",
    "transport_authenticity",
    "caller_authorization",
)
INSTANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
TERMINAL_OUTCOMES = frozenset({"effect_applied", "effect_not_applied"})
EFFECT_OUTCOMES = frozenset({*TERMINAL_OUTCOMES, "outcome_unknown"})


class OperatorFenceError(RuntimeError):
    pass


class OperatorFenceDenied(OperatorFenceError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _bounded_identity(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > maximum
        or IDENTITY_RE.fullmatch(normalized) is None
    ):
        raise ValueError(f"{field} must be a bounded operator identity")
    return normalized


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("generation must be a positive integer")
    return value


def _lease_seconds(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < MIN_LEASE_SECONDS
        or value > MAX_LEASE_SECONDS
    ):
        raise ValueError(
            f"lease_seconds must be between {MIN_LEASE_SECONDS} and "
            f"{MAX_LEASE_SECONDS}"
        )
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _instance_id(value: Any, field: str = "instance_id") -> str:
    if not isinstance(value, str) or INSTANCE_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase 128-bit hexadecimal id")
    return value


def _minimum_generation(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("minimum_generation_seen must be a non-negative integer")
    return value


def _read_private_regular(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > maximum
        ):
            raise PermissionError(f"operator fence private file is unsafe: {path.name}")
        data = os.read(descriptor, maximum + 1)
        if len(data) != info.st_size:
            raise OperatorFenceError(
                f"operator fence private file changed while read: {path.name}"
            )
        return data
    finally:
        os.close(descriptor)


def _atomic_private_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short operator fence private-file write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    directory = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class OperatorFenceStore:
    """Local durable single-writer fence state.

    The store deliberately knows nothing about network routing or operator health.
    It serializes one writer generation and one exact in-flight mutation intent.
    A later transport/service layer authenticates callers and decides when failover
    is permitted; this core only enforces the writer/intent invariants.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.path = Path(database_path).expanduser()
        if not self.path.is_absolute():
            raise ValueError("operator fence database path must be absolute")
        self.anchor_path = self.path.with_name(
            self.path.name + ".generation-anchor.json"
        )
        self.session_key_path = self.path.with_name(self.path.name + ".session-key")
        self._clock = clock or (lambda: int(time.time()))
        self._database_identity: tuple[int, int] | None = None
        self._schema_ready = False
        created = self._prepare_storage()
        if created:
            self._session_key = os.urandom(SESSION_KEY_BYTES)
            _atomic_private_write(self.session_key_path, self._session_key)
            self._new_instance_id = secrets.token_hex(16)
        else:
            self._session_key = _read_private_regular(
                self.session_key_path, maximum=SESSION_KEY_BYTES
            )
            if len(self._session_key) != SESSION_KEY_BYTES:
                raise OperatorFenceError("operator fence session key length is invalid")
            self._new_instance_id = None
        self._initialize(created=created)
        self._schema_ready = True
        status = self.path.lstat()
        self._database_identity = (status.st_dev, status.st_ino)
        self._validate_no_wal_sidecars()

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeError("operator fence clock returned an invalid timestamp")
        return value

    def _session_digest(self, session_id: str) -> str:
        return hmac.new(
            self._session_key, session_id.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _prepare_storage(self) -> bool:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_status = parent.lstat()
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != os.geteuid()
            or parent_status.st_mode & 0o077
        ):
            raise PermissionError("operator fence state directory must be private")
        existed = self.path.exists() or self.path.is_symlink()
        if not existed and (
            self.anchor_path.exists() or self.session_key_path.exists()
        ):
            raise OperatorFenceError(
                "operator fence database is missing while durable sidecars remain"
            )
        if not existed:
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(self.path, flags, 0o600)
            os.close(descriptor)
        if existed:
            for sidecar in (self.anchor_path, self.session_key_path):
                if not sidecar.exists() or sidecar.is_symlink():
                    raise OperatorFenceError(
                        f"operator fence durable sidecar is missing: {sidecar.name}"
                    )
        return not existed

    def _validate_database_file(self) -> None:
        status = self.path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.geteuid()
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            raise PermissionError("operator fence database identity is unsafe")
        if (
            self._database_identity is not None
            and (status.st_dev, status.st_ino) != self._database_identity
        ):
            raise OperatorFenceError("operator fence database identity changed")

    def _validate_no_wal_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists() or candidate.is_symlink():
                raise OperatorFenceError(
                    f"operator fence unexpected SQLite sidecar exists: {candidate.name}"
                )

    def _connect(self) -> sqlite3.Connection:
        self._validate_database_file()
        try:
            connection = sqlite3.connect(
                self.path, timeout=5, isolation_level=None
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA synchronous=FULL")
        except sqlite3.Error as exc:
            raise OperatorFenceError("operator fence SQLite connection failed") from exc
        self._validate_database_file()
        if self._schema_ready:
            self._validate_schema(connection)
            mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if mode != "delete":
                connection.close()
                raise OperatorFenceError(
                    "operator fence database journal mode is not DELETE"
                )
        return connection

    @staticmethod
    def _sqlite_error(exc: sqlite3.Error) -> OperatorFenceError:
        detail = str(exc).lower()
        if "locked" in detail or "busy" in detail:
            return OperatorFenceError("operator fence SQLite store is busy")
        return OperatorFenceError("operator fence SQLite operation failed")

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise self._sqlite_error(exc) from exc
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise self._sqlite_error(exc) from exc
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE fence_meta ("
            "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
            "schema_version INTEGER NOT NULL, "
            "instance_id TEXT NOT NULL UNIQUE, "
            "created_at_unix INTEGER NOT NULL)"
        )
        connection.execute(
            """
            CREATE TABLE fence_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                generation INTEGER NOT NULL CHECK (generation >= 0),
                owner_id TEXT,
                session_digest TEXT,
                acquire_reason TEXT,
                lease_until_unix INTEGER,
                inflight_operation_id TEXT,
                inflight_operation_name TEXT,
                inflight_intent_sha256 TEXT,
                inflight_state TEXT CHECK (
                    inflight_state IS NULL OR
                    inflight_state IN ('begun', 'outcome_unknown')
                ),
                inflight_started_at_unix INTEGER,
                updated_at_unix INTEGER NOT NULL,
                CHECK (
                    (owner_id IS NULL AND session_digest IS NULL AND
                     acquire_reason IS NULL AND lease_until_unix IS NULL)
                    OR
                    (owner_id IS NOT NULL AND session_digest IS NOT NULL AND
                     acquire_reason IS NOT NULL AND lease_until_unix IS NOT NULL)
                ),
                CHECK (
                    (inflight_operation_id IS NULL AND
                     inflight_operation_name IS NULL AND
                     inflight_intent_sha256 IS NULL AND
                     inflight_state IS NULL AND
                     inflight_started_at_unix IS NULL)
                    OR
                    (inflight_operation_id IS NOT NULL AND
                     inflight_operation_name IS NOT NULL AND
                     inflight_intent_sha256 IS NOT NULL AND
                     inflight_state IS NOT NULL AND
                     inflight_started_at_unix IS NOT NULL)
                ),
                CHECK (inflight_operation_id IS NULL OR owner_id IS NOT NULL)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE settlements (
                settlement_id INTEGER PRIMARY KEY AUTOINCREMENT,
                generation INTEGER NOT NULL CHECK (generation >= 1),
                owner_id TEXT NOT NULL,
                session_digest TEXT NOT NULL,
                operation_id TEXT NOT NULL UNIQUE,
                operation_name TEXT NOT NULL,
                intent_sha256 TEXT NOT NULL UNIQUE,
                outcome TEXT NOT NULL CHECK (
                    outcome IN ('effect_applied', 'effect_not_applied')
                ),
                evidence_sha256 TEXT NOT NULL,
                resolution_source TEXT NOT NULL CHECK (
                    resolution_source IN ('writer', 'reconcile')
                ),
                reconciler_id TEXT,
                settled_at_unix INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE effect_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                generation INTEGER NOT NULL CHECK (generation >= 1),
                owner_id TEXT NOT NULL,
                session_digest TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK (
                    event_type IN ('outcome_unknown', 'reconcile', 'writer_dispute')
                ),
                observed_outcome TEXT,
                evidence_sha256 TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                observed_at_unix INTEGER NOT NULL,
                UNIQUE (event_type, operation_id, actor_id, observed_outcome, evidence_sha256)
            )
            """
        )

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        expected = {
            "fence_meta": ("singleton", "schema_version", "instance_id", "created_at_unix"),
            "fence_state": ("singleton", "generation", "owner_id", "session_digest", "acquire_reason", "lease_until_unix", "inflight_operation_id", "inflight_operation_name", "inflight_intent_sha256", "inflight_state", "inflight_started_at_unix", "updated_at_unix"),
            "settlements": ("settlement_id", "generation", "owner_id", "session_digest", "operation_id", "operation_name", "intent_sha256", "outcome", "evidence_sha256", "resolution_source", "reconciler_id", "settled_at_unix"),
            "effect_events": ("event_id", "generation", "owner_id", "session_digest", "operation_id", "event_type", "observed_outcome", "evidence_sha256", "actor_id", "observed_at_unix"),
        }
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != set(expected):
            raise OperatorFenceError("operator fence database table set is invalid")
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type IN ('view','trigger') LIMIT 1"
        ).fetchone() is not None:
            raise OperatorFenceError("operator fence database contains views or triggers")
        for table, columns in expected.items():
            actual = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))
            if actual != columns:
                raise OperatorFenceError(f"operator fence database schema mismatch: {table}")
        meta = connection.execute(
            "SELECT schema_version, instance_id FROM fence_meta WHERE singleton=1"
        ).fetchone()
        if (
            meta is None
            or int(meta["schema_version"]) != DATABASE_SCHEMA_VERSION
            or INSTANCE_RE.fullmatch(str(meta["instance_id"])) is None
        ):
            raise OperatorFenceError("operator fence database metadata is invalid")
        values = [str(row[0]).lower() for row in connection.execute("PRAGMA quick_check")]
        if values != ["ok"]:
            raise OperatorFenceError("operator fence database integrity check failed")

    @staticmethod
    def _meta(connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM fence_meta WHERE singleton=1").fetchone()
        if row is None:
            raise OperatorFenceError("operator fence metadata is missing")
        return row

    def _load_anchor(self) -> dict[str, Any]:
        raw = _read_private_regular(self.anchor_path, maximum=MAX_ANCHOR_BYTES)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OperatorFenceError("operator fence generation anchor is invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "kind", "instance_id", "generation"}
            or value.get("schema_version") != SCHEMA_VERSION
            or value.get("kind") != ANCHOR_KIND
        ):
            raise OperatorFenceError("operator fence generation anchor shape is invalid")
        instance = _instance_id(value.get("instance_id"), "anchor.instance_id")
        generation = value.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise OperatorFenceError("operator fence generation anchor value is invalid")
        return {"instance_id": instance, "generation": generation}

    def _write_anchor(self, *, instance_id: str, generation: int) -> None:
        _atomic_private_write(
            self.anchor_path,
            _canonical_json_bytes({
                "schema_version": SCHEMA_VERSION,
                "kind": ANCHOR_KIND,
                "instance_id": instance_id,
                "generation": generation,
            }) + b"\n",
        )

    def _initialize(self, *, created: bool) -> None:
        connection = self._connect()
        try:
            mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
            if mode != "delete":
                raise OperatorFenceError("operator fence could not establish DELETE journal mode")
            if created:
                now = self._now()
                assert self._new_instance_id is not None
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._create_schema(connection)
                    connection.execute(
                        "INSERT INTO fence_meta (singleton, schema_version, instance_id, created_at_unix) VALUES (1, ?, ?, ?)",
                        (DATABASE_SCHEMA_VERSION, self._new_instance_id, now),
                    )
                    connection.execute(
                        "INSERT INTO fence_state (singleton, generation, updated_at_unix) VALUES (1, 0, ?)",
                        (now,),
                    )
                    connection.execute("COMMIT")
                except BaseException:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
            self._validate_schema(connection)
            if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
                raise OperatorFenceError("operator fence database journal mode is not DELETE")
        finally:
            connection.close()
        if created:
            assert self._new_instance_id is not None
            self._write_anchor(instance_id=self._new_instance_id, generation=0)
        self._reconcile_generation_anchor()
        self._validate_no_wal_sidecars()

    @staticmethod
    def _require_clock_not_backward(row: sqlite3.Row, now: int) -> None:
        if now < int(row["updated_at_unix"]):
            raise OperatorFenceDenied("clock_moved_backward")

    def _reconcile_generation_anchor(self) -> None:
        anchor = self._load_anchor()
        connection = self._connect()
        try:
            self._validate_schema(connection)
            connection.execute("BEGIN IMMEDIATE")
            try:
                meta = self._meta(connection)
                row = self._state(connection)
                instance = str(meta["instance_id"])
                if anchor["instance_id"] != instance:
                    raise OperatorFenceError("operator fence generation anchor instance mismatch")
                db_generation = int(row["generation"])
                anchor_generation = int(anchor["generation"])
                if db_generation > anchor_generation:
                    raise OperatorFenceError("operator fence generation anchor rolled back")
                if anchor_generation > db_generation:
                    now = self._now()
                    self._require_clock_not_backward(row, now)
                    if row["inflight_operation_id"] is not None:
                        raise OperatorFenceError("operator fence generation anchor is ahead of unresolved state")
                    if row["owner_id"] is not None and int(row["lease_until_unix"]) > now:
                        raise OperatorFenceError("operator fence generation anchor is ahead of a live grant")
                    connection.execute(
                        "UPDATE fence_state SET generation=?, owner_id=NULL, session_digest=NULL, acquire_reason=NULL, lease_until_unix=NULL, updated_at_unix=? WHERE singleton=1",
                        (anchor_generation, now),
                    )
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
        finally:
            connection.close()

    @staticmethod
    def _state(connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM fence_state WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise OperatorFenceError("operator fence state is missing")
        return row

    @staticmethod
    def _last_settlement(connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM settlements ORDER BY settlement_id DESC LIMIT 1"
        ).fetchone()

    @staticmethod
    def _last_event(connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM effect_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()

    @staticmethod
    def _settlement_for_operation(
        connection: sqlite3.Connection, operation_id: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM settlements WHERE operation_id=?", (operation_id,)
        ).fetchone()

    @staticmethod
    def _settlement_for_intent(
        connection: sqlite3.Connection, intent_sha256: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM settlements WHERE intent_sha256=?", (intent_sha256,)
        ).fetchone()

    @staticmethod
    def _settlement_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            key: row[key]
            for key in (
                "settlement_id", "generation", "owner_id", "operation_id",
                "operation_name", "intent_sha256", "outcome",
                "evidence_sha256", "resolution_source", "reconciler_id",
                "settled_at_unix",
            )
        }

    @staticmethod
    def _event_public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            key: row[key]
            for key in (
                "event_id", "generation", "owner_id", "operation_id",
                "event_type", "observed_outcome", "evidence_sha256",
                "actor_id", "observed_at_unix",
            )
        }

    @staticmethod
    def _fencing_mark(instance_id: str, generation: int) -> dict[str, Any]:
        """Return a checksum-bound mark, never an authentication credential."""
        material = {"instance_id": instance_id, "generation": generation}
        return {
            **material,
            "mark_sha256": _sha256_json(material),
            "does_not_establish": list(FENCING_MARK_DOES_NOT_ESTABLISH),
        }

    @staticmethod
    def _require_instance(
        meta: sqlite3.Row, expected_instance_id: str | None
    ) -> None:
        if expected_instance_id is None:
            return
        expected = _instance_id(expected_instance_id, "expected_instance_id")
        if str(meta["instance_id"]) != expected:
            raise OperatorFenceDenied("stale_fence_instance")

    @staticmethod
    def _require_minimum_generation(
        row: sqlite3.Row, minimum_generation_seen: int
    ) -> None:
        minimum_seen = _minimum_generation(minimum_generation_seen)
        if int(row["generation"]) < minimum_seen:
            raise OperatorFenceDenied("generation_rollback_detected")

    def _status_from_connection(
        self, connection: sqlite3.Connection, *, now: int
    ) -> dict[str, Any]:
        meta = self._meta(connection)
        row = self._state(connection)
        instance = str(meta["instance_id"])
        generation = int(row["generation"])
        owner = row["owner_id"]
        writer = None
        if owner is not None:
            lease_until = int(row["lease_until_unix"])
            writer = {
                "owner_id": str(owner),
                "session_id_sha256": str(row["session_digest"]),
                "acquire_reason": str(row["acquire_reason"]),
                "lease_until_unix": lease_until,
                "lease_active": lease_until > now,
            }
        inflight = None
        if row["inflight_operation_id"] is not None:
            inflight = {
                "generation": generation,
                "owner_id": str(row["owner_id"]),
                "operation_id": str(row["inflight_operation_id"]),
                "operation_name": str(row["inflight_operation_name"]),
                "intent_sha256": str(row["inflight_intent_sha256"]),
                "state": str(row["inflight_state"]),
                "started_at_unix": int(row["inflight_started_at_unix"]),
            }
        last = self._last_settlement(connection)
        event = self._last_event(connection)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": STATUS_KIND,
            "observed_at_unix": now,
            "instance_id": instance,
            "generation": generation,
            "fencing_mark": self._fencing_mark(instance, generation),
            "clock_regressed": now < int(row["updated_at_unix"]),
            "writer": writer,
            "inflight": inflight,
            "last_settlement": None if last is None else self._settlement_public(last),
            "last_event": None if event is None else self._event_public(event),
        }

    def status(self) -> dict[str, Any]:
        now = self._now()
        with self._read_transaction() as connection:
            return self._status_from_connection(connection, now=now)

    @staticmethod
    def validate_fencing_mark(
        mark: Mapping[str, Any],
        *,
        expected_instance_id: str,
        minimum_generation_seen: int,
    ) -> dict[str, Any]:
        """Validate self-consistency/non-regression, not source authenticity.

        The mark is deliberately unkeyed because downstream clients do not hold
        coordinator secrets.  Callers MUST establish coordinator and transport
        authenticity separately (G6.3 uses a pinned SSH host identity) before a
        validated mark may advance durable client high-water state.
        """
        expected_fields = {
            "instance_id", "generation", "mark_sha256", "does_not_establish"
        }
        if not isinstance(mark, Mapping) or set(mark) != expected_fields:
            raise OperatorFenceDenied("invalid_fencing_mark")
        if mark.get("does_not_establish") != list(FENCING_MARK_DOES_NOT_ESTABLISH):
            raise OperatorFenceDenied("invalid_fencing_mark")
        instance = _instance_id(mark.get("instance_id"), "mark.instance_id")
        generation = _minimum_generation(mark.get("generation"))
        supplied = _sha256(mark.get("mark_sha256"), "mark.mark_sha256")
        expected_digest = _sha256_json(
            {"instance_id": instance, "generation": generation}
        )
        if supplied != expected_digest:
            raise OperatorFenceDenied("invalid_fencing_mark")
        expected_instance = _instance_id(expected_instance_id, "expected_instance_id")
        if instance != expected_instance:
            raise OperatorFenceDenied("stale_fence_instance")
        minimum_seen = _minimum_generation(minimum_generation_seen)
        if generation < minimum_seen:
            raise OperatorFenceDenied("generation_rollback_detected")
        return {
            "instance_id": instance,
            "generation": generation,
            "mark_sha256": supplied,
            "does_not_establish": list(FENCING_MARK_DOES_NOT_ESTABLISH),
        }

    def acquire(
        self,
        *,
        owner_id: str,
        session_id: str,
        reason: str,
        lease_seconds: int,
        expected_instance_id: str | None = None,
        minimum_generation_seen: int = 0,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        session_digest = self._session_digest(session)
        acquire_reason = _bounded_identity(
            reason, "reason", maximum=MAX_REASON_BYTES
        )
        ttl = _lease_seconds(lease_seconds)
        minimum_seen = _minimum_generation(minimum_generation_seen)
        now = self._now()
        with self._write_transaction() as connection:
            meta = self._meta(connection)
            self._require_instance(meta, expected_instance_id)
            row = self._state(connection)
            self._require_clock_not_backward(row, now)
            self._require_minimum_generation(row, minimum_seen)
            current_owner = row["owner_id"]
            lease_active = (
                current_owner is not None and int(row["lease_until_unix"]) > now
            )
            if lease_active:
                same_holder = (
                    current_owner == owner
                    and hmac.compare_digest(
                        str(row["session_digest"]), session_digest
                    )
                )
                if same_holder and row["acquire_reason"] == acquire_reason:
                    status = self._status_from_connection(connection, now=now)
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": GRANT_KIND,
                        "idempotent": True,
                        "instance_id": str(meta["instance_id"]),
                        "generation": int(row["generation"]),
                        "owner_id": owner,
                        "session_id_sha256": session_digest,
                        "lease_until_unix": int(row["lease_until_unix"]),
                        "fencing_mark": status["fencing_mark"],
                        "status": status,
                    }
                if same_holder:
                    raise OperatorFenceDenied("grant_parameters_changed")
                raise OperatorFenceDenied("writer_active")
            if row["inflight_operation_id"] is not None:
                raise OperatorFenceDenied("unresolved_inflight")
            instance = str(meta["instance_id"])
            anchor = self._load_anchor()
            if (
                anchor["instance_id"] != instance
                or int(anchor["generation"]) != int(row["generation"])
            ):
                raise OperatorFenceDenied("generation_anchor_mismatch")
            new_generation = int(row["generation"]) + 1
            self._write_anchor(instance_id=instance, generation=new_generation)
            lease_until = now + ttl
            connection.execute(
                """
                UPDATE fence_state
                SET generation=?, owner_id=?, session_digest=?, acquire_reason=?,
                    lease_until_unix=?, updated_at_unix=?
                WHERE singleton=1
                """,
                (
                    new_generation, owner, session_digest, acquire_reason,
                    lease_until, now,
                ),
            )
            status = self._status_from_connection(connection, now=now)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": GRANT_KIND,
                "idempotent": False,
                "instance_id": instance,
                "generation": new_generation,
                "owner_id": owner,
                "session_id_sha256": session_digest,
                "lease_until_unix": lease_until,
                "fencing_mark": status["fencing_mark"],
                "status": status,
            }

    def renew(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
        lease_seconds: int,
        expected_instance_id: str | None = None,
        minimum_generation_seen: int = 0,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        expected_generation = _generation(generation)
        ttl = _lease_seconds(lease_seconds)
        now = self._now()
        with self._write_transaction() as connection:
            meta = self._meta(connection)
            self._require_instance(meta, expected_instance_id)
            row = self._state(connection)
            self._require_clock_not_backward(row, now)
            self._require_minimum_generation(row, minimum_generation_seen)
            self._require_holder(
                row, owner=owner, session=session, generation=expected_generation
            )
            current_until = int(row["lease_until_unix"])
            if current_until <= now:
                raise OperatorFenceDenied("grant_expired")
            new_until = max(current_until, now + ttl)
            connection.execute(
                "UPDATE fence_state SET lease_until_unix=?, updated_at_unix=? WHERE singleton=1",
                (new_until, now),
            )
            return self._status_from_connection(connection, now=now)

    def _require_holder(
        self,
        row: sqlite3.Row,
        *,
        owner: str,
        session: str,
        generation: int,
    ) -> str:
        if int(row["generation"]) != generation:
            raise OperatorFenceDenied("stale_generation")
        digest = self._session_digest(session)
        if row["owner_id"] != owner or not hmac.compare_digest(
            str(row["session_digest"] or ""), digest
        ):
            raise OperatorFenceDenied("not_grant_holder")
        return digest

    def begin_effect(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
        operation_id: str,
        operation_name: str,
        intent_sha256: str,
        expected_instance_id: str | None = None,
        minimum_generation_seen: int = 0,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        expected_generation = _generation(generation)
        operation = _bounded_identity(
            operation_id, "operation_id", maximum=MAX_OPERATION_BYTES
        )
        operation_label = _bounded_identity(
            operation_name, "operation_name", maximum=MAX_OPERATION_BYTES
        )
        intent = _sha256(intent_sha256, "intent_sha256")
        now = self._now()
        with self._write_transaction() as connection:
            meta = self._meta(connection)
            self._require_instance(meta, expected_instance_id)
            row = self._state(connection)
            self._require_clock_not_backward(row, now)
            self._require_minimum_generation(row, minimum_generation_seen)
            self._require_holder(
                row, owner=owner, session=session, generation=expected_generation
            )
            settled = self._settlement_for_operation(connection, operation)
            if settled is not None:
                if (
                    settled["intent_sha256"] == intent
                    and settled["operation_name"] == operation_label
                ):
                    raise OperatorFenceDenied("operation_already_settled")
                raise OperatorFenceDenied("operation_identity_conflict")
            if self._settlement_for_intent(connection, intent) is not None:
                raise OperatorFenceDenied("intent_already_settled")
            if row["inflight_operation_id"] is not None:
                if (
                    row["inflight_operation_id"] == operation
                    and row["inflight_operation_name"] == operation_label
                    and row["inflight_intent_sha256"] == intent
                ):
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": BEGIN_KIND,
                        "idempotent": True,
                        "instance_id": str(meta["instance_id"]),
                        "generation": expected_generation,
                        "operation_id": operation,
                        "operation_name": operation_label,
                        "intent_sha256": intent,
                        "state": str(row["inflight_state"]),
                        "started_at_unix": int(row["inflight_started_at_unix"]),
                    }
                if row["inflight_intent_sha256"] == intent:
                    raise OperatorFenceDenied("intent_inflight")
                raise OperatorFenceDenied("effect_inflight")
            if int(row["lease_until_unix"]) <= now:
                raise OperatorFenceDenied("grant_expired")
            connection.execute(
                """
                UPDATE fence_state
                SET inflight_operation_id=?, inflight_operation_name=?,
                    inflight_intent_sha256=?, inflight_state='begun',
                    inflight_started_at_unix=?, updated_at_unix=?
                WHERE singleton=1
                """,
                (operation, operation_label, intent, now, now),
            )
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": BEGIN_KIND,
                "idempotent": False,
                "instance_id": str(meta["instance_id"]),
                "generation": expected_generation,
                "operation_id": operation,
                "operation_name": operation_label,
                "intent_sha256": intent,
                "state": "begun",
                "started_at_unix": now,
            }

    @staticmethod
    def _require_inflight(
        row: sqlite3.Row,
        *,
        generation: int,
        operation_id: str,
        operation_name: str,
        intent_sha256: str,
    ) -> None:
        if int(row["generation"]) != generation:
            raise OperatorFenceDenied("stale_generation")
        if row["inflight_operation_id"] is None:
            raise OperatorFenceDenied("no_inflight_effect")
        if (
            row["inflight_operation_id"] != operation_id
            or row["inflight_operation_name"] != operation_name
            or row["inflight_intent_sha256"] != intent_sha256
        ):
            raise OperatorFenceDenied("inflight_identity_mismatch")

    @staticmethod
    def _insert_settlement(
        connection: sqlite3.Connection,
        *,
        generation: int,
        owner_id: str,
        session_digest: str,
        operation_id: str,
        operation_name: str,
        intent_sha256: str,
        outcome: str,
        evidence_sha256: str,
        resolution_source: str,
        reconciler_id: str | None,
        settled_at_unix: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO settlements (
                generation, owner_id, session_digest, operation_id,
                operation_name, intent_sha256, outcome, evidence_sha256,
                resolution_source, reconciler_id, settled_at_unix
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                generation, owner_id, session_digest, operation_id,
                operation_name, intent_sha256, outcome, evidence_sha256,
                resolution_source, reconciler_id, settled_at_unix,
            ),
        )

    @staticmethod
    def _record_event(
        connection: sqlite3.Connection,
        *,
        generation: int,
        owner_id: str,
        session_digest: str,
        operation_id: str,
        event_type: str,
        observed_outcome: str | None,
        evidence_sha256: str,
        actor_id: str,
        observed_at_unix: int,
    ) -> int:
        connection.execute(
            """
            INSERT OR IGNORE INTO effect_events (
                generation, owner_id, session_digest, operation_id,
                event_type, observed_outcome, evidence_sha256,
                actor_id, observed_at_unix
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                generation, owner_id, session_digest, operation_id,
                event_type, observed_outcome, evidence_sha256,
                actor_id, observed_at_unix,
            ),
        )
        row = connection.execute(
            """
            SELECT event_id FROM effect_events
            WHERE event_type=? AND operation_id=? AND actor_id=?
              AND observed_outcome IS ? AND evidence_sha256=?
            """,
            (event_type, operation_id, actor_id, observed_outcome, evidence_sha256),
        ).fetchone()
        if row is None:
            raise OperatorFenceError("operator fence effect event was not persisted")
        return int(row["event_id"])

    @staticmethod
    def _clear_inflight(connection: sqlite3.Connection, *, now: int) -> None:
        connection.execute(
            """
            UPDATE fence_state
            SET inflight_operation_id=NULL, inflight_operation_name=NULL,
                inflight_intent_sha256=NULL, inflight_state=NULL,
                inflight_started_at_unix=NULL, updated_at_unix=?
            WHERE singleton=1
            """,
            (now,),
        )

    def settle_effect(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
        operation_id: str,
        operation_name: str,
        intent_sha256: str,
        outcome: str,
        evidence_sha256: str,
        expected_instance_id: str | None = None,
        minimum_generation_seen: int = 0,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        session_digest = self._session_digest(session)
        expected_generation = _generation(generation)
        operation = _bounded_identity(
            operation_id, "operation_id", maximum=MAX_OPERATION_BYTES
        )
        operation_label = _bounded_identity(
            operation_name, "operation_name", maximum=MAX_OPERATION_BYTES
        )
        intent = _sha256(intent_sha256, "intent_sha256")
        evidence = _sha256(evidence_sha256, "evidence_sha256")
        if outcome not in EFFECT_OUTCOMES:
            raise ValueError("outcome is not a supported fence effect outcome")
        now = self._now()
        with self._write_transaction() as connection:
            meta = self._meta(connection)
            self._require_instance(meta, expected_instance_id)
            row = self._state(connection)
            self._require_minimum_generation(row, minimum_generation_seen)
            settled = self._settlement_for_operation(connection, operation)
            if settled is not None:
                same_actor = (
                    settled["owner_id"] == owner
                    and hmac.compare_digest(
                        str(settled["session_digest"]), session_digest
                    )
                    and settled["operation_name"] == operation_label
                    and settled["intent_sha256"] == intent
                )
                if not same_actor:
                    raise OperatorFenceDenied("operation_already_settled")
                if (
                    outcome in TERMINAL_OUTCOMES
                    and settled["resolution_source"] == "writer"
                    and settled["outcome"] == outcome
                    and settled["evidence_sha256"] == evidence
                ):
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": SETTLEMENT_KIND,
                        "idempotent": True,
                        "terminal": True,
                        "recorded_settlement": self._settlement_public(settled),
                        "status": self._status_from_connection(connection, now=now),
                    }
                if outcome in TERMINAL_OUTCOMES:
                    self._require_clock_not_backward(row, now)
                    event_id = self._record_event(
                        connection,
                        generation=int(settled["generation"]),
                        owner_id=owner,
                        session_digest=session_digest,
                        operation_id=operation,
                        event_type="writer_dispute",
                        observed_outcome=outcome,
                        evidence_sha256=evidence,
                        actor_id=owner,
                        observed_at_unix=now,
                    )
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": SETTLEMENT_KIND,
                        "idempotent": False,
                        "terminal": True,
                        "dispute_recorded": True,
                        "dispute_event_id": event_id,
                        "recorded_settlement": self._settlement_public(settled),
                        "status": self._status_from_connection(connection, now=now),
                    }
                raise OperatorFenceDenied("operation_already_settled")
            if self._settlement_for_intent(connection, intent) is not None:
                raise OperatorFenceDenied("intent_already_settled")
            self._require_clock_not_backward(row, now)
            holder_digest = self._require_holder(
                row, owner=owner, session=session, generation=expected_generation
            )
            self._require_inflight(
                row,
                generation=expected_generation,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
            )
            if outcome == "outcome_unknown":
                event_id = self._record_event(
                    connection,
                    generation=expected_generation,
                    owner_id=owner,
                    session_digest=holder_digest,
                    operation_id=operation,
                    event_type="outcome_unknown",
                    observed_outcome=outcome,
                    evidence_sha256=evidence,
                    actor_id=owner,
                    observed_at_unix=now,
                )
                already_unknown = row["inflight_state"] == "outcome_unknown"
                if not already_unknown:
                    connection.execute(
                        "UPDATE fence_state SET inflight_state='outcome_unknown', updated_at_unix=? WHERE singleton=1",
                        (now,),
                    )
                return {
                    "schema_version": SCHEMA_VERSION,
                    "kind": SETTLEMENT_KIND,
                    "idempotent": already_unknown,
                    "terminal": False,
                    "event_id": event_id,
                    "status": self._status_from_connection(connection, now=now),
                }
            self._insert_settlement(
                connection,
                generation=expected_generation,
                owner_id=owner,
                session_digest=holder_digest,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
                outcome=outcome,
                evidence_sha256=evidence,
                resolution_source="writer",
                reconciler_id=None,
                settled_at_unix=now,
            )
            self._clear_inflight(connection, now=now)
            recorded = self._settlement_for_operation(connection, operation)
            assert recorded is not None
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": SETTLEMENT_KIND,
                "idempotent": False,
                "terminal": True,
                "recorded_settlement": self._settlement_public(recorded),
                "status": self._status_from_connection(connection, now=now),
            }

    def reconcile_effect(
        self,
        *,
        reconciler_id: str,
        generation: int,
        operation_id: str,
        operation_name: str,
        intent_sha256: str,
        outcome: str,
        evidence_sha256: str,
        expected_instance_id: str | None = None,
        minimum_generation_seen: int = 0,
    ) -> dict[str, Any]:
        reconciler = _bounded_identity(
            reconciler_id, "reconciler_id", maximum=MAX_RECONCILER_BYTES
        )
        expected_generation = _generation(generation)
        operation = _bounded_identity(
            operation_id, "operation_id", maximum=MAX_OPERATION_BYTES
        )
        operation_label = _bounded_identity(
            operation_name, "operation_name", maximum=MAX_OPERATION_BYTES
        )
        intent = _sha256(intent_sha256, "intent_sha256")
        evidence = _sha256(evidence_sha256, "evidence_sha256")
        if outcome not in TERMINAL_OUTCOMES:
            raise ValueError("reconciliation must resolve to a terminal effect outcome")
        now = self._now()
        with self._write_transaction() as connection:
            meta = self._meta(connection)
            self._require_instance(meta, expected_instance_id)
            row = self._state(connection)
            self._require_minimum_generation(row, minimum_generation_seen)
            settled = self._settlement_for_operation(connection, operation)
            if settled is not None:
                if (
                    settled["generation"] == expected_generation
                    and settled["operation_name"] == operation_label
                    and settled["intent_sha256"] == intent
                    and settled["outcome"] == outcome
                    and settled["evidence_sha256"] == evidence
                    and settled["resolution_source"] == "reconcile"
                    and settled["reconciler_id"] == reconciler
                ):
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": SETTLEMENT_KIND,
                        "idempotent": True,
                        "terminal": True,
                        "recorded_settlement": self._settlement_public(settled),
                        "status": self._status_from_connection(connection, now=now),
                    }
                if settled["resolution_source"] == "writer":
                    raise OperatorFenceDenied("operation_resolved_by_writer")
                raise OperatorFenceDenied("operation_already_settled")
            if self._settlement_for_intent(connection, intent) is not None:
                raise OperatorFenceDenied("intent_already_settled")
            self._require_clock_not_backward(row, now)
            self._require_inflight(
                row,
                generation=expected_generation,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
            )
            lease_until = int(row["lease_until_unix"])
            if lease_until > now:
                raise OperatorFenceDenied("reconcile_requires_expired_writer")
            if row["inflight_state"] != "outcome_unknown":
                raise OperatorFenceDenied("begun_reconcile_requires_typed_proof")
            if outcome != "effect_applied":
                raise OperatorFenceDenied(
                    "non_application_reconcile_requires_typed_finality_proof"
                )
            original_owner = str(row["owner_id"])
            original_session_digest = str(row["session_digest"])
            self._insert_settlement(
                connection,
                generation=expected_generation,
                owner_id=original_owner,
                session_digest=original_session_digest,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
                outcome=outcome,
                evidence_sha256=evidence,
                resolution_source="reconcile",
                reconciler_id=reconciler,
                settled_at_unix=now,
            )
            event_id = self._record_event(
                connection,
                generation=expected_generation,
                owner_id=original_owner,
                session_digest=original_session_digest,
                operation_id=operation,
                event_type="reconcile",
                observed_outcome=outcome,
                evidence_sha256=evidence,
                actor_id=reconciler,
                observed_at_unix=now,
            )
            self._clear_inflight(connection, now=now)
            recorded = self._settlement_for_operation(connection, operation)
            assert recorded is not None
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": SETTLEMENT_KIND,
                "idempotent": False,
                "terminal": True,
                "event_id": event_id,
                "recorded_settlement": self._settlement_public(recorded),
                "status": self._status_from_connection(connection, now=now),
            }

    def release(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
        expected_instance_id: str | None = None,
        minimum_generation_seen: int = 0,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        expected_generation = _generation(generation)
        now = self._now()
        with self._write_transaction() as connection:
            meta = self._meta(connection)
            self._require_instance(meta, expected_instance_id)
            row = self._state(connection)
            self._require_clock_not_backward(row, now)
            self._require_minimum_generation(row, minimum_generation_seen)
            self._require_holder(
                row, owner=owner, session=session, generation=expected_generation
            )
            if row["inflight_operation_id"] is not None:
                raise OperatorFenceDenied("unresolved_inflight")
            connection.execute(
                "UPDATE fence_state SET owner_id=NULL, session_digest=NULL, "
                "acquire_reason=NULL, lease_until_unix=NULL, updated_at_unix=? "
                "WHERE singleton=1",
                (now,),
            )
            return self._status_from_connection(connection, now=now)


__all__ = [
    "DATABASE_SCHEMA_VERSION",
    "EFFECT_OUTCOMES",
    "MAX_LEASE_SECONDS",
    "OperatorFenceDenied",
    "OperatorFenceError",
    "OperatorFenceStore",
    "TERMINAL_OUTCOMES",
]

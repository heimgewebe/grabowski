from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any


SCHEMA_VERSION = 1
STATUS_KIND = "grabowski.operator_fence_status"
GRANT_KIND = "grabowski.operator_fence_grant"
BEGIN_KIND = "grabowski.operator_fence_begin"
SETTLEMENT_KIND = "grabowski.operator_fence_settlement"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_RE = re.compile(r"[A-Za-z0-9._:@/-]+\Z")
MAX_OWNER_BYTES = 128
MAX_SESSION_BYTES = 256
MAX_REASON_BYTES = 192
MAX_OPERATION_BYTES = 256
MAX_RECONCILER_BYTES = 128
MIN_LEASE_SECONDS = 1
MAX_LEASE_SECONDS = 600
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


def _session_digest(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


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
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_storage()
        self._initialize()

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeError("operator fence clock returned an invalid timestamp")
        return value

    def _prepare_storage(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_status = parent.lstat()
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid != os.geteuid()
            or parent_status.st_mode & 0o077
        ):
            raise PermissionError("operator fence state directory must be private")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        status = self.path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.geteuid()
            or status.st_nlink != 1
            or status.st_mode & 0o077
        ):
            raise PermissionError("operator fence database is not private")

    def _validate_database_file(self) -> None:
        status = self.path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.geteuid()
            or status.st_nlink != 1
        ):
            raise PermissionError("operator fence database identity is unsafe")
        os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=5,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
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
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._write_transaction() as connection:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS fence_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    generation INTEGER NOT NULL CHECK (generation >= 0),
                    owner_id TEXT,
                    session_id TEXT,
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
                        (owner_id IS NULL AND session_id IS NULL AND
                         acquire_reason IS NULL AND lease_until_unix IS NULL)
                        OR
                        (owner_id IS NOT NULL AND session_id IS NOT NULL AND
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
                CREATE TABLE IF NOT EXISTS settlements (
                    settlement_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    owner_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    operation_name TEXT NOT NULL,
                    intent_sha256 TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (
                        outcome IN ('effect_applied', 'effect_not_applied')
                    ),
                    evidence_sha256 TEXT NOT NULL,
                    resolution_source TEXT NOT NULL CHECK (
                        resolution_source IN ('writer', 'reconcile')
                    ),
                    reconciler_id TEXT,
                    settled_at_unix INTEGER NOT NULL,
                    UNIQUE (operation_id)
                )
                """
            )
            now = self._now()
            connection.execute(
                """
                INSERT OR IGNORE INTO fence_state (
                    singleton, generation, updated_at_unix
                ) VALUES (1, 0, ?)
                """,
                (now,),
            )
        self._validate_database_file()

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
    def _settlement_for_operation(
        connection: sqlite3.Connection,
        operation_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM settlements WHERE operation_id=?",
            (operation_id,),
        ).fetchone()

    def _status_from_connection(
        self,
        connection: sqlite3.Connection,
        *,
        now: int,
    ) -> dict[str, Any]:
        row = self._state(connection)
        owner = row["owner_id"]
        writer = None
        if owner is not None:
            lease_until = int(row["lease_until_unix"])
            writer = {
                "owner_id": str(owner),
                "session_id_sha256": _session_digest(str(row["session_id"])),
                "acquire_reason": str(row["acquire_reason"]),
                "lease_until_unix": lease_until,
                "lease_active": lease_until > now,
            }
        inflight = None
        if row["inflight_operation_id"] is not None:
            inflight = {
                "generation": int(row["generation"]),
                "owner_id": str(row["owner_id"]),
                "operation_id": str(row["inflight_operation_id"]),
                "operation_name": str(row["inflight_operation_name"]),
                "intent_sha256": str(row["inflight_intent_sha256"]),
                "state": str(row["inflight_state"]),
                "started_at_unix": int(row["inflight_started_at_unix"]),
            }
        last = self._last_settlement(connection)
        last_settlement = None
        if last is not None:
            last_settlement = {
                key: last[key]
                for key in (
                    "settlement_id",
                    "generation",
                    "owner_id",
                    "operation_id",
                    "operation_name",
                    "intent_sha256",
                    "outcome",
                    "evidence_sha256",
                    "resolution_source",
                    "reconciler_id",
                    "settled_at_unix",
                )
            }
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": STATUS_KIND,
            "observed_at_unix": now,
            "generation": int(row["generation"]),
            "writer": writer,
            "inflight": inflight,
            "last_settlement": last_settlement,
        }

    def status(self) -> dict[str, Any]:
        now = self._now()
        with self._read_transaction() as connection:
            return self._status_from_connection(connection, now=now)

    def acquire(
        self,
        *,
        owner_id: str,
        session_id: str,
        reason: str,
        lease_seconds: int,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        acquire_reason = _bounded_identity(
            reason, "reason", maximum=MAX_REASON_BYTES
        )
        ttl = _lease_seconds(lease_seconds)
        now = self._now()
        with self._write_transaction() as connection:
            row = self._state(connection)
            current_owner = row["owner_id"]
            lease_active = (
                current_owner is not None
                and int(row["lease_until_unix"]) > now
            )
            if lease_active:
                if (
                    current_owner == owner
                    and row["session_id"] == session
                    and row["acquire_reason"] == acquire_reason
                ):
                    status = self._status_from_connection(connection, now=now)
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": GRANT_KIND,
                        "idempotent": True,
                        "generation": int(row["generation"]),
                        "owner_id": owner,
                        "session_id_sha256": _session_digest(session),
                        "lease_until_unix": int(row["lease_until_unix"]),
                        "status": status,
                    }
                raise OperatorFenceDenied("writer_active")
            if row["inflight_operation_id"] is not None:
                raise OperatorFenceDenied("unresolved_inflight")
            new_generation = int(row["generation"]) + 1
            lease_until = now + ttl
            connection.execute(
                """
                UPDATE fence_state
                SET generation=?, owner_id=?, session_id=?, acquire_reason=?,
                    lease_until_unix=?, updated_at_unix=?
                WHERE singleton=1
                """,
                (
                    new_generation,
                    owner,
                    session,
                    acquire_reason,
                    lease_until,
                    now,
                ),
            )
            status = self._status_from_connection(connection, now=now)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": GRANT_KIND,
                "idempotent": False,
                "generation": new_generation,
                "owner_id": owner,
                "session_id_sha256": _session_digest(session),
                "lease_until_unix": lease_until,
                "status": status,
            }

    def renew(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
        lease_seconds: int,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        expected_generation = _generation(generation)
        ttl = _lease_seconds(lease_seconds)
        now = self._now()
        with self._write_transaction() as connection:
            row = self._state(connection)
            self._require_holder(
                row,
                owner=owner,
                session=session,
                generation=expected_generation,
            )
            current_until = int(row["lease_until_unix"])
            if current_until <= now:
                raise OperatorFenceDenied("grant_expired")
            new_until = max(current_until, now + ttl)
            connection.execute(
                """
                UPDATE fence_state
                SET lease_until_unix=?, updated_at_unix=?
                WHERE singleton=1
                """,
                (new_until, now),
            )
            return self._status_from_connection(connection, now=now)

    @staticmethod
    def _require_holder(
        row: sqlite3.Row,
        *,
        owner: str,
        session: str,
        generation: int,
    ) -> None:
        if int(row["generation"]) != generation:
            raise OperatorFenceDenied("stale_generation")
        if row["owner_id"] != owner or row["session_id"] != session:
            raise OperatorFenceDenied("not_grant_holder")

    def begin_effect(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
        operation_id: str,
        operation_name: str,
        intent_sha256: str,
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
            row = self._state(connection)
            self._require_holder(
                row,
                owner=owner,
                session=session,
                generation=expected_generation,
            )
            if int(row["lease_until_unix"]) <= now:
                raise OperatorFenceDenied("grant_expired")
            settled = self._settlement_for_operation(connection, operation)
            if settled is not None:
                if (
                    settled["intent_sha256"] == intent
                    and settled["operation_name"] == operation_label
                ):
                    raise OperatorFenceDenied("operation_already_settled")
                raise OperatorFenceDenied("operation_identity_conflict")
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
                        "generation": expected_generation,
                        "operation_id": operation,
                        "operation_name": operation_label,
                        "intent_sha256": intent,
                        "state": str(row["inflight_state"]),
                        "started_at_unix": int(
                            row["inflight_started_at_unix"]
                        ),
                    }
                raise OperatorFenceDenied("effect_inflight")
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
                generation, owner_id, operation_id, operation_name,
                intent_sha256, outcome, evidence_sha256, resolution_source,
                reconciler_id, settled_at_unix
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                generation,
                owner_id,
                operation_id,
                operation_name,
                intent_sha256,
                outcome,
                evidence_sha256,
                resolution_source,
                reconciler_id,
                settled_at_unix,
            ),
        )

    @staticmethod
    def _clear_inflight(connection: sqlite3.Connection, *, now: int) -> None:
        connection.execute(
            """
            UPDATE fence_state
            SET inflight_operation_id=NULL,
                inflight_operation_name=NULL,
                inflight_intent_sha256=NULL,
                inflight_state=NULL,
                inflight_started_at_unix=NULL,
                updated_at_unix=?
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
        evidence = _sha256(evidence_sha256, "evidence_sha256")
        if outcome not in EFFECT_OUTCOMES:
            raise ValueError("outcome is not a supported fence effect outcome")
        now = self._now()
        with self._write_transaction() as connection:
            row = self._state(connection)
            self._require_holder(
                row,
                owner=owner,
                session=session,
                generation=expected_generation,
            )
            settled = self._settlement_for_operation(connection, operation)
            if row["inflight_operation_id"] is None and settled is not None:
                if (
                    outcome in TERMINAL_OUTCOMES
                    and settled["generation"] == expected_generation
                    and settled["owner_id"] == owner
                    and settled["operation_name"] == operation_label
                    and settled["intent_sha256"] == intent
                    and settled["outcome"] == outcome
                    and settled["evidence_sha256"] == evidence
                    and settled["resolution_source"] == "writer"
                ):
                    return {
                        "schema_version": SCHEMA_VERSION,
                        "kind": SETTLEMENT_KIND,
                        "idempotent": True,
                        "status": self._status_from_connection(
                            connection, now=now
                        ),
                    }
                raise OperatorFenceDenied("operation_already_settled")
            self._require_inflight(
                row,
                generation=expected_generation,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
            )
            if outcome == "outcome_unknown":
                if row["inflight_state"] != "outcome_unknown":
                    connection.execute(
                        """
                        UPDATE fence_state
                        SET inflight_state='outcome_unknown', updated_at_unix=?
                        WHERE singleton=1
                        """,
                        (now,),
                    )
                return {
                    "schema_version": SCHEMA_VERSION,
                    "kind": SETTLEMENT_KIND,
                    "idempotent": row["inflight_state"] == "outcome_unknown",
                    "terminal": False,
                    "status": self._status_from_connection(
                        connection, now=now
                    ),
                }
            self._insert_settlement(
                connection,
                generation=expected_generation,
                owner_id=owner,
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
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": SETTLEMENT_KIND,
                "idempotent": False,
                "terminal": True,
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
            row = self._state(connection)
            settled = self._settlement_for_operation(connection, operation)
            if row["inflight_operation_id"] is None and settled is not None:
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
                        "status": self._status_from_connection(
                            connection, now=now
                        ),
                    }
                raise OperatorFenceDenied("operation_already_settled")
            self._require_inflight(
                row,
                generation=expected_generation,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
            )
            lease_active = int(row["lease_until_unix"]) > now
            if row["inflight_state"] != "outcome_unknown" and lease_active:
                raise OperatorFenceDenied("effect_not_reconcilable")
            original_owner = str(row["owner_id"])
            self._insert_settlement(
                connection,
                generation=expected_generation,
                owner_id=original_owner,
                operation_id=operation,
                operation_name=operation_label,
                intent_sha256=intent,
                outcome=outcome,
                evidence_sha256=evidence,
                resolution_source="reconcile",
                reconciler_id=reconciler,
                settled_at_unix=now,
            )
            self._clear_inflight(connection, now=now)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": SETTLEMENT_KIND,
                "idempotent": False,
                "terminal": True,
                "status": self._status_from_connection(connection, now=now),
            }

    def release(
        self,
        *,
        owner_id: str,
        session_id: str,
        generation: int,
    ) -> dict[str, Any]:
        owner = _bounded_identity(owner_id, "owner_id", maximum=MAX_OWNER_BYTES)
        session = _bounded_identity(
            session_id, "session_id", maximum=MAX_SESSION_BYTES
        )
        expected_generation = _generation(generation)
        now = self._now()
        with self._write_transaction() as connection:
            row = self._state(connection)
            self._require_holder(
                row,
                owner=owner,
                session=session,
                generation=expected_generation,
            )
            if row["inflight_operation_id"] is not None:
                raise OperatorFenceDenied("unresolved_inflight")
            connection.execute(
                """
                UPDATE fence_state
                SET owner_id=NULL, session_id=NULL, acquire_reason=NULL,
                    lease_until_unix=NULL, updated_at_unix=?
                WHERE singleton=1
                """,
                (now,),
            )
            return self._status_from_connection(connection, now=now)


__all__ = [
    "EFFECT_OUTCOMES",
    "MAX_LEASE_SECONDS",
    "OperatorFenceDenied",
    "OperatorFenceError",
    "OperatorFenceStore",
    "TERMINAL_OUTCOMES",
]

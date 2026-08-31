from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Iterator, Protocol


SCHEMA_VERSION = 1
KIND = "grabowski.slot_capture_evidence"
DEFAULT_STATE_ROOT = Path.home() / ".local/state/grabowski/slot-capture"
DEFAULT_DB = DEFAULT_STATE_ROOT / "slot-capture.sqlite3"
MAX_JSON_BYTES = 256 * 1024
SLOT_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
ELAPSED_CLOCKS = frozenset({"provider_boottime", "provider_realtime_cross_boot"})
TERMINAL_COLUMNS = (
    "terminal_payload_json",
    "terminal_payload_sha256",
    "terminal_boot_id",
    "terminal_monotonic_ns",
    "terminal_unix_ns",
    "elapsed_ns",
    "elapsed_clock",
    "terminal_evidence_sha256",
)
EXPECTED_SLOT_COLUMNS = (
    "slot_id",
    "state",
    "birth_binding_json",
    "birth_binding_sha256",
    "session_identity_sha256",
    "begun_boot_id",
    "begun_monotonic_ns",
    "begun_unix_ns",
    "begun_evidence_sha256",
    *TERMINAL_COLUMNS,
)

SLOTS_SCHEMA_SQL = """CREATE TABLE slots(
slot_id TEXT PRIMARY KEY NOT NULL,
state TEXT NOT NULL CHECK(state IN ('begun','terminal')),
birth_binding_json TEXT NOT NULL,
birth_binding_sha256 TEXT NOT NULL,
session_identity_sha256 TEXT NOT NULL,
begun_boot_id TEXT NOT NULL,
begun_monotonic_ns INTEGER NOT NULL,
begun_unix_ns INTEGER NOT NULL,
begun_evidence_sha256 TEXT NOT NULL,
terminal_payload_json TEXT,
terminal_payload_sha256 TEXT,
terminal_boot_id TEXT,
terminal_monotonic_ns INTEGER,
terminal_unix_ns INTEGER,
elapsed_ns INTEGER,
elapsed_clock TEXT,
terminal_evidence_sha256 TEXT,
CHECK(
 (state='begun' AND terminal_payload_json IS NULL AND terminal_payload_sha256 IS NULL AND terminal_boot_id IS NULL AND terminal_monotonic_ns IS NULL AND terminal_unix_ns IS NULL AND elapsed_ns IS NULL AND elapsed_clock IS NULL AND terminal_evidence_sha256 IS NULL)
 OR
 (state='terminal' AND terminal_payload_json IS NOT NULL AND terminal_payload_sha256 IS NOT NULL AND terminal_boot_id IS NOT NULL AND terminal_monotonic_ns IS NOT NULL AND terminal_unix_ns IS NOT NULL AND elapsed_ns IS NOT NULL AND elapsed_clock IS NOT NULL AND terminal_evidence_sha256 IS NOT NULL)
)
) STRICT"""


class SlotCaptureError(RuntimeError):
    pass


class SlotCaptureConflictError(SlotCaptureError):
    pass


class SlotCaptureIntegrityError(SlotCaptureError):
    pass


class SlotCaptureSessionError(SlotCaptureError):
    pass


class SessionAuthority(Protocol):
    """Server-owned session authority consumed by the evidence provider.

    Implementations must return only a non-secret stable digest.  The provider
    never accepts a caller-supplied session identity for begin/finalize.
    """

    def current_session_identity_sha256(self) -> str | None: ...

    def live_session_guard(
        self, session_identity_sha256: str
    ) -> AbstractContextManager[None]: ...

    def lost_session_guard(
        self, session_identity_sha256: str
    ) -> AbstractContextManager[None]: ...


@dataclass(frozen=True)
class ClockSample:
    boot_id: str
    monotonic_ns: int
    unix_ns: int


class ProviderClock(Protocol):
    def sample(self) -> ClockSample: ...


class SystemProviderClock:
    def sample(self) -> ClockSample:
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise SlotCaptureIntegrityError("provider boot identity is unavailable") from exc
        if not boot_id or len(boot_id) > 128 or any(ch in boot_id for ch in "\r\n\x00"):
            raise SlotCaptureIntegrityError("provider boot identity is invalid")
        if hasattr(time, "CLOCK_BOOTTIME"):
            monotonic_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        else:
            monotonic_ns = time.monotonic_ns()
        return ClockSample(
            boot_id=boot_id,
            monotonic_ns=monotonic_ns,
            unix_ns=time.time_ns(),
        )


def canonical_json_bytes(value: Any) -> bytes:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("slot capture value is not canonical JSON") from exc
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError("slot capture value exceeds the size bound")
    return payload


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_slot_id(value: Any) -> str:
    if not isinstance(value, str) or SLOT_ID_RE.fullmatch(value) is None:
        raise ValueError("slot_id must be a lowercase SHA-256")
    return value


def _validate_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SlotCaptureIntegrityError(f"{field} must be a lowercase SHA-256")
    return value


def _stored_nonnegative_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SlotCaptureIntegrityError(f"{field} must be a non-negative integer")
    return value


def _stored_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise SlotCaptureIntegrityError(f"{field} must be stored text")
    return value


def _normalize_object(value: Any, *, field: str) -> tuple[dict[str, Any], str, str]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    normalized = dict(value)
    payload = canonical_json_bytes(normalized)
    return normalized, payload.decode("utf-8"), hashlib.sha256(payload).hexdigest()


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is unsupported: {value}")


def _stored_canonical_object(
    value: Any, *, field: str
) -> tuple[dict[str, Any], str]:
    text = _stored_text(value, field=field)
    try:
        decoded = json.loads(text, parse_constant=_reject_nonfinite_json)
    except (json.JSONDecodeError, ValueError) as exc:
        raise SlotCaptureIntegrityError(f"{field} is invalid canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise SlotCaptureIntegrityError(f"{field} must contain an object")
    try:
        canonical = canonical_json_bytes(decoded).decode("utf-8")
    except ValueError as exc:
        raise SlotCaptureIntegrityError(f"{field} is not canonical JSON") from exc
    if text != canonical:
        raise SlotCaptureIntegrityError(f"{field} bytes are not canonical")
    return decoded, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_clock_sample(value: Any) -> ClockSample:
    if not isinstance(value, ClockSample):
        raise SlotCaptureIntegrityError("provider clock returned an invalid sample")
    if (
        not value.boot_id
        or len(value.boot_id) > 128
        or any(ch in value.boot_id for ch in "\r\n\x00")
        or isinstance(value.monotonic_ns, bool)
        or not isinstance(value.monotonic_ns, int)
        or value.monotonic_ns < 0
        or isinstance(value.unix_ns, bool)
        or not isinstance(value.unix_ns, int)
        or value.unix_ns < 0
    ):
        raise SlotCaptureIntegrityError("provider clock sample is invalid")
    return value


def _elapsed(begin: ClockSample, finish: ClockSample) -> tuple[int, str]:
    begin = _validate_clock_sample(begin)
    finish = _validate_clock_sample(finish)
    if begin.boot_id == finish.boot_id:
        if finish.monotonic_ns < begin.monotonic_ns:
            raise SlotCaptureIntegrityError("provider monotonic clock moved backwards")
        return finish.monotonic_ns - begin.monotonic_ns, "provider_boottime"
    if finish.unix_ns < begin.unix_ns:
        raise SlotCaptureIntegrityError("provider realtime clock moved backwards across boot")
    return finish.unix_ns - begin.unix_ns, "provider_realtime_cross_boot"


def _elapsed_seconds(elapsed_ns: int) -> float:
    return round(elapsed_ns / 1_000_000_000, 9)


def _public_nonclaims() -> list[str]:
    return [
        "bureau_candidate_identity_birth",
        "routing_authority",
        "queue_authority",
        "merge_authority",
        "deployment_authority",
        "runtime_policy_authority",
        "product_authority",
    ]


class SlotCaptureProvider:
    """Durable evidence-only absent -> begun -> terminal state machine.

    This core deliberately has no MCP, Bureau, routing, merge, deployment or
    product integration.  Session authority is injected by a server-owned
    adapter; callers cannot choose or reconstruct the session identity.
    """

    def __init__(
        self,
        database: Path = DEFAULT_DB,
        *,
        session_authority: SessionAuthority | None = None,
        clock: ProviderClock | None = None,
    ) -> None:
        self.database = Path(os.path.abspath(str(database.expanduser())))
        self.session_authority = session_authority
        self.clock = clock or SystemProviderClock()
        self._initialize()

    def _ensure_parent(self) -> None:
        parent = self.database.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            resolved_parent = parent.resolve(strict=True)
        except OSError as exc:
            raise SlotCaptureIntegrityError(
                "slot capture state root cannot be resolved exactly"
            ) from exc
        metadata = os.lstat(parent)
        if (
            resolved_parent != parent
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise SlotCaptureIntegrityError("slot capture state root is not private")
        if self.database.is_symlink():
            raise SlotCaptureIntegrityError("slot capture database may not be a symlink")
        if self.database.exists():
            database_metadata = os.lstat(self.database)
            if (
                not stat.S_ISREG(database_metadata.st_mode)
                or database_metadata.st_uid != os.getuid()
                or stat.S_IMODE(database_metadata.st_mode) & 0o077
                or database_metadata.st_nlink != 1
            ):
                raise SlotCaptureIntegrityError(
                    "slot capture database violates its private-file contract"
                )

    def _ensure_database_file(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.database, flags, 0o600)
        except FileExistsError:
            self._ensure_parent()
            return
        except OSError as exc:
            raise SlotCaptureIntegrityError(
                "slot capture database could not be created privately"
            ) from exc
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            directory_descriptor = os.open(self.database.parent, directory_flags)
        except OSError as exc:
            raise SlotCaptureIntegrityError(
                "slot capture state root cannot be durably opened"
            ) from exc
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        self._ensure_parent()

    @staticmethod
    def _normalize_schema_sql(value: str) -> str:
        return " ".join(value.split())

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != {"slots"}:
            raise SlotCaptureIntegrityError(
                "slot capture database schema tables are invalid"
            )
        schema_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='slots'"
        ).fetchone()
        if (
            schema_row is None
            or not isinstance(schema_row[0], str)
            or SlotCaptureProvider._normalize_schema_sql(schema_row[0])
            != SlotCaptureProvider._normalize_schema_sql(SLOTS_SCHEMA_SQL)
        ):
            raise SlotCaptureIntegrityError(
                "slot capture database schema definition is invalid"
            )
        table_info = [
            (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in connection.execute("PRAGMA table_info(slots)")
        ]
        expected_table_info = [
            ("slot_id", "TEXT", 1, 1),
            ("state", "TEXT", 1, 0),
            ("birth_binding_json", "TEXT", 1, 0),
            ("birth_binding_sha256", "TEXT", 1, 0),
            ("session_identity_sha256", "TEXT", 1, 0),
            ("begun_boot_id", "TEXT", 1, 0),
            ("begun_monotonic_ns", "INTEGER", 1, 0),
            ("begun_unix_ns", "INTEGER", 1, 0),
            ("begun_evidence_sha256", "TEXT", 1, 0),
            ("terminal_payload_json", "TEXT", 0, 0),
            ("terminal_payload_sha256", "TEXT", 0, 0),
            ("terminal_boot_id", "TEXT", 0, 0),
            ("terminal_monotonic_ns", "INTEGER", 0, 0),
            ("terminal_unix_ns", "INTEGER", 0, 0),
            ("elapsed_ns", "INTEGER", 0, 0),
            ("elapsed_clock", "TEXT", 0, 0),
            ("terminal_evidence_sha256", "TEXT", 0, 0),
        ]
        if tuple(name for name, _type, _required, _pk in table_info) != EXPECTED_SLOT_COLUMNS:
            raise SlotCaptureIntegrityError("slot capture database columns are invalid")
        if table_info != expected_table_info:
            raise SlotCaptureIntegrityError(
                "slot capture database column contract is invalid"
            )
        quick_check = [
            str(row[0]).lower() for row in connection.execute("PRAGMA quick_check")
        ]
        if quick_check != ["ok"]:
            raise SlotCaptureIntegrityError("slot capture database failed quick_check")

    @staticmethod
    def _validate_row_state_shape(row: sqlite3.Row) -> None:
        state = row["state"]
        terminal_values = [row[column] for column in TERMINAL_COLUMNS]
        if state == "begun":
            if any(value is not None for value in terminal_values):
                raise SlotCaptureIntegrityError("begun slot contains terminal fields")
            return
        if state == "terminal":
            if any(value is None for value in terminal_values):
                raise SlotCaptureIntegrityError("terminal slot is incomplete")
            return
        raise SlotCaptureIntegrityError("stored slot state is invalid")

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        self._ensure_parent()
        self._ensure_database_file()
        self._ensure_parent()
        connection = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()
        self._ensure_parent()

    def _initialize(self) -> None:
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version not in {0, SCHEMA_VERSION}:
                    raise SlotCaptureIntegrityError(
                        "slot capture database schema version is unsupported"
                    )
                existing_tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                if version == 0:
                    if existing_tables:
                        raise SlotCaptureIntegrityError(
                            "unversioned slot capture database is not empty"
                        )
                    connection.execute(SLOTS_SCHEMA_SQL)
                    self._validate_schema(connection)
                    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                else:
                    if existing_tables != {"slots"}:
                        raise SlotCaptureIntegrityError(
                            "versioned slot capture database is missing its exact schema"
                        )
                    self._validate_schema(connection)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            journal_mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "delete":
                raise SlotCaptureIntegrityError(
                    "slot capture database journal mode did not converge"
                )
        self._ensure_parent()

    def _current_session(self) -> str:
        if self.session_authority is None:
            raise SlotCaptureSessionError("server-owned session authority is unavailable")
        value = self.session_authority.current_session_identity_sha256()
        if value is None:
            raise SlotCaptureSessionError("current provider session is unavailable")
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise SlotCaptureSessionError("current provider session identity is invalid")
        return value

    @contextmanager
    def _live_session_guard(self, identity: str) -> Iterator[None]:
        if self.session_authority is None:
            raise SlotCaptureSessionError("server-owned session authority is unavailable")
        _validate_sha256(identity, field="session_identity_sha256")
        with self.session_authority.live_session_guard(identity):
            yield

    @contextmanager
    def _lost_session_guard(self, identity: str) -> Iterator[None]:
        if self.session_authority is None:
            raise SlotCaptureSessionError("server-owned session authority is unavailable")
        _validate_sha256(identity, field="session_identity_sha256")
        with self.session_authority.lost_session_guard(identity):
            yield

    @staticmethod
    def _begin_material(
        *,
        slot_id: str,
        birth_binding: dict[str, Any],
        birth_binding_sha256: str,
        session_identity_sha256: str,
        sample: ClockSample,
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "slot_id": slot_id,
            "state": "begun",
            "birth_binding": birth_binding,
            "birth_binding_sha256": birth_binding_sha256,
            "session_identity_sha256": session_identity_sha256,
            "begun_at": {
                "boot_id": sample.boot_id,
                "monotonic_ns": sample.monotonic_ns,
                "unix_ns": sample.unix_ns,
            },
            "does_not_establish": _public_nonclaims(),
        }

    @staticmethod
    def _begin_from_row(row: sqlite3.Row) -> dict[str, Any]:
        binding, binding_sha = _stored_canonical_object(
            row["birth_binding_json"], field="birth_binding_json"
        )
        if binding_sha != _validate_sha256(
            row["birth_binding_sha256"], field="birth_binding_sha256"
        ):
            raise SlotCaptureIntegrityError("stored birth binding digest mismatch")
        try:
            slot_id = _validate_slot_id(row["slot_id"])
        except ValueError as exc:
            raise SlotCaptureIntegrityError("stored slot_id is invalid") from exc
        sample = _validate_clock_sample(
            ClockSample(
                boot_id=_stored_text(row["begun_boot_id"], field="begun_boot_id"),
                monotonic_ns=_stored_nonnegative_int(
                    row["begun_monotonic_ns"], field="begun_monotonic_ns"
                ),
                unix_ns=_stored_nonnegative_int(
                    row["begun_unix_ns"], field="begun_unix_ns"
                ),
            )
        )
        material = SlotCaptureProvider._begin_material(
            slot_id=slot_id,
            birth_binding=binding,
            birth_binding_sha256=binding_sha,
            session_identity_sha256=_validate_sha256(
                row["session_identity_sha256"], field="session_identity_sha256"
            ),
            sample=sample,
        )
        digest = sha256_json(material)
        if digest != _validate_sha256(
            row["begun_evidence_sha256"], field="begun_evidence_sha256"
        ):
            raise SlotCaptureIntegrityError("stored begun evidence digest mismatch")
        return {**material, "evidence_sha256": digest}

    @staticmethod
    def _terminal_material(row: sqlite3.Row) -> dict[str, Any]:
        begun = SlotCaptureProvider._begin_from_row(row)
        payload, payload_sha = _stored_canonical_object(
            row["terminal_payload_json"], field="terminal_payload_json"
        )
        if payload_sha != _validate_sha256(
            row["terminal_payload_sha256"], field="terminal_payload_sha256"
        ):
            raise SlotCaptureIntegrityError("stored terminal payload digest mismatch")
        elapsed_ns = _stored_nonnegative_int(row["elapsed_ns"], field="elapsed_ns")
        terminal_sample = _validate_clock_sample(
            ClockSample(
                boot_id=_stored_text(
                    row["terminal_boot_id"], field="terminal_boot_id"
                ),
                monotonic_ns=_stored_nonnegative_int(
                    row["terminal_monotonic_ns"], field="terminal_monotonic_ns"
                ),
                unix_ns=_stored_nonnegative_int(
                    row["terminal_unix_ns"], field="terminal_unix_ns"
                ),
            )
        )
        elapsed_clock = _stored_text(row["elapsed_clock"], field="elapsed_clock")
        if elapsed_clock not in ELAPSED_CLOCKS:
            raise SlotCaptureIntegrityError("stored elapsed clock is invalid")
        material = {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "slot_id": begun["slot_id"],
            "state": "terminal",
            "birth_binding": begun["birth_binding"],
            "birth_binding_sha256": begun["birth_binding_sha256"],
            "session_identity_sha256": begun["session_identity_sha256"],
            "begun_at": begun["begun_at"],
            "begun_evidence_sha256": begun["evidence_sha256"],
            "terminal_payload": payload,
            "terminal_payload_sha256": payload_sha,
            "terminal_at": {
                "boot_id": terminal_sample.boot_id,
                "monotonic_ns": terminal_sample.monotonic_ns,
                "unix_ns": terminal_sample.unix_ns,
            },
            "elapsed_ns": elapsed_ns,
            "elapsed_seconds": _elapsed_seconds(elapsed_ns),
            "elapsed_clock": elapsed_clock,
            "does_not_establish": _public_nonclaims(),
        }
        digest = sha256_json(material)
        if digest != _validate_sha256(
            row["terminal_evidence_sha256"], field="terminal_evidence_sha256"
        ):
            raise SlotCaptureIntegrityError("stored terminal evidence digest mismatch")
        return {**material, "evidence_sha256": digest}

    @staticmethod
    def _row_readback(row: sqlite3.Row) -> dict[str, Any]:
        SlotCaptureProvider._validate_row_state_shape(row)
        state = row["state"]
        if state == "begun":
            return SlotCaptureProvider._begin_from_row(row)
        if state == "terminal":
            return SlotCaptureProvider._terminal_material(row)
        raise SlotCaptureIntegrityError("stored slot state is invalid")

    def read(self, slot_id: str) -> dict[str, Any]:
        identifier = _validate_slot_id(slot_id)
        with self._database() as connection:
            row = connection.execute(
                "SELECT * FROM slots WHERE slot_id=?", (identifier,)
            ).fetchone()
        if row is None:
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": KIND,
                "slot_id": identifier,
                "state": "absent",
                "evidence_sha256": None,
                "does_not_establish": _public_nonclaims(),
            }
        return self._row_readback(row)

    def begin(self, slot_id: str, birth_binding: Mapping[str, Any]) -> dict[str, Any]:
        identifier = _validate_slot_id(slot_id)
        binding, binding_json, binding_sha = _normalize_object(
            birth_binding, field="birth_binding"
        )
        session_identity = self._current_session()
        readback: dict[str, Any] | None = None
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM slots WHERE slot_id=?", (identifier,)
                ).fetchone()
                if row is None:
                    with self._live_session_guard(session_identity):
                        sample = _validate_clock_sample(self.clock.sample())
                        material = self._begin_material(
                            slot_id=identifier,
                            birth_binding=binding,
                            birth_binding_sha256=binding_sha,
                            session_identity_sha256=session_identity,
                            sample=sample,
                        )
                        evidence_sha = sha256_json(material)
                        connection.execute(
                            """
                            INSERT INTO slots(
                                slot_id,state,birth_binding_json,birth_binding_sha256,
                                session_identity_sha256,begun_boot_id,begun_monotonic_ns,
                                begun_unix_ns,begun_evidence_sha256
                            ) VALUES(?, 'begun', ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                identifier,
                                binding_json,
                                binding_sha,
                                session_identity,
                                sample.boot_id,
                                sample.monotonic_ns,
                                sample.unix_ns,
                                evidence_sha,
                            ),
                        )
                        row = connection.execute(
                            "SELECT * FROM slots WHERE slot_id=?", (identifier,)
                        ).fetchone()
                        if row is None:
                            raise SlotCaptureIntegrityError(
                                "begun slot disappeared before commit"
                            )
                        readback = self._row_readback(row)
                        connection.commit()
                    created = True
                else:
                    readback = self._row_readback(row)
                    if readback["birth_binding_sha256"] != binding_sha:
                        raise SlotCaptureConflictError(
                            "slot_id is already bound to a different birth binding"
                        )
                    connection.commit()
                    created = False
            except BaseException:
                connection.rollback()
                raise
        if readback is None:
            raise SlotCaptureIntegrityError("slot readback is unavailable after begin")
        return {
            **readback,
            "created": created,
            "replayed": not created,
            "session_matches_current": (
                readback["session_identity_sha256"] == session_identity
            ),
        }

    def _finish_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        terminal_payload: dict[str, Any],
        terminal_payload_json: str,
        terminal_payload_sha256: str,
        finish: ClockSample,
    ) -> sqlite3.Row:
        begin_sample = ClockSample(
            boot_id=str(row["begun_boot_id"]),
            monotonic_ns=int(row["begun_monotonic_ns"]),
            unix_ns=int(row["begun_unix_ns"]),
        )
        elapsed_ns, elapsed_clock = _elapsed(begin_sample, finish)
        begun = self._begin_from_row(row)
        material = {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "slot_id": begun["slot_id"],
            "state": "terminal",
            "birth_binding": begun["birth_binding"],
            "birth_binding_sha256": begun["birth_binding_sha256"],
            "session_identity_sha256": begun["session_identity_sha256"],
            "begun_at": begun["begun_at"],
            "begun_evidence_sha256": begun["evidence_sha256"],
            "terminal_payload": terminal_payload,
            "terminal_payload_sha256": terminal_payload_sha256,
            "terminal_at": {
                "boot_id": finish.boot_id,
                "monotonic_ns": finish.monotonic_ns,
                "unix_ns": finish.unix_ns,
            },
            "elapsed_ns": elapsed_ns,
            "elapsed_seconds": _elapsed_seconds(elapsed_ns),
            "elapsed_clock": elapsed_clock,
            "does_not_establish": _public_nonclaims(),
        }
        terminal_evidence_sha = sha256_json(material)
        cursor = connection.execute(
            """
            UPDATE slots SET
                state='terminal', terminal_payload_json=?, terminal_payload_sha256=?,
                terminal_boot_id=?, terminal_monotonic_ns=?, terminal_unix_ns=?,
                elapsed_ns=?, elapsed_clock=?, terminal_evidence_sha256=?
            WHERE slot_id=? AND state='begun'
            """,
            (
                terminal_payload_json,
                terminal_payload_sha256,
                finish.boot_id,
                finish.monotonic_ns,
                finish.unix_ns,
                elapsed_ns,
                elapsed_clock,
                terminal_evidence_sha,
                row["slot_id"],
            ),
        )
        if cursor.rowcount != 1:
            raise SlotCaptureConflictError("slot state changed before terminalization")
        updated = connection.execute(
            "SELECT * FROM slots WHERE slot_id=?", (row["slot_id"],)
        ).fetchone()
        if updated is None:
            raise SlotCaptureIntegrityError("terminal slot disappeared after persistence")
        return updated

    def finalize(self, slot_id: str, terminal_payload: Mapping[str, Any]) -> dict[str, Any]:
        identifier = _validate_slot_id(slot_id)
        payload, payload_json, payload_sha = _normalize_object(
            terminal_payload, field="terminal_payload"
        )
        terminal_readback: dict[str, Any] | None = None
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM slots WHERE slot_id=?", (identifier,)
                ).fetchone()
                if row is None:
                    raise SlotCaptureConflictError("slot is absent")
                self._validate_row_state_shape(row)
                if row["state"] == "terminal":
                    current = self._terminal_material(row)
                    if current["terminal_payload_sha256"] != payload_sha:
                        raise SlotCaptureConflictError(
                            "terminal slot already contains a different payload"
                        )
                    connection.commit()
                    return {**current, "created": False, "replayed": True}
                current_session = self._current_session()
                stored_session = _validate_sha256(
                    row["session_identity_sha256"], field="session_identity_sha256"
                )
                if stored_session != current_session:
                    raise SlotCaptureSessionError(
                        "current session does not own the begun slot"
                    )
                with self._live_session_guard(stored_session):
                    finish = _validate_clock_sample(self.clock.sample())
                    updated = self._finish_row(
                        connection,
                        row,
                        terminal_payload=payload,
                        terminal_payload_json=payload_json,
                        terminal_payload_sha256=payload_sha,
                        finish=finish,
                    )
                    terminal_readback = self._terminal_material(updated)
                    connection.commit()
            except BaseException:
                connection.rollback()
                raise
        if terminal_readback is None:
            raise SlotCaptureIntegrityError(
                "terminal readback is unavailable after finalization"
            )
        return {**terminal_readback, "created": True, "replayed": False}

    def terminalize_lost_session(self, slot_id: str) -> dict[str, Any]:
        identifier = _validate_slot_id(slot_id)
        payload = {
            "state": "indeterminate",
            "reason": "capture_session_lost",
        }
        payload_json = canonical_json_bytes(payload).decode("utf-8")
        payload_sha = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        terminal_readback: dict[str, Any] | None = None
        with self._database() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM slots WHERE slot_id=?", (identifier,)
                ).fetchone()
                if row is None:
                    raise SlotCaptureConflictError("slot is absent")
                self._validate_row_state_shape(row)
                if row["state"] == "terminal":
                    current = self._terminal_material(row)
                    if current["terminal_payload_sha256"] != payload_sha:
                        raise SlotCaptureConflictError(
                            "terminal slot already contains a different payload"
                        )
                    connection.commit()
                    return {**current, "created": False, "replayed": True}
                stored_session = _validate_sha256(
                    row["session_identity_sha256"], field="session_identity_sha256"
                )
                with self._lost_session_guard(stored_session):
                    finish = _validate_clock_sample(self.clock.sample())
                    updated = self._finish_row(
                        connection,
                        row,
                        terminal_payload=payload,
                        terminal_payload_json=payload_json,
                        terminal_payload_sha256=payload_sha,
                        finish=finish,
                    )
                    terminal_readback = self._terminal_material(updated)
                    connection.commit()
            except BaseException:
                connection.rollback()
                raise
        if terminal_readback is None:
            raise SlotCaptureIntegrityError(
                "terminal readback is unavailable after lost-session terminalization"
            )
        return {**terminal_readback, "created": True, "replayed": False}

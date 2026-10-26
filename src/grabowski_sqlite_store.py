from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from typing import TypeVar


FileIdentity = tuple[int, int, int, int, int]
ChangedError = TypeVar("ChangedError", bound=Exception)
INVENTORY_CHANGED_MESSAGE = (
    "Store changed while schema inventory was read; retry inventory"
)
COPY_CHUNK_BYTES = 1024 * 1024


def status_identity(status: os.stat_result) -> FileIdentity:
    return (
        status.st_dev,
        status.st_ino,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def file_identity(path: Path) -> FileIdentity:
    return status_identity(path.stat())


def _changed(
    error_type: type[ChangedError],
    message: str,
    *,
    cause: BaseException | None = None,
) -> ChangedError:
    error = error_type(message)
    if cause is not None:
        error.__cause__ = cause
    return error


def assert_identity(
    path: Path,
    expected: FileIdentity,
    *,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
) -> None:
    try:
        status = os.lstat(path)
    except FileNotFoundError as exc:
        raise _changed(error_type, message, cause=exc)
    if not stat.S_ISREG(status.st_mode) or status_identity(status) != expected:
        raise _changed(error_type, message)


def copy_regular_file(
    source: Path,
    target: Path,
    *,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
    max_bytes: int | None = None,
) -> FileIdentity:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)
    try:
        before_status = os.fstat(descriptor)
        if not stat.S_ISREG(before_status.st_mode):
            raise _changed(error_type, message)
        before = status_identity(before_status)
        with os.fdopen(os.dup(descriptor), "rb") as source_handle:
            with target.open("xb") as target_handle:
                copied = 0
                while chunk := source_handle.read(COPY_CHUNK_BYTES):
                    # A source that grows while it is streamed never writes
                    # past the caller's budget.
                    copied += len(chunk)
                    if max_bytes is not None and copied > max_bytes:
                        raise _changed(error_type, message)
                    target_handle.write(chunk)
        os.chmod(target, 0o600)
        target_status = os.lstat(target)
        if (
            not stat.S_ISREG(target_status.st_mode)
            or target_status.st_size != before_status.st_size
        ):
            raise _changed(error_type, message)
        if status_identity(os.fstat(descriptor)) != before:
            raise _changed(error_type, message)
        assert_identity(source, before, error_type=error_type, message=message)
        return before
    finally:
        os.close(descriptor)


@contextmanager
def schema_directory_lock(parent: Path) -> Iterator[None]:
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
def readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
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


@contextmanager
def inventory_readonly_sqlite(
    path: Path,
    *,
    temporary_prefix: str,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
    allow_wal_copy: bool = True,
    allow_checkpointed_empty_wal: bool = False,
    max_copy_bytes: int | None = None,
) -> Iterator[sqlite3.Connection]:
    wal_path = Path(str(path) + "-wal")
    wal_present = wal_path.exists() or wal_path.is_symlink()
    shm_path = Path(str(path) + "-shm")
    if not allow_wal_copy and not allow_checkpointed_empty_wal and (
        wal_present or shm_path.exists() or shm_path.is_symlink()
    ):
        raise _changed(error_type, "Strict read-only snapshot unavailable while SQLite WAL sidecars exist")
    # Explicit opt-in: a checkpointed, zero-length WAL contains no committed frames.  It can
    # safely be ignored by the immutable reader, but ONLY if the database and
    # every pre-existing sidecar retain their exact inode/stat identity through
    # the observation.  Active/nonempty WAL still fails strict READ_ONLY.
    empty_wal_identity: FileIdentity | None = None
    shm_identity: FileIdentity | None = None
    if not allow_wal_copy:
        try:
            if wal_present:
                wal_status = os.lstat(wal_path)
                if not stat.S_ISREG(wal_status.st_mode) or wal_status.st_size != 0:
                    raise _changed(
                        error_type,
                        "Strict read-only snapshot unavailable while SQLite WAL sidecars exist",
                    )
                empty_wal_identity = status_identity(wal_status)
            if shm_path.exists() or shm_path.is_symlink():
                if empty_wal_identity is None:
                    raise _changed(
                        error_type,
                        "Strict read-only snapshot unavailable while SQLite WAL sidecars exist",
                    )
                shm_status = os.lstat(shm_path)
                if not stat.S_ISREG(shm_status.st_mode):
                    raise _changed(
                        error_type,
                        "Strict read-only snapshot unavailable while SQLite WAL sidecars exist",
                    )
                shm_identity = status_identity(shm_status)
        except OSError as exc:
            raise _changed(error_type, message, cause=exc)
    if not wal_present or empty_wal_identity is not None:
        before_identity = file_identity(path)
        connection = sqlite3.connect(
            path.absolute().as_uri() + "?mode=ro&immutable=1",
            uri=True,
            timeout=1,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        try:
            yield connection
        finally:
            connection.close()
            assert_identity(
                path,
                before_identity,
                error_type=error_type,
                message=message,
            )
            if empty_wal_identity is not None:
                assert_identity(
                    wal_path, empty_wal_identity,
                    error_type=error_type, message=message,
                )
            elif wal_path.exists() or wal_path.is_symlink():
                raise _changed(error_type, message)
            if shm_identity is not None:
                assert_identity(
                    shm_path, shm_identity,
                    error_type=error_type, message=message,
                )
            elif not allow_wal_copy and (shm_path.exists() or shm_path.is_symlink()):
                raise _changed(error_type, message)
        return

    with tempfile.TemporaryDirectory(prefix=temporary_prefix) as temporary_directory:
        snapshot = Path(temporary_directory) / path.name
        snapshot_wal = Path(str(snapshot) + "-wal")
        database_identity = copy_regular_file(
            path,
            snapshot,
            error_type=error_type,
            message=message,
            max_bytes=max_copy_bytes,
        )
        wal_identity = copy_regular_file(
            wal_path,
            snapshot_wal,
            error_type=error_type,
            message=message,
            max_bytes=(
                None
                if max_copy_bytes is None
                else max_copy_bytes - database_identity[2]
            ),
        )
        connection = sqlite3.connect(snapshot, timeout=1)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        try:
            yield connection
        finally:
            connection.close()
            assert_identity(
                path,
                database_identity,
                error_type=error_type,
                message=message,
            )
            assert_identity(
                wal_path,
                wal_identity,
                error_type=error_type,
                message=message,
            )


@contextmanager
def inventory_native_wal_readonly_sqlite(
    path: Path,
    *,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
) -> Iterator[sqlite3.Connection]:
    """Read one SQLite WAL transaction, never copy moving WAL bytes.

    Only internal checkout admission uses this mode. A pinned SQLite read
    transaction gives a consistent table image while legitimate WAL writers
    continue. All source filenames must already exist as ordinary, singly
    linked files inside a private directory; SQLite must not create -shm.
    This is not a same-UID hostile-path-swap or privileged issuer boundary.
    """
    path = path.absolute()
    directory = path.parent
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")

    def identity(file: Path, *, directory_entry: bool = False) -> tuple[int, int, int, int]:
        try:
            info = os.lstat(file)
        except OSError as exc:
            raise _changed(error_type, message, cause=exc)
        correct_type = (
            stat.S_ISDIR(info.st_mode)
            if directory_entry
            else stat.S_ISREG(info.st_mode)
        )
        if (
            not correct_type
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
            or (not directory_entry and info.st_nlink != 1)
        ):
            raise _changed(error_type, message)
        return (info.st_dev, info.st_ino, info.st_uid, info.st_nlink)

    if directory.resolve(strict=True) != directory:
        raise _changed(error_type, message)
    original = {
        directory: identity(directory, directory_entry=True),
        path: identity(path),
        wal: identity(wal),
        shm: identity(shm),
    }

    def assert_origin() -> None:
        for filename, expected in original.items():
            if identity(
                filename, directory_entry=(filename == directory),
            ) != expected:
                raise _changed(error_type, message)

    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            path.as_uri() + "?mode=ro", uri=True, timeout=1,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
            raise _changed(error_type, message)
        assert_origin()
        connection.execute("BEGIN")
        # BEGIN is lazy: read sqlite_master now to pin one WAL snapshot before
        # returning control to the caller's multi-statement inventory.
        connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
        yield connection
        assert_origin()
    except sqlite3.Error as exc:
        raise _changed(error_type, message, cause=exc)
    finally:
        if connection is not None:
            # The outer inventory scope can outlive individual legacy readers
            # that explicitly close their handle. SQLite connection.close()
            # safely releases a pinned read-only WAL transaction and is
            # idempotent; rollback() on an already-closed handle would raise
            # ProgrammingError and hide the actual observation result.
            connection.close()


@contextmanager
def inventory_coherent_readonly_sqlite(
    path: Path,
    *,
    temporary_prefix: str,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
    allow_checkpointed_empty_wal: bool = False,
) -> Iterator[sqlite3.Connection]:
    """Observe a pinned WAL transaction or a quiescent immutable database.

    An existing WAL+SHM pair is normal SQLite operation, not a reason to
    report an unavailable inventory. Never make, delete or checkpoint sidecars:
    a missing half of a pair still fails closed rather than letting SQLite
    create SHM during observation.
    """
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    if (wal.exists() or wal.is_symlink()) and (shm.exists() or shm.is_symlink()):
        with inventory_native_wal_readonly_sqlite(
            path, error_type=error_type, message=message,
        ) as connection:
            yield connection
    else:
        with inventory_readonly_sqlite(
            path,
            temporary_prefix=temporary_prefix,
            error_type=error_type,
            message=message,
            allow_wal_copy=False,
            allow_checkpointed_empty_wal=allow_checkpointed_empty_wal,
        ) as connection:
            yield connection


def sqlite_integrity(
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


def sqlite_fingerprint(connection: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    for statement in connection.iterdump():
        digest.update(statement.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def database_tables(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }

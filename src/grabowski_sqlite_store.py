from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import os
import selectors
import signal
import time
from pathlib import Path
import sqlite3
import subprocess
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
                while chunk := source_handle.read(COPY_CHUNK_BYTES):
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
) -> Iterator[sqlite3.Connection]:
    wal_path = Path(str(path) + "-wal")
    wal_present = wal_path.exists() or wal_path.is_symlink()
    if not wal_present:
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
            if wal_path.exists() or wal_path.is_symlink():
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
        )
        wal_identity = copy_regular_file(
            wal_path,
            snapshot_wal,
            error_type=error_type,
            message=message,
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


# Scoped mutation admission cannot create even a temporary host-side copy of a
# WAL-backed state database. In particular, the schema-inventory helper above
# is intentionally NOT suitable for a pre-authorization read: it materializes
# the WAL in tempfile.TemporaryDirectory.
_PREAUTH_WAL_MAX_STORE_BYTES = 128 * 1024 * 1024
_PREAUTH_WAL_MAX_DUMP_BYTES = 64 * 1024 * 1024
_PREAUTH_WAL_DUMP_CODE = """
import resource
import sqlite3
import sys

# The untrusted database must not induce unbounded helper memory/CPU usage.
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CPU, (10, 11))
source = sqlite3.connect(
    "file:" + sys.argv[1] + "?mode=ro", uri=True, timeout=2,
)
source.execute("PRAGMA trusted_schema=OFF")
source.execute("PRAGMA query_only=ON")
source.execute("BEGIN")
total = 0
try:
    for statement in source.iterdump():
        if len(statement) > 16 * 1024 * 1024:
            raise RuntimeError("Oversized SQL record in WAL snapshot")
        raw = (statement + chr(10)).encode("utf-8")
        total += len(raw)
        if total > 64 * 1024 * 1024:
            raise RuntimeError("Scoped WAL snapshot exceeds size limit")
        sys.stdout.buffer.write(raw)
finally:
    source.close()
"""


@contextmanager
def preauthorization_readonly_sqlite(
    path: Path,
    *,
    error_type: type[ChangedError],
) -> Iterator[sqlite3.Connection]:
    """Give pre-gate callers one SQLite snapshot without host filesystem writes.

    For rollback-mode stores, immutable=1 is sufficient. An active WAL MUST
    be consumed, never silently ignored by immutable=1. Obtain that snapshot
    inside a kernel-enforced read-only mount namespace; the fixed helper reads
    the source WAL through SQLite's native reader and emits a bounded SQL
    stream. Reconstruct exclusively in the parent's private SQLite :memory:
    database, which also avoids reading the untrusted WAL without SQLite's
    transactional locks. No host temporary directory, DB chmod or shm write is
    authorized by this operation. If bubblewrap or the kernel is unavailable,
    deny the recovery rather than falling back to a writable DB connection.
    """
    if path.parent.is_symlink() or path.is_symlink():
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)
    wal_path = Path(str(path) + "-wal")
    if not wal_path.exists() and not wal_path.is_symlink():
        with inventory_readonly_sqlite(
            path, temporary_prefix="unused-no-wal-", error_type=error_type
        ) as connection:
            yield connection
        return
    if wal_path.is_symlink():
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)
    try:
        main_status, wal_status = os.lstat(path), os.lstat(wal_path)
    except OSError as exc:
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE, cause=exc)
    if (
        not stat.S_ISREG(main_status.st_mode)
        or not stat.S_ISREG(wal_status.st_mode)
        or max(main_status.st_size, wal_status.st_size)
        > _PREAUTH_WAL_MAX_STORE_BYTES
    ):
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)
    main_identity, wal_identity = (
        status_identity(main_status), status_identity(wal_status)
    )
    # The source's *containing directory* is mounted read-only. bubblewrap's
    # private /tmp is tmpfs and cannot persist an interrupted snapshot on the
    # host. No symlinked parent or database file is accepted at this boundary.
    argv = [
        "/usr/bin/bwrap",
        "--die-with-parent", "--new-session", "--unshare-user",
        "--unshare-pid", "--unshare-ipc", "--unshare-uts",
        "--unshare-net",
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
    ]
    if Path("/usr/lib64").is_dir():
        argv.extend(["--symlink", "usr/lib64", "/lib64"])
    argv.extend(
        [
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            # The helper must only see the required two regular source files.
            # /snapshot is private tmpfs so SQLite may create its own -shm.
            "--tmpfs", "/snapshot",
            "--ro-bind", str(path.absolute()), "/snapshot/input.db",
            "--ro-bind", str(wal_path.absolute()), "/snapshot/input.db-wal",
            "--clearenv", "--setenv", "HOME", "/tmp",
            "--chdir", "/tmp",
            "--", "/usr/bin/python3", "-I", "-S", "-c",
            _PREAUTH_WAL_DUMP_CODE, "/snapshot/input.db",
        ]
    )
    # subprocess.run(capture_output=True) accumulates unbounded output before
    # enforcing an after-the-fact limit. Read only up to the hard budget and
    # kill the isolated process group on overflow, error or deadline.
    process = None
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
        )
        if process.stdout is None:
            raise RuntimeError("WAL helper stdout unavailable")
        output = bytearray()
        deadline = time.monotonic() + 12
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("Scoped WAL snapshot timed out")
                data = os.read(
                    process.stdout.fileno(),
                    min(65536, _PREAUTH_WAL_MAX_DUMP_BYTES + 1 - len(output)),
                )
                if not data:
                    break
                output.extend(data)
                if len(output) > _PREAUTH_WAL_MAX_DUMP_BYTES:
                    raise ValueError("Scoped WAL snapshot exceeds output limit")
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0 or not output:
            raise ValueError("Scoped WAL snapshot failed")
    except (OSError, subprocess.SubprocessError, TimeoutError, RuntimeError, ValueError) as exc:
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE, cause=exc)
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            if process.stdout is not None:
                process.stdout.close()
    assert_identity(path, main_identity, error_type=error_type)
    assert_identity(wal_path, wal_identity, error_type=error_type)
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA trusted_schema=OFF")
        # sqlite3's dump contains source DDL and data. Defense in depth:
        # do not let a corrupt/untrusted source attach a real host database,
        # create virtual tables or run PRAGMAs / host extension functions.
        forbidden_actions = {
            sqlite3.SQLITE_ATTACH,
            sqlite3.SQLITE_DETACH,
            sqlite3.SQLITE_CREATE_VTABLE,
            sqlite3.SQLITE_DROP_VTABLE,
            # Schema triggers are recreated after inserts by sqlite3.iterdump.
            # Restore them but never enable external attachment or VTABLE.
            sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_CREATE_TEMP_VIEW,
            sqlite3.SQLITE_PRAGMA,
        }

        def authorize_restore(
            action: int, arg1: str | None, arg2: str | None,
            database: str | None, source: str | None,
        ) -> int:
            if action in forbidden_actions or database not in {None, "main"}:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() == "load_extension":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorize_restore)
        dump = output.decode("utf-8", errors="strict")
        connection.executescript(dump)
        # Python 3.10 does not reliably clear a callback with None. Keep a
        # read-only authorizer after the schema restore instead.
        readonly_actions = {
            sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
            sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_PRAGMA,
            sqlite3.SQLITE_TRANSACTION,
        }

        def authorize_readonly(action, _a, _b, _database, _source):
            return sqlite3.SQLITE_OK if action in readonly_actions else sqlite3.SQLITE_DENY

        connection.set_authorizer(authorize_readonly)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        yield connection
    finally:
        connection.close()
        assert_identity(path, main_identity, error_type=error_type)
        assert_identity(wal_path, wal_identity, error_type=error_type)



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
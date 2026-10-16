from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import json
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


# Pre-admission inspection is not permitted to create a host WAL/SHM/tempfile.
# SQLite parsing, schema evaluation, and all queries remain in the constrained
# child. No SQL from the inspected database is ever executed by the host.
_PREAUTH_WAL_MAX_STORE_BYTES = 128 * 1024 * 1024
_PREAUTH_WAL_MAX_DUMP_BYTES = 64 * 1024 * 1024
_PREAUTH_WAL_MAX_REQUEST_BYTES = 32 * 1024
_PREAUTH_WAL_TIMEOUT_SECONDS = 12
_PREAUTH_WAL_QUERY_CODE = r"""
import base64
import json
import resource
import sqlite3
import sys

resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_CPU, (10, 11))
source = sqlite3.connect("file:/snapshot/input.db?mode=ro", uri=True, timeout=2)
source.execute("PRAGMA trusted_schema=OFF")
source.execute("PRAGMA query_only=ON")

# Reject any attempt to use the child as a general SQL execution service.
# These calls are issued only by the operator's fixed preauthorization code,
# not by any caller-provided task command or database schema.
read_actions = {
    sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
    sqlite3.SQLITE_PRAGMA, sqlite3.SQLITE_TRANSACTION,
}
def authorize(action, arg1, arg2, database, origin):
    if action not in read_actions or database not in (None, "main"):
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() == "load_extension":
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK

source.set_authorizer(authorize)
source.execute("BEGIN")
# Acquire a consistent read transaction before admitting the first query.
source.execute("SELECT count(*) FROM sqlite_master").fetchone()

def convert(value):
    if isinstance(value, bytes):
        return {"__sqlite_blob_base64__": base64.b64encode(value).decode("ascii")}
    return value

sys.stdout.write('{"ready":true}\n')
sys.stdout.flush()
try:
    for line in sys.stdin.buffer:
        if len(line) > 32768:
            raise RuntimeError("oversized WAL query")
        request = json.loads(line)
        if not isinstance(request, dict) or set(request) != {"sql", "args"}:
            raise RuntimeError("invalid WAL query")
        sql, args = request["sql"], request["args"]
        if not isinstance(sql, str) or len(sql) > 8192 or not isinstance(args, list):
            raise RuntimeError("invalid WAL query shape")
        cursor = source.execute(sql, args)
        names = [col[0] for col in cursor.description] if cursor.description else []
        rows = []
        total = 0
        for record in cursor:
            values = [convert(value) for value in record]
            total += len(json.dumps(values, ensure_ascii=True))
            if len(rows) >= 20000 or total > 32 * 1024 * 1024:
                raise RuntimeError("WAL query result exceeds resource limit")
            rows.append(values)
        output = json.dumps(
            {"columns": names, "rows": rows}, ensure_ascii=True, separators=(",", ":")
        )
        if len(output.encode("utf-8")) > 64 * 1024 * 1024:
            raise RuntimeError("WAL response exceeds output limit")
        sys.stdout.write(output + "\n")
        sys.stdout.flush()
finally:
    source.close()
"""


class _WALReadRow:
    """Only the read-only SQLite Row interface used by scoped admissions."""

    def __init__(self, columns: list[str], values: list[object]) -> None:
        self._columns = columns
        self._values = values

    def keys(self) -> list[str]:
        return list(self._columns)

    def __getitem__(self, key: int | str) -> object:
        if isinstance(key, str):
            # sqlite3.Row names are case-insensitive.
            key_lower = key.lower()
            for index, column in enumerate(self._columns):
                if column.lower() == key_lower:
                    return self._values[index]
            raise IndexError(key)
        return self._values[key]

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Iterator[object]:
        return iter(self._values)


class _WALReadCursor:
    def __init__(self, columns: list[str], rows: list[_WALReadRow]) -> None:
        self.description = [(name, None, None, None, None, None, None) for name in columns]
        self._rows = rows
        self._offset = 0

    def fetchone(self) -> _WALReadRow | None:
        if self._offset >= len(self._rows):
            return None
        row = self._rows[self._offset]
        self._offset += 1
        return row

    def fetchall(self) -> list[_WALReadRow]:
        rows = self._rows[self._offset:]
        self._offset = len(self._rows)
        return rows

    def fetchmany(self, size: int = 1) -> list[_WALReadRow]:
        if type(size) is not int or size < 0:
            raise ValueError("Invalid bounded fetch size")
        end = min(len(self._rows), self._offset + size)
        rows = self._rows[self._offset:end]
        self._offset = end
        return rows

    def __iter__(self) -> Iterator[_WALReadRow]:
        while (row := self.fetchone()) is not None:
            yield row


class _WALReadConnection:
    """Bounded read-only query proxy; never compiles database SQL in the host."""

    def __init__(
        self, process: subprocess.Popen[bytes],
        *, deadline: float, error_type: type[ChangedError],
    ) -> None:
        self.process = process
        self.deadline = deadline
        self.error_type = error_type
        self._pending = bytearray()
        if self._read_line() != {"ready": True}:
            raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)

    def _wait(self, file, events: int) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Scoped WAL preauthorization timed out")
        with selectors.DefaultSelector() as selector:
            selector.register(file, events)
            if not selector.select(remaining):
                raise TimeoutError("Scoped WAL preauthorization timed out")

    def _child_eof_diagnostic(self) -> str:
        """Report a fixed failure class, never raw child stderr or state paths.

        A broken bwrap/namespace setup must remain an authorization failure,
        but a bare EOF is insufficient to distinguish it from SQLite errors.
        Reading at most one nonblocking stderr sample avoids a new pipe hang.
        """
        status = self.process.poll()
        captured = b""
        if self.process.stderr is not None:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(self.process.stderr, selectors.EVENT_READ)
                    if selector.select(0):
                        captured = os.read(self.process.stderr.fileno(), 4096)
            except (OSError, ValueError):
                pass
        category = "unknown"
        if b"bwrap:" in captured:
            if b"NETLINK_ROUTE" in captured or b"loopback:" in captured:
                category = "sandbox-network"
            elif b"Permission denied" in captured or b"Operation not permitted" in captured:
                category = "sandbox-permission"
            else:
                category = "sandbox-startup"
        elif b"MemoryError" in captured:
            category = "child-memory"
        elif b"sqlite3." in captured:
            category = "child-sqlite"
        elif captured:
            category = "child-startup"
        return f"Unexpected WAL child EOF (exit={status}, class={category})"

    def _read_line(self) -> dict:
        if self.process.stdout is None:
            raise RuntimeError("WAL child stdout unavailable")
        while True:
            boundary = self._pending.find(b"\n")
            if boundary >= 0:
                raw = bytes(self._pending[:boundary])
                del self._pending[:boundary + 1]
                response = json.loads(raw)
                if not isinstance(response, dict):
                    raise ValueError("Invalid WAL response")
                return response
            if len(self._pending) >= _PREAUTH_WAL_MAX_DUMP_BYTES:
                raise ValueError("WAL response over size limit")
            self._wait(self.process.stdout, selectors.EVENT_READ)
            data = os.read(
                self.process.stdout.fileno(),
                min(65536, _PREAUTH_WAL_MAX_DUMP_BYTES + 1 - len(self._pending)),
            )
            if not data:
                raise ValueError(self._child_eof_diagnostic())
            self._pending.extend(data)
            if len(self._pending) > _PREAUTH_WAL_MAX_DUMP_BYTES:
                raise ValueError("WAL response over size limit")

    def execute(self, sql: str, parameters: object = ()) -> _WALReadCursor:
        if not isinstance(sql, str) or len(sql) > 8192:
            raise _changed(self.error_type, INVENTORY_CHANGED_MESSAGE)
        if not isinstance(parameters, (list, tuple)):
            raise _changed(self.error_type, INVENTORY_CHANGED_MESSAGE)
        if self.process.stdin is None:
            raise _changed(self.error_type, INVENTORY_CHANGED_MESSAGE)
        request = (json.dumps(
            {"sql": sql, "args": list(parameters)}, ensure_ascii=True,
            separators=(",", ":"),
        ) + "\n").encode("utf-8")
        if len(request) > _PREAUTH_WAL_MAX_REQUEST_BYTES:
            raise _changed(self.error_type, INVENTORY_CHANGED_MESSAGE)
        try:
            offset = 0
            while offset < len(request):
                self._wait(self.process.stdin, selectors.EVENT_WRITE)
                offset += os.write(self.process.stdin.fileno(), request[offset:])
            response = self._read_line()
            columns, rows = response["columns"], response["rows"]
            if (
                not isinstance(columns, list) or not isinstance(rows, list)
                or len(rows) > 20000
                or any(not isinstance(name, str) for name in columns)
            ):
                raise ValueError("Invalid WAL query result")
            parsed = []
            for values in rows:
                if not isinstance(values, list) or len(values) != len(columns):
                    raise ValueError("Invalid WAL query row")
                converted: list[object] = []
                for value in values:
                    if isinstance(value, dict) and set(value) == {"__sqlite_blob_base64__"}:
                        import base64
                        converted.append(base64.b64decode(
                            value["__sqlite_blob_base64__"], validate=True
                        ))
                    elif value is None or isinstance(value, (str, int, float)):
                        converted.append(value)
                    else:
                        raise ValueError("Invalid WAL query scalar")
                parsed.append(_WALReadRow(columns, converted))
            return _WALReadCursor(columns, parsed)
        except (OSError, TimeoutError, ValueError, KeyError, TypeError,
                json.JSONDecodeError, subprocess.SubprocessError) as exc:
            raise _changed(self.error_type, INVENTORY_CHANGED_MESSAGE, cause=exc)


@contextmanager
def preauthorization_readonly_sqlite(
    path: Path,
    *,
    error_type: type[ChangedError],
) -> Iterator[sqlite3.Connection]:
    """Pre-gate read: rollback store immutable, WAL store pinned + isolated.

    Existing valid WAL snapshots are read inside a bounded, network-isolated
    child that owns SQLite parsing and query evaluation; only typed row data
    crosses back to the operator. FDs pin the database and WAL before
    Bubblewrap, excluding same-UID pathname substitution during its launch.
    No SQL dump or schema expressions execute in the main process.
    """
    if path.parent.is_symlink() or path.is_symlink():
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)
    wal_path = Path(str(path) + "-wal")
    if not wal_path.exists() and not wal_path.is_symlink():
        with inventory_readonly_sqlite(
            path, temporary_prefix="unused-no-wal-", error_type=error_type,
            allow_wal_copy=False,
        ) as connection:
            yield connection
        return
    if wal_path.is_symlink():
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)
    process = None
    descriptors: list[int] = []
    identities: list[FileIdentity] = []
    parent_identity = None
    inside_caller_scope = False
    try:
        directory = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        descriptors.append(directory)
        parent_status = os.fstat(directory)
        original_parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent_status.st_mode) or (
            parent_status.st_dev, parent_status.st_ino
        ) != (original_parent.st_dev, original_parent.st_ino):
            raise ValueError("WAL directory identity drift")
        parent_identity = (parent_status.st_dev, parent_status.st_ino)
        for filename, original in ((path.name, path), (wal_path.name, wal_path)):
            before = os.lstat(original)
            descriptor = os.open(
                filename, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode) or not stat.S_ISREG(opened.st_mode)
                or status_identity(before) != status_identity(opened)
                or opened.st_size > _PREAUTH_WAL_MAX_STORE_BYTES
            ):
                raise ValueError("WAL descriptor identity drift")
            identities.append(status_identity(opened))
        main_fd, wal_fd = descriptors[1], descriptors[2]
        argv = [
            "/usr/bin/bwrap",
            "--die-with-parent", "--new-session", "--unshare-user",
            "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
            "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
        ]
        if Path("/usr/lib64").is_dir():
            argv.extend(["--symlink", "usr/lib64", "/lib64"])
        argv.extend([
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--tmpfs", "/snapshot",
            # Copy directly from verified descriptors inside private bwrap.
            # /proc/self/fd/N path mounts fail for an unlinked WAL inode;
            # --ro-bind-data avoids a second pathname resolution and never
            # creates a preauthorization snapshot on the host filesystem.
            "--ro-bind-data", str(main_fd), "/snapshot/input.db",
            "--ro-bind-data", str(wal_fd), "/snapshot/input.db-wal",
            "--clearenv", "--setenv", "HOME", "/tmp", "--chdir", "/tmp",
            "--", "/usr/bin/python3", "-I", "-S", "-c",
            _PREAUTH_WAL_QUERY_CODE,
        ])
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True,
            pass_fds=(main_fd, wal_fd), start_new_session=True,
        )
        connection = _WALReadConnection(
            process, deadline=time.monotonic() + _PREAUTH_WAL_TIMEOUT_SECONDS,
            error_type=error_type,
        )
        inside_caller_scope = True
        yield connection
    except (OSError, ValueError, TimeoutError, RuntimeError, subprocess.SubprocessError) as exc:
        # A caller's scoped PermissionError/ValueError is an authorization or
        # input decision, not a SQLite transport error. Preserve its identity.
        if inside_caller_scope:
            raise
        raise _changed(error_type, INVENTORY_CHANGED_MESSAGE, cause=exc)
    finally:
        if process is not None:
            # Allow the bounded read-only child to finish SQLite cleanup after
            # stdin EOF. On a stalled child, retain the existing kill boundary.
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
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
            if process.stderr is not None:
                process.stderr.close()
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if identities:
            assert_identity(path, identities[0], error_type=error_type)
        if len(identities) == 2:
            assert_identity(wal_path, identities[1], error_type=error_type)
        if parent_identity is not None:
            observed = os.lstat(path.parent)
            if (observed.st_dev, observed.st_ino) != parent_identity:
                raise _changed(error_type, INVENTORY_CHANGED_MESSAGE)


@contextmanager
def inventory_readonly_sqlite(
    path: Path,
    *,
    temporary_prefix: str,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
    allow_wal_copy: bool = True,
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

    # Pre-authorization callers must fail closed if a WAL appears between
    # their no-WAL check and this inventory probe. Never fall back to a host
    # snapshot copy before a scoped mutation gate has granted authority.
    if not allow_wal_copy:
        raise _changed(error_type, message)

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
            try:
                connection.rollback()
            finally:
                connection.close()


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

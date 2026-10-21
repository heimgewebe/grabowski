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
STRICT_PRIVATE_WAL_MAX_BYTES = 2 * 1024 * 1024 * 1024
STRICT_PRIVATE_WAL_FREE_RESERVE = 64 * 1024 * 1024
STRICT_PRIVATE_WAL_MAX_WAL_BYTES = 32 * 1024 * 1024


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



def _strict_wal_file_fingerprint(
    path: Path,
    *,
    error_type: type[ChangedError],
    message: str,
    optional: bool = False,
) -> tuple[FileIdentity, str] | None:
    """Pin a named, owner-private regular file and hash actual bytes through its fd."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        if optional and not path.is_symlink():
            return None
        raise _changed(error_type, message, cause=exc)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)
    try:
        before = os.fstat(descriptor)
        def identity(info: os.stat_result) -> tuple[FileIdentity, int, int, int]:
            return (
                status_identity(info), info.st_uid,
                stat.S_IMODE(info.st_mode), info.st_nlink,
            )
        expected = identity(before)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or (
                before.st_mode & 0o077
                and not (
                    (parent := os.stat(path.parent)).st_uid == os.geteuid()
                    and stat.S_ISDIR(parent.st_mode)
                    and not parent.st_mode & 0o077
                )
            )
            or before.st_nlink != 1
        ):
            raise _changed(error_type, message)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, COPY_CHUNK_BYTES):
            digest.update(chunk)
        try:
            named = os.lstat(path)
        except OSError as exc:
            raise _changed(error_type, message, cause=exc)
        if identity(os.fstat(descriptor)) != expected or identity(named) != expected:
            raise _changed(error_type, message)
        return status_identity(before), digest.hexdigest()
    finally:
        os.close(descriptor)


def _strict_wal_memory_root(
    *, error_type: type[ChangedError], message: str,
) -> Path:
    """Require private tmpfs with no plaintext disk swap; never fall back to /tmp."""
    root = Path("/dev/shm")
    try:
        info = os.lstat(root)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o1777
            or root.resolve(strict=True) != root
        ):
            raise _changed(error_type, message)
        # A later overmount supersedes earlier /dev/shm mountinfo entries.
        last_mount_type = None
        with Path("/proc/self/mountinfo").open(encoding="utf-8") as mounted:
            for line in mounted:
                if " - " not in line:
                    raise _changed(error_type, message)
                left, right = line.rstrip("\n").split(" - ", 1)
                columns, filesystem = left.split(), right.split()
                if len(columns) < 5 or not filesystem:
                    raise _changed(error_type, message)
                if columns[4] == "/dev/shm":
                    last_mount_type = filesystem[0]
        if last_mount_type != "tmpfs":
            raise _changed(error_type, message)
        with Path("/proc/swaps").open(encoding="utf-8") as swaps:
            next(swaps)
            for line in swaps:
                device = line.split()[0]
                resolved = Path(os.path.realpath(device))
                if resolved.parent != Path("/dev") or not stat.S_ISBLK(os.stat(resolved).st_mode):
                    raise _changed(error_type, message)
                if resolved.name.startswith("zram") and resolved.name[4:].isdigit():
                    backing = Path("/sys/block") / resolved.name / "backing_dev"
                    if backing.read_text(encoding="ascii").strip() == "none":
                        continue
                if resolved.name.startswith("dm-") and resolved.name[3:].isdigit():
                    identity = Path("/sys/block") / resolved.name / "dm" / "uuid"
                    if identity.read_text(encoding="ascii").strip().startswith("CRYPT-"):
                        continue
                raise _changed(error_type, message)
    except (OSError, ValueError, StopIteration) as exc:
        raise _changed(error_type, message, cause=exc)
    return root



def _strict_validate_copied_wal(
    path: Path, *, error_type: type[ChangedError], message: str,
) -> None:
    """Check WAL salts and rolling frame checksums, not just the size/header.

    SQLite can silently ignore a corrupt committed tail and show stale base
    rows, which is unacceptable for a positive strict READ_ONLY projection.
    """
    try:
        size = path.stat().st_size
        if size > STRICT_PRIVATE_WAL_MAX_WAL_BYTES or size < 32:
            raise _changed(error_type, message)
        with path.open("rb") as source:
            header = source.read(32)
            magic = header[:4]
            order = "little" if magic == bytes.fromhex("377f0682") else "big"
            page_size = int.from_bytes(header[8:12], "big")
            if page_size == 1:
                page_size = 65536
            if (
                magic not in (bytes.fromhex("377f0682"), bytes.fromhex("377f0683"))
                or int.from_bytes(header[4:8], "big") != 3007000
                or page_size < 512 or page_size > 65536
                or page_size & (page_size - 1)
                or size <= 32 or (size - 32) % (page_size + 24) != 0
            ):
                raise _changed(error_type, message)

            def roll(data: bytes, first: int, second: int) -> tuple[int, int]:
                for offset in range(0, len(data), 8):
                    a = int.from_bytes(data[offset:offset + 4], order)
                    b = int.from_bytes(data[offset + 4:offset + 8], order)
                    first = (first + a + second) & 0xffffffff
                    second = (second + b + first) & 0xffffffff
                return first, second

            first, second = roll(header[:24], 0, 0)
            if header[24:32] != first.to_bytes(4, "big") + second.to_bytes(4, "big"):
                raise _changed(error_type, message)
            committed = False
            count = (size - 32) // (page_size + 24)
            for _ in range(count):
                frame = source.read(24)
                page = source.read(page_size)
                if (
                    len(frame) != 24 or len(page) != page_size
                    or frame[8:16] != header[16:24]
                    or int.from_bytes(frame[0:4], "big") < 1
                ):
                    raise _changed(error_type, message)
                first, second = roll(frame[:8], first, second)
                first, second = roll(page, first, second)
                if frame[16:24] != first.to_bytes(4, "big") + second.to_bytes(4, "big"):
                    raise _changed(error_type, message)
                committed |= int.from_bytes(frame[4:8], "big") != 0
            if not committed or source.read(1):
                raise _changed(error_type, message)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)


@contextmanager
def _strict_private_wal_snapshot(
    path: Path,
    *,
    error_type: type[ChangedError],
    message: str,
    max_copy_bytes: int | None,
) -> Iterator[sqlite3.Connection]:
    """Replay committed WAL on a private RAM copy, never on original SQLite files.

    Exact named inode/stat AND actual SHA-256 bytes of DB/WAL/SHM must agree
    before private consumption and after the entire caller observation.
    Content changes, absent/present transitions and races reject, not retry.
    Only one large RAM copy at a time is permitted; no disk scratch fallback.
    """
    path = path.absolute()
    if path.resolve(strict=True) != path or path.parent.resolve(strict=True) != path.parent:
        raise _changed(error_type, message)
    wal = Path(str(path) + "-wal")
    shm = Path(str(path) + "-shm")
    budget = STRICT_PRIVATE_WAL_MAX_BYTES
    if max_copy_bytes is not None:
        if not isinstance(max_copy_bytes, int) or isinstance(max_copy_bytes, bool) or max_copy_bytes < 0:
            raise _changed(error_type, message)
        budget = min(budget, max_copy_bytes)
    # Reject oversized inputs before SHA-256 streaming over gigabytes.
    # Subsequent fd/name and byte-hash comparison detects races with this preflight.
    try:
        database_status, wal_status = os.lstat(path), os.lstat(wal)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)
    if (
        not stat.S_ISREG(database_status.st_mode)
        or not stat.S_ISREG(wal_status.st_mode)
        or wal_status.st_size > STRICT_PRIVATE_WAL_MAX_WAL_BYTES
        or wal_status.st_size <= 32
        or database_status.st_size + wal_status.st_size > budget
    ):
        raise _changed(error_type, message)
    before = {
        filename: _strict_wal_file_fingerprint(
            filename, error_type=error_type, message=message,
            optional=(filename == shm),
        )
        for filename in (path, wal, shm)
    }
    database_id = before[path]
    wal_id = before[wal]
    assert database_id is not None and wal_id is not None
    wal_size = wal_id[0][2]
    if wal_size > STRICT_PRIVATE_WAL_MAX_WAL_BYTES:
        raise _changed(error_type, message)
    if wal_size <= 32:
        raise _changed(error_type, message)
    # Fail closed rather than accepting a truncated WAL that SQLite might ignore.
    try:
        with wal.open("rb") as source:
            header = source.read(32)
        page = int.from_bytes(header[8:12], "big")
        if page == 1:
            page = 65536
        if (
            header[:4] not in (bytes.fromhex("377f0682"), bytes.fromhex("377f0683"))
            or page < 512 or page > 65536 or page & (page - 1)
            or (wal_size - 32) % (24 + page) != 0
        ):
            raise _changed(error_type, message)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)
    size = database_id[0][2] + wal_size
    if size > budget:
        raise _changed(error_type, message)

    root = _strict_wal_memory_root(error_type=error_type, message=message)
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise _changed(error_type, message, cause=exc)
        stats = os.statvfs(root)
        if stats.f_bavail * stats.f_frsize < size + STRICT_PRIVATE_WAL_FREE_RESERVE:
            raise _changed(error_type, message)

        def verify_source() -> None:
            for filename, fingerprint in before.items():
                current = _strict_wal_file_fingerprint(
                    filename, error_type=error_type, message=message,
                    optional=(filename == shm),
                )
                if current != fingerprint:
                    raise _changed(error_type, message)

        with tempfile.TemporaryDirectory(dir=root, prefix="grabowski-strict-wal-") as directory:
            snapshot = Path(directory) / path.name
            snap_wal = Path(str(snapshot) + "-wal")
            copy_regular_file(
                path, snapshot, error_type=error_type, message=message,
                max_bytes=budget,
            )
            copy_regular_file(
                wal, snap_wal, error_type=error_type, message=message,
                max_bytes=budget - database_id[0][2],
            )
            if (
                _strict_wal_file_fingerprint(
                    snapshot, error_type=error_type, message=message
                )[1] != database_id[1]
                or _strict_wal_file_fingerprint(
                    snap_wal, error_type=error_type, message=message
                )[1] != wal_id[1]
            ):
                raise _changed(error_type, message)
            _strict_validate_copied_wal(
                snap_wal, error_type=error_type, message=message,
            )
            verify_source()
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    snapshot.as_uri() + "?mode=ro", uri=True, timeout=1,
                )
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                if connection.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
                    raise _changed(error_type, message)
                connection.execute("BEGIN")
                connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
                verify_source()
                yield connection
            except sqlite3.Error as exc:
                raise _changed(error_type, message, cause=exc)
            finally:
                if connection is not None:
                    try:
                        connection.rollback()
                    finally:
                        connection.close()
                verify_source()
    finally:
        os.close(directory_fd)



@contextmanager
def inventory_readonly_sqlite(
    path: Path,
    *,
    temporary_prefix: str,
    error_type: type[ChangedError],
    message: str = INVENTORY_CHANGED_MESSAGE,
    allow_wal_copy: bool = True,
    allow_checkpointed_empty_wal: bool = False,
    allow_private_wal_snapshot: bool = False,
    max_copy_bytes: int | None = None,
) -> Iterator[sqlite3.Connection]:
    wal_path = Path(str(path) + "-wal")
    wal_present = wal_path.exists() or wal_path.is_symlink()
    shm_path = Path(str(path) + "-shm")
    if allow_private_wal_snapshot and allow_wal_copy:
        raise ValueError("Private strict WAL snapshot requires allow_wal_copy=False")
    if not allow_wal_copy and allow_private_wal_snapshot and wal_present:
        try:
            active_wal = os.lstat(wal_path)
        except OSError as exc:
            raise _changed(error_type, message, cause=exc)
        if not stat.S_ISREG(active_wal.st_mode):
            raise _changed(error_type, message)
        if active_wal.st_size > 0:
            with _strict_private_wal_snapshot(
                path, error_type=error_type, message=message,
                max_copy_bytes=max_copy_bytes,
            ) as connection:
                yield connection
            return
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
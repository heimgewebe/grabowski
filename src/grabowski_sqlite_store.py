from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import pwd
import subprocess
import sys
import threading
import time
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
# Full physical tails are repeatedly verified; cap that IO independently.
STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES = 128 * 1024 * 1024
STRICT_PRIVATE_WAL_MAX_SHM_BYTES = 16 * 1024 * 1024
STRICT_PRIVATE_WAL_LOCK_TIMEOUT_SECONDS = 10
STRICT_PRIVATE_WAL_MEMORY_RESERVE_BYTES = 2 * 1024 * 1024 * 1024
_STRICT_PRIVATE_WAL_PROCESS_LOCK = threading.RLock()
_STRICT_PRIVATE_WAL_DEPTH = threading.local()
_STRICT_PRIVATE_WAL_SNAPSHOT_PREFIX = "grabowski-strict-wal-"
_STRICT_PRIVATE_WAL_SNAPSHOT_MARKER = ".grabowski-owned-wal-snapshot-v1"
_STRICT_PRIVATE_WAL_SNAPSHOT_KIND = "grabowski.strict-private-wal-snapshot.v1"
_STRICT_PRIVATE_WAL_MAX_ORPHAN_ENTRIES = 64
_STRICT_PRIVATE_WAL_MAX_SCANNED_PREFIX_ENTRIES = 4096


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
    copy_bytes: int | None = None,
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
        if (
            copy_bytes is not None
            and (
                type(copy_bytes) is not int
                or copy_bytes < 0
                or copy_bytes > before_status.st_size
            )
        ):
            raise _changed(error_type, message)
        with os.fdopen(os.dup(descriptor), "rb") as source_handle:
            # The private 0600 mode must be established at creation, not
            # only after a successful copy: SIGKILL can interrupt the stream.
            target_fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            with os.fdopen(target_fd, "wb") as target_handle:
                copied = 0
                while True:
                    request = (
                        COPY_CHUNK_BYTES
                        if copy_bytes is None
                        else min(COPY_CHUNK_BYTES, copy_bytes - copied)
                    )
                    if request == 0:
                        break
                    chunk = source_handle.read(request)
                    if not chunk:
                        if copy_bytes is not None:
                            raise _changed(error_type, message)
                        break
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
            or target_status.st_size != (
                before_status.st_size if copy_bytes is None else copy_bytes
            )
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
    max_bytes: int | None = None,
) -> tuple[FileIdentity, str] | None:
    """Pin a named owner-private regular file and hash only its initial fd size.

    Unbounded WAL/SHM growth during hashing must not exhaust memory or IO;
    inode, size and timestamp drift still invalidates the source witness.
    """
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
            or (max_bytes is not None and before.st_size > max_bytes)
        ):
            raise _changed(error_type, message)
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, COPY_CHUNK_BYTES))
            if not chunk:
                raise _changed(error_type, message)
            remaining -= len(chunk)
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
    wal_index_header: bytes | None = None,
) -> int:
    """Validate committed WAL frames and return the safe private replay length.

    SQLite reuses a WAL after checkpoint without truncating its physical tail.
    A validated -shm WalIndexHdr binds mxFrame to the committed prefix; only
    that prefix may be replayed. A missing index keeps the older conservative
    full-file validation, never guessing an active boundary from stale salts.
    """
    try:
        size = path.stat().st_size
        if size > STRICT_PRIVATE_WAL_MAX_BYTES or size < 32:
            raise _changed(error_type, message)
        with path.open("rb") as source:
            header = source.read(32)
            magic = header[:4]
            order = "little" if magic == bytes.fromhex("377f0682") else "big"
            page_size = int.from_bytes(header[8:12], "big")
            if page_size == 1:
                page_size = 65536
            frame_size = page_size + 24
            if (
                magic not in (bytes.fromhex("377f0682"), bytes.fromhex("377f0683"))
                or int.from_bytes(header[4:8], "big") != 3007000
                or page_size < 512 or page_size > 65536
                or page_size & (page_size - 1)
                or size <= 32
            ):
                raise _changed(error_type, message)

            def roll(data: bytes, first: int, second: int, *, byte_order: str) -> tuple[int, int]:
                for offset in range(0, len(data), 8):
                    a = int.from_bytes(data[offset:offset + 4], byte_order)
                    b = int.from_bytes(data[offset + 4:offset + 8], byte_order)
                    first = (first + a + second) & 0xffffffff
                    second = (second + b + first) & 0xffffffff
                return first, second

            first, second = roll(header[:24], 0, 0, byte_order=order)
            if header[24:32] != first.to_bytes(4, "big") + second.to_bytes(4, "big"):
                raise _changed(error_type, message)

            if wal_index_header is None:
                if size > STRICT_PRIVATE_WAL_MAX_WAL_BYTES or (size - 32) % frame_size:
                    raise _changed(error_type, message)
                count = (size - 32) // frame_size
                expected_last_pages = None
                expected_last_checksum = None
            else:
                if (
                    type(wal_index_header) is not bytes
                    or len(wal_index_header) != 96
                    or wal_index_header[:48] != wal_index_header[48:]
                ):
                    raise _changed(error_type, message)
                index = wal_index_header[:48]
                native = sys.byteorder
                checksum1, checksum2 = roll(index[:40], 0, 0, byte_order=native)
                index_page_size = int.from_bytes(index[14:16], native)
                if index_page_size == 1:
                    index_page_size = 65536
                count = int.from_bytes(index[16:20], native)
                expected_last_pages = int.from_bytes(index[20:24], native)
                expected_last_checksum = (
                    int.from_bytes(index[24:28], native),
                    int.from_bytes(index[28:32], native),
                )
                if (
                    int.from_bytes(index[:4], native) != 3007000
                    or index[4:8] != b"\x00" * 4
                    or index[12] != 1
                    or index[13] != (1 if order == "big" else 0)
                    or index_page_size != page_size
                    or index[32:40] != header[16:24]
                    or index[40:48] != (
                        checksum1.to_bytes(4, native) + checksum2.to_bytes(4, native)
                    )
                    or count < 1 or expected_last_pages < 1
                    or 32 + count * frame_size > size
                    or 32 + count * frame_size > STRICT_PRIVATE_WAL_MAX_WAL_BYTES
                ):
                    raise _changed(error_type, message)

            committed = False
            last_pages = 0
            for _ in range(count):
                frame = source.read(24)
                page = source.read(page_size)
                if (
                    len(frame) != 24 or len(page) != page_size
                    or frame[8:16] != header[16:24]
                    or int.from_bytes(frame[0:4], "big") < 1
                ):
                    raise _changed(error_type, message)
                first, second = roll(frame[:8], first, second, byte_order=order)
                first, second = roll(page, first, second, byte_order=order)
                if frame[16:24] != first.to_bytes(4, "big") + second.to_bytes(4, "big"):
                    raise _changed(error_type, message)
                last_pages = int.from_bytes(frame[4:8], "big")
                committed |= last_pages != 0
            if wal_index_header is not None:
                # The index may have a *valid* checksum but describe an
                # earlier commit in the same WAL epoch. Never accept a
                # private replay that hides subsequent committed frames.
                # A restart creates different salts; rolled-back spill
                # frames keep commit size zero. Only the former is denied.
                if (
                    size > STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES
                    or (size - 32) % frame_size
                ):
                    raise _changed(error_type, message)
                tail_first, tail_second = first, second
                for _ in range((size - 32) // frame_size - count):
                    frame = source.read(24)
                    page = source.read(page_size)
                    if len(frame) != 24 or len(page) != page_size:
                        raise _changed(error_type, message)
                    if (
                        frame[8:16] != header[16:24]
                        or int.from_bytes(frame[:4], "big") < 1
                    ):
                        break  # Retained physical tail from an older epoch.
                    next_first, next_second = roll(
                        frame[:8], tail_first, tail_second, byte_order=order,
                    )
                    next_first, next_second = roll(
                        page, next_first, next_second, byte_order=order,
                    )
                    if frame[16:24] != (
                        next_first.to_bytes(4, "big")
                        + next_second.to_bytes(4, "big")
                    ):
                        break  # Stale or partial physical tail is not replayed.
                    if int.from_bytes(frame[4:8], "big") != 0:
                        raise _changed(error_type, message)
                    tail_first, tail_second = next_first, next_second
            if (
                not committed
                or (
                    expected_last_pages is not None
                    and (
                        last_pages != expected_last_pages
                        or (first, second) != expected_last_checksum
                    )
                )
                or (wal_index_header is None and source.read(1))
            ):
                raise _changed(error_type, message)
            return 32 + count * frame_size
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)


def _strict_wal_worker_main(arguments: list[str]) -> int:
    """Subprocess-only original source fd reads; never run in the SQLite owner."""
    if (
        len(arguments) not in (5, 7)
        or arguments[0] != "--strict-wal-source-worker"
        or arguments[1] not in {"prepare", "fingerprint"}
        or (arguments[1] == "prepare") != (len(arguments) == 7)
    ):
        return 2
    action = arguments[1]
    database, wal, shm = (Path(value) for value in arguments[2:5])
    source_paths = (database, wal, shm)
    try:
        before = [
            _strict_wal_file_fingerprint(
                source, error_type=RuntimeError,
                message=INVENTORY_CHANGED_MESSAGE, optional=(source == shm),
                max_bytes=(
                    STRICT_PRIVATE_WAL_MAX_BYTES if source == database
                    else STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES if source == wal
                    else STRICT_PRIVATE_WAL_MAX_SHM_BYTES
                ),
            )
            for source in source_paths
        ]
        if action == "prepare":
            scratch = Path(arguments[5])
            budget = int(arguments[6])
            metadata = os.lstat(scratch)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or scratch.is_symlink()
                or not 0 <= budget <= STRICT_PRIVATE_WAL_MAX_BYTES
                or before[0] is None or before[1] is None
                or before[1][0][2] <= 32
                or before[1][0][2] > STRICT_PRIVATE_WAL_MAX_BYTES
                or before[0][0][2] > budget
            ):
                raise RuntimeError("unsafe strict WAL worker input")
            snapshot = scratch / database.name
            snap_wal = Path(str(snapshot) + "-wal")
            # All original WAL/-shm reads remain in this child: the parent
            # must never close a raw fd and drop live SQLite fcntl locks.
            wal_index_header = None
            if before[2] is not None:
                descriptor = os.open(shm, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    expected = before[2][0]
                    if (
                        status_identity(os.fstat(descriptor)) != expected
                        or status_identity(os.lstat(shm)) != expected
                    ):
                        raise RuntimeError("strict WAL index source changed")
                    wal_index_header = os.read(descriptor, 96)
                    if (
                        len(wal_index_header) != 96
                        or status_identity(os.fstat(descriptor)) != expected
                        or status_identity(os.lstat(shm)) != expected
                    ):
                        raise RuntimeError("strict WAL index header is invalid")
                finally:
                    os.close(descriptor)
            replay_bytes = _strict_validate_copied_wal(
                wal, error_type=RuntimeError, message=INVENTORY_CHANGED_MESSAGE,
                wal_index_header=wal_index_header,
            )
            if (
                replay_bytes > STRICT_PRIVATE_WAL_MAX_WAL_BYTES
                or before[0][0][2] + replay_bytes > budget
            ):
                raise RuntimeError("strict WAL active-prefix budget exceeded")
            copy_regular_file(
                database, snapshot, error_type=RuntimeError,
                max_bytes=budget,
            )
            copy_regular_file(
                wal, snap_wal, error_type=RuntimeError,
                max_bytes=budget - before[0][0][2], copy_bytes=replay_bytes,
            )
            copied_wal = _strict_wal_file_fingerprint(
                snap_wal, error_type=RuntimeError, message=INVENTORY_CHANGED_MESSAGE,
            )
            if copied_wal is None:
                raise RuntimeError("strict WAL prefix copy missing")
            after = [
                _strict_wal_file_fingerprint(
                    source, error_type=RuntimeError,
                    message=INVENTORY_CHANGED_MESSAGE, optional=(source == shm),
                    max_bytes=(
                        STRICT_PRIVATE_WAL_MAX_BYTES if source == database
                        else STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES if source == wal
                        else STRICT_PRIVATE_WAL_MAX_SHM_BYTES
                    ),
                )
                for source in source_paths
            ]
            if after != before:
                raise RuntimeError("strict WAL source changed while copying")
        payload = {
            "schema_version": 1,
            "copied_wal_bytes": replay_bytes if action == "prepare" else None,
            "copied_wal_sha256": copied_wal[1] if action == "prepare" else None,
            "wal_index_header": (
                wal_index_header.hex() if action == "prepare" and wal_index_header is not None
                else None
            ),
            "files": [
                None if observed is None else {
                    "identity": list(observed[0]),
                    "sha256": observed[1],
                }
                for observed in before
            ],
        }
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, RuntimeError, ValueError, TypeError):
        return 1


def _strict_wal_source_worker(
    action: str,
    *,
    database: Path,
    wal: Path,
    shm: Path,
    error_type: type[ChangedError],
    message: str,
    scratch: Path | None = None,
    budget: int | None = None,
) -> tuple[
    dict[Path, tuple[FileIdentity, str] | None], bytes | None,
    tuple[int, str] | None,
]:
    """Isolate all raw original SQLite fd close() calls from the owning process.

    POSIX fcntl locks are process-wide. Closing even an unrelated raw -shm
    descriptor in the SQLite writer process can cancel its live WAL_WRITE_LOCK.
    A separate exec'ed worker has independent POSIX locks; it cannot cancel
    the caller's SQLite locks. Do not silently fall back to in-process IO.
    """
    if action not in {"prepare", "fingerprint"}:
        raise _changed(error_type, message)
    if action == "prepare" and (scratch is None or budget is None):
        raise _changed(error_type, message)
    if action == "fingerprint" and (scratch is not None or budget is not None):
        raise _changed(error_type, message)
    command = [
        sys.executable, "-I", str(Path(__file__).resolve(strict=True)),
        "--strict-wal-source-worker", action,
        str(database), str(wal), str(shm),
    ]
    if action == "prepare":
        assert scratch is not None and budget is not None
        command.extend((str(scratch), str(budget)))
    try:
        # The owner flock must outlive the parent if SIGKILL happens while
        # this subprocess still copies bytes into the marked snapshot.
        # Passing its existing file description keeps orphan reaping excluded
        # until the last copy worker exits, without introducing another lock.
        lock_descriptor = getattr(_STRICT_PRIVATE_WAL_DEPTH, "descriptor", None)
        lock_depth = getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0)
        inherited_fds = (
            (lock_descriptor,)
            if lock_depth > 0 and type(lock_descriptor) is int
            and lock_descriptor >= 0
            else ()
        )
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, close_fds=True,
            pass_fds=inherited_fds, timeout=120,
        )
        if result.returncode != 0 or not 0 < len(result.stdout) <= 4096:
            raise ValueError("strict WAL worker did not produce a valid result")
        response = json.loads(result.stdout)
        if (
            not isinstance(response, dict)
            or set(response) != {
                "schema_version", "files", "wal_index_header",
                "copied_wal_bytes", "copied_wal_sha256",
            }
            or type(response["schema_version"]) is not int
            or response["schema_version"] != 1
            or not isinstance(response["files"], list)
            or len(response["files"]) != 3
        ):
            raise ValueError("strict WAL worker result shape is invalid")
        encoded_header = response["wal_index_header"]
        if encoded_header is not None and (
            action != "prepare"
            or not isinstance(encoded_header, str)
            or len(encoded_header) != 192
            or any(character not in "0123456789abcdef" for character in encoded_header)
        ):
            raise ValueError("strict WAL index header response is invalid")
        wal_index_header = (
            bytes.fromhex(encoded_header) if encoded_header is not None else None
        )
        copied_bytes = response["copied_wal_bytes"]
        copied_sha = response["copied_wal_sha256"]
        if action == "prepare":
            if (
                type(copied_bytes) is not int
                or not 32 < copied_bytes <= STRICT_PRIVATE_WAL_MAX_WAL_BYTES
                or not isinstance(copied_sha, str)
                or len(copied_sha) != 64
                or any(ch not in "0123456789abcdef" for ch in copied_sha)
            ):
                raise ValueError("strict WAL prefix result invalid")
            copied_wal = (copied_bytes, copied_sha)
        else:
            if copied_bytes is not None or copied_sha is not None:
                raise ValueError("strict WAL fingerprint supplied copy result")
            copied_wal = None
        fingerprints: dict[Path, tuple[FileIdentity, str] | None] = {}
        for index, (source, item) in enumerate(
            zip((database, wal, shm), response["files"], strict=True)
        ):
            if item is None and index == 2:
                fingerprints[source] = None
                continue
            if (
                not isinstance(item, dict)
                or set(item) != {"identity", "sha256"}
                or not isinstance(item["identity"], list)
                or len(item["identity"]) != 5
                or any(type(value) is not int or value < 0 for value in item["identity"])
                or not isinstance(item["sha256"], str)
                or len(item["sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in item["sha256"])
            ):
                raise ValueError("strict WAL source fingerprint is invalid")
            fingerprints[source] = (
                tuple(item["identity"]), item["sha256"],
            )
        return fingerprints, wal_index_header, copied_wal
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        raise _changed(error_type, message, cause=exc)



def _strict_wal_cgroup_memory_headroom(
    *, error_type: type[ChangedError], message: str,
    cgroup_file: Path = Path("/proc/self/cgroup"),
    mount_root: Path = Path("/sys/fs/cgroup"),
) -> int | None:
    """Read the tightest inherited cgroup-v2 memory budget, without effects.

    A parent systemd slice may constrain memory even when the leaf's
    memory.max is 'max'. Malformed advertised controls deny the snapshot.
    """
    try:
        # v1 memory may govern this process even with a mounted cgroup2 tree.
        # Read all memberships once; an unverified memory authority denies.
        entries = cgroup_file.read_text(encoding="ascii").splitlines()
        if not entries:
            raise ValueError("cgroup controller membership unavailable")
        memberships = []
        for entry in entries:
            parts = entry.split(":", 2)
            if (len(parts) != 3 or not parts[0].isdigit()
                    or not parts[2].startswith("/")):
                raise ValueError("malformed cgroup membership")
            if "memory" in parts[1].split(","):
                raise ValueError("unverifiable v1/hybrid memory controller")
            memberships.append(parts)
        locations = [
            path for hierarchy, controllers, path in memberships
            if hierarchy == "0" and controllers == ""
        ]
        if not (mount_root / "cgroup.controllers").is_file():
            if locations:
                raise ValueError("unverifiable unified cgroup mount")
            return None
        if len(locations) != 1 or not locations[0].startswith("/"):
            raise ValueError("unverifiable unified cgroup")
        if any(item in {".", ".."} for item in locations[0].split("/")):
            raise ValueError("unsafe cgroup path")
        root = mount_root.resolve(strict=True)
        leaf = (root / locations[0].lstrip("/")).resolve(strict=True)
        if leaf != root and not leaf.is_relative_to(root):
            raise ValueError("cgroup outside memory hierarchy")
        available: int | None = None
        scope = leaf
        while True:
            max_file, current_file = scope / "memory.max", scope / "memory.current"
            max_present, current_present = max_file.is_file(), current_file.is_file()
            if max_present != current_present:
                raise ValueError("incomplete cgroup memory controls")
            if max_present:
                maximum = max_file.read_text(encoding="ascii").strip()
                usage = current_file.read_text(encoding="ascii").strip()
                if (not usage.isdigit() or len(usage) > 20
                        or (maximum != "max" and
                            (not maximum.isdigit() or len(maximum) > 20))):
                    raise ValueError("invalid cgroup memory controls")
                if maximum != "max":
                    headroom = max(0, int(maximum) - int(usage))
                    available = (
                        headroom if available is None
                        else min(available, headroom)
                    )
            if scope == root:
                return available
            scope = scope.parent
    except (OSError, ValueError) as exc:
        raise _changed(error_type, message, cause=exc)


def _strict_wal_available_memory(
    *, error_type: type[ChangedError], message: str,
) -> int:
    """Fail closed when the kernel cannot establish current memory headroom."""
    try:
        with Path("/proc/meminfo").open(encoding="ascii") as source:
            entries = [
                line.split()
                for line in source
                if line.startswith("MemAvailable:")
            ]
        if (
            len(entries) != 1 or len(entries[0]) != 3
            or entries[0][1].isdigit() is False or entries[0][2] != "kB"
        ):
            raise ValueError("unverifiable MemAvailable")
        host_available = int(entries[0][1]) * 1024
        cgroup_available = _strict_wal_cgroup_memory_headroom(
            error_type=error_type, message=message,
        )
        return (
            host_available if cgroup_available is None
            else min(host_available, cgroup_available)
        )
    except (OSError, ValueError) as exc:
        raise _changed(error_type, message, cause=exc)


def _strict_wal_owner_lock_acquire(
    *, error_type: type[ChangedError], message: str,
    private_scratch_root: Path | None = None,
) -> int:
    """Serialize scratch copies without locking a world-readable tmpfs directory.

    Production locks the existing uid-bound account-private config inode,
    never HOME. A separately verified private scratch root can be supplied
    by a hermetic test fixture, whose distinct snapshots cannot overlap with
    production /dev/shm. No persistent lock file or source write is created.
    Thread-local recursion uses the same outer flock while a process RLock
    serializes other threads. Cross-process readers wait a bounded interval.
    """
    if private_scratch_root is not None and (
        not isinstance(private_scratch_root, Path)
        or not private_scratch_root.is_absolute()
    ):
        raise _changed(error_type, message)
    try:
        account_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        if not account_home.is_absolute():
            raise _changed(error_type, message)
        private_dir = (
            private_scratch_root
            if private_scratch_root is not None
            and private_scratch_root != Path("/dev/shm")
            else account_home / ".config" / "grabowski"
        )
    except (KeyError, OSError, ValueError) as exc:
        raise _changed(error_type, message, cause=exc)
    if not _STRICT_PRIVATE_WAL_PROCESS_LOCK.acquire(
        timeout=STRICT_PRIVATE_WAL_LOCK_TIMEOUT_SECONDS
    ):
        raise _changed(error_type, message)
    depth = getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0)
    if depth:
        # All nested callers share one fd. A sentinel (-1) would make a
        # non-LIFO release unlock an invalid fd and leak the outer flock.
        held_descriptor = getattr(_STRICT_PRIVATE_WAL_DEPTH, "descriptor", None)
        if (
            type(held_descriptor) is not int
            or held_descriptor < 0
            or getattr(_STRICT_PRIVATE_WAL_DEPTH, "lock_dir", None) != private_dir
        ):
            _STRICT_PRIVATE_WAL_PROCESS_LOCK.release()
            raise _changed(error_type, message)
        _STRICT_PRIVATE_WAL_DEPTH.value = depth + 1
        return held_descriptor
    descriptor = -1
    try:
        before = os.lstat(private_dir)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or private_dir.resolve(strict=True) != private_dir
        ):
            raise _changed(error_type, message)
        descriptor = os.open(
            private_dir, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        now = os.fstat(descriptor)
        if (
            (now.st_dev, now.st_ino) != (before.st_dev, before.st_ino)
            or now.st_uid != before.st_uid
            or stat.S_IMODE(now.st_mode) != stat.S_IMODE(before.st_mode)
        ):
            raise _changed(error_type, message)
        deadline = time.monotonic() + STRICT_PRIVATE_WAL_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise _changed(error_type, message)
                time.sleep(0.05)
        _STRICT_PRIVATE_WAL_DEPTH.descriptor = descriptor
        _STRICT_PRIVATE_WAL_DEPTH.lock_dir = private_dir
        _STRICT_PRIVATE_WAL_DEPTH.value = 1
        return descriptor
    except (OSError, ValueError, KeyError) as exc:
        raise _changed(error_type, message, cause=exc)
    finally:
        if getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0) == 0:
            if descriptor >= 0:
                os.close(descriptor)
            _STRICT_PRIVATE_WAL_PROCESS_LOCK.release()


def _strict_wal_owner_lock_release(descriptor: int) -> None:
    depth = getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0)
    held_descriptor = getattr(_STRICT_PRIVATE_WAL_DEPTH, "descriptor", None)
    if depth < 1 or type(descriptor) is not int or descriptor != held_descriptor:
        raise RuntimeError("strict WAL reader lock ownership lost")
    _STRICT_PRIVATE_WAL_DEPTH.value = depth - 1
    try:
        if depth == 1:
            del _STRICT_PRIVATE_WAL_DEPTH.descriptor
            del _STRICT_PRIVATE_WAL_DEPTH.lock_dir
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
    finally:
        _STRICT_PRIVATE_WAL_PROCESS_LOCK.release()


def _strict_wal_mark_private_snapshot(directory: Path, database_name: str) -> None:
    """Mark only safely reappable names before any plaintext can be copied."""
    # The later orphan reaper deliberately accepts at most 240 UTF-8 bytes
    # (including room for SQLite sidecar suffixes). A longer live database
    # name must be denied here, not left as an unrecoverable SIGKILL copy.
    if (
        not isinstance(database_name, str)
        or not database_name
        or database_name in {".", ".."}
        or "/" in database_name
        or len(database_name.encode("utf-8")) > 240
    ):
        raise ValueError("strict WAL snapshot filename is not safely recoverable")
    payload = json.dumps(
        {"kind": _STRICT_PRIVATE_WAL_SNAPSHOT_KIND, "database_name": database_name},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    descriptor = os.open(
        directory / _STRICT_PRIVATE_WAL_SNAPSHOT_MARKER,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        if os.write(descriptor, payload) != len(payload):
            raise OSError("incomplete private WAL snapshot marker")
    finally:
        os.close(descriptor)


def _strict_wal_reap_private_snapshot_orphans(
    root: Path, *, error_type: type[ChangedError], message: str,
) -> None:
    """Reap only a marker-attested inactive copy, never an arbitrary glob.

    The existing per-user flock excludes other readers throughout their copy
    and query lifetimes. Reentrant nested readers share the flock and must not
    reap a still-live outer copy, so reaping is only allowed at depth one.
    Every candidate is checked through no-follow, directory-relative FDs;
    unsupported or unmarked directories are left untouched.
    """
    if getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0) != 1:
        raise RuntimeError("orphan cleanup requires outermost strict WAL owner lock")
    root_fd = -1
    try:
        root_status = os.lstat(root)
        if not stat.S_ISDIR(root_status.st_mode):
            raise _changed(error_type, message)
        root_fd = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        pinned_root = os.fstat(root_fd)
        if (root_status.st_dev, root_status.st_ino) != (
            pinned_root.st_dev, pinned_root.st_ino
        ):
            raise _changed(error_type, message)
        reaped = 0
        inspected = 0
        with os.scandir(root_fd) as entries:
            for entry in entries:
                directory_name = entry.name
                if (
                    not directory_name.startswith(_STRICT_PRIVATE_WAL_SNAPSHOT_PREFIX)
                    or len(directory_name) > 255
                ):
                    continue
                # This namespace is shared by other users. Foreign entries
                # cannot consume the authenticated-orphan deletion budget,
                # and exceeding the independent scan bound merely defers
                # optional cleanup instead of denying public READ_ONLY.
                inspected += 1
                if inspected > _STRICT_PRIVATE_WAL_MAX_SCANNED_PREFIX_ENTRIES:
                    break
                try:
                    observed = os.stat(
                        directory_name, dir_fd=root_fd, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    # scandir enumerates shared /dev/shm. A foreign prefix
                    # entry that vanishes before its first identity proof has
                    # no cleanup authority and must not deny READ_ONLY.
                    continue
                if (
                    not stat.S_ISDIR(observed.st_mode)
                    or observed.st_dev != pinned_root.st_dev
                    or observed.st_uid != os.geteuid()
                    or stat.S_IMODE(observed.st_mode) != 0o700
                ):
                    continue
                child_fd = os.open(
                    directory_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_fd,
                )
                try:
                    child = os.fstat(child_fd)
                    if (child.st_dev, child.st_ino) != (
                        observed.st_dev, observed.st_ino
                    ):
                        raise _changed(error_type, message)
                    try:
                        marker_fd = os.open(
                            _STRICT_PRIVATE_WAL_SNAPSHOT_MARKER,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=child_fd,
                        )
                    except FileNotFoundError:
                        continue  # Older/unrelated copies have no deletion authority.
                    try:
                        marker = os.fstat(marker_fd)
                        if (
                            not stat.S_ISREG(marker.st_mode)
                            or marker.st_uid != os.geteuid()
                            or marker.st_nlink != 1
                            or stat.S_IMODE(marker.st_mode) != 0o600
                            or marker.st_size > 512
                        ):
                            continue
                        try:
                            record = json.loads(os.read(marker_fd, 513))
                        except (ValueError, UnicodeError, TypeError):
                            continue
                        after_marker = os.fstat(marker_fd)
                        # Reading a marker can update atime (relatime); atime
                        # is not provenance and must not block safe recovery.
                        if status_identity(after_marker) != status_identity(marker):
                            raise _changed(error_type, message)
                    finally:
                        os.close(marker_fd)
                    if not isinstance(record, dict) or record.get("kind") != (
                        _STRICT_PRIVATE_WAL_SNAPSHOT_KIND
                    ):
                        continue
                    database_name = record.get("database_name")
                    if (
                        not isinstance(database_name, str)
                        or not database_name
                        or len(database_name.encode("utf-8")) > 240
                        or database_name in {".", ".."}
                        or "/" in database_name
                    ):
                        continue
                    allowed = {
                        _STRICT_PRIVATE_WAL_SNAPSHOT_MARKER, database_name,
                        database_name + "-wal", database_name + "-shm",
                        database_name + "-journal",
                    }
                    filenames = os.listdir(child_fd)
                    if not 1 <= len(filenames) <= len(allowed) or any(
                        filename not in allowed for filename in filenames
                    ):
                        continue
                    budget = (
                        STRICT_PRIVATE_WAL_MAX_BYTES
                        + STRICT_PRIVATE_WAL_MAX_WAL_BYTES
                        + STRICT_PRIVATE_WAL_MAX_SHM_BYTES
                    )
                    file_stats = [
                        os.stat(filename, dir_fd=child_fd, follow_symlinks=False)
                        for filename in filenames
                    ]
                    if any(
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.geteuid()
                        or info.st_dev != pinned_root.st_dev
                        or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) & 0o077
                        or info.st_size > budget
                        for info in file_stats
                    ) or sum(info.st_size for info in file_stats) > budget + 512:
                        continue
                    # Only fully authenticated, safely unlinkable copies
                    # consume the bounded orphan-deletion budget. More
                    # cleanup may be performed by the next strict reader;
                    # it is not a condition of a valid READ_ONLY response.
                    if reaped >= _STRICT_PRIVATE_WAL_MAX_ORPHAN_ENTRIES:
                        break
                    # Reconfirm the candidate's root binding immediately
                    # before the irreversible, bounded single-level unlink.
                    still = os.stat(
                        directory_name, dir_fd=root_fd, follow_symlinks=False,
                    )
                    if (still.st_dev, still.st_ino) != (child.st_dev, child.st_ino):
                        raise _changed(error_type, message)
                    for filename in filenames:
                        if filename != _STRICT_PRIVATE_WAL_SNAPSHOT_MARKER:
                            os.unlink(filename, dir_fd=child_fd)
                    os.unlink(_STRICT_PRIVATE_WAL_SNAPSHOT_MARKER, dir_fd=child_fd)
                    os.rmdir(directory_name, dir_fd=root_fd)
                    reaped += 1
                finally:
                    os.close(child_fd)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)
    finally:
        if root_fd >= 0:
            os.close(root_fd)


@contextmanager
def _strict_private_wal_snapshot(
    path: Path,
    *,
    error_type: type[ChangedError],
    message: str,
    max_copy_bytes: int | None,
) -> Iterator[sqlite3.Connection]:
    """Replay committed WAL on tmpfs without original fd opens in SQLite process.

    The subprocess fingerprints DB/WAL/SHM before and after copying. Identical
    no-effect subprocess fingerprints are checked before/during/after reading
    the private SQLite copy, including WAL-only commits and live writer races.
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
    # Never hash gigabytes or allocate scratch before a bounded stat-only check.
    try:
        database_status, wal_status = os.lstat(path), os.lstat(wal)
    except OSError as exc:
        raise _changed(error_type, message, cause=exc)
    if (
        not stat.S_ISREG(database_status.st_mode)
        or not stat.S_ISREG(wal_status.st_mode)
        or wal_status.st_size > STRICT_PRIVATE_WAL_MAX_PHYSICAL_WAL_BYTES
        or wal_status.st_size <= 32
        or database_status.st_size + min(wal_status.st_size, 32 + 24 + 512) > budget
    ):
        # A valid committed WAL needs at least one 512-byte frame. Reject
        # impossible budgets before scratch, even when its old tail is huge.
        raise _changed(error_type, message)
    root = _strict_wal_memory_root(error_type=error_type, message=message)
    lock_descriptor = _strict_wal_owner_lock_acquire(
        error_type=error_type, message=message, private_scratch_root=root,
    )
    try:
        if getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0) == 1:
            _strict_wal_reap_private_snapshot_orphans(
                root, error_type=error_type, message=message,
            )
        stats = os.statvfs(root)
        # Only committed bytes can enter the private snapshot, never stale tail.
        total = database_status.st_size + min(
            wal_status.st_size, STRICT_PRIVATE_WAL_MAX_WAL_BYTES,
        )
        if (
            stats.f_bavail * stats.f_frsize < total + STRICT_PRIVATE_WAL_FREE_RESERVE
            or _strict_wal_available_memory(error_type=error_type, message=message)
            < (2 * total + STRICT_PRIVATE_WAL_MEMORY_RESERVE_BYTES)
        ):
            raise _changed(error_type, message)

        with tempfile.TemporaryDirectory(
            dir=root, prefix=_STRICT_PRIVATE_WAL_SNAPSHOT_PREFIX,
        ) as directory:
            # SIGKILL before this marker cannot leave copied plaintext.
            try:
                _strict_wal_mark_private_snapshot(Path(directory), path.name)
            except (OSError, ValueError) as exc:
                raise _changed(error_type, message, cause=exc)
            snapshot = Path(directory) / path.name
            snap_wal = Path(str(snapshot) + "-wal")
            before, wal_index_header, copied_wal = _strict_wal_source_worker(
                "prepare", database=path, wal=wal, shm=shm,
                error_type=error_type, message=message,
                # Never exceed the tmpfs/memory allocation approved before
                # a concurrent SQLite writer can grow the source database.
                scratch=Path(directory), budget=min(budget, total),
            )
            database_id, wal_id = before[path], before[wal]
            if (
                database_id is None or wal_id is None or copied_wal is None
                or database_id[0][2] + copied_wal[0] > budget
                or database_id[0][2] != database_status.st_size
                or wal_id[0][2] != wal_status.st_size
            ):
                raise _changed(error_type, message)
            # These are private copy paths, never original SQLite locks.
            if (
                _strict_wal_file_fingerprint(
                    snapshot, error_type=error_type, message=message,
                )[1] != database_id[1]
                or _strict_wal_file_fingerprint(
                    snap_wal, error_type=error_type, message=message,
                )[1] != copied_wal[1]
                or snap_wal.stat().st_size != copied_wal[0]
            ):
                raise _changed(error_type, message)
            replay_bytes = _strict_validate_copied_wal(
                snap_wal, error_type=error_type, message=message,
                wal_index_header=wal_index_header,
            )
            # Exactly the authenticated prefix was copied; SQLite cannot
            # replay arbitrary stale physical frames from the source tail.
            if replay_bytes != copied_wal[0]:
                raise _changed(error_type, message)

            def verify_source() -> None:
                current, _, _ = _strict_wal_source_worker(
                    "fingerprint", database=path, wal=wal, shm=shm,
                    error_type=error_type, message=message,
                )
                if current != before:
                    raise _changed(error_type, message)

            verify_source()
            connection: sqlite3.Connection | None = None
            caller_completed = False
            try:
                # Only snapshot-setup SQLite failures are retryable inventory
                # errors. Once yielded, the caller owns its query diagnostics.
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
                except sqlite3.Error as exc:
                    raise _changed(error_type, message, cause=exc)
                yield connection
                caller_completed = True
            finally:
                # Source verification must happen AFTER private SQLite cleanup:
                # a writer can commit during rollback/close, and the caller's
                # successful return must never conceal that concurrent drift.
                # If a caller raises, preserve that original diagnostic rather
                # than masking it with a cleanup or post-error inventory check.
                if connection is not None:
                    try:
                        connection.rollback()
                    except Exception:
                        if caller_completed:
                            raise
                    finally:
                        try:
                            connection.close()
                        except Exception:
                            if caller_completed:
                                raise
                if caller_completed:
                    verify_source()
    finally:
        _strict_wal_owner_lock_release(lock_descriptor)



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

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--strict-wal-source-worker":
        raise SystemExit(2)
    raise SystemExit(_strict_wal_worker_main(sys.argv[1:]))
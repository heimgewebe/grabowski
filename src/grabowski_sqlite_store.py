from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
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
            with target.open("xb") as target_handle:
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
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, close_fds=True,
            timeout=120,
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
        return int(entries[0][1]) * 1024
    except (OSError, ValueError) as exc:
        raise _changed(error_type, message, cause=exc)


def _strict_wal_owner_lock_acquire(
    *, error_type: type[ChangedError], message: str,
) -> int:
    """Serialize scratch copies without locking a world-readable tmpfs directory.

    The pre-existing per-user private config directory is a lockable inode;
    no persistent file, source database, WAL or SHM is created or mutated.
    Thread-local recursion uses the same outer flock while a process RLock
    serializes other threads. Cross-process readers wait a bounded interval.
    """
    if not _STRICT_PRIVATE_WAL_PROCESS_LOCK.acquire(
        timeout=STRICT_PRIVATE_WAL_LOCK_TIMEOUT_SECONDS
    ):
        raise _changed(error_type, message)
    depth = getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0)
    if depth:
        _STRICT_PRIVATE_WAL_DEPTH.value = depth + 1
        return -1
    descriptor = -1
    try:
        private_dir = Path.home() / ".config" / "grabowski"
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
        _STRICT_PRIVATE_WAL_DEPTH.value = 1
        return descriptor
    except (OSError, ValueError) as exc:
        raise _changed(error_type, message, cause=exc)
    finally:
        if getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0) == 0:
            if descriptor >= 0:
                os.close(descriptor)
            _STRICT_PRIVATE_WAL_PROCESS_LOCK.release()


def _strict_wal_owner_lock_release(descriptor: int) -> None:
    depth = getattr(_STRICT_PRIVATE_WAL_DEPTH, "value", 0)
    if depth < 1:
        raise RuntimeError("strict WAL reader lock ownership lost")
    _STRICT_PRIVATE_WAL_DEPTH.value = depth - 1
    try:
        if depth == 1:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
    finally:
        _STRICT_PRIVATE_WAL_PROCESS_LOCK.release()


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
        error_type=error_type, message=message,
    )
    try:
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

        with tempfile.TemporaryDirectory(dir=root, prefix="grabowski-strict-wal-") as directory:
            snapshot = Path(directory) / path.name
            snap_wal = Path(str(snapshot) + "-wal")
            before, wal_index_header, copied_wal = _strict_wal_source_worker(
                "prepare", database=path, wal=wal, shm=shm,
                error_type=error_type, message=message,
                scratch=Path(directory), budget=budget,
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
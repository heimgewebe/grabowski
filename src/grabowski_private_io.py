from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _inode(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _safe_name(path: Path, *, label: str) -> str:
    name = path.name
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"{label} name is invalid")
    return name


def _assert_open_directory_binding(
    directory_fd: int,
    directory: Path,
    *,
    label: str,
) -> tuple[int, int]:
    """Bind a path to the already opened private directory inode.

    All file operations below use ``dir_fd``. Rechecking the path before return
    detects a rename/replacement of the caller-visible directory path; fchdir is
    intentionally unnecessary and would only add process-global state.
    """
    opened = os.fstat(directory_fd)
    linked = directory.lstat()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(linked.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) & 0o077
        or _identity(opened) != _identity(linked)
    ):
        raise RuntimeError(f"{label} directory identity is unsafe")
    return _inode(opened)


def _stat_at(directory_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)


def _unlink_if_same_inode(
    directory_fd: int,
    name: str,
    expected_inode: tuple[int, int],
) -> bool:
    try:
        current = _stat_at(directory_fd, name)
    except FileNotFoundError:
        return False
    if _inode(current) != expected_inode:
        return False
    os.unlink(name, dir_fd=directory_fd)
    return True


def _assert_published_target(
    directory_fd: int,
    target_name: str,
    expected_inode: tuple[int, int],
    *,
    label: str,
) -> None:
    target = _stat_at(directory_fd, target_name)
    if (
        not stat.S_ISREG(target.st_mode)
        or stat.S_IMODE(target.st_mode) != 0o600
        or target.st_nlink != 1
        or _inode(target) != expected_inode
    ):
        raise RuntimeError(f"published {label} failed integrity validation")


def publish_private_create_only_json(
    directory: Path,
    target: Path,
    payload: dict[str, Any],
    *,
    max_bytes: int,
    label: str,
) -> bool:
    """Publish one private JSON file create-only inside an opened directory.

    False means another writer already published the target. The caller remains
    responsible for reading and validating that winner against its own schema.
    This primitive deliberately never replaces an existing target.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be an object")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")

    directory = Path(directory)
    target = Path(target)
    if target.parent != directory:
        raise ValueError(f"{label} target must be a direct child of its directory")
    target_name = _safe_name(target, label=label)
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} is too large")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(directory, directory_flags)
    temporary_name = f".{target_name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    temporary_present = False
    published_inode: tuple[int, int] | None = None
    try:
        _assert_open_directory_binding(directory_fd, directory, label=label)

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        temporary_present = True
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

        temporary = _stat_at(directory_fd, temporary_name)
        published_inode = _inode(temporary)
        if (
            not stat.S_ISREG(temporary.st_mode)
            or stat.S_IMODE(temporary.st_mode) != 0o600
            or temporary.st_nlink != 1
        ):
            raise RuntimeError(f"temporary {label} is unsafe")

        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            published_inode = None
            return False

        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_present = False
        except OSError:
            _unlink_if_same_inode(directory_fd, target_name, published_inode)
            published_inode = None
            raise

        _assert_published_target(
            directory_fd,
            target_name,
            published_inode,
            label=label,
        )
        os.fsync(directory_fd)
        _assert_open_directory_binding(directory_fd, directory, label=label)
        _assert_published_target(
            directory_fd,
            target_name,
            published_inode,
            label=label,
        )
        return True
    except BaseException:
        if published_inode is not None:
            try:
                removed = _unlink_if_same_inode(
                    directory_fd,
                    target_name,
                    published_inode,
                )
                if removed:
                    os.fsync(directory_fd)
            except OSError:
                # Preserve the primary failure. The target is never removed when
                # its inode no longer matches the file published by this call.
                pass
        raise
    finally:
        active_error = sys.exc_info()[0] is not None
        cleanup_error: OSError | None = None
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_error = exc
        if temporary_present:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        try:
            os.close(directory_fd)
        except OSError as exc:
            if cleanup_error is None:
                cleanup_error = exc
        if cleanup_error is not None and not active_error:
            raise cleanup_error

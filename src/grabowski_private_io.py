from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import stat
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


def _safe_name(path: Path, *, label: str) -> str:
    name = path.name
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"{label} name is invalid")
    return name


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
    published = False
    temporary_identity: tuple[int, int] | None = None
    try:
        opened_directory = os.fstat(directory_fd)
        linked_directory = directory.lstat()
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or stat.S_ISLNK(linked_directory.st_mode)
            or opened_directory.st_uid != os.getuid()
            or stat.S_IMODE(opened_directory.st_mode) & 0o077
            or _identity(opened_directory) != _identity(linked_directory)
        ):
            raise RuntimeError(f"{label} directory identity is unsafe")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

        temporary_metadata = os.stat(
            temporary_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        temporary_identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_nlink != 1
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
            return False
        published = True

        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except OSError:
            try:
                current = os.stat(
                    target_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == temporary_identity:
                    os.unlink(target_name, dir_fd=directory_fd)
                    published = False
            finally:
                raise
        target_metadata = os.stat(
            target_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(target_metadata.st_mode)
            or stat.S_IMODE(target_metadata.st_mode) != 0o600
            or target_metadata.st_nlink != 1
            or (target_metadata.st_dev, target_metadata.st_ino) != temporary_identity
        ):
            try:
                current = os.stat(
                    target_name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == temporary_identity:
                    os.unlink(target_name, dir_fd=directory_fd)
                    published = False
            except FileNotFoundError:
                published = False
            raise RuntimeError(f"published {label} failed integrity validation")
        os.fsync(directory_fd)
        return True
    finally:
        cleanup_error: OSError | None = None
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            cleanup_error = exc
        try:
            if published and temporary_identity is not None:
                try:
                    current = os.stat(
                        target_name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError as exc:
                    raise RuntimeError(f"published {label} disappeared") from exc
                if current.st_nlink != 1:
                    if (current.st_dev, current.st_ino) == temporary_identity:
                        os.unlink(target_name, dir_fd=directory_fd)
                        published = False
                    raise RuntimeError(f"published {label} lost single-link integrity")
            if cleanup_error is not None:
                if published and temporary_identity is not None:
                    try:
                        current = os.stat(
                            target_name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                        if (current.st_dev, current.st_ino) == temporary_identity:
                            os.unlink(target_name, dir_fd=directory_fd)
                            published = False
                    except FileNotFoundError:
                        published = False
                raise cleanup_error
        finally:
            os.close(directory_fd)

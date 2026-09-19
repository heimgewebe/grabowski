"""Immutable argv bootstrap for RepoBrief Codex benchmark entrypoints.

This file is distribution data.  Do not execute it by path.  A trusted caller
must read these exact bytes first and pass them as the program operand of
``python -c``, followed by one absolute target script path.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys

MAX_SOURCE_BYTES = 16 * 1024 * 1024
BOOTSTRAP_KIND = "grabowski.python_c_source_bootstrap"
BOOTSTRAP_SCHEMA_VERSION = 1
BOOTSTRAP_NAME = "repobrief_agent_benchmark_source_bootstrap.py"


def _python_c_program() -> tuple[bytes, str]:
    try:
        raw = Path("/proc/self/cmdline").read_bytes()
    except OSError as exc:
        raise RuntimeError("immutable source bootstrap requires Linux /proc") from exc
    parts = raw.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    positions = [index for index, value in enumerate(parts) if value == b"-c"]
    if len(positions) != 1:
        raise RuntimeError("immutable source bootstrap requires exactly one python -c program")
    index = positions[0]
    if index + 2 >= len(parts) or sys.argv[0] != "-c" or len(sys.argv) < 2:
        raise RuntimeError("immutable source bootstrap invocation is incomplete")
    program = parts[index + 1]
    target = os.fsdecode(parts[index + 2])
    if target != sys.argv[1]:
        raise RuntimeError("immutable source bootstrap target argv mismatch")
    return program, target



def _open_absolute_regular_nofollow(path: Path, *, label: str) -> int:
    requested = path.expanduser()
    if not requested.is_absolute():
        raise RuntimeError(f"{label} path must be absolute")
    parts = requested.parts
    if (
        len(parts) < 2
        or parts[0] != os.sep
        or any(part in {"", ".", ".."} for part in parts[1:])
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise RuntimeError(f"{label} path is not safely openable")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directories: list[int] = []
    try:
        current = os.open(os.sep, directory_flags)
        directories.append(current)
        for component in parts[1:-1]:
            current = os.open(component, directory_flags, dir_fd=current)
            directories.append(current)
            if not stat.S_ISDIR(os.fstat(current).st_mode):
                raise RuntimeError(f"{label} parent path is not a directory")
        return os.open(parts[-1], file_flags, dir_fd=current)
    except OSError as exc:
        raise RuntimeError(f"{label} path must be symlink-free") from exc
    finally:
        for directory_fd in reversed(directories):
            os.close(directory_fd)


def _read_target(path: Path) -> tuple[bytes, dict[str, object]]:
    requested = path.expanduser()
    if not requested.is_absolute():
        raise RuntimeError("immutable source bootstrap target must be absolute")
    before = requested.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError("immutable source bootstrap target must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > MAX_SOURCE_BYTES:
        raise RuntimeError("immutable source bootstrap target size is invalid")
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    descriptor = _open_absolute_regular_nofollow(
        requested, label="immutable source bootstrap target"
    )
    try:
        opened = os.fstat(descriptor)
        identity_opened = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if identity_opened != identity_before:
            raise RuntimeError("immutable source bootstrap target changed before capture")
        data = bytearray()
        while len(data) <= MAX_SOURCE_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_SOURCE_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            raise RuntimeError(
                "immutable source bootstrap cannot bind the opened target path"
            ) from exc
        if (
            not os.path.isabs(descriptor_path)
            or descriptor_path.endswith(" (deleted)")
            or os.path.normpath(descriptor_path) != os.path.normpath(str(requested))
        ):
            raise RuntimeError(
                "immutable source bootstrap opened target path is unavailable"
            )
        after = requested.lstat()
        identity_after_descriptor = (
            after_descriptor.st_dev,
            after_descriptor.st_ino,
            after_descriptor.st_mode,
            after_descriptor.st_size,
            after_descriptor.st_mtime_ns,
            after_descriptor.st_ctime_ns,
        )
        identity_after_path = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            identity_after_descriptor != identity_before
            or identity_after_path != identity_before
            or len(data) != before.st_size
            or len(data) > MAX_SOURCE_BYTES
        ):
            raise RuntimeError("immutable source bootstrap target changed during capture")
        resolved = Path(descriptor_path)
        raw = bytes(data)
        return raw, {
            "path": str(resolved),
            "name": resolved.name,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    finally:
        os.close(descriptor)


def _main() -> None:
    program, target_arg = _python_c_program()
    target = Path(target_arg)
    target_raw, target_identity = _read_target(target)
    bootstrap_identity = {
        "schema_version": BOOTSTRAP_SCHEMA_VERSION,
        "kind": BOOTSTRAP_KIND,
        "name": BOOTSTRAP_NAME,
        "bytes": len(program),
        "sha256": hashlib.sha256(program).hexdigest(),
    }
    resolved = Path(str(target_identity["path"]))
    sys.argv = [str(resolved), *sys.argv[2:]]
    namespace = {
        "__name__": "__main__",
        "__file__": str(resolved),
        "__package__": None,
        "__builtins__": __builtins__,
        "__grabowski_captured_entrypoint_active__": True,
        "__grabowski_captured_entrypoint_raw__": target_raw,
        "__grabowski_captured_entrypoint_identity__": target_identity,
        "__grabowski_entrypoint_bootstrap_identity__": bootstrap_identity,
        "__grabowski_entrypoint_bootstrap_raw__": program,
    }
    exec(compile(target_raw, str(resolved), "exec"), namespace)
    raise RuntimeError("immutable source bootstrap target returned unexpectedly")


_main()
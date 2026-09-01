from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import fcntl
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Literal, cast, get_args

import grabowski_fleet as fleet
import grabowski_mcp as base
import grabowski_chronik as chronik
import grabowski_recall as recall
import grabowski_privileged as privileged
import grabowski_recovery as recovery
import grabowski_resources as resources
import grabowski_nonconflict as nonconflict
import grabowski_consumer_surface as consumer_surface
import grabowski_command_identity as command_identity
import grabowski_bureau_runtime_refresh_executor as bureau_runtime_refresh_executor
import grabowski_lifecycle_projection as lifecycle_projection
import grabowski_sqlite_store as sqlite_store
import grabowski_terminal_convergence as terminal_convergence
import grabowski_reposkop_effectiveness as reposkop_effectiveness
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
TASK_DB = Path(
    os.environ.get(
        "GRABOWSKI_TASK_DB",
        str(operator.STATE_DIR / "tasks.sqlite3"),
    )
).expanduser()
TASK_OUTCOMES_DIR = TASK_DB.with_suffix(".outcomes")
REPOSKOP_SHADOW_TERMINAL_MARKER_MAX_BYTES = 64 * 1024
TASK_LIST_SCAN_BATCH = 100
TASK_RECONCILE_BATCH_LIMIT = 500
DEFAULT_TASK_RECONCILE_BATCH_SIZE = 100
TASK_RECONCILE_ACTIVE_REFRESH_MAX = 20
TASK_RECONCILE_ACTIVE_CURSOR_METADATA_KEY = "task_reconcile_active_refresh_cursor_v1"
DEFAULT_TASK_RECONCILE_CHECK_LIMIT = 50
TASK_RECONCILE_CHECK_LIMIT = 200
TASK_RECONCILE_CHECK_MAX_BYTES = 1024 * 1024
TASK_RECONCILE_CHECK_CURSOR_SCOPE = "task-reconcile-check-v1"
TASK_RECONCILE_CURSOR_METADATA_KEY = "task_reconcile_refresh_cursor_v1"
TASK_RECONCILE_CYCLE_VERSION = 2
TASK_RECONCILE_CYCLE_PHASE = "scan_to_high_water"
TASK_RECONCILE_SEQUENCE_COUNTER_KEY = "task_reconcile_sequence_counter_v1"
TASK_RECONCILE_SEQUENCE_KEY_PREFIX = "task_reconcile_sequence_v1:"
TASK_RECONCILE_SEQUENCE_MAX = (1 << 63) - 1
TASK_RECONCILE_PHASE_TURN_METADATA_KEY = "task_reconcile_phase_turn_v1"
TASK_RECONCILE_PHASE_TERMINALIZATION = "terminalization"
TASK_RECONCILE_PHASE_TASKS = "tasks"
TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY = (
    "task_terminalization_recovery_cursor_v1"
)
TASK_TERMINALIZATION_RECOVERY_CURSOR_VERSION = 1
REPOSKOP_SHADOW_TERMINAL_FINALIZED_METADATA_PREFIX = (
    "reposkop_shadow_terminal_finalized_v1:"
)
GRABOWSKI_RUNTIME_PYTHON = operator.HOME / ".local/share/grabowski-mcp/.venv/bin/python"
GRABOWSKI_REPOSITORY_SLUG = "heimgewebe/grabowski"
MANAGED_BUILD_RESOLVER = (
    operator.HOME / ".local/lib/heim-pc/managed-build/scripts/managed_build.py"
)
MANAGED_BUILD_PYTHON = Path("/usr/bin/python3")
MANAGED_CARGO_CACHE_ROOT = operator.HOME / ".cache/heim-pc/managed-builds/cargo"
MANAGED_BUILD_STATE_ROOT = operator.HOME / ".local/state/heim-pc/managed-builds"
MANAGED_CARGO_LOCK_ROOT = MANAGED_BUILD_STATE_ROOT / "cache-locks" / "cargo"
MANAGED_CARGO_PROFILE = "operator-task"
SYSTEMD_ENV_EXECUTABLE = "/usr/bin/env"
FLOCK_EXECUTABLE = "/usr/bin/flock"
SCRIPT_EXECUTABLES = frozenset({"bash", "sh", "zsh", "fish", "python", "python3"})
CARGO_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_])cargo(?:$|[^A-Za-z0-9_])")
JUST_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_])just(?:$|[^A-Za-z0-9_])")
MAKE_TOKEN = re.compile(r"(?:^|[^A-Za-z0-9_])make(?:$|[^A-Za-z0-9_])")
MAX_BUILD_SCRIPT_INSPECTION_BYTES = 256 * 1024
MANAGED_CARGO_ATTENTION_MATCH_LIMIT = 50_000
DEFAULT_TASK_LIST_LIMIT = 20
TASK_OUTPUT_ROOT = Path(operator.STATE_DIR) / "task-output"
TASK_OUTPUT_LEGACY_ROOT = Path(operator.HOME)
TASK_OUTPUT_CONTRACT_VERSION = 2
TASK_OUTPUT_LEGACY_CONTRACT_VERSION = 1
TASK_OUTPUT_LAUNCHER_BINDING_KEY = "task_output_managed_from_attempt"
TASK_OUTPUT_DIRECTORY_PREFIX = ".grabowski-task-output"
TASK_OUTPUT_MAX_BYTES = 8 * 1024 * 1024
TASK_OUTPUT_TAIL_BYTES = 64 * 1024
TASK_OUTPUT_CAPTURE_PYTHON = "/usr/bin/python3"
TASK_LOG_RATE_LIMIT_INTERVAL_SECONDS = 30
TASK_LOG_RATE_LIMIT_BURST = 200
TASK_OUTPUT_CAPTURE_CODE = r"""
import os
import signal
import stat
import subprocess
import sys
import threading

directory = sys.argv[1]
limit = int(sys.argv[2])
tail_limit = int(sys.argv[3])
command = sys.argv[4:]
parent = os.path.dirname(directory)
name = os.path.basename(directory)
if (
    not command
    or not os.path.isabs(directory)
    or os.path.normpath(directory) != directory
    or not name
    or parent == directory
    or limit < 4096
    or tail_limit < 1
    or tail_limit >= limit // 2
):
    raise SystemExit(125)
marker_reserve = 256
head_limit = limit - tail_limit - marker_reserve
file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    file_flags |= os.O_NOFOLLOW
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    directory_flags |= os.O_NOFOLLOW
parent_fd = os.open(parent, directory_flags)
parent_before = os.fstat(parent_fd)
linked_parent = os.lstat(parent)
if (
    not stat.S_ISDIR(parent_before.st_mode)
    or stat.S_ISLNK(linked_parent.st_mode)
    or parent_before.st_dev != linked_parent.st_dev
    or parent_before.st_ino != linked_parent.st_ino
    or parent_before.st_uid != os.geteuid()
    or parent_before.st_gid != os.getegid()
    or parent_before.st_nlink < 1
    or (stat.S_IMODE(parent_before.st_mode) & 0o022) != 0
):
    raise RuntimeError("task output parent identity is unsafe")
os.mkdir(name, 0o700, dir_fd=parent_fd)
directory_fd = os.open(name, directory_flags, dir_fd=parent_fd)
opened_directory = os.fstat(directory_fd)
linked_directory = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
if (
    not stat.S_ISDIR(opened_directory.st_mode)
    or opened_directory.st_dev != linked_directory.st_dev
    or opened_directory.st_ino != linked_directory.st_ino
    or opened_directory.st_mode != linked_directory.st_mode
    or opened_directory.st_nlink != linked_directory.st_nlink
    or opened_directory.st_uid != parent_before.st_uid
    or opened_directory.st_gid != parent_before.st_gid
    or opened_directory.st_nlink < 1
    or stat.S_IMODE(opened_directory.st_mode) != 0o700
):
    raise RuntimeError("task output directory identity is unsafe")
stdout_fd = os.open("stdout.log", file_flags, 0o600, dir_fd=directory_fd)
try:
    stderr_fd = os.open("stderr.log", file_flags, 0o600, dir_fd=directory_fd)
except BaseException:
    os.close(stdout_fd)
    os.unlink("stdout.log", dir_fd=directory_fd)
    os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.close(parent_fd)
    raise
errors = []

def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short task output write")
        view = view[written:]

def pump(pipe, descriptor, stream):
    total = 0
    head_written = 0
    tail = bytearray()
    writing = True
    try:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if writing and head_written < head_limit:
                selected = chunk[: head_limit - head_written]
                try:
                    write_all(descriptor, selected)
                    head_written += len(selected)
                except BaseException as exc:
                    errors.append(exc)
                    writing = False
                overflow = chunk[len(selected):]
            else:
                overflow = chunk
            if overflow:
                tail.extend(overflow)
                if len(tail) > tail_limit:
                    del tail[: len(tail) - tail_limit]
        if writing and total > head_written:
            marker = (
                "\n<GRABOWSKI_TASK_OUTPUT_TRUNCATED "
                + stream
                + " total_bytes="
                + str(total)
                + " retained_head_bytes="
                + str(head_written)
                + " retained_tail_bytes="
                + str(len(tail))
                + ">\n"
            ).encode("utf-8")
            write_all(descriptor, marker[:marker_reserve])
            write_all(descriptor, tail)
        if writing:
            os.fsync(descriptor)
    except BaseException as exc:
        errors.append(exc)
    finally:
        pipe.close()

try:
    child = subprocess.Popen(
        command,
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        close_fds=True,
    )
    stdout_thread = threading.Thread(
        target=pump, args=(child.stdout, stdout_fd, "stdout")
    )
    stderr_thread = threading.Thread(
        target=pump, args=(child.stderr, stderr_fd, "stderr")
    )
    stdout_thread.start()
    stderr_thread.start()
    returncode = child.wait()
    stdout_thread.join()
    stderr_thread.join()
    if errors:
        raise errors[0]
    directory_after = os.fstat(directory_fd)
    linked_directory_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    parent_after = os.fstat(parent_fd)
    linked_parent_after = os.lstat(parent)
    if (
        directory_after.st_dev != opened_directory.st_dev
        or directory_after.st_ino != opened_directory.st_ino
        or directory_after.st_mode != opened_directory.st_mode
        or directory_after.st_nlink != opened_directory.st_nlink
        or linked_directory_after.st_dev != opened_directory.st_dev
        or linked_directory_after.st_ino != opened_directory.st_ino
        or linked_directory_after.st_mode != opened_directory.st_mode
        or linked_directory_after.st_nlink != opened_directory.st_nlink
        or parent_after.st_dev != parent_before.st_dev
        or parent_after.st_ino != parent_before.st_ino
        or parent_after.st_mode != parent_before.st_mode
        or linked_parent_after.st_dev != parent_before.st_dev
        or linked_parent_after.st_ino != parent_before.st_ino
        or linked_parent_after.st_mode != parent_before.st_mode
    ):
        raise RuntimeError("task output path identity changed during capture")
    os.fsync(directory_fd)
    os.fsync(parent_fd)
finally:
    os.close(stdout_fd)
    os.close(stderr_fd)
    os.close(directory_fd)
    os.close(parent_fd)
if returncode < 0:
    signum = -returncode
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)
if returncode == 1 and command and os.path.basename(command[0]) == "rg":
    returncode = 0
raise SystemExit(returncode)
""".strip()
TASK_OUTPUT_REMOTE_READ_CODE = r"""
import os
import stat
import sys

directory = sys.argv[1]
name = sys.argv[2]
max_lines = int(sys.argv[3])
byte_limit = int(sys.argv[4])
parent = os.path.dirname(directory)
directory_name = os.path.basename(directory)
if (
    not os.path.isabs(directory)
    or os.path.normpath(directory) != directory
    or not directory_name
    or parent == directory
    or name not in {"stdout.log", "stderr.log"}
    or max_lines < 1
    or max_lines > 2000
    or byte_limit < 1024
):
    raise SystemExit(125)
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    directory_flags |= os.O_NOFOLLOW
parent_fd = os.open(parent, directory_flags)
parent_before = os.fstat(parent_fd)
linked_parent = os.lstat(parent)
if (
    not stat.S_ISDIR(parent_before.st_mode)
    or stat.S_ISLNK(linked_parent.st_mode)
    or parent_before.st_dev != linked_parent.st_dev
    or parent_before.st_ino != linked_parent.st_ino
    or parent_before.st_uid != os.geteuid()
    or parent_before.st_gid != os.getegid()
    or parent_before.st_nlink < 1
    or (stat.S_IMODE(parent_before.st_mode) & 0o022) != 0
):
    raise RuntimeError("task output parent identity is unsafe")
try:
    directory_fd = os.open(directory_name, directory_flags, dir_fd=parent_fd)
except FileNotFoundError:
    print("GRABOWSKI_TASK_OUTPUT_DIRECTORY_MISSING", file=sys.stderr)
    os.close(parent_fd)
    raise SystemExit(44)
try:
    opened_directory = os.fstat(directory_fd)
    linked_directory = os.stat(
        directory_name, dir_fd=parent_fd, follow_symlinks=False
    )
    if (
        not stat.S_ISDIR(opened_directory.st_mode)
        or opened_directory.st_dev != linked_directory.st_dev
        or opened_directory.st_ino != linked_directory.st_ino
        or opened_directory.st_mode != linked_directory.st_mode
        or opened_directory.st_nlink != linked_directory.st_nlink
        or opened_directory.st_uid != parent_before.st_uid
        or opened_directory.st_gid != parent_before.st_gid
        or opened_directory.st_nlink < 1
        or stat.S_IMODE(opened_directory.st_mode) != 0o700
    ):
        raise RuntimeError("task output directory identity is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        print("GRABOWSKI_TASK_OUTPUT_FILE_MISSING", file=sys.stderr)
        raise SystemExit(45)
    try:
        before = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_uid != opened_directory.st_uid
            or before.st_gid != opened_directory.st_gid
            or before.st_dev != linked.st_dev
            or before.st_ino != linked.st_ino
            or before.st_mode != linked.st_mode
            or before.st_nlink != linked.st_nlink
        ):
            raise RuntimeError("task output file identity is unsafe")
        end = int(before.st_size)
        start = max(0, end - byte_limit)
        os.lseek(descriptor, start, os.SEEK_SET)
        data = bytearray()
        remaining = end - start
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            data.extend(chunk)
            remaining -= len(chunk)
        lines = bytes(data).splitlines(keepends=True)
        line_truncated = len(lines) > max_lines
        if line_truncated:
            data = bytearray(b"".join(lines[-max_lines:]))
        after = os.fstat(descriptor)
        linked_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        directory_after = os.fstat(directory_fd)
        linked_directory_after = os.stat(
            directory_name, dir_fd=parent_fd, follow_symlinks=False
        )
        parent_after = os.fstat(parent_fd)
        linked_parent_after = os.lstat(parent)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_mode != before.st_mode
            or after.st_nlink != before.st_nlink
            or linked_after.st_dev != before.st_dev
            or linked_after.st_ino != before.st_ino
            or linked_after.st_mode != before.st_mode
            or linked_after.st_nlink != before.st_nlink
            or directory_after.st_dev != opened_directory.st_dev
            or directory_after.st_ino != opened_directory.st_ino
            or directory_after.st_mode != opened_directory.st_mode
            or directory_after.st_nlink != opened_directory.st_nlink
            or linked_directory_after.st_dev != opened_directory.st_dev
            or linked_directory_after.st_ino != opened_directory.st_ino
            or linked_directory_after.st_mode != opened_directory.st_mode
            or linked_directory_after.st_nlink != opened_directory.st_nlink
            or parent_after.st_dev != parent_before.st_dev
            or parent_after.st_ino != parent_before.st_ino
            or parent_after.st_mode != parent_before.st_mode
            or parent_after.st_nlink != parent_before.st_nlink
            or linked_parent_after.st_dev != parent_before.st_dev
            or linked_parent_after.st_ino != parent_before.st_ino
            or linked_parent_after.st_mode != parent_before.st_mode
            or linked_parent_after.st_nlink != parent_before.st_nlink
        ):
            raise RuntimeError("task output path identity changed during read")
        print(
            "GRABOWSKI_TASK_OUTPUT_READ_METADATA "
            + "byte_truncated="
            + str(int(start > 0))
            + " line_truncated="
            + str(int(line_truncated)),
            file=sys.stderr,
        )
        view = memoryview(data)
        while view:
            written = os.write(1, view)
            if written <= 0:
                raise OSError("short task output read write")
            view = view[written:]
    finally:
        os.close(descriptor)
finally:
    os.close(directory_fd)
    os.close(parent_fd)
""".strip()
TASK_OUTPUT_CLEANUP_CODE = r"""
import hashlib
import json
import os
import re
import stat
import sys

mode = sys.argv[1]
directory = sys.argv[2]
token = sys.argv[3]
expected_stdout_sha256 = sys.argv[4]
expected_stderr_sha256 = sys.argv[5]
expected_stdout_bytes = int(sys.argv[6])
expected_stderr_bytes = int(sys.argv[7])
parent = os.path.dirname(directory)
directory_name = os.path.basename(directory)
match = re.fullmatch(
    r"\.grabowski-task-output-([0-9a-f]{24})-a([1-9][0-9]*)",
    directory_name,
)
if (
    mode not in {"inspect", "delete"}
    or not os.path.isabs(directory)
    or os.path.normpath(directory) != directory
    or match is None
    or parent == directory
    or re.fullmatch(r"[0-9a-f]{64}", token) is None
):
    raise SystemExit(125)
if mode == "inspect":
    if (
        expected_stdout_sha256 != "-"
        or expected_stderr_sha256 != "-"
        or expected_stdout_bytes != -1
        or expected_stderr_bytes != -1
    ):
        raise SystemExit(125)
else:
    if (
        re.fullmatch(r"[0-9a-f]{64}", expected_stdout_sha256) is None
        or re.fullmatch(r"[0-9a-f]{64}", expected_stderr_sha256) is None
        or not 0 <= expected_stdout_bytes <= 8 * 1024 * 1024
        or not 0 <= expected_stderr_bytes <= 8 * 1024 * 1024
    ):
        raise SystemExit(125)

directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
file_flags = os.O_RDONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    directory_flags |= os.O_NOFOLLOW
    file_flags |= os.O_NOFOLLOW
parent_fd = os.open(parent, directory_flags)
parent_before = os.fstat(parent_fd)
linked_parent = os.lstat(parent)
if (
    not stat.S_ISDIR(parent_before.st_mode)
    or stat.S_ISLNK(linked_parent.st_mode)
    or parent_before.st_dev != linked_parent.st_dev
    or parent_before.st_ino != linked_parent.st_ino
    or parent_before.st_uid != os.geteuid()
    or parent_before.st_gid != os.getegid()
    or parent_before.st_nlink < 1
    or (stat.S_IMODE(parent_before.st_mode) & 0o022) != 0
):
    raise RuntimeError("task output cleanup parent identity is unsafe")

staging_name = (
    ".grabowski-task-output-cleanup-"
    + match.group(1)
    + "-a"
    + match.group(2)
    + "-"
    + token[:16]
)

def exists_at(name):
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False

def open_directory(name):
    descriptor = os.open(name, directory_flags, dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_dev != linked.st_dev
        or opened.st_ino != linked.st_ino
        or opened.st_mode != linked.st_mode
        or opened.st_nlink != linked.st_nlink
        or opened.st_uid != parent_before.st_uid
        or opened.st_gid != parent_before.st_gid
        or opened.st_nlink < 1
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise RuntimeError("task output cleanup directory identity is unsafe")
    return descriptor, opened

def stream_inventory(directory_fd, directory_metadata, name, *, allow_missing):
    try:
        descriptor = os.open(name, file_flags, dir_fd=directory_fd)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise RuntimeError("task output cleanup stream is missing")
    try:
        before = os.fstat(descriptor)
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_uid != directory_metadata.st_uid
            or before.st_gid != directory_metadata.st_gid
            or before.st_dev != linked.st_dev
            or before.st_ino != linked.st_ino
            or before.st_mode != linked.st_mode
            or before.st_nlink != linked.st_nlink
            or before.st_size > 8 * 1024 * 1024
        ):
            raise RuntimeError("task output cleanup stream identity is unsafe")
        digest = hashlib.sha256()
        remaining = int(before.st_size)
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise RuntimeError("short task output cleanup stream read")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        linked_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_mode != before.st_mode
            or after.st_nlink != before.st_nlink
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or linked_after.st_dev != before.st_dev
            or linked_after.st_ino != before.st_ino
            or linked_after.st_mode != before.st_mode
            or linked_after.st_nlink != before.st_nlink
            or linked_after.st_size != before.st_size
            or linked_after.st_mtime_ns != before.st_mtime_ns
            or linked_after.st_ctime_ns != before.st_ctime_ns
        ):
            raise RuntimeError("task output cleanup stream changed during read")
        return {
            "sha256": digest.hexdigest(),
            "bytes": int(before.st_size),
            "mode": stat.S_IMODE(before.st_mode),
            "nlink": int(before.st_nlink),
        }
    finally:
        os.close(descriptor)

def inventory(directory_fd, directory_metadata, *, allow_missing):
    names = set(os.listdir(directory_fd))
    unexpected = sorted(names - {"stdout.log", "stderr.log"})
    if unexpected:
        raise RuntimeError("task output cleanup directory contains unexpected entries")
    streams = {
        "stdout": stream_inventory(
            directory_fd, directory_metadata, "stdout.log", allow_missing=allow_missing
        ),
        "stderr": stream_inventory(
            directory_fd, directory_metadata, "stderr.log", allow_missing=allow_missing
        ),
    }
    return streams

def compare_expected(streams):
    expected = {
        "stdout": (expected_stdout_sha256, expected_stdout_bytes),
        "stderr": (expected_stderr_sha256, expected_stderr_bytes),
    }
    for stream, (sha256, size) in expected.items():
        value = streams[stream]
        if value is None:
            continue
        if value["sha256"] != sha256 or value["bytes"] != size:
            raise RuntimeError("task output cleanup inventory mismatch")

original_exists = exists_at(directory_name)
staging_exists = exists_at(staging_name)
if original_exists and staging_exists:
    raise RuntimeError("task output cleanup has conflicting original and staging paths")
if mode == "inspect":
    if staging_exists:
        print("GRABOWSKI_TASK_OUTPUT_CLEANUP_STAGING_PRESENT", file=sys.stderr)
        os.close(parent_fd)
        raise SystemExit(46)
    if not original_exists:
        print("GRABOWSKI_TASK_OUTPUT_DIRECTORY_MISSING", file=sys.stderr)
        os.close(parent_fd)
        raise SystemExit(44)
    directory_fd, directory_metadata = open_directory(directory_name)
    try:
        streams = inventory(directory_fd, directory_metadata, allow_missing=False)
        print(json.dumps({
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_inventory",
            "task_id": match.group(1),
            "attempt": int(match.group(2)),
            "directory": directory,
            "streams": streams,
        }, sort_keys=True, separators=(",", ":")))
    finally:
        os.close(directory_fd)
        os.close(parent_fd)
    raise SystemExit(0)

if original_exists:
    active_name = directory_name
    resumed_from_staging = False
elif staging_exists:
    active_name = staging_name
    resumed_from_staging = True
else:
    print("GRABOWSKI_TASK_OUTPUT_DIRECTORY_MISSING", file=sys.stderr)
    os.close(parent_fd)
    raise SystemExit(44)

directory_fd, directory_metadata = open_directory(active_name)
try:
    streams = inventory(
        directory_fd,
        directory_metadata,
        allow_missing=resumed_from_staging,
    )
    compare_expected(streams)
    if not resumed_from_staging:
        if streams["stdout"] is None or streams["stderr"] is None:
            raise RuntimeError("task output cleanup original contract is incomplete")
        os.rename(
            directory_name,
            staging_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
        linked_staging = os.stat(
            staging_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            linked_staging.st_dev != directory_metadata.st_dev
            or linked_staging.st_ino != directory_metadata.st_ino
            or linked_staging.st_mode != directory_metadata.st_mode
            or linked_staging.st_nlink != directory_metadata.st_nlink
        ):
            raise RuntimeError("task output cleanup staging identity mismatch")
    removed = []
    for stream_name in ("stdout.log", "stderr.log"):
        try:
            os.unlink(stream_name, dir_fd=directory_fd)
            removed.append(stream_name)
        except FileNotFoundError:
            if not resumed_from_staging:
                raise
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
try:
    os.rmdir(staging_name, dir_fd=parent_fd)
except FileNotFoundError:
    raise RuntimeError("task output cleanup staging path disappeared")
os.fsync(parent_fd)
parent_after = os.fstat(parent_fd)
linked_parent_after = os.lstat(parent)
if (
    parent_after.st_dev != parent_before.st_dev
    or parent_after.st_ino != parent_before.st_ino
    or parent_after.st_mode != parent_before.st_mode
    or linked_parent_after.st_dev != parent_before.st_dev
    or linked_parent_after.st_ino != parent_before.st_ino
    or linked_parent_after.st_mode != parent_before.st_mode
):
    raise RuntimeError("task output cleanup parent changed during delete")
os.close(parent_fd)
print(json.dumps({
    "schema_version": 1,
    "kind": "grabowski_task_output_cleanup_delete_result",
    "task_id": match.group(1),
    "attempt": int(match.group(2)),
    "directory": directory,
    "token": token,
    "resumed_from_staging": resumed_from_staging,
    "removed": removed,
    "streams": streams,
    "post_state": "absent",
}, sort_keys=True, separators=(",", ":")))
""".strip()

# One re-entrant in-process lock plus one shared file lock serializes every
# persistent-task mutation across the MCP runtime and the timer-driven
# reconciler process. Nested task operations reuse the outer file lock.
TASK_RECONCILE_LOCK = threading.RLock()
_TASK_MUTATION_LOCK_STATE = threading.local()


def _task_mutation_lock_parent_identity(descriptor: int, parent: Path) -> None:
    opened = os.fstat(descriptor)
    linked = os.stat(parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or opened.st_dev != linked.st_dev
        or opened.st_ino != linked.st_ino
        or opened.st_uid != os.geteuid()
        or opened.st_gid != os.getegid()
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise PermissionError(
            "Task mutation lock parent violates its directory contract"
        )


def _task_mutation_lock_identity(
    descriptor: int,
    parent_descriptor: int,
    filename: str,
) -> None:
    opened = os.fstat(descriptor)
    linked = os.stat(
        filename,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or opened.st_dev != linked.st_dev
        or opened.st_ino != linked.st_ino
        or opened.st_uid != os.geteuid()
        or opened.st_gid != os.getegid()
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
    ):
        raise PermissionError("Task mutation lock violates its file contract")


def _open_task_mutation_lock(lock_path: Path) -> tuple[int, int]:
    parent = lock_path.parent
    if parent.is_symlink():
        raise PermissionError("Task mutation lock parent may not be a symlink")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        parent_flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        parent_flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(parent, parent_flags)
    except OSError as exc:
        raise PermissionError(
            "Task mutation lock parent cannot be opened safely"
        ) from exc
    try:
        _task_mutation_lock_parent_identity(parent_descriptor, parent)
        flags = os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            try:
                descriptor = os.open(
                    lock_path.name,
                    flags,
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError:
                try:
                    descriptor = os.open(
                        lock_path.name,
                        flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=parent_descriptor,
                    )
                except FileExistsError:
                    descriptor = os.open(
                        lock_path.name,
                        flags,
                        dir_fd=parent_descriptor,
                    )
        except OSError as exc:
            raise PermissionError(
                "Task mutation lock cannot be opened safely"
            ) from exc
        try:
            _task_mutation_lock_identity(
                descriptor,
                parent_descriptor,
                lock_path.name,
            )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, parent_descriptor
    except BaseException:
        os.close(parent_descriptor)
        raise


@contextmanager
def _task_mutation_lock() -> Iterator[None]:
    with TASK_RECONCILE_LOCK:
        depth = int(getattr(_TASK_MUTATION_LOCK_STATE, "depth", 0))
        if depth:
            _TASK_MUTATION_LOCK_STATE.depth = depth + 1
            try:
                yield
            finally:
                _TASK_MUTATION_LOCK_STATE.depth = depth
            return

        lock_path = TASK_DB.with_suffix(".mutation.lock")
        descriptor, parent_descriptor = _open_task_mutation_lock(lock_path)
        locked = False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            _task_mutation_lock_parent_identity(
                parent_descriptor,
                lock_path.parent,
            )
            _task_mutation_lock_identity(
                descriptor,
                parent_descriptor,
                lock_path.name,
            )
            _TASK_MUTATION_LOCK_STATE.depth = 1
            try:
                yield
            finally:
                _TASK_MUTATION_LOCK_STATE.depth = 0
        finally:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
            os.close(parent_descriptor)


def _serialize_task_mutation(function):
    @functools.wraps(function)
    def serialized(*args: Any, **kwargs: Any) -> Any:
        with _task_mutation_lock():
            return function(*args, **kwargs)

    return serialized

TASK_ID = re.compile(r"[0-9a-f]{24}\Z")
EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Deliberately canonical: only names emitted by _task_unit are accepted.
# Manual or future-format units must never be adopted as authoritative by accident.
UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
# Authoritative contract for static callers, runtime validation, and reflected tool schemas.
ResumePolicy = Literal[
    "manual",
    "never",
    "retry-safe",
    "verify-then-retry",
]
RESUME_POLICIES: frozenset[str] = frozenset(get_args(ResumePolicy))
CHRONIK_OPERATION_TASK_CLASS = {
    "implement": "coding",
    "review": "review",
    "merge": "merge",
    "deploy": "deploy",
    "runtime_verify": "runtime_verify",
    "recovery": "recovery",
    "other": "other",
}
TASK_STATES = {
    "launching",
    "running",
    "completed",
    "failed",
    "cancelled",
    "timed_out",
    "signalled",
    "outcome_unknown",
    "interrupted",
}
TASK_STATE_PROJECTIONS: dict[str, tuple[str, ...]] = {
    # "active" is current execution truth, not retained recovery history.
    "active": ("launching", "running"),
    "attention": ("interrupted", "outcome_unknown", "failed", "timed_out", "signalled"),
    "terminal": ("completed", "failed", "cancelled", "timed_out", "signalled"),
}
MUTATING_AGENT_EXECUTABLES = reposkop_effectiveness.AGENT_EXECUTABLES
READ_ONLY_AGENT_MODES = reposkop_effectiveness.READ_ONLY_AGENT_MODES
REPOSKOP_EXECUTION_ATTESTATION_POLICY_VERSION = reposkop_effectiveness.POLICY_VERSION
REPOSKOP_EXECUTION_ATTESTATION_KIND = (
    "grabowski.task_reposkop_execution_attestation"
)
TASK_EXECUTION_BACKENDS = {"systemd-user", "systemd-root-broker"}
SYSTEMD_SCOPES = {"user", "system"}
TASK_SCHEMA_V4_ADDITIVE_COLUMNS = {
    "terminalization_sha256": ("TEXT", 0, 0),
    "terminalized_at_unix": ("INTEGER", 0, 0),
    "lifecycle_receipt_sha256": ("TEXT", 0, 0),
}
TASK_SCHEMA_V5_ADDITIVE_COLUMNS = {
    **TASK_SCHEMA_V4_ADDITIVE_COLUMNS,
    "repository_scope_manifest_json": ("TEXT", 0, 0),
}
LEASE_MAINTENANCE_TASK_STATES = {"running", "outcome_unknown"}
TASK_LEASE_DELEGATION_STATES = frozenset({"running"})
TASK_RETRY_CONTEXT_SCHEMA_VERSION = 1
TASK_OPERATION_IDENTITY_SCHEMA_VERSION = 1
TASK_OPERATION_REUSE_WINDOW_SECONDS = 600
TASK_ACTIVE_OBSERVATION_MAX_AGE_SECONDS = 120
TASK_INTERRUPTED_RECOVERY_CONTEXT_SCHEMA_VERSION = 1
TASK_INTERRUPTED_RECOVERY_CONTEXT_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "source_task_id",
        "source_attempt",
        "source_state",
        "source_resume_policy",
        "source_unit",
        "source_authoritative_unit",
        "source_updated_at_unix",
        "source_execution_identity_sha256",
        "source_recovery_evidence_sha256",
        "named_state_change",
        "admitted_at_unix",
        "does_not_establish",
        "context_sha256",
    }
)
UNCHANGED_RETRY_STATES = frozenset(TASK_STATE_PROJECTIONS["attention"])


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _redact_reason(text: str) -> str:
    redact_text = getattr(operator, "_redact_text", None)
    if callable(redact_text):
        return redact_text(text)
    redact = getattr(operator, "_redact", None)
    if callable(redact):
        return redact(text)
    return text


def _is_terminal_state(state: str) -> bool:
    return state in {"completed", "failed", "cancelled", "timed_out", "signalled"}


def _state_releases_resources(state: str) -> bool:
    return _is_terminal_state(state)


def _read_existing_outcome_receipt(
    path: Path,
    *,
    transition_sha256: str | None,
    allow_legacy: bool,
) -> str | None:
    existing = json.loads(path.read_text(encoding="utf-8"))
    existing_digest = existing.get("receipt_sha256")
    if not isinstance(existing_digest, str) or existing_digest != _sha256_json(
        {key: value for key, value in existing.items() if key != "receipt_sha256"}
    ):
        raise RuntimeError("Stored task lifecycle receipt integrity is invalid")
    if transition_sha256 is None:
        return existing_digest
    existing_terminalization = existing.get("terminalization")
    if (
        isinstance(existing_terminalization, dict)
        and existing_terminalization.get("transition_sha256") == transition_sha256
    ):
        return existing_digest
    if allow_legacy and existing.get("schema_version") == 1:
        return None
    raise RuntimeError("Stored task lifecycle receipt belongs to another transition")


def _write_outcome_receipt(
    record: dict[str, Any],
    state: str,
    observation: dict[str, Any] | None,
    *,
    terminalization: dict[str, Any] | None = None,
) -> str | None:
    if not _is_terminal_state(state):
        return None
    TASK_OUTCOMES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    primary_path = TASK_OUTCOMES_DIR / f"{record['task_id']}.json"
    terminalization_payload: dict[str, Any] | None = None
    transition_sha256: str | None = None
    if terminalization is not None:
        transition_sha256 = terminalization["transition_sha256"]
        terminalization_payload = {
            "kind": terminalization["kind"],
            "transition_sha256": transition_sha256,
            "task_projection_sha256": terminalization["task_projection_sha256"],
            "requested_resource_keys": terminalization["requested_resource_keys"],
            "requested_resource_keys_sha256": terminalization[
                "requested_resource_keys_sha256"
            ],
            "prior_leases": terminalization["prior_leases"],
            "prior_leases_sha256": terminalization["prior_leases_sha256"],
            "revoked_resource_keys": terminalization["revoked_resource_keys"],
            "missing_resource_keys": terminalization["missing_resource_keys"],
            "prepared_at_unix": terminalization["prepared_at_unix"],
            "leases_revoked_at_unix": terminalization["leases_revoked_at_unix"],
            "recovery_status": terminalization["recovery_status"],
        }
    payload = {
        "schema_version": 2 if terminalization is not None else 1,
        "task_id": record["task_id"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "attempt": record["attempt"],
        "state": state,
        "argv_sha256": record["argv_sha256"],
        "execution_envelope_sha256": record.get("execution_envelope_sha256"),
        "resource_keys": _record_resource_keys(record),
        "observed_at_unix": _now(),
        "observation_sha256": _sha256_json(observation or {}),
        "observation": observation or {},
    }
    if terminalization is not None:
        payload["kind"] = "grabowski_task_lifecycle_receipt"
        payload["terminalization"] = terminalization_payload
    payload["receipt_sha256"] = _sha256_json(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )

    candidates = [(primary_path, terminalization is not None)]
    if terminalization is not None:
        candidates.append(
            (TASK_OUTCOMES_DIR / f"{record['task_id']}.lifecycle.json", False)
        )
    for path, allow_legacy in candidates:
        if not path.exists():
            continue
        existing_digest = _read_existing_outcome_receipt(
            path,
            transition_sha256=transition_sha256,
            allow_legacy=allow_legacy,
        )
        if existing_digest is not None:
            return existing_digest

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{record['task_id']}.", suffix=".tmp", dir=TASK_OUTCOMES_DIR
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        for path, allow_legacy in candidates:
            try:
                os.link(tmp_name, path)
            except FileExistsError:
                existing_digest = _read_existing_outcome_receipt(
                    path,
                    transition_sha256=transition_sha256,
                    allow_legacy=allow_legacy,
                )
                if existing_digest is not None:
                    return existing_digest
                continue
            directory_fd = os.open(TASK_OUTCOMES_DIR, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return str(payload["receipt_sha256"])
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
    raise RuntimeError("Task lifecycle receipt could not be persisted")

def _classify_observation(result: dict[str, Any], properties: dict[str, str]) -> str:
    active = properties.get("ActiveState")
    load = properties.get("LoadState")
    unit_result = properties.get("Result")
    exec_code = properties.get("ExecMainCode")
    exec_status = properties.get("ExecMainStatus")
    if unit_result == "success" and exec_status in {None, "", "0"}:
        return "completed" if active not in {"active", "activating", "reloading"} else "running"
    if active in {"active", "activating", "reloading"}:
        return "running"
    if unit_result == "timeout":
        return "timed_out"
    if unit_result in {"signal", "core-dump"} or exec_code in {"2", "3"}:
        return "signalled"
    if unit_result in {"exit-code", "resources", "protocol", "watchdog"} or active == "failed":
        return "failed"
    if result["returncode"] != 0 or load in {None, "not-found"}:
        return "outcome_unknown"
    if active in {"inactive", "deactivating"}:
        return "completed" if unit_result in {None, "", "success"} else "failed"
    return "outcome_unknown"


TASK_SCHEMA_V5_COLUMN_SHAPES = {
    "task_id": ("TEXT", 0, 1),
    "host": ("TEXT", 1, 0),
    "unit": ("TEXT", 1, 0),
    "attempt": ("INTEGER", 1, 0),
    "state": ("TEXT", 1, 0),
    "resume_policy": ("TEXT", 1, 0),
    "argv_json": ("TEXT", 1, 0),
    "argv_sha256": ("TEXT", 1, 0),
    "cwd": ("TEXT", 1, 0),
    "runtime_seconds": ("INTEGER", 1, 0),
    "cpu_weight": ("INTEGER", 1, 0),
    "io_weight": ("INTEGER", 1, 0),
    "memory_max_bytes": ("INTEGER", 0, 0),
    "created_at_unix": ("INTEGER", 1, 0),
    "updated_at_unix": ("INTEGER", 1, 0),
    "launcher_json": ("TEXT", 1, 0),
    "last_observation_json": ("TEXT", 0, 0),
    "resource_keys_json": ("TEXT", 1, 0),
    "lease_owner_id": ("TEXT", 0, 0),
    "request_id": ("TEXT", 0, 0),
    "origin_ref": ("TEXT", 0, 0),
    "external_run_id": ("TEXT", 0, 0),
    "execution_envelope_sha256": ("TEXT", 0, 0),
    "acceptance_json": ("TEXT", 1, 0),
    "request_sha256": ("TEXT", 0, 0),
    "execution_backend": ("TEXT", 1, 0),
    "systemd_scope": ("TEXT", 1, 0),
    "authoritative_unit": ("TEXT", 0, 0),
    "chronik_outbox_enabled": ("INTEGER", 1, 0),
    "chronik_outbox_state_root": ("TEXT", 0, 0),
    "chronik_context_json": ("TEXT", 0, 0),
    "terminalization_sha256": ("TEXT", 0, 0),
    "terminalized_at_unix": ("INTEGER", 0, 0),
    "lifecycle_receipt_sha256": ("TEXT", 0, 0),
    "repository_scope_manifest_json": ("TEXT", 0, 0),
}
TASK_SCHEMA_V1_COLUMNS = frozenset({
    "task_id", "host", "unit", "attempt", "state", "resume_policy",
    "argv_json", "argv_sha256", "cwd", "runtime_seconds", "cpu_weight",
    "io_weight", "memory_max_bytes", "created_at_unix", "updated_at_unix",
    "launcher_json", "last_observation_json",
})
TASK_SCHEMA_V2_COLUMNS = TASK_SCHEMA_V1_COLUMNS | {
    "resource_keys_json", "lease_owner_id",
}
TASK_SCHEMA_V3_COLUMNS = frozenset(TASK_SCHEMA_V5_COLUMN_SHAPES) - {
    "terminalization_sha256", "terminalized_at_unix",
    "lifecycle_receipt_sha256", "repository_scope_manifest_json",
}
TASK_SCHEMA_V4_COLUMNS = frozenset(TASK_SCHEMA_V5_COLUMN_SHAPES) - {
    "repository_scope_manifest_json",
}
TASK_SCHEMA_REQUIRED_INDEXES = frozenset({
    "tasks_state_created_task_idx", "tasks_created_task_idx",
})
TASK_CURRENT_SCHEMA_VERSION = "5"
TASK_SUPPORTED_SCHEMA_VERSIONS = ("1", "2", "3", "4", "5")
TASK_SCHEMA_MIGRATION_PATHS = {
    version: (version, TASK_CURRENT_SCHEMA_VERSION)
    for version in TASK_SUPPORTED_SCHEMA_VERSIONS
    if version != TASK_CURRENT_SCHEMA_VERSION
}
TASK_SCHEMA_RECOVERY_INSTRUCTION = (
    "Keep the task store unchanged; use a runtime that explicitly supports the "
    "observed schema or restore a verified backup before retrying."
)

TASK_SCHEMA_ROLLING_UPGRADE = {
    "current_runtime_current_store": "supported",
    "current_runtime_supported_older_store": (
        "supported_with_exclusive_migration"
    ),
    "current_runtime_newer_store": "fail_closed_without_mutation",
    "pre_t062_runtime_overlap_with_future_schema": (
        "unsupported_require_full_runtime_drain"
    ),
}


_schema_directory_lock = sqlite_store.schema_directory_lock
_readonly_sqlite = sqlite_store.readonly_sqlite


class TaskSchemaInventoryChanged(RuntimeError):
    pass


@contextmanager
def _inventory_readonly_sqlite(path: Path) -> Iterator[sqlite3.Connection]:
    with sqlite_store.inventory_readonly_sqlite(
        path,
        temporary_prefix="grabowski-task-schema-inventory-",
        error_type=TaskSchemaInventoryChanged,
    ) as connection:
        yield connection


_sqlite_integrity = sqlite_store.sqlite_integrity
_sqlite_fingerprint = sqlite_store.sqlite_fingerprint
_database_tables = sqlite_store.database_tables


def _metadata_shape(connection: sqlite3.Connection) -> tuple[tuple[str, str, int, int], ...]:
    return tuple(
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(metadata)")
    )


def _task_schema_version(connection: sqlite3.Connection) -> str | None:
    tables = _database_tables(connection)
    if not tables:
        return None
    if "metadata" not in tables:
        raise RuntimeError(
            "Task database schema metadata is missing; restore or inspect the store"
        )
    if _metadata_shape(connection) != (
        ("key", "TEXT", 0, 1),
        ("value", "TEXT", 1, 0),
    ):
        raise RuntimeError("Task database metadata table is malformed")
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError(
            "Task database schema_version metadata is missing or ambiguous"
        )
    return str(rows[0][0])


def _task_column_shapes(connection: sqlite3.Connection) -> dict[str, tuple[str, int, int]]:
    return {
        str(row[1]): (str(row[2]).upper(), int(row[3]), int(row[5]))
        for row in connection.execute("PRAGMA table_info(tasks)")
    }


def _task_indexes(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute("PRAGMA index_list(tasks)")
    }


def _validate_task_schema_legacy(
    connection: sqlite3.Connection,
    version: str,
) -> None:
    if _database_tables(connection) != {"metadata", "tasks"}:
        raise RuntimeError(
            f"Task database schema {version} has unsupported tables"
        )
    shapes = _task_column_shapes(connection)
    expected = {
        "1": TASK_SCHEMA_V1_COLUMNS,
        "2": TASK_SCHEMA_V2_COLUMNS,
        "3": TASK_SCHEMA_V3_COLUMNS,
        "4": TASK_SCHEMA_V4_COLUMNS,
    }[version]
    names = set(shapes)
    if names != expected:
        raise RuntimeError(
            f"Task database schema {version} is incomplete or unsupported"
        )
    mismatched = sorted(
        name for name, shape in shapes.items()
        if TASK_SCHEMA_V5_COLUMN_SHAPES.get(name) != shape
    )
    if mismatched:
        raise RuntimeError(
            f"Task database schema {version} has incompatible columns: "
            + ", ".join(mismatched)
        )
    if version in {"3", "4"}:
        missing_indexes = TASK_SCHEMA_REQUIRED_INDEXES - _task_indexes(connection)
        if missing_indexes:
            raise RuntimeError(
                f"Task database schema {version} indexes are incomplete: "
                + ", ".join(sorted(missing_indexes))
            )


def _validate_task_schema_current(connection: sqlite3.Connection) -> None:
    if _database_tables(connection) != {"metadata", "tasks"}:
        raise RuntimeError("Task database schema 5 has unsupported tables")
    shapes = _task_column_shapes(connection)
    if shapes != TASK_SCHEMA_V5_COLUMN_SHAPES:
        raise RuntimeError("Task database schema 5 is incomplete or unsupported")
    missing_indexes = TASK_SCHEMA_REQUIRED_INDEXES - _task_indexes(connection)
    if missing_indexes:
        raise RuntimeError(
            "Task database schema 5 indexes are incomplete: "
            + ", ".join(sorted(missing_indexes))
        )


def _task_schema_inventory() -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "store": "tasks",
        "database": str(TASK_DB),
        "observed_version": None,
        "current_version": TASK_CURRENT_SCHEMA_VERSION,
        "supported_versions": list(TASK_SUPPORTED_SCHEMA_VERSIONS),
        "status": "uninitialized",
        "migration_required": False,
        "migration_path": [],
        "write_compatible": False,
        "mutation_performed": False,
        "required_action": "initialize_on_first_write",
        "recovery_instruction": None,
        "rolling_upgrade": dict(TASK_SCHEMA_ROLLING_UPGRADE),
    }
    if not TASK_DB.exists():
        return result
    if TASK_DB.is_symlink() or not TASK_DB.is_file():
        result.update(
            status="blocked",
            required_action="inspect_store_path",
            recovery_instruction=TASK_SCHEMA_RECOVERY_INSTRUCTION,
            error="Task database must be a regular non-symlink file",
        )
        return result
    if TASK_DB.stat().st_size == 0:
        return result
    try:
        with _inventory_readonly_sqlite(TASK_DB) as connection:
            _sqlite_integrity(connection, "Task database", quick=True)
            observed = _task_schema_version(connection)
            result["observed_version"] = observed
            if observed not in TASK_SUPPORTED_SCHEMA_VERSIONS:
                future = (
                    observed is not None
                    and observed.isdecimal()
                    and int(observed) > int(TASK_CURRENT_SCHEMA_VERSION)
                )
                result.update(
                    status="unsupported_future" if future else "unsupported_schema",
                    required_action="upgrade_runtime_or_restore_verified_backup",
                    recovery_instruction=TASK_SCHEMA_RECOVERY_INSTRUCTION,
                )
                return result
            if observed == TASK_CURRENT_SCHEMA_VERSION:
                _validate_task_schema_current(connection)
            else:
                _validate_task_schema_legacy(connection, observed)
    except TaskSchemaInventoryChanged as exc:
        result.update(
            status="blocked",
            required_action="retry_schema_inventory",
            recovery_instruction=(
                "Retry after the concurrent writer completes; do not mutate the store "
                "from this inventory result."
            ),
            error=f"{type(exc).__name__}: {exc}",
        )
        return result
    except (OSError, RuntimeError, sqlite3.DatabaseError) as exc:
        result.update(
            status="blocked",
            required_action="restore_or_inspect_store",
            recovery_instruction=TASK_SCHEMA_RECOVERY_INSTRUCTION,
            error=f"{type(exc).__name__}: {exc}",
        )
        return result
    if observed == TASK_CURRENT_SCHEMA_VERSION:
        result.update(status="current", write_compatible=True, required_action="none")
        return result
    path = TASK_SCHEMA_MIGRATION_PATHS[observed]
    result.update(
        status="migration_required",
        migration_required=True,
        migration_path=[
            {
                "from": path[0],
                "to": path[1],
                "lock": "exclusive_store_directory",
                "transaction": "immediate",
                "verified_backup_required": True,
            }
        ],
        required_action="open_with_current_runtime_to_migrate",
    )
    return result


def _validate_task_backup(
    path: Path,
    version: str,
    fingerprint: str,
) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Task migration backup may not be a symlink: {path}")
    try:
        status = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Task migration backup disappeared: {path}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise RuntimeError(f"Task migration backup is not a regular file: {path}")
    mode = stat.S_IMODE(status.st_mode)
    if mode not in {0o400, 0o600}:
        raise RuntimeError(f"Task migration backup permissions are unsafe: {path}")
    with _readonly_sqlite(path) as backup:
        _sqlite_integrity(backup, "Task migration backup")
        if _task_schema_version(backup) != version:
            raise RuntimeError("Task migration backup schema version does not match")
        _validate_task_schema_legacy(backup, version)
        if _sqlite_fingerprint(backup) != fingerprint:
            raise RuntimeError("Task migration backup fingerprint does not match")


def _verified_task_migration_backup(
    version: str,
    fingerprint: str,
) -> Path:
    with _readonly_sqlite(TASK_DB) as source:
        source.execute("BEGIN")
        _sqlite_integrity(source, "Task database")
        if _sqlite_fingerprint(source) != fingerprint:
            raise RuntimeError(
                "Task database changed identity before backup; retry migration"
            )
        backup_path = TASK_DB.parent / (
            f"{TASK_DB.name}.schema-{version}-{fingerprint}.backup"
        )
        if backup_path.exists() or backup_path.is_symlink():
            _validate_task_backup(backup_path, version, fingerprint)
            return backup_path
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{TASK_DB.name}.schema-{version}-",
            suffix=".backup.tmp",
            dir=TASK_DB.parent,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
            os.chmod(temporary, 0o400)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            _validate_task_backup(temporary, version, fingerprint)
            try:
                os.link(temporary, backup_path)
            except FileExistsError:
                pass
            else:
                temporary.unlink()
            _validate_task_backup(backup_path, version, fingerprint)
            flags = os.O_RDONLY | os.O_DIRECTORY
            directory = os.open(TASK_DB.parent, flags)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return backup_path
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _preflight_task_store() -> str | None:
    if not TASK_DB.exists():
        return None
    if TASK_DB.is_symlink() or not TASK_DB.is_file():
        raise PermissionError(f"Task database must be a regular file: {TASK_DB}")
    if TASK_DB.stat().st_size == 0:
        return None
    with _readonly_sqlite(TASK_DB) as connection:
        _sqlite_integrity(connection, "Task database", quick=True)
        version = _task_schema_version(connection)
        if version not in {"1", "2", "3", "4", "5"}:
            raise RuntimeError(
                "Unsupported task database schema; use a runtime that explicitly supports it"
            )
        if version == "5":
            _validate_task_schema_current(connection)
        else:
            _validate_task_schema_legacy(connection, version)
        return version


def _create_task_schema_v5(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        """
        CREATE TABLE tasks (
            task_id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            unit TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            state TEXT NOT NULL,
            resume_policy TEXT NOT NULL,
            argv_json TEXT NOT NULL,
            argv_sha256 TEXT NOT NULL,
            cwd TEXT NOT NULL,
            runtime_seconds INTEGER NOT NULL,
            cpu_weight INTEGER NOT NULL,
            io_weight INTEGER NOT NULL,
            memory_max_bytes INTEGER,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            launcher_json TEXT NOT NULL,
            last_observation_json TEXT,
            resource_keys_json TEXT NOT NULL DEFAULT '[]',
            lease_owner_id TEXT,
            request_id TEXT,
            origin_ref TEXT,
            external_run_id TEXT,
            execution_envelope_sha256 TEXT,
            acceptance_json TEXT NOT NULL DEFAULT '[]',
            request_sha256 TEXT,
            execution_backend TEXT NOT NULL DEFAULT 'systemd-user',
            systemd_scope TEXT NOT NULL DEFAULT 'user',
            authoritative_unit TEXT,
            chronik_outbox_enabled INTEGER NOT NULL DEFAULT 0,
            chronik_outbox_state_root TEXT,
            chronik_context_json TEXT,
            terminalization_sha256 TEXT,
            terminalized_at_unix INTEGER,
            lifecycle_receipt_sha256 TEXT,
            repository_scope_manifest_json TEXT
        )
        """
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES('schema_version', '5')"
    )


def _migrate_task_schema(connection: sqlite3.Connection, version: str) -> None:
    columns = set(_task_column_shapes(connection))
    additions = (
        ("resource_keys_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("lease_owner_id", "TEXT"),
        ("request_id", "TEXT"),
        ("origin_ref", "TEXT"),
        ("external_run_id", "TEXT"),
        ("execution_envelope_sha256", "TEXT"),
        ("acceptance_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("request_sha256", "TEXT"),
        ("chronik_outbox_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ("chronik_outbox_state_root", "TEXT"),
        ("chronik_context_json", "TEXT"),
        ("execution_backend", "TEXT NOT NULL DEFAULT 'systemd-user'"),
        ("systemd_scope", "TEXT NOT NULL DEFAULT 'user'"),
        ("authoritative_unit", "TEXT"),
        ("terminalization_sha256", "TEXT"),
        ("terminalized_at_unix", "INTEGER"),
        ("lifecycle_receipt_sha256", "TEXT"),
        ("repository_scope_manifest_json", "TEXT"),
    )
    for name, definition in additions:
        if name not in columns:
            connection.execute(f"ALTER TABLE tasks ADD COLUMN {name} {definition}")
    if "execution_backend" in columns:
        connection.execute(
            "UPDATE tasks SET execution_backend='systemd-user' "
            "WHERE execution_backend IS NULL OR execution_backend=''"
        )
    if "systemd_scope" in columns:
        connection.execute(
            "UPDATE tasks SET systemd_scope='user' "
            "WHERE systemd_scope IS NULL OR systemd_scope=''"
        )
    connection.execute(
        "UPDATE tasks SET authoritative_unit=unit "
        "WHERE authoritative_unit IS NULL OR authoritative_unit=''"
    )
    connection.execute(
        "UPDATE metadata SET value='5' WHERE key='schema_version'"
    )


def _connect_existing_task_database() -> sqlite3.Connection:
    if TASK_DB.is_symlink():
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")
    connection = sqlite3.connect(
        TASK_DB.absolute().as_uri() + "?mode=rw",
        uri=True,
        timeout=10,
    )
    if TASK_DB.is_symlink():
        connection.close()
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")
    return connection


def _open_current_task_database() -> sqlite3.Connection:
    connection = _connect_existing_task_database()
    connection.row_factory = sqlite3.Row
    try:
        if _task_schema_version(connection) != "5":
            raise RuntimeError(
                "Task database schema changed while opening; retry with a compatible runtime"
            )
        _validate_task_schema_current(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        if stat.S_IMODE(TASK_DB.stat().st_mode) != 0o600:
            os.chmod(TASK_DB, 0o600)
        return connection
    except Exception:
        connection.close()
        raise


def _database() -> sqlite3.Connection:
    parent = TASK_DB.parent
    if parent.is_symlink():
        raise PermissionError(f"Task state directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if TASK_DB.is_symlink():
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")

    observed = _preflight_task_store()
    if observed == "5":
        return _open_current_task_database()

    with _schema_directory_lock(parent):
        observed = _preflight_task_store()
        if observed == "5":
            return _open_current_task_database()
        connection = (
            sqlite3.connect(TASK_DB, timeout=10)
            if observed is None
            else _connect_existing_task_database()
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            version = _task_schema_version(connection)
            if version not in {None, "1", "2", "3", "4", "5"}:
                raise RuntimeError(
                    "Unsupported task database schema; use a compatible runtime"
                )
            if version is None:
                if _database_tables(connection):
                    raise RuntimeError(
                        "Task database schema metadata is missing from an existing database"
                    )
                _create_task_schema_v5(connection)
            elif version == "5":
                _validate_task_schema_current(connection)
            else:
                _validate_task_schema_legacy(connection, version)
                _sqlite_integrity(connection, "Task database")
                fingerprint = _sqlite_fingerprint(connection)
                _verified_task_migration_backup(version, fingerprint)
                _migrate_task_schema(connection, version)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS tasks_state_created_task_idx "
                "ON tasks(state, created_at_unix DESC, task_id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS tasks_created_task_idx "
                "ON tasks(created_at_unix DESC, task_id DESC)"
            )
            if _task_schema_version(connection) != "5":
                raise RuntimeError("Task database migration did not reach schema 5")
            _validate_task_schema_current(connection)
            _sqlite_integrity(connection, "Migrated task database")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            if stat.S_IMODE(TASK_DB.stat().st_mode) != 0o600:
                os.chmod(TASK_DB, 0o600)
            return connection
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            raise


def _command_requires_recovery(argv: list[str]) -> bool:
    names = [Path(item).name.lower() for item in argv if isinstance(item, str)]
    if not names:
        return False
    direct = {
        "shutdown", "reboot", "poweroff", "halt", "hibernate",
        "sleep-heimserver", "sleep-heim-pc", "sleep-heimberry",
    }
    if any(name in direct for name in names[:2]):
        return True
    joined = " ".join(item.lower() for item in argv)
    power_actions = (
        "systemctl poweroff", "systemctl reboot", "systemctl suspend",
        "systemctl hibernate", "loginctl poweroff", "loginctl reboot",
        "loginctl suspend", "loginctl hibernate",
    )
    return any(action in joined for action in power_actions)


def _require_recovery_gate(argv: list[str]) -> dict[str, Any]:
    if not _command_requires_recovery(argv):
        return {"required": False, "checked_at_unix": None}
    status = recovery.recovery_status()
    if not status["ready_for_user_power_worker"]:
        actions = status.get("required_actions", [])
        detail = "; ".join(actions) if actions else "recovery evidence is incomplete"
        raise PermissionError(f"Power-worker recovery gate is not ready: {detail}")
    return {**status, "required": True}


def _validate_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID.fullmatch(task_id) is None:
        raise ValueError("Invalid task id")
    return task_id


def _validate_unit(unit: str) -> str:
    if UNIT.fullmatch(unit) is None:
        raise ValueError("Invalid task unit")
    return unit


def _validate_execution_backend(value: str) -> str:
    if value not in TASK_EXECUTION_BACKENDS:
        raise ValueError("Invalid task execution backend")
    return value


def _validate_systemd_scope(value: str) -> str:
    if value not in SYSTEMD_SCOPES:
        raise ValueError("Invalid task systemd scope")
    return value


def _execution_backend(record: dict[str, Any]) -> str:
    return _validate_execution_backend(record.get("execution_backend") or "systemd-user")


def _systemd_scope(record: dict[str, Any]) -> str:
    return _validate_systemd_scope(record.get("systemd_scope") or "user")


def _authoritative_unit(record: dict[str, Any]) -> str:
    return _validate_unit(record.get("authoritative_unit") or record["unit"])


def _is_root_systemd_backend(record: dict[str, Any]) -> bool:
    return _execution_backend(record) == "systemd-root-broker"


def _execution_contract(target: dict[str, Any], command: list[str]) -> tuple[str, str]:
    if target["transport"] == "local" and _command_requires_recovery(command):
        return "systemd-root-broker", "system"
    return "systemd-user", "user"


def _task_unit(task_id: str, attempt: int) -> str:
    if attempt < 1:
        raise ValueError("Task attempt must be positive")
    return f"grabowski-task-{task_id}-a{attempt}.service"


BUREAU_RUNTIME_REFRESH_PRELAUNCH_MIN_REMAINING_SECONDS = 600


def _runtime_refresh_prelaunch_lease_binding_request(
    request: dict[str, str],
    intent: dict[str, Any],
    authority_contract: dict[str, Any],
    task_id: str,
    unit: str,
) -> dict[str, Any]:
    bureau_runtime_refresh_executor.task_identity_environment(task_id, unit)
    expected_intent = request.get("expected_intent_sha256")
    if (
        not isinstance(expected_intent, str)
        or bureau_runtime_refresh_executor.SHA256_RE.fullmatch(expected_intent) is None
        or intent.get("intent_sha256") != expected_intent
    ):
        raise ValueError(
            "Bureau runtime-refresh prelaunch intent identity differs from the request"
        )
    observed_intent = bureau_runtime_refresh_executor._bureau_payload_digest(
        intent, "intent_sha256"
    )
    if observed_intent != expected_intent:
        raise ValueError(
            "Bureau runtime-refresh prelaunch intent digest no longer matches its payload"
        )
    lease_task_id = request.get("lease_task_id")
    if not isinstance(lease_task_id, str) or intent.get("approval_task_id") != lease_task_id:
        raise ValueError(
            "Bureau runtime-refresh prelaunch authority task differs from the intent"
        )
    intent_authority = intent.get("authority_task_spec")
    authority_task_id = authority_contract.get("task_id")
    authority_revision = authority_contract.get("revision")
    authority_spec_sha256 = authority_contract.get("spec_sha256")
    if (
        not isinstance(intent_authority, dict)
        or authority_task_id != lease_task_id
        or intent_authority.get("task_id") != lease_task_id
        or isinstance(authority_revision, bool)
        or not isinstance(authority_revision, int)
        or authority_revision < 1
        or intent_authority.get("revision") != authority_revision
        or not isinstance(authority_spec_sha256, str)
        or bureau_runtime_refresh_executor.SHA256_RE.fullmatch(authority_spec_sha256) is None
        or intent_authority.get("spec_sha256") != authority_spec_sha256
        or intent_authority.get("state") not in {"ready", "active"}
    ):
        raise ValueError(
            "Bureau runtime-refresh prelaunch authority binding is invalid"
        )
    target_sha256 = intent.get("target_sha256")
    runtime_approval = intent.get("runtime_approval")
    approval_evidence = (
        runtime_approval.get("evidence") if isinstance(runtime_approval, dict) else None
    )
    approval_scope = (
        approval_evidence.get("scope") if isinstance(approval_evidence, dict) else None
    )
    if (
        not isinstance(target_sha256, str)
        or bureau_runtime_refresh_executor.SHA256_RE.fullmatch(target_sha256) is None
        or not isinstance(runtime_approval, dict)
        or runtime_approval.get("schema_version") != 1
        or runtime_approval.get("action_class") != "runtime_mutation"
        or runtime_approval.get("allowed") is not True
        or runtime_approval.get("required") is not True
        or runtime_approval.get("required_level") != "break_glass"
        or runtime_approval.get("expected_task_id") != lease_task_id
        or runtime_approval.get("expected_reference") != target_sha256
        or not isinstance(approval_evidence, dict)
        or approval_evidence.get("schema_version") != 1
        or approval_evidence.get("approved") is not True
        or approval_evidence.get("level") != "break_glass"
        or approval_evidence.get("task_id") != lease_task_id
        or approval_evidence.get("reference") != target_sha256
        or not isinstance(approval_scope, list)
        or "runtime_mutation" not in approval_scope
    ):
        raise ValueError(
            "Bureau runtime-refresh prelaunch approval binding is invalid"
        )
    lease_owner = request.get("lease_owner")
    expected_lease_owner = f"runtime-refresh:{expected_intent[:16]}"
    if (
        not isinstance(lease_owner, str)
        or bureau_runtime_refresh_executor.OWNER_RE.fullmatch(lease_owner) is None
        or lease_owner != expected_lease_owner
    ):
        raise ValueError(
            "Bureau runtime-refresh prelaunch lease owner is not intent-bound"
        )
    raw_keys = intent.get("required_resource_keys")
    if (
        not isinstance(raw_keys, list)
        or not raw_keys
        or not all(isinstance(item, str) for item in raw_keys)
    ):
        raise ValueError("Bureau runtime-refresh prelaunch resource keys are invalid")
    try:
        canonical_keys = resources.normalize_resource_keys(raw_keys)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Bureau runtime-refresh prelaunch resource keys are invalid"
        ) from exc
    if raw_keys != canonical_keys:
        raise ValueError(
            "Bureau runtime-refresh prelaunch resource keys are not canonical"
        )
    if any(
        key.split(":", 1)[0] not in {"path", "service"}
        for key in canonical_keys
    ):
        raise ValueError(
            "Bureau runtime-refresh prelaunch contains an unsupported resource kind"
        )
    material: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_bureau_runtime_refresh_prelaunch_lease_binding_request",
        "intent_sha256": expected_intent,
        "target_sha256": target_sha256,
        "lease_owner": lease_owner,
        "lease_task_id": lease_task_id,
        "authority_revision": authority_revision,
        "authority_spec_sha256": authority_spec_sha256,
        "task_id": task_id,
        "executor_unit": unit,
        "resource_keys": canonical_keys,
        "minimum_remaining_seconds": (
            BUREAU_RUNTIME_REFRESH_PRELAUNCH_MIN_REMAINING_SECONDS
        ),
    }
    return {**material, "request_sha256": _sha256_json(material)}


BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX = (
    "runtime_refresh_executor_prelaunch_v1:"
)


def _runtime_refresh_prelaunch_journal_key(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID.fullmatch(task_id) is None:
        raise ValueError("runtime-refresh prelaunch journal task id is invalid")
    return BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + task_id


def _runtime_refresh_prelaunch_binding_journal(
    request: dict[str, Any],
    *,
    argv_sha256: str,
    binding_plan: dict[str, Any],
) -> dict[str, Any]:
    task_id = request.get("task_id")
    unit = request.get("executor_unit")
    bureau_runtime_refresh_executor.task_identity_environment(task_id, unit)
    if not isinstance(argv_sha256, str) or SHA256.fullmatch(argv_sha256) is None:
        raise ValueError("runtime-refresh prelaunch journal argv digest is invalid")
    plan = resources._normalize_runtime_refresh_executor_binding_plan(binding_plan)
    if (
        plan["owner_id"] != request.get("lease_owner")
        or plan["executor_unit"] != unit
        or plan["resource_keys"] != request.get("resource_keys")
        or plan["minimum_remaining_seconds"]
        != request.get("minimum_remaining_seconds")
    ):
        raise ValueError("runtime-refresh prelaunch journal plan differs from request")
    intent_sha256 = request.get("intent_sha256")
    request_sha256 = request.get("request_sha256")
    for label, value in (
        ("intent", intent_sha256),
        ("request", request_sha256),
    ):
        if not isinstance(value, str) or SHA256.fullmatch(value) is None:
            raise ValueError(f"runtime-refresh prelaunch journal {label} digest is invalid")
    material: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_bureau_runtime_refresh_prelaunch_binding_journal",
        "task_id": task_id,
        "executor_unit": unit,
        "argv_sha256": argv_sha256,
        "intent_sha256": intent_sha256,
        "request_sha256": request_sha256,
        "lease_owner": plan["owner_id"],
        "resource_keys": plan["resource_keys"],
        "binding_plan": plan,
    }
    return {**material, "journal_sha256": _sha256_json(material)}


def _normalize_runtime_refresh_prelaunch_binding_journal(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("runtime-refresh prelaunch journal is not an object")
    expected_fields = {
        "schema_version",
        "kind",
        "task_id",
        "executor_unit",
        "argv_sha256",
        "intent_sha256",
        "request_sha256",
        "lease_owner",
        "resource_keys",
        "binding_plan",
        "journal_sha256",
    }
    if set(value) != expected_fields:
        raise RuntimeError("runtime-refresh prelaunch journal shape is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("kind")
        != "grabowski_bureau_runtime_refresh_prelaunch_binding_journal"
    ):
        raise RuntimeError("runtime-refresh prelaunch journal contract is unsupported")
    observed_digest = value.get("journal_sha256")
    material = {key: item for key, item in value.items() if key != "journal_sha256"}
    if (
        not isinstance(observed_digest, str)
        or SHA256.fullmatch(observed_digest) is None
        or observed_digest != _sha256_json(material)
    ):
        raise RuntimeError("runtime-refresh prelaunch journal digest is invalid")
    task_id = value.get("task_id")
    unit = value.get("executor_unit")
    try:
        bureau_runtime_refresh_executor.task_identity_environment(task_id, unit)
    except bureau_runtime_refresh_executor.BureauRuntimeRefreshExecutorError as exc:
        raise RuntimeError("runtime-refresh prelaunch journal task identity is invalid") from exc
    for field in ("argv_sha256", "intent_sha256", "request_sha256"):
        item = value.get(field)
        if not isinstance(item, str) or SHA256.fullmatch(item) is None:
            raise RuntimeError(f"runtime-refresh prelaunch journal {field} is invalid")
    lease_owner = value.get("lease_owner")
    if (
        not isinstance(lease_owner, str)
        or bureau_runtime_refresh_executor.OWNER_RE.fullmatch(lease_owner) is None
    ):
        raise RuntimeError("runtime-refresh prelaunch journal lease owner is invalid")
    raw_keys = value.get("resource_keys")
    if not isinstance(raw_keys, list) or any(not isinstance(item, str) for item in raw_keys):
        raise RuntimeError("runtime-refresh prelaunch journal resource keys are invalid")
    try:
        keys = resources.normalize_resource_keys(raw_keys)
        plan = resources._normalize_runtime_refresh_executor_binding_plan(
            value.get("binding_plan")
        )
    except (PermissionError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError("runtime-refresh prelaunch journal binding plan is invalid") from exc
    if raw_keys != keys:
        raise RuntimeError("runtime-refresh prelaunch journal resource keys are not canonical")
    if (
        plan["owner_id"] != lease_owner
        or plan["executor_unit"] != unit
        or plan["resource_keys"] != keys
    ):
        raise RuntimeError("runtime-refresh prelaunch journal binding plan drifted")
    return {**value, "resource_keys": keys, "binding_plan": plan}


def _persist_runtime_refresh_prelaunch_binding_journal(
    journal: dict[str, Any],
) -> dict[str, Any]:
    normalized = _normalize_runtime_refresh_prelaunch_binding_journal(journal)
    key = _runtime_refresh_prelaunch_journal_key(normalized["task_id"])
    payload = _canonical_json(normalized)
    with _database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?)", (key, payload)
            )
        elif row["value"] != payload:
            raise RuntimeError("runtime-refresh prelaunch journal key collision")
        connection.commit()
    return {
        "key": key,
        "journal_sha256": normalized["journal_sha256"],
        "persisted": True,
    }


def _delete_runtime_refresh_prelaunch_binding_journal(
    connection: sqlite3.Connection,
    journal: dict[str, Any],
) -> None:
    normalized = _normalize_runtime_refresh_prelaunch_binding_journal(journal)
    key = _runtime_refresh_prelaunch_journal_key(normalized["task_id"])
    payload = _canonical_json(normalized)
    deleted = connection.execute(
        "DELETE FROM metadata WHERE key=? AND value=?", (key, payload)
    )
    if deleted.rowcount != 1:
        raise RuntimeError("runtime-refresh prelaunch journal changed before deletion")


def _reconcile_runtime_refresh_prelaunch_binding_journals(
    resource_keys: list[str],
) -> dict[str, Any]:
    keys = resources.normalize_resource_keys(resource_keys)
    selected = set(keys)
    recovered: list[dict[str, Any]] = []
    retained: list[str] = []
    connection = _database()
    try:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            "SELECT key, value FROM metadata WHERE key LIKE ? ORDER BY key",
            (BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
        ).fetchall()
        for row in rows:
            try:
                journal = _normalize_runtime_refresh_prelaunch_binding_journal(
                    json.loads(row["value"])
                )
            except (json.JSONDecodeError, TypeError, RuntimeError, ValueError) as exc:
                raise RuntimeError(
                    "runtime-refresh prelaunch recovery journal is malformed"
                ) from exc
            if not selected.intersection(journal["resource_keys"]):
                continue
            task_row = connection.execute(
                "SELECT task_id, unit, argv_sha256 FROM tasks WHERE task_id=?",
                (journal["task_id"],),
            ).fetchone()
            if task_row is not None:
                if (
                    task_row["task_id"] != journal["task_id"]
                    or task_row["unit"] != journal["executor_unit"]
                    or task_row["argv_sha256"] != journal["argv_sha256"]
                ):
                    raise RuntimeError(
                        "runtime-refresh prelaunch recovery task identity mismatched"
                    )
                _delete_runtime_refresh_prelaunch_binding_journal(
                    connection, journal
                )
                retained.append(journal["task_id"])
                continue
            recovery = resources.restore_runtime_refresh_executor_lease_binding_plan(
                journal["binding_plan"]
            )
            _delete_runtime_refresh_prelaunch_binding_journal(connection, journal)
            recovered.append(
                {
                    "task_id": journal["task_id"],
                    "journal_sha256": journal["journal_sha256"],
                    "plan_sha256": journal["binding_plan"]["plan_sha256"],
                    "action": recovery["action"],
                }
            )
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()
    material = {
        "schema_version": 1,
        "kind": "grabowski_bureau_runtime_refresh_prelaunch_recovery",
        "resource_keys": keys,
        "recovered": recovered,
        "retained_task_ids": retained,
    }
    return {**material, "recovery_sha256": _sha256_json(material)}


def _validate_cwd(host: str, raw: str | None) -> str:
    candidate = str(operator.HOME) if raw is None else raw
    if not isinstance(candidate, str) or not candidate.startswith("/"):
        raise ValueError("Task cwd must be an absolute path")
    if len(candidate.encode("utf-8")) > 4096 or "\x00" in candidate:
        raise ValueError("Task cwd is too large or contains NUL")
    target = fleet.fleet_host(host)
    if target["transport"] == "local":
        return str(operator._resolve_cwd(candidate))
    return candidate


def _normalized_github_repository_slug(remote_url: str) -> str | None:
    value = remote_url.strip()
    prefixes = (
        "git@github.com:",
        "ssh://git@github.com/",
        "https://github.com/",
        "http://github.com/",
    )
    for prefix in prefixes:
        if value.startswith(prefix):
            slug = value[len(prefix):].rstrip("/")
            if slug.endswith(".git"):
                slug = slug[:-4]
            return slug or None
    return None


def _is_local_grabowski_checkout(cwd: str) -> bool:
    result = operator._run(
        ["git", "-C", cwd, "config", "--get", "remote.origin.url"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
    )
    if result.get("returncode") != 0:
        return False
    return (
        _normalized_github_repository_slug(str(result.get("stdout", "")))
        == GRABOWSKI_REPOSITORY_SLUG
    )


def _unqualified_python_index(command: list[str]) -> int | None:
    if command[0] in {"python", "python3"}:
        return 0
    if command[0] not in {"env", "/bin/env", "/usr/bin/env"}:
        return None
    for index, item in enumerate(command[1:], start=1):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item):
            continue
        return index if item in {"python", "python3"} else None
    return None


def _bind_grabowski_runtime_python(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    enabled: bool,
) -> list[str]:
    if not isinstance(enabled, bool):
        raise ValueError("runtime_python must be boolean")
    if not enabled:
        return command
    python_index = _unqualified_python_index(command)
    if python_index is None or target["transport"] != "local":
        return command
    if not _is_local_grabowski_checkout(cwd):
        return command
    if not GRABOWSKI_RUNTIME_PYTHON.is_file() or not os.access(
        GRABOWSKI_RUNTIME_PYTHON, os.X_OK
    ):
        raise RuntimeError("Grabowski runtime Python is unavailable")
    bound = list(command)
    bound[python_index] = str(GRABOWSKI_RUNTIME_PYTHON)
    return bound


def _explicit_cargo_target_dir(command: list[str]) -> bool:
    # Conservative by design: shell snippets can override an inherited target.
    return any("CARGO_TARGET_DIR=" in item for item in command)


def _direct_cargo_target_dir_values(command: list[str]) -> list[str]:
    if not command or Path(command[0]).name != "env":
        return []
    values: list[str] = []
    for item in command[1:]:
        if item == "--" or (item.startswith("-") and "=" not in item):
            continue
        if "=" not in item:
            break
        if item.startswith("CARGO_TARGET_DIR="):
            values.append(item.removeprefix("CARGO_TARGET_DIR="))
    return values


def _ambiguous_managed_cargo_target_override(command: list[str]) -> bool:
    occurrences = sum("CARGO_TARGET_DIR=" in item for item in command)
    if occurrences == 0:
        return False
    values = _direct_cargo_target_dir_values(command)
    if occurrences != 1 or len(values) != 1:
        return True
    path = Path(values[0])
    if not path.is_absolute() or ".." in path.parts:
        return True
    try:
        relative = path.relative_to(MANAGED_CARGO_CACHE_ROOT)
    except ValueError:
        return False
    return not (
        len(relative.parts) == 2
        and relative.parts[1] == "target"
        and SHA256.fullmatch(relative.parts[0]) is not None
    )

def _explicit_managed_cargo_target_dir(command: list[str]) -> str | None:
    values = sorted(set(_direct_cargo_target_dir_values(command)))
    if len(values) != 1:
        return None
    path = Path(values[0])
    if not path.is_absolute() or ".." in path.parts:
        return None
    try:
        relative = path.relative_to(MANAGED_CARGO_CACHE_ROOT)
    except ValueError:
        return None
    if (
        len(relative.parts) != 2
        or relative.parts[1] != "target"
        or SHA256.fullmatch(relative.parts[0]) is None
    ):
        return None
    return str(path)


def _git_repository_discovery_environment() -> dict[str, str]:
    environment = operator._safe_environment()
    return {
        key: value
        for key, value in environment.items()
        if not key.upper().startswith("GIT_")
    }


def _local_git_root(
    cwd: str,
    *,
    environment: dict[str, str] | None = None,
) -> Path | None:
    result = operator._run(
        ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
        environment=environment,
    )
    if result.get("returncode") != 0 or result.get("timed_out") is True:
        return None
    value = str(result.get("stdout", "")).strip()
    if not value or not value.startswith("/") or "\x00" in value:
        return None
    root = Path(value)
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _regular_cargo_lock(root: Path) -> bool:
    path = root / "Cargo.lock"
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _bounded_regular_text(candidate: Path, root: Path) -> str | None:
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        info = resolved.lstat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return None
    if info.st_size > MAX_BUILD_SCRIPT_INSPECTION_BYTES:
        return None
    try:
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _wrapper_definition_mentions_cargo(executable: str, root: Path) -> bool:
    names = (
        ("Justfile", "justfile", ".justfile")
        if executable == "just"
        else ("GNUmakefile", "makefile", "Makefile")
    )
    for name in names:
        text = _bounded_regular_text(root / name, root)
        if text is not None and CARGO_TOKEN.search(text) is not None:
            return True
    return False


def _text_may_invoke_cargo(text: str, root: Path) -> bool:
    if CARGO_TOKEN.search(text) is not None:
        return True
    if JUST_TOKEN.search(text) is not None and _wrapper_definition_mentions_cargo("just", root):
        return True
    if MAKE_TOKEN.search(text) is not None and _wrapper_definition_mentions_cargo("make", root):
        return True
    return False


def _bounded_script_mentions_cargo(candidate: Path, root: Path) -> bool:
    text = _bounded_regular_text(candidate, root)
    return text is not None and _text_may_invoke_cargo(text, root)

def _command_may_invoke_cargo(command: list[str], *, cwd: str, root: Path) -> bool:
    executable = Path(command[0]).name
    if executable == "cargo":
        return True
    if executable in {"just", "make"}:
        return _wrapper_definition_mentions_cargo(executable, root)
    if executable in {"env", "command"}:
        for index, item in enumerate(command[1:], start=1):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item):
                continue
            return _command_may_invoke_cargo(command[index:], cwd=cwd, root=root)
        return False
    if executable in SCRIPT_EXECUTABLES:
        if _text_may_invoke_cargo(" ".join(command[1:]), root):
            return True
        for item in command[1:]:
            if item.startswith("-"):
                continue
            candidate = Path(item)
            if not candidate.is_absolute():
                candidate = Path(cwd) / candidate
            if _bounded_script_mentions_cargo(candidate, root):
                return True
        return False
    executable_path = Path(command[0])
    if "/" in command[0]:
        if not executable_path.is_absolute():
            executable_path = Path(cwd) / executable_path
        return _bounded_script_mentions_cargo(executable_path, root)
    return False


def _managed_cargo_profile(command: list[str]) -> str:
    current = command
    if Path(current[0]).name in {"env", "command"}:
        for index, item in enumerate(current[1:], start=1):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item):
                continue
            return _managed_cargo_profile(current[index:])
        return MANAGED_CARGO_PROFILE
    if Path(current[0]).name != "cargo":
        return MANAGED_CARGO_PROFILE
    args = current[1:]
    if "--profile" in args:
        index = args.index("--profile")
        if index + 1 < len(args):
            value = args[index + 1]
            if value.replace("-", "").replace("_", "").isalnum():
                return value
    if "--release" in args:
        return "release"
    for candidate in ("test", "bench", "check", "doc"):
        if candidate in args:
            return candidate
    return "dev"


def _managed_cargo_request_root(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    execution_backend: str,
) -> Path | None:
    if target["transport"] != "local" or execution_backend != "systemd-user":
        return None
    if _explicit_cargo_target_dir(command):
        return None
    root = _local_git_root(cwd)
    if root is None or not _regular_cargo_lock(root):
        return None
    if not _command_may_invoke_cargo(command, cwd=cwd, root=root):
        return None
    return root


def _resolve_managed_cargo_target_dir(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    execution_backend: str,
) -> str | None:
    root = _managed_cargo_request_root(
        command,
        target=target,
        cwd=cwd,
        execution_backend=execution_backend,
    )
    if root is None:
        return None
    try:
        resolver_info = MANAGED_BUILD_RESOLVER.lstat()
        python_resolved = MANAGED_BUILD_PYTHON.resolve(strict=True)
        python_info = python_resolved.stat()
    except OSError as exc:
        raise RuntimeError("Managed-build resolver runtime is unavailable") from exc
    if (
        stat.S_ISLNK(resolver_info.st_mode)
        or not stat.S_ISREG(resolver_info.st_mode)
        or not stat.S_ISREG(python_info.st_mode)
        or python_resolved.parent != Path("/usr/bin")
    ):
        raise RuntimeError("Managed-build resolver runtime is unsafe")
    profile = _managed_cargo_profile(command)
    result = operator._run(
        [
            str(MANAGED_BUILD_PYTHON),
            str(MANAGED_BUILD_RESOLVER),
            "prepare-environment",
            "--repo",
            str(root),
            "--tool",
            "cargo",
            "--profile",
            profile,
            "--executable",
            "cargo",
        ],
        cwd=operator.HOME,
        timeout_seconds=10,
        max_output_bytes=16 * 1024,
    )
    if result.get("returncode") != 0:
        raise RuntimeError("Managed-build resolver failed for Cargo task")
    try:
        payload = json.loads(str(result.get("stdout", "")))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Managed-build resolver returned invalid JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or payload.get("kind") != "heim_pc.managed_build_environment_prepared"
        or payload.get("tool") != "cargo"
        or payload.get("profile") != profile
        or payload.get("repository_root") != str(root)
    ):
        raise RuntimeError("Managed-build resolver returned an incompatible contract")
    environment = payload.get("environment")
    if not isinstance(environment, dict) or set(environment) != {"CARGO_TARGET_DIR"}:
        raise RuntimeError("Managed-build resolver returned an invalid Cargo environment")
    raw_target = environment.get("CARGO_TARGET_DIR")
    raw_cache = payload.get("cache_path")
    raw_lifecycle_lock = payload.get("lifecycle_lock_path")
    prepared_paths = payload.get("prepared_paths")
    if (
        not isinstance(raw_target, str)
        or not raw_target.startswith("/")
        or "\x00" in raw_target
        or not isinstance(raw_cache, str)
        or not raw_cache.startswith("/")
        or "\x00" in raw_cache
        or not isinstance(raw_lifecycle_lock, str)
        or not raw_lifecycle_lock.startswith("/")
        or "\x00" in raw_lifecycle_lock
        or not isinstance(prepared_paths, list)
        or any(not isinstance(item, str) for item in prepared_paths)
    ):
        raise RuntimeError("Managed-build resolver returned an invalid Cargo target path")
    target_dir = Path(raw_target)
    cache_path = Path(raw_cache)
    try:
        relative_cache = cache_path.relative_to(MANAGED_CARGO_CACHE_ROOT)
    except ValueError as exc:
        raise RuntimeError("Managed-build resolver Cargo cache escapes the managed cache") from exc
    if len(relative_cache.parts) != 1 or target_dir != cache_path / "target":
        raise RuntimeError("Managed-build resolver returned an invalid Cargo cache binding")
    expected_lock = MANAGED_CARGO_LOCK_ROOT / f"{relative_cache.parts[0]}.lock"
    if raw_lifecycle_lock != str(expected_lock):
        raise RuntimeError("Managed-build resolver returned an invalid Cargo lifecycle lock binding")
    if (
        str(cache_path) not in prepared_paths
        or str(target_dir) not in prepared_paths
        or str(expected_lock.parent) not in prepared_paths
    ):
        raise RuntimeError("Managed-build resolver did not prepare the Cargo cache binding")
    if target_dir == root or root in target_dir.parents:
        raise RuntimeError("Managed-build resolver Cargo target points into the worktree")
    return str(target_dir)


def _managed_cargo_lifecycle_lock_path(cargo_target_dir: str) -> Path:
    target_dir = Path(cargo_target_dir)
    cache_path = target_dir.parent
    try:
        relative = cache_path.relative_to(MANAGED_CARGO_CACHE_ROOT)
    except ValueError as exc:
        raise RuntimeError("managed Cargo target escapes the managed cache") from exc
    if len(relative.parts) != 1 or target_dir != cache_path / "target":
        raise RuntimeError("managed Cargo target has an invalid lifecycle lock binding")
    cache_key = relative.parts[0]
    if SHA256.fullmatch(cache_key) is None:
        raise RuntimeError("managed Cargo cache key is invalid for lifecycle lock")
    return MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"


def _managed_cargo_lifecycle_lock(cargo_target_dir: str) -> Path:
    lifecycle_lock = _managed_cargo_lifecycle_lock_path(cargo_target_dir)
    try:
        MANAGED_CARGO_LOCK_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved_lock_root = MANAGED_CARGO_LOCK_ROOT.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("managed Cargo lifecycle lock root is unavailable") from exc
    if (
        resolved_lock_root != MANAGED_CARGO_LOCK_ROOT
        or MANAGED_CARGO_LOCK_ROOT.is_symlink()
        or not MANAGED_CARGO_LOCK_ROOT.is_dir()
    ):
        raise RuntimeError("managed Cargo lifecycle lock root is unsafe")
    if not Path(FLOCK_EXECUTABLE).is_file() or not os.access(FLOCK_EXECUTABLE, os.X_OK):
        raise RuntimeError("managed Cargo lifecycle lock executable is unavailable")
    return lifecycle_lock


def _bind_managed_cargo_environment(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    execution_backend: str,
) -> list[str]:
    local_systemd = target["transport"] == "local" and execution_backend == "systemd-user"
    explicit_managed_target = (
        _explicit_managed_cargo_target_dir(command) if local_systemd else None
    )
    if (
        local_systemd
        and explicit_managed_target is None
        and _ambiguous_managed_cargo_target_override(command)
    ):
        raise RuntimeError(
            "ambiguous managed Cargo target override cannot be lifecycle-fenced"
        )
    if explicit_managed_target is not None:
        lifecycle_lock = _managed_cargo_lifecycle_lock(explicit_managed_target)
        return [
            FLOCK_EXECUTABLE,
            "--shared",
            str(lifecycle_lock),
            *command,
        ]
    cargo_target_dir = _resolve_managed_cargo_target_dir(
        command,
        target=target,
        cwd=cwd,
        execution_backend=execution_backend,
    )
    if cargo_target_dir is None:
        return command
    lifecycle_lock = _managed_cargo_lifecycle_lock(cargo_target_dir)
    return [
        FLOCK_EXECUTABLE,
        "--shared",
        str(lifecycle_lock),
        SYSTEMD_ENV_EXECUTABLE,
        f"CARGO_TARGET_DIR={cargo_target_dir}",
        *command,
    ]


def _validate_weights(cpu_weight: int, io_weight: int) -> tuple[int, int]:
    if not isinstance(cpu_weight, int) or not 1 <= cpu_weight <= 10_000:
        raise ValueError("cpu_weight must be between 1 and 10000")
    if not isinstance(io_weight, int) or not 1 <= io_weight <= 10_000:
        raise ValueError("io_weight must be between 1 and 10000")
    return cpu_weight, io_weight


def _validate_memory(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 16 * 1024 * 1024:
        raise ValueError("memory_max_bytes must be at least 16 MiB")
    return value


def _validate_chronik_outbox(
    enabled: bool,
    state_root: str | None,
) -> tuple[int, str | None]:
    if not isinstance(enabled, bool):
        raise ValueError("chronik_outbox must be boolean")
    if state_root in {None, ""}:
        return (1 if enabled else 0), None
    if not enabled:
        raise ValueError("chronik_outbox_state_root requires chronik_outbox")
    if not isinstance(state_root, str) or not state_root.startswith("/"):
        raise ValueError("chronik_outbox_state_root must be an absolute path")
    if len(state_root.encode("utf-8")) > 4096 or "\x00" in state_root:
        raise ValueError("chronik_outbox_state_root is too large or contains NUL")
    return 1, state_root


def _validate_chronik_operation(value: str, *, enabled: bool) -> str:
    if not isinstance(value, str) or value not in CHRONIK_OPERATION_TASK_CLASS:
        raise ValueError(
            f"chronik_operation must be one of {sorted(CHRONIK_OPERATION_TASK_CLASS)}"
        )
    if value != "other" and not enabled:
        raise ValueError("chronik_operation requires chronik_outbox")
    return value


def _validate_chronik_context_metadata(
    component: str,
    bureau_task_id: str,
    pr_number: int | None,
    *,
    enabled: bool,
) -> tuple[str, str, int | None]:
    values = {
        "chronik_component": (component, 160),
        "chronik_bureau_task_id": (bureau_task_id, 160),
    }
    normalized: dict[str, str] = {}
    for label, (value, maximum) in values.items():
        if not isinstance(value, str):
            raise ValueError(f"{label} must be text")
        candidate = value.strip()
        if len(candidate) > maximum or any(ord(character) < 32 for character in candidate):
            raise ValueError(f"{label} is invalid")
        normalized[label] = candidate
    if pr_number is not None and (
        isinstance(pr_number, bool)
        or not isinstance(pr_number, int)
        or not 1 <= pr_number <= 2_147_483_647
    ):
        raise ValueError("chronik_pr_number must be a positive bounded integer")
    if not enabled and (
        normalized["chronik_component"]
        or normalized["chronik_bureau_task_id"]
        or pr_number is not None
    ):
        raise ValueError("Chronik context metadata requires chronik_outbox")
    return (
        normalized["chronik_component"],
        normalized["chronik_bureau_task_id"],
        pr_number,
    )



def _validate_resume_policy(value: str) -> ResumePolicy:
    if value not in RESUME_POLICIES:
        raise ValueError(f"resume_policy must be one of {sorted(RESUME_POLICIES)}")
    return cast(ResumePolicy, value)


def _resource_keys(values: list[str] | None) -> list[str]:
    if values is None or values == []:
        return []
    return resources.normalize_resource_keys(values)


def _argument_value(argv: list[str], *names: str) -> str | None:
    for index, item in enumerate(argv):
        if item in names:
            if index + 1 >= len(argv):
                return None
            return argv[index + 1]
        for name in names:
            prefix = f"{name}="
            if item.startswith(prefix):
                return item[len(prefix):]
    return None


def _git_marker_conclusively_invalid(marker: Path) -> bool:
    try:
        if marker.is_symlink():
            return False
        if marker.is_file():
            return marker.stat().st_size == 0
        if marker.is_dir():
            return next(marker.iterdir(), None) is None
    except OSError:
        return False
    return False


def _local_workspace_path(raw: str | None, *, cwd: str) -> str:
    candidate = Path(cwd) if raw in {None, ""} else Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    resolved = Path(operator._resolve_cwd(str(candidate)))
    for current in (resolved, *resolved.parents):
        marker = current / ".git"
        if marker.is_symlink() or not (marker.is_file() or marker.is_dir()):
            continue
        if current == resolved:
            # A direct marker is itself enough to keep the workspace fail-closed,
            # even when the repository metadata is currently damaged.
            return str(resolved)
        if _git_marker_conclusively_invalid(marker):
            # Empty marker stubs cannot describe a Git repository and may be
            # unrelated temporary state.  Continue looking for a real ancestor.
            continue
        git_root = _local_git_root(
            str(current),
            environment=_git_repository_discovery_environment(),
        )
        if git_root is None or git_root != current:
            raise RuntimeError(
                f"unable to validate ancestor Git workspace root: {current}"
            )
        return str(current)
    return str(resolved)


def _workspace_has_git_marker(workspace: str) -> bool:
    marker = Path(workspace) / ".git"
    return not marker.is_symlink() and (marker.is_file() or marker.is_dir())


def _mutating_agent_workspace(
    host: str,
    argv: list[str],
    *,
    cwd: str,
) -> str | None:
    if fleet.fleet_host(host)["transport"] != "local":
        return None
    executable = Path(argv[0]).name.lower()
    if executable == "codex":
        sandbox = _argument_value(argv, "--sandbox", "-s")
        if sandbox in READ_ONLY_AGENT_MODES:
            return None
        return _local_workspace_path(_argument_value(argv, "-C", "--cd"), cwd=cwd)
    if executable in MUTATING_AGENT_EXECUTABLES - {"codex"}:
        permission_mode = _argument_value(argv, "--permission-mode")
        if permission_mode in READ_ONLY_AGENT_MODES:
            return None
        return _local_workspace_path(None, cwd=cwd)
    # Framework-managed writers already hold a workspace-level lease owned by
    # their workspace lifecycle. Inferring a second task-owned lease here would
    # make the formal workspace deadlock against itself.
    return None


def _reposkop_task_purpose(
    *,
    task_id: str,
    argv_sha256: str,
    executable: str,
) -> str:
    readable = re.sub(
        r"[^a-z0-9._-]+",
        "-",
        Path(executable).name.strip().lower(),
    ).strip("-._") or "agent"
    binding = _sha256_json(
        {
            "policy_version": REPOSKOP_EXECUTION_ATTESTATION_POLICY_VERSION,
            "task_id": task_id,
            "argv_sha256": argv_sha256,
            "executable": executable,
        }
    )
    return f"grabowski-task-start:{readable[:32]}:{binding[:8]}"


def _default_reposkop_execution_context(
    workspace: str,
    purpose: str,
) -> dict[str, Any]:
    import grabowski_reposkop_context

    return grabowski_reposkop_context.grabowski_reposkop_context(
        workspace,
        purpose,
    )


def _capture_reposkop_shadow_before_best_effort(
    *,
    task_id: str,
    workspace: str,
    evaluation_id: str | None,
    reposkop_cohort: str | None,
) -> dict[str, Any] | None:
    try:
        import grabowski_reposkop_shadow

        return grabowski_reposkop_shadow.capture_before_best_effort(
            task_id=task_id,
            workspace=workspace,
            evaluation_id=evaluation_id,
            reposkop_cohort=reposkop_cohort,
        )
    except Exception:
        return {
            "phase": "before",
            "status": "unavailable",
            "task_id": task_id,
            "evaluation_id": evaluation_id,
            "reposkop_cohort": reposkop_cohort,
            "measurement_class": "inconclusive/unavailable",
            "failure_category": "shadow_adapter_error",
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": None,
        }


def _prepare_reposkop_shadow_terminal_best_effort(
    *,
    task_id: str,
    before_summary: dict[str, Any],
) -> dict[str, Any]:
    try:
        import grabowski_reposkop_shadow

        return grabowski_reposkop_shadow.prepare_terminal_best_effort(
            task_id=task_id,
            before_summary=before_summary,
        )
    except Exception:
        material = {
            "schema_version": 1,
            "kind": "grabowski.reposkop_checkout_shadow_evidence",
            "phase": "terminal_prepare",
            "status": "unavailable",
            "task_id": task_id,
            "evaluation_id": before_summary.get("evaluation_id"),
            "reposkop_cohort": before_summary.get("reposkop_cohort"),
            "captured_at_unix": _now(),
            "before_evidence_sha256": before_summary.get("evidence_sha256"),
            "before_observation_sha256": before_summary.get(
                "before_observation_sha256"
            ),
            "failure_category": "shadow_adapter_error",
            "continuity_state": "inconclusive",
            "measurement_class": "inconclusive/unavailable",
            "reason_codes": ["shadow.shadow_adapter_error"],
            "anomaly_codes": [],
            "decision_effect": False,
            "effect_authorized": False,
        }
        return {**material, "evidence_sha256": _sha256_json(material)}


def _finalize_reposkop_shadow_terminal_best_effort(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
    prepared: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        import grabowski_reposkop_shadow

        return grabowski_reposkop_shadow.finalize_terminal_best_effort(
            task_id=task_id,
            terminalization_sha256=terminalization_sha256,
            lifecycle_receipt_sha256=lifecycle_receipt_sha256,
            prepared=prepared,
        )
    except Exception:
        return None


def _workspace_lease_resource_keys(
    workspace: str,
    resource_keys: list[str],
) -> list[str]:
    exact_repository = resources.normalize_resource_key(f"repo:{workspace}")
    covering: set[str] = set()
    for value in resource_keys:
        key = resources.normalize_resource_key(value)
        if key == exact_repository:
            covering.add(key)
            continue
        if not key.startswith("path:"):
            continue
        path = key.removeprefix("path:")
        try:
            if os.path.commonpath([path, workspace]) == path:
                covering.add(key)
        except ValueError:
            continue
    return sorted(covering)


def _attest_mutating_agent_workspace(
    *,
    workspace: str,
    task_id: str,
    lease_owner_id: str,
    workspace_lease_resource_keys: list[str],
    argv: list[str],
    argv_sha256: str,
    execution_identity_sha256: str,
    reposkop_context_loader: Any | None = None,
) -> dict[str, Any]:
    import grabowski_work_admission as work_admission

    normalized_workspace_leases = sorted(
        {
            resources.normalize_resource_key(value)
            for value in workspace_lease_resource_keys
        }
    )
    covering_workspace_leases = _workspace_lease_resource_keys(
        workspace, normalized_workspace_leases
    )
    if (
        not covering_workspace_leases
        or covering_workspace_leases != normalized_workspace_leases
    ):
        raise ValueError(
            "Reposkop execution attestation requires only workspace-covering "
            "lease resources"
        )

    purpose = _reposkop_task_purpose(
        task_id=task_id,
        argv_sha256=argv_sha256,
        executable=argv[0],
    )
    result = (
        reposkop_context_loader or _default_reposkop_execution_context
    )(workspace, purpose)
    evidence = work_admission._reposkop_context_evidence(
        result,
        repository=workspace,
        purpose=purpose,
    )
    summary = reposkop_effectiveness.finding_summary(result.get("report"))
    material = {
        "schema_version": 1,
        "kind": REPOSKOP_EXECUTION_ATTESTATION_KIND,
        "policy_version": REPOSKOP_EXECUTION_ATTESTATION_POLICY_VERSION,
        "required": True,
        "status": "verified",
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "workspace_lease_resource_keys": covering_workspace_leases,
        "workspace_lease_resource_keys_sha256": _sha256_json(
            covering_workspace_leases
        ),
        "workspace": workspace,
        "argv_sha256": argv_sha256,
        "execution_identity_sha256": execution_identity_sha256,
        "purpose": evidence["purpose"],
        "reposkop_executable_sha256": evidence[
            "reposkop_executable_sha256"
        ],
        "report_sha256": evidence["report_sha256"],
        "observation_sha256": evidence["observation_sha256"],
        "projection_sha256": evidence["projection_sha256"],
        "repository_identity_sha256": evidence[
            "repository_identity_sha256"
        ],
        "checkout_identity_sha256": evidence[
            "checkout_identity_sha256"
        ],
        "usage_receipt_path": evidence["usage_receipt_path"],
        "usage_receipt_sha256": evidence["usage_receipt_sha256"],
        "usage_key_sha256": evidence["usage_key_sha256"],
        "audit_ref": evidence["audit_ref"],
        "finding_summary": summary,
        "effect_authorized": False,
    }
    return {
        **material,
        "execution_binding_sha256": _sha256_json(material),
    }


def _record_reposkop_execution_attestation(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    raw = record.get("launcher_json")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        launcher = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    value = launcher.get("reposkop_execution_attestation")
    return dict(value) if isinstance(value, dict) else None


def _record_reposkop_checkout_shadow_before(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    raw = record.get("launcher_json")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        launcher = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    value = launcher.get("reposkop_checkout_shadow_before")
    if (
        not isinstance(value, dict)
        or value.get("phase") != "before"
        or value.get("status") not in {"completed", "unavailable"}
        or value.get("decision_effect") is not False
        or value.get("effect_authorized") is not False
    ):
        return None
    return dict(value)


def _record_reposkop_checkout_shadow_terminal_prepare(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    raw = record.get("launcher_json")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        launcher = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    value = launcher.get("reposkop_checkout_shadow_terminal_prepare")
    if not isinstance(value, dict):
        return None
    digest = value.get("evidence_sha256")
    material = {key: item for key, item in value.items() if key != "evidence_sha256"}
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "grabowski.reposkop_checkout_shadow_evidence"
        or value.get("phase") != "terminal_prepare"
        or value.get("task_id") != record.get("task_id")
        or value.get("status") not in {"completed", "unavailable"}
        or value.get("decision_effect") is not False
        or value.get("effect_authorized") is not False
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
        or digest != _sha256_json(material)
    ):
        return None
    return dict(value)


def _reposkop_shadow_terminal_marker_root() -> Path:
    parent = TASK_OUTCOMES_DIR
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_stat = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
    ):
        raise PermissionError(
            "Reposkop terminal shadow marker parent violates its private-directory contract"
        )
    root = parent / ".reposkop-shadow-terminals"
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    root_stat = root.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise PermissionError(
            "Reposkop terminal shadow marker root violates its private-directory contract"
        )
    return root


def _reposkop_shadow_terminal_marker_path(task_id: str) -> Path:
    identifier = _validate_task_id(task_id)
    return _reposkop_shadow_terminal_marker_root() / f"{identifier}.json"


def _reposkop_shadow_terminal_marker(task_id: str) -> dict[str, Any] | None:
    path = _reposkop_shadow_terminal_marker_path(task_id)
    if not path.exists():
        return None
    payload = base._read_private_evidence(
        path,
        max_bytes=REPOSKOP_SHADOW_TERMINAL_MARKER_MAX_BYTES,
    )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Reposkop terminal shadow marker is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Reposkop terminal shadow marker is invalid")
    digest = value.get("marker_sha256")
    material = {key: item for key, item in value.items() if key != "marker_sha256"}
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "grabowski.reposkop_terminal_shadow_marker"
        or value.get("task_id") != task_id
        or not isinstance(value.get("terminalization_sha256"), str)
        or SHA256.fullmatch(value["terminalization_sha256"]) is None
        or not isinstance(value.get("lifecycle_receipt_sha256"), str)
        or SHA256.fullmatch(value["lifecycle_receipt_sha256"]) is None
        or not isinstance(value.get("shadow_evidence_sha256"), str)
        or SHA256.fullmatch(value["shadow_evidence_sha256"]) is None
        or not isinstance(value.get("audit_ref"), str)
        or re.fullmatch(r"audit-record-sha256:[0-9a-f]{64}", value["audit_ref"])
        is None
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
        or digest != _sha256_json(material)
        or payload.decode("utf-8") != _canonical_json(value) + "\n"
    ):
        raise RuntimeError("Reposkop terminal shadow marker is invalid")
    return value


def _reposkop_shadow_terminal_finalization_metadata_key(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
) -> str:
    identifier = _validate_task_id(task_id)
    if SHA256.fullmatch(terminalization_sha256) is None:
        raise ValueError("Reposkop terminalization digest is invalid")
    if SHA256.fullmatch(lifecycle_receipt_sha256) is None:
        raise ValueError("Reposkop lifecycle receipt digest is invalid")
    return (
        REPOSKOP_SHADOW_TERMINAL_FINALIZED_METADATA_PREFIX
        + identifier
        + ":"
        + terminalization_sha256
        + ":"
        + lifecycle_receipt_sha256
    )


def _record_reposkop_shadow_terminal_finalization(
    marker: dict[str, Any],
) -> str:
    marker_sha256 = marker.get("marker_sha256")
    lifecycle_receipt_sha256 = marker.get("lifecycle_receipt_sha256")
    if not isinstance(marker_sha256, str) or SHA256.fullmatch(marker_sha256) is None:
        raise RuntimeError("Reposkop terminal shadow marker digest is invalid")
    if (
        not isinstance(lifecycle_receipt_sha256, str)
        or SHA256.fullmatch(lifecycle_receipt_sha256) is None
    ):
        raise RuntimeError("Reposkop terminal shadow lifecycle receipt is invalid")
    key = _reposkop_shadow_terminal_finalization_metadata_key(
        task_id=str(marker.get("task_id") or ""),
        terminalization_sha256=str(marker.get("terminalization_sha256") or ""),
        lifecycle_receipt_sha256=lifecycle_receipt_sha256,
    )
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (key,),
        ).fetchone()
        if existing is not None and str(existing[0]) != lifecycle_receipt_sha256:
            connection.rollback()
            raise RuntimeError(
                "Reposkop terminal shadow finalization index conflicts with marker truth"
            )
        if existing is None:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?)",
                (key, lifecycle_receipt_sha256),
            )
        connection.commit()
    return key

def _persist_reposkop_shadow_terminal_marker(
    *,
    task_id: str,
    terminalization_sha256: str,
    lifecycle_receipt_sha256: str,
    result: dict[str, Any],
) -> dict[str, Any] | None:
    evidence_sha256 = result.get("evidence_sha256")
    audit_ref = result.get("audit_ref")
    if (
        not isinstance(evidence_sha256, str)
        or SHA256.fullmatch(evidence_sha256) is None
        or not isinstance(audit_ref, str)
        or re.fullmatch(r"audit-record-sha256:[0-9a-f]{64}", audit_ref) is None
    ):
        return None
    material = {
        "schema_version": 1,
        "kind": "grabowski.reposkop_terminal_shadow_marker",
        "task_id": task_id,
        "terminalization_sha256": terminalization_sha256,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "shadow_evidence_sha256": evidence_sha256,
        "shadow_status": result.get("status"),
        "audit_ref": audit_ref,
        "decision_effect": False,
    }
    marker = {**material, "marker_sha256": _sha256_json(material)}
    path = _reposkop_shadow_terminal_marker_path(task_id)
    payload = (_canonical_json(marker) + "\n").encode("utf-8")
    try:
        base._write_private_create_only(path, payload)
    except FileExistsError:
        existing = _reposkop_shadow_terminal_marker(task_id)
        if existing != marker:
            raise RuntimeError("Reposkop terminal shadow marker conflicts with terminal truth")
        marker = existing
    _record_reposkop_shadow_terminal_finalization(marker)
    return marker


def _reposkop_shadow_terminal_recovery_needed(record: dict[str, Any]) -> bool:
    if not _is_terminal_state(str(record.get("state"))):
        return False
    if _record_reposkop_checkout_shadow_terminal_prepare(record) is None:
        return False
    transition_sha256 = record.get("terminalization_sha256")
    receipt_sha256 = record.get("lifecycle_receipt_sha256")
    if (
        not isinstance(transition_sha256, str)
        or SHA256.fullmatch(transition_sha256) is None
        or not isinstance(receipt_sha256, str)
        or SHA256.fullmatch(receipt_sha256) is None
    ):
        return False
    try:
        marker = _reposkop_shadow_terminal_marker(str(record["task_id"]))
    except Exception:
        return True
    if marker is None:
        return True
    if (
        marker["terminalization_sha256"] != transition_sha256
        or marker["lifecycle_receipt_sha256"] != receipt_sha256
    ):
        return True
    try:
        _record_reposkop_shadow_terminal_finalization(marker)
    except Exception:
        return True
    return False


def _recover_reposkop_shadow_terminal(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    prepared = _record_reposkop_checkout_shadow_terminal_prepare(record)
    if prepared is None:
        return None
    transition_sha256 = record.get("terminalization_sha256")
    receipt_sha256 = record.get("lifecycle_receipt_sha256")
    if (
        not isinstance(transition_sha256, str)
        or SHA256.fullmatch(transition_sha256) is None
        or not isinstance(receipt_sha256, str)
        or SHA256.fullmatch(receipt_sha256) is None
    ):
        return None
    existing = _reposkop_shadow_terminal_marker(str(record["task_id"]))
    if existing is not None:
        if (
            existing["terminalization_sha256"] != transition_sha256
            or existing["lifecycle_receipt_sha256"] != receipt_sha256
        ):
            raise RuntimeError("Reposkop terminal shadow marker is bound to another lifecycle")
        _record_reposkop_shadow_terminal_finalization(existing)
        return existing
    result = _finalize_reposkop_shadow_terminal_best_effort(
        task_id=str(record["task_id"]),
        terminalization_sha256=transition_sha256,
        lifecycle_receipt_sha256=receipt_sha256,
        prepared=prepared,
    )
    if result is None:
        return None
    return _persist_reposkop_shadow_terminal_marker(
        task_id=str(record["task_id"]),
        terminalization_sha256=transition_sha256,
        lifecycle_receipt_sha256=receipt_sha256,
        result=result,
    )


def _record_task_effect_classification(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    raw = record.get("launcher_json")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        launcher = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    value = launcher.get("task_effect_classification")
    return dict(value) if isinstance(value, dict) else None


def _task_resource_keys(
    host: str,
    argv: list[str],
    *,
    cwd: str,
    requested: list[str],
) -> tuple[list[str], str | None]:
    workspace = _mutating_agent_workspace(host, argv, cwd=cwd)
    if workspace is None:
        return requested, None
    if _workspace_lease_resource_keys(workspace, requested):
        return requested, None
    implicit = resources.normalize_resource_key(f"repo:{workspace}")
    return sorted({*requested, implicit}), implicit


def _workspace_scope_identity(workspace: str) -> tuple[str, str]:
    environment = _git_repository_discovery_environment()
    head_result = operator._run(
        ["git", "-C", workspace, "rev-parse", "HEAD"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
        environment=environment,
    )
    raw_head = head_result.get("stdout", "").strip().lower()
    if head_result.get("returncode") == 0 and re.fullmatch(
        r"[0-9a-f]{40}(?:[0-9a-f]{24})?", raw_head
    ):
        head = raw_head
    else:
        head = "0" * 40
    branch_result = operator._run(
        ["git", "-C", workspace, "symbolic-ref", "--quiet", "--short", "HEAD"],
        cwd=operator.HOME,
        timeout_seconds=5,
        max_output_bytes=4096,
        environment=environment,
    )
    raw_branch = branch_result.get("stdout", "").strip()
    if branch_result.get("returncode") == 0 and re.fullmatch(
        r"[A-Za-z0-9._:@/+\-=]{1,512}", raw_branch
    ):
        branch = raw_branch
    elif head != "0" * 40:
        branch = f"detached/{head[:12]}"
    else:
        branch = "unversioned"
    return head, branch


def _reposkop_broad_admission_evidence(
    *,
    lease_result: dict[str, Any] | None,
    repository_scope_manifest: dict[str, Any] | None,
    workspace: str | None,
) -> dict[str, Any] | None:
    if (
        not isinstance(lease_result, dict)
        or not isinstance(repository_scope_manifest, dict)
        or not isinstance(workspace, str)
        or repository_scope_manifest.get("repository") != workspace
        or repository_scope_manifest.get("worktree") != workspace
    ):
        return None
    head = repository_scope_manifest.get("head")
    branch = repository_scope_manifest.get("branch")
    if (
        not isinstance(head, str)
        or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", head) is None
        or set(head) == {"0"}
        or not isinstance(branch, str)
        or not branch
        or branch in {"main", "master", "unversioned"}
        or branch.startswith("detached/")
    ):
        return None
    evidence = lease_result.get("work_admission")
    if not isinstance(evidence, list):
        return None
    for item in evidence:
        if (
            isinstance(item, dict)
            and item.get("repository") == workspace
            and item.get("decision") == "allow"
            and item.get("read_only") is True
        ):
            return dict(item)
    return None


def _reposkop_exact_checkout_admission_evidence(
    *,
    lease_result: dict[str, Any] | None,
    lease_owner_id: str,
    task_resources: list[str],
    workspace: str | None,
    head: str,
    branch: str,
    now: int,
) -> dict[str, Any] | None:
    if (
        not isinstance(lease_result, dict)
        or not isinstance(workspace, str)
        or not isinstance(head, str)
        or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", head) is None
        or set(head) == {"0"}
        or not isinstance(branch, str)
        or not branch
        or branch in {"main", "master", "unversioned"}
        or branch.startswith("detached/")
    ):
        return None
    exact_path_key = resources.normalize_resource_key(f"path:{workspace}")
    if exact_path_key not in task_resources:
        return None
    branch_bindings: list[tuple[str, str]] = []
    for key in task_resources:
        repository = resources.scoped_repository_resource_root(key)
        if repository is None:
            continue
        expected_key = resources.normalize_resource_key(
            f"repo:{repository}:branch:{branch}"
        )
        if key == expected_key:
            branch_bindings.append((key, repository))
    if len(branch_bindings) != 1:
        return None
    branch_key, repository = branch_bindings[0]
    acquired = {
        str(item.get("resource_key")): item
        for item in lease_result.get("leases", [])
        if isinstance(item, dict)
    }
    for key in (exact_path_key, branch_key):
        lease = acquired.get(key)
        if (
            lease is None
            or lease.get("owner_id") != lease_owner_id
            or int(lease.get("expires_at_unix", 0)) <= now
        ):
            return None
    requested_scope = {
        "schema_version": 1,
        "repository": repository,
        "worktree": workspace,
        "head": head,
        "branch": branch,
        "resource_keys": list(task_resources),
    }
    try:
        assessment = resources.work_admission.require_repository_admission(
            repo=repository,
            owner_id=lease_owner_id,
            operation="task_existing_checkout",
            requested_scope=requested_scope,
            target_path=workspace,
            branch=branch,
        )
    except (
        resources.work_admission.WorkAdmissionBlocked,
        OSError,
        RuntimeError,
        ValueError,
    ):
        return None
    if (
        not isinstance(assessment, dict)
        or assessment.get("decision") != "allow"
        or assessment.get("read_only") is not True
        or assessment.get("scope_mode") != "exact_checkout"
        or assessment.get("scope_identity")
        != {"target_path": workspace, "branch": branch, "head": head}
    ):
        return None
    return dict(assessment)


def _reposkop_prospective_admission_evidence(
    *,
    lease_result: dict[str, Any] | None,
    lease_owner_id: str,
    task_resources: list[str],
    repository_scope_manifest: dict[str, Any] | None,
    workspace: str | None,
    head: str,
    branch: str,
    now: int,
) -> dict[str, Any] | None:
    broad = _reposkop_broad_admission_evidence(
        lease_result=lease_result,
        repository_scope_manifest=repository_scope_manifest,
        workspace=workspace,
    )
    if broad is not None:
        return broad
    return _reposkop_exact_checkout_admission_evidence(
        lease_result=lease_result,
        lease_owner_id=lease_owner_id,
        task_resources=task_resources,
        workspace=workspace,
        head=head,
        branch=branch,
        now=now,
    )


def _whole_repository_scope_manifest(
    resource_key: str, task_id: str
) -> dict[str, Any]:
    if not resource_key.startswith("repo:"):
        raise ValueError("repository resource must use repo:<absolute-path> syntax")
    workspace = resource_key.removeprefix("repo:")
    head, branch = _workspace_scope_identity(workspace)
    return nonconflict.normalize_scope_manifest(
        {
            "schema_version": 1,
            "repository": workspace,
            "task_id": task_id,
            "base_head": head,
            "head": head,
            "branch": branch,
            "worktree": workspace,
            "effects": ["write"],
            "paths": [workspace],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
    )


def _task_repository_resource(resource_keys: list[str]) -> str | None:
    broad_repository_keys = [
        key
        for key in resource_keys
        if key.startswith("repo:")
        and resources.scoped_repository_resource_root(key) is None
    ]
    if not broad_repository_keys:
        return None
    if len(broad_repository_keys) != 1:
        raise ValueError("tasks may lease at most one broad repository")
    return broad_repository_keys[0]


def _record_implicit_workspace_resource(
    record: dict[str, Any], repository_resource: str | None
) -> str | None:
    if repository_resource is None:
        return None
    command = json.loads(record["argv_json"])
    workspace = _mutating_agent_workspace(
        str(record["host"]), command, cwd=str(record["cwd"])
    )
    if workspace is None:
        return None
    candidate = resources.normalize_resource_key(f"repo:{workspace}")
    return repository_resource if candidate == repository_resource else None


def _record_repository_scope_manifest(
    record: dict[str, Any], repository_resource: str | None
) -> dict[str, Any] | None:
    raw = record.get("repository_scope_manifest_json")
    if raw is None or raw == "":
        if repository_resource is None:
            return None
        return resources.repository_scope_manifest_for_owner(
            str(record.get("lease_owner_id") or _lease_owner(record["task_id"])),
            repository_resource,
        )
    if repository_resource is None:
        raise RuntimeError(
            "stored repository scope manifest has no broad repository resource"
        )
    try:
        manifest = nonconflict.normalize_scope_manifest(json.loads(str(raw)))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("stored repository scope manifest is invalid") from exc
    if f"repo:{manifest['repository']}" != repository_resource:
        raise RuntimeError(
            "stored repository scope manifest does not match repository resource"
        )
    return manifest


def _task_lease_metadata(
    *,
    task_id: str,
    host: str,
    attempt: int,
    repository_resource: str | None,
    implicit_workspace_resource: str | None,
    repository_scope_manifest: dict[str, Any] | None = None,
    recovered_after_expiry: bool = False,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "task_id": task_id,
        "host": host,
        "attempt": attempt,
        "implicit_workspace_resource_key": implicit_workspace_resource,
    }
    if recovered_after_expiry:
        metadata["recovered_after_expiry"] = True
    if repository_resource is not None:
        if repository_scope_manifest is None:
            raise RuntimeError(
                "repository scope manifest evidence is required for repository lease"
            )
        manifest = nonconflict.normalize_scope_manifest(repository_scope_manifest)
        if f"repo:{manifest['repository']}" != repository_resource:
            raise ValueError("repository scope manifest must match repository resource")
        metadata["scope_manifest"] = manifest
        metadata["scope_manifest_complete"] = True
    return metadata


def _chronik_context(
    host: str,
    resource_keys: list[str],
    operation: str,
    *,
    component: str = "",
    bureau_task_id: str = "",
    pr_number: int | None = None,
) -> str:
    context: dict[str, Any] = {
        "subject_scope": "host",
        "host": host,
        "operation": operation,
        "task_class": CHRONIK_OPERATION_TASK_CLASS[operation],
    }
    if component:
        context["component"] = component
    if bureau_task_id:
        context["bureau_task_id"] = bureau_task_id
    if pr_number is not None:
        context["pr_number"] = pr_number
    if fleet.fleet_host(host)["transport"] != "local":
        return _canonical_json(context)
    repositories = [key.removeprefix("repo:") for key in resource_keys if key.startswith("repo:")]
    if len(repositories) != 1:
        return _canonical_json(context)
    result = operator._run(
        ["git", "-C", repositories[0], "config", "--get", "remote.origin.url"],
        cwd=operator.HOME, timeout_seconds=5, max_output_bytes=4096,
    )
    if result["returncode"] != 0:
        return _canonical_json(context)
    remote = result["stdout"].strip()
    match = re.search(r"(?:github\.com[:/])(?P<slug>[^/\s]+/[^/\s]+?)(?:\.git)?$", remote)
    if match is None or not match.group("slug").startswith("heimgewebe/"):
        return _canonical_json(context)
    context.pop("host", None)
    context["subject_scope"] = "repository"
    context["repo"] = match.group("slug")
    return _canonical_json(context)


def _lease_owner(task_id: str) -> str:
    return f"task:{_validate_task_id(task_id)}"


def _record_resource_keys(record: dict[str, Any]) -> list[str]:
    raw = record.get("resource_keys_json") or "[]"
    try:
        values = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("stored task resource keys are invalid") from exc
    if not isinstance(values, list):
        raise RuntimeError("stored task resource keys are invalid")
    try:
        return [resources.normalize_resource_key(value) for value in values]
    except (TypeError, ValueError) as exc:
        raise RuntimeError("stored task resource keys are invalid") from exc


def _task_execution_identity(
    *,
    host: str,
    argv_sha256: str,
    cwd: str,
    resource_keys: list[str],
    runtime_seconds: int,
    cpu_weight: int,
    io_weight: int,
    memory_max_bytes: int | None,
    chronik_outbox_enabled: bool,
    chronik_outbox_state_root: str | None,
    chronik_context_json: str | None,
    execution_backend: str,
    systemd_scope: str,
) -> dict[str, Any]:
    chronik_context: dict[str, Any] | None = None
    if chronik_context_json is not None:
        try:
            decoded_chronik_context = json.loads(chronik_context_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError("stored task Chronik context is invalid") from exc
        if not isinstance(decoded_chronik_context, dict):
            raise RuntimeError("stored task Chronik context is invalid")
        chronik_context = decoded_chronik_context
    return terminal_convergence.task_execution_identity(
        host=host,
        argv_sha256=argv_sha256,
        cwd=cwd,
        resource_keys=[
            resources.normalize_resource_key(value) for value in resource_keys
        ],
        runtime_seconds=runtime_seconds,
        cpu_weight=cpu_weight,
        io_weight=io_weight,
        memory_max_bytes=memory_max_bytes,
        chronik_outbox_enabled=chronik_outbox_enabled,
        chronik_outbox_state_root=chronik_outbox_state_root,
        chronik_context=chronik_context,
        execution_backend=execution_backend,
        systemd_scope=systemd_scope,
    )


def _record_execution_identity(record: dict[str, Any]) -> dict[str, Any]:
    return _task_execution_identity(
        host=str(record["host"]),
        argv_sha256=str(record["argv_sha256"]),
        cwd=str(record["cwd"]),
        resource_keys=_record_resource_keys(record),
        runtime_seconds=int(record["runtime_seconds"]),
        cpu_weight=int(record["cpu_weight"]),
        io_weight=int(record["io_weight"]),
        memory_max_bytes=(
            None
            if record.get("memory_max_bytes") is None
            else int(record["memory_max_bytes"])
        ),
        chronik_outbox_enabled=bool(record.get("chronik_outbox_enabled")),
        chronik_outbox_state_root=record.get("chronik_outbox_state_root"),
        chronik_context_json=record.get("chronik_context_json"),
        execution_backend=_execution_backend(record),
        systemd_scope=_systemd_scope(record),
    )


def _latest_matching_execution_record(
    identity: dict[str, Any],
) -> dict[str, Any] | None:
    with _database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM tasks WHERE host=? AND argv_sha256=? AND cwd=? "
            "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
            "AND io_weight=? AND memory_max_bytes IS ? "
            "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
            "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
            "ORDER BY created_at_unix DESC, rowid DESC LIMIT 1",
            (
                identity["host"],
                identity["argv_sha256"],
                identity["cwd"],
                _canonical_json(identity["resource_keys"]),
                identity["runtime_seconds"],
                identity["cpu_weight"],
                identity["io_weight"],
                identity["memory_max_bytes"],
                int(identity["chronik_outbox_enabled"]),
                identity["chronik_outbox_state_root"],
                (
                    _canonical_json(identity["chronik_context"])
                    if identity["chronik_context"] is not None
                    else None
                ),
                identity["execution_backend"],
                identity["systemd_scope"],
            ),
        ).fetchone()
    if row is None:
        return None
    record = dict(row)
    if (
        _record_execution_identity(record)["identity_sha256"]
        != identity["identity_sha256"]
    ):
        raise RuntimeError("stored task execution identity is inconsistent")
    return record


def _latest_matching_active_execution_record(
    identity: dict[str, Any],
) -> dict[str, Any] | None:
    active_states = tuple(TASK_STATE_PROJECTIONS["active"])
    placeholders = ",".join("?" for _ in active_states)
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE host=? AND argv_sha256=? AND cwd=? "
            "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
            "AND io_weight=? AND memory_max_bytes IS ? "
            "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
            "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
            f"AND state IN ({placeholders}) "
            "ORDER BY created_at_unix DESC, rowid DESC LIMIT 50001",
            (
                identity["host"],
                identity["argv_sha256"],
                identity["cwd"],
                _canonical_json(identity["resource_keys"]),
                identity["runtime_seconds"],
                identity["cpu_weight"],
                identity["io_weight"],
                identity["memory_max_bytes"],
                int(identity["chronik_outbox_enabled"]),
                identity["chronik_outbox_state_root"],
                (
                    _canonical_json(identity["chronik_context"])
                    if identity["chronik_context"] is not None
                    else None
                ),
                identity["execution_backend"],
                identity["systemd_scope"],
                *active_states,
            ),
        ).fetchall()
    if len(rows) > 50000:
        raise RuntimeError("active execution identity scan limit exceeded")
    matching: list[dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        if _persisted_task_operation_identity(record) is not None:
            continue
        if (
            _record_execution_identity(record)["identity_sha256"]
            != identity["identity_sha256"]
        ):
            raise RuntimeError("stored active task execution identity is inconsistent")
        matching.append(record)
    if len(matching) > 1:
        raise RuntimeError(
            "multiple active tasks share one execution identity; reconcile before retry"
        )
    return matching[0] if matching else None


def _resolve_active_execution_reuse(
    identity: dict[str, Any],
    *,
    resume_policy: ResumePolicy,
) -> dict[str, Any] | None:
    latest = _latest_matching_active_execution_record(identity)
    if latest is None:
        return None
    if (
        _persisted_retry_binding_or_raise(latest) is not None
        or _persisted_interrupted_recovery_binding_or_raise(latest) is not None
    ):
        return None
    if str(latest["resume_policy"]) != resume_policy:
        raise RuntimeError(
            "active execution identity has a different resume policy; "
            f"reconcile task {latest['task_id']} before another start"
        )
    now = _now()
    if not _task_has_fresh_active_observation(latest, now=now):
        grabowski_task_status(str(latest["task_id"]))
        latest = _row_raw(str(latest["task_id"]))
    if str(latest["state"]) in TASK_STATE_PROJECTIONS["active"]:
        return latest
    return None


def _matching_attention_execution_records(
    identity: dict[str, Any],
) -> list[dict[str, Any]]:
    attention_states = tuple(TASK_STATE_PROJECTIONS["attention"])
    placeholders = ",".join("?" for _ in attention_states)
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE host=? AND argv_sha256=? AND cwd=? "
            "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
            "AND io_weight=? AND memory_max_bytes IS ? "
            "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
            "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
            f"AND state IN ({placeholders}) "
            "ORDER BY created_at_unix DESC, rowid DESC LIMIT 50001",
            (
                identity["host"],
                identity["argv_sha256"],
                identity["cwd"],
                _canonical_json(identity["resource_keys"]),
                identity["runtime_seconds"],
                identity["cpu_weight"],
                identity["io_weight"],
                identity["memory_max_bytes"],
                int(identity["chronik_outbox_enabled"]),
                identity["chronik_outbox_state_root"],
                (
                    _canonical_json(identity["chronik_context"])
                    if identity["chronik_context"] is not None
                    else None
                ),
                identity["execution_backend"],
                identity["systemd_scope"],
                *attention_states,
            ),
        ).fetchall()
    if len(rows) > 50000:
        raise RuntimeError("matching attention execution scan limit exceeded")
    records = [dict(row) for row in rows]
    if any(
        _record_execution_identity(record)["identity_sha256"]
        != identity["identity_sha256"]
        for record in records
    ):
        raise RuntimeError("stored task execution identity is inconsistent")
    return records


def _build_terminal_retry_context(
    record: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    normalized_reason = _redact_reason(reason.strip())
    if not normalized_reason:
        raise ValueError("named retry state change is required")
    state = str(record["state"])
    if state not in UNCHANGED_RETRY_STATES:
        raise ValueError("retry source task is not an attention state")
    lifecycle_receipt_sha256 = record.get("lifecycle_receipt_sha256")
    terminalization_sha256 = record.get("terminalization_sha256")
    if not isinstance(lifecycle_receipt_sha256, str) or len(lifecycle_receipt_sha256) != 64:
        raise ValueError("retry source lifecycle receipt is missing")
    if not isinstance(terminalization_sha256, str) or len(terminalization_sha256) != 64:
        raise ValueError("retry source terminalization receipt is missing")
    material = {
        "schema_version": TASK_RETRY_CONTEXT_SCHEMA_VERSION,
        "kind": "grabowski_named_terminal_retry",
        "source_task_id": str(record["task_id"]),
        "source_attempt": int(record["attempt"]),
        "source_state": state,
        "source_resume_policy": str(record["resume_policy"]),
        "source_lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "source_terminalization_sha256": terminalization_sha256,
        "source_execution_identity_sha256": _record_execution_identity(record)[
            "identity_sha256"
        ],
        "named_state_change": normalized_reason,
        "observed_at_unix": _now(),
        "does_not_establish": [
            "that_the_named_change_is_sufficient",
            "that_the_retry_will_succeed",
            "automatic_retry_authority",
        ],
    }
    return {**material, "context_sha256": _sha256_json(material)}


def _validate_terminal_retry_context(
    context: dict[str, Any],
    *,
    predecessor: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("terminal retry context must be an object")
    context_sha256 = context.get("context_sha256")
    material = {key: value for key, value in context.items() if key != "context_sha256"}
    if not isinstance(context_sha256, str) or context_sha256 != _sha256_json(material):
        raise ValueError("terminal retry context integrity is invalid")
    expected = {
        "source_task_id": str(predecessor["task_id"]),
        "source_attempt": int(predecessor["attempt"]),
        "source_state": str(predecessor["state"]),
        "source_resume_policy": str(predecessor["resume_policy"]),
        "source_lifecycle_receipt_sha256": predecessor.get(
            "lifecycle_receipt_sha256"
        ),
        "source_terminalization_sha256": predecessor.get(
            "terminalization_sha256"
        ),
        "source_execution_identity_sha256": identity["identity_sha256"],
    }
    if context.get("schema_version") != TASK_RETRY_CONTEXT_SCHEMA_VERSION:
        raise ValueError("terminal retry context schema is invalid")
    if context.get("kind") != "grabowski_named_terminal_retry":
        raise ValueError("terminal retry context kind is invalid")
    for key, value in expected.items():
        if context.get(key) != value:
            raise ValueError(f"terminal retry context {key} binding is stale")
    named_state_change = context.get("named_state_change")
    if not isinstance(named_state_change, str) or not named_state_change.strip():
        raise ValueError("terminal retry context requires a named state change")
    observed_at_unix = context.get("observed_at_unix")
    now = _now()
    if (
        isinstance(observed_at_unix, bool)
        or not isinstance(observed_at_unix, int)
        or observed_at_unix < 0
        or observed_at_unix > now + 300
    ):
        raise ValueError("terminal retry context timestamp is invalid")
    return {
        "schema_version": TASK_RETRY_CONTEXT_SCHEMA_VERSION,
        "kind": "grabowski_named_terminal_retry",
        "source_task_id": expected["source_task_id"],
        "source_attempt": expected["source_attempt"],
        "source_state": expected["source_state"],
        "source_resume_policy": expected["source_resume_policy"],
        "source_lifecycle_receipt_sha256": expected[
            "source_lifecycle_receipt_sha256"
        ],
        "source_terminalization_sha256": expected[
            "source_terminalization_sha256"
        ],
        "source_execution_identity_sha256": expected[
            "source_execution_identity_sha256"
        ],
        "named_state_change": named_state_change,
        "observed_at_unix": observed_at_unix,
        "does_not_establish": list(context.get("does_not_establish") or []),
        "context_sha256": context_sha256,
    }


def _interrupted_recovery_evidence_projection(
    record: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, Any]:
    if str(record.get("state")) != "interrupted":
        raise ValueError("interrupted recovery source task is not interrupted")
    if not isinstance(observation, dict):
        raise ValueError("interrupted recovery observation is invalid")
    properties = observation.get("properties")
    probe = observation.get("probe")
    observer = observation.get("observer")
    if (
        not isinstance(properties, dict)
        or not isinstance(probe, dict)
        or not isinstance(observer, dict)
    ):
        raise ValueError("interrupted recovery observation evidence is incomplete")
    if properties.get("LoadState") != "not-found":
        raise ValueError("interrupted recovery old unit is not confirmed absent")
    if properties.get("ActiveState") not in {None, "", "inactive"}:
        raise ValueError("interrupted recovery old unit state is not safely absent")
    if properties.get("SubState") not in {None, "", "dead"}:
        raise ValueError("interrupted recovery old unit substate is not safely absent")
    if properties.get("Result") not in {None, "", "success"}:
        raise ValueError("interrupted recovery old unit retains a material result")
    if properties.get("ExecMainCode") not in {None, "", "0"}:
        raise ValueError("interrupted recovery old unit retains a material exit code")
    if properties.get("ExecMainStatus") not in {None, "", "0"}:
        raise ValueError("interrupted recovery old unit retains a material exit status")
    returncode = probe.get("returncode")
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or returncode not in {0, 1, 3, 4}
        or bool(probe.get("timed_out"))
        or bool(probe.get("outcome_unknown"))
    ):
        raise ValueError("interrupted recovery probe transport is not authoritative")
    expected_backend = _execution_backend(record)
    expected_scope = _systemd_scope(record)
    if (
        observer.get("execution_backend") != expected_backend
        or observer.get("systemd_scope") != expected_scope
        or not isinstance(observer.get("kind"), str)
        or not str(observer.get("kind")).strip()
    ):
        raise ValueError("interrupted recovery observer binding is invalid")
    return {
        "schema_version": 1,
        "kind": "grabowski_interrupted_unit_absence_evidence",
        "source_task_id": str(record["task_id"]),
        "source_unit": str(record["unit"]),
        "source_authoritative_unit": _authoritative_unit(record),
        "execution_backend": expected_backend,
        "systemd_scope": expected_scope,
        "observer_kind": str(observer["kind"]),
        "observation_state": str(observation.get("state") or ""),
        "load_state": "not-found",
        "active_state": str(properties.get("ActiveState") or ""),
        "sub_state": str(properties.get("SubState") or ""),
        "result": str(properties.get("Result") or ""),
        "exec_main_code": str(properties.get("ExecMainCode") or ""),
        "exec_main_status": str(properties.get("ExecMainStatus") or ""),
        "probe_returncode": returncode,
        "probe_timed_out": False,
        "probe_outcome_unknown": False,
    }


def _build_interrupted_recovery_context(
    record: dict[str, Any],
    observation: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    normalized_reason = _redact_reason(reason.strip())
    if not normalized_reason:
        raise ValueError("named interrupted recovery state change is required")
    recovery_evidence = _interrupted_recovery_evidence_projection(record, observation)
    material = {
        "schema_version": TASK_INTERRUPTED_RECOVERY_CONTEXT_SCHEMA_VERSION,
        "kind": "grabowski_named_interrupted_recovery",
        "source_task_id": str(record["task_id"]),
        "source_attempt": int(record["attempt"]),
        "source_state": "interrupted",
        "source_resume_policy": str(record["resume_policy"]),
        "source_unit": str(record["unit"]),
        "source_authoritative_unit": _authoritative_unit(record),
        "source_updated_at_unix": int(record["updated_at_unix"]),
        "source_execution_identity_sha256": _record_execution_identity(record)[
            "identity_sha256"
        ],
        "source_recovery_evidence_sha256": _sha256_json(recovery_evidence),
        "named_state_change": normalized_reason,
        "admitted_at_unix": _now(),
        "does_not_establish": [
            "that_the_interrupted_execution_failed",
            "that_the_named_change_is_sufficient",
            "that_the_recovery_will_succeed",
            "automatic_retry_authority",
        ],
    }
    return {**material, "context_sha256": _sha256_json(material)}


def _validate_interrupted_recovery_context(
    context: dict[str, Any],
    *,
    record: dict[str, Any],
    observation: dict[str, Any],
) -> dict[str, Any]:
    required = TASK_INTERRUPTED_RECOVERY_CONTEXT_KEYS
    if not isinstance(context, dict) or set(context) != required:
        raise ValueError("interrupted recovery context shape is invalid")
    material = {key: context[key] for key in required - {"context_sha256"}}
    if context.get("context_sha256") != _sha256_json(material):
        raise ValueError("interrupted recovery context integrity is invalid")
    if (
        context.get("schema_version")
        != TASK_INTERRUPTED_RECOVERY_CONTEXT_SCHEMA_VERSION
        or context.get("kind") != "grabowski_named_interrupted_recovery"
    ):
        raise ValueError("interrupted recovery context contract is invalid")
    recovery_evidence = _interrupted_recovery_evidence_projection(record, observation)
    expected = {
        "source_task_id": str(record["task_id"]),
        "source_attempt": int(record["attempt"]),
        "source_state": "interrupted",
        "source_resume_policy": str(record["resume_policy"]),
        "source_unit": str(record["unit"]),
        "source_authoritative_unit": _authoritative_unit(record),
        "source_updated_at_unix": int(record["updated_at_unix"]),
        "source_execution_identity_sha256": _record_execution_identity(record)[
            "identity_sha256"
        ],
        "source_recovery_evidence_sha256": _sha256_json(recovery_evidence),
    }
    for key, value in expected.items():
        if context.get(key) != value:
            raise ValueError(f"interrupted recovery context {key} binding is stale")
    named_state_change = context.get("named_state_change")
    if not isinstance(named_state_change, str) or not named_state_change.strip():
        raise ValueError("interrupted recovery context requires a named state change")
    admitted_at_unix = context.get("admitted_at_unix")
    now = _now()
    if (
        isinstance(admitted_at_unix, bool)
        or not isinstance(admitted_at_unix, int)
        or admitted_at_unix < 0
        or admitted_at_unix > now + 300
    ):
        raise ValueError("interrupted recovery context timestamp is invalid")
    non_claims = context.get("does_not_establish")
    if not isinstance(non_claims, list) or any(
        not isinstance(item, str) or not item for item in non_claims
    ):
        raise ValueError("interrupted recovery context non-claims are invalid")
    return dict(context)



def _persisted_retry_binding_or_raise(record: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return terminal_convergence.persisted_retry_binding(record)
    except terminal_convergence.TerminalConvergenceError as exc:
        raise RuntimeError("stored retry admission evidence is invalid") from exc


def _persisted_interrupted_recovery_binding_or_raise(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    raw_launcher = record.get("launcher_json")
    if raw_launcher in {None, ""}:
        return None
    try:
        launcher = json.loads(str(raw_launcher))
    except (json.JSONDecodeError, TypeError) as exc:
        if "interrupted_recovery_binding" in str(raw_launcher):
            raise RuntimeError(
                "stored interrupted recovery admission evidence is invalid"
            ) from exc
        return None
    if not isinstance(launcher, dict):
        return None
    binding = launcher.get("interrupted_recovery_binding")
    if binding is None:
        return None
    if not isinstance(binding, dict) or set(binding) != set(
        TASK_INTERRUPTED_RECOVERY_CONTEXT_KEYS
    ):
        raise RuntimeError("stored interrupted recovery admission evidence is invalid")
    material = {
        key: binding[key]
        for key in TASK_INTERRUPTED_RECOVERY_CONTEXT_KEYS
        if key != "context_sha256"
    }
    source_attempt = binding.get("source_attempt")
    if (
        isinstance(source_attempt, bool)
        or not isinstance(source_attempt, int)
        or source_attempt < 1
    ):
        raise RuntimeError("stored interrupted recovery admission evidence is invalid")
    source_unit = _task_unit(str(record["task_id"]), source_attempt)
    expected = {
        "schema_version": TASK_INTERRUPTED_RECOVERY_CONTEXT_SCHEMA_VERSION,
        "kind": "grabowski_named_interrupted_recovery",
        "source_task_id": str(record["task_id"]),
        "source_attempt": int(record["attempt"]) - 1,
        "source_state": "interrupted",
        "source_resume_policy": str(record["resume_policy"]),
        "source_unit": source_unit,
        "source_authoritative_unit": source_unit,
        "source_execution_identity_sha256": _record_execution_identity(record)[
            "identity_sha256"
        ],
    }
    source_updated_at_unix = binding.get("source_updated_at_unix")
    admitted_at_unix = binding.get("admitted_at_unix")
    named_state_change = binding.get("named_state_change")
    source_recovery_evidence_sha256 = binding.get("source_recovery_evidence_sha256")
    non_claims = binding.get("does_not_establish")
    if (
        binding.get("context_sha256") != _sha256_json(material)
        or any(binding.get(key) != value for key, value in expected.items())
        or isinstance(source_updated_at_unix, bool)
        or not isinstance(source_updated_at_unix, int)
        or source_updated_at_unix < 0
        or isinstance(admitted_at_unix, bool)
        or not isinstance(admitted_at_unix, int)
        or admitted_at_unix < source_updated_at_unix
        or not isinstance(named_state_change, str)
        or not named_state_change.strip()
        or not isinstance(source_recovery_evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_recovery_evidence_sha256) is None
        or not isinstance(non_claims, list)
        or any(not isinstance(item, str) or not item for item in non_claims)
    ):
        raise RuntimeError("stored interrupted recovery admission evidence is invalid")
    return dict(binding)


def _retained_retry_successor_for_source(
    source_task_id: str,
) -> dict[str, Any] | None:
    if (
        not isinstance(source_task_id, str)
        or terminal_convergence.TASK_ID_RE.fullmatch(source_task_id) is None
    ):
        raise ValueError("retry successor source task id is invalid")
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE task_id<>? AND state<>'cancelled' "
            "AND launcher_json IS NOT NULL AND ("
            "(json_valid(launcher_json) "
            "AND json_type(launcher_json, '$.retry_binding.source_task_id') = 'text' "
            "AND json_extract(launcher_json, '$.retry_binding.source_task_id')=?) "
            "OR (NOT json_valid(launcher_json) AND instr(launcher_json, ?) > 0)"
            ") ORDER BY created_at_unix DESC, rowid DESC LIMIT 2",
            (source_task_id, source_task_id, '"retry_binding"'),
        ).fetchall()
    if not rows:
        return None
    records = [dict(row) for row in rows]
    for record in records:
        binding = _persisted_retry_binding_or_raise(record)
        if binding is None or str(binding.get("source_task_id")) != source_task_id:
            raise RuntimeError("stored retry admission evidence is invalid")
    if len(records) > 1:
        raise RuntimeError("named retry source has multiple retained successors")
    return records[0]


def _guard_linked_retry_successor(
    latest: dict[str, Any] | None,
    *,
    source_task_id: str,
) -> None:
    if latest is not None and str(latest["task_id"]) != source_task_id:
        binding = _persisted_retry_binding_or_raise(latest)
        if binding is not None and str(latest["state"]) in {
            "launching",
            "running",
            "outcome_unknown",
        }:
            raise RuntimeError(
                "unchanged task start blocked by unresolved retry successor; "
                f"reconcile task {latest['task_id']} before another start"
            )
    retained = _retained_retry_successor_for_source(source_task_id)
    if retained is None:
        return
    retained_state = str(retained["state"])
    if retained_state in {"launching", "running", "outcome_unknown"}:
        raise RuntimeError(
            "unchanged task start blocked by unresolved retry successor; "
            f"reconcile task {retained['task_id']} before another start"
        )
    raise RuntimeError(
        "named retry source already has a retained successor; "
        f"reconcile task {retained['task_id']} instead"
    )


def _execution_identity_without_command(identity: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in identity.items()
        if key not in {"argv_sha256", "identity_sha256"}
    }


def _record_matches_unprepared_managed_cargo_command(
    record: dict[str, Any],
    command: list[str],
) -> bool:
    try:
        stored = json.loads(str(record["argv_json"]))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError("stored task argv is invalid") from exc
    if not isinstance(stored, list) or any(not isinstance(item, str) for item in stored):
        raise RuntimeError("stored task argv is invalid")
    if stored == command:
        return True

    # An explicitly managed CARGO_TARGET_DIR is lifecycle-fenced by prefixing
    # only the flock wrapper. Match that persisted form before the lock root is
    # prepared again, so an unchanged terminal retry remains effect-free.
    if len(stored) == len(command) + 3 and stored[3:] == command:
        target_dir = _explicit_managed_cargo_target_dir(command)
        if (
            stored[0] != FLOCK_EXECUTABLE
            or stored[1] != "--shared"
            or target_dir is None
        ):
            raise RuntimeError("stored managed Cargo task wrapper is invalid")
        expected_lock = _managed_cargo_lifecycle_lock_path(target_dir)
        if stored[2] != str(expected_lock):
            raise RuntimeError("stored managed Cargo task lock binding is invalid")
        return True

    # An unprepared Cargo request gains both the lifecycle flock and an env
    # assignment produced by the managed-build resolver.
    if len(stored) != len(command) + 5 or stored[5:] != command:
        return False
    if (
        stored[0] != FLOCK_EXECUTABLE
        or stored[1] != "--shared"
        or Path(stored[3]).name != Path(SYSTEMD_ENV_EXECUTABLE).name
        or not stored[4].startswith("CARGO_TARGET_DIR=")
    ):
        raise RuntimeError("stored managed Cargo task wrapper is invalid")
    target_dir = stored[4].removeprefix("CARGO_TARGET_DIR=")
    expected_lock = _managed_cargo_lifecycle_lock_path(target_dir)
    if stored[2] != str(expected_lock):
        raise RuntimeError("stored managed Cargo task lock binding is invalid")
    return True


def _managed_cargo_command_sql_predicate(
    command: list[str],
) -> tuple[str, tuple[Any, ...]]:
    if not command or any(not isinstance(item, str) for item in command):
        raise ValueError("managed Cargo command must contain only strings")

    clauses = ["argv_json=?"]
    parameters: list[Any] = [_canonical_json(command)]
    explicit_target = _explicit_managed_cargo_target_dir(command)
    if explicit_target is not None:
        clauses.append("argv_json=?")
        parameters.append(
            _canonical_json(
                [
                    FLOCK_EXECUTABLE,
                    "--shared",
                    str(_managed_cargo_lifecycle_lock_path(explicit_target)),
                    *command,
                ]
            )
        )

    target_prefix = "CARGO_TARGET_DIR="
    wrapper_terms = [
        "json_valid(argv_json)",
        "json_type(argv_json)='array'",
        "json_array_length(argv_json)=?",
        "json_type(argv_json, '$[0]')='text'",
        "json_extract(argv_json, '$[0]')=?",
        "json_type(argv_json, '$[1]')='text'",
        "json_extract(argv_json, '$[1]')=?",
        "json_type(argv_json, '$[2]')='text'",
        "json_type(argv_json, '$[3]')='text'",
        "(json_extract(argv_json, '$[3]')=? "
        "OR json_extract(argv_json, '$[3]') GLOB '*/env')",
        "json_type(argv_json, '$[4]')='text'",
        "substr(json_extract(argv_json, '$[4]'), 1, ?)=?",
    ]
    wrapper_parameters: list[Any] = [
        len(command) + 5,
        FLOCK_EXECUTABLE,
        "--shared",
        Path(SYSTEMD_ENV_EXECUTABLE).name,
        len(target_prefix),
        target_prefix,
    ]
    for index, item in enumerate(command, start=5):
        wrapper_terms.extend(
            [
                f"json_type(argv_json, '$[{index}]')='text'",
                f"json_extract(argv_json, '$[{index}]')=?",
            ]
        )
        wrapper_parameters.append(item)
    clauses.append("(" + " AND ".join(wrapper_terms) + ")")
    parameters.extend(wrapper_parameters)

    # Preserve the old fail-closed behavior for corrupt stored argv.
    # CASE prevents JSON table functions from evaluating malformed JSON.
    invalid_stored_argv = (
        "CASE WHEN NOT json_valid(argv_json) THEN 1 "
        "WHEN json_type(argv_json)<>'array' THEN 1 "
        "WHEN EXISTS (SELECT 1 FROM json_each(argv_json) WHERE type<>'text') "
        "THEN 1 ELSE 0 END=1"
    )
    clauses.append(invalid_stored_argv)
    return (
        "(" + " OR ".join(f"({clause})" for clause in clauses) + ")",
        tuple(parameters),
    )


def _latest_matching_unprepared_managed_cargo_record(
    identity: dict[str, Any],
    command: list[str],
) -> dict[str, Any] | None:
    argv_predicate, argv_parameters = _managed_cargo_command_sql_predicate(command)
    with _database_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM tasks WHERE host=? AND cwd=? "
            "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
            "AND io_weight=? AND memory_max_bytes IS ? "
            "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
            "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
            f"AND {argv_predicate} "
            "ORDER BY created_at_unix DESC, rowid DESC",
            (
                identity["host"],
                identity["cwd"],
                _canonical_json(identity["resource_keys"]),
                identity["runtime_seconds"],
                identity["cpu_weight"],
                identity["io_weight"],
                identity["memory_max_bytes"],
                int(identity["chronik_outbox_enabled"]),
                identity["chronik_outbox_state_root"],
                (
                    _canonical_json(identity["chronik_context"])
                    if identity["chronik_context"] is not None
                    else None
                ),
                identity["execution_backend"],
                identity["systemd_scope"],
                *argv_parameters,
            ),
        )
        while True:
            rows = cursor.fetchmany(256)
            if not rows:
                return None
            for row in rows:
                record = dict(row)
                if _record_matches_unprepared_managed_cargo_command(
                    record, command
                ):
                    return record

def _matching_attention_unprepared_managed_cargo_records(
    identity: dict[str, Any],
    command: list[str],
) -> list[dict[str, Any]]:
    attention_states = tuple(TASK_STATE_PROJECTIONS["attention"])
    placeholders = ",".join("?" for _ in attention_states)
    argv_predicate, argv_parameters = _managed_cargo_command_sql_predicate(command)
    scan_limit = MANAGED_CARGO_ATTENTION_MATCH_LIMIT
    if (
        isinstance(scan_limit, bool)
        or not isinstance(scan_limit, int)
        or scan_limit < 1
    ):
        raise RuntimeError("managed Cargo attention scan limit is invalid")
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE host=? AND cwd=? "
            "AND resource_keys_json=? AND runtime_seconds=? AND cpu_weight=? "
            "AND io_weight=? AND memory_max_bytes IS ? "
            "AND chronik_outbox_enabled=? AND chronik_outbox_state_root IS ? "
            "AND chronik_context_json IS ? AND execution_backend=? AND systemd_scope=? "
            f"AND {argv_predicate} "
            f"AND state IN ({placeholders}) "
            "ORDER BY created_at_unix DESC, rowid DESC LIMIT ?",
            (
                identity["host"],
                identity["cwd"],
                _canonical_json(identity["resource_keys"]),
                identity["runtime_seconds"],
                identity["cpu_weight"],
                identity["io_weight"],
                identity["memory_max_bytes"],
                int(identity["chronik_outbox_enabled"]),
                identity["chronik_outbox_state_root"],
                (
                    _canonical_json(identity["chronik_context"])
                    if identity["chronik_context"] is not None
                    else None
                ),
                identity["execution_backend"],
                identity["systemd_scope"],
                *argv_parameters,
                *attention_states,
                scan_limit + 1,
            ),
        ).fetchall()
    if len(rows) > scan_limit:
        raise RuntimeError("matching managed Cargo attention scan limit exceeded")
    return [
        record
        for row in rows
        if _record_matches_unprepared_managed_cargo_command(
            record := dict(row), command
        )
    ]

def _guard_direct_terminal_retry_record(record: dict[str, Any] | None) -> None:
    if record is None:
        return
    state = str(record["state"])
    if state in UNCHANGED_RETRY_STATES:
        raise RuntimeError(
            "unchanged terminal task retry blocked; use "
            "grabowski_task_reconcile_resume for task "
            f"{record['task_id']} with a named state change"
        )
    if state in {"launching", "running", "outcome_unknown"}:
        pending_retry = _persisted_retry_binding_or_raise(record)
        pending_interrupted_recovery = (
            _persisted_interrupted_recovery_binding_or_raise(record)
        )
        if pending_retry is not None:
            raise RuntimeError(
                "unchanged task start blocked by unresolved retry successor; "
                f"reconcile task {record['task_id']} before another start"
            )
        if pending_interrupted_recovery is not None:
            raise RuntimeError(
                "unchanged task start blocked by unresolved recovery attempt; "
                f"reconcile task {record['task_id']} before another start"
            )


def _guard_unprepared_managed_cargo_retry(
    command: list[str],
    *,
    target: dict[str, Any],
    cwd: str,
    execution_backend: str,
    identity: dict[str, Any],
    retry_context: dict[str, Any] | None,
) -> None:
    local_systemd = (
        target["transport"] == "local" and execution_backend == "systemd-user"
    )
    request_root = _managed_cargo_request_root(
        command,
        target=target,
        cwd=cwd,
        execution_backend=execution_backend,
    )
    explicit_managed_target = (
        _explicit_managed_cargo_target_dir(command) if local_systemd else None
    )
    if request_root is None and explicit_managed_target is None:
        return
    if retry_context is None:
        latest = _latest_matching_unprepared_managed_cargo_record(identity, command)
        _guard_direct_terminal_retry_record(latest)
        latest_task_id = str(latest["task_id"]) if latest is not None else None
        for source in _matching_attention_unprepared_managed_cargo_records(
            identity, command
        ):
            if str(source["task_id"]) == latest_task_id:
                continue
            if _retained_retry_successor_for_source(str(source["task_id"])) is not None:
                continue
            _guard_direct_terminal_retry_record(source)
        return
    source_task_id = retry_context.get("source_task_id")
    if not isinstance(source_task_id, str):
        raise ValueError("terminal retry context source task is invalid")
    source = _row_raw(source_task_id)
    source_identity = _record_execution_identity(source)
    if _execution_identity_without_command(source_identity) != _execution_identity_without_command(
        identity
    ):
        raise ValueError("terminal retry context execution identity is stale")
    if not _record_matches_unprepared_managed_cargo_command(source, command):
        raise ValueError("terminal retry context command binding is stale")
    _guard_unchanged_terminal_retry(source_identity, retry_context)


def _guard_unchanged_terminal_retry(
    identity: dict[str, Any],
    retry_context: dict[str, Any] | None,
) -> dict[str, Any] | None:
    latest = _latest_matching_execution_record(identity)
    if retry_context is not None:
        source_task_id = retry_context.get("source_task_id")
        if not isinstance(source_task_id, str):
            raise ValueError("terminal retry context source task is invalid")
        source = _row_raw(source_task_id)
        source_identity = _record_execution_identity(source)
        if source_identity["identity_sha256"] != identity["identity_sha256"]:
            raise ValueError("terminal retry context execution identity is stale")
        _guard_linked_retry_successor(
            latest,
            source_task_id=str(source["task_id"]),
        )
        return _validate_terminal_retry_context(
            retry_context,
            predecessor=source,
            identity=identity,
        )

    _guard_direct_terminal_retry_record(latest)
    latest_task_id = str(latest["task_id"]) if latest is not None else None
    for source in _matching_attention_execution_records(identity):
        if str(source["task_id"]) == latest_task_id:
            continue
        if _retained_retry_successor_for_source(str(source["task_id"])) is not None:
            continue
        _guard_direct_terminal_retry_record(source)
    return None


def _task_lease_ttl(record: dict[str, Any], state: str) -> int:
    if state == "outcome_unknown":
        # Unknown root truth must remain protected long enough for operator
        # recovery, but the lease is still bounded and therefore not permanent.
        return resources.MAX_TTL_SECONDS
    return min(
        resources.MAX_TTL_SECONDS,
        max(
            resources.MIN_TTL_SECONDS,
            int(record["runtime_seconds"]) + 300,
        ),
    )


def _effective_observed_state(record: dict[str, Any], observed_state: str) -> str:
    """Preserve authoritative terminal truth before lease maintenance."""
    stored_state = str(record["state"])
    return stored_state if _is_terminal_state(stored_state) else observed_state


@_serialize_task_mutation
def _maintain_record_resources(
    record: dict[str, Any],
    state: str,
) -> dict[str, Any] | None:
    if state not in LEASE_MAINTENANCE_TASK_STATES:
        return None
    keys = _record_resource_keys(record)
    if not keys:
        return None
    owner = record.get("lease_owner_id") or _lease_owner(record["task_id"])
    ttl = _task_lease_ttl(record, state)
    try:
        renewed = resources.renew_resources(owner, keys, ttl_seconds=ttl)
        leases = renewed.get("leases", [])
        return {
            "maintained": True,
            "mode": "renewed",
            "expires_at_unix": (
                min(int(item["expires_at_unix"]) for item in leases)
                if leases
                else None
            ),
        }
    except (resources.ResourceLeaseMissing, resources.ResourceLeaseExpired):
        # A lease may be missing or have expired between observations. Reacquire
        # only when the resource is still free; a foreign owner remains a hard
        # conflict.
        try:
            repository_resource = _task_repository_resource(keys)
            implicit_workspace_resource = _record_implicit_workspace_resource(
                record, repository_resource
            )
            repository_scope_manifest = _record_repository_scope_manifest(
                record, repository_resource
            )
            acquired = resources.acquire_resources(
                owner,
                keys,
                purpose=f"persistent task {record['task_id']}",
                ttl_seconds=ttl,
                metadata=_task_lease_metadata(
                    task_id=str(record["task_id"]),
                    host=str(record["host"]),
                    attempt=int(record["attempt"]),
                    repository_resource=repository_resource,
                    implicit_workspace_resource=implicit_workspace_resource,
                    repository_scope_manifest=repository_scope_manifest,
                    recovered_after_expiry=True,
                ),
                _preserve_live_same_owner=True,
            )
        except Exception as exc:
            return {
                "maintained": False,
                "mode": "failed",
                "error": _redact_reason(f"{type(exc).__name__}: {exc}"),
            }
        return {
            "maintained": True,
            "mode": "reconciled" if acquired.get("preserved") else "reacquired",
            "expires_at_unix": acquired.get("expires_at_unix"),
        }
    except Exception as exc:
        # Ownership drift is evidence, not a reason to hide task status. Keep
        # the task observable and surface the lease failure explicitly.
        return {
            "maintained": False,
            "mode": "failed",
            "error": _redact_reason(f"{type(exc).__name__}: {exc}"),
        }


def _validate_command(argv: list[str]) -> list[str]:
    command = operator._validate_argv(argv, cwd=operator.HOME)
    if operator._redact_argv(command) != command:
        raise ValueError("Task argv appears to contain secret material")
    return command


def _resolve_task_dispatch_host(host: str) -> tuple[str, dict[str, Any], bool]:
    """Resolve one persisted task host, including the bounded legacy local alias."""
    try:
        return host, fleet.fleet_host(host), False
    except ValueError as exc:
        if host != "local" or str(exc) != f"Unknown fleet host: {host}":
            raise
        registered = fleet.load_fleet()
        local_hosts = [
            (name, candidate)
            for name, candidate in registered["hosts"].items()
            if candidate["enabled"]
            and candidate["transport"] == "local"
            and candidate["target"] == "local"
        ]
        if len(local_hosts) != 1:
            raise
        resolved_host, target = local_hosts[0]
        return resolved_host, target, True


def _dispatch(
    host: str,
    argv: list[str],
    *,
    timeout_seconds: int = 60,
    allow_legacy_local_alias: bool = False,
) -> dict[str, Any]:
    if allow_legacy_local_alias:
        resolved_host, target, legacy_local_alias = _resolve_task_dispatch_host(host)
    else:
        resolved_host, target, legacy_local_alias = host, fleet.fleet_host(host), False
    if target["transport"] == "local":
        result = operator._run(
            argv,
            cwd=operator.HOME,
            timeout_seconds=timeout_seconds,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    else:
        remote = fleet.run_fleet_host(
            resolved_host,
            argv,
            timeout_seconds=timeout_seconds,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
        result = remote["result"]
    if legacy_local_alias:
        result = dict(result)
        result["task_host_resolution"] = {
            "kind": "legacy-local-task-host-v1",
            "stored_host": host,
            "resolved_host": resolved_host,
            "transport": target["transport"],
        }
    return result


def _task_output_managed_from_attempt(record: dict[str, Any]) -> int | None:
    raw = record.get("launcher_json")
    if not isinstance(raw, str):
        return None
    try:
        launcher = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("task output launcher binding is invalid JSON") from exc
    if not isinstance(launcher, dict):
        raise RuntimeError("task output launcher binding must be an object")
    value = launcher.get(TASK_OUTPUT_LAUNCHER_BINDING_KEY)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuntimeError("task output managed-attempt binding is invalid")
    return value


def _task_output_root(record: dict[str, Any]) -> Path:
    attempt = record.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise RuntimeError("task output identity has invalid attempt")
    managed_from = _task_output_managed_from_attempt(record)
    root = (
        Path(TASK_OUTPUT_ROOT)
        if managed_from is not None and attempt >= managed_from
        else Path(TASK_OUTPUT_LEGACY_ROOT)
    )
    if not root.is_absolute():
        raise RuntimeError("task output root must be absolute")
    return root


def _task_output_contract_version(record: dict[str, Any]) -> int:
    attempt = record.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise RuntimeError("task output identity has invalid attempt")
    managed_from = _task_output_managed_from_attempt(record)
    return (
        TASK_OUTPUT_CONTRACT_VERSION
        if managed_from is not None and attempt >= managed_from
        else TASK_OUTPUT_LEGACY_CONTRACT_VERSION
    )


def _task_output_paths(record: dict[str, Any]) -> dict[str, Path]:
    task_id = str(record.get("task_id", ""))
    if TASK_ID.fullmatch(task_id) is None:
        raise RuntimeError("task output identity has invalid task_id")
    attempt = record.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise RuntimeError("task output identity has invalid attempt")
    root = _task_output_root(record)
    directory = root / f"{TASK_OUTPUT_DIRECTORY_PREFIX}-{task_id}-a{attempt}"
    return {
        "directory": directory,
        "stdout": directory / "stdout.log",
        "stderr": directory / "stderr.log",
    }


def _bind_task_output_managed_from_attempt(
    task_id: str, *, expected_attempt: int, managed_from_attempt: int
) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    if (
        isinstance(expected_attempt, bool)
        or not isinstance(expected_attempt, int)
        or expected_attempt < 1
        or isinstance(managed_from_attempt, bool)
        or not isinstance(managed_from_attempt, int)
        or managed_from_attempt < 1
    ):
        raise ValueError("task output managed-attempt binding is invalid")
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT attempt, launcher_json FROM tasks WHERE task_id=?",
            (identifier,),
        ).fetchone()
        if row is None:
            connection.rollback()
            raise ValueError(f"Unknown task: {identifier}")
        if int(row["attempt"]) != expected_attempt:
            connection.rollback()
            raise RuntimeError("task attempt changed before output-root binding")
        try:
            launcher = json.loads(str(row["launcher_json"]))
        except json.JSONDecodeError as exc:
            connection.rollback()
            raise RuntimeError("task output launcher binding is invalid JSON") from exc
        if not isinstance(launcher, dict):
            connection.rollback()
            raise RuntimeError("task output launcher binding must be an object")
        existing = launcher.get(TASK_OUTPUT_LAUNCHER_BINDING_KEY)
        created = False
        if existing is None:
            launcher[TASK_OUTPUT_LAUNCHER_BINDING_KEY] = managed_from_attempt
            connection.execute(
                "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                (_canonical_json(launcher), identifier),
            )
            connection.commit()
            created = True
        elif (
            isinstance(existing, bool)
            or not isinstance(existing, int)
            or existing < 1
        ):
            connection.rollback()
            raise RuntimeError("task output managed-attempt binding is invalid")
        elif existing == managed_from_attempt:
            connection.commit()
        else:
            connection.rollback()
            raise RuntimeError("task output managed-attempt binding conflicts with stored state")
    if created:
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "task-output-root-cutover-bind",
                "task_id": identifier,
                "previous_attempt": expected_attempt,
                "task_output_managed_from_attempt": managed_from_attempt,
                "output_contract_version": TASK_OUTPUT_CONTRACT_VERSION,
            }
        )
    return _row_raw(identifier)


def _task_output_capture_argv(record: dict[str, Any]) -> list[str]:
    command = json.loads(record["argv_json"])
    paths = _task_output_paths(record)
    return [
        TASK_OUTPUT_CAPTURE_PYTHON,
        "-c",
        TASK_OUTPUT_CAPTURE_CODE,
        str(paths["directory"]),
        str(TASK_OUTPUT_MAX_BYTES),
        str(TASK_OUTPUT_TAIL_BYTES),
        *command,
    ]


def _task_output_public_result(
    record: dict[str, Any],
    *,
    max_lines: int,
    stdout: str,
    stderr: str,
    stdout_truncated: bool,
    stderr_truncated: bool,
    duration_seconds: float,
    reader: str,
) -> dict[str, Any]:
    synthetic_argv = ["grabowski-task-output-files-v1", "--lines", str(max_lines)]
    paths = _task_output_paths(record)
    return {
        "argv": synthetic_argv,
        "argv_sha256": hashlib.sha256(
            _canonical_json(synthetic_argv).encode("utf-8")
        ).hexdigest(),
        "command": "grabowski-task-output-files-v1 --lines " + str(max_lines),
        "cwd": str(paths["directory"].parent),
        "returncode": 0,
        "timed_out": False,
        "duration_seconds": duration_seconds,
        "stdout": operator._redact(stdout),
        "stderr": operator._redact(stderr),
        "stdout_truncated": bool(stdout_truncated),
        "stderr_truncated": bool(stderr_truncated),
        "output_source": "private-task-files-v1",
        "output_reader": reader,
        "output_contract_version": _task_output_contract_version(record),
        "output_directory_sha256": hashlib.sha256(
            str(paths["directory"]).encode("utf-8")
        ).hexdigest(),
        "stdout_path_sha256": hashlib.sha256(
            str(paths["stdout"]).encode("utf-8")
        ).hexdigest(),
        "stderr_path_sha256": hashlib.sha256(
            str(paths["stderr"]).encode("utf-8")
        ).hexdigest(),
        "does_not_establish": [
            "same_uid_output_authenticity",
            "complete_output_beyond_stream_cap",
            "retention_or_archive_completion",
        ],
    }


def _task_output_tail_fd(descriptor: int, max_lines: int) -> tuple[str, bool]:
    metadata = os.fstat(descriptor)
    budget = int(operator.DEFAULT_OUTPUT_BYTES)
    end = int(metadata.st_size)
    start = max(0, end - budget)
    os.lseek(descriptor, start, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = end - start
    while remaining > 0:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    lines = data.splitlines(keepends=True)
    line_truncated = len(lines) > max_lines
    if line_truncated:
        data = b"".join(lines[-max_lines:])
    return data.decode("utf-8", errors="replace"), bool(start > 0 or line_truncated)


def _task_output_inode_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    )


def _ensure_local_task_output_root() -> None:
    root = Path(TASK_OUTPUT_ROOT)
    parent = root.parent
    if not root.is_absolute() or root == parent:
        raise RuntimeError("task output root is invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        parent_fd = os.open(parent, flags)
    except OSError as exc:
        raise RuntimeError("task output root parent could not be opened safely") from exc
    try:
        opened_parent = os.fstat(parent_fd)
        linked_parent = parent.lstat()
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or stat.S_ISLNK(linked_parent.st_mode)
            or _task_output_inode_identity(opened_parent)
            != _task_output_inode_identity(linked_parent)
            or opened_parent.st_uid != os.geteuid()
            or opened_parent.st_gid != os.getegid()
            or opened_parent.st_nlink < 1
            or (stat.S_IMODE(opened_parent.st_mode) & 0o022) != 0
        ):
            raise RuntimeError("task output root parent identity is unsafe")
        created = False
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        try:
            root_fd = os.open(root.name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise RuntimeError("task output root could not be opened safely") from exc
        try:
            opened_root = os.fstat(root_fd)
            linked_root = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or _task_output_inode_identity(opened_root)
                != _task_output_inode_identity(linked_root)
                or opened_root.st_uid != opened_parent.st_uid
                or opened_root.st_gid != opened_parent.st_gid
                or opened_root.st_nlink < 1
                or stat.S_IMODE(opened_root.st_mode) != 0o700
            ):
                raise RuntimeError("task output root identity is unsafe")
        finally:
            os.close(root_fd)
        if created:
            os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _open_local_task_output_root(root: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as exc:
        raise RuntimeError("task output parent could not be opened safely") from exc
    opened = os.fstat(descriptor)
    linked = root.lstat()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(linked.st_mode)
        or _task_output_inode_identity(opened)
        != _task_output_inode_identity(linked)
        or opened.st_uid != os.geteuid()
        or opened.st_gid != os.getegid()
        or opened.st_nlink < 1
        or (stat.S_IMODE(opened.st_mode) & 0o022) != 0
    ):
        os.close(descriptor)
        raise RuntimeError("task output parent identity is unsafe")
    return descriptor, opened


def _revalidate_local_task_output_root(
    root: Path, descriptor: int, original: os.stat_result
) -> None:
    current = os.fstat(descriptor)
    linked = root.lstat()
    if (
        _task_output_inode_identity(current)
        != _task_output_inode_identity(original)
        or _task_output_inode_identity(linked)
        != _task_output_inode_identity(original)
    ):
        raise RuntimeError("task output parent changed identity during read")


def _read_local_task_output_files(
    record: dict[str, Any], max_lines: int
) -> dict[str, Any] | None:
    started = time.monotonic()
    paths = _task_output_paths(record)
    root = paths["directory"].parent
    directory = paths["directory"]
    if directory.parent != root:
        raise RuntimeError("task output directory escaped its parent")
    if not root.exists():
        return None
    root_fd, opened_root = _open_local_task_output_root(root)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        try:
            directory_fd = os.open(
                directory.name, directory_flags, dir_fd=root_fd
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RuntimeError(
                "task output directory could not be opened safely"
            ) from exc
        try:
            opened_directory = os.fstat(directory_fd)
            linked_directory = os.stat(
                directory.name, dir_fd=root_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISDIR(opened_directory.st_mode)
                or _task_output_inode_identity(opened_directory)
                != _task_output_inode_identity(linked_directory)
                or opened_directory.st_uid != opened_root.st_uid
                or opened_directory.st_gid != opened_root.st_gid
                or stat.S_IMODE(opened_directory.st_mode) != 0o700
                or opened_directory.st_nlink < 1
            ):
                raise RuntimeError("task output directory identity is unsafe")
            captured: dict[str, tuple[str, bool]] = {}
            for stream in ("stdout", "stderr"):
                path = paths[stream]
                if path.parent != directory:
                    raise RuntimeError("task output path escaped its directory")
                flags = os.O_RDONLY | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(path.name, flags, dir_fd=directory_fd)
                except FileNotFoundError as exc:
                    raise RuntimeError(
                        f"task output contract is incomplete: missing {stream}"
                    ) from exc
                except OSError as exc:
                    raise RuntimeError(
                        f"task {stream} output could not be opened safely"
                    ) from exc
                try:
                    before = os.fstat(descriptor)
                    linked = os.stat(
                        path.name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or stat.S_IMODE(before.st_mode) != 0o600
                        or before.st_nlink != 1
                        or before.st_uid != opened_directory.st_uid
                        or before.st_gid != opened_directory.st_gid
                        or _task_output_inode_identity(before)
                        != _task_output_inode_identity(linked)
                    ):
                        raise RuntimeError(
                            f"task {stream} output identity is unsafe"
                        )
                    value = _task_output_tail_fd(descriptor, max_lines)
                    after = os.fstat(descriptor)
                    linked_after = os.stat(
                        path.name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        _task_output_inode_identity(after)
                        != _task_output_inode_identity(before)
                        or _task_output_inode_identity(linked_after)
                        != _task_output_inode_identity(before)
                    ):
                        raise RuntimeError(
                            f"task {stream} output changed identity during read"
                        )
                    captured[stream] = value
                finally:
                    os.close(descriptor)
            directory_after = os.fstat(directory_fd)
            linked_directory_after = os.stat(
                directory.name, dir_fd=root_fd, follow_symlinks=False
            )
            if (
                _task_output_inode_identity(directory_after)
                != _task_output_inode_identity(opened_directory)
                or _task_output_inode_identity(linked_directory_after)
                != _task_output_inode_identity(opened_directory)
            ):
                raise RuntimeError(
                    "task output directory changed identity during read"
                )
            _revalidate_local_task_output_root(root, root_fd, opened_root)
            return _task_output_public_result(
                record,
                max_lines=max_lines,
                stdout=captured["stdout"][0],
                stderr=captured["stderr"][0],
                stdout_truncated=captured["stdout"][1],
                stderr_truncated=captured["stderr"][1],
                duration_seconds=time.monotonic() - started,
                reader="local-descriptor-v1",
            )
        finally:
            os.close(directory_fd)
    finally:
        os.close(root_fd)


def _read_remote_task_output_stream(
    record: dict[str, Any], stream: str, max_lines: int
) -> tuple[str, bool] | None:
    if stream not in {"stdout", "stderr"}:
        raise ValueError("task output stream is invalid")
    paths = _task_output_paths(record)
    envelope = fleet.run_fleet_task_output_read(
        str(record["host"]),
        [
            TASK_OUTPUT_CAPTURE_PYTHON,
            "-c",
            TASK_OUTPUT_REMOTE_READ_CODE,
            str(paths["directory"]),
            paths[stream].name,
            str(max_lines),
            str(min(int(operator.DEFAULT_OUTPUT_BYTES) - 1024, 60 * 1024)),
        ],
        timeout_seconds=30,
        max_output_bytes=int(operator.DEFAULT_OUTPUT_BYTES),
    )
    result = envelope["result"]
    returncode = int(result.get("returncode", 1))
    diagnostic = str(result.get("stderr", ""))
    if returncode == 44 and "GRABOWSKI_TASK_OUTPUT_DIRECTORY_MISSING" in diagnostic:
        return None
    if returncode == 45 and "GRABOWSKI_TASK_OUTPUT_FILE_MISSING" in diagnostic:
        raise RuntimeError(f"remote task output contract is incomplete: missing {stream}")
    if returncode != 0:
        raise RuntimeError(f"remote task {stream} output read failed")
    marker = "GRABOWSKI_TASK_OUTPUT_READ_METADATA "
    metadata_lines = [
        line for line in diagnostic.splitlines() if line.startswith(marker)
    ]
    if len(metadata_lines) != 1:
        raise RuntimeError("remote task output read metadata is invalid")
    fields = {}
    for item in metadata_lines[0][len(marker):].split():
        if "=" not in item:
            raise RuntimeError("remote task output read metadata field is invalid")
        key, value = item.split("=", 1)
        fields[key] = value
    if set(fields) != {"byte_truncated", "line_truncated"}:
        raise RuntimeError("remote task output read metadata shape is invalid")
    if fields["byte_truncated"] not in {"0", "1"} or fields["line_truncated"] not in {"0", "1"}:
        raise RuntimeError("remote task output read metadata value is invalid")
    return (
        str(result.get("stdout", "")),
        bool(
            result.get("stdout_truncated")
            or fields["byte_truncated"] == "1"
            or fields["line_truncated"] == "1"
        ),
    )


def _read_remote_task_output_files(
    record: dict[str, Any], max_lines: int
) -> dict[str, Any] | None:
    started = time.monotonic()
    stdout = _read_remote_task_output_stream(record, "stdout", max_lines)
    if stdout is None:
        return None
    stderr = _read_remote_task_output_stream(record, "stderr", max_lines)
    if stderr is None:
        raise RuntimeError("remote task output contract disappeared during read")
    return _task_output_public_result(
        record,
        max_lines=max_lines,
        stdout=stdout[0],
        stderr=stderr[0],
        stdout_truncated=stdout[1],
        stderr_truncated=stderr[1],
        duration_seconds=time.monotonic() - started,
        reader="fleet-descriptor-v1",
    )


def _read_task_output_files(
    record: dict[str, Any], max_lines: int
) -> dict[str, Any] | None:
    target = fleet.fleet_host(str(record["host"]))
    if target["transport"] == "local":
        return _read_local_task_output_files(record, max_lines)
    return _read_remote_task_output_files(record, max_lines)


def _task_output_cleanup_argv(
    record: dict[str, Any],
    *,
    mode: str,
    token: str,
    inventory: dict[str, Any] | None = None,
) -> list[str]:
    paths = _task_output_paths(record)
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise ValueError("task output cleanup token must be a SHA-256 digest")
    if mode == "inspect":
        bindings = ["-", "-", "-1", "-1"]
    elif mode == "delete":
        if not isinstance(inventory, dict):
            raise ValueError("task output cleanup delete requires inventory")
        streams = inventory.get("streams")
        if not isinstance(streams, dict):
            raise ValueError("task output cleanup inventory streams are invalid")
        values: list[str] = []
        for stream in ("stdout", "stderr"):
            item = streams.get(stream)
            if not isinstance(item, dict):
                raise ValueError("task output cleanup inventory stream is invalid")
            sha256 = item.get("sha256")
            size = item.get("bytes")
            if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
                raise ValueError("task output cleanup inventory digest is invalid")
            if (
                not isinstance(size, int)
                or isinstance(size, bool)
                or not 0 <= size <= TASK_OUTPUT_MAX_BYTES
            ):
                raise ValueError("task output cleanup inventory size is invalid")
            values.extend([sha256, str(size)])
        bindings = [values[0], values[2], values[1], values[3]]
    else:
        raise ValueError("task output cleanup mode is invalid")
    return [
        TASK_OUTPUT_CAPTURE_PYTHON,
        "-c",
        TASK_OUTPUT_CLEANUP_CODE,
        mode,
        str(paths["directory"]),
        token,
        *bindings,
    ]


def _task_output_cleanup_run(
    record: dict[str, Any],
    *,
    mode: str,
    token: str,
    inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    command = _task_output_cleanup_argv(
        record, mode=mode, token=token, inventory=inventory
    )
    envelope = fleet.run_fleet_task_output_cleanup(
        str(record["host"]),
        command,
        timeout_seconds=30,
        max_output_bytes=int(operator.DEFAULT_OUTPUT_BYTES),
    )
    result = envelope.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("task output cleanup result is invalid")
    returncode = result.get("returncode")
    diagnostic = str(result.get("stderr", ""))
    if returncode == 44 and "GRABOWSKI_TASK_OUTPUT_DIRECTORY_MISSING" in diagnostic:
        return {
            "status": "missing",
            "mode": mode,
            "observer": envelope.get("observer"),
        }
    if returncode == 46 and "GRABOWSKI_TASK_OUTPUT_CLEANUP_STAGING_PRESENT" in diagnostic:
        return {
            "status": "staging_present",
            "mode": mode,
            "observer": envelope.get("observer"),
        }
    if returncode != 0:
        raise RuntimeError("task output cleanup command failed")
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > 64 * 1024:
        raise RuntimeError("task output cleanup payload is invalid")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("task output cleanup payload is not JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("task output cleanup payload must be an object")
    if payload.get("task_id") != record.get("task_id") or payload.get("attempt") != record.get("attempt"):
        raise RuntimeError("task output cleanup payload binding mismatch")
    if payload.get("directory") != str(_task_output_paths(record)["directory"]):
        raise RuntimeError("task output cleanup directory binding mismatch")
    expected_kind = (
        "grabowski_task_output_cleanup_inventory"
        if mode == "inspect"
        else "grabowski_task_output_cleanup_delete_result"
    )
    if payload.get("schema_version") != 1 or payload.get("kind") != expected_kind:
        raise RuntimeError("task output cleanup payload kind is invalid")
    if mode == "inspect":
        streams = payload.get("streams")
        if not isinstance(streams, dict) or set(streams) != {"stdout", "stderr"}:
            raise RuntimeError("task output cleanup inventory shape is invalid")
        for stream in ("stdout", "stderr"):
            item = streams.get(stream)
            if not isinstance(item, dict) or set(item) != {"sha256", "bytes", "mode", "nlink"}:
                raise RuntimeError("task output cleanup inventory stream shape is invalid")
            if (
                not isinstance(item.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                or not isinstance(item.get("bytes"), int)
                or isinstance(item.get("bytes"), bool)
                or not 0 <= item["bytes"] <= TASK_OUTPUT_MAX_BYTES
                or item.get("mode") != 0o600
                or item.get("nlink") != 1
            ):
                raise RuntimeError("task output cleanup inventory stream is invalid")
        return {
            "status": "present",
            "mode": mode,
            "inventory": payload,
            "observer": envelope.get("observer"),
            "code_sha256": envelope.get("cleanup_code_sha256"),
        }
    if payload.get("token") != token or payload.get("post_state") != "absent":
        raise RuntimeError("task output cleanup delete binding is invalid")
    if not isinstance(payload.get("removed"), list) or any(
        item not in {"stdout.log", "stderr.log"} for item in payload["removed"]
    ):
        raise RuntimeError("task output cleanup removed-set is invalid")
    return {
        "status": "deleted",
        "mode": mode,
        "delete_result": payload,
        "observer": envelope.get("observer"),
        "code_sha256": envelope.get("cleanup_code_sha256"),
    }


def _launch_argv(
    record: dict[str, Any], *, include_managed_runtime: bool
) -> list[str]:
    command = _task_output_capture_argv(record)
    unit = _authoritative_unit(record)
    argv = [
        "systemd-run",
        "--user",
        f"--description={operator._systemd_safe_description('task', unit, record['argv_sha256'])}",
        "--unit",
        unit,
        "--slice=grabowski-tasks.slice",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=LimitCORE=0",
        "--property=NoNewPrivileges=no",
        "--property=ProtectSystem=off",
        "--property=ProtectHome=no",
        "--property=PrivateTmp=no",
        "--property=MemoryDenyWriteExecute=no",
        "--property=UMask=0077",
        "--property=StandardOutput=null",
        "--property=StandardError=journal",
        f"--property=LogRateLimitIntervalSec={TASK_LOG_RATE_LIMIT_INTERVAL_SECONDS}s",
        f"--property=LogRateLimitBurst={TASK_LOG_RATE_LIMIT_BURST}",
        f"--property=RuntimeMaxSec={record['runtime_seconds']}s",
        f"--property=WorkingDirectory={record['cwd']}",
        f"--property=CPUWeight={record['cpu_weight']}",
        f"--property=IOWeight={record['io_weight']}",
    ]
    if record["memory_max_bytes"] is not None:
        argv.append(f"--property=MemoryMax={record['memory_max_bytes']}")
    try:
        persisted_command = json.loads(record["argv_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("stored task argv is invalid") from exc
    if (
        isinstance(persisted_command, list)
        and all(isinstance(item, str) for item in persisted_command)
        and bureau_runtime_refresh_executor.is_executor_module_command(persisted_command)
    ):
        executor_environment = bureau_runtime_refresh_executor.task_identity_environment(
            str(record["task_id"]), unit
        )
        argv.extend(
            f"--setenv={key}={value}" for key, value in executor_environment.items()
        )
    if include_managed_runtime:
        argv.extend(
            f"--setenv={key}={value}"
            for key, value in operator._managed_runtime_environment().items()
        )
    return [*argv, "--", *command_identity.systemd_escape_argv(command)]


def _root_task_start_payload(record: dict[str, Any]) -> dict[str, Any]:
    unit = _authoritative_unit(record)
    return {
        "operation": "start",
        "unit": unit,
        "argv": json.loads(record["argv_json"]),
        "cwd": record["cwd"],
        "runtime_seconds": int(record["runtime_seconds"]),
        "cpu_weight": int(record["cpu_weight"]),
        "io_weight": int(record["io_weight"]),
        "memory_max_bytes": record["memory_max_bytes"],
        "description": operator._systemd_safe_description(
            "task",
            unit,
            record["argv_sha256"],
        ),
    }


def _root_task_payload(record: dict[str, Any], operation: str, **extra: Any) -> dict[str, Any]:
    return {"operation": operation, "unit": _authoritative_unit(record), **extra}


def _launch(record: dict[str, Any]) -> dict[str, Any]:
    if _is_root_systemd_backend(record):
        try:
            return privileged.root_task_systemd_request(
                _root_task_start_payload(record),
                timeout_seconds=60,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            # These failures occur before a structured broker response exists:
            # broker readiness, local reference creation or client execution
            # failed, so no accepted root dispatch is evidenced. Mark the
            # attempt failed and release its resources instead of stranding a
            # launching record. Once the client has contacted the broker, its
            # timeout and malformed-response paths return outcome_unknown.
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": _redact_reason(f"{type(exc).__name__}: {exc}"),
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "root_truth_observable": False,
                "outcome_unknown": False,
                "launch_not_dispatched": True,
                "privileged_broker": None,
            }
    target = fleet.fleet_host(record["host"])
    return _dispatch(
        record["host"],
        _launch_argv(
            record,
            include_managed_runtime=target["transport"] == "local",
        ),
        timeout_seconds=60,
    )


def _launch_state(result: dict[str, Any]) -> str:
    if result.get("outcome_unknown"):
        return "outcome_unknown"
    return "running" if result["returncode"] == 0 else "failed"


def _row_raw(task_id: str) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    with _database_connection() as connection:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (identifier,)
        ).fetchone()
    if row is None:
        raise ValueError(f"Unknown task: {identifier}")
    return dict(row)


def _terminal_projection(
    record: dict[str, Any],
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
    unit: str | None = None,
    authoritative_unit: str | None = None,
    attempt: int | None = None,
) -> dict[str, Any]:
    return {
        "task_id": record["task_id"],
        "state": state,
        "updated_at_unix": _now(),
        "launcher_json": (
            record["launcher_json"]
            if launcher is None
            else _canonical_json(launcher)
        ),
        "last_observation_json": (
            record.get("last_observation_json")
            if observation is None
            else _canonical_json(observation)
        ),
        "unit": record["unit"] if unit is None else _validate_unit(unit),
        "authoritative_unit": (
            _authoritative_unit(record)
            if authoritative_unit is None
            else _validate_unit(authoritative_unit)
        ),
        "attempt": int(record["attempt"] if attempt is None else attempt),
    }


def _apply_terminalization_projection(
    terminalization: dict[str, Any], *, recovered: bool = False
) -> dict[str, Any]:
    projection = terminalization.get("task_projection")
    required = {
        "task_id", "state", "updated_at_unix", "launcher_json",
        "last_observation_json", "unit", "authoritative_unit", "attempt",
    }
    if not isinstance(projection, dict) or set(projection) != required:
        raise RuntimeError("Task terminalization projection is invalid")
    task_id = _validate_task_id(projection["task_id"])
    if task_id != terminalization.get("task_id"):
        raise RuntimeError("Task terminalization projection identity drift")
    state = projection["state"]
    if not _is_terminal_state(state) or state != terminalization.get("terminal_state"):
        raise RuntimeError("Task terminalization projection state drift")
    transition_sha256 = terminalization.get("transition_sha256")
    if not isinstance(transition_sha256, str) or SHA256.fullmatch(transition_sha256) is None:
        raise RuntimeError("Task terminalization digest is invalid")
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        current = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if current is None:
            connection.rollback()
            raise ValueError(f"Unknown task: {task_id}")
        current_record = dict(current)
        existing_digest = current_record.get("terminalization_sha256")
        if existing_digest not in {None, transition_sha256}:
            connection.rollback()
            raise RuntimeError("Task row is bound to another terminalization")
        if _is_terminal_state(current_record["state"]) and current_record["state"] != state:
            connection.rollback()
            raise RuntimeError("Task row terminal state conflicts with terminalization")
        connection.execute(
            """
            UPDATE tasks SET
                state=?, updated_at_unix=?, launcher_json=?,
                last_observation_json=?, unit=?, authoritative_unit=?, attempt=?,
                terminalization_sha256=?, terminalized_at_unix=?
            WHERE task_id=?
            """,
            (
                state,
                int(projection["updated_at_unix"]),
                str(projection["launcher_json"]),
                projection["last_observation_json"],
                _validate_unit(str(projection["unit"])),
                _validate_unit(str(projection["authoritative_unit"])),
                int(projection["attempt"]),
                transition_sha256,
                int(terminalization["leases_revoked_at_unix"]),
                task_id,
            ),
        )
        connection.commit()
    updated = _row_raw(task_id)
    observation = (
        json.loads(updated["last_observation_json"])
        if updated.get("last_observation_json")
        else None
    )
    receipt_sha256 = _write_outcome_receipt(
        updated,
        state,
        observation,
        terminalization=terminalization,
    )
    if receipt_sha256 is None:
        raise RuntimeError("Task lifecycle receipt was not emitted")
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT terminalization_sha256, lifecycle_receipt_sha256 "
            "FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None or row["terminalization_sha256"] != transition_sha256:
            connection.rollback()
            raise RuntimeError("Task terminalization projection changed before receipt binding")
        if row["lifecycle_receipt_sha256"] not in {None, receipt_sha256}:
            connection.rollback()
            raise RuntimeError("Task lifecycle receipt digest drift")
        connection.execute(
            "UPDATE tasks SET lifecycle_receipt_sha256=? WHERE task_id=?",
            (receipt_sha256, task_id),
        )
        connection.commit()
    reposkop_effectiveness.record_task_outcome(
        marker_root=TASK_OUTCOMES_DIR / ".reposkop-outcomes",
        attestation=_record_reposkop_execution_attestation(updated),
        task_id=task_id,
        terminal_state=state,
        lifecycle_receipt_sha256=receipt_sha256,
        terminalized_at_unix=int(updated["terminalized_at_unix"]),
        observation=observation,
    )
    resources.complete_task_terminalization(
        task_id,
        transition_sha256,
        receipt_sha256,
        recovered=recovered,
    )
    updated = _row_raw(task_id)
    chronik.record_task_state_safely(updated, state)
    if _record_reposkop_checkout_shadow_terminal_prepare(updated) is not None:
        try:
            _recover_reposkop_shadow_terminal(updated)
        except Exception:
            pass
    return updated


def _recover_task_terminalization(task_id: str) -> dict[str, Any] | None:
    identifier = _validate_task_id(task_id)
    transition = resources.task_terminalization_record(
        identifier, include_projection=True
    )
    if transition is not None:
        record = _row_raw(identifier)
        if (
            transition["phase"] != "projected"
            or record.get("terminalization_sha256") != transition["transition_sha256"]
            or record.get("lifecycle_receipt_sha256")
            != transition.get("lifecycle_receipt_sha256")
        ):
            return _apply_terminalization_projection(transition, recovered=True)
        if _record_reposkop_checkout_shadow_terminal_prepare(record) is not None:
            try:
                _recover_reposkop_shadow_terminal(record)
            except Exception:
                pass
        return record
    record = _row_raw(identifier)
    if not _is_terminal_state(str(record["state"])):
        return None
    projection = _terminal_projection(record, str(record["state"]))
    observation = (
        json.loads(record["last_observation_json"])
        if record.get("last_observation_json")
        else {}
    )
    transition = resources.begin_task_terminalization(
        identifier,
        int(record["attempt"]),
        record.get("lease_owner_id") or _lease_owner(identifier),
        str(record["state"]),
        _record_resource_keys(record),
        task_projection=projection,
        observation_sha256=_sha256_json(observation),
        recovery_status="recovered_legacy_row_first",
    )
    return _apply_terminalization_projection(transition, recovered=True)


def _terminalization_recovery_position(
    value: Any,
) -> tuple[int, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"prepared_at_unix", "task_id"}
        or isinstance(value["prepared_at_unix"], bool)
        or not isinstance(value["prepared_at_unix"], int)
        or value["prepared_at_unix"] < 0
        or not isinstance(value["task_id"], str)
        or TASK_ID.fullmatch(value["task_id"]) is None
    ):
        raise RuntimeError("Task terminalization recovery cursor metadata is invalid")
    return int(value["prepared_at_unix"]), str(value["task_id"])


def _load_terminalization_recovery_cycle() -> dict[str, Any] | None:
    with _database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,),
        ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(str(row[0]))
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Task terminalization recovery cursor metadata is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "high_water", "cursor"}
        or payload["version"] != TASK_TERMINALIZATION_RECOVERY_CURSOR_VERSION
    ):
        raise RuntimeError("Task terminalization recovery cursor metadata is invalid")
    high_water = _terminalization_recovery_position(payload["high_water"])
    cursor = _terminalization_recovery_position(payload["cursor"])
    if cursor > high_water:
        raise RuntimeError(
            "Task terminalization recovery cursor metadata is inconsistent"
        )
    return {
        "version": TASK_TERMINALIZATION_RECOVERY_CURSOR_VERSION,
        "high_water": high_water,
        "cursor": cursor,
    }


def _save_terminalization_recovery_cycle(
    cycle: dict[str, Any] | None,
) -> None:
    with _database_connection() as connection:
        if cycle is None:
            connection.execute(
                "DELETE FROM metadata WHERE key=?",
                (TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,),
            )
            return
        high_water = cycle["high_water"]
        cursor = cycle["cursor"]
        payload = _canonical_json(
            {
                "version": TASK_TERMINALIZATION_RECOVERY_CURSOR_VERSION,
                "high_water": {
                    "prepared_at_unix": high_water[0],
                    "task_id": high_water[1],
                },
                "cursor": {
                    "prepared_at_unix": cursor[0],
                    "task_id": cursor[1],
                },
            }
        )
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY, payload),
        )


def _validate_terminalization_recovery_page(
    page: dict[str, Any],
    *,
    cursor_before: tuple[int, str] | None,
    high_water: tuple[int, str] | None,
) -> None:
    page_high_water = page.get("high_water")
    cursor_after = page.get("cursor_after")
    cycle_completed = page.get("cycle_completed")
    if (
        page.get("cursor_before") != cursor_before
        or (
            high_water is not None
            and page_high_water != high_water
        )
        or not isinstance(cycle_completed, bool)
    ):
        raise RuntimeError("Task terminalization recovery page is inconsistent")
    for field, value in (
        ("high_water", page_high_water),
        ("cursor_after", cursor_after),
    ):
        if value is None:
            continue
        try:
            resources._task_terminalization_cursor(value, field=field)
        except ValueError as exc:
            raise RuntimeError(
                "Task terminalization recovery page is inconsistent"
            ) from exc
    if (
        cursor_before is not None
        and page_high_water is not None
        and cursor_before > page_high_water
    ):
        raise RuntimeError("Task terminalization recovery page is inconsistent")
    if cursor_after is not None and (
        page_high_water is None
        or cursor_after > page_high_water
        or (
            cursor_before is not None
            and cursor_after <= cursor_before
        )
    ):
        raise RuntimeError("Task terminalization recovery page is inconsistent")
    if cycle_completed:
        if cursor_after is not None:
            raise RuntimeError(
                "Task terminalization recovery page is inconsistent"
            )
    elif page_high_water is None or cursor_after is None:
        raise RuntimeError("Task terminalization recovery page is inconsistent")


@_serialize_task_mutation
def _recover_pending_task_terminalizations(
    *,
    limit: int = DEFAULT_TASK_RECONCILE_BATCH_SIZE,
) -> dict[str, Any]:
    bounded_limit = _validate_reconcile_phase_limit(limit)
    cycle = _load_terminalization_recovery_cycle()
    cursor_before = None if cycle is None else cycle["cursor"]
    high_water = None if cycle is None else cycle["high_water"]
    if bounded_limit == 0:
        return {
            "limit": 0,
            "examined": 0,
            "recovered": [],
            "failed": [],
            "cursor_before": cursor_before,
            "cursor_after": cursor_before,
            "cycle_high_water": high_water,
            "cycle_completed": False,
        }
    page = resources.pending_task_terminalizations(
        limit=bounded_limit,
        cursor=cursor_before,
        high_water=high_water,
    )
    _validate_terminalization_recovery_page(
        page,
        cursor_before=cursor_before,
        high_water=high_water,
    )
    recovered: list[str] = []
    failed: list[dict[str, str]] = []
    for terminalization in page["terminalizations"]:
        task_id = str(terminalization["task_id"])
        try:
            updated = _apply_terminalization_projection(
                terminalization,
                recovered=True,
            )
        except Exception as exc:
            failed.append(
                {
                    "task_id": task_id,
                    "error_type": type(exc).__name__,
                    "reason": _redact_reason(str(exc)),
                }
            )
            continue
        recovered.append(str(updated["task_id"]))
    cycle_after = None
    if not page["cycle_completed"]:
        if page["high_water"] is None or page["cursor_after"] is None:
            raise RuntimeError("Task terminalization recovery page is inconsistent")
        cycle_after = {
            "version": TASK_TERMINALIZATION_RECOVERY_CURSOR_VERSION,
            "high_water": page["high_water"],
            "cursor": page["cursor_after"],
        }
    _save_terminalization_recovery_cycle(cycle_after)
    return {
        "limit": bounded_limit,
        "examined": int(page["examined"]),
        "recovered": recovered,
        "failed": failed,
        "cursor_before": cursor_before,
        "cursor_after": page["cursor_after"],
        "cycle_high_water": page["high_water"],
        "cycle_completed": bool(page["cycle_completed"]),
    }


@_serialize_task_mutation
def _row(task_id: str) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    recovered = _recover_task_terminalization(identifier)
    return recovered if recovered is not None else _row_raw(identifier)

def _task_systemd_unit_health(
    state: str,
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    if state not in TASK_STATE_PROJECTIONS["active"]:
        return {"status": "not_applicable"}
    if not isinstance(observation, dict):
        return {"status": "unknown", "reason": "missing_observation"}
    properties = observation.get("properties")
    if not isinstance(properties, dict):
        return {"status": "unknown", "reason": "missing_systemd_properties"}
    observed_at = observation.get("observed_at_unix")
    now = _now()
    if (
        isinstance(observed_at, bool)
        or not isinstance(observed_at, int)
        or observed_at < 0
        or not 0 <= now - observed_at <= TASK_ACTIVE_OBSERVATION_MAX_AGE_SECONDS
    ):
        return {
            "status": "unknown",
            "reason": "stale_or_invalid_systemd_observation",
            "observed_at_unix": observed_at,
        }
    load_state = properties.get("LoadState")
    health = {
        "load_state": load_state,
        "active_state": properties.get("ActiveState"),
        "sub_state": properties.get("SubState"),
    }
    if load_state == "bad-setting":
        return {
            "status": "degraded",
            "reason": "systemd_load_state_bad_setting",
            **health,
            "does_not_establish": [
                "task_process_inactive",
                "task_outcome_failure",
            ],
        }
    if load_state == "loaded":
        return {"status": "nominal", **health}
    return {"status": "unknown", "reason": "unexpected_systemd_load_state", **health}


def _public(record: dict[str, Any]) -> dict[str, Any]:
    last_observation = (
        json.loads(record["last_observation_json"])
        if record["last_observation_json"]
        else None
    )
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "attempt": record["attempt"],
        "state": record["state"],
        "resume_policy": record["resume_policy"],
        "argv": operator._redact_argv(json.loads(record["argv_json"])),
        "argv_sha256": record["argv_sha256"],
        "cwd": record["cwd"],
        "runtime_seconds": record["runtime_seconds"],
        "cpu_weight": record["cpu_weight"],
        "io_weight": record["io_weight"],
        "memory_max_bytes": record["memory_max_bytes"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "launcher": json.loads(record["launcher_json"]),
        "last_observation": last_observation,
        "systemd_unit_health": _task_systemd_unit_health(
            str(record["state"]), last_observation
        ),
        "resource_keys": _record_resource_keys(record),
        "lease_owner_id": record.get("lease_owner_id"),
        "chronik_outbox_enabled": bool(record.get("chronik_outbox_enabled")),
        "chronik_outbox_state_root": record.get("chronik_outbox_state_root"),
        "chronik_context": json.loads(record["chronik_context_json"]) if record.get("chronik_context_json") else None,
        "terminalization_sha256": record.get("terminalization_sha256"),
        "terminalized_at_unix": record.get("terminalized_at_unix"),
        "lifecycle_receipt_sha256": record.get("lifecycle_receipt_sha256"),
    }


@contextmanager
def _database_connection() -> Iterator[sqlite3.Connection]:
    connection = _database()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


@contextmanager
def _task_read_snapshot() -> Iterator[sqlite3.Connection]:
    connection = _database()
    try:
        connection.execute("BEGIN DEFERRED")
        yield connection
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def _task_filter_states(state: str | None) -> tuple[str, ...] | None:
    if state is None:
        return None
    if state in TASK_STATES:
        return (state,)
    projection = TASK_STATE_PROJECTIONS.get(state)
    if projection is None:
        allowed = sorted(TASK_STATES | set(TASK_STATE_PROJECTIONS))
        raise ValueError(f"state must be one of {allowed}")
    return projection


def _task_state_counts(
    connection: sqlite3.Connection,
) -> tuple[dict[str, int], dict[str, int], int]:
    rows = connection.execute(
        "SELECT state, COUNT(*) AS count FROM tasks GROUP BY state"
    ).fetchall()
    exact = {state: 0 for state in sorted(TASK_STATES)}
    unknown_state_count = 0
    for row in rows:
        state = str(row["state"])
        count = int(row["count"])
        if state in exact:
            exact[state] = count
        else:
            unknown_state_count += count
    projections = {
        name: sum(exact[state] for state in states)
        for name, states in sorted(TASK_STATE_PROJECTIONS.items())
    }
    return exact, projections, unknown_state_count


def _task_archive_payload_sha256(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError("Stored task archive payload is not text")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _task_archive_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return the stable, redaction-independent record bound into task archives."""
    return {
        "schema_version": 1,
        "kind": "grabowski_task_archive_record",
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": record.get("authoritative_unit") or record["unit"],
        "execution_backend": record.get("execution_backend") or "systemd-user",
        "systemd_scope": record.get("systemd_scope") or "user",
        "attempt": int(record["attempt"]),
        "state": record["state"],
        "resume_policy": record["resume_policy"],
        "argv_sha256": record["argv_sha256"],
        "cwd": record["cwd"],
        "runtime_seconds": int(record["runtime_seconds"]),
        "cpu_weight": int(record["cpu_weight"]),
        "io_weight": int(record["io_weight"]),
        "memory_max_bytes": record.get("memory_max_bytes"),
        "created_at_unix": int(record["created_at_unix"]),
        "updated_at_unix": int(record["updated_at_unix"]),
        "launcher_sha256": _task_archive_payload_sha256(record["launcher_json"]),
        "last_observation_sha256": _task_archive_payload_sha256(
            record.get("last_observation_json")
        ),
        "resource_keys_sha256": _task_archive_payload_sha256(
            record.get("resource_keys_json") or "[]"
        ),
        "lease_owner_id": record.get("lease_owner_id"),
        "request_id": record.get("request_id"),
        "origin_ref": record.get("origin_ref"),
        "external_run_id": record.get("external_run_id"),
        "execution_envelope_sha256": record.get("execution_envelope_sha256"),
        "acceptance_sha256": _task_archive_payload_sha256(
            record.get("acceptance_json") or "[]"
        ),
        "request_sha256": record.get("request_sha256"),
        "chronik_outbox_enabled": bool(record.get("chronik_outbox_enabled")),
        "chronik_outbox_state_root": record.get("chronik_outbox_state_root"),
        "chronik_context_sha256": _task_archive_payload_sha256(
            record.get("chronik_context_json")
        ),
        "terminalization_sha256": record.get("terminalization_sha256"),
        "terminalized_at_unix": record.get("terminalized_at_unix"),
        "lifecycle_receipt_sha256": record.get("lifecycle_receipt_sha256"),
        "repository_scope_manifest_sha256": _task_archive_payload_sha256(
            record.get("repository_scope_manifest_json")
        ),
    }


def _task_archive_root() -> Path:
    configured = os.environ.get("GRABOWSKI_TASK_ARCHIVE_ROOT")
    return (
        Path(configured).expanduser()
        if configured
        else TASK_DB.parent / "task-archives"
    )


def _task_projection_root() -> Path:
    configured = os.environ.get("GRABOWSKI_TASK_PROJECTION_ROOT")
    return (
        Path(configured).expanduser()
        if configured
        else TASK_DB.parent / "task-projection"
    )


def _task_current_projection() -> dict[str, Any]:
    return lifecycle_projection.load_task_archive_projection(
        projection_root=_task_projection_root(),
        archive_root=_task_archive_root(),
    )


def _projected_task_state_counts(
    connection: sqlite3.Connection,
    projection: dict[str, Any],
) -> tuple[dict[str, int], int]:
    bindings = projection.get("archived_task_bindings")
    if not isinstance(bindings, dict):
        raise lifecycle_projection.LifecycleProjectionIntegrityError(
            "current task projection bindings are invalid"
        )
    exact = {state: 0 for state in sorted(TASK_STATES)}
    unknown_state_count = 0
    for task_id in sorted(bindings):
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise lifecycle_projection.LifecycleProjectionIntegrityError(
                f"projected task row is missing from current store: {task_id}"
            )
        raw = dict(row)
        archive_record = _task_archive_record(raw)
        if lifecycle_projection.bounded_current_task_projection(
            [archive_record],
            projection=projection,
        ):
            raise lifecycle_projection.LifecycleProjectionIntegrityError(
                f"projected task unexpectedly remains current: {task_id}"
            )
        state = str(raw["state"])
        if state in exact:
            exact[state] += 1
        else:
            unknown_state_count += 1
    return exact, unknown_state_count


def _subtract_projected_task_counts(
    exact: dict[str, int],
    unknown_state_count: int,
    projected_exact: dict[str, int],
    projected_unknown_state_count: int,
) -> tuple[dict[str, int], dict[str, int], int]:
    current_exact: dict[str, int] = {}
    for state in sorted(TASK_STATES):
        remaining = exact[state] - projected_exact[state]
        if remaining < 0:
            raise lifecycle_projection.LifecycleProjectionIntegrityError(
                f"projected task count exceeds stored state count: {state}"
            )
        current_exact[state] = remaining
    current_unknown = unknown_state_count - projected_unknown_state_count
    if current_unknown < 0:
        raise lifecycle_projection.LifecycleProjectionIntegrityError(
            "projected unknown task count exceeds stored unknown state count"
        )
    current_projections = {
        name: sum(current_exact[state] for state in states)
        for name, states in sorted(TASK_STATE_PROJECTIONS.items())
    }
    return current_exact, current_projections, current_unknown


def _task_current_records_for_states(
    connection: sqlite3.Connection,
    *,
    states: tuple[str, ...],
    projection: dict[str, Any],
) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in states)
    rows = connection.execute(
        f"SELECT * FROM tasks WHERE state IN ({placeholders}) "
        "ORDER BY created_at_unix DESC, task_id DESC",
        states,
    ).fetchall()
    raw_records = [dict(row) for row in rows]
    archive_records = [_task_archive_record(record) for record in raw_records]
    current_archive_records = lifecycle_projection.bounded_current_task_projection(
        archive_records,
        projection=projection,
    )
    current_task_ids = {str(record["task_id"]) for record in current_archive_records}
    return [
        record
        for record in raw_records
        if str(record["task_id"]) in current_task_ids
    ]


def _task_retry_successor_records(
    connection: sqlite3.Connection,
    *,
    source_task_ids: set[str],
    limit: int,
) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("retry successor limit must be a non-negative integer")
    if not isinstance(source_task_ids, set) or any(
        not isinstance(task_id, str)
        or terminal_convergence.TASK_ID_RE.fullmatch(task_id) is None
        for task_id in source_task_ids
    ):
        raise ValueError("retry successor source task ids must be a set of task ids")
    if not source_task_ids:
        return []
    support_states = tuple(
        sorted(terminal_convergence.RETRY_SUCCESSOR_SUPPORT_STATES)
    )
    placeholders = ",".join("?" for _ in support_states)
    rows = connection.execute(
        f"SELECT * FROM tasks WHERE state IN ({placeholders}) "
        "AND ("
        "(json_valid(launcher_json) "
        "AND json_type(launcher_json, '$.retry_binding.source_task_id') = 'text' "
        "AND json_extract(launcher_json, '$.retry_binding.source_task_id') "
        "IN (SELECT value FROM json_each(?))) "
        "OR (NOT json_valid(launcher_json) AND instr(launcher_json, ?) > 0)"
        ") "
        "ORDER BY created_at_unix DESC, rowid DESC LIMIT ?",
        (
            *support_states,
            _canonical_json(sorted(source_task_ids)),
            '"retry_binding"',
            limit + 1,
        ),
    ).fetchall()
    if len(rows) > limit:
        raise RuntimeError("retry successor convergence scan limit exceeded")
    records: list[dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        binding = terminal_convergence.persisted_retry_binding(record)
        if binding is not None:
            records.append(record)
    return records


def _task_attention_projection_not_evaluated(
    raw_attention_count: int,
) -> dict[str, Any]:
    if (
        isinstance(raw_attention_count, bool)
        or not isinstance(raw_attention_count, int)
        or raw_attention_count < 0
    ):
        raise ValueError("raw attention count must be a non-negative integer")
    return {
        "status": "not_evaluated",
        "evidence_error": None,
        "projection_sha256": _sha256_json(
            {
                "schema_version": 1,
                "status": "not_evaluated",
                "raw_attention_count": raw_attention_count,
                "scope": "non_attention_filtered_task_list",
            }
        ),
        "raw_attention_count": raw_attention_count,
        "current_attention_count": None,
        "excluded_attention_count": None,
        "excluded_classification_counts": {},
        "decision_candidate_count": None,
        "decision_classification_counts": {},
        "retry_successor_record_count": None,
        "scope": "non_attention_filtered_task_list",
        "raw_scope": "current_task_projection_before_attention_decisions",
    }


def _task_attention_projection(
    connection: sqlite3.Connection,
    projection: dict[str, Any],
    *,
    decision_snapshot: dict[str, str | None] | None = None,
) -> tuple[dict[str, Any], set[str]]:
    import grabowski_task_attention as task_attention

    records = _task_current_records_for_states(
        connection,
        states=TASK_STATE_PROJECTIONS["attention"],
        projection=projection,
    )

    def degraded(error_name: str) -> tuple[dict[str, Any], set[str]]:
        raw_bindings = [
            {
                "task_id": str(record["task_id"]),
                "attempt": int(record["attempt"]),
                "state": str(record["state"]),
                "updated_at_unix": int(record["updated_at_unix"]),
            }
            for record in records
        ]
        return (
            {
                "status": "degraded",
                "evidence_error": error_name,
                "projection_sha256": _sha256_json(
                    {
                        "schema_version": 1,
                        "status": "degraded",
                        "evidence_error": error_name,
                        "task_bindings": raw_bindings,
                    }
                ),
                "raw_attention_count": len(records),
                "current_attention_count": len(records),
                "excluded_attention_count": 0,
                "excluded_classification_counts": {},
                "decision_candidate_count": None,
                "decision_classification_counts": {},
                "retry_successor_record_count": 0,
                "scope": "current_task_projection_after_valid_attention_decisions",
                "raw_scope": "current_task_projection_before_attention_decisions",
            },
            set(),
        )

    snapshot_status = (decision_snapshot or {}).get("status", "locked")
    snapshot_error = (decision_snapshot or {}).get("evidence_error")
    if snapshot_status == "degraded":
        return degraded(str(snapshot_error or "TaskAttentionDecisionSnapshotError"))
    try:
        if len(records) > task_attention.MAX_CURRENT_CONVERGENCE_ROWS:
            return degraded("attention_convergence_scan_limit_exceeded")
        retry_successors = _task_retry_successor_records(
            connection,
            source_task_ids={str(record["task_id"]) for record in records},
            limit=(
                task_attention.MAX_CURRENT_CONVERGENCE_ROWS - len(records)
            ),
        )
        projected = task_attention.current_attention_projection(
            records,
            include_decisions=snapshot_status != "absent",
            retry_successor_records=retry_successors,
        )
    except terminal_convergence.TerminalConvergenceError:
        return degraded("TaskAttentionIntegrityError")
    except (
        task_attention.TaskAttentionError,
        task_attention.TaskAttentionInputError,
        RuntimeError,
        OSError,
    ) as exc:
        error = (
            str(exc) or type(exc).__name__
            if type(exc) is RuntimeError
            else type(exc).__name__
        )
        return degraded(error)
    excluded_task_ids = set(projected["excluded_task_ids"])
    public_projection = {
        key: value
        for key, value in projected.items()
        if key
        not in {
            "excluded_task_ids",
            "convergence_excluded_task_ids",
            "decision_excluded_task_ids",
        }
    }
    return public_projection, excluded_task_ids


def _task_list_current_rows(
    connection: sqlite3.Connection,
    *,
    where: list[str],
    parameters: list[Any],
    cursor_created_at: int | None,
    cursor_task_id: str | None,
    limit: int,
    projection: dict[str, Any],
    excluded_task_ids: set[str] | None = None,
) -> list[sqlite3.Row]:
    selected: list[sqlite3.Row] = []
    scan_created_at = cursor_created_at
    scan_task_id = cursor_task_id
    batch_limit = max(TASK_LIST_SCAN_BATCH, limit + 1)
    while len(selected) < limit + 1:
        scan_where = list(where)
        scan_parameters = list(parameters)
        if scan_created_at is not None and scan_task_id is not None:
            scan_where.append(
                "(created_at_unix < ? OR (created_at_unix = ? AND task_id < ?))"
            )
            scan_parameters.extend([scan_created_at, scan_created_at, scan_task_id])
        where_sql = f" WHERE {' AND '.join(scan_where)}" if scan_where else ""
        rows = connection.execute(
            f"SELECT * FROM tasks{where_sql} "
            "ORDER BY created_at_unix DESC, task_id DESC LIMIT ?",
            (*scan_parameters, batch_limit),
        ).fetchall()
        if not rows:
            break
        for row in rows:
            archive_record = _task_archive_record(dict(row))
            current = lifecycle_projection.bounded_current_task_projection(
                [archive_record],
                projection=projection,
            )
            if current and (
                excluded_task_ids is None
                or str(row["task_id"]) not in excluded_task_ids
            ):
                selected.append(row)
                if len(selected) >= limit + 1:
                    break
        if len(selected) >= limit + 1 or len(rows) < batch_limit:
            break
        last = rows[-1]
        scan_created_at = int(last["created_at_unix"])
        scan_task_id = str(last["task_id"])
    return selected


def _task_recommended_next_action(
    state: str,
    *,
    systemd_unit_health: dict[str, Any] | None = None,
) -> str:
    if (
        state in {"launching", "running"}
        and isinstance(systemd_unit_health, dict)
        and systemd_unit_health.get("status") == "degraded"
    ):
        return (
            "inspect degraded systemd unit configuration before relying on "
            "active task continuity"
        )
    if state in {"launching", "running"}:
        return "read grabowski_task_status before deciding the next action"
    if state == "interrupted":
        return "run grabowski_task_reconcile_check and read current status before any retry"
    if state == "outcome_unknown":
        return "reconcile and read post-state before any unchanged retry"
    if state in {"failed", "timed_out", "signalled"}:
        return "inspect bounded task logs and recovery evidence"
    if state == "completed":
        return "consume the outcome receipt and close external bookkeeping"
    if state == "cancelled":
        return "confirm resource release and retained evidence"
    return "inspect task status"


def _public_for_view(record: dict[str, Any], view: str) -> dict[str, Any]:
    full = _public(record)
    if view == "evidence":
        return full
    minimal = {
        "task_id": full["task_id"],
        "host": full["host"],
        "unit": full["unit"],
        "authoritative_unit": full["authoritative_unit"],
        "execution_backend": full["execution_backend"],
        "systemd_scope": full["systemd_scope"],
        "attempt": full["attempt"],
        "state": full["state"],
        "resume_policy": full["resume_policy"],
        "argv_sha256": full["argv_sha256"],
        "created_at_unix": full["created_at_unix"],
        "updated_at_unix": full["updated_at_unix"],
        "resource_keys": full["resource_keys"],
        "systemd_unit_health": full["systemd_unit_health"],
        "recommended_next_action": _task_recommended_next_action(
            full["state"], systemd_unit_health=full["systemd_unit_health"]
        ),
    }
    if view == "standard":
        minimal.update({
            "argv": full["argv"],
            "cwd": full["cwd"],
            "runtime_seconds": full["runtime_seconds"],
            "memory_max_bytes": full["memory_max_bytes"],
            "last_observation": full["last_observation"],
            "lease_owner_id": full["lease_owner_id"],
            "chronik_outbox_enabled": full["chronik_outbox_enabled"],
        })
    return minimal


@_serialize_task_mutation
def _set_state(
    task_id: str,
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
    unit: str | None = None,
    authoritative_unit: str | None = None,
    attempt: int | None = None,
) -> dict[str, Any]:
    if state not in TASK_STATES:
        raise ValueError("Invalid task state")
    identifier = _validate_task_id(task_id)
    current = _row_raw(identifier)
    existing_terminalization = resources.task_terminalization_record(
        identifier, include_projection=True
    )
    if existing_terminalization is not None:
        return _apply_terminalization_projection(
            existing_terminalization,
            recovered=existing_terminalization["phase"] != "projected",
        )
    if _is_terminal_state(current["state"]):
        recovered = _recover_task_terminalization(identifier)
        return recovered if recovered is not None else _row_raw(identifier)
    if _is_terminal_state(state):
        projection_launcher = launcher
        selected_launcher = (
            dict(launcher)
            if launcher is not None
            else json.loads(str(current["launcher_json"]))
        )
        shadow_record = {
            **current,
            "launcher_json": _canonical_json(selected_launcher),
        }
        before_shadow = _record_reposkop_checkout_shadow_before(shadow_record)
        if before_shadow is not None:
            prepared_shadow = _prepare_reposkop_shadow_terminal_best_effort(
                task_id=identifier,
                before_summary=before_shadow,
            )
            selected_launcher[
                "reposkop_checkout_shadow_terminal_prepare"
            ] = prepared_shadow
            projection_launcher = selected_launcher
        projection = _terminal_projection(
            current,
            state,
            launcher=projection_launcher,
            observation=observation,
            unit=unit,
            authoritative_unit=authoritative_unit,
            attempt=attempt,
        )
        observation_material = observation
        if observation_material is None:
            observation_material = (
                json.loads(current["last_observation_json"])
                if current.get("last_observation_json")
                else {}
            )
        terminalization = resources.begin_task_terminalization(
            identifier,
            int(projection["attempt"]),
            current.get("lease_owner_id") or _lease_owner(identifier),
            state,
            _record_resource_keys(current),
            task_projection=projection,
            observation_sha256=_sha256_json(observation_material),
        )
        return _apply_terminalization_projection(terminalization)
    updates = ["state=?", "updated_at_unix=?"]
    values: list[Any] = [state, _now()]
    if launcher is not None:
        updates.append("launcher_json=?")
        values.append(_canonical_json(launcher))
    if observation is not None:
        updates.append("last_observation_json=?")
        values.append(_canonical_json(observation))
    if unit is not None:
        updates.append("unit=?")
        values.append(_validate_unit(unit))
    if authoritative_unit is not None:
        updates.append("authoritative_unit=?")
        values.append(_validate_unit(authoritative_unit))
    if attempt is not None:
        updates.append("attempt=?")
        values.append(attempt)
    values.append(identifier)
    with _database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        current_row = connection.execute(
            "SELECT state, terminalization_sha256 FROM tasks WHERE task_id=?",
            (identifier,),
        ).fetchone()
        if current_row is None:
            connection.rollback()
            raise ValueError(f"Unknown task: {identifier}")
        if current_row["terminalization_sha256"] is not None or _is_terminal_state(
            current_row["state"]
        ):
            connection.rollback()
            recovered = _recover_task_terminalization(identifier)
            return recovered if recovered is not None else _row_raw(identifier)
        connection.execute(
            f"UPDATE tasks SET {', '.join(updates)} WHERE task_id=?",
            values,
        )
        connection.commit()
    updated = _row_raw(identifier)
    chronik.record_task_state_safely(updated, state)
    return updated

def _observe(record: dict[str, Any]) -> dict[str, Any]:
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(
                record,
                "show",
                properties=list(fleet.TASK_UNIT_SHOW_PROPERTIES),
            ),
            timeout_seconds=30,
            max_output_bytes=8192,
        )
        observer: dict[str, Any] = {
            "kind": "root-systemd-broker-show-v1",
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
        }
        properties: dict[str, str] = {}
        for line in result.get("stdout", "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        state = "outcome_unknown" if result.get("outcome_unknown") else _classify_observation(result, properties)
        return {
            "state": state,
            "properties": properties,
            "probe": result,
            "observer": observer,
            "observed_at_unix": _now(),
        }

    command = [
        "systemctl",
        "--user",
        "show",
        _authoritative_unit(record),
        "--no-pager",
    ]
    command.extend(f"--property={item}" for item in fleet.TASK_UNIT_SHOW_PROPERTIES)
    observer: dict[str, Any] = {
        "kind": "fleet-dispatch-v1",
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
    }
    try:
        result = _dispatch(
            record["host"],
            command,
            timeout_seconds=30,
            allow_legacy_local_alias=True,
        )
    except fleet.FleetCommandDenied:
        # Production hosts intentionally do not expose generic systemctl through
        # fleet_run.  Reconcile still needs one fixed read-only observation shape
        # for Grabowski-owned task units, so fall back to the narrow fleet helper.
        observed = fleet.run_fleet_task_unit_show(
            record["host"],
            _authoritative_unit(record),
            fleet.TASK_UNIT_SHOW_PROPERTIES,
            timeout_seconds=30,
            max_output_bytes=8192,
        )
        result = observed["result"]
        observer = {
            "host": observed["host"],
            "transport": observed["transport"],
            "roles": observed["roles"],
            "kind": observed["observer"],
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
            "fallback_from": "fleet-dispatch-permission-denied",
        }
    properties: dict[str, str] = {}
    for line in result.get("stdout", "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    state = _classify_observation(result, properties)
    return {
        "state": state,
        "properties": properties,
        "probe": result,
        "observer": observer,
        "observed_at_unix": _now(),
    }



def _normalize_task_operation_identity(
    value: dict[str, Any] | None,
    *,
    cwd: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    required = {
        "repository_head",
        "source_fingerprint_sha256",
        "purpose",
        "scope_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(
            "operation_identity must contain repository_head, "
            "source_fingerprint_sha256, purpose and scope_sha256"
        )
    repository_head = value.get("repository_head")
    if (
        not isinstance(repository_head, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", repository_head) is None
    ):
        raise ValueError("operation_identity.repository_head is invalid")
    source_fingerprint = value.get("source_fingerprint_sha256")
    scope_sha256 = value.get("scope_sha256")
    if not isinstance(source_fingerprint, str) or SHA256.fullmatch(source_fingerprint) is None:
        raise ValueError(
            "operation_identity.source_fingerprint_sha256 is invalid"
        )
    if not isinstance(scope_sha256, str) or SHA256.fullmatch(scope_sha256) is None:
        raise ValueError("operation_identity.scope_sha256 is invalid")
    raw_purpose = value.get("purpose")
    if not isinstance(raw_purpose, str):
        raise ValueError("operation_identity.purpose must be text")
    purpose = " ".join(raw_purpose.split())
    if not purpose or len(purpose) > 512:
        raise ValueError("operation_identity.purpose is empty or too long")
    material = {
        "schema_version": TASK_OPERATION_IDENTITY_SCHEMA_VERSION,
        "canonical_cwd": cwd,
        "repository_head": repository_head,
        "source_fingerprint_sha256": source_fingerprint,
        "purpose": purpose,
        "scope_sha256": scope_sha256,
    }
    return {
        **material,
        "operation_identity_sha256": _sha256_json(material),
    }


def _persisted_task_operation_identity(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    raw_launcher = record.get("launcher_json")
    if raw_launcher in {None, ""}:
        return None
    try:
        launcher = json.loads(str(raw_launcher))
    except (json.JSONDecodeError, TypeError) as exc:
        if "operation_identity" in str(raw_launcher):
            raise RuntimeError("stored task operation identity is invalid") from exc
        return None
    if not isinstance(launcher, dict):
        return None
    identity = launcher.get("operation_identity")
    if identity is None:
        return None
    if not isinstance(identity, dict):
        raise RuntimeError("stored task operation identity is invalid")
    required = {
        "schema_version",
        "canonical_cwd",
        "repository_head",
        "source_fingerprint_sha256",
        "purpose",
        "scope_sha256",
        "operation_identity_sha256",
    }
    if set(identity) != required:
        raise RuntimeError("stored task operation identity is invalid")
    material = {
        key: identity[key]
        for key in required
        if key != "operation_identity_sha256"
    }
    if (
        identity.get("schema_version") != TASK_OPERATION_IDENTITY_SCHEMA_VERSION
        or identity.get("canonical_cwd") != str(record["cwd"])
        or not isinstance(identity.get("repository_head"), str)
        or re.fullmatch(r"[0-9a-f]{40,64}", identity["repository_head"]) is None
        or not isinstance(identity.get("source_fingerprint_sha256"), str)
        or SHA256.fullmatch(identity["source_fingerprint_sha256"]) is None
        or not isinstance(identity.get("scope_sha256"), str)
        or SHA256.fullmatch(identity["scope_sha256"]) is None
        or not isinstance(identity.get("purpose"), str)
        or not identity["purpose"]
        or identity.get("operation_identity_sha256") != _sha256_json(material)
    ):
        raise RuntimeError("stored task operation identity is invalid")
    return dict(identity)


def _latest_task_for_operation_identity(
    operation_identity_sha256: str,
) -> dict[str, Any] | None:
    if SHA256.fullmatch(operation_identity_sha256) is None:
        raise ValueError("operation identity sha256 is invalid")
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE launcher_json IS NOT NULL "
            "AND json_valid(launcher_json) "
            "AND json_type(launcher_json, '$.operation_identity.operation_identity_sha256')='text' "
            "AND json_extract(launcher_json, '$.operation_identity.operation_identity_sha256')=? "
            "AND state<>'cancelled' "
            "ORDER BY created_at_unix DESC, rowid DESC LIMIT 2",
            (operation_identity_sha256,),
        ).fetchall()
    if not rows:
        return None
    records = [dict(row) for row in rows]
    for record in records:
        identity = _persisted_task_operation_identity(record)
        if (
            identity is None
            or identity["operation_identity_sha256"]
            != operation_identity_sha256
        ):
            raise RuntimeError("stored task operation identity is inconsistent")
    return records[0]


def _task_has_fresh_active_observation(
    record: dict[str, Any],
    *,
    now: int,
) -> bool:
    if str(record.get("state")) not in TASK_STATE_PROJECTIONS["active"]:
        return False
    raw = record.get("last_observation_json")
    if raw in {None, ""}:
        return False
    try:
        observation = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(observation, dict):
        return False
    observed_at = observation.get("observed_at_unix")
    properties = observation.get("properties")
    created_at = record.get("created_at_unix")
    runtime_seconds = record.get("runtime_seconds")
    within_runtime_budget = bool(
        isinstance(created_at, int)
        and not isinstance(created_at, bool)
        and isinstance(runtime_seconds, int)
        and not isinstance(runtime_seconds, bool)
        and created_at >= 0
        and runtime_seconds > 0
        and 0 <= now - created_at <= runtime_seconds
    )
    return bool(
        within_runtime_budget
        and isinstance(observed_at, int)
        and not isinstance(observed_at, bool)
        and 0 <= now - observed_at <= TASK_ACTIVE_OBSERVATION_MAX_AGE_SECONDS
        and observation.get("state") in TASK_STATE_PROJECTIONS["active"]
        and isinstance(properties, dict)
        and properties.get("ActiveState") == "active"
        and properties.get("SubState") == "running"
    )


def _operation_retry_binding(
    record: dict[str, Any],
    operation_identity: dict[str, Any],
    *,
    supersedes_task_id: str,
    supersedes_receipt_sha256: str,
    force_new_reason: str,
) -> dict[str, Any]:
    if supersedes_task_id != str(record["task_id"]):
        raise ValueError("operation retry supersedes_task_id is stale")
    receipt = record.get("lifecycle_receipt_sha256")
    if (
        not isinstance(receipt, str)
        or SHA256.fullmatch(receipt) is None
        or supersedes_receipt_sha256 != receipt
    ):
        raise ValueError("operation retry predecessor receipt is missing or stale")
    reason = " ".join(force_new_reason.split())
    if not reason or len(reason) > 512:
        raise ValueError("operation retry force-new reason is missing or too long")
    material = {
        "schema_version": 1,
        "kind": "grabowski_operation_identity_retry",
        "source_task_id": str(record["task_id"]),
        "source_state": str(record["state"]),
        "source_lifecycle_receipt_sha256": receipt,
        "source_operation_identity_sha256": operation_identity[
            "operation_identity_sha256"
        ],
        "force_new_reason": reason,
        "admitted_at_unix": _now(),
    }
    return {**material, "binding_sha256": _sha256_json(material)}


def _resolve_task_operation_identity(
    operation_identity: dict[str, Any] | None,
    *,
    supersedes_task_id: str,
    supersedes_receipt_sha256: str,
    force_new_reason: str,
) -> dict[str, Any]:
    retry_fields = (
        supersedes_task_id,
        supersedes_receipt_sha256,
        force_new_reason,
    )
    if operation_identity is None:
        if any(retry_fields):
            raise ValueError(
                "operation retry fields require operation_identity"
            )
        return {"reuse": None, "reuse_reason": None, "retry_binding": None}
    latest = _latest_task_for_operation_identity(
        operation_identity["operation_identity_sha256"]
    )
    if latest is None:
        if any(retry_fields):
            raise ValueError("operation retry predecessor was not found")
        return {"reuse": None, "reuse_reason": None, "retry_binding": None}
    now = _now()
    if str(latest["state"]) in TASK_STATE_PROJECTIONS["active"]:
        if not _task_has_fresh_active_observation(latest, now=now):
            grabowski_task_status(str(latest["task_id"]))
            latest = _row_raw(str(latest["task_id"]))
        if str(latest["state"]) in TASK_STATE_PROJECTIONS["active"]:
            if any(retry_fields):
                raise ValueError("active operation identity cannot be superseded")
            return {
                "reuse": latest,
                "reuse_reason": "active_operation_identity",
                "retry_binding": None,
            }
    if (
        str(latest["state"]) == "completed"
        and isinstance(latest.get("lifecycle_receipt_sha256"), str)
        and int(latest.get("terminalized_at_unix") or latest["updated_at_unix"])
        >= now - TASK_OPERATION_REUSE_WINDOW_SECONDS
    ):
        if any(retry_fields):
            raise ValueError("successful operation identity cannot be superseded")
        return {
            "reuse": latest,
            "reuse_reason": "recent_successful_operation_identity",
            "retry_binding": None,
        }
    if str(latest["state"]) in TASK_STATE_PROJECTIONS["attention"]:
        if not all(retry_fields):
            raise RuntimeError(
                "operation identity has an attention predecessor; bind "
                "supersedes_task_id, predecessor receipt and force-new reason"
            )
        return {
            "reuse": None,
            "reuse_reason": None,
            "retry_binding": _operation_retry_binding(
                latest,
                operation_identity,
                supersedes_task_id=supersedes_task_id,
                supersedes_receipt_sha256=supersedes_receipt_sha256,
                force_new_reason=force_new_reason,
            ),
        }
    if any(retry_fields):
        raise ValueError("operation retry fields do not match an attention predecessor")
    return {"reuse": None, "reuse_reason": None, "retry_binding": None}

def server_task_lease_delegation_evidence(lease_owner_id: str) -> dict[str, Any]:
    """Validate one live task and its complete current lease set for server delegation."""
    if not isinstance(lease_owner_id, str):
        raise ValueError("task lease owner must be text")
    match = re.fullmatch(r"task:([0-9a-f]{24})", lease_owner_id)
    if match is None:
        raise ValueError("task lease owner is invalid")
    task_id = match.group(1)
    record = _row(task_id)
    effective_owner = record.get("lease_owner_id") or _lease_owner(task_id)
    if effective_owner != lease_owner_id:
        raise ValueError("task record lease owner mismatch")
    state = str(record.get("state", ""))
    if state not in TASK_LEASE_DELEGATION_STATES:
        raise ValueError(f"task state does not permit lease delegation: {state}")
    resource_keys = _record_resource_keys(record)
    if not resource_keys:
        raise ValueError("task has no resource leases to delegate")
    lease_evidence = resources.task_lease_delegation_evidence(
        lease_owner_id,
        task_id,
        resource_keys,
    )
    task_binding = {
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "state": state,
        "attempt": int(record["attempt"]),
        "updated_at_unix": int(record["updated_at_unix"]),
        "resource_keys_sha256": lease_evidence["resource_keys_sha256"],
        "lease_bindings_sha256": lease_evidence["lease_bindings_sha256"],
    }
    return {
        "schema_version": 1,
        "kind": "grabowski_live_task_lease_delegation_evidence",
        **task_binding,
        "task_record_sha256": _sha256_json(task_binding),
        "resource_keys": lease_evidence["resource_keys"],
        "minimum_expires_at_unix": lease_evidence["minimum_expires_at_unix"],
        "observed_at_unix": lease_evidence["observed_at_unix"],
    }


@_serialize_task_mutation
def grabowski_task_start(
    host: str,
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = operator.DEFAULT_JOB_RUNTIME,
    resume_policy: ResumePolicy = "verify-then-retry",
    cpu_weight: int = 100,
    io_weight: int = 100,
    memory_max_bytes: int | None = None,
    resource_keys: list[str] | None = None,
    chronik_outbox: bool = False,
    chronik_outbox_state_root: str | None = None,
    chronik_operation: str = "other",
    chronik_component: str = "",
    chronik_bureau_task_id: str = "",
    chronik_pr_number: int | None = None,
    runtime_python: bool = False,
    route_evidence: dict[str, Any] | None = None,
    operation_identity: dict[str, Any] | None = None,
    supersedes_task_id: str = "",
    supersedes_receipt_sha256: str = "",
    force_new_reason: str = "",
    effect_profile: str | None = None,
    _retry_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start one persistent local or fleet task in its own systemd unit.

    Direct local write-capable agent CLIs receive an implicit repository lease
    unless the caller supplies an explicit path or repository scope. Before any new
    local writer process starts, its exact checkout first passes the repository admission
    bound to its task resource lease. Reposkop v3 then keeps risky/exact-path/repository
    writes fail-closed while deterministically sampling clean admitted workspace writes;
    the remaining admitted writers form an audit-bound prospective control cohort. Every
    task-owned broad repository lease carries a complete whole-repository scope manifest.
    An exact already-active execution identity is reused instead of launching
    another process, even when no explicit operation identity was supplied.
    """
    target = fleet.fleet_host(host)
    executor_request: dict[str, str] | None = None
    executor_intent: dict[str, Any] | None = None
    executor_authority_contract: dict[str, Any] | None = None
    if bureau_runtime_refresh_executor.is_reserved_task_request(argv):
        if target.get("transport") != "local" or target.get("target") != "local":
            raise PermissionError("Bureau runtime-refresh executor requires the local fleet host")
        if resume_policy != "never":
            raise ValueError("Bureau runtime-refresh executor requires resume_policy=never")
        if operation_identity is not None:
            raise ValueError("Bureau runtime-refresh executor operation_identity is server-owned")
        if resource_keys is not None:
            raise ValueError(
                "resource_keys are server-owned by the bound Bureau runtime-refresh intent"
            )
        executor_request = bureau_runtime_refresh_executor.parse_reserved_task_request(argv)
        executor_intent = bureau_runtime_refresh_executor.load_bound_intent(executor_request)
        executor_authority_contract = (
            bureau_runtime_refresh_executor.validate_authority_execution_contract(
                executor_intent
            )
        )
        command = bureau_runtime_refresh_executor.build_executor_command(
            executor_request, runtime_python=GRABOWSKI_RUNTIME_PYTHON
        )
        command = _validate_command(command)
    else:
        command = _validate_command(argv)
        bureau_runtime_refresh_executor.reject_generic_runtime_refresh_execution(
            command, surface="grabowski_task_start"
        )
    recovery_gate = _require_recovery_gate(command)
    working_directory = _validate_cwd(host, cwd)
    if executor_request is not None and working_directory != str(operator.HOME):
        raise ValueError("Bureau runtime-refresh executor requires cwd=/home/alex")
    command = _bind_grabowski_runtime_python(
        command,
        target=target,
        cwd=working_directory,
        enabled=runtime_python,
    )
    mutating_agent_workspace = _mutating_agent_workspace(
        host,
        command,
        cwd=working_directory,
    )
    task_effect_classification = reposkop_effectiveness.classify_task_effect(
        transport=str(target["transport"]),
        argv=command,
        mutating_workspace=mutating_agent_workspace,
        explicit_effect_profile=effect_profile,
    )
    runtime = operator._job_runtime(runtime_seconds)
    policy = _validate_resume_policy(resume_policy)
    cpu, io = _validate_weights(cpu_weight, io_weight)
    memory = _validate_memory(memory_max_bytes)
    chronik_enabled, chronik_state_root = _validate_chronik_outbox(
        chronik_outbox,
        chronik_outbox_state_root,
    )
    chronik_operation = _validate_chronik_operation(
        chronik_operation, enabled=bool(chronik_enabled)
    )
    chronik_component, chronik_bureau_task_id, chronik_pr_number = (
        _validate_chronik_context_metadata(
            chronik_component,
            chronik_bureau_task_id,
            chronik_pr_number,
            enabled=bool(chronik_enabled),
        )
    )
    normalized_operation_identity = _normalize_task_operation_identity(
        (
            bureau_runtime_refresh_executor.operation_identity(
                executor_request, executor_intent, executor_authority_contract
            )
            if (
                executor_request is not None
                and executor_intent is not None
                and executor_authority_contract is not None
            )
            else operation_identity
        ),
        cwd=working_directory,
    )
    task_id = uuid.uuid4().hex[:24]
    operation_resolution = _resolve_task_operation_identity(
        normalized_operation_identity,
        supersedes_task_id=supersedes_task_id,
        supersedes_receipt_sha256=supersedes_receipt_sha256,
        force_new_reason=force_new_reason,
    )
    reused_record = operation_resolution["reuse"]
    if reused_record is not None:
        reused_attestation = _record_reposkop_execution_attestation(reused_record)
        reused_classification = (
            _record_task_effect_classification(reused_record)
            or task_effect_classification
        )
        reuse_audit = {
            "timestamp_unix": _now(),
            "operation": "task-start-deduplicated",
            "requested_task_id": task_id,
            "reused_task_id": str(reused_record["task_id"]),
            "reuse_reason": operation_resolution["reuse_reason"],
            "operation_identity_sha256": normalized_operation_identity[
                "operation_identity_sha256"
            ],
            "effect_profile": reused_classification["effect_profile"],
            "reposkop_policy": reused_classification["reposkop_policy"],
            "surface": reused_classification["surface"],
            "agent_executable": reused_classification.get("agent_executable"),
            "policy_version": reused_classification["policy_version"],
            "evaluation_id": (
                reused_attestation.get("evaluation_id")
                if reused_attestation is not None
                else None
            ),
            "reposkop_reuse_status": (
                "reused_existing_evaluation"
                if reused_attestation is not None
                and reused_attestation.get("evaluation_id")
                else "legacy_unattested"
            ),
            "no_process_started": True,
        }
        base._append_audit(reuse_audit)
        return {
            "task": _public(reused_record),
            "audit": reuse_audit,
            "execution_identity": _record_execution_identity(reused_record),
            "retry_binding": _persisted_retry_binding_or_raise(reused_record),
            "routing_shadow_capture": None,
            "operation_identity": normalized_operation_identity,
            "operation_retry_binding": None,
            "reposkop_execution_attestation": reused_attestation,
            "task_effect_classification": reused_classification,
            "deduplicated_reuse": {
                "reused": True,
                "task_id": str(reused_record["task_id"]),
                "reason": operation_resolution["reuse_reason"],
            },
        }
    operation_retry_binding = operation_resolution["retry_binding"]
    requested_resources = _resource_keys(resource_keys)
    task_resources, implicit_workspace_resource = _task_resource_keys(
        host,
        command,
        cwd=working_directory,
        requested=requested_resources,
    )
    workspace_lease_resource_keys = (
        _workspace_lease_resource_keys(
            mutating_agent_workspace, task_resources
        )
        if mutating_agent_workspace is not None
        else []
    )
    if (
        mutating_agent_workspace is not None
        and not workspace_lease_resource_keys
    ):
        raise RuntimeError(
            "write-capable agent task has no lease covering its workspace"
        )
    chronik_context_json = (
        _chronik_context(
            host,
            task_resources,
            chronik_operation,
            component=chronik_component,
            bureau_task_id=chronik_bureau_task_id,
            pr_number=chronik_pr_number,
        )
        if chronik_enabled
        else None
    )
    lease_owner = _lease_owner(task_id)
    repository_resource = _task_repository_resource(task_resources)
    repository_scope_manifest = (
        _whole_repository_scope_manifest(repository_resource, task_id)
        if repository_resource is not None
        else None
    )
    normalized_route_evidence: dict[str, Any] | None = None
    if route_evidence is not None:
        import grabowski_agent_workspace as agent_workspace

        try:
            normalized_route_evidence = agent_workspace._normalize_route_evidence(
                route_evidence, execution_surface="direct_task"
            )
        except agent_workspace.AgentWorkspaceError as exc:
            raise ValueError(f"direct task route evidence is invalid: {exc}") from exc
        if (
            normalized_route_evidence.get("status") != "verified"
            or normalized_route_evidence.get("evidence_complete") is not True
        ):
            raise ValueError("direct task route evidence must be complete and verified")
    execution_backend, systemd_scope = _execution_contract(target, command)
    if executor_request is not None and (
        execution_backend != "systemd-user" or systemd_scope != "user"
    ):
        raise PermissionError(
            "Bureau runtime-refresh executor requires the systemd-user execution backend"
        )
    if (
        execution_backend == "systemd-root-broker"
        and runtime + 300 > resources.MAX_TTL_SECONDS
    ):
        raise ValueError(
            "root task runtime must leave 300 seconds of lease and stop grace"
        )
    operator._require_operator_mutation(
        "durable_job",
        path=working_directory,
        repo=working_directory,
        task_id=task_id,
        owner_id=lease_owner,
        host=host,
        opaque_command=True,
    )
    executor_prelaunch_recovery: dict[str, Any] | None = None
    if executor_request is not None and executor_intent is not None:
        recovery_keys = executor_intent.get("required_resource_keys")
        if not isinstance(recovery_keys, list):
            raise ValueError("Bureau runtime-refresh prelaunch resource keys are invalid")
        executor_prelaunch_recovery = (
            _reconcile_runtime_refresh_prelaunch_binding_journals(recovery_keys)
        )
    unprepared_identity = _task_execution_identity(
        host=host,
        argv_sha256=command_identity.argv_sha256(command),
        cwd=working_directory,
        resource_keys=task_resources,
        runtime_seconds=runtime,
        cpu_weight=cpu,
        io_weight=io,
        memory_max_bytes=memory,
        chronik_outbox_enabled=bool(chronik_enabled),
        chronik_outbox_state_root=chronik_state_root,
        chronik_context_json=chronik_context_json,
        execution_backend=execution_backend,
        systemd_scope=systemd_scope,
    )
    _guard_unprepared_managed_cargo_retry(
        command,
        target=target,
        cwd=working_directory,
        execution_backend=execution_backend,
        identity=unprepared_identity,
        retry_context=_retry_context,
    )
    command = _bind_managed_cargo_environment(
        command,
        target=target,
        cwd=working_directory,
        execution_backend=execution_backend,
    )
    argv_sha256 = command_identity.argv_sha256(command)
    execution_identity = _task_execution_identity(
        host=host,
        argv_sha256=argv_sha256,
        cwd=working_directory,
        resource_keys=task_resources,
        runtime_seconds=runtime,
        cpu_weight=cpu,
        io_weight=io,
        memory_max_bytes=memory,
        chronik_outbox_enabled=bool(chronik_enabled),
        chronik_outbox_state_root=chronik_state_root,
        chronik_context_json=chronik_context_json,
        execution_backend=execution_backend,
        systemd_scope=systemd_scope,
    )
    checkout_head: str | None = None
    checkout_branch: str | None = None
    if mutating_agent_workspace is not None:
        if (
            repository_scope_manifest is not None
            and repository_scope_manifest["repository"]
            == mutating_agent_workspace
        ):
            checkout_head = str(repository_scope_manifest["head"])
            checkout_branch = str(repository_scope_manifest["branch"])
        else:
            checkout_head, checkout_branch = _workspace_scope_identity(
                mutating_agent_workspace
            )
        if (
            task_effect_classification["reposkop_policy"] == "required"
            and task_effect_classification["effect_profile"] == "workspace_write"
            and not _workspace_has_git_marker(mutating_agent_workspace)
        ):
            task_effect_classification = {
                **task_effect_classification,
                "reposkop_policy": "not_required",
                "reposkop_cohort": "not_applicable",
                "reposkop_applicability": "no_git_marker",
            }

    reposkop_evaluation_id: str | None = None
    reposkop_checkout_binding_sha256: str | None = None
    if task_effect_classification["reposkop_policy"] == "required":
        if (
            mutating_agent_workspace is None
            or checkout_head is None
            or checkout_branch is None
        ):
            raise RuntimeError("required Reposkop task has no local workspace identity")
        reposkop_checkout_binding_sha256 = _sha256_json(
            {
                "schema_version": 1,
                "workspace": mutating_agent_workspace,
                "head": checkout_head,
                "branch": checkout_branch,
            }
        )
        reposkop_evaluation_id = reposkop_effectiveness.evaluation_id(
            task_id=task_id,
            execution_identity_sha256=execution_identity["identity_sha256"],
            checkout_binding_sha256=reposkop_checkout_binding_sha256,
            argv_sha256=argv_sha256,
            policy_version=int(task_effect_classification["policy_version"]),
        )
    active_execution_reuse = None
    if (
        normalized_operation_identity is None
        and operation_retry_binding is None
        and _retry_context is None
        and not task_resources
    ):
        active_execution_reuse = _resolve_active_execution_reuse(
            execution_identity,
            resume_policy=policy,
        )
    if active_execution_reuse is not None:
        reused_attestation = _record_reposkop_execution_attestation(
            active_execution_reuse
        )
        reused_classification = (
            _record_task_effect_classification(active_execution_reuse)
            or task_effect_classification
        )
        reuse_audit = {
            "timestamp_unix": _now(),
            "operation": "task-start-execution-deduplicated",
            "requested_task_id": task_id,
            "reused_task_id": str(active_execution_reuse["task_id"]),
            "reuse_reason": "active_execution_identity",
            "execution_identity_sha256": execution_identity["identity_sha256"],
            "effect_profile": reused_classification["effect_profile"],
            "reposkop_policy": reused_classification["reposkop_policy"],
            "surface": reused_classification["surface"],
            "agent_executable": reused_classification.get("agent_executable"),
            "policy_version": reused_classification["policy_version"],
            "evaluation_id": (
                reused_attestation.get("evaluation_id")
                if reused_attestation is not None
                else None
            ),
            "reposkop_reuse_status": (
                "reused_existing_evaluation"
                if reused_attestation is not None
                and reused_attestation.get("evaluation_id")
                else "legacy_unattested"
            ),
            "no_process_started": True,
        }
        base._append_audit(reuse_audit)
        return {
            "task": _public(active_execution_reuse),
            "audit": reuse_audit,
            "execution_identity": execution_identity,
            "retry_binding": _persisted_retry_binding_or_raise(
                active_execution_reuse
            ),
            "routing_shadow_capture": None,
            "operation_identity": None,
            "operation_retry_binding": None,
            "reposkop_execution_attestation": reused_attestation,
            "task_effect_classification": reused_classification,
            "deduplicated_reuse": {
                "reused": True,
                "task_id": str(active_execution_reuse["task_id"]),
                "reason": "active_execution_identity",
            },
        }
    retry_binding = (
        None
        if operation_retry_binding is not None
        else _guard_unchanged_terminal_retry(
            execution_identity,
            _retry_context,
        )
    )
    routing_shadow_capture: dict[str, Any] | None = None
    if normalized_route_evidence is not None:
        import grabowski_operator_routing_shadow_capture as routing_shadow

        routing_shadow_capture = routing_shadow.capture_direct_task_start_best_effort(
            task_id=task_id,
            route_evidence=normalized_route_evidence,
            host=host,
            argv_sha256=argv_sha256,
            cwd=working_directory,
            resource_keys=task_resources,
            runtime_seconds=runtime,
        )
    attempt = 1
    unit = _task_unit(task_id, attempt)
    now = _now()
    lease_result = None
    lease_metadata = None
    if task_resources:
        lease_metadata = _task_lease_metadata(
            task_id=task_id,
            host=host,
            attempt=attempt,
            repository_resource=repository_resource,
            implicit_workspace_resource=implicit_workspace_resource,
            repository_scope_manifest=repository_scope_manifest,
        )
        lease_result = resources.acquire_resources(
            lease_owner,
            task_resources,
            purpose=f"persistent task {task_id}",
            ttl_seconds=min(
                resources.MAX_TTL_SECONDS,
                max(resources.MIN_TTL_SECONDS, runtime + 300),
            ),
            metadata=lease_metadata,
        )
    prospective_admission_evidence: dict[str, Any] | None = None
    if mutating_agent_workspace is not None:
        prospective_admission_evidence = _reposkop_prospective_admission_evidence(
            lease_result=lease_result,
            lease_owner_id=lease_owner,
            task_resources=task_resources,
            repository_scope_manifest=repository_scope_manifest,
            workspace=mutating_agent_workspace,
            head=checkout_head,
            branch=checkout_branch,
            now=now,
        )
        task_effect_classification = (
            reposkop_effectiveness.select_prospective_policy(
                task_effect_classification,
                sampling_key=task_id,
                admission_verified=prospective_admission_evidence is not None,
            )
        )
    reposkop_execution_attestation: dict[str, Any] | None = None
    reposkop_requested_audit_ref: str | None = None
    reposkop_completed_audit_ref: str | None = None
    reposkop_decision_audit_ref: str | None = None
    reposkop_event_identity = (
        {
            "transaction_id": reposkop_evaluation_id,
            "evaluation_id": reposkop_evaluation_id,
            "task_id": task_id,
            "effect_profile": task_effect_classification["effect_profile"],
            "reposkop_policy": task_effect_classification["reposkop_policy"],
            "reposkop_cohort": task_effect_classification.get("reposkop_cohort"),
            "prospective_admission_verified": task_effect_classification.get(
                "prospective_admission_verified"
            ),
            "sampling_modulus": task_effect_classification.get("sampling_modulus"),
            "sampling_bucket": task_effect_classification.get("sampling_bucket"),
            "sampling_key_sha256": task_effect_classification.get(
                "sampling_key_sha256"
            ),
            "surface": task_effect_classification["surface"],
            "agent_executable": task_effect_classification.get(
                "agent_executable"
            ),
            "policy_version": task_effect_classification["policy_version"],
            "argv_sha256": argv_sha256,
            "execution_identity_sha256": execution_identity[
                "identity_sha256"
            ],
            "checkout_binding_sha256": (
                reposkop_checkout_binding_sha256
            ),
        }
        if reposkop_evaluation_id is not None
        else None
    )
    if task_effect_classification["reposkop_policy"] == "required":
        if mutating_agent_workspace is None or reposkop_event_identity is None:
            raise RuntimeError("required Reposkop task lacks evaluation identity")
        try:
            if lease_result is None:
                raise RuntimeError(
                    "write-capable agent workspace lease was not acquired"
                )
            acquired_leases = {
                str(item.get("resource_key")): item
                for item in lease_result.get("leases", [])
                if isinstance(item, dict)
            }
            for resource_key in workspace_lease_resource_keys:
                acquired = acquired_leases.get(resource_key)
                if (
                    acquired is None
                    or acquired.get("owner_id") != lease_owner
                    or int(acquired.get("expires_at_unix", 0)) <= now
                ):
                    raise RuntimeError(
                        "write-capable agent workspace lease evidence is "
                        "missing, foreign or expired"
                    )
            reposkop_requested_audit_ref = (
                reposkop_effectiveness.append_event(
                    {
                        "timestamp_unix": _now(),
                        "operation": "reposkop-evaluation-requested",
                        **reposkop_event_identity,
                        "workspace_lease_resource_keys": (
                            workspace_lease_resource_keys
                        ),
                        "baseline_decision": "allow_without_reposkop",
                    }
                )
            )
            reposkop_started_ns = time.monotonic_ns()
            raw_attestation = _attest_mutating_agent_workspace(
                workspace=mutating_agent_workspace,
                task_id=task_id,
                lease_owner_id=lease_owner,
                workspace_lease_resource_keys=(
                    workspace_lease_resource_keys
                ),
                argv=command,
                argv_sha256=argv_sha256,
                execution_identity_sha256=execution_identity[
                    "identity_sha256"
                ],
            )
            reposkop_duration_ms = max(
                0,
                (time.monotonic_ns() - reposkop_started_ns) // 1_000_000,
            )
            reposkop_execution_attestation = (
                reposkop_effectiveness.enrich_attestation(
                    raw_attestation,
                    evaluation=reposkop_evaluation_id,
                    classification=task_effect_classification,
                    checkout_binding_sha256=(
                        reposkop_checkout_binding_sha256
                    ),
                    duration_ms=reposkop_duration_ms,
                )
            )
            finding_summary = reposkop_execution_attestation[
                "finding_summary"
            ]
            reposkop_completed_audit_ref = (
                reposkop_effectiveness.append_event(
                    {
                        "timestamp_unix": _now(),
                        "operation": "reposkop-evaluation-completed",
                        **reposkop_event_identity,
                        "status": "verified",
                        "duration_ms": reposkop_duration_ms,
                        "reposkop_executable_sha256": (
                            reposkop_execution_attestation[
                                "reposkop_executable_sha256"
                            ]
                        ),
                        "report_sha256": reposkop_execution_attestation[
                            "report_sha256"
                        ],
                        "observation_sha256": (
                            reposkop_execution_attestation[
                                "observation_sha256"
                            ]
                        ),
                        "projection_sha256": (
                            reposkop_execution_attestation[
                                "projection_sha256"
                            ]
                        ),
                        "repository_identity_sha256": (
                            reposkop_execution_attestation[
                                "repository_identity_sha256"
                            ]
                        ),
                        "checkout_identity_sha256": (
                            reposkop_execution_attestation[
                                "checkout_identity_sha256"
                            ]
                        ),
                        "usage_key_sha256": (
                            reposkop_execution_attestation[
                                "usage_key_sha256"
                            ]
                        ),
                        "usage_receipt_sha256": (
                            reposkop_execution_attestation[
                                "usage_receipt_sha256"
                            ]
                        ),
                        "requested_audit_ref": (
                            reposkop_requested_audit_ref
                        ),
                        **finding_summary,
                    }
                )
            )
            reposkop_decision_audit_ref = (
                reposkop_effectiveness.append_event(
                    {
                        "timestamp_unix": _now(),
                        "operation": "reposkop-decision-applied",
                        **reposkop_event_identity,
                        "baseline_decision": "allow_without_reposkop",
                        "final_decision": "allow",
                        "decision_changed": False,
                        "action": "task_start_allowed",
                        "rule_ids": ["reposkop-policy-v3"],
                        "decision_reason_codes": (
                            reposkop_effectiveness.decision_reason_codes(
                                finding_summary,
                                final_decision="allow",
                            )
                        ),
                        "projection_state": finding_summary.get(
                            "projection_state"
                        ),
                        "advisory_posture": finding_summary.get(
                            "advisory_posture"
                        ),
                        "completed_audit_ref": (
                            reposkop_completed_audit_ref
                        ),
                    }
                )
            )
            attestation_material = {
                key: value
                for key, value in reposkop_execution_attestation.items()
                if key != "execution_binding_sha256"
            }
            attestation_material.update(
                {
                    "requested_audit_ref": (
                        reposkop_requested_audit_ref
                    ),
                    "completed_audit_ref": (
                        reposkop_completed_audit_ref
                    ),
                    "decision_audit_ref": reposkop_decision_audit_ref,
                }
            )
            reposkop_execution_attestation = {
                **attestation_material,
                "execution_binding_sha256": _sha256_json(
                    attestation_material
                ),
            }
        except Exception as exc:
            failure = reposkop_effectiveness.failure_summary(exc)
            if reposkop_event_identity is not None:
                try:
                    reposkop_decision_audit_ref = (
                        reposkop_effectiveness.append_event(
                            {
                                "timestamp_unix": _now(),
                                "operation": "reposkop-decision-applied",
                                **reposkop_event_identity,
                                "baseline_decision": (
                                    "allow_without_reposkop"
                                ),
                                "final_decision": "block",
                                "decision_changed": True,
                                "action": (
                                    "blocked_before_task_record"
                                ),
                                "rule_ids": ["reposkop-policy-v3"],
                                "failure_class": type(exc).__name__,
                                "failure_category": failure[
                                    "failure_category"
                                ],
                                "decision_reason_codes": failure[
                                    "decision_reason_codes"
                                ],
                                "requested_audit_ref": (
                                    reposkop_requested_audit_ref
                                ),
                            }
                        )
                    )
                except Exception:
                    reposkop_decision_audit_ref = None
            compensation: dict[str, Any] | None = None
            compensation_error: str | None = None
            if task_resources and lease_result is not None:
                try:
                    compensation = resources.release_resources(
                        lease_owner,
                        task_resources,
                        expected_leases=[
                            resources._release_lease_snapshot(item)
                            for item in lease_result["leases"]
                        ],
                    )
                except Exception as release_exc:
                    compensation_error = (
                        f"{type(release_exc).__name__}: {release_exc}"
                    )[:1024]
            blocked_audit = {
                "timestamp_unix": _now(),
                "operation": "reposkop-execution-attestation-blocked",
                "transaction_id": reposkop_evaluation_id,
                "evaluation_id": reposkop_evaluation_id,
                "task_id": task_id,
                "host": host,
                "workspace": mutating_agent_workspace,
                "lease_owner_id": lease_owner,
                "workspace_lease_resource_keys": (
                    workspace_lease_resource_keys
                ),
                "argv_sha256": argv_sha256,
                "execution_identity_sha256": execution_identity[
                    "identity_sha256"
                ],
                "checkout_binding_sha256": (
                    reposkop_checkout_binding_sha256
                ),
                "effect_profile": task_effect_classification[
                    "effect_profile"
                ],
                "reposkop_policy": task_effect_classification[
                    "reposkop_policy"
                ],
                "surface": task_effect_classification["surface"],
                "agent_executable": task_effect_classification.get(
                    "agent_executable"
                ),
                "policy_version": task_effect_classification[
                    "policy_version"
                ],
                "error_type": type(exc).__name__,
                "error": _redact_reason(str(exc))[:1024],
                "failure_category": failure["failure_category"],
                "decision_reason_codes": failure[
                    "decision_reason_codes"
                ],
                "requested_audit_ref": reposkop_requested_audit_ref,
                "decision_audit_ref": reposkop_decision_audit_ref,
                "lease_compensation": compensation,
                "lease_compensation_error": compensation_error,
                "no_task_record_created": True,
                "no_process_started": True,
            }
            base._append_audit(blocked_audit)
            if compensation_error is not None:
                raise RuntimeError(
                    "Reposkop execution attestation and lease compensation failed"
                ) from exc
            raise RuntimeError(
                "Reposkop execution attestation failed before task launch"
            ) from exc
    elif task_effect_classification.get("reposkop_cohort") == "prospective_control":
        if (
            mutating_agent_workspace is None
            or reposkop_event_identity is None
            or lease_result is None
        ):
            raise RuntimeError("prospective Reposkop control lacks bound admission evidence")
        admission_evidence = prospective_admission_evidence
        if admission_evidence is None:
            raise RuntimeError("prospective Reposkop control lost repository admission")
        admission_sha256 = _sha256_json(admission_evidence)
        reposkop_decision_audit_ref = reposkop_effectiveness.append_event(
            {
                "timestamp_unix": _now(),
                "operation": "reposkop-decision-applied",
                **reposkop_event_identity,
                "baseline_decision": "allow_without_reposkop",
                "final_decision": "allow",
                "decision_changed": False,
                "action": "task_start_allowed_without_reposkop",
                "reposkop_execution_skipped": True,
                "admission_evidence_sha256": admission_sha256,
                "rule_ids": ["reposkop-policy-v3-prospective-control"],
                "decision_reason_codes": [
                    "prospective_control",
                    "repository_admission_verified",
                    "reposkop_execution_skipped",
                ],
            }
        )
        control_material = {
            "schema_version": 1,
            "kind": REPOSKOP_EXECUTION_ATTESTATION_KIND,
            "policy_version": task_effect_classification["policy_version"],
            "required": False,
            "status": "skipped_control",
            "task_id": task_id,
            "lease_owner_id": lease_owner,
            "workspace_lease_resource_keys": workspace_lease_resource_keys,
            "workspace_lease_resource_keys_sha256": _sha256_json(
                workspace_lease_resource_keys
            ),
            "workspace": mutating_agent_workspace,
            "argv_sha256": argv_sha256,
            "execution_identity_sha256": execution_identity["identity_sha256"],
            "evaluation_id": reposkop_evaluation_id,
            "effect_profile": task_effect_classification["effect_profile"],
            "reposkop_policy": task_effect_classification["reposkop_policy"],
            "reposkop_cohort": task_effect_classification.get("reposkop_cohort"),
            "surface": task_effect_classification["surface"],
            "agent_executable": task_effect_classification.get("agent_executable"),
            "checkout_binding_sha256": reposkop_checkout_binding_sha256,
            "decision_audit_ref": reposkop_decision_audit_ref,
            "admission_evidence_sha256": admission_sha256,
            "reposkop_execution_skipped": True,
            "effect_authorized": False,
        }
        reposkop_execution_attestation = {
            **control_material,
            "execution_binding_sha256": _sha256_json(control_material),
        }
    reposkop_checkout_shadow_before = (
        _capture_reposkop_shadow_before_best_effort(
            task_id=task_id,
            workspace=mutating_agent_workspace,
            evaluation_id=reposkop_evaluation_id,
            reposkop_cohort=task_effect_classification.get("reposkop_cohort"),
        )
        if (
            mutating_agent_workspace is not None
            and task_effect_classification.get("reposkop_cohort") != "not_applicable"
        )
        else None
    )
    task_output_managed_from_attempt = (
        1
        if target["transport"] == "local" and execution_backend == "systemd-user"
        else None
    )
    executor_lease_binding_request: dict[str, Any] | None = None
    executor_lease_binding_plan: dict[str, Any] | None = None
    executor_lease_binding_journal: dict[str, Any] | None = None
    executor_lease_binding: dict[str, Any] | None = None
    executor_lease_binding_evidence: dict[str, Any] | None = None
    record = {
        "task_id": task_id,
        "host": host,
        "unit": unit,
        "authoritative_unit": unit,
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
        "attempt": attempt,
        "state": "launching",
        "resume_policy": policy,
        "argv_json": _canonical_json(command),
        "argv_sha256": argv_sha256,
        "cwd": working_directory,
        "runtime_seconds": runtime,
        "cpu_weight": cpu,
        "io_weight": io,
        "memory_max_bytes": memory,
        "created_at_unix": now,
        "updated_at_unix": now,
        "launcher_json": _canonical_json(
            {
                "pending": True,
                **(
                    {TASK_OUTPUT_LAUNCHER_BINDING_KEY: task_output_managed_from_attempt}
                    if task_output_managed_from_attempt is not None
                    else {}
                ),
                "task_effect_classification": dict(
                    task_effect_classification
                ),
                **(
                    {"retry_binding": dict(retry_binding)}
                    if retry_binding is not None
                    else {}
                ),
                **(
                    {"operation_identity": dict(normalized_operation_identity)}
                    if normalized_operation_identity is not None
                    else {}
                ),
                **(
                    {"operation_retry_binding": dict(operation_retry_binding)}
                    if operation_retry_binding is not None
                    else {}
                ),
                **(
                    {
                        "reposkop_execution_attestation": dict(
                            reposkop_execution_attestation
                        )
                    }
                    if reposkop_execution_attestation is not None
                    else {}
                ),
                **(
                    {
                        "reposkop_checkout_shadow_before": dict(
                            reposkop_checkout_shadow_before
                        )
                    }
                    if reposkop_checkout_shadow_before is not None
                    else {}
                ),
            }
        ),
        "last_observation_json": None,
        "resource_keys_json": _canonical_json(task_resources),
        "lease_owner_id": lease_owner,
        "chronik_outbox_enabled": chronik_enabled,
        "chronik_outbox_state_root": chronik_state_root,
        "chronik_context_json": chronik_context_json,
        "repository_scope_manifest_json": (
            _canonical_json(repository_scope_manifest)
            if repository_scope_manifest is not None
            else None
        ),
    }
    try:
        if executor_request is not None:
            if executor_intent is None or executor_authority_contract is None:
                raise RuntimeError(
                    "Bureau runtime-refresh executor authority vanished before prelaunch binding"
                )
            executor_lease_binding_request = (
                _runtime_refresh_prelaunch_lease_binding_request(
                    executor_request,
                    executor_intent,
                    executor_authority_contract,
                    task_id,
                    unit,
                )
            )
            executor_lease_binding_plan = (
                resources.prepare_runtime_refresh_executor_lease_binding(
                    executor_lease_binding_request["lease_owner"],
                    executor_lease_binding_request["resource_keys"],
                    executor_lease_binding_request["executor_unit"],
                    minimum_remaining_seconds=executor_lease_binding_request[
                        "minimum_remaining_seconds"
                    ],
                )
            )
            executor_lease_binding_journal = (
                _runtime_refresh_prelaunch_binding_journal(
                    executor_lease_binding_request,
                    argv_sha256=record["argv_sha256"],
                    binding_plan=executor_lease_binding_plan,
                )
            )
            _persist_runtime_refresh_prelaunch_binding_journal(
                executor_lease_binding_journal
            )
            executor_lease_binding = resources.bind_runtime_refresh_executor_leases(
                executor_lease_binding_request["lease_owner"],
                executor_lease_binding_request["resource_keys"],
                executor_lease_binding_request["executor_unit"],
                minimum_remaining_seconds=executor_lease_binding_request[
                    "minimum_remaining_seconds"
                ],
                prepared_binding=executor_lease_binding_plan,
            )
            binding_evidence_material = {
                "schema_version": 1,
                "kind": "grabowski_bureau_runtime_refresh_prelaunch_lease_binding",
                "intent_sha256": executor_lease_binding_request["intent_sha256"],
                "request_sha256": executor_lease_binding_request["request_sha256"],
                "binding_sha256": executor_lease_binding["binding_sha256"],
                "binding_plan_sha256": executor_lease_binding_plan["plan_sha256"],
                "journal_sha256": executor_lease_binding_journal["journal_sha256"],
                "executor_unit": unit,
                "resource_count": len(executor_lease_binding_request["resource_keys"]),
                "resource_keys_sha256": _sha256_json(
                    executor_lease_binding_request["resource_keys"]
                ),
                "minimum_remaining_seconds": executor_lease_binding_request[
                    "minimum_remaining_seconds"
                ],
            }
            executor_lease_binding_evidence = {
                **binding_evidence_material,
                "evidence_sha256": _sha256_json(binding_evidence_material),
            }
            initial_launcher = json.loads(record["launcher_json"])
            initial_launcher["runtime_refresh_executor_lease_binding"] = dict(
                executor_lease_binding_evidence
            )
            record["launcher_json"] = _canonical_json(initial_launcher)
        if task_output_managed_from_attempt is not None:
            _ensure_local_task_output_root()
        with _database_connection() as connection:
            connection.execute(
                """
            INSERT INTO tasks(
                task_id, host, unit, attempt, state, resume_policy,
                argv_json, argv_sha256, cwd, runtime_seconds,
                cpu_weight, io_weight, memory_max_bytes,
                created_at_unix, updated_at_unix, launcher_json,
                last_observation_json, resource_keys_json, lease_owner_id,
                execution_backend, systemd_scope, authoritative_unit,
                chronik_outbox_enabled, chronik_outbox_state_root,
                chronik_context_json, repository_scope_manifest_json
            ) VALUES(
                :task_id, :host, :unit, :attempt, :state, :resume_policy,
                :argv_json, :argv_sha256, :cwd, :runtime_seconds,
                :cpu_weight, :io_weight, :memory_max_bytes,
                :created_at_unix, :updated_at_unix, :launcher_json,
                :last_observation_json, :resource_keys_json, :lease_owner_id,
                :execution_backend, :systemd_scope, :authoritative_unit,
                :chronik_outbox_enabled, :chronik_outbox_state_root,
                :chronik_context_json, :repository_scope_manifest_json
            )
            """,
                record,
            )
            _register_task_reconcile_sequence(connection, task_id)
            if executor_lease_binding_journal is not None:
                _delete_runtime_refresh_prelaunch_binding_journal(
                    connection, executor_lease_binding_journal
                )
            connection.commit()
    except Exception as exc:
        executor_record_state = "not_applicable"
        executor_compensation_error: Exception | None = None
        if executor_lease_binding is not None:
            try:
                observed_record = _row_raw(task_id)
            except ValueError as readback_error:
                if str(readback_error) == f"Unknown task: {task_id}":
                    executor_record_state = "absent"
                else:
                    executor_record_state = "readback_unknown"
            except Exception:
                executor_record_state = "readback_unknown"
            else:
                if (
                    observed_record.get("task_id") == task_id
                    and observed_record.get("unit") == unit
                    and observed_record.get("argv_sha256") == record["argv_sha256"]
                ):
                    executor_record_state = "present_exact"
                else:
                    executor_record_state = "present_mismatch"
            if executor_record_state == "absent":
                try:
                    resources.unbind_runtime_refresh_executor_leases(
                        executor_lease_binding
                    )
                except Exception as compensation_error:
                    executor_compensation_error = compensation_error
        if task_resources and lease_result is not None:
            resources.release_resources(
                lease_owner,
                task_resources,
                expected_leases=[
                    resources._release_lease_snapshot(item)
                    for item in lease_result["leases"]
                ],
            )
        if executor_lease_binding is not None:
            if executor_record_state != "absent":
                raise RuntimeError(
                    "Bureau runtime-refresh task record persistence requires reconciliation; "
                    f"executor lease binding retained ({executor_record_state})"
                ) from exc
            if executor_compensation_error is not None:
                raise RuntimeError(
                    "Bureau runtime-refresh task start failed before persistence and exact "
                    "executor lease compensation failed; reconciliation is required"
                ) from executor_compensation_error
        raise
    launcher = {
        **_launch(record),
        "task_effect_classification": dict(task_effect_classification),
        **(
            {TASK_OUTPUT_LAUNCHER_BINDING_KEY: task_output_managed_from_attempt}
            if task_output_managed_from_attempt is not None
            else {}
        ),
    }
    if executor_lease_binding_evidence is not None:
        launcher = {
            **launcher,
            "runtime_refresh_executor_lease_binding": dict(
                executor_lease_binding_evidence
            ),
        }
    if retry_binding is not None:
        launcher = {**launcher, "retry_binding": dict(retry_binding)}
    if normalized_operation_identity is not None:
        launcher = {
            **launcher,
            "operation_identity": dict(normalized_operation_identity),
        }
    if operation_retry_binding is not None:
        launcher = {
            **launcher,
            "operation_retry_binding": dict(operation_retry_binding),
        }
    if reposkop_execution_attestation is not None:
        launcher = {
            **launcher,
            "reposkop_execution_attestation": dict(
                reposkop_execution_attestation
            ),
        }
    if reposkop_checkout_shadow_before is not None:
        launcher = {
            **launcher,
            "reposkop_checkout_shadow_before": dict(
                reposkop_checkout_shadow_before
            ),
        }
    state = _launch_state(launcher)
    stored = _set_state(task_id, state, launcher=launcher)
    lease_maintenance = _maintain_record_resources(stored, state)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-start",
        "task_id": task_id,
        "host": host,
        "transport": target["transport"],
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
        "authoritative_unit": unit,
        "argv_sha256": record["argv_sha256"],
        "execution_identity_sha256": execution_identity["identity_sha256"],
        "retry_binding": retry_binding,
        "operation_identity_sha256": (
            normalized_operation_identity["operation_identity_sha256"]
            if normalized_operation_identity is not None
            else None
        ),
        "operation_retry_binding": operation_retry_binding,
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
        "launcher_outcome_unknown": bool(launcher.get("outcome_unknown")),
        "task_output_managed_from_attempt": task_output_managed_from_attempt,
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "requested_resource_keys": requested_resources,
        "implicit_workspace_resource_key": implicit_workspace_resource,
        "repository_scope_manifest_sha256": (
            hashlib.sha256(
                _canonical_json(lease_metadata["scope_manifest"]).encode("utf-8")
            ).hexdigest()
            if lease_metadata is not None and "scope_manifest" in lease_metadata
            else None
        ),
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
        "resource_lease_maintenance": lease_maintenance,
        "runtime_refresh_executor_lease_binding": executor_lease_binding_evidence,
        "runtime_refresh_executor_prelaunch_recovery": executor_prelaunch_recovery,
        "routing_shadow_capture": routing_shadow_capture,
        "effect_profile": task_effect_classification["effect_profile"],
        "reposkop_policy": task_effect_classification["reposkop_policy"],
        "reposkop_cohort": task_effect_classification.get("reposkop_cohort"),
        "prospective_admission_verified": task_effect_classification.get(
            "prospective_admission_verified"
        ),
        "sampling_modulus": task_effect_classification.get("sampling_modulus"),
        "sampling_bucket": task_effect_classification.get("sampling_bucket"),
        "sampling_key_sha256": task_effect_classification.get(
            "sampling_key_sha256"
        ),
        "surface": task_effect_classification["surface"],
        "agent_executable": task_effect_classification.get(
            "agent_executable"
        ),
        "classification_source": task_effect_classification[
            "classification_source"
        ],
        "policy_version": task_effect_classification["policy_version"],
        "evaluation_id": reposkop_evaluation_id,
        "reposkop_checkout_binding_sha256": (
            reposkop_checkout_binding_sha256
        ),
        "reposkop_requested_audit_ref": reposkop_requested_audit_ref,
        "reposkop_completed_audit_ref": reposkop_completed_audit_ref,
        "reposkop_decision_audit_ref": reposkop_decision_audit_ref,
        "reposkop_execution_attestation_required": (
            task_effect_classification["reposkop_policy"] == "required"
        ),
        "reposkop_execution_attestation_sha256": (
            reposkop_execution_attestation[
                "execution_binding_sha256"
            ]
            if reposkop_execution_attestation is not None
            else None
        ),
        "reposkop_usage_key_sha256": (
            reposkop_execution_attestation.get("usage_key_sha256")
            if reposkop_execution_attestation is not None
            else None
        ),
        "reposkop_workspace_lease_resource_keys": (
            reposkop_execution_attestation.get(
                "workspace_lease_resource_keys", []
            )
            if reposkop_execution_attestation is not None
            else []
        ),
        "reposkop_checkout_shadow_before": reposkop_checkout_shadow_before,
    }
    base._append_audit(audit)
    return {
        "task": _public(stored),
        "audit": audit,
        "execution_identity": execution_identity,
        "retry_binding": retry_binding,
        "routing_shadow_capture": routing_shadow_capture,
        "operation_identity": normalized_operation_identity,
        "operation_retry_binding": operation_retry_binding,
        "reposkop_execution_attestation": reposkop_execution_attestation,
        "reposkop_checkout_shadow_before": reposkop_checkout_shadow_before,
        "task_effect_classification": task_effect_classification,
        "runtime_refresh_executor_lease_binding": executor_lease_binding_evidence,
        "runtime_refresh_executor_prelaunch_recovery": executor_prelaunch_recovery,
        "deduplicated_reuse": None,
    }


@_serialize_task_mutation
def grabowski_task_status(task_id: str) -> dict[str, Any]:
    """Observe one persistent task and refresh its recorded state."""
    operator._require_operator_capability("durable_job")
    record = _row(task_id)
    observation = _observe(record)
    effective_state = _effective_observed_state(record, observation["state"])
    lease_maintenance = _maintain_record_resources(record, effective_state)
    if lease_maintenance is not None:
        observation["lease_maintenance"] = lease_maintenance
    stored = _set_state(
        task_id,
        observation["state"],
        observation=observation,
    )
    result = _public(stored)
    import grabowski_task_attention as task_attention

    result["closeout"] = task_attention.terminal_closeout_plan(stored)
    result["lease_maintenance"] = lease_maintenance
    return result


def grabowski_task_routing_shadow_seal(
    task_id: str,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    execution_provenance: dict[str, Any],
    semantic_assessments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Seal one independently reviewed direct-task shadow outcome without routing effect."""
    record = _row(task_id)
    observation = _observe(record)
    effective_state = _effective_observed_state(record, observation["state"])
    if not _is_terminal_state(effective_state):
        raise RuntimeError("routing shadow outcome requires a terminal task")
    if not isinstance(execution_provenance, dict):
        raise ValueError("execution_provenance must be an object")
    execution_status = execution_provenance.get("status")
    if effective_state == "completed":
        if execution_status != "completed":
            raise ValueError(
                "completed task requires execution_provenance.status=completed"
            )
    elif execution_status not in {"execution_aborted", "infrastructure_failure"}:
        raise ValueError(
            "non-completed terminal task requires abort or infrastructure provenance"
        )
    cohort_root = Path(
        os.environ.get(
            "GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT",
            str(Path.home() / ".local/state/grabowski/operator-routing-shadow-cohort"),
        )
    ).expanduser()
    operator._require_operator_mutation(
        "durable_job",
        path=str(cohort_root),
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
    )
    import grabowski_operator_routing_shadow_capture as routing_shadow

    authoritative_task_identity = routing_shadow.build_direct_task_identity(
        host=str(record["host"]),
        argv_sha256=str(record["argv_sha256"]),
        cwd=str(record["cwd"]),
        resource_keys=_record_resource_keys(record),
        runtime_seconds=int(record["runtime_seconds"]),
    )
    sealed = routing_shadow.seal_direct_task_case(
        task_id=task_id,
        outcome=outcome,
        primary_evidence_refs=primary_evidence_refs,
        execution_provenance=execution_provenance,
        semantic_assessments=semantic_assessments,
        authoritative_task_identity=authoritative_task_identity,
        root=cohort_root,
    )
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-routing-shadow-seal",
        "task_id": task_id,
        "observed_task_state": effective_state,
        "record_id": sealed.get("record_id"),
        "eligibility_id": sealed.get("eligibility_id"),
        "case_id": sealed.get("case_id"),
        "status": sealed.get("status"),
        "record_schema_version": sealed.get("record_schema_version"),
        "no_effect": sealed.get("no_effect"),
    }
    base._append_audit(audit)
    return {
        "task_id": task_id,
        "observed_task_state": effective_state,
        "sealed": sealed,
        "audit": audit,
    }

def grabowski_task_logs(task_id: str, max_lines: int = 200) -> dict[str, Any]:
    """Read bounded redacted stdout and stderr for one local or fleet task."""
    operator._require_operator_capability("durable_job")
    if not isinstance(max_lines, int) or not 1 <= max_lines <= 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    record = _row(task_id)
    output_source = "root-journal-v1"
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(record, "journal", max_lines=max_lines),
            timeout_seconds=30,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    else:
        result = _read_task_output_files(record, max_lines)
        if result is None:
            output_source = "user-journal-fallback-v1"
            result = _dispatch(
                record["host"],
                [
                    "journalctl",
                    "--user",
                    "--unit",
                    _authoritative_unit(record),
                    "--no-pager",
                    "--output=cat",
                    "--lines",
                    str(max_lines),
                ],
                timeout_seconds=30,
            )
        else:
            output_source = "private-task-files-v1"
    return {
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "output_source": output_source,
        "result": result,
    }


@_serialize_task_mutation
def grabowski_task_cancel(task_id: str) -> dict[str, Any]:
    """Stop one task process group and retain its persistent task record."""
    record = _row(task_id)
    operator._require_operator_mutation(
        "durable_job",
        path=record["cwd"],
        repo=record["cwd"],
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
    )
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(record, "stop"),
            timeout_seconds=60,
        )
    else:
        result = _dispatch(
            record["host"],
            ["systemctl", "--user", "stop", _authoritative_unit(record)],
            timeout_seconds=60,
        )
    if result.get("outcome_unknown"):
        state = "outcome_unknown"
    else:
        state = "cancelled" if result["returncode"] == 0 else record["state"]
    cancel_observation = {"cancel": result}
    effective_state = _effective_observed_state(record, state)
    lease_maintenance = _maintain_record_resources(record, effective_state)
    if lease_maintenance is not None:
        cancel_observation["lease_maintenance"] = lease_maintenance
    stored = _set_state(task_id, state, observation=cancel_observation)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-cancel",
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "returncode": result["returncode"],
        "outcome_unknown": bool(result.get("outcome_unknown")),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "result": result, "audit": audit}


@_serialize_task_mutation
def grabowski_task_resume(
    task_id: str,
    *,
    _interrupted_recovery_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recreate a missing or stopped task unit from its persistent record."""
    record = _row(task_id)
    operator._require_operator_mutation(
        "durable_job",
        path=record["cwd"],
        repo=record["cwd"],
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
        opaque_command=True,
    )
    if _is_terminal_state(record["state"]):
        raise RuntimeError("Terminal task cannot be resumed")
    if record["resume_policy"] == "never":
        raise PermissionError("Task resume policy does not permit automatic retry")
    if (
        str(record["state"]) == "interrupted"
        and _interrupted_recovery_context is None
    ):
        raise PermissionError(
            "Interrupted task resume requires exact recovery evidence"
        )
    if record["resume_policy"] == "manual" and _interrupted_recovery_context is None:
        raise PermissionError("Task resume policy does not permit automatic retry")
    command = json.loads(record["argv_json"])
    recovery_gate = _require_recovery_gate(command)
    observation = _observe(record)
    if observation["state"] == "running":
        raise RuntimeError("Task is still running")
    if (
        observation["state"] == "completed"
        and _interrupted_recovery_context is None
    ):
        stored = _set_state(
            task_id,
            "completed",
            observation=observation,
        )
        raise RuntimeError("Task already completed; refusing retry")
    if (
        observation["state"] == "outcome_unknown"
        and _interrupted_recovery_context is None
    ):
        _set_state(
            task_id,
            "outcome_unknown",
            observation=observation,
        )
        raise RuntimeError("Task outcome is unknown; verify the authoritative unit before retry")
    interrupted_recovery_binding = None
    recovery_launcher_bindings: dict[str, Any] = {}
    if _interrupted_recovery_context is not None:
        interrupted_recovery_binding = _validate_interrupted_recovery_context(
            _interrupted_recovery_context,
            record=record,
            observation=observation,
        )
        recovery_launcher_bindings["interrupted_recovery_binding"] = (
            interrupted_recovery_binding
        )
        retained_retry_binding = _persisted_retry_binding_or_raise(record)
        if retained_retry_binding is not None:
            recovery_launcher_bindings["retry_binding"] = retained_retry_binding
    attempt = int(record["attempt"]) + 1
    task_output_managed_from_attempt = _task_output_managed_from_attempt(record)
    if not _is_root_systemd_backend(record):
        _resolved_host, resume_target, _legacy_local_alias = (
            _resolve_task_dispatch_host(str(record["host"]))
        )
        if task_output_managed_from_attempt is None:
            if resume_target["transport"] == "local":
                record = _bind_task_output_managed_from_attempt(
                    task_id,
                    expected_attempt=int(record["attempt"]),
                    managed_from_attempt=attempt,
                )
                task_output_managed_from_attempt = attempt
        elif resume_target["transport"] != "local":
            raise RuntimeError(
                "Task with managed local output cannot resume on non-local transport; "
                "restore the fleet host to local transport or start a new task"
            )
    if task_output_managed_from_attempt is not None:
        _ensure_local_task_output_root()
    unit = _task_unit(task_id, attempt)
    candidate = {**record, "attempt": attempt, "unit": unit, "authoritative_unit": unit}
    task_resources = _record_resource_keys(record)
    lease_owner = record.get("lease_owner_id") or _lease_owner(task_id)
    lease_metadata = None
    if task_resources:
        repository_resource = _task_repository_resource(task_resources)
        implicit_workspace_resource = _record_implicit_workspace_resource(
            record, repository_resource
        )
        repository_scope_manifest = _record_repository_scope_manifest(
            record, repository_resource
        )
        lease_metadata = _task_lease_metadata(
            task_id=task_id,
            host=str(record["host"]),
            attempt=attempt,
            repository_resource=repository_resource,
            implicit_workspace_resource=implicit_workspace_resource,
            repository_scope_manifest=repository_scope_manifest,
        )
    if interrupted_recovery_binding is not None:
        _set_state(
            task_id,
            "launching",
            launcher={
                "pending": True,
                **(
                    {TASK_OUTPUT_LAUNCHER_BINDING_KEY: task_output_managed_from_attempt}
                    if task_output_managed_from_attempt is not None
                    else {}
                ),
                **recovery_launcher_bindings,
            },
            observation=observation,
            unit=unit,
            authoritative_unit=unit,
            attempt=attempt,
        )
    lease_result = None
    lease_mode = None
    if task_resources:
        lease_ttl = min(
            resources.MAX_TTL_SECONDS,
            max(resources.MIN_TTL_SECONDS, int(record["runtime_seconds"]) + 300),
        )
        try:
            lease_result = resources.renew_resources(
                lease_owner,
                task_resources,
                ttl_seconds=lease_ttl,
            )
            lease_mode = "renewed"
        except (
            resources.ResourceLeaseMissing,
            resources.ResourceLeaseExpired,
        ):
            if lease_metadata is None:
                raise RuntimeError("task lease metadata missing for reacquisition")
            recovery_lease_metadata = dict(lease_metadata)
            recovery_lease_metadata["recovered_after_expiry"] = True
            lease_result = resources.acquire_resources(
                lease_owner,
                task_resources,
                purpose=f"persistent task {task_id}",
                ttl_seconds=lease_ttl,
                metadata=recovery_lease_metadata,
                _preserve_live_same_owner=True,
            )
            lease_mode = (
                "reconciled" if lease_result.get("preserved") else "reacquired"
            )
    launcher = _launch(candidate)
    if task_output_managed_from_attempt is not None:
        launcher = {
            **launcher,
            TASK_OUTPUT_LAUNCHER_BINDING_KEY: task_output_managed_from_attempt,
        }
    if interrupted_recovery_binding is not None:
        launcher = {
            **launcher,
            **recovery_launcher_bindings,
        }
    state = _launch_state(launcher)
    stored = _set_state(
        task_id,
        state,
        launcher=launcher,
        observation=observation,
        unit=unit,
        authoritative_unit=unit,
        attempt=attempt,
    )
    lease_maintenance = _maintain_record_resources(stored, state)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-resume",
        "task_id": task_id,
        "host": record["host"],
        "attempt": attempt,
        "unit": unit,
        "authoritative_unit": unit,
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "launcher_returncode": launcher["returncode"],
        "launcher_outcome_unknown": bool(launcher.get("outcome_unknown")),
        "task_output_managed_from_attempt": task_output_managed_from_attempt,
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
        "resource_lease_mode": lease_mode,
        "resource_lease_maintenance": lease_maintenance,
        "interrupted_recovery_binding": interrupted_recovery_binding,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


def _reconcile_candidate_rows(
    task_id: str = "",
    *,
    include_converged_terminal: bool = False,
) -> list[dict[str, Any]]:
    candidate_states = {
        "launching",
        "running",
        "outcome_unknown",
        "interrupted",
        "failed",
        "timed_out",
        "signalled",
    }
    if task_id:
        record = _row(task_id)
        rows = [record] if record["state"] in candidate_states else []
    else:
        with _database_connection() as connection:
            selected = connection.execute(
                "SELECT * FROM tasks WHERE state IN ('launching', 'running', 'outcome_unknown', 'interrupted', 'failed', 'timed_out', 'signalled') "
                "ORDER BY created_at_unix, task_id"
            ).fetchall()
        rows = [dict(row) for row in selected]

    candidates: list[dict[str, Any]] = []
    for record in rows:
        if (
            not include_converged_terminal
            and _is_terminal_state(str(record["state"]))
        ):
            terminal_valid, lease_valid = _terminal_convergence_evidence(record)
            if terminal_valid and lease_valid:
                continue
        candidates.append(record)
    return candidates


def _validate_reconcile_batch_size(batch_size: int) -> int:
    if (
        isinstance(batch_size, bool)
        or not isinstance(batch_size, int)
        or not 1 <= batch_size <= TASK_RECONCILE_BATCH_LIMIT
    ):
        raise ValueError(
            f"batch_size must be between 1 and {TASK_RECONCILE_BATCH_LIMIT}"
        )
    return batch_size


def _validate_reconcile_phase_limit(limit: int) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 0 <= limit <= TASK_RECONCILE_BATCH_LIMIT
    ):
        raise ValueError(
            f"phase limit must be between 0 and {TASK_RECONCILE_BATCH_LIMIT}"
        )
    return limit


def _load_reconcile_sequence_counter(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT value FROM metadata WHERE key=?",
        (TASK_RECONCILE_SEQUENCE_COUNTER_KEY,),
    ).fetchone()
    if row is None:
        return 0
    raw = str(row[0])
    if not raw.isdecimal():
        raise RuntimeError("Task reconcile sequence metadata is invalid")
    value = int(raw)
    if value < 0 or value > TASK_RECONCILE_SEQUENCE_MAX:
        raise RuntimeError("Task reconcile sequence metadata is invalid")
    return value


def _register_task_reconcile_sequence(
    connection: sqlite3.Connection,
    task_id: str,
) -> int:
    identifier = _validate_task_id(task_id)
    current = _load_reconcile_sequence_counter(connection)
    if current >= TASK_RECONCILE_SEQUENCE_MAX:
        raise RuntimeError("Task reconcile sequence is exhausted")
    sequence = current + 1
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (TASK_RECONCILE_SEQUENCE_COUNTER_KEY, str(sequence)),
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?)",
        (f"{TASK_RECONCILE_SEQUENCE_KEY_PREFIX}{identifier}", str(sequence)),
    )
    return sequence


def _load_reconcile_cycle(
    connection: sqlite3.Connection,
) -> dict[str, Any] | None:
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key=?",
        (TASK_RECONCILE_CURSOR_METADATA_KEY,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise RuntimeError("Task reconcile cursor metadata is ambiguous")
    try:
        payload = json.loads(str(rows[0][0]))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Task reconcile cursor metadata is invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Task reconcile cursor metadata is invalid")
    if set(payload) == {"created_at_unix", "task_id"}:
        created_at_unix = payload["created_at_unix"]
        task_id = payload["task_id"]
        if (
            isinstance(created_at_unix, bool)
            or not isinstance(created_at_unix, int)
            or created_at_unix < 0
            or not isinstance(task_id, str)
            or TASK_ID.fullmatch(task_id) is None
        ):
            raise RuntimeError("Task reconcile cursor metadata is invalid")
        # A v1 cursor has no insertion high-water mark. Restarting the bounded
        # scan may replay rows, but cannot falsely claim a completed cycle.
        return None
    if set(payload) != {
        "version",
        "phase",
        "high_water_sequence",
        "cursor",
    }:
        raise RuntimeError("Task reconcile cursor metadata is invalid")
    version = payload["version"]
    phase = payload["phase"]
    high_water_sequence = payload["high_water_sequence"]
    cursor_payload = payload["cursor"]
    if (
        type(version) is not int
        or version != TASK_RECONCILE_CYCLE_VERSION
        or phase != TASK_RECONCILE_CYCLE_PHASE
        or type(high_water_sequence) is not int
        or high_water_sequence < 0
        or high_water_sequence > TASK_RECONCILE_SEQUENCE_MAX
    ):
        raise RuntimeError("Task reconcile cursor metadata is invalid")
    cursor: tuple[int, str] | None = None
    if cursor_payload is not None:
        if not isinstance(cursor_payload, dict) or set(cursor_payload) != {
            "created_at_unix",
            "task_id",
        }:
            raise RuntimeError("Task reconcile cursor metadata is invalid")
        created_at_unix = cursor_payload["created_at_unix"]
        task_id = cursor_payload["task_id"]
        if (
            isinstance(created_at_unix, bool)
            or not isinstance(created_at_unix, int)
            or created_at_unix < 0
            or not isinstance(task_id, str)
            or TASK_ID.fullmatch(task_id) is None
        ):
            raise RuntimeError("Task reconcile cursor metadata is invalid")
        cursor = (created_at_unix, task_id)
    return {
        "version": version,
        "phase": phase,
        "high_water_sequence": high_water_sequence,
        "cursor": cursor,
    }


def _write_reconcile_cycle(
    connection: sqlite3.Connection,
    cycle: dict[str, Any] | None,
) -> None:
    if cycle is None:
        connection.execute(
            "DELETE FROM metadata WHERE key=?",
            (TASK_RECONCILE_CURSOR_METADATA_KEY,),
        )
        return
    cursor = cycle["cursor"]
    cursor_payload = (
        None
        if cursor is None
        else {"created_at_unix": cursor[0], "task_id": cursor[1]}
    )
    payload = _canonical_json(
        {
            "version": cycle["version"],
            "phase": cycle["phase"],
            "high_water_sequence": cycle["high_water_sequence"],
            "cursor": cursor_payload,
        }
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (TASK_RECONCILE_CURSOR_METADATA_KEY, payload),
    )


def _load_reconcile_phase_turn(
    connection: sqlite3.Connection,
) -> str:
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key=?",
        (TASK_RECONCILE_PHASE_TURN_METADATA_KEY,),
    ).fetchall()
    if not rows:
        return TASK_RECONCILE_PHASE_TERMINALIZATION
    if len(rows) != 1 or str(rows[0][0]) not in {
        TASK_RECONCILE_PHASE_TERMINALIZATION,
        TASK_RECONCILE_PHASE_TASKS,
    }:
        raise RuntimeError("Task reconcile phase turn metadata is invalid")
    return str(rows[0][0])


def _write_reconcile_phase_turn(
    connection: sqlite3.Connection,
    phase_turn: str,
) -> None:
    if phase_turn not in {
        TASK_RECONCILE_PHASE_TERMINALIZATION,
        TASK_RECONCILE_PHASE_TASKS,
    }:
        raise RuntimeError("Task reconcile phase turn is invalid")
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (TASK_RECONCILE_PHASE_TURN_METADATA_KEY, phase_turn),
    )


def _save_reconcile_cycle(
    cycle: dict[str, Any] | None,
    *,
    phase_turn: str,
    active_refresh_cursor: tuple[int, int, str] | None,
) -> None:
    with _database_connection() as connection:
        _write_reconcile_cycle(connection, cycle)
        _write_reconcile_phase_turn(connection, phase_turn)
        _write_active_refresh_cursor(connection, active_refresh_cursor)


def _ensure_reconcile_cycle(
    connection: sqlite3.Connection,
) -> dict[str, Any]:
    cycle = _load_reconcile_cycle(connection)
    if cycle is not None:
        return cycle
    cycle = {
        "version": TASK_RECONCILE_CYCLE_VERSION,
        "phase": TASK_RECONCILE_CYCLE_PHASE,
        "high_water_sequence": _load_reconcile_sequence_counter(connection),
        "cursor": None,
    }
    # Persist the cycle boundary before any external observation. A crash
    # from this point replays the same bounded cycle.
    _write_reconcile_cycle(connection, cycle)
    return cycle


def _select_reconcile_task_rows(
    connection: sqlite3.Connection,
    cycle: dict[str, Any],
    *,
    limit: int,
    excluded_task_ids: set[str] | None = None,
) -> list[sqlite3.Row]:
    candidate_clause = (
        "(state IN ('launching', 'running', 'outcome_unknown', 'interrupted', "
        "'failed', 'timed_out', 'signalled') OR "
        "(state IN ('completed', 'cancelled') AND "
        "launcher_json LIKE '%\"reposkop_checkout_shadow_terminal_prepare\"%' AND "
        "shadow_terminal_finalized.key IS NULL))"
    )
    parameters: list[Any] = [
        REPOSKOP_SHADOW_TERMINAL_FINALIZED_METADATA_PREFIX,
        TASK_RECONCILE_SEQUENCE_KEY_PREFIX,
        cycle["high_water_sequence"],
    ]
    excluded = sorted(excluded_task_ids or ())
    excluded_clause = ""
    if excluded:
        excluded_clause = (
            " AND tasks.task_id NOT IN ("
            + ",".join("?" for _ in excluded)
            + ")"
        )
        parameters.extend(excluded)
    cursor = cycle["cursor"]
    cursor_clause = ""
    if cursor is not None:
        cursor_clause = (
            " AND (created_at_unix > ? OR "
            "(created_at_unix = ? AND task_id > ?))"
        )
        parameters.extend((cursor[0], cursor[0], cursor[1]))
    parameters.append(limit)
    return connection.execute(
        "SELECT tasks.* FROM tasks "
        "LEFT JOIN metadata AS shadow_terminal_finalized ON "
        "shadow_terminal_finalized.key = ? || tasks.task_id || ':' || "
        "COALESCE(tasks.terminalization_sha256, '') || ':' || "
        "COALESCE(tasks.lifecycle_receipt_sha256, '') "
        "AND shadow_terminal_finalized.value = tasks.lifecycle_receipt_sha256 "
        "LEFT JOIN metadata AS reconcile_order "
        "ON reconcile_order.key = ? || tasks.task_id "
        f"WHERE {candidate_clause} "
        "AND (reconcile_order.value IS NULL "
        f"OR CAST(reconcile_order.value AS INTEGER) <= ?){excluded_clause}{cursor_clause} "
        "ORDER BY created_at_unix, task_id LIMIT ?",
        parameters,
    ).fetchall()


def _reconcile_task_phase_has_work(
    *,
    excluded_task_ids: set[str] | None = None,
) -> bool:
    with _database_connection() as connection:
        cycle = _ensure_reconcile_cycle(connection)
        return bool(
            _select_reconcile_task_rows(
                connection,
                cycle,
                limit=1,
                excluded_task_ids=excluded_task_ids,
            )
        )


def _load_active_refresh_cursor(
    connection: sqlite3.Connection,
) -> tuple[int, int, str] | None:
    rows = connection.execute(
        "SELECT value FROM metadata WHERE key=?",
        (TASK_RECONCILE_ACTIVE_CURSOR_METADATA_KEY,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise RuntimeError("Task reconcile active cursor metadata is ambiguous")
    try:
        payload = json.loads(str(rows[0][0]))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Task reconcile active cursor metadata is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "updated_at_unix",
        "created_at_unix",
        "task_id",
    }:
        raise RuntimeError("Task reconcile active cursor metadata is invalid")
    updated_at_unix = payload["updated_at_unix"]
    created_at_unix = payload["created_at_unix"]
    task_id = payload["task_id"]
    if (
        isinstance(updated_at_unix, bool)
        or not isinstance(updated_at_unix, int)
        or updated_at_unix < 0
        or isinstance(created_at_unix, bool)
        or not isinstance(created_at_unix, int)
        or created_at_unix < 0
        or not isinstance(task_id, str)
        or TASK_ID.fullmatch(task_id) is None
    ):
        raise RuntimeError("Task reconcile active cursor metadata is invalid")
    return updated_at_unix, created_at_unix, task_id


def _write_active_refresh_cursor(
    connection: sqlite3.Connection,
    cursor: tuple[int, int, str] | None,
) -> None:
    if cursor is None:
        connection.execute(
            "DELETE FROM metadata WHERE key=?",
            (TASK_RECONCILE_ACTIVE_CURSOR_METADATA_KEY,),
        )
        return
    payload = _canonical_json(
        {
            "updated_at_unix": cursor[0],
            "created_at_unix": cursor[1],
            "task_id": cursor[2],
        }
    )
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (TASK_RECONCILE_ACTIVE_CURSOR_METADATA_KEY, payload),
    )


def _reconcile_active_refresh_page(limit: int) -> dict[str, Any]:
    bounded_limit = _validate_reconcile_phase_limit(limit)
    now = _now()
    active_states = tuple(TASK_STATE_PROJECTIONS["active"])
    placeholders = ",".join("?" for _ in active_states)
    with _database_connection() as connection:
        cursor_before = _load_active_refresh_cursor(connection)
        if bounded_limit == 0:
            return {
                "rows": [],
                "examined": 0,
                "cursor_before": cursor_before,
                "cursor_after": cursor_before,
                "cycle_completed": False,
            }
        parameters: list[Any] = [
            *active_states,
            now - TASK_ACTIVE_OBSERVATION_MAX_AGE_SECONDS,
            now,
        ]
        cursor_clause = ""
        if cursor_before is not None:
            cursor_clause = (
                " AND (updated_at_unix > ? OR "
                "(updated_at_unix = ? AND created_at_unix > ?) OR "
                "(updated_at_unix = ? AND created_at_unix = ? AND task_id > ?))"
            )
            parameters.extend(
                (
                    cursor_before[0],
                    cursor_before[0],
                    cursor_before[1],
                    cursor_before[0],
                    cursor_before[1],
                    cursor_before[2],
                )
            )
        parameters.append(bounded_limit + 1)
        examined_rows = connection.execute(
            f"SELECT * FROM tasks WHERE state IN ({placeholders}) "
            "AND (updated_at_unix <= ? OR created_at_unix + runtime_seconds <= ?)"
            f"{cursor_clause} "
            "ORDER BY updated_at_unix, created_at_unix, task_id LIMIT ?",
            parameters,
        ).fetchall()
    has_more = len(examined_rows) > bounded_limit
    examined_rows = examined_rows[:bounded_limit]
    selected = [
        dict(row)
        for row in examined_rows
        if not _task_has_fresh_active_observation(dict(row), now=now)
    ]
    cursor_after = (
        (
            int(examined_rows[-1]["updated_at_unix"]),
            int(examined_rows[-1]["created_at_unix"]),
            str(examined_rows[-1]["task_id"]),
        )
        if examined_rows and has_more
        else None
    )
    return {
        "rows": selected,
        "examined": len(examined_rows),
        "cursor_before": cursor_before,
        "cursor_after": cursor_after,
        "cycle_completed": not has_more,
    }


def _reconcile_task_candidate_page(
    limit: int,
    *,
    excluded_task_ids: set[str] | None = None,
) -> dict[str, Any]:
    bounded_limit = _validate_reconcile_phase_limit(limit)
    with _database_connection() as connection:
        cycle = _ensure_reconcile_cycle(connection)
        cursor_before = cycle["cursor"]
        selected = _select_reconcile_task_rows(
            connection,
            cycle,
            limit=bounded_limit + 1,
            excluded_task_ids=excluded_task_ids,
        )
    has_more = len(selected) > bounded_limit
    examined_rows = selected[:bounded_limit]
    examined = [dict(row) for row in examined_rows]
    cursor_after = (
        (
            int(examined[-1]["created_at_unix"]),
            str(examined[-1]["task_id"]),
        )
        if examined and has_more
        else None
    )
    cycle_after = (
        {
            **cycle,
            "cursor": cursor_after,
        }
        if has_more
        else None
    )
    candidates: list[dict[str, Any]] = []
    for record in examined:
        terminalization = resources.task_terminalization_record(
            str(record["task_id"])
        )
        if (
            terminalization is not None
            and terminalization["phase"] != "projected"
        ):
            # Pending transitions are owned exclusively by the separately
            # bounded fair recovery cursor above. Advancing the task cursor
            # past them preserves task-cycle fairness without exceeding the
            # terminalization recovery budget through _set_state().
            continue
        if _is_terminal_state(str(record["state"])):
            terminal_valid, lease_valid = _terminal_convergence_evidence(record)
            if terminal_valid and lease_valid:
                if _reposkop_shadow_terminal_recovery_needed(record):
                    candidates.append(record)
                continue
        candidates.append(record)
    return {
        "rows": candidates,
        "examined": len(examined),
        "cursor_before": cursor_before,
        "cursor_after": cursor_after,
        "cycle_wrapped": False,
        "cycle_phase": cycle["phase"],
        "cycle_high_water_sequence": cycle["high_water_sequence"],
        "cycle_completed": not has_more,
        "cycle_after": cycle_after,
        "limit": bounded_limit,
    }


def _reconcile_candidate_batch(batch_size: int) -> dict[str, Any]:
    limit = _validate_reconcile_batch_size(batch_size)
    active_refresh_limit = min(
        TASK_RECONCILE_ACTIVE_REFRESH_MAX,
        limit // 5,
    )
    active_refresh_page = _reconcile_active_refresh_page(active_refresh_limit)
    active_refresh_rows = active_refresh_page["rows"]
    active_refresh_ids = {str(row["task_id"]) for row in active_refresh_rows}
    active_refresh_examined = len(active_refresh_rows)
    fair_limit = limit - active_refresh_examined
    # Validate persisted terminal recovery truth before either phase can
    # observe or mutate task state, even when the task phase has first turn.
    terminalization_cycle = _load_terminalization_recovery_cycle()
    with _database_connection() as connection:
        stored_phase_turn = _load_reconcile_phase_turn(connection)
    terminalization_has_work = resources.pending_task_terminalizations_exist(
        cursor=(
            None
            if terminalization_cycle is None
            else terminalization_cycle["cursor"]
        ),
        high_water=(
            None
            if terminalization_cycle is None
            else terminalization_cycle["high_water"]
        ),
    )
    task_has_work = _reconcile_task_phase_has_work(
        excluded_task_ids=active_refresh_ids,
    )
    both_phases_have_work = terminalization_has_work and task_has_work
    if not both_phases_have_work:
        phase_first = TASK_RECONCILE_PHASE_TERMINALIZATION
        terminalization_recovery = _recover_pending_task_terminalizations(
            limit=fair_limit
        )
        task_page = _reconcile_task_candidate_page(
            fair_limit - int(terminalization_recovery["examined"]),
            excluded_task_ids=active_refresh_ids,
        )
    else:
        phase_first = stored_phase_turn
        first_phase_limit = (fair_limit + 1) // 2
        if phase_first == TASK_RECONCILE_PHASE_TERMINALIZATION:
            terminalization_recovery = _recover_pending_task_terminalizations(
                limit=first_phase_limit
            )
            task_page = _reconcile_task_candidate_page(
                fair_limit - int(terminalization_recovery["examined"]),
                excluded_task_ids=active_refresh_ids,
            )
        else:
            task_page = _reconcile_task_candidate_page(
                first_phase_limit,
                excluded_task_ids=active_refresh_ids,
            )
            terminalization_recovery = _recover_pending_task_terminalizations(
                limit=fair_limit - int(task_page["examined"])
            )
    fair_examined = int(task_page["examined"]) + int(
        terminalization_recovery["examined"]
    )
    total_examined = active_refresh_examined + fair_examined
    if total_examined > limit:
        raise RuntimeError("Task reconcile shared batch budget was exceeded")
    task_examined = int(task_page["examined"])
    if both_phases_have_work:
        phase_next = (
            TASK_RECONCILE_PHASE_TASKS
            if phase_first == TASK_RECONCILE_PHASE_TERMINALIZATION
            else TASK_RECONCILE_PHASE_TERMINALIZATION
        )
    else:
        phase_next = stored_phase_turn
    fair_rows = [
        row
        for row in task_page["rows"]
        if str(row["task_id"]) not in active_refresh_ids
    ]
    return {
        **task_page,
        "rows": [*active_refresh_rows, *fair_rows],
        "limit": limit,
        "active_refresh": {
            "limit": active_refresh_limit,
            "examined": int(active_refresh_page["examined"]),
            "selected": active_refresh_examined,
            "cursor_before": active_refresh_page["cursor_before"],
            "cursor_after": active_refresh_page["cursor_after"],
            "cycle_completed": active_refresh_page["cycle_completed"],
            "max_observation_age_seconds": TASK_ACTIVE_OBSERVATION_MAX_AGE_SECONDS,
        },
        "task_limit": int(task_page["limit"]),
        "task_examined": task_examined,
        "terminalization_recovery": terminalization_recovery,
        "phase_first": phase_first,
        "phase_next": phase_next,
        "total_examined": total_examined,
        "total_examined_limit": limit,
    }


def _terminal_convergence_evidence(record: dict[str, Any]) -> tuple[bool, bool]:
    terminalization = resources.task_terminalization_record(
        str(record["task_id"]), include_projection=True
    )
    if terminalization is None:
        return False, False
    projection = terminalization.get("task_projection")
    terminal_valid = bool(
        terminalization.get("phase") == "projected"
        and terminalization.get("lifecycle_receipt_sha256")
        == record.get("lifecycle_receipt_sha256")
        and terminalization.get("transition_sha256")
        == record.get("terminalization_sha256")
        and isinstance(projection, dict)
        and projection.get("task_id") == record.get("task_id")
        and projection.get("attempt") == record.get("attempt")
        and projection.get("state") == record.get("state")
    )
    requested = terminalization.get("requested_resource_keys")
    revoked = terminalization.get("revoked_resource_keys")
    missing = terminalization.get("missing_resource_keys")
    lease_valid = bool(
        terminal_valid
        and isinstance(requested, list)
        and isinstance(revoked, list)
        and isinstance(missing, list)
        and not missing
        and set(requested) == set(revoked)
    )
    return terminal_valid, lease_valid


def _reconcile_observation(record: dict[str, Any]) -> dict[str, Any]:
    terminal_valid, _ = _terminal_convergence_evidence(record)
    if _is_terminal_state(str(record["state"])) and terminal_valid:
        return {
            "state": record["state"],
            "properties": {},
            "probe": None,
            "observer": {
                "kind": "terminal-evidence-v1",
                "execution_backend": _execution_backend(record),
                "systemd_scope": _systemd_scope(record),
            },
            "observed_at_unix": _now(),
            "terminal_evidence_reused": True,
        }
    return _observe(record)


def _unknown_fleet_host_error(exc: ValueError) -> bool:
    return str(exc).startswith("Unknown fleet host: ")


def _reconcile_unknown_host(record: dict[str, Any], exc: ValueError) -> dict[str, Any]:
    current_state = str(record["state"])
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "current_state": current_state,
        "resume_policy": record["resume_policy"],
        "reason": f"host retired or unregistered: {_redact_reason(str(exc))}",
        "reason_class": "host_retired_or_unregistered",
        "retryable": False,
        "automatic_resume_allowed": False,
        # This path is reached only when no reusable terminal evidence exists.
        # A retired host cannot provide a fresh observation, so the record must
        # remain explicitly blocked until an owner supplies bounded closeout evidence.
        "owner_decision_required": True,
        "terminal_evidence_required": True,
    }


def _terminal_convergence_classification(
    record: dict[str, Any],
    observation: dict[str, Any],
    *,
    observation_denied: bool = False,
) -> dict[str, Any]:
    terminal_valid, lease_valid = _terminal_convergence_evidence(record)
    current_state = str(record["state"])
    observed_state = str(observation.get("state") or current_state)
    if _is_terminal_state(current_state) and terminal_valid:
        observed_state = current_state
    return terminal_convergence.classify_terminal_failure(
        current_state=current_state,
        observed_state=observed_state,
        resume_policy=str(record["resume_policy"]),
        terminal_evidence_valid=terminal_valid,
        lease_evidence_valid=lease_valid,
        retry_count=max(0, int(record["attempt"]) - 1),
        retry_limit=1,
        observation_denied=observation_denied,
    )


def _terminal_retry_command(record: dict[str, Any]) -> list[str]:
    command = json.loads(record["argv_json"])
    if (
        not isinstance(command, list)
        or any(not isinstance(item, str) for item in command)
        or not command
    ):
        raise RuntimeError("stored task argv is invalid for retry")
    if (
        str(record["host"]) != "local"
        or _execution_backend(record) != "systemd-user"
        or len(command) < 6
        or command[0] != FLOCK_EXECUTABLE
        or command[1] != "--shared"
        or Path(command[3]).name != Path(SYSTEMD_ENV_EXECUTABLE).name
    ):
        return command
    replay = command[3:]
    managed_target = _explicit_managed_cargo_target_dir(replay)
    if managed_target is None:
        return command
    # Pure path validation only: do not prepare the lock root here. Named
    # reconcile retries must remain effect-free until grabowski_task_start has
    # run retained-successor admission.
    expected_lock = _managed_cargo_lifecycle_lock_path(managed_target)
    if command[2] != str(expected_lock):
        raise RuntimeError("stored managed Cargo retry lock binding is invalid")
    return replay


def _terminal_retry_successor(
    record: dict[str, Any],
    *,
    reason: str,
    explicit_policy_override: bool = False,
) -> dict[str, Any]:
    context = (
        json.loads(record["chronik_context_json"])
        if record.get("chronik_context_json")
        else {}
    )
    retry_context = _build_terminal_retry_context(record, reason=reason)
    started = grabowski_task_start(
        str(record["host"]),
        _terminal_retry_command(record),
        cwd=str(record["cwd"]),
        runtime_seconds=int(record["runtime_seconds"]),
        resume_policy="manual",
        cpu_weight=int(record["cpu_weight"]),
        io_weight=int(record["io_weight"]),
        memory_max_bytes=record.get("memory_max_bytes"),
        resource_keys=_record_resource_keys(record),
        chronik_outbox=bool(record.get("chronik_outbox_enabled")),
        chronik_outbox_state_root=record.get("chronik_outbox_state_root"),
        chronik_operation=str(context.get("operation") or "other"),
        chronik_component=str(context.get("component") or ""),
        chronik_bureau_task_id=str(context.get("bureau_task_id") or ""),
        chronik_pr_number=(
            int(context["pr_number"])
            if isinstance(context.get("pr_number"), int)
            else None
        ),
        effect_profile=(
            (_record_task_effect_classification(record) or {}).get(
                "effect_profile"
            )
        ),
        _retry_context=retry_context,
    )
    task = dict(started["task"])
    task["retry_of_task_id"] = record["task_id"]
    task["retry_reason"] = _redact_reason(reason)
    task["retry_context_sha256"] = retry_context["context_sha256"]
    task["explicit_policy_override"] = explicit_policy_override
    task["automatic_retry_budget_exhausted_after_start"] = True
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile-retry-successor",
            "source_task_id": record["task_id"],
            "source_lifecycle_receipt_sha256": record.get(
                "lifecycle_receipt_sha256"
            ),
            "successor_task_id": task["task_id"],
            "successor_resume_policy": task["resume_policy"],
            "source_execution_identity_sha256": retry_context[
                "source_execution_identity_sha256"
            ],
            "retry_context_sha256": retry_context["context_sha256"],
            "explicit_policy_override": explicit_policy_override,
            "source_resume_policy": retry_context["source_resume_policy"],
            "reason": _redact_reason(reason),
        }
    )
    return task


def _reconcile_blocker(record: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any] | None:
    classification = _terminal_convergence_classification(record, observation)
    if classification["reason_class"] == "running":
        return None
    if classification["automatic_resume_allowed"] is True:
        return None
    return {
        "task_id": record["task_id"],
        "resume_policy": record["resume_policy"],
        "reason": classification["reason"],
        "reason_class": classification["reason_class"],
        "retryable": classification["retryable"],
        "automatic_resume_allowed": classification["automatic_resume_allowed"],
        "owner_decision_required": classification["owner_decision_required"],
        "terminal_evidence_required": classification["terminal_evidence_required"],
        "lease_evidence_required": classification["lease_evidence_required"],
    }


def _reconcile_observe_denial(record: dict[str, Any], exc: PermissionError) -> dict[str, Any]:
    classification = _terminal_convergence_classification(
        record,
        {"state": record["state"]},
        observation_denied=True,
    )
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "current_state": record["state"],
        "resume_policy": record["resume_policy"],
        "reason": f"observation denied: {_redact_reason(str(exc))}",
        "reason_class": classification["reason_class"],
        "retryable": classification["retryable"],
        "automatic_resume_allowed": classification["automatic_resume_allowed"],
        "owner_decision_required": classification["owner_decision_required"],
    }


def _reconcile_candidate_states() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                "launching",
                "running",
                "outcome_unknown",
                "interrupted",
                "failed",
                "timed_out",
                "signalled",
            }
        )
    )


def _sqlite_rows_revision(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[Any, ...] = (),
) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    for row in connection.execute(query, parameters):
        encoded = _canonical_json(dict(row)).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    return {"row_count": count, "rows_sha256": digest.hexdigest()}


def _reconcile_resource_store_revision() -> dict[str, Any]:
    version = resources._preflight_resource_store()
    if version is None:
        return {"present": False, "schema_version": None, "tables": {}}
    with resources._resource_readonly_sqlite(resources.RESOURCE_DB) as connection:
        connection.execute("BEGIN")
        table_names = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        tables: dict[str, Any] = {}
        table_queries = {
            "leases": (
                "SELECT * FROM leases WHERE owner_id LIKE 'task:%' "
                "ORDER BY resource_key"
            ),
            "task_terminalizations": (
                "SELECT * FROM task_terminalizations ORDER BY task_id"
            ),
            "task_authority_adoptions": (
                "SELECT * FROM task_authority_adoptions ORDER BY task_id"
            ),
        }
        for table, query in table_queries.items():
            tables[table] = (
                _sqlite_rows_revision(connection, query)
                if table in table_names
                else {"absent": True}
            )
    return {
        "present": True,
        "schema_version": version,
        "tables": tables,
    }


def _reconcile_check_store_snapshot(
    task_connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    if task_connection is None:
        with _task_read_snapshot() as connection:
            return _reconcile_check_store_snapshot(connection)
    candidate_states = _reconcile_candidate_states()
    placeholders = ",".join("?" for _ in candidate_states)
    material = {
        "schema_version": 1,
        "task_store": _sqlite_rows_revision(
            task_connection,
            f"SELECT * FROM tasks WHERE state IN ({placeholders}) "
            "ORDER BY task_id",
            candidate_states,
        ),
        "resource_store": _reconcile_resource_store_revision(),
    }
    return {**material, "snapshot_sha256": _sha256_json(material)}


def _validate_reconcile_check_limit(limit: int) -> int:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= TASK_RECONCILE_CHECK_LIMIT
    ):
        raise ValueError(
            f"limit must be between 1 and {TASK_RECONCILE_CHECK_LIMIT}"
        )
    return limit


def _reconcile_check_candidate_page(
    *,
    limit: int,
    cursor: str | None,
) -> dict[str, Any]:
    page_started_ns = time.perf_counter_ns()
    bounded_limit = _validate_reconcile_check_limit(limit)
    candidate_states = _reconcile_candidate_states()
    placeholders = ",".join("?" for _ in candidate_states)
    with _task_read_snapshot() as connection:
        connection.execute("SELECT 1 FROM tasks LIMIT 1").fetchone()
        snapshot_started_ns = time.perf_counter_ns()
        snapshot = _reconcile_check_store_snapshot(connection)
        snapshot_ms = round(
            (time.perf_counter_ns() - snapshot_started_ns) / 1_000_000,
            3,
        )
        query_started_ns = time.perf_counter_ns()
        snapshot_scope = TASK_RECONCILE_CHECK_CURSOR_SCOPE
        scope = f"{snapshot_scope}:{snapshot['snapshot_sha256']}"
        position = consumer_surface.decode_cursor(
            cursor,
            scope,
            snapshot_scope=snapshot_scope,
        )
        cursor_created_at: int | None = None
        cursor_task_id: str | None = None
        if position is not None:
            cursor_created_at = position.get("created_at_unix")
            cursor_task_id = position.get("task_id")
            if (
                isinstance(cursor_created_at, bool)
                or not isinstance(cursor_created_at, int)
                or cursor_created_at < 0
                or not isinstance(cursor_task_id, str)
                or TASK_ID.fullmatch(cursor_task_id) is None
            ):
                raise ValueError("cursor position is invalid")
        where = f"state IN ({placeholders})"
        parameters: list[Any] = list(candidate_states)
        if cursor_created_at is not None and cursor_task_id is not None:
            where += (
                " AND (created_at_unix > ? OR "
                "(created_at_unix = ? AND task_id > ?))"
            )
            parameters.extend(
                (cursor_created_at, cursor_created_at, cursor_task_id)
            )
        rows = connection.execute(
            f"SELECT * FROM tasks WHERE {where} "
            "ORDER BY created_at_unix, task_id LIMIT ?",
            (*parameters, bounded_limit + 1),
        ).fetchall()
        total_candidates = int(
            connection.execute(
                f"SELECT COUNT(*) FROM tasks WHERE state IN ({placeholders})",
                candidate_states,
            ).fetchone()[0]
        )
        cursor_and_query_ms = round(
            (time.perf_counter_ns() - query_started_ns) / 1_000_000,
            3,
        )
    has_more = len(rows) > bounded_limit
    page_rows = [dict(row) for row in rows[:bounded_limit]]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = consumer_surface.encode_cursor(
            scope,
            {
                "created_at_unix": int(last["created_at_unix"]),
                "task_id": str(last["task_id"]),
            },
        )
    return {
        "rows": page_rows,
        "limit": bounded_limit,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "snapshot": snapshot,
        "total_candidates": total_candidates,
        "timings_ms": {
            "snapshot": snapshot_ms,
            "cursor_and_query": cursor_and_query_ms,
            "page_setup_total": round(
                (time.perf_counter_ns() - page_started_ns) / 1_000_000,
                3,
            ),
        },
    }


def reconcile_tasks_check(
    *,
    task_id: str = "",
    limit: int = DEFAULT_TASK_RECONCILE_CHECK_LIMIT,
    cursor: str | None = None,
) -> dict[str, Any]:
    check_started_ns = time.perf_counter_ns()
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
        if limit != DEFAULT_TASK_RECONCILE_CHECK_LIMIT or cursor is not None:
            raise ValueError("task-specific reconcile check cannot use limit or cursor")
        rows = _reconcile_candidate_rows(
            task_id,
            include_converged_terminal=True,
        )
        page = None
    else:
        page = _reconcile_check_candidate_page(limit=limit, cursor=cursor)
        rows = []
        for record in page["rows"]:
            if _is_terminal_state(str(record["state"])):
                terminal_valid, lease_valid = _terminal_convergence_evidence(record)
                if terminal_valid and lease_valid:
                    continue
            rows.append(record)
    observations: list[dict[str, Any]] = []
    would_refresh: list[dict[str, Any]] = []
    would_release: list[str] = []
    would_resume: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    compact = not bool(task_id)
    observation_started_ns = time.perf_counter_ns()
    for record in rows:
        try:
            observation = _reconcile_observation(record)
        except PermissionError as exc:
            blocked.append(_reconcile_observe_denial(record, exc))
            continue
        except ValueError as exc:
            if not _unknown_fleet_host_error(exc):
                raise
            blocked.append(_reconcile_unknown_host(record, exc))
            continue
        classification = _terminal_convergence_classification(record, observation)
        resource_keys = _record_resource_keys(record)
        item = {
            "task_id": record["task_id"],
            "current_state": record["state"],
            "observed_state": observation["state"],
            "resume_policy": record["resume_policy"],
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
            **(
                {
                    "resource_key_count": len(resource_keys),
                    "resource_keys_sha256": _sha256_json(resource_keys),
                }
                if compact
                else {"resource_keys": resource_keys}
            ),
            "convergence": classification,
        }
        observations.append(item)
        if observation["state"] != record["state"]:
            would_refresh.append(item)
        if _state_releases_resources(observation["state"]):
            would_release.append(record["task_id"])
        blocker = _reconcile_blocker(record, observation)
        if blocker is not None:
            blocked.append(blocker)
        elif observation["state"] != "running":
            would_resume.append(item)
    observation_ms = round(
        (time.perf_counter_ns() - observation_started_ns) / 1_000_000,
        3,
    )
    result: dict[str, Any] = {
        "mode": "check",
        "task_id": task_id,
        "scanned": len(rows),
        "observations": observations,
        "would_refresh": would_refresh,
        "would_release": would_release,
        "would_resume": would_resume,
        "blocked": blocked,
        "checked_at_unix": _now(),
    }
    if page is not None:
        # The selected rows already come from one pinned SQLite read snapshot.
        # Re-hashing both stores after live unit observation made a read-only page
        # fail whenever unrelated task state changed during the observation phase.
        # The cursor remains fail-closed: the next page recomputes the snapshot
        # before decoding the cursor and rejects any intervening store mutation.
        result["pagination"] = {
            "limit": page["limit"],
            "examined": len(page["rows"]),
            "returned": len(rows),
            "has_more": page["has_more"],
            "next_cursor": page["next_cursor"],
            "ordering": "created_at_unix_asc_task_id_asc",
            "snapshot_sha256": page["snapshot"]["snapshot_sha256"],
            "total_candidates": page["total_candidates"],
            "max_payload_bytes": TASK_RECONCILE_CHECK_MAX_BYTES,
            "payload_bytes": 0,
            "timings_ms": {
                **page["timings_ms"],
                "observation": observation_ms,
                "serialization": 0.0,
                "total": 0.0,
            },
        }
        serialization_started_ns = time.perf_counter_ns()
        for _ in range(4):
            payload_bytes = len(_canonical_json(result).encode("utf-8"))
            if result["pagination"]["payload_bytes"] == payload_bytes:
                break
            result["pagination"]["payload_bytes"] = payload_bytes
        result["pagination"]["timings_ms"]["serialization"] = round(
            (time.perf_counter_ns() - serialization_started_ns) / 1_000_000,
            3,
        )
        result["pagination"]["timings_ms"]["total"] = round(
            (time.perf_counter_ns() - check_started_ns) / 1_000_000,
            3,
        )
        for _ in range(4):
            payload_bytes = len(_canonical_json(result).encode("utf-8"))
            if result["pagination"]["payload_bytes"] == payload_bytes:
                break
            result["pagination"]["payload_bytes"] = payload_bytes
        payload_bytes = len(_canonical_json(result).encode("utf-8"))
        result["pagination"]["payload_bytes"] = payload_bytes
        if payload_bytes > TASK_RECONCILE_CHECK_MAX_BYTES:
            raise RuntimeError("reconcile check page exceeds payload byte limit")
    return result

def _reconcile_tasks_refresh_locked(
    *,
    task_id: str = "",
    batch_size: int | None = None,
) -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    if batch_size is not None and task_id:
        raise ValueError("batch_size cannot be combined with task_id")
    batch = (
        None
        if task_id
        else _reconcile_candidate_batch(
            DEFAULT_TASK_RECONCILE_BATCH_SIZE
            if batch_size is None
            else batch_size
        )
    )
    rows = (
        list(batch["rows"])
        if batch is not None
        else _reconcile_candidate_rows(task_id)
    )
    refreshed: list[dict[str, Any]] = []
    released: list[str] = []
    denied: list[dict[str, Any]] = []
    for record in rows:
        if _is_terminal_state(str(record["state"])):
            terminal_valid, lease_valid = _terminal_convergence_evidence(record)
            if (
                terminal_valid
                and lease_valid
                and _reposkop_shadow_terminal_recovery_needed(record)
            ):
                try:
                    marker = _recover_reposkop_shadow_terminal(record)
                except Exception as exc:
                    denied.append(
                        {
                            "task_id": str(record["task_id"]),
                            "reason": _redact_reason(str(exc)),
                            "error_type": type(exc).__name__,
                        }
                    )
                    continue
                if marker is None:
                    denied.append(
                        {
                            "task_id": str(record["task_id"]),
                            "reason": (
                                "Reposkop terminal shadow recovery did not persist a marker"
                            ),
                            "error_type": "Unavailable",
                        }
                    )
                    continue
                public = _public(_row_raw(str(record["task_id"])))
                public["lease_maintenance"] = None
                refreshed.append(public)
                continue
        try:
            observation = _reconcile_observation(record)
        except PermissionError as exc:
            denied.append(_reconcile_observe_denial(record, exc))
            continue
        except ValueError as exc:
            if not _unknown_fleet_host_error(exc):
                raise
            denied.append(_reconcile_unknown_host(record, exc))
            continue
        effective_state = _effective_observed_state(record, observation["state"])
        lease_maintenance = _maintain_record_resources(record, effective_state)
        if lease_maintenance is not None:
            observation["lease_maintenance"] = lease_maintenance
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if _state_releases_resources(observation["state"]):
            released.append(stored["task_id"])
        public = _public(stored)
        public["lease_maintenance"] = lease_maintenance
        refreshed.append(public)
    if batch is not None:
        _save_reconcile_cycle(
            batch["cycle_after"],
            phase_turn=batch["phase_next"],
            active_refresh_cursor=batch["active_refresh"]["cursor_after"],
        )
    result = {
        "mode": "refresh",
        "task_id": task_id,
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": [],
        "blocked": denied,
        "checked_at_unix": _now(),
    }
    if batch is not None:
        result["batch"] = {
            key: batch[key]
            for key in (
                "limit",
                "task_limit",
                "examined",
                "task_examined",
                "cursor_before",
                "cursor_after",
                "cycle_wrapped",
                "cycle_phase",
                "cycle_high_water_sequence",
                "cycle_completed",
                "phase_first",
                "phase_next",
                "total_examined",
                "total_examined_limit",
            )
        }
        result["batch"]["active_refresh"] = batch["active_refresh"]
        result["batch"]["terminalization_recovery"] = batch[
            "terminalization_recovery"
        ]
    return result


def _attach_task_output_cleanup(
    result: dict[str, Any],
) -> dict[str, Any]:
    if "batch" not in result:
        return result
    output = dict(result)
    try:
        import grabowski_task_attention as task_attention

        output["task_output_cleanup"] = (
            task_attention.reconcile_archived_task_outputs(
                limit=task_attention.DEFAULT_TASK_OUTPUT_CLEANUP_BATCH_SIZE
            )
        )
    except Exception as exc:
        output["task_output_cleanup"] = {
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_reconcile",
            "status": "degraded",
            "error_type": type(exc).__name__,
            "error": operator._redact(str(exc))[:512],
            "checked_at_unix": _now(),
            "does_not_establish": [
                "task_output_cleanup_completed",
                "absence_of_archived_output",
                "safe_blind_retry",
            ],
        }
    return output


def reconcile_tasks_refresh(
    *,
    task_id: str = "",
    batch_size: int | None = None,
) -> dict[str, Any]:
    with _task_mutation_lock():
        result = _reconcile_tasks_refresh_locked(
            task_id=task_id,
            batch_size=batch_size,
        )
    return _attach_task_output_cleanup(result)


@_serialize_task_mutation
def reconcile_tasks_resume(
    *,
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    if not isinstance(max_resumes, int) or not 1 <= max_resumes <= 50:
        raise ValueError("max_resumes must be between 1 and 50")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason is required for task reconcile resume")
    rows = _reconcile_candidate_rows(
        task_id,
        include_converged_terminal=True,
    )
    refreshed: list[dict[str, Any]] = []
    released: list[str] = []
    resumed: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for record in rows:
        try:
            observation = _reconcile_observation(record)
        except PermissionError as exc:
            blocked.append(_reconcile_observe_denial(record, exc))
            continue
        except ValueError as exc:
            if not _unknown_fleet_host_error(exc):
                raise
            blocked.append(_reconcile_unknown_host(record, exc))
            continue

        if str(record["state"]) == "interrupted":
            if not task_id:
                blocked.append(
                    {
                        "task_id": record["task_id"],
                        "resume_policy": record["resume_policy"],
                        "reason": (
                            "interrupted recovery requires an exact task target "
                            "and named state change"
                        ),
                        "reason_class": "evidence_drift",
                        "retryable": False,
                        "automatic_resume_allowed": False,
                        "owner_decision_required": True,
                    }
                )
                continue
            try:
                _interrupted_recovery_evidence_projection(record, observation)
            except ValueError as exc:
                blocked.append(
                    {
                        "task_id": record["task_id"],
                        "resume_policy": record["resume_policy"],
                        "reason": _redact_reason(str(exc)),
                        "reason_class": "evidence_drift",
                        "retryable": False,
                        "automatic_resume_allowed": False,
                        "owner_decision_required": True,
                    }
                )
                continue
            if len(resumed) >= max_resumes:
                blocked.append(
                    {
                        "task_id": record["task_id"],
                        "resume_policy": record["resume_policy"],
                        "reason": "max_resumes reached",
                        "reason_class": "retry_exhausted",
                        "retryable": False,
                        "automatic_resume_allowed": False,
                        "owner_decision_required": True,
                    }
                )
                continue
            stored = _set_state(
                record["task_id"],
                "interrupted",
                observation=observation,
            )
            public = _public(stored)
            public["lease_maintenance"] = None
            refreshed.append(public)
            try:
                interrupted_context = _build_interrupted_recovery_context(
                    stored,
                    observation,
                    reason=reason,
                )
                resumed_task = dict(
                    grabowski_task_resume(
                        stored["task_id"],
                        _interrupted_recovery_context=interrupted_context,
                    )["task"]
                )
                resumed_task["explicit_interrupted_recovery"] = True
                resumed_task["recovery_reason"] = _redact_reason(reason.strip())
                resumed_task["interrupted_recovery_context_sha256"] = (
                    interrupted_context["context_sha256"]
                )
                resumed.append(resumed_task)
            except Exception as exc:
                blocked.append(
                    {
                        "task_id": stored["task_id"],
                        "resume_policy": stored["resume_policy"],
                        "reason": _redact_reason(str(exc)),
                        "reason_class": "evidence_drift",
                        "retryable": False,
                        "automatic_resume_allowed": False,
                        "owner_decision_required": True,
                    }
                )
            continue

        effective_state = _effective_observed_state(record, observation["state"])
        lease_maintenance = _maintain_record_resources(record, effective_state)
        if lease_maintenance is not None:
            observation["lease_maintenance"] = lease_maintenance
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if _state_releases_resources(observation["state"]):
            released.append(stored["task_id"])
        public = _public(stored)
        public["lease_maintenance"] = lease_maintenance
        refreshed.append(public)
        if observation["state"] == "running":
            continue
        blocker = _reconcile_blocker(stored, observation)
        explicit_policy_override = bool(task_id) and bool(blocker) and (
            _is_terminal_state(str(stored["state"]))
            and (
                (
                    str(stored["resume_policy"])
                    in {"manual", "verify-then-retry"}
                    and blocker.get("reason_class") == "non_retryable_failure"
                    and blocker.get("reason")
                    == "task resume policy does not permit automatic retry"
                )
                or (
                    str(stored["resume_policy"]) == "retry-safe"
                    and blocker.get("reason_class") == "retry_exhausted"
                )
            )
        )
        if blocker is not None and not explicit_policy_override:
            blocked.append(blocker)
            continue
        if len(resumed) >= max_resumes:
            blocked.append(
                {
                    "task_id": stored["task_id"],
                    "resume_policy": stored["resume_policy"],
                    "reason": "max_resumes reached",
                    "reason_class": "retry_exhausted",
                    "retryable": False,
                    "automatic_resume_allowed": False,
                    "owner_decision_required": True,
                }
            )
            continue
        try:
            if _is_terminal_state(str(stored["state"])):
                resumed.append(
                    _terminal_retry_successor(
                        stored,
                        reason=reason,
                        explicit_policy_override=explicit_policy_override,
                    )
                )
            else:
                resumed.append(grabowski_task_resume(stored["task_id"])["task"])
        except Exception as exc:
            blocked.append(
                {
                    "task_id": stored["task_id"],
                    "resume_policy": stored["resume_policy"],
                    "reason": _redact_reason(str(exc)),
                }
            )
    return {
        "mode": "resume",
        "task_id": task_id,
        "max_resumes": max_resumes,
        "reason": _redact_reason(reason.strip()),
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": resumed,
        "blocked": blocked,
        "checked_at_unix": _now(),
    }


def _reconcile_tasks_locked(
    *,
    auto_resume: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(auto_resume, bool):
        raise ValueError("auto_resume must be boolean")
    if auto_resume:
        preview = reconcile_tasks_check()
        refresh = _reconcile_tasks_refresh_locked()
        disabled = [
            {
                "task_id": item["task_id"],
                "resume_policy": item["resume_policy"],
                "reason": "legacy auto_resume reconcile is disabled; use explicit resume mode",
            }
            for item in preview["would_resume"]
        ]
        result = {
            "auto_resume": auto_resume,
            "legacy_auto_resume_disabled": True,
            "scanned": refresh["scanned"],
            "refreshed": refresh["refreshed"],
            "resumed": [],
            "blocked": [*preview["blocked"], *disabled],
            "checked_at_unix": refresh["checked_at_unix"],
        }
        return result, refresh
    refresh = _reconcile_tasks_refresh_locked()
    result = {
        "auto_resume": auto_resume,
        "scanned": refresh["scanned"],
        "refreshed": refresh["refreshed"],
        "resumed": refresh["resumed"],
        "blocked": refresh["blocked"],
        "checked_at_unix": refresh["checked_at_unix"],
    }
    return result, refresh


def reconcile_tasks(*, auto_resume: bool = False) -> dict[str, Any]:
    with _task_mutation_lock():
        result, refresh = _reconcile_tasks_locked(auto_resume=auto_resume)
    cleanup = _attach_task_output_cleanup(refresh)
    if "task_output_cleanup" in cleanup:
        result["task_output_cleanup"] = cleanup["task_output_cleanup"]
    return result


def _task_reconcile_check_after_guard(
    task_id: str,
    limit: int,
    cursor: str | None,
) -> dict[str, Any]:
    with TASK_RECONCILE_LOCK:
        operator._require_operator_capability("durable_job")
        return reconcile_tasks_check(task_id=task_id, limit=limit, cursor=cursor)


def grabowski_task_reconcile_check(
    task_id: str = "",
    limit: int = DEFAULT_TASK_RECONCILE_CHECK_LIMIT,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Read one bounded, resumable reconcile preview for persistent tasks."""
    operator._require_operator_capability("durable_job")
    return _task_reconcile_check_after_guard(task_id, limit, cursor)


@mcp.tool(name="grabowski_task_reconcile_check", annotations=READ_ONLY)
async def _grabowski_task_reconcile_check_tool(
    task_id: str = "",
    limit: int = DEFAULT_TASK_RECONCILE_CHECK_LIMIT,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Read one bounded, resumable reconcile preview for persistent tasks."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(
        _task_reconcile_check_after_guard,
        task_id,
        limit,
        cursor,
    )


def _task_reconcile_refresh_after_guard(task_id: str) -> dict[str, Any]:
    with _task_mutation_lock():
        operator._require_operator_mutation("durable_job")
        result = _reconcile_tasks_refresh_locked(task_id=task_id)
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "task-reconcile-refresh",
                "task_id": task_id,
                "scanned": result["scanned"],
                "released_count": len(result["released"]),
            }
        )
    return _attach_task_output_cleanup(result)


def grabowski_task_reconcile_refresh(task_id: str = "") -> dict[str, Any]:
    """Refresh persistent task states without resuming processes."""
    operator._require_operator_mutation("durable_job")
    return _task_reconcile_refresh_after_guard(task_id)


@mcp.tool(name="grabowski_task_reconcile_refresh", annotations=MUTATING)
async def _grabowski_task_reconcile_refresh_tool(task_id: str = "") -> dict[str, Any]:
    """Refresh persistent task states without resuming processes."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(_task_reconcile_refresh_after_guard, task_id)


def _task_reconcile_resume_after_guard(
    task_id: str,
    max_resumes: int,
    reason: str,
) -> dict[str, Any]:
    with _task_mutation_lock():
        operator._require_operator_mutation("durable_job")
        result = reconcile_tasks_resume(
            task_id=task_id,
            max_resumes=max_resumes,
            reason=reason,
        )
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "task-reconcile-resume",
                "task_id": task_id,
                "max_resumes": max_resumes,
                "reason": result["reason"],
                "scanned": result["scanned"],
                "resumed_count": len(result["resumed"]),
                "blocked_count": len(result["blocked"]),
            }
        )
        return result


def grabowski_task_reconcile_resume(
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    """Resume retry-safe tasks after reconcile verification."""
    operator._require_operator_mutation("durable_job")
    return _task_reconcile_resume_after_guard(task_id, max_resumes, reason)


@mcp.tool(name="grabowski_task_reconcile_resume", annotations=MUTATING)
async def _grabowski_task_reconcile_resume_tool(
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    """Resume retry-safe tasks after reconcile verification."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(
        _task_reconcile_resume_after_guard,
        task_id,
        max_resumes,
        reason,
    )


def _task_reconcile_after_guard(auto_resume: bool) -> dict[str, Any]:
    with _task_mutation_lock():
        operator._require_operator_mutation("durable_job")
        result, refresh = _reconcile_tasks_locked(auto_resume=auto_resume)
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "task-reconcile",
                "auto_resume": auto_resume,
                "scanned": result["scanned"],
                "resumed_count": len(result["resumed"]),
                "blocked_count": len(result["blocked"]),
            }
        )
    cleanup = _attach_task_output_cleanup(refresh)
    if "task_output_cleanup" in cleanup:
        result["task_output_cleanup"] = cleanup["task_output_cleanup"]
    return result


def grabowski_task_reconcile(auto_resume: bool = False) -> dict[str, Any]:
    """Reconcile persistent tasks after process loss or host restart."""
    operator._require_operator_mutation("durable_job")
    return _task_reconcile_after_guard(auto_resume)


@mcp.tool(name="grabowski_task_reconcile", annotations=MUTATING)
async def _grabowski_task_reconcile_tool(
    auto_resume: bool = False,
) -> dict[str, Any]:
    """Reconcile persistent tasks after process loss or host restart."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(_task_reconcile_after_guard, auto_resume)


def grabowski_task_list(
    limit: int = DEFAULT_TASK_LIST_LIMIT,
    state: str | None = None,
    view: str = "minimal",
    cursor: str | None = None,
    fields: list[str] | None = None,
    schema_only: bool = False,
) -> dict[str, Any]:
    """List persistent tasks or inspect store-schema compatibility read-only."""
    operator._require_operator_capability("durable_job")
    if not isinstance(schema_only, bool):
        raise ValueError("schema_only must be boolean")
    if schema_only:
        if (
            limit != DEFAULT_TASK_LIST_LIMIT
            or state is not None
            or view != "minimal"
            or cursor is not None
            or fields is not None
        ):
            raise ValueError(
                "schema_only cannot be combined with task-list filters or projections"
            )
        return _task_schema_inventory()
    if view == "managed_cargo_evidence":
        if state is not None or cursor is not None or fields is not None:
            raise ValueError(
                "managed_cargo_evidence view cannot be combined with state, cursor or fields"
            )
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        _recover_pending_task_terminalizations()
        return _managed_cargo_evidence_from_task_store(limit)
    selected_view = consumer_surface.normalize_view(view)
    _recover_pending_task_terminalizations()
    current_projection = _task_current_projection()
    projection_sha256 = current_projection.get("projection_sha256")
    archived_task_bindings = current_projection.get("archived_task_bindings")
    projection_switches = current_projection.get("switches")
    if (
        not isinstance(projection_sha256, str)
        or SHA256.fullmatch(projection_sha256) is None
        or not isinstance(archived_task_bindings, dict)
        or not isinstance(projection_switches, list)
    ):
        raise lifecycle_projection.LifecycleProjectionIntegrityError(
            "current task projection metadata is invalid"
        )
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    filter_states = _task_filter_states(state)
    snapshot_scope = f"task-list:{selected_view}:{state or 'all'}"
    where: list[str] = []
    parameters: list[Any] = []
    if filter_states is not None:
        placeholders = ",".join("?" for _ in filter_states)
        where.append(f"state IN ({placeholders})")
        parameters.extend(filter_states)
    with _task_read_snapshot() as connection:
        # BEGIN DEFERRED does not pin a SQLite snapshot until the first read.
        # Pin it before helper calls so row pages, counts and attention decisions
        # are all derived against one task-store view even if a concurrent writer
        # commits while the list operation is in progress.
        connection.execute("SELECT 1 FROM tasks LIMIT 1").fetchone()
        retained_state_counts, _, retained_unknown_state_count = _task_state_counts(connection)
        projected_state_counts, projected_unknown_state_count = _projected_task_state_counts(
            connection,
            current_projection,
        )
        state_counts, raw_projection_counts, unknown_state_count = _subtract_projected_task_counts(
            retained_state_counts,
            retained_unknown_state_count,
            projected_state_counts,
            projected_unknown_state_count,
        )
        import grabowski_task_attention as task_attention

        evaluate_attention_projection = state in {None, "attention"}
        decision_guard = (
            task_attention.decision_snapshot_guard()
            if evaluate_attention_projection
            else nullcontext(None)
        )
        # Decision files live outside SQLite. Hold the shared decision lock from
        # projection through cursor validation and row materialization only when
        # the caller requested the unfiltered or decision-aware attention view.
        # Exact and non-attention projection filters must not scan unrelated
        # attention history merely to return their bounded row page.
        with decision_guard as decision_snapshot:
            projection_counts = dict(raw_projection_counts)
            attention_excluded_task_ids: set[str] = set()
            if evaluate_attention_projection:
                attention_projection, attention_excluded_task_ids = (
                    _task_attention_projection(
                        connection,
                        current_projection,
                        decision_snapshot=decision_snapshot,
                    )
                )
                if (
                    attention_projection["raw_attention_count"]
                    != raw_projection_counts["attention"]
                ):
                    raise lifecycle_projection.LifecycleProjectionIntegrityError(
                        "decision-aware attention projection does not match current raw attention count"
                    )
                projection_counts["attention"] = attention_projection[
                    "current_attention_count"
                ]
            else:
                attention_projection = _task_attention_projection_not_evaluated(
                    raw_projection_counts["attention"]
                )
            list_snapshot_sha256 = projection_sha256
            if state == "attention":
                list_snapshot_sha256 = _sha256_json(
                    {
                        "archive_projection_sha256": projection_sha256,
                        "attention_projection_sha256": attention_projection[
                            "projection_sha256"
                        ],
                    }
                )
            scope = f"{snapshot_scope}:{list_snapshot_sha256}"
            position = consumer_surface.decode_cursor(
                cursor,
                scope,
                snapshot_scope=snapshot_scope,
            )
            cursor_created_at: int | None = None
            cursor_task_id: str | None = None
            if position is not None:
                cursor_created_at = position.get("created_at_unix")
                cursor_task_id = position.get("task_id")
                if (
                    isinstance(cursor_created_at, bool)
                    or not isinstance(cursor_created_at, int)
                    or cursor_created_at < 0
                    or not isinstance(cursor_task_id, str)
                    or not TASK_ID.fullmatch(cursor_task_id)
                ):
                    raise ValueError("cursor position is invalid")
            rows = _task_list_current_rows(
                connection,
                where=where,
                parameters=parameters,
                cursor_created_at=cursor_created_at,
                cursor_task_id=cursor_task_id,
                limit=limit,
                projection=current_projection,
                excluded_task_ids=(
                    attention_excluded_task_ids if state == "attention" else None
                ),
            )
            if filter_states is None:
                total_matching = sum(state_counts.values()) + unknown_state_count
            elif state == "attention":
                total_matching = projection_counts["attention"]
            else:
                total_matching = sum(state_counts[item] for item in filter_states)
    projection_readback = _task_current_projection()
    if projection_readback.get("projection_sha256") != projection_sha256:
        raise lifecycle_projection.LifecycleProjectionIntegrityError(
            "current task projection changed during list read"
        )
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    tasks = [_public_for_view(dict(row), selected_view) for row in page_rows]
    next_cursor = None
    if has_more and page_rows:
        last = dict(page_rows[-1])
        next_cursor = consumer_surface.encode_cursor(
            scope,
            {
                "created_at_unix": int(last["created_at_unix"]),
                "task_id": str(last["task_id"]),
            },
        )
    warning_states = {
        "interrupted",
        "failed",
        "timed_out",
        "signalled",
        "outcome_unknown",
    }
    warnings: list[dict[str, Any]] = []
    if unknown_state_count:
        warnings.append({
            "code": "unknown_task_states",
            "count": unknown_state_count,
        })
    if attention_projection["status"] == "degraded":
        warnings.append({
            "code": "attention_projection_degraded",
            "evidence_error": attention_projection["evidence_error"],
            "raw_attention_count": attention_projection["raw_attention_count"],
        })
    if attention_projection["status"] != "not_evaluated":
        warnings.extend(
            {
                "code": "task_requires_attention",
                "task_id": task["task_id"],
                "state": task["state"],
            }
            for task in tasks
            if task.get("state") in warning_states
            and task.get("task_id") not in attention_excluded_task_ids
        )
    warnings.extend(
        {
            "code": "task_systemd_unit_degraded",
            "task_id": task["task_id"],
            "state": task["state"],
            "reason": task["systemd_unit_health"].get("reason"),
            "load_state": task["systemd_unit_health"].get("load_state"),
        }
        for task in tasks
        if isinstance(task.get("systemd_unit_health"), dict)
        and task["systemd_unit_health"].get("status") == "degraded"
    )
    payload: dict[str, Any] = {
        "schema_version": 2,
        "view": selected_view,
        "count": len(tasks),
        "total_matching": total_matching,
        "state_filter": state,
        "state_filter_kind": (
            "all" if state is None else "projection" if state in TASK_STATE_PROJECTIONS else "exact"
        ),
        "state_filter_states": list(filter_states or ()),
        "state_counts": state_counts,
        "state_counts_scope": "current_projection",
        "state_counts_complete": unknown_state_count == 0,
        "unknown_state_count": unknown_state_count,
        "projection_counts": projection_counts,
        "raw_projection_counts": raw_projection_counts,
        "projection_counts_scope": "current_projection",
        "projection_counts_semantics": {
            "active": "current_task_states",
            "attention": (
                "current_task_projection_after_valid_attention_decisions"
                if evaluate_attention_projection
                else "raw_current_task_states_attention_not_decision_filtered"
            ),
            "terminal": "current_task_states",
        },
        "projection_counts_overlap": True,
        "attention_projection": attention_projection,
        "current_projection": {
            "status": "verified",
            "projection_sha256": projection_sha256,
            "switch_count": len(projection_switches),
            "projected_task_count": len(archived_task_bindings),
        },
        "tasks": tasks,
        "pagination": {
            "limit": limit,
            "returned": len(tasks),
            "has_more": has_more,
            "next_cursor": next_cursor,
            "ordering": "created_at_unix_desc_task_id_desc",
            "snapshot_sha256": list_snapshot_sha256,
        },
        "warnings": warnings,
        "recommended_next_action": (
            "inspect unknown task states before relying on projections"
            if unknown_state_count
            else "repair attention projection evidence before relying on closeout filtering"
            if attention_projection["status"] == "degraded"
            else (
                "inspect returned tasks before deciding the next action"
                if tasks
                else "none"
            )
            if attention_projection["status"] == "not_evaluated"
            else "inspect current attention tasks before retry"
            if projection_counts["attention"]
            else "none"
        ),
        "does_not_establish": [
            "task_output_correctness",
            "safe_unchanged_retry",
            "resource_release_complete",
            "physical_archive_pruning",
            *(
                ["decision-aware attention count for this non-attention filter"]
                if attention_projection["status"] == "not_evaluated"
                else []
            ),
        ],
    }
    if selected_view == "evidence":
        payload["database"] = str(TASK_DB)
        payload["current_projection"].update(
            {
                "projection_root": str(_task_projection_root()),
                "archive_root": str(_task_archive_root()),
            }
        )
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "view",
            "current_projection",
            "warnings",
            "recommended_next_action",
            "does_not_establish",
        ),
    )


@mcp.tool(name="grabowski_task_start", annotations=MUTATING)
async def _grabowski_task_start_tool(
    host: str,
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = operator.DEFAULT_JOB_RUNTIME,
    resume_policy: ResumePolicy = "verify-then-retry",
    cpu_weight: int = 100,
    io_weight: int = 100,
    memory_max_bytes: int | None = None,
    resource_keys: list[str] | None = None,
    chronik_outbox: bool = False,
    chronik_outbox_state_root: str | None = None,
    chronik_operation: str = "other",
    chronik_component: str = "",
    chronik_bureau_task_id: str = "",
    chronik_pr_number: int | None = None,
    runtime_python: bool = False,
    route_evidence: dict[str, Any] | None = None,
    operation_identity: dict[str, Any] | None = None,
    supersedes_task_id: str = "",
    supersedes_receipt_sha256: str = "",
    force_new_reason: str = "",
    effect_profile: str | None = None,
) -> dict[str, Any]:
    """Start one persistent local or fleet task in its own systemd unit.

    Direct local write-capable agent CLIs receive an implicit repository lease
    unless the caller supplies an explicit path or repository scope. Every
    task-owned broad repository lease carries a complete whole-repository scope manifest.
    """
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(
        grabowski_task_start,
        host,
        argv,
        cwd,
        runtime_seconds,
        resume_policy,
        cpu_weight,
        io_weight,
        memory_max_bytes,
        resource_keys,
        chronik_outbox,
        chronik_outbox_state_root,
        chronik_operation,
        chronik_component,
        chronik_bureau_task_id,
        chronik_pr_number,
        runtime_python,
        route_evidence,
        operation_identity,
        supersedes_task_id,
        supersedes_receipt_sha256,
        force_new_reason,
        effect_profile,
    )


@mcp.tool(name="grabowski_task_status", annotations=READ_ONLY)
async def _grabowski_task_status_tool(task_id: str) -> dict[str, Any]:
    """Observe one persistent task and refresh its recorded state."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(grabowski_task_status, task_id)


@mcp.tool(name="grabowski_task_routing_shadow_seal", annotations=MUTATING)
async def _grabowski_task_routing_shadow_seal_tool(
    task_id: str,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    execution_provenance: dict[str, Any],
    semantic_assessments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Seal one independently reviewed direct-task shadow outcome without routing effect."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(
        grabowski_task_routing_shadow_seal,
        task_id,
        outcome,
        primary_evidence_refs,
        execution_provenance,
        semantic_assessments,
    )


@mcp.tool(name="grabowski_task_logs", annotations=READ_ONLY)
async def _grabowski_task_logs_tool(
    task_id: str,
    max_lines: int = 200,
) -> dict[str, Any]:
    """Read redacted journal output for one local or fleet task."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(grabowski_task_logs, task_id, max_lines)


@mcp.tool(name="grabowski_task_cancel", annotations=MUTATING)
async def _grabowski_task_cancel_tool(task_id: str) -> dict[str, Any]:
    """Stop one task process group and retain its persistent task record."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(grabowski_task_cancel, task_id)


@mcp.tool(name="grabowski_task_resume", annotations=MUTATING)
async def _grabowski_task_resume_tool(task_id: str) -> dict[str, Any]:
    """Recreate a missing or stopped task unit from its persistent record."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(grabowski_task_resume, task_id)


@mcp.tool(name="grabowski_task_list", annotations=READ_ONLY)
async def _grabowski_task_list_tool(
    limit: int = DEFAULT_TASK_LIST_LIMIT,
    state: str | None = None,
    view: str = "minimal",
    cursor: str | None = None,
    fields: list[str] | None = None,
    schema_only: bool = False,
) -> dict[str, Any]:
    """List persistent tasks or inspect store-schema compatibility read-only."""
    operator._require_operator_capability("durable_job")
    return await asyncio.to_thread(
        grabowski_task_list,
        limit,
        state,
        view,
        cursor,
        fields,
        schema_only,
    )


# Managed Cargo cache evidence is a read-only projection of the canonical task database.
import grabowski_managed_cargo as managed_cargo


def _managed_cargo_evidence_from_task_store(max_entries: int) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    with _task_read_snapshot() as connection:
        rows = connection.execute(
            "SELECT task_id, state, argv_json, updated_at_unix "
            "FROM tasks ORDER BY task_id"
        ).fetchall()
        for row in rows:
            try:
                argv = json.loads(str(row["argv_json"]))
            except json.JSONDecodeError:
                argv = None
            records.append(
                {
                    "task_id": str(row["task_id"]),
                    "state": str(row["state"]),
                    "argv": argv,
                    "updated_at_unix": int(row["updated_at_unix"]),
                }
            )
    return managed_cargo.build_evidence(
        records,
        cache_root=MANAGED_CARGO_CACHE_ROOT,
        max_entries=max_entries,
    )


CHRONIK_CLI_TIMEOUT_SECONDS = 30
CHRONIK_CLI_MAX_OUTPUT_BYTES = 1 * 1024 * 1024
CHRONIK_HISTORY_MAX_LIMIT = 100


def _chronik_bounded_text(value: str, *, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    normalized = value.strip()
    if len(normalized) > maximum or any(
        ord(character) < 32 for character in normalized
    ):
        raise ValueError(f"{label} is invalid")
    return normalized


def _chronik_parse_timestamp(value: str, *, label: str) -> datetime:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _chronik_history_event_matches_query(
    event: dict[str, Any],
    normalized: dict[str, str],
    *,
    since_timestamp: datetime | None,
) -> bool:
    if event.get("schema_version") != "agent-run-event.v0":
        return False
    source = event.get("source")
    if (
        not isinstance(source, dict)
        or source.get("repo") != "heimgewebe/grabowski"
        or source.get("component") != "grabowski"
    ):
        return False
    if event.get("kind") not in {
        "agent.run.started",
        "agent.run.completed",
        "agent.run.blocked",
    }:
        return False
    if event.get("event_id") != chronik.event_id(event):
        return False
    subject = event.get("subject")
    data = event.get("data")
    if not isinstance(subject, dict) or not isinstance(data, dict):
        return False
    if normalized["repo"]:
        if subject.get("scope") != "repository" or subject.get("repo") != normalized["repo"]:
            return False
    elif subject.get("scope") != "host" or subject.get("host") != normalized["host"]:
        return False
    if normalized["component"] and source.get("component") != normalized["component"]:
        return False
    if normalized["subject_component"] and subject.get("component") != normalized["subject_component"]:
        return False
    if normalized["operation"] and data.get("operation") != normalized["operation"]:
        return False
    if normalized["task_class"] and data.get("task_class") != normalized["task_class"]:
        return False
    if normalized["outcome"] and data.get("result") != normalized["outcome"]:
        return False
    if since_timestamp is not None:
        timestamp = event.get("ts")
        if not isinstance(timestamp, str):
            return False
        try:
            event_timestamp = _chronik_parse_timestamp(timestamp, label="history event ts")
        except ValueError:
            return False
        if event_timestamp < since_timestamp:
            return False
    return True


def _chronik_cli_run(
    arguments: list[str], *, configuration: dict[str, Any], data_dir: Path | str
) -> dict[str, Any]:
    command = [
        configuration["python"],
        configuration["cli"],
        "--data-dir",
        str(data_dir),
        *arguments,
    ]
    try:
        return operator._run(
            command,
            cwd=Path(configuration["repository"]),
            timeout_seconds=CHRONIK_CLI_TIMEOUT_SECONDS,
            max_output_bytes=CHRONIK_CLI_MAX_OUTPUT_BYTES,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": _redact_reason(str(exc)),
            "timed_out": False,
            "launch_error": True,
        }


def _chronik_write_snapshot(raw: bytes, path: Path) -> Path:
    """Write exactly `raw` to a private, newly created file the CLI can import.

    The snapshot is what gets handed to the Chronik CLI, never the original outbox
    path, so the import is bound to bytes that were already read and validated once.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Chronik snapshot write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def _chronik_bounded_error(text: str, *, maximum: int = 2000) -> str:
    if len(text) <= maximum:
        return text
    return text[:maximum] + "...(truncated)"


def _chronik_cli_json(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("returncode") != 0 or result.get("timed_out") is True:
        raise ValueError("Chronik coding-memory CLI did not complete successfully")
    raw = result.get("stdout")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Chronik coding-memory CLI returned no JSON")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Chronik coding-memory CLI returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Chronik coding-memory CLI result must be an object")
    return payload


def _chronik_receipt(payload: dict[str, Any], *, field: str) -> dict[str, Any]:
    result = dict(payload)
    result[field] = _sha256_json(result)
    return result


def _chronik_failure_details(result: dict[str, Any] | None) -> dict[str, Any]:
    if result is None:
        return {}
    stderr = result.get("stderr")
    error = _redact_reason(stderr) if isinstance(stderr, str) and stderr else None
    return {
        "returncode": result.get("returncode"),
        "timed_out": result.get("timed_out") is True,
        "error": _chronik_bounded_error(error) if error else None,
    }


def _chronik_unsigned_receipt_valid(payload: dict[str, Any]) -> bool:
    claimed = payload.get("receipt_sha256")
    if not isinstance(claimed, str):
        return False
    unsigned = dict(payload)
    unsigned.pop("receipt_sha256", None)
    return claimed == _sha256_json(unsigned)


_CHRONIK_IMPORT_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "domain",
        "event_ids",
        "requested",
        "imported",
        "skipped_existing",
        "recorded_at",
        "source_sha256",
        "historical_only",
        "does_not_establish",
        "receipt_sha256",
    }
)


def _validate_chronik_import_result(
    source: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _CHRONIK_IMPORT_RECEIPT_KEYS:
        raise ValueError("Chronik coding-memory import receipt has invalid fields")
    if payload.get("schema_version") != "chronik-import-receipt.v1":
        raise ValueError("Chronik coding-memory import contract is stale")
    if payload.get("domain") != "agent.ledger":
        raise ValueError("Chronik coding-memory import domain is invalid")
    if payload.get("event_ids") != sorted(source["event_ids"]):
        raise ValueError("Chronik coding-memory import event_ids are unbound")
    requested = payload.get("requested")
    imported = payload.get("imported")
    skipped = payload.get("skipped_existing")
    if (
        type(requested) is not int
        or requested != source["event_count"]
        or type(imported) is not int
        or imported < 0
        or type(skipped) is not int
        or skipped < 0
        or imported + skipped != requested
    ):
        raise ValueError("Chronik coding-memory import counts are invalid")
    if payload.get("source_sha256") != source["chronik_source_sha256"]:
        raise ValueError("Chronik coding-memory import source digest is unbound")
    if payload.get("historical_only") is not True:
        raise ValueError("Chronik coding-memory import is not historical-only")
    claims = payload.get("does_not_establish")
    if claims != list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH):
        raise ValueError("Chronik coding-memory import truth exclusions are invalid")
    recorded_at = _chronik_bounded_text(
        payload.get("recorded_at"), label="Chronik import recorded_at", maximum=64
    )
    if chronik._EVENT_TIMESTAMP_PATTERN.fullmatch(recorded_at) is None:
        raise ValueError("Chronik coding-memory import recorded_at is invalid")
    if not _chronik_unsigned_receipt_valid(payload):
        raise ValueError("Chronik coding-memory import receipt digest is invalid")
    return payload


def _chronik_source_unchanged(source: dict[str, Any]) -> tuple[bool, str | None]:
    return chronik.coding_memory_source_unchanged(source)


@mcp.tool(name="grabowski_chronik_outbox_import", annotations=MUTATING)
def grabowski_chronik_outbox_import(path: str) -> dict[str, Any]:
    """Import one redacted Grabowski outbox JSONL into optional local Chronik."""
    operator._require_operator_mutation("durable_job")
    source, raw = chronik.read_coding_memory_source(path)
    configuration = chronik.coding_memory_configuration()
    base_payload: dict[str, Any] = {
        "schema_version": 2,
        "kind": "grabowski_chronik_outbox_import_receipt",
        "source": {
            key: source[key]
            for key in ("path", "sha256", "bytes", "event_count", "event_ids_sha256")
        },
        "cli_present": bool(configuration["available"]),
        "available": False,
        "succeeded": False,
        "events_imported": 0,
        "events_skipped_existing": 0,
        "idempotent_import_contract": True,
        "source_unchanged": True,
        "outcome_unknown": False,
        "does_not_establish": list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH),
    }

    def _finish(payload: dict[str, Any]) -> dict[str, Any]:
        receipt = _chronik_receipt(payload, field="receipt_sha256")
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "chronik-outbox-import",
                "source_sha256": source["sha256"],
                "source_event_count": source["event_count"],
                "available": receipt["available"],
                "succeeded": receipt["succeeded"],
                "events_imported": receipt["events_imported"],
                "events_skipped_existing": receipt["events_skipped_existing"],
                "outcome_unknown": receipt["outcome_unknown"],
                "receipt_sha256": receipt["receipt_sha256"],
            }
        )
        return receipt

    if not configuration["available"]:
        return _finish(
            {
                **base_payload,
                "failure": {
                    "code": configuration["reason"],
                    "returncode": None,
                    "timed_out": False,
                    "error": None,
                },
            }
        )

    with tempfile.TemporaryDirectory(prefix="grabowski-chronik-import-") as workspace_name:
        workspace = Path(workspace_name)
        snapshot_path = _chronik_write_snapshot(raw, workspace / "snapshot.jsonl")

        # Preflight: import the exact same snapshot into a private, empty data_dir first.
        # The real store is only ever mutated once this receipt is fully contract-valid.
        preflight_execution = _chronik_cli_run(
            ["import", str(snapshot_path)],
            configuration=configuration,
            data_dir=workspace / "preflight-data",
        )
        try:
            preflight_result = _validate_chronik_import_result(
                source, _chronik_cli_json(preflight_execution)
            )
            if (
                preflight_result["requested"] != source["event_count"]
                or preflight_result["imported"] != source["event_count"]
                or preflight_result["skipped_existing"] != 0
            ):
                raise ValueError(
                    "Chronik coding-memory preflight did not prove a fresh complete import"
                )
        except ValueError as exc:
            return _finish(
                {
                    **base_payload,
                    "failure": {
                        "code": "chronik_coding_memory_preflight_failed",
                        **_chronik_failure_details(preflight_execution),
                        "contract_error": str(exc),
                    },
                }
            )

        real_execution = _chronik_cli_run(
            ["import", str(snapshot_path)],
            configuration=configuration,
            data_dir=configuration["data_dir"],
        )
        source_unchanged, source_readback_error = _chronik_source_unchanged(source)
        try:
            real_result = _validate_chronik_import_result(
                source, _chronik_cli_json(real_execution)
            )
        except ValueError as exc:
            return _finish(
                {
                    **base_payload,
                    "source_unchanged": source_unchanged,
                    "outcome_unknown": True,
                    "failure": {
                        "code": "chronik_coding_memory_cli_failed",
                        **_chronik_failure_details(real_execution),
                        "contract_error": str(exc),
                        "source_readback_error": source_readback_error,
                    },
                }
            )

        payload = {
            **base_payload,
            "available": True,
            "succeeded": True,
            "events_imported": real_result["imported"],
            "events_skipped_existing": real_result["skipped_existing"],
            "source_unchanged": source_unchanged,
            "outcome_unknown": False,
            "chronik_result": dict(real_result),
        }
        if source_readback_error is not None:
            payload["source_readback_error"] = _chronik_bounded_error(
                _redact_reason(source_readback_error)
            )
        return _finish(payload)


_CHRONIK_HISTORY_KEYS = frozenset(
    {
        "schema_version",
        "query",
        "target",
        "events",
        "event_ids",
        "historical_only",
        "does_not_establish",
        "ledger_snapshot",
    }
)
_CHRONIK_LEDGER_SNAPSHOT_KEYS = frozenset(
    {
        "domain",
        "sha256",
        "complete_bytes",
        "total_record_count",
        "valid_record_count",
        "invalid_record_count",
        "integrity_valid",
        "diagnostics",
        "diagnostics_truncated",
    }
)
_CHRONIK_QUERY_KEYS = frozenset(
    {"repo", "host", "component", "operation", "task_class", "outcome", "since", "limit"}
)


def _validate_chronik_ledger_snapshot(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _CHRONIK_LEDGER_SNAPSHOT_KEYS:
        raise ValueError("Chronik coding-memory ledger snapshot has invalid fields")
    complete_bytes = payload.get("complete_bytes")
    total = payload.get("total_record_count")
    valid = payload.get("valid_record_count")
    invalid = payload.get("invalid_record_count")
    integrity_valid = payload.get("integrity_valid")
    diagnostics = payload.get("diagnostics")
    diagnostics_truncated = payload.get("diagnostics_truncated")
    digest = payload.get("sha256")
    if (
        payload.get("domain") != "agent.ledger"
        or type(complete_bytes) is not int
        or complete_bytes < 0
        or type(total) is not int
        or total < 0
        or type(valid) is not int
        or valid < 0
        or type(invalid) is not int
        or invalid < 0
        or valid + invalid != total
        or not isinstance(integrity_valid, bool)
        or diagnostics != []
        or diagnostics_truncated is not False
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
    ):
        raise ValueError("Chronik coding-memory ledger snapshot fields are invalid")
    if integrity_valid is not True or invalid != 0:
        raise ValueError("Chronik coding-memory ledger snapshot integrity check failed")
    return {
        "domain": "agent.ledger",
        "sha256": digest,
        "complete_bytes": complete_bytes,
        "total_record_count": total,
        "valid_record_count": valid,
        "invalid_record_count": invalid,
        "integrity_valid": True,
        "diagnostics": [],
        "diagnostics_truncated": False,
    }


@mcp.tool(name="grabowski_chronik_history", annotations=READ_ONLY)
def grabowski_chronik_history(
    repo: str = "",
    host: str = "",
    component: str = "",
    subject_component: str = "",
    operation: str = "",
    task_class: str = "",
    outcome: str = "",
    since: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """Read bounded historical coding events without asserting current truth.

    The optional component filter is bound to Chronik's canonical producer/source component.
    subject_component independently filters task-context subject.component.
    """
    operator._require_operator_capability("durable_job")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= CHRONIK_HISTORY_MAX_LIMIT
    ):
        raise ValueError(f"limit must be between 1 and {CHRONIK_HISTORY_MAX_LIMIT}")
    normalized = {
        "repo": _chronik_bounded_text(repo, label="repo"),
        "host": _chronik_bounded_text(host, label="host"),
        "component": _chronik_bounded_text(component, label="component"),
        "subject_component": _chronik_bounded_text(subject_component, label="subject_component"),
        "operation": _chronik_bounded_text(operation, label="operation"),
        "task_class": _chronik_bounded_text(task_class, label="task_class"),
        "outcome": _chronik_bounded_text(outcome, label="outcome"),
        "since": _chronik_bounded_text(since, label="since"),
    }
    if bool(normalized["repo"]) == bool(normalized["host"]):
        raise ValueError("exactly one of repo or host is required")
    since_timestamp = (
        _chronik_parse_timestamp(normalized["since"], label="since")
        if normalized["since"]
        else None
    )
    arguments = ["query"]
    target_key = "repo" if normalized["repo"] else "host"
    arguments.append(f"--{target_key}={normalized[target_key]}")
    for key in ("component", "subject_component", "operation", "task_class", "outcome", "since"):
        if normalized[key]:
            arguments.append(f"--{key.replace('_', '-')}={normalized[key]}")
    arguments.append(f"--limit={limit}")
    configuration = chronik.coding_memory_configuration()
    query = {key: value for key, value in normalized.items() if value}
    query["limit"] = limit
    base_payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_chronik_history",
        "query": query,
        "cli_present": bool(configuration["available"]),
        "available": False,
        "historical_only": True,
        "events": [],
        "does_not_establish": list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH),
    }
    if not configuration["available"]:
        return _chronik_receipt(
            {
                **base_payload,
                "failure": {
                    "code": configuration["reason"],
                    "returncode": None,
                    "timed_out": False,
                    "error": None,
                },
            },
            field="result_sha256",
        )

    execution = _chronik_cli_run(
        arguments, configuration=configuration, data_dir=configuration["data_dir"]
    )
    expected_target = (
        {"scope": "repository", "repo": normalized["repo"]}
        if target_key == "repo"
        else {"scope": "host", "host": normalized["host"]}
    )
    try:
        history = _chronik_cli_json(execution)
        if set(history) != _CHRONIK_HISTORY_KEYS:
            raise ValueError("Chronik coding-memory history has invalid fields")
        if history.get("schema_version") != "chronik-coding-history.v1":
            raise ValueError("Chronik coding-memory history contract is stale")
        if history.get("historical_only") is not True:
            raise ValueError("Chronik coding-memory history is not historical-only")
        raw_query = history.get("query")
        expected_query_keys = set(_CHRONIK_QUERY_KEYS)
        if normalized["subject_component"]:
            expected_query_keys.add("subject_component")
        if not isinstance(raw_query, dict) or set(raw_query) != expected_query_keys:
            raise ValueError("Chronik coding-memory history query is unbound")
        bound_query = {
            key: value for key, value in raw_query.items() if value not in (None, "")
        }
        if bound_query != query:
            raise ValueError("Chronik coding-memory history query is unbound")
        if history.get("target") != expected_target:
            raise ValueError("Chronik coding-memory history target is unbound")
        raw_events = history.get("events")
        raw_event_ids = history.get("event_ids")
        raw_claims = history.get("does_not_establish")
        if not isinstance(raw_events, list):
            raise ValueError("Chronik coding-memory history events must be a list of objects")
        if len(raw_events) > limit:
            raise ValueError("Chronik coding-memory history exceeded the requested limit")
        for index, event in enumerate(raw_events, start=1):
            chronik._validate_agent_run_event_shape(
                event, label=f"Chronik coding-memory history event {index}"
            )
            if not _chronik_history_event_matches_query(
                event, normalized, since_timestamp=since_timestamp
            ):
                raise ValueError(
                    f"Chronik coding-memory history event {index} is not bound to the requested query"
                )
        if not isinstance(raw_event_ids, list) or not all(
            isinstance(event_id, str) for event_id in raw_event_ids
        ):
            raise ValueError("Chronik coding-memory history event_ids must be a list of text")
        if raw_event_ids != [event["event_id"] for event in raw_events]:
            raise ValueError("Chronik coding-memory history event_ids are unbound")
        if raw_claims != list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH):
            raise ValueError("Chronik coding-memory history truth exclusions are invalid")
        ledger_snapshot = _validate_chronik_ledger_snapshot(history.get("ledger_snapshot"))
    except ValueError as exc:
        payload = {
            **base_payload,
            "failure": {
                "code": "chronik_coding_memory_cli_failed",
                **_chronik_failure_details(execution),
                "contract_error": str(exc),
            },
        }
    else:
        safe_claims = list(chronik.CODING_MEMORY_DOES_NOT_ESTABLISH)
        history_metadata = {
            "schema_version": "chronik-coding-history.v1",
            "query": dict(raw_query),
            "target": dict(expected_target),
            "event_ids": list(raw_event_ids),
            "historical_only": True,
            "does_not_establish": safe_claims,
            "ledger_snapshot": ledger_snapshot,
        }
        payload = {
            **base_payload,
            "available": True,
            "events": [dict(event) for event in raw_events],
            "history": history_metadata,
        }
    return _chronik_receipt(payload, field="result_sha256")


OPERATOR_HISTORICAL_RECALL_TOOL = "grabowski_operator_historical_recall"
OPERATOR_HISTORICAL_RECALL_CAPABILITY = "durable_job"
OPERATOR_HISTORICAL_RECALL_HELPER = "_require_operator_capability"


def _operator_runtime_head() -> str | None:
    manifest_path = getattr(base, "DEPLOYMENT_MANIFEST", None)
    if not isinstance(manifest_path, Path):
        return None
    try:
        raw = manifest_path.read_bytes()
        if len(raw) > getattr(base, "MAX_MANIFEST_BYTES", 1024 * 1024):
            return None
        manifest = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    source_commit = manifest.get("source_commit") if isinstance(manifest, dict) else None
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", source_commit) is None:
        return None
    return source_commit


def _operator_historical_recall_dependency_failure(*, missing_dependency: str) -> dict[str, Any]:
    runtime_head = _operator_runtime_head()
    return {
        "schema_version": 1,
        "kind": "grabowski_operator_historical_recall",
        "authority": "runtime_dependency_failure",
        "source_trust": recall.HISTORICAL_SOURCE_TRUST,
        "evidence_binding": recall.HISTORICAL_EVIDENCE_BINDING,
        "available": False,
        "historical_only": True,
        "returned": 0,
        "items": [],
        "failure_code": "operator_runtime_dependency_missing",
        "failure": {
            "code": "operator_runtime_dependency_missing",
            "tool": OPERATOR_HISTORICAL_RECALL_TOOL,
            "runtime_head": runtime_head,
            "runtime_head_available": runtime_head is not None,
            "capability": OPERATOR_HISTORICAL_RECALL_CAPABILITY,
            "missing_dependency": missing_dependency,
        },
        "does_not_establish": list(recall.HISTORICAL_RECALL_DOES_NOT_ESTABLISH),
    }


@mcp.tool(name="grabowski_operator_historical_recall", annotations=READ_ONLY)
def grabowski_operator_historical_recall(
    repo: str = "",
    host: str = "",
    component: str = "",
    subject_component: str = "",
    operation: str = "",
    task_class: str = "",
    outcome: str = "",
    since: str = "",
    limit: int = 20,
) -> dict[str, Any]:
    """Read evidence-bound operator recall derived from validated Chronik history."""
    capability_gate = getattr(operator, OPERATOR_HISTORICAL_RECALL_HELPER, None)
    if not callable(capability_gate):
        operator_module = getattr(operator, "__name__", "grabowski_operator_core")
        return _operator_historical_recall_dependency_failure(
            missing_dependency=f"{operator_module}.{OPERATOR_HISTORICAL_RECALL_HELPER}"
        )
    operator._require_operator_capability("durable_job")
    history = grabowski_chronik_history(
        repo=repo,
        host=host,
        component=component,
        subject_component=subject_component,
        operation=operation,
        task_class=task_class,
        outcome=outcome,
        since=since,
        limit=limit,
    )
    return recall.export_chronik_history_recall(history, limit=limit)

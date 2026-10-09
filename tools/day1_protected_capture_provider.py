#!/usr/bin/env python3
"""Opt-in root-only Day-1 capture producer (not a Grabowski task backend).

A fixed root-owned static ELF collector runs under a dedicated unprivileged UID.
The root parent captures its pipes, signs the *observed* bytes, and publishes
the whole bundle atomically. No CLI-configurable command, shell, rootbroker
registration, legacy receipt upgrade, or productive admission is provided.
"""

from __future__ import annotations

import ctypes
import errno
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from typing import Any

POLICY_PATH = Path("/etc/grabowski/day1-capture-policy-v1.json")
SIGNING_KEY_PATH = Path("/etc/grabowski/day1-capture-signing-key")
COLLECTOR_PATH = Path("/usr/local/libexec/grabowski/day1-collector-static")
EVIDENCE_ROOT = Path("/var/lib/grabowski/day1-capture")
SIGN_TOOL = Path("/usr/local/libexec/grabowski/day1-ssh-keygen-static")
CHILD_USER = "grabowski-day1-collector"
PROOF_KIND = "grabowski.day1_capture_prototype_not_admitted"
PROOF_ISSUER = "grabowski-day1-prototype@heimgewebe"
PROOF_NAMESPACE = "grabowski-day1-capture-prototype-v1@heimgewebe"
CAPTURE_BOUNDARY = "protected-parent-pipe-v1"
POLICY_KIND = "grabowski.day1_protected_capture_policy"
MAX_EXECUTABLE = 8 * 1024 * 1024
MAX_POLICY_BYTES = 4096
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_RUNTIME = 300
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
REV_RE = re.compile(r"[0-9a-f]{40}\Z")
POLICY_FIELDS = frozenset({
    "schema_version", "kind", "host", "source_revision",
    "collector_sha256", "signer_sha256", "runtime_seconds",
    "max_stdout_bytes", "max_stderr_bytes",
})


class CaptureDenied(RuntimeError):
    """Fail-closed: no authoritative Day-1 artifact can be claimed."""


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _integer(value: Any, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise CaptureDenied(f"{label} is outside strict contract")
    return value


def _as_canonical_path(path: Path) -> tuple[str, ...]:
    if not path.is_absolute() or not path.name:
        raise CaptureDenied("root-owned path must be absolute")
    parts = path.parts[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise CaptureDenied("path traversal is forbidden")
    return parts


def _owned_directory(fd: int) -> os.stat_result:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
        or (stat.S_IMODE(info.st_mode) & 0o022) != 0
        or info.st_nlink < 1):
        raise CaptureDenied("root directory is not protected from task UID")
    return info


def _open_root_directory(path: Path, *, private: bool = False) -> int:
    parts = _as_canonical_path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        _owned_directory(current)
        for part in parts:
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
            _owned_directory(current)
        if private and stat.S_IMODE(os.fstat(current).st_mode) != 0o700:
            raise CaptureDenied("protected output root must be mode 0700")
        return current
    except BaseException:
        os.close(current)
        raise


def _file_identity(s: os.stat_result) -> tuple[int, ...]:
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _open_root_file(path: Path, *, max_bytes: int, executable: bool = False,
                    private: bool = False) -> tuple[int, bytes]:
    """Open every ancestor as root-owned, nofollow; retain the actual file FD."""
    parts = _as_canonical_path(path)
    parent = _open_root_directory(path.parent)
    fd: int | None = None
    try:
        pre = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=parent)
        original = os.fstat(fd)
        mode = stat.S_IMODE(original.st_mode)
        if (_file_identity(pre) != _file_identity(original)
            or not stat.S_ISREG(original.st_mode) or original.st_uid != 0
            or original.st_nlink != 1 or not 0 < original.st_size <= max_bytes
            or (mode & 0o022) != 0 or (mode & 0o7000) != 0
            or (private and mode != 0o600)
            # The already opened file is execve'd after dropping to a
            # dedicated UID; root-only executable bits would fail closed but
            # SUID/SGID bits must be refused even if NoNewPrivileges is set.
            or (executable and (mode & 0o005) != 0o005)):
            raise CaptureDenied("root-owned file identity/permissions are invalid")
        remaining = original.st_size
        parts_out: list[bytes] = []
        while remaining:
            data = os.read(fd, min(remaining, 65536))
            if not data:
                break
            parts_out.append(data)
            remaining -= len(data)
        current = os.fstat(fd)
        linked = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (remaining or _file_identity(original) != _file_identity(current)
            or _file_identity(original) != _file_identity(linked)):
            raise CaptureDenied("trusted file changed while being read")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, b"".join(parts_out)
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        os.close(parent)


def _policy(payload: bytes, *, hostname: str) -> dict[str, Any]:
    if not payload or len(payload) > MAX_POLICY_BYTES:
        raise CaptureDenied("root policy size is invalid")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CaptureDenied("root policy JSON is invalid") from exc
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS:
        raise CaptureDenied("root policy is not the exact bounded schema")
    if payload != _json_bytes(value):
        raise CaptureDenied("root policy must be canonical JSON")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
        or value["kind"] != POLICY_KIND or value["host"] != hostname):
        raise CaptureDenied("root policy identity or host mismatch")
    for label, regex in (
        ("source_revision", REV_RE),
        ("collector_sha256", SHA_RE),
        ("signer_sha256", SHA_RE),
    ):
        if not isinstance(value[label], str) or regex.fullmatch(value[label]) is None:
            raise CaptureDenied(f"{label} is not an exact digest")
    _integer(value["runtime_seconds"], "runtime_seconds", 1, MAX_RUNTIME)
    for field in ("max_stdout_bytes", "max_stderr_bytes"):
        _integer(value[field], field, 1, MAX_CAPTURE_BYTES)
    return value


def _validate_native_static_elf(data: bytes) -> None:
    """Reject scripts, dynamic linkers, shared libraries and wrong architecture.

    Only ELF64 little-endian x86_64 ET_EXEC with no PT_INTERP/PT_DYNAMIC is
    allowed. This executable and its source revision must be reviewed/pinned
    separately. No PATH/shell/argv supplied by a user is executed.
    """
    if (len(data) < 64 or data[:4] != b"\x7fELF"
        or data[4:6] != b"\x02\x01"):
        raise CaptureDenied("collector is not supported ELF64 static executable")
    try:
        values = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        elf_type, machine, version = values[:3]
        program_offset, elf_header_size, program_size, program_count = (
            values[4], values[7], values[8], values[9]
        )
        if (elf_type != 2 or machine != 62 or version != 1
            or elf_header_size != 64 or program_size != 56
            or not 1 <= program_count <= 128
            or program_offset + program_size * program_count > len(data)):
            raise CaptureDenied("ELF executable header is not tightly allowed")
        for index in range(program_count):
            segment_type = struct.unpack_from(
                "<I", data, program_offset + index * program_size
            )[0]
            if segment_type in (2, 3):  # PT_DYNAMIC or PT_INTERP
                raise CaptureDenied("collector has dynamic loader or imports")
    except struct.error as exc:
        raise CaptureDenied("collector ELF metadata is truncated") from exc


def _separate_child_identity() -> tuple[int, int]:
    try:
        user = pwd.getpwnam(CHILD_USER)
    except KeyError as exc:
        raise CaptureDenied("dedicated child account is not installed") from exc
    try:
        controller = pwd.getpwnam("alex")
        canonical = pwd.getpwuid(user.pw_uid)
        collector_group = grp.getgrgid(user.pw_gid)
        controller_gids = set(os.getgrouplist(controller.pw_name, controller.pw_gid))
    except (KeyError, OSError) as exc:
        raise CaptureDenied(
            "dedicated collector/controller UID and GID cannot be confirmed"
        ) from exc
    if (user.pw_name != CHILD_USER or user.pw_uid < 1 or user.pw_gid < 1
        or user.pw_uid == controller.pw_uid or canonical.pw_name != CHILD_USER
        or collector_group.gr_name != CHILD_USER
        or user.pw_gid == controller.pw_gid
        or user.pw_gid in controller_gids):
        raise CaptureDenied("dedicated capture UID/GID is not isolated")
    if not (user.pw_shell.endswith("/nologin") or user.pw_shell.endswith("/false")):
        raise CaptureDenied("dedicated collector must have a disabled login shell")
    return user.pw_uid, user.pw_gid


def _drop_to_child(uid: int, gid: int) -> None:
    # Only called by Popen in the freshly forked child, never root parent.
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    os.umask(0o077)


# x86_64 Linux Landlock ABI (required by the pinned ELF64 x86-64 policy).
# Landlock alone restricts only filesystem-backed execution. A separate
# Seccomp filter narrows known anonymous execution syscalls; neither filter
# establishes a complete in-process or transitive executable-code closure.
_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_ACCESS_FS_EXECUTE = 1
_PR_SET_NO_NEW_PRIVS = 38

# Resolve libc symbols in the parent at module import, before Popen forks.
# The child must not invoke dlopen/dlsym via ctypes.CDLL in preexec_fn.
# Python preexec_fn still requires the enforced single-thread cgroup gate.
_LANDLOCK_LIBC = ctypes.CDLL(None, use_errno=True)
_LANDLOCK_SYSCALL = _LANDLOCK_LIBC.syscall
_LANDLOCK_SYSCALL.restype = ctypes.c_long
_LANDLOCK_PRCTL = _LANDLOCK_LIBC.prctl
_LANDLOCK_PRCTL.restype = ctypes.c_int


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    # Linux UAPI declares struct landlock_path_beneath_attr packed (12 bytes).
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _confine_child_filesystem_exec(program_fd: int) -> None:
    """Allow filesystem exec only of the previously verified collector inode.

    This runs after UID drop, before the *first* exec, only in the forked
    child. No attempt to enable a product proof: memfd and in-memory
    execution are not covered by a Landlock file rule.
    """
    try:
        info = os.fstat(program_fd)
        if not stat.S_ISREG(info.st_mode):
            raise CaptureDenied("collector execute allowlist is not a regular FD")
        attr = _LandlockRulesetAttr(_LANDLOCK_ACCESS_FS_EXECUTE)
        ruleset_fd = _LANDLOCK_SYSCALL(
            ctypes.c_long(_LANDLOCK_CREATE_RULESET), ctypes.byref(attr),
            ctypes.c_size_t(ctypes.sizeof(attr)), ctypes.c_uint(0),
        )
        if ruleset_fd < 0:
            raise CaptureDenied("Landlock execute ruleset is unavailable")
        try:
            rule = _LandlockPathBeneathAttr(
                _LANDLOCK_ACCESS_FS_EXECUTE, program_fd,
            )
            if _LANDLOCK_SYSCALL(
                ctypes.c_long(_LANDLOCK_ADD_RULE), ctypes.c_int(ruleset_fd),
                ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule), ctypes.c_uint(0),
            ) != 0:
                raise CaptureDenied("Landlock cannot pin the collector executable")
            if _LANDLOCK_PRCTL(
                ctypes.c_int(_PR_SET_NO_NEW_PRIVS), ctypes.c_ulong(1),
                ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0),
            ) != 0:
                raise CaptureDenied("Landlock no_new_privs setup failed")
            if _LANDLOCK_SYSCALL(
                ctypes.c_long(_LANDLOCK_RESTRICT_SELF),
                ctypes.c_int(ruleset_fd), ctypes.c_uint(0),
            ) != 0:
                raise CaptureDenied("Landlock execution restriction not installed")
        finally:
            os.close(ruleset_fd)
    except OSError as exc:
        raise CaptureDenied("Landlock execution restriction unavailable") from exc


# Pinned Linux x86-64 Seccomp UAPI. This is a narrow denial of two known
# anonymous-FD execution routes, NOT a complete executable-code sandbox.
# seccomp_data.arch is at byte offset 4, nr at 0; x32 shares the arch token
# but ORs 0x40000000 into its syscall numbers and must not evade the filter.
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000
_SYS_MEMFD_CREATE = 319
_SYS_EXECVEAT = 322
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JGE_K = 0x35
_BPF_RET_K = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO_EPERM = 0x00050000 | errno.EPERM
_SECCOMP_RET_ALLOW = 0x7FFF0000


class _SeccompSockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32),
    ]


class _SeccompSockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SeccompSockFilter)),
    ]


def _seccomp_anonymous_exec_instructions() -> tuple[_SeccompSockFilter, ...]:
    # Every branch lands on a kernel action without backward jumps. Always
    # check ABI first (including x32) before comparing native syscall IDs.
    return (
        _SeccompSockFilter(_BPF_LD_W_ABS, 0, 0, 4),
        _SeccompSockFilter(_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH_X86_64),
        _SeccompSockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SeccompSockFilter(_BPF_LD_W_ABS, 0, 0, 0),
        _SeccompSockFilter(_BPF_JMP_JGE_K, 0, 1, _X32_SYSCALL_BIT),
        _SeccompSockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SeccompSockFilter(_BPF_JMP_JEQ_K, 0, 1, _SYS_MEMFD_CREATE),
        _SeccompSockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO_EPERM),
        _SeccompSockFilter(_BPF_JMP_JEQ_K, 0, 1, _SYS_EXECVEAT),
        _SeccompSockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ERRNO_EPERM),
        _SeccompSockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
    )


def _confine_child_anonymous_exec() -> None:
    """Block native memfd_create and execveat before the pinned first exec.

    Called ONLY in the already unprivileged, no_new_privs child following
    Landlock. Uses the parent's prebound libc prctl pointer; missing kernel
    support or denial fails closed before any collector bytes are captured.
    This does not rule out arbitrary in-process code or prove full closure.
    """
    try:
        instructions = _seccomp_anonymous_exec_instructions()
        rule_array = (_SeccompSockFilter * len(instructions))(*instructions)
        program = _SeccompSockFprog(len(rule_array), rule_array)
        if _LANDLOCK_PRCTL(
            ctypes.c_int(_PR_SET_SECCOMP), ctypes.c_ulong(_SECCOMP_MODE_FILTER),
            ctypes.byref(program), ctypes.c_ulong(0), ctypes.c_ulong(0),
        ) != 0:
            raise CaptureDenied("seccomp anonymous exec restriction unavailable")
    except OSError as exc:
        raise CaptureDenied("seccomp anonymous exec restriction unavailable") from exc


def _prepare_child_capture(uid: int, gid: int, program_fd: int) -> None:
    _drop_to_child(uid, gid)
    _confine_child_filesystem_exec(program_fd)
    _confine_child_anonymous_exec()


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass



UNIT_CGROUP = "/system.slice/grabowski-day1-protected-capture.service"
UNIT_CGROUP_ROOT = Path("/sys/fs/cgroup" + UNIT_CGROUP)
MAX_CGROUP_CONTROL_BYTES = 128


def _read_proc_cgroup() -> bytes:
    """Read the parent's kernel cgroup identity, never a caller-chosen path."""
    try:
        fd = os.open("/proc/self/cgroup", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            value = os.read(fd, 1025)
        finally:
            os.close(fd)
    except OSError as exc:
        raise CaptureDenied("protected parent cgroup identity is unavailable") from exc
    if not value or len(value) > 1024:
        raise CaptureDenied("protected parent cgroup identity is invalid")
    return value


def _read_cgroup_leaf(directory_fd: int, name: str) -> bytes:
    """Read fixed root-controlled cgroup kernel files via pinned directory FD."""
    if name not in {"pids.max", "pids.current", "cgroup.procs"}:
        raise CaptureDenied("unapproved cgroup control requested")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                     dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or (stat.S_IMODE(info.st_mode) & 0o022) != 0):
                raise CaptureDenied("cgroup control is not root-controlled")
            raw = os.read(fd, MAX_CGROUP_CONTROL_BYTES + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise CaptureDenied("cgroup control is unavailable") from exc
    if not raw or len(raw) > MAX_CGROUP_CONTROL_BYTES:
        raise CaptureDenied("cgroup control is unbounded or empty")
    return raw


def _assert_cgroup_drained() -> None:
    """Require only root parent remains in the exact protected systemd cgroup.

    pids.current counts threads and descendants in nested child cgroups;
    cgroup.procs alone does not. Secondary execve is still NOT confined.
    """
    expected = f"0::{UNIT_CGROUP}\n".encode("ascii")
    if _read_proc_cgroup() != expected:
        raise CaptureDenied("collector is outside its fixed systemd cgroup")
    fd = _open_root_directory(UNIT_CGROUP_ROOT)
    try:
        for _ in range(2):
            if (_read_cgroup_leaf(fd, "pids.max") != b"2\n"
                or _read_cgroup_leaf(fd, "pids.current") != b"1\n"
                or _read_cgroup_leaf(fd, "cgroup.procs")
                    != f"{os.getpid()}\n".encode("ascii")):
                raise CaptureDenied(
                    "protected collector cgroup limit or process tree is unverified"
                )
    finally:
        os.close(fd)
    if _read_proc_cgroup() != expected:
        raise CaptureDenied("protected parent changed cgroup during capture")


def _capture_from_pipes(
    program_fd: int, *, uid: int, gid: int, seconds: int,
    stdout_cap: int, stderr_cap: int,
) -> tuple[bytes, bytes, int, int, int, list[str]]:
    """Direct protected-parent reads, bounded memory, timeout and process group."""
    # Inherited FD pins the already-verified inode for execve via /proc/self/fd.
    command = [f"/proc/self/fd/{program_fd}"]
    begin = int(time.time())
    started = time.monotonic()
    try:
        child = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(program_fd,), close_fds=True,
            start_new_session=True, cwd="/",
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            preexec_fn=lambda: _prepare_child_capture(uid, gid, program_fd),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CaptureDenied("protected collector child could not start") from exc
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_cap, "stderr": stderr_cap}
    selector = selectors.DefaultSelector()
    try:
        assert child.stdout is not None and child.stderr is not None
        for name, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or child.poll() is None:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise CaptureDenied("protected collector timed out")
            for key, _ in selector.select(timeout=min(remaining, 0.2)):
                stream, name = key.fileobj, key.data
                piece = os.read(stream.fileno(), 65536)
                if piece:
                    if len(output[name]) + len(piece) > limits[name]:
                        raise CaptureDenied(f"protected {name} stream exceeded limit")
                    output[name].extend(piece)
                else:
                    selector.unregister(stream)
                    stream.close()
        code = child.wait(timeout=1)
        ended = int(time.time())
        if code != 0:
            raise CaptureDenied("protected collector did not exit successfully")
        return bytes(output["stdout"]), bytes(output["stderr"]), code, begin, ended, command
    except (CaptureDenied, OSError, subprocess.TimeoutExpired) as exc:
        _kill_group(child.pid)
        child.wait(timeout=3)
        if isinstance(exc, CaptureDenied):
            raise
        raise CaptureDenied("protected collector capture was incomplete") from exc
    finally:
        selector.close()
        for stream in (child.stdout, child.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _recheck_executable_fd(
    fd: int, initial_bytes: bytes, *, label: str = "collector executable"
) -> None:
    """Verify pinned protected file FD bytes again, not cached RAM."""
    before = os.fstat(fd)
    if before.st_size != len(initial_bytes) or not stat.S_ISREG(before.st_mode):
        raise CaptureDenied(f"{label} identity changed after use")
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = len(initial_bytes)
    while count:
        data = os.read(fd, min(count, 65536))
        if not data:
            break
        digest.update(data)
        count -= len(data)
    after = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    if (count or _file_identity(before) != _file_identity(after)
        or digest.hexdigest() != _sha(initial_bytes)):
        raise CaptureDenied(f"{label} FD changed during use")


def _canonical_receipt(policy: dict[str, Any], *, hostname: str, code_hash: str,
                       task_id: str, nonce: str, argv: list[str], stdout: bytes,
                       stderr: bytes, started_at: int, terminal_at: int) -> bytes:
    if not 0 <= terminal_at - started_at <= MAX_RUNTIME + 1:
        raise CaptureDenied("actual captured terminal time is invalid")
    # This parent is NOT bound to an observed Grabowski task/attempt/unit or
    # a transitive verified executable closure. A signature must not upgrade
    # these synthetically generated IDs into a production-shaped task proof.
    # The admission verifier in Draft #1389 rejects this deliberately separate
    # prototype kind/namespace/field set, even with a valid SSH signature.
    value = {
        "schema_version": 1,
        "kind": PROOF_KIND,
        "issuer": PROOF_ISSUER,
        "capture_boundary": CAPTURE_BOUNDARY,
        "host": hostname,
        "capture_id": task_id,
        "capture_attempt": 1,
        "provider_unit_template": "grabowski-day1-protected-capture.service",
        "initial_exec_command_sha256": _sha(_json_bytes({"argv": argv})),
        "initial_executable_sha256": code_hash,
        "source_revision_policy_claim": policy["source_revision"],
        "execution_closure_verified": False,
        "actual_task_binding_verified": False,
        "collector_process_tree_verified": False,
        "day1_admission_authorized": False,
        "nonce": nonce,
        "captured_stdout_sha256": _sha(stdout),
        "captured_stdout_bytes": len(stdout),
        "captured_stdout_complete": True,
        "stdout_truncated": False,
        "captured_stderr_sha256": _sha(stderr),
        "captured_stderr_bytes": len(stderr),
        "captured_stderr_complete": True,
        "stderr_truncated": False,
        "parent_capture_started_at_unix": started_at,
        "primary_exit_observed_at_unix": terminal_at,
        "state": "primary_exited_zero_pipes_closed_tree_unverified",
        "primary_exit_code": 0,
    }
    return _json_bytes(value)


def _validate_signer_static(data: bytes) -> None:
    """Reject unpinned runtime loader/libraries before exposing signing key.

    Verifying only the main ssh-keygen executable FD does not bind PT_INTERP,
    libcrypto, libc or other dynamically loaded signer code. No production
    signing is possible until a separately reviewed static signer is staged.
    """
    try:
        _validate_native_static_elf(data)
    except CaptureDenied as exc:
        raise CaptureDenied(
            "signer requires pinned reviewed static ELF without dynamic loader"
        ) from exc


def _sign_receipt(
    payload: bytes, *, expected_signer_sha256: str
) -> bytes:
    """Sign using verified pinned key/signer inodes, never reopened paths."""
    if not isinstance(expected_signer_sha256, str) or not SHA_RE.fullmatch(
        expected_signer_sha256
    ):
        raise CaptureDenied("pinned signer executable SHA-256 is invalid")
    key_fd, key_bytes = _open_root_file(
        SIGNING_KEY_PATH, max_bytes=64 * 1024, private=True,
    )
    try:
        signer_fd, signer_bytes = _open_root_file(
            SIGN_TOOL, max_bytes=4 * 1024 * 1024, executable=True,
        )
        try:
            if _sha(signer_bytes) != expected_signer_sha256:
                raise CaptureDenied("actual signer executable differs from root policy")
            # Enforce the root-owned reviewed static signer before handing its
            # process the pinned private key FD. No dynamic OpenSSH fallback.
            _validate_signer_static(signer_bytes)
            # The trusted parent retains both descriptors through signing.
            # /proc/self/fd/N names the exact checked inode inherited by the
            # child, so root-managed key or package rotations cannot switch it.
            try:
                run = subprocess.run(
                    [
                        f"/proc/self/fd/{signer_fd}", "-Y", "sign",
                        "-f", f"/proc/self/fd/{key_fd}",
                        "-n", PROOF_NAMESPACE,
                    ],
                    pass_fds=(signer_fd, key_fd),
                    input=payload, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False, timeout=15,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise CaptureDenied("root-only signing failed to start") from exc
            _recheck_executable_fd(
                signer_fd, signer_bytes, label="signer executable"
            )
            _recheck_executable_fd(
                key_fd, key_bytes, label="private signing key"
            )
            if (
                run.returncode != 0 or not 0 < len(run.stdout) <= MAX_SIGNATURE_BYTES
                or not run.stdout.startswith(b"-----BEGIN SSH SIGNATURE-----")
                or not run.stdout.rstrip().endswith(b"-----END SSH SIGNATURE-----")
            ):
                raise CaptureDenied("protected evidence could not be signed")
            return run.stdout
        finally:
            os.close(signer_fd)
    finally:
        os.close(key_fd)


def _write_new(fd: int, name: str, blob: bytes) -> None:
    file_fd = os.open(
        name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600, dir_fd=fd,
    )
    try:
        os.fchmod(file_fd, 0o600)
        view = memoryview(blob)
        while view:
            count = os.write(file_fd, view)
            if count <= 0:
                raise CaptureDenied("protected artifact write made no progress")
            view = view[count:]
        os.fsync(file_fd)
    finally:
        os.close(file_fd)
    check_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                       dir_fd=fd)
    try:
        if os.fstat(check_fd).st_size != len(blob):
            raise CaptureDenied("protected artifact size drift during publication")
        rest = len(blob)
        digest = hashlib.sha256()
        while rest:
            part = os.read(check_fd, min(rest, 65536))
            if not part:
                break
            digest.update(part)
            rest -= len(part)
        if rest or digest.hexdigest() != _sha(blob):
            raise CaptureDenied("protected artifact bytes changed after fsync")
    finally:
        os.close(check_fd)


def _check_staging_root_owned(fd: int) -> None:
    info = os.fstat(fd)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise CaptureDenied("staged protected directory mode/owner mismatch")



ATTEMPT_MARKER = ".capture-attempt-v1.json"
MAX_ATTEMPT_MARKER_BYTES = 1024


def _check_attempt_leaf(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
        or not 0 < info.st_size <= MAX_ATTEMPT_MARKER_BYTES):
        raise CaptureDenied("protected capture reservation is not root-owned 0600")


def _read_capture_reservation(root_fd: int) -> dict[str, Any] | None:
    """Read the canonical root-owned reservation via an exact pinned inode."""
    try:
        before = os.stat(ATTEMPT_MARKER, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    try:
        fd = os.open(
            ATTEMPT_MARKER, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
    except OSError as exc:
        raise CaptureDenied("protected capture reservation cannot be opened") from exc
    try:
        opened = os.fstat(fd)
        _check_attempt_leaf(opened)
        if _file_identity(before) != _file_identity(opened):
            raise CaptureDenied("protected capture reservation was replaced")
        remaining = opened.st_size
        chunks: list[bytes] = []
        while remaining:
            data = os.read(fd, min(65536, remaining))
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        trailing = os.read(fd, 1)
        after = os.fstat(fd)
        linked = os.stat(ATTEMPT_MARKER, dir_fd=root_fd, follow_symlinks=False)
        if (remaining or trailing or _file_identity(opened) != _file_identity(after)
            or _file_identity(opened) != _file_identity(linked)):
            raise CaptureDenied("protected capture reservation changed during read")
        raw = b"".join(chunks)
    except OSError as exc:
        raise CaptureDenied("protected capture reservation read failed") from exc
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise CaptureDenied("protected capture reservation is not canonical JSON") from exc
    if (not isinstance(value, dict)
        or set(value) != {
            "schema_version", "kind", "state", "capture_id", "nonce",
            "host", "policy_sha256", "initial_executable_sha256",
        }
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("kind") != "grabowski.day1_capture_reservation_prototype"
        or value.get("state") != "reserved_unreconciled"
        or not isinstance(value.get("capture_id"), str)
        or re.fullmatch(r"[0-9a-f]{24}", value["capture_id"]) is None
        or not isinstance(value.get("nonce"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["nonce"]) is None
        or not isinstance(value.get("host"), str)
        or not value["host"] or len(value["host"]) > 255
        or any(
            not isinstance(value.get(key), str)
            or SHA_RE.fullmatch(value[key]) is None
            for key in ("policy_sha256", "initial_executable_sha256")
        )
        or _json_bytes(value) != raw):
        raise CaptureDenied("protected capture reservation has invalid binding")
    return value


def _reserve_prototype_capture(
    root_fd: int, *, host: str, policy_sha256: str,
    initial_executable_sha256: str,
) -> tuple[str, str]:
    """Persist one capture identity BEFORE exec; never silently retry it.

    Not a Grabowski task/attempt issuer. A restart after crash (or even a
    successful prototype) is deliberately held for independent reconciliation.
    This avoids reissuing unrelated random IDs on an uncertain retry.
    """
    _check_staging_root_owned(root_fd)
    prior = _read_capture_reservation(root_fd)
    if prior is not None:
        if (prior["host"] != host
            or prior["policy_sha256"] != policy_sha256
            or prior["initial_executable_sha256"] != initial_executable_sha256):
            raise CaptureDenied("previous capture reservation binding changed")
        raise CaptureDenied(
            "previous capture reservation requires protected recovery; retry denied"
        )
    try:
        # With a missing reservation, unknown prior publications/stages make
        # issuing a fresh identity unsafe. This is a one-shot evidence root,
        # not a general retry queue or a cleanup/delete mechanism.
        entries = os.listdir(root_fd)
    except OSError as exc:
        raise CaptureDenied("protected capture root is not enumerable") from exc
    if entries:
        raise CaptureDenied("unreconciled protected capture root blocks new attempt")
    value = {
        "schema_version": 1,
        "kind": "grabowski.day1_capture_reservation_prototype",
        "state": "reserved_unreconciled",
        "capture_id": secrets.token_hex(12),
        "nonce": secrets.token_hex(32),
        "host": host,
        "policy_sha256": policy_sha256,
        "initial_executable_sha256": initial_executable_sha256,
    }
    try:
        _write_new(root_fd, ATTEMPT_MARKER, _json_bytes(value))
    except FileExistsError as exc:
        raise CaptureDenied("protected capture reservation already exists") from exc
    try:
        os.fsync(root_fd)
    except OSError as exc:
        raise CaptureDenied(
            "protected capture reservation durability uncertain; retry denied"
        ) from exc
    return value["capture_id"], value["nonce"]


def _publish_bundle(
    root_fd: int, *, task_id: str, nonce: str, stdout: bytes, stderr: bytes,
    receipt: bytes, signature: bytes,
) -> str:
    """Create-only root-owned directory publication; no mutable current pointer."""
    dirname = f"prototype-{task_id}-{nonce}"
    staging = f".incomplete-{task_id}-{nonce}"
    try:
        os.stat(dirname, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise CaptureDenied("protected prototype identity has already been committed")
    os.mkdir(staging, 0o700, dir_fd=root_fd)
    sub_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    try:
        _check_staging_root_owned(sub_fd)
        for name, blob in (
            ("stdout.bin", stdout), ("stderr.bin", stderr),
            ("proof.json", receipt), ("proof.sshsig", signature),
        ):
            _write_new(sub_fd, name, blob)
        os.fsync(sub_fd)
        # A crash before this same-filesystem rename leaves only an ignored
        # .incomplete-* directory, never an authoritative proof-* bundle.
        os.rename(staging, dirname, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        try:
            os.fsync(root_fd)
        except OSError as exc:
            # A prototype-* directory may now be visible but not durable.
            # Never report publication success for this unknown outcome.
            # A real task-proof producer must later reconcile a stable task
            # attempt and nonce, rather than inventing a fresh identity.
            raise CaptureDenied(
                "prototype publication durability uncertain after rename"
            ) from exc
        return dirname
    finally:
        os.close(sub_fd)


def run() -> dict[str, Any]:
    """Root-only fixed-operation entry; never consumes caller-controlled argv."""
    if os.geteuid() != 0:
        raise CaptureDenied("protected collector requires root-owned service authority")
    policy_fd, config_bytes = _open_root_file(POLICY_PATH, max_bytes=MAX_POLICY_BYTES)
    os.close(policy_fd)
    hostname = socket.gethostname()
    policy = _policy(config_bytes, hostname=hostname)
    collector_fd, executable = _open_root_file(
        COLLECTOR_PATH, max_bytes=MAX_EXECUTABLE, executable=True,
    )
    try:
        _validate_native_static_elf(executable)
        actual_sha = _sha(executable)
        if actual_sha != policy["collector_sha256"]:
            raise CaptureDenied("staged collector differs from reviewed root policy")
        uid, gid = _separate_child_identity()
        root_fd = _open_root_directory(EVIDENCE_ROOT, private=True)
        try:
            _assert_cgroup_drained()  # Kernel pids limit before child launch.
            task_id, nonce = _reserve_prototype_capture(
                root_fd, host=hostname, policy_sha256=_sha(config_bytes),
                initial_executable_sha256=actual_sha,
            )
            stdout, stderr, code, started, stopped, argv = _capture_from_pipes(
                collector_fd, uid=uid, gid=gid,
                seconds=policy["runtime_seconds"],
                stdout_cap=policy["max_stdout_bytes"],
                stderr_cap=policy["max_stderr_bytes"],
            )
            if code != 0:
                raise CaptureDenied("protected collector exit was unsuccessful")
            # The opened root-owned executable inode is the process's execve
            # target; only root may change it. Detect any unexpected FD drift.
            _recheck_executable_fd(collector_fd, executable)
            _assert_cgroup_drained()  # No surviving descendants before signing.
            receipt = _canonical_receipt(
                policy, hostname=hostname, code_hash=actual_sha,
                task_id=task_id, nonce=nonce, argv=argv, stdout=stdout,
                stderr=stderr, started_at=started, terminal_at=stopped,
            )
            signed = _sign_receipt(
                receipt, expected_signer_sha256=policy["signer_sha256"]
            )
            _assert_cgroup_drained()  # No new descendant before publication.
            name = _publish_bundle(
                root_fd, task_id=task_id, nonce=nonce,
                stdout=stdout, stderr=stderr, receipt=receipt, signature=signed,
            )
            return {
                "kind": "grabowski.protected_day1_capture_result",
                "status": "root_owned_prototype_bundle_published_not_admitted",
                "capture_id": task_id,
                "bundle_name": name,
                "receipt_sha256": _sha(receipt),
                "source_executable_sha256": actual_sha,
                "day1_admission_authorized": False,
                "ledger_binding_verified": False,
                "real_deployment_verified": False,
            }
        finally:
            os.close(root_fd)
    finally:
        os.close(collector_fd)


def main(argv: list[str]) -> int:
    if argv:
        print("no caller commands or alternative paths are accepted", file=sys.stderr)
        return 2
    try:
        result = run()
    except (CaptureDenied, OSError, ValueError, subprocess.SubprocessError) as exc:
        # No trusted output or key material is printed, even on failure.
        print(f"protected Day-1 capture denied: {type(exc).__name__}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
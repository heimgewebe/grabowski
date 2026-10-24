#!/usr/bin/env python3
"""Fail-closed Codex runner for RepoBrief Agent Benchmark v1.

The runner is intentionally separate from the Claude runner.  It reuses only
provider-neutral request/receipt helpers, binds one exact Codex execution
contract, persists raw provider stdout/stderr *before* interpreting either
stream, and classifies stderr through an explicit policy.

A live provider call requires ``--allow-live-provider`` plus an absolute,
SHA-256-bound Codex executable.  Synthetic fixtures never authorize a provider
call and are the supported way to qualify the contract before a one-shot run.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import fcntl
from datetime import datetime, timezone
import hashlib
import hmac
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import selectors
import signal
import shlex
import shutil
import stat
import socket
import struct
import subprocess
import tempfile
import sys
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any

SOURCE_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024

# Never persist the key: a new process after SIGKILL/RuntimeMaxSec cannot
# continue a previously completed condition under the original pair grant.
_DISPATCH_PROCESS_NONCE = os.urandom(32)


def _live_dispatch_process_binding(pair_id: str) -> str:
    return hmac.new(
        _DISPATCH_PROCESS_NONCE,
        pair_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


ENTRYPOINT_BOOTSTRAP_KIND = "grabowski.python_c_source_bootstrap"
ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION = 1
ENTRYPOINT_BOOTSTRAP_NAME = "repobrief_agent_benchmark_source_bootstrap.py"
ENTRYPOINT_BOOTSTRAP_PATH = Path(__file__).with_name(ENTRYPOINT_BOOTSTRAP_NAME)
MCP_PROXY_PYTHON_LINK = Path("/usr/bin/python3")

# Immutable inline child bootstrap. Only the provider subprocess receives this
# inheritable kernel syscall filter; the trusted runner may still attest root
# systemd through the authenticated system bus before irreversible dispatch.
_UNIX_SOCKET_DENY_CHILD_PROGRAM = """# This isolated Python process installs seccomp before exec'ing Codex.
# An RO filesystem bind does NOT prevent connecting to a privileged Unix socket.
import ctypes
import errno
import os
import socket
import stat
import sys
import sysconfig

# Search only deterministic system library directories, never an environment
# influenced dynamic loader search path or a relative library name.
_SECCOMP_TRUSTED_LIBRARY_ROOTS = ("/usr/lib", "/usr/lib64", "/lib", "/lib64")

def trusted_seccomp_library():
    multiarch = sysconfig.get_config_var("MULTIARCH")
    if not isinstance(multiarch, str) or not multiarch or not all(
        char.isascii() and (char.isalnum() or char in "_+.-")
        for char in multiarch
    ) or multiarch in (".", "..") or ".." in multiarch:
        multiarch = None
    directories = (
        [os.path.join(root, multiarch) for root in _SECCOMP_TRUSTED_LIBRARY_ROOTS]
        if multiarch else []
    ) + list(_SECCOMP_TRUSTED_LIBRARY_ROOTS)
    for directory in dict.fromkeys(directories):
        requested = os.path.join(directory, "libseccomp.so.2")
        if not os.path.lexists(requested):
            continue
        binary = os.path.realpath(requested)
        if not any(
            binary.startswith(root + os.sep)
            for root in _SECCOMP_TRUSTED_LIBRARY_ROOTS
        ):
            raise RuntimeError("untrusted kernel socket filter library location")
        current = os.sep
        for part in binary.split(os.sep)[1:-1]:
            current = os.path.join(current, part)
            info = os.lstat(current)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or (
                stat.S_IMODE(info.st_mode) & 0o022
            ):
                raise RuntimeError("untrusted kernel socket filter directory")
        info = os.lstat(binary)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or (
            stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise RuntimeError("untrusted kernel socket filter library")
        return binary
    raise RuntimeError("trusted kernel socket filter library unavailable")

def deny_unix(block_network=False, pid_isolated=False):
    # The trusted runner and provider may have the same UID. Force a separate
    # session for login/probe subprocesses as well as the live provider. The
    # live Popen already uses start_new_session=True; never join its parent's
    # session, and fail closed if we cannot establish that separation.
    trusted_parent = os.getppid()
    if trusted_parent <= 1:
        raise RuntimeError("trusted signal parent is unavailable")
    try:
        trusted_parent_group = os.getpgid(trusted_parent)
        if os.getpgrp() == trusted_parent_group:
            os.setsid()
        if os.getpgrp() == trusted_parent_group:
            raise RuntimeError("provider shares trusted parent process group")
    except OSError as exc:
        raise RuntimeError("trusted parent signal isolation unavailable") from exc
    library = trusted_seccomp_library()
    seccomp = ctypes.CDLL(library, use_errno=True)
    class Compare(ctypes.Structure):
        _fields_ = [
            ("arg", ctypes.c_uint), ("op", ctypes.c_int),
            ("datum_a", ctypes.c_ulonglong), ("datum_b", ctypes.c_ulonglong),
        ]
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("unable to allocate kernel socket filter")
    try:
        error_action = 0x00050000 | errno.EPERM  # SCMP_ACT_ERRNO(EPERM)
        # Never allow creating a new AF_UNIX endpoint that could connect
        # to an accessible privileged daemon. Kernel syscall int arguments
        # are truncated AFTER seccomp sees the raw 64-bit registers.
        unix_socket = seccomp.seccomp_syscall_resolve_name(b"socket")
        if unix_socket < 0:
            raise RuntimeError("unable to identify Unix socket syscall")
        # Post-provider Git may process hostile repository-local hooks/config.
        # Deny *all* new sockets for it, not just AF_UNIX, including localhost
        # HTTP/INET escape routes; Codex itself retains its scoped INET proxy.
        if block_network:
            socket_rule = seccomp.seccomp_rule_add(
                context, error_action, unix_socket, 0,
            )
        else:
            socket_rule = seccomp.seccomp_rule_add(
                context, error_action, unix_socket, 1,
                Compare(0, 7, 0xffffffff, socket.AF_UNIX),
            )
        if socket_rule != 0:
            raise RuntimeError("unable to deny new kernel sockets")
        # Tokio needs anonymous, already-connected SOCK_STREAM socketpairs
        # for its internal wakeup channel. Such a stream cannot reconnect
        # to a filesystem socket. Reject every other AF_UNIX socketpair type
        # by denying each way the low type nibble differs from SOCK_STREAM.
        unix_pair = seccomp.seccomp_syscall_resolve_name(b"socketpair")
        if unix_pair < 0:
            raise RuntimeError("unable to identify Unix socketpair syscall")
        for mask, bits in ((1, 0), (2, 2), (4, 4), (8, 8)):
            if seccomp.seccomp_rule_add(
                context, error_action, unix_pair, 2,
                Compare(0, 7, 0xffffffff, socket.AF_UNIX),
                Compare(1, 7, mask, bits),
            ) != 0:
                raise RuntimeError("unable to restrict Unix socketpairs")
        # io_uring can submit socket/connect ops without the socket syscall.
        for name in (b"io_uring_setup", b"io_uring_enter", b"io_uring_register"):
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0 or seccomp.seccomp_rule_add(
                context, error_action, syscall, 0,
            ) != 0:
                raise RuntimeError("unable to deny io_uring socket bypass")
        # Prevent the filtered Codex process from taking control of the
        # same-UID trusted (unfiltered) parent through kernel process access.
        for name in (
            b"ptrace", b"process_vm_readv", b"process_vm_writev", b"pidfd_getfd",
        ):
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0 or seccomp.seccomp_rule_add(
                context, error_action, syscall, 0,
            ) != 0:
                raise RuntimeError("unable to deny kernel process introspection")
        # Do not deny ALL child-management signals: Codex must still stop its
        # own commands and process groups on timeout/cancellation. A separate
        # session makes kill(0) local to the provider. The original parent's
        # PID and process-group target, plus broadcast kill(-1), are forbidden.
        # pid_t/tgid are 32-bit arguments; mask before comparison so high
        # syscall-register bits cannot bypass the filter.
        protected_targets = (
            (b"kill", (trusted_parent, -trusted_parent_group, -1)),
            (b"tgkill", (trusted_parent,)),
            (b"rt_sigqueueinfo", (trusted_parent,)),
            (b"rt_tgsigqueueinfo", (trusted_parent,)),
        )
        for name, targets in protected_targets:
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0:
                raise RuntimeError("unable to identify provider signal syscall")
            for target in sorted({item & 0xffffffff for item in targets}):
                if seccomp.seccomp_rule_add(
                    context, error_action, syscall, 1,
                    Compare(0, 7, 0xffffffff, target),
                ) != 0:
                    raise RuntimeError("unable to deny provider-to-parent signals")
        # prlimit64 can mutate any same-UID process's limits without sending
        # a signal. A nonzero PID could be the runner (or any of its threads),
        # and the kernel does not expose child ownership to seccomp. Deny all
        # cross-process targets while retaining pid=0 for the provider itself.
        # An untrusted direct child without PID isolation must never name
        # another same-UID task (including the trusted runner or its TIDs).
        # In the separately attested nested provider PID namespace, ancestor
        # tasks cannot be addressed, so normal child prlimit64 may remain
        # usable. Only the fixed trusted bwrap launcher runs before unshare.
        if not pid_isolated:
            cross_process_prlimit = seccomp.seccomp_syscall_resolve_name(b"prlimit64")
            if cross_process_prlimit < 0 or seccomp.seccomp_rule_add(
                context, error_action, cross_process_prlimit, 1,
                Compare(0, 1, 0, 0),  # SCMP_CMP_NE: requested PID != 0
            ) != 0:
                raise RuntimeError("unable to deny cross-process provider prlimit64")
        # tkill addresses a raw TID and pidfd_send_signal addresses an opaque
        # FD; seccomp cannot safely prove either is not a trusted runner thread.
        for name in (b"tkill", b"pidfd_send_signal"):
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0 or seccomp.seccomp_rule_add(
                context, error_action, syscall, 0,
            ) != 0:
                raise RuntimeError("unable to deny opaque provider signals")
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [
            ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.c_ulong, ctypes.c_ulong,
        ]
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise RuntimeError("kernel no-new-privileges unavailable")
        if seccomp.seccomp_load(context) != 0:
            raise RuntimeError("kernel Unix socket filter unavailable")
    finally:
        seccomp.seccomp_release(context)
    # Verify effective kernel behavior before invoking any Codex bytes.
    for create in (
        lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
        lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM),
        lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET),
    ):
        try:
            created = create()
        except OSError as exc:
            if exc.errno != errno.EPERM:
                raise RuntimeError("kernel Unix socket filter not enforced") from exc
        else:
            for item in created if isinstance(created, tuple) else (created,):
                item.close()
            raise RuntimeError("kernel Unix socket filter not enforced")
    if block_network:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                created = socket.socket(family, socket.SOCK_STREAM)
            except OSError as exc:
                if exc.errno != errno.EPERM:
                    raise RuntimeError("post-provider network filter not enforced") from exc
            else:
                created.close()
                raise RuntimeError("post-provider network filter not enforced")
    try:
        pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as exc:
        raise RuntimeError("anonymous UnixStream wakeup channel unavailable") from exc
    else:
        for item in pair:
            item.close()

args = sys.argv[1:]
block_network = args[:1] == ["--block-network"]
if block_network:
    args = args[1:]
pid_isolated = args[:1] == ["--provider-pid-namespace"]
if pid_isolated:
    args = args[1:]
command = args
if not command or not os.path.isabs(command[0]):
    raise RuntimeError("Codex child executable must be absolute")
if pid_isolated:
    # The only relaxed prlimit profile is allowed for a fixed, root-owned
    # bwrap stage that unshares PID before executing any provider bytes.
    required = [
        "/usr/bin/bwrap", "--ro-bind", "/", "/", "--unshare-pid",
        "--unshare-ipc", "--die-with-parent", "--proc", "/proc",
    ]
    if block_network or command[:len(required)] != required:
        raise RuntimeError("isolated provider PID namespace launcher invalid")
    if "--" not in command or command.index("--") < len(required):
        raise RuntimeError("isolated provider executable bootstrap missing")
deny_unix(block_network=block_network, pid_isolated=pid_isolated)
os.execve(command[0], command, os.environ)
"""


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


def _read_source_snapshot(path: Path) -> tuple[bytes, dict[str, Any]]:
    requested = path.expanduser()
    before = requested.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"cannot safely load {path.name}")
    if before.st_size <= 0 or before.st_size > SOURCE_SNAPSHOT_MAX_BYTES:
        raise RuntimeError(f"cannot safely load {path.name}")
    descriptor = _open_absolute_regular_nofollow(requested, label=f"{path.name} source")
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"{path.name} changed before load")
        data = bytearray()
        while len(data) <= SOURCE_SNAPSHOT_MAX_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, SOURCE_SNAPSHOT_MAX_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            raise RuntimeError(f"{path.name} opened path cannot be bound") from exc
        if (
            not os.path.isabs(descriptor_path)
            or descriptor_path.endswith(" (deleted)")
            or os.path.normpath(descriptor_path) != os.path.normpath(str(requested))
        ):
            raise RuntimeError(f"{path.name} opened path is unavailable")
        after = requested.lstat()
        if (
            len(data) != opened.st_size
            or len(data) > SOURCE_SNAPSHOT_MAX_BYTES
            or (
                after_descriptor.st_dev,
                after_descriptor.st_ino,
                after_descriptor.st_size,
            )
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or (after.st_dev, after.st_ino, after.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
        ):
            raise RuntimeError(f"{path.name} changed during load")
        resolved = Path(descriptor_path)
        return bytes(data), {
            "path": str(resolved),
            "name": resolved.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    finally:
        os.close(descriptor)


_CAPTURED_ENTRYPOINT_ACTIVE = (
    globals().get("__grabowski_captured_entrypoint_active__") is True
)
_CAPTURED_ENTRYPOINT_RAW = globals().get("__grabowski_captured_entrypoint_raw__")
_CAPTURED_ENTRYPOINT_IDENTITY = globals().get(
    "__grabowski_captured_entrypoint_identity__"
)
_ENTRYPOINT_BOOTSTRAP_RAW = globals().get("__grabowski_entrypoint_bootstrap_raw__")
_ENTRYPOINT_BOOTSTRAP_IDENTITY = globals().get(
    "__grabowski_entrypoint_bootstrap_identity__"
)


def _validated_captured_self_source(
    raw: Any, identity: Any, source: Path
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(identity, dict):
        raise RuntimeError("captured Codex runner source binding is invalid")
    data = bytes(raw)
    resolved = source.expanduser().resolve()
    expected = {
        "path": str(resolved),
        "name": resolved.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if identity != expected:
        raise RuntimeError("captured Codex runner source identity mismatch")
    return data, expected


def _validated_entrypoint_bootstrap_context(
    raw: Any, identity: Any
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(raw, (bytes, bytearray)) or not isinstance(identity, dict):
        raise RuntimeError("immutable Codex bootstrap binding is missing")
    data = bytes(raw)
    expected = {
        "schema_version": ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION,
        "kind": ENTRYPOINT_BOOTSTRAP_KIND,
        "name": ENTRYPOINT_BOOTSTRAP_NAME,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if identity != expected:
        raise RuntimeError("immutable Codex bootstrap identity mismatch")
    return data, expected


if __name__ == "__main__":
    if not _CAPTURED_ENTRYPOINT_ACTIVE:
        raise RuntimeError(
            "Codex runner must be started through the immutable source bootstrap"
        )
    _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY = (
        _validated_entrypoint_bootstrap_context(
            _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY
        )
    )
    _SELF_SOURCE_RAW, _SELF_SOURCE_IDENTITY = _validated_captured_self_source(
        _CAPTURED_ENTRYPOINT_RAW,
        _CAPTURED_ENTRYPOINT_IDENTITY,
        Path(__file__),
    )
else:
    _SELF_SOURCE_RAW, _SELF_SOURCE_IDENTITY = _read_source_snapshot(Path(__file__))


def _load_captured_module(name: str, path: Path) -> Any:
    raw, identity = _read_source_snapshot(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
        _after_raw, after_identity = _read_source_snapshot(path)
        if after_identity != identity:
            raise RuntimeError(f"{path.name} changed while being loaded")
    except BaseException:
        sys.modules.pop(name, None)
        raise
    module.__grabowski_source_identity__ = dict(identity)
    return module


BASE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_runner.py")
base = _load_captured_module("repobrief_agent_benchmark_base", BASE_PATH)

PROVIDER = "openai-codex-cli"
MODEL = "gpt-6-astra"
EXECUTION_CONTRACT = "grabowski-codex-cli-live-v1"
SAMPLING = {"reasoning_effort": "medium"}
STDERR_POLICY_VERSION = "codex-stderr-v1"
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_PROVIDER_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_MCP_SOURCE_TREE_FILES = 4096
MAX_MCP_SOURCE_TREE_BYTES = 64 * 1024 * 1024
MAX_MCP_SOURCE_TREE_LISTING_BYTES = 32 * 1024 * 1024
MAX_MCP_STAGE_METADATA_BYTES = 64 * 1024 * 1024
MCP_STAGE_METADATA_NAME = "stage-metadata.json"
MAX_MCP_MANIFEST_ARTIFACTS = 4096
MAX_MCP_MANIFEST_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_AUTH_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_DISPATCH_AUTHORIZATION_BYTES = 16 * 1024 * 1024
MAX_PREFLIGHT_REPORT_BYTES = 16 * 1024 * 1024
MAX_PREFLIGHT_REPORT_DIGEST_BYTES = 512
PREFLIGHT_AUTHORIZATION_REPORT_KIND = (
    "repobrief.agent_benchmark_preflight_dispatch_authorization"
)
PREFLIGHT_LEDGER_KIND = "repobrief.agent_benchmark_preflight_dispatch_ledger"
PREFLIGHT_LEDGER_VERSION = "1.0"
PREFLIGHT_EVENT_KIND = "repobrief.agent_benchmark_preflight_dispatch_event"
DISPATCH_INTENT_LOCK_NAME = ".codex-dispatch-intent.lock"
MAX_DISPATCH_EVENT_BYTES = 1024 * 1024
PERMISSION_PROFILE = "rab-benchmark"
CHATGPT_LOGIN_LINE = "Logged in using ChatGPT"
CODEX_CREDENTIAL_COMMITMENT_KIND = "grabowski.codex_credential_commitment"
CODEX_CREDENTIAL_COMMITMENT_DOMAIN = "grabowski.codex-credential-commitment.v1"
ALLOWED_MCP = {
    "ask_context",
    "grounding_verify",
    "live_freshness",
    "repobrief_resource_read",
}
UPSTREAM_MCP = {"ask_context", "grounding_verify", "live_freshness"}
REPOGROUND_MCP_SCHEMA_CONTRACT_COMMIT = "9c24c2887b4b5724686a5051e5feb8aa54783019"
EXPECTED_REPOGROUND_READ_ONLY_KIND = base.EXPECTED_REPOGROUND_READ_ONLY_KIND
EXPECTED_REPOGROUND_READ_ONLY_VERSION = base.EXPECTED_REPOGROUND_READ_ONLY_VERSION
EXPECTED_REPOGROUND_FRESHNESS_VALUES = base.EXPECTED_REPOGROUND_FRESHNESS_VALUES
EXPECTED_REPOGROUND_FRESHNESS_DOES_NOT_ESTABLISH = (
    base.EXPECTED_REPOGROUND_FRESHNESS_DOES_NOT_ESTABLISH
)
EXPECTED_REPOGROUND_FRONTDOOR_DOES_NOT_ESTABLISH = (
    base.EXPECTED_REPOGROUND_FRONTDOOR_DOES_NOT_ESTABLISH
)
EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH = (
    base.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH
)
EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS = (
    base.EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS
)
EXPECTED_ASK_CONTEXT_PACK_KIND = base.EXPECTED_ASK_CONTEXT_PACK_KIND
EXPECTED_ASK_CONTEXT_PACK_VERSION = base.EXPECTED_ASK_CONTEXT_PACK_VERSION
EXPECTED_GROUNDING_VERDICT_KIND = base.EXPECTED_GROUNDING_VERDICT_KIND
EXPECTED_GROUNDING_VERDICT_VERSION = base.EXPECTED_GROUNDING_VERDICT_VERSION
EXPECTED_GROUNDING_VERDICT_STATUSES = base.EXPECTED_GROUNDING_VERDICT_STATUSES
_REPOGROUND_SELECTOR_PROPERTIES: dict[str, Any] = {
    "bundle_manifest": {
        "type": ["string", "null"],
        "description": "Optional exact manifest path inside the startup bundle root.",
    },
    "repo": {
        "type": ["string", "null"],
        "description": "Repository identity such as owner/repository or repository name.",
    },
    "stem": {
        "type": ["string", "null"],
        "description": "Optional exact snapshot stem.",
    },
}


def _repoground_schema(
    properties: Mapping[str, Any], required: Sequence[str] = ()
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {**_REPOGROUND_SELECTOR_PROPERTIES, **dict(properties)},
        "required": list(required),
        "additionalProperties": False,
    }


EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "ask_context": _repoground_schema(
        {
            "query": {"type": "string"},
            "task_profile": {"type": "string", "default": "basic_repo_question"},
            "max_context_tokens": {"type": "integer", "minimum": 1, "default": 8000},
            "max_answer_tokens": {"type": "integer", "minimum": 1, "default": 1200},
            "k": {"type": "integer", "minimum": 1, "maximum": 100, "default": 5},
            "verbose": {"type": "boolean", "default": False},
        },
        ("query",),
    ),
    "grounding_verify": _repoground_schema(
        {
            "declaration": {"type": "object"},
            "citation_map": {"type": ["string", "null"]},
            "task_profile": {"type": ["string", "null"]},
            "verbose": {"type": "boolean", "default": False},
        },
        ("declaration",),
    ),
    "live_freshness": _repoground_schema({}),
}
_REPOGROUND_READ_ANNOTATIONS: dict[str, bool] = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
}
EXPECTED_UPSTREAM_MCP_DESCRIPTORS: dict[str, dict[str, Any]] = {
    "ask_context": {
        "name": "ask_context",
        "title": "RepoGround context pack",
        "description": "Build a cited context pack from one existing RepoGround bundle.",
        "inputSchema": EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS["ask_context"],
        "annotations": _REPOGROUND_READ_ANNOTATIONS,
    },
    "grounding_verify": {
        "name": "grounding_verify",
        "title": "RepoGround grounding verifier",
        "description": "Verify declared citations and ranges against an existing RepoGround bundle.",
        "inputSchema": EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS["grounding_verify"],
        "annotations": _REPOGROUND_READ_ANNOTATIONS,
    },
    "live_freshness": {
        "name": "live_freshness",
        "title": "RepoGround live freshness",
        "description": "Compare snapshot Git provenance with the configured local checkout without refreshing it.",
        "inputSchema": EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS["live_freshness"],
        "annotations": _REPOGROUND_READ_ANNOTATIONS,
    },
}
MCP_PROFILE_MODERN = "modern"
MCP_PROFILE_FROZEN_G1 = "frozen-g1-lenskit-legacy"
FROZEN_G1_LEGACY_IDENTITY = {
    "taskset_id": "repobrief-agent-benchmark-v1-20260713",
    "taskset_sha256": "834c4a730fe741b6015a69767db162c87c80311a6688dd8e83eb4a6c6e258184",
    "case_id": "grounding-clean-freshness",
    "repository": {
        "id": "lenskit",
        "repository": "heimgewebe/repoground",
        "commit": "dff582f9c4e8b5511d4ce436db81e3e245f725ec",
    },
    "prompt_sha256": "010b2b9f986ea57ad6a33ad729f75e695cf8bd244c155f2d7a4239565fc7b0e9",
    "manifest_sha256": "11b9983e8a41de41dc042b2dfd25dfd68be68e49d0c0065af9dbaa37e3a98179",
    "python_path": "/usr/bin/python3",
    "source_root": "/home/alex/.local/state/grabowski/rab-g1-historical-20261009/lenskit",
    "launcher_path": (
        "/home/alex/.local/state/grabowski/rab-g1-historical-20261009/"
        "lenskit/scripts/repobrief-mcp-stdio.py"
    ),
    "generator_commit": "cc345356056f2d160bc09f4b70e91cd80b36a033",
    "launcher_sha256": "0cf2e6ce0a923632f5d659c3de0552ac189142011e7b21dd9dfdfc97a9bb7873",
    "descriptors_sha256": "12ebf1efaa29a583c5948e2d33c5b3a9c725a6c18645ba81b0b6eea7e773aa96",
}


# The historical Python 3.10 server requires schema validation absent
# from isolated system site. Freeze exact dependency bytes instead of
# admitting ambient user imports or installing mutable global packages.
FROZEN_G1_VENDOR_SITE_ROOT = Path("/home/alex/.local/lib/python3.10/site-packages")
FROZEN_G1_VENDOR_TYPING_EXT = Path(
    "/home/alex/repos/grabowski/.venv/lib/python3.12/site-packages/typing_extensions.py"
)
FROZEN_G1_VENDOR_PACKAGES = (
    "attr",
    "attrs",
    "jsonschema",
    "jsonschema_specifications",
    "referencing",
    "rpds",
)
FROZEN_G1_VENDOR_MANIFEST_SHA256 = (
    "8dbc45b4c54ec79a4e84efec8c5b577031896a081a6fd325a9283bf50c2e9f8a"
)
MAX_FROZEN_G1_VENDOR_FILES = 128
MAX_FROZEN_G1_VENDOR_BYTES = 8 * 1024 * 1024


def _frozen_g1_mcp_profile(request: Mapping[str, Any]) -> str:
    """Enable one historical read-only MCP profile; never negotiate schemas."""
    frozen = FROZEN_G1_LEGACY_IDENTITY
    if (
        request.get("taskset_id") != frozen["taskset_id"]
        or request.get("taskset_sha256") != frozen["taskset_sha256"]
        or request.get("case_id") != frozen["case_id"]
        or request.get("condition") != "treatment"
    ):
        return MCP_PROFILE_MODERN
    binding = request.get("repobrief")
    command = binding.get("mcp_command") if isinstance(binding, Mapping) else None
    if (
        request.get("repository") != frozen["repository"]
        or not isinstance(request.get("prompt"), str)
        or sha_bytes(request["prompt"].encode("utf-8")) != frozen["prompt_sha256"]
        or base.validated_setup(request) != "clean"
        or not isinstance(binding, Mapping)
        or binding.get("manifest_sha256") != frozen["manifest_sha256"]
        or not isinstance(binding.get("manifest"), str)
        or not Path(binding["manifest"]).is_absolute()
        or not isinstance(command, list)
        or len(command) != 6
        or not all(isinstance(item, str) and item for item in command)
        or command[0] != frozen["python_path"]
        or command[1] != frozen["launcher_path"]
        or command[5] != frozen["source_root"]
        or command[2] != "--bundle-root"
        or command[3] != binding["manifest"]
        or command[4] != "--repo-root"
        or not Path(command[5]).is_absolute()
        or Path(command[1]).parent.parent != Path(command[5])
    ):
        raise RunnerError("frozen historical G1 MCP identity is not authorized")
    return MCP_PROFILE_FROZEN_G1


def _frozen_g1_baseline_pair(request: Mapping[str, Any]) -> bool:
    """Gate the exact frozen G1 baseline too; a bad treatment must not burn it."""
    frozen = FROZEN_G1_LEGACY_IDENTITY
    if (
        request.get("taskset_id") != frozen["taskset_id"]
        or request.get("case_id") != frozen["case_id"]
        or request.get("condition") != "baseline"
    ):
        return False
    prompt = request.get("prompt")
    if (
        request.get("taskset_sha256") != frozen["taskset_sha256"]
        or request.get("repository") != frozen["repository"]
        or not isinstance(prompt, str)
        or sha_bytes(prompt.encode("utf-8")) != frozen["prompt_sha256"]
        or base.validated_setup(request) != "clean"
    ):
        raise RunnerError("frozen historical G1 baseline identity is not authorized")
    return True


MCP_CLIENT_METHODS = {
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
}
MAX_FROZEN_RESOURCES = 512

# Exact benign stderr qualified on 2026-09-15 against the current standalone
# Codex CLI and OpenAI's arg0 implementation.  The upstream implementation
# deliberately warns and continues when helper PATH-alias creation fails.  Keep
# this exact: broader warning families remain unqualified and fail closed.
# Source: https://github.com/openai/codex/blob/main/codex-rs/arg0/src/lib.rs
QUALIFIED_BENIGN_STDERR_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"WARNING: proceeding, even though we could not create PATH aliases: "
        r"Read-only file system \(os error 30\)"
    ),
)


# Codex 0.156.1 additionally warns when login status uses a temporary
# CODEX_HOME. Qualify only the exact temp root and snapshot home created by
# this invocation; the live-provider stderr policy remains unchanged.
def _login_status_line_is_qualified(
    line: str, *, snapshot_root: Path, snapshot_home: Path
) -> bool:
    if any(pattern.fullmatch(line) for pattern in QUALIFIED_BENIGN_STDERR_PATTERNS):
        return True
    expected = (
        "WARNING: proceeding, even though we could not create PATH aliases: "
        "Refusing to create helper binaries under temporary dir "
        f'"{snapshot_root.parent}" '
        f'(codex_home: AbsolutePathBuf("{snapshot_home}"))'
    )
    return hmac.compare_digest(line, expected)


RunnerError = base.RunnerError


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _credential_commitment_sha256(credential_data: bytes, nonce: str) -> str:
    credential_sha256 = sha_bytes(credential_data)
    payload = canonical(
        {
            "domain": CODEX_CREDENTIAL_COMMITMENT_DOMAIN,
            "nonce": nonce,
            "credential_sha256": credential_sha256,
        }
    ).encode("utf-8")
    return sha_bytes(payload)


def _validated_authorized_authentication(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "mode",
        "credential_digest_public",
        "credential_bytes",
        "commitment",
    }:
        raise RunnerError("preflight dispatch authorization authentication is invalid")
    commitment = value.get("commitment")
    if (
        value.get("mode") != "chatgpt_subscription"
        or value.get("credential_digest_public") is not False
        or not isinstance(value.get("credential_bytes"), int)
        or isinstance(value.get("credential_bytes"), bool)
        or value.get("credential_bytes") <= 0
        or not isinstance(commitment, dict)
        or set(commitment) != {"schema_version", "kind", "nonce", "commitment_sha256"}
        or commitment.get("schema_version") != 1
        or commitment.get("kind") != CODEX_CREDENTIAL_COMMITMENT_KIND
        or not isinstance(commitment.get("nonce"), str)
        or re.fullmatch(r"[0-9a-f]{32}", commitment["nonce"]) is None
        or not isinstance(commitment.get("commitment_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", commitment["commitment_sha256"]) is None
    ):
        raise RunnerError("preflight dispatch authorization authentication is invalid")
    return json.loads(json.dumps(value))


def _assert_authorized_chatgpt_auth(
    auth_data: bytes, expected: Mapping[str, Any]
) -> None:
    if len(auth_data) != expected.get("credential_bytes"):
        raise RunnerError("ChatGPT credential does not match preflight authorization")
    commitment = expected.get("commitment")
    if not isinstance(commitment, Mapping):
        raise RunnerError("ChatGPT credential authorization is unavailable")
    nonce = commitment.get("nonce")
    expected_digest = commitment.get("commitment_sha256")
    if not isinstance(nonce, str) or not isinstance(expected_digest, str):
        raise RunnerError("ChatGPT credential authorization is unavailable")
    actual = _credential_commitment_sha256(auth_data, nonce)
    if not hmac.compare_digest(actual, expected_digest):
        raise RunnerError("ChatGPT credential does not match preflight authorization")


def _valid_jsonrpc_request_id(value: Any) -> bool:
    return isinstance(value, str) or (
        isinstance(value, int) and not isinstance(value, bool)
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _preflight_request_projection(request: Mapping[str, Any]) -> dict[str, Any]:
    """Legacy Claude projection retained only for negative authorization regression tests."""

    shadow = json.loads(json.dumps(request))
    shadow["runner"] = {
        "execution_contract": base.EXECUTION_CONTRACT,
        "provider": base.PROVIDER,
        "model": "claude-haiku-4-5-20251001",
        "sampling": {},
    }
    return shadow


def validate_request(request: Mapping[str, Any]) -> None:
    """Validate provider-neutral invariants, then bind the exact Codex contract."""

    base._validate_request_common(request)
    expected = {
        "execution_contract": EXECUTION_CONTRACT,
        "provider": PROVIDER,
        "model": MODEL,
        "sampling": SAMPLING,
    }
    if request.get("runner") != expected:
        raise RunnerError("Codex runner contract mismatch")


def validate_executable(
    path_text: str, expected_sha256: str, *, require_read_only_mount: bool = False
) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise RunnerError("codex command SHA-256 is invalid")
    path = Path(path_text)
    if not path.is_absolute():
        raise RunnerError("Codex executable path must be absolute")
    try:
        source_metadata = path.lstat()
        if stat.S_ISLNK(source_metadata.st_mode):
            raise RunnerError("Codex executable path must not be a symlink")
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except RunnerError:
        raise
    except OSError as exc:
        raise RunnerError("Codex executable unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise RunnerError("Codex executable must resolve to a regular file")
    if (
        metadata.st_size <= 0
        or metadata.st_size > MAX_PROVIDER_EXECUTABLE_BYTES
        or metadata.st_mode & 0o111 == 0
    ):
        raise RunnerError("Codex executable metadata invalid")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise RunnerError("Codex executable could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    try:
        after = resolved.lstat()
    except OSError as exc:
        raise RunnerError("Codex executable disappeared during validation") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or digest.hexdigest() != expected_sha256
    ):
        raise RunnerError("Codex executable changed or SHA-256 mismatched")
    if require_read_only_mount:
        try:
            mount_flags = os.statvfs(resolved).f_flag
        except OSError as exc:
            raise RunnerError(
                "Codex executable filesystem could not be verified"
            ) from exc
        if not (mount_flags & getattr(os, "ST_RDONLY", 1)):
            raise RunnerError(
                "live Codex executable must reside on a read-only filesystem"
            )
    return str(resolved)


def _validate_support_executable(
    path: Path, *, owner_uid: int | None = None, require_read_only_mount: bool = False
) -> str:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerError(
            f"required Codex support executable is unavailable: {path}"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RunnerError(f"required Codex support executable is unsafe: {path}")
    if (
        metadata.st_mode & 0o111 == 0
        or metadata.st_mode & 0o022
        or metadata.st_mode & 0o7000
    ):
        raise RunnerError(
            f"required Codex support executable permissions are unsafe: {path}"
        )
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise RunnerError(f"required Codex support executable owner is unsafe: {path}")
    if require_read_only_mount and not (
        os.statvfs(path).f_flag & getattr(os, "ST_RDONLY", 1)
    ):
        raise RunnerError(f"required Codex support executable is not read-only: {path}")
    return str(path)


def _validated_mcp_proxy_python(
    authorized_files: Sequence[Mapping[str, Any]] | None = None,
) -> str:
    try:
        resolved = MCP_PROXY_PYTHON_LINK.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RunnerError(
            "required Codex MCP proxy Python executable is unavailable"
        ) from exc
    validated = _validate_support_executable(resolved, owner_uid=0)
    if authorized_files is not None:
        expected = _normalized_authorized_mcp_files(list(authorized_files))
        current = _mcp_authorization_identity(
            _bind_mcp_file(
                resolved,
                label="Codex MCP proxy Python executable",
                executable=True,
            )
        )
        if current not in expected:
            raise RunnerError(
                "Codex MCP proxy Python executable is not preflight-authorized"
            )
    return validated


def _assert_trusted_runner_nondumpable() -> None:
    """Deny same-UID Codex process inspection before the first Codex child.

    If the privileged-unfiltered runner were ptraceable, a filtered child
    could hijack it and delegate Unix RPC or rewrite trusted evidence.
    PR_SET_DUMPABLE=0 is enforced at the actual Linux process boundary.
    Restrict Yama policy as an additional fail-closed prerequisite.
    """
    if sys.platform != "linux":
        raise RunnerError("Codex parent process isolation requires Linux")
    try:
        yama = Path("/proc/sys/kernel/yama/ptrace_scope").read_bytes()
    except OSError as exc:
        raise RunnerError("Codex kernel ptrace policy unavailable") from exc
    if len(yama) > 16 or yama.strip() not in {b"1", b"2", b"3"}:
        raise RunnerError("Codex kernel ptrace policy is unsafe")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            raise RunnerError("Codex trusted parent cannot disable ptrace")
        if libc.prctl(3, 0, 0, 0, 0) != 0:  # PR_GET_DUMPABLE
            raise RunnerError("Codex trusted parent remains ptraceable")
    except (AttributeError, OSError, ctypes.ArgumentError) as exc:
        raise RunnerError("Codex trusted parent ptrace isolation unavailable") from exc


def _unix_socket_restricted_codex_argv(
    command: Sequence[str],
    *,
    block_network: bool = False,
    provider_pid_namespace: bool = False,
) -> list[str]:
    """Wrap an authorized Codex executable with a fail-closed seccomp exec.

    A DynamicUser and read-only mounts cannot prevent privileged AF_UNIX RPC.
    The root-owned Python interpreter applies a kernel-enforced, exec-inherited
    AF_UNIX and io_uring denial before Codex (or its descendants) run.
    """
    if (
        not command
        or not isinstance(command[0], str)
        or not Path(command[0]).is_absolute()
        or any(not isinstance(argument, str) for argument in command)
    ):
        raise RunnerError("Codex socket isolation command is invalid")
    if type(block_network) is not bool or type(provider_pid_namespace) is not bool:
        raise RunnerError("kernel socket isolation profile is invalid")
    if provider_pid_namespace and (
        block_network
        or list(command[:9])
        != [
            "/usr/bin/bwrap",
            "--ro-bind",
            "/",
            "/",
            "--unshare-pid",
            "--unshare-ipc",
            "--die-with-parent",
            "--proc",
            "/proc",
        ]
    ):
        raise RunnerError("provider PID namespace profile requires trusted bwrap")
    python = _validated_mcp_proxy_python()
    prefix = ["--block-network"] if block_network else []
    if provider_pid_namespace:
        prefix.append("--provider-pid-namespace")
    return [python, "-I", "-c", _UNIX_SOCKET_DENY_CHILD_PROGRAM, *prefix, *command]


_PROVIDER_PID_ATTEST_AND_EXEC_PROGRAM = r"""
import os
from pathlib import Path
import sys

# These exact arguments are constructed by the trusted parent, never by Codex.
if len(sys.argv) < 10 or sys.argv[8] != "--":
    raise RuntimeError("provider PID sandbox bootstrap arguments are invalid")
outer_pid_ns, source, state, transcripts, evidence, reports, codex_home = sys.argv[1:8]
command = sys.argv[9:]
if (
    not outer_pid_ns.startswith("pid:[")
    or not outer_pid_ns.endswith("]")
    or not command
    or not os.path.isabs(command[0])
    or not hasattr(os, "ST_RDONLY")
):
    raise RuntimeError("provider PID sandbox bootstrap identity is invalid")
# /proc is a freshly mounted procfs for the new PID namespace.  Merely
# using a different mount namespace is not sufficient to hide host TIDs.
if os.readlink("/proc/self/ns/pid") == outer_pid_ns:
    raise RuntimeError("provider still shares the trusted parent's PID namespace")
status = Path("/proc/self/status").read_text(encoding="ascii")
nspid = [line.split(":", 1)[1].split() for line in status.splitlines()
         if line.startswith("NSpid:")]
if len(nspid) != 1 or nspid[0] != [str(os.getpid())]:
    raise RuntimeError("provider procfs does not belong to isolated PID namespace")
if not (os.statvfs("/").f_flag & os.ST_RDONLY):
    raise RuntimeError("provider root filesystem is writable")
if not (os.statvfs(source).f_flag & os.ST_RDONLY):
    raise RuntimeError("provider immutable source is writable")
for output in (state, transcripts, evidence, reports):
    if not (os.statvfs(output).f_flag & os.ST_RDONLY):
        raise RuntimeError("trusted epoch output is writable inside provider namespace")
if (
    Path(codex_home).parent.name != "codex-runtime"
    or Path(codex_home).parent.parent != Path(state)
    or os.statvfs(codex_home).f_flag & os.ST_RDONLY
    or os.environ.get("CODEX_HOME") != codex_home
):
    raise RuntimeError("provider session home mount or environment is invalid")
fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
if (
    fields.get("NoNewPrivs", "").strip() != "1"
    or fields.get("Seccomp", "").strip() != "2"
    or int(fields.get("CapEff", "1").strip(), 16) != 0
):
    raise RuntimeError("provider kernel privileges or seccomp are unsafe")
os.execve(command[0], command, os.environ)
"""


def _provider_pid_namespaced_codex_argv(
    command: Sequence[str],
    *,
    source: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_root: Path,
    codex_home: Path,
) -> list[str]:
    """Run hostile provider bytes below a distinct PID namespace.

    Seccomp can compare numeric PID arguments, but cannot prove that a TID
    belongs to the trusted parent. A separate PID namespace makes *all*
    ancestor process and thread IDs unreachable while retaining normal
    signals and prlimit64 handling for the provider's own children.
    """
    if (
        not command
        or any(not isinstance(arg, str) for arg in command)
        or not Path(command[0]).is_absolute()
        or sys.platform != "linux"
    ):
        raise RunnerError("provider PID sandbox command is invalid")
    requested = {
        "state": state_root,
        "transcripts": transcript_root,
        "evidence": evidence_root,
        "reports": report_root,
    }
    try:
        source_real = source.expanduser().resolve(strict=True)
        outputs = {
            name: path.expanduser().resolve(strict=True)
            for name, path in requested.items()
        }
        home = Path.home().resolve(strict=True)
        private_home = codex_home.expanduser().resolve(strict=True)
        private_home_stat = private_home.lstat()
        outer_pid_ns = os.readlink("/proc/self/ns/pid")
    except (OSError, RuntimeError) as exc:
        raise RunnerError("provider PID sandbox paths are unavailable") from exc
    epoch = outputs["state"].parent
    if (
        home not in epoch.parents
        or any(
            path.parent != epoch or path.name != name for name, path in outputs.items()
        )
        or len(set(outputs.values())) != 4
        or private_home.parent.parent != outputs["state"]
        or private_home.parent.name != "codex-runtime"
        or re.fullmatch(r"session-[0-9a-f]{24}", private_home.name) is None
        or private_home != codex_home.expanduser().absolute()
        or not stat.S_ISDIR(private_home_stat.st_mode)
        or private_home_stat.st_uid != os.geteuid()
        or stat.S_IMODE(private_home_stat.st_mode) != 0o700
        or not outer_pid_ns.startswith("pid:[")
        or not outer_pid_ns.endswith("]")
    ):
        raise RunnerError("provider PID sandbox output binding is invalid")
    # Private /tmp is ephemeral; prevent it from hiding any protected input
    # or the only copy of a permitted epoch output directory.
    temp = Path("/tmp")
    if any(
        path == temp or temp in path.parents
        for path in (source_real, private_home, *outputs.values())
    ):
        raise RunnerError("provider PID sandbox cannot shadow bound paths")
    bwrap = [
        "/usr/bin/bwrap",
        "--ro-bind",
        "/",
        "/",
        "--unshare-pid",
        "--unshare-ipc",
        "--die-with-parent",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--chmod",
        "1777",
        "/tmp",
        # Root's systemd LoadCredential directory remains available to the
        # trusted outer runner, but never to the isolated Codex process or
        # model-driven tools. A read-only root bind would expose these bytes.
        "--tmpfs",
        "/run/credentials",
    ]
    # Only the unique private per-session Codex home is writable to hostile
    # provider bytes; trusted state, ledger, receipts and reports remain RO.
    bwrap.extend(("--bind", str(private_home), str(private_home)))
    bwrap.extend(
        (
            "--",
            _validated_mcp_proxy_python(),
            "-I",
            "-B",
            "-c",
            _PROVIDER_PID_ATTEST_AND_EXEC_PROGRAM,
            outer_pid_ns,
            str(source_real),
            *(str(path) for path in outputs.values()),
            str(private_home),
            "--",
            *command,
        )
    )
    return bwrap


def _assert_provider_pid_namespace_ready(
    *,
    source: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_root: Path,
    codex_home: Path,
    cwd: Path,
    codex_command: str | None = None,
) -> None:
    """Exercise the real outer bwrap PIDNS (and nested Codex sandbox) before intent."""
    probe = _provider_pid_namespaced_codex_argv(
        [
            _validated_mcp_proxy_python(),
            "-I",
            "-B",
            "-c",
            "print('RAB_PID_NAMESPACE_READY')",
        ],
        source=source,
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_root=report_root,
        codex_home=codex_home,
    )
    try:
        completed = subprocess.run(
            _unix_socket_restricted_codex_argv(probe, provider_pid_namespace=True),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={**base._git_environment(), "CODEX_HOME": str(codex_home)},
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError("provider PID sandbox smoke unavailable") from exc
    if (
        completed.returncode != 0
        or completed.stdout != b"RAB_PID_NAMESPACE_READY\n"
        or completed.stderr
    ):
        raise RunnerError("provider PID sandbox smoke failed")
    if codex_command is None:
        # Older no-provider kernel regressions cover parent-TID isolation
        # without an installed Codex CLI. The live path always supplies Codex.
        return

    private_tmp, tmp_fd = _open_private_directory(codex_home / "tmp")
    os.close(tmp_fd)
    filesystem = (
        '{":minimal"="read",":workspace_roots"={"."="read"},'
        + _toml_string(str(private_tmp))
        + '="read",'
        + _toml_string(str(Path(codex_command).parent))
        + '="read"}'
    )
    nested_command = [
        codex_command,
        "sandbox",
        "-c",
        "allow_login_shell=false",
        "-c",
        "features.network_proxy=true",
        "-c",
        f"permissions.{PERMISSION_PROFILE}.filesystem={filesystem}",
        "-c",
        f'permissions.{PERMISSION_PROFILE}.network={{enabled=false,mode="limited",allow_local_binding=false,domains={{}}}}',
        "--permission-profile",
        PERMISSION_PROFILE,
        "--enable",
        "network_proxy",
        "--cd",
        str(cwd),
        "--",
        "/bin/true",
    ]
    nested = _provider_pid_namespaced_codex_argv(
        nested_command,
        source=source,
        state_root=state_root,
        transcript_root=transcript_root,
        evidence_root=evidence_root,
        report_root=report_root,
        codex_home=codex_home,
    )
    try:
        nested_result = subprocess.run(
            _unix_socket_restricted_codex_argv(nested, provider_pid_namespace=True),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=provider_env(codex=codex_command, codex_home=codex_home),
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError(
            "nested Codex sandbox smoke unavailable before intent"
        ) from exc
    if (
        nested_result.returncode != 0
        or not isinstance(nested_result.stdout, bytes)
        or not isinstance(nested_result.stderr, bytes)
        or len(nested_result.stdout) > 8192
        or len(nested_result.stderr) > 8192
    ):
        raise RunnerError("nested Codex sandbox smoke failed before intent")


_POST_PROVIDER_GIT_ISOLATED_PROGRAM = r"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

if len(sys.argv) != 5:
    raise RuntimeError("invalid frozen checkout readback arguments")
base_path, checkout_path, source_path = map(Path, sys.argv[1:4])
expected_base_sha256 = sys.argv[4]
if not all(path.is_absolute() for path in (base_path, checkout_path, source_path)):
    raise RuntimeError("post-provider attestation must use absolute paths")
# The trusted parent passes an immutable source-byte snapshot in its pipe.
# The child MUST NOT reload Python code from a mutable filesystem pathname.
read_limit = 1024 * 1024 + 16 * 1024 * 1024 + 4
raw = sys.stdin.buffer.read(read_limit + 1)
if len(raw) < 5 or len(raw) > read_limit:
    raise RuntimeError("post-provider frozen input is unbounded")
request_length = struct.unpack("!I", raw[:4])[0]
if request_length < 1 or request_length > 1024 * 1024 or len(raw) < 4 + request_length:
    raise RuntimeError("post-provider request framing is invalid")
request = json.loads(raw[4:4 + request_length])
if not isinstance(request, dict):
    raise RuntimeError("post-provider request is invalid")
base_source = raw[4 + request_length:]
if (
    not base_source
    or len(base_source) > 16 * 1024 * 1024
    or len(expected_base_sha256) != 64
    or hashlib.sha256(base_source).hexdigest() != expected_base_sha256
):
    raise RuntimeError("post-provider base source identity is not authorized")
spec = importlib.util.spec_from_loader(
    "post_provider_frozen_base", loader=None, origin=str(base_path)
)
if spec is None:
    raise RuntimeError("trusted base module cannot be loaded")
base = importlib.util.module_from_spec(spec)
base.__file__ = str(base_path)
exec(compile(base_source, str(base_path), "exec"), base.__dict__)
# Prevent fsmonitor, hooks and Git optional index writes even if the
# checkout's local configuration was modified by untrusted Codex.
original_git_environment = base._git_environment
def isolated_git_environment():
    env = original_git_environment()
    env.update({
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env
base._git_environment = isolated_git_environment
checkout = Path(checkout_path)
source = Path(source_path)
if any(
    not (os.statvfs(path).f_flag & os.ST_RDONLY)
    for path in (base_path, checkout, source)
):
    raise RuntimeError("post-provider input is writable inside read-only sandbox")
# Never run Git against the provider-writable checkout after model execution:
# its .git/config, info/attributes, filters, refs and gitfile can forge status
# and execute programs. Read ONLY the immutable source's Git tree and compare
# each physical tracked file against its exact Git object, without filters.
import re
import stat
import subprocess

expected = request["repository"]["commit"]
if not isinstance(expected, str) or re.fullmatch("[0-9a-f]{40}", expected) is None:
    raise RuntimeError("bound source Git commit identity is invalid")
setup = base.validated_setup(request)
MAX_TREE_BYTES = 16 * 1024 * 1024
MAX_FILES = 65536
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
total_read = [0]

def bound_file_digests(path, *, executable=None):
    first = path.lstat()
    if (
        not stat.S_ISREG(first.st_mode)
        or first.st_nlink != 1
        or first.st_size > MAX_FILE_BYTES
        or (executable is not None and bool(first.st_mode & 0o111) != executable)
    ):
        raise RuntimeError("untrusted checkout file type, mode or size")
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode,
            opened.st_mtime_ns
        ) != (
            first.st_dev, first.st_ino, first.st_size, first.st_mode,
            first.st_mtime_ns
        ):
            raise RuntimeError("untrusted checkout file identity changed")
        sha1 = hashlib.sha1()
        sha1.update(b"blob " + str(opened.st_size).encode("ascii") + b"\0")
        sha256 = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            count += len(chunk)
            total_read[0] += len(chunk)
            if count > opened.st_size or total_read[0] > MAX_TOTAL_BYTES:
                raise RuntimeError("untrusted checkout file bytes exceed bounds")
            sha1.update(chunk)
            sha256.update(chunk)
        after = os.fstat(descriptor)
        if (
            count != opened.st_size
            or (
                after.st_dev, after.st_ino, after.st_size, after.st_mode,
                after.st_mtime_ns
            ) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode,
                opened.st_mtime_ns
            )
        ):
            raise RuntimeError("untrusted checkout file changed during readback")
        return sha1.hexdigest(), sha256.hexdigest()
    finally:
        os.close(descriptor)

# Freeze the checkout's mutable Git control metadata before intent. A provider
# editing .git/HEAD/config/index/info/attributes is rejected even if tracked
# bytes happen to remain identical. Never interpret these bytes as Git config.
git_root = checkout / ".git"
git_info = git_root.lstat()
if not stat.S_ISDIR(git_info.st_mode):
    raise RuntimeError("provider checkout Git metadata is not a directory")
controls = (
    "HEAD", "config", "index", "info/attributes", "info/exclude",
    "objects/info/alternates", "commondir", "gitdir", "packed-refs"
)
control_hash = hashlib.sha256()
for relative in controls:
    current = git_root
    parts = Path(relative).parts
    for component in parts[:-1]:
        current = current / component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current = None
            break
        if not stat.S_ISDIR(metadata.st_mode):
            raise RuntimeError("untrusted Git control parent is not a directory")
    target = None if current is None else current / parts[-1]
    control_hash.update(relative.encode("ascii") + b"\0")
    try:
        info = target.lstat() if target is not None else None
    except FileNotFoundError:
        info = None
    if info is None:
        control_hash.update(b"absent\0")
        if relative in ("HEAD", "config", "index"):
            raise RuntimeError("provider checkout mandatory Git control is absent")
        continue
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("provider Git control is linked or not regular")
    _sha1, content_hash = bound_file_digests(target)
    control_hash.update(info.st_mode.to_bytes(4, "little"))
    control_hash.update(bytes.fromhex(content_hash))
    if relative == "HEAD":
        if target.read_bytes() != (expected + "\n").encode("ascii"):
            raise RuntimeError("provider checkout detached HEAD changed")

# Inspect committed tree with Git in the immutable source, NEVER in checkout.
listing = subprocess.run(
    ["/usr/bin/git", "-C", str(source), "ls-tree", "-r",
     "--full-tree", "-z", expected],
    env=base._git_environment(),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    check=False,
    timeout=30,
)
if (
    listing.returncode != 0
    or len(listing.stdout) > MAX_TREE_BYTES
    or len(listing.stderr) > 4096
    or not listing.stdout.endswith(b"\0")
):
    raise RuntimeError("immutable source Git tree listing invalid")
tracked = {}
expected_directories = set()
for entry in listing.stdout[:-1].split(b"\0"):
    metadata, tab, relative = entry.partition(b"\t")
    header = metadata.split(b" ")
    components = relative.split(b"/")
    if (
        tab != b"\t"
        or len(header) != 3
        or header[0] not in (b"100644", b"100755")
        or header[1] != b"blob"
        or re.fullmatch(rb"[0-9a-f]{40}", header[2]) is None
        or len(entry) > 8192
        or not 1 <= len(components) <= 30
        or any(part in (b"", b".", b"..") for part in components)
        or components[0] == b".git"
    ):
        raise RuntimeError("immutable source Git tree has unsupported entries")
    rel = Path(os.fsdecode(relative))
    if rel in tracked:
        raise RuntimeError("duplicate immutable Git tree entry")
    tracked[rel] = (header[0] == b"100755", header[2].decode("ascii"))
    for depth in range(1, len(components)):
        expected_directories.add(Path(os.fsdecode(b"/".join(components[:depth]))))
    if len(tracked) + len(expected_directories) > MAX_FILES:
        raise RuntimeError("immutable source tree too large")

expected_files = set(tracked)
if setup == "dirty":
    fixture = Path(base.DIRTY_FIXTURE_NAME)
    if fixture in tracked or len(fixture.parts) != 1:
        raise RuntimeError("dirty fixture aliases committed path")
    expected_files.add(fixture)
seen = set()
entries_seen = 0
for directory, directories, filenames in os.walk(checkout, followlinks=False):
    current = Path(directory)
    ancestor = current.relative_to(checkout)
    for child in list(directories):
        relative = ancestor / child
        info = (current / child).lstat()
        if relative == Path(".git") and ancestor == Path("."):
            if not stat.S_ISDIR(info.st_mode):
                raise RuntimeError("provider checkout git root is invalid")
            directories.remove(child)
            continue
        if not stat.S_ISDIR(info.st_mode) or relative not in expected_directories:
            raise RuntimeError("provider checkout has unexpected directory")
    for child in filenames:
        relative = ancestor / child
        if relative not in expected_files or relative in seen:
            raise RuntimeError("provider checkout has unexpected file")
        info = (current / child).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("provider checkout contains linked or special file")
        seen.add(relative)
    entries_seen += len(directories) + len(filenames)
    if entries_seen > MAX_FILES or len(ancestor.parts) > 32:
        raise RuntimeError("provider checkout exceeds filesystem scan bounds")
if seen != expected_files:
    raise RuntimeError("provider checkout missing committed file")

for relative, (executable, object_id) in tracked.items():
    original_sha1, original_sha256 = bound_file_digests(
        source / relative, executable=executable
    )
    checkout_sha1, checkout_sha256 = bound_file_digests(
        checkout / relative, executable=executable
    )
    if (
        original_sha1 != object_id
        or checkout_sha1 != object_id
        or original_sha256 != checkout_sha256
    ):
        raise RuntimeError("provider checkout tracked file differs from source commit")

status = b""
fixture_sha256 = None
if setup == "dirty":
    path = checkout / base.DIRTY_FIXTURE_NAME
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o777 != 0o600
        or info.st_uid != os.geteuid()
        or path.read_bytes() != base.DIRTY_FIXTURE_BYTES
    ):
        raise RuntimeError("provider dirty fixture differs from frozen bytes")
    status = ("?? " + base.DIRTY_FIXTURE_NAME).encode("utf-8")
    fixture_sha256 = hashlib.sha256(base.DIRTY_FIXTURE_BYTES).hexdigest()

# The immutable source is itself still subject to the root/kernel mount check
# and the original clean-source attestation, but it cannot delegate via the
# mutable provider checkout.
if (
    base._run_checked(["git", "rev-parse", "HEAD"], cwd=source) != expected
    or base._run_checked(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=source
    )
):
    raise RuntimeError("historical benchmark source checkout changed")
scenario = {
    "working_tree": setup,
    "git_commit": expected,
    "status_sha256": hashlib.sha256(status).hexdigest(),
    "fixture_sha256": fixture_sha256,
}
sys.stdout.write(json.dumps(
    {"scenario": scenario, "git_control_sha256": control_hash.hexdigest()},
    sort_keys=True, separators=(",", ":")
))
"""


def _secure_post_provider_checkout_readback(
    request: Mapping[str, Any],
    checkout: Path,
    source: Path,
    *,
    expected_git_control_sha256: str | None = None,
    git_control_out: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect potentially hostile post-Codex Git only in a read-only child.

    The root filesystem is bind-mounted read-only, IPC/PID are unshared,
    /dev and /tmp are private, and a seccomp filter denies ALL new sockets,
    including network sockets, before bwrap and its user namespace run.
    This avoids accepting unmapped UID 65534 as a trusted library owner.
    The unfiltered parent never invokes Git with untrusted checkout config.
    """
    if (
        not checkout.is_absolute()
        or not source.is_absolute()
        or not checkout.is_dir()
        or not source.is_dir()
    ):
        raise RunnerError("post-provider checkout readback paths are invalid")
    try:
        encoded_request = canonical(dict(request)).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RunnerError("post-provider checkout request is invalid") from exc
    if len(encoded_request) > base.MAX_REQUEST_BYTES:
        raise RunnerError("post-provider checkout request is unbounded")
    # Validate the exact captured base module identity before transferring its
    # current frozen bytes.  A late host-side source replacement must not
    # become executed code in this otherwise read-only child.
    try:
        base_raw, base_identity = _read_source_snapshot(BASE_PATH)
    except (OSError, RuntimeError) as exc:
        raise RunnerError("post-provider base source snapshot unavailable") from exc
    if base_identity != getattr(base, "__grabowski_source_identity__", None):
        raise RunnerError("post-provider base source differs from captured code")
    frozen_input = struct.pack("!I", len(encoded_request)) + encoded_request + base_raw
    command = [
        "/usr/bin/bwrap",
        "--ro-bind",
        "/",
        "/",
        "--unshare-ipc",
        "--unshare-pid",
        "--die-with-parent",
        "--new-session",
        "--tmpfs",
        "/tmp",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--chdir",
        "/",
        "--",
        _validated_mcp_proxy_python(),
        "-I",
        "-B",
        "-c",
        _POST_PROVIDER_GIT_ISOLATED_PROGRAM,
        str(BASE_PATH),
        str(checkout),
        str(source),
        base_identity["sha256"],
    ]
    try:
        completed = run_bounded(
            _unix_socket_restricted_codex_argv(command, block_network=True),
            cwd=Path("/"),
            timeout_seconds=90,
            stdin_data=frozen_input,
            environment=base._git_environment(),
            stdout_limit=8192,
            stderr_limit=8192,
        )
    except (OSError, subprocess.SubprocessError, RunnerError) as exc:
        raise RunnerError("post-provider Git isolation unavailable") from exc
    # Bounded capture kills the whole isolated process group after the first
    # overflow byte.  A malicious filter subprocess must not fill trusted
    # memory or hide the evidence before the provider ledger is terminalized.
    if (
        completed.get("capture_error") is not None
        or completed.get("stdout_overflow") is not False
        or completed.get("stderr_overflow") is not False
        or completed.get("returncode") != 0
        or not isinstance(completed.get("stdout"), bytes)
        or not isinstance(completed.get("stderr"), bytes)
        or len(completed["stdout"]) > 8192
        or len(completed["stderr"]) > 8192
    ):
        raise RunnerError("post-provider Git isolation failed")
    try:
        result = json.loads(completed["stdout"])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError("post-provider Git readback is invalid") from exc
    if not isinstance(result, dict) or set(result) != {
        "scenario",
        "git_control_sha256",
    }:
        raise RunnerError("post-provider Git readback differs from bound request")
    control = result["git_control_sha256"]
    scenario = result["scenario"]
    if (
        not isinstance(control, str)
        or re.fullmatch(r"[0-9a-f]{64}", control) is None
        or not isinstance(scenario, dict)
        or set(scenario)
        != {
            "working_tree",
            "git_commit",
            "status_sha256",
            "fixture_sha256",
        }
        or scenario["git_commit"] != request["repository"]["commit"]
        or scenario["working_tree"] != base.validated_setup(request)
        or not isinstance(scenario["status_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", scenario["status_sha256"]) is None
        or (
            scenario["fixture_sha256"] is not None
            and (
                not isinstance(scenario["fixture_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", scenario["fixture_sha256"]) is None
            )
        )
    ):
        raise RunnerError("post-provider Git readback differs from bound request")
    if expected_git_control_sha256 is not None and not hmac.compare_digest(
        control, expected_git_control_sha256
    ):
        raise RunnerError("post-provider Git control metadata changed")
    if git_control_out is not None:
        git_control_out["sha256"] = control
    return scenario


def validate_toolchain(codex: str) -> str:
    bundled_rg = Path(codex).parent.parent / "codex-path" / "rg"
    _validate_support_executable(bundled_rg, require_read_only_mount=True)
    for path in (Path("/usr/bin/cat"), Path("/usr/bin/sed"), Path("/bin/bash")):
        _validate_support_executable(path, owner_uid=0)
    _validated_mcp_proxy_python()
    _validate_support_executable(
        Path("/usr/bin/bwrap"), owner_uid=0, require_read_only_mount=True
    )
    return f"{bundled_rg.parent}:/usr/bin:/bin"


def _kernel_procfs_mount_id(fd: int) -> int:
    """Authenticate the kernel filesystem and mount object of an open proc FD."""
    # Linux statfs begins with native long f_type; statx has a fixed 256-byte
    # ABI with stx_mask at 0 and stx_mnt_id at 144.
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fstatfs = libc.fstatfs
        statx = libc.statx
        fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
        fstatfs.restype = ctypes.c_int
        statx.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_void_p,
        )
        statx.restype = ctypes.c_int
        fs_info = ctypes.create_string_buffer(256)
        mount_info = ctypes.create_string_buffer(256)
        if fstatfs(fd, ctypes.byref(fs_info)) != 0:
            raise RunnerError("live Codex kernel procfs type is unavailable")
        if ctypes.c_long.from_buffer_copy(fs_info).value != 0x9FA0:
            raise RunnerError("live Codex isolation source is not kernel procfs")
        # AT_EMPTY_PATH binds statx to this exact opened file, not a later
        # pathname lookup. STATX_MNT_ID identifies individual Linux binds.
        if statx(fd, b"", 0x1000, 0x1000, ctypes.byref(mount_info)) != 0:
            raise RunnerError("live Codex kernel procfs mount ID is unavailable")
        mask = ctypes.c_uint32.from_buffer_copy(mount_info, 0).value
        mount_id = ctypes.c_uint64.from_buffer_copy(mount_info, 144).value
    except (AttributeError, OSError) as exc:
        raise RunnerError("live Codex kernel procfs attestation unavailable") from exc
    if not mask & 0x1000 or mount_id == 0:
        raise RunnerError("live Codex kernel procfs mount ID is unavailable")
    return mount_id


def _authenticated_procfs_evidence() -> tuple[bytes, bytes]:
    """Read status and mountinfo from FDs proven to be the same real procfs.

    A read-only bind over /proc or either virtual file must not supply
    security metadata from ordinary files or a different procfs mount object.
    """
    descriptors: list[int] = []

    def opened(path: str, flags: int, *, directory_fd: int | None = None) -> int:
        kwargs = {} if directory_fd is None else {"dir_fd": directory_fd}
        descriptor = os.open(path, flags, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def bounded_read(descriptor: int, maximum: int) -> bytes:
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if not result or len(result) > maximum:
            raise RunnerError("live Codex kernel procfs evidence size is unsafe")
        return bytes(result)

    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        proc = opened("/proc", directory_flags | os.O_NOFOLLOW)
        self_dir = opened("self", directory_flags, directory_fd=proc)
        status = opened("status", file_flags, directory_fd=self_dir)
        mounts = opened("mountinfo", file_flags, directory_fd=self_dir)
        mount_ids = {
            _kernel_procfs_mount_id(fd) for fd in (proc, self_dir, status, mounts)
        }
        if len(mount_ids) != 1:
            raise RunnerError("live Codex procfs mount identity is inconsistent")
        if not all(stat.S_ISREG(os.fstat(fd).st_mode) for fd in (status, mounts)):
            raise RunnerError("live Codex procfs sources are not regular files")
        return bounded_read(status, 128 * 1024), bounded_read(mounts, 4 * 1024 * 1024)
    except OSError as exc:
        raise RunnerError("live Codex kernel procfs evidence is unavailable") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _authenticated_procfs_cgroup(pid: int | None = None) -> bytes:
    """Read our or a kernel-authenticated peer's cgroup from genuine procfs FDs.

    Numeric PID lookups must never trust a mounted ordinary-file stand-in;
    every opened descriptor is checked against one genuine procfs mount ID.
    """
    if pid is not None and (type(pid) is not int or pid <= 0):
        raise RunnerError("live Codex device isolation procfs PID is invalid")
    descriptors: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        proc = os.open("/proc", directory_flags | os.O_NOFOLLOW)
        descriptors.append(proc)
        target = "self" if pid is None else str(pid)
        # proc/self is the trusted kernel-provided symlink; numeric peers
        # must be opened without following any further pathname links.
        target_flags = (
            directory_flags if pid is None else directory_flags | os.O_NOFOLLOW
        )
        target_dir = os.open(target, target_flags, dir_fd=proc)
        descriptors.append(target_dir)
        cgroup = os.open("cgroup", file_flags, dir_fd=target_dir)
        descriptors.append(cgroup)
        if len({_kernel_procfs_mount_id(fd) for fd in descriptors}) != 1:
            raise RunnerError("live Codex device isolation procfs identity differs")
        if not stat.S_ISREG(os.fstat(cgroup).st_mode):
            raise RunnerError("live Codex device isolation procfs cgroup is unsafe")
        data = os.read(cgroup, 8193)
        if not data or len(data) > 8192:
            raise RunnerError("live Codex device isolation cgroup evidence is unsafe")
        return data
    except OSError as exc:
        raise RunnerError(
            "live Codex device isolation cgroup evidence unavailable"
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _authenticated_live_broker_cgroup(
    peer_socket: socket.socket, peer_pid: int
) -> bytes:
    """Kernel-bind every D-Bus socket peer, including UID-0, to its cgroup.

    Linux SO_PEERPIDFD (77, from asm-generic/socket.h) yields the pidfd
    of the *connected socket peer*. os.pidfd_open(peer_pid) is insufficient:
    the numeric PID could already refer to another process. A readable
    pidfd means the original peer has exited. Reject that state both
    before and after opening /proc/<pid>/cgroup, while the socket remains
    open, rather than trusting a recycled PID or a stale mock service.
    """
    try:
        raw_pidfd = peer_socket.getsockopt(socket.SOL_SOCKET, 77, struct.calcsize("i"))
        (pidfd,) = struct.unpack("i", raw_pidfd)
    except (OSError, struct.error) as exc:
        raise RunnerError(
            "live Codex system manager channel peer pidfd unavailable"
        ) from exc
    if pidfd < 0:
        raise RunnerError("live Codex system manager channel peer pidfd invalid")
    try:
        with selectors.DefaultSelector() as monitor:
            monitor.register(pidfd, selectors.EVENT_READ)
            if monitor.select(timeout=0):
                raise RunnerError("live Codex system manager channel peer exited")
            peer_cgroup = _authenticated_procfs_cgroup(peer_pid)
            if monitor.select(timeout=0):
                raise RunnerError("live Codex system manager channel peer exited")
            return peer_cgroup
    except RunnerError:
        raise
    except (OSError, ValueError) as exc:
        raise RunnerError(
            "live Codex system manager channel peer pidfd unavailable"
        ) from exc
    finally:
        os.close(pidfd)


def _authenticated_pid1_mountinfo() -> bytes:
    """Read PID 1's host mount namespace directly from genuine kernel procfs."""
    descriptors: list[int] = []
    try:
        directories = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        files = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        proc = os.open("/proc", directories)
        descriptors.append(proc)
        pid1 = os.open("1", directories, dir_fd=proc)
        descriptors.append(pid1)
        mountinfo = os.open("mountinfo", files, dir_fd=pid1)
        descriptors.append(mountinfo)
        if len(
            {_kernel_procfs_mount_id(fd) for fd in descriptors}
        ) != 1 or not stat.S_ISREG(os.fstat(mountinfo).st_mode):
            raise RunnerError("live Codex PID 1 mountinfo is untrusted")
        chunks = bytearray()
        while len(chunks) <= 4 * 1024 * 1024:
            chunk = os.read(mountinfo, min(65536, 4 * 1024 * 1024 + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if not chunks or len(chunks) > 4 * 1024 * 1024:
            raise RunnerError("live Codex PID 1 mountinfo is unbounded")
        return bytes(chunks)
    except OSError as exc:
        raise RunnerError("live Codex PID 1 mountinfo unavailable") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _system_bus_mount_origins(
    mountinfo: bytes,
) -> list[tuple[bytes, bytes, bytes, bytes]]:
    """Derive backing filesystem and original path for every /run bus mount.

    Include *all* matching /run ancestor/bus mounts, including covered ones:
    an opaque later ancestor bind must never conceal a foreign socket source.
    The only relevant canonical bus path is ASCII without mountinfo escapes.
    """
    if not mountinfo or len(mountinfo) > 4 * 1024 * 1024:
        raise RunnerError("live Codex system bus mountinfo is unbounded")
    lines = mountinfo.splitlines()
    if len(lines) > 8192:
        raise RunnerError("live Codex system bus mountinfo is unbounded")
    channel = b"/run/dbus/system_bus_socket"
    allowed_points = {
        b"/run",
        b"/run/dbus",
        channel,
    }
    origins: list[tuple[bytes, bytes, bytes, bytes]] = []
    for line in lines:
        pre, separator, post = line.partition(b" - ")
        fields = pre.split()
        fs_fields = post.split()
        if not separator or len(fields) < 6 or len(fs_fields) < 3:
            raise RunnerError("live Codex system bus mountinfo is malformed")
        point = fields[4]
        if point not in allowed_points:
            continue
        device, root, filesystem = fields[2], fields[3], fs_fields[0]
        suffix = channel[len(point) :]
        if (
            not re.fullmatch(rb"[0-9]+:[0-9]+", device)
            or not root.startswith(b"/")
            or b"\\" in root
            or b"\0" in root
            or b"/../" in root
            or b"/./" in root
            or filesystem not in {b"tmpfs", b"ramfs"}
        ):
            raise RunnerError("live Codex system bus mount origin is unsafe")
        origin = posixpath.normpath(root.rstrip(b"/") + suffix)
        origins.append((point, device, origin, filesystem))
    if not origins:
        raise RunnerError("live Codex system bus mount origin is missing")
    return origins


def _attest_pid1_system_bus_origin(socket_stat: os.stat_result) -> None:
    """Prove a PID-1-created listener has the host system-bus inode backing.

    The peer's sun_path text is not sufficient: the same pathname can name a
    different filesystem socket in another mount namespace. Compare the
    immutable kernel-reported mount source to the *real PID 1 namespace*.
    Never consume systemctl policy from a substituted activated listener.
    """
    _, local_mounts = _authenticated_procfs_evidence()
    host_origins = _system_bus_mount_origins(_authenticated_pid1_mountinfo())
    local_origins = _system_bus_mount_origins(local_mounts)
    host = max(host_origins, key=lambda item: len(item[0]))
    if (
        host[0] != b"/run"
        or host[2] != b"/dbus/system_bus_socket"
        or any(origin[0] == host[0] and origin != host for origin in host_origins)
    ):
        # This safety policy deliberately supports only the normal root-owned
        # systemd /run socket layout; unfamiliar host layouts fail closed.
        raise RunnerError("live Codex host system bus socket origin is untrusted")
    expected = (host[1], host[2], host[3])
    if (
        f"{os.major(socket_stat.st_dev)}:{os.minor(socket_stat.st_dev)}".encode()
        != host[1]
        or any(
            (device, origin, filesystem) != expected
            for _, device, origin, filesystem in local_origins
        )
    ):
        raise RunnerError("live Codex system bus socket bind origin is untrusted")


def _assert_initial_kernel_namespaces() -> None:
    """Reject synthetic root-systemd evidence from unprivileged namespaces.

    Genuine procfs alone does not imply the host's initial user, PID or cgroup
    namespaces. Read each kernel namespace symlink through an O_PATH FD bound
    to the exact authenticated procfs mount, preventing mount aliases and
    readlink path replacement. Linux initial namespace inodes are fixed.
    /proc/1/ns may be inaccessible under ptrace/hidepid; it is not required.
    """
    expected = {
        "user": "user:[4026531837]",
        "pid": "pid:[4026531836]",
        "cgroup": "cgroup:[4026531835]",
    }
    if not hasattr(os, "O_PATH"):
        raise RunnerError("live Codex initial namespaces cannot be authenticated")
    descriptors: list[int] = []
    try:
        directories = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        files = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        proc = os.open("/proc", directories)
        descriptors.append(proc)
        own_process = os.open(
            "self", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=proc
        )
        descriptors.append(own_process)
        namespace_directory = os.open("ns", directories, dir_fd=own_process)
        descriptors.append(namespace_directory)
        mount_identity = _kernel_procfs_mount_id(proc)
        for descriptor in (own_process, namespace_directory):
            if _kernel_procfs_mount_id(descriptor) != mount_identity:
                raise RunnerError("live Codex initial namespace procfs is untrusted")
        for namespace, required_link in expected.items():
            link_fd = os.open(
                namespace,
                os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=namespace_directory,
            )
            descriptors.append(link_fd)
            if (
                _kernel_procfs_mount_id(link_fd) != mount_identity
                or not stat.S_ISLNK(os.fstat(link_fd).st_mode)
                or os.readlink("", dir_fd=link_fd) != required_link
            ):
                raise RunnerError("live Codex initial namespace identity is untrusted")
        for filename in ("uid_map", "gid_map"):
            map_fd = os.open(filename, files, dir_fd=own_process)
            descriptors.append(map_fd)
            if _kernel_procfs_mount_id(map_fd) != mount_identity or not stat.S_ISREG(
                os.fstat(map_fd).st_mode
            ):
                raise RunnerError("live Codex initial user namespace map is untrusted")
            value = os.read(map_fd, 128)
            if (
                value.split() != [b"0", b"0", b"4294967295"]
                or not value.endswith(b"\n")
                or os.read(map_fd, 1)
            ):
                raise RunnerError("live Codex initial user namespace map is untrusted")
    except RunnerError:
        raise
    except (OSError, AttributeError, ValueError) as exc:
        raise RunnerError("live Codex initial namespace evidence unavailable") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _attest_root_system_manager_channels() -> None:
    """Authenticate the accessible root-owned system bus before systemctl.

    The root systemd private socket is often mode 0700 and unavailable to
    DynamicUser. We must never connect to it from this unprivileged runner.
    Authenticate the accessible root-owned system-bus inode and its
    SO_PEERCRED peer. Every peer, including UID-0, requires genuine procfs
    and an SO_PEERPIDFD-backed live process. Root PID 1 must belong to
    /init.scope; any other peer must belong to an exact system D-Bus unit.
    Arbitrary root or nonroot broker impostors fail before systemctl is called.
    """
    _assert_initial_kernel_namespaces()
    channel = "/run/dbus/system_bus_socket"
    try:
        before = os.lstat(channel)
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid != 0:
            raise RunnerError("live Codex system manager channel is untrusted")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer_socket:
            peer_socket.settimeout(2)
            peer_socket.connect(channel)
            credentials = peer_socket.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
            after = os.lstat(channel)
            if (
                peer_pid <= 0
                or peer_uid < 0
                or peer_gid < 0
                or (peer_uid == 0) != (peer_gid == 0)
                or (
                    peer_uid != 0
                    and (peer_uid == os.geteuid() or peer_gid == os.getegid())
                )
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_uid,
                )
                != (after.st_dev, after.st_ino, after.st_mode, after.st_uid)
            ):
                raise RunnerError("live Codex system manager channel is untrusted")
            if peer_uid == 0 and peer_pid == 1:
                # SO_PEERCRED and SO_PEERPIDFD identify socket-activating
                # systemd, not necessarily the eventual service.  A foreign
                # activated socket bind-mounted onto the bus path retains its
                # original kernel sun_path, so reject the alias here.
                try:
                    listener_name = peer_socket.getpeername()
                except OSError as exc:
                    raise RunnerError(
                        "live Codex system manager channel listener unavailable"
                    ) from exc
                if type(listener_name) is not str or listener_name != channel:
                    raise RunnerError(
                        "live Codex system manager channel listener is untrusted"
                    )
            # A root-owned socket can still be served by an arbitrary UID-0
            # process. Bind *every* peer to its live pidfd and kernel cgroup,
            # including root peers, before trusting any systemd property.
            try:
                peer_cgroup = _authenticated_live_broker_cgroup(peer_socket, peer_pid)
            except RunnerError as exc:
                raise RunnerError(
                    "live Codex system manager channel is untrusted"
                ) from exc
            if peer_uid == 0 and peer_pid == 1:
                # On the target host the genuine root system manager is PID 1
                # under init.scope. An unrelated root process cannot qualify.
                trusted_cgroups = {b"0::/init.scope\n"}
            else:
                trusted_cgroups = {
                    b"0::/system.slice/dbus.service\n",
                    b"0::/system.slice/dbus-broker.service\n",
                    b"0::/system.slice/dbus-daemon.service\n",
                }
            if peer_cgroup not in trusted_cgroups:
                raise RunnerError("live Codex system manager channel is untrusted")
            if peer_uid == 0 and peer_pid == 1:
                _attest_pid1_system_bus_origin(before)
    except (OSError, struct.error) as exc:
        raise RunnerError("live Codex system manager channel unavailable") from exc


def _assert_root_owned_device_policy() -> None:
    """Bind raw-device denial to the kernel process cgroup and root systemd.

    Read-only mounts and a clean /dev pathname alone do not deny opening a
    raw block device via an unrelated mount.  Require a root-system-manager
    unit whose kernel-bound cgroup is active, whose /dev is private, and whose
    device cgroup has no extra DeviceAllow entries.  Missing/inconsistent
    policy is a dispatch denial, never a soft warning.
    """
    try:
        cgroup_data = _authenticated_procfs_cgroup().decode("ascii")
    except (UnicodeError, OSError) as exc:
        raise RunnerError("live Codex device isolation cgroup unavailable") from exc
    match = re.fullmatch(
        r"0::(/system\.slice/(grabowski-rab-[A-Za-z0-9_.@-]{1,100}\.service))\n?",
        cgroup_data,
    )
    if match is None:
        raise RunnerError("live Codex device isolation lacks root-owned system unit")
    cgroup, unit = match.groups()
    # The root-manager-owned dynamic user separates this service from the
    # invoking user's same-UID desktop, container and user-systemd sockets.
    # The unique system unit name must equal its own dynamic user and group.
    sandbox_identity = unit.removesuffix(".service")
    required = {
        "User": sandbox_identity,
        "Group": sandbox_identity,
        "DynamicUser": "yes",
        "PrivateTmp": "yes",
        "PrivateIPC": "yes",
        # PrivateDevices alone bind-mounts host /dev/shm into the new /dev.
        # Require an independently mounted tmpfs with private 1777 mode, as
        # verified in real root-systemd249 DynamicUser micro-units.
        "TemporaryFileSystem": "/dev/shm:rw,nosuid,nodev,noexec,mode=1777",
        # Numeric UID/GID must also match the real process, not only the
        # unit's declared user/group strings. Prevent credential drift or
        # a separate same-UID worker masquerading as the dynamic service.
        "UID": str(os.geteuid()),
        "GID": str(os.getegid()),
        "ActiveState": "active",
        "LoadState": "loaded",
        "ControlGroup": cgroup,
        "PrivateDevices": "yes",
        "DevicePolicy": "closed",
        "DeviceAllow": "",
        "Delegate": "no",
    }
    argv = [
        "/usr/bin/systemctl",
        "--system",
        "show",
        unit,
        "--no-pager",
        *(f"--property={name}" for name in sorted(required)),
    ]
    _attest_root_system_manager_channels()
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError(
            "live Codex device isolation system manager unavailable"
        ) from exc
    if (
        completed.returncode != 0
        or not isinstance(completed.stdout, str)
        or len(completed.stdout) > 16384
    ):
        raise RunnerError("live Codex device isolation system manager readback failed")
    actual: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in required or key in actual:
            raise RunnerError(
                "live Codex device isolation system manager evidence invalid"
            )
        actual[key] = value
    # Empty multi-valued DeviceAllow is omitted by systemctl show, whereas
    # additional permission lines (including duplicates) remain disallowed.
    actual.setdefault("DeviceAllow", "")
    if actual != required:
        raise RunnerError("live Codex device isolation system device policy unsafe")


def _assert_private_output_tree_scan(
    roots: Sequence[Path], *, reserved_entries: int = 0
) -> int:
    """Bound the real output tree and any deterministic pre-intent additions.

    The staged clone and generated .git are scanned before one-use identity
    allocation; reserved_entries accounts for future schema and runtime
    artifacts that are written before the provider intent can be persisted.
    """
    if type(reserved_entries) is not int or not 0 <= reserved_entries <= 65536:
        raise RunnerError("live Codex reserved output entries are invalid")
    entries_seen = 0
    pending = [(path, 0) for path in roots]
    while pending:
        directory, depth = pending.pop()
        if depth > 32:
            raise RunnerError("live Codex private output scan depth exceeded")
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    entries_seen += 1
                    if entries_seen + reserved_entries > 65536:
                        raise RunnerError(
                            "live Codex private output scan entry budget exceeded"
                        )
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(metadata.st_mode):
                        if metadata.st_nlink != 1:
                            raise RunnerError(
                                "live Codex private output contains hardlinked regular file"
                            )
                    elif stat.S_ISDIR(metadata.st_mode):
                        pending.append((Path(entry.path), depth + 1))
                    else:
                        raise RunnerError(
                            "live Codex private output contains special file"
                        )
        except OSError as exc:
            raise RunnerError("live Codex private output scan unavailable") from exc
    return entries_seen


def _assert_empty_mcp_stage_parent(state_root: Path) -> None:
    """Reject leftover stages before baseline can spend pair one-shot."""
    parent = state_root / "repoground-mcp-upstream-runtime"
    try:
        entry = parent.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RunnerError("pre-intent MCP stage parent is unavailable") from exc
    if not stat.S_ISDIR(entry.st_mode):
        raise RunnerError("pre-intent MCP stage parent is not a real directory")
    verified, fd = _open_private_directory(parent, create_final=False)
    try:
        _directory_fd_matches(verified, fd)
        if os.listdir(fd):
            raise RunnerError(
                "pre-intent MCP stage parent already contains a sibling stage"
            )
        _directory_fd_matches(verified, fd)
    finally:
        os.close(fd)


def _preintent_output_entry_reservation(
    condition: str,
    expected_manifest: Mapping[str, Any] | None,
    *,
    mcp_script: Path | None = None,
    legacy_g1: bool = False,
    state_root: Path | None = None,
) -> int:
    """Reserve both MCP stages and their exact source/manifest parent directories.

    All checks run before workspace allocation and the first paired provider
    intent, including baseline's future treatment. A later successful
    postflight scan cannot refund an already-spent one-shot authorization.
    """
    reservation = 4  # answer-schema.json + codex-runtime/session/auth.json
    if condition == "baseline":
        return reservation
    if condition != "treatment" or not isinstance(expected_manifest, Mapping):
        raise RunnerError("pre-intent manifest binding is missing")
    if not isinstance(mcp_script, Path) or not mcp_script.is_absolute():
        raise RunnerError("pre-intent MCP script binding is missing")
    if type(legacy_g1) is not bool:
        raise RunnerError("pre-intent MCP profile is invalid")
    if state_root is not None:
        _assert_empty_mcp_stage_parent(state_root)
    manifest = Path(str(expected_manifest.get("path"))).expanduser()
    current, raw = _runtime_file_snapshot(
        manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if canonical(current) != canonical(dict(expected_manifest)):
        raise RunnerError("pre-intent manifest binding changed")
    artifacts = _manifest_artifact_paths(manifest, raw)

    # First stage: repoground-manifest-runtime/bundle-*/<artifact>.
    manifest_directories: set[tuple[str, ...]] = set()
    for relative, _candidate, _size, _sha256 in artifacts:
        if len(relative.parts) > 31:
            raise RunnerError(
                "pre-intent manifest artifact tree depth exceeds scan limit"
            )
        for depth in range(1, len(relative.parts)):
            manifest_directories.add(relative.parts[:depth])

    # The trusted parent makes an additional, independent upstream snapshot:
    # executable/script, manifest/artifacts, entire RepoGround Python source,
    # and, only for frozen G1, pinned vendor modules. Verify those bytes and
    # parent paths now, not after the baseline provider has already spent.
    script_name = "repobrief-mcp-stdio.py" if legacy_g1 else "repoground-mcp-stdio.py"
    if mcp_script.name != script_name:
        raise RunnerError("pre-intent MCP script does not match the bound profile")
    source_tree = _repoground_source_tree_snapshot(mcp_script, raw, legacy_g1=legacy_g1)
    if not isinstance(source_tree, Mapping) or not isinstance(
        source_tree.get("entries"), list
    ):
        raise RunnerError("pre-intent RepoGround MCP source closure is unavailable")
    vendor_entries = _frozen_g1_vendor_snapshot() if legacy_g1 else []
    upstream_files = [
        Path(MCP_STAGE_METADATA_NAME),
        Path("executable") / "mcp-python",
        Path("script") / script_name,
        Path("manifest") / manifest.name,
        *(Path("manifest") / relative for relative, *_rest in artifacts),
    ]
    for entry in source_tree["entries"]:
        if not isinstance(entry, Mapping) or not isinstance(
            entry.get("relative"), Path
        ):
            raise RunnerError("pre-intent RepoGround MCP source path invalid")
        upstream_files.append(entry["relative"])
    for entry in vendor_entries:
        if not isinstance(entry, Mapping) or not isinstance(
            entry.get("relative"), Path
        ):
            raise RunnerError("pre-intent historical G1 dependency path invalid")
        upstream_files.append(Path("vendor") / entry["relative"])

    upstream_directories: set[tuple[str, ...]] = set()
    for relative in upstream_files:
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
            or len(relative.parts) > 31
        ):
            raise RunnerError(
                "pre-intent upstream MCP stage tree depth or path invalid"
            )
        for depth in range(1, len(relative.parts)):
            upstream_directories.add(relative.parts[:depth])
    if len(upstream_files) != len(set(upstream_files)):
        raise RunnerError("pre-intent upstream MCP stage has duplicate file paths")
    # Pessimistic envelope for UTF-8/JSON-escaped absolute stage paths and
    # worst-case inode/size/mode fields. Baseline checks the future Treatment
    # before its first one-shot intent, not merely before Treatment intent.
    prospective_root = (
        (state_root if state_root is not None else Path("/tmp/repobrief-test-state"))
        / "repoground-mcp-upstream-runtime"
        / ("upstream-" + "0" * 24)
    )
    # Stage serialization uses ensure_ascii=False and UTF-8. Linux paths can
    # contain surrogateescaped bytes; an ASCII-escaped size estimate alone
    # would admit them before Baseline but fail Treatment after one-shot intent.
    try:
        path_max = os.pathconf("/", "PC_PATH_MAX")
    except (OSError, ValueError) as exc:
        raise RunnerError("pre-intent Linux path limit unavailable") from exc
    if type(path_max) is not int or path_max <= 0:
        raise RunnerError("pre-intent Linux path limit is invalid")
    try:
        for field in (manifest, mcp_script, prospective_root, source_tree.get("root")):
            if field is not None:
                str(field).encode("utf-8")
        for relative in upstream_files:
            candidate = str(prospective_root / relative).encode("utf-8")
            if len(candidate) >= path_max:
                raise RunnerError("pre-intent MCP staged path exceeds Linux PATH_MAX")
    except UnicodeEncodeError as exc:
        raise RunnerError("pre-intent MCP stage metadata path is not UTF-8") from exc
    metadata_upper_bound = 1024 * 1024 + sum(
        512 + len(json.dumps(str(prospective_root / relative), ensure_ascii=True))
        for relative in upstream_files
    )
    if metadata_upper_bound > MAX_MCP_STAGE_METADATA_BYTES:
        raise RunnerError("pre-intent MCP stage metadata exceeds its byte budget")

    # Four proxy-stage entries, three initial manifest-stage entries,
    # then the second upstream stage's two private parent directories,
    # executable/script/manifest/artifact/source/vendor files and directories.
    return (
        reservation
        + 4
        + 3
        + len(artifacts)
        + len(manifest_directories)
        + 2
        + len(upstream_files)
        + len(upstream_directories)
        + 2  # temporary MCP FIFOs in parent-owned read-only codex-runtime
    )


def validate_live_immutable_mounts(
    *,
    source: Path,
    codex: Path,
    request_root: Path,
    repository_map: Path,
    manifest: Path | None,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
    report_root: Path | None = None,
    runtime_binding: Mapping[str, Any] | None = None,
    pending_output_entries: int = 0,
) -> None:
    """Fail closed on writable input or nested mount, without provider/ledger effects."""
    if sys.platform != "linux" or not hasattr(os, "ST_RDONLY"):
        raise RunnerError("live Codex mount isolation requires Linux")
    _assert_initial_kernel_namespaces()
    if os.getuid() != os.geteuid() or os.geteuid() == 0:
        raise RunnerError("live Codex must have an unprivileged unchanged UID")
    # A saved root UID/GID can be restored by an unprivileged process even with
    # NoNewPrivs=1 and no capabilities; check every kernel credential slot.
    try:
        user_ids = os.getresuid()
        group_ids = os.getresgid()
        supplementary_groups = os.getgroups()
    except (AttributeError, OSError) as exc:
        raise RunnerError("live Codex kernel execution identity unavailable") from exc
    if (
        user_ids != (os.geteuid(),) * 3
        or group_ids != (os.getegid(),) * 3
        or os.getegid() == 0
        or os.getegid() != os.geteuid()
    ):
        # Primary docker/libvirt GIDs are privileged even if supplementary
        # group membership is empty. The root-owned DynamicUser unit below
        # must also attest this private non-root UID/GID.
        raise RunnerError("live Codex execution identity is unsafe")
    # NoNewPrivs and dropping effective capabilities do not revoke group access
    # to privileged Unix sockets such as Docker's. An inherited supplementary
    # group may therefore delegate raw mount or filesystem writes to a daemon.
    if any(gid != os.getegid() for gid in supplementary_groups):
        raise RunnerError("live Codex supplementary groups are unsafe")
    try:
        status_bytes, mount_info = _authenticated_procfs_evidence()
        status = status_bytes.decode("ascii")
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        no_new_privs = fields.get("NoNewPrivs", "").strip()
        capabilities = (
            fields.get(name, "").strip() for name in ("CapEff", "CapPrm", "CapAmb")
        )
        no_caps = all(value != "" and int(value, 16) == 0 for value in capabilities)
    except (OSError, ValueError) as exc:
        raise RunnerError("live Codex kernel privilege state unavailable") from exc
    if no_new_privs != "1" or not no_caps:
        raise RunnerError("live Codex execution privileges are unsafe")
    if runtime_binding is not None:
        if not isinstance(runtime_binding, Mapping):
            raise RunnerError("live Codex runtime mount binding is invalid")
        if manifest is None:
            recorded = runtime_binding.get("manifest")
            if not isinstance(recorded, Mapping) or not isinstance(
                recorded.get("path"), str
            ):
                raise RunnerError("live Codex authorized manifest path is missing")
            manifest = Path(recorded["path"])
        if report_root is None:
            report_out = runtime_binding.get("report_out")
            if not isinstance(report_out, str) or not report_out:
                raise RunnerError("live Codex authorized report path is missing")
            report_root = Path(report_out).parent
    if manifest is None or report_root is None:
        raise RunnerError("live Codex immutable input binding is incomplete")

    def resolved(path: Path, label: str) -> Path:
        try:
            return path.expanduser().resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RunnerError(f"live Codex {label} path is unavailable") from exc

    home = resolved(Path.home(), "home")
    outputs = {
        "state": resolved(state_root, "state"),
        "transcripts": resolved(transcript_root, "transcripts"),
        "evidence": resolved(evidence_root, "evidence"),
        "reports": resolved(report_root, "reports"),
    }
    epoch = outputs["state"].parent
    if (
        epoch == home
        or home not in epoch.parents
        or any(
            path.name != name or path.parent != epoch for name, path in outputs.items()
        )
    ):
        raise RunnerError(
            "live Codex output scope is not exactly four private epoch leaves"
        )
    for name, path in outputs.items():
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RunnerError(f"live Codex {name} output ownership is unsafe")
        try:
            writable = not bool(os.statvfs(path).f_flag & os.ST_RDONLY)
        except OSError as exc:
            raise RunnerError(f"live Codex {name} output mount unavailable") from exc
        if not writable:
            raise RunnerError(f"live Codex {name} output is read-only")

    _assert_private_output_tree_scan(
        tuple(outputs.values()), reserved_entries=pending_output_entries
    )

    source_path = resolved(source, "source")
    git_marker = source_path / ".git"
    if git_marker.is_symlink():
        raise RunnerError("live Codex Git metadata symlink is unsafe")
    if git_marker.is_file():
        pointer = git_marker.read_bytes()
        if not pointer.startswith(b"gitdir: ") or len(pointer) > 4096:
            raise RunnerError("live Codex Git metadata pointer is invalid")
        try:
            git_dir = resolved(
                source_path / pointer[8:].strip().decode("utf-8"), "Git metadata"
            )
        except UnicodeError as exc:
            raise RunnerError("live Codex Git metadata pointer is invalid") from exc
    elif git_marker.is_dir():
        git_dir = resolved(git_marker, "Git metadata")
    else:
        raise RunnerError("live Codex Git metadata is absent")
    common_marker = git_dir / "commondir"
    if common_marker.is_file():
        pointer = common_marker.read_bytes()
        if not pointer or len(pointer) > 4096:
            raise RunnerError("live Codex Git common-dir pointer is invalid")
        try:
            common_dir = resolved(
                git_dir / pointer.strip().decode("utf-8"), "Git common directory"
            )
        except UnicodeError as exc:
            raise RunnerError("live Codex Git common-dir pointer is invalid") from exc
    else:
        common_dir = git_dir

    immutable_paths = {
        "filesystem root": Path("/"),
        "system tools": Path("/usr"),
        "system loader configuration": Path("/etc"),
        # The provider binary and its bundled rg may be RO-bind-mounted from
        # another filesystem: another RW alias to either device is unsafe.
        "Codex executable": codex,
        "Codex bundled rg": codex.parent.parent / "codex-path" / "rg",
        "home": home,
        "repository parent": home / "repos",
        "epoch parent": epoch,
        "source parent": source_path.parent,
        "source": source_path,
        "Git metadata parent": git_dir.parent,
        "Git metadata": git_dir,
        "Git common parent": common_dir.parent,
        "Git common directory": common_dir,
        "request parent": request_root.parent,
        "request root": request_root,
        "repository map parent": repository_map.parent,
        "repository map": repository_map,
        "manifest": manifest,
        "manifest parent": manifest.parent,
        "runner parent": Path(__file__).parent,
        "runner source": Path(__file__),
    }
    # On non-usr-merged hosts, /bin and the shared loader trees may have
    # distinct RO bind mounts backed by writable private tmpfs. Protect each
    # actual filesystem backing, not only the common /usr path spelling.
    # Absent optional multiarch directories are harmless; an inaccessible or
    # dangling existing runtime path must instead fail closed.
    for runtime_path in (
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/lib32"),
        Path("/libx32"),
    ):
        try:
            runtime_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RunnerError(
                "live Codex runtime loader/tool path is unavailable"
            ) from exc
        immutable_paths[f"runtime {runtime_path}"] = runtime_path

    protected_targets = {}
    for label, path in immutable_paths.items():
        target = resolved(Path(path), label)
        protected_targets[label] = target
        try:
            read_only = bool(os.statvfs(target).f_flag & os.ST_RDONLY)
        except OSError as exc:
            raise RunnerError(f"live Codex {label} mount check failed") from exc
        if not read_only:
            raise RunnerError(f"live Codex protected input mount writable: {label}")

    # A writable epoch must be disjoint from historical inputs even before
    # looking at mount roots: an output path resolving inside a source checkout
    # could be given an exact RW leaf remount and evade samefile checks.
    immutable_epoch_roots = {
        target
        for label, target in protected_targets.items()
        if label
        in {
            "repository parent",
            "source parent",
            "source",
            "Git metadata parent",
            "Git metadata",
            "Git common parent",
            "Git common directory",
            "request parent",
            "request root",
            "manifest parent",
            "manifest",
            "runner parent",
            "runner source",
        }
    }
    if any(epoch == root or root in epoch.parents for root in immutable_epoch_roots):
        raise RunnerError("live Codex output epoch overlaps protected input subtree")

    # An RO directory can still hide an RW bind below it. Include protected
    # source and metadata directories even when they live outside HOME.
    protected_directories = {
        target
        for label, target in protected_targets.items()
        if label not in {"filesystem root", "system tools", "home"} and target.is_dir()
    }

    # A writable bind of a protected directory onto an output leaf is unsafe
    # even when the original path remains read-only in this namespace.
    for output in outputs.values():
        for protected in protected_targets.values():
            try:
                aliases = os.path.samefile(output, protected)
            except OSError as exc:
                raise RunnerError(
                    "live Codex output alias identity unavailable"
                ) from exc
            if aliases:
                raise RunnerError("live Codex writable output aliases protected source")

    if not mount_info or len(mount_info) > 4 * 1024 * 1024:
        raise RunnerError("live Codex mountinfo size is unsafe")
    mount_lines = mount_info.splitlines()
    if len(mount_lines) > 8192:
        raise RunnerError("live Codex mount listing is unbounded")

    # Keep the mount root as well as the mountpoint: statvfs cannot detect
    # a writable output leaf whose bind source is a protected subdirectory.
    def decode_mountinfo_field(raw: bytes) -> Path:
        decoded = re.sub(
            rb"\\([0-7]{3})", lambda match: bytes([int(match.group(1), 8)]), raw
        )
        result = Path(os.fsdecode(decoded))
        if not result.is_absolute():
            raise RunnerError("live Codex mountinfo path is invalid")
        return result

    # Mountpoint text alone is not a visible mount identity. Linux can stack
    # multiple mounts at one path, with each new mount naming the covered
    # mount as parent. Select the unique top of that chain, independent of
    # mountinfo line order. Descendants of a covered mount are inaccessible.
    records: dict[int, tuple[int, Path, Path, bytes, bool, bytes]] = {}
    at_point: dict[Path, list[int]] = {}
    for line in mount_lines:
        sections = line.split(b" - ", 1)
        fields = sections[0].split()
        filesystem_fields = sections[1].split() if len(sections) == 2 else []
        if (
            len(fields) < 6
            or len(fields[0]) > 20
            or len(fields[1]) > 20
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or len(filesystem_fields) < 3
            or len(filesystem_fields[0]) > 128
        ):
            raise RunnerError("live Codex mountinfo is malformed")
        mount_id, parent_id = int(fields[0]), int(fields[1])
        point = decode_mountinfo_field(fields[4])
        if mount_id == 0 or mount_id in records:
            raise RunnerError("live Codex mountinfo mount IDs are invalid")
        if mount_id == parent_id:
            if point != Path("/"):
                raise RunnerError("live Codex mountinfo mount parent is invalid")
            parent_id = 0  # The namespace root may name itself as parent.
        records[mount_id] = (
            parent_id,
            point,
            decode_mountinfo_field(fields[3]),
            fields[2],
            b"rw" in fields[5].split(b","),
            filesystem_fields[0],
        )
        at_point.setdefault(point, []).append(mount_id)
    if Path("/") not in at_point:
        raise RunnerError("live Codex mountinfo namespace root is missing")

    top_at_point: dict[Path, int] = {}
    for point, ids in at_point.items():
        group = set(ids)
        covered = {records[mount_id][0] for mount_id in ids} & group
        possible_top = group - covered
        if len(possible_top) != 1:
            raise RunnerError("live Codex mountinfo mount stack is ambiguous")
        top = next(iter(possible_top))
        chain: set[int] = set()
        current = top
        while current in group:
            if current in chain:
                raise RunnerError("live Codex mountinfo mount stack is cyclic")
            chain.add(current)
            current = records[current][0]
        if chain != group:
            raise RunnerError("live Codex mountinfo mount stack is disconnected")
        top_at_point[point] = top

    # A mount can also be covered by a *later ancestor mount*, not only
    # another mount at the same point. Work out visible parent prefixes from
    # the namespace root downwards. A hidden child never supplies a backing
    # identity or a writable alias, and cannot hide the actually visible one.
    visible_at_point: dict[Path, int] = {}
    for point in sorted(top_at_point, key=lambda path: (len(path.parts), str(path))):
        mount_id = top_at_point[point]
        parent_id = records[mount_id][0]
        while parent_id in records and records[parent_id][1] == point:
            parent_id = records[parent_id][0]  # Skip covered same-path stack.
        if point == Path("/"):
            if parent_id in records:
                raise RunnerError(
                    "live Codex mountinfo namespace root parent is invalid"
                )
            visible_at_point[point] = mount_id
            continue
        if parent_id not in records or records[parent_id][1] not in point.parents:
            raise RunnerError("live Codex mountinfo parent topology is invalid")
        nearest_visible_parent = next(
            (parent for parent in point.parents if parent in visible_at_point),
            None,
        )
        if nearest_visible_parent is None:
            raise RunnerError("live Codex mountinfo visible parent is missing")
        if parent_id == visible_at_point[nearest_visible_parent]:
            visible_at_point[point] = mount_id

    # A synthetic device/root does not describe union lower/upper directories,
    # FUSE userspace backings or remotely mutable/clustered filesystems.  Even a
    # read-only local mount cannot make those underlying bytes immutable.
    # Allow only known local inode or kernel-virtual filesystem types; any new
    # or opaque filesystem must be explicitly security-reviewed before use.
    # Covered mounts are excluded because only visible mounts grant access.
    transparent_filesystems = frozenset(
        {
            b"ext2",
            b"ext3",
            b"ext4",
            b"xfs",
            b"btrfs",
            b"f2fs",
            b"zfs",
            b"vfat",
            b"exfat",
            b"squashfs",
            b"erofs",
            b"iso9660",
            b"tmpfs",
            b"ramfs",
            b"devtmpfs",
            b"devpts",
            b"proc",
            b"sysfs",
            b"cgroup2",
            b"nsfs",
            b"bpf",
            b"fusectl",
            b"efivarfs",
            b"securityfs",
            b"pstore",
            b"debugfs",
            b"tracefs",
            b"configfs",
            b"hugetlbfs",
            b"mqueue",
            b"binfmt_misc",
        }
    )
    for visible_mount_id in visible_at_point.values():
        if records[visible_mount_id][5] not in transparent_filesystems:
            raise RunnerError(
                "live Codex mount filesystem backing cannot be authenticated"
            )

    mounts: list[tuple[Path, Path, bytes, bool]] = [
        (
            records[mount_id][1],
            records[mount_id][2],
            records[mount_id][3],
            records[mount_id][4],
        )
        for mount_id in visible_at_point.values()
    ]

    # The allowed writable leaves cannot be trusted if a read-only bind
    # underneath HOME first redirects their epoch parent onto source data.
    # Check every intermediate mount's underlying root against its closest
    # ancestor, not merely each writable leaf against that (possibly aliased)
    # intermediate mount.
    for mount, mount_root, device, _writable in mounts:
        if mount == home or home not in mount.parents:
            continue
        if mount != epoch and mount not in epoch.parents:
            continue
        ancestors = [
            (parent, parent_root, parent_device)
            for parent, parent_root, parent_device, _rw in mounts
            if parent in mount.parents
        ]
        if not ancestors:
            raise RunnerError("live Codex epoch parent mount has no safe ancestor")
        parent, parent_root, parent_device = max(
            ancestors, key=lambda item: len(item[0].parts)
        )
        if device != parent_device or mount_root != parent_root / mount.relative_to(
            parent
        ):
            raise RunnerError(
                "live Codex epoch parent mount has unexpected backing root"
            )

    # The mountpoint alone is not a source identity: a writable bind at
    # /tmp/alias could expose immutable source inodes even while their original
    # pathname remains read-only. Compare device + filesystem-relative mount
    # roots for every protected input. Keep the filesystem-wide root backing
    # separately: legitimate output leaves may share its device, whereas an
    # additional writable mount exposing that device must never be accepted.
    def backing_identity(target: Path) -> tuple[bytes, Path]:
        ancestors = [
            (mount, mount_root, device)
            for mount, mount_root, device, _rw in mounts
            if mount == target or mount in target.parents
        ]
        if not ancestors:
            raise RunnerError("live Codex protected input mount backing is unavailable")
        mount, mount_root, device = max(ancestors, key=lambda x: len(x[0].parts))
        return device, mount_root / target.relative_to(mount)

    filesystem_root_device, filesystem_root_backing = backing_identity(
        protected_targets["filesystem root"]
    )
    protected_backings = {
        label: backing_identity(target)
        for label, target in protected_targets.items()
        if label != "filesystem root"
    }

    allowed_outputs = set(outputs.values())
    # All visible read-only mounts inside immutable paths have their own backing.
    nested_ro_roots = protected_directories | {home, protected_targets["system tools"]}
    for point, backing, device, writable in mounts:
        if writable or any(
            point == output or output in point.parents for output in allowed_outputs
        ):
            continue
        if any(root == point or root in point.parents for root in nested_ro_roots):
            label = f"nested protected mount {point}"
            protected_targets[label] = point
            protected_backings[label] = (device, backing)
    observed_writable_outputs: set[Path] = set()
    for mount, mount_root, device, writable in mounts:
        if not writable:
            continue
        if mount == Path("/"):
            raise RunnerError("live Codex filesystem root mount writable")
        if any(
            mount == root or root in mount.parents
            for root in (
                Path("/usr"),
                Path("/bin"),
                Path("/sbin"),
                Path("/lib"),
                Path("/lib64"),
            )
        ):
            raise RunnerError(
                "live Codex has an unexpected writable system tool bind mount"
            )
        if mount in allowed_outputs:
            # A legitimate systemd ReadWritePaths remount retains the same
            # underlying filesystem subtree as the protected parent. A bind
            # from a different root, including source/src, is not an output.
            parents = [
                (parent, parent_root)
                for parent, parent_root, parent_device, _rw in mounts
                if parent_device == device and parent in mount.parents
            ]
            if not parents:
                raise RunnerError("live Codex output mount has no safe parent")
            parent, parent_root = max(parents, key=lambda entry: len(entry[0].parts))
            expected_root = parent_root / mount.relative_to(parent)
            if mount_root != expected_root:
                raise RunnerError(
                    "live Codex output mount root does not match writable target"
                )
            # The output's ordinary home/epoch ancestry is harmless, but a
            # protected RO bind sourced from inside this RW leaf is not:
            # the original protected files would still be writable here.
            # Only equality or protected descendants of this output root
            # are forbidden; an ancestor such as HOME is not an alias leak.
            if any(
                device == protected_device
                and (
                    protected_root == mount_root or mount_root in protected_root.parents
                )
                for protected_device, protected_root in protected_backings.values()
            ):
                raise RunnerError(
                    "live Codex writable output contains protected mount backing"
                )
            # Only logical HOME/epoch parents may back writable output
            # descendants. This also covers the repository-map parent when
            # it is exactly the legitimate read-only epoch directory.
            # All other protected physical roots must remain disjoint.
            if any(
                protected_targets[label] not in {home, epoch}
                and device == protected_device
                and protected_root in mount_root.parents
                for label, (
                    protected_device,
                    protected_root,
                ) in protected_backings.items()
            ):
                raise RunnerError(
                    "live Codex writable output overlaps protected mount backing"
                )
            observed_writable_outputs.add(mount)
            continue
        # Bind-remounting / somewhere else is unsafe even if every narrower
        # protected path lives on a separate read-only filesystem. Reject the
        # root backing before comparing the other immutable input roots.
        if device == filesystem_root_device and mount_root == filesystem_root_backing:
            raise RunnerError("live Codex has a writable alias of filesystem root")
        if mount == home or home in mount.parents:
            # No writable submount of HOME may be an accidental or malicious
            # alias to original plans, sources, credentials or repo metadata.
            raise RunnerError("live Codex has an unexpected writable home bind mount")
        if any(
            mount == protected or protected in mount.parents
            for protected in protected_directories
        ):
            raise RunnerError(
                "live Codex has an unexpected writable protected input bind mount"
            )
        if mount != Path("/") and any(
            device == protected_device
            and (
                mount_root == protected_root
                or protected_root in mount_root.parents
                or mount_root in protected_root.parents
            )
            for protected_device, protected_root in protected_backings.values()
        ):
            raise RunnerError(
                "live Codex has a writable alias of protected input mount"
            )
        # A hard link outside all four outputs can still write a protected
        # inode whenever any other RW mount exposes the same filesystem.
        # Unrelated tmpfs and virtual mounts cannot hard-link across devices.
        if device == filesystem_root_device or any(
            device == protected_device
            for protected_device, _ in protected_backings.values()
        ):
            raise RunnerError(
                "live Codex unexpected writable mount sharing protected filesystem"
            )
        # Another writable persistent filesystem may reach protected storage
        # through an opaque block backing even when its mount device differs.
        # The four checked output leaves are the sole persistent RW mounts;
        # unrelated memory-backed/kernel virtual mounts are handled separately.
        filesystem_type = records[visible_at_point[mount]][5]
        if filesystem_type in {
            b"ext2",
            b"ext3",
            b"ext4",
            b"xfs",
            b"btrfs",
            b"f2fs",
            b"zfs",
            b"vfat",
            b"exfat",
            b"squashfs",
            b"erofs",
            b"iso9660",
        }:
            raise RunnerError(
                "live Codex unexpected writable persistent filesystem mount"
            )
        # A writable tmpfs outside these root-systemd private paths may
        # expose same-UID sockets (user systemd, container daemon, D-Bus).
        # RO bind mounting a socket also permits connect(), so the
        # DynamicUser + private IPC root-owned attestation remains required.
        # /dev is private through PrivateDevices=yes; /tmp through
        # PrivateTmp=yes. Unexpected /run or user-session mounts must fail.
        isolated_volatile_mounts = {
            (Path("/dev"), b"tmpfs"),
            (Path("/dev/shm"), b"tmpfs"),
            (Path("/dev/pts"), b"devpts"),
            (Path("/dev/mqueue"), b"mqueue"),
            (Path("/tmp"), b"tmpfs"),
            (Path("/var/tmp"), b"tmpfs"),
        }
        if (mount, filesystem_type) not in isolated_volatile_mounts:
            raise RunnerError("live Codex unexpected writable runtime mount")
    if observed_writable_outputs != allowed_outputs:
        raise RunnerError("live Codex private writable output mounts are missing")
    _assert_root_owned_device_policy()


def provider_env(
    *, codex: str | None = None, codex_home: Path | None = None
) -> dict[str, str]:
    keep = {"HOME", "LANG", "LC_ALL", "TMPDIR", "XDG_RUNTIME_DIR"}
    environment = {key: value for key, value in os.environ.items() if key in keep}
    environment["PATH"] = (
        validate_toolchain(codex) if codex is not None else "/usr/bin:/bin"
    )
    if codex_home is not None:
        environment["CODEX_HOME"] = str(codex_home)
    for key in (
        "OPENAI_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "XAI_API_KEY",
        "CODEX_ACCESS_TOKEN",
    ):
        environment.pop(key, None)
    return environment


def _read_chatgpt_auth_file(home: Path) -> bytes:
    path = home / ".codex" / "auth.json"
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError("Codex ChatGPT auth file is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError("Codex ChatGPT auth file must be a regular non-symlink file")
    if linked.st_uid != os.geteuid() or linked.st_mode & 0o077:
        raise RunnerError("Codex ChatGPT auth file permissions are unsafe")
    if linked.st_size <= 0 or linked.st_size > MAX_AUTH_BYTES:
        raise RunnerError("Codex ChatGPT auth file size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunnerError("Codex ChatGPT auth file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = b""
        while len(data) <= MAX_AUTH_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_AUTH_BYTES + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise RunnerError(
            "Codex ChatGPT auth file disappeared during validation"
        ) from exc
    initial_identity = (
        linked.st_dev,
        linked.st_ino,
        linked.st_size,
        linked.st_mode,
        linked.st_uid,
    )
    opened_identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mode,
        opened.st_uid,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_uid,
    )
    if initial_identity != opened_identity or opened_identity != after_identity:
        raise RunnerError("Codex ChatGPT auth file changed during validation")
    if len(data) != opened.st_size or len(data) > MAX_AUTH_BYTES:
        raise RunnerError("Codex ChatGPT auth file changed or exceeds its bound")
    return data


def _read_bound_regular_file_at(
    directory_fd: int,
    name: str,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise RunnerError(f"{label} relative name is invalid")
    try:
        linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if linked.st_size < 0 or linked.st_size > max_bytes:
        raise RunnerError(f"{label} size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise RunnerError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        final_descriptor = os.fstat(descriptor)
        try:
            final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RunnerError(f"{label} disappeared during validation") from exc
        initial_identity = (
            linked.st_dev,
            linked.st_ino,
            linked.st_size,
            linked.st_mode,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mode,
        )
        final_descriptor_identity = (
            final_descriptor.st_dev,
            final_descriptor.st_ino,
            final_descriptor.st_size,
            final_descriptor.st_mode,
        )
        final_identity = (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mode,
        )
        if (
            initial_identity != opened_identity
            or opened_identity != final_descriptor_identity
            or opened_identity != final_identity
        ):
            raise RunnerError(f"{label} changed during validation")
        if len(data) != opened.st_size or len(data) > max_bytes:
            raise RunnerError(f"{label} changed or exceeds its bound")
        return bytes(data)
    finally:
        os.close(descriptor)


def _read_bound_regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    if not path.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if linked.st_size < 0 or linked.st_size > max_bytes:
        raise RunnerError(f"{label} size is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunnerError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} disappeared during validation") from exc
    initial_identity = (linked.st_dev, linked.st_ino, linked.st_size, linked.st_mode)
    opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
    if initial_identity != opened_identity or opened_identity != after_identity:
        raise RunnerError(f"{label} changed during validation")
    if len(data) != opened.st_size or len(data) > max_bytes:
        raise RunnerError(f"{label} changed or exceeds its bound")
    return bytes(data)


def validate_chatgpt_subscription(codex: str) -> bytes:
    source_environment = provider_env(codex=codex)
    home_text = source_environment.get("HOME")
    if not home_text or not Path(home_text).is_absolute():
        raise RunnerError("HOME is unavailable for Codex ChatGPT authentication")
    auth_data = _read_chatgpt_auth_file(Path(home_text))

    # Snapshot the exact credential bytes before asking Codex what login mode
    # they represent.  The real run later stages these returned bytes again, so
    # status validation and provider execution are byte-identical even if the
    # user's mutable ~/.codex/auth.json changes concurrently.
    with tempfile.TemporaryDirectory(prefix="grabowski-codex-auth-") as temporary:
        snapshot_root = Path(temporary)
        snapshot_root.chmod(0o700)
        snapshot_home = stage_codex_home(snapshot_root, auth_data)
        try:
            environment = provider_env(codex=codex, codex_home=snapshot_home)
            # Protect the unfiltered parent BEFORE the first real Codex
            # child, and therefore before any irreversible provider intent.
            _assert_trusted_runner_nondumpable()
            try:
                completed = subprocess.run(
                    _unix_socket_restricted_codex_argv([codex, "login", "status"]),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    shell=False,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RunnerError(
                    "Codex ChatGPT login status could not be verified"
                ) from exc
            try:
                text = (
                    completed.stdout.decode("utf-8")
                    + "\n"
                    + completed.stderr.decode("utf-8")
                )
            except UnicodeDecodeError as exc:
                raise RunnerError("Codex ChatGPT login status was not UTF-8") from exc
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            status_lines = [
                line
                for line in lines
                if not _login_status_line_is_qualified(
                    line, snapshot_root=snapshot_root, snapshot_home=snapshot_home
                )
            ]
            if completed.returncode != 0 or status_lines != [CHATGPT_LOGIN_LINE]:
                raise RunnerError(
                    "Codex must be logged in using the ChatGPT subscription"
                )
            staged = _read_bound_regular_file(
                snapshot_home / "auth.json",
                label="staged Codex ChatGPT auth file",
                max_bytes=MAX_AUTH_BYTES,
            )
            if staged != auth_data:
                raise RunnerError(
                    "staged Codex ChatGPT auth bytes changed during validation"
                )
        except BaseException:
            cleanup_codex_home(snapshot_home)
            raise
        cleanup_error = cleanup_codex_home(snapshot_home)
        if cleanup_error is not None:
            raise RunnerError("Codex ChatGPT auth snapshot cleanup failed")
    return auth_data


def stage_codex_home(state_root: Path, auth_data: bytes) -> Path:
    parent_path, parent_fd = _open_private_directory(state_root / "codex-runtime")
    child_fd: int | None = None
    runtime_name: str | None = None
    try:
        for _attempt in range(4):
            candidate = "session-" + sha_bytes(os.urandom(32))[:24]
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            runtime_name = candidate
            break
        if runtime_name is None:
            raise RunnerError("could not allocate unique Codex runtime home")
        child_fd = os.open(runtime_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        child = os.fstat(child_fd)
        if child.st_uid != os.geteuid() or stat.S_IMODE(child.st_mode) != 0o700:
            raise RunnerError("Codex runtime home permissions are unsafe")
        _write_private_dirfd(child_fd, "auth.json", auth_data)
        _directory_fd_matches(parent_path, parent_fd)
        os.fsync(parent_fd)
        return parent_path / runtime_name
    except BaseException:
        if child_fd is not None:
            try:
                os.unlink("auth.json", dir_fd=child_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if runtime_name is not None:
            try:
                os.rmdir(runtime_name, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        raise
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)


def cleanup_codex_home(path: Path) -> str | None:
    try:
        shutil.rmtree(path)
    except OSError as exc:
        return type(exc).__name__
    return None


def validate_codex_linux_sandbox_before_intent(
    codex: str, source: Path, state_root: Path
) -> None:
    """Exercise the real Codex Linux sandbox without provider or one-shot use.

    Run before workspace/evidence allocation and before recording dispatch
    intent. The transient Codex home stays on the trusted private state mount:
    Codex refuses to create its argv0 Linux helper when CODEX_HOME is in /tmp.
    No authenticated bytes are staged or sent to this smoke process.
    """
    private_home = stage_codex_home(state_root, b"{}")
    try:
        private_tmp, tmp_fd = _open_private_directory(private_home / "tmp")
        os.close(tmp_fd)
        filesystem = (
            '{":minimal"="read",":workspace_roots"={"."="read"},'
            + _toml_string(str(private_tmp))
            + '="read",'
            + _toml_string(str(Path(codex).parent))
            + '="read"}'
        )
        command = [
            codex,
            "sandbox",
            "-c",
            "allow_login_shell=false",
            "-c",
            "features.network_proxy=true",
            "-c",
            f"permissions.{PERMISSION_PROFILE}.filesystem={filesystem}",
            "-c",
            f"permissions.{PERMISSION_PROFILE}.network="
            '{enabled=true,mode="limited",allow_local_binding=false,domains={}}',
            "--permission-profile",
            PERMISSION_PROFILE,
            "--enable",
            "network_proxy",
            "--cd",
            str(source),
            "--",
            "/bin/true",
        ]
        try:
            completed = subprocess.run(
                _unix_socket_restricted_codex_argv(command),
                cwd=source,
                env=provider_env(codex=codex, codex_home=private_home),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=25,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RunnerError(
                "Codex Linux sandbox startup failed before provider intent"
            ) from exc
        if (
            completed.returncode != 0
            or not isinstance(completed.stdout, bytes)
            or not isinstance(completed.stderr, bytes)
            or len(completed.stdout) > 8192
            or len(completed.stderr) > 8192
        ):
            raise RunnerError(
                "Codex Linux sandbox startup failed before provider intent"
            )
    finally:
        if cleanup_codex_home(private_home) is not None:
            raise RunnerError("Codex sandbox qualification cleanup failed")


def _validated_live_mode(
    *,
    stream_fixture: Path | None,
    stderr_fixture: Path | None,
    fixture_returncode: int,
    allow_live_provider: bool,
    codex_command_sha256: str | None,
) -> None:
    if stream_fixture is not None:
        if allow_live_provider or codex_command_sha256 is not None:
            raise RunnerError(
                "synthetic fixture must not carry live-provider authorization"
            )
        return
    if stderr_fixture is not None or fixture_returncode != 0:
        raise RunnerError("live execution must not carry synthetic fixture controls")
    if not allow_live_provider:
        raise RunnerError("live execution requires explicit allow_live_provider")
    if codex_command_sha256 is None:
        raise RunnerError("live execution requires codex_command_sha256")


_DIRECTORY_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
)


def _open_private_directory(
    path: Path, *, create_final: bool = True
) -> tuple[Path, int]:
    if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
        raise RunnerError(
            "private output directory must be an absolute normalized path"
        )
    parts = path.parts
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for index, component in enumerate(parts[1:], start=1):
            final = index == len(parts) - 1
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                if not final or not create_final:
                    raise RunnerError("private output directory parent is unavailable")
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise RunnerError(
                    "private output directory contains an unsafe component"
                ) from exc
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise RunnerError("private output directory ownership is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_nlink < 1:
            raise RunnerError("private output directory permissions are unsafe")
        return path, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_fd_matches(path: Path, descriptor: int) -> None:
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError("private output directory identity disappeared") from exc
    opened = os.fstat(descriptor)
    if stat.S_ISLNK(linked.st_mode) or (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_uid,
    ) != (linked.st_dev, linked.st_ino, linked.st_mode, linked.st_uid):
        raise RunnerError("private output directory identity changed")


def _write_private_dirfd(
    descriptor: int, name: str, data: bytes, *, mode: int = 0o600
) -> None:
    if Path(name).name != name or not name:
        raise RunnerError("private artifact name is unsafe")
    if mode not in {0o600, 0o700}:
        raise RunnerError("private artifact mode is unsafe")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        file_descriptor = os.open(name, flags, mode, dir_fd=descriptor)
    except FileExistsError as exc:
        raise RunnerError("provider evidence artifact already exists") from exc
    write_error: BaseException | None = None
    try:
        view = memoryview(data)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError("short private artifact write")
            view = view[written:]
        os.fsync(file_descriptor)
    except BaseException as exc:
        write_error = exc
        try:
            os.fsync(file_descriptor)
        except OSError:
            pass
    finally:
        os.close(file_descriptor)
    try:
        os.fsync(descriptor)
    except OSError:
        if write_error is None:
            raise
    if write_error is not None:
        raise write_error


def _assert_absent(descriptor: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise RunnerError("provider evidence artifact already exists")


def prepare_provider_evidence(
    request: Mapping[str, Any], transcript_root: Path, evidence_root: Path
) -> dict[str, Any]:
    names = _provider_artifact_names(request)
    transcript_path, transcript_fd = _open_private_directory(transcript_root)
    try:
        evidence_path, evidence_fd = _open_private_directory(evidence_root)
    except BaseException:
        os.close(transcript_fd)
        raise
    try:
        _directory_fd_matches(transcript_path, transcript_fd)
        _directory_fd_matches(evidence_path, evidence_fd)
        _assert_absent(transcript_fd, names["stdout"])
        for key in ("stderr", "diagnostics", "stderr_policy"):
            _assert_absent(evidence_fd, names[key])
        return {
            "names": names,
            "transcript_root": transcript_path,
            "evidence_root": evidence_path,
            "transcript_fd": transcript_fd,
            "evidence_fd": evidence_fd,
        }
    except BaseException:
        os.close(transcript_fd)
        os.close(evidence_fd)
        raise


def close_provider_evidence_plan(plan: Mapping[str, Any]) -> None:
    for key in ("transcript_fd", "evidence_fd"):
        try:
            os.close(int(plan[key]))
        except OSError:
            pass


def _assert_checkout_tree_has_regular_blobs(source: Path, commit: str) -> None:
    """Reject unbounded Git trees before cloning or consuming a one-use ID.

    Do not let partial-clone promisor remotes fetch missing objects; scanning
    must remain local, streaming, bounded in bytes, entries and wall time.
    """
    try:
        process = subprocess.Popen(
            ["git", "ls-tree", "-r", "-l", "--full-tree", "-z", commit],
            cwd=source,
            env=base._git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise RunnerError("benchmark source Git tree cannot be inspected") from exc
    deadline = time.monotonic() + 30
    try:
        if process.stdout is None:
            raise RunnerError("benchmark source Git tree stream is unavailable")
        remainder = b""
        total_bytes = 0
        total_files = 0
        total_blob_bytes = 0
        # Postflight shares a 2 GiB counter across both source and checkout
        # reads, plus Git control files. Reject before reserving a one-use
        # workspace, leaving 128 MiB for the fresh checkout's Git metadata.
        max_blob_bytes = 256 * 1024 * 1024
        max_total_blob_bytes = (2 * 1024 * 1024 * 1024 - 128 * 1024 * 1024) // 2
        directories: set[tuple[bytes, ...]] = set()
        # read1() can block indefinitely when a promisor process or inherited
        # pipe remains open. A nonblocking pipe and selector bound the *entire*
        # scan, including EOF and the final process reaping.
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as stream_selector:
            stream_selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not stream_selector.select(timeout=remaining):
                    raise RunnerError("benchmark source Git tree inspection timed out")
                try:
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > 16 * 1024 * 1024:
                    raise RunnerError(
                        "benchmark source Git tree listing exceeds byte budget"
                    )
                *records, remainder = (remainder + chunk).split(bytes((0,)))
                if len(remainder) > 8192:
                    raise RunnerError(
                        "benchmark source Git tree entry exceeds byte budget"
                    )
                for record in records:
                    if not (
                        record.startswith(b"100644 blob ")
                        or record.startswith(b"100755 blob ")
                    ):
                        raise RunnerError("unsupported tracked Git tree entry")
                    metadata, separator, relative = record.partition(b"\t")
                    fields = metadata.split()
                    if (
                        len(fields) != 4
                        or fields[0] not in (b"100644", b"100755")
                        or fields[1] != b"blob"
                        or re.fullmatch(rb"[0-9a-f]{40}", fields[2]) is None
                        or re.fullmatch(rb"(0|[1-9][0-9]{0,19})", fields[3]) is None
                    ):
                        raise RunnerError(
                            "benchmark source Git blob size metadata is invalid"
                        )
                    blob_size = int(fields[3])
                    if blob_size > max_blob_bytes:
                        raise RunnerError(
                            "benchmark source Git blob byte limit exceeded"
                        )
                    total_blob_bytes += blob_size
                    if total_blob_bytes > max_total_blob_bytes:
                        raise RunnerError(
                            "benchmark source Git blob byte aggregate exceeded"
                        )
                    segments = relative.split(b"/")
                    if (
                        not separator
                        or len(record) > 8192
                        or any(part in (b"", b".", b"..") for part in segments)
                    ):
                        raise RunnerError("benchmark source Git tree entry is invalid")
                    if len(segments) > 30:
                        raise RunnerError(
                            "benchmark source Git tree depth exceeds scan limit"
                        )
                    total_files += 1
                    if total_files > 65536:
                        raise RunnerError(
                            "benchmark source Git tree has too many entries"
                        )
                    for length in range(1, len(segments)):
                        directories.add(tuple(segments[:length]))
                    if total_files + len(directories) > 65536:
                        raise RunnerError(
                            "benchmark source Git tree has too many entries"
                        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunnerError("benchmark source Git tree inspection timed out")
        try:
            exit_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("benchmark source Git tree inspection timed out") from exc
        if remainder or exit_code != 0:
            raise RunnerError("benchmark source Git tree inspection was incomplete")
    except BaseException:
        try:
            if process.poll() is None:
                process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("benchmark source Git tree cleanup timed out") from exc
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()


def create_checkout(
    request: Mapping[str, Any],
    source: Path,
    state_root: Path,
    *,
    preallocate_check: Callable[[int], None] | None = None,
) -> Path:
    """Prepare and validate a disposable clone before claiming one-use identity.

    A Git clone generates .git files outside the tracked tree. Prove the exact
    output scan on the staged clone before reserving the final workspace name.
    """
    scenario = base.validated_setup(request)
    commit = str(request["repository"]["commit"])
    if base._run_checked(
        ["git", "rev-parse", "HEAD"], cwd=source
    ) != commit or base._run_checked(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=source
    ):
        raise RunnerError("benchmark source checkout is not clean at requested commit")
    _assert_checkout_tree_has_regular_blobs(source, commit)
    workspace_id = str(request["workspace_id"])
    workspace_name = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
    checkout_name = "source" if scenario == "dirty" else "repo"
    parent_path, parent_fd = _open_private_directory(state_root / "codex-workspaces")
    staging_name = "preflight-" + sha_bytes(os.urandom(32))[:24]
    staging_path = parent_path / staging_name
    try:
        os.mkdir(staging_name, 0o700, dir_fd=parent_fd)
        try:
            staged_checkout = staging_path / checkout_name
            base._run_checked(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "clone",
                    "--no-hardlinks",
                    "--no-checkout",
                    "--",
                    str(source),
                    str(staged_checkout),
                ]
            )
            base._run_checked(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "checkout",
                    "--detach",
                    commit,
                ],
                cwd=staged_checkout,
            )
            if (
                base._run_checked(["git", "rev-parse", "HEAD"], cwd=staged_checkout)
                != commit
            ):
                raise RunnerError("isolated Codex checkout HEAD mismatch")
            if base._run_checked(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=staged_checkout,
            ):
                raise RunnerError(
                    "isolated Codex checkout is dirty before fixture setup"
                )
            base.apply_checkout_setup(request, staged_checkout)
            if base._run_checked(
                ["git", "rev-parse", "HEAD"], cwd=source
            ) != commit or base._run_checked(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                cwd=source,
            ):
                raise RunnerError(
                    "benchmark source checkout changed during fixture setup"
                )

            # Check generated .git objects and the full output tree while only
            # a disposable staging checkout exists. No one-use ID is held yet.
            if preallocate_check is None:
                _assert_private_output_tree_scan((state_root,), reserved_entries=1)
            else:
                future_pair_entries = 0
                if request["order"] == 1:
                    # The first condition can be treatment or baseline. Before
                    # spending its one-shot, reserve only the remaining
                    # condition's clone. The current staged checkout is
                    # already included in the state-root scan, and no third
                    # clone exists for the final condition.
                    staged_entries = _assert_private_output_tree_scan(
                        (staged_checkout,)
                    )
                    future_pair_entries = staged_entries + 2 + 16
                    if future_pair_entries > 65536:
                        raise RunnerError("paired clone budget exceeds output limit")
                preallocate_check(future_pair_entries)

            try:
                os.mkdir(workspace_name, 0o700, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise RunnerError("Codex workspace identity was already used") from exc
            child_fd = os.open(workspace_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            try:
                child = os.fstat(child_fd)
                if child.st_uid != os.geteuid() or stat.S_IMODE(child.st_mode) != 0o700:
                    raise RunnerError("Codex workspace directory is unsafe")
            finally:
                os.close(child_fd)
            workspace = parent_path / workspace_name
            checkout = workspace / checkout_name
            os.rename(staged_checkout, checkout)
            os.fsync(parent_fd)
            _directory_fd_matches(parent_path, parent_fd)
            return checkout
        finally:
            # Only a private disposable clone is removed here. A final
            # one-use workspace, once allocated, is never silently deleted.
            shutil.rmtree(staging_path)
    finally:
        os.close(parent_fd)


def prompt_for(request: Mapping[str, Any]) -> str:
    vocabulary = ", ".join(base.CLAIM_VOCABULARY)
    extra = ""
    if request["condition"] == "treatment":
        extra = (
            " For treatment, you must successfully use at least one of these RepoGround "
            "MCP tools before answering: ask_context, grounding_verify, live_freshness, "
            "repobrief_resource_read. Use only these RepoGround MCP tools."
        )
    return (
        str(request["prompt"])
        + "\n\nBenchmark rules: work read-only. For direct repository inspection use ONLY "
        "one single command per tool call and ONLY these forms: rg --files ... ; "
        "rg ... ; sed -n 'START,ENDp' PATH ; cat PATH. Do not use ls, find, git, "
        "python, shell pipes, redirections, command chaining, web search, subagents, "
        "or file edits. Any such use invalidates the run."
        + extra
        + " Return only the JSON object required by the provided output schema. Paths "
        "must be repository-relative; citations use exact inclusive line ranges. Use "
        "only these claim labels when supported: "
        + vocabulary
        + ". Do not guess missing evidence."
    )


def _proxy_write(message: Mapping[str, Any], lock: threading.Lock) -> None:
    raw = canonical(message).encode("utf-8") + b"\n"
    with lock:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()


def _freeze_resource_result(value: Any) -> tuple[dict[str, Any], set[str]]:
    if not isinstance(value, dict) or not isinstance(value.get("resources"), list):
        raise RunnerError("RepoGround resource list is malformed")
    if value.get("nextCursor") not in {None, ""}:
        raise RunnerError("RepoGround resource list is paginated")
    resources = value["resources"]
    if len(resources) > MAX_FROZEN_RESOURCES:
        raise RunnerError("RepoGround resource list exceeds its bound")
    uris: set[str] = set()
    frozen: list[dict[str, Any]] = []
    for item in resources:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("uri"), str)
            or not item["uri"]
        ):
            raise RunnerError("RepoGround resource list contains an invalid URI")
        uri = item["uri"]
        if uri in uris or len(uri.encode("utf-8")) > 4096:
            raise RunnerError("RepoGround resource URI is duplicate or oversized")
        uris.add(uri)
        frozen.append(json.loads(json.dumps(item)))
    return {"resources": frozen}, uris


def _validated_resource_read_result(value: Any, *, expected_uri: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"contents", "_meta"}:
        raise RunnerError("RepoGround resource read result is malformed")
    contents = value.get("contents")
    if not isinstance(contents, list) or len(contents) != 1:
        raise RunnerError(
            "RepoGround resource read result must contain exactly one item"
        )
    item = contents[0]
    if not isinstance(item, dict) or set(item) != {"uri", "mimeType", "text"}:
        raise RunnerError("RepoGround resource read content item is malformed")
    if item.get("uri") != expected_uri:
        raise RunnerError(
            "RepoGround resource read URI does not match the frozen request"
        )
    mime_type = item.get("mimeType")
    if (
        not isinstance(mime_type, str)
        or not mime_type
        or len(mime_type.encode("utf-8")) > 256
    ):
        raise RunnerError("RepoGround resource read mimeType is invalid")
    if not isinstance(item.get("text"), str):
        raise RunnerError("RepoGround resource read text is invalid")
    if not isinstance(value.get("_meta"), dict):
        raise RunnerError("RepoGround resource read metadata is malformed")
    return json.loads(json.dumps(value))


def _rebind_resource_read_manifest(
    value: Mapping[str, Any],
    *,
    staged_manifest: Path,
    external_manifest: Path,
) -> dict[str, Any]:
    rebound = json.loads(json.dumps(value))
    meta = rebound.get("_meta")
    repoground = meta.get("repoground") if isinstance(meta, dict) else None
    freshness = (
        repoground.get("liveFreshness") if isinstance(repoground, dict) else None
    )
    if not isinstance(freshness, dict):
        return rebound
    if freshness.get("bundle_manifest") != str(staged_manifest):
        raise RunnerError(
            "RepoGround resource live freshness manifest does not match staged manifest"
        )
    freshness["bundle_manifest"] = str(external_manifest)
    return rebound


_validated_live_freshness_payload = base._validated_live_freshness_payload
_validated_read_only_frontdoor_projection = (
    base._validated_read_only_frontdoor_projection
)
_validated_ask_context_pack = base._validated_ask_context_pack
_validated_grounding_verdict = base._validated_grounding_verdict


def _validated_frozen_g1_context_pack(
    value: Any, *, expected_manifest: Path
) -> dict[str, Any]:
    """Validate the actual 2026 G1 contract; never synthesize modern evidence."""
    fields = {
        "kind",
        "version",
        "request_id",
        "snapshot_ref",
        "freshness",
        "availability",
        "required_reading",
        "retrieval_hits",
        "resolved_ranges",
        "answer_scaffold",
        "budget",
        "forbidden_operations",
        "does_not_establish",
    }

    def bad() -> None:
        raise RunnerError("historical G1 ask_context context pack is malformed")

    if not isinstance(value, dict) or set(value) != fields:
        bad()
    if (
        value.get("kind") != EXPECTED_ASK_CONTEXT_PACK_KIND
        or value.get("version") != EXPECTED_ASK_CONTEXT_PACK_VERSION
        or not isinstance(value.get("request_id"), str)
        or re.fullmatch(r"[0-9a-f]{16}", value["request_id"]) is None
        or value.get("forbidden_operations")
        != list(EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS)
        or value.get("does_not_establish")
        != list(EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH)
    ):
        bad()
    snapshot = value.get("snapshot_ref")
    if (
        not isinstance(snapshot, dict)
        or set(snapshot)
        != {
            "freshness_policy",
            "freshness_status",
            "git_commit",
            "manifest_path",
            "manifest_sha256",
            "stem",
        }
        or snapshot.get("freshness_policy") != "allow_stale_with_caveat"
        or snapshot.get("freshness_status") not in EXPECTED_REPOGROUND_FRESHNESS_VALUES
        or snapshot.get("git_commit")
        not in (None, FROZEN_G1_LEGACY_IDENTITY["repository"]["commit"])
        or snapshot.get("manifest_path") != str(expected_manifest)
        or snapshot.get("manifest_sha256")
        != FROZEN_G1_LEGACY_IDENTITY["manifest_sha256"]
        or snapshot.get("stem")
        != expected_manifest.name.removesuffix(".bundle.manifest.json")
    ):
        bad()
    for key, statuses in (
        (
            "freshness",
            {"fresh", "stale", "unknown", "not_comparable", "not_applicable"},
        ),
        ("availability", {"available", "partial", "missing", "unknown"}),
    ):
        item = value.get(key)
        if (
            not isinstance(item, dict)
            or set(item) != {"status", "caveats"}
            or item.get("status") not in statuses
            or not isinstance(item.get("caveats"), list)
            or any(
                not isinstance(c, dict)
                or set(c) != {"kind", "detail"}
                or not all(
                    isinstance(c.get(n), str) and c[n] for n in ("kind", "detail")
                )
                for c in item["caveats"]
            )
        ):
            bad()
    if snapshot["freshness_status"] != value["freshness"]["status"]:
        bad()
    reading = value.get("required_reading")
    if (
        not isinstance(reading, dict)
        or set(reading)
        != {
            "status",
            "task_profile",
            "required",
            "recommended",
            "missing_required",
            "missing_recommended",
        }
        or reading.get("status") not in {"pass", "partial", "fail", "unknown"}
        or not isinstance(reading.get("task_profile"), str)
        or not reading["task_profile"]
        or any(
            not isinstance(reading.get(k), list)
            or any(not isinstance(item, str) or not item for item in reading[k])
            for k in (
                "required",
                "recommended",
                "missing_required",
                "missing_recommended",
            )
        )
    ):
        bad()
    if any(
        not isinstance(value.get(k), list)
        or any(not isinstance(item, dict) for item in value[k])
        for k in ("retrieval_hits", "resolved_ranges")
    ):
        bad()
    scaffold = value.get("answer_scaffold")
    if (
        not isinstance(scaffold, dict)
        or set(scaffold)
        != {"citation_obligations", "caveats_to_surface", "non_claims_to_surface"}
        or not isinstance(scaffold.get("citation_obligations"), list)
        or any(
            not isinstance(i, str) or not i for i in scaffold["citation_obligations"]
        )
        or not isinstance(scaffold.get("caveats_to_surface"), list)
        or any(
            not isinstance(c, dict) or set(c) != {"kind", "detail"}
            for c in scaffold["caveats_to_surface"]
        )
        or scaffold.get("non_claims_to_surface")
        != list(EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH)
    ):
        bad()
    budget = value.get("budget")
    if (
        not isinstance(budget, dict)
        or set(budget)
        != {
            "max_context_tokens",
            "max_answer_tokens",
            "approx_context_chars_used",
            "truncated",
            "does_not_establish_quality",
        }
        or any(
            type(budget.get(k)) is not int or budget[k] < 0
            for k in (
                "max_context_tokens",
                "max_answer_tokens",
                "approx_context_chars_used",
            )
        )
        or budget["max_context_tokens"] < 1
        or budget["max_answer_tokens"] < 1
        or type(budget.get("truncated")) is not bool
        or budget.get("does_not_establish_quality") is not True
    ):
        bad()
    return json.loads(json.dumps(value))


def _validated_treatment_structured_payload(
    value: Any,
    *,
    tool_name: str,
    expected_manifest: Path,
    is_error: bool,
    profile: str = MCP_PROFILE_MODERN,
) -> dict[str, Any]:
    if profile == MCP_PROFILE_MODERN:
        return base._validated_treatment_structured_payload(
            value,
            tool_name=tool_name,
            expected_manifest=expected_manifest,
            is_error=is_error,
        )
    if profile != MCP_PROFILE_FROZEN_G1:
        raise RunnerError("unknown treatment MCP profile")
    if not isinstance(value, dict):
        raise RunnerError("RepoGround treatment tool structured payload is malformed")
    if is_error:
        if (
            set(value) != {"status", "tool", "error"}
            or value.get("status") != "error"
            or value.get("tool") != tool_name
            or not isinstance(value.get("error"), str)
            or not value.get("error")
        ):
            raise RunnerError(
                "RepoGround treatment tool structured payload is malformed"
            )
        return json.loads(json.dumps(value))
    if tool_name == "live_freshness":
        return _validated_live_freshness_payload(
            value, expected_manifest=expected_manifest
        )
    common = {
        "kind",
        "version",
        "tool",
        "status",
        "mutation_boundary",
        "does_not_establish",
        "live_freshness",
    }
    if tool_name == "ask_context":
        expected_keys = common | {
            "context_pack",
            "request_semantics",
            "context_pack_semantics",
        }
        valid = (
            set(value) == expected_keys
            and value.get("kind") == EXPECTED_REPOGROUND_READ_ONLY_KIND
            and value.get("version") == EXPECTED_REPOGROUND_READ_ONLY_VERSION
            and value.get("tool") == "ask_context"
            and value.get("status") == "ok"
            and value.get("request_semantics") == "repobrief.ask_request.v1"
            and value.get("context_pack_semantics") == "repobrief.ask_context_pack.v1"
        )
    elif tool_name == "grounding_verify":
        expected_keys = common | {
            "verdict",
            "declaration_semantics",
            "verdict_semantics",
        }
        verdict = _validated_grounding_verdict(value.get("verdict"))
        verdict_status = verdict["status"]
        valid = (
            set(value) == expected_keys
            and value.get("kind") == EXPECTED_REPOGROUND_READ_ONLY_KIND
            and value.get("version") == EXPECTED_REPOGROUND_READ_ONLY_VERSION
            and value.get("tool") == "grounding_verify"
            and isinstance(value.get("status"), str)
            and value.get("status") == verdict_status
            and value.get("declaration_semantics")
            == "repobrief.answer_grounding_declaration.v1"
            and value.get("verdict_semantics")
            == "repobrief.answer_grounding_verdict.v1"
        )
    else:
        raise RunnerError("RepoGround treatment tool response is not authorized")
    if not valid:
        raise RunnerError("RepoGround treatment tool structured payload is malformed")
    _validated_read_only_frontdoor_projection(value)
    if tool_name == "ask_context":
        if profile == MCP_PROFILE_FROZEN_G1:
            _validated_frozen_g1_context_pack(
                value.get("context_pack"), expected_manifest=expected_manifest
            )
        else:
            _validated_ask_context_pack(value.get("context_pack"))
    _validated_live_freshness_payload(
        value.get("live_freshness"), expected_manifest=expected_manifest
    )
    return json.loads(json.dumps(value))


def _validated_treatment_tool_result(
    value: Any,
    *,
    tool_name: str,
    expected_manifest: Path,
    external_manifest: Path | None = None,
    profile: str = MCP_PROFILE_MODERN,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "content",
        "structuredContent",
        "isError",
    }:
        raise RunnerError("RepoGround treatment tool result is malformed")
    content = value.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise RunnerError("RepoGround treatment tool result is malformed")
    item = content[0]
    if (
        not isinstance(item, dict)
        or set(item) != {"type", "text"}
        or item.get("type") != "text"
        or not isinstance(item.get("text"), str)
        or not item.get("text")
    ):
        raise RunnerError("RepoGround treatment tool result is malformed")
    is_error = value.get("isError")
    if not isinstance(is_error, bool):
        raise RunnerError("RepoGround treatment tool result is malformed")
    structured = _validated_treatment_structured_payload(
        value.get("structuredContent"),
        tool_name=tool_name,
        expected_manifest=expected_manifest,
        is_error=is_error,
        profile=profile,
    )
    if not is_error and external_manifest is not None:
        freshness = (
            structured
            if tool_name == "live_freshness"
            else structured.get("live_freshness")
        )
        if not isinstance(freshness, dict):
            raise RunnerError("RepoGround treatment tool freshness binding is missing")
        freshness["bundle_manifest"] = str(external_manifest)
        if profile == MCP_PROFILE_FROZEN_G1 and tool_name == "ask_context":
            # Never expose the ephemeral private-stage path as public evidence.
            structured["context_pack"]["snapshot_ref"]["manifest_path"] = str(
                external_manifest
            )
        if profile == MCP_PROFILE_MODERN and tool_name in {
            "grounding_verify",
            "ask_context",
        }:
            parent = (
                structured.get("verdict")
                if tool_name == "grounding_verify"
                else structured.get("context_pack")
            )
            snapshot_ref = (
                parent.get("snapshot_ref") if isinstance(parent, dict) else None
            )
            if isinstance(snapshot_ref, dict) and "manifest_path" in snapshot_ref:
                if snapshot_ref["manifest_path"] != str(expected_manifest):
                    raise RunnerError(
                        f"RepoGround {tool_name.replace('_verify', '')} snapshot manifest does not match staged manifest"
                    )
                snapshot_ref["manifest_path"] = str(external_manifest)
    return {
        "content": [{"type": "text", "text": canonical(structured)}],
        "structuredContent": structured,
        "isError": is_error,
    }


def _proxy_error(identifier: Any, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "error": {"code": -32601, "message": message},
    }


def _filtered_treatment_tools(
    value: Any, *, profile: str = MCP_PROFILE_MODERN
) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("tools"), list):
        raise RunnerError("RepoGround tools/list result is missing a tools array")
    if profile == MCP_PROFILE_FROZEN_G1:
        tools = value["tools"]
        if (
            len(tools) != 3
            or [item.get("name") if isinstance(item, dict) else None for item in tools]
            != ["ask_context", "grounding_verify", "live_freshness"]
            or not hmac.compare_digest(
                sha_bytes(canonical(tools).encode("utf-8")),
                FROZEN_G1_LEGACY_IDENTITY["descriptors_sha256"],
            )
        ):
            raise RunnerError("historical G1 MCP tools/list descriptor drifted")
        filtered = json.loads(json.dumps(tools))
    elif profile == MCP_PROFILE_MODERN:
        counts = {name: 0 for name in UPSTREAM_MCP}
        filtered: list[dict[str, Any]] = []
        for item in value["tools"]:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if name in counts:
                expected_schema = EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS[str(name)]
                if canonical(item.get("inputSchema")) != canonical(expected_schema):
                    raise RunnerError(
                        f"RepoGround treatment tool inputSchema drifted for {name}"
                    )
                expected_descriptor = EXPECTED_UPSTREAM_MCP_DESCRIPTORS[str(name)]
                if canonical(item) != canonical(expected_descriptor):
                    raise RunnerError(
                        f"RepoGround treatment tool descriptor drifted for {name}"
                    )
                counts[str(name)] += 1
                filtered.append(json.loads(json.dumps(expected_descriptor)))
        invalid = [
            f"{name}={counts[name]}" for name in sorted(counts) if counts[name] != 1
        ]
        if invalid:
            raise RunnerError(
                "RepoGround tools/list must expose every required treatment tool exactly once: "
                + ", ".join(invalid)
            )
    else:
        raise RunnerError("unrecognized RepoGround MCP tool profile")
    filtered.append(
        {
            "name": "repobrief_resource_read",
            "description": "List frozen RepoGround resources or read one exact frozen resource URI.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["action"],
                "properties": {
                    "action": {"enum": ["list", "read"]},
                    "uri": {"type": "string"},
                },
            },
        }
    )
    return filtered


def _read_bounded_mcp_line(stream: Any, *, peer: str) -> bytes:
    raw = stream.readline(base.MAX_MCP_MESSAGE_BYTES + 1)
    if len(raw) > base.MAX_MCP_MESSAGE_BYTES:
        raise RunnerError(f"MCP {peer} message too large")
    if raw and not raw.endswith(b"\n"):
        raise RunnerError(f"MCP {peer} message must be newline terminated")
    return raw


def _normalized_authorized_mcp_files(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RunnerError("preflight MCP command file authorization is missing")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected_keys = {"path", "bytes", "sha256", "mode"}
    for item in value:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise RunnerError("preflight MCP command file authorization is invalid")
        path_text = item.get("path")
        size = item.get("bytes")
        digest = item.get("sha256")
        mode = item.get("mode")
        if (
            not isinstance(path_text, str)
            or not Path(path_text).is_absolute()
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > MAX_PROVIDER_EXECUTABLE_BYTES
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(mode, str)
            or re.fullmatch(r"0o[0-7]{1,3}", mode) is None
            or path_text in seen
        ):
            raise RunnerError("preflight MCP command file authorization is invalid")
        seen.add(path_text)
        result.append(
            {"path": path_text, "bytes": size, "sha256": digest, "mode": mode}
        )
    return result


def _mcp_authorization_identity(binding: Mapping[str, Any]) -> dict[str, Any]:
    identity = binding.get("identity")
    digest = binding.get("sha256")
    path = binding.get("path")
    if (
        not isinstance(identity, tuple)
        or len(identity) != 4
        or not isinstance(path, Path)
        or not isinstance(digest, str)
    ):
        raise RunnerError("MCP runtime file binding is invalid")
    return {
        "path": str(path.resolve(strict=True)),
        "bytes": int(identity[2]),
        "sha256": digest,
        # Preflight serializes only the ordinary rwx permission bits.
        # Normalize runtime identity to that same explicit 9-bit contract.
        "mode": oct(stat.S_IMODE(int(identity[3])) & 0o777),
    }


def _rebind_staged_manifest_authorization(
    authorized_files: Sequence[Mapping[str, Any]],
    manifest_binding: Mapping[str, Any],
) -> list[dict[str, Any]]:
    expected = _normalized_authorized_mcp_files(list(authorized_files))
    original = manifest_binding.get("expected_manifest")
    if not isinstance(original, Mapping):
        raise RunnerError(
            "staged RepoGround manifest authorization provenance is missing"
        )
    original_authorization = _normalized_authorized_mcp_files([dict(original)])[0]
    matches = [
        index
        for index, item in enumerate(expected)
        if canonical(item) == canonical(original_authorization)
    ]
    if not matches:
        # A directory --bundle-root is intentionally absent from preflight's
        # command-file authorization. Preserve the program-only binding; the
        # subsequent _bind_mcp_upstream call revalidates that exact shape.
        return [dict(item) for item in expected]
    if len(matches) != 1:
        raise RunnerError(
            "preflight MCP files bind the authorized RepoGround manifest ambiguously"
        )
    staged_authorization = _mcp_authorization_identity(manifest_binding)
    match = matches[0]
    if any(
        index != match and item["path"] == staged_authorization["path"]
        for index, item in enumerate(expected)
    ):
        raise RunnerError(
            "staged RepoGround manifest path collides with MCP authorization"
        )
    rebound = [dict(item) for item in expected]
    rebound[match] = staged_authorization
    return rebound


def _require_private_ledger_directory(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        raise RunnerError(f"{label} is unsafe")


_AUTHORIZED_RUNTIME_CODE_NAMES = (
    "repobrief_agent_benchmark_preflight_core.py",
    "repobrief_agent_benchmark_codex_preflight.py",
    "repobrief_agent_benchmark_runner.py",
    ENTRYPOINT_BOOTSTRAP_NAME,
    Path(__file__).name,
)


def _runtime_code_path(name: str) -> Path:
    if name not in _AUTHORIZED_RUNTIME_CODE_NAMES:
        raise RunnerError(
            "preflight dispatch authorization code identity is unexpected"
        )
    try:
        path = Path(__file__).with_name(name).resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"authorized runtime code is unavailable: {name}") from exc
    return path


def _validated_authorized_runtime_code(code: Any) -> dict[str, dict[str, Any]]:
    files = code.get("files") if isinstance(code, dict) else None
    bundle_sha256 = code.get("bundle_sha256") if isinstance(code, dict) else None
    if (
        not isinstance(files, list)
        or len(files) != len(_AUTHORIZED_RUNTIME_CODE_NAMES)
        or not isinstance(bundle_sha256, str)
        or bundle_sha256 != base._sha256_json(files)
    ):
        raise RunnerError("preflight dispatch authorization code identity is invalid")
    executed_identities = {
        Path(__file__).name: globals().get(
            "__grabowski_source_identity__", _SELF_SOURCE_IDENTITY
        ),
        BASE_PATH.name: getattr(base, "__grabowski_source_identity__", None),
        ENTRYPOINT_BOOTSTRAP_NAME: _ENTRYPOINT_BOOTSTRAP_IDENTITY,
    }
    by_name: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise RunnerError(
                "preflight dispatch authorization code identity is invalid"
            )
        name = item.get("name")
        size = item.get("bytes")
        digest = item.get("sha256")
        if (
            not isinstance(name, str)
            or name in by_name
            or name not in _AUTHORIZED_RUNTIME_CODE_NAMES
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise RunnerError(
                "preflight dispatch authorization code identity is invalid"
            )
        executed = executed_identities.get(name)
        if executed is not None:
            executed_projection = (
                {
                    "name": executed.get("name"),
                    "bytes": executed.get("bytes"),
                    "sha256": executed.get("sha256"),
                }
                if isinstance(executed, dict)
                else None
            )
            if executed_projection != {
                "name": name,
                "bytes": size,
                "sha256": digest,
            }:
                raise RunnerError(
                    f"authorized runtime code differs from executed bytes: {name}"
                )
        path = _runtime_code_path(name)
        current = _read_bound_regular_file(
            path,
            label=f"authorized runtime code {name}",
            max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES,
        )
        if len(current) != size or sha_bytes(current) != digest:
            raise RunnerError(
                f"authorized runtime code changed after preflight: {name}"
            )
        by_name[name] = {"name": name, "bytes": size, "sha256": digest}
    if set(by_name) != set(_AUTHORIZED_RUNTIME_CODE_NAMES):
        raise RunnerError(
            "preflight dispatch authorization code identity is incomplete"
        )
    return by_name


def _validated_authorized_codex_provider(
    provider: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    codex = provider.get("codex") if isinstance(provider, dict) else None
    authentication = (
        provider.get("authentication") if isinstance(provider, dict) else None
    )
    if not isinstance(codex, dict):
        raise RunnerError("preflight dispatch authorization Codex identity is missing")
    path = codex.get("path")
    size = codex.get("bytes")
    digest = codex.get("sha256")
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise RunnerError("preflight dispatch authorization Codex identity is invalid")
    return (
        {"path": path, "bytes": size, "sha256": digest},
        _validated_authorized_authentication(authentication),
    )


def _assert_authorized_codex_executable(
    codex: str, codex_command_sha256: str, expected: Mapping[str, Any]
) -> None:
    path = Path(codex)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RunnerError("Codex executable disappeared after validation") from exc
    current = {
        "path": str(resolved),
        "bytes": metadata.st_size,
        "sha256": codex_command_sha256,
    }
    if canonical(current) != canonical(dict(expected)):
        raise RunnerError("Codex executable does not match preflight authorization")


def _runtime_file_snapshot(
    path: Path, *, label: str, max_bytes: int
) -> tuple[dict[str, Any], bytes]:
    requested = path.expanduser()
    if not requested.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    try:
        linked = requested.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if linked.st_size < 0 or linked.st_size > max_bytes:
        raise RunnerError(f"{label} size is invalid")
    try:
        descriptor = _open_absolute_regular_nofollow(requested, label=label)
    except RuntimeError as exc:
        raise RunnerError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            descriptor_path = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            raise RunnerError(f"{label} opened path cannot be bound") from exc
        if (
            not os.path.isabs(descriptor_path)
            or descriptor_path.endswith(" (deleted)")
            or os.path.normpath(descriptor_path) != os.path.normpath(str(requested))
        ):
            raise RunnerError(f"{label} opened path is unavailable")
        try:
            after = requested.lstat()
        except OSError as exc:
            raise RunnerError(f"{label} disappeared during validation") from exc
        initial_identity = (
            linked.st_dev,
            linked.st_ino,
            linked.st_size,
            linked.st_mode,
        )
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mode)
        after_descriptor_identity = (
            after_descriptor.st_dev,
            after_descriptor.st_ino,
            after_descriptor.st_size,
            after_descriptor.st_mode,
        )
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
        if (
            initial_identity != opened_identity
            or opened_identity != after_descriptor_identity
            or opened_identity != after_identity
        ):
            raise RunnerError(f"{label} changed during validation")
        if len(data) != opened.st_size or len(data) > max_bytes:
            raise RunnerError(f"{label} changed or exceeds its bound")
        raw = bytes(data)
        return (
            {
                "path": descriptor_path,
                "bytes": len(raw),
                "sha256": sha_bytes(raw),
                "mode": oct(opened.st_mode & 0o777),
            },
            raw,
        )
    finally:
        os.close(descriptor)


def _runtime_file_identity(path: Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    identity, _raw = _runtime_file_snapshot(path, label=label, max_bytes=max_bytes)
    return identity


def _repository_root_from_authorized_map_bytes(
    request: Mapping[str, Any], raw: bytes
) -> Path:
    document = base._load_object_bytes(raw, label="authorized repository map")
    repository = base._mapping(request.get("repository"))
    repository_id = str(repository.get("id"))
    entry = base._mapping(document.get(repository_id))
    if set(entry) != {"repository", "root"}:
        raise RunnerError(f"repository map misses strict entry for {repository_id}")
    if entry.get("repository") != repository.get("repository"):
        raise RunnerError("repository map owner/name mismatch")
    root = (
        Path(base._require_string(entry.get("root"), "repository map root"))
        .expanduser()
        .resolve()
    )
    if not root.is_dir() or not (root / ".git").exists():
        raise RunnerError("repository map root is not a Git checkout")
    return root


def _assert_all_authorized_request_files(
    binding: Mapping[str, Any], request_root: Path
) -> None:
    requests = binding.get("requests")
    if not isinstance(requests, dict) or set(requests) != {"baseline", "treatment"}:
        raise RunnerError(
            "preflight dispatch authorization request bindings are incomplete"
        )
    root = request_root.expanduser().resolve()
    for condition in ("baseline", "treatment"):
        expected_request = requests.get(condition)
        expected_file = (
            expected_request.get("file") if isinstance(expected_request, dict) else None
        )
        if not isinstance(expected_file, dict) or not isinstance(
            expected_file.get("path"), str
        ):
            raise RunnerError(
                f"preflight dispatch authorization {condition} request file identity is missing"
            )
        expected_path = Path(expected_file["path"])
        try:
            expected_path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise RunnerError(
                f"preflight dispatch authorization {condition} request file escapes request root"
            ) from exc
        current = _runtime_file_identity(
            expected_path,
            label=f"{condition} request",
            max_bytes=base.MAX_REQUEST_BYTES,
        )
        if canonical(expected_file) != canonical(current):
            raise RunnerError(
                f"preflight dispatch authorization {condition} request file identity mismatch"
            )


def _assert_authorized_runtime_binding(
    binding: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    evidence_root: Path,
) -> bytes:
    actual_paths = {
        "request_root": str(request_root.expanduser().resolve()),
        "state_root": str(state_root.expanduser().resolve()),
        "transcript_root": str(transcript_root.expanduser().resolve()),
        "evidence_root": str(evidence_root.expanduser().resolve()),
    }
    for field, actual in actual_paths.items():
        if binding.get(field) != actual:
            raise RunnerError(
                f"preflight dispatch authorization runtime binding mismatch: {field}"
            )

    expected_map = binding.get("repository_map")
    if not isinstance(expected_map, dict):
        raise RunnerError(
            "preflight dispatch authorization repository map identity is missing"
        )
    current_map, repository_map_bytes = _runtime_file_snapshot(
        repository_map.expanduser(),
        label="repository map",
        max_bytes=base.MAX_REQUEST_BYTES,
    )
    if canonical(expected_map) != canonical(current_map):
        raise RunnerError(
            "preflight dispatch authorization repository map identity mismatch"
        )

    _assert_all_authorized_request_files(binding, request_root)

    condition = request.get("condition")
    requests = binding.get("requests")
    expected_request = requests.get(condition) if isinstance(requests, dict) else None
    if not isinstance(condition, str) or not isinstance(expected_request, dict):
        raise RunnerError("preflight dispatch authorization request binding is missing")
    if expected_request.get("request_id") != request.get(
        "request_id"
    ) or expected_request.get("sha256") != base._sha256_json(request):
        raise RunnerError(
            f"preflight dispatch authorization does not bind this {condition} request"
        )
    return repository_map_bytes


def _preflight_report_evidence_projection(
    report: Mapping[str, Any],
) -> dict[str, Any]:
    projected = json.loads(canonical(report))
    ledger = projected.get("dispatch_ledger")
    if not isinstance(ledger, dict):
        raise RunnerError("preflight report ledger is invalid")
    ledger["authorization_sha256"] = None
    return projected


def _require_g2_preflight_evidence(
    report: Mapping[str, Any], binding: Mapping[str, Any]
) -> None:
    """Accept stale only with an immutable, real isolated G2 preflight proof."""

    frozen = base.FROZEN_G2_IDENTITY
    pair_id = binding.get("pair_id")
    if (
        binding.get("taskset_id") == frozen["taskset_id"]
        and binding.get("taskset_sha256") == frozen["taskset_sha256"]
        and isinstance(pair_id, str)
        and pair_id.startswith(frozen["taskset_id"] + ":" + frozen["case_id"] + ":r")
    ):
        prefix = frozen["taskset_id"] + ":" + frozen["case_id"] + ":r"
        if re.fullmatch(re.escape(prefix) + r"[12]", pair_id) is None:
            raise RunnerError(
                "unsupported frozen G2 pair repetition in preflight proof"
            )
        scenario = report.get("scenario_probe")
        expected = {
            "working_tree": "dirty",
            "fixture": "dirty-checkout",
            "expected_status": "stale",
            "observed_status": "stale",
            "observed_reason": "current_working_tree_is_dirty",
            "git_commit": frozen["repository"]["commit"],
            "fixture_sha256": base._sha256_bytes(base.DIRTY_FIXTURE_BYTES),
            "status_sha256": base._sha256_bytes(
                f"?? {base.DIRTY_FIXTURE_NAME}".encode("utf-8")
            ),
            "source_unchanged_required": True,
            "provider_started": False,
        }
        if (
            not isinstance(scenario, dict)
            or not all(scenario.get(key) == value for key, value in expected.items())
            or not isinstance(scenario.get("mcp_result_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", scenario["mcp_result_sha256"]) is None
            or not isinstance(scenario.get("probe_ms"), int)
            or isinstance(scenario.get("probe_ms"), bool)
            or scenario["probe_ms"] < 0
            or report.get("source_before") != report.get("source_after")
            or not isinstance(report.get("source_before"), dict)
            or report["source_before"].get("clean") is not True
        ):
            raise RunnerError("preflight report lacks bound G2 stale scenario proof")


def _assert_preflight_report_evidence(
    authorization: Mapping[str, Any],
    binding: Mapping[str, Any],
    authorization_path: Path,
) -> None:
    report_evidence_sha256 = authorization.get("report_evidence_sha256")
    if (
        not isinstance(report_evidence_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", report_evidence_sha256) is None
    ):
        raise RunnerError("preflight dispatch authorization report binding is invalid")

    report_text = binding.get("report_out")
    digest_text = binding.get("report_digest_out")
    if not isinstance(report_text, str) or not isinstance(digest_text, str):
        raise RunnerError("preflight report binding is unavailable")
    report_path = Path(report_text)
    digest_path = Path(digest_text)
    if (
        not report_path.is_absolute()
        or not digest_path.is_absolute()
        or digest_path != Path(str(report_path) + ".sha256")
    ):
        raise RunnerError("preflight report binding is invalid")

    report_raw = _read_bound_regular_file(
        report_path,
        label="preflight report",
        max_bytes=MAX_PREFLIGHT_REPORT_BYTES,
    )
    digest_raw = _read_bound_regular_file(
        digest_path,
        label="preflight report digest",
        max_bytes=MAX_PREFLIGHT_REPORT_DIGEST_BYTES,
    )
    for candidate, label in (
        (report_path, "preflight report"),
        (digest_path, "preflight report digest"),
    ):
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise RunnerError(f"{label} disappeared") from exc
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise RunnerError(f"{label} permissions are unsafe")

    expected_digest = f"{sha_bytes(report_raw)}  {report_path.name}\n".encode("ascii")
    if not hmac.compare_digest(digest_raw, expected_digest):
        raise RunnerError("preflight report digest mismatch")

    report = base._load_object_bytes(report_raw, label="preflight report")
    ledger = report.get("dispatch_ledger")
    requests = binding.get("requests")
    expected_request_sha256 = (
        {condition: value.get("sha256") for condition, value in requests.items()}
        if isinstance(requests, dict)
        and set(requests) == {"baseline", "treatment"}
        and all(isinstance(value, dict) for value in requests.values())
        else None
    )
    snapshot = report.get("snapshot")
    authorization_sha256 = base._sha256_json(authorization)
    if (
        report.get("kind") != PREFLIGHT_AUTHORIZATION_REPORT_KIND
        or report.get("version") != "1.0"
        or report.get("status") != "authorized"
        or report.get("pair_id") != binding.get("pair_id")
        or report.get("synthetic_fixture") is not False
        or report.get("default_promoted") is not False
        or expected_request_sha256 is None
        or report.get("request_sha256") != expected_request_sha256
        or canonical(report.get("provider")) != canonical(binding.get("provider"))
        or not isinstance(snapshot, dict)
        or snapshot.get("status") != "fresh"
        or not isinstance(ledger, dict)
        or ledger.get("authorization") != str(authorization_path)
        or ledger.get("authorization_sha256") != authorization_sha256
        or ledger.get("contract_sha256") != authorization.get("contract_sha256")
        or ledger.get("retry_permitted") is not False
    ):
        raise RunnerError("preflight report does not prove this dispatch authorization")

    _require_g2_preflight_evidence(report, binding)
    actual_evidence_sha256 = base._sha256_json(
        _preflight_report_evidence_projection(report)
    )
    if not hmac.compare_digest(actual_evidence_sha256, report_evidence_sha256):
        raise RunnerError("preflight report evidence binding mismatch")


def _load_preflight_dispatch_authorization(
    request: Mapping[str, Any],
    state_root: Path,
    *,
    runtime_binding: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    condition = request.get("condition")
    if condition not in {"baseline", "treatment"}:
        raise RunnerError("preflight dispatch authorization condition is invalid")
    pair_id = request.get("pair_id")
    if not isinstance(pair_id, str) or not pair_id:
        raise RunnerError("preflight dispatch authorization pair ID is invalid")
    pair_digest = hashlib.sha256(pair_id.encode("utf-8")).hexdigest()
    ledger_root = state_root / "preflight-dispatch-ledger"
    pair_root = ledger_root / pair_digest
    _require_private_ledger_directory(ledger_root, label="preflight dispatch ledger")
    _require_private_ledger_directory(pair_root, label="preflight dispatch pair ledger")
    authorization_path = pair_root / "authorization.json"
    raw = _read_bound_regular_file(
        authorization_path,
        label="preflight dispatch authorization",
        max_bytes=MAX_DISPATCH_AUTHORIZATION_BYTES,
    )
    try:
        metadata = authorization_path.lstat()
    except OSError as exc:
        raise RunnerError("preflight dispatch authorization disappeared") from exc
    if metadata.st_mode & 0o077:
        raise RunnerError("preflight dispatch authorization permissions are unsafe")
    authorization = base._load_object_bytes(
        raw, label="preflight dispatch authorization"
    )
    if (
        authorization.get("kind") != PREFLIGHT_LEDGER_KIND
        or authorization.get("version") != PREFLIGHT_LEDGER_VERSION
        or authorization.get("retry_permitted") is not False
    ):
        raise RunnerError("preflight dispatch authorization contract is invalid")
    binding = authorization.get("binding")
    contract_sha256 = authorization.get("contract_sha256")
    if (
        not isinstance(binding, dict)
        or not isinstance(contract_sha256, str)
        or contract_sha256 != base._sha256_json(binding)
    ):
        raise RunnerError("preflight dispatch authorization binding is invalid")
    if binding.get("pair_id") != pair_id or binding.get("state_root") != str(
        state_root.resolve()
    ):
        raise RunnerError(
            "preflight dispatch authorization does not bind this pair/state root"
        )

    requests = binding.get("requests")
    selected = requests.get(condition) if isinstance(requests, dict) else None
    if (
        not isinstance(selected, dict)
        or selected.get("request_id") != request.get("request_id")
        or selected.get("sha256") != base._sha256_json(request)
    ):
        raise RunnerError(
            f"preflight dispatch authorization does not bind this {condition} request"
        )

    _assert_preflight_report_evidence(authorization, binding, authorization_path)

    repository_map_bytes: bytes | None = None
    if runtime_binding is not None:
        required = {
            "request_root",
            "repository_map",
            "transcript_root",
            "evidence_root",
        }
        if set(runtime_binding) != required or not all(
            isinstance(runtime_binding[name], Path) for name in required
        ):
            raise RunnerError("runtime dispatch binding inputs are incomplete")
        repository_map_bytes = _assert_authorized_runtime_binding(
            binding,
            request,
            request_root=runtime_binding["request_root"],
            repository_map=runtime_binding["repository_map"],
            state_root=state_root,
            transcript_root=runtime_binding["transcript_root"],
            evidence_root=runtime_binding["evidence_root"],
        )

    code_files = _validated_authorized_runtime_code(binding.get("code"))
    provider_codex, provider_authentication = _validated_authorized_codex_provider(
        binding.get("provider")
    )
    result: dict[str, Any] = {
        "authorization": dict(authorization),
        "mcp_files": [],
        "proxy_code": None,
        "proxy_base_code": None,
        "manifest": None,
        "provider_codex": provider_codex,
        "provider_authentication": provider_authentication,
        "code_files": [
            dict(code_files[name]) for name in _AUTHORIZED_RUNTIME_CODE_NAMES
        ],
        "binding": dict(binding),
        "repository_map_bytes": repository_map_bytes,
    }
    if condition == "baseline":
        return result

    repobrief = request.get("repobrief")
    if not isinstance(repobrief, dict):
        raise RunnerError("treatment RepoGround binding is invalid")
    command = repobrief.get("mcp_command")
    if binding.get("mcp_command_sha256") != base._sha256_json(command):
        raise RunnerError("preflight dispatch authorization MCP command mismatch")
    manifest = Path(str(repobrief.get("manifest")))
    current_manifest = _runtime_file_identity(
        manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if current_manifest["sha256"] != repobrief.get("manifest_sha256") or canonical(
        binding.get("manifest")
    ) != canonical(current_manifest):
        raise RunnerError("preflight dispatch authorization manifest mismatch")
    result.update(
        {
            "mcp_files": _normalized_authorized_mcp_files(
                binding.get("mcp_command_files")
            ),
            "proxy_code": dict(code_files[Path(__file__).name]),
            "proxy_base_code": dict(code_files[BASE_PATH.name]),
            "manifest": dict(current_manifest),
        }
    )
    return result


def _validated_dispatch_event_state(
    request: Mapping[str, Any], state_root: Path, authorization: Mapping[str, Any]
) -> dict[str, Any]:
    pair_id = str(request["pair_id"])
    pair_root = (
        state_root
        / "preflight-dispatch-ledger"
        / hashlib.sha256(pair_id.encode()).hexdigest()
    )
    events_root = pair_root / "events"
    _require_private_ledger_directory(
        events_root, label="preflight dispatch event ledger"
    )
    entries = sorted(events_root.iterdir(), key=lambda path: path.name)
    # Authorized + two (intent, outcome) pairs + optional pair-failed event.
    if not 1 <= len(entries) <= 6:
        raise RunnerError("preflight dispatch event ledger cardinality is invalid")
    binding = authorization.get("binding")
    contract = authorization.get("contract_sha256")
    if not isinstance(binding, dict) or not isinstance(contract, str):
        raise RunnerError("preflight dispatch authorization binding is invalid")
    report_raw = _read_bound_regular_file(
        Path(str(binding.get("report_out"))),
        label="preflight report",
        max_bytes=MAX_PREFLIGHT_REPORT_BYTES,
    )
    report = base._load_object_bytes(report_raw, label="preflight report")
    ledger = report.get("dispatch_ledger")
    if (
        not isinstance(ledger, dict)
        or ledger.get("event_count") != 1
        or ledger.get("condition_intents") != []
        or ledger.get("provider_process_intents") != 0
        or ledger.get("retry_permitted") is not False
    ):
        raise RunnerError("preflight report initial dispatch ledger is invalid")

    previous = contract
    intents: list[str] = []
    outcomes: dict[str, str] = {}
    terminal_failure = False
    pending_condition: str | None = None
    authorized_sha256: str | None = None
    origin_process_sha256: str | None = None

    def valid_sha256(value: Any) -> bool:
        return (
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
        )

    def valid_transcript(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        status = value.get("status")
        if status == "present":
            byte_count = value.get("bytes")
            return (
                valid_sha256(value.get("sha256"))
                and isinstance(byte_count, int)
                and not isinstance(byte_count, bool)
                and byte_count >= 0
                and isinstance(value.get("artifact"), str)
                and bool(value.get("artifact"))
            )
        if status in {"absent", "unavailable"}:
            reason = value.get("reason")
            return reason is None or isinstance(reason, str)
        return False

    def valid_error(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        size = value.get("error_bytes")
        return (
            isinstance(value.get("error_type"), str)
            and bool(value.get("error_type"))
            and isinstance(size, int)
            and not isinstance(size, bool)
            and size >= 0
            and valid_sha256(value.get("error_sha256"))
        )

    for sequence, event_path in enumerate(entries):
        event = base._load_object_bytes(
            _read_bound_regular_file(
                event_path,
                label="preflight dispatch event",
                max_bytes=MAX_DISPATCH_EVENT_BYTES,
            ),
            label="preflight dispatch event",
        )
        event_type = event.get("event")
        if (
            event_path.name != f"{sequence:04d}-{event_type}.json"
            or event.get("kind") != PREFLIGHT_EVENT_KIND
            or event.get("version") != PREFLIGHT_LEDGER_VERSION
            or event.get("sequence") != sequence
            or event.get("pair_id") != pair_id
            or event.get("contract_sha256") != contract
            or event.get("previous_event_sha256") != previous
        ):
            raise RunnerError("preflight dispatch event chain is invalid")
        event_sha256 = base._sha256_json(event)
        payload = event.get("payload")

        if sequence == 0:
            if (
                event_type != "authorized"
                or not isinstance(payload, dict)
                or payload.get("synthetic_fixture") is not False
                or payload.get("max_provider_processes") != 2
            ):
                raise RunnerError("preflight authorized event is invalid")
            authorized_sha256 = event_sha256
            previous = event_sha256
            continue

        if not isinstance(payload, dict):
            raise RunnerError("preflight dispatch event payload is invalid")
        condition = payload.get("condition")
        expected = binding.get("requests", {}).get(condition)

        if event_type == "dispatch-intent":
            next_process_index = len(intents) + 1
            process_sha256 = payload.get("origin_process_sha256")
            if (
                terminal_failure
                or len(intents) != len(outcomes)
                or condition not in {"baseline", "treatment"}
                or condition in intents
                or not isinstance(expected, dict)
                or payload.get("request_id") != expected.get("request_id")
                or payload.get("request_sha256") != expected.get("sha256")
                or payload.get("process_index") != next_process_index
                or payload.get("order") != next_process_index
                or payload.get("synthetic_fixture") is not False
                or payload.get("max_cost_usd") != binding.get("max_cost_usd")
                or not valid_sha256(process_sha256)
                or (
                    origin_process_sha256 is not None
                    and process_sha256 != origin_process_sha256
                )
            ):
                raise RunnerError("preflight dispatch intent event is invalid")
            if origin_process_sha256 is None:
                origin_process_sha256 = str(process_sha256)
            intents.append(str(condition))
            pending_condition = str(condition)

        elif event_type in {"condition-completed", "condition-failed"}:
            process_index = len(intents)
            observed_cost = payload.get("observed_cost_usd")
            if (
                observed_cost is not None
                or payload.get("observed_cost_status")
                != "not-reported-by-codex-subscription-stream"
            ):
                raise RunnerError("preflight dispatch outcome cost is invalid")
            common_valid = (
                len(intents) == len(outcomes) + 1
                and condition == intents[-1]
                and condition not in outcomes
                and not terminal_failure
                and isinstance(expected, dict)
                and payload.get("request_id") == expected.get("request_id")
                and payload.get("request_sha256") == expected.get("sha256")
                and payload.get("process_index") == process_index
                and payload.get("order") == process_index
                and payload.get("synthetic_fixture") is False
                and isinstance(payload.get("provider_process_started"), bool)
                and isinstance(payload.get("outcome_ambiguous"), bool)
                and valid_transcript(payload.get("transcript"))
                and isinstance(payload.get("observed_cost_status"), str)
                and bool(payload.get("observed_cost_status"))
            )
            if not common_valid:
                raise RunnerError("preflight dispatch outcome event is invalid")

            if event_type == "condition-completed":
                if (
                    payload.get("provider_process_started") is not True
                    or payload.get("outcome_ambiguous") is not False
                    or payload.get("transcript", {}).get("status") != "present"
                    or not valid_sha256(payload.get("receipt_sha256"))
                    or payload.get("error") is not None
                ):
                    raise RunnerError("preflight dispatch completed event is invalid")
            else:
                if (
                    payload.get("outcome_ambiguous")
                    is not payload.get("provider_process_started")
                    or (
                        payload.get("provider_process_started") is False
                        and payload.get("transcript", {}).get("status") == "present"
                    )
                    or payload.get("receipt_sha256") is not None
                    or not valid_error(payload.get("error"))
                ):
                    raise RunnerError("preflight dispatch failed event is invalid")
                terminal_failure = True

            outcomes[str(condition)] = str(event_type)
            pending_condition = None

        elif event_type == "pair-failed":
            # The runner may have completed a condition, while its external
            # receipt validator or cost gate rejects the PAIR afterward.
            # Without this terminal event a second direct dispatch could
            # reuse the same internal authorization.
            if (
                terminal_failure
                or pending_condition is not None
                or not intents
                or len(intents) != len(outcomes)
                or condition != intents[-1]
                or outcomes.get(condition) != "condition-completed"
                or not isinstance(expected, dict)
                or payload.get("request_id") != expected.get("request_id")
                or payload.get("request_sha256") != expected.get("sha256")
                or payload.get("process_index") != len(intents)
                or payload.get("order") != len(intents)
                or payload.get("synthetic_fixture") is not False
                or payload.get("provider_process_started") is not False
                or payload.get("outcome_ambiguous") is not False
                or payload.get("transcript")
                != {"status": "unavailable", "reason": "pair-validation-failed"}
                or payload.get("receipt_sha256") is not None
                or payload.get("observed_cost_usd") is not None
                or payload.get("observed_cost_status")
                != "not-reported-by-codex-subscription-stream"
                or not valid_error(payload.get("error"))
            ):
                raise RunnerError("preflight paired terminal failure event is invalid")
            terminal_failure = True

        else:
            raise RunnerError("preflight dispatch event type is invalid")

        previous = event_sha256

    if authorized_sha256 != ledger.get("final_event_sha256"):
        raise RunnerError("preflight authorized event does not match durable report")
    return {
        "pair_root": pair_root,
        "events_root": events_root,
        "next_sequence": len(entries),
        "previous_event_sha256": previous,
        "condition_intents": intents,
        "condition_outcomes": outcomes,
        "pending_condition": pending_condition,
        "terminal_failure": terminal_failure,
        "origin_process_sha256": origin_process_sha256,
    }


def _record_preflight_dispatch_intent(
    request: Mapping[str, Any],
    state_root: Path,
    authorization: Mapping[str, Any],
    *,
    intent_persisted_callback: Callable[[], None] | None = None,
) -> str:
    pair_id = str(request["pair_id"])
    pair_root = (
        state_root
        / "preflight-dispatch-ledger"
        / hashlib.sha256(pair_id.encode()).hexdigest()
    )
    pair_path, pair_fd = _open_private_directory(pair_root, create_final=False)
    lock_fd: int | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(DISPATCH_INTENT_LOCK_NAME, flags, 0o600, dir_fd=pair_fd)
        lock_stat = os.fstat(lock_fd)
        linked = os.stat(
            DISPATCH_INTENT_LOCK_NAME,
            dir_fd=pair_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
            or lock_stat.st_nlink != 1
            or (lock_stat.st_dev, lock_stat.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RunnerError("preflight dispatch intent lock is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _directory_fd_matches(pair_path, pair_fd)
        current_raw = _read_bound_regular_file_at(
            pair_fd,
            "authorization.json",
            label="preflight dispatch authorization",
            max_bytes=MAX_DISPATCH_AUTHORIZATION_BYTES,
        )
        current = base._load_object_bytes(
            current_raw, label="preflight dispatch authorization"
        )
        if canonical(current) != canonical(dict(authorization)):
            raise RunnerError("preflight dispatch authorization changed before intent")
        _assert_preflight_report_evidence(
            current,
            current["binding"],
            pair_root / "authorization.json",
        )
        state = _validated_dispatch_event_state(request, state_root, current)
        condition = str(request.get("condition"))
        intents = list(state["condition_intents"])
        if condition in intents:
            raise RunnerError(
                f"preflight dispatch intent already exists for {condition}"
            )
        if state["terminal_failure"]:
            raise RunnerError("preflight dispatch pair is terminal after failure")
        if state["pending_condition"] is not None:
            raise RunnerError("prior dispatch intent has no terminal outcome")
        process_sha256 = _live_dispatch_process_binding(pair_id)
        if intents and state["origin_process_sha256"] != process_sha256:
            raise RunnerError(
                "preflight dispatch pair cannot resume after process restart"
            )
        if len(intents) >= 2:
            raise RunnerError(
                "preflight dispatch ledger refuses a third provider process"
            )
        order = request.get("order")
        expected_order = len(intents) + 1
        if (
            isinstance(order, bool)
            or not isinstance(order, int)
            or order != expected_order
        ):
            raise RunnerError("preflight dispatch order is invalid")

        sequence = int(state["next_sequence"])
        binding = current["binding"]
        event = {
            "kind": PREFLIGHT_EVENT_KIND,
            "version": PREFLIGHT_LEDGER_VERSION,
            "sequence": sequence,
            "event": "dispatch-intent",
            "recorded_at": iso(utc_now()),
            "pair_id": pair_id,
            "contract_sha256": current["contract_sha256"],
            "previous_event_sha256": state["previous_event_sha256"],
            "payload": {
                "condition": condition,
                "request_id": request["request_id"],
                "request_sha256": base._sha256_json(request),
                "process_index": expected_order,
                "order": order,
                "synthetic_fixture": False,
                "max_cost_usd": binding.get("max_cost_usd"),
                "origin_process_sha256": process_sha256,
            },
        }
        events_path, events_fd = _open_private_directory(
            state["events_root"], create_final=False
        )
        try:
            _write_private_dirfd(
                events_fd,
                f"{sequence:04d}-dispatch-intent.json",
                (
                    json.dumps(
                        event,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            if intent_persisted_callback is not None:
                intent_persisted_callback()
            _directory_fd_matches(events_path, events_fd)
        finally:
            os.close(events_fd)
        return base._sha256_json(event)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(pair_fd)


def _dispatch_failure_transcript_evidence(
    request: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    binding = authorization.get("binding")
    if not isinstance(binding, dict):
        return {"status": "unavailable", "reason": "binding-invalid"}
    root = Path(str(binding.get("transcript_root")))
    if not root.is_absolute():
        return {"status": "unavailable", "reason": "transcript-root-invalid"}
    path = root / _provider_artifact_names(request)["stdout"]
    try:
        linked = path.lstat()
    except FileNotFoundError:
        return {"status": "absent", "reason": "not-persisted"}
    except OSError:
        return {"status": "unavailable", "reason": "metadata-unavailable"}
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        return {"status": "unavailable", "reason": "unsafe-artifact"}
    try:
        raw = _read_bound_regular_file(
            path,
            label="preflight dispatch failure transcript",
            max_bytes=MAX_TRANSCRIPT_BYTES,
        )
    except RunnerError:
        return {"status": "unavailable", "reason": "read-failed"}
    return {
        "status": "present",
        "artifact": str(path),
        "bytes": len(raw),
        "sha256": sha_bytes(raw),
    }


def _dispatch_receipt_transcript_evidence(
    receipt_value: Mapping[str, Any],
) -> dict[str, Any]:
    transcript = receipt_value.get("transcript")
    if not isinstance(transcript, dict):
        raise RunnerError("dispatch completion transcript evidence is invalid")
    sha256 = transcript.get("sha256")
    byte_count = transcript.get("bytes")
    artifact = transcript.get("artifact")
    if (
        not isinstance(sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        or isinstance(byte_count, bool)
        or not isinstance(byte_count, int)
        or byte_count < 0
        or not isinstance(artifact, str)
        or not artifact
    ):
        raise RunnerError("dispatch completion transcript evidence is invalid")
    return {
        "status": "present",
        "artifact": artifact,
        "bytes": byte_count,
        "sha256": sha256,
    }


def _dispatch_error_evidence(exc: BaseException) -> dict[str, Any]:
    raw = str(exc).encode("utf-8", errors="replace")
    return {
        "error_type": type(exc).__name__,
        "error_bytes": len(raw),
        "error_sha256": sha_bytes(raw),
    }


def _record_preflight_dispatch_outcome(
    request: Mapping[str, Any],
    state_root: Path,
    authorization: Mapping[str, Any],
    *,
    event_type: str,
    provider_process_started: bool,
    outcome_ambiguous: bool,
    transcript: Mapping[str, Any],
    receipt_sha256: str | None,
    error: Mapping[str, Any] | None,
    observed_cost_usd: str | None = None,
    observed_cost_status: str = "unavailable",
) -> str:
    if event_type not in {"condition-completed", "condition-failed", "pair-failed"}:
        raise RunnerError("preflight dispatch outcome type is invalid")
    pair_id = str(request["pair_id"])
    pair_root = (
        state_root
        / "preflight-dispatch-ledger"
        / hashlib.sha256(pair_id.encode()).hexdigest()
    )
    pair_path, pair_fd = _open_private_directory(pair_root, create_final=False)
    lock_fd: int | None = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(DISPATCH_INTENT_LOCK_NAME, flags, 0o600, dir_fd=pair_fd)
        lock_stat = os.fstat(lock_fd)
        linked = os.stat(
            DISPATCH_INTENT_LOCK_NAME,
            dir_fd=pair_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
            or lock_stat.st_nlink != 1
            or (lock_stat.st_dev, lock_stat.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise RunnerError("preflight dispatch outcome lock is unsafe")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _directory_fd_matches(pair_path, pair_fd)
        current_raw = _read_bound_regular_file_at(
            pair_fd,
            "authorization.json",
            label="preflight dispatch authorization",
            max_bytes=MAX_DISPATCH_AUTHORIZATION_BYTES,
        )
        current = base._load_object_bytes(
            current_raw, label="preflight dispatch authorization"
        )
        if canonical(current) != canonical(dict(authorization)):
            raise RunnerError("preflight dispatch authorization changed before outcome")
        _assert_preflight_report_evidence(
            current,
            current["binding"],
            pair_root / "authorization.json",
        )
        state = _validated_dispatch_event_state(request, state_root, current)
        condition = str(request.get("condition"))
        if state["terminal_failure"]:
            if event_type == "pair-failed":
                return str(state["previous_event_sha256"])
            raise RunnerError("preflight dispatch pair is terminal after failure")
        if event_type == "pair-failed":
            completed = state["condition_intents"]
            if (
                not completed
                or state["pending_condition"] is not None
                or state["condition_outcomes"].get(condition) != "condition-completed"
                or completed[-1] != condition
            ):
                raise RunnerError("paired failure has no completed condition")
        elif state["pending_condition"] != condition:
            raise RunnerError(
                "preflight dispatch outcome has no matching pending intent"
            )
        process_index = len(state["condition_intents"])
        order = request.get("order")
        if (
            isinstance(order, bool)
            or not isinstance(order, int)
            or order != process_index
        ):
            raise RunnerError("preflight dispatch outcome order is invalid")
        sequence = int(state["next_sequence"])
        event = {
            "kind": PREFLIGHT_EVENT_KIND,
            "version": PREFLIGHT_LEDGER_VERSION,
            "sequence": sequence,
            "event": event_type,
            "recorded_at": iso(utc_now()),
            "pair_id": pair_id,
            "contract_sha256": current["contract_sha256"],
            "previous_event_sha256": state["previous_event_sha256"],
            "payload": {
                "condition": condition,
                "request_id": request["request_id"],
                "request_sha256": base._sha256_json(request),
                "process_index": process_index,
                "order": order,
                "synthetic_fixture": False,
                "provider_process_started": provider_process_started,
                "outcome_ambiguous": outcome_ambiguous,
                "transcript": dict(transcript),
                "observed_cost_usd": observed_cost_usd,
                "observed_cost_status": observed_cost_status,
                "receipt_sha256": receipt_sha256,
                "error": None if error is None else dict(error),
            },
        }
        events_path, events_fd = _open_private_directory(
            state["events_root"], create_final=False
        )
        try:
            _write_private_dirfd(
                events_fd,
                f"{sequence:04d}-{event_type}.json",
                (
                    json.dumps(
                        event,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            _directory_fd_matches(events_path, events_fd)
        finally:
            os.close(events_fd)
        return base._sha256_json(event)
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(pair_fd)


def _record_preflight_dispatch_completed(
    request: Mapping[str, Any],
    state_root: Path,
    authorization: Mapping[str, Any],
    receipt_value: Mapping[str, Any],
) -> str:
    return _record_preflight_dispatch_outcome(
        request,
        state_root,
        authorization,
        event_type="condition-completed",
        provider_process_started=True,
        outcome_ambiguous=False,
        transcript=_dispatch_receipt_transcript_evidence(receipt_value),
        receipt_sha256=base._sha256_json(receipt_value),
        error=None,
        observed_cost_usd=None,
        observed_cost_status="not-reported-by-codex-subscription-stream",
    )


def _record_preflight_dispatch_failed(
    request: Mapping[str, Any],
    state_root: Path,
    authorization: Mapping[str, Any],
    exc: BaseException,
    *,
    provider_process_started: bool,
) -> str:
    return _record_preflight_dispatch_outcome(
        request,
        state_root,
        authorization,
        event_type="condition-failed",
        provider_process_started=provider_process_started,
        outcome_ambiguous=provider_process_started,
        transcript=_dispatch_failure_transcript_evidence(request, authorization),
        receipt_sha256=None,
        error=_dispatch_error_evidence(exc),
        observed_cost_usd=None,
        observed_cost_status="not-reported-by-codex-subscription-stream",
    )


def _record_preflight_dispatch_pair_failed(
    request: Mapping[str, Any],
    state_root: Path,
    authorization: Mapping[str, Any],
    exc: BaseException,
) -> str:
    """One create-only terminal ledger event for post-condition pair failure.

    Serialized under the same trusted dispatch lock as every future intent.
    If the runner already recorded a condition-failed event, the ledger is
    already terminal. No new event is added in that case.
    """
    return _record_preflight_dispatch_outcome(
        request,
        state_root,
        authorization,
        event_type="pair-failed",
        provider_process_started=False,
        outcome_ambiguous=False,
        transcript={"status": "unavailable", "reason": "pair-validation-failed"},
        receipt_sha256=None,
        error=_dispatch_error_evidence(exc),
        observed_cost_usd=None,
        observed_cost_status="not-reported-by-codex-subscription-stream",
    )


def _load_preflight_mcp_authorization(
    request: Mapping[str, Any], state_root: Path
) -> list[dict[str, Any]]:
    return list(
        _load_preflight_dispatch_authorization(request, state_root)["mcp_files"]
    )


def _bind_mcp_file(path: Path, *, label: str, executable: bool) -> dict[str, Any]:
    if not path.is_absolute():
        raise RunnerError(f"{label} path must be absolute")
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise RunnerError(f"{label} must be a regular non-symlink file")
    if executable and linked.st_mode & 0o111 == 0:
        raise RunnerError(f"{label} is not executable")
    if executable and linked.st_mode & 0o7000:
        raise RunnerError(f"{label} executable permissions are unsafe")
    data = _read_bound_regular_file(
        path, label=label, max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES
    )
    after = path.lstat()
    return {
        "path": path,
        "identity": (after.st_dev, after.st_ino, after.st_size, after.st_mode),
        "sha256": sha_bytes(data),
    }


def _revalidate_mcp_file(binding: Mapping[str, Any], *, label: str) -> None:
    current = _bind_mcp_file(
        Path(binding["path"]), label=label, executable=label == "MCP executable"
    )
    if (
        current["identity"] != binding["identity"]
        or current["sha256"] != binding["sha256"]
    ):
        raise RunnerError(f"{label} changed during execution")


def _create_private_stage_directory(
    parent: Path, *, prefix: str, require_empty: bool = False
) -> tuple[Path, int]:
    parent_path, parent_fd = _open_private_directory(parent)
    child_fd: int | None = None
    runtime_name: str | None = None
    try:
        if require_empty and os.listdir(parent_fd):
            raise RunnerError(
                "MCP upstream stage parent already contains a sibling stage"
            )
        for _attempt in range(4):
            candidate = prefix + sha_bytes(os.urandom(32))[:24]
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            runtime_name = candidate
            break
        if runtime_name is None:
            raise RunnerError("could not allocate unique private runtime stage")
        child_fd = os.open(runtime_name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        child = os.fstat(child_fd)
        if child.st_uid != os.geteuid() or stat.S_IMODE(child.st_mode) != 0o700:
            raise RunnerError("private runtime stage permissions are unsafe")
        _directory_fd_matches(parent_path, parent_fd)
        os.fsync(parent_fd)
        return parent_path / runtime_name, child_fd
    except BaseException:
        if child_fd is not None:
            try:
                os.close(child_fd)
            except OSError:
                pass
            child_fd = None
        if runtime_name is not None:
            try:
                os.rmdir(runtime_name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_fd)


def _write_private_relative_file(
    root_fd: int, relative: Path, data: bytes, *, mode: int = 0o600
) -> None:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise RunnerError("private relative artifact path is unsafe")
    descriptor = os.dup(root_fd)
    try:
        for component in relative.parts[:-1]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            metadata = os.fstat(child)
            if (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                os.close(child)
                raise RunnerError("private artifact directory permissions are unsafe")
            os.close(descriptor)
            descriptor = child
        _write_private_dirfd(descriptor, relative.name, data, mode=mode)
    finally:
        os.close(descriptor)


def _manifest_artifact_paths(
    source: Path, raw: bytes
) -> list[tuple[Path, Path, int, str]]:
    document = base._load_object_bytes(raw, label="RepoGround manifest")
    artifacts = document.get("artifacts")
    if artifacts is None:
        artifacts = []
    if not isinstance(artifacts, list):
        raise RunnerError("RepoGround manifest artifacts contract is invalid")
    manifest_source = source.resolve(strict=True)
    root = manifest_source.parent
    result: list[tuple[Path, Path, int, str]] = []
    seen: dict[Path, tuple[int, str]] = {}
    total_bytes = 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise RunnerError("RepoGround manifest artifact entry is invalid")
        raw_path = artifact.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise RunnerError("RepoGround manifest artifact path is invalid")
        expected_bytes = artifact.get("bytes")
        expected_sha256 = artifact.get("sha256")
        if (
            isinstance(expected_bytes, bool)
            or not isinstance(expected_bytes, int)
            or expected_bytes < 0
            or expected_bytes > MAX_PROVIDER_EXECUTABLE_BYTES
            or not isinstance(expected_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
        ):
            raise RunnerError("RepoGround manifest artifact identity is invalid")
        relative = Path(raw_path)
        if (
            relative.is_absolute()
            or not relative.parts
            or any(part == ".." for part in relative.parts)
        ):
            raise RunnerError(
                "RepoGround manifest artifact path is not safely stageable"
            )
        candidate = root / relative
        try:
            normalized = candidate.resolve(strict=False).relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise RunnerError(
                "RepoGround manifest artifact path escapes the bundle root"
            ) from exc
        if normalized != relative:
            raise RunnerError(
                "RepoGround manifest artifact path changes through filesystem indirection"
            )
        if candidate.resolve(strict=False) == manifest_source:
            raise RunnerError(
                "RepoGround manifest cannot declare itself as an artifact"
            )
        identity = (expected_bytes, expected_sha256)
        previous_identity = seen.get(relative)
        if previous_identity is not None:
            if previous_identity != identity:
                raise RunnerError(
                    "RepoGround manifest artifact path has conflicting identities"
                )
            continue
        if len(result) >= MAX_MCP_MANIFEST_ARTIFACTS:
            raise RunnerError("RepoGround manifest artifact count exceeds its budget")
        total_bytes += expected_bytes
        if total_bytes > MAX_MCP_MANIFEST_ARTIFACT_BYTES:
            raise RunnerError(
                "RepoGround manifest artifacts exceed their aggregate byte budget"
            )
        seen[relative] = identity
        result.append((relative, candidate, expected_bytes, expected_sha256))
    return result


def _stage_code_source(
    source: Path, expected_code: Mapping[str, Any], *, label: str
) -> bytes:
    raw = _read_bound_regular_file(
        source, label=label, max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES
    )
    if (
        expected_code.get("name") != source.name
        or expected_code.get("bytes") != len(raw)
        or expected_code.get("sha256") != sha_bytes(raw)
    ):
        raise RunnerError(f"{label} does not match preflight authorization")
    return raw


def _private_directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid)


def _revalidate_private_stage_tree(
    binding: Mapping[str, Any], file_bindings: Sequence[Mapping[str, Any]]
) -> None:
    runtime_dir = Path(binding["runtime_dir"])
    opened_path, descriptor = _open_private_directory(runtime_dir, create_final=False)
    try:
        _directory_fd_matches(opened_path, descriptor)
        current_identity = _private_directory_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    expected_identity = tuple(binding["runtime_identity"])
    if current_identity != expected_identity:
        raise RunnerError("private runtime stage changed during execution")

    expected_files: set[Path] = set()
    expected_directories: set[Path] = set()
    for file_binding in file_bindings:
        candidate = Path(file_binding["path"])
        try:
            relative = candidate.relative_to(runtime_dir)
        except ValueError as exc:
            raise RunnerError("private runtime stage file escapes its root") from exc
        if not relative.parts:
            raise RunnerError("private runtime stage file path is invalid")
        expected_files.add(relative)
        for parent in relative.parents:
            if parent != Path("."):
                expected_directories.add(parent)

    actual_files: set[Path] = set()
    actual_directories: set[Path] = set()
    for directory, dirnames, filenames in os.walk(runtime_dir, followlinks=False):
        root = Path(directory)
        relative_root = root.relative_to(runtime_dir)
        for name in dirnames:
            candidate = root / name
            metadata = candidate.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise RunnerError("private runtime stage directory is unsafe")
            actual_directories.add(relative_root / name)
        for name in filenames:
            candidate = root / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RunnerError("private runtime stage file is unsafe")
            actual_files.add(relative_root / name)

    if actual_files != expected_files or actual_directories != expected_directories:
        raise RunnerError("private runtime stage contains unexpected entries")

    reopened_path, descriptor = _open_private_directory(runtime_dir, create_final=False)
    try:
        _directory_fd_matches(reopened_path, descriptor)
        final_identity = _private_directory_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    if final_identity != expected_identity:
        raise RunnerError("private runtime stage changed during validation")


def stage_mcp_proxy(
    state_root: Path,
    expected_code: Mapping[str, Any],
    expected_base_code: Mapping[str, Any],
) -> dict[str, Any]:
    source = Path(__file__).resolve()
    base_source = BASE_PATH.resolve(strict=True)
    raw = _stage_code_source(source, expected_code, label="Codex MCP proxy source")
    base_raw = _stage_code_source(
        base_source, expected_base_code, label="RepoBrief benchmark base source"
    )
    stage_root: Path | None = None
    stage_fd: int | None = None
    try:
        stage_root, stage_fd = _create_private_stage_directory(
            state_root / "codex-mcp-proxy-runtime", prefix="stage-"
        )
        _write_private_dirfd(stage_fd, source.name, raw)
        _write_private_dirfd(stage_fd, base_source.name, base_raw)
        _directory_fd_matches(stage_root, stage_fd)
        staged = stage_root / source.name
        staged_base = stage_root / base_source.name
        bound = _bind_mcp_file(staged, label="Codex MCP proxy stage", executable=False)
        bound_base = _bind_mcp_file(
            staged_base, label="RepoBrief benchmark base stage", executable=False
        )
        if bound["sha256"] != expected_code.get("sha256"):
            raise RunnerError("staged Codex MCP proxy SHA mismatch")
        if bound_base["sha256"] != expected_base_code.get("sha256"):
            raise RunnerError("staged RepoBrief benchmark base SHA mismatch")
        bound["expected_code"] = dict(expected_code)
        bound["runtime_dir"] = stage_root
        bound["runtime_identity"] = _private_directory_identity(os.fstat(stage_fd))
        bound["base_path"] = bound_base["path"]
        bound["base_identity"] = bound_base["identity"]
        bound["base_sha256"] = bound_base["sha256"]
        bound["expected_base_code"] = dict(expected_base_code)
        return bound
    except BaseException:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
            stage_fd = None
        if stage_root is not None:
            shutil.rmtree(stage_root, ignore_errors=True)
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _revalidate_staged_mcp_proxy(binding: Mapping[str, Any]) -> None:
    current = _bind_mcp_file(
        Path(binding["path"]), label="Codex MCP proxy stage", executable=False
    )
    if (
        current["identity"] != binding["identity"]
        or current["sha256"] != binding["sha256"]
    ):
        raise RunnerError("Codex MCP proxy stage changed during execution")
    current_base = _bind_mcp_file(
        Path(binding["base_path"]),
        label="RepoBrief benchmark base stage",
        executable=False,
    )
    if (
        current_base["identity"] != binding["base_identity"]
        or current_base["sha256"] != binding["base_sha256"]
    ):
        raise RunnerError("RepoBrief benchmark base stage changed during execution")
    _revalidate_private_stage_tree(
        binding,
        (
            {"path": binding["path"]},
            {"path": binding["base_path"]},
        ),
    )


def cleanup_staged_mcp_proxy(binding: Mapping[str, Any]) -> str | None:
    try:
        _revalidate_staged_mcp_proxy(binding)
        runtime_dir = Path(binding["runtime_dir"])
        if (
            Path(binding["path"]).parent != runtime_dir
            or Path(binding["base_path"]).parent != runtime_dir
        ):
            raise RunnerError("Codex MCP proxy runtime binding is inconsistent")
        shutil.rmtree(runtime_dir)
    except BaseException as exc:
        return type(exc).__name__
    return None


def stage_repoground_manifest(
    state_root: Path, expected_manifest: Mapping[str, Any]
) -> dict[str, Any]:
    source = Path(str(expected_manifest.get("path"))).expanduser()
    current, raw = _runtime_file_snapshot(
        source, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if canonical(current) != canonical(dict(expected_manifest)):
        raise RunnerError("RepoGround manifest changed after preflight authorization")
    artifact_paths = _manifest_artifact_paths(source, raw)
    stage_root: Path | None = None
    stage_fd: int | None = None
    try:
        stage_root, stage_fd = _create_private_stage_directory(
            state_root / "repoground-manifest-runtime", prefix="bundle-"
        )
        artifact_bindings: list[dict[str, Any]] = []
        artifact_bytes_staged = 0
        for relative, candidate, expected_bytes, expected_sha256 in artifact_paths:
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise RunnerError("RepoGround bundle artifact is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RunnerError(
                    "RepoGround bundle artifact must be a regular non-symlink file"
                )
            remaining_bytes = MAX_MCP_MANIFEST_ARTIFACT_BYTES - artifact_bytes_staged
            if (
                remaining_bytes < 0
                or metadata.st_size != expected_bytes
                or expected_bytes > remaining_bytes
            ):
                raise RunnerError(
                    "RepoGround bundle artifact size does not match its bounded manifest identity"
                )
            _snapshot, artifact_raw = _runtime_file_snapshot(
                candidate,
                label=f"RepoGround bundle artifact {relative}",
                max_bytes=min(expected_bytes, remaining_bytes),
            )
            if (
                len(artifact_raw) != expected_bytes
                or sha_bytes(artifact_raw) != expected_sha256
            ):
                raise RunnerError(
                    "RepoGround bundle artifact changed after preflight authorization"
                )
            artifact_bytes_staged += len(artifact_raw)
            _write_private_relative_file(stage_fd, relative, artifact_raw)
            staged_artifact = stage_root / relative
            artifact_bound = _bind_mcp_file(
                staged_artifact,
                label=f"staged RepoGround bundle artifact {relative}",
                executable=False,
            )
            artifact_bindings.append(
                {
                    "path": artifact_bound["path"],
                    "identity": artifact_bound["identity"],
                    "sha256": artifact_bound["sha256"],
                }
            )
        manifest_name = source.resolve(strict=True).name
        _write_private_dirfd(stage_fd, manifest_name, raw)
        _directory_fd_matches(stage_root, stage_fd)
        staged = stage_root / manifest_name
        bound = _bind_mcp_file(
            staged, label="RepoGround manifest stage", executable=False
        )
        if bound["sha256"] != expected_manifest.get("sha256"):
            raise RunnerError("staged RepoGround manifest SHA mismatch")
        bound["expected_manifest"] = dict(expected_manifest)
        bound["runtime_dir"] = stage_root
        bound["runtime_identity"] = _private_directory_identity(os.fstat(stage_fd))
        bound["artifact_bindings"] = artifact_bindings
        return bound
    except BaseException:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
            stage_fd = None
        if stage_root is not None:
            shutil.rmtree(stage_root, ignore_errors=True)
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _revalidate_staged_repoground_manifest(binding: Mapping[str, Any]) -> None:
    current = _bind_mcp_file(
        Path(binding["path"]), label="RepoGround manifest stage", executable=False
    )
    if (
        current["identity"] != binding["identity"]
        or current["sha256"] != binding["sha256"]
    ):
        raise RunnerError("RepoGround manifest stage changed during execution")
    for artifact in binding.get("artifact_bindings", []):
        current_artifact = _bind_mcp_file(
            Path(artifact["path"]),
            label="staged RepoGround bundle artifact",
            executable=False,
        )
        if (
            current_artifact["identity"] != artifact["identity"]
            or current_artifact["sha256"] != artifact["sha256"]
        ):
            raise RunnerError(
                "RepoGround bundle artifact stage changed during execution"
            )
    _revalidate_private_stage_tree(
        binding,
        (binding, *binding.get("artifact_bindings", [])),
    )


def cleanup_staged_repoground_manifest(binding: Mapping[str, Any]) -> str | None:
    try:
        _revalidate_staged_repoground_manifest(binding)
        runtime_dir = Path(binding["runtime_dir"])
        if Path(binding["path"]).parent != runtime_dir:
            raise RunnerError("RepoGround manifest runtime binding is inconsistent")
        shutil.rmtree(runtime_dir)
    except BaseException as exc:
        return type(exc).__name__
    return None


def _terminate_git_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait()


def _run_git_bounded_nul_records(
    command: Sequence[str],
    *,
    cwd: Path,
    label: str,
    max_records: int,
    max_bytes: int,
) -> list[bytes]:
    if not command or command[0] != "git" or max_records <= 0 or max_bytes <= 0:
        raise RunnerError(f"{label} bounds are invalid")
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=base._git_environment(),
            start_new_session=True,
        )
    except OSError as exc:
        raise RunnerError(f"{label} could not be started") from exc
    if process.stdout is None or process.stderr is None:
        _terminate_git_process_group(process)
        raise RunnerError(f"{label} pipes are unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    pending = bytearray()
    stderr = bytearray()
    records: list[bytes] = []
    stdout_bytes = 0
    deadline = time.monotonic() + 120
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_git_process_group(process)
                raise RunnerError(f"{label} timed out")
            for key, _mask in selector.select(timeout=min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr.extend(chunk)
                    if len(stderr) > MAX_STDERR_BYTES:
                        _terminate_git_process_group(process)
                        raise RunnerError(f"{label} stderr exceeds its bound")
                    continue
                stdout_bytes += len(chunk)
                if stdout_bytes > max_bytes:
                    _terminate_git_process_group(process)
                    raise RunnerError(f"{label} exceeds its byte budget")
                pending.extend(chunk)
                while True:
                    marker = pending.find(0)
                    if marker < 0:
                        break
                    record = bytes(pending[:marker])
                    del pending[: marker + 1]
                    if not record:
                        _terminate_git_process_group(process)
                        raise RunnerError(f"{label} emitted an empty record")
                    records.append(record)
                    if len(records) > max_records:
                        _terminate_git_process_group(process)
                        raise RunnerError(f"{label} exceeds its file budget")
        returncode = process.wait(timeout=5)
        if pending:
            raise RunnerError(f"{label} emitted an unterminated record")
        if returncode != 0:
            raise RunnerError(f"{label} command failed")
        return records
    finally:
        selector.close()
        if process.poll() is None:
            _terminate_git_process_group(process)
        process.stdout.close()
        process.stderr.close()


def _git_index_differs_from_commit(
    commit: str, *, source_root: Path, launcher_relative: Path
) -> bool:
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "diff-index",
                "--cached",
                "--quiet",
                commit,
                "--",
                "merger",
                str(launcher_relative),
            ],
            cwd=source_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            env=base._git_environment(),
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError("RepoGround MCP source index cannot be verified") from exc
    if completed.returncode == 0:
        return False
    if completed.returncode == 1:
        return True
    raise RunnerError("RepoGround MCP source index cannot be verified")


def _frozen_g1_vendor_snapshot() -> list[dict[str, Any]]:
    """Attest every byte of the historical-only isolated dependency tree."""
    entries: list[dict[str, Any]] = []
    roots = [
        (FROZEN_G1_VENDOR_SITE_ROOT / package, FROZEN_G1_VENDOR_SITE_ROOT)
        for package in FROZEN_G1_VENDOR_PACKAGES
    ]
    roots.append((FROZEN_G1_VENDOR_TYPING_EXT, FROZEN_G1_VENDOR_TYPING_EXT.parent))
    total_bytes = 0
    for source, base in roots:
        if source.is_symlink() or not source.exists():
            raise RunnerError("historical G1 vendor source is unavailable or linked")
        candidates = sorted(source.rglob("*")) if source.is_dir() else [source]
        for candidate in candidates:
            if candidate.suffix not in {".py", ".json", ".so"}:
                continue
            relative = candidate.relative_to(base)
            if (
                any(part in {"", ".", ".."} for part in relative.parts)
                or candidate.is_symlink()
            ):
                raise RunnerError("historical G1 vendor path is unsafe")
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise RunnerError("historical G1 vendor file is unavailable") from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o7022
                or metadata.st_size <= 0
                and candidate.suffix != ".py"
            ):
                raise RunnerError("historical G1 vendor metadata is unsafe")
            remaining = MAX_FROZEN_G1_VENDOR_BYTES - total_bytes
            if (
                len(entries) >= MAX_FROZEN_G1_VENDOR_FILES
                or metadata.st_size > remaining
            ):
                raise RunnerError("historical G1 vendor source exceeds bounds")
            raw = _read_bound_regular_file(
                candidate,
                label="historical G1 frozen dependency",
                max_bytes=remaining,
            )
            total_bytes += len(raw)
            entries.append(
                {
                    "relative": relative,
                    "raw": raw,
                    "sha256": sha_bytes(raw),
                }
            )
    entries.sort(key=lambda entry: str(entry["relative"]))
    paths = [str(entry["relative"]) for entry in entries]
    if len(paths) != len(set(paths)):
        raise RunnerError("historical G1 vendor source has duplicate paths")
    digest = sha_bytes(
        canonical(
            [
                {
                    "p": str(entry["relative"]),
                    "n": len(entry["raw"]),
                    "h": entry["sha256"],
                }
                for entry in entries
            ]
        ).encode("utf-8")
    )
    if not hmac.compare_digest(digest, FROZEN_G1_VENDOR_MANIFEST_SHA256):
        raise RunnerError("historical G1 vendor source digest is not frozen")
    return entries


def _repoground_source_tree_snapshot(
    script: Path, manifest_raw: bytes, *, legacy_g1: bool = False
) -> dict[str, Any] | None:
    if legacy_g1:
        if script.name != "repobrief-mcp-stdio.py":
            raise RunnerError("historical G1 MCP launcher name is invalid")
    elif script.name != "repoground-mcp-stdio.py":
        return None
    document = base._load_object_bytes(manifest_raw, label="RepoGround manifest")
    generator = document.get("generator")
    runtime = generator.get("runtime") if isinstance(generator, dict) else None
    commit = runtime.get("git_commit") if isinstance(runtime, dict) else None
    if (
        not isinstance(commit, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None
        or runtime.get("git_dirty") is not False
    ):
        raise RunnerError("RepoGround manifest generator commit is invalid")
    if legacy_g1:
        frozen = FROZEN_G1_LEGACY_IDENTITY
        if (
            not hmac.compare_digest(sha_bytes(manifest_raw), frozen["manifest_sha256"])
            or commit != frozen["generator_commit"]
            or runtime.get("module") != "merger.lenskit.core.merge"
        ):
            raise RunnerError("historical G1 bundle generator identity is invalid")
        # The historical snapshot's source commit and generator commit differ
        # intentionally. Verify both rather than substituting a newer server.
        commit = frozen["repository"]["commit"]
    try:
        source_root = script.resolve(strict=True).parent.parent
    except OSError as exc:
        raise RunnerError("RepoGround MCP source root is unavailable") from exc
    try:
        object_format = base._run_checked(
            ["git", "-c", "core.fsmonitor=false", "rev-parse", "--show-object-format"],
            cwd=source_root,
        )
    except base.RunnerError as exc:
        raise RunnerError("RepoGround MCP source checkout is unavailable") from exc
    if object_format not in {"sha1", "sha256"}:
        raise RunnerError("RepoGround MCP generator object format is unsupported")
    oid_length = 40 if object_format == "sha1" else 64
    if len(commit) != oid_length:
        raise RunnerError(
            "RepoGround manifest generator commit does not match source object format"
        )

    launcher_relative = Path(
        "scripts/repobrief-mcp-stdio.py"
        if legacy_g1
        else "scripts/repoground-mcp-stdio.py"
    )

    def verify_source() -> None:
        try:
            git_root = Path(
                base._run_checked(
                    [
                        "git",
                        "-c",
                        "core.fsmonitor=false",
                        "rev-parse",
                        "--show-toplevel",
                    ],
                    cwd=source_root,
                )
            ).resolve(strict=True)
            head = base._run_checked(
                ["git", "-c", "core.fsmonitor=false", "rev-parse", "HEAD"],
                cwd=source_root,
            )
        except (base.RunnerError, OSError) as exc:
            raise RunnerError("RepoGround MCP source checkout is unavailable") from exc
        if git_root != source_root:
            raise RunnerError("RepoGround MCP source root is not the Git checkout root")
        if head != commit:
            raise RunnerError(
                "RepoGround MCP source commit does not match the bundle generator commit"
            )
        index_changes = _git_index_differs_from_commit(
            commit,
            source_root=source_root,
            launcher_relative=launcher_relative,
        )
        untracked = _run_git_bounded_nul_records(
            [
                "git",
                "-c",
                "core.fsmonitor=false",
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "merger",
                str(launcher_relative),
            ],
            cwd=source_root,
            label="RepoGround MCP untracked source enumeration",
            max_records=MAX_MCP_SOURCE_TREE_FILES + 1,
            max_bytes=MAX_MCP_SOURCE_TREE_LISTING_BYTES,
        )
        if index_changes or untracked:
            raise RunnerError("RepoGround MCP source checkout is dirty")

    try:
        if script.resolve(strict=True) != (source_root / launcher_relative).resolve(
            strict=True
        ):
            raise RunnerError("RepoGround MCP launcher path is invalid")
    except OSError as exc:
        raise RunnerError("RepoGround MCP launcher is unavailable") from exc

    verify_source()
    tracked_records = _run_git_bounded_nul_records(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "ls-files",
            "-v",
            "-z",
            "--",
            "merger",
            str(launcher_relative),
        ],
        cwd=source_root,
        label="RepoGround MCP source tree enumeration",
        max_records=MAX_MCP_SOURCE_TREE_FILES + 1,
        max_bytes=MAX_MCP_SOURCE_TREE_LISTING_BYTES,
    )
    try:
        tracked_entries = [item.decode("utf-8") for item in tracked_records]
    except UnicodeDecodeError as exc:
        raise RunnerError("RepoGround MCP source tree path is not UTF-8") from exc
    if any(
        len(item) < 3 or item[1] != " " or item[0] != "H" for item in tracked_entries
    ):
        raise RunnerError("RepoGround MCP source tree index flags are unsafe")
    tracked_relatives = [Path(item[2:]) for item in tracked_entries]
    relatives = [
        relative
        for relative in tracked_relatives
        if relative.parts and relative.parts[0] == "merger"
    ]
    required = Path(
        "merger/lenskit/cli/repobrief_mcp_stdio.py"
        if legacy_g1
        else "merger/repoground/cli/mcp_stdio.py"
    )
    if (
        not relatives
        or len(relatives) > MAX_MCP_SOURCE_TREE_FILES
        or required not in relatives
        or launcher_relative not in tracked_relatives
    ):
        raise RunnerError("RepoGround MCP source tree is incomplete")

    committed_tree_records = _run_git_bounded_nul_records(
        [
            "git",
            "-c",
            "core.fsmonitor=false",
            "ls-tree",
            "-rz",
            "--full-tree",
            commit,
            "--",
            "merger",
            str(launcher_relative),
        ],
        cwd=source_root,
        label="RepoGround MCP generator tree enumeration",
        max_records=MAX_MCP_SOURCE_TREE_FILES + 1,
        max_bytes=MAX_MCP_SOURCE_TREE_LISTING_BYTES,
    )
    committed_blobs: dict[Path, str] = {}
    committed_modes: dict[Path, int] = {}
    for raw_item in committed_tree_records:
        try:
            item = raw_item.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RunnerError(
                "RepoGround MCP generator tree path is not UTF-8"
            ) from exc
        metadata, separator, path_text = item.partition("\t")
        fields = metadata.split()
        if (
            separator != "\t"
            or len(fields) != 3
            or fields[0] not in {"100644", "100755"}
            or fields[1] != "blob"
            or re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", fields[2]) is None
            or not path_text
        ):
            raise RunnerError("RepoGround MCP generator tree entry is unsafe")
        relative = Path(path_text)
        if relative in committed_blobs:
            raise RunnerError("RepoGround MCP generator tree contains duplicate paths")
        committed_blobs[relative] = fields[2]
        committed_modes[relative] = 0o700 if fields[0] == "100755" else 0o600
    if set(committed_blobs) != set(tracked_relatives):
        raise RunnerError(
            "RepoGround MCP source tree does not match the generator commit tree"
        )

    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for relative in relatives:
        if (
            relative.is_absolute()
            or not relative.parts
            or relative.parts[0] != "merger"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise RunnerError("RepoGround MCP source tree path is unsafe")
        source = source_root / relative
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise RunnerError("RepoGround MCP source tree file is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise RunnerError("RepoGround MCP source tree file is unsafe")
        remaining_bytes = MAX_MCP_SOURCE_TREE_BYTES - total_bytes
        if remaining_bytes < 0 or metadata.st_size > remaining_bytes:
            raise RunnerError("RepoGround MCP source tree exceeds its byte budget")
        raw = _read_bound_regular_file(
            source,
            label=f"RepoGround MCP source tree file {relative}",
            max_bytes=remaining_bytes,
        )
        git_object = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        blob_oid = (
            hashlib.sha1(git_object).hexdigest()
            if object_format == "sha1"
            else hashlib.sha256(git_object).hexdigest()
        )
        if blob_oid != committed_blobs[relative]:
            raise RunnerError(
                "RepoGround MCP source tree file does not match generator commit"
            )
        total_bytes += len(raw)
        if total_bytes > MAX_MCP_SOURCE_TREE_BYTES:
            raise RunnerError("RepoGround MCP source tree exceeds its byte budget")
        entries.append(
            {
                "relative": relative,
                "raw": raw,
                "sha256": sha_bytes(raw),
                "mode": committed_modes[relative],
            }
        )

    launcher_raw = _read_bound_regular_file(
        script,
        label="RepoGround MCP launcher",
        max_bytes=MAX_MCP_SOURCE_TREE_BYTES,
    )
    launcher_object = (
        b"blob " + str(len(launcher_raw)).encode("ascii") + b"\0" + launcher_raw
    )
    launcher_oid = (
        hashlib.sha1(launcher_object).hexdigest()
        if object_format == "sha1"
        else hashlib.sha256(launcher_object).hexdigest()
    )
    if launcher_oid != committed_blobs[launcher_relative]:
        raise RunnerError("RepoGround MCP launcher does not match generator commit")
    if legacy_g1 and not hmac.compare_digest(
        sha_bytes(launcher_raw), FROZEN_G1_LEGACY_IDENTITY["launcher_sha256"]
    ):
        raise RunnerError("historical G1 MCP launcher bytes differ from frozen source")

    verify_source()
    return {
        "root": source_root,
        "commit": commit,
        "entries": entries,
        "launcher": {
            "raw": launcher_raw,
            "sha256": sha_bytes(launcher_raw),
            "mode": committed_modes[launcher_relative],
        },
        "file_count": len(entries),
        "total_bytes": total_bytes,
    }


def _bind_mcp_upstream(
    upstream: Sequence[str],
    manifest: Path,
    authorized_files: Sequence[Mapping[str, Any]],
) -> tuple[list[str], list[dict[str, Any]], dict[str, Any] | None]:
    executable = Path(upstream[0])
    if not executable.is_absolute():
        resolved = shutil.which(upstream[0], path=provider_env().get("PATH"))
        if resolved is None:
            raise RunnerError("MCP executable is unavailable")
        executable = Path(resolved)
    try:
        executable = executable.resolve(strict=True)
    except OSError as exc:
        raise RunnerError("MCP executable is unavailable") from exc
    executable_binding = _bind_mcp_file(
        executable, label="MCP executable", executable=True
    )
    expected = _normalized_authorized_mcp_files(list(authorized_files))
    argv = [str(executable), *upstream[1:]]
    bindings = [executable_binding]
    if len(argv) > 1 and Path(executable).name.startswith("python"):
        script = Path(argv[1]).expanduser()
        if not script.is_absolute():
            if len(expected) < 2:
                raise RunnerError(
                    "relative MCP script lacks a preflight-authorized file identity"
                )
            authorized_script = Path(expected[1]["path"])
            relative_parts = script.parts
            if (
                not relative_parts
                or ".." in relative_parts
                or tuple(authorized_script.parts[-len(relative_parts) :])
                != relative_parts
            ):
                raise RunnerError(
                    "relative MCP script does not match preflight-authorized path"
                )
            script = authorized_script
        try:
            script = script.resolve(strict=True)
        except OSError as exc:
            raise RunnerError("MCP script is unavailable") from exc
        script_binding = _bind_mcp_file(script, label="MCP script", executable=False)
        argv[1] = str(script)
        bindings.append(script_binding)
    if "--bundle-root" not in argv:
        raise RunnerError("MCP upstream must declare --bundle-root")
    index = argv.index("--bundle-root")
    if index + 1 >= len(argv) or argv.count("--bundle-root") != 1:
        raise RunnerError("MCP upstream bundle root is invalid")
    current = [_mcp_authorization_identity(binding) for binding in bindings]
    manifest_authorization: dict[str, Any] | None = None
    if canonical(current) != canonical(expected):
        program_expected = expected[: len(current)]
        manifest_expected = expected[len(current) :]
        bundle_source = Path(argv[index + 1]).expanduser().resolve(strict=False)
        if (
            canonical(current) != canonical(program_expected)
            or len(manifest_expected) != 1
            or manifest_expected[0]["path"] != str(bundle_source)
        ):
            raise RunnerError(
                "MCP program does not match preflight-authorized file identities"
            )
        current_manifest = _mcp_authorization_identity(
            _bind_mcp_file(
                manifest,
                label="staged MCP bundle manifest",
                executable=False,
            )
        )
        if canonical(current_manifest) != canonical(manifest_expected[0]):
            raise RunnerError(
                "MCP bundle manifest does not match preflight-authorized file identity"
            )
        manifest_authorization = dict(current_manifest)
    argv[index + 1] = str(manifest)
    return argv, bindings, manifest_authorization


def stage_mcp_upstream(
    state_root: Path,
    upstream: Sequence[str],
    manifest: Path,
    authorized_files: Sequence[Mapping[str, Any]],
    *,
    legacy_g1: bool = False,
) -> dict[str, Any]:
    bound_argv, source_bindings, manifest_authorization = _bind_mcp_upstream(
        upstream, manifest, authorized_files
    )
    manifest_snapshot, manifest_raw = _runtime_file_snapshot(
        manifest,
        label="RepoGround manifest",
        max_bytes=MAX_MANIFEST_BYTES,
    )
    if manifest_authorization is not None and canonical(manifest_snapshot) != canonical(
        manifest_authorization
    ):
        raise RunnerError("MCP bundle manifest changed before private staging")
    manifest_artifacts = _manifest_artifact_paths(manifest, manifest_raw)
    source_tree = (
        _repoground_source_tree_snapshot(
            Path(source_bindings[1]["path"]), manifest_raw, legacy_g1=legacy_g1
        )
        if len(source_bindings) > 1
        else None
    )
    vendor_entries = _frozen_g1_vendor_snapshot() if legacy_g1 else []
    stage_root: Path | None = None
    stage_fd: int | None = None
    try:
        stage_root, stage_fd = _create_private_stage_directory(
            state_root / "repoground-mcp-upstream-runtime",
            prefix="upstream-",
            require_empty=True,
        )
        staged_argv = list(bound_argv)
        staged_bindings: list[dict[str, Any]] = []
        for index, source_binding in enumerate(source_bindings):
            label = "MCP executable" if index == 0 else "MCP script"
            source = Path(source_binding["path"])
            if index == 1 and source_tree is not None:
                launcher = source_tree.get("launcher")
                if not isinstance(launcher, Mapping):
                    raise RunnerError("RepoGround MCP launcher snapshot is invalid")
                raw = launcher.get("raw")
                stage_mode = launcher.get("mode")
                if (
                    not isinstance(raw, bytes)
                    or stage_mode not in {0o600, 0o700}
                    or launcher.get("sha256") != sha_bytes(raw)
                ):
                    raise RunnerError("RepoGround MCP launcher snapshot is invalid")
                if sha_bytes(raw) != source_binding["sha256"]:
                    raise RunnerError(
                        "preflight-authorized MCP launcher does not match generator commit"
                    )
            else:
                raw = _read_bound_regular_file(
                    source, label=label, max_bytes=MAX_PROVIDER_EXECUTABLE_BYTES
                )
                current = _bind_mcp_file(source, label=label, executable=index == 0)
                if (
                    current["identity"] != source_binding["identity"]
                    or current["sha256"] != source_binding["sha256"]
                    or sha_bytes(raw) != source_binding["sha256"]
                ):
                    raise RunnerError(f"{label} changed before private staging")
                stage_mode = 0o700 if index == 0 else 0o600
            relative = Path("executable" if index == 0 else "script") / source.name
            _write_private_relative_file(
                stage_fd,
                relative,
                raw,
                mode=stage_mode,
            )
            staged_path = stage_root / relative
            staged = _bind_mcp_file(
                staged_path,
                label=f"staged {label}",
                executable=index == 0,
            )
            if (
                staged["sha256"] != source_binding["sha256"]
                or stat.S_IMODE(int(staged["identity"][3])) != stage_mode
            ):
                raise RunnerError(f"staged {label} binding mismatch")
            staged_bindings.append(staged)
            staged_argv[index] = str(staged_path)

        manifest_relative = Path("manifest") / Path(str(manifest_snapshot["path"])).name
        _write_private_relative_file(
            stage_fd,
            manifest_relative,
            manifest_raw,
            mode=0o600,
        )
        staged_manifest_path = stage_root / manifest_relative
        staged_manifest_binding = _bind_mcp_file(
            staged_manifest_path,
            label="staged MCP bundle manifest",
            executable=False,
        )
        if staged_manifest_binding["sha256"] != manifest_snapshot["sha256"]:
            raise RunnerError("staged MCP bundle manifest SHA mismatch")

        manifest_artifact_bindings: list[dict[str, Any]] = []
        manifest_artifact_bytes_staged = 0
        for relative, candidate, expected_bytes, expected_sha256 in manifest_artifacts:
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                raise RunnerError("MCP bundle artifact is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RunnerError(
                    "MCP bundle artifact must be a regular non-symlink file"
                )
            remaining_bytes = (
                MAX_MCP_MANIFEST_ARTIFACT_BYTES - manifest_artifact_bytes_staged
            )
            if (
                remaining_bytes < 0
                or metadata.st_size != expected_bytes
                or expected_bytes > remaining_bytes
            ):
                raise RunnerError(
                    "MCP bundle artifact size does not match its bounded manifest identity"
                )
            _snapshot, artifact_raw = _runtime_file_snapshot(
                candidate,
                label=f"MCP bundle artifact {relative}",
                max_bytes=min(expected_bytes, remaining_bytes),
            )
            if (
                len(artifact_raw) != expected_bytes
                or sha_bytes(artifact_raw) != expected_sha256
            ):
                raise RunnerError("MCP bundle artifact changed before private staging")
            manifest_artifact_bytes_staged += len(artifact_raw)
            staged_relative = Path("manifest") / relative
            _write_private_relative_file(
                stage_fd,
                staged_relative,
                artifact_raw,
                mode=0o600,
            )
            staged_artifact = _bind_mcp_file(
                stage_root / staged_relative,
                label=f"staged MCP bundle artifact {relative}",
                executable=False,
            )
            if staged_artifact["sha256"] != expected_sha256:
                raise RunnerError("staged MCP bundle artifact SHA mismatch")
            manifest_artifact_bindings.append(staged_artifact)

        bundle_index = staged_argv.index("--bundle-root")
        staged_argv[bundle_index + 1] = str(staged_manifest_path)

        source_tree_bindings: list[dict[str, Any]] = []
        if source_tree is not None:
            for entry in source_tree["entries"]:
                relative = entry["relative"]
                raw = entry["raw"]
                stage_mode = entry.get("mode")
                if stage_mode not in {0o600, 0o700}:
                    raise RunnerError("RepoGround MCP source stage mode is invalid")
                _write_private_relative_file(stage_fd, relative, raw, mode=stage_mode)
                staged_path = stage_root / relative
                staged = _bind_mcp_file(
                    staged_path,
                    label=f"staged RepoGround MCP source {relative}",
                    executable=stage_mode == 0o700,
                )
                if (
                    staged["sha256"] != entry["sha256"]
                    or stat.S_IMODE(int(staged["identity"][3])) != stage_mode
                ):
                    raise RunnerError("staged RepoGround MCP source binding mismatch")
                source_tree_bindings.append(staged)
            if Path(staged_argv[0]).name.startswith("python"):
                if legacy_g1:
                    for entry in vendor_entries:
                        relative = Path("vendor") / entry["relative"]
                        _write_private_relative_file(
                            stage_fd, relative, entry["raw"], mode=0o600
                        )
                        staged = _bind_mcp_file(
                            stage_root / relative,
                            label=f"staged historical G1 dependency {relative}",
                            executable=False,
                        )
                        if staged["sha256"] != entry["sha256"]:
                            raise RunnerError(
                                "historical G1 staged dependency digest changed"
                            )
                        source_tree_bindings.append(staged)
                    # -I continues excluding all ambient user site packages.
                    # Only this hash-bound private snapshot enters sys.path.
                    if len(staged_argv) != 6 or not vendor_entries:
                        raise RunnerError("historical G1 isolated launcher is invalid")
                    staged_script = staged_argv[1]
                    entry_code = (
                        "import sys,runpy;"
                        "vendor=sys.argv.pop(1);"
                        "script=sys.argv.pop(1);"
                        "sys.path.insert(0,vendor);"
                        "runpy.run_path(script,run_name='__main__')"
                    )
                    staged_argv[1:2] = [
                        "-I",
                        "-B",
                        "-c",
                        entry_code,
                        str(stage_root / "vendor"),
                        staged_script,
                    ]
                else:
                    staged_argv[1:1] = ["-I", "-B"]

        _directory_fd_matches(stage_root, stage_fd)
        stage: dict[str, Any] = {
            "argv": staged_argv,
            "bindings": staged_bindings,
            "manifest_binding": staged_manifest_binding,
            "manifest_artifact_bindings": manifest_artifact_bindings,
            "source_tree": (
                None
                if source_tree is None
                else {
                    "root": str(source_tree["root"]),
                    "commit": source_tree["commit"],
                    "file_count": source_tree["file_count"],
                    "total_bytes": source_tree["total_bytes"],
                }
            ),
            "source_tree_bindings": source_tree_bindings,
            "runtime_dir": stage_root,
            "runtime_identity": _private_directory_identity(os.fstat(stage_fd)),
        }
        # The hostile provider receives a small immutable reference, never
        # thousands of source_tree_bindings inside one Codex -c argument.
        metadata_raw = canonical(_mcp_stage_wire(stage)).encode("utf-8")
        if len(metadata_raw) > MAX_MCP_STAGE_METADATA_BYTES:
            raise RunnerError("MCP stage metadata exceeds its pre-intent byte budget")
        metadata_relative = Path(MCP_STAGE_METADATA_NAME)
        _write_private_relative_file(
            stage_fd, metadata_relative, metadata_raw, mode=0o600
        )
        metadata_binding = _bind_mcp_file(
            stage_root / metadata_relative,
            label="MCP stage metadata",
            executable=False,
        )
        if metadata_binding["sha256"] != sha_bytes(metadata_raw):
            raise RunnerError("MCP stage metadata changed during preparation")
        stage["metadata_binding"] = metadata_binding
        _directory_fd_matches(stage_root, stage_fd)
        _require_unique_mcp_stage(stage_root)
        return stage
    except BaseException:
        if stage_fd is not None:
            try:
                os.close(stage_fd)
            except OSError:
                pass
            stage_fd = None
        if stage_root is not None:
            shutil.rmtree(stage_root, ignore_errors=True)
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)


def _read_bound_mcp_stage_metadata(binding: Mapping[str, Any]) -> bytes:
    """Read one create-only stage record through a bounded non-symlink path."""
    if not isinstance(binding, Mapping) or set(binding) != {
        "path",
        "identity",
        "sha256",
    }:
        raise RunnerError("MCP stage metadata reference is invalid")
    # The trusted parent holds Paths; the serialized child reference uses str.
    path_text = binding["path"]
    if isinstance(path_text, Path):
        path_text = str(path_text)
    identity = binding["identity"]
    expected_sha = binding["sha256"]
    if (
        not isinstance(path_text, str)
        or not Path(path_text).is_absolute()
        or Path(path_text).name != MCP_STAGE_METADATA_NAME
        or not isinstance(identity, (tuple, list))
        or len(identity) != 4
        or any(type(number) is not int for number in identity)
        or not isinstance(expected_sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None
    ):
        raise RunnerError("MCP stage metadata reference is invalid")
    path = Path(path_text)
    if os.path.normpath(path_text) != path_text:
        raise RunnerError("MCP stage metadata path is not normalized")
    try:
        linked = path.lstat()
    except OSError as exc:
        raise RunnerError("MCP stage metadata is unavailable") from exc
    if (
        not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or linked.st_nlink != 1
        or stat.S_IMODE(linked.st_mode) != 0o600
        or linked.st_size < 0
        or linked.st_size > MAX_MCP_STAGE_METADATA_BYTES
    ):
        raise RunnerError("MCP stage metadata is unsafe or exceeds its bound")
    raw = _read_bound_regular_file(
        path, label="MCP stage metadata", max_bytes=MAX_MCP_STAGE_METADATA_BYTES
    )
    after = path.lstat()
    actual = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
    if (
        actual != tuple(identity)
        or (linked.st_dev, linked.st_ino, linked.st_size, linked.st_mode) != actual
        or sha_bytes(raw) != expected_sha
    ):
        raise RunnerError("MCP stage metadata identity or digest mismatch")
    return raw


def _require_unique_mcp_stage(stage_root: Path) -> None:
    """Reject a valid but stale sibling selected through untrusted Codex argv."""
    if (
        not stage_root.is_absolute()
        or os.path.normpath(str(stage_root)) != str(stage_root)
        or stage_root.parent.name != "repoground-mcp-upstream-runtime"
        or re.fullmatch(r"upstream-[0-9a-f]{24}", stage_root.name) is None
    ):
        raise RunnerError("MCP upstream stage path is invalid")
    parent, fd = _open_private_directory(stage_root.parent, create_final=False)
    try:
        _directory_fd_matches(parent, fd)
        try:
            names = os.listdir(fd)
        except OSError as exc:
            raise RunnerError("MCP upstream sibling enumeration failed") from exc
        if names != [stage_root.name]:
            raise RunnerError(
                "MCP upstream runtime contains a sibling or unexpected stage"
            )
        _directory_fd_matches(parent, fd)
    finally:
        os.close(fd)


def _revalidate_staged_mcp_upstream(binding: Mapping[str, Any]) -> None:
    _require_unique_mcp_stage(Path(binding["runtime_dir"]))
    bindings = binding.get("bindings")
    manifest_binding = binding.get("manifest_binding")
    manifest_artifact_bindings = binding.get("manifest_artifact_bindings")
    source_tree_bindings = binding.get("source_tree_bindings")
    metadata_binding = binding.get("metadata_binding")
    if (
        not isinstance(metadata_binding, Mapping)
        or not isinstance(bindings, list)
        or not bindings
        or not isinstance(manifest_binding, Mapping)
        or not isinstance(manifest_artifact_bindings, list)
        or not isinstance(source_tree_bindings, list)
    ):
        raise RunnerError("staged MCP upstream binding is invalid")
    if Path(str(metadata_binding.get("path"))) != (
        Path(binding["runtime_dir"]) / MCP_STAGE_METADATA_NAME
    ):
        raise RunnerError("MCP stage metadata escaped its private runtime root")
    raw = _read_bound_mcp_stage_metadata(metadata_binding)
    stage_without_reference = {
        key: value for key, value in binding.items() if key != "metadata_binding"
    }
    if raw != canonical(_mcp_stage_wire(stage_without_reference)).encode("utf-8"):
        raise RunnerError("MCP stage metadata content differs from parent binding")
    for index, file_binding in enumerate(bindings):
        label = "MCP executable" if index == 0 else "MCP script"
        current = _bind_mcp_file(
            Path(file_binding["path"]),
            label=f"staged {label}",
            executable=index == 0,
        )
        if (
            tuple(current["identity"]) != tuple(file_binding["identity"])
            or current["sha256"] != file_binding["sha256"]
        ):
            raise RunnerError(f"staged {label} changed during execution")
    current_manifest = _bind_mcp_file(
        Path(manifest_binding["path"]),
        label="staged MCP bundle manifest",
        executable=False,
    )
    if (
        tuple(current_manifest["identity"]) != tuple(manifest_binding["identity"])
        or current_manifest["sha256"] != manifest_binding["sha256"]
    ):
        raise RunnerError("staged MCP bundle manifest changed during execution")
    for file_binding in manifest_artifact_bindings:
        current = _bind_mcp_file(
            Path(file_binding["path"]),
            label="staged MCP bundle artifact",
            executable=False,
        )
        if (
            tuple(current["identity"]) != tuple(file_binding["identity"])
            or current["sha256"] != file_binding["sha256"]
        ):
            raise RunnerError("staged MCP bundle artifact changed during execution")
    for file_binding in source_tree_bindings:
        current = _bind_mcp_file(
            Path(file_binding["path"]),
            label="staged RepoGround MCP source",
            executable=False,
        )
        if (
            tuple(current["identity"]) != tuple(file_binding["identity"])
            or current["sha256"] != file_binding["sha256"]
        ):
            raise RunnerError("staged RepoGround MCP source changed during execution")
    _revalidate_private_stage_tree(
        binding,
        [
            *bindings,
            manifest_binding,
            *manifest_artifact_bindings,
            *source_tree_bindings,
            metadata_binding,
        ],
    )
    _require_unique_mcp_stage(Path(binding["runtime_dir"]))


def cleanup_staged_mcp_upstream(binding: Mapping[str, Any]) -> str | None:
    try:
        _revalidate_staged_mcp_upstream(binding)
        runtime_dir = Path(binding["runtime_dir"])
        for file_binding in [
            *binding["bindings"],
            binding["manifest_binding"],
            *binding["manifest_artifact_bindings"],
            *binding["source_tree_bindings"],
            binding["metadata_binding"],
        ]:
            Path(file_binding["path"]).relative_to(runtime_dir)
        shutil.rmtree(runtime_dir)
    except BaseException as exc:
        return type(exc).__name__
    return None


def _pin_treatment_arguments(
    message: dict[str, Any],
    manifest: Path,
    *,
    legacy_g1: bool = False,
    external_manifest: Path | None = None,
) -> None:
    params = message.get("params")
    if not isinstance(params, dict):
        raise RunnerError("MCP tools/call params must be an object")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
        params["arguments"] = arguments
    expected = str(manifest)
    supplied = arguments.get("bundle_manifest")
    if legacy_g1:
        allowed = {
            "ask_context": {
                "bundle_manifest",
                "query",
                "task_profile",
                "max_context_tokens",
                "max_answer_tokens",
                "k",
            },
            "grounding_verify": {
                "bundle_manifest",
                "declaration",
                "citation_map",
                "task_profile",
            },
            "live_freshness": {"bundle_manifest"},
        }
        name = params.get("name")
        if (
            name not in allowed
            or not set(arguments).issubset(allowed[name])
            or supplied
            not in (
                None,
                expected,
                str(external_manifest) if external_manifest is not None else None,
            )
        ):
            raise RunnerError("historical G1 MCP tool selectors are not authorized")
        if name == "ask_context":
            if not isinstance(arguments.get("query"), str):
                raise RunnerError("historical G1 ask_context requires a query")
            task_profile = arguments.get("task_profile")
            if task_profile is not None and not isinstance(task_profile, str):
                raise RunnerError("historical G1 ask_context task_profile is invalid")
            for integer_field in ("max_context_tokens", "max_answer_tokens", "k"):
                value = arguments.get(integer_field)
                if value is not None and (
                    type(value) is not int
                    or value < 1
                    or (integer_field == "k" and value > 100)
                ):
                    raise RunnerError("historical G1 ask_context budget is invalid")
        elif name == "grounding_verify":
            if not isinstance(arguments.get("declaration"), dict):
                raise RunnerError(
                    "historical G1 grounding_verify declaration is invalid"
                )
            for field in ("citation_map", "task_profile"):
                value = arguments.get(field)
                if value is not None and not isinstance(value, str):
                    raise RunnerError(
                        "historical G1 grounding_verify selector is invalid"
                    )
        arguments["bundle_manifest"] = expected
        return

    if supplied not in (None, expected):
        raise RunnerError("MCP bundle_manifest conflicts with the bound manifest")
    for selector in ("repo", "stem"):
        if arguments.get(selector) is not None:
            raise RunnerError(
                f"MCP {selector} selector conflicts with the bound manifest"
            )
    arguments["bundle_manifest"] = expected
    arguments["repo"] = None
    arguments["stem"] = None


def _attest_mcp_proxy_original_mount_namespace() -> None:
    """Detect ordinary mount drift inside a trusted parent-started broker.

    Nested Codex user namespaces can mount attacker bytes over a read-only
    stage and remount them read-only.  A statvfs RO bit or an argv hash
    cannot authenticate the original parent stage.  The fresh outer bwrap
    PID namespace has a fixed PID 1; only that initial mount namespace
    may read or run parent-staged MCP program bytes.  Authenticate both
    namespace links as kernel-procfs objects on ONE mount before comparison:
    bind-overlaid procfs names or substituted nsfs links must not pass.
    """
    if sys.platform != "linux" or not hasattr(os, "O_PATH"):
        raise RunnerError("MCP proxy mount namespace attestation requires Linux")
    opened: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        proc = os.open("/proc", directory_flags)
        opened.append(proc)
        mount_id = _kernel_procfs_mount_id(proc)
        identities: list[str] = []
        for process in ("self", "1"):
            process_dir = os.open(
                process,
                directory_flags & ~os.O_NOFOLLOW
                if process == "self"
                else directory_flags,
                dir_fd=proc,
            )
            opened.append(process_dir)
            namespace_dir = os.open("ns", directory_flags, dir_fd=process_dir)
            opened.append(namespace_dir)
            namespace_link = os.open(
                "mnt",
                os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=namespace_dir,
            )
            opened.append(namespace_link)
            if any(
                _kernel_procfs_mount_id(fd) != mount_id
                for fd in (process_dir, namespace_dir, namespace_link)
            ) or not stat.S_ISLNK(os.fstat(namespace_link).st_mode):
                raise RunnerError("MCP proxy mount namespace procfs is untrusted")
            link = os.readlink("", dir_fd=namespace_link)
            if re.fullmatch(r"mnt:\[[0-9]+\]", link) is None:
                raise RunnerError("MCP proxy mount namespace link is invalid")
            identities.append(link)
        if identities[0] != identities[1]:
            raise RunnerError(
                "MCP proxy has left the parent-staged read-only mount namespace"
            )
    except (OSError, ValueError, AttributeError) as exc:
        raise RunnerError(
            "MCP proxy kernel mount namespace attestation unavailable"
        ) from exc
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _prepared_mcp_upstream_from_parent(
    stage_text: str, manifest: Path
) -> dict[str, Any]:
    """Accept only a parent-staged MCP closure on a kernel-readonly mount.

    All executable bytes are staged before provider intent. This child never
    writes executable files or trusts a final digest to cover a transient edit.
    """
    _attest_mcp_proxy_original_mount_namespace()
    if not isinstance(stage_text, str) or len(stage_text.encode("utf-8")) > 8192:
        raise RunnerError("MCP stage metadata reference exceeds its argv bound")
    try:
        reference = json.loads(stage_text)
    except (TypeError, ValueError) as exc:
        raise RunnerError("MCP stage metadata reference is invalid") from exc
    if not isinstance(reference, dict):
        raise RunnerError("MCP stage metadata reference is invalid")
    # Check the physical/read-only stage root before opening the metadata
    # file: no provider-writable aliases or dynamic CODEX_HOME transport.
    metadata_path = Path(str(reference.get("path")))
    expected_parent = manifest.parents[2] / "repoground-mcp-upstream-runtime"
    if (
        not manifest.is_absolute()
        or metadata_path.name != MCP_STAGE_METADATA_NAME
        or metadata_path.parent.parent != expected_parent
        or re.fullmatch(r"upstream-[0-9a-f]{24}", metadata_path.parent.name) is None
        or not hasattr(os, "ST_RDONLY")
    ):
        raise RunnerError("MCP stage metadata is outside its authorized root")
    # Never let a hostile provider substitute an old valid stage from a
    # persistent StateDirectory through its own metadata-pointer argument.
    _require_unique_mcp_stage(metadata_path.parent)
    for path in (metadata_path.parent, metadata_path, manifest):
        try:
            if not os.statvfs(path).f_flag & os.ST_RDONLY:
                raise RunnerError("MCP stage metadata is provider-writable")
        except OSError as exc:
            raise RunnerError("MCP stage metadata mount is unavailable") from exc
    raw = _read_bound_mcp_stage_metadata(reference)
    try:
        stage = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RunnerError("MCP upstream stage metadata is not JSON") from exc
    if (
        not isinstance(stage, dict)
        or "metadata_binding" in stage
        or not isinstance(stage.get("argv"), list)
    ):
        raise RunnerError("MCP upstream requires parent-prepared stage")
    stage["metadata_binding"] = reference
    try:
        root = Path(stage["runtime_dir"])
        state = manifest.parents[2]
        staged_manifest = Path(stage["manifest_binding"]["path"])
        home_text = os.environ.get("CODEX_HOME")
        if (
            not root.is_absolute()
            or not manifest.is_absolute()
            or manifest.parent.parent != state / "repoground-manifest-runtime"
            or root.parent != state / "repoground-mcp-upstream-runtime"
            or not root.name.startswith("upstream-")
            or staged_manifest.parent != root / "manifest"
            or staged_manifest
            != Path(stage["argv"][stage["argv"].index("--bundle-root") + 1])
            or (home_text is not None and Path(home_text).parents[1] != state)
            or (
                home_text is not None
                and (root == Path(home_text) or Path(home_text) in root.parents)
            )
        ):
            raise RunnerError("MCP prepared-stage physical binding is invalid")
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        raise RunnerError("MCP prepared-stage physical binding is invalid") from exc
    if not hasattr(os, "ST_RDONLY"):
        raise RunnerError("MCP prepared stage requires kernel readonly evidence")
    for path in (root, manifest, staged_manifest, metadata_path):
        try:
            if not os.statvfs(path).f_flag & os.ST_RDONLY:
                raise RunnerError("MCP prepared stage is provider-writable")
        except OSError as exc:
            raise RunnerError("MCP prepared stage mount is unavailable") from exc
    _revalidate_staged_mcp_upstream(stage)
    return stage


def run_mcp_proxy(
    upstream: Sequence[str],
    manifest_text: str,
    external_manifest_text: str,
    manifest_sha256: str,
    authorized_files: Sequence[Mapping[str, Any]],
    runtime_root_text: str,
    *,
    profile: str = MCP_PROFILE_MODERN,
    trusted_ready_fd: int | None = None,
) -> int:
    if not upstream or any(not isinstance(item, str) or not item for item in upstream):
        raise RunnerError("invalid MCP upstream argv")
    manifest = Path(manifest_text)
    external_manifest = Path(external_manifest_text).expanduser()
    if not external_manifest.is_absolute() or external_manifest.name != manifest.name:
        raise RunnerError("logical RepoGround manifest path is invalid")
    manifest_data = _read_bound_regular_file(
        manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
    )
    if sha_bytes(manifest_data) != manifest_sha256:
        raise RunnerError("RepoGround manifest SHA mismatch")
    if profile == MCP_PROFILE_FROZEN_G1:
        if (
            manifest_sha256 != FROZEN_G1_LEGACY_IDENTITY["manifest_sha256"]
            or len(upstream) != 6
            or upstream[0] != FROZEN_G1_LEGACY_IDENTITY["python_path"]
            or upstream[1] != FROZEN_G1_LEGACY_IDENTITY["launcher_path"]
            or upstream[5] != FROZEN_G1_LEGACY_IDENTITY["source_root"]
            or upstream[2] != "--bundle-root"
            or upstream[3] != str(manifest)
            or upstream[4] != "--repo-root"
            or Path(upstream[1]).parent.parent != Path(upstream[5])
        ):
            raise RunnerError("historical G1 MCP proxy origin is not authorized")
    elif profile != MCP_PROFILE_MODERN:
        raise RunnerError("unknown MCP proxy tool profile")
    manifest_metadata = manifest.lstat()
    manifest_identity = (
        manifest_metadata.st_dev,
        manifest_metadata.st_ino,
        manifest_metadata.st_size,
        manifest_metadata.st_mode,
    )
    # The true runner, NOT this child's namespace/procfs introspection,
    # authorizes source provenance by launching and owning the separate broker
    # and checking its private readiness pipe. This check is defense-in-depth.
    upstream_stage = _prepared_mcp_upstream_from_parent(runtime_root_text, manifest)
    bound_upstream = [str(item) for item in upstream_stage["argv"]]
    staged_manifest = Path(upstream_stage["manifest_binding"]["path"])
    process: subprocess.Popen[bytes] | None = None
    try:
        try:
            process = subprocess.Popen(
                bound_upstream,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=provider_env(),
                shell=False,
            )
        except OSError as exc:
            raise RunnerError("MCP upstream could not be started") from exc
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise RunnerError("MCP upstream pipes unavailable")
        if trusted_ready_fd is not None:
            if type(trusted_ready_fd) is not int or trusted_ready_fd < 3:
                raise RunnerError("trusted MCP broker readiness FD is invalid")
            os.write(trusted_ready_fd, _MCP_BROKER_READY)
            os.close(trusted_ready_fd)
        output_lock = threading.Lock()
        state_lock = threading.Lock()
        pending_requests: dict[Any, str] = {}
        pending_treatment_tools: dict[Any, str] = {}
        tools_inventory_validated = False
        resource_calls: dict[Any, tuple[str, str | None]] = {}
        frozen_resources: dict[str, Any] | None = None
        frozen_uris: set[str] = set()
        resource_list_upstream_id: Any | None = None
        resource_list_waiters: list[Any] = []
        errors: list[BaseException] = []
        upstream_stderr = bytearray()
        upstream_stderr_overflow = False

        # Keep the upstream in the inherited provider process group. The outer
        # runner can therefore still kill Codex, this proxy, and RepoGround as one
        # containment unit. Proxy-local failures additionally own/reap this child.
        def terminate_upstream() -> None:
            if process.poll() is not None:
                return
            try:
                process.kill()
            except ProcessLookupError:
                return
            except OSError as exc:
                errors.append(exc)

        def send(message: Mapping[str, Any]) -> None:
            raw = canonical(message).encode("utf-8") + b"\n"
            process.stdin.write(raw)
            process.stdin.flush()

        def drain_stderr() -> None:
            nonlocal upstream_stderr_overflow
            try:
                while True:
                    chunk = process.stderr.read(65536)
                    if not chunk:
                        break
                    room = MAX_STDERR_BYTES + 1 - len(upstream_stderr)
                    upstream_stderr.extend(chunk[: max(room, 0)])
                    if len(upstream_stderr) > MAX_STDERR_BYTES:
                        upstream_stderr_overflow = True
            except BaseException as exc:
                errors.append(exc)
                terminate_upstream()

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stderr_thread.start()

        client_stop = threading.Event()

        def client_to_upstream() -> None:
            nonlocal resource_list_upstream_id
            client_selector: selectors.BaseSelector | None = None
            client_fd: int | None = None
            client_was_blocking: bool | None = None
            pending_input = bytearray()
            try:
                client_fd = sys.stdin.buffer.fileno()
                client_was_blocking = os.get_blocking(client_fd)
                os.set_blocking(client_fd, False)
                client_selector = selectors.DefaultSelector()
                client_selector.register(client_fd, selectors.EVENT_READ)
                while not client_stop.is_set():
                    newline = pending_input.find(b"\n")
                    if newline < 0:
                        if len(pending_input) > base.MAX_MCP_MESSAGE_BYTES:
                            raise RunnerError("MCP client message too large")
                        events = client_selector.select(0.25)
                        if not events:
                            continue
                        try:
                            chunk = os.read(
                                client_fd,
                                min(
                                    65536,
                                    base.MAX_MCP_MESSAGE_BYTES + 1 - len(pending_input),
                                ),
                            )
                        except BlockingIOError:
                            continue
                        if not chunk:
                            if pending_input:
                                raise RunnerError(
                                    "MCP client message must be newline terminated"
                                )
                            break
                        pending_input.extend(chunk)
                        continue
                    raw = bytes(pending_input[: newline + 1])
                    del pending_input[: newline + 1]
                    if len(raw) > base.MAX_MCP_MESSAGE_BYTES:
                        raise RunnerError("MCP client message too large")
                    message = json.loads(raw)
                    if not isinstance(message, dict):
                        raise RunnerError("MCP client message must be an object")
                    if message.get("jsonrpc") != "2.0":
                        raise RunnerError("MCP client JSON-RPC version is invalid")
                    if "params" in message and not isinstance(
                        message.get("params"), (dict, list)
                    ):
                        raise RunnerError("MCP client JSON-RPC params are invalid")
                    method = message.get("method")
                    has_identifier = "id" in message
                    identifier = message.get("id")
                    if has_identifier and not _valid_jsonrpc_request_id(identifier):
                        raise RunnerError("MCP client request ID is invalid")
                    if method == "tools/call" and not has_identifier:
                        raise RunnerError("MCP tools/call request ID is required")
                    if method not in MCP_CLIENT_METHODS:
                        if identifier is not None:
                            _proxy_write(
                                _proxy_error(
                                    identifier, "benchmark MCP method is not authorized"
                                ),
                                output_lock,
                            )
                        continue
                    pending_kind: str | None = None
                    pending_treatment_tool: str | None = None
                    if method == "initialize":
                        pending_kind = "initialize"
                    elif method == "tools/list":
                        pending_kind = "tools/list"
                    elif method == "tools/call":
                        params = (
                            message.get("params")
                            if isinstance(message.get("params"), dict)
                            else {}
                        )
                        name = params.get("name")
                        if name == "repobrief_resource_read":
                            arguments = (
                                params.get("arguments")
                                if isinstance(params.get("arguments"), dict)
                                else {}
                            )
                            action = arguments.get("action")
                            uri = arguments.get("uri")
                            if identifier is None or action not in {"list", "read"}:
                                if identifier is not None:
                                    _proxy_write(
                                        _proxy_error(
                                            identifier, "invalid resource request"
                                        ),
                                        output_lock,
                                    )
                                continue
                            coalesced = False
                            with state_lock:
                                if identifier in pending_requests:
                                    raise RunnerError(
                                        "MCP client reused a pending request ID"
                                    )
                                if action == "list" and frozen_resources is not None:
                                    cached = canonical(frozen_resources)
                                else:
                                    cached = None
                                if (
                                    action == "list"
                                    and frozen_resources is None
                                    and resource_list_upstream_id is not None
                                ):
                                    pending_requests[identifier] = (
                                        "resource-list-waiter"
                                    )
                                    resource_list_waiters.append(identifier)
                                    coalesced = True
                                if action == "read" and frozen_resources is None:
                                    error = "list frozen resources before reading"
                                elif action == "read" and (
                                    not isinstance(uri, str) or uri not in frozen_uris
                                ):
                                    error = "resource URI is not in the frozen list"
                                else:
                                    error = None
                            if cached is not None:
                                _proxy_write(
                                    {
                                        "jsonrpc": "2.0",
                                        "id": identifier,
                                        "result": {
                                            "content": [
                                                {"type": "text", "text": cached}
                                            ],
                                            "isError": False,
                                        },
                                    },
                                    output_lock,
                                )
                                continue
                            if coalesced:
                                continue
                            if error is not None:
                                _proxy_write(
                                    {
                                        "jsonrpc": "2.0",
                                        "id": identifier,
                                        "result": {
                                            "content": [
                                                {"type": "text", "text": error}
                                            ],
                                            "isError": True,
                                        },
                                    },
                                    output_lock,
                                )
                                continue
                            with state_lock:
                                pending_requests[identifier] = "resource"
                                resource_calls[identifier] = (
                                    str(action),
                                    str(uri) if uri is not None else None,
                                )
                                if action == "list":
                                    resource_list_upstream_id = identifier
                            if action == "list":
                                send(
                                    {
                                        "jsonrpc": "2.0",
                                        "id": identifier,
                                        "method": "resources/list",
                                        "params": {},
                                    }
                                )
                            else:
                                send(
                                    {
                                        "jsonrpc": "2.0",
                                        "id": identifier,
                                        "method": "resources/read",
                                        "params": {"uri": uri},
                                    }
                                )
                            continue
                        if name not in UPSTREAM_MCP:
                            if identifier is not None:
                                _proxy_write(
                                    _proxy_error(
                                        identifier,
                                        "benchmark MCP tool is not authorized",
                                    ),
                                    output_lock,
                                )
                            continue
                        if profile == MCP_PROFILE_FROZEN_G1:
                            _pin_treatment_arguments(
                                message,
                                staged_manifest,
                                legacy_g1=True,
                                external_manifest=external_manifest,
                            )
                        else:
                            _pin_treatment_arguments(message, staged_manifest)
                        pending_kind = "tools/call"
                        pending_treatment_tool = str(name)
                    elif identifier is not None:
                        pending_kind = "passthrough"
                    if identifier is not None:
                        with state_lock:
                            if identifier in pending_requests:
                                raise RunnerError(
                                    "MCP client reused a pending request ID"
                                )
                            pending_requests[identifier] = pending_kind or "passthrough"
                            if pending_treatment_tool is not None:
                                pending_treatment_tools[identifier] = (
                                    pending_treatment_tool
                                )
                    send(message)
            except BaseException as exc:
                errors.append(exc)
                terminate_upstream()
            finally:
                client_stop.set()
                if client_selector is not None:
                    try:
                        client_selector.close()
                    except BaseException as exc:
                        errors.append(exc)
                if client_fd is not None and client_was_blocking is not None:
                    try:
                        os.set_blocking(client_fd, client_was_blocking)
                    except (OSError, ValueError) as exc:
                        errors.append(exc)
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass

        client_thread = threading.Thread(target=client_to_upstream, daemon=False)
        client_thread.start()
        returncode: int | None = None

    except BaseException as exc:
        cleanup_failures: list[str] = []
        setup_client_stop = locals().get("client_stop")
        if isinstance(setup_client_stop, threading.Event):
            setup_client_stop.set()
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
            except BaseException as cleanup_exc:
                cleanup_failures.append(f"process-kill:{type(cleanup_exc).__name__}")
            try:
                process.wait(timeout=5)
            except BaseException as cleanup_exc:
                cleanup_failures.append(f"process-reap:{type(cleanup_exc).__name__}")
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is None or stream.closed:
                    continue
                try:
                    stream.close()
                except BaseException as cleanup_exc:
                    cleanup_failures.append(
                        f"stream-close:{type(cleanup_exc).__name__}"
                    )
        setup_client_thread = locals().get("client_thread")
        if (
            isinstance(setup_client_thread, threading.Thread)
            and setup_client_thread.ident is not None
        ):
            try:
                setup_client_thread.join(timeout=1)
                if setup_client_thread.is_alive():
                    cleanup_failures.append("client-thread-still-running")
            except BaseException as cleanup_exc:
                cleanup_failures.append(
                    f"client-thread-join:{type(cleanup_exc).__name__}"
                )
        setup_stderr_thread = locals().get("stderr_thread")
        if (
            isinstance(setup_stderr_thread, threading.Thread)
            and setup_stderr_thread.ident is not None
        ):
            try:
                setup_stderr_thread.join(timeout=5)
                if setup_stderr_thread.is_alive():
                    cleanup_failures.append("stderr-thread-still-running")
            except BaseException as cleanup_exc:
                cleanup_failures.append(
                    f"stderr-thread-join:{type(cleanup_exc).__name__}"
                )
        # The trusted parent owns staged executable cleanup. The untrusted
        # provider namespace is readonly and must not remove that closure.
        if cleanup_failures:
            raise RunnerError(
                "MCP upstream setup failed and cleanup was incomplete: "
                + ",".join(cleanup_failures)
            ) from exc
        if not isinstance(exc, Exception):
            raise
        if isinstance(exc, RunnerError):
            raise
        raise RunnerError("benchmark MCP proxy setup failed") from exc

    try:
        while True:
            raw = _read_bounded_mcp_line(process.stdout, peer="upstream")
            if not raw:
                break
            message = json.loads(raw)
            if not isinstance(message, dict):
                raise RunnerError("MCP upstream message must be an object")
            has_identifier = "id" in message
            identifier = message.get("id")
            if (
                not has_identifier
                and "result" not in message
                and "error" not in message
            ):
                continue
            if not has_identifier or not _valid_jsonrpc_request_id(identifier):
                raise RunnerError("MCP upstream response envelope is invalid")
            with state_lock:
                pending_kind = pending_requests.get(identifier)
                if (
                    message.get("jsonrpc") != "2.0"
                    or pending_kind is None
                    or (("result" in message) == ("error" in message))
                ):
                    raise RunnerError("MCP upstream response envelope is invalid")
                if "error" in message:
                    error = message["error"]
                    if (
                        not isinstance(error, dict)
                        or isinstance(error.get("code"), bool)
                        or not isinstance(error.get("code"), int)
                        or not isinstance(error.get("message"), str)
                    ):
                        raise RunnerError("MCP upstream error response is invalid")
                elif pending_kind == "tools/call":
                    treatment_tool = pending_treatment_tools.get(identifier)
                    if treatment_tool not in UPSTREAM_MCP:
                        raise RunnerError(
                            "MCP treatment tool response binding is missing"
                        )
                    message["result"] = _validated_treatment_tool_result(
                        message["result"],
                        tool_name=treatment_tool,
                        expected_manifest=staged_manifest,
                        external_manifest=external_manifest,
                        profile=profile,
                    )
                pending_requests.pop(identifier, None)
                pending_treatment_tools.pop(identifier, None)
                resource_call = resource_calls.pop(identifier, None)
                is_initialize = pending_kind == "initialize"
                is_tools_list = pending_kind == "tools/list"
            if is_initialize and "result" in message:
                result = (
                    message.get("result")
                    if isinstance(message.get("result"), dict)
                    else {}
                )
                caps = (
                    result.get("capabilities")
                    if isinstance(result.get("capabilities"), dict)
                    else {}
                )
                filtered = {
                    key: result[key]
                    for key in ("protocolVersion", "serverInfo")
                    if key in result
                }
                # The benchmark exposes a frozen tool inventory. Do not advertise
                # upstream listChanged support because upstream notifications are
                # intentionally outside the deterministic benchmark surface.
                filtered["capabilities"] = {"tools": {}}
                message = {"jsonrpc": "2.0", "id": identifier, "result": filtered}
            elif is_tools_list:
                if "error" in message or "result" not in message:
                    raise RunnerError(
                        "MCP tools/list response must contain a successful result"
                    )
                tools = _filtered_treatment_tools(
                    message.get("result"), profile=profile
                )
                tools_inventory_validated = True
                message = {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "result": {"tools": tools},
                }
            elif resource_call is not None:
                action, _uri = resource_call
                waiter_ids: list[Any] = []
                if "error" in message:
                    text = canonical(message["error"])
                    is_error = True
                elif action == "list":
                    try:
                        frozen, uris = _freeze_resource_result(message.get("result"))
                    except RunnerError as exc:
                        text = str(exc)
                        is_error = True
                    else:
                        with state_lock:
                            if resource_list_upstream_id != identifier:
                                raise RunnerError(
                                    "MCP resource-list response identity is inconsistent"
                                )
                            if frozen_resources is None:
                                frozen_resources = frozen
                                frozen_uris = uris
                            text = canonical(frozen_resources)
                        is_error = False
                else:
                    if not isinstance(_uri, str):
                        raise RunnerError(
                            "MCP resource-read request URI is unavailable"
                        )
                    validated_read = _validated_resource_read_result(
                        message.get("result"), expected_uri=_uri
                    )
                    validated_read = _rebind_resource_read_manifest(
                        validated_read,
                        staged_manifest=staged_manifest,
                        external_manifest=external_manifest,
                    )
                    text = canonical(validated_read)
                    is_error = False
                if action == "list":
                    with state_lock:
                        if resource_list_upstream_id != identifier:
                            raise RunnerError(
                                "MCP resource-list response identity is inconsistent"
                            )
                        resource_list_upstream_id = None
                        waiter_ids = list(resource_list_waiters)
                        resource_list_waiters.clear()
                        for waiter_id in waiter_ids:
                            if (
                                pending_requests.pop(waiter_id, None)
                                != "resource-list-waiter"
                            ):
                                raise RunnerError(
                                    "MCP resource-list waiter state is inconsistent"
                                )
                message = {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "result": {
                        "content": [{"type": "text", "text": text}],
                        "isError": is_error,
                    },
                }
                for waiter_id in waiter_ids:
                    _proxy_write(
                        {
                            "jsonrpc": "2.0",
                            "id": waiter_id,
                            "result": message["result"],
                        },
                        output_lock,
                    )
            _proxy_write(message, output_lock)
        client_thread.join(timeout=1)
        if client_thread.is_alive():
            client_stop.set()
            client_thread.join(timeout=1)
            if client_thread.is_alive():
                raise RunnerError(
                    "MCP client intake could not be stopped at upstream EOF"
                )
            raise RunnerError("MCP client intake remained active at upstream EOF")
        if errors:
            raise RunnerError("benchmark MCP proxy stream failed") from errors[0]
        with state_lock:
            pending_kinds = tuple(pending_requests.values())
            pending_treatment = tuple(pending_treatment_tools.values())
        if pending_treatment:
            raise RunnerError(
                "MCP treatment tool response bindings remained pending at upstream EOF"
            )
        if "tools/list" in pending_kinds or not tools_inventory_validated:
            raise RunnerError(
                "MCP tools/list inventory was not validated before upstream EOF"
            )
        if pending_kinds:
            raise RunnerError("MCP upstream responses remained pending at upstream EOF")
        returncode = process.wait(timeout=5)
    finally:
        client_stop.set()
        if process.poll() is None:
            terminate_upstream()
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            errors.append(exc)
            terminate_upstream()
            try:
                returncode = process.wait(timeout=5)
            except subprocess.TimeoutExpired as followup:
                errors.append(followup)
                returncode = (
                    process.returncode if isinstance(process.returncode, int) else -1
                )
        try:
            process.stdin.close()
        except (OSError, ValueError):
            pass
        client_thread.join(timeout=1)
        if client_thread.is_alive():
            errors.append(
                RunnerError("MCP client intake remained active during cleanup")
            )
        process.stdout.close()
        stderr_thread.join(timeout=5)
        if upstream_stderr:
            sys.stderr.buffer.write(bytes(upstream_stderr))
            sys.stderr.buffer.flush()
        # The immutable staged tree remains parent-owned until the provider
        # group has exited and the trusted parent can revalidate and remove it.
        _revalidate_staged_mcp_upstream(upstream_stage)
        current_manifest = _read_bound_regular_file(
            manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
        )
        current_metadata = manifest.lstat()
        current_identity = (
            current_metadata.st_dev,
            current_metadata.st_ino,
            current_metadata.st_size,
            current_metadata.st_mode,
        )
        if (
            current_identity != manifest_identity
            or sha_bytes(current_manifest) != manifest_sha256
        ):
            raise RunnerError("RepoGround manifest changed during execution")
    if errors:
        raise RunnerError("benchmark MCP proxy stream failed") from errors[0]
    if (
        returncode is None
        or upstream_stderr_overflow
        or returncode != 0
        or upstream_stderr
    ):
        raise RunnerError("benchmark MCP upstream failed or emitted diagnostics")
    return returncode


_CODEX_OUTPUT_SCHEMA_UNIQUE_ITEM_FIELDS = (
    "reported_paths",
    "reported_symbols",
    "citations",
    "claims",
)


def _schema_contains_unique_items(value: Any) -> bool:
    if isinstance(value, Mapping):
        if "uniqueItems" in value:
            return True
        return any(_schema_contains_unique_items(item) for item in value.values())
    if isinstance(value, list):
        return any(_schema_contains_unique_items(item) for item in value)
    return False


def _codex_output_schema() -> dict[str, Any]:
    """Project the canonical answer contract into Codex Structured Outputs."""

    schema = json.loads(json.dumps(base.ANSWER_SCHEMA))
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise RunnerError("Codex output schema properties contract drift")
    for field in _CODEX_OUTPUT_SCHEMA_UNIQUE_ITEM_FIELDS:
        node = properties.get(field)
        if not isinstance(node, dict) or node.get("uniqueItems") is not True:
            raise RunnerError("Codex output schema uniqueness contract drift")
        del node["uniqueItems"]
    if _schema_contains_unique_items(schema):
        raise RunnerError("Codex output schema contains unsupported uniqueItems")
    return schema


def write_schema(path: Path) -> None:
    base._write_private_exclusive(
        path,
        (json.dumps(_codex_output_schema(), sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        ),
    )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _bootstrap_program_text() -> str:
    if (
        _ENTRYPOINT_BOOTSTRAP_RAW is not None
        and _ENTRYPOINT_BOOTSTRAP_IDENTITY is not None
    ):
        raw, _identity = _validated_entrypoint_bootstrap_context(
            _ENTRYPOINT_BOOTSTRAP_RAW, _ENTRYPOINT_BOOTSTRAP_IDENTITY
        )
    else:
        raw = _read_bound_regular_file(
            ENTRYPOINT_BOOTSTRAP_PATH,
            label="Codex immutable source bootstrap",
            max_bytes=SOURCE_SNAPSHOT_MAX_BYTES,
        )
        identity = {
            "schema_version": ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION,
            "kind": ENTRYPOINT_BOOTSTRAP_KIND,
            "name": ENTRYPOINT_BOOTSTRAP_NAME,
            "bytes": len(raw),
            "sha256": sha_bytes(raw),
        }
        raw, _identity = _validated_entrypoint_bootstrap_context(raw, identity)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunnerError("Codex immutable source bootstrap is not UTF-8") from exc


def _mcp_stage_wire(value: Any) -> Any:
    """Serialize only validated stage metadata, never ambient object reprs."""
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, (list, tuple)):
        return [_mcp_stage_wire(item) for item in value]
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise RunnerError("MCP stage transport keys are invalid")
        return {key: _mcp_stage_wire(item) for key, item in value.items()}
    raise RunnerError("MCP stage transport contains unsupported data")


def _treatment_mcp_upstream_command(
    request: Mapping[str, Any],
    checkout: Path,
    source: Path | None,
    manifest_path: Path,
) -> list[str]:
    binding = request["repobrief"]
    upstream = [str(item) for item in binding["mcp_command"]]
    if upstream.count("--bundle-root") != 1:
        raise RunnerError("treatment MCP command bundle root is invalid")
    bundle_index = upstream.index("--bundle-root")
    if bundle_index + 1 >= len(upstream):
        raise RunnerError("treatment MCP command bundle root is invalid")
    upstream[bundle_index + 1] = str(manifest_path)
    if base.validated_setup(request) == "dirty":
        if upstream.count("--repo-root") != 1:
            raise RunnerError("dirty treatment requires exactly one MCP --repo-root")
        repo_index = upstream.index("--repo-root")
        if (
            repo_index + 1 >= len(upstream)
            or source is None
            or Path(upstream[repo_index + 1]).expanduser().resolve() != source.resolve()
        ):
            raise RunnerError(
                "dirty treatment MCP source is not the bound clean checkout"
            )
        upstream[repo_index + 1] = str(checkout)
    return upstream


# Codex may enter arbitrarily nested mount/user/PID namespaces. Its MCP command
# must only transport untrusted JSON bytes to a *parent-launched* read-only MCP
# process. It must never load/revalidate executable program files in its own
# namespace, where both the files and kernel mount evidence can be forged.
_UNTRUSTED_MCP_FIFO_RELAY = r"""
import json
import os
import select
import stat
import sys
import threading
import time

if len(sys.argv) != 3:
    raise RuntimeError("MCP FIFO bridge requires two bound absolute paths")
request, response = sys.argv[1:3]
for value in (request, response):
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise RuntimeError("MCP FIFO bridge path is invalid")
flags = os.O_NONBLOCK | os.O_NOFOLLOW
sent = os.open(request, os.O_WRONLY | flags)
received = os.open(response, os.O_RDONLY | flags)
if not all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (sent, received)):
    raise RuntimeError("MCP FIFO bridge is not a pipe")
# Only the trusted parent owns the write end of the response FIFO.
if stat.S_IMODE(os.fstat(sent).st_mode) != 0o200 or stat.S_IMODE(os.fstat(received).st_mode) != 0o400:
    raise RuntimeError("MCP FIFO bridge permissions changed")
failures = []
finished = threading.Event()
pending_lock = threading.Lock()
pending = set()
max_line_bytes = 16 * 1024 * 1024

def key_of(line):
    message = json.loads(line)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise RuntimeError("MCP FIFO bridge JSON-RPC message is invalid")
    if "id" not in message:
        return None
    identity = message["id"]
    if type(identity) not in (int, str):
        raise RuntimeError("MCP FIFO bridge JSON-RPC ID is invalid")
    return type(identity).__name__, identity

def write_all(fd, payload):
    view = memoryview(payload)
    deadline = time.monotonic() + 30
    while view:
        if not select.select([], [fd], [], 0.25)[1]:
            if time.monotonic() > deadline:
                raise RuntimeError("MCP FIFO bridge write timeout")
            continue
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            continue
        if written <= 0:
            raise RuntimeError("MCP FIFO bridge short write")
        view = view[written:]

def forward_input():
    partial = bytearray()
    try:
        while True:
            chunk = os.read(0, 65536)
            if not chunk:
                if partial:
                    raise RuntimeError("MCP FIFO bridge request is unterminated")
                return
            partial.extend(chunk)
            while b"\n" in partial:
                line, _, rest = partial.partition(b"\n")
                partial = bytearray(rest)
                if len(line) + 1 > max_line_bytes:
                    raise RuntimeError("MCP FIFO bridge request too large")
                packet = bytes(line) + b"\n"
                key = key_of(packet)
                if key is not None:
                    with pending_lock:
                        if key in pending:
                            raise RuntimeError("MCP FIFO bridge reused a pending ID")
                        pending.add(key)
                write_all(sent, packet)
            if len(partial) > max_line_bytes:
                raise RuntimeError("MCP FIFO bridge request too large")
    except BaseException as exc:
        failures.append(exc)
    finally:
        finished.set()

worker = threading.Thread(target=forward_input, daemon=True)
worker.start()
partial = bytearray()
try:
    while True:
        if failures:
            raise RuntimeError("MCP FIFO bridge request transport failed") from failures[0]
        with pending_lock:
            all_answered = not pending
        if finished.is_set() and all_answered and not partial:
            break
        if not select.select([received], [], [], 0.1)[0]:
            continue
        try:
            chunk = os.read(received, 65536)
        except BlockingIOError:
            continue
        if not chunk:
            raise RuntimeError("trusted MCP parent transport closed")
        partial.extend(chunk)
        while b"\n" in partial:
            line, _, rest = partial.partition(b"\n")
            partial = bytearray(rest)
            if len(line) + 1 > max_line_bytes:
                raise RuntimeError("MCP FIFO bridge response too large")
            packet = bytes(line) + b"\n"
            key = key_of(packet)
            if key is not None:
                with pending_lock:
                    if key not in pending:
                        raise RuntimeError("MCP FIFO bridge unexpected response ID")
                    pending.remove(key)
            write_all(1, packet)
        if len(partial) > max_line_bytes:
            raise RuntimeError("MCP FIFO bridge response too large")
finally:
    os.close(sent)
    os.close(received)
if failures:
    raise RuntimeError("MCP FIFO bridge failed")
"""

_MCP_BRIDGE_REQUEST_NAME = "repobrief-requests.fifo"
_MCP_BRIDGE_RESPONSE_NAME = "repobrief-responses.fifo"
_MCP_BROKER_READY = b"TRUSTED_MCP_READY\n"


def _mcp_parent_bridge_paths(codex_home: Path) -> dict[str, Path]:
    """The provider can write only session HOME, never its parent directory."""
    name = codex_home.name + "-"
    return {
        "request": codex_home.parent / (name + _MCP_BRIDGE_REQUEST_NAME),
        "response": codex_home.parent / (name + _MCP_BRIDGE_RESPONSE_NAME),
    }


def _start_trusted_parent_mcp_broker(
    request: Mapping[str, Any],
    checkout: Path,
    source: Path,
    codex_home: Path,
    proxy_path: Path,
    manifest_path: Path,
    authorized_files: Sequence[Mapping[str, Any]],
    staged: Mapping[str, Any],
) -> dict[str, Any]:
    """Launch authentic MCP bytes as a trusted runner child, not a Codex child.

    The two FIFOs are in the parent-owned read-only directory (outside
    writable CODEX_HOME). The parent pins both inodes and opens them before exec.
    Its broker runs in a separate read-only bwrap PID/mount namespace, and
    authenticates the stage *before* signalling readiness through a private FD.
    """
    home, home_fd = _open_private_directory(codex_home, create_final=False)
    parent, parent_fd = _open_private_directory(codex_home.parent, create_final=False)
    pipes: list[dict[str, Any]] = []
    descriptors: list[int] = []
    broker: subprocess.Popen[bytes] | None = None
    ready_read: int | None = None
    ready_write: int | None = None
    try:
        if (
            home != codex_home
            or parent != home.parent
            or re.fullmatch(r"session-[0-9a-f]{24}", home.name) is None
            or parent.name != "codex-runtime"
        ):
            raise RunnerError("trusted MCP bridge private home identity invalid")
        # The real provider bwrap mounts only *home* writable. These FIFOs
        # belong to its read-only parent, so the provider cannot replace,
        # chmod, rename, or alias the authoritative transport in that mount.
        for kind, path in _mcp_parent_bridge_paths(home).items():
            name = path.name
            os.mkfifo(name, 0o600, dir_fd=parent_fd)
            descriptor = os.open(
                name, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent_fd
            )
            descriptors.append(descriptor)
            # The untrusted process may send requests but never read another
            # client's requests, and may read responses but never inject them
            # into the authentic broker's response FIFO.
            final_mode = 0o200 if kind == "request" else 0o400
            os.chmod(name, final_mode, dir_fd=parent_fd, follow_symlinks=False)
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            current = os.fstat(descriptor)
            if (
                not stat.S_ISFIFO(info.st_mode)
                or stat.S_IMODE(info.st_mode) != final_mode
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or (current.st_dev, current.st_ino, current.st_mode)
                != (info.st_dev, info.st_ino, info.st_mode)
            ):
                raise RunnerError("trusted MCP bridge FIFO identity is unsafe")
            pipes.append(
                {"path": path, "identity": (info.st_dev, info.st_ino, info.st_mode)}
            )
            # Broker stdio starts in blocking mode. Its request reader
            # deliberately switches to O_NONBLOCK only after registering the
            # FD with a selector, while response writes stay blocking so a
            # large valid JSON-RPC frame cannot fail with EAGAIN.
            os.set_blocking(descriptor, True)
        _directory_fd_matches(home, home_fd)
        _directory_fd_matches(parent, parent_fd)
        reference = staged.get("metadata_binding")
        if not isinstance(reference, Mapping):
            raise RunnerError("trusted parent MCP metadata reference unavailable")
        logical_manifest = Path(request["repobrief"]["manifest"]).expanduser()
        upstream = _treatment_mcp_upstream_command(
            request, checkout, source, manifest_path
        )
        profile = _frozen_g1_mcp_profile(request)
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        proxy_args = [
            _validated_mcp_proxy_python(authorized_files),
            "-I",
            "-B",
            "-c",
            _bootstrap_program_text(),
            str(proxy_path),
            "--codex-mcp-proxy",
            "--trusted-broker-ready-fd",
            str(ready_write),
            canonical(upstream),
            str(manifest_path),
            str(logical_manifest),
            str(request["repobrief"]["manifest_sha256"]),
            canonical(list(authorized_files)),
            canonical(_mcp_stage_wire(dict(reference))),
        ]
        if profile == MCP_PROFILE_FROZEN_G1:
            proxy_args.append(profile)
        bwrap = [
            "/usr/bin/bwrap",
            "--ro-bind",
            "/",
            "/",
            "--unshare-pid",
            "--unshare-ipc",
            "--die-with-parent",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--chmod",
            "1777",
            "/tmp",
            "--",
            *proxy_args,
        ]
        broker = subprocess.Popen(
            _unix_socket_restricted_codex_argv(bwrap, block_network=True),
            stdin=descriptors[0],
            stdout=descriptors[1],
            stderr=subprocess.DEVNULL,
            env={**provider_env(codex_home=codex_home), "HOME": "/nonexistent"},
            pass_fds=(ready_write,),
            start_new_session=True,
            shell=False,
        )
        os.close(ready_write)
        ready_write = None
        with selectors.DefaultSelector() as selector:
            selector.register(ready_read, selectors.EVENT_READ)
            events = selector.select(10)
        signal_bytes = (
            os.read(ready_read, len(_MCP_BROKER_READY) + 1) if events else b""
        )
        if signal_bytes != _MCP_BROKER_READY or broker.poll() is not None:
            raise RunnerError(
                "trusted parent MCP broker did not authenticate readiness"
            )
        return {"process": broker, "pipes": pipes, "home": home, "parent": parent}
    except BaseException:
        if broker is not None:
            try:
                os.killpg(broker.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                pass
            try:
                broker.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for pipe in pipes:
            try:
                pipe["path"].unlink()
            except OSError:
                pass
        raise
    finally:
        if ready_read is not None:
            os.close(ready_read)
        if ready_write is not None:
            os.close(ready_write)
        for descriptor in descriptors:
            os.close(descriptor)
        os.close(parent_fd)
        os.close(home_fd)


def _stop_trusted_parent_mcp_broker(binding: Mapping[str, Any]) -> str | None:
    """Kill the entire trusted broker group, including orphaned descendants."""
    errors: list[str] = []
    process = binding["process"]
    if not isinstance(process, subprocess.Popen):
        raise RunnerError("trusted MCP broker process handle invalid")
    # poll() observes only the broker leader. A dead leader can leave its
    # child MCP server alive in the same process group; never skip killpg.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        errors.append(f"broker-kill:{type(exc).__name__}")
    try:
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"broker-reap:{type(exc).__name__}")
    if process.stderr is not None:
        process.stderr.close()
    for pipe in binding["pipes"]:
        path = pipe["path"]
        try:
            info = path.lstat()
            if (
                not stat.S_ISFIFO(info.st_mode)
                or (info.st_dev, info.st_ino, info.st_mode) != pipe["identity"]
                or path.parent != binding["parent"]
            ):
                errors.append("broker-fifo-identity-drift")
                continue
            path.unlink()
        except OSError as exc:
            errors.append(f"broker-fifo-cleanup:{type(exc).__name__}")
    return ";".join(errors) or None


def build_command(
    request: Mapping[str, Any],
    codex: str,
    checkout: Path,
    schema: Path,
    codex_home: Path,
    *,
    authorized_mcp_files: Sequence[Mapping[str, Any]] | None = None,
    proxy_path: Path | None = None,
    manifest_path: Path | None = None,
    mcp_runtime_root: Path | None = None,
    source: Path | None = None,
    prepared_mcp_stage: Mapping[str, Any] | None = None,
    mcp_bridge: Mapping[str, Any] | None = None,
) -> list[str]:
    filesystem = (
        '{":minimal"="read",":workspace_roots"={"."="read"},'
        + _toml_string(str(codex_home / "tmp"))
        + '="read",'
        # Codex authenticates in its trusted process, never in model tools.
        + _toml_string(str(codex_home / "auth.json"))
        + '="deny",'
        + _toml_string(str(Path(codex).parent))
        + '="read"}'
    )
    command = [
        codex,
        "exec",
        "-c",
        f'default_permissions="{PERMISSION_PROFILE}"',
        "-c",
        "allow_login_shell=false",
        "-c",
        "features.network_proxy=true",
        "-c",
        f"permissions.{PERMISSION_PROFILE}.filesystem={filesystem}",
        "-c",
        f'permissions.{PERMISSION_PROFILE}.network={{enabled=false,mode="limited",allow_local_binding=false,domains={{}}}}',
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--color",
        "never",
        "--json",
        "--model",
        MODEL,
        "-c",
        'model_reasoning_effort="medium"',
        "-c",
        'web_search="disabled"',
        "--cd",
        str(checkout),
        "--output-schema",
        str(schema),
        "-",
    ]
    if request["condition"] == "treatment":
        if authorized_mcp_files is None:
            raise RunnerError(
                "treatment requires preflight-authorized MCP file identities"
            )
        if proxy_path is None or not proxy_path.is_absolute():
            raise RunnerError("treatment requires a bound absolute MCP proxy path")
        if manifest_path is None or not manifest_path.is_absolute():
            raise RunnerError(
                "treatment requires a staged absolute RepoGround manifest path"
            )
        if mcp_runtime_root is None or not mcp_runtime_root.is_absolute():
            raise RunnerError("treatment requires a private absolute MCP runtime root")
        proxy_python = _validated_mcp_proxy_python(authorized_mcp_files)
        binding = request["repobrief"]
        if prepared_mcp_stage is None:
            raise RunnerError("treatment requires parent-prepared immutable MCP stage")
        _treatment_mcp_upstream_command(request, checkout, source, manifest_path)
        metadata_reference = prepared_mcp_stage.get("metadata_binding")
        if not isinstance(metadata_reference, Mapping):
            raise RunnerError("treatment requires bound MCP stage metadata")
        logical_manifest = Path(str(binding.get("manifest"))).expanduser()
        if not logical_manifest.is_absolute():
            raise RunnerError("treatment logical manifest path must be absolute")
        # The provider is untrusted even inside a syntactically read-only mount.
        # Only the bytes of MCP JSON-RPC may cross to a trusted parent-launched
        # broker; no executable path or source/manifest stage metadata enters
        # the Codex MCP subprocess command line.
        _frozen_g1_mcp_profile(request)
        if not isinstance(mcp_bridge, Mapping) or set(mcp_bridge) != {
            "request",
            "response",
        }:
            raise RunnerError("treatment requires trusted parent-owned MCP bridge")
        request_pipe = Path(mcp_bridge["request"])
        response_pipe = Path(mcp_bridge["response"])
        expected_bridge = _mcp_parent_bridge_paths(codex_home)
        if (
            request_pipe != expected_bridge["request"]
            or response_pipe != expected_bridge["response"]
        ):
            raise RunnerError("trusted MCP bridge paths escaped bound CODEX_HOME")
        proxy_args = [
            "-I",
            "-B",
            "-c",
            _UNTRUSTED_MCP_FIFO_RELAY,
            str(request_pipe),
            str(response_pipe),
        ]
        command[2:2] = [
            "-c",
            f"mcp_servers.repobrief.command={_toml_string(proxy_python)}",
            "-c",
            "mcp_servers.repobrief.args=" + canonical(proxy_args),
            "-c",
            "mcp_servers.repobrief.enabled=true",
            "-c",
            "mcp_servers.repobrief.required=true",
            "-c",
            "mcp_servers.repobrief.enabled_tools=" + canonical(sorted(ALLOWED_MCP)),
        ]
    return command


def _validate_provider_exec_argv_budget(
    argv: Sequence[str], environment: Mapping[str, str]
) -> None:
    """Never spend one-shot intent on an OS-rejected argument or environment."""
    if sys.platform != "linux":
        raise RunnerError("provider exec budget requires Linux")
    try:
        per_argument = min(os.sysconf("SC_PAGESIZE") * 32, 128 * 1024)
        total_limit = os.sysconf("SC_ARG_MAX")
    except (OSError, ValueError) as exc:
        raise RunnerError("provider exec argument limits unavailable") from exc
    if per_argument <= 0 or total_limit <= 0:
        raise RunnerError("provider exec argument limits are invalid")
    try:
        sizes = [len(arg.encode("utf-8")) + 1 for arg in argv]
        env_sizes = [
            len(key.encode("utf-8")) + len(value.encode("utf-8")) + 2
            for key, value in environment.items()
        ]
    except (AttributeError, UnicodeError) as exc:
        raise RunnerError("provider exec argument encoding is invalid") from exc
    if not sizes or max([*sizes, *env_sizes], default=0) >= per_argument:
        raise RunnerError("provider exec argument exceeds Linux per-string bound")
    # Count argv/env pointer slots and leave room for kernel/loader overhead.
    if (
        sum(sizes) + sum(env_sizes) + 8 * (len(sizes) + len(env_sizes) + 32)
        >= total_limit - 32768
    ):
        raise RunnerError("provider exec arguments exceed Linux process budget")


def _enable_child_subreaper() -> None:
    """Adopt orphaned provider descendants so this runner can reap them."""
    if not sys.platform.startswith("linux"):
        raise RunnerError("provider containment requires Linux child-subreaper support")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
    except (OSError, AttributeError) as exc:
        raise RunnerError("provider containment cannot access prctl") from exc
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(36, 1, 0, 0, 0) != 0:  # Linux PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise RunnerError(
            f"provider containment cannot enable child subreaper: {os.strerror(error)}"
        )


def _scan_proc_direct_child_pids(parent_pid: int) -> set[int]:
    """Fallback for Linux procfs mounts without task ``children`` files."""
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise RunnerError("provider containment cannot enumerate /proc") from exc
    children: set[int] = set()
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            status = (entry / "status").read_text(encoding="ascii", errors="replace")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        except OSError:
            continue
        for line in status.splitlines():
            if not line.startswith("PPid:"):
                continue
            try:
                ppid = int(line.split(":", 1)[1].strip())
            except ValueError:
                break
            if ppid == parent_pid:
                children.add(int(entry.name))
            break
    return children


def _direct_child_pids() -> set[int]:
    """Return this process' direct Linux children for descendant containment."""
    parent_pid = os.getpid()
    path = Path(f"/proc/self/task/{parent_pid}/children")
    try:
        payload = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return _scan_proc_direct_child_pids(parent_pid)
    except (OSError, UnicodeError) as exc:
        raise RunnerError(
            "provider containment cannot enumerate child processes"
        ) from exc
    if not payload:
        return set()
    try:
        return {int(value) for value in payload.split()}
    except ValueError as exc:
        raise RunnerError(
            "provider containment received invalid child process data"
        ) from exc


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    stdin_data: bytes,
    environment: Mapping[str, str] | None = None,
    process_started_callback: Callable[[], None] | None = None,
    stdout_limit: int = MAX_TRANSCRIPT_BYTES,
    stderr_limit: int = MAX_STDERR_BYTES,
) -> dict[str, Any]:
    """Capture a bounded provider process without interpreting its streams.

    Before ``Popen`` succeeds, setup errors may raise normally.  After the
    provider process exists, every catchable capture/cleanup failure is converted
    into ``capture_error`` so already-observed stdout/stderr can be persisted by
    the caller before the benchmark arm fails.
    """

    _enable_child_subreaper()
    baseline_children = _direct_child_pids()
    process: subprocess.Popen[bytes] | None = None
    popen_in_progress = False
    process_started_callback_completed = False

    try:
        try:
            popen_in_progress = True
            process = subprocess.Popen(
                list(command),
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(environment) if environment is not None else provider_env(),
                shell=False,
                start_new_session=True,
            )
        except OSError as exc:
            popen_in_progress = False
            raise RunnerError("Codex process could not be started") from exc

        popen_in_progress = False
        if process_started_callback is not None:
            process_started_callback()
            process_started_callback_completed = True
        deadline = time.monotonic() + timeout_seconds
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": stdout_limit, "stderr": stderr_limit}
        overflow = {"stdout": False, "stderr": False}
        capture_error: str | None = None
        containment_events: list[str] = []
        selector: selectors.BaseSelector | None = None

        def note_error(marker: str) -> None:
            nonlocal capture_error
            if capture_error is None:
                capture_error = marker
            elif marker not in capture_error.split(";"):
                capture_error += ";" + marker

        def note_containment(marker: str) -> None:
            if marker not in containment_events:
                containment_events.append(marker)

        def kill_process_tree() -> None:
            group_killed = False
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_killed = True
            except ProcessLookupError:
                return
            except OSError as exc:
                note_error(f"process_group_kill_failed:{type(exc).__name__}")
            if group_killed or process.poll() is not None:
                return
            try:
                process.kill()
            except ProcessLookupError:
                return
            except OSError as exc:
                note_error(f"process_kill_failed:{type(exc).__name__}")

        def process_group_exists() -> bool:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return False
            except OSError as exc:
                note_error(f"process_group_probe_failed:{type(exc).__name__}")
                return True
            return True

        def adopted_provider_children() -> set[int]:
            try:
                return _direct_child_pids() - baseline_children
            except RunnerError:
                note_error("provider_child_scan_failed")
                return set()

        def kill_adopted_children(children: set[int]) -> None:
            for child_pid in sorted(children):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    continue
                except OSError as exc:
                    note_error(f"adopted_child_kill_failed:{type(exc).__name__}")

        def reap_adopted_children(children: set[int]) -> None:
            for child_pid in sorted(children):
                try:
                    os.waitpid(child_pid, os.WNOHANG)
                except ChildProcessError:
                    continue
                except OSError as exc:
                    note_error(f"adopted_child_reap_failed:{type(exc).__name__}")

        def contain_surviving_process_group() -> None:
            group_present = process_group_exists()
            adopted = adopted_provider_children()
            if not group_present and not adopted:
                return
            if group_present:
                note_containment("process_group_survived_provider_exit")
                kill_process_tree()
            if adopted:
                note_containment("adopted_descendant_survived_provider_exit")
                kill_adopted_children(adopted)
            cleanup_deadline = time.monotonic() + 1.0
            while time.monotonic() < cleanup_deadline:
                adopted = adopted_provider_children()
                if adopted:
                    kill_adopted_children(adopted)
                    reap_adopted_children(adopted)
                group_present = process_group_exists()
                adopted = adopted_provider_children()
                if not group_present and not adopted:
                    return
                if group_present:
                    kill_process_tree()
                time.sleep(0.01)
            adopted = adopted_provider_children()
            if adopted:
                kill_adopted_children(adopted)
                reap_adopted_children(adopted)
            if process_group_exists() or adopted_provider_children():
                note_error("process_group_cleanup_failed")

        def store(label: str, chunk: bytes) -> None:
            if not chunk or overflow[label]:
                return
            limit = limits[label]
            room = max(limit + 1 - len(buffers[label]), 0)
            buffers[label].extend(chunk[:room])
            if len(buffers[label]) > limit:
                overflow[label] = True
                note_error(f"{label}_limit_exceeded")
                kill_process_tree()

        streams = ((process.stdout, "stdout"), (process.stderr, "stderr"))
        if process.stdin is None or process.stdout is None or process.stderr is None:
            note_error("capture_pipe_unavailable")
            kill_process_tree()
        else:
            try:
                selector = selectors.DefaultSelector()
                for stream, label in streams:
                    assert stream is not None
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
            except Exception as exc:
                note_error(f"capture_setup_failed:{type(exc).__name__}")
                kill_process_tree()

        stdin_pending = memoryview(stdin_data)
        if selector is not None and capture_error is None:
            assert process.stdin is not None
            try:
                os.set_blocking(process.stdin.fileno(), False)
                if stdin_pending:
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    process.stdin.close()
            except Exception as exc:
                note_error(f"stdin_setup_failed:{type(exc).__name__}")
                kill_process_tree()

        if selector is not None and capture_error is None:
            try:
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        note_error("timeout")
                        kill_process_tree()
                        break
                    wait_for = (
                        0
                        if process.poll() is not None
                        else max(min(remaining, 0.25), 0)
                    )
                    events = selector.select(wait_for)
                    if not events and process.poll() is not None:
                        for key in list(selector.get_map().values()):
                            if key.data == "stdin":
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                                continue
                            try:
                                chunk = os.read(key.fileobj.fileno(), 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                selector.unregister(key.fileobj)
                            else:
                                store(str(key.data), chunk)
                        continue
                    for key, _mask in events:
                        if key.data == "stdin":
                            try:
                                written = os.write(key.fileobj.fileno(), stdin_pending)
                            except BlockingIOError:
                                continue
                            except OSError as exc:
                                note_error(f"stdin_write_failed:{type(exc).__name__}")
                                kill_process_tree()
                                selector.unregister(key.fileobj)
                                continue
                            if written <= 0:
                                note_error("stdin_write_failed:short_write")
                                kill_process_tree()
                                selector.unregister(key.fileobj)
                                continue
                            stdin_pending = stdin_pending[written:]
                            if not stdin_pending:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                            continue
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        store(str(key.data), chunk)
            except Exception as exc:
                note_error(f"capture_stream_failed:{type(exc).__name__}")
                kill_process_tree()

        if selector is not None:
            try:
                selector.close()
            except Exception as exc:
                note_error(f"selector_cleanup_failed:{type(exc).__name__}")

        if capture_error is not None:
            kill_process_tree()

        if capture_error is None and process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                note_error("timeout")
                kill_process_tree()
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    note_error("timeout")
                    kill_process_tree()
                except Exception as exc:
                    note_error(f"process_wait_failed:{type(exc).__name__}")
                    kill_process_tree()

        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except Exception as followup:
                note_error(f"process_reap_failed:{type(followup).__name__}")
        returncode = process.returncode if isinstance(process.returncode, int) else -1
        if process.poll() is not None:
            contain_surviving_process_group()

        # After a capture fault, drain whatever bytes the terminated process left in
        # its pipes.  This is best-effort and bounded; failures themselves become
        # evidence-bearing capture errors rather than escaping past the caller.
        if capture_error is not None:
            for stream, label in streams:
                if stream is None:
                    continue
                try:
                    os.set_blocking(stream.fileno(), False)
                except (OSError, ValueError) as exc:
                    note_error(f"capture_drain_setup_failed:{type(exc).__name__}")
                    continue
                while True:
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        break
                    except (OSError, ValueError) as exc:
                        note_error(f"capture_drain_failed:{type(exc).__name__}")
                        break
                    if not chunk:
                        break
                    store(label, chunk)

        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is None or stream.closed:
                continue
            try:
                stream.close()
            except OSError as exc:
                note_error(f"stream_cleanup_failed:{type(exc).__name__}")

        return {
            "returncode": returncode,
            "stdout": bytes(buffers["stdout"]),
            "stderr": bytes(buffers["stderr"]),
            "capture_error": capture_error,
            "containment_events": list(containment_events),
            "stdout_overflow": overflow["stdout"],
            "stderr_overflow": overflow["stderr"],
        }

    except BaseException as exc:
        # Emergency containment for any post-Popen exception not handled by the
        # normal bounded-capture path. Once Popen returned, no catchable failure
        # may leave the provider process or adopted descendants alive.
        emergency_errors = [f"capture_unhandled:{type(exc).__name__}"]
        process_started = process is not None
        if process_started:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as cleanup_exc:
                emergency_errors.append(
                    f"emergency_process_group_kill_failed:{type(cleanup_exc).__name__}"
                )
                try:
                    if process.poll() is None:
                        process.kill()
                except BaseException as kill_exc:
                    emergency_errors.append(
                        f"emergency_process_kill_failed:{type(kill_exc).__name__}"
                    )
            try:
                process.wait(timeout=5)
            except BaseException as cleanup_exc:
                emergency_errors.append(
                    f"emergency_process_reap_failed:{type(cleanup_exc).__name__}"
                )
        child_scan_failed = False
        try:
            adopted = _direct_child_pids() - baseline_children
        except BaseException as cleanup_exc:
            emergency_errors.append(
                f"emergency_child_scan_failed:{type(cleanup_exc).__name__}"
            )
            child_scan_failed = True
            adopted = set()
        provider_start_uncertain = (
            process is not None
            or bool(adopted)
            or child_scan_failed
            or popen_in_progress
        )
        if (
            provider_start_uncertain
            and process_started_callback is not None
            and not process_started_callback_completed
        ):
            try:
                process_started_callback()
                process_started_callback_completed = True
            except BaseException as callback_exc:
                emergency_errors.append(
                    "emergency_process_started_callback_failed:"
                    f"{type(callback_exc).__name__}"
                )
        for child_pid in sorted(adopted):
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except BaseException as cleanup_exc:
                emergency_errors.append(
                    f"emergency_child_kill_failed:{type(cleanup_exc).__name__}"
                )
                continue
            try:
                os.waitpid(child_pid, 0)
            except ChildProcessError:
                pass
            except BaseException as cleanup_exc:
                emergency_errors.append(
                    f"emergency_child_reap_failed:{type(cleanup_exc).__name__}"
                )
        if process_started:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is None or stream.closed:
                    continue
                try:
                    stream.close()
                except BaseException as cleanup_exc:
                    emergency_errors.append(
                        f"emergency_stream_cleanup_failed:{type(cleanup_exc).__name__}"
                    )
        if not process_started or not isinstance(exc, Exception):
            raise

        existing_buffers = locals().get("buffers")
        stdout = (
            bytes(existing_buffers.get("stdout", b""))
            if isinstance(existing_buffers, dict)
            else b""
        )
        stderr = (
            bytes(existing_buffers.get("stderr", b""))
            if isinstance(existing_buffers, dict)
            else b""
        )
        existing_overflow = locals().get("overflow")
        stdout_overflow = (
            bool(existing_overflow.get("stdout", False))
            if isinstance(existing_overflow, dict)
            else False
        )
        stderr_overflow = (
            bool(existing_overflow.get("stderr", False))
            if isinstance(existing_overflow, dict)
            else False
        )
        return {
            "returncode": (
                process.returncode
                if isinstance(process.returncode, int)
                and not isinstance(process.returncode, bool)
                else -1
            ),
            "stdout": stdout,
            "stderr": stderr,
            "capture_error": ";".join(emergency_errors),
            "stdout_overflow": stdout_overflow,
            "stderr_overflow": stderr_overflow,
        }


def classify_stderr(raw: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "policy": STDERR_POLICY_VERSION,
        "sha256": sha_bytes(raw),
        "bytes": len(raw),
        "allowed": False,
        "classification": "unclassified",
        "meaningful_line_count": 0,
        "line_sha256": [],
    }
    if not raw:
        result.update({"allowed": True, "classification": "empty"})
        return result
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        result["classification"] = "non_utf8_unqualified"
        return result
    meaningful = [line for line in text.splitlines() if line.strip()]
    result["meaningful_line_count"] = len(meaningful)
    result["line_sha256"] = [sha_bytes(line.encode("utf-8")) for line in meaningful]
    if not meaningful:
        result.update({"allowed": True, "classification": "whitespace_only"})
        return result
    if QUALIFIED_BENIGN_STDERR_PATTERNS and all(
        any(pattern.fullmatch(line) for pattern in QUALIFIED_BENIGN_STDERR_PATTERNS)
        for line in meaningful
    ):
        result.update({"allowed": True, "classification": "qualified_benign_text"})
        return result
    result["classification"] = "text_unqualified"
    return result


def _provider_artifact_names(request: Mapping[str, Any]) -> dict[str, str]:
    stem = hashlib.sha256(str(request["request_id"]).encode("utf-8")).hexdigest()
    return {
        "stdout": f"{stem}.jsonl",
        "stderr": f"{stem}.stderr",
        "diagnostics": f"{stem}.provider.json",
        "stderr_policy": f"{stem}.stderr-policy.json",
    }


def persist_provider_capture(
    request: Mapping[str, Any],
    *,
    transcript_root: Path,
    evidence_root: Path,
    capture: Mapping[str, Any],
    started_at: datetime,
    ended_at: datetime,
    synthetic_fixture: bool,
    evidence_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist raw capture facts through pre-opened create-only directories."""
    owned_plan = evidence_plan is None
    plan = evidence_plan or prepare_provider_evidence(
        request, transcript_root, evidence_root
    )
    try:
        names = dict(plan["names"])
        transcript_path = Path(plan["transcript_root"])
        evidence_path = Path(plan["evidence_root"])
        transcript_fd = int(plan["transcript_fd"])
        evidence_fd = int(plan["evidence_fd"])
        _directory_fd_matches(transcript_path, transcript_fd)
        _directory_fd_matches(evidence_path, evidence_fd)
        stdout = bytes(capture.get("stdout") or b"")
        stderr = bytes(capture.get("stderr") or b"")
        stdout_path = transcript_path / names["stdout"]
        stderr_path = evidence_path / names["stderr"]
        diagnostics_path = evidence_path / names["diagnostics"]
        stderr_policy_path = evidence_path / names["stderr_policy"]
        raw_write_errors: list[tuple[str, BaseException]] = []
        raw_persisted = {"stdout": False, "stderr": False}
        for label, descriptor, name, data in (
            ("stdout", transcript_fd, names["stdout"], stdout),
            ("stderr", evidence_fd, names["stderr"], stderr),
        ):
            try:
                _write_private_dirfd(descriptor, name, data)
                raw_persisted[label] = True
            except BaseException as exc:
                raw_write_errors.append((label, exc))
        if raw_write_errors:
            failure_diagnostics = {
                "kind": "repobrief.codex_provider_capture_persistence_failure",
                "version": base.VERSION,
                "request_id": request["request_id"],
                "request_sha256": base._sha256_json(request),
                "provider": PROVIDER,
                "model": MODEL,
                "synthetic_fixture": synthetic_fixture,
                "started_at": iso(started_at),
                "ended_at": iso(ended_at),
                "returncode": capture.get("returncode"),
                "capture_error": capture.get("capture_error"),
                "containment_events": list(capture.get("containment_events") or []),
                "raw_persistence_complete": False,
                "raw_persisted": dict(raw_persisted),
                "write_errors": [
                    {"artifact": label, "error_type": type(exc).__name__}
                    for label, exc in raw_write_errors
                ],
                "stdout": {
                    "artifact": names["stdout"],
                    "sha256": sha_bytes(stdout),
                    "bytes": len(stdout),
                },
                "stderr": {
                    "artifact": names["stderr"],
                    "sha256": sha_bytes(stderr),
                    "bytes": len(stderr),
                },
                "semantic_interpretation": "not_performed",
                "does_not_establish": [
                    "provider_success",
                    "stderr_policy_acceptance",
                    "benchmark_receipt_validity",
                    "answer_correctness",
                    "retry_authority",
                ],
            }
            failure_raw = (
                json.dumps(failure_diagnostics, sort_keys=True, indent=2) + "\n"
            ).encode()
            try:
                _write_private_dirfd(evidence_fd, names["diagnostics"], failure_raw)
            except BaseException as diagnostics_exc:
                raise RunnerError(
                    "raw provider evidence and failure diagnostics could not be persisted completely"
                ) from diagnostics_exc
            raise RunnerError(
                "raw provider evidence could not be persisted completely; "
                f"failure_diagnostics_sha256={sha_bytes(failure_raw)}"
            ) from raw_write_errors[0][1]
        diagnostics = {
            "kind": "repobrief.codex_provider_capture",
            "version": base.VERSION,
            "request_id": request["request_id"],
            "request_sha256": base._sha256_json(request),
            "provider": PROVIDER,
            "model": MODEL,
            "synthetic_fixture": synthetic_fixture,
            "stderr_policy_version": STDERR_POLICY_VERSION,
            "started_at": iso(started_at),
            "ended_at": iso(ended_at),
            "returncode": capture.get("returncode"),
            "capture_error": capture.get("capture_error"),
            "containment_events": list(capture.get("containment_events") or []),
            "stdout": {
                "artifact": names["stdout"],
                "sha256": sha_bytes(stdout),
                "bytes": len(stdout),
                "overflow": bool(capture.get("stdout_overflow")),
            },
            "stderr": {
                "artifact": names["stderr"],
                "sha256": sha_bytes(stderr),
                "bytes": len(stderr),
                "overflow": bool(capture.get("stderr_overflow")),
            },
            "semantic_interpretation": "not_performed",
            "scenario_before": capture.get("scenario_before"),
            "scenario_after": capture.get("scenario_after"),
            "does_not_establish": [
                "provider_success",
                "stderr_policy_acceptance",
                "benchmark_receipt_validity",
                "answer_correctness",
                "retry_authority",
            ],
        }
        raw = (json.dumps(diagnostics, sort_keys=True, indent=2) + "\n").encode()
        _write_private_dirfd(evidence_fd, names["diagnostics"], raw)
        stderr_classification = classify_stderr(stderr)
        stderr_policy = {
            "kind": "repobrief.codex_stderr_policy",
            "version": base.VERSION,
            "request_id": request["request_id"],
            "request_sha256": base._sha256_json(request),
            "provider": PROVIDER,
            "model": MODEL,
            "synthetic_fixture": synthetic_fixture,
            "started_at": iso(started_at),
            "ended_at": iso(ended_at),
            "returncode": capture.get("returncode"),
            "capture_error": capture.get("capture_error"),
            "stdout": diagnostics["stdout"],
            "stderr": {
                "artifact": names["stderr"],
                **stderr_classification,
                "overflow": bool(capture.get("stderr_overflow")),
            },
            "capture_diagnostics_sha256": sha_bytes(raw),
            "does_not_establish": [
                "provider_success",
                "benchmark_receipt_validity",
                "answer_correctness",
                "retry_authority",
            ],
        }
        policy_raw = (
            json.dumps(stderr_policy, sort_keys=True, indent=2) + "\n"
        ).encode()
        _write_private_dirfd(evidence_fd, names["stderr_policy"], policy_raw)
        _directory_fd_matches(transcript_path, transcript_fd)
        _directory_fd_matches(evidence_path, evidence_fd)
        return {
            "stdout_path": stdout_path,
            "stderr_path": stderr_path,
            "diagnostics_path": diagnostics_path,
            "diagnostics_sha256": sha_bytes(raw),
            "diagnostics": diagnostics,
            "stderr_policy_path": stderr_policy_path,
            "stderr_policy_sha256": sha_bytes(policy_raw),
            "stderr_policy": stderr_policy,
            "stdout_artifact": names["stdout"],
        }
    finally:
        if owned_plan:
            close_provider_evidence_plan(plan)


def parse_events(raw: bytes) -> list[dict[str, Any]]:
    if not raw or len(raw) > MAX_TRANSCRIPT_BYTES:
        raise RunnerError("Codex transcript empty or oversized")
    result: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError(f"Codex transcript line {number} invalid JSON") from exc
        if not isinstance(value, dict):
            raise RunnerError(f"Codex transcript line {number} not object")
        if not isinstance(value.get("type"), str) or not value["type"]:
            raise RunnerError(
                f"Codex transcript line {number} event type must be a nonempty string"
            )
        result.append(value)
    if not result:
        raise RunnerError("Codex transcript contains no events")
    return result


_RG_SAFE_SWITCHES = {
    "--files",
    "--hidden",
    "--no-heading",
    "--no-ignore",
    "--no-ignore-vcs",
    "--no-messages",
    "--with-filename",
    "--fixed-strings",
    "--ignore-case",
    "--line-number",
    "--smart-case",
    "--word-regexp",
    "-F",
    "-H",
    "-i",
    "-n",
    "-S",
    "-w",
}
_RG_SAFE_VALUE_OPTIONS = {
    "--after-context",
    "--before-context",
    "--context",
    "--glob",
    "--iglob",
    "--max-count",
    "--max-depth",
    "--regexp",
    "--type",
    "--type-not",
    "-A",
    "-B",
    "-C",
    "-e",
    "-g",
    "-m",
    "-t",
    "-T",
}


def _reject_unquoted_shell_expansion(text: str) -> None:
    quote: str | None = None
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == "\\":
            escaped = True
            continue
        if quote == '"':
            if char == '"':
                quote = None
            elif char in {"$", "`"}:
                raise RunnerError("shell expansion is not allowed")
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {"$", "`", "*", "?", "[", "]", "{", "}", "~", "!", "(", ")"}:
            raise RunnerError("shell expansion is not allowed")


def _split_shell_words(text: str) -> list[str]:
    if "\n" in text or "\r" in text:
        raise RunnerError("command line breaks are not allowed")
    _reject_unquoted_shell_expansion(text)
    if "$(" in text or "`" in text:
        raise RunnerError("command substitution is not allowed")
    try:
        lexer = shlex.shlex(text.strip(), posix=True, punctuation_chars=";&|<>")
        lexer.commenters = ""
        lexer.whitespace_split = True
        parts = list(lexer)
    except ValueError as exc:
        raise RunnerError("unparseable Codex command") from exc
    if any(re.fullmatch(r"[;&|<>]+", part) is not None for part in parts):
        raise RunnerError("chained, piped, or redirected command is not allowed")
    return parts


def _repository_relative_path(value: str) -> str:
    if (
        not value
        or value.startswith("-")
        or value.startswith("~")
        or os.path.isabs(value)
    ):
        raise RunnerError("benchmark path must be repository-relative")
    if any(
        char in value
        for char in ("$", "*", "?", "[", "]", "{", "}", "!", "\n", "\r", "\x00")
    ):
        raise RunnerError("benchmark path contains shell expansion syntax")
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../"):
        raise RunnerError("benchmark path escapes the repository")
    return normalized


def _rg_kind(parts: Sequence[str]) -> str:
    if not parts or parts[0] != "rg":
        raise RunnerError("invalid rg command")
    files_mode = False
    explicit_pattern = False
    operands: list[str] = []
    index = 1
    while index < len(parts):
        item = parts[index]
        if item == "--":
            operands.extend(parts[index + 1 :])
            break
        if item in _RG_SAFE_SWITCHES:
            files_mode = files_mode or item == "--files"
            index += 1
            continue
        if item in _RG_SAFE_VALUE_OPTIONS:
            if index + 1 >= len(parts):
                raise RunnerError(f"rg option requires a value: {item}")
            explicit_pattern = explicit_pattern or item in {"-e", "--regexp"}
            index += 2
            continue
        matched_value_option = next(
            (
                option
                for option in _RG_SAFE_VALUE_OPTIONS
                if option.startswith("--") and item.startswith(option + "=")
            ),
            None,
        )
        if matched_value_option is not None:
            explicit_pattern = explicit_pattern or matched_value_option == "--regexp"
            index += 1
            continue
        if item.startswith("-"):
            raise RunnerError(f"unapproved rg option: {item}")
        operands.append(item)
        index += 1
    if files_mode:
        if explicit_pattern:
            raise RunnerError("rg --files must not carry a search expression")
        for path in operands:
            _repository_relative_path(path)
        return "glob"
    if not explicit_pattern:
        if not operands:
            raise RunnerError("rg grep form requires a search expression")
        path_operands = operands[1:]
    else:
        path_operands = operands
    for path in path_operands:
        _repository_relative_path(path)
    return "grep"


def _cat_kind(parts: Sequence[str]) -> str:
    if not parts or parts[0] != "cat":
        raise RunnerError("invalid cat command")
    operands = list(parts[1:])
    if operands[:1] == ["--"]:
        operands = operands[1:]
    if len(operands) != 1:
        raise RunnerError("cat benchmark form requires exactly one repository path")
    _repository_relative_path(operands[0])
    return "read_file"


def _sed_kind(parts: Sequence[str]) -> str:
    if not parts or parts[0] != "sed" or len(parts) not in {4, 5} or parts[1] != "-n":
        raise RunnerError("sed benchmark form must be: sed -n START,ENDp PATH")
    range_expression = parts[2]
    path_index = 3
    if len(parts) == 5:
        if parts[3] != "--":
            raise RunnerError("sed benchmark form has unexpected arguments")
        path_index = 4
    if re.fullmatch(r"[0-9]+(?:,[0-9]+)?p", range_expression) is None:
        raise RunnerError("sed benchmark range is not a bounded line read")
    _repository_relative_path(parts[path_index])
    return "read_file"


def command_kind(command: str) -> str:
    parts = _split_shell_words(command)
    # build_command pins allow_login_shell=false; normalize only Codex's
    # corresponding non-login wrapper so user profiles cannot change the
    # validated benchmark toolchain before the inner command runs.
    if len(parts) == 3 and parts[:2] == ["/bin/bash", "-c"]:
        parts = _split_shell_words(parts[2])
    if not parts:
        raise RunnerError("empty Codex command")
    executable = parts[0]
    if executable == "rg":
        return _rg_kind(parts)
    if executable == "cat":
        return _cat_kind(parts)
    if executable == "sed":
        return _sed_kind(parts)
    raise RunnerError(f"unapproved Codex command: {executable}")


def _codex_mcp_result_is_success(value: Any, *, tool_name: str, arguments: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if "isError" in value:
        return value.get("isError") is False
    content = value.get("content")
    if not isinstance(content, list) or len(content) != 1:
        return False
    item = content[0]
    if (
        not isinstance(item, dict)
        or item.get("type") != "text"
        or not isinstance(item.get("text"), str)
        or not item.get("text")
    ):
        return False
    if tool_name == "repobrief_resource_read":
        if not isinstance(arguments, dict):
            return False
        try:
            decoded = json.loads(item["text"])
            action = arguments.get("action")
            if action == "list":
                frozen, _uris = _freeze_resource_result(decoded)
                return canonical(decoded) == canonical(frozen)
            if action == "read":
                uri = arguments.get("uri")
                if not isinstance(uri, str) or not uri:
                    return False
                validated = _validated_resource_read_result(decoded, expected_uri=uri)
                return canonical(decoded) == canonical(validated)
        except (json.JSONDecodeError, RunnerError):
            return False
        return False
    structured = value.get("structured_content")
    if not isinstance(structured, dict):
        return False
    status = structured.get("status")
    if tool_name == "ask_context":
        return status == "ok"
    if tool_name == "live_freshness":
        return status in EXPECTED_REPOGROUND_FRESHNESS_VALUES
    if tool_name == "grounding_verify":
        return status in EXPECTED_GROUNDING_VERDICT_STATUSES
    return False


def _repoground_evidence_from_codex_events(
    request: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    calls: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    if request.get("condition") != "treatment":
        return None
    binding = request.get("repobrief")
    manifest = (
        Path(str(binding.get("manifest")))
        if isinstance(binding, Mapping) and isinstance(binding.get("manifest"), str)
        else None
    )
    if manifest is None:
        return None
    sequence = 0
    evidence_calls: list[dict[str, Any]] = []
    commits: set[str] = set()
    manifest_binding: tuple[str, str, str | None, frozenset[str]] | None = None
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item") if isinstance(event.get("item"), dict) else {}
        item_type = item.get("type")
        if not isinstance(item_type, str):
            continue
        if item_type in {"agent_message", "reasoning", "todo_list"}:
            continue
        if item_type not in {"command_execution", "mcp_tool_call"}:
            continue
        sequence += 1
        if item_type != "mcp_tool_call":
            continue
        tool_name = item.get("tool")
        if not isinstance(tool_name, str):
            continue
        if tool_name not in {
            "ask_context",
            "grounding_verify",
            "live_freshness",
            "repobrief_resource_read",
        }:
            continue
        if sequence > len(calls):
            continue
        call = calls[sequence - 1]
        if call.get("name") != tool_name or call.get("status") != "success":
            continue
        result_value = item.get("result")
        if not isinstance(result_value, Mapping):
            continue
        if tool_name == "repobrief_resource_read":
            arguments = item.get("arguments")
            if not isinstance(arguments, Mapping) or arguments.get("action") != "read":
                continue
            prepared_resource = base._repoground_resource_read_payload(
                result=result_value,
                expected_uri=arguments.get("uri"),
            )
            if prepared_resource is None:
                continue
            if manifest_binding is None:
                manifest_binding = base._optional_repoground_manifest_binding(request)
                if manifest_binding is None:
                    return None
            live_freshness, content_bytes = prepared_resource
            normalized = base._repoground_resource_read_evidence(
                manifest_binding=manifest_binding,
                sequence=sequence,
                live_freshness=live_freshness,
                content_bytes=content_bytes,
            )
        else:
            structured = result_value.get("structured_content")
            if not isinstance(structured, Mapping):
                continue
            try:
                payload = _validated_treatment_structured_payload(
                    structured,
                    tool_name=str(tool_name),
                    expected_manifest=manifest,
                    is_error=False,
                )
            except (RunnerError, TypeError, ValueError):
                continue
            if manifest_binding is None:
                manifest_binding = base._optional_repoground_manifest_binding(request)
                if manifest_binding is None:
                    return None
            try:
                normalized = base._repoground_evidence_from_payload(
                    manifest_binding=manifest_binding,
                    tool_name=str(tool_name),
                    sequence=sequence,
                    payload=payload,
                )
            except (RunnerError, TypeError, ValueError):
                continue
        if normalized is None:
            continue
        commit, call_evidence = normalized
        commits.add(commit)
        evidence_calls.append(call_evidence)
    if not evidence_calls or len(commits) != 1:
        return None
    return {
        "target_commit": str(request["repository"]["commit"]),
        "bundle_commit": next(iter(commits)),
        "calls": evidence_calls,
    }


def normalize(
    request: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> tuple[int, int, list[dict[str, Any]], dict[str, Any]]:
    completed = [event for event in events if event.get("type") == "turn.completed"]
    if len(completed) != 1:
        raise RunnerError("Codex transcript requires one turn.completed")
    if any(event.get("type") in {"turn.failed", "error"} for event in events):
        raise RunnerError("Codex emitted terminal error")
    usage = (
        completed[0].get("usage") if isinstance(completed[0].get("usage"), dict) else {}
    )
    raw_input_tokens = usage.get("input_tokens")
    cached_input_tokens = usage.get("cached_input_tokens")
    output_tokens = usage.get("output_tokens")
    if (
        not isinstance(raw_input_tokens, int)
        or isinstance(raw_input_tokens, bool)
        or raw_input_tokens < 0
        or not isinstance(cached_input_tokens, int)
        or isinstance(cached_input_tokens, bool)
        or cached_input_tokens < 0
        or cached_input_tokens > raw_input_tokens
        or not isinstance(output_tokens, int)
        or isinstance(output_tokens, bool)
        or output_tokens < 0
    ):
        raise RunnerError("Codex usage is invalid")
    # Codex includes cached reads in input_tokens. The frozen benchmark was
    # defined against Claude usage where cache-read tokens are reported
    # separately, so compare the provider-reported non-cached input quantity.
    # Cache-write input remains non-cached input and is therefore not deducted.
    input_tokens = raw_input_tokens - cached_input_tokens
    budgets = request["budgets"]
    if (
        input_tokens > budgets["input_tokens"]
        or output_tokens > budgets["output_tokens"]
    ):
        raise RunnerError("Codex token budget exceeded")

    calls: list[dict[str, Any]] = []
    answers: list[str] = []
    total_input = 0
    total_output = 0
    allowed = set(request["allowed_tools"])
    for event in events:
        if event.get("type") != "item.completed":
            continue
        item = event.get("item") if isinstance(event.get("item"), dict) else {}
        item_type = item.get("type")
        if not isinstance(item_type, str):
            raise RunnerError("Codex completed item type must be a string")
        if item_type == "agent_message":
            if isinstance(item.get("text"), str):
                answers.append(item["text"])
            continue
        if item_type in {"reasoning", "todo_list"}:
            continue
        if item_type == "command_execution":
            name = command_kind(str(item.get("command", "")))
            input_bytes = len(str(item.get("command", "")).encode("utf-8"))
            output_bytes = len(str(item.get("aggregated_output", "")).encode("utf-8"))
            status = (
                "success"
                if item.get("status") == "completed" and item.get("exit_code") == 0
                else "failed"
            )
        elif item_type == "mcp_tool_call":
            tool_name = item.get("tool")
            if (
                request["condition"] != "treatment"
                or item.get("server") != "repobrief"
                or not isinstance(tool_name, str)
                or tool_name not in ALLOWED_MCP
            ):
                raise RunnerError("unapproved Codex MCP tool call")
            name = tool_name
            input_bytes = len(canonical(item.get("arguments")).encode("utf-8"))
            result_value = item.get("result")
            output_value = (
                result_value if result_value is not None else item.get("error")
            )
            output_bytes = len(canonical(output_value).encode("utf-8"))
            result_is_success = _codex_mcp_result_is_success(
                result_value,
                tool_name=name,
                arguments=item.get("arguments"),
            )
            status = (
                "success"
                if (
                    item.get("status") == "completed"
                    and item.get("error") is None
                    and result_is_success
                )
                else "failed"
            )
        elif item_type in {"file_change", "web_search", "collab_tool_call", "error"}:
            raise RunnerError(f"unapproved Codex item type: {item_type}")
        else:
            raise RunnerError(f"unknown Codex completed item type: {item_type}")
        if name not in allowed:
            raise RunnerError(f"normalized tool not allowed: {name}")
        total_input += input_bytes
        total_output += output_bytes
        calls.append(
            {
                "sequence": len(calls) + 1,
                "name": name,
                "status": status,
                "duration_ms": 0,
                "input_bytes": input_bytes,
                "output_bytes": output_bytes,
            }
        )
    if (
        len(calls) > budgets["max_tool_calls"]
        or total_input > budgets["max_tool_input_bytes"]
        or total_output > budgets["max_tool_output_bytes"]
    ):
        raise RunnerError("Codex tool budget exceeded")
    if request["condition"] == "treatment" and not any(
        call["name"] in ALLOWED_MCP and call["status"] == "success" for call in calls
    ):
        raise RunnerError("treatment used no successful RepoBrief tool or resource")
    if not answers:
        raise RunnerError("Codex produced no final agent message")
    try:
        answer_raw = json.loads(answers[-1])
    except json.JSONDecodeError as exc:
        raise RunnerError("Codex final message is not structured JSON") from exc
    return input_tokens, output_tokens, calls, base.validate_answer(answer_raw)


def receipt(
    request: Mapping[str, Any],
    raw: bytes,
    artifact: str,
    returncode: int,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    if returncode != 0:
        raise RunnerError(f"Codex exited nonzero: {returncode}")
    events = parse_events(raw)
    input_tokens, output_tokens, calls, answer = normalize(request, events)
    repoground_evidence = _repoground_evidence_from_codex_events(request, events, calls)
    elapsed = max(0, int((ended_at - started_at).total_seconds() * 1000))
    if elapsed > int(request["budgets"]["wall_seconds"]) * 1000:
        raise RunnerError("Codex wall budget exceeded")
    return {
        "kind": base.RECEIPT_KIND,
        "version": base.VERSION,
        "request_id": request["request_id"],
        "request_sha256": base._sha256_json(request),
        "status": "success",
        "provider": {
            "name": PROVIDER,
            "model": MODEL,
            "sampling": SAMPLING,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "token_source": "provider_reported",
        },
        "started_at": iso(started_at),
        "ended_at": iso(ended_at),
        "duration_ms": elapsed,
        "exit_code": 0,
        "tool_calls": calls,
        **(
            {"repoground_evidence": repoground_evidence}
            if repoground_evidence is not None
            else {}
        ),
        "answer": answer,
        "transcript": {
            "storage": "artifact",
            "sha256": sha_bytes(raw),
            "bytes": len(raw),
            "inline": None,
            "artifact": artifact,
        },
        "error": None,
        "does_not_establish": list(base.DOES_NOT_ESTABLISH),
    }


def _fixture_capture(
    stream_fixture: Path, stderr_fixture: Path | None, fixture_returncode: int
) -> dict[str, Any]:
    return {
        "returncode": fixture_returncode,
        "stdout": stream_fixture.read_bytes(),
        "stderr": stderr_fixture.read_bytes() if stderr_fixture is not None else b"",
        "capture_error": None,
        "stdout_overflow": False,
        "stderr_overflow": False,
    }


def _require_external_provider_one_shot(
    *, request: Mapping[str, Any], authorization: Mapping[str, Any]
) -> None:
    """Do not spend from an internal ledger or CLI flag.

    A separate trusted verifier must eventually bind the exact source, pair,
    condition, model, total budget and one-time authorization. Until that
    canonical verifier exists, every direct live path remains fail closed.
    This function runs before the irreversible provider intent.
    """
    if not isinstance(request, Mapping) or not isinstance(authorization, Mapping):
        raise RunnerError("external one-shot provider authorization is invalid")
    raise RunnerError(
        "external one-shot provider authorization verifier is unavailable"
    )


# Not a CLI flag, environment token or durable authorization. This ephemeral
# state exists only in the trusted preflight process after the pair was fully
# bound and authorized. A separate Python interpreter has no active scope.
_ACTIVE_IN_PROCESS_PAIR = threading.local()


@contextmanager
def _in_process_pair_dispatch_scope(
    *, authorization: Mapping[str, Any], ordered: Sequence[Mapping[str, Any]]
) -> Iterator[None]:
    """Permit exactly two ordered conditions in one trusted Python process."""
    pair = tuple(ordered)
    if len(pair) != 2 or {item.get("condition") for item in pair} != {
        "baseline",
        "treatment",
    }:
        raise RunnerError("in-process pair must contain both conditions")
    pair_id = pair[0].get("pair_id")
    hashes = {str(item["condition"]): base._sha256_json(item) for item in pair}
    if (
        not isinstance(pair_id, str)
        or not pair_id
        or any(item.get("pair_id") != pair_id for item in pair)
        or not isinstance(authorization, Mapping)
        or authorization.get("status") != "authorized"
        or authorization.get("pair_id") != pair_id
        or authorization.get("request_sha256") != hashes
    ):
        raise RunnerError("in-process pair authorization identity mismatch")
    if getattr(_ACTIVE_IN_PROCESS_PAIR, "state", None) is not None:
        raise RunnerError("nested in-process provider pair is forbidden")
    _ACTIVE_IN_PROCESS_PAIR.state = {
        "pid": os.getpid(),
        "pair_id": pair_id,
        "conditions": tuple(
            (str(item["condition"]), hashes[str(item["condition"])]) for item in pair
        ),
        "next": 0,
    }
    try:
        yield
    finally:
        _ACTIVE_IN_PROCESS_PAIR.state = None


def _require_in_process_pair_condition(request: Mapping[str, Any]) -> None:
    """Fail before opening a ledger, consuming workspaces, login or dispatch."""
    state = getattr(_ACTIVE_IN_PROCESS_PAIR, "state", None)
    if not isinstance(state, dict) or state.get("pid") != os.getpid():
        raise RunnerError("direct live provider condition requires in-process pair")
    index = state["next"]
    sequence = state["conditions"]
    if (
        index >= len(sequence)
        or (
            request.get("condition"),
            base._sha256_json(request),
        )
        != sequence[index]
        or request.get("pair_id") != state["pair_id"]
    ):
        raise RunnerError("in-process pair condition order or identity mismatch")
    # A failed first condition consumes this process-local slot; never replay.
    state["next"] = index + 1


def execute(request: Mapping[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    validate_request(request)
    _validated_live_mode(
        stream_fixture=args.stream_fixture,
        stderr_fixture=args.stderr_fixture,
        fixture_returncode=args.fixture_returncode,
        allow_live_provider=args.allow_live_provider,
        codex_command_sha256=args.codex_command_sha256,
    )
    if args.stream_fixture is None:
        _require_in_process_pair_condition(request)
    base.load_planned_request(request, args.request_root)
    synthetic = args.stream_fixture is not None

    # Bind every static live input before consuming the create-only workspace id.
    # A typo in an executable digest or frozen Treatment manifest must not burn a
    # one-shot workspace even though it has not yet contacted the provider.
    if request["condition"] == "treatment":
        binding = request["repobrief"]
        manifest = Path(binding["manifest"])
        manifest_bytes = _read_bound_regular_file(
            manifest, label="RepoGround manifest", max_bytes=MAX_MANIFEST_BYTES
        )
        if sha_bytes(manifest_bytes) != binding["manifest_sha256"]:
            raise RunnerError("RepoGround manifest SHA mismatch")
    codex: str | None = None
    auth_data: bytes | None = None
    if not synthetic:
        codex = validate_executable(
            args.codex_command, args.codex_command_sha256, require_read_only_mount=True
        )

    state_path, state_fd = _open_private_directory(args.state_root)
    try:
        _directory_fd_matches(state_path, state_fd)
    finally:
        os.close(state_fd)
    authorized_mcp_files: list[dict[str, Any]] | None = None
    authorized_proxy_code: dict[str, Any] | None = None
    authorized_proxy_base_code: dict[str, Any] | None = None
    authorized_manifest: dict[str, Any] | None = None
    dispatch_authorization: dict[str, Any] | None = None
    dispatch_intent_recorded = False
    provider_process_started = False

    def mark_dispatch_intent_recorded() -> None:
        nonlocal dispatch_intent_recorded
        dispatch_intent_recorded = True

    def mark_provider_process_started() -> None:
        nonlocal provider_process_started
        provider_process_started = True

    if not synthetic:
        assert codex is not None
        dispatch_authorization = _load_preflight_dispatch_authorization(
            request,
            state_path,
            runtime_binding={
                "request_root": args.request_root,
                "repository_map": args.repository_map,
                "transcript_root": args.transcript_root,
                "evidence_root": args.provider_evidence_root,
            },
        )
        _assert_authorized_codex_executable(
            codex,
            str(args.codex_command_sha256),
            dispatch_authorization["provider_codex"],
        )
        # The external one-shot grant is a separate precondition, never the
        # internally produced dispatch ledger or a CLI --allow-live-provider
        # flag. Deny before Codex login/sandbox calls or consuming a checkout;
        # repeat the non-consuming verification immediately before intent.
        _require_external_provider_one_shot(
            request=request,
            authorization=dispatch_authorization["authorization"],
        )
        validate_toolchain(codex)
        if request["condition"] == "treatment":
            authorized_mcp_files = list(dispatch_authorization["mcp_files"])
            proxy_code = dispatch_authorization["proxy_code"]
            proxy_base_code = dispatch_authorization["proxy_base_code"]
            manifest_authorization = dispatch_authorization["manifest"]
            if (
                not isinstance(proxy_code, dict)
                or not isinstance(proxy_base_code, dict)
                or not isinstance(manifest_authorization, dict)
            ):
                raise RunnerError("treatment runtime authorization is incomplete")
            authorized_proxy_code = dict(proxy_code)
            authorized_proxy_base_code = dict(proxy_base_code)
            authorized_manifest = dict(manifest_authorization)

    if dispatch_authorization is None:
        source = base.load_repository_root(request, args.repository_map)
    else:
        repository_map_bytes = dispatch_authorization.get("repository_map_bytes")
        if not isinstance(repository_map_bytes, bytes):
            raise RunnerError("authorized repository map snapshot is unavailable")
        source = _repository_root_from_authorized_map_bytes(
            request, repository_map_bytes
        )
        _assert_authorized_runtime_binding(
            dispatch_authorization["binding"],
            request,
            request_root=args.request_root,
            repository_map=args.repository_map,
            state_root=state_path,
            transcript_root=args.transcript_root,
            evidence_root=args.provider_evidence_root,
        )
    # A changed mount namespace must fail without even consuming a workspace
    # or creating provider evidence. The second check immediately before the
    # irreversible intent remains authoritative against later mount drift.
    preallocate_check: Callable[[], None] | None = None
    if dispatch_authorization is not None:
        assert codex is not None
        # Every admitted pair has an immutable ordered condition list. The
        # first condition (whether baseline or treatment) must reserve the
        # remaining condition's outputs *before* spending its one-shot.
        # Benchmark and MCP source need not be the same repository.
        future_mcp_files = _normalized_authorized_mcp_files(
            dispatch_authorization["binding"].get("mcp_command_files")
        )
        if len(future_mcp_files) < 2:
            raise RunnerError("pre-intent paired MCP launcher binding is incomplete")
        mcp_script = Path(future_mcp_files[1]["path"])
        legacy_g1 = (
            _frozen_g1_baseline_pair(request)
            if request["condition"] == "baseline"
            else _frozen_g1_mcp_profile(request) == MCP_PROFILE_FROZEN_G1
        )
        pending_output_entries = _preintent_output_entry_reservation(
            str(request["condition"]),
            dispatch_authorization.get("manifest"),
            mcp_script=mcp_script,
            legacy_g1=legacy_g1,
            state_root=args.state_root,
        )
        if request["order"] == 1:
            # Reserve only the condition that remains, independent of order.
            future_condition = (
                "treatment" if request["condition"] == "baseline" else "baseline"
            )
            pending_output_entries += _preintent_output_entry_reservation(
                future_condition,
                dispatch_authorization["binding"].get("manifest"),
                mcp_script=mcp_script,
                legacy_g1=legacy_g1,
                state_root=args.state_root,
            )

        def check_preallocation_mounts(future_pair_entries: int = 0) -> None:
            if type(future_pair_entries) is not int or future_pair_entries < 0:
                raise RunnerError("paired clone headroom is invalid")
            validate_live_immutable_mounts(
                source=source,
                codex=Path(codex),
                request_root=args.request_root,
                repository_map=args.repository_map,
                manifest=(
                    Path(request["repobrief"]["manifest"])
                    if request["condition"] == "treatment"
                    else None
                ),
                state_root=args.state_root,
                transcript_root=args.transcript_root,
                evidence_root=args.provider_evidence_root,
                runtime_binding=dispatch_authorization["binding"],
                pending_output_entries=pending_output_entries + future_pair_entries,
            )

        preallocate_check = check_preallocation_mounts
        preallocate_check()
        # Even the non-inferential Codex login-status call executes the Codex
        # binary. The kernel write boundary must hold before any such process.
        assert codex is not None
        auth_data = validate_chatgpt_subscription(codex)
        _assert_authorized_chatgpt_auth(
            auth_data, dispatch_authorization["provider_authentication"]
        )
        validate_codex_linux_sandbox_before_intent(codex, source, args.state_root)
    evidence_plan = prepare_provider_evidence(
        request, args.transcript_root, args.provider_evidence_root
    )
    try:
        checkout = create_checkout(
            request, source, args.state_root, preallocate_check=preallocate_check
        )
        scenario_before = base.attest_checkout_setup(request, checkout)
        schema = checkout.parent / "answer-schema.json"
        write_schema(schema)
        started = utc_now()
        provider_started_at: datetime | None = None
        provider_ended_at: datetime | None = None
        if synthetic:
            capture = _fixture_capture(
                args.stream_fixture, args.stderr_fixture, args.fixture_returncode
            )
        else:
            assert codex is not None and auth_data is not None
            codex_home = stage_codex_home(args.state_root, auth_data)
            proxy_binding: dict[str, Any] | None = None
            manifest_binding: dict[str, Any] | None = None
            upstream_stage: dict[str, Any] | None = None
            trusted_mcp_broker: dict[str, Any] | None = None
            try:
                if request["condition"] == "treatment":
                    if (
                        authorized_proxy_code is None
                        or authorized_proxy_base_code is None
                        or authorized_manifest is None
                        or authorized_mcp_files is None
                    ):
                        raise RunnerError(
                            "treatment runtime authorization is incomplete"
                        )
                    proxy_binding = stage_mcp_proxy(
                        args.state_root,
                        authorized_proxy_code,
                        authorized_proxy_base_code,
                    )
                    manifest_binding = stage_repoground_manifest(
                        args.state_root, authorized_manifest
                    )
                    authorized_mcp_files = _rebind_staged_manifest_authorization(
                        authorized_mcp_files,
                        manifest_binding,
                    )
                    staged_manifest = Path(manifest_binding["path"])
                    if _frozen_g1_mcp_profile(request) == MCP_PROFILE_FROZEN_G1:
                        # Historical dependency provenance is a separate
                        # pre-intent security boundary, even if upstream
                        # authorization fails before stage creation.
                        _frozen_g1_vendor_snapshot()
                    upstream_stage = stage_mcp_upstream(
                        args.state_root,
                        _treatment_mcp_upstream_command(
                            request, checkout, source, staged_manifest
                        ),
                        staged_manifest,
                        authorized_mcp_files,
                        legacy_g1=(
                            _frozen_g1_mcp_profile(request) == MCP_PROFILE_FROZEN_G1
                        ),
                    )
                command = build_command(
                    request,
                    codex,
                    checkout,
                    schema,
                    codex_home,
                    authorized_mcp_files=authorized_mcp_files,
                    proxy_path=None
                    if proxy_binding is None
                    else Path(proxy_binding["path"]),
                    manifest_path=None
                    if manifest_binding is None
                    else Path(manifest_binding["path"]),
                    # The Codex child MCP proxy may stage only inside its
                    # private session home; epoch/ledger roots stay read-only.
                    mcp_runtime_root=args.state_root,
                    source=source,
                    prepared_mcp_stage=upstream_stage,
                    mcp_bridge=(
                        None
                        if upstream_stage is None
                        else {
                            **_mcp_parent_bridge_paths(codex_home),
                        }
                    ),
                )
                if dispatch_authorization is None:
                    raise RunnerError(
                        "live dispatch authorization is unavailable before provider intent"
                    )
                # Historical G1 dependencies must remain pinned immediately before
                # consuming the one-shot authorization. The MCP proxy's private
                # runtime staging independently rechecks them after dispatch.
                if _frozen_g1_baseline_pair(request) or (
                    request["condition"] == "treatment"
                    and _frozen_g1_mcp_profile(request) == MCP_PROFILE_FROZEN_G1
                ):
                    _frozen_g1_vendor_snapshot()
                # Prove the real byte-for-byte working tree and freeze Git
                # control metadata BEFORE consuming the provider one-shot.
                git_controls_before: dict[str, str] = {}
                _secure_post_provider_checkout_readback(
                    request, checkout, source, git_control_out=git_controls_before
                )
                if "sha256" not in git_controls_before:
                    raise RunnerError("post-provider Git control baseline unavailable")
                # Recheck in the actual provider process namespace, after all
                # staging and immediately before the irreversible one-shot intent.
                validate_live_immutable_mounts(
                    source=source,
                    codex=Path(codex),
                    request_root=args.request_root,
                    repository_map=args.repository_map,
                    manifest=(
                        Path(request["repobrief"]["manifest"])
                        if request["condition"] == "treatment"
                        else None
                    ),
                    state_root=args.state_root,
                    transcript_root=args.transcript_root,
                    evidence_root=args.provider_evidence_root,
                    runtime_binding=dispatch_authorization["binding"],
                )
                # A PID namespace, not a per-PID seccomp exception, keeps
                # every trusted parent thread unreachable from hostile Codex.
                # Trusted epoch outputs must be readonly to hostile Codex.
                # Only its unique session HOME may be writable; the fixed inner
                # bootstrap re-attests mount/namespace state before provider bytes.
                report_out = dispatch_authorization["binding"].get("report_out")
                if not isinstance(report_out, str) or not report_out:
                    raise RunnerError("provider PID sandbox report binding missing")
                pid_sandbox = {
                    "source": source,
                    "state_root": args.state_root,
                    "transcript_root": args.transcript_root,
                    "evidence_root": args.provider_evidence_root,
                    "report_root": Path(report_out).parent,
                    "codex_home": codex_home,
                }
                _assert_provider_pid_namespace_ready(
                    **pid_sandbox, cwd=checkout, codex_command=codex
                )
                if upstream_stage is not None:
                    # The trusted parent checks all executable bytes immediately
                    # before irreversible provider intent; the provider child
                    # independently checks its own kernel-readonly view.
                    _revalidate_staged_mcp_upstream(upstream_stage)
                    if (
                        proxy_binding is None
                        or manifest_binding is None
                        or authorized_mcp_files is None
                    ):
                        raise RunnerError("trusted MCP broker parent binding missing")
                    trusted_mcp_broker = _start_trusted_parent_mcp_broker(
                        request,
                        checkout,
                        source,
                        codex_home,
                        Path(proxy_binding["path"]),
                        Path(manifest_binding["path"]),
                        authorized_mcp_files,
                        upstream_stage,
                    )
                provider_argv = _unix_socket_restricted_codex_argv(
                    _provider_pid_namespaced_codex_argv(command, **pid_sandbox),
                    provider_pid_namespace=True,
                )
                provider_environment = provider_env(codex=codex, codex_home=codex_home)
                _validate_provider_exec_argv_budget(provider_argv, provider_environment)
                _require_external_provider_one_shot(
                    request=request,
                    authorization=dispatch_authorization["authorization"],
                )
                _record_preflight_dispatch_intent(
                    request,
                    state_path,
                    dispatch_authorization["authorization"],
                    intent_persisted_callback=mark_dispatch_intent_recorded,
                )
                # Provider wall-clock begins only at the irreversible bounded
                # invocation. Sandbox and pre-intent preparation have separate
                # allowances in the outer systemd service lifetime.
                provider_started_at = utc_now()
                capture = run_bounded(
                    provider_argv,
                    cwd=checkout,
                    timeout_seconds=int(request["budgets"]["wall_seconds"]),
                    stdin_data=(prompt_for(request) + "\n").encode("utf-8"),
                    environment=provider_environment,
                    process_started_callback=mark_provider_process_started,
                )
                provider_ended_at = utc_now()
            except BaseException as exc:
                broker_cleanup_error = (
                    None
                    if trusted_mcp_broker is None
                    else _stop_trusted_parent_mcp_broker(trusted_mcp_broker)
                )
                upstream_cleanup_error = (
                    None
                    if upstream_stage is None
                    else cleanup_staged_mcp_upstream(upstream_stage)
                )
                manifest_cleanup_error = (
                    None
                    if manifest_binding is None
                    else cleanup_staged_repoground_manifest(manifest_binding)
                )
                proxy_cleanup_error = (
                    None
                    if proxy_binding is None
                    else cleanup_staged_mcp_proxy(proxy_binding)
                )
                cleanup_error = cleanup_codex_home(codex_home)
                if (
                    broker_cleanup_error is not None
                    or upstream_cleanup_error is not None
                    or manifest_cleanup_error is not None
                    or proxy_cleanup_error is not None
                    or cleanup_error is not None
                ):
                    failure_exc = RunnerError(
                        "Codex failed before capture completion and private runtime cleanup failed: "
                        f"broker={broker_cleanup_error} upstream={upstream_cleanup_error} "
                        f"manifest={manifest_cleanup_error} proxy={proxy_cleanup_error} home={cleanup_error}"
                    )
                    if dispatch_intent_recorded and dispatch_authorization is not None:
                        try:
                            _record_preflight_dispatch_failed(
                                request,
                                state_path,
                                dispatch_authorization["authorization"],
                                failure_exc,
                                provider_process_started=provider_process_started,
                            )
                        except Exception as ledger_exc:
                            raise RunnerError(
                                "Codex provider failure could not be terminalized in dispatch ledger"
                            ) from ledger_exc
                    raise failure_exc from exc
                if dispatch_intent_recorded and dispatch_authorization is not None:
                    try:
                        _record_preflight_dispatch_failed(
                            request,
                            state_path,
                            dispatch_authorization["authorization"],
                            exc,
                            provider_process_started=provider_process_started,
                        )
                    except Exception as ledger_exc:
                        raise RunnerError(
                            "Codex provider failure could not be terminalized in dispatch ledger"
                        ) from ledger_exc
                raise
            capture = dict(capture)
            if trusted_mcp_broker is not None:
                if trusted_mcp_broker["process"].poll() is not None:
                    prior = capture.get("capture_error")
                    marker = "trusted_mcp_broker_exited_during_provider"
                    capture["capture_error"] = (
                        marker if prior is None else f"{prior};{marker}"
                    )
                broker_cleanup_error = _stop_trusted_parent_mcp_broker(
                    trusted_mcp_broker
                )
                if broker_cleanup_error is not None:
                    prior = capture.get("capture_error")
                    marker = f"trusted_mcp_broker_cleanup_failed:{broker_cleanup_error}"
                    capture["capture_error"] = (
                        marker if prior is None else f"{prior};{marker}"
                    )
            if upstream_stage is not None:
                try:
                    _revalidate_staged_mcp_upstream(upstream_stage)
                except BaseException as exc:
                    marker = f"mcp_upstream_revalidate_failed:{type(exc).__name__}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = (
                        marker if previous is None else f"{previous};{marker}"
                    )
                upstream_cleanup_error = cleanup_staged_mcp_upstream(upstream_stage)
                if upstream_cleanup_error is not None:
                    marker = f"mcp_upstream_cleanup_failed:{upstream_cleanup_error}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = (
                        marker if previous is None else f"{previous};{marker}"
                    )
            if manifest_binding is not None:
                try:
                    _revalidate_staged_repoground_manifest(manifest_binding)
                except BaseException as exc:
                    marker = f"manifest_revalidate_failed:{type(exc).__name__}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = (
                        marker if previous is None else f"{previous};{marker}"
                    )
                manifest_cleanup_error = cleanup_staged_repoground_manifest(
                    manifest_binding
                )
                if manifest_cleanup_error is not None:
                    marker = f"manifest_cleanup_failed:{manifest_cleanup_error}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = (
                        marker if previous is None else f"{previous};{marker}"
                    )
            if proxy_binding is not None:
                try:
                    _revalidate_staged_mcp_proxy(proxy_binding)
                except BaseException as exc:
                    marker = f"mcp_proxy_revalidate_failed:{type(exc).__name__}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = (
                        marker if previous is None else f"{previous};{marker}"
                    )
                proxy_cleanup_error = cleanup_staged_mcp_proxy(proxy_binding)
                if proxy_cleanup_error is not None:
                    marker = f"mcp_proxy_cleanup_failed:{proxy_cleanup_error}"
                    previous = capture.get("capture_error")
                    capture["capture_error"] = (
                        marker if previous is None else f"{previous};{marker}"
                    )
            cleanup_error = cleanup_codex_home(codex_home)
            if cleanup_error is not None:
                cleanup_marker = f"codex_home_cleanup_failed:{cleanup_error}"
                previous = capture.get("capture_error")
                capture["capture_error"] = (
                    cleanup_marker
                    if previous is None
                    else f"{previous};{cleanup_marker}"
                )
        capture = dict(capture)
        capture["scenario_before"] = scenario_before
        try:
            if synthetic:
                capture["scenario_after"] = base.attest_checkout_setup(
                    request, checkout
                )
                if base._run_checked(
                    ["git", "rev-parse", "HEAD"], cwd=source
                ) != request["repository"]["commit"] or base._run_checked(
                    ["git", "status", "--porcelain=v1", "--untracked-files=all"],
                    cwd=source,
                ):
                    raise RunnerError("historical benchmark source checkout changed")
            else:
                capture["scenario_after"] = _secure_post_provider_checkout_readback(
                    request,
                    checkout,
                    source,
                    expected_git_control_sha256=git_controls_before["sha256"],
                )
        except BaseException as exc:
            marker = f"benchmark_scenario_readback_failed:{type(exc).__name__}"
            previous = capture.get("capture_error")
            capture["capture_error"] = (
                marker if previous is None else f"{previous};{marker}"
            )
        if synthetic:
            ended = utc_now()
        else:
            if provider_started_at is None or provider_ended_at is None:
                raise RunnerError("bounded live provider timestamps are unavailable")
            # Post-provider source readback, cleanup, and evidence persistence
            # remain inside RuntimeMaxSec, but may not invalidate a provider
            # that respected its independent request wall_seconds budget.
            started = provider_started_at
            ended = provider_ended_at
        try:
            evidence = persist_provider_capture(
                request,
                transcript_root=args.transcript_root,
                evidence_root=args.provider_evidence_root,
                capture=capture,
                started_at=started,
                ended_at=ended,
                synthetic_fixture=synthetic,
                evidence_plan=evidence_plan,
            )
        except BaseException as exc:
            if dispatch_intent_recorded and dispatch_authorization is not None:
                try:
                    _record_preflight_dispatch_failed(
                        request,
                        state_path,
                        dispatch_authorization["authorization"],
                        exc,
                        provider_process_started=provider_process_started,
                    )
                except Exception as ledger_exc:
                    raise RunnerError(
                        "Codex evidence failure could not be terminalized in dispatch ledger"
                    ) from ledger_exc
            raise
    finally:
        close_provider_evidence_plan(evidence_plan)
    try:
        stderr_policy = evidence["stderr_policy"]

        if capture.get("capture_error") is not None:
            raise RunnerError(
                "Codex capture failed after evidence persistence: "
                f"{capture['capture_error']} diagnostics={evidence['diagnostics_sha256']} "
                f"stderr_policy={evidence['stderr_policy_sha256']}"
            )
        if not stderr_policy["stderr"]["allowed"]:
            raise RunnerError(
                "Codex stderr is not qualified by the fail-closed policy after evidence "
                f"persistence: classification={stderr_policy['stderr']['classification']} "
                f"sha256={stderr_policy['stderr']['sha256']} "
                f"bytes={stderr_policy['stderr']['bytes']} "
                f"diagnostics={evidence['diagnostics_sha256']} "
                f"stderr_policy={evidence['stderr_policy_sha256']}"
            )

        if not synthetic:
            validate_executable(
                args.codex_command,
                args.codex_command_sha256,
                require_read_only_mount=True,
            )
        if synthetic:
            base.attest_checkout_setup(request, checkout)
            if base._run_checked(["git", "rev-parse", "HEAD"], cwd=source) != request[
                "repository"
            ]["commit"] or base._run_checked(
                ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=source
            ):
                raise RunnerError("Codex changed historical benchmark source checkout")
        else:
            _secure_post_provider_checkout_readback(
                request,
                checkout,
                source,
                expected_git_control_sha256=git_controls_before["sha256"],
            )

        normalized = receipt(
            request,
            bytes(capture["stdout"]),
            evidence["stdout_artifact"],
            int(capture["returncode"]),
            started,
            ended,
        )
    except BaseException as exc:
        if dispatch_intent_recorded and dispatch_authorization is not None:
            try:
                _record_preflight_dispatch_failed(
                    request,
                    state_path,
                    dispatch_authorization["authorization"],
                    exc,
                    provider_process_started=provider_process_started,
                )
            except Exception as ledger_exc:
                raise RunnerError(
                    "Codex terminal validation failure could not be terminalized in dispatch ledger"
                ) from ledger_exc
        raise

    if synthetic:
        return base.build_fixture_report(request, normalized)
    if dispatch_authorization is None or not dispatch_intent_recorded:
        raise RunnerError("live dispatch outcome has no recorded provider intent")
    _record_preflight_dispatch_completed(
        request,
        state_path,
        dispatch_authorization["authorization"],
        normalized,
    )
    return normalized


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Run one isolated read-only RepoBrief Codex benchmark request."
    )
    result.add_argument("--request-root", required=True, type=Path)
    result.add_argument("--repository-map", required=True, type=Path)
    result.add_argument("--state-root", required=True, type=Path)
    result.add_argument("--transcript-root", required=True, type=Path)
    result.add_argument("--provider-evidence-root", required=True, type=Path)
    result.add_argument("--codex-command", default="codex")
    result.add_argument("--codex-command-sha256")
    result.add_argument("--allow-live-provider", action="store_true")
    result.add_argument("--stream-fixture", type=Path)
    result.add_argument("--stderr-fixture", type=Path)
    result.add_argument("--fixture-returncode", type=int, default=0)
    return result


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "--codex-mcp-proxy":
        try:
            # A provider-created nested mount/PID namespace can forge every
            # self-attestation below. Only the original trusted runner starts
            # this broker with a private readiness pipe that IT verifies.
            # Direct CLI invocation without that parent transport is retired.
            if len(raw) < 3 or raw[1] != "--trusted-broker-ready-fd":
                raise RunnerError(
                    "direct Codex MCP proxy is disabled without parent-owned readiness"
                )
            if not raw[2].isascii() or not raw[2].isdecimal():
                raise RunnerError("trusted MCP broker readiness FD is invalid")
            trusted_ready_fd = int(raw[2])
            if trusted_ready_fd < 3:
                raise RunnerError("trusted MCP broker readiness FD is invalid")
            raw = [raw[0], *raw[3:]]
            if len(raw) not in (7, 8):
                raise RunnerError(
                    "codex MCP proxy requires exactly the authorized upstream, manifest, file identities, runtime root and optional frozen G1 profile"
                )
            upstream = json.loads(raw[1])
            authorized_files = json.loads(raw[5])
            if not isinstance(upstream, list):
                raise RunnerError("codex MCP proxy upstream argv must be a list")
            if not isinstance(authorized_files, list):
                raise RunnerError("codex MCP proxy authorized files must be a list")
            if len(raw) == 8:
                if raw[7] != MCP_PROFILE_FROZEN_G1:
                    raise RunnerError("unrecognized historical G1 MCP profile")
                return run_mcp_proxy(
                    upstream,
                    raw[2],
                    raw[3],
                    raw[4],
                    authorized_files,
                    raw[6],
                    profile=raw[7],
                    trusted_ready_fd=trusted_ready_fd,
                )
            return run_mcp_proxy(
                upstream,
                raw[2],
                raw[3],
                raw[4],
                authorized_files,
                raw[6],
                trusted_ready_fd=trusted_ready_fd,
            )
        except Exception as exc:
            print(f"codex MCP proxy failed: {exc}", file=sys.stderr)
            return 2
    args = parser().parse_args(raw)
    try:
        request = base._load_object_bytes(base._bounded_stdin(), label="stdin request")
        result = execute(request, args)
    except Exception as exc:
        print(
            json.dumps({"status": "error", "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

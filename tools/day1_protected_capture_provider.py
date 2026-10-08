#!/usr/bin/env python3
"""Opt-in root-only Day-1 capture producer (not a Grabowski task backend).

A fixed root-owned static ELF collector runs under a dedicated unprivileged UID.
The root parent captures its pipes, signs the *observed* bytes, and publishes
the whole bundle atomically. No CLI-configurable command, shell, rootbroker
registration, legacy receipt upgrade, or productive admission is provided.
"""

from __future__ import annotations

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
SIGN_TOOL = Path("/usr/bin/ssh-keygen")
CHILD_USER = "grabowski-day1-collector"
PROOF_KIND = "grabowski.protected_day1_task_proof"
PROOF_ISSUER = "grabowski-day1-capture@heimgewebe"
PROOF_NAMESPACE = "grabowski-day1-task-proof-v1@heimgewebe"
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
    "collector_sha256", "runtime_seconds", "max_stdout_bytes",
    "max_stderr_bytes",
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
    for label, regex in (("source_revision", REV_RE), ("collector_sha256", SHA_RE)):
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
    except KeyError as exc:
        raise CaptureDenied("dedicated collector/controller UID cannot be confirmed") from exc
    if (user.pw_name != CHILD_USER or user.pw_uid < 1 or user.pw_gid < 1
        or user.pw_uid == controller.pw_uid or canonical.pw_name != CHILD_USER):
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


def _kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


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
            preexec_fn=lambda: _drop_to_child(uid, gid),
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


def _recheck_executable_fd(fd: int, initial_bytes: bytes) -> None:
    """Verify pinned executable FD bytes again after child exit, not old RAM."""
    before = os.fstat(fd)
    if before.st_size != len(initial_bytes) or not stat.S_ISREG(before.st_mode):
        raise CaptureDenied("collector executable identity changed after run")
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
        raise CaptureDenied("collector executable FD changed during capture")


def _canonical_receipt(policy: dict[str, Any], *, hostname: str, code_hash: str,
                       task_id: str, nonce: str, argv: list[str], stdout: bytes,
                       stderr: bytes, started_at: int, terminal_at: int) -> bytes:
    if not 0 <= terminal_at - started_at <= MAX_RUNTIME + 1:
        raise CaptureDenied("actual captured terminal time is invalid")
    closure = _sha(_json_bytes({
        "mode": "root-staged-static-elf64-x86_64-v1",
        "executable_sha256": code_hash,
        "source_revision": policy["source_revision"],
        "collector_path": str(COLLECTOR_PATH),
    }))
    value = {
        "schema_version": 1,
        "kind": PROOF_KIND,
        "issuer": PROOF_ISSUER,
        "capture_boundary": CAPTURE_BOUNDARY,
        "host": hostname,
        "task_id": task_id,
        "attempt": 1,
        "unit": f"grabowski-task-{task_id}-a1.service",
        "argv_sha256": _sha(_json_bytes({"argv": argv})),
        "executed_source_sha256": code_hash,
        "execution_closure_sha256": closure,
        "nonce": nonce,
        "captured_stdout_sha256": _sha(stdout),
        "captured_stdout_bytes": len(stdout),
        "captured_stdout_complete": True,
        "stdout_truncated": False,
        "captured_stderr_sha256": _sha(stderr),
        "captured_stderr_bytes": len(stderr),
        "captured_stderr_complete": True,
        "stderr_truncated": False,
        "started_at_unix": started_at,
        "terminalized_at_unix": terminal_at,
        "state": "completed",
        "exit_code": 0,
    }
    return _json_bytes(value)


def _sign_receipt(payload: bytes) -> bytes:
    key_fd, _key_bytes = _open_root_file(
        SIGNING_KEY_PATH, max_bytes=64 * 1024, private=True,
    )
    os.close(key_fd)
    signer_fd, _signer_bytes = _open_root_file(
        SIGN_TOOL, max_bytes=4 * 1024 * 1024, executable=True,
    )
    os.close(signer_fd)
    try:
        run = subprocess.run(
            [str(SIGN_TOOL), "-Y", "sign", "-f", str(SIGNING_KEY_PATH),
             "-n", PROOF_NAMESPACE],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=15,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureDenied("root-only signing failed to start") from exc
    if (run.returncode != 0 or not 0 < len(run.stdout) <= MAX_SIGNATURE_BYTES
        or not run.stdout.startswith(b"-----BEGIN SSH SIGNATURE-----")
        or not run.stdout.rstrip().endswith(b"-----END SSH SIGNATURE-----")):
        raise CaptureDenied("protected evidence could not be signed")
    return run.stdout


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


def _publish_bundle(
    root_fd: int, *, task_id: str, nonce: str, stdout: bytes, stderr: bytes,
    receipt: bytes, signature: bytes,
) -> str:
    """Create-only root-owned directory publication; no mutable current pointer."""
    dirname = f"proof-{task_id}-{nonce}"
    staging = f".incomplete-{task_id}-{nonce}"
    try:
        os.stat(dirname, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise CaptureDenied("protected proof identity has already been committed")
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
        os.fsync(root_fd)
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
            task_id, nonce = secrets.token_hex(12), secrets.token_hex(32)
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
            receipt = _canonical_receipt(
                policy, hostname=hostname, code_hash=actual_sha,
                task_id=task_id, nonce=nonce, argv=argv, stdout=stdout,
                stderr=stderr, started_at=started, terminal_at=stopped,
            )
            signed = _sign_receipt(receipt)
            name = _publish_bundle(
                root_fd, task_id=task_id, nonce=nonce,
                stdout=stdout, stderr=stderr, receipt=receipt, signature=signed,
            )
            return {
                "kind": "grabowski.protected_day1_capture_result",
                "status": "root_owned_proof_published_not_admitted",
                "task_id": task_id,
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
#!/usr/bin/env python3
"""Strict offline verifier for a proposed Day-1 signed task proof.

This module is NOT a protected capture/signing service, has no public task
execution API, and NEVER authorizes Day-1 admission. In particular, a signed
claim does not prove that the signer observed the actual executed closure.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any

PROOF_KIND = "grabowski.protected_day1_task_proof"
RESULT_KIND = "grabowski.day1_signed_task_proof_check"
SIGNER_PRINCIPAL = "grabowski-day1-capture@heimgewebe"
SIGNATURE_NAMESPACE = "grabowski-day1-task-proof-v1@heimgewebe"
CAPTURE_BOUNDARY = "protected-parent-pipe-v1"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
ROOT_SIGNERS_PATH = Path("/etc/grabowski/day1-capture-allowed-signers")
MAX_PROOF_BYTES = 16 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_SIGNERS_BYTES = 64 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_RUN_SECONDS = 3600
MAX_PROOF_AGE_SECONDS = 24 * 3600
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TASK_ID = re.compile(r"^[0-9a-f]{16,64}$")
EXPECTED_KEYS = frozenset({
    "host", "task_id", "attempt", "unit", "argv_sha256",
    "executed_source_sha256", "execution_closure_sha256", "nonce",
})
PROOF_KEYS = frozenset({
    "schema_version", "kind", "issuer", "capture_boundary",
    "host", "task_id", "attempt", "unit", "argv_sha256",
    "executed_source_sha256", "execution_closure_sha256", "nonce",
    "captured_stdout_sha256", "captured_stdout_bytes",
    "captured_stdout_complete", "stdout_truncated",
    "captured_stderr_sha256", "captured_stderr_bytes",
    "captured_stderr_complete", "stderr_truncated",
    "started_at_unix", "terminalized_at_unix", "state", "exit_code",
})


class ValidationError(ValueError):
    """The proposed task proof has not been independently authenticated."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ValidationError(f"{field} is not exact lowercase SHA-256")
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(f"{field} is not a valid integer")
    return value


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("utf-8")


def _validated_proof(payload: bytes, expected: dict[str, Any],
                     stdout: bytes, stderr: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_PROOF_BYTES:
        raise ValidationError("signed proof bytes are missing or oversized")
    if not isinstance(stdout, bytes) or len(stdout) > MAX_STREAM_BYTES:
        raise ValidationError("stdout snapshot is missing or oversized")
    if not isinstance(stderr, bytes) or len(stderr) > MAX_STREAM_BYTES:
        raise ValidationError("stderr snapshot is missing or oversized")
    if not isinstance(expected, dict) or set(expected) != EXPECTED_KEYS:
        raise ValidationError("expected task binding is not exact")
    try:
        proof = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("proof is not valid UTF-8 JSON") from exc
    if not isinstance(proof, dict) or set(proof) != PROOF_KEYS:
        raise ValidationError("proof field set differs from contract")
    if payload != _canonical_json(proof):
        raise ValidationError("signed proof is not canonical JSON")
    if (type(proof.get("schema_version")) is not int
        or proof["schema_version"] != 1
        or proof.get("kind") != PROOF_KIND
        or proof.get("issuer") != SIGNER_PRINCIPAL
        or proof.get("capture_boundary") != CAPTURE_BOUNDARY):
        raise ValidationError("proof identity or capture contract is invalid")
    task_id = proof.get("task_id")
    if not isinstance(task_id, str) or TASK_ID.fullmatch(task_id) is None:
        raise ValidationError("proof task_id is invalid")
    attempt = _integer(proof.get("attempt"), "attempt", minimum=1)
    if proof.get("unit") != f"grabowski-task-{task_id}-a{attempt}.service":
        raise ValidationError("proof unit does not bind task and attempt")
    if not isinstance(proof.get("host"), str) or not proof["host"]:
        raise ValidationError("proof host is missing")
    for field in ("argv_sha256", "executed_source_sha256",
                  "execution_closure_sha256", "nonce"):
        _hex(proof.get(field), field)
    for field in EXPECTED_KEYS:
        if expected[field] != proof[field]:
            raise ValidationError(f"proof does not match expected {field}")
    if proof.get("state") != "completed" or (
        type(proof.get("exit_code")) is not int or proof["exit_code"] != 0
    ):
        raise ValidationError("proof does not describe a successful terminal task")
    for name, value in (("stdout", stdout), ("stderr", stderr)):
        if proof.get(f"captured_{name}_complete") is not True:
            raise ValidationError(f"{name} capture is not explicitly complete")
        if proof.get(f"{name}_truncated") is not False:
            raise ValidationError(f"{name} capture was truncated or unknown")
        amount = _integer(proof.get(f"captured_{name}_bytes"),
                          f"captured_{name}_bytes")
        if amount != len(value) or amount > MAX_STREAM_BYTES:
            raise ValidationError(f"{name} capture byte count differs")
        if _hex(proof.get(f"captured_{name}_sha256"),
                f"captured_{name}_sha256") != _digest(value):
            raise ValidationError(f"{name} capture bytes differ")
    start = _integer(proof.get("started_at_unix"), "started_at_unix", minimum=1)
    end = _integer(proof.get("terminalized_at_unix"),
                   "terminalized_at_unix", minimum=1)
    now = int(time.time())
    if (end < start or end - start > MAX_RUN_SECONDS
        or end > now + 5 or now - end > MAX_PROOF_AGE_SECONDS):
        raise ValidationError("signed task-time bounds are invalid or stale")
    return proof


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _check_root_directory(fd: int) -> None:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022):
        raise ValidationError("trusted signing policy has an unsafe ancestor")


def _read_root_owned_signers() -> bytes:
    """Read one pinned root-owned policy through no-follow directory FDs.

    The current task UID must not be able to write any path component. A
    user-supplied allowed-signers path is intentionally not accepted.
    """
    path = ROOT_SIGNERS_PATH
    if not path.is_absolute() or len(path.parts) < 3 or any(
        part in (".", "..") for part in path.parts
    ):
        raise ValidationError("configured signer policy path is not canonical")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        parent_fd = os.open("/", flags)
        try:
            _check_root_directory(parent_fd)
            for part in path.parts[1:-1]:
                next_fd = os.open(part, flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
                _check_root_directory(parent_fd)
            before = os.stat(path.name, dir_fd=parent_fd,
                             follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
                or not 0 < before.st_size <= MAX_SIGNERS_BYTES):
                raise ValidationError("trusted signing policy is not root-protected")
            descriptor = os.open(path.name, file_flags, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                if _file_identity(before) != _file_identity(opened):
                    raise ValidationError("signing policy changed during opening")
                remaining = before.st_size
                chunks: list[bytes] = []
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 65536))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            linked_after = os.stat(path.name, dir_fd=parent_fd,
                                   follow_symlinks=False)
            if (remaining or _file_identity(opened) != _file_identity(after)
                or _file_identity(opened) != _file_identity(linked_after)):
                raise ValidationError("signing policy changed during read")
            return b"".join(chunks)
        finally:
            os.close(parent_fd)
    except OSError as exc:
        raise ValidationError("root-protected signing policy is unavailable") from exc


def _sealed_memfd(name: str, data: bytes) -> int:
    """Freeze verifier inputs in kernel-sealed anonymous FDs, not /tmp."""
    if not hasattr(os, "memfd_create") or not hasattr(os, "MFD_ALLOW_SEALING"):
        raise ValidationError("sealed verifier input descriptors are unavailable")
    try:
        descriptor = os.memfd_create(
            name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
    except OSError as exc:
        raise ValidationError("sealed verifier inputs cannot be created") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ValidationError("cannot freeze verifier input")
            view = view[written:]
        seal = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seal)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ValidationError("sealed verifier inputs cannot be written") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _verify_signature(payload: bytes, signature: bytes,
                      trusted_signers: bytes) -> None:
    if not isinstance(signature, bytes) or not 0 < len(signature) <= MAX_SIGNATURE_BYTES:
        raise ValidationError("detached signature is missing or oversized")
    if not isinstance(trusted_signers, bytes) or not 0 < len(trusted_signers) <= MAX_SIGNERS_BYTES:
        raise ValidationError("trusted signing policy is empty or oversized")
    signers_fd = _sealed_memfd("day1-allowed-signers", trusted_signers)
    try:
        signature_fd = _sealed_memfd("day1-proof-signature", signature)
        try:
            argv = [
                SSH_KEYGEN, "-Y", "verify",
                "-f", f"/proc/self/fd/{signers_fd}",
                "-I", SIGNER_PRINCIPAL, "-n", SIGNATURE_NAMESPACE,
                "-s", f"/proc/self/fd/{signature_fd}",
            ]
            try:
                completed = subprocess.run(
                    argv, input=payload, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=10, check=False,
                    pass_fds=(signers_fd, signature_fd),
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ValidationError("SSH signature verifier unavailable") from exc
            if completed.returncode != 0:
                raise ValidationError("detached task-proof signature is untrusted")
        finally:
            os.close(signature_fd)
    finally:
        os.close(signers_fd)


def verify_signed_task_proof(
    proof_bytes: bytes, signature_bytes: bytes, stdout_bytes: bytes,
    stderr_bytes: bytes, *, expected: dict[str, Any],
) -> dict[str, Any]:
    """Check a bounded signature and byte binding; always deny admission.

    expected identity and nonce MUST eventually come from a separate trusted
    task requester; caller-supplied values are not independent evidence.
    """
    proof = _validated_proof(
        proof_bytes, expected, stdout_bytes, stderr_bytes,
    )
    trusted_signers = _read_root_owned_signers()
    _verify_signature(proof_bytes, signature_bytes, trusted_signers)
    return {
        "schema_version": 1,
        "kind": RESULT_KIND,
        "status": "signed_fields_consistent",
        "proof_sha256": _digest(proof_bytes),
        "captured_stdout_sha256": proof["captured_stdout_sha256"],
        "captured_stdout_bytes": proof["captured_stdout_bytes"],
        "cryptographic_binding_checked": True,
        "protected_capture_verified": False,
        "executed_source_verified": False,
        "day1_admission_authorized": False,
        "does_not_establish": [
            "real_uid_separated_capture_parent",
            "actual_executed_immutable_source_closure",
            "root_symmetric_or_signing_key_custody",
            "request_nonce_issuance_authority",
            "atomic_day1_evidence_publication",
            "productive_day1_admission",
        ],
    }
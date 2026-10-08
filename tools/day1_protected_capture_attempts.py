#!/usr/bin/env python3
"""Read-only classification of one non-admitting protected Day-1 prototype.

Never runs a collector, issues an attempt/nonce, verifies SSHSIG authority,
alters root-owned evidence, authorizes replay, or upgrades task completion.
The caller supplies an already authenticated root directory descriptor.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from typing import Any

from tools import day1_protected_capture_provider as provider

PROTOTYPE_LEAVES = frozenset({
    "stdout.bin", "stderr.bin", "proof.json", "proof.sshsig",
})
PROTOTYPE_PROOF_KEYS = frozenset({
    "schema_version", "kind", "issuer", "capture_boundary", "host",
    "capture_id", "capture_attempt", "provider_unit_template",
    "initial_exec_command_sha256", "initial_executable_sha256",
    "source_revision_policy_claim", "execution_closure_verified",
    "actual_task_binding_verified", "collector_process_tree_verified",
    "day1_admission_authorized", "nonce",
    "captured_stdout_sha256", "captured_stdout_bytes", "captured_stdout_complete",
    "stdout_truncated", "captured_stderr_sha256", "captured_stderr_bytes",
    "captured_stderr_complete", "stderr_truncated",
    "parent_capture_started_at_unix", "primary_exit_observed_at_unix",
    "state", "primary_exit_code",
})


def _check_prototype_leaf(info: os.stat_result, maximum: int) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
        or not 0 <= info.st_size <= maximum):
        raise provider.CaptureDenied("prototype artifact inode or size is unsafe")


def _read_leaf(directory_fd: int, name: str, maximum: int) -> bytes:
    if name not in PROTOTYPE_LEAVES:
        raise provider.CaptureDenied("unrecognized prototype artifact requested")
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        fd = os.open(
            name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            opened = os.fstat(fd)
            _check_prototype_leaf(opened, maximum)
            if provider._file_identity(before) != provider._file_identity(opened):
                raise provider.CaptureDenied("prototype artifact changed at open")
            chunks = []
            remaining = opened.st_size
            while remaining:
                piece = os.read(fd, min(65536, remaining))
                if not piece:
                    raise provider.CaptureDenied("prototype artifact truncated")
                chunks.append(piece)
                remaining -= len(piece)
            if os.read(fd, 1):
                raise provider.CaptureDenied("prototype artifact grew during read")
            after = os.fstat(fd)
            linked = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (provider._file_identity(opened) != provider._file_identity(after)
                or provider._file_identity(opened) != provider._file_identity(linked)):
                raise provider.CaptureDenied("prototype artifact changed during read")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        raise provider.CaptureDenied("prototype artifact read cannot be authenticated") from exc


def _open_exact_directory(parent_fd: int, name: str) -> int:
    fd = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        opened = os.fstat(fd)
        provider._check_staging_root_owned(fd)
        if (not stat.S_ISDIR(opened.st_mode)
            or provider._file_identity(before) != provider._file_identity(opened)):
            raise provider.CaptureDenied("prototype directory identity changed")
        return fd
    except BaseException as exc:
        if fd is not None:
            os.close(fd)
        if isinstance(exc, OSError):
            raise provider.CaptureDenied(
                "prototype directory is not safely openable"
            ) from exc
        raise


def _require_current_directory(parent_fd: int, name: str, fd: int) -> None:
    try:
        opened = os.fstat(fd)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise provider.CaptureDenied(
            "prototype directory changed during inspection"
        ) from exc
    if provider._file_identity(opened) != provider._file_identity(linked):
        raise provider.CaptureDenied(
            "prototype directory changed during inspection"
        )


def _verify_nonadmitting_proof(
    raw: bytes, reservation: dict[str, Any], stdout: bytes, stderr: bytes
) -> None:
    try:
        proof = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise provider.CaptureDenied("prototype proof is not JSON") from exc
    if not isinstance(proof, dict) or provider._json_bytes(proof) != raw:
        raise provider.CaptureDenied("prototype proof is not canonical")
    if (set(proof) != PROTOTYPE_PROOF_KEYS
        or type(proof.get("schema_version")) is not int
        or proof["schema_version"] != 1
        or proof.get("kind") != provider.PROOF_KIND
        or proof.get("issuer") != provider.PROOF_ISSUER
        or proof.get("capture_boundary") != provider.CAPTURE_BOUNDARY
        or proof.get("provider_unit_template") != "grabowski-day1-protected-capture.service"
        or proof.get("capture_id") != reservation["capture_id"]
        or proof.get("nonce") != reservation["nonce"]
        or proof.get("host") != reservation["host"]
        or type(proof.get("capture_attempt")) is not int
        or proof["capture_attempt"] != 1
        or proof.get("initial_executable_sha256") != reservation["initial_executable_sha256"]
        or proof.get("state") != "primary_exited_zero_pipes_closed_tree_unverified"
        or type(proof.get("primary_exit_code")) is not int
        or proof["primary_exit_code"] != 0):
        raise provider.CaptureDenied("prototype proof identity and schema mismatch")
    for field in (
        "execution_closure_verified", "actual_task_binding_verified",
        "collector_process_tree_verified", "day1_admission_authorized",
        "stdout_truncated", "stderr_truncated",
    ):
        if proof[field] is not False:
            raise provider.CaptureDenied("prototype proof must explicitly deny admission")
    for field in ("captured_stdout_complete", "captured_stderr_complete"):
        if proof[field] is not True:
            raise provider.CaptureDenied("prototype proof reports incomplete stream")
    for name, data in (("stdout", stdout), ("stderr", stderr)):
        if (proof[f"captured_{name}_sha256"] != hashlib.sha256(data).hexdigest()
            or type(proof[f"captured_{name}_bytes"]) is not int
            or proof[f"captured_{name}_bytes"] != len(data)):
            raise provider.CaptureDenied("prototype proof stream digest mismatch")
    if (not isinstance(proof["initial_exec_command_sha256"], str)
        or provider.SHA_RE.fullmatch(proof["initial_exec_command_sha256"]) is None
        or not isinstance(proof["source_revision_policy_claim"], str)
        or provider.REV_RE.fullmatch(proof["source_revision_policy_claim"]) is None):
        raise provider.CaptureDenied("prototype claim digest format invalid")
    began = proof["parent_capture_started_at_unix"]
    ended = proof["primary_exit_observed_at_unix"]
    if (type(began) is not int or type(ended) is not int
        or not 0 <= ended - began <= provider.MAX_RUNTIME + 1):
        raise provider.CaptureDenied("prototype claimed runtime is invalid")


def inspect_reserved_prototype(root_fd: int) -> dict[str, Any]:
    """Describe persisted material without cryptographic admission or retry.

    The only positive classification means *byte consistency*, NOT a signature
    verification, actual task authority, durability proof, or host attestation.
    Every result explicitly forbids admission and another capture attempt.
    """
    provider._check_staging_root_owned(root_fd)
    reservation = provider._read_capture_reservation(root_fd)
    if reservation is None:
        raise provider.CaptureDenied("no authenticated protected reservation")
    capture_id, nonce = reservation["capture_id"], reservation["nonce"]
    published = f"prototype-{capture_id}-{nonce}"
    staging = f".incomplete-{capture_id}-{nonce}"
    try:
        entries = os.listdir(root_fd)
    except OSError as exc:
        raise provider.CaptureDenied("protected root cannot be enumerated") from exc
    if len(entries) > 3 or (set(entries) - {provider.ATTEMPT_MARKER, published, staging}):
        raise provider.CaptureDenied("unexpected or foreign protected capture artifacts")
    if published in entries and staging in entries:
        raise provider.CaptureDenied("simultaneous staged and published attempt")
    result = {
        "kind": "grabowski.day1_prototype_reconciliation_diagnostic",
        "capture_id": capture_id,
        "reservation_sha256": hashlib.sha256(
            provider._json_bytes(reservation)
        ).hexdigest(),
        "day1_admission_authorized": False,
        "task_binding_verified": False,
        "signature_verified": False,
        "retry_authorized": False,
        "recovery_complete": False,
    }
    if published not in entries and staging not in entries:
        return {**result, "status": "reserved_without_publication"}
    name = published if published in entries else staging
    fd = _open_exact_directory(root_fd, name)
    try:
        try:
            children = os.listdir(fd)
        except OSError as exc:
            raise provider.CaptureDenied("protected attempt directory is unreadable") from exc
        if len(children) > len(PROTOTYPE_LEAVES) or (set(children) - PROTOTYPE_LEAVES):
            raise provider.CaptureDenied("unexpected prototype files")
        if name == staging:
            _require_current_directory(root_fd, name, fd)
            return {**result, "status": "incomplete_staging_unverified"}
        if set(children) != PROTOTYPE_LEAVES:
            raise provider.CaptureDenied("published prototype lacks required files")
        stdout = _read_leaf(fd, "stdout.bin", provider.MAX_CAPTURE_BYTES)
        stderr = _read_leaf(fd, "stderr.bin", provider.MAX_CAPTURE_BYTES)
        proof_raw = _read_leaf(fd, "proof.json", 4096)
        signature = _read_leaf(fd, "proof.sshsig", provider.MAX_SIGNATURE_BYTES)
        _verify_nonadmitting_proof(proof_raw, reservation, stdout, stderr)
        if (not signature.startswith(b"-----BEGIN SSH SIGNATURE-----")
            or not signature.rstrip().endswith(b"-----END SSH SIGNATURE-----")):
            raise provider.CaptureDenied("prototype signature envelope is malformed")
        _require_current_directory(root_fd, name, fd)
        return {
            **result,
            "status": "published_prototype_bytes_consistent_signature_unverified",
            "proof_sha256": hashlib.sha256(proof_raw).hexdigest(),
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
        }
    finally:
        os.close(fd)
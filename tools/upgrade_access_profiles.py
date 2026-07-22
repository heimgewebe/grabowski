#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "config" / "access.trusted-owner.example.json"
MAX_POLICY_BYTES = 4 * 1024 * 1024


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


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_descriptor(descriptor: int, *, max_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > max_bytes:
        raise ValueError("policy exceeds maximum size")
    return payload


def _open_locked_policy(path: Path) -> tuple[int, bytes, tuple[int, ...]]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or _identity(opened) != _identity(linked)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) not in {0o400, 0o600}
            or opened.st_size > MAX_POLICY_BYTES
        ):
            raise ValueError("policy must be one private regular file")
        payload = _read_descriptor(descriptor, max_bytes=MAX_POLICY_BYTES)
        after = os.fstat(descriptor)
        rebound = path.lstat()
        if _identity(opened) != _identity(after) or _identity(opened) != _identity(rebound):
            raise ValueError("policy changed while reading")
        return descriptor, payload, _identity(opened)
    except Exception:
        os.close(descriptor)
        raise


def _load_json_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def upgraded(policy: dict[str, Any], template: dict[str, Any]) -> dict[str, Any]:
    if policy.get("version") != 2:
        raise ValueError("only version 2 policies are supported")
    profiles = policy.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError("policy profiles are invalid")
    trusted_owner = profiles.get("trusted-owner")
    if not isinstance(trusted_owner, dict):
        raise ValueError("policy must contain a valid trusted-owner profile")

    template_profiles = template.get("profiles")
    if not isinstance(template_profiles, dict):
        raise ValueError("template profiles are invalid")
    observe = template_profiles.get("observe")
    maintain = template_profiles.get("maintain")
    if not isinstance(observe, dict) or not isinstance(maintain, dict):
        raise ValueError("template must contain valid observe and maintain profiles")

    active_profile = policy.get("active_profile", "trusted-owner")
    if not isinstance(active_profile, str):
        raise ValueError("active profile is invalid")

    policy_definitions = policy.get("capability_definitions")
    template_definitions = template.get("capability_definitions")
    if policy_definitions is not None and not isinstance(policy_definitions, dict):
        raise ValueError("policy capability definitions are invalid")
    if template_definitions is not None and not isinstance(template_definitions, dict):
        raise ValueError("template capability definitions are invalid")

    result = copy.deepcopy(policy)
    if isinstance(template_definitions, dict):
        merged_definitions = copy.deepcopy(policy_definitions or {})
        for capability, description in template_definitions.items():
            if capability not in merged_definitions:
                merged_definitions[capability] = copy.deepcopy(description)
        result["capability_definitions"] = merged_definitions
    result["profiles"] = {
        "observe": copy.deepcopy(observe),
        "maintain": copy.deepcopy(maintain),
        "trusted-owner": copy.deepcopy(trusted_owner),
    }
    result["active_profile"] = active_profile
    if active_profile not in result["profiles"]:
        raise ValueError("active profile would be lost")
    if result["profiles"]["trusted-owner"] != trusted_owner:
        raise ValueError("trusted-owner authority changed during upgrade")
    return result


def _atomic_replace(
    path: Path,
    payload: bytes,
    *,
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_sha256: str,
) -> None:
    parent = path.parent
    parent_metadata = parent.lstat()
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise ValueError("policy parent must be a non-symlink directory")

    current = path.lstat()
    current_payload = _read_descriptor(descriptor, max_bytes=MAX_POLICY_BYTES)
    current_descriptor_metadata = os.fstat(descriptor)
    if (
        _identity(current) != expected_identity
        or _identity(current_descriptor_metadata) != expected_identity
        or _sha256_bytes(current_payload) != expected_sha256
    ):
        raise ValueError("policy changed before atomic replace")

    temporary_descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    try:
        with os.fdopen(temporary_descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary_metadata = os.lstat(temporary)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_nlink != 1
        ):
            raise ValueError("temporary policy file is unsafe")

        final_current = path.lstat()
        final_descriptor_metadata = os.fstat(descriptor)
        if (
            _identity(final_current) != expected_identity
            or _identity(final_descriptor_metadata) != expected_identity
        ):
            raise ValueError("policy identity drifted before atomic replace")
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        published = path.lstat()
        if (
            not stat.S_ISREG(published.st_mode)
            or stat.S_IMODE(published.st_mode) != 0o600
            or published.st_nlink != 1
        ):
            raise ValueError("published policy file is unsafe")
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    path = Path(os.path.abspath(os.fspath(args.policy.expanduser())))
    descriptor: int | None = None
    try:
        descriptor, policy_bytes, policy_identity = _open_locked_policy(path)
        before = _sha256_bytes(policy_bytes)
        if args.expected_sha256 and before != args.expected_sha256:
            raise SystemExit("policy SHA-256 precondition failed")

        policy = _load_json_object(policy_bytes, label="policy")
        template = _load_json_object(TEMPLATE.read_bytes(), label="template")
        result = upgraded(policy, template)
        encoded = (
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        after = _sha256_bytes(encoded)
        if args.apply and before != after:
            _atomic_replace(
                path,
                encoded,
                descriptor=descriptor,
                expected_identity=policy_identity,
                expected_sha256=before,
            )
        print(json.dumps({
            "schema_version": 1,
            "path": str(path),
            "applied": bool(args.apply and before != after),
            "changed": before != after,
            "before_sha256": before,
            "after_sha256": after,
            "active_profile": result["active_profile"],
            "profiles": sorted(result["profiles"]),
            "does_not_establish": [
                "client_tool_snapshot_refresh",
                "new_action_authority",
            ],
        }, sort_keys=True))
        return 0
    finally:
        if descriptor is not None:
            os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())

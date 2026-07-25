from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any


class MergeDeliveryError(RuntimeError):
    """Fail-closed merge-delivery contract error."""


TEXT_ARTIFACT_ROOT = Path.home() / ".local/state/grabowski/text-artifacts"
MERGE_DELIVERY_ROOT = Path.home() / ".local/state/grabowski/merge-deliveries"
MERGE_DELIVERY_SCHEMA = "grabowski-merge-delivery-receipt.v1"
TEXT_ARTIFACT_SCHEMA = "git-diff-artifact.v1"
TEXT_ARTIFACT_PROFILE = "git-diff.v1"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_DELIVERY_REFERENCE_BYTES = 4096
MAX_DELIVERY_AGE_SECONDS = 3600
CLOCK_SKEW_TOLERANCE_SECONDS = 120
GITHUB_TIMESTAMP_UNCERTAINTY_NS = 1_000_000_000
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
ARTIFACT_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
CHANNEL_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")

_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "repository",
        "pull_request",
        "base_sha",
        "head_sha",
        "diff_sha256",
        "artifact_id",
        "artifact_sha256",
        "artifact_receipt_sha256",
        "artifact_repository_path_sha256",
        "artifact_filename",
        "artifact_byte_size",
        "artifact_created_at_unix_ns",
        "delivery_channel",
        "delivery_reference",
        "delivery_reference_sha256",
        "delivery_confirmed_at_unix_ns",
        "expires_at_unix_ns",
        "clock_domain",
        "ordering_uncertainty_ns",
        "binding_sha256",
        "does_not_establish",
    }
)

_DOES_NOT_ESTABLISH = (
    "that_the_user_opened_or_downloaded_the_artifact",
    "artifact_or_review_correctness",
    "merge_authority",
    "ci_green",
    "production_safety",
)


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or COMMIT_SHA_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a full lowercase Git commit SHA")
    return value


def _validate_repository(value: Any) -> str:
    if not isinstance(value, str) or REPOSITORY_RE.fullmatch(value) is None:
        raise ValueError("repository must be an owner/repository identity")
    return value


def _validate_pull_request(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("pull_request must be a positive integer")
    return value


def _validate_artifact_id(value: Any) -> str:
    if not isinstance(value, str) or ARTIFACT_ID_RE.fullmatch(value) is None:
        raise ValueError("artifact_id must be 32 lowercase hexadecimal characters")
    return value


def _validate_channel(value: Any) -> str:
    if not isinstance(value, str) or CHANNEL_RE.fullmatch(value) is None:
        raise ValueError("delivery_channel must be one conservative lowercase token")
    return value


def _validate_reference(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("delivery_reference must be a non-empty trimmed string")
    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("delivery_reference must be a single line")
    if len(value.encode("utf-8")) > MAX_DELIVERY_REFERENCE_BYTES:
        raise ValueError("delivery_reference exceeds the size limit")
    return value


def _private_directory(path: Path, *, create: bool) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise MergeDeliveryError("merge-delivery directory is missing") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise MergeDeliveryError("merge-delivery directory is not private and owner-controlled")
    return path


def _private_regular_file(path: Path, *, max_bytes: int) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise MergeDeliveryError("merge-delivery evidence file is missing") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > max_bytes
    ):
        raise MergeDeliveryError("merge-delivery evidence file is not one private regular file")
    return metadata


def _read_stable_bytes(path: Path, *, max_bytes: int) -> bytes:
    before = _private_regular_file(path, max_bytes=max_bytes)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if opened_identity != before_identity:
            raise MergeDeliveryError("merge-delivery evidence changed before reading")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 64 * 1024))
            if not block:
                raise MergeDeliveryError("merge-delivery evidence ended early")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        linked = os.lstat(path)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        linked_identity = (
            linked.st_dev,
            linked.st_ino,
            linked.st_mode,
            linked.st_nlink,
            linked.st_uid,
            linked.st_gid,
            linked.st_size,
            linked.st_mtime_ns,
            linked.st_ctime_ns,
        )
        if after_identity != before_identity or linked_identity != before_identity:
            raise MergeDeliveryError("merge-delivery evidence changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_canonical_json(
    path: Path,
    *,
    expected_sha256: str,
    max_bytes: int = MAX_RECEIPT_BYTES,
) -> tuple[dict[str, Any], bytes]:
    raw = _read_stable_bytes(path, max_bytes=max_bytes)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise MergeDeliveryError("receipt hash precondition failed")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MergeDeliveryError("receipt is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        raise MergeDeliveryError("receipt is not canonical JSON")
    return value, raw


def _hash_stable_file(path: Path, *, max_bytes: int) -> tuple[str, int]:
    raw = _read_stable_bytes(path, max_bytes=max_bytes)
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _artifact_evidence(
    *,
    artifact_id: str,
    artifact_sha256: str,
    artifact_receipt_sha256: str,
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    diff_sha256: str,
    artifact_root: Path,
) -> dict[str, Any]:
    artifact_directory = _private_directory(artifact_root / artifact_id, create=False)
    receipt, _ = _read_canonical_json(
        artifact_directory / "receipt.json",
        expected_sha256=artifact_receipt_sha256,
    )
    required = {
        "schema",
        "profile",
        "artifact_id",
        "repository",
        "repository_path_sha256",
        "base_commit",
        "head_commit",
        "pull_request_number",
        "filename",
        "diff_sha256",
        "byte_size",
        "generated_at_unix",
        "encoding",
        "format",
    }
    if set(receipt) != required:
        raise MergeDeliveryError("text artifact receipt fields are invalid")
    if (
        receipt.get("schema") != TEXT_ARTIFACT_SCHEMA
        or receipt.get("profile") != TEXT_ARTIFACT_PROFILE
        or receipt.get("artifact_id") != artifact_id
        or receipt.get("repository") != repository
        or receipt.get("base_commit") != base_sha
        or receipt.get("head_commit") != head_sha
        or receipt.get("pull_request_number") != pull_request
        or receipt.get("diff_sha256") != diff_sha256
        or receipt.get("diff_sha256") != artifact_sha256
        or receipt.get("encoding") != "utf-8"
        or receipt.get("format") != "unified-diff"
    ):
        raise MergeDeliveryError("text artifact receipt does not match the merge binding")
    repository_path_sha256 = _validate_sha256(
        receipt.get("repository_path_sha256"), "repository_path_sha256"
    )
    filename = receipt.get("filename")
    byte_size = receipt.get("byte_size")
    generated_at = receipt.get("generated_at_unix")
    if not isinstance(filename, str) or not filename.endswith(".txt") or Path(filename).name != filename:
        raise MergeDeliveryError("text artifact filename is invalid")
    if isinstance(byte_size, bool) or not isinstance(byte_size, int) or byte_size < 1:
        raise MergeDeliveryError("text artifact byte size is invalid")
    if isinstance(generated_at, bool) or not isinstance(generated_at, int) or generated_at < 1:
        raise MergeDeliveryError("text artifact generated_at is invalid")
    observed_sha, observed_size = _hash_stable_file(
        artifact_directory / filename,
        max_bytes=byte_size,
    )
    if observed_sha != artifact_sha256 or observed_size != byte_size:
        raise MergeDeliveryError("text artifact payload failed integrity verification")
    return {
        "filename": filename,
        "byte_size": byte_size,
        "generated_at_unix": generated_at,
        "repository_path_sha256": repository_path_sha256,
    }


def _binding(
    *,
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    diff_sha256: str,
) -> dict[str, Any]:
    return {
        "repository": repository,
        "pull_request": pull_request,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "diff_sha256": diff_sha256,
    }


def _receipt_path(root: Path, receipt: dict[str, Any]) -> Path:
    repo_key = hashlib.sha256(receipt["repository"].encode("utf-8")).hexdigest()
    return (
        root
        / repo_key
        / f"pr-{receipt['pull_request']}"
        / f"{receipt['binding_sha256']}-{receipt['artifact_id']}.json"
    )


def record_merge_delivery(
    *,
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    diff_sha256: str,
    artifact_id: str,
    artifact_sha256: str,
    artifact_receipt_sha256: str,
    delivery_channel: str,
    delivery_reference: str,
    root: Path | None = None,
    artifact_root: Path | None = None,
    now_ns: int | None = None,
) -> dict[str, Any]:
    repository = _validate_repository(repository)
    pull_request = _validate_pull_request(pull_request)
    base_sha = _validate_commit(base_sha, "base_sha")
    head_sha = _validate_commit(head_sha, "head_sha")
    diff_sha256 = _validate_sha256(diff_sha256, "diff_sha256")
    artifact_id = _validate_artifact_id(artifact_id)
    artifact_sha256 = _validate_sha256(artifact_sha256, "artifact_sha256")
    artifact_receipt_sha256 = _validate_sha256(artifact_receipt_sha256, "artifact_receipt_sha256")
    delivery_channel = _validate_channel(delivery_channel)
    delivery_reference = _validate_reference(delivery_reference)
    if artifact_sha256 != diff_sha256:
        raise MergeDeliveryError("artifact_sha256 must equal diff_sha256")
    destination_root = root or MERGE_DELIVERY_ROOT
    source_root = artifact_root or TEXT_ARTIFACT_ROOT
    artifact = _artifact_evidence(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        artifact_receipt_sha256=artifact_receipt_sha256,
        repository=repository,
        pull_request=pull_request,
        base_sha=base_sha,
        head_sha=head_sha,
        diff_sha256=diff_sha256,
        artifact_root=source_root,
    )
    observed_now_ns = time.time_ns() if now_ns is None else now_ns
    if isinstance(observed_now_ns, bool) or not isinstance(observed_now_ns, int) or observed_now_ns < 1:
        raise ValueError("now_ns must be a positive integer")
    binding = _binding(
        repository=repository,
        pull_request=pull_request,
        base_sha=base_sha,
        head_sha=head_sha,
        diff_sha256=diff_sha256,
    )
    binding_sha256 = sha256_json(binding)
    receipt: dict[str, Any] = {
        "schema": MERGE_DELIVERY_SCHEMA,
        "kind": "user-visible-diff-delivery",
        **binding,
        "artifact_id": artifact_id,
        "artifact_sha256": artifact_sha256,
        "artifact_receipt_sha256": artifact_receipt_sha256,
        "artifact_repository_path_sha256": artifact["repository_path_sha256"],
        "artifact_filename": artifact["filename"],
        "artifact_byte_size": artifact["byte_size"],
        "artifact_created_at_unix_ns": artifact["generated_at_unix"] * 1_000_000_000,
        "delivery_channel": delivery_channel,
        "delivery_reference": delivery_reference,
        "delivery_reference_sha256": hashlib.sha256(delivery_reference.encode("utf-8")).hexdigest(),
        "delivery_confirmed_at_unix_ns": observed_now_ns,
        "expires_at_unix_ns": observed_now_ns + MAX_DELIVERY_AGE_SECONDS * 1_000_000_000,
        "clock_domain": "unix-realtime",
        "ordering_uncertainty_ns": GITHUB_TIMESTAMP_UNCERTAINTY_NS,
        "binding_sha256": binding_sha256,
        "does_not_establish": list(_DOES_NOT_ESTABLISH),
    }
    raw = canonical_json_bytes(receipt)
    receipt_sha256 = hashlib.sha256(raw).hexdigest()
    _private_directory(destination_root, create=True)
    repo_directory = _private_directory(
        destination_root / hashlib.sha256(repository.encode("utf-8")).hexdigest(),
        create=True,
    )
    pr_directory = _private_directory(repo_directory / f"pr-{pull_request}", create=True)
    lock_path = pr_directory / ".delivery.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_uid != os.geteuid()
            or lock_metadata.st_nlink != 1
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
        ):
            raise MergeDeliveryError("merge-delivery lock is not private")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        receipt_path = _receipt_path(destination_root, receipt)
        if receipt_path.exists() or receipt_path.is_symlink():
            existing_raw = _read_stable_bytes(receipt_path, max_bytes=MAX_RECEIPT_BYTES)
            existing_sha = hashlib.sha256(existing_raw).hexdigest()
            existing, _ = _read_canonical_json(receipt_path, expected_sha256=existing_sha)
            stable_keys = set(receipt) - {"delivery_confirmed_at_unix_ns", "expires_at_unix_ns"}
            if {key: existing.get(key) for key in stable_keys} != {
                key: receipt[key] for key in stable_keys
            }:
                raise MergeDeliveryError("a conflicting delivery receipt already exists for this binding")
            receipt = existing
            raw = existing_raw
            receipt_sha256 = existing_sha
        else:
            file_descriptor = os.open(
                receipt_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                written = 0
                while written < len(raw):
                    written += os.write(file_descriptor, raw[written:])
                os.fsync(file_descriptor)
            finally:
                os.close(file_descriptor)
            directory_descriptor = os.open(pr_directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        os.close(descriptor)
    return {
        "receipt": receipt,
        "receipt_sha256": receipt_sha256,
        "receipt_path": str(_receipt_path(destination_root, receipt)),
        "binding_sha256": receipt["binding_sha256"],
        "delivery_confirmed": True,
    }


def validate_delivery_receipt_snapshot(
    receipt: Any,
    *,
    expected_repository: str,
    expected_pull_request: int,
    expected_base_sha: str,
    expected_head_sha: str,
    expected_diff_sha256: str,
    expected_receipt_sha256: str,
    now_ns: int | None = None,
) -> dict[str, Any]:
    expected_repository = _validate_repository(expected_repository)
    expected_pull_request = _validate_pull_request(expected_pull_request)
    expected_base_sha = _validate_commit(expected_base_sha, "expected_base_sha")
    expected_head_sha = _validate_commit(expected_head_sha, "expected_head_sha")
    expected_diff_sha256 = _validate_sha256(expected_diff_sha256, "expected_diff_sha256")
    expected_receipt_sha256 = _validate_sha256(expected_receipt_sha256, "expected_receipt_sha256")
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_FIELDS:
        raise MergeDeliveryError("merge-delivery receipt fields are invalid")
    if hashlib.sha256(canonical_json_bytes(receipt)).hexdigest() != expected_receipt_sha256:
        raise MergeDeliveryError("merge-delivery receipt digest mismatch")
    if receipt.get("schema") != MERGE_DELIVERY_SCHEMA or receipt.get("kind") != "user-visible-diff-delivery":
        raise MergeDeliveryError("merge-delivery receipt schema or kind is invalid")
    expected_binding = _binding(
        repository=expected_repository,
        pull_request=expected_pull_request,
        base_sha=expected_base_sha,
        head_sha=expected_head_sha,
        diff_sha256=expected_diff_sha256,
    )
    for key, value in expected_binding.items():
        if receipt.get(key) != value:
            raise MergeDeliveryError(f"merge-delivery receipt {key} mismatch")
    if receipt.get("binding_sha256") != sha256_json(expected_binding):
        raise MergeDeliveryError("merge-delivery binding digest mismatch")
    _validate_artifact_id(receipt.get("artifact_id"))
    _validate_sha256(receipt.get("artifact_sha256"), "artifact_sha256")
    _validate_sha256(receipt.get("artifact_receipt_sha256"), "artifact_receipt_sha256")
    _validate_sha256(
        receipt.get("artifact_repository_path_sha256"),
        "artifact_repository_path_sha256",
    )
    if receipt.get("artifact_sha256") != expected_diff_sha256:
        raise MergeDeliveryError("merge-delivery artifact digest mismatch")
    _validate_channel(receipt.get("delivery_channel"))
    reference = _validate_reference(receipt.get("delivery_reference"))
    if receipt.get("delivery_reference_sha256") != hashlib.sha256(reference.encode("utf-8")).hexdigest():
        raise MergeDeliveryError("merge-delivery reference digest mismatch")
    artifact_size = receipt.get("artifact_byte_size")
    artifact_created_ns = receipt.get("artifact_created_at_unix_ns")
    delivered_ns = receipt.get("delivery_confirmed_at_unix_ns")
    expires_ns = receipt.get("expires_at_unix_ns")
    uncertainty_ns = receipt.get("ordering_uncertainty_ns")
    for label, value in (
        ("artifact_byte_size", artifact_size),
        ("artifact_created_at_unix_ns", artifact_created_ns),
        ("delivery_confirmed_at_unix_ns", delivered_ns),
        ("expires_at_unix_ns", expires_ns),
        ("ordering_uncertainty_ns", uncertainty_ns),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise MergeDeliveryError(f"merge-delivery {label} is invalid")
    if receipt.get("clock_domain") != "unix-realtime":
        raise MergeDeliveryError("merge-delivery clock domain is invalid")
    if receipt.get("does_not_establish") != list(_DOES_NOT_ESTABLISH):
        raise MergeDeliveryError("merge-delivery non-claims are invalid")
    if artifact_created_ns > delivered_ns + uncertainty_ns:
        raise MergeDeliveryError("merge-delivery timestamp ordering is invalid")
    if expires_ns != delivered_ns + MAX_DELIVERY_AGE_SECONDS * 1_000_000_000:
        raise MergeDeliveryError("merge-delivery expiry binding is invalid")
    observed_now_ns = time.time_ns() if now_ns is None else now_ns
    if isinstance(observed_now_ns, bool) or not isinstance(observed_now_ns, int) or observed_now_ns < 1:
        raise ValueError("now_ns must be a positive integer")
    if observed_now_ns + CLOCK_SKEW_TOLERANCE_SECONDS * 1_000_000_000 < delivered_ns:
        raise MergeDeliveryError("merge-delivery receipt is from the future")
    if observed_now_ns > expires_ns:
        raise MergeDeliveryError("merge-delivery receipt is stale")
    return {
        "valid": True,
        "receipt_sha256": expected_receipt_sha256,
        "binding_sha256": receipt["binding_sha256"],
        "artifact_id": receipt["artifact_id"],
        "artifact_receipt_sha256": receipt["artifact_receipt_sha256"],
        "artifact_repository_path_sha256": receipt["artifact_repository_path_sha256"],
        "artifact_filename": receipt["artifact_filename"],
        "artifact_byte_size": artifact_size,
        "delivery_channel": receipt["delivery_channel"],
        "delivery_reference_sha256": receipt["delivery_reference_sha256"],
        "artifact_created_at_unix_ns": artifact_created_ns,
        "delivery_confirmed_at_unix_ns": delivered_ns,
        "expires_at_unix_ns": expires_ns,
        "clock_domain": receipt["clock_domain"],
        "ordering_uncertainty_ns": uncertainty_ns,
        "does_not_establish": list(_DOES_NOT_ESTABLISH),
    }


def verify_merge_delivery(
    receipt: Any,
    *,
    expected_repository: str,
    expected_pull_request: int,
    expected_base_sha: str,
    expected_head_sha: str,
    expected_diff_sha256: str,
    expected_receipt_sha256: str,
    root: Path | None = None,
    artifact_root: Path | None = None,
    now_ns: int | None = None,
) -> dict[str, Any]:
    info = validate_delivery_receipt_snapshot(
        receipt,
        expected_repository=expected_repository,
        expected_pull_request=expected_pull_request,
        expected_base_sha=expected_base_sha,
        expected_head_sha=expected_head_sha,
        expected_diff_sha256=expected_diff_sha256,
        expected_receipt_sha256=expected_receipt_sha256,
        now_ns=now_ns,
    )
    if not isinstance(receipt, dict):
        raise MergeDeliveryError("merge-delivery receipt is invalid")
    destination_root = root or MERGE_DELIVERY_ROOT
    receipt_path = _receipt_path(destination_root, receipt)
    stored, _ = _read_canonical_json(receipt_path, expected_sha256=expected_receipt_sha256)
    if stored != receipt:
        raise MergeDeliveryError("stored merge-delivery receipt differs from request")
    artifact_info = _artifact_evidence(
        artifact_id=receipt["artifact_id"],
        artifact_sha256=receipt["artifact_sha256"],
        artifact_receipt_sha256=receipt["artifact_receipt_sha256"],
        repository=expected_repository,
        pull_request=expected_pull_request,
        base_sha=expected_base_sha,
        head_sha=expected_head_sha,
        diff_sha256=expected_diff_sha256,
        artifact_root=artifact_root or TEXT_ARTIFACT_ROOT,
    )
    expected_artifact_binding = {
        "artifact_repository_path_sha256": artifact_info["repository_path_sha256"],
        "artifact_filename": artifact_info["filename"],
        "artifact_byte_size": artifact_info["byte_size"],
        "artifact_created_at_unix_ns": artifact_info["generated_at_unix"]
        * 1_000_000_000,
    }
    for field, expected_value in expected_artifact_binding.items():
        if receipt.get(field) != expected_value:
            raise MergeDeliveryError(
                f"merge-delivery receipt {field} drifted from the text artifact"
            )
    return {**info, "receipt_path": str(receipt_path), "durable": True}


def github_timestamp_unix_ns(value: Any) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return int(parsed.astimezone(timezone.utc).timestamp() * 1_000_000_000)


def github_merge_ordering(
    delivery_info: dict[str, Any],
    merged_at_unix_ns: int | None,
) -> dict[str, Any]:
    delivered_ns = delivery_info.get("delivery_confirmed_at_unix_ns")
    uncertainty_ns = delivery_info.get("ordering_uncertainty_ns", GITHUB_TIMESTAMP_UNCERTAINTY_NS)
    if (
        isinstance(delivered_ns, bool)
        or not isinstance(delivered_ns, int)
        or delivered_ns < 1
        or isinstance(merged_at_unix_ns, bool)
        or not isinstance(merged_at_unix_ns, int)
        or merged_at_unix_ns < 1
    ):
        return {
            "ordering": "unknown",
            "pre_merge_delivery_contract_satisfied": False,
            "reason": "comparable_delivery_or_merge_timestamp_unavailable",
            "post_merge_exposure_is_not_equivalent": True,
        }
    uncertainty_ns = int(uncertainty_ns)
    if delivered_ns + uncertainty_ns <= merged_at_unix_ns:
        ordering = "delivery_before_merge"
        satisfied = True
    elif delivered_ns > merged_at_unix_ns + uncertainty_ns:
        ordering = "delivery_after_merge"
        satisfied = False
    else:
        ordering = "ordering_uncertain"
        satisfied = False
    return {
        "ordering": ordering,
        "pre_merge_delivery_contract_satisfied": satisfied,
        "delivery_confirmed_at_unix_ns": delivered_ns,
        "github_merged_at_unix_ns": merged_at_unix_ns,
        "ordering_uncertainty_ns": uncertainty_ns,
        "post_merge_exposure_is_not_equivalent": True,
    }

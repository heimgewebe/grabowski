#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any

SOURCE_ROOT = Path("/home/alex/worktrees")
SOURCE_NAME_RE = re.compile(r"\.grabowski-platform-snapshot-[0-9a-f]{32}\.json\Z")
DESTINATION = Path("/run/grabowski/platform-connector-snapshot.json")
EXPECTED_SOURCE_UID = 1000
MAX_SNAPSHOT_BYTES = 64 * 1024
SNAPSHOT_KIND = "grabowski_platform_connector_snapshot"
SOURCE_KIND = "chatgpt_connector_catalog"
OBSERVATION_SCOPES = frozenset({"connector_catalog", "new_chat_catalog", "chat_session_catalog"})
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
RELEASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


class CaptureError(RuntimeError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CaptureError(f"{label} is invalid")
    return value


def _require_identifier(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise CaptureError(f"{label} is invalid")
    return value


def _safe_source_path(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise CaptureError("snapshot source path is invalid")
    path = Path(raw)
    if not path.is_absolute() or os.path.normpath(raw) != raw:
        raise CaptureError("snapshot source path must be canonical and absolute")
    if path.parent != SOURCE_ROOT or SOURCE_NAME_RE.fullmatch(path.name) is None:
        raise CaptureError("snapshot source path is outside the fixed capture staging contract")
    return path


def _read_hash_bound_source(path: Path, expected_sha256: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CaptureError("snapshot source cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != EXPECTED_SOURCE_UID
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
            or metadata.st_size > MAX_SNAPSHOT_BYTES
        ):
            raise CaptureError("snapshot source metadata violates the fixed trust contract")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CaptureError("snapshot source ended before its declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CaptureError("snapshot source grew while being read")
        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_dev != metadata.st_dev
            or final_metadata.st_ino != metadata.st_ino
            or final_metadata.st_size != metadata.st_size
        ):
            raise CaptureError("snapshot source changed while being read")
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if _sha256_bytes(data) != expected_sha256:
        raise CaptureError("snapshot source SHA-256 mismatch")
    return data


def _validate_observed_tools(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "tools",
        "complete_schema_count",
        "complete_schema_sha256",
    }:
        raise CaptureError("observed tools contract is invalid")
    if value.get("schema_version") != 2:
        raise CaptureError("observed tools schema version is invalid")
    tools = value.get("tools")
    if not isinstance(tools, list) or not 1 <= len(tools) <= 1000:
        raise CaptureError("observed tools list is invalid")
    names: set[str] = set()
    for item in tools:
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict) and set(item) == {"name", "inputSchema"}:
            name = item.get("name")
            if not isinstance(item.get("inputSchema"), dict):
                raise CaptureError("observed tool schema is invalid")
        else:
            raise CaptureError("observed tool entry is invalid")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 512:
            raise CaptureError("observed tool name is invalid")
        if name in names:
            raise CaptureError("observed tool names must be unique")
        names.add(name)
    count = value.get("complete_schema_count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(tools):
        raise CaptureError("complete schema count does not match observed tool count")
    _require_sha256(value.get("complete_schema_sha256"), label="complete schema SHA-256")


def _validate_snapshot(document: Any) -> str:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "kind",
        "source",
        "runtime_binding",
        "observed_tools",
        "snapshot_sha256",
    }:
        raise CaptureError("platform snapshot fields are invalid")
    if document.get("schema_version") != 2 or document.get("kind") != SNAPSHOT_KIND:
        raise CaptureError("platform snapshot identity is invalid")
    declared_snapshot_sha256 = _require_sha256(
        document.get("snapshot_sha256"), label="snapshot SHA-256"
    )
    unsigned = dict(document)
    unsigned.pop("snapshot_sha256")
    if _sha256_bytes(_canonical_bytes(unsigned)) != declared_snapshot_sha256:
        raise CaptureError("platform snapshot content hash mismatch")

    source = document.get("source")
    if not isinstance(source, dict) or set(source) != {
        "kind",
        "platform",
        "connector_id",
        "observation_scope",
        "observation_id",
        "publication_request_id",
        "requested_contract_sha256",
        "reference",
        "observed_at_unix",
        "catalog_sha256",
    }:
        raise CaptureError("platform snapshot source contract is invalid")
    if (
        source.get("kind") != SOURCE_KIND
        or source.get("platform") != "chatgpt"
        or source.get("connector_id") != "grabowski"
        or source.get("observation_scope") not in OBSERVATION_SCOPES
    ):
        raise CaptureError("platform snapshot source identity is invalid")
    _require_identifier(source.get("observation_id"), label="observation id")
    _require_identifier(source.get("publication_request_id"), label="publication request id")
    _require_sha256(source.get("requested_contract_sha256"), label="requested contract SHA-256")
    reference = source.get("reference")
    if (
        not isinstance(reference, str)
        or not reference
        or reference.strip() != reference
        or len(reference.encode("utf-8")) > 1024
    ):
        raise CaptureError("platform source reference is invalid")
    observed_at = source.get("observed_at_unix")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise CaptureError("platform observation time is invalid")
    catalog_sha256 = _require_sha256(source.get("catalog_sha256"), label="catalog SHA-256")

    binding = document.get("runtime_binding")
    if not isinstance(binding, dict) or set(binding) != {
        "registered_tool_count",
        "registered_names_sha256",
        "release_id",
        "repo_head",
        "agent_instructions_sha256",
    }:
        raise CaptureError("runtime binding contract is invalid")
    count = binding.get("registered_tool_count")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 1000:
        raise CaptureError("runtime tool count is invalid")
    _require_sha256(binding.get("registered_names_sha256"), label="runtime names SHA-256")
    release_id = binding.get("release_id")
    if not isinstance(release_id, str) or RELEASE_RE.fullmatch(release_id) is None:
        raise CaptureError("runtime release id is invalid")
    repo_head = binding.get("repo_head")
    if not isinstance(repo_head, str) or COMMIT_RE.fullmatch(repo_head) is None:
        raise CaptureError("runtime repository head is invalid")
    _require_sha256(
        binding.get("agent_instructions_sha256"), label="agent instructions SHA-256"
    )

    observed_tools = document.get("observed_tools")
    _validate_observed_tools(observed_tools)
    if count != observed_tools["complete_schema_count"]:
        raise CaptureError("runtime and observed tool counts differ")
    if _sha256_bytes(_canonical_bytes(observed_tools)) != catalog_sha256:
        raise CaptureError("observed tools content hash mismatch")
    return declared_snapshot_sha256


def _validate_destination_parent() -> None:
    parent = DESTINATION.parent
    try:
        metadata = parent.lstat()
    except OSError as exc:
        raise CaptureError("platform snapshot destination parent is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CaptureError("platform snapshot destination parent is unsafe")


def _read_existing() -> bytes | None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(DESTINATION, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CaptureError("existing platform snapshot cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > MAX_SNAPSHOT_BYTES
        ):
            raise CaptureError("existing platform snapshot is unsafe")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CaptureError("existing platform snapshot ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CaptureError("existing platform snapshot grew while being read")
        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_dev != metadata.st_dev
            or final_metadata.st_ino != metadata.st_ino
            or final_metadata.st_size != metadata.st_size
        ):
            raise CaptureError("existing platform snapshot changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _persist(data: bytes) -> str:
    _validate_destination_parent()
    existing = _read_existing()
    if existing == data:
        return "already_current"
    parent = DESTINATION.parent
    temporary = parent / f".{DESTINATION.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o644)
        os.fchmod(descriptor, 0o644)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("platform snapshot write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, DESTINATION)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise CaptureError("platform snapshot persistence failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    if _read_existing() != data:
        raise CaptureError("platform snapshot readback mismatch")
    return "published"


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        raise CaptureError("trusted platform snapshot publisher requires root")
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        raise CaptureError("trusted platform snapshot publisher requires one target object")
    try:
        target = json.loads(arguments[0])
    except json.JSONDecodeError as exc:
        raise CaptureError("trusted platform snapshot target is not valid JSON") from exc
    if not isinstance(target, dict) or set(target) != {"source_path", "expected_file_sha256"}:
        raise CaptureError("trusted platform snapshot target contract is invalid")
    source_path = _safe_source_path(target.get("source_path"))
    expected_file_sha256 = _require_sha256(
        target.get("expected_file_sha256"), label="source file SHA-256"
    )
    data = _read_hash_bound_source(source_path, expected_file_sha256)
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError("prepared platform snapshot is not valid UTF-8 JSON") from exc
    snapshot_sha256 = _validate_snapshot(document)
    state = _persist(data)
    print(json.dumps({
        "schema_version": 1,
        "kind": "grabowski_trusted_platform_connector_capture",
        "state": state,
        "snapshot_sha256": snapshot_sha256,
        "file_sha256": expected_file_sha256,
        "does_not_establish": [
            "cryptographic platform origin",
            "future platform catalog stability",
            "execution authority",
        ],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CaptureError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)

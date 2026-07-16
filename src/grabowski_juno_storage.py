from __future__ import annotations

import base64
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

import grabowski_juno as bridge

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
MUTATING = operator.MUTATING

SCHEMA_VERSION = 1
GRANT_ID_RE = re.compile(r"^grant-[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_RELATIVE_PATH_BYTES = 2_048
MAX_PROVIDER_BYTES = 256
MAX_PATH_SEGMENTS = 64
MAX_READ_BYTES = 512 * 1024
MAX_WRITE_BYTES = 1024 * 1024
MAX_DIRECTORY_ENTRIES = 500
MAX_DIRECTORY_SCAN_ENTRIES = 4_096
MAX_GRANT_RECORD_BYTES = 128 * 1024
MAX_DEVICE_FILE_BYTES = 16 * 1024 * 1024

_STORAGE_JOB_SOURCE = r"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid
from typing import Any

from juno.objc import ObjCClass, ns, nsdata_to_bytes, py_from_ns


SCHEMA_VERSION = 1
GRANT_ID_RE = re.compile(r"^grant-[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_GRANT_RECORD_BYTES = 128 * 1024
MAX_DEVICE_FILE_BYTES = 16 * 1024 * 1024
MAX_DIRECTORY_SCAN_ENTRIES = 4_096
BOOKMARK_RESOLUTION_WITH_SECURITY_SCOPE = 1 << 10


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _zero_arg(value: Any) -> Any:
    return value() if callable(value) else value


def _state_root() -> Path:
    return (
        Path.home().resolve(strict=False)
        / "Library"
        / "Application Support"
        / "GrabowskiJunoAgent"
    )


def _grants_root() -> Path:
    return _state_root() / "storage-grants"


def _validated_grants_root(*, required: bool) -> Path | None:
    root = _grants_root()
    if not os.path.lexists(root):
        if required:
            raise FileNotFoundError("storage grants root does not exist")
        return None
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RuntimeError("unsafe storage grants root")
    return root


def _read_private_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_GRANT_RECORD_BYTES
        ):
            raise RuntimeError("unsafe storage grant record")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError("short storage grant record read")
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("invalid storage grant JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("storage grant is not an object")
    return value


def _safe_grant_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record.get(key)
        for key in (
            "schema_version",
            "kind",
            "grant_id",
            "selected_path",
            "selected_name",
            "provider_hint",
            "bookmark_sha256",
            "evidence_hash",
            "created_at",
            "exists",
            "readable",
            "writable",
            "externally_granted",
            "limitations",
        )
    }


def _validate_grant_record(record: dict[str, Any], expected_grant_id: str) -> bytes:
    if record.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("unsupported storage grant schema")
    if record.get("kind") != "grabowski_juno_storage_grant":
        raise RuntimeError("unexpected storage grant kind")
    if record.get("grant_id") != expected_grant_id:
        raise RuntimeError("storage grant id mismatch")
    bookmark_b64 = record.get("bookmark_b64")
    bookmark_sha256 = record.get("bookmark_sha256")
    evidence_hash = record.get("evidence_hash")
    if not isinstance(bookmark_b64, str):
        raise RuntimeError("storage grant bookmark is missing")
    if not isinstance(bookmark_sha256, str) or SHA256_RE.fullmatch(bookmark_sha256) is None:
        raise RuntimeError("storage grant bookmark hash is invalid")
    if not isinstance(evidence_hash, str) or SHA256_RE.fullmatch(evidence_hash) is None:
        raise RuntimeError("storage grant evidence hash is invalid")
    try:
        bookmark = base64.b64decode(bookmark_b64, validate=True)
    except Exception as exc:
        raise RuntimeError("storage grant bookmark encoding is invalid") from exc
    if not bookmark or _sha256_bytes(bookmark) != bookmark_sha256:
        raise RuntimeError("storage grant bookmark hash mismatch")
    evidence_material = {
        key: record.get(key)
        for key in (
            "schema_version",
            "grant_id",
            "selected_path",
            "selected_name",
            "provider_hint",
            "bookmark_sha256",
            "bookmark_creation_options",
            "bookmark_resolution_options",
            "created_at",
            "exists",
            "readable",
            "writable",
            "externally_granted",
        )
    }
    if _sha256_bytes(_canonical_json_bytes(evidence_material)) != evidence_hash:
        raise RuntimeError("storage grant evidence hash mismatch")
    selected_path = record.get("selected_path")
    provider_hint = record.get("provider_hint")
    if (
        not isinstance(selected_path, str)
        or not Path(selected_path).is_absolute()
        or not isinstance(provider_hint, str)
        or not provider_hint
        or record.get("externally_granted") is not True
    ):
        raise RuntimeError("storage grant identity fields are invalid")
    return bookmark


def _load_grant(grant_id: str) -> tuple[dict[str, Any], bytes]:
    if not isinstance(grant_id, str) or GRANT_ID_RE.fullmatch(grant_id) is None:
        raise ValueError("invalid grant id")
    root = _validated_grants_root(required=True)
    assert root is not None
    record = _read_private_json(root / f"{grant_id}.json")
    return record, _validate_grant_record(record, grant_id)


def _iter_grants() -> list[dict[str, Any]]:
    root = _validated_grants_root(required=False)
    if root is None:
        return []
    records = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if len(records) >= 256:
            break
        if path.suffix != ".json" or path.is_symlink():
            continue
        grant_id = path.stem
        if GRANT_ID_RE.fullmatch(grant_id) is None:
            continue
        try:
            record = _read_private_json(path)
            _validate_grant_record(record, grant_id)
            records.append(_safe_grant_summary(record))
        except Exception as exc:
            records.append(
                {
                    "grant_id": grant_id,
                    "valid": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:300],
                }
            )
    return records


def _url_path(url: Any) -> Path:
    raw = _zero_arg(url.path)
    converted = py_from_ns(raw)
    if not isinstance(converted, str) or not converted:
        converted = str(raw)
    path = Path(converted).resolve(strict=False)
    if not path.is_absolute():
        raise RuntimeError("resolved grant path is not absolute")
    return path


def _resolve_grant(record: dict[str, Any], bookmark: bytes) -> tuple[Any, Path, None]:
    NSURL = ObjCClass("NSURL")
    bookmark_data = ns(bookmark)
    resolved = (
        NSURL.URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
            bookmark_data,
            BOOKMARK_RESOLUTION_WITH_SECURITY_SCOPE,
            None,
            None,
            None,
        )
    )
    if resolved is None:
        raise RuntimeError("storage grant bookmark cannot be resolved")
    scoped = bool(resolved.startAccessingSecurityScopedResource())
    if not scoped:
        raise RuntimeError("storage grant security scope cannot be opened")
    path = _url_path(resolved)
    expected_path = record.get("selected_path")
    if not isinstance(expected_path, str) or path != Path(expected_path).resolve(strict=False):
        resolved.stopAccessingSecurityScopedResource()
        raise RuntimeError("storage grant resolved path changed")
    return resolved, path, None


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    if relative_path == "":
        return ()
    raw_parts = relative_path.split("/")
    if any(part in {"", ".", ".."} or "\x00" in part for part in raw_parts):
        raise ValueError("relative path contains an unsafe segment")
    path = PurePosixPath(relative_path)
    if path.is_absolute():
        raise ValueError("relative path must not be absolute")
    return tuple(path.parts)


def _target(root: Path, relative_path: str) -> Path:
    parts = _relative_parts(relative_path)
    root_resolved = root.resolve(strict=False)
    if not parts:
        return root_resolved
    candidate = root_resolved.joinpath(*parts)
    parent_resolved = candidate.parent.resolve(strict=False)
    if os.path.commonpath([str(root_resolved), str(parent_resolved)]) != str(root_resolved):
        raise PermissionError("relative path escapes the granted root")
    current = root_resolved
    for part in parts[:-1]:
        current = current / part
        if not current.exists():
            raise FileNotFoundError(f"parent path does not exist: {part}")
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PermissionError("relative path crosses a symlink or non-directory")
    if os.path.lexists(candidate) and stat.S_ISLNK(candidate.lstat().st_mode):
        raise PermissionError("target path is a symlink")
    return candidate


def _stat_entry(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        entry_type = "symlink"
    elif stat.S_ISREG(metadata.st_mode):
        entry_type = "file"
    elif stat.S_ISDIR(metadata.st_mode):
        entry_type = "directory"
    else:
        entry_type = "other"
    return {
        "name": path.name,
        "path_type": entry_type,
        "size": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
        "readable": os.access(path, os.R_OK),
        "writable": os.access(path, os.W_OK),
    }


def _read_file(path: Path, max_bytes: int) -> tuple[bytes, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("target is not a regular file")
        if metadata.st_nlink != 1:
            raise PermissionError("target regular file has multiple hard links")
        if metadata.st_size > max_bytes:
            raise ValueError("file exceeds the requested read bound")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError("short file read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_nlink,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        if identity_before != identity_after:
            raise RuntimeError("file changed during read")
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    return payload, {
        "size": len(payload),
        "sha256": _sha256_bytes(payload),
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
    }


def _decode_payload(request: dict[str, Any]) -> bytes:
    payload_b64 = request.get("payload_b64")
    expected = request.get("payload_sha256")
    if not isinstance(payload_b64, str):
        raise ValueError("payload_b64 is missing")
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        raise ValueError("payload_sha256 is invalid")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise ValueError("payload_b64 is invalid") from exc
    if len(payload) > int(request.get("max_write_bytes", 0)):
        raise ValueError("payload exceeds the write bound")
    if _sha256_bytes(payload) != expected:
        raise ValueError("payload hash mismatch")
    return payload


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise RuntimeError("short file write")
        offset += written
    os.fsync(descriptor)


def _create_file(path: Path, payload: bytes) -> dict[str, Any]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, payload)
    finally:
        os.close(descriptor)
    readback, metadata = _read_file(path, len(payload))
    if readback != payload:
        raise RuntimeError("create readback differs from payload")
    return metadata


def _replace_file(path: Path, payload: bytes, expected_sha256: str) -> dict[str, Any]:
    _current, before = _read_file(path, MAX_DEVICE_FILE_BYTES)
    if before["sha256"] != expected_sha256:
        raise RuntimeError("existing file hash does not match expected_sha256")
    temporary = path.parent / f".grabowski-replace-{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        _write_all(descriptor, payload)
    finally:
        os.close(descriptor)
    try:
        _pre_replace_payload, pre_replace = _read_file(path, MAX_DEVICE_FILE_BYTES)
        if pre_replace["sha256"] != expected_sha256:
            raise RuntimeError("existing file changed before replace")
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    durability = {"directory_fsync": False, "error_type": None}
    try:
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
            durability["directory_fsync"] = True
        finally:
            os.close(directory_descriptor)
    except OSError as exc:
        durability["error_type"] = type(exc).__name__
    readback, after = _read_file(path, len(payload))
    if readback != payload:
        raise RuntimeError("replace readback differs from payload")
    return {
        "before": before,
        "pre_replace": pre_replace,
        "after": after,
        "durability": durability,
        "limitations": [
            "a concurrent writer can still race between final preimage check and same-directory replace",
            "document-provider replace and durability semantics are provider-dependent",
        ],
    }


def _grant_context(request: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    grant_id = request.get("grant_id")
    record, bookmark = _load_grant(grant_id)
    expected_evidence = request.get("expected_grant_evidence_hash")
    if expected_evidence is not None and record.get("evidence_hash") != expected_evidence:
        raise RuntimeError("storage grant evidence hash changed")
    expected_provider = request.get("expected_provider")
    if expected_provider is not None and record.get("provider_hint") != expected_provider:
        raise RuntimeError("storage grant provider changed")
    return record, bookmark


def _with_grant(request: dict[str, Any], action):
    record, bookmark = _grant_context(request)
    resolved, root, stale = _resolve_grant(record, bookmark)
    try:
        return action(record, root, stale)
    finally:
        resolved.stopAccessingSecurityScopedResource()


def _capability_row(
    *,
    logical_name: str,
    path: str,
    provider: str,
    exists: bool,
    readable: bool,
    writable: bool,
    persistent: bool,
    externally_granted: bool,
    verification_time: str,
    limitations: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "logical_name": logical_name,
        "path": path,
        "provider": provider,
        "exists": bool(exists),
        "readable": bool(readable),
        "writable": bool(writable),
        "persistent": bool(persistent),
        "externally_granted": bool(externally_granted),
        "verification_time": verification_time,
        "limitations": list(limitations),
    }
    if extra:
        row.update(extra)
    row["evidence_hash"] = _sha256_bytes(_canonical_json_bytes(row))
    return row


def _sandbox_inventory(verification_time: str) -> list[dict[str, Any]]:
    python_home = Path.home().resolve(strict=False)
    state_root = _state_root()
    candidates = []
    parts = python_home.parts
    app_root = None
    try:
        data_index = parts.index("Data")
        application_index = parts.index("Application", data_index + 1)
        if application_index + 1 < len(parts):
            candidate_root = Path(*parts[: application_index + 2])
            if str(python_home).startswith(str(candidate_root) + os.sep):
                app_root = candidate_root
    except ValueError:
        pass
    if app_root is not None:
        candidates.extend(
            [
                ("juno_app_documents", app_root / "Documents", "juno_app_documents", True),
                ("juno_app_library", app_root / "Library", "juno_app_sandbox", True),
                ("juno_app_application_support", app_root / "Library" / "Application Support", "juno_app_sandbox", True),
                ("juno_app_caches", app_root / "Library" / "Caches", "juno_app_cache", False),
                ("juno_app_tmp", app_root / "tmp", "juno_app_temporary", False),
            ]
        )
    candidates.extend([
        ("juno_python_home", python_home, "juno_python_user", True),
        ("juno_state", state_root, "grabowski_juno_state", True),
        ("juno_workspace", state_root / "workspace", "grabowski_juno_workspace", True),
        ("system_mobile_documents", Path("/private/var/mobile/Library/Mobile Documents"), "apple_mobile_documents", True),
        ("system_shared_app_groups", Path("/private/var/mobile/Containers/Shared/AppGroup"), "ios_shared_app_group_or_file_provider", True),
        ("system_mobile_media", Path("/private/var/mobile/Media"), "ios_media_area", True),
    ])
    result = []
    for logical_name, path, provider, persistent_hint in candidates:
        exists = path.exists()
        readable = bool(exists and os.access(path, os.R_OK))
        writable = bool(exists and os.access(path, os.W_OK))
        limitations = [
            "provider_is_a_logical_classification_not_a_verified_file_provider_identity",
            "no_file_contents_read",
        ]
        if not exists:
            limitations.append("path_not_present")
        if exists and not readable:
            limitations.append("not_readable_by_juno_process")
        if exists and not writable:
            limitations.append("not_writable_by_juno_process")
        if logical_name.startswith("system_"):
            limitations.append("direct_system_path_access_is_not_a_document_provider_grant")
        result.append(
            _capability_row(
                logical_name=logical_name,
                path=str(path),
                provider=provider,
                exists=exists,
                readable=readable,
                writable=writable,
                persistent=bool(exists and persistent_hint),
                externally_granted=False,
                verification_time=verification_time,
                limitations=limitations,
            )
        )
    return result


def _started_after(created_at: Any, started_at: Any) -> bool:
    if not isinstance(created_at, str) or not isinstance(started_at, str):
        return False
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if created.tzinfo is None or started.tzinfo is None:
        return False
    return started > created


def _grant_inventory(
    request: dict[str, Any],
    verification_time: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    summaries = _iter_grants()
    resolved_grants = []
    capabilities = []
    for summary in summaries:
        grant_id = summary.get("grant_id")
        if summary.get("valid") is False or not isinstance(grant_id, str):
            resolved_grants.append(summary)
            continue
        try:
            record, bookmark = _load_grant(grant_id)
            resolved, root, stale = _resolve_grant(record, bookmark)
            try:
                exists = root.exists()
                readable = bool(exists and os.access(root, os.R_OK))
                writable = bool(exists and os.access(root, os.W_OK))
                juno_persistent = bool(
                    exists
                    and _started_after(
                        record.get("created_at"),
                        request.get("agent_instance_started_at"),
                    )
                )
                resolved_summary = {
                    **_safe_grant_summary(record),
                    "resolved_path": str(root),
                    "exists_now": exists,
                    "readable_now": readable,
                    "writable_now": writable,
                    "juno_restart_persistent": juno_persistent,
                    "device_restart_persistent": False,
                    "bookmark_stale": stale,
                    "bookmark_stale_observed": False,
                }
                resolved_grants.append(resolved_summary)
                limitations = list(record.get("limitations") or [])
                limitations.extend(
                    [
                        "provider_is_a_path_based_hint_not_a_verified_file_provider_identity",
                        "bookmark_stale_status_was_not_observed",
                        "device_restart_persistence_requires_a_separate_post_reboot_readback",
                        "no_file_contents_read",
                    ]
                )
                if not juno_persistent:
                    limitations.append("juno_restart_persistence_not_yet_proven")
                capabilities.append(
                    _capability_row(
                        logical_name=grant_id,
                        path=str(root),
                        provider=str(record.get("provider_hint") or "document_provider_unknown"),
                        exists=exists,
                        readable=readable,
                        writable=writable,
                        persistent=juno_persistent,
                        externally_granted=True,
                        verification_time=verification_time,
                        limitations=limitations,
                        extra={
                            "grant_id": grant_id,
                            "grant_evidence_hash": record.get("evidence_hash"),
                            "juno_restart_persistent": juno_persistent,
                            "device_restart_persistent": False,
                        },
                    )
                )
            finally:
                resolved.stopAccessingSecurityScopedResource()
        except Exception as exc:
            resolved_grants.append(
                {
                    **summary,
                    "resolve_error_type": type(exc).__name__,
                    "resolve_error": str(exc)[:300],
                }
            )
    return resolved_grants, capabilities


def _run(request: dict[str, Any]) -> dict[str, Any]:
    operation = request.get("operation")
    verification_time = _utc_now()

    if operation == "capability_manifest":
        sandbox = _sandbox_inventory(verification_time)
        grants, grant_capabilities = _grant_inventory(request, verification_time)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_capability_manifest",
            "verification_time": verification_time,
            "capabilities": sandbox + grant_capabilities,
            "sandbox": sandbox,
            "grants": grants,
            "limitations": [
                "private app containers and iPadOS system areas remain inaccessible",
                "grant persistence is not established until restart readback succeeds",
                "no recursive mutation, move, or user-facing delete operation is exposed",
            ],
        }

    if operation == "storage_inventory":
        sandbox = _sandbox_inventory(verification_time)
        resolved_grants, grant_capabilities = _grant_inventory(request, verification_time)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_storage_inventory",
            "verification_time": verification_time,
            "capabilities": sandbox + grant_capabilities,
            "sandbox": sandbox,
            "grants": resolved_grants,
        }

    if operation == "grant_status":
        grant_id = request.get("grant_id")
        if grant_id:
            records = [_safe_grant_summary(_load_grant(grant_id)[0])]
        else:
            records = _iter_grants()
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_storage_grant_status",
            "verification_time": verification_time,
            "grants": records,
        }

    if operation == "permission_probe":
        def probe(record, root, stale):
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "ipad_permission_probe",
                "verification_time": verification_time,
                "grant": _safe_grant_summary(record),
                "resolved_path": str(root),
                "exists": root.exists(),
                "readable": bool(root.exists() and os.access(root, os.R_OK)),
                "writable": bool(root.exists() and os.access(root, os.W_OK)),
                "bookmark_stale": stale,
                "bookmark_stale_observed": False,
                "no_write_performed": True,
            }
        return _with_grant(request, probe)

    if operation == "file_stat":
        def stat_action(record, root, stale):
            target = _target(root, request.get("relative_path", ""))
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "ipad_file_stat",
                "verification_time": verification_time,
                "grant_id": record["grant_id"],
                "provider": record["provider_hint"],
                "grant_evidence_hash": record["evidence_hash"],
                "relative_path": request.get("relative_path", ""),
                "entry": _stat_entry(target),
                "bookmark_stale": stale,
                "bookmark_stale_observed": False,
            }
        return _with_grant(request, stat_action)

    if operation == "directory_list":
        def list_action(record, root, stale):
            target = _target(root, request.get("relative_path", ""))
            if not target.is_dir() or target.is_symlink():
                raise ValueError("target is not a directory")
            limit = int(request.get("limit", 100))
            max_scan_entries = int(request.get("max_scan_entries", 0))
            if not 1 <= limit <= max_scan_entries <= MAX_DIRECTORY_SCAN_ENTRIES:
                raise ValueError("directory scan bounds are invalid")
            scanned = list(
                itertools.islice(
                    target.iterdir(),
                    max_scan_entries + 1,
                )
            )
            scan_truncated = len(scanned) > max_scan_entries
            scanned = scanned[:max_scan_entries]
            selected = sorted(scanned, key=lambda item: item.name)[: limit + 1]
            output_truncated = len(selected) > limit
            entries = [_stat_entry(child) for child in selected[:limit]]
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "ipad_directory_list",
                "verification_time": verification_time,
                "grant_id": record["grant_id"],
                "provider": record["provider_hint"],
                "grant_evidence_hash": record["evidence_hash"],
                "relative_path": request.get("relative_path", ""),
                "entries": entries,
                "truncated": bool(output_truncated or scan_truncated),
                "scan_limit": max_scan_entries,
                "scanned_count": len(scanned),
                "scan_truncated": scan_truncated,
                "limitations": (
                    ["directory_view_is_partial_because_scan_limit_was_reached"]
                    if scan_truncated
                    else []
                ),
                "bookmark_stale": stale,
                "bookmark_stale_observed": False,
            }
        return _with_grant(request, list_action)

    if operation == "file_read":
        def read_action(record, root, stale):
            target = _target(root, request.get("relative_path", ""))
            payload, metadata = _read_file(target, int(request.get("max_bytes", 0)))
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "ipad_file_read",
                "verification_time": verification_time,
                "grant_id": record["grant_id"],
                "provider": record["provider_hint"],
                "grant_evidence_hash": record["evidence_hash"],
                "relative_path": request.get("relative_path", ""),
                "payload_b64": base64.b64encode(payload).decode("ascii"),
                **metadata,
                "bookmark_stale": stale,
                "bookmark_stale_observed": False,
            }
        return _with_grant(request, read_action)

    if operation == "file_create":
        payload = _decode_payload(request)
        def create_action(record, root, stale):
            target = _target(root, request.get("relative_path", ""))
            if target.exists():
                raise FileExistsError("target already exists")
            metadata = _create_file(target, payload)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "ipad_file_create",
                "verification_time": verification_time,
                "grant_id": record["grant_id"],
                "grant_evidence_hash": record["evidence_hash"],
                "provider": record["provider_hint"],
                "relative_path": request.get("relative_path", ""),
                "expected_prestate": "absent",
                "payload_sha256": request["payload_sha256"],
                "readback": metadata,
                "bookmark_stale": stale,
                "bookmark_stale_observed": False,
            }
        return _with_grant(request, create_action)

    if operation == "file_replace":
        payload = _decode_payload(request)
        expected_sha256 = request.get("expected_sha256")
        if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
            raise ValueError("expected_sha256 is invalid")
        def replace_action(record, root, stale):
            target = _target(root, request.get("relative_path", ""))
            metadata = _replace_file(target, payload, expected_sha256)
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "ipad_file_replace",
                "verification_time": verification_time,
                "grant_id": record["grant_id"],
                "grant_evidence_hash": record["evidence_hash"],
                "provider": record["provider_hint"],
                "relative_path": request.get("relative_path", ""),
                "expected_sha256": expected_sha256,
                "payload_sha256": request["payload_sha256"],
                "readback": metadata,
                "bookmark_stale": stale,
                "bookmark_stale_observed": False,
            }
        return _with_grant(request, replace_action)

    raise ValueError("unsupported iPad storage operation")


_REQUEST = json.loads(base64.b64decode("__REQUEST_B64__").decode("utf-8"))
GRABOWSKI_RESULT = _run(_REQUEST)
"""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_grant_id(value: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return value
    if not isinstance(value, str) or GRANT_ID_RE.fullmatch(value) is None:
        raise ValueError("grant_id is invalid")
    return value


def _validate_provider(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > MAX_PROVIDER_BYTES
        or operator._redact(value) != value
    ):
        raise ValueError("expected_provider is invalid")
    return value


def _normalize_relative_path(value: str, *, allow_root: bool) -> str:
    if not isinstance(value, str):
        raise ValueError("relative_path must be a string")
    if len(value.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES or "\x00" in value:
        raise ValueError("relative_path exceeds the safety bound")
    if value == "":
        if allow_root:
            return value
        raise ValueError("relative_path must name a file")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("relative_path contains an unsafe segment")
    path = PurePosixPath(value)
    if path.is_absolute():
        raise ValueError("relative_path must not be absolute")
    parts = path.parts
    if not parts or len(parts) > MAX_PATH_SEGMENTS:
        raise ValueError("relative_path has an invalid segment count")
    return "/".join(parts)


def _validate_expected_started_at(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("expected_started_at must be non-empty")
    return value


def _validate_limit(value: int, *, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError(f"{label} must be between 1 and {maximum}")
    return value


def _storage_code(request: dict[str, Any]) -> tuple[str, str]:
    request_bytes = _canonical_json_bytes(request)
    request_b64 = base64.b64encode(request_bytes).decode("ascii")
    code = _STORAGE_JOB_SOURCE.replace("__REQUEST_B64__", request_b64)
    return code, _sha256_bytes(code.encode("utf-8"))


EXPECTED_RESULT_KINDS = {
    "capability_manifest": "ipad_capability_manifest",
    "storage_inventory": "ipad_storage_inventory",
    "grant_status": "ipad_storage_grant_status",
    "permission_probe": "ipad_permission_probe",
    "file_stat": "ipad_file_stat",
    "directory_list": "ipad_directory_list",
    "file_read": "ipad_file_read",
    "file_create": "ipad_file_create",
    "file_replace": "ipad_file_replace",
}
CAPABILITY_FIELDS = {
    "logical_name",
    "path",
    "provider",
    "exists",
    "readable",
    "writable",
    "persistent",
    "externally_granted",
    "verification_time",
    "evidence_hash",
    "limitations",
}


def _contains_key(value: Any, forbidden_key: str) -> bool:
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > 20_000:
            raise RuntimeError("device result exceeds the semantic traversal bound")
        if isinstance(current, dict):
            if forbidden_key in current:
                return True
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return False


def _validate_capability_rows(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 512:
        raise RuntimeError("device capability map is missing or exceeds the bound")
    for row in value:
        if not isinstance(row, dict) or not CAPABILITY_FIELDS.issubset(row):
            raise RuntimeError("device capability row is incomplete")
        if not all(
            isinstance(row[field], bool)
            for field in (
                "exists",
                "readable",
                "writable",
                "persistent",
                "externally_granted",
            )
        ):
            raise RuntimeError("device capability booleans are invalid")
        for field in ("logical_name", "path", "provider", "verification_time"):
            if not isinstance(row[field], str) or not row[field]:
                raise RuntimeError(f"device capability {field} is invalid")
        if not isinstance(row["limitations"], list) or len(row["limitations"]) > 64:
            raise RuntimeError("device capability limitations are invalid")
        evidence_hash = row.get("evidence_hash")
        if not isinstance(evidence_hash, str) or SHA256_RE.fullmatch(evidence_hash) is None:
            raise RuntimeError("device capability evidence hash is invalid")
        evidence_material = dict(row)
        evidence_material.pop("evidence_hash", None)
        if _sha256_bytes(_canonical_json_bytes(evidence_material)) != evidence_hash:
            raise RuntimeError("device capability evidence hash mismatch")


def _validate_grant_binding(request: dict[str, Any], result: dict[str, Any]) -> None:
    if result.get("grant_id") != request.get("grant_id"):
        raise RuntimeError("device result grant id mismatch")
    if result.get("grant_evidence_hash") != request.get("expected_grant_evidence_hash"):
        raise RuntimeError("device result grant evidence mismatch")
    if result.get("provider") != request.get("expected_provider"):
        raise RuntimeError("device result provider mismatch")
    if result.get("relative_path") != request.get("relative_path"):
        raise RuntimeError("device result relative path mismatch")


def _validate_hash_metadata(value: Any, *, expected_sha256: str, expected_size: int | None = None) -> None:
    if not isinstance(value, dict) or value.get("sha256") != expected_sha256:
        raise RuntimeError("device result hash metadata mismatch")
    size = value.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise RuntimeError("device result size metadata is invalid")
    if expected_size is not None and size != expected_size:
        raise RuntimeError("device result size metadata mismatch")


def _validate_device_result(request: dict[str, Any], result: Any) -> dict[str, Any]:
    operation = request.get("operation")
    expected_kind = EXPECTED_RESULT_KINDS.get(operation)
    if expected_kind is None:
        raise RuntimeError("unsupported typed storage result operation")
    if not isinstance(result, dict) or result.get("kind") != expected_kind:
        raise RuntimeError("device result kind mismatch")
    if result.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("device result schema mismatch")
    if _contains_key(result, "bookmark_b64"):
        raise RuntimeError("device result exposed private bookmark bytes")

    if operation in {"capability_manifest", "storage_inventory"}:
        _validate_capability_rows(result.get("capabilities"))
        if not isinstance(result.get("sandbox"), list) or not isinstance(result.get("grants"), list):
            raise RuntimeError("device inventory projections are invalid")
        return result

    if operation == "grant_status":
        grants = result.get("grants")
        if not isinstance(grants, list) or len(grants) > 256:
            raise RuntimeError("device grant status list is invalid")
        expected_grant_id = request.get("grant_id")
        if expected_grant_id and (
            len(grants) != 1
            or not isinstance(grants[0], dict)
            or grants[0].get("grant_id") != expected_grant_id
        ):
            raise RuntimeError("device grant status binding mismatch")
        return result

    if operation == "permission_probe":
        grant = result.get("grant")
        if (
            not isinstance(grant, dict)
            or grant.get("grant_id") != request.get("grant_id")
            or grant.get("evidence_hash") != request.get("expected_grant_evidence_hash")
            or grant.get("provider_hint") != request.get("expected_provider")
            or result.get("no_write_performed") is not True
        ):
            raise RuntimeError("device permission result binding mismatch")
        return result

    _validate_grant_binding(request, result)

    if operation == "file_stat":
        if not isinstance(result.get("entry"), dict):
            raise RuntimeError("device stat result is invalid")
        return result

    if operation == "directory_list":
        entries = result.get("entries")
        scan_limit = request.get("max_scan_entries")
        scanned_count = result.get("scanned_count")
        limitations = result.get("limitations")
        if (
            not isinstance(entries, list)
            or len(entries) > int(request.get("limit", 0))
            or result.get("scan_limit") != scan_limit
            or isinstance(scanned_count, bool)
            or not isinstance(scanned_count, int)
            or not 0 <= scanned_count <= int(scan_limit or 0)
            or not isinstance(result.get("truncated"), bool)
            or not isinstance(result.get("scan_truncated"), bool)
            or not isinstance(limitations, list)
            or len(limitations) > 8
        ):
            raise RuntimeError("device directory result exceeds the request bound")
        if result.get("scan_truncated") and result.get("truncated") is not True:
            raise RuntimeError("device directory truncation projection is inconsistent")
        return result

    if operation == "file_read":
        payload_b64 = result.get("payload_b64")
        if not isinstance(payload_b64, str):
            raise RuntimeError("device read payload is missing")
        try:
            payload = base64.b64decode(payload_b64, validate=True)
        except Exception as exc:
            raise RuntimeError("device read payload encoding is invalid") from exc
        if len(payload) > int(request.get("max_bytes", 0)):
            raise RuntimeError("device read payload exceeds the request bound")
        _validate_hash_metadata(
            result,
            expected_sha256=_sha256_bytes(payload),
            expected_size=len(payload),
        )
        return result

    payload_b64 = request.get("payload_b64")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise RuntimeError("host write payload encoding became invalid") from exc
    payload_sha256 = request.get("payload_sha256")
    if _sha256_bytes(payload) != payload_sha256:
        raise RuntimeError("host write payload hash changed")
    if result.get("provider") != request.get("expected_provider"):
        raise RuntimeError("device result provider mismatch")
    if result.get("payload_sha256") != payload_sha256:
        raise RuntimeError("device result payload hash mismatch")

    if operation == "file_create":
        if result.get("expected_prestate") != "absent":
            raise RuntimeError("device create prestate mismatch")
        _validate_hash_metadata(
            result.get("readback"),
            expected_sha256=payload_sha256,
            expected_size=len(payload),
        )
        return result

    expected_sha256 = request.get("expected_sha256")
    if result.get("expected_sha256") != expected_sha256:
        raise RuntimeError("device replace preimage binding mismatch")
    readback = result.get("readback")
    if not isinstance(readback, dict):
        raise RuntimeError("device replace readback is missing")
    _validate_hash_metadata(readback.get("before"), expected_sha256=expected_sha256)
    _validate_hash_metadata(readback.get("pre_replace"), expected_sha256=expected_sha256)
    _validate_hash_metadata(
        readback.get("after"),
        expected_sha256=payload_sha256,
        expected_size=len(payload),
    )
    return result


def _run_typed_storage_job(
    *,
    request: dict[str, Any],
    purpose: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    receipt_fields: dict[str, Any],
) -> dict[str, Any]:
    _validate_expected_started_at(expected_started_at)
    code, code_sha256 = _storage_code(request)
    execution = bridge.grabowski_juno_run(
        code=code,
        code_sha256=code_sha256,
        purpose=purpose,
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
        timeout_seconds=20,
    )
    status = execution.get("status")
    terminal = isinstance(status, dict) and status.get("state") == "succeeded"
    result = status.get("result") if isinstance(status, dict) else None
    semantic_valid: bool | None = None
    semantic_error_type = None
    semantic_error = None
    if terminal:
        try:
            _validate_device_result(request, result)
            semantic_valid = True
        except Exception as exc:
            semantic_valid = False
            semantic_error_type = type(exc).__name__
            semantic_error = operator._redact(str(exc)[:300])
    receipt = bridge._write_receipt(
        "grabowski_juno_storage_receipt",
        {
            "agent_id": bridge.AGENT_ID,
            "started_at": expected_started_at,
            "operation": request["operation"],
            "request_sha256": _sha256_bytes(_canonical_json_bytes(request)),
            "job_id": execution.get("job_id"),
            "code_sha256": code_sha256,
            "terminal_succeeded": terminal,
            "semantic_validation": {
                "valid": semantic_valid,
                "error_type": semantic_error_type,
                "error": semantic_error,
                "error_sha256": (
                    _sha256_bytes((semantic_error or "").encode("utf-8"))
                    if semantic_error is not None
                    else None
                ),
            },
            "result_sha256": (
                _sha256_bytes(_canonical_json_bytes(result))
                if result is not None
                else None
            ),
            **receipt_fields,
            "does_not_establish": [
                "iPadOS root access",
                "access outside locally selected document-provider grants",
                "background execution persistence",
                "restart persistence without a later readback",
                "cross-process compare-and-swap atomicity",
            ],
        },
    )
    if terminal and semantic_valid is not True:
        raise RuntimeError(
            "Juno storage result failed host semantic validation; "
            f"receipt_sha256={receipt.get('sha256')}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": bridge.AGENT_ID,
        "started_at": expected_started_at,
        "operation": request["operation"],
        "job_id": execution.get("job_id"),
        "status": status,
        "receipt": receipt,
    }


def _read_request(
    operation: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    **fields: Any,
) -> dict[str, Any]:
    return _run_typed_storage_job(
        request={
            "schema_version": SCHEMA_VERSION,
            "operation": operation,
            "agent_instance_started_at": expected_started_at,
            **fields,
        },
        purpose=f"Run bounded typed Juno iPad storage read: {operation}",
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
        receipt_fields={
            "authority": "typed-storage-read",
            "grant_id": fields.get("grant_id"),
            "relative_path": fields.get("relative_path"),
        },
    )


def _write_request(
    operation: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    **fields: Any,
) -> dict[str, Any]:
    return _run_typed_storage_job(
        request={
            "schema_version": SCHEMA_VERSION,
            "operation": operation,
            "agent_instance_started_at": expected_started_at,
            **fields,
        },
        purpose=f"Run bounded typed Juno iPad storage write: {operation}",
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
        receipt_fields={
            "authority": "typed-storage-write",
            "grant_id": fields.get("grant_id"),
            "grant_evidence_hash": fields.get("expected_grant_evidence_hash"),
            "provider": fields.get("expected_provider"),
            "relative_path": fields.get("relative_path"),
            "expected_prestate": (
                "absent"
                if operation == "file_create"
                else {"sha256": fields.get("expected_sha256")}
                if operation == "file_replace"
                else None
            ),
            "expected_sha256": fields.get("expected_sha256"),
            "payload_sha256": fields.get("payload_sha256"),
        },
    )


@mcp.tool(name="ipad_capability_manifest", annotations=MUTATING)
def ipad_capability_manifest(
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Read a bounded manifest of Juno sandbox paths and locally granted folders."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "capability_manifest",
        expected_started_at,
        session_escalation,
    )


@mcp.tool(name="ipad_storage_inventory", annotations=MUTATING)
def ipad_storage_inventory(
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Resolve all private grant records and return current bounded storage access."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "storage_inventory",
        expected_started_at,
        session_escalation,
    )


@mcp.tool(name="ipad_storage_grant_status", annotations=MUTATING)
def ipad_storage_grant_status(
    expected_started_at: str,
    session_escalation: dict[str, Any],
    grant_id: str = "",
) -> dict[str, Any]:
    """Read one or all private grant records without exposing bookmark bytes."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "grant_status",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id, optional=True),
    )


@mcp.tool(name="ipad_permission_probe", annotations=MUTATING)
def ipad_permission_probe(
    grant_id: str,
    expected_grant_evidence_hash: str,
    expected_provider: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Resolve one exact grant and check current read/write access without writing."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "permission_probe",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id),
        expected_grant_evidence_hash=_validate_sha256(
            expected_grant_evidence_hash,
            label="expected_grant_evidence_hash",
        ),
        expected_provider=_validate_provider(expected_provider),
    )


@mcp.tool(name="ipad_file_stat", annotations=MUTATING)
def ipad_file_stat(
    grant_id: str,
    expected_grant_evidence_hash: str,
    expected_provider: str,
    relative_path: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Read metadata for one exact path under one locally granted folder."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "file_stat",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id),
        expected_grant_evidence_hash=_validate_sha256(
            expected_grant_evidence_hash,
            label="expected_grant_evidence_hash",
        ),
        expected_provider=_validate_provider(expected_provider),
        relative_path=_normalize_relative_path(relative_path, allow_root=True),
    )


@mcp.tool(name="ipad_directory_list", annotations=MUTATING)
def ipad_directory_list(
    grant_id: str,
    expected_grant_evidence_hash: str,
    expected_provider: str,
    relative_path: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    limit: int = 100,
) -> dict[str, Any]:
    """List bounded immediate metadata under one exact granted directory."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "directory_list",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id),
        expected_grant_evidence_hash=_validate_sha256(
            expected_grant_evidence_hash,
            label="expected_grant_evidence_hash",
        ),
        expected_provider=_validate_provider(expected_provider),
        relative_path=_normalize_relative_path(relative_path, allow_root=True),
        limit=_validate_limit(limit, maximum=MAX_DIRECTORY_ENTRIES, label="limit"),
        max_scan_entries=MAX_DIRECTORY_SCAN_ENTRIES,
    )


@mcp.tool(name="ipad_file_read", annotations=MUTATING)
def ipad_file_read(
    grant_id: str,
    expected_grant_evidence_hash: str,
    expected_provider: str,
    relative_path: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    max_bytes: int = 256 * 1024,
) -> dict[str, Any]:
    """Read one bounded regular file from one exact locally granted path."""
    operator._require_operator_capability("terminal_execute")
    return _read_request(
        "file_read",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id),
        expected_grant_evidence_hash=_validate_sha256(
            expected_grant_evidence_hash,
            label="expected_grant_evidence_hash",
        ),
        expected_provider=_validate_provider(expected_provider),
        relative_path=_normalize_relative_path(relative_path, allow_root=False),
        max_bytes=_validate_limit(
            max_bytes,
            maximum=MAX_READ_BYTES,
            label="max_bytes",
        ),
    )


@mcp.tool(name="ipad_file_create", annotations=MUTATING)
def ipad_file_create(
    grant_id: str,
    expected_grant_evidence_hash: str,
    expected_provider: str,
    relative_path: str,
    payload_b64: str,
    payload_sha256: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Create one absent regular file and verify its exact payload hash."""
    operator._require_operator_capability("terminal_execute")
    _validate_sha256(payload_sha256, label="payload_sha256")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise ValueError("payload_b64 is invalid") from exc
    if len(payload) > MAX_WRITE_BYTES:
        raise ValueError("payload exceeds the write bound")
    if _sha256_bytes(payload) != payload_sha256:
        raise ValueError("payload_sha256 does not match payload_b64")
    return _write_request(
        "file_create",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id),
        expected_grant_evidence_hash=_validate_sha256(
            expected_grant_evidence_hash,
            label="expected_grant_evidence_hash",
        ),
        expected_provider=_validate_provider(expected_provider),
        relative_path=_normalize_relative_path(relative_path, allow_root=False),
        payload_b64=payload_b64,
        payload_sha256=payload_sha256,
        max_write_bytes=MAX_WRITE_BYTES,
    )


@mcp.tool(name="ipad_file_replace", annotations=MUTATING)
def ipad_file_replace(
    grant_id: str,
    expected_grant_evidence_hash: str,
    expected_provider: str,
    relative_path: str,
    expected_sha256: str,
    payload_b64: str,
    payload_sha256: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Replace one regular file only when its exact preimage hash matches."""
    operator._require_operator_capability("terminal_execute")
    _validate_sha256(expected_sha256, label="expected_sha256")
    _validate_sha256(payload_sha256, label="payload_sha256")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise ValueError("payload_b64 is invalid") from exc
    if len(payload) > MAX_WRITE_BYTES:
        raise ValueError("payload exceeds the write bound")
    if _sha256_bytes(payload) != payload_sha256:
        raise ValueError("payload_sha256 does not match payload_b64")
    return _write_request(
        "file_replace",
        expected_started_at,
        session_escalation,
        grant_id=_validate_grant_id(grant_id),
        expected_grant_evidence_hash=_validate_sha256(
            expected_grant_evidence_hash,
            label="expected_grant_evidence_hash",
        ),
        expected_provider=_validate_provider(expected_provider),
        relative_path=_normalize_relative_path(relative_path, allow_root=False),
        expected_sha256=expected_sha256,
        payload_b64=payload_b64,
        payload_sha256=payload_sha256,
        max_write_bytes=MAX_WRITE_BYTES,
    )

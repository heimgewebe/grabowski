from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

import grabowski_consumer_surface as consumer_surface
import grabowski_lifecycle_archive as lifecycle


SCHEMA_VERSION = 1
SEGMENT_ID = re.compile(r"segment-[0-9a-f]{24}\Z")
DEFAULT_LIMIT = 20
MAX_LIMIT = 200
MAX_SEGMENTS = 4096
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_CATALOG_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_RECORDS_BYTES = 64 * 1024 * 1024
TASK_ARCHIVE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_TASK_ARCHIVE_ROOT",
        str(Path.home() / ".local" / "state" / "grabowski" / "task-archives"),
    )
).expanduser()


class LifecycleReadSurfaceError(RuntimeError):
    pass


class LifecycleReadSurfaceIntegrityError(LifecycleReadSurfaceError):
    pass


def _validated_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    return limit


def _safe_archive_root(root: Path) -> Path:
    candidate = root.expanduser()
    if candidate.is_symlink():
        raise LifecycleReadSurfaceIntegrityError("task archive root must not be a symlink")
    if not candidate.exists():
        return candidate
    if not candidate.is_dir():
        raise LifecycleReadSurfaceIntegrityError("task archive root must be a directory")
    return candidate


def _segment_dir(root: Path, segment_id: str) -> Path:
    if not isinstance(segment_id, str) or SEGMENT_ID.fullmatch(segment_id) is None:
        raise ValueError("segment_id must match segment-[0-9a-f]{24}")
    path = root / segment_id
    if path.parent != root:
        raise ValueError("segment_id escapes archive root")
    return path


def _read_bounded_regular_json(
    path: Path,
    max_bytes: int,
) -> tuple[dict[str, Any], int]:
    if path.is_symlink() or not path.is_file():
        raise LifecycleReadSurfaceIntegrityError(f"archive file is missing or unsafe: {path.name}")
    try:
        payload = lifecycle._read_regular_bytes(path, max_bytes=max_bytes)
        value = json.loads(payload.decode("utf-8"))
    except lifecycle.LifecycleArchiveIntegrityError as exc:
        raise LifecycleReadSurfaceIntegrityError(str(exc)) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleReadSurfaceIntegrityError(f"archive JSON is invalid: {path.name}") from exc
    if not isinstance(value, dict):
        raise LifecycleReadSurfaceIntegrityError(f"archive JSON must be an object: {path.name}")
    return value, len(payload)


def _regular_file_size(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LifecycleReadSurfaceIntegrityError(
            f"archive file is missing or unsafe: {path.name}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LifecycleReadSurfaceIntegrityError(
                f"archive file is missing or unsafe: {path.name}"
            )
        return metadata.st_size
    finally:
        os.close(descriptor)


def _verify_manifest_only(
    segment_dir: Path,
    *,
    max_manifest_bytes: int = MAX_MANIFEST_BYTES,
) -> dict[str, Any]:
    if segment_dir.is_symlink() or not segment_dir.is_dir():
        raise LifecycleReadSurfaceIntegrityError("archive segment must be a regular directory")
    manifest_path = segment_dir / "manifest.json"
    records_path = segment_dir / "records.jsonl"
    manifest, manifest_bytes = _read_bounded_regular_json(
        manifest_path,
        max_manifest_bytes,
    )
    records_bytes = _regular_file_size(records_path)

    expected_manifest_sha256 = manifest.get("manifest_sha256")
    if not isinstance(expected_manifest_sha256, str) or lifecycle.SHA256.fullmatch(expected_manifest_sha256) is None:
        raise LifecycleReadSurfaceIntegrityError("archive manifest digest is missing or invalid")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if lifecycle.sha256_json(body) != expected_manifest_sha256:
        raise LifecycleReadSurfaceIntegrityError("archive manifest digest mismatch")
    if manifest.get("schema_version") != lifecycle.SCHEMA_VERSION:
        raise LifecycleReadSurfaceIntegrityError("unsupported archive manifest schema")
    if manifest.get("kind") != "grabowski_task_archive_segment":
        raise LifecycleReadSurfaceIntegrityError("archive manifest kind mismatch")
    if manifest.get("segment_id") != segment_dir.name:
        raise LifecycleReadSurfaceIntegrityError("archive segment identity mismatch")

    for key in ("source_store_sha256", "plan_sha256", "segment_sha256", "segment_identity_sha256"):
        value = manifest.get(key)
        if not isinstance(value, str) or lifecycle.SHA256.fullmatch(value) is None:
            raise LifecycleReadSurfaceIntegrityError(f"archive manifest {key} is invalid")
    identity_body = {
        "source_store_sha256": manifest["source_store_sha256"],
        "source_schema_version": manifest.get("source_schema_version"),
        "plan_sha256": manifest["plan_sha256"],
        "segment_sha256": manifest["segment_sha256"],
    }
    if lifecycle.sha256_json(identity_body) != manifest["segment_identity_sha256"]:
        raise LifecycleReadSurfaceIntegrityError("archive segment identity digest mismatch")
    if segment_dir.name != f"segment-{manifest['segment_identity_sha256'][:24]}":
        raise LifecycleReadSurfaceIntegrityError("archive segment directory name mismatch")

    record_count = manifest.get("record_count")
    record_sha256s = manifest.get("record_sha256s")
    if isinstance(record_count, bool) or not isinstance(record_count, int) or record_count < 1:
        raise LifecycleReadSurfaceIntegrityError("archive record count is invalid")
    if not isinstance(record_sha256s, list) or len(record_sha256s) != record_count:
        raise LifecycleReadSurfaceIntegrityError("archive record hash sequence is invalid")
    if any(not isinstance(value, str) or lifecycle.SHA256.fullmatch(value) is None for value in record_sha256s):
        raise LifecycleReadSurfaceIntegrityError("archive record hash sequence contains invalid digest")
    if manifest.get("first_record_sha256") != record_sha256s[0]:
        raise LifecycleReadSurfaceIntegrityError("archive first record digest mismatch")
    if manifest.get("last_record_sha256") != record_sha256s[-1]:
        raise LifecycleReadSurfaceIntegrityError("archive last record digest mismatch")

    return {
        "manifest": manifest,
        "manifest_sha256": expected_manifest_sha256,
        "manifest_bytes": manifest_bytes,
        "records_bytes": records_bytes,
        "record_hash_sequence_sha256": lifecycle.sha256_json(record_sha256s),
    }


def _segment_names(root: Path) -> list[str]:
    if not root.exists():
        return []
    names: list[str] = []
    for entry in root.iterdir():
        if SEGMENT_ID.fullmatch(entry.name) is None:
            raise LifecycleReadSurfaceIntegrityError(
                f"unexpected task archive root entry: {entry.name}"
            )
        if entry.is_symlink() or not entry.is_dir():
            raise LifecycleReadSurfaceIntegrityError(
                f"task archive segment entry is unsafe: {entry.name}"
            )
        names.append(entry.name)
        if len(names) > MAX_SEGMENTS:
            raise LifecycleReadSurfaceIntegrityError(
                "task archive segment count exceeds server-owned scan bound"
            )
    return sorted(names)


def _catalog(root: Path) -> tuple[list[dict[str, Any]], str]:
    names = _segment_names(root)
    verified_segments: list[dict[str, Any]] = []
    aggregate_manifest_bytes = 0
    snapshot_entries: list[dict[str, Any]] = []
    for name in names:
        segment_dir = _segment_dir(root, name)
        remaining_manifest_bytes = MAX_CATALOG_MANIFEST_BYTES - aggregate_manifest_bytes
        if remaining_manifest_bytes <= 0:
            raise LifecycleReadSurfaceIntegrityError(
                "task archive catalog manifests exceed server-owned aggregate read bound"
            )
        verified = _verify_manifest_only(
            segment_dir,
            max_manifest_bytes=min(MAX_MANIFEST_BYTES, remaining_manifest_bytes),
        )
        aggregate_manifest_bytes += verified["manifest_bytes"]
        verified_segments.append(verified)
        manifest = verified["manifest"]
        snapshot_entries.append(
            {
                "segment_id": manifest["segment_id"],
                "manifest_sha256": verified["manifest_sha256"],
                "segment_identity_sha256": manifest["segment_identity_sha256"],
                "records_bytes": verified["records_bytes"],
            }
        )
    snapshot_sha256 = hashlib.sha256(
        consumer_surface.canonical_json_bytes(snapshot_entries)
    ).hexdigest()
    return verified_segments, snapshot_sha256


def _summary(verified: Mapping[str, Any], *, view: str) -> dict[str, Any]:
    manifest = verified["manifest"]
    summary: dict[str, Any] = {
        "segment_id": manifest.get("segment_id"),
        "record_count": manifest.get("record_count"),
        "first_task_id": manifest.get("first_task_id"),
        "last_task_id": manifest.get("last_task_id"),
        "first_created_at_unix": manifest.get("first_created_at_unix"),
        "last_created_at_unix": manifest.get("last_created_at_unix"),
        "segment_sha256": manifest.get("segment_sha256"),
        "manifest_sha256": verified["manifest_sha256"],
        "records_bytes": verified["records_bytes"],
        "integrity_state": "manifest_verified_records_unverified",
    }
    if view in {"standard", "evidence"}:
        summary.update(
            {
                "source_store_sha256": manifest.get("source_store_sha256"),
                "source_schema_version": manifest.get("source_schema_version"),
                "plan_sha256": manifest.get("plan_sha256"),
                "segment_identity_sha256": manifest.get("segment_identity_sha256"),
                "first_record_sha256": manifest.get("first_record_sha256"),
                "last_record_sha256": manifest.get("last_record_sha256"),
                "record_hash_sequence_sha256": verified[
                    "record_hash_sequence_sha256"
                ],
            }
        )
    return summary


def task_archive_list(
    *,
    archive_root: Path = TASK_ARCHIVE_ROOT,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
    view: str = "minimal",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    selected_view = consumer_surface.normalize_view(view)
    selected_limit = _validated_limit(limit)
    root = _safe_archive_root(archive_root)
    verified_segments, snapshot_sha256 = _catalog(root)
    names = [item["manifest"]["segment_id"] for item in verified_segments]
    scope = f"task-archive-list:{selected_view}:{snapshot_sha256}"
    position = consumer_surface.decode_cursor(
        cursor,
        scope,
        snapshot_scope=f"task-archive-list:{selected_view}",
    )
    offset = 0 if position is None else position.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("cursor offset is invalid")
    page = verified_segments[offset : offset + selected_limit]
    segments = [_summary(item, view=selected_view) for item in page]
    next_offset = offset + len(page)
    next_cursor = (
        consumer_surface.encode_cursor(scope, {"offset": next_offset})
        if next_offset < len(names)
        else None
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "view": selected_view,
        "archive_root": str(root),
        "archive_root_exists": root.exists(),
        "segment_count": len(names),
        "segments": segments,
        "pagination": {
            "limit": selected_limit,
            "returned": len(segments),
            "offset": offset,
            "has_more": next_cursor is not None,
            "next_cursor": next_cursor,
            "snapshot_sha256": snapshot_sha256,
        },
        "integrity_state": "catalog_manifests_verified_records_unverified",
        "does_not_establish": [
            "record_payload_integrity_before_segment_read",
            "source_task_store_unchanged_after_archival",
            "permission_to_delete_archived_evidence",
        ],
    }
    if selected_view == "evidence":
        payload["server_bounds"] = {
            "max_segments": MAX_SEGMENTS,
            "max_manifest_bytes": MAX_MANIFEST_BYTES,
            "max_catalog_manifest_bytes": MAX_CATALOG_MANIFEST_BYTES,
            "max_records_bytes_per_verified_read": MAX_RECORDS_BYTES,
        }
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=("schema_version", "view", "integrity_state", "does_not_establish"),
    )


def task_archive_read(
    segment_id: str,
    *,
    archive_root: Path = TASK_ARCHIVE_ROOT,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
    view: str = "standard",
    fields: list[str] | None = None,
) -> dict[str, Any]:
    selected_view = consumer_surface.normalize_view(view, default="standard")
    selected_limit = _validated_limit(limit)
    root = _safe_archive_root(archive_root)
    segment_dir = _segment_dir(root, segment_id)
    manifest_evidence = _verify_manifest_only(segment_dir)
    if manifest_evidence["records_bytes"] > MAX_RECORDS_BYTES:
        raise LifecycleReadSurfaceIntegrityError(
            "archive segment exceeds server-owned full-verification read bound"
        )
    verified = lifecycle.verify_task_archive_segment(
        segment_dir,
        max_manifest_bytes=MAX_MANIFEST_BYTES,
        max_records_bytes=MAX_RECORDS_BYTES,
    )
    manifest = verified["manifest"]
    records = verified["records"]
    snapshot_sha256 = manifest["manifest_sha256"]
    scope = f"task-archive-read:{segment_id}:{selected_view}:{snapshot_sha256}"
    position = consumer_surface.decode_cursor(
        cursor,
        scope,
        snapshot_scope=f"task-archive-read:{segment_id}:{selected_view}",
    )
    offset = 0 if position is None else position.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("cursor offset is invalid")
    page = records[offset : offset + selected_limit]
    if selected_view == "minimal":
        selected_records = [
            {
                "task_id": record.get("task_id"),
                "state": record.get("state"),
                "created_at_unix": record.get("created_at_unix"),
                "terminalized_at_unix": record.get("terminalized_at_unix"),
                "lifecycle_receipt_sha256": record.get("lifecycle_receipt_sha256"),
            }
            for record in page
        ]
    else:
        selected_records = [dict(record) for record in page]
    next_offset = offset + len(page)
    next_cursor = (
        consumer_surface.encode_cursor(scope, {"offset": next_offset})
        if next_offset < len(records)
        else None
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "view": selected_view,
        "segment_id": segment_id,
        "manifest_sha256": manifest["manifest_sha256"],
        "segment_sha256": manifest["segment_sha256"],
        "record_count": len(records),
        "records": selected_records,
        "pagination": {
            "limit": selected_limit,
            "returned": len(selected_records),
            "offset": offset,
            "has_more": next_cursor is not None,
            "next_cursor": next_cursor,
            "snapshot_sha256": snapshot_sha256,
        },
        "integrity_state": "segment_verified",
        "does_not_establish": [
            "source_task_store_unchanged_after_archival",
            "current_task_projection_membership",
            "permission_to_delete_archived_evidence",
        ],
    }
    if selected_view == "evidence":
        payload["manifest"] = manifest
        payload["records_bytes"] = manifest_evidence["records_bytes"]
        payload["record_hash_sequence_sha256"] = manifest_evidence[
            "record_hash_sequence_sha256"
        ]
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "view",
            "segment_id",
            "integrity_state",
            "does_not_establish",
        ),
    )

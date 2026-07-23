from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import stat
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ENABLED_ENV = "GRABOWSKI_CHRONIK_AGENT_RUN_OUTBOX"
STATE_ROOT_ENV = "GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT"
PLEXER_EVENTS_URL_ENV = "GRABOWSKI_PLEXER_EVENTS_URL"
CODING_MEMORY_REPO_ENV = "GRABOWSKI_CHRONIK_CODING_MEMORY_REPO"
CODING_MEMORY_DATA_DIR_ENV = "GRABOWSKI_CHRONIK_CODING_MEMORY_DATA_DIR"
TASK_ENABLED_FIELD = "chronik_outbox_enabled"
TASK_STATE_ROOT_FIELD = "chronik_outbox_state_root"
TASK_CONTEXT_FIELD = "chronik_context_json"
TRUTHY = {"1", "true", "yes", "on"}
TERMINAL = {"completed", "failed", "cancelled", "timed_out", "signalled", "outcome_unknown"}
ARCHIVE_INDEX_FILENAME = "archive-index.v1.json"
ARCHIVE_INDEX_SCHEMA = "chronik-grabowski-outbox-archive-index.v1"
BUNDLE_MANIFEST_SCHEMA = "chronik-grabowski-outbox-bundle-manifest.v1"
BUNDLE_SOURCE_SCHEMA = "chronik-grabowski-outbox-bundle-source.v1"
WRITER_COMPACTION_LOCK_FILENAME = ".writer-compaction.lock"
WRITER_COMPACTION_LOCK_TIMEOUT_SECONDS = 5.0
WRITER_COMPACTION_LOCK_POLL_SECONDS = 0.01
MAX_ARCHIVE_INDEX_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_CODING_MEMORY_SOURCE_BYTES = 16 * 1024 * 1024
CODING_MEMORY_DOES_NOT_ESTABLISH = (
    "current_git_state",
    "current_ci_state",
    "current_runtime_state",
    "safe_retry",
)
CODING_MEMORY_FORBIDDEN_EVENT_KEYS = frozenset(
    {
        "argv",
        "command",
        "cwd",
        "env",
        "environment",
        "password",
        "prompt",
        "secret",
        "stderr",
        "stdout",
        "token",
    }
)
_ARCHIVE_INDEX_CACHE: dict[Path, tuple[tuple[int, int, int, int, int], dict[str, Any]]] = {}
_MANIFEST_CACHE: dict[Path, tuple[tuple[int, int, int, int, int], dict[str, Any]]] = {}



def enabled() -> bool:
    return os.environ.get(ENABLED_ENV, "").strip().lower() in TRUTHY


def task_enabled(record: dict[str, Any]) -> bool:
    value = record.get(TASK_ENABLED_FIELD)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in TRUTHY
    return False


def record_enabled(record: dict[str, Any]) -> bool:
    return enabled() or task_enabled(record)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _file_identity(file_stat: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _regular_file_identity(
    path: Path,
    *,
    maximum: int,
    label: str,
    allow_missing: bool = False,
) -> tuple[int, int, int, int, int] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{label} must be a regular file: {path}")
        if file_stat.st_size <= 0 or file_stat.st_size > maximum:
            raise ValueError(f"{label} has invalid size: {path}")
        return _file_identity(file_stat)
    finally:
        os.close(descriptor)


def _read_regular_file(
    path: Path,
    *,
    maximum: int,
    label: str,
    allow_missing: bool = False,
) -> tuple[bytes, tuple[int, int, int, int, int]] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} must be a regular file: {path}")
        if before.st_size <= 0 or before.st_size > maximum:
            raise ValueError(f"{label} has invalid size: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"{label} changed during read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise ValueError(f"{label} changed during read: {path}")
        return b"".join(chunks), _file_identity(after)
    finally:
        os.close(descriptor)


def _safe_basename(value: Any, *, suffix: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or Path(value).name != value
        or not value.endswith(suffix)
    ):
        raise ValueError(f"invalid {label}")
    return value


def _validate_event_ids(value: Any, *, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(set(value))
        or any(
            not isinstance(event_id, str)
            or not event_id.startswith("sha256:")
            or not _valid_sha256(event_id.removeprefix("sha256:"))
            for event_id in value
        )
    ):
        raise ValueError(f"invalid {label}")
    return tuple(value)


def _load_archive_index(index_path: Path) -> dict[str, Any] | None:
    identity = _regular_file_identity(
        index_path,
        maximum=MAX_ARCHIVE_INDEX_BYTES,
        label="Chronik archive index",
        allow_missing=True,
    )
    if identity is None:
        _ARCHIVE_INDEX_CACHE.pop(index_path, None)
        return None
    cached = _ARCHIVE_INDEX_CACHE.get(index_path)
    if cached is not None and cached[0] == identity:
        return cached[1]
    loaded = _read_regular_file(
        index_path,
        maximum=MAX_ARCHIVE_INDEX_BYTES,
        label="Chronik archive index",
    )
    assert loaded is not None
    raw, read_identity = loaded
    if read_identity != identity:
        raise ValueError("Chronik archive index changed before read")
    if not raw.endswith(b"\n"):
        raise ValueError("Chronik archive index is incomplete")
    try:
        index = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Chronik archive index is invalid JSON") from exc
    expected_keys = {
        "authoritative",
        "does_not_establish",
        "domain",
        "historical_only",
        "index_sha256",
        "manifest_count",
        "manifests",
        "reconstructible",
        "schema_version",
        "source_count",
        "sources",
    }
    if not isinstance(index, dict) or set(index) != expected_keys:
        raise ValueError("Chronik archive index has invalid fields")
    if (
        index["schema_version"] != ARCHIVE_INDEX_SCHEMA
        or index["domain"] != "agent.ledger"
        or index["historical_only"] is not True
        or index["authoritative"] is not False
        or index["reconstructible"] is not True
    ):
        raise ValueError("Chronik archive index has invalid contract")
    claimed_digest = index.get("index_sha256")
    unsigned = dict(index)
    unsigned.pop("index_sha256", None)
    if not _valid_sha256(claimed_digest) or claimed_digest != _sha256_bytes(
        _canonical_bytes(unsigned)
    ):
        raise ValueError("Chronik archive index digest mismatch")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("Chronik archive index manifests are invalid")
    normalized_manifests: list[dict[str, str]] = []
    manifest_names: list[str] = []
    for manifest in manifests:
        if not isinstance(manifest, dict) or set(manifest) != {"file", "sha256"}:
            raise ValueError("Chronik archive index manifest fields are invalid")
        manifest_name = _safe_basename(
            manifest.get("file"), suffix=".manifest.json", label="manifest file"
        )
        manifest_digest = manifest.get("sha256")
        if not _valid_sha256(manifest_digest):
            raise ValueError("Chronik archive index manifest digest is invalid")
        manifest_names.append(manifest_name)
        normalized_manifests.append(
            {"file": manifest_name, "sha256": manifest_digest}
        )
    if manifest_names != sorted(manifest_names) or len(manifest_names) != len(
        set(manifest_names)
    ):
        raise ValueError("Chronik archive index manifests are not unique and sorted")
    sources = index.get("sources")
    if not isinstance(sources, list):
        raise ValueError("Chronik archive index sources are invalid")
    normalized_sources: dict[str, list[dict[str, Any]]] = {}
    ordered_generations: list[tuple[str, str]] = []
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "event_ids",
            "manifest_index",
            "source_name",
            "source_sha256",
        }:
            raise ValueError("Chronik archive index source fields are invalid")
        source_name = _safe_basename(
            source.get("source_name"), suffix=".jsonl", label="source name"
        )
        source_digest = source.get("source_sha256")
        manifest_index = source.get("manifest_index")
        if (
            not _valid_sha256(source_digest)
            or type(manifest_index) is not int
            or manifest_index < 0
            or manifest_index >= len(normalized_manifests)
        ):
            raise ValueError("Chronik archive index source contract is invalid")
        generation = (source_name, source_digest)
        ordered_generations.append(generation)
        normalized_sources.setdefault(source_name, []).append(
            {
                "source_sha256": source_digest,
                "event_ids": _validate_event_ids(
                    source.get("event_ids"), label="archive event ids"
                ),
                "manifest_index": manifest_index,
            }
        )
    if ordered_generations != sorted(ordered_generations) or len(
        ordered_generations
    ) != len(set(ordered_generations)):
        raise ValueError(
            "Chronik archive index source generations are not unique and sorted"
        )
    if (
        type(index.get("manifest_count")) is not int
        or index["manifest_count"] != len(normalized_manifests)
        or type(index.get("source_count")) is not int
        or index["source_count"] != len(ordered_generations)
    ):
        raise ValueError("Chronik archive index inventory mismatch")
    normalized = {
        "index_sha256": claimed_digest,
        "manifests": normalized_manifests,
        "sources": normalized_sources,
    }
    _ARCHIVE_INDEX_CACHE[index_path] = (read_identity, normalized)
    return normalized


def _load_manifest_sources(
    manifest_path: Path,
    *,
    expected_sha256: str,
) -> dict[str, dict[str, Any]]:
    identity = _regular_file_identity(
        manifest_path,
        maximum=MAX_BUNDLE_MANIFEST_BYTES,
        label="Chronik bundle manifest",
    )
    assert identity is not None
    cached = _MANIFEST_CACHE.get(manifest_path)
    if cached is not None and cached[0] == identity:
        cached_value = cached[1]
        bundle_path = manifest_path.parent / cached_value["bundle_file"]
        try:
            bundle_stat = bundle_path.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError("Chronik bundle cannot be inspected safely") from exc
        if (
            cached_value["manifest_sha256"] != expected_sha256
            or not stat.S_ISREG(bundle_stat.st_mode)
            or _file_identity(bundle_stat) != cached_value["bundle_identity"]
        ):
            _MANIFEST_CACHE.pop(manifest_path, None)
        else:
            return cached_value["sources"]
    loaded = _read_regular_file(
        manifest_path,
        maximum=MAX_BUNDLE_MANIFEST_BYTES,
        label="Chronik bundle manifest",
    )
    assert loaded is not None
    raw, read_identity = loaded
    if read_identity != identity:
        raise ValueError("Chronik bundle manifest changed before read")
    if not raw.endswith(b"\n"):
        raise ValueError("Chronik bundle manifest is incomplete")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Chronik bundle manifest is invalid JSON") from exc
    expected_keys = {
        "bundle_bytes",
        "bundle_file",
        "bundle_sha256",
        "created_at",
        "does_not_establish",
        "domain",
        "event_count",
        "historical_only",
        "manifest_sha256",
        "schema_version",
        "source_count",
        "sources",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise ValueError("Chronik bundle manifest has invalid fields")
    claimed_manifest_digest = manifest.get("manifest_sha256")
    unsigned_manifest = dict(manifest)
    unsigned_manifest.pop("manifest_sha256", None)
    if (
        manifest["schema_version"] != BUNDLE_MANIFEST_SCHEMA
        or manifest["domain"] != "agent.ledger"
        or manifest["historical_only"] is not True
        or not _valid_sha256(claimed_manifest_digest)
        or claimed_manifest_digest != _sha256_bytes(_canonical_bytes(unsigned_manifest))
        or claimed_manifest_digest != expected_sha256
    ):
        raise ValueError("Chronik bundle manifest contract mismatch")
    bundle_name = _safe_basename(
        manifest.get("bundle_file"), suffix=".bundle.jsonl", label="bundle file"
    )
    bundle_digest = manifest.get("bundle_sha256")
    if not _valid_sha256(bundle_digest):
        raise ValueError("Chronik bundle digest is invalid")
    bundle_path = manifest_path.parent / bundle_name
    loaded_bundle = _read_regular_file(
        bundle_path, maximum=MAX_BUNDLE_BYTES, label="Chronik bundle"
    )
    assert loaded_bundle is not None
    bundle_raw, bundle_identity = loaded_bundle
    if (
        _sha256_bytes(bundle_raw) != bundle_digest
        or type(manifest.get("bundle_bytes")) is not int
        or manifest["bundle_bytes"] != len(bundle_raw)
    ):
        raise ValueError("Chronik bundle content mismatch")
    source_records = manifest.get("sources")
    if not isinstance(source_records, list):
        raise ValueError("Chronik bundle sources are invalid")
    sources: dict[str, dict[str, Any]] = {}
    total_events = 0
    for record in source_records:
        expected_source_keys = {
            "event_ids",
            "offset",
            "record_sha256",
            "schema_version",
            "source_bytes",
            "source_name",
            "source_path",
            "source_sha256",
            "terminal_kind",
        }
        if not isinstance(record, dict) or set(record) != expected_source_keys:
            raise ValueError("Chronik bundle source fields are invalid")
        claimed_record_digest = record.get("record_sha256")
        unsigned_record = dict(record)
        unsigned_record.pop("record_sha256", None)
        source_name = _safe_basename(
            record.get("source_name"), suffix=".jsonl", label="bundle source name"
        )
        event_ids = _validate_event_ids(
            record.get("event_ids"), label="bundle event ids"
        )
        offset = record.get("offset")
        source_bytes = record.get("source_bytes")
        source_digest = record.get("source_sha256")
        if (
            record.get("schema_version") != BUNDLE_SOURCE_SCHEMA
            or not _valid_sha256(claimed_record_digest)
            or claimed_record_digest != _sha256_bytes(_canonical_bytes(unsigned_record))
            or not _valid_sha256(source_digest)
            or type(offset) is not int
            or offset < 0
            or type(source_bytes) is not int
            or source_bytes <= 0
            or offset + source_bytes > len(bundle_raw)
            or Path(str(record.get("source_path"))).name != source_name
            or source_name in sources
        ):
            raise ValueError("Chronik bundle source contract mismatch")
        source_raw = bundle_raw[offset : offset + source_bytes]
        if _sha256_bytes(source_raw) != source_digest:
            raise ValueError("Chronik bundled source digest mismatch")
        parsed_event_ids: list[str] = []
        for line in source_raw.splitlines():
            try:
                parsed_event_ids.append(json.loads(line).get("event_id"))
            except json.JSONDecodeError as exc:
                raise ValueError("Chronik bundled source is invalid JSONL") from exc
        if tuple(parsed_event_ids) != event_ids:
            raise ValueError("Chronik bundled source event mismatch")
        sources[source_name] = {
            "source_sha256": source_digest,
            "event_ids": event_ids,
        }
        total_events += len(event_ids)
    if (
        type(manifest.get("source_count")) is not int
        or manifest["source_count"] != len(sources)
        or type(manifest.get("event_count")) is not int
        or manifest["event_count"] != total_events
    ):
        raise ValueError("Chronik bundle manifest inventory mismatch")
    normalized = {
        "manifest_sha256": claimed_manifest_digest,
        "bundle_file": bundle_name,
        "bundle_identity": bundle_identity,
        "sources": sources,
    }
    _MANIFEST_CACHE[manifest_path] = (read_identity, normalized)
    return sources


def _bundle_manifest_names(bundle_dir: Path) -> tuple[str, ...]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(bundle_dir, flags)
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise ValueError("Chronik bundle directory cannot be opened safely") from exc
    try:
        directory_stat = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or directory_stat.st_mode & 0o022
        ):
            raise ValueError(
                "Chronik bundle directory must be real, owned, and not broadly writable"
            )
        names: list[str] = []
        for name in os.listdir(descriptor):
            if not name.endswith(".manifest.json"):
                continue
            manifest_stat = os.stat(
                name, dir_fd=descriptor, follow_symlinks=False
            )
            if not stat.S_ISREG(manifest_stat.st_mode):
                raise ValueError("Chronik bundle manifest must be a regular file")
            names.append(name)
        return tuple(sorted(names))
    finally:
        os.close(descriptor)


def _archived_event_ids(path: Path) -> tuple[str, ...] | None:
    bundle_dir = path.parent / "bundles"
    manifest_names = _bundle_manifest_names(bundle_dir)
    index = _load_archive_index(bundle_dir / ARCHIVE_INDEX_FILENAME)
    if index is None:
        if manifest_names:
            raise ValueError(
                "Chronik archive index is missing while bundle manifests exist"
            )
        return None
    indexed_manifest_names = tuple(
        manifest["file"] for manifest in index["manifests"]
    )
    if indexed_manifest_names != manifest_names:
        raise ValueError("Chronik archive index does not cover all bundle manifests")
    generations = index["sources"].get(path.name)
    if generations is None:
        return None
    archived_event_ids: list[str] = []
    seen_event_ids: set[str] = set()
    for indexed in generations:
        manifest = index["manifests"][indexed["manifest_index"]]
        manifest_sources = _load_manifest_sources(
            bundle_dir / manifest["file"], expected_sha256=manifest["sha256"]
        )
        bound = manifest_sources.get(path.name)
        if (
            bound is None
            or bound["source_sha256"] != indexed["source_sha256"]
            or bound["event_ids"] != indexed["event_ids"]
        ):
            raise ValueError("Chronik archive index is not bound to its manifest")
        for event_id_value in indexed["event_ids"]:
            if event_id_value not in seen_event_ids:
                seen_event_ids.add(event_id_value)
                archived_event_ids.append(event_id_value)
    return tuple(archived_event_ids)


@contextmanager
def _writer_compaction_lock(source_dir: Path):
    source_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        source_stat = source_dir.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError("Chronik outbox directory cannot be inspected safely") from exc
    if (
        not stat.S_ISDIR(source_stat.st_mode)
        or source_stat.st_uid != os.geteuid()
        or source_stat.st_mode & 0o022
    ):
        raise ValueError(
            "Chronik outbox directory must be real, owned, and not broadly writable"
        )
    lock_path = source_dir / WRITER_COMPACTION_LOCK_FILENAME
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or file_stat.st_nlink != 1
        ):
            raise ValueError(
                "Chronik writer-compaction lock must be a private owned file"
            )
        os.fchmod(descriptor, 0o600)
        deadline = time.monotonic() + WRITER_COMPACTION_LOCK_TIMEOUT_SECONDS
        acquired = False
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Chronik writer-compaction lock acquisition timed out"
                    ) from exc
                time.sleep(min(WRITER_COMPACTION_LOCK_POLL_SECONDS, remaining))
        try:
            yield
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _append_event(path: Path, event: dict[str, Any]) -> None:
    payload = _canonical_bytes(event) + b"\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError("Chronik outbox source must be a regular file")
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Chronik outbox write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def event_id(event: dict[str, Any]) -> str:
    payload = dict(event)
    payload.pop("event_id", None)
    raw = canonical_json(payload)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _timestamp_from_unix(value: Any, *, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"task record is missing numeric {field}")
    timestamp = float(value)
    if not math.isfinite(timestamp):
        raise ValueError(f"task record has non-finite {field}")
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _event_timestamp(record: dict[str, Any], state: str) -> str:
    if state in TERMINAL:
        if record.get("terminalized_at_unix") is not None:
            return _timestamp_from_unix(
                record["terminalized_at_unix"], field="terminalized_at_unix"
            )
        return _timestamp_from_unix(record.get("updated_at_unix"), field="updated_at_unix")
    return _timestamp_from_unix(record.get("created_at_unix"), field="created_at_unix")


def state_root(record: dict[str, Any] | None = None) -> Path:
    raw = None
    if record is not None:
        candidate = record.get(TASK_STATE_ROOT_FIELD)
        if isinstance(candidate, str) and candidate.strip():
            raw = candidate
    if raw is None:
        raw = os.environ.get(STATE_ROOT_ENV)
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "state"


def run_id(record: dict[str, Any]) -> str:
    return f"task-{record['task_id']}-a{record['attempt']}"


def classify(state: str) -> tuple[str, dict[str, Any]] | None:
    if state in {"launching", "running"}:
        return "agent.run.started", {"result": "started"}
    if state == "completed":
        return "agent.run.completed", {"result": "completed"}
    if state in TERMINAL:
        return "agent.run.blocked", {"result": "blocked", "blocker_code": f"task-{state.replace('_', '-')}"}
    return None


def _context(record: dict[str, Any]) -> dict[str, Any]:
    raw = record.get(TASK_CONTEXT_FIELD)
    if isinstance(raw, str) and raw:
        value = json.loads(raw)
    elif isinstance(raw, dict):
        value = dict(raw)
    else:
        value = {"subject_scope": "host", "host": record.get("host", "unknown"), "operation": "other", "task_class": "other"}
    if not isinstance(value, dict):
        raise ValueError("stored Chronik context must be an object")
    return value


def _subject(context: dict[str, Any]) -> dict[str, Any]:
    scope = context.get("subject_scope")
    if scope == "repository":
        subject: dict[str, Any] = {"scope": "repository", "repo": context["repo"]}
    elif scope == "host":
        subject = {"scope": "host", "host": context["host"]}
    else:
        raise ValueError("stored Chronik context has invalid subject scope")
    for key in ("branch", "head", "component", "bureau_task_id", "pr_number"):
        if context.get(key) is not None and context.get(key) != "":
            subject[key] = context[key]
    return subject


def build_event(record: dict[str, Any], state: str) -> dict[str, Any] | None:
    result = classify(state)
    if result is None:
        return None
    kind, data = result
    rid = run_id(record)
    context = _context(record)
    data = {**data, "operation": context["operation"], "task_class": context["task_class"]}
    event = {
        "schema_version": "agent-run-event.v0",
        "kind": kind,
        "ts": _event_timestamp(record, state),
        "source": {"repo": "heimgewebe/grabowski", "component": "grabowski", "run_id": rid},
        "subject": _subject(context),
        "trust_tier": "observed" if state in TERMINAL else "declared",
        "status": "active",
        "caused_by": [],
        "evidence_refs": [f"grabowski-task:{record['task_id']}", f"grabowski-unit:{record['unit']}"],
        "data": data,
    }
    event["event_id"] = event_id(event)
    return event


def outbox_path(event: dict[str, Any], root: Path | None = None) -> Path:
    rid = event["source"]["run_id"].replace("/", "_")
    return (root or state_root()) / "grabowski" / "chronik-outbox" / f"grabowski_{rid}.jsonl"


def append_unique(path: Path, event: dict[str, Any]) -> bool:
    if event.get("event_id") != event_id(event):
        raise ValueError("event_id does not match payload")
    with _writer_compaction_lock(path.parent):
        archived_event_ids = _archived_event_ids(path)
        if archived_event_ids is not None and event["event_id"] in archived_event_ids:
            return False
        if path.exists():
            loaded = _read_regular_file(
                path, maximum=MAX_BUNDLE_BYTES, label="Chronik outbox source"
            )
            assert loaded is not None
            raw, _ = loaded
            for line in raw.splitlines():
                if not line.strip():
                    continue
                try:
                    existing = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if existing.get("event_id") != event["event_id"]:
                    continue
                if canonical_json(existing) != canonical_json(event):
                    raise ValueError(
                        "event_id already exists with different payload"
                    )
                return False
        _append_event(path, event)
        return True


def record_task_state(record: dict[str, Any], state: str) -> dict[str, Any]:
    if not record_enabled(record):
        return {"enabled": False, "written": False}
    event = build_event(record, state)
    if event is None:
        return {"enabled": True, "written": False}
    path = outbox_path(event, state_root(record))
    return {"enabled": True, "written": append_unique(path, event), "path": str(path), "kind": event["kind"]}


def record_task_state_safely(record: dict[str, Any], state: str) -> dict[str, Any]:
    try:
        return record_task_state(record, state)
    except Exception as exc:
        return {"enabled": record_enabled(record), "written": False, "error": str(exc)}


def plexer_events_url(raw: str | None = None) -> str | None:
    value = raw if raw is not None else os.environ.get(PLEXER_EVENTS_URL_ENV)
    if not isinstance(value, str):
        return None
    stripped = value.strip().rstrip("/")
    if not stripped:
        return None
    if stripped.endswith("/v1/events"):
        return stripped
    return f"{stripped}/v1/events"


def send_event_to_plexer(
    event: dict[str, Any],
    url: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    target = plexer_events_url(url)
    if target is None:
        return {"configured": False, "sent": False, "retryable": False}
    request = Request(
        target,
        data=canonical_json(event).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(getattr(response, "status", response.getcode()))
        return {"configured": True, "sent": 200 <= status_code < 300, "retryable": status_code == 429 or status_code >= 500, "status_code": status_code}
    except HTTPError as exc:
        return {"configured": True, "sent": False, "retryable": exc.code == 429 or exc.code >= 500, "status_code": exc.code, "error": str(exc)}
    except (TimeoutError, URLError, OSError) as exc:
        return {"configured": True, "sent": False, "retryable": True, "error": str(exc)}


def send_event_to_plexer_safely(
    event: dict[str, Any],
    url: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    try:
        return send_event_to_plexer(event, url=url, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return {"configured": plexer_events_url(url) is not None, "sent": False, "retryable": True, "error": str(exc)}


def flush_outbox_file_to_plexer(
    path: Path,
    url: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            results.append({"line": line_number, "sent": False, "retryable": False, "error": f"invalid json: {exc}"})
            continue
        result = send_event_to_plexer_safely(event, url=url, timeout_seconds=timeout_seconds)
        result["line"] = line_number
        results.append(result)
    return {
        "events": len(results),
        "sent": sum(1 for result in results if result.get("sent") is True),
        "results": results,
    }


_EVENT_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "ts",
        "source",
        "subject",
        "trust_tier",
        "status",
        "caused_by",
        "evidence_refs",
        "data",
        "event_id",
    }
)
_EVENT_SOURCE_KEYS = frozenset({"repo", "component", "run_id"})
_EVENT_SUBJECT_REPOSITORY_KEYS = frozenset(
    {"scope", "repo", "branch", "head", "component", "bureau_task_id", "pr_number"}
)
_EVENT_SUBJECT_HOST_KEYS = frozenset(
    {"scope", "host", "component", "bureau_task_id", "pr_number"}
)
_EVENT_DATA_KEYS = frozenset({"result", "operation", "task_class", "blocker_code"})
_EVENT_OPERATIONS = frozenset(
    {"implement", "review", "merge", "deploy", "runtime_verify", "recovery", "other"}
)
_EVENT_TASK_CLASSES = frozenset(
    {
        "coding",
        "review",
        "merge",
        "deploy",
        "runtime_verify",
        "recovery",
        "maintenance",
        "diagnostic",
        "other",
    }
)
_EVENT_BLOCKER_CODES = frozenset(
    {"task-failed", "task-cancelled", "task-timed-out", "task-signalled", "task-outcome-unknown"}
)
_EVENT_KIND_RESULT = {
    "agent.run.started": "started",
    "agent.run.completed": "completed",
    "agent.run.blocked": "blocked",
}
_RUN_ID_PATTERN = re.compile(r"task-([0-9a-f]{24})-a([1-9][0-9]*)\Z")
_EVENT_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _validate_agent_run_event_shape(event: Any, *, label: str) -> None:
    """Reject anything that is not exactly the agent-run-event.v0 shape Grabowski emits."""
    if not isinstance(event, dict) or set(event) != _EVENT_TOP_LEVEL_KEYS:
        raise ValueError(f"{label} has invalid fields")
    if event.get("schema_version") != "agent-run-event.v0":
        raise ValueError(f"{label} has invalid schema")
    kind = event.get("kind")
    if kind not in _EVENT_KIND_RESULT:
        raise ValueError(f"{label} has unsupported kind")
    ts = event.get("ts")
    if not isinstance(ts, str) or not _EVENT_TIMESTAMP_PATTERN.match(ts):
        raise ValueError(f"{label} has an invalid timestamp")
    source = event.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != _EVENT_SOURCE_KEYS
        or source.get("repo") != "heimgewebe/grabowski"
        or source.get("component") != "grabowski"
        or not isinstance(source.get("run_id"), str)
        or not _RUN_ID_PATTERN.match(source["run_id"])
    ):
        raise ValueError(f"{label} is not from Grabowski")
    subject = event.get("subject")
    if not isinstance(subject, dict):
        raise ValueError(f"{label} has an invalid subject")
    scope = subject.get("scope")
    if scope == "repository":
        if (
            set(subject) - _EVENT_SUBJECT_REPOSITORY_KEYS
            or not isinstance(subject.get("repo"), str)
            or not subject["repo"]
            or any(
                key in subject and (not isinstance(subject[key], str) or not subject[key])
                for key in ("branch", "head")
            )
        ):
            raise ValueError(f"{label} has an invalid repository subject")
    elif scope == "host":
        if (
            set(subject) != _EVENT_SUBJECT_HOST_KEYS
            or not isinstance(subject.get("host"), str)
            or not subject["host"]
        ):
            raise ValueError(f"{label} has an invalid host subject")
    else:
        raise ValueError(f"{label} has an invalid subject scope")
    for optional_key in ("component", "bureau_task_id"):
        if optional_key in subject and (
            not isinstance(subject[optional_key], str)
            or not subject[optional_key]
            or len(subject[optional_key]) > 160
            or any(ord(character) < 32 for character in subject[optional_key])
        ):
            raise ValueError(f"{label} has invalid subject metadata")
    if "pr_number" in subject and (
        isinstance(subject["pr_number"], bool)
        or not isinstance(subject["pr_number"], int)
        or not 1 <= subject["pr_number"] <= 2_147_483_647
    ):
        raise ValueError(f"{label} has invalid subject metadata")
    if event.get("trust_tier") not in {"observed", "declared"}:
        raise ValueError(f"{label} has an invalid trust tier")
    if event.get("status") != "active":
        raise ValueError(f"{label} has an invalid status")
    if event.get("caused_by") != []:
        raise ValueError(f"{label} has an invalid caused_by")
    run_match = _RUN_ID_PATTERN.fullmatch(source["run_id"])
    assert run_match is not None
    task_id, attempt = run_match.groups()
    refs = event.get("evidence_refs")
    if refs != [
        f"grabowski-task:{task_id}",
        f"grabowski-unit:grabowski-task-{task_id}-a{attempt}.service",
    ]:
        raise ValueError(f"{label} has invalid evidence refs")
    data = event.get("data")
    expected_result = _EVENT_KIND_RESULT[kind]
    if (
        not isinstance(data, dict)
        or set(data) - _EVENT_DATA_KEYS
        or data.get("result") != expected_result
        or data.get("operation") not in _EVENT_OPERATIONS
        or data.get("task_class") not in _EVENT_TASK_CLASSES
    ):
        raise ValueError(f"{label} has invalid data")
    if expected_result == "blocked":
        blocker_code = data.get("blocker_code")
        if blocker_code not in _EVENT_BLOCKER_CODES:
            raise ValueError(f"{label} has an invalid blocker code")
    elif "blocker_code" in data:
        raise ValueError(f"{label} has an unexpected blocker code")
    if event.get("event_id") != event_id(event):
        raise ValueError(f"{label} has an invalid event_id")
    if _contains_forbidden_coding_memory_key(event):
        raise ValueError(f"{label} is not redacted")


def _contains_forbidden_coding_memory_key(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if (
                isinstance(key, str)
                and key.lower() in CODING_MEMORY_FORBIDDEN_EVENT_KEYS
            ):
                return True
            if _contains_forbidden_coding_memory_key(nested):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_forbidden_coding_memory_key(item) for item in value)
    return False


def read_coding_memory_source(path: str) -> tuple[dict[str, Any], bytes]:
    """Validate one redacted Grabowski outbox JSONL and return its metadata and exact bytes.

    The returned bytes are exactly what was read and validated; callers that need to hand
    the source to an external process must stage a private copy of these bytes rather than
    re-reading (and re-trusting) the original path.
    """
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Chronik outbox path must be non-empty text")
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ValueError("Chronik outbox path must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"Chronik outbox source is unavailable: {exc}") from exc
    if resolved != candidate:
        raise ValueError("Chronik outbox path may not traverse symlinks or aliases")
    expected_parent = (state_root() / "grabowski" / "chronik-outbox").resolve()
    if resolved.parent != expected_parent:
        raise ValueError(
            "Chronik outbox source must be directly inside the configured state root"
        )
    if not resolved.name.startswith("grabowski_") or resolved.suffix != ".jsonl":
        raise ValueError("Chronik outbox source must be a Grabowski JSONL file")
    loaded = _read_regular_file(
        resolved,
        maximum=MAX_CODING_MEMORY_SOURCE_BYTES,
        label="Chronik coding-memory source",
    )
    assert loaded is not None
    raw, identity = loaded
    if not raw.endswith(b"\n"):
        raise ValueError("Chronik outbox source is incomplete")
    event_ids: list[str] = []
    canonical_events: list[bytes] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line:
            raise ValueError(f"Chronik outbox source has a blank line at {line_number}")
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Chronik outbox source has invalid JSON at line {line_number}"
            ) from exc
        _validate_agent_run_event_shape(
            event, label=f"Chronik outbox event {line_number}"
        )
        event_ids.append(event["event_id"])
        canonical_events.append(_canonical_bytes(event))
    if not event_ids:
        raise ValueError("Chronik outbox source is empty")
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("Chronik outbox source contains duplicate event IDs")
    metadata = {
        "path": str(resolved),
        "sha256": _sha256_bytes(raw),
        "bytes": len(raw),
        "event_count": len(event_ids),
        "event_ids": event_ids,
        "event_ids_sha256": _sha256_bytes(_canonical_bytes(event_ids)),
        "chronik_source_sha256": _sha256_bytes(b"\n".join(canonical_events)),
        "identity": identity,
    }
    return metadata, raw


def inspect_coding_memory_source(path: str) -> dict[str, Any]:
    """Validate and hash one redacted Grabowski outbox JSONL without mutating it."""
    metadata, _raw = read_coding_memory_source(path)
    return metadata


def coding_memory_source_unchanged(
    source: dict[str, Any],
) -> tuple[bool, str | None]:
    """Compare one source to validated metadata without reparsing JSON."""
    try:
        loaded = _read_regular_file(
            Path(source["path"]),
            maximum=MAX_CODING_MEMORY_SOURCE_BYTES,
            label="Chronik coding-memory source readback",
        )
    except (OSError, ValueError) as exc:
        return False, str(exc)
    if loaded is None:
        return False, "Chronik coding-memory source disappeared after snapshot"
    raw, identity = loaded
    unchanged = (
        _sha256_bytes(raw) == source.get("sha256")
        and len(raw) == source.get("bytes")
        and identity == source.get("identity")
    )
    return (
        unchanged,
        None if unchanged else "Chronik coding-memory source changed after snapshot",
    )


def coding_memory_configuration() -> dict[str, Any]:
    """Resolve the optional local Chronik coding-memory CLI without requiring it."""
    repository = Path(
        os.environ.get(CODING_MEMORY_REPO_ENV, str(Path.home() / "repos" / "chronik"))
    ).expanduser()
    data_dir = Path(
        os.environ.get(
            CODING_MEMORY_DATA_DIR_ENV,
            str(Path.home() / ".local" / "state" / "chronik"),
        )
    ).expanduser()
    cli = repository / "tools" / "coding_memory.py"
    reason = None
    if not repository.is_absolute():
        reason = "chronik_repository_unavailable"
    elif repository.is_symlink() or not repository.is_dir():
        reason = "chronik_repository_unavailable"
    elif not data_dir.is_absolute():
        reason = "chronik_data_dir_unavailable"
    elif cli.is_symlink() or not cli.is_file():
        reason = "chronik_coding_memory_cli_unavailable"
    return {
        "available": reason is None,
        "reason": reason,
        "repository": str(repository),
        "data_dir": str(data_dir),
        "cli": str(cli),
    }

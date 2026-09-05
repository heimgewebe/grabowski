from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

TRACE_SCHEMA_VERSION = "grabowski.long-horizon-trace.v1"
PRODUCER_SCHEMA_VERSION = "grabowski.long-horizon-producer.v1"
CLOSEOUT_SCHEMA_VERSION = "grabowski.long-horizon-producer-closeout.v1"
MAX_EVENTS = 512
MAX_TRACE_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
TASK_ID_RE = re.compile(r"[0-9a-f]{24}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/#=-]{0,159}\Z")
RETENTION_MODES = frozenset({"ephemeral", "operator-managed-local"})
ABANDONMENT_REASONS = frozenset(
    {
        "blocked",
        "invalidated",
        "not_needed",
        "other_explicit",
        "superseded",
        "target_changed",
    }
)
RECORD_KINDS = frozenset(
    {
        "monitor.requirement",
        "monitor.check",
        "commitment.declared",
        "commitment.completed",
        "commitment.abandoned",
    }
)
DOES_NOT_ESTABLISH = (
    "current_task_state",
    "current_git_state",
    "current_ci_state",
    "routing_authority",
    "merge_authority",
    "deployment_authority",
    "policy_authority",
    "strategic_correctness_of_abandonment",
)
FORBIDDEN_CAPTURE_CATEGORIES = (
    "argv",
    "argv_digest",
    "command",
    "environment",
    "prompt",
    "chain_of_thought",
    "stdout",
    "stderr",
    "secret",
    "token",
    "password",
)


class TraceProducerError(ValueError):
    """Raised when producer input or persisted trace state is unsafe or invalid."""


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    )


def _content_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while persisting long-horizon trace evidence")
        view = view[written:]


def _private_mode(path: Path, *, directory: bool) -> os.stat_result:
    metadata = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if stat.S_ISLNK(metadata.st_mode) or not expected(metadata.st_mode):
        raise TraceProducerError(f"unsafe path type: {path}")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise TraceProducerError(f"path must be private and owner-controlled: {path}")
    return metadata


def _ensure_private_root(state_root: Path) -> Path:
    root = state_root.expanduser()
    if not root.is_absolute():
        raise TraceProducerError("state_root must be absolute")
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except FileNotFoundError as exc:
        raise TraceProducerError("state_root parent must already exist") from exc
    _private_mode(root, directory=True)
    return root


def _validate_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise TraceProducerError(
            "task_id must be a 24-character lowercase hex Grabowski task id"
        )
    return task_id


def _validate_attempt(attempt: int) -> int:
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise TraceProducerError("attempt must be an integer >= 1")
    return attempt


def _validate_step(step: int) -> int:
    if isinstance(step, bool) or not isinstance(step, int) or step < 0:
        raise TraceProducerError("step must be an integer >= 0")
    return step


def _validate_positive_int(value: int, *, field: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TraceProducerError(f"{field} must be an integer >= {minimum}")
    return value


def _token(value: str, *, field: str) -> str:
    if not isinstance(value, str) or TOKEN_RE.fullmatch(value) is None:
        raise TraceProducerError(f"{field} must be one bounded opaque token")
    return value


def _safe_evidence_refs(value: list[str] | None) -> list[str]:
    refs = [] if value is None else value
    if not isinstance(refs, list) or len(refs) > 8:
        raise TraceProducerError("evidence_refs must be a list of at most 8 opaque tokens")
    normalized = [_token(item, field="evidence_ref") for item in refs]
    if len(normalized) != len(set(normalized)):
        raise TraceProducerError("evidence_refs must be unique")
    return normalized


def _source_snapshot(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise TraceProducerError("task source record is invalid")
    task_id = _validate_task_id(record.get("task_id"))
    attempt = _validate_attempt(record.get("attempt"))
    created_at = record.get("created_at_unix")
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 0:
        raise TraceProducerError("task source created_at_unix is invalid")
    authoritative_unit = _token(
        record.get("authoritative_unit"), field="task source authoritative_unit"
    )
    return {
        "task_id": task_id,
        "attempt": attempt,
        "created_at_unix": created_at,
        "authoritative_unit": authoritative_unit,
    }


def resolve_grabowski_task_snapshot(task_id: str) -> dict[str, Any]:
    """Read one task through a query-only SQLite connection without refreshing it."""
    identifier = _validate_task_id(task_id)
    import grabowski_tasks

    database = Path(grabowski_tasks.TASK_DB).expanduser()
    if database.is_symlink() or not database.is_file():
        raise TraceProducerError("Grabowski task database is unavailable or unsafe")
    metadata = database.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise TraceProducerError(
            "Grabowski task database must be private and owner-controlled"
        )
    connection = sqlite3.connect(
        database.absolute().as_uri() + "?mode=ro",
        uri=True,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute(
            "SELECT task_id, attempt, created_at_unix, authoritative_unit "
            "FROM tasks WHERE task_id=?",
            (identifier,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise TraceProducerError(f"unknown Grabowski task: {identifier}")
    return _source_snapshot(dict(row))


def _session_name(task_id: str, attempt: int) -> str:
    return f"task-{task_id}-attempt-{attempt}"


def _run_id(task_id: str, attempt: int) -> str:
    return f"grabowski-task:{task_id}:attempt:{attempt}"


def _paths(root: Path, task_id: str, attempt: int) -> dict[str, Path]:
    session = root / _session_name(task_id, attempt)
    return {
        "session": session,
        "manifest": session / "manifest.json",
        "trace": session / "trace.jsonl",
        "closeout": session / "closeout.json",
        "lock": session / ".trace.lock",
    }


def _read_private_bytes(path: Path, *, maximum: int, allow_empty: bool = False) -> bytes:
    linked_before = _private_mode(path, directory=False)
    if linked_before.st_size > maximum or (
        linked_before.st_size == 0 and not allow_empty
    ):
        raise TraceProducerError(f"invalid file size: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        if _file_identity(opened_before) != _file_identity(linked_before):
            raise TraceProducerError(f"file identity changed before read: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        opened_after = os.fstat(descriptor)
        linked_after = path.lstat()
    finally:
        os.close(descriptor)
    if (
        len(payload) > maximum
        or _file_identity(opened_before) != _file_identity(opened_after)
        or _content_identity(opened_before) != _content_identity(opened_after)
        or _file_identity(opened_before) != _file_identity(linked_after)
        or _content_identity(opened_before) != _content_identity(linked_after)
    ):
        raise TraceProducerError(f"file changed while reading: {path}")
    return payload


def _read_private_json(path: Path, *, maximum: int) -> dict[str, Any]:
    try:
        value = json.loads(_read_private_bytes(path, maximum=maximum))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TraceProducerError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise TraceProducerError(f"JSON must be an object: {path}")
    return value


def _create_private_json(path: Path, payload: dict[str, Any]) -> None:
    raw = (canonical_json(payload) + "\n").encode("utf-8")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise TraceProducerError("JSON artifact exceeds producer size bound")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _session_lock(path: Path) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise TraceProducerError("trace lock must be one private regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _event_allowed_fields(kind: str) -> set[str]:
    base = {"schema_version", "run_id", "step", "kind"}
    if kind == "monitor.requirement":
        return base | {"monitor_id", "cadence_steps", "grace_steps"}
    if kind == "monitor.check":
        return base | {"monitor_id"}
    if kind == "commitment.declared":
        return base | {"commitment_id", "horizon_steps"}
    if kind == "commitment.completed":
        return base | {"commitment_id"}
    if kind == "commitment.abandoned":
        return base | {"commitment_id", "reason", "evidence_refs"}
    if kind in {"run.started", "run.terminal"}:
        return base
    raise TraceProducerError(f"unsupported event kind: {kind}")


def _validate_event_shape(event: dict[str, Any], *, expected_run_id: str) -> None:
    if not isinstance(event, dict):
        raise TraceProducerError("trace event must be an object")
    if event.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise TraceProducerError("trace event schema_version mismatch")
    if event.get("run_id") != expected_run_id:
        raise TraceProducerError("trace run_id drift")
    _validate_step(event.get("step"))
    kind = event.get("kind")
    if not isinstance(kind, str) or set(event) != _event_allowed_fields(kind):
        raise TraceProducerError("trace event fields are invalid")
    if kind == "monitor.requirement":
        _token(event.get("monitor_id"), field="monitor_id")
        _validate_positive_int(event.get("cadence_steps"), field="cadence_steps")
        _validate_positive_int(
            event.get("grace_steps"), field="grace_steps", minimum=0
        )
    elif kind == "monitor.check":
        _token(event.get("monitor_id"), field="monitor_id")
    elif kind == "commitment.declared":
        _token(event.get("commitment_id"), field="commitment_id")
        _validate_positive_int(event.get("horizon_steps"), field="horizon_steps")
    elif kind in {"commitment.completed", "commitment.abandoned"}:
        _token(event.get("commitment_id"), field="commitment_id")
        if kind == "commitment.abandoned":
            if event.get("reason") not in ABANDONMENT_REASONS:
                raise TraceProducerError(
                    "commitment abandonment reason is not allowlisted"
                )
            _safe_evidence_refs(event.get("evidence_refs"))


def _validate_semantics(events: list[dict[str, Any]], *, run_id: str) -> None:
    if not events:
        raise TraceProducerError("trace must contain run.started")
    if events[0].get("kind") != "run.started" or events[0].get("step") != 0:
        raise TraceProducerError("trace must begin with run.started at step 0")
    requirements: set[str] = set()
    commitments: set[str] = set()
    resolutions: set[str] = set()
    terminal_seen = False
    previous_step = -1
    for index, event in enumerate(events):
        _validate_event_shape(event, expected_run_id=run_id)
        step = int(event["step"])
        if step < previous_step:
            raise TraceProducerError("trace steps must be monotone non-decreasing")
        previous_step = step
        kind = str(event["kind"])
        if terminal_seen:
            raise TraceProducerError("events after run.terminal are forbidden")
        if kind == "run.started" and index != 0:
            raise TraceProducerError("run.started may appear only once")
        if kind == "run.terminal":
            terminal_seen = True
        elif kind == "monitor.requirement":
            monitor_id = str(event["monitor_id"])
            if monitor_id in requirements:
                raise TraceProducerError("duplicate monitor requirement")
            requirements.add(monitor_id)
        elif kind == "monitor.check":
            if str(event["monitor_id"]) not in requirements:
                raise TraceProducerError(
                    "monitor check requires an earlier requirement"
                )
        elif kind == "commitment.declared":
            commitment_id = str(event["commitment_id"])
            if commitment_id in commitments:
                raise TraceProducerError("duplicate commitment declaration")
            commitments.add(commitment_id)
        elif kind in {"commitment.completed", "commitment.abandoned"}:
            commitment_id = str(event["commitment_id"])
            if commitment_id not in commitments:
                raise TraceProducerError(
                    "commitment resolution requires an earlier declaration"
                )
            if commitment_id in resolutions:
                raise TraceProducerError("commitment may be resolved only once")
            resolutions.add(commitment_id)


def _load_trace(path: Path, *, run_id: str) -> tuple[list[dict[str, Any]], bytes]:
    try:
        raw = _read_private_bytes(path, maximum=MAX_TRACE_BYTES, allow_empty=True)
    except FileNotFoundError:
        return [], b""
    if not raw:
        return [], raw
    if not raw.endswith(b"\n"):
        raise TraceProducerError("trace must end with newline")
    events: list[dict[str, Any]] = []
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise TraceProducerError("trace is not valid UTF-8") from exc
    for raw_line in lines:
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise TraceProducerError("trace contains invalid JSON") from exc
        if not isinstance(event, dict) or raw_line != canonical_json(event):
            raise TraceProducerError("trace contains non-canonical or invalid event")
        events.append(event)
    if len(events) > MAX_EVENTS:
        raise TraceProducerError("trace exceeds event-count bound")
    _validate_semantics(events, run_id=run_id)
    return events, raw


def _append_event(
    trace_path: Path, event: dict[str, Any], *, run_id: str
) -> dict[str, Any]:
    events, raw = _load_trace(trace_path, run_id=run_id)
    encoded = (canonical_json(event) + "\n").encode("utf-8")
    if any(existing == event for existing in events):
        return {
            "appended": False,
            "idempotent_replay": True,
            "event_sha256": sha256_json(event),
            "event_count": len(events),
            "last_step": events[-1]["step"] if events else None,
            "trace_sha256": _sha256_bytes(raw),
        }
    if len(events) >= MAX_EVENTS or len(raw) + len(encoded) > MAX_TRACE_BYTES:
        raise TraceProducerError("trace retention bound reached")
    candidate = [*events, event]
    _validate_semantics(candidate, run_id=run_id)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(trace_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise TraceProducerError("trace must be one private regular file")
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    updated = raw + encoded
    return {
        "appended": True,
        "idempotent_replay": False,
        "event_sha256": sha256_json(event),
        "event_count": len(candidate),
        "last_step": event["step"],
        "trace_sha256": _sha256_bytes(updated),
    }


def _load_manifest(
    root: Path, task_id: str, attempt: int
) -> tuple[dict[str, Any], dict[str, Path]]:
    paths = _paths(root, task_id, attempt)
    _private_mode(paths["session"], directory=True)
    manifest = _read_private_json(paths["manifest"], maximum=MAX_MANIFEST_BYTES)
    expected_run_id = _run_id(task_id, attempt)
    if (
        manifest.get("schema_version") != PRODUCER_SCHEMA_VERSION
        or manifest.get("task_id") != task_id
        or manifest.get("attempt") != attempt
        or manifest.get("run_id") != expected_run_id
        or manifest.get("source_authority")
        != "grabowski-persistent-task-store-snapshot"
        or manifest.get("historical_evidence_only") is not True
        or manifest.get("routing_effect") is not False
        or manifest.get("policy_effect") is not False
    ):
        raise TraceProducerError("trace manifest contract mismatch")
    claimed = manifest.get("manifest_sha256")
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if not isinstance(claimed, str) or claimed != sha256_json(unsigned):
        raise TraceProducerError("trace manifest digest mismatch")
    return manifest, paths


def open_trace(
    state_root: Path,
    task_id: str,
    *,
    retention_mode: str,
    task_lookup: Callable[[str], dict[str, Any]] = resolve_grabowski_task_snapshot,
) -> dict[str, Any]:
    root = _ensure_private_root(state_root)
    identifier = _validate_task_id(task_id)
    if retention_mode not in RETENTION_MODES:
        raise TraceProducerError(
            f"retention_mode must be one of {sorted(RETENTION_MODES)}"
        )
    source = _source_snapshot(task_lookup(identifier))
    if source["task_id"] != identifier:
        raise TraceProducerError("task source identity mismatch")
    attempt = int(source["attempt"])
    paths = _paths(root, identifier, attempt)
    try:
        paths["session"].mkdir(mode=0o700)
    except FileExistsError:
        pass
    _private_mode(paths["session"], directory=True)
    source_sha256 = sha256_json(source)
    with _session_lock(paths["lock"]):
        manifest_unsigned = {
            "schema_version": PRODUCER_SCHEMA_VERSION,
            "task_id": identifier,
            "attempt": attempt,
            "run_id": _run_id(identifier, attempt),
            "source_authority": "grabowski-persistent-task-store-snapshot",
            "source_snapshot": source,
            "source_snapshot_sha256": source_sha256,
            "created_at_unix": int(time.time()),
            "retention": {
                "mode": retention_mode,
                "automatic_deletion": False,
                "max_events": MAX_EVENTS,
                "max_trace_bytes": MAX_TRACE_BYTES,
                "state_root_is_explicit": True,
            },
            "privacy": {
                "free_text_capture": False,
                "abandonment_reason_is_allowlisted_code": True,
                "forbidden_capture_categories": list(FORBIDDEN_CAPTURE_CATEGORIES),
            },
            "historical_evidence_only": True,
            "routing_effect": False,
            "policy_effect": False,
            "does_not_establish": list(DOES_NOT_ESTABLISH),
        }
        if paths["manifest"].exists():
            manifest, _ = _load_manifest(root, identifier, attempt)
            if (
                manifest.get("source_snapshot") != source
                or manifest.get("source_snapshot_sha256") != source_sha256
                or manifest.get("retention", {}).get("mode") != retention_mode
            ):
                raise TraceProducerError(
                    "existing trace session conflicts with requested source"
                )
            created = False
        else:
            manifest = {
                **manifest_unsigned,
                "manifest_sha256": sha256_json(manifest_unsigned),
            }
            _create_private_json(paths["manifest"], manifest)
            created = True
        event = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "step": 0,
            "kind": "run.started",
        }
        append = _append_event(
            paths["trace"], event, run_id=manifest["run_id"]
        )
    return {
        "schema_version": PRODUCER_SCHEMA_VERSION,
        "status": "opened",
        "created": created,
        "task_id": identifier,
        "attempt": attempt,
        "run_id": manifest["run_id"],
        "manifest_sha256": manifest["manifest_sha256"],
        "source_snapshot_sha256": source_sha256,
        "trace_path": str(paths["trace"]),
        "retention_mode": retention_mode,
        **append,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }


def record_event(
    state_root: Path,
    task_id: str,
    attempt: int,
    *,
    step: int,
    kind: str,
    monitor_id: str | None = None,
    cadence_steps: int | None = None,
    grace_steps: int = 0,
    commitment_id: str | None = None,
    horizon_steps: int = 10,
    reason: str | None = None,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    root = _ensure_private_root(state_root)
    identifier = _validate_task_id(task_id)
    selected_attempt = _validate_attempt(attempt)
    selected_step = _validate_step(step)
    if kind not in RECORD_KINDS:
        raise TraceProducerError(f"kind must be one of {sorted(RECORD_KINDS)}")
    paths = _paths(root, identifier, selected_attempt)
    with _session_lock(paths["lock"]):
        manifest, paths = _load_manifest(root, identifier, selected_attempt)
        if paths["closeout"].exists():
            raise TraceProducerError("trace is already closed")
        event: dict[str, Any] = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "step": selected_step,
            "kind": kind,
        }
        if kind == "monitor.requirement":
            event.update(
                {
                    "monitor_id": _token(monitor_id, field="monitor_id"),
                    "cadence_steps": _validate_positive_int(
                        cadence_steps, field="cadence_steps"
                    ),
                    "grace_steps": _validate_positive_int(
                        grace_steps, field="grace_steps", minimum=0
                    ),
                }
            )
        elif kind == "monitor.check":
            event["monitor_id"] = _token(monitor_id, field="monitor_id")
        elif kind == "commitment.declared":
            event.update(
                {
                    "commitment_id": _token(
                        commitment_id, field="commitment_id"
                    ),
                    "horizon_steps": _validate_positive_int(
                        horizon_steps, field="horizon_steps"
                    ),
                }
            )
        elif kind == "commitment.completed":
            event["commitment_id"] = _token(
                commitment_id, field="commitment_id"
            )
        elif kind == "commitment.abandoned":
            event.update(
                {
                    "commitment_id": _token(
                        commitment_id, field="commitment_id"
                    ),
                    "reason": reason,
                    "evidence_refs": _safe_evidence_refs(evidence_refs),
                }
            )
            if reason not in ABANDONMENT_REASONS:
                raise TraceProducerError(
                    f"reason must be one of {sorted(ABANDONMENT_REASONS)}"
                )
        _validate_event_shape(event, expected_run_id=manifest["run_id"])
        append = _append_event(
            paths["trace"], event, run_id=manifest["run_id"]
        )
    return {
        "schema_version": PRODUCER_SCHEMA_VERSION,
        "status": "recorded",
        "task_id": identifier,
        "attempt": selected_attempt,
        "run_id": manifest["run_id"],
        "kind": kind,
        "step": selected_step,
        "trace_path": str(paths["trace"]),
        **append,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }


def close_trace(
    state_root: Path, task_id: str, attempt: int, *, step: int
) -> dict[str, Any]:
    root = _ensure_private_root(state_root)
    identifier = _validate_task_id(task_id)
    selected_attempt = _validate_attempt(attempt)
    selected_step = _validate_step(step)
    paths = _paths(root, identifier, selected_attempt)
    with _session_lock(paths["lock"]):
        manifest, paths = _load_manifest(root, identifier, selected_attempt)
        terminal = {
            "schema_version": TRACE_SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "step": selected_step,
            "kind": "run.terminal",
        }
        append = _append_event(
            paths["trace"], terminal, run_id=manifest["run_id"]
        )
        events, raw = _load_trace(paths["trace"], run_id=manifest["run_id"])
        closeout_unsigned = {
            "schema_version": CLOSEOUT_SCHEMA_VERSION,
            "task_id": identifier,
            "attempt": selected_attempt,
            "run_id": manifest["run_id"],
            "manifest_sha256": manifest["manifest_sha256"],
            "trace_sha256": _sha256_bytes(raw),
            "event_count": len(events),
            "terminal_step": selected_step,
            "historical_evidence_only": True,
            "routing_effect": False,
            "policy_effect": False,
            "does_not_establish": list(DOES_NOT_ESTABLISH),
        }
        closeout = {
            **closeout_unsigned,
            "closeout_sha256": sha256_json(closeout_unsigned),
        }
        if paths["closeout"].exists():
            existing = _read_private_json(
                paths["closeout"], maximum=MAX_MANIFEST_BYTES
            )
            if existing != closeout:
                raise TraceProducerError(
                    "existing trace closeout conflicts with trace"
                )
            closeout_created = False
        else:
            _create_private_json(paths["closeout"], closeout)
            closeout_created = True
    return {
        "schema_version": PRODUCER_SCHEMA_VERSION,
        "status": "closed",
        "task_id": identifier,
        "attempt": selected_attempt,
        "run_id": manifest["run_id"],
        "trace_path": str(paths["trace"]),
        "trace_sha256": closeout["trace_sha256"],
        "closeout_sha256": closeout["closeout_sha256"],
        "closeout_created": closeout_created,
        **append,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }

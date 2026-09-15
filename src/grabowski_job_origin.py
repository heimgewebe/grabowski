from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any

from grabowski_consumer_surface import canonical_json_bytes

ORIGIN_SCHEMA_VERSION = 1
ORIGIN_KIND = "grabowski_job_origin"
ORIGIN_INVOCATION_RE = re.compile(r"grabowski_[a-z0-9_]{1,80}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})")
OWNER_RE = re.compile(r"uid:[0-9]+")
STARTED_AT_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
_ORIGIN_FIELDS = {
    "schema_version",
    "kind",
    "invoker_tool",
    "unit",
    "job_id",
    "owner",
    "argv_sha256",
    "scope",
    "notify_on_done",
    "created_at_unix",
    "started_at",
}
_NOTIFY_FIELDS = {"requested", "channels", "note"}

DECISION_REVIEW_BINDING_KIND = "grabowski_decision_bound_review"
DECISION_REVIEW_ORDER_KIND = "grabowski_decision_review_logical_clock"
DECISION_REVIEW_ORDER_SCHEMA_VERSION = 1
DECISION_REVIEW_ORDER_ROOT = (
    Path.home() / ".local" / "state" / "grabowski" / "decision-review-order"
)
DECISION_REVIEW_JOBS_ROOT = Path.home() / ".local" / "state" / "grabowski" / "jobs"
DECISION_REVIEW_ORDER_MAX_BYTES = 4096
DECISION_REVIEW_ORDER_MAX_JOB_DIRECTORIES = 10_000
DECISION_REVIEW_ORDER_MAX_METADATA_BYTES = 256 * 1024
DECISION_REVIEW_ORDER_MAX_NS = (1 << 63) - 1
_DECISION_REVIEW_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_DECISION_REVIEW_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_DECISION_REVIEW_ORDER_FIELDS = {
    "schema_version",
    "kind",
    "key_sha256",
    "last_logical_ns",
}


def notification_request(value: dict[str, Any]) -> dict[str, Any]:
    requested = value.get("requested")
    channels = value.get("channels")
    if not isinstance(requested, bool):
        raise ValueError("origin notification request flag is invalid")
    if (
        not isinstance(channels, list)
        or len(channels) > 5
        or not all(
            isinstance(item, str) and 0 < len(item) <= 40 for item in channels
        )
    ):
        raise ValueError("origin notification channels are invalid")
    result: dict[str, Any] = {"requested": requested, "channels": list(channels)}
    if "note" in value:
        note = value["note"]
        if not isinstance(note, str) or not note or len(note) > 200:
            raise ValueError("origin notification note is invalid")
        result["note"] = note
    return result


def _decision_review_order_key(scope: dict[str, Any]) -> str | None:
    binding = scope.get("decision_bound_review")
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise ValueError("decision review binding is invalid for causal ordering")
    if binding.get("kind") != DECISION_REVIEW_BINDING_KIND:
        raise ValueError("decision review binding kind is invalid for causal ordering")
    repo = binding.get("repo")
    pr = binding.get("pr")
    head_sha = binding.get("head_sha")
    if (
        not isinstance(repo, str)
        or _DECISION_REVIEW_REPO_RE.fullmatch(repo.strip()) is None
        or isinstance(pr, bool)
        or not isinstance(pr, int)
        or pr <= 0
        or not isinstance(head_sha, str)
        or _DECISION_REVIEW_SHA40_RE.fullmatch(head_sha.strip().lower()) is None
    ):
        raise ValueError("decision review binding is invalid for causal ordering")
    material = {
        "repo": repo.strip().lower(),
        "pr": pr,
        "head_sha": head_sha.strip().lower(),
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _validate_decision_review_order_point(
    scope: dict[str, Any], created_at_unix: int
) -> int | None:
    key = _decision_review_order_key(scope)
    if key is None or "started_at_unix_ns" not in scope:
        return None
    started_at_unix_ns = scope.get("started_at_unix_ns")
    if (
        isinstance(started_at_unix_ns, bool)
        or not isinstance(started_at_unix_ns, int)
        or started_at_unix_ns < 0
        or started_at_unix_ns > DECISION_REVIEW_ORDER_MAX_NS
        or started_at_unix_ns // 1_000_000_000 != created_at_unix
    ):
        raise ValueError("decision review causal ordering seed is invalid")
    return started_at_unix_ns


def _ensure_private_directory(path: Path, *, label: str) -> None:
    if path.exists() and path.is_symlink():
        raise PermissionError(f"{label} may not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise PermissionError(f"{label} is not a private owned directory")


def _read_exact_fd(descriptor: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise ValueError("decision review ordering state was truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _legacy_decision_review_upper_bound_ns(created_at_unix: int) -> int:
    if (
        isinstance(created_at_unix, bool)
        or not isinstance(created_at_unix, int)
        or created_at_unix < 0
    ):
        raise ValueError("existing decision review creation time is invalid")
    upper_bound = created_at_unix * 1_000_000_000 + 999_999_999
    if upper_bound > DECISION_REVIEW_ORDER_MAX_NS:
        raise OverflowError("legacy decision review ordering frontier is exhausted")
    return upper_bound


def _existing_decision_review_max_ns(key_sha256: str) -> int:
    root = DECISION_REVIEW_JOBS_ROOT
    try:
        root_metadata = root.lstat()
    except FileNotFoundError:
        return -1
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise PermissionError("decision review jobs root is unsafe")
    directories = list(root.iterdir())
    if len(directories) > DECISION_REVIEW_ORDER_MAX_JOB_DIRECTORIES:
        raise ValueError("decision review job bootstrap exceeds directory limit")
    maximum = -1
    for directory in directories:
        try:
            directory_metadata = directory.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(
            directory_metadata.st_mode
        ):
            continue
        metadata_path = directory / "metadata.json"
        try:
            metadata_stat = metadata_path.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISREG(metadata_stat.st_mode)
            or metadata_stat.st_nlink != 1
            or stat.S_IMODE(metadata_stat.st_mode) & 0o077
            or metadata_stat.st_size > DECISION_REVIEW_ORDER_MAX_METADATA_BYTES
        ):
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(metadata, dict):
            continue
        origin = metadata.get("origin")
        origin_sha256 = metadata.get("origin_sha256")
        if not isinstance(origin, dict) or not isinstance(origin_sha256, str):
            continue
        calculated = hashlib.sha256(canonical_json_bytes(origin)).hexdigest()
        if not hmac.compare_digest(origin_sha256, calculated):
            continue
        scope = origin.get("scope")
        created = origin.get("created_at_unix")
        if not isinstance(scope, dict):
            continue
        try:
            candidate_key = _decision_review_order_key(scope)
        except ValueError:
            continue
        if candidate_key != key_sha256:
            continue
        if "started_at_unix_ns" not in scope:
            maximum = max(maximum, _legacy_decision_review_upper_bound_ns(created))
            continue
        candidate = scope.get("started_at_unix_ns")
        if (
            isinstance(created, bool)
            or not isinstance(created, int)
            or created < 0
            or isinstance(candidate, bool)
            or not isinstance(candidate, int)
            or candidate < 0
            or candidate > DECISION_REVIEW_ORDER_MAX_NS
            or candidate // 1_000_000_000 != created
        ):
            raise ValueError("existing decision review ordering evidence is invalid")
        maximum = max(maximum, candidate)
    return maximum


def _read_decision_review_order_state(
    descriptor: int, *, key_sha256: str
) -> int | None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size > DECISION_REVIEW_ORDER_MAX_BYTES
    ):
        raise PermissionError("decision review ordering state file is unsafe")
    if metadata.st_size == 0:
        return None
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = _read_exact_fd(descriptor, metadata.st_size)
    try:
        state = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("decision review ordering state is invalid JSON") from exc
    if not isinstance(state, dict) or set(state) != _DECISION_REVIEW_ORDER_FIELDS:
        raise ValueError("decision review ordering state has an invalid shape")
    last_logical_ns = state.get("last_logical_ns")
    if (
        state.get("schema_version") != DECISION_REVIEW_ORDER_SCHEMA_VERSION
        or isinstance(state.get("schema_version"), bool)
        or state.get("kind") != DECISION_REVIEW_ORDER_KIND
        or state.get("key_sha256") != key_sha256
        or isinstance(last_logical_ns, bool)
        or not isinstance(last_logical_ns, int)
        or last_logical_ns < 0
        or last_logical_ns > DECISION_REVIEW_ORDER_MAX_NS
    ):
        raise ValueError("decision review ordering state is invalid")
    return last_logical_ns


def _read_decision_review_order_state_path(
    path: Path, *, key_sha256: str
) -> int | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        return _read_decision_review_order_state(
            descriptor, key_sha256=key_sha256
        )
    finally:
        os.close(descriptor)


def _write_decision_review_order_state(
    path: Path, *, key_sha256: str, last_logical_ns: int
) -> None:
    state = {
        "schema_version": DECISION_REVIEW_ORDER_SCHEMA_VERSION,
        "kind": DECISION_REVIEW_ORDER_KIND,
        "key_sha256": key_sha256,
        "last_logical_ns": last_logical_ns,
    }
    payload = canonical_json_bytes(state)
    if len(payload) > DECISION_REVIEW_ORDER_MAX_BYTES:
        raise ValueError("decision review ordering state is too large")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{key_sha256}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short decision review ordering state write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _allocate_decision_review_order(
    scope: dict[str, Any], created_at_unix: int
) -> int:
    observed_ns = _validate_decision_review_order_point(scope, created_at_unix)
    if observed_ns is None:
        return created_at_unix
    key_sha256 = _decision_review_order_key(scope)
    if key_sha256 is None:
        return created_at_unix
    root = DECISION_REVIEW_ORDER_ROOT
    _ensure_private_directory(root, label="decision review ordering root")
    path = root / f"{key_sha256}.json"
    lock_path = root / f"{key_sha256}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(lock_metadata.st_mode) & 0o077
        ):
            raise PermissionError("decision review ordering lock file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        stored_logical_ns = _read_decision_review_order_state_path(
            path, key_sha256=key_sha256
        )
        existing_logical_ns = _existing_decision_review_max_ns(key_sha256)
        last_logical_ns = max(
            -1 if stored_logical_ns is None else stored_logical_ns,
            existing_logical_ns,
        )
        if last_logical_ns >= DECISION_REVIEW_ORDER_MAX_NS:
            raise OverflowError("decision review logical clock is exhausted")
        logical_ns = max(observed_ns, last_logical_ns + 1)
        if logical_ns > DECISION_REVIEW_ORDER_MAX_NS:
            raise OverflowError("decision review logical clock is exhausted")
        _write_decision_review_order_state(
            path,
            key_sha256=key_sha256,
            last_logical_ns=logical_ns,
        )
        scope["started_at_unix_ns"] = logical_ns
        return logical_ns // 1_000_000_000
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _build_origin(
    *,
    unit: str,
    owner: str,
    argv_sha256: str,
    scope: dict[str, Any],
    notify_on_done: dict[str, Any],
    created_at_unix: int,
    started_at: str,
    invoker_tool: str,
    allocate_decision_review_order: bool,
) -> tuple[dict[str, Any], str]:
    match = UNIT_RE.fullmatch(unit) if isinstance(unit, str) else None
    if match is None:
        raise ValueError("origin unit is invalid")
    if not isinstance(owner, str) or OWNER_RE.fullmatch(owner) is None:
        raise ValueError("origin owner is invalid")
    if not isinstance(argv_sha256, str) or SHA256_RE.fullmatch(argv_sha256) is None:
        raise ValueError("origin argv hash is invalid")
    if not isinstance(scope, dict):
        raise ValueError("origin scope is invalid")
    if (
        isinstance(created_at_unix, bool)
        or not isinstance(created_at_unix, int)
        or created_at_unix < 0
    ):
        raise ValueError("origin creation time is invalid")
    if not isinstance(started_at, str) or STARTED_AT_RE.fullmatch(started_at) is None:
        raise ValueError("origin start time is invalid")
    if (
        not isinstance(invoker_tool, str)
        or ORIGIN_INVOCATION_RE.fullmatch(invoker_tool) is None
    ):
        raise ValueError("origin invoker tool is invalid")
    if allocate_decision_review_order:
        created_at_unix = _allocate_decision_review_order(scope, created_at_unix)
    else:
        _validate_decision_review_order_point(scope, created_at_unix)
    origin = {
        "schema_version": ORIGIN_SCHEMA_VERSION,
        "kind": ORIGIN_KIND,
        "invoker_tool": invoker_tool,
        "unit": unit,
        "job_id": match.group(1),
        "owner": owner,
        "argv_sha256": argv_sha256,
        "scope": scope,
        "notify_on_done": notification_request(notify_on_done),
        "created_at_unix": created_at_unix,
        "started_at": started_at,
    }
    return origin, hashlib.sha256(canonical_json_bytes(origin)).hexdigest()


def build_origin(
    *,
    unit: str,
    owner: str,
    argv_sha256: str,
    scope: dict[str, Any],
    notify_on_done: dict[str, Any],
    created_at_unix: int,
    started_at: str,
    invoker_tool: str,
) -> tuple[dict[str, Any], str]:
    return _build_origin(
        unit=unit,
        owner=owner,
        argv_sha256=argv_sha256,
        scope=scope,
        notify_on_done=notify_on_done,
        created_at_unix=created_at_unix,
        started_at=started_at,
        invoker_tool=invoker_tool,
        allocate_decision_review_order=True,
    )


def validate_origin(
    origin: Any,
    origin_sha256: Any,
    *,
    expected_unit: str | None = None,
    expected_invoker_tool: str | None = None,
    expected_origin_sha256: str | None = None,
) -> dict[str, Any]:
    if not isinstance(origin, dict) or set(origin) != _ORIGIN_FIELDS:
        raise ValueError("job origin schema is invalid")
    rebuilt, calculated = _build_origin(
        unit=origin.get("unit"),
        owner=origin.get("owner"),
        argv_sha256=origin.get("argv_sha256"),
        scope=origin.get("scope"),
        notify_on_done=origin.get("notify_on_done"),
        created_at_unix=origin.get("created_at_unix"),
        started_at=origin.get("started_at"),
        invoker_tool=origin.get("invoker_tool"),
        allocate_decision_review_order=False,
    )
    if rebuilt != origin:
        raise ValueError("job origin normalization mismatch")
    if not isinstance(origin_sha256, str) or SHA256_RE.fullmatch(origin_sha256) is None:
        raise ValueError("job origin hash is invalid")
    if not hmac.compare_digest(origin_sha256, calculated):
        raise ValueError("job origin hash mismatch")
    if expected_origin_sha256 is not None and not hmac.compare_digest(
        origin_sha256,
        expected_origin_sha256,
    ):
        raise ValueError("job origin does not match the launcher precondition")
    if expected_unit is not None and origin.get("unit") != expected_unit:
        raise ValueError("job origin unit binding mismatch")
    if (
        expected_invoker_tool is not None
        and origin.get("invoker_tool") != expected_invoker_tool
    ):
        raise ValueError("job origin invoker binding mismatch")
    notify = origin.get("notify_on_done")
    if not isinstance(notify, dict) or not set(notify).issubset(_NOTIFY_FIELDS):
        raise ValueError("job origin notification request is invalid")
    return origin

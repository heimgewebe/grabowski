from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Iterator

import grabowski_consumer_surface as consumer_surface
import grabowski_private_io as private_io
import grabowski_tasks as tasks
import grabowski_terminal_convergence as terminal_convergence

try:
    alert_outbox = importlib.import_module("grabowski_alert_outbox")
except ModuleNotFoundError as exc:
    if exc.name != "grabowski_alert_outbox":
        raise
    alert_outbox = None


SCHEMA_VERSION = 1
DECISION_KIND = "grabowski_task_attention_decision"
DECISIONS = frozenset({"closed", "deferred", "superseded"})
ATTENTION_VIEWS = frozenset({"current", "history"})
CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS = frozenset(
    {"decision_closed", "decision_superseded"}
)
ARCHIVE_RESOLVED_CLASSIFICATIONS = CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS
TERMINAL_ATTENTION_STATES = frozenset({"failed", "timed_out", "signalled"})
RECOVERY_ATTENTION_STATES = frozenset({"interrupted", "outcome_unknown"})
ATTENTION_STATES = tuple(tasks.TASK_STATE_PROJECTIONS["attention"])
MAX_RECORD_BYTES = 64 * 1024
MAX_TEXT_BYTES = 2_048
MAX_PAGE_LIMIT = 100
MAX_CURRENT_SCAN_ROWS = 5 * MAX_PAGE_LIMIT
MAX_CURRENT_CONVERGENCE_ROWS = 50_000
LOCK_TIMEOUT_SECONDS = 5.0
LOCK_POLL_SECONDS = 0.02
ARCHIVE_EFFECT_LEASE_TTL_SECONDS = 120
TASK_OUTPUT_MINIMUM_RETENTION_SECONDS = 24 * 60 * 60
TASK_OUTPUT_CLEANUP_CURSOR_METADATA_KEY = (
    "task_output_cleanup_cursor_v1"
)
DEFAULT_TASK_OUTPUT_CLEANUP_BATCH_SIZE = 10
MAX_TASK_OUTPUT_CLEANUP_BATCH_SIZE = 100
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
AUTHORITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}\Z")
DECISION_FILE_RE = re.compile(r"(?P<task_id>[0-9a-f]{24})\.a(?P<attempt>[1-9][0-9]*)\.json\Z")


class TaskAttentionError(RuntimeError):
    pass


class TaskAttentionInputError(ValueError):
    pass


class TaskAttentionIntegrityError(TaskAttentionError):
    pass


class TaskAttentionConflictError(TaskAttentionError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_sha256(value: Any, *, label: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise TaskAttentionInputError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_text(value: Any, *, label: str, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaskAttentionInputError(f"{label} must be a non-empty string")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > maximum:
        raise TaskAttentionInputError(f"{label} exceeds the size bound")
    return normalized


def _validate_authority(value: Any) -> str:
    if not isinstance(value, str) or AUTHORITY_RE.fullmatch(value) is None:
        raise TaskAttentionInputError("authority must be a bounded named authority")
    return value


def _validate_exact_keys(
    value: Any,
    *,
    allowed: set[str],
    required: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TaskAttentionInputError(f"{label} must be an object")
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise TaskAttentionInputError(f"{label} contains unknown keys: {unknown}")
    if missing:
        raise TaskAttentionInputError(f"{label} is missing keys: {missing}")
    return dict(value)


def _state_root() -> Path:
    configured = os.environ.get("GRABOWSKI_TASK_ATTENTION_ROOT")
    root = (
        Path(configured).expanduser()
        if configured
        else tasks.TASK_DB.with_suffix(".attention-decisions")
    )
    if not root.is_absolute():
        raise TaskAttentionIntegrityError("task attention root must be absolute")
    return root


def _ensure_private_directory(path: Path, *, create: bool) -> None:
    if create:
        try:
            path.mkdir(parents=True, mode=0o700)
        except FileExistsError:
            pass
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise TaskAttentionIntegrityError(f"unsafe private directory: {path}")


def _read_private_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_RECORD_BYTES
        ):
            raise TaskAttentionIntegrityError(f"unsafe {label}: {path}")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise TaskAttentionIntegrityError(f"short {label} read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise TaskAttentionIntegrityError(f"{label} changed during read: {path}")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TaskAttentionIntegrityError(f"invalid {label} JSON: {path}") from exc
    if not isinstance(value, dict):
        raise TaskAttentionIntegrityError(f"{label} is not an object: {path}")
    return value, hashlib.sha256(raw).hexdigest()


@contextmanager
def _state_lock(*, shared: bool = False, create: bool = True) -> Iterator[None]:
    root = _state_root()
    _ensure_private_directory(root, create=create)
    lock_path = root / ".lock"
    flags = os.O_RDWR | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise TaskAttentionIntegrityError("task attention lock is unsafe")
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        lock_mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        while True:
            try:
                fcntl.flock(descriptor, lock_mode | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TaskAttentionError("task attention lock timed out")
                time.sleep(LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def decision_snapshot_lock() -> Iterator[None]:
    """Hold a shared snapshot boundary against create-only decision writes."""
    with _state_lock(shared=True, create=False):
        yield


@contextmanager
def decision_snapshot_guard() -> Iterator[dict[str, str | None]]:
    """Return one stable decision-store generation without read-side creation."""
    root = _state_root()
    try:
        _ensure_private_directory(root, create=False)
    except FileNotFoundError:
        # Linearize an absent decision store at this observation. A writer may
        # create the store afterwards, but this read remains a valid pre-write
        # snapshot and the next attention cursor will bind the newer generation.
        yield {"status": "absent", "evidence_error": None}
        return
    except (TaskAttentionError, OSError) as exc:
        yield {"status": "degraded", "evidence_error": type(exc).__name__}
        return

    lock = decision_snapshot_lock()
    try:
        lock.__enter__()
    except (FileNotFoundError, TaskAttentionError, OSError) as exc:
        yield {"status": "degraded", "evidence_error": type(exc).__name__}
        return
    try:
        yield {"status": "locked", "evidence_error": None}
    finally:
        lock.__exit__(None, None, None)


def _task_binding(record: dict[str, Any]) -> dict[str, Any]:
    envelope = record.get("execution_envelope_sha256")
    if envelope is not None and (
        not isinstance(envelope, str) or SHA256_RE.fullmatch(envelope) is None
    ):
        raise TaskAttentionIntegrityError("task execution envelope binding is invalid")
    argv_sha256 = record.get("argv_sha256")
    if not isinstance(argv_sha256, str) or SHA256_RE.fullmatch(argv_sha256) is None:
        raise TaskAttentionIntegrityError("task argv binding is invalid")
    attempt = record.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise TaskAttentionIntegrityError("task attempt binding is invalid")
    return {
        "task_id": tasks._validate_task_id(record.get("task_id")),
        "attempt": attempt,
        "unit": tasks._validate_unit(record.get("unit")),
        "authoritative_unit": tasks._authoritative_unit(record),
        "argv_sha256": argv_sha256,
        "execution_envelope_sha256": envelope,
    }


def _validate_expected_binding(
    parameters: dict[str, Any],
    binding: dict[str, Any],
) -> None:
    expected_attempt = parameters["expected_attempt"]
    if isinstance(expected_attempt, bool) or not isinstance(expected_attempt, int) or expected_attempt < 1:
        raise TaskAttentionInputError("expected_attempt must be a positive integer")
    expected_task_unit = _validate_text(
        parameters["expected_unit"],
        label="expected_unit",
        maximum=255,
    )
    expected_unit = _validate_text(
        parameters["expected_authoritative_unit"],
        label="expected_authoritative_unit",
        maximum=255,
    )
    expected_argv = _validate_sha256(
        parameters["expected_argv_sha256"],
        label="expected_argv_sha256",
    )
    expected_envelope = _validate_sha256(
        parameters["expected_execution_envelope_sha256"],
        label="expected_execution_envelope_sha256",
        optional=True,
    )
    expected = {
        "task_id": parameters["task_id"],
        "attempt": expected_attempt,
        "unit": expected_task_unit,
        "authoritative_unit": expected_unit,
        "argv_sha256": expected_argv,
        "execution_envelope_sha256": expected_envelope,
    }
    if expected != binding:
        raise TaskAttentionConflictError("current task binding does not match the expected decision target")


def _outcome_paths(task_id: str) -> tuple[Path, Path]:
    return (
        tasks.TASK_OUTCOMES_DIR / f"{task_id}.json",
        tasks.TASK_OUTCOMES_DIR / f"{task_id}.lifecycle.json",
    )


def _validate_outcome_receipt(
    value: dict[str, Any],
    *,
    record: dict[str, Any],
    binding: dict[str, Any],
    expected_receipt_sha256: str | None,
    allowed_states: frozenset[str] = TERMINAL_ATTENTION_STATES,
) -> str:
    base_required = {
        "schema_version",
        "task_id",
        "unit",
        "authoritative_unit",
        "execution_backend",
        "systemd_scope",
        "attempt",
        "state",
        "argv_sha256",
        "execution_envelope_sha256",
        "resource_keys",
        "observed_at_unix",
        "observation_sha256",
        "observation",
        "receipt_sha256",
    }
    schema_version = value.get("schema_version")
    if schema_version == 1:
        if set(value) != base_required:
            raise TaskAttentionIntegrityError("task outcome receipt fields are invalid")
    elif schema_version == 2:
        if set(value) != base_required | {"kind", "terminalization"}:
            raise TaskAttentionIntegrityError("task lifecycle receipt fields are invalid")
        if value.get("kind") != "grabowski_task_lifecycle_receipt":
            raise TaskAttentionIntegrityError("task lifecycle receipt kind is invalid")
    else:
        raise TaskAttentionIntegrityError("task outcome receipt schema is unsupported")
    receipt_sha256 = value["receipt_sha256"]
    if not isinstance(receipt_sha256, str) or SHA256_RE.fullmatch(receipt_sha256) is None:
        raise TaskAttentionIntegrityError("task outcome receipt hash is invalid")
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if receipt_sha256 != _sha256_json(material):
        raise TaskAttentionIntegrityError("task outcome receipt self-hash is invalid")
    if expected_receipt_sha256 is not None and receipt_sha256 != expected_receipt_sha256:
        raise TaskAttentionConflictError("task outcome receipt does not match expected hash")
    if value["task_id"] != binding["task_id"]:
        raise TaskAttentionIntegrityError("task outcome receipt task binding is invalid")
    if value["attempt"] != binding["attempt"]:
        raise TaskAttentionIntegrityError("task outcome receipt attempt binding is invalid")
    if value["unit"] != binding["unit"]:
        raise TaskAttentionIntegrityError("task outcome receipt unit binding is invalid")
    if value["authoritative_unit"] != binding["authoritative_unit"]:
        raise TaskAttentionIntegrityError("task outcome receipt unit binding is invalid")
    if value["argv_sha256"] != binding["argv_sha256"]:
        raise TaskAttentionIntegrityError("task outcome receipt argv binding is invalid")
    if value["execution_envelope_sha256"] != binding["execution_envelope_sha256"]:
        raise TaskAttentionIntegrityError("task outcome receipt envelope binding is invalid")
    if value["state"] not in allowed_states:
        raise TaskAttentionIntegrityError("task outcome receipt state is not allowed for this closeout")
    observation = value["observation"]
    if not isinstance(observation, dict):
        raise TaskAttentionIntegrityError("task outcome observation is invalid")
    if value["observation_sha256"] != _sha256_json(observation):
        raise TaskAttentionIntegrityError("task outcome observation binding is invalid")
    observed_at = value["observed_at_unix"]
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise TaskAttentionIntegrityError("task outcome timestamp is invalid")
    resource_keys = value["resource_keys"]
    if (
        not isinstance(resource_keys, list)
        or resource_keys != sorted(set(resource_keys))
        or not all(isinstance(item, str) and item for item in resource_keys)
    ):
        raise TaskAttentionIntegrityError("task outcome resource binding is invalid")

    if schema_version == 2:
        terminalization = value["terminalization"]
        terminalization_required = {
            "kind",
            "transition_sha256",
            "task_projection_sha256",
            "requested_resource_keys",
            "requested_resource_keys_sha256",
            "prior_leases",
            "prior_leases_sha256",
            "revoked_resource_keys",
            "missing_resource_keys",
            "prepared_at_unix",
            "leases_revoked_at_unix",
            "recovery_status",
        }
        if not isinstance(terminalization, dict) or set(terminalization) != terminalization_required:
            raise TaskAttentionIntegrityError("task lifecycle terminalization fields are invalid")
        if terminalization["kind"] != "grabowski_task_terminalization":
            raise TaskAttentionIntegrityError("task lifecycle terminalization kind is invalid")
        for field in (
            "transition_sha256",
            "task_projection_sha256",
            "requested_resource_keys_sha256",
            "prior_leases_sha256",
        ):
            field_value = terminalization[field]
            if not isinstance(field_value, str) or SHA256_RE.fullmatch(field_value) is None:
                raise TaskAttentionIntegrityError(
                    f"task lifecycle terminalization {field} is invalid"
                )
        requested_keys = terminalization["requested_resource_keys"]
        revoked_keys = terminalization["revoked_resource_keys"]
        missing_keys = terminalization["missing_resource_keys"]
        for label, keys in (
            ("requested", requested_keys),
            ("revoked", revoked_keys),
            ("missing", missing_keys),
        ):
            if (
                not isinstance(keys, list)
                or keys != sorted(set(keys))
                or not all(isinstance(item, str) and item for item in keys)
            ):
                raise TaskAttentionIntegrityError(
                    f"task lifecycle terminalization {label} resources are invalid"
                )
        if requested_keys != resource_keys:
            raise TaskAttentionIntegrityError(
                "task lifecycle requested resources do not match outcome resources"
            )
        if terminalization["requested_resource_keys_sha256"] != _sha256_json(requested_keys):
            raise TaskAttentionIntegrityError("task lifecycle requested resource hash is invalid")
        if missing_keys != sorted(set(requested_keys) - set(revoked_keys)):
            raise TaskAttentionIntegrityError("task lifecycle missing resource set is invalid")
        prior_leases = terminalization["prior_leases"]
        if not isinstance(prior_leases, list) or not all(
            isinstance(item, dict) and isinstance(item.get("resource_key"), str)
            for item in prior_leases
        ):
            raise TaskAttentionIntegrityError("task lifecycle prior lease evidence is invalid")
        if terminalization["prior_leases_sha256"] != _sha256_json(prior_leases):
            raise TaskAttentionIntegrityError("task lifecycle prior lease hash is invalid")
        if sorted(item["resource_key"] for item in prior_leases) != revoked_keys:
            raise TaskAttentionIntegrityError("task lifecycle revoked lease evidence is invalid")
        prepared_at = terminalization["prepared_at_unix"]
        revoked_at = terminalization["leases_revoked_at_unix"]
        if (
            isinstance(prepared_at, bool)
            or not isinstance(prepared_at, int)
            or prepared_at < 0
            or isinstance(revoked_at, bool)
            or not isinstance(revoked_at, int)
            or revoked_at < prepared_at
        ):
            raise TaskAttentionIntegrityError("task lifecycle terminalization timestamps are invalid")
        recovery_status = terminalization["recovery_status"]
        if recovery_status not in {
            "not_recovered",
            "recovered_legacy_row_first",
            "recovered_after_revocation",
        }:
            raise TaskAttentionIntegrityError("task lifecycle recovery status is invalid")
        task_projection = {
            "task_id": record["task_id"],
            "state": record["state"],
            "updated_at_unix": record["updated_at_unix"],
            "launcher_json": record["launcher_json"],
            "last_observation_json": record.get("last_observation_json"),
            "unit": record["unit"],
            "authoritative_unit": tasks._authoritative_unit(record),
            "attempt": int(record["attempt"]),
        }
        if terminalization["task_projection_sha256"] != _sha256_json(task_projection):
            raise TaskAttentionIntegrityError("task lifecycle task projection hash is invalid")
        transition_material = {
            "schema_version": 1,
            "kind": terminalization["kind"],
            "task_id": binding["task_id"],
            "attempt": binding["attempt"],
            "lease_owner_id": f"task:{binding['task_id']}",
            "terminal_state": value["state"],
            "task_projection_sha256": terminalization["task_projection_sha256"],
            "requested_resource_keys_sha256": terminalization[
                "requested_resource_keys_sha256"
            ],
            "prior_leases_sha256": terminalization["prior_leases_sha256"],
            "revoked_resource_keys": revoked_keys,
            "missing_resource_keys": missing_keys,
            "observation_sha256": value["observation_sha256"],
            "prepared_at_unix": prepared_at,
            "leases_revoked_at_unix": revoked_at,
            "recovery_status": recovery_status,
        }
        if terminalization["transition_sha256"] != _sha256_json(transition_material):
            raise TaskAttentionIntegrityError("task lifecycle transition hash is invalid")
        if record.get("terminalization_sha256") != terminalization["transition_sha256"]:
            raise TaskAttentionIntegrityError("task lifecycle task-row transition binding is invalid")
        if record.get("lifecycle_receipt_sha256") != receipt_sha256:
            raise TaskAttentionIntegrityError("task lifecycle task-row receipt binding is invalid")
    return receipt_sha256


def _lifecycle_binding(record: dict[str, Any]) -> tuple[str | None, str | None]:
    terminalization_sha256 = record.get("terminalization_sha256")
    lifecycle_receipt_sha256 = record.get("lifecycle_receipt_sha256")
    for label, value in (
        ("terminalization", terminalization_sha256),
        ("lifecycle receipt", lifecycle_receipt_sha256),
    ):
        if value is not None and (
            not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
        ):
            raise TaskAttentionIntegrityError(
                f"task lifecycle {label} binding is invalid"
            )
    if (terminalization_sha256 is None) != (lifecycle_receipt_sha256 is None):
        raise TaskAttentionConflictError("task lifecycle binding is incomplete")
    return terminalization_sha256, lifecycle_receipt_sha256


def _read_valid_outcome(
    record: dict[str, Any],
    *,
    expected_receipt_sha256: str | None,
    allowed_states: frozenset[str] = TERMINAL_ATTENTION_STATES,
) -> tuple[dict[str, Any], str, str]:
    binding = _task_binding(record)
    _terminalization_sha256, authoritative_receipt_sha256 = _lifecycle_binding(record)
    if authoritative_receipt_sha256 is not None:
        if (
            expected_receipt_sha256 is not None
            and expected_receipt_sha256 != authoritative_receipt_sha256
        ):
            raise TaskAttentionConflictError(
                "task outcome receipt does not match authoritative task-row hash"
            )
        expected_receipt_sha256 = authoritative_receipt_sha256

    _ensure_private_directory(tasks.TASK_OUTCOMES_DIR, create=False)
    primary_path, lifecycle_path = _outcome_paths(binding["task_id"])
    paths = (primary_path, lifecycle_path)
    if authoritative_receipt_sha256 is not None:
        # Prefer the dedicated lifecycle path, but keep the primary path as a
        # compatibility location because current writers may have persisted the
        # authoritative v2 receipt there before a legacy primary existed.
        paths = (lifecycle_path, primary_path)
    first_missing: FileNotFoundError | None = None
    first_conflict: TaskAttentionConflictError | None = None
    for path in paths:
        try:
            value, file_sha256 = _read_private_json(
                path,
                label="task outcome receipt",
            )
        except FileNotFoundError as exc:
            if first_missing is None:
                first_missing = exc
            continue
        if (
            authoritative_receipt_sha256 is not None
            and value.get("receipt_sha256") != authoritative_receipt_sha256
        ):
            # A historical or unrelated receipt at the alternate compatibility
            # path has no authority once the task row binds an exact lifecycle
            # digest. Do not let its older schema mask the bound receipt.
            continue
        try:
            receipt_sha256 = _validate_outcome_receipt(
                value,
                record=record,
                binding=binding,
                expected_receipt_sha256=expected_receipt_sha256,
                allowed_states=allowed_states,
            )
        except TaskAttentionConflictError as exc:
            if first_conflict is None:
                first_conflict = exc
            continue
        return value, receipt_sha256, file_sha256

    if first_conflict is not None:
        raise first_conflict
    if first_missing is not None:
        raise first_missing
    raise FileNotFoundError(f"No task outcome receipt for {binding['task_id']}")


def _decision_path(binding: dict[str, Any]) -> Path:
    return _state_root() / f"{binding['task_id']}.a{binding['attempt']}.json"


def _schedule_owner_decision_alert(
    binding: dict[str, Any],
    decision: dict[str, Any],
) -> None:
    if alert_outbox is None:
        return
    try:
        alert_outbox.enqueue_and_schedule(
            event_class="owner_decision",
            producer="task_attention",
            correlation_key=f"{binding['task_id']}:a{binding['attempt']}",
            deduplication_key=str(decision["receipt_sha256"]),
            subject="task",
            fields={
                "attempt": str(binding["attempt"]),
                "decision": str(decision["decision"]),
            },
        )
    except Exception:
        # Alert publication and dispatch are advisory side effects. A failure
        # must not rewrite or invalidate the authoritative decision receipt.
        return


def _validate_decision_record(
    value: dict[str, Any],
    *,
    binding: dict[str, Any],
    outcome_receipt_sha256: str,
    outcome_file_sha256: str,
) -> dict[str, Any]:
    required = {
        "kind",
        "schema_version",
        "task_binding",
        "decision",
        "authority",
        "evidence_ref",
        "outcome_receipt_sha256",
        "outcome_file_sha256",
        "created_at_unix",
        "material_sha256",
        "receipt_sha256",
    }
    if set(value) != required:
        raise TaskAttentionIntegrityError("task attention decision fields are invalid")
    if value["kind"] != DECISION_KIND or value["schema_version"] != SCHEMA_VERSION:
        raise TaskAttentionIntegrityError("task attention decision schema is invalid")
    if value["task_binding"] != binding:
        raise TaskAttentionIntegrityError("task attention decision target binding is stale or invalid")
    if value["decision"] not in DECISIONS:
        raise TaskAttentionIntegrityError("task attention decision value is invalid")
    _validate_authority(value["authority"])
    _validate_text(value["evidence_ref"], label="evidence_ref")
    if value["outcome_receipt_sha256"] != outcome_receipt_sha256:
        raise TaskAttentionIntegrityError("task attention decision outcome receipt binding is invalid")
    if value["outcome_file_sha256"] != outcome_file_sha256:
        raise TaskAttentionIntegrityError("task attention decision outcome file binding is invalid")
    created_at = value["created_at_unix"]
    if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 0:
        raise TaskAttentionIntegrityError("task attention decision timestamp is invalid")
    material = {
        "kind": value["kind"],
        "schema_version": value["schema_version"],
        "task_binding": value["task_binding"],
        "decision": value["decision"],
        "authority": value["authority"],
        "evidence_ref": value["evidence_ref"],
        "outcome_receipt_sha256": value["outcome_receipt_sha256"],
        "outcome_file_sha256": value["outcome_file_sha256"],
    }
    material_sha256 = value["material_sha256"]
    if not isinstance(material_sha256, str) or material_sha256 != _sha256_json(material):
        raise TaskAttentionIntegrityError("task attention decision material binding is invalid")
    payload = {key: item for key, item in value.items() if key != "receipt_sha256"}
    receipt_sha256 = value["receipt_sha256"]
    if not isinstance(receipt_sha256, str) or receipt_sha256 != _sha256_json(payload):
        raise TaskAttentionIntegrityError("task attention decision self-hash is invalid")
    return value


def record_decision(parameters: dict[str, Any]) -> dict[str, Any]:
    required = {
        "task_id",
        "decision",
        "expected_attempt",
        "expected_unit",
        "expected_authoritative_unit",
        "expected_argv_sha256",
        "expected_execution_envelope_sha256",
        "outcome_receipt_sha256",
        "authority",
        "evidence_ref",
    }
    parameters = _validate_exact_keys(
        parameters,
        allowed=required,
        required=required,
        label="task attention decision parameters",
    )
    task_id = tasks._validate_task_id(parameters["task_id"])
    decision = parameters["decision"]
    if not isinstance(decision, str) or decision not in DECISIONS:
        raise TaskAttentionInputError("decision must be closed, deferred, or superseded")
    authority = _validate_authority(parameters["authority"])
    evidence_ref = _validate_text(parameters["evidence_ref"], label="evidence_ref")
    expected_outcome_sha256 = _validate_sha256(
        parameters["outcome_receipt_sha256"],
        label="outcome_receipt_sha256",
    )

    with _state_lock():
        record = tasks._row(task_id)
        binding = _task_binding(record)
        lifecycle_binding = _lifecycle_binding(record)
        _validate_expected_binding(parameters, binding)
        if record["state"] not in TERMINAL_ATTENTION_STATES:
            raise TaskAttentionConflictError(
                "task state is not eligible for a decision-backed attention closeout"
            )
        _outcome, outcome_receipt_sha256, outcome_file_sha256 = _read_valid_outcome(
            record,
            expected_receipt_sha256=expected_outcome_sha256,
        )
        material = {
            "kind": DECISION_KIND,
            "schema_version": SCHEMA_VERSION,
            "task_binding": binding,
            "decision": decision,
            "authority": authority,
            "evidence_ref": evidence_ref,
            "outcome_receipt_sha256": outcome_receipt_sha256,
            "outcome_file_sha256": outcome_file_sha256,
        }
        payload = {
            **material,
            "created_at_unix": int(time.time()),
            "material_sha256": _sha256_json(material),
        }
        payload["receipt_sha256"] = _sha256_json(payload)

        current = tasks._row(task_id)
        current_lifecycle_binding = _lifecycle_binding(current)
        if (
            _task_binding(current) != binding
            or current["state"] != record["state"]
            or current_lifecycle_binding != lifecycle_binding
        ):
            raise TaskAttentionConflictError("task binding changed before decision publication")
        root = _state_root()
        target = _decision_path(binding)
        created = private_io.publish_private_create_only_json(
            root,
            target,
            payload,
            max_bytes=MAX_RECORD_BYTES,
            label="task attention decision",
        )
        winner, file_sha256 = _read_private_json(
            target,
            label="task attention decision",
        )
        winner = _validate_decision_record(
            winner,
            binding=binding,
            outcome_receipt_sha256=outcome_receipt_sha256,
            outcome_file_sha256=outcome_file_sha256,
        )
        if winner["material_sha256"] != payload["material_sha256"]:
            raise TaskAttentionConflictError(
                "task attention decision already exists with different material"
            )
    _schedule_owner_decision_alert(binding, winner)
    return {
        "schema_version": SCHEMA_VERSION,
        "created": created,
        "replayed": not created,
        "task_binding": binding,
        "decision": winner["decision"],
        "authority": winner["authority"],
        "evidence_ref": winner["evidence_ref"],
        "outcome_receipt_sha256": outcome_receipt_sha256,
        "material_sha256": winner["material_sha256"],
        "receipt_sha256": winner["receipt_sha256"],
        "file_sha256": file_sha256,
        "does_not_establish": [
            "task_output_correctness",
            "task_record_mutation",
            "automatic_retry_safety",
            "future_attempt_closeout",
        ],
    }


def _classify_record(
    record: dict[str, Any],
    *,
    include_decisions: bool = True,
) -> dict[str, Any]:
    binding = _task_binding(record)
    base: dict[str, Any] = {
        "task_id": binding["task_id"],
        "attempt": binding["attempt"],
        "unit": binding["unit"],
        "authoritative_unit": binding["authoritative_unit"],
        "argv_sha256": binding["argv_sha256"],
        "execution_envelope_sha256": binding["execution_envelope_sha256"],
        "state": record["state"],
        "classification": "actionable",
        "decision": None,
        "authority": None,
        "evidence_ref": None,
        "outcome_receipt_sha256": None,
        "evidence_error": None,
    }
    if record["state"] in {"outcome_unknown", "interrupted"}:
        if not include_decisions:
            if record["state"] == "outcome_unknown":
                base["classification"] = "outcome_unknown"
            return base
        target = _decision_path(binding)
        try:
            _ensure_private_directory(_state_root(), create=False)
            target.lstat()
        except FileNotFoundError:
            if record["state"] == "outcome_unknown":
                base["classification"] = "outcome_unknown"
            return base
        except (OSError, TaskAttentionError) as exc:
            base["classification"] = "invalid_evidence"
            base["evidence_error"] = type(exc).__name__
            return base
        base["classification"] = "invalid_evidence"
        base["evidence_error"] = "decision_without_eligible_outcome"
        return base
    try:
        _outcome, outcome_receipt_sha256, outcome_file_sha256 = _read_valid_outcome(
            record,
            expected_receipt_sha256=None,
        )
        base["outcome_receipt_sha256"] = outcome_receipt_sha256
    except (FileNotFoundError, OSError, TaskAttentionError, TaskAttentionInputError) as exc:
        base["classification"] = "invalid_evidence"
        base["evidence_error"] = type(exc).__name__
        return base
    if not include_decisions:
        return base
    target = _decision_path(binding)
    try:
        _ensure_private_directory(_state_root(), create=False)
        decision, _file_sha256 = _read_private_json(
            target,
            label="task attention decision",
        )
    except FileNotFoundError:
        return base
    except (OSError, TaskAttentionError) as exc:
        base["classification"] = "invalid_evidence"
        base["evidence_error"] = type(exc).__name__
        return base
    try:
        decision = _validate_decision_record(
            decision,
            binding=binding,
            outcome_receipt_sha256=outcome_receipt_sha256,
            outcome_file_sha256=outcome_file_sha256,
        )
    except (TaskAttentionError, TaskAttentionInputError) as exc:
        base["classification"] = "invalid_evidence"
        base["evidence_error"] = type(exc).__name__
        return base
    base["classification"] = f"decision_{decision['decision']}"
    base["decision"] = decision["decision"]
    base["authority"] = decision["authority"]
    base["evidence_ref"] = decision["evidence_ref"]
    return base


def terminal_closeout_plan(record: dict[str, Any]) -> dict[str, Any]:
    """Project one task closeout without creating a second lifecycle truth.

    The task row and authoritative lifecycle receipt remain the terminal-state
    authority. Attention decisions remain create-only evidence. This projection
    only joins both authorities to answer whether a retained terminal task is
    ready for archival or still has exactly one concrete closeout obligation.
    """
    if not isinstance(record, dict):
        raise TaskAttentionInputError("task closeout record must be an object")
    binding = _task_binding(record)
    state = record.get("state")
    if not isinstance(state, str) or state not in tasks.TASK_STATES:
        raise TaskAttentionInputError("task closeout state is invalid")

    terminal = tasks._is_terminal_state(state)
    lifecycle_evidence_valid = False
    lifecycle_evidence_error: str | None = None
    outcome_receipt_sha256: str | None = None
    attention_classification = "not_required"
    attention_decision: str | None = None

    if state in TERMINAL_ATTENTION_STATES:
        classified = _classify_record(record)
        attention_classification = str(classified["classification"])
        attention_decision = classified.get("decision")
        outcome_receipt_sha256 = classified.get("outcome_receipt_sha256")
        if attention_classification == "invalid_evidence":
            lifecycle_evidence_error = str(
                classified.get("evidence_error") or "TaskAttentionIntegrityError"
            )
        else:
            lifecycle_evidence_valid = outcome_receipt_sha256 is not None
    elif terminal:
        try:
            _outcome, outcome_receipt_sha256, _outcome_file_sha256 = _read_valid_outcome(
                record,
                expected_receipt_sha256=None,
                allowed_states=frozenset(tasks.TASK_STATE_PROJECTIONS["terminal"]),
            )
            lifecycle_evidence_valid = True
        except (
            FileNotFoundError,
            OSError,
            TaskAttentionError,
            TaskAttentionInputError,
        ) as exc:
            lifecycle_evidence_error = type(exc).__name__

    operator_obligation: dict[str, Any] | None = None
    if state in tasks.TASK_STATE_PROJECTIONS["active"]:
        closeout_state = "active"
        recommended_next_action = "observe the active task before closeout"
    elif state in RECOVERY_ATTENTION_STATES:
        closeout_state = "recovery_required"
        operator_obligation = {
            "kind": "reconcile_task",
            "task_id": binding["task_id"],
            "reason": f"task_state:{state}",
        }
        recommended_next_action = "reconcile authoritative task state before any closeout decision"
    elif not terminal:
        closeout_state = "blocking"
        operator_obligation = {
            "kind": "inspect_task_state",
            "task_id": binding["task_id"],
            "reason": f"task_state:{state}",
        }
        recommended_next_action = "inspect task state before closeout"
    elif not lifecycle_evidence_valid:
        closeout_state = "evidence_repair_required"
        operator_obligation = {
            "kind": "repair_terminal_evidence",
            "task_id": binding["task_id"],
            "reason": lifecycle_evidence_error or "terminal_evidence_invalid",
        }
        recommended_next_action = "repair terminal lifecycle evidence before attention or archive closeout"
    elif state in TERMINAL_ATTENTION_STATES:
        if attention_classification in ARCHIVE_RESOLVED_CLASSIFICATIONS:
            closeout_state = "ready_to_archive"
            recommended_next_action = "archive after retention and lifecycle revalidation"
        elif attention_classification == "decision_deferred":
            closeout_state = "attention_deferred"
            operator_obligation = {
                "kind": "resolve_deferred_attention",
                "task_id": binding["task_id"],
                "reason": attention_classification,
            }
            recommended_next_action = "resolve the deferred attention decision before archival"
        else:
            closeout_state = "attention_required"
            operator_obligation = {
                "kind": "decide_task_attention",
                "task_id": binding["task_id"],
                "reason": attention_classification,
            }
            recommended_next_action = "record an evidence-bound attention decision before archival"
    else:
        closeout_state = "ready_to_archive"
        recommended_next_action = "archive after retention and lifecycle revalidation"

    return {
        "schema_version": 1,
        "task_binding": binding,
        "state": state,
        "terminal": terminal,
        "lifecycle_evidence_valid": lifecycle_evidence_valid,
        "lifecycle_evidence_error": lifecycle_evidence_error,
        "outcome_receipt_sha256": outcome_receipt_sha256,
        "attention_required": state in TERMINAL_ATTENTION_STATES,
        "attention_classification": attention_classification,
        "attention_decision": attention_decision,
        "closeout_state": closeout_state,
        "archive_ready": closeout_state == "ready_to_archive",
        "operator_obligation": operator_obligation,
        "recommended_next_action": recommended_next_action,
        "does_not_establish": [
            "task_output_correctness",
            "automatic_supersession",
            "archive_retention_satisfied",
            "physical_checkout_cleanup",
            "deletion_authority",
        ],
    }


def _task_archive_effect_root() -> Path:
    configured = os.environ.get("GRABOWSKI_TASK_ARCHIVE_EFFECT_ROOT")
    root = (
        Path(configured).expanduser()
        if configured
        else tasks.TASK_DB.parent / "task-archive-effects"
    )
    if not root.is_absolute():
        raise TaskAttentionIntegrityError("task archive effect root must be absolute")
    return root


def _validate_archive_execution_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    required = {
        "task_id",
        "expected_attempt",
        "expected_unit",
        "expected_authoritative_unit",
        "expected_argv_sha256",
        "expected_execution_envelope_sha256",
        "expected_lifecycle_receipt_sha256",
        "minimum_age_seconds",
        "execution_id",
    }
    value = _validate_exact_keys(
        parameters,
        allowed=required,
        required=required,
        label="task closeout archive parameters",
    )
    value["task_id"] = tasks._validate_task_id(value["task_id"])
    value["expected_lifecycle_receipt_sha256"] = _validate_sha256(
        value["expected_lifecycle_receipt_sha256"],
        label="expected_lifecycle_receipt_sha256",
    )
    minimum_age_seconds = value["minimum_age_seconds"]
    if (
        isinstance(minimum_age_seconds, bool)
        or not isinstance(minimum_age_seconds, int)
        or minimum_age_seconds < 0
    ):
        raise TaskAttentionInputError("minimum_age_seconds must be a non-negative integer")
    value["execution_id"] = _validate_text(
        value["execution_id"],
        label="execution_id",
        maximum=512,
    )
    return value


def _validate_archive_target(
    parameters: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    binding = _task_binding(record)
    _validate_expected_binding(parameters, binding)
    expected_receipt = parameters["expected_lifecycle_receipt_sha256"]
    if record.get("lifecycle_receipt_sha256") != expected_receipt:
        raise TaskAttentionConflictError(
            "current task lifecycle receipt does not match the expected archive target"
        )
    closeout = terminal_closeout_plan(record)
    if closeout.get("outcome_receipt_sha256") != expected_receipt:
        raise TaskAttentionConflictError(
            "current task closeout receipt does not match the expected archive target"
        )
    if closeout.get("archive_ready") is not True:
        raise TaskAttentionConflictError(
            "task closeout is not ready for archival: "
            + str(closeout.get("closeout_state") or "unknown")
        )
    return closeout


def _task_archive_source_binding(record: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    archive_record = tasks._task_archive_record(record)
    record_sha256 = _sha256_json(archive_record)
    source_schema_version = tasks.TASK_CURRENT_SCHEMA_VERSION
    source_store_sha256 = _sha256_json(
        {
            "schema_version": 1,
            "scope": "selected_task_record_snapshot",
            "task_store_schema_version": source_schema_version,
            "task_id": archive_record["task_id"],
            "task_record_sha256": record_sha256,
        }
    )
    return archive_record, record_sha256, source_store_sha256


def _task_retention_boundary(
    record: dict[str, Any],
    *,
    minimum_age_seconds: int,
) -> int:
    terminalized_at = record.get("terminalized_at_unix")
    updated_at = record.get("updated_at_unix")
    age_anchor = terminalized_at if isinstance(terminalized_at, int) else updated_at
    if isinstance(age_anchor, bool) or not isinstance(age_anchor, int):
        raise TaskAttentionIntegrityError("task archive retention anchor is unavailable")
    return age_anchor + minimum_age_seconds


def _assert_task_archive_retention(
    record: dict[str, Any],
    *,
    minimum_age_seconds: int,
    now_unix: int,
) -> int:
    retention_boundary_unix = _task_retention_boundary(
        record, minimum_age_seconds=minimum_age_seconds
    )
    if now_unix < retention_boundary_unix:
        raise TaskAttentionConflictError(
            "task archive minimum retention is not yet satisfied"
        )
    return retention_boundary_unix


def _assert_no_live_task_resource_leases(
    record: dict[str, Any],
    *,
    now_unix: int,
) -> dict[str, Any]:
    resource_keys = sorted(tasks._record_resource_keys(record))
    active: list[dict[str, Any]] = []
    for resource_key in resource_keys:
        lease = tasks.resources.inspect_resource(resource_key)
        if lease is None:
            continue
        expires_at_unix = lease.get("expires_at_unix")
        if (
            isinstance(expires_at_unix, int)
            and not isinstance(expires_at_unix, bool)
            and expires_at_unix > now_unix
        ):
            active.append(
                {
                    "resource_key": resource_key,
                    "owner_id": lease.get("owner_id"),
                    "expires_at_unix": expires_at_unix,
                    "metadata_sha256": lease.get("metadata_sha256"),
                }
            )
    if active:
        raise TaskAttentionConflictError(
            "task archive is blocked by active task resource leases"
        )
    return {
        "schema_version": 1,
        "kind": "grabowski_task_archive_lease_observation",
        "task_id": record["task_id"],
        "resource_keys": resource_keys,
        "active_lease": False,
    }


def _assert_no_live_task_process(record: dict[str, Any]) -> dict[str, Any]:
    try:
        observation = tasks._observe(record)
    except Exception as exc:
        raise TaskAttentionIntegrityError(
            "task archive process liveness could not be observed"
        ) from exc
    properties = observation.get("properties")
    probe = observation.get("probe")
    if not isinstance(properties, dict) or not isinstance(probe, dict):
        raise TaskAttentionIntegrityError("task archive process observation is incomplete")
    if probe.get("outcome_unknown"):
        raise TaskAttentionIntegrityError("task archive process observation outcome is unknown")
    active_state = properties.get("ActiveState")
    if active_state in {"active", "activating", "reloading", "deactivating"}:
        raise TaskAttentionConflictError(
            "task archive is blocked because the authoritative unit is still live"
        )
    if active_state not in {"inactive", "failed"}:
        raise TaskAttentionIntegrityError(
            "task archive authoritative unit liveness is ambiguous"
        )
    return {
        "schema_version": 1,
        "kind": "grabowski_task_archive_process_observation",
        "task_id": record["task_id"],
        "authoritative_unit": tasks._authoritative_unit(record),
        "active_process": False,
    }


def _task_archive_classification(
    record: dict[str, Any],
    *,
    expected_lifecycle_receipt_sha256: str,
    archived: bool,
    archive_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    import grabowski_lifecycle_evidence as lifecycle_evidence

    archive_record, record_sha256, _source_store_sha256 = _task_archive_source_binding(record)
    now_unix = int(time.time())
    lease_source = _assert_no_live_task_resource_leases(record, now_unix=now_unix)
    process_source = _assert_no_live_task_process(record)
    _outcome, outcome_receipt_sha256, outcome_file_sha256 = _read_valid_outcome(
        record,
        expected_receipt_sha256=expected_lifecycle_receipt_sha256,
        allowed_states=frozenset(tasks.TASK_STATE_PROJECTIONS["terminal"]),
    )
    sources: dict[str, dict[str, Any]] = {
        "task": {
            "schema_version": 1,
            "kind": "grabowski_task_archive_task_observation",
            "task_id": record["task_id"],
            "state": record["state"],
            "task_record_sha256": record_sha256,
        },
        "lease": lease_source,
        "process": process_source,
        "receipt": {
            "schema_version": 1,
            "kind": "grabowski_task_archive_receipt_observation",
            "task_id": record["task_id"],
            "lifecycle_receipt_sha256": expected_lifecycle_receipt_sha256,
            "outcome_receipt_sha256": outcome_receipt_sha256,
            "outcome_file_sha256": outcome_file_sha256,
            "archive_evidence": archive_evidence,
        },
    }
    for source in ("workspace", "checkout", "tmux"):
        sources[source] = {
            "schema_version": 1,
            "kind": "grabowski_task_archive_not_applicable_observation",
            "source": source,
            "task_id": record["task_id"],
            "reason": "task_archive_does_not_mutate_related_runtime_object",
        }
    required_sources = lifecycle_evidence.REQUIRED_SOURCES
    observed_sources = frozenset({"task", "lease", "process", "receipt"})
    source_applicability = {
        "task": "observed",
        "workspace": "not_applicable",
        "lease": "explicit_absence",
        "checkout": "not_applicable",
        "process": "explicit_absence",
        "tmux": "not_applicable",
        "receipt": "observed",
    }
    source_sha256s = {
        source: _sha256_json(sources[source])
        for source in sorted(required_sources)
    }
    classified = lifecycle_evidence.classify_observation_bundle(
        lifecycle_evidence.LifecycleObservationBundle(
            identity=str(record["task_id"]),
            kind="task",
            observed_sources=observed_sources,
            source_sha256s=source_sha256s,
            source_applicability=source_applicability,
            source_applicability_profile=(
                lifecycle_evidence.SOURCE_APPLICABILITY_PROFILE_TASK_ARCHIVE_V1
            ),
            state=str(record["state"]),
            archived=archived,
            dirty=False,
            active_task=False,
            active_process=False,
            active_lease=False,
            foreign_retention=False,
            retention_expired=False,
            retention_recovery_archived=False,
            shared_reference=False,
            open_task_role=False,
            tmux_session_present=False,
            tmux_role_bound=False,
            receipt_integrity_valid=True,
        )
    )
    if archived:
        expected_classification = "archived"
    else:
        expected_classification = "terminal_archivable"
    if classified.get("classification") != expected_classification:
        raise TaskAttentionConflictError(
            "task archive lifecycle classification is not eligible: "
            + str(classified.get("classification"))
        )
    return classified


def _task_archive_lease_observations(leases: list[dict[str, Any]]) -> list[Any]:
    import grabowski_lifecycle_effect_plan as effect_plan

    observations: list[Any] = []
    for lease in leases:
        observations.append(
            effect_plan.LeaseObservation(
                resource_key=str(lease["resource_key"]),
                owner_id=str(lease["owner_id"]),
                expires_at_unix=int(lease["expires_at_unix"]),
                metadata_sha256=str(lease["metadata_sha256"]),
            )
        )
    return observations


def _existing_task_projection_binding(
    task_id: str,
    *,
    expected_record_sha256: str,
) -> dict[str, Any] | None:
    projection = tasks._task_current_projection()
    bindings = projection.get("archived_task_bindings")
    if not isinstance(bindings, dict):
        raise TaskAttentionIntegrityError("task archive current projection is invalid")
    binding = bindings.get(task_id)
    if binding is None:
        return None
    if (
        not isinstance(binding, dict)
        or binding.get("record_sha256") != expected_record_sha256
    ):
        raise TaskAttentionIntegrityError(
            "task archive current projection conflicts with the authoritative task record"
        )
    return {
        "task_id": task_id,
        "record_sha256": expected_record_sha256,
        "segment_id": binding.get("segment_id"),
        "switch_sha256": binding.get("switch_sha256"),
        "projection_sha256": projection.get("projection_sha256"),
    }


def _release_owned_archive_resources(
    owner: str,
    resource_keys: list[str],
) -> dict[str, Any]:
    owned: list[str] = []
    foreign_preserved: list[dict[str, Any]] = []
    for resource_key in resource_keys:
        lease = tasks.resources.inspect_resource(resource_key)
        if lease is None:
            continue
        if lease.get("owner_id") == owner:
            owned.append(resource_key)
        else:
            foreign_preserved.append(
                {
                    "resource_key": resource_key,
                    "owner_id": lease.get("owner_id"),
                }
            )
    if not owned:
        return {
            "status": "not_required",
            "released": [],
            "foreign_preserved": foreign_preserved,
        }
    try:
        released = tasks.resources.release_resources(owner, owned)
    except Exception as exc:
        return {
            "status": "release_failed",
            "released": [],
            "foreign_preserved": foreign_preserved,
            "error_type": type(exc).__name__,
        }
    return {
        "status": "released",
        "released": [item["resource_key"] for item in released["released"]],
        "foreign_preserved": foreign_preserved,
    }


TASK_OUTPUT_CLEANUP_INTENT_KIND = "grabowski_task_output_cleanup_intent"
TASK_OUTPUT_CLEANUP_COMPLETION_KIND = "grabowski_task_output_cleanup_completion"
TASK_OUTPUT_CLEANUP_PROBE_TOKEN = "0" * 64


def _task_output_cleanup_root() -> Path:
    root = tasks.TASK_DB.with_suffix(".output-cleanup")
    if not root.is_absolute():
        raise TaskAttentionIntegrityError("task output cleanup root must be absolute")
    _ensure_private_directory(root, create=True)
    return root


def _task_output_cleanup_paths(binding: dict[str, Any]) -> tuple[Path, Path]:
    root = _task_output_cleanup_root()
    stem = f"{binding['task_id']}.a{binding['attempt']}"
    return root / f"{stem}.intent.json", root / f"{stem}.completion.json"


def _task_output_cleanup_archive_binding(
    manifest: dict[str, Any],
    *,
    record_sha256: str,
) -> dict[str, Any]:
    required = (
        "segment_id",
        "segment_identity_sha256",
        "manifest_sha256",
        "segment_sha256",
        "plan_sha256",
        "record_sha256s",
    )
    if not isinstance(manifest, dict) or any(key not in manifest for key in required):
        raise TaskAttentionIntegrityError("task output cleanup archive manifest is incomplete")
    if record_sha256 not in manifest["record_sha256s"]:
        raise TaskAttentionIntegrityError("task output cleanup archive does not bind task record")
    return {
        "segment_id": manifest["segment_id"],
        "segment_identity_sha256": manifest["segment_identity_sha256"],
        "manifest_sha256": manifest["manifest_sha256"],
        "segment_sha256": manifest["segment_sha256"],
        "plan_sha256": manifest["plan_sha256"],
        "record_sha256": record_sha256,
    }


def _task_output_cleanup_projection_binding(
    projection: dict[str, Any],
) -> dict[str, Any]:
    required = ("task_id", "record_sha256", "segment_id", "switch_sha256", "projection_sha256")
    if not isinstance(projection, dict) or any(key not in projection for key in required):
        raise TaskAttentionIntegrityError("task output cleanup projection is incomplete")
    return {key: projection[key] for key in required}


def _task_output_cleanup_read_receipt(
    path: Path,
    *,
    kind: str,
) -> tuple[dict[str, Any], str]:
    value, file_sha256 = _read_private_json(path, label="task output cleanup receipt")
    if value.get("schema_version") != 1 or value.get("kind") != kind:
        raise TaskAttentionIntegrityError("task output cleanup receipt kind is invalid")
    receipt_sha256 = value.get("receipt_sha256")
    if not isinstance(receipt_sha256, str) or SHA256_RE.fullmatch(receipt_sha256) is None:
        raise TaskAttentionIntegrityError("task output cleanup receipt digest is invalid")
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if _sha256_json(material) != receipt_sha256:
        raise TaskAttentionIntegrityError("task output cleanup receipt self-hash is invalid")
    return value, file_sha256


def _task_output_cleanup_publish(
    path: Path,
    payload: dict[str, Any],
) -> tuple[dict[str, Any], str, bool]:
    root = _task_output_cleanup_root()
    body = dict(payload)
    body["receipt_sha256"] = _sha256_json(body)
    created = private_io.publish_private_create_only_json(
        root,
        path,
        body,
        max_bytes=MAX_RECORD_BYTES,
        label="task output cleanup receipt",
    )
    winner, file_sha256 = _task_output_cleanup_read_receipt(
        path, kind=str(body["kind"])
    )
    return winner, file_sha256, created


def _task_output_cleanup_validate_intent(
    intent: dict[str, Any],
    *,
    expected_prefix: dict[str, Any],
) -> dict[str, Any]:
    material = intent.get("material")
    material_sha256 = intent.get("material_sha256")
    if not isinstance(material, dict) or not isinstance(material_sha256, str):
        raise TaskAttentionIntegrityError("task output cleanup intent material is invalid")
    if _sha256_json(material) != material_sha256:
        raise TaskAttentionIntegrityError("task output cleanup intent material hash is invalid")
    for key, value in expected_prefix.items():
        if material.get(key) != value:
            raise TaskAttentionConflictError(
                f"task output cleanup intent {key} binding changed"
            )
    inventory = material.get("inventory")
    if not isinstance(inventory, dict):
        raise TaskAttentionIntegrityError("task output cleanup intent inventory is invalid")
    return inventory


def _task_output_cleanup_validate_completion(
    completion: dict[str, Any],
    *,
    intent: dict[str, Any],
) -> None:
    material = intent.get("material")
    if not isinstance(material, dict):
        raise TaskAttentionIntegrityError(
            "task output cleanup completion intent material is invalid"
        )
    if completion.get("task_binding") != material.get("task_binding"):
        raise TaskAttentionIntegrityError(
            "task output cleanup completion task binding is invalid"
        )
    if completion.get("intent_receipt_sha256") != intent.get("receipt_sha256"):
        raise TaskAttentionIntegrityError("task output cleanup completion intent binding is invalid")
    if completion.get("material_sha256") != intent.get("material_sha256"):
        raise TaskAttentionIntegrityError("task output cleanup completion material binding is invalid")
    delete_result_sha256 = completion.get("delete_result_sha256")
    if (
        not isinstance(delete_result_sha256, str)
        or SHA256_RE.fullmatch(delete_result_sha256) is None
    ):
        raise TaskAttentionIntegrityError(
            "task output cleanup completion result digest is invalid"
        )
    if completion.get("mutation_state") not in {
        "performed",
        "reconciled_absent",
    }:
        raise TaskAttentionIntegrityError(
            "task output cleanup completion mutation state is invalid"
        )
    if completion.get("post_state") != "absent":
        raise TaskAttentionIntegrityError("task output cleanup completion post-state is invalid")


def _task_output_cleanup_after_archive_unlocked(
    record: dict[str, Any],
    *,
    archive_binding: dict[str, Any],
    projection: dict[str, Any],
    retention_boundary_unix: int,
) -> dict[str, Any]:
    binding = _task_binding(record)
    lifecycle_receipt = record.get("lifecycle_receipt_sha256")
    if not isinstance(lifecycle_receipt, str) or SHA256_RE.fullmatch(lifecycle_receipt) is None:
        raise TaskAttentionIntegrityError("task output cleanup lifecycle receipt is unavailable")
    projection_binding = _task_output_cleanup_projection_binding(projection)
    expected_prefix = {
        "schema_version": 1,
        "task_binding": binding,
        "lifecycle_receipt_sha256": lifecycle_receipt,
        "retention_boundary_unix": retention_boundary_unix,
        "archive": archive_binding,
        "projection": projection_binding,
    }
    intent_path, completion_path = _task_output_cleanup_paths(binding)
    intent: dict[str, Any] | None = None
    intent_file_sha256: str | None = None
    if completion_path.exists() and not intent_path.exists():
        raise TaskAttentionIntegrityError(
            "task output cleanup completion exists without its intent"
        )
    if intent_path.exists():
        intent, intent_file_sha256 = _task_output_cleanup_read_receipt(
            intent_path, kind=TASK_OUTPUT_CLEANUP_INTENT_KIND
        )
        inventory = _task_output_cleanup_validate_intent(
            intent, expected_prefix=expected_prefix
        )
    else:
        inspection = tasks._task_output_cleanup_run(
            record,
            mode="inspect",
            token=TASK_OUTPUT_CLEANUP_PROBE_TOKEN,
        )
        if inspection.get("status") == "missing":
            return {
                "status": "not_present",
                "reason": "no_private_task_output_directory",
                "task_binding": binding,
                "archive": archive_binding,
                "projection": projection_binding,
                "does_not_establish": ["historical_output_was_never_created"],
            }
        if inspection.get("status") == "staging_present":
            raise TaskAttentionIntegrityError(
                "task output cleanup staging exists without a durable intent"
            )
        if inspection.get("status") != "present":
            raise TaskAttentionIntegrityError("task output cleanup inspection is incomplete")
        inventory = inspection["inventory"]
        material = {**expected_prefix, "inventory": inventory}
        material_sha256 = _sha256_json(material)
        intent_payload = {
            "schema_version": 1,
            "kind": TASK_OUTPUT_CLEANUP_INTENT_KIND,
            "material": material,
            "material_sha256": material_sha256,
            "created_at_unix": int(time.time()),
        }
        intent, intent_file_sha256, _created = _task_output_cleanup_publish(
            intent_path, intent_payload
        )
        inventory = _task_output_cleanup_validate_intent(
            intent, expected_prefix=expected_prefix
        )
        if intent.get("material_sha256") != material_sha256:
            raise TaskAttentionConflictError(
                "task output cleanup intent already exists with different inventory"
            )
    if completion_path.exists():
        completion, completion_file_sha256 = _task_output_cleanup_read_receipt(
            completion_path, kind=TASK_OUTPUT_CLEANUP_COMPLETION_KIND
        )
        _task_output_cleanup_validate_completion(completion, intent=intent)
        return {
            "status": "deleted",
            "idempotent_replay": True,
            "task_binding": binding,
            "intent_receipt_sha256": intent["receipt_sha256"],
            "intent_file_sha256": intent_file_sha256,
            "completion_receipt_sha256": completion["receipt_sha256"],
            "completion_file_sha256": completion_file_sha256,
            "inventory": inventory,
            "mutation_state": completion["mutation_state"],
            "post_state": "absent",
        }
    current = tasks._row_raw(str(binding["task_id"]))
    if _task_binding(current) != binding or current.get("lifecycle_receipt_sha256") != lifecycle_receipt:
        raise TaskAttentionConflictError("task binding changed before output cleanup")
    current_projection = _existing_task_projection_binding(
        str(binding["task_id"]), expected_record_sha256=str(projection_binding["record_sha256"])
    )
    if _task_output_cleanup_projection_binding(current_projection or {}) != projection_binding:
        raise TaskAttentionConflictError("task archive projection changed before output cleanup")
    deletion = tasks._task_output_cleanup_run(
        current,
        mode="delete",
        token=str(intent["material_sha256"]),
        inventory=inventory,
    )
    if deletion.get("status") == "missing":
        delete_result = {
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_absent_readback",
            "task_id": binding["task_id"],
            "attempt": binding["attempt"],
            "directory": str(tasks._task_output_paths(current)["directory"]),
            "token": intent["material_sha256"],
            "observer": deletion.get("observer"),
            "mutation_state": "unknown",
            "post_state": "absent",
            "does_not_establish": [
                "which_same_uid_process_removed_the_output",
                "cleanup_process_completed_before_interruption",
            ],
        }
        mutation_state = "reconciled_absent"
    elif deletion.get("status") == "deleted":
        delete_result = deletion["delete_result"]
        mutation_state = "performed"
    else:
        raise TaskAttentionIntegrityError(
            "task output cleanup did not reach absent post-state"
        )
    completion_payload = {
        "schema_version": 1,
        "kind": TASK_OUTPUT_CLEANUP_COMPLETION_KIND,
        "task_binding": binding,
        "intent_receipt_sha256": intent["receipt_sha256"],
        "intent_file_sha256": intent_file_sha256,
        "material_sha256": intent["material_sha256"],
        "delete_result_sha256": _sha256_json(delete_result),
        "mutation_state": mutation_state,
        "post_state": "absent",
        "completed_at_unix": int(time.time()),
    }
    completion, completion_file_sha256, _created = _task_output_cleanup_publish(
        completion_path, completion_payload
    )
    _task_output_cleanup_validate_completion(completion, intent=intent)
    if completion.get("delete_result_sha256") != _sha256_json(delete_result):
        raise TaskAttentionConflictError(
            "task output cleanup completion already exists with different result"
        )
    return {
        "status": "deleted",
        "idempotent_replay": False,
        "task_binding": binding,
        "intent_receipt_sha256": intent["receipt_sha256"],
        "intent_file_sha256": intent_file_sha256,
        "completion_receipt_sha256": completion["receipt_sha256"],
        "completion_file_sha256": completion_file_sha256,
        "inventory": inventory,
        "delete_result_sha256": completion["delete_result_sha256"],
        "mutation_state": completion["mutation_state"],
        "post_state": "absent",
    }


def _task_output_cleanup_after_archive(
    record: dict[str, Any],
    *,
    archive_binding: dict[str, Any],
    projection: dict[str, Any],
    retention_boundary_unix: int,
) -> dict[str, Any]:
    binding = _task_binding(record)
    now_unix = int(time.time())
    if now_unix < retention_boundary_unix:
        return {
            "status": "deferred",
            "task_binding": binding,
            "eligible_at_unix": retention_boundary_unix,
            "remaining_seconds": retention_boundary_unix - now_unix,
            "minimum_retention_seconds": TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
            "does_not_establish": [
                "task_output_deleted",
                "retention_or_archive_completion",
            ],
        }
    resource_key = (
        "component:grabowski-task-output-cleanup:"
        + str(binding["task_id"])
        + ":a"
        + str(binding["attempt"])
    )
    owner = tasks.resources._owner(
        "operator:task-output-cleanup:"
        + str(binding["task_id"])
        + ":a"
        + str(binding["attempt"])
    )
    try:
        tasks.resources.acquire_resources(
            owner,
            [resource_key],
            purpose=(
                "task output cleanup "
                + str(binding["task_id"])
                + " attempt "
                + str(binding["attempt"])
            ),
            ttl_seconds=ARCHIVE_EFFECT_LEASE_TTL_SECONDS,
            metadata={
                "schema_version": 1,
                "operation": "task-output-cleanup",
                "task_id": binding["task_id"],
                "attempt": binding["attempt"],
                "lifecycle_receipt_sha256": record.get(
                    "lifecycle_receipt_sha256"
                ),
            },
        )
    except tasks.resources.ResourceConflict as exc:
        raise TaskAttentionConflictError(str(exc)) from exc
    try:
        result = _task_output_cleanup_after_archive_unlocked(
            record,
            archive_binding=archive_binding,
            projection=projection,
            retention_boundary_unix=retention_boundary_unix,
        )
    except BaseException:
        _release_owned_archive_resources(owner, [resource_key])
        raise
    release = _release_owned_archive_resources(owner, [resource_key])
    if release.get("status") not in {"released", "not_required"}:
        raise TaskAttentionError("task output cleanup resource release failed")
    return {**result, "cleanup_resource_release": release}


def _load_task_output_cleanup_cursor(
    *,
    projection_sha256: str,
) -> str | None:
    with tasks._database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (TASK_OUTPUT_CLEANUP_CURSOR_METADATA_KEY,),
        ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(str(row[0]))
    except json.JSONDecodeError as exc:
        raise TaskAttentionIntegrityError(
            "task output cleanup cursor is malformed"
        ) from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "projection_sha256",
        "cursor",
    }:
        raise TaskAttentionIntegrityError(
            "task output cleanup cursor shape is invalid"
        )
    if value.get("schema_version") != 1:
        raise TaskAttentionIntegrityError(
            "task output cleanup cursor schema is invalid"
        )
    if value.get("projection_sha256") != projection_sha256:
        return None
    cursor = value.get("cursor")
    if cursor is not None and (
        not isinstance(cursor, str) or tasks.TASK_ID.fullmatch(cursor) is None
    ):
        raise TaskAttentionIntegrityError(
            "task output cleanup cursor identity is invalid"
        )
    return cursor


def _save_task_output_cleanup_cursor(
    *,
    projection_sha256: str,
    cursor: str | None,
) -> None:
    if not isinstance(projection_sha256, str) or SHA256_RE.fullmatch(
        projection_sha256
    ) is None:
        raise TaskAttentionIntegrityError(
            "task output cleanup projection digest is invalid"
        )
    if cursor is not None and tasks.TASK_ID.fullmatch(cursor) is None:
        raise TaskAttentionIntegrityError(
            "task output cleanup cursor identity is invalid"
        )
    payload = json.dumps(
        {
            "schema_version": 1,
            "projection_sha256": projection_sha256,
            "cursor": cursor,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    with tasks._database_connection() as connection:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (TASK_OUTPUT_CLEANUP_CURSOR_METADATA_KEY, payload),
        )


def reconcile_archived_task_outputs(
    *,
    limit: int = DEFAULT_TASK_OUTPUT_CLEANUP_BATCH_SIZE,
) -> dict[str, Any]:
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= MAX_TASK_OUTPUT_CLEANUP_BATCH_SIZE
    ):
        raise TaskAttentionInputError(
            "task output cleanup limit is invalid"
        )
    projection = tasks._task_current_projection()
    projection_sha256 = projection.get("projection_sha256")
    bindings = projection.get("archived_task_bindings")
    if (
        not isinstance(projection_sha256, str)
        or SHA256_RE.fullmatch(projection_sha256) is None
        or not isinstance(bindings, dict)
    ):
        raise TaskAttentionIntegrityError(
            "task output cleanup current projection is invalid"
        )
    task_ids = sorted(bindings)
    for task_id in task_ids:
        if not isinstance(task_id, str) or tasks.TASK_ID.fullmatch(task_id) is None:
            raise TaskAttentionIntegrityError(
                "task output cleanup projection task identity is invalid"
            )
    cursor_before = _load_task_output_cleanup_cursor(
        projection_sha256=projection_sha256
    )
    start = 0
    if cursor_before is not None:
        while start < len(task_ids) and task_ids[start] <= cursor_before:
            start += 1
    selected = task_ids[start : start + limit]
    cycle_wrapped = False
    if not selected and task_ids:
        selected = task_ids[:limit]
        start = 0
        cycle_wrapped = True
    cycle_completed = not task_ids or start + len(selected) >= len(task_ids)
    cursor_after = None if cycle_completed else selected[-1]
    results: list[dict[str, Any]] = []
    counts = {
        "deleted": 0,
        "deferred": 0,
        "not_present": 0,
        "errors": 0,
    }
    archive_root = tasks._task_archive_root()
    lifecycle = importlib.import_module("grabowski_lifecycle_archive")
    now_unix = int(time.time())
    for task_id in selected:
        try:
            binding = bindings.get(task_id)
            if not isinstance(binding, dict):
                raise TaskAttentionIntegrityError(
                    "task output cleanup projection binding is invalid"
                )
            record = tasks._row_raw(task_id)
            _archive_record, record_sha256, _source = (
                _task_archive_source_binding(record)
            )
            if binding.get("record_sha256") != record_sha256:
                raise TaskAttentionIntegrityError(
                    "task output cleanup task record drifted from projection"
                )
            projection_binding = _existing_task_projection_binding(
                task_id, expected_record_sha256=record_sha256
            )
            if projection_binding is None:
                raise TaskAttentionIntegrityError(
                    "task output cleanup projection binding disappeared"
                )
            segment_id = projection_binding.get("segment_id")
            if not isinstance(segment_id, str) or not segment_id:
                raise TaskAttentionIntegrityError(
                    "task output cleanup segment identity is invalid"
                )
            verified_segment = lifecycle.verify_task_archive_segment(
                archive_root / segment_id
            )
            archive_binding = _task_output_cleanup_archive_binding(
                verified_segment["manifest"],
                record_sha256=record_sha256,
            )
            retention_boundary_unix = _task_retention_boundary(
                record,
                minimum_age_seconds=TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
            )
            if now_unix >= retention_boundary_unix:
                _assert_no_live_task_resource_leases(
                    record, now_unix=now_unix
                )
                _assert_no_live_task_process(record)
            cleanup = _task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection_binding,
                retention_boundary_unix=retention_boundary_unix,
            )
            status = str(cleanup.get("status"))
            if status not in {"deleted", "deferred", "not_present"}:
                raise TaskAttentionIntegrityError(
                    "task output cleanup returned an unknown status"
                )
            counts[status] += 1
            results.append(
                {
                    "task_id": task_id,
                    "attempt": record.get("attempt"),
                    "status": status,
                    "eligible_at_unix": cleanup.get("eligible_at_unix"),
                    "intent_receipt_sha256": cleanup.get(
                        "intent_receipt_sha256"
                    ),
                    "completion_receipt_sha256": cleanup.get(
                        "completion_receipt_sha256"
                    ),
                }
            )
        except Exception as exc:
            counts["errors"] += 1
            results.append(
                {
                    "task_id": task_id,
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error": tasks.operator._redact(str(exc))[:512],
                }
            )
    _save_task_output_cleanup_cursor(
        projection_sha256=projection_sha256,
        cursor=cursor_after,
    )
    return {
        "schema_version": 1,
        "kind": "grabowski_task_output_cleanup_reconcile",
        "status": "ok" if counts["errors"] == 0 else "degraded",
        "projection_sha256": projection_sha256,
        "archived_task_count": len(task_ids),
        "limit": limit,
        "cursor_before": cursor_before,
        "cursor_after": cursor_after,
        "cycle_wrapped": cycle_wrapped,
        "cycle_completed": cycle_completed,
        "scanned": len(selected),
        "counts": counts,
        "results": results,
        "checked_at_unix": now_unix,
        "does_not_establish": [
            "physical_task_row_deletion",
            "same_uid_output_authenticity",
            "cleanup_of_unarchived_tasks",
        ],
    }


def execute_closeout_archive(parameters: dict[str, Any]) -> dict[str, Any]:
    import grabowski_lifecycle_archive as lifecycle
    import grabowski_lifecycle_effect_plan as effect_plan
    import grabowski_lifecycle_projection as lifecycle_projection

    value = _validate_archive_execution_parameters(parameters)
    task_id = str(value["task_id"])
    record = tasks._row_raw(task_id)
    closeout = _validate_archive_target(value, record)
    archive_record, record_sha256, source_store_sha256 = _task_archive_source_binding(record)
    archive_root = tasks._task_archive_root()
    effect_root = _task_archive_effect_root()
    projection_root = tasks._task_projection_root()
    archive_resource = lifecycle._task_archive_effect_resource_key(archive_root)
    effect_resource = lifecycle._task_archive_effect_resource_key(effect_root)
    projection_resource = lifecycle_projection._projection_resource_key(projection_root)
    resources_to_hold = sorted(
        {archive_resource, effect_resource, projection_resource}
    )
    caller_execution_id = str(value["execution_id"])
    caller_execution_id_sha256 = hashlib.sha256(
        caller_execution_id.encode("utf-8")
    ).hexdigest()
    execution_id = (
        f"task-closeout-archive:{task_id}:"
        f"{caller_execution_id_sha256[:32]}"
    )
    execution_id_sha256 = hashlib.sha256(
        execution_id.encode("utf-8")
    ).hexdigest()
    owner = tasks.resources._owner(
        "operator:task-closeout-archive:" + execution_id_sha256[:24]
    )
    existing_projection = _existing_task_projection_binding(
        task_id,
        expected_record_sha256=record_sha256,
    )
    if existing_projection is not None:
        now_unix = int(time.time())
        retention_boundary_unix = _assert_task_archive_retention(
            record,
            minimum_age_seconds=int(value["minimum_age_seconds"]),
            now_unix=now_unix,
        )
        task_output_retention_boundary_unix = _task_retention_boundary(
            record,
            minimum_age_seconds=max(
                int(value["minimum_age_seconds"]),
                TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
            ),
        )
        if now_unix >= task_output_retention_boundary_unix:
            _assert_no_live_task_resource_leases(record, now_unix=now_unix)
            _assert_no_live_task_process(record)
        segment_id = existing_projection.get("segment_id")
        if not isinstance(segment_id, str) or not segment_id:
            raise TaskAttentionIntegrityError(
                "task archive projection segment identity is unavailable"
            )
        verified_segment = lifecycle.verify_task_archive_segment(
            archive_root / segment_id
        )
        archive_binding = _task_output_cleanup_archive_binding(
            verified_segment["manifest"],
            record_sha256=record_sha256,
        )
        task_output_cleanup = _task_output_cleanup_after_archive(
            record,
            archive_binding=archive_binding,
            projection=existing_projection,
            retention_boundary_unix=task_output_retention_boundary_unix,
        )
        resource_release = _release_owned_archive_resources(
            owner,
            resources_to_hold,
        )
        return {
            "schema_version": 1,
            "task_binding": _task_binding(record),
            "closeout": closeout,
            "archive_record_sha256": record_sha256,
            "execution_id_sha256": execution_id_sha256,
            "caller_execution_id_sha256": caller_execution_id_sha256,
            "retention_boundary_unix": retention_boundary_unix,
            "task_output_retention_boundary_unix": (
                task_output_retention_boundary_unix
            ),
            "already_archived": True,
            "idempotent_replay": True,
            "projection": existing_projection,
            "task_output_cleanup": task_output_cleanup,
            "resource_release": resource_release,
            "does_not_establish": [
                "physical_task_row_deletion",
                "workspace_cleanup_authority",
                "checkout_cleanup_authority",
                "same_uid_output_authenticity",
                "blind_retry_after_recovery_required",
            ],
        }

    now_unix = int(time.time())
    retention_boundary_unix = _assert_task_archive_retention(
        record,
        minimum_age_seconds=int(value["minimum_age_seconds"]),
        now_unix=now_unix,
    )
    task_output_retention_boundary_unix = _task_retention_boundary(
        record,
        minimum_age_seconds=max(
            int(value["minimum_age_seconds"]),
            TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
        ),
    )
    _assert_no_live_task_resource_leases(record, now_unix=now_unix)
    _assert_no_live_task_process(record)
    lease_result: dict[str, Any] | None = None
    resource_release: dict[str, Any] = {"status": "not_acquired", "released": []}
    output: dict[str, Any] | None = None
    try:
        try:
            lease_result = tasks.resources.acquire_resources(
                owner,
                resources_to_hold,
                purpose=f"task closeout archive {task_id}",
                ttl_seconds=ARCHIVE_EFFECT_LEASE_TTL_SECONDS,
                metadata={
                    "schema_version": 1,
                    "operation": "task-closeout-archive",
                    "task_id": task_id,
                    "execution_id_sha256": execution_id_sha256,
                    "caller_execution_id_sha256": caller_execution_id_sha256,
                },
            )
        except tasks.resources.ResourceConflict as exc:
            raise TaskAttentionConflictError(str(exc)) from exc
        lease_observations = _task_archive_lease_observations(
            list(lease_result["leases"])
        )

        current = tasks._row_raw(task_id)
        current_closeout = _validate_archive_target(value, current)
        current_archive_record, current_record_sha256, current_source_store_sha256 = (
            _task_archive_source_binding(current)
        )
        if current_record_sha256 != record_sha256:
            raise TaskAttentionConflictError(
                "task archive record changed before archive planning"
            )
        if current_source_store_sha256 != source_store_sha256:
            raise TaskAttentionConflictError(
                "task archive source binding changed before archive planning"
            )
        current_now = int(time.time())
        _assert_task_archive_retention(
            current,
            minimum_age_seconds=int(value["minimum_age_seconds"]),
            now_unix=current_now,
        )
        classification = _task_archive_classification(
            current,
            expected_lifecycle_receipt_sha256=str(
                value["expected_lifecycle_receipt_sha256"]
            ),
            archived=False,
        )
        # The dry-run plan uses the immutable earliest eligibility instant as its
        # reference time so an ambiguous retry reconstructs the same plan digest.
        # Wall-clock retention and all live evidence are still checked immediately
        # before planning and again before effect execution. This reference is not
        # an execution timestamp.
        archive_plan = lifecycle.build_task_archive_plan(
            [current_archive_record],
            {task_id: classification},
            now_unix=retention_boundary_unix,
            minimum_age_seconds=int(value["minimum_age_seconds"]),
        )
        if archive_plan.get("blocked") or archive_plan.get("eligible_task_ids") != [task_id]:
            raise TaskAttentionConflictError(
                "task archive dry-run plan is not eligible for exactly the target task"
            )
        archive_effect_plan = effect_plan.build_effect_plan(
            [classification],
            effect_kind="task_archive",
            lease_owner_id=owner,
            required_resource_keys=[archive_resource, effect_resource],
            created_at_unix=retention_boundary_unix,
        )

        revalidated_record = tasks._row_raw(task_id)
        _validate_archive_target(value, revalidated_record)
        revalidated_archive_record, revalidated_record_sha256, _ = (
            _task_archive_source_binding(revalidated_record)
        )
        if revalidated_record_sha256 != record_sha256:
            raise TaskAttentionConflictError(
                "task archive record changed during immediate revalidation"
            )
        _assert_task_archive_retention(
            revalidated_record,
            minimum_age_seconds=int(value["minimum_age_seconds"]),
            now_unix=int(time.time()),
        )
        revalidated_classification = _task_archive_classification(
            revalidated_record,
            expected_lifecycle_receipt_sha256=str(
                value["expected_lifecycle_receipt_sha256"]
            ),
            archived=False,
        )
        archive_effect = lifecycle.execute_task_archive_effect(
            [revalidated_archive_record],
            archive_root=archive_root,
            effect_root=effect_root,
            source_store_sha256=source_store_sha256,
            source_schema_version=tasks.TASK_CURRENT_SCHEMA_VERSION,
            archive_plan=archive_plan,
            plan=archive_effect_plan,
            current_classifications={task_id: revalidated_classification},
            lease_observations=lease_observations,
            execution_id=execution_id,
        )
        manifest = archive_effect["manifest"]
        effect_receipt = archive_effect["effect_receipt"]["receipt"]
        archive_evidence = {
            "archive_manifest_sha256": manifest["manifest_sha256"],
            "archive_segment_sha256": manifest["segment_sha256"],
            "archive_plan_sha256": manifest["plan_sha256"],
            "effect_receipt_sha256": effect_receipt["receipt_sha256"],
        }

        projected = _existing_task_projection_binding(
            task_id,
            expected_record_sha256=record_sha256,
        )
        projection_replay = projected is not None
        if projected is not None:
            if projected.get("segment_id") != manifest.get("segment_id"):
                raise TaskAttentionIntegrityError(
                    "task archive projection points at a different archive segment"
                )
        else:
            projection_record = tasks._row_raw(task_id)
            _validate_archive_target(value, projection_record)
            _, projection_record_sha256, _ = _task_archive_source_binding(
                projection_record
            )
            if projection_record_sha256 != record_sha256:
                raise TaskAttentionConflictError(
                    "task archive record changed before projection switch"
                )
            archived_classification = _task_archive_classification(
                projection_record,
                expected_lifecycle_receipt_sha256=str(
                    value["expected_lifecycle_receipt_sha256"]
                ),
                archived=True,
                archive_evidence=archive_evidence,
            )
            projection_plan = effect_plan.build_effect_plan(
                [archived_classification],
                effect_kind="current_projection_switch",
                lease_owner_id=owner,
                required_resource_keys=[projection_resource],
                created_at_unix=retention_boundary_unix,
            )
            projection_revalidated_record = tasks._row_raw(task_id)
            _validate_archive_target(value, projection_revalidated_record)
            _, projection_revalidated_sha256, _ = _task_archive_source_binding(
                projection_revalidated_record
            )
            if projection_revalidated_sha256 != record_sha256:
                raise TaskAttentionConflictError(
                    "task archive record changed during projection revalidation"
                )
            projection_current_classification = _task_archive_classification(
                projection_revalidated_record,
                expected_lifecycle_receipt_sha256=str(
                    value["expected_lifecycle_receipt_sha256"]
                ),
                archived=True,
                archive_evidence=archive_evidence,
            )
            projection_revalidation = effect_plan.revalidate_effect_plan(
                projection_plan,
                {task_id: projection_current_classification},
                lease_observations,
                now_unix=int(time.time()),
            )
            if projection_revalidation.get("ready_for_effect") is not True:
                raise TaskAttentionConflictError(
                    "task archive projection revalidation is not ready"
                )
            projection_effect = lifecycle_projection.apply_task_archive_projection_switch(
                Path(str(archive_effect["segment_dir"])),
                projection_root=projection_root,
                plan=projection_plan,
                revalidation=projection_revalidation,
                applied_at_unix=int(time.time()),
            )

        final_projection = _existing_task_projection_binding(
            task_id,
            expected_record_sha256=record_sha256,
        )
        if final_projection is None:
            raise TaskAttentionIntegrityError(
                "task archive projection readback did not contain the archived task"
            )
        cleanup_archive_binding = _task_output_cleanup_archive_binding(
            manifest,
            record_sha256=record_sha256,
        )
        task_output_cleanup = _task_output_cleanup_after_archive(
            revalidated_record,
            archive_binding=cleanup_archive_binding,
            projection=final_projection,
            retention_boundary_unix=task_output_retention_boundary_unix,
        )
        output = {
            "schema_version": 1,
            "task_binding": _task_binding(revalidated_record),
            "closeout": current_closeout,
            "retention_boundary_unix": retention_boundary_unix,
            "minimum_age_seconds": int(value["minimum_age_seconds"]),
            "task_output_retention_boundary_unix": (
                task_output_retention_boundary_unix
            ),
            "task_output_minimum_retention_seconds": (
                TASK_OUTPUT_MINIMUM_RETENTION_SECONDS
            ),
            "archive_record_sha256": record_sha256,
            "source_store_sha256": source_store_sha256,
            "source_store_scope": "selected_task_record_snapshot",
            "archive_plan_sha256": archive_plan["plan_sha256"],
            "archive_plan_reference_unix": retention_boundary_unix,
            "archive_plan_reference_semantics": "earliest_retention_eligibility_for_idempotent_replay",
            "archive_segment": {
                "segment_id": manifest["segment_id"],
                "segment_identity_sha256": manifest["segment_identity_sha256"],
                "manifest_sha256": manifest["manifest_sha256"],
                "segment_sha256": manifest["segment_sha256"],
                "idempotent_replay": bool(archive_effect.get("idempotent_replay")),
            },
            "archive_effect_receipt_sha256": effect_receipt["receipt_sha256"],
            "execution_id_sha256": execution_id_sha256,
            "caller_execution_id_sha256": caller_execution_id_sha256,
            "projection": final_projection,
            "projection_idempotent_replay": projection_replay,
            "task_output_cleanup": task_output_cleanup,
            "already_archived": False,
            "idempotent_replay": bool(
                archive_effect.get("idempotent_replay") or projection_replay
            ),
            "does_not_establish": [
                "physical_task_row_deletion",
                "workspace_cleanup_authority",
                "checkout_cleanup_authority",
                "same_uid_output_authenticity",
                "blind_retry_after_recovery_required",
            ],
        }
    except (
        lifecycle.LifecycleArchiveError,
        lifecycle_projection.LifecycleProjectionError,
        effect_plan.LifecycleEffectPlanError,
    ) as exc:
        raise TaskAttentionError(str(exc)) from exc
    finally:
        if lease_result is not None:
            resource_release = _release_owned_archive_resources(
                owner,
                resources_to_hold,
            )
    if output is None:
        raise TaskAttentionError("task closeout archive ended without a result")
    output["resource_release"] = resource_release
    return output


def current_attention_projection(
    records: list[dict[str, Any]],
    *,
    include_decisions: bool = True,
    retry_successor_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project operational attention without rewriting retained task history.

    Raw attention remains the state-derived set. Only a validated persisted
    retry edge or a valid create-only decision bound to the current task attempt
    may remove a record from the operational projection. Missing, stale or invalid
    evidence therefore fails open into current attention rather than hiding work.
    """
    validated_records: list[dict[str, Any]] = []
    for value in records:
        if not isinstance(value, dict):
            raise TaskAttentionInputError("current attention records must be objects")
        record = dict(value)
        if record.get("state") not in ATTENTION_STATES:
            raise TaskAttentionInputError("current attention record has a non-attention state")
        _task_binding(record)
        validated_records.append(record)
    attention_task_ids = {str(record["task_id"]) for record in validated_records}
    convergence_records = list(validated_records)
    support_task_ids: set[str] = set()
    if retry_successor_records is not None and not isinstance(
        retry_successor_records, list
    ):
        raise TaskAttentionInputError(
            "retry_successor_records must be a list when provided"
        )
    for value in list(retry_successor_records or []):
        if not isinstance(value, dict):
            raise TaskAttentionInputError(
                "retry successor records must be objects"
            )
        record = dict(value)
        if (
            record.get("state")
            not in terminal_convergence.RETRY_SUCCESSOR_SUPPORT_STATES
        ):
            raise TaskAttentionInputError(
                "retry successor record state is not support-eligible"
            )
        binding = _task_binding(record)
        try:
            persisted_binding = terminal_convergence.persisted_retry_binding(record)
        except terminal_convergence.TerminalConvergenceError as exc:
            raise TaskAttentionIntegrityError(str(exc)) from exc
        if persisted_binding is None:
            raise TaskAttentionInputError(
                "retry successor record lacks persisted retry evidence"
            )
        task_id = str(binding["task_id"])
        if task_id in attention_task_ids:
            raise TaskAttentionIntegrityError(
                "retry successor record overlaps the attention scope"
            )
        if task_id in support_task_ids:
            raise TaskAttentionIntegrityError(
                "retry successor record is duplicated in the support snapshot"
            )
        support_task_ids.add(task_id)
        convergence_records.append(record)
    try:
        convergence = terminal_convergence.converge_attention_records(
            convergence_records,
            attention_task_ids=attention_task_ids,
        )
    except terminal_convergence.TerminalConvergenceError as exc:
        raise TaskAttentionIntegrityError(str(exc)) from exc
    current_by_task = {
        str(record["task_id"]): record for record in convergence["current"]
    }

    convergence_excluded_task_ids = {
        str(item["task_id"])
        for item in convergence["historical"]
        if item.get("convergence_classification")
        == "superseded_by_verified_retry"
    }
    excluded_task_ids: set[str] = set(convergence_excluded_task_ids)
    decision_excluded_task_ids: set[str] = set()
    decision_classification_counts: dict[str, int] = {}
    decision_candidate_count = 0
    if include_decisions:
        root = _state_root()
        try:
            _ensure_private_directory(root, create=False)
        except FileNotFoundError:
            pass
        else:
            try:
                entries = sorted(root.iterdir(), key=lambda path: path.name)
            except OSError as exc:
                raise TaskAttentionIntegrityError(
                    "task attention decisions cannot be listed safely"
                ) from exc
            for path in entries:
                match = DECISION_FILE_RE.fullmatch(path.name)
                if match is None:
                    continue
                record = current_by_task.get(match.group("task_id"))
                if record is None or int(record["attempt"]) != int(
                    match.group("attempt")
                ):
                    continue
                decision_candidate_count += 1
                classified = _classify_record(record)
                classification = str(classified["classification"])
                decision_classification_counts[classification] = (
                    decision_classification_counts.get(classification, 0) + 1
                )
                if classification in CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS:
                    task_id = str(record["task_id"])
                    decision_excluded_task_ids.add(task_id)
                    excluded_task_ids.add(task_id)

    excluded_counts = {
        classification: decision_classification_counts.get(classification, 0)
        for classification in sorted(CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS)
    }
    deduplicated_attention_count = len(current_by_task)
    current_attention_count = (
        deduplicated_attention_count - len(decision_excluded_task_ids)
    )
    excluded_attention_count = convergence["raw_count"] - current_attention_count
    projection_material = {
        "schema_version": 1,
        "task_bindings": [
            {**_task_binding(record), "state": record["state"]}
            for _task_id, record in sorted(current_by_task.items())
        ],
        "excluded_task_ids": sorted(excluded_task_ids),
        "convergence_excluded_task_ids": sorted(convergence_excluded_task_ids),
        "decision_classification_counts": dict(sorted(decision_classification_counts.items())),
        "attention_convergence_counts": convergence["classification_counts"],
        "attention_converged_bindings": [
            {
                "task_id": item["task_id"],
                "attempt": item["attempt"],
                "lifecycle_receipt_sha256": item.get("lifecycle_receipt_sha256"),
                "classification": item["convergence_classification"],
                "success_claimed": bool(item.get("success_claimed", False)),
                "successor_task_id": item.get("successor_task_id"),
            }
            for item in convergence["historical"]
        ],
    }
    return {
        "status": "verified",
        "evidence_error": None,
        "projection_sha256": _sha256_json(projection_material),
        "raw_attention_count": convergence["raw_count"],
        "deduplicated_attention_count": deduplicated_attention_count,
        "current_attention_count": current_attention_count,
        "excluded_attention_count": excluded_attention_count,
        "convergence_excluded_attention_count": len(
            convergence_excluded_task_ids
        ),
        "excluded_classification_counts": excluded_counts,
        "decision_candidate_count": decision_candidate_count,
        "decision_classification_counts": dict(sorted(decision_classification_counts.items())),
        "attention_convergence_counts": convergence["classification_counts"],
        "converged_attention_count": convergence["converged_count"],
        "retry_successor_record_count": convergence["support_record_count"],
        "excluded_task_ids": excluded_task_ids,
        "convergence_excluded_task_ids": convergence_excluded_task_ids,
        "decision_excluded_task_ids": decision_excluded_task_ids,
        "scope": "current_task_projection_after_valid_attention_decisions",
        "raw_scope": "current_task_projection_before_attention_decisions",
    }


def reconcile_attention(parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    parameters = _validate_exact_keys(
        dict(parameters or {}),
        allowed={"limit", "cursor", "view"},
        required=set(),
        label="task attention reconciliation parameters",
    )
    limit = parameters.get("limit", 20)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PAGE_LIMIT:
        raise TaskAttentionInputError(f"limit must be between 1 and {MAX_PAGE_LIMIT}")
    view = parameters.get("view", "current")
    if not isinstance(view, str) or view not in ATTENTION_VIEWS:
        raise TaskAttentionInputError("view must be current or history")
    cursor = parameters.get("cursor")
    if cursor is not None and not isinstance(cursor, str):
        raise TaskAttentionInputError("cursor must be a string when provided")
    scope = (
        "task-attention-reconciliation:v1"
        if view == "history"
        else "task-attention-reconciliation:current:v1"
    )
    try:
        position = consumer_surface.decode_cursor(cursor, scope)
    except ValueError as exc:
        raise TaskAttentionInputError(str(exc)) from exc
    cursor_created_at: int | None = None
    cursor_task_id: str | None = None
    if position is not None:
        cursor_created_at = position.get("created_at_unix")
        cursor_task_id = position.get("task_id")
        if (
            isinstance(cursor_created_at, bool)
            or not isinstance(cursor_created_at, int)
            or cursor_created_at < 0
            or not isinstance(cursor_task_id, str)
            or tasks.TASK_ID.fullmatch(cursor_task_id) is None
        ):
            raise TaskAttentionInputError("cursor position is invalid")

    placeholders = ",".join("?" for _ in ATTENTION_STATES)

    def fetch_rows(
        connection: Any,
        *,
        created_at: int | None,
        task_id: str | None,
        batch_limit: int,
    ) -> list[Any]:
        where = [f"state IN ({placeholders})"]
        values: list[Any] = list(ATTENTION_STATES)
        if created_at is not None and task_id is not None:
            where.append("(created_at_unix < ? OR (created_at_unix = ? AND task_id < ?))")
            values.extend([created_at, created_at, task_id])
        return connection.execute(
            f"SELECT * FROM tasks WHERE {' AND '.join(where)} "
            "ORDER BY created_at_unix DESC, task_id DESC LIMIT ?",
            (*values, batch_limit),
        ).fetchall()

    scanned_raw = 0
    filtered_counts = {
        "decision_closed": 0,
        "decision_superseded": 0,
        "superseded_by_verified_retry": 0,
    }
    convergence_status = "not_applicable"
    convergence_error: str | None = None
    convergence_counts = {
        "duplicate": 0,
        "superseded": 0,
        "already_satisfied": 0,
        "superseded_by_verified_retry": 0,
    }
    converged_attention_count = 0
    retry_successor_record_count = 0
    convergence_excluded_task_ids: set[str] = set()
    decision_excluded_task_ids: set[str] = set()
    page_records: list[dict[str, Any]] = []
    has_more = False
    next_cursor = None

    with tasks._task_read_snapshot() as connection, decision_snapshot_guard() as decision_snapshot:
        raw_total_attention = int(
            connection.execute(
                f"SELECT COUNT(*) FROM tasks WHERE state IN ({placeholders})",
                ATTENTION_STATES,
            ).fetchone()[0]
        )
        if view == "history":
            rows = fetch_rows(
                connection,
                created_at=cursor_created_at,
                task_id=cursor_task_id,
                batch_limit=limit + 1,
            )
            scanned_raw = min(len(rows), limit)
            has_more = len(rows) > limit
            page_rows = rows[:limit]
            page_records = [_classify_record(dict(row)) for row in page_rows]
            if has_more and page_rows:
                last = dict(page_rows[-1])
                next_cursor = consumer_surface.encode_cursor(
                    scope,
                    {
                        "created_at_unix": int(last["created_at_unix"]),
                        "task_id": str(last["task_id"]),
                    },
                )
        else:
            snapshot_status = str(decision_snapshot.get("status") or "degraded")
            if raw_total_attention > MAX_CURRENT_CONVERGENCE_ROWS:
                convergence_status = "degraded"
                convergence_error = "attention_convergence_scan_limit_exceeded"
            else:
                convergence_rows = connection.execute(
                    f"SELECT * FROM tasks WHERE state IN ({placeholders}) "
                    "ORDER BY created_at_unix DESC, task_id DESC LIMIT ?",
                    (*ATTENTION_STATES, MAX_CURRENT_CONVERGENCE_ROWS + 1),
                ).fetchall()
                if len(convergence_rows) != raw_total_attention:
                    convergence_status = "degraded"
                    convergence_error = "attention_convergence_snapshot_count_mismatch"
                else:
                    try:
                        retry_successors = tasks._task_retry_successor_records(
                            connection,
                            source_task_ids={
                                str(row["task_id"]) for row in convergence_rows
                            },
                            limit=(
                                MAX_CURRENT_CONVERGENCE_ROWS
                                - len(convergence_rows)
                            ),
                        )
                        projection = current_attention_projection(
                            [dict(row) for row in convergence_rows],
                            include_decisions=snapshot_status == "locked",
                            retry_successor_records=retry_successors,
                        )
                    except terminal_convergence.TerminalConvergenceError:
                        convergence_status = "degraded"
                        convergence_error = "TaskAttentionIntegrityError"
                    except (
                        TaskAttentionError,
                        TaskAttentionInputError,
                        RuntimeError,
                        OSError,
                    ) as exc:
                        convergence_status = "degraded"
                        convergence_error = (
                            str(exc) or type(exc).__name__
                            if type(exc) is RuntimeError
                            else type(exc).__name__
                        )
                    else:
                        convergence_status = "verified"
                        convergence_counts = dict(
                            projection["attention_convergence_counts"]
                        )
                        converged_attention_count = int(
                            projection["converged_attention_count"]
                        )
                        retry_successor_record_count = int(
                            projection["retry_successor_record_count"]
                        )
                        convergence_excluded_task_ids = set(
                            projection["convergence_excluded_task_ids"]
                        )
                        decision_excluded_task_ids = set(
                            projection["decision_excluded_task_ids"]
                        )
            scan_created_at = cursor_created_at
            scan_task_id = cursor_task_id
            visible: list[tuple[dict[str, Any], dict[str, Any]]] = []
            source_exhausted = False
            last_scanned_raw: dict[str, Any] | None = None
            while (
                len(visible) <= limit
                and not source_exhausted
                and scanned_raw < MAX_CURRENT_SCAN_ROWS
            ):
                batch_limit = min(
                    MAX_PAGE_LIMIT,
                    MAX_CURRENT_SCAN_ROWS - scanned_raw,
                )
                rows = fetch_rows(
                    connection,
                    created_at=scan_created_at,
                    task_id=scan_task_id,
                    batch_limit=batch_limit,
                )
                if not rows:
                    source_exhausted = True
                    break
                for row in rows:
                    raw = dict(row)
                    scanned_raw += 1
                    last_scanned_raw = raw
                    task_id_value = str(raw["task_id"])
                    if task_id_value in convergence_excluded_task_ids:
                        filtered_counts["superseded_by_verified_retry"] += 1
                    else:
                        classified = _classify_record(
                            raw,
                            include_decisions=snapshot_status == "locked",
                        )
                        if snapshot_status == "degraded":
                            classified["classification"] = "invalid_evidence"
                            evidence_error = str(
                                decision_snapshot.get("evidence_error")
                                or "TaskAttentionDecisionSnapshotError"
                            )
                            if raw["state"] in {"outcome_unknown", "interrupted"}:
                                try:
                                    _decision_path(_task_binding(raw)).lstat()
                                except FileNotFoundError:
                                    pass
                                except OSError as exc:
                                    evidence_error = type(exc).__name__
                                else:
                                    evidence_error = "decision_without_eligible_outcome"
                            classified["evidence_error"] = evidence_error
                        classification = classified["classification"]
                        if task_id_value in decision_excluded_task_ids:
                            if classification not in CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS:
                                raise TaskAttentionIntegrityError(
                                    "decision exclusion classification changed during snapshot"
                                )
                            filtered_counts[classification] += 1
                        else:
                            visible.append((raw, classified))
                            if len(visible) > limit:
                                break
                    scan_created_at = int(raw["created_at_unix"])
                    scan_task_id = str(raw["task_id"])
                if len(visible) > limit:
                    break
                if len(rows) < batch_limit:
                    source_exhausted = True
                else:
                    last_raw = dict(rows[-1])
                    scan_created_at = int(last_raw["created_at_unix"])
                    scan_task_id = str(last_raw["task_id"])

            scan_budget_exhausted = False
            if scanned_raw >= MAX_CURRENT_SCAN_ROWS and not source_exhausted:
                scan_budget_exhausted = bool(
                    fetch_rows(
                        connection,
                        created_at=scan_created_at,
                        task_id=scan_task_id,
                        batch_limit=1,
                    )
                )
                if not scan_budget_exhausted:
                    source_exhausted = True
            has_more = len(visible) > limit or scan_budget_exhausted
            page_visible = visible[:limit]
            page_records = [classified for _raw, classified in page_visible]
            cursor_row: dict[str, Any] | None = None
            if len(visible) > limit and page_visible:
                cursor_row = page_visible[-1][0]
            elif scan_budget_exhausted:
                cursor_row = last_scanned_raw
            if has_more and cursor_row is not None:
                next_cursor = consumer_surface.encode_cursor(
                    scope,
                    {
                        "created_at_unix": int(cursor_row["created_at_unix"]),
                        "task_id": str(cursor_row["task_id"]),
                    },
                )

    counts = {
        classification: sum(
            1 for record in page_records if record["classification"] == classification
        )
        for classification in (
            "actionable",
            "outcome_unknown",
            "decision_closed",
            "decision_deferred",
            "decision_superseded",
            "invalid_evidence",
        )
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "authority": "task_store_plus_create_only_decision_receipts",
        "view": view,
        "records": page_records,
        "classification_counts": counts,
        "classification_counts_scope": "returned_page",
        "total_attention": raw_total_attention,
        "total_attention_scope": "raw_task_state_projection_before_decisions",
        "current_attention_excluded_classifications": sorted(
            CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS
        ),
        "filtered_classification_counts": filtered_counts,
        "filtered_classification_counts_scope": "scanned_raw_window",
        "attention_convergence_status": convergence_status,
        "attention_convergence_error": convergence_error,
        "attention_convergence_counts": convergence_counts,
        "converged_attention_count": converged_attention_count,
        "retry_successor_record_count": retry_successor_record_count,
        "convergence_excluded_attention_count": len(
            convergence_excluded_task_ids
        ),
        "decision_snapshot_status": (
            str(decision_snapshot.get("status"))
            if view == "current"
            else "not_applicable"
        ),
        "pagination": {
            "limit": limit,
            "returned": len(page_records),
            "scanned_raw": scanned_raw,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "ordering": "created_at_unix_desc_task_id_desc",
        },
        "recommended_next_action": (
            "inspect invalid evidence before relying on decisions"
            if counts["invalid_evidence"]
            else "inspect actionable, deferred and outcome-unknown tasks"
            if counts["actionable"] or counts["decision_deferred"] or counts["outcome_unknown"]
            else "continue pagination" if has_more else "none"
        ),
        "does_not_establish": [
            "task_output_correctness",
            "automatic_retry_safety",
            "decision_without_a_valid_current_outcome_receipt",
            "completion_of_future_attempts",
            "systemd_or_fleet_post_state",
            "task_or_outcome_receipt_mutation",
            "exact_global_current_attention_count",
        ],
    }

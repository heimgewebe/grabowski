from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
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


SCHEMA_VERSION = 1
DECISION_KIND = "grabowski_task_attention_decision"
DECISIONS = frozenset({"closed", "deferred", "superseded"})
ATTENTION_VIEWS = frozenset({"current", "history"})
CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS = frozenset(
    {"decision_closed", "decision_superseded"}
)
TERMINAL_ATTENTION_STATES = frozenset({"failed", "timed_out", "signalled"})
ATTENTION_STATES = tuple(tasks.TASK_STATE_PROJECTIONS["attention"])
MAX_RECORD_BYTES = 64 * 1024
MAX_TEXT_BYTES = 2_048
MAX_PAGE_LIMIT = 100
MAX_CURRENT_SCAN_ROWS = 5 * MAX_PAGE_LIMIT
LOCK_TIMEOUT_SECONDS = 5.0
LOCK_POLL_SECONDS = 0.02
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
def _state_lock(*, shared: bool = False) -> Iterator[None]:
    root = _state_root()
    _ensure_private_directory(root, create=True)
    lock_path = root / ".lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
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
    with _state_lock(shared=True):
        yield


@contextmanager
def decision_snapshot_guard() -> Iterator[str | None]:
    """Yield a lock error name instead of hiding raw attention on lock failure."""
    lock = decision_snapshot_lock()
    try:
        lock.__enter__()
    except (TaskAttentionError, OSError) as exc:
        yield type(exc).__name__
        return
    try:
        yield None
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
    if value["state"] not in TERMINAL_ATTENTION_STATES:
        raise TaskAttentionIntegrityError("task outcome receipt is not a decision-eligible attention outcome")
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


def _classify_record(record: dict[str, Any]) -> dict[str, Any]:
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


def current_attention_projection(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Project operational attention without rewriting retained task history.

    Raw attention remains the state-derived set. Only valid create-only decisions
    bound to the current task attempt may remove ``closed`` or ``superseded``
    records from the operational attention projection. Missing, stale or invalid
    evidence therefore fails open into current attention rather than hiding work.
    """
    current_by_task: dict[str, dict[str, Any]] = {}
    for value in records:
        if not isinstance(value, dict):
            raise TaskAttentionInputError("current attention records must be objects")
        record = dict(value)
        if record.get("state") not in ATTENTION_STATES:
            raise TaskAttentionInputError("current attention record has a non-attention state")
        binding = _task_binding(record)
        task_id = binding["task_id"]
        if task_id in current_by_task:
            raise TaskAttentionIntegrityError("current attention projection contains duplicate task ids")
        current_by_task[task_id] = record

    excluded_task_ids: set[str] = set()
    decision_classification_counts: dict[str, int] = {}
    decision_candidate_count = 0
    root = _state_root()
    try:
        _ensure_private_directory(root, create=False)
    except FileNotFoundError:
        pass
    else:
        try:
            entries = sorted(root.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise TaskAttentionIntegrityError("task attention decisions cannot be listed safely") from exc
        for path in entries:
            match = DECISION_FILE_RE.fullmatch(path.name)
            if match is None:
                continue
            record = current_by_task.get(match.group("task_id"))
            if record is None or int(record["attempt"]) != int(match.group("attempt")):
                continue
            decision_candidate_count += 1
            classified = _classify_record(record)
            classification = str(classified["classification"])
            decision_classification_counts[classification] = (
                decision_classification_counts.get(classification, 0) + 1
            )
            if classification in CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS:
                excluded_task_ids.add(str(record["task_id"]))

    excluded_counts = {
        classification: decision_classification_counts.get(classification, 0)
        for classification in sorted(CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS)
    }
    raw_attention_count = len(current_by_task)
    current_attention_count = raw_attention_count - len(excluded_task_ids)
    projection_material = {
        "schema_version": 1,
        "task_bindings": [
            {**_task_binding(record), "state": record["state"]}
            for _task_id, record in sorted(current_by_task.items())
        ],
        "excluded_task_ids": sorted(excluded_task_ids),
        "decision_classification_counts": dict(sorted(decision_classification_counts.items())),
    }
    return {
        "status": "verified",
        "evidence_error": None,
        "projection_sha256": _sha256_json(projection_material),
        "raw_attention_count": raw_attention_count,
        "current_attention_count": current_attention_count,
        "excluded_attention_count": len(excluded_task_ids),
        "excluded_classification_counts": excluded_counts,
        "decision_candidate_count": decision_candidate_count,
        "decision_classification_counts": dict(sorted(decision_classification_counts.items())),
        "excluded_task_ids": excluded_task_ids,
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
    }
    page_records: list[dict[str, Any]] = []
    has_more = False
    next_cursor = None

    with tasks._task_read_snapshot() as connection:
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
                    classified = _classify_record(raw)
                    classification = classified["classification"]
                    if classification in CURRENT_ATTENTION_EXCLUDED_CLASSIFICATIONS:
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

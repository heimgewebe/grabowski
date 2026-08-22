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
import uuid
from typing import Any, Callable, Iterator

import grabowski_checkouts as checkouts
import grabowski_execution_plan as execution_plan_contract
import grabowski_lane_closeout as lane_closeout
import grabowski_operator_obligation as operator_obligation
import grabowski_operator_core as operator
import grabowski_resources as resources
import grabowski_work_admission as work_admission
import grabowski_worktree_ensure as worktree_ensure

mcp = operator.mcp
MUTATING = operator.MUTATING
SCHEMA_VERSION = 1
LANE_KIND = "grabowski.work_lane"
ACTOR_RE = re.compile(r"[A-Za-z0-9._:@/-]{1,256}\Z")
SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
SUCCESS_STATES = frozenset({"CREATED", "ALREADY_CORRECT"})
DIRECT_SOURCE_KINDS = frozenset({"direct", "direct-user"})
MAX_WRITE_PATHS = 256
MAX_WRITER_ARGV = 256
MAX_WRITER_ARGUMENT_BYTES = 8192


class ScopedWriterStartPreflight(ValueError):
    """Writer launch validation failed before any launch effect."""


class LeaseAcquisitionOutcomeUnknown(RuntimeError):
    """A resource acquisition returned without trustworthy lease evidence."""


class LeaseCompensationOutcomeUnknown(RuntimeError):
    """A guarded resource release returned without trustworthy evidence."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _state_root() -> Path:
    configured = os.environ.get("GRABOWSKI_WORK_LANE_ROOT")
    if configured:
        return Path(configured).expanduser()
    state_home = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))).expanduser()
    return state_home / "grabowski" / "work-lanes"


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError("work-lane state root is not owner controlled")
    os.chmod(path, 0o700)
    return path


@contextmanager
def _lane_lock(lane_id: str) -> Iterator[Path]:
    root = _private_directory(_state_root())
    lock_path = root / f"{lane_id}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise RuntimeError("work-lane lock is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield root / f"{lane_id}.json"
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short work-lane receipt write")
        view = view[written:]


def _write_state(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    material["receipt_sha256"] = _sha(material)
    raw = json.dumps(material, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return material


def _read_state(path: Path) -> dict[str, Any] | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size > 1_048_576:
            raise RuntimeError("work-lane receipt is unsafe")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError("work-lane receipt ended before its recorded size")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or value.get("kind") != LANE_KIND or value.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("work-lane receipt shape is invalid")
    supplied = value.get("receipt_sha256")
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(supplied, str) or supplied != _sha(material):
        raise RuntimeError("work-lane receipt integrity mismatch")
    return value


def _stored_lane_inputs(lane_id: str) -> dict[str, Any]:
    _text(lane_id, "lane_id", pattern=re.compile(r"[0-9a-f]{32}\Z"))
    with _lane_lock(lane_id) as receipt_path:
        record = _read_state(receipt_path)
    if record is None or record.get("lane_id") != lane_id:
        raise RuntimeError("work-lane receipt is missing or bound to another lane")
    inputs = record.get("inputs")
    if not isinstance(inputs, dict) or record.get("inputs_sha256") != _sha(inputs):
        raise RuntimeError("work-lane stored inputs are invalid")
    if inputs.get("lane_id") != lane_id or inputs.get("lease_owner_id") != f"lane:{lane_id}":
        raise RuntimeError("work-lane stored input identity is invalid")
    identity = {
        key: value
        for key, value in inputs.items()
        if key not in {"lane_id", "lease_owner_id", "ttl_seconds"}
    }
    if _sha(identity)[:32] != lane_id:
        raise RuntimeError("work-lane stored identity digest is invalid")
    return dict(inputs)


def _closeout_inputs(parameters: dict[str, Any], lane_id: str) -> dict[str, Any]:
    """Bind closeout to durable lane identity without re-resolving mutable paths."""
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be an object")
    inputs = _stored_lane_inputs(lane_id)

    controller_actor = _text(
        parameters.get("controller_actor"), "controller_actor", pattern=ACTOR_RE
    )
    if parameters.get("controller_role", "controller") != "controller":
        raise ValueError("controller_role must be controller")
    writer = parameters.get("scoped_writer_actor")
    if writer is not None:
        writer = _text(writer, "scoped_writer_actor", pattern=ACTOR_RE)
        if writer == controller_actor:
            raise ValueError("scoped_writer_actor must differ from controller_actor")
    source_kind, source_id = checkouts._source_binding(
        _text(parameters.get("source_kind"), "source_kind"),
        _text(parameters.get("source_id"), "source_id"),
    )
    _text(parameters.get("repo"), "repo")
    target = Path(_text(parameters.get("target_path"), "target_path")).expanduser()
    if not target.is_absolute():
        raise ValueError("target_path must be absolute")
    branch = _text(parameters.get("branch"), "branch")
    base_head = _text(parameters.get("base_head"), "base_head").lower()
    if SHA40_RE.fullmatch(base_head) is None:
        raise ValueError("base_head must be an exact lowercase 40-character commit")
    purpose = checkouts._purpose(_text(parameters.get("purpose"), "purpose"))
    artifact_class = checkouts._artifact_class(
        parameters.get("artifact_class", "implementation-worktree")
    )
    retention = parameters.get("retention_until_unix")
    if isinstance(retention, bool) or not isinstance(retention, int) or retention < 0:
        raise ValueError("retention_until_unix must be a non-negative integer timestamp")
    ttl = parameters.get("ttl_seconds", 7200)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 120 <= ttl <= 86400:
        raise ValueError("ttl_seconds must be between 120 and 86400")
    idempotency_key = _text(
        parameters.get("idempotency_key"), "idempotency_key", pattern=IDEMPOTENCY_RE
    )
    system_convergence = parameters.get("system_convergence")
    if system_convergence is not None and not isinstance(system_convergence, dict):
        raise ValueError("system_convergence must be an object or null")
    requested = parameters.get("resource_keys") or []
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        raise ValueError("resource_keys must be a list of strings")
    write_paths = parameters.get("write_paths")
    if write_paths is not None:
        if not isinstance(write_paths, list) or len(write_paths) > MAX_WRITE_PATHS:
            raise ValueError(
                f"write_paths must be a list with at most {MAX_WRITE_PATHS} entries"
            )
        for index, item in enumerate(write_paths):
            _text(item, f"write_paths[{index}]")
    writer_argv = _scoped_writer_argv(parameters.get("scoped_writer_argv"), writer)
    writer_runtime = parameters.get("scoped_writer_runtime_seconds", 7200)
    if (
        isinstance(writer_runtime, bool)
        or not isinstance(writer_runtime, int)
        or not 120 <= writer_runtime <= 86400
    ):
        raise ValueError(
            "scoped_writer_runtime_seconds must be between 120 and 86400"
        )
    writer_command = None
    if writer_argv is not None:
        writer_command = {
            "argv_sha256": _sha(writer_argv),
            "argc": len(writer_argv),
            "runtime_seconds": writer_runtime,
        }

    expected = {
        "source": {"kind": source_kind, "id": source_id},
        "controller": {"actor": controller_actor, "role": "controller"},
        "scoped_writer": ({"actor": writer, "role": "scoped_writer"} if writer else None),
        "base_head": base_head,
        "branch": branch,
        "purpose": purpose,
        "artifact_class": artifact_class,
        "retention_until_unix": retention,
        "idempotency_key": idempotency_key,
        "system_convergence": (
            dict(system_convergence) if system_convergence is not None else None
        ),
        "ttl_seconds": ttl,
        "scoped_writer_command": writer_command,
    }
    stored = {key: inputs.get(key) for key in expected}
    if stored != expected:
        raise RuntimeError("terminal closeout parameters do not match stored work lane inputs")
    return inputs


def _terminal_assessment_replay_sha256(assessment: dict[str, Any]) -> str:
    validated = lane_closeout.validate_terminal_assessment(assessment)
    material = {
        key: item
        for key, item in validated.items()
        if key
        not in {
            "observed_at_unix",
            "assessment_sha256",
            "audit_record_sha256",
            "does_not_establish",
        }
    }
    return _sha(material)


def _terminal_closeout_assessment(record: dict[str, Any]) -> dict[str, Any] | None:
    terminal = record.get("terminal_closeout")
    if terminal is None:
        return None
    if not isinstance(terminal, dict) or terminal.get("schema_version") != 1 or terminal.get("kind") != "grabowski.work_lane_terminal_closeout":
        raise RuntimeError("work-lane terminal closeout wrapper is invalid")
    assessment = terminal.get("assessment")
    if not isinstance(assessment, dict):
        raise RuntimeError("work-lane terminal closeout assessment is missing")
    validated = lane_closeout.validate_terminal_assessment(assessment)
    if (validated.get("lane_id") != record.get("lane_id")
        or terminal.get("closeout_state") != validated.get("closeout_state")
        or terminal.get("assessment_sha256") != validated.get("assessment_sha256")):
        raise RuntimeError("work-lane terminal closeout binding is invalid")
    return validated


def _text(value: Any, label: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be trimmed non-empty text")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ValueError(f"{label} has an invalid format")
    return value


def _terminal_closeout_audit_event(
    record: dict[str, Any], assessment: dict[str, Any]
) -> dict[str, Any]:
    terminal = record.get("terminal_closeout")
    if not isinstance(terminal, dict):
        raise RuntimeError("work-lane terminal closeout wrapper is missing")
    expected_preimage = terminal.get("expected_receipt_sha256")
    receipt_sha256 = record.get("receipt_sha256")
    if (
        not isinstance(expected_preimage, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_preimage) is None
        or not isinstance(receipt_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt_sha256) is None
    ):
        raise RuntimeError("work-lane terminal closeout audit binding is invalid")
    material = {
        "operation": "work-lane-terminal-closeout",
        "lane_id": record["lane_id"],
        "state": "persisted",
        "closeout_state": assessment["closeout_state"],
        "assessment_sha256": assessment["assessment_sha256"],
        "receipt_sha256": receipt_sha256,
        "expected_receipt_sha256": expected_preimage,
    }
    return {**material, "terminal_transition_sha256": _sha(material)}


def _find_terminal_closeout_audit(event: dict[str, Any]) -> str | None:
    records, status = operator.base._audit_records_snapshot()
    if not status.get("valid"):
        raise RuntimeError("audit snapshot is invalid during terminal closeout recovery")
    matches = [
        record
        for record in records
        if all(record.get(key) == value for key, value in event.items())
    ]
    if len(matches) > 1:
        raise RuntimeError("terminal closeout audit contains duplicate transition records")
    if not matches:
        return None
    digest = matches[0].get("record_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RuntimeError("terminal closeout audit record digest is invalid")
    return digest


def _ensure_terminal_closeout_audit(
    record: dict[str, Any],
    assessment: dict[str, Any],
    *,
    audit_fn: Callable[[dict[str, Any]], str | None] | None,
    audit_lookup_fn: Callable[[dict[str, Any]], str | None] | None,
) -> str | None:
    if audit_fn is None:
        if audit_lookup_fn is not None:
            raise ValueError("audit_lookup_fn requires audit_fn")
        return None
    if audit_lookup_fn is None:
        raise ValueError("audit_fn requires audit_lookup_fn for retry-safe closeout")
    event = _terminal_closeout_audit_event(record, assessment)
    existing = audit_lookup_fn(event)
    if existing is not None:
        if not isinstance(existing, str) or re.fullmatch(r"[0-9a-f]{64}", existing) is None:
            raise RuntimeError("terminal closeout audit lookup returned an invalid digest")
        return existing
    appended = audit_fn(event)
    if not isinstance(appended, str) or re.fullmatch(r"[0-9a-f]{64}", appended) is None:
        raise RuntimeError("terminal closeout audit append returned an invalid digest")
    readback = audit_lookup_fn(event)
    if readback != appended:
        raise RuntimeError("terminal closeout audit append readback mismatch")
    return appended


def persist_terminal_closeout(
    lane_id: str,
    assessment: dict[str, Any],
    *,
    expected_receipt_sha256: str,
    audit_fn: Callable[[dict[str, Any]], str | None] | None = None,
    audit_lookup_fn: Callable[[dict[str, Any]], str | None] | None = None,
) -> dict[str, Any]:
    """CAS-persist one terminal assessment into the existing lane receipt."""
    _text(lane_id, "lane_id", pattern=re.compile(r"[0-9a-f]{32}\Z"))
    _text(expected_receipt_sha256, "expected_receipt_sha256", pattern=re.compile(r"[0-9a-f]{64}\Z"))
    validated = lane_closeout.validate_terminal_assessment(assessment)
    if validated.get("lane_id") != lane_id:
        raise RuntimeError("terminal closeout assessment is bound to another lane")
    wrapper = {
        "schema_version": 1,
        "kind": "grabowski.work_lane_terminal_closeout",
        "closeout_state": validated["closeout_state"],
        "assessment_sha256": validated["assessment_sha256"],
        "expected_receipt_sha256": expected_receipt_sha256,
        "assessment": validated,
    }
    with _lane_lock(lane_id) as receipt_path:
        record = _read_state(receipt_path)
        if record is None or record.get("lane_id") != lane_id:
            raise RuntimeError("work-lane receipt is missing or bound to another lane")
        existing = _terminal_closeout_assessment(record)
        if existing is not None:
            if _terminal_assessment_replay_sha256(existing) != _terminal_assessment_replay_sha256(validated):
                raise RuntimeError("work-lane already records another terminal assessment")
            audit_record_sha256 = _ensure_terminal_closeout_audit(
                record, existing, audit_fn=audit_fn, audit_lookup_fn=audit_lookup_fn
            )
            result = {**record, "durable_receipt_path": str(receipt_path), "replayed": True}
            if audit_record_sha256 is not None:
                result["terminal_closeout_audit_record_sha256"] = audit_record_sha256
            return result
        if record.get("receipt_sha256") != expected_receipt_sha256:
            raise RuntimeError("work-lane terminal closeout CAS preimage changed")
        stored = _write_state(receipt_path, {**record, "terminal_closeout": wrapper, "updated_at_unix": int(time.time())})
        result = {**stored, "durable_receipt_path": str(receipt_path), "replayed": False}
        audit_record_sha256 = _ensure_terminal_closeout_audit(
            stored, validated, audit_fn=audit_fn, audit_lookup_fn=audit_lookup_fn
        )
        if audit_record_sha256 is not None:
            result["terminal_closeout_audit_record_sha256"] = audit_record_sha256
        return result


def _write_path_resource_keys(repo: Path, value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_WRITE_PATHS:
        raise ValueError(
            f"write_paths must be a list with at most {MAX_WRITE_PATHS} entries"
        )
    result: list[str] = []
    for index, item in enumerate(value):
        raw = _text(item, f"write_paths[{index}]")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = repo / candidate
        candidate = candidate.resolve(strict=False)
        if candidate == repo or not candidate.is_relative_to(repo):
            raise ValueError(f"write_paths[{index}] must resolve below repo")
        result.append(f"path:{candidate}")
    return result


def _normalized_plan_write_scope(
    repo: Path, write_path_resources: list[str]
) -> list[str]:
    result: list[str] = []
    for resource_key in write_path_resources:
        if not resource_key.startswith("path:"):
            raise RuntimeError("normalized write path resource is invalid")
        path = Path(resource_key.removeprefix("path:"))
        try:
            relative = path.relative_to(repo)
        except ValueError as exc:
            raise RuntimeError("normalized write path escaped repository") from exc
        result.append(relative.as_posix())
    return sorted(set(result))


def _execution_plan_binding(
    value: Any,
    *,
    source_kind: str,
    source_id: str,
    repo: Path,
    write_path_resources: list[str],
) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        plan = execution_plan_contract.validate_execution_plan(value)
    except execution_plan_contract.ExecutionPlanError as exc:
        raise ValueError(f"execution_plan is invalid: {exc}") from exc
    expected_source = {"kind": source_kind, "id": source_id}
    if plan.get("source_binding") != expected_source:
        raise ValueError("execution_plan source binding does not match work lane source")
    expected_scope = _normalized_plan_write_scope(repo, write_path_resources)
    if plan.get("write_scope") != expected_scope:
        raise ValueError("execution_plan write scope does not match work lane write_paths")
    return plan


def _scoped_writer_argv(value: Any, writer: str | None) -> list[str] | None:
    if value is None:
        return None
    if writer is None:
        raise ValueError("scoped_writer_argv requires scoped_writer_actor")
    if not isinstance(value, list) or not value or len(value) > MAX_WRITER_ARGV:
        raise ValueError(
            f"scoped_writer_argv must contain between 1 and {MAX_WRITER_ARGV} arguments"
        )
    result: list[str] = []
    for index, item in enumerate(value):
        if (
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > MAX_WRITER_ARGUMENT_BYTES
        ):
            raise ValueError(f"scoped_writer_argv[{index}] is invalid")
        result.append(item)
    return result


def _start_scoped_writer(
    argv: list[str], *, cwd: str, runtime_seconds: int
) -> dict[str, Any]:
    working_directory = Path(cwd).resolve(strict=True)
    try:
        operator._validate_argv(argv, cwd=working_directory)
        operator._job_runtime(runtime_seconds)
    except Exception as exc:
        raise ScopedWriterStartPreflight(str(exc)) from exc
    return operator._start_job(
        argv,
        cwd=str(working_directory),
        runtime_seconds=runtime_seconds,
    )


def _writer_job_receipt(result: dict[str, Any]) -> dict[str, Any]:
    required = ("job_id", "unit", "argv_sha256", "metadata_path")
    if not all(isinstance(result.get(key), str) and result[key] for key in required):
        raise RuntimeError("scoped writer start omitted durable job identity")
    receipt = {
        "job_id": result["job_id"],
        "unit": result["unit"],
        "owner": result.get("owner"),
        "argv_sha256": result["argv_sha256"],
        "cwd": result.get("cwd"),
        "runtime_seconds": result.get("runtime_seconds"),
        "metadata_path": result["metadata_path"],
        "expected_receipt": result.get("expected_receipt"),
        "final_status": result.get("final_status"),
    }
    return {**receipt, "receipt_sha256": _sha(receipt)}


def _normalize(
    parameters: dict[str, Any], *, require_fresh_retention: bool = True
) -> dict[str, Any]:
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be an object")
    controller_actor = _text(parameters.get("controller_actor"), "controller_actor", pattern=ACTOR_RE)
    controller_role = parameters.get("controller_role", "controller")
    if controller_role != "controller":
        raise ValueError("controller_role must be controller")
    writer = parameters.get("scoped_writer_actor")
    if writer is not None:
        writer = _text(writer, "scoped_writer_actor", pattern=ACTOR_RE)
        if writer == controller_actor:
            raise ValueError("scoped_writer_actor must differ from controller_actor")
    source_kind, source_id = checkouts._source_binding(
        _text(parameters.get("source_kind"), "source_kind"),
        _text(parameters.get("source_id"), "source_id"),
    )
    if (
        source_kind == "operator_obligation"
        and operator_obligation.OBLIGATION_ID_RE.fullmatch(source_id) is None
    ):
        raise ValueError(
            "source_id for operator_obligation must match goo-[a-z0-9-]"
        )
    repo = Path(_text(parameters.get("repo"), "repo")).expanduser().resolve(strict=True)
    if not repo.is_dir():
        raise ValueError("repo must be an existing directory")
    target = Path(_text(parameters.get("target_path"), "target_path")).expanduser()
    if not target.is_absolute():
        raise ValueError("target_path must be absolute")
    target = target.resolve(strict=False)
    repo_parent = repo.parent.resolve(strict=True)
    if target == repo or not target.is_relative_to(repo_parent):
        raise ValueError("target_path must be below the repository parent and differ from repo")
    if not target.parent.exists() or not target.parent.is_dir():
        raise ValueError("target_path parent must already exist")
    branch = _text(parameters.get("branch"), "branch")
    base_head = _text(parameters.get("base_head"), "base_head").lower()
    if SHA40_RE.fullmatch(base_head) is None:
        raise ValueError("base_head must be an exact lowercase 40-character commit")
    purpose = checkouts._purpose(_text(parameters.get("purpose"), "purpose"))
    artifact_class = checkouts._artifact_class(parameters.get("artifact_class", "implementation-worktree"))
    retention_value = parameters.get("retention_until_unix")
    if require_fresh_retention:
        retention = checkouts._retention_until(retention_value)
    else:
        if not isinstance(retention_value, int) or isinstance(retention_value, bool) or retention_value < 0:
            raise ValueError("retention_until_unix must be a non-negative integer timestamp")
        retention = retention_value
    ttl = parameters.get("ttl_seconds", 7200)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 120 <= ttl <= 86400:
        raise ValueError("ttl_seconds must be between 120 and 86400")
    idempotency_key = _text(parameters.get("idempotency_key"), "idempotency_key", pattern=IDEMPOTENCY_RE)
    system_convergence = parameters.get("system_convergence")
    if system_convergence is not None and not isinstance(system_convergence, dict):
        raise ValueError("system_convergence must be an object or null")
    normalized_system_convergence_plan = work_admission.plan_system_convergence(
        system_convergence
    )
    normalized_system_convergence = (
        dict(system_convergence) if system_convergence is not None else None
    )
    requested = parameters.get("resource_keys") or []
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        raise ValueError("resource_keys must be a list of strings")
    path_resources = _write_path_resource_keys(repo, parameters.get("write_paths"))
    execution_plan = _execution_plan_binding(
        parameters.get("execution_plan"),
        source_kind=source_kind,
        source_id=source_id,
        repo=repo,
        write_path_resources=path_resources,
    )
    writer_argv = _scoped_writer_argv(parameters.get("scoped_writer_argv"), writer)
    writer_runtime = parameters.get("scoped_writer_runtime_seconds", 7200)
    if (
        isinstance(writer_runtime, bool)
        or not isinstance(writer_runtime, int)
        or not 120 <= writer_runtime <= 86400
    ):
        raise ValueError(
            "scoped_writer_runtime_seconds must be between 120 and 86400"
        )
    required = [f"path:{target}", f"repo:{repo}:branch:{branch}"]
    resource_keys = resources.normalize_resource_keys(
        [*requested, *path_resources, *required]
    )
    identity = {
        "source": {"kind": source_kind, "id": source_id},
        "controller": {"actor": controller_actor, "role": "controller"},
        "scoped_writer": ({"actor": writer, "role": "scoped_writer"} if writer else None),
        "repo": str(repo),
        "base_head": base_head,
        "branch": branch,
        "target_path": str(target),
        "purpose": purpose,
        "artifact_class": artifact_class,
        "retention_until_unix": retention,
        "resource_keys": resource_keys,
        "idempotency_key": idempotency_key,
        "system_convergence": normalized_system_convergence,
        "system_convergence_plan": normalized_system_convergence_plan,
    }
    if execution_plan is not None:
        identity["execution_plan"] = execution_plan
    if writer_argv is not None:
        identity["scoped_writer_command"] = {
            "argv_sha256": _sha(writer_argv),
            "argc": len(writer_argv),
            "runtime_seconds": writer_runtime,
        }
    lane_id = _sha(identity)[:32]
    return {
        **identity,
        "lane_id": lane_id,
        "lease_owner_id": f"lane:{lane_id}",
        "ttl_seconds": ttl,
        "_scoped_writer_argv": writer_argv,
    }


def _lifecycle_source(inputs: dict[str, Any]) -> dict[str, str]:
    source = inputs.get("source")
    if not isinstance(source, dict):
        raise RuntimeError("work lane source binding is missing")
    kind = source.get("kind")
    source_id = source.get("id")
    if not isinstance(kind, str) or not isinstance(source_id, str):
        raise RuntimeError("work lane source binding is invalid")
    if kind in DIRECT_SOURCE_KINDS:
        lane_id = inputs.get("lane_id")
        if not isinstance(lane_id, str) or not lane_id:
            raise RuntimeError("direct work lane identity is missing")
        return {"kind": "work_lane", "id": lane_id}
    return {"kind": kind, "id": source_id}


def _git_runner(cwd: Path, arguments: list[str]) -> dict[str, Any]:
    command = ["git", "-C", str(cwd), *arguments]
    command = operator._validate_argv(command, cwd=cwd)
    return operator._run(
        command,
        cwd=cwd,
        timeout_seconds=60,
        max_output_bytes=250_000,
        environment=operator._git_environment(),
    )


def _effect_observed(output: dict[str, Any]) -> bool:
    post = output.get("post_state")
    return bool(
        isinstance(post, dict)
        and (
            post.get("target_registered") is True
            or post.get("target_path_exists") is True
            or isinstance(post.get("branch_ref_head"), str)
        )
    )


def _resource_acquisition_plan(resource_keys: list[str]) -> list[dict[str, Any]]:
    keys = resources.normalize_resource_keys(resource_keys)
    bureau_keys = resources.bureau_leases.bureau_resource_keys(keys)
    if (
        not isinstance(bureau_keys, list)
        or any(not isinstance(key, str) for key in bureau_keys)
        or len(set(bureau_keys)) != len(bureau_keys)
        or not set(bureau_keys).issubset(keys)
    ):
        raise RuntimeError("Bureau resource classification returned an invalid partition")
    bureau_keys = sorted(bureau_keys)
    bureau_key_set = set(bureau_keys)
    standard_keys = [key for key in keys if key not in bureau_key_set]
    return [
        {"contract_group": contract_group, "resource_keys": group_keys}
        for contract_group, group_keys in (
            ("bureau", bureau_keys),
            ("standard", standard_keys),
        )
        if group_keys
    ]


def _lease_snapshot(lease: Any, *, owner_id: str) -> dict[str, Any]:
    if not isinstance(lease, dict) or not resources.LEASE_SNAPSHOT_KEYS.issubset(lease):
        raise LeaseAcquisitionOutcomeUnknown("acquisition lease snapshot is malformed")
    snapshot = {
        key: lease[key] for key in sorted(resources.LEASE_SNAPSHOT_KEYS)
    }
    if snapshot["owner_id"] != owner_id:
        raise LeaseAcquisitionOutcomeUnknown(
            "acquisition lease snapshot is owned by another owner"
        )
    for key in ("acquired_at_unix", "updated_at_unix", "expires_at_unix"):
        if type(snapshot[key]) is not int:
            raise LeaseAcquisitionOutcomeUnknown(
                f"acquisition lease {key} is invalid"
            )
    if not (
        snapshot["acquired_at_unix"]
        <= snapshot["updated_at_unix"]
        < snapshot["expires_at_unix"]
    ):
        raise LeaseAcquisitionOutcomeUnknown(
            "acquisition lease timestamps are inconsistent"
        )
    metadata_sha256 = snapshot["metadata_sha256"]
    if (
        not isinstance(metadata_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", metadata_sha256) is None
    ):
        raise LeaseAcquisitionOutcomeUnknown(
            "acquisition lease metadata SHA-256 is invalid"
        )
    return snapshot


def _acquisition_evidence(
    group: dict[str, Any], receipt: Any, *, owner_id: str
) -> dict[str, Any]:
    if not isinstance(receipt, dict) or receipt.get("owner_id") != owner_id:
        raise LeaseAcquisitionOutcomeUnknown(
            "resource acquisition omitted the expected owner identity"
        )
    leases = receipt.get("leases")
    if not isinstance(leases, list):
        raise LeaseAcquisitionOutcomeUnknown(
            "resource acquisition omitted exact lease evidence"
        )
    snapshots = [_lease_snapshot(lease, owner_id=owner_id) for lease in leases]
    snapshots.sort(key=lambda item: item["resource_key"])
    expected_keys = list(group["resource_keys"])
    if [item["resource_key"] for item in snapshots] != expected_keys:
        raise LeaseAcquisitionOutcomeUnknown(
            "resource acquisition lease evidence does not match its contract group"
        )
    preserved = receipt.get("preserved")
    if (
        not isinstance(preserved, list)
        or any(not isinstance(key, str) for key in preserved)
        or len(set(preserved)) != len(preserved)
        or not set(preserved).issubset(expected_keys)
    ):
        raise LeaseAcquisitionOutcomeUnknown(
            "resource acquisition preserved-set evidence is invalid"
        )
    contract_group = group["contract_group"]
    bureau_contract = receipt.get("bureau_contract")
    if contract_group == "bureau" and not isinstance(bureau_contract, dict):
        raise LeaseAcquisitionOutcomeUnknown(
            "Bureau resource acquisition omitted its contract evidence"
        )
    if contract_group == "standard" and bureau_contract is not None:
        raise LeaseAcquisitionOutcomeUnknown(
            "standard resource acquisition returned a Bureau contract"
        )
    preserved_set = set(preserved)
    return {
        "contract_group": contract_group,
        "resource_keys": expected_keys,
        "receipt": receipt,
        "attempt_lease_snapshots": [
            snapshot
            for snapshot in snapshots
            if snapshot["resource_key"] not in preserved_set
        ],
    }


def _acquisition_bundle(
    owner_id: str,
    plan: list[dict[str, Any]],
    acquisitions: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(plan) == 1 and len(acquisitions) == 1:
        return acquisitions[0]["receipt"]
    return {
        "schema_version": 1,
        "kind": "grabowski.work_lane.lease_bundle",
        "owner_id": owner_id,
        "leases": [
            lease
            for acquisition in acquisitions
            for lease in acquisition["receipt"]["leases"]
        ],
        "preserved": sorted(
            {
                key
                for acquisition in acquisitions
                for key in acquisition["receipt"]["preserved"]
            }
        ),
        "reclaimed": [
            reclaimed
            for acquisition in acquisitions
            for reclaimed in acquisition["receipt"].get("reclaimed", [])
        ],
        "acquisitions": [acquisition["receipt"] for acquisition in acquisitions],
        "resource_classes": {
            acquisition["contract_group"]: list(acquisition["resource_keys"])
            for acquisition in acquisitions
        },
    }


def _group_evidence_fields(
    plan: list[dict[str, Any]], acquisitions: list[dict[str, Any]]
) -> dict[str, Any]:
    if len(plan) == 1:
        return {}
    return {
        "acquisition_plan": plan,
        "lease_acquisition_groups": acquisitions,
    }


def _definite_acquisition_failure(exc: Exception) -> bool:
    return isinstance(
        exc,
        (
            ValueError,
            PermissionError,
            resources.ResourceConflict,
            resources.bureau_leases.BureauLeaseContractError,
            work_admission.WorkAdmissionBlocked,
        ),
    )


def _verified_release_receipt(
    receipt: Any,
    *,
    owner_id: str,
    expected_leases: list[dict[str, Any]],
) -> dict[str, Any]:
    if (
        not isinstance(receipt, dict)
        or receipt.get("owner_id") != owner_id
        or receipt.get("snapshot_guarded") is not True
        or not isinstance(receipt.get("released"), list)
    ):
        raise LeaseCompensationOutcomeUnknown(
            "guarded lease release omitted exact outcome evidence"
        )
    try:
        released = [
            _lease_snapshot(lease, owner_id=owner_id)
            for lease in receipt["released"]
        ]
    except LeaseAcquisitionOutcomeUnknown as exc:
        raise LeaseCompensationOutcomeUnknown(str(exc)) from exc
    released.sort(key=lambda item: item["resource_key"])
    if released != expected_leases:
        raise LeaseCompensationOutcomeUnknown(
            "guarded lease release evidence does not match the requested snapshots"
        )
    return receipt


def _compensate_acquisitions(
    *,
    owner_id: str,
    plan: list[dict[str, Any]],
    acquisitions: list[dict[str, Any]],
    release_resources_fn: Callable[..., dict[str, Any]],
    receipt_path: Path,
    base_record: dict[str, Any],
    lease_receipt: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    released_groups: list[dict[str, Any]] = []
    preserved_keys = sorted(
        {
            key
            for acquisition in acquisitions
            for key in acquisition["receipt"]["preserved"]
        }
    )
    for acquisition in reversed(acquisitions):
        expected_leases = list(acquisition["attempt_lease_snapshots"])
        if not expected_leases:
            continue
        resource_keys = [item["resource_key"] for item in expected_leases]
        in_flight = {
            "state": "group_in_flight",
            "contract_group": acquisition["contract_group"],
            "resource_keys": resource_keys,
            "expected_leases": expected_leases,
            "released_groups": released_groups,
            "preserved_resource_keys": preserved_keys,
        }
        _write_state(
            receipt_path,
            {
                **base_record,
                "state": "compensating",
                "decision": "HARD_BLOCK",
                "lease_receipt": lease_receipt,
                **_group_evidence_fields(plan, acquisitions),
                "compensation": in_flight,
                "next_action": "complete_guarded_lease_compensation",
            },
        )
        try:
            release_receipt = release_resources_fn(
                owner_id,
                resource_keys,
                expected_leases=expected_leases,
            )
            release_receipt = _verified_release_receipt(
                release_receipt,
                owner_id=owner_id,
                expected_leases=expected_leases,
            )
        except Exception as exc:
            return (
                {
                    **in_flight,
                    "state": "outcome_unknown",
                    "error_class": type(exc).__name__,
                    "error": str(exc)[:2048],
                },
                False,
            )
        released_groups.append(
            {
                "contract_group": acquisition["contract_group"],
                "resource_keys": resource_keys,
                "expected_leases": expected_leases,
                "release_receipt": release_receipt,
            }
        )
    released = [
        lease
        for group in released_groups
        for lease in group["release_receipt"]["released"]
    ]
    return (
        {
            "state": "complete",
            "snapshot_guarded": True,
            "released": released,
            "released_groups": released_groups,
            "preserved_resource_keys": preserved_keys,
        },
        True,
    )


def acquire_work(
    parameters: dict[str, Any],
    *,
    acquire_resources_fn: Callable[..., dict[str, Any]] = resources.acquire_resources,
    release_resources_fn: Callable[..., dict[str, Any]] = resources.release_resources,
    inspect_resource_fn: Callable[[str], dict[str, Any] | None] = resources.inspect_resource,
    ensure_worktree_fn: Callable[..., dict[str, Any]] = worktree_ensure.ensure_worktree,
    runner: Callable[[Path, list[str]], dict[str, Any]] = _git_runner,
    start_writer_fn: Callable[..., dict[str, Any]] = _start_scoped_writer,
    audit_fn: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    inputs = _normalize(parameters)
    writer_argv = inputs.pop("_scoped_writer_argv")
    lane_id = inputs["lane_id"]
    inputs_sha256 = _sha(inputs)
    lifecycle_source = _lifecycle_source(inputs)
    acquisition_plan = _resource_acquisition_plan(inputs["resource_keys"])
    with _lane_lock(lane_id) as receipt_path:
        existing = _read_state(receipt_path)
        if existing is not None and existing.get("inputs_sha256") != inputs_sha256:
            raise RuntimeError("work-lane identity collision")
        if existing is not None and _terminal_closeout_assessment(existing) is not None:
            return {**existing, "durable_receipt_path": str(receipt_path), "replayed": True}
        existing_writer_job = (
            existing.get("writer_job")
            if isinstance(existing, dict) and isinstance(existing.get("writer_job"), dict)
            else None
        )
        existing_writer_start = (
            existing.get("writer_start") if isinstance(existing, dict) else None
        )
        ambiguous_writer_start = (
            writer_argv is not None
            and existing is not None
            and existing_writer_job is None
            and existing.get("state") in {"writer_starting", "outcome_unknown"}
            and isinstance(existing_writer_start, dict)
            and existing_writer_start.get("state") in {"starting", "outcome_unknown"}
        )
        if ambiguous_writer_start:
            record = _write_state(
                receipt_path,
                {
                    **existing,
                    "state": "outcome_unknown",
                    "decision": "HARD_BLOCK",
                    "updated_at_unix": int(time.time()),
                    "writer_start": {
                        **existing_writer_start,
                        "state": "outcome_unknown",
                    },
                    "next_action": "readback_scoped_writer_before_retry",
                },
            )
            return {
                **record,
                "durable_receipt_path": str(receipt_path),
                "replayed": True,
            }
        if existing is not None and existing.get("state") == "outcome_unknown":
            return {
                **existing,
                "durable_receipt_path": str(receipt_path),
                "replayed": True,
            }
        if existing is not None and existing.get("state") in {
            "acquiring",
            "compensating",
        }:
            record = _write_state(
                receipt_path,
                {
                    **existing,
                    "state": "outcome_unknown",
                    "decision": "HARD_BLOCK",
                    "updated_at_unix": int(time.time()),
                    "next_action": "reconcile_resource_leases_before_retry",
                },
            )
            return {
                **record,
                "durable_receipt_path": str(receipt_path),
                "replayed": True,
            }
        attempt = int(existing.get("attempt_count", 0)) + 1 if existing else 1
        base_record = {
            "kind": LANE_KIND,
            "schema_version": SCHEMA_VERSION,
            "lane_id": lane_id,
            "inputs_sha256": inputs_sha256,
            "inputs": inputs,
            "lifecycle_source": lifecycle_source,
            "attempt_count": attempt,
            "created_at_unix": existing.get("created_at_unix", int(time.time())) if existing else int(time.time()),
            "updated_at_unix": int(time.time()),
            **(
                {"writer_job": existing_writer_job}
                if existing_writer_job is not None
                else {}
            ),
            **(
                {"writer_start": existing_writer_start}
                if isinstance(existing_writer_start, dict)
                else {}
            ),
        }
        metadata = {
            "schema_version": 1,
            "kind": LANE_KIND,
            "lane_id": lane_id,
            "controller_actor": inputs["controller"]["actor"],
            "controller_role": "controller",
            "scoped_writer_actor": (inputs["scoped_writer"] or {}).get("actor"),
            "source": inputs["source"],
            "lifecycle_source": lifecycle_source,
            "repo": inputs["repo"],
            "branch": inputs["branch"],
            "target_path": inputs["target_path"],
        }
        acquisitions: list[dict[str, Any]] = []
        for group_index, group in enumerate(acquisition_plan):
            _write_state(
                receipt_path,
                {
                    **base_record,
                    "state": "acquiring",
                    **_group_evidence_fields(acquisition_plan, acquisitions),
                    "acquisition": {
                        "state": "group_in_flight",
                        "group_index": group_index,
                        "contract_group": group["contract_group"],
                        "resource_keys": group["resource_keys"],
                        "completed_group_count": len(acquisitions),
                    },
                    "next_action": "acquire_resource_contract_group",
                },
            )
            try:
                acquisition_receipt = acquire_resources_fn(
                    inputs["lease_owner_id"],
                    group["resource_keys"],
                    purpose=inputs["purpose"],
                    ttl_seconds=inputs["ttl_seconds"],
                    metadata=metadata,
                )
                acquisition = _acquisition_evidence(
                    group,
                    acquisition_receipt,
                    owner_id=inputs["lease_owner_id"],
                )
            except Exception as exc:
                lease_receipt = (
                    _acquisition_bundle(
                        inputs["lease_owner_id"], acquisition_plan, acquisitions
                    )
                    if acquisitions
                    else None
                )
                compensation: dict[str, Any] | None = None
                compensation_complete = True
                if acquisitions:
                    assert lease_receipt is not None
                    compensation, compensation_complete = _compensate_acquisitions(
                        owner_id=inputs["lease_owner_id"],
                        plan=acquisition_plan,
                        acquisitions=acquisitions,
                        release_resources_fn=release_resources_fn,
                        receipt_path=receipt_path,
                        base_record=base_record,
                        lease_receipt=lease_receipt,
                    )
                definite_failure = _definite_acquisition_failure(exc)
                state = (
                    "blocked"
                    if definite_failure and compensation_complete
                    else "outcome_unknown"
                )
                failure_evidence = {
                    "state": (
                        "failed" if definite_failure else "outcome_unknown"
                    ),
                    "group_index": group_index,
                    "contract_group": group["contract_group"],
                    "resource_keys": group["resource_keys"],
                    "completed_group_count": len(acquisitions),
                }
                record = _write_state(
                    receipt_path,
                    {
                        **base_record,
                        "state": state,
                        "decision": "HARD_BLOCK",
                        **(
                            {"lease_receipt": lease_receipt}
                            if lease_receipt is not None
                            else {}
                        ),
                        **_group_evidence_fields(acquisition_plan, acquisitions),
                        "acquisition": failure_evidence,
                        "error_class": type(exc).__name__,
                        "error": str(exc)[:2048],
                        "leases_acquired": (
                            False
                            if definite_failure and compensation_complete
                            else None
                        ),
                        "compensation": compensation,
                        **(
                            {
                                "next_action": (
                                    "reconcile_lease_compensation_before_retry"
                                    if not compensation_complete
                                    else "retry_after_resource_conflict_changes"
                                    if definite_failure
                                    else "reconcile_resource_acquisition_before_retry"
                                )
                            }
                            if state == "outcome_unknown"
                            else {}
                        ),
                    },
                )
                if audit_fn is not None:
                    audit_fn(
                        {
                            "operation": "work-acquire",
                            "lane_id": lane_id,
                            "state": state,
                            "inputs_sha256": inputs_sha256,
                        }
                    )
                return {
                    **record,
                    "durable_receipt_path": str(receipt_path),
                    "replayed": existing is not None,
                }
            acquisitions.append(acquisition)
            acquired_so_far = _acquisition_bundle(
                inputs["lease_owner_id"], acquisition_plan, acquisitions
            )
            _write_state(
                receipt_path,
                {
                    **base_record,
                    "state": "acquiring",
                    "lease_receipt": acquired_so_far,
                    **_group_evidence_fields(acquisition_plan, acquisitions),
                    "acquisition": {
                        "state": "group_acquired",
                        "group_index": group_index,
                        "contract_group": group["contract_group"],
                        "resource_keys": group["resource_keys"],
                        "completed_group_count": len(acquisitions),
                    },
                    "next_action": (
                        "acquire_resource_contract_group"
                        if len(acquisitions) < len(acquisition_plan)
                        else "ensure_worktree"
                    ),
                },
            )
        acquired = _acquisition_bundle(
            inputs["lease_owner_id"], acquisition_plan, acquisitions
        )
        group_evidence = _group_evidence_fields(acquisition_plan, acquisitions)

        ensure_parameters = {
            "repo": inputs["repo"],
            "target_path": inputs["target_path"],
            "branch": inputs["branch"],
            "base_head": inputs["base_head"],
            "lease_owner_id": inputs["lease_owner_id"],
            "purpose": inputs["purpose"],
            "source_kind": lifecycle_source["kind"],
            "source_id": lifecycle_source["id"],
            "artifact_class": inputs["artifact_class"],
            "retention_until_unix": inputs["retention_until_unix"],
            "idempotency_key": f"work-acquire:{lane_id}",
            "system_convergence": inputs["system_convergence"],
            "system_convergence_plan_sha256": inputs["system_convergence_plan"][
                "plan_sha256"
            ],
            "reposkop_required": True,
        }
        try:
            output = ensure_worktree_fn(
                ensure_parameters,
                runner,
                inspect_resource_fn,
            )
        except worktree_ensure.WorktreeEnsurePreflight as exc:
            compensation, compensation_complete = _compensate_acquisitions(
                owner_id=inputs["lease_owner_id"],
                plan=acquisition_plan,
                acquisitions=acquisitions,
                release_resources_fn=release_resources_fn,
                receipt_path=receipt_path,
                base_record=base_record,
                lease_receipt=acquired,
            )
            record = _write_state(
                receipt_path,
                {
                    **base_record,
                    "state": "blocked" if compensation_complete else "outcome_unknown",
                    "decision": (
                        "AUTO_PREPARE_FAILED"
                        if compensation_complete
                        else "HARD_BLOCK"
                    ),
                    "lease_receipt": acquired,
                    **group_evidence,
                    "error_class": type(exc).__name__,
                    "error": str(exc)[:2048],
                    "effect_observed": False,
                    "compensation": compensation,
                    **(
                        {
                            "next_action": "reconcile_lease_compensation_before_retry"
                        }
                        if not compensation_complete
                        else {}
                    ),
                },
            )
            if audit_fn is not None:
                audit_fn({
                    "operation": "work-acquire",
                    "lane_id": lane_id,
                    "state": record["state"],
                    "inputs_sha256": inputs_sha256,
                    "effect_observed": False,
                })
            return {**record, "durable_receipt_path": str(receipt_path), "replayed": existing is not None}
        except Exception as exc:
            record = _write_state(
                receipt_path,
                {
                    **base_record,
                    "state": "outcome_unknown",
                    "decision": "HARD_BLOCK",
                    "lease_receipt": acquired,
                    **group_evidence,
                    "error_class": type(exc).__name__,
                    "error": str(exc)[:2048],
                    "effect_observed": None,
                    "compensation": None,
                },
            )
            if audit_fn is not None:
                audit_fn({
                    "operation": "work-acquire",
                    "lane_id": lane_id,
                    "state": "outcome_unknown",
                    "inputs_sha256": inputs_sha256,
                    "effect_observed": None,
                })
            return {**record, "durable_receipt_path": str(receipt_path), "replayed": existing is not None}
        if not isinstance(output, dict):
            record = _write_state(
                receipt_path,
                {
                    **base_record,
                    "state": "outcome_unknown",
                    "decision": "HARD_BLOCK",
                    "lease_receipt": acquired,
                    **group_evidence,
                    "error_class": "InvalidWorktreeEnsureResult",
                    "error": "worktree ensure returned a non-object result",
                    "effect_observed": None,
                    "compensation": None,
                },
            )
            if audit_fn is not None:
                audit_fn({
                    "operation": "work-acquire",
                    "lane_id": lane_id,
                    "state": "outcome_unknown",
                    "inputs_sha256": inputs_sha256,
                    "effect_observed": None,
                })
            return {**record, "durable_receipt_path": str(receipt_path), "replayed": existing is not None}
        result_state = output.get("result_state")
        if result_state in SUCCESS_STATES:
            admission = output.get("work_admission")
            decision = (
                "ISOLATE_AND_EXECUTE"
                if work_admission.has_verified_isolation_evidence(admission)
                else "AUTO_PREPARE_AND_EXECUTE"
                if result_state == "CREATED"
                else "EXECUTE"
            )
            authority = {
                "controller": inputs["controller"],
                "scoped_writer": inputs["scoped_writer"],
                "source": inputs["source"],
                "lifecycle_source": lifecycle_source,
                "writer_effects": [
                    "implement",
                    "test",
                    "commit",
                    "push",
                    "pull-request-create-or-update",
                ],
                "controller_only_effects": [
                    "merge",
                    "deployment",
                    "bureau-terminalization",
                    "closeout",
                ],
                "single_writer_scope": "overlapping-resource-lane",
            }
            writer_job = existing_writer_job
            writer_start: dict[str, Any] | None = None
            if writer_job is not None:
                writer_start = {
                    "state": "reused",
                    "job_receipt_sha256": writer_job.get("receipt_sha256"),
                }
            elif writer_argv is not None:
                _write_state(
                    receipt_path,
                    {
                        **base_record,
                        "state": "writer_starting",
                        "decision": decision,
                        "lease_receipt": acquired,
                        **group_evidence,
                        "worktree_receipt": output,
                        "authority": authority,
                        "writer_start": {"state": "starting"},
                        "next_action": "start_scoped_writer",
                    },
                )
                try:
                    writer_result = start_writer_fn(
                        writer_argv,
                        cwd=inputs["target_path"],
                        runtime_seconds=inputs["scoped_writer_command"][
                            "runtime_seconds"
                        ],
                    )
                except ScopedWriterStartPreflight as exc:
                    record = _write_state(
                        receipt_path,
                        {
                            **base_record,
                            "state": "ready",
                            "decision": decision,
                            "lease_receipt": acquired,
                            **group_evidence,
                            "worktree_receipt": output,
                            "authority": authority,
                            "writer_start": {
                                "state": "preflight_failed",
                                "error_class": type(exc).__name__,
                                "error": str(exc)[:2048],
                            },
                            "next_action": "controller_execute",
                        },
                    )
                    return {
                        **record,
                        "durable_receipt_path": str(receipt_path),
                        "replayed": existing is not None,
                    }
                except Exception as exc:
                    record = _write_state(
                        receipt_path,
                        {
                            **base_record,
                            "state": "outcome_unknown",
                            "decision": "HARD_BLOCK",
                            "lease_receipt": acquired,
                            **group_evidence,
                            "worktree_receipt": output,
                            "authority": authority,
                            "writer_start": {
                                "state": "outcome_unknown",
                                "error_class": type(exc).__name__,
                                "error": str(exc)[:2048],
                            },
                            "next_action": "readback_scoped_writer_before_retry",
                        },
                    )
                    return {
                        **record,
                        "durable_receipt_path": str(receipt_path),
                        "replayed": existing is not None,
                    }
                if not isinstance(writer_result, dict):
                    record = _write_state(
                        receipt_path,
                        {
                            **base_record,
                            "state": "outcome_unknown",
                            "decision": "HARD_BLOCK",
                            "lease_receipt": acquired,
                            **group_evidence,
                            "worktree_receipt": output,
                            "authority": authority,
                            "writer_start": {
                                "state": "outcome_unknown",
                                "error_class": "InvalidScopedWriterStartResult",
                                "error": "scoped writer start returned a non-object result",
                            },
                            "next_action": "readback_scoped_writer_before_retry",
                        },
                    )
                    return {
                        **record,
                        "durable_receipt_path": str(receipt_path),
                        "replayed": existing is not None,
                    }
                try:
                    writer_job = _writer_job_receipt(writer_result)
                except Exception as exc:
                    record = _write_state(
                        receipt_path,
                        {
                            **base_record,
                            "state": "outcome_unknown",
                            "decision": "HARD_BLOCK",
                            "lease_receipt": acquired,
                            **group_evidence,
                            "worktree_receipt": output,
                            "authority": authority,
                            "writer_start": {
                                "state": "outcome_unknown",
                                "error_class": type(exc).__name__,
                                "error": str(exc)[:2048],
                            },
                            "next_action": "readback_scoped_writer_before_retry",
                        },
                    )
                    return {
                        **record,
                        "durable_receipt_path": str(receipt_path),
                        "replayed": existing is not None,
                    }
                writer_start = {
                    "state": "started",
                    "job_receipt_sha256": writer_job["receipt_sha256"],
                }
            record = _write_state(
                receipt_path,
                {
                    **base_record,
                    "state": "ready",
                    "decision": decision,
                    "lease_receipt": acquired,
                    **group_evidence,
                    "worktree_receipt": output,
                    "authority": authority,
                    **({"writer_job": writer_job} if writer_job is not None else {}),
                    **({"writer_start": writer_start} if writer_start is not None else {}),
                    "next_action": (
                        "writer_started"
                        if writer_job is not None
                        else "start_scoped_writer"
                        if inputs["scoped_writer"]
                        else "controller_execute"
                    ),
                },
            )
            if audit_fn is not None:
                audit_fn({"operation": "work-acquire", "lane_id": lane_id, "state": "ready", "decision": decision, "inputs_sha256": inputs_sha256, "worktree_receipt_sha256": output.get("durable_receipt_sha256")})
            return {**record, "durable_receipt_path": str(receipt_path), "replayed": existing is not None}

        mutation_attempted = isinstance(output.get("mutation"), dict)
        effect_observed = mutation_attempted and _effect_observed(output)
        compensation: dict[str, Any] | None = None
        compensation_complete = True
        if not effect_observed:
            compensation, compensation_complete = _compensate_acquisitions(
                owner_id=inputs["lease_owner_id"],
                plan=acquisition_plan,
                acquisitions=acquisitions,
                release_resources_fn=release_resources_fn,
                receipt_path=receipt_path,
                base_record=base_record,
                lease_receipt=acquired,
            )
        outcome_unknown = effect_observed or not compensation_complete
        record = _write_state(
            receipt_path,
            {
                **base_record,
                "state": "outcome_unknown" if outcome_unknown else "blocked",
                "decision": "HARD_BLOCK" if outcome_unknown else "AUTO_PREPARE_FAILED",
                "lease_receipt": acquired,
                **group_evidence,
                "worktree_receipt": output,
                "mutation_attempted": mutation_attempted,
                "effect_observed": effect_observed,
                "compensation": compensation,
                **(
                    {"next_action": "reconcile_lease_compensation_before_retry"}
                    if not effect_observed and not compensation_complete
                    else {}
                ),
            },
        )
        if audit_fn is not None:
            audit_fn({"operation": "work-acquire", "lane_id": lane_id, "state": record["state"], "inputs_sha256": inputs_sha256, "effect_observed": effect_observed})
        return {**record, "durable_receipt_path": str(receipt_path), "replayed": existing is not None}


@mcp.tool(name="grabowski_work_acquire", annotations=MUTATING)
def grabowski_work_acquire(
    source_kind: str,
    source_id: str,
    controller_actor: str,
    repo: str,
    base_head: str,
    branch: str,
    target_path: str,
    purpose: str,
    retention_until_unix: int,
    idempotency_key: str,
    resource_keys: list[str] | None = None,
    write_paths: list[str] | None = None,
    scoped_writer_actor: str | None = None,
    scoped_writer_argv: list[str] | None = None,
    scoped_writer_runtime_seconds: int = 7200,
    system_convergence: dict[str, Any] | None = None,
    artifact_class: str = "implementation-worktree",
    ttl_seconds: int = 7200,
    terminal_closeout: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Acquire a work lane, or persist its evidence-bound terminal closeout."""
    parameters = {
        "source_kind": source_kind,
        "source_id": source_id,
        "controller_actor": controller_actor,
        "controller_role": "controller",
        "scoped_writer_actor": scoped_writer_actor,
        "repo": repo,
        "base_head": base_head,
        "branch": branch,
        "target_path": target_path,
        "purpose": purpose,
        "retention_until_unix": retention_until_unix,
        "idempotency_key": idempotency_key,
        "resource_keys": resource_keys or [],
        "write_paths": write_paths,
        "scoped_writer_argv": scoped_writer_argv,
        "scoped_writer_runtime_seconds": scoped_writer_runtime_seconds,
        "system_convergence": system_convergence,
        "artifact_class": artifact_class,
        "ttl_seconds": ttl_seconds,
    }
    if terminal_closeout is not None:
        if not isinstance(terminal_closeout, dict) or set(terminal_closeout) != {
            "expected_receipt_sha256",
            "observation",
        }:
            raise ValueError(
                "terminal_closeout must contain exactly expected_receipt_sha256 and observation"
            )
        observation = terminal_closeout["observation"]
        if not isinstance(observation, dict):
            raise ValueError("terminal_closeout.observation must be an object")
        try:
            observed = lane_closeout.LaneCloseoutObservation(**observation)
        except TypeError as exc:
            raise ValueError(f"terminal_closeout observation shape is invalid: {exc}") from exc
        inputs = _closeout_inputs(parameters, observed.lane_id)
        operator._require_operator_mutation(
            "resource_lease", path=inputs["target_path"], repo=inputs["repo"]
        )
        expected_observation_identity = {
            "repository": inputs["repo"],
            "workspace": inputs["target_path"],
            "branch": inputs["branch"],
            "base_revision": inputs["base_head"],
        }
        observed_identity = {
            field: getattr(observed, field) for field in expected_observation_identity
        }
        if observed_identity != expected_observation_identity:
            raise RuntimeError(
                "terminal closeout observation identity does not match work lane inputs"
            )
        assessment = lane_closeout.assess(observed)
        if assessment.get("lane_id") != inputs["lane_id"]:
            raise RuntimeError("terminal closeout observation is bound to another lane")
        if assessment.get("phase") != "terminal":
            return {
                "status": "nonterminal",
                "persisted": False,
                "lane_id": inputs["lane_id"],
                "assessment": assessment,
            }
        return persist_terminal_closeout(
            inputs["lane_id"],
            assessment,
            expected_receipt_sha256=terminal_closeout["expected_receipt_sha256"],
            audit_fn=operator.base._append_audit_with_digest,
            audit_lookup_fn=_find_terminal_closeout_audit,
        )
    operator._require_operator_mutation("resource_lease", path=target_path, repo=repo)
    operator._require_operator_capability("git_cli")
    if scoped_writer_argv is not None:
        operator._require_operator_mutation(
            "durable_job",
            path=target_path,
            repo=repo,
            opaque_command=True,
        )
    return acquire_work(parameters, audit_fn=operator.base._append_audit)

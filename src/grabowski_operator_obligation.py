from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Iterator

import grabowski_private_io as private_io


SCHEMA_VERSION = 1
OPEN_KIND = "grabowski.operator_obligation"
CLOSE_KIND = "grabowski.operator_obligation_close"
OBLIGATION_ID_RE = re.compile(r"^goo-[a-z0-9][a-z0-9-]{7,79}$")
ACCEPTANCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
CODE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_RECORD_BYTES = 256 * 1024
MAX_ACCEPTANCE = 64
MAX_REFERENCES = 32
MAX_EVIDENCE = 128
MAX_BLOCKERS = 32
MAX_LIST_LIMIT = 100
MAX_LIST_SCAN = 1_000
MAX_TEXT = 4_096
LOCK_TIMEOUT_SECONDS = 5.0
LOCK_POLL_SECONDS = 0.02
TERMINAL_OUTCOMES = frozenset({"completed", "blocked", "delegated"})
EVIDENCE_STATUSES = frozenset({"passed", "failed", "partial", "not_run", "unknown"})
EVIDENCE_SOURCES = frozenset(
    {
        "receipt",
        "test",
        "git",
        "github",
        "runtime",
        "bureau",
        "workspace",
        "job",
        "user",
    }
)
REFERENCE_KINDS = frozenset(
    {"grabowski_task", "agent_workspace", "systemd_job", "bureau_task", "pull_request", "runtime"}
)
DELEGATION_TOOLS = {
    "grabowski_task": "grabowski_task_status",
    "agent_workspace": "grabowski_agent_workspace_status",
    "systemd_job": "grabowski_job_status",
}
DELEGATION_STATUSES = frozenset({"launch_submitted", "launching", "running"})


class OperatorObligationError(RuntimeError):
    pass


class OperatorObligationInputError(ValueError):
    pass


class OperatorObligationConflictError(OperatorObligationError):
    pass


class OperatorObligationIntegrityError(OperatorObligationError):
    pass


def _state_root() -> Path:
    configured = os.environ.get("GRABOWSKI_OPERATOR_OBLIGATION_ROOT")
    root = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".local" / "state" / "grabowski" / "operator-obligations"
    )
    if not root.is_absolute():
        raise OperatorObligationIntegrityError("operator obligation root must be absolute")
    return root


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_timestamp(value: Any, *, label: str) -> str:
    text = _validate_text(value, label=label, maximum=128)
    if not text.endswith("Z"):
        raise OperatorObligationInputError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise OperatorObligationInputError(f"{label} must be a canonical UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise OperatorObligationInputError(f"{label} must be a canonical UTC timestamp")
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if canonical != text:
        raise OperatorObligationInputError(f"{label} must be a canonical UTC timestamp")
    return text


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_text(value: Any, *, label: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperatorObligationInputError(f"{label} must be a non-empty string")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > maximum:
        raise OperatorObligationInputError(f"{label} exceeds the size bound")
    return normalized


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise OperatorObligationInputError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_obligation_id(value: Any) -> str:
    if not isinstance(value, str) or OBLIGATION_ID_RE.fullmatch(value) is None:
        raise OperatorObligationInputError("obligation_id must match goo-[a-z0-9-]")
    return value


def _validate_exact_keys(value: dict[str, Any], *, allowed: set[str], required: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise OperatorObligationInputError(f"{label} contains unknown keys: {unknown}")
    if missing:
        raise OperatorObligationInputError(f"{label} is missing keys: {missing}")


def _normalize_acceptance(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > MAX_ACCEPTANCE:
        raise OperatorObligationInputError("acceptance must be a non-empty bounded list")
    normalized: list[dict[str, str]] = []
    identifiers: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise OperatorObligationInputError(f"acceptance[{index}] must be an object")
        _validate_exact_keys(
            item,
            allowed={"id", "description"},
            required={"id", "description"},
            label=f"acceptance[{index}]",
        )
        identifier = item["id"]
        if not isinstance(identifier, str) or ACCEPTANCE_ID_RE.fullmatch(identifier) is None:
            raise OperatorObligationInputError(f"acceptance[{index}].id is invalid")
        if identifier in identifiers:
            raise OperatorObligationInputError(f"duplicate acceptance id: {identifier}")
        identifiers.add(identifier)
        normalized.append(
            {
                "id": identifier,
                "description": _validate_text(item["description"], label=f"acceptance[{index}].description"),
            }
        )
    return normalized


def _normalize_origin(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise OperatorObligationInputError("origin must be an object")
    allowed = {"thread_id", "source", "repo", "task_id"}
    _validate_exact_keys(value, allowed=allowed, required=set(), label="origin")
    return {
        key: _validate_text(raw, label=f"origin.{key}", maximum=1_024)
        for key, raw in sorted(value.items())
    }


def _normalize_references(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_REFERENCES:
        raise OperatorObligationInputError("references must be a bounded list")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise OperatorObligationInputError(f"references[{index}] must be an object")
        _validate_exact_keys(
            item,
            allowed={"kind", "id", "observation_tool"},
            required={"kind", "id", "observation_tool"},
            label=f"references[{index}]",
        )
        kind = item["kind"]
        if not isinstance(kind, str) or kind not in REFERENCE_KINDS:
            raise OperatorObligationInputError(f"references[{index}].kind is unsupported")
        identifier = _validate_text(item["id"], label=f"references[{index}].id", maximum=1_024)
        key = (kind, identifier)
        if key in seen:
            raise OperatorObligationInputError(f"duplicate reference: {kind}:{identifier}")
        seen.add(key)
        normalized.append(
            {
                "kind": kind,
                "id": identifier,
                "observation_tool": _validate_text(
                    item["observation_tool"],
                    label=f"references[{index}].observation_tool",
                    maximum=256,
                ),
            }
        )
    return normalized


def _normalize_evidence(value: Any, *, acceptance_ids: set[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE:
        raise OperatorObligationInputError("evidence must be a bounded list")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise OperatorObligationInputError(f"evidence[{index}] must be an object")
        _validate_exact_keys(
            item,
            allowed={"acceptance_id", "status", "source", "reference", "sha256"},
            required={"acceptance_id", "status", "source", "reference"},
            label=f"evidence[{index}]",
        )
        acceptance_id = item["acceptance_id"]
        if not isinstance(acceptance_id, str) or acceptance_id not in acceptance_ids:
            raise OperatorObligationInputError(f"evidence[{index}] references unknown acceptance id")
        if acceptance_id in seen:
            raise OperatorObligationInputError(f"duplicate evidence for acceptance id: {acceptance_id}")
        seen.add(acceptance_id)
        status_value = item["status"]
        source = item["source"]
        if not isinstance(status_value, str) or status_value not in EVIDENCE_STATUSES:
            raise OperatorObligationInputError(f"evidence[{index}].status is unsupported")
        if not isinstance(source, str) or source not in EVIDENCE_SOURCES:
            raise OperatorObligationInputError(f"evidence[{index}].source is unsupported")
        entry: dict[str, Any] = {
            "acceptance_id": acceptance_id,
            "status": status_value,
            "source": source,
            "reference": _validate_text(item["reference"], label=f"evidence[{index}].reference", maximum=2_048),
        }
        if "sha256" in item:
            entry["sha256"] = _validate_sha256(item["sha256"], label=f"evidence[{index}].sha256")
        normalized.append(entry)
    return sorted(normalized, key=lambda item: item["acceptance_id"])


def _normalize_blockers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > MAX_BLOCKERS:
        raise OperatorObligationInputError("blocked outcome requires a non-empty bounded blockers list")
    normalized: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise OperatorObligationInputError(f"blockers[{index}] must be an object")
        _validate_exact_keys(
            item,
            allowed={"code", "detail", "reference", "sha256"},
            required={"code", "detail", "reference", "sha256"},
            label=f"blockers[{index}]",
        )
        code = item["code"]
        if not isinstance(code, str) or CODE_RE.fullmatch(code) is None:
            raise OperatorObligationInputError(f"blockers[{index}].code is invalid")
        normalized.append(
            {
                "code": code,
                "detail": _validate_text(item["detail"], label=f"blockers[{index}].detail"),
                "reference": _validate_text(item["reference"], label=f"blockers[{index}].reference", maximum=2_048),
                "sha256": _validate_sha256(item["sha256"], label=f"blockers[{index}].sha256"),
            }
        )
    return normalized


def _normalize_delegation(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise OperatorObligationInputError("delegated outcome requires a delegation object")
    fields = {
        "kind",
        "id",
        "observation_tool",
        "status",
        "observed_at",
        "identity_sha256",
        "observation_receipt_sha256",
    }
    _validate_exact_keys(
        value,
        allowed=fields,
        required=fields,
        label="delegation",
    )
    kind = value["kind"]
    if not isinstance(kind, str) or kind not in DELEGATION_TOOLS:
        raise OperatorObligationInputError("delegation.kind is unsupported")
    identifier = _validate_text(value["id"], label="delegation.id", maximum=1_024)
    observation_tool = _validate_text(
        value["observation_tool"],
        label="delegation.observation_tool",
        maximum=256,
    )
    if observation_tool != DELEGATION_TOOLS[kind]:
        raise OperatorObligationInputError("delegation.observation_tool does not match kind")
    status_value = value["status"]
    if not isinstance(status_value, str) or status_value not in DELEGATION_STATUSES:
        raise OperatorObligationInputError("delegation.status is not a live continuation state")
    observed_at = _validate_timestamp(value["observed_at"], label="delegation.observed_at")
    identity_sha256 = _validate_sha256(
        value["identity_sha256"], label="delegation.identity_sha256"
    )
    material = {
        "kind": kind,
        "id": identifier,
        "observation_tool": observation_tool,
        "status": status_value,
        "observed_at": observed_at,
        "identity_sha256": identity_sha256,
    }
    receipt_sha256 = _validate_sha256(
        value["observation_receipt_sha256"],
        label="delegation.observation_receipt_sha256",
    )
    if receipt_sha256 != _sha256(material):
        raise OperatorObligationInputError("delegation observation receipt binding is invalid")
    return {**material, "observation_receipt_sha256": receipt_sha256}


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
        raise OperatorObligationIntegrityError(f"unsafe private directory: {path}")


def _record_path(obligation_id: str, name: str) -> Path:
    return _state_root() / obligation_id / name


def _read_private_json(path: Path) -> tuple[dict[str, Any], str]:
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
            raise OperatorObligationIntegrityError(f"unsafe obligation record: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise OperatorObligationIntegrityError(f"short obligation record read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise OperatorObligationIntegrityError(f"obligation record changed during read: {path}")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorObligationIntegrityError(f"invalid obligation JSON: {path}") from exc
    if not isinstance(value, dict):
        raise OperatorObligationIntegrityError(f"obligation record is not an object: {path}")
    return value, hashlib.sha256(raw).hexdigest()


@contextmanager
def _state_lock() -> Iterator[None]:
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
            raise OperatorObligationIntegrityError("operator obligation lock is unsafe")
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OperatorObligationError("operator obligation lock timed out")
                time.sleep(LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_open_record(record: dict[str, Any], *, expected_id: str) -> None:
    required = {
        "kind",
        "schema_version",
        "obligation_id",
        "objective",
        "acceptance",
        "origin",
        "references",
        "created_at",
        "material_sha256",
        "record_sha256",
    }
    if set(record) != required:
        raise OperatorObligationIntegrityError("operator obligation open record shape is invalid")
    material = {
        key: record[key]
        for key in required - {"created_at", "material_sha256", "record_sha256"}
    }
    record_material = {key: record[key] for key in required - {"record_sha256"}}
    if (
        record["kind"] != OPEN_KIND
        or record["schema_version"] != SCHEMA_VERSION
        or record["obligation_id"] != expected_id
        or record["material_sha256"] != _sha256(material)
        or record["record_sha256"] != _sha256(record_material)
    ):
        raise OperatorObligationIntegrityError("operator obligation open binding is invalid")
    try:
        _validate_timestamp(record["created_at"], label="open.created_at")
        _normalize_acceptance(record["acceptance"])
        _normalize_origin(record["origin"])
        _normalize_references(record["references"])
    except OperatorObligationInputError as exc:
        raise OperatorObligationIntegrityError("operator obligation open record semantics are invalid") from exc


def _validate_close_record(record: dict[str, Any], *, open_record: dict[str, Any], open_file_sha256: str) -> None:
    required = {
        "kind",
        "schema_version",
        "obligation_id",
        "open_file_sha256",
        "outcome",
        "evidence",
        "blockers",
        "delegation",
        "next_action",
        "closed_at",
        "material_sha256",
        "record_sha256",
    }
    if set(record) != required:
        raise OperatorObligationIntegrityError("operator obligation close record shape is invalid")
    material = {
        key: record[key]
        for key in required - {"closed_at", "material_sha256", "record_sha256"}
    }
    record_material = {key: record[key] for key in required - {"record_sha256"}}
    if (
        record["kind"] != CLOSE_KIND
        or record["schema_version"] != SCHEMA_VERSION
        or record["obligation_id"] != open_record["obligation_id"]
        or record["open_file_sha256"] != open_file_sha256
        or not isinstance(record["outcome"], str)
        or record["outcome"] not in TERMINAL_OUTCOMES
        or record["material_sha256"] != _sha256(material)
        or record["record_sha256"] != _sha256(record_material)
    ):
        raise OperatorObligationIntegrityError("operator obligation close binding is invalid")
    try:
        _validate_timestamp(record["closed_at"], label="close.closed_at")
        acceptance_ids = {item["id"] for item in open_record["acceptance"]}
        evidence = _normalize_evidence(record["evidence"], acceptance_ids=acceptance_ids)
        outcome = record["outcome"]
        if outcome == "completed":
            passed = {item["acceptance_id"] for item in evidence if item["status"] == "passed"}
            if passed != acceptance_ids or len(evidence) != len(acceptance_ids):
                raise OperatorObligationInputError("completed close does not cover all acceptance criteria")
            if any("sha256" not in item for item in evidence):
                raise OperatorObligationInputError("completed close evidence must be SHA-256 bound")
            if record["blockers"] or record["delegation"] or record["next_action"]:
                raise OperatorObligationInputError("completed close contains incompatible continuation fields")
        elif outcome == "blocked":
            _normalize_blockers(record["blockers"])
            if record["delegation"]:
                raise OperatorObligationInputError("blocked close contains delegation")
            _validate_text(record["next_action"], label="close.next_action")
        elif outcome == "delegated":
            _normalize_delegation(record["delegation"])
            if record["blockers"]:
                raise OperatorObligationInputError("delegated close contains blockers")
            _validate_text(record["next_action"], label="close.next_action")
    except OperatorObligationInputError as exc:
        raise OperatorObligationIntegrityError("operator obligation close record semantics are invalid") from exc


def open_obligation(parameters: dict[str, Any]) -> dict[str, Any]:
    allowed = {"obligation_id", "objective", "acceptance", "origin", "references"}
    _validate_exact_keys(parameters, allowed=allowed, required={"obligation_id", "objective", "acceptance"}, label="open parameters")
    obligation_id = _validate_obligation_id(parameters["obligation_id"])
    material = {
        "kind": OPEN_KIND,
        "schema_version": SCHEMA_VERSION,
        "obligation_id": obligation_id,
        "objective": _validate_text(parameters["objective"], label="objective"),
        "acceptance": _normalize_acceptance(parameters["acceptance"]),
        "origin": _normalize_origin(parameters.get("origin")),
        "references": _normalize_references(parameters.get("references")),
    }
    material_sha256 = _sha256(material)
    directory = _state_root() / obligation_id
    target = directory / "open.json"
    with _state_lock():
        _ensure_private_directory(directory, create=True)
        payload = {**material, "created_at": _utc_now(), "material_sha256": material_sha256}
        payload["record_sha256"] = _sha256(payload)
        try:
            created = private_io.publish_private_create_only_json(
                directory,
                target,
                payload,
                max_bytes=MAX_RECORD_BYTES,
                label="operator obligation open record",
            )
        except FileNotFoundError as exc:
            raise OperatorObligationIntegrityError("operator obligation directory disappeared") from exc
        winner, file_sha256 = _read_private_json(target)
        _validate_open_record(winner, expected_id=obligation_id)
        if winner["material_sha256"] != material_sha256:
            raise OperatorObligationConflictError("operator obligation id is already bound to different work")
    status = status_obligation(obligation_id)
    return {
        **status,
        "created": created,
        "replayed": not created,
        "material_sha256": material_sha256,
        "open_file_sha256": file_sha256,
    }


def status_obligation(obligation_id: str) -> dict[str, Any]:
    obligation_id = _validate_obligation_id(obligation_id)
    root = _state_root()
    directory = root / obligation_id
    _ensure_private_directory(root, create=False)
    _ensure_private_directory(directory, create=False)
    open_record, open_file_sha256 = _read_private_json(directory / "open.json")
    _validate_open_record(open_record, expected_id=obligation_id)
    close_path = directory / "close.json"
    try:
        close_record, close_file_sha256 = _read_private_json(close_path)
    except FileNotFoundError:
        acceptance_ids = [item["id"] for item in open_record["acceptance"]]
        return {
            "obligation_id": obligation_id,
            "state": "open",
            "objective": open_record["objective"],
            "origin": open_record["origin"],
            "references": open_record["references"],
            "created_at": open_record["created_at"],
            "closed_at": None,
            "acceptance_ids": acceptance_ids,
            "evidence": [],
            "missing_acceptance_ids": acceptance_ids,
            "continuation_required": True,
            "response_may_end": False,
            "work_complete": False,
            "open_file_sha256": open_file_sha256,
            "close_file_sha256": None,
            "recommended_next_action": "continue work; the chat response must not imply completion",
        }
    _validate_close_record(close_record, open_record=open_record, open_file_sha256=open_file_sha256)
    evidence_by_id = {item["acceptance_id"]: item for item in close_record["evidence"]}
    missing = [item["id"] for item in open_record["acceptance"] if item["id"] not in evidence_by_id]
    outcome = close_record["outcome"]
    return {
        "obligation_id": obligation_id,
        "state": outcome,
        "objective": open_record["objective"],
        "origin": open_record["origin"],
        "references": open_record["references"],
        "created_at": open_record["created_at"],
        "closed_at": close_record["closed_at"],
        "acceptance_ids": [item["id"] for item in open_record["acceptance"]],
        "evidence": close_record["evidence"],
        "missing_acceptance_ids": missing,
        "blockers": close_record["blockers"],
        "delegation": close_record["delegation"],
        "next_action": close_record["next_action"],
        "continuation_required": False,
        "response_may_end": True,
        "work_complete": outcome == "completed",
        "open_file_sha256": open_file_sha256,
        "close_file_sha256": close_file_sha256,
        "recommended_next_action": (
            "report acceptance-bound completion"
            if outcome == "completed"
            else close_record["next_action"]
        ),
        "non_claims": (
            []
            if outcome == "completed"
            else ["terminal chat closeout does not establish that the underlying work is complete"]
        ),
    }


def list_obligations(parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    parameters = dict(parameters or {})
    _validate_exact_keys(
        parameters,
        allowed={"state", "repo", "thread_id", "limit"},
        required=set(),
        label="list parameters",
    )
    state_filter = parameters.get("state", "open")
    if not isinstance(state_filter, str) or state_filter not in TERMINAL_OUTCOMES | {"open", "all"}:
        raise OperatorObligationInputError(
            "state must be open, completed, blocked, delegated, or all"
        )
    repo_filter = parameters.get("repo")
    if repo_filter is not None:
        repo_filter = _validate_text(repo_filter, label="repo", maximum=1_024)
    thread_filter = parameters.get("thread_id")
    if thread_filter is not None:
        thread_filter = _validate_text(thread_filter, label="thread_id", maximum=1_024)
    limit = parameters.get("limit", 20)
    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or not 1 <= limit <= MAX_LIST_LIMIT
    ):
        raise OperatorObligationInputError(
            f"limit must be an integer from 1 to {MAX_LIST_LIMIT}"
        )

    root = _state_root()
    try:
        _ensure_private_directory(root, create=False)
    except FileNotFoundError:
        return {
            "state_filter": state_filter,
            "repo_filter": repo_filter,
            "thread_id_filter": thread_filter,
            "records": [],
            "record_count": 0,
            "integrity_errors": [],
            "scan_truncated": False,
            "attention_required": False,
            "recommended_next_action": "no matching operator obligation exists",
        }

    records: list[dict[str, Any]] = []
    integrity_errors: list[dict[str, str]] = []
    entries: list[Path] = []
    scan_truncated = False
    for index, child in enumerate(root.iterdir()):
        if index >= MAX_LIST_SCAN:
            scan_truncated = True
            break
        entries.append(child)
    entries.sort(key=lambda item: item.name)
    for index, child in enumerate(entries):
        if child.name == ".lock":
            continue
        if OBLIGATION_ID_RE.fullmatch(child.name) is None:
            integrity_errors.append(
                {"obligation_id": "invalid-name", "error": "unexpected state-root entry"}
            )
            continue
        try:
            status = status_obligation(child.name)
        except (OSError, OperatorObligationError, OperatorObligationInputError) as exc:
            integrity_errors.append(
                {"obligation_id": child.name, "error": type(exc).__name__}
            )
            continue
        if state_filter != "all" and status["state"] != state_filter:
            continue
        origin = status.get("origin")
        origin = origin if isinstance(origin, dict) else {}
        if repo_filter is not None and origin.get("repo") != repo_filter:
            continue
        if thread_filter is not None and origin.get("thread_id") != thread_filter:
            continue
        records.append(
            {
                "obligation_id": status["obligation_id"],
                "state": status["state"],
                "objective": status["objective"],
                "origin": origin,
                "created_at": status["created_at"],
                "closed_at": status["closed_at"],
                "continuation_required": status["continuation_required"],
                "response_may_end": status["response_may_end"],
                "work_complete": status["work_complete"],
                "recommended_next_action": status["recommended_next_action"],
            }
        )
        if len(records) >= limit:
            scan_truncated = any(
                remaining.name != ".lock"
                for remaining in entries[index + 1 :]
            ) or scan_truncated
            break

    attention_required = bool(
        integrity_errors
        or scan_truncated
        or any(item["continuation_required"] for item in records)
    )
    if integrity_errors:
        next_action = "inspect integrity errors before relying on the affected obligations"
    elif any(item["continuation_required"] for item in records):
        next_action = "resume the matching open obligation before starting unrelated work"
    elif scan_truncated:
        next_action = "narrow the filters and list again"
    else:
        next_action = "no matching open obligation requires continuation"
    return {
        "state_filter": state_filter,
        "repo_filter": repo_filter,
        "thread_id_filter": thread_filter,
        "records": records,
        "record_count": len(records),
        "integrity_errors": integrity_errors,
        "scan_truncated": scan_truncated,
        "attention_required": attention_required,
        "recommended_next_action": next_action,
        "non_claims": [
            "listing does not live-observe delegated tasks, workspaces, jobs, pull requests, or runtimes",
            "a terminal delegated or blocked record does not establish completed work",
        ],
    }


def close_obligation(parameters: dict[str, Any]) -> dict[str, Any]:
    allowed = {"obligation_id", "outcome", "evidence", "blockers", "delegation", "next_action"}
    _validate_exact_keys(
        parameters,
        allowed=allowed,
        required={"obligation_id", "outcome", "evidence"},
        label="close parameters",
    )
    obligation_id = _validate_obligation_id(parameters["obligation_id"])
    outcome = parameters["outcome"]
    if not isinstance(outcome, str) or outcome not in TERMINAL_OUTCOMES:
        raise OperatorObligationInputError("outcome must be completed, blocked, or delegated")
    directory = _state_root() / obligation_id
    with _state_lock():
        _ensure_private_directory(directory, create=False)
        open_record, open_file_sha256 = _read_private_json(directory / "open.json")
        _validate_open_record(open_record, expected_id=obligation_id)
        acceptance_ids = {item["id"] for item in open_record["acceptance"]}
        evidence = _normalize_evidence(parameters["evidence"], acceptance_ids=acceptance_ids)
        blockers: list[dict[str, str]] = []
        delegation: dict[str, str] = {}
        next_action = ""
        if outcome == "completed":
            passed = {item["acceptance_id"] for item in evidence if item["status"] == "passed"}
            if passed != acceptance_ids or len(evidence) != len(acceptance_ids):
                missing = sorted(acceptance_ids - passed)
                raise OperatorObligationInputError(
                    f"completed outcome requires passed evidence for every acceptance id; missing={missing}"
                )
            if any("sha256" not in item for item in evidence):
                raise OperatorObligationInputError("completed outcome evidence must be SHA-256 bound")
            if any(key in parameters for key in ("blockers", "delegation", "next_action")):
                raise OperatorObligationInputError("completed outcome may not contain continuation fields")
        elif outcome == "blocked":
            blockers = _normalize_blockers(parameters.get("blockers"))
            next_action = _validate_text(parameters.get("next_action"), label="next_action")
            if "delegation" in parameters:
                raise OperatorObligationInputError("blocked outcome may not contain delegation")
        else:
            delegation = _normalize_delegation(parameters.get("delegation"))
            next_action = _validate_text(parameters.get("next_action"), label="next_action")
            if "blockers" in parameters:
                raise OperatorObligationInputError("delegated outcome may not contain blockers")
        material = {
            "kind": CLOSE_KIND,
            "schema_version": SCHEMA_VERSION,
            "obligation_id": obligation_id,
            "open_file_sha256": open_file_sha256,
            "outcome": outcome,
            "evidence": evidence,
            "blockers": blockers,
            "delegation": delegation,
            "next_action": next_action,
        }
        material_sha256 = _sha256(material)
        payload = {**material, "closed_at": _utc_now(), "material_sha256": material_sha256}
        payload["record_sha256"] = _sha256(payload)
        target = directory / "close.json"
        created = private_io.publish_private_create_only_json(
            directory,
            target,
            payload,
            max_bytes=MAX_RECORD_BYTES,
            label="operator obligation close record",
        )
        winner, close_file_sha256 = _read_private_json(target)
        _validate_close_record(winner, open_record=open_record, open_file_sha256=open_file_sha256)
        if winner["material_sha256"] != material_sha256:
            raise OperatorObligationConflictError("operator obligation already has a different terminal close")
    status = status_obligation(obligation_id)
    return {
        **status,
        "created": created,
        "replayed": not created,
        "close_material_sha256": material_sha256,
        "close_file_sha256": close_file_sha256,
    }

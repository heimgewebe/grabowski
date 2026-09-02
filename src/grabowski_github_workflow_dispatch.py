from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import quote
import uuid

import grabowski_grips
import grabowski_operator_core as operator

SCHEMA_VERSION = 1
GRIP_NAME = "github-workflow-dispatch"
RUNNER_NAME = "github_workflow_dispatch"
RECEIPT_KIND = "grabowski_github_workflow_dispatch_receipt"
RESULT_KIND = "grabowski_github_workflow_dispatch_result"
STATE_DIR_ENV = "GRABOWSKI_GITHUB_WORKFLOW_DISPATCH_STATE_DIR"
DEFAULT_STATE_DIR = Path.home() / ".local/state/grabowski/github-workflow-dispatch"

MAX_REPOSITORY_BYTES = 205
MAX_WORKFLOW_BYTES = 255
MAX_REF_BYTES = 255
MAX_INPUTS = 32
MAX_INPUT_KEY_BYTES = 80
MAX_INPUT_VALUE_BYTES = 4096
MAX_INPUT_BYTES = 32 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
RUN_POLL_ATTEMPTS = 20
RUN_POLL_INTERVAL_SECONDS = 1.0
RUN_CREATED_SKEW_SECONDS = 15.0
RUN_CREATED_FUTURE_SECONDS = 60.0

_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_WORKFLOW_FILE_RE = re.compile(r"[A-Za-z0-9_.-]+\.(?:yml|yaml)\Z", re.IGNORECASE)
_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_INPUT_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HTTP_STATUS_RE = re.compile(r"\bHTTP\s+([1-5][0-9]{2})\b", re.IGNORECASE)
_SECRET_VALUE_RE = re.compile(
    r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|Bearer\s+\S{12,}|-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)",
    re.IGNORECASE,
)
_SECRET_KEY_PARTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "cookie",
    "credential",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
)
_ALLOWED_GRIP_PARAMETERS = frozenset(
    {"repository", "workflow", "ref", "inputs", "expected_head"}
)


class WorkflowDispatchContractError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


GitHubRunner = Callable[[list[str]], dict[str, Any]]
Sleep = Callable[[float], None]
TimeFn = Callable[[], float]


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _bounded_text(value: Any, *, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise WorkflowDispatchContractError(
            "input_invalid", f"{label} must be non-empty trimmed text"
        )
    if len(value.encode("utf-8")) > maximum or _CONTROL_RE.search(value):
        raise WorkflowDispatchContractError(
            "input_invalid", f"{label} is unbounded or contains controls"
        )
    return value


def _normalize_repository(value: Any) -> str:
    repository = _bounded_text(
        value, label="repository", maximum=MAX_REPOSITORY_BYTES
    )
    if _REPOSITORY_RE.fullmatch(repository) is None:
        raise WorkflowDispatchContractError(
            "repository_invalid", "repository must be owner/name"
        )
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise WorkflowDispatchContractError(
            "repository_invalid", "repository segments are invalid"
        )
    return repository


def _normalize_workflow(value: Any) -> tuple[str, str]:
    workflow = _bounded_text(value, label="workflow", maximum=MAX_WORKFLOW_BYTES)
    if workflow.isdigit():
        if int(workflow) < 1:
            raise WorkflowDispatchContractError(
                "workflow_invalid", "workflow id must be positive"
            )
        return "id", str(int(workflow))
    filename = workflow.removeprefix(".github/workflows/")
    if (
        "/" in filename
        or filename in {".", ".."}
        or _WORKFLOW_FILE_RE.fullmatch(filename) is None
    ):
        raise WorkflowDispatchContractError(
            "workflow_invalid",
            "workflow must be a positive id or one filename under .github/workflows",
        )
    return "path", f".github/workflows/{filename}"


def _normalize_ref(value: Any) -> str:
    ref = _bounded_text(value, label="ref", maximum=MAX_REF_BYTES)
    if (
        ref.startswith(("-", "."))
        or ref.endswith((".", "/"))
        or ".." in ref
        or "@{" in ref
        or "\\" in ref
        or " " in ref
        or any(character in ref for character in "~^:?*[")
    ):
        raise WorkflowDispatchContractError(
            "ref_invalid", "ref is not a conservative Git ref"
        )
    return ref


def _normalize_expected_head(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _SHA40_RE.fullmatch(value) is None:
        raise WorkflowDispatchContractError(
            "expected_head_invalid",
            "expected_head must be a full lowercase Git SHA",
        )
    return value


def _looks_sensitive_key(value: str) -> bool:
    normalized = value.casefold()
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _looks_sensitive_value(value: str) -> bool:
    if _SECRET_VALUE_RE.search(value):
        return True
    redactor = getattr(operator, "_redact", None)
    return bool(callable(redactor) and redactor(value) != value)


def _normalize_inputs(value: Any) -> tuple[dict[str, str], dict[str, Any]]:
    raw: Mapping[str, Any]
    if value is None:
        raw = {}
    elif isinstance(value, Mapping):
        raw = value
    else:
        raise WorkflowDispatchContractError(
            "inputs_invalid", "inputs must be a structured object"
        )
    if len(raw) > MAX_INPUTS:
        raise WorkflowDispatchContractError(
            "inputs_invalid", "inputs exceed the item bound"
        )
    normalized: dict[str, str] = {}
    total_bytes = 0
    for raw_key, raw_value in raw.items():
        if not isinstance(raw_key, str) or _INPUT_KEY_RE.fullmatch(raw_key) is None:
            raise WorkflowDispatchContractError(
                "inputs_invalid", "workflow input key is invalid"
            )
        if (
            len(raw_key.encode("utf-8")) > MAX_INPUT_KEY_BYTES
            or _looks_sensitive_key(raw_key)
        ):
            raise WorkflowDispatchContractError(
                "secret_input_rejected",
                "secret-like workflow input keys are forbidden",
            )
        if not isinstance(raw_value, str):
            raise WorkflowDispatchContractError(
                "inputs_invalid", "workflow input values must be strings"
            )
        if (
            len(raw_value.encode("utf-8")) > MAX_INPUT_VALUE_BYTES
            or _CONTROL_RE.search(raw_value)
        ):
            raise WorkflowDispatchContractError(
                "inputs_invalid",
                "workflow input value is unbounded or contains controls",
            )
        if _looks_sensitive_value(raw_value):
            raise WorkflowDispatchContractError(
                "secret_input_rejected",
                "workflow input value resembles secret material",
            )
        normalized[raw_key] = raw_value
        total_bytes += len(raw_key.encode("utf-8")) + len(raw_value.encode("utf-8"))
    if total_bytes > MAX_INPUT_BYTES:
        raise WorkflowDispatchContractError(
            "inputs_invalid", "workflow inputs exceed the byte bound"
        )
    ordered = dict(sorted(normalized.items()))
    metadata = {
        "count": len(ordered),
        "keys": sorted(ordered),
        "bytes": total_bytes,
        "sha256": _sha256_json(ordered),
        "values_persisted": False,
    }
    return ordered, metadata


def _operator_identity() -> dict[str, Any]:
    hostname = socket.gethostname()
    trusted_predicate = getattr(operator, "_trusted_owner_mode", None)
    trusted = bool(trusted_predicate()) if callable(trusted_predicate) else False
    return {
        "kind": "grabowski_operator_process",
        "uid": os.geteuid(),
        "pid": os.getpid(),
        "hostname_sha256": hashlib.sha256(hostname.encode("utf-8")).hexdigest(),
        "profile": "trusted_owner" if trusted else "operator",
    }


def _state_root(value: Path | None = None) -> Path:
    if value is not None:
        root = value
    else:
        configured = os.environ.get(STATE_DIR_ENV)
        root = Path(configured).expanduser() if configured else DEFAULT_STATE_DIR
    if not root.is_absolute():
        raise WorkflowDispatchContractError(
            "receipt_store_invalid", "receipt state root must be absolute"
        )
    return root


def _ensure_private_directory(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise WorkflowDispatchContractError(
            "receipt_store_invalid", "receipt directory may not be a symlink"
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise WorkflowDispatchContractError(
            "receipt_store_invalid",
            "receipt directory is not private and owner-controlled",
        )
    return path


def _request_directory(root: Path, request_sha256: str) -> Path:
    return _ensure_private_directory(_ensure_private_directory(root) / request_sha256)


@contextmanager
def _request_lock(directory: Path) -> Iterator[None]:
    path = directory / ".lock"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise WorkflowDispatchContractError(
                "receipt_store_invalid",
                "request lock is not private and owner-controlled",
            )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _receipt_unsigned(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_sha256", "receipt_path"}
    }


def _write_receipt(directory: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    unsigned = _receipt_unsigned(receipt)
    finalized = dict(unsigned)
    finalized["receipt_sha256"] = _sha256_json(unsigned)
    encoded = _canonical_json_bytes(finalized) + b"\n"
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise WorkflowDispatchContractError(
            "receipt_too_large", "dispatch receipt exceeds size bound"
        )
    target = directory / f"{time.time_ns()}-{uuid.uuid4().hex}.json"
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_fd = os.open(
        directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return {**finalized, "receipt_path": str(target)}


def _read_prior_receipts(directory: Path) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    try:
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return []
    for path in entries[-64:]:
        if path.suffix != ".json" or path.is_symlink():
            continue
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_RECEIPT_BYTES
            ):
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                continue
            stored_sha = payload.get("receipt_sha256")
            unsigned = {
                key: value
                for key, value in payload.items()
                if key != "receipt_sha256"
            }
            if not isinstance(stored_sha, str) or stored_sha != _sha256_json(unsigned):
                continue
            if (
                payload.get("schema_version") != SCHEMA_VERSION
                or payload.get("kind") != RECEIPT_KIND
            ):
                continue
            receipts.append({**payload, "receipt_path": str(path)})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
    return receipts


def _latest_unresolved_ambiguous(
    receipts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    for receipt in reversed(receipts):
        if (
            receipt.get("effect_state") == "unknown"
            and receipt.get("run") is None
            and receipt.get("result_code")
            in {"dispatch_outcome_unknown", "accepted_run_not_observed"}
        ):
            return receipt
        if receipt.get("effect_state") in {"observed", "not_started"}:
            return None
    return None


def _http_status(result: Mapping[str, Any]) -> int | None:
    for field in ("stderr", "stdout"):
        value = result.get(field)
        if isinstance(value, str):
            match = _HTTP_STATUS_RE.search(value)
            if match:
                return int(match.group(1))
    return None


def _runner_result(runner: GitHubRunner, args: list[str]) -> dict[str, Any]:
    try:
        result = runner(args)
    except Exception as exc:
        return {
            "returncode": None,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "runner_exception": type(exc).__name__,
        }
    if not isinstance(result, dict):
        return {
            "returncode": None,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "runner_exception": "invalid_runner_result",
        }
    return result


def _gh_json(
    runner: GitHubRunner,
    args: list[str],
    *,
    phase: str,
    not_found_code: str,
) -> tuple[Any | None, dict[str, Any] | None]:
    result = _runner_result(runner, args)
    status = _http_status(result)
    if result.get("timed_out") is True or result.get("runner_exception"):
        return None, {
            "result_code": f"{phase}_transport_error",
            "effect_state": "not_started",
            "http_status": status,
        }
    if result.get("returncode") != 0:
        if status in {401, 403}:
            code = "github_auth_or_permission"
        elif status == 404:
            code = not_found_code
        elif status == 422:
            code = f"{phase}_invalid"
        else:
            code = f"{phase}_github_error"
        return None, {
            "result_code": code,
            "effect_state": "not_started",
            "http_status": status,
        }
    stdout = result.get("stdout")
    if not isinstance(stdout, str):
        return None, {
            "result_code": f"{phase}_response_invalid",
            "effect_state": "not_started",
            "http_status": status,
        }
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return None, {
            "result_code": f"{phase}_response_invalid",
            "effect_state": "not_started",
            "http_status": status,
        }


def _repository_preflight(
    runner: GitHubRunner, repository: str
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    payload, error = _gh_json(
        runner,
        [
            "api",
            f"repos/{repository}",
            "--jq",
            '{"full_name":.full_name,"archived":.archived,"disabled":.disabled,"default_branch":.default_branch}',
        ],
        phase="repository_preflight",
        not_found_code="repository_not_found",
    )
    if error:
        return None, error
    if (
        not isinstance(payload, dict)
        or payload.get("full_name") != repository
        or not isinstance(payload.get("archived"), bool)
        or not isinstance(payload.get("disabled"), bool)
        or not isinstance(payload.get("default_branch"), str)
    ):
        return None, {
            "result_code": "repository_response_invalid",
            "effect_state": "not_started",
        }
    if payload["archived"] or payload["disabled"]:
        return None, {
            "result_code": "repository_inactive",
            "effect_state": "not_started",
        }
    return payload, None


def _workflow_preflight(
    runner: GitHubRunner,
    repository: str,
    workflow_kind: str,
    workflow_selector: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    api_identifier = (
        workflow_selector
        if workflow_kind == "id"
        else workflow_selector.rsplit("/", 1)[-1]
    )
    payload, error = _gh_json(
        runner,
        [
            "api",
            f"repos/{repository}/actions/workflows/{quote(api_identifier, safe='')}",
            "--jq",
            '{"id":.id,"name":.name,"path":.path,"state":.state}',
        ],
        phase="workflow_preflight",
        not_found_code="workflow_not_found",
    )
    if error:
        return None, error
    if (
        not isinstance(payload, dict)
        or isinstance(payload.get("id"), bool)
        or not isinstance(payload.get("id"), int)
        or payload["id"] < 1
        or not isinstance(payload.get("path"), str)
        or not isinstance(payload.get("state"), str)
    ):
        return None, {
            "result_code": "workflow_response_invalid",
            "effect_state": "not_started",
        }
    if payload["state"] != "active":
        return None, {
            "result_code": "workflow_inactive",
            "effect_state": "not_started",
        }
    if workflow_kind == "id" and str(payload["id"]) != workflow_selector:
        return None, {
            "result_code": "workflow_identity_mismatch",
            "effect_state": "not_started",
        }
    if workflow_kind == "path" and payload["path"] != workflow_selector:
        return None, {
            "result_code": "workflow_identity_mismatch",
            "effect_state": "not_started",
        }
    return payload, None


def _ref_preflight(
    runner: GitHubRunner, repository: str, ref: str
) -> tuple[str | None, dict[str, Any] | None]:
    payload, error = _gh_json(
        runner,
        [
            "api",
            f"repos/{repository}/commits/{quote(ref, safe='')}",
            "--jq",
            '{"sha":.sha}',
        ],
        phase="ref_preflight",
        not_found_code="ref_not_found",
    )
    if error:
        return None, error
    sha = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(sha, str) or _SHA40_RE.fullmatch(sha) is None:
        return None, {
            "result_code": "ref_response_invalid",
            "effect_state": "not_started",
        }
    return sha, None


def _parse_created_at(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _normalize_run(
    raw: Mapping[str, Any], workflow_path: str
) -> dict[str, Any] | None:
    run_id = raw.get("id")
    workflow_id = raw.get("workflow_id")
    head_sha = raw.get("head_sha")
    created_at = raw.get("created_at")
    if (
        isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id < 1
        or isinstance(workflow_id, bool)
        or not isinstance(workflow_id, int)
        or workflow_id < 1
        or raw.get("event") != "workflow_dispatch"
        or not isinstance(head_sha, str)
        or _SHA40_RE.fullmatch(head_sha) is None
        or _parse_created_at(created_at) is None
    ):
        return None
    return {
        "run_id": run_id,
        "workflow_id": workflow_id,
        "workflow_path": workflow_path,
        "event": "workflow_dispatch",
        "head_sha": head_sha,
        "head_branch": raw.get("head_branch"),
        "status": raw.get("status"),
        "conclusion": raw.get("conclusion"),
        "url": raw.get("html_url"),
        "created_at": created_at,
        "updated_at": raw.get("updated_at"),
        "run_attempt": raw.get("run_attempt"),
        "run_number": raw.get("run_number"),
    }


def _workflow_runs(
    runner: GitHubRunner,
    repository: str,
    workflow_id: int,
    workflow_path: str,
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    jq = (
        '{"workflow_runs":[.workflow_runs[]|'
        '{id:.id,workflow_id:.workflow_id,event:.event,head_sha:.head_sha,'
        'head_branch:.head_branch,status:.status,conclusion:.conclusion,html_url:.html_url,'
        'created_at:.created_at,updated_at:.updated_at,run_attempt:.run_attempt,run_number:.run_number}]}'
    )
    payload, error = _gh_json(
        runner,
        [
            "api",
            f"repos/{repository}/actions/workflows/{workflow_id}/runs?event=workflow_dispatch&per_page=100",
            "--jq",
            jq,
        ],
        phase="run_readback",
        not_found_code="workflow_not_found",
    )
    if error:
        return None, error
    rows = payload.get("workflow_runs") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return None, {
            "result_code": "run_readback_response_invalid",
            "effect_state": "not_started",
        }
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            return None, {
                "result_code": "run_readback_response_invalid",
                "effect_state": "not_started",
            }
        run = _normalize_run(row, workflow_path)
        if run is None:
            return None, {
                "result_code": "run_readback_response_invalid",
                "effect_state": "not_started",
            }
        normalized.append(run)
    return normalized, None


def _new_matching_runs(
    runs: list[dict[str, Any]],
    *,
    workflow_id: int,
    head_sha: str,
    baseline_ids: set[int],
    attempted_at_unix: float,
    now_unix: float,
) -> list[dict[str, Any]]:
    lower = attempted_at_unix - RUN_CREATED_SKEW_SECONDS
    upper = now_unix + RUN_CREATED_FUTURE_SECONDS
    matches: list[dict[str, Any]] = []
    for run in runs:
        created = _parse_created_at(run.get("created_at"))
        if (
            run.get("workflow_id") == workflow_id
            and run.get("head_sha") == head_sha
            and run.get("event") == "workflow_dispatch"
            and run.get("run_id") not in baseline_ids
            and created is not None
            and lower <= created <= upper
        ):
            matches.append(run)
    return sorted(matches, key=lambda item: int(item["run_id"]))


def _readback_new_run(
    runner: GitHubRunner,
    *,
    repository: str,
    workflow_id: int,
    workflow_path: str,
    head_sha: str,
    baseline_ids: set[int],
    attempted_at_unix: float,
    attempts: int,
    sleep: Sleep,
    time_fn: TimeFn,
) -> tuple[dict[str, Any] | None, str, dict[str, Any] | None]:
    for attempt in range(max(1, attempts)):
        runs, error = _workflow_runs(
            runner, repository, workflow_id, workflow_path
        )
        if error:
            return None, "run_readback_failed", error
        assert runs is not None
        matches = _new_matching_runs(
            runs,
            workflow_id=workflow_id,
            head_sha=head_sha,
            baseline_ids=baseline_ids,
            attempted_at_unix=attempted_at_unix,
            now_unix=time_fn(),
        )
        if len(matches) == 1:
            return matches[0], "unique", None
        if len(matches) > 1:
            return None, "ambiguous", None
        if attempt + 1 < attempts:
            sleep(RUN_POLL_INTERVAL_SECONDS)
    return None, "missing", None


def _dispatch_post(
    runner: GitHubRunner,
    *,
    repository: str,
    workflow_id: int,
    ref: str,
    inputs: dict[str, str],
    request_directory: Path,
) -> tuple[str, int | None]:
    descriptor, temp_name = tempfile.mkstemp(
        prefix="dispatch-body-",
        suffix=".json",
        dir=request_directory,
        text=False,
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(
            descriptor,
            _canonical_json_bytes({"ref": ref, "inputs": inputs}),
        )
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        result = _runner_result(
            runner,
            [
                "api",
                "--method",
                "POST",
                f"repos/{repository}/actions/workflows/{workflow_id}/dispatches",
                "--input",
                str(temp_path),
            ],
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
    status = _http_status(result)
    if result.get("timed_out") is True or result.get("runner_exception"):
        return "unknown", status
    if result.get("returncode") == 0:
        return "accepted", status
    if status in {401, 403}:
        return "auth", status
    if status == 404:
        return "not_found", status
    if status == 422:
        return "invalid_inputs", status
    return "unknown", status


def _base_receipt(
    *,
    request_sha256: str,
    repository: str,
    workflow_kind: str,
    workflow_selector: str,
    ref: str,
    expected_head: str | None,
    inputs_metadata: dict[str, Any],
    started_at_unix: float,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "request_sha256": request_sha256,
        "operator_identity": _operator_identity(),
        "repository": repository,
        "workflow_requested": {
            "kind": workflow_kind,
            "selector": workflow_selector,
        },
        "workflow_resolved": None,
        "ref": ref,
        "expected_head": expected_head,
        "observed_head": None,
        "inputs": inputs_metadata,
        "baseline_run_ids": [],
        "started_at_unix": started_at_unix,
        "dispatch_attempted_at_unix": None,
        "completed_at_unix": None,
        "result_code": None,
        "effect_state": "not_started",
        "http_status": None,
        "run": None,
        "does_not_establish": [
            "workflow_success",
            "artifact_correctness",
            "merge_authority",
            "production_activation",
            "retry_authority_after_ambiguous_outcome",
        ],
    }


def _finish(
    directory: Path,
    receipt: dict[str, Any],
    *,
    result_code: str,
    effect_state: str,
    completed_at_unix: float,
    http_status: int | None = None,
    run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = {
        **receipt,
        "result_code": result_code,
        "effect_state": effect_state,
        "http_status": http_status,
        "run": run,
        "completed_at_unix": completed_at_unix,
    }
    stored = _write_receipt(directory, receipt)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "ok": result_code
        in {"dispatch_accepted", "dispatch_recovered_after_ambiguous_transport"},
        "result_code": result_code,
        "effect_state": effect_state,
        "repository": receipt["repository"],
        "workflow": receipt["workflow_resolved"] or receipt["workflow_requested"],
        "ref": receipt["ref"],
        "expected_head": receipt["expected_head"],
        "observed_head": receipt["observed_head"],
        "input_sha256": receipt["inputs"]["sha256"],
        "run": run,
        "receipt": {
            "path": stored["receipt_path"],
            "sha256": stored["receipt_sha256"],
        },
        "retry_authorized": False,
        "authoritative_readback_required": effect_state == "unknown",
    }


def _contract_error_result(exc: WorkflowDispatchContractError) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "ok": False,
        "result_code": exc.code,
        "effect_state": "not_started",
        "retry_authorized": False,
        "authoritative_readback_required": False,
    }


def dispatch_workflow(
    repository: str,
    workflow: str,
    ref: str,
    inputs: Mapping[str, str] | None = None,
    expected_head: str | None = None,
    *,
    runner: GitHubRunner,
    state_root: Path | None = None,
    sleep: Sleep = time.sleep,
    time_fn: TimeFn = time.time,
    poll_attempts: int = RUN_POLL_ATTEMPTS,
) -> dict[str, Any]:
    try:
        repository = _normalize_repository(repository)
        workflow_kind, workflow_selector = _normalize_workflow(workflow)
        ref = _normalize_ref(ref)
        expected_head = _normalize_expected_head(expected_head)
        normalized_inputs, inputs_metadata = _normalize_inputs(inputs)
        request_sha256 = _sha256_json(
            {
                "repository": repository,
                "workflow": {
                    "kind": workflow_kind,
                    "selector": workflow_selector,
                },
                "ref": ref,
                "expected_head": expected_head,
                "inputs_sha256": inputs_metadata["sha256"],
            }
        )
        directory = _request_directory(_state_root(state_root), request_sha256)
    except WorkflowDispatchContractError as exc:
        return _contract_error_result(exc)

    with _request_lock(directory):
        started_at = time_fn()
        receipt = _base_receipt(
            request_sha256=request_sha256,
            repository=repository,
            workflow_kind=workflow_kind,
            workflow_selector=workflow_selector,
            ref=ref,
            expected_head=expected_head,
            inputs_metadata=inputs_metadata,
            started_at_unix=started_at,
        )

        _repository, error = _repository_preflight(runner, repository)
        if error:
            return _finish(
                directory,
                receipt,
                result_code=error["result_code"],
                effect_state=error["effect_state"],
                completed_at_unix=time_fn(),
                http_status=error.get("http_status"),
            )

        workflow_info, error = _workflow_preflight(
            runner, repository, workflow_kind, workflow_selector
        )
        if error:
            return _finish(
                directory,
                receipt,
                result_code=error["result_code"],
                effect_state=error["effect_state"],
                completed_at_unix=time_fn(),
                http_status=error.get("http_status"),
            )
        assert workflow_info is not None
        receipt["workflow_resolved"] = {
            "id": workflow_info["id"],
            "path": workflow_info["path"],
            "name": workflow_info.get("name"),
            "state": workflow_info["state"],
        }

        observed_head, error = _ref_preflight(runner, repository, ref)
        if error:
            return _finish(
                directory,
                receipt,
                result_code=error["result_code"],
                effect_state=error["effect_state"],
                completed_at_unix=time_fn(),
                http_status=error.get("http_status"),
            )
        assert observed_head is not None
        receipt["observed_head"] = observed_head
        if expected_head is not None and observed_head != expected_head:
            return _finish(
                directory,
                receipt,
                result_code="ref_head_drift",
                effect_state="not_started",
                completed_at_unix=time_fn(),
            )

        runs, error = _workflow_runs(
            runner,
            repository,
            int(workflow_info["id"]),
            str(workflow_info["path"]),
        )
        if error:
            return _finish(
                directory,
                receipt,
                result_code=error["result_code"],
                effect_state="not_started",
                completed_at_unix=time_fn(),
                http_status=error.get("http_status"),
            )
        assert runs is not None
        baseline_ids = {
            int(run["run_id"])
            for run in runs
            if run.get("workflow_id") == workflow_info["id"]
            and run.get("head_sha") == observed_head
            and run.get("event") == "workflow_dispatch"
        }
        receipt["baseline_run_ids"] = sorted(baseline_ids)

        prior = _latest_unresolved_ambiguous(_read_prior_receipts(directory))
        if prior is not None:
            if prior.get("observed_head") != observed_head:
                return _finish(
                    directory,
                    receipt,
                    result_code="prior_ambiguous_ref_drift",
                    effect_state="unknown",
                    completed_at_unix=time_fn(),
                )
            prior_baseline = prior.get("baseline_run_ids")
            attempted_at = prior.get("dispatch_attempted_at_unix")
            if (
                not isinstance(prior_baseline, list)
                or not all(
                    isinstance(item, int) and not isinstance(item, bool) and item > 0
                    for item in prior_baseline
                )
                or not isinstance(attempted_at, (int, float))
                or isinstance(attempted_at, bool)
            ):
                return _finish(
                    directory,
                    receipt,
                    result_code="prior_ambiguous_receipt_invalid",
                    effect_state="unknown",
                    completed_at_unix=time_fn(),
                )
            run, state, readback_error = _readback_new_run(
                runner,
                repository=repository,
                workflow_id=int(workflow_info["id"]),
                workflow_path=str(workflow_info["path"]),
                head_sha=observed_head,
                baseline_ids=set(prior_baseline),
                attempted_at_unix=float(attempted_at),
                attempts=1,
                sleep=sleep,
                time_fn=time_fn,
            )
            if readback_error:
                return _finish(
                    directory,
                    receipt,
                    result_code="prior_ambiguous_readback_failed",
                    effect_state="unknown",
                    completed_at_unix=time_fn(),
                    http_status=readback_error.get("http_status"),
                )
            if state == "unique" and run is not None:
                return _finish(
                    directory,
                    receipt,
                    result_code="dispatch_recovered_after_ambiguous_transport",
                    effect_state="observed",
                    completed_at_unix=time_fn(),
                    run=run,
                )
            if state == "ambiguous":
                return _finish(
                    directory,
                    receipt,
                    result_code="prior_ambiguous_multiple_runs",
                    effect_state="unknown",
                    completed_at_unix=time_fn(),
                )
            return _finish(
                directory,
                receipt,
                result_code="prior_ambiguous_outcome_unresolved",
                effect_state="unknown",
                completed_at_unix=time_fn(),
            )

        attempted_at = time_fn()
        receipt["dispatch_attempted_at_unix"] = attempted_at
        post_state, http_status = _dispatch_post(
            runner,
            repository=repository,
            workflow_id=int(workflow_info["id"]),
            ref=ref,
            inputs=normalized_inputs,
            request_directory=directory,
        )
        if post_state == "auth":
            return _finish(
                directory,
                receipt,
                result_code="github_auth_or_permission",
                effect_state="not_started",
                completed_at_unix=time_fn(),
                http_status=http_status,
            )
        if post_state == "not_found":
            return _finish(
                directory,
                receipt,
                result_code="workflow_or_ref_not_found_at_dispatch",
                effect_state="not_started",
                completed_at_unix=time_fn(),
                http_status=http_status,
            )
        if post_state == "invalid_inputs":
            return _finish(
                directory,
                receipt,
                result_code="invalid_workflow_inputs",
                effect_state="not_started",
                completed_at_unix=time_fn(),
                http_status=http_status,
            )

        run, readback_state, readback_error = _readback_new_run(
            runner,
            repository=repository,
            workflow_id=int(workflow_info["id"]),
            workflow_path=str(workflow_info["path"]),
            head_sha=observed_head,
            baseline_ids=baseline_ids,
            attempted_at_unix=attempted_at,
            attempts=poll_attempts if post_state == "accepted" else 1,
            sleep=sleep,
            time_fn=time_fn,
        )
        if readback_error:
            return _finish(
                directory,
                receipt,
                result_code=(
                    "accepted_run_readback_failed"
                    if post_state == "accepted"
                    else "dispatch_outcome_unknown"
                ),
                effect_state="unknown",
                completed_at_unix=time_fn(),
                http_status=readback_error.get("http_status"),
            )
        if readback_state == "unique" and run is not None:
            return _finish(
                directory,
                receipt,
                result_code=(
                    "dispatch_accepted"
                    if post_state == "accepted"
                    else "dispatch_recovered_after_ambiguous_transport"
                ),
                effect_state="observed",
                completed_at_unix=time_fn(),
                http_status=http_status,
                run=run,
            )
        if readback_state == "ambiguous":
            return _finish(
                directory,
                receipt,
                result_code="run_identity_ambiguous",
                effect_state="unknown",
                completed_at_unix=time_fn(),
                http_status=http_status,
            )
        return _finish(
            directory,
            receipt,
            result_code=(
                "accepted_run_not_observed"
                if post_state == "accepted"
                else "dispatch_outcome_unknown"
            ),
            effect_state="unknown",
            completed_at_unix=time_fn(),
            http_status=http_status,
        )


def _grip_runner(
    spec: grabowski_grips.GripSpec,
    parameters: dict[str, Any],
    receipt: dict[str, Any],
    command_runner: grabowski_grips.CommandRunner,
    github_runner: grabowski_grips.GithubRunner,
) -> dict[str, Any]:
    del spec, command_runner
    unknown = sorted(set(parameters) - _ALLOWED_GRIP_PARAMETERS)
    if unknown:
        raise grabowski_grips.GripPreflightError(
            f"github-workflow-dispatch received unsupported parameters: {unknown}"
        )

    def run_github(arguments: list[str]) -> dict[str, Any]:
        return github_runner(operator.HOME, arguments)

    result = dispatch_workflow(
        parameters.get("repository"),
        parameters.get("workflow"),
        parameters.get("ref"),
        inputs=parameters.get("inputs"),
        expected_head=parameters.get("expected_head"),
        runner=run_github,
    )
    code = str(result.get("result_code", "unknown"))
    effect_state = result.get("effect_state")
    if code == "ref_head_drift":
        grabowski_grips._check(
            receipt,
            "exact-head-fail-closed",
            "pass",
            "observed ref head differed; no dispatch was attempted",
        )
    elif parameters.get("expected_head") is not None:
        exact = result.get("observed_head") == parameters.get("expected_head")
        grabowski_grips._check(
            receipt,
            "exact-head-fail-closed",
            "pass" if exact or effect_state == "not_started" else "fail",
            code,
        )

    if result.get("ok") is True:
        run = result.get("run")
        unique = isinstance(run, dict) and isinstance(run.get("run_id"), int)
        grabowski_grips._check(
            receipt,
            "unique-run-readback",
            "pass" if unique else "fail",
            str(run.get("run_id")) if isinstance(run, dict) else "missing",
        )
    elif effect_state == "unknown":
        grabowski_grips._check(
            receipt,
            "ambiguous-outcome-dedupe",
            "pass",
            "retry remains unauthorized until authoritative readback resolves the effect",
        )

    return {
        **result,
        "receipt_status": "passed" if result.get("ok") is True else "blocked",
        "decision": "dispatched" if result.get("ok") is True else "blocked",
        "blocked_reasons": [] if result.get("ok") is True else [code],
    }


_GRIP_SPEC = grabowski_grips.GripSpec(
    name=GRIP_NAME,
    version="1.0",
    summary=(
        "Dispatch one explicitly named GitHub Actions workflow with fresh target "
        "resolution, optional exact-head binding, deduplicating readback and a durable receipt."
    ),
    effect=grabowski_grips.MUTATING,
    required_parameters=("repository", "workflow", "ref", "inputs"),
    acceptance_ids=(
        "fresh-targets",
        "exact-head-fail-closed",
        "typed-errors",
        "unique-run-readback",
        "ambiguous-dedupe",
        "audit-receipt",
    ),
    runner=RUNNER_NAME,
    uses_github=True,
    operation_effect_class="external_provider",
    operation_class="github-actions-workflow-dispatch",
    capability="github_cli",
)


def _register_grip() -> None:
    existing_spec = grabowski_grips.GRIP_SPECS.get(GRIP_NAME)
    existing_runner = grabowski_grips._RUNNERS.get(RUNNER_NAME)
    if existing_spec is not None or existing_runner is not None:
        if existing_spec == _GRIP_SPEC and existing_runner is _grip_runner:
            return
        raise RuntimeError("github-workflow-dispatch grip registration collision")
    grabowski_grips.GRIP_SPECS[GRIP_NAME] = _GRIP_SPEC
    grabowski_grips._RUNNERS[RUNNER_NAME] = _grip_runner
    grabowski_grips.GRIP_SURFACE_ALLOWLIST = frozenset(
        {*grabowski_grips.GRIP_SURFACE_ALLOWLIST, GRIP_NAME}
    )
    grabowski_grips.GRIP_RISK_LEVELS[GRIP_NAME] = "high"
    grabowski_grips.GRIP_SURFACE_TARGETS[GRIP_NAME] = (
        "one explicit GitHub Actions workflow dispatch"
    )
    grabowski_grips.GRIP_RECOVERY_PATHS_BY_NAME[GRIP_NAME] = (
        "inspect the nested dispatch receipt and authoritative workflow-run readback; "
        "if effect_state is unknown, do not dispatch again until the same request is reconciled"
    )


_register_grip()

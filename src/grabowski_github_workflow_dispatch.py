from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
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
ACTIVE_ATTEMPT_FILE = "active-attempt.json"

MAX_RECEIPT_BYTES = 128 * 1024
MAX_INPUTS = 32
MAX_INPUT_BYTES = 32 * 1024
POLL_ATTEMPTS = 20
POLL_SECONDS = 1.0
RUN_SKEW_SECONDS = 15.0
RUN_FUTURE_SECONDS = 60.0

_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_WORKFLOW_RE = re.compile(r"[A-Za-z0-9_.-]+\.(?:yml|yaml)\Z", re.I)
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_ATTEMPT_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_REF_BAD_RE = re.compile(r"(?:\.\.|@\{|[ ~^:?*\[\\])")
_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,80}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HTTP_RE = re.compile(r"\bHTTP\s+([1-5][0-9]{2})\b", re.I)
_SECRET_RE = re.compile(
    r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"Bearer\s+\S{12,}|-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)",
    re.I,
)
_SECRET_KEYS = (
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
_ALLOWED_PARAMETERS = frozenset(
    {"repository", "workflow", "ref", "inputs", "expected_head"}
)
_UNRESOLVED_DISPATCH_CODES = frozenset(
    {
        "dispatch_in_flight",
        "dispatch_outcome_unknown",
        "accepted_run_not_observed",
        "accepted_run_readback_failed",
        "run_identity_ambiguous",
    }
)

GithubRunner = Callable[[list[str]], dict[str, Any]]
Sleep = Callable[[float], None]
TimeFn = Callable[[], float]


class DispatchError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _normalize_repository(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or len(value.encode()) > 205
        or not _REPO_RE.fullmatch(value)
    ):
        raise DispatchError(
            "repository_invalid", "repository must be bounded owner/name text"
        )
    if any(part in {".", ".."} for part in value.split("/", 1)):
        raise DispatchError("repository_invalid", "repository segments are invalid")
    return value


def _normalize_workflow(value: Any) -> tuple[str, str]:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value.encode()) > 255
    ):
        raise DispatchError("workflow_invalid", "workflow must be bounded text")
    if value.isdigit():
        if int(value) < 1:
            raise DispatchError("workflow_invalid", "workflow id must be positive")
        return "id", str(int(value))
    filename = value.removeprefix(".github/workflows/")
    if "/" in filename or not _WORKFLOW_RE.fullmatch(filename):
        raise DispatchError(
            "workflow_invalid", "workflow must be a positive id or workflow filename"
        )
    return "path", f".github/workflows/{filename}"


def _normalize_ref(value: Any) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value.encode()) > 255
        or value.startswith(("-", "."))
        or value.endswith((".", "/"))
        or _REF_BAD_RE.search(value)
    ):
        raise DispatchError("ref_invalid", "ref is not a conservative Git ref")
    return value


def _normalize_head(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise DispatchError(
            "expected_head_invalid", "expected_head must be a full lowercase SHA"
        )
    return value


def _normalize_inputs(value: Any) -> tuple[dict[str, str], dict[str, Any]]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping) or len(value) > MAX_INPUTS:
        raise DispatchError("inputs_invalid", "inputs must be a bounded object")
    normalized: dict[str, str] = {}
    total = 0
    redactor = getattr(operator, "_redact", None)
    for key, item in value.items():
        if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
            raise DispatchError("inputs_invalid", "workflow input key is invalid")
        if any(part in key.casefold() for part in _SECRET_KEYS):
            raise DispatchError(
                "secret_input_rejected",
                "secret-like workflow input keys are forbidden",
            )
        if (
            not isinstance(item, str)
            or len(item.encode()) > 4096
            or _CONTROL_RE.search(item)
        ):
            raise DispatchError(
                "inputs_invalid", "workflow input values must be bounded strings"
            )
        if _SECRET_RE.search(item) or (
            callable(redactor) and redactor(item) != item
        ):
            raise DispatchError(
                "secret_input_rejected",
                "workflow input value resembles secret material",
            )
        normalized[key] = item
        total += len(key.encode()) + len(item.encode())
    if total > MAX_INPUT_BYTES:
        raise DispatchError("inputs_invalid", "workflow inputs exceed the byte bound")
    normalized = dict(sorted(normalized.items()))
    return normalized, {
        "count": len(normalized),
        "keys": sorted(normalized),
        "bytes": total,
        "sha256": _digest(normalized),
        "values_persisted": False,
    }


def _state_root(override: Path | None) -> Path:
    root = override or Path(os.environ.get(STATE_DIR_ENV, DEFAULT_STATE_DIR)).expanduser()
    if not root.is_absolute():
        raise DispatchError("receipt_store_invalid", "state root must be absolute")
    return root


def _private_dir(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise DispatchError(
            "receipt_store_invalid", "state directory may not be a symlink"
        )
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DispatchError(
            "receipt_store_invalid", "state directory is not private"
        )
    return path


@contextmanager
def _lock(directory: Path) -> Iterator[None]:
    fd = os.open(
        directory / ".lock",
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise DispatchError(
                "receipt_store_invalid", "request lock is not private"
            )
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _fsync_directory(directory: Path) -> None:
    directory_fd = os.open(
        directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_receipt(directory: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    unsigned = {
        key: item
        for key, item in receipt.items()
        if key not in {"receipt_sha256", "receipt_path"}
    }
    stored = {**unsigned, "receipt_sha256": _digest(unsigned)}
    data = _json_bytes(stored) + b"\n"
    if len(data) > MAX_RECEIPT_BYTES:
        raise DispatchError("receipt_too_large", "receipt exceeds size bound")
    path = directory / f"{time.time_ns()}-{uuid.uuid4().hex}.json"
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(directory)
    return {**stored, "receipt_path": str(path)}


def _read_receipt(path: Path) -> dict[str, Any] | None:
    try:
        info = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > MAX_RECEIPT_BYTES
        ):
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return None
        stored = payload.pop("receipt_sha256", None)
        if (
            payload.get("kind") != RECEIPT_KIND
            or payload.get("schema_version") != SCHEMA_VERSION
            or stored != _digest(payload)
        ):
            return None
        return {
            **payload,
            "receipt_sha256": stored,
            "receipt_path": str(path),
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _write_active_attempt(directory: Path, receipt: dict[str, Any]) -> None:
    attempt_id = receipt.get("dispatch_attempt_id")
    if (
        receipt.get("kind") != RECEIPT_KIND
        or receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("effect_state") != "unknown"
        or receipt.get("result_code") != "dispatch_in_flight"
        or not isinstance(attempt_id, str)
        or _ATTEMPT_ID_RE.fullmatch(attempt_id) is None
    ):
        raise DispatchError("dispatch_journal_invalid", "active attempt is invalid")
    payload = {key: value for key, value in receipt.items() if key != "receipt_path"}
    stored_sha = payload.get("receipt_sha256")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if stored_sha != _digest(unsigned):
        raise DispatchError(
            "dispatch_journal_invalid", "active attempt receipt hash is invalid"
        )
    data = _json_bytes(payload) + b"\n"
    fd, raw_path = tempfile.mkstemp(prefix=".active-attempt-", suffix=".tmp", dir=directory)
    temporary = Path(raw_path)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, directory / ACTIVE_ATTEMPT_FILE)
        _fsync_directory(directory)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def _clear_active_attempt(directory: Path) -> None:
    path = directory / ACTIVE_ATTEMPT_FILE
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(directory)


def _prior_receipts(directory: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    paths = [
        path
        for path in sorted(directory.glob("*.json"))
        if path.name != ACTIVE_ATTEMPT_FILE
    ][-64:]
    for path in paths:
        receipt = _read_receipt(path)
        if receipt is not None:
            result.append(receipt)
    return result


def _unresolved(
    directory: Path, receipts: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, str | None]:
    active_path = directory / ACTIVE_ATTEMPT_FILE
    if active_path.exists() or active_path.is_symlink():
        active = _read_receipt(active_path)
        if active is None:
            return None, "active_attempt_invalid"
        attempt_id = active.get("dispatch_attempt_id")
        if (
            not isinstance(attempt_id, str)
            or _ATTEMPT_ID_RE.fullmatch(attempt_id) is None
            or active.get("result_code") != "dispatch_in_flight"
            or active.get("effect_state") != "unknown"
        ):
            return None, "active_attempt_invalid"
        for receipt in reversed(receipts):
            if (
                receipt.get("dispatch_attempt_id") == attempt_id
                and receipt.get("effect_state") in {"observed", "not_started"}
                and receipt.get("completed_at_unix") is not None
            ):
                try:
                    _clear_active_attempt(directory)
                except OSError:
                    pass
                return None, None
        return active, None
    for receipt in reversed(receipts):
        if (
            receipt.get("effect_state") == "unknown"
            and receipt.get("run") is None
            and receipt.get("result_code") in _UNRESOLVED_DISPATCH_CODES
        ):
            return receipt, None
        if receipt.get("effect_state") == "observed":
            return None, None
    return None, None


def _http_status(result: Mapping[str, Any]) -> int | None:
    text = f"{result.get('stderr', '')}\n{result.get('stdout', '')}"
    match = _HTTP_RE.search(text)
    return int(match.group(1)) if match else None


def _call(runner: GithubRunner, args: list[str]) -> dict[str, Any]:
    try:
        result = runner(args)
        return (
            result
            if isinstance(result, dict)
            else {"runner_exception": "invalid_result"}
        )
    except Exception as exc:
        return {"runner_exception": type(exc).__name__}


def _gh_json(
    runner: GithubRunner,
    endpoint: str,
    jq: str,
    *,
    phase: str,
    not_found: str,
) -> tuple[Any | None, dict[str, Any] | None]:
    result = _call(runner, ["api", endpoint, "--jq", jq])
    status = _http_status(result)
    if result.get("timed_out") is True or result.get("runner_exception"):
        return None, {
            "result_code": f"{phase}_transport_error",
            "effect_state": "not_started",
            "http_status": status,
        }
    if result.get("returncode") != 0:
        code = (
            "github_auth_or_permission"
            if status in {401, 403}
            else not_found
            if status == 404
            else f"{phase}_invalid"
            if status == 422
            else f"{phase}_github_error"
        )
        return None, {
            "result_code": code,
            "effect_state": "not_started",
            "http_status": status,
        }
    try:
        return json.loads(result.get("stdout", "")), None
    except (TypeError, json.JSONDecodeError):
        return None, {
            "result_code": f"{phase}_response_invalid",
            "effect_state": "not_started",
            "http_status": status,
        }


def _preflight(
    runner: GithubRunner,
    repository: str,
    workflow_kind: str,
    workflow_selector: str,
    ref: str,
) -> tuple[dict[str, Any] | None, str | None, dict[str, Any] | None]:
    repo, error = _gh_json(
        runner,
        f"repos/{repository}",
        '{"full_name":.full_name,"archived":.archived,"disabled":.disabled}',
        phase="repository_preflight",
        not_found="repository_not_found",
    )
    if error:
        return None, None, error
    if (
        not isinstance(repo, dict)
        or repo.get("full_name") != repository
        or not isinstance(repo.get("archived"), bool)
        or not isinstance(repo.get("disabled"), bool)
    ):
        return None, None, {
            "result_code": "repository_response_invalid",
            "effect_state": "not_started",
        }
    if repo["archived"] or repo["disabled"]:
        return None, None, {
            "result_code": "repository_inactive",
            "effect_state": "not_started",
        }

    identifier = (
        workflow_selector
        if workflow_kind == "id"
        else workflow_selector.rsplit("/", 1)[-1]
    )
    workflow, error = _gh_json(
        runner,
        f"repos/{repository}/actions/workflows/{quote(identifier, safe='')}",
        '{"id":.id,"name":.name,"path":.path,"state":.state}',
        phase="workflow_preflight",
        not_found="workflow_not_found",
    )
    if error:
        return None, None, error
    if (
        not isinstance(workflow, dict)
        or not isinstance(workflow.get("id"), int)
        or isinstance(workflow.get("id"), bool)
        or workflow["id"] < 1
        or not isinstance(workflow.get("path"), str)
        or not isinstance(workflow.get("state"), str)
    ):
        return None, None, {
            "result_code": "workflow_response_invalid",
            "effect_state": "not_started",
        }
    if workflow["state"] != "active":
        return None, None, {
            "result_code": "workflow_inactive",
            "effect_state": "not_started",
        }
    if (
        workflow_kind == "id"
        and str(workflow["id"]) != workflow_selector
    ) or (
        workflow_kind == "path"
        and workflow.get("path") != workflow_selector
    ):
        return None, None, {
            "result_code": "workflow_identity_mismatch",
            "effect_state": "not_started",
        }

    commit, error = _gh_json(
        runner,
        f"repos/{repository}/commits/{quote(ref, safe='')}",
        '{"sha":.sha}',
        phase="ref_preflight",
        not_found="ref_not_found",
    )
    if error:
        return None, None, error
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        return None, None, {
            "result_code": "ref_response_invalid",
            "effect_state": "not_started",
        }
    return workflow, sha, None


def _created_at(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _runs(
    runner: GithubRunner,
    repository: str,
    workflow_id: int,
    workflow_path: str,
) -> tuple[list[dict[str, Any]] | None, dict[str, Any] | None]:
    jq = (
        '{"workflow_runs":[.workflow_runs[]|{id:.id,workflow_id:.workflow_id,'
        'event:.event,head_sha:.head_sha,head_branch:.head_branch,status:.status,'
        'conclusion:.conclusion,html_url:.html_url,created_at:.created_at,'
        'updated_at:.updated_at,run_attempt:.run_attempt,run_number:.run_number}]}'
    )
    payload, error = _gh_json(
        runner,
        f"repos/{repository}/actions/workflows/{workflow_id}/runs?event=workflow_dispatch&per_page=100",
        jq,
        phase="run_readback",
        not_found="workflow_not_found",
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
        if (
            not isinstance(row, Mapping)
            or row.get("event") != "workflow_dispatch"
            or not isinstance(row.get("id"), int)
            or isinstance(row.get("id"), bool)
            or not isinstance(row.get("workflow_id"), int)
            or isinstance(row.get("workflow_id"), bool)
            or not isinstance(row.get("head_sha"), str)
            or not _SHA_RE.fullmatch(row["head_sha"])
            or _created_at(row.get("created_at")) is None
        ):
            return None, {
                "result_code": "run_readback_response_invalid",
                "effect_state": "not_started",
            }
        normalized.append(
            {
                "run_id": row["id"],
                "workflow_id": row["workflow_id"],
                "workflow_path": workflow_path,
                "event": "workflow_dispatch",
                "head_sha": row["head_sha"],
                "head_branch": row.get("head_branch"),
                "status": row.get("status"),
                "conclusion": row.get("conclusion"),
                "url": row.get("html_url"),
                "created_at": row.get("created_at"),
                "updated_at": row.get("updated_at"),
                "run_attempt": row.get("run_attempt"),
                "run_number": row.get("run_number"),
            }
        )
    return normalized, None


def _readback(
    runner: GithubRunner,
    *,
    repository: str,
    workflow_id: int,
    workflow_path: str,
    ref: str,
    head: str,
    baseline: set[int],
    attempted_at: float,
    attempts: int,
    sleep: Sleep,
    time_fn: TimeFn,
) -> tuple[dict[str, Any] | None, str, dict[str, Any] | None]:
    poll_count = max(1, attempts)
    candidates: dict[int, dict[str, Any]] = {}
    for index in range(poll_count):
        rows, error = _runs(runner, repository, workflow_id, workflow_path)
        if error:
            return None, "failed", error
        assert rows is not None
        lower = attempted_at - RUN_SKEW_SECONDS
        upper = time_fn() + RUN_FUTURE_SECONDS
        matches = []
        for run in rows:
            created = _created_at(run["created_at"])
            if (
                run["workflow_id"] == workflow_id
                and run["head_branch"] == ref
                and run["head_sha"] == head
                and run["run_id"] not in baseline
                and created is not None
                and lower <= created <= upper
            ):
                matches.append(run)
        if len(matches) == 1:
            candidate = matches[0]
            candidates[candidate["run_id"]] = candidate
            if len(candidates) > 1:
                return None, "ambiguous", None
        if len(matches) > 1:
            return None, "ambiguous", None
        if index + 1 < poll_count:
            sleep(POLL_SECONDS)
    if len(candidates) == 1:
        return next(iter(candidates.values())), "unique", None
    return None, "missing", None


def _post(
    runner: GithubRunner,
    directory: Path,
    repository: str,
    workflow_id: int,
    ref: str,
    inputs: dict[str, str],
) -> tuple[str, int | None]:
    fd, raw_path = tempfile.mkstemp(
        prefix="dispatch-", suffix=".json", dir=directory
    )
    path = Path(raw_path)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, _json_bytes({"ref": ref, "inputs": inputs}))
        os.fsync(fd)
        os.close(fd)
        fd = -1
        result = _call(
            runner,
            [
                "api",
                "--method",
                "POST",
                f"repos/{repository}/actions/workflows/{workflow_id}/dispatches",
                "--input",
                str(path),
            ],
        )
    finally:
        if fd >= 0:
            os.close(fd)
        path.unlink(missing_ok=True)
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


def _receipt(
    request_sha: str,
    repository: str,
    workflow_kind: str,
    workflow_selector: str,
    ref: str,
    expected_head: str | None,
    inputs_meta: dict[str, Any],
    started: float,
) -> dict[str, Any]:
    trusted = getattr(operator, "_trusted_owner_mode", lambda: False)()
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "request_sha256": request_sha,
        "operator_identity": {
            "kind": "grabowski_operator_process",
            "uid": os.geteuid(),
            "pid": os.getpid(),
            "hostname_sha256": hashlib.sha256(
                socket.gethostname().encode()
            ).hexdigest(),
            "profile": "trusted_owner" if trusted else "operator",
        },
        "repository": repository,
        "workflow_requested": {
            "kind": workflow_kind,
            "selector": workflow_selector,
        },
        "workflow_resolved": None,
        "ref": ref,
        "expected_head": expected_head,
        "observed_head": None,
        "inputs": inputs_meta,
        "baseline_run_ids": [],
        "started_at_unix": started,
        "dispatch_attempt_id": None,
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
    code: str,
    effect: str,
    now: float,
    *,
    status: int | None = None,
    run: dict[str, Any] | None = None,
    clear_active: bool = False,
) -> dict[str, Any]:
    stored = _write_receipt(
        directory,
        {
            **receipt,
            "result_code": code,
            "effect_state": effect,
            "http_status": status,
            "run": run,
            "completed_at_unix": now,
        },
    )
    if clear_active:
        try:
            _clear_active_attempt(directory)
        except OSError:
            pass
    ok = code in {
        "dispatch_accepted",
        "dispatch_recovered_after_ambiguous_transport",
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "ok": ok,
        "result_code": code,
        "effect_state": effect,
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
        "authoritative_readback_required": effect == "unknown",
    }


def dispatch_workflow(
    repository: str,
    workflow: str,
    ref: str,
    inputs: Mapping[str, str] | None = None,
    expected_head: str | None = None,
    *,
    runner: GithubRunner,
    state_root: Path | None = None,
    sleep: Sleep = time.sleep,
    time_fn: TimeFn = time.time,
    poll_attempts: int = POLL_ATTEMPTS,
) -> dict[str, Any]:
    try:
        repository = _normalize_repository(repository)
        workflow_kind, workflow_selector = _normalize_workflow(workflow)
        ref = _normalize_ref(ref)
        expected_head = _normalize_head(expected_head)
        normalized_inputs, inputs_meta = _normalize_inputs(inputs)
        request_sha = _digest(
            {
                "repository": repository,
                "workflow": {
                    "kind": workflow_kind,
                    "selector": workflow_selector,
                },
                "ref": ref,
                "expected_head": expected_head,
                "inputs_sha256": inputs_meta["sha256"],
            }
        )
        directory = _private_dir(
            _private_dir(_state_root(state_root)) / request_sha
        )
    except DispatchError as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": RESULT_KIND,
            "ok": False,
            "result_code": exc.code,
            "effect_state": "not_started",
            "retry_authorized": False,
            "authoritative_readback_required": False,
        }

    with _lock(directory):
        receipt = _receipt(
            request_sha,
            repository,
            workflow_kind,
            workflow_selector,
            ref,
            expected_head,
            inputs_meta,
            time_fn(),
        )
        prior_receipts = _prior_receipts(directory)
        prior, prior_error = _unresolved(directory, prior_receipts)
        if prior_error is not None:
            return _finish(
                directory,
                receipt,
                prior_error,
                "unknown",
                time_fn(),
            )
        workflow_info, head, error = _preflight(
            runner, repository, workflow_kind, workflow_selector, ref
        )
        if error:
            return _finish(
                directory,
                receipt,
                "prior_ambiguous_preflight_failed"
                if prior is not None
                else error["result_code"],
                "unknown" if prior is not None else error["effect_state"],
                time_fn(),
                status=error.get("http_status"),
            )
        assert workflow_info is not None and head is not None
        receipt["workflow_resolved"] = {
            "id": workflow_info["id"],
            "path": workflow_info["path"],
            "name": workflow_info.get("name"),
            "state": workflow_info["state"],
        }
        receipt["observed_head"] = head
        if prior is not None and prior.get("observed_head") != head:
            return _finish(
                directory,
                receipt,
                "prior_ambiguous_ref_drift",
                "unknown",
                time_fn(),
            )
        if expected_head is not None and head != expected_head:
            return _finish(
                directory,
                receipt,
                "ref_head_drift",
                "not_started",
                time_fn(),
            )

        rows, error = _runs(
            runner,
            repository,
            workflow_info["id"],
            workflow_info["path"],
        )
        if error:
            return _finish(
                directory,
                receipt,
                "prior_ambiguous_readback_failed"
                if prior is not None
                else error["result_code"],
                "unknown" if prior is not None else "not_started",
                time_fn(),
                status=error.get("http_status"),
            )
        assert rows is not None
        baseline = {
            run["run_id"]
            for run in rows
            if run["workflow_id"] == workflow_info["id"]
            and run["head_sha"] == head
        }
        receipt["baseline_run_ids"] = sorted(baseline)

        if prior is not None:
            prior_baseline = prior.get("baseline_run_ids")
            attempted = prior.get("dispatch_attempted_at_unix")
            prior_attempt_id = prior.get("dispatch_attempt_id")
            if (
                not isinstance(prior_baseline, list)
                or not all(
                    isinstance(item, int)
                    and not isinstance(item, bool)
                    and item > 0
                    for item in prior_baseline
                )
                or not isinstance(attempted, (int, float))
                or isinstance(attempted, bool)
                or (
                    prior_attempt_id is not None
                    and (
                        not isinstance(prior_attempt_id, str)
                        or _ATTEMPT_ID_RE.fullmatch(prior_attempt_id) is None
                    )
                )
            ):
                return _finish(
                    directory,
                    receipt,
                    "prior_ambiguous_receipt_invalid",
                    "unknown",
                    time_fn(),
                )
            if isinstance(prior_attempt_id, str):
                receipt["dispatch_attempt_id"] = prior_attempt_id
            receipt["dispatch_attempted_at_unix"] = float(attempted)
            receipt["baseline_run_ids"] = list(prior_baseline)
            run, state, error = _readback(
                runner,
                repository=repository,
                workflow_id=workflow_info["id"],
                workflow_path=workflow_info["path"],
                ref=ref,
                head=head,
                baseline=set(prior_baseline),
                attempted_at=float(attempted),
                attempts=poll_attempts,
                sleep=sleep,
                time_fn=time_fn,
            )
            if error:
                return _finish(
                    directory,
                    receipt,
                    "prior_ambiguous_readback_failed",
                    "unknown",
                    time_fn(),
                    status=error.get("http_status"),
                )
            if state == "unique" and run:
                return _finish(
                    directory,
                    receipt,
                    "dispatch_recovered_after_ambiguous_transport",
                    "observed",
                    time_fn(),
                    run=run,
                    clear_active=True,
                )
            return _finish(
                directory,
                receipt,
                "prior_ambiguous_multiple_runs"
                if state == "ambiguous"
                else "prior_ambiguous_outcome_unresolved",
                "unknown",
                time_fn(),
            )

        attempted = time_fn()
        receipt["dispatch_attempted_at_unix"] = attempted
        receipt["dispatch_attempt_id"] = uuid.uuid4().hex
        try:
            in_flight = _write_receipt(
                directory,
                {
                    **receipt,
                    "result_code": "dispatch_in_flight",
                    "effect_state": "unknown",
                    "completed_at_unix": None,
                },
            )
            _write_active_attempt(directory, in_flight)
        except (DispatchError, OSError):
            return _finish(
                directory,
                receipt,
                "dispatch_journal_failed",
                "unknown",
                time_fn(),
            )
        post, status = _post(
            runner,
            directory,
            repository,
            workflow_info["id"],
            ref,
            normalized_inputs,
        )
        terminal = {
            "auth": "github_auth_or_permission",
            "not_found": "workflow_or_ref_not_found_at_dispatch",
            "invalid_inputs": "invalid_workflow_inputs",
        }
        if post in terminal:
            return _finish(
                directory,
                receipt,
                terminal[post],
                "not_started",
                time_fn(),
                status=status,
                clear_active=True,
            )

        run, state, error = _readback(
            runner,
            repository=repository,
            workflow_id=workflow_info["id"],
            workflow_path=workflow_info["path"],
            ref=ref,
            head=head,
            baseline=baseline,
            attempted_at=attempted,
            attempts=poll_attempts,
            sleep=sleep,
            time_fn=time_fn,
        )
        if error:
            code = (
                "accepted_run_readback_failed"
                if post == "accepted"
                else "dispatch_outcome_unknown"
            )
            return _finish(
                directory,
                receipt,
                code,
                "unknown",
                time_fn(),
                status=error.get("http_status"),
            )
        if state == "unique" and run:
            code = (
                "dispatch_accepted"
                if post == "accepted"
                else "dispatch_recovered_after_ambiguous_transport"
            )
            return _finish(
                directory,
                receipt,
                code,
                "observed",
                time_fn(),
                status=status,
                run=run,
                clear_active=True,
            )
        if state == "ambiguous":
            return _finish(
                directory,
                receipt,
                "run_identity_ambiguous",
                "unknown",
                time_fn(),
                status=status,
            )
        return _finish(
            directory,
            receipt,
            "accepted_run_not_observed"
            if post == "accepted"
            else "dispatch_outcome_unknown",
            "unknown",
            time_fn(),
            status=status,
        )


def _grip_runner(
    spec: grabowski_grips.GripSpec,
    parameters: dict[str, Any],
    receipt: dict[str, Any],
    command_runner: grabowski_grips.CommandRunner,
    github_runner: grabowski_grips.GithubRunner,
) -> dict[str, Any]:
    del spec, command_runner
    unknown = sorted(set(parameters) - _ALLOWED_PARAMETERS)
    if unknown:
        raise grabowski_grips.GripPreflightError(
            f"{GRIP_NAME} received unsupported parameters: {unknown}"
        )

    result = dispatch_workflow(
        parameters.get("repository"),
        parameters.get("workflow"),
        parameters.get("ref"),
        inputs=parameters.get("inputs"),
        expected_head=parameters.get("expected_head"),
        runner=lambda args: github_runner(operator.HOME, args),
    )
    code = str(result.get("result_code", "unknown"))
    effect = result.get("effect_state")
    if parameters.get("expected_head") is not None:
        passed = (
            code == "ref_head_drift"
            or result.get("observed_head") == parameters.get("expected_head")
            or effect == "not_started"
        )
        grabowski_grips._check(
            receipt,
            "exact-head-fail-closed",
            "pass" if passed else "fail",
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
    elif effect == "unknown":
        grabowski_grips._check(
            receipt,
            "ambiguous-dedupe",
            "pass",
            "retry remains unauthorized until authoritative readback",
        )
    return {
        **result,
        "receipt_status": "passed" if result.get("ok") is True else "blocked",
        "decision": "dispatched" if result.get("ok") is True else "blocked",
        "blocked_reasons": [] if result.get("ok") is True else [code],
    }


_SPEC = grabowski_grips.GripSpec(
    name=GRIP_NAME,
    version="1.0",
    summary=(
        "Dispatch one named GitHub Actions workflow with fresh resolution, optional "
        "exact-head binding, deduplicating readback and a durable receipt."
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


def _register() -> None:
    if GRIP_NAME in grabowski_grips.GRIP_SPECS or RUNNER_NAME in grabowski_grips._RUNNERS:
        raise RuntimeError(f"{GRIP_NAME} registration collision")
    grabowski_grips.GRIP_SPECS[GRIP_NAME] = _SPEC
    grabowski_grips._RUNNERS[RUNNER_NAME] = _grip_runner
    grabowski_grips.GRIP_SURFACE_ALLOWLIST = frozenset(
        {*grabowski_grips.GRIP_SURFACE_ALLOWLIST, GRIP_NAME}
    )
    grabowski_grips.GRIP_RISK_LEVELS[GRIP_NAME] = "high"
    grabowski_grips.GRIP_SURFACE_TARGETS[GRIP_NAME] = (
        "one explicit GitHub Actions workflow dispatch"
    )
    grabowski_grips.GRIP_RECOVERY_PATHS_BY_NAME[GRIP_NAME] = (
        "inspect the nested dispatch receipt; unknown effects must be authoritatively "
        "reconciled before another dispatch"
    )


_register()

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable


SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
ALLOWED_STATUSES = frozenset(
    {
        "transition_allowed",
        "evidence_missing",
        "conflicting_evidence",
        "source_stale",
        "blocked",
        "terminally_closed",
    }
)
STATUS_EXIT_CODES = {
    "transition_allowed": 0,
    "terminally_closed": 0,
    "evidence_missing": 2,
    "conflicting_evidence": 4,
    "source_stale": 5,
    "blocked": 6,
}
EXPECTED_ASSESSMENT_KEYS = frozenset(
    {
        "assessment_id",
        "blocked_by",
        "conflicts",
        "missing_evidence",
        "profile_sha256",
        "risk_level",
        "schema_version",
        "status",
    }
)
GitRunner = Callable[[Path, list[str]], dict[str, Any]]
EvaluatorRunner = Callable[[Path, list[str]], dict[str, Any]]


class ConvergenceInputError(ValueError):
    pass


class ConvergenceExecutionError(RuntimeError):
    pass


def _protocol_repo() -> Path:
    configured = os.environ.get("GRABOWSKI_CONVERGENCE_PROTOCOL_REPO")
    value = Path(configured).expanduser() if configured else Path.home() / "repos" / "konvergenzregelkreis"
    if not value.is_absolute():
        raise ConvergenceInputError("convergence protocol repository must be absolute")
    return value.resolve()


def _protocol_executable(repo: Path) -> Path:
    configured = os.environ.get("GRABOWSKI_CONVERGENCE_EXECUTABLE")
    value = Path(configured).expanduser() if configured else repo / ".venv" / "bin" / "regelkreis"
    if not value.is_absolute():
        raise ConvergenceInputError("convergence executable must be absolute")
    return value


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ConvergenceInputError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_git_oid(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or GIT_OID_RE.fullmatch(value) is None:
        raise ConvergenceInputError(f"{label} must be a lowercase 40- or 64-character Git object id")
    return value


def _read_regular_file(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConvergenceInputError(f"{label} cannot be opened safely: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ConvergenceInputError(f"{label} must be a regular file")
        if before.st_size <= 0 or before.st_size > maximum:
            raise ConvergenceInputError(f"{label} size is outside the accepted bound")
        chunks: list[bytes] = []
        size = 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise ConvergenceInputError(f"{label} exceeds the accepted bound")
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ConvergenceInputError(f"{label} changed while being read")
    return data


def _read_bound_request(path_value: Any, expected_sha256: str) -> tuple[Path, bytes]:
    if not isinstance(path_value, str) or not path_value.strip():
        raise ConvergenceInputError("request_path must be a non-empty absolute path")
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        raise ConvergenceInputError("request_path must be absolute")
    data = _read_regular_file(path, maximum=MAX_REQUEST_BYTES, label="request_path")
    actual_sha256 = hashlib.sha256(data).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ConvergenceInputError(
            "request_path SHA-256 does not match expected_request_sha256"
        )
    try:
        parsed = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConvergenceInputError("request_path is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ConvergenceInputError("request_path must contain a JSON object")
    return path.resolve(), data


def _run_checked(runner: Callable[[Path, list[str]], dict[str, Any]], cwd: Path, argv: list[str], *, label: str) -> dict[str, Any]:
    result = runner(cwd, argv)
    if not isinstance(result, dict):
        raise ConvergenceExecutionError(f"{label} runner returned a non-object")
    returncode = result.get("returncode")
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    if not isinstance(returncode, int) or not isinstance(stdout, str) or not isinstance(stderr, str):
        raise ConvergenceExecutionError(f"{label} runner returned an invalid shape")
    return result


def _validate_protocol_identity(
    runner: GitRunner,
    repo: Path,
    executable: Path,
    expected_head: str,
) -> tuple[str, str]:
    if not repo.is_dir():
        raise ConvergenceInputError("convergence protocol repository does not exist")
    executable_bytes = _read_regular_file(
        executable,
        maximum=MAX_EXECUTABLE_BYTES,
        label="convergence executable",
    )
    executable_sha256 = hashlib.sha256(executable_bytes).hexdigest()

    head_result = _run_checked(runner, repo, ["rev-parse", "HEAD"], label="protocol head")
    if head_result["returncode"] != 0:
        raise ConvergenceExecutionError(head_result["stderr"] or "protocol head lookup failed")
    observed_head = head_result["stdout"].strip()
    if observed_head != expected_head:
        raise ConvergenceInputError(
            f"convergence protocol head mismatch: observed={observed_head} expected={expected_head}"
        )
    status_result = _run_checked(
        runner,
        repo,
        ["status", "--porcelain=v1", "--untracked-files=normal"],
        label="protocol status",
    )
    if status_result["returncode"] != 0:
        raise ConvergenceExecutionError(status_result["stderr"] or "protocol status lookup failed")
    if status_result["stdout"].strip():
        raise ConvergenceInputError("convergence protocol repository is dirty")
    return observed_head, executable_sha256


def _validate_assessment(value: Any, returncode: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != EXPECTED_ASSESSMENT_KEYS:
        raise ConvergenceExecutionError("convergence evaluator returned an unexpected assessment shape")
    status_value = value.get("status")
    if not isinstance(status_value, str) or status_value not in ALLOWED_STATUSES:
        raise ConvergenceExecutionError("convergence evaluator returned an unsupported status")
    if STATUS_EXIT_CODES[status_value] != returncode:
        raise ConvergenceExecutionError("convergence evaluator status and exit code disagree")
    if value.get("schema_version") != 1:
        raise ConvergenceExecutionError("convergence evaluator schema version is unsupported")
    for field in ("blocked_by", "conflicts", "missing_evidence"):
        items = value.get(field)
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise ConvergenceExecutionError(f"convergence evaluator field {field} is invalid")
    for field in ("assessment_id", "profile_sha256", "risk_level"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ConvergenceExecutionError(f"convergence evaluator field {field} is invalid")
    _validate_sha256(value["profile_sha256"], label="assessment.profile_sha256")
    return value


def _default_evaluator_runner(cwd: Path, argv: list[str]) -> dict[str, Any]:
    env = {
        "HOME": str(Path.home()),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
    }
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": "convergence evaluator timed out"}
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout[: 1024 * 1024],
        "stderr": completed.stderr[: 64 * 1024],
    }


def assess(
    parameters: dict[str, Any],
    runner: GitRunner,
    evaluator_runner: EvaluatorRunner | None = None,
) -> dict[str, Any]:
    expected_request_sha256 = _validate_sha256(
        parameters.get("expected_request_sha256"), label="expected_request_sha256"
    )
    expected_protocol_head = _validate_git_oid(
        parameters.get("expected_protocol_head"), label="expected_protocol_head"
    )
    request_path, request_bytes = _read_bound_request(
        parameters.get("request_path"), expected_request_sha256
    )
    repo = _protocol_repo()
    executable = _protocol_executable(repo)
    observed_head, executable_sha256 = _validate_protocol_identity(
        runner, repo, executable, expected_protocol_head
    )
    result = _run_checked(
        evaluator_runner or _default_evaluator_runner,
        repo,
        [str(executable), "evaluate", str(request_path)],
        label="convergence evaluation",
    )
    if result["returncode"] not in set(STATUS_EXIT_CODES.values()):
        detail = result["stderr"].strip() or f"unexpected exit code {result['returncode']}"
        raise ConvergenceExecutionError(f"convergence evaluation failed: {detail}")
    try:
        parsed = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        raise ConvergenceExecutionError("convergence evaluator returned invalid JSON") from exc
    assessment = _validate_assessment(parsed, result["returncode"])
    post_head, post_executable_sha256 = _validate_protocol_identity(
        runner, repo, executable, expected_protocol_head
    )
    if post_head != observed_head or post_executable_sha256 != executable_sha256:
        raise ConvergenceExecutionError(
            "convergence protocol identity changed during evaluation"
        )
    closure_allowed = assessment["status"] == "terminally_closed"
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski.convergence_assessment",
        "request_path": str(request_path),
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "protocol_repo": str(repo),
        "protocol_head": observed_head,
        "executable_sha256": executable_sha256,
        "assessment": assessment,
        "closure_allowed": closure_allowed,
        "decision": "allow_closure" if closure_allowed else "block_closure",
        "does_not_establish": [
            "task state",
            "merge authorization",
            "deployment truth beyond supplied receipts",
            "runtime truth beyond supplied receipts",
            "Bureau completion",
            "Chronik persistence",
        ],
    }

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import stat
import time
from typing import Annotated, Any, Iterator

from mcp.types import ToolAnnotations
from pydantic import Field

import grabowski_mcp as base
import grabowski_operator_core as operator
import grabowski_read_surface as read_surface


mcp = operator.mcp

DEPLOY_MUTATING = ToolAnnotations(
    title="Schedule verified Grabowski runtime deployment",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
ExpectedHead = Annotated[
    str,
    Field(
        min_length=40,
        max_length=64,
        pattern=OBJECT_ID_RE.pattern,
    ),
]
DelaySeconds = Annotated[int, Field(ge=5, le=60)]
CANONICAL_REPOSITORY = Path.home() / "repos/grabowski"
RUNNER_RELATIVE_PATH = Path("tools/run_scheduled_deploy.py")
DEPLOY_SCHEDULE_LOCK = Path.home() / ".local/state/grabowski/runtime-deploy-schedule.lock"
DEPLOY_JOB_PREFIX = operator.JOB_PREFIX
DEPLOY_JOB_ROOT = operator.JOBS_DIR
DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS = 10.0
DEPLOY_SCHEDULE_LOCK_POLL_SECONDS = 0.05
MAX_JOB_SCAN_ENTRIES = 2_000
REUSABLE_JOB_STATUSES = frozenset({"running"})
TERMINAL_JOB_STATUSES = frozenset({"completed", "succeeded", "failed", "launch_failed"})


def _git_result(repository: Path, *arguments: str) -> dict[str, Any]:
    return read_surface._run_read(
        read_surface._git_command(repository, *arguments),
        cwd=repository,
        timeout_seconds=30,
        max_output_bytes=65_536,
    )


def _required_stdout(result: dict[str, Any], label: str) -> str:
    if result["returncode"] != 0 or result["timed_out"]:
        message = result["stderr"].strip() or result["stdout"].strip()
        raise RuntimeError(message or f"{label} failed")
    if result["stdout_truncated"] or result["stderr_truncated"]:
        raise RuntimeError(f"{label} output exceeded the preflight bound")
    return result["stdout"].strip()


def _deploy_command(repository: Path, runner: Path, expected_head: str, delay_seconds: int) -> list[str]:
    return [
        "/usr/bin/python3",
        str(runner),
        "--repo",
        str(repository),
        "--expected-head",
        expected_head,
        "--delay-seconds",
        str(delay_seconds),
    ]


def _deploy_command_sha256(command: list[str]) -> str:
    return operator._argv_hash(command)


def _deploy_command_fields(command: Any) -> dict[str, str] | None:
    if (
        not isinstance(command, list)
        or len(command) != 8
        or not all(isinstance(item, str) for item in command)
        or command[0] != "/usr/bin/python3"
    ):
        return None
    values: dict[str, str] = {}
    allowed = {"--repo", "--expected-head", "--delay-seconds"}
    for index in range(2, len(command), 2):
        option = command[index]
        if option not in allowed or option in values:
            return None
        values[option] = command[index + 1]
    if set(values) != allowed or not OBJECT_ID_RE.fullmatch(values["--expected-head"]):
        return None
    try:
        delay_seconds = int(values["--delay-seconds"])
    except ValueError:
        return None
    if not 5 <= delay_seconds <= 60:
        return None
    return {
        "python": command[0],
        "runner": command[1],
        "repository": values["--repo"],
        "expected_head": values["--expected-head"],
        "delay_seconds": str(delay_seconds),
    }


def _deploy_identity(command: Any) -> tuple[str, ...] | None:
    fields = _deploy_command_fields(command)
    if fields is None:
        return None
    return (
        fields["python"],
        fields["runner"],
        fields["repository"],
        fields["expected_head"],
    )


@contextmanager
def _deploy_schedule_lock() -> Iterator[None]:
    parent = DEPLOY_SCHEDULE_LOCK.parent
    if parent.is_symlink():
        raise PermissionError(f"runtime deploy lock directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if DEPLOY_SCHEDULE_LOCK.is_symlink():
        raise PermissionError(f"runtime deploy lock may not be a symlink: {DEPLOY_SCHEDULE_LOCK}")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(DEPLOY_SCHEDULE_LOCK, flags, 0o600)
    locked = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != os.getuid():
            raise PermissionError("runtime deploy lock must be one owner-controlled regular file")
        deadline = time.monotonic() + DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("runtime deploy schedule lock acquisition timed out") from exc
                time.sleep(DEPLOY_SCHEDULE_LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _durable_job_unit(name: str) -> bool:
    return re.fullmatch(rf"{re.escape(DEPLOY_JOB_PREFIX)}[0-9a-f]{{12}}", name) is not None


def _validated_deploy_job_receipt(entry: Path, metadata: dict[str, Any]) -> dict[str, str]:
    expected_receipt = metadata.get("expected_receipt")
    if not isinstance(expected_receipt, dict):
        raise RuntimeError(f"deploy job receipt is unavailable: {entry.name}")
    expected = {
        "unit": entry.name,
        "metadata_path": str(entry / "metadata.json"),
        "stdout_path": str(entry / "stdout.log"),
        "stderr_path": str(entry / "stderr.log"),
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
    }
    for key, value in expected.items():
        if expected_receipt.get(key) != value:
            raise RuntimeError(f"deploy job receipt {key} is not bound to {entry.name}")
    return {
        "metadata_path": expected["metadata_path"],
        "stdout_path": expected["stdout_path"],
        "stderr_path": expected["stderr_path"],
    }


def _matching_inflight_deploy_job(command: list[str], repository: Path) -> dict[str, Any] | None:
    expected_identity = _deploy_identity(command)
    if expected_identity is None:
        raise ValueError("runtime deploy command identity is invalid")
    expected_runner = str(repository / RUNNER_RELATIVE_PATH)
    jobs_root = operator._jobs_root()
    entries = sorted(
        (entry for entry in jobs_root.iterdir() if _durable_job_unit(entry.name)),
        key=lambda path: path.name,
    )
    if len(entries) > MAX_JOB_SCAN_ENTRIES:
        raise RuntimeError("job registry exceeds the bounded runtime deploy deduplication scan")

    matches: list[dict[str, Any]] = []
    for entry in reversed(entries):
        if entry.is_symlink() or not entry.is_dir():
            raise RuntimeError(f"durable job entry is not a real directory: {entry.name}")
        try:
            metadata = operator._read_job_metadata(entry.name)
        except (OSError, ValueError, PermissionError) as exc:
            raise RuntimeError(f"durable job metadata is unreadable: {entry.name}") from exc
        candidate_command = metadata.get("argv")
        if not isinstance(candidate_command, list) or not all(
            isinstance(item, str) for item in candidate_command
        ):
            raise RuntimeError(f"durable job argv is malformed: {entry.name}")
        references_self_deploy = (
            len(candidate_command) >= 2
            and candidate_command[0] == "/usr/bin/python3"
            and candidate_command[1] == expected_runner
        )
        if not references_self_deploy:
            continue
        candidate_fields = _deploy_command_fields(candidate_command)
        candidate_identity = _deploy_identity(candidate_command)
        if candidate_fields is None or candidate_identity is None or metadata.get("cwd") != str(repository):
            raise RuntimeError(f"self deploy job metadata is malformed: {entry.name}")
        argv_sha256 = metadata.get("argv_sha256")
        if argv_sha256 != _deploy_command_sha256(candidate_command):
            raise RuntimeError(f"self deploy job command hash mismatch: {entry.name}")
        status = operator.grabowski_job_status(entry.name)
        if not isinstance(status, dict):
            raise RuntimeError(f"self deploy job status is unavailable: {entry.name}")
        final_status = status.get("final_status")
        if final_status in TERMINAL_JOB_STATUSES:
            continue
        if final_status not in REUSABLE_JOB_STATUSES:
            raise RuntimeError(
                f"self deploy job has an uncertain non-reusable outcome: {entry.name} ({final_status})"
            )
        if candidate_identity != expected_identity:
            raise RuntimeError(
                f"another Grabowski self deploy is already running for a different head: {entry.name}"
            )
        receipt_paths = _validated_deploy_job_receipt(entry, metadata)
        matches.append(
            {
                "unit": entry.name,
                "argv_sha256": argv_sha256,
                "delay_seconds": int(candidate_fields["delay_seconds"]),
                **receipt_paths,
                "final_status": final_status,
            }
        )

    if len(matches) > 1:
        units = ", ".join(sorted(item["unit"] for item in matches))
        raise RuntimeError(f"multiple identical Grabowski self deploy jobs are running: {units}")
    return matches[0] if matches else None


def _schedule_result(
    *,
    expected_head: str,
    requested_delay_seconds: int,
    effective_delay_seconds: int,
    job: dict[str, Any],
    intent: dict[str, Any] | None,
    scheduled: dict[str, Any],
    already_scheduled: bool,
) -> dict[str, Any]:
    return {
        "scheduled": True,
        "already_scheduled": already_scheduled,
        "expected_head": expected_head,
        "requested_delay_seconds": requested_delay_seconds,
        "delay_seconds": effective_delay_seconds,
        "unit": job["unit"],
        "argv_sha256": job["argv_sha256"],
        "metadata_path": job["metadata_path"],
        "stdout_path": job["stdout_path"],
        "stderr_path": job["stderr_path"],
        "expected_connector_disconnect": True,
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
        "audit": {
            "intent": intent,
            "scheduled": scheduled,
        },
    }


def _canonical_preflight(expected_head: str) -> tuple[Path, Path]:
    if not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")

    raw_repository = CANONICAL_REPOSITORY
    if raw_repository.is_symlink() or not raw_repository.is_dir():
        raise RuntimeError(f"canonical repository is unavailable: {raw_repository}")
    repository = raw_repository.resolve(strict=True)
    if repository != raw_repository:
        raise RuntimeError("canonical repository path must not traverse a symlink")

    head = _required_stdout(
        _git_result(repository, "rev-parse", "--verify", "HEAD"),
        "HEAD lookup",
    )
    branch = _required_stdout(
        _git_result(repository, "symbolic-ref", "--short", "HEAD"),
        "branch lookup",
    )
    origin_main = _required_stdout(
        _git_result(
            repository,
            "rev-parse",
            "--verify",
            "refs/remotes/origin/main",
        ),
        "origin/main lookup",
    )
    status = _required_stdout(
        _git_result(
            repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ),
        "working-tree status",
    )

    if head != expected_head:
        raise RuntimeError(f"HEAD drift: expected {expected_head}, found {head}")
    if branch != "main":
        raise RuntimeError(f"canonical checkout is not on main: {branch}")
    if origin_main != expected_head:
        raise RuntimeError(
            f"origin/main drift: expected {expected_head}, found {origin_main}"
        )
    if status:
        raise RuntimeError("canonical checkout is dirty")

    runner = repository / RUNNER_RELATIVE_PATH
    if runner.is_symlink() or not runner.is_file():
        raise RuntimeError(f"scheduled deployment runner is unavailable: {runner}")
    return repository, runner


@mcp.tool(name="grabowski_runtime_deploy_schedule", annotations=DEPLOY_MUTATING)
def grabowski_runtime_deploy_schedule(
    expected_head: ExpectedHead,
    delay_seconds: DelaySeconds = 8,
) -> dict[str, Any]:
    """Schedule one validated self-deployment, reusing an identical in-flight job."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_capability("git_cli")
    repository, runner = _canonical_preflight(expected_head)
    command = _deploy_command(repository, runner, expected_head, delay_seconds)

    with _deploy_schedule_lock():
        existing = _matching_inflight_deploy_job(command, repository)
        if existing is not None:
            observed = {
                "timestamp_unix": int(time.time()),
                "operation": "runtime-deploy-existing-schedule-observed",
                "expected_head": expected_head,
                "requested_delay_seconds": delay_seconds,
                "delay_seconds": existing["delay_seconds"],
                "unit": existing["unit"],
                "argv_sha256": existing["argv_sha256"],
                "final_status": existing["final_status"],
            }
            base._append_audit(observed)
            return _schedule_result(
                expected_head=expected_head,
                requested_delay_seconds=delay_seconds,
                effective_delay_seconds=existing["delay_seconds"],
                job=existing,
                intent=None,
                scheduled=observed,
                already_scheduled=True,
            )

        intent = {
            "timestamp_unix": int(time.time()),
            "operation": "runtime-deploy-schedule-intent",
            "expected_head": expected_head,
            "delay_seconds": delay_seconds,
        }
        base._append_audit(intent)
        job = operator._start_job(
            command,
            cwd=str(repository),
            runtime_seconds=3_600,
            finalization_expected_head=expected_head,
        )
        scheduled = {
            "timestamp_unix": int(time.time()),
            "operation": "runtime-deploy-scheduled",
            "expected_head": expected_head,
            "delay_seconds": delay_seconds,
            "unit": job["unit"],
            "argv_sha256": job["argv_sha256"],
        }
        base._append_audit(scheduled)
        return _schedule_result(
            expected_head=expected_head,
            requested_delay_seconds=delay_seconds,
            effective_delay_seconds=delay_seconds,
            job=job,
            intent=intent,
            scheduled=scheduled,
            already_scheduled=False,
        )

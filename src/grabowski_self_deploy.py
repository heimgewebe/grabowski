from __future__ import annotations

from pathlib import Path
import re
import time
from typing import Annotated, Any

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
    """Schedule a validated self-deployment in an independent delayed systemd job."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_capability("git_cli")
    repository, runner = _canonical_preflight(expected_head)

    intent = {
        "timestamp_unix": int(time.time()),
        "operation": "runtime-deploy-schedule-intent",
        "expected_head": expected_head,
        "delay_seconds": delay_seconds,
    }
    base._append_audit(intent)

    job = operator.grabowski_job_start(
        [
            "/usr/bin/python3",
            str(runner),
            "--repo",
            str(repository),
            "--expected-head",
            expected_head,
            "--delay-seconds",
            str(delay_seconds),
        ],
        cwd=str(repository),
        runtime_seconds=3_600,
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
    return {
        "scheduled": True,
        "expected_head": expected_head,
        "delay_seconds": delay_seconds,
        "unit": job["unit"],
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

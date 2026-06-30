from __future__ import annotations

import argparse
import json
from typing import Sequence

import grabowski_tasks


MODE_CHECK = "check"
MODE_REFRESH = "refresh"
MODE_RESUME = "resume"
MAX_RESUMES_LIMIT = 50


def _bounded_max_resumes(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "--max-resumes must be an integer between 1 and 50"
        ) from exc
    if not 1 <= parsed <= MAX_RESUMES_LIMIT:
        raise argparse.ArgumentTypeError(
            "--max-resumes must be an integer between 1 and 50"
        )
    return parsed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Reconcile persistent Grabowski task records with user systemd units."
    )
    result.add_argument(
        "--mode",
        choices=(MODE_CHECK, MODE_REFRESH, MODE_RESUME),
        default=MODE_REFRESH,
        help=(
            "Reconcile mode: check previews only, refresh updates observed task state "
            "without process starts, resume explicitly restarts bounded retry-safe tasks."
        ),
    )
    result.add_argument(
        "--task-id",
        default="",
        help="Optional 24-hex task id. Defaults to all eligible task records.",
    )
    result.add_argument(
        "--max-resumes",
        type=_bounded_max_resumes,
        default=1,
        help="Maximum tasks to resume in resume mode. Must be between 1 and 50.",
    )
    result.add_argument(
        "--reason",
        default="",
        help="Required human/operator reason for resume mode.",
    )
    result.add_argument(
        "--expected-state-hash",
        default="",
        help=(
            "Reserved precondition for a future stable task state hash. The current "
            "task record model does not expose such a hash."
        ),
    )
    result.add_argument(
        "--auto-resume",
        action="store_true",
        help=(
            "Deprecated unsafe legacy alias. Rejected; use --mode resume with "
            "--reason and bounded --max-resumes."
        ),
    )
    return result


def _append_resume_audit(arguments: argparse.Namespace, result: dict[str, object]) -> None:
    grabowski_tasks.base._append_audit(
        {
            "timestamp_unix": result["checked_at_unix"],
            "operation": "task-reconcile-resume",
            "mode": MODE_RESUME,
            "task_id": arguments.task_id,
            "reason": result["reason"],
            "max_resumes": arguments.max_resumes,
            "resumed_count": len(result["resumed"]),
            "blocked_count": len(result["blocked"]),
        }
    )


def run(arguments: argparse.Namespace) -> dict[str, object]:
    if arguments.auto_resume:
        raise ValueError(
            "--auto-resume is deprecated for CLI/systemd use; use --mode resume "
            "with --reason and bounded --max-resumes"
        )
    if arguments.expected_state_hash:
        raise ValueError(
            "--expected-state-hash is not supported by the current task state model"
        )
    if arguments.mode == MODE_CHECK:
        return grabowski_tasks.reconcile_tasks_check(task_id=arguments.task_id)
    if arguments.mode == MODE_REFRESH:
        return grabowski_tasks.reconcile_tasks_refresh(task_id=arguments.task_id)
    if arguments.mode == MODE_RESUME:
        if not arguments.reason.strip():
            raise ValueError("--reason is required for --mode resume")
        result = grabowski_tasks.reconcile_tasks_resume(
            task_id=arguments.task_id,
            max_resumes=arguments.max_resumes,
            reason=arguments.reason,
        )
        _append_resume_audit(arguments, result)
        return result
    raise ValueError(f"Unsupported reconcile mode: {arguments.mode}")


def main(argv: Sequence[str] | None = None) -> int:
    cli = parser()
    arguments = cli.parse_args(argv)
    try:
        result = run(arguments)
    except ValueError as exc:
        cli.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

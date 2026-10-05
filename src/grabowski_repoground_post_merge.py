from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable, Mapping

REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
DEFAULT_PUBLISHER = Path.home() / ".local" / "bin" / "repoground-publish-fleet"
DEFAULT_MAX_ATTEMPTS = 8
DEFAULT_BUSY_SLEEP_SECONDS = 15.0
DEFAULT_PUBLISH_TIMEOUT_SECONDS = 900
MAX_PUBLISH_OUTPUT_BYTES = 2 * 1024 * 1024

PublisherRunner = Callable[[list[str], int], dict[str, Any]]
FreshnessReader = Callable[[str], dict[str, Any]]
SleepFn = Callable[[float], None]
AncestryChecker = Callable[[str, str, str], bool]
JobStarter = Callable[..., dict[str, Any]]


def resolve_job_starter(modules: Mapping[str, Any]) -> JobStarter | None:
    operator_module = modules.get("grabowski_operator")
    starter = getattr(operator_module, "grabowski_job_start", None)
    if callable(starter):
        return starter

    main_module = modules.get("__main__")
    main_spec = getattr(main_module, "__spec__", None)
    if getattr(main_spec, "name", None) != "grabowski_operator":
        return None
    starter = getattr(main_module, "grabowski_job_start", None)
    return starter if callable(starter) else None


FOLLOWUP_KIND = "grabowski.repoground_post_merge_followup"
DEFAULT_JOB_RUNTIME_SECONDS = 9_000


class RepoGroundPostMergeError(RuntimeError):
    pass


def _validate_repository(value: str) -> str:
    if not isinstance(value, str) or REPOSITORY_RE.fullmatch(value) is None:
        raise RepoGroundPostMergeError("repository must be owner/repository")
    return value


def _validate_sha(value: str) -> str:
    value = str(value).lower()
    if SHA40_RE.fullmatch(value) is None:
        raise RepoGroundPostMergeError(
            "merge_sha must be a lowercase 40-character Git SHA"
        )
    return value


def _publisher_command(publisher: Path, repository: str) -> list[str]:
    return [
        str(publisher),
        "--repo",
        repository,
        "--if-changed",
        "--retention",
        "3",
    ]


def _run_publisher(argv: list[str], timeout_seconds: int) -> dict[str, Any]:
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout_seconds,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    if len(stdout.encode("utf-8")) > MAX_PUBLISH_OUTPUT_BYTES:
        raise RepoGroundPostMergeError(
            "RepoGround publisher stdout exceeds bounded output"
        )
    if len(stderr.encode("utf-8")) > MAX_PUBLISH_OUTPUT_BYTES:
        raise RepoGroundPostMergeError(
            "RepoGround publisher stderr exceeds bounded output"
        )
    payload: Any = None
    if stdout.strip():
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RepoGroundPostMergeError(
                "RepoGround publisher returned malformed JSON"
            ) from exc
    return {
        "returncode": completed.returncode,
        "payload": payload,
        "stderr": stderr[-4000:],
    }


def _read_freshness(repository: str) -> dict[str, Any]:
    import grabowski_mcp

    value = grabowski_mcp.repoground_freshness_check(repository)
    if not isinstance(value, dict):
        raise RepoGroundPostMergeError("RepoGround freshness response is not an object")
    return value


def _check_ancestry(repo_path: str, merge_sha: str, live_head: str) -> bool:
    completed = subprocess.run(
        ["git", "-C", repo_path, "merge-base", "--is-ancestor", merge_sha, live_head],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RepoGroundPostMergeError(
        "Git ancestry check failed: " + completed.stderr[-1000:]
    )


def _freshness_projection(value: dict[str, Any]) -> dict[str, Any]:
    bundle = value.get("bundle")
    live = value.get("live_repo")
    branch = (
        live.get("branch_head_observation")
        if isinstance(live, dict)
        and isinstance(live.get("branch_head_observation"), dict)
        else {}
    )
    return {
        "freshness": value.get("freshness"),
        "freshness_status": value.get("freshness_status"),
        "reason": value.get("reason"),
        "bundle_commit": bundle.get("git_commit") if isinstance(bundle, dict) else None,
        "live_head": live.get("head") if isinstance(live, dict) else None,
        "remote_head": branch.get("head"),
        "repo_path": live.get("repo_path") if isinstance(live, dict) else None,
    }


def _fresh_exact(
    freshness: dict[str, Any],
    *,
    merge_sha: str,
    ancestry_checker: AncestryChecker,
) -> tuple[bool, dict[str, Any]]:
    projection = _freshness_projection(freshness)
    bundle_commit = projection["bundle_commit"]
    live_head = projection["live_head"]
    remote_head = projection["remote_head"]
    repo_path = projection["repo_path"]
    exact = (
        freshness.get("freshness") == "fresh_exact"
        and freshness.get("freshness_status") == "fresh"
        and isinstance(bundle_commit, str)
        and isinstance(live_head, str)
        and isinstance(remote_head, str)
        and bundle_commit == live_head == remote_head
        and isinstance(repo_path, str)
        and bool(repo_path)
    )
    if not exact:
        projection["merge_is_ancestor"] = None
        return False, projection
    projection["merge_is_ancestor"] = ancestry_checker(repo_path, merge_sha, live_head)
    return projection["merge_is_ancestor"] is True, projection


def converge(
    *,
    repository: str,
    merge_sha: str,
    publisher: Path = DEFAULT_PUBLISHER,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    busy_sleep_seconds: float = DEFAULT_BUSY_SLEEP_SECONDS,
    publish_timeout_seconds: int = DEFAULT_PUBLISH_TIMEOUT_SECONDS,
    publisher_runner: PublisherRunner = _run_publisher,
    freshness_reader: FreshnessReader = _read_freshness,
    ancestry_checker: AncestryChecker = _check_ancestry,
    sleep_fn: SleepFn = time.sleep,
) -> dict[str, Any]:
    repository = _validate_repository(repository)
    merge_sha = _validate_sha(merge_sha)
    if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 32:
        raise RepoGroundPostMergeError("max_attempts must be between 1 and 32")
    if busy_sleep_seconds < 0 or busy_sleep_seconds > 300:
        raise RepoGroundPostMergeError("busy_sleep_seconds is out of bounds")
    if (
        type(publish_timeout_seconds) is not int
        or publish_timeout_seconds < 1
        or publish_timeout_seconds > 3600
    ):
        raise RepoGroundPostMergeError("publish_timeout_seconds is out of bounds")

    attempts: list[dict[str, Any]] = []
    argv = _publisher_command(publisher, repository)
    for attempt in range(1, max_attempts + 1):
        publish = publisher_runner(argv, publish_timeout_seconds)
        payload = publish.get("payload")
        returncode = publish.get("returncode")
        if not isinstance(payload, dict):
            raise RepoGroundPostMergeError(
                "RepoGround publisher returned no JSON object"
            )
        publisher_status = payload.get("status")
        attempt_record: dict[str, Any] = {
            "attempt": attempt,
            "publisher_status": publisher_status,
            "publisher_returncode": returncode,
        }
        attempts.append(attempt_record)

        if publisher_status == "busy":
            if returncode != 0:
                raise RepoGroundPostMergeError(
                    "RepoGround publisher reported busy with a failing exit code"
                )
            if attempt == max_attempts:
                return {
                    "kind": "grabowski.repoground_post_merge_freshness",
                    "schema_version": 1,
                    "status": "failed",
                    "reason": "publisher_busy_exhausted",
                    "repository": repository,
                    "merge_sha": merge_sha,
                    "attempts": attempts,
                }
            sleep_fn(busy_sleep_seconds)
            continue

        if returncode != 0 or publisher_status not in {"ok", "success"}:
            return {
                "kind": "grabowski.repoground_post_merge_freshness",
                "schema_version": 1,
                "status": "failed",
                "reason": "publisher_failed",
                "repository": repository,
                "merge_sha": merge_sha,
                "attempts": attempts,
                "publisher_error": str(publish.get("stderr") or "")[-1000:],
            }

        freshness = freshness_reader(repository)
        exact, projection = _fresh_exact(
            freshness,
            merge_sha=merge_sha,
            ancestry_checker=ancestry_checker,
        )
        attempt_record["freshness"] = projection
        if exact:
            return {
                "kind": "grabowski.repoground_post_merge_freshness",
                "schema_version": 1,
                "status": "fresh_exact",
                "repository": repository,
                "merge_sha": merge_sha,
                "attempts": attempts,
                "final": projection,
            }
        if projection.get("merge_is_ancestor") is False:
            return {
                "kind": "grabowski.repoground_post_merge_freshness",
                "schema_version": 1,
                "status": "failed",
                "reason": "merge_not_ancestor_of_live_head",
                "repository": repository,
                "merge_sha": merge_sha,
                "attempts": attempts,
                "final": projection,
            }
        if attempt < max_attempts:
            continue

    return {
        "kind": "grabowski.repoground_post_merge_freshness",
        "schema_version": 1,
        "status": "failed",
        "reason": "freshness_not_converged",
        "repository": repository,
        "merge_sha": merge_sha,
        "attempts": attempts,
    }


def _captain_pr_merge_execution(result: dict[str, Any]) -> dict[str, Any] | None:
    output = result.get("output")
    executions = output.get("executions") if isinstance(output, dict) else None
    if not isinstance(executions, list):
        return None
    matches = [
        item
        for item in executions
        if isinstance(item, dict) and item.get("action") == "pr-merge"
    ]
    return matches[0] if len(matches) == 1 else None


def _verified_merge_sha(execution: dict[str, Any]) -> str | None:
    viewed = execution.get("verified_pr")
    merge_commit = viewed.get("mergeCommit") if isinstance(viewed, dict) else None
    if isinstance(merge_commit, dict):
        oid = merge_commit.get("oid")
        if isinstance(oid, str) and SHA40_RE.fullmatch(oid.lower()) is not None:
            return oid.lower()

    reconciliation = execution.get("post_merge_reconciliation")
    if (
        isinstance(reconciliation, dict)
        and reconciliation.get("status")
        == "verified_base_mutation_pr_metadata_unsettled"
        and reconciliation.get("errors") in (None, [])
    ):
        merge_sha = reconciliation.get("merge_sha")
        if (
            isinstance(merge_sha, str)
            and SHA40_RE.fullmatch(merge_sha.lower()) is not None
        ):
            return merge_sha.lower()
    return None


def _followup_base(
    *,
    status: str,
    reason: str,
    repository: str | None = None,
    merge_sha: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": FOLLOWUP_KIND,
        "schema_version": 1,
        "status": status,
        "reason": reason,
    }
    if repository is not None:
        result["repository"] = repository
    if merge_sha is not None:
        result["merge_sha"] = merge_sha
    return result


def captain_followup_request(
    result: dict[str, Any],
    *,
    python_executable: str,
    script_path: Path,
) -> dict[str, Any]:
    execution = _captain_pr_merge_execution(result)
    if execution is None:
        return _followup_base(
            status="not_applicable",
            reason="single_pr_merge_execution_absent",
        )

    repository = execution.get("repo")
    if not isinstance(repository, str) or REPOSITORY_RE.fullmatch(repository) is None:
        return _followup_base(
            status="not_scheduled",
            reason="repository_identity_invalid",
        )

    if execution.get("verification_passed") is not True:
        return _followup_base(
            status="not_scheduled",
            reason="merge_verification_not_passed",
            repository=repository,
        )

    if execution.get("merge_completion_verified") is not True:
        return _followup_base(
            status=(
                "pending_merge_queue"
                if execution.get("merge_queued") is True
                else "not_scheduled"
            ),
            reason=(
                "merge_queued_not_completed"
                if execution.get("merge_queued") is True
                else "merge_completion_not_verified"
            ),
            repository=repository,
        )

    merge_sha = _verified_merge_sha(execution)
    if merge_sha is None:
        return _followup_base(
            status="not_scheduled",
            reason="verified_merge_sha_unavailable",
            repository=repository,
        )

    executable = str(python_executable)
    if not executable or "\x00" in executable:
        raise RepoGroundPostMergeError("python executable is invalid")
    script = Path(script_path).expanduser().resolve(strict=True)
    if not script.is_file():
        raise RepoGroundPostMergeError("RepoGround post-merge script is unavailable")

    return {
        **_followup_base(
            status="ready",
            reason="verified_merge_ready_for_freshness",
            repository=repository,
            merge_sha=merge_sha,
        ),
        "argv": [
            executable,
            "-B",
            str(script),
            "--repo",
            repository,
            "--merge-sha",
            merge_sha,
        ],
        "cwd": str(script.parent),
    }


def schedule_from_captain_result(
    result: dict[str, Any],
    *,
    job_starter: JobStarter,
    python_executable: str,
    script_path: Path,
    runtime_seconds: int = DEFAULT_JOB_RUNTIME_SECONDS,
) -> dict[str, Any]:
    request = captain_followup_request(
        result,
        python_executable=python_executable,
        script_path=script_path,
    )
    if request.get("status") != "ready":
        return request
    if (
        type(runtime_seconds) is not int
        or runtime_seconds < 60
        or runtime_seconds > 21_600
    ):
        raise RepoGroundPostMergeError("job runtime is out of bounds")

    try:
        job = job_starter(
            list(request["argv"]),
            cwd=str(request["cwd"]),
            runtime_seconds=runtime_seconds,
        )
    except Exception as exc:
        unit = getattr(exc, "unit", None)
        return {
            **_followup_base(
                status="schedule_unknown"
                if isinstance(unit, str) and unit
                else "schedule_error",
                reason="durable_job_start_failed",
                repository=str(request["repository"]),
                merge_sha=str(request["merge_sha"]),
            ),
            "error_class": type(exc).__name__,
            **({"unit": unit} if isinstance(unit, str) and unit else {}),
            "does_not_establish": [
                "job_not_started",
                "freshness_failed",
                "merge_failure",
            ],
        }

    if not isinstance(job, dict):
        return {
            **_followup_base(
                status="schedule_unknown",
                reason="durable_job_start_result_invalid",
                repository=str(request["repository"]),
                merge_sha=str(request["merge_sha"]),
            ),
            "does_not_establish": [
                "job_not_started",
                "freshness_failed",
                "merge_failure",
            ],
        }
    unit = job.get("unit")
    if not isinstance(unit, str) or not unit.startswith("grabowski-job-"):
        return {
            **_followup_base(
                status="schedule_unknown",
                reason="durable_job_identity_unavailable",
                repository=str(request["repository"]),
                merge_sha=str(request["merge_sha"]),
            ),
            "does_not_establish": [
                "job_not_started",
                "freshness_failed",
                "merge_failure",
            ],
        }

    return {
        **_followup_base(
            status="scheduled",
            reason="durable_freshness_job_started",
            repository=str(request["repository"]),
            merge_sha=str(request["merge_sha"]),
        ),
        "unit": unit,
        "job_id": job.get("job_id"),
        "argv_sha256": job.get("argv_sha256"),
        "expected_receipt": job.get("expected_receipt"),
        "does_not_establish": [
            "freshness_converged",
            "job_terminal_success",
            "future_branch_freshness",
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Converge one verified PR merge to an exact RepoGround fleet publication."
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    parser.add_argument(
        "--busy-sleep-seconds", type=float, default=DEFAULT_BUSY_SLEEP_SECONDS
    )
    parser.add_argument(
        "--publish-timeout-seconds",
        type=int,
        default=DEFAULT_PUBLISH_TIMEOUT_SECONDS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = converge(
            repository=args.repo,
            merge_sha=args.merge_sha,
            max_attempts=args.max_attempts,
            busy_sleep_seconds=args.busy_sleep_seconds,
            publish_timeout_seconds=args.publish_timeout_seconds,
        )
    except (
        OSError,
        RepoGroundPostMergeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "kind": "grabowski.repoground_post_merge_freshness",
            "schema_version": 1,
            "status": "failed",
            "reason": "exception",
            "error_class": type(exc).__name__,
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("status") == "fresh_exact" else 1


if __name__ == "__main__":
    raise SystemExit(main())

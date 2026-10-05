from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import selectors
import subprocess
import time
from typing import Any, Callable, Mapping

REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
DEFAULT_PUBLISHER = Path.home() / ".local" / "bin" / "repoground-publish-fleet"
DEFAULT_MAX_ATTEMPTS = 8
DEFAULT_BUSY_SLEEP_SECONDS = 15.0
DEFAULT_PUBLISH_TIMEOUT_SECONDS = 900
DEFAULT_ANCESTRY_TIMEOUT_SECONDS = 30
MAX_PUBLISH_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_GITHUB_OUTPUT_BYTES = 128 * 1024
DEFAULT_JOB_RUNTIME_SECONDS = 21_600
DEFAULT_QUEUE_POLL_SECONDS = 15.0
DEFAULT_QUEUE_MAX_ATTEMPTS = 1_320
DEFAULT_QUEUE_READ_TIMEOUT_SECONDS = 60
CONVERGENCE_RUNTIME_SAFETY_MARGIN_SECONDS = 2_000
DEFAULT_CONVERGENCE_RUNTIME_RESERVE_SECONDS = int(
    DEFAULT_MAX_ATTEMPTS * DEFAULT_PUBLISH_TIMEOUT_SECONDS
    + (DEFAULT_MAX_ATTEMPTS - 1) * DEFAULT_BUSY_SLEEP_SECONDS
    + DEFAULT_MAX_ATTEMPTS * DEFAULT_ANCESTRY_TIMEOUT_SECONDS
    + DEFAULT_QUEUE_READ_TIMEOUT_SECONDS
    + CONVERGENCE_RUNTIME_SAFETY_MARGIN_SECONDS
)
DEFAULT_QUEUE_WATCH_SECONDS = float(
    DEFAULT_JOB_RUNTIME_SECONDS - DEFAULT_CONVERGENCE_RUNTIME_RESERVE_SECONDS
)
QUEUE_OBSERVATION_LIMIT = 20

PublisherRunner = Callable[[list[str], int], dict[str, Any]]
FreshnessReader = Callable[[str], dict[str, Any]]
SleepFn = Callable[[float], None]
MonotonicFn = Callable[[], float]
AncestryChecker = Callable[[str, str, str], bool]
JobStarter = Callable[..., dict[str, Any]]
QueueReader = Callable[[str, int], dict[str, Any]]
QueueConverger = Callable[[str, str], dict[str, Any]]


POST_MERGE_TERMINAL_JOB_STATUSES = frozenset(
    {"succeeded", "failed", "launch_failed"}
)
POST_MERGE_JOB_SLOT_LIMIT = 16


def _post_merge_job_starter(
    operator_module: Any,
    public_starter: JobStarter,
) -> JobStarter:
    argv_hash = getattr(operator_module, "_argv_hash", None)
    read_metadata = getattr(operator_module, "_read_job_metadata", None)
    read_status = getattr(operator_module, "grabowski_job_status", None)
    require_mutation = getattr(operator_module, "_require_operator_mutation", None)
    private_starter = getattr(operator_module, "_start_job", None)
    if not all(
        callable(candidate)
        for candidate in (
            argv_hash,
            read_metadata,
            read_status,
            require_mutation,
            private_starter,
        )
    ):
        return public_starter

    def start_reusable_job(
        argv: list[str],
        *,
        cwd: str,
        runtime_seconds: int,
    ) -> dict[str, Any]:
        working_directory = str(Path(cwd).expanduser().resolve())
        expected_argv_sha256 = argv_hash(list(argv))
        identity_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "argv_sha256": expected_argv_sha256,
                    "cwd": working_directory,
                    "runtime_seconds": runtime_seconds,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        def exact(metadata: dict[str, Any]) -> bool:
            return bool(
                metadata.get("argv_sha256") == expected_argv_sha256
                and metadata.get("cwd") == working_directory
                and metadata.get("runtime_seconds") == runtime_seconds
            )

        def uncertain(
            metadata: dict[str, Any],
            *,
            final_status: Any = None,
            error_class: str | None = None,
        ) -> dict[str, Any]:
            result = {
                **metadata,
                "reused": True,
                "reuse_uncertain": True,
            }
            if isinstance(final_status, str):
                result["observed_final_status"] = final_status
            if isinstance(error_class, str):
                result["reuse_status_error_class"] = error_class
            return result

        def reuse(unit: str, metadata: dict[str, Any]) -> dict[str, Any] | None:
            try:
                status = read_status(unit)
            except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
                return uncertain(metadata, error_class=type(exc).__name__)
            if not isinstance(status, dict):
                return uncertain(metadata, error_class="InvalidStatusResult")
            if status.get("unit") != unit:
                raise RuntimeError(
                    "existing RepoGround post-merge job status identity mismatched"
                )
            observed_metadata = status.get("metadata")
            if not isinstance(observed_metadata, dict) or not exact(observed_metadata):
                raise RuntimeError(
                    "existing RepoGround post-merge job status scope mismatched"
                )
            final_status = status.get("final_status")
            if final_status == "running":
                return {**observed_metadata, "reused": True}
            if final_status in POST_MERGE_TERMINAL_JOB_STATUSES:
                return None
            return uncertain(observed_metadata, final_status=final_status)

        for attempt in range(POST_MERGE_JOB_SLOT_LIMIT):
            unit = f"grabowski-job-rgpm-{identity_sha256[:16]}-{attempt:02d}"
            try:
                existing = read_metadata(unit)
            except (OSError, PermissionError, ValueError):
                existing = None
            if isinstance(existing, dict):
                if not exact(existing):
                    raise RuntimeError(
                        "existing RepoGround post-merge job identity mismatched"
                    )
                reusable = reuse(unit, existing)
                if reusable is not None:
                    return reusable
                continue

            require_mutation(
                "durable_job",
                path=working_directory,
                opaque_command=True,
            )
            try:
                started = private_starter(
                    list(argv),
                    cwd=working_directory,
                    runtime_seconds=runtime_seconds,
                    reserved_unit=unit,
                )
            except Exception as exc:
                try:
                    readback = read_metadata(unit)
                except (OSError, PermissionError, ValueError):
                    readback = None
                if isinstance(readback, dict) and exact(readback):
                    reusable = reuse(unit, readback)
                    if reusable is not None:
                        return reusable
                    if isinstance(exc, FileExistsError):
                        continue
                    return uncertain(
                        readback,
                        final_status="terminal_after_ambiguous_start",
                        error_class=type(exc).__name__,
                    )
                raise

            if (
                not isinstance(started, dict)
                or started.get("unit") != unit
                or started.get("argv_sha256") != expected_argv_sha256
            ):
                raise RuntimeError(
                    "RepoGround post-merge job start receipt mismatched"
                )
            return {**started, "reused": False}

        raise RuntimeError("RepoGround post-merge reusable job slots exhausted")

    return start_reusable_job

def resolve_job_starter(modules: Mapping[str, Any]) -> JobStarter | None:
    operator_module = modules.get("grabowski_operator")
    starter = getattr(operator_module, "grabowski_job_start", None)
    if callable(starter):
        return _post_merge_job_starter(operator_module, starter)

    main_module = modules.get("__main__")
    main_spec = getattr(main_module, "__spec__", None)
    if getattr(main_spec, "name", None) != "grabowski_operator":
        return None
    starter = getattr(main_module, "grabowski_job_start", None)
    return (
        _post_merge_job_starter(main_module, starter)
        if callable(starter)
        else None
    )


FOLLOWUP_KIND = "grabowski.repoground_post_merge_followup"


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


def _run_bounded_process(
    argv: list[str],
    timeout_seconds: int,
    *,
    max_output_bytes: int,
) -> dict[str, Any]:
    if type(timeout_seconds) is not int or timeout_seconds < 1:
        raise RepoGroundPostMergeError("subprocess timeout must be a positive integer")
    if type(max_output_bytes) is not int or max_output_bytes < 1:
        raise RepoGroundPostMergeError("subprocess output limit must be positive")

    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise RepoGroundPostMergeError("subprocess pipes are unavailable")

    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(argv, timeout_seconds)

            ready = selector.select(timeout=min(0.25, remaining))
            if not ready:
                continue

            for key, _events in ready:
                chunk = key.fileobj.read1(64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream_name = str(key.data)
                buffer = buffers[stream_name]
                capacity = max_output_bytes + 1 - len(buffer)
                if capacity > 0:
                    buffer.extend(chunk[:capacity])
                if len(buffer) > max_output_bytes or len(chunk) > capacity:
                    process.kill()
                    process.wait()
                    raise RepoGroundPostMergeError(
                        f"subprocess {stream_name} exceeds bounded output"
                    )
        returncode = process.poll()
        if returncode is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(argv, timeout_seconds)
            try:
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(argv, timeout_seconds) from exc
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    try:
        stdout = bytes(buffers["stdout"]).decode("utf-8", errors="strict")
        stderr = bytes(buffers["stderr"]).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RepoGroundPostMergeError("subprocess output is not valid UTF-8") from exc
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }


def _run_publisher(argv: list[str], timeout_seconds: int) -> dict[str, Any]:
    completed = _run_bounded_process(
        argv,
        timeout_seconds,
        max_output_bytes=MAX_PUBLISH_OUTPUT_BYTES,
    )
    stdout = str(completed["stdout"])
    stderr = str(completed["stderr"])
    payload: Any = None
    if stdout.strip():
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RepoGroundPostMergeError(
                "RepoGround publisher returned malformed JSON"
            ) from exc
    return {
        "returncode": completed["returncode"],
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
        timeout=DEFAULT_ANCESTRY_TIMEOUT_SECONDS,
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


def _validate_pull_request(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RepoGroundPostMergeError("pull request number must be a positive integer")
    return value


def _validate_base_ref(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or "\x00" in value
    ):
        raise RepoGroundPostMergeError("expected base ref is invalid")
    return value


def _read_queue_pr(repository: str, pull_request: int) -> dict[str, Any]:
    completed = _run_bounded_process(
        [
            "gh",
            "pr",
            "view",
            str(pull_request),
            "--repo",
            repository,
            "--json",
            "number,state,headRefOid,baseRefName,mergeCommit",
        ],
        DEFAULT_QUEUE_READ_TIMEOUT_SECONDS,
        max_output_bytes=MAX_GITHUB_OUTPUT_BYTES,
    )
    if completed["returncode"] != 0:
        raise RepoGroundPostMergeError(
            "GitHub PR read failed: " + str(completed["stderr"])[-1000:]
        )
    try:
        payload = json.loads(str(completed["stdout"]))
    except json.JSONDecodeError as exc:
        raise RepoGroundPostMergeError("GitHub PR read returned malformed JSON") from exc
    if not isinstance(payload, dict):
        raise RepoGroundPostMergeError("GitHub PR read returned a non-object")
    return payload


def _queue_converge(repository: str, merge_sha: str) -> dict[str, Any]:
    return converge(repository=repository, merge_sha=merge_sha)


def watch_merge_queue(
    *,
    repository: str,
    pull_request: int,
    expected_head: str,
    expected_base: str,
    max_attempts: int = DEFAULT_QUEUE_MAX_ATTEMPTS,
    poll_seconds: float = DEFAULT_QUEUE_POLL_SECONDS,
    queue_reader: QueueReader = _read_queue_pr,
    queue_converger: QueueConverger = _queue_converge,
    sleep_fn: SleepFn = time.sleep,
    watch_seconds: float = DEFAULT_QUEUE_WATCH_SECONDS,
    monotonic_fn: MonotonicFn = time.monotonic,
) -> dict[str, Any]:
    repository = _validate_repository(repository)
    pull_request = _validate_pull_request(pull_request)
    expected_head = _validate_sha(expected_head)
    expected_base = _validate_base_ref(expected_base)
    if type(max_attempts) is not int or max_attempts < 1 or max_attempts > 2_000:
        raise RepoGroundPostMergeError("queue max_attempts must be between 1 and 2000")
    if poll_seconds < 0 or poll_seconds > 300:
        raise RepoGroundPostMergeError("queue poll_seconds is out of bounds")
    if (
        isinstance(watch_seconds, bool)
        or not isinstance(watch_seconds, (int, float))
        or watch_seconds <= 0
        or watch_seconds > DEFAULT_QUEUE_WATCH_SECONDS
    ):
        raise RepoGroundPostMergeError("queue watch_seconds is out of bounds")

    started_at = monotonic_fn()
    observations: list[dict[str, Any]] = []

    def deadline_result(attempt: int) -> dict[str, Any]:
        return {
            "kind": "grabowski.repoground_merge_queue_followup",
            "schema_version": 1,
            "status": "failed",
            "reason": "merge_queue_watch_deadline_exhausted",
            "repository": repository,
            "pull_request": pull_request,
            "attempt_count": attempt,
            "watch_seconds": watch_seconds,
            "observations": observations,
        }

    for attempt in range(1, max_attempts + 1):
        if monotonic_fn() - started_at >= watch_seconds:
            return deadline_result(attempt - 1)
        try:
            viewed = queue_reader(repository, pull_request)
        except (
            OSError,
            RepoGroundPostMergeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            observations.append(
                {
                    "attempt": attempt,
                    "status": "read_error",
                    "error_class": type(exc).__name__,
                }
            )
            observations[:] = observations[-QUEUE_OBSERVATION_LIMIT:]
            if monotonic_fn() - started_at >= watch_seconds:
                return deadline_result(attempt)
            if attempt == max_attempts:
                return {
                    "kind": "grabowski.repoground_merge_queue_followup",
                    "schema_version": 1,
                    "status": "failed",
                    "reason": "merge_queue_read_exhausted",
                    "repository": repository,
                    "pull_request": pull_request,
                    "attempt_count": attempt,
                    "observations": observations,
                }
            remaining = watch_seconds - (monotonic_fn() - started_at)
            sleep_fn(min(poll_seconds, max(0.0, remaining)))
            continue

        if not isinstance(viewed, dict):
            raise RepoGroundPostMergeError("queue reader returned a non-object")
        state = viewed.get("state")
        observed_head = viewed.get("headRefOid")
        observed_head = (
            observed_head.lower()
            if isinstance(observed_head, str)
            and SHA40_RE.fullmatch(observed_head.lower()) is not None
            else None
        )
        observed_base = viewed.get("baseRefName")
        observed_number = viewed.get("number")
        observation = {
            "attempt": attempt,
            "state": state,
            "head": observed_head,
            "base": observed_base,
        }
        observations.append(observation)
        observations[:] = observations[-QUEUE_OBSERVATION_LIMIT:]
        if monotonic_fn() - started_at >= watch_seconds:
            return deadline_result(attempt)

        if (
            observed_number != pull_request
            or observed_head != expected_head
            or observed_base != expected_base
        ):
            return {
                "kind": "grabowski.repoground_merge_queue_followup",
                "schema_version": 1,
                "status": "failed",
                "reason": "merge_queue_identity_mismatch",
                "repository": repository,
                "pull_request": pull_request,
                "attempt_count": attempt,
                "observations": observations,
            }

        if state == "MERGED":
            merge_commit = viewed.get("mergeCommit")
            merge_sha = (
                merge_commit.get("oid")
                if isinstance(merge_commit, dict)
                else None
            )
            if (
                not isinstance(merge_sha, str)
                or SHA40_RE.fullmatch(merge_sha.lower()) is None
            ):
                observations[-1]["merge_sha_status"] = "unsettled"
                if monotonic_fn() - started_at >= watch_seconds:
                    return deadline_result(attempt)
                if attempt == max_attempts:
                    return {
                        "kind": "grabowski.repoground_merge_queue_followup",
                        "schema_version": 1,
                        "status": "failed",
                        "reason": "merge_queue_merge_sha_unavailable",
                        "repository": repository,
                        "pull_request": pull_request,
                        "attempt_count": attempt,
                        "observations": observations,
                    }
                remaining = watch_seconds - (monotonic_fn() - started_at)
                sleep_fn(min(poll_seconds, max(0.0, remaining)))
                continue
            merge_sha = merge_sha.lower()
            convergence = queue_converger(repository, merge_sha)
            if not isinstance(convergence, dict):
                raise RepoGroundPostMergeError(
                    "queue convergence returned a non-object"
                )
            if convergence.get("status") != "fresh_exact":
                return {
                    "kind": "grabowski.repoground_merge_queue_followup",
                    "schema_version": 1,
                    "status": "failed",
                    "reason": "freshness_after_queue_merge_failed",
                    "repository": repository,
                    "pull_request": pull_request,
                    "merge_sha": merge_sha,
                    "attempt_count": attempt,
                    "observations": observations,
                    "convergence": convergence,
                }
            return {
                "kind": "grabowski.repoground_merge_queue_followup",
                "schema_version": 1,
                "status": "fresh_exact",
                "reason": "merge_queue_completed_and_freshness_converged",
                "repository": repository,
                "pull_request": pull_request,
                "merge_sha": merge_sha,
                "attempt_count": attempt,
                "observations": observations,
                "convergence": convergence,
            }

        if state == "CLOSED":
            return {
                "kind": "grabowski.repoground_merge_queue_followup",
                "schema_version": 1,
                "status": "failed",
                "reason": "merge_queue_closed_without_merge",
                "repository": repository,
                "pull_request": pull_request,
                "attempt_count": attempt,
                "observations": observations,
            }
        if state != "OPEN":
            return {
                "kind": "grabowski.repoground_merge_queue_followup",
                "schema_version": 1,
                "status": "failed",
                "reason": "merge_queue_pr_state_unexpected",
                "repository": repository,
                "pull_request": pull_request,
                "attempt_count": attempt,
                "observations": observations,
            }
        if attempt < max_attempts:
            remaining = watch_seconds - (monotonic_fn() - started_at)
            sleep_fn(min(poll_seconds, max(0.0, remaining)))

    return {
        "kind": "grabowski.repoground_merge_queue_followup",
        "schema_version": 1,
        "status": "failed",
        "reason": "merge_queue_wait_exhausted",
        "repository": repository,
        "pull_request": pull_request,
        "attempt_count": max_attempts,
        "observations": observations,
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


def _validated_runtime_request(
    *, python_executable: str, script_path: Path
) -> tuple[str, Path]:
    executable = str(python_executable)
    if not executable or "\x00" in executable:
        raise RepoGroundPostMergeError("python executable is invalid")
    script = Path(script_path).expanduser().resolve(strict=True)
    if not script.is_file():
        raise RepoGroundPostMergeError("RepoGround post-merge script is unavailable")
    return executable, script


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

    executable, script = _validated_runtime_request(
        python_executable=python_executable,
        script_path=script_path,
    )

    if execution.get("merge_completion_verified") is not True:
        if execution.get("merge_queued") is not True:
            return _followup_base(
                status="not_scheduled",
                reason="merge_completion_not_verified",
                repository=repository,
            )
        try:
            pull_request = _validate_pull_request(execution.get("pr"))
            expected_head = _validate_sha(execution.get("expected_head"))
            expected_base = _validate_base_ref(execution.get("expected_base"))
        except RepoGroundPostMergeError:
            return _followup_base(
                status="not_scheduled",
                reason="merge_queue_identity_invalid",
                repository=repository,
            )
        return {
            **_followup_base(
                status="ready_queue_watch",
                reason="verified_merge_queue_ready_for_watch",
                repository=repository,
            ),
            "pull_request": pull_request,
            "expected_head": expected_head,
            "expected_base": expected_base,
            "argv": [
                executable,
                "-B",
                str(script),
                "--repo",
                repository,
                "--pr",
                str(pull_request),
                "--expected-head",
                expected_head,
                "--expected-base",
                expected_base,
            ],
            "cwd": str(script.parent),
        }

    merge_sha = _verified_merge_sha(execution)
    if merge_sha is None:
        return _followup_base(
            status="not_scheduled",
            reason="verified_merge_sha_unavailable",
            repository=repository,
        )

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


def _schedule_request_identity(request: dict[str, Any]) -> dict[str, Any]:
    identity: dict[str, Any] = {"repository": str(request["repository"])}
    merge_sha = request.get("merge_sha")
    if isinstance(merge_sha, str):
        identity["merge_sha"] = merge_sha
    pull_request = request.get("pull_request")
    if isinstance(pull_request, int):
        identity["pull_request"] = pull_request
    return identity


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
    request_status = request.get("status")
    if request_status not in {"ready", "ready_queue_watch"}:
        return request
    if (
        type(runtime_seconds) is not int
        or runtime_seconds < 60
        or runtime_seconds > 21_600
    ):
        raise RepoGroundPostMergeError("job runtime is out of bounds")

    identity = _schedule_request_identity(request)
    job_argv = list(request["argv"])
    if request_status == "ready_queue_watch":
        queue_watch_seconds = (
            runtime_seconds - DEFAULT_CONVERGENCE_RUNTIME_RESERVE_SECONDS
        )
        if queue_watch_seconds < 60:
            raise RepoGroundPostMergeError(
                "queue watcher runtime leaves no convergence reserve"
            )
        job_argv.extend(
            ["--queue-watch-seconds", str(float(queue_watch_seconds))]
        )
    try:
        job = job_starter(
            job_argv,
            cwd=str(request["cwd"]),
            runtime_seconds=runtime_seconds,
        )
    except Exception as exc:
        unit = getattr(exc, "unit", None)
        return {
            **_followup_base(
                status=(
                    "schedule_unknown"
                    if isinstance(unit, str) and unit
                    else "schedule_error"
                ),
                reason="durable_job_start_failed",
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
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
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
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
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
            ),
            "does_not_establish": [
                "job_not_started",
                "freshness_failed",
                "merge_failure",
            ],
        }

    if job.get("reuse_uncertain") is True:
        return {
            **_followup_base(
                status="schedule_unknown",
                reason="durable_job_reuse_outcome_unknown",
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
            ),
            "unit": unit,
            "job_id": job.get("job_id"),
            "argv_sha256": job.get("argv_sha256"),
            "expected_receipt": job.get("expected_receipt"),
            "does_not_establish": [
                "job_not_started",
                "freshness_failed",
                "merge_failure",
            ],
        }

    reused = job.get("reused") is True
    reason = (
        (
            "durable_merge_queue_watch_reused"
            if reused
            else "durable_merge_queue_watch_started"
        )
        if request_status == "ready_queue_watch"
        else (
            "durable_freshness_job_reused"
            if reused
            else "durable_freshness_job_started"
        )
    )
    return {
        **_followup_base(
            status="scheduled",
            reason=reason,
            repository=identity["repository"],
            merge_sha=identity.get("merge_sha"),
        ),
        **(
            {"pull_request": identity["pull_request"]}
            if "pull_request" in identity
            else {}
        ),
        "unit": unit,
        "reused": reused,
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
        description=(
            "Converge one verified PR merge to an exact RepoGround fleet publication, "
            "or watch one verified merge-queue entry until it is merged."
        )
    )
    parser.add_argument("--repo", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--merge-sha")
    mode.add_argument("--pr", type=int)
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-base")
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    parser.add_argument(
        "--busy-sleep-seconds", type=float, default=DEFAULT_BUSY_SLEEP_SECONDS
    )
    parser.add_argument(
        "--publish-timeout-seconds",
        type=int,
        default=DEFAULT_PUBLISH_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--queue-max-attempts",
        type=int,
        default=DEFAULT_QUEUE_MAX_ATTEMPTS,
    )
    parser.add_argument(
        "--queue-poll-seconds",
        type=float,
        default=DEFAULT_QUEUE_POLL_SECONDS,
    )
    parser.add_argument(
        "--queue-watch-seconds",
        type=float,
        default=DEFAULT_QUEUE_WATCH_SECONDS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.pr is not None:
            if args.expected_head is None or args.expected_base is None:
                parser.error(
                    "--pr requires --expected-head and --expected-base"
                )
            result = watch_merge_queue(
                repository=args.repo,
                pull_request=args.pr,
                expected_head=args.expected_head,
                expected_base=args.expected_base,
                max_attempts=args.queue_max_attempts,
                poll_seconds=args.queue_poll_seconds,
                watch_seconds=args.queue_watch_seconds,
            )
        else:
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
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import os
import stat as statmod
import json
from pathlib import Path
from types import SimpleNamespace
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
DEFAULT_RECONCILE_LOOKBACK_SECONDS = DEFAULT_JOB_RUNTIME_SECONDS + 3_600
QUEUE_OBSERVATION_LIMIT = 20

PublisherRunner = Callable[[list[str], int], dict[str, Any]]
FreshnessReader = Callable[[str], dict[str, Any]]
SleepFn = Callable[[float], None]
MonotonicFn = Callable[[], float]
AncestryChecker = Callable[[str, str, str], bool]
JobStarter = Callable[..., dict[str, Any]]
QueueReader = Callable[[str, int], dict[str, Any]]
QueueConverger = Callable[[str, str, str], dict[str, Any]]


POST_MERGE_TERMINAL_JOB_STATUSES = frozenset(
    {
        "failed",
        "timed_out",
        "signalled",
        "terminated_unclear",
        "launch_failed",
    }
)
POST_MERGE_JOB_SLOT_LIMIT = 16
POST_MERGE_FAILURE_RETRY_BACKOFF_SECONDS = 300
POST_MERGE_MISSING_UNIT_RECOVERY_GRACE_SECONDS = 300
POST_MERGE_METADATA_FREE_SLOT_GRACE_SECONDS = 300
POST_MERGE_STATUS_READ_TIMEOUT_SECONDS = 30
POST_MERGE_START_TIMEOUT_SECONDS = 60
POST_MERGE_SINGLE_IDENTITY_BUDGET_SECONDS = (
    POST_MERGE_JOB_SLOT_LIMIT * POST_MERGE_STATUS_READ_TIMEOUT_SECONDS
    + POST_MERGE_START_TIMEOUT_SECONDS
)
DEFAULT_RECONCILE_PASS_BUDGET_SECONDS = 720
RECONCILE_CURSOR_METADATA_KEY = "repoground_post_merge_reconcile_cursor_v1"
RECONCILE_DISCOVERY_METADATA_KEY = "repoground_post_merge_reconcile_discovery_v1"
RECONCILE_SCAN_NEXT_METADATA_KEY = "repoground_post_merge_reconcile_scan_next_v1"
RECONCILE_EXHAUSTED_METADATA_PREFIX = "repoground_post_merge_exhausted_v1:"
RECONCILE_ACKNOWLEDGED_METADATA_PREFIX = "repoground_post_merge_ack_v1:"
_RECONCILE_CAS_UNSET = object()
DEFAULT_PREDECESSOR_RECONCILER_SOURCE = (
    Path.home()
    / ".local/share/grabowski-mcp/inputs/src/grabowski_repoground_post_merge.py"
)


class _ReusableJobSlotsExhausted(RuntimeError):
    pass


def _post_merge_semantic_argv(argv: list[str]) -> tuple[str, ...] | None:
    if (
        len(argv) >= 4
        and argv[1] == "-B"
        and Path(argv[2]).name == "grabowski_repoground_post_merge.py"
    ):
        return tuple(argv[3:])
    return None


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
        semantic_argv = _post_merge_semantic_argv(argv)
        identity_material: dict[str, Any] = {
            "runtime_seconds": runtime_seconds,
        }
        if semantic_argv is None:
            identity_material.update(
                {
                    "argv_sha256": expected_argv_sha256,
                    "cwd": working_directory,
                }
            )
        else:
            identity_material["post_merge_argv"] = list(semantic_argv)
        identity_sha256 = hashlib.sha256(
            json.dumps(
                identity_material,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        def exact(metadata: dict[str, Any]) -> bool:
            if metadata.get("runtime_seconds") != runtime_seconds:
                return False
            if (
                metadata.get("argv_sha256") == expected_argv_sha256
                and metadata.get("cwd") == working_directory
            ):
                return True
            if semantic_argv is None:
                return False
            observed_argv = metadata.get("argv")
            return bool(
                isinstance(observed_argv, list)
                and all(isinstance(item, str) for item in observed_argv)
                and _post_merge_semantic_argv(observed_argv) == semantic_argv
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
            if final_status == "succeeded":
                return {
                    **observed_metadata,
                    "reused": True,
                    "reuse_satisfied": True,
                    "observed_final_status": "succeeded",
                }
            if final_status == "missing_finalization_evidence":
                terminalization = status.get("terminalization_evidence")
                created_at_unix = observed_metadata.get("created_at_unix")
                missing_unit_is_verified = bool(
                    isinstance(terminalization, dict)
                    and terminalization.get("query_valid") is True
                    and terminalization.get("systemd_visible") is False
                    and terminalization.get("load_state") == "not-found"
                )
                if (
                    missing_unit_is_verified
                    and isinstance(created_at_unix, int)
                    and not isinstance(created_at_unix, bool)
                    and created_at_unix >= 0
                ):
                    retry_after_unix = (
                        created_at_unix
                        + POST_MERGE_MISSING_UNIT_RECOVERY_GRACE_SECONDS
                    )
                    if int(time.time()) >= retry_after_unix:
                        return None
                    return {
                        **observed_metadata,
                        "reused": True,
                        "reuse_retry_deferred": True,
                        "observed_final_status": final_status,
                        "retry_after_unix": retry_after_unix,
                    }
                return uncertain(observed_metadata, final_status=final_status)
            if final_status in POST_MERGE_TERMINAL_JOB_STATUSES:
                retry_anchor_unix: int | None = None
                finalization_receipt = status.get("finalization_receipt")
                if isinstance(finalization_receipt, dict):
                    terminalized_at_unix = finalization_receipt.get("timestamp_unix")
                    if (
                        isinstance(terminalized_at_unix, int)
                        and not isinstance(terminalized_at_unix, bool)
                        and terminalized_at_unix >= 0
                    ):
                        retry_anchor_unix = terminalized_at_unix
                if retry_anchor_unix is None and final_status == "launch_failed":
                    created_at_unix = observed_metadata.get("created_at_unix")
                    if (
                        isinstance(created_at_unix, int)
                        and not isinstance(created_at_unix, bool)
                        and created_at_unix >= 0
                    ):
                        retry_anchor_unix = created_at_unix
                if retry_anchor_unix is None:
                    return {
                        **observed_metadata,
                        "reused": True,
                        "reuse_retry_deferred": True,
                        "reuse_terminal_evidence_pending": True,
                        "observed_final_status": final_status,
                        "retry_after_unix": None,
                    }
                retry_after_unix = (
                    retry_anchor_unix + POST_MERGE_FAILURE_RETRY_BACKOFF_SECONDS
                )
                if int(time.time()) < retry_after_unix:
                    return {
                        **observed_metadata,
                        "reused": True,
                        "reuse_retry_deferred": True,
                        "observed_final_status": final_status,
                        "retry_after_unix": retry_after_unix,
                    }
                return None
            return uncertain(observed_metadata, final_status=final_status)

        def metadata_free_slot_state(unit: str) -> str | None:
            """Observe partial startup without deleting or retrying artifacts."""
            root = getattr(operator_module, "JOBS_DIR", None)
            if not isinstance(root, Path):
                return None
            try:
                root_info = root.lstat()
            except FileNotFoundError:
                return None
            if not statmod.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
                return "uncertain"
            directory = root / unit
            try:
                info = directory.lstat()
            except FileNotFoundError:
                return None
            if (
                not statmod.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or statmod.S_IMODE(info.st_mode) & 0o077
            ):
                return "uncertain"
            # A corrupt metadata file never proves the job failed. Preserve
            # it unchanged, but after a grace period allow an explicit manual
            # recovery through the existing publisher. Never retry the slot.
            latest_ns = info.st_mtime_ns
            try:
                metadata_info = (directory / "metadata.json").lstat()
            except FileNotFoundError:
                pass
            except OSError:
                return "uncertain"
            else:
                latest_ns = max(latest_ns, metadata_info.st_mtime_ns)
            for name in ("stdout.log", "stderr.log"):
                try:
                    log = (directory / name).lstat()
                except FileNotFoundError:
                    continue
                if (
                    not statmod.S_ISREG(log.st_mode)
                    or log.st_nlink != 1
                    or log.st_uid != os.getuid()
                    or statmod.S_IMODE(log.st_mode) & 0o077
                ):
                    return "uncertain"
                latest_ns = max(latest_ns, log.st_mtime_ns)
            # The directory can be left behind before *either* log was made.
            # Its own mtime is the immutable minimum evidence for the grace.
            return (
                "abandoned"
                if time.time_ns() - latest_ns
                >= POST_MERGE_METADATA_FREE_SLOT_GRACE_SECONDS * 1_000_000_000
                else "uncertain"
            )

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

            # Existing O_EXCL logs with no metadata may be a partially
            # started job. Inspect only; never retry the same reserved slot.
            slot_state = metadata_free_slot_state(unit)
            if slot_state == "uncertain":
                return uncertain(
                    {"unit": unit, "reused": True},
                    error_class="MetadataFreeReservedSlot",
                )
            if slot_state == "abandoned":
                raise _ReusableJobSlotsExhausted(
                    "RepoGround reserved job slot is metadata-free past grace"
                )

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
                if isinstance(exc, FileExistsError) and readback is None:
                    # First observation is always ambiguous. A start may be
                    # concurrently writing metadata; do not try another unit.
                    return uncertain(
                        {"unit": unit, "reused": True},
                        error_class="MetadataFreeReservedSlot",
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

        raise _ReusableJobSlotsExhausted("RepoGround post-merge reusable job slots exhausted")

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
        "source_kind": live.get("source_kind") if isinstance(live, dict) else None,
        "repo_path": live.get("repo_path") if isinstance(live, dict) else None,
    }


def _read_remote_branch_head(repo_path: str, target_branch: str) -> str:
    target_branch = _validate_base_ref(target_branch)
    full_ref = f"refs/heads/{target_branch}"
    completed = subprocess.run(
        [
            "git",
            "-C",
            repo_path,
            "ls-remote",
            "--exit-code",
            "--refs",
            "--",
            "origin",
            full_ref,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=DEFAULT_ANCESTRY_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise RepoGroundPostMergeError(
            "authoritative remote target branch head is unavailable"
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RepoGroundPostMergeError(
            "authoritative remote target branch head is ambiguous"
        )
    fields = lines[0].split()
    if (
        len(fields) != 2
        or fields[1] != full_ref
        or SHA40_RE.fullmatch(fields[0].lower()) is None
    ):
        raise RepoGroundPostMergeError(
            "authoritative remote target branch head is invalid"
        )
    return fields[0].lower()


def _fresh_exact(
    freshness: dict[str, Any],
    *,
    merge_sha: str,
    target_branch: str,
    ancestry_checker: AncestryChecker,
) -> tuple[bool, dict[str, Any]]:
    projection = _freshness_projection(freshness)
    bundle_commit = projection["bundle_commit"]
    live_head = projection["live_head"]
    remote_head = projection["remote_head"]
    source_kind = projection["source_kind"]
    repo_path = projection["repo_path"]
    if (
        source_kind == "conventional_checkout"
        and isinstance(repo_path, str)
        and repo_path
    ):
        try:
            remote_head = _read_remote_branch_head(repo_path, target_branch)
            projection["remote_head"] = remote_head
            projection["target_branch"] = target_branch
            projection["remote_head_status"] = "observed"
            projection["remote_head_basis"] = "git_ls_remote_origin"
        except (OSError, RepoGroundPostMergeError, subprocess.SubprocessError):
            projection["remote_head"] = None
            projection["remote_head_status"] = "unavailable"
            projection["remote_head_basis"] = "git_ls_remote_origin"
            projection["merge_is_ancestor"] = None
            return False, projection
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
    target_branch: str = "main",
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
    target_branch = _validate_base_ref(target_branch)
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
            target_branch=target_branch,
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
        if projection.get("remote_head_status") == "unavailable":
            return {
                "kind": "grabowski.repoground_post_merge_freshness",
                "schema_version": 1,
                "status": "failed",
                "reason": "authoritative_remote_head_unavailable",
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


def _queue_converge(
    repository: str, merge_sha: str, target_branch: str
) -> dict[str, Any]:
    return converge(
        repository=repository,
        merge_sha=merge_sha,
        target_branch=target_branch,
    )


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
            convergence = queue_converger(repository, merge_sha, expected_base)
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
    try:
        target_branch = _validate_base_ref(execution.get("expected_base"))
    except RepoGroundPostMergeError:
        return _followup_base(
            status="not_scheduled",
            reason="merge_target_branch_invalid",
            repository=repository,
            merge_sha=merge_sha,
        )

    return {
        **_followup_base(
            status="ready",
            reason="verified_merge_ready_for_freshness",
            repository=repository,
            merge_sha=merge_sha,
        ),
        "target_branch": target_branch,
        "argv": [
            executable,
            "-B",
            str(script),
            "--repo",
            repository,
            "--merge-sha",
            merge_sha,
            "--target-branch",
            target_branch,
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


def schedule_followup_request(
    request: dict[str, Any],
    *,
    job_starter: JobStarter,
    runtime_seconds: int = DEFAULT_JOB_RUNTIME_SECONDS,
) -> dict[str, Any]:
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
    except _ReusableJobSlotsExhausted:
        return {
            **_followup_base(
                status="not_scheduled",
                reason="durable_freshness_job_slots_exhausted",
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
            ),
            "does_not_establish": [
                "freshness_converged",
                "freshness_failed",
                "future_branch_freshness",
            ],
        }
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

    if job.get("reuse_satisfied") is True:
        return {
            **_followup_base(
                status="already_satisfied",
                reason="durable_freshness_job_already_succeeded",
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
            ),
            "unit": unit,
            "reused": True,
            "job_id": job.get("job_id"),
            "argv_sha256": job.get("argv_sha256"),
            "expected_receipt": job.get("expected_receipt"),
            "does_not_establish": ["future_branch_freshness"],
        }

    if job.get("reuse_retry_deferred") is True:
        return {
            **_followup_base(
                status="retry_deferred",
                reason="durable_freshness_job_retry_backoff",
                repository=identity["repository"],
                merge_sha=identity.get("merge_sha"),
            ),
            **(
                {"pull_request": identity["pull_request"]}
                if "pull_request" in identity
                else {}
            ),
            "unit": unit,
            "reused": True,
            "observed_final_status": job.get("observed_final_status"),
            "retry_after_unix": job.get("retry_after_unix"),
            "terminal_evidence_pending": (
                job.get("reuse_terminal_evidence_pending") is True
            ),
            "does_not_establish": [
                "freshness_converged",
                "future_branch_freshness",
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
    return schedule_followup_request(
        request,
        job_starter=job_starter,
        runtime_seconds=runtime_seconds,
    )


def _verified_captain_completion_record(
    completion_record_sha256: str,
) -> dict[str, Any]:
    if (
        not isinstance(completion_record_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", completion_record_sha256) is None
    ):
        raise RepoGroundPostMergeError("Captain completion record SHA-256 is invalid")
    import grabowski_audit_query
    import grabowski_grip_orchestration

    snapshot = grabowski_audit_query.capture_verified_audit_snapshot()
    record = grabowski_grip_orchestration._verified_captain_audit_record(
        completion_record_sha256,
        snapshot=snapshot,
        audit_query_module=grabowski_audit_query,
    )
    if (
        not isinstance(record, dict)
        or record.get("operation") != "captain-run-audit-completion"
        or record.get("kind") != "grabowski_captain_run_audit"
        or record.get("schema_version") != 1
        or record.get("phase") != "completion"
        or record.get("action") != "pr-merge"
    ):
        raise RepoGroundPostMergeError("Captain completion audit record is not a PR merge")
    return record


def captain_followup_request_from_audit(
    completion_record_sha256: str,
    *,
    python_executable: str,
    script_path: Path,
) -> dict[str, Any]:
    record = _verified_captain_completion_record(completion_record_sha256)
    repository = _validate_repository(record.get("target_repo"))
    execution = record.get("execution_result")
    if not isinstance(execution, dict):
        raise RepoGroundPostMergeError("Captain completion execution result is unavailable")
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
    provenance_mode = execution.get("provenance_mode")
    if provenance_mode == "captain_dispatch_verified":
        merge_sha = _validate_sha(execution.get("observed_merge_sha"))
        target_branch = _validate_base_ref(record.get("expected_base"))
        return {
            **_followup_base(
                status="ready",
                reason="verified_captain_merge_ready_for_freshness",
                repository=repository,
                merge_sha=merge_sha,
            ),
            "captain_audit_completion_sha256": completion_record_sha256,
            "target_branch": target_branch,
            "argv": [
                executable,
                "-B",
                str(script),
                "--repo",
                repository,
                "--merge-sha",
                merge_sha,
                "--target-branch",
                target_branch,
            ],
            "cwd": str(script.parent),
        }
    if provenance_mode == "captain_queue_dispatch_pending":
        pull_request = _validate_pull_request(record.get("target_pr"))
        expected_head = _validate_sha(record.get("expected_head"))
        expected_base = _validate_base_ref(record.get("expected_base"))
        return {
            **_followup_base(
                status="ready_queue_watch",
                reason="verified_captain_merge_queue_ready_for_watch",
                repository=repository,
            ),
            "captain_audit_completion_sha256": completion_record_sha256,
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
    return _followup_base(
        status="not_scheduled",
        reason="captain_merge_not_fast_path_eligible",
        repository=repository,
    )


def schedule_from_captain_audit_completion(
    completion_record_sha256: str,
    *,
    job_starter: JobStarter,
    python_executable: str,
    script_path: Path,
    runtime_seconds: int = DEFAULT_JOB_RUNTIME_SECONDS,
) -> dict[str, Any]:
    request = captain_followup_request_from_audit(
        completion_record_sha256,
        python_executable=python_executable,
        script_path=script_path,
    )
    result = schedule_followup_request(
        request,
        job_starter=job_starter,
        runtime_seconds=runtime_seconds,
    )
    result["captain_audit_completion_sha256"] = completion_record_sha256
    return result


def _reconcile_record_timestamp_unix(record: Mapping[str, Any]) -> int:
    timestamp_unix = record.get("timestamp_unix")
    if type(timestamp_unix) is int and timestamp_unix >= 0:
        return timestamp_unix
    timestamp = record.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        raise RepoGroundPostMergeError(
            "Captain audit reconciliation timestamp is invalid"
        )
    normalized = (
        timestamp[:-1] + "+00:00"
        if timestamp.endswith("Z")
        else timestamp
    )
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RepoGroundPostMergeError(
            "Captain audit reconciliation timestamp is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise RepoGroundPostMergeError(
            "Captain audit reconciliation timestamp is invalid"
        )
    parsed_unix = int(parsed.timestamp())
    if parsed_unix < 0:
        raise RepoGroundPostMergeError(
            "Captain audit reconciliation timestamp is invalid"
        )
    return parsed_unix


def _load_reconcile_cursor(tasks_module: Any) -> str | None:
    with tasks_module._database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (RECONCILE_CURSOR_METADATA_KEY,),
        ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(str(row[0]))
    except json.JSONDecodeError as exc:
        raise RepoGroundPostMergeError(
            "RepoGround post-merge reconcile cursor is malformed"
        ) from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "cursor"}:
        raise RepoGroundPostMergeError(
            "RepoGround post-merge reconcile cursor shape is invalid"
        )
    if value.get("schema_version") != 1:
        raise RepoGroundPostMergeError(
            "RepoGround post-merge reconcile cursor schema is invalid"
        )
    cursor = value.get("cursor")
    if cursor is not None and (
        not isinstance(cursor, str)
        or re.fullmatch(r"[0-9a-f]{64}", cursor) is None
    ):
        raise RepoGroundPostMergeError(
            "RepoGround post-merge reconcile cursor identity is invalid"
        )
    return cursor


def _load_reconcile_discovery_ordinal(tasks_module: Any) -> int | None:
    with tasks_module._database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (RECONCILE_DISCOVERY_METADATA_KEY,),
        ).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(str(row[0]))
    except json.JSONDecodeError as exc:
        raise RepoGroundPostMergeError(
            "RepoGround post-merge discovery watermark is malformed"
        ) from exc
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "global_ordinal",
    }:
        raise RepoGroundPostMergeError(
            "RepoGround post-merge discovery watermark shape is invalid"
        )
    if value.get("schema_version") != 1:
        raise RepoGroundPostMergeError(
            "RepoGround post-merge discovery watermark schema is invalid"
        )
    global_ordinal = value.get("global_ordinal")
    if (
        isinstance(global_ordinal, bool)
        or not isinstance(global_ordinal, int)
        or global_ordinal < 0
    ):
        raise RepoGroundPostMergeError(
            "RepoGround post-merge discovery watermark ordinal is invalid"
        )
    return global_ordinal



def _load_reconcile_scan_next(tasks_module: Any) -> int | None:
    with tasks_module._database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?",
            (RECONCILE_SCAN_NEXT_METADATA_KEY,),
        ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(str(row[0]))
    except (TypeError, ValueError) as exc:
        raise RepoGroundPostMergeError("RepoGround scan cursor is malformed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "next_ordinal"}
        or payload.get("schema_version") != 1
        or type(payload.get("next_ordinal")) is not int
        or payload["next_ordinal"] < 1
    ):
        raise RepoGroundPostMergeError("RepoGround scan cursor is invalid")
    return payload["next_ordinal"]


def _exhausted_record_key(record_sha256: str) -> str:
    if (
        not isinstance(record_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", record_sha256) is None
    ):
        raise RepoGroundPostMergeError("Exhausted RepoGround audit SHA-256 is invalid")
    return RECONCILE_EXHAUSTED_METADATA_PREFIX + record_sha256


def _exhausted_record_payload(record_sha256: str) -> str:
    _exhausted_record_key(record_sha256)
    return json.dumps(
        {
            "schema_version": 1,
            "captain_audit_completion_sha256": record_sha256,
            "status": "manual_recovery_required",
            "reason": "durable_freshness_job_slots_exhausted",
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _acknowledged_record_key(record_sha256: str) -> str:
    _exhausted_record_key(record_sha256)
    return RECONCILE_ACKNOWLEDGED_METADATA_PREFIX + record_sha256


def _acknowledged_record_payload(
    record_sha256: str, *, merge_sha: str, authoritative_head: str,
) -> str:
    _acknowledged_record_key(record_sha256)
    for value in (merge_sha, authoritative_head):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise RepoGroundPostMergeError(
                "Exhausted acknowledgement SHA-1 identity is invalid"
            )
    return json.dumps(
        {
            "schema_version": 1,
            "captain_audit_completion_sha256": record_sha256,
            "status": "fresh_exact_acknowledged",
            "merge_sha": merge_sha,
            "authoritative_head": authoritative_head,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _is_exhausted_acknowledged(
    connection: Any, record_sha256: str,
) -> bool:
    key = _acknowledged_record_key(record_sha256)
    row = connection.execute(
        "SELECT value FROM metadata WHERE key=?", (key,),
    ).fetchone()
    if row is None:
        return False
    try:
        payload = json.loads(str(row[0]))
    except (TypeError, ValueError) as exc:
        raise RepoGroundPostMergeError(
            "Exhausted acknowledgement record is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "schema_version", "captain_audit_completion_sha256",
            "status", "merge_sha", "authoritative_head",
        }
        or payload.get("schema_version") != 1
        or payload.get("captain_audit_completion_sha256") != record_sha256
        or payload.get("status") != "fresh_exact_acknowledged"
    ):
        raise RepoGroundPostMergeError(
            "Exhausted acknowledgement record is invalid"
        )
    if str(row[0]) != _acknowledged_record_payload(
        record_sha256,
        merge_sha=payload["merge_sha"],
        authoritative_head=payload["authoritative_head"],
    ):
        raise RepoGroundPostMergeError(
            "Exhausted acknowledgement record is invalid"
        )
    return True


def _read_exhausted_acknowledgement(
    tasks_module: Any, record_sha256: str,
) -> bool:
    with tasks_module._database_connection() as connection:
        return _is_exhausted_acknowledged(connection, record_sha256)


def _require_exhausted_record(tasks_module: Any, record_sha256: str) -> None:
    key = _exhausted_record_key(record_sha256)
    with tasks_module._database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key=?", (key,)
        ).fetchone()
    if row is None:
        raise RepoGroundPostMergeError(
            "Exhausted RepoGround audit is not durably registered"
        )
    if str(row[0]) != _exhausted_record_payload(record_sha256):
        raise RepoGroundPostMergeError("Exhausted RepoGround audit record is invalid")


def list_exhausted_audit_followups(
    *, limit: int = 50, after_sha256: str | None = None
) -> dict[str, Any]:
    """Report only bounded, persisted manual recovery obligations."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise RepoGroundPostMergeError("Exhausted audit list limit is invalid")
    if after_sha256 is not None:
        _exhausted_record_key(after_sha256)
    import grabowski_tasks

    lower = (
        RECONCILE_EXHAUSTED_METADATA_PREFIX
        if after_sha256 is None
        else _exhausted_record_key(after_sha256)
    )
    with grabowski_tasks._database_connection() as connection:
        rows = connection.execute(
            "SELECT key, value FROM metadata WHERE key>? AND key<? "
            "ORDER BY key LIMIT ?",
            (lower, RECONCILE_EXHAUSTED_METADATA_PREFIX + "g", limit + 1),
        ).fetchall()
    entries: list[dict[str, Any]] = []
    for row in rows[:limit]:
        key, payload = row[0], row[1]
        if not isinstance(key, str) or not key.startswith(
            RECONCILE_EXHAUSTED_METADATA_PREFIX
        ):
            raise RepoGroundPostMergeError("Exhausted audit inventory key is invalid")
        sha = key[len(RECONCILE_EXHAUSTED_METADATA_PREFIX):]
        if key != _exhausted_record_key(sha) or str(payload) != (
            _exhausted_record_payload(sha)
        ):
            raise RepoGroundPostMergeError("Exhausted audit inventory entry is invalid")
        entries.append({"captain_audit_completion_sha256": sha})
    return {
        "kind": "grabowski.repoground_post_merge_exhausted_audits",
        "schema_version": 1,
        "status": "ok",
        "items": entries,
        "returned": len(entries),
        "truncated": len(rows) > limit,
        "next_after_sha256": (
            entries[-1]["captain_audit_completion_sha256"] if entries else None
        ),
        "does_not_establish": ["freshness_converged", "recovery_started"],
    }


def _exhausted_recovery_request(record_sha256: str) -> dict[str, Any]:
    import grabowski_tasks

    _require_exhausted_record(grabowski_tasks, record_sha256)
    request = captain_followup_request_from_audit(
        record_sha256,
        python_executable=__import__("sys").executable,
        script_path=Path(__file__).resolve(),
    )
    if request.get("status") not in {"ready", "ready_queue_watch"}:
        raise RepoGroundPostMergeError(
            "Exhausted audit does not identify a recoverable verified Captain merge"
        )
    return request


def recover_exhausted_audit_followup(record_sha256: str) -> dict[str, Any]:
    """Explicit manual retry via the existing publisher, without new job slots.

    The durable debt remains until a different invocation proves fresh_exact
    and atomically acknowledges it. This call never edits task metadata.
    """
    request = _exhausted_recovery_request(record_sha256)
    if request["status"] == "ready":
        convergence = converge(
            repository=request["repository"],
            merge_sha=request["merge_sha"],
            target_branch=request["target_branch"],
        )
    else:
        convergence = watch_merge_queue(
            repository=request["repository"],
            pull_request=request["pull_request"],
            expected_head=request["expected_head"],
            expected_base=request["expected_base"],
        )
    if not isinstance(convergence, dict):
        raise RepoGroundPostMergeError("Exhausted recovery result is invalid")
    return {
        "kind": "grabowski.repoground_post_merge_exhausted_recovery",
        "schema_version": 1,
        "status": "fresh_exact" if convergence.get("status") == "fresh_exact" else "failed",
        "captain_audit_completion_sha256": record_sha256,
        "ledger_retained": True,
        "acknowledgement_required": True,
        "convergence": convergence,
        "does_not_establish": ["debt_acknowledged", "future_branch_freshness"],
    }


def acknowledge_exhausted_audit_followup(record_sha256: str) -> dict[str, Any]:
    """Single CAS metadata mutation, only after live exactness is reverified."""
    import grabowski_tasks

    request = _exhausted_recovery_request(record_sha256)
    repository = request["repository"]
    if request["status"] == "ready":
        merge_sha = request["merge_sha"]
        target_branch = request["target_branch"]
    else:
        observed = _read_queue_pr(repository, request["pull_request"])
        if (
            observed.get("number") != request["pull_request"]
            or observed.get("headRefOid") != request["expected_head"]
            or observed.get("baseRefName") != request["expected_base"]
            or observed.get("state") != "MERGED"
        ):
            raise RepoGroundPostMergeError(
                "Exhausted queue audit has no verified merged identity"
            )
        merge_commit = observed.get("mergeCommit")
        merge_sha = _validate_sha(
            merge_commit.get("oid") if isinstance(merge_commit, dict) else None
        )
        target_branch = request["expected_base"]

    exact, projection = _fresh_exact(
        _read_freshness(repository),
        merge_sha=merge_sha,
        target_branch=target_branch,
        ancestry_checker=_check_ancestry,
    )
    repo_path = projection.get("repo_path")
    bundle_commit = projection.get("bundle_commit")
    if not exact or not isinstance(repo_path, str) or not repo_path:
        raise RepoGroundPostMergeError(
            "Exhausted audit acknowledgement requires live fresh_exact"
        )
    # Re-read origin directly, even if the freshness source supplied an older
    # previously observed remote head. A stale publication is not an ACK.
    authoritative_head = _read_remote_branch_head(repo_path, target_branch)
    if authoritative_head != bundle_commit:
        raise RepoGroundPostMergeError(
            "Exhausted audit acknowledgement detected a newer origin branch"
        )
    key = _exhausted_record_key(record_sha256)
    payload = _exhausted_record_payload(record_sha256)
    with grabowski_tasks._database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if _is_exhausted_acknowledged(connection, record_sha256):
            raise RepoGroundPostMergeError(
                "Exhausted audit is already acknowledged"
            )
        # One transaction owns both the deleted debt and the durable positive
        # ACK. A stale scanner must be able to distinguish "never existed"
        # from "verified fresh_exact and already acknowledged".
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?)",
            (
                _acknowledged_record_key(record_sha256),
                _acknowledged_record_payload(
                    record_sha256,
                    merge_sha=merge_sha,
                    authoritative_head=authoritative_head,
                ),
            ),
        )
        deleted = connection.execute(
            "DELETE FROM metadata WHERE key=? AND value=?", (key, payload)
        ).rowcount
        if deleted != 1:
            raise RepoGroundPostMergeError(
                "Exhausted audit changed before acknowledgement"
            )
    return {
        "kind": "grabowski.repoground_post_merge_exhausted_ack",
        "schema_version": 1,
        "status": "ok",
        "captain_audit_completion_sha256": record_sha256,
        "recovered_merge_sha": merge_sha,
        "authoritative_head": authoritative_head,
        "freshness": projection,
        "ledger_removed": True,
        "acknowledgement_persisted": True,
        "does_not_establish": ["future_branch_freshness"],
    }


def _save_reconcile_progress(
    tasks_module: Any,
    *,
    cursor: str | None,
    discovery_ordinal: int | None,
    exhausted_completion_record_sha256s: tuple[str, ...] = (),
    scan_next_ordinal: int | None = None,
    expected_discovery_ordinal: Any = _RECONCILE_CAS_UNSET,
    expected_cursor: Any = _RECONCILE_CAS_UNSET,
    expected_scan_next_ordinal: Any = _RECONCILE_CAS_UNSET,
) -> None:
    payloads: list[tuple[str, str]] = []
    if cursor is not None:
        if (
            not isinstance(cursor, str)
            or re.fullmatch(r"[0-9a-f]{64}", cursor) is None
        ):
            raise RepoGroundPostMergeError(
                "RepoGround post-merge reconcile cursor identity is invalid"
            )
        payloads.append(
            (
                RECONCILE_CURSOR_METADATA_KEY,
                json.dumps(
                    {"schema_version": 1, "cursor": cursor},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
    if discovery_ordinal is not None:
        if (
            isinstance(discovery_ordinal, bool)
            or not isinstance(discovery_ordinal, int)
            or discovery_ordinal < 0
        ):
            raise RepoGroundPostMergeError(
                "RepoGround post-merge discovery watermark ordinal is invalid"
            )
        payloads.append(
            (
                RECONCILE_DISCOVERY_METADATA_KEY,
                json.dumps(
                    {
                        "schema_version": 1,
                        "global_ordinal": discovery_ordinal,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
    if scan_next_ordinal is not None:
        if type(scan_next_ordinal) is not int or scan_next_ordinal < 1:
            raise RepoGroundPostMergeError("RepoGround scan cursor is invalid")
        payloads.append(
            (
                RECONCILE_SCAN_NEXT_METADATA_KEY,
                json.dumps(
                    {"schema_version": 1, "next_ordinal": scan_next_ordinal},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
    if len(exhausted_completion_record_sha256s) > 100:
        raise RepoGroundPostMergeError("Exhausted RepoGround obligations exceed pass bound")
    for record_sha256 in exhausted_completion_record_sha256s:
        payloads.append(
            (
                _exhausted_record_key(record_sha256),
                _exhausted_record_payload(record_sha256),
            )
        )
    if not payloads:
        return

    cas_discovery = expected_discovery_ordinal is not _RECONCILE_CAS_UNSET
    cas_cursor = expected_cursor is not _RECONCILE_CAS_UNSET
    cas_scan = expected_scan_next_ordinal is not _RECONCILE_CAS_UNSET
    if cas_scan and expected_scan_next_ordinal is not None and (
        type(expected_scan_next_ordinal) is not int
        or expected_scan_next_ordinal < 1
    ):
        raise RepoGroundPostMergeError("Expected RepoGround scan cursor is invalid")
    if cas_discovery and expected_discovery_ordinal is not None and (
        type(expected_discovery_ordinal) is not int
        or expected_discovery_ordinal < 0
    ):
        raise RepoGroundPostMergeError(
            "Expected RepoGround discovery watermark is invalid"
        )
    if cas_cursor and expected_cursor is not None and (
        not isinstance(expected_cursor, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_cursor) is None
    ):
        raise RepoGroundPostMergeError("Expected RepoGround cursor is invalid")
    if (
        cas_discovery
        and discovery_ordinal is not None
        and expected_discovery_ordinal is not None
        and discovery_ordinal < expected_discovery_ordinal
    ):
        raise RepoGroundPostMergeError(
            "RepoGround discovery watermark must never move backwards"
        )

    # Validate the exact old cursor/discovery under the SQLite writer lock.
    # A stale reconciler must neither rewind progress nor recreate a ledger
    # entry which a concurrent manual fresh_exact acknowledgement removed.
    # Cursor, watermark and new debt remain one atomic mutation.
    with tasks_module._database_connection() as connection:
        if cas_discovery or cas_cursor or cas_scan or exhausted_completion_record_sha256s:
            connection.execute("BEGIN IMMEDIATE")
        # Fail closed on a monotone per-audit ACK, even if an overlapping
        # stale pass still has a valid old cursor/ordinal CAS preimage.
        for record_sha256 in exhausted_completion_record_sha256s:
            if _is_exhausted_acknowledged(connection, record_sha256):
                raise RepoGroundPostMergeError(
                    "Exhausted audit is already acknowledged"
                )
        if cas_discovery or cas_cursor or cas_scan:
            for field, key, value in (
                (
                    "discovery watermark",
                    RECONCILE_DISCOVERY_METADATA_KEY,
                    expected_discovery_ordinal,
                ),
                ("cursor", RECONCILE_CURSOR_METADATA_KEY, expected_cursor),
                ("scan cursor", RECONCILE_SCAN_NEXT_METADATA_KEY,
                 expected_scan_next_ordinal),
            ):
                if value is _RECONCILE_CAS_UNSET:
                    continue
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key=?", (key,)
                ).fetchone()
                try:
                    observed = json.loads(str(row[0])) if row is not None else None
                except (TypeError, ValueError) as exc:
                    raise RepoGroundPostMergeError(
                        "RepoGround " + field + " changed before persistence"
                    ) from exc
                expected = (
                    None
                    if value is None
                    else {
                        "schema_version": 1,
                        (
                            "global_ordinal" if field == "discovery watermark"
                            else "next_ordinal" if field == "scan cursor"
                            else "cursor"
                        ): value,
                    }
                )
                if observed != expected:
                    raise RepoGroundPostMergeError(
                        "RepoGround " + field + " changed before persistence"
                    )
        for key, payload in payloads:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, payload),
            )


def _save_reconcile_cursor(tasks_module: Any, cursor: str) -> None:
    _save_reconcile_progress(
        tasks_module,
        cursor=cursor,
        discovery_ordinal=None,
    )


def initialize_reconcile_discovery_watermark(
    *,
    predecessor_module_path: Path | None = None,
) -> dict[str, Any]:
    """Seed the verified audit tip only before first activation of this feature.

    Deployment must call this before the target operator can serve Captain merges.
    Existing progress is immutable to the initializer: later deployments must
    retain unfinished obligations instead of replacing their lower boundary.
    """
    import grabowski_audit_query
    import grabowski_operator
    import grabowski_tasks

    if not isinstance(getattr(grabowski_operator, "STATE_DIR", None), Path):
        raise RepoGroundPostMergeError(
            "RepoGround discovery state store is unavailable"
        )

    existing = _load_reconcile_discovery_ordinal(grabowski_tasks)
    if existing is not None:
        return {
            "kind": "grabowski.repoground_post_merge_discovery_bootstrap",
            "schema_version": 1,
            "status": "ok",
            "initialized": False,
            "global_ordinal": existing,
        }

    predecessor = (
        DEFAULT_PREDECESSOR_RECONCILER_SOURCE
        if predecessor_module_path is None
        else predecessor_module_path
    )
    if not isinstance(predecessor, Path):
        raise RepoGroundPostMergeError("Predecessor module path is invalid")
    if predecessor.is_file():
        raise RepoGroundPostMergeError(
            "Prior runtime supports RepoGround reconciliation but its "
            "discovery watermark is missing; refusing to discard pending work"
        )

    snapshot = grabowski_audit_query.capture_verified_audit_snapshot()
    tip = snapshot.total_records
    if type(tip) is not int or tip < 0:
        raise RepoGroundPostMergeError("Verified audit tip ordinal is invalid")

    payload = json.dumps(
        {"schema_version": 1, "global_ordinal": tip},
        sort_keys=True,
        separators=(",", ":"),
    )
    with grabowski_tasks._database_connection() as connection:
        inserted = connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO NOTHING",
            (RECONCILE_DISCOVERY_METADATA_KEY, payload),
        ).rowcount == 1
    observed = _load_reconcile_discovery_ordinal(grabowski_tasks)
    if observed is None:
        raise RepoGroundPostMergeError(
            "RepoGround discovery bootstrap did not persist a valid watermark"
        )
    return {
        "kind": "grabowski.repoground_post_merge_discovery_bootstrap",
        "schema_version": 1,
        "status": "ok",
        "initialized": inserted,
        "global_ordinal": observed,
    }


def _cursor_ordered_completion_records(
    record_sha256s: list[str],
    cursor: str | None,
) -> list[str]:
    ordered = list(record_sha256s)
    if cursor is None or cursor not in ordered:
        return ordered
    start = ordered.index(cursor) + 1
    return ordered[start:] + ordered[:start]


def _iter_reconcile_audit_window(
    audit_query: Any,
    snapshot: Any,
    *,
    first: int,
    last: int,
) -> Any:
    """Seek in verified segment ordinals, decode at most a bounded page."""
    segments = getattr(snapshot, "segments", None)
    if not isinstance(segments, tuple) or not segments:
        raise RepoGroundPostMergeError("Verified audit segments are unavailable")
    selected = tuple(
        segment
        for segment in segments
        if (
            type(getattr(segment, "global_start_ordinal", None)) is int
            and type(getattr(segment, "global_end_ordinal", None)) is int
            and segment.global_start_ordinal <= last
            and segment.global_end_ordinal >= first
        )
    )
    if not selected:
        raise RepoGroundPostMergeError("Verified audit scan window is not covered")
    # The full audit snapshot was verified by its authoritative source. Only
    # its unchanged segment objects are passed to the existing checked reader.
    view = SimpleNamespace(segments=selected)
    for item in audit_query._iter_snapshot_items(view, order="asc"):
        evidence = item.get("evidence") if isinstance(item, dict) else None
        ordinal = evidence.get("global_ordinal") if isinstance(evidence, dict) else None
        if type(ordinal) is not int:
            raise RepoGroundPostMergeError("Verified audit scan ordinal is unavailable")
        if ordinal < first:
            continue
        if ordinal > last:
            break
        yield item


def reconcile_recent_captain_audit_followups(
    *,
    lookback_seconds: int = DEFAULT_RECONCILE_LOOKBACK_SECONDS,
    limit: int = 64,
) -> dict[str, Any]:
    if type(lookback_seconds) is not int or not 60 <= lookback_seconds <= 86_400:
        raise RepoGroundPostMergeError("reconcile lookback is out of bounds")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise RepoGroundPostMergeError("reconcile limit is out of bounds")

    pass_started_monotonic = time.monotonic()
    pass_deadline_monotonic = (
        pass_started_monotonic + DEFAULT_RECONCILE_PASS_BUDGET_SECONDS
    )

    import grabowski_audit_query
    import grabowski_operator

    cursor_tasks: Any | None = None
    cursor_before: str | None = None
    discovery_ordinal_before: int | None = None
    scan_next_before: int | None = None
    if isinstance(getattr(grabowski_operator, "STATE_DIR", None), Path):
        import grabowski_tasks

        cursor_tasks = grabowski_tasks
        cursor_before = _load_reconcile_cursor(cursor_tasks)
        discovery_ordinal_before = _load_reconcile_discovery_ordinal(cursor_tasks)
        if callable(getattr(cursor_tasks, "_database_connection", None)):
            scan_next_before = _load_reconcile_scan_next(cursor_tasks)

    since_unix = int(time.time()) - lookback_seconds
    snapshot = grabowski_audit_query.capture_verified_audit_snapshot()
    max_scan_records = grabowski_audit_query.MAX_SCAN_RECORDS
    if (
        type(max_scan_records) is not int
        or max_scan_records < 1
    ):
        raise RepoGroundPostMergeError("Captain audit reconciliation scan bound is invalid")

    # Bootstrap with the bounded wall-clock lookback, then resume from a durable
    # audit ordinal. Once the watermark exists, outages cannot age an unseen
    # Captain merge out of discovery.
    completion_record_sha256s: list[str] = []
    completion_record_ordinals: dict[str, int] = {}
    scanned_records = 0
    lookback_horizon_reached = False
    window_mode = (
        discovery_ordinal_before is not None
        and type(getattr(snapshot, "total_records", None)) is int
        and (
            snapshot.total_records - discovery_ordinal_before >= max_scan_records
            or (
                isinstance(getattr(snapshot, "segments", None), tuple)
                and snapshot.total_records > discovery_ordinal_before
            )
        )
    )
    scan_start: int | None = None
    scan_end: int | None = None
    if window_mode:
        scan_start = (
            scan_next_before
            if (
                scan_next_before is not None
                and discovery_ordinal_before < scan_next_before <= snapshot.total_records
            )
            else discovery_ordinal_before + 1
        )
        scan_end = min(snapshot.total_records, scan_start + max_scan_records - 1)
    newest_global_ordinal: int | None = scan_end if window_mode else None
    discovery_watermark_reached = (
        scan_start == discovery_ordinal_before + 1
        if window_mode
        else discovery_ordinal_before in (None, 0)
    )
    iterator = (
        _iter_reconcile_audit_window(
            grabowski_audit_query, snapshot, first=scan_start, last=scan_end
        )
        if window_mode
        else grabowski_audit_query._iter_snapshot_items(snapshot, order="desc")
    )
    for item in iterator:
        if scanned_records >= max_scan_records:
            raise RepoGroundPostMergeError(
                "Captain audit reconciliation scan truncated before discovery boundary"
            )
        scanned_records += 1
        evidence = item.get("evidence") if isinstance(item, dict) else None
        record = item.get("record") if isinstance(item, dict) else None
        if not isinstance(evidence, dict) or not isinstance(record, dict):
            raise RepoGroundPostMergeError(
                "Captain audit reconciliation snapshot item is invalid"
            )

        global_ordinal = evidence.get("global_ordinal")
        if global_ordinal is not None and (
            isinstance(global_ordinal, bool)
            or not isinstance(global_ordinal, int)
            or global_ordinal < 1
        ):
            raise RepoGroundPostMergeError(
                "Captain audit reconciliation global ordinal is invalid"
            )
        if window_mode:
            assert scan_start is not None
            if global_ordinal != scan_start + scanned_records - 1:
                raise RepoGroundPostMergeError(
                    "Verified audit scan window contains an ordinal gap"
                )
        if newest_global_ordinal is None and isinstance(global_ordinal, int):
            newest_global_ordinal = global_ordinal
            if (
                discovery_ordinal_before is not None
                and newest_global_ordinal < discovery_ordinal_before
            ):
                raise RepoGroundPostMergeError(
                    "Captain audit reconciliation discovery watermark is ahead of audit"
                )
        if discovery_ordinal_before is not None:
            if not isinstance(global_ordinal, int):
                raise RepoGroundPostMergeError(
                    "Captain audit reconciliation global ordinal is unavailable"
                )
            if global_ordinal <= discovery_ordinal_before:
                discovery_watermark_reached = True
                break

        is_pr_merge_completion = bool(
            record.get("operation") == "captain-run-audit-completion"
            and record.get("action") == "pr-merge"
        )
        try:
            timestamp_unix = _reconcile_record_timestamp_unix(record)
        except RepoGroundPostMergeError:
            if is_pr_merge_completion:
                raise
            continue
        if timestamp_unix < since_unix:
            lookback_horizon_reached = True
            # A moving wall-clock horizon cannot prove that initial discovery
            # is complete after an outage. With no durable ordinal, exhaust
            # the verified stream or fail closed at MAX_SCAN_RECORDS.
        if not is_pr_merge_completion:
            continue
        record_sha256 = evidence.get("record_sha256")
        if (
            not isinstance(record_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", record_sha256) is None
        ):
            raise RepoGroundPostMergeError(
                "Captain audit reconciliation record identity is invalid"
            )
        completion_record_sha256s.append(record_sha256)
        if window_mode:
            if type(global_ordinal) is not int:
                raise RepoGroundPostMergeError(
                    "Verified Captain completion ordinal is unavailable"
                )
            completion_record_ordinals[record_sha256] = global_ordinal
        if window_mode and len(completion_record_sha256s) >= limit:
            # This is a contiguous, ordinal-verified prefix. Never collect
            # more exhausted obligations than one transaction can persist.
            scan_end = global_ordinal
            newest_global_ordinal = scan_end
            break

    if window_mode:
        assert scan_start is not None and scan_end is not None
        if scanned_records != scan_end - scan_start + 1:
            raise RepoGroundPostMergeError(
                "Verified audit scan window was truncated before its last ordinal"
            )
    elif discovery_ordinal_before is not None and not discovery_watermark_reached:
        raise RepoGroundPostMergeError(
            "Captain audit reconciliation discovery watermark was not reached"
        )

    starter = resolve_job_starter({"grabowski_operator": grabowski_operator})
    if starter is None:
        raise RepoGroundPostMergeError("durable Grabowski job starter is unavailable")

    outcomes: list[dict[str, Any]] = []
    budget_exhausted = False
    cursor_candidate = cursor_before
    scheduling_mutation_attempted = False
    processing_record_sha256s = _cursor_ordered_completion_records(
        completion_record_sha256s,
        cursor_before,
    )
    for record_sha256 in processing_record_sha256s:
        remaining_seconds = pass_deadline_monotonic - time.monotonic()
        if remaining_seconds < POST_MERGE_SINGLE_IDENTITY_BUDGET_SECONDS:
            budget_exhausted = True
            break
        # A fresh_exact ACK is a terminal fact for this immutable audit.
        # On later retries it must not consume job slots or recreate debt.
        # The save-side check below handles ACKs racing with this read.
        if cursor_tasks is not None and callable(
            getattr(cursor_tasks, "_database_connection", None)
        ) and _read_exhausted_acknowledgement(cursor_tasks, record_sha256):
            outcome = {
                "status": "already_satisfied",
                "reason": "durable_exhausted_audit_previously_acknowledged",
                "reused": True,
            }
        else:
            outcome = schedule_from_captain_audit_completion(
                record_sha256,
                job_starter=starter,
                python_executable=__import__("sys").executable,
                script_path=Path(__file__).resolve(),
            )
        outcome_summary = {
            "captain_audit_completion_sha256": record_sha256,
            "status": outcome.get("status"),
            "reason": outcome.get("reason"),
            "repository": outcome.get("repository"),
            "merge_sha": outcome.get("merge_sha"),
            "pull_request": outcome.get("pull_request"),
            "unit": outcome.get("unit"),
            "reused": outcome.get("reused") is True,
        }
        outcomes.append(outcome_summary)
        # One reconciliation invocation is one mutation attempt. Reads may skip
        # already-satisfied/running work, but after a new or uncertain launch
        # we stop so a single reconcile pass can never create two jobs.
        status = outcome.get("status")
        safe_read_only = (
            status in {"already_satisfied", "not_scheduled", "retry_deferred"}
            or (status == "scheduled" and outcome.get("reused") is True)
        )
        if safe_read_only:
            cursor_candidate = record_sha256
            continue

        # A new or uncertain schedule is the mutation attempt for this pass.
        # Cursor persistence must therefore wait for a later read-only pass.
        scheduling_mutation_attempted = True
        break

    cursor_after = cursor_before
    discovery_ordinal_after = discovery_ordinal_before
    cursor_persisted = False
    discovery_watermark_persisted = False
    progress_persisted = False
    exhausted_obligations_recorded: tuple[str, ...] = ()
    if not scheduling_mutation_attempted:
        exhausted_pending = tuple(
            outcome["captain_audit_completion_sha256"]
            for outcome in outcomes
            if outcome["status"] == "not_scheduled"
            and outcome["reason"] == "durable_freshness_job_slots_exhausted"
        )
        cursor_after = cursor_candidate
        # Only terminal, immutable outcomes can be checkpointed. In the
        # oldest-first verified audit window a slow pass can commit the
        # contiguous terminal prefix while keeping the remaining completions
        # discoverable. Never advance across a deferred or unknown outcome.
        def terminal_discovery_outcome(outcome: dict[str, Any]) -> bool:
            return bool(
                outcome["status"] == "already_satisfied"
                or (
                    outcome["status"] == "not_scheduled"
                    and (
                        outcome["reason"] in {
                            "merge_verification_not_passed",
                            "captain_merge_not_fast_path_eligible",
                        }
                        or (
                            outcome["reason"] == "durable_freshness_job_slots_exhausted"
                            and cursor_tasks is not None
                        )
                    )
                )
            )

        discovery_complete = (
            not budget_exhausted
            and len(outcomes) == len(completion_record_sha256s)
            and all(terminal_discovery_outcome(outcome) for outcome in outcomes)
        )
        discovery_ordinal_candidate = (
            newest_global_ordinal
            if (
                discovery_complete
                and newest_global_ordinal is not None
                and (not window_mode or discovery_watermark_reached)
            )
            else discovery_ordinal_before
        )
        if window_mode and discovery_watermark_reached and not discovery_complete:
            settled_outcomes = {
                outcome["captain_audit_completion_sha256"]: outcome
                for outcome in outcomes
            }
            for completion_sha in completion_record_sha256s:
                completion = settled_outcomes.get(completion_sha)
                if completion is None or not terminal_discovery_outcome(completion):
                    break
                discovery_ordinal_candidate = completion_record_ordinals[completion_sha]
        discovery_ordinal_after = discovery_ordinal_candidate
        cursor_changed = (
            cursor_candidate is not None and cursor_candidate != cursor_before
        )
        discovery_changed = (
            discovery_ordinal_candidate is not None
            and discovery_ordinal_candidate != discovery_ordinal_before
        )
        # Only expose exhausted work for manual recovery once the verified
        # discovery boundary can advance in this same SQLite transaction.
        # Otherwise the next pass could resurrect an already-acknowledged debt.
        exhausted_to_record = (
            tuple(
                sha for sha in exhausted_pending
                if completion_record_ordinals.get(sha, 0)
                <= discovery_ordinal_candidate
            )
            if window_mode and discovery_changed
            else exhausted_pending if discovery_changed else ()
        )
        scan_next_after = scan_next_before
        scan_next_changed = False
        if window_mode:
            assert scan_end is not None
            assert discovery_ordinal_before is not None
            assert type(snapshot.total_records) is int
            scan_next_candidate = (
                discovery_ordinal_candidate + 1
                if discovery_changed and not discovery_complete
                else (
                    scan_end + 1
                    if scan_end < snapshot.total_records or discovery_changed
                    else discovery_ordinal_before + 1
                )
            )
            scan_next_changed = scan_next_candidate != scan_next_before
        if cursor_tasks is not None and (
            cursor_changed or discovery_changed or exhausted_to_record
            or scan_next_changed
        ):
            progress_args: dict[str, Any] = {
                "cursor": cursor_candidate if cursor_changed else None,
                "discovery_ordinal": (
                    discovery_ordinal_candidate if discovery_changed else None
                ),
            }
            if exhausted_to_record:
                progress_args["exhausted_completion_record_sha256s"] = exhausted_to_record
            if scan_next_changed:
                progress_args["scan_next_ordinal"] = scan_next_candidate
            # Existing mocked legacy unit fixtures without a database retain
            # their original signature; actual TaskStore persistence is CAS.
            if callable(getattr(cursor_tasks, "_database_connection", None)):
                progress_args["expected_discovery_ordinal"] = discovery_ordinal_before
                progress_args["expected_cursor"] = cursor_before
                progress_args["expected_scan_next_ordinal"] = scan_next_before
            _save_reconcile_progress(cursor_tasks, **progress_args)
            cursor_persisted = cursor_changed
            discovery_watermark_persisted = discovery_changed
            exhausted_obligations_recorded = exhausted_to_record
            progress_persisted = True
            if scan_next_changed:
                scan_next_after = scan_next_candidate

    return {
        "kind": "grabowski.repoground_post_merge_reconcile",
        "schema_version": 1,
        "status": "ok",
        "lookback_seconds": lookback_seconds,
        "matched": len(completion_record_sha256s),
        "processed": len(outcomes),
        "outcomes": outcomes,
        "audit_query_truncated": False,
        "scanned_records": scanned_records,
        "lookback_horizon_reached": lookback_horizon_reached,
        "processing_order": (
            "cursor_round_robin_bounded_oldest_window"
            if window_mode else "cursor_round_robin_newest_seed"
        ),
        "scan_mode": "bounded_rotation" if window_mode else "normal",
        "scan_start_ordinal": scan_start,
        "scan_end_ordinal": scan_end,
        "scan_next_before": scan_next_before,
        "scan_next_after": (
            scan_next_after if not scheduling_mutation_attempted and window_mode
            else scan_next_before
        ),
        "cursor_before": cursor_before,
        "cursor_after": cursor_after,
        "cursor_persisted": cursor_persisted,
        "cursor_persistence_available": cursor_tasks is not None,
        "discovery_ordinal_before": discovery_ordinal_before,
        "discovery_ordinal_after": discovery_ordinal_after,
        "discovery_watermark_reached": discovery_watermark_reached,
        "discovery_watermark_persisted": discovery_watermark_persisted,
        "progress_persisted": progress_persisted,
        "exhausted_obligations_recorded": list(exhausted_obligations_recorded),
        "pass_budget_seconds": DEFAULT_RECONCILE_PASS_BUDGET_SECONDS,
        "budget_exhausted": budget_exhausted,
        "remaining": len(completion_record_sha256s) - len(outcomes),
    }

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Converge one verified PR merge to an exact RepoGround fleet publication, "
            "or watch one verified merge-queue entry until it is merged."
        )
    )
    parser.add_argument("--repo")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--merge-sha")
    mode.add_argument("--pr", type=int)
    mode.add_argument("--reconcile-audit-followups", action="store_true")
    mode.add_argument("--initialize-reconcile-watermark", action="store_true")
    mode.add_argument("--list-exhausted-audits", action="store_true")
    mode.add_argument("--recover-exhausted-audit")
    mode.add_argument("--ack-exhausted-audit")
    parser.add_argument("--exhausted-limit", type=int, default=50)
    parser.add_argument("--exhausted-after-sha256")
    parser.add_argument(
        "--reconcile-lookback-seconds",
        type=int,
        default=DEFAULT_RECONCILE_LOOKBACK_SECONDS,
    )
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-base")
    parser.add_argument("--target-branch", default="main")
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
        if args.list_exhausted_audits:
            if args.repo is not None:
                parser.error("--list-exhausted-audits does not accept --repo")
            result = list_exhausted_audit_followups(
                limit=args.exhausted_limit,
                after_sha256=args.exhausted_after_sha256,
            )
        elif args.recover_exhausted_audit is not None:
            if args.repo is not None or args.exhausted_after_sha256 is not None:
                parser.error("--recover-exhausted-audit does not accept --repo or pagination")
            result = recover_exhausted_audit_followup(args.recover_exhausted_audit)
        elif args.ack_exhausted_audit is not None:
            if args.repo is not None or args.exhausted_after_sha256 is not None:
                parser.error("--ack-exhausted-audit does not accept --repo or pagination")
            result = acknowledge_exhausted_audit_followup(args.ack_exhausted_audit)
        elif args.initialize_reconcile_watermark:
            if args.repo is not None:
                parser.error("--initialize-reconcile-watermark does not accept --repo")
            result = initialize_reconcile_discovery_watermark()
        elif args.reconcile_audit_followups:
            if args.repo is not None:
                parser.error("--reconcile-audit-followups does not accept --repo")
            result = reconcile_recent_captain_audit_followups(
                lookback_seconds=args.reconcile_lookback_seconds,
            )
        elif args.pr is not None:
            if args.repo is None:
                parser.error("--pr requires --repo")
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
            if args.repo is None:
                parser.error("--merge-sha requires --repo")
            result = converge(
                repository=args.repo,
                merge_sha=args.merge_sha,
                target_branch=args.target_branch,
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
    return 0 if result.get("status") in {"fresh_exact", "ok"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
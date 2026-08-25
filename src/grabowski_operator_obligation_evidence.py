from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import time
from typing import Any, Mapping

import grabowski_operator_obligation as obligations

SCHEMA_VERSION = 1
KIND = "grabowski.operator_obligation_evidence_assessment"
SAMPLE_KIND = "grabowski.operator_obligation_evidence_sample"
OBSERVATION_KIND = "grabowski.operator_obligation_evidence_observation"
PREPARATION_KIND = "grabowski.operator_obligation_evidence_preparation"
PREPARABLE_SOURCES = ("bureau", "github", "git", "runtime", "test")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TASK_ID_RE = re.compile(r"^[0-9a-f]{24}$")
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{16,240}$")
BUREAU_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:@/+-]{1,512}$")
CLASSIFICATIONS = (
    "verified",
    "unverified",
    "stale",
    "mismatch",
    "missing",
    "legacy_unverifiable",
    "unsupported",
)
OBSERVATION_STATUSES = frozenset({"verified", "stale", "mismatch", "unsupported"})
MIN_ROLLOUT_SAMPLE = 30
MAX_SAMPLE = 30
TRUSTED_OBSERVATION_ADAPTER_SOURCES = (
    "bureau",
    "github",
    "git",
    "receipt",
    "runtime",
    "test",
)
ROLLOUT_THRESHOLD_KIND = "grabowski.operator_obligation_evidence_rollout_threshold"
MAX_ADAPTER_FILE_BYTES = 4 * 1024 * 1024
MAX_ADAPTER_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
ADAPTER_COMMAND_TIMEOUT_SECONDS = 15
MAX_ADAPTER_COLLECTION_SECONDS = 12.0
GITHUB_PR_REFERENCE_RE = re.compile(
    r"^github-pr:(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"#(?P<pr>[1-9][0-9]{0,9})@(?P<head>[0-9a-f]{40})"
    r":base=(?P<base>[0-9a-f]{40})"
    r":merge=(?P<merge>[0-9a-f]{40})"
    r":checks=(?P<passed>[0-9]{1,3})/(?P<total>[0-9]{1,3})-success$"
)
GITHUB_PR_V2_REFERENCE_RE = re.compile(
    r"^github-pr-v2:(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"#(?P<pr>[1-9][0-9]{0,9})@(?P<head>[0-9a-f]{40})"
    r":base=(?P<base>[0-9a-f]{40})"
    r":merge=(?P<merge>[0-9a-f]{40})"
    r":checks=(?P<passed>[0-9]{1,3})/(?P<total>[0-9]{1,3})-effective-success$"
)
GIT_COMMIT_REFERENCE_RE = re.compile(
    r"^git-commit:(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"@(?P<commit>[0-9a-f]{40})$"
)
RUNTIME_REFERENCE_RE = re.compile(
    r"^grabowski-runtime-manifest:repo_head=(?P<repo_head>[0-9a-f]{40});"
    r"release_id=(?P<release_id>[A-Za-z0-9_.-]{16,240});"
    r"runtime_input_sha256=(?P<runtime_input_sha256>[0-9a-f]{64})$"
)
BUREAU_CANDIDATE_REFERENCE_RE = re.compile(
    r"^bureau-candidate:(?P<candidate_id>candidate-[0-9a-f]{24})"
    r":event=(?P<event_id>[1-9][0-9]{0,18})"
    r":idempotency=(?P<idempotency_key>[A-Za-z0-9._:@/+-]{1,512})$"
)
TEST_TASK_REFERENCE_RE = re.compile(
    r"^grabowski-task:(?P<task_id>[0-9a-f]{24}):"
    r"(?P<passed>[0-9]{1,6})-passed\+(?P<subtests>[0-9]{1,6})-subtests$"
)
TEST_SUMMARY_RE = re.compile(
    rb"(?m)^(?P<passed>[0-9]{1,6}) passed"
    rb"(?P<extras>(?:, [0-9]{1,6} (?:subtests passed|skipped|xfailed|xpassed|deselected|warnings?|reruns?))*)"
    rb"(?: in [^\n]+)?$"
)
TEST_SUMMARY_EXTRA_RE = re.compile(
    rb", (?P<count>[0-9]{1,6}) (?P<label>subtests passed|skipped|xfailed|xpassed|deselected|warnings?|reruns?)"
)
UNITTEST_SUMMARY_RE = re.compile(
    rb"(?m)^Ran (?P<passed>[0-9]{1,6}) tests in [^\n]+\n\nOK(?:\n|$)"
)
WORKTREE_ENSURE_RECEIPT_PATH_RE = re.compile(
    r"^grip-receipts/worktree-ensure/(?P<key>[0-9a-f]{64})\.json$"
)
WORKTREE_ENSURE_SUCCESS_STATES = frozenset({"CREATED", "ALREADY_CORRECT"})
GITHUB_REMOTE_RE = re.compile(
    r"github\.com(?::|/)(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$"
)


class EvidenceAssessmentError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceAssessmentError(f"{label} must be a non-empty string")
    return value.strip()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and obligations.SHA256_RE.fullmatch(value) is not None


def _trusted_observation(
    evidence: Mapping[str, Any], *, status: str, sha256: str | None = None
) -> dict[str, Any]:
    digest = sha256 if _is_sha256(sha256) else evidence.get("sha256")
    if not _is_sha256(digest):
        digest = "0" * 64
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": OBSERVATION_KIND,
        "acceptance_id": _text(evidence.get("acceptance_id"), "acceptance_id"),
        "source": _text(evidence.get("source"), "source"),
        "reference": _text(evidence.get("reference"), "reference"),
        "sha256": digest,
        "status": status,
    }


def _read_regular_bytes(path: Path, *, maximum: int) -> bytes:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise EvidenceAssessmentError("adapter evidence path is unavailable") from exc
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise EvidenceAssessmentError("adapter evidence path cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceAssessmentError("adapter evidence path must be a regular file")
        if before.st_uid != os.geteuid() or (stat.S_IMODE(before.st_mode) & 0o022):
            raise EvidenceAssessmentError("adapter evidence path permissions are unsafe")
        if before.st_size < 0 or before.st_size > maximum:
            raise EvidenceAssessmentError("adapter evidence path exceeds the size bound")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise EvidenceAssessmentError("adapter evidence path exceeds the size bound")
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise EvidenceAssessmentError("adapter evidence path changed while being read")
    return data


def _run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    deadline_monotonic: float | None = None,
) -> tuple[int, bytes, bytes]:
    environment = dict(os.environ)
    environment.update(
        {
            "GH_PROMPT_DISABLED": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "PAGER": "cat",
        }
    )
    timeout_seconds = float(ADAPTER_COMMAND_TIMEOUT_SECONDS)
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise EvidenceAssessmentError("trusted source adapter budget exhausted")
        timeout_seconds = min(timeout_seconds, max(0.05, remaining))
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceAssessmentError("trusted source adapter command failed") from exc
    if (
        len(completed.stdout) > MAX_ADAPTER_COMMAND_OUTPUT_BYTES
        or len(completed.stderr) > MAX_ADAPTER_COMMAND_OUTPUT_BYTES
    ):
        raise EvidenceAssessmentError("trusted source adapter command output exceeded the bound")
    return completed.returncode, completed.stdout, completed.stderr


def _github_reference(reference: str) -> dict[str, Any] | None:
    match = GITHUB_PR_REFERENCE_RE.fullmatch(reference)
    version = 1
    if match is None:
        match = GITHUB_PR_V2_REFERENCE_RE.fullmatch(reference)
        version = 2
    if match is None:
        return None
    parsed: dict[str, Any] = {
        "repo": match.group("repo"),
        "pr": int(match.group("pr")),
        "head": match.group("head"),
        "base": match.group("base"),
        "merge": match.group("merge"),
        "passed": int(match.group("passed")),
        "total": int(match.group("total")),
        "version": version,
    }
    if parsed["total"] < 1 or parsed["total"] > 100 or parsed["passed"] != parsed["total"]:
        return None
    return parsed

def _github_observation_material(parsed: Mapping[str, Any]) -> dict[str, Any]:
    material = {
        "schema_version": 1,
        "kind": "grabowski.operator_obligation_evidence.github_pr_v1",
        "repo": parsed["repo"],
        "pr": parsed["pr"],
        "head": parsed["head"],
        "base": parsed["base"],
        "merge": parsed["merge"],
        "checks_passed": parsed["passed"],
        "checks_total": parsed["total"],
    }
    if parsed.get("version", 1) == 2:
        material.update(
            {
                "schema_version": 2,
                "kind": "grabowski.operator_obligation_evidence.github_pr_v2",
                "check_semantics": "latest_per_logical_identity_v1",
            }
        )
    return material


def _github_check_identity(
    check: Mapping[str, Any],
) -> tuple[tuple[str, ...], datetime] | None:
    typename = check.get("__typename")
    started_at = check.get("startedAt")
    if not isinstance(started_at, str) or not started_at.endswith("Z"):
        return None
    try:
        started = datetime.fromisoformat(started_at.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    if started.tzinfo != timezone.utc:
        return None
    if typename == "CheckRun":
        name = check.get("name")
        workflow_name = check.get("workflowName")
        if not isinstance(name, str) or not name or not isinstance(workflow_name, str):
            return None
        return ("CheckRun", workflow_name, name), started
    if typename == "StatusContext":
        context = check.get("context")
        if not isinstance(context, str) or not context:
            return None
        return ("StatusContext", context), started
    return None


def _effective_github_checks(
    checks: list[Any],
) -> list[Mapping[str, Any]] | None:
    effective: dict[tuple[str, ...], tuple[datetime, Mapping[str, Any]]] = {}
    for check in checks:
        if not isinstance(check, Mapping):
            return None
        identity = _github_check_identity(check)
        if identity is None:
            return None
        key, started = identity
        previous = effective.get(key)
        if previous is None or started > previous[0]:
            effective[key] = (started, check)
            continue
        if started == previous[0] and dict(check) != dict(previous[1]):
            return None
    return [effective[key][1] for key in sorted(effective)]


def _github_check_success(check: Mapping[str, Any]) -> bool:
    typename = check.get("__typename")
    if typename == "CheckRun":
        return check.get("status") == "COMPLETED" and check.get("conclusion") == "SUCCESS"
    if typename == "StatusContext":
        return check.get("state") == "SUCCESS"
    return False


def _github_observation(
    evidence: Mapping[str, Any], *, deadline_monotonic: float | None = None
) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    parsed = _github_reference(reference)
    if parsed is None:
        return None
    try:
        returncode, stdout, _stderr = _run_command(
            [
                "gh",
                "pr",
                "view",
                str(parsed["pr"]),
                "--repo",
                str(parsed["repo"]),
                "--json",
                "state,isDraft,baseRefOid,headRefOid,mergeCommit,statusCheckRollup",
            ],
            deadline_monotonic=deadline_monotonic,
        )
    except EvidenceAssessmentError:
        return _trusted_observation(evidence, status="stale")
    if returncode != 0:
        return _trusted_observation(evidence, status="stale")
    try:
        payload = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _trusted_observation(evidence, status="mismatch")
    if not isinstance(payload, Mapping):
        return _trusted_observation(evidence, status="mismatch")
    merge = payload.get("mergeCommit")
    checks = payload.get("statusCheckRollup")
    merge_oid = merge.get("oid") if isinstance(merge, Mapping) else None
    if not isinstance(checks, list):
        return _trusted_observation(evidence, status="mismatch")
    if parsed.get("version", 1) == 2:
        observed_checks = _effective_github_checks(checks)
        if observed_checks is None:
            return _trusted_observation(evidence, status="mismatch")
    else:
        observed_checks = checks
    successful = 0
    for check in observed_checks:
        if not isinstance(check, Mapping):
            return _trusted_observation(evidence, status="mismatch")
        successful += int(_github_check_success(check))
    identity_matches = (
        payload.get("state") == "MERGED"
        and payload.get("isDraft") is False
        and payload.get("headRefOid") == parsed["head"]
        and payload.get("baseRefOid") == parsed["base"]
        and merge_oid == parsed["merge"]
        and len(observed_checks) == parsed["total"]
        and successful == parsed["passed"]
    )
    if not identity_matches:
        return _trusted_observation(evidence, status="mismatch")
    return _trusted_observation(
        evidence,
        status="verified",
        sha256=_sha256(_github_observation_material(parsed)),
    )


def _remote_repo_slug(value: str) -> str | None:
    match = GITHUB_REMOTE_RE.search(value.strip())
    return match.group("repo") if match is not None else None


def _local_git_repo(
    repo_slug: str, *, deadline_monotonic: float | None = None
) -> Path | None:
    repo_name = repo_slug.rsplit("/", 1)[-1]
    candidate = Path.home() / "repos" / repo_name
    if not candidate.is_dir():
        return None
    try:
        returncode, stdout, _stderr = _run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "remote", "get-url", "origin"],
            cwd=candidate,
            deadline_monotonic=deadline_monotonic,
        )
    except EvidenceAssessmentError:
        return None
    if returncode != 0:
        return None
    try:
        remote = stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    observed_slug = _remote_repo_slug(remote)
    if observed_slug is None or observed_slug.casefold() != repo_slug.casefold():
        return None
    return candidate


def _git_observation(
    evidence: Mapping[str, Any], *, deadline_monotonic: float | None = None
) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    match = GIT_COMMIT_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    repo = _local_git_repo(
        match.group("repo"), deadline_monotonic=deadline_monotonic
    )
    if repo is None:
        return _trusted_observation(evidence, status="stale")
    commit = match.group("commit")
    try:
        returncode, stdout, _stderr = _run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "cat-file", "commit", commit],
            cwd=repo,
            deadline_monotonic=deadline_monotonic,
        )
    except EvidenceAssessmentError:
        return _trusted_observation(evidence, status="stale")
    if returncode != 0:
        return _trusted_observation(evidence, status="stale")
    return _trusted_observation(
        evidence, status="verified", sha256=hashlib.sha256(stdout).hexdigest()
    )


def _receipt_root() -> Path:
    configured = os.environ.get("GRABOWSKI_EVIDENCE_RECEIPT_ROOT")
    return Path(configured).expanduser() if configured else Path.home() / ".local/state/grabowski"


def _receipt_observation(
    evidence: Mapping[str, Any], *, deadline_monotonic: float | None = None
) -> dict[str, Any] | None:
    del deadline_monotonic
    reference = _text(evidence.get("reference"), "reference")
    prefix = "grabowski-receipt:"
    if not reference.startswith(prefix):
        return None
    relative = reference[len(prefix) :]
    match = WORKTREE_ENSURE_RECEIPT_PATH_RE.fullmatch(relative)
    if match is None:
        return None
    root = _receipt_root().resolve()
    path = (root / relative).resolve(strict=False)
    if root not in path.parents:
        return None
    try:
        data = _read_regular_bytes(path, maximum=MAX_ADAPTER_FILE_BYTES)
        payload = json.loads(data)
    except (EvidenceAssessmentError, UnicodeDecodeError, json.JSONDecodeError):
        return _trusted_observation(evidence, status="stale")
    if not isinstance(payload, Mapping):
        return _trusted_observation(evidence, status="mismatch")
    error = payload.get("error")
    result_state = payload.get("result_state")
    successful = (
        payload.get("schema_version") == 1
        and payload.get("kind") == "grabowski.worktree_ensure_receipt"
        and payload.get("state") == "complete"
        and (error is None or error == "")
        and isinstance(result_state, str)
        and result_state in WORKTREE_ENSURE_SUCCESS_STATES
        and payload.get("idempotency_key_sha256") == match.group("key")
        and _is_sha256(payload.get("receipt_sha256"))
    )
    if not successful:
        return _trusted_observation(evidence, status="mismatch")
    return _trusted_observation(
        evidence, status="verified", sha256=hashlib.sha256(data).hexdigest()
    )

def _bureau_observation(
    evidence: Mapping[str, Any], *, deadline_monotonic: float | None = None
) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    match = BUREAU_CANDIDATE_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    remaining = ADAPTER_COMMAND_TIMEOUT_SECONDS
    if deadline_monotonic is not None:
        remaining = min(remaining, max(0.0, deadline_monotonic - time.monotonic()))
    if remaining < 1:
        return _trusted_observation(evidence, status="stale")
    try:
        import grabowski_bureau_intake as bureau_intake

        payload = bureau_intake._invoke_bureau(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--idempotency-key",
                match.group("idempotency_key"),
            ],
            timeout_seconds=max(1, int(remaining)),
        )
    except (ImportError, OSError, RuntimeError, ValueError):
        return _trusted_observation(evidence, status="stale")
    if not isinstance(payload, Mapping):
        return _trusted_observation(evidence, status="mismatch")
    if payload.get("kind") == "grabowski_bureau_intake_adapter_failure":
        return _trusted_observation(evidence, status="stale")
    fingerprint = payload.get("content_fingerprint")
    matches = (
        payload.get("status") == "assessed"
        and payload.get("candidate_id") == match.group("candidate_id")
        and payload.get("event_id") == int(match.group("event_id"))
        and _is_sha256(fingerprint)
    )
    if not matches:
        return _trusted_observation(evidence, status="mismatch")
    return _trusted_observation(
        evidence, status="verified", sha256=str(fingerprint)
    )


def _deployment_manifest_path(release_id: str) -> Path:
    configured = os.environ.get("GRABOWSKI_EVIDENCE_DEPLOYMENT_MANIFEST")
    if configured:
        return Path(configured).expanduser()
    root_value = os.environ.get("GRABOWSKI_EVIDENCE_RELEASES_ROOT")
    root = (
        Path(root_value).expanduser()
        if root_value
        else Path.home() / ".local/share/grabowski-mcp-releases"
    ).resolve(strict=False)
    path = (root / release_id / "deployment-manifest.json").resolve(strict=False)
    if root not in path.parents:
        raise EvidenceAssessmentError("runtime release manifest escapes the release root")
    return path


def _runtime_observation(
    evidence: Mapping[str, Any], *, deadline_monotonic: float | None = None
) -> dict[str, Any] | None:
    del deadline_monotonic
    reference = _text(evidence.get("reference"), "reference")
    match = RUNTIME_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    try:
        data = _read_regular_bytes(
            _deployment_manifest_path(match.group("release_id")),
            maximum=MAX_ADAPTER_FILE_BYTES,
        )
        payload = json.loads(data)
    except (EvidenceAssessmentError, UnicodeDecodeError, json.JSONDecodeError):
        return _trusted_observation(evidence, status="stale")
    if not isinstance(payload, Mapping):
        return _trusted_observation(evidence, status="mismatch")
    runtime_input_sha256 = payload.get("runtime_input_sha256")
    matches = (
        payload.get("completion_status") == "complete"
        and payload.get("repo_head") == match.group("repo_head")
        and payload.get("release_id") == match.group("release_id")
        and runtime_input_sha256 == match.group("runtime_input_sha256")
        and _is_sha256(runtime_input_sha256)
    )
    if not matches:
        return _trusted_observation(evidence, status="mismatch")
    return _trusted_observation(
        evidence, status="verified", sha256=str(runtime_input_sha256)
    )


def _task_database_path() -> Path:
    configured = os.environ.get("GRABOWSKI_EVIDENCE_TASK_DATABASE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local/state/grabowski/tasks.sqlite3"


def _task_output_root() -> Path:
    configured = os.environ.get("GRABOWSKI_EVIDENCE_TASK_OUTPUT_ROOT")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local/state/grabowski/task-output"


def _pytest_summary_counts(stream: bytes) -> set[tuple[int, int]]:
    summaries: set[tuple[int, int]] = set()
    for item in TEST_SUMMARY_RE.finditer(stream):
        subtests = 0
        extras = item.group("extras") or b""
        for extra in TEST_SUMMARY_EXTRA_RE.finditer(extras):
            if extra.group("label") == b"subtests passed":
                subtests = int(extra.group("count"))
        summaries.add((int(item.group("passed")), subtests))
    return summaries


def _recognized_test_argv(argv_json: Any) -> bool:
    if not isinstance(argv_json, str):
        return False
    try:
        argv = json.loads(argv_json)
    except json.JSONDecodeError:
        return False
    if not isinstance(argv, list) or not argv or any(
        not isinstance(item, str) or not item for item in argv
    ):
        return False
    executable = Path(argv[0]).name
    rest = argv[1:]
    if executable in {"pytest", "py.test"}:
        return True
    return (
        executable.startswith("python")
        and len(rest) >= 2
        and rest[0] == "-m"
        and rest[1] in {"pytest", "unittest"}
    )


def _read_task_evidence_row(database: Path, task_id: str) -> tuple[Any, ...] | None:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2.0)
    try:
        return connection.execute(
            "SELECT attempt, state, lifecycle_receipt_sha256, argv_json "
            "FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

def _test_observation_digest(
    *,
    task_id: str,
    attempt: int,
    lifecycle_receipt_sha256: str,
    argv_json: str,
    passed: int,
    subtests: int,
    output_sha256s: list[str],
) -> str:
    return _sha256(
        {
            "schema_version": 1,
            "kind": "grabowski.operator_obligation_evidence.test_task_v1",
            "task_id": task_id,
            "attempt": attempt,
            "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
            "argv_sha256": hashlib.sha256(argv_json.encode("utf-8")).hexdigest(),
            "passed": passed,
            "subtests": subtests,
            "output_sha256s": sorted(output_sha256s),
        }
    )


def _test_observation(
    evidence: Mapping[str, Any], *, deadline_monotonic: float | None = None
) -> dict[str, Any] | None:
    del deadline_monotonic
    reference = _text(evidence.get("reference"), "reference")
    match = TEST_TASK_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    database = _task_database_path().resolve(strict=False)
    try:
        before = _read_task_evidence_row(database, match.group("task_id"))
    except sqlite3.Error:
        return _trusted_observation(evidence, status="stale")
    if before is None:
        return _trusted_observation(evidence, status="stale")
    attempt, state, lifecycle_receipt_sha256, argv_json = before
    if (
        not isinstance(attempt, int)
        or attempt < 1
        or state != "completed"
        or not _is_sha256(lifecycle_receipt_sha256)
        or not _recognized_test_argv(argv_json)
    ):
        return _trusted_observation(evidence, status="mismatch")
    output_dir = _task_output_root() / (
        f".grabowski-task-output-{match.group('task_id')}-a{attempt}"
    )
    streams: list[bytes] = []
    output_sha256s: list[str] = []
    for name in ("stdout.log", "stderr.log"):
        try:
            data = _read_regular_bytes(output_dir / name, maximum=MAX_ADAPTER_FILE_BYTES)
        except EvidenceAssessmentError:
            continue
        streams.append(data)
        output_sha256s.append(hashlib.sha256(data).hexdigest())
    if not streams:
        return _trusted_observation(evidence, status="stale")
    summaries: set[tuple[int, int]] = set()
    for stream in streams:
        summaries.update(_pytest_summary_counts(stream))
    summaries.update(
        (int(item.group("passed")), 0)
        for stream in streams
        for item in UNITTEST_SUMMARY_RE.finditer(stream)
    )
    expected = (int(match.group("passed")), int(match.group("subtests")))
    if expected not in summaries:
        return _trusted_observation(evidence, status="mismatch")
    try:
        after = _read_task_evidence_row(database, match.group("task_id"))
    except sqlite3.Error:
        return _trusted_observation(evidence, status="stale")
    if after != before:
        return _trusted_observation(evidence, status="stale")
    observation_sha256 = _test_observation_digest(
        task_id=match.group("task_id"),
        attempt=attempt,
        lifecycle_receipt_sha256=str(lifecycle_receipt_sha256),
        argv_json=str(argv_json),
        passed=expected[0],
        subtests=expected[1],
        output_sha256s=output_sha256s,
    )
    return _trusted_observation(
        evidence, status="verified", sha256=observation_sha256
    )


def _preparation_result(
    *,
    acceptance_id: str,
    source: str,
    status: str,
    reason: str,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": PREPARATION_KIND,
        "acceptance_id": acceptance_id,
        "source": source,
        "status": status,
        "reason": reason,
        "evidence": dict(evidence) if evidence is not None else None,
        "verified_completion_enforcement_enabled": False,
        "does_not_establish": [
            "operator obligation completion",
            "semantic relevance of the source artifact to the acceptance condition",
            "future source truth after preparation",
            "trust in caller-authored observations or digests",
            "trust in generic non-persisted grip receipt strings",
            "permission to enforce verified completion",
            "mutation authority",
        ],
    }
    result["preparation_sha256"] = _sha256(result)
    return result


def _prepared(
    acceptance_id: str, source: str, reference: str, sha256: str
) -> dict[str, Any]:
    evidence_item = {
        "acceptance_id": acceptance_id,
        "status": "passed",
        "source": source,
        "reference": reference,
        "sha256": sha256,
    }
    return _preparation_result(
        acceptance_id=acceptance_id,
        source=source,
        status="prepared",
        reason="authoritative_source_bound",
        evidence=evidence_item,
    )


def _prepare_github(
    acceptance_id: str,
    selectors: Mapping[str, Any],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    if set(selectors) != {"repo", "pr"}:
        raise EvidenceAssessmentError("github preparation requires exactly repo and pr")
    repo = _text(selectors.get("repo"), "repo")
    pr = selectors.get("pr")
    if GITHUB_REPO_SLUG_RE.fullmatch(repo) is None:
        raise EvidenceAssessmentError("repo must be an exact GitHub owner/repository slug")
    if isinstance(pr, bool) or not isinstance(pr, int) or not 1 <= pr <= 9_999_999_999:
        raise EvidenceAssessmentError("pr must be a positive integer")
    try:
        returncode, stdout, _stderr = _run_command(
            [
                "gh",
                "pr",
                "view",
                str(pr),
                "--repo",
                repo,
                "--json",
                "state,isDraft,baseRefOid,headRefOid,mergeCommit,statusCheckRollup",
            ],
            deadline_monotonic=deadline_monotonic,
        )
    except EvidenceAssessmentError:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="github",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    if returncode != 0:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="github",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    try:
        payload = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, Mapping):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="github",
            status="mismatch",
            reason="authoritative_source_malformed",
        )
    merge = payload.get("mergeCommit")
    merge_oid = merge.get("oid") if isinstance(merge, Mapping) else None
    head = payload.get("headRefOid")
    base = payload.get("baseRefOid")
    checks = payload.get("statusCheckRollup")
    if (
        payload.get("state") != "MERGED"
        or payload.get("isDraft") is not False
        or not isinstance(head, str)
        or SHA40_RE.fullmatch(head) is None
        or not isinstance(base, str)
        or SHA40_RE.fullmatch(base) is None
        or not isinstance(merge_oid, str)
        or SHA40_RE.fullmatch(merge_oid) is None
        or not isinstance(checks, list)
        or not 1 <= len(checks) <= 100
    ):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="github",
            status="mismatch",
            reason="github_pr_not_terminal_success",
        )
    effective_checks = _effective_github_checks(checks)
    if effective_checks is None:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="github",
            status="mismatch",
            reason="github_check_shape_invalid",
        )
    successful = sum(int(_github_check_success(check)) for check in effective_checks)
    if successful != len(effective_checks):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="github",
            status="mismatch",
            reason="github_checks_not_all_successful",
        )
    parsed = {
        "repo": repo,
        "pr": pr,
        "head": head,
        "base": base,
        "merge": merge_oid,
        "passed": successful,
        "total": len(effective_checks),
        "version": 2,
    }
    reference = (
        f"github-pr-v2:{repo}#{pr}@{head}:base={base}:merge={merge_oid}:"
        f"checks={successful}/{len(effective_checks)}-effective-success"
    )
    return _prepared(
        acceptance_id,
        "github",
        reference,
        _sha256(_github_observation_material(parsed)),
    )


def _prepare_git(
    acceptance_id: str,
    selectors: Mapping[str, Any],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    if set(selectors) != {"repo", "commit"}:
        raise EvidenceAssessmentError("git preparation requires exactly repo and commit")
    repo_slug = _text(selectors.get("repo"), "repo")
    commit = _text(selectors.get("commit"), "commit")
    if GITHUB_REPO_SLUG_RE.fullmatch(repo_slug) is None:
        raise EvidenceAssessmentError("repo must be an exact GitHub owner/repository slug")
    if SHA40_RE.fullmatch(commit) is None:
        raise EvidenceAssessmentError("commit must be an exact lowercase 40-character SHA")
    repo = _local_git_repo(repo_slug, deadline_monotonic=deadline_monotonic)
    if repo is None:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="git",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    try:
        returncode, stdout, _stderr = _run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "cat-file", "commit", commit],
            cwd=repo,
            deadline_monotonic=deadline_monotonic,
        )
    except EvidenceAssessmentError:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="git",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    if returncode != 0:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="git",
            status="stale",
            reason="git_commit_unavailable",
        )
    return _prepared(
        acceptance_id,
        "git",
        f"git-commit:{repo_slug}@{commit}",
        hashlib.sha256(stdout).hexdigest(),
    )


def _prepare_bureau(
    acceptance_id: str,
    selectors: Mapping[str, Any],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    if set(selectors) != {"idempotency_key"}:
        raise EvidenceAssessmentError(
            "bureau preparation requires exactly idempotency_key"
        )
    idempotency_key = _text(selectors.get("idempotency_key"), "idempotency_key")
    if BUREAU_IDEMPOTENCY_RE.fullmatch(idempotency_key) is None:
        raise EvidenceAssessmentError("idempotency_key has unsupported characters")
    remaining = ADAPTER_COMMAND_TIMEOUT_SECONDS
    if deadline_monotonic is not None:
        remaining = min(remaining, max(0.0, deadline_monotonic - time.monotonic()))
    if remaining < 1:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="bureau",
            status="stale",
            reason="authoritative_source_deadline_exhausted",
        )
    try:
        import grabowski_bureau_intake as bureau_intake

        payload = bureau_intake._invoke_bureau(
            [
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
                "--idempotency-key",
                idempotency_key,
            ],
            timeout_seconds=max(1, int(remaining)),
        )
    except (ImportError, OSError, RuntimeError, ValueError):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="bureau",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    if (
        not isinstance(payload, Mapping)
        or payload.get("kind") == "grabowski_bureau_intake_adapter_failure"
    ):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="bureau",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    candidate_id = payload.get("candidate_id")
    event_id = payload.get("event_id")
    fingerprint = payload.get("content_fingerprint")
    if (
        payload.get("status") != "assessed"
        or not isinstance(candidate_id, str)
        or re.fullmatch(r"candidate-[0-9a-f]{24}", candidate_id) is None
        or isinstance(event_id, bool)
        or not isinstance(event_id, int)
        or event_id < 1
        or not _is_sha256(fingerprint)
    ):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="bureau",
            status="mismatch",
            reason="bureau_candidate_identity_invalid",
        )
    reference = (
        f"bureau-candidate:{candidate_id}:event={event_id}:"
        f"idempotency={idempotency_key}"
    )
    return _prepared(acceptance_id, "bureau", reference, str(fingerprint))


def _prepare_runtime(
    acceptance_id: str,
    selectors: Mapping[str, Any],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    del deadline_monotonic
    if set(selectors) != {"release_id"}:
        raise EvidenceAssessmentError("runtime preparation requires exactly release_id")
    release_id = _text(selectors.get("release_id"), "release_id")
    if RELEASE_ID_RE.fullmatch(release_id) is None:
        raise EvidenceAssessmentError("release_id has invalid format")
    try:
        data = _read_regular_bytes(
            _deployment_manifest_path(release_id),
            maximum=MAX_ADAPTER_FILE_BYTES,
        )
        payload = json.loads(data)
    except (EvidenceAssessmentError, UnicodeDecodeError, json.JSONDecodeError):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="runtime",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    if not isinstance(payload, Mapping):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="runtime",
            status="mismatch",
            reason="runtime_manifest_malformed",
        )
    repo_head = payload.get("repo_head")
    runtime_input = payload.get("runtime_input_sha256")
    if (
        payload.get("completion_status") != "complete"
        or payload.get("release_id") != release_id
        or not isinstance(repo_head, str)
        or SHA40_RE.fullmatch(repo_head) is None
        or not _is_sha256(runtime_input)
    ):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="runtime",
            status="mismatch",
            reason="runtime_manifest_identity_invalid",
        )
    reference = (
        f"grabowski-runtime-manifest:repo_head={repo_head};"
        f"release_id={release_id};runtime_input_sha256={runtime_input}"
    )
    return _prepared(acceptance_id, "runtime", reference, str(runtime_input))


def _prepare_test(
    acceptance_id: str,
    selectors: Mapping[str, Any],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    del deadline_monotonic
    if set(selectors) != {"task_id"}:
        raise EvidenceAssessmentError("test preparation requires exactly task_id")
    task_id = _text(selectors.get("task_id"), "task_id")
    if TASK_ID_RE.fullmatch(task_id) is None:
        raise EvidenceAssessmentError("task_id must be an exact 24-character hex id")
    database = _task_database_path().resolve(strict=False)
    try:
        before = _read_task_evidence_row(database, task_id)
    except sqlite3.Error:
        before = None
    if before is None:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="stale",
            reason="authoritative_source_unavailable",
        )
    attempt, state, lifecycle_receipt_sha256, argv_json = before
    if (
        not isinstance(attempt, int)
        or attempt < 1
        or state != "completed"
        or not _is_sha256(lifecycle_receipt_sha256)
        or not _recognized_test_argv(argv_json)
    ):
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="mismatch",
            reason="test_task_not_terminal_test_execution",
        )
    output_dir = _task_output_root() / f".grabowski-task-output-{task_id}-a{attempt}"
    streams: list[bytes] = []
    output_sha256s: list[str] = []
    for name in ("stdout.log", "stderr.log"):
        try:
            data = _read_regular_bytes(output_dir / name, maximum=MAX_ADAPTER_FILE_BYTES)
        except EvidenceAssessmentError:
            continue
        streams.append(data)
        output_sha256s.append(hashlib.sha256(data).hexdigest())
    if not streams:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="stale",
            reason="test_output_unavailable",
        )
    summaries: set[tuple[int, int]] = set()
    for stream in streams:
        summaries.update(_pytest_summary_counts(stream))
        summaries.update(
            (int(item.group("passed")), 0)
            for item in UNITTEST_SUMMARY_RE.finditer(stream)
        )
    if len(summaries) != 1:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="mismatch",
            reason="test_summary_not_unique_success",
        )
    try:
        after = _read_task_evidence_row(database, task_id)
    except sqlite3.Error:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="stale",
            reason="authoritative_source_changed_or_unavailable",
        )
    if after != before:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="stale",
            reason="authoritative_source_changed_or_unavailable",
        )
    passed, subtests = next(iter(summaries))
    if passed + subtests < 1:
        return _preparation_result(
            acceptance_id=acceptance_id,
            source="test",
            status="mismatch",
            reason="test_summary_no_successful_tests",
        )
    digest = _test_observation_digest(
        task_id=task_id,
        attempt=attempt,
        lifecycle_receipt_sha256=str(lifecycle_receipt_sha256),
        argv_json=str(argv_json),
        passed=passed,
        subtests=subtests,
        output_sha256s=output_sha256s,
    )
    reference = f"grabowski-task:{task_id}:{passed}-passed+{subtests}-subtests"
    return _prepared(acceptance_id, "test", reference, digest)


_PREPARERS = {
    "bureau": _prepare_bureau,
    "github": _prepare_github,
    "git": _prepare_git,
    "runtime": _prepare_runtime,
    "test": _prepare_test,
}


def prepare_evidence(
    acceptance_id: str,
    source: str,
    selectors: Mapping[str, Any],
) -> dict[str, Any]:
    """Prepare close evidence only from a fresh independent authoritative read."""

    acceptance = _text(acceptance_id, "acceptance_id")
    source_name = _text(source, "source")
    if source_name not in PREPARABLE_SOURCES:
        raise EvidenceAssessmentError(
            "source is not preparable; generic receipt strings remain intentionally untrusted"
        )
    if not isinstance(selectors, Mapping):
        raise EvidenceAssessmentError("selectors must be an object")
    deadline = time.monotonic() + MAX_ADAPTER_COLLECTION_SECONDS
    return _PREPARERS[source_name](
        acceptance,
        selectors,
        deadline_monotonic=deadline,
    )


_SOURCE_ADAPTERS = {
    "bureau": _bureau_observation,
    "github": _github_observation,
    "git": _git_observation,
    "receipt": _receipt_observation,
    "runtime": _runtime_observation,
    "test": _test_observation,
}


def collect_trusted_observations(
    status: Mapping[str, Any],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, dict[str, Any]]:
    """Collect only server-owned source observations from strict references.

    Stored close evidence chooses neither adapter output nor adapter status.  A
    free-form or unknown reference simply receives no trusted observation and
    therefore remains unverified.
    """

    if status.get("close_schema_version") == obligations.LEGACY_CLOSE_SCHEMA_VERSION:
        return {}
    evidence_items = status.get("evidence")
    if not isinstance(evidence_items, list):
        return {}
    if deadline_monotonic is None:
        deadline_monotonic = time.monotonic() + MAX_ADAPTER_COLLECTION_SECONDS
    observations: dict[str, dict[str, Any]] = {}
    for item in evidence_items:
        if time.monotonic() >= deadline_monotonic:
            break
        if not isinstance(item, Mapping):
            continue
        source = item.get("source")
        acceptance_id = item.get("acceptance_id")
        if not isinstance(source, str) or not isinstance(acceptance_id, str):
            continue
        adapter = _SOURCE_ADAPTERS.get(source)
        if adapter is None:
            continue
        try:
            observation = adapter(
                item, deadline_monotonic=deadline_monotonic
            )
        except (EvidenceAssessmentError, OSError, ValueError, sqlite3.Error):
            observation = _trusted_observation(item, status="stale")
        if observation is not None:
            observations[acceptance_id] = observation
    return observations



def _root_cause_for_assessment(item: Mapping[str, Any]) -> str:
    classification = str(item.get("classification"))
    reason = str(item.get("reason"))
    source = item.get("source")
    reference = item.get("reference")
    if classification == "verified":
        return "verified"
    if classification == "legacy_unverifiable":
        return "historical_truth_unavailable"
    if classification == "mismatch":
        if reason in {"observation_acceptance_mismatch", "observation_identity_mismatch"}:
            return "identity_mismatch"
        if reason == "stored_evidence_not_passed":
            return "stored_evidence_status_mismatch"
        return "trusted_observation_mismatch"
    if classification == "stale":
        return "source_temporarily_unavailable"
    if classification == "missing":
        return "evidence_at_source_missing"
    if classification == "unsupported":
        if source == "user" or reason == "human_assertion_is_not_machine_verification":
            return "non_machine_verifiable"
        return "trusted_adapter_gap"
    if classification == "unverified":
        if reason == "missing_or_invalid_evidence_digest":
            return "evidence_at_source_digest_unbound"
        if source == "receipt" and isinstance(reference, str) and reference.startswith("grip:"):
            return "evidence_at_source_not_persisted"
        if isinstance(source, str) and source in _SOURCE_ADAPTERS:
            return "evidence_at_source_reference_unbound"
        return "trusted_adapter_gap"
    return "non_machine_verifiable"


def _attach_root_causes(items: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in items:
        root_cause = _root_cause_for_assessment(item)
        item["root_cause"] = root_cause
        counts[root_cause] += 1
    return counts


def _observation_for(
    observations: Mapping[str, Mapping[str, Any]] | None,
    acceptance_id: str,
) -> Mapping[str, Any] | None:
    if observations is None:
        return None
    observation = observations.get(acceptance_id)
    if observation is None:
        return None
    if not isinstance(observation, Mapping):
        raise EvidenceAssessmentError("trusted observation must be a mapping")
    return observation


def _validate_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema_version",
        "kind",
        "acceptance_id",
        "source",
        "reference",
        "sha256",
        "status",
    }
    unknown = set(observation) - allowed
    missing = allowed - set(observation)
    if unknown:
        raise EvidenceAssessmentError(
            f"trusted observation has unsupported fields: {sorted(unknown)}"
        )
    if missing:
        raise EvidenceAssessmentError(
            f"trusted observation is missing fields: {sorted(missing)}"
        )
    if observation.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceAssessmentError("trusted observation schema_version is invalid")
    if observation.get("kind") != OBSERVATION_KIND:
        raise EvidenceAssessmentError("trusted observation kind is invalid")
    status = _text(observation.get("status"), "trusted observation status")
    if status not in OBSERVATION_STATUSES:
        raise EvidenceAssessmentError("trusted observation status is invalid")
    sha256 = observation.get("sha256")
    if not _is_sha256(sha256):
        raise EvidenceAssessmentError("trusted observation sha256 is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": OBSERVATION_KIND,
        "acceptance_id": _text(
            observation.get("acceptance_id"), "trusted observation acceptance_id"
        ),
        "source": _text(observation.get("source"), "trusted observation source"),
        "reference": _text(
            observation.get("reference"), "trusted observation reference"
        ),
        "sha256": sha256,
        "status": status,
    }


def assess_evidence_item(
    evidence: Mapping[str, Any],
    *,
    observation: Mapping[str, Any] | None = None,
    legacy: bool = False,
) -> dict[str, Any]:
    """Classify one stored evidence item without granting completion authority.

    A stored SHA only proves that a string was supplied to the historical close
    contract.  It does not prove the referenced test, commit, PR, runtime, job,
    receipt, workspace, or Bureau state.  ``verified`` therefore requires a
    typed observation produced by a trusted internal adapter.  The public grip
    does not accept caller-authored observations.
    """

    if not isinstance(evidence, Mapping):
        raise EvidenceAssessmentError("evidence item must be a mapping")
    acceptance_id = _text(evidence.get("acceptance_id"), "acceptance_id")
    source = _text(evidence.get("source"), "source")
    reference = _text(evidence.get("reference"), "reference")
    status = _text(evidence.get("status"), "status")
    evidence_sha = evidence.get("sha256")

    base = {
        "acceptance_id": acceptance_id,
        "source": source,
        "reference": reference,
        "evidence_sha256": evidence_sha if isinstance(evidence_sha, str) else None,
    }
    if source not in obligations.EVIDENCE_SOURCES:
        return {
            **base,
            "classification": "unsupported",
            "reason": "unknown_evidence_source",
        }
    if status != "passed":
        return {
            **base,
            "classification": "mismatch",
            "reason": "stored_evidence_not_passed",
        }
    if not _is_sha256(evidence_sha):
        return {
            **base,
            "classification": "legacy_unverifiable" if legacy else "unverified",
            "reason": "missing_or_invalid_evidence_digest",
        }
    if legacy:
        return {
            **base,
            "classification": "legacy_unverifiable",
            "reason": "legacy_close_not_reverified",
        }
    if source == "user":
        return {
            **base,
            "classification": "unsupported",
            "reason": "human_assertion_is_not_machine_verification",
        }
    if observation is None:
        return {
            **base,
            "classification": "legacy_unverifiable" if legacy else "unverified",
            "reason": "source_specific_observation_absent",
        }

    observed = _validate_observation(observation)
    if observed["acceptance_id"] != acceptance_id:
        return {
            **base,
            "classification": "mismatch",
            "reason": "observation_acceptance_mismatch",
        }
    if observed["source"] != source or observed["reference"] != reference:
        return {
            **base,
            "classification": "mismatch",
            "reason": "observation_identity_mismatch",
        }
    if observed["status"] == "unsupported":
        return {
            **base,
            "classification": "unsupported",
            "reason": "source_adapter_unsupported",
        }
    if observed["status"] == "stale":
        return {
            **base,
            "classification": "stale",
            "reason": "trusted_observation_stale",
        }
    if observed["status"] == "mismatch" or observed["sha256"] != evidence_sha:
        return {
            **base,
            "classification": "mismatch",
            "reason": "trusted_observation_digest_mismatch",
        }
    return {
        **base,
        "classification": "verified",
        "reason": "trusted_observation_matches",
    }


def _missing_acceptance(acceptance_id: str) -> dict[str, Any]:
    return {
        "acceptance_id": acceptance_id,
        "source": None,
        "reference": None,
        "evidence_sha256": None,
        "classification": "missing",
        "reason": "acceptance_evidence_missing",
    }


def assess_status(
    status: Mapping[str, Any],
    *,
    observations: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(status, Mapping):
        raise EvidenceAssessmentError("obligation status must be a mapping")
    obligation_id = _text(status.get("obligation_id"), "obligation_id")
    state = _text(status.get("state"), "state")
    open_file_sha256 = status.get("open_file_sha256")
    close_file_sha256 = status.get("close_file_sha256")
    if not _is_sha256(open_file_sha256):
        raise EvidenceAssessmentError("open_file_sha256 must bind the assessed open record")
    if state == "open":
        if close_file_sha256 is not None:
            raise EvidenceAssessmentError("open obligation must not have close_file_sha256")
    elif not _is_sha256(close_file_sha256):
        raise EvidenceAssessmentError("close_file_sha256 must bind the assessed terminal record")
    evidence = status.get("evidence")
    acceptance_ids = status.get("acceptance_ids")
    declared_missing = status.get("missing_acceptance_ids")
    if not isinstance(evidence, list):
        raise EvidenceAssessmentError("obligation evidence must be a list")
    if not isinstance(acceptance_ids, list) or any(
        not isinstance(item, str) or not item for item in acceptance_ids
    ):
        raise EvidenceAssessmentError("acceptance_ids must be a non-empty string list")
    if len(set(acceptance_ids)) != len(acceptance_ids):
        raise EvidenceAssessmentError("acceptance_ids must be unique")
    if not isinstance(declared_missing, list) or any(
        not isinstance(item, str) for item in declared_missing
    ):
        raise EvidenceAssessmentError("missing_acceptance_ids must be a string list")

    evidence_by_id: dict[str, Mapping[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, Mapping):
            raise EvidenceAssessmentError("obligation evidence item must be a mapping")
        acceptance_id = _text(item.get("acceptance_id"), "acceptance_id")
        if acceptance_id not in acceptance_ids:
            raise EvidenceAssessmentError("evidence references unknown acceptance id")
        if acceptance_id in evidence_by_id:
            raise EvidenceAssessmentError("duplicate evidence acceptance id")
        evidence_by_id[acceptance_id] = item

    computed_missing = [
        acceptance_id for acceptance_id in acceptance_ids if acceptance_id not in evidence_by_id
    ]
    if sorted(declared_missing) != sorted(computed_missing):
        raise EvidenceAssessmentError("missing_acceptance_ids disagrees with stored evidence")

    close_schema_version = status.get("close_schema_version")
    legacy = (
        state == "completed"
        and close_schema_version == obligations.LEGACY_CLOSE_SCHEMA_VERSION
    )
    assessed: list[dict[str, Any]] = []
    for acceptance_id in acceptance_ids:
        item = evidence_by_id.get(acceptance_id)
        if item is None:
            assessed.append(_missing_acceptance(acceptance_id))
            continue
        assessed.append(
            assess_evidence_item(
                item,
                observation=_observation_for(observations, acceptance_id),
                legacy=legacy,
            )
        )

    root_cause_counts = _attach_root_causes(assessed)
    counts = Counter(item["classification"] for item in assessed)
    fully_verified = (
        state == "completed"
        and bool(acceptance_ids)
        and len(assessed) == len(acceptance_ids)
        and all(item["classification"] == "verified" for item in assessed)
    )
    declared_hash_bound = (
        state == "completed"
        and bool(acceptance_ids)
        and not computed_missing
        and len(evidence_by_id) == len(acceptance_ids)
        and all(
            item.get("status") == "passed" and _is_sha256(item.get("sha256"))
            for item in evidence_by_id.values()
        )
    )
    false_confidence_risk = declared_hash_bound and not fully_verified
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "obligation_id": obligation_id,
        "obligation_state": state,
        "close_schema_version": close_schema_version,
        "record_binding": {
            "open_file_sha256": open_file_sha256,
            "close_file_sha256": close_file_sha256,
        },
        "acceptance_count": len(acceptance_ids),
        "evidence_count": len(evidence_by_id),
        "missing_acceptance_ids": computed_missing,
        "classifications": {
            name: int(counts.get(name, 0)) for name in CLASSIFICATIONS
        },
        "root_cause_counts": dict(sorted(root_cause_counts.items())),
        "acceptance": assessed,
        "fully_verified": fully_verified,
        "declared_hash_bound_completion": declared_hash_bound,
        "false_confidence_risk": false_confidence_risk,
        "legacy_close": legacy,
        "does_not_establish": [
            "operator obligation completion",
            "historical completion was incorrect",
            "source truth without a trusted source-specific observation",
            "merge readiness",
            "deployment correctness",
            "runtime correctness",
            "semantic relevance of a verified source artifact to an acceptance condition",
            "completion correctness",
            "mutation authority",
        ],
    }
    result["assessment_sha256"] = _sha256(result)
    return result


def assess_obligation(obligation_id: str) -> dict[str, Any]:
    status = obligations.status_obligation(obligation_id)
    observations = collect_trusted_observations(status)
    return assess_status(status, observations=observations)


def _completed_population() -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    """Read a bounded completed-obligation population from the existing truth owner."""

    root = obligations._state_root()
    try:
        obligations._ensure_private_directory(root, create=False)
    except FileNotFoundError:
        return [], [], False

    population: list[dict[str, Any]] = []
    integrity_errors: list[dict[str, str]] = []
    scanned = 0
    scan_truncated = False
    for child in sorted(root.iterdir(), key=lambda item: item.name):
        if child.name == ".lock":
            continue
        if scanned >= obligations.MAX_LIST_SCAN:
            scan_truncated = True
            break
        scanned += 1
        if obligations.OBLIGATION_ID_RE.fullmatch(child.name) is None:
            integrity_errors.append(
                {
                    "obligation_id": "invalid-name",
                    "error": "unexpected_state_root_entry",
                }
            )
            continue
        try:
            status = obligations.status_obligation(child.name)
        except (
            OSError,
            obligations.OperatorObligationError,
            obligations.OperatorObligationInputError,
        ) as exc:
            integrity_errors.append(
                {"obligation_id": child.name, "error": type(exc).__name__}
            )
            continue
        if status.get("state") != "completed":
            continue
        population.append(
            {
                "obligation_id": _text(
                    status.get("obligation_id"), "population obligation_id"
                ),
                "close_schema_version": status.get("close_schema_version"),
            }
        )
    return population, integrity_errors, scan_truncated


def _selection_rank(obligation_id: str) -> str:
    return _sha256(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski.operator_obligation_evidence_sample_selection_v1",
            "obligation_id": obligation_id,
        }
    )


def _rank_population(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            _selection_rank(str(item["obligation_id"])),
            str(item["obligation_id"]),
        ),
    )


def _select_sample_population(
    population: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    """Deterministically preserve current-schema visibility without claiming prevalence."""

    legacy = [
        item
        for item in population
        if item.get("close_schema_version") == obligations.LEGACY_CLOSE_SCHEMA_VERSION
    ]
    current = [
        item
        for item in population
        if item.get("close_schema_version") != obligations.LEGACY_CLOSE_SCHEMA_VERSION
    ]
    if current and legacy:
        current_target = min(len(current), max(1, limit // 2))
    else:
        current_target = min(len(current), limit)

    selected = _rank_population(current)[:current_target]
    remaining = limit - len(selected)
    selected.extend(_rank_population(legacy)[:remaining])
    remaining = limit - len(selected)
    if remaining:
        selected_ids = {str(item["obligation_id"]) for item in selected}
        extras = [
            item
            for item in population
            if str(item["obligation_id"]) not in selected_ids
        ]
        selected.extend(_rank_population(extras)[:remaining])
    return selected[:limit]



def _cohort_summary(
    population: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    assessments: list[dict[str, Any]],
    *,
    legacy: bool,
    integrity_ok: bool,
) -> dict[str, Any]:
    def is_legacy_record(item: Mapping[str, Any]) -> bool:
        return item.get("close_schema_version") == obligations.LEGACY_CLOSE_SCHEMA_VERSION

    population_items = [item for item in population if is_legacy_record(item) is legacy]
    selected_ids = {
        str(item["obligation_id"])
        for item in selected
        if is_legacy_record(item) is legacy
    }
    cohort_assessments = [
        item
        for item in assessments
        if bool(item.get("legacy_close")) is legacy
    ]
    classification_counts: Counter[str] = Counter()
    root_cause_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    for assessment in cohort_assessments:
        for item in assessment["acceptance"]:
            classification_counts[str(item["classification"])] += 1
            root_cause_counts[str(item["root_cause"])] += 1
            source = item.get("source")
            if isinstance(source, str):
                source_counts[source] += 1
    return {
        "population_total": len(population_items),
        "selected_total": len(cohort_assessments),
        "fully_represented": (
            integrity_ok
            and len(population_items) == len(selected_ids)
            and {str(item["obligation_id"]) for item in population_items} == selected_ids
        ),
        "schema_versions": sorted(
            {
                item.get("close_schema_version")
                for item in population_items
                if isinstance(item.get("close_schema_version"), int)
            }
        ),
        "acceptance_total": sum(
            int(item["acceptance_count"]) for item in cohort_assessments
        ),
        "acceptance_classification_counts": {
            name: int(classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "root_cause_counts": dict(sorted(root_cause_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "obligations_fully_verified": sum(
            1 for item in cohort_assessments if item["fully_verified"]
        ),
        "obligations_with_false_confidence_risk": sum(
            1 for item in cohort_assessments if item["false_confidence_risk"]
        ),
    }


def _gap_policy(source: str | None, root_cause: str, reference: str | None) -> dict[str, Any]:
    durable_receipt = (
        source == "receipt"
        and isinstance(reference, str)
        and reference.startswith("grabowski-receipt:grip-receipts/worktree-ensure/")
    )
    independent = source in PREPARABLE_SOURCES or durable_receipt
    adapter_available = isinstance(source, str) and source in _SOURCE_ADAPTERS
    producer_hardening = root_cause.startswith("evidence_at_source_") or root_cause in {
        "identity_mismatch",
        "stored_evidence_status_mismatch",
        "trusted_observation_mismatch",
    }
    if root_cause in {
        "identity_mismatch",
        "stored_evidence_status_mismatch",
        "trusted_observation_mismatch",
    }:
        action = "investigate_producer_evidence_binding; do_not_relax_adapter"
        benefit = "eliminates false source claims without increasing trust permissiveness"
        risk = "historical mismatch may be irreparable"
    elif root_cause == "historical_truth_unavailable":
        action = "retain_legacy_unverifiable"
        benefit = "preserves truthful legacy boundary"
        risk = "legacy verification ratio remains low"
    elif root_cause == "non_machine_verifiable":
        action = "retain_explicit_non_machine_boundary"
        benefit = "avoids automating qualitative acceptance"
        risk = "requires a separate human-policy decision before enforcement"
    elif root_cause == "trusted_adapter_gap":
        action = "add_adapter_only_if_independent_authoritative_source_exists"
        benefit = "could verify existing exact identities without producer changes"
        risk = "new adapter expands trust surface"
    elif root_cause == "evidence_at_source_not_persisted":
        action = "keep_generic_grip_receipt_untrusted; add_concrete_durable_receipt_only_if_recurrent"
        benefit = "avoids inventing evidence after the fact"
        risk = "generic historical grip evidence remains unverified"
    elif root_cause in {
        "evidence_at_source_reference_unbound",
        "evidence_at_source_digest_unbound",
        "evidence_at_source_missing",
    }:
        if source in PREPARABLE_SOURCES:
            action = "use_authoritative_evidence_preparation_at_producer"
            benefit = "future evidence carries canonical identity and independently recomputable digest"
            risk = "producer must choose the semantically correct acceptance/source pairing"
        elif source == "receipt":
            action = "replace_free_form_receipt_with_primary_source_or_concrete_durable_receipt"
            benefit = "avoids granting trust to non-persisted or prose-only receipt claims"
            risk = "historical free-form receipt claims remain unverified"
        else:
            action = "bind_evidence_to_independent_authoritative_source_at_producer"
            benefit = "future evidence can become independently observable without widening trust"
            risk = "no current preparer exists for the selected evidence source"
    elif root_cause == "source_temporarily_unavailable":
        action = "retry_read_only_source_observation_later"
        benefit = "distinguishes transient availability from identity mismatch"
        risk = "verification remains unavailable while source is stale"
    else:
        action = "inspect_case"
        benefit = "keeps classification conservative"
        risk = "unknown gap remains"
    return {
        "independent_primary_source_present": independent,
        "adapter_available": adapter_available,
        "producer_hardening_necessary": producer_hardening,
        "expected_benefit": benefit,
        "risk": risk,
        "recommended_action": action,
    }


def _gap_audit(assessments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, str | None, str, str], dict[str, Any]] = {}
    for assessment in assessments:
        schema = assessment.get("close_schema_version")
        obligation_id = str(assessment["obligation_id"])
        for item in assessment["acceptance"]:
            classification = str(item["classification"])
            if classification == "verified":
                continue
            source = item.get("source") if isinstance(item.get("source"), str) else None
            root_cause = str(item["root_cause"])
            key = (schema, source, root_cause, classification)
            entry = groups.setdefault(
                key,
                {
                    "completion_schema": schema,
                    "source": source,
                    "classification": classification,
                    "root_cause": root_cause,
                    "count": 0,
                    "examples": [],
                },
            )
            entry["count"] += 1
            if len(entry["examples"]) < 3:
                entry["examples"].append(
                    {
                        "obligation_id": obligation_id,
                        "acceptance_id": item.get("acceptance_id"),
                        "reference": item.get("reference"),
                    }
                )
    result: list[dict[str, Any]] = []
    for key in sorted(
        groups,
        key=lambda item: (
            str(item[0]),
            item[1] or "",
            item[2],
            item[3],
        ),
    ):
        entry = groups[key]
        first_reference = (
            entry["examples"][0].get("reference") if entry["examples"] else None
        )
        entry.update(
            _gap_policy(
                entry["source"],
                entry["root_cause"],
                first_reference if isinstance(first_reference, str) else None,
            )
        )
        result.append(entry)
    return result


def sample_completed(limit: int = MIN_ROLLOUT_SAMPLE) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_SAMPLE:
        raise EvidenceAssessmentError(f"limit must be an integer from 1 to {MAX_SAMPLE}")

    population, integrity_errors, scan_truncated = _completed_population()
    selected = _select_sample_population(population, limit)
    obligation_ids = [str(item["obligation_id"]) for item in selected]
    statuses = [obligations.status_obligation(obligation_id) for obligation_id in obligation_ids]
    adapter_deadline = time.monotonic() + MAX_ADAPTER_COLLECTION_SECONDS
    observation_maps = [
        collect_trusted_observations(status, deadline_monotonic=adapter_deadline)
        for status in statuses
    ]
    assessments = [
        assess_status(status, observations=observations)
        for status, observations in zip(statuses, observation_maps, strict=True)
    ]

    acceptance_total = sum(item["acceptance_count"] for item in assessments)
    classification_counts: Counter[str] = Counter()
    obligation_classification_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    missing_adapter_source_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    root_cause_counts: Counter[str] = Counter()
    adapter_observation_counts: Counter[str] = Counter()
    adapter_status_counts: Counter[str] = Counter()
    for observations in observation_maps:
        for observation in observations.values():
            adapter_observation_counts[str(observation["source"])] += 1
            adapter_status_counts[
                f"{observation['source']}:{observation['status']}"
            ] += 1
    for assessment in assessments:
        seen_classes: set[str] = set()
        for item in assessment["acceptance"]:
            classification = item["classification"]
            classification_counts[classification] += 1
            seen_classes.add(classification)
            source = item.get("source")
            if isinstance(source, str):
                source_counts[source] += 1
                if (
                    classification in {"unverified", "legacy_unverifiable"}
                    and item["reason"] == "source_specific_observation_absent"
                ):
                    missing_adapter_source_counts[source] += 1
            reason_counts[item["reason"]] += 1
            root_cause_counts[str(item["root_cause"])] += 1
        for classification in seen_classes:
            obligation_classification_counts[classification] += 1

    fully_verified = sum(1 for item in assessments if item["fully_verified"])
    false_confidence_risk = sum(
        1 for item in assessments if item["false_confidence_risk"]
    )
    acceptance_verified = int(classification_counts.get("verified", 0))
    if integrity_errors or scan_truncated:
        signal = "inconclusive_population_integrity"
    elif len(assessments) < MIN_ROLLOUT_SAMPLE:
        signal = "inconclusive_sample_too_small"
    elif fully_verified == len(assessments):
        signal = "fully_verifiable_sample"
    else:
        signal = "verifiability_gap_observed"

    rollout_threshold = {
        "schema_version": 1,
        "kind": ROLLOUT_THRESHOLD_KIND,
        "minimum_sample": MIN_ROLLOUT_SAMPLE,
        "requires_population_integrity": True,
        "requires_all_acceptance_verified": True,
        "requires_all_obligations_fully_verified": True,
        "requires_zero_false_confidence_risk": True,
        "verification_scope": "source_observation_identity_only",
        "semantic_acceptance_relevance_established": False,
        "adapter_collection_budget_seconds": MAX_ADAPTER_COLLECTION_SECONDS,
        "enforcement_change_separate": True,
    }
    rollout_eligible = (
        not integrity_errors
        and not scan_truncated
        and len(assessments) >= MIN_ROLLOUT_SAMPLE
        and acceptance_total > 0
        and acceptance_verified == acceptance_total
        and fully_verified == len(assessments)
        and false_confidence_risk == 0
    )
    if integrity_errors or scan_truncated:
        rollout_decision = "stop_population_integrity"
    elif len(assessments) < MIN_ROLLOUT_SAMPLE:
        rollout_decision = "stop_sample_too_small"
    elif rollout_eligible:
        rollout_decision = (
            "source_verifiability_threshold_met_separate_enforcement_review_required"
        )
    else:
        rollout_decision = "stop_verifiability_threshold_not_met"

    population_schema_counts = Counter(
        str(item.get("close_schema_version")) for item in population
    )
    sample_schema_counts = Counter(
        str(item.get("close_schema_version")) for item in selected
    )
    population_binding = sorted(
        (
            {
                "obligation_id": str(item["obligation_id"]),
                "close_schema_version": item.get("close_schema_version"),
            }
            for item in population
        ),
        key=lambda item: item["obligation_id"],
    )
    summary = {
        "total": len(assessments),
        **{
            name: int(classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "acceptance_total": acceptance_total,
        "acceptance_verified": acceptance_verified,
        "obligations_fully_verified": fully_verified,
        "obligations_with_false_confidence_risk": false_confidence_risk,
    }
    integrity_ok = not integrity_errors and not scan_truncated
    legacy_cohort = _cohort_summary(
        population, selected, assessments, legacy=True, integrity_ok=integrity_ok
    )
    modern_cohort = _cohort_summary(
        population, selected, assessments, legacy=False, integrity_ok=integrity_ok
    )
    gap_audit = _gap_audit(assessments)
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": SAMPLE_KIND,
        "requested_limit": limit,
        "sample_size": len(assessments),
        "minimum_sample": MIN_ROLLOUT_SAMPLE,
        "maximum_sample": MAX_SAMPLE,
        "population_completed_total": len(population),
        "population_close_schema_counts": dict(sorted(population_schema_counts.items())),
        "sample_close_schema_counts": dict(sorted(sample_schema_counts.items())),
        "selection_order": "schema_stratified_sha256_rank_v1",
        "selection_obligation_ids": obligation_ids,
        "selection_sha256": _sha256(obligation_ids),
        "selection_population_sha256": _sha256(population_binding),
        "selection_scan_truncated": scan_truncated,
        "selection_integrity_errors": integrity_errors,
        "summary": summary,
        "acceptance_classification_counts": {
            name: int(classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "obligation_classification_counts": {
            name: int(obligation_classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "source_counts": dict(sorted(source_counts.items())),
        "missing_adapter_source_counts": dict(
            sorted(missing_adapter_source_counts.items())
        ),
        "reason_counts": dict(sorted(reason_counts.items())),
        "root_cause_counts": dict(sorted(root_cause_counts.items())),
        "legacy_cohort": legacy_cohort,
        "modern_cohort": modern_cohort,
        "gap_audit": gap_audit,
        "trusted_observation_adapter_sources": list(
            TRUSTED_OBSERVATION_ADAPTER_SOURCES
        ),
        "trusted_observation_counts": dict(sorted(adapter_observation_counts.items())),
        "trusted_observation_status_counts": dict(sorted(adapter_status_counts.items())),
        "rollout_threshold": rollout_threshold,
        "rollout_eligible": rollout_eligible,
        "rollout_decision": rollout_decision,
        "verified_completion_enforcement_enabled": False,
        "shadow_signal": signal,
        "records": [
            {
                "obligation_id": item["obligation_id"],
                "record_binding": item["record_binding"],
                "acceptance_count": item["acceptance_count"],
                "classifications": item["classifications"],
                "fully_verified": item["fully_verified"],
                "declared_hash_bound_completion": item[
                    "declared_hash_bound_completion"
                ],
                "false_confidence_risk": item["false_confidence_risk"],
                "legacy_close": item["legacy_close"],
                "assessment_sha256": item["assessment_sha256"],
            }
            for item in assessments
        ],
        "does_not_establish": [
            "historical completion was incorrect",
            "a false DONE occurred",
            "sample proportions estimate population prevalence",
            "causality",
            "permission to enforce verified completion",
            "verified completion enforcement in this change",
            "future source truth after the adapter observation",
            "semantic relevance of a verified source artifact to an acceptance condition",
            "completion correctness",
            "permission to rewrite legacy obligation records",
            "mutation authority",
        ],
    }
    result["sample_sha256"] = _sha256(result)
    return result

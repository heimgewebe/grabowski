from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
from typing import Any, Mapping

import grabowski_operator_obligation as obligations

SCHEMA_VERSION = 1
KIND = "grabowski.operator_obligation_evidence_assessment"
SAMPLE_KIND = "grabowski.operator_obligation_evidence_sample"
OBSERVATION_KIND = "grabowski.operator_obligation_evidence_observation"
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
GITHUB_PR_REFERENCE_RE = re.compile(
    r"^github-pr:(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"#(?P<pr>[1-9][0-9]{0,9})@(?P<head>[0-9a-f]{40})"
    r":base=(?P<base>[0-9a-f]{40})"
    r":merge=(?P<merge>[0-9a-f]{40})"
    r":checks=(?P<passed>[0-9]{1,3})/(?P<total>[0-9]{1,3})-success$"
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
TEST_TASK_REFERENCE_RE = re.compile(
    r"^grabowski-task:(?P<task_id>[0-9a-f]{24}):"
    r"(?P<passed>[0-9]{1,6})-passed\+(?P<subtests>[0-9]{1,6})-subtests$"
)
TEST_SUMMARY_RE = re.compile(
    rb"(?m)(?P<passed>[0-9]{1,6}) passed"
    rb"(?:, (?P<subtests>[0-9]{1,6}) subtests passed)?(?: in [^\n]+)?$"
)
UNITTEST_SUMMARY_RE = re.compile(
    rb"(?m)^Ran (?P<passed>[0-9]{1,6}) tests in [^\n]+\n\nOK(?:\n|$)"
)
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
    argv: list[str], *, cwd: Path | None = None
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
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=ADAPTER_COMMAND_TIMEOUT_SECONDS,
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
    }
    if parsed["total"] < 1 or parsed["total"] > 100 or parsed["passed"] != parsed["total"]:
        return None
    return parsed


def _github_observation_material(parsed: Mapping[str, Any]) -> dict[str, Any]:
    return {
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


def _github_observation(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
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
            ]
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
    successful = 0
    for check in checks:
        if not isinstance(check, Mapping):
            return _trusted_observation(evidence, status="mismatch")
        typename = check.get("__typename")
        if typename == "CheckRun":
            ok = check.get("status") == "COMPLETED" and check.get("conclusion") == "SUCCESS"
        elif typename == "StatusContext":
            ok = check.get("state") == "SUCCESS"
        else:
            ok = False
        successful += int(ok)
    identity_matches = (
        payload.get("state") == "MERGED"
        and payload.get("isDraft") is False
        and payload.get("headRefOid") == parsed["head"]
        and payload.get("baseRefOid") == parsed["base"]
        and merge_oid == parsed["merge"]
        and len(checks) == parsed["total"]
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


def _local_git_repo(repo_slug: str) -> Path | None:
    repo_name = repo_slug.rsplit("/", 1)[-1]
    candidate = Path.home() / "repos" / repo_name
    if not candidate.is_dir():
        return None
    try:
        returncode, stdout, _stderr = _run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "remote", "get-url", "origin"],
            cwd=candidate,
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


def _git_observation(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    match = GIT_COMMIT_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    repo = _local_git_repo(match.group("repo"))
    if repo is None:
        return _trusted_observation(evidence, status="stale")
    commit = match.group("commit")
    try:
        returncode, stdout, _stderr = _run_command(
            ["git", "-c", "core.hooksPath=/dev/null", "cat-file", "commit", commit],
            cwd=repo,
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


def _receipt_payload_succeeded(relative: str, payload: Mapping[str, Any]) -> bool | None:
    if relative.startswith("grip-receipts/"):
        return (
            payload.get("schema_version") == 1
            and isinstance(payload.get("kind"), str)
            and str(payload.get("kind")).startswith("grabowski.")
            and payload.get("state") == "complete"
            and payload.get("error") in {None, ""}
            and _is_sha256(payload.get("receipt_sha256"))
        )
    if relative.startswith("jobs/") and relative.endswith("/finalization.json"):
        return (
            payload.get("schema_version") == 1
            and payload.get("kind") == "grabowski_job_finalization"
            and payload.get("completion_status") == "complete"
            and payload.get("final_status") == "succeeded"
            and _is_sha256(payload.get("payload_sha256"))
            and _is_sha256(payload.get("contract_sha256"))
        )
    return None


def _receipt_observation(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    prefix = "grabowski-receipt:"
    if not reference.startswith(prefix):
        return None
    relative = reference[len(prefix) :]
    if (
        not relative
        or len(relative) > 1024
        or relative.startswith("/")
        or re.fullmatch(r"[A-Za-z0-9_.@/+:-]+", relative) is None
        or any(part in {"", ".", ".."} for part in Path(relative).parts)
    ):
        return None
    root = _receipt_root().resolve()
    path = (root / relative).resolve(strict=False)
    if path != root and root not in path.parents:
        return None
    try:
        data = _read_regular_bytes(path, maximum=MAX_ADAPTER_FILE_BYTES)
        payload = json.loads(data)
    except (EvidenceAssessmentError, UnicodeDecodeError, json.JSONDecodeError):
        return _trusted_observation(evidence, status="stale")
    if not isinstance(payload, Mapping):
        return _trusted_observation(evidence, status="unsupported")
    succeeded = _receipt_payload_succeeded(relative, payload)
    if succeeded is None:
        return _trusted_observation(evidence, status="unsupported")
    if not succeeded:
        return _trusted_observation(evidence, status="mismatch")
    return _trusted_observation(
        evidence, status="verified", sha256=hashlib.sha256(data).hexdigest()
    )


def _deployment_manifest_path() -> Path:
    configured = os.environ.get("GRABOWSKI_EVIDENCE_DEPLOYMENT_MANIFEST")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local/share/grabowski-mcp/deployment-manifest.json"


def _runtime_observation(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    match = RUNTIME_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    try:
        data = _read_regular_bytes(
            _deployment_manifest_path(), maximum=MAX_ADAPTER_FILE_BYTES
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


def _recognized_test_argv(argv_json: Any) -> bool:
    if not isinstance(argv_json, str):
        return False
    try:
        argv = json.loads(argv_json)
    except json.JSONDecodeError:
        return False
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
        return False
    command = Path(argv[0]).name
    rest = argv[1:]
    if command == "env":
        while rest and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", rest[0]):
            rest = rest[1:]
        if not rest:
            return False
        command = Path(rest[0]).name
        rest = rest[1:]
    if command in {"pytest", "py.test"}:
        return True
    if command.startswith("python") and len(rest) >= 2 and rest[0] == "-m" and rest[1] in {"pytest", "unittest"}:
        return True
    if command == "cargo" and rest and rest[0] == "test":
        return True
    if command in {"npm", "pnpm", "yarn"} and rest and (rest[0] == "test" or rest[0].startswith("test:")):
        return True
    return command in {"make", "just"} and bool(rest) and rest[0] in {"test", "tests", "check", "validate"}


def _test_observation(evidence: Mapping[str, Any]) -> dict[str, Any] | None:
    reference = _text(evidence.get("reference"), "reference")
    match = TEST_TASK_REFERENCE_RE.fullmatch(reference)
    if match is None:
        return None
    database = _task_database_path().resolve(strict=False)
    try:
        connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2.0)
        try:
            row = connection.execute(
                "SELECT attempt, state, lifecycle_receipt_sha256, argv_json FROM tasks WHERE task_id = ?",
                (match.group("task_id"),),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return _trusted_observation(evidence, status="stale")
    if row is None:
        return _trusted_observation(evidence, status="stale")
    attempt, state, lifecycle_receipt_sha256, argv_json = row
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
    for name in ("stdout.log", "stderr.log"):
        try:
            streams.append(
                _read_regular_bytes(output_dir / name, maximum=MAX_ADAPTER_FILE_BYTES)
            )
        except EvidenceAssessmentError:
            continue
    if not streams:
        return _trusted_observation(evidence, status="stale")
    summaries = {
        (
            int(item.group("passed")),
            int(item.group("subtests") or b"0"),
        )
        for stream in streams
        for item in TEST_SUMMARY_RE.finditer(stream)
    }
    summaries.update(
        (int(item.group("passed")), 0)
        for stream in streams
        for item in UNITTEST_SUMMARY_RE.finditer(stream)
    )
    expected = (int(match.group("passed")), int(match.group("subtests")))
    if expected not in summaries:
        return _trusted_observation(evidence, status="mismatch")
    return _trusted_observation(
        evidence, status="verified", sha256=str(lifecycle_receipt_sha256)
    )


_SOURCE_ADAPTERS = {
    "github": _github_observation,
    "git": _git_observation,
    "receipt": _receipt_observation,
    "runtime": _runtime_observation,
    "test": _test_observation,
}


def collect_trusted_observations(
    status: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Collect only server-owned source observations from strict references.

    Stored close evidence chooses neither adapter output nor adapter status.  A
    free-form or unknown reference simply receives no trusted observation and
    therefore remains unverified.
    """

    evidence_items = status.get("evidence")
    if not isinstance(evidence_items, list):
        return {}
    observations: dict[str, dict[str, Any]] = {}
    for item in evidence_items:
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
            observation = adapter(item)
        except (EvidenceAssessmentError, OSError, ValueError, sqlite3.Error):
            observation = _trusted_observation(item, status="stale")
        if observation is not None:
            observations[acceptance_id] = observation
    return observations


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


def sample_completed(limit: int = MIN_ROLLOUT_SAMPLE) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_SAMPLE:
        raise EvidenceAssessmentError(f"limit must be an integer from 1 to {MAX_SAMPLE}")

    population, integrity_errors, scan_truncated = _completed_population()
    selected = _select_sample_population(population, limit)
    obligation_ids = [str(item["obligation_id"]) for item in selected]
    statuses = [obligations.status_obligation(obligation_id) for obligation_id in obligation_ids]
    observation_maps = [collect_trusted_observations(status) for status in statuses]
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
        rollout_decision = "eligible_for_separate_enforcement_change"
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
            "permission to rewrite legacy obligation records",
            "mutation authority",
        ],
    }
    result["sample_sha256"] = _sha256(result)
    return result

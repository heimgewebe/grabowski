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
COMMON_ASSESSMENT_KEYS = frozenset(
    {
        "assessment_id",
        "blocked_by",
        "conflicts",
        "missing_evidence",
        "profile_sha256",
        "schema_version",
        "status",
    }
)
EXPECTED_ASSESSMENT_KEYS_BY_VERSION = {
    1: COMMON_ASSESSMENT_KEYS | {"risk_level"},
    2: COMMON_ASSESSMENT_KEYS
    | {"change_risk", "target_criticality", "profile_id", "profile_cell_id"},
}
ASSESSMENT_STRING_FIELDS_BY_VERSION = {
    1: ("risk_level",),
    2: ("change_risk", "target_criticality", "profile_id", "profile_cell_id"),
}
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
    if not isinstance(value, dict):
        raise ConvergenceExecutionError("convergence evaluator returned an unexpected assessment shape")
    schema_version = value.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in EXPECTED_ASSESSMENT_KEYS_BY_VERSION
    ):
        raise ConvergenceExecutionError("convergence evaluator schema version is unsupported")
    if set(value) != EXPECTED_ASSESSMENT_KEYS_BY_VERSION[schema_version]:
        raise ConvergenceExecutionError("convergence evaluator returned an unexpected assessment shape")
    status_value = value.get("status")
    if not isinstance(status_value, str) or status_value not in ALLOWED_STATUSES:
        raise ConvergenceExecutionError("convergence evaluator returned an unsupported status")
    if STATUS_EXIT_CODES[status_value] != returncode:
        raise ConvergenceExecutionError("convergence evaluator status and exit code disagree")
    for field in ("blocked_by", "conflicts", "missing_evidence"):
        items = value.get(field)
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise ConvergenceExecutionError(f"convergence evaluator field {field} is invalid")
    for field in (
        "assessment_id",
        "profile_sha256",
        *ASSESSMENT_STRING_FIELDS_BY_VERSION[schema_version],
    ):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ConvergenceExecutionError(f"convergence evaluator field {field} is invalid")
    if SHA256_RE.fullmatch(value["profile_sha256"]) is None:
        raise ConvergenceExecutionError("convergence evaluator field profile_sha256 is invalid")
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


ALLOWED_CHANGE_CLASSES = frozenset(
    {
        "documentation",
        "contract",
        "application",
        "runtime",
        "infrastructure",
        "security",
        "data",
        "lifecycle",
        "product_outcome",
    }
)
ALLOWED_SOURCE_STATES = frozenset({"current", "stale", "unknown"})
ALLOWED_EVIDENCE_AUTHORITIES = frozenset({"supplied", "authoritative_receipts"})
ALLOWED_EFFECT_KINDS = frozenset(
    {"commit", "pull_request", "merge", "artifact", "deployment", "configuration_change"}
)
ALLOWED_VERIFICATION_KINDS = frozenset(
    {
        "deterministic_regeneration",
        "tests",
        "review",
        "independent_review",
        "ci",
        "deployment_identity",
        "runtime_identity",
        "service_health",
        "smoke_test",
        "negative_control",
        "consumer_compatibility",
        "recovery",
        "product_outcome",
    }
)
ISO_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _validate_iso_datetime(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or ISO_DATETIME_RE.fullmatch(value) is None:
        raise ConvergenceInputError(f"{label} must be an explicit valid ISO 8601 date-time string")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConvergenceInputError(f"{label} must be a non-empty string")
    return value.strip()


PR_CLOSURE_PROFILE_ID = "pr-closure-v1"
PR_CLOSURE_EVIDENCE_CATEGORIES = ("pr_merge", "deployment_live", "obligation", "checkout")


def _sha256_canonical(val: Any) -> str:
    encoded = json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_pr_closure_profile(
    evidence: dict[str, Any] | None = None,
    *,
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> dict[str, Any]:
    """
    Builds a PR closure evidence profile binding PR/merge, deployment/live,
    obligation, and checkout evidence categories.

    Trust boundary & provenance non-claim:
    - Default `evidence_authority` is 'supplied'. Caller-supplied evidence cannot,
      by itself, yield `source_state=current` or terminal closure.
    - Setting `evidence_authority='authoritative_receipts'` preserves the caller-provided
      authority designation and requires an explicit `source_state` ('current', 'stale', or 'unknown').
      The builder only preserves this caller-provided designation and does NOT cryptographically verify provenance.
    - Category status dictionaries (e.g. pr_merge.status='merged', deployment_live.status='live')
      are descriptive supplied coverage only and MUST NEVER synthesize effect or verification receipts.
      Only protocol-compatible raw effects, verifications, and closure participate in evaluator evidence.
    """
    if evidence is None:
        evidence = {}
    if not isinstance(evidence, dict):
        raise ConvergenceInputError("evidence must be a dictionary")

    authority = evidence.get("evidence_authority") or evidence_authority
    if authority not in ALLOWED_EVIDENCE_AUTHORITIES:
        raise ConvergenceInputError(
            f"evidence_authority must be 'supplied' or 'authoritative_receipts', got '{authority}'"
        )

    profile_categories: dict[str, dict[str, Any]] = {}
    blocked_by: list[str] = []
    conflicts: list[str] = []
    missing_evidence: list[str] = []
    claims: list[str] = []
    source_refs: list[dict[str, str]] = []
    effects: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []

    raw_effects = evidence.get("effects")
    if isinstance(raw_effects, list):
        for idx, item in enumerate(raw_effects):
            if not isinstance(item, dict):
                raise ConvergenceInputError(f"effects[{idx}] must be a dictionary")
            if item.get("schema_version") != 1:
                raise ConvergenceInputError(f"effects[{idx}].schema_version must be 1")
            kind = _text(item.get("kind"), f"effects[{idx}].kind")
            if kind not in ALLOWED_EFFECT_KINDS:
                raise ConvergenceInputError(f"effects[{idx}].kind '{kind}' is not a valid v1 effect kind")
            ref = _text(item.get("evidence_ref"), f"effects[{idx}].evidence_ref")
            subj_sha = _validate_sha256(item.get("subject_sha256"), label=f"effects[{idx}].subject_sha256")
            effects.append({
                "schema_version": 1,
                "kind": kind,
                "evidence_ref": ref,
                "subject_sha256": subj_sha,
            })
            source_refs.append({"kind": f"effect:{kind}", "ref": ref, "subject_sha256": subj_sha})

    raw_verifications = evidence.get("verifications")
    if isinstance(raw_verifications, list):
        for idx, item in enumerate(raw_verifications):
            if not isinstance(item, dict):
                raise ConvergenceInputError(f"verifications[{idx}] must be a dictionary")
            if item.get("schema_version") != 1:
                raise ConvergenceInputError(f"verifications[{idx}].schema_version must be 1")
            kind = _text(item.get("kind"), f"verifications[{idx}].kind")
            if kind not in ALLOWED_VERIFICATION_KINDS:
                raise ConvergenceInputError(f"verifications[{idx}].kind '{kind}' is not a valid v1 verification kind")
            ref = _text(item.get("evidence_ref"), f"verifications[{idx}].evidence_ref")
            subj_sha = _validate_sha256(item.get("subject_sha256"), label=f"verifications[{idx}].subject_sha256")
            result = _text(item.get("result"), f"verifications[{idx}].result")
            if result not in ("pass", "fail", "unknown"):
                raise ConvergenceInputError(f"verifications[{idx}].result must be pass, fail, or unknown")
            verifications.append({
                "schema_version": 1,
                "kind": kind,
                "result": result,
                "evidence_ref": ref,
                "subject_sha256": subj_sha,
            })
            source_refs.append({"kind": f"verification:{kind}", "ref": ref, "subject_sha256": subj_sha})

    raw_source_refs = evidence.get("source_refs")
    if isinstance(raw_source_refs, list):
        for idx, item in enumerate(raw_source_refs):
            if isinstance(item, dict):
                k = _text(item.get("kind"), f"source_refs[{idx}].kind")
                r = _text(item.get("ref"), f"source_refs[{idx}].ref")
                s = _validate_sha256(item.get("subject_sha256"), label=f"source_refs[{idx}].subject_sha256")
                source_refs.append({"kind": k, "ref": r, "subject_sha256": s})

    raw_closure = evidence.get("closure") if isinstance(evidence, dict) else None
    if raw_closure is not None:
        if not isinstance(raw_closure, dict):
            raise ConvergenceInputError("closure must be a dictionary")
        if raw_closure.get("schema_version") != 1:
            raise ConvergenceInputError("closure.schema_version must be 1")

    merge_effect = next((e for e in effects if e["kind"] == "merge"), None)
    deploy_effect = next((e for e in effects if e["kind"] == "deployment"), None)
    has_deploy_identity_pass = any(v["kind"] == "deployment_identity" and v["result"] == "pass" for v in verifications)

    has_obligation_ref = isinstance(raw_closure, dict) and bool(raw_closure.get("bureau_task_ref"))
    has_checkout_cleanup = (
        isinstance(raw_closure, dict)
        and isinstance(raw_closure.get("cleanup_evidence"), list)
        and len(raw_closure.get("cleanup_evidence")) > 0
    )

    # Category 1: pr_merge
    pr_data = evidence.get("pr_merge")
    if isinstance(pr_data, dict):
        status = pr_data.get("status", "unknown")
        ref = pr_data.get("evidence_ref") or f"github-pr:{pr_data.get('repository', 'repo')}#{pr_data.get('pr_number', 0)}"
        subj_sha = pr_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="pr_merge.subject_sha256")
            source_refs.append({"kind": "git_commit", "ref": ref, "subject_sha256": subj_sha})

        if status == "conflicted":
            conflicts.append(f"pr_merge:{ref}")
            blocked_by.append("conflicting_evidence:pr_merge")
            profile_categories["pr_merge"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:pr_merge")
            profile_categories["pr_merge"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif merge_effect:
            claims.append(f"Supplied PR merge evidence: {merge_effect['evidence_ref']}")
            profile_categories["pr_merge"] = {
                "status": "supplied" if status in ("merged", "pass") else status,
                "ref": merge_effect["evidence_ref"],
                "subject_sha256": merge_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("pr_merge")
            blocked_by.append("evidence_missing:pr_merge")
            profile_categories["pr_merge"] = {
                "status": status if status not in ("merged", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if merge_effect:
            claims.append(f"Supplied PR merge evidence: {merge_effect['evidence_ref']}")
            profile_categories["pr_merge"] = {
                "status": "supplied",
                "ref": merge_effect["evidence_ref"],
                "subject_sha256": merge_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("pr_merge")
            blocked_by.append("evidence_missing:pr_merge")
            profile_categories["pr_merge"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    # Category 2: deployment_live
    deploy_data = evidence.get("deployment_live")
    if isinstance(deploy_data, dict):
        status = deploy_data.get("status", "unknown")
        ref = deploy_data.get("evidence_ref") or f"grabowski-release:{deploy_data.get('release_id', 'unknown')}"
        subj_sha = deploy_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="deployment_live.subject_sha256")
            source_refs.append({"kind": "artifact", "ref": ref, "subject_sha256": subj_sha})

        if status == "conflicted":
            conflicts.append(f"deployment_live:{ref}")
            blocked_by.append("conflicting_evidence:deployment_live")
            profile_categories["deployment_live"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:deployment_live")
            profile_categories["deployment_live"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif deploy_effect and has_deploy_identity_pass:
            claims.append(f"Supplied deployment evidence: {deploy_effect['evidence_ref']}")
            profile_categories["deployment_live"] = {
                "status": "supplied" if status in ("live", "pass") else status,
                "ref": deploy_effect["evidence_ref"],
                "subject_sha256": deploy_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("deployment_live")
            blocked_by.append("evidence_missing:deployment_live")
            profile_categories["deployment_live"] = {
                "status": status if status not in ("live", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if deploy_effect and has_deploy_identity_pass:
            claims.append(f"Supplied deployment evidence: {deploy_effect['evidence_ref']}")
            profile_categories["deployment_live"] = {
                "status": "supplied",
                "ref": deploy_effect["evidence_ref"],
                "subject_sha256": deploy_effect["subject_sha256"],
            }
        else:
            missing_evidence.append("deployment_live")
            blocked_by.append("evidence_missing:deployment_live")
            profile_categories["deployment_live"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    # Category 3: obligation
    ob_data = evidence.get("obligation")
    if isinstance(ob_data, dict):
        status = ob_data.get("status", "unknown")
        ref = ob_data.get("evidence_ref") or ob_data.get("bureau_task_ref") or f"obligation:{ob_data.get('obligation_id', 'unknown')}"
        subj_sha = ob_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="obligation.subject_sha256")
            source_refs.append({"kind": "obligation", "ref": ref, "subject_sha256": subj_sha})

        if status == "conflicted":
            conflicts.append(f"obligation:{ref}")
            blocked_by.append("conflicting_evidence:obligation")
            profile_categories["obligation"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:obligation")
            profile_categories["obligation"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif has_obligation_ref:
            ob_ref = raw_closure["bureau_task_ref"]
            claims.append(f"Supplied obligation evidence: {ob_ref}")
            profile_categories["obligation"] = {
                "status": "supplied" if status in ("completed", "closed", "pass") else status,
                "ref": ob_ref,
                "subject_sha256": subj_sha or "",
            }
        else:
            missing_evidence.append("obligation")
            blocked_by.append("evidence_missing:obligation")
            profile_categories["obligation"] = {
                "status": status if status not in ("completed", "closed", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if has_obligation_ref:
            ob_ref = raw_closure["bureau_task_ref"]
            claims.append(f"Supplied obligation evidence: {ob_ref}")
            profile_categories["obligation"] = {"status": "supplied", "ref": ob_ref, "subject_sha256": ""}
        else:
            missing_evidence.append("obligation")
            blocked_by.append("evidence_missing:obligation")
            profile_categories["obligation"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    # Category 4: checkout
    chk_data = evidence.get("checkout")
    if isinstance(chk_data, dict):
        status = chk_data.get("status", "unknown")
        ref = chk_data.get("evidence_ref") or f"grabowski:checkout:{chk_data.get('checkout_key', 'unknown')}"
        subj_sha = chk_data.get("subject_sha256")
        if subj_sha is not None:
            _validate_sha256(subj_sha, label="checkout.subject_sha256")
            source_refs.append({"kind": "checkout", "ref": ref, "subject_sha256": subj_sha})

        if chk_data.get("dirty") or status == "dirty":
            conflicts.append(f"checkout_dirty:{ref}")
            blocked_by.append("checkout_dirty")
            profile_categories["checkout"] = {"status": "dirty", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "conflicted":
            conflicts.append(f"checkout:{ref}")
            blocked_by.append("conflicting_evidence:checkout")
            profile_categories["checkout"] = {"status": "conflicted", "ref": ref, "subject_sha256": subj_sha or ""}
        elif status == "stale":
            blocked_by.append("source_stale:checkout")
            profile_categories["checkout"] = {"status": "stale", "ref": ref, "subject_sha256": subj_sha or ""}
        elif has_checkout_cleanup:
            chk_ref = raw_closure["cleanup_evidence"][0]
            claims.append(f"Supplied checkout cleanup evidence: {chk_ref}")
            profile_categories["checkout"] = {
                "status": "supplied" if status in ("cleaned", "archived", "pass") else status,
                "ref": chk_ref,
                "subject_sha256": subj_sha or "",
            }
        else:
            missing_evidence.append("checkout")
            blocked_by.append("evidence_missing:checkout")
            profile_categories["checkout"] = {
                "status": status if status not in ("cleaned", "archived", "pass") else "supplied",
                "ref": ref,
                "subject_sha256": subj_sha or "",
            }
    else:
        if has_checkout_cleanup:
            chk_ref = raw_closure["cleanup_evidence"][0]
            claims.append(f"Supplied checkout cleanup evidence: {chk_ref}")
            profile_categories["checkout"] = {"status": "supplied", "ref": chk_ref, "subject_sha256": ""}
        else:
            missing_evidence.append("checkout")
            blocked_by.append("evidence_missing:checkout")
            profile_categories["checkout"] = {"status": "missing", "ref": "", "subject_sha256": ""}

    dedup_refs: list[dict[str, str]] = []
    seen_ref_keys: set[str] = set()
    for sref in source_refs:
        rk = f"{sref['kind']}:{sref['ref']}:{sref['subject_sha256']}"
        if rk not in seen_ref_keys:
            seen_ref_keys.add(rk)
            dedup_refs.append(sref)

    return {
        "profile_id": PR_CLOSURE_PROFILE_ID,
        "categories": profile_categories,
        "blocked_by": sorted(set(blocked_by)),
        "conflicts": sorted(set(conflicts)),
        "missing_evidence": sorted(set(missing_evidence)),
        "claims": claims,
        "source_refs": dedup_refs,
        "effects": effects,
        "verifications": verifications,
    }


def build_pr_closure_assessment_request(
    evidence: dict[str, Any] | None = None,
    *,
    risk_level: str = "R2",
    assessment_id: str | None = None,
    observed_at: str | None = None,
    change_class: str = "lifecycle",
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> dict[str, Any]:
    """
    Builds a deterministic assessment request suitable for the convergence evaluator.
    Requires an explicit valid ISO 8601 date-time observation.
    Never invents missing evidence or synthesizes closure from category status strings.

    Trust boundary & provenance non-claim:
    - Default `evidence_authority` is 'supplied'. Supplying evidence forces `source_state='unknown'`
      (unless stale evidence forces 'stale') and adds 'supplied_evidence_requires_authoritative_read'
      to `blocked_by`, preventing caller-supplied data from by itself evaluating terminally closed.
    - Setting `evidence_authority='authoritative_receipts'` requires an explicit `source_state`
      ('current', 'stale', or 'unknown'). The builder preserves the caller-provided authority
      designation and does NOT cryptographically verify provenance.
    """
    observed_at = _validate_iso_datetime(observed_at, label="observed_at")
    if risk_level not in ("R0", "R1", "R2", "R3"):
        raise ConvergenceInputError("risk_level must be one of R0, R1, R2, R3")
    if change_class not in ALLOWED_CHANGE_CLASSES:
        raise ConvergenceInputError(f"change_class must be one of {sorted(ALLOWED_CHANGE_CLASSES)}")

    if evidence is None:
        evidence = {}

    authority = evidence.get("evidence_authority") or evidence_authority
    if authority not in ALLOWED_EVIDENCE_AUTHORITIES:
        raise ConvergenceInputError(
            f"evidence_authority must be 'supplied' or 'authoritative_receipts', got '{authority}'"
        )

    source_st = evidence.get("source_state") or source_state

    profile = build_pr_closure_profile(
        evidence,
        evidence_authority=authority,
        source_state=source_st,
    )

    categories_sha = _sha256_canonical(profile["categories"])
    if not assessment_id:
        assessment_id = f"pr-closure-{categories_sha[:16]}"

    blocked_by = list(profile["blocked_by"])

    if authority == "supplied":
        if "supplied_evidence_requires_authoritative_read" not in blocked_by:
            blocked_by.append("supplied_evidence_requires_authoritative_read")
        if any("source_stale" in item for item in blocked_by) or source_st == "stale":
            effective_source_state = "stale"
        else:
            effective_source_state = "unknown"
    else:  # authoritative_receipts
        if source_st is None or source_st not in ALLOWED_SOURCE_STATES:
            raise ConvergenceInputError(
                "authoritative_receipts requires an explicit source_state argument ('current', 'stale', or 'unknown')"
            )
        effective_source_state = source_st

    does_not_establish = [
        "automatic_merge_authority",
        "automatic_deploy_authority",
        "unverified_runtime_truth",
        "unread_evidence_validity",
        "bureau_mutation",
    ]

    claims = list(profile["claims"])
    source_refs = list(profile["source_refs"])
    if not source_refs:
        input_sha = hashlib.sha256(categories_sha.encode("utf-8")).hexdigest()
        source_refs = [{
            "kind": "assessment_input",
            "ref": f"grabowski:assessment-request-input:{assessment_id}",
            "subject_sha256": input_sha,
        }]
        claims.append("Bound to request input parameters (input-binding reference only; does not establish source truth)")
        does_not_establish.append("source_truth_from_input_binding")

    if not claims:
        claims = ["No positive evidence claims read"]

    request: dict[str, Any] = {
        "schema_version": 1,
        "assessment_id": assessment_id,
        "risk_level": risk_level,
        "classification": {
            "schema_version": 1,
            "change_class": change_class,
            "semantic_change": "material",
            "blocked_by": sorted(set(blocked_by)),
        },
        "observation": {
            "schema_version": 1,
            "observation_id": f"obs-{assessment_id}",
            "observed_at": observed_at,
            "source_state": effective_source_state,
            "claims": claims,
            "does_not_establish": sorted(set(does_not_establish)),
            "source_refs": source_refs,
        },
        "effects": profile["effects"],
        "verifications": profile["verifications"],
    }

    raw_closure = evidence.get("closure") if isinstance(evidence, dict) else None
    if isinstance(raw_closure, dict):
        cls_id = raw_closure.get("closure_id") or f"closure-{assessment_id}"
        cls_status = raw_closure.get("status", "proposed")
        if cls_status not in ("proposed", "closed"):
            raise ConvergenceInputError("closure.status must be proposed or closed")
        closure_dict: dict[str, Any] = {
            "schema_version": 1,
            "closure_id": _text(cls_id, "closure.closure_id"),
            "status": cls_status,
            "residual_risks": raw_closure.get("residual_risks") if isinstance(raw_closure.get("residual_risks"), list) else [],
        }
        if raw_closure.get("bureau_task_ref") is not None:
            closure_dict["bureau_task_ref"] = _text(raw_closure["bureau_task_ref"], "closure.bureau_task_ref")
        if raw_closure.get("chronik_event_ref") is not None:
            closure_dict["chronik_event_ref"] = _text(raw_closure["chronik_event_ref"], "closure.chronik_event_ref")
        if isinstance(raw_closure.get("cleanup_evidence"), list):
            closure_dict["cleanup_evidence"] = [_text(item, "closure.cleanup_evidence") for item in raw_closure["cleanup_evidence"]]
        request["closure"] = closure_dict

    return request


def build_pr_closure_request(
    evidence: dict[str, Any] | None = None,
    *,
    risk_level: str = "R2",
    assessment_id: str | None = None,
    observed_at: str | None = None,
    change_class: str = "lifecycle",
    evidence_authority: str = "supplied",
    source_state: str | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    """
    Emits a deterministic hash-bound (request_dict, request_bytes, request_sha256) tuple.
    """
    request_dict = build_pr_closure_assessment_request(
        evidence,
        risk_level=risk_level,
        assessment_id=assessment_id,
        observed_at=observed_at,
        change_class=change_class,
        evidence_authority=evidence_authority,
        source_state=source_state,
    )
    request_bytes = json.dumps(
        request_dict, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    request_sha256 = hashlib.sha256(request_bytes).hexdigest()
    return request_dict, request_bytes, request_sha256


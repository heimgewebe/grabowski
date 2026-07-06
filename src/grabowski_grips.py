from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Callable


Receipt = dict[str, Any]
CommandRunner = Callable[[Path, list[str]], dict[str, Any]]
GithubRunner = Callable[[Path, list[str]], dict[str, Any]]


@dataclass(frozen=True)
class GripSpec:
    name: str
    version: str
    summary: str
    effect: str
    required_parameters: tuple[str, ...]
    acceptance_ids: tuple[str, ...]
    runner: str


GRIP_RECEIPT_KIND = "grabowski.operator_grip_receipt"
GRIP_RECEIPT_SCHEMA_VERSION = 1
READ_ONLY = "read_only"
MUTATING = "mutating"


GRIP_SPECS: dict[str, GripSpec] = {
    "repo-orient": GripSpec(
        name="repo-orient",
        version="1.0",
        summary="Orient on a Git checkout without mutating it.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="repo_orient",
    ),
    "pr-check-readiness": GripSpec(
        name="pr-check-readiness",
        version="1.0",
        summary="Check whether a checkout is shaped like a publishable PR branch.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="pr_check_readiness",
    ),
    "worktree-orient": GripSpec(
        name="worktree-orient",
        version="1.0",
        summary="Orient on Git worktrees without mutating them.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("worktree-orient-grip", "dirty-and-stale-visible", "next-safe-grip", "focused-tests"),
        runner="worktree_orient",
    ),
    "post-merge-sync": GripSpec(
        name="post-merge-sync",
        version="1.0",
        summary="Plan post-merge local synchronization as a dry-run grip.",
        effect=READ_ONLY,
        required_parameters=("repo", "target_branch"),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="post_merge_sync",
    ),
    "branch-publish": GripSpec(
        name="branch-publish",
        version="1.0",
        summary="Publish the current HEAD to a work branch with expected-head verification.",
        effect=MUTATING,
        required_parameters=("repo", "branch", "expected_head"),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="branch_publish",
    ),
    "pr-create-or-update": GripSpec(
        name="pr-create-or-update",
        version="1.0",
        summary="Create or update an open PR for the current published work branch.",
        effect=MUTATING,
        required_parameters=("repo", "branch", "base", "expected_head", "title"),
        acceptance_ids=("acceptance-1", "acceptance-2"),
        runner="pr_create_or_update",
    ),
}


class GripPreflightError(ValueError):
    pass


class GripActionError(RuntimeError):
    pass


def _json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return {
        "__non_json_type__": f"{type(value).__module__}.{type(value).__qualname__}",
        "repr": repr(value),
    }


def canonical_json(value: Any) -> str:
    return json.dumps(_json_compatible(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_command_runner(repo: Path, argv: list[str]) -> dict[str, Any]:
    command = ["git", "--no-optional-locks", "-C", str(repo), *argv]
    env = os.environ.copy()
    for key in (
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_ASKPASS",
        "PAGER",
    ):
        env.pop(key, None)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
        }
    )
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": (exc.stdout or "").rstrip("\n") if isinstance(exc.stdout, str) else "",
            "stderr": "git command timed out after 30 seconds",
            "argv": command,
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.rstrip("\n"),
        "stderr": completed.stderr.rstrip("\n"),
        "argv": command,
    }


def _default_github_runner(repo: Path, argv: list[str]) -> dict[str, Any]:
    command = ["gh", *argv]
    env = os.environ.copy()
    for key in (
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_ASKPASS",
        "PAGER",
    ):
        env.pop(key, None)
    env.update({"GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat"})
    try:
        completed = subprocess.run(
            command,
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": (exc.stdout or "").rstrip("\n") if isinstance(exc.stdout, str) else "",
            "stderr": "gh command timed out after 30 seconds",
            "argv": command,
        }
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.rstrip("\n"),
        "stderr": completed.stderr.rstrip("\n"),
        "argv": command,
    }


def _new_receipt(spec: GripSpec, parameters: dict[str, Any]) -> Receipt:
    return {
        "kind": GRIP_RECEIPT_KIND,
        "schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
        "grip": {
            "name": spec.name,
            "version": spec.version,
            "effect": spec.effect,
        },
        "status": "running",
        "phase": "preflight",
        "started_at": utc_now(),
        "ended_at": None,
        "parameters_sha256": sha256_json(parameters),
        "acceptance_ids": list(spec.acceptance_ids),
        "checks": [],
        "output_sha256": None,
    }


def _finish(receipt: Receipt, status: str, phase: str, output: dict[str, Any] | None = None) -> dict[str, Any]:
    output = output or {}
    receipt["status"] = status
    receipt["phase"] = phase
    receipt["ended_at"] = utc_now()
    receipt["output_sha256"] = sha256_json(output)
    receipt["receipt_sha256"] = sha256_json({k: v for k, v in receipt.items() if k != "receipt_sha256"})
    return {"receipt": receipt, "output": output}


def _check(receipt: Receipt, check_id: str, status: str, detail: str) -> None:
    receipt["checks"].append({"id": check_id, "status": status, "detail": detail})


def _repo_path(parameters: dict[str, Any]) -> Path:
    raw = parameters.get("repo")
    if not isinstance(raw, str) or not raw.strip():
        raise GripPreflightError("repo parameter must be a non-empty string")
    return Path(raw).expanduser().resolve()


def _require_parameters(spec: GripSpec, parameters: dict[str, Any]) -> None:
    missing = [name for name in spec.required_parameters if name not in parameters]
    if missing:
        raise GripPreflightError(f"missing required parameters: {', '.join(missing)}")


def _git(repo: Path, runner: CommandRunner, argv: list[str]) -> dict[str, Any]:
    result = runner(repo, argv)
    if int(result.get("returncode", 1)) != 0:
        message = result.get("stderr") or result.get("stdout") or "git command failed"
        raise GripActionError(str(message))
    return result


def _git_optional(repo: Path, runner: CommandRunner, argv: list[str]) -> dict[str, Any]:
    return runner(repo, argv)


def _github(repo: Path, runner: GithubRunner, argv: list[str]) -> dict[str, Any]:
    result = runner(repo, argv)
    if int(result.get("returncode", 1)) != 0:
        message = result.get("stderr") or result.get("stdout") or "gh command failed"
        raise GripActionError(str(message))
    return result


def _json_stdout(result: dict[str, Any]) -> Any:
    raw = str(result.get("stdout", "")).strip()
    if not raw:
        raise GripActionError("expected JSON output from gh command")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GripActionError("invalid JSON output from gh command") from exc


def _orient(repo: Path, runner: CommandRunner) -> dict[str, Any]:
    root = _git(repo, runner, ["rev-parse", "--show-toplevel"])["stdout"]
    branch = _git(repo, runner, ["rev-parse", "--abbrev-ref", "HEAD"])["stdout"]
    head = _git(repo, runner, ["rev-parse", "HEAD"])["stdout"]
    status = _git(repo, runner, ["status", "--short", "--branch"])["stdout"]
    upstream = _git_optional(repo, runner, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    lines = [line for line in status.splitlines() if line]
    body = [line for line in lines[1:] if line]
    return {
        "repo": str(repo),
        "root": root,
        "branch": branch,
        "head": head,
        "dirty": bool(body),
        "status_header": lines[0] if lines else "",
        "status_entries": body,
        "upstream": upstream.get("stdout") if upstream.get("returncode") == 0 else None,
    }


def _run_repo_orient(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    if not repo.exists():
        _check(receipt, "repo_exists", "fail", str(repo))
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "repo_exists", "pass", str(repo))
    orientation = _orient(repo, runner)
    expected = parameters.get("expected_branch")
    if isinstance(expected, str) and expected:
        matches = orientation["branch"] == expected
        _check(
            receipt,
            "expected_branch",
            "pass" if matches else "fail",
            f"actual={orientation['branch']} expected={expected}",
        )
        orientation["expected_branch_match"] = matches
        if not matches:
            raise GripPreflightError(
                f"expected_branch mismatch: actual={orientation['branch']} expected={expected}"
            )
    else:
        _check(receipt, "expected_branch", "skip", "no expected_branch parameter")
        orientation["expected_branch_match"] = None
    return orientation


def _check_results(parameters: dict[str, Any]) -> dict[str, str]:
    raw = parameters.get("check_results", {})
    if not isinstance(raw, dict):
        raise GripPreflightError("check_results must be a dictionary of check name to state")
    result: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise GripPreflightError("check_results must map strings to strings")
        result[key] = value.lower()
    return result

def _is_hex_sha(value: Any, *, lengths: tuple[int, ...]) -> bool:
    if not isinstance(value, str) or len(value) not in lengths:
        return False
    hex_digits = set("0123456789abcdef")
    return all(char in hex_digits for char in value.lower())


def _external_review_evidence_errors(evidence: Any, *, expected_head: str | None) -> list[str]:
    if not isinstance(evidence, dict):
        return ["external review evidence must be a structured object"]
    errors: list[str] = []
    head_sha = evidence.get("head_sha")
    if not _is_hex_sha(head_sha, lengths=(40,)):
        errors.append("head_sha must be a 40 character hex SHA")
    elif expected_head is not None and head_sha != expected_head:
        errors.append("head_sha does not match expected_head")
    if not _is_hex_sha(evidence.get("diff_sha256"), lengths=(64,)):
        errors.append("diff_sha256 must be a 64 character hex SHA")
    reviews = evidence.get("reviews")
    if not isinstance(reviews, list) or not reviews or not all(isinstance(item, dict) for item in reviews):
        errors.append("reviews must be a non-empty list of review objects")
    elif not any(item.get("verdict") for item in reviews):
        errors.append("at least one review must include a verdict")
    if evidence.get("external_reviews_triaged") is not True:
        errors.append("external_reviews_triaged must be true")
    findings = evidence.get("findings", [])
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        errors.append("findings must be a list of finding objects")
    return errors



def _string_list_parameter(parameters: dict[str, Any], name: str, default: list[str] | None = None) -> list[str]:
    raw = parameters.get(name, default or [])
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise GripPreflightError(f"{name} must be a list of strings")
    return raw



def _parse_worktree_porcelain(value: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for raw_line in value.splitlines():
        line = raw_line.rstrip("\r")
        if line == "":
            continue
        if line.startswith("worktree "):
            if current:
                entries.append(current)
            current = {"path": line.removeprefix("worktree ")}
            continue
        if not current:
            continue
        if line.startswith("HEAD "):
            current["head"] = line.removeprefix("HEAD ")
        elif line.startswith("branch "):
            current["branch"] = line.removeprefix("branch ").removeprefix("refs/heads/")
        elif line == "detached":
            current["detached"] = True
        elif line == "bare":
            current["bare"] = True
        elif line == "locked" or line.startswith("locked "):
            current["locked"] = True
            current["locked_reason"] = line.removeprefix("locked").strip()
        elif line == "prunable" or line.startswith("prunable "):
            current["prunable"] = True
            current["prunable_reason"] = line.removeprefix("prunable").strip()
        else:
            current.setdefault("unknown_fields", []).append(line)
    if current:
        entries.append(current)
    return entries


def _worktree_status(path: Path, runner: CommandRunner) -> dict[str, Any]:
    status = _git_optional(path, runner, ["status", "--short", "--branch"])
    try:
        returncode = int(status.get("returncode", 1))
    except (TypeError, ValueError):
        returncode = 1
    status_available = returncode == 0
    stdout_raw = status.get("stdout") if status_available else ""
    stdout = stdout_raw if isinstance(stdout_raw, str) else ""
    lines = [line for line in stdout.splitlines() if line]
    body = [line for line in lines[1:] if line]
    return {
        "path": str(path),
        "dirty": bool(body),
        "status_header": lines[0] if lines else "",
        "status_entries": body,
        "status_available": status_available,
    }


def _run_worktree_orient(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    if not repo.exists():
        _check(receipt, "repo_exists", "fail", str(repo))
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "repo_exists", "pass", str(repo))
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    protected_branches = set(protected)
    raw = _git(repo, runner, ["worktree", "list", "--porcelain"])["stdout"]
    entries = _parse_worktree_porcelain(str(raw))
    _check(receipt, "worktree_list", "pass" if entries else "warn", f"count={len(entries)}")
    worktrees: list[dict[str, Any]] = []
    dirty_worktrees: list[str] = []
    unobservable_worktrees: list[str] = []
    active_feature_worktrees: list[str] = []
    clean_feature_worktrees: list[str] = []
    detached_worktrees: list[str] = []
    stale_candidates: list[str] = []
    cleanup_candidates: list[dict[str, Any]] = []
    cleanup_candidate_index: dict[str, dict[str, Any]] = {}
    canonical_checkout: str | None = None

    def add_stale_candidate(path: str) -> None:
        if path and path not in stale_candidates:
            stale_candidates.append(path)

    def add_cleanup_candidate(path: str, branch: str | None, reason: str) -> None:
        if not path:
            return
        existing = cleanup_candidate_index.get(path)
        if existing is not None:
            reasons = existing.setdefault("reasons", [])
            if reason not in reasons:
                reasons.append(reason)
                existing["reason"] = "; ".join(reasons)
            if branch and not existing.get("branch"):
                existing["branch"] = branch
            return
        record: dict[str, Any] = {
            "path": path,
            "branch": branch,
            "reason": reason,
            "reasons": [reason],
            "cleanup_allowed": False,
        }
        cleanup_candidate_index[path] = record
        cleanup_candidates.append(record)

    for entry in entries:
        path_raw = entry.get("path")
        path_value = path_raw if isinstance(path_raw, str) else ""
        branch = str(entry.get("branch", "")) if entry.get("branch") else None
        detached = bool(entry.get("detached"))
        status = _worktree_status(Path(path_value), runner) if path_value else {"dirty": False, "status_available": False, "status_entries": [], "status_header": "", "path": ""}
        status_available = bool(status.get("status_available"))
        dirty = bool(status.get("dirty"))
        record = {**entry, **status, "path": path_value, "branch": branch}
        worktrees.append(record)
        if path_value == "":
            continue
        if branch in protected_branches and canonical_checkout is None:
            canonical_checkout = path_value
        if detached:
            detached_worktrees.append(path_value)
        if not status_available:
            unobservable_worktrees.append(path_value)
        if dirty:
            dirty_worktrees.append(path_value)
        if branch and branch not in protected_branches:
            active_feature_worktrees.append(path_value)
            if status_available and not dirty:
                clean_feature_worktrees.append(path_value)
        if detached and status_available and not dirty:
            add_cleanup_candidate(path_value, None, "detached worktree has no local status entries")
        if entry.get("prunable"):
            add_stale_candidate(path_value)
            add_cleanup_candidate(path_value, branch, str(entry.get("prunable_reason") or "git marks worktree prunable"))
    if canonical_checkout is None and worktrees:
        canonical_checkout = str(worktrees[0].get("path"))
    blocked_by_worktree_review = bool(stale_candidates or cleanup_candidates or unobservable_worktrees)
    if blocked_by_worktree_review:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "manual review is required before cleanup or unobservable worktrees; no automatic next grip is recommended",
            "effect": READ_ONLY,
        }
    elif len(clean_feature_worktrees) == 1:
        next_safe_grip = {
            "name": "pr-check-readiness",
            "parameters": {"repo": clean_feature_worktrees[0]},
            "reason": "one clean feature worktree is the unambiguous next read-only PR readiness target",
            "effect": READ_ONLY,
        }
    elif len(clean_feature_worktrees) > 1:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "multiple clean feature worktrees exist; choose a target manually",
            "effect": READ_ONLY,
        }
    else:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "no unambiguous clean PR worktree target",
            "effect": READ_ONLY,
        }
    return {
        "repo": str(repo),
        "canonical_checkout": canonical_checkout,
        "runtime_matching_worktree": {
            "available": False,
            "reason": "runtime binding not implemented in worktree-orient v1",
        },
        "active_feature_worktrees": active_feature_worktrees,
        "clean_feature_worktrees": clean_feature_worktrees,
        "detached_worktrees": detached_worktrees,
        "dirty_worktrees": dirty_worktrees,
        "unobservable_worktrees": unobservable_worktrees,
        "stale_candidates": stale_candidates,
        "cleanup_candidates": cleanup_candidates,
        "cleanup_review_candidates": cleanup_candidates,
        "worktrees": worktrees,
        "next_safe_grip": next_safe_grip,
    }

def _run_pr_check_readiness(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    branch_is_work = orientation["branch"] not in set(protected)
    upstream_set = orientation["upstream"] is not None
    clean_required = bool(parameters.get("require_clean", False))
    clean_ok = not orientation["dirty"] if clean_required else True
    blocking_reasons: list[str] = []
    warnings: list[str] = []
    _check(
        receipt,
        "work_branch",
        "pass" if branch_is_work else "fail",
        f"branch={orientation['branch']}",
    )
    if not branch_is_work:
        blocking_reasons.append("protected branch is not a PR work branch")
    _check(
        receipt,
        "upstream",
        "pass" if upstream_set else "warn",
        orientation["upstream"] or "no upstream configured",
    )
    if not upstream_set:
        warnings.append("no upstream configured")
    _check(
        receipt,
        "cleanliness",
        "pass" if clean_ok else "fail",
        "clean required" if clean_required else "clean not required",
    )
    if not clean_ok:
        blocking_reasons.append("worktree is dirty")
    expected_head = parameters.get("expected_head")
    if expected_head is not None:
        expected_head = _sha_parameter(parameters, "expected_head")
        head_ok = orientation["head"] == expected_head
        _check(receipt, "expected_head", "pass" if head_ok else "fail", f"actual={orientation['head']} expected={expected_head}")
        if not head_ok:
            blocking_reasons.append("expected_head mismatch")
    required_checks = _string_list_parameter(parameters, "required_checks")
    check_results = _check_results(parameters)
    missing_checks = [name for name in required_checks if name not in check_results]
    failing_checks = [name for name in required_checks if check_results.get(name) not in (None, "success", "pass", "passed")]
    if required_checks:
        checks_ok = not missing_checks and not failing_checks
        detail = f"required={required_checks} missing={missing_checks} failing={failing_checks}"
        _check(receipt, "required_checks", "pass" if checks_ok else "fail", detail)
        if missing_checks:
            blocking_reasons.append("required checks missing")
        if failing_checks:
            blocking_reasons.append("required checks failing")
    else:
        _check(receipt, "required_checks", "skip", "no required_checks parameter")
    review_decision = parameters.get("review_decision")
    if review_decision is not None:
        if not isinstance(review_decision, str):
            raise GripPreflightError("review_decision must be a string when provided")
        normalized_review = review_decision.upper()
        if normalized_review in {"CHANGES_REQUESTED", "REQUEST_CHANGES"}:
            _check(receipt, "review_decision", "fail", normalized_review)
            blocking_reasons.append("review changes requested")
        elif normalized_review == "REVIEW_REQUIRED":
            _check(receipt, "review_decision", "fail", normalized_review)
            blocking_reasons.append("review approval required")
        elif normalized_review in {"APPROVED", "", "COMMENTED"}:
            _check(receipt, "review_decision", "pass" if normalized_review == "APPROVED" else "warn", normalized_review or "empty")
            if normalized_review != "APPROVED":
                warnings.append("review is not approved")
        else:
            _check(receipt, "review_decision", "warn", normalized_review)
            warnings.append("unknown review decision")
    unresolved_findings = _string_list_parameter(parameters, "unresolved_findings")
    if unresolved_findings:
        _check(receipt, "unresolved_findings", "fail", ", ".join(unresolved_findings))
        blocking_reasons.append("unresolved review findings")
    else:
        _check(receipt, "unresolved_findings", "pass", "none")
    external_review_required = bool(parameters.get("external_review_required", False))
    external_review_evidence = parameters.get("external_review_evidence")
    if external_review_required and not external_review_evidence:
        _check(receipt, "external_review_evidence", "fail", "external review required but no evidence provided")
        blocking_reasons.append("external review evidence missing")
    elif external_review_required:
        expected_head_for_review = expected_head if isinstance(expected_head, str) else None
        evidence_errors = _external_review_evidence_errors(external_review_evidence, expected_head=expected_head_for_review)
        if evidence_errors:
            _check(receipt, "external_review_evidence", "fail", "; ".join(evidence_errors))
            blocking_reasons.append("external review evidence invalid")
        else:
            _check(receipt, "external_review_evidence", "pass", "structured evidence provided")
    else:
        _check(receipt, "external_review_evidence", "skip", "not required")
    ready = branch_is_work and upstream_set and clean_ok and not blocking_reasons
    verdict = "ready" if ready else "blocked"
    return {
        "ready": ready,
        "verdict": verdict,
        "blocking_reasons": blocking_reasons,
        "warnings": warnings,
        "orientation": orientation,
        "protected_branches": protected,
        "require_clean": clean_required,
        "required_checks": required_checks,
        "check_results": check_results,
        "unresolved_findings": unresolved_findings,
        "external_review_required": external_review_required,
    }


def _string_parameter(parameters: dict[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value.strip():
        raise GripPreflightError(f"{name} parameter must be a non-empty string")
    return value.strip()


def _sha_parameter(parameters: dict[str, Any], name: str) -> str:
    value = _string_parameter(parameters, name)
    hex_digits = set("0123456789abcdef")
    if len(value) not in (40, 64) or any(char not in hex_digits for char in value.lower()):
        raise GripPreflightError(f"{name} parameter must be a 40 or 64 character hex SHA")
    return value


def _short_branch_name(parameters: dict[str, Any], name: str) -> str:
    branch = _string_parameter(parameters, name)
    if branch.startswith("refs/"):
        raise GripPreflightError(f"{name} parameter must be a short branch name, not a ref")
    if ":" in branch or branch.startswith("-"):
        raise GripPreflightError(f"{name} parameter must be a safe short branch name")
    return branch


def _run_post_merge_sync(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    target = _string_parameter(parameters, "target_branch")
    dry_run = parameters.get("dry_run", True)
    if dry_run is not True:
        _check(receipt, "dry_run_only", "fail", "post-merge-sync foundation grip is dry-run only")
        raise GripPreflightError("post-merge-sync is dry-run only in GRIP-001")
    _check(receipt, "dry_run_only", "pass", "no mutation will be executed")
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    commands = [
        ["git", "fetch", "origin"],
        ["git", "switch", target],
        ["git", "pull", "--ff-only"],
    ]
    return {
        "dry_run": True,
        "orientation": orientation,
        "target_branch": target,
        "planned_commands": commands,
    }


def _run_branch_publish(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    branch = _short_branch_name(parameters, "branch")
    expected_head = _sha_parameter(parameters, "expected_head")
    remote = parameters.get("remote", "origin")
    if not isinstance(remote, str) or not remote.strip():
        raise GripPreflightError("remote parameter must be a non-empty string")
    remote = remote.strip()
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    if branch in set(protected):
        _check(receipt, "protected_branch", "fail", f"branch={branch}")
        raise GripPreflightError("branch-publish refuses protected branches")
    _check(receipt, "protected_branch", "pass", f"branch={branch}")
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    if orientation["branch"] != branch:
        _check(
            receipt,
            "publish_branch",
            "fail",
            f"actual={orientation['branch']} target={branch}",
        )
        raise GripPreflightError(
            f"branch mismatch: actual={orientation['branch']} target={branch}"
        )
    _check(receipt, "publish_branch", "pass", branch)
    if orientation["head"] != expected_head:
        _check(
            receipt,
            "expected_head",
            "fail",
            f"actual={orientation['head']} expected={expected_head}",
        )
        raise GripPreflightError(
            f"expected_head mismatch: actual={orientation['head']} expected={expected_head}"
        )
    _check(receipt, "expected_head", "pass", expected_head)
    allow_dirty = bool(parameters.get("allow_dirty", False))
    if orientation["dirty"] and not allow_dirty:
        _check(receipt, "clean_worktree", "fail", "dirty worktree")
        raise GripPreflightError("branch-publish requires a clean worktree unless allow_dirty=true")
    _check(receipt, "clean_worktree", "pass" if not orientation["dirty"] else "warn", "clean" if not orientation["dirty"] else "allow_dirty=true")
    ref = f"refs/heads/{branch}"
    push = _git(repo=Path(orientation["root"]), runner=runner, argv=["push", remote, f"HEAD:{branch}"])
    remote_result = _git(repo=Path(orientation["root"]), runner=runner, argv=["ls-remote", remote, ref])
    remote_line = str(remote_result.get("stdout", "")).splitlines()[0] if remote_result.get("stdout") else ""
    remote_head = remote_line.split()[0] if remote_line.split() else ""
    if remote_head != expected_head:
        _check(receipt, "remote_head", "fail", f"actual={remote_head} expected={expected_head}")
        raise GripActionError("remote head did not match expected_head after push")
    _check(receipt, "remote_head", "pass", remote_head)
    return {
        "branch": branch,
        "head": expected_head,
        "remote": remote,
        "ref": ref,
        "remote_head": remote_head,
        "push_stdout": push.get("stdout", ""),
        "push_stderr": push.get("stderr", ""),
    }


def _open_pr_from_stdout(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise GripActionError("unexpected PR lookup output")
    return value


def _run_pr_create_or_update(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    branch = _short_branch_name(parameters, "branch")
    base = _short_branch_name(parameters, "base")
    title = _string_parameter(parameters, "title")
    expected_head = _sha_parameter(parameters, "expected_head")
    body_value = parameters.get("body", "")
    if body_value is None:
        body = ""
    elif isinstance(body_value, str):
        body = body_value
    else:
        raise GripPreflightError("body parameter must be a string when provided")
    protected = parameters.get("protected_branches", ["main", "master"])
    if not isinstance(protected, list) or not all(isinstance(item, str) for item in protected):
        raise GripPreflightError("protected_branches must be a list of strings")
    if branch in set(protected):
        _check(receipt, "protected_head_branch", "fail", f"branch={branch}")
        raise GripPreflightError("pr-create-or-update refuses protected head branches")
    _check(receipt, "protected_head_branch", "pass", f"branch={branch}")
    orientation = _run_repo_orient(spec, parameters, receipt, runner)
    if orientation["branch"] != branch:
        _check(receipt, "head_branch", "fail", f"actual={orientation['branch']} expected={branch}")
        raise GripPreflightError(f"branch mismatch: actual={orientation['branch']} expected={branch}")
    _check(receipt, "head_branch", "pass", branch)
    if orientation["head"] != expected_head:
        _check(receipt, "expected_head", "fail", f"actual={orientation['head']} expected={expected_head}")
        raise GripPreflightError(f"expected_head mismatch: actual={orientation['head']} expected={expected_head}")
    _check(receipt, "expected_head", "pass", expected_head)
    allow_dirty = bool(parameters.get("allow_dirty", False))
    if orientation["dirty"] and not allow_dirty:
        _check(receipt, "clean_worktree", "fail", "dirty worktree")
        raise GripPreflightError("pr-create-or-update requires a clean worktree unless allow_dirty=true")
    _check(
        receipt,
        "clean_worktree",
        "pass" if not orientation["dirty"] else "warn",
        "clean" if not orientation["dirty"] else "allow_dirty=true",
    )
    remote = parameters.get("remote", "origin")
    if not isinstance(remote, str) or not remote.strip():
        raise GripPreflightError("remote parameter must be a non-empty string")
    remote = remote.strip()
    remote_ref = f"refs/heads/{branch}"
    remote_result = _git(repo, runner, ["ls-remote", remote, remote_ref])
    remote_line = str(remote_result.get("stdout", "")).splitlines()[0] if remote_result.get("stdout") else ""
    remote_head = remote_line.split()[0] if remote_line.split() else ""
    if remote_head != expected_head:
        _check(receipt, "remote_head", "fail", f"actual={remote_head} expected={expected_head}")
        raise GripPreflightError("remote branch does not match expected_head")
    _check(receipt, "remote_head", "pass", remote_head)
    lookup = _json_stdout(_github(
        repo,
        github_runner,
        [
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "open",
            "--json",
            "number,url,baseRefName,headRefName,headRefOid",
            "--jq",
            ".[0] // null",
        ],
    ))
    existing = _open_pr_from_stdout(lookup)
    if existing is not None:
        if existing.get("baseRefName") != base:
            _check(receipt, "base_branch", "fail", f"actual={existing.get('baseRefName')} expected={base}")
            raise GripPreflightError("existing PR base does not match requested base")
        if existing.get("headRefOid") != expected_head:
            _check(receipt, "pr_head", "fail", f"actual={existing.get('headRefOid')} expected={expected_head}")
            raise GripPreflightError("existing PR head does not match expected_head")
        _check(receipt, "existing_pr", "pass", str(existing.get("number")))
        edit_args = ["pr", "edit", str(existing["number"]), "--title", title]
        if body:
            edit_args.extend(["--body", body])
        _github(repo, github_runner, edit_args)
        action = "updated"
        view_target = str(existing["number"])
    else:
        _check(receipt, "existing_pr", "skip", "no open PR for branch")
        _github(repo, github_runner, ["pr", "create", "--base", base, "--head", branch, "--title", title, "--body", body])
        action = "created"
        view_target = branch
    viewed = _json_stdout(_github(
        repo,
        github_runner,
        [
            "pr",
            "view",
            view_target,
            "--json",
            "number,url,state,baseRefName,headRefName,headRefOid,isDraft,mergeable",
        ],
    ))
    if not isinstance(viewed, dict):
        raise GripActionError("unexpected PR view output")
    if viewed.get("baseRefName") != base or viewed.get("headRefName") != branch or viewed.get("headRefOid") != expected_head:
        _check(receipt, "pr_verify", "fail", json.dumps(viewed, sort_keys=True))
        raise GripActionError("PR verification did not match requested branch/base/head")
    _check(receipt, "pr_verify", "pass", str(viewed.get("number")))
    return {"action": action, "pr": viewed, "branch": branch, "base": base, "head": expected_head}


_RUNNERS = {
    "repo_orient": _run_repo_orient,
    "pr_check_readiness": _run_pr_check_readiness,
    "worktree_orient": _run_worktree_orient,
    "post_merge_sync": _run_post_merge_sync,
    "branch_publish": _run_branch_publish,
    "pr_create_or_update": _run_pr_create_or_update,
}


def run_grip(
    name: str,
    parameters: dict[str, Any] | None = None,
    *,
    allow_mutation: bool = False,
    command_runner: CommandRunner | None = None,
    github_runner: GithubRunner | None = None,
) -> dict[str, Any]:
    parameters = dict(parameters or {})
    spec = GRIP_SPECS.get(name)
    if spec is None:
        fallback = GripSpec(
            name=name,
            version="0",
            summary="unknown grip",
            effect=READ_ONLY,
            required_parameters=(),
            acceptance_ids=(),
            runner="unknown",
        )
        receipt = _new_receipt(fallback, parameters)
        _check(receipt, "known_grip", "fail", f"unknown grip: {name}")
        return _finish(receipt, "blocked", "preflight", {"error": f"unknown grip: {name}"})

    receipt = _new_receipt(spec, parameters)
    _check(receipt, "known_grip", "pass", spec.summary)
    try:
        _require_parameters(spec, parameters)
        _check(receipt, "required_parameters", "pass", ", ".join(spec.required_parameters))
        if spec.effect == MUTATING and not allow_mutation:
            _check(receipt, "mutation_allowed", "fail", "allow_mutation is false")
            return _finish(
                receipt,
                "blocked",
                "preflight",
                {"error": "mutating grip requires allow_mutation=true"},
            )
        _check(receipt, "mutation_allowed", "pass", f"effect={spec.effect}")
        action = _RUNNERS[spec.runner]
        command = command_runner or _default_command_runner
        if spec.runner == "pr_create_or_update":
            output = action(
                spec,
                parameters,
                receipt,
                command,
                github_runner or _default_github_runner,
            )
        else:
            output = action(spec, parameters, receipt, command)
        return _finish(receipt, "passed", "action", output)
    except GripPreflightError as exc:
        return _finish(receipt, "blocked", "preflight", {"error": str(exc)})
    except GripActionError as exc:
        return _finish(receipt, "failed", "action", {"error": str(exc)})


def list_grips() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "version": spec.version,
            "summary": spec.summary,
            "effect": spec.effect,
            "required_parameters": list(spec.required_parameters),
            "acceptance_ids": list(spec.acceptance_ids),
        }
        for spec in sorted(GRIP_SPECS.values(), key=lambda item: item.name)
    ]

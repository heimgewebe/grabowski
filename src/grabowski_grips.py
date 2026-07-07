from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

import grabowski_repobrief

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
    uses_github: bool = False


GRIP_RECEIPT_KIND = "grabowski.operator_grip_receipt"
GRIP_RECEIPT_SCHEMA_VERSION = 1
READ_ONLY = "read_only"
MUTATING = "mutating"

SITUATION_ACCEPTANCE_IDS = (
    "situation-readonly",
    "core-state-fields",
    "snapshot-digest",
    "next-safe-grip",
    "tests",
)
SITUATION_CHECK_REPO_STATE = "repo_state"
SITUATION_CHECK_PR_STATE = "pr_state"
SITUATION_CHECK_SNAPSHOT_DIGEST = "snapshot_digest"
SITUATION_CHECK_NEXT_SAFE_GRIP = "next_safe_grip"
SITUATION_NON_CLAIMS = (
    "does not refresh connectors",
    "does not mutate repositories",
    "does not dispatch work",
    "does not complete Bureau tasks",
    "does not establish Bureau truth",
)


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
    "situation": GripSpec(
        name="situation",
        version="1.0",
        summary="Summarize repo, PR, Bureau and grip context without mutating anything.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=SITUATION_ACCEPTANCE_IDS,
        runner="situation",
        uses_github=True,
    ),
    "scout": GripSpec(
        name="scout",
        version="1.0",
        summary="Report only actionable changes across repository, PR and runtime signals.",
        effect=READ_ONLY,
        required_parameters=("repo",),
        acceptance_ids=("only-changes", "pr-and-runtime-drift", "disable-switch", "no-mutation"),
        runner="scout",
        uses_github=True,
    ),
    "mechanic-loop": GripSpec(
        name="mechanic-loop",
        version="1.0",
        summary="Run a bounded sequence of normal receipt-bound grips.",
        effect=MUTATING,
        required_parameters=("actions",),
        acceptance_ids=("normal-grips-only", "scope-visible", "receipt-per-grip"),
        runner="mechanic_loop",
        uses_github=True,
    ),
    "captain-preflight": GripSpec(
        name="captain-preflight",
        version="1.0",
        summary="Preflight high-impact Captain actions without executing privileged mutations.",
        effect=READ_ONLY,
        required_parameters=("actions",),
        acceptance_ids=("high-impact-marked", "recovery-or-irreversibility", "target-change-record"),
        runner="captain_preflight",
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
        uses_github=True,
    ),
}


GRIP_SURFACE_ALLOWLIST = frozenset(
    {
        "repo-orient",
        "worktree-orient",
        "situation",
        "scout",
        "mechanic-loop",
        "captain-preflight",
        "pr-check-readiness",
        "post-merge-sync",
        "branch-publish",
        "pr-create-or-update",
    }
)
GRIP_SURFACE_PROFILES = {"observer", "operator", "captain"}
GRIP_SURFACE_MUTATING_PROFILES = {"operator", "captain"}
GRIP_SURFACE_TARGETS = {
    "repo-orient": "repository checkout",
    "worktree-orient": "repository worktree inventory",
    "situation": "repository and PR situation snapshot",
    "scout": "change-only repository, PR and runtime drift signal",
    "mechanic-loop": "bounded normal grip action sequence",
    "captain-preflight": "high-impact Captain action preflight only",
    "pr-check-readiness": "pull request readiness evidence",
    "post-merge-sync": "post-merge local checkout sync",
    "branch-publish": "git branch publication",
    "pr-create-or-update": "GitHub pull request metadata",
}
GRIP_SURFACE_RECOVERY_PATHS = {
    READ_ONLY: "rerun the grip with the same inputs; no local recovery should be required",
    MUTATING: "inspect the emitted receipt, verify target/scope, then use git/GitHub rollback or retry from the recorded head",
}
MECHANIC_NORMAL_GRIPS = frozenset(
    {
        "repo-orient",
        "worktree-orient",
        "situation",
        "scout",
        "pr-check-readiness",
        "post-merge-sync",
        "branch-publish",
        "pr-create-or-update",
    }
)
CAPTAIN_HIGH_IMPACT_ACTIONS = frozenset(
    {
        "pr-merge",
        "runtime-deploy",
        "service-restart",
        "fleet-mutation",
        "cleanup-apply",
    }
)
GRIP_SURFACE_CAPTAIN_ONLY = frozenset({"captain-preflight"})
MECHANIC_FORBIDDEN_EFFECTS = tuple(sorted(CAPTAIN_HIGH_IMPACT_ACTIONS | {"force-push", "secret-mutation", "database-migration", "privileged-broker-mutation"}))
MECHANIC_MAX_ACTIONS = 10
CAPTAIN_MAX_ACTIONS = 10


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
    try:
        rb = grabowski_repobrief.context(repo, runner, orientation, parameters)
    except Exception as exc:
        rb = {"available": False, "status": "error", "reason": str(exc)}
    orientation["repobrief_context"] = rb
    rb_status = str(rb.get("status") or "unknown")
    rb_check = "pass" if rb.get("available") else ("skip" if rb_status == "excluded" else "warn")
    _check(receipt, "repobrief_context", rb_check, rb_status)
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

def _is_sha256_hex(value: Any) -> bool:
    return _is_hex_sha(value, lengths=(64,))


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




def _parse_worktree_porcelain(value: str) -> list[dict[str, str | bool | list[str]]]:
    entries: list[dict[str, str | bool | list[str]]] = []
    current: dict[str, str | bool | list[str]] | None = None

    for raw_line in value.splitlines():
        if not raw_line:
            continue

        if raw_line.startswith("worktree "):
            if current is not None:
                entries.append(current)
            current = {"path": raw_line[len("worktree ") :]}
            continue

        if current is None:
            continue

        if raw_line.startswith("HEAD "):
            current["head"] = raw_line[len("HEAD ") :]
        elif raw_line.startswith("branch "):
            current["branch"] = raw_line[len("branch ") :].removeprefix("refs/heads/")
        elif raw_line == "detached":
            current["detached"] = True
        elif raw_line == "bare":
            current["bare"] = True
        elif raw_line == "locked":
            current["locked"] = True
            current["locked_reason"] = ""
        elif raw_line.startswith("locked "):
            current["locked"] = True
            current["locked_reason"] = raw_line.removeprefix("locked ")
        elif raw_line == "prunable":
            current["prunable"] = True
            current["prunable_reason"] = ""
        elif raw_line.startswith("prunable "):
            current["prunable"] = True
            current["prunable_reason"] = raw_line.removeprefix("prunable ")
        else:
            unknown = current.get("unknown_fields")
            if not isinstance(unknown, list):
                unknown = []
                current["unknown_fields"] = unknown
            unknown.append(raw_line)

    if current is not None:
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
    lines = [line for line in stdout.splitlines() if line] if status_available else []
    body = [line for line in lines[1:] if line]
    error_raw = status.get("stderr") or status.get("stdout") or "git status failed"
    if not isinstance(error_raw, str):
        error_raw = f"git status failed with non-text output ({type(error_raw).__name__})"
    return {
        "path": str(path),
        "dirty": bool(body) if status_available else None,
        "status_header": lines[0] if lines else "",
        "status_entries": body,
        "status_available": status_available,
        "status_error": "" if status_available else error_raw,
        "status_returncode": returncode,
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

    try:
        protected = _string_list_parameter(parameters, "protected_branches", ["main", "master"])
    except GripPreflightError as exc:
        _check(receipt, "protected_branches_valid", "fail", str(exc))
        raise
    if not protected:
        _check(receipt, "protected_branches_valid", "fail", "empty list")
        raise GripPreflightError("protected_branches must not be empty")
    invalid_protected = [item for item in protected if not item or item != item.strip() or item.startswith("refs/")]
    if invalid_protected:
        _check(receipt, "protected_branches_valid", "fail", "branch names must be non-empty trimmed short names")
        raise GripPreflightError("protected_branches entries must be non-empty trimmed short branch names")
    if len(set(protected)) != len(protected):
        _check(receipt, "protected_branches_valid", "fail", "duplicate branch names")
        raise GripPreflightError("protected_branches entries must be unique")
    _check(receipt, "protected_branches_valid", "pass", ", ".join(protected))

    worktree_result = _git(repo, runner, ["worktree", "list", "--porcelain"])
    raw = worktree_result.get("stdout")
    if not isinstance(raw, str):
        raise GripActionError("git worktree porcelain output must be text")
    entries = _parse_worktree_porcelain(raw)
    _check(receipt, "worktree_list", "pass" if entries else "warn", f"count={len(entries)}")

    worktrees: list[dict[str, Any]] = []
    active_feature_worktrees: list[str] = []
    clean_feature_worktrees: list[str] = []
    dirty_worktrees: list[str] = []
    unobservable_worktrees: list[str] = []
    detached_worktrees: list[str] = []
    prunable_worktrees: list[str] = []
    locked_worktrees: list[str] = []
    bare_worktrees: list[str] = []
    stale_candidates: list[str] = []
    cleanup_candidates: list[dict[str, Any]] = []
    cleanup_candidate_index: dict[str, dict[str, Any]] = {}
    stale_candidate_seen: set[str] = set()

    canonical_checkout: str | None = None
    canonical_checkout_reason: str | None = None
    repo_resolved = repo.resolve()

    def same_resolved_path(path_value: str) -> bool:
        try:
            return Path(path_value).expanduser().resolve() == repo_resolved
        except OSError:
            return False

    def add_cleanup_candidate(path_value: str, branch: str | None, reason: str) -> None:
        if not path_value:
            return
        if path_value not in stale_candidate_seen:
            stale_candidate_seen.add(path_value)
            stale_candidates.append(path_value)

        existing = cleanup_candidate_index.get(path_value)
        if existing is not None:
            reasons = existing.setdefault("reasons", [])
            if reason not in reasons:
                reasons.append(reason)
                existing["reason"] = "; ".join(reasons)
            if branch and not existing.get("branch"):
                existing["branch"] = branch
            return

        record: dict[str, Any] = {
            "path": path_value,
            "branch": branch,
            "reason": reason,
            "reasons": [reason],
            "cleanup_allowed": False,
        }
        cleanup_candidate_index[path_value] = record
        cleanup_candidates.append(record)

    for entry in entries:
        path_value = str(entry.get("path", ""))
        branch = entry.get("branch") if isinstance(entry.get("branch"), str) else None
        detached = bool(entry.get("detached"))
        bare = bool(entry.get("bare"))
        locked = bool(entry.get("locked"))
        prunable = bool(entry.get("prunable"))

        status = (
            _worktree_status(Path(path_value), runner)
            if path_value
            else {
                "dirty": None,
                "status_available": False,
                "status_error": "missing worktree path",
                "status_returncode": 1,
            }
        )
        status_available = bool(status.get("status_available"))
        dirty = status.get("dirty") is True

        is_protected = branch in protected if branch else False
        is_feature = bool(branch and branch not in protected)

        record = {
            **entry,
            **status,
            "branch": branch,
            "is_protected": is_protected,
            "is_feature": is_feature,
            "is_canonical": False,
            "is_cleanup_candidate": False,
        }

        if same_resolved_path(path_value) and canonical_checkout is None:
            canonical_checkout = path_value
            canonical_checkout_reason = "matches requested repo path"
            record["is_canonical"] = True

        if detached and path_value:
            detached_worktrees.append(path_value)
        if bare and path_value:
            bare_worktrees.append(path_value)
        if locked and path_value:
            locked_worktrees.append(path_value)
        if prunable and path_value:
            prunable_worktrees.append(path_value)
        if not status_available and path_value:
            unobservable_worktrees.append(path_value)
        if dirty and path_value:
            dirty_worktrees.append(path_value)

        if is_feature and path_value:
            active_feature_worktrees.append(path_value)
            if status_available and not dirty:
                clean_feature_worktrees.append(path_value)

        if prunable and path_value:
            if status_available:
                add_cleanup_candidate(
                    path_value,
                    branch,
                    str(entry.get("prunable_reason") or "git marks worktree prunable"),
                )
                record["is_cleanup_candidate"] = True
            else:
                record["classification_degraded_reason"] = "prunable marker present but status unavailable"

        worktrees.append(record)

    if canonical_checkout is None:
        for protected_branch in protected:
            for record in worktrees:
                if record.get("path") and record.get("branch") == protected_branch:
                    canonical_checkout = str(record.get("path"))
                    canonical_checkout_reason = "first protected branch worktree by protected_branches order"
                    record["is_canonical"] = True
                    break
            if canonical_checkout is not None:
                break

    if canonical_checkout is None and worktrees:
        canonical_checkout = str(worktrees[0].get("path"))
        canonical_checkout_reason = "fallback to first listed worktree"
        worktrees[0]["is_canonical"] = True

    unavailable_count = len(unobservable_worktrees)
    _check(
        receipt,
        "worktree_status_read",
        "pass" if unavailable_count == 0 else "warn",
        f"unavailable={unavailable_count} observed={len(worktrees) - unavailable_count}",
    )
    _check(
        receipt,
        "status_unavailable_count",
        "pass" if unavailable_count == 0 else "warn",
        str(unavailable_count),
    )
    _check(
        receipt,
        "classification_degraded",
        "warn" if unavailable_count else "pass",
        "status unavailable for some worktrees" if unavailable_count else "all listed worktrees classified",
    )

    blocked_by_worktree_review = bool(cleanup_candidates or unobservable_worktrees)
    if blocked_by_worktree_review:
        next_safe_grip = {
            "name": None,
            "parameters": None,
            "reason": "manual review is required before cleanup or unknown-status worktree handling; no automatic next grip is recommended",
            "effect": READ_ONLY,
        }
    elif len(active_feature_worktrees) == 1 and len(clean_feature_worktrees) == 1:
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
        "canonical_checkout_reason": canonical_checkout_reason,
        "active_feature_worktrees": active_feature_worktrees,
        "clean_feature_worktrees": clean_feature_worktrees,
        "detached_worktrees": detached_worktrees,
        "dirty_worktrees": dirty_worktrees,
        "unobservable_worktrees": unobservable_worktrees,
        "prunable_worktrees": prunable_worktrees,
        "locked_worktrees": locked_worktrees,
        "bare_worktrees": bare_worktrees,
        "stale_candidates": stale_candidates,
        "cleanup_candidates": cleanup_candidates,
        "cleanup_candidate_count": len(cleanup_candidates),
        "worktrees": worktrees,
        "next_safe_grip": next_safe_grip,
    }




def _grip_catalog_snapshot() -> dict[str, Any]:
    return {
        "receipt_kind": GRIP_RECEIPT_KIND,
        "receipt_schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
        "grips": {
            name: {
                "name": spec.name,
                "version": spec.version,
                "summary": spec.summary,
                "effect": spec.effect,
                "required_parameters": list(spec.required_parameters),
                "acceptance_ids": list(spec.acceptance_ids),
                "runner": spec.runner,
                "uses_github": spec.uses_github,
            }
            for name, spec in sorted(GRIP_SPECS.items())
        },
    }


def _grip_catalog_digest() -> str:
    return sha256_json(_grip_catalog_snapshot())


def _bool_parameter(parameters: dict[str, Any], name: str, default: bool) -> bool:
    value = parameters.get(name, default)
    if not isinstance(value, bool):
        raise GripPreflightError(f"{name} must be a boolean when provided")
    return value


def _source_object(parameters: dict[str, Any], name: str) -> dict[str, Any]:
    value = parameters.get(name)
    if value is None:
        return {"available": False, "reason": f"{name} parameter not provided"}
    if not isinstance(value, dict):
        raise GripPreflightError(f"{name} must be an object when provided")
    return {"available": True, "value": value}


def _source_list(parameters: dict[str, Any], name: str) -> dict[str, Any]:
    value = parameters.get(name)
    if value is None:
        return {"available": False, "items": [], "reason": f"{name} parameter not provided"}
    if not isinstance(value, list):
        raise GripPreflightError(f"{name} must be a list when provided")
    return {"available": True, "items": value}


def _truncate_reason(value: Any, limit: int = 500) -> str:
    text = str(value).strip()
    return text[:limit] if text else "unknown"


def _check_rollup_summary(checks: Any) -> dict[str, Any]:
    states: list[str] = []
    check_results: dict[str, str] = {}
    if isinstance(checks, list):
        for item in checks:
            if not isinstance(item, dict):
                continue
            state = item.get("conclusion") or item.get("status") or item.get("state")
            if not isinstance(state, str):
                continue
            states.append(state)
            name = item.get("name") or item.get("context") or item.get("workflowName")
            if isinstance(name, str) and name.strip():
                check_results[name] = state
    counter = Counter(states)
    return {
        "check_state_counts": {state: counter[state] for state in sorted(counter)},
        "check_results": dict(sorted(check_results.items())),
    }


def _valid_pr_candidate(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        isinstance(value.get("number"), int)
        and isinstance(value.get("headRefName"), str)
        and bool(value.get("headRefName"))
        and isinstance(value.get("headRefOid"), str)
        and bool(value.get("headRefOid"))
    )


def _summarize_pr_candidate(value: dict[str, Any]) -> dict[str, Any]:
    check_summary = _check_rollup_summary(value.get("statusCheckRollup"))
    return {
        "number": value.get("number"),
        "url": value.get("url"),
        "state": value.get("state"),
        "base": value.get("baseRefName"),
        "head": value.get("headRefName"),
        "head_oid": value.get("headRefOid"),
        "is_draft": value.get("isDraft"),
        "mergeable": value.get("mergeable"),
        "review_decision": value.get("reviewDecision"),
        **check_summary,
    }


def _lookup_open_prs_for_branch(
    repo: Path,
    branch: str,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    if branch == "HEAD":
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": "detached HEAD; PR lookup by branch skipped",
        }

    pr_result = github_runner(
        repo,
        [
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "open",
            "--json",
            "number,url,state,baseRefName,headRefName,headRefOid,isDraft,mergeable,reviewDecision,statusCheckRollup",
        ],
    )
    if int(pr_result.get("returncode", 1)) != 0:
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": _truncate_reason(
                pr_result.get("stderr") or pr_result.get("stdout") or "PR lookup unavailable"
            ),
        }

    raw = str(pr_result.get("stdout", "")).strip()
    try:
        parsed = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": "PR lookup returned invalid JSON",
        }
    if not isinstance(parsed, list):
        return {
            "available": False,
            "ambiguous": False,
            "count": 0,
            "reason": "PR lookup returned non-list JSON",
        }

    candidates = [_summarize_pr_candidate(item) for item in parsed if _valid_pr_candidate(item)]
    if not candidates:
        reason = "no open PR for current branch" if not parsed else "PR lookup returned incomplete PR object"
        return {"available": False, "ambiguous": False, "count": 0, "reason": reason}
    if len(candidates) == 1:
        return {"available": True, "ambiguous": False, "count": 1, **candidates[0]}
    return {
        "available": True,
        "ambiguous": True,
        "count": len(candidates),
        "reason": "multiple open PRs for current branch",
        "candidates": [
            {"number": item.get("number"), "url": item.get("url"), "head_oid": item.get("head_oid")}
            for item in candidates
        ],
    }


def _situation_digest_info(parameters: dict[str, Any], receipt: Receipt) -> dict[str, Any]:
    digest = _grip_catalog_digest()
    expected_digest = parameters.get("expected_grip_catalog_sha256")
    stale_warning = None
    if expected_digest is not None:
        if not _is_hex_sha(expected_digest, lengths=(64,)):
            raise GripPreflightError(
                "expected_grip_catalog_sha256 must be a 64 character hex SHA when provided"
            )
        if expected_digest != digest:
            stale_warning = "expected grip catalog digest differs from runtime grip catalog digest"
    _check(
        receipt,
        SITUATION_CHECK_SNAPSHOT_DIGEST,
        "warn" if stale_warning else "pass",
        stale_warning or digest,
    )
    return {
        "generated_at": utc_now(),
        "grip_catalog_sha256": digest,
        "expected_grip_catalog_sha256": expected_digest,
        "stale_warning": stale_warning,
        "source_identity": {
            "module": __name__,
            "receipt_kind": GRIP_RECEIPT_KIND,
            "receipt_schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
            "grip_count": len(GRIP_SPECS),
        },
    }


def _build_situation_bureau_section(parameters: dict[str, Any]) -> dict[str, Any]:
    return {
        "task": _source_object(parameters, "bureau_task"),
        "run": _source_object(parameters, "bureau_run"),
        "blockers": _source_list(parameters, "blockers"),
    }


def _determine_situation_next_safe_grip(
    repo: Path,
    orientation: dict[str, Any],
    pr_summary: dict[str, Any],
) -> dict[str, Any]:
    if orientation["dirty"]:
        return {
            "name": "repo-orient",
            "parameters": {"repo": str(repo), "expected_branch": orientation["branch"]},
            "reason": "checkout is dirty; stay read-only until the dirty state is reviewed",
            "preconditions": ["same repo path", "same branch"],
            "does_not_establish": list(SITUATION_NON_CLAIMS),
        }
    if pr_summary.get("ambiguous"):
        return {
            "name": None,
            "parameters": None,
            "reason": "multiple open PRs match the current branch; choose the PR explicitly first",
            "preconditions": ["one PR target is selected explicitly"],
            "does_not_establish": list(SITUATION_NON_CLAIMS),
        }
    if pr_summary.get("available"):
        parameters: dict[str, Any] = {"repo": str(repo), "expected_head": orientation["head"]}
        review_decision = pr_summary.get("review_decision")
        if isinstance(review_decision, str):
            parameters["review_decision"] = review_decision
        check_results = pr_summary.get("check_results")
        if isinstance(check_results, dict) and check_results:
            parameters["check_results"] = check_results
        return {
            "name": "pr-check-readiness",
            "parameters": parameters,
            "reason": "open PR exists for current branch and checkout is clean",
            "preconditions": [
                "PR head is re-read before acting",
                "checks and reviews are re-read before acting",
            ],
            "does_not_establish": list(SITUATION_NON_CLAIMS),
        }
    return {
        "name": "worktree-orient",
        "parameters": {"repo": str(repo)},
        "reason": "no open PR was observed; orient worktrees before choosing an action target",
        "preconditions": ["worktree list remains readable"],
        "does_not_establish": list(SITUATION_NON_CLAIMS),
    }


def _run_situation(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    repo = _repo_path(parameters)
    if not repo.exists():
        _check(receipt, "repo_exists", "fail", str(repo))
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "repo_exists", "pass", str(repo))

    include_pr = _bool_parameter(parameters, "include_pr", True)
    orientation = _orient(repo, runner)
    _check(
        receipt,
        SITUATION_CHECK_REPO_STATE,
        "pass" if not orientation["dirty"] else "warn",
        f"branch={orientation['branch']} dirty={orientation['dirty']}",
    )
    digest_info = _situation_digest_info(parameters, receipt)

    pr_summary = (
        _lookup_open_prs_for_branch(repo, str(orientation["branch"]), github_runner)
        if include_pr
        else {"available": False, "ambiguous": False, "count": 0, "reason": "PR lookup skipped"}
    )
    _check(
        receipt,
        SITUATION_CHECK_PR_STATE,
        "pass" if pr_summary.get("available") and not pr_summary.get("ambiguous") else "warn",
        str(pr_summary.get("number") or pr_summary.get("reason")),
    )

    next_safe = _determine_situation_next_safe_grip(repo, orientation, pr_summary)
    _check(receipt, SITUATION_CHECK_NEXT_SAFE_GRIP, "pass", str(next_safe["name"]))

    return {
        "repo": orientation,
        "pr": pr_summary,
        "bureau": _build_situation_bureau_section(parameters),
        "jobs": _source_list(parameters, "jobs"),
        "snapshot_digest": digest_info,
        "next_safe_grip": next_safe,
        "non_claims": list(SITUATION_NON_CLAIMS),
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


def _github_repo_from_remote_url(value: str) -> str | None:
    text = value.strip()
    if text.endswith(".git"):
        text = text[:-4]
    if text.startswith("git@github.com:"):
        path = text.removeprefix("git@github.com:")
    else:
        marker = "github.com/"
        if marker not in text:
            return None
        path = text.split(marker, 1)[1]
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) < 2:
        return None
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts[:2]):
        return None
    return f"{parts[0]}/{parts[1]}"


def _scout_bool(parameters: dict[str, Any], name: str, default: bool = False) -> bool:
    value = parameters.get(name, default)
    if not isinstance(value, bool):
        raise GripPreflightError(f"{name} must be a boolean when provided")
    return value


def _scout_string_list(parameters: dict[str, Any], name: str) -> list[str]:
    value = parameters.get(name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise GripPreflightError(f"{name} must be a list of non-empty strings when provided")
    return [item.strip() for item in value]


def _scout_change(category: str, summary: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"category": category, "summary": summary, "details": details}


def _scout_pr_changes(pr_items: Any, *, branch: str, head: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    if not isinstance(pr_items, list):
        return changes
    for item in pr_items:
        if not isinstance(item, dict):
            continue
        number = item.get("number")
        title = item.get("title")
        pr_branch = item.get("headRefName")
        pr_head = item.get("headRefOid")
        merge_state = item.get("mergeStateStatus")
        decision = item.get("reviewDecision")
        if item.get("isDraft") is True:
            changes.append(_scout_change("pr_drift", "open PR is still draft", {"number": number, "title": title}))
        if isinstance(merge_state, str) and merge_state not in {"CLEAN", "UNKNOWN", ""}:
            changes.append(_scout_change("pr_drift", "open PR merge state changed", {"number": number, "merge_state": merge_state}))
        if pr_branch == branch and isinstance(pr_head, str) and pr_head and pr_head != head:
            changes.append(_scout_change("pr_drift", "local branch head differs from open PR head", {"number": number, "local_head": head, "pr_head": pr_head}))
        if isinstance(decision, str) and decision.upper() in {"CHANGES_REQUESTED", "REQUEST_CHANGES", "REVIEW_REQUIRED"}:
            changes.append(_scout_change("stale_review", "open PR review state requires attention", {"number": number, "review_decision": decision}))
    return changes


def _run_scout(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    if _scout_bool(parameters, "disabled", False):
        _check(receipt, "disable-switch", "pass", "scout disabled by parameter")
        return {"enabled": False, "changes": [], "change_count": 0, "non_claims": ["disabled scout performs no observation"]}

    repo = _repo_path(parameters)
    if not repo.exists() or not repo.is_dir():
        raise GripPreflightError(f"repo does not exist: {repo}")
    _check(receipt, "disable-switch", "pass", "scout enabled")
    _check(receipt, "no-mutation", "pass", "uses read-only git and gh observations only")

    _git(repo, runner, ["rev-parse", "--show-toplevel"])
    branch = _git(repo, runner, ["rev-parse", "--abbrev-ref", "HEAD"])["stdout"]
    head = _git(repo, runner, ["rev-parse", "HEAD"])["stdout"]
    origin_main_result = _git_optional(repo, runner, ["rev-parse", "origin/main"])
    origin_main = str(origin_main_result.get("stdout", "")).strip() if int(origin_main_result.get("returncode", 1)) == 0 else ""
    changes: list[dict[str, Any]] = []

    runtime_head = parameters.get("runtime_head")
    if runtime_head is not None:
        if not isinstance(runtime_head, str) or not re.fullmatch(r"[0-9a-f]{40,64}", runtime_head):
            raise GripPreflightError("runtime_head must be a 40-64 character lowercase hex string when provided")
        if origin_main and runtime_head != origin_main:
            changes.append(_scout_change("runtime_main_drift", "runtime head differs from origin/main", {"runtime_head": runtime_head, "origin_main": origin_main}))

    upstream = _git_optional(repo, runner, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    if int(upstream.get("returncode", 1)) == 0:
        upstream_name = str(upstream.get("stdout", "")).strip()
        counts = _git_optional(repo, runner, ["rev-list", "--left-right", "--count", f"{upstream_name}...HEAD"])
        if int(counts.get("returncode", 1)) == 0:
            parts = str(counts.get("stdout", "")).split()
            if len(parts) == 2 and all(part.isdigit() for part in parts):
                behind, ahead = (int(parts[0]), int(parts[1]))
                if ahead > 0:
                    changes.append(_scout_change("unpushed_branch", "local branch has commits not present upstream", {"branch": branch, "upstream": upstream_name, "ahead": ahead, "behind": behind}))

    remote = _git_optional(repo, runner, ["remote", "get-url", "origin"])
    github_repo = parameters.get("github_repo")
    if github_repo is None and int(remote.get("returncode", 1)) == 0:
        github_repo = _github_repo_from_remote_url(str(remote.get("stdout", "")))
    if github_repo is not None:
        if not isinstance(github_repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", github_repo):
            raise GripPreflightError("github_repo must have owner/repo form when provided")
        pr_result = _github(repo, github_runner, ["pr", "list", "--repo", github_repo, "--state", "open", "--json", "number,title,headRefName,headRefOid,isDraft,mergeStateStatus,reviewDecision,updatedAt"])
        changes.extend(_scout_pr_changes(_json_stdout(pr_result), branch=branch, head=head))

    for raw_path in _scout_string_list(parameters, "receipt_paths"):
        candidate = Path(raw_path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise GripPreflightError("receipt_paths entries must be relative paths inside the repository")
        if not (repo / candidate).is_file():
            changes.append(_scout_change("missing_receipt", "expected receipt file is missing", {"path": candidate.as_posix()}))

    _check(receipt, "only-changes", "pass", f"changes={len(changes)}")
    _check(receipt, "pr-and-runtime-drift", "pass", "scout evaluated PR, runtime, branch and receipt signals")
    return {
        "enabled": True,
        "change_count": len(changes),
        "changes": changes,
        "non_claims": [
            "does not mutate repositories",
            "does not refresh runtime state",
            "does not close or merge pull requests",
            "does not create receipts",
        ],
    }



def _mechanic_bool(parameters: dict[str, Any], name: str, default: bool = False) -> bool:
    value = parameters.get(name, default)
    if not isinstance(value, bool):
        raise GripPreflightError(f"{name} must be a boolean when provided")
    return value


def _relative_receipt_path(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GripPreflightError(f"{context}.receipt_path must be a non-empty relative path")
    candidate = Path(value.strip())
    if candidate.is_absolute() or ".." in candidate.parts:
        raise GripPreflightError(f"{context}.receipt_path must stay inside the repository")
    if ".git" in candidate.parts:
        raise GripPreflightError(f"{context}.receipt_path must not target .git")
    if not candidate.parts or candidate.parts[0] != "receipts":
        raise GripPreflightError(f"{context}.receipt_path must stay under receipts/")
    return candidate.as_posix()


def _bound_mapping(value: Any, *, context: str, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise GripPreflightError(f"{context}.{name} must be a non-empty object")
    return dict(value)


def _normal_action_name(item: dict[str, Any], *, index: int) -> str:
    raw = item.get("action")
    if not isinstance(raw, str) or not raw.strip():
        raise GripPreflightError(f"actions[{index}].action must be a non-empty string")
    action_name = raw.strip()
    alias = item.get("grip")
    if alias is not None:
        if not isinstance(alias, str) or not alias.strip():
            raise GripPreflightError(f"actions[{index}].grip alias must be a non-empty string when provided")
        if alias.strip() != action_name:
            raise GripPreflightError(f"actions[{index}].grip alias must match action")
    return action_name


def _validate_mechanic_target_matches_parameters(
    action_name: str,
    parameters: dict[str, Any],
    target: dict[str, Any],
    *,
    index: int,
) -> None:
    if action_name == "branch-publish":
        branch = parameters.get("branch")
        if target.get("branch") != branch:
            raise GripPreflightError(f"actions[{index}].target.branch must match parameters.branch")
        remote = target.get("remote")
        if remote is not None and remote != "origin":
            raise GripPreflightError(f"actions[{index}].target.remote must be origin for branch-publish")
    if action_name == "pr-create-or-update":
        for key in ("base", "head", "branch"):
            if key in target and key in parameters and target.get(key) != parameters.get(key):
                raise GripPreflightError(f"actions[{index}].target.{key} must match parameters.{key}")


def _mechanic_actions(parameters: dict[str, Any]) -> list[dict[str, Any]]:
    value = parameters.get("actions")
    if not isinstance(value, list) or not value:
        raise GripPreflightError("actions must be a non-empty list")
    if len(value) > MECHANIC_MAX_ACTIONS:
        raise GripPreflightError(f"actions may contain at most {MECHANIC_MAX_ACTIONS} entries")
    actions: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise GripPreflightError(f"actions[{index}] must be an object")
        action_name = _normal_action_name(item, index=index)
        if action_name == "mechanic-loop" or action_name in GRIP_SURFACE_CAPTAIN_ONLY:
            raise GripPreflightError(f"actions[{index}].action is not dispatchable by mechanic-loop: {action_name}")
        if action_name in CAPTAIN_HIGH_IMPACT_ACTIONS:
            raise GripPreflightError(f"actions[{index}].action requires Captain: {action_name}")
        if action_name not in MECHANIC_NORMAL_GRIPS:
            raise GripPreflightError(f"actions[{index}].action is not a normal mechanic action: {action_name}")
        spec = GRIP_SPECS.get(action_name)
        if spec is None:
            raise GripPreflightError(f"actions[{index}].action is not dispatchable by mechanic-loop: {action_name}")
        parameters_value = item.get("parameters", {})
        if not isinstance(parameters_value, dict):
            raise GripPreflightError(f"actions[{index}].parameters must be an object when provided")
        allow_mutation = item.get("allow_mutation", False)
        if not isinstance(allow_mutation, bool):
            raise GripPreflightError(f"actions[{index}].allow_mutation must be a boolean when provided")
        target = _bound_mapping(item.get("target"), context=f"actions[{index}]", name="target")
        scope = _bound_mapping(item.get("scope"), context=f"actions[{index}]", name="scope")
        receipt_path = _relative_receipt_path(item.get("receipt_path"), context=f"actions[{index}]")
        risk_level = item.get("risk_level", "normal")
        if risk_level != "normal":
            raise GripPreflightError(f"actions[{index}].risk_level must be normal for mechanic actions")
        forbidden = scope.get("forbidden_effects")
        if forbidden is not None and (not isinstance(forbidden, list) or not all(isinstance(entry, str) for entry in forbidden)):
            raise GripPreflightError(f"actions[{index}].scope.forbidden_effects must be a list of strings when provided")
        _validate_mechanic_target_matches_parameters(action_name, parameters_value, target, index=index)
        actions.append(
            {
                "index": index,
                "action": action_name,
                "grip": action_name,
                "parameters": dict(parameters_value),
                "allow_mutation": allow_mutation,
                "target": target,
                "scope": scope,
                "receipt_path": receipt_path,
                "risk_level": risk_level,
                "effect": spec.effect,
                "envelope": {
                    "schema_version": 1,
                    "role": "mechanic",
                    "action": action_name,
                    "target": target,
                    "scope": scope,
                    "risk_level": "normal",
                    "requires_captain": False,
                    "receipt_required": True,
                    "receipt_path": receipt_path,
                    "created_at": utc_now(),
                },
            }
        )
    return actions


def _mechanic_record_sha256(record: dict[str, Any]) -> str:
    return sha256_json({key: value for key, value in record.items() if key != "receipt_sha256"})


def _mechanic_child_error_record(
    action: dict[str, Any],
    child: Any,
    *,
    error: str,
) -> dict[str, Any]:
    mechanic_receipt = {
        "schema_version": 1,
        "role": "mechanic",
        "action": action["action"],
        "target": action["target"],
        "scope": action["scope"],
        "status": "blocked",
        "child_receipt_error": error,
        "receipt_path": action["receipt_path"],
        "does_not_establish": [
            "merge_readiness",
            "runtime_correctness",
            "review_completeness",
            "deployment_safety",
        ],
    }
    mechanic_receipt["receipt_sha256"] = _mechanic_record_sha256(mechanic_receipt)
    return {
        "index": action["index"],
        "action": action["action"],
        "grip": action["grip"],
        "effect": action["effect"],
        "target": action["target"],
        "scope": action["scope"],
        "risk_level": action["risk_level"],
        "allow_mutation": action["allow_mutation"],
        "receipt_path": action["receipt_path"],
        "receipt_sha256": mechanic_receipt["receipt_sha256"],
        "child_receipt_sha256": None,
        "receipt_status": "blocked",
        "receipt_phase": None,
        "receipt_error": error,
        "envelope": action["envelope"],
        "mechanic_receipt": mechanic_receipt,
        "receipt": child.get("receipt") if isinstance(child, dict) else None,
        "output": child.get("output", {}) if isinstance(child, dict) else {},
    }


def _run_mechanic_loop(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
    github_runner: GithubRunner,
) -> dict[str, Any]:
    actions = _mechanic_actions(parameters)
    continue_on_blocked = _mechanic_bool(parameters, "continue_on_blocked", False)
    _check(receipt, "normal-grips-only", "pass", ", ".join(action["action"] for action in actions))

    records: list[dict[str, Any]] = []
    stopped_after: int | None = None
    stopped_at_action: str | None = None
    any_child_not_passed = False
    for action in actions:
        child = run_grip(
            str(action["grip"]),
            dict(action["parameters"]),
            allow_mutation=bool(action["allow_mutation"]),
            command_runner=runner,
            github_runner=github_runner,
        )
        raw_child_receipt = child.get("receipt") if isinstance(child, dict) else None
        child_status: str | None = None
        child_receipt_sha: str | None = None
        child_receipt = raw_child_receipt if isinstance(raw_child_receipt, dict) else None
        child_error: str | None = None
        if child_receipt is None:
            child_error = f"actions[{action['index']}].child receipt is missing or invalid"
        else:
            raw_child_status = child_receipt.get("status")
            if not isinstance(raw_child_status, str):
                child_error = f"actions[{action['index']}].child receipt status is missing or invalid"
            else:
                child_status = raw_child_status
            raw_child_receipt_sha = child_receipt.get("receipt_sha256")
            if not _is_sha256_hex(raw_child_receipt_sha):
                child_error = f"actions[{action['index']}].child receipt hash is missing or invalid"
            else:
                child_receipt_sha = raw_child_receipt_sha
        if child_error is not None:
            records.append(_mechanic_child_error_record(action, child, error=child_error))
            any_child_not_passed = True
            if stopped_after is None:
                stopped_after = action["index"]
                stopped_at_action = str(action["action"])
            if not continue_on_blocked:
                break
            continue
        assert child_receipt is not None
        assert child_status is not None
        assert child_receipt_sha is not None
        mechanic_receipt = {
            "schema_version": 1,
            "role": "mechanic",
            "action": action["action"],
            "target": action["target"],
            "scope": action["scope"],
            "status": child_status,
            "child_receipt_sha256": child_receipt_sha,
            "receipt_path": action["receipt_path"],
            "does_not_establish": [
                "merge_readiness",
                "runtime_correctness",
                "review_completeness",
                "deployment_safety",
            ],
        }
        mechanic_receipt["receipt_sha256"] = _mechanic_record_sha256(mechanic_receipt)
        record = {
            "index": action["index"],
            "action": action["action"],
            "grip": action["grip"],
            "effect": action["effect"],
            "target": action["target"],
            "scope": action["scope"],
            "risk_level": action["risk_level"],
            "allow_mutation": action["allow_mutation"],
            "receipt_path": action["receipt_path"],
            "receipt_sha256": mechanic_receipt["receipt_sha256"],
            "child_receipt_sha256": child_receipt_sha,
            "receipt_status": child_status,
            "receipt_phase": child_receipt.get("phase"),
            "envelope": action["envelope"],
            "mechanic_receipt": mechanic_receipt,
            "receipt": child_receipt,
            "output": child.get("output", {}),
        }
        records.append(record)
        if child_status != "passed":
            any_child_not_passed = True
            if stopped_after is None:
                stopped_after = action["index"]
                stopped_at_action = str(action["action"])
            if not continue_on_blocked:
                break

    scope_visible = all(isinstance(record.get("target"), dict) and isinstance(record.get("scope"), dict) for record in records)
    receipt_bound = all(_is_sha256_hex(record.get("receipt_sha256")) for record in records)
    _check(receipt, "scope-visible", "pass" if scope_visible else "fail", f"actions={len(records)}")
    _check(receipt, "receipt-per-grip", "pass" if receipt_bound else "fail", f"actions={len(records)}")
    return {
        "schema_version": 1,
        "profile": "mechanic",
        "normal_action_allowlist": sorted(MECHANIC_NORMAL_GRIPS),
        "forbidden_effects": list(MECHANIC_FORBIDDEN_EFFECTS),
        "requested_action_count": len(actions),
        "executed_action_count": len(records),
        "status": "blocked" if any_child_not_passed else "passed",
        "receipt_status": "blocked" if any_child_not_passed else "passed",
        "complete": not any_child_not_passed and len(records) == len(actions),
        "stopped_after": stopped_after,
        "stopped_at_index": stopped_after,
        "stopped_at_action": stopped_at_action,
        "continue_on_blocked": continue_on_blocked,
        "actions": records,
        "non_claims": [
            "does not expose generic shell execution",
            "does not run Captain-only high-impact actions",
            "does not bypass child grip receipts",
        ],
    }


def _captain_actions(parameters: dict[str, Any]) -> list[dict[str, Any]]:
    value = parameters.get("actions")
    if not isinstance(value, list) or not value:
        raise GripPreflightError("actions must be a non-empty list")
    if len(value) > CAPTAIN_MAX_ACTIONS:
        raise GripPreflightError(f"actions may contain at most {CAPTAIN_MAX_ACTIONS} entries")
    actions: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise GripPreflightError(f"actions[{index}] must be an object")
        action_name = _normal_action_name(item, index=index)
        if action_name not in CAPTAIN_HIGH_IMPACT_ACTIONS:
            raise GripPreflightError(f"actions[{index}].action must be an explicit high-impact Captain action")
        if item.get("high_impact") is not True:
            raise GripPreflightError(f"actions[{index}].high_impact must be true")
        target = _bound_mapping(item.get("target"), context=f"actions[{index}]", name="target")
        scope = _bound_mapping(item.get("scope"), context=f"actions[{index}]", name="scope")
        risk = _bound_mapping(item.get("risk"), context=f"actions[{index}]", name="risk")
        recovery_path = risk.get("recovery_path")
        irreversibility = risk.get("irreversibility")
        if irreversibility is not None and irreversibility not in {"reversible", "irreversible"}:
            raise GripPreflightError(f"actions[{index}].risk.irreversibility must be reversible or irreversible")
        if not isinstance(recovery_path, str) or not recovery_path.strip():
            if not isinstance(irreversibility, str) or not irreversibility.strip():
                raise GripPreflightError(f"actions[{index}].risk requires recovery_path or irreversibility")
        if irreversibility == "irreversible" and not isinstance(item.get("irreversibility_record"), dict):
            raise GripPreflightError(f"actions[{index}].irreversibility_record is required for irreversible actions")
        target_change_required = item.get("target_change_required", False)
        if not isinstance(target_change_required, bool):
            raise GripPreflightError(f"actions[{index}].target_change_required must be a boolean when provided")
        target_change = item.get("target_change")
        if target_change_required and not isinstance(target_change, dict):
            raise GripPreflightError(f"actions[{index}].target_change record is required")
        if target_change is not None and not isinstance(target_change, dict):
            raise GripPreflightError(f"actions[{index}].target_change must be an object or null")
        receipt_path = _relative_receipt_path(item.get("receipt_path"), context=f"actions[{index}]")
        actions.append(
            {
                "index": index,
                "action": action_name,
                "high_impact": True,
                "target": target,
                "scope": scope,
                "risk": risk,
                "target_change": target_change,
                "receipt_path": receipt_path,
                "envelope": {
                    "schema_version": 1,
                    "role": "captain",
                    "action": action_name,
                    "high_impact": True,
                    "target": target,
                    "scope": scope,
                    "target_change": target_change,
                    "risk": risk,
                    "receipt_path": receipt_path,
                    "created_at": utc_now(),
                },
            }
        )
    return actions


def _run_captain_preflight(
    spec: GripSpec,
    parameters: dict[str, Any],
    receipt: Receipt,
    runner: CommandRunner,
) -> dict[str, Any]:
    actions = _captain_actions(parameters)
    status_projection_fresh = _mechanic_bool(parameters, "status_projection_fresh", False)
    allow_execution = _mechanic_bool(parameters, "allow_execution", False)
    blocked_reasons: list[str] = []
    if not status_projection_fresh:
        blocked_reasons.append("fresh_status_projection_unavailable")
    if not allow_execution:
        blocked_reasons.append("privileged_execution_disabled")
    _check(receipt, "high-impact-marked", "pass", ", ".join(action["action"] for action in actions))
    _check(receipt, "recovery-or-irreversibility", "pass", "risk records include recovery or irreversibility")
    _check(receipt, "target-change-record", "pass", "target changes are explicit or null")
    aggregate_status = "blocked" if blocked_reasons else "passed"
    return {
        "schema_version": 1,
        "profile": "captain",
        "decision": "blocked" if blocked_reasons else "plan_only",
        "status": aggregate_status,
        "receipt_status": aggregate_status,
        "blocked_reasons": blocked_reasons,
        "high_impact_action_allowlist": sorted(CAPTAIN_HIGH_IMPACT_ACTIONS),
        "actions": actions,
        "does_not_establish": [
            "automatic_merge_authority",
            "automatic_deploy_authority",
            "service_restart_safety",
            "fleet_mutation_safety",
            "cleanup_safety",
            "runtime_correctness",
            "semantic_correctness",
            "review_completeness",
        ],
        "non_claims": [
            "does not execute privileged mutations",
            "does not treat CI as production safety",
            "does not treat review approval as semantic correctness",
        ],
    }


_RUNNERS = {
    "repo_orient": _run_repo_orient,
    "pr_check_readiness": _run_pr_check_readiness,
    "worktree_orient": _run_worktree_orient,
    "post_merge_sync": _run_post_merge_sync,
    "situation": _run_situation,
    "scout": _run_scout,
    "mechanic_loop": _run_mechanic_loop,
    "captain_preflight": _run_captain_preflight,
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
        if spec.uses_github:
            output = action(
                spec,
                parameters,
                receipt,
                command,
                github_runner or _default_github_runner,
            )
        else:
            output = action(spec, parameters, receipt, command)
        final_status = "passed"
        if isinstance(output, dict):
            requested_status = output.get("receipt_status")
            if requested_status in {"passed", "blocked", "failed"}:
                final_status = requested_status
        return _finish(receipt, final_status, "action", output)
    except GripPreflightError as exc:
        return _finish(receipt, "blocked", "preflight", {"error": str(exc)})
    except GripActionError as exc:
        return _finish(receipt, "failed", "action", {"error": str(exc)})


def _surface_availability(spec: GripSpec, profile: str) -> dict[str, Any]:
    if spec.name not in GRIP_SURFACE_ALLOWLIST:
        return {
            "available": False,
            "reason": "not exposed by grip surface allowlist",
            "requires_allow_mutation": False,
        }
    if spec.name in GRIP_SURFACE_CAPTAIN_ONLY and profile != "captain":
        return {
            "available": False,
            "reason": f"profile {profile} cannot run captain-only grips",
            "requires_allow_mutation": False,
        }
    if spec.effect == MUTATING and profile not in GRIP_SURFACE_MUTATING_PROFILES:
        return {
            "available": False,
            "reason": f"profile {profile} cannot run mutating grips",
            "requires_allow_mutation": True,
        }
    return {
        "available": True,
        "reason": "allowed by current grip surface profile",
        "requires_allow_mutation": spec.effect == MUTATING,
    }


def _surface_grip_contract(spec: GripSpec, profile: str) -> dict[str, Any]:
    availability = _surface_availability(spec, profile)
    required = ", ".join(spec.required_parameters) or "none"
    return {
        "name": spec.name,
        "version": spec.version,
        "summary": spec.summary,
        "purpose": spec.summary,
        "target": GRIP_SURFACE_TARGETS.get(spec.name, "narrow Grabowski grip target"),
        "scope": "observation only" if spec.effect == READ_ONLY else "bounded write through a named grip runner",
        "effect": spec.effect,
        "effect_class": "read-only" if spec.effect == READ_ONLY else "mutating",
        "risk": "low" if spec.effect == READ_ONLY else "medium",
        "recovery_path": GRIP_SURFACE_RECOVERY_PATHS[spec.effect],
        "preconditions": [
            f"required parameters: {required}",
            "grip name is present in GRIP_SURFACE_ALLOWLIST",
            "mutating grips require allow_mutation=true and an eligible profile",
        ],
        "required_parameters": list(spec.required_parameters),
        "acceptance_ids": list(spec.acceptance_ids),
        "uses_github": spec.uses_github,
        "profile": profile,
        "availability": availability,
        "expected_receipt_shape": {
            "kind": GRIP_RECEIPT_KIND,
            "schema_version": GRIP_RECEIPT_SCHEMA_VERSION,
            "required_top_level_fields": [
                "kind",
                "schema_version",
                "grip",
                "parameters_sha256",
                "status",
                "phase",
                "checks",
                "output",
            ],
            "mutating_receipt_contract": "mutating grips must return a blocked, failed or passed receipt; they may not bypass run_grip",
        },
    }


def _validate_surface_profile(profile: str) -> str:
    if profile not in GRIP_SURFACE_PROFILES:
        raise GripPreflightError(
            f"unknown grip surface profile: {profile}; expected one of {sorted(GRIP_SURFACE_PROFILES)}"
        )
    return profile


def list_grips(profile: str = "operator") -> list[dict[str, Any]]:
    profile = _validate_surface_profile(profile)
    return [
        _surface_grip_contract(spec, profile)
        for spec in sorted(GRIP_SPECS.values(), key=lambda item: item.name)
        if spec.name in GRIP_SURFACE_ALLOWLIST
    ]


def grip_list(profile: str = "operator") -> dict[str, Any]:
    profile = _validate_surface_profile(profile)
    return {
        "profile": profile,
        "allowlist": sorted(GRIP_SURFACE_ALLOWLIST),
        "grips": list_grips(profile),
        "non_claims": [
            "does not expose generic shell execution",
            "does not grant mutation without allow_mutation",
            "does not replace receipt review",
        ],
    }


def _blocked_surface_receipt(name: str, parameters: dict[str, Any], reason: str) -> dict[str, Any]:
    spec = GripSpec(
        name=name,
        version="0",
        summary="grip surface dispatch rejected",
        effect=READ_ONLY,
        required_parameters=(),
        acceptance_ids=("grip-run-allowlist",),
        runner="surface_reject",
    )
    receipt = _new_receipt(spec, parameters)
    _check(receipt, "surface_allowlist", "fail", reason)
    return _finish(receipt, "blocked", "preflight", {"error": reason})


def grip_run(
    name: str,
    parameters: dict[str, Any] | None = None,
    *,
    profile: str = "operator",
    allow_mutation: bool = False,
    command_runner: CommandRunner | None = None,
    github_runner: GithubRunner | None = None,
) -> dict[str, Any]:
    parameters = dict(parameters or {})
    try:
        profile = _validate_surface_profile(profile)
    except GripPreflightError as exc:
        return _blocked_surface_receipt(name, parameters, str(exc))
    spec = GRIP_SPECS.get(name)
    if spec is None or name not in GRIP_SURFACE_ALLOWLIST:
        return _blocked_surface_receipt(name, parameters, f"grip is not exposed by surface allowlist: {name}")
    availability = _surface_availability(spec, profile)
    if not availability["available"]:
        return _blocked_surface_receipt(name, parameters, str(availability["reason"]))
    return run_grip(
        name,
        parameters,
        allow_mutation=allow_mutation,
        command_runner=command_runner,
        github_runner=github_runner,
    )

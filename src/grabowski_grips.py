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
    _check(
        receipt,
        "work_branch",
        "pass" if branch_is_work else "fail",
        f"branch={orientation['branch']}",
    )
    _check(
        receipt,
        "upstream",
        "pass" if upstream_set else "warn",
        orientation["upstream"] or "no upstream configured",
    )
    _check(
        receipt,
        "cleanliness",
        "pass" if clean_ok else "fail",
        "clean required" if clean_required else "clean not required",
    )
    ready = branch_is_work and upstream_set and clean_ok
    return {
        "ready": ready,
        "orientation": orientation,
        "protected_branches": protected,
        "require_clean": clean_required,
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

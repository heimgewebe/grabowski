from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time
from typing import Any

import grabowski_capabilities as capabilities
import grabowski_mcp as base
import grabowski_operator_core as operator

mcp = operator.mcp
HOME = operator.HOME
EVIDENCE_ROOT = operator.EVIDENCE_ROOT
PROTECTED_BRANCHES = operator.PROTECTED_BRANCHES
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
MAX_OUTPUT_BYTES = operator.MAX_OUTPUT_BYTES


def _runtime_contract_snapshot() -> dict[str, Any]:
    manifest_path = base.DEPLOYMENT_MANIFEST
    try:
        if manifest_path.is_file() and manifest_path.stat().st_size <= base.MAX_MANIFEST_BYTES:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            contract = manifest.get("entrypoint_contract")
            if isinstance(contract, dict):
                return {"source": str(manifest_path), "contract": contract}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    repository_contract = Path(__file__).resolve().parents[1] / "config" / "runtime-entrypoint.json"
    try:
        contract = json.loads(repository_contract.read_text(encoding="utf-8"))
        if isinstance(contract, dict):
            return {"source": str(repository_contract), "contract": contract}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {"source": None, "contract": {}}


def _git_state(repo: Path) -> dict[str, Any]:
    def run(*arguments: str) -> tuple[int, str]:
        completed = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=operator._safe_environment(),
        )
        return completed.returncode, completed.stdout.strip()
    head_code, head = run("rev-parse", "HEAD")
    branch_code, branch = run("branch", "--show-current")
    status_code, status = run("status", "--porcelain")
    return {
        "path": str(repo),
        "head": head if head_code == 0 else None,
        "branch": branch if branch_code == 0 else None,
        "dirty": bool(status) if status_code == 0 else None,
    }


def _worktree_context(runtime_head: str | None) -> dict[str, Any]:
    repository = HOME / "repos" / "grabowski"
    if not repository.is_dir():
        return {"repository": str(repository), "exists": False, "worktrees": []}
    completed = subprocess.run(
        ["git", "-C", str(repository), "worktree", "list", "--porcelain"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=operator._safe_environment(),
    )
    worktrees: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in completed.stdout.splitlines() + [""]:
        if not line:
            if current:
                current["matches_runtime"] = bool(runtime_head and current.get("head") == runtime_head)
                worktrees.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            current["path"] = value
        elif key == "HEAD":
            current["head"] = value
        elif key == "branch":
            current["branch"] = value.removeprefix("refs/heads/")
        elif key in {"detached", "bare", "prunable"}:
            current[key] = True
    canonical = next((item for item in worktrees if item.get("path") == str(repository)), None)
    return {
        "repository": str(repository),
        "exists": True,
        "command_returncode": completed.returncode,
        "canonical_checkout": canonical,
        "canonical_matches_runtime": bool(canonical and canonical.get("matches_runtime")),
        "runtime_matching_worktrees": [item for item in worktrees if item.get("matches_runtime")],
        "worktrees": worktrees,
    }


def _validate_branch_name(repo: Path, branch: str) -> str:
    if not branch or len(branch) > 200:
        raise ValueError("Invalid branch name")
    completed = subprocess.run(
        ["git", "-C", str(repo), "check-ref-format", "--branch", branch],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=operator._safe_environment(),
    )
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "Invalid branch name")
    return branch


@mcp.tool(name="grabowski_context", annotations=READ_ONLY)
def grabowski_context(profile: str = "concise") -> dict[str, Any]:
    """Return a task-oriented live operator context and explicit drift findings."""
    snapshot = _runtime_contract_snapshot()
    contract = snapshot["contract"]
    expected_tools = contract.get("expected_tools", [])
    if not isinstance(expected_tools, list):
        expected_tools = []
    records = capabilities.capability_records(expected_tools)
    classification = capabilities.classify_contract(expected_tools)
    deployment = base._deployment_metadata()
    runtime_head = deployment.get("repo_head")
    worktrees = _worktree_context(runtime_head if isinstance(runtime_head, str) else None)
    known_gaps: list[str] = []
    for key, values in classification.items():
        if values:
            known_gaps.append(f"{key}: {', '.join(values)}")
    if not expected_tools:
        known_gaps.append("runtime entrypoint contract is unavailable")
    known_gaps.append("the connector's frozen client-side tool snapshot is not observable from the local runtime")
    policy = base._load_policy()
    active_profile = base._active_profile(policy)
    return {
        "schema_version": capabilities.CONTEXT_SCHEMA_VERSION,
        "profile": profile,
        "generated_at_unix": int(time.time()),
        "runtime": {
            "service": "grabowski-mcp",
            "contract_source": snapshot["source"],
            "expected_tools": expected_tools,
            "deployment": deployment,
        },
        "policy": {
            "mode": policy.get("mode"),
            "active_profile": active_profile["name"],
            "access_profiles": sorted(policy.get("profiles", {})),
            "capabilities": sorted(base._effective_capabilities(policy)),
            "read_roots": base._profile_values(policy, "read_roots"),
            "write_roots": base._profile_values(policy, "write_roots"),
            "write_excluded_roots": (
                base._profile_values(policy, "write_excluded_roots") or []
            ),
            "secret_roots": base._secret_root_values(policy),
            "browser_profile_roots": base._browser_profile_root_values(policy),
            "secret_export_roots": base._secret_export_root_values(policy),
            "forbidden_capabilities": policy.get("forbidden_capabilities", []),
            "kill_switch": base._kill_switch_state(),
            "audit": base._verify_audit_log(base.AUDIT_LOG),
        },
        "capabilities": capabilities.filter_capabilities(records, profile),
        "classification": classification,
        "checkout": worktrees,
        "drift": {
            "catalog_matches_contract": not any(classification.values()),
            "canonical_checkout_matches_runtime": worktrees.get("canonical_matches_runtime"),
            "runtime_matching_worktree_count": len(worktrees.get("runtime_matching_worktrees", [])),
            "connector_snapshot_observable": False,
        },
        "known_gaps": known_gaps,
    }


@mcp.tool(name="grabowski_git_branch", annotations=MUTATING)
def grabowski_git_branch(repo: str, action: str, branch: str, start_point: str = "HEAD") -> dict[str, Any]:
    """Create or switch one local Git branch through a typed operation."""
    operator._require_operator_mutation("git_cli")
    path = Path(repo).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    if path == EVIDENCE_ROOT or EVIDENCE_ROOT in path.parents:
        raise PermissionError("Git mutation of immutable evidence is blocked.")
    name = _validate_branch_name(path, branch)
    allowed = {"create", "switch", "create-and-switch"}
    if action not in allowed:
        raise ValueError(f"action must be one of {sorted(allowed)}")
    if action != "switch" and name in PROTECTED_BRANCHES:
        raise PermissionError("Creation of a protected main branch is blocked.")
    if not start_point or len(start_point) > 200 or start_point.startswith("-"):
        raise ValueError("Invalid start point")
    before = _git_state(path)
    if action == "create":
        arguments = ["branch", name, start_point]
    elif action == "switch":
        arguments = ["switch", name]
    else:
        arguments = ["switch", "-c", name, start_point]
    result = operator._run(
        ["git", "-C", str(path), *arguments],
        cwd=path,
        timeout_seconds=60,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    after = _git_state(path)
    record = {
        "timestamp_unix": int(time.time()),
        "operation": "git-branch",
        "action": action,
        "repo": str(path),
        "branch": name,
        "start_point": start_point,
        "returncode": result["returncode"],
        "before": before,
        "after": after,
    }
    if result["returncode"] == 0:
        base._append_audit(record)
    return {"result": result, "audit": record}

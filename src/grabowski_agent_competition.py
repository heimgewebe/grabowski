from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
from typing import Any

import grabowski_agent_workspace as workspace
import grabowski_operator_core as operator
import grabowski_tasks as tasks

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

COMPETITION_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_AGENT_COMPETITION_ROOT",
        str(operator.STATE_DIR / "agent-competitions"),
    )
).expanduser()
RUNNER = Path(__file__).resolve().parent.parent / "tools" / "external_programming_candidate.py"
PROVIDERS = {"claude", "agy"}
MODES = {"competitor", "contrast"}
TASK_KINDS = {"code", "docs", "analysis", "operations"}
NOVELTY = {"low", "medium", "high"}
RISK_FLAGS = {
    "security", "runtime", "deployment", "schema", "concurrency", "data_migration",
    "privilege", "external_api", "cross_repo", "destructive", "user_data",
}
SENSITIVE_PARTS = {
    ".env", "secret", "secrets", "credential", "credentials", "token", "tokens",
    "private_key", "id_rsa", "id_ed25519", "cookies", "login data", "web data",
}
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
MAX_CONTEXT_BYTES = 500_000
MAX_CONTEXT_FILE_BYTES = 120_000
MAX_RECEIPT_BYTES = 2_000_000


class AgentCompetitionError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _strict_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise AgentCompetitionError(f"{label} must be boolean")
    return value


def _competition_id(provider: str, mode: str, task_sha256: str, request_id: str) -> str:
    request_digest = _sha256_bytes(request_id.encode("utf-8"))[:10]
    return f"gac-{provider}-{mode}-{task_sha256[:10]}-{request_digest}"


def _competition_root() -> Path:
    root = COMPETITION_ROOT.expanduser()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
        raise AgentCompetitionError("agent competition root must be a private non-symlink directory")
    return root.resolve(strict=True)


def _competition_dir(identifier: str) -> Path:
    clean = workspace._required_string(identifier, "competition_id", max_length=100)
    if re.fullmatch(r"gac-(claude|agy)-(competitor|contrast)-[0-9a-f]{10}-[0-9a-f]{10}", clean) is None:
        raise AgentCompetitionError("competition_id has an invalid format")
    return _competition_root() / clean


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    parent_metadata = path.parent.lstat()
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_mode & 0o077:
        raise AgentCompetitionError("state parent must be a private non-symlink directory")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise AgentCompetitionError(f"state file already exists: {path.name}") from exc
        temporary.unlink()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_private_json(path: Path, *, label: str, max_bytes: int = MAX_RECEIPT_BYTES) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise AgentCompetitionError(f"{label} does not exist") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AgentCompetitionError(f"{label} must be one regular private file")
    if metadata.st_size > max_bytes:
        raise AgentCompetitionError(f"{label} exceeds byte limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentCompetitionError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise AgentCompetitionError(f"{label} is not a JSON object")
    return value


def _git(repo: Path, args: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "diff.external=", *args],
        cwd=repo,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/false", "GIT_CONFIG_NOSYSTEM": "1"},
    )


def _normalize_relative(value: Any, *, label: str) -> str:
    clean = workspace._required_string(value, label, max_length=500)
    path = PurePosixPath(clean)
    if path.is_absolute() or clean.startswith("./") or any(part in {"", ".", ".."} for part in path.parts):
        raise AgentCompetitionError(f"{label} must be a normalized relative path")
    return path.as_posix()


def _path_in_scope(path: str, roots: list[str]) -> bool:
    item = PurePosixPath(path)
    return any(item == PurePosixPath(root) or PurePosixPath(root) in item.parents for root in roots)


def _path_is_sensitive(path: str) -> bool:
    lower = path.lower()
    return any(part in lower for part in SENSITIVE_PARTS)


def _repository(repository: str, expected_head: str) -> tuple[Path, str]:
    repo = Path(workspace._required_string(repository, "repository", max_length=4096)).expanduser().resolve(strict=True)
    top = _git(repo, ["rev-parse", "--show-toplevel"])
    if top.returncode != 0 or Path(top.stdout.decode().strip()).resolve(strict=True) != repo:
        raise AgentCompetitionError("repository must be a Git worktree root")
    head = workspace._required_string(expected_head, "expected_head", max_length=40).lower()
    if SHA40_RE.fullmatch(head) is None:
        raise AgentCompetitionError("expected_head must be a full lowercase Git SHA")
    observed = _git(repo, ["rev-parse", "HEAD^{commit}"])
    if observed.returncode != 0 or observed.stdout.decode().strip().lower() != head:
        raise AgentCompetitionError("repository HEAD does not match expected_head")
    status = _git(repo, ["status", "--porcelain=v1", "-z", "--untracked-files=normal"])
    if status.returncode != 0 or status.stdout:
        raise AgentCompetitionError("repository must be clean before external candidate generation")
    return repo, head


def _context(repo: Path, context_paths: list[str], allowed: list[str], forbidden: list[str]) -> list[dict[str, Any]]:
    if not isinstance(context_paths, list) or not context_paths or len(context_paths) > 40:
        raise AgentCompetitionError("context_paths must contain between 1 and 40 entries")
    result: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    for index, raw in enumerate(context_paths):
        relative = _normalize_relative(raw, label=f"context_paths[{index}]")
        if relative in seen:
            raise AgentCompetitionError("context_paths contains duplicates")
        seen.add(relative)
        if not _path_in_scope(relative, allowed) or _path_in_scope(relative, forbidden):
            raise AgentCompetitionError(f"context path is outside declared scope: {relative}")
        if _path_is_sensitive(relative):
            raise AgentCompetitionError(f"sensitive-looking context path is not exportable: {relative}")
        target = repo.joinpath(*PurePosixPath(relative).parts)
        try:
            metadata = target.lstat()
        except FileNotFoundError as exc:
            raise AgentCompetitionError(f"context path does not exist: {relative}") from exc
        if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AgentCompetitionError(f"context path must be one regular non-symlink file: {relative}")
        if metadata.st_size > MAX_CONTEXT_FILE_BYTES:
            raise AgentCompetitionError(f"context file exceeds per-file byte limit: {relative}")
        raw_bytes = target.read_bytes()
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AgentCompetitionError(f"context file is not UTF-8 text: {relative}") from exc
        redact = getattr(operator, "_redact", None)
        if callable(redact) and redact(text) != text:
            raise AgentCompetitionError(f"context file contains secret-like content: {relative}")
        total += len(raw_bytes)
        if total > MAX_CONTEXT_BYTES:
            raise AgentCompetitionError("combined context exceeds byte limit")
        result.append({"path": relative, "sha256": _sha256_bytes(raw_bytes), "text": text})
    return result


def _scope(values: list[str] | None, *, label: str, nonempty: bool) -> list[str]:
    if not isinstance(values, list) or (nonempty and not values) or len(values) > 50:
        raise AgentCompetitionError(f"{label} has an invalid size")
    normalized = [_normalize_relative(item, label=f"{label}[{index}]") for index, item in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        raise AgentCompetitionError(f"{label} contains duplicates")
    return normalized


def _validated_manifest(identifier: str) -> dict[str, Any]:
    manifest = _load_private_json(_competition_dir(identifier) / "manifest.json", label="competition manifest")
    required = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "provider", "mode", "repository", "expected_head", "task_sha256", "packet_sha256",
        "start_intent_sha256", "task_id", "task_unit", "created_at", "authority",
        "automatic_apply", "manifest_sha256",
    }
    if set(manifest) != required:
        raise AgentCompetitionError("competition manifest shape is invalid")
    observed_hash = manifest["manifest_sha256"]
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if not isinstance(observed_hash, str) or SHA256_RE.fullmatch(observed_hash) is None or observed_hash != _sha256_json(unsigned):
        raise AgentCompetitionError("competition manifest hash is invalid")
    if manifest["schema_version"] != 1 or manifest["kind"] != "external_programming_competition_manifest":
        raise AgentCompetitionError("competition manifest contract is invalid")
    if (
        manifest["competition_id"] != identifier
        or manifest["provider"] not in PROVIDERS
        or manifest["mode"] not in MODES
        or not isinstance(manifest["request_id"], str)
        or REQUEST_ID_RE.fullmatch(manifest["request_id"]) is None
    ):
        raise AgentCompetitionError("competition manifest identity is invalid")
    if manifest["authority"] != "advisory_only" or manifest["automatic_apply"] is not False:
        raise AgentCompetitionError("competition manifest authority is invalid")
    for field in ("expected_head", "task_sha256", "packet_sha256", "request_fingerprint", "start_intent_sha256"):
        pattern = SHA40_RE if field == "expected_head" else SHA256_RE
        value = manifest[field]
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise AgentCompetitionError(f"competition manifest {field} is invalid")
    packet = _load_private_json(_competition_dir(identifier) / "packet.json", label="candidate packet")
    packet_hash = packet.get("packet_sha256")
    unsigned_packet = {key: value for key, value in packet.items() if key != "packet_sha256"}
    if not isinstance(packet_hash, str) or packet_hash != _sha256_json(unsigned_packet):
        raise AgentCompetitionError("candidate packet hash is invalid")
    bindings = {
        "competition_id": identifier,
        "request_id": manifest["request_id"],
        "request_fingerprint": manifest["request_fingerprint"],
        "provider": manifest["provider"],
        "mode": manifest["mode"],
        "repository": manifest["repository"],
        "expected_head": manifest["expected_head"],
        "task_sha256": manifest["task_sha256"],
        "packet_sha256": manifest["packet_sha256"],
    }
    for field, expected in bindings.items():
        if packet.get(field) != expected:
            raise AgentCompetitionError(f"candidate packet binding mismatch: {field}")
    intent = _load_private_json(
        _competition_dir(identifier) / "start-intent.json",
        label="competition start intent",
    )
    observed_intent_hash = intent.get("start_intent_sha256")
    unsigned_intent = {key: value for key, value in intent.items() if key != "start_intent_sha256"}
    if (
        not isinstance(observed_intent_hash, str)
        or observed_intent_hash != _sha256_json(unsigned_intent)
        or observed_intent_hash != manifest["start_intent_sha256"]
        or intent.get("competition_id") != identifier
        or intent.get("request_id") != manifest["request_id"]
        or intent.get("request_fingerprint") != manifest["request_fingerprint"]
        or intent.get("packet_sha256") != manifest["packet_sha256"]
        or intent.get("state") != "prepared"
    ):
        raise AgentCompetitionError("competition start intent binding is invalid")
    return manifest


def _receipt(identifier: str, manifest: dict[str, Any] | None = None) -> dict[str, Any] | None:
    path = _competition_dir(identifier) / "receipt.json"
    if not path.exists():
        return None
    bound_manifest = _validated_manifest(identifier) if manifest is None else manifest
    receipt = _load_private_json(path, label="candidate receipt")
    observed_hash = receipt.get("receipt_sha256")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if not isinstance(observed_hash, str) or SHA256_RE.fullmatch(observed_hash) is None or observed_hash != _sha256_json(unsigned):
        raise AgentCompetitionError("candidate receipt hash is invalid")
    required = {
        "schema_version", "kind", "competition_id", "request_id", "request_fingerprint",
        "provider", "mode", "repository", "expected_head", "task_sha256", "packet_sha256",
        "prompt_sha256", "provider_version", "command_shape",
        "provider_cwd_kind", "command_sha256", "prompt_in_argv", "returncode", "runtime_seconds",
        "stdout_sha256", "stderr_sha256", "before", "after", "candidate", "authority",
        "automatic_apply", "automatic_commit", "automatic_merge", "automatic_deploy",
        "does_not_establish", "receipt_sha256",
    }
    allowed = required | {"total_cost_usd"}
    if set(receipt) < required or not set(receipt) <= allowed:
        raise AgentCompetitionError("candidate receipt shape is invalid")
    if receipt["schema_version"] != 1 or receipt["kind"] != "external_programming_candidate_receipt":
        raise AgentCompetitionError("candidate receipt contract is invalid")
    bindings = {
        "competition_id": identifier,
        "request_id": bound_manifest["request_id"],
        "request_fingerprint": bound_manifest["request_fingerprint"],
        "provider": bound_manifest["provider"],
        "mode": bound_manifest["mode"],
        "repository": bound_manifest["repository"],
        "expected_head": bound_manifest["expected_head"],
        "task_sha256": bound_manifest["task_sha256"],
        "packet_sha256": bound_manifest["packet_sha256"],
    }
    for field, expected in bindings.items():
        if receipt.get(field) != expected:
            raise AgentCompetitionError(f"candidate receipt binding mismatch: {field}")
    if receipt["authority"] != "advisory_only" or any(
        receipt[field] is not False
        for field in ("automatic_apply", "automatic_commit", "automatic_merge", "automatic_deploy")
    ):
        raise AgentCompetitionError("candidate receipt authority is invalid")
    candidate = receipt["candidate"]
    if not isinstance(candidate, dict):
        raise AgentCompetitionError("candidate receipt candidate is invalid")
    patch = candidate.get("patch")
    patch_hash = candidate.get("patch_sha256")
    if not isinstance(patch, str) or len(patch.encode("utf-8")) > 300_000:
        raise AgentCompetitionError("candidate receipt patch is invalid")
    if not isinstance(patch_hash, str) or patch_hash != _sha256_bytes(patch.encode("utf-8")):
        raise AgentCompetitionError("candidate receipt patch hash is invalid")
    return receipt



def _route_score(
    *,
    task_kind: str,
    changed_file_estimate: int,
    expected_duration_minutes: int,
    novelty: str,
    risk_flags: list[str],
    connector_instability: bool,
    parallel_work: bool,
) -> int:
    score = 0
    if task_kind == "code":
        score += 2
    elif task_kind == "operations":
        score += 1
    if changed_file_estimate >= 4:
        score += 1
    if changed_file_estimate >= 10:
        score += 1
    if expected_duration_minutes >= 30:
        score += 1
    if expected_duration_minutes >= 120:
        score += 1
    score += {"low": 0, "medium": 1, "high": 3}[novelty]
    score += min(4, len(risk_flags))
    if connector_instability:
        score += 2
    if parallel_work:
        score += 2
    return score


@mcp.tool(name="grabowski_agent_execution_route", annotations=READ_ONLY)
def grabowski_agent_execution_route(
    task_kind: str,
    changed_file_estimate: int,
    expected_duration_minutes: int,
    novelty: str,
    risk_flags: list[str] | None = None,
    connector_instability: bool = False,
    parallel_work: bool = False,
    user_requested_external: bool = False,
    available_external_agents: list[str] | None = None,
) -> dict[str, Any]:
    """Recommend direct, workspace, contrast or competition execution without authorizing it."""
    kind = workspace._required_string(task_kind, "task_kind", max_length=32)
    if kind not in TASK_KINDS:
        raise AgentCompetitionError(f"task_kind must be one of {sorted(TASK_KINDS)}")
    if isinstance(changed_file_estimate, bool) or not isinstance(changed_file_estimate, int) or not 0 <= changed_file_estimate <= 10000:
        raise AgentCompetitionError("changed_file_estimate must be an integer between 0 and 10000")
    if isinstance(expected_duration_minutes, bool) or not isinstance(expected_duration_minutes, int) or not 0 <= expected_duration_minutes <= 10080:
        raise AgentCompetitionError("expected_duration_minutes must be an integer between 0 and 10080")
    novelty_value = workspace._required_string(novelty, "novelty", max_length=16)
    if novelty_value not in NOVELTY:
        raise AgentCompetitionError(f"novelty must be one of {sorted(NOVELTY)}")
    flags = [] if risk_flags is None else risk_flags
    if not isinstance(flags, list) or len(flags) > len(RISK_FLAGS):
        raise AgentCompetitionError("risk_flags is invalid")
    normalized_flags = sorted(set(workspace._required_string(item, "risk_flag", max_length=32) for item in flags))
    unknown_flags = sorted(set(normalized_flags) - RISK_FLAGS)
    if unknown_flags:
        raise AgentCompetitionError(f"unknown risk_flags: {unknown_flags}")
    connector_flag = _strict_bool(connector_instability, "connector_instability")
    parallel_flag = _strict_bool(parallel_work, "parallel_work")
    external_requested = _strict_bool(user_requested_external, "user_requested_external")
    if available_external_agents is None:
        normalized_agents = [provider for provider in ("claude", "agy") if shutil.which(provider)]
    else:
        agents = available_external_agents
        if not isinstance(agents, list) or len(agents) > 10:
            raise AgentCompetitionError("available_external_agents is invalid")
        requested_agents = {workspace._required_string(item, "external_agent", max_length=32) for item in agents}
        unsupported = sorted(requested_agents - PROVIDERS)
        if unsupported:
            raise AgentCompetitionError(f"unsupported external agents: {unsupported}")
        normalized_agents = [provider for provider in ("claude", "agy") if provider in requested_agents]
    score = _route_score(
        task_kind=kind,
        changed_file_estimate=changed_file_estimate,
        expected_duration_minutes=expected_duration_minutes,
        novelty=novelty_value,
        risk_flags=normalized_flags,
        connector_instability=connector_flag,
        parallel_work=parallel_flag,
    )
    design_space = novelty_value == "high" or any(flag in normalized_flags for flag in {"security", "schema", "concurrency", "data_migration", "cross_repo"})
    external_available = [agent for agent in normalized_agents if agent in PROVIDERS]
    if kind in {"docs", "analysis"} and score <= 2 and not external_requested:
        mode = "direct_operator"
    elif score <= 3 and not external_requested:
        mode = "isolated_worktree"
    elif score <= 6 and not external_requested:
        mode = "full_workspace"
    elif (external_requested or design_space) and len(external_available) >= 2:
        mode = "workspace_with_competition"
    elif (external_requested or score >= 7) and external_available:
        mode = "workspace_with_contrast"
    else:
        mode = "full_workspace"
    candidate_plan: list[dict[str, Any]] = []
    if mode == "workspace_with_competition":
        providers = external_available[:2]
        candidate_plan = [
            {"provider": providers[0], "mode": "competitor", "timing": "before_primary_writer"},
            {"provider": providers[1], "mode": "contrast", "timing": "after_primary_plan_or_candidate"},
        ]
    elif mode == "workspace_with_contrast":
        candidate_plan = [{"provider": external_available[0], "mode": "contrast", "timing": "after_primary_plan_or_candidate"}]
    return {
        "schema_version": 1,
        "score": score,
        "execution_mode": mode,
        "full_workspace": mode.startswith("full_workspace") or mode.startswith("workspace_with_"),
        "external_candidates": candidate_plan,
        "max_external_candidates": 2,
        "external_results_are_advisory": True,
        "automatic_patch_apply": False,
        "automatic_winner_selection": False,
        "operator_remains_integrator": True,
        "roles_remain_isolated": mode != "direct_operator",
        "rationale": {
            "task_kind": kind,
            "novelty": novelty_value,
            "risk_flags": normalized_flags,
            "connector_instability": connector_flag,
            "parallel_work": parallel_flag,
            "design_space_benefits_from_contrast": design_space,
            "external_agents_available": external_available,
        },
        "stop_conditions": [
            "external candidate exceeds scope or context limits",
            "repository head or cleanliness drifts",
            "candidate attempts mutation or returns unstructured output",
            "additional candidate would repeat an already represented approach",
        ],
        "does_not_establish": ["execution_authority", "candidate_correctness", "merge_readiness", "need_for_external_agents"],
    }


@mcp.tool(name="grabowski_agent_competition_start", annotations=MUTATING)
def grabowski_agent_competition_start(
    request_id: str,
    provider: str,
    mode: str,
    repository: str,
    expected_head: str,
    task: str,
    allowed_paths: list[str],
    context_paths: list[str],
    forbidden_paths: list[str] | None = None,
    primary_summary: str = "",
    timeout_seconds: int = 900,
    max_budget_usd: float = 2.0,
) -> dict[str, Any]:
    """Start one durable read-only external competitor or contrast programmer."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_capability("git_cli")
    request_value = workspace._required_string(request_id, "request_id", max_length=80)
    if REQUEST_ID_RE.fullmatch(request_value) is None:
        raise AgentCompetitionError("request_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,79}")
    provider_value = workspace._required_string(provider, "provider", max_length=16)
    mode_value = workspace._required_string(mode, "mode", max_length=16)
    if provider_value not in PROVIDERS or mode_value not in MODES:
        raise AgentCompetitionError("provider or mode is unsupported")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 30 <= timeout_seconds <= 3600:
        raise AgentCompetitionError("timeout_seconds must be between 30 and 3600")
    if isinstance(max_budget_usd, bool) or not isinstance(max_budget_usd, (int, float)) or not 0 < float(max_budget_usd) <= 10:
        raise AgentCompetitionError("max_budget_usd must be in (0, 10]")
    repo, head = _repository(repository, expected_head)
    task_value = workspace._required_string(task, "task", max_length=16000)
    if not isinstance(primary_summary, str) or len(primary_summary.encode("utf-8")) > 32000 or "\x00" in primary_summary:
        raise AgentCompetitionError("primary_summary is invalid")
    summary = primary_summary.strip()
    allowed = _scope(allowed_paths, label="allowed_paths", nonempty=True)
    forbidden = _scope([] if forbidden_paths is None else forbidden_paths, label="forbidden_paths", nonempty=False)
    sensitive_allowed = [path for path in allowed if _path_is_sensitive(path)]
    if sensitive_allowed:
        raise AgentCompetitionError(f"sensitive-looking allowed paths are not exportable: {sensitive_allowed}")
    contexts = _context(repo, context_paths, allowed, forbidden)
    executable = shutil.which(provider_value)
    if not executable:
        raise AgentCompetitionError(f"provider executable is unavailable: {provider_value}")
    runner_metadata = RUNNER.lstat()
    if RUNNER.is_symlink() or not stat.S_ISREG(runner_metadata.st_mode) or runner_metadata.st_nlink != 1:
        raise AgentCompetitionError("external candidate runner is unavailable or unsafe")
    task_sha256 = _sha256_bytes(task_value.encode("utf-8"))
    request_contract = {
        "request_id": request_value,
        "provider": provider_value,
        "mode": mode_value,
        "repository": str(repo),
        "expected_head": head,
        "task_sha256": task_sha256,
        "task": task_value,
        "allowed_paths": allowed,
        "forbidden_paths": forbidden,
        "context": [{"path": item["path"], "sha256": item["sha256"]} for item in contexts],
        "primary_summary": summary,
        "timeout_seconds": timeout_seconds,
        "max_budget_usd": float(max_budget_usd),
    }
    request_fingerprint = _sha256_json(request_contract)
    identifier = _competition_id(provider_value, mode_value, task_sha256, request_value)
    directory = _competition_dir(identifier)
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        manifest_path = directory / "manifest.json"
        intent_path = directory / "start-intent.json"
        if manifest_path.exists():
            existing = _validated_manifest(identifier)
            if existing["request_fingerprint"] != request_fingerprint:
                raise AgentCompetitionError("request_id already exists with a different competition contract")
            return {
                "competition_id": identifier,
                "request_id": request_value,
                "provider": existing["provider"],
                "mode": existing["mode"],
                "task_id": existing["task_id"],
                "packet_sha256": existing["packet_sha256"],
                "status_tool": "grabowski_agent_competition_status",
                "already_started": True,
                "automatic_apply": False,
                "does_not_establish": ["candidate_success", "candidate_correctness", "preferred_candidate"],
            }
        if intent_path.exists():
            intent = _load_private_json(intent_path, label="competition start intent")
            if intent.get("request_fingerprint") != request_fingerprint:
                raise AgentCompetitionError("request_id already exists with a different unresolved start intent")
            raise AgentCompetitionError(
                "competition start outcome is unresolved; inspect durable tasks before using a new request_id"
            )
        raise AgentCompetitionError("competition directory already exists without a valid manifest or start intent")
    packet: dict[str, Any] = {
        "schema_version": 1,
        "kind": "external_programming_candidate_packet",
        "competition_id": identifier,
        "request_id": request_value,
        "request_fingerprint": request_fingerprint,
        "provider": provider_value,
        "mode": mode_value,
        "repository": str(repo),
        "expected_head": head,
        "task": task_value,
        "task_sha256": task_sha256,
        "allowed_paths": allowed,
        "forbidden_paths": forbidden,
        "context": contexts,
        "primary_summary": summary,
        "packet_nonce": secrets.token_hex(16),
        "created_at": workspace._utc(),
    }
    packet["packet_sha256"] = _sha256_json(packet)
    packet_path = directory / "packet.json"
    receipt_path = directory / "receipt.json"
    raw_path = directory / "raw-output.json"
    stderr_path = directory / "stderr.txt"
    _atomic_json(packet_path, packet)
    command = [
        "/usr/bin/python3", str(RUNNER),
        "--packet", str(packet_path),
        "--output", str(receipt_path),
        "--raw-output", str(raw_path),
        "--stderr-output", str(stderr_path),
        "--timeout-seconds", str(timeout_seconds),
        "--max-budget-usd", format(float(max_budget_usd), "g"),
    ]
    start_intent = {
        "schema_version": 1,
        "kind": "external_programming_competition_start_intent",
        "competition_id": identifier,
        "request_id": request_value,
        "request_fingerprint": request_fingerprint,
        "packet_sha256": packet["packet_sha256"],
        "command_sha256": _sha256_json(command),
        "created_at": workspace._utc(),
        "state": "prepared",
    }
    start_intent["start_intent_sha256"] = _sha256_json(start_intent)
    _atomic_json(directory / "start-intent.json", start_intent)
    try:
        task_start = tasks.grabowski_task_start(
            host="heim-pc",
            argv=command,
            cwd=str(repo),
            runtime_seconds=timeout_seconds + 180,
            resume_policy="never",
            cpu_weight=80,
            io_weight=80,
            memory_max_bytes=2 * 1024 * 1024 * 1024,
            resource_keys=[f"path:{directory}"],
        )
    except Exception:
        failure = {
            "schema_version": 1,
            "competition_id": identifier,
            "request_id": request_value,
            "request_fingerprint": request_fingerprint,
            "packet_sha256": packet["packet_sha256"],
            "start_intent_sha256": start_intent["start_intent_sha256"],
            "state": "task_start_failed",
            "recorded_at": workspace._utc(),
        }
        _atomic_json(directory / "start-failure.json", failure)
        raise
    task_record = task_start.get("task") if isinstance(task_start, dict) else None
    if not isinstance(task_record, dict) or not isinstance(task_record.get("task_id"), str):
        unknown = {
            "schema_version": 1,
            "competition_id": identifier,
            "request_id": request_value,
            "request_fingerprint": request_fingerprint,
            "start_intent_sha256": start_intent["start_intent_sha256"],
            "state": "task_start_outcome_unknown",
            "recorded_at": workspace._utc(),
        }
        _atomic_json(directory / "start-unknown.json", unknown)
        raise AgentCompetitionError("durable task start outcome is unknown; retry is blocked")
    manifest = {
        "schema_version": 1,
        "kind": "external_programming_competition_manifest",
        "competition_id": identifier,
        "request_id": request_value,
        "request_fingerprint": request_fingerprint,
        "provider": provider_value,
        "mode": mode_value,
        "repository": str(repo),
        "expected_head": head,
        "task_sha256": task_sha256,
        "packet_sha256": packet["packet_sha256"],
        "start_intent_sha256": start_intent["start_intent_sha256"],
        "task_id": task_record["task_id"],
        "task_unit": task_record.get("unit"),
        "created_at": workspace._utc(),
        "authority": "advisory_only",
        "automatic_apply": False,
    }
    manifest["manifest_sha256"] = _sha256_json(manifest)
    try:
        _atomic_json(directory / "manifest.json", manifest)
    except Exception:
        try:
            tasks.grabowski_task_cancel(task_record["task_id"])
        except Exception as cancel_exc:
            failure = {
                "schema_version": 1,
                "competition_id": identifier,
                "task_id": task_record["task_id"],
                "state": "manifest_publish_failed_cancel_unconfirmed",
                "cancel_error": workspace._error_summary(cancel_exc),
                "recorded_at": workspace._utc(),
            }
            _atomic_json(directory / "manifest-failure.json", failure)
        raise
    return {
        "competition_id": identifier,
        "request_id": request_value,
        "provider": provider_value,
        "mode": mode_value,
        "task_id": task_record["task_id"],
        "packet_sha256": packet["packet_sha256"],
        "status_tool": "grabowski_agent_competition_status",
        "already_started": False,
        "automatic_apply": False,
        "does_not_establish": ["candidate_success", "candidate_correctness", "preferred_candidate"],
    }


@mcp.tool(name="grabowski_agent_competition_status", annotations=READ_ONLY)
def grabowski_agent_competition_status(competition_id: str) -> dict[str, Any]:
    """Read one external candidate task and validate its immutable receipt when present."""
    operator._require_operator_capability("durable_job")
    manifest = _validated_manifest(competition_id)
    task_status = tasks.grabowski_task_status(manifest["task_id"])
    receipt = _receipt(competition_id, manifest)
    bounded_task = {
        key: task_status.get(key)
        for key in ("task_id", "unit", "attempt", "state", "updated_at_unix", "resume_policy")
        if key in task_status
    }
    return {
        "schema_version": 1,
        "competition_id": competition_id,
        "request_id": manifest["request_id"],
        "provider": manifest["provider"],
        "mode": manifest["mode"],
        "repository": manifest["repository"],
        "expected_head": manifest["expected_head"],
        "task_sha256": manifest["task_sha256"],
        "task": bounded_task,
        "receipt_present": receipt is not None,
        "candidate": _candidate_summary(receipt) if receipt is not None else None,
        "candidate_ready": receipt is not None and task_status.get("state") == "completed",
        "authority": "advisory_only",
        "automatic_apply": False,
        "does_not_establish": ["correctness", "test_pass", "review_pass", "preferred_candidate"],
    }


def _candidate_summary(receipt: dict[str, Any]) -> dict[str, Any]:
    candidate = receipt["candidate"]
    return {
        "competition_id": receipt["competition_id"],
        "provider": receipt["provider"],
        "mode": receipt["mode"],
        "approach_id": candidate["approach_id"],
        "approach_summary": candidate["approach_summary"],
        "confidence": candidate["confidence"],
        "changed_paths": candidate["changed_paths"],
        "patch_sha256": candidate["patch_sha256"],
        "patch_size_bytes": len(candidate["patch"].encode("utf-8")),
        "patch_available": bool(candidate["patch"]),
        "patch_applies": candidate["patch_check"]["applies"],
        "assumptions": candidate["assumptions"],
        "design_invariants": candidate["design_invariants"],
        "tradeoffs": candidate["tradeoffs"],
        "risks": candidate["risks"],
        "proposed_tests": candidate["proposed_tests"],
        "contrast_observations": candidate["contrast_observations"],
        "receipt_sha256": receipt["receipt_sha256"],
    }


@mcp.tool(name="grabowski_agent_competition_compare", annotations=READ_ONLY)
def grabowski_agent_competition_compare(competition_ids: list[str]) -> dict[str, Any]:
    """Generate a deterministic contrast matrix and validation opportunities from two to four candidates."""
    operator._require_operator_capability("durable_job")
    if not isinstance(competition_ids, list) or not 2 <= len(competition_ids) <= 4:
        raise AgentCompetitionError("competition_ids must contain between 2 and 4 entries")
    if len(set(competition_ids)) != len(competition_ids):
        raise AgentCompetitionError("competition_ids must be unique")
    receipts: list[dict[str, Any]] = []
    for identifier in competition_ids:
        manifest = _validated_manifest(identifier)
        receipt = _receipt(identifier, manifest)
        if receipt is None:
            raise AgentCompetitionError(f"candidate receipt is not ready: {identifier}")
        receipts.append(receipt)
    bindings = {(item["repository"], item["expected_head"], item["task_sha256"]) for item in receipts}
    if len(bindings) != 1:
        raise AgentCompetitionError("candidate receipts do not share repository, head and task binding")
    candidates = [_candidate_summary(item) for item in receipts]
    path_sets = [set(item["changed_paths"]) for item in candidates]
    risk_sets = [set(item["risks"]) for item in candidates]
    invariant_sets = [set(item["design_invariants"]) for item in candidates]
    test_counter: Counter[str] = Counter(test for item in candidates for test in item["proposed_tests"])
    shared_paths = sorted(set.intersection(*path_sets)) if path_sets else []
    all_paths = sorted(set.union(*path_sets)) if path_sets else []
    shared_risks = sorted(set.intersection(*risk_sets)) if risk_sets else []
    shared_invariants = sorted(set.intersection(*invariant_sets)) if invariant_sets else []
    pairwise = []
    for left_index, left in enumerate(candidates):
        for right in candidates[left_index + 1 :]:
            left_paths = set(left["changed_paths"])
            right_paths = set(right["changed_paths"])
            union = left_paths | right_paths
            pairwise.append({
                "left": left["competition_id"],
                "right": right["competition_id"],
                "shared_paths": sorted(left_paths & right_paths),
                "unique_left_paths": sorted(left_paths - right_paths),
                "unique_right_paths": sorted(right_paths - left_paths),
                "path_jaccard": round(len(left_paths & right_paths) / len(union), 6) if union else 1.0,
                "same_patch": left["patch_sha256"] == right["patch_sha256"],
            })
    insights: list[dict[str, Any]] = []
    if shared_paths:
        insights.append({
            "kind": "implementation_consensus",
            "evidence": shared_paths,
            "interpretation": "independent candidates converge on these code surfaces; inspect them first but do not treat convergence as correctness",
        })
    divergent_paths = sorted(set(all_paths) - set(shared_paths))
    if divergent_paths:
        insights.append({
            "kind": "architectural_divergence",
            "evidence": divergent_paths,
            "interpretation": "candidates disagree on implementation boundaries; compare coupling, rollback and test cost before choosing",
        })
    if shared_risks:
        insights.append({
            "kind": "shared_risk",
            "evidence": shared_risks,
            "interpretation": "convert repeated independent risks into explicit tests or invariants",
        })
    if shared_invariants:
        insights.append({
            "kind": "shared_invariant",
            "evidence": shared_invariants,
            "interpretation": "preserve these constraints in the integrated implementation and review evidence",
        })
    repeated_tests = sorted(test for test, count in test_counter.items() if count >= 2)
    if repeated_tests:
        insights.append({
            "kind": "validation_consensus",
            "evidence": repeated_tests,
            "interpretation": "multiple candidates independently request these checks; prioritize them in the deterministic test role",
        })
    applying = [item["competition_id"] for item in candidates if item["patch_applies"]]
    nonapplying = [item["competition_id"] for item in candidates if not item["patch_applies"]]
    if nonapplying:
        insights.append({
            "kind": "patch_applicability_gap",
            "evidence": nonapplying,
            "interpretation": "use these candidates for reasoning only unless the operator reconstructs and validates their changes",
        })
    result = {
        "schema_version": 1,
        "kind": "external_programming_contrast_matrix",
        "repository": receipts[0]["repository"],
        "expected_head": receipts[0]["expected_head"],
        "task_sha256": receipts[0]["task_sha256"],
        "candidate_count": len(candidates),
        "candidates": candidates,
        "pairwise_contrasts": pairwise,
        "consensus": {
            "changed_paths": shared_paths,
            "risks": shared_risks,
            "design_invariants": shared_invariants,
            "proposed_tests": repeated_tests,
        },
        "divergence": {
            "changed_paths": divergent_paths,
            "assumptions_by_candidate": {item["competition_id"]: item["assumptions"] for item in candidates},
            "tradeoffs_by_candidate": {item["competition_id"]: item["tradeoffs"] for item in candidates},
            "contrast_observations_by_candidate": {item["competition_id"]: item["contrast_observations"] for item in candidates},
        },
        "patch_applicability": {"applying": applying, "nonapplying": nonapplying},
        "insights": insights,
        "integration_rule": "operator selects explicit insights; normal isolated Writer reimplements or imports them, then deterministic Tests and independent Review validate the resulting frozen diff",
        "winner_selected": False,
        "automatic_apply": False,
        "automatic_merge": False,
        "does_not_establish": ["candidate_correctness", "causal_superiority", "test_pass", "review_pass", "merge_readiness"],
    }
    result["comparison_sha256"] = _sha256_json(result)
    return result

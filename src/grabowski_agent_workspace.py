from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Iterable

import grabowski_agent_role as agent_role
import grabowski_mcp as base
import grabowski_resources as resources
import grabowski_tasks as tasks
from grabowski_agent_sandbox import safe_git_environment
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

WORKSPACE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_AGENT_WORKSPACE_ROOT",
        str(operator.STATE_DIR / "agent-workspaces"),
    )
).expanduser()
TMUX = Path(os.environ.get("GRABOWSKI_TMUX_BIN", shutil.which("tmux") or "/usr/bin/tmux"))
BUREAU = Path(os.environ.get("GRABOWSKI_BUREAU_BIN", shutil.which("bureau") or str(Path.home() / ".local/bin/bureau")))
BUREAU_ROOT = Path(os.environ.get("GRABOWSKI_BUREAU_ROOT", str(Path.home() / "repos/bureau"))).expanduser()
SCHEMA_VERSION = 1
WORKSPACE_ID_RE = re.compile(r"^gaw-[a-z0-9][a-z0-9-]{7,79}$")
BUREAU_TASK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BINDING_KINDS = frozenset({"bureau_task", "thread_focus"})
TERMINAL_TASK_STATES = frozenset(
    {"completed", "failed", "cancelled", "timed_out", "signalled", "outcome_unknown"}
)
READ_ONLY_ROLES = ("tests", "review")
ALL_ROLES = ("captain", "writer", "tests", "review")
PLAN_FIELDS = (
    "schema_version",
    "workspace_id",
    "session_name",
    "binding",
    "binding_evidence",
    "repository",
    "expected_base_head",
    "writer_branch",
    "writer_worktree",
    "scope",
    "commands",
    "roles",
    "role_ownership",
    "route_evidence",
    "resources",
)
PANE_ID_RE = re.compile(r"^%[0-9]+$")
ROLE_COMMAND_WRAPPERS = frozenset({"env", "nohup", "nice", "timeout", "setsid", "stdbuf", "ionice", "chrt"})
ROLE_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh"})
MAX_PATHS = 256
MAX_ARGV = 256
MAX_UNTRACKED_FILE_BYTES = 16 * 1024 * 1024
MAX_UNTRACKED_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATCH_BYTES = 128 * 1024 * 1024
MAX_STATE_JSON_BYTES = 4 * 1024 * 1024
WRITER_FREEZE_SETTLE_SECONDS = 0.1
WORKSPACE_LOCK_TIMEOUT_SECONDS = 10.0
WORKSPACE_LOCK_POLL_SECONDS = 0.05
AGENT_WORKSPACE_TASK_HOST = "heim-pc"
MAX_ROLE_RETRIES = 1
MAX_WORKSPACE_EVENTS = 512
MAX_WORKSPACE_EVENT_BYTES = 1024 * 1024
ROUTE_EXECUTION_MODES = frozenset({
    "direct_operator",
    "isolated_worktree",
    "full_workspace",
    "workspace_with_contrast",
    "workspace_with_competition",
})
ROUTE_TASK_KINDS = frozenset({"code", "docs", "analysis", "operations"})
ROUTE_NOVELTY = frozenset({"low", "medium", "high"})
ROUTE_RISK_FLAGS = frozenset({
    "security", "runtime", "deployment", "schema", "concurrency",
    "data_migration", "privilege", "external_api", "cross_repo",
    "destructive", "user_data",
})
ROUTE_EXTERNAL_AGENTS = frozenset({"claude", "agy"})
CommandRunner = Callable[[Path, list[str]], dict[str, Any]]
BindingVerifier = Callable[[str, str], dict[str, Any]]


class AgentWorkspaceError(ValueError):
    pass


class AgentWorkspaceActionError(RuntimeError):
    pass


def _now() -> int:
    return int(time.time())


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_string(value: Any, field: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentWorkspaceError(f"{field} must be a non-empty string")
    result = value.strip()
    if len(result) > max_length or "\x00" in result:
        raise AgentWorkspaceError(f"{field} is invalid")
    return result


def _error_summary(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    redact = getattr(operator, "_redact", None)
    if callable(redact):
        text = str(redact(text))
    return text[:4000]


def _positive_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AgentWorkspaceError(f"{field} must be between {minimum} and {maximum}")
    return value


def _argv(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARGV:
        raise AgentWorkspaceError(f"{field} must be a non-empty argv list")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_required_string(item, f"{field}[{index}]", max_length=8192))
    return result


def _normalize_route_input_facts(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentWorkspaceError("route_evidence.input_facts must be an object")
    expected = {
        "task_kind",
        "changed_file_estimate",
        "expected_duration_minutes",
        "novelty",
        "risk_flags",
        "connector_instability",
        "parallel_work",
        "user_requested_external",
        "available_external_agents",
    }
    if set(value) != expected:
        raise AgentWorkspaceError("route_evidence.input_facts shape is invalid")
    task_kind = _required_string(value.get("task_kind"), "route_evidence.input_facts.task_kind", max_length=32)
    if task_kind not in ROUTE_TASK_KINDS:
        raise AgentWorkspaceError("route_evidence task_kind is invalid")
    changed_files = value.get("changed_file_estimate")
    duration = value.get("expected_duration_minutes")
    if isinstance(changed_files, bool) or not isinstance(changed_files, int) or not 0 <= changed_files <= 10000:
        raise AgentWorkspaceError("route_evidence changed_file_estimate is invalid")
    if isinstance(duration, bool) or not isinstance(duration, int) or not 0 <= duration <= 10080:
        raise AgentWorkspaceError("route_evidence expected_duration_minutes is invalid")
    novelty = _required_string(value.get("novelty"), "route_evidence.input_facts.novelty", max_length=16)
    if novelty not in ROUTE_NOVELTY:
        raise AgentWorkspaceError("route_evidence novelty is invalid")
    raw_flags = value.get("risk_flags")
    if not isinstance(raw_flags, list) or len(raw_flags) > len(ROUTE_RISK_FLAGS):
        raise AgentWorkspaceError("route_evidence risk_flags are invalid")
    flags = sorted({_required_string(item, "route_evidence.risk_flag", max_length=32) for item in raw_flags})
    if len(flags) != len(raw_flags) or set(flags) - ROUTE_RISK_FLAGS:
        raise AgentWorkspaceError("route_evidence risk_flags are invalid")
    booleans: dict[str, bool] = {}
    for field in ("connector_instability", "parallel_work", "user_requested_external"):
        candidate = value.get(field)
        if not isinstance(candidate, bool):
            raise AgentWorkspaceError(f"route_evidence {field} must be boolean")
        booleans[field] = candidate
    raw_agents = value.get("available_external_agents")
    if not isinstance(raw_agents, list) or len(raw_agents) > len(ROUTE_EXTERNAL_AGENTS):
        raise AgentWorkspaceError("route_evidence available_external_agents are invalid")
    agents = [_required_string(item, "route_evidence.external_agent", max_length=32) for item in raw_agents]
    if len(set(agents)) != len(agents) or set(agents) - ROUTE_EXTERNAL_AGENTS:
        raise AgentWorkspaceError("route_evidence available_external_agents are invalid")
    return {
        "task_kind": task_kind,
        "changed_file_estimate": changed_files,
        "expected_duration_minutes": duration,
        "novelty": novelty,
        "risk_flags": flags,
        **booleans,
        "available_external_agents": agents,
    }


def _route_decision(input_facts: dict[str, Any]) -> dict[str, Any]:
    """Replay the deterministic routing policy from normalized input facts."""
    kind = str(input_facts["task_kind"])
    changed_files = int(input_facts["changed_file_estimate"])
    duration = int(input_facts["expected_duration_minutes"])
    novelty = str(input_facts["novelty"])
    risk_flags = list(input_facts["risk_flags"])
    connector_instability = bool(input_facts["connector_instability"])
    parallel_work = bool(input_facts["parallel_work"])
    external_requested = bool(input_facts["user_requested_external"])
    external_available = list(input_facts["available_external_agents"])

    score = 0
    if kind == "code":
        score += 2
    elif kind == "operations":
        score += 1
    if changed_files >= 4:
        score += 1
    if changed_files >= 10:
        score += 1
    if duration >= 30:
        score += 1
    if duration >= 120:
        score += 1
    score += {"low": 0, "medium": 1, "high": 3}[novelty]
    score += min(4, len(risk_flags))
    if connector_instability:
        score += 2
    if parallel_work:
        score += 2

    design_space = novelty == "high" or any(
        flag in risk_flags
        for flag in {"security", "schema", "concurrency", "data_migration", "cross_repo"}
    )
    if kind in {"docs", "analysis"} and score <= 2 and not external_requested:
        mode = "direct_operator"
    elif score <= 3 and not external_requested:
        mode = "isolated_worktree"
    elif score <= 6 and not external_requested:
        mode = "full_workspace"
    elif len(external_available) >= 2 and (
        external_requested or (design_space and score >= 9)
    ):
        mode = "workspace_with_competition"
    elif external_available and (
        external_requested or (design_space and score >= 8) or score >= 10
    ):
        mode = "workspace_with_contrast"
    else:
        mode = "full_workspace"

    candidates: list[dict[str, str]] = []
    if mode == "workspace_with_competition":
        candidates = [
            {"provider": external_available[0], "mode": "competitor", "timing": "before_primary_writer"},
            {"provider": external_available[1], "mode": "contrast", "timing": "after_primary_plan_or_candidate"},
        ]
    elif mode == "workspace_with_contrast":
        candidates = [
            {"provider": external_available[0], "mode": "contrast", "timing": "after_primary_plan_or_candidate"}
        ]
    trivial_work = bool(
        changed_files <= 1
        and duration <= 15
        and novelty == "low"
        and not risk_flags
        and not connector_instability
        and not parallel_work
    )
    return {
        "score": score,
        "execution_mode": mode,
        "external_candidates": candidates,
        "design_space": design_space,
        "trivial_work": trivial_work,
    }


def _normalize_route_evidence(value: Any) -> dict[str, Any]:
    if value is None:
        return {
            "schema_version": 1,
            "status": "missing",
            "recommendation_id": None,
            "score": None,
            "recommended_route": None,
            "actual_route": "full_workspace",
            "input_facts": None,
            "external_candidates": [],
            "deviation_reason": None,
            "evidence_complete": False,
        }
    if not isinstance(value, dict):
        raise AgentWorkspaceError("route_evidence must be an object")
    expected = {
        "schema_version",
        "recommendation_id",
        "score",
        "recommended_route",
        "actual_route",
        "input_facts",
        "external_candidates",
        "deviation_reason",
    }
    if set(value) != expected or value.get("schema_version") != 1:
        raise AgentWorkspaceError("route_evidence shape is invalid")
    recommendation_id = _required_string(value.get("recommendation_id"), "route_evidence.recommendation_id", max_length=64).lower()
    if SHA256_RE.fullmatch(recommendation_id) is None:
        raise AgentWorkspaceError("route_evidence recommendation_id is invalid")
    score = value.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 20:
        raise AgentWorkspaceError("route_evidence score is invalid")
    recommended = _required_string(value.get("recommended_route"), "route_evidence.recommended_route", max_length=40)
    actual = _required_string(value.get("actual_route"), "route_evidence.actual_route", max_length=40)
    if recommended not in ROUTE_EXECUTION_MODES or actual not in ROUTE_EXECUTION_MODES:
        raise AgentWorkspaceError("route_evidence route is invalid")
    if actual not in {"full_workspace", "workspace_with_contrast", "workspace_with_competition"}:
        raise AgentWorkspaceError("agent workspace actual_route must be a workspace route")
    facts = _normalize_route_input_facts(value.get("input_facts"))
    raw_candidates = value.get("external_candidates")
    if not isinstance(raw_candidates, list) or len(raw_candidates) > 2:
        raise AgentWorkspaceError("route_evidence external_candidates are invalid")
    candidates: list[dict[str, str]] = []
    for item in raw_candidates:
        if not isinstance(item, dict) or set(item) != {"provider", "mode", "timing"}:
            raise AgentWorkspaceError("route_evidence external candidate shape is invalid")
        provider = _required_string(item.get("provider"), "route_evidence.external_candidate.provider", max_length=32)
        mode = _required_string(item.get("mode"), "route_evidence.external_candidate.mode", max_length=32)
        timing = _required_string(item.get("timing"), "route_evidence.external_candidate.timing", max_length=80)
        if provider not in ROUTE_EXTERNAL_AGENTS or mode not in {"competitor", "contrast"}:
            raise AgentWorkspaceError("route_evidence external candidate is invalid")
        candidates.append({"provider": provider, "mode": mode, "timing": timing})
    decision = _route_decision(facts)
    if (
        score != decision["score"]
        or recommended != decision["execution_mode"]
        or candidates != decision["external_candidates"]
    ):
        raise AgentWorkspaceError(
            "route_evidence recommendation does not match deterministic policy replay"
        )
    expected_id = _sha256_json({
        "schema_version": 1,
        "score": score,
        "execution_mode": recommended,
        "input_facts": facts,
        "external_candidates": candidates,
    })
    if recommendation_id != expected_id:
        raise AgentWorkspaceError("route_evidence recommendation_id does not match its normalized recommendation")
    reason = value.get("deviation_reason")
    if recommended == actual:
        if reason not in {None, ""}:
            raise AgentWorkspaceError("route_evidence deviation_reason must be empty when routes match")
        clean_reason = None
    else:
        clean_reason = _required_string(reason, "route_evidence.deviation_reason", max_length=1000)
    return {
        "schema_version": 1,
        "status": "verified",
        "recommendation_id": recommendation_id,
        "score": score,
        "recommended_route": recommended,
        "actual_route": actual,
        "input_facts": facts,
        "external_candidates": candidates,
        "deviation_reason": clean_reason,
        "evidence_complete": True,
    }


def _role_privilege_escalator(command: list[str]) -> str | None:
    executable = Path(command[0]).name
    if executable in operator.PRIVILEGE_ESCALATORS:
        return executable
    if executable in ROLE_COMMAND_WRAPPERS:
        for token in command[1:]:
            candidate = Path(token).name
            if candidate in operator.PRIVILEGE_ESCALATORS:
                return candidate
    if executable in ROLE_SHELLS:
        for token in command[1:]:
            try:
                nested = shlex.split(token)
            except ValueError:
                continue
            for item in nested:
                candidate = Path(item).name
                if candidate in operator.PRIVILEGE_ESCALATORS:
                    return candidate
    return None


def _role_argv(value: Any, field: str, *, cwd: Path) -> list[str]:
    command = _argv(value, field)
    try:
        validated = operator._validate_argv(command, cwd=cwd)
    except (PermissionError, ValueError) as exc:
        raise AgentWorkspaceError(f"{field} violates the operator command policy: {exc}") from exc
    escalator = _role_privilege_escalator(validated)
    if escalator is not None:
        raise AgentWorkspaceError(
            f"{field} may not invoke privilege escalator {escalator} inside an agent workspace"
        )
    if operator._redact_argv(validated) != validated:
        raise AgentWorkspaceError(f"{field} appears to contain secret material")
    return list(validated)


def _declared_python_module(command: list[str]) -> str | None:
    return agent_role.declared_python_module(command)


def _role_toolchain_preflight(manifest: dict[str, Any], role: str, command: list[str]) -> dict[str, Any]:
    """Validate role prerequisites inside the exact read-only role sandbox."""
    worktree = Path(str(manifest["writer_worktree"]))
    probe = agent_role.toolchain_probe(worktree, command)
    return {
        "role": role,
        "command_sha256": _sha256_json(command),
        "checked_at": _utc(),
        "sandbox": agent_role.SANDBOX_LABEL,
        **probe,
    }

def _absolute_path(value: Any, field: str, *, must_exist: bool) -> Path:
    raw = _required_string(value, field)
    path = Path(raw).expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise AgentWorkspaceError(f"{field} must be an absolute non-symlink path")
    try:
        if must_exist:
            return path.resolve(strict=True)
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise AgentWorkspaceError(f"{field} is not safely resolvable: {exc}") from exc
    return parent / path.name


def _scope_path(value: Any, field: str) -> str:
    raw = _required_string(value, field, max_length=1024).replace("\\", "/")
    path = PurePosixPath(raw)
    if path.is_absolute() or raw in {".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
        raise AgentWorkspaceError(f"{field} must be a normalized relative path")
    return path.as_posix().rstrip("/")


def _scope_list(value: Any, field: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_PATHS or (nonempty and not value):
        raise AgentWorkspaceError(f"{field} must be a bounded list")
    result = [_scope_path(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(set(result)) != len(result):
        raise AgentWorkspaceError(f"{field} contains duplicates")
    return sorted(result)


def _contains(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent + "/")


def _run(cwd: Path, argv: list[str], *, timeout: int = 120) -> dict[str, Any]:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
        env=safe_git_environment(),
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _checked(runner: CommandRunner, cwd: Path, argv: list[str], *, label: str) -> dict[str, Any]:
    result = runner(cwd, argv)
    if not isinstance(result, dict) or not isinstance(result.get("returncode"), int):
        raise AgentWorkspaceActionError(f"{label} returned an invalid result")
    if result["returncode"] != 0:
        detail = str(result.get("stderr") or result.get("stdout") or label).strip()
        raise AgentWorkspaceActionError(f"{label} failed: {detail[:2000]}")
    return result


def _run_bytes(cwd: Path, argv: list[str], *, timeout: int = 120) -> dict[str, Any]:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        timeout=timeout,
        check=False,
        env=safe_git_environment(),
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _checked_bytes(cwd: Path, argv: list[str], *, label: str) -> dict[str, Any]:
    result = _run_bytes(cwd, argv)
    if result["returncode"] != 0:
        raw = result.get("stderr") or result.get("stdout") or label.encode("utf-8")
        detail = bytes(raw).decode("utf-8", errors="replace").strip()
        raise AgentWorkspaceActionError(f"{label} failed: {detail[:2000]}")
    return result


def _repo_top(runner: CommandRunner, repo: Path) -> Path:
    result = _checked(runner, repo, ["git", "rev-parse", "--show-toplevel"], label="git top-level")
    return Path(str(result.get("stdout", "")).strip()).resolve(strict=True)


def _git_head(runner: CommandRunner, repo: Path) -> str:
    result = _checked(runner, repo, ["git", "rev-parse", "HEAD"], label="git head")
    head = str(result.get("stdout", "")).strip().lower()
    if SHA40_RE.fullmatch(head) is None:
        raise AgentWorkspaceActionError("git returned an invalid HEAD")
    return head


def _slug(value: str, *, limit: int = 24) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (normalized or "workspace")[:limit].rstrip("-")


def _workspace_identity(binding_kind: str, binding_id: str, repo: Path, base_head: str) -> tuple[str, str]:
    digest = hashlib.sha256(
        "\n".join((binding_kind, binding_id, str(repo), base_head)).encode("utf-8")
    ).hexdigest()[:12]
    workspace_id = f"gaw-{_slug(repo.name, limit=18)}-{_slug(binding_id, limit=22)}-{digest}"
    if len(workspace_id) > 80:
        workspace_id = f"gaw-{_slug(repo.name, limit=18)}-{digest}"
    if WORKSPACE_ID_RE.fullmatch(workspace_id) is None:
        raise AgentWorkspaceError("could not derive a valid workspace id")
    return workspace_id, workspace_id


def _ensure_root() -> Path:
    root = WORKSPACE_ROOT
    if root.is_symlink():
        raise PermissionError(f"agent workspace root may not be a symlink: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    return root.resolve(strict=True)


def _workspace_dir(workspace_id: str, *, create: bool = False) -> Path:
    if WORKSPACE_ID_RE.fullmatch(workspace_id) is None:
        raise AgentWorkspaceError("invalid workspace_id")
    root = _ensure_root()
    path = root / workspace_id
    if path.exists() and path.is_symlink():
        raise PermissionError("workspace directory may not be a symlink")
    if create:
        path.mkdir(mode=0o700)
    if not path.is_dir():
        raise AgentWorkspaceError(f"unknown workspace: {workspace_id}")
    return path


def _fdopen_owned(descriptor: int, *args: Any, **kwargs: Any):
    try:
        return os.fdopen(descriptor, *args, **kwargs)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _lock(workspace_id: str, *, create: bool = False):
    path = _workspace_dir(workspace_id, create=create) / ".lock"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            raise PermissionError("workspace lock must be one owner-controlled private regular file")
    except BaseException:
        os.close(descriptor)
        raise
    handle = _fdopen_owned(descriptor, "r+")
    try:
        deadline = time.monotonic() + WORKSPACE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("workspace lock acquisition timed out") from exc
                time.sleep(WORKSPACE_LOCK_POLL_SECONDS)
    except BaseException:
        handle.close()
        raise
    return handle


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and (path.is_symlink() or path.stat().st_nlink != 1):
        raise PermissionError(f"unsafe workspace state path: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with _fdopen_owned(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_bounded_chunks(
    path: Path,
    chunks: Iterable[bytes],
    *,
    max_bytes: int,
) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and (path.is_symlink() or path.stat().st_nlink != 1):
        raise PermissionError(f"unsafe workspace artifact path: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    total = 0
    digest = hashlib.sha256()
    try:
        with _fdopen_owned(descriptor, "wb") as handle:
            for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise TypeError("workspace artifact chunks must be bytes")
                total += len(chunk)
                if total > max_bytes:
                    raise AgentWorkspaceActionError("writer patch is empty or exceeds the safety boundary")
                handle.write(chunk)
                digest.update(chunk)
            if total == 0:
                raise AgentWorkspaceActionError("writer patch is empty or exceeds the safety boundary")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return total, digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise
        raise PermissionError(f"unsafe workspace state path: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise PermissionError(f"unsafe workspace state path: {path}")
        if metadata.st_size > MAX_STATE_JSON_BYTES:
            raise AgentWorkspaceError(
                f"workspace state exceeds {MAX_STATE_JSON_BYTES} bytes: {path}"
            )
        owned_descriptor = descriptor
        descriptor = -1
        handle = _fdopen_owned(owned_descriptor, "r", encoding="utf-8")
        with handle:
            payload = handle.read(MAX_STATE_JSON_BYTES + 1)
        if len(payload.encode("utf-8")) > MAX_STATE_JSON_BYTES:
            raise AgentWorkspaceError(
                f"workspace state exceeds {MAX_STATE_JSON_BYTES} bytes: {path}"
            )
        value = json.loads(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise AgentWorkspaceError(f"workspace state is not an object: {path}")
    return value


def _event_log_path(workspace_id: str) -> Path:
    return _workspace_dir(workspace_id) / "events.jsonl"


def _event_log_sequence(path: Path, workspace_id: str) -> int:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return 0
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PermissionError("workspace event log must be one private regular file")
    if metadata.st_size > MAX_WORKSPACE_EVENT_BYTES:
        raise AgentWorkspaceError("workspace event log byte limit reached")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise PermissionError("workspace event log descriptor is unsafe")
        raw = os.read(descriptor, MAX_WORKSPACE_EVENT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_WORKSPACE_EVENT_BYTES:
        raise AgentWorkspaceError("workspace event log byte limit reached")
    expected = 1
    for line in raw.splitlines():
        if not line:
            continue
        if expected > MAX_WORKSPACE_EVENTS:
            raise AgentWorkspaceError("workspace event count limit reached")
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentWorkspaceError("workspace event log contains invalid JSON") from exc
        if not isinstance(event, dict):
            raise AgentWorkspaceError("workspace event log contains a non-object")
        observed_hash = event.get("event_sha256")
        unsigned = {key: value for key, value in event.items() if key != "event_sha256"}
        if (
            event.get("schema_version") != 1
            or event.get("workspace_id") != workspace_id
            or event.get("sequence") != expected
            or not isinstance(observed_hash, str)
            or observed_hash != _sha256_json(unsigned)
        ):
            raise AgentWorkspaceError("workspace event log integrity is invalid")
        expected += 1
    return expected - 1


def _append_workspace_event(
    manifest: dict[str, Any],
    event_type: str,
    *,
    role: str | None = None,
    outcome: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one bounded, redacted workspace lifecycle event."""
    workspace_id = _required_string(manifest.get("workspace_id"), "workspace_id", max_length=80)
    clean_type = _required_string(event_type, "event_type", max_length=80)
    if role is not None and role not in (*ALL_ROLES, "observer"):
        raise AgentWorkspaceError("invalid workspace event role")
    path = _event_log_path(workspace_id)
    current_sequence = _event_log_sequence(path, workspace_id)
    manifest_sequence = int(manifest.get("event_sequence", 0))
    if manifest_sequence > current_sequence:
        raise AgentWorkspaceError("workspace manifest event sequence is ahead of event log")
    if current_sequence >= MAX_WORKSPACE_EVENTS:
        raise AgentWorkspaceError("workspace event count limit reached")
    event = {
        "schema_version": 1,
        "workspace_id": workspace_id,
        "sequence": current_sequence + 1,
        "event_type": clean_type,
        "recorded_at": _utc(),
        "role": role,
        "outcome": None if outcome is None else _required_string(outcome, "outcome", max_length=120),
        "evidence": evidence or {},
    }
    event["event_sha256"] = _sha256_json(event)
    line = (_canonical_json(event) + "\n").encode("utf-8")
    if len(line) > 16384:
        raise AgentWorkspaceError("workspace event exceeds bounded size")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PermissionError("workspace event log must be one private regular file")
        if metadata.st_size + len(line) > MAX_WORKSPACE_EVENT_BYTES:
            raise AgentWorkspaceError("workspace event log byte limit reached")
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != 0o600:
            raise PermissionError("workspace event log descriptor is unsafe")
        os.write(descriptor, line)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    manifest["event_sequence"] = event["sequence"]
    return event


def _manifest_path(workspace_id: str) -> Path:
    return _workspace_dir(workspace_id) / "manifest.json"


def _manifest(workspace_id: str) -> dict[str, Any]:
    value = _load_json(_manifest_path(workspace_id))
    if value.get("schema_version") != SCHEMA_VERSION or value.get("workspace_id") != workspace_id:
        raise AgentWorkspaceError("workspace manifest identity mismatch")
    return value


def _write_manifest(value: dict[str, Any]) -> None:
    value = dict(value)
    value["updated_at"] = _utc()
    _atomic_json(_manifest_path(str(value["workspace_id"])), value)


def _tmux_result(argv: list[str], *, timeout: int = 30) -> dict[str, Any]:
    if not TMUX.is_file() or not os.access(TMUX, os.X_OK):
        raise AgentWorkspaceActionError(f"tmux executable unavailable: {TMUX}")
    return _run(Path.home(), [str(TMUX), *argv], timeout=timeout)


def _tmux_has_session(session: str) -> bool:
    result = _tmux_result(["has-session", "-t", session])
    return result["returncode"] == 0


def _tmux_pane_ids(session: str) -> set[str]:
    result = _tmux_result(["list-panes", "-t", f"{session}:agents", "-F", "#{pane_id}"])
    if result["returncode"] != 0:
        raise AgentWorkspaceActionError(str(result.get("stderr") or "tmux list-panes failed"))
    pane_ids = {line.strip() for line in str(result.get("stdout", "")).splitlines() if line.strip()}
    if not pane_ids or any(PANE_ID_RE.fullmatch(pane_id) is None for pane_id in pane_ids):
        raise AgentWorkspaceActionError("tmux pane inventory is invalid")
    return pane_ids


def _task_public(task_id: str | None) -> dict[str, Any]:
    if task_id is None:
        return {"task_id": None, "state": "not_started", "terminal": False}
    try:
        value = tasks.grabowski_task_status(task_id)
    except Exception as exc:
        return {
            "task_id": task_id,
            "state": "observation_error",
            "terminal": False,
            "error": _error_summary(exc),
            "reconcile_required": True,
        }
    state = str(value.get("state", "unknown"))
    return {
        "task_id": task_id,
        "host": value.get("host"),
        "unit": value.get("unit"),
        "state": state,
        "terminal": state in TERMINAL_TASK_STATES,
        "attempt": value.get("attempt"),
        "resume_policy": value.get("resume_policy"),
        "argv_sha256": value.get("argv_sha256"),
        "cwd": value.get("cwd"),
        "outcome_receipt": value.get("outcome_receipt"),
    }


def _verify_bureau_binding(
    binding_kind: str,
    binding_id: str,
    *,
    runner: CommandRunner = _run,
) -> dict[str, Any]:
    if not BUREAU.is_file() or not os.access(BUREAU, os.X_OK):
        raise AgentWorkspaceError(f"Bureau executable unavailable: {BUREAU}")
    if BUREAU_ROOT.is_symlink() or not BUREAU_ROOT.is_dir():
        raise AgentWorkspaceError(f"Bureau root unavailable or unsafe: {BUREAU_ROOT}")
    root = BUREAU_ROOT.resolve(strict=True)
    if binding_kind == "thread_focus":
        result = _checked(
            runner,
            root,
            [
                str(BUREAU), "--root", str(root), "--json", "live-list",
                "--kind", "thread_focus", "--thread-id", binding_id, "--limit", "50",
            ],
            label="Bureau thread focus lookup",
        )
        try:
            payload = json.loads(str(result.get("stdout", "")))
        except json.JSONDecodeError as exc:
            raise AgentWorkspaceError("Bureau thread focus lookup returned invalid JSON") from exc
        records = payload.get("records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            raise AgentWorkspaceError("Bureau thread focus lookup omitted records")
        matches: list[dict[str, Any]] = []
        for item in records:
            record = item.get("record") if isinstance(item, dict) else None
            if (
                isinstance(record, dict)
                and record.get("kind") == "thread_focus"
                and record.get("thread_id") == binding_id
                and record.get("status") == "active"
            ):
                matches.append(item)
        if len(matches) != 1:
            raise AgentWorkspaceError(
                f"Bureau thread focus must resolve to exactly one active record; found {len(matches)}"
            )
        match = matches[0]
        record = match["record"]
        evidence = {
            "source": "bureau-live-register",
            "kind": "thread_focus",
            "id": binding_id,
            "status": "active",
            "event_id": match.get("event_id"),
            "repo": record.get("repo"),
            "worker_id": record.get("worker_id"),
            "does_not_establish": record.get("does_not_establish", []),
        }
        evidence["evidence_sha256"] = _sha256_json(evidence)
        return evidence
    if binding_kind == "bureau_task":
        if BUREAU_TASK_ID_RE.fullmatch(binding_id) is None:
            raise AgentWorkspaceError("bureau_task binding_id has an invalid format")
        truth = _checked(
            runner,
            root,
            [
                str(BUREAU), "--root", str(root), "--json", "registry-truth",
                "--strict", "--no-baseline-probe",
            ],
            label="Bureau registry truth",
        )
        try:
            truth_payload = json.loads(str(truth.get("stdout", "")))
        except json.JSONDecodeError as exc:
            raise AgentWorkspaceError("Bureau registry truth returned invalid JSON") from exc
        if not isinstance(truth_payload, dict) or truth_payload.get("healthy") is not True:
            raise AgentWorkspaceError("Bureau registry truth is not healthy")
        task_path = root / "registry" / "tasks" / f"{binding_id}.json"
        if task_path.is_symlink() or not task_path.is_file() or task_path.stat().st_nlink != 1:
            raise AgentWorkspaceError(f"Bureau task does not exist safely: {binding_id}")
        try:
            task = json.loads(task_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AgentWorkspaceError(f"Bureau task JSON is invalid: {binding_id}") from exc
        if not isinstance(task, dict) or task.get("id") != binding_id:
            raise AgentWorkspaceError("Bureau task identity mismatch")
        state = task.get("state")
        if state not in {"inbox", "planned", "ready"}:
            raise AgentWorkspaceError(f"Bureau task is not actionable: {binding_id} state={state}")
        task_sha256 = hashlib.sha256(task_path.read_bytes()).hexdigest()
        evidence = {
            "source": "bureau-task-registry",
            "kind": "bureau_task",
            "id": binding_id,
            "state": state,
            "title": task.get("title"),
            "task_sha256": task_sha256,
            "registry_healthy": True,
        }
        evidence["evidence_sha256"] = _sha256_json(evidence)
        return evidence
    raise AgentWorkspaceError(f"unsupported binding_kind: {binding_kind}")


def _remote_branch_collision(repo: Path, branch: str, runner: CommandRunner) -> bool:
    for ref in (f"refs/heads/{branch}", f"refs/remotes/origin/{branch}"):
        probe = runner(repo, ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
        rc = int(probe.get("returncode", 1))
        if rc == 0:
            return True
        if rc != 1:
            detail = str(probe.get("stderr") or probe.get("stdout") or ref).strip()
            raise AgentWorkspaceActionError(f"branch collision check failed: {detail[:2000]}")
    origin = runner(repo, ["git", "remote", "get-url", "origin"])
    origin_rc = int(origin.get("returncode", 1))
    if origin_rc == 2:
        return False
    if origin_rc != 0:
        detail = str(origin.get("stderr") or origin.get("stdout") or "origin lookup").strip()
        raise AgentWorkspaceActionError(f"origin lookup failed: {detail[:2000]}")
    live = runner(
        repo,
        ["git", "ls-remote", "--exit-code", "--heads", "origin", f"refs/heads/{branch}"],
    )
    live_rc = int(live.get("returncode", 1))
    if live_rc == 0:
        return True
    if live_rc == 2:
        return False
    detail = str(live.get("stderr") or live.get("stdout") or "remote branch lookup").strip()
    raise AgentWorkspaceActionError(f"remote branch lookup failed: {detail[:2000]}")


def _normalize_create(
    *,
    binding_kind: str,
    binding_id: str,
    repository: str,
    expected_base_head: str,
    writer_branch: str,
    writer_worktree: str,
    allowed_paths: list[str],
    forbidden_paths: list[str],
    writer_argv: list[str],
    test_argv: list[str],
    review_argv: list[str],
    runtime_seconds: int,
    memory_max_bytes: int | None,
    runner: CommandRunner,
    binding_verifier: BindingVerifier | None = None,
    route_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kind = _required_string(binding_kind, "binding_kind", max_length=32)
    if kind not in BINDING_KINDS:
        raise AgentWorkspaceError(f"binding_kind must be one of {sorted(BINDING_KINDS)}")
    binding = _required_string(binding_id, "binding_id", max_length=256)
    verifier = _verify_bureau_binding if binding_verifier is None else binding_verifier
    binding_evidence = verifier(kind, binding)
    if not isinstance(binding_evidence, dict) or binding_evidence.get("id") != binding:
        raise AgentWorkspaceError("Bureau binding verifier returned mismatched evidence")
    repo = _absolute_path(repository, "repository", must_exist=True)
    if _repo_top(runner, repo) != repo:
        raise AgentWorkspaceError("repository must be the canonical checkout root")
    base_head = _required_string(expected_base_head, "expected_base_head", max_length=40).lower()
    if SHA40_RE.fullmatch(base_head) is None:
        raise AgentWorkspaceError("expected_base_head must be a full lowercase Git SHA")
    resolved = _checked(
        runner,
        repo,
        ["git", "rev-parse", "--verify", f"{base_head}^{{commit}}"],
        label="baseline resolution",
    )
    if str(resolved.get("stdout", "")).strip() != base_head:
        raise AgentWorkspaceError("expected_base_head did not resolve exactly")
    if _git_head(runner, repo) != base_head:
        raise AgentWorkspaceError("canonical checkout HEAD drifted from expected_base_head")
    branch = _required_string(writer_branch, "writer_branch", max_length=255)
    if BRANCH_RE.fullmatch(branch) is None:
        raise AgentWorkspaceError("writer_branch has an invalid format")
    _checked(runner, repo, ["git", "check-ref-format", "--branch", branch], label="branch validation")
    if branch in operator.PROTECTED_BRANCHES:
        raise AgentWorkspaceError("writer_branch may not be protected")
    worktree = _absolute_path(writer_worktree, "writer_worktree", must_exist=False)
    if worktree == repo or worktree.is_relative_to(repo):
        raise AgentWorkspaceError("writer_worktree must be outside the canonical checkout")
    allowed = _scope_list(allowed_paths, "allowed_paths", nonempty=True)
    if any(PurePosixPath(relative).parts[0] == ".git" for relative in allowed):
        raise AgentWorkspaceError("writer scope may not include root Git metadata")
    for relative in allowed:
        target = repo.joinpath(*PurePosixPath(relative).parts)
        if target.is_symlink() or not target.exists():
            raise AgentWorkspaceError(
                f"allowed path must exist in the bound base and may not be a symlink: {relative}"
            )
        metadata = target.stat()
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise AgentWorkspaceError(f"allowed path must be a regular file or directory: {relative}")
        resolved_target = target.resolve(strict=True)
        try:
            resolved_target.relative_to(repo)
        except ValueError as exc:
            raise AgentWorkspaceError(f"allowed path escapes repository: {relative}") from exc
    forbidden = _scope_list(forbidden_paths, "forbidden_paths")
    overlaps = sorted(
        f"{left}:{right}"
        for left in allowed
        for right in forbidden
        if _contains(left, right) or _contains(right, left)
    )
    if overlaps:
        raise AgentWorkspaceError("allowed and forbidden paths overlap: " + ", ".join(overlaps[:10]))
    runtime = _positive_int(runtime_seconds, "runtime_seconds", 60, 24 * 60 * 60)
    memory = None if memory_max_bytes is None else _positive_int(
        memory_max_bytes, "memory_max_bytes", 16 * 1024 * 1024, 1024**4
    )
    workspace_id, session = _workspace_identity(kind, binding, repo, base_head)
    repo_hash = hashlib.sha256(str(repo).encode("utf-8")).hexdigest()[:20]
    lease_keys = resources.normalize_resource_keys(
        [
            f"path:{worktree}",
            f"service:agent-workspace-{workspace_id}",
            f"service:repo-writer-{repo_hash}",
        ]
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "workspace_id": workspace_id,
        "session_name": session,
        "binding": {"kind": kind, "id": binding},
        "binding_evidence": binding_evidence,
        "repository": str(repo),
        "expected_base_head": base_head,
        "writer_branch": branch,
        "writer_worktree": str(worktree),
        "scope": {"allowed_paths": allowed, "forbidden_paths": forbidden},
        "commands": {
            "writer": _role_argv(writer_argv, "writer_argv", cwd=repo),
            "tests": _role_argv(test_argv, "test_argv", cwd=repo),
            "review": _role_argv(review_argv, "review_argv", cwd=repo),
        },
        "roles": {
            "captain": {"access": "integrator_control", "merge_authority": False},
            "writer": {"access": "write_worktree", "merge_authority": False},
            "tests": {"access": "read_only", "merge_authority": False},
            "review": {"access": "read_only", "merge_authority": False},
        },
        "role_ownership": {
            "operator_may_coordinate_all_roles": True,
            "single_unisolated_agent_may_not_substitute_for_all_roles": True,
            "captain": "operator_control_plane",
            "writer": "isolated_mutating_execution",
            "tests": "deterministic_read_only_validation",
            "review": "independently_bound_read_only_review",
            "observer": "optional_read_only_process_analysis",
            "reason": "coordination may be unified, but write, validation and review evidence remain technically isolated to avoid self-confirming success",
        },
        "route_evidence": _normalize_route_evidence(route_evidence),
        "resources": {
            "owner_id": f"agent-workspace:{workspace_id}",
            "lease_keys": lease_keys,
            "runtime_seconds": runtime,
            "memory_max_bytes": memory,
            "task_host": AGENT_WORKSPACE_TASK_HOST,
        },
    }


def _pane_command(workspace_id: str, role: str) -> str:
    environment = [
        "/usr/bin/env",
        f"GRABOWSKI_AGENT_WORKSPACE_ROOT={_ensure_root()}",
        f"GRABOWSKI_TMUX_BIN={TMUX}",
    ]
    pythonpath = os.environ.get("PYTHONPATH")
    if pythonpath:
        environment.append(f"PYTHONPATH={pythonpath}")
    return shlex.join(
        [
            *environment,
            sys.executable,
            "-m",
            "grabowski_agent_workspace",
            "pane",
            workspace_id,
            role,
        ]
    )


def _created_pane_id(result: dict[str, Any], label: str) -> str:
    if result["returncode"] != 0:
        raise AgentWorkspaceActionError(str(result.get("stderr") or f"{label} failed"))
    pane_ids = [line.strip() for line in str(result.get("stdout", "")).splitlines() if line.strip()]
    if len(pane_ids) != 1 or PANE_ID_RE.fullmatch(pane_ids[0]) is None:
        raise AgentWorkspaceActionError(f"{label} did not return one valid pane id")
    return pane_ids[0]


def _create_tmux(manifest: dict[str, Any]) -> dict[str, str]:
    workspace_id = str(manifest["workspace_id"])
    session = str(manifest["session_name"])
    if _tmux_has_session(session):
        raise AgentWorkspaceError(f"tmux session already exists: {session}")
    first = _tmux_result(
        [
            "new-session", "-d", "-P", "-F", "#{pane_id}",
            "-s", session, "-n", "agents", _pane_command(workspace_id, "captain"),
        ]
    )
    session_created = first.get("returncode") == 0
    try:
        panes = {"captain": _created_pane_id(first, "tmux new-session")}
        for role in ("writer", "tests", "review"):
            result = _tmux_result(
                [
                    "split-window", "-d", "-P", "-F", "#{pane_id}",
                    "-t", f"{session}:agents", _pane_command(workspace_id, role),
                ]
            )
            panes[role] = _created_pane_id(result, "tmux split-window")
        layout = _tmux_result(["select-layout", "-t", f"{session}:agents", "tiled"])
        if layout["returncode"] != 0:
            raise AgentWorkspaceActionError(str(layout.get("stderr") or "tmux layout failed"))
        live_ids = _tmux_pane_ids(session)
        if len(live_ids) != 4 or live_ids != set(panes.values()):
            raise AgentWorkspaceActionError("tmux pane inventory does not match created roles")
        for role, pane_id in panes.items():
            titled = _tmux_result(["select-pane", "-t", pane_id, "-T", role.capitalize()])
            if titled["returncode"] != 0:
                raise AgentWorkspaceActionError(str(titled.get("stderr") or "tmux pane title failed"))
        return panes
    except Exception:
        if session_created:
            try:
                _tmux_result(["kill-session", "-t", session])
            except Exception:
                pass
        raise


def _local_branch_head(repo: Path, branch: str, runner: CommandRunner) -> str | None:
    result = runner(
        repo,
        ["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}"],
    )
    returncode = int(result.get("returncode", 1))
    if returncode == 0:
        head = str(result.get("stdout", "")).strip().lower()
        if SHA40_RE.fullmatch(head) is None:
            raise AgentWorkspaceActionError("writer branch observation returned an invalid head")
        return head
    if returncode == 1:
        return None
    detail = str(result.get("stderr") or result.get("stdout") or branch).strip()
    raise AgentWorkspaceActionError(f"writer branch observation failed: {detail[:2000]}")


def _remove_created_worktree(
    repo: Path,
    worktree: Path,
    branch: str,
    expected_base_head: str,
    runner: CommandRunner,
) -> bool:
    if worktree.exists():
        status = runner(worktree, ["git", "status", "--porcelain=v1", "--untracked-files=all"])
        if int(status.get("returncode", 1)) != 0 or str(status.get("stdout", "")).strip():
            return False
        worktree_head = _git_head(runner, worktree)
        if worktree_head != expected_base_head:
            return False
        removed = runner(repo, ["git", "worktree", "remove", str(worktree)])
        if int(removed.get("returncode", 1)) != 0 or worktree.exists():
            return False
    branch_head = _local_branch_head(repo, branch, runner)
    if branch_head is not None:
        if branch_head != expected_base_head:
            return False
        deleted = runner(repo, ["git", "branch", "-D", branch])
        if int(deleted.get("returncode", 1)) != 0:
            return False
    return not worktree.exists() and _local_branch_head(repo, branch, runner) is None

def _role_receipt_path(manifest: dict[str, Any], role: str, *, attempt: int = 1) -> Path:
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise AgentWorkspaceError("attempt must be a positive integer")
    name = f"{role}-receipt.json" if attempt == 1 else f"{role}-receipt.attempt-{attempt}.json"
    return _workspace_dir(str(manifest["workspace_id"])) / name


def _role_final_attempt(manifest: dict[str, Any], role: str) -> int:
    attempts = manifest.get("role_final_attempt")
    if isinstance(attempts, dict):
        value = attempts.get(role)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            return value
    return 1


def _role_attempt_record(
    manifest: dict[str, Any], role: str, attempt: int
) -> dict[str, Any] | None:
    """Return exactly one persisted retry record for one concrete role attempt."""
    retries = manifest.get("role_retries")
    if not isinstance(retries, dict):
        return None
    role_retry = retries.get(role)
    if not isinstance(role_retry, dict):
        return None
    attempts = role_retry.get("attempts")
    if not isinstance(attempts, list):
        return None
    matches = [
        item
        for item in attempts
        if isinstance(item, dict)
        and item.get("attempt") == attempt
        and not isinstance(item.get("attempt"), bool)
    ]
    return matches[0] if len(matches) == 1 else None


def _expected_role_argv_sha256(
    manifest: dict[str, Any], role: str, *, attempt: int | None = None
) -> str | None:
    """Return the command hash bound to the selected concrete role attempt."""
    resolved_attempt = _role_final_attempt(manifest, role) if attempt is None else attempt
    retry_record = _role_attempt_record(manifest, role, resolved_attempt)
    if retry_record is not None:
        candidate = retry_record.get("new_command_sha256")
        if isinstance(candidate, str) and SHA256_RE.fullmatch(candidate):
            return candidate
        return None
    if resolved_attempt == 1:
        return _sha256_json(manifest["commands"][role])
    return None


def _writer_patch_path(manifest: dict[str, Any]) -> Path:
    return _workspace_dir(str(manifest["workspace_id"])) / "writer.patch"


def _writer_task_argv(manifest: dict[str, Any]) -> list[str]:
    allowed_arguments = [
        value
        for relative in manifest["scope"]["allowed_paths"]
        for value in ("--allowed-path", str(relative))
    ]
    return [
        sys.executable,
        "-m",
        "grabowski_agent_writer",
        "--repository",
        str(manifest["writer_worktree"]),
        "--expected-base-head",
        str(manifest["expected_base_head"]),
        "--expected-branch",
        str(manifest["writer_branch"]),
        *allowed_arguments,
        "--output",
        str(_role_receipt_path(manifest, "writer")),
        "--",
        *list(manifest["commands"]["writer"]),
    ]


def _role_task_argv(
    manifest: dict[str, Any],
    role: str,
    head: str,
    diff_sha256: str,
    dirty: bool,
    *,
    command: list[str] | None = None,
    output_path: Path | None = None,
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "grabowski_agent_role",
        "--role",
        role,
        "--repository",
        str(manifest["writer_worktree"]),
        "--expected-head",
        head,
        "--expected-base-head",
        str(manifest["expected_base_head"]),
        "--expected-diff-sha256",
        diff_sha256,
        "--expected-dirty",
        "true" if dirty else "false",
        "--output",
        str(output_path if output_path is not None else _role_receipt_path(manifest, role)),
        "--",
        *(list(command) if command is not None else list(manifest["commands"][role])),
    ]


def _safe_untracked_file(root: Path, relative: PurePosixPath) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise AgentWorkspaceActionError("git returned an unsafe untracked path")
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise AgentWorkspaceActionError(f"untracked path is not stable: {relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise AgentWorkspaceActionError(f"untracked path crosses a symlink: {relative}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AgentWorkspaceActionError(f"untracked path must be one regular non-hardlinked file: {relative}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise AgentWorkspaceActionError(f"untracked path escapes writer worktree: {relative}") from exc
    return resolved


def _writer_create_identity(manifest: dict[str, Any], runner: CommandRunner) -> dict[str, Any]:
    worktree = Path(str(manifest["writer_worktree"]))
    if not worktree.is_dir() or _repo_top(runner, worktree) != worktree:
        raise AgentWorkspaceActionError("writer worktree is missing or no longer canonical")
    head = _git_head(runner, worktree)
    branch_result = _checked(
        runner,
        worktree,
        ["git", "branch", "--show-current"],
        label="writer branch",
    )
    branch = str(branch_result.get("stdout", "")).strip()
    return {
        "writer_worktree": str(worktree),
        "writer_head": head,
        "writer_branch": branch,
        "writer_branch_matches": branch == manifest["writer_branch"],
    }


def _git_snapshot(manifest: dict[str, Any], runner: CommandRunner) -> dict[str, Any]:
    worktree = Path(str(manifest["writer_worktree"]))
    repo = Path(str(manifest["repository"]))
    base_head = str(manifest["expected_base_head"])
    if not worktree.is_dir() or _repo_top(runner, worktree) != worktree:
        raise AgentWorkspaceActionError("writer worktree is missing or no longer canonical")
    head = _git_head(runner, worktree)
    branch_result = _checked(
        runner, worktree, ["git", "branch", "--show-current"], label="writer branch"
    )
    branch = str(branch_result.get("stdout", "")).strip()
    status_result = _checked_bytes(
        worktree,
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        label="writer status",
    )
    status_lines = [os.fsdecode(item) for item in bytes(status_result["stdout"]).split(b"\x00") if item]
    committed_diff = _checked_bytes(
        worktree,
        ["git", "diff", "--binary", "--no-ext-diff", "--no-textconv", f"{base_head}...{head}"],
        label="committed diff",
    )
    working_diff = _checked_bytes(
        worktree,
        ["git", "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD"],
        label="working diff",
    )
    changed_result = _checked_bytes(
        worktree,
        ["git", "diff", "--name-only", "-z", "--no-renames", f"{base_head}...{head}"],
        label="changed paths",
    )
    working_changed = _checked_bytes(
        worktree,
        ["git", "diff", "--name-only", "-z", "--no-renames", "HEAD"],
        label="working changed paths",
    )
    untracked_result = _checked_bytes(
        worktree,
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        label="untracked files",
    )
    untracked: list[dict[str, Any]] = []
    total = 0
    for raw in bytes(untracked_result["stdout"]).split(b"\x00"):
        if not raw:
            continue
        relative = PurePosixPath(os.fsdecode(raw))
        target = _safe_untracked_file(worktree, relative)
        metadata = target.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_UNTRACKED_FILE_BYTES:
            raise AgentWorkspaceActionError(f"untracked file exceeds safety boundary: {relative}")
        total += metadata.st_size
        if total > MAX_UNTRACKED_TOTAL_BYTES:
            raise AgentWorkspaceActionError("untracked files exceed aggregate safety boundary")
        digest_value = hashlib.sha256(target.read_bytes()).hexdigest()
        untracked.append({"path": relative.as_posix(), "size": metadata.st_size, "sha256": digest_value})
    changed = sorted(
        {
            os.fsdecode(raw)
            for payload in (bytes(changed_result["stdout"]), bytes(working_changed["stdout"]))
            for raw in payload.split(b"\x00")
            if raw
        }
        | {item["path"] for item in untracked}
    )
    scope = manifest["scope"]
    violations: list[dict[str, str]] = []
    for path in changed:
        if any(_contains(item, path) for item in scope["forbidden_paths"]):
            violations.append({"path": path, "reason": "forbidden_path"})
        elif not any(_contains(item, path) for item in scope["allowed_paths"]):
            violations.append({"path": path, "reason": "outside_allowed_paths"})
    payload = {
        "base_head": base_head,
        "head": head,
        "branch": branch,
        "committed_diff_sha256": hashlib.sha256(bytes(committed_diff["stdout"])).hexdigest(),
        "working_diff_sha256": hashlib.sha256(bytes(working_diff["stdout"])).hexdigest(),
        "untracked": untracked,
    }
    diff_sha256 = _sha256_json(payload)
    canonical_head = _git_head(runner, repo)
    conflict = None
    if canonical_head != base_head:
        probe = runner(repo, ["git", "merge-tree", "--write-tree", canonical_head, head])
        conflict = {
            "returncode": probe.get("returncode"),
            "conflicting": int(probe.get("returncode", 1)) != 0,
            "stdout": str(probe.get("stdout", ""))[:4000],
            "stderr": str(probe.get("stderr", ""))[:4000],
        }
    return {
        "expected_base_head": base_head,
        "canonical_head": canonical_head,
        "base_drift": canonical_head != base_head,
        "writer_head": head,
        "writer_branch": branch,
        "writer_branch_matches": branch == manifest["writer_branch"],
        "writer_has_commit": head != base_head,
        "writer_worktree": str(worktree),
        "dirty": bool(status_lines),
        "result_type": "patch" if status_lines and head == base_head else "none",
        "status_lines": status_lines,
        "changed_paths": changed,
        "scope_violations": violations,
        "scope_passed": not violations,
        "untracked_artifacts": untracked,
        "diff_sha256": diff_sha256,
        "integration_probe": conflict,
    }


def _writer_freeze_binding(snapshot: dict[str, Any]) -> str:
    return _sha256_json(
        {
            key: snapshot.get(key)
            for key in (
                "expected_base_head",
                "canonical_head",
                "base_drift",
                "writer_head",
                "writer_branch",
                "writer_branch_matches",
                "dirty",
                "result_type",
                "changed_paths",
                "scope_violations",
                "scope_passed",
                "diff_sha256",
            )
        }
    )


def _settled_writer_snapshot(
    manifest: dict[str, Any],
    baseline: dict[str, Any],
    runner: CommandRunner,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[bool, dict[str, Any]]:
    expected = _writer_freeze_binding(baseline)
    immediate = _git_snapshot(manifest, runner)
    if _writer_freeze_binding(immediate) != expected:
        return False, immediate
    sleep(WRITER_FREEZE_SETTLE_SECONDS)
    settled = _git_snapshot(manifest, runner)
    if _writer_freeze_binding(settled) != expected:
        return False, settled
    return True, settled


def _materialize_writer_patch(
    manifest: dict[str, Any],
    snapshot: dict[str, Any],
    runner: CommandRunner,
) -> dict[str, Any]:
    del runner
    if snapshot.get("result_type") != "patch":
        raise AgentWorkspaceError("writer patch requested for a non-patch result")
    worktree = Path(str(manifest["writer_worktree"]))
    base_head = str(manifest["expected_base_head"])
    tracked = _checked_bytes(
        worktree,
        ["git", "diff", "--binary", "--no-ext-diff", "--no-textconv", base_head, "--"],
        label="writer full tracked patch",
    )
    def patch_chunks() -> Iterable[bytes]:
        yield bytes(tracked["stdout"])
        for item in snapshot.get("untracked_artifacts", []):
            relative = str(item["path"])
            result = _run_bytes(
                worktree,
                [
                    "git", "diff", "--no-index", "--binary", "--no-ext-diff", "--no-textconv",
                    "--src-prefix=a/", "--dst-prefix=b/",
                    "--", "/dev/null", relative,
                ],
            )
            rc = int(result.get("returncode", 1))
            if rc not in {0, 1}:
                raw = result.get("stderr") or result.get("stdout") or relative.encode("utf-8")
                detail = bytes(raw).decode("utf-8", errors="replace").strip()
                raise AgentWorkspaceActionError(f"untracked patch generation failed: {detail[:2000]}")
            yield bytes(result.get("stdout", b""))

    path = _writer_patch_path(manifest)
    payload_bytes, payload_sha256 = _atomic_bounded_chunks(
        path,
        patch_chunks(),
        max_bytes=MAX_PATCH_BYTES,
    )
    return {
        "type": "patch",
        "path": str(path),
        "sha256": payload_sha256,
        "bytes": payload_bytes,
        "applies_to": base_head,
    }


def _verify_patch_artifact(
    result: dict[str, Any],
    *,
    expected_path: Path | None = None,
) -> bool:
    path_value = result.get("path")
    expected = result.get("sha256")
    expected_bytes = result.get("bytes")
    if (
        not isinstance(path_value, str)
        or SHA256_RE.fullmatch(str(expected)) is None
        or isinstance(expected_bytes, bool)
        or not isinstance(expected_bytes, int)
        or not 0 < expected_bytes <= MAX_PATCH_BYTES
    ):
        return False
    path = Path(path_value)
    if expected_path is not None and path != expected_path:
        return False
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size != expected_bytes
        ):
            return False
        owned_descriptor = descriptor
        descriptor = -1
        try:
            handle = _fdopen_owned(owned_descriptor, "rb")
        except OSError:
            return False
        digest = hashlib.sha256()
        total = 0
        with handle:
            while chunk := handle.read(1024 * 1024):
                total += len(chunk)
                if total > expected_bytes:
                    return False
                digest.update(chunk)
        return total == expected_bytes and digest.hexdigest() == expected
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _receipt_integrity(value: dict[str, Any]) -> bool:
    expected = value.get("receipt_sha256")
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        return False
    stable = {key: item for key, item in value.items() if key != "receipt_sha256"}
    return _sha256_json(stable) == expected


def _collection_result_sha256(value: dict[str, Any]) -> str:
    stable = {key: item for key, item in value.items() if key != "result_sha256"}
    return _sha256_json(stable)


def _collection_integrity_status(
    manifest: dict[str, Any],
    collection: Any,
) -> dict[str, Any]:
    result = {
        "valid": False,
        "hash_valid": False,
        "receipt_present": False,
        "receipt_matches_manifest": False,
    }
    if not isinstance(collection, dict):
        return result
    expected = collection.get("result_sha256")
    result["hash_valid"] = bool(
        isinstance(expected, str)
        and SHA256_RE.fullmatch(expected) is not None
        and _collection_result_sha256(collection) == expected
    )
    path = _workspace_dir(str(manifest["workspace_id"])) / "collection-receipt.json"
    if not path.exists():
        return result
    try:
        receipt = _load_json(path)
    except Exception as exc:
        result["error"] = _error_summary(exc)
        return result
    result["receipt_present"] = True
    result["receipt_matches_manifest"] = receipt == collection
    result["valid"] = bool(result["hash_valid"] and result["receipt_matches_manifest"])
    return result


def _close_integrity_status(manifest: dict[str, Any], receipt: Any) -> dict[str, Any]:
    result = {
        "valid": False,
        "hash_valid": False,
        "receipt_present": False,
        "receipt_matches_manifest": False,
    }
    if not isinstance(receipt, dict):
        return result
    result["hash_valid"] = _receipt_integrity(receipt)
    path = _workspace_dir(str(manifest["workspace_id"])) / "close-receipt.json"
    if not path.exists():
        return result
    try:
        stored = _load_json(path)
    except Exception as exc:
        result["error"] = _error_summary(exc)
        return result
    result["receipt_present"] = True
    result["receipt_matches_manifest"] = stored == receipt
    result["valid"] = bool(result["hash_valid"] and result["receipt_matches_manifest"])
    return result


def _role_receipt(manifest: dict[str, Any], role: str, *, attempt: int | None = None) -> dict[str, Any] | None:
    resolved_attempt = _role_final_attempt(manifest, role) if attempt is None else attempt
    path = _role_receipt_path(manifest, role, attempt=resolved_attempt)
    return _load_json(path) if path.exists() else None


def _role_start_intent_classification(
    manifest: dict[str, Any], role: str
) -> tuple[str, dict[str, Any]] | None:
    start_intents = manifest.get("task_start_intents", {})
    if not isinstance(start_intents, dict):
        return "role_start_intents_invalid", {}
    if role in start_intents:
        return "role_start_outcome_unknown", {
            "task_start_intent": start_intents[role],
            "reconcile_required": True,
        }
    return None


def _role_retry_classification(
    manifest: dict[str, Any], role: str, frozen: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    """Classify whether one read-only role may be retried, and why."""
    start_intent = _role_start_intent_classification(manifest, role)
    if start_intent is not None:
        return start_intent
    task_id = manifest.get("tasks", {}).get(role)
    if task_id is None:
        blocks = manifest.get("role_preflight_blocks", {})
        role_blocks = blocks.get(role) if isinstance(blocks, dict) else None
        if isinstance(role_blocks, list) and role_blocks:
            latest = role_blocks[-1]
            if isinstance(latest, dict) and latest.get("failure_classification") == "environment_toolchain_failure":
                return "eligible", {
                    "prior_failure_classification": "toolchain_preflight_blocked",
                    "prior_preflight": latest,
                    "prior_attempt_consumed": False,
                }
            return "preflight_probe_error", {"prior_preflight": latest}
        return "not_attempted", {}
    task_public = _task_public(task_id)
    if not task_public["terminal"]:
        return "role_running", {"task": task_public}
    if task_public["state"] in {"observation_error", "outcome_unknown", "interrupted"}:
        return "unknown_prior_outcome", {"task": task_public}
    receipt = _role_receipt(manifest, role)
    if receipt is None:
        return "unknown_prior_outcome", {"task": task_public}
    if (
        not _receipt_integrity(receipt)
        or receipt.get("role") != role
        or receipt.get("expected_head") != frozen.get("writer_head")
        or receipt.get("expected_base_head") != manifest.get("expected_base_head")
        or receipt.get("expected_diff_sha256") != frozen.get("diff_sha256")
        or receipt.get("expected_dirty") != frozen.get("dirty")
        or receipt.get("head_before") != frozen.get("writer_head")
        or receipt.get("head_after") != frozen.get("writer_head")
        or receipt.get("diff_after") != frozen.get("diff_sha256")
        or receipt.get("worktree_dirty_after") != frozen.get("dirty")
        or receipt.get("argv_sha256") != _expected_role_argv_sha256(manifest, role)
        or receipt.get("sandbox") != agent_role.SANDBOX_LABEL
    ):
        return "invalid_receipt", {"receipt_present": True}
    returncode = receipt.get("returncode")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        return "invalid_receipt", {"receipt_present": True}
    failure_classification = receipt.get("failure_classification")
    environment_detail: dict[str, Any] | None = None
    if failure_classification == "environment_toolchain_failure" and returncode != 0:
        environment_detail = {"typed_failure_classification": failure_classification}
    if environment_detail is not None:
        return "eligible", {
            "prior_failure_classification": "environment_toolchain_failure",
            "previous_task_id": task_id,
            "previous_receipt_sha256": receipt.get("receipt_sha256"),
            "prior_attempt_consumed": True,
            **environment_detail,
        }
    if returncode == 0 and task_public.get("state") != "completed":
        return "unknown_prior_outcome", {"task": task_public}
    if role == "tests":
        if returncode == 0:
            return "already_succeeded", {"receipt_sha256": receipt.get("receipt_sha256")}
        return "semantic_test_failure", {
            "receipt_sha256": receipt.get("receipt_sha256"),
            "returncode": returncode,
            "failure_classification": failure_classification,
        }
    verdict = receipt.get("verdict")
    if verdict == "PASS" and returncode == 0:
        return "already_succeeded", {"receipt_sha256": receipt.get("receipt_sha256")}
    if verdict in {"NEEDS_CHANGE", "BLOCK"}:
        return "review_verdict_blocks_retry", {
            "verdict": verdict,
            "receipt_sha256": receipt.get("receipt_sha256"),
        }
    return "invalid_receipt", {
        "verdict": verdict,
        "receipt_sha256": receipt.get("receipt_sha256"),
        "failure_classification": failure_classification,
    }

def _collection_incomplete_roles(collection: Any) -> list[str]:
    if not isinstance(collection, dict) or collection.get("state") != "complete":
        return list(READ_ONLY_ROLES)
    incomplete: list[str] = []
    tests = collection.get("tests")
    if not (
        isinstance(tests, dict)
        and tests.get("status") in {"passed", "failed"}
        and isinstance(tests.get("returncode"), int)
        and not isinstance(tests.get("returncode"), bool)
        and isinstance(tests.get("receipt_sha256"), str)
        and SHA256_RE.fullmatch(tests["receipt_sha256"]) is not None
    ):
        incomplete.append("tests")
    review = collection.get("review")
    if not (
        isinstance(review, dict)
        and review.get("status") in {"passed", "failed"}
        and isinstance(review.get("returncode"), int)
        and not isinstance(review.get("returncode"), bool)
        and review.get("verdict") in {"PASS", "NEEDS_CHANGE", "BLOCK", "INVALID"}
        and isinstance(review.get("findings"), list)
        and all(isinstance(item, dict) for item in review["findings"])
        and isinstance(review.get("receipt_sha256"), str)
        and SHA256_RE.fullmatch(review["receipt_sha256"]) is not None
    ):
        incomplete.append("review")
    return incomplete


def _collection_failed_roles(collection: Any) -> list[str]:
    if _collection_incomplete_roles(collection):
        return []
    failed: list[str] = []
    tests = collection["tests"]
    if tests["status"] != "passed" or tests["returncode"] != 0:
        failed.append("tests")
    review = collection["review"]
    if (
        review["status"] != "passed"
        or review["returncode"] != 0
        or review["verdict"] != "PASS"
        or review["findings"]
    ):
        failed.append("review")
    return failed


def _role_retry_state(
    manifest: dict[str, Any], role: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Return one structurally valid retry state or a fail-closed error."""
    retries = manifest.get("role_retries", {})
    if not isinstance(retries, dict):
        return None, "role_retries_not_object"
    raw = retries.get(role)
    if raw is None:
        return {"count": 0, "attempts": []}, None
    if not isinstance(raw, dict):
        return None, "role_retry_state_not_object"
    count = raw.get("count", 0)
    attempts = raw.get("attempts", [])
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or not isinstance(attempts, list)
        or count != len(attempts)
        or any(not isinstance(item, dict) for item in attempts)
    ):
        return None, "role_retry_state_invalid"
    return {**raw, "count": count, "attempts": list(attempts)}, None


def _status_role_retry(manifest: dict[str, Any]) -> dict[str, Any]:
    frozen = manifest.get("frozen_writer")
    result: dict[str, Any] = {}
    for role_name in READ_ONLY_ROLES:
        if not isinstance(frozen, dict):
            result[role_name] = {"classification": "not_collected", "eligible": False}
            continue
        classification, detail = _role_retry_classification(manifest, role_name, frozen)
        role_retry_state, retry_state_error = _role_retry_state(manifest, role_name)
        if retry_state_error is not None or role_retry_state is None:
            result[role_name] = {
                "classification": "retry_state_invalid",
                "eligible": False,
                "retries_used": None,
                "max_retries": MAX_ROLE_RETRIES,
                "error": retry_state_error,
                **detail,
            }
            continue
        retries_used = role_retry_state["count"]
        eligible = classification == "eligible" and retries_used < MAX_ROLE_RETRIES
        effective_classification = classification
        if classification == "eligible" and not eligible:
            effective_classification = "retry_limit_reached"
        result[role_name] = {
            "classification": effective_classification,
            "eligible": eligible,
            "retries_used": retries_used,
            "max_retries": MAX_ROLE_RETRIES,
            **detail,
        }
    return result


def _prospective_closure_outcome(manifest: dict[str, Any], collection: Any) -> str:
    close_receipt = manifest.get("close_receipt")
    if isinstance(close_receipt, dict):
        if not _close_integrity_status(manifest, close_receipt)["valid"]:
            return "unknown"
        outcome = close_receipt.get("closure_outcome")
        return outcome if isinstance(outcome, str) else "unknown"
    if not isinstance(collection, dict) or collection.get("state") != "complete":
        return "not_ready"
    if _collection_incomplete_roles(collection):
        return "incomplete_role_evidence"
    return "would_abandon_failed_roles" if _collection_failed_roles(collection) else "would_be_successful"


def _recommended_next_action(
    *,
    creation_ready: bool,
    closed: bool,
    route_gate_passed: bool,
    closeable: bool,
    success_ready: bool,
    role_retry: dict[str, Any],
    failed_roles: list[str],
    incomplete_roles: list[str],
) -> str:
    if closed:
        return "none_closed"
    if not creation_ready:
        return "await_creation"
    if not route_gate_passed:
        return "recreate_with_route_evidence"
    if any(
        value.get("classification") == "role_start_outcome_unknown"
        for value in role_retry.values()
        if isinstance(value, dict)
    ):
        return "reconcile_role_start_outcome"
    for role_name in sorted(role_retry):
        if role_retry[role_name].get("eligible"):
            return f"retry_role:{role_name}"
    if incomplete_roles:
        return "recollect_or_reconcile_incomplete_role_evidence"
    if not closeable:
        return "await_collection_or_reconcile"
    if success_ready:
        return "close"
    if failed_roles:
        return "close_with_abandon_failed_roles"
    return "collect"


def _external_closeout_checklist(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    close_receipt = manifest.get("close_receipt")
    close_valid = bool(
        isinstance(close_receipt, dict)
        and _close_integrity_status(manifest, close_receipt)["valid"]
    )
    lease_verified = bool(
        close_valid
        and close_receipt.get("state") == "complete"
        and close_receipt.get("resources_released") is True
        and not close_receipt.get("remaining_resource_keys")
    )
    return [
        {
            "item": "pr_integration_truth",
            "description": (
                "Confirm pull request and branch integration truth with Git/GitHub tools; "
                "this workspace only observes local Git state, never merge or PR status."
            ),
            "status": "unknown",
            "source_of_truth": "git_github",
        },
        {
            "item": "bureau_task_reconciliation",
            "description": (
                "Reconcile the bound Bureau binding or task with Bureau directly; "
                "binding_evidence is a point-in-time snapshot, not live truth."
            ),
            "status": "unknown",
            "source_of_truth": "bureau",
            "binding": manifest.get("binding"),
        },
        {
            "item": "workspace_lease_release",
            "description": (
                "Release this workspace's resource leases via close, or verify manual release; "
                "leases block conflicting writers until released."
            ),
            "status": "verified" if lease_verified else "unknown",
            "source_of_truth": "grabowski_resources",
            "evidence": (
                {
                    "close_receipt_sha256": close_receipt.get("receipt_sha256"),
                    "resources_released": True,
                }
                if lease_verified
                else None
            ),
        },
        {
            "item": "writer_worktree_archive_or_cleanup",
            "description": (
                "Archive or remove the preserved writer worktree and branch with the checkout tools; "
                "close never deletes them."
            ),
            "status": "unknown",
            "source_of_truth": "grabowski_checkouts",
        },
        {
            "item": "operator_final_summary",
            "description": (
                "Publish an operator-facing final summary of this workspace's outcome; "
                "Agent Workspace v1 does not itself produce or track one."
            ),
            "status": "unknown",
            "source_of_truth": "operator",
        },
    ]


OUTCOME_RECEIPT_PHASES = frozenset({"collection", "close"})


def _outcome_identity(manifest: dict[str, Any], phase: str) -> str:
    if phase == "collection":
        collection = manifest.get("collection")
        identity = collection.get("result_sha256") if isinstance(collection, dict) else None
    elif phase == "close":
        close_receipt = manifest.get("close_receipt")
        identity = close_receipt.get("receipt_sha256") if isinstance(close_receipt, dict) else None
    else:
        raise AgentWorkspaceError("workspace outcome phase is invalid")
    if not isinstance(identity, str) or SHA256_RE.fullmatch(identity) is None:
        raise AgentWorkspaceError("workspace outcome identity is unavailable or invalid")
    return identity


def _outcome_receipt_path(manifest: dict[str, Any], phase: str) -> Path:
    identity = _outcome_identity(manifest, phase)
    return (
        _workspace_dir(str(manifest["workspace_id"]))
        / f"outcome-receipt.{phase}.{identity}.json"
    )


def _elapsed_seconds(started_at: Any, ended_at: Any) -> int | None:
    if not isinstance(started_at, str) or not isinstance(ended_at, str):
        return None
    try:
        started = datetime.fromisoformat(started_at)
        ended = datetime.fromisoformat(ended_at)
    except ValueError:
        return None
    seconds = int((ended - started).total_seconds())
    return seconds if seconds >= 0 else None


def _role_attempt_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for role in ("writer", "tests", "review"):
        final_attempt = 1 if role == "writer" else _role_final_attempt(manifest, role)
        retry_state, retry_error = (
            ({"count": 0, "attempts": []}, None)
            if role == "writer"
            else _role_retry_state(manifest, role)
        )
        summary[role] = {
            "final_attempt": final_attempt,
            "retries_used": (
                retry_state.get("count")
                if isinstance(retry_state, dict) and retry_error is None
                else None
            ),
            "retry_state_valid": retry_error is None,
        }
    return summary


def _first_pass_role_results(
    manifest: dict[str, Any], collection: dict[str, Any]
) -> dict[str, Any]:
    writer = {
        "state": (
            collection.get("writer_task", {}).get("state")
            if isinstance(collection.get("writer_task"), dict)
            else None
        ),
        "receipt_sha256": collection.get("writer_receipt_sha256"),
    }
    result: dict[str, Any] = {"writer": writer}
    for role in ("tests", "review"):
        receipt = _role_receipt(manifest, role, attempt=1)
        if not isinstance(receipt, dict) or not _receipt_integrity(receipt):
            result[role] = {
                "status": "missing",
                "returncode": None,
                "receipt_sha256": None,
            }
            continue
        returncode = receipt.get("returncode")
        item: dict[str, Any] = {
            "status": "passed" if returncode == 0 else "failed",
            "returncode": returncode,
            "receipt_sha256": receipt.get("receipt_sha256"),
        }
        if role == "review":
            item["verdict"] = receipt.get("verdict")
            findings = receipt.get("findings")
            item["finding_count"] = len(findings) if isinstance(findings, list) else None
        result[role] = item
    return result


def _workspace_event_type_counts(
    manifest: dict[str, Any],
) -> tuple[dict[str, int], bool]:
    workspace_id = _required_string(
        manifest.get("workspace_id"), "workspace_id", max_length=80
    )
    path = _event_log_path(workspace_id)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return {}, False
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_WORKSPACE_EVENT_BYTES
    ):
        raise AgentWorkspaceError("workspace event log is unsafe or oversized")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise PermissionError("workspace event log descriptor is unsafe")
        raw = os.read(descriptor, MAX_WORKSPACE_EVENT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_WORKSPACE_EVENT_BYTES:
        raise AgentWorkspaceError("workspace event log byte limit reached")
    counts: dict[str, int] = {}
    expected = 1
    for line in raw.splitlines():
        if not line:
            continue
        if expected > MAX_WORKSPACE_EVENTS:
            raise AgentWorkspaceError("workspace event count limit reached")
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentWorkspaceError("workspace event log contains invalid JSON") from exc
        if not isinstance(event, dict):
            raise AgentWorkspaceError("workspace event log contains a non-object")
        observed_hash = event.get("event_sha256")
        unsigned = {key: value for key, value in event.items() if key != "event_sha256"}
        if (
            event.get("schema_version") != 1
            or event.get("workspace_id") != workspace_id
            or event.get("sequence") != expected
            or not isinstance(observed_hash, str)
            or observed_hash != _sha256_json(unsigned)
        ):
            raise AgentWorkspaceError("workspace event log integrity is invalid")
        event_type = event.get("event_type")
        if isinstance(event_type, str):
            counts[event_type] = counts.get(event_type, 0) + 1
        expected += 1
    return counts, True


def _known_workspace_tool_calls(manifest: dict[str, Any], phase: str) -> dict[str, Any]:
    retries = manifest.get("role_retries")
    retry_count = 0
    if isinstance(retries, dict):
        for value in retries.values():
            if isinstance(value, dict):
                count = value.get("count")
                if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                    retry_count += count
    event_counts, event_bound = _workspace_event_type_counts(manifest)
    calls = {
        "create": event_counts.get("plan_created", 1),
        "collect": event_counts.get("collection_requested", 1),
        "role_retry": event_counts.get("retry_decision", retry_count),
        "close": (
            event_counts.get("close_requested", 1) if phase == "close" else 0
        ),
    }
    return {
        "known_mutating_calls": calls,
        "known_mutating_call_count": sum(calls.values()),
        "counting_basis": (
            "integrity_valid_workspace_event_log"
            if event_bound
            else "legacy_conservative_minimum"
        ),
        "event_log_integrity_bound": event_bound,
        "role_task_ids": {
            role: task_id
            for role, task_id in manifest.get("tasks", {}).items()
            if role in {"writer", "tests", "review"}
        },
        "read_only_status_attach_observe_calls_tracked": False,
    }


def _route_gate(manifest: dict[str, Any]) -> tuple[dict[str, Any], bool, bool]:
    if "route_evidence" not in manifest:
        return (
            {
                "schema_version": 1,
                "status": "legacy_absent",
                "recommendation_id": None,
                "score": None,
                "recommended_route": None,
                "actual_route": "full_workspace",
                "input_facts": None,
                "external_candidates": [],
                "deviation_reason": None,
                "evidence_complete": False,
            },
            True,
            True,
        )
    route = manifest.get("route_evidence")
    complete = bool(
        isinstance(route, dict)
        and route.get("status") == "verified"
        and route.get("evidence_complete") is True
    )
    return (dict(route) if isinstance(route, dict) else {}, complete, False)


def _publish_workspace_outcome(
    manifest: dict[str, Any],
    phase: str,
) -> dict[str, Any]:
    if phase not in OUTCOME_RECEIPT_PHASES:
        raise AgentWorkspaceError("workspace outcome phase is invalid")
    collection = manifest.get("collection")
    if not isinstance(collection, dict) or collection.get("state") != "complete":
        raise AgentWorkspaceError("workspace outcome requires a complete collection")
    close_receipt = manifest.get("close_receipt") if phase == "close" else None
    if phase == "close" and (
        not isinstance(close_receipt, dict)
        or close_receipt.get("state") != "complete"
        or not _close_integrity_status(manifest, close_receipt)["valid"]
    ):
        raise AgentWorkspaceError("close outcome requires a valid complete close receipt")
    recorded_at = (
        close_receipt.get("closed_at")
        if isinstance(close_receipt, dict)
        else collection.get("collected_at")
    )
    checklist = _external_closeout_checklist(manifest)
    route_evidence, route_complete, legacy_route = _route_gate(manifest)
    first_pass = _first_pass_role_results(manifest, collection)
    elapsed = _elapsed_seconds(manifest.get("created_at"), recorded_at)
    frozen_identity = {
        "expected_base_head": collection.get("expected_base_head"),
        "writer_head": collection.get("writer_head"),
        "diff_sha256": collection.get("diff_sha256"),
        "result_sha256": collection.get("result_sha256"),
        "writer_patch_sha256": (
            collection.get("writer_result", {}).get("sha256")
            if isinstance(collection.get("writer_result"), dict)
            else None
        ),
    }
    missing_fields: list[str] = []
    if not route_complete:
        missing_fields.append("route_evidence")
    if elapsed is None:
        missing_fields.append("elapsed_seconds")
    if not isinstance(recorded_at, str) or not recorded_at:
        missing_fields.append("recorded_at")
    for field, pattern in (
        ("expected_base_head", SHA40_RE),
        ("writer_head", SHA40_RE),
        ("diff_sha256", SHA256_RE),
        ("result_sha256", SHA256_RE),
        ("writer_patch_sha256", SHA256_RE),
    ):
        value = frozen_identity[field]
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            missing_fields.append(f"frozen_result_identity.{field}")
    for role in ("writer", "tests", "review"):
        receipt_hash = first_pass.get(role, {}).get("receipt_sha256")
        if not isinstance(receipt_hash, str) or SHA256_RE.fullmatch(receipt_hash) is None:
            missing_fields.append(f"first_pass_role_results.{role}.receipt_sha256")
    receipt = {
        "schema_version": 2,
        "kind": "agent_workspace_outcome",
        "workspace_id": manifest["workspace_id"],
        "phase": phase,
        "outcome_identity": _outcome_identity(manifest, phase),
        "recorded_at": recorded_at,
        "binding": manifest.get("binding"),
        "route_evidence": route_evidence,
        "route_legacy_compatibility": legacy_route,
        "first_pass_role_results": first_pass,
        "final_role_results": {
            "writer": first_pass["writer"],
            "tests": dict(collection.get("tests", {})) if isinstance(collection.get("tests"), dict) else {},
            "review": dict(collection.get("review", {})) if isinstance(collection.get("review"), dict) else {},
        },
        "role_attempts": _role_attempt_summary(manifest),
        "elapsed_seconds": elapsed,
        "tool_calls": _known_workspace_tool_calls(manifest, phase),
        "frozen_result_identity": frozen_identity,
        "integration_or_salvage_outcome": (
            "workspace_closed_patch_preserved_external_truth_pending"
            if phase == "close"
            else "collection_complete_external_truth_pending"
        ),
        "closure_outcome": (
            close_receipt.get("closure_outcome")
            if isinstance(close_receipt, dict)
            else None
        ),
        "external_closeout_completion": [
            {
                "item": item.get("item"),
                "status": item.get("status"),
                "source_of_truth": item.get("source_of_truth"),
            }
            for item in checklist
            if isinstance(item, dict)
        ],
        "evidence_complete": not missing_fields,
        "missing_fields": sorted(missing_fields),
        "missing_fields_fail_closed": True,
        "does_not_establish": [
            "pull request integration",
            "Bureau reconciliation",
            "writer checkout cleanup",
            "operator final summary",
            "read-only tool call count",
            "general productivity improvement",
        ],
    }
    receipt["outcome_sha256"] = _sha256_json(receipt)
    path = _outcome_receipt_path(manifest, phase)
    if path.exists():
        existing = _load_json(path)
        if existing != receipt:
            raise AgentWorkspaceError("existing workspace outcome receipt differs from deterministic outcome")
    else:
        _atomic_json(path, receipt)
    references = dict(manifest.get("outcome_receipts", {}))
    current = references.get(phase)
    history = list(current.get("history", [])) if isinstance(current, dict) and isinstance(current.get("history"), list) else []
    reference = {
        "path": str(path),
        "outcome_identity": receipt["outcome_identity"],
        "outcome_sha256": receipt["outcome_sha256"],
    }
    if not any(
        isinstance(item, dict) and item.get("outcome_sha256") == receipt["outcome_sha256"]
        for item in history
    ):
        history.append(reference)
    references[phase] = {**reference, "history": history}
    manifest["outcome_receipts"] = references
    return receipt


def _status_data(manifest: dict[str, Any], runner: CommandRunner = _run) -> dict[str, Any]:
    snapshot: dict[str, Any]
    try:
        snapshot = _git_snapshot(manifest, runner)
    except Exception as exc:
        snapshot = {"error": _error_summary(exc), "dirty": None}
    task_state = {
        role: _task_public(manifest.get("tasks", {}).get(role))
        for role in ("writer", "tests", "review")
    }
    try:
        tmux_live = _tmux_has_session(str(manifest["session_name"]))
    except Exception as exc:
        tmux_live = False
        tmux_error = _error_summary(exc)
    else:
        tmux_error = None
    collection = manifest.get("collection")
    findings: list[dict[str, Any]] = []
    if isinstance(collection, dict):
        review = collection.get("review")
        if isinstance(review, dict) and isinstance(review.get("findings"), list):
            findings = [item for item in review["findings"] if isinstance(item, dict)]
    all_terminal = all(task_state[role]["terminal"] for role in ("writer", "tests", "review"))
    all_completed = all(task_state[role]["state"] == "completed" for role in ("writer", "tests", "review"))
    task_start_intents = manifest.get("task_start_intents", {})
    start_intents_clear = isinstance(task_start_intents, dict) and not task_start_intents
    collection_integrity = _collection_integrity_status(manifest, collection)
    collection_complete = bool(
        isinstance(collection, dict)
        and collection.get("state") == "complete"
        and collection_integrity["valid"]
    )
    snapshot_matches = (
        collection_complete
        and isinstance(snapshot.get("writer_head"), str)
        and collection.get("writer_head") == snapshot.get("writer_head")
        and collection.get("diff_sha256") == snapshot.get("diff_sha256")
    )
    creation_ready = manifest.get("creation_state") == "ready"
    route_evidence, route_gate_passed, legacy_route = _route_gate(manifest)
    incomplete_roles = _collection_incomplete_roles(collection) if collection_complete else []
    closeable = bool(
        creation_ready
        and route_gate_passed
        and all_terminal
        and collection_complete
        and not incomplete_roles
        and snapshot_matches
        and start_intents_clear
    )
    collected_result = collection.get("writer_result", {}) if isinstance(collection, dict) else {}
    result_valid = bool(
        collected_result.get("type") == "patch"
        and snapshot.get("dirty") is True
        and snapshot.get("writer_head") == snapshot.get("expected_base_head")
        and _verify_patch_artifact(
            collected_result,
            expected_path=_writer_patch_path(manifest),
        )
    )
    success_ready = bool(
        closeable
        and not incomplete_roles
        and all_completed
        and result_valid
        and not snapshot.get("base_drift")
        and snapshot.get("writer_branch_matches") is True
        and snapshot.get("scope_passed") is True
        and not findings
        and collection.get("tests", {}).get("status") == "passed"
        and collection.get("review", {}).get("status") == "passed"
        and collection.get("review", {}).get("verdict") == "PASS"
    )
    close_integrity = _close_integrity_status(manifest, manifest.get("close_receipt"))
    failed_roles = _collection_failed_roles(collection)
    role_retry = _status_role_retry(manifest)
    closure_outcome = _prospective_closure_outcome(manifest, collection)
    recommended_next_action = _recommended_next_action(
        creation_ready=creation_ready,
        closed=close_integrity["valid"],
        route_gate_passed=route_gate_passed,
        closeable=closeable,
        success_ready=success_ready,
        role_retry=role_retry,
        failed_roles=failed_roles,
        incomplete_roles=incomplete_roles,
    )
    return {
        "workspace_id": manifest["workspace_id"],
        "creation_state": manifest.get("creation_state"),
        "creation_ready": creation_ready,
        "binding": manifest["binding"],
        "route_evidence": route_evidence,
        "route_evidence_complete": route_gate_passed,
        "route_legacy_compatibility": legacy_route,
        "repository": manifest["repository"],
        "expected_base_head": manifest["expected_base_head"],
        "writer": snapshot,
        "roles": manifest["roles"],
        "tasks": task_state,
        "task_start_intents": task_start_intents,
        "role_start_reconcile_required": not start_intents_clear,
        "tmux": {
            "session_name": manifest["session_name"],
            "live": tmux_live,
            "pane_ids": manifest.get("pane_ids", {}),
            "establishes_success": False,
            "error": tmux_error,
        },
        "collection": collection,
        "collection_integrity": collection_integrity,
        "unresolved_findings": findings,
        "failed_roles": failed_roles,
        "incomplete_roles": incomplete_roles,
        "role_retry": role_retry,
        "closeable": closeable,
        "success_ready": success_ready,
        "closure_outcome": closure_outcome,
        "recommended_next_action": recommended_next_action,
        "close_integrity": close_integrity,
        "closed": close_integrity["valid"],
        "outcome_receipts": manifest.get("outcome_receipts", {}),
        "external_closeout_checklist": _external_closeout_checklist(manifest),
    }


def _bound_task_host(manifest: dict[str, Any]) -> str:
    resources_value = manifest.get("resources")
    if not isinstance(resources_value, dict) or resources_value.get("task_host") != AGENT_WORKSPACE_TASK_HOST:
        raise AgentWorkspaceError("workspace task host binding is invalid")
    return AGENT_WORKSPACE_TASK_HOST


def _validate_started_task(
    public: Any,
    *,
    role: str,
    expected_host: str,
    expected_argv: list[str],
    expected_cwd: str,
) -> dict[str, Any]:
    if not isinstance(public, dict) or not isinstance(public.get("task_id"), str):
        raise AgentWorkspaceActionError(f"{role} task did not return a task id")
    errors: list[str] = []
    if public.get("host") != expected_host:
        errors.append("host_mismatch")
    if public.get("argv_sha256") != _sha256_json(expected_argv):
        errors.append("argv_sha256_mismatch")
    if public.get("cwd") != expected_cwd:
        errors.append("cwd_mismatch")
    if errors:
        raise AgentWorkspaceActionError(
            f"{role} task binding mismatch: {', '.join(errors)}"
        )
    return public


def _start_role_task(manifest: dict[str, Any], role: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    if role not in READ_ONLY_ROLES:
        raise AgentWorkspaceError("only read-only roles may be started from collect")
    host = _bound_task_host(manifest)
    argv = _role_task_argv(
        manifest,
        role,
        str(snapshot["writer_head"]),
        str(snapshot["diff_sha256"]),
        bool(snapshot["dirty"]),
    )
    cwd = str(manifest["writer_worktree"])
    task = tasks.grabowski_task_start(
        host=host,
        argv=argv,
        cwd=cwd,
        runtime_seconds=int(manifest["resources"]["runtime_seconds"]),
        resume_policy="never",
        cpu_weight=100,
        io_weight=100,
        memory_max_bytes=manifest["resources"]["memory_max_bytes"],
        resource_keys=None,
        chronik_outbox=True,
    )
    public = task.get("task") if isinstance(task, dict) else None
    return _validate_started_task(
        public,
        role=role,
        expected_host=host,
        expected_argv=argv,
        expected_cwd=cwd,
    )

def _validate_new_workspace_collisions(plan: dict[str, Any], runner: CommandRunner) -> None:
    worktree = Path(str(plan["writer_worktree"]))
    if worktree.exists():
        raise AgentWorkspaceError("writer_worktree already exists")
    if _remote_branch_collision(
        Path(str(plan["repository"])),
        str(plan["writer_branch"]),
        runner,
    ):
        raise AgentWorkspaceError("writer_branch already exists locally or remotely")


def _plan_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    return {field: manifest.get(field) for field in PLAN_FIELDS}


def _optional_state(path: Path) -> dict[str, Any] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AgentWorkspaceError(f"workspace state is not observable: {path}: {exc}") from exc
    return _load_json(path)


def _create_completion_errors(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("creation_state") != "ready":
        errors.append("creation_state_not_ready")
    tasks_value = manifest.get("tasks")
    writer_task_id = tasks_value.get("writer") if isinstance(tasks_value, dict) else None
    if not isinstance(writer_task_id, str) or not writer_task_id:
        errors.append("writer_task_not_bound")
    pane_ids = manifest.get("pane_ids")
    if not isinstance(pane_ids, dict) or set(pane_ids) != set(ALL_ROLES):
        errors.append("pane_inventory_incomplete")
    else:
        values = list(pane_ids.values())
        if any(not isinstance(value, str) or PANE_ID_RE.fullmatch(value) is None for value in values):
            errors.append("pane_inventory_invalid")
        elif len(set(values)) != len(values):
            errors.append("pane_inventory_not_unique")
    intents = manifest.get("task_start_intents", {})
    if not isinstance(intents, dict):
        errors.append("task_start_intents_invalid")
    elif intents:
        errors.append("role_start_outcome_unknown")
    if manifest.get("close_receipt") is not None:
        errors.append("workspace_already_closed")
    return errors


def _failure_summary(failure: dict[str, Any]) -> dict[str, Any]:
    return {
        "failed_at": failure.get("failed_at"),
        "writer_task_id": failure.get("writer_task_id"),
        "writer_start_attempted": failure.get("writer_start_attempted"),
        "writer_task_argv_sha256": failure.get("writer_task_argv_sha256"),
        "writer_cancel_confirmed": failure.get("writer_cancel_confirmed"),
        "worktree_create_attempted": failure.get("worktree_create_attempted"),
        "worktree_created": failure.get("worktree_created"),
        "worktree_cleanup_confirmed": failure.get("worktree_cleanup_confirmed"),
        "lease_retained": failure.get("lease_retained"),
        "worktree_preserved": failure.get("worktree_preserved"),
    }


def _validate_failure_identity(
    failure: dict[str, Any],
    *,
    workspace_id: str,
    plan_sha256: str,
) -> None:
    if (
        failure.get("schema_version") != SCHEMA_VERSION
        or failure.get("workspace_id") != workspace_id
        or failure.get("plan_sha256") != plan_sha256
    ):
        raise AgentWorkspaceError("workspace failure receipt belongs to a different plan or identity")


def _existing_workspace_response(
    *,
    directory: Path,
    plan: dict[str, Any],
    plan_sha256: str,
) -> dict[str, Any]:
    try:
        directory_metadata = directory.lstat()
    except OSError as exc:
        raise PermissionError(f"workspace directory is not safely observable: {exc}") from exc
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != os.getuid()
        or stat.S_IMODE(directory_metadata.st_mode) & 0o077
    ):
        raise PermissionError("workspace directory must be one private owner-controlled directory")
    workspace_id = str(plan["workspace_id"])
    failure = _optional_state(directory / "create-failure.json")
    if failure is not None:
        _validate_failure_identity(
            failure,
            workspace_id=workspace_id,
            plan_sha256=plan_sha256,
        )
    manifest = _optional_state(directory / "manifest.json")
    if manifest is None:
        if failure is not None:
            return {
                "workspace_id": workspace_id,
                "state": "creation_failed",
                "failure_receipt_present": True,
                "failure": _failure_summary(failure),
                "idempotent": False,
                "retry_requires_recovery": True,
                "receipt_status": "blocked",
            }
        return {
            "workspace_id": workspace_id,
            "state": "creation_in_progress",
            "failure_receipt_present": False,
            "idempotent": False,
            "receipt_status": "blocked",
        }
    if manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("workspace_id") != workspace_id:
        raise AgentWorkspaceError("workspace manifest identity mismatch")
    stored_plan_sha256 = _sha256_json(_plan_from_manifest(manifest))
    if manifest.get("plan_sha256") != stored_plan_sha256:
        raise AgentWorkspaceError("workspace manifest plan digest mismatch")
    if stored_plan_sha256 != plan_sha256:
        raise AgentWorkspaceError("workspace id already exists with a different plan")
    if failure is not None:
        return {
            "workspace_id": workspace_id,
            "workspace": manifest,
            "state": "creation_failed",
            "failure_receipt_present": True,
            "failure": _failure_summary(failure),
            "idempotent": False,
            "retry_requires_recovery": True,
            "receipt_status": "blocked",
        }
    completion_errors = _create_completion_errors(manifest)
    if completion_errors:
        return {
            "workspace_id": workspace_id,
            "workspace": manifest,
            "state": "creation_incomplete",
            "completion_errors": completion_errors,
            "failure_receipt_present": False,
            "idempotent": False,
            "retry_requires_recovery": True,
            "receipt_status": "blocked",
        }
    owner_id = str(plan["resources"]["owner_id"])
    expected_lease_keys = set(plan["resources"]["lease_keys"])
    expected_pane_ids = set(manifest["pane_ids"].values())
    expected_writer_task_id = str(manifest["tasks"]["writer"])
    try:
        live_leases = resources.list_resources(owner_id=owner_id, include_expired=False, limit=MAX_PATHS + 8)
        observed_lease_keys = {str(item.get("resource_key")) for item in live_leases}
        tmux_live = _tmux_has_session(str(plan["session_name"]))
        observed_pane_ids = _tmux_pane_ids(str(plan["session_name"])) if tmux_live else set()
        writer_task = _task_public(expected_writer_task_id)
        writer_identity = _writer_create_identity(manifest, _run)
    except Exception as exc:
        return {
            "workspace_id": workspace_id,
            "workspace": manifest,
            "state": "creation_runtime_unobservable",
            "error": _error_summary(exc),
            "idempotent": False,
            "receipt_status": "blocked",
        }
    runtime_errors: list[str] = []
    if not expected_lease_keys.issubset(observed_lease_keys):
        runtime_errors.append("workspace_lease_missing")
    if not tmux_live:
        runtime_errors.append("tmux_session_missing")
    elif observed_pane_ids != expected_pane_ids:
        runtime_errors.append("tmux_pane_inventory_mismatch")
    if writer_task.get("state") in {"not_started", "observation_error"}:
        runtime_errors.append("writer_task_unobservable")
    if writer_task.get("task_id") != expected_writer_task_id:
        runtime_errors.append("writer_task_id_mismatch")
    if writer_task.get("host") != AGENT_WORKSPACE_TASK_HOST:
        runtime_errors.append("writer_task_host_mismatch")
    if writer_task.get("argv_sha256") != _sha256_json(_writer_task_argv(manifest)):
        runtime_errors.append("writer_task_argv_mismatch")
    if writer_task.get("cwd") != manifest["writer_worktree"]:
        runtime_errors.append("writer_task_cwd_mismatch")
    if writer_identity.get("writer_branch_matches") is not True:
        runtime_errors.append("writer_branch_mismatch")
    if writer_identity.get("writer_head") != manifest["expected_base_head"]:
        runtime_errors.append("writer_head_mismatch")
    if runtime_errors:
        return {
            "workspace_id": workspace_id,
            "workspace": manifest,
            "state": "creation_runtime_incomplete",
            "runtime_errors": runtime_errors,
            "writer_task": writer_task,
            "writer_identity": writer_identity,
            "live_lease_keys": sorted(observed_lease_keys),
            "tmux_live": tmux_live,
            "observed_pane_ids": sorted(observed_pane_ids),
            "idempotent": False,
            "retry_requires_recovery": True,
            "receipt_status": "blocked",
        }
    return {
        "workspace": manifest,
        "writer_task": writer_task,
        "writer_identity": writer_identity,
        "live_lease_keys": sorted(observed_lease_keys),
        "tmux_live": True,
        "observed_pane_ids": sorted(observed_pane_ids),
        "idempotent": True,
    }


@mcp.tool(name="grabowski_agent_workspace_create", annotations=MUTATING)
def grabowski_agent_workspace_create(
    binding_kind: str,
    binding_id: str,
    repository: str,
    expected_base_head: str,
    writer_branch: str,
    writer_worktree: str,
    allowed_paths: list[str],
    writer_argv: list[str],
    test_argv: list[str],
    review_argv: list[str],
    route_evidence: dict[str, Any] | None = None,
    forbidden_paths: list[str] | None = None,
    runtime_seconds: int = 3600,
    memory_max_bytes: int | None = None,
) -> dict[str, Any]:
    """Create one four-role tmux workspace with one isolated durable writer task."""
    operator._require_operator_mutation("tmux_interaction")
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    plan = _normalize_create(
        binding_kind=binding_kind,
        binding_id=binding_id,
        repository=repository,
        expected_base_head=expected_base_head,
        writer_branch=writer_branch,
        writer_worktree=writer_worktree,
        allowed_paths=allowed_paths,
        forbidden_paths=forbidden_paths or [],
        writer_argv=writer_argv,
        test_argv=test_argv,
        review_argv=review_argv,
        route_evidence=route_evidence,
        runtime_seconds=runtime_seconds,
        memory_max_bytes=memory_max_bytes,
        runner=_run,
    )
    workspace_id = str(plan["workspace_id"])
    directory = _ensure_root() / workspace_id
    plan_sha256 = _sha256_json(plan)
    try:
        directory.lstat()
    except FileNotFoundError:
        directory_exists = False
    else:
        directory_exists = True
    if directory_exists:
        return _existing_workspace_response(
            directory=directory,
            plan=plan,
            plan_sha256=plan_sha256,
        )
    _validate_new_workspace_collisions(plan, _run)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        return _existing_workspace_response(
            directory=directory,
            plan=plan,
            plan_sha256=plan_sha256,
        )
    lease = None
    writer_task: dict[str, Any] | None = None
    writer_start_attempted = False
    worktree_create_attempted = False
    worktree_created = False
    tmux_created = False
    manifest = {
        **plan,
        "plan_sha256": plan_sha256,
        "creation_state": "creating",
        "created_at": _utc(),
        "updated_at": _utc(),
        "tasks": {"writer": None, "tests": None, "review": None},
        "task_start_intents": {},
        "pane_ids": {},
        "collection": None,
        "close_receipt": None,
        "event_sequence": 0,
        "truth_model": {
            "bureau": "binding and ball truth",
            "git_github": "code, branch, diff, PR and merge truth",
            "grabowski": "task, lease, execution and receipt truth",
            "tmux": "non-authoritative process UI only",
        },
    }
    _append_workspace_event(
        manifest,
        "plan_created",
        outcome="planned",
        evidence={"plan_sha256": plan_sha256, "binding": manifest["binding"]},
    )
    _write_manifest(manifest)
    writer_task_argv = _writer_task_argv(manifest)
    writer_task_argv_sha256 = _sha256_json(writer_task_argv)
    try:
        lease = resources.acquire_resources(
            str(plan["resources"]["owner_id"]),
            list(plan["resources"]["lease_keys"]),
            purpose=f"agent workspace {workspace_id}",
            ttl_seconds=min(resources.MAX_TTL_SECONDS, int(plan["resources"]["runtime_seconds"]) + 900),
            metadata={
                "workspace_id": workspace_id,
                "binding": plan["binding"],
                "base_head": plan["expected_base_head"],
                "plan_sha256": plan_sha256,
            },
        )
        repo = Path(str(plan["repository"]))
        worktree = Path(str(plan["writer_worktree"]))
        worktree_create_attempted = True
        _checked(
            _run,
            repo,
            [
                "git",
                "worktree",
                "add",
                "-b",
                str(plan["writer_branch"]),
                str(worktree),
                str(plan["expected_base_head"]),
            ],
            label="writer worktree creation",
        )
        worktree_created = True
        writer_intents = dict(manifest.get("task_start_intents", {}))
        writer_intents["writer"] = {
            "role": "writer",
            "created_at": _utc(),
            "nonce": hashlib.sha256(
                f"{workspace_id}:writer:{time.time_ns()}".encode("utf-8")
            ).hexdigest()[:24],
            "expected_base_head": plan["expected_base_head"],
            "command_sha256": _sha256_json(plan["commands"]["writer"]),
            "task_argv_sha256": writer_task_argv_sha256,
            "task_host": plan["resources"]["task_host"],
            "task_cwd": plan["writer_worktree"],
        }
        manifest["task_start_intents"] = writer_intents
        _write_manifest(manifest)
        writer_start_attempted = True
        started = tasks.grabowski_task_start(
            host=_bound_task_host(manifest),
            argv=writer_task_argv,
            cwd=str(worktree),
            runtime_seconds=int(plan["resources"]["runtime_seconds"]),
            resume_policy="never",
            cpu_weight=100,
            io_weight=100,
            memory_max_bytes=plan["resources"]["memory_max_bytes"],
            resource_keys=None,
            chronik_outbox=True,
        )
        writer_task = started.get("task") if isinstance(started, dict) else None
        writer_task = _validate_started_task(
            writer_task,
            role="writer",
            expected_host=_bound_task_host(manifest),
            expected_argv=writer_task_argv,
            expected_cwd=str(worktree),
        )
        manifest["tasks"]["writer"] = writer_task["task_id"]
        _append_workspace_event(
            manifest, "role_started", role="writer", outcome="started",
            evidence={"task_id": writer_task["task_id"], "command_sha256": plan["commands"] and _sha256_json(plan["commands"]["writer"])},
        )
        writer_intents = dict(manifest.get("task_start_intents", {}))
        writer_intents.pop("writer", None)
        manifest["task_start_intents"] = writer_intents
        _write_manifest(manifest)
        panes = _create_tmux(manifest)
        tmux_created = True
        manifest["pane_ids"] = panes
        _write_manifest(manifest)
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "agent-workspace-create-runtime-ready",
                "workspace_id": workspace_id,
                "plan_sha256": plan_sha256,
                "writer_task_id": manifest["tasks"]["writer"],
                "session_name": manifest["session_name"],
                "creation_state": "runtime_ready",
            }
        )
        manifest["creation_state"] = "ready"
        _append_workspace_event(manifest, "workspace_ready", outcome="ready", evidence={"pane_count": len(panes)})
        _write_manifest(manifest)
    except Exception as exc:
        writer_cancel_confirmed = not writer_start_attempted
        writer_cancel_returncode: int | None = None
        writer_cancel_error: str | None = (
            "writer task start outcome is unknown"
            if writer_start_attempted and writer_task is None
            else None
        )
        if writer_task is not None:
            try:
                cancelled = tasks.grabowski_task_cancel(str(writer_task["task_id"]))
                cancelled_task = cancelled.get("task") if isinstance(cancelled, dict) else None
                cancel_result = cancelled.get("result") if isinstance(cancelled, dict) else None
                if isinstance(cancel_result, dict):
                    returncode = cancel_result.get("returncode")
                    if isinstance(returncode, int) and not isinstance(returncode, bool):
                        writer_cancel_returncode = returncode
                writer_cancel_confirmed = bool(
                    writer_cancel_returncode == 0
                    and isinstance(cancelled_task, dict)
                    and cancelled_task.get("state") == "cancelled"
                )
            except Exception as cancel_exc:
                writer_cancel_error = _error_summary(cancel_exc)
        if tmux_created:
            try:
                _tmux_result(["kill-session", "-t", str(plan["session_name"])])
            except Exception:
                pass
        worktree_cleanup_confirmed = not worktree_create_attempted or writer_start_attempted
        worktree_cleanup_error: str | None = None
        if worktree_create_attempted and not writer_start_attempted:
            try:
                worktree_cleanup_confirmed = _remove_created_worktree(
                    Path(str(plan["repository"])),
                    Path(str(plan["writer_worktree"])),
                    str(plan["writer_branch"]),
                    str(plan["expected_base_head"]),
                    _run,
                )
            except Exception as cleanup_exc:
                worktree_cleanup_confirmed = False
                worktree_cleanup_error = _error_summary(cleanup_exc)
        lease_released = False
        lease_release_error: str | None = None
        if lease is not None and writer_cancel_confirmed and worktree_cleanup_confirmed:
            try:
                resources.release_resources(
                    str(plan["resources"]["owner_id"]),
                    list(plan["resources"]["lease_keys"]),
                )
                lease_released = True
            except Exception as release_exc:
                lease_release_error = _error_summary(release_exc)
        failure = {
            "schema_version": 1,
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "failed_at": _utc(),
            "error": _error_summary(exc),
            "writer_task_id": None if writer_task is None else writer_task.get("task_id"),
            "writer_start_attempted": writer_start_attempted,
            "writer_task_argv_sha256": writer_task_argv_sha256,
            "writer_task_host": plan["resources"]["task_host"],
            "writer_task_cwd": plan["writer_worktree"],
            "writer_cancel_confirmed": writer_cancel_confirmed,
            "writer_cancel_returncode": writer_cancel_returncode,
            "writer_cancel_error": writer_cancel_error,
            "worktree_create_attempted": worktree_create_attempted,
            "worktree_created": worktree_created,
            "worktree_cleanup_confirmed": worktree_cleanup_confirmed,
            "worktree_cleanup_error": worktree_cleanup_error,
            "lease_released": lease_released,
            "lease_retained": lease is not None and not lease_released,
            "lease_release_error": lease_release_error,
            "worktree_preserved": Path(str(plan["writer_worktree"])).exists(),
        }
        try:
            _atomic_json(directory / "create-failure.json", failure)
        except Exception as receipt_exc:
            raise AgentWorkspaceActionError(
                "agent workspace creation failed and its failure receipt could not be published: "
                f"create={_error_summary(exc)}; receipt={_error_summary(receipt_exc)}"
            ) from exc
        raise
    return {
        "workspace": manifest,
        "writer_task": writer_task,
        "resource_lease": lease,
        "idempotent": False,
        "tmux_establishes_success": False,
    }


@mcp.tool(name="grabowski_agent_workspace_status", annotations=READ_ONLY)
def grabowski_agent_workspace_status(workspace_id: str) -> dict[str, Any]:
    """Derive live workspace status from Grabowski tasks, Git and tmux without trusting pane state."""
    operator._require_operator_capability("durable_job")
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("tmux_interaction")
    return _status_data(_manifest(workspace_id))


@mcp.tool(name="grabowski_agent_workspace_attach", annotations=READ_ONLY)
def grabowski_agent_workspace_attach(workspace_id: str) -> dict[str, Any]:
    """Return the exact attach command for an existing workspace tmux session."""
    operator._require_operator_capability("tmux_interaction")
    manifest = _manifest(workspace_id)
    session = str(manifest["session_name"])
    live = _tmux_has_session(session)
    return {
        "workspace_id": workspace_id,
        "session_name": session,
        "session_live": live,
        "creation_state": manifest.get("creation_state"),
        "workspace_ready": manifest.get("creation_state") == "ready",
        "attach_argv": [str(TMUX), "attach-session", "-t", session],
        "creates_state": False,
        "establishes_success": False,
    }


@mcp.tool(name="grabowski_agent_workspace_collect", annotations=MUTATING)
def grabowski_agent_workspace_collect(workspace_id: str) -> dict[str, Any]:
    """Freeze writer evidence, start/read read-only checks, and write one head/diff-bound receipt."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("git_cli")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    with _lock(identifier):
        manifest = _manifest(identifier)
        _append_workspace_event(manifest, "collection_requested", outcome="observing")
        _write_manifest(manifest)
        if manifest.get("creation_state") != "ready":
            return {
                "workspace_id": identifier,
                "state": "creation_incomplete",
                "completion_errors": ["creation_state_not_ready"],
                "receipt_status": "blocked",
            }
        if manifest.get("close_receipt") is not None:
            raise AgentWorkspaceError("workspace is already closed")
        writer = _task_public(manifest["tasks"]["writer"])
        if writer["state"] in {"observation_error", "outcome_unknown", "interrupted"}:
            try:
                reconcile = tasks.grabowski_task_reconcile_check(str(writer["task_id"]))
            except Exception as exc:
                reconcile = {"error": _error_summary(exc)}
            return {
                "workspace_id": identifier,
                "state": "writer_outcome_unknown",
                "writer_task": writer,
                "reconcile": reconcile,
                "receipt_status": "blocked",
            }
        if not writer["terminal"]:
            return {
                "workspace_id": identifier,
                "state": "writer_running",
                "writer_task": writer,
                "reconcile": None,
                "receipt_status": "blocked",
            }
        if writer["state"] != "completed":
            return {
                "workspace_id": identifier,
                "state": "writer_failed",
                "writer_task": writer,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        writer_receipt = _role_receipt(manifest, "writer")
        if writer_receipt is None:
            return {
                "workspace_id": identifier,
                "state": "writer_receipt_missing",
                "writer_task": writer,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        if (
            not _receipt_integrity(writer_receipt)
            or writer_receipt.get("role") != "writer"
            or writer_receipt.get("expected_base_head") != manifest["expected_base_head"]
            or writer_receipt.get("expected_branch") != manifest["writer_branch"]
            or writer_receipt.get("allowed_paths") != manifest["scope"]["allowed_paths"]
            or writer_receipt.get("allowed_paths_sha256") != _sha256_json(manifest["scope"]["allowed_paths"])
            or writer_receipt.get("command_sha256") != _sha256_json(manifest["commands"]["writer"])
            or writer_receipt.get("head_before") != manifest["expected_base_head"]
            or writer_receipt.get("branch_before") != manifest["writer_branch"]
            or writer_receipt.get("head_after") != manifest["expected_base_head"]
            or writer_receipt.get("branch_after") != manifest["writer_branch"]
            or writer_receipt.get("sandbox") != "bubblewrap-minimal-root-bounded-writable-paths-v1"
            or writer_receipt.get("git_common_dir_mode") != "read_only"
            or writer_receipt.get("returncode") != 0
        ):
            return {
                "workspace_id": identifier,
                "state": "writer_receipt_invalid",
                "writer_task": writer,
                "writer_receipt": writer_receipt,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        snapshot = _git_snapshot(manifest, _run)
        if not snapshot["writer_branch_matches"]:
            return {
                "workspace_id": identifier,
                "state": "writer_branch_mismatch",
                "snapshot": snapshot,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        if snapshot["writer_head"] != manifest["expected_base_head"]:
            return {
                "workspace_id": identifier,
                "state": "writer_head_changed",
                "snapshot": snapshot,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        if snapshot["result_type"] == "none":
            return {
                "workspace_id": identifier,
                "state": "writer_result_missing",
                "snapshot": snapshot,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        if not snapshot["scope_passed"]:
            return {
                "workspace_id": identifier,
                "state": "scope_violation",
                "snapshot": snapshot,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        if snapshot["base_drift"]:
            return {
                "workspace_id": identifier,
                "state": "base_drift",
                "snapshot": snapshot,
                "worktree_preserved": True,
                "receipt_status": "blocked",
            }
        tasks_map = dict(manifest["tasks"])
        started_roles: list[str] = []
        frozen = manifest.get("frozen_writer")
        if not isinstance(frozen, dict):
            writer_result = _materialize_writer_patch(manifest, snapshot, _run)
            freeze_stable, verified_snapshot = _settled_writer_snapshot(manifest, snapshot, _run)
            if not freeze_stable:
                return {
                    "workspace_id": identifier,
                    "state": "writer_changed_during_freeze",
                    "snapshot_before": snapshot,
                    "snapshot_after": verified_snapshot,
                    "untrusted_patch_artifact": writer_result,
                    "receipt_status": "blocked",
                }
            snapshot = verified_snapshot
            manifest["frozen_writer"] = {
                "writer_head": snapshot["writer_head"],
                "diff_sha256": snapshot["diff_sha256"],
                "dirty": snapshot["dirty"],
                "writer_result": writer_result,
                "frozen_at": _utc(),
            }
            _write_manifest(manifest)
            frozen = manifest["frozen_writer"]
        elif (
            frozen.get("writer_head") != snapshot["writer_head"]
            or frozen.get("diff_sha256") != snapshot["diff_sha256"]
            or frozen.get("dirty") != snapshot["dirty"]
        ):
            return {
                "workspace_id": identifier,
                "state": "writer_changed_after_freeze",
                "snapshot": snapshot,
                "frozen_writer": frozen,
                "receipt_status": "blocked",
            }
        writer_result = frozen.get("writer_result")
        if (
            not isinstance(writer_result, dict)
            or writer_result.get("type") != "patch"
            or not _verify_patch_artifact(
                writer_result,
                expected_path=_writer_patch_path(manifest),
            )
        ):
            return {
                "workspace_id": identifier,
                "state": "writer_result_artifact_invalid",
                "snapshot": snapshot,
                "frozen_writer": frozen,
                "receipt_status": "blocked",
            }
        intents_value = manifest.get("task_start_intents", {})
        if not isinstance(intents_value, dict):
            return {
                "workspace_id": identifier,
                "state": "role_start_intents_invalid",
                "receipt_status": "blocked",
            }
        unresolved_intents = {
            role: intents_value[role]
            for role in READ_ONLY_ROLES
            if role in intents_value
        }
        if unresolved_intents:
            return {
                "workspace_id": identifier,
                "state": "role_start_outcome_unknown",
                "task_start_intents": unresolved_intents,
                "reconcile_required": True,
                "receipt_status": "blocked",
            }
        for role in READ_ONLY_ROLES:
            if tasks_map.get(role) is None:
                preflight = _role_toolchain_preflight(manifest, role, manifest["commands"][role])
                _append_workspace_event(
                    manifest, "role_preflight", role=role,
                    outcome="passed" if preflight["passed"] else "environment_failure",
                    evidence={"command_sha256": preflight.get("command_sha256"), "failure_classification": preflight.get("failure_classification")},
                )
                if not preflight["passed"]:
                    blocks = dict(manifest.get("role_preflight_blocks", {}))
                    role_blocks = list(blocks.get(role, []))
                    role_blocks.append({**preflight, "attempt": None, "attempt_consumed": False, "proposed_attempt": 1, "source": "collect"})
                    blocks[role] = role_blocks
                    manifest["role_preflight_blocks"] = blocks
                    _write_manifest(manifest)
                    return {
                        "workspace_id": identifier,
                        "state": "role_toolchain_preflight_failed",
                        "role": role,
                        "preflight": preflight,
                        "receipt_status": "blocked",
                    }
                intents = dict(manifest.get("task_start_intents", {}))
                role_task_argv = _role_task_argv(
                    manifest,
                    role,
                    str(snapshot["writer_head"]),
                    str(snapshot["diff_sha256"]),
                    bool(snapshot["dirty"]),
                )
                intent = {
                    "role": role,
                    "created_at": _utc(),
                    "nonce": hashlib.sha256(
                        f"{identifier}:{role}:{time.time_ns()}".encode("utf-8")
                    ).hexdigest()[:24],
                    "writer_head": snapshot["writer_head"],
                    "diff_sha256": snapshot["diff_sha256"],
                    "dirty": snapshot["dirty"],
                    "command_sha256": _sha256_json(manifest["commands"][role]),
                    "task_argv_sha256": _sha256_json(role_task_argv),
                    "task_host": _bound_task_host(manifest),
                    "task_cwd": manifest["writer_worktree"],
                }
                intents[role] = intent
                manifest["task_start_intents"] = intents
                _write_manifest(manifest)
                public = _start_role_task(manifest, role, snapshot)
                tasks_map[role] = public["task_id"]
                manifest["tasks"] = dict(tasks_map)
                _append_workspace_event(
                    manifest, "role_started", role=role, outcome="started",
                    evidence={"task_id": public["task_id"], "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"]},
                )
                intents = dict(manifest.get("task_start_intents", {}))
                intents.pop(role, None)
                manifest["task_start_intents"] = intents
                _write_manifest(manifest)
                started_roles.append(role)
        if started_roles:
            return {
                "workspace_id": identifier,
                "state": "collecting",
                "started_roles": started_roles,
                "tasks": {role: _task_public(tasks_map[role]) for role in READ_ONLY_ROLES},
                "snapshot": snapshot,
                "receipt_status": "passed",
            }
        role_tasks = {role: _task_public(tasks_map[role]) for role in READ_ONLY_ROLES}
        if not all(value["terminal"] for value in role_tasks.values()):
            return {
                "workspace_id": identifier,
                "state": "collecting",
                "tasks": role_tasks,
                "snapshot": snapshot,
                "receipt_status": "passed",
            }
        test_receipt = _role_receipt(manifest, "tests")
        review_receipt = _role_receipt(manifest, "review")
        if test_receipt is None or review_receipt is None:
            return {
                "workspace_id": identifier,
                "state": "role_receipt_missing",
                "tasks": role_tasks,
                "test_receipt_present": test_receipt is not None,
                "review_receipt_present": review_receipt is not None,
                "receipt_status": "blocked",
            }
        for role, receipt in (("tests", test_receipt), ("review", review_receipt)):
            if not _receipt_integrity(receipt):
                return {
                    "workspace_id": identifier,
                    "state": "role_receipt_integrity_mismatch",
                    "role": role,
                    "receipt_status": "blocked",
                }
            receipt_returncode = receipt.get("returncode")
            task_completed = role_tasks[role].get("state") == "completed"
            if (
                isinstance(receipt_returncode, bool)
                or not isinstance(receipt_returncode, int)
                or (receipt_returncode == 0) != task_completed
            ):
                return {
                    "workspace_id": identifier,
                    "state": "role_task_receipt_state_mismatch",
                    "role": role,
                    "task": role_tasks[role],
                    "receipt_returncode": receipt_returncode,
                    "receipt_status": "blocked",
                }
            if (
                receipt.get("role") != role
                or receipt.get("expected_head") != snapshot["writer_head"]
                or receipt.get("expected_base_head") != manifest["expected_base_head"]
                or receipt.get("expected_diff_sha256") != snapshot["diff_sha256"]
                or receipt.get("expected_dirty") != snapshot["dirty"]
                or receipt.get("head_before") != snapshot["writer_head"]
                or receipt.get("head_after") != snapshot["writer_head"]
                or receipt.get("diff_after") != snapshot["diff_sha256"]
                or receipt.get("worktree_dirty_after") != snapshot["dirty"]
                or receipt.get("argv_sha256") != _expected_role_argv_sha256(manifest, role)
                or receipt.get("sandbox") != agent_role.SANDBOX_LABEL
            ):
                return {
                    "workspace_id": identifier,
                    "state": "role_receipt_binding_mismatch",
                    "role": role,
                    "expected": {
                        "head": snapshot["writer_head"],
                        "diff_sha256": snapshot["diff_sha256"],
                        "dirty": snapshot["dirty"],
                    },
                    "observed": {
                        "role": receipt.get("role"),
                        "head": receipt.get("expected_head"),
                        "base_head": receipt.get("expected_base_head"),
                        "diff_sha256": receipt.get("expected_diff_sha256"),
                        "dirty": receipt.get("expected_dirty"),
                        "argv_sha256": receipt.get("argv_sha256"),
                        "sandbox": receipt.get("sandbox"),
                    },
                    "receipt_status": "blocked",
                }
        findings = review_receipt.get("findings")
        if not isinstance(findings, list):
            return {
                "workspace_id": identifier,
                "state": "review_receipt_invalid",
                "error": "review receipt findings must be a list",
                "receipt_status": "blocked",
            }
        for observed_role, observed_receipt in (("tests", test_receipt), ("review", review_receipt)):
            _append_workspace_event(
                manifest, "role_finished", role=observed_role,
                outcome="passed" if observed_receipt.get("returncode") == 0 else "failed",
                evidence={"receipt_sha256": observed_receipt.get("receipt_sha256"), "returncode": observed_receipt.get("returncode")},
            )
        result = {
            "schema_version": 1,
            "workspace_id": identifier,
            "binding": manifest["binding"],
            "repository": manifest["repository"],
            "expected_base_head": manifest["expected_base_head"],
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "writer_result": writer_result,
            "changed_paths": snapshot["changed_paths"],
            "scope_passed": snapshot["scope_passed"],
            "scope_violations": snapshot["scope_violations"],
            "dirty": snapshot["dirty"],
            "base_drift": snapshot["base_drift"],
            "integration_probe": snapshot["integration_probe"],
            "tests": {
                "status": "passed" if test_receipt.get("returncode") == 0 else "failed",
                "receipt_sha256": test_receipt.get("receipt_sha256"),
                "returncode": test_receipt.get("returncode"),
            },
            "review": {
                "status": "passed" if review_receipt.get("returncode") == 0 else "failed",
                "returncode": review_receipt.get("returncode"),
                "verdict": review_receipt.get("verdict"),
                "findings": findings,
                "receipt_sha256": review_receipt.get("receipt_sha256"),
                "independent_read_only": True,
            },
            "task_ids": tasks_map,
            "writer_task": writer,
            "writer_receipt_sha256": writer_receipt.get("receipt_sha256"),
            "tmux_establishes_success": False,
            "collected_at": _utc(),
        }
        result["state"] = "complete"
        result["result_sha256"] = _collection_result_sha256(result)
        manifest["collection"] = result
        outcome_receipt = _publish_workspace_outcome(manifest, "collection")
        _append_workspace_event(
            manifest, "collection_completed", outcome="complete",
            evidence={"result_sha256": result["result_sha256"], "writer_head": result["writer_head"], "diff_sha256": result["diff_sha256"]},
        )
        _write_manifest(manifest)
        _atomic_json(_workspace_dir(identifier) / "collection-receipt.json", result)
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "agent-workspace-collect",
                "workspace_id": identifier,
                "writer_head": result["writer_head"],
                "diff_sha256": result["diff_sha256"],
                "result_sha256": result["result_sha256"],
            }
        )
        return {
            "workspace_id": identifier,
            "state": "complete",
            "result": result,
            "receipt_status": "passed",
            "outcome_receipt": outcome_receipt,
            "external_closeout_checklist": _external_closeout_checklist(manifest),
        }


@mcp.tool(name="grabowski_agent_workspace_role_retry", annotations=MUTATING)
def grabowski_agent_workspace_role_retry(
    workspace_id: str,
    role: str,
    replacement_argv: list[str],
) -> dict[str, Any]:
    """Retry one collected-but-not-closed read-only role once with an explicit replacement command bound to the frozen writer snapshot."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("git_cli")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    role_name = _required_string(role, "role", max_length=16)
    if role_name not in READ_ONLY_ROLES:
        raise AgentWorkspaceError(f"role_retry supports only {sorted(READ_ONLY_ROLES)}; writer may never be retried")
    with _lock(identifier):
        manifest = _manifest(identifier)
        _append_workspace_event(manifest, "retry_decision", role=role_name, outcome="requested")
        _write_manifest(manifest)
        if manifest.get("creation_state") != "ready":
            raise AgentWorkspaceError("workspace creation is incomplete: creation_state_not_ready")
        if manifest.get("close_receipt") is not None:
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "workspace_closed",
                "retry_status": "blocked",
            }
        frozen = manifest.get("frozen_writer")
        if not isinstance(frozen, dict):
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "not_collected",
                "retry_status": "blocked",
            }
        worktree = Path(str(manifest["writer_worktree"]))
        command = _role_argv(replacement_argv, "replacement_argv", cwd=worktree)
        start_intent = _role_start_intent_classification(manifest, role_name)
        if start_intent is not None:
            classification, detail = start_intent
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": classification,
                **detail,
                "retry_status": "blocked",
            }
        live = _git_snapshot(manifest, _run)
        if (
            live["writer_head"] != frozen.get("writer_head")
            or live["diff_sha256"] != frozen.get("diff_sha256")
            or live["dirty"] != frozen.get("dirty")
        ):
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "binding_drift",
                "snapshot": live,
                "frozen_writer": {
                    "writer_head": frozen.get("writer_head"),
                    "diff_sha256": frozen.get("diff_sha256"),
                    "dirty": frozen.get("dirty"),
                },
                "retry_status": "blocked",
            }
        classification, detail = _role_retry_classification(manifest, role_name, frozen)
        if classification != "eligible":
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": classification,
                **detail,
                "retry_status": "blocked",
            }
        role_retry_state, retry_state_error = _role_retry_state(manifest, role_name)
        if retry_state_error is not None or role_retry_state is None:
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "retry_state_invalid",
                "error": retry_state_error,
                "retry_status": "blocked",
            }
        retries = dict(manifest.get("role_retries", {}))
        if role_retry_state["count"] >= MAX_ROLE_RETRIES:
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "retry_limit_reached",
                "max_retries": MAX_ROLE_RETRIES,
                "retry_status": "blocked",
            }
        previous_task_id = manifest["tasks"].get(role_name)
        previous_attempt = _role_final_attempt(manifest, role_name) if previous_task_id is not None else 0
        attempt_number = previous_attempt + 1
        preflight = _role_toolchain_preflight(manifest, role_name, command)
        _append_workspace_event(
            manifest, "role_preflight", role=role_name,
            outcome="passed" if preflight["passed"] else "environment_failure",
            evidence={"command_sha256": preflight.get("command_sha256"), "failure_classification": preflight.get("failure_classification"), "retry": True},
        )
        if not preflight["passed"]:
            blocks = dict(manifest.get("role_preflight_blocks", {}))
            role_blocks = list(blocks.get(role_name, []))
            role_blocks.append(
                {
                    **preflight,
                    "attempt": None,
                    "attempt_consumed": False,
                    "proposed_attempt": attempt_number,
                    "source": "retry",
                }
            )
            blocks[role_name] = role_blocks
            manifest["role_preflight_blocks"] = blocks
            _write_manifest(manifest)
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "role_toolchain_preflight_failed",
                "preflight": preflight,
                "attempt": None,
                "attempt_consumed": False,
                "proposed_attempt": attempt_number,
                "retry_status": "blocked",
            }
        previous_receipt = _role_receipt(manifest, role_name) if previous_task_id is not None else None
        previous_receipt_sha256 = (
            previous_receipt.get("receipt_sha256") if isinstance(previous_receipt, dict) else None
        )
        old_command_sha256 = _expected_role_argv_sha256(manifest, role_name)
        new_command_sha256 = _sha256_json(command)
        output_path = _role_receipt_path(manifest, role_name, attempt=attempt_number)
        try:
            output_path.lstat()
        except FileNotFoundError:
            attempt_receipt_exists = False
        else:
            attempt_receipt_exists = True
        if attempt_receipt_exists:
            return {
                "workspace_id": identifier,
                "role": role_name,
                "state": "attempt_receipt_already_exists",
                "attempt": attempt_number,
                "receipt_path": str(output_path),
                "retry_status": "blocked",
            }
        task_argv = _role_task_argv(
            manifest,
            role_name,
            str(frozen["writer_head"]),
            str(frozen["diff_sha256"]),
            bool(frozen["dirty"]),
            command=command,
            output_path=output_path,
        )
        cwd = str(manifest["writer_worktree"])
        host = _bound_task_host(manifest)
        intents = dict(manifest.get("task_start_intents", {}))
        intents[role_name] = {
            "role": role_name,
            "kind": "retry",
            "attempt": attempt_number,
            "created_at": _utc(),
            "nonce": hashlib.sha256(
                f"{identifier}:{role_name}:retry:{attempt_number}:{time.time_ns()}".encode("utf-8")
            ).hexdigest()[:24],
            "writer_head": frozen["writer_head"],
            "diff_sha256": frozen["diff_sha256"],
            "dirty": frozen["dirty"],
            "command_sha256": new_command_sha256,
            "task_argv_sha256": _sha256_json(task_argv),
            "task_host": host,
            "task_cwd": cwd,
        }
        manifest["task_start_intents"] = intents
        _write_manifest(manifest)
        started = tasks.grabowski_task_start(
            host=host,
            argv=task_argv,
            cwd=cwd,
            runtime_seconds=int(manifest["resources"]["runtime_seconds"]),
            resume_policy="never",
            cpu_weight=100,
            io_weight=100,
            memory_max_bytes=manifest["resources"]["memory_max_bytes"],
            resource_keys=None,
            chronik_outbox=True,
        )
        public = started.get("task") if isinstance(started, dict) else None
        public = _validate_started_task(
            public,
            role=role_name,
            expected_host=host,
            expected_argv=task_argv,
            expected_cwd=cwd,
        )
        intents = dict(manifest.get("task_start_intents", {}))
        intents.pop(role_name, None)
        manifest["task_start_intents"] = intents
        tasks_map = dict(manifest["tasks"])
        tasks_map[role_name] = public["task_id"]
        manifest["tasks"] = tasks_map
        final_attempts = dict(manifest.get("role_final_attempt", {}))
        final_attempts[role_name] = attempt_number
        manifest["role_final_attempt"] = final_attempts
        previous_failure_classification = detail.get("prior_failure_classification")
        retry_reason = (
            "toolchain_preflight_blocked"
            if previous_failure_classification == "toolchain_preflight_blocked"
            else "terminal_environment_toolchain_failure"
        )
        attempt_record = {
            "attempt": attempt_number,
            "created_at": _utc(),
            "retry_reason": retry_reason,
            "previous_failure_classification": previous_failure_classification,
            "previous_task_id": previous_task_id,
            "previous_receipt_sha256": previous_receipt_sha256,
            "old_command_sha256": old_command_sha256,
            "new_command_sha256": new_command_sha256,
            "new_task_id": public["task_id"],
            "selected_final_attempt": attempt_number,
        }
        role_retry_state["count"] += 1
        role_retry_state["attempts"] = [*role_retry_state["attempts"], attempt_record]
        retries[role_name] = role_retry_state
        manifest["role_retries"] = retries
        _append_workspace_event(
            manifest, "role_retry_started", role=role_name, outcome="started",
            evidence={"attempt": attempt_number, "new_task_id": public["task_id"], "previous_failure_classification": previous_failure_classification, "old_command_sha256": old_command_sha256, "new_command_sha256": new_command_sha256},
        )
        _write_manifest(manifest)
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "agent-workspace-role-retry",
                "workspace_id": identifier,
                "role": role_name,
                "attempt": attempt_number,
                "new_task_id": public["task_id"],
                "retry_reason": retry_reason,
                "previous_failure_classification": previous_failure_classification,
                "old_command_sha256": old_command_sha256,
                "new_command_sha256": new_command_sha256,
            }
        )
        return {
            "workspace_id": identifier,
            "role": role_name,
            "state": "retry_started",
            "attempt": attempt_number,
            "task": public,
            "attempt_record": attempt_record,
            "retry_status": "passed",
        }


@mcp.tool(name="grabowski_agent_workspace_close", annotations=MUTATING)
def grabowski_agent_workspace_close(
    workspace_id: str,
    expected_head: str,
    expected_diff_sha256: str,
    expected_result_sha256: str,
    cancel_running: bool = False,
    remove_tmux_session: bool = True,
    abandon_failed_roles: bool = False,
) -> dict[str, Any]:
    """Close one collected workspace without deleting its writer worktree or branch."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("tmux_interaction")
    operator._require_operator_mutation("resource_lease")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    head = _required_string(expected_head, "expected_head", max_length=40).lower()
    diff_sha = _required_string(expected_diff_sha256, "expected_diff_sha256", max_length=64).lower()
    result_sha = _required_string(expected_result_sha256, "expected_result_sha256", max_length=64).lower()
    if SHA40_RE.fullmatch(head) is None or SHA256_RE.fullmatch(diff_sha) is None or SHA256_RE.fullmatch(result_sha) is None:
        raise AgentWorkspaceError("close bindings must be canonical hashes")
    with _lock(identifier):
        manifest = _manifest(identifier)
        _append_workspace_event(
            manifest, "close_requested", outcome="requested",
            evidence={"expected_head": head, "expected_diff_sha256": diff_sha, "expected_result_sha256": result_sha, "abandon_failed_roles": abandon_failed_roles},
        )
        _write_manifest(manifest)
        if manifest.get("creation_state") != "ready":
            raise AgentWorkspaceError(
                "workspace creation is incomplete: creation_state_not_ready"
            )
        existing = manifest.get("close_receipt")
        if isinstance(existing, dict):
            if not _close_integrity_status(manifest, existing)["valid"]:
                raise AgentWorkspaceError("existing close receipt integrity is invalid")
            if existing.get("expected_head") != head or existing.get("expected_diff_sha256") != diff_sha or existing.get("expected_result_sha256") != result_sha:
                raise AgentWorkspaceError("workspace was closed with different bindings")
            return {
                "workspace_id": identifier,
                "close_receipt": existing,
                "idempotent": True,
                "outcome_receipt": (
                    _load_json(_outcome_receipt_path(manifest, "close"))
                    if _outcome_receipt_path(manifest, "close").is_file()
                    else None
                ),
                "external_closeout_checklist": _external_closeout_checklist(manifest),
            }
        collection = manifest.get("collection")
        if not isinstance(collection, dict) or collection.get("state") != "complete":
            raise AgentWorkspaceError("workspace has no complete collection receipt")
        collection_integrity = _collection_integrity_status(manifest, collection)
        if not collection_integrity["valid"]:
            raise AgentWorkspaceError("collection receipt integrity is invalid")
        if collection.get("writer_head") != head or collection.get("diff_sha256") != diff_sha or collection.get("result_sha256") != result_sha:
            raise AgentWorkspaceError("close bindings do not match collection receipt")
        route_evidence, route_gate_passed, legacy_route = _route_gate(manifest)
        if not route_gate_passed:
            return {
                "workspace_id": identifier,
                "state": "route_evidence_incomplete",
                "route_evidence": route_evidence,
                "route_legacy_compatibility": legacy_route,
                "receipt_status": "blocked",
                "recommended_next_action": "recreate_with_route_evidence",
                "external_closeout_checklist": _external_closeout_checklist(manifest),
            }
        snapshot = _git_snapshot(manifest, _run)
        if (
            snapshot["writer_head"] != head
            or snapshot["diff_sha256"] != diff_sha
            or not snapshot["writer_branch_matches"]
        ):
            raise AgentWorkspaceError("writer state changed after collection")
        incomplete_roles = _collection_incomplete_roles(collection)
        if incomplete_roles:
            return {
                "workspace_id": identifier,
                "state": "incomplete_role_evidence",
                "incomplete_roles": incomplete_roles,
                "receipt_status": "blocked",
                "external_closeout_checklist": _external_closeout_checklist(manifest),
            }
        failed_roles = _collection_failed_roles(collection)
        if failed_roles and not abandon_failed_roles:
            return {
                "workspace_id": identifier,
                "state": "failed_roles_require_explicit_abandonment",
                "failed_roles": failed_roles,
                "receipt_status": "blocked",
                "external_closeout_checklist": _external_closeout_checklist(manifest),
            }
        task_states = {
            role: _task_public(manifest["tasks"].get(role))
            for role in ("writer", "tests", "review")
        }
        active = [role for role, value in task_states.items() if not value["terminal"]]
        cancelled: list[str] = []
        if active and not cancel_running:
            return {
                "workspace_id": identifier,
                "state": "active_tasks",
                "active_roles": active,
                "tasks": task_states,
                "receipt_status": "blocked",
                "external_closeout_checklist": _external_closeout_checklist(manifest),
            }
        if active:
            for role in active:
                task_id = manifest["tasks"].get(role)
                if task_id is not None:
                    tasks.grabowski_task_cancel(str(task_id))
                    cancelled.append(role)
            task_states = {
                role: _task_public(manifest["tasks"].get(role))
                for role in ("writer", "tests", "review")
            }
            if not all(value["terminal"] for value in task_states.values()):
                raise AgentWorkspaceActionError("not all tasks reached a terminal state after cancellation")
        receipt = {
            "schema_version": 1,
            "state": "closing",
            "workspace_id": identifier,
            "expected_head": head,
            "expected_diff_sha256": diff_sha,
            "expected_result_sha256": result_sha,
            "closed_at": _utc(),
            "task_states": task_states,
            "cancelled_roles": cancelled,
            "writer_worktree": manifest["writer_worktree"],
            "writer_branch": manifest["writer_branch"],
            "worktree_preserved": True,
            "branch_preserved": True,
            "dirty": snapshot["dirty"],
            "tmux_removed": False,
            "resources_released": False,
            "no_unsecured_changes_discarded": True,
            "failed_roles": failed_roles,
            "abandon_failed_roles": abandon_failed_roles,
            "closure_outcome": "abandoned_failed_roles" if failed_roles else "successful",
        }
        _atomic_json(_workspace_dir(identifier) / "close-receipt.json", receipt)
        if remove_tmux_session and _tmux_has_session(str(manifest["session_name"])):
            killed = _tmux_result(["kill-session", "-t", str(manifest["session_name"])])
            if killed["returncode"] != 0:
                raise AgentWorkspaceActionError(str(killed.get("stderr") or "tmux session removal failed"))
            receipt["tmux_removed"] = True
        expected_resource_keys = set(manifest["resources"]["lease_keys"])
        release_error: str | None = None
        released_resource_keys: set[str] = set()
        try:
            released = resources.release_resources(
                str(manifest["resources"]["owner_id"]),
                sorted(expected_resource_keys),
            )
            released_items = released.get("released") if isinstance(released, dict) else None
            if not isinstance(released_items, list):
                raise AgentWorkspaceActionError("resource release returned an invalid receipt")
            released_resource_keys = {
                str(item.get("resource_key"))
                for item in released_items
                if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
            }
        except Exception as release_exc:
            release_error = _error_summary(release_exc)
        receipt["released_resource_keys"] = sorted(released_resource_keys)
        receipt["resource_release_error"] = release_error
        try:
            live_resources = resources.list_resources(
                owner_id=str(manifest["resources"]["owner_id"]),
                include_expired=False,
                limit=MAX_PATHS + 8,
            )
            observed_live_keys = {
                str(item.get("resource_key"))
                for item in live_resources
                if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
            }
        except Exception as observe_exc:
            receipt["state"] = "resource_release_unverified"
            receipt["resource_release_observation_error"] = (
                _error_summary(observe_exc)
            )
            receipt["receipt_sha256"] = _sha256_json(receipt)
            _atomic_json(_workspace_dir(identifier) / "close-receipt.json", receipt)
            raise AgentWorkspaceActionError(
                "resource release outcome is unverified; close remains incomplete"
            ) from observe_exc
        remaining_resource_keys = expected_resource_keys & observed_live_keys
        receipt["remaining_resource_keys"] = sorted(remaining_resource_keys)
        receipt["resources_released"] = not remaining_resource_keys
        if remaining_resource_keys:
            receipt["state"] = "resource_release_incomplete"
            receipt["receipt_sha256"] = _sha256_json(receipt)
            _atomic_json(_workspace_dir(identifier) / "close-receipt.json", receipt)
            raise AgentWorkspaceActionError(
                "resource release incomplete; remaining keys: "
                + ", ".join(sorted(remaining_resource_keys))
            )
        _append_workspace_event(
            manifest, "workspace_lease_release",
            outcome="verified" if not remaining_resource_keys else "incomplete",
            evidence={"released_resource_keys": sorted(released_resource_keys), "remaining_resource_keys": sorted(remaining_resource_keys)},
        )
        receipt["state"] = "complete"
        receipt["receipt_sha256"] = _sha256_json(receipt)
        _atomic_json(_workspace_dir(identifier) / "close-receipt.json", receipt)
        manifest["close_receipt"] = receipt
        outcome_receipt = _publish_workspace_outcome(manifest, "close")
        _append_workspace_event(
            manifest, "workspace_closed", outcome=receipt["closure_outcome"],
            evidence={"receipt_sha256": receipt["receipt_sha256"], "resources_released": receipt["resources_released"]},
        )
        _write_manifest(manifest)
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "agent-workspace-close",
                "workspace_id": identifier,
                "writer_head": head,
                "diff_sha256": diff_sha,
                "result_sha256": result_sha,
                "worktree_preserved": True,
            }
        )
        return {
            "workspace_id": identifier,
            "close_receipt": receipt,
            "idempotent": False,
            "outcome_receipt": outcome_receipt,
            "external_closeout_checklist": _external_closeout_checklist(manifest),
        }


def _pane_snapshot(workspace_id: str, role: str) -> str:
    try:
        manifest = _manifest(workspace_id)
    except Exception as exc:
        return f"Agent Workspace {workspace_id}\nRole: {role}\nManifest unavailable: {exc}\n"
    task_id = manifest.get("tasks", {}).get(role) if role != "captain" else None
    lines = [
        "!!! TMUX IS UI ONLY — TRUST GIT, TASKS AND RECEIPTS !!!",
        "Pane exit or visible output never establishes success.",
        "",
        f"Agent Workspace: {workspace_id}",
        f"Role: {role.capitalize()}",
        f"Binding: {manifest['binding']['kind']}:{manifest['binding']['id']}",
        f"Repository: {manifest['repository']}",
        f"Writer worktree: {manifest['writer_worktree']}",
        f"Expected base: {manifest['expected_base_head']}",
    ]
    if task_id is None:
        lines.append("Task: not started" if role != "captain" else "Captain: integration/control view")
    else:
        lines.append(f"Task: {task_id}")
    if role in {"writer", "tests", "review"}:
        try:
            receipt = _role_receipt(manifest, role)
        except Exception as exc:
            lines.append(f"Receipt: unreadable ({type(exc).__name__}: {exc})")
        else:
            if isinstance(receipt, dict):
                lines.append(
                    f"Receipt: integrity={'PASS' if _receipt_integrity(receipt) else 'BLOCK'} "
                    f"rc={receipt.get('returncode')} verdict={receipt.get('verdict', '-')} "
                    f"error={receipt.get('error', '-')}"
                )
            else:
                lines.append("Receipt: pending")
    collection = manifest.get("collection")
    if isinstance(collection, dict):
        lines.append(f"Collection: {collection.get('state')} {collection.get('result_sha256', '')}")
    else:
        lines.append("Collection: pending")
    if manifest.get("close_receipt") is not None:
        lines.append("Closed: yes (worktree preserved)")
    return "\n".join(lines) + "\n"


def _pane_loop(workspace_id: str, role: str) -> int:
    if WORKSPACE_ID_RE.fullmatch(workspace_id) is None or role not in ALL_ROLES:
        return 2
    while True:
        sys.stdout.write("\x1b[2J\x1b[H" + _pane_snapshot(workspace_id, role))
        sys.stdout.flush()
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            return 130


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 3 and arguments[0] == "pane":
        return _pane_loop(arguments[1], arguments[2])
    print("usage: python -m grabowski_agent_workspace pane WORKSPACE_ID ROLE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

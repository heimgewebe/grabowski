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
import tempfile
import time
from typing import Any, Callable, Iterable

import grabowski_agent_role as agent_role
import grabowski_mcp as base
import grabowski_resources as resources
import grabowski_tasks as tasks
import grabowski_command_identity as command_identity
import grabowski_checkouts as checkouts
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
ROLE_PREFLIGHT_CACHE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_ROLE_PREFLIGHT_CACHE_ROOT",
        str(operator.STATE_DIR / "agent-role-preflight-cache"),
    )
).expanduser()
TMUX = Path(os.environ.get("GRABOWSKI_TMUX_BIN", shutil.which("tmux") or "/usr/bin/tmux"))
BUREAU = Path(os.environ.get("GRABOWSKI_BUREAU_BIN", shutil.which("bureau") or str(Path.home() / ".local/bin/bureau")))
BUREAU_ROOT = Path(os.environ.get("GRABOWSKI_BUREAU_ROOT", str(Path.home() / "repos/bureau"))).expanduser()
SCHEMA_VERSION = 1
WORKSPACE_RUNTIME_IDENTITY_SCHEMA_VERSION = 1
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
MAX_INTEGRATION_PROBE_OUTPUT_CHARS = 4000
MAX_INTEGRATION_PROBE_PATHS = 128
WRITER_FREEZE_SETTLE_SECONDS = 0.1
WORKSPACE_LOCK_TIMEOUT_SECONDS = 10.0
WORKSPACE_LOCK_POLL_SECONDS = 0.05
AGENT_WORKSPACE_TASK_HOST = "heim-pc"
MAX_ROLE_RETRIES = 1
MAX_WRITER_HANDOFFS = 1
MAX_WRITER_HANDOFF_PREFLIGHT_BLOCKS = 16
WRITER_HANDOFF_TERMINAL_STATES = frozenset({"failed", "cancelled", "timed_out", "signalled"})
ROLE_PREFLIGHT_CACHE_TTL_SECONDS = 300
MAX_WORKSPACE_EVENTS = 512
WORKSPACE_CLEANUP_RETENTION_SECONDS = 30 * 24 * 60 * 60
MAX_CLEANUP_WORKSPACES = 100
MAX_WORKSPACE_REFERENCE_SCAN = 1000
STALE_WORKSPACE_MINIMUM_AGE_SECONDS = 60 * 60
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
ROUTE_POLICY_VERSION = "workspace-routing-v2.1"
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


def _source_file_sha256(path: Path) -> str | None:
    descriptor = -1
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return None
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
        ):
            return None
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _workspace_runtime_identity() -> dict[str, Any]:
    deployment: dict[str, Any] = {}
    try:
        deployment = _load_json(base.DEPLOYMENT_MANIFEST)
    except (FileNotFoundError, OSError, ValueError, PermissionError, json.JSONDecodeError):
        deployment = {}
    body = {
        "schema_version": WORKSPACE_RUNTIME_IDENTITY_SCHEMA_VERSION,
        "workspace_schema_version": SCHEMA_VERSION,
        "runtime_release": (
            deployment.get("release_id") if isinstance(deployment.get("release_id"), str) else None
        ),
        "runtime_repo_head": (
            deployment.get("repo_head") if isinstance(deployment.get("repo_head"), str) else None
        ),
        "python_implementation": sys.implementation.name,
        "python_version": list(sys.version_info[:3]),
        "sandbox_contract": agent_role.SANDBOX_LABEL,
        "toolchain_probe_contract": getattr(agent_role, "TOOLCHAIN_PROBE_CONTRACT", "role-toolchain-probe-v1"),
        "workspace_source_sha256": _source_file_sha256(Path(__file__)),
        "role_source_sha256": _source_file_sha256(Path(agent_role.__file__)),
    }
    return {**body, "identity_sha256": _sha256_json(body)}


def _task_argv_sha256(value: Any) -> str:
    """Use the task store's versioned argv identity contract."""
    try:
        return command_identity.argv_sha256(value)
    except ValueError as exc:
        raise AgentWorkspaceError(f"invalid task argv identity: {exc}") from exc


def _bureau_result_envelope(
    stdout: Any, label: str
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Parse Bureau direct JSON or a compatibility-checked result envelope."""
    try:
        payload = json.loads(str(stdout or ""))
    except json.JSONDecodeError as exc:
        raise AgentWorkspaceError(f"{label} returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise AgentWorkspaceError(f"{label} returned a non-object payload")
    has_envelope_keys = "result" in payload or "runtime_identity" in payload
    if not has_envelope_keys:
        return payload, None
    result = payload.get("result")
    identity = payload.get("runtime_identity")
    if not isinstance(result, dict) or not isinstance(identity, dict):
        raise AgentWorkspaceError(f"{label} returned an invalid result envelope")
    compatibility = identity.get("compatibility")
    if not isinstance(compatibility, dict):
        raise AgentWorkspaceError(f"{label} omitted Bureau runtime compatibility")
    status = compatibility.get("status")
    if status not in {"compatible", "canonical-read-only"}:
        reasons = compatibility.get("reason_codes")
        reason_text = (
            ",".join(str(item) for item in reasons)
            if isinstance(reasons, list)
            else "unknown"
        )
        raise AgentWorkspaceError(
            f"{label} Bureau runtime is not read-compatible: {status} ({reason_text})"
        )
    return result, identity


def _bureau_result_payload(stdout: Any, label: str) -> dict[str, Any]:
    """Accept legacy direct JSON and the current Bureau result envelope."""
    return _bureau_result_envelope(stdout, label)[0]


def _bureau_command_cwd() -> Path:
    try:
        root = BUREAU.parent.resolve(strict=True)
    except OSError as exc:
        raise AgentWorkspaceError("Bureau executable directory is unavailable") from exc
    if root.is_symlink() or not root.is_dir():
        raise AgentWorkspaceError("Bureau executable directory is unsafe")
    return root


def _legacy_bureau_root() -> Path:
    if BUREAU_ROOT.is_symlink() or not BUREAU_ROOT.is_dir():
        raise AgentWorkspaceError(f"Bureau root unavailable or unsafe: {BUREAU_ROOT}")
    return BUREAU_ROOT.resolve(strict=True)


def _canonical_bureau_registry_root(
    identity: dict[str, Any], label: str
) -> Path:
    manifest = identity.get("manifest")
    canonical = manifest.get("canonical_registry") if isinstance(manifest, dict) else None
    if (
        not isinstance(canonical, dict)
        or canonical.get("available") is not True
        or canonical.get("valid") is not True
    ):
        raise AgentWorkspaceError(f"{label} omitted a valid canonical Registry snapshot")
    raw = canonical.get("root")
    if not isinstance(raw, str) or not raw or len(raw) > 4096 or "\x00" in raw:
        raise AgentWorkspaceError(f"{label} returned an invalid canonical Registry root")
    root = Path(raw)
    if not root.is_absolute() or root.is_symlink():
        raise AgentWorkspaceError(f"{label} canonical Registry root is unsafe")
    try:
        resolved = root.resolve(strict=True)
        metadata = root.stat()
    except OSError as exc:
        raise AgentWorkspaceError(
            f"{label} canonical Registry root is unavailable"
        ) from exc
    if resolved != root or not root.is_dir() or stat.S_IMODE(metadata.st_mode) & 0o222:
        raise AgentWorkspaceError(f"{label} canonical Registry root is not immutable")
    return root


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


def _normalize_route_input_facts(
    value: Any, *, schema_version: int | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentWorkspaceError("route_evidence.input_facts must be an object")
    expected_v1 = {
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
    expected_v2 = {
        "task_kind",
        "changed_file_estimate",
        "expected_duration_minutes",
        "novelty",
        "risk_flags",
        "connector_instability",
        "concurrent_external_activity",
        "parallelization_candidate",
        "decision_fork",
        "architecture_hypotheses",
        "user_requested_external",
        "available_external_agents",
    }
    observed_fields = set(value)
    resolved_schema = schema_version
    if resolved_schema is None:
        resolved_schema = (
            1
            if observed_fields == expected_v1
            else 2
            if observed_fields == expected_v2
            else None
        )
    expected = (
        expected_v1
        if resolved_schema == 1
        else expected_v2
        if resolved_schema == 2
        else set()
    )
    if observed_fields != expected:
        raise AgentWorkspaceError("route_evidence.input_facts shape is invalid")
    task_kind = _required_string(
        value.get("task_kind"),
        "route_evidence.input_facts.task_kind",
        max_length=32,
    )
    if task_kind not in ROUTE_TASK_KINDS:
        raise AgentWorkspaceError("route_evidence task_kind is invalid")
    changed_files = value.get("changed_file_estimate")
    duration = value.get("expected_duration_minutes")
    if (
        isinstance(changed_files, bool)
        or not isinstance(changed_files, int)
        or not 0 <= changed_files <= 10000
    ):
        raise AgentWorkspaceError("route_evidence changed_file_estimate is invalid")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or not 0 <= duration <= 10080
    ):
        raise AgentWorkspaceError("route_evidence expected_duration_minutes is invalid")
    novelty = _required_string(
        value.get("novelty"),
        "route_evidence.input_facts.novelty",
        max_length=16,
    )
    if novelty not in ROUTE_NOVELTY:
        raise AgentWorkspaceError("route_evidence novelty is invalid")
    raw_flags = value.get("risk_flags")
    if not isinstance(raw_flags, list) or len(raw_flags) > len(ROUTE_RISK_FLAGS):
        raise AgentWorkspaceError("route_evidence risk_flags are invalid")
    flags = sorted(
        {
            _required_string(
                item, "route_evidence.risk_flag", max_length=32
            )
            for item in raw_flags
        }
    )
    if len(flags) != len(raw_flags) or set(flags) - ROUTE_RISK_FLAGS:
        raise AgentWorkspaceError("route_evidence risk_flags are invalid")
    booleans: dict[str, bool] = {}
    boolean_fields = (
        ("connector_instability", "parallel_work", "user_requested_external")
        if resolved_schema == 1
        else (
            "connector_instability",
            "concurrent_external_activity",
            "parallelization_candidate",
            "decision_fork",
            "user_requested_external",
        )
    )
    for field in boolean_fields:
        candidate = value.get(field)
        if not isinstance(candidate, bool):
            raise AgentWorkspaceError(f"route_evidence {field} must be boolean")
        booleans[field] = candidate
    architecture_hypotheses = None
    if resolved_schema == 2:
        architecture_hypotheses = value.get("architecture_hypotheses")
        if (
            isinstance(architecture_hypotheses, bool)
            or not isinstance(architecture_hypotheses, int)
            or not 1 <= architecture_hypotheses <= 4
        ):
            raise AgentWorkspaceError(
                "route_evidence architecture_hypotheses must be between 1 and 4"
            )
    raw_agents = value.get("available_external_agents")
    if (
        not isinstance(raw_agents, list)
        or len(raw_agents) > len(ROUTE_EXTERNAL_AGENTS)
    ):
        raise AgentWorkspaceError(
            "route_evidence available_external_agents are invalid"
        )
    agents = [
        _required_string(
            item, "route_evidence.external_agent", max_length=32
        )
        for item in raw_agents
    ]
    if len(set(agents)) != len(agents) or set(agents) - ROUTE_EXTERNAL_AGENTS:
        raise AgentWorkspaceError(
            "route_evidence available_external_agents are invalid"
        )
    return {
        "task_kind": task_kind,
        "changed_file_estimate": changed_files,
        "expected_duration_minutes": duration,
        "novelty": novelty,
        "risk_flags": flags,
        **booleans,
        **(
            {"architecture_hypotheses": architecture_hypotheses}
            if resolved_schema == 2
            else {}
        ),
        "available_external_agents": agents,
    }


def _route_decision_v1(input_facts: dict[str, Any]) -> dict[str, Any]:
    """Replay the original deterministic routing policy for legacy evidence."""
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
            {
                "provider": external_available[0],
                "mode": "competitor",
                "timing": "before_primary_writer",
            },
            {
                "provider": external_available[1],
                "mode": "contrast",
                "timing": "after_primary_plan_or_candidate",
            },
        ]
    elif mode == "workspace_with_contrast":
        candidates = [
            {
                "provider": external_available[0],
                "mode": "contrast",
                "timing": "after_primary_plan_or_candidate",
            }
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


def _route_decision_v2(input_facts: dict[str, Any]) -> dict[str, Any]:
    """Route conservatively: one writer by default, contrast only for qualified R3 code."""
    kind = str(input_facts["task_kind"])
    changed_files = int(input_facts["changed_file_estimate"])
    duration = int(input_facts["expected_duration_minutes"])
    novelty = str(input_facts["novelty"])
    risk_flags = list(input_facts["risk_flags"])
    connector_instability = bool(input_facts["connector_instability"])
    concurrent_activity = bool(input_facts["concurrent_external_activity"])
    parallelization_candidate = bool(input_facts["parallelization_candidate"])
    decision_fork = bool(input_facts["decision_fork"])
    architecture_hypotheses = int(input_facts["architecture_hypotheses"])
    external_requested = bool(input_facts["user_requested_external"])
    external_available = list(input_facts["available_external_agents"])

    critical_flags = {
        "security",
        "runtime",
        "deployment",
        "schema",
        "concurrency",
        "data_migration",
        "privilege",
        "cross_repo",
        "destructive",
        "user_data",
    }
    design_flags = {
        "security",
        "schema",
        "concurrency",
        "data_migration",
        "cross_repo",
    }
    score = 0
    if kind in {"code", "operations"}:
        score += 1
    if changed_files >= 7:
        score += 1
    if changed_files >= 15:
        score += 1
    if duration >= 60:
        score += 1
    if duration >= 180:
        score += 1
    score += {"low": 0, "medium": 1, "high": 2}[novelty]
    score += min(4, len(risk_flags))
    if connector_instability:
        score += 1
    if concurrent_activity:
        score += 1

    trivial_work = bool(
        changed_files <= 1
        and duration <= 15
        and novelty == "low"
        and not risk_flags
        and not connector_instability
        and not concurrent_activity
    )
    critical_risk = bool(set(risk_flags) & critical_flags)
    r3_scale = bool(
        kind == "code"
        and novelty == "high"
        and duration >= 120
        and changed_files >= 8
    )
    if trivial_work:
        risk_tier = "R0"
    elif critical_risk or r3_scale:
        risk_tier = "R3"
    elif (
        (
            kind == "code"
            and (
                changed_files >= 7
                or duration >= 90
                or novelty == "high"
                or bool(risk_flags)
                or connector_instability
                or concurrent_activity
            )
        )
        or (
            kind == "operations"
            and (
                duration >= 90
                or bool(risk_flags)
                or connector_instability
                or concurrent_activity
            )
        )
        or (kind == "analysis" and novelty == "high" and duration >= 90)
    ):
        risk_tier = "R2"
    else:
        risk_tier = "R1"

    if risk_tier in {"R0", "R1"}:
        mode = (
            "direct_operator"
            if kind in {"docs", "analysis"}
            else "isolated_worktree"
        )
    elif risk_tier == "R2":
        if kind == "code" and (
            changed_files >= 7
            or duration >= 90
            or novelty == "high"
            or bool(risk_flags)
        ):
            mode = "full_workspace"
        elif kind == "operations" and (bool(risk_flags) or connector_instability):
            mode = "full_workspace"
        else:
            mode = (
                "direct_operator"
                if kind in {"docs", "analysis"}
                else "isolated_worktree"
            )
    else:
        mode = "full_workspace"

    design_space = bool(novelty == "high" or set(risk_flags) & design_flags)
    contrast_eligible = bool(
        kind == "code"
        and risk_tier == "R3"
        and design_space
        and external_available
        and (
            external_requested
            or (
                novelty == "high"
                and duration >= 120
                and (
                    bool(set(risk_flags) & design_flags)
                    or changed_files >= 10
                )
            )
        )
    )
    competition_eligible = bool(
        contrast_eligible
        and decision_fork
        and architecture_hypotheses >= 2
        and len(external_available) >= 2
    )
    candidates: list[dict[str, str]] = []
    if competition_eligible:
        mode = "workspace_with_competition"
        candidates = [
            {
                "provider": external_available[0],
                "mode": "competitor",
                "timing": "before_primary_writer",
            },
            {
                "provider": external_available[1],
                "mode": "contrast",
                "timing": "after_primary_plan_or_candidate",
            },
        ]
    elif contrast_eligible:
        mode = "workspace_with_contrast"
        candidates = [
            {
                "provider": external_available[0],
                "mode": "contrast",
                "timing": "after_primary_plan_or_candidate",
            }
        ]

    assessment_blockers: list[str] = []
    if kind != "code" or risk_tier != "R3":
        assessment_blockers.append("parallel writer pilot is restricted to R3 code")
    if duration < 180:
        assessment_blockers.append("expected duration is below 180 minutes")
    if changed_files < 10:
        assessment_blockers.append("changed file estimate is below 10")
    eligible_for_assessment = bool(
        parallelization_candidate
        and kind == "code"
        and risk_tier == "R3"
        and duration >= 180
        and changed_files >= 10
    )
    parallel_writer_pilot = {
        "requested": parallelization_candidate,
        "eligible_for_assessment": eligible_for_assessment,
        "execution_authorized": False,
        "workspace_group_implemented": False,
        "required_shard_count": 2,
        "minimum_estimated_minutes_per_shard": 90,
        "assessment_blockers": assessment_blockers,
        "implementation_blockers": [
            "explicit two-shard scope and conflict-domain proof is required",
            "integration workspace and cross-shard tests are not implemented",
        ],
    }
    return {
        "score": score,
        "risk_tier": risk_tier,
        "route_policy_version": ROUTE_POLICY_VERSION,
        "execution_mode": mode,
        "external_candidates": candidates,
        "design_space": design_space,
        "trivial_work": trivial_work,
        "parallel_writer_pilot": parallel_writer_pilot,
        "contrast_eligible": contrast_eligible,
        "competition_eligible": competition_eligible,
    }


def _route_decision(input_facts: dict[str, Any]) -> dict[str, Any]:
    """Replay the policy matching the exact route-input schema."""
    return (
        _route_decision_v1(input_facts)
        if "parallel_work" in input_facts
        else _route_decision_v2(input_facts)
    )


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
    schema_version = value.get("schema_version")
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
    if schema_version == 2:
        expected |= {
            "route_policy_version",
            "risk_tier",
            "parallel_writer_pilot",
        }
    if set(value) != expected or schema_version not in {1, 2}:
        raise AgentWorkspaceError("route_evidence shape is invalid")
    recommendation_id = _required_string(
        value.get("recommendation_id"),
        "route_evidence.recommendation_id",
        max_length=64,
    ).lower()
    if SHA256_RE.fullmatch(recommendation_id) is None:
        raise AgentWorkspaceError("route_evidence recommendation_id is invalid")
    score = value.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 20:
        raise AgentWorkspaceError("route_evidence score is invalid")
    recommended = _required_string(
        value.get("recommended_route"),
        "route_evidence.recommended_route",
        max_length=40,
    )
    actual = _required_string(
        value.get("actual_route"),
        "route_evidence.actual_route",
        max_length=40,
    )
    if recommended not in ROUTE_EXECUTION_MODES or actual not in ROUTE_EXECUTION_MODES:
        raise AgentWorkspaceError("route_evidence route is invalid")
    if actual not in {
        "full_workspace",
        "workspace_with_contrast",
        "workspace_with_competition",
    }:
        raise AgentWorkspaceError(
            "agent workspace actual_route must be a workspace route"
        )
    facts = _normalize_route_input_facts(
        value.get("input_facts"), schema_version=schema_version
    )
    raw_candidates = value.get("external_candidates")
    if not isinstance(raw_candidates, list) or len(raw_candidates) > 2:
        raise AgentWorkspaceError("route_evidence external_candidates are invalid")
    candidates: list[dict[str, str]] = []
    for item in raw_candidates:
        if (
            not isinstance(item, dict)
            or set(item) != {"provider", "mode", "timing"}
        ):
            raise AgentWorkspaceError(
                "route_evidence external candidate shape is invalid"
            )
        provider = _required_string(
            item.get("provider"),
            "route_evidence.external_candidate.provider",
            max_length=32,
        )
        mode = _required_string(
            item.get("mode"),
            "route_evidence.external_candidate.mode",
            max_length=32,
        )
        timing = _required_string(
            item.get("timing"),
            "route_evidence.external_candidate.timing",
            max_length=80,
        )
        if provider not in ROUTE_EXTERNAL_AGENTS or mode not in {
            "competitor",
            "contrast",
        }:
            raise AgentWorkspaceError(
                "route_evidence external candidate is invalid"
            )
        candidates.append(
            {"provider": provider, "mode": mode, "timing": timing}
        )
    decision = _route_decision(facts)
    if schema_version == 2:
        if value.get("route_policy_version") != decision["route_policy_version"]:
            raise AgentWorkspaceError(
                "route_evidence route policy version is invalid"
            )
        if value.get("risk_tier") != decision["risk_tier"]:
            raise AgentWorkspaceError("route_evidence risk tier is invalid")
        if value.get("parallel_writer_pilot") != decision["parallel_writer_pilot"]:
            raise AgentWorkspaceError(
                "route_evidence parallel writer pilot is invalid"
            )
    if (
        score != decision["score"]
        or recommended != decision["execution_mode"]
        or candidates != decision["external_candidates"]
    ):
        raise AgentWorkspaceError(
            "route_evidence recommendation does not match deterministic policy replay"
        )
    recommendation_contract = {
        "schema_version": schema_version,
        "score": score,
        "execution_mode": recommended,
        "input_facts": facts,
        "external_candidates": candidates,
    }
    if schema_version == 2:
        recommendation_contract.update(
            {
                "route_policy_version": decision["route_policy_version"],
                "risk_tier": decision["risk_tier"],
                "parallel_writer_pilot": decision["parallel_writer_pilot"],
            }
        )
    expected_id = _sha256_json(recommendation_contract)
    if recommendation_id != expected_id:
        raise AgentWorkspaceError(
            "route_evidence recommendation_id does not match its normalized recommendation"
        )
    reason = value.get("deviation_reason")
    if recommended == actual:
        if reason not in {None, ""}:
            raise AgentWorkspaceError(
                "route_evidence deviation_reason must be empty when routes match"
            )
        clean_reason = None
    else:
        clean_reason = _required_string(
            reason, "route_evidence.deviation_reason", max_length=1000
        )
    result = {
        "schema_version": schema_version,
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
    if schema_version == 2:
        result.update(
            {
                "route_policy_version": decision["route_policy_version"],
                "risk_tier": decision["risk_tier"],
                "parallel_writer_pilot": decision["parallel_writer_pilot"],
            }
        )
    return result


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


def _preflight_stat_identity(path: Path) -> dict[str, Any] | None:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    return {
        "path": str(resolved),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _role_preflight_environment(
    manifest: dict[str, Any], command: list[str]
) -> dict[str, Any]:
    worktree = Path(str(manifest["writer_worktree"]))
    prepared = agent_role.prepare_external_agent_command(command)
    executable = str(prepared.command[0])
    if Path(executable).is_absolute():
        resolved_executable = Path(executable)
    else:
        found = shutil.which(executable)
        resolved_executable = Path(found) if found else Path(executable)
    executable_identity = _preflight_stat_identity(resolved_executable)
    environment_paths: list[dict[str, Any]] = []
    candidate_roots: list[Path] = []
    if executable_identity is not None:
        resolved = Path(str(executable_identity["path"]))
        candidate_roots.extend([resolved.parent.parent, Path("/usr/lib/python3/dist-packages")])
    for source, _target in prepared.extra_read_only:
        candidate_roots.append(Path(source))
    seen: set[str] = set()
    for candidate in candidate_roots:
        identity = _preflight_stat_identity(candidate)
        if identity is None or identity["path"] in seen:
            continue
        seen.add(str(identity["path"]))
        environment_paths.append(identity)
        root = Path(str(identity["path"]))
        pyvenv = root / "pyvenv.cfg"
        pyvenv_identity = _preflight_stat_identity(pyvenv)
        pyvenv_sha256 = _source_file_sha256(pyvenv)
        if pyvenv_identity is not None and pyvenv_sha256 is not None:
            environment_paths.append({**pyvenv_identity, "sha256": pyvenv_sha256})
        for site_packages in sorted(root.glob("lib/python*/site-packages")):
            site_identity = _preflight_stat_identity(site_packages)
            if site_identity is not None and site_identity["path"] not in seen:
                seen.add(str(site_identity["path"]))
                environment_paths.append(site_identity)
    head, diff_identity, dirty = agent_role.current_binding(
        worktree, str(manifest["expected_base_head"])
    )
    body = {
        "schema_version": 1,
        "probe_contract": agent_role.TOOLCHAIN_PROBE_CONTRACT,
        "sandbox": agent_role.SANDBOX_LABEL,
        "command_sha256": _sha256_json(command),
        "prepared_command_sha256": _sha256_json(list(prepared.command)),
        "external_agent_profile": prepared.profile,
        "executable_identity": executable_identity,
        "environment_paths": environment_paths,
        "writer_head": head,
        "writer_diff_identity": diff_identity,
        "writer_dirty": dirty,
        "role_source_sha256": _source_file_sha256(Path(agent_role.__file__)),
    }
    return {**body, "environment_sha256": _sha256_json(body)}


def _preflight_cache_record_valid(record: Any, cache_key: str, now: int) -> bool:
    if not isinstance(record, dict):
        return False
    observed = record.get("record_sha256")
    unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
    created = record.get("created_at_unix")
    return bool(
        record.get("schema_version") == 1
        and record.get("cache_key") == cache_key
        and isinstance(created, int)
        and not isinstance(created, bool)
        and 0 <= now - created <= ROLE_PREFLIGHT_CACHE_TTL_SECONDS
        and isinstance(record.get("probe"), dict)
        and isinstance(observed, str)
        and observed == _sha256_json(unsigned)
    )


def _role_toolchain_preflight(manifest: dict[str, Any], role: str, command: list[str]) -> dict[str, Any]:
    """Validate exact role prerequisites with a short, snapshot-bound cross-workspace cache."""
    worktree = Path(str(manifest["writer_worktree"]))
    checked_at = _utc()
    now = _now()
    environment: dict[str, Any] | None = None
    cache_error: str | None = None
    try:
        environment = _role_preflight_environment(manifest, command)
    except Exception as exc:
        cache_error = _error_summary(exc)
    cache_key = (
        _sha256_json({"role": role, "environment": environment})
        if environment is not None
        else None
    )
    if cache_key is not None:
        cache_path = ROLE_PREFLIGHT_CACHE_ROOT / f"{cache_key}.json"
        try:
            record = _load_json(cache_path)
        except FileNotFoundError:
            record = None
        except Exception as exc:
            record = None
            cache_error = _error_summary(exc)
        if _preflight_cache_record_valid(record, cache_key, now):
            return {
                "role": role,
                "command_sha256": _sha256_json(command),
                "checked_at": checked_at,
                "sandbox": agent_role.SANDBOX_LABEL,
                **dict(record["probe"]),
                "environment": environment,
                "cache": {
                    "eligible": True,
                    "hit": True,
                    "cache_key": cache_key,
                    "created_at_unix": record["created_at_unix"],
                    "ttl_seconds": ROLE_PREFLIGHT_CACHE_TTL_SECONDS,
                },
            }
    probe = agent_role.toolchain_probe(worktree, command)
    if cache_key is not None:
        try:
            ROLE_PREFLIGHT_CACHE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
            if ROLE_PREFLIGHT_CACHE_ROOT.is_symlink() or not ROLE_PREFLIGHT_CACHE_ROOT.is_dir():
                raise PermissionError("role preflight cache root must be a real directory")
            record_body = {
                "schema_version": 1,
                "cache_key": cache_key,
                "created_at_unix": now,
                "environment_sha256": environment["environment_sha256"],
                "probe": probe,
            }
            _atomic_json(
                ROLE_PREFLIGHT_CACHE_ROOT / f"{cache_key}.json",
                {**record_body, "record_sha256": _sha256_json(record_body)},
            )
        except Exception as exc:
            cache_error = _error_summary(exc)
    return {
        "role": role,
        "command_sha256": _sha256_json(command),
        "checked_at": checked_at,
        "sandbox": agent_role.SANDBOX_LABEL,
        **probe,
        "environment": environment,
        "cache": {
            "eligible": cache_key is not None,
            "hit": False,
            "cache_key": cache_key,
            "ttl_seconds": ROLE_PREFLIGHT_CACHE_TTL_SECONDS,
            "error": cache_error,
        },
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


def _tmux_exact_target(session: str) -> str:
    return f"={session}"


def _tmux_has_exact_session(session: str) -> bool:
    result = _tmux_result(["has-session", "-t", _tmux_exact_target(session)])
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


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_bureau_task(
    path: Path, *, require_immutable: bool
) -> tuple[dict[str, Any], bytes]:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AgentWorkspaceError(f"Bureau task is unavailable: {path.name}") from exc
    if resolved != path or path.is_symlink():
        raise AgentWorkspaceError(f"Bureau task path is unsafe: {path.name}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AgentWorkspaceError(f"Bureau task cannot be opened safely: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(linked)
            or opened.st_size > MAX_STATE_JSON_BYTES
        ):
            raise AgentWorkspaceError(f"Bureau task file is unsafe: {path.name}")
        if require_immutable and stat.S_IMODE(opened.st_mode) & 0o222:
            raise AgentWorkspaceError(f"Bureau canonical task file is not immutable: {path.name}")
        chunks: list[bytes] = []
        remaining = MAX_STATE_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_STATE_JSON_BYTES:
            raise AgentWorkspaceError(f"Bureau task exceeds size limit: {path.name}")
        after = os.fstat(descriptor)
        rebound = path.lstat()
        if (
            _stat_identity(opened) != _stat_identity(after)
            or _stat_identity(opened) != _stat_identity(rebound)
        ):
            raise AgentWorkspaceError(f"Bureau task changed while reading: {path.name}")
    finally:
        os.close(descriptor)
    try:
        task = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentWorkspaceError(f"Bureau task JSON is invalid: {path.stem}") from exc
    if not isinstance(task, dict):
        raise AgentWorkspaceError(f"Bureau task JSON is not an object: {path.stem}")
    return task, raw


def _verify_bureau_binding(
    binding_kind: str,
    binding_id: str,
    *,
    runner: CommandRunner = _run,
) -> dict[str, Any]:
    if not BUREAU.is_file() or not os.access(BUREAU, os.X_OK):
        raise AgentWorkspaceError(f"Bureau executable unavailable: {BUREAU}")
    command_cwd = _bureau_command_cwd()
    if binding_kind == "thread_focus":
        result = _checked(
            runner,
            command_cwd,
            [
                str(BUREAU), "--json", "live-list",
                "--kind", "thread_focus", "--thread-id", binding_id, "--limit", "50",
            ],
            label="Bureau thread focus lookup",
        )
        payload = _bureau_result_payload(result.get("stdout"), "Bureau thread focus lookup")
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
            command_cwd,
            [
                str(BUREAU), "--json", "registry-truth",
                "--strict", "--no-baseline-probe",
            ],
            label="Bureau registry truth",
        )
        truth_payload, runtime_identity = _bureau_result_envelope(
            truth.get("stdout"), "Bureau registry truth"
        )
        if not isinstance(truth_payload, dict) or truth_payload.get("healthy") is not True:
            raise AgentWorkspaceError("Bureau registry truth is not healthy")
        if runtime_identity is None:
            root = _legacy_bureau_root()
            registry_source = "legacy-explicit-root"
        else:
            root = _canonical_bureau_registry_root(
                runtime_identity, "Bureau registry truth"
            )
            registry_source = "canonical-runtime-snapshot"
        task_path = root / "registry" / "tasks" / f"{binding_id}.json"
        task, task_bytes = _read_bureau_task(
            task_path,
            require_immutable=runtime_identity is not None,
        )
        if task.get("id") != binding_id:
            raise AgentWorkspaceError("Bureau task identity mismatch")
        state = task.get("state")
        if state not in {"inbox", "planned", "ready"}:
            raise AgentWorkspaceError(f"Bureau task is not actionable: {binding_id} state={state}")
        task_sha256 = hashlib.sha256(task_bytes).hexdigest()
        evidence = {
            "source": "bureau-task-registry",
            "registry_source": registry_source,
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


def _writer_task_argv(
    manifest: dict[str, Any],
    *,
    command: list[str] | None = None,
    attempt: int = 1,
    launch_nonce: str | None = None,
) -> list[str]:
    allowed_arguments = [
        value
        for relative in manifest["scope"]["allowed_paths"]
        for value in ("--allowed-path", str(relative))
    ]
    selected_command = list(manifest["commands"]["writer"]) if command is None else list(command)
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
        *([] if launch_nonce is None else ["--launch-nonce", launch_nonce]),
        "--output",
        str(_role_receipt_path(manifest, "writer", attempt=attempt)),
        "--",
        *selected_command,
    ]


def _writer_attempts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    command = list(manifest["commands"]["writer"])
    legacy = {
        "attempt": 1,
        "actor": "initial_writer",
        "task_id": manifest["tasks"]["writer"],
        "command": command,
        "command_sha256": _sha256_json(command),
        "task_argv_sha256": _task_argv_sha256(_writer_task_argv(manifest)),
        "receipt_path": str(_role_receipt_path(manifest, "writer")),
        "expected_base_head": manifest["expected_base_head"],
        "expected_branch": manifest["writer_branch"],
    }
    stored = manifest.get("writer_attempts")
    if stored is None:
        return [legacy]
    if not isinstance(stored, list) or not stored:
        raise AgentWorkspaceError("writer_attempts must be a non-empty list")
    attempts = [dict(item) for item in stored if isinstance(item, dict)]
    if len(attempts) != len(stored):
        raise AgentWorkspaceError("writer_attempts entries must be objects")
    if len(attempts) > MAX_WRITER_HANDOFFS + 1:
        raise AgentWorkspaceError("writer_attempts exceeds the handoff limit")
    numbers = [item.get("attempt") for item in attempts]
    if numbers != list(range(1, len(attempts) + 1)):
        raise AgentWorkspaceError("writer_attempts must be contiguous and ordered")
    first = attempts[0]
    for key, expected in legacy.items():
        if first.get(key) != expected:
            raise AgentWorkspaceError("writer attempt one does not match original binding")
    if len(attempts) == 2:
        handoff = attempts[1]
        if handoff.get("actor") != "operator_handoff":
            raise AgentWorkspaceError("writer handoff actor is invalid")
        if handoff.get("previous_task_id") != first.get("task_id"):
            raise AgentWorkspaceError("writer handoff previous task binding is invalid")
        if handoff.get("previous_state") not in WRITER_HANDOFF_TERMINAL_STATES:
            raise AgentWorkspaceError("writer handoff previous state is invalid")
    return attempts


def _writer_final_attempt(manifest: dict[str, Any]) -> int:
    value = manifest.get("writer_final_attempt", 1)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise AgentWorkspaceError("writer_final_attempt is invalid")
    return value


def _writer_attempt_refs(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    fields = (
        "attempt", "actor", "task_id", "command_sha256", "task_argv_sha256",
        "receipt_path", "expected_base_head", "expected_branch",
        "previous_task_id", "previous_state", "started_at", "start_reconciled",
        "launch_nonce_sha256",
    )
    return [{key: item.get(key) for key in fields if key in item} for item in _writer_attempts(manifest)]


def _effective_writer_attempt(manifest: dict[str, Any]) -> dict[str, Any]:
    attempts = _writer_attempts(manifest)
    final = _writer_final_attempt(manifest)
    if final != len(attempts):
        raise AgentWorkspaceError("writer_final_attempt must select the last append-only attempt")
    selected = dict(attempts[final - 1])
    command = selected.get("command")
    task_id = selected.get("task_id")
    if not isinstance(command, list) or not command or not all(isinstance(v, str) and v for v in command):
        raise AgentWorkspaceError("effective writer command is invalid")
    if not isinstance(task_id, str) or not task_id:
        raise AgentWorkspaceError("effective writer task is invalid")
    if selected.get("command_sha256") != _sha256_json(command):
        raise AgentWorkspaceError("effective writer command hash mismatch")
    launch_nonce = selected.get("launch_nonce")
    if final > 1:
        if not isinstance(launch_nonce, str) or len(launch_nonce) != 24:
            raise AgentWorkspaceError("effective writer launch nonce is invalid")
        if selected.get("launch_nonce_sha256") != hashlib.sha256(launch_nonce.encode()).hexdigest():
            raise AgentWorkspaceError("effective writer launch nonce hash mismatch")
    elif launch_nonce is not None:
        raise AgentWorkspaceError("legacy writer attempt may not carry a launch nonce")
    argv = _writer_task_argv(
        manifest,
        command=command,
        attempt=final,
        launch_nonce=launch_nonce,
    )
    if selected.get("task_argv_sha256") != _task_argv_sha256(argv):
        raise AgentWorkspaceError("effective writer task argv hash mismatch")
    if selected.get("receipt_path") != str(_role_receipt_path(manifest, "writer", attempt=final)):
        raise AgentWorkspaceError("effective writer receipt path mismatch")
    if selected.get("expected_base_head") != manifest["expected_base_head"]:
        raise AgentWorkspaceError("effective writer expected head mismatch")
    if selected.get("expected_branch") != manifest["writer_branch"]:
        raise AgentWorkspaceError("effective writer expected branch mismatch")
    return selected


def _writer_task_binding_reasons(
    manifest: dict[str, Any],
    attempt: dict[str, Any],
    writer: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if writer.get("task_id") != attempt.get("task_id"):
        reasons.append("writer_task_id_mismatch")
    if writer.get("host") != _bound_task_host(manifest):
        reasons.append("writer_task_host_mismatch")
    if writer.get("argv_sha256") != attempt.get("task_argv_sha256"):
        reasons.append("writer_task_argv_mismatch")
    if writer.get("cwd") != manifest.get("writer_worktree"):
        reasons.append("writer_task_cwd_mismatch")
    if writer.get("attempt") != 1:
        reasons.append("writer_task_attempt_mismatch")
    if writer.get("resume_policy") != "never":
        reasons.append("writer_task_resume_policy_mismatch")
    return reasons


def _writer_handoff_eligibility(
    manifest: dict[str, Any],
    writer: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    attempts = _writer_attempts(manifest)
    reasons = _writer_task_binding_reasons(manifest, attempts[-1], writer)
    if len(attempts) - 1 >= MAX_WRITER_HANDOFFS:
        reasons.append("handoff_limit_reached")
    if manifest.get("creation_state") != "ready":
        reasons.append("creation_state_not_ready")
    _, route_passed, _ = _route_gate(manifest)
    if not route_passed:
        reasons.append("route_evidence_incomplete")
    if manifest.get("close_receipt") is not None:
        reasons.append("workspace_closed")
    if manifest.get("collection") is not None:
        reasons.append("collection_already_started")
    if manifest.get("frozen_writer") is not None:
        reasons.append("writer_already_frozen")
    intents = manifest.get("task_start_intents")
    if not isinstance(intents, dict) or intents:
        reasons.append("task_start_reconcile_required")
    state = str(writer.get("state"))
    if state in {"outcome_unknown", "interrupted", "observation_error"}:
        reasons.append("writer_outcome_reconcile_required")
    elif not writer.get("terminal"):
        reasons.append("writer_not_terminal")
    elif state not in WRITER_HANDOFF_TERMINAL_STATES:
        reasons.append("writer_not_failed")
    if snapshot.get("writer_branch_matches") is not True:
        reasons.append("writer_branch_mismatch")
    if snapshot.get("writer_head") != manifest.get("expected_base_head"):
        reasons.append("writer_head_mismatch")
    if snapshot.get("dirty") is not False:
        reasons.append("writer_worktree_not_clean")
    if snapshot.get("base_drift"):
        reasons.append("base_drift")
    if snapshot.get("scope_passed") is not True:
        reasons.append("scope_violation")
    lifecycle = manifest.get("checkout_lifecycle")
    resources_value = manifest.get("resources", {})
    if not isinstance(lifecycle, dict):
        reasons.append("checkout_lifecycle_missing")
    elif (
        lifecycle.get("owner_id") != resources_value.get("owner_id")
        or lifecycle.get("expected_head") != manifest.get("expected_base_head")
        or lifecycle.get("expected_branch") != manifest.get("writer_branch")
        or lifecycle.get("phase") != "active"
        or not isinstance(lifecycle.get("checkout_key"), str)
    ):
        reasons.append("checkout_lifecycle_mismatch")
    else:
        try:
            key = str(lifecycle["checkout_key"])
            observed_binding = checkouts._lifecycle_bindings([key]).get(key)
            if not isinstance(observed_binding, dict):
                reasons.append("checkout_lifecycle_unbound")
            elif (
                observed_binding.get("owner_id") != lifecycle.get("owner_id")
                or observed_binding.get("checkout_path") != lifecycle.get("checkout_path")
                or observed_binding.get("expected_head") != lifecycle.get("expected_head")
                or observed_binding.get("expected_branch") != lifecycle.get("expected_branch")
                or observed_binding.get("phase") != "active"
                or int(observed_binding.get("retention_until_unix") or 0) <= _now()
            ):
                reasons.append("checkout_lifecycle_live_mismatch")
        except Exception:
            reasons.append("checkout_lifecycle_unobservable")
    owner = resources_value.get("owner_id")
    keys = resources_value.get("lease_keys")
    if not isinstance(owner, str) or not isinstance(keys, list):
        reasons.append("workspace_resources_invalid")
    else:
        try:
            live = resources.list_resources(owner_id=owner, include_expired=False, limit=MAX_PATHS + 8)
            observed = {str(item.get("resource_key")) for item in live}
            if not set(str(key) for key in keys).issubset(observed):
                reasons.append("workspace_lease_missing")
        except Exception:
            reasons.append("workspace_lease_unobservable")
    return {
        "eligible": not reasons,
        "reasons": reasons,
        "max": MAX_WRITER_HANDOFFS,
        "used": len(attempts) - 1,
    }


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


def _bounded_probe_text(value: Any) -> str:
    return str(value or "")[:MAX_INTEGRATION_PROBE_OUTPUT_CHARS]


def _probe_error(
    *,
    mode: str,
    stage: str,
    result: dict[str, Any] | None = None,
    fallback_reason: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "status": "error",
        "mode": mode,
        "stage": stage,
        "conflicting": None,
        "returncode": None,
        "stdout": "",
        "stderr": "",
    }
    if isinstance(result, dict):
        returncode = result.get("returncode")
        payload["returncode"] = (
            returncode if isinstance(returncode, int) and not isinstance(returncode, bool) else None
        )
        payload["stdout"] = _bounded_probe_text(result.get("stdout"))
        payload["stderr"] = _bounded_probe_text(result.get("stderr"))
    if fallback_reason is not None:
        payload["fallback_reason"] = fallback_reason
    return payload


def _valid_probe_result(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and isinstance(result.get("returncode"), int)
        and not isinstance(result.get("returncode"), bool)
    )


def _write_tree_mode_unavailable(result: dict[str, Any]) -> bool:
    if result.get("returncode") not in {128, 129}:
        return False
    detail = "\n".join(
        (_bounded_probe_text(result.get("stdout")), _bounded_probe_text(result.get("stderr")))
    ).lower()
    return (
        "unknown rev --write-tree" in detail
        or ("unknown option" in detail and "write-tree" in detail)
        or ("unrecognized option" in detail and "write-tree" in detail)
    )


def _source_object_directory(repo: Path, runner: CommandRunner) -> Path:
    result = _checked(
        runner,
        repo,
        ["git", "rev-parse", "--git-path", "objects"],
        label="git object directory",
    )
    raw = str(result.get("stdout", "")).strip()
    if not raw or "\n" in raw or "\r" in raw:
        raise AgentWorkspaceActionError("git returned an invalid object directory")
    path = Path(raw)
    if not path.is_absolute():
        path = repo / path
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AgentWorkspaceActionError("git object directory is unavailable") from exc
    if "\n" in str(resolved) or "\r" in str(resolved):
        raise AgentWorkspaceActionError("git object directory contains a line break")
    if not resolved.is_dir():
        raise AgentWorkspaceActionError("git object directory is not a directory")
    return resolved


def _initialize_isolated_git_repository(root: Path, source_objects: Path) -> None:
    git_dir = root / ".git"
    (git_dir / "objects" / "info").mkdir(parents=True, mode=0o700)
    (git_dir / "objects" / "pack").mkdir(mode=0o700)
    (git_dir / "refs" / "heads").mkdir(parents=True, mode=0o700)
    (git_dir / "refs" / "tags").mkdir(parents=True, mode=0o700)
    (git_dir / "HEAD").write_text(
        "ref: refs/heads/grabowski-integration-probe\n", encoding="utf-8"
    )
    (git_dir / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tbare = false\n"
        "\tfilemode = true\n"
        "\thooksPath = /dev/null\n",
        encoding="utf-8",
    )
    (git_dir / "objects" / "info" / "alternates").write_text(
        f"{source_objects}\n", encoding="utf-8"
    )


def _unmerged_path_summary(stdout: str) -> tuple[int, list[str]]:
    paths: set[str] = set()
    for entry in stdout.split("\x00"):
        if not entry:
            continue
        if "\t" not in entry:
            raise AgentWorkspaceActionError("git returned a malformed unmerged index entry")
        path = entry.split("\t", 1)[1]
        if not path:
            raise AgentWorkspaceActionError("git returned an empty unmerged path")
        paths.add(path)
    ordered = sorted(paths)
    bounded: list[str] = []
    used = 0
    for path in ordered[:MAX_INTEGRATION_PROBE_PATHS]:
        size = len(path)
        if used + size > MAX_INTEGRATION_PROBE_OUTPUT_CHARS:
            break
        bounded.append(path)
        used += size
    return len(ordered), bounded


def _integration_probe(
    repo: Path, canonical_head: str, writer_head: str, runner: CommandRunner
) -> dict[str, Any]:
    source_objects = _source_object_directory(repo, runner)
    with tempfile.TemporaryDirectory(prefix="grabowski-agent-integration-") as raw_root:
        isolated = Path(raw_root)
        _initialize_isolated_git_repository(isolated, source_objects)

        modern = runner(
            isolated,
            ["git", "merge-tree", "--write-tree", canonical_head, writer_head],
        )
        if not _valid_probe_result(modern):
            return _probe_error(
                mode="merge-tree-write-tree-isolated-v1",
                stage="modern_result",
            )
        modern_returncode = int(modern["returncode"])
        if modern_returncode in {0, 1}:
            merge_tree = str(modern.get("stdout", "")).splitlines()[0:1]
            merge_tree_oid = merge_tree[0].strip().lower() if merge_tree else ""
            if SHA40_RE.fullmatch(merge_tree_oid) is None:
                return _probe_error(
                    mode="merge-tree-write-tree-isolated-v1",
                    stage="modern_tree_identity",
                    result=modern,
                )
            return {
                "schema_version": 1,
                "status": "conflicting" if modern_returncode == 1 else "clean",
                "mode": "merge-tree-write-tree-isolated-v1",
                "stage": "complete",
                "merge_tree": merge_tree_oid,
                "conflicting": modern_returncode == 1,
                "returncode": modern_returncode,
                "stdout": _bounded_probe_text(modern.get("stdout")),
                "stderr": _bounded_probe_text(modern.get("stderr")),
            }
        if not _write_tree_mode_unavailable(modern):
            return _probe_error(
                mode="merge-tree-write-tree-isolated-v1",
                stage="modern_probe",
                result=modern,
            )

        fallback_reason = "merge_tree_write_tree_unavailable"
        merge_base = runner(
            isolated, ["git", "merge-base", canonical_head, writer_head]
        )
        if not _valid_probe_result(merge_base) or merge_base.get("returncode") != 0:
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="merge_base",
                result=merge_base if isinstance(merge_base, dict) else None,
                fallback_reason=fallback_reason,
            )
        base_head = str(merge_base.get("stdout", "")).strip().lower()
        if SHA40_RE.fullmatch(base_head) is None:
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="merge_base_identity",
                result=merge_base,
                fallback_reason=fallback_reason,
            )

        initialize = runner(
            isolated,
            ["git", "read-tree", "--reset", "-u", canonical_head],
        )
        if not _valid_probe_result(initialize) or initialize.get("returncode") != 0:
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="initialize",
                result=initialize if isinstance(initialize, dict) else None,
                fallback_reason=fallback_reason,
            )

        merge = runner(
            isolated,
            [
                "git",
                "merge-recursive",
                base_head,
                "--",
                canonical_head,
                writer_head,
            ],
        )
        if not _valid_probe_result(merge):
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="merge_result",
                fallback_reason=fallback_reason,
            )
        unmerged = runner(isolated, ["git", "ls-files", "--unmerged", "-z"])
        if not _valid_probe_result(unmerged) or unmerged.get("returncode") != 0:
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="unmerged_index",
                result=unmerged if isinstance(unmerged, dict) else None,
                fallback_reason=fallback_reason,
            )

        try:
            unmerged_path_count, paths = _unmerged_path_summary(
                str(unmerged.get("stdout", ""))
            )
        except AgentWorkspaceActionError:
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="unmerged_index_shape",
                result=unmerged,
                fallback_reason=fallback_reason,
            )
        merge_returncode = int(merge["returncode"])
        if merge_returncode == 0 and unmerged_path_count == 0:
            status = "clean"
            conflicting = False
        elif merge_returncode == 1 and unmerged_path_count > 0:
            status = "conflicting"
            conflicting = True
        else:
            return _probe_error(
                mode="merge-recursive-isolated-v1",
                stage="fallback_semantics",
                result=merge,
                fallback_reason=fallback_reason,
            )
        return {
            "schema_version": 1,
            "status": status,
            "mode": "merge-recursive-isolated-v1",
            "stage": "complete",
            "fallback_reason": fallback_reason,
            "merge_base": base_head,
            "conflicting": conflicting,
            "returncode": merge_returncode,
            "unmerged_path_count": unmerged_path_count,
            "unmerged_paths": paths,
            "stdout": _bounded_probe_text(merge.get("stdout")),
            "stderr": _bounded_probe_text(merge.get("stderr")),
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
        conflict = _integration_probe(repo, canonical_head, head, runner)
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


def _legacy_absence_receipt_valid(
    manifest: dict[str, Any],
    legacy: Any,
    *,
    expected_plan_sha256: str | None = None,
) -> bool:
    if not isinstance(legacy, dict) or not _receipt_integrity(legacy):
        return False
    source_plan_sha256 = legacy.get("source_plan_sha256")
    if not isinstance(source_plan_sha256, str) or SHA256_RE.fullmatch(source_plan_sha256) is None:
        return False
    if expected_plan_sha256 is not None and source_plan_sha256 != expected_plan_sha256:
        return False
    required_hashes = ("liveness_sha256", "workspace_reference_inventory_sha256")
    if any(
        not isinstance(legacy.get(field), str)
        or SHA256_RE.fullmatch(str(legacy.get(field))) is None
        for field in required_hashes
    ):
        return False
    return bool(
        legacy.get("schema_version") == 1
        and legacy.get("workspace_id") == manifest.get("workspace_id")
        and legacy.get("repository") == manifest.get("repository")
        and legacy.get("writer_worktree") == manifest.get("writer_worktree")
        and legacy.get("writer_branch") == manifest.get("writer_branch")
        and legacy.get("workspace_created_at") == manifest.get("created_at")
        and legacy.get("observed_worktree_absent") is True
        and legacy.get("task_mutation_performed") is False
        and legacy.get("resource_mutation_performed") is False
        and legacy.get("tmux_mutation_performed") is False
        and legacy.get("worktree_mutation_performed") is False
        and legacy.get("historical_evidence_preserved") is True
        and isinstance(legacy.get("recorded_at"), str)
        and bool(legacy.get("recorded_at"))
    )


def _legacy_absence_receipt_status(
    manifest: dict[str, Any], close_receipt: dict[str, Any]
) -> dict[str, Any]:
    result = {
        "required": close_receipt.get("closure_outcome") == "abandoned_legacy_workspace",
        "present": False,
        "valid": False,
        "matches_close_receipt": False,
    }
    if not result["required"]:
        result["valid"] = True
        return result
    path = _workspace_dir(str(manifest["workspace_id"])) / "legacy-absence-receipt.json"
    try:
        legacy = _load_json(path)
    except FileNotFoundError:
        return result
    except Exception as exc:
        result["error"] = _error_summary(exc)
        return result
    result["present"] = True
    observed = legacy.get("receipt_sha256")
    result["matches_close_receipt"] = bool(
        isinstance(observed, str)
        and observed == close_receipt.get("legacy_absence_receipt_sha256")
    )
    result["valid"] = bool(
        _legacy_absence_receipt_valid(manifest, legacy)
        and result["matches_close_receipt"]
    )
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
    legacy_absence = _legacy_absence_receipt_status(manifest, receipt)
    result["legacy_absence_receipt"] = legacy_absence
    result["valid"] = bool(
        result["hash_valid"]
        and result["receipt_matches_manifest"]
        and legacy_absence["valid"]
    )
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


def _cached_role_preflight_block(
    manifest: dict[str, Any], role: str, command: list[str]
) -> dict[str, Any] | None:
    """Return the latest unchanged failed preflight instead of probing again."""
    blocks = manifest.get("role_preflight_blocks", {})
    role_blocks = blocks.get(role) if isinstance(blocks, dict) else None
    if not isinstance(role_blocks, list) or not role_blocks:
        return None
    latest = role_blocks[-1]
    if not isinstance(latest, dict):
        return None
    if latest.get("command_sha256") != _sha256_json(command):
        return None
    if latest.get("passed") is not False:
        return None
    return latest


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
    writer_terminal_failure: bool = False,
) -> str:
    if closed:
        return "none_closed"
    if not creation_ready:
        return "await_creation"
    if not route_gate_passed:
        return "recreate_with_route_evidence"
    if writer_terminal_failure:
        return "salvage_or_close_failed_writer"
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
    checkout_decision = (
        close_receipt.get("checkout_lifecycle_decision")
        if isinstance(close_receipt, dict)
        else None
    )
    checkout_decision_verified = bool(
        close_valid
        and isinstance(checkout_decision, dict)
        and checkout_decision.get("automatic_cleanup_authorized") is False
        and checkout_decision.get("selected_action")
        in {"retain", "register_or_retain", "archive", "cleanup_dry_run"}
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
                "Use the recorded lifecycle decision for the preserved writer checkout; "
                "close never deletes it and external GitHub/Bureau truth remains authoritative."
            ),
            "status": "verified" if checkout_decision_verified else "unknown",
            "source_of_truth": "grabowski_checkouts",
            "evidence": checkout_decision if checkout_decision_verified else None,
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
        "schema_version": 3,
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
        "retry_measurement": _workspace_retry_measurement(manifest),
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


WORKSPACE_RISK_LEVEL_BY_TIER = {
    "R0": "low",
    "R1": "medium",
    "R2": "high",
    "R3": "critical",
}


def _workspace_execution_outcome_binding_path(
    manifest: dict[str, Any], workspace_outcome_sha256: str
) -> Path:
    if SHA256_RE.fullmatch(workspace_outcome_sha256) is None:
        raise AgentWorkspaceError("workspace outcome hash is invalid")
    return (
        _workspace_dir(str(manifest["workspace_id"]))
        / f"execution-outcome-binding.close.{workspace_outcome_sha256}.json"
    )


def _workspace_retry_measurement(manifest: dict[str, Any]) -> dict[str, int]:
    unchanged = 0
    changed = 0
    total = 0
    retries = manifest.get("role_retries", {})
    if not isinstance(retries, dict):
        raise AgentWorkspaceError("workspace role retry state is invalid")
    for role in READ_ONLY_ROLES:
        state = retries.get(role)
        if state is None:
            continue
        if not isinstance(state, dict):
            raise AgentWorkspaceError("workspace role retry state is invalid")
        count = state.get("count")
        attempts = state.get("attempts")
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            or count > MAX_ROLE_RETRIES
            or not isinstance(attempts, list)
            or len(attempts) != count
        ):
            raise AgentWorkspaceError("workspace role retry state is invalid")
        for attempt in attempts:
            if not isinstance(attempt, dict):
                raise AgentWorkspaceError("workspace role retry attempt is invalid")
            old_hash = attempt.get("old_command_sha256")
            new_hash = attempt.get("new_command_sha256")
            if (
                not isinstance(old_hash, str)
                or SHA256_RE.fullmatch(old_hash) is None
                or not isinstance(new_hash, str)
                or SHA256_RE.fullmatch(new_hash) is None
            ):
                raise AgentWorkspaceError("workspace role retry command identity is invalid")
            total += 1
            if old_hash == new_hash:
                unchanged += 1
            else:
                changed += 1
    return {"total": total, "unchanged": unchanged, "changed": changed}


def _workspace_first_pass_success(outcome: dict[str, Any]) -> bool:
    results = outcome.get("first_pass_role_results")
    if not isinstance(results, dict):
        return False
    writer = results.get("writer")
    tests_result = results.get("tests")
    review = results.get("review")
    return bool(
        isinstance(writer, dict)
        and writer.get("state") == "completed"
        and isinstance(tests_result, dict)
        and tests_result.get("status") == "passed"
        and isinstance(review, dict)
        and review.get("status") == "passed"
        and review.get("verdict") == "PASS"
    )


def _workspace_risk_level(route: dict[str, Any]) -> str:
    tier = route.get("risk_tier")
    if tier is None:
        facts = route.get("input_facts")
        if not isinstance(facts, dict):
            raise AgentWorkspaceError("workspace route risk evidence is unavailable")
        tier = _route_decision(facts).get("risk_tier")
    risk = WORKSPACE_RISK_LEVEL_BY_TIER.get(tier)
    if risk is None:
        raise AgentWorkspaceError("workspace route risk tier is invalid")
    return risk


def _bind_workspace_execution_outcome(
    manifest: dict[str, Any], outcome: dict[str, Any]
) -> dict[str, Any]:
    if outcome.get("phase") != "close":
        raise AgentWorkspaceError("execution outcome binding requires close phase")
    if outcome.get("workspace_id") != manifest.get("workspace_id"):
        raise AgentWorkspaceActionError("workspace outcome belongs to another workspace")
    close_receipt = manifest.get("close_receipt")
    close_integrity = _close_integrity_status(manifest, close_receipt)
    if (
        not isinstance(close_receipt, dict)
        or close_receipt.get("state") != "complete"
        or close_receipt.get("resources_released") is not True
        or close_receipt.get("remaining_resource_keys") != []
        or close_integrity.get("valid") is not True
    ):
        raise AgentWorkspaceActionError(
            "workspace execution outcome requires a valid complete close receipt"
        )
    workspace_outcome_sha256 = outcome.get("outcome_sha256")
    unsigned_outcome = {
        key: value for key, value in outcome.items() if key != "outcome_sha256"
    }
    if (
        not isinstance(workspace_outcome_sha256, str)
        or SHA256_RE.fullmatch(workspace_outcome_sha256) is None
        or _sha256_json(unsigned_outcome) != workspace_outcome_sha256
    ):
        raise AgentWorkspaceActionError("workspace outcome hash is invalid")
    route = outcome.get("route_evidence")
    if not isinstance(route, dict):
        raise AgentWorkspaceError("workspace route evidence is unavailable")
    if outcome.get("route_legacy_compatibility") is True:
        return {
            "schema_version": 1,
            "kind": "agent_workspace_execution_outcome_binding",
            "workspace_id": manifest["workspace_id"],
            "phase": "close",
            "state": "not_applicable_legacy_route",
            "recorded": False,
            "does_not_establish": ["execution governor outcome"],
        }
    if outcome.get("schema_version") != 3:
        return {
            "schema_version": 1,
            "kind": "agent_workspace_execution_outcome_binding",
            "workspace_id": manifest["workspace_id"],
            "phase": "close",
            "state": "not_applicable_legacy_outcome_schema",
            "recorded": False,
            "does_not_establish": ["execution governor outcome"],
        }
    if outcome.get("evidence_complete") is not True:
        missing = outcome.get("missing_fields")
        raise AgentWorkspaceActionError(
            "workspace execution outcome evidence is incomplete: "
            + ", ".join(str(item) for item in missing if isinstance(item, str))
        )
    if route.get("status") != "verified" or route.get("evidence_complete") is not True:
        raise AgentWorkspaceActionError("workspace route evidence is not verified")
    recommendation_id = route.get("recommendation_id")
    recommended_route = route.get("recommended_route")
    actual_route = route.get("actual_route")
    if (
        not isinstance(recommendation_id, str)
        or SHA256_RE.fullmatch(recommendation_id) is None
        or recommended_route not in ROUTE_EXECUTION_MODES
        or actual_route not in ROUTE_EXECUTION_MODES
    ):
        raise AgentWorkspaceActionError("workspace route binding is invalid")
    elapsed_seconds = outcome.get("elapsed_seconds")
    if (
        isinstance(elapsed_seconds, bool)
        or not isinstance(elapsed_seconds, int)
        or elapsed_seconds < 0
        or elapsed_seconds > 86_400
    ):
        raise AgentWorkspaceActionError(
            "workspace elapsed time is outside the execution governor bound"
        )
    tool_calls = outcome.get("tool_calls")
    tool_call_count = (
        tool_calls.get("known_mutating_call_count")
        if isinstance(tool_calls, dict)
        else None
    )
    if (
        not isinstance(tool_calls, dict)
        or tool_calls.get("event_log_integrity_bound") is not True
        or tool_calls.get("counting_basis")
        != "integrity_valid_workspace_event_log"
        or isinstance(tool_call_count, bool)
        or not isinstance(tool_call_count, int)
        or tool_call_count < 1
        or tool_call_count > 1000
    ):
        raise AgentWorkspaceActionError(
            "workspace tool-call evidence is not integrity-bound"
        )
    retry_measurement = outcome.get("retry_measurement")
    if (
        not isinstance(retry_measurement, dict)
        or set(retry_measurement) != {"total", "unchanged", "changed"}
        or any(
            isinstance(retry_measurement.get(key), bool)
            or not isinstance(retry_measurement.get(key), int)
            or retry_measurement.get(key) < 0
            for key in ("total", "unchanged", "changed")
        )
        or retry_measurement["total"]
        != retry_measurement["unchanged"] + retry_measurement["changed"]
        or retry_measurement["total"] > len(READ_ONLY_ROLES) * MAX_ROLE_RETRIES
    ):
        raise AgentWorkspaceActionError(
            "workspace retry measurement is invalid or unbound"
        )
    first_pass_success = _workspace_first_pass_success(outcome)
    mapped = {
        "recommendation_id": recommendation_id,
        "operation_class": "long_running",
        "risk_level": _workspace_risk_level(route),
        "recommended_route": recommended_route,
        "actual_route": actual_route,
        "first_pass_success": first_pass_success,
        "unchanged_retries": retry_measurement["unchanged"],
        "ambiguous_mutation_outcomes": 0,
        "tool_call_count": tool_call_count,
        "elapsed_ms": elapsed_seconds * 1000,
        "evidence_ref": (
            f"artifact:agent-workspace:{manifest['workspace_id']}:"
            f"close:{workspace_outcome_sha256}"
        ),
        "regression_signal": not first_pass_success,
        "friction_event_ids": [],
    }
    binding_material = {
        "schema_version": 1,
        "kind": "agent_workspace_execution_outcome_binding",
        "workspace_id": manifest["workspace_id"],
        "phase": "close",
        "workspace_outcome_sha256": workspace_outcome_sha256,
        "mapped_outcome": mapped,
    }
    binding_id = _sha256_json(binding_material)
    import grabowski_friction as friction

    ledger = friction.record_execution_outcome_once(
        binding_id=binding_id,
        **mapped,
    )
    receipt = {
        **binding_material,
        "binding_id": binding_id,
        "state": "recorded",
        "recorded": True,
        "execution_outcome_id": ledger["outcome_id"],
        "shadow_mode": ledger["shadow_mode"],
        "measurement_basis": {
            "operation_class": "agent workspace is a durable multi-role execution",
            "risk_level": "deterministic route-policy risk tier mapping",
            "first_pass_success": "writer completed and tests/review first attempts passed with review verdict PASS",
            "unchanged_retries": "only retry attempts whose old and new command SHA-256 values are identical",
            "changed_retries_excluded": retry_measurement["changed"],
            "total_role_retries_observed": retry_measurement["total"],
            "ambiguous_mutation_outcomes": "zero only after a valid complete close receipt, frozen Git readback and verified resource release",
            "tool_call_count": tool_calls.get("counting_basis"),
            "read_only_tool_calls_counted": False,
            "elapsed_ms": "exact whole elapsed seconds from workspace creation to close",
        },
        "does_not_establish": [
            "general productivity improvement",
            "read-only tool call count",
            "live routing promotion",
            "merge or deployment success",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    receipt_path = _workspace_execution_outcome_binding_path(
        manifest, workspace_outcome_sha256
    )
    if receipt_path.exists():
        existing = _load_json(receipt_path)
        if existing != receipt:
            raise AgentWorkspaceActionError(
                "existing workspace execution outcome binding differs"
            )
    else:
        _atomic_json(receipt_path, receipt)
    references = dict(manifest.get("execution_outcome_bindings", {}))
    references["close"] = {
        "path": str(receipt_path),
        "binding_id": binding_id,
        "execution_outcome_id": ledger["outcome_id"],
        "receipt_sha256": receipt["receipt_sha256"],
    }
    manifest["execution_outcome_bindings"] = references
    return receipt


def _ensure_workspace_closed_event(
    manifest: dict[str, Any],
    close_receipt: dict[str, Any],
    execution_outcome_binding: dict[str, Any],
) -> None:
    counts, _integrity_bound = _workspace_event_type_counts(manifest)
    count = counts.get("workspace_closed", 0)
    if count > 1:
        raise AgentWorkspaceActionError(
            "workspace event log contains duplicate close events"
        )
    if count == 0:
        _append_workspace_event(
            manifest,
            "workspace_closed",
            outcome=str(close_receipt["closure_outcome"]),
            evidence={
                "receipt_sha256": close_receipt["receipt_sha256"],
                "resources_released": close_receipt["resources_released"],
                "execution_outcome_binding_state": execution_outcome_binding.get(
                    "state"
                ),
                "execution_outcome_binding_id": execution_outcome_binding.get(
                    "binding_id"
                ),
            },
        )
        return
    workspace_id = _required_string(
        manifest.get("workspace_id"), "workspace_id", max_length=80
    )
    observed_sequence = _event_log_sequence(
        _event_log_path(workspace_id), workspace_id
    )
    manifest_sequence = manifest.get("event_sequence", 0)
    if (
        isinstance(manifest_sequence, bool)
        or not isinstance(manifest_sequence, int)
        or manifest_sequence < 0
        or manifest_sequence > observed_sequence
    ):
        raise AgentWorkspaceActionError(
            "workspace manifest event sequence is invalid during close readback"
        )
    manifest["event_sequence"] = observed_sequence


def _status_data(manifest: dict[str, Any], runner: CommandRunner = _run) -> dict[str, Any]:
    snapshot: dict[str, Any]
    try:
        snapshot = _git_snapshot(manifest, runner)
    except Exception as exc:
        snapshot = {"error": _error_summary(exc), "dirty": None}
    try:
        writer_attempt = _effective_writer_attempt(manifest)
        writer_attempts = _writer_attempts(manifest)
        writer_final_attempt = _writer_final_attempt(manifest)
        writer_attempt_error = None
        writer_task_id = str(writer_attempt["task_id"])
    except Exception as exc:
        writer_attempt = None
        writer_attempts = []
        writer_final_attempt = None
        writer_attempt_error = _error_summary(exc)
        writer_task_id = manifest.get("tasks", {}).get("writer")
    task_state = {
        "writer": _task_public(writer_task_id),
        "tests": _task_public(manifest.get("tasks", {}).get("tests")),
        "review": _task_public(manifest.get("tasks", {}).get("review")),
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
    writer_terminal_failure = bool(
        task_state["writer"]["terminal"]
        and task_state["writer"]["state"] in WRITER_HANDOFF_TERMINAL_STATES
        and not collection_complete
    )
    try:
        writer_handoff = _writer_handoff_eligibility(manifest, task_state["writer"], snapshot)
    except Exception as exc:
        writer_handoff = {"eligible": False, "reasons": ["writer_attempt_history_invalid"], "error": _error_summary(exc), "max": MAX_WRITER_HANDOFFS, "used": None}
    if writer_terminal_failure and "writer" not in failed_roles:
        failed_roles = ["writer", *failed_roles]
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
        writer_terminal_failure=writer_terminal_failure,
    )
    if isinstance(task_start_intents, dict) and "writer_handoff" in task_start_intents:
        recommended_next_action = "repeat_identical_writer_handoff_to_reconcile_start"
    elif writer_handoff.get("eligible"):
        recommended_next_action = "writer_handoff"
    elif "writer_outcome_reconcile_required" in writer_handoff.get("reasons", []):
        recommended_next_action = "reconcile_writer_outcome"
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
        "original_writer_task": _task_public(manifest.get("tasks", {}).get("writer")),
        "writer_attempts": _writer_attempt_refs(manifest) if writer_attempt_error is None else [],
        "writer_final_attempt": writer_final_attempt,
        "writer_attempt_error": writer_attempt_error,
        "writer_handoff": writer_handoff,
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
        "writer_terminal_failure": writer_terminal_failure,
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
    if public.get("argv_sha256") != _task_argv_sha256(expected_argv):
        errors.append("argv_sha256_mismatch")
    if public.get("cwd") != expected_cwd:
        errors.append("cwd_mismatch")
    if public.get("attempt") != 1:
        errors.append("attempt_mismatch")
    if public.get("resume_policy") != "never":
        errors.append("resume_policy_mismatch")
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

def _writer_checkout_lifecycle_purpose(manifest: dict[str, Any]) -> str:
    binding = manifest.get("binding")
    if not isinstance(binding, dict):
        raise AgentWorkspaceError("workspace checkout lifecycle requires a binding")
    kind = _required_string(binding.get("kind"), "binding.kind", max_length=32)
    identifier = _required_string(binding.get("id"), "binding.id", max_length=256)
    return f"agent workspace {manifest['workspace_id']} for {kind}:{identifier}"


def _writer_checkout_lifecycle_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    binding = manifest.get("binding")
    if not isinstance(binding, dict):
        raise AgentWorkspaceError("workspace checkout lifecycle requires a binding")
    runtime_seconds = int(manifest["resources"]["runtime_seconds"] or 0)
    return {
        "owner_id": str(manifest["resources"]["owner_id"]),
        "purpose": _writer_checkout_lifecycle_purpose(manifest),
        "source_kind": str(binding["kind"]),
        "source_id": str(binding["id"]),
        "artifact_class": "agent_workspace_writer",
        "retention_until_unix": _now()
        + max(WORKSPACE_CLEANUP_RETENTION_SECONDS, runtime_seconds + 900),
    }


def _reserve_writer_checkout_lifecycle(manifest: dict[str, Any]) -> dict[str, Any]:
    repo = Path(str(manifest["repository"]))
    checkout = Path(str(manifest["writer_worktree"]))
    top_level = checkouts._git_top_level(repo)
    common_dir = checkouts._git_common_dir(repo)
    contract = _writer_checkout_lifecycle_contract(manifest)
    reservation = checkouts._reserve_checkout_lifecycle(
        repo_common_dir=common_dir,
        repo_path=top_level,
        checkout_path=checkout,
        owner_id=contract["owner_id"],
        purpose=contract["purpose"],
        source_kind=contract["source_kind"],
        source_id=contract["source_id"],
        artifact_class=contract["artifact_class"],
        retention_until_unix=contract["retention_until_unix"],
        expected_head=str(manifest["expected_base_head"]),
        expected_branch=str(manifest["writer_branch"]),
    )
    manifest["checkout_lifecycle_reservation"] = reservation
    return reservation


def _bind_writer_checkout_lifecycle(manifest: dict[str, Any]) -> dict[str, Any]:
    repo = Path(str(manifest["repository"]))
    checkout = Path(str(manifest["writer_worktree"]))
    top_level, common_dir, record = checkouts._worktree_for_path(repo, checkout)
    checkouts._require_linked(record)
    checkouts._require_expected(
        record,
        str(manifest["expected_base_head"]),
        str(manifest["writer_branch"]),
    )
    contract = _writer_checkout_lifecycle_contract(manifest)
    owner_id = checkouts._owner(str(contract["owner_id"]))
    retention_until_unix = int(contract["retention_until_unix"])
    purpose = str(contract["purpose"])
    lifecycle_binding = _reserve_writer_checkout_lifecycle(manifest)
    retention = checkouts._upsert_retention(
        checkout_key=str(record["checkout_key"]),
        repo_common_dir=common_dir,
        repo_path=top_level,
        checkout_path=checkout,
        owner_id=owner_id,
        purpose=purpose,
        retention_until_unix=retention_until_unix,
        expected_head=str(manifest["expected_base_head"]),
        expected_branch=str(manifest["writer_branch"]),
    )
    binding = manifest["binding"]
    return {
        "schema_version": 1,
        "state": "retained",
        "checkout_key": retention["checkout_key"],
        "checkout_path": retention["checkout_path"],
        "repo_common_dir": retention["repo_common_dir"],
        "owner_id": retention["owner_id"],
        "source": lifecycle_binding["source"],
        "artifact_class": lifecycle_binding["artifact_class"],
        "phase": lifecycle_binding["phase"],
        "limit": lifecycle_binding["limit"],
        "task": {
            "binding_kind": binding["kind"],
            "binding_id": binding["id"],
            "writer_task_id": None,
        },
        "purpose": retention["purpose"],
        "created_at_unix": retention["created_at_unix"],
        "updated_at_unix": retention["updated_at_unix"],
        "expires_at_unix": retention["retention_until_unix"],
        "expected_head": retention["expected_head"],
        "expected_branch": retention["expected_branch"],
        "automatic_cleanup_authorized": False,
    }


def _release_failed_workspace_checkout_lifecycle(manifest: dict[str, Any]) -> bool:
    checkout = Path(str(manifest.get("writer_worktree") or ""))
    if os.path.lexists(checkout):
        return False
    reservation = manifest.get("checkout_lifecycle_reservation")
    binding_released = True
    if isinstance(reservation, dict):
        binding_released = checkouts._release_checkout_lifecycle_exact(reservation)
    lifecycle = manifest.get("checkout_lifecycle")
    if not isinstance(lifecycle, dict):
        return binding_released
    checkout_key = lifecycle.get("checkout_key")
    owner_id = lifecycle.get("owner_id")
    if not isinstance(checkout_key, str) or not isinstance(owner_id, str):
        return False
    created_at_unix = lifecycle.get("created_at_unix")
    updated_at_unix = lifecycle.get("updated_at_unix")
    expected_head = lifecycle.get("expected_head")
    expected_branch = lifecycle.get("expected_branch")
    if not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in (created_at_unix, updated_at_unix)
    ):
        return False
    with checkouts._database() as connection:
        row = connection.execute(
            """
            SELECT owner_id, created_at_unix, updated_at_unix,
                   expected_head, expected_branch
            FROM retention WHERE checkout_key=?
            """,
            (checkout_key,),
        ).fetchone()
        if row is None:
            return True
        expected_identity = (
            owner_id,
            created_at_unix,
            updated_at_unix,
            expected_head,
            expected_branch,
        )
        observed_identity = (
            row["owner_id"],
            row["created_at_unix"],
            row["updated_at_unix"],
            row["expected_head"],
            row["expected_branch"],
        )
        if observed_identity != expected_identity:
            return False
        deleted = connection.execute(
            """
            DELETE FROM retention
            WHERE checkout_key=? AND owner_id=?
              AND created_at_unix=? AND updated_at_unix=?
              AND expected_head IS ? AND expected_branch IS ?
            """,
            (
                checkout_key,
                owner_id,
                created_at_unix,
                updated_at_unix,
                expected_head,
                expected_branch,
            ),
        )
        connection.commit()
    return binding_released and deleted.rowcount == 1


def _terminal_writer_checkout_decision(
    manifest: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    lifecycle = manifest.get("checkout_lifecycle")
    if not isinstance(lifecycle, dict):
        return {
            "schema_version": 1,
            "state": "unregistered",
            "selected_action": "register_or_retain",
            "reason": "workspace predates checkout lifecycle binding",
            "checkout_path": manifest["writer_worktree"],
            "automatic_cleanup_authorized": False,
            "does_not_establish": [
                "permission_to_delete_checkout",
                "pull_request_integration_truth",
                "bureau_task_completion",
            ],
        }
    dirty = bool(snapshot.get("dirty"))
    observed_head = str(snapshot.get("writer_head") or "")
    completed_binding = checkouts._mark_checkout_completed_retained(
        checkout_key=str(lifecycle["checkout_key"]),
        owner_id=str(lifecycle["owner_id"]),
        expected_head=observed_head,
        expected_branch=str(lifecycle["expected_branch"]),
    )
    return {
        "schema_version": 1,
        "state": "terminal_decision_recorded",
        "selected_action": "retain",
        "reason": (
            "writer checkout is dirty and requires owner review"
            if dirty
            else "GitHub integration and Bureau completion remain external truth"
        ),
        "checkout_key": lifecycle.get("checkout_key"),
        "checkout_path": lifecycle.get("checkout_path"),
        "owner_id": lifecycle.get("owner_id"),
        "source": completed_binding.get("source"),
        "artifact_class": completed_binding.get("artifact_class"),
        "lifecycle_phase": completed_binding.get("phase"),
        "limit": completed_binding.get("limit"),
        "task": lifecycle.get("task"),
        "purpose": lifecycle.get("purpose"),
        "created_at_unix": lifecycle.get("created_at_unix"),
        "expires_at_unix": lifecycle.get("expires_at_unix"),
        "expected_head": lifecycle.get("expected_head"),
        "expected_branch": lifecycle.get("expected_branch"),
        "observed_head": snapshot.get("writer_head"),
        "observed_dirty": dirty,
        "next_action": "archive_after_external_truth_reconciliation",
        "automatic_cleanup_authorized": False,
        "does_not_establish": [
            "permission_to_delete_checkout",
            "pull_request_integration_truth",
            "bureau_task_completion",
        ],
    }


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
    if writer_task.get("argv_sha256") != _task_argv_sha256(_writer_task_argv(manifest)):
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
        "runtime_identity": _workspace_runtime_identity(),
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
    writer_task_argv_sha256 = _task_argv_sha256(writer_task_argv)
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
        lifecycle_reservation = _reserve_writer_checkout_lifecycle(manifest)
        _append_workspace_event(
            manifest,
            "writer_checkout_lifecycle_reserved",
            role="writer",
            outcome="reserved",
            evidence={
                "checkout_key": lifecycle_reservation["checkout_key"],
                "source": lifecycle_reservation["source"],
                "artifact_class": lifecycle_reservation["artifact_class"],
                "limit": lifecycle_reservation["limit"],
            },
        )
        _write_manifest(manifest)
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
        initial_preflights: dict[str, Any] = {}
        for preflight_role in ("writer", "tests", "review"):
            role_preflight = _role_toolchain_preflight(
                manifest, preflight_role, list(plan["commands"][preflight_role])
            )
            initial_preflights[preflight_role] = role_preflight
            manifest["initial_role_preflights"] = dict(initial_preflights)
            if preflight_role == "writer":
                manifest["writer_toolchain_preflight"] = role_preflight
            _append_workspace_event(
                manifest,
                "role_preflight",
                role=preflight_role,
                outcome="passed" if role_preflight.get("passed") is True else "blocked",
                evidence={
                    "phase": "workspace_creation",
                    "command_sha256": role_preflight.get("command_sha256"),
                    "environment_sha256": (
                        role_preflight.get("environment", {}).get("environment_sha256")
                        if isinstance(role_preflight.get("environment"), dict)
                        else None
                    ),
                    "cache_hit": (
                        role_preflight.get("cache", {}).get("hit")
                        if isinstance(role_preflight.get("cache"), dict)
                        else None
                    ),
                    "external_agent_profile": role_preflight.get("external_agent_profile"),
                    "failure_classification": role_preflight.get("failure_classification"),
                },
            )
            _write_manifest(manifest)
            if role_preflight.get("passed") is not True:
                classification = role_preflight.get("failure_classification") or "toolchain_probe_error"
                raise AgentWorkspaceActionError(
                    f"{preflight_role} toolchain preflight failed: {classification}"
                )
        manifest["checkout_lifecycle"] = _bind_writer_checkout_lifecycle(manifest)
        _append_workspace_event(
            manifest,
            "writer_checkout_lifecycle_bound",
            role="writer",
            outcome="retained",
            evidence={
                "checkout_key": manifest["checkout_lifecycle"]["checkout_key"],
                "owner_id": manifest["checkout_lifecycle"]["owner_id"],
                "task": manifest["checkout_lifecycle"]["task"],
                "expires_at_unix": manifest["checkout_lifecycle"]["expires_at_unix"],
                "expected_head": manifest["checkout_lifecycle"]["expected_head"],
                "expected_branch": manifest["checkout_lifecycle"]["expected_branch"],
                "automatic_cleanup_authorized": False,
            },
        )
        _write_manifest(manifest)
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
        checkout_lifecycle = manifest.get("checkout_lifecycle")
        if isinstance(checkout_lifecycle, dict):
            task_binding = dict(checkout_lifecycle.get("task") or {})
            task_binding["writer_task_id"] = writer_task["task_id"]
            checkout_lifecycle["task"] = task_binding
            checkout_lifecycle["updated_at_unix"] = _now()
            manifest["checkout_lifecycle"] = checkout_lifecycle
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
        checkout_lifecycle_released = True
        if worktree_cleanup_confirmed and not writer_start_attempted:
            try:
                checkout_lifecycle_released = _release_failed_workspace_checkout_lifecycle(
                    manifest
                )
            except Exception:
                checkout_lifecycle_released = False
        lease_released = False
        lease_release_error: str | None = None
        if (
            lease is not None
            and writer_cancel_confirmed
            and worktree_cleanup_confirmed
            and checkout_lifecycle_released
        ):
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
            "checkout_lifecycle_released": checkout_lifecycle_released,
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
        try:
            effective_writer = _effective_writer_attempt(manifest)
            writer_final_attempt = _writer_final_attempt(manifest)
        except Exception as exc:
            return {"workspace_id": identifier, "state": "writer_attempt_binding_invalid", "error": _error_summary(exc), "receipt_status": "blocked"}
        writer = _task_public(str(effective_writer["task_id"]))
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
        if writer_final_attempt > 1 and (
            writer.get("host") != _bound_task_host(manifest)
            or writer.get("argv_sha256") != effective_writer.get("task_argv_sha256")
            or writer.get("cwd") != manifest["writer_worktree"]
        ):
            return {"workspace_id": identifier, "state": "writer_task_binding_mismatch", "writer_task": writer, "receipt_status": "blocked"}
        writer_receipt = _role_receipt(manifest, "writer", attempt=writer_final_attempt)
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
            or writer_receipt.get("command_sha256") != effective_writer.get("command_sha256")
            or (
                writer_final_attempt > 1
                and writer_receipt.get("launch_nonce") != effective_writer.get("launch_nonce")
            )
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
                cached_preflight = _cached_role_preflight_block(
                    manifest, role, manifest["commands"][role]
                )
                if cached_preflight is not None:
                    return {
                        "workspace_id": identifier,
                        "state": "role_toolchain_preflight_cached_failure",
                        "role": role,
                        "preflight": cached_preflight,
                        "retry_required": True,
                        "retry_tool": "grabowski_agent_workspace_role_retry",
                        "receipt_status": "blocked",
                    }
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
                    "task_argv_sha256": _task_argv_sha256(role_task_argv),
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
            "original_writer_task_id": manifest["tasks"].get("writer"),
            "effective_writer_task_id": effective_writer.get("task_id"),
            "writer_final_attempt": writer_final_attempt,
            "writer_attempts": _writer_attempt_refs(manifest),
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


def _bind_writer_handoff_attempt(
    manifest: dict[str, Any],
    *,
    attempts: list[dict[str, Any]],
    effective: dict[str, Any],
    previous_state: str,
    command: list[str],
    task_argv: list[str],
    public: dict[str, Any],
    output: Path,
    launch_nonce: str,
    reconciled: bool,
) -> dict[str, Any]:
    command_sha = _sha256_json(command)
    record = {
        "attempt": 2,
        "actor": "operator_handoff",
        "task_id": public["task_id"],
        "command": command,
        "command_sha256": command_sha,
        "task_argv_sha256": _task_argv_sha256(task_argv),
        "receipt_path": str(output),
        "expected_base_head": manifest["expected_base_head"],
        "expected_branch": manifest["writer_branch"],
        "previous_task_id": effective["task_id"],
        "previous_state": previous_state,
        "started_at": _utc(),
        "start_reconciled": reconciled,
        "launch_nonce": launch_nonce,
        "launch_nonce_sha256": hashlib.sha256(launch_nonce.encode()).hexdigest(),
    }
    manifest["writer_attempts"] = [attempts[0], record]
    manifest["writer_final_attempt"] = 2
    lifecycle = manifest.get("checkout_lifecycle")
    if isinstance(lifecycle, dict):
        task_binding = dict(lifecycle.get("task") or {})
        original_task_id = task_binding.get("writer_task_id") or attempts[0].get("task_id")
        task_binding["writer_task_id"] = original_task_id
        task_binding["effective_writer_task_id"] = public["task_id"]
        task_binding["writer_attempt_task_ids"] = [original_task_id, public["task_id"]]
        lifecycle["task"] = task_binding
        lifecycle["updated_at_unix"] = _now()
        manifest["checkout_lifecycle"] = lifecycle
    intents = dict(manifest.get("task_start_intents", {}))
    intents.pop("writer_handoff", None)
    manifest["task_start_intents"] = intents
    event_type = "writer_handoff_start_reconciled" if reconciled else "writer_handoff_started"
    _append_workspace_event(
        manifest,
        event_type,
        role="writer",
        outcome="bound" if reconciled else "started",
        evidence={
            "attempt": 2,
            "task_id": public["task_id"],
            "previous_task_id": effective["task_id"],
            "previous_state": previous_state,
            "command_sha256": command_sha,
            "task_argv_sha256": record["task_argv_sha256"],
        },
    )
    _write_manifest(manifest)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": (
                "agent-workspace-writer-handoff-reconcile"
                if reconciled
                else "agent-workspace-writer-handoff"
            ),
            "workspace_id": manifest["workspace_id"],
            "attempt": 2,
            "task_id": public["task_id"],
            "previous_task_id": effective["task_id"],
            "previous_state": previous_state,
            "command_sha256": command_sha,
            "task_argv_sha256": record["task_argv_sha256"],
        }
    )
    return {
        "workspace_id": manifest["workspace_id"],
        "state": (
            "writer_handoff_start_reconciled"
            if reconciled
            else "writer_handoff_started"
        ),
        "attempt": 2,
        "task": public,
        "attempt_record": _writer_attempt_refs(manifest)[-1],
        "handoff_status": "reconciled" if reconciled else "passed",
    }


def _reconcile_writer_handoff_start(
    manifest: dict[str, Any],
    *,
    attempts: list[dict[str, Any]],
    effective: dict[str, Any],
    writer: dict[str, Any],
    command: list[str],
    intent: dict[str, Any],
) -> dict[str, Any]:
    command_sha = _sha256_json(command)
    launch_nonce = intent.get("launch_nonce")
    if not isinstance(launch_nonce, str) or len(launch_nonce) != 24:
        return {
            "workspace_id": manifest["workspace_id"],
            "state": "writer_handoff_start_intent_invalid",
            "handoff_status": "blocked",
            "reconcile_required": True,
        }
    task_argv = _writer_task_argv(
        manifest,
        command=command,
        attempt=2,
        launch_nonce=launch_nonce,
    )
    expected_task_argv_sha = _task_argv_sha256(task_argv)
    host = _bound_task_host(manifest)
    cwd = str(manifest["writer_worktree"])
    if (
        intent.get("kind") != "operator_handoff"
        or intent.get("attempt") != 2
        or intent.get("command_sha256") != command_sha
        or intent.get("task_argv_sha256") != expected_task_argv_sha
        or intent.get("task_host") != host
        or intent.get("task_cwd") != cwd
        or intent.get("previous_task_id") != effective["task_id"]
        or intent.get("previous_state") not in WRITER_HANDOFF_TERMINAL_STATES
        or intent.get("launch_nonce_sha256") != hashlib.sha256(launch_nonce.encode()).hexdigest()
    ):
        return {
            "workspace_id": manifest["workspace_id"],
            "state": "writer_handoff_start_intent_mismatch",
            "handoff_status": "blocked",
            "reconcile_required": True,
        }
    created_at_unix = intent.get("created_at_unix")
    if isinstance(created_at_unix, bool) or not isinstance(created_at_unix, int):
        return {
            "workspace_id": manifest["workspace_id"],
            "state": "writer_handoff_start_intent_invalid",
            "handoff_status": "blocked",
            "reconcile_required": True,
        }
    candidates: list[dict[str, Any]] = []
    cursor: str | None = None
    exhausted = False
    for _ in range(10):
        page = tasks.grabowski_task_list(limit=100, view="standard", cursor=cursor)
        page_tasks = page.get("tasks") if isinstance(page, dict) else None
        if not isinstance(page_tasks, list):
            return {
                "workspace_id": manifest["workspace_id"],
                "state": "writer_handoff_start_reconcile_unobservable",
                "handoff_status": "blocked",
                "reconcile_required": True,
            }
        for item in page_tasks:
            if not isinstance(item, dict):
                continue
            observed_created = item.get("created_at_unix")
            if (
                item.get("host") == host
                and item.get("cwd") == cwd
                and item.get("argv_sha256") == expected_task_argv_sha
                and isinstance(observed_created, int)
                and not isinstance(observed_created, bool)
                and observed_created >= created_at_unix - 2
            ):
                candidates.append(item)
        pagination = page.get("pagination") if isinstance(page, dict) else None
        has_more = bool(isinstance(pagination, dict) and pagination.get("has_more"))
        if not has_more:
            exhausted = True
            break
        oldest = min(
            (
                item.get("created_at_unix")
                for item in page_tasks
                if isinstance(item, dict)
                and isinstance(item.get("created_at_unix"), int)
                and not isinstance(item.get("created_at_unix"), bool)
            ),
            default=None,
        )
        if oldest is not None and oldest < created_at_unix - 2:
            exhausted = True
            break
        cursor = pagination.get("next_cursor") if isinstance(pagination, dict) else None
        if not isinstance(cursor, str) or not cursor:
            break
    unique = {str(item.get("task_id")): item for item in candidates if isinstance(item.get("task_id"), str)}
    if len(unique) != 1:
        if not unique and exhausted and _now() - created_at_unix >= 10:
            intents = dict(manifest.get("task_start_intents", {}))
            intent_sha256 = _sha256_json(intent)
            intents.pop("writer_handoff", None)
            manifest["task_start_intents"] = intents
            _append_workspace_event(
                manifest,
                "writer_handoff_start_absent",
                role="writer",
                outcome="intent_cleared",
                evidence={
                    "attempt": 2,
                    "intent_sha256": intent_sha256,
                    "task_argv_sha256": expected_task_argv_sha,
                    "scan_exhausted": True,
                    "candidate_count": 0,
                },
            )
            _write_manifest(manifest)
            base._append_audit(
                {
                    "timestamp_unix": _now(),
                    "operation": "agent-workspace-writer-handoff-start-absent",
                    "workspace_id": manifest["workspace_id"],
                    "attempt": 2,
                    "intent_sha256": intent_sha256,
                    "task_argv_sha256": expected_task_argv_sha,
                }
            )
            return {
                "workspace_id": manifest["workspace_id"],
                "state": "writer_handoff_start_absent_intent_cleared",
                "scan_exhausted": True,
                "handoff_status": "aborted",
                "reconcile_required": False,
                "retry_allowed_on_new_call": True,
            }
        return {
            "workspace_id": manifest["workspace_id"],
            "state": (
                "writer_handoff_start_unresolved"
                if not unique
                else "writer_handoff_start_ambiguous"
            ),
            "candidate_task_ids": sorted(unique),
            "scan_exhausted": exhausted,
            "handoff_status": "blocked",
            "reconcile_required": True,
        }
    candidate = next(iter(unique.values()))
    public = _validate_started_task(
        candidate,
        role="writer",
        expected_host=host,
        expected_argv=task_argv,
        expected_cwd=cwd,
    )
    return _bind_writer_handoff_attempt(
        manifest,
        attempts=attempts,
        effective=effective,
        previous_state=str(intent["previous_state"]),
        command=command,
        task_argv=task_argv,
        public=public,
        output=_role_receipt_path(manifest, "writer", attempt=2),
        launch_nonce=launch_nonce,
        reconciled=True,
    )


@mcp.tool(name="grabowski_agent_workspace_writer_handoff", annotations=MUTATING)
def grabowski_agent_workspace_writer_handoff(workspace_id: str, replacement_argv: list[str]) -> dict[str, Any]:
    """Start one operator-bound replacement writer after a proven terminal failure."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    with _lock(identifier):
        manifest = _manifest(identifier)
        command = _role_argv(replacement_argv, "replacement_argv", cwd=Path(str(manifest["writer_worktree"])))
        command_sha = _sha256_json(command)
        try:
            attempts = _writer_attempts(manifest)
            final = _writer_final_attempt(manifest)
            effective = _effective_writer_attempt(manifest)
        except Exception as exc:
            return {"workspace_id": identifier, "state": "writer_attempt_binding_invalid", "error": _error_summary(exc), "handoff_status": "blocked"}
        if final > 1:
            if final == 2 and effective.get("actor") == "operator_handoff" and effective.get("command_sha256") == command_sha:
                writer = _task_public(str(effective["task_id"]))
                binding_reasons = _writer_task_binding_reasons(
                    manifest, effective, writer
                )
                if binding_reasons:
                    return {
                        "workspace_id": identifier,
                        "state": "writer_handoff_task_binding_mismatch",
                        "attempt": 2,
                        "task": writer,
                        "binding_reasons": binding_reasons,
                        "handoff_status": "blocked",
                    }
                return {
                    "workspace_id": identifier,
                    "state": "writer_handoff_already_started",
                    "attempt": 2,
                    "task": writer,
                    "handoff_status": "idempotent",
                }
            return {"workspace_id": identifier, "state": "writer_handoff_limit_reached", "handoff_status": "blocked"}
        writer = _task_public(str(effective["task_id"]))
        intents_value = manifest.get("task_start_intents", {})
        if not isinstance(intents_value, dict):
            return {"workspace_id": identifier, "state": "writer_handoff_start_intents_invalid", "handoff_status": "blocked", "reconcile_required": True}
        existing_intent = intents_value.get("writer_handoff")
        if existing_intent is not None:
            if not isinstance(existing_intent, dict):
                return {"workspace_id": identifier, "state": "writer_handoff_start_intent_invalid", "handoff_status": "blocked", "reconcile_required": True}
            return _reconcile_writer_handoff_start(
                manifest,
                attempts=attempts,
                effective=effective,
                writer=writer,
                command=command,
                intent=existing_intent,
            )
        try:
            snapshot = _git_snapshot(manifest, _run)
            eligibility = _writer_handoff_eligibility(manifest, writer, snapshot)
        except Exception as exc:
            return {"workspace_id": identifier, "state": "writer_handoff_unobservable", "error": _error_summary(exc), "handoff_status": "blocked"}
        if not eligibility["eligible"]:
            return {"workspace_id": identifier, "state": "writer_handoff_blocked", "writer_handoff": eligibility, "writer_task": writer, "handoff_status": "blocked"}
        preflight = _role_toolchain_preflight(manifest, "writer", command)
        _append_workspace_event(
            manifest,
            "role_preflight",
            role="writer",
            outcome="passed" if preflight["passed"] else "environment_failure",
            evidence={
                "command_sha256": preflight.get("command_sha256"),
                "failure_classification": preflight.get("failure_classification"),
                "writer_handoff": True,
                "attempt_consumed": False,
            },
        )
        if not preflight["passed"]:
            blocks_value = manifest.get("writer_handoff_preflight_blocks", [])
            if not isinstance(blocks_value, list) or any(
                not isinstance(item, dict) for item in blocks_value
            ):
                return {
                    "workspace_id": identifier,
                    "state": "writer_handoff_preflight_history_invalid",
                    "attempt_consumed": False,
                    "handoff_status": "blocked",
                }
            blocks = [
                *blocks_value,
                {**preflight, "attempt_consumed": False, "proposed_attempt": 2},
            ][-MAX_WRITER_HANDOFF_PREFLIGHT_BLOCKS:]
            manifest["writer_handoff_preflight_blocks"] = blocks
            _write_manifest(manifest)
            return {"workspace_id": identifier, "state": "writer_toolchain_preflight_failed", "preflight": preflight, "attempt_consumed": False, "handoff_status": "blocked"}
        revalidated_writer = _task_public(str(effective["task_id"]))
        revalidated_snapshot = _git_snapshot(manifest, _run)
        revalidated = _writer_handoff_eligibility(
            manifest, revalidated_writer, revalidated_snapshot
        )
        if not revalidated["eligible"]:
            _append_workspace_event(
                manifest,
                "writer_handoff_revalidation",
                role="writer",
                outcome="blocked",
                evidence={
                    "attempt": 2,
                    "command_sha256": command_sha,
                    "reasons": list(revalidated["reasons"]),
                },
            )
            _write_manifest(manifest)
            return {
                "workspace_id": identifier,
                "state": "writer_handoff_revalidation_blocked",
                "writer_handoff": revalidated,
                "handoff_status": "blocked",
            }
        resources_value = manifest["resources"]
        renewed = resources.renew_resources(
            str(resources_value["owner_id"]),
            list(resources_value["lease_keys"]),
            ttl_seconds=min(
                resources.MAX_TTL_SECONDS,
                int(resources_value["runtime_seconds"]) + 900,
            ),
        )
        _append_workspace_event(
            manifest,
            "writer_handoff_leases_renewed",
            role="writer",
            outcome="renewed",
            evidence={
                "attempt": 2,
                "expires_at_unix": renewed.get("expires_at_unix"),
                "lease_count": len(renewed.get("leases", [])),
            },
        )
        output = _role_receipt_path(manifest, "writer", attempt=2)
        if os.path.lexists(output):
            return {"workspace_id": identifier, "state": "writer_handoff_receipt_already_exists", "receipt_path": str(output), "handoff_status": "blocked"}
        launch_nonce = hashlib.sha256(
            f"{identifier}:writer:handoff:{time.time_ns()}".encode()
        ).hexdigest()[:24]
        task_argv = _writer_task_argv(
            manifest,
            command=command,
            attempt=2,
            launch_nonce=launch_nonce,
        )
        host = _bound_task_host(manifest)
        cwd = str(manifest["writer_worktree"])
        intent = {
            "role": "writer", "kind": "operator_handoff", "attempt": 2, "created_at": _utc(),
            "created_at_unix": _now(),
            "nonce": hashlib.sha256(f"{identifier}:writer:intent:{time.time_ns()}".encode()).hexdigest()[:24],
            "launch_nonce": launch_nonce,
            "launch_nonce_sha256": hashlib.sha256(launch_nonce.encode()).hexdigest(),
            "previous_task_id": effective["task_id"], "previous_state": revalidated_writer.get("state"),
            "command_sha256": command_sha, "task_argv_sha256": _task_argv_sha256(task_argv),
            "task_host": host, "task_cwd": cwd,
        }
        intents = dict(manifest.get("task_start_intents", {}))
        intents["writer_handoff"] = intent
        manifest["task_start_intents"] = intents
        _append_workspace_event(
            manifest,
            "writer_handoff_start_intent",
            role="writer",
            outcome="persisted",
            evidence={
                "attempt": 2,
                "previous_task_id": effective["task_id"],
                "previous_state": revalidated_writer.get("state"),
                "command_sha256": command_sha,
                "task_argv_sha256": intent["task_argv_sha256"],
            },
        )
        _write_manifest(manifest)
        started = tasks.grabowski_task_start(
            host=host, argv=task_argv, cwd=cwd,
            runtime_seconds=int(manifest["resources"]["runtime_seconds"]), resume_policy="never",
            cpu_weight=100, io_weight=100, memory_max_bytes=manifest["resources"]["memory_max_bytes"],
            resource_keys=None, chronik_outbox=True,
        )
        public = _validate_started_task(started.get("task") if isinstance(started, dict) else None, role="writer", expected_host=host, expected_argv=task_argv, expected_cwd=cwd)
        return _bind_writer_handoff_attempt(
            manifest,
            attempts=attempts,
            effective=effective,
            previous_state=str(revalidated_writer["state"]),
            command=command,
            task_argv=task_argv,
            public=public,
            output=output,
            launch_nonce=launch_nonce,
            reconciled=False,
        )


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
            "task_argv_sha256": _task_argv_sha256(task_argv),
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
            outcome_path = _outcome_receipt_path(manifest, "close")
            if outcome_path.is_file():
                outcome_receipt = _load_json(outcome_path)
                observed_outcome_sha256 = outcome_receipt.get("outcome_sha256")
                unsigned_outcome = {
                    key: value
                    for key, value in outcome_receipt.items()
                    if key != "outcome_sha256"
                }
                if (
                    not isinstance(observed_outcome_sha256, str)
                    or SHA256_RE.fullmatch(observed_outcome_sha256) is None
                    or _sha256_json(unsigned_outcome) != observed_outcome_sha256
                    or outcome_receipt.get("workspace_id") != identifier
                    or outcome_receipt.get("phase") != "close"
                    or outcome_receipt.get("outcome_identity")
                    != _outcome_identity(manifest, "close")
                ):
                    raise AgentWorkspaceActionError(
                        "existing workspace outcome receipt integrity is invalid"
                    )
                references = dict(manifest.get("outcome_receipts", {}))
                current = references.get("close")
                history = (
                    list(current.get("history", []))
                    if isinstance(current, dict)
                    and isinstance(current.get("history"), list)
                    else []
                )
                reference = {
                    "path": str(outcome_path),
                    "outcome_identity": outcome_receipt["outcome_identity"],
                    "outcome_sha256": observed_outcome_sha256,
                }
                if not any(
                    isinstance(item, dict)
                    and item.get("outcome_sha256") == observed_outcome_sha256
                    for item in history
                ):
                    history.append(reference)
                references["close"] = {**reference, "history": history}
                manifest["outcome_receipts"] = references
            else:
                outcome_receipt = _publish_workspace_outcome(manifest, "close")
            _write_manifest(manifest)
            execution_outcome_binding = _bind_workspace_execution_outcome(
                manifest, outcome_receipt
            )
            _ensure_workspace_closed_event(
                manifest, existing, execution_outcome_binding
            )
            _write_manifest(manifest)
            base._append_audit(
                {
                    "timestamp_unix": _now(),
                    "operation": "agent-workspace-close-readback",
                    "workspace_id": identifier,
                    "writer_head": head,
                    "diff_sha256": diff_sha,
                    "result_sha256": result_sha,
                    "execution_outcome_binding_state": (
                        execution_outcome_binding.get("state")
                    ),
                    "idempotent": True,
                }
            )
            return {
                "workspace_id": identifier,
                "close_receipt": existing,
                "idempotent": True,
                "outcome_receipt": outcome_receipt,
                "execution_outcome_binding": execution_outcome_binding,
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
        receipt["checkout_lifecycle_decision"] = (
            _terminal_writer_checkout_decision(manifest, snapshot)
        )
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
        _write_manifest(manifest)
        outcome_receipt = _publish_workspace_outcome(manifest, "close")
        _write_manifest(manifest)
        execution_outcome_binding = _bind_workspace_execution_outcome(
            manifest, outcome_receipt
        )
        _ensure_workspace_closed_event(
            manifest, receipt, execution_outcome_binding
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
            "execution_outcome_binding": execution_outcome_binding,
            "external_closeout_checklist": _external_closeout_checklist(manifest),
        }



def _path_identity(value: str) -> str:
    return os.path.realpath(os.path.abspath(os.path.expanduser(value)))


def _workspace_cleanup_owner(workspace_id: str) -> str:
    return checkouts._owner(f"agent-workspace-cleanup:{workspace_id}")


def _valid_workspace_cleanup_receipt(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    receipt_sha256 = value.get("receipt_sha256")
    if not isinstance(receipt_sha256, str) or SHA256_RE.fullmatch(receipt_sha256) is None:
        return False
    stable = dict(value)
    stable.pop("receipt_sha256", None)
    return _sha256_json(stable) == receipt_sha256


def _workspace_cleanup_integrity_status(
    manifest: dict[str, Any], receipt: Any
) -> dict[str, Any]:
    result = {
        "valid": False,
        "hash_valid": False,
        "receipt_present": False,
        "receipt_matches_manifest": False,
    }
    if isinstance(receipt, dict):
        result["hash_valid"] = _valid_workspace_cleanup_receipt(receipt)
    path = _workspace_dir(str(manifest["workspace_id"])) / "cleanup-receipt.json"
    if not path.exists():
        return result
    try:
        stored = _load_json(path)
    except Exception as exc:
        result["error"] = _error_summary(exc)
        return result
    result["receipt_present"] = True
    result["receipt_matches_manifest"] = isinstance(receipt, dict) and stored == receipt
    result["valid"] = bool(
        result["hash_valid"] and result["receipt_matches_manifest"]
    )
    return result


def _workspace_cleanup_references(
    writer_worktree: str, current_workspace_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    target = _path_identity(writer_worktree)
    references: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not WORKSPACE_ROOT.exists():
        return references, errors
    if WORKSPACE_ROOT.is_symlink() or not WORKSPACE_ROOT.is_dir():
        raise AgentWorkspaceError("workspace root must be one real directory")
    entries = [
        entry
        for entry in sorted(WORKSPACE_ROOT.iterdir(), key=lambda item: item.name)
        if WORKSPACE_ID_RE.fullmatch(entry.name) is not None
    ]
    if len(entries) > MAX_WORKSPACE_REFERENCE_SCAN:
        return references, [
            {
                "code": "workspace_reference_scan_limit_exceeded",
                "observed_entries": len(entries),
                "maximum_entries": MAX_WORKSPACE_REFERENCE_SCAN,
            }
        ]
    for directory in entries:
        if directory.is_symlink() or not directory.is_dir():
            errors.append(
                {
                    "code": "workspace_registry_entry_unsafe",
                    "workspace_id": directory.name,
                }
            )
            continue
        manifest_path = directory / "manifest.json"
        try:
            candidate = _load_json(manifest_path)
        except Exception as exc:
            errors.append(
                {
                    "code": "workspace_manifest_unreadable",
                    "workspace_id": directory.name,
                    "error": _error_summary(exc),
                }
            )
            continue
        candidate_path = candidate.get("writer_worktree")
        candidate_id = candidate.get("workspace_id")
        if candidate_id != directory.name or not isinstance(candidate_path, str):
            errors.append(
                {
                    "code": "workspace_manifest_identity_invalid",
                    "workspace_id": directory.name,
                }
            )
            continue
        if _path_identity(candidate_path) != target:
            continue
        close_receipt = candidate.get("close_receipt")
        close_integrity = _close_integrity_status(candidate, close_receipt)
        fully_closed = bool(
            isinstance(close_receipt, dict)
            and close_receipt.get("state") == "complete"
            and close_receipt.get("resources_released") is True
            and close_integrity["valid"]
        )
        references.append(
            {
                "workspace_id": candidate_id,
                "current": candidate_id == current_workspace_id,
                "creation_state": candidate.get("creation_state"),
                "close_receipt_present": isinstance(close_receipt, dict),
                "close_receipt_valid": close_integrity["valid"],
                "closed": fully_closed,
                "resources_released": (
                    close_receipt.get("resources_released")
                    if isinstance(close_receipt, dict)
                    else None
                ),
            }
        )
    return references, errors


def _workspace_created_unix(manifest: dict[str, Any]) -> int | None:
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        return None
    try:
        parsed = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _closed_workspace_liveness(manifest: dict[str, Any]) -> dict[str, Any]:
    close_receipt = manifest.get("close_receipt")
    task_states = (
        dict(close_receipt.get("task_states", {}))
        if isinstance(close_receipt, dict)
        and isinstance(close_receipt.get("task_states"), dict)
        else {}
    )
    created_unix = _workspace_created_unix(manifest)
    stale_after_unix = (
        created_unix + STALE_WORKSPACE_MINIMUM_AGE_SECONDS
        if created_unix is not None
        else None
    )
    return {
        "created_at": manifest.get("created_at"),
        "created_at_unix": created_unix,
        "stale_after_unix": stale_after_unix,
        "stale_threshold_met": bool(
            stale_after_unix is not None and _now() >= stale_after_unix
        ),
        "task_states": task_states,
        "nonterminal_roles": [],
        "execution_live_roles": [],
        "recovery_attention_roles": [],
        "task_observation_error_roles": [],
        "live_resource_keys": [],
        "resource_observation_error": None,
        "session_live": False,
        "operationally_live": False,
        "session_only_non_authoritative": False,
        "unresolved_task_start_roles": [],
        "source": "complete_close_receipt",
    }


def _workspace_liveness(manifest: dict[str, Any]) -> dict[str, Any]:
    task_states: dict[str, dict[str, Any]] = {}
    nonterminal_roles: list[str] = []
    execution_live_roles: list[str] = []
    recovery_attention_roles: list[str] = []
    task_observation_error_roles: list[str] = []
    for role_name in ("writer", "tests", "review"):
        task_id = manifest.get("tasks", {}).get(role_name)
        public = _task_public(task_id)
        task_states[role_name] = public
        if task_id is None:
            continue
        state = str(public.get("state", "unknown"))
        if not public.get("terminal"):
            nonterminal_roles.append(role_name)
        if state in {"launching", "running"}:
            execution_live_roles.append(role_name)
        elif state in {"interrupted", "outcome_unknown"}:
            recovery_attention_roles.append(role_name)
        elif not public.get("terminal"):
            task_observation_error_roles.append(role_name)
    resource_owner = manifest.get("resources", {}).get("owner_id")
    live_resource_keys: list[str] = []
    resource_observation_error: str | None = None
    if isinstance(resource_owner, str) and resource_owner:
        try:
            observed = resources.list_resources(
                owner_id=resource_owner,
                include_expired=False,
                limit=MAX_PATHS + 8,
            )
            live_resource_keys = sorted(
                str(item.get("resource_key"))
                for item in observed
                if isinstance(item, dict) and isinstance(item.get("resource_key"), str)
            )
        except Exception as exc:
            resource_observation_error = _error_summary(exc)
    session_name = manifest.get("session_name")
    session_live = bool(
        isinstance(session_name, str) and session_name and _tmux_has_session(session_name)
    )
    start_intents = manifest.get("task_start_intents", {})
    unresolved_start_roles = sorted(start_intents) if isinstance(start_intents, dict) else ["invalid"]
    operationally_live = bool(
        execution_live_roles
        or task_observation_error_roles
        or live_resource_keys
        or resource_observation_error
        or unresolved_start_roles
    )
    created_unix = _workspace_created_unix(manifest)
    stale_after_unix = (
        created_unix + STALE_WORKSPACE_MINIMUM_AGE_SECONDS
        if created_unix is not None
        else None
    )
    return {
        "created_at": manifest.get("created_at"),
        "created_at_unix": created_unix,
        "stale_after_unix": stale_after_unix,
        "stale_threshold_met": bool(
            stale_after_unix is not None and _now() >= stale_after_unix
        ),
        "task_states": task_states,
        "nonterminal_roles": nonterminal_roles,
        "execution_live_roles": execution_live_roles,
        "recovery_attention_roles": recovery_attention_roles,
        "task_observation_error_roles": task_observation_error_roles,
        "live_resource_keys": live_resource_keys,
        "resource_observation_error": resource_observation_error,
        "session_live": session_live,
        "operationally_live": operationally_live,
        "session_only_non_authoritative": bool(session_live and not operationally_live),
        "unresolved_task_start_roles": unresolved_start_roles,
        "source": "live_runtime",
    }


def _stale_workspace_reconciliation_plan(
    manifest: dict[str, Any], liveness: dict[str, Any]
) -> dict[str, Any]:
    blockers: list[dict[str, Any]] = []
    close_receipt = manifest.get("close_receipt")
    if isinstance(close_receipt, dict):
        blockers.append({"code": "workspace_already_closed"})
    if liveness.get("created_at_unix") is None:
        blockers.append({"code": "workspace_age_unknown"})
    elif liveness.get("stale_threshold_met") is not True:
        blockers.append(
            {
                "code": "workspace_not_stale",
                "stale_after_unix": liveness.get("stale_after_unix"),
                "minimum_age_seconds": STALE_WORKSPACE_MINIMUM_AGE_SECONDS,
            }
        )
    # tmux is not authoritative evidence of operational liveness. However, the
    # stale reconciler is deliberately non-destructive and therefore cannot
    # close a workspace while an idle session would remain behind.
    if liveness.get("session_live"):
        blockers.append(
            {
                "code": (
                    "workspace_tmux_session_live"
                    if liveness.get("operationally_live")
                    else "workspace_idle_tmux_cleanup_required"
                )
            }
        )
    if liveness.get("resource_observation_error"):
        blockers.append(
            {
                "code": "workspace_resource_outcome_unknown",
                "error": liveness["resource_observation_error"],
            }
        )
    if liveness.get("live_resource_keys"):
        blockers.append(
            {
                "code": "workspace_resources_live",
                "resource_keys": liveness["live_resource_keys"],
            }
        )
    if liveness.get("execution_live_roles"):
        blockers.append(
            {
                "code": "workspace_tasks_nonterminal",
                "roles": liveness["execution_live_roles"],
            }
        )
    if liveness.get("recovery_attention_roles"):
        blockers.append(
            {
                "code": "workspace_tasks_require_reconciliation",
                "roles": liveness["recovery_attention_roles"],
            }
        )
    if liveness.get("task_observation_error_roles"):
        blockers.append(
            {
                "code": "workspace_task_observation_error",
                "roles": liveness["task_observation_error_roles"],
            }
        )
    if liveness.get("unresolved_task_start_roles"):
        blockers.append(
            {
                "code": "workspace_task_start_outcome_unknown",
                "roles": liveness["unresolved_task_start_roles"],
            }
        )
    return {
        "eligible": not blockers,
        "blockers": blockers,
        "minimum_age_seconds": STALE_WORKSPACE_MINIMUM_AGE_SECONDS,
        "action": "mark-stale-workspace-abandoned",
        "mutates_tasks": False,
        "mutates_resources": False,
        "removes_tmux": False,
        "removes_worktree": False,
        "deletes_workspace_evidence": False,
    }


def _workspace_cleanup_plan_data(
    manifest: dict[str, Any]
) -> dict[str, Any]:
    identifier = str(manifest["workspace_id"])
    repository = str(manifest["repository"])
    writer_worktree = str(manifest["writer_worktree"])
    writer_branch = str(manifest["writer_branch"])
    owner = _workspace_cleanup_owner(identifier)
    close_receipt = manifest.get("close_receipt")
    close_integrity = _close_integrity_status(manifest, close_receipt)
    fully_closed = bool(
        isinstance(close_receipt, dict)
        and close_receipt.get("state") == "complete"
        and close_receipt.get("resources_released") is True
        and close_integrity["valid"]
    )
    liveness = (
        _closed_workspace_liveness(manifest)
        if fully_closed
        else _workspace_liveness(manifest)
    )
    stale_reconciliation = _stale_workspace_reconciliation_plan(manifest, liveness)
    blockers: list[dict[str, Any]] = []
    cleanup_receipt = manifest.get("workspace_cleanup_receipt")
    cleanup_intent = manifest.get("workspace_cleanup_intent")
    cleanup_integrity = _workspace_cleanup_integrity_status(
        manifest, cleanup_receipt
    )
    cleanup_receipt_valid = cleanup_integrity["valid"]
    close_receipt_path = _workspace_dir(identifier) / "close-receipt.json"
    if cleanup_integrity["receipt_present"] and cleanup_receipt is None:
        blockers.append({"code": "cleanup_receipt_outcome_unknown"})
    elif cleanup_receipt is not None and not cleanup_receipt_valid:
        blockers.append(
            {"code": "cleanup_receipt_invalid", "integrity": cleanup_integrity}
        )
    if close_receipt is None and close_receipt_path.exists():
        blockers.append({"code": "workspace_close_outcome_unknown"})
    elif not isinstance(close_receipt, dict):
        blockers.append({"code": "workspace_not_closed"})
    elif not close_integrity["valid"]:
        blockers.append(
            {
                "code": "workspace_close_receipt_invalid",
                "integrity": close_integrity,
            }
        )
    elif close_receipt.get("state") != "complete":
        blockers.append({"code": "workspace_not_closed"})
    elif close_receipt.get("resources_released") is not True:
        blockers.append({"code": "workspace_resources_not_released"})
    if isinstance(cleanup_intent, dict) and cleanup_intent.get("state") == "started":
        blockers.append(
            {
                "code": "cleanup_outcome_unknown",
                "intent_id": cleanup_intent.get("intent_id"),
                "archive_id": cleanup_intent.get("archive_id"),
            }
        )
    references, reference_scan_errors = _workspace_cleanup_references(
        writer_worktree, identifier
    )
    if reference_scan_errors:
        blockers.append(
            {
                "code": "workspace_reference_inventory_incomplete",
                "errors": reference_scan_errors,
            }
        )
    open_references = [
        item for item in references if not item["current"] and not item["closed"]
    ]
    if open_references:
        blockers.append(
            {
                "code": "worktree_referenced_by_open_workspace",
                "workspace_ids": sorted(item["workspace_id"] for item in open_references),
            }
        )
    checkout_state: dict[str, Any] = {
        "exists": False,
        "linked": False,
        "clean": False,
        "head": None,
        "branch": None,
        "checkout_key": None,
        "coordination": None,
    }
    checkout_path = Path(writer_worktree).expanduser()
    if checkout_path.is_symlink():
        blockers.append({"code": "writer_worktree_is_symlink"})
    elif not checkout_path.exists():
        if not cleanup_receipt_valid and not fully_closed:
            blockers.append({"code": "writer_worktree_missing_without_valid_cleanup_receipt"})
    elif not checkout_path.is_dir():
        blockers.append({"code": "writer_worktree_not_directory"})
    else:
        checkout_state["exists"] = True
        try:
            top_level, common_dir, record = checkouts._worktree_for_path(
                checkouts._resolve_repo(repository), checkout_path
            )
            status = checkouts._worktree_status(record)
            clean = status.get("dirty") is False
            checkout_state.update(
                {
                    "linked": True,
                    "clean": clean,
                    "head": record.get("head"),
                    "branch": record.get("branch"),
                    "checkout_key": record.get("checkout_key"),
                    "status": status,
                    "repo": str(top_level),
                }
            )
            if not clean:
                blockers.append(
                    {
                        "code": "checkout_not_clean_linked",
                        "error": "Checkout must be clean before archival or cleanup",
                    }
                )
            if record.get("branch") != writer_branch:
                blockers.append(
                    {
                        "code": "writer_branch_mismatch",
                        "expected": writer_branch,
                        "actual": record.get("branch"),
                    }
                )
            expected_head = (
                close_receipt.get("expected_head")
                if isinstance(close_receipt, dict)
                else None
            )
            if isinstance(expected_head, str) and record.get("head") != expected_head:
                blockers.append(
                    {
                        "code": "writer_head_mismatch",
                        "expected": expected_head,
                        "actual": record.get("head"),
                    }
                )
            coordination = checkouts._linked_checkout_coordination(
                checkout_path,
                top_level,
                common_dir,
                owner_id=owner,
                include_processes=True,
                include_tasks=True,
                include_resources=True,
            )
            checkout_state["coordination"] = coordination
            if coordination.get("blocking"):
                blockers.append(
                    {
                        "code": "active_checkout_coordination",
                        "blocking_counts": coordination.get("blocking_counts", {}),
                    }
                )
        except Exception as exc:
            blockers.append(
                {
                    "code": "checkout_state_unverified",
                    "error": _error_summary(exc),
                }
            )
    stale_blockers = list(stale_reconciliation["blockers"])
    if close_receipt is None and close_receipt_path.exists():
        stale_blockers.append({"code": "workspace_close_outcome_unknown"})
    if cleanup_receipt is not None or cleanup_integrity["receipt_present"]:
        stale_blockers.append({"code": "workspace_cleanup_state_present"})
    if cleanup_intent is not None:
        stale_blockers.append({"code": "workspace_cleanup_intent_present"})
    if checkout_state["exists"] and not checkout_state["clean"]:
        stale_blockers.append({"code": "stale_workspace_dirty_checkout"})
    if reference_scan_errors:
        stale_blockers.append(
            {
                "code": "workspace_reference_inventory_incomplete",
                "errors": reference_scan_errors,
            }
        )
    if open_references:
        stale_blockers.append(
            {
                "code": "shared_worktree_open_reference",
                "workspace_ids": sorted(item["workspace_id"] for item in open_references),
            }
        )
    coordination = checkout_state.get("coordination")
    if isinstance(coordination, dict) and coordination.get("blocking"):
        stale_blockers.append(
            {
                "code": "stale_workspace_checkout_coordination_active",
                "blocking_counts": coordination.get("blocking_counts", {}),
            }
        )
    legacy_absence_reconciliation = bool(
        not checkout_state["exists"]
        and manifest.get("runtime_identity") is None
        and cleanup_receipt is None
        and cleanup_intent is None
    )
    stale_reconciliation = {
        **stale_reconciliation,
        "eligible": not stale_blockers,
        "blockers": stale_blockers,
        "reconciliation_kind": (
            "legacy_absence" if legacy_absence_reconciliation else "stale_abandonment"
        ),
        "closure_outcome": (
            "abandoned_legacy_workspace"
            if legacy_absence_reconciliation
            else "abandoned_stale_workspace"
        ),
        "legacy_absence_receipt_required": legacy_absence_reconciliation,
    }
    session_name = manifest.get("session_name")
    exact_idle_tmux_session_live = bool(
        liveness.get("session_live") is True
        and isinstance(session_name, str)
        and session_name
        and _tmux_has_exact_session(session_name)
    )
    idle_tmux_transition_eligible = bool(
        exact_idle_tmux_session_live
        and liveness.get("operationally_live") is False
        and liveness.get("session_only_non_authoritative") is True
        and isinstance(session_name, str)
        and session_name
        and stale_reconciliation["reconciliation_kind"] == "stale_abandonment"
        and checkout_state["exists"]
        and checkout_state["linked"]
        and checkout_state["clean"]
        and len(stale_blockers) == 1
        and stale_blockers[0].get("code") == "workspace_idle_tmux_cleanup_required"
    )
    stale_reconciliation["idle_tmux_transition"] = {
        "eligible": idle_tmux_transition_eligible,
        "action": "remove-idle-tmux-and-mark-stale-workspace-abandoned",
        "confirmation_required": "remove-idle-tmux-and-mark-stale-workspace-abandoned",
        "session_name": session_name,
        "exact_session_live": exact_idle_tmux_session_live,
        "removes_tmux": True,
        "mutates_tasks": False,
        "mutates_resources": False,
        "removes_worktree": False,
        "deletes_workspace_evidence": False,
    }
    if cleanup_receipt_valid and checkout_state["exists"]:
        blockers.append({"code": "writer_worktree_reappeared_after_cleanup"})
    already_cleaned = bool(cleanup_receipt_valid and not checkout_state["exists"])
    already_absent = bool(
        fully_closed
        and not checkout_state["exists"]
        and not cleanup_receipt_valid
        and not blockers
    )
    eligible = not blockers and checkout_state["exists"] and checkout_state["linked"]
    body = {
        "schema_version": 1,
        "operation": "agent-workspace-cleanup",
        "workspace_id": identifier,
        "owner_id": owner,
        "repository": repository,
        "writer_worktree": writer_worktree,
        "writer_branch": writer_branch,
        "closed": fully_closed,
        "closure_outcome": (
            close_receipt.get("closure_outcome")
            if isinstance(close_receipt, dict)
            else None
        ),
        "resources_released": (
            close_receipt.get("resources_released")
            if isinstance(close_receipt, dict)
            else None
        ),
        "close_receipt_integrity": close_integrity,
        "cleanup_receipt_integrity": cleanup_integrity,
        "workspace_references": references,
        "workspace_reference_scan_errors": reference_scan_errors,
        "liveness": liveness,
        "stale_reconciliation": stale_reconciliation,
        "checkout": checkout_state,
        "prior_failed_intent": (
            cleanup_intent
            if isinstance(cleanup_intent, dict) and cleanup_intent.get("state") == "failed"
            else None
        ),
        "already_cleaned": already_cleaned,
        "already_absent": already_absent,
        "eligible": eligible,
        "blockers": blockers,
        "historical_evidence_preserved": True,
        "workspace_state_deleted": False,
        "execution_authorized": False,
        "cleanup_method": "archive-recovery-refs-then-remove-linked-checkout",
        "confirmation_required": "archive-and-remove-worktree",
        "does_not_establish": [
            "branch_merge_readiness",
            "pull_request_truth",
            "permission_to_delete_workspace_evidence",
        ],
    }
    return {**body, "plan_sha256": _sha256_json(body)}


@mcp.tool(name="grabowski_agent_workspace_cleanup_plan", annotations=READ_ONLY)
def grabowski_agent_workspace_cleanup_plan(
    workspace_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Inventory cleanup eligibility without deleting workspace evidence or a checkout."""
    operator._require_operator_capability("durable_job")
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("resource_lease")
    operator._require_operator_capability("tmux_interaction")
    selected: list[str]
    if workspace_ids is None:
        if not WORKSPACE_ROOT.exists():
            selected = []
        elif WORKSPACE_ROOT.is_symlink() or not WORKSPACE_ROOT.is_dir():
            raise AgentWorkspaceError("workspace root must be a real directory")
        else:
            selected = sorted(
                directory.name
                for directory in WORKSPACE_ROOT.iterdir()
                if directory.is_dir()
                and not directory.is_symlink()
                and WORKSPACE_ID_RE.fullmatch(directory.name) is not None
            )
    else:
        if not isinstance(workspace_ids, list) or not workspace_ids:
            raise AgentWorkspaceError("workspace_ids must be a non-empty list or null")
        selected = []
        for raw in workspace_ids:
            identifier = _required_string(raw, "workspace_id", max_length=80)
            if WORKSPACE_ID_RE.fullmatch(identifier) is None:
                raise AgentWorkspaceError(f"invalid workspace_id: {identifier}")
            if identifier not in selected:
                selected.append(identifier)
    if len(selected) > MAX_CLEANUP_WORKSPACES:
        raise AgentWorkspaceError(
            f"cleanup inventory exceeds {MAX_CLEANUP_WORKSPACES} workspaces"
        )
    plans = [_workspace_cleanup_plan_data(_manifest(identifier)) for identifier in selected]
    summary = {
        "workspace_count": len(plans),
        "eligible_count": sum(1 for plan in plans if plan["eligible"]),
        "already_cleaned_count": sum(1 for plan in plans if plan["already_cleaned"]),
        "already_absent_count": sum(1 for plan in plans if plan["already_absent"]),
        "stale_reconciliation_eligible_count": sum(
            1 for plan in plans if plan["stale_reconciliation"]["eligible"]
        ),
        "legacy_absence_reconciliation_eligible_count": sum(
            1
            for plan in plans
            if plan["stale_reconciliation"]["eligible"]
            and plan["stale_reconciliation"].get("reconciliation_kind") == "legacy_absence"
        ),
        "operationally_live_count": sum(
            1 for plan in plans if plan["liveness"].get("operationally_live")
        ),
        "session_only_non_authoritative_count": sum(
            1
            for plan in plans
            if plan["liveness"].get("session_only_non_authoritative")
        ),
        "blocked_count": sum(
            1
            for plan in plans
            if not plan["eligible"]
            and not plan["already_cleaned"]
            and not plan["already_absent"]
        ),
    }
    body = {
        "schema_version": 1,
        "report_kind": "agent_workspace_cleanup_inventory",
        "owner_strategy": "derived-per-workspace",
        "plans": plans,
        "summary": summary,
        "execution_authorized": False,
        "historical_evidence_preserved": True,
    }
    return {**body, "inventory_sha256": _sha256_json(body)}



def _load_or_create_legacy_absence_receipt(
    manifest: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    path = _workspace_dir(str(manifest["workspace_id"])) / "legacy-absence-receipt.json"
    if path.exists():
        existing = _load_json(path)
        if _legacy_absence_receipt_valid(
            manifest,
            existing,
            expected_plan_sha256=plan.get("plan_sha256"),
        ):
            return existing
        raise AgentWorkspaceError(
            "existing legacy absence receipt is invalid or bound to another lifecycle plan"
        )
    body = {
        "schema_version": 1,
        "workspace_id": manifest["workspace_id"],
        "source_plan_sha256": plan["plan_sha256"],
        "repository": manifest["repository"],
        "writer_worktree": manifest["writer_worktree"],
        "writer_branch": manifest["writer_branch"],
        "workspace_created_at": manifest.get("created_at"),
        "observed_worktree_absent": True,
        "liveness_sha256": _sha256_json(plan["liveness"]),
        "workspace_reference_inventory_sha256": _sha256_json(
            {
                "references": plan["workspace_references"],
                "errors": plan["workspace_reference_scan_errors"],
            }
        ),
        "task_mutation_performed": False,
        "resource_mutation_performed": False,
        "tmux_mutation_performed": False,
        "worktree_mutation_performed": False,
        "historical_evidence_preserved": True,
        "recorded_at": _utc(),
    }
    receipt = {**body, "receipt_sha256": _sha256_json(body)}
    _atomic_json(path, receipt)
    return receipt


@mcp.tool(name="grabowski_agent_workspace_reconcile_stale", annotations=MUTATING)
def grabowski_agent_workspace_reconcile_stale(
    workspace_id: str,
    expected_plan_sha256: str,
    confirmation: str = "",
) -> dict[str, Any]:
    """Mark one provably inactive stale workspace abandoned without stopping or deleting anything."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    operator._require_operator_mutation("tmux_interaction")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    if WORKSPACE_ID_RE.fullmatch(identifier) is None:
        raise AgentWorkspaceError(f"invalid workspace_id: {identifier}")
    expected_hash = _required_string(
        expected_plan_sha256, "expected_plan_sha256", max_length=64
    )
    if SHA256_RE.fullmatch(expected_hash) is None:
        raise AgentWorkspaceError("expected_plan_sha256 must be a lowercase SHA-256")
    if confirmation != "mark-stale-workspace-abandoned":
        raise AgentWorkspaceError(
            "confirmation must be exactly 'mark-stale-workspace-abandoned'"
        )
    with _lock(identifier):
        manifest = _manifest(identifier)
        existing = manifest.get("close_receipt")
        if isinstance(existing, dict) and _close_integrity_status(manifest, existing)["valid"]:
            return {
                "workspace_id": identifier,
                "state": "already_closed",
                "idempotent": True,
                "close_receipt": existing,
            }
        plan = _workspace_cleanup_plan_data(manifest)
        if plan["plan_sha256"] != expected_hash:
            raise AgentWorkspaceError("workspace lifecycle plan is stale; rerun cleanup_plan")
        stale = plan["stale_reconciliation"]
        if not stale["eligible"]:
            return {
                "workspace_id": identifier,
                "state": "stale_reconciliation_blocked",
                "idempotent": False,
                "plan": plan,
            }
        task_states = plan["liveness"]["task_states"]
        failed_roles = sorted(
            role_name
            for role_name, task in task_states.items()
            if task.get("task_id") is not None and task.get("state") != "completed"
        )
        closure_outcome = str(stale["closure_outcome"])
        legacy_absence_receipt = (
            _load_or_create_legacy_absence_receipt(manifest, plan)
            if stale.get("reconciliation_kind") == "legacy_absence"
            else None
        )
        receipt = {
            "schema_version": 1,
            "state": "complete",
            "workspace_id": identifier,
            "source_plan_sha256": expected_hash,
            "expected_head": plan["checkout"]["head"],
            "closed_at": _utc(),
            "task_states": task_states,
            "cancelled_roles": [],
            "writer_worktree": manifest["writer_worktree"],
            "writer_branch": manifest["writer_branch"],
            "worktree_preserved": bool(plan["checkout"]["exists"]),
            "branch_preserved": bool(plan["checkout"]["exists"]),
            "dirty": None if not plan["checkout"]["exists"] else not plan["checkout"]["clean"],
            "tmux_removed": False,
            "resources_released": True,
            "released_resource_keys": [],
            "remaining_resource_keys": [],
            "resource_release_error": None,
            "no_unsecured_changes_discarded": True,
            "failed_roles": failed_roles,
            "abandon_failed_roles": True,
            "closure_outcome": closure_outcome,
            "stale_reconciliation": True,
            "reconciliation_kind": stale["reconciliation_kind"],
            "legacy_absence_reconciliation": legacy_absence_receipt is not None,
            "legacy_absence_receipt_sha256": (
                legacy_absence_receipt["receipt_sha256"]
                if legacy_absence_receipt is not None
                else None
            ),
            "task_mutation_performed": False,
            "resource_mutation_performed": False,
            "worktree_mutation_performed": False,
            "historical_evidence_preserved": True,
        }
        receipt["receipt_sha256"] = _sha256_json(receipt)
        _atomic_json(_workspace_dir(identifier) / "close-receipt.json", receipt)
        manifest["close_receipt"] = receipt
        _append_workspace_event(
            manifest,
            "workspace_stale_reconciled",
            outcome=closure_outcome,
            evidence={
                "receipt_sha256": receipt["receipt_sha256"],
                "source_plan_sha256": expected_hash,
                "task_mutation_performed": False,
                "resource_mutation_performed": False,
                "worktree_mutation_performed": False,
                "reconciliation_kind": stale["reconciliation_kind"],
                "legacy_absence_receipt_sha256": (
                    legacy_absence_receipt["receipt_sha256"]
                    if legacy_absence_receipt is not None
                    else None
                ),
            },
        )
        _write_manifest(manifest)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "agent-workspace-stale-reconcile",
            "workspace_id": identifier,
            "source_plan_sha256": expected_hash,
            "closure_outcome": closure_outcome,
            "reconciliation_kind": stale["reconciliation_kind"],
            "legacy_absence_receipt_sha256": (
                legacy_absence_receipt["receipt_sha256"]
                if legacy_absence_receipt is not None
                else None
            ),
            "task_mutation_performed": False,
            "resource_mutation_performed": False,
            "worktree_mutation_performed": False,
            "historical_evidence_preserved": True,
        }
    )
    return {
        "workspace_id": identifier,
        "state": (
            "legacy_workspace_reconciled"
            if closure_outcome == "abandoned_legacy_workspace"
            else "stale_workspace_reconciled"
        ),
        "idempotent": False,
        "close_receipt": receipt,
        "legacy_absence_receipt": legacy_absence_receipt,
        "worktree_preserved": receipt["worktree_preserved"],
        "historical_evidence_preserved": True,
    }


@mcp.tool(name="grabowski_agent_workspace_reconcile_idle_tmux", annotations=MUTATING)
def grabowski_agent_workspace_reconcile_idle_tmux(
    workspace_id: str,
    expected_plan_sha256: str,
    confirmation: str = "",
) -> dict[str, Any]:
    """Remove one exact non-authoritative idle tmux session, then stale-reconcile the workspace."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    operator._require_operator_mutation("tmux_interaction")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    if WORKSPACE_ID_RE.fullmatch(identifier) is None:
        raise AgentWorkspaceError(f"invalid workspace_id: {identifier}")
    expected_hash = _required_string(
        expected_plan_sha256, "expected_plan_sha256", max_length=64
    )
    if SHA256_RE.fullmatch(expected_hash) is None:
        raise AgentWorkspaceError("expected_plan_sha256 must be a lowercase SHA-256")
    required_confirmation = "remove-idle-tmux-and-mark-stale-workspace-abandoned"
    if confirmation != required_confirmation:
        raise AgentWorkspaceError(
            f"confirmation must be exactly '{required_confirmation}'"
        )
    with _lock(identifier):
        manifest = _manifest(identifier)
        existing = manifest.get("close_receipt")
        if isinstance(existing, dict) and _close_integrity_status(manifest, existing)["valid"]:
            return {
                "workspace_id": identifier,
                "state": "already_closed",
                "idempotent": True,
                "close_receipt": existing,
                "tmux_removed": False,
                "tmux_mutation_performed": False,
            }
        plan = _workspace_cleanup_plan_data(manifest)
        if plan["plan_sha256"] != expected_hash:
            raise AgentWorkspaceError("workspace lifecycle plan is stale; rerun cleanup_plan")
        transition = plan["stale_reconciliation"].get("idle_tmux_transition")
        if not isinstance(transition, dict) or transition.get("eligible") is not True:
            return {
                "workspace_id": identifier,
                "state": "idle_tmux_transition_blocked",
                "idempotent": False,
                "plan": plan,
            }
        session_name = transition.get("session_name")
        if not isinstance(session_name, str) or not session_name:
            raise AgentWorkspaceError("idle tmux transition has no exact session binding")
        pre_mutation_plan = _workspace_cleanup_plan_data(manifest)
        if pre_mutation_plan["plan_sha256"] != expected_hash:
            raise AgentWorkspaceError(
                "workspace lifecycle plan changed before idle tmux removal; rerun cleanup_plan"
            )
        pre_mutation_transition = pre_mutation_plan["stale_reconciliation"].get(
            "idle_tmux_transition"
        )
        if (
            not isinstance(pre_mutation_transition, dict)
            or pre_mutation_transition.get("eligible") is not True
            or pre_mutation_transition.get("session_name") != session_name
        ):
            raise AgentWorkspaceError("idle tmux transition changed before removal")
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "agent-workspace-idle-tmux-transition-start",
                "workspace_id": identifier,
                "source_plan_sha256": expected_hash,
                "session_name": session_name,
                "confirmation": required_confirmation,
                "mutation_performed": False,
            }
        )
        killed = _tmux_result(["kill-session", "-t", _tmux_exact_target(session_name)])
        tmux_mutation_performed = killed.get("returncode") == 0
        if not tmux_mutation_performed and _tmux_has_exact_session(session_name):
            raise AgentWorkspaceActionError(
                str(killed.get("stderr") or "idle tmux session removal failed")
            )
        if _tmux_has_exact_session(session_name):
            raise AgentWorkspaceActionError("idle tmux session remained live after removal")
        transition_body = {
            "schema_version": 1,
            "workspace_id": identifier,
            "source_plan_sha256": expected_hash,
            "session_name": session_name,
            "tmux_removed": True,
            "tmux_mutation_performed": tmux_mutation_performed,
            "task_mutation_performed": False,
            "resource_mutation_performed": False,
            "worktree_mutation_performed": False,
            "historical_evidence_preserved": True,
            "transitioned_at": _utc(),
        }
        transition_receipt = {
            **transition_body,
            "receipt_sha256": _sha256_json(transition_body),
        }
        _atomic_json(
            _workspace_dir(identifier) / "idle-tmux-transition-receipt.json",
            transition_receipt,
        )
        manifest["idle_tmux_transition_receipt"] = transition_receipt
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "agent-workspace-idle-tmux-remove",
                "workspace_id": identifier,
                "source_plan_sha256": expected_hash,
                "session_name": session_name,
                "receipt_sha256": transition_receipt["receipt_sha256"],
                "tmux_removed": True,
                "tmux_mutation_performed": tmux_mutation_performed,
                "historical_evidence_preserved": True,
            }
        )
        _append_workspace_event(
            manifest,
            "workspace_idle_tmux_removed",
            outcome="verified",
            evidence={
                "source_plan_sha256": expected_hash,
                "session_name": session_name,
                "receipt_sha256": transition_receipt["receipt_sha256"],
                "tmux_mutation_performed": tmux_mutation_performed,
            },
        )
        _write_manifest(manifest)
        post_tmux_plan = _workspace_cleanup_plan_data(manifest)
        post_tmux_plan_sha256 = str(post_tmux_plan["plan_sha256"])
        if not post_tmux_plan["stale_reconciliation"]["eligible"]:
            return {
                "workspace_id": identifier,
                "state": "idle_tmux_removed_stale_reconciliation_blocked",
                "idempotent": False,
                "source_plan_sha256": expected_hash,
                "post_tmux_plan_sha256": post_tmux_plan_sha256,
                "tmux_removed": True,
                "tmux_mutation_performed": tmux_mutation_performed,
                "idle_tmux_transition_receipt": transition_receipt,
                "plan": post_tmux_plan,
            }
    try:
        close_result = grabowski_agent_workspace_reconcile_stale(
            identifier,
            post_tmux_plan_sha256,
            "mark-stale-workspace-abandoned",
        )
    except AgentWorkspaceError as exc:
        if "workspace lifecycle plan is stale" not in str(exc):
            raise
        with _lock(identifier):
            current_plan = _workspace_cleanup_plan_data(_manifest(identifier))
        return {
            "workspace_id": identifier,
            "state": "idle_tmux_removed_stale_reconciliation_blocked",
            "idempotent": False,
            "source_plan_sha256": expected_hash,
            "post_tmux_plan_sha256": post_tmux_plan_sha256,
            "tmux_removed": True,
            "tmux_mutation_performed": tmux_mutation_performed,
            "idle_tmux_transition_receipt": transition_receipt,
            "reconciliation_error": str(exc),
            "plan": current_plan,
        }
    return {
        **close_result,
        "source_plan_sha256": expected_hash,
        "post_tmux_plan_sha256": post_tmux_plan_sha256,
        "tmux_removed": True,
        "tmux_mutation_performed": tmux_mutation_performed,
        "idle_tmux_transition_receipt": transition_receipt,
    }


def _verified_workspace_cleanup_archive(
    manifest: dict[str, Any],
    intent: dict[str, Any],
    owner: str,
) -> dict[str, Any] | None:
    archive_id = intent.get("archive_id")
    if not isinstance(archive_id, str):
        return None
    expected = {
        "checkout_path": _path_identity(str(manifest["writer_worktree"])),
        "head": intent.get("writer_head"),
        "branch": intent.get("writer_branch"),
        "owner_id": owner,
    }
    if (
        intent.get("owner_id") != owner
        or _path_identity(str(intent.get("writer_worktree", "")))
        != expected["checkout_path"]
        or intent.get("writer_branch") != manifest.get("writer_branch")
        or not isinstance(intent.get("writer_head"), str)
    ):
        return None
    try:
        archive = checkouts._load_archive(archive_id)
    except Exception:
        return None
    if (
        archive.get("cleaned_at_unix") is None
        or archive.get("cleanup_plan_id") is None
        or _path_identity(str(archive.get("checkout_path", "")))
        != expected["checkout_path"]
        or archive.get("head") != expected["head"]
        or archive.get("branch") != expected["branch"]
        or archive.get("owner_id") != owner
    ):
        return None
    try:
        repo = checkouts._resolve_repo(str(manifest["repository"]))
        if _path_identity(str(archive.get("repo_path", ""))) != _path_identity(str(repo)):
            return None
        archive_root = checkouts.ARCHIVE_ROOT
        if archive_root.is_symlink() or not archive_root.is_dir():
            return None
        expected_manifest = archive_root.resolve(strict=True) / archive_id / "manifest.json"
        manifest_path = Path(str(archive.get("manifest_path", "")))
        if manifest_path.is_symlink() or manifest_path.resolve(strict=True) != expected_manifest:
            return None
        archive_manifest = _load_json(manifest_path)
    except Exception:
        return None
    recovery_refs = archive.get("recovery_refs")
    if (
        archive_manifest.get("schema_version") != 1
        or archive_manifest.get("archive_id") != archive_id
        or _path_identity(str(archive_manifest.get("checkout_path", "")))
        != expected["checkout_path"]
        or archive_manifest.get("head") != expected["head"]
        or archive_manifest.get("branch") != expected["branch"]
        or archive_manifest.get("owner_id") != owner
        or archive_manifest.get("recovery_refs") != recovery_refs
        or not isinstance(recovery_refs, list)
        or not recovery_refs
    ):
        return None
    head_ref_valid = False
    for item in recovery_refs:
        if not isinstance(item, dict):
            return None
        ref = item.get("ref")
        target = item.get("target")
        role = item.get("role")
        if not isinstance(ref, str) or not isinstance(target, str):
            return None
        try:
            observed = checkouts._git_read(
                repo, ["rev-parse", "--verify", f"{ref}^{{commit}}"]
            ).stdout.strip()
        except Exception:
            return None
        if observed != target:
            return None
        if role == "head" and target == expected["head"]:
            head_ref_valid = True
    return archive if head_ref_valid else None


def _workspace_cleanup_finalize_missing(
    manifest: dict[str, Any], expected_plan_sha256: str, owner: str
) -> dict[str, Any] | None:
    intent = manifest.get("workspace_cleanup_intent")
    if not isinstance(intent, dict):
        return None
    if intent.get("source_plan_sha256") != expected_plan_sha256:
        return None
    archive = _verified_workspace_cleanup_archive(manifest, intent, owner)
    if archive is None:
        return None
    return {
        "archive_id": archive["archive_id"],
        "checkout_cleanup_plan_id": archive["cleanup_plan_id"],
        "applied_at_unix": archive["cleaned_at_unix"],
        "reconciled_after_missing_worktree": True,
    }


def _publish_workspace_cleanup_receipt(
    manifest: dict[str, Any],
    *,
    source_plan_sha256: str,
    archive_id: str,
    checkout_cleanup_plan_id: str,
    checkout_cleanup_plan_sha256: str | None,
    applied_at_unix: int,
    reconciled_after_missing_worktree: bool,
) -> dict[str, Any]:
    receipt = {
        "schema_version": 1,
        "workspace_id": manifest["workspace_id"],
        "source_plan_sha256": source_plan_sha256,
        "writer_worktree": manifest["writer_worktree"],
        "writer_branch": manifest["writer_branch"],
        "archive_id": archive_id,
        "checkout_cleanup_plan_id": checkout_cleanup_plan_id,
        "checkout_cleanup_plan_sha256": checkout_cleanup_plan_sha256,
        "applied_at_unix": applied_at_unix,
        "historical_evidence_preserved": True,
        "workspace_state_deleted": False,
        "reconciled_after_missing_worktree": reconciled_after_missing_worktree,
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    _atomic_json(
        _workspace_dir(str(manifest["workspace_id"])) / "cleanup-receipt.json",
        receipt,
    )
    manifest["workspace_cleanup_receipt"] = receipt
    manifest.pop("workspace_cleanup_intent", None)
    _append_workspace_event(
        manifest,
        "workspace_cleanup_completed",
        outcome="reconciled" if reconciled_after_missing_worktree else "complete",
        evidence={
            "receipt_sha256": receipt["receipt_sha256"],
            "archive_id": archive_id,
            "checkout_cleanup_plan_id": checkout_cleanup_plan_id,
            "historical_evidence_preserved": True,
        },
    )
    _write_manifest(manifest)
    return receipt


@mcp.tool(name="grabowski_agent_workspace_cleanup", annotations=MUTATING)
def grabowski_agent_workspace_cleanup(
    workspace_id: str,
    expected_plan_sha256: str,
    confirmation: str = "",
) -> dict[str, Any]:
    """Archive and remove one eligible closed writer checkout while preserving all workspace evidence."""
    operator._require_operator_mutation("git_cli")
    operator._require_operator_mutation("resource_lease")
    identifier = _required_string(workspace_id, "workspace_id", max_length=80)
    if WORKSPACE_ID_RE.fullmatch(identifier) is None:
        raise AgentWorkspaceError(f"invalid workspace_id: {identifier}")
    expected_hash = _required_string(
        expected_plan_sha256, "expected_plan_sha256", max_length=64
    )
    if SHA256_RE.fullmatch(expected_hash) is None:
        raise AgentWorkspaceError("expected_plan_sha256 must be a lowercase SHA-256")
    if confirmation != "archive-and-remove-worktree":
        raise AgentWorkspaceError(
            "confirmation must be exactly 'archive-and-remove-worktree'"
        )
    owner = _workspace_cleanup_owner(identifier)
    with _lock(identifier):
        manifest = _manifest(identifier)
        existing_receipt = manifest.get("workspace_cleanup_receipt")
        cleanup_integrity = _workspace_cleanup_integrity_status(
            manifest, existing_receipt
        )
        if cleanup_integrity["valid"]:
            if existing_receipt.get("source_plan_sha256") != expected_hash:
                raise AgentWorkspaceError("workspace was cleaned under a different plan")
            if Path(str(manifest["writer_worktree"])).expanduser().exists():
                return {
                    "workspace_id": identifier,
                    "state": "cleanup_receipt_drift",
                    "idempotent": False,
                    "cleanup_receipt": existing_receipt,
                    "blocker": "writer_worktree_reappeared_after_cleanup",
                }
            return {
                "workspace_id": identifier,
                "state": "already_cleaned",
                "idempotent": True,
                "cleanup_receipt": existing_receipt,
            }
        if existing_receipt is not None or cleanup_integrity["receipt_present"]:
            return {
                "workspace_id": identifier,
                "state": "cleanup_receipt_invalid",
                "idempotent": False,
                "integrity": cleanup_integrity,
            }
        reconciled = _workspace_cleanup_finalize_missing(manifest, expected_hash, owner)
        if reconciled is not None:
            receipt = _publish_workspace_cleanup_receipt(
                manifest,
                source_plan_sha256=expected_hash,
                archive_id=reconciled["archive_id"],
                checkout_cleanup_plan_id=reconciled["checkout_cleanup_plan_id"],
                checkout_cleanup_plan_sha256=None,
                applied_at_unix=int(reconciled["applied_at_unix"]),
                reconciled_after_missing_worktree=True,
            )
            return {
                "workspace_id": identifier,
                "state": "cleanup_reconciled",
                "idempotent": False,
                "cleanup_receipt": receipt,
            }
        plan = _workspace_cleanup_plan_data(manifest)
        if plan["plan_sha256"] != expected_hash:
            raise AgentWorkspaceError("workspace cleanup plan is stale; rerun cleanup_plan")
        if not plan["eligible"]:
            return {
                "workspace_id": identifier,
                "state": "cleanup_blocked",
                "plan": plan,
                "idempotent": False,
            }
        prior_intent = manifest.get("workspace_cleanup_intent")
        reusable_archive_id = None
        if (
            isinstance(prior_intent, dict)
            and prior_intent.get("state") in {"failed", "waiting_grace"}
            and prior_intent.get("writer_worktree") == plan["writer_worktree"]
            and prior_intent.get("writer_branch") == plan["checkout"]["branch"]
            and prior_intent.get("writer_head") == plan["checkout"]["head"]
            and isinstance(prior_intent.get("archive_id"), str)
        ):
            reusable_archive_id = prior_intent["archive_id"]
        intent = {
            "schema_version": 1,
            "intent_id": hashlib.sha256(
                f"{identifier}:{expected_hash}:{time.time_ns()}".encode("utf-8")
            ).hexdigest()[:24],
            "state": "started",
            "source_plan_sha256": expected_hash,
            "owner_id": owner,
            "writer_worktree": plan["writer_worktree"],
            "writer_branch": plan["checkout"]["branch"],
            "writer_head": plan["checkout"]["head"],
            "archive_id": reusable_archive_id,
            "started_at": _utc(),
        }
        manifest["workspace_cleanup_intent"] = intent
        _append_workspace_event(
            manifest,
            "workspace_cleanup_requested",
            outcome="started",
            evidence={
                "intent_id": intent["intent_id"],
                "source_plan_sha256": expected_hash,
                "historical_evidence_preserved": True,
            },
        )
        _write_manifest(manifest)
    archive_id = reusable_archive_id
    try:
        if archive_id is None:
            archive_result = checkouts.grabowski_checkout_archive(
                repo=plan["repository"],
                checkout_path=plan["writer_worktree"],
                owner_id=owner,
                purpose=f"agent workspace cleanup {identifier}",
                retention_until_unix=_now() + WORKSPACE_CLEANUP_RETENTION_SECONDS,
                expected_head=str(plan["checkout"]["head"]),
                expected_branch=str(plan["checkout"]["branch"]),
            )
            archive_id = str(archive_result["archive"]["archive_id"])
            with _lock(identifier):
                manifest = _manifest(identifier)
                current_intent = manifest.get("workspace_cleanup_intent")
                if not isinstance(current_intent, dict) or current_intent.get("intent_id") != intent["intent_id"]:
                    raise AgentWorkspaceActionError("workspace cleanup intent changed after archive")
                current_intent["archive_id"] = archive_id
                manifest["workspace_cleanup_intent"] = current_intent
                _write_manifest(manifest)
        archive_record = checkouts._load_archive(archive_id)
        archive_age_seconds = max(
            0, _now() - int(archive_record["created_at_unix"])
        )
        if archive_age_seconds < checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS:
            with _lock(identifier):
                manifest = _manifest(identifier)
                current_intent = manifest.get("workspace_cleanup_intent")
                if (
                    not isinstance(current_intent, dict)
                    or current_intent.get("intent_id") != intent["intent_id"]
                ):
                    raise AgentWorkspaceActionError(
                        "workspace cleanup intent changed during archive grace"
                    )
                current_intent.update(
                    {
                        "state": "waiting_grace",
                        "archive_id": archive_id,
                        "archive_created_at_unix": archive_record["created_at_unix"],
                        "archive_age_seconds": archive_age_seconds,
                        "archive_grace_seconds": (
                            checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS
                        ),
                        "updated_at": _utc(),
                    }
                )
                manifest["workspace_cleanup_intent"] = current_intent
                _append_workspace_event(
                    manifest,
                    "workspace_cleanup_archive_grace",
                    outcome="waiting",
                    evidence={
                        "intent_id": intent["intent_id"],
                        "archive_id": archive_id,
                        "archive_age_seconds": archive_age_seconds,
                        "archive_grace_seconds": (
                            checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS
                        ),
                    },
                )
                _write_manifest(manifest)
            return {
                "workspace_id": identifier,
                "state": "archived_waiting_grace",
                "idempotent": False,
                "archive_id": archive_id,
                "archive_age_seconds": archive_age_seconds,
                "archive_grace_seconds": checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS,
                "worktree_preserved": True,
            }
        dry_run = checkouts.grabowski_checkout_cleanup(
            repo=plan["repository"],
            checkout_path=plan["writer_worktree"],
            owner_id=owner,
            dry_run=True,
            archive_id=archive_id,
            expected_head=str(plan["checkout"]["head"]),
            expected_branch=str(plan["checkout"]["branch"]),
        )
        cleanup_plan = dry_run["plan"]
        if not cleanup_plan.get("safe_to_apply"):
            raise AgentWorkspaceActionError("checkout cleanup dry run acquired new blockers")
        dry_run_record = dry_run["dry_run_record"]
        applied = checkouts.grabowski_checkout_cleanup(
            repo=plan["repository"],
            checkout_path=plan["writer_worktree"],
            owner_id=owner,
            dry_run=False,
            archive_id=archive_id,
            plan_id=str(dry_run_record["plan_id"]),
            expected_plan_sha256=str(cleanup_plan["plan_sha256"]),
            confirmation="remove-linked-checkout",
        )
    except Exception as exc:
        with _lock(identifier):
            manifest = _manifest(identifier)
            current_intent = manifest.get("workspace_cleanup_intent")
            if isinstance(current_intent, dict) and current_intent.get("intent_id") == intent["intent_id"]:
                current_intent.update(
                    {
                        "state": "failed",
                        "archive_id": archive_id,
                        "failed_at": _utc(),
                        "error": _error_summary(exc),
                    }
                )
                manifest["workspace_cleanup_intent"] = current_intent
                _append_workspace_event(
                    manifest,
                    "workspace_cleanup_failed",
                    outcome="failed",
                    evidence={
                        "intent_id": intent["intent_id"],
                        "archive_id": archive_id,
                        "error": _error_summary(exc),
                    },
                )
                _write_manifest(manifest)
        raise
    with _lock(identifier):
        manifest = _manifest(identifier)
        current_intent = manifest.get("workspace_cleanup_intent")
        if not isinstance(current_intent, dict) or current_intent.get("intent_id") != intent["intent_id"]:
            raise AgentWorkspaceActionError("workspace cleanup intent changed before finalization")
        receipt = _publish_workspace_cleanup_receipt(
            manifest,
            source_plan_sha256=expected_hash,
            archive_id=str(archive_id),
            checkout_cleanup_plan_id=str(dry_run_record["plan_id"]),
            checkout_cleanup_plan_sha256=str(cleanup_plan["plan_sha256"]),
            applied_at_unix=int(applied["applied_at_unix"]),
            reconciled_after_missing_worktree=False,
        )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "agent-workspace-cleanup",
            "workspace_id": identifier,
            "source_plan_sha256": expected_hash,
            "archive_id": archive_id,
            "checkout_cleanup_plan_id": dry_run_record["plan_id"],
            "historical_evidence_preserved": True,
            "workspace_state_deleted": False,
        }
    )
    return {
        "workspace_id": identifier,
        "state": "cleaned",
        "idempotent": False,
        "cleanup_receipt": receipt,
        "archive": archive_record,
        "checkout_cleanup": applied,
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

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from contextvars import ContextVar
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from typing import Annotated, Any, Callable, Iterator

try:
    from mcp.server.fastmcp import Context
except ImportError:
    Context = Any
from mcp.types import ToolAnnotations
from pydantic import Field

import grabowski_client_snapshot as client_snapshot
import grabowski_connector_contract as connector_contract
import grabowski_mcp as base
import grabowski_midcutover_resume as midcutover
import grabowski_deployment_observer as deployment_observer
import grabowski_operator_core as operator
import grabowski_privileged as privileged
import grabowski_read_surface as read_surface
import grabowski_serving_process as serving_process


mcp = operator.mcp

DEPLOY_MUTATING = ToolAnnotations(
    title="Schedule verified Grabowski runtime deployment",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
ExpectedHead = Annotated[
    str,
    Field(
        min_length=40,
        max_length=64,
        pattern=OBJECT_ID_RE.pattern,
    ),
]
DelaySeconds = Annotated[int, Field(ge=5, le=60)]
SourceRepository = Annotated[str, Field(min_length=1, max_length=4096)]
SourceLeaseOwner = Annotated[str, Field(min_length=1, max_length=128, pattern=r"[A-Za-z0-9._:@-]{1,128}")]
SOURCE_KINDS = frozenset({"canonical-main", "detached-worktree"})
CANONICAL_REPOSITORY = Path.home() / "repos/grabowski"
CANONICAL_OPERATOR_MODULE = "grabowski_operator"
PUBLIC_GITHUB_REPOSITORY_URL = "https://github.com/heimgewebe/grabowski.git"
PUBLIC_GITHUB_MAIN_REF = "refs/heads/main"
PUBLIC_GITHUB_LOOKUP_TIMEOUT_SECONDS = 15
PUBLIC_GITHUB_LOOKUP_MAX_BYTES = 4096
REPOGROUND_MANAGED_SOURCE_ROOT = Path.home() / "repos" / ".repoground-sources"
RUNNER_RELATIVE_PATH = Path("tools/run_scheduled_deploy.py")
DEPLOY_SCHEDULE_LOCK = Path.home() / ".local/state/grabowski/runtime-deploy-schedule.lock"
DEPLOY_JOB_PREFIX = operator.JOB_PREFIX
DEPLOY_JOB_ROOT = operator.JOBS_DIR
DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS = 10.0
DEPLOY_SCHEDULE_LOCK_POLL_SECONDS = 0.05
AUDIT_LOCK_TIMEOUT_ERROR = "Audit lock acquisition timed out"
MAX_JOB_SCAN_ENTRIES = 2_000
MAX_DEPLOY_INDEX_ENTRIES = 512
DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
REUSABLE_JOB_STATUSES = frozenset({"running"})
TERMINAL_JOB_STATUSES = frozenset({"completed", "succeeded", "failed", "launch_failed"})
BLUE_GREEN_RECEIPT_KIND = "grabowski_blue_green_deployment_receipt"
BLUE_GREEN_RECEIPT_SCHEMA_VERSION = 1
BLUE_GREEN_RECEIPT_ROOT = (
    Path.home() / ".local/state/grabowski/blue-green-deployment-receipts"
)
MAX_BLUE_GREEN_RECEIPT_BYTES = 256 * 1024
SIDECAR_ROUTER_SOURCE_RELATIVE = Path("tools/agent-route")
SIDECAR_SCHEDULER_SOURCE_RELATIVE = Path("tools/coding_agent_probe_scheduler.py")
SIDECAR_ROUTER_TARGET = Path.home() / "bin/agent-route"
SIDECAR_SCHEDULER_TARGET = (
    Path.home() / ".local/libexec/grabowski/coding_agent_probe_scheduler.py"
)
SIDECAR_ROUTER_PIN = (
    Path.home() / ".config/grabowski/coding-agent-probe-scheduler-router.sha256"
)
SIDECAR_RUNTIME_PYTHON = Path.home() / ".local/share/grabowski-mcp/.venv/bin/python"
MAX_SIDECAR_SOURCE_BYTES = 1024 * 1024
MAX_SIDECAR_READBACK_BYTES = 256 * 1024
_RUNTIME_PROOF_CACHE: ContextVar[dict[tuple[str, str, str], bool] | None] = ContextVar(
    "grabowski_runtime_proof_cache", default=None
)


class BlueGreenCutoverError(RuntimeError):
    """Raised when a blue-green cutover phase fails with a classified recovery path."""

    def __init__(
        self,
        message: str,
        *,
        phase: str,
        failure_class: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.phase = phase
        self.failure_class = failure_class
        self.details = details or {}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


@dataclass
class BlueGreenHooks:
    """Injectable runtime effects for the blue-green cutover protocol.

    Production wiring may start a parallel green process, switch the connector
    pointer and retire blue. Tests supply deterministic fakes. None of the hooks
    receive secret material.
    """

    start_green: Callable[[], dict[str, Any]]
    verify_green: Callable[[], dict[str, Any]]
    switch_connector: Callable[[], dict[str, Any]]
    rebind_snapshot: Callable[[str, int], dict[str, Any]]
    close_blue_mutations: Callable[[], dict[str, Any]]
    terminalize_blue_effects: Callable[[], dict[str, Any]]
    retire_blue: Callable[[], dict[str, Any]]
    rollback_green: Callable[[], dict[str, Any]]
    authoritative_readback: Callable[[], dict[str, Any]] | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)


def build_blue_green_plan(
    *,
    expected_head: str,
    blue_release_id: str,
    green_release_id: str,
    source_identity_sha256: str,
    expected_names_sha256: str,
    expected_agent_instructions_sha256: str,
    cutover_id: str | None = None,
    cutover_generation: int = 1,
) -> dict[str, Any]:
    """Build one hash-bound blue-green cutover plan without executing it."""
    if not isinstance(expected_head, str) or len(expected_head) not in {40, 64}:
        raise ValueError("expected_head must be a Git object id")
    for label, value in (
        ("blue_release_id", blue_release_id),
        ("green_release_id", green_release_id),
    ):
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise ValueError(f"{label} is invalid")
    for label, value in (
        ("source_identity_sha256", source_identity_sha256),
        ("expected_names_sha256", expected_names_sha256),
        ("expected_agent_instructions_sha256", expected_agent_instructions_sha256),
    ):
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(f"{label} must be a lowercase SHA-256")
        try:
            int(value, 16)
        except ValueError as exc:
            raise ValueError(f"{label} must be a lowercase SHA-256") from exc
        if value != value.lower():
            raise ValueError(f"{label} must be a lowercase SHA-256")
    if (
        isinstance(cutover_generation, bool)
        or not isinstance(cutover_generation, int)
        or cutover_generation < 1
    ):
        raise ValueError("cutover_generation must be a positive integer")
    cutover = cutover_id or f"bgc-{secrets.token_hex(8)}"
    if not isinstance(cutover, str) or not cutover.strip() or len(cutover) > 128:
        raise ValueError("cutover_id is invalid")
    material = {
        "schema_version": 1,
        "kind": "grabowski_blue_green_cutover_plan",
        "cutover_id": cutover.strip(),
        "cutover_generation": cutover_generation,
        "expected_head": expected_head,
        "blue_release_id": blue_release_id,
        "green_release_id": green_release_id,
        "source_identity_sha256": source_identity_sha256,
        "expected_names_sha256": expected_names_sha256,
        "expected_agent_instructions_sha256": expected_agent_instructions_sha256,
        "phases": list(deployment_observer.CUTOVER_PHASES),
        "drain_policy": {
            "wait_for_long_lived_reads": False,
            "terminalize_effect_bearing_only": True,
            "close_blue_mutations_before_retirement": True,
            "snapshot_rebind_is_part_of_cutover": True,
        },
    }
    return {**material, "plan_sha256": _sha256_json(material)}


def _record_observation(
    hooks: BlueGreenHooks,
    plan: dict[str, Any],
    phase: str,
    *,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    observation = deployment_observer.build_cutover_observation(
        cutover_id=plan["cutover_id"],
        phase=phase,
        expected_head=plan["expected_head"],
        blue_release_id=plan["blue_release_id"],
        green_release_id=plan["green_release_id"],
        source_identity_sha256=plan["source_identity_sha256"],
        details=details,
    )
    hooks.observations.append(observation)
    return observation


def build_deployment_receipt(
    *,
    plan: dict[str, Any],
    phase: str,
    green_readiness: dict[str, Any] | None,
    snapshot_rebind: dict[str, Any] | None,
    effect_terminalization: dict[str, Any] | None,
    selector_switch: dict[str, Any] | None,
    retirement: dict[str, Any] | None,
    authoritative_readback: dict[str, Any] | None,
    observations: list[dict[str, Any]],
    outcome: str,
    recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one deployment receipt binding runtime, names, schemas, sentinel, snapshot and Bedienvertrag."""
    if outcome not in {
        "completed",
        "rolled_back",
        "outcome_unknown",
        "failed_pre_cutover",
    }:
        raise ValueError(f"unsupported blue-green outcome: {outcome!r}")
    material = {
        "schema_version": BLUE_GREEN_RECEIPT_SCHEMA_VERSION,
        "kind": BLUE_GREEN_RECEIPT_KIND,
        "cutover_id": plan["cutover_id"],
        "cutover_generation": plan["cutover_generation"],
        "expected_head": plan["expected_head"],
        "blue_release_id": plan["blue_release_id"],
        "green_release_id": plan["green_release_id"],
        "source_identity_sha256": plan["source_identity_sha256"],
        "names_sha256": plan["expected_names_sha256"],
        "agent_instructions_sha256": plan["expected_agent_instructions_sha256"],
        "schema_sentinels": sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS),
        "phase": phase,
        "outcome": outcome,
        "failure_class": deployment_observer.cutover_failure_class(phase),
        "green_readiness": green_readiness,
        "snapshot_rebind": (
            {
                "receipt_sha256": snapshot_rebind.get("receipt_sha256"),
                "client_declaration_sha256": snapshot_rebind.get(
                    "client_declaration_sha256"
                ),
                "source_receipt_sha256": snapshot_rebind.get(
                    "source_receipt_sha256"
                ),
                "cutover_binding": snapshot_rebind.get("cutover_binding"),
                "cutover_transition": snapshot_rebind.get(
                    "cutover_transition"
                ),
                "verified": snapshot_rebind.get("verified"),
            }
            if isinstance(snapshot_rebind, dict)
            else None
        ),
        "effect_terminalization": (
            {
                "terminalized_count": effect_terminalization.get("terminalized_count"),
                "initial_blocking_tool_calls": effect_terminalization.get(
                    "initial_blocking_tool_calls"
                ),
                "blocking_tool_calls": effect_terminalization.get(
                    "blocking_tool_calls"
                ),
                "remaining_read_count": effect_terminalization.get(
                    "remaining_read_count"
                ),
                "read_only_active_tool_calls": effect_terminalization.get(
                    "read_only_active_tool_calls"
                ),
                "operator_observation_sha256": effect_terminalization.get(
                    "operator_observation_sha256"
                ),
            }
            if isinstance(effect_terminalization, dict)
            else None
        ),
        "selector_switch": selector_switch,
        "retirement": retirement,
        "final_routing": (
            retirement.get("final_routing")
            if isinstance(retirement, dict)
            else None
        ),
        "authoritative_readback": authoritative_readback,
        "observations": [
            {
                "phase": item.get("phase"),
                "observation_sha256": item.get("observation_sha256"),
                "failure_class": item.get("failure_class"),
            }
            for item in observations
        ],
        "recovery": recovery,
        "preserves": [
            "manifest_integrity",
            "provenance_integrity",
            "audit_integrity",
        ],
        "does_not_establish": [
            "connector platform identity",
            "that every remote client refreshed tools/list",
            "application success of terminalized mutations",
        ],
    }
    return {**material, "receipt_sha256": _sha256_json(material)}


def persist_blue_green_receipt(
    receipt: dict[str, Any],
    *,
    root: Path = BLUE_GREEN_RECEIPT_ROOT,
) -> dict[str, str]:
    """Create one immutable private receipt and verify exact readback."""
    if (
        not isinstance(receipt, dict)
        or receipt.get("kind") != BLUE_GREEN_RECEIPT_KIND
        or receipt.get("schema_version") != BLUE_GREEN_RECEIPT_SCHEMA_VERSION
    ):
        raise ValueError("blue-green deployment receipt is invalid")
    declared = receipt.get("receipt_sha256")
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    if (
        not isinstance(declared, str)
        or re.fullmatch(r"[0-9a-f]{64}", declared) is None
        or _sha256_json(unsigned) != declared
    ):
        raise ValueError("blue-green deployment receipt hash mismatch")
    cutover_id = receipt.get("cutover_id")
    if (
        not isinstance(cutover_id, str)
        or re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", cutover_id) is None
    ):
        raise ValueError("blue-green cutover id is invalid")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = root.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or root.resolve(strict=True) != root
    ):
        raise PermissionError(
            "blue-green receipt directory must be private and owner-controlled"
        )
    encoded = _canonical_json_bytes(receipt) + b"\n"
    if len(encoded) > MAX_BLUE_GREEN_RECEIPT_BYTES:
        raise ValueError("blue-green deployment receipt exceeds size bound")
    path = root / f"{cutover_id}.json"
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("blue-green receipt write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    observed = json.loads(path.read_text(encoding="utf-8"))
    if observed != receipt:
        raise RuntimeError("blue-green deployment receipt readback mismatch")
    return {"path": str(path), "receipt_sha256": declared}


def execute_blue_green_cutover(
    plan: dict[str, Any],
    hooks: BlueGreenHooks,
) -> dict[str, Any]:
    """Execute the blue-green cutover protocol with classified rollback/recovery.

    Pre-cutover failure rolls green back and leaves blue authoritative.
    After the atomic connector switch, failures become ``outcome_unknown`` and
    require recovery readback rather than automatic pointer reversal.
    """
    if not isinstance(plan, dict) or plan.get("kind") != "grabowski_blue_green_cutover_plan":
        raise ValueError("blue-green cutover plan is invalid")
    declared = plan.get("plan_sha256")
    unsigned = dict(plan)
    unsigned.pop("plan_sha256", None)
    if declared != _sha256_json(unsigned):
        raise ValueError("blue-green cutover plan hash mismatch")

    phase = "prepare"
    green_readiness: dict[str, Any] | None = None
    snapshot_rebind: dict[str, Any] | None = None
    effect_terminalization: dict[str, Any] | None = None
    selector_switch: dict[str, Any] | None = None
    retirement: dict[str, Any] | None = None
    authoritative_readback: dict[str, Any] | None = None
    connector_switched = False
    green_started = False

    def fail(message: str, *, details: dict[str, Any] | None = None) -> None:
        raise BlueGreenCutoverError(
            message,
            phase=phase,
            failure_class=deployment_observer.cutover_failure_class(phase),
            details=details,
        )

    try:
        _record_observation(hooks, plan, phase)
        phase = "start_green"
        start_result = hooks.start_green()
        green_started = True
        _record_observation(hooks, plan, phase, details={"start": start_result})

        phase = "verify_green"
        green_readiness = hooks.verify_green()
        if not isinstance(green_readiness, dict) or green_readiness.get("ready") is not True:
            fail(
                "green runtime failed readiness against manifest/tools/schemas/sentinel/Bedienvertrag",
                details={"green_readiness": green_readiness},
            )
        readiness_release = green_readiness.get("release_id") or green_readiness.get(
            "expected_release_id"
        )
        if readiness_release not in {None, plan["green_release_id"]}:
            fail(
                "green readiness release does not match the cutover plan",
                details={"green_readiness": green_readiness},
            )
        _record_observation(
            hooks, plan, phase, details={"ready": True, "green_readiness_ready": True}
        )

        phase = "pre_cutover_ready"
        close_result = hooks.close_blue_mutations()
        effect_terminalization = hooks.terminalize_blue_effects()
        if (
            not isinstance(effect_terminalization, dict)
            or "terminalized_count" not in effect_terminalization
        ):
            fail(
                "effect-bearing drain returned an invalid operator receipt",
                details={"effect_terminalization": effect_terminalization},
            )
        _record_observation(
            hooks,
            plan,
            phase,
            details={
                "close_blue": close_result,
                "terminalized_count": effect_terminalization.get(
                    "terminalized_count"
                ),
                "remaining_read_count": effect_terminalization.get(
                    "remaining_read_count"
                ),
            },
        )

        phase = "cutover"
        selector_switch = hooks.switch_connector()
        connector_switched = True
        snapshot_rebind = hooks.rebind_snapshot(
            plan["cutover_id"], plan["cutover_generation"]
        )
        if (
            not isinstance(snapshot_rebind, dict)
            or snapshot_rebind.get("verified") is not True
            or not isinstance(snapshot_rebind.get("receipt_sha256"), str)
            or not isinstance(snapshot_rebind.get("source_receipt_sha256"), str)
            or len(set(snapshot_rebind["receipt_sha256"])) == 1
            or len(set(snapshot_rebind["source_receipt_sha256"])) == 1
        ):
            fail(
                "cutover snapshot rebind lacks authentic receipt evidence",
                details={"snapshot_rebind": snapshot_rebind},
            )
        _record_observation(
            hooks,
            plan,
            phase,
            details={
                "switch": selector_switch,
                "snapshot_receipt_sha256": (
                    snapshot_rebind.get("receipt_sha256")
                    if isinstance(snapshot_rebind, dict)
                    else None
                ),
            },
        )

        phase = "post_cutover"
        _record_observation(
            hooks,
            plan,
            phase,
            details={"connector_switched": True},
        )

        phase = "terminalize_effects"
        _record_observation(
            hooks,
            plan,
            phase,
            details={
                "terminalized_count": effect_terminalization.get("terminalized_count"),
                "remaining_read_count": effect_terminalization.get(
                    "remaining_read_count"
                ),
            },
        )

        phase = "retire_blue"
        retirement = hooks.retire_blue()
        authoritative_readback = (
            hooks.authoritative_readback()
            if hooks.authoritative_readback is not None
            else retirement.get("authoritative_readback")
            if isinstance(retirement, dict)
            else None
        )
        if (
            not isinstance(authoritative_readback, dict)
            or authoritative_readback.get("authoritative") is not True
        ):
            fail(
                "final routing lacks authoritative ingress readback",
                details={"retirement": retirement},
            )
        _record_observation(hooks, plan, phase, details={"retire": retirement})

        phase = "completed"
        _record_observation(hooks, plan, phase)
        return build_deployment_receipt(
            plan=plan,
            phase=phase,
            green_readiness=green_readiness,
            snapshot_rebind=snapshot_rebind,
            effect_terminalization=effect_terminalization,
            selector_switch=selector_switch,
            retirement=retirement,
            authoritative_readback=authoritative_readback,
            observations=hooks.observations,
            outcome="completed",
        )
    except BlueGreenCutoverError as exc:
        failure_class = exc.failure_class
        if failure_class == "pre_cutover_rollback":
            rollback_details: dict[str, Any] = {"error": str(exc), "details": exc.details}
            if green_started:
                try:
                    rollback_details["rollback"] = hooks.rollback_green()
                except Exception as rollback_error:  # noqa: BLE001 - classified recovery
                    rollback_details["rollback_error"] = {
                        "type": type(rollback_error).__name__,
                        "message": str(rollback_error),
                    }
                    phase = "outcome_unknown"
                    _record_observation(hooks, plan, phase, details=rollback_details)
                    return build_deployment_receipt(
                        plan=plan,
                        phase=phase,
                        green_readiness=green_readiness,
                        snapshot_rebind=snapshot_rebind,
                        effect_terminalization=effect_terminalization,
                        selector_switch=selector_switch,
                        retirement=retirement,
                        authoritative_readback=authoritative_readback,
                        observations=hooks.observations,
                        outcome="outcome_unknown",
                        recovery={
                            "action": "inspect_green_and_blue_runtimes",
                            "reason": "pre-cutover rollback itself failed",
                        },
                    )
            phase = "rolled_back"
            _record_observation(hooks, plan, phase, details=rollback_details)
            return build_deployment_receipt(
                plan=plan,
                phase=phase,
                green_readiness=green_readiness,
                snapshot_rebind=snapshot_rebind,
                effect_terminalization=effect_terminalization,
                selector_switch=selector_switch,
                retirement=retirement,
                authoritative_readback=authoritative_readback,
                observations=hooks.observations,
                outcome="rolled_back",
                recovery={
                    "action": "retry_from_clean_blue",
                    "reason": "failure occurred before connector cutover",
                },
            )
        if hooks.authoritative_readback is not None:
            try:
                authoritative_readback = hooks.authoritative_readback()
            except Exception as readback_error:  # noqa: BLE001
                authoritative_readback = {
                    "authoritative": False,
                    "error_type": type(readback_error).__name__,
                }
        phase = "outcome_unknown"
        _record_observation(
            hooks,
            plan,
            phase,
            details={
                "error": str(exc),
                "details": exc.details,
                "connector_switched": connector_switched,
            },
        )
        return build_deployment_receipt(
            plan=plan,
            phase=phase,
            green_readiness=green_readiness,
            snapshot_rebind=snapshot_rebind,
            effect_terminalization=effect_terminalization,
            selector_switch=selector_switch,
            retirement=retirement,
            authoritative_readback=authoritative_readback,
            observations=hooks.observations,
            outcome="outcome_unknown",
            recovery={
                "action": "readback_active_runtime_and_recover",
                "reason": "failure occurred after connector cutover",
                "connector_switched": connector_switched,
            },
        )
    except Exception as exc:  # noqa: BLE001 - map unexpected failures into recovery classes
        failure_class = deployment_observer.cutover_failure_class(phase)
        if failure_class == "pre_cutover_rollback" and not connector_switched:
            rollback_details = {
                "error": str(exc),
                "error_type": type(exc).__name__,
            }
            if green_started:
                try:
                    rollback_details["rollback"] = hooks.rollback_green()
                except Exception as rollback_error:  # noqa: BLE001
                    rollback_details["rollback_error"] = {
                        "type": type(rollback_error).__name__,
                        "message": str(rollback_error),
                    }
                    phase = "outcome_unknown"
                    _record_observation(hooks, plan, phase, details=rollback_details)
                    return build_deployment_receipt(
                        plan=plan,
                        phase=phase,
                        green_readiness=green_readiness,
                        snapshot_rebind=snapshot_rebind,
                        effect_terminalization=effect_terminalization,
                        selector_switch=selector_switch,
                        retirement=retirement,
                        authoritative_readback=authoritative_readback,
                        observations=hooks.observations,
                        outcome="outcome_unknown",
                        recovery={
                            "action": "inspect_green_and_blue_runtimes",
                            "reason": "pre-cutover rollback itself failed",
                        },
                    )
            phase = "rolled_back"
            _record_observation(hooks, plan, phase, details=rollback_details)
            return build_deployment_receipt(
                plan=plan,
                phase=phase,
                green_readiness=green_readiness,
                snapshot_rebind=snapshot_rebind,
                effect_terminalization=effect_terminalization,
                selector_switch=selector_switch,
                retirement=retirement,
                authoritative_readback=authoritative_readback,
                observations=hooks.observations,
                outcome="rolled_back",
                recovery={
                    "action": "retry_from_clean_blue",
                    "reason": "failure occurred before connector cutover",
                },
            )
        if hooks.authoritative_readback is not None:
            try:
                authoritative_readback = hooks.authoritative_readback()
            except Exception as readback_error:  # noqa: BLE001
                authoritative_readback = {
                    "authoritative": False,
                    "error_type": type(readback_error).__name__,
                }
        phase = "outcome_unknown"
        _record_observation(
            hooks,
            plan,
            phase,
            details={
                "error": str(exc),
                "error_type": type(exc).__name__,
                "connector_switched": connector_switched,
            },
        )
        return build_deployment_receipt(
            plan=plan,
            phase=phase,
            green_readiness=green_readiness,
            snapshot_rebind=snapshot_rebind,
            effect_terminalization=effect_terminalization,
            selector_switch=selector_switch,
            retirement=retirement,
            authoritative_readback=authoritative_readback,
            observations=hooks.observations,
            outcome="outcome_unknown",
            recovery={
                "action": "readback_active_runtime_and_recover",
                "reason": "unexpected failure after or during cutover",
                "connector_switched": connector_switched,
            },
        )


def default_local_blue_green_hooks(
    *,
    green_readiness: dict[str, Any],
    snapshot_parameters: dict[str, Any] | None = None,
) -> BlueGreenHooks:
    """Build explicit test-only hooks for deterministic protocol unit tests.

    Production scheduling never calls this helper.  A real snapshot parameter
    set is mandatory so the helper cannot manufacture receipt hashes.
    """

    def start_green() -> dict[str, Any]:
        serving_process.set_role(serving_process.ROLE_STANDBY)
        return {"started": True, "role": serving_process.ROLE_STANDBY}

    def verify_green() -> dict[str, Any]:
        return green_readiness

    def switch_connector() -> dict[str, Any]:
        return {"connector": "green", "switched": True}

    def rebind_snapshot(cutover_id: str, cutover_generation: int) -> dict[str, Any]:
        if snapshot_parameters is None:
            raise client_snapshot.ClientSnapshotError(
                "test blue-green hooks require explicit snapshot parameters"
            )
        return client_snapshot.rebind_for_cutover(
            snapshot_parameters,
            cutover_id=cutover_id,
            cutover_generation=cutover_generation,
        )

    def close_blue_mutations() -> dict[str, Any]:
        return serving_process.close_for_mutations(reason="blue-green-cutover")

    def terminalize_blue_effects() -> dict[str, Any]:
        return serving_process.terminalize_effect_bearing_calls()

    def retire_blue() -> dict[str, Any]:
        return {
            "retired": True,
            "remaining_read_count": len(serving_process.active_read_calls()),
            "final_routing": {"selected_slot": "canonical", "upstream_port": 18181},
            "authoritative_readback": {
                "authoritative": True,
                "selected_slot": "canonical",
                "upstream_port": 18181,
            },
        }

    def authoritative_readback() -> dict[str, Any]:
        return {
            "authoritative": True,
            "selected_slot": "canonical",
            "upstream_port": 18181,
        }

    def rollback_green() -> dict[str, Any]:
        serving_process.set_role(serving_process.ROLE_ACTIVE)
        return {"rolled_back": True, "role": serving_process.ROLE_ACTIVE}

    return BlueGreenHooks(
        start_green=start_green,
        verify_green=verify_green,
        switch_connector=switch_connector,
        rebind_snapshot=rebind_snapshot,
        close_blue_mutations=close_blue_mutations,
        terminalize_blue_effects=terminalize_blue_effects,
        retire_blue=retire_blue,
        rollback_green=rollback_green,
        authoritative_readback=authoritative_readback,
    )



def _git_result(repository: Path, *arguments: str) -> dict[str, Any]:
    return read_surface._run_read(
        read_surface._git_command(repository, *arguments),
        cwd=repository,
        timeout_seconds=30,
        max_output_bytes=65_536,
    )


def _required_stdout(result: dict[str, Any], label: str) -> str:
    if result["returncode"] != 0 or result["timed_out"]:
        message = result["stderr"].strip() or result["stdout"].strip()
        raise RuntimeError(message or f"{label} failed")
    if result["stdout_truncated"] or result["stderr_truncated"]:
        raise RuntimeError(f"{label} output exceeded the preflight bound")
    return result["stdout"].strip()


def _deploy_command(
    repository: Path,
    runner: Path,
    expected_head: str,
    delay_seconds: int,
    *,
    canonical_repository: Path | None = None,
    source_kind: str = "canonical-main",
    source_identity_sha256: str = "0" * 64,
) -> list[str]:
    canonical = canonical_repository or CANONICAL_REPOSITORY
    return [
        "/usr/bin/python3",
        str(runner),
        "--repo",
        str(repository),
        "--canonical-repo",
        str(canonical),
        "--source-kind",
        source_kind,
        "--source-identity-sha256",
        source_identity_sha256,
        "--expected-head",
        expected_head,
        "--delay-seconds",
        str(delay_seconds),
    ]


MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH = Path("tools/run_midcutover_resume.py")
MIDCUTOVER_RESUME_TIMEOUT_SECONDS = 40
_CUTOVER_ID_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _midcutover_resume_command(
    repository: Path,
    runner: Path,
    expected_head: str,
    cutover_id: str,
    resume_binding_sha256: str,
    *,
    timeout_seconds: int = MIDCUTOVER_RESUME_TIMEOUT_SECONDS,
) -> list[str]:
    """Build the exact argv of a receipt-bound mid-cutover resume.

    Every argument names evidence that already exists.  There is no target to
    choose, no source kind and no delay: the resume continues one specific
    cutover or it does nothing at all.
    """
    if OBJECT_ID_RE.fullmatch(expected_head) is None:
        raise ValueError("expected_head must be a lowercase Git object id")
    if _CUTOVER_ID_RE.fullmatch(cutover_id or "") is None:
        raise ValueError("cutover_id is invalid")
    if _SHA256_RE.fullmatch(resume_binding_sha256 or "") is None:
        raise ValueError("resume_binding_sha256 must be a lowercase SHA-256")
    if not 5 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be between 5 and 120")
    return [
        "/usr/bin/python3",
        str(runner),
        "--repo",
        str(repository),
        "--expected-head",
        expected_head,
        "--cutover-id",
        cutover_id,
        "--resume-binding-sha256",
        resume_binding_sha256,
        "--timeout-seconds",
        str(timeout_seconds),
    ]


def _midcutover_resume_command_fields(command: Any) -> dict[str, str] | None:
    """Recognise a resume argv; anything unexpected is not one."""
    if (
        not isinstance(command, list)
        or len(command) != 12
        or not all(isinstance(item, str) for item in command)
        or command[0] != "/usr/bin/python3"
    ):
        return None
    allowed = {
        "--repo",
        "--expected-head",
        "--cutover-id",
        "--resume-binding-sha256",
        "--timeout-seconds",
    }
    values: dict[str, str] = {}
    for index in range(2, len(command), 2):
        option = command[index]
        if option not in allowed or option in values:
            return None
        values[option] = command[index + 1]
    if (
        set(values) != allowed
        or OBJECT_ID_RE.fullmatch(values["--expected-head"]) is None
        or _CUTOVER_ID_RE.fullmatch(values["--cutover-id"]) is None
        or _SHA256_RE.fullmatch(values["--resume-binding-sha256"]) is None
        or not Path(values["--repo"]).is_absolute()
    ):
        return None
    try:
        timeout_seconds = int(values["--timeout-seconds"])
    except ValueError:
        return None
    if not 5 <= timeout_seconds <= 120:
        return None
    return {
        "python": command[0],
        "runner": command[1],
        "repository": values["--repo"],
        "expected_head": values["--expected-head"],
        "cutover_id": values["--cutover-id"],
        "resume_binding_sha256": values["--resume-binding-sha256"],
        "timeout_seconds": str(timeout_seconds),
    }


def _deploy_command_sha256(command: list[str]) -> str:
    return operator._argv_hash(command)


def _deploy_command_fields(command: Any) -> dict[str, str] | None:
    if (
        not isinstance(command, list)
        or len(command) != 14
        or not all(isinstance(item, str) for item in command)
        or command[0] != "/usr/bin/python3"
    ):
        return None
    values: dict[str, str] = {}
    allowed = {
        "--repo",
        "--canonical-repo",
        "--source-kind",
        "--source-identity-sha256",
        "--expected-head",
        "--delay-seconds",
    }
    for index in range(2, len(command), 2):
        option = command[index]
        if option not in allowed or option in values:
            return None
        values[option] = command[index + 1]
    if (
        set(values) != allowed
        or not OBJECT_ID_RE.fullmatch(values["--expected-head"])
        or values["--source-kind"] not in SOURCE_KINDS
        or re.fullmatch(r"[0-9a-f]{64}", values["--source-identity-sha256"]) is None
    ):
        return None
    for name in ("--repo", "--canonical-repo"):
        if not Path(values[name]).is_absolute():
            return None
    try:
        delay_seconds = int(values["--delay-seconds"])
    except ValueError:
        return None
    if not 5 <= delay_seconds <= 60:
        return None
    return {
        "python": command[0],
        "runner": command[1],
        "repository": values["--repo"],
        "canonical_repository": values["--canonical-repo"],
        "source_kind": values["--source-kind"],
        "source_identity_sha256": values["--source-identity-sha256"],
        "expected_head": values["--expected-head"],
        "delay_seconds": str(delay_seconds),
    }


def _deploy_identity(command: Any) -> tuple[str, ...] | None:
    fields = _deploy_command_fields(command)
    if fields is None:
        return None
    return (
        fields["python"],
        fields["runner"],
        fields["repository"],
        fields["canonical_repository"],
        fields["source_kind"],
        fields["source_identity_sha256"],
        fields["expected_head"],
    )


def _append_deploy_audit(record: dict[str, Any]) -> None:
    """Persist deploy audit evidence despite transient audit-lock contention.

    The audit coordination lock is process-bound. Its exact timeout is raised
    before the append critical section is entered, so retrying only the audit
    append cannot duplicate a deployment, Rootbroker refresh, or job start.
    Other audit failures remain fail-closed.
    """
    while True:
        try:
            base._append_audit(record)
            return
        except RuntimeError as exc:
            if str(exc) != AUDIT_LOCK_TIMEOUT_ERROR:
                raise


@contextmanager
def _deploy_schedule_lock() -> Iterator[None]:
    parent = DEPLOY_SCHEDULE_LOCK.parent
    if parent.is_symlink():
        raise PermissionError(f"runtime deploy lock directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if DEPLOY_SCHEDULE_LOCK.is_symlink():
        raise PermissionError(f"runtime deploy lock may not be a symlink: {DEPLOY_SCHEDULE_LOCK}")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(DEPLOY_SCHEDULE_LOCK, flags, 0o600)
    locked = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != os.getuid():
            raise PermissionError("runtime deploy lock must be one owner-controlled regular file")
        deadline = time.monotonic() + DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("runtime deploy schedule lock acquisition timed out") from exc
                time.sleep(DEPLOY_SCHEDULE_LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _durable_job_unit(name: str) -> bool:
    return re.fullmatch(rf"{re.escape(DEPLOY_JOB_PREFIX)}[0-9a-f]{{12}}", name) is not None


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short write while publishing runtime deploy index")
        offset += written


def _deploy_index_path(jobs_root: Path) -> Path:
    return jobs_root / DEPLOY_INDEX_FILENAME


def _private_jobs_root(jobs_root: Path) -> Path:
    if jobs_root.is_symlink():
        raise RuntimeError("runtime deploy index directory may not be a symlink")
    try:
        metadata = jobs_root.stat()
    except FileNotFoundError as exc:
        raise RuntimeError("runtime deploy index directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError("runtime deploy index directory must be private and owner-controlled")
    return jobs_root.resolve(strict=True)


def _validate_index_unit(value: Any) -> str:
    if not isinstance(value, str) or not _durable_job_unit(value):
        raise RuntimeError("runtime deploy index contains an invalid unit")
    return value


def _read_index_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("runtime deploy index is unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > 128 * 1024
        ):
            raise RuntimeError("runtime deploy index must be one private owner-controlled regular file")
        data = bytearray()
        while len(data) <= 128 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 128 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 128 * 1024:
            raise RuntimeError("runtime deploy index exceeds its size bound")
        return bytes(data)
    finally:
        os.close(descriptor)


def _read_deploy_index(jobs_root: Path) -> dict[str, Any] | None:
    root = _private_jobs_root(jobs_root)
    path = _deploy_index_path(root)
    if path.is_symlink():
        raise RuntimeError("runtime deploy index may not be a symlink")
    if not path.exists():
        return None
    try:
        payload = json.loads(_read_index_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime deploy index is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "units", "pending_unit", "updated_at_unix"
    }:
        raise RuntimeError("runtime deploy index shape is invalid")
    if payload.get("schema_version") != 1:
        raise RuntimeError("runtime deploy index schema is unsupported")
    units_raw = payload.get("units")
    if not isinstance(units_raw, list) or len(units_raw) > MAX_DEPLOY_INDEX_ENTRIES:
        raise RuntimeError("runtime deploy index entry count is invalid")
    units = [_validate_index_unit(item) for item in units_raw]
    if len(units) != len(set(units)):
        raise RuntimeError("runtime deploy index contains duplicate units")
    pending = payload.get("pending_unit")
    if pending is not None:
        pending = _validate_index_unit(pending)
    updated = payload.get("updated_at_unix")
    if isinstance(updated, bool) or not isinstance(updated, int) or updated < 0:
        raise RuntimeError("runtime deploy index timestamp is invalid")
    return {
        "schema_version": 1,
        "units": sorted(units),
        "pending_unit": pending,
        "updated_at_unix": updated,
    }


def _write_deploy_index(
    jobs_root: Path,
    *,
    units: list[str],
    pending_unit: str | None,
) -> dict[str, Any]:
    normalized = sorted({_validate_index_unit(item) for item in units})
    if len(normalized) > MAX_DEPLOY_INDEX_ENTRIES:
        raise RuntimeError("runtime deploy index exceeds its bounded entry count")
    pending = None if pending_unit is None else _validate_index_unit(pending_unit)
    payload = {
        "schema_version": 1,
        "units": normalized,
        "pending_unit": pending,
        "updated_at_unix": int(time.time()),
    }
    root = _private_jobs_root(jobs_root)
    path = _deploy_index_path(root)
    if path.is_symlink():
        raise RuntimeError("runtime deploy index may not be a symlink")
    if path.exists():
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise RuntimeError("runtime deploy index must be one private owner-controlled regular file")
    temporary = root / f".{path.name}.{uuid.uuid4().hex}.tmp"
    data = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return payload


def _deploy_finalization_retry_block(
    entry: Path, metadata: dict[str, Any]
) -> bool:
    """Recognize only the durable no-blind-retry deployment state.

    This is a scheduling guard, not a second success authority.  Any present
    runtime-deploy finalization that cannot be safely parsed blocks bootstrap
    rather than authorizing a retry.
    """
    contract = metadata.get("finalization_contract")
    if not isinstance(contract, dict):
        return False
    if contract.get("kind") != "grabowski_runtime_deploy_finalization":
        return False
    receipt_paths = contract.get("receipt_paths")
    if not isinstance(receipt_paths, dict):
        raise RuntimeError(
            f"runtime deploy finalization contract is malformed: {entry.name}"
        )
    path = entry / "finalization.json"
    if receipt_paths.get("finalization") != str(path):
        raise RuntimeError(
            f"runtime deploy finalization path is not bound to {entry.name}"
        )
    if path.is_symlink():
        raise RuntimeError(
            f"runtime deploy finalization may not be a symlink: {entry.name}"
        )
    if not path.exists():
        return False
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(
            f"runtime deploy finalization is unreadable: {entry.name}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or opened.st_size > 64 * 1024
        ):
            raise RuntimeError(
                f"runtime deploy finalization is not one private regular file: {entry.name}"
            )
        raw = bytearray()
        while len(raw) <= 64 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 64 * 1024 + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > 64 * 1024:
            raise RuntimeError(
                f"runtime deploy finalization exceeds its size bound: {entry.name}"
            )
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"runtime deploy finalization is invalid JSON: {entry.name}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            f"runtime deploy finalization is not an object: {entry.name}"
        )
    declared = payload.get("payload_sha256")
    unsigned = dict(payload)
    unsigned.pop("payload_sha256", None)
    if (
        not isinstance(declared, str)
        or re.fullmatch(r"[0-9a-f]{64}", declared) is None
        or _sha256_json(unsigned) != declared
    ):
        raise RuntimeError(
            f"runtime deploy finalization hash is invalid: {entry.name}"
        )
    for key in ("unit", "job_id", "argv_sha256", "expected_head"):
        if payload.get(key) != contract.get(key):
            raise RuntimeError(
                f"runtime deploy finalization binding drift: {entry.name}:{key}"
            )
    final_status = payload.get("final_status")
    if final_status != "outcome_unknown":
        return False
    blue_green = payload.get("blue_green")
    if (
        payload.get("completion_status") != "outcome_unknown"
        or payload.get("blind_retry_allowed") is not False
        or not isinstance(blue_green, dict)
        or blue_green.get("outcome") not in ("completed", "outcome_unknown")
        or blue_green.get("receipt_persisted") is not False
        or blue_green.get("expected_head") != contract.get("expected_head")
        or blue_green.get("receipt_sha256")
        != payload.get("blue_green_receipt_sha256")
    ):
        raise RuntimeError(
            f"runtime deploy outcome_unknown finalization is invalid: {entry.name}"
        )
    return True


def _references_runtime_runner(command: list[str], runner: Path) -> bool:
    """Does this argv start one of the runners that mutate the live runtime?"""
    return (
        len(command) >= 2
        and command[0] == "/usr/bin/python3"
        and command[1].endswith(f"/{runner}")
    )


def _bootstrap_deploy_index(
    jobs_root: Path,
    _repository: Path | None = None,
) -> dict[str, Any]:
    entries = sorted(
        (entry for entry in jobs_root.iterdir() if _durable_job_unit(entry.name)),
        key=lambda path: path.name,
    )
    if len(entries) > MAX_JOB_SCAN_ENTRIES:
        raise RuntimeError("job registry exceeds the bounded runtime deploy index bootstrap scan")
    units: list[str] = []
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir():
            raise RuntimeError(f"durable job entry is not a real directory: {entry.name}")
        try:
            metadata = operator._read_job_metadata(entry.name)
        except (OSError, ValueError, PermissionError) as exc:
            raise RuntimeError(f"durable job metadata is unreadable: {entry.name}") from exc
        candidate_command = metadata.get("argv")
        if not isinstance(candidate_command, list) or not all(isinstance(item, str) for item in candidate_command):
            raise RuntimeError(f"durable job argv is malformed: {entry.name}")
        # Both runners mutate the same live runtime, so both belong in the
        # index this bootstrap rebuilds.  Recognising only the deploy runner
        # here would drop a live mid-cutover resume before any later reader
        # sees it, and an ordinary deployment could then be scheduled straight
        # into the recovery it was supposed to wait for -- the same blindness
        # this change removes one layer up.
        references_deploy_runner = _references_runtime_runner(
            candidate_command, RUNNER_RELATIVE_PATH
        )
        references_resume_runner = _references_runtime_runner(
            candidate_command, MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
        )
        references_runtime_job = references_deploy_runner or references_resume_runner
        unresolved_finalization = (
            # Only the deploy runner writes the runtime-deploy finalization
            # receipt this predicate reads; a resume carries its outcome in its
            # own durable receipt instead.
            _deploy_finalization_retry_block(entry, metadata)
            if references_deploy_runner
            else False
        )
        if references_runtime_job and (
            unresolved_finalization
            or metadata.get("final_status") not in TERMINAL_JOB_STATUSES
        ):
            units.append(entry.name)
    return _write_deploy_index(jobs_root, units=units, pending_unit=None)


def _deploy_index(
    jobs_root: Path,
    _repository: Path | None = None,
) -> dict[str, Any]:
    index = _read_deploy_index(jobs_root)
    if index is None:
        index = _bootstrap_deploy_index(jobs_root)
    pending = index["pending_unit"]
    if pending is not None:
        pending_entry = jobs_root / pending
        if pending_entry.is_symlink():
            raise RuntimeError("pending runtime deploy job path is a symlink")
        if pending_entry.exists():
            if not pending_entry.is_dir():
                raise RuntimeError("pending runtime deploy job path is not a directory")
            units = sorted(set(index["units"]) | {pending})
        else:
            units = list(index["units"])
        index = _write_deploy_index(jobs_root, units=units, pending_unit=None)
    return index


def _validated_deploy_job_receipt(entry: Path, metadata: dict[str, Any]) -> dict[str, str]:
    expected_receipt = metadata.get("expected_receipt")
    if not isinstance(expected_receipt, dict):
        raise RuntimeError(f"deploy job receipt is unavailable: {entry.name}")
    expected = {
        "unit": entry.name,
        "metadata_path": str(entry / "metadata.json"),
        "stdout_path": str(entry / "stdout.log"),
        "stderr_path": str(entry / "stderr.log"),
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
    }
    for key, value in expected.items():
        if expected_receipt.get(key) != value:
            raise RuntimeError(f"deploy job receipt {key} is not bound to {entry.name}")
    return {
        "metadata_path": expected["metadata_path"],
        "stdout_path": expected["stdout_path"],
        "stderr_path": expected["stderr_path"],
    }


class IndexedRuntimeJobConflict(RuntimeError):
    """An indexed runtime job forbids starting another one right now."""


def _classify_indexed_job(entry: Path) -> dict[str, Any]:
    """Read one indexed durable job into a decided shape.

    Extracted so the scheduler and the recovery lane read the deploy index
    through the same eyes.  Two readers of one index become two definitions of
    "is a deployment already running", and the weaker one is the one that lets a
    second job start.
    """
    if entry.is_symlink() or not entry.is_dir():
        raise IndexedRuntimeJobConflict(
            f"durable job entry is not a real directory: {entry.name}"
        )
    try:
        metadata = operator._read_job_metadata(entry.name)
    except (OSError, ValueError, PermissionError) as exc:
        raise IndexedRuntimeJobConflict(
            f"durable job metadata is unreadable: {entry.name}"
        ) from exc
    candidate_command = metadata.get("argv")
    if not isinstance(candidate_command, list) or not all(
        isinstance(item, str) for item in candidate_command
    ):
        raise IndexedRuntimeJobConflict(f"durable job argv is malformed: {entry.name}")
    deploy_fields = _deploy_command_fields(candidate_command)
    resume_fields = (
        _midcutover_resume_command_fields(candidate_command)
        if deploy_fields is None
        else None
    )
    if deploy_fields is None and resume_fields is None:
        raise IndexedRuntimeJobConflict(
            f"self deploy job metadata is malformed: {entry.name}"
        )
    command_fields = deploy_fields or resume_fields
    assert command_fields is not None
    candidate_repository = Path(command_fields["repository"])
    candidate_runner = str(
        candidate_repository
        / (
            RUNNER_RELATIVE_PATH
            if deploy_fields is not None
            else MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
        )
    )
    if (
        candidate_command[0] != "/usr/bin/python3"
        or candidate_command[1] != candidate_runner
        or metadata.get("cwd") != str(candidate_repository)
    ):
        raise IndexedRuntimeJobConflict(
            f"self deploy job metadata is malformed: {entry.name}"
        )
    argv_sha256 = metadata.get("argv_sha256")
    if argv_sha256 != _deploy_command_sha256(candidate_command):
        raise IndexedRuntimeJobConflict(
            f"self deploy job command hash mismatch: {entry.name}"
        )
    status = operator.grabowski_job_status(entry.name)
    if not isinstance(status, dict):
        raise IndexedRuntimeJobConflict(
            f"self deploy job status is unavailable: {entry.name}"
        )
    final_status = status.get("final_status")
    # A job whose finalization receipt says outcome_unknown with blind retry
    # forbidden is *not* finished in the sense that matters here, however
    # cleanly its unit exited.  Treating the systemd status as the whole truth
    # would prune exactly the entry that demands an authoritative runtime
    # readback before anything else runs.
    finalization = status.get("finalization_receipt")
    readback_required = bool(
        isinstance(finalization, dict)
        and finalization.get("valid") is True
        and finalization.get("final_status") == "outcome_unknown"
        and finalization.get("blind_retry_allowed") is False
    )
    runtime_proven_terminal = bool(
        deploy_fields is not None
        and _missing_finalization_deploy_is_runtime_proven(status, deploy_fields)
    )
    noeffect_proven_terminal = bool(
        deploy_fields is not None
        and not runtime_proven_terminal
        and _missing_finalization_deploy_is_noeffect_proven(status, deploy_fields)
    )
    return {
        "unit": entry.name,
        "kind": "deploy" if deploy_fields is not None else "midcutover_resume",
        "argv": candidate_command,
        "argv_sha256": argv_sha256,
        "metadata": metadata,
        "status": status,
        "final_status": final_status,
        "fields": command_fields,
        "readback_required": readback_required,
        "runtime_proven_terminal": runtime_proven_terminal,
        "noeffect_proven_terminal": noeffect_proven_terminal,
        "terminal": (
            final_status in TERMINAL_JOB_STATUSES and not readback_required
        ) or runtime_proven_terminal or noeffect_proven_terminal,
        "reusable": final_status in REUSABLE_JOB_STATUSES and not readback_required,
    }


def _sidecar_git_blob(repository: Path, expected_head: str, relative: Path) -> bytes:
    if (
        OBJECT_ID_RE.fullmatch(expected_head) is None
        or relative not in {SIDECAR_ROUTER_SOURCE_RELATIVE, SIDECAR_SCHEDULER_SOURCE_RELATIVE}
    ):
        raise RuntimeError("sidecar source binding is invalid")
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.file.allow=never",
            "-C",
            str(repository),
            "show",
            f"{expected_head}:{relative.as_posix()}",
        ],
        cwd="/",
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
        },
    )
    if completed.returncode != 0:
        raise RuntimeError("sidecar source blob is unavailable")
    if (
        len(completed.stdout) > MAX_SIDECAR_SOURCE_BYTES
        or len(completed.stderr) > MAX_SIDECAR_READBACK_BYTES
    ):
        raise RuntimeError("sidecar source blob exceeds bounded output")
    return completed.stdout


def _sidecar_file_bytes(path: Path, *, mode: int) -> bytes:
    parent = path.parent
    parent_metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        or parent.resolve(strict=True) != Path(os.path.abspath(parent))
    ):
        raise RuntimeError("installed sidecar parent directory is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or before.st_size > MAX_SIDECAR_SOURCE_BYTES
        ):
            raise RuntimeError("installed sidecar file is unsafe")
        data = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError("installed sidecar file ended early")
            data.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError("installed sidecar file grew while reading")
        after = os.fstat(descriptor)
        if (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise RuntimeError("installed sidecar file changed while reading")
        return bytes(data)
    finally:
        os.close(descriptor)


def _sidecar_json_readback(argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        argv,
        cwd="/",
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        env={
            "HOME": str(Path.home()),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
        },
    )
    if completed.returncode != 0:
        raise RuntimeError("sidecar readback command failed")
    if (
        len(completed.stdout) > MAX_SIDECAR_READBACK_BYTES
        or len(completed.stderr) > MAX_SIDECAR_READBACK_BYTES
    ):
        raise RuntimeError("sidecar readback exceeds bounded output")
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("sidecar readback is not valid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("sidecar readback root is not an object")
    return value


def _sidecar_controller_contract_valid(value: dict[str, Any]) -> bool:
    expected = {
        "decision": "controller",
        "controller": "grabowski-primary",
        "primary_role": "controller-integrator",
        "delegated_scoped_writers_allowed": True,
        "controller_integration_required": True,
        "single_mutating_writer": True,
        "single_mutating_writer_scope": "overlapping-resource-lane",
        "external_primary_writer_forbidden": False,
        "automatic_execution_authorized": True,
    }
    return all(value.get(key) == expected_value for key, expected_value in expected.items())


def _sidecars_match_deploy_head(command_fields: dict[str, Any]) -> bool:
    try:
        if command_fields.get("source_kind") not in SOURCE_KINDS:
            return False
        repository = Path(str(command_fields.get("canonical_repository"))).resolve(strict=True)
        if repository != CANONICAL_REPOSITORY.resolve(strict=True):
            return False
        expected_head = str(command_fields.get("expected_head"))
        router_template_bytes = _sidecar_git_blob(
            repository, expected_head, SIDECAR_ROUTER_SOURCE_RELATIVE
        )
        try:
            router_template = router_template_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return False
        marker = 'runtime_python="$HOME/.local/share/grabowski-mcp/.venv/bin/python"'
        if router_template.count(marker) != 1:
            return False
        expected_router = router_template.replace(
            marker, f"runtime_python={shlex.quote(str(SIDECAR_RUNTIME_PYTHON))}", 1
        ).encode("utf-8")
        expected_scheduler = _sidecar_git_blob(
            repository, expected_head, SIDECAR_SCHEDULER_SOURCE_RELATIVE
        )
        if not expected_scheduler.startswith(b"#!/usr/bin/env python3\n"):
            return False
        installed_router = _sidecar_file_bytes(SIDECAR_ROUTER_TARGET, mode=0o755)
        installed_scheduler = _sidecar_file_bytes(SIDECAR_SCHEDULER_TARGET, mode=0o755)
        installed_pin = _sidecar_file_bytes(SIDECAR_ROUTER_PIN, mode=0o600)
        router_sha256 = hashlib.sha256(expected_router).hexdigest()
        if (
            installed_router != expected_router
            or installed_scheduler != expected_scheduler
            or installed_pin != f"{router_sha256}\n".encode("ascii")
        ):
            return False
        runtime = _sidecar_json_readback(
            [
                str(SIDECAR_RUNTIME_PYTHON),
                "-m",
                "grabowski_coding_agent_router_cli",
                "validate",
            ]
        )
        catalog_sha256 = runtime.get("catalog_sha256")
        if (
            runtime.get("valid") is not True
            or runtime.get("catalog_source") != "deployment_catalog"
            or not isinstance(catalog_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", catalog_sha256) is None
        ):
            return False
        recommendation = _sidecar_json_readback(
            [
                str(SIDECAR_ROUTER_TARGET),
                "recommend",
                "--task-class",
                "complex-patch",
                "--changed-files",
                "50",
                "--duration-minutes",
                "600",
                "--novelty",
                "high",
                "--need-review",
            ]
        )
        return bool(
            recommendation.get("catalog_sha256") == catalog_sha256
            and _sidecar_controller_contract_valid(recommendation)
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        return False


def _missing_finalization_deploy_is_runtime_proven(
    status: dict[str, Any],
    command_fields: dict[str, Any],
    *,
    runtime_proof_cache: dict[tuple[str, str, str], bool] | None = None,
) -> bool:
    """Treat an exited deploy as terminal only when its active release proves the head.

    The reconciliation must stay valid when canonical source has already advanced
    beyond the deployed release.  Deployment metadata validates the active immutable
    release independently of the canonical checkout, so require its complete runtime
    binding and provenance in addition to the exact release head and sidecar readback.
    No missing job receipt is synthesized or rewritten.
    """
    if status.get("final_status") in TERMINAL_JOB_STATUSES | REUSABLE_JOB_STATUSES:
        return False
    finalization = status.get("finalization_receipt")
    if not isinstance(finalization, dict):
        return False
    if finalization.get("state") not in {"missing_receipt", "not_configured"}:
        return False
    if finalization.get("valid") is True:
        return False
    properties = status.get("properties")
    if not isinstance(properties, dict):
        return False
    if (
        properties.get("ActiveState") != "inactive"
        or properties.get("SubState") != "dead"
        or properties.get("Result") != "success"
        or str(properties.get("ExecMainStatus")) != "0"
    ):
        return False
    effective_cache = (
        runtime_proof_cache
        if runtime_proof_cache is not None
        else _RUNTIME_PROOF_CACHE.get()
    )
    cache_key = (
        str(command_fields.get("source_kind")),
        str(command_fields.get("canonical_repository")),
        str(command_fields.get("expected_head")),
    )
    if effective_cache is not None and cache_key in effective_cache:
        return effective_cache[cache_key]
    deployment = base._deployment_metadata()
    required_release_integrity = (
        "manifest_parse_valid",
        "manifest_schema_valid",
        "release_path_valid",
        "release_id_valid",
        "repo_head_valid",
        "stable_runtime_manifest_valid",
        "runtime_pointer_valid",
        "artifact_integrity_valid",
        "runtime_asset_identity_valid",
        "release_python_identity_valid",
        "runtime_binding_valid",
        "environment_compatibility_valid",
        "provenance_valid",
    )
    proven = bool(
        isinstance(deployment, dict)
        and deployment.get("completion_status") == "complete"
        and deployment.get("repo_head") == command_fields.get("expected_head")
        and all(deployment.get(key) is True for key in required_release_integrity)
        and _sidecars_match_deploy_head(command_fields)
    )
    if effective_cache is not None:
        effective_cache[cache_key] = proven
    return proven


def _linux_process_started_at_unix(pid: int) -> float | None:
    """Return one Linux process start time without trusting wall-clock prose."""
    if type(pid) is not int or pid <= 0:
        return None
    try:
        process_stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        close = process_stat.rfind(")")
        if close < 0:
            return None
        fields = process_stat[close + 2 :].split()
        start_ticks = int(fields[19])
        clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        boot_time = None
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
            if line.startswith("btime "):
                boot_time = int(line.split()[1])
                break
        if boot_time is None or clock_ticks <= 0:
            return None
        return boot_time + (start_ticks / clock_ticks)
    except (OSError, UnicodeError, ValueError, IndexError):
        return None


def _active_runtime_process_matches_stable_pointer(deployment: dict[str, Any]) -> bool:
    """Bind the live canonical operator to the current stable release pointer."""
    release_id = deployment.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        return False
    stable_runtime = base.EXPECTED_STABLE_RUNTIME
    try:
        pointer_info = stable_runtime.lstat()
        if not stat.S_ISLNK(pointer_info.st_mode):
            return False
        release_path = stable_runtime.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    if release_path.name != release_id:
        return False

    try:
        observed = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "grabowski-operator.service",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    fields: dict[str, str] = {}
    for line in observed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            return False
        fields[key] = value
    if (
        observed.returncode != 0
        or set(fields) != {"LoadState", "ActiveState", "SubState", "MainPID"}
        or fields["LoadState"] != "loaded"
        or fields["ActiveState"] != "active"
        or fields["SubState"] != "running"
    ):
        return False
    try:
        pid = int(fields["MainPID"])
    except ValueError:
        return False
    process_started = _linux_process_started_at_unix(pid)
    if process_started is None or pointer_info.st_mtime > process_started:
        # If the stable pointer changed after this process started, its original
        # release cannot be recovered from argv alone.  Preserve the ambiguity.
        return False
    try:
        raw_cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    if not raw_cmdline or len(raw_cmdline) > 16 * 1024:
        return False
    try:
        argv = [
            part.decode("utf-8")
            for part in raw_cmdline.rstrip(b"\0").split(b"\0")
        ]
    except UnicodeDecodeError:
        return False
    expected = [
        str(stable_runtime / ".venv/bin/python"),
        "-m",
        CANONICAL_OPERATOR_MODULE,
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "18181",
    ]
    return argv == expected


def _missing_finalization_deploy_is_noeffect_proven(
    status: dict[str, Any],
    command_fields: dict[str, Any],
) -> bool:
    """Prove an interrupted deploy no longer owns an unresolved cutover.

    A missing runner receipt is normally an ambiguity and must keep blocking.
    The one safe negative case is when an independently bound canonical operator
    is serving a complete artifact-valid *different* release and the existing
    mid-cutover classifier says no cutover remains to resume.  This does not
    synthesize the missing receipt; it only removes the dead job from the
    concurrency index after its target is proven not to be active.
    """
    if status.get("final_status") in TERMINAL_JOB_STATUSES | REUSABLE_JOB_STATUSES:
        return False
    finalization = status.get("finalization_receipt")
    if not isinstance(finalization, dict):
        return False
    if finalization.get("state") not in {"missing_receipt", "not_configured"}:
        return False
    if finalization.get("valid") is True:
        return False
    properties = status.get("properties")
    if not isinstance(properties, dict):
        return False
    if (
        properties.get("ActiveState") != "inactive"
        or properties.get("SubState") != "dead"
        or properties.get("Result") != "success"
        or str(properties.get("ExecMainStatus")) != "0"
    ):
        return False

    deployment = base._deployment_metadata()
    source_independent_integrity = (
        "manifest_parse_valid",
        "manifest_schema_valid",
        "release_path_valid",
        "release_id_valid",
        "repo_head_valid",
        "stable_runtime_manifest_valid",
        "runtime_pointer_valid",
        "runtime_input_identity_valid",
        "lock_identity_valid",
        "source_snapshot_identity_valid",
        "runtime_asset_snapshot_identity_valid",
        "runtime_asset_identity_valid",
        "embedded_contract_valid",
        "entrypoint_contract_identity_valid",
        "agent_instructions_identity_valid",
        "release_python_identity_valid",
        "executable_identity_valid",
        "pip_identity_valid",
        "protocol_identity_valid",
        "python_runtime_identity_valid",
        "platform_identity_valid",
        "artifact_integrity_valid",
        "environment_compatibility_valid",
    )
    expected_head = command_fields.get("expected_head")
    if not (
        isinstance(deployment, dict)
        and deployment.get("completion_status") == "complete"
        and isinstance(expected_head, str)
        and OBJECT_ID_RE.fullmatch(expected_head) is not None
        and deployment.get("repo_head") != expected_head
        and all(deployment.get(key) is True for key in source_independent_integrity)
        and _active_runtime_process_matches_stable_pointer(deployment)
    ):
        return False
    try:
        classification = midcutover.classify_from_durable_state(
            expected_head=expected_head,
            snapshot_inspector=client_snapshot.inspect_cutover_snapshot_binding,
        )
    except Exception:  # noqa: BLE001 - ambiguity must remain blocking
        return False
    return bool(
        classification.get("lane") == midcutover.LANE_SCHEDULED_DEPLOY
        and not classification.get("reasons")
        and classification.get("resume_binding") is None
    )


def inflight_runtime_job_evidence(
    command: list[str] | None = None, *, prune: bool = False
) -> dict[str, Any]:
    """Project the deploy index for a gate, without deciding for it.

    The provenance recovery gate previously looked only at ``pending_unit``.
    That field is cleared the moment a job actually starts, so between the start
    and the job's own completion the index looked empty and a second identical
    repair could dispatch a second job -- the double dispatch this lane exists
    to prevent.  The units list is the durable record; this reads it.

    Identity matters as much as presence: an in-flight job with the *same* argv
    is this same intent already running and may be coalesced, while any other
    in-flight deploy, repair or resume is a competitor and must close the gate.
    """
    evidence: dict[str, Any] = {
        "inflight_units": [],
        "blocking_units": [],
        "idempotent_match": None,
        "ambiguous_identical_units": [],
        "pruned_units": [],
        "error": None,
    }
    expected_sha256 = _deploy_command_sha256(command) if command else None
    try:
        jobs_root = operator._jobs_root()
        index = _deploy_index(jobs_root)
    except (OSError, RuntimeError, ValueError) as exc:
        evidence["error"] = f"deployment job index is unreadable: {exc}"
        return evidence
    pending = index.get("pending_unit")
    if pending:
        # A reservation with no started job yet is still an in-flight intent.
        evidence["inflight_units"].append(str(pending))
        evidence["blocking_units"].append(str(pending))
    retained: list[str] = []
    runtime_proof_cache: dict[tuple[str, str, str], bool] = {}
    for unit in index["units"]:
        cache_token = _RUNTIME_PROOF_CACHE.set(runtime_proof_cache)
        try:
            try:
                classified = _classify_indexed_job(jobs_root / unit)
            except IndexedRuntimeJobConflict as exc:
                # Unreadable is not absent.  An entry this reader cannot judge must
                # close the gate rather than vanish from it.
                evidence["blocking_units"].append(str(unit))
                evidence["error"] = str(exc)
                retained.append(str(unit))
                continue
        finally:
            _RUNTIME_PROOF_CACHE.reset(cache_token)
        if classified["terminal"]:
            evidence["pruned_units"].append(str(unit))
            continue
        retained.append(str(unit))
        evidence["inflight_units"].append(str(unit))
        if (
            expected_sha256 is not None
            and classified["argv_sha256"] == expected_sha256
            and classified["reusable"]
        ):
            if evidence["idempotent_match"] is not None:
                # Historical double-dispatch residue.  Two identical running
                # jobs cannot both be "the one we may join", and silently
                # picking the last would coalesce onto an arbitrary half of an
                # ambiguity.  Both block instead.
                evidence["ambiguous_identical_units"] = sorted(
                    {evidence["idempotent_match"]["unit"], str(unit)}
                )
                evidence["blocking_units"].extend(
                    evidence["ambiguous_identical_units"]
                )
                evidence["idempotent_match"] = None
                evidence["error"] = (
                    "multiple identical runtime jobs are running: "
                    + ", ".join(evidence["ambiguous_identical_units"])
                )
                continue
            if evidence.get("ambiguous_identical_units"):
                evidence["blocking_units"].append(str(unit))
                continue
            evidence["idempotent_match"] = {
                "unit": classified["unit"],
                "kind": classified["kind"],
                "argv_sha256": classified["argv_sha256"],
                "final_status": classified["final_status"],
            }
            continue
        evidence["blocking_units"].append(str(unit))
    if prune and evidence["pruned_units"] and evidence["error"] is None:
        try:
            _write_deploy_index(jobs_root, units=retained, pending_unit=pending)
        except (OSError, RuntimeError, ValueError) as exc:
            evidence["error"] = f"deploy index pruning failed: {exc}"
    return evidence


def _matching_inflight_deploy_job(command: list[str], _repository: Path) -> dict[str, Any] | None:
    expected_fields = _deploy_command_fields(command)
    if expected_fields is None:
        raise ValueError("runtime deploy command identity is invalid")
    expected_target = (
        expected_fields["canonical_repository"],
        expected_fields["expected_head"],
    )
    jobs_root = operator._jobs_root()
    index = _deploy_index(jobs_root)
    entries = [jobs_root / unit for unit in index["units"]]

    matches: list[dict[str, Any]] = []
    retained_units: list[str] = []
    runtime_proof_cache: dict[tuple[str, str, str], bool] = {}
    for entry in reversed(entries):
        if entry.is_symlink() or not entry.is_dir():
            raise RuntimeError(f"durable job entry is not a real directory: {entry.name}")
        try:
            metadata = operator._read_job_metadata(entry.name)
        except (OSError, ValueError, PermissionError) as exc:
            raise RuntimeError(f"durable job metadata is unreadable: {entry.name}") from exc
        candidate_command = metadata.get("argv")
        if not isinstance(candidate_command, list) or not all(
            isinstance(item, str) for item in candidate_command
        ):
            raise RuntimeError(f"durable job argv is malformed: {entry.name}")
        candidate_fields = _deploy_command_fields(candidate_command)
        resume_fields = (
            _midcutover_resume_command_fields(candidate_command)
            if candidate_fields is None
            else None
        )
        if candidate_fields is None and resume_fields is None:
            raise RuntimeError(f"self deploy job metadata is malformed: {entry.name}")
        command_fields = candidate_fields or resume_fields
        assert command_fields is not None
        candidate_repository = Path(command_fields["repository"])
        candidate_runner = str(
            candidate_repository
            / (
                RUNNER_RELATIVE_PATH
                if candidate_fields is not None
                else MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH
            )
        )
        if (
            candidate_command[0] != "/usr/bin/python3"
            or candidate_command[1] != candidate_runner
            or metadata.get("cwd") != str(candidate_repository)
        ):
            raise RuntimeError(f"self deploy job metadata is malformed: {entry.name}")
        argv_sha256 = metadata.get("argv_sha256")
        if argv_sha256 != _deploy_command_sha256(candidate_command):
            raise RuntimeError(f"self deploy job command hash mismatch: {entry.name}")
        status = operator.grabowski_job_status(entry.name)
        if not isinstance(status, dict):
            raise RuntimeError(f"self deploy job status is unavailable: {entry.name}")
        final_status = status.get("final_status")
        if resume_fields is not None:
            # The provenance-recovery lane reserves its receipt-bound resume in
            # this same index so an ordinary deploy cannot race it.  Once that
            # job is terminal the index has served its concurrency purpose; its
            # outcome authority remains the durable bgcr receipt and the fresh
            # recovery classification performed by the scheduled runner before
            # any deployment effect.  Never reinterpret the resume argv as a
            # deploy argv, and never discard an in-flight or ambiguous resume.
            if final_status in TERMINAL_JOB_STATUSES:
                continue
            retained_units.append(entry.name)
            if final_status in REUSABLE_JOB_STATUSES:
                raise RuntimeError(
                    f"mid-cutover resume job is still running: {entry.name}"
                )
            raise RuntimeError(
                "mid-cutover resume job has an uncertain non-reusable outcome: "
                f"{entry.name} ({final_status})"
            )
        finalization = status.get("finalization_receipt")
        if (
            isinstance(finalization, dict)
            and finalization.get("valid") is True
            and finalization.get("final_status") == "outcome_unknown"
            and finalization.get("blind_retry_allowed") is False
        ):
            raise RuntimeError(
                f"self deploy job requires authoritative runtime readback before retry: {entry.name} (outcome_unknown)"
            )
        if final_status in TERMINAL_JOB_STATUSES:
            continue
        if _missing_finalization_deploy_is_runtime_proven(
            status, candidate_fields, runtime_proof_cache=runtime_proof_cache
        ):
            continue
        if _missing_finalization_deploy_is_noeffect_proven(status, candidate_fields):
            continue
        retained_units.append(entry.name)
        if final_status not in REUSABLE_JOB_STATUSES:
            raise RuntimeError(
                f"self deploy job has an uncertain non-reusable outcome: {entry.name} ({final_status})"
            )
        candidate_target = (
            candidate_fields["canonical_repository"],
            candidate_fields["expected_head"],
        )
        if candidate_target[0] != expected_target[0]:
            raise RuntimeError(
                f"another Grabowski self deploy is already running for a different canonical repository: {entry.name}"
            )
        if candidate_target[1] != expected_target[1]:
            raise RuntimeError(
                f"another Grabowski self deploy is already running for a different head: {entry.name}"
            )
        receipt_paths = _validated_deploy_job_receipt(entry, metadata)
        matches.append(
            {
                "unit": entry.name,
                "argv_sha256": argv_sha256,
                "delay_seconds": int(candidate_fields["delay_seconds"]),
                "source_identity_sha256": candidate_fields["source_identity_sha256"],
                **receipt_paths,
                "final_status": final_status,
            }
        )

    _write_deploy_index(jobs_root, units=retained_units, pending_unit=None)
    if len(matches) > 1:
        units = ", ".join(sorted(item["unit"] for item in matches))
        raise RuntimeError(f"multiple identical Grabowski self deploy jobs are running: {units}")
    return matches[0] if matches else None


def _schedule_result(
    *,
    expected_head: str,
    requested_delay_seconds: int,
    effective_delay_seconds: int,
    job: dict[str, Any],
    intent: dict[str, Any] | None,
    scheduled: dict[str, Any],
    already_scheduled: bool,
    source_identity: dict[str, Any],
    deployment_observer_capability: str | None = None,
) -> dict[str, Any]:
    contract = job.get("deployment_observer_contract")
    observer_available = (
        isinstance(deployment_observer_capability, str)
        and isinstance(contract, dict)
    )
    return {
        "scheduled": True,
        "already_scheduled": already_scheduled,
        "expected_head": expected_head,
        "requested_delay_seconds": requested_delay_seconds,
        "delay_seconds": effective_delay_seconds,
        "source_identity": source_identity,
        "source_identity_sha256": source_identity["identity_sha256"],
        "effective_source_identity_sha256": job.get(
            "source_identity_sha256", source_identity["identity_sha256"]
        ),
        "reused_across_source_identity": (
            already_scheduled
            and job.get("source_identity_sha256", source_identity["identity_sha256"])
            != source_identity["identity_sha256"]
        ),
        "unit": job["unit"],
        "argv_sha256": job["argv_sha256"],
        "metadata_path": job["metadata_path"],
        "stdout_path": job["stdout_path"],
        "stderr_path": job["stderr_path"],
        "expected_connector_disconnect": True,
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
        "deployment_observer": {
            "available": observer_available,
            "operation": deployment_observer.OPERATION,
            "capability": (
                deployment_observer_capability if observer_available else None
            ),
            "contract_sha256": (
                contract.get("contract_sha256")
                if isinstance(contract, dict)
                else None
            ),
            "expires_at_unix": (
                contract.get("expires_at_unix")
                if isinstance(contract, dict)
                else None
            ),
            "client_id_bound": (
                contract.get("client_id_sha256") is not None
                if isinstance(contract, dict)
                else False
            ),
            "does_not_establish": [
                "deployment_success",
                "authority_for_another_job_or_operation",
                "generic_read_only_drain_exemption",
                "capability_recovery_after_loss_or_expiry",
            ],
        },
        "audit": {
            "intent": intent,
            "scheduled": scheduled,
        },
    }


def _validated_repository_path(raw: Path, *, label: str) -> Path:
    if not raw.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if raw.is_symlink() or not raw.is_dir():
        raise RuntimeError(f"{label} is unavailable: {raw}")
    resolved = raw.resolve(strict=True)
    if resolved != raw:
        raise RuntimeError(f"{label} must not traverse a symlink or relative segment")
    return resolved


def _repoground_managed_source_roots() -> tuple[Path, ...]:
    roots = [REPOGROUND_MANAGED_SOURCE_ROOT]
    configured = os.environ.get("REPOGROUND_SOURCE_ROOT")
    if configured:
        configured_root = Path(configured)
        if not configured_root.is_absolute():
            raise RuntimeError("RepoGround managed source root must be an absolute path")
        roots.append(configured_root)
    return tuple(dict.fromkeys(root.resolve(strict=False) for root in roots))


def _assert_not_repoground_managed_source(repository: Path) -> None:
    resolved_repository = repository.resolve(strict=False)
    for resolved_root in _repoground_managed_source_roots():
        try:
            resolved_repository.relative_to(resolved_root)
        except ValueError:
            continue
        raise RuntimeError(
            "RepoGround-managed source repository cannot be used as a deploy source: "
            f"{repository}"
        )


def _git_common_directory(repository: Path) -> Path:
    raw = _required_stdout(
        _git_result(repository, "rev-parse", "--git-common-dir"),
        "git common directory lookup",
    )
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repository / candidate
    if candidate.is_symlink():
        raise RuntimeError("git common directory may not be a symlink")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate or not resolved.is_dir():
        raise RuntimeError("git common directory must be an exact real directory")
    return resolved


def _resource_inspect(resource_key: str) -> dict[str, Any]:
    import grabowski_resources

    return grabowski_resources.grabowski_resource_inspect(resource_key)


def _source_lease_evidence(
    repository: Path,
    expected_owner: str | None,
) -> dict[str, Any]:
    resource_key = f"path:{repository}"
    payload = _resource_inspect(resource_key)
    if not isinstance(payload, dict) or payload.get("resource_key") != resource_key:
        raise RuntimeError("source repository lease readback is malformed")
    lease = payload.get("lease")
    if lease is None:
        if expected_owner is not None:
            raise RuntimeError("expected source repository lease is absent")
        return {"resource_key": resource_key, "lease": None}
    if not isinstance(lease, dict):
        raise RuntimeError("source repository lease readback is malformed")

    # Inspect is already current-state only, but deployment rechecks expiry at
    # the effect boundary so a just-expired or malformed snapshot cannot grant
    # authority.  Invalid expiry is evidence of no live authority, not a lease.
    now_unix = int(time.time())
    expires_at_unix = lease.get("expires_at_unix")
    lease_is_live = (
        isinstance(expires_at_unix, int)
        and not isinstance(expires_at_unix, bool)
        and expires_at_unix > now_unix
    )
    if not lease_is_live:
        if expected_owner is not None:
            raise RuntimeError("expected source repository lease is absent or expired")
        return {"resource_key": resource_key, "lease": None}

    owner = lease.get("owner_id")
    if expected_owner is None:
        raise RuntimeError(f"source repository has an active lease: {owner}")
    if owner != expected_owner:
        raise RuntimeError(
            f"source repository lease owner drift: expected {expected_owner}, found {owner}"
        )
    required = (
        "resource_key",
        "owner_id",
        "acquired_at_unix",
        "updated_at_unix",
        "expires_at_unix",
        "metadata_sha256",
    )
    snapshot = {name: lease.get(name) for name in required}
    if snapshot["resource_key"] != resource_key or any(
        snapshot[name] is None for name in required
    ):
        raise RuntimeError("source repository lease snapshot is incomplete")
    return {"resource_key": resource_key, "lease": snapshot}


def _source_identity_sha256(identity: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _deployment_source_preflight(
    expected_head: str,
    source_repository: str | None,
    source_lease_owner_id: str | None,
) -> tuple[Path, Path, dict[str, Any]]:
    if not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")
    if source_lease_owner_id is not None and re.fullmatch(
        r"[A-Za-z0-9._:@-]{1,128}", source_lease_owner_id
    ) is None:
        raise ValueError("source_lease_owner_id is invalid")

    canonical = _validated_repository_path(
        CANONICAL_REPOSITORY,
        label="canonical repository",
    )
    if source_repository is None:
        repository = canonical
    else:
        repository = _validated_repository_path(
            Path(source_repository).expanduser(),
            label="source repository",
        )
    _assert_not_repoground_managed_source(repository)

    canonical_common = _git_common_directory(canonical)
    source_common = (
        canonical_common
        if repository == canonical
        else _git_common_directory(repository)
    )
    if source_common != canonical_common:
        raise RuntimeError("source repository does not share the canonical Git common directory")

    head = _required_stdout(
        _git_result(repository, "rev-parse", "--verify", "HEAD"),
        "HEAD lookup",
    )
    branch = _required_stdout(
        _git_result(repository, "rev-parse", "--abbrev-ref", "HEAD"),
        "branch lookup",
    )
    origin_main = _required_stdout(
        _git_result(
            repository,
            "rev-parse",
            "--verify",
            "refs/remotes/origin/main",
        ),
        "origin/main lookup",
    )
    status = _required_stdout(
        _git_result(
            repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ),
        "working-tree status",
    )

    source_kind = "canonical-main" if repository == canonical else "detached-worktree"
    expected_branch = "main" if source_kind == "canonical-main" else "HEAD"
    if head != expected_head:
        raise RuntimeError(f"HEAD drift: expected {expected_head}, found {head}")
    if branch != expected_branch:
        raise RuntimeError(
            f"{source_kind} source has invalid branch state: expected {expected_branch}, found {branch}"
        )
    if origin_main != expected_head:
        raise RuntimeError(
            f"origin/main drift: expected {expected_head}, found {origin_main}"
        )
    if status:
        raise RuntimeError("source repository is dirty")

    runner = repository / RUNNER_RELATIVE_PATH
    if runner.is_symlink() or not runner.is_file():
        raise RuntimeError(f"scheduled deployment runner is unavailable: {runner}")
    if source_kind == "detached-worktree" and source_lease_owner_id is None:
        raise ValueError(
            "detached deployment source requires source_lease_owner_id"
        )
    lease_evidence = _source_lease_evidence(repository, source_lease_owner_id)
    identity = {
        "schema_version": 1,
        "kind": "grabowski_runtime_deploy_source_identity",
        "source_kind": source_kind,
        "repository": str(repository),
        "canonical_repository": str(canonical),
        "git_common_directory": str(source_common),
        "head": head,
        "origin_main": origin_main,
        "clean": True,
        "lease_evidence": lease_evidence,
    }
    return repository, runner, {
        **identity,
        "identity_sha256": _source_identity_sha256(identity),
    }


def _fresh_public_github_main(expected_head: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", expected_head) is None:
        raise ValueError("public GitHub main verification requires one full SHA-1 commit id")
    argv = [
        "/usr/bin/git",
        "-c",
        "credential.helper=",
        "-c",
        "http.followRedirects=false",
        "ls-remote",
        "--refs",
        PUBLIC_GITHUB_REPOSITORY_URL,
        PUBLIC_GITHUB_MAIN_REF,
    ]
    completed = subprocess.run(
        argv,
        cwd="/",
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=PUBLIC_GITHUB_LOOKUP_TIMEOUT_SECONDS,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
        },
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "fresh public GitHub main lookup failed: "
            f"git exit {completed.returncode}"
        )
    if (
        len(completed.stdout.encode("utf-8", errors="replace"))
        > PUBLIC_GITHUB_LOOKUP_MAX_BYTES
        or len(completed.stderr.encode("utf-8", errors="replace"))
        > PUBLIC_GITHUB_LOOKUP_MAX_BYTES
    ):
        raise RuntimeError("fresh public GitHub main lookup exceeded output bound")
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise RuntimeError("fresh public GitHub main lookup returned an ambiguous result")
    fields = lines[0].split("\t")
    if len(fields) != 2 or fields[1] != PUBLIC_GITHUB_MAIN_REF:
        raise RuntimeError("fresh public GitHub main lookup returned an invalid ref")
    head = fields[0]
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise RuntimeError("fresh public GitHub main lookup returned an invalid commit")
    return head


def _canonical_preflight(expected_head: str) -> tuple[Path, Path]:
    repository, runner, _identity = _deployment_source_preflight(
        expected_head,
        None,
        None,
    )
    return repository, runner


@mcp.tool(name="grabowski_runtime_deploy_schedule", annotations=DEPLOY_MUTATING)
def grabowski_runtime_deploy_schedule(
    expected_head: ExpectedHead,
    delay_seconds: DelaySeconds = 8,
    source_repository: SourceRepository | None = None,
    source_lease_owner_id: SourceLeaseOwner | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Schedule one source-identity-bound self-deployment, reusing an identical in-flight job."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_capability("git_cli")
    operator._require_operator_capability("privileged_reference")
    with _deploy_schedule_lock():
        repository, runner, source_identity = _deployment_source_preflight(
            expected_head,
            source_repository,
            source_lease_owner_id,
        )
        public_github_main_before = _fresh_public_github_main(expected_head)
        if public_github_main_before != expected_head:
            raise RuntimeError(
                "fresh public GitHub main differs from deployment target: "
                f"expected {expected_head}, found {public_github_main_before}"
            )
        authority = privileged.ensure_rootbroker_authority(expected_head)
        if not authority.get("success"):
            raise RuntimeError(
                "Rootbroker authority refresh failed before deployment scheduling: "
                + str(authority.get("failure_reason") or authority.get("outcome"))
            )
        public_github_main_after = _fresh_public_github_main(expected_head)
        if public_github_main_after != expected_head:
            raise RuntimeError(
                "public GitHub main drifted during Rootbroker authority refresh: "
                f"expected {expected_head}, found {public_github_main_after}"
            )
        repository_after, runner_after, source_identity_after = _deployment_source_preflight(
            expected_head,
            source_repository,
            source_lease_owner_id,
        )
        if (
            repository_after != repository
            or runner_after != runner
            or source_identity_after["identity_sha256"]
            != source_identity["identity_sha256"]
        ):
            raise RuntimeError("deployment source identity drifted during Rootbroker authority refresh")
        repository = repository_after
        runner = runner_after
        source_identity = source_identity_after
        canonical_repository = Path(source_identity["canonical_repository"])
        command = _deploy_command(
            repository,
            runner,
            expected_head,
            delay_seconds,
            canonical_repository=canonical_repository,
            source_kind=source_identity["source_kind"],
            source_identity_sha256=source_identity["identity_sha256"],
        )
        existing = _matching_inflight_deploy_job(command, repository)
        if existing is not None:
            observed = {
                "timestamp_unix": int(time.time()),
                "operation": "runtime-deploy-existing-schedule-observed",
                "expected_head": expected_head,
                "requested_delay_seconds": delay_seconds,
                "delay_seconds": existing["delay_seconds"],
                "unit": existing["unit"],
                "argv_sha256": existing["argv_sha256"],
                "final_status": existing["final_status"],
                "source_identity_sha256": source_identity["identity_sha256"],
                "effective_source_identity_sha256": existing.get(
                    "source_identity_sha256", source_identity["identity_sha256"]
                ),
                "reused_across_source_identity": (
                    existing.get(
                        "source_identity_sha256",
                        source_identity["identity_sha256"],
                    )
                    != source_identity["identity_sha256"]
                ),
            }
            _append_deploy_audit(observed)
            return _schedule_result(
                expected_head=expected_head,
                requested_delay_seconds=delay_seconds,
                effective_delay_seconds=existing["delay_seconds"],
                job=existing,
                intent=None,
                scheduled=observed,
                already_scheduled=True,
                source_identity=source_identity,
            )

        intent = {
            "timestamp_unix": int(time.time()),
            "operation": "runtime-deploy-schedule-intent",
            "expected_head": expected_head,
            "delay_seconds": delay_seconds,
            "source_identity": source_identity,
            "source_identity_sha256": source_identity["identity_sha256"],
            "public_github_main": {
                "repository": PUBLIC_GITHUB_REPOSITORY_URL,
                "ref": PUBLIC_GITHUB_MAIN_REF,
                "before": public_github_main_before,
                "after": public_github_main_after,
                "verification": "fresh-public-https-git-ls-remote-v1",
            },
            "rootbroker_authority": {
                key: authority.get(key)
                for key in (
                    "outcome",
                    "expected_head",
                    "attested_head",
                    "effect_started",
                    "request_id",
                    "reference_sha256",
                )
            },
        }
        _append_deploy_audit(intent)
        jobs_root = operator._jobs_root()
        index = _deploy_index(jobs_root)
        reserved_unit = DEPLOY_JOB_PREFIX + uuid.uuid4().hex[:12]
        _write_deploy_index(
            jobs_root,
            units=index["units"],
            pending_unit=reserved_unit,
        )
        observer_capability = (
            deployment_observer.issue_capability() if ctx is not None else None
        )
        client_id: str | None = None
        if ctx is not None:
            try:
                observed_client_id = ctx.client_id
            except (AttributeError, RuntimeError, ValueError):
                observed_client_id = None
            if isinstance(observed_client_id, str) and observed_client_id.strip():
                client_id = observed_client_id
        observer_request = (
            {
                "capability": observer_capability,
                "client_id": client_id,
                "expected_head": expected_head,
                "source_identity_sha256": source_identity["identity_sha256"],
            }
            if observer_capability is not None
            else None
        )
        observer_keyword = (
            {"deployment_observer_request": observer_request}
            if observer_request is not None
            else {}
        )
        job = operator._start_job(
            command,
            cwd=str(repository),
            runtime_seconds=3_600,
            finalization_expected_head=expected_head,
            reserved_unit=reserved_unit,
            allow_reserved_runtime_deploy=True,
            **observer_keyword,
        )
        _write_deploy_index(
            jobs_root,
            units=[*index["units"], reserved_unit],
            pending_unit=None,
        )
        scheduled = {
            "timestamp_unix": int(time.time()),
            "operation": "runtime-deploy-scheduled",
            "expected_head": expected_head,
            "delay_seconds": delay_seconds,
            "unit": job["unit"],
            "argv_sha256": job["argv_sha256"],
            "source_identity_sha256": source_identity["identity_sha256"],
        }
        _append_deploy_audit(scheduled)
        return _schedule_result(
            expected_head=expected_head,
            requested_delay_seconds=delay_seconds,
            effective_delay_seconds=delay_seconds,
            job=job,
            intent=intent,
            scheduled=scheduled,
            already_scheduled=False,
            source_identity=source_identity,
            deployment_observer_capability=observer_capability,
        )

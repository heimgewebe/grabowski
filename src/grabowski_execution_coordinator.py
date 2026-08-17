from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

import grabowski_agent_workspace as workspace

SHA40_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
READ_ONLY_ROLES = ("tests", "review")
WORK_LANE_OWNERSHIP = "work_lane"
UNCERTAIN_TASK_STATES = frozenset(
    {"observation_error", "outcome_unknown", "interrupted", "unknown"}
)
REVISION_STARTED_STATES = frozenset(
    {
        "candidate_revision_started",
        "candidate_revision_start_reconciled",
        "writer_handoff_start_absent_intent_cleared",
    }
)
COLLECT_PROGRESS_STATES = frozenset({"collecting", "complete", "writer_running"})
COLLECT_UNKNOWN_STATES = frozenset(
    {"role_start_outcome_unknown", "writer_outcome_unknown"}
)


class ExecutionCoordinatorError(ValueError):
    pass


def _required_workspace_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ExecutionCoordinatorError("workspace_id must be a string")
    identifier = value.strip()
    if not identifier or len(identifier) > 80 or "\x00" in identifier:
        raise ExecutionCoordinatorError(
            "workspace_id is empty, too large or contains NUL"
        )
    return identifier


def _revision_command(value: Any) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise ExecutionCoordinatorError(
            "revision_argv must be a non-empty argv list or null"
        )
    if any(not isinstance(item, str) or not item or "\x00" in item for item in value):
        raise ExecutionCoordinatorError(
            "revision_argv entries must be non-empty strings without NUL"
        )
    return list(value)


def _poll_config(max_polls: Any, poll_seconds: Any) -> tuple[int, float]:
    if (
        isinstance(max_polls, bool)
        or not isinstance(max_polls, int)
        or not 1 <= max_polls <= 600
    ):
        raise ExecutionCoordinatorError(
            "max_polls must be an integer between 1 and 600"
        )
    if (
        isinstance(poll_seconds, bool)
        or not isinstance(poll_seconds, (int, float))
        or not 0 <= poll_seconds <= 30
    ):
        raise ExecutionCoordinatorError("poll_seconds must be between 0 and 30")
    return max_polls, float(poll_seconds)


def _outcome(
    identifier: str,
    state: str,
    reason: str,
    *,
    polls: int,
    actions: list[dict[str, Any]],
    status: dict[str, Any] | None,
    error: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": 1,
        "kind": "agent_workspace_candidate_coordinator",
        "workspace_id": identifier,
        "state": state,
        "reason": reason,
        "polls": polls,
        "actions": list(actions),
        "status": status,
        "owns_state_store": False,
        "adoption_performed": False,
        "publication_performed": False,
    }
    if error is not None:
        result["error"] = error
    return result


def _terminal_decision(state: str, reason: str) -> dict[str, str]:
    return {"action": "return", "state": state, "reason": reason}


def _workspace_gate(status: dict[str, Any]) -> dict[str, str] | None:
    if status.get("ownership_mode") != WORK_LANE_OWNERSHIP:
        return _terminal_decision("blocked", "lane_backed_workspace_required")
    if status.get("closed") is True:
        return _terminal_decision("closed", "workspace_already_closed")
    if status.get("creation_ready") is not True:
        return _terminal_decision("reconcile_required", "workspace_creation_not_ready")
    if status.get("route_evidence_complete") is not True:
        return _terminal_decision("blocked", "route_evidence_incomplete")
    return None


def _intent_decision(
    status: dict[str, Any], revision_bound: bool
) -> dict[str, str] | None:
    intents = status.get("task_start_intents")
    if not isinstance(intents, dict):
        return _terminal_decision("reconcile_required", "task_start_intents_invalid")
    if not intents:
        return None
    handoff = intents.get("writer_handoff")
    if (
        len(intents) == 1
        and isinstance(handoff, dict)
        and handoff.get("kind") == "candidate_revision"
        and revision_bound
    ):
        return {"action": "revision", "record_action": "candidate_revision_reconcile"}
    return _terminal_decision(
        "reconcile_required", "task_start_outcome_requires_reconciliation"
    )


def _writer_decision(status: dict[str, Any]) -> dict[str, str] | None:
    tasks = status.get("tasks")
    if not isinstance(tasks, dict):
        return _terminal_decision("reconcile_required", "workspace_task_state_invalid")
    writer = tasks.get("writer")
    if not isinstance(writer, dict) or writer.get("task_id") is None:
        return _terminal_decision("reconcile_required", "writer_task_missing")
    writer_state = str(writer.get("state", "unknown"))
    if writer_state in UNCERTAIN_TASK_STATES:
        return _terminal_decision(
            "reconcile_required", "writer_outcome_requires_reconciliation"
        )
    if writer.get("terminal") is not True:
        return {"action": "wait"}
    if writer_state != "completed":
        return _terminal_decision("blocked", "writer_failed_requires_explicit_recovery")
    return None


def _collection_decision(status: dict[str, Any]) -> dict[str, str] | None:
    collection = status.get("collection")
    if isinstance(collection, dict) and collection.get("state") == "complete":
        return None
    tasks = status.get("tasks")
    if not isinstance(tasks, dict):
        return _terminal_decision("reconcile_required", "workspace_task_state_invalid")
    read_roles = tuple(tasks.get(role) for role in READ_ONLY_ROLES)
    if any(
        isinstance(role, dict) and role.get("state") in UNCERTAIN_TASK_STATES
        for role in read_roles
    ):
        return _terminal_decision(
            "reconcile_required", "verification_role_outcome_requires_reconciliation"
        )
    if any(
        isinstance(role, dict)
        and role.get("task_id") is not None
        and role.get("terminal") is not True
        for role in read_roles
    ):
        return {"action": "wait"}
    return {"action": "collect"}


def _verified_decision(status: dict[str, Any], revision_bound: bool) -> dict[str, str]:
    revision = status.get("candidate_revision")
    if isinstance(revision, dict) and revision.get("eligible") is True:
        if not revision_bound:
            return _terminal_decision(
                "revision_required", "candidate_revision_command_not_bound"
            )
        return {"action": "revision", "record_action": "candidate_revision"}
    if status.get("success_ready") is not True:
        return _terminal_decision("blocked", "verification_not_passed")
    return {"action": "close"}


def reduce_status(status: dict[str, Any], *, revision_bound: bool) -> dict[str, str]:
    decision = _workspace_gate(status)
    if decision is not None:
        return decision
    decision = _intent_decision(status, revision_bound)
    if decision is not None:
        return decision
    decision = _writer_decision(status)
    if decision is not None:
        return decision
    decision = _collection_decision(status)
    if decision is not None:
        return decision
    return _verified_decision(status, revision_bound)


def _readback_after_unknown(
    identifier: str,
    action: str,
    exc: Exception,
    *,
    polls: int,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        status = workspace.grabowski_agent_workspace_status(identifier)
        readback_error = None
    except Exception as read_exc:  # pragma: no cover - exercised through result shape
        status = None
        readback_error = f"{type(read_exc).__name__}: {read_exc}"
    reason = f"{action}_outcome_requires_reconciliation"
    error = f"{type(exc).__name__}: {exc}"
    if readback_error is not None:
        reason = f"{action}_outcome_and_readback_unknown"
        error = f"{error}; readback={readback_error}"
    return _outcome(
        identifier,
        "reconcile_required",
        reason,
        polls=polls,
        actions=actions,
        status=status,
        error=error,
    )


def _collect_effect(
    identifier: str,
    *,
    polls: int,
    actions: list[dict[str, Any]],
    status: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        collected = workspace.grabowski_agent_workspace_collect(identifier)
    except Exception as exc:
        return _readback_after_unknown(
            identifier, "collect", exc, polls=polls, actions=actions
        )
    state = str(collected.get("state", "unknown"))
    actions.append({"action": "collect", "state": state})
    if state in COLLECT_PROGRESS_STATES:
        return None
    if state in COLLECT_UNKNOWN_STATES:
        return _outcome(
            identifier,
            "reconcile_required",
            "collection_outcome_requires_reconciliation",
            polls=polls,
            actions=actions,
            status=status,
        )
    return _outcome(
        identifier,
        "blocked",
        f"collection_blocked:{state}",
        polls=polls,
        actions=actions,
        status=status,
    )


def _revision_effect(
    identifier: str,
    revision_argv: list[str],
    record_action: str,
    *,
    polls: int,
    actions: list[dict[str, Any]],
    status: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        handoff = workspace.grabowski_agent_workspace_writer_handoff(
            identifier, revision_argv
        )
    except Exception as exc:
        return _readback_after_unknown(
            identifier, "candidate_revision", exc, polls=polls, actions=actions
        )
    state = str(handoff.get("state", "unknown"))
    actions.append({"action": record_action, "state": state})
    if state in REVISION_STARTED_STATES:
        return None
    return _outcome(
        identifier,
        "blocked",
        f"candidate_revision_blocked:{state}",
        polls=polls,
        actions=actions,
        status=status,
    )


def _close_bindings(status: dict[str, Any]) -> tuple[str, str, str] | None:
    collection = status.get("collection")
    if not isinstance(collection, dict):
        return None
    head = collection.get("writer_head")
    diff_sha256 = collection.get("diff_sha256")
    result_sha256 = collection.get("result_sha256")
    if not (
        isinstance(head, str)
        and SHA40_RE.fullmatch(head)
        and isinstance(diff_sha256, str)
        and SHA256_RE.fullmatch(diff_sha256)
        and isinstance(result_sha256, str)
        and SHA256_RE.fullmatch(result_sha256)
    ):
        return None
    return head, diff_sha256, result_sha256


def _close_effect(
    identifier: str,
    *,
    polls: int,
    actions: list[dict[str, Any]],
    status: dict[str, Any],
) -> dict[str, Any]:
    bindings = _close_bindings(status)
    if bindings is None:
        return _outcome(
            identifier,
            "reconcile_required",
            "collection_close_binding_invalid",
            polls=polls,
            actions=actions,
            status=status,
        )
    head, diff_sha256, result_sha256 = bindings
    try:
        closed = workspace.grabowski_agent_workspace_close(
            identifier,
            expected_head=head,
            expected_diff_sha256=diff_sha256,
            expected_result_sha256=result_sha256,
            cancel_running=False,
            remove_tmux_session=True,
            abandon_failed_roles=False,
        )
    except Exception as exc:
        return _readback_after_unknown(
            identifier, "close", exc, polls=polls, actions=actions
        )
    receipt = closed.get("close_receipt")
    receipt_state = receipt.get("state") if isinstance(receipt, dict) else None
    actions.append({"action": "close", "state": receipt_state})
    try:
        readback = workspace.grabowski_agent_workspace_status(identifier)
    except Exception as exc:
        return _outcome(
            identifier,
            "reconcile_required",
            "close_readback_failed",
            polls=polls,
            actions=actions,
            status=None,
            error=f"{type(exc).__name__}: {exc}",
        )
    terminal = bool(
        isinstance(receipt, dict)
        and receipt.get("state") == "complete"
        and receipt.get("closure_outcome") == "successful"
        and readback.get("closed") is True
    )
    return _outcome(
        identifier,
        "verified_candidate_closed" if terminal else "reconcile_required",
        "candidate_verified_and_workspace_closed"
        if terminal
        else "close_not_proven_terminal",
        polls=polls,
        actions=actions,
        status=readback,
    )


def _apply_decision(
    identifier: str,
    decision: dict[str, str],
    status: dict[str, Any],
    revision_argv: list[str] | None,
    *,
    poll: int,
    max_polls: int,
    poll_seconds: float,
    sleeper: Callable[[float], None],
    actions: list[dict[str, Any]],
) -> dict[str, Any] | None:
    action = decision["action"]
    if action == "return":
        return _outcome(
            identifier,
            decision["state"],
            decision["reason"],
            polls=poll,
            actions=actions,
            status=status,
        )
    if action == "wait":
        if poll < max_polls and poll_seconds:
            sleeper(poll_seconds)
        return None
    if action == "collect":
        return _collect_effect(identifier, polls=poll, actions=actions, status=status)
    if action == "revision":
        if revision_argv is None:
            raise ExecutionCoordinatorError("revision decision lost its argv binding")
        return _revision_effect(
            identifier,
            revision_argv,
            decision["record_action"],
            polls=poll,
            actions=actions,
            status=status,
        )
    if action == "close":
        return _close_effect(identifier, polls=poll, actions=actions, status=status)
    raise ExecutionCoordinatorError(f"unsupported coordinator action: {action}")


def run_workspace_candidate_coordinator(
    workspace_id: str,
    *,
    revision_argv: list[str] | None = None,
    max_polls: int = 120,
    poll_seconds: float = 1.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Advance one lane-backed workspace without creating another work-state truth."""
    identifier = _required_workspace_id(workspace_id)
    revision_command = _revision_command(revision_argv)
    poll_limit, poll_delay = _poll_config(max_polls, poll_seconds)
    actions: list[dict[str, Any]] = []
    last_status: dict[str, Any] | None = None
    for poll in range(1, poll_limit + 1):
        try:
            status = workspace.grabowski_agent_workspace_status(identifier)
        except Exception as exc:
            return _outcome(
                identifier,
                "reconcile_required",
                "workspace_status_unobservable",
                polls=poll,
                actions=actions,
                status=None,
                error=f"{type(exc).__name__}: {exc}",
            )
        last_status = status
        decision = reduce_status(status, revision_bound=revision_command is not None)
        result = _apply_decision(
            identifier,
            decision,
            status,
            revision_command,
            poll=poll,
            max_polls=poll_limit,
            poll_seconds=poll_delay,
            sleeper=sleeper,
            actions=actions,
        )
        if result is not None:
            return result
    return _outcome(
        identifier,
        "pending",
        "poll_budget_exhausted_without_terminal_effect",
        polls=poll_limit,
        actions=actions,
        status=last_status,
    )

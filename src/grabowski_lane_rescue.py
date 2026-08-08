from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import json
from typing import Any

import grabowski_lane_closeout as closeout


SCHEMA_VERSION = 1
PLAN_KIND = "grabowski.lane_rescue_plan"
RECEIPT_KIND = "grabowski.lane_rescue_receipt"
FINAL_KIND = "grabowski.lane_rescue_finalization"

ACTION_ORDER = (
    "commit",
    "push",
    "create_pr",
    "update_pr",
    "merge",
    "deployment",
    "durable_followup",
)
MUTATING_ACTIONS = frozenset(ACTION_ORDER)
CONTROLLER_ONLY_ACTIONS = frozenset({"merge", "deployment"})
REPLAY_SAFE_STATUSES = frozenset(
    {
        "effects_applied",
        "outcome_unknown",
        "blocked_before_effect",
        "terminal",
        "observe",
        "readback_required",
    }
)

Adapter = Callable[[dict[str, Any]], Mapping[str, Any]]


class LaneRescueError(RuntimeError):
    pass


class LaneRescueInputError(ValueError):
    pass


class EffectNotApplied(LaneRescueError):
    """An adapter proves that it failed before producing its requested effect."""

    def __init__(self, action: str, detail: str = "") -> None:
        super().__init__(detail or f"{action} was not applied")
        self.action = action
        self.detail = detail or f"{action} was not applied"


class EffectOutcomeUnknown(LaneRescueError):
    """An adapter may have produced an effect but its response was lost."""

    def __init__(self, action: str, detail: str = "") -> None:
        super().__init__(detail or f"{action} outcome is unknown")
        self.action = action
        self.detail = detail or f"{action} outcome is unknown"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _lane_assessment(
    observation: closeout.LaneCloseoutObservation,
    reader: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    lane_id = observation.lane_id
    if len(lane_id) == 32 and all(character in "0123456789abcdef" for character in lane_id):
        import grabowski_work_acquire as work_acquire
        record = reader(lane_id) if reader is not None else work_acquire._read_state(
            work_acquire._state_root() / f"{lane_id}.json"
        )
        if record is not None:
            if not isinstance(record, Mapping) or record.get("lane_id") != lane_id:
                raise LaneRescueInputError("persisted lane receipt is bound to another lane")
            terminal = work_acquire._terminal_closeout_assessment(dict(record))
            if terminal is not None:
                inputs = record.get("inputs")
                if not isinstance(inputs, Mapping):
                    raise LaneRescueInputError("persisted lane receipt inputs are missing")
                expected_identity = {
                    "repository": inputs.get("repo"),
                    "workspace": inputs.get("target_path"),
                    "branch": inputs.get("branch"),
                    "base_revision": inputs.get("base_head"),
                }
                observed_identity = {
                    "repository": observation.repository,
                    "workspace": observation.workspace,
                    "branch": observation.branch,
                    "base_revision": observation.base_revision,
                }
                if observed_identity != expected_identity:
                    raise LaneRescueInputError(
                        "persisted lane receipt identity does not match observation"
                    )
                return terminal
    return closeout.classify(observation)


def _identity(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise LaneRescueInputError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or normalized != value or len(normalized) > 512:
        raise LaneRescueInputError(f"{field} must be a bounded trimmed string")
    if any(character in normalized for character in "\r\n\x00"):
        raise LaneRescueInputError(f"{field} contains an invalid control character")
    return normalized


def _requested_actions(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise LaneRescueInputError("requested_actions must be a list or tuple")
    result: list[str] = []
    for value in values:
        action = _identity(value, "requested_action")
        if action not in MUTATING_ACTIONS:
            raise LaneRescueInputError(f"unsupported rescue action: {action}")
        if action not in result:
            result.append(action)
    return tuple(result)


def _readback_unknown(observation: closeout.LaneCloseoutObservation) -> bool:
    return bool(
        observation.readback_errors
        or observation.task_active is None
        or observation.process_active is None
        or observation.lease_active is None
        or observation.git_dirty is None
    )


def _derive_actions(
    observation: closeout.LaneCloseoutObservation,
    assessment: Mapping[str, Any],
) -> list[str]:
    if assessment.get("phase") != "rescue_required" or _readback_unknown(observation):
        return []

    actions: list[str] = []
    if observation.git_dirty is True:
        actions.append("commit")
    if (
        (observation.ahead_commits is not None and observation.ahead_commits > 0)
        or (
            observation.head_sha is not None
            and observation.remote_head_sha is not None
            and observation.head_sha != observation.remote_head_sha
        )
    ):
        actions.append("push")
    if observation.pr_state == "open" and observation.pr_head_sha != observation.head_sha:
        actions.append("update_pr")
    elif observation.pr_state is None and observation.no_change_proven is not True:
        actions.append("create_pr")
    elif observation.pr_state == "closed":
        actions.append("durable_followup")
    if not actions:
        actions.append("durable_followup")
    return [action for action in ACTION_ORDER if action in actions]


def build_plan(
    observation: closeout.LaneCloseoutObservation,
    *,
    lane_owner_id: str,
    requesting_owner_id: str,
    resource_keys: list[str] | tuple[str, ...],
    requested_actions: list[str] | tuple[str, ...] = (),
    controller_authorized_actions: list[str] | tuple[str, ...] = (),
    lane_receipt_reader: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Build a deterministic rescue plan without performing effects."""

    lane_owner = _identity(lane_owner_id, "lane_owner_id")
    requester = _identity(requesting_owner_id, "requesting_owner_id")
    if requester != lane_owner:
        raise LaneRescueInputError("requesting owner does not match the lane owner")
    if not isinstance(resource_keys, (list, tuple)) or not resource_keys:
        raise LaneRescueInputError("resource_keys must be a non-empty list or tuple")
    normalized_resources = sorted({_identity(item, "resource_key") for item in resource_keys})

    explicit_actions = _requested_actions(requested_actions)
    authorized = frozenset(_requested_actions(controller_authorized_actions))
    forbidden = sorted(set(explicit_actions) & CONTROLLER_ONLY_ACTIONS - authorized)
    if forbidden:
        raise LaneRescueInputError(
            "controller authorization is required for: " + ", ".join(forbidden)
        )

    assessment = _lane_assessment(observation, lane_receipt_reader)
    actions = _derive_actions(observation, assessment)
    for action in explicit_actions:
        if action not in actions:
            actions.append(action)
    actions = [action for action in ACTION_ORDER if action in actions]

    mode = (
        "terminal"
        if assessment.get("phase") == "terminal"
        else "observe"
        if assessment.get("phase") == "active"
        else "readback_required"
        if _readback_unknown(observation)
        else "execute"
    )
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "lane_id": observation.lane_id,
        "repository": observation.repository,
        "workspace": observation.workspace,
        "branch": observation.branch,
        "lane_owner_id": lane_owner,
        "resource_keys": normalized_resources,
        "assessment": assessment,
        "assessment_sha256": assessment.get("assessment_sha256") or closeout.sha256_json(assessment),
        "mode": mode,
        "actions": actions,
        "controller_authorized_actions": sorted(authorized),
        "handoff": {
            "next_role": (
                "controller"
                if mode in {"terminal", "observe", "readback_required"}
                else "scoped_writer"
            ),
            "lane_id": observation.lane_id,
            "workspace": observation.workspace,
            "branch": observation.branch,
            "required_readback": mode == "readback_required",
        },
        "non_claims": [
            "does not create a second lifecycle truth",
            "does not authorize mutation outside the exact resource keys",
            "does not establish terminal closeout before a fresh readback",
        ],
    }
    return {**material, "plan_sha256": _sha256(material)}


def _validate_receipt_integrity(receipt: Mapping[str, Any]) -> None:
    receipt_material = dict(receipt)
    receipt_material.pop("replayed", None)
    receipt_sha256 = receipt_material.pop("receipt_sha256", None)
    if not isinstance(receipt_sha256, str) or receipt_sha256 != _sha256(receipt_material):
        raise LaneRescueInputError("execution receipt integrity mismatch")


def _replay(
    prior_receipt: Mapping[str, Any] | None,
    plan_sha256: str,
) -> dict[str, Any] | None:
    if prior_receipt is None:
        return None
    if not isinstance(prior_receipt, Mapping):
        raise LaneRescueInputError("prior_receipt must be a mapping")
    _validate_receipt_integrity(prior_receipt)
    if prior_receipt.get("plan_sha256") != plan_sha256:
        raise LaneRescueInputError("prior receipt is bound to another rescue plan")
    if prior_receipt.get("status") not in REPLAY_SAFE_STATUSES:
        return None
    return {**dict(prior_receipt), "replayed": True}


def _receipt(plan: Mapping[str, Any], status: str, **fields: Any) -> dict[str, Any]:
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "plan_sha256": plan.get("plan_sha256"),
        "lane_id": plan.get("lane_id"),
        "status": status,
        **fields,
    }
    return {**material, "receipt_sha256": _sha256(material), "replayed": False}


def _controller_handoff(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **dict(plan.get("handoff") or {}),
        "next_role": "controller",
        "required_readback": True,
    }


def execute_plan(
    plan: Mapping[str, Any],
    *,
    actor_owner_id: str,
    adapters: Mapping[str, Adapter],
    prior_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one plan once; a matching receipt prevents duplicate effects."""

    if not isinstance(plan, Mapping) or plan.get("kind") != PLAN_KIND:
        raise LaneRescueInputError("plan has an invalid kind")
    plan_sha256 = plan.get("plan_sha256")
    if not isinstance(plan_sha256, str) or plan_sha256 != _sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    ):
        raise LaneRescueInputError("plan integrity mismatch")
    actor = _identity(actor_owner_id, "actor_owner_id")
    if actor != plan.get("lane_owner_id"):
        raise LaneRescueInputError("actor owner does not match the plan owner")

    replayed = _replay(prior_receipt, plan_sha256)
    if replayed is not None:
        return replayed

    mode = plan.get("mode")
    if mode in {"terminal", "observe", "readback_required"}:
        status = "terminal" if mode == "terminal" else str(mode)
        return _receipt(
            plan,
            status,
            effects=[],
            retry_authorized=False,
            readback_required=mode == "readback_required",
            handoff=plan.get("handoff"),
            closeout_state=(plan.get("assessment") or {}).get("closeout_state"),
            lease_release_ready=bool(
                (plan.get("assessment") or {}).get("lease_release_ready")
            ),
        )

    actions = list(plan.get("actions") or [])
    missing = [action for action in actions if not callable(adapters.get(action))]
    if missing:
        return _receipt(
            plan,
            "blocked_before_effect",
            effects=[],
            missing_adapters=missing,
            retry_authorized=True,
            readback_required=False,
            handoff=plan.get("handoff"),
            lease_release_ready=False,
        )

    effects: list[dict[str, Any]] = []
    for action in actions:
        payload = {
            "lane_id": plan.get("lane_id"),
            "repository": plan.get("repository"),
            "workspace": plan.get("workspace"),
            "branch": plan.get("branch"),
            "resource_keys": list(plan.get("resource_keys") or []),
            "plan_sha256": plan_sha256,
            "action": action,
        }
        input_sha256 = _sha256(payload)
        try:
            raw_result = adapters[action](payload)
        except EffectNotApplied as exc:
            status = "blocked_before_effect" if not effects else "outcome_unknown"
            return _receipt(
                plan,
                status,
                effects=effects,
                failed_action=action,
                failed_input_sha256=input_sha256,
                error_class=type(exc).__name__,
                error=exc.detail[:2048],
                retry_authorized=not effects,
                readback_required=bool(effects),
                handoff=plan.get("handoff") if not effects else _controller_handoff(plan),
                lease_release_ready=False,
            )
        except EffectOutcomeUnknown as exc:
            return _receipt(
                plan,
                "outcome_unknown",
                effects=effects,
                uncertain_action=action,
                uncertain_input_sha256=input_sha256,
                error=exc.detail[:2048],
                retry_authorized=False,
                readback_required=True,
                handoff=_controller_handoff(plan),
                lease_release_ready=False,
            )
        except Exception as exc:
            return _receipt(
                plan,
                "outcome_unknown",
                effects=effects,
                uncertain_action=action,
                uncertain_input_sha256=input_sha256,
                error_class=type(exc).__name__,
                error=str(exc)[:2048],
                retry_authorized=False,
                readback_required=True,
                handoff=_controller_handoff(plan),
                lease_release_ready=False,
            )

        if not isinstance(raw_result, Mapping):
            return _receipt(
                plan,
                "outcome_unknown",
                effects=effects,
                uncertain_action=action,
                uncertain_input_sha256=input_sha256,
                error_class="INVALID_ADAPTER_RESULT",
                error="adapter returned a non-mapping result",
                retry_authorized=False,
                readback_required=True,
                handoff=_controller_handoff(plan),
                lease_release_ready=False,
            )
        result = dict(raw_result)
        if result.get("outcome_unknown") is True:
            return _receipt(
                plan,
                "outcome_unknown",
                effects=effects,
                uncertain_action=action,
                uncertain_input_sha256=input_sha256,
                uncertain_result_sha256=_sha256(result),
                retry_authorized=False,
                readback_required=True,
                handoff=_controller_handoff(plan),
                lease_release_ready=False,
            )
        effects.append(
            {
                "action": action,
                "input_sha256": input_sha256,
                "result_sha256": _sha256(result),
                "domain_receipt_sha256": result.get("receipt_sha256"),
            }
        )

    return _receipt(
        plan,
        "effects_applied",
        effects=effects,
        retry_authorized=False,
        readback_required=True,
        handoff=_controller_handoff(plan),
        lease_release_ready=False,
    )


def finalize(
    observation: closeout.LaneCloseoutObservation,
    execution_receipt: Mapping[str, Any],
    *,
    lane_owner_id: str,
    requesting_owner_id: str,
    lane_receipt_reader: Callable[[str], Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Bind a fresh readback to the rescue receipt and decide release readiness."""

    owner = _identity(lane_owner_id, "lane_owner_id")
    requester = _identity(requesting_owner_id, "requesting_owner_id")
    if requester != owner:
        raise LaneRescueInputError("requesting owner does not match the lane owner")
    if not isinstance(execution_receipt, Mapping) or execution_receipt.get("kind") != RECEIPT_KIND:
        raise LaneRescueInputError("execution receipt has an invalid kind")
    _validate_receipt_integrity(execution_receipt)
    if execution_receipt.get("lane_id") != observation.lane_id:
        raise LaneRescueInputError("readback lane does not match the execution receipt")

    assessment = _lane_assessment(observation, lane_receipt_reader)
    terminal = assessment.get("phase") == "terminal"
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": FINAL_KIND,
        "lane_id": observation.lane_id,
        "lane_owner_id": owner,
        "execution_receipt_sha256": execution_receipt.get("receipt_sha256"),
        "assessment": assessment,
        "assessment_sha256": assessment.get("assessment_sha256") or closeout.sha256_json(assessment),
        "status": "terminal" if terminal else "readback_required",
        "closeout_state": assessment.get("closeout_state"),
        "lease_release_ready": bool(assessment.get("lease_release_ready")) if terminal else False,
        "workspace_cleanup_ready": bool(assessment.get("workspace_cleanup_ready")) if terminal else False,
        "retry_authorized": False,
    }
    return {**material, "finalization_sha256": _sha256(material)}

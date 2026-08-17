from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import re
import time
from typing import Any


SCHEMA_VERSION = 1
KIND = "grabowski.lane_closeout_assessment"
SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
TERMINAL_CLOSEOUT_STATES = frozenset(
    {
        "pr_opened",
        "pr_updated",
        "pr_merged",
        "deployed",
        "candidate_adopted",
        "no_change_proven",
        "blocked_with_durable_followup",
    }
)
WRITER_STATES = frozenset(
    {
        "launching",
        "running",
        "completed",
        "failed",
        "timed_out",
        "signalled",
        "cancelled",
        "outcome_unknown",
    }
)
ACTIVE_WRITER_STATES = frozenset({"launching", "running"})
TERMINAL_WRITER_STATES = WRITER_STATES - ACTIVE_WRITER_STATES
PR_STATES = frozenset({"open", "closed", "merged"})
PR_ORIGINS = frozenset({"opened", "updated"})
MAX_IDENTITY_LENGTH = 512

AuditAppender = Callable[[dict[str, Any]], str | None]


@dataclass(frozen=True)
class LaneCloseoutObservation:
    lane_id: str
    repository: str
    workspace: str
    branch: str
    base_revision: str
    writer_state: str
    task_active: bool | None
    process_active: bool | None
    lease_active: bool | None
    git_dirty: bool | None
    head_sha: str | None = None
    remote_head_sha: str | None = None
    ahead_commits: int | None = None
    behind_commits: int | None = None
    pr_number: int | None = None
    pr_state: str | None = None
    pr_head_sha: str | None = None
    pr_origin: str | None = None
    merged_sha: str | None = None
    deployed_sha: str | None = None
    no_change_proven: bool = False
    candidate_id: str | None = None
    adoption_receipt_sha256: str | None = None
    adoption_commit_sha: str | None = None
    durable_followup_id: str | None = None
    readback_errors: tuple[str, ...] = ()


class LaneCloseoutError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def validate_terminal_assessment(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an exact terminal assess() result before durable reuse."""
    if not isinstance(value, Mapping):
        raise LaneCloseoutError("terminal closeout assessment must be a mapping")
    if value.get("phase") != "terminal" or value.get("closeout_state") not in TERMINAL_CLOSEOUT_STATES:
        raise LaneCloseoutError("lane closeout assessment is not terminal")
    supplied = value.get("assessment_sha256")
    material = {
        key: item for key, item in value.items()
        if key not in {"assessment_sha256", "audit_record_sha256", "does_not_establish"}
    }
    if not isinstance(supplied, str) or SHA256.fullmatch(supplied) is None or supplied != sha256_json(material):
        raise LaneCloseoutError("terminal closeout assessment digest mismatch")
    return dict(value)


def _identity(value: Any, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_IDENTITY_LENGTH:
        raise ValueError(f"{field} must be a bounded non-empty string")
    if any(character in normalized for character in "\r\n\x00"):
        raise ValueError(f"{field} contains an invalid control character")
    return normalized


def _sha(value: Any, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase Git object id")
    return value


def _sha256(value: Any, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _boolean(value: Any, field: str, *, allow_null: bool = True) -> bool | None:
    if value is None:
        if allow_null:
            return None
        raise ValueError(f"{field} must be a boolean")
    if not isinstance(value, bool):
        raise ValueError(
            f"{field} must be a boolean" + (" or null" if allow_null else "")
        )
    return value


def _count(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer or null")
    return value


def _timestamp(value: int | None) -> int:
    result = int(time.time()) if value is None else value
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise ValueError("observed_at_unix must be a non-negative integer")
    return result


def _validated(observation: LaneCloseoutObservation) -> dict[str, Any]:
    writer_state = _identity(observation.writer_state, "writer_state")
    if writer_state not in WRITER_STATES:
        raise ValueError(f"unsupported writer_state: {writer_state}")
    pr_state = _identity(observation.pr_state, "pr_state", optional=True)
    if pr_state is not None and pr_state not in PR_STATES:
        raise ValueError(f"unsupported pr_state: {pr_state}")
    pr_origin = _identity(observation.pr_origin, "pr_origin", optional=True)
    if pr_origin is not None and pr_origin not in PR_ORIGINS:
        raise ValueError(f"unsupported pr_origin: {pr_origin}")
    if observation.pr_number is not None and (
        isinstance(observation.pr_number, bool)
        or not isinstance(observation.pr_number, int)
        or observation.pr_number < 1
    ):
        raise ValueError("pr_number must be a positive integer or null")
    errors: list[str] = []
    for value in observation.readback_errors:
        normalized = _identity(value, "readback_error")
        if normalized is not None:
            errors.append(normalized)
    data = {
        "lane_id": _identity(observation.lane_id, "lane_id"),
        "repository": _identity(observation.repository, "repository"),
        "workspace": _identity(observation.workspace, "workspace"),
        "branch": _identity(observation.branch, "branch"),
        "base_revision": _sha(observation.base_revision, "base_revision"),
        "writer_state": writer_state,
        "task_active": _boolean(observation.task_active, "task_active"),
        "process_active": _boolean(observation.process_active, "process_active"),
        "lease_active": _boolean(observation.lease_active, "lease_active"),
        "git_dirty": _boolean(observation.git_dirty, "git_dirty"),
        "head_sha": _sha(observation.head_sha, "head_sha", optional=True),
        "remote_head_sha": _sha(
            observation.remote_head_sha, "remote_head_sha", optional=True
        ),
        "ahead_commits": _count(observation.ahead_commits, "ahead_commits"),
        "behind_commits": _count(observation.behind_commits, "behind_commits"),
        "pr_number": observation.pr_number,
        "pr_state": pr_state,
        "pr_head_sha": _sha(
            observation.pr_head_sha, "pr_head_sha", optional=True
        ),
        "pr_origin": pr_origin,
        "merged_sha": _sha(
            observation.merged_sha, "merged_sha", optional=True
        ),
        "deployed_sha": _sha(
            observation.deployed_sha, "deployed_sha", optional=True
        ),
        # Terminal no-change closeout accepts only the exact boolean True.
        # Truthy non-booleans (e.g. "yes", 1) must not become terminal proof.
        "no_change_proven": _boolean(
            observation.no_change_proven, "no_change_proven", allow_null=False
        ),
        "candidate_id": _sha256(
            observation.candidate_id, "candidate_id", optional=True
        ),
        "adoption_receipt_sha256": _sha256(
            observation.adoption_receipt_sha256,
            "adoption_receipt_sha256",
            optional=True,
        ),
        "adoption_commit_sha": _sha(
            observation.adoption_commit_sha, "adoption_commit_sha", optional=True
        ),
        "durable_followup_id": _identity(
            observation.durable_followup_id,
            "durable_followup_id",
            optional=True,
        ),
        "readback_errors": sorted(set(errors)),
    }
    adoption_binding = (
        data["candidate_id"],
        data["adoption_receipt_sha256"],
        data["adoption_commit_sha"],
    )
    if any(value is not None for value in adoption_binding) and not all(
        value is not None for value in adoption_binding
    ):
        raise ValueError(
            "candidate adoption closeout requires candidate_id, "
            "adoption_receipt_sha256, and adoption_commit_sha together"
        )
    return data


def _terminal_result(
    data: Mapping[str, Any],
    closeout_state: str,
    reasons: list[str],
) -> dict[str, Any]:
    if closeout_state not in TERMINAL_CLOSEOUT_STATES:
        raise ValueError(f"invalid terminal closeout state: {closeout_state}")
    return {
        "phase": "terminal",
        "closeout_state": closeout_state,
        "action_required": False,
        "reason_codes": reasons,
        "recovery_actions": [],
        "lease_release_ready": closeout_state != "blocked_with_durable_followup",
        "workspace_cleanup_ready": False,
        "lane_id": data["lane_id"],
    }


def _rescue_result(
    data: Mapping[str, Any],
    reasons: list[str],
    actions: list[str],
) -> dict[str, Any]:
    ordered: list[str] = []
    for value in ["preserve_workspace_and_leases", *actions]:
        if value not in ordered:
            ordered.append(value)
    return {
        "phase": "rescue_required",
        "closeout_state": None,
        "action_required": True,
        "reason_codes": reasons,
        "recovery_actions": ordered,
        "lease_release_ready": False,
        "workspace_cleanup_ready": False,
        "lane_id": data["lane_id"],
    }


def classify(observation: LaneCloseoutObservation) -> dict[str, Any]:
    """Classify lane completion without performing Git, process, lease, or PR effects."""

    data = _validated(observation)
    reasons: list[str] = []
    actions: list[str] = []

    # Active liveness is higher priority than any terminal readback closeout.
    # A still-running writer/task/process must stay non-terminal active even when
    # readback failed and a durable followup id is already bound.
    if (
        data["writer_state"] in ACTIVE_WRITER_STATES
        or data["task_active"] is True
        or data["process_active"] is True
    ):
        return {
            "phase": "active",
            "closeout_state": None,
            "action_required": False,
            "reason_codes": ["writer_or_process_active"],
            "recovery_actions": [],
            "lease_release_ready": False,
            "workspace_cleanup_ready": False,
            "lane_id": data["lane_id"],
        }

    liveness_unknown = data["task_active"] is None or data["process_active"] is None
    if data["readback_errors"]:
        reasons.extend(f"readback_error:{value}" for value in data["readback_errors"])
        actions.append("refresh_git_task_process_and_pr_readback")
        # Unknown liveness with readback errors must never become terminal
        # blocked_with_durable_followup; only known-inactive liveness may.
        if liveness_unknown:
            if data["task_active"] is None:
                reasons.append("observation_unknown:task_active")
            if data["process_active"] is None:
                reasons.append("observation_unknown:process_active")
            actions.append("create_durable_followup")
            return _rescue_result(data, reasons, actions)
        if data["durable_followup_id"] is not None:
            return _terminal_result(
                data,
                "blocked_with_durable_followup",
                [*reasons, "durable_followup_bound"],
            )
        actions.append("create_durable_followup")
        return _rescue_result(data, reasons, actions)

    unknown = [
        field
        for field in (
            "task_active",
            "process_active",
            "lease_active",
            "git_dirty",
        )
        if data[field] is None
    ]
    if unknown:
        reasons.extend(f"observation_unknown:{field}" for field in unknown)
        actions.extend(
            ["refresh_git_task_process_and_pr_readback", "create_durable_followup"]
        )
        return _rescue_result(data, reasons, actions)

    head = data["head_sha"]
    remote = data["remote_head_sha"]
    pr_head = data["pr_head_sha"]

    if data["deployed_sha"] is not None:
        deploy_sources = {value for value in (head, data["merged_sha"]) if value}
        if data["deployed_sha"] in deploy_sources:
            # deployed is lease-release-ready only when the deployed head is
            # bound and the workspace is clean with zero unpushed commits.
            # Missing ahead observation, dirty, or ahead must not release.
            deployed_clean = (
                data["git_dirty"] is False and data["ahead_commits"] == 0
            )
            if deployed_clean:
                return _terminal_result(
                    data, "deployed", ["deployment_head_bound"]
                )
            if data["git_dirty"] is not False:
                reasons.append("valuable_dirty_state")
                actions.extend(
                    ["bind_successor_controller", "commit_validated_changes"]
                )
            if data["ahead_commits"] is None:
                reasons.append("ahead_count_unobserved")
                actions.append("refresh_git_branch_readback")
            elif data["ahead_commits"] > 0:
                reasons.append("unpushed_commits")
                actions.append("push_exact_branch_head")
        else:
            reasons.append("deployed_head_mismatch")
            actions.append("verify_deployment_and_repository_heads")

    if data["pr_state"] == "merged":
        head_bound_to_merged = (
            head is not None
            and data["merged_sha"] is not None
            and head == data["merged_sha"]
        )
        head_matches_pr = (
            head is not None and pr_head is not None and head == pr_head
        )
        merged_clean = (
            data["git_dirty"] is False and data["ahead_commits"] == 0
        )
        if (head_bound_to_merged or head_matches_pr) and merged_clean:
            return _terminal_result(data, "pr_merged", ["merged_pr_observed"])
        if head is None:
            reasons.append("merged_head_unbound")
            actions.append("verify_pr_and_workspace_heads")
        elif not head_bound_to_merged and not head_matches_pr:
            reasons.append("merged_head_mismatch")
            actions.append("verify_pr_and_workspace_heads")
        if data["git_dirty"] is not False:
            reasons.append("valuable_dirty_state")
            actions.extend(["bind_successor_controller", "commit_validated_changes"])
        if data["ahead_commits"] is None:
            reasons.append("ahead_count_unobserved")
            actions.append("refresh_git_branch_readback")
        elif data["ahead_commits"] > 0:
            reasons.append("unpushed_commits")
            actions.append("push_exact_branch_head")

    open_pr_complete = bool(
        data["pr_state"] == "open"
        and data["pr_number"] is not None
        and head is not None
        and remote == head
        and pr_head == head
        and data["git_dirty"] is False
        and data["ahead_commits"] == 0
    )
    if open_pr_complete:
        state = "pr_updated" if data["pr_origin"] == "updated" else "pr_opened"
        return _terminal_result(data, state, ["open_pr_exact_head_bound"])

    candidate_adoption_bound = bool(
        data["candidate_id"] is not None
        and data["adoption_receipt_sha256"] is not None
        and data["adoption_commit_sha"] is not None
    )
    if (
        candidate_adoption_bound
        and data["lease_active"] is True
        and data["git_dirty"] is False
        and head == data["adoption_commit_sha"]
    ):
        return _terminal_result(
            data,
            "candidate_adopted",
            ["candidate_adoption_receipt_bound"],
        )

    no_change_complete = bool(
        data["no_change_proven"] is True
        and data["git_dirty"] is False
        and data["ahead_commits"] == 0
        and (head == data["base_revision"] or head == remote)
    )
    if no_change_complete:
        return _terminal_result(data, "no_change_proven", ["no_change_exactly_proven"])

    if data["durable_followup_id"] is not None:
        return _terminal_result(
            data,
            "blocked_with_durable_followup",
            ["durable_followup_bound"],
        )

    if data["writer_state"] == "outcome_unknown":
        reasons.append("writer_outcome_unknown")
        actions.append("refresh_git_task_process_and_pr_readback")
    if data["git_dirty"] and "valuable_dirty_state" not in reasons:
        reasons.append("valuable_dirty_state")
        actions.extend(["bind_successor_controller", "commit_validated_changes"])
    if data["ahead_commits"] is None:
        if "ahead_count_unobserved" not in reasons:
            reasons.append("ahead_count_unobserved")
            actions.append("refresh_git_branch_readback")
    elif data["ahead_commits"] > 0:
        if "unpushed_commits" not in reasons:
            reasons.append("unpushed_commits")
            actions.append("push_exact_branch_head")
    if head is not None and remote is not None and remote != head:
        reasons.append("remote_head_mismatch")
        actions.append("push_or_reconcile_exact_branch_head")
    if data["pr_state"] == "open" and pr_head != head:
        reasons.append("pr_head_mismatch")
        actions.append("update_pr_to_exact_branch_head")
    if data["pr_state"] is None and data["no_change_proven"] is not True:
        reasons.append("pr_or_no_change_closeout_missing")
        actions.append("create_or_update_pr")
    if data["pr_state"] == "closed":
        reasons.append("pr_closed_without_terminal_integration")
        actions.append("create_durable_followup_or_replacement_pr")
    if data["writer_state"] in TERMINAL_WRITER_STATES and not reasons:
        reasons.append("terminal_writer_without_closeout_evidence")
        actions.append("refresh_git_task_process_and_pr_readback")
    actions.append("create_durable_followup")
    return _rescue_result(data, reasons, actions)


def assess(
    observation: LaneCloseoutObservation,
    *,
    observed_at_unix: int | None = None,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    data = _validated(observation)
    assessment = classify(observation)
    observed_at = _timestamp(observed_at_unix)
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "observed_at_unix": observed_at,
        "observation_sha256": sha256_json(data),
        **assessment,
    }
    assessment_sha256 = sha256_json(material)
    audit_record_sha256: str | None = None
    if append_audit is not None:
        value = append_audit(
            {
                "timestamp_unix": observed_at,
                "operation": "lane-closeout-assessment",
                **material,
                "assessment_sha256": assessment_sha256,
            }
        )
        if value is not None and (
            not isinstance(value, str) or SHA256.fullmatch(value) is None
        ):
            raise LaneCloseoutError("audit appender returned an invalid digest")
        audit_record_sha256 = value
    return {
        **material,
        "assessment_sha256": assessment_sha256,
        "audit_record_sha256": audit_record_sha256,
        "does_not_establish": [
            "process_signal_authority",
            "lease_release_authority",
            "workspace_cleanup_authority",
            "merge_or_deployment_authority",
        ],
    }

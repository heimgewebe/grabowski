from __future__ import annotations

import hashlib
import json
from typing import Any

import grabowski_friction
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

IMMUTABLE_BOUNDARIES = (
    "user_intent",
    "authorization",
    "secret_handling",
    "resource_leases",
    "recovery",
    "kill_switch",
    "review",
    "merge",
    "deployment",
    "privileged_execution",
)

ENTRY_SEQUENCE = (
    "read_live_runtime_and_connector_snapshot",
    "read_repository_head_dirty_state_and_leases",
    "classify_one_next_operation",
    "request_execution_shape_for_nontrivial_or_mutating_work",
    "perform_exactly_one_bounded_effect",
    "read_back_target_state",
    "record_truthful_outcome",
    "continue_only_from_observed_state",
)


def _stable_sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def call_shape_check(
    *,
    intent_count: int,
    command_count: int,
    expected_output_bytes: int,
    may_mutate: bool,
    transport_sensitive: bool,
    typed_tool_available: bool,
    post_state_read_available: bool,
) -> dict[str, Any]:
    values = {
        "intent_count": intent_count,
        "command_count": command_count,
        "expected_output_bytes": expected_output_bytes,
    }
    for label, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{label} must be an integer")
        if value < 0:
            raise ValueError(f"{label} must be non-negative")
    if intent_count > 32 or command_count > 64 or expected_output_bytes > 16 * 1024 * 1024:
        raise ValueError("call-shape input exceeds bounded limits")

    findings: list[str] = []
    if intent_count != 1:
        findings.append("multiple_or_missing_independent_intents")
    if command_count > 1:
        findings.append("multiple_commands_require_decomposition")
    if expected_output_bytes > 64 * 1024:
        findings.append("expected_output_requires_bounded_reads")
    if may_mutate and command_count != 1:
        findings.append("mutation_must_be_isolated")
    if may_mutate and not post_state_read_available:
        findings.append("mutation_requires_post_state_readback")
    if transport_sensitive and may_mutate:
        findings.append("transport_sensitive_mutation_requires_unknown_outcome_contract")
    if typed_tool_available is False:
        findings.append("no_typed_tool_available_consider_grip_or_durable_task")

    allowed = not any(
        finding in findings
        for finding in (
            "multiple_or_missing_independent_intents",
            "multiple_commands_require_decomposition",
            "mutation_must_be_isolated",
            "mutation_requires_post_state_readback",
        )
    )
    recommendation = "proceed_bounded" if allowed else "split_before_execution"
    result = {
        "schema_version": 1,
        "authority": "deterministic_advisory_linter",
        "execution_authorized": False,
        "allowed_shape": allowed,
        "recommendation": recommendation,
        "findings": findings,
        "retry_limit_after_operator_stop": 0,
        "unchanged_mutation_retry_allowed": False,
        "required_sequence": [
            "one_intent",
            "one_mutation_at_most",
            "bounded_output",
            "post_state_readback_after_mutation",
        ],
        "does_not_establish": [
            "permission_to_execute",
            "resource_lease_ownership",
            "policy_gate_satisfaction",
            "safe_mutation_retry",
        ],
    }
    result["shape_sha256"] = _stable_sha256(result)
    return result


def agent_bootstrap(*, friction_limit: int = 100, outcome_limit: int = 200) -> dict[str, Any]:
    if isinstance(friction_limit, bool) or not isinstance(friction_limit, int):
        raise ValueError("friction_limit must be an integer")
    if isinstance(outcome_limit, bool) or not isinstance(outcome_limit, int):
        raise ValueError("outcome_limit must be an integer")
    if not 1 <= friction_limit <= 500:
        raise ValueError("friction_limit must be between 1 and 500")
    if not 1 <= outcome_limit <= 1000:
        raise ValueError("outcome_limit must be between 1 and 1000")

    friction = grabowski_friction.friction_summary(limit=friction_limit)
    governor = grabowski_friction.execution_governor_summary(limit=outcome_limit)
    integrity_valid = bool(
        friction.get("event_log_integrity", {}).get("integrity_valid", True)
        and friction.get("decision_log", {}).get("integrity_valid", True)
        and governor.get("ledger_integrity_valid") is True
    )
    adaptive_enabled = integrity_valid and not any(
        candidate.get("circuit_breaker_open") is True
        for candidate in governor.get("candidates", [])
    )

    capsule = {
        "schema_version": 1,
        "authority": "proposal_only_agent_entry_capsule",
        "execution_authorized": False,
        "adaptive_mode": "shadow" if adaptive_enabled else "disabled_fail_closed",
        "automatic_live_routing_enabled": False,
        "entry_sequence": list(ENTRY_SEQUENCE),
        "call_rules": {
            "one_independent_intent_per_call": True,
            "split_broad_reads": True,
            "bounded_output_required": True,
            "prefer_typed_tool_then_grip_then_durable_task": True,
            "one_mutation_per_attempt": True,
            "post_state_readback_after_mutation": True,
            "operator_stop_retry_limit": 0,
            "unchanged_mutation_retry_allowed": False,
            "unknown_outcome_after_possible_mutation_transport_failure": True,
        },
        "immutable_boundaries": list(IMMUTABLE_BOUNDARIES),
        "adaptive_evidence": {
            "integrity_valid": integrity_valid,
            "friction_fingerprint_sha256": friction.get("fingerprint_sha256"),
            "governor_summary_sha256": governor.get("summary_sha256"),
            "minimum_evidence": governor.get("minimum_evidence"),
            "time_decay_seconds": governor.get("decay_seconds"),
            "live_promotions": governor.get("live_promotions", []),
            "eligible_risk_levels": ["low", "medium"],
            "excluded_risk_levels": ["high", "critical"],
        },
        "drift_contract": {
            "refresh_on_connector_or_release_change": True,
            "stale_capsule_may_not_authorize_execution": True,
            "missing_expected_tool_blocks_instead_of_guessing": True,
        },
        "learning_contract": {
            "learnable": [
                "typed_tool_preference",
                "read_batch_size",
                "output_bound",
                "durable_task_preference",
                "readback_shape",
            ],
            "promotion_requires_integrity": True,
            "promotion_requires_minimum_evidence": True,
            "promotion_requires_no_regression_signal": True,
            "promotion_is_reversible": True,
        },
        "does_not_establish": [
            "automatic_task_creation_authority",
            "automatic_policy_mutation_authority",
            "queue_or_claim_authority",
            "merge_or_deploy_permission",
            "resource_lease_ownership",
            "live_routing_promotion",
        ],
    }
    capsule["capsule_sha256"] = _stable_sha256(capsule)
    return capsule


@mcp.tool(name="grabowski_agent_bootstrap", annotations=READ_ONLY)
def grabowski_agent_bootstrap(friction_limit: int = 100, outcome_limit: int = 200) -> dict[str, Any]:
    """Return a bounded adaptive agent entry capsule for the current runtime evidence."""
    return agent_bootstrap(friction_limit=friction_limit, outcome_limit=outcome_limit)


@mcp.tool(name="grabowski_call_shape_check", annotations=READ_ONLY)
def grabowski_call_shape_check(
    intent_count: int,
    command_count: int,
    expected_output_bytes: int,
    may_mutate: bool = False,
    transport_sensitive: bool = False,
    typed_tool_available: bool = True,
    post_state_read_available: bool = True,
) -> dict[str, Any]:
    """Lint one proposed tool-call shape before execution without authorizing it."""
    return call_shape_check(
        intent_count=intent_count,
        command_count=command_count,
        expected_output_bytes=expected_output_bytes,
        may_mutate=may_mutate,
        transport_sensitive=transport_sensitive,
        typed_tool_available=typed_tool_available,
        post_state_read_available=post_state_read_available,
    )

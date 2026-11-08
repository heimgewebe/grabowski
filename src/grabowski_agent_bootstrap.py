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
    "read_chronik_history_for_explicit_target_if_available",
    "read_live_runtime_and_connector_snapshot",
    "read_repository_head_dirty_state_and_leases",
    "classify_one_next_operation",
    "discover_existing_capability_or_route",
    "read_adler_inbox_if_present",
    "read_relevant_historical_recall_when_high_value_or_repeat_signal",
    "request_execution_shape_for_nontrivial_or_mutating_work",
    "perform_exactly_one_bounded_effect",
    "read_back_target_state",
    "record_truthful_outcome",
    "continue_only_from_observed_state",
)

HISTORICAL_RECALL = {
    "authority": "advisory_historical_evidence_only",
    "tool": "grabowski_operator_historical_recall",
    "exact_search_tool": "grabowski_chronik_full_search",
    "exact_search_selectors": ["pr_number", "bureau_task_id", "run_id", "task_id", "event_id"],
    "mode": "target_first_fail_open_then_selective_patterns",
    "trigger_profiles": ["repository", "service_status", "failure_continuation", "pr", "bureau", "deployment"],
    "trigger_signals": [
        "retry",
        "recovery",
        "repeated_failure",
        "re_review",
        "repeat_deploy",
    ],
    "skip_for": ["unbound_nonproject_task", "trivial_read_without_relevant_target"],
    "selection_order": [
        "read_chronik_first_for_explicit_target_before_live_interpretation",
        "bind_target_from_fresh_live_context",
        "prefer_full_search_for_exact_or_cross_project_history",
        "filter_host_scoped_project_events_by_subject_component_not_source_repo",
        "check_exhaustive_integrity_before_concluding_no_record",
        "use_bounded_historical_recall_only_for_pattern_summaries",
        "discard_nonmatching_or_unbound_history",
        "continue_from_fresh_live_truth",
    ],
    "requirements": [
        "bound_chronik_first_precedes_live_status_interpretation",
        "fresh_live_truth_precedes_every_effect",
        "history_must_be_evidence_bound",
        "history_must_remain_historical_only",
        "full_search_cursors_are_bound_to_snapshot_and_must_restart_when_stale",
        "missing_record_is_not_evidence_that_work_never_occurred",
        "fresh_owning_authority_must_be_rechecked_before_effect",
    ],
    "does_not_establish": [
        "current_truth",
        "safe_retry",
        "routing_authority",
        "policy_authority",
        "merge_readiness",
        "deployment_authorization",
        "bureau_publication_authority",
        "task_completion",
    ],
}

ADLER_SIDECAR = {
    "authority": "advisory_evidence_only",
    "path": ".adler/inbox.json",
    "on_lane_entry": "read_if_present",
    "before_commit": "reread_if_present",
    "absence_semantics": "unknown_not_no_findings",
    "failure_semantics": "local_reversible_work_may_continue",
    "requirements": [
        "consider_present_findings_as_advisory_evidence",
        "do_not_infer_no_findings_from_missing_inbox",
        "reread_present_inbox_before_commit",
    ],
    "does_not_establish": [
        "work_authority",
        "blocking_authority",
        "acknowledgement_or_delivery_state",
        "finding_freshness_beyond_the_inbox_checkpoint",
    ],
}


REUSE_BEFORE_BUILD = {
    "authority": "discovery_order_only",
    "ordered_discovery": [
        "native_typed_surface",
        "host_capability_locator_if_host_local_and_no_native_surface",
        "declared_specialized_route_if_non_host_or_host_not_found",
        "live_readiness_of_selected_authority",
    ],
    "host_capability_tool": "grabowski_host_capability_resolve",
    "new_infrastructure_gate": "only_when_no_existing_authority_or_declared_route_is_found",
    "invariants": [
        "not_ready_is_not_not_found",
        "not_ready_requires_existing_authority_recovery_not_parallel_replacement",
        "host_capability_blocked_stops_host_local_discovery",
        "non_host_intent_does_not_require_host_contract",
        "discovery_does_not_authorize_execution",
        "do_not_duplicate_existing_control_plane",
    ],
    "creation_triggers": [
        "virtualenv",
        "package_install",
        "model_or_download_cache",
        "local_service",
        "worker",
        "browser_or_gui_replacement",
        "device_bridge",
        "transfer_path",
        "provider_integration",
        "cloud_fallback",
    ],
}


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



def _chronik_first_context(
    *, repo: str = "", host: str = "", subject_component: str = "",
    pr_number: int | None = None, task_id: str = "", search_fn: Any = None,
) -> dict[str, Any]:
    """Read bounded Chronik evidence without losing host-scoped project history."""
    targets = {"repo": repo, "host": host, "subject_component": subject_component, "task_id": task_id}
    filters: dict[str, Any] = {}
    for key, value in targets.items():
        if not isinstance(value, str) or len(value) > 160 or "\x00" in value:
            raise ValueError(f"invalid Chronik target {key}")
        if value:
            filters[key] = value
    if pr_number is not None:
        if type(pr_number) is not int or not 1 <= pr_number <= 2_147_483_647:
            raise ValueError("invalid Chronik PR number")
        if not repo and not subject_component:
            raise ValueError("Chronik PR number needs repository/component binding")
        filters["pr_number"] = pr_number
    base = {
        "schema_version": 1,
        "historical_only": True,
        "authority": "chronik_advisory_historical_evidence",
        "filters": filters,
        "does_not_establish": [
            "current_git_ci_or_runtime_state", "safe_retry",
            "merge_or_deployment_authority", "task_completion",
        ],
    }
    if not filters:
        return {**base, "status": "skipped_unbound_target", "events": []}

    # repo matches source.repo OR subject.repo in the Chronik provider.
    # Host-scoped producer events identify the project by subject.component,
    # not subject.repo. Both scopes must be searched separately.
    queries: list[tuple[str, dict[str, Any]]] = []
    if repo and not task_id:
        repository_query: dict[str, Any] = {"repo": repo}
        if pr_number is not None:
            repository_query["pr_number"] = pr_number
        queries.append(("repository", repository_query))
        component_query: dict[str, Any] = {
            "subject_component": subject_component or repo.split("/", 1)[-1],
        }
        if host:
            component_query["host"] = host
        if pr_number is not None:
            component_query["pr_number"] = pr_number
        queries.append(("host_component", component_query))
    elif repo and task_id:
        # A unique task identity crosses host/repository event scopes.
        queries.append(("exact_task", {"task_id": task_id}))
    else:
        queries.append(("exact_target", filters))

    if search_fn is None:
        try:
            from grabowski_tasks import grabowski_chronik_full_search
        except Exception as exc:
            return {
                **base, "status": "historical_context_unavailable",
                "failure_code": type(exc).__name__,
                "failed_scope": "provider_import", "events": [],
            }
        search_fn = grabowski_chronik_full_search

    results: list[tuple[str, dict[str, Any]]] = []
    for scope, query in queries:
        try:
            result = search_fn(**query, limit=10)
        except Exception as exc:
            return {
                **base, "status": "historical_context_unavailable",
                "failure_code": type(exc).__name__, "failed_scope": scope,
                "events": [],
            }
        if not isinstance(result, dict) or result.get("available") is not True:
            failure = result.get("failure") if isinstance(result, dict) else None
            return {
                **base, "status": "historical_context_unavailable",
                "failure_code": (
                    result.get("failure_code")
                    or (failure.get("code") if isinstance(failure, dict) else None)
                    or "provider_unavailable"
                ) if isinstance(result, dict) else "invalid_provider_result",
                "failed_scope": scope, "events": [],
            }
        snapshot = result.get("ledger_snapshot")
        if (
            result.get("historical_only") is not True
            or result.get("search_exhaustive") is not True
            or not isinstance(snapshot, dict)
            or snapshot.get("integrity_valid") is not True
            or snapshot.get("invalid_record_count") != 0
        ):
            return {
                **base, "status": "historical_context_unavailable",
                "failure_code": "historical_evidence_not_verified",
                "failed_scope": scope, "events": [],
            }
        results.append((scope, result))

    compact: list[dict[str, Any]] = []
    seen: set[str] = set()
    discarded = 0
    heuristic_host_matches = 0
    for scope, result in results:
        for index, item in enumerate((result.get("events") or [])[:10]):
            if not isinstance(item, dict) or not isinstance(item.get("event"), dict):
                continue
            event = item["event"]
            subject = event.get("subject") if isinstance(event.get("subject"), dict) else {}
            match_basis = "exact_target"
            if repo:
                if subject.get("scope") == "repository" and subject.get("repo") == repo:
                    match_basis = "subject_repository"
                elif (
                    subject.get("scope") == "host"
                    and subject.get("repo") is None
                    and subject.get("component") == (
                        subject_component or repo.split("/", 1)[-1]
                    )
                    and (not host or subject.get("host") == host)
                    and (pr_number is None or subject.get("pr_number") == pr_number)
                ):
                    match_basis = "host_component_heuristic"
                elif scope == "exact_task" and subject.get("repo") is None:
                    # Keep exact task evidence, but never claim repo attribution.
                    match_basis = "exact_task_unattributed"
                else:
                    discarded += 1
                    continue
            elif host and subject.get("host") not in {host, None}:
                discarded += 1
                continue
            key = (
                item.get("event_ref") or event.get("event_id")
                or item.get("canonical_event_sha256")
                or f"{scope}:{index}"
            )
            if key in seen:
                continue
            seen.add(key)
            data = event.get("data") if isinstance(event.get("data"), dict) else {}
            source = event.get("source") if isinstance(event.get("source"), dict) else {}
            refs = event.get("evidence_refs")
            compact.append({
                "event_ref": item.get("event_ref"),
                "canonical_event_sha256": item.get("canonical_event_sha256"),
                "observed_at": event.get("ts"),
                "kind": event.get("kind"),
                "operation": data.get("operation"),
                "outcome": data.get("result"),
                "task_class": data.get("task_class"),
                "source_run_id": source.get("run_id"),
                "evidence_refs": refs[:4] if isinstance(refs, list) else [],
                "match_basis": match_basis,
            })
            if match_basis in {"host_component_heuristic", "exact_task_unattributed"}:
                heuristic_host_matches += 1

    snapshots = {
        scope: result["ledger_snapshot"].get("sha256")
        for scope, result in results
    }
    snapshot_values = list(snapshots.values())
    snapshots_consistent = len(set(snapshot_values)) <= 1
    any_more = any(result.get("has_more") is True for _, result in results)
    selection_truncated = len(compact) > 10
    context_gap = (
        "ledger_snapshot_changed_between_scopes" if not snapshots_consistent
        else "bounded_candidate_page_only" if any_more or selection_truncated
        else "host_component_attribution_heuristic" if heuristic_host_matches
        else None
    )
    completed = context_gap is None
    provider_counts = {
        scope: result.get("matching_count") for scope, result in results
    }
    provider_result_hashes = {
        scope: result.get("result_sha256") for scope, result in results
    }
    return {
        **base, "status": "available", "events": compact[:10],
        "selected_event_count": len(compact[:10]),
        "matching_count": len(compact) if completed else None,
        "provider_matching_count": (
            sum(value for value in provider_counts.values() if type(value) is int)
        ),
        "provider_matching_counts": provider_counts,
        "discarded_source_only_matches": discarded,
        "selection_complete": completed,
        "context_gap": context_gap,
        "has_more": any_more or selection_truncated,
        "snapshot_sha256": snapshot_values[0] if snapshots_consistent else None,
        "scope_snapshot_sha256": snapshots,
        # A multi-query aggregate is NOT a canonical provider result receipt.
        "result_sha256": results[0][1].get("result_sha256") if len(results) == 1 else None,
        "scope_result_sha256": provider_result_hashes,
        "scope_queries": [scope for scope, _ in queries],
    }


def _workspace_metrics_snapshot(limit: int) -> dict[str, Any]:
    """Defer heavyweight workspace observation from the synchronous entry capsule.

    Workspace observation refreshes durable task state and can therefore contend with
    the global task-mutation lock. Agent bootstrap is a frequent, read-only entry
    point and must not amplify that contention or hold deployment admission open.
    Detailed workspace evidence remains available through the dedicated observer.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("workspace metrics limit must be an integer")
    if not 1 <= limit <= 50:
        raise ValueError("workspace metrics limit must be between 1 and 50")
    body = {
        "schema_version": 1,
        "report_kind": "workspace_metrics_snapshot_deferred",
        "collection_mode": "deferred_to_dedicated_workspace_observer",
        "integrity_valid": False,
        "friction_fingerprint_sha256": None,
        "friction_fingerprint_unavailable_reason": (
            "workspace_metrics_deferred_from_synchronous_bootstrap"
        ),
        "requested_limit": limit,
        "current_cohort": None,
        "current_cohort_sample_size": 0,
        "automatic_live_routing_enabled": False,
        "recommended_tool": "grabowski_agent_workspace_optimize",
        "does_not_establish": [
            "workspace_metrics_integrity",
            "workspace_task_freshness",
            "workspace_cohort_completeness",
            "permission_to_execute",
        ],
    }
    return {**body, "snapshot_sha256": _stable_sha256(body)}


def agent_bootstrap(*, friction_limit: int = 100, outcome_limit: int = 200, repo: str = "", host: str = "", subject_component: str = "", pr_number: int | None = None, task_id: str = "") -> dict[str, Any]:
    if isinstance(friction_limit, bool) or not isinstance(friction_limit, int):
        raise ValueError("friction_limit must be an integer")
    if isinstance(outcome_limit, bool) or not isinstance(outcome_limit, int):
        raise ValueError("outcome_limit must be an integer")
    if not 1 <= friction_limit <= 500:
        raise ValueError("friction_limit must be between 1 and 500")
    if not 1 <= outcome_limit <= 1000:
        raise ValueError("outcome_limit must be between 1 and 1000")

    chronik_first = _chronik_first_context(repo=repo, host=host, subject_component=subject_component, pr_number=pr_number, task_id=task_id)
    friction = grabowski_friction.friction_summary(limit=friction_limit)
    governor = grabowski_friction.execution_governor_summary(limit=outcome_limit)
    workspace_metrics = _workspace_metrics_snapshot(
        min(outcome_limit, 50)
    )
    integrity_valid = bool(
        friction.get("event_log_integrity", {}).get("integrity_valid", True)
        and friction.get("decision_log", {}).get("integrity_valid", True)
        and governor.get("ledger_integrity_valid") is True
    )
    adaptive_enabled = integrity_valid and not any(
        candidate.get("circuit_breaker_open") is True
        for candidate in governor.get("candidates", [])
    )
    workspace_metrics_integrity_valid = workspace_metrics.get("integrity_valid") is True
    workspace_fingerprint = (
        workspace_metrics.get("friction_fingerprint_sha256")
        if workspace_metrics_integrity_valid
        else None
    )
    workspace_fingerprint_unavailable_reason = workspace_metrics.get(
        "friction_fingerprint_unavailable_reason"
    )
    if (
        not isinstance(workspace_fingerprint_unavailable_reason, str)
        or not workspace_fingerprint_unavailable_reason
    ):
        workspace_fingerprint_unavailable_reason = (
            None
            if workspace_metrics_integrity_valid
            else "workspace_metrics_integrity_invalid"
        )
    friction_fingerprint = friction.get("fingerprint_sha256") or workspace_fingerprint

    capsule = {
        "schema_version": 1,
        "authority": "proposal_only_agent_entry_capsule",
        "adaptive_mode": "shadow" if adaptive_enabled else "disabled_fail_closed",
        "automatic_live_routing_enabled": False,
        "entry_sequence": list(ENTRY_SEQUENCE),
        "chronik_first": chronik_first,
        "adler_sidecar": ADLER_SIDECAR,
        "historical_recall": HISTORICAL_RECALL,
        "reuse_before_build": REUSE_BEFORE_BUILD,
        "call_rules": {
            "one_independent_intent_per_call": True,
            "split_broad_reads": True,
            "bounded_output_required": True,
            "prefer_typed_tool_then_grip_then_durable_task": True,
            "reuse_existing_capability_before_new_infrastructure": True,
            "one_mutation_per_attempt": True,
            "post_state_readback_after_mutation": True,
            "operator_stop_retry_limit": 0,
            "unchanged_mutation_retry_allowed": False,
            "unknown_outcome_after_possible_mutation_transport_failure": True,
            "generic_sync_shell_composition_allowed": False,
            "generic_sync_known_wrapper_execution_allowed": False,
            "generic_sync_indirect_execution_detection_complete": False,
            "generic_sync_timeout_ceiling_seconds": 30,
            "generic_sync_output_ceiling_bytes": 64 * 1024,
            "client_selected_sync_timeout_allowed": False,
            "client_selected_sync_output_limit_allowed": False,
            "long_running_work_requires_durable_identity": True,
        },
        "enforced_runtime_boundaries": {
            "generic_sync_tools": [
                "grabowski_terminal_run",
                "grabowski_fleet_run",
            ],
            "shell_composition": "deny_before_process_start",
            "known_wrapper_execution": "deny_before_process_start",
            "arbitrary_indirect_execution": "not_claimed_detectable",
            "timeout_seconds_max": 30,
            "max_output_bytes": 64 * 1024,
            "limits_owned_by": "server",
            "client_selected_timeout_supported": False,
            "client_selected_output_limit_supported": False,
            "long_running_required_route": "durable_task",
            "large_read_required_route": "split_read",
            "internal_server_timeouts_retained": True,
        },
        "immutable_boundaries": list(IMMUTABLE_BOUNDARIES),
        "adaptive_evidence": {
            "integrity_valid": integrity_valid,
            "friction_fingerprint_sha256": friction_fingerprint,
            "generic_friction_fingerprint_sha256": friction.get("fingerprint_sha256"),
            "workspace_friction_fingerprint_sha256": workspace_fingerprint,
            "workspace_metrics_snapshot_sha256": workspace_metrics.get("snapshot_sha256"),
            "workspace_metrics_integrity_valid": workspace_metrics_integrity_valid,
            "workspace_current_cohort": workspace_metrics.get("current_cohort"),
            "workspace_current_cohort_sample_size": workspace_metrics.get(
                "current_cohort_sample_size", 0
            ),
            "workspace_fingerprint_unavailable_reason": (
                workspace_fingerprint_unavailable_reason
            ),
            "workspace_metrics_report_kind": workspace_metrics.get("report_kind"),
            "workspace_metrics_collection_mode": workspace_metrics.get(
                "collection_mode"
            ),
            "workspace_metrics_recommended_tool": workspace_metrics.get(
                "recommended_tool"
            ),
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
            "workspace_outcomes_are_cohort_bound": True,
            "quality_signals_do_not_count_as_platform_friction": True,
            "workspace_route_calibration_mode": "shadow_only",
        },
        "does_not_establish": [
            "execution_authority",
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
def grabowski_agent_bootstrap(friction_limit: int = 100, outcome_limit: int = 200, repo: str = "", host: str = "", subject_component: str = "", pr_number: int | None = None, task_id: str = "") -> dict[str, Any]:
    """Return a bounded adaptive agent entry capsule for the current runtime evidence."""
    return agent_bootstrap(friction_limit=friction_limit, outcome_limit=outcome_limit, repo=repo, host=host, subject_component=subject_component, pr_number=pr_number, task_id=task_id)


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

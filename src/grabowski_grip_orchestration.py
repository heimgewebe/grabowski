from __future__ import annotations

from typing import Any

import grabowski_merge_guard

CoreModule = Any


def run_mechanic_loop(core: CoreModule, spec: Any, parameters: dict[str, Any], receipt: dict[str, Any], runner: Any, github_runner: Any) -> dict[str, Any]:
    actions = core._mechanic_actions(parameters)
    continue_on_blocked = core._mechanic_bool(parameters, "continue_on_blocked", False)
    core._check(receipt, "normal-grips-only", "pass", ", ".join(action["action"] for action in actions))

    records: list[dict[str, Any]] = []
    stopped_after: int | None = None
    stopped_at_action: str | None = None
    any_child_not_passed = False
    for action in actions:
        child = core.run_grip(
            str(action["grip"]),
            dict(action["parameters"]),
            allow_mutation=bool(action["allow_mutation"]),
            command_runner=runner,
            github_runner=github_runner,
        )
        raw_child_receipt = child.get("receipt") if isinstance(child, dict) else None
        child_status: str | None = None
        child_receipt_sha: str | None = None
        child_receipt = raw_child_receipt if isinstance(raw_child_receipt, dict) else None
        child_error: str | None = None
        if child_receipt is None:
            child_error = f"actions[{action['index']}].child receipt is missing or invalid"
        else:
            raw_child_status = child_receipt.get("status")
            if not isinstance(raw_child_status, str):
                child_error = f"actions[{action['index']}].child receipt status is missing or invalid"
            else:
                child_status = raw_child_status
            raw_child_receipt_sha = child_receipt.get("receipt_sha256")
            if not core._is_sha256_hex(raw_child_receipt_sha):
                child_error = f"actions[{action['index']}].child receipt hash is missing or invalid"
            else:
                child_receipt_sha = raw_child_receipt_sha
        if child_error is not None:
            records.append(core._mechanic_child_error_record(action, child, error=child_error))
            any_child_not_passed = True
            if stopped_after is None:
                stopped_after = action["index"]
                stopped_at_action = str(action["action"])
            if not continue_on_blocked:
                break
            continue
        assert child_receipt is not None
        assert child_status is not None
        assert child_receipt_sha is not None
        mechanic_receipt = {
            "schema_version": 1,
            "role": "mechanic",
            "action": action["action"],
            "target": action["target"],
            "scope": action["scope"],
            "status": child_status,
            "child_receipt_sha256": child_receipt_sha,
            "receipt_path": action["receipt_path"],
            "does_not_establish": [
                "merge_readiness",
                "runtime_correctness",
                "review_completeness",
                "deployment_safety",
            ],
        }
        mechanic_receipt["receipt_sha256"] = core._mechanic_record_sha256(mechanic_receipt)
        record = {
            "index": action["index"],
            "action": action["action"],
            "grip": action["grip"],
            "effect": action["effect"],
            "target": action["target"],
            "scope": action["scope"],
            "risk_level": action["risk_level"],
            "allow_mutation": action["allow_mutation"],
            "receipt_path": action["receipt_path"],
            "receipt_sha256": mechanic_receipt["receipt_sha256"],
            "child_receipt_sha256": child_receipt_sha,
            "receipt_status": child_status,
            "receipt_phase": child_receipt.get("phase"),
            "envelope": action["envelope"],
            "mechanic_receipt": mechanic_receipt,
            "receipt": child_receipt,
            "output": child.get("output", {}),
        }
        records.append(record)
        if child_status != "passed":
            any_child_not_passed = True
            if stopped_after is None:
                stopped_after = action["index"]
                stopped_at_action = str(action["action"])
            if not continue_on_blocked:
                break

    scope_visible = all(isinstance(record.get("target"), dict) and isinstance(record.get("scope"), dict) for record in records)
    receipt_bound = all(core._is_sha256_hex(record.get("receipt_sha256")) for record in records)
    core._check(receipt, "scope-visible", "pass" if scope_visible else "fail", f"actions={len(records)}")
    core._check(receipt, "receipt-per-grip", "pass" if receipt_bound else "fail", f"actions={len(records)}")
    return {
        "schema_version": 1,
        "profile": "mechanic",
        "normal_action_allowlist": sorted(core.MECHANIC_NORMAL_GRIPS),
        "forbidden_effects": list(core.MECHANIC_FORBIDDEN_EFFECTS),
        "requested_action_count": len(actions),
        "executed_action_count": len(records),
        "status": "blocked" if any_child_not_passed else "passed",
        "receipt_status": "blocked" if any_child_not_passed else "passed",
        "complete": not any_child_not_passed and len(records) == len(actions),
        "stopped_after": stopped_after,
        "stopped_at_index": stopped_after,
        "stopped_at_action": stopped_at_action,
        "continue_on_blocked": continue_on_blocked,
        "actions": records,
        "non_claims": [
            "does not expose generic shell execution",
            "does not run Captain-only high-impact actions",
            "does not bypass child grip receipts",
        ],
    }


def run_captain_preflight(core: CoreModule, spec: Any, parameters: dict[str, Any], receipt: dict[str, Any], runner: Any) -> dict[str, Any]:
    actions = core._captain_actions(parameters, gate_native_validation=True)
    core._mechanic_bool(parameters, "allow_execution", False)
    action_names = ", ".join(action["action"] for action in actions)
    gates, projection_info = core._captain_authority_gates(parameters, actions)
    blocked_reasons = core._captain_blocked_reasons(gates)
    all_gates_pass = not blocked_reasons
    autonomous_ready = core._captain_trusted_owner_autonomy_ready(parameters, actions)
    gate_decision = (
        "ready_for_autonomous_captain_execution"
        if all_gates_pass and autonomous_ready
        else "ready_for_manual_captain_decision"
        if all_gates_pass
        else "blocked"
    )
    manual_decision_candidate = all_gates_pass and not autonomous_ready
    autonomous_execution_candidate = all_gates_pass and autonomous_ready
    if all_gates_pass:
        blocked_reasons = ["captain_preflight_does_not_execute; use captain-run for execution"]
    for gate in gates:
        core._check(receipt, f"captain-gate-{gate['id']}", "pass" if gate["status"] == "pass" else "fail", str(gate["reason"]))
    gate_status = {str(gate["id"]): str(gate["status"]) for gate in gates}
    gate_reason = {str(gate["id"]): str(gate["reason"]) for gate in gates}
    core._check(receipt, "high-impact-marked", "pass", action_names)
    core._check(
        receipt,
        "recovery-or-irreversibility",
        "pass" if gate_status.get("recovery-or-irreversibility") == "pass" else "fail",
        gate_reason.get("recovery-or-irreversibility", "risk gate missing"),
    )
    core._check(
        receipt,
        "target-change-record",
        "pass" if gate_status.get("target-change-record") == "pass" else "fail",
        gate_reason.get("target-change-record", "target-change gate missing"),
    )
    return {
        "schema_version": 2,
        "profile": "captain",
        "decision": "blocked",
        "gate_decision": gate_decision,
        "manual_decision_candidate": manual_decision_candidate,
        "autonomous_execution_candidate": autonomous_execution_candidate,
        "status": "blocked",
        "receipt_status": "blocked",
        "blocked_reasons": blocked_reasons,
        "gates": gates,
        "status_projection": projection_info,
        "actions_sha256": core._captain_actions_sha256(actions),
        "authority_contract": core._captain_authority_contract("captain-preflight"),
        "high_impact_action_allowlist": sorted(core.CAPTAIN_HIGH_IMPACT_ACTIONS),
        "actions": [core._captain_action_record(action, gate_decision=gate_decision, projection_info=projection_info) for action in actions],
        "why_no_mutation": core.CAPTAIN_NO_MUTATION_REASON,
        "does_not_establish": list(core.CAPTAIN_DOES_NOT_ESTABLISH),
        "non_claims": list(core.CAPTAIN_NON_CLAIMS),
    }


def run_captain_run(core: CoreModule, spec: Any, parameters: dict[str, Any], receipt: dict[str, Any], runner: Any, github_runner: Any) -> dict[str, Any]:
    actions = core._captain_actions(parameters)
    allow_execution = core._mechanic_bool(parameters, "allow_execution", False)
    action_names = ", ".join(action["action"] for action in actions)
    gates, projection_info = core._captain_authority_gates(parameters, actions)
    blocked_reasons = core._captain_blocked_reasons(gates)
    if len(actions) != 1:
        blocked_reasons.append("captain_run_supports_exactly_one_action_in_v1")
    if not allow_execution:
        blocked_reasons.append("allow_execution_required")
    unsupported = [action["action"] for action in actions if action["action"] not in core.CAPTAIN_EXECUTABLE_ACTIONS]
    if unsupported:
        blocked_reasons.extend(f"captain_action_execution_not_implemented:{name}" for name in unsupported)
    intent_info, intent_errors = core._captain_execution_intent_review(parameters, actions)
    blocked_reasons.extend(intent_errors)
    if blocked_reasons:
        for gate in gates:
            core._check(receipt, f"captain-gate-{gate['id']}", "pass" if gate["status"] == "pass" else "fail", str(gate["reason"]))
        core._check(receipt, "captain-gates-pass", "fail", "; ".join(blocked_reasons))
        core._check(
            receipt,
            "execution-intent-bound",
            "fail" if intent_errors else "pass",
            "; ".join(intent_errors) if intent_errors else f"intent_sha256={intent_info['intent_sha256']}",
        )
        core._check(receipt, "receipt-bound-execution", "skip", "execution not attempted")
        return {
            "schema_version": 1,
            "profile": "captain",
            "decision": "blocked",
            "gate_decision": "blocked",
            "status": "blocked",
            "receipt_status": "blocked",
            "blocked_reasons": blocked_reasons,
            "gates": gates,
            "status_projection": projection_info,
            "execution_intent": intent_info,
            "actions_sha256": core._captain_actions_sha256(actions),
            "authority_contract": core._captain_authority_contract("captain-run"),
            "executable_action_allowlist": sorted(core.CAPTAIN_EXECUTABLE_ACTIONS),
            "actions": [
                core._captain_action_record(
                    action,
                    gate_decision="blocked",
                    projection_info=projection_info,
                    execution_intent_sha256=intent_info["intent_sha256"],
                )
                for action in actions
            ],
            "executions": [],
            "non_claims": list(core.CAPTAIN_NON_CLAIMS),
        }

    repo_path = core._captain_execution_cwd(parameters)
    executions: list[dict[str, Any]] = []
    action_records: list[dict[str, Any]] = []
    for action in actions:
        if action["action"] == "pr-merge":
            guarded_runner = grabowski_merge_guard.CaptainMergeGuardRunner(
                repo_path=repo_path,
                action=action,
                parameters=parameters,
                github_runner=github_runner,
                execution_intent_sha256=str(intent_info["intent_sha256"]),
                lease_owner_id=str(
                    parameters["execution_intent"]["context"].get("lease_owner_id", "")
                ),
                server_actor_identity=parameters.get("_server_runtime_actor_identity"),
            )
            execution_result: dict[str, Any] = {
                "action": "pr-merge",
                "repo": action["target"].get("repo"),
                "pr": action["target"].get("pr"),
                "execution_invoked": False,
                "execution_attempted": False,
                "command_returned": False,
                "remote_mutation_observed": False,
                "preflight_passed": False,
                "verification_passed": False,
            }
            try:
                if guarded_runner.static_errors:
                    execution_result.update(
                        {
                            "preflight_errors": list(guarded_runner.static_errors),
                            "verification_error": "merge lease guard static binding validation failed",
                        }
                    )
                else:
                    execution_result = core._run_captain_pr_merge(
                        repo_path, action, parameters, guarded_runner
                    )
            except Exception as exc:  # defensive cleanup boundary
                execution_result.update(
                    {
                        "execution_invoked": guarded_runner.dispatch_called,
                        "execution_attempted": guarded_runner.dispatch_called,
                        "command_returned": False,
                        "verification_passed": False,
                        "verification_error": "captain pr merge executor raised before receipt completion",
                        "executor_exception": f"{type(exc).__name__}: {core._bounded_command_output(str(exc), limit=512)}",
                    }
                )
            finally:
                guarded_runner.finalize(execution_result)
        elif action["action"] == "runtime-deploy":
            execution_result = core._run_captain_runtime_deploy(action, parameters)
        else:
            raise core.GripPreflightError(f"captain-run has no executor for {action['action']}")
        executions.append(execution_result)
        invoked = execution_result.get("execution_invoked") is True
        command_returned = execution_result.get("command_returned") is True
        verified = execution_result.get("verification_passed") is True
        cleanup_passed = execution_result.get("merge_guard_cleanup_passed") is not False
        operationally_complete = verified and cleanup_passed
        asynchronously_scheduled = (
            verified
            and execution_result.get("deployment_scheduled") is True
            and execution_result.get("deployment_completion_verified") is False
        )
        successful_decision = "scheduled" if asynchronously_scheduled else "executed"
        execution_label = (
            "scheduled"
            if asynchronously_scheduled
            else "performed"
            if command_returned
            else "attempt-failed"
            if invoked
            else "not-performed"
        )
        action_records.append(
            core._captain_action_record(
                action,
                gate_decision=(
                    successful_decision
                    if operationally_complete
                    else "executed_with_guard_cleanup_failure"
                    if verified
                    else "verification_failed_after_execution"
                    if invoked
                    else "blocked"
                ),
                projection_info=projection_info,
                status="passed" if operationally_complete else "failed" if invoked else "blocked",
                decision=(
                    successful_decision
                    if operationally_complete
                    else "executed_with_guard_cleanup_failure"
                    if verified
                    else "verification_failed_after_execution"
                    if invoked
                    else "blocked"
                ),
                execution=execution_label,
                execution_result=execution_result,
                execution_intent_sha256=intent_info["intent_sha256"],
                does_not_establish=core.CAPTAIN_EXECUTION_DOES_NOT_ESTABLISH if invoked else core.CAPTAIN_DOES_NOT_ESTABLISH,
            )
        )

    pre_execution_failures = [
        result for result in executions if result.get("execution_invoked") is not True
    ]
    verification_failures = [
        result
        for result in executions
        if result.get("execution_invoked") is True and result.get("verification_passed") is not True
    ]
    cleanup_failures = [
        result
        for result in executions
        if result.get("verification_passed") is True
        and result.get("merge_guard_cleanup_passed") is False
    ]
    if pre_execution_failures:
        receipt_status = "blocked"
        decision = "blocked"
    elif verification_failures:
        receipt_status = "failed"
        decision = "verification_failed_after_execution"
    elif cleanup_failures:
        receipt_status = "failed"
        decision = "executed_with_guard_cleanup_failure"
    else:
        receipt_status = "passed"
        decision = (
            "scheduled"
            if any(
                result.get("deployment_scheduled") is True
                and result.get("deployment_completion_verified") is False
                for result in executions
            )
            else "executed"
        )
    invoked_count = sum(1 for result in executions if result.get("execution_invoked") is True)
    command_returned_count = sum(1 for result in executions if result.get("command_returned") is True)
    attempted_count = sum(1 for result in executions if result.get("execution_attempted") is True)
    verified_count = sum(1 for result in executions if result.get("verification_passed") is True)
    cleanup_failed_count = len(cleanup_failures)
    for gate in gates:
        core._check(receipt, f"captain-gate-{gate['id']}", "pass", str(gate["reason"]))
    core._check(receipt, "captain-gates-pass", "pass", action_names)
    core._check(
        receipt,
        "execution-intent-bound",
        "pass",
        f"intent_sha256={intent_info['intent_sha256']} issued_at={intent_info['issued_at']}",
    )
    core._check(receipt, "trusted-owner-autonomy", "pass" if core._captain_trusted_owner_autonomy_ready(parameters, actions) else "warn", str(parameters.get("autonomy_policy") or "manual evidence mode"))
    core._check(receipt, "receipt-bound-execution", "pass", f"execution_records={len(executions)} invoked={invoked_count} command_returned={command_returned_count} attempted={attempted_count} verified={verified_count} cleanup_failed={cleanup_failed_count}")
    preflight_reasons = [
        reason
        for result in pre_execution_failures
        for reason in result.get("preflight_errors", [str(result.get("verification_error") or "pre-execution failure")])
    ]
    post_execution_reasons = [
        str(result.get("verification_error") or "post-execution verification failed")
        for result in verification_failures
    ]
    cleanup_reasons = [
        str(result.get("merge_guard_cleanup_error") or "merge guard cleanup failed")
        for result in cleanup_failures
    ]
    post_execution_reasons.extend(cleanup_reasons)
    if pre_execution_failures:
        core._check(receipt, "execution-preflight", "fail", "; ".join(preflight_reasons))
        core._check(receipt, "execution-attempted", "skip", "execution not attempted")
        core._check(receipt, "post-execution-verification", "skip", "execution not attempted")
    else:
        core._check(receipt, "execution-preflight", "pass", "execution preflight passed")
        core._check(receipt, "execution-attempted", "pass", f"invoked={invoked_count} command_returned={command_returned_count} attempted={attempted_count}")
        if verification_failures:
            core._check(
                receipt,
                "post-execution-verification",
                "fail",
                "; ".join(
                    str(result.get("verification_error") or "post-execution verification failed")
                    for result in verification_failures
                ),
            )
        else:
            core._check(
                receipt,
                "post-execution-verification",
                "pass",
                "all execution receipts verified within their declared verification scope",
            )
        core._check(
            receipt,
            "merge-guard-cleanup",
            "fail" if cleanup_failures else "pass",
            "; ".join(cleanup_reasons) if cleanup_reasons else "all required merge guard leases released",
        )
    return {
        "schema_version": 1,
        "profile": "captain",
        "decision": decision,
        "gate_decision": decision,
        "status": receipt_status,
        "receipt_status": receipt_status,
        "blocked_reasons": preflight_reasons,
        "failed_reasons": post_execution_reasons,
        "gates": gates,
        "status_projection": projection_info,
        "execution_intent": intent_info,
        "actions_sha256": core._captain_actions_sha256(actions),
        "authority_contract": core._captain_authority_contract("captain-run"),
        "executable_action_allowlist": sorted(core.CAPTAIN_EXECUTABLE_ACTIONS),
        "actions": action_records,
        "execution_counts": {
            "invoked_count": invoked_count,
            "command_returned_count": command_returned_count,
            "attempted_count": attempted_count,
            "verified_count": verified_count,
            "cleanup_failed_count": cleanup_failed_count,
        },
        "executions": executions,
        "non_claims": [
            "does not execute actions outside the explicit executable_action_allowlist",
            "does not bypass expected_head, expected_base_sha, review, diff, CI, status-projection or execution-intent gates",
            "does not establish semantic correctness beyond the observed execution receipt",
            "does not echo raw execution_intent, actor or context values; receipts carry only normalized fields and digests",
        ],
    }

from __future__ import annotations

from typing import Any, Callable, Mapping

import hashlib
import json
from pathlib import Path
import re

import grabowski_merge_guard

CoreModule = Any
ReceiptHasher = Callable[[Any], str]

CAPTAIN_GATE_DETAIL_MAX_ITEMS = 32
CAPTAIN_GATE_DETAIL_PREVIEW_LIMIT = 256


def _bounded_captain_gates(
    core: CoreModule,
    gates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bounded_gates: list[dict[str, Any]] = []
    for gate in gates:
        bounded_gate = dict(gate)
        details = bounded_gate.get("details")
        if (
            isinstance(details, (list, tuple))
            and all(isinstance(entry, (str, bytes)) for entry in details)
        ):
            bounded_details = [
                core._bounded_command_output(
                    entry,
                    limit=CAPTAIN_GATE_DETAIL_PREVIEW_LIMIT,
                )
                for entry in details
            ]
            if len(bounded_details) > CAPTAIN_GATE_DETAIL_MAX_ITEMS:
                visible = bounded_details[: CAPTAIN_GATE_DETAIL_MAX_ITEMS - 1]
                omitted = len(bounded_details) - len(visible)
                visible.append(f"...[truncated {omitted} gate details]")
                bounded_details = visible
            bounded_gate["details"] = bounded_details
        bounded_gates.append(bounded_gate)
    return bounded_gates


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
    gates = _bounded_captain_gates(core, gates)
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
        "errors": core._captain_error_records(blocked_reasons, phase="preflight"),
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


def run_captain_run(
    core: CoreModule,
    spec: Any,
    parameters: dict[str, Any],
    receipt: dict[str, Any],
    runner: Any,
    github_runner: Any,
    resource_authority: grabowski_merge_guard.MergeGuardResourceAuthority,
) -> dict[str, Any]:
    actions = core._captain_actions(parameters)
    allow_execution = core._mechanic_bool(parameters, "allow_execution", False)
    action_names = ", ".join(action["action"] for action in actions)
    gates, projection_info = core._captain_authority_gates(parameters, actions)
    gates = _bounded_captain_gates(core, gates)
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
            "errors": core._captain_error_records(blocked_reasons, phase="preflight"),
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
                resource_authority=resource_authority,
                execution_intent_sha256=str(intent_info["intent_sha256"]),
                lease_owner_id=str(
                    parameters["execution_intent"]["context"].get("lease_owner_id", "")
                ),
                server_actor_identity=parameters.get("_server_runtime_actor_identity"),
                server_task_lease_delegation=parameters.get(
                    "_server_task_lease_delegation"
                ),
                server_operator_lease_delegation=parameters.get(
                    "_server_operator_lease_delegation"
                ),
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
                "preflight_errors": [],
                "configured_automatic_platform_effects": [],
                "automatic_platform_effects": [],
                "effect_scope_decision": core._captain_effect_scope_not_evaluated(),
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
        "errors": [
            *core._captain_error_records(preflight_reasons, phase="execution-preflight"),
            *core._captain_error_records(post_execution_reasons, phase="post-verification"),
        ],
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


# Operator Saga v1 pure contract
SCHEMA_VERSION = 1
PLAN_KIND = "OperatorSagaPlan.v1"
RUN_KIND = "OperatorSagaRunReceipt.v1"
SETTLEMENT_KIND = "OperatorSagaSettlementReceipt.v1"
CAPTAIN_AUDIT_BINDING_KIND = "VerifiedCaptainAuditBinding.v1"
CAPTAIN_AUDIT_RESULT_REF_KIND = "VerifiedCaptainAuditResultRef.v1"
SAGA_RUN_RECEIPT_REF_KIND = "VerifiedSagaRunReceiptRef.v1"
SAGA_RUN_AUDIT_KIND = "grabowski_operator_saga_run_receipt_audit"
SAGA_RUN_AUDIT_OPERATION = "operator-saga-run-receipt"
SAGA_KINDS = frozenset({"pr-settlement", "runtime-deployment"})
PHASES = ("prepare", "plan", "apply", "readback", "settle")
SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
RUN_ID_RE = re.compile(r"BUR-RUN-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}\Z")
PR_MERGE_METHODS = frozenset({"merge", "squash", "rebase"})
GRABOWSKI_REPOSITORY = "heimgewebe/grabowski"
GRABOWSKI_DEPLOY_ADAPTER = "grabowski-self"
GRABOWSKI_RUNTIME_TARGET = "heim-pc"
MAX_IDEMPOTENCY_BYTES = 512
MAX_PLAN_BYTES = 131072
MAX_EVIDENCE_BYTES = 512000


class SagaError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SagaError("value is not canonical JSON") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _bounded_mapping(value: Any, field: str, *, max_bytes: int = MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SagaError(f"{field} must be an object")
    result = dict(value)
    if len(canonical_json_bytes(result)) > max_bytes:
        raise SagaError(f"{field} exceeds the bounded contract size")
    return result


def _text(value: Any, field: str, *, maximum_bytes: int = 1024) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise SagaError(f"{field} must be trimmed non-empty text")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise SagaError(f"{field} exceeds the bounded contract size")
    return value


def _sha40(value: Any, field: str) -> str:
    text = _text(value, field, maximum_bytes=40)
    if SHA40_RE.fullmatch(text) is None:
        raise SagaError(f"{field} must be a lowercase Git SHA")
    return text


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field, maximum_bytes=64)
    if SHA256_RE.fullmatch(text) is None:
        raise SagaError(f"{field} must be a lowercase SHA-256")
    return text


def _repository(value: Any, field: str = "target.repository") -> str:
    text = _text(value, field, maximum_bytes=220)
    if REPOSITORY_RE.fullmatch(text) is None:
        raise SagaError(f"{field} must be one concrete owner/repository")
    return text


def _repository_path(value: Any) -> str:
    text = _text(value, "target.repository_path", maximum_bytes=4096)
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise SagaError("target.repository_path must be absolute")
    return str(path)


def _branch(value: Any, field: str) -> str:
    text = _text(value, field, maximum_bytes=255)
    if (
        text.startswith(("-", "refs/"))
        or text.endswith(("/", ".", ".lock"))
        or ".." in text
        or "@{" in text
        or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in text)
        or any(segment in {"", ".", ".."} for segment in text.split("/"))
    ):
        raise SagaError(f"{field} must be a safe short branch name")
    return text


def _idempotency_key(value: Any) -> str:
    text = _text(value, "idempotency_key", maximum_bytes=MAX_IDEMPOTENCY_BYTES)
    if IDENTIFIER_RE.fullmatch(text) is None:
        raise SagaError("idempotency_key has an invalid format")
    return text


def _optional_bureau_run_id(value: Any) -> str | None:
    if value is None:
        return None
    text = _text(value, "target.bureau_run_id", maximum_bytes=128)
    if RUN_ID_RE.fullmatch(text) is None:
        raise SagaError("target.bureau_run_id is invalid")
    return text


def _normalize_pr_target(value: Any) -> dict[str, Any]:
    raw = _bounded_mapping(value, "target")
    allowed = {
        "repository_path",
        "repository",
        "pr",
        "base",
        "expected_head",
        "expected_base_sha",
        "expected_diff_sha256",
        "self_review_audit",
        "bureau_run_id",
        "merge_method",
    }
    unknown = sorted(set(raw) - allowed)
    required = {
        "repository_path",
        "repository",
        "pr",
        "base",
        "expected_head",
        "expected_base_sha",
        "expected_diff_sha256",
        "self_review_audit",
    }
    missing = sorted(required - set(raw))
    if unknown or missing:
        raise SagaError(f"pr-settlement target shape is invalid: missing={missing}; unknown={unknown}")
    pr = raw.get("pr")
    if type(pr) is not int or pr <= 0:
        raise SagaError("target.pr must be a positive integer")
    repository = _repository(raw.get("repository"))
    path = _repository_path(raw.get("repository_path"))
    base = _branch(raw.get("base"), "target.base")
    expected_head = _sha40(raw.get("expected_head"), "target.expected_head")
    expected_base_sha = _sha40(raw.get("expected_base_sha"), "target.expected_base_sha")
    expected_diff_sha256 = _sha256(
        raw.get("expected_diff_sha256"), "target.expected_diff_sha256"
    )
    self_review_audit = _bounded_mapping(
        raw.get("self_review_audit"), "target.self_review_audit"
    )
    bureau_run_id = _optional_bureau_run_id(raw.get("bureau_run_id"))
    merge_method = raw.get("merge_method")
    if merge_method is not None:
        merge_method = _text(merge_method, "target.merge_method", maximum_bytes=16)
        if merge_method not in PR_MERGE_METHODS:
            raise SagaError("target.merge_method is unsupported")
    return {
        "repository_path": path,
        "repository": repository,
        "pr": pr,
        "base": base,
        "expected_head": expected_head,
        "expected_base_sha": expected_base_sha,
        "expected_diff_sha256": expected_diff_sha256,
        "self_review_audit": self_review_audit,
        "bureau_run_id": bureau_run_id,
        "merge_method": merge_method,
    }


def _normalize_runtime_target(value: Any) -> dict[str, Any]:
    raw = _bounded_mapping(value, "target")
    allowed = {
        "repository_path",
        "repository",
        "adapter",
        "runtime_target",
        "expected_head",
        "source_repository",
        "source_lease_owner_id",
    }
    required = {"repository_path", "repository", "adapter", "runtime_target", "expected_head"}
    unknown = sorted(set(raw) - allowed)
    missing = sorted(required - set(raw))
    if unknown or missing:
        raise SagaError(f"runtime-deployment target shape is invalid: missing={missing}; unknown={unknown}")
    repository = _repository(raw.get("repository"))
    adapter = _text(raw.get("adapter"), "target.adapter", maximum_bytes=64)
    runtime_target = _text(raw.get("runtime_target"), "target.runtime_target", maximum_bytes=128)
    if repository != GRABOWSKI_REPOSITORY:
        raise SagaError("runtime-deployment is limited to the registered Grabowski repository")
    if adapter != GRABOWSKI_DEPLOY_ADAPTER:
        raise SagaError("runtime-deployment is limited to the registered grabowski-self adapter")
    if runtime_target != GRABOWSKI_RUNTIME_TARGET:
        raise SagaError("runtime-deployment is limited to the registered Heim-PC runtime target")
    source_repository = raw.get("source_repository")
    source_owner = raw.get("source_lease_owner_id")
    if (source_repository is None) != (source_owner is None):
        raise SagaError("source_repository and source_lease_owner_id must be supplied together")
    if source_repository is not None:
        source_repository = _repository_path(source_repository)
        source_owner = _text(source_owner, "target.source_lease_owner_id", maximum_bytes=128)
        if re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", source_owner) is None:
            raise SagaError("target.source_lease_owner_id is invalid")
    return {
        "repository_path": _repository_path(raw.get("repository_path")),
        "repository": repository,
        "adapter": adapter,
        "runtime_target": runtime_target,
        "expected_head": _sha40(raw.get("expected_head"), "target.expected_head"),
        "source_repository": source_repository,
        "source_lease_owner_id": source_owner,
    }


def normalize_target(saga_kind: Any, target: Any) -> tuple[str, dict[str, Any]]:
    kind = _text(saga_kind, "saga_kind", maximum_bytes=64)
    if kind not in SAGA_KINDS:
        raise SagaError(f"saga_kind must be one of {sorted(SAGA_KINDS)}")
    if kind == "pr-settlement":
        return kind, _normalize_pr_target(target)
    return kind, _normalize_runtime_target(target)


def _mechanic_action(
    action: str,
    *,
    parameters: dict[str, Any],
    target: dict[str, Any],
    receipt_name: str,
) -> dict[str, Any]:
    return {
        "action": action,
        "parameters": parameters,
        "allow_mutation": False,
        "target": target,
        "scope": {
            "allowed_effects": ["read"],
            "forbidden_effects": ["pr-merge", "runtime-deploy", "force-push", "privileged-broker-mutation"],
        },
        "receipt_path": f"receipts/sagas/{receipt_name}.json",
        "risk_level": "normal",
    }


def build_plan(saga_kind: Any, target: Any, idempotency_key: Any) -> dict[str, Any]:
    kind, normalized = normalize_target(saga_kind, target)
    key = _idempotency_key(idempotency_key)
    mechanic_actions: list[dict[str, Any]] = []
    if kind == "pr-settlement":
        bureau_run_id = normalized["bureau_run_id"]
        if bureau_run_id is not None:
            mechanic_actions.append(
                _mechanic_action(
                    "bureau-pickup-status",
                    parameters={"run_id": bureau_run_id},
                    target={"bureau_run_id": bureau_run_id},
                    receipt_name="bureau-pickup-status",
                )
            )
        mechanic_actions.append(
            _mechanic_action(
                "pr-check-readiness",
                parameters={
                    "repo": normalized["repository_path"],
                    "expected_head": normalized["expected_head"],
                    "expected_diff_sha256": normalized["expected_diff_sha256"],
                    "self_review_audit": normalized["self_review_audit"],
                },
                target={
                    "repository": normalized["repository"],
                    "pr": normalized["pr"],
                    "expected_head": normalized["expected_head"],
                },
                receipt_name="pr-check-readiness",
            )
        )
        captain_target = {
            "repo": normalized["repository"],
            "pr": normalized["pr"],
            "base": normalized["base"],
        }
        if normalized["merge_method"] is not None:
            captain_target["merge_method"] = normalized["merge_method"]
        expected_identity = {
            "repository": normalized["repository"],
            "pr": normalized["pr"],
            "base": normalized["base"],
            "expected_head": normalized["expected_head"],
            "expected_base_sha": normalized["expected_base_sha"],
            "expected_diff_sha256": normalized["expected_diff_sha256"],
        }
        captain_handoff = {
            "profile": "captain",
            "grip": "captain-run",
            "action": "pr-merge",
            "target": captain_target,
            "required_evidence_contract": "captain-run live action evidence schema",
            "required_parameters": [
                "expected_head",
                "expected_base_sha",
                "diff_sha256",
                "status_projection",
                "status_projection_sha256",
                "review_evidence",
                "ci_evidence",
                "execution_intent",
            ],
        }
        readback = {
            "surface": "grabowski_github",
            "operation": "pr-view",
            "required": {
                "state": "MERGED",
                "headRefOid": normalized["expected_head"],
            },
        }
    else:
        deploy_parameters: dict[str, Any] = {
            "adapter": normalized["adapter"],
            "expected_head": normalized["expected_head"],
        }
        if normalized["source_repository"] is not None:
            deploy_parameters.update(
                {
                    "source_repository": normalized["source_repository"],
                    "source_lease_owner_id": normalized["source_lease_owner_id"],
                }
            )
        mechanic_target = {
            "adapter": normalized["adapter"],
            "expected_head": normalized["expected_head"],
            "repo": normalized["repository"],
            "runtime_target": normalized["runtime_target"],
            "source_repository": normalized["source_repository"],
            "source_lease_owner_id": normalized["source_lease_owner_id"],
        }
        mechanic_actions.append(
            _mechanic_action(
                "runtime-deploy-check",
                parameters=deploy_parameters,
                target=mechanic_target,
                receipt_name="runtime-deploy-check",
            )
        )
        captain_target = {
            "repo": normalized["repository"],
            "runtime_target": normalized["runtime_target"],
            "adapter": normalized["adapter"],
        }
        if normalized["source_repository"] is not None:
            captain_target.update(
                {
                    "source_repository": normalized["source_repository"],
                    "source_lease_owner_id": normalized["source_lease_owner_id"],
                }
            )
        expected_identity = {
            "repository": normalized["repository"],
            "runtime_target": normalized["runtime_target"],
            "expected_head": normalized["expected_head"],
        }
        captain_handoff = {
            "profile": "captain",
            "grip": "captain-run",
            "action": "runtime-deploy",
            "target": captain_target,
            "required_evidence_contract": "captain-run live action evidence schema",
            "required_parameters": [
                "expected_head",
                "status_projection",
                "status_projection_sha256",
                "execution_intent",
            ],
        }
        readback = {
            "surface": "grabowski_deployment_identity",
            "operation": "deployment-identity",
            "required": {
                "identity.repo_head": normalized["expected_head"],
                "identity.completion_status": "complete",
                "serving_process.matches_deployed_manifest": True,
                "serving_process.serves_deployed_release": True,
            },
        }

    plan_body = {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "saga_kind": kind,
        "idempotency_key": key,
        "target": normalized,
        "scope": {
            "mechanic_grips": [item["action"] for item in mechanic_actions],
            "captain_action": captain_handoff["action"],
            "forbidden_effects_before_captain": [
                "pr-merge",
                "runtime-deploy",
                "force-push",
                "privileged-broker-mutation",
            ],
        },
        "expected_identity": expected_identity,
        "phases": [
            {"name": "prepare", "authority": "mechanic-loop", "steps": [item["action"] for item in mechanic_actions]},
            {"name": "plan", "authority": "saga", "steps": ["bind-target-scope-identity-idempotency"]},
            {"name": "apply", "authority": "captain-run", "steps": [captain_handoff["action"]]},
            {"name": "readback", "authority": "typed-read", "steps": [readback["surface"]]},
            {"name": "settle", "authority": "saga", "steps": ["bind-captain-receipt-and-live-readback"]},
        ],
        "mechanic_actions": mechanic_actions,
        "captain_handoff": captain_handoff,
        "readback_contract": readback,
        "retry_contract": {
            "prepare": "repeat only read-only child grips or re-plan after target identity changes",
            "apply": "never retry from a missing response; obtain authoritative target readback first",
            "readback": "read-only repetition is allowed",
            "settle": "read-only repetition is allowed while a scheduled deployment is still pending",
        },
        "does_not_establish": [
            "cross-system-atomicity",
            "captain-execution-authority",
            "merge-authority",
            "deployment-authority",
            "policy-bypass",
            "automatic-retry-authority",
        ],
    }
    if len(canonical_json_bytes(plan_body)) > MAX_PLAN_BYTES:
        raise SagaError("saga plan exceeds the bounded contract size")
    return {**plan_body, "plan_sha256": sha256_json(plan_body)}


def validate_plan(value: Any) -> dict[str, Any]:
    plan = _bounded_mapping(value, "plan", max_bytes=MAX_PLAN_BYTES + 128)
    expected = {
        "schema_version",
        "kind",
        "saga_kind",
        "idempotency_key",
        "target",
        "scope",
        "expected_identity",
        "phases",
        "mechanic_actions",
        "captain_handoff",
        "readback_contract",
        "retry_contract",
        "does_not_establish",
        "plan_sha256",
    }
    if set(plan) != expected:
        raise SagaError("saga plan shape is not canonical")
    rebuilt = build_plan(plan.get("saga_kind"), plan.get("target"), plan.get("idempotency_key"))
    if plan != rebuilt:
        raise SagaError("saga plan identity drifted")
    phase_names = tuple(item.get("name") for item in plan["phases"] if isinstance(item, dict))
    if phase_names != PHASES:
        raise SagaError("saga plan phases are incomplete or reordered")
    return rebuilt


def _validate_grip_result(
    value: Any,
    *,
    expected_grip: str,
    field: str,
    receipt_sha256_json: ReceiptHasher | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = _bounded_mapping(value, field)
    receipt = _bounded_mapping(result.get("receipt"), f"{field}.receipt")
    output = _bounded_mapping(result.get("output"), f"{field}.output")
    grip = receipt.get("grip")
    if (
        receipt.get("kind") != "grabowski.operator_grip_receipt"
        or receipt.get("schema_version") != 1
        or not isinstance(grip, Mapping)
        or grip.get("name") != expected_grip
    ):
        raise SagaError(f"{field} lacks a canonical {expected_grip} receipt")
    receipt_hasher = receipt_sha256_json or sha256_json
    receipt_sha = _sha256(receipt.get("receipt_sha256"), f"{field}.receipt.receipt_sha256")
    expected_receipt_sha = receipt_hasher(
        {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    )
    if receipt_sha != expected_receipt_sha:
        raise SagaError(f"{field} receipt digest mismatch")
    if result.get("receipt_sha256") != receipt_sha:
        raise SagaError(f"{field} top-level receipt digest mismatch")
    if receipt.get("output_sha256") != receipt_hasher(output):
        raise SagaError(f"{field} output digest mismatch")
    if result.get("status") != receipt.get("status"):
        raise SagaError(f"{field} status differs from its receipt")
    return receipt, output


def _child_semantically_ready(
    plan: dict[str, Any], planned: Mapping[str, Any], child_output: Mapping[str, Any]
) -> bool:
    if (
        plan.get("saga_kind") != "pr-settlement"
        or planned.get("action") != "pr-check-readiness"
    ):
        return True
    blocking_reasons = child_output.get("blocking_reasons")
    return (
        child_output.get("ready") is True
        and child_output.get("verdict") == "ready"
        and isinstance(blocking_reasons, list)
        and not blocking_reasons
    )


def is_saga_run_receipt_ref(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("kind") == SAGA_RUN_RECEIPT_REF_KIND
    )


def validate_saga_run_receipt_ref(value: Any) -> dict[str, Any]:
    ref = _bounded_mapping(value, "run_receipt")
    required = {"schema_version", "kind", "record_sha256"}
    if set(ref) != required:
        raise SagaError("run_receipt audit reference shape is not canonical")
    if ref.get("schema_version") != SCHEMA_VERSION:
        raise SagaError("run_receipt audit reference schema is unsupported")
    if ref.get("kind") != SAGA_RUN_RECEIPT_REF_KIND:
        raise SagaError("run_receipt audit reference kind is invalid")
    _sha256(ref.get("record_sha256"), "run_receipt.record_sha256")
    return ref


def is_captain_audit_result_ref(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("kind") == CAPTAIN_AUDIT_RESULT_REF_KIND
    )


def validate_captain_audit_result_ref(value: Any) -> dict[str, Any]:
    ref = _bounded_mapping(value, "captain_result")
    required = {
        "schema_version",
        "kind",
        "completion_record_sha256",
    }
    if set(ref) != required:
        raise SagaError("captain_result audit reference shape is not canonical")
    if ref.get("schema_version") != SCHEMA_VERSION:
        raise SagaError("captain_result audit reference schema is unsupported")
    if ref.get("kind") != CAPTAIN_AUDIT_RESULT_REF_KIND:
        raise SagaError("captain_result audit reference kind is invalid")
    _sha256(
        ref.get("completion_record_sha256"),
        "captain_result.completion_record_sha256",
    )
    return ref


def _verified_captain_audit_record(
    record_sha256: str,
    *,
    snapshot: Any,
    audit_query_module: Any,
) -> dict[str, Any]:
    wanted = _sha256(record_sha256, "Captain audit record SHA-256")
    needle = f'"record_sha256":"{wanted}"'.encode("ascii")
    for segment in reversed(snapshot.segments):
        try:
            data = (
                segment.captured_data
                if segment.captured_data is not None
                else audit_query_module._load_snapshot_segment(segment)
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise SagaError(
                f"verified Captain audit segment unavailable: {type(exc).__name__}"
            ) from exc
        if needle not in data:
            continue
        for raw_line in reversed(data.splitlines()):
            if needle not in raw_line:
                continue
            try:
                record = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SagaError("verified Captain audit record is not valid JSON") from exc
            if isinstance(record, dict) and record.get("record_sha256") == wanted:
                return record
    raise SagaError(
        f"Captain audit record is absent from the verified audit chain: {wanted}"
    )


def _verified_captain_audit_reference_identity(
    plan: dict[str, Any], audit_ref: dict[str, Any]
) -> dict[str, Any]:
    try:
        import grabowski_audit_query

        snapshot = grabowski_audit_query.capture_verified_audit_snapshot()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise SagaError(
            f"verified Captain audit snapshot unavailable: {type(exc).__name__}"
        ) from exc

    completion_sha = _sha256(
        audit_ref.get("completion_record_sha256"),
        "captain_result.completion_record_sha256",
    )
    completion = _verified_captain_audit_record(
        completion_sha, snapshot=snapshot, audit_query_module=grabowski_audit_query
    )
    intent_sha = _sha256(
        completion.get("intent_audit_sha256"),
        "Captain audit completion.intent_audit_sha256",
    )
    intent = _verified_captain_audit_record(
        intent_sha, snapshot=snapshot, audit_query_module=grabowski_audit_query
    )

    expected_identity = plan["expected_identity"]
    expected_base = (
        expected_identity.get("base") if plan["saga_kind"] == "pr-settlement" else None
    )
    expected_base_sha = (
        expected_identity.get("expected_base_sha")
        if plan["saga_kind"] == "pr-settlement"
        else None
    )
    expected_common = {
        "kind": "grabowski_captain_run_audit",
        "action": plan["captain_handoff"]["action"],
        "target_sha256": sha256_json(plan["captain_handoff"]["target"]),
        "expected_head": expected_identity["expected_head"],
        "expected_base": expected_base,
        "expected_base_sha": expected_base_sha,
    }
    for phase, record in (("intent", intent), ("completion", completion)):
        if (
            record.get("operation") != f"captain-run-audit-{phase}"
            or record.get("phase") != phase
        ):
            raise SagaError(f"Captain audit {phase} record has the wrong operation")
        drift = [
            key for key, expected in expected_common.items()
            if record.get(key) != expected
        ]
        if drift:
            raise SagaError(
                f"Captain audit {phase} differs from saga plan: " + ", ".join(drift)
            )
    if completion.get("intent_audit_sha256") != intent_sha:
        raise SagaError("Captain audit completion is not bound to its intent")
    for field in ("actor_id", "context_sha256", "request_sha256"):
        if completion.get(field) != intent.get(field):
            raise SagaError(f"Captain audit {field} changed between intent and completion")

    execution_result = completion.get("execution_result")
    if not isinstance(execution_result, dict):
        raise SagaError("Captain audit completion lacks execution result binding")
    if completion.get("execution_result_sha256") != sha256_json(execution_result):
        raise SagaError("Captain audit execution result digest mismatch")
    if set(execution_result) != {"status", "receipt_sha256", "output_sha256"}:
        raise SagaError("Captain audit reference execution result shape is not canonical")
    if execution_result.get("status") != "passed":
        raise SagaError("Captain audit reference requires a passed Captain result")
    receipt_sha = _sha256(
        execution_result.get("receipt_sha256"),
        "Captain audit execution_result.receipt_sha256",
    )
    output_sha = _sha256(
        execution_result.get("output_sha256"),
        "Captain audit execution_result.output_sha256",
    )
    return {
        "intent_record_sha256": intent_sha,
        "completion_record_sha256": completion_sha,
        "action": expected_common["action"],
        "target_sha256": expected_common["target_sha256"],
        "expected_head": expected_common["expected_head"],
        "expected_base": expected_base,
        "expected_base_sha": expected_base_sha,
        "receipt_sha256": receipt_sha,
        "output_sha256": output_sha,
        "status": "passed",
    }


def _validate_mechanic_result(
    plan: dict[str, Any],
    mechanic_result: Any,
    *,
    receipt_sha256_json: ReceiptHasher | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str], bool]:
    receipt_hasher = receipt_sha256_json or sha256_json
    receipt, output = _validate_grip_result(
        mechanic_result,
        expected_grip="mechanic-loop",
        field="mechanic_result",
        receipt_sha256_json=receipt_hasher,
    )
    planned_actions = plan["mechanic_actions"]
    child_actions = output.get("actions")
    if (
        child_actions is None
        and receipt.get("status") == "blocked"
        and receipt.get("phase") == "preflight"
    ):
        return receipt, output, [], False
    if not isinstance(child_actions, list):
        raise SagaError("mechanic_result actions are missing")
    if output.get("requested_action_count") != len(planned_actions):
        raise SagaError("mechanic_result requested action count differs from saga plan")
    if output.get("executed_action_count") != len(child_actions):
        raise SagaError("mechanic_result executed action count is inconsistent")
    if len(child_actions) > len(planned_actions):
        raise SagaError("mechanic_result executed unplanned actions")

    child_receipts: list[str] = []
    semantic_child_results: list[bool] = []
    for index, record_value in enumerate(child_actions):
        if not isinstance(record_value, Mapping):
            raise SagaError(f"mechanic_result.actions[{index}] must be an object")
        record = dict(record_value)
        planned = planned_actions[index]
        expected_fields = {
            "index": index,
            "action": planned["action"],
            "grip": planned["action"],
            "target": planned["target"],
            "scope": planned["scope"],
            "receipt_path": planned["receipt_path"],
            "allow_mutation": planned["allow_mutation"],
        }
        drift = [
            name for name, expected in expected_fields.items() if record.get(name) != expected
        ]
        if drift:
            raise SagaError(
                f"mechanic_result.actions[{index}] differs from saga plan: {', '.join(drift)}"
            )
        child_receipt = _bounded_mapping(
            record.get("receipt"), f"mechanic_result.actions[{index}].receipt"
        )
        child_output = _bounded_mapping(
            record.get("output", {}), f"mechanic_result.actions[{index}].output"
        )
        child_grip = child_receipt.get("grip")
        if (
            child_receipt.get("kind") != "grabowski.operator_grip_receipt"
            or child_receipt.get("schema_version") != 1
            or not isinstance(child_grip, Mapping)
            or child_grip.get("name") != planned["action"]
        ):
            raise SagaError(
                f"mechanic_result.actions[{index}] lacks the planned child grip receipt"
            )
        child_sha = _sha256(
            child_receipt.get("receipt_sha256"),
            f"mechanic_result.actions[{index}].receipt.receipt_sha256",
        )
        if child_sha != receipt_hasher(
            {key: item for key, item in child_receipt.items() if key != "receipt_sha256"}
        ):
            raise SagaError(f"mechanic_result.actions[{index}] child receipt digest mismatch")
        if record.get("child_receipt_sha256") != child_sha:
            raise SagaError(f"mechanic_result.actions[{index}] child receipt binding mismatch")
        if child_receipt.get("output_sha256") != receipt_hasher(child_output):
            raise SagaError(f"mechanic_result.actions[{index}] child output digest mismatch")
        if record.get("receipt_status") != child_receipt.get("status"):
            raise SagaError(f"mechanic_result.actions[{index}] child status mismatch")
        child_receipts.append(child_sha)
        semantic_child_results.append(
            _child_semantically_ready(plan, planned, child_output)
        )

    complete = output.get("complete") is True
    mechanic_passed = (
        receipt.get("status") == "passed"
        and complete
        and len(child_actions) == len(planned_actions)
        and all(
            isinstance(item, Mapping) and item.get("receipt_status") == "passed"
            for item in child_actions
        )
    )
    if receipt.get("status") == "passed" and not mechanic_passed:
        raise SagaError("mechanic_result claims pass without complete planned child success")
    prepare_passed = mechanic_passed and all(semantic_child_results)
    return receipt, output, child_receipts, prepare_passed


def build_run_receipt(
    plan_value: Any,
    mechanic_result: Any,
    *,
    receipt_sha256_json: ReceiptHasher | None = None,
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    receipt, output, child_receipts, prepare_passed = _validate_mechanic_result(
        plan,
        mechanic_result,
        receipt_sha256_json=receipt_sha256_json,
    )
    state = "captain_required" if prepare_passed else "prepare_blocked"
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": RUN_KIND,
        "saga_kind": plan["saga_kind"],
        "plan_sha256": plan["plan_sha256"],
        "mechanic_plan_sha256": sha256_json(plan["mechanic_actions"]),
        "idempotency_key": plan["idempotency_key"],
        "state": state,
        "captain_ready": prepare_passed,
        "phase_status": {
            "prepare": "passed" if prepare_passed else "blocked",
            "plan": "passed",
            "apply": "required" if prepare_passed else "blocked",
            "readback": "pending" if prepare_passed else "blocked",
            "settle": "pending" if prepare_passed else "blocked",
        },
        "mechanic_receipt_sha256": receipt["receipt_sha256"],
        "child_receipt_sha256s": child_receipts,
        "captain_handoff": plan["captain_handoff"] if prepare_passed else None,
        "captain_handoff_sha256": sha256_json(plan["captain_handoff"]),
        "required_readback": plan["readback_contract"],
        "recovery": (
            "invoke captain-run only with fresh evidence and this exact handoff; after ambiguous apply, read back before retry"
            if prepare_passed
            else "repair the blocked mechanic evidence and build a fresh saga run receipt"
        ),
        "does_not_establish": [
            "captain-execution-authority",
            "captain-execution-completion",
            "merge-completion",
            "deployment-completion",
        ],
    }
    return {
        **body,
        "run_sha256": sha256_json(body),
        "receipt_status": "passed" if prepare_passed else "blocked",
    }


def validate_run_receipt(value: Any, *, plan_value: Any) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    run = _bounded_mapping(value, "run_receipt")
    run_sha = _sha256(run.get("run_sha256"), "run_receipt.run_sha256")
    material = {
        key: item for key, item in run.items() if key not in {"run_sha256", "receipt_status"}
    }
    expected_sha = sha256_json(material)
    if run_sha != expected_sha:
        raise SagaError("run_receipt digest mismatch")
    if run.get("kind") != RUN_KIND or run.get("schema_version") != SCHEMA_VERSION:
        raise SagaError("run_receipt contract is unsupported")
    if run.get("plan_sha256") != plan["plan_sha256"]:
        raise SagaError("run_receipt is bound to another saga plan")
    if run.get("mechanic_plan_sha256") != sha256_json(plan["mechanic_actions"]):
        raise SagaError("run_receipt Mechanic plan binding drifted")
    if (
        run.get("saga_kind") != plan["saga_kind"]
        or run.get("idempotency_key") != plan["idempotency_key"]
    ):
        raise SagaError("run_receipt saga identity drifted")
    if run.get("captain_handoff_sha256") != sha256_json(plan["captain_handoff"]):
        raise SagaError("run_receipt Captain handoff drifted")
    hashes = run.get("child_receipt_sha256s")
    if not isinstance(hashes, list) or any(
        not isinstance(item, str) or SHA256_RE.fullmatch(item) is None for item in hashes
    ):
        raise SagaError("run_receipt child receipt bindings are invalid")
    captain_ready = run.get("captain_ready") is True
    if captain_ready:
        if run.get("state") != "captain_required" or run.get("captain_handoff") != plan["captain_handoff"]:
            raise SagaError("run_receipt Captain-ready state is inconsistent")
    elif run.get("state") != "prepare_blocked" or run.get("captain_handoff") is not None:
        raise SagaError("run_receipt blocked state is inconsistent")
    return run


def _verified_saga_run_receipt_reference(
    plan: dict[str, Any], audit_ref: dict[str, Any]
) -> dict[str, Any]:
    try:
        import grabowski_audit_query

        snapshot = grabowski_audit_query.capture_verified_audit_snapshot()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise SagaError(
            f"verified Saga run audit snapshot unavailable: {type(exc).__name__}"
        ) from exc

    record_sha = _sha256(
        audit_ref.get("record_sha256"), "run_receipt.record_sha256"
    )
    try:
        record = _verified_captain_audit_record(
            record_sha, snapshot=snapshot, audit_query_module=grabowski_audit_query
        )
    except SagaError as exc:
        raise SagaError(
            f"verified Saga run audit record unavailable: {record_sha}"
        ) from exc
    if (
        record.get("schema_version") != SCHEMA_VERSION
        or record.get("kind") != SAGA_RUN_AUDIT_KIND
        or record.get("operation") != SAGA_RUN_AUDIT_OPERATION
    ):
        raise SagaError("verified Saga run audit record contract is invalid")
    if record.get("plan_sha256") != plan["plan_sha256"]:
        raise SagaError("verified Saga run audit record is bound to another saga plan")
    if record.get("saga_kind") != plan["saga_kind"]:
        raise SagaError("verified Saga run audit record saga kind drifted")
    run_value = _bounded_mapping(
        record.get("run_receipt"), "verified Saga run audit.run_receipt"
    )
    if record.get("run_receipt_sha256") != sha256_json(run_value):
        raise SagaError("verified Saga run audit receipt digest mismatch")
    run = validate_run_receipt(run_value, plan_value=plan)
    if record.get("run_sha256") != run["run_sha256"]:
        raise SagaError("verified Saga run audit run digest mismatch")
    return run


def _captain_outcome(
    captain_result: dict[str, Any],
    *,
    plan: dict[str, Any],
    receipt_sha256_json: ReceiptHasher | None = None,
) -> tuple[str, dict[str, Any] | None, str | None, str]:
    receipt, output = _validate_grip_result(
        captain_result,
        expected_grip="captain-run",
        field="captain_result",
        receipt_sha256_json=receipt_sha256_json,
    )
    actions = output.get("actions")
    executions = output.get("executions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], Mapping):
        raise SagaError("captain_result must contain exactly one action")
    action = actions[0]
    if action.get("action") != plan["captain_handoff"]["action"]:
        raise SagaError("captain_result action differs from saga handoff")
    if action.get("target") != plan["captain_handoff"]["target"]:
        raise SagaError("captain_result target differs from saga handoff")
    execution = (
        executions[0]
        if isinstance(executions, list)
        and len(executions) == 1
        and isinstance(executions[0], Mapping)
        else None
    )
    receipt_status = receipt.get("status")
    invoked = execution.get("execution_invoked") is True if isinstance(execution, Mapping) else False
    verified = execution.get("verification_passed") is True if isinstance(execution, Mapping) else False
    if receipt_status == "passed" and verified:
        return "verified", dict(execution), None, receipt["receipt_sha256"]
    if invoked:
        return (
            "outcome_unknown",
            dict(execution) if isinstance(execution, Mapping) else None,
            str(output.get("decision") or receipt_status or "unknown"),
            receipt["receipt_sha256"],
        )
    return (
        "blocked",
        dict(execution) if isinstance(execution, Mapping) else None,
        str(output.get("decision") or receipt_status or "blocked"),
        receipt["receipt_sha256"],
    )


def validate_captain_audit_binding(
    value: Any,
    *,
    plan_value: Any,
    captain_result_value: Any,
    receipt_sha256_json: ReceiptHasher | None = None,
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    captain = _bounded_mapping(captain_result_value, "captain_result")
    receipt_hasher = receipt_sha256_json or sha256_json
    audit_ref = (
        validate_captain_audit_result_ref(captain)
        if is_captain_audit_result_ref(captain)
        else None
    )
    receipt = None
    trusted_audit_identity = None
    if audit_ref is None:
        receipt, _output = _validate_grip_result(
            captain,
            expected_grip="captain-run",
            field="captain_result",
            receipt_sha256_json=receipt_hasher,
        )
    else:
        trusted_audit_identity = _verified_captain_audit_reference_identity(
            plan, audit_ref
        )

    binding = _bounded_mapping(value, "captain_audit_binding")
    required = {
        "schema_version", "kind", "authority", "intent_record_sha256",
        "completion_record_sha256", "action", "target_sha256",
        "expected_head", "expected_base", "expected_base_sha",
        "receipt_sha256", "output_sha256", "status", "binding_sha256",
    }
    if set(binding) != required:
        raise SagaError("captain_audit_binding shape is not canonical")
    if (
        binding.get("schema_version") != SCHEMA_VERSION
        or binding.get("kind") != CAPTAIN_AUDIT_BINDING_KIND
        or binding.get("authority") != "verified_grabowski_audit_chain"
    ):
        raise SagaError("captain_audit_binding authority is invalid")

    binding_sha = _sha256(
        binding.get("binding_sha256"), "captain_audit_binding.binding_sha256"
    )
    binding_hasher = sha256_json if audit_ref is not None else receipt_hasher
    if binding_sha != binding_hasher(
        {key: item for key, item in binding.items() if key != "binding_sha256"}
    ):
        raise SagaError("captain_audit_binding digest mismatch")
    _sha256(
        binding.get("intent_record_sha256"),
        "captain_audit_binding.intent_record_sha256",
    )
    _sha256(
        binding.get("completion_record_sha256"),
        "captain_audit_binding.completion_record_sha256",
    )

    if trusted_audit_identity is not None:
        expected_values = trusted_audit_identity
    else:
        assert receipt is not None
        expected_identity = plan["expected_identity"]
        expected_base = (
            expected_identity.get("base")
            if plan["saga_kind"] == "pr-settlement"
            else None
        )
        expected_base_sha = (
            expected_identity.get("expected_base_sha")
            if plan["saga_kind"] == "pr-settlement"
            else None
        )
        expected_values = {
            "action": plan["captain_handoff"]["action"],
            "target_sha256": receipt_hasher(plan["captain_handoff"]["target"]),
            "expected_head": expected_identity["expected_head"],
            "expected_base": expected_base,
            "expected_base_sha": expected_base_sha,
            "receipt_sha256": receipt["receipt_sha256"],
            "output_sha256": receipt["output_sha256"],
            "status": receipt["status"],
        }

    drift = [
        key for key, expected in expected_values.items()
        if binding.get(key) != expected
    ]
    if drift:
        raise SagaError(
            "captain_audit_binding differs from saga/Captain evidence: "
            + ", ".join(drift)
        )
    return binding


def _settle_pr(plan: dict[str, Any], readback: dict[str, Any]) -> tuple[str, list[str]]:
    expected = plan["expected_identity"]
    reasons: list[str] = []
    if readback.get("state") != "MERGED":
        reasons.append("pr_not_merged")
    if readback.get("headRefOid") != expected["expected_head"]:
        reasons.append("pr_head_mismatch")
    if readback.get("baseRefName") != expected["base"]:
        reasons.append("pr_base_mismatch")
    if readback.get("number") != expected["pr"]:
        reasons.append("pr_number_mismatch")
    merge_commit = readback.get("mergeCommit")
    merge_oid = merge_commit.get("oid") if isinstance(merge_commit, Mapping) else None
    if not isinstance(merge_oid, str) or SHA40_RE.fullmatch(merge_oid) is None:
        reasons.append("pr_merge_commit_missing")
    return ("settled", []) if not reasons else ("recovery_required", reasons)


def _settle_runtime(plan: dict[str, Any], readback: dict[str, Any]) -> tuple[str, list[str]]:
    expected_head = plan["expected_identity"]["expected_head"]
    identity = readback.get("identity")
    integrity = readback.get("integrity")
    serving = readback.get("serving_process")
    if not isinstance(identity, Mapping) or not isinstance(integrity, Mapping) or not isinstance(serving, Mapping):
        return "recovery_required", ["deployment_identity_incomplete"]
    if identity.get("repo_head") != expected_head:
        return "readback_pending", ["runtime_head_not_converged"]
    reasons: list[str] = []
    if identity.get("completion_status") != "complete":
        reasons.append("deployment_manifest_incomplete")
    if not integrity or any(value is not True for value in integrity.values()):
        reasons.append("runtime_integrity_not_fully_valid")
    if serving.get("matches_deployed_manifest") is not True:
        reasons.append("serving_process_manifest_mismatch")
    if serving.get("serves_deployed_release") is not True:
        reasons.append("serving_process_not_on_deployed_release")
    return ("settled", []) if not reasons else ("recovery_required", reasons)


def settle(
    *,
    plan_value: Any,
    run_receipt_value: Any,
    captain_result_value: Any,
    captain_audit_binding_value: Any,
    readback_value: Any,
    receipt_sha256_json: ReceiptHasher | None = None,
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    if is_saga_run_receipt_ref(run_receipt_value):
        run_ref = validate_saga_run_receipt_ref(run_receipt_value)
        run = _verified_saga_run_receipt_reference(plan, run_ref)
    else:
        run = validate_run_receipt(run_receipt_value, plan_value=plan)
    captain = _bounded_mapping(captain_result_value, "captain_result")
    captain_audit_binding = validate_captain_audit_binding(
        captain_audit_binding_value,
        plan_value=plan,
        captain_result_value=captain,
        receipt_sha256_json=receipt_sha256_json,
    )
    readback = _bounded_mapping(readback_value, "readback")
    if run.get("captain_ready") is not True or run.get("state") != "captain_required":
        raise SagaError("blocked saga run cannot be settled as an applied saga")
    if is_captain_audit_result_ref(captain):
        captain_state = "verified"
        execution = {
            "source": "verified_grabowski_audit_chain",
            "completion_record_sha256": captain_audit_binding[
                "completion_record_sha256"
            ],
            "receipt_sha256": captain_audit_binding["receipt_sha256"],
            "output_sha256": captain_audit_binding["output_sha256"],
            "status": captain_audit_binding["status"],
        }
        captain_reason = None
        captain_receipt_sha256 = captain_audit_binding["receipt_sha256"]
    else:
        captain_state, execution, captain_reason, captain_receipt_sha256 = _captain_outcome(
            captain,
            plan=plan,
            receipt_sha256_json=receipt_sha256_json,
        )
    if captain_state == "blocked":
        state = "apply_blocked"
        reasons = [f"captain_blocked:{captain_reason}"]
    elif captain_state == "outcome_unknown":
        state = "recovery_required"
        reasons = [f"captain_outcome_unknown:{captain_reason}"]
    elif plan["saga_kind"] == "pr-settlement":
        state, reasons = _settle_pr(plan, readback)
    else:
        state, reasons = _settle_runtime(plan, readback)
    phase_status = {
        "prepare": "passed",
        "plan": "passed",
        "apply": "passed" if captain_state == "verified" else "blocked" if captain_state == "blocked" else "unknown",
        "readback": "passed" if state == "settled" else "pending" if state == "readback_pending" else "requires_recovery",
        "settle": "passed" if state == "settled" else "pending" if state == "readback_pending" else "blocked",
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": SETTLEMENT_KIND,
        "saga_kind": plan["saga_kind"],
        "plan_sha256": plan["plan_sha256"],
        "run_sha256": run["run_sha256"],
        "captain_result_sha256": sha256_json(captain),
        "captain_receipt_sha256": captain_receipt_sha256,
        "captain_audit_binding_sha256": captain_audit_binding["binding_sha256"],
        "captain_audit_intent_record_sha256": captain_audit_binding["intent_record_sha256"],
        "captain_audit_completion_record_sha256": captain_audit_binding["completion_record_sha256"],
        "readback_sha256": sha256_json(readback),
        "state": state,
        "phase_status": phase_status,
        "reasons": reasons,
        "captain_execution": execution,
        "retry_allowed": state in {"readback_pending"},
        "required_next_action": (
            "none"
            if state == "settled"
            else "repeat typed deployment identity readback and saga-settle only"
            if state == "readback_pending"
            else "perform authoritative target readback and repair named evidence; never blind-retry Captain"
        ),
        "does_not_establish": [
            "cross-system-atomicity",
            "future-correctness",
            "automatic-Captain-retry-authority",
            "policy-bypass",
        ],
    }
    return {**body, "settlement_sha256": sha256_json(body), "receipt_status": "passed" if state in {"settled", "readback_pending"} else "blocked"}

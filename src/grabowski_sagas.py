from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping


SCHEMA_VERSION = 1
PLAN_KIND = "OperatorSagaPlan.v1"
RUN_KIND = "OperatorSagaRunReceipt.v1"
SETTLEMENT_KIND = "OperatorSagaSettlementReceipt.v1"
CAPTAIN_AUDIT_BINDING_KIND = "VerifiedCaptainAuditBinding.v1"
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
                parameters={"repo": normalized["repository_path"]},
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
    receipt_sha = _sha256(receipt.get("receipt_sha256"), f"{field}.receipt.receipt_sha256")
    expected_receipt_sha = sha256_json(
        {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    )
    if receipt_sha != expected_receipt_sha:
        raise SagaError(f"{field} receipt digest mismatch")
    if result.get("receipt_sha256") != receipt_sha:
        raise SagaError(f"{field} top-level receipt digest mismatch")
    if receipt.get("output_sha256") != sha256_json(output):
        raise SagaError(f"{field} output digest mismatch")
    if result.get("status") != receipt.get("status"):
        raise SagaError(f"{field} status differs from its receipt")
    return receipt, output


def _validate_mechanic_result(
    plan: dict[str, Any], mechanic_result: Any
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    receipt, output = _validate_grip_result(
        mechanic_result,
        expected_grip="mechanic-loop",
        field="mechanic_result",
    )
    planned_actions = plan["mechanic_actions"]
    child_actions = output.get("actions")
    if not isinstance(child_actions, list):
        raise SagaError("mechanic_result actions are missing")
    if output.get("requested_action_count") != len(planned_actions):
        raise SagaError("mechanic_result requested action count differs from saga plan")
    if output.get("executed_action_count") != len(child_actions):
        raise SagaError("mechanic_result executed action count is inconsistent")
    if len(child_actions) > len(planned_actions):
        raise SagaError("mechanic_result executed unplanned actions")

    child_receipts: list[str] = []
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
        if child_sha != sha256_json(
            {key: item for key, item in child_receipt.items() if key != "receipt_sha256"}
        ):
            raise SagaError(f"mechanic_result.actions[{index}] child receipt digest mismatch")
        if record.get("child_receipt_sha256") != child_sha:
            raise SagaError(f"mechanic_result.actions[{index}] child receipt binding mismatch")
        if child_receipt.get("output_sha256") != sha256_json(child_output):
            raise SagaError(f"mechanic_result.actions[{index}] child output digest mismatch")
        if record.get("receipt_status") != child_receipt.get("status"):
            raise SagaError(f"mechanic_result.actions[{index}] child status mismatch")
        child_receipts.append(child_sha)

    complete = output.get("complete") is True
    prepare_passed = (
        receipt.get("status") == "passed"
        and complete
        and len(child_actions) == len(planned_actions)
        and all(
            isinstance(item, Mapping) and item.get("receipt_status") == "passed"
            for item in child_actions
        )
    )
    if receipt.get("status") == "passed" and not prepare_passed:
        raise SagaError("mechanic_result claims pass without complete planned child success")
    return receipt, output, child_receipts


def build_run_receipt(plan_value: Any, mechanic_result: Any) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    receipt, output, child_receipts = _validate_mechanic_result(plan, mechanic_result)
    prepare_passed = receipt.get("status") == "passed" and output.get("complete") is True
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


def _captain_outcome(
    captain_result: dict[str, Any],
    *,
    plan: dict[str, Any],
) -> tuple[str, dict[str, Any] | None, str | None, str]:
    receipt, output = _validate_grip_result(
        captain_result,
        expected_grip="captain-run",
        field="captain_result",
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
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    captain = _bounded_mapping(captain_result_value, "captain_result")
    receipt, _output = _validate_grip_result(
        captain, expected_grip="captain-run", field="captain_result"
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
    if binding_sha != sha256_json(
        {key: item for key, item in binding.items() if key != "binding_sha256"}
    ):
        raise SagaError("captain_audit_binding digest mismatch")
    _sha256(binding.get("intent_record_sha256"), "captain_audit_binding.intent_record_sha256")
    _sha256(binding.get("completion_record_sha256"), "captain_audit_binding.completion_record_sha256")
    expected_identity = plan["expected_identity"]
    expected_base = expected_identity.get("base") if plan["saga_kind"] == "pr-settlement" else None
    expected_base_sha = expected_identity.get("expected_base_sha") if plan["saga_kind"] == "pr-settlement" else None
    expected_values = {
        "action": plan["captain_handoff"]["action"],
        "target_sha256": sha256_json(plan["captain_handoff"]["target"]),
        "expected_head": expected_identity["expected_head"],
        "expected_base": expected_base,
        "expected_base_sha": expected_base_sha,
        "receipt_sha256": receipt["receipt_sha256"],
        "output_sha256": receipt["output_sha256"],
        "status": receipt["status"],
    }
    drift = [key for key, expected in expected_values.items() if binding.get(key) != expected]
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
) -> dict[str, Any]:
    plan = validate_plan(plan_value)
    run = validate_run_receipt(run_receipt_value, plan_value=plan)
    captain = _bounded_mapping(captain_result_value, "captain_result")
    captain_audit_binding = validate_captain_audit_binding(
        captain_audit_binding_value,
        plan_value=plan,
        captain_result_value=captain,
    )
    readback = _bounded_mapping(readback_value, "readback")
    if run.get("captain_ready") is not True or run.get("state") != "captain_required":
        raise SagaError("blocked saga run cannot be settled as an applied saga")
    captain_state, execution, captain_reason, captain_receipt_sha256 = _captain_outcome(
        captain, plan=plan
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

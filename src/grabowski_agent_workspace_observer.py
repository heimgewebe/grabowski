from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
import re
import stat
from typing import Any

import grabowski_agent_workspace as workspace
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
REPORT_SCHEMA_VERSION = 2
MAX_REPORT_EVENTS = 512
MAX_OPTIMIZER_WORKSPACES = 50
SUCCESS_CLASSIFICATIONS = frozenset({
    "already_succeeded",
    "eligible",
    "not_attempted",
    "not_collected",
    "passed",
})
NON_ACTIONABLE_FAILURE_CLASSES = frozenset({
    "legacy_workspace_without_event_log",
    "unknown_external_closeout",
    "role_running",
    "unknown_prior_outcome",
})
CLOSEOUT_SOURCES = {
    "pr_integration_truth": "git_github",
    "bureau_task_reconciliation": "bureau",
    "workspace_lease_release": "grabowski_resources",
    "writer_worktree_archive_or_cleanup": "grabowski_checkouts",
    "operator_final_summary": "operator",
}


class WorkspaceObserverError(ValueError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _read_events(workspace_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    identifier = workspace._required_string(workspace_id, "workspace_id", max_length=80)
    path = workspace._event_log_path(identifier)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return [], {"present": False, "integrity_valid": True, "reason": "legacy_workspace_without_event_log"}
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return [], {"present": True, "integrity_valid": False, "reason": "unsafe_event_log"}
    if metadata.st_size > workspace.MAX_WORKSPACE_EVENT_BYTES:
        return [], {"present": True, "integrity_valid": False, "reason": "event_log_too_large"}
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            return [], {"present": True, "integrity_valid": False, "reason": "unsafe_event_log_descriptor"}
        raw = os.read(descriptor, workspace.MAX_WORKSPACE_EVENT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > workspace.MAX_WORKSPACE_EVENT_BYTES:
        return [], {"present": True, "integrity_valid": False, "reason": "event_log_too_large"}
    events: list[dict[str, Any]] = []
    expected_sequence = 1
    hashes: set[str] = set()
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line:
            continue
        if len(events) >= MAX_REPORT_EVENTS:
            return events, {"present": True, "integrity_valid": False, "reason": "event_count_limit", "line": line_number}
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return events, {"present": True, "integrity_valid": False, "reason": "invalid_json", "line": line_number}
        if not isinstance(event, dict):
            return events, {"present": True, "integrity_valid": False, "reason": "event_not_object", "line": line_number}
        observed_hash = event.get("event_sha256")
        unsigned = {key: value for key, value in event.items() if key != "event_sha256"}
        if (
            event.get("schema_version") != 1
            or event.get("workspace_id") != identifier
            or event.get("sequence") != expected_sequence
            or not isinstance(observed_hash, str)
            or observed_hash != _sha256_json(unsigned)
            or observed_hash in hashes
        ):
            return events, {"present": True, "integrity_valid": False, "reason": "event_binding_mismatch", "line": line_number}
        hashes.add(observed_hash)
        events.append(event)
        expected_sequence += 1
    return events, {
        "present": True,
        "integrity_valid": True,
        "event_count": len(events),
        "last_sequence": events[-1]["sequence"] if events else 0,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _receipt_failure_class(manifest: dict[str, Any], role: str) -> str | None:
    receipt = workspace._role_receipt(manifest, role)
    if not isinstance(receipt, dict):
        return None
    returncode = receipt.get("returncode")
    if returncode == 0:
        return None
    text = " ".join(
        str(receipt.get(key, ""))
        for key in ("stderr_tail", "stdout_tail")
    ).lower()
    command = manifest.get("commands", {}).get(role)
    command = command if isinstance(command, list) else []
    declared_module = workspace._declared_python_module(command) if command else None
    if declared_module:
        module_pattern = re.compile(
            rf"no module named\s+['\"]?{re.escape(declared_module.lower())}['\"]?(?:\s|$)"
        )
        if module_pattern.search(text):
            return "environment_toolchain_failure"
    executable = str(command[0]).lower() if command else ""
    executable_name = executable.rsplit("/", 1)[-1]
    executable_named = bool(
        executable
        and (executable in text or executable_name in text)
    )
    if (
        returncode in {126, 127}
        and executable_named
        and any(
            marker in text
            for marker in ("no such file or directory", "command not found", "execvp")
        )
    ):
        return "environment_toolchain_failure"
    if role == "tests":
        return "semantic_test_failure"
    verdict = receipt.get("verdict")
    if verdict in {"NEEDS_CHANGE", "BLOCK"}:
        return "review_verdict_blocks_retry"
    return "review_execution_failure"


def _legacy_failure_classes(manifest: dict[str, Any], status: dict[str, Any]) -> list[str]:
    failed_roles = {
        str(item)
        for item in status.get("failed_roles", [])
        if isinstance(item, str)
    }
    collection = manifest.get("collection")
    if isinstance(collection, dict):
        tests = collection.get("tests")
        if isinstance(tests, dict) and tests.get("status") == "failed":
            failed_roles.add("tests")
        review = collection.get("review")
        if isinstance(review, dict) and review.get("status") == "failed":
            failed_roles.add("review")
    result: list[str] = []
    for role in sorted(failed_roles):
        if role in {"tests", "review"}:
            classification = _receipt_failure_class(manifest, role)
            if classification:
                result.append(classification)
    return result


def _failure_classes(
    events: list[dict[str, Any]],
    status: dict[str, Any],
    manifest: dict[str, Any],
) -> list[str]:
    classes: list[str] = []
    for event in events:
        outcome = event.get("outcome")
        evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
        failure = evidence.get("failure_classification")
        if isinstance(failure, str) and failure and failure not in SUCCESS_CLASSIFICATIONS:
            classes.append(failure)
        elif outcome in {"environment_failure", "failed", "incomplete"}:
            classes.append(f"{event.get('event_type')}:{outcome}")
    legacy_receipt_classes = {
        role: _receipt_failure_class(manifest, role)
        for role in ("tests", "review")
    } if not events else {}
    for role, value in status.get("role_retry", {}).items():
        if not isinstance(value, dict):
            continue
        if legacy_receipt_classes.get(role):
            classes.append(str(legacy_receipt_classes[role]))
            continue
        classification = value.get("classification")
        if (
            isinstance(classification, str)
            and classification not in SUCCESS_CLASSIFICATIONS
            and classification not in {"retry_limit_reached"}
        ):
            classes.append(f"{role}:{classification}")
    if not events:
        classes.extend(_legacy_failure_classes(manifest, status))
    return sorted(set(classes))


def _writer_identity(manifest: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    writer = status.get("writer") if isinstance(status.get("writer"), dict) else {}
    collection = manifest.get("collection") if isinstance(manifest.get("collection"), dict) else {}
    head = writer.get("writer_head") or collection.get("writer_head") or manifest.get("expected_base_head")
    diff = writer.get("diff_sha256") or collection.get("diff_sha256")
    base = writer.get("expected_base_head") or collection.get("expected_base_head") or manifest.get("expected_base_head")
    source = "live_git"
    if not writer.get("writer_head") and collection.get("writer_head"):
        source = "collection_receipt"
    elif not writer.get("writer_head"):
        source = "manifest"
    return {
        "writer_head": head,
        "diff_sha256": diff,
        "expected_base_head": base,
        "source": source,
    }


def _validate_closeout_evidence(
    workspace_id: str,
    manifest: dict[str, Any],
    value: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise WorkspaceObserverError("external_closeout_evidence must be an object")
    expected_fields = {
        "schema_version",
        "workspace_id",
        "collection_result_sha256",
        "close_receipt_sha256",
        "writer_head",
        "diff_sha256",
        "items",
        "evidence_sha256",
    }
    observed_hash = value.get("evidence_sha256")
    unsigned = {key: item for key, item in value.items() if key != "evidence_sha256"}
    collection = manifest.get("collection") if isinstance(manifest.get("collection"), dict) else {}
    close_receipt = manifest.get("close_receipt") if isinstance(manifest.get("close_receipt"), dict) else {}
    current_result = collection.get("result_sha256")
    current_head = collection.get("writer_head")
    current_diff = collection.get("diff_sha256")
    current_close = close_receipt.get("receipt_sha256")
    bindings_valid = bool(
        isinstance(current_result, str)
        and workspace.SHA256_RE.fullmatch(current_result)
        and isinstance(current_head, str)
        and workspace.SHA40_RE.fullmatch(current_head)
        and isinstance(current_diff, str)
        and workspace.SHA256_RE.fullmatch(current_diff)
        and (
            current_close is None
            or (isinstance(current_close, str) and workspace.SHA256_RE.fullmatch(current_close))
        )
    )
    if (
        set(value) != expected_fields
        or value.get("schema_version") != 1
        or value.get("workspace_id") != workspace_id
        or not bindings_valid
        or value.get("collection_result_sha256") != current_result
        or value.get("writer_head") != current_head
        or value.get("diff_sha256") != current_diff
        or value.get("close_receipt_sha256") != current_close
        or not isinstance(observed_hash, str)
        or observed_hash != _sha256_json(unsigned)
        or not isinstance(value.get("items"), list)
    ):
        raise WorkspaceObserverError("external closeout evidence is invalid, stale or unbound")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value["items"]):
        if not isinstance(item, dict):
            raise WorkspaceObserverError(f"external closeout item {index} must be an object")
        name = item.get("item")
        if name not in CLOSEOUT_SOURCES or name in result:
            raise WorkspaceObserverError("external closeout items must be unique known items")
        if item.get("source_of_truth") != CLOSEOUT_SOURCES[name]:
            raise WorkspaceObserverError("external closeout source mismatch")
        if item.get("status") not in {"verified", "unknown"}:
            raise WorkspaceObserverError("external closeout status is invalid")
        reference = item.get("reference")
        if reference is not None and (not isinstance(reference, str) or not reference.strip() or len(reference) > 1000):
            raise WorkspaceObserverError("external closeout reference is invalid")
        result[name] = dict(item)
    return result


def _resolved_closeout(
    status: dict[str, Any],
    supplied: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    resolved: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for raw in status.get("external_closeout_checklist", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("item"), str):
            continue
        item = dict(raw)
        supplied_item = supplied.get(item["item"])
        if item.get("status") != "verified" and supplied_item and supplied_item.get("status") == "verified":
            item["status"] = "verified"
            item["evidence_mode"] = "explicit_hash_bound"
            item["evidence_reference"] = supplied_item.get("reference")
        if item.get("status") != "verified":
            unresolved.append(item["item"])
        resolved.append(item)
    return resolved, sorted(unresolved)


def _is_actionable_failure(value: str) -> bool:
    if value in NON_ACTIONABLE_FAILURE_CLASSES:
        return False
    return not any(
        marker in value
        for marker in (
            "already_succeeded",
            "not_attempted",
            "not_collected",
            "role_running",
            "unknown_prior_outcome",
        )
    )


def _observer_report(
    workspace_id: str,
    *,
    activation_reason: str,
    external_closeout_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = workspace._manifest(workspace_id)
    status = workspace._status_data(manifest)
    events, integrity = _read_events(workspace_id)
    failure_classes = _failure_classes(events, status, manifest)
    supplied = _validate_closeout_evidence(workspace_id, manifest, external_closeout_evidence)
    closeout, unresolved = _resolved_closeout(status, supplied)
    identity = _writer_identity(manifest, status)
    facts = {
        "workspace_id": workspace_id,
        "binding": manifest.get("binding"),
        **identity,
        "closed": status.get("closed"),
        "closure_outcome": status.get("closure_outcome"),
        "success_ready": status.get("success_ready"),
        "failed_roles": status.get("failed_roles", []),
        "event_log": integrity,
        "failure_classes": failure_classes,
        "actionable_failure_classes": [item for item in failure_classes if _is_actionable_failure(item)],
        "external_closeout": closeout,
        "unresolved_external_closeout": unresolved,
        "supplied_closeout_evidence_sha256": (
            external_closeout_evidence.get("evidence_sha256")
            if isinstance(external_closeout_evidence, dict)
            else None
        ),
        "outcome_receipts": manifest.get("outcome_receipts", {}),
    }
    inferences: list[dict[str, Any]] = []
    actionable = facts["actionable_failure_classes"]
    if actionable:
        inferences.append({
            "inference": "workspace experienced actionable classified friction",
            "failure_classes": actionable,
            "confidence": "high" if integrity.get("integrity_valid") else "medium",
        })
    if unresolved:
        inferences.append({
            "inference": "workspace-local completion does not establish full operator closeout",
            "evidence_items": unresolved,
            "confidence": "high",
        })
    proposals: list[dict[str, Any]] = []
    if "environment_toolchain_failure" in actionable:
        proposals.append({
            "proposal": "prefer declared toolchain preflight and an explicit replacement command",
            "authority": "advisory_only",
            "validation": "replay the same failure class in an isolated workspace fixture",
        })
    if unresolved:
        proposals.append({
            "proposal": "complete external closeout checklist before declaring the operator task finished",
            "authority": "advisory_only",
            "validation": "verify each item with its named source of truth",
        })
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": "agent_workspace_process_observer",
        "workspace_id": workspace_id,
        "activation": {
            "mode": "explicit_read_only",
            "reason": activation_reason,
            "adds_mutation_authority": False,
            "runtime_cost": "one bounded local metadata and receipt scan",
            "agent_invocation_required": False,
        },
        "role_ownership": manifest.get("role_ownership"),
        "facts": facts,
        "inferences": inferences,
        "proposals": proposals,
        "timeline": events,
        "privacy": {
            "raw_commands_included": False,
            "environment_values_included": False,
            "credentials_included": False,
            "evidence_is_hash_or_redacted_metadata_only": True,
        },
        "non_claims": [
            "workspace correctness",
            "review completeness",
            "merge readiness",
            "independent verification of caller-supplied closeout evidence",
            "automatic optimization authority",
        ],
        "execution_authorized": False,
    }
    report["report_sha256"] = _sha256_json(report)
    return report


@mcp.tool(name="grabowski_agent_workspace_observe", annotations=READ_ONLY)
def grabowski_agent_workspace_observe(
    workspace_id: str,
    activation_reason: str = "explicit",
    external_closeout_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return an immutable-evidence process report without mutating or retrying the workspace."""
    operator._require_operator_capability("durable_job")
    operator._require_operator_capability("git_cli")
    reason = workspace._required_string(activation_reason, "activation_reason", max_length=240)
    return _observer_report(
        workspace._required_string(workspace_id, "workspace_id", max_length=80),
        activation_reason=reason,
        external_closeout_evidence=external_closeout_evidence,
    )


@mcp.tool(name="grabowski_agent_workspace_optimize", annotations=READ_ONLY)
def grabowski_agent_workspace_optimize(workspace_ids: list[str]) -> dict[str, Any]:
    """Derive advisory cross-workspace proposals from repeated actionable failures."""
    operator._require_operator_capability("durable_job")
    operator._require_operator_capability("git_cli")
    if not isinstance(workspace_ids, list) or not 2 <= len(workspace_ids) <= MAX_OPTIMIZER_WORKSPACES:
        raise WorkspaceObserverError("workspace_ids must contain between 2 and 50 entries")
    identifiers = [workspace._required_string(item, f"workspace_ids[{index}]", max_length=80) for index, item in enumerate(workspace_ids)]
    if len(set(identifiers)) != len(identifiers):
        raise WorkspaceObserverError("workspace_ids must be unique")
    reports = [_observer_report(identifier, activation_reason="cross_workspace_optimizer") for identifier in identifiers]
    counter: Counter[str] = Counter()
    for report in reports:
        counter.update(report["facts"]["actionable_failure_classes"])
    repeated = [
        {"failure_class": failure_class, "workspace_count": count}
        for failure_class, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        if count >= 2
    ]
    proposals = []
    for item in repeated:
        proposals.append({
            "rank": len(proposals) + 1,
            "failure_class": item["failure_class"],
            "measured_baseline": {
                "workspace_count": item["workspace_count"],
                "sample_size": len(reports),
                "independent_workspace_ids": identifiers,
            },
            "expected_benefit": "reduce repeated workspace friction for this actionable failure",
            "regression_risk": "medium",
            "validation_plan": "register a normal reviewed task, add focused fixtures, run full validation, and compare later reports",
            "authority": "proposal_only",
        })
    result = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": "agent_workspace_cross_run_optimizer",
        "workspace_ids": identifiers,
        "sample_size": len(reports),
        "repeated_failure_classes": repeated,
        "proposals": proposals,
        "minimum_evidence_met": len(reports) >= 2,
        "proposal_threshold": {
            "minimum_independent_workspaces": 2,
            "success_states_counted_as_failures": False,
            "unknown_closeout_counted_as_failure": False,
            "legacy_event_log_absence_counted_as_failure": False,
        },
        "single_run_can_authorize_change": False,
        "execution_authorized": False,
        "automatic_code_change": False,
        "automatic_policy_change": False,
        "automatic_bureau_change": False,
        "non_claims": ["causal correctness", "safe automatic optimization", "merge readiness"],
        "source_report_sha256": [report["report_sha256"] for report in reports],
    }
    result["optimizer_sha256"] = _sha256_json(result)
    return result

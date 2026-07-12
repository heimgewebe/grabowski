from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

import grabowski_agent_workspace as workspace
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
REPORT_SCHEMA_VERSION = 1
MAX_REPORT_EVENTS = 512
MAX_OPTIMIZER_WORKSPACES = 50


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


def _failure_classes(events: list[dict[str, Any]], status: dict[str, Any]) -> list[str]:
    classes: list[str] = []
    for event in events:
        outcome = event.get("outcome")
        evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
        failure = evidence.get("failure_classification")
        if isinstance(failure, str) and failure:
            classes.append(failure)
        elif outcome in {"environment_failure", "failed", "incomplete"}:
            classes.append(f"{event.get('event_type')}:{outcome}")
    for role, value in status.get("role_retry", {}).items():
        if isinstance(value, dict):
            classification = value.get("classification")
            if isinstance(classification, str) and classification not in {"not_attempted", "not_collected", "eligible"}:
                classes.append(f"{role}:{classification}")
    return sorted(set(classes))


def _unresolved_closeout(status: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for item in status.get("external_closeout_checklist", []):
        if isinstance(item, dict) and item.get("status") != "verified" and isinstance(item.get("item"), str):
            result.append(item["item"])
    return sorted(result)


def _observer_report(workspace_id: str, *, activation_reason: str) -> dict[str, Any]:
    manifest = workspace._manifest(workspace_id)
    status = workspace._status_data(manifest)
    events, integrity = _read_events(workspace_id)
    failure_classes = _failure_classes(events, status)
    unresolved = _unresolved_closeout(status)
    facts = {
        "workspace_id": workspace_id,
        "binding": manifest.get("binding"),
        "writer_head": status.get("writer", {}).get("writer_head") if isinstance(status.get("writer"), dict) else None,
        "diff_sha256": status.get("writer", {}).get("diff_sha256") if isinstance(status.get("writer"), dict) else None,
        "closed": status.get("closed"),
        "closure_outcome": status.get("closure_outcome"),
        "success_ready": status.get("success_ready"),
        "failed_roles": status.get("failed_roles", []),
        "event_log": integrity,
        "failure_classes": failure_classes,
        "unresolved_external_closeout": unresolved,
    }
    inferences: list[dict[str, Any]] = []
    if failure_classes:
        inferences.append({
            "inference": "workspace experienced classified friction",
            "evidence_event_types": sorted({str(event.get("event_type")) for event in events if event.get("outcome") in {"environment_failure", "failed", "incomplete"}}),
            "confidence": "high" if integrity.get("integrity_valid") else "low",
        })
    if unresolved:
        inferences.append({
            "inference": "workspace-local completion does not establish full operator closeout",
            "evidence_items": unresolved,
            "confidence": "high",
        })
    proposals: list[dict[str, Any]] = []
    if any("environment" in item or "toolchain" in item for item in failure_classes):
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
            "Bureau reconciliation",
            "automatic optimization authority",
        ],
        "execution_authorized": False,
    }
    report["report_sha256"] = _sha256_json(report)
    return report


@mcp.tool(name="grabowski_agent_workspace_observe", annotations=READ_ONLY)
def grabowski_agent_workspace_observe(workspace_id: str, activation_reason: str = "explicit") -> dict[str, Any]:
    """Return an immutable-evidence process report without mutating or retrying the workspace."""
    operator._require_operator_capability("durable_job")
    operator._require_operator_capability("git_cli")
    reason = workspace._required_string(activation_reason, "activation_reason", max_length=240)
    return _observer_report(workspace._required_string(workspace_id, "workspace_id", max_length=80), activation_reason=reason)


@mcp.tool(name="grabowski_agent_workspace_optimize", annotations=READ_ONLY)
def grabowski_agent_workspace_optimize(workspace_ids: list[str]) -> dict[str, Any]:
    """Derive advisory cross-workspace proposals from at least two immutable reports."""
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
        counter.update(report["facts"]["failure_classes"])
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
            "measured_baseline": {"workspace_count": item["workspace_count"], "sample_size": len(reports)},
            "expected_benefit": "reduce repeated workspace friction for this classified failure",
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

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from typing import Any

import grabowski_agent_workspace as workspace
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
REPORT_SCHEMA_VERSION = 3
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
PLATFORM_FRICTION_CLASSES = frozenset({
    "environment_toolchain_failure",
    "toolchain_probe_error",
    "preflight_probe_error",
    "invalid_review_output",
    "review_execution_failure",
    "output_limit_exceeded",
    "writer_binding_violation",
})
QUALITY_SIGNAL_CLASSES = frozenset({
    "semantic_test_failure",
    "review_verdict",
    "review_verdict_blocks_retry",
})
LIFECYCLE_DEBT_CLASSES = frozenset({
    "legacy_workspace_without_event_log",
    "unknown_external_closeout",
    "unknown_prior_outcome",
    "role_running",
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
    generic_failures: list[tuple[str | None, str]] = []
    specifically_classified_roles: set[str] = set()
    for event in events:
        outcome = event.get("outcome")
        role = event.get("role") if isinstance(event.get("role"), str) else None
        evidence = event.get("evidence") if isinstance(event.get("evidence"), dict) else {}
        failure = evidence.get("failure_classification")
        if isinstance(failure, str) and failure and failure not in SUCCESS_CLASSIFICATIONS:
            classes.append(failure)
            if role:
                specifically_classified_roles.add(role)
        elif outcome in {"environment_failure", "failed", "incomplete"}:
            generic_failures.append((role, f"{event.get('event_type')}:{outcome}"))
    legacy_receipt_classes = {
        role: _receipt_failure_class(manifest, role)
        for role in ("tests", "review")
    } if not events else {}
    for role, value in status.get("role_retry", {}).items():
        if not isinstance(value, dict):
            continue
        if role in specifically_classified_roles:
            continue
        if legacy_receipt_classes.get(role):
            classes.append(str(legacy_receipt_classes[role]))
            specifically_classified_roles.add(role)
            continue
        classification = value.get("classification")
        if (
            isinstance(classification, str)
            and classification not in SUCCESS_CLASSIFICATIONS
            and classification not in {"retry_limit_reached"}
        ):
            classes.append(f"{role}:{classification}")
            specifically_classified_roles.add(role)
    classes.extend(
        failure
        for role, failure in generic_failures
        if role is None or role not in specifically_classified_roles
    )
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


def _failure_category(value: str) -> str:
    """Separate workspace/platform friction from useful quality and lifecycle signals."""
    if value in NON_ACTIONABLE_FAILURE_CLASSES or value in LIFECYCLE_DEBT_CLASSES:
        return "lifecycle_debt"
    if (
        value in QUALITY_SIGNAL_CLASSES
        or value.endswith(":semantic_test_failure")
        or value.endswith(":review_verdict")
        or value.endswith(":review_verdict_blocks_retry")
    ):
        return "quality_signal"
    if (
        value in PLATFORM_FRICTION_CLASSES
        or value.endswith(":invalid_receipt")
        or value.endswith(":invalid_review_output")
        or value.endswith(":preflight_probe_error")
        or value.endswith(":toolchain_probe_error")
        or value.startswith("role_finished:")
    ):
        return "platform_friction"
    return "unclassified_failure"


def _categorized_failures(values: list[str]) -> dict[str, list[str]]:
    result = {
        "platform_friction": [],
        "quality_signal": [],
        "lifecycle_debt": [],
        "unclassified_failure": [],
    }
    for value in values:
        result[_failure_category(value)].append(value)
    return {key: sorted(set(items)) for key, items in result.items()}


def _is_actionable_failure(value: str) -> bool:
    """Compatibility name: only platform friction can drive workspace optimization."""
    return _failure_category(value) == "platform_friction"


def _closeout_handoff(closeout: list[dict[str, Any]], unresolved: list[str]) -> dict[str, Any]:
    verified = [str(item.get("item")) for item in closeout if item.get("status") == "verified"]
    return {
        "state": "complete" if not unresolved else "pending_external_truth",
        "verified_items": verified,
        "unresolved_items": list(unresolved),
        "next_action": "none" if not unresolved else f"verify:{unresolved[0]}",
        "mutation_authorized": False,
    }


def _event_recorded_unix(event: dict[str, Any]) -> float | None:
    value = event.get("recorded_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _event_timing_metrics(events: list[dict[str, Any]]) -> dict[str, float | None]:
    first: dict[str, float] = {}
    for event in events:
        event_type = event.get("event_type")
        observed = _event_recorded_unix(event)
        if isinstance(event_type, str) and observed is not None:
            first.setdefault(event_type, observed)
    start = first.get("plan_created")

    def elapsed(event_type: str) -> float | None:
        end = first.get(event_type)
        return None if start is None or end is None or end < start else round(end - start, 6)

    collection_start = first.get("collection_requested")
    collection_end = first.get("collection_completed")
    return {
        "workspace_ready_seconds": elapsed("workspace_ready"),
        "writer_observed_terminal_seconds": elapsed("collection_requested"),
        "collection_complete_seconds": elapsed("collection_completed"),
        "close_complete_seconds": (
            elapsed("workspace_closed")
            if "workspace_closed" in first
            else elapsed("workspace_stale_reconciled")
        ),
        "collection_duration_seconds": (
            round(collection_end - collection_start, 6)
            if collection_start is not None
            and collection_end is not None
            and collection_end >= collection_start
            else None
        ),
    }


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _cohort_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    identity = manifest.get("runtime_identity")
    if not isinstance(identity, dict):
        return {
            "kind": "legacy",
            "cohort_key": "legacy:unversioned",
            "runtime_release": None,
            "runtime_repo_head": None,
            "runtime_identity_sha256": None,
        }
    observed = identity.get("identity_sha256")
    unsigned = {key: value for key, value in identity.items() if key != "identity_sha256"}
    if not isinstance(observed, str) or observed != _sha256_json(unsigned):
        return {
            "kind": "invalid",
            "cohort_key": "invalid:runtime-identity",
            "runtime_release": None,
            "runtime_repo_head": None,
            "runtime_identity_sha256": None,
        }
    release = identity.get("runtime_release")
    head = identity.get("runtime_repo_head")
    cohort_key = f"release:{release}" if isinstance(release, str) and release else f"identity:{observed}"
    return {
        "kind": "versioned",
        "cohort_key": cohort_key,
        "runtime_release": release if isinstance(release, str) else None,
        "runtime_repo_head": head if isinstance(head, str) else None,
        "runtime_identity_sha256": observed,
    }


def _cohort_metrics(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for report in reports:
        cohort = report["facts"].get("cohort", {})
        key = str(cohort.get("cohort_key", "legacy:unversioned"))
        grouped.setdefault(key, []).append(report)
    result: list[dict[str, Any]] = []
    for key, members in sorted(grouped.items()):
        closed = sum(item["facts"].get("closed") is True for item in members)
        success = sum(item["facts"].get("closure_outcome") == "successful" for item in members)
        result.append({
            "cohort_key": key,
            "cohort_kind": members[0]["facts"].get("cohort", {}).get("kind"),
            "sample_size": len(members),
            "closed_count": closed,
            "successful_close_count": success,
            "completion_ratio": closed / len(members) if members else None,
            "closed_success_ratio": success / closed if closed else None,
            "platform_friction_workspace_count": sum(
                bool(item["facts"].get("workspace_friction_classes")) for item in members
            ),
            "quality_signal_workspace_count": sum(
                bool(item["facts"].get("quality_signal_classes")) for item in members
            ),
            "lifecycle_debt_workspace_count": sum(
                bool(item["facts"].get("lifecycle_debt_classes")) for item in members
            ),
            "source_report_sha256": [item["report_sha256"] for item in members],
        })
    return result


def _metrics_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    closed = sum(report["facts"].get("closed") is True for report in reports)
    success = sum(report["facts"].get("closure_outcome") == "successful" for report in reports)
    failed = sum(bool(report["facts"].get("failed_roles")) for report in reports)
    platform_friction = sum(bool(report["facts"].get("workspace_friction_classes")) for report in reports)
    quality_signals = sum(bool(report["facts"].get("quality_signal_classes")) for report in reports)
    lifecycle_debt = sum(bool(report["facts"].get("lifecycle_debt_classes")) for report in reports)
    cohorts = _cohort_metrics(reports)
    timing_fields = (
        "workspace_ready_seconds",
        "writer_observed_terminal_seconds",
        "collection_complete_seconds",
        "close_complete_seconds",
        "collection_duration_seconds",
    )
    timing_medians = {
        field: _median([
            float(value)
            for report in reports
            if isinstance((value := report["facts"].get("timing", {}).get(field)), (int, float))
            and not isinstance(value, bool)
        ])
        for field in timing_fields
    }
    body = {
        "schema_version": 2,
        "sample_size": len(reports),
        "closed_count": closed,
        "successful_close_count": success,
        "failed_role_workspace_count": failed,
        "platform_friction_workspace_count": platform_friction,
        "quality_signal_workspace_count": quality_signals,
        "lifecycle_debt_workspace_count": lifecycle_debt,
        "actionable_failure_workspace_count": platform_friction,
        "completion_ratio": (closed / len(reports)) if reports else None,
        "closed_success_ratio": (success / closed) if closed else None,
        "success_ratio": (success / closed) if closed else None,
        "legacy_workspace_count": sum(
            report["facts"].get("cohort", {}).get("kind", "legacy") == "legacy" for report in reports
        ),
        "versioned_workspace_count": sum(
            report["facts"].get("cohort", {}).get("kind") == "versioned" for report in reports
        ),
        "cohorts": cohorts,
        "timing_median_seconds": timing_medians,
        "source_report_sha256": [report["report_sha256"] for report in reports],
        "read_only_projection": True,
        "does_not_establish": ["causality", "global_workspace_population", "automatic_change_authority"],
    }
    body["metrics_sha256"] = _sha256_json(body)
    return body


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
    categorized = _categorized_failures(failure_classes)
    typed_event_evidence = bool(
        integrity.get("present") and integrity.get("integrity_valid")
    )
    workspace_friction_classes = (
        categorized["platform_friction"] if typed_event_evidence else []
    )
    quality_signal_classes = categorized["quality_signal"]
    lifecycle_debt_classes = list(categorized["lifecycle_debt"])
    if not typed_event_evidence:
        lifecycle_debt_classes = sorted(set([*lifecycle_debt_classes, "legacy_workspace_without_event_log"]))
    actionable_failure_classes = list(workspace_friction_classes)
    supplied = _validate_closeout_evidence(workspace_id, manifest, external_closeout_evidence)
    closeout, unresolved = _resolved_closeout(status, supplied)
    identity = _writer_identity(manifest, status)
    facts = {
        "workspace_id": workspace_id,
        "binding": manifest.get("binding"),
        "created_at": manifest.get("created_at"),
        "updated_at": manifest.get("updated_at"),
        "route_evidence": manifest.get("route_evidence"),
        "timing": _event_timing_metrics(events),
        **identity,
        "closed": status.get("closed"),
        "closure_outcome": status.get("closure_outcome"),
        "success_ready": status.get("success_ready"),
        "failed_roles": status.get("failed_roles", []),
        "event_log": integrity,
        "failure_classes": failure_classes,
        "failure_taxonomy": categorized,
        "workspace_friction_classes": workspace_friction_classes,
        "quality_signal_classes": quality_signal_classes,
        "lifecycle_debt_classes": lifecycle_debt_classes,
        "unclassified_failure_classes": categorized["unclassified_failure"],
        "actionable_failure_classes": actionable_failure_classes,
        "cohort": _cohort_identity(manifest),
        "legacy_diagnostic_failure_classes": (
            failure_classes if not typed_event_evidence else []
        ),
        "external_closeout": closeout,
        "unresolved_external_closeout": unresolved,
        "external_closeout_handoff": _closeout_handoff(closeout, unresolved),
        "supplied_closeout_evidence_sha256": (
            external_closeout_evidence.get("evidence_sha256")
            if isinstance(external_closeout_evidence, dict)
            else None
        ),
        "outcome_receipts": manifest.get("outcome_receipts", {}),
    }
    inferences: list[dict[str, Any]] = []
    actionable = facts["workspace_friction_classes"]
    if actionable:
        inferences.append({
            "inference": "workspace experienced classified platform friction",
            "failure_classes": actionable,
            "confidence": "high" if integrity.get("integrity_valid") else "medium",
        })
    if quality_signal_classes:
        inferences.append({
            "inference": "workspace produced quality signals that must not be treated as platform friction",
            "failure_classes": quality_signal_classes,
            "confidence": "high",
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


def workspace_metrics_snapshot(limit: int = MAX_OPTIMIZER_WORKSPACES) -> dict[str, Any]:
    """Return a bounded, current-cohort workspace evidence snapshot without authority."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_OPTIMIZER_WORKSPACES:
        raise WorkspaceObserverError(
            f"limit must be between 1 and {MAX_OPTIMIZER_WORKSPACES}"
        )
    root = workspace.WORKSPACE_ROOT
    selected: list[str] = []
    inventory_errors: list[dict[str, Any]] = []
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise WorkspaceObserverError("workspace root must be a real directory")
        for directory in sorted(root.iterdir(), key=lambda item: item.name):
            if len(selected) >= limit:
                break
            if (
                directory.is_dir()
                and not directory.is_symlink()
                and workspace.WORKSPACE_ID_RE.fullmatch(directory.name) is not None
            ):
                selected.append(directory.name)
    reports: list[dict[str, Any]] = []
    for identifier in selected:
        try:
            reports.append(
                _observer_report(
                    identifier,
                    activation_reason="workspace-metrics-snapshot",
                )
            )
        except Exception as exc:
            inventory_errors.append({
                "workspace_id": identifier,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
            })
    metrics = _metrics_summary(reports)
    current_identity = workspace._workspace_runtime_identity()
    current_cohort = _cohort_identity({"runtime_identity": current_identity})
    current_reports = [
        report
        for report in reports
        if report["facts"].get("cohort", {}).get("cohort_key")
        == current_cohort["cohort_key"]
    ]
    current_metrics = _metrics_summary(current_reports)
    current_source_hashes = [report["report_sha256"] for report in current_reports]
    fingerprint_body = {
        "schema_version": 1,
        "cohort_key": current_cohort["cohort_key"],
        "runtime_identity_sha256": current_cohort["runtime_identity_sha256"],
        "source_report_sha256": current_source_hashes,
        "metrics_sha256": current_metrics["metrics_sha256"],
    }
    fingerprint = _sha256_json(fingerprint_body) if current_reports else None
    route_records = [
        {
            "workspace_id": report["workspace_id"],
            "cohort_key": report["facts"].get("cohort", {}).get("cohort_key"),
            "route_evidence": report["facts"].get("route_evidence"),
            "closed": report["facts"].get("closed"),
            "closure_outcome": report["facts"].get("closure_outcome"),
            "workspace_friction_classes": report["facts"].get("workspace_friction_classes", []),
            "quality_signal_classes": report["facts"].get("quality_signal_classes", []),
            "timing": report["facts"].get("timing", {}),
            "report_sha256": report["report_sha256"],
        }
        for report in current_reports
    ]
    body = {
        "schema_version": 1,
        "report_kind": "workspace_metrics_snapshot",
        "workspace_limit": limit,
        "selected_workspace_count": len(selected),
        "observed_workspace_count": len(reports),
        "inventory_errors": inventory_errors,
        "inventory_complete": not inventory_errors and len(selected) < limit,
        "current_cohort": current_cohort,
        "current_cohort_sample_size": len(current_reports),
        "current_cohort_metrics": current_metrics,
        "all_cohort_metrics": metrics,
        "route_records": route_records,
        "friction_fingerprint_sha256": fingerprint,
        "friction_fingerprint_unavailable_reason": (
            None if fingerprint is not None else "no_current_runtime_cohort_workspaces"
        ),
        "integrity_valid": not inventory_errors,
        "read_only_projection": True,
        "execution_authorized": False,
        "automatic_live_routing_enabled": False,
        "does_not_establish": [
            "causality",
            "route_superiority",
            "live_routing_promotion",
            "automatic_change_authority",
        ],
    }
    return {**body, "snapshot_sha256": _sha256_json(body)}


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
    workspaces_by_class: dict[tuple[str, str], list[str]] = {}
    quality_by_class: dict[tuple[str, str], list[str]] = {}
    lifecycle_by_class: dict[tuple[str, str], list[str]] = {}
    cohort_counts: dict[str, int] = {}
    for report in reports:
        identifier = str(report["workspace_id"])
        cohort_key = str(report["facts"].get("cohort", {}).get("cohort_key", "legacy:unversioned"))
        cohort_counts[cohort_key] = cohort_counts.get(cohort_key, 0) + 1
        for failure_class in report["facts"]["workspace_friction_classes"]:
            workspaces_by_class.setdefault((cohort_key, failure_class), []).append(identifier)
        for failure_class in report["facts"]["quality_signal_classes"]:
            quality_by_class.setdefault((cohort_key, failure_class), []).append(identifier)
        for failure_class in report["facts"]["lifecycle_debt_classes"]:
            lifecycle_by_class.setdefault((cohort_key, failure_class), []).append(identifier)
    repeated = [
        {
            "cohort_key": cohort_key,
            "failure_class": failure_class,
            "workspace_count": len(affected),
            "workspace_ids": affected,
        }
        for (cohort_key, failure_class), affected in sorted(
            workspaces_by_class.items(),
            key=lambda item: (-len(item[1]), item[0][0], item[0][1]),
        )
        if len(affected) >= 2
    ]
    quality_signals = [
        {
            "cohort_key": cohort_key,
            "failure_class": failure_class,
            "workspace_count": len(affected),
            "workspace_ids": affected,
            "drives_workspace_optimization": False,
        }
        for (cohort_key, failure_class), affected in sorted(
            quality_by_class.items(),
            key=lambda item: (-len(item[1]), item[0][0], item[0][1]),
        )
    ]
    lifecycle_debt = [
        {
            "cohort_key": cohort_key,
            "failure_class": failure_class,
            "workspace_count": len(affected),
            "workspace_ids": affected,
            "drives_workspace_optimization": False,
        }
        for (cohort_key, failure_class), affected in sorted(
            lifecycle_by_class.items(),
            key=lambda item: (-len(item[1]), item[0][0], item[0][1]),
        )
    ]
    proposals = []
    for item in repeated:
        proposals.append({
            "rank": len(proposals) + 1,
            "failure_class": item["failure_class"],
            "measured_baseline": {
                "workspace_count": item["workspace_count"],
                "sample_size": len(reports),
                "cohort_key": item["cohort_key"],
                "cohort_sample_size": cohort_counts[item["cohort_key"]],
                "independent_workspace_ids": item["workspace_ids"],
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
        "quality_signals": quality_signals,
        "lifecycle_debt": lifecycle_debt,
        "metrics": _metrics_summary(reports),
        "proposals": proposals,
        "minimum_evidence_met": any(count >= 2 for count in cohort_counts.values()),
        "proposal_threshold": {
            "minimum_independent_workspaces": 2,
            "same_cohort_required": True,
            "success_states_counted_as_failures": False,
            "quality_signals_counted_as_platform_friction": False,
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

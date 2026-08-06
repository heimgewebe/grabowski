from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Literal, cast, get_args

import grabowski_audit_query as audit_query
import grabowski_mcp as base
import grabowski_operator_core as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

EffectProfile = Literal[
    "read_only",
    "workspace_write",
    "repository_write",
    "host_write",
    "remote_write",
    "unknown",
]
ReposkopPolicy = Literal["required", "not_required"]
EFFECT_PROFILES = frozenset(get_args(EffectProfile))
REPOSKOP_POLICIES = frozenset(get_args(ReposkopPolicy))
AGENT_EXECUTABLES = frozenset(
    {"agy", "claude", "cline", "codex", "grok", "grok-cli", "opencode", "openhands"}
)
READ_ONLY_AGENT_MODES = frozenset({"plan", "read-only"})
POLICY_VERSION = 2
SURFACE = "task_start"
MAX_SCAN_LIMIT = 50_000
DEFAULT_SCAN_LIMIT = 10_000
MAX_SAMPLE_REFS = 20
MIN_OPERATIONAL_FAILURE_SAMPLE = 3
MIN_RUNTIME_REGRESSION_SAMPLE = 60
RUNTIME_REGRESSION_FACTOR = 1.5
FINDING_TAXONOMY_VERSION = 2
REVIEW_SCHEMA_VERSION = 1
MAX_REVIEW_SCAN_RECORDS = 500_000
MAX_REVIEW_EVIDENCE_REFS = 20
MAX_REVIEW_REASON_CODES = 16
MIN_FALSE_POSITIVE_CLUSTER = 3
MIN_FALSE_NEGATIVE_CLUSTER = 2
REVIEW_CLASSIFICATIONS = frozenset(
    {
        "confirmed_prevention",
        "beneficial_context",
        "neutral",
        "false_positive",
        "false_negative",
        "operational_failure",
        "unresolved",
    }
)
REVIEW_SCOPES = frozenset({"technical", "repository", "delivery"})
REVIEWER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
REASON_CODE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
AUDIT_REF_RE = re.compile(r"audit-record-sha256:[0-9a-f]{64}\Z")
EVIDENCE_REF_RE = re.compile(
    r"(?:audit-record-sha256|receipt-sha256|test-run-sha256|deployment-receipt-sha256):[0-9a-f]{64}\Z"
    r"|(?:git-commit-sha|github-pr-head-sha):[0-9a-f]{40}\Z"
)


class ReposkopReviewError(RuntimeError):
    pass


class ReposkopReviewInputError(ValueError):
    pass


class ReposkopReviewConflictError(ReposkopReviewError):
    pass


class ReposkopReviewIntegrityError(ReposkopReviewError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def validate_effect_profile(value: str | None) -> EffectProfile | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in EFFECT_PROFILES:
        raise ValueError(f"effect_profile must be one of {sorted(EFFECT_PROFILES)}")
    return cast(EffectProfile, value)


def _argument_value(argv: list[str], *names: str) -> str | None:
    for index, item in enumerate(argv):
        if item in names:
            return argv[index + 1] if index + 1 < len(argv) else None
        for name in names:
            prefix = f"{name}="
            if item.startswith(prefix):
                return item[len(prefix) :]
    return None


def _agent_read_only(argv: list[str], executable: str) -> bool:
    if "--read-only" in argv:
        return True
    if executable == "codex":
        return _argument_value(argv, "--sandbox", "-s") in READ_ONLY_AGENT_MODES
    return _argument_value(argv, "--permission-mode") in READ_ONLY_AGENT_MODES


def classify_task_effect(
    *,
    transport: str,
    argv: list[str],
    mutating_workspace: str | None,
    explicit_effect_profile: str | None = None,
) -> dict[str, Any]:
    explicit = validate_effect_profile(explicit_effect_profile)
    executable = Path(argv[0]).name.lower()
    declared_agent = executable in AGENT_EXECUTABLES
    read_only_mode = declared_agent and _agent_read_only(argv, executable)

    if declared_agent and explicit == "unknown":
        raise ValueError("declared local or remote agents may not use effect_profile=unknown")

    if not declared_agent:
        profile: EffectProfile = explicit or "unknown"
        return {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "surface": SURFACE,
            "effect_profile": profile,
            "reposkop_policy": "not_required",
            "agent_executable": None,
            "classification_source": "explicit" if explicit is not None else "legacy_default_unknown",
        }

    if transport != "local":
        derived: EffectProfile = "read_only" if read_only_mode else "remote_write"
        if explicit is not None and explicit != derived:
            raise ValueError(
                f"effect_profile={explicit} conflicts with derived agent profile {derived}"
            )
        return {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "surface": SURFACE,
            "effect_profile": derived,
            "reposkop_policy": "not_required",
            "agent_executable": executable,
            "classification_source": "explicit" if explicit is not None else "agent_command",
        }

    if read_only_mode:
        if explicit is not None and explicit != "read_only":
            raise ValueError(
                f"effect_profile={explicit} conflicts with read-only agent mode"
            )
        return {
            "schema_version": 1,
            "policy_version": POLICY_VERSION,
            "surface": SURFACE,
            "effect_profile": "read_only",
            "reposkop_policy": "not_required",
            "agent_executable": executable,
            "classification_source": "explicit" if explicit is not None else "agent_command",
        }

    if mutating_workspace is None:
        raise RuntimeError("write-capable local agent classification has no workspace")
    if explicit is not None and explicit not in {"workspace_write", "repository_write"}:
        raise ValueError(
            f"effect_profile={explicit} conflicts with write-capable local agent"
        )
    profile = explicit or "workspace_write"
    return {
        "schema_version": 1,
        "policy_version": POLICY_VERSION,
        "surface": SURFACE,
        "effect_profile": profile,
        "reposkop_policy": "required",
        "agent_executable": executable,
        "classification_source": "explicit" if explicit is not None else "agent_command",
    }


def evaluation_id(
    *,
    task_id: str,
    execution_identity_sha256: str,
    checkout_binding_sha256: str,
    argv_sha256: str,
    policy_version: int = POLICY_VERSION,
) -> str:
    return _sha256_json(
        {
            "schema_version": 1,
            "kind": "grabowski.reposkop_evaluation_identity",
            "policy_version": policy_version,
            "surface": SURFACE,
            "task_id": task_id,
            "execution_identity_sha256": execution_identity_sha256,
            "checkout_binding_sha256": checkout_binding_sha256,
            "argv_sha256": argv_sha256,
        }
    )


def _finding_add(
    counts: dict[str, int],
    categories: dict[str, int],
    reasons: set[str],
    *,
    severity: str,
    category: str,
    reason: str,
    count: int = 1,
) -> None:
    if count <= 0:
        return
    counts[severity] = counts.get(severity, 0) + count
    categories[category] = categories.get(category, 0) + count
    reasons.add(reason)


def finding_summary(report: dict[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {
            "finding_taxonomy_status": "not_available_v1",
            "finding_taxonomy_version": None,
            "finding_count": None,
            "finding_counts": {},
            "finding_categories": {},
            "finding_reason_codes": [],
            "projection_state": None,
            "advisory_posture": "unknown",
        }

    counts = {"critical": 0, "error": 0, "warning": 0, "information": 0}
    categories: dict[str, int] = {}
    reasons: set[str] = set()
    observation = report.get("observation")
    projection = report.get("projection")
    if not isinstance(observation, dict) or not isinstance(projection, dict):
        _finding_add(
            counts,
            categories,
            reasons,
            severity="error",
            category="report_integrity",
            reason="report_structure_incomplete",
        )
        projection_state = "unknown"
    else:
        errors = observation.get("errors")
        if isinstance(errors, list) and errors:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="error",
                category="observation",
                reason="observation_errors_present",
                count=len(errors),
            )
        git = observation.get("git")
        if not isinstance(git, dict):
            git = {}
            _finding_add(
                counts,
                categories,
                reasons,
                severity="error",
                category="observation",
                reason="git_observation_missing",
            )
        granular_worktree_findings = [
            reason
            for field, reason in (
                ("staged", "staged_changes_present"),
                ("unstaged", "unstaged_changes_present"),
                ("untracked", "untracked_changes_present"),
            )
            if git.get(field) is True
        ]
        for reason in granular_worktree_findings:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="warning",
                category="working_tree_state",
                reason=reason,
            )
        if git.get("dirty") is True:
            reasons.add("working_tree_dirty")
            if not granular_worktree_findings:
                _finding_add(
                    counts,
                    categories,
                    reasons,
                    severity="warning",
                    category="working_tree_state",
                    reason="working_tree_dirty",
                )
        operation_state = git.get("operation_state")
        if isinstance(operation_state, list) and operation_state:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="error",
                category="git_operation",
                reason="git_operation_in_progress",
                count=len(operation_state),
            )
        if git.get("detached") is True:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="warning",
                category="checkout_identity",
                reason="detached_head",
            )
        if git.get("alternates_configured") is True:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="warning",
                category="checkout_identity",
                reason="git_alternates_configured",
            )
        if git.get("gitmodules_present") is True:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="information",
                category="repository_structure",
                reason="gitmodules_present",
            )
        ahead = git.get("ahead")
        behind = git.get("behind")
        if type(ahead) is int and ahead > 0:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="information",
                category="remote_freshness",
                reason="upstream_ahead",
            )
        if type(behind) is int and behind > 0:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="warning",
                category="remote_freshness",
                reason="upstream_behind",
            )
        upstream_freshness = git.get("upstream_freshness")
        if upstream_freshness not in {"current", "fresh", "verified"}:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="information",
                category="remote_freshness",
                reason=(
                    "upstream_unbound"
                    if git.get("upstream") in {None, ""}
                    else "upstream_freshness_unverified"
                ),
            )
        role = observation.get("role")
        if isinstance(role, dict) and role.get("value") not in {
            "canonical_checkout",
            "linked_worktree",
            "standalone_checkout",
        }:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="warning",
                category="checkout_identity",
                reason="checkout_role_unrecognized",
            )
        validation = projection.get("observation_validation")
        if isinstance(validation, dict) and validation.get("valid") is False:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="error",
                category="report_integrity",
                reason="observation_validation_failed",
            )
        active_bindings = projection.get("active_bindings")
        if isinstance(active_bindings, list) and active_bindings:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="information",
                category="lifecycle_evidence",
                reason="active_lifecycle_bindings_present",
                count=len(active_bindings),
            )
        known_projection_reasons = {
            "lifecycle_evidence_missing": (
                "information",
                "lifecycle_evidence",
                "lifecycle_evidence_missing",
            ),
            "lifecycle_evidence_invalid": (
                "error",
                "lifecycle_evidence",
                "lifecycle_evidence_invalid",
            ),
            "checkout_identity_conflict": (
                "error",
                "checkout_identity",
                "checkout_identity_conflict",
            ),
            "checkout_identity_mismatch": (
                "error",
                "checkout_identity",
                "checkout_identity_mismatch",
            ),
        }
        projection_reasons = projection.get("reasons")
        if isinstance(projection_reasons, list):
            for value in projection_reasons[:32]:
                if not isinstance(value, str):
                    continue
                mapped = known_projection_reasons.get(value)
                if mapped is None:
                    mapped = (
                        "information",
                        "projection",
                        "projection_reason_other",
                    )
                _finding_add(
                    counts,
                    categories,
                    reasons,
                    severity=mapped[0],
                    category=mapped[1],
                    reason=mapped[2],
                )
        raw_state = projection.get("state")
        projection_state = (
            raw_state
            if isinstance(raw_state, str)
            and REASON_CODE_RE.fullmatch(raw_state.replace("-", "_")) is not None
            else "unknown"
        )
        normalized_state = projection_state.replace("-", "_")
        if normalized_state in {"conflict", "blocking", "invalid", "error"}:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="error",
                category="coherence_state",
                reason=f"projection_state_{normalized_state}",
            )
        elif normalized_state in {"inconclusive", "unknown"}:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="information",
                category="coherence_state",
                reason=f"projection_state_{normalized_state}",
            )
        elif normalized_state not in {"coherent", "clean", "ready", "verified"}:
            _finding_add(
                counts,
                categories,
                reasons,
                severity="information",
                category="coherence_state",
                reason="projection_state_other",
            )

    total = sum(counts.values())
    posture = (
        "attention"
        if counts["critical"] or counts["error"] or counts["warning"]
        else "informational"
        if counts["information"]
        else "clean"
    )
    return {
        "finding_taxonomy_status": "available_v2",
        "finding_taxonomy_version": FINDING_TAXONOMY_VERSION,
        "finding_count": total,
        "finding_counts": counts,
        "finding_categories": dict(sorted(categories.items())),
        "finding_reason_codes": sorted(reasons),
        "projection_state": projection_state,
        "advisory_posture": posture,
    }


def decision_reason_codes(
    summary: dict[str, Any] | None,
    *,
    final_decision: str,
    failure_category: str | None = None,
) -> list[str]:
    if final_decision == "block":
        return sorted(
            {
                "reposkop_evaluation_failed",
                failure_category or "unknown_operational_failure",
            }
        )
    value = summary if isinstance(summary, dict) else {}
    counts = value.get("finding_counts")
    codes = {"reposkop_report_verified", "reposkop_taxonomy_attached"}
    if isinstance(counts, dict):
        if int(counts.get("critical", 0) or 0) or int(counts.get("error", 0) or 0) or int(counts.get("warning", 0) or 0):
            codes.add("reposkop_advisory_attention")
        elif int(counts.get("information", 0) or 0):
            codes.add("reposkop_informational_context")
        else:
            codes.add("reposkop_no_findings")
    return sorted(codes)


def failure_summary(error: BaseException) -> dict[str, Any]:
    message = str(error).lower()
    mappings = (
        ("observation must be complete", "observation_incomplete"),
        ("kind or schema is unsupported", "report_schema_invalid"),
        ("mismatched", "report_integrity_invalid"),
        ("not bound", "report_integrity_invalid"),
        ("executable identity changed", "executable_integrity_failure"),
        ("target identity changed", "target_identity_changed"),
        ("timed out", "report_execution_timeout"),
        ("returncode", "report_execution_failure"),
        ("workspace lease", "workspace_lease_invalid"),
        ("usage receipt", "receipt_publication_failure"),
        ("receipt root", "receipt_publication_failure"),
    )
    category = "unknown_operational_failure"
    for fragment, candidate in mappings:
        if fragment in message:
            category = candidate
            break
    return {
        "failure_category": category,
        "decision_reason_codes": decision_reason_codes(
            None,
            final_decision="block",
            failure_category=category,
        ),
    }


def append_event(record: dict[str, Any]) -> str:
    forbidden = {"argv", "command", "prompt", "raw_report", "error", "stderr", "stdout"}
    present = forbidden & set(record)
    if present:
        raise ValueError(f"Reposkop public audit event contains forbidden fields: {sorted(present)}")
    digest = base._append_audit_with_digest(record)
    return f"audit-record-sha256:{digest}"


def enrich_attestation(
    attestation: dict[str, Any],
    *,
    evaluation: str,
    classification: dict[str, Any],
    checkout_binding_sha256: str,
    duration_ms: int,
) -> dict[str, Any]:
    material = {
        key: value
        for key, value in attestation.items()
        if key != "execution_binding_sha256"
    }
    material.update(
        {
            "evaluation_id": evaluation,
            "effect_profile": classification["effect_profile"],
            "reposkop_policy": classification["reposkop_policy"],
            "surface": classification["surface"],
            "agent_executable": classification["agent_executable"],
            "checkout_binding_sha256": checkout_binding_sha256,
            "duration_ms": duration_ms,
            "finding_summary": (
                dict(attestation["finding_summary"])
                if isinstance(attestation.get("finding_summary"), dict)
                else finding_summary()
            ),
        }
    )
    return {**material, "execution_binding_sha256": _sha256_json(material)}


def _raw_records(
    *,
    since_unix: int,
    scan_limit: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    snapshot = audit_query.capture_verified_audit_snapshot()
    records: list[dict[str, Any]] = []
    scanned = 0
    for segment in reversed(snapshot.segments):
        data = audit_query._load_snapshot_segment(segment)
        lines = data.splitlines()
        if len(lines) != segment.records:
            raise RuntimeError("verified audit segment changed during Reposkop projection")
        for raw_line in reversed(lines):
            if scanned >= scan_limit:
                break
            scanned += 1
            parsed = json.loads(raw_line.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise RuntimeError("verified audit record is not an object")
            timestamp = parsed.get("timestamp_unix")
            if isinstance(timestamp, int) and timestamp < since_unix:
                continue
            digest = parsed.get("record_sha256")
            if not isinstance(digest, str):
                digest = hashlib.sha256(raw_line).hexdigest()
            records.append({**parsed, "_audit_ref": f"audit-record-sha256:{digest}"})
        if scanned >= scan_limit:
            break
    return records, {
        "chain_content_sha256": snapshot.chain_content_sha256,
        "chain_materialization_sha256": snapshot.chain_materialization_sha256,
        "total_records": snapshot.total_records,
        "scanned_records": scanned,
        "scan_limit": scan_limit,
        "scan_truncated": snapshot.total_records > scanned,
    }


def _review_records(
    *,
    evaluation: str,
    evidence_refs: set[str],
    scan_limit: int = MAX_REVIEW_SCAN_RECORDS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    snapshot = audit_query.capture_verified_audit_snapshot()
    if snapshot.total_records > scan_limit:
        return [], {
            "chain_content_sha256": snapshot.chain_content_sha256,
            "chain_materialization_sha256": snapshot.chain_materialization_sha256,
            "total_records": snapshot.total_records,
            "scanned_records": 0,
            "retained_records": 0,
            "scan_limit": scan_limit,
            "scan_truncated": True,
        }
    selected: list[dict[str, Any]] = []
    scanned = 0
    for segment in reversed(snapshot.segments):
        data = audit_query._load_snapshot_segment(segment)
        lines = data.splitlines()
        if len(lines) != segment.records:
            raise RuntimeError(
                "verified audit segment changed during Reposkop review scan"
            )
        for raw_line in reversed(lines):
            scanned += 1
            parsed = json.loads(raw_line.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise RuntimeError("verified audit record is not an object")
            digest = parsed.get("record_sha256")
            if not isinstance(digest, str):
                digest = hashlib.sha256(raw_line).hexdigest()
            audit_ref = f"audit-record-sha256:{digest}"
            if (
                audit_ref in evidence_refs
                or parsed.get("evaluation_id") == evaluation
                or parsed.get("transaction_id") == evaluation
            ):
                selected.append({**parsed, "_audit_ref": audit_ref})
    return selected, {
        "chain_content_sha256": snapshot.chain_content_sha256,
        "chain_materialization_sha256": snapshot.chain_materialization_sha256,
        "total_records": snapshot.total_records,
        "scanned_records": scanned,
        "retained_records": len(selected),
        "scan_limit": scan_limit,
        "scan_truncated": False,
    }


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def _candidate(
    metric: str,
    *,
    status: str,
    threshold: Any,
    observed: Any,
    sample_size: int,
    evidence_refs: list[str],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    binding = {
        "metric": metric,
        "policy_version": POLICY_VERSION,
        "threshold": threshold,
        "context": context or {},
    }
    return {
        "metric": metric,
        "status": status,
        "threshold": threshold,
        "observed": observed,
        "sample_size": sample_size,
        "evidence_refs": evidence_refs[:MAX_SAMPLE_REFS],
        "deduplication_key": _sha256_json(binding),
        "context": context or {},
    }


def _review_required_text(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ReposkopReviewInputError(f"{field} must be a non-empty trimmed string")
    if len(value.encode("utf-8")) > maximum or "\x00" in value:
        raise ReposkopReviewInputError(f"{field} is too long or contains NUL")
    return value


def _review_reason_codes(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_REVIEW_REASON_CODES:
        raise ReposkopReviewInputError(
            f"reason_codes must contain between 1 and {MAX_REVIEW_REASON_CODES} entries"
        )
    result: list[str] = []
    for item in value:
        code = _review_required_text(item, "reason_codes entry", maximum=64)
        if REASON_CODE_RE.fullmatch(code) is None:
            raise ReposkopReviewInputError("reason_codes entries are invalid")
        result.append(code)
    if len(set(result)) != len(result):
        raise ReposkopReviewInputError("reason_codes entries must be unique")
    return sorted(result)


def _review_evidence_refs(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_REVIEW_EVIDENCE_REFS:
        raise ReposkopReviewInputError(
            f"evidence_refs must contain between 1 and {MAX_REVIEW_EVIDENCE_REFS} entries"
        )
    result: list[str] = []
    for item in value:
        reference = _review_required_text(item, "evidence_refs entry")
        if EVIDENCE_REF_RE.fullmatch(reference) is None:
            raise ReposkopReviewInputError("evidence_refs entries are unsupported")
        result.append(reference)
    if len(set(result)) != len(result):
        raise ReposkopReviewInputError("evidence_refs entries must be unique")
    return sorted(result)


def _review_audit_ref(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    reference = _review_required_text(value, field, maximum=96)
    if AUDIT_REF_RE.fullmatch(reference) is None:
        raise ReposkopReviewInputError(f"{field} must be one audit-record SHA reference")
    return reference


def record_review_classification(parameters: dict[str, Any]) -> dict[str, Any]:
    expected_fields = {
        "evaluation_id",
        "classification",
        "reviewer",
        "scope",
        "detectable_category",
        "reason_codes",
        "evidence_refs",
        "expected_decision_audit_ref",
        "supersedes_review_audit_ref",
    }
    if not isinstance(parameters, dict) or set(parameters) != expected_fields:
        missing = sorted(expected_fields - set(parameters or {}))
        extra = sorted(set(parameters or {}) - expected_fields)
        raise ReposkopReviewInputError(
            f"review classification shape is invalid: missing={missing}; extra={extra}"
        )
    evaluation = _review_required_text(parameters["evaluation_id"], "evaluation_id", maximum=64)
    if SHA256_RE.fullmatch(evaluation) is None:
        raise ReposkopReviewInputError("evaluation_id must be a lowercase SHA-256")
    classification = _review_required_text(parameters["classification"], "classification", maximum=64)
    if classification not in REVIEW_CLASSIFICATIONS:
        raise ReposkopReviewInputError(
            f"classification must be one of {sorted(REVIEW_CLASSIFICATIONS)}"
        )
    reviewer = _review_required_text(parameters["reviewer"], "reviewer", maximum=128)
    if REVIEWER_RE.fullmatch(reviewer) is None:
        raise ReposkopReviewInputError("reviewer is invalid")
    scope = _review_required_text(parameters["scope"], "scope", maximum=32)
    if scope not in REVIEW_SCOPES:
        raise ReposkopReviewInputError(f"scope must be one of {sorted(REVIEW_SCOPES)}")
    detectable_category = _review_required_text(
        parameters["detectable_category"], "detectable_category", maximum=64
    )
    if REASON_CODE_RE.fullmatch(detectable_category) is None:
        raise ReposkopReviewInputError("detectable_category is invalid")
    reasons = _review_reason_codes(parameters["reason_codes"])
    evidence_refs = _review_evidence_refs(parameters["evidence_refs"])
    expected_decision_ref = _review_audit_ref(
        parameters["expected_decision_audit_ref"], "expected_decision_audit_ref"
    )
    supersedes_ref = _review_audit_ref(
        parameters["supersedes_review_audit_ref"],
        "supersedes_review_audit_ref",
        allow_empty=True,
    )
    if expected_decision_ref not in evidence_refs:
        raise ReposkopReviewInputError(
            "evidence_refs must include expected_decision_audit_ref"
        )
    corroborating_refs = [
        reference
        for reference in evidence_refs
        if reference != expected_decision_ref
    ]
    if classification != "unresolved" and not corroborating_refs:
        raise ReposkopReviewInputError(
            "material review classifications require corroborating evidence beyond the decision"
        )

    records, source = _review_records(
        evaluation=evaluation,
        evidence_refs=set(evidence_refs),
        scan_limit=MAX_REVIEW_SCAN_RECORDS,
    )
    if source.get("scan_truncated") is True:
        raise ReposkopReviewIntegrityError(
            "verified audit chain exceeds the bounded Reposkop review scan"
        )
    audit_records_by_ref = {
        str(record["_audit_ref"]): record
        for record in records
        if isinstance(record.get("_audit_ref"), str)
    }
    missing_audit_refs = sorted(
        reference
        for reference in evidence_refs
        if reference.startswith("audit-record-sha256:")
        and reference not in audit_records_by_ref
    )
    if missing_audit_refs:
        raise ReposkopReviewIntegrityError(
            "review evidence references are unavailable in the verified audit window"
        )
    verified_corroborating: list[str] = []
    if classification != "unresolved":
        verified_corroborating = [
            reference
            for reference in corroborating_refs
            if reference in audit_records_by_ref
            and audit_records_by_ref[reference].get("operation")
            not in {
                "reposkop-evaluation-requested",
                "reposkop-decision-applied",
                "reposkop-review-classification-recorded",
            }
        ]
        if not verified_corroborating:
            raise ReposkopReviewIntegrityError(
                "material review classifications require verified corroborating audit evidence"
            )
    evaluation_records = [
        record for record in records if record.get("evaluation_id") == evaluation
    ]
    decision = next(
        (
            record
            for record in evaluation_records
            if record.get("operation") == "reposkop-decision-applied"
            and record.get("_audit_ref") == expected_decision_ref
        ),
        None,
    )
    if decision is None:
        raise ReposkopReviewIntegrityError(
            "expected Reposkop decision evidence is unavailable in the verified audit window"
        )
    request = next(
        (
            record
            for record in evaluation_records
            if record.get("operation") == "reposkop-evaluation-requested"
        ),
        None,
    )
    task_id = (request or decision).get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise ReposkopReviewIntegrityError("Reposkop evaluation has no task binding")
    if verified_corroborating:
        correlated_corroborating = [
            reference
            for reference in verified_corroborating
            if (
                audit_records_by_ref[reference].get("evaluation_id") == evaluation
                or audit_records_by_ref[reference].get("transaction_id") == evaluation
                or audit_records_by_ref[reference].get("task_id") == task_id
            )
        ]
        if not correlated_corroborating:
            raise ReposkopReviewIntegrityError(
                "corroborating audit evidence is not bound to the reviewed evaluation or task"
            )
    final_decision = decision.get("final_decision")
    if final_decision not in {"allow", "block"}:
        raise ReposkopReviewIntegrityError("Reposkop decision outcome is unsupported")
    if classification in {"confirmed_prevention", "false_positive", "operational_failure"} and final_decision != "block":
        raise ReposkopReviewInputError(
            f"classification={classification} requires a blocked evaluation"
        )
    if classification in {"beneficial_context", "neutral", "false_negative"} and final_decision != "allow":
        raise ReposkopReviewInputError(
            f"classification={classification} requires an allowed evaluation"
        )
    if classification == "false_negative" and detectable_category == "not_applicable":
        raise ReposkopReviewInputError(
            "false_negative requires one declared detectable_category"
        )
    if classification != "false_negative" and detectable_category == "":
        raise ReposkopReviewInputError("detectable_category may not be empty")

    existing_reviews = sorted(
        (
            record
            for record in evaluation_records
            if record.get("operation") == "reposkop-review-classification-recorded"
        ),
        key=lambda item: (
            int(item.get("review_sequence") or 0),
            int(item.get("timestamp_unix") or 0),
        ),
        reverse=True,
    )
    latest = existing_reviews[0] if existing_reviews else None
    identity = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "kind": "grabowski.reposkop_review_classification",
        "evaluation_id": evaluation,
        "task_id": task_id,
        "classification": classification,
        "scope": scope,
        "detectable_category": detectable_category,
        "reviewer_sha256": hashlib.sha256(reviewer.encode("utf-8")).hexdigest(),
        "reason_codes": reasons,
        "evidence_refs": evidence_refs,
        "expected_decision_audit_ref": expected_decision_ref,
        "supersedes_review_audit_ref": supersedes_ref or None,
        "final_decision": final_decision,
    }
    review_identity_sha256 = _sha256_json(identity)
    if latest is not None:
        if latest.get("review_identity_sha256") == review_identity_sha256:
            return {
                **identity,
                "review_identity_sha256": review_identity_sha256,
                "review_sequence": int(latest.get("review_sequence") or 1),
                "audit_ref": latest.get("_audit_ref"),
                "replayed": True,
                "source": source,
            }
        if supersedes_ref != latest.get("_audit_ref"):
            raise ReposkopReviewConflictError(
                "review revision must supersede the latest exact review audit reference"
            )
    elif supersedes_ref:
        raise ReposkopReviewConflictError(
            "initial review may not supersede a missing prior review"
        )

    review_sequence = int(latest.get("review_sequence") or 0) + 1 if latest else 1
    event = {
        "timestamp_unix": int(time.time()),
        "operation": "reposkop-review-classification-recorded",
        "transaction_id": evaluation,
        **identity,
        "review_sequence": review_sequence,
        "review_identity_sha256": review_identity_sha256,
    }
    audit_ref = append_event(event)
    return {
        **identity,
        "review_identity_sha256": review_identity_sha256,
        "review_sequence": review_sequence,
        "audit_ref": audit_ref,
        "replayed": False,
        "source": source,
    }


def project_records(
    records: list[dict[str, Any]],
    *,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    relevant = {
        "reposkop-evaluation-requested",
        "reposkop-evaluation-completed",
        "reposkop-decision-applied",
        "reposkop-execution-attestation-blocked",
        "reposkop-task-outcome-observed",
        "reposkop-review-classification-recorded",
        "task-start",
    }
    requested: dict[str, dict[str, Any]] = {}
    completed: dict[str, dict[str, Any]] = {}
    decisions: dict[str, dict[str, Any]] = {}
    blocked: dict[str, dict[str, Any]] = {}
    outcomes: dict[str, dict[str, Any]] = {}
    reviews: dict[str, dict[str, Any]] = {}
    classified_starts: list[dict[str, Any]] = []
    legacy_unclassified = 0

    for record in records:
        operation = record.get("operation")
        if operation == "task-start":
            if record.get("effect_profile") in EFFECT_PROFILES:
                classified_starts.append(record)
            else:
                legacy_unclassified += 1
            continue
        if operation not in relevant:
            continue
        evaluation = record.get("evaluation_id")
        if not isinstance(evaluation, str) or len(evaluation) != 64:
            continue
        if operation == "reposkop-evaluation-requested":
            requested.setdefault(evaluation, record)
        elif operation == "reposkop-evaluation-completed":
            completed.setdefault(evaluation, record)
        elif operation == "reposkop-decision-applied":
            decisions.setdefault(evaluation, record)
        elif operation == "reposkop-execution-attestation-blocked":
            blocked.setdefault(evaluation, record)
        elif operation == "reposkop-task-outcome-observed":
            outcomes.setdefault(evaluation, record)
        elif operation == "reposkop-review-classification-recorded":
            current = reviews.get(evaluation)
            candidate_key = (
                int(record.get("review_sequence") or 0),
                int(record.get("timestamp_unix") or 0),
            )
            current_key = (
                int((current or {}).get("review_sequence") or 0),
                int((current or {}).get("timestamp_unix") or 0),
            )
            if current is None or candidate_key > current_key:
                reviews[evaluation] = record

    attempts: dict[str, dict[str, Any]] = dict(requested)
    for start in classified_starts:
        if start.get("reposkop_policy") != "required":
            continue
        evaluation = start.get("evaluation_id")
        key = evaluation if isinstance(evaluation, str) and evaluation else f"task:{start.get('task_id')}"
        attempts.setdefault(key, start)
    for evaluation, record in blocked.items():
        attempts.setdefault(evaluation, record)

    required_ids = set(attempts)
    allowed_decisions = {
        evaluation
        for evaluation, value in decisions.items()
        if value.get("final_decision") == "allow"
    }
    verified_ids = required_ids & set(completed) & allowed_decisions
    blocked_ids = required_ids & set(blocked)
    missing_ids = required_ids - verified_ids - blocked_ids
    terminal_ids = verified_ids & set(outcomes)
    terminal_successes = {
        value for value in terminal_ids if outcomes[value].get("terminal_state") == "completed"
    }
    terminal_failures = terminal_ids - terminal_successes

    group_counts: dict[str, dict[str, int]] = {
        "effect_profile": {},
        "surface": {},
        "agent": {},
        "policy_version": {},
    }
    for value in attempts.values():
        dimensions = {
            "effect_profile": str(value.get("effect_profile") or "unknown"),
            "surface": str(value.get("surface") or "unknown"),
            "agent": str(value.get("agent_executable") or "non_agent"),
            "policy_version": str(value.get("policy_version") or "legacy"),
        }
        for dimension, member in dimensions.items():
            group_counts[dimension][member] = group_counts[dimension].get(member, 0) + 1

    aggregate_severity = {"critical": 0, "error": 0, "warning": 0, "information": 0}
    aggregate_categories: dict[str, int] = {}
    aggregate_reasons: dict[str, int] = {}
    projection_states: dict[str, int] = {}
    for value in completed.values():
        counts = value.get("finding_counts")
        if isinstance(counts, dict):
            for severity in aggregate_severity:
                count = counts.get(severity)
                if type(count) is int and count >= 0:
                    aggregate_severity[severity] += count
        categories = value.get("finding_categories")
        if isinstance(categories, dict):
            for category, count in categories.items():
                if isinstance(category, str) and type(count) is int and count >= 0:
                    aggregate_categories[category] = aggregate_categories.get(category, 0) + count
        reason_codes = value.get("finding_reason_codes")
        if isinstance(reason_codes, list):
            for reason in reason_codes:
                if isinstance(reason, str):
                    aggregate_reasons[reason] = aggregate_reasons.get(reason, 0) + 1
        state = value.get("projection_state")
        if isinstance(state, str):
            projection_states[state] = projection_states.get(state, 0) + 1

    reviewed_ids = required_ids & set(reviews)
    review_counts = {name: 0 for name in sorted(REVIEW_CLASSIFICATIONS)}
    review_evidence_refs: dict[str, list[str]] = {name: [] for name in REVIEW_CLASSIFICATIONS}
    review_reason_clusters: dict[str, dict[str, int]] = {
        "false_positive": {},
        "false_negative": {},
        "operational_failure": {},
    }
    review_category_clusters: dict[str, dict[str, int]] = {
        "false_positive": {},
        "false_negative": {},
        "operational_failure": {},
    }
    for evaluation in reviewed_ids:
        review = reviews[evaluation]
        classification = review.get("classification")
        if classification in review_counts:
            review_counts[classification] += 1
            reference = review.get("_audit_ref")
            if isinstance(reference, str):
                review_evidence_refs[classification].append(reference)
            if classification in review_reason_clusters:
                reason_codes = review.get("reason_codes")
                if isinstance(reason_codes, list):
                    for reason in reason_codes:
                        if isinstance(reason, str):
                            cluster = review_reason_clusters[classification]
                            cluster[reason] = cluster.get(reason, 0) + 1
                detectable_category = review.get("detectable_category")
                if isinstance(detectable_category, str) and detectable_category:
                    category_cluster = review_category_clusters[classification]
                    category_cluster[detectable_category] = (
                        category_cluster.get(detectable_category, 0) + 1
                    )
    confirmed_preventions = review_counts["confirmed_prevention"]
    false_positives = review_counts["false_positive"]
    false_negatives = review_counts["false_negative"]
    false_positive_cluster_size = max(
        review_category_clusters["false_positive"].values(),
        default=0,
    )
    false_negative_cluster_size = max(
        review_category_clusters["false_negative"].values(),
        default=0,
    )
    precision_denominator = confirmed_preventions + false_positives
    detectable_denominator = confirmed_preventions + false_negatives
    decision_change_ids = {
        evaluation
        for evaluation, decision in decisions.items()
        if decision.get("decision_changed") is True or decision.get("final_decision") == "block"
    } & required_ids
    unreviewed_decision_changes = decision_change_ids - reviewed_ids

    durations_with_time = sorted(
        (
            (int(value.get("timestamp_unix") or 0), int(value["duration_ms"]))
            for value in completed.values()
            if isinstance(value.get("duration_ms"), int)
            and not isinstance(value.get("duration_ms"), bool)
            and int(value["duration_ms"]) >= 0
        ),
        key=lambda item: item[0],
    )
    durations = [value for _timestamp, value in durations_with_time]
    p50 = _percentile(durations, 0.50)
    p95 = _percentile(durations, 0.95)

    refs = [
        str(value.get("_audit_ref"))
        for mapping in (requested, completed, blocked, outcomes, reviews)
        for value in mapping.values()
        if isinstance(value.get("_audit_ref"), str)
    ][:MAX_SAMPLE_REFS]
    missing_refs = [
        str(attempts[value].get("_audit_ref"))
        for value in sorted(missing_ids)
        if isinstance(attempts[value].get("_audit_ref"), str)
    ]
    blocked_refs = [
        str(blocked[value].get("_audit_ref"))
        for value in sorted(blocked_ids)
        if isinstance(blocked[value].get("_audit_ref"), str)
    ]
    unreviewed_change_refs = [
        str(decisions[value].get("_audit_ref"))
        for value in sorted(unreviewed_decision_changes)
        if isinstance(decisions.get(value, {}).get("_audit_ref"), str)
    ]

    improvement_candidates = [
        _candidate(
            "missing_required_attestation",
            status="active" if missing_ids else "clear",
            threshold=0,
            observed=len(missing_ids),
            sample_size=len(required_ids),
            evidence_refs=missing_refs,
        ),
        _candidate(
            "repeated_operational_failure",
            status=(
                "active"
                if len(blocked_ids) >= MIN_OPERATIONAL_FAILURE_SAMPLE
                else "insufficient_sample"
            ),
            threshold=MIN_OPERATIONAL_FAILURE_SAMPLE,
            observed=len(blocked_ids),
            sample_size=len(required_ids),
            evidence_refs=blocked_refs,
        ),
        _candidate(
            "unreviewed_decision_change",
            status="active" if unreviewed_decision_changes else "clear",
            threshold=0,
            observed=len(unreviewed_decision_changes),
            sample_size=len(decision_change_ids),
            evidence_refs=unreviewed_change_refs,
        ),
        _candidate(
            "false_positive_cluster",
            status=(
                "active"
                if false_positive_cluster_size >= MIN_FALSE_POSITIVE_CLUSTER
                else "clear"
                if precision_denominator >= MIN_FALSE_POSITIVE_CLUSTER
                else "insufficient_sample"
            ),
            threshold=MIN_FALSE_POSITIVE_CLUSTER,
            observed={
                "max_category_count": false_positive_cluster_size,
                "category_counts": dict(
                    sorted(review_category_clusters["false_positive"].items())
                ),
            },
            sample_size=precision_denominator,
            evidence_refs=review_evidence_refs["false_positive"],
            context={
                "category_counts": dict(
                    sorted(review_category_clusters["false_positive"].items())
                ),
                "reason_counts": review_reason_clusters["false_positive"],
            },
        ),
        _candidate(
            "false_negative_cluster",
            status=(
                "active"
                if false_negative_cluster_size >= MIN_FALSE_NEGATIVE_CLUSTER
                else "clear"
                if detectable_denominator >= MIN_FALSE_NEGATIVE_CLUSTER
                else "insufficient_sample"
            ),
            threshold=MIN_FALSE_NEGATIVE_CLUSTER,
            observed={
                "max_category_count": false_negative_cluster_size,
                "category_counts": dict(
                    sorted(review_category_clusters["false_negative"].items())
                ),
            },
            sample_size=detectable_denominator,
            evidence_refs=review_evidence_refs["false_negative"],
            context={
                "category_counts": dict(
                    sorted(review_category_clusters["false_negative"].items())
                ),
                "reason_counts": review_reason_clusters["false_negative"],
            },
        ),
    ]
    if len(durations) >= MIN_RUNTIME_REGRESSION_SAMPLE:
        midpoint = len(durations_with_time) // 2
        baseline = [value for _timestamp, value in durations_with_time[:midpoint]]
        recent = [value for _timestamp, value in durations_with_time[midpoint:]]
        baseline_p95 = _percentile(baseline, 0.95) or 0
        recent_p95 = _percentile(recent, 0.95) or 0
        threshold = int(baseline_p95 * RUNTIME_REGRESSION_FACTOR)
        runtime_status = "active" if baseline_p95 > 0 and recent_p95 > threshold else "clear"
        improvement_candidates.append(
            _candidate(
                "p95_runtime_regression",
                status=runtime_status,
                threshold={"factor": RUNTIME_REGRESSION_FACTOR, "baseline_p95_ms": baseline_p95},
                observed={"recent_p95_ms": recent_p95},
                sample_size=len(durations),
                evidence_refs=refs,
            )
        )
    else:
        improvement_candidates.append(
            _candidate(
                "p95_runtime_regression",
                status="insufficient_sample",
                threshold={"minimum_sample": MIN_RUNTIME_REGRESSION_SAMPLE},
                observed={"p95_ms": p95},
                sample_size=len(durations),
                evidence_refs=refs,
            )
        )

    required_count = len(required_ids)
    covered_count = len(verified_ids | blocked_ids)
    technical_denominator = len(verified_ids) + len(blocked_ids)
    return {
        "schema_version": 2,
        "kind": "grabowski_reposkop_effectiveness_projection",
        "authority": "derived_from_verified_audit_chain",
        "policy_version": POLICY_VERSION,
        "finding_taxonomy_version": FINDING_TAXONOMY_VERSION,
        "review_schema_version": REVIEW_SCHEMA_VERSION,
        "source": source or {},
        "classified_task_starts": len(classified_starts),
        "legacy_unclassified_task_starts": legacy_unclassified,
        "required_task_starts": required_count,
        "required_verified": len(verified_ids),
        "required_blocked": len(blocked_ids),
        "required_missing": len(missing_ids),
        "coverage_ratio": covered_count / required_count if required_count else None,
        "technical_success_ratio": (
            len(verified_ids) / technical_denominator if technical_denominator else None
        ),
        "terminal_outcomes": len(terminal_ids),
        "terminal_successes": len(terminal_successes),
        "terminal_failures": len(terminal_failures),
        "unresolved": len(verified_ids - terminal_ids),
        "groups": group_counts,
        "findings": {
            "evaluated_reports": len(completed),
            "severity_counts": aggregate_severity,
            "category_counts": dict(sorted(aggregate_categories.items())),
            "reason_counts": dict(sorted(aggregate_reasons.items())),
            "projection_state_counts": dict(sorted(projection_states.items())),
        },
        "review": {
            "reviewed_evaluations": len(reviewed_ids),
            "unreviewed_evaluations": len(required_ids - reviewed_ids),
            "review_coverage_ratio": len(reviewed_ids) / required_count if required_count else None,
            "classification_counts": review_counts,
            "confirmed_preventions": confirmed_preventions,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "precision": (
                confirmed_preventions / precision_denominator
                if precision_denominator
                else None
            ),
            "false_negative_ratio": (
                false_negatives / detectable_denominator
                if detectable_denominator
                else None
            ),
            "detectable_review_denominator": detectable_denominator,
            "decision_changes": len(decision_change_ids),
            "unreviewed_decision_changes": len(unreviewed_decision_changes),
            "detectable_category_counts": {
                classification: dict(sorted(counts.items()))
                for classification, counts in sorted(
                    review_category_clusters.items()
                )
            },
        },
        "duration_ms": {
            "sample_size": len(durations),
            "p50": p50,
            "p95": p95,
        },
        "sample_evidence_refs": refs,
        "improvement_candidates": improvement_candidates,
        "does_not_establish": [
            "causality_between_reposkop_and_task_outcome",
            "semantic_correctness_of_agent_output",
            "review_truth_beyond_the_supplied_evidence_refs",
            "future_failure_probability",
        ],
    }

def build_reposkop_effectiveness(
    *,
    since_unix: int = 0,
    limit: int = DEFAULT_SCAN_LIMIT,
) -> dict[str, Any]:
    if isinstance(since_unix, bool) or not isinstance(since_unix, int) or since_unix < 0:
        raise ValueError("since_unix must be a non-negative integer")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SCAN_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_SCAN_LIMIT}")
    records, source = _raw_records(since_unix=since_unix, scan_limit=limit)
    return project_records(records, source=source)


def _marker_payload(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("Reposkop outcome marker is invalid")
    unsigned = {key: item for key, item in value.items() if key != "marker_sha256"}
    if value.get("marker_sha256") != _sha256_json(unsigned):
        raise RuntimeError("Reposkop outcome marker integrity is invalid")
    return value


def _write_marker(path: Path, value: dict[str, Any], *, exclusive: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {**value, "marker_sha256": _sha256_json(value)}
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        data = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _find_existing_outcome(evaluation: str, event_sha256: str) -> str | None:
    records, _source = _raw_records(since_unix=0, scan_limit=MAX_SCAN_LIMIT)
    for record in records:
        if (
            record.get("operation") == "reposkop-task-outcome-observed"
            and record.get("evaluation_id") == evaluation
            and record.get("outcome_event_sha256") == event_sha256
        ):
            return str(record.get("_audit_ref"))
    return None


def record_task_outcome(
    *,
    marker_root: Path,
    attestation: dict[str, Any] | None,
    task_id: str,
    terminal_state: str,
    lifecycle_receipt_sha256: str,
    terminalized_at_unix: int,
    observation: dict[str, Any] | None,
) -> str | None:
    if not isinstance(attestation, dict):
        return None
    evaluation = attestation.get("evaluation_id")
    if not isinstance(evaluation, str) or len(evaluation) != 64:
        return None
    properties = (observation or {}).get("properties")
    if not isinstance(properties, dict):
        properties = {}
    event_material = {
        "operation": "reposkop-task-outcome-observed",
        "timestamp_unix": terminalized_at_unix,
        "transaction_id": evaluation,
        "evaluation_id": evaluation,
        "task_id": task_id,
        "effect_profile": attestation.get("effect_profile"),
        "reposkop_policy": attestation.get("reposkop_policy"),
        "surface": attestation.get("surface"),
        "agent_executable": attestation.get("agent_executable"),
        "policy_version": attestation.get("policy_version"),
        "terminal_state": terminal_state,
        "lifecycle_receipt_sha256": lifecycle_receipt_sha256,
        "unit_result": properties.get("Result"),
        "exec_main_code": properties.get("ExecMainCode"),
        "exec_main_status": properties.get("ExecMainStatus"),
        "terminal_success": terminal_state == "completed",
    }
    event_sha256 = _sha256_json(event_material)
    event = {**event_material, "outcome_event_sha256": event_sha256}
    marker = marker_root / f"{evaluation}.json"
    existing = _marker_payload(marker)
    created_pending = False
    if existing is not None:
        if existing.get("outcome_event_sha256") != event_sha256:
            raise RuntimeError("Reposkop outcome marker belongs to another terminal outcome")
        if existing.get("status") == "completed":
            return cast(str, existing["audit_ref"])
    else:
        try:
            _write_marker(
                marker,
                {
                    "schema_version": 1,
                    "kind": "grabowski.reposkop_outcome_marker",
                    "status": "pending",
                    "evaluation_id": evaluation,
                    "task_id": task_id,
                    "outcome_event_sha256": event_sha256,
                },
                exclusive=True,
            )
            created_pending = True
        except FileExistsError:
            existing = _marker_payload(marker)
            if existing is None or existing.get("outcome_event_sha256") != event_sha256:
                raise RuntimeError("Reposkop outcome marker race changed identity")
    audit_ref = (
        None
        if created_pending
        else _find_existing_outcome(evaluation, event_sha256)
    )
    if audit_ref is None:
        audit_ref = append_event(event)
    completed_marker = {
        "schema_version": 1,
        "kind": "grabowski.reposkop_outcome_marker",
        "status": "completed",
        "evaluation_id": evaluation,
        "task_id": task_id,
        "outcome_event_sha256": event_sha256,
        "audit_ref": audit_ref,
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{evaluation}.", dir=marker_root)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        _write_marker(temporary, completed_marker, exclusive=False)
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
    return audit_ref


@mcp.tool(name="grabowski_reposkop_effectiveness", annotations=READ_ONLY)
async def grabowski_reposkop_effectiveness(
    since_unix: int = 0,
    limit: int = DEFAULT_SCAN_LIMIT,
) -> dict[str, Any]:
    """Project bounded Reposkop coverage, technical outcomes and improvement signals."""
    base._require_capability("audit_read")
    return await asyncio.to_thread(
        build_reposkop_effectiveness,
        since_unix=since_unix,
        limit=limit,
    )

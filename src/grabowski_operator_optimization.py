from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import time
from typing import Any, Callable

import grabowski_consumer_surface as consumer_surface
import grabowski_current_work as current_work_core


REPORT_WINDOWS = {
    "24h": 86_400,
    "7d": 604_800,
    "30d": 2_592_000,
}
COMPARISON_WINDOWS = {
    "24h": "7d",
    "7d": "30d",
    "30d": None,
}
MAX_TOP_LIMIT = 25
MAX_FRICTION_LIMIT = 100
MAX_OUTCOME_LIMIT = 500
MAX_CURRENT_WORK_LIMIT = current_work_core.PAGE_LIMIT_MAX
MAX_FINDINGS = 12
SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "none": 0}

Provider = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class ReportEvidence:
    window: str
    comparison_label: str | None
    health: dict[str, Any] | None
    audit: dict[str, Any] | None
    friction: dict[str, Any] | None
    outcomes: dict[str, Any] | None
    current_work: dict[str, Any] | None
    selected_metrics: dict[str, Any] | None
    comparison_metrics: dict[str, Any] | None
    audit_projection_sha: str | None
    friction_snapshot_sha: str | None
    outcome_summary_sha: str | None
    current_work_sha: str | None


def _bounded_int(
    value: int,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _repositories(value: list[str]) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= current_work_core.MAX_REPOSITORIES:
        raise ValueError(
            "repositories must contain between 1 and "
            f"{current_work_core.MAX_REPOSITORIES} paths"
        )
    result: list[str] = []
    for repository in value:
        if not isinstance(repository, str) or not repository or "\x00" in repository:
            raise ValueError("repository paths must be non-empty strings")
        if repository in result:
            raise ValueError("repositories must be unique")
        result.append(repository)
    return result


def _safe_call(
    label: str,
    provider: Callable[[], dict[str, Any]],
    warnings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    try:
        payload = provider()
    except Exception as exc:  # A partial report is better than a false green.
        warnings.append(
            {
                "code": "source_unavailable",
                "source": label,
                "error": type(exc).__name__,
            }
        )
        return None
    if not isinstance(payload, dict):
        warnings.append(
            {
                "code": "source_invalid",
                "source": label,
                "error": "non_mapping_payload",
            }
        )
        return None
    return payload


def _resolve_providers(
    health_provider: Provider | None,
    audit_provider: Provider | None,
    friction_provider: Provider | None,
    outcome_provider: Provider | None,
    current_work_provider: Provider | None,
) -> tuple[Provider, Provider, Provider, Provider, Provider]:
    if health_provider is None or audit_provider is None:
        read_surface = importlib.import_module("grabowski_read_surface")
        health_provider = health_provider or read_surface.grabowski_runtime_health
        audit_provider = audit_provider or read_surface.grabowski_audit_projection
    if friction_provider is None or outcome_provider is None:
        friction = importlib.import_module("grabowski_friction")
        friction_provider = friction_provider or friction.grabowski_friction_summary
        outcome_provider = outcome_provider or friction.execution_governor_summary
    if current_work_provider is None:
        current_work_surface = importlib.import_module("grabowski_current_work_surface")
        current_work_provider = current_work_surface.grabowski_current_work
    return (
        health_provider,
        audit_provider,
        friction_provider,
        outcome_provider,
        current_work_provider,
    )


def _window(audit: dict[str, Any] | None, label: str) -> dict[str, Any] | None:
    if not isinstance(audit, dict):
        return None
    windows = audit.get("windows")
    if not isinstance(windows, list):
        return None
    return next(
        (
            item
            for item in windows
            if isinstance(item, dict) and item.get("label") == label
        ),
        None,
    )


def _count(mapping: Any, key: str) -> int:
    if not isinstance(mapping, dict):
        return 0
    value = mapping.get(key, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _ratio(numerator: int, denominator: int, *, scale: float = 1.0) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * scale, 6)


def _window_metrics(window: dict[str, Any] | None, label: str) -> dict[str, Any] | None:
    if not isinstance(window, dict):
        return None
    seconds = REPORT_WINDOWS[label]
    days = seconds / 86_400
    records = _count(window, "record_count")
    failures = _count(window, "failure_signal_count")
    task_activity = window.get("task_activity")
    resource_activity = window.get("resource_activity")
    bureau_activity = window.get("bureau_activity")
    task_starts = _count(task_activity, "task-start")
    task_cancels = _count(task_activity, "task-cancel")
    return {
        "label": label,
        "seconds": seconds,
        "record_count": records,
        "records_per_day": round(records / days, 4),
        "failure_signal_count": failures,
        "failure_signal_rate": _ratio(failures, records),
        "failure_signals_per_day": round(failures / days, 4),
        "task_starts": task_starts,
        "task_starts_per_day": round(task_starts / days, 4),
        "task_cancels": task_cancels,
        "task_cancels_per_1000_starts": _ratio(
            task_cancels,
            task_starts,
            scale=1000.0,
        ),
        "resource_acquires": _count(resource_activity, "resource-acquire"),
        "resource_releases": _count(resource_activity, "resource-release"),
        "resource_reclamation_events": _count(
            resource_activity,
            "resource_reclamation_event_count",
        ),
        "reclaimed_resources": _count(resource_activity, "reclaimed_resource_count"),
        "bureau_candidate_records": _count(bureau_activity, "bureau-candidate-record"),
        "bureau_task_proposals": _count(bureau_activity, "bureau-task-propose"),
        "bureau_task_publishes": _count(bureau_activity, "bureau-task-publish"),
    }


def _metric_delta(selected: float, comparison: float) -> dict[str, float | None]:
    absolute = round(selected - comparison, 6)
    relative = None if comparison == 0 else round(absolute / comparison, 6)
    return {
        "selected_minus_comparison": absolute,
        "relative_change": relative,
    }


def _comparison(
    selected: dict[str, Any] | None,
    comparison: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(selected, dict) or not isinstance(comparison, dict):
        return None
    rate_fields = (
        "records_per_day",
        "failure_signal_rate",
        "failure_signals_per_day",
        "task_starts_per_day",
        "task_cancels_per_1000_starts",
    )
    return {
        "selected_label": selected["label"],
        "comparison_label": comparison["label"],
        "rates": {
            field: _metric_delta(
                float(selected.get(field, 0.0)),
                float(comparison.get(field, 0.0)),
            )
            for field in rate_fields
        },
        "semantics": (
            "Selected-window rates are compared with the longer containing window; "
            "the samples overlap and therefore do not establish causality or an "
            "independent experiment."
        ),
    }


def _evidence_ref(prefix: str, value: Any, suffix: str = "") -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return f"{prefix}:{value}{suffix}"


def _finding(
    *,
    finding_id: str,
    severity: str,
    evidence_scope: str,
    title: str,
    observation: str,
    evidence_count: int,
    evidence_refs: list[str | None],
    interpretation: str,
    alternative_interpretation: str,
    recommended_action: str,
    does_not_establish: list[str],
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "evidence_scope": evidence_scope,
        "title": title,
        "observation": observation,
        "evidence_count": max(0, int(evidence_count)),
        "evidence_refs": [ref for ref in evidence_refs if isinstance(ref, str)],
        "interpretation": interpretation,
        "alternative_interpretation": alternative_interpretation,
        "recommended_action": recommended_action,
        "does_not_establish": does_not_establish,
    }


def _candidate_pattern(
    audit: dict[str, Any] | None,
    pattern: str,
) -> dict[str, Any] | None:
    if not isinstance(audit, dict):
        return None
    candidates = audit.get("candidate_patterns")
    if not isinstance(candidates, list):
        return None
    return next(
        (
            item
            for item in candidates
            if isinstance(item, dict) and item.get("pattern") == pattern
        ),
        None,
    )


def _audit_signal(
    audit: dict[str, Any] | None,
    signal_id: str,
) -> dict[str, Any] | None:
    if not isinstance(audit, dict):
        return None
    projection = audit.get("signal_projection")
    signals = projection.get("signals") if isinstance(projection, dict) else None
    if not isinstance(signals, list):
        return None
    return next(
        (
            item
            for item in signals
            if isinstance(item, dict) and item.get("id") == signal_id
        ),
        None,
    )


def _collect_sources(
    repositories: list[str],
    *,
    window: str,
    top_limit: int,
    friction_limit: int,
    outcome_limit: int,
    current_work_limit: int,
    providers: tuple[Provider, Provider, Provider, Provider, Provider],
    warnings: list[dict[str, Any]],
) -> ReportEvidence:
    (
        health_provider,
        audit_provider,
        friction_provider,
        outcome_provider,
        current_work_provider,
    ) = providers
    health = _safe_call("runtime_health", health_provider, warnings)
    audit = _safe_call(
        "audit_projection",
        lambda: audit_provider(view="minimal", top_limit=top_limit),
        warnings,
    )
    friction = _safe_call(
        "friction_summary",
        lambda: friction_provider(limit=friction_limit, view="minimal"),
        warnings,
    )
    outcomes = _safe_call(
        "execution_governor_summary",
        lambda: outcome_provider(limit=outcome_limit),
        warnings,
    )
    current_work = _safe_call(
        "current_work",
        lambda: current_work_provider(
            repositories,
            view="current",
            limit=current_work_limit,
        ),
        warnings,
    )
    comparison_label = COMPARISON_WINDOWS[window]
    selected_metrics = _window_metrics(_window(audit, window), window)
    comparison_metrics = (
        _window_metrics(_window(audit, comparison_label), comparison_label)
        if comparison_label is not None
        else None
    )
    if selected_metrics is None:
        warnings.append({"code": "selected_window_unavailable", "window": window})

    friction_snapshot_sha = None
    if isinstance(friction, dict):
        pagination = friction.get("pagination")
        if isinstance(pagination, dict):
            friction_snapshot_sha = pagination.get("snapshot_sha256")
            if pagination.get("has_more"):
                warnings.append(
                    {
                        "code": "friction_window_bounded",
                        "source": "friction_summary",
                        "snapshot_sha256": friction_snapshot_sha,
                    }
                )

    return ReportEvidence(
        window=window,
        comparison_label=comparison_label,
        health=health,
        audit=audit,
        friction=friction,
        outcomes=outcomes,
        current_work=current_work,
        selected_metrics=selected_metrics,
        comparison_metrics=comparison_metrics,
        audit_projection_sha=(
            audit.get("projection_sha256") if isinstance(audit, dict) else None
        ),
        friction_snapshot_sha=friction_snapshot_sha,
        outcome_summary_sha=(
            outcomes.get("summary_sha256") if isinstance(outcomes, dict) else None
        ),
        current_work_sha=(
            current_work.get("snapshot_sha256")
            if isinstance(current_work, dict)
            else None
        ),
    )


def _runtime_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    health = evidence.health
    if not isinstance(health, dict) or health.get("healthy"):
        return []
    return [
        _finding(
            finding_id="runtime_health_degraded",
            severity="high",
            evidence_scope="live",
            title="Runtime health is degraded",
            observation="The live runtime health contract is not fully green.",
            evidence_count=1,
            evidence_refs=[_evidence_ref("runtime-release", health.get("release_id"))],
            interpretation=(
                "Optimization conclusions may be distorted while deployment, audit, "
                "kill-switch or runtime integrity is degraded."
            ),
            alternative_interpretation=(
                "A single intentionally unavailable optional surface can also make a "
                "broad health view look degraded."
            ),
            recommended_action=(
                "Restore or explicitly classify runtime health before changing "
                "optimization policy."
            ),
            does_not_establish=["root_cause", "safe_recovery_action"],
        )
    ]


def _outcome_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    outcomes = evidence.outcomes
    if not isinstance(outcomes, dict):
        return []
    seven_day_metrics = _window_metrics(_window(evidence.audit, "7d"), "7d")
    task_starts = seven_day_metrics.get("task_starts", 0) if seven_day_metrics else 0
    active_outcomes = _count(outcomes, "active_after_decay")
    minimum_evidence = _count(outcomes, "minimum_evidence")
    if task_starts <= 0 or active_outcomes >= max(1, minimum_evidence):
        return []
    return [
        _finding(
            finding_id="fresh_execution_outcomes_missing",
            severity="high" if task_starts >= 100 else "medium",
            evidence_scope="7d",
            title="Execution activity lacks fresh outcome calibration",
            observation=(
                f"The seven-day audit contains {task_starts} task starts, while only "
                f"{active_outcomes} execution outcomes remain active after decay."
            ),
            evidence_count=task_starts,
            evidence_refs=[
                _evidence_ref("audit-projection", evidence.audit_projection_sha, "#window/7d"),
                _evidence_ref("execution-governor", evidence.outcome_summary_sha),
            ],
            interpretation=(
                "The ecosystem can describe activity and friction better than it can "
                "measure whether chosen execution routes succeeded efficiently."
            ),
            alternative_interpretation=(
                "Many task starts can be low-level or test activity for which an "
                "execution-outcome record would add noise."
            ),
            recommended_action=(
                "Record bounded final execution outcomes only at meaningful operator "
                "closeout points and keep routing promotion disabled."
            ),
            does_not_establish=["operator_productivity", "route_failure"],
        )
    ]


def _bureau_contract_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    pattern = _candidate_pattern(evidence.audit, "repeated_bureau_contract_failures")
    count = _count(pattern, "count_7d")
    if count <= 0:
        return []
    retryable = _count(pattern, "failure_retryable_count_7d")
    nonretryable = _count(pattern, "failure_nonretryable_count_7d")
    retryability_unknown = _count(pattern, "failure_retryability_unknown_count_7d")
    retryability_total = retryable + nonretryable + retryability_unknown
    retryability_coverage = (retryable + nonretryable) / retryability_total if retryability_total else 0.0
    identity_complete = _count(pattern, "failure_identity_complete_count_7d")
    identity_partial = _count(pattern, "failure_identity_partial_count_7d")
    identity_unknown = _count(pattern, "failure_identity_unknown_count_7d")
    identity_total = identity_complete + identity_partial + identity_unknown
    identity_groups = _count(pattern, "failure_identity_group_count_7d")
    identity_coverage = identity_complete / identity_total if identity_total else 0.0
    observation = f"The audit projection grouped {count} contract failures in seven days."
    if retryability_total:
        observation += (
            f" Retryability is attributed for {retryable + nonretryable} of "
            f"{retryability_total} Bureau failure records ({retryability_coverage:.1%})."
        )
    if identity_total:
        observation += (
            f" Exact caller/runtime/schema identity is verified for {identity_complete} of "
            f"{identity_total} failure records ({identity_coverage:.1%}) across "
            f"{identity_groups} exact identity groups; {identity_partial} are partial and "
            f"{identity_unknown} remain unknown."
        )
    return [
        _finding(
            finding_id="repeated_bureau_contract_failures",
            severity="high" if count >= 100 else "medium",
            evidence_scope="7d",
            title="Bureau contract failures repeat at scale",
            observation=observation,
            evidence_count=count,
            evidence_refs=[
                _evidence_ref(
                    "audit-projection",
                    evidence.audit_projection_sha,
                    "#candidate/repeated_bureau_contract_failures",
                )
            ],
            interpretation=(
                "Only failures with a verified complete caller/runtime/schema identity may "
                "be treated as one homogeneous investigation candidate. Partial and unknown "
                "historical identities remain separate, and sparse retryability attribution "
                "prevents treating the aggregate as one retry class."
            ),
            alternative_interpretation=(
                "Even one exact identity group may contain multiple underlying causes; the "
                "identity proves correlation boundaries, not causality."
            ),
            recommended_action=(
                "Inspect the largest complete identity group first; keep partial and unknown "
                "records separate, never retry records explicitly marked non-retryable and "
                "never infer retryability or shared root cause where attribution is absent."
            ),
            does_not_establish=["shared_root_cause", "bureau_task_readiness"],
        )
    ]


def _resource_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    pattern = _candidate_pattern(evidence.audit, "repeated_resource_reclamation")
    event_count = _count(pattern, "event_count_7d")
    reclaimed = _count(pattern, "reclaimed_resource_count_7d")
    if event_count <= 0:
        return []

    has_attribution = any(
        key in pattern
        for key in (
            "same_owner_reclaimed_resource_count_7d",
            "foreign_owner_reclaimed_resource_count_7d",
            "unattributed_reclaimed_resource_count_7d",
        )
    )
    same_owner = _count(pattern, "same_owner_reclaimed_resource_count_7d")
    foreign_owner = _count(pattern, "foreign_owner_reclaimed_resource_count_7d")
    unattributed = _count(pattern, "unattributed_reclaimed_resource_count_7d")
    attributed = same_owner + foreign_owner
    coverage = attributed / reclaimed if reclaimed else 0.0

    if not has_attribution:
        severity = "medium" if event_count >= 20 else "low"
        title = "Resource reclamation is recurrent"
        observation = (
            f"Seven-day evidence contains {event_count} reclamation events "
            f"covering {reclaimed} resources."
        )
        interpretation = (
            "Lease lifetime, terminalization and release timing may be misaligned."
        )
    elif coverage < 0.5:
        severity = "low"
        title = "Resource reclamation attribution is incomplete"
        observation = (
            f"Seven-day evidence contains {event_count} reclamation events covering "
            f"{reclaimed} resources; {attributed} are owner-attributed ({coverage:.1%}), "
            f"including {same_owner} same-owner and {foreign_owner} foreign-owner reclaims, "
            f"while {unattributed} remain historical or unattributed."
        )
        interpretation = (
            "The aggregate reclamation count currently mixes legacy records with newer "
            "owner-attributed evidence, so it is insufficient for lease-policy changes."
        )
    else:
        severity = "medium" if foreign_owner >= 20 else "low"
        title = "Resource reclamation is owner-attributed"
        observation = (
            f"Seven-day evidence contains {event_count} reclamation events covering "
            f"{reclaimed} resources; {same_owner} are same-owner, {foreign_owner} are "
            f"foreign-owner and {unattributed} are unattributed ({coverage:.1%} coverage)."
        )
        interpretation = (
            "Foreign-owner reclamation is the subset relevant to stale-owner cleanup; "
            "same-owner reclamation can instead reflect expiry-and-resume behavior."
        )

    return [
        _finding(
            finding_id="repeated_resource_reclamation",
            severity=severity,
            evidence_scope="7d",
            title=title,
            observation=observation,
            evidence_count=event_count,
            evidence_refs=[
                _evidence_ref(
                    "audit-projection",
                    evidence.audit_projection_sha,
                    "#candidate/repeated_resource_reclamation",
                )
            ],
            interpretation=interpretation,
            alternative_interpretation=(
                "High reclamation can also demonstrate that cleanup safeguards are "
                "working as designed."
            ),
            recommended_action=(
                "Inspect provenance-attributed foreign-owner reclaims against expiry, "
                "terminal and release timing first; treat same-owner reclaims separately "
                "and do not change lease duration from unattributed aggregate counts."
            ),
            does_not_establish=["lease_bug", "owner_failure"],
        )
    ]


def _audit_signal_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    blockade = _audit_signal(evidence.audit, "repeated_blockade")
    if isinstance(blockade, dict) and blockade.get("status") == "observed":
        count = _count(blockade, "count")
        findings.append(
            _finding(
                finding_id="repeated_blockade",
                severity=str(blockade.get("severity") or "medium"),
                evidence_scope="7d",
                title="The same guarded path is repeatedly blocked",
                observation=(
                    f"The seven-day audit signal projection reports {count} repeated "
                    "blockades."
                ),
                evidence_count=count,
                evidence_refs=list(blockade.get("evidence_refs") or []),
                interpretation=(
                    "The operator repeatedly arrives without evidence required by the "
                    "same gate, or the selected route is structurally inappropriate."
                ),
                alternative_interpretation=(
                    "Repeated denial can be correct protective behavior under genuinely "
                    "conflicting work."
                ),
                recommended_action=(
                    "Prepare the missing gate evidence once in a narrow preflight, or "
                    "revise the owning policy deliberately; never retry unchanged."
                ),
                does_not_establish=["policy_is_wrong", "policy_bypass_authority"],
            )
        )
    stale = _audit_signal(evidence.audit, "stale_attention")
    if isinstance(stale, dict) and stale.get("status") == "observed":
        count = _count(stale, "count")
        findings.append(
            _finding(
                finding_id="stale_attention",
                severity=str(stale.get("severity") or "medium"),
                evidence_scope="7d",
                title="Historical friction remains open after current recovery",
                observation=(
                    f"The seven-day projection identifies {count} closeout-review "
                    "candidates."
                ),
                evidence_count=count,
                evidence_refs=list(stale.get("evidence_refs") or []),
                interpretation=(
                    "Attention state is retaining historical incidents after the live "
                    "runtime or connector condition has changed."
                ),
                alternative_interpretation=(
                    "Historical incidents may still require a durable explanation even "
                    "though the current runtime is healthy."
                ),
                recommended_action=(
                    "Review each candidate against the current runtime receipt and close, "
                    "reopen or defer it explicitly."
                ),
                does_not_establish=[
                    "automatic_closeout_authority",
                    "historical_event_was_false",
                ],
            )
        )
    return findings


def _friction_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    friction = evidence.friction
    if not isinstance(friction, dict):
        return []
    classification = friction.get("failure_classification")
    decision_required = _count(classification, "decision_required_count")
    if decision_required <= 0:
        return []
    return [
        _finding(
            finding_id="friction_decision_backlog",
            severity="high" if decision_required >= 50 else "medium",
            evidence_scope="recent_valid_events",
            title="Friction evidence awaits decisions",
            observation=(
                f"The bounded friction summary contains {decision_required} events "
                "that still require a decision."
            ),
            evidence_count=decision_required,
            evidence_refs=[_evidence_ref("friction-summary", evidence.friction_snapshot_sha)],
            interpretation=(
                "The system is collecting failure evidence faster than it is resolving, "
                "linking or deliberately accepting it."
            ),
            alternative_interpretation=(
                "A backlog can be intentional while evidence accumulates for one "
                "systemic repair."
            ),
            recommended_action=(
                "Decide the largest repeated failure class in bounded batches and link "
                "only homogeneous unresolved events to one repair task."
            ),
            does_not_establish=["root_cause", "task_resume_permission"],
        )
    ]


def _current_work_findings(
    evidence: ReportEvidence,
    warnings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    current = evidence.current_work
    if not isinstance(current, dict):
        return []
    for source_error in current.get("source_errors") or []:
        if isinstance(source_error, dict):
            warnings.append(
                {
                    "code": "current_work_source_error",
                    "source": source_error.get("source"),
                    "error": source_error.get("error"),
                }
            )
    truncation = current.get("source_truncation")
    if isinstance(truncation, dict) and any(truncation.values()):
        warnings.append(
            {
                "code": "current_work_source_truncated",
                "sources": sorted(key for key, value in truncation.items() if value),
            }
        )
    state_counts = current.get("state_counts")
    total = _count(current, "total_projected")
    blocking = _count(state_counts, "blocking")
    resumable = _count(state_counts, "resumable")
    if total < 20 or blocking / max(1, total) < 0.5:
        return []
    return [
        _finding(
            finding_id="current_work_attention_noise",
            severity="high" if blocking >= 100 and resumable == 0 else "medium",
            evidence_scope="live_snapshot",
            title="Current-work projection is dominated by blocking state",
            observation=(
                f"{blocking} of {total} projected work groups are blocking; "
                f"{resumable} are resumable."
            ),
            evidence_count=blocking,
            evidence_refs=[_evidence_ref("current-work", evidence.current_work_sha)],
            interpretation=(
                "The projection may surface lifecycle residue and heuristic drift as "
                "attention faster than it identifies a finishable chain."
            ),
            alternative_interpretation=(
                "The repository set may genuinely contain many independent dirty or "
                "conflicting work groups."
            ),
            recommended_action=(
                "Separate finishable authoritative work from historical binding drift, "
                "dirty foreign work and heuristic-only attention before ranking actions."
            ),
            does_not_establish=["safe_cleanup", "absence_of_real_blockers"],
        )
    ]


def _trend_findings(evidence: ReportEvidence) -> list[dict[str, Any]]:
    comparison = _comparison(evidence.selected_metrics, evidence.comparison_metrics)
    if not isinstance(comparison, dict):
        return []
    delta = comparison["rates"]["failure_signal_rate"]
    relative_change = delta.get("relative_change")
    if not isinstance(relative_change, float) or relative_change < 0.25:
        return []
    count = (
        evidence.selected_metrics.get("failure_signal_count", 0)
        if evidence.selected_metrics
        else 0
    )
    return [
        _finding(
            finding_id="failure_signal_rate_rising",
            severity="medium",
            evidence_scope=(
                f"{evidence.window}_vs_{evidence.comparison_label}_overlapping"
            ),
            title="Failure-signal rate is above its longer-window baseline",
            observation=(
                f"The selected {evidence.window} failure-signal rate is "
                f"{relative_change:.1%} above the overlapping "
                f"{evidence.comparison_label} rate."
            ),
            evidence_count=count,
            evidence_refs=[
                _evidence_ref(
                    "audit-projection",
                    evidence.audit_projection_sha,
                    f"#window/{evidence.window}",
                )
            ],
            interpretation=(
                "Recent operator friction may be increasing relative to the longer trend."
            ),
            alternative_interpretation=(
                "The windows overlap and useful stress testing can raise the rate without "
                "indicating regression."
            ),
            recommended_action=(
                "Inspect recent failure classes before changing tools or policy; compare "
                "again after the next equivalent window."
            ),
            does_not_establish=["regression", "causality"],
        )
    ]


def _collect_findings(
    evidence: ReportEvidence,
    warnings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for analyzer in (
        _runtime_findings,
        _outcome_findings,
        _bureau_contract_findings,
        _resource_findings,
        _audit_signal_findings,
        _friction_findings,
        _trend_findings,
    ):
        findings.extend(analyzer(evidence))
    findings.extend(_current_work_findings(evidence, warnings))
    findings.sort(
        key=lambda item: (
            -SEVERITY_WEIGHT.get(str(item.get("severity")), 0),
            -int(item.get("evidence_count", 0)),
            str(item.get("id", "")),
        )
    )
    return findings[:MAX_FINDINGS]


def _recommendation(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"recommendation:{finding['id']}",
        "priority": finding["severity"],
        "finding_id": finding["id"],
        "action": finding["recommended_action"],
        "preconditions": [
            "bind any implementation to the same source identities",
            "re-read live task, lease, checkout and repository state before effects",
            "measure the same signal again after the change",
        ],
        "does_not_establish": [
            "implementation_authority",
            "automatic_task_creation",
            "policy_bypass",
            "merge_or_deploy_readiness",
        ],
    }


def _source_bindings(evidence: ReportEvidence) -> dict[str, Any]:
    health = evidence.health
    audit = evidence.audit
    friction = evidence.friction
    outcomes = evidence.outcomes
    current = evidence.current_work
    return {
        "runtime": {
            "release_id": health.get("release_id") if isinstance(health, dict) else None,
            "repo_head": health.get("repo_head") if isinstance(health, dict) else None,
        },
        "audit": {
            "projection_sha256": evidence.audit_projection_sha,
            "findings_sha256": audit.get("findings_sha256") if isinstance(audit, dict) else None,
            "source_binding": audit.get("source_binding") if isinstance(audit, dict) else None,
        },
        "friction": {
            "snapshot_sha256": evidence.friction_snapshot_sha,
            "event_log_integrity_valid": (
                friction.get("event_log_integrity", {}).get("integrity_valid")
                if isinstance(friction, dict)
                and isinstance(friction.get("event_log_integrity"), dict)
                else None
            ),
            "decision_log_integrity_valid": (
                friction.get("decision_log", {}).get("integrity_valid")
                if isinstance(friction, dict)
                and isinstance(friction.get("decision_log"), dict)
                else None
            ),
        },
        "execution_outcomes": {
            "summary_sha256": evidence.outcome_summary_sha,
            "ledger_integrity_valid": (
                outcomes.get("ledger_integrity_valid")
                if isinstance(outcomes, dict)
                else None
            ),
        },
        "current_work": {
            "snapshot_sha256": evidence.current_work_sha,
            "generated_at_unix": (
                current.get("generated_at_unix") if isinstance(current, dict) else None
            ),
        },
    }


def _source_health(evidence: ReportEvidence) -> dict[str, Any]:
    sources = (
        evidence.health,
        evidence.audit,
        evidence.friction,
        evidence.outcomes,
        evidence.current_work,
    )
    all_available = all(item is not None for item in sources)
    current_truncated = False
    current_has_errors = False
    if isinstance(evidence.current_work, dict):
        truncation = evidence.current_work.get("source_truncation")
        current_truncated = isinstance(truncation, dict) and any(truncation.values())
        current_has_errors = bool(evidence.current_work.get("source_errors"))
    bounded_complete = all_available and not current_truncated and not current_has_errors
    return {
        "runtime_available": evidence.health is not None,
        "runtime_healthy": (
            evidence.health.get("healthy")
            if isinstance(evidence.health, dict)
            else None
        ),
        "audit_available": evidence.audit is not None,
        "friction_available": evidence.friction is not None,
        "execution_outcomes_available": evidence.outcomes is not None,
        "current_work_available": evidence.current_work is not None,
        "all_sources_available": all_available,
        "bounded_source_set_complete": bounded_complete,
        "complete": bounded_complete,
    }


def _coverage_gaps() -> list[dict[str, str]]:
    return [
        {
            "id": "remote_delivery_not_collected",
            "missing": "fresh GitHub PR, CI, merge and deployment results across repositories",
            "needed_for": "end-to-end delivery conversion and latency",
        },
        {
            "id": "product_effect_not_canonical",
            "missing": "a bounded canonical effect class on meaningful task closeout",
            "needed_for": (
                "separating product, quality and operational effect from internal activity"
            ),
        },
        {
            "id": "chat_completion_not_audited",
            "missing": "a durable binding from one user request to proven final operator closeout",
            "needed_for": (
                "detecting normal chat termination before requested work is complete"
            ),
        },
        {
            "id": "cross_store_causality_partial",
            "missing": (
                "complete causal identity across audit, friction, task, Bureau and "
                "delivery stores"
            ),
            "needed_for": "root-cause attribution rather than correlation",
        },
    ]


def _source_evidence(evidence: ReportEvidence) -> dict[str, Any]:
    audit = evidence.audit
    friction = evidence.friction
    outcomes = evidence.outcomes
    current = evidence.current_work
    return {
        "audit_candidate_patterns": (
            audit.get("candidate_patterns") if isinstance(audit, dict) else []
        ),
        "audit_signals": (
            audit.get("signal_projection", {}).get("signals", [])
            if isinstance(audit, dict)
            and isinstance(audit.get("signal_projection"), dict)
            else []
        ),
        "friction_failure_classification": (
            friction.get("failure_classification", {})
            if isinstance(friction, dict)
            else {}
        ),
        "execution_governor_candidates": (
            outcomes.get("candidates", []) if isinstance(outcomes, dict) else []
        ),
        "current_work_summary": (
            {
                key: current.get(key)
                for key in (
                    "count",
                    "total_projected",
                    "state_counts",
                    "convergence_summary",
                    "source_counts",
                    "source_truncation",
                    "warnings",
                )
            }
            if isinstance(current, dict)
            else {}
        ),
    }


def build_operator_optimization_report(
    repositories: list[str],
    *,
    window: str = "7d",
    view: str = "minimal",
    top_limit: int = 10,
    friction_limit: int = 100,
    outcome_limit: int = 200,
    current_work_limit: int = 50,
    now_unix: int | None = None,
    health_provider: Provider | None = None,
    audit_provider: Provider | None = None,
    friction_provider: Provider | None = None,
    outcome_provider: Provider | None = None,
    current_work_provider: Provider | None = None,
) -> dict[str, Any]:
    selected_repositories = _repositories(repositories)
    if window not in REPORT_WINDOWS:
        raise ValueError(f"window must be one of {sorted(REPORT_WINDOWS)}")
    selected_view = consumer_surface.normalize_view(view)
    top_limit = _bounded_int(
        top_limit,
        label="top_limit",
        minimum=1,
        maximum=MAX_TOP_LIMIT,
    )
    friction_limit = _bounded_int(
        friction_limit,
        label="friction_limit",
        minimum=1,
        maximum=MAX_FRICTION_LIMIT,
    )
    outcome_limit = _bounded_int(
        outcome_limit,
        label="outcome_limit",
        minimum=1,
        maximum=MAX_OUTCOME_LIMIT,
    )
    current_work_limit = _bounded_int(
        current_work_limit,
        label="current_work_limit",
        minimum=1,
        maximum=MAX_CURRENT_WORK_LIMIT,
    )
    generated_at_unix = int(time.time()) if now_unix is None else _bounded_int(
        now_unix,
        label="now_unix",
        minimum=0,
        maximum=4_102_444_800,
    )
    providers = _resolve_providers(
        health_provider,
        audit_provider,
        friction_provider,
        outcome_provider,
        current_work_provider,
    )
    warnings: list[dict[str, Any]] = []
    evidence = _collect_sources(
        selected_repositories,
        window=window,
        top_limit=top_limit,
        friction_limit=friction_limit,
        outcome_limit=outcome_limit,
        current_work_limit=current_work_limit,
        providers=providers,
        warnings=warnings,
    )
    findings = _collect_findings(evidence, warnings)
    recommendations = [_recommendation(item) for item in findings]
    comparison = _comparison(evidence.selected_metrics, evidence.comparison_metrics)
    coverage_gaps = _coverage_gaps()

    payload: dict[str, Any] = {
        "schema_version": 1,
        "report_kind": "operator_optimization_report.v1",
        "authority": "derived_read_only_advisory",
        "view": selected_view,
        "generated_at_unix": generated_at_unix,
        "scope": {
            "window": window,
            "comparison_window": evidence.comparison_label,
            "repositories": selected_repositories,
            "personal_activity_observation": False,
            "excluded_personal_telemetry": [
                "window_titles",
                "keyboard_input",
                "clipboard",
                "browser_history",
                "shell_history",
                "audio_or_video",
            ],
        },
        "source_health": _source_health(evidence),
        "source_bindings": _source_bindings(evidence),
        "measurement": {
            "selected_window": evidence.selected_metrics,
            "comparison_window": evidence.comparison_metrics,
            "comparison": comparison,
        },
        "findings": findings,
        "recommendations": recommendations,
        "coverage_gaps": coverage_gaps,
        "warnings": warnings,
        "recommended_next_action": (
            recommendations[0]["action"] if recommendations else "none"
        ),
        "does_not_establish": [
            "causality",
            "operator_productivity",
            "product_impact",
            "user_behavior",
            "automatic_task_creation_authority",
            "automatic_policy_mutation_authority",
            "safe_mutation_retry",
            "merge_or_deploy_readiness",
            "permission_to_change_foreign_work",
            "live_routing_promotion",
        ],
    }
    if selected_view in {"standard", "evidence"}:
        payload["source_evidence"] = _source_evidence(evidence)
    payload["findings_sha256"] = hashlib.sha256(
        consumer_surface.canonical_json_bytes(
            {
                "measurement": payload["measurement"],
                "findings": findings,
                "coverage_gaps": coverage_gaps,
                "warnings": warnings,
            }
        )
    ).hexdigest()
    payload["report_sha256"] = hashlib.sha256(
        consumer_surface.canonical_json_bytes(payload)
    ).hexdigest()
    return payload

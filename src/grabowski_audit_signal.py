from __future__ import annotations

from collections import Counter
import heapq
import hashlib
import re
import sys
from typing import Any

import grabowski_consumer_surface as consumer_surface

AUDIT_FUTURE_TOLERANCE_SECONDS = 300
AUDIT_PROJECTION_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}")
AUDIT_SIGNAL_WINDOW_SECONDS = 604_800
AUDIT_SIGNAL_GRACE_SECONDS = 300
AUDIT_SIGNAL_MAX_EVIDENCE_REFS = 20
AUDIT_SIGNAL_IDS = (
    "uncertain_outcome",
    "contract_contradiction",
    "transition_gap",
    "repeated_blockade",
    "stale_attention",
)
AUDIT_TRANSITION_PAIRS = (
    ("runtime-state-retention-intent", "runtime-state-retention-complete"),
    ("runtime-deploy-schedule-intent", "runtime-deploy-scheduled"),
)
RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION = (
    "runtime-state-retention-completion-audit-reconciled"
)
AUDIT_EVIDENCE_RECORD_SHA256_FIELD = "__grabowski_audit_evidence_record_sha256"
AUDIT_CONTRADICTION_OPERATION_TERMS = (
    "contract",
    "envelope",
    "projection",
    "receipt",
    "result",
    "schema",
)
AUDIT_CONTRADICTION_STRONG_TERMS = (
    "contradict",
    "inconsistent",
    "mismatch",
    "widerspr",
)
AUDIT_CONTRADICTION_DUAL_REPORT_MARKERS = ("while", "simultaneously")


def _label(value: Any, *, fallback: str = "unknown") -> str:
    if not isinstance(value, str) or not value:
        return fallback
    return value if AUDIT_PROJECTION_LABEL_RE.fullmatch(value) else "<redacted>"


def _audit_sha256_valid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _runtime_snapshot_timestamp_valid(value: Any, *, end_unix: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= end_unix + AUDIT_FUTURE_TOLERANCE_SECONDS
    )


def _audit_record_evidence_sha256(record: dict[str, Any]) -> str | None:
    stored = record.get("record_sha256")
    if _audit_sha256_valid(stored):
        return stored
    derived = record.get(AUDIT_EVIDENCE_RECORD_SHA256_FIELD)
    return derived if _audit_sha256_valid(derived) else None


def _audit_record_ref(record: dict[str, Any]) -> str | None:
    value = _audit_record_evidence_sha256(record)
    return f"audit-record-sha256:{value}" if value is not None else None


def _audit_signal_refs(values: list[str]) -> tuple[list[str], bool]:
    ordered = list(dict.fromkeys(value for value in values if value))
    return ordered[:AUDIT_SIGNAL_MAX_EVIDENCE_REFS], len(
        ordered
    ) > AUDIT_SIGNAL_MAX_EVIDENCE_REFS


def _audit_signal_entry(
    signal_id: str,
    *,
    status: str,
    severity: str,
    count: int | None,
    observed_count: int | None,
    evidence_refs: list[str],
    evidence_quality: str,
    recommended_action: str,
    details: dict[str, Any] | None = None,
    does_not_establish: list[str] | None = None,
) -> dict[str, Any]:
    if signal_id not in AUDIT_SIGNAL_IDS:
        raise RuntimeError(f"unknown audit signal id: {signal_id}")
    refs, truncated = _audit_signal_refs(evidence_refs)
    return {
        "id": signal_id,
        "status": status,
        "severity": severity,
        "count": count,
        "observed_count": observed_count,
        "evidence_refs": refs,
        "evidence_refs_truncated": truncated,
        "evidence_quality": evidence_quality,
        "recommended_action": recommended_action,
        "details": details or {},
        "does_not_establish": does_not_establish or [],
    }


def _retention_transition_identity(record: dict[str, Any]) -> tuple[str, int] | None:
    plan_sha256 = record.get("plan_sha256")
    attempt = record.get("attempt")
    if (
        not _audit_sha256_valid(plan_sha256)
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or attempt < 1
    ):
        return None
    return plan_sha256, attempt


def _audit_transition_identity(
    intent: str, record: dict[str, Any]
) -> tuple[str, int] | None:
    if intent == "runtime-state-retention-intent":
        return _retention_transition_identity(record)
    return None


def _audit_transition_identity_fields_present(
    intent: str, record: dict[str, Any]
) -> bool:
    return intent == "runtime-state-retention-intent" and (
        "plan_sha256" in record or "attempt" in record
    )


def _audit_transition_match_index(
    intent: str,
    entries: list[tuple[dict[str, Any], int]],
    completion_record: dict[str, Any],
) -> int | None:
    completion_fields_present = _audit_transition_identity_fields_present(
        intent, completion_record
    )
    completion_identity = _audit_transition_identity(intent, completion_record)
    if completion_fields_present:
        if completion_identity is None:
            return None
        for index, (candidate, _timestamp_unix) in enumerate(entries):
            if _audit_transition_identity(intent, candidate) == completion_identity:
                return index
        return None
    for index, (candidate, _timestamp_unix) in enumerate(entries):
        if not _audit_transition_identity_fields_present(intent, candidate):
            return index
    return None


def _retention_intent_index_key(
    record: dict[str, Any],
) -> tuple[str, int, str] | None:
    identity = _retention_transition_identity(record)
    record_sha256 = _audit_record_evidence_sha256(record)
    if identity is None or record_sha256 is None:
        return None
    return identity[0], identity[1], record_sha256


def _retention_reconciliation_target_key(
    reconciliation_record: dict[str, Any],
) -> tuple[str, int, str] | None:
    identity = _retention_transition_identity(reconciliation_record)
    intent_record_sha256 = reconciliation_record.get("intent_record_sha256")
    if (
        reconciliation_record.get("operation")
        != RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION
        or identity is None
        or not _audit_sha256_valid(intent_record_sha256)
    ):
        return None
    return identity[0], identity[1], intent_record_sha256


def _retention_reconciliation_record_valid(
    reconciliation_record: dict[str, Any],
) -> bool:
    return bool(
        _retention_reconciliation_target_key(reconciliation_record) is not None
        and reconciliation_record.get("reconciliation_kind") == "completion_audit_gap"
        and reconciliation_record.get("completed") is True
        and reconciliation_record.get("retention_effect_retried") is False
        and _audit_sha256_valid(reconciliation_record.get("receipt_sha256"))
    )


def _retention_reconciliation_target_index(
    entries: list[tuple[dict[str, Any], int]],
    reconciliation_record: dict[str, Any],
) -> int | None:
    target_key = _retention_reconciliation_target_key(reconciliation_record)
    if target_key is None:
        return None
    for index, (candidate, _timestamp_unix) in enumerate(entries):
        if _retention_intent_index_key(candidate) == target_key:
            return index
    return None


def _retention_reconciliation_match_index(
    entries: list[tuple[dict[str, Any], int]],
    reconciliation_record: dict[str, Any],
) -> int | None:
    if not _retention_reconciliation_record_valid(reconciliation_record):
        return None
    return _retention_reconciliation_target_index(entries, reconciliation_record)


def _audit_transition_gap_signal(
    prepared_records: list[tuple[dict[str, Any], int | None]],
    *,
    start_unix: int,
    end_unix: int,
) -> dict[str, Any]:
    retention_pair = (
        "runtime-state-retention-intent",
        "runtime-state-retention-complete",
    )
    pending: dict[tuple[str, str], list[tuple[dict[str, Any], int]]] = {
        pair: [] for pair in AUDIT_TRANSITION_PAIRS
    }
    pending_retention: dict[
        tuple[str, int, str], tuple[dict[str, Any], int]
    ] = {}
    pending_retention_keys_by_identity: dict[
        tuple[str, int], dict[tuple[str, int, str], None]
    ] = {}
    historical_retention_intents: dict[
        tuple[str, int, str], tuple[dict[str, Any], int]
    ] = {}
    historical_reconciled_keys: set[tuple[str, int, str]] = set()
    historical_unmatched: dict[
        tuple[str, int, str], tuple[str, dict[str, Any], int]
    ] = {}
    historical_intent_order: dict[tuple[str, int, str], int] = {}
    historical_unmatched_keys_by_identity: dict[
        tuple[str, int], set[tuple[str, int, str]]
    ] = {}
    historical_unmatched_heap_by_identity: dict[
        tuple[str, int], list[tuple[int, tuple[str, int, str]]]
    ] = {}
    seen_retention_completion_identities: set[tuple[str, int]] = set()
    completed_counts: Counter[str] = Counter()
    reconciled_counts: Counter[str] = Counter()
    reconciled_records: list[dict[str, Any]] = []

    def _remember_pending_retention(
        key: tuple[str, int, str], record: dict[str, Any], timestamp_unix: int
    ) -> None:
        pending_retention[key] = (record, timestamp_unix)
        keys = pending_retention_keys_by_identity.setdefault(key[:2], {})
        keys.setdefault(key, None)

    def _pop_pending_retention(
        key: tuple[str, int, str]
    ) -> tuple[dict[str, Any], int] | None:
        item = pending_retention.pop(key, None)
        keys = pending_retention_keys_by_identity.get(key[:2])
        if keys is not None:
            keys.pop(key, None)
            if not keys:
                pending_retention_keys_by_identity.pop(key[:2], None)
        return item

    def _remember_historical_unmatched(
        key: tuple[str, int, str], record: dict[str, Any], timestamp_unix: int
    ) -> None:
        historical_unmatched[key] = (
            retention_pair[0],
            record,
            timestamp_unix,
        )
        identity = key[:2]
        keys = historical_unmatched_keys_by_identity.setdefault(identity, set())
        if key not in keys:
            keys.add(key)
            order = historical_intent_order[key]
            heapq.heappush(
                historical_unmatched_heap_by_identity.setdefault(identity, []),
                (-order, key),
            )

    def _pop_historical_unmatched(
        key: tuple[str, int, str]
    ) -> tuple[str, dict[str, Any], int] | None:
        item = historical_unmatched.pop(key, None)
        keys = historical_unmatched_keys_by_identity.get(key[:2])
        if keys is not None:
            keys.discard(key)
            if not keys:
                historical_unmatched_keys_by_identity.pop(key[:2], None)
                historical_unmatched_heap_by_identity.pop(key[:2], None)
        return item

    def _pop_latest_historical_unmatched(
        identity: tuple[str, int],
    ) -> tuple[str, dict[str, Any], int] | None:
        keys = historical_unmatched_keys_by_identity.get(identity)
        heap = historical_unmatched_heap_by_identity.get(identity)
        if not keys or not heap:
            return None
        while heap:
            _negative_order, key = heapq.heappop(heap)
            if key in keys:
                return _pop_historical_unmatched(key)
        historical_unmatched_heap_by_identity.pop(identity, None)
        return None

    for audit_order, (record, timestamp_unix) in enumerate(prepared_records):
        if timestamp_unix is None or timestamp_unix > end_unix:
            continue
        operation = record.get("operation")

        if timestamp_unix < start_unix:
            if operation == retention_pair[0]:
                key = _retention_intent_index_key(record)
                if key is not None:
                    historical_retention_intents[key] = (record, timestamp_unix)
                    historical_intent_order[key] = audit_order
            elif operation == retention_pair[1]:
                identity = _retention_transition_identity(record)
                if identity is not None:
                    seen_retention_completion_identities.add(identity)
            elif operation == RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION:
                target_key = _retention_reconciliation_target_key(record)
                identity = _retention_transition_identity(record)
                if (
                    target_key in historical_retention_intents
                    and _retention_reconciliation_record_valid(record)
                    and identity not in seen_retention_completion_identities
                ):
                    historical_reconciled_keys.add(target_key)
            continue

        if operation == retention_pair[0]:
            key = _retention_intent_index_key(record)
            if key is None:
                # Preserve legacy/malformed fail-closed FIFO behavior separately.
                pending[retention_pair].append((record, timestamp_unix))
            else:
                _remember_pending_retention(key, record, timestamp_unix)
            continue

        if operation == RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION:
            target_key = _retention_reconciliation_target_key(record)
            if target_key is None:
                continue
            if target_key in pending_retention:
                if _retention_reconciliation_record_valid(record):
                    _pop_pending_retention(target_key)
                    reconciled_counts[retention_pair[0]] += 1
                    reconciled_records.append(record)
                # Invalid evidence leaves the indexed in-window intent pending/HIGH.
                continue

            historical_target = historical_retention_intents.get(target_key)
            if historical_target is None:
                continue
            identity = target_key[:2]
            if (
                target_key in historical_reconciled_keys
                or identity in seen_retention_completion_identities
            ):
                continue
            historical_record, historical_timestamp = historical_target
            if _retention_reconciliation_record_valid(record):
                _pop_historical_unmatched(target_key)
                historical_reconciled_keys.add(target_key)
                reconciled_counts[retention_pair[0]] += 1
                reconciled_records.append(record)
            else:
                # Fresh invalid reconciliation evidence keeps the exact old intent HIGH.
                _remember_historical_unmatched(
                    target_key,
                    historical_record,
                    historical_timestamp,
                )
            continue

        if operation == retention_pair[1]:
            completion_fields_present = _audit_transition_identity_fields_present(
                retention_pair[0], record
            )
            identity = _retention_transition_identity(record)
            matched = False
            if completion_fields_present:
                if identity is not None:
                    keys = pending_retention_keys_by_identity.get(identity, {})
                    if keys:
                        # Dict insertion order is verified audit order. Membership and
                        # exact removal stay O(1), while reversed(keys) selects the
                        # most recent preceding duplicate deterministically.
                        latest_key = next(reversed(keys))
                        _pop_pending_retention(latest_key)
                        matched = True
            else:
                match_index = _audit_transition_match_index(
                    retention_pair[0], pending[retention_pair], record
                )
                if match_index is not None:
                    pending[retention_pair].pop(match_index)
                    matched = True
            if matched:
                completed_counts[retention_pair[0]] += 1
            if identity is not None:
                seen_retention_completion_identities.add(identity)
                # One completion can resolve at most one intent.  Prefer a matching
                # in-window pending intent; only when none matched may it close one
                # historical unknown of the same identity.
                if (
                    not matched
                    and _pop_latest_historical_unmatched(identity) is not None
                ):
                    completed_counts[retention_pair[0]] += 1
            continue

        for intent, completion in AUDIT_TRANSITION_PAIRS:
            key = (intent, completion)
            if key == retention_pair:
                continue
            if operation == intent:
                pending[key].append((record, timestamp_unix))
                break
            if operation == completion:
                match_index = _audit_transition_match_index(
                    intent, pending[key], record
                )
                if match_index is not None:
                    pending[key].pop(match_index)
                    completed_counts[intent] += 1
                break

    gaps: list[tuple[str, dict[str, Any], int]] = list(
        historical_unmatched.values()
    )
    for record, timestamp_unix in pending_retention.values():
        if timestamp_unix <= end_unix - AUDIT_SIGNAL_GRACE_SECONDS:
            gaps.append((retention_pair[0], record, timestamp_unix))
    for (intent, _completion), entries in pending.items():
        for record, timestamp_unix in entries:
            if timestamp_unix <= end_unix - AUDIT_SIGNAL_GRACE_SECONDS:
                gaps.append((intent, record, timestamp_unix))

    by_transition = Counter(intent for intent, _record, _timestamp in gaps)
    execution_refs = [
        ref
        for _intent, record, _timestamp in gaps
        if (ref := _audit_record_ref(record))
    ]
    reconciliation_refs_all = [
        ref for record in reconciled_records if (ref := _audit_record_ref(record))
    ]
    reconciliation_refs, reconciliation_refs_truncated = _audit_signal_refs(
        reconciliation_refs_all
    )
    unique_reconciliation_ref_count = len(
        dict.fromkeys(ref for ref in reconciliation_refs_all if ref)
    )
    observed_count = len(gaps) + len(reconciled_records)
    if gaps:
        severity = "high"
        recommended_action = "trace each unmatched intent and read the exact target state before retry"
    elif reconciled_records:
        severity = "medium"
        recommended_action = (
            "review append-only completion-audit reconciliation evidence; "
            "do not retry the retention effect"
        )
    else:
        severity = "none"
        recommended_action = "none"
    return _audit_signal_entry(
        "transition_gap",
        status="observed" if observed_count else "clear",
        severity=severity,
        count=observed_count,
        observed_count=observed_count,
        evidence_refs=execution_refs + reconciliation_refs_all,
        evidence_quality=(
            "explicit_identity_with_terminal_receipt_reconciliation_and_legacy_fifo_fallback"
        ),
        recommended_action=recommended_action,
        details={
            "grace_seconds": AUDIT_SIGNAL_GRACE_SECONDS,
            "execution_gap_count": len(gaps),
            "completion_audit_gap_count": len(reconciled_records),
            "unmatched_intents_by_transition": dict(sorted(by_transition.items())),
            "completed_pairs_by_transition": dict(sorted(completed_counts.items())),
            "completion_audit_gaps_by_transition": dict(sorted(reconciled_counts.items())),
            "completion_audit_gap_evidence_refs": reconciliation_refs,
            "completion_audit_gap_evidence_refs_truncated": reconciliation_refs_truncated,
            "completion_audit_gap_evidence_refs_omitted_count": max(
                0, unique_reconciliation_ref_count - len(reconciliation_refs)
            ),
            "pairing_semantics": (
                "retention identities are indexed by (plan_sha256, attempt, "
                "intent_record_sha256); append-only reconciliations resolve only that "
                "exact indexed intent, including older verified intents outside the "
                "reporting window when no prior matching completion exists; invalid "
                "current reconciliation evidence keeps that exact historical intent "
                "visible as an execution_gap; records with both identity fields absent "
                "retain legacy FIFO behavior; other transition families use FIFO"
            ),
        },
        does_not_establish=[
            "effect_absence_outside_the_audit_chain",
            "causality",
            "safe_retry",
            "exact_cross-operation_identity_when_no_transaction_id_is_logged",
            "that_the_original_completion_audit_record_existed",
            "cause_of_the_completion_audit_gap",
        ],
    )


def _audit_friction_signal_source() -> dict[str, Any]:
    module = sys.modules.get("grabowski_friction")
    if module is None:
        return {
            "available": False,
            "integrity_valid": False,
            "reason": "friction_module_not_loaded",
            "events": [],
            "snapshot_sha256": None,
        }
    summary_func = getattr(module, "friction_summary", None)
    classifier = getattr(module, "classify_friction_event", None)
    if not callable(summary_func) or not callable(classifier):
        return {
            "available": False,
            "integrity_valid": False,
            "reason": "friction_provider_incomplete",
            "events": [],
            "snapshot_sha256": None,
        }
    try:
        summary = summary_func(limit=500, view="evidence")
    except Exception as exc:  # pragma: no cover - defensive provider boundary
        return {
            "available": False,
            "integrity_valid": False,
            "reason": "friction_provider_failed",
            "error_type": type(exc).__name__,
            "events": [],
            "snapshot_sha256": None,
        }
    event_integrity = summary.get("event_log_integrity", {})
    decision_integrity = summary.get("decision_log", {})
    events = summary.get("events", [])
    if not isinstance(events, list):
        events = []
    enriched: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        bounded = dict(event)
        bounded["failure_class"] = classifier(event)
        enriched.append(bounded)
    pagination = summary.get("pagination", {})
    return {
        "available": True,
        "integrity_valid": (
            event_integrity.get("integrity_valid") is True
            and decision_integrity.get("integrity_valid") is True
        ),
        "reason": None,
        "events": enriched,
        "snapshot_sha256": pagination.get("snapshot_sha256"),
        "returned": len(enriched),
        "has_more": pagination.get("has_more") is True,
    }


def _runtime_signal_source(runtime_status_provider: Any) -> dict[str, Any]:
    status_func = runtime_status_provider
    if not callable(status_func):
        return {"available": False, "reason": "runtime_status_unavailable"}
    try:
        try:
            status = status_func(view="evidence")
        except TypeError:
            status = status_func()
    except Exception as exc:  # pragma: no cover - defensive provider boundary
        return {
            "available": False,
            "reason": "runtime_status_failed",
            "error_type": type(exc).__name__,
        }
    if not isinstance(status, dict):
        return {"available": False, "reason": "runtime_status_invalid"}
    tool_contract = status.get("tool_contract", {})
    if not isinstance(tool_contract, dict):
        tool_contract = {}
    client_snapshot = tool_contract.get("client_snapshot", {})
    if not isinstance(client_snapshot, dict):
        client_snapshot = {}
    return {
        "available": True,
        "healthy": status.get("healthy") is True,
        "runtime_matches_contract": (
            tool_contract.get("runtime_matches_deployment_contract") is True
        ),
        "client_snapshot_observable": (
            tool_contract.get("client_snapshot_observable") is True
        ),
        "client_snapshot_fresh": client_snapshot.get("fresh") is True,
        "client_snapshot_matched": client_snapshot.get("matched") is True,
        "client_snapshot_created_at_unix": client_snapshot.get("created_at_unix"),
        "client_snapshot_receipt_sha256": client_snapshot.get("receipt_sha256"),
    }


def _audit_event_unresolved(event: dict[str, Any]) -> bool:
    resolution_status = event.get("resolution_status")
    return event.get("resolved") is not True or resolution_status in {
        "unresolved",
        "reopened",
    }


def _audit_contract_contradiction_kind(event: dict[str, Any]) -> str | None:
    operation = str(event.get("operation") or "").lower()
    symptom = str(event.get("symptom") or "").lower()
    contradiction_language = any(
        term in symptom for term in AUDIT_CONTRADICTION_STRONG_TERMS
    ) or (
        "reported" in symptom
        and any(marker in symptom for marker in AUDIT_CONTRADICTION_DUAL_REPORT_MARKERS)
    )
    if (
        event.get("failure_class") == "contract_error"
        or event.get("kind") == "ci_contract"
    ):
        return "structured_contract_mismatch" if contradiction_language else None
    if event.get("kind") != "operator_bug":
        return None
    if (
        any(term in operation for term in AUDIT_CONTRADICTION_OPERATION_TERMS)
        and contradiction_language
    ):
        return "heuristic_projection_or_receipt_mismatch"
    return None


def _audit_friction_window_complete(source: dict[str, Any], *, start_unix: int) -> bool:
    if source.get("has_more") is not True:
        return True
    timestamps = [
        event.get("recorded_at_unix")
        for event in source.get("events", [])
        if isinstance(event, dict) and isinstance(event.get("recorded_at_unix"), int)
    ]
    return bool(timestamps and min(timestamps) <= start_unix)


def _audit_stale_attention_signal(
    events: list[dict[str, Any]],
    runtime_source: dict[str, Any],
    *,
    window_complete: bool,
    end_unix: int,
) -> dict[str, Any]:
    if runtime_source.get("available") is not True:
        return {
            "status": "indeterminate",
            "severity": "unknown",
            "count": None,
            "observed_count": None,
            "evidence_refs": [],
            "evidence_quality": "runtime_status_unavailable",
            "recommended_action": "restore live runtime observation before classifying attention as stale",
            "details": {"reason": runtime_source.get("reason")},
        }

    runtime_contract_clean = bool(
        runtime_source.get("healthy") is True
        and runtime_source.get("runtime_matches_contract") is True
        and runtime_source.get("client_snapshot_observable") is True
        and runtime_source.get("client_snapshot_fresh") is True
        and runtime_source.get("client_snapshot_matched") is True
    )
    if not runtime_contract_clean:
        return {
            "status": "indeterminate",
            "severity": "unknown",
            "count": None,
            "observed_count": None,
            "evidence_refs": [],
            "evidence_quality": "live_runtime_not_clean",
            "recommended_action": "restore a healthy contract-matched runtime snapshot before classifying attention as stale",
            "details": {
                "live_runtime_clean": False,
                "window_complete": window_complete,
                "reason": "runtime_or_client_snapshot_not_healthy_fresh_and_matched",
            },
        }

    snapshot_created = runtime_source.get("client_snapshot_created_at_unix")
    if not _runtime_snapshot_timestamp_valid(snapshot_created, end_unix=end_unix):
        return {
            "status": "indeterminate",
            "severity": "unknown",
            "count": None,
            "observed_count": None,
            "evidence_refs": [],
            "evidence_quality": "runtime_snapshot_timestamp_unavailable",
            "recommended_action": "restore a valid client snapshot timestamp before classifying attention as stale",
            "details": {
                "live_runtime_clean": False,
                "window_complete": window_complete,
                "reason": "client_snapshot_created_at_unix_missing_or_invalid",
            },
        }

    snapshot_receipt = runtime_source.get("client_snapshot_receipt_sha256")
    if not _audit_sha256_valid(snapshot_receipt):
        return {
            "status": "indeterminate",
            "severity": "unknown",
            "count": None,
            "observed_count": None,
            "evidence_refs": [],
            "evidence_quality": "runtime_snapshot_receipt_unavailable",
            "recommended_action": "restore a valid client snapshot receipt before classifying attention as stale",
            "details": {
                "live_runtime_clean": False,
                "window_complete": window_complete,
                "reason": "client_snapshot_receipt_sha256_missing_or_invalid",
            },
        }

    stale_candidates = [
        event
        for event in events
        if event.get("kind") == "connector_snapshot"
        and _audit_event_unresolved(event)
        and isinstance(event.get("recorded_at_unix"), int)
        and event["recorded_at_unix"] < snapshot_created
    ]
    stale_refs = [
        f"friction-event:{event['event_id']}"
        for event in stale_candidates
        if isinstance(event.get("event_id"), str) and event.get("event_id")
    ]
    return {
        "status": (
            "observed"
            if stale_candidates
            else ("clear" if window_complete else "indeterminate")
        ),
        "severity": (
            "medium" if stale_candidates else ("none" if window_complete else "unknown")
        ),
        "count": len(stale_candidates),
        "observed_count": len(stale_candidates),
        "evidence_refs": stale_refs,
        "evidence_quality": "friction_event_bound_to_later_fresh_matched_client_snapshot",
        "recommended_action": (
            "review and close or reopen each candidate with the current runtime receipt"
            if stale_candidates
            else "none"
        ),
        "details": {
            "live_runtime_clean": True,
            "client_snapshot_created_at_unix": snapshot_created,
            "client_snapshot_receipt_sha256": snapshot_receipt,
            "candidate_semantics": "closeout review only; no automatic resolution",
            "window_complete": window_complete,
            "count_semantics": "exact" if window_complete else "lower_bound",
        },
    }


def _audit_friction_signals(
    source: dict[str, Any],
    runtime_source: dict[str, Any],
    *,
    start_unix: int,
    end_unix: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if source.get("available") is not True or source.get("integrity_valid") is not True:
        reason = str(source.get("reason") or "friction_integrity_invalid")
        indeterminate = {
            "status": "indeterminate",
            "severity": "unknown",
            "count": None,
            "observed_count": None,
            "evidence_refs": [],
            "evidence_quality": "unavailable",
            "recommended_action": "restore and verify the friction evidence provider",
            "details": {"reason": reason},
        }
        return indeterminate, indeterminate, indeterminate

    window_complete = _audit_friction_window_complete(source, start_unix=start_unix)
    events = [
        event
        for event in source.get("events", [])
        if isinstance(event.get("recorded_at_unix"), int)
        and start_unix
        <= event["recorded_at_unix"]
        <= end_unix + AUDIT_FUTURE_TOLERANCE_SECONDS
    ]
    contradictions: list[tuple[dict[str, Any], str]] = []
    for event in events:
        contradiction_kind = _audit_contract_contradiction_kind(event)
        if contradiction_kind is not None:
            contradictions.append((event, contradiction_kind))
    active_contradictions = [
        (event, kind)
        for event, kind in contradictions
        if _audit_event_unresolved(event)
    ]
    contradiction_refs = [
        f"friction-event:{event['event_id']}"
        for event, _kind in active_contradictions
        if isinstance(event.get("event_id"), str) and event.get("event_id")
    ]
    contradiction_kinds = Counter(kind for _event, kind in contradictions)
    contradiction_operations = Counter(
        _label(event.get("operation"), fallback="unknown")
        for event, _kind in active_contradictions
    )
    contradiction = {
        "status": (
            "observed"
            if active_contradictions
            else ("clear" if window_complete else "indeterminate")
        ),
        "severity": (
            "high"
            if active_contradictions
            else ("none" if window_complete else "unknown")
        ),
        "count": len(active_contradictions),
        "observed_count": len(contradictions),
        "evidence_refs": contradiction_refs,
        "evidence_quality": (
            "structured_and_bounded_heuristic_friction_classification"
            if contradictions
            else "structured_friction_classification"
        ),
        "recommended_action": (
            "trace each event to producer, consumer and live readback before changing the contract"
            if active_contradictions
            else "none"
        ),
        "details": {
            "observed_by_classification": dict(sorted(contradiction_kinds.items())),
            "active_by_operation": dict(sorted(contradiction_operations.items())),
            "window_complete": window_complete,
            "count_semantics": "exact" if window_complete else "lower_bound",
        },
    }

    blockade_groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if event.get("failure_class") != "policy_gate" or not _audit_event_unresolved(
            event
        ):
            continue
        operation = _label(event.get("operation"), fallback="unknown")
        blockade_groups.setdefault(operation, []).append(event)
    repeated_groups = {
        operation: grouped
        for operation, grouped in blockade_groups.items()
        if len(grouped) >= 3
    }
    repeated_events = [
        event
        for operation in sorted(repeated_groups)
        for event in repeated_groups[operation]
    ]
    blockade_refs = [
        f"friction-event:{event['event_id']}"
        for event in repeated_events
        if isinstance(event.get("event_id"), str) and event.get("event_id")
    ]
    repeated_blockade = {
        "status": (
            "observed"
            if repeated_events
            else ("clear" if window_complete else "indeterminate")
        ),
        "severity": (
            "medium" if repeated_events else ("none" if window_complete else "unknown")
        ),
        "count": len(repeated_events),
        "observed_count": sum(len(group) for group in blockade_groups.values()),
        "evidence_refs": blockade_refs,
        "evidence_quality": "structured_unresolved_policy_gate_grouping",
        "recommended_action": (
            "prepare the missing gate evidence or deliberately revise the owning policy; do not retry unchanged"
            if repeated_events
            else "none"
        ),
        "details": {
            "repeat_threshold": 3,
            "repeated_by_operation": {
                operation: len(grouped)
                for operation, grouped in sorted(repeated_groups.items())
            },
            "window_complete": window_complete,
            "count_semantics": "exact" if window_complete else "lower_bound",
        },
    }

    stale_attention = _audit_stale_attention_signal(
        events,
        runtime_source,
        window_complete=window_complete,
        end_unix=end_unix,
    )
    return contradiction, repeated_blockade, stale_attention


def _audit_signal_semantic_details(signal: dict[str, Any]) -> dict[str, Any]:
    details = signal.get("details", {})
    if not isinstance(details, dict):
        return {}
    semantic = dict(details)
    semantic.pop("client_snapshot_created_at_unix", None)
    semantic.pop("client_snapshot_receipt_sha256", None)
    return semantic


def findings_payload(signal_projection: dict[str, Any]) -> dict[str, Any]:
    source_health = signal_projection.get("source_health", {})
    if not isinstance(source_health, dict):
        source_health = {}
    semantic_source_health = {
        key: value
        for key, value in source_health.items()
        if not key.endswith("_sha256")
    }
    return {
        "signals": [
            {
                key: signal.get(key)
                for key in (
                    "id",
                    "status",
                    "severity",
                    "count",
                    "observed_count",
                    "evidence_refs",
                    "evidence_refs_truncated",
                    "evidence_quality",
                    "recommended_action",
                    "does_not_establish",
                )
            }
            | {"details": _audit_signal_semantic_details(signal)}
            for signal in signal_projection.get("signals", [])
            if isinstance(signal, dict)
        ],
        "source_health": semantic_source_health,
    }


def build_projection(
    prepared_records: list[tuple[dict[str, Any], int | None]],
    *,
    as_of_unix: int,
    audit_source_binding: dict[str, Any],
    runtime_status_provider: Any = None,
) -> dict[str, Any]:
    start_unix = as_of_unix - AUDIT_SIGNAL_WINDOW_SECONDS
    uncertain_records: list[dict[str, Any]] = []
    for record, timestamp_unix in prepared_records:
        if (
            timestamp_unix is None
            or timestamp_unix < start_unix
            or timestamp_unix > as_of_unix
        ):
            continue
        if (
            record.get("outcome_unknown") is True
            or record.get("launcher_outcome_unknown") is True
            or record.get("recovery_required") is True
        ):
            uncertain_records.append(record)
    uncertain_refs = [
        ref for record in uncertain_records if (ref := _audit_record_ref(record))
    ]
    uncertain_outcome = _audit_signal_entry(
        "uncertain_outcome",
        status="observed" if uncertain_records else "clear",
        severity="critical" if uncertain_records else "none",
        count=len(uncertain_records),
        observed_count=len(uncertain_records),
        evidence_refs=uncertain_refs,
        evidence_quality="direct_verified_audit_fields",
        recommended_action=(
            "read the exact target state and recovery evidence before any retry"
            if uncertain_records
            else "none"
        ),
        details={"window_seconds": AUDIT_SIGNAL_WINDOW_SECONDS},
        does_not_establish=["mutation_failure", "safe_retry", "root_cause"],
    )
    transition_gap = _audit_transition_gap_signal(
        prepared_records,
        start_unix=start_unix,
        end_unix=as_of_unix,
    )
    friction_source = _audit_friction_signal_source()
    runtime_source = _runtime_signal_source(runtime_status_provider)
    contradiction_raw, blockade_raw, stale_raw = _audit_friction_signals(
        friction_source,
        runtime_source,
        start_unix=start_unix,
        end_unix=as_of_unix,
    )
    contract_contradiction = _audit_signal_entry(
        "contract_contradiction",
        **contradiction_raw,
        does_not_establish=[
            "root_cause",
            "which_side_of_the_contract_is_wrong",
            "automatic_contract_change_authority",
        ],
    )
    repeated_blockade = _audit_signal_entry(
        "repeated_blockade",
        **blockade_raw,
        does_not_establish=[
            "policy_is_wrong",
            "policy_bypass_authority",
            "shared_root_cause",
        ],
    )
    stale_attention = _audit_signal_entry(
        "stale_attention",
        **stale_raw,
        does_not_establish=[
            "automatic_closeout_authority",
            "historical_event_was_false",
            "current_transport_reliability",
        ],
    )
    signals = [
        uncertain_outcome,
        contract_contradiction,
        transition_gap,
        repeated_blockade,
        stale_attention,
    ]
    friction_available = friction_source.get("available") is True
    friction_integrity_valid = friction_source.get("integrity_valid") is True
    friction_recent_window_complete = bool(
        friction_available
        and friction_integrity_valid
        and _audit_friction_window_complete(friction_source, start_unix=start_unix)
    )
    client_snapshot_timestamp_valid = _runtime_snapshot_timestamp_valid(
        runtime_source.get("client_snapshot_created_at_unix"), end_unix=as_of_unix
    )
    client_snapshot_receipt_valid = _audit_sha256_valid(
        runtime_source.get("client_snapshot_receipt_sha256")
    )
    source_health = {
        "audit_chain_verified": True,
        "friction_available": friction_available,
        "friction_integrity_valid": friction_integrity_valid,
        "friction_recent_window_complete": friction_recent_window_complete,
        "runtime_status_available": runtime_source.get("available") is True,
        "runtime_healthy": runtime_source.get("healthy") is True,
        "client_snapshot_fresh_and_matched": bool(
            runtime_source.get("client_snapshot_observable") is True
            and runtime_source.get("client_snapshot_fresh") is True
            and runtime_source.get("client_snapshot_matched") is True
            and client_snapshot_timestamp_valid
            and client_snapshot_receipt_valid
        ),
        "client_snapshot_timestamp_valid": client_snapshot_timestamp_valid,
        "client_snapshot_receipt_valid": client_snapshot_receipt_valid,
    }
    payload: dict[str, Any] = {
        "schema_version": 1,
        "projection_kind": "audit-signal.v1",
        "authority": "derived_read_only_projection",
        "as_of_unix": as_of_unix,
        "window": {
            "label": "7d",
            "start_unix": start_unix,
            "end_unix": as_of_unix,
        },
        "source_binding": {
            "audit_snapshot_sha256": audit_source_binding.get("snapshot_sha256"),
            "audit_last_record_sha256": audit_source_binding.get("last_record_sha256"),
            "friction_snapshot_sha256": friction_source.get("snapshot_sha256"),
            "runtime_client_snapshot_receipt_sha256": runtime_source.get(
                "client_snapshot_receipt_sha256"
            ),
        },
        "source_health": source_health,
        "signals": signals,
        "recommended_next_action": next(
            (
                signal["recommended_action"]
                for signal in signals
                if signal["status"] == "observed"
                and signal["recommended_action"] != "none"
            ),
            next(
                (
                    signal["recommended_action"]
                    for signal in signals
                    if signal["status"] == "indeterminate"
                    and signal["recommended_action"] != "none"
                ),
                "none",
            ),
        ),
        "does_not_establish": [
            "causality",
            "root_cause",
            "automatic_task_creation_authority",
            "automatic_closeout_authority",
            "safe_mutation_retry",
            "future_failure_probability",
        ],
    }
    payload["findings_sha256"] = hashlib.sha256(
        consumer_surface.canonical_json_bytes(findings_payload(payload))
    ).hexdigest()
    payload["projection_sha256"] = hashlib.sha256(
        consumer_surface.canonical_json_bytes(payload)
    ).hexdigest()
    return payload

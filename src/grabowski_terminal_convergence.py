from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = 1
FAILURE_CLASSES = frozenset({
    "completed",
    "running",
    "retry_safe_failure",
    "retry_exhausted",
    "outcome_unknown",
    "stale_process",
    "non_retryable_failure",
    "evidence_drift",
    "observation_denied",
})
TERMINAL_FAILURE_STATES = frozenset({"failed", "timed_out", "signalled", "interrupted"})


class TerminalConvergenceError(ValueError):
    pass


@dataclass(frozen=True)
class TerminalFailureClassification:
    reason_class: str
    retryable: bool
    automatic_resume_allowed: bool
    owner_decision_required: bool
    terminal_evidence_required: bool
    lease_evidence_required: bool
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "reason_class": self.reason_class,
            "retryable": self.retryable,
            "automatic_resume_allowed": self.automatic_resume_allowed,
            "owner_decision_required": self.owner_decision_required,
            "terminal_evidence_required": self.terminal_evidence_required,
            "lease_evidence_required": self.lease_evidence_required,
            "reason": self.reason,
        }


def classify_terminal_failure(
    *,
    current_state: str,
    observed_state: str,
    resume_policy: str,
    terminal_evidence_valid: bool,
    lease_evidence_valid: bool,
    retry_count: int = 0,
    retry_limit: int = 1,
    observation_denied: bool = False,
) -> dict[str, Any]:
    if not isinstance(current_state, str) or not isinstance(observed_state, str):
        raise TerminalConvergenceError("task states must be strings")
    if not isinstance(resume_policy, str) or not resume_policy:
        raise TerminalConvergenceError("resume_policy must be a non-empty string")
    if not isinstance(terminal_evidence_valid, bool) or not isinstance(lease_evidence_valid, bool):
        raise TerminalConvergenceError("evidence flags must be boolean")
    if isinstance(retry_count, bool) or not isinstance(retry_count, int) or retry_count < 0:
        raise TerminalConvergenceError("retry_count must be a non-negative integer")
    if isinstance(retry_limit, bool) or not isinstance(retry_limit, int) or retry_limit < 1:
        raise TerminalConvergenceError("retry_limit must be a positive integer")

    if observation_denied:
        result = TerminalFailureClassification(
            "observation_denied", False, False, True, True, True,
            "authoritative task observation was denied",
        )
    elif observed_state == "running":
        result = TerminalFailureClassification(
            "running", False, False, False, False, False,
            "task is still running",
        )
    elif observed_state == "completed":
        result = TerminalFailureClassification(
            "completed", False, False, False, True, False,
            "task completed and must converge through terminal evidence",
        )
    elif observed_state == "outcome_unknown":
        result = TerminalFailureClassification(
            "outcome_unknown", False, False, True, True, True,
            "outcome_unknown requires authoritative verification before retry",
        )
    elif current_state == "running" and observed_state in {"interrupted", "failed", "timed_out", "signalled"} and not terminal_evidence_valid:
        result = TerminalFailureClassification(
            "stale_process", False, False, True, True, True,
            "process disappeared without valid terminal evidence",
        )
    elif not terminal_evidence_valid or not lease_evidence_valid:
        result = TerminalFailureClassification(
            "evidence_drift", False, False, True, True, True,
            "terminal or lease evidence does not match the current task binding",
        )
    elif resume_policy != "retry-safe":
        result = TerminalFailureClassification(
            "non_retryable_failure", False, False, True, True, True,
            "task resume policy does not permit automatic retry",
        )
    elif retry_count >= retry_limit:
        result = TerminalFailureClassification(
            "retry_exhausted", False, False, True, True, True,
            "retry budget is exhausted",
        )
    elif observed_state in TERMINAL_FAILURE_STATES:
        result = TerminalFailureClassification(
            "retry_safe_failure", True, True, False, True, True,
            "verified retry-safe terminal failure may be resumed",
        )
    else:
        result = TerminalFailureClassification(
            "non_retryable_failure", False, False, True, True, True,
            "observed state is not eligible for automatic retry",
        )
    return result.to_json()


def converge_attention_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(records, list):
        raise TerminalConvergenceError("attention records must be a list")
    groups: dict[str, list[dict[str, Any]]] = {}
    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            raise TerminalConvergenceError(f"attention record {index} must be an object")
        task_id = raw.get("task_id")
        attempt = raw.get("attempt")
        outcome = raw.get("lifecycle_receipt_sha256")
        if not isinstance(task_id, str) or not task_id:
            raise TerminalConvergenceError(f"attention record {index} task_id is invalid")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise TerminalConvergenceError(f"attention record {index} attempt is invalid")
        if outcome is not None and (not isinstance(outcome, str) or len(outcome) != 64):
            raise TerminalConvergenceError(f"attention record {index} lifecycle receipt is invalid")
        updated_at = raw.get("updated_at_unix", 0)
        if isinstance(updated_at, bool) or not isinstance(updated_at, int) or updated_at < 0:
            raise TerminalConvergenceError(f"attention record {index} updated_at_unix is invalid")
        groups.setdefault(task_id, []).append(dict(raw))

    current: list[dict[str, Any]] = []
    historical: list[dict[str, Any]] = []
    for task_id in sorted(groups):
        ordered = sorted(
            groups[task_id],
            key=lambda item: (
                int(item["attempt"]),
                int(item.get("updated_at_unix") or 0),
                str(item.get("lifecycle_receipt_sha256") or ""),
            ),
        )
        winner = ordered[-1]
        current.append(winner)
        winner_binding = (winner["attempt"], winner.get("lifecycle_receipt_sha256"))
        seen_bindings: set[tuple[Any, Any]] = {winner_binding}
        for item in reversed(ordered[:-1]):
            binding = (item["attempt"], item.get("lifecycle_receipt_sha256"))
            if binding in seen_bindings:
                classification = "duplicate"
            elif int(item["attempt"]) < int(winner["attempt"]):
                classification = "superseded"
            else:
                classification = "already_satisfied"
            seen_bindings.add(binding)
            historical.append({**item, "convergence_classification": classification})
    return {
        "schema_version": SCHEMA_VERSION,
        "current": current,
        "historical": historical,
        "raw_count": len(records),
        "current_count": len(current),
        "converged_count": len(historical),
        "classification_counts": {
            name: sum(1 for item in historical if item["convergence_classification"] == name)
            for name in ("duplicate", "superseded", "already_satisfied")
        },
    }

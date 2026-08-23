from __future__ import annotations

from collections import Counter
import hashlib
import json
from typing import Any, Mapping

import grabowski_operator_obligation as obligations

SCHEMA_VERSION = 1
KIND = "grabowski.operator_obligation_evidence_assessment"
SAMPLE_KIND = "grabowski.operator_obligation_evidence_sample"
OBSERVATION_KIND = "grabowski.operator_obligation_evidence_observation"
CLASSIFICATIONS = (
    "verified",
    "unverified",
    "stale",
    "mismatch",
    "missing",
    "legacy_unverifiable",
    "unsupported",
)
OBSERVATION_STATUSES = frozenset({"verified", "stale", "mismatch", "unsupported"})
MIN_ROLLOUT_SAMPLE = 30
MAX_SAMPLE = 30


class EvidenceAssessmentError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceAssessmentError(f"{label} must be a non-empty string")
    return value.strip()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and obligations.SHA256_RE.fullmatch(value) is not None


def _observation_for(
    observations: Mapping[str, Mapping[str, Any]] | None,
    acceptance_id: str,
) -> Mapping[str, Any] | None:
    if observations is None:
        return None
    observation = observations.get(acceptance_id)
    if observation is None:
        return None
    if not isinstance(observation, Mapping):
        raise EvidenceAssessmentError("trusted observation must be a mapping")
    return observation


def _validate_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {
        "schema_version",
        "kind",
        "acceptance_id",
        "source",
        "reference",
        "sha256",
        "status",
    }
    unknown = set(observation) - allowed
    missing = allowed - set(observation)
    if unknown:
        raise EvidenceAssessmentError(
            f"trusted observation has unsupported fields: {sorted(unknown)}"
        )
    if missing:
        raise EvidenceAssessmentError(
            f"trusted observation is missing fields: {sorted(missing)}"
        )
    if observation.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceAssessmentError("trusted observation schema_version is invalid")
    if observation.get("kind") != OBSERVATION_KIND:
        raise EvidenceAssessmentError("trusted observation kind is invalid")
    status = _text(observation.get("status"), "trusted observation status")
    if status not in OBSERVATION_STATUSES:
        raise EvidenceAssessmentError("trusted observation status is invalid")
    sha256 = observation.get("sha256")
    if not _is_sha256(sha256):
        raise EvidenceAssessmentError("trusted observation sha256 is invalid")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": OBSERVATION_KIND,
        "acceptance_id": _text(
            observation.get("acceptance_id"), "trusted observation acceptance_id"
        ),
        "source": _text(observation.get("source"), "trusted observation source"),
        "reference": _text(
            observation.get("reference"), "trusted observation reference"
        ),
        "sha256": sha256,
        "status": status,
    }


def assess_evidence_item(
    evidence: Mapping[str, Any],
    *,
    observation: Mapping[str, Any] | None = None,
    legacy: bool = False,
) -> dict[str, Any]:
    """Classify one stored evidence item without granting completion authority.

    A stored SHA only proves that a string was supplied to the historical close
    contract.  It does not prove the referenced test, commit, PR, runtime, job,
    receipt, workspace, or Bureau state.  ``verified`` therefore requires a
    typed observation produced by a trusted internal adapter.  The public grip
    does not accept caller-authored observations.
    """

    if not isinstance(evidence, Mapping):
        raise EvidenceAssessmentError("evidence item must be a mapping")
    acceptance_id = _text(evidence.get("acceptance_id"), "acceptance_id")
    source = _text(evidence.get("source"), "source")
    reference = _text(evidence.get("reference"), "reference")
    status = _text(evidence.get("status"), "status")
    evidence_sha = evidence.get("sha256")

    base = {
        "acceptance_id": acceptance_id,
        "source": source,
        "reference": reference,
        "evidence_sha256": evidence_sha if isinstance(evidence_sha, str) else None,
    }
    if source not in obligations.EVIDENCE_SOURCES:
        return {
            **base,
            "classification": "unsupported",
            "reason": "unknown_evidence_source",
        }
    if status != "passed":
        return {
            **base,
            "classification": "mismatch",
            "reason": "stored_evidence_not_passed",
        }
    if not _is_sha256(evidence_sha):
        return {
            **base,
            "classification": "legacy_unverifiable" if legacy else "unverified",
            "reason": "missing_or_invalid_evidence_digest",
        }
    if source == "user":
        return {
            **base,
            "classification": "unsupported",
            "reason": "human_assertion_is_not_machine_verification",
        }
    if observation is None:
        return {
            **base,
            "classification": "legacy_unverifiable" if legacy else "unverified",
            "reason": "source_specific_observation_absent",
        }

    observed = _validate_observation(observation)
    if observed["acceptance_id"] != acceptance_id:
        return {
            **base,
            "classification": "mismatch",
            "reason": "observation_acceptance_mismatch",
        }
    if observed["source"] != source or observed["reference"] != reference:
        return {
            **base,
            "classification": "mismatch",
            "reason": "observation_identity_mismatch",
        }
    if observed["status"] == "unsupported":
        return {
            **base,
            "classification": "unsupported",
            "reason": "source_adapter_unsupported",
        }
    if observed["status"] == "stale":
        return {
            **base,
            "classification": "stale",
            "reason": "trusted_observation_stale",
        }
    if observed["status"] == "mismatch" or observed["sha256"] != evidence_sha:
        return {
            **base,
            "classification": "mismatch",
            "reason": "trusted_observation_digest_mismatch",
        }
    return {
        **base,
        "classification": "verified",
        "reason": "trusted_observation_matches",
    }


def _missing_acceptance(acceptance_id: str) -> dict[str, Any]:
    return {
        "acceptance_id": acceptance_id,
        "source": None,
        "reference": None,
        "evidence_sha256": None,
        "classification": "missing",
        "reason": "acceptance_evidence_missing",
    }


def assess_status(
    status: Mapping[str, Any],
    *,
    observations: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(status, Mapping):
        raise EvidenceAssessmentError("obligation status must be a mapping")
    obligation_id = _text(status.get("obligation_id"), "obligation_id")
    state = _text(status.get("state"), "state")
    open_file_sha256 = status.get("open_file_sha256")
    close_file_sha256 = status.get("close_file_sha256")
    if not _is_sha256(open_file_sha256):
        raise EvidenceAssessmentError("open_file_sha256 must bind the assessed open record")
    if state == "open":
        if close_file_sha256 is not None:
            raise EvidenceAssessmentError("open obligation must not have close_file_sha256")
    elif not _is_sha256(close_file_sha256):
        raise EvidenceAssessmentError("close_file_sha256 must bind the assessed terminal record")
    evidence = status.get("evidence")
    acceptance_ids = status.get("acceptance_ids")
    declared_missing = status.get("missing_acceptance_ids")
    if not isinstance(evidence, list):
        raise EvidenceAssessmentError("obligation evidence must be a list")
    if not isinstance(acceptance_ids, list) or any(
        not isinstance(item, str) or not item for item in acceptance_ids
    ):
        raise EvidenceAssessmentError("acceptance_ids must be a non-empty string list")
    if len(set(acceptance_ids)) != len(acceptance_ids):
        raise EvidenceAssessmentError("acceptance_ids must be unique")
    if not isinstance(declared_missing, list) or any(
        not isinstance(item, str) for item in declared_missing
    ):
        raise EvidenceAssessmentError("missing_acceptance_ids must be a string list")

    evidence_by_id: dict[str, Mapping[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, Mapping):
            raise EvidenceAssessmentError("obligation evidence item must be a mapping")
        acceptance_id = _text(item.get("acceptance_id"), "acceptance_id")
        if acceptance_id not in acceptance_ids:
            raise EvidenceAssessmentError("evidence references unknown acceptance id")
        if acceptance_id in evidence_by_id:
            raise EvidenceAssessmentError("duplicate evidence acceptance id")
        evidence_by_id[acceptance_id] = item

    computed_missing = [
        acceptance_id for acceptance_id in acceptance_ids if acceptance_id not in evidence_by_id
    ]
    if sorted(declared_missing) != sorted(computed_missing):
        raise EvidenceAssessmentError("missing_acceptance_ids disagrees with stored evidence")

    close_schema_version = status.get("close_schema_version")
    legacy = (
        state == "completed"
        and close_schema_version == obligations.LEGACY_CLOSE_SCHEMA_VERSION
    )
    assessed: list[dict[str, Any]] = []
    for acceptance_id in acceptance_ids:
        item = evidence_by_id.get(acceptance_id)
        if item is None:
            assessed.append(_missing_acceptance(acceptance_id))
            continue
        assessed.append(
            assess_evidence_item(
                item,
                observation=_observation_for(observations, acceptance_id),
                legacy=legacy,
            )
        )

    counts = Counter(item["classification"] for item in assessed)
    fully_verified = (
        state == "completed"
        and bool(acceptance_ids)
        and len(assessed) == len(acceptance_ids)
        and all(item["classification"] == "verified" for item in assessed)
    )
    declared_hash_bound = (
        state == "completed"
        and bool(acceptance_ids)
        and not computed_missing
        and len(evidence_by_id) == len(acceptance_ids)
        and all(
            item.get("status") == "passed" and _is_sha256(item.get("sha256"))
            for item in evidence_by_id.values()
        )
    )
    false_confidence_risk = declared_hash_bound and not fully_verified
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "obligation_id": obligation_id,
        "obligation_state": state,
        "close_schema_version": close_schema_version,
        "record_binding": {
            "open_file_sha256": open_file_sha256,
            "close_file_sha256": close_file_sha256,
        },
        "acceptance_count": len(acceptance_ids),
        "evidence_count": len(evidence_by_id),
        "missing_acceptance_ids": computed_missing,
        "classifications": {
            name: int(counts.get(name, 0)) for name in CLASSIFICATIONS
        },
        "acceptance": assessed,
        "fully_verified": fully_verified,
        "declared_hash_bound_completion": declared_hash_bound,
        "false_confidence_risk": false_confidence_risk,
        "legacy_close": legacy,
        "does_not_establish": [
            "operator obligation completion",
            "historical completion was incorrect",
            "source truth without a trusted source-specific observation",
            "merge readiness",
            "deployment correctness",
            "runtime correctness",
            "mutation authority",
        ],
    }
    result["assessment_sha256"] = _sha256(result)
    return result


def assess_obligation(obligation_id: str) -> dict[str, Any]:
    status = obligations.status_obligation(obligation_id)
    return assess_status(status)


def _completed_population() -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    """Read a bounded completed-obligation population from the existing truth owner."""

    root = obligations._state_root()
    try:
        obligations._ensure_private_directory(root, create=False)
    except FileNotFoundError:
        return [], [], False

    population: list[dict[str, Any]] = []
    integrity_errors: list[dict[str, str]] = []
    scanned = 0
    scan_truncated = False
    for child in sorted(root.iterdir(), key=lambda item: item.name):
        if child.name == ".lock":
            continue
        if scanned >= obligations.MAX_LIST_SCAN:
            scan_truncated = True
            break
        scanned += 1
        if obligations.OBLIGATION_ID_RE.fullmatch(child.name) is None:
            integrity_errors.append(
                {
                    "obligation_id": "invalid-name",
                    "error": "unexpected_state_root_entry",
                }
            )
            continue
        try:
            status = obligations.status_obligation(child.name)
        except (
            OSError,
            obligations.OperatorObligationError,
            obligations.OperatorObligationInputError,
        ) as exc:
            integrity_errors.append(
                {"obligation_id": child.name, "error": type(exc).__name__}
            )
            continue
        if status.get("state") != "completed":
            continue
        population.append(
            {
                "obligation_id": _text(
                    status.get("obligation_id"), "population obligation_id"
                ),
                "close_schema_version": status.get("close_schema_version"),
            }
        )
    return population, integrity_errors, scan_truncated


def _selection_rank(obligation_id: str) -> str:
    return _sha256(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski.operator_obligation_evidence_sample_selection_v1",
            "obligation_id": obligation_id,
        }
    )


def _rank_population(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            _selection_rank(str(item["obligation_id"])),
            str(item["obligation_id"]),
        ),
    )


def _select_sample_population(
    population: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    """Deterministically preserve current-schema visibility without claiming prevalence."""

    legacy = [
        item
        for item in population
        if item.get("close_schema_version") == obligations.LEGACY_CLOSE_SCHEMA_VERSION
    ]
    current = [
        item
        for item in population
        if item.get("close_schema_version") != obligations.LEGACY_CLOSE_SCHEMA_VERSION
    ]
    if current and legacy:
        current_target = min(len(current), max(1, limit // 2))
    else:
        current_target = min(len(current), limit)

    selected = _rank_population(current)[:current_target]
    remaining = limit - len(selected)
    selected.extend(_rank_population(legacy)[:remaining])
    remaining = limit - len(selected)
    if remaining:
        selected_ids = {str(item["obligation_id"]) for item in selected}
        extras = [
            item
            for item in population
            if str(item["obligation_id"]) not in selected_ids
        ]
        selected.extend(_rank_population(extras)[:remaining])
    return selected[:limit]


def sample_completed(limit: int = MIN_ROLLOUT_SAMPLE) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_SAMPLE:
        raise EvidenceAssessmentError(f"limit must be an integer from 1 to {MAX_SAMPLE}")

    population, integrity_errors, scan_truncated = _completed_population()
    selected = _select_sample_population(population, limit)
    obligation_ids = [str(item["obligation_id"]) for item in selected]
    assessments = [
        assess_status(obligations.status_obligation(obligation_id))
        for obligation_id in obligation_ids
    ]

    acceptance_total = sum(item["acceptance_count"] for item in assessments)
    classification_counts: Counter[str] = Counter()
    obligation_classification_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    missing_adapter_source_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    for assessment in assessments:
        seen_classes: set[str] = set()
        for item in assessment["acceptance"]:
            classification = item["classification"]
            classification_counts[classification] += 1
            seen_classes.add(classification)
            source = item.get("source")
            if isinstance(source, str):
                source_counts[source] += 1
                if (
                    classification in {"unverified", "legacy_unverifiable"}
                    and item["reason"] == "source_specific_observation_absent"
                ):
                    missing_adapter_source_counts[source] += 1
            reason_counts[item["reason"]] += 1
        for classification in seen_classes:
            obligation_classification_counts[classification] += 1

    fully_verified = sum(1 for item in assessments if item["fully_verified"])
    false_confidence_risk = sum(
        1 for item in assessments if item["false_confidence_risk"]
    )
    acceptance_verified = int(classification_counts.get("verified", 0))
    if integrity_errors or scan_truncated:
        signal = "inconclusive_population_integrity"
    elif len(assessments) < MIN_ROLLOUT_SAMPLE:
        signal = "inconclusive_sample_too_small"
    elif fully_verified == len(assessments):
        signal = "fully_verifiable_sample"
    else:
        signal = "verifiability_gap_observed"

    population_schema_counts = Counter(
        str(item.get("close_schema_version")) for item in population
    )
    sample_schema_counts = Counter(
        str(item.get("close_schema_version")) for item in selected
    )
    population_binding = sorted(
        (
            {
                "obligation_id": str(item["obligation_id"]),
                "close_schema_version": item.get("close_schema_version"),
            }
            for item in population
        ),
        key=lambda item: item["obligation_id"],
    )
    summary = {
        "total": len(assessments),
        **{
            name: int(classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "acceptance_total": acceptance_total,
        "acceptance_verified": acceptance_verified,
        "obligations_fully_verified": fully_verified,
        "obligations_with_false_confidence_risk": false_confidence_risk,
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": SAMPLE_KIND,
        "requested_limit": limit,
        "sample_size": len(assessments),
        "minimum_sample": MIN_ROLLOUT_SAMPLE,
        "maximum_sample": MAX_SAMPLE,
        "population_completed_total": len(population),
        "population_close_schema_counts": dict(sorted(population_schema_counts.items())),
        "sample_close_schema_counts": dict(sorted(sample_schema_counts.items())),
        "selection_order": "schema_stratified_sha256_rank_v1",
        "selection_obligation_ids": obligation_ids,
        "selection_sha256": _sha256(obligation_ids),
        "selection_population_sha256": _sha256(population_binding),
        "selection_scan_truncated": scan_truncated,
        "selection_integrity_errors": integrity_errors,
        "summary": summary,
        "acceptance_classification_counts": {
            name: int(classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "obligation_classification_counts": {
            name: int(obligation_classification_counts.get(name, 0))
            for name in CLASSIFICATIONS
        },
        "source_counts": dict(sorted(source_counts.items())),
        "missing_adapter_source_counts": dict(
            sorted(missing_adapter_source_counts.items())
        ),
        "reason_counts": dict(sorted(reason_counts.items())),
        "trusted_observation_adapter_sources": [],
        "shadow_signal": signal,
        "records": [
            {
                "obligation_id": item["obligation_id"],
                "record_binding": item["record_binding"],
                "acceptance_count": item["acceptance_count"],
                "classifications": item["classifications"],
                "fully_verified": item["fully_verified"],
                "declared_hash_bound_completion": item[
                    "declared_hash_bound_completion"
                ],
                "false_confidence_risk": item["false_confidence_risk"],
                "legacy_close": item["legacy_close"],
                "assessment_sha256": item["assessment_sha256"],
            }
            for item in assessments
        ],
        "does_not_establish": [
            "historical completion was incorrect",
            "a false DONE occurred",
            "sample proportions estimate population prevalence",
            "causality",
            "permission to enforce verified completion",
            "permission to rewrite legacy obligation records",
            "mutation authority",
        ],
    }
    result["sample_sha256"] = _sha256(result)
    return result

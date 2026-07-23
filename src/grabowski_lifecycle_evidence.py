from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import grabowski_lifecycle_archive as lifecycle


SCHEMA_VERSION = 2
REQUIRED_SOURCES = frozenset(
    {"task", "workspace", "lease", "checkout", "process", "tmux", "receipt"}
)
SOURCE_APPLICABILITY_SCHEMA_VERSION = 1
SOURCE_APPLICABILITY_STATES = frozenset(
    {"observed", "explicit_absence", "not_applicable"}
)
READBACK_SOURCE_APPLICABILITY_STATES = frozenset(
    {"observed", "explicit_absence"}
)
SOURCE_APPLICABILITY_PROFILE_FULL_READBACK_V1 = "full_readback.v1"
SOURCE_APPLICABILITY_PROFILE_TASK_ARCHIVE_V1 = "task_archive.v1"
SOURCE_APPLICABILITY_PROFILES = {
    SOURCE_APPLICABILITY_PROFILE_FULL_READBACK_V1: {
        "kinds": None,
        "not_applicable_sources": frozenset(),
    },
    SOURCE_APPLICABILITY_PROFILE_TASK_ARCHIVE_V1: {
        "kinds": frozenset({"task"}),
        "not_applicable_sources": frozenset({"workspace", "checkout", "tmux"}),
    },
}


def source_applicability_profile_policy(profile: Any, *, kind: str) -> dict[str, str]:
    if not isinstance(profile, str) or not profile:
        raise ValueError("source_applicability_profile_invalid")
    spec = SOURCE_APPLICABILITY_PROFILES.get(profile)
    if spec is None:
        raise ValueError("source_applicability_profile_unknown")
    kinds = spec["kinds"]
    if kinds is not None and kind not in kinds:
        raise ValueError("source_applicability_profile_kind_invalid")
    not_applicable_sources = spec["not_applicable_sources"]
    return {
        source: (
            "not_applicable"
            if source in not_applicable_sources
            else "readback_required"
        )
        for source in sorted(REQUIRED_SOURCES)
    }


@dataclass(frozen=True)
class LifecycleObservationBundle:
    """Normalized current observations from the typed operator surfaces.

    ``observed_sources`` contains only sources for which an actual readback was
    performed, including a readback that proves explicit absence.
    ``source_applicability`` distinguishes an observed object, explicit absence,
    and a source that is formally not applicable under the canonical
    ``source_applicability_profile``. Every required source remains digest-bound.
    Missing, unknown, contradictory, profile-foreign, or schema-foreign
    applicability fails closed.
    """

    identity: str
    kind: str
    observed_sources: frozenset[str]
    source_sha256s: Mapping[str, str]
    source_applicability: Mapping[str, str]
    source_applicability_profile: str = SOURCE_APPLICABILITY_PROFILE_FULL_READBACK_V1
    source_applicability_schema_version: int = SOURCE_APPLICABILITY_SCHEMA_VERSION
    state: str | None = None
    closed: bool | None = None
    archived: bool = False
    dirty: bool | None = False
    active_task: bool | None = False
    active_process: bool | None = False
    active_lease: bool | None = False
    foreign_retention: bool | None = False
    retention_expired: bool | None = False
    retention_recovery_archived: bool | None = False
    shared_reference: bool | None = False
    open_task_role: bool | None = False
    tmux_session_present: bool | None = False
    tmux_role_bound: bool | None = False
    receipt_integrity_valid: bool | None = True
    source_errors: tuple[str, ...] = ()


def _source_errors(bundle: LifecycleObservationBundle) -> list[str]:
    errors = [f"source_error:{value}" for value in bundle.source_errors]
    observed_sources = set(bundle.observed_sources)
    unknown_sources = sorted(
        source
        for source in observed_sources
        if isinstance(source, str) and source not in REQUIRED_SOURCES
    )
    errors.extend(f"source_unknown:{source}" for source in unknown_sources)
    if any(not isinstance(source, str) for source in observed_sources):
        errors.append("source_unknown_key_type")

    version = bundle.source_applicability_schema_version
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != SOURCE_APPLICABILITY_SCHEMA_VERSION
    ):
        errors.append("source_applicability_schema_unsupported")

    try:
        profile_policy = source_applicability_profile_policy(
            bundle.source_applicability_profile,
            kind=bundle.kind,
        )
    except ValueError as exc:
        errors.append(str(exc))
        profile_policy = None

    applicability = bundle.source_applicability
    if not isinstance(applicability, Mapping):
        errors.append("source_applicability_invalid")
        applicability = {}
    unknown_applicability_sources = sorted(
        source
        for source in applicability
        if isinstance(source, str) and source not in REQUIRED_SOURCES
    )
    errors.extend(
        f"source_applicability_unknown:{source}"
        for source in unknown_applicability_sources
    )
    if any(not isinstance(source, str) for source in applicability):
        errors.append("source_applicability_unknown_key_type")
    for source in sorted(REQUIRED_SOURCES):
        if source not in applicability:
            errors.append(f"source_applicability_missing:{source}")
            if source not in observed_sources:
                errors.append(f"source_unobserved:{source}")
            continue
        state = applicability[source]
        if not isinstance(state, str) or state not in SOURCE_APPLICABILITY_STATES:
            errors.append(f"source_applicability_invalid:{source}")
            continue
        if profile_policy is not None:
            expected = profile_policy[source]
            if expected == "not_applicable" and state != "not_applicable":
                errors.append(
                    f"source_applicability_profile_mismatch:{source}:expected_not_applicable"
                )
            if expected == "readback_required" and state == "not_applicable":
                errors.append(
                    f"source_applicability_profile_mismatch:{source}:expected_readback"
                )
        if state in READBACK_SOURCE_APPLICABILITY_STATES and source not in observed_sources:
            errors.append(f"source_unobserved:{source}")
        if state == "not_applicable" and source in observed_sources:
            errors.append(
                f"source_applicability_contradiction:{source}:not_applicable"
            )

    source_sha256s = bundle.source_sha256s
    if not isinstance(source_sha256s, Mapping):
        errors.append("source_digest_mapping_invalid")
        source_sha256s = {}
    unknown_digest_sources = sorted(
        source
        for source in source_sha256s
        if isinstance(source, str) and source not in REQUIRED_SOURCES
    )
    errors.extend(f"source_digest_unknown:{source}" for source in unknown_digest_sources)
    if any(not isinstance(source, str) for source in source_sha256s):
        errors.append("source_digest_unknown_key_type")
    for source in sorted(REQUIRED_SOURCES):
        digest = source_sha256s.get(source)
        if not isinstance(digest, str) or lifecycle.SHA256.fullmatch(digest) is None:
            errors.append(f"source_unbound:{source}")
    return errors


def _retention_state(bundle: LifecycleObservationBundle) -> tuple[bool | None, bool | None]:
    """Return effective foreign-retention block and recovery requirement."""
    values = (
        bundle.foreign_retention,
        bundle.retention_expired,
        bundle.retention_recovery_archived,
    )
    if any(value is None for value in values):
        return None, None
    foreign = bool(bundle.foreign_retention)
    expired = bool(bundle.retention_expired)
    recovery_archived = bool(bundle.retention_recovery_archived)
    if not foreign:
        return False, False
    if not expired:
        return True, False
    return False, not recovery_archived


def _tmux_session_only(bundle: LifecycleObservationBundle) -> bool | None:
    values = (
        bundle.tmux_session_present,
        bundle.tmux_role_bound,
        bundle.active_process,
        bundle.open_task_role,
    )
    if any(value is None for value in values):
        return None
    return bool(
        bundle.tmux_session_present
        and not bundle.tmux_role_bound
        and not bundle.active_process
        and not bundle.open_task_role
    )


def normalized_evidence(bundle: LifecycleObservationBundle) -> dict[str, Any]:
    if not bundle.identity:
        raise ValueError("identity must not be empty")
    if not bundle.kind:
        raise ValueError("kind must not be empty")

    effective_foreign_retention, retention_recovery_required = _retention_state(bundle)
    tmux_session_only = _tmux_session_only(bundle)
    errors = _source_errors(bundle)
    evidence = lifecycle.LifecycleEvidence(
        identity=bundle.identity,
        kind=bundle.kind,
        state=bundle.state,
        closed=bundle.closed,
        archived=bundle.archived,
        dirty=bundle.dirty,
        active_task=bundle.active_task,
        active_process=bundle.active_process,
        active_lease=bundle.active_lease,
        foreign_retention=effective_foreign_retention,
        shared_reference=bundle.shared_reference,
        open_task_role=bundle.open_task_role,
        retention_recovery_required=retention_recovery_required,
        tmux_session_only=tmux_session_only,
        receipt_integrity_valid=bundle.receipt_integrity_valid,
        observation_errors=tuple(errors),
    )
    source_sha256s = {
        source: bundle.source_sha256s[source]
        for source in sorted(REQUIRED_SOURCES)
        if isinstance(bundle.source_sha256s, Mapping)
        and isinstance(bundle.source_sha256s.get(source), str)
    }
    source_applicability = {
        source: bundle.source_applicability[source]
        for source in sorted(REQUIRED_SOURCES)
        if isinstance(bundle.source_applicability, Mapping)
        and isinstance(bundle.source_applicability.get(source), str)
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_lifecycle_evidence_snapshot",
        "identity": bundle.identity,
        "lifecycle_kind": bundle.kind,
        "observed_sources": sorted(bundle.observed_sources),
        "required_sources": sorted(REQUIRED_SOURCES),
        "source_applicability_schema_version": bundle.source_applicability_schema_version,
        "source_applicability_profile": (
            bundle.source_applicability_profile
            if isinstance(bundle.source_applicability_profile, str)
            else None
        ),
        "source_applicability": source_applicability,
        "source_sha256s": source_sha256s,
        "source_errors": list(bundle.source_errors),
        "state": bundle.state,
        "closed": bundle.closed,
        "archived": bundle.archived,
        "dirty": bundle.dirty,
        "active_task": bundle.active_task,
        "active_process": bundle.active_process,
        "active_lease": bundle.active_lease,
        "foreign_retention": bundle.foreign_retention,
        "retention_expired": bundle.retention_expired,
        "retention_recovery_archived": bundle.retention_recovery_archived,
        "effective_foreign_retention": effective_foreign_retention,
        "retention_recovery_required": retention_recovery_required,
        "shared_reference": bundle.shared_reference,
        "open_task_role": bundle.open_task_role,
        "tmux_session_present": bundle.tmux_session_present,
        "tmux_role_bound": bundle.tmux_role_bound,
        "tmux_session_only": tmux_session_only,
        "receipt_integrity_valid": bundle.receipt_integrity_valid,
        "normalization_errors": errors,
        "does_not_establish": [
            "cleanup_authority_from_source_presence_alone",
            "absence_of_future_activity",
            "permission_to_override_foreign_retention",
            "physical_deletion_authority",
        ],
    }
    return {
        **body,
        "evidence_sha256": lifecycle.sha256_json(body),
        "lifecycle_evidence": evidence,
    }


def classify_observation_bundle(bundle: LifecycleObservationBundle) -> dict[str, Any]:
    normalized = normalized_evidence(bundle)
    classification = lifecycle.classify_lifecycle(normalized["lifecycle_evidence"])
    public_snapshot = {
        key: value
        for key, value in normalized.items()
        if key != "lifecycle_evidence"
    }
    return {
        **classification,
        "evidence_sha256": public_snapshot["evidence_sha256"],
        "evidence": public_snapshot,
    }

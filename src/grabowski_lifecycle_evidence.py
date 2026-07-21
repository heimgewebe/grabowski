from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import grabowski_lifecycle_archive as lifecycle


SCHEMA_VERSION = 1
REQUIRED_SOURCES = frozenset(
    {"task", "workspace", "lease", "checkout", "process", "tmux", "receipt"}
)


@dataclass(frozen=True)
class LifecycleObservationBundle:
    """Normalized current observations from the typed operator surfaces.

    ``observed_sources`` means the source was actively checked for this object,
    including the explicit observation that no matching live object exists.
    ``source_sha256s`` binds each checked source payload after the caller has
    normalized/redacted it. Missing source checks or digests fail closed.
    """

    identity: str
    kind: str
    observed_sources: frozenset[str]
    source_sha256s: Mapping[str, str]
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
    unknown_sources = sorted(set(bundle.observed_sources) - REQUIRED_SOURCES)
    errors.extend(f"source_unknown:{source}" for source in unknown_sources)
    for source in sorted(REQUIRED_SOURCES - set(bundle.observed_sources)):
        errors.append(f"source_unobserved:{source}")
    for source in sorted(REQUIRED_SOURCES & set(bundle.observed_sources)):
        digest = bundle.source_sha256s.get(source)
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
        for source in sorted(bundle.source_sha256s)
        if source in REQUIRED_SOURCES and source in bundle.observed_sources
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_lifecycle_evidence_snapshot",
        "identity": bundle.identity,
        "lifecycle_kind": bundle.kind,
        "observed_sources": sorted(bundle.observed_sources),
        "required_sources": sorted(REQUIRED_SOURCES),
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

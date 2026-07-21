from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

import grabowski_lifecycle_archive as lifecycle
import grabowski_lifecycle_evidence as lifecycle_evidence


SCHEMA_VERSION = 1
EFFECT_KINDS = frozenset(
    {
        "task_archive",
        "workspace_archive",
        "retention_converge",
        "current_projection_switch",
    }
)
ARCHIVE_EFFECT_KINDS = frozenset(
    {"task_archive", "workspace_archive", "retention_converge"}
)
PLAN_DOES_NOT_ESTABLISH = [
    "effect_execution",
    "physical_deletion_authority",
    "source_state_unchanged_after_planning",
    "lease_ownership_after_planning",
    "permission_to_override_foreign_ownership",
]
PLAN_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "effect_kind",
        "created_at_unix",
        "lease_owner_id",
        "required_resource_keys",
        "entries",
        "mutation_performed",
        "requires_immediate_revalidation",
        "does_not_establish",
        "plan_sha256",
    }
)
PLAN_ENTRY_KEYS = frozenset(
    {
        "identity",
        "lifecycle_kind",
        "classification",
        "evidence_sha256",
        "source_sha256s",
    }
)


class LifecycleEffectPlanError(RuntimeError):
    pass


class LifecycleEffectPlanIntegrityError(LifecycleEffectPlanError):
    pass


@dataclass(frozen=True)
class LeaseObservation:
    resource_key: str
    owner_id: str
    expires_at_unix: int
    metadata_sha256: str


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or lifecycle.SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _normalize_resource_keys(values: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for index, raw in enumerate(values):
        value = _validate_string(raw, label=f"required_resource_keys[{index}]")
        if not any(
            value.startswith(prefix)
            for prefix in (
                "path:",
                "component:",
                "repo:",
                "service:",
                "gate:",
                "deployment:",
            )
        ):
            raise ValueError(
                f"required_resource_keys[{index}] is not a typed resource key"
            )
        if value.startswith("repo:") and not any(
            marker in value for marker in (":branch:", ":operation:")
        ):
            raise ValueError(
                f"required_resource_keys[{index}] must not be a broad repository lease"
            )
        normalized.append(value)
    if not normalized:
        raise ValueError("required_resource_keys must not be empty")
    if len(normalized) != len(set(normalized)):
        raise ValueError("required_resource_keys must not contain duplicates")
    return sorted(normalized)


def _expected_classification(effect_kind: str) -> str:
    if effect_kind in ARCHIVE_EFFECT_KINDS:
        return "terminal_archivable"
    return "archived"


def _normalize_source_sha256s(value: Any, *, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{label} must be a non-empty source digest mapping")
    normalized: dict[str, str] = {}
    for source, digest in value.items():
        key = _validate_string(source, label=f"{label}.source")
        normalized[key] = _validate_sha256(digest, label=f"{label}.{key}")
    return dict(sorted(normalized.items()))


def _reclassify_evidence_snapshot(evidence: Mapping[str, Any]) -> dict[str, Any]:
    try:
        bundle = lifecycle_evidence.LifecycleObservationBundle(
            identity=evidence["identity"],
            kind=evidence["lifecycle_kind"],
            observed_sources=frozenset(evidence["observed_sources"]),
            source_sha256s=evidence["source_sha256s"],
            state=evidence["state"],
            closed=evidence["closed"],
            archived=evidence["archived"],
            dirty=evidence["dirty"],
            active_task=evidence["active_task"],
            active_process=evidence["active_process"],
            active_lease=evidence["active_lease"],
            foreign_retention=evidence["foreign_retention"],
            retention_expired=evidence["retention_expired"],
            retention_recovery_archived=evidence["retention_recovery_archived"],
            shared_reference=evidence["shared_reference"],
            open_task_role=evidence["open_task_role"],
            tmux_session_present=evidence["tmux_session_present"],
            tmux_role_bound=evidence["tmux_role_bound"],
            receipt_integrity_valid=evidence["receipt_integrity_valid"],
            source_errors=tuple(evidence["source_errors"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise LifecycleEffectPlanIntegrityError(
            "classification evidence snapshot cannot be reconstructed"
        ) from exc
    reclassified = lifecycle_evidence.classify_observation_bundle(bundle)
    if reclassified["evidence"] != dict(evidence):
        raise LifecycleEffectPlanIntegrityError(
            "classification evidence snapshot integrity mismatch"
        )
    return reclassified


def _normalize_classification(
    raw: Mapping[str, Any],
    *,
    effect_kind: str,
) -> dict[str, Any]:
    evidence = raw.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("classification.evidence must be an object")
    reclassified = _reclassify_evidence_snapshot(evidence)
    identity = _validate_string(
        reclassified.get("identity"), label="classification.identity"
    )
    lifecycle_kind = _validate_string(
        reclassified.get("kind"), label=f"classification[{identity}].kind"
    )
    if raw.get("identity") != identity or raw.get("kind") != lifecycle_kind:
        raise LifecycleEffectPlanIntegrityError(
            f"classification identity or kind does not match evidence for {identity}"
        )
    if raw.get("evidence_sha256") != reclassified.get("evidence_sha256"):
        raise LifecycleEffectPlanIntegrityError(
            f"classification evidence digest does not match evidence for {identity}"
        )
    if raw.get("classification") != reclassified.get("classification"):
        raise LifecycleEffectPlanIntegrityError(
            f"classification verdict does not match evidence for {identity}"
        )
    if raw.get("safe_to_archive") is not reclassified.get("safe_to_archive"):
        raise LifecycleEffectPlanIntegrityError(
            f"classification archive eligibility does not match evidence for {identity}"
        )
    classification = reclassified["classification"]
    expected = _expected_classification(effect_kind)
    if classification != expected:
        raise LifecycleEffectPlanError(
            f"{identity} classification {classification!r} is not eligible for {effect_kind}; expected {expected}"
        )
    if effect_kind in ARCHIVE_EFFECT_KINDS and reclassified["safe_to_archive"] is not True:
        raise LifecycleEffectPlanError(
            f"{identity} is not explicitly safe_to_archive"
        )
    normalization_errors = evidence.get("normalization_errors")
    if not isinstance(normalization_errors, list):
        raise ValueError(
            f"classification[{identity}].evidence.normalization_errors must be a list"
        )
    if normalization_errors:
        raise LifecycleEffectPlanError(
            f"{identity} has unresolved evidence normalization errors"
        )
    evidence_sha256 = _validate_sha256(
        reclassified.get("evidence_sha256"),
        label=f"classification[{identity}].evidence_sha256",
    )
    source_sha256s = _normalize_source_sha256s(
        evidence.get("source_sha256s"),
        label=f"classification[{identity}].evidence.source_sha256s",
    )
    return {
        "identity": identity,
        "lifecycle_kind": lifecycle_kind,
        "classification": classification,
        "evidence_sha256": evidence_sha256,
        "source_sha256s": source_sha256s,
    }


def build_effect_plan(
    classifications: Iterable[Mapping[str, Any]],
    *,
    effect_kind: str,
    lease_owner_id: str,
    required_resource_keys: Iterable[str],
    created_at_unix: int,
) -> dict[str, Any]:
    if effect_kind not in EFFECT_KINDS:
        raise ValueError(f"effect_kind must be one of {sorted(EFFECT_KINDS)}")
    owner = _validate_string(lease_owner_id, label="lease_owner_id")
    if not isinstance(created_at_unix, int) or isinstance(created_at_unix, bool):
        raise ValueError("created_at_unix must be an integer")
    resources = _normalize_resource_keys(required_resource_keys)
    entries = [
        _normalize_classification(raw, effect_kind=effect_kind)
        for raw in classifications
    ]
    if not entries:
        raise ValueError("classifications must not be empty")
    entries.sort(key=lambda item: (item["lifecycle_kind"], item["identity"]))
    identities = [item["identity"] for item in entries]
    if len(identities) != len(set(identities)):
        raise ValueError("classifications must not contain duplicate identities")

    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_lifecycle_effect_plan",
        "effect_kind": effect_kind,
        "created_at_unix": created_at_unix,
        "lease_owner_id": owner,
        "required_resource_keys": resources,
        "entries": entries,
        "mutation_performed": False,
        "requires_immediate_revalidation": True,
        "does_not_establish": list(PLAN_DOES_NOT_ESTABLISH),
    }
    return {**body, "plan_sha256": sha256_json(body)}


def _validate_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(plan)
    if set(value) != PLAN_KEYS:
        raise LifecycleEffectPlanIntegrityError("effect plan fields are not exact")
    expected_digest = value.get("plan_sha256")
    _validate_sha256(expected_digest, label="plan.plan_sha256")
    body = {key: item for key, item in value.items() if key != "plan_sha256"}
    if sha256_json(body) != expected_digest:
        raise LifecycleEffectPlanIntegrityError("effect plan digest mismatch")
    if body.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleEffectPlanIntegrityError("unsupported effect plan schema")
    if body.get("kind") != "grabowski_lifecycle_effect_plan":
        raise LifecycleEffectPlanIntegrityError("effect plan kind mismatch")
    effect_kind = body.get("effect_kind")
    if effect_kind not in EFFECT_KINDS:
        raise LifecycleEffectPlanIntegrityError("effect plan effect_kind is invalid")
    _validate_string(body.get("lease_owner_id"), label="plan.lease_owner_id")
    created_at_unix = body.get("created_at_unix")
    if not isinstance(created_at_unix, int) or isinstance(created_at_unix, bool):
        raise LifecycleEffectPlanIntegrityError("effect plan created_at_unix is invalid")
    if body.get("mutation_performed") is not False:
        raise LifecycleEffectPlanIntegrityError("effect plan may not claim mutation")
    if body.get("requires_immediate_revalidation") is not True:
        raise LifecycleEffectPlanIntegrityError(
            "effect plan must require immediate revalidation"
        )
    if body.get("does_not_establish") != PLAN_DOES_NOT_ESTABLISH:
        raise LifecycleEffectPlanIntegrityError(
            "effect plan safety non-claims are invalid"
        )
    raw_resources = body.get("required_resource_keys")
    if not isinstance(raw_resources, list):
        raise LifecycleEffectPlanIntegrityError(
            "effect plan required_resource_keys must be a list"
        )
    if _normalize_resource_keys(raw_resources) != raw_resources:
        raise LifecycleEffectPlanIntegrityError(
            "effect plan required_resource_keys are not canonical"
        )
    entries = body.get("entries")
    if not isinstance(entries, list) or not entries:
        raise LifecycleEffectPlanIntegrityError("effect plan entries are missing")
    normalized_entries: list[dict[str, Any]] = []
    for raw in entries:
        if not isinstance(raw, Mapping):
            raise LifecycleEffectPlanIntegrityError("effect plan entry is invalid")
        if set(raw) != PLAN_ENTRY_KEYS:
            raise LifecycleEffectPlanIntegrityError(
                "effect plan entry fields are not exact"
            )
        identity = _validate_string(raw.get("identity"), label="plan.entry.identity")
        lifecycle_kind = _validate_string(
            raw.get("lifecycle_kind"), label=f"plan.entry[{identity}].lifecycle_kind"
        )
        classification = raw.get("classification")
        if classification != _expected_classification(effect_kind):
            raise LifecycleEffectPlanIntegrityError(
                f"effect plan entry classification drift for {identity}"
            )
        evidence_sha256 = _validate_sha256(
            raw.get("evidence_sha256"), label=f"plan.entry[{identity}].evidence_sha256"
        )
        source_sha256s = _normalize_source_sha256s(
            raw.get("source_sha256s"), label=f"plan.entry[{identity}].source_sha256s"
        )
        normalized_entry = {
            "identity": identity,
            "lifecycle_kind": lifecycle_kind,
            "classification": classification,
            "evidence_sha256": evidence_sha256,
            "source_sha256s": source_sha256s,
        }
        if normalized_entry != dict(raw):
            raise LifecycleEffectPlanIntegrityError(
                f"effect plan entry is not canonical for {identity}"
            )
        normalized_entries.append(normalized_entry)
    if normalized_entries != sorted(
        normalized_entries, key=lambda item: (item["lifecycle_kind"], item["identity"])
    ):
        raise LifecycleEffectPlanIntegrityError("effect plan entries are not canonical")
    if len({item["identity"] for item in normalized_entries}) != len(normalized_entries):
        raise LifecycleEffectPlanIntegrityError("effect plan contains duplicate identities")
    return value


def _write_create_only(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_effect_plan(plan: Mapping[str, Any], *, plan_root: Path) -> dict[str, Any]:
    value = _validate_plan(plan)
    if plan_root.is_symlink():
        raise LifecycleEffectPlanIntegrityError("effect plan root may not be a symlink")
    plan_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if plan_root.is_symlink() or not plan_root.is_dir():
        raise LifecycleEffectPlanIntegrityError("effect plan root must be a regular directory")
    os.chmod(plan_root, 0o700)
    plan_path = plan_root / f"plan-{value['plan_sha256']}.json"
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8") + b"\n"
    if plan_path.exists():
        verified = verify_effect_plan(plan_path)
        if verified["plan"] != value:
            raise LifecycleEffectPlanIntegrityError(
                "existing effect plan conflicts with requested plan"
            )
        return {**verified, "idempotent_replay": True}
    _write_create_only(plan_path, payload)
    _fsync_directory(plan_root)
    verified = verify_effect_plan(plan_path)
    return {**verified, "idempotent_replay": False}


def verify_effect_plan(plan_path: Path) -> dict[str, Any]:
    if plan_path.is_symlink() or not plan_path.is_file():
        raise LifecycleEffectPlanIntegrityError(
            "effect plan path must be a regular non-symlink file"
        )
    try:
        value = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleEffectPlanIntegrityError("effect plan JSON is invalid") from exc
    if not isinstance(value, Mapping):
        raise LifecycleEffectPlanIntegrityError("effect plan must be a JSON object")
    plan = _validate_plan(value)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "verified",
        "plan_path": str(plan_path),
        "plan": plan,
    }


def _normalize_lease_observation(
    raw: LeaseObservation | Mapping[str, Any],
) -> LeaseObservation:
    if isinstance(raw, LeaseObservation):
        observation = raw
    elif isinstance(raw, Mapping):
        observation = LeaseObservation(
            resource_key=_validate_string(
                raw.get("resource_key"), label="lease.resource_key"
            ),
            owner_id=_validate_string(raw.get("owner_id"), label="lease.owner_id"),
            expires_at_unix=raw.get("expires_at_unix"),
            metadata_sha256=_validate_sha256(
                raw.get("metadata_sha256"), label="lease.metadata_sha256"
            ),
        )
    else:
        raise ValueError("lease observation must be an object")
    _validate_string(observation.resource_key, label="lease.resource_key")
    _normalize_resource_keys([observation.resource_key])
    _validate_string(observation.owner_id, label="lease.owner_id")
    if not isinstance(observation.expires_at_unix, int) or isinstance(
        observation.expires_at_unix, bool
    ):
        raise ValueError("lease.expires_at_unix must be an integer")
    _validate_sha256(observation.metadata_sha256, label="lease.metadata_sha256")
    return observation


def revalidate_effect_plan(
    plan: Mapping[str, Any],
    current_classifications: Mapping[str, Mapping[str, Any]],
    lease_observations: Iterable[LeaseObservation | Mapping[str, Any]],
    *,
    now_unix: int,
) -> dict[str, Any]:
    value = _validate_plan(plan)
    if not isinstance(now_unix, int) or isinstance(now_unix, bool):
        raise ValueError("now_unix must be an integer")
    effect_kind = value["effect_kind"]
    errors: list[str] = []
    current_bindings: list[dict[str, Any]] = []

    for expected in value["entries"]:
        identity = expected["identity"]
        current = current_classifications.get(identity)
        if not isinstance(current, Mapping):
            errors.append(f"current_classification_missing:{identity}")
            continue
        try:
            normalized = _normalize_classification(current, effect_kind=effect_kind)
        except (ValueError, LifecycleEffectPlanError) as exc:
            errors.append(f"current_classification_invalid:{identity}:{type(exc).__name__}")
            continue
        current_bindings.append(normalized)
        if normalized["lifecycle_kind"] != expected["lifecycle_kind"]:
            errors.append(f"lifecycle_kind_drift:{identity}")
        if normalized["classification"] != expected["classification"]:
            errors.append(f"classification_drift:{identity}")
        if normalized["evidence_sha256"] != expected["evidence_sha256"]:
            errors.append(f"evidence_drift:{identity}")
        if normalized["source_sha256s"] != expected["source_sha256s"]:
            errors.append(f"source_digest_drift:{identity}")

    observations: dict[str, LeaseObservation] = {}
    for raw in lease_observations:
        observation = _normalize_lease_observation(raw)
        if observation.resource_key in observations:
            errors.append(f"duplicate_lease_observation:{observation.resource_key}")
            continue
        observations[observation.resource_key] = observation

    owner = value["lease_owner_id"]
    lease_bindings: list[dict[str, Any]] = []
    for resource_key in value["required_resource_keys"]:
        observation = observations.get(resource_key)
        if observation is None:
            errors.append(f"required_lease_missing:{resource_key}")
            continue
        lease_bindings.append(
            {
                "resource_key": observation.resource_key,
                "owner_id": observation.owner_id,
                "expires_at_unix": observation.expires_at_unix,
                "metadata_sha256": observation.metadata_sha256,
            }
        )
        if observation.owner_id != owner:
            errors.append(f"required_lease_foreign_owner:{resource_key}")
        if observation.expires_at_unix <= now_unix:
            errors.append(f"required_lease_expired:{resource_key}")

    current_bindings.sort(key=lambda item: (item["lifecycle_kind"], item["identity"]))
    lease_bindings.sort(key=lambda item: item["resource_key"])
    revalidation_body = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_lifecycle_effect_revalidation",
        "plan_sha256": value["plan_sha256"],
        "now_unix": now_unix,
        "current_bindings": current_bindings,
        "lease_bindings": lease_bindings,
        "errors": sorted(set(errors)),
        "ready_for_effect": not errors,
        "mutation_performed": False,
        "does_not_establish": [
            "effect_execution",
            "physical_deletion_authority",
            "continued_lease_validity_after_revalidation",
            "source_state_unchanged_after_revalidation",
        ],
    }
    return {
        **revalidation_body,
        "revalidation_sha256": sha256_json(revalidation_body),
    }

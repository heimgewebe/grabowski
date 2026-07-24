#!/usr/bin/env python3
"""Create one proposal-only operator-routing shadow record.

This tool never changes routing, policy, queue, merge or runtime state. It reads one
Agent Workspace manifest, reuses Grabowski's canonical route-evidence validator,
binds exactly one referenced task to a separately supplied semantic outcome or
explicit abstention, and writes one create-only JSON record.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_workspace as workspace  # noqa: E402

SCHEMA_VERSION = "operator-routing-shadow-record.v1"
ELIGIBILITY_SCHEMA_VERSION = "operator-routing-shadow-eligibility.v1"
TASK_ID_RE = re.compile(r"^[0-9a-f]{24}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_PREFIXES = (
    "github-ci:",
    "diff-review:",
    "operator-decision:",
    "chronik:",
    "artifact:",
)
REVIEW_AUTHORITIES = {
    "diff_bound_review",
    "operator_decision",
    "ci_and_review",
    "bounded_chronik_evidence",
}
OUTCOME_KINDS = {"task_correctness", "decision_quality"}
OUTCOME_LABELS = {"success", "partial", "failure"}
ABSTENTION_REASONS = {
    "no_semantic_review",
    "non_semantic_task",
    "insufficient_primary_evidence",
    "ambiguous_outcome",
}
NO_EFFECT = {
    "proposal_only": True,
    "routing": False,
    "policy": False,
    "queue": False,
    "merge": False,
    "runtime": False,
}
AGENT_WORKSPACE_ROUTE_SOURCE = "agent-workspace-manifest"
DIRECT_TASK_ROUTE_SOURCE = "direct-task-start"
ROUTE_SOURCES = {AGENT_WORKSPACE_ROUTE_SOURCE, DIRECT_TASK_ROUTE_SOURCE}
TOP_LEVEL_FIELDS = {
    "schema_version",
    "record_id",
    "eligibility",
    "eligible_case",
    "canonical_route_evidence",
    "features",
    "outcome",
    "primary_evidence_refs",
    "captured_at",
    "no_effect",
}
ELIGIBILITY_FIELDS = {
    "schema_version",
    "eligibility_id",
    "eligible_case",
    "canonical_route_evidence",
    "features",
    "frozen_at",
    "no_effect",
}
COMMON_FEATURE_FIELDS = {
    "task_kind",
    "changed_file_estimate",
    "expected_duration_minutes",
    "novelty",
    "risk_flags",
    "connector_instability",
    "user_requested_external",
}
V1_FEATURE_FIELDS = COMMON_FEATURE_FIELDS | {"parallel_work"}
V2_FEATURE_FIELDS = COMMON_FEATURE_FIELDS | {
    "risk_tier",
    "concurrent_external_activity",
    "parallelization_candidate",
    "decision_fork",
    "architecture_hypotheses",
}


class ShadowCaptureError(RuntimeError):
    pass


class ShadowRecordExistsError(ShadowCaptureError):
    """The final create-only slot is already claimed by an on-disk record.

    Carried as a dedicated type so idempotent callers can branch on identity
    instead of matching human-readable exception text.
    """


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _parse_timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ShadowCaptureError(f"{field} must be a bounded RFC3339 timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ShadowCaptureError(f"{field} must be a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ShadowCaptureError(f"{field} must include a timezone")
    # Project every equivalent offset onto a single canonical UTC-Z instant so
    # two spellings of the same moment always normalize to the same string.
    normalized = parsed.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z")


def _absolute_unresolved(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def _open_directory_fd(path: Path) -> int:
    candidate = _absolute_unresolved(path)
    if not candidate.is_absolute():
        raise ShadowCaptureError("directory path must resolve from an absolute anchor")
    parts = candidate.parts
    descriptor = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:]:
            try:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise ShadowCaptureError(
                    f"path component is not a real directory: {part}"
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_json(path: Path, *, label: str) -> dict[str, Any]:
    candidate = _absolute_unresolved(path)
    parent_descriptor = _open_directory_fd(candidate.parent)
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                candidate.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise ShadowCaptureError(
                f"{label} must be a regular non-symlink file"
            ) from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ShadowCaptureError(f"{label} must be a regular file")
        if metadata.st_size > 2_000_000:
            raise ShadowCaptureError(f"{label} exceeds the 2 MiB bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65536, 2_000_001 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 2_000_000:
                raise ShadowCaptureError(f"{label} exceeds the 2 MiB bound")
        try:
            value = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ShadowCaptureError(f"{label} must contain valid UTF-8 JSON") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)
    if not isinstance(value, dict):
        raise ShadowCaptureError(f"{label} must contain a JSON object")
    return value


def _task_references(manifest: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    tasks = manifest.get("tasks")
    if not isinstance(tasks, dict):
        return refs
    for value in tasks.values():
        if isinstance(value, str) and TASK_ID_RE.fullmatch(value):
            refs.add(value)
        elif isinstance(value, dict):
            for key in ("task_id", "id"):
                candidate = value.get(key)
                if isinstance(candidate, str) and TASK_ID_RE.fullmatch(candidate):
                    refs.add(candidate)
    return refs


def _writer_task_reference(manifest: dict[str, Any]) -> str | None:
    """Return the bound writer task id, the sole routing-relevant task.

    The workspace contract makes ``writer`` the task whose execution the route
    decision governs; ``tests`` and ``review`` are not routing-relevant.
    """
    tasks = manifest.get("tasks")
    if not isinstance(tasks, dict):
        return None
    writer = tasks.get("writer")
    if isinstance(writer, str) and TASK_ID_RE.fullmatch(writer):
        return writer
    return None


def _normalize_evidence_refs(value: Any, *, reviewed: bool, sort: bool) -> list[str]:
    if not isinstance(value, list) or len(value) > 16:
        raise ShadowCaptureError(
            "primary_evidence_refs must be a list with at most 16 entries"
        )
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 300:
            raise ShadowCaptureError(
                "primary_evidence_refs contains an invalid reference"
            )
        prefix = next((p for p in EVIDENCE_PREFIXES if item.startswith(p)), None)
        if prefix is None or len(item) <= len(prefix):
            # A bare prefix such as "github-ci:" carries no evidence identity.
            raise ShadowCaptureError(
                "primary_evidence_refs contains an invalid reference"
            )
        refs.append(item)
    if len(set(refs)) != len(refs):
        raise ShadowCaptureError("primary_evidence_refs must not contain duplicates")
    if reviewed and not refs:
        raise ShadowCaptureError(
            "reviewed outcomes require at least one primary evidence reference"
        )
    if sort:
        # V2 evidence order carries no semantics: sort so identical evidence sets
        # yield one canonical, order-independent record identity regardless of
        # caller ordering. V1 records predate this rule (PR #410 froze caller
        # order into record_id), so the v1 builder/validator pass sort=False to
        # keep those historical, unsorted-but-valid records provable unchanged.
        return sorted(refs)
    return refs


def _normalize_outcome(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ShadowCaptureError("outcome must be an object")
    status_value = value.get("status")
    if status_value == "reviewed":
        expected = {"status", "kind", "label", "observed_at", "review_authority"}
        if set(value) != expected:
            raise ShadowCaptureError("reviewed outcome shape is invalid")
        kind = value.get("kind")
        label = value.get("label")
        authority = value.get("review_authority")
        if kind not in OUTCOME_KINDS or label not in OUTCOME_LABELS:
            raise ShadowCaptureError("reviewed outcome kind or label is invalid")
        if authority not in REVIEW_AUTHORITIES:
            raise ShadowCaptureError("reviewed outcome authority is invalid")
        return {
            "status": "reviewed",
            "kind": kind,
            "label": label,
            "observed_at": _parse_timestamp(
                value.get("observed_at"), "outcome.observed_at"
            ),
            "review_authority": authority,
        }
    if status_value == "abstained":
        expected = {"status", "reason_code", "observed_at"}
        if set(value) != expected:
            raise ShadowCaptureError("abstained outcome shape is invalid")
        reason = value.get("reason_code")
        if reason not in ABSTENTION_REASONS:
            raise ShadowCaptureError("abstention reason is invalid")
        return {
            "status": "abstained",
            "reason_code": reason,
            "observed_at": _parse_timestamp(
                value.get("observed_at"), "outcome.observed_at"
            ),
        }
    raise ShadowCaptureError("outcome.status must be reviewed or abstained")


def _bounded_features(route: dict[str, Any]) -> dict[str, Any]:
    facts = route.get("input_facts")
    if not isinstance(facts, dict):
        raise ShadowCaptureError("verified route evidence is missing input_facts")
    common = {
        "task_kind": facts.get("task_kind"),
        "changed_file_estimate": facts.get("changed_file_estimate"),
        "expected_duration_minutes": facts.get("expected_duration_minutes"),
        "novelty": facts.get("novelty"),
        "risk_flags": list(facts.get("risk_flags", [])),
        "connector_instability": facts.get("connector_instability"),
        "user_requested_external": facts.get("user_requested_external"),
    }
    if route.get("schema_version") == 1:
        features = {**common, "parallel_work": facts.get("parallel_work")}
    elif route.get("schema_version") == 2:
        features = {
            **common,
            "risk_tier": route.get("risk_tier"),
            "concurrent_external_activity": facts.get("concurrent_external_activity"),
            "parallelization_candidate": facts.get("parallelization_candidate"),
            "decision_fork": facts.get("decision_fork"),
            "architecture_hypotheses": facts.get("architecture_hypotheses"),
        }
    else:
        raise ShadowCaptureError(
            "verified route evidence schema_version is unsupported"
        )
    _validate_features(features, route_schema_version=route["schema_version"])
    return features


def _validate_features(features: Any, *, route_schema_version: int) -> None:
    expected_fields = (
        V1_FEATURE_FIELDS
        if route_schema_version == 1
        else V2_FEATURE_FIELDS
        if route_schema_version == 2
        else set()
    )
    if not isinstance(features, dict) or set(features) != expected_fields:
        raise ShadowCaptureError("features shape is invalid for route schema version")
    if (
        not isinstance(features["task_kind"], str)
        or not 1 <= len(features["task_kind"]) <= 40
    ):
        raise ShadowCaptureError("features.task_kind is invalid")
    for field in ("changed_file_estimate", "expected_duration_minutes"):
        value = features[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ShadowCaptureError(f"features.{field} is invalid")
    if (
        not isinstance(features["novelty"], str)
        or not 1 <= len(features["novelty"]) <= 32
    ):
        raise ShadowCaptureError("features.novelty is invalid")
    flags = features["risk_flags"]
    if (
        not isinstance(flags, list)
        or len(flags) > 32
        or any(not isinstance(item, str) or not 1 <= len(item) <= 32 for item in flags)
        or len(set(flags)) != len(flags)
    ):
        raise ShadowCaptureError("features.risk_flags is invalid")
    for field in ("connector_instability", "user_requested_external"):
        if not isinstance(features[field], bool):
            raise ShadowCaptureError(f"features.{field} is invalid")
    if route_schema_version == 1:
        if not isinstance(features["parallel_work"], bool):
            raise ShadowCaptureError("features.parallel_work is invalid")
        return
    risk_tier = features["risk_tier"]
    if not isinstance(risk_tier, str) or not 1 <= len(risk_tier) <= 32:
        raise ShadowCaptureError("features.risk_tier is invalid")
    for field in (
        "concurrent_external_activity",
        "parallelization_candidate",
        "decision_fork",
    ):
        if not isinstance(features[field], bool):
            raise ShadowCaptureError(f"features.{field} is invalid")
    hypotheses = features["architecture_hypotheses"]
    if (
        isinstance(hypotheses, bool)
        or not isinstance(hypotheses, int)
        or not 1 <= hypotheses <= 4
    ):
        raise ShadowCaptureError("features.architecture_hypotheses is invalid")


def _validated_route_evidence(
    value: Any, *, execution_surface: str = "workspace"
) -> dict[str, Any]:
    persisted = isinstance(value, dict) and (
        "status" in value or "evidence_complete" in value
    )
    candidate = value
    if persisted:
        if (
            value.get("status") != "verified"
            or value.get("evidence_complete") is not True
        ):
            raise ShadowCaptureError(
                "canonical route evidence is missing or incomplete"
            )
        candidate = {
            key: item
            for key, item in value.items()
            if key not in {"status", "evidence_complete"}
        }
    try:
        normalized = workspace._normalize_route_evidence(
            candidate, execution_surface=execution_surface
        )
    except workspace.AgentWorkspaceError as exc:
        raise ShadowCaptureError(f"canonical route evidence is invalid: {exc}") from exc
    if (
        normalized.get("status") != "verified"
        or normalized.get("evidence_complete") is not True
    ):
        raise ShadowCaptureError("canonical route evidence is missing or incomplete")
    if persisted and normalized != value:
        raise ShadowCaptureError(
            "persisted canonical route evidence does not match deterministic policy replay"
        )
    return normalized


def _manifest_execution_surface(manifest: dict[str, Any]) -> str:
    surface = manifest.get("routing_surface", "workspace")
    if surface not in {"workspace", "direct_task"}:
        raise ShadowCaptureError("manifest routing_surface is invalid")
    return str(surface)

def _manifest_route_source(manifest: dict[str, Any]) -> str:
    return (
        DIRECT_TASK_ROUTE_SOURCE
        if _manifest_execution_surface(manifest) == "direct_task"
        else AGENT_WORKSPACE_ROUTE_SOURCE
    )

def _case_id(task_id: str, recommendation_id: str) -> str:
    return _sha256_json(
        {
            "schema_version": 1,
            "task_id": task_id,
            "recommendation_id": recommendation_id,
        }
    )


def _route_reference(route: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": AGENT_WORKSPACE_ROUTE_SOURCE,
        "schema_version": route["schema_version"],
        "recommendation_id": route["recommendation_id"],
        "route_evidence_sha256": _sha256_json(route),
        "manifest_sha256": _sha256_json(manifest),
    }


def _manifest_identity_sha256(
    workspace_id: str,
    plan_sha256: str,
    route_evidence_sha256: str,
    *,
    route_source: str = AGENT_WORKSPACE_ROUTE_SOURCE,
) -> str:
    """Stable allowlisted manifest identity.

    Binds only workspace, plan and canonical route evidence. It deliberately
    excludes private_note, commands, prompts and mutating lifecycle fields
    (created_at/updated_at/tasks/...), so the digest is identical between the
    prospective freeze and the later task binding of the same workspace case.
    """
    if route_source not in ROUTE_SOURCES:
        raise ShadowCaptureError("canonical route source is invalid")
    payload = {
        "schema_version": "operator-routing-shadow-manifest-identity.v1",
        "workspace_id": workspace_id,
        "plan_sha256": plan_sha256,
        "route_evidence_sha256": route_evidence_sha256,
    }
    if route_source != AGENT_WORKSPACE_ROUTE_SOURCE:
        payload = {
            "schema_version": "operator-routing-shadow-manifest-identity.v2",
            "route_source": route_source,
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "route_evidence_sha256": route_evidence_sha256,
        }
    return _sha256_json(payload)


def _cohort_route_reference(
    route: dict[str, Any],
    workspace_id: str,
    plan_sha256: str,
    *,
    route_source: str = AGENT_WORKSPACE_ROUTE_SOURCE,
) -> dict[str, Any]:
    route_evidence_sha256 = _sha256_json(route)
    if route_source not in ROUTE_SOURCES:
        raise ShadowCaptureError("canonical route source is invalid")
    return {
        "source": route_source,
        "schema_version": route["schema_version"],
        "recommendation_id": route["recommendation_id"],
        "route_evidence_sha256": route_evidence_sha256,
        "manifest_identity_sha256": _manifest_identity_sha256(
            workspace_id,
            plan_sha256,
            route_evidence_sha256,
            route_source=route_source,
        ),
    }


def _validate_case_and_route(
    eligible: Any, route_ref: Any, *, manifest_field: str = "manifest_sha256"
) -> tuple[str, str, int]:
    if not isinstance(eligible, dict) or set(eligible) != {"task_id", "case_id"}:
        raise ShadowCaptureError("eligible_case shape is invalid")
    task_id = eligible.get("task_id")
    case_id = eligible.get("case_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise ShadowCaptureError("eligible_case.task_id is invalid")
    if not isinstance(case_id, str) or SHA256_RE.fullmatch(case_id) is None:
        raise ShadowCaptureError("eligible_case.case_id is invalid")
    route_schema_version = _validate_route_reference(
        route_ref, manifest_field=manifest_field
    )
    expected_case_id = _case_id(task_id, route_ref["recommendation_id"])
    if case_id != expected_case_id:
        raise ShadowCaptureError(
            "eligible_case.case_id is not bound to task and route evidence"
        )
    return task_id, case_id, route_schema_version


def _validate_route_reference(route_ref: Any, *, manifest_field: str) -> int:
    if not isinstance(route_ref, dict) or set(route_ref) != {
        "source",
        "schema_version",
        "recommendation_id",
        "route_evidence_sha256",
        manifest_field,
    }:
        raise ShadowCaptureError("canonical_route_evidence shape is invalid")
    route_schema_version = route_ref.get("schema_version")
    if route_ref.get("source") not in ROUTE_SOURCES or route_schema_version not in {
        1,
        2,
    }:
        raise ShadowCaptureError(
            "canonical_route_evidence source or schema_version is invalid"
        )
    for field in ("recommendation_id", "route_evidence_sha256", manifest_field):
        value = route_ref.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ShadowCaptureError(f"canonical_route_evidence.{field} is invalid")
    return route_schema_version


def build_eligibility_receipt(
    manifest: dict[str, Any],
    *,
    eligible_task_id: str,
    frozen_at: str,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ShadowCaptureError("manifest must be an object")
    if (
        not isinstance(eligible_task_id, str)
        or TASK_ID_RE.fullmatch(eligible_task_id) is None
    ):
        raise ShadowCaptureError("eligible_task_id must be a Grabowski task id")
    if eligible_task_id not in _task_references(manifest):
        raise ShadowCaptureError(
            "eligible_task_id is not referenced by the workspace manifest"
        )
    route = _validated_route_evidence(
        manifest.get("route_evidence"),
        execution_surface=_manifest_execution_surface(manifest),
    )
    normalized_frozen_at = _parse_timestamp(frozen_at, "frozen_at")
    payload = {
        "schema_version": ELIGIBILITY_SCHEMA_VERSION,
        "eligible_case": {
            "task_id": eligible_task_id,
            "case_id": _case_id(eligible_task_id, route["recommendation_id"]),
        },
        "canonical_route_evidence": _route_reference(route, manifest),
        "features": _bounded_features(route),
        "frozen_at": normalized_frozen_at,
        "no_effect": dict(NO_EFFECT),
    }
    receipt = {"eligibility_id": _sha256_json(payload), **payload}
    validate_eligibility_receipt(receipt)
    return receipt


def validate_eligibility_receipt(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != ELIGIBILITY_FIELDS:
        raise ShadowCaptureError("eligibility receipt shape is invalid")
    if receipt.get("schema_version") != ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility schema_version is invalid")
    eligibility_id = receipt.get("eligibility_id")
    if (
        not isinstance(eligibility_id, str)
        or SHA256_RE.fullmatch(eligibility_id) is None
    ):
        raise ShadowCaptureError("eligibility_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        receipt.get("eligible_case"), receipt.get("canonical_route_evidence")
    )
    _validate_features(
        receipt.get("features"), route_schema_version=route_schema_version
    )
    frozen_at = _parse_timestamp(receipt.get("frozen_at"), "frozen_at")
    if frozen_at != receipt.get("frozen_at"):
        raise ShadowCaptureError("frozen_at is not normalized")
    if receipt.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    payload = {key: receipt[key] for key in receipt if key != "eligibility_id"}
    if _sha256_json(payload) != eligibility_id:
        raise ShadowCaptureError(
            "eligibility_id does not match the canonical eligibility payload"
        )
    return receipt


def _timestamp_value(value: str) -> datetime:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(candidate)


def build_shadow_record(
    eligibility_receipt: dict[str, Any],
    *,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    captured_at: str,
) -> dict[str, Any]:
    eligibility = validate_eligibility_receipt(eligibility_receipt)
    normalized_outcome = _normalize_outcome(outcome)
    refs = _normalize_evidence_refs(
        primary_evidence_refs,
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=False,
    )
    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")
    frozen_at = eligibility["frozen_at"]
    observed_at = normalized_outcome["observed_at"]
    if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
        raise ShadowCaptureError(
            "eligibility must be frozen before outcome observation"
        )
    if _timestamp_value(observed_at) > _timestamp_value(normalized_captured_at):
        raise ShadowCaptureError(
            "outcome observation must not occur after capture sealing"
        )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "eligibility": {
            "schema_version": ELIGIBILITY_SCHEMA_VERSION,
            "eligibility_id": eligibility["eligibility_id"],
            "frozen_at": frozen_at,
        },
        "eligible_case": dict(eligibility["eligible_case"]),
        "canonical_route_evidence": dict(eligibility["canonical_route_evidence"]),
        "features": dict(eligibility["features"]),
        "outcome": normalized_outcome,
        "primary_evidence_refs": refs,
        "captured_at": normalized_captured_at,
        "no_effect": dict(NO_EFFECT),
    }
    record = {"record_id": _sha256_json(payload), **payload}
    validate_shadow_record(record)
    return record


def validate_shadow_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != TOP_LEVEL_FIELDS:
        raise ShadowCaptureError("shadow record shape is invalid")
    if record.get("schema_version") != SCHEMA_VERSION:
        raise ShadowCaptureError("shadow record schema_version is invalid")
    record_id = record.get("record_id")
    if not isinstance(record_id, str) or SHA256_RE.fullmatch(record_id) is None:
        raise ShadowCaptureError("record_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        record.get("eligible_case"), record.get("canonical_route_evidence")
    )
    _validate_features(
        record.get("features"), route_schema_version=route_schema_version
    )
    eligibility_ref = record.get("eligibility")
    if not isinstance(eligibility_ref, dict) or set(eligibility_ref) != {
        "schema_version",
        "eligibility_id",
        "frozen_at",
    }:
        raise ShadowCaptureError("eligibility reference shape is invalid")
    if eligibility_ref.get("schema_version") != ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility reference schema_version is invalid")
    eligibility_id = eligibility_ref.get("eligibility_id")
    if (
        not isinstance(eligibility_id, str)
        or SHA256_RE.fullmatch(eligibility_id) is None
    ):
        raise ShadowCaptureError("eligibility reference id is invalid")
    frozen_at = _parse_timestamp(
        eligibility_ref.get("frozen_at"), "eligibility.frozen_at"
    )
    if frozen_at != eligibility_ref.get("frozen_at"):
        raise ShadowCaptureError("eligibility.frozen_at is not normalized")
    normalized_outcome = _normalize_outcome(record.get("outcome"))
    if normalized_outcome != record.get("outcome"):
        raise ShadowCaptureError("outcome is not normalized")
    refs = _normalize_evidence_refs(
        record.get("primary_evidence_refs"),
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=False,
    )
    if refs != record.get("primary_evidence_refs"):
        raise ShadowCaptureError("primary_evidence_refs is not normalized")
    captured_at = _parse_timestamp(record.get("captured_at"), "captured_at")
    if captured_at != record.get("captured_at"):
        raise ShadowCaptureError("captured_at is not normalized")
    if _timestamp_value(frozen_at) > _timestamp_value(
        normalized_outcome["observed_at"]
    ):
        raise ShadowCaptureError(
            "eligibility must be frozen before outcome observation"
        )
    if _timestamp_value(normalized_outcome["observed_at"]) > _timestamp_value(
        captured_at
    ):
        raise ShadowCaptureError(
            "outcome observation must not occur after capture sealing"
        )
    if record.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    eligibility_payload = {
        "schema_version": ELIGIBILITY_SCHEMA_VERSION,
        "eligible_case": record["eligible_case"],
        "canonical_route_evidence": record["canonical_route_evidence"],
        "features": record["features"],
        "frozen_at": frozen_at,
        "no_effect": record["no_effect"],
    }
    if _sha256_json(eligibility_payload) != eligibility_id:
        raise ShadowCaptureError(
            "eligibility reference does not match frozen record fields"
        )
    payload = {key: record[key] for key in record if key != "record_id"}
    if _sha256_json(payload) != record_id:
        raise ShadowCaptureError(
            "record_id does not match the canonical record payload"
        )
    return record


def _publish_create_only(
    parent_descriptor: int, name: str, data: bytes, *, conflict_message: str
) -> None:
    """Crash-safe create-only publication into ``name`` within an open directory.

    Writes a fully materialized owner-private temp file (fsync'd), then claims
    the final name atomically with a no-replace hard link. A crash before the
    link leaves only a stray temp file, never a half-written final slot. An
    already-present final name is surfaced as ``ShadowRecordExistsError``.
    """
    tmp_name = f".tmp-{os.getpid()}-{os.urandom(8).hex()}"
    try:
        tmp_descriptor = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise ShadowCaptureError(
            "create-only publication could not open a private temp file"
        ) from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(tmp_descriptor, view)
            view = view[written:]
        os.fsync(tmp_descriptor)
    except OSError:
        os.close(tmp_descriptor)
        _silent_unlink(parent_descriptor, tmp_name)
        raise
    else:
        os.close(tmp_descriptor)
    try:
        os.link(
            tmp_name,
            name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
    except FileExistsError as exc:
        _silent_unlink(parent_descriptor, tmp_name)
        raise ShadowRecordExistsError(conflict_message) from exc
    except OSError as exc:
        _silent_unlink(parent_descriptor, tmp_name)
        raise ShadowCaptureError(
            "output path must resolve to a new regular non-symlink file"
        ) from exc
    _silent_unlink(parent_descriptor, tmp_name)
    os.fsync(parent_descriptor)


def _silent_unlink(parent_descriptor: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent_descriptor)
    except OSError:
        pass


def write_create_only(path: Path, record: dict[str, Any]) -> None:
    schema_version = record.get("schema_version") if isinstance(record, dict) else None
    if schema_version == ELIGIBILITY_SCHEMA_VERSION:
        validate_eligibility_receipt(record)
    elif schema_version == SCHEMA_VERSION:
        validate_shadow_record(record)
    else:
        raise ShadowCaptureError("unsupported create-only record schema")
    candidate = _absolute_unresolved(path)
    parent_descriptor = _open_directory_fd(candidate.parent)
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        _publish_create_only(
            parent_descriptor,
            candidate.name,
            data,
            conflict_message="refusing to overwrite an existing shadow record",
        )
    finally:
        os.close(parent_descriptor)


PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION = (
    "operator-routing-shadow-prospective-eligibility.v1"
)
PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION = (
    "operator-routing-shadow-prospective-eligibility.v2"
)
ELIGIBILITY_V2_SCHEMA_VERSION = "operator-routing-shadow-eligibility.v2"
ELIGIBILITY_V3_SCHEMA_VERSION = "operator-routing-shadow-eligibility.v3"
RECORD_V2_SCHEMA_VERSION = "operator-routing-shadow-record.v2"
RECORD_V3_SCHEMA_VERSION = "operator-routing-shadow-record.v3"
CAPTURE_ATTEMPT_SCHEMA_VERSION = "operator-routing-shadow-capture-attempt.v1"
CASE_ORIGINS = {"production", "test", "synthetic", "quarantined"}
WORKSPACE_PRESTART_CAPTURE_PATH = "agent_workspace_prestart"
DIRECT_CAPTURE_PATH = "direct_capture"
DIRECT_TASK_PRESTART_CAPTURE_PATH = "direct_task_prestart"
CAPTURE_PATHS = {
    WORKSPACE_PRESTART_CAPTURE_PATH,
    DIRECT_CAPTURE_PATH,
    DIRECT_TASK_PRESTART_CAPTURE_PATH,
}
DIRECT_TASK_BINDING_SCHEMA_VERSION = "operator-routing-shadow-direct-task-binding.v1"
_WORKSPACE_PRESTART_ATTESTATION = object()
_DIRECT_TASK_PRESTART_ATTESTATION = object()
_UNSET = object()
EXECUTION_STATUSES = {"completed", "execution_aborted", "infrastructure_failure"}
EXECUTION_UNKNOWN_REASONS = {"not_observed", "ambiguous"}
PROSPECTIVE_FIELDS = {
    "schema_version",
    "prospective_eligibility_id",
    "workspace_case",
    "canonical_route_evidence",
    "features",
    "frozen_at",
    "no_effect",
}
PROSPECTIVE_V2_FIELDS = PROSPECTIVE_FIELDS | {"case_provenance"}
ELIGIBILITY_V2_FIELDS = {
    "schema_version",
    "eligibility_id",
    "prospective_eligibility",
    "eligible_case",
    "canonical_route_evidence",
    "features",
    "frozen_at",
    "no_effect",
}
ELIGIBILITY_V3_FIELDS = ELIGIBILITY_V2_FIELDS | {"case_provenance"}
RECORD_V2_FIELDS = {
    "schema_version",
    "record_id",
    "eligibility",
    "eligible_case",
    "canonical_route_evidence",
    "features",
    "outcome",
    "primary_evidence_refs",
    "captured_at",
    "no_effect",
}
RECORD_V3_FIELDS = RECORD_V2_FIELDS | {
    "case_provenance",
    "execution_provenance",
    "semantic_assessments",
}
ATTEMPT_STATUSES = {"created", "duplicate", "rejected", "error"}


def _workspace_case_id(
    workspace_id: str,
    plan_sha256: str,
    route_evidence_sha256: str,
    *,
    route_source: str = AGENT_WORKSPACE_ROUTE_SOURCE,
) -> str:
    payload = {
        "schema_version": 1,
        "workspace_id": workspace_id,
        "plan_sha256": plan_sha256,
        "route_evidence_sha256": route_evidence_sha256,
    }
    if route_source != AGENT_WORKSPACE_ROUTE_SOURCE:
        if route_source not in ROUTE_SOURCES:
            raise ShadowCaptureError("canonical route source is invalid")
        payload = {
            "schema_version": 2,
            "route_source": route_source,
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "route_evidence_sha256": route_evidence_sha256,
        }
    return _sha256_json(payload)


def _prove_prospective_binding(
    *,
    workspace_id: str,
    plan_sha256: str,
    workspace_case_id: str,
    prospective_eligibility_id: str,
    route_ref: dict[str, Any],
    features: dict[str, Any],
    frozen_at: str,
    no_effect: dict[str, Any],
    prospective_schema_version: str = PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION,
    case_provenance: dict[str, Any] | None = None,
) -> None:
    """Reconstruct the full prospective payload and prove its self-consistency.

    Because the manifest identity digest is stable across the freeze and the
    later binding, the prospective ``canonical_route_evidence`` is identical to
    the bound one, so the entire prospective receipt can be rebuilt from the v2
    lineage fields and its ``prospective_eligibility_id`` re-derived here.
    """
    # Re-derive the manifest identity digest from workspace, plan and route so an
    # isolated eligibility-v2/record-v2 cannot substitute a foreign digest and
    # then re-hash prospective_eligibility_id, eligibility_id and record_id into
    # a self-consistent but forged lineage. The digest is a pure function of the
    # bound (workspace_id, plan_sha256, route_evidence_sha256), never free input.
    route_source = route_ref["source"]
    if route_ref["manifest_identity_sha256"] != _manifest_identity_sha256(
        workspace_id,
        plan_sha256,
        route_ref["route_evidence_sha256"],
        route_source=route_source,
    ):
        raise ShadowCaptureError(
            "canonical_route_evidence.manifest_identity_sha256 is not bound to "
            "workspace, plan and route"
        )
    if workspace_case_id != _workspace_case_id(
        workspace_id,
        plan_sha256,
        route_ref["route_evidence_sha256"],
        route_source=route_source,
    ):
        raise ShadowCaptureError(
            "workspace_case_id is not bound to workspace, plan and route"
        )
    reconstructed = {
        "schema_version": prospective_schema_version,
        "workspace_case": {
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "case_id": workspace_case_id,
        },
        "canonical_route_evidence": route_ref,
        "features": features,
        "frozen_at": frozen_at,
        "no_effect": no_effect,
    }
    if prospective_schema_version == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION:
        reconstructed["case_provenance"] = _normalize_case_provenance(case_provenance)
    elif prospective_schema_version != PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("prospective schema version is unsupported")
    if _sha256_json(reconstructed) != prospective_eligibility_id:
        raise ShadowCaptureError(
            "prospective_eligibility_id does not match the reconstructed "
            "prospective payload"
        )


def build_prospective_eligibility(
    manifest: dict[str, Any],
    *,
    frozen_at: str,
) -> dict[str, Any]:
    """Freeze workspace eligibility before a writer task exists or can produce an outcome."""
    if not isinstance(manifest, dict):
        raise ShadowCaptureError("manifest must be an object")
    workspace_id = manifest.get("workspace_id")
    plan_sha256 = manifest.get("plan_sha256")
    if (
        not isinstance(workspace_id, str)
        or workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None
    ):
        raise ShadowCaptureError("workspace_id is invalid for prospective eligibility")
    if not isinstance(plan_sha256, str) or SHA256_RE.fullmatch(plan_sha256) is None:
        raise ShadowCaptureError("plan_sha256 is invalid for prospective eligibility")
    tasks_value = manifest.get("tasks")
    if not isinstance(tasks_value, dict) or any(
        value is not None for value in tasks_value.values()
    ):
        raise ShadowCaptureError(
            "prospective eligibility must be frozen before workspace tasks are bound"
        )
    execution_surface = _manifest_execution_surface(manifest)
    route_source = _manifest_route_source(manifest)
    route = _validated_route_evidence(
        manifest.get("route_evidence"), execution_surface=execution_surface
    )
    normalized_frozen_at = _parse_timestamp(frozen_at, "frozen_at")
    route_ref = _cohort_route_reference(
        route, workspace_id, plan_sha256, route_source=route_source
    )
    case_id = _workspace_case_id(
        workspace_id,
        plan_sha256,
        route_ref["route_evidence_sha256"],
        route_source=route_source,
    )
    payload = {
        "schema_version": PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION,
        "workspace_case": {
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "case_id": case_id,
        },
        "canonical_route_evidence": route_ref,
        "features": _bounded_features(route),
        "frozen_at": normalized_frozen_at,
        "no_effect": dict(NO_EFFECT),
    }
    receipt = {
        "prospective_eligibility_id": _sha256_json(payload),
        **payload,
    }
    validate_prospective_eligibility(receipt)
    return receipt


def validate_prospective_eligibility(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != PROSPECTIVE_FIELDS:
        raise ShadowCaptureError("prospective eligibility receipt shape is invalid")
    if receipt.get("schema_version") != PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("prospective eligibility schema_version is invalid")
    receipt_id = receipt.get("prospective_eligibility_id")
    if not isinstance(receipt_id, str) or SHA256_RE.fullmatch(receipt_id) is None:
        raise ShadowCaptureError("prospective_eligibility_id is invalid")
    workspace_case = receipt.get("workspace_case")
    if not isinstance(workspace_case, dict) or set(workspace_case) != {
        "workspace_id",
        "plan_sha256",
        "case_id",
    }:
        raise ShadowCaptureError("workspace_case shape is invalid")
    workspace_id = workspace_case.get("workspace_id")
    plan_sha256 = workspace_case.get("plan_sha256")
    case_id = workspace_case.get("case_id")
    if (
        not isinstance(workspace_id, str)
        or workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None
        or not isinstance(plan_sha256, str)
        or SHA256_RE.fullmatch(plan_sha256) is None
        or not isinstance(case_id, str)
        or SHA256_RE.fullmatch(case_id) is None
    ):
        raise ShadowCaptureError("workspace_case identity is invalid")
    route_ref = receipt.get("canonical_route_evidence")
    route_schema_version = _validate_route_reference(
        route_ref, manifest_field="manifest_identity_sha256"
    )
    route_source = route_ref["source"]
    if route_ref["manifest_identity_sha256"] != _manifest_identity_sha256(
        workspace_id,
        plan_sha256,
        route_ref["route_evidence_sha256"],
        route_source=route_source,
    ):
        raise ShadowCaptureError(
            "canonical_route_evidence.manifest_identity_sha256 is not bound to "
            "workspace, plan and route"
        )
    if case_id != _workspace_case_id(
        workspace_id,
        plan_sha256,
        route_ref["route_evidence_sha256"],
        route_source=route_ref["source"],
    ):
        raise ShadowCaptureError(
            "workspace_case.case_id is not bound to workspace, plan and route"
        )
    _validate_features(
        receipt.get("features"), route_schema_version=route_schema_version
    )
    frozen_at = _parse_timestamp(receipt.get("frozen_at"), "frozen_at")
    if frozen_at != receipt.get("frozen_at"):
        raise ShadowCaptureError("frozen_at is not normalized")
    if receipt.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    payload = {
        key: receipt[key] for key in receipt if key != "prospective_eligibility_id"
    }
    if _sha256_json(payload) != receipt_id:
        raise ShadowCaptureError(
            "prospective_eligibility_id does not match the canonical payload"
        )
    return receipt


def _normalize_case_provenance(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"case_origin", "capture_path"}:
        raise ShadowCaptureError("case_provenance shape is invalid")
    origin = value.get("case_origin")
    if origin not in CASE_ORIGINS:
        raise ShadowCaptureError("case_provenance.case_origin is invalid")
    capture_path = value.get("capture_path")
    if capture_path not in CAPTURE_PATHS:
        raise ShadowCaptureError("case_provenance.capture_path is invalid")
    if capture_path == DIRECT_CAPTURE_PATH and origin == "production":
        raise ShadowCaptureError("direct capture cannot claim production case provenance")
    return {"case_origin": origin, "capture_path": capture_path}

def _normalize_execution_provenance(value: Any) -> dict[str, Any]:
    if value is None:
        return {"status": "unknown", "reason_code": "not_observed"}
    if not isinstance(value, dict):
        raise ShadowCaptureError("execution_provenance must be an object")
    status_value = value.get("status")
    if status_value == "unknown":
        if set(value) != {"status", "reason_code"}:
            raise ShadowCaptureError("unknown execution_provenance shape is invalid")
        reason = value.get("reason_code")
        if reason not in EXECUTION_UNKNOWN_REASONS:
            raise ShadowCaptureError("execution_provenance reason_code is invalid")
        return {"status": "unknown", "reason_code": reason}
    if status_value not in EXECUTION_STATUSES:
        raise ShadowCaptureError("execution_provenance status is invalid")
    if set(value) != {"status", "observed_at", "evidence_refs"}:
        raise ShadowCaptureError("observed execution_provenance shape is invalid")
    refs = _normalize_evidence_refs(value.get("evidence_refs"), reviewed=False, sort=True)
    if not refs:
        raise ShadowCaptureError("observed execution_provenance requires evidence_refs")
    return {
        "status": status_value,
        "observed_at": _parse_timestamp(value.get("observed_at"), "execution_provenance.observed_at"),
        "evidence_refs": refs,
    }


def _normalize_semantic_assessments(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 4:
        raise ShadowCaptureError("semantic_assessments must be a list with at most 4 entries")
    if len(value) == 1:
        raise ShadowCaptureError(
            "semantic_assessments must be empty or contain at least 2 independent assessments"
        )
    normalized: list[dict[str, Any]] = []
    reviewer_ids: set[str] = set()
    kinds: set[str] = set()
    expected = {
        "reviewer_pseudonym_sha256",
        "kind",
        "label",
        "observed_at",
        "review_authority",
        "primary_evidence_refs",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != expected:
            raise ShadowCaptureError("semantic assessment shape is invalid")
        reviewer_id = item.get("reviewer_pseudonym_sha256")
        if not isinstance(reviewer_id, str) or SHA256_RE.fullmatch(reviewer_id) is None:
            raise ShadowCaptureError("semantic assessment reviewer pseudonym is invalid")
        if reviewer_id in reviewer_ids:
            raise ShadowCaptureError("semantic assessments require distinct reviewer pseudonyms")
        reviewer_ids.add(reviewer_id)
        kind = item.get("kind")
        label = item.get("label")
        authority = item.get("review_authority")
        if kind not in OUTCOME_KINDS or label not in OUTCOME_LABELS:
            raise ShadowCaptureError("semantic assessment kind or label is invalid")
        if authority not in REVIEW_AUTHORITIES:
            raise ShadowCaptureError("semantic assessment review_authority is invalid")
        kinds.add(kind)
        normalized.append(
            {
                "reviewer_pseudonym_sha256": reviewer_id,
                "kind": kind,
                "label": label,
                "observed_at": _parse_timestamp(item.get("observed_at"), "semantic_assessment.observed_at"),
                "review_authority": authority,
                "primary_evidence_refs": _normalize_evidence_refs(
                    item.get("primary_evidence_refs"), reviewed=True, sort=True
                ),
            }
        )
    if len(kinds) > 1:
        raise ShadowCaptureError("semantic assessments must address one outcome kind")
    return sorted(normalized, key=lambda item: item["reviewer_pseudonym_sha256"])


def _validate_v3_timeline(
    *,
    frozen_at: str,
    outcome: dict[str, Any],
    execution: dict[str, Any],
    assessments: list[dict[str, Any]],
    captured_at: str,
) -> None:
    timeline_values = [("outcome observation", outcome["observed_at"])]
    timeline_values.extend(
        ("semantic assessment", item["observed_at"]) for item in assessments
    )
    if execution["status"] != "unknown":
        timeline_values.append(("execution observation", execution["observed_at"]))
    for label, observed_at in timeline_values:
        if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
            raise ShadowCaptureError(f"eligibility must be frozen before {label}")
        if _timestamp_value(observed_at) > _timestamp_value(captured_at):
            raise ShadowCaptureError(f"{label} must not occur after capture sealing")

    if (
        outcome.get("status") == "reviewed"
        and outcome.get("kind") == "task_correctness"
        and execution["status"] != "unknown"
    ):
        execution_at = execution["observed_at"]
        correctness_observations = [("outcome observation", outcome["observed_at"])]
        correctness_observations.extend(
            ("semantic assessment", item["observed_at"]) for item in assessments
        )
        for label, observed_at in correctness_observations:
            if _timestamp_value(execution_at) > _timestamp_value(observed_at):
                raise ShadowCaptureError(
                    f"task_correctness {label} must not precede terminal execution observation"
                )


def build_prospective_eligibility_v2(
    manifest: dict[str, Any],
    *,
    frozen_at: str,
    case_origin: str,
    capture_path: str = DIRECT_CAPTURE_PATH,
) -> dict[str, Any]:
    """Freeze a new provenance-observable case without mutating v1 history."""
    legacy = build_prospective_eligibility(manifest, frozen_at=frozen_at)
    payload = {
        "schema_version": PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION,
        "workspace_case": dict(legacy["workspace_case"]),
        "canonical_route_evidence": dict(legacy["canonical_route_evidence"]),
        "features": dict(legacy["features"]),
        "case_provenance": _normalize_case_provenance(
            {"case_origin": case_origin, "capture_path": capture_path}
        ),
        "frozen_at": legacy["frozen_at"],
        "no_effect": dict(NO_EFFECT),
    }
    receipt = {"prospective_eligibility_id": _sha256_json(payload), **payload}
    validate_prospective_eligibility_v2(receipt)
    return receipt

def validate_prospective_eligibility_v2(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != PROSPECTIVE_V2_FIELDS:
        raise ShadowCaptureError("prospective eligibility v2 receipt shape is invalid")
    if receipt.get("schema_version") != PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION:
        raise ShadowCaptureError("prospective eligibility v2 schema_version is invalid")
    receipt_id = receipt.get("prospective_eligibility_id")
    if not isinstance(receipt_id, str) or SHA256_RE.fullmatch(receipt_id) is None:
        raise ShadowCaptureError("prospective_eligibility_id is invalid")
    legacy_payload = {
        "schema_version": PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION,
        "workspace_case": receipt.get("workspace_case"),
        "canonical_route_evidence": receipt.get("canonical_route_evidence"),
        "features": receipt.get("features"),
        "frozen_at": receipt.get("frozen_at"),
        "no_effect": receipt.get("no_effect"),
    }
    validate_prospective_eligibility(
        {"prospective_eligibility_id": _sha256_json(legacy_payload), **legacy_payload}
    )
    _normalize_case_provenance(receipt.get("case_provenance"))
    payload = {key: receipt[key] for key in receipt if key != "prospective_eligibility_id"}
    if _sha256_json(payload) != receipt_id:
        raise ShadowCaptureError(
            "prospective_eligibility_id does not match the canonical v2 payload"
        )
    return receipt


def _validate_any_prospective(receipt: Any) -> dict[str, Any]:
    schema_version = receipt.get("schema_version") if isinstance(receipt, dict) else None
    if schema_version == PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION:
        return validate_prospective_eligibility(receipt)
    if schema_version == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION:
        return validate_prospective_eligibility_v2(receipt)
    raise ShadowCaptureError("unsupported prospective eligibility schema")


def _legacy_projection_from_prospective_v2(receipt: dict[str, Any]) -> dict[str, Any]:
    current = validate_prospective_eligibility_v2(receipt)
    payload = {
        "schema_version": PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION,
        "workspace_case": dict(current["workspace_case"]),
        "canonical_route_evidence": dict(current["canonical_route_evidence"]),
        "features": dict(current["features"]),
        "frozen_at": current["frozen_at"],
        "no_effect": dict(current["no_effect"]),
    }
    return {"prospective_eligibility_id": _sha256_json(payload), **payload}


def build_bound_eligibility_v2(
    prospective_receipt: dict[str, Any],
    manifest: dict[str, Any],
    *,
    eligible_task_id: str,
) -> dict[str, Any]:
    """Bind a pre-start eligibility freeze to the later real Grabowski task identity."""
    prospective = validate_prospective_eligibility(prospective_receipt)
    if prospective.get("schema_version") != PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility v2 requires prospective eligibility v1")
    if not isinstance(manifest, dict):
        raise ShadowCaptureError("manifest must be an object")
    workspace_case = prospective["workspace_case"]
    if manifest.get("workspace_id") != workspace_case["workspace_id"]:
        raise ShadowCaptureError(
            "manifest workspace does not match prospective eligibility"
        )
    if manifest.get("plan_sha256") != workspace_case["plan_sha256"]:
        raise ShadowCaptureError("manifest plan does not match prospective eligibility")
    if (
        not isinstance(eligible_task_id, str)
        or TASK_ID_RE.fullmatch(eligible_task_id) is None
    ):
        raise ShadowCaptureError("eligible_task_id must be a Grabowski task id")
    if eligible_task_id != _writer_task_reference(manifest):
        # The prospective route freeze describes the writer decision; v2 binds
        # only that routing-relevant task, never an arbitrary test/review id.
        raise ShadowCaptureError("eligible_task_id must be the workspace writer task")
    execution_surface = _manifest_execution_surface(manifest)
    route_source = _manifest_route_source(manifest)
    route = _validated_route_evidence(
        manifest.get("route_evidence"), execution_surface=execution_surface
    )
    current_route_ref = _cohort_route_reference(
        route,
        workspace_case["workspace_id"],
        workspace_case["plan_sha256"],
        route_source=route_source,
    )
    frozen_route_ref = prospective["canonical_route_evidence"]
    if current_route_ref != frozen_route_ref:
        raise ShadowCaptureError(
            "canonical route evidence changed after prospective freeze"
        )
    features = _bounded_features(route)
    if features != prospective["features"]:
        raise ShadowCaptureError(
            "allowlisted route features changed after prospective freeze"
        )
    payload = {
        "schema_version": ELIGIBILITY_V2_SCHEMA_VERSION,
        "prospective_eligibility": {
            "schema_version": PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION,
            "prospective_eligibility_id": prospective["prospective_eligibility_id"],
            "workspace_id": workspace_case["workspace_id"],
            "plan_sha256": workspace_case["plan_sha256"],
            "workspace_case_id": workspace_case["case_id"],
            "frozen_at": prospective["frozen_at"],
        },
        "eligible_case": {
            "task_id": eligible_task_id,
            "case_id": _case_id(eligible_task_id, route["recommendation_id"]),
        },
        "canonical_route_evidence": current_route_ref,
        "features": features,
        "frozen_at": prospective["frozen_at"],
        "no_effect": dict(NO_EFFECT),
    }
    receipt = {"eligibility_id": _sha256_json(payload), **payload}
    validate_bound_eligibility_v2(receipt)
    return receipt


def validate_bound_eligibility_v2(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != ELIGIBILITY_V2_FIELDS:
        raise ShadowCaptureError("eligibility v2 receipt shape is invalid")
    if receipt.get("schema_version") != ELIGIBILITY_V2_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility v2 schema_version is invalid")
    eligibility_id = receipt.get("eligibility_id")
    if (
        not isinstance(eligibility_id, str)
        or SHA256_RE.fullmatch(eligibility_id) is None
    ):
        raise ShadowCaptureError("eligibility_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        receipt.get("eligible_case"),
        receipt.get("canonical_route_evidence"),
        manifest_field="manifest_identity_sha256",
    )
    prospective = receipt.get("prospective_eligibility")
    if not isinstance(prospective, dict) or set(prospective) != {
        "schema_version",
        "prospective_eligibility_id",
        "workspace_id",
        "plan_sha256",
        "workspace_case_id",
        "frozen_at",
    }:
        raise ShadowCaptureError("prospective eligibility reference shape is invalid")
    if prospective.get("schema_version") != PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("prospective eligibility reference schema is invalid")
    for field in ("prospective_eligibility_id", "plan_sha256", "workspace_case_id"):
        value = prospective.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ShadowCaptureError(
                f"prospective eligibility reference {field} is invalid"
            )
    workspace_id = prospective.get("workspace_id")
    if (
        not isinstance(workspace_id, str)
        or workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None
    ):
        raise ShadowCaptureError("prospective eligibility workspace_id is invalid")
    frozen_at = _parse_timestamp(receipt.get("frozen_at"), "frozen_at")
    prospective_frozen_at = _parse_timestamp(
        prospective.get("frozen_at"), "prospective_eligibility.frozen_at"
    )
    if frozen_at != receipt.get(
        "frozen_at"
    ) or prospective_frozen_at != prospective.get("frozen_at"):
        raise ShadowCaptureError("eligibility v2 timestamps are not normalized")
    if frozen_at != prospective_frozen_at:
        raise ShadowCaptureError("eligibility v2 must preserve prospective frozen_at")
    _validate_features(
        receipt.get("features"), route_schema_version=route_schema_version
    )
    if receipt.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    _prove_prospective_binding(
        workspace_id=workspace_id,
        plan_sha256=prospective["plan_sha256"],
        workspace_case_id=prospective["workspace_case_id"],
        prospective_eligibility_id=prospective["prospective_eligibility_id"],
        route_ref=receipt["canonical_route_evidence"],
        features=receipt["features"],
        frozen_at=frozen_at,
        no_effect=receipt["no_effect"],
    )
    payload = {key: receipt[key] for key in receipt if key != "eligibility_id"}
    if _sha256_json(payload) != eligibility_id:
        raise ShadowCaptureError(
            "eligibility_id does not match the canonical eligibility v2 payload"
        )
    return receipt


def build_bound_eligibility_v3(
    prospective_receipt: dict[str, Any],
    manifest: dict[str, Any],
    *,
    eligible_task_id: str,
) -> dict[str, Any]:
    prospective = validate_prospective_eligibility_v2(prospective_receipt)
    legacy = _legacy_projection_from_prospective_v2(prospective)
    legacy_eligibility = build_bound_eligibility_v2(
        legacy, manifest, eligible_task_id=eligible_task_id
    )
    workspace_case = prospective["workspace_case"]
    payload = {
        "schema_version": ELIGIBILITY_V3_SCHEMA_VERSION,
        "prospective_eligibility": {
            "schema_version": PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION,
            "prospective_eligibility_id": prospective["prospective_eligibility_id"],
            "workspace_id": workspace_case["workspace_id"],
            "plan_sha256": workspace_case["plan_sha256"],
            "workspace_case_id": workspace_case["case_id"],
            "frozen_at": prospective["frozen_at"],
        },
        "eligible_case": dict(legacy_eligibility["eligible_case"]),
        "canonical_route_evidence": dict(legacy_eligibility["canonical_route_evidence"]),
        "features": dict(legacy_eligibility["features"]),
        "case_provenance": dict(prospective["case_provenance"]),
        "frozen_at": prospective["frozen_at"],
        "no_effect": dict(NO_EFFECT),
    }
    receipt = {"eligibility_id": _sha256_json(payload), **payload}
    validate_bound_eligibility_v3(receipt)
    return receipt


def validate_bound_eligibility_v3(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != ELIGIBILITY_V3_FIELDS:
        raise ShadowCaptureError("eligibility v3 receipt shape is invalid")
    if receipt.get("schema_version") != ELIGIBILITY_V3_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility v3 schema_version is invalid")
    eligibility_id = receipt.get("eligibility_id")
    if not isinstance(eligibility_id, str) or SHA256_RE.fullmatch(eligibility_id) is None:
        raise ShadowCaptureError("eligibility_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        receipt.get("eligible_case"),
        receipt.get("canonical_route_evidence"),
        manifest_field="manifest_identity_sha256",
    )
    _validate_features(receipt.get("features"), route_schema_version=route_schema_version)
    provenance = _normalize_case_provenance(receipt.get("case_provenance"))
    if provenance != receipt.get("case_provenance"):
        raise ShadowCaptureError("case_provenance is not normalized")
    prospective = receipt.get("prospective_eligibility")
    expected_ref = {
        "schema_version",
        "prospective_eligibility_id",
        "workspace_id",
        "plan_sha256",
        "workspace_case_id",
        "frozen_at",
    }
    if not isinstance(prospective, dict) or set(prospective) != expected_ref:
        raise ShadowCaptureError("prospective eligibility v2 reference shape is invalid")
    if prospective.get("schema_version") != PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION:
        raise ShadowCaptureError("prospective eligibility v2 reference schema is invalid")
    for field in ("prospective_eligibility_id", "plan_sha256", "workspace_case_id"):
        value = prospective.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ShadowCaptureError(f"prospective eligibility v2 reference {field} is invalid")
    workspace_id = prospective.get("workspace_id")
    if not isinstance(workspace_id, str) or workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None:
        raise ShadowCaptureError("prospective eligibility v2 workspace_id is invalid")
    frozen_at = _parse_timestamp(receipt.get("frozen_at"), "frozen_at")
    prospective_frozen_at = _parse_timestamp(
        prospective.get("frozen_at"), "prospective_eligibility.frozen_at"
    )
    if frozen_at != receipt.get("frozen_at") or prospective_frozen_at != prospective.get("frozen_at"):
        raise ShadowCaptureError("eligibility v3 timestamps are not normalized")
    if frozen_at != prospective_frozen_at:
        raise ShadowCaptureError("eligibility v3 must preserve prospective frozen_at")
    if receipt.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    _prove_prospective_binding(
        workspace_id=workspace_id,
        plan_sha256=prospective["plan_sha256"],
        workspace_case_id=prospective["workspace_case_id"],
        prospective_eligibility_id=prospective["prospective_eligibility_id"],
        route_ref=receipt["canonical_route_evidence"],
        features=receipt["features"],
        frozen_at=frozen_at,
        no_effect=receipt["no_effect"],
        prospective_schema_version=PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION,
        case_provenance=receipt["case_provenance"],
    )
    payload = {key: receipt[key] for key in receipt if key != "eligibility_id"}
    if _sha256_json(payload) != eligibility_id:
        raise ShadowCaptureError("eligibility_id does not match the canonical eligibility v3 payload")
    return receipt


def build_shadow_record_v2(
    eligibility_receipt: dict[str, Any],
    *,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    captured_at: str,
) -> dict[str, Any]:
    eligibility = validate_bound_eligibility_v2(eligibility_receipt)
    normalized_outcome = _normalize_outcome(outcome)
    refs = _normalize_evidence_refs(
        primary_evidence_refs,
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=True,
    )
    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")
    frozen_at = eligibility["frozen_at"]
    observed_at = normalized_outcome["observed_at"]
    if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
        raise ShadowCaptureError(
            "eligibility must be frozen before outcome observation"
        )
    if _timestamp_value(observed_at) > _timestamp_value(normalized_captured_at):
        raise ShadowCaptureError(
            "outcome observation must not occur after capture sealing"
        )
    prospective = eligibility["prospective_eligibility"]
    payload = {
        "schema_version": RECORD_V2_SCHEMA_VERSION,
        "eligibility": {
            "schema_version": ELIGIBILITY_V2_SCHEMA_VERSION,
            "eligibility_id": eligibility["eligibility_id"],
            "prospective_eligibility_id": prospective["prospective_eligibility_id"],
            "workspace_id": prospective["workspace_id"],
            "plan_sha256": prospective["plan_sha256"],
            "workspace_case_id": prospective["workspace_case_id"],
            "frozen_at": frozen_at,
        },
        "eligible_case": dict(eligibility["eligible_case"]),
        "canonical_route_evidence": dict(eligibility["canonical_route_evidence"]),
        "features": dict(eligibility["features"]),
        "outcome": normalized_outcome,
        "primary_evidence_refs": refs,
        "captured_at": normalized_captured_at,
        "no_effect": dict(NO_EFFECT),
    }
    record = {"record_id": _sha256_json(payload), **payload}
    validate_shadow_record_v2(record)
    return record


def validate_shadow_record_v2(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != RECORD_V2_FIELDS:
        raise ShadowCaptureError("shadow record v2 shape is invalid")
    if record.get("schema_version") != RECORD_V2_SCHEMA_VERSION:
        raise ShadowCaptureError("shadow record v2 schema_version is invalid")
    record_id = record.get("record_id")
    if not isinstance(record_id, str) or SHA256_RE.fullmatch(record_id) is None:
        raise ShadowCaptureError("record_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        record.get("eligible_case"),
        record.get("canonical_route_evidence"),
        manifest_field="manifest_identity_sha256",
    )
    _validate_features(
        record.get("features"), route_schema_version=route_schema_version
    )
    eligibility = record.get("eligibility")
    if not isinstance(eligibility, dict) or set(eligibility) != {
        "schema_version",
        "eligibility_id",
        "prospective_eligibility_id",
        "workspace_id",
        "plan_sha256",
        "workspace_case_id",
        "frozen_at",
    }:
        raise ShadowCaptureError("eligibility v2 reference shape is invalid")
    if eligibility.get("schema_version") != ELIGIBILITY_V2_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility v2 reference schema is invalid")
    for field in (
        "eligibility_id",
        "prospective_eligibility_id",
        "plan_sha256",
        "workspace_case_id",
    ):
        value = eligibility.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ShadowCaptureError(f"eligibility v2 reference {field} is invalid")
    workspace_id = eligibility.get("workspace_id")
    if (
        not isinstance(workspace_id, str)
        or workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None
    ):
        raise ShadowCaptureError("eligibility v2 reference workspace_id is invalid")
    frozen_at = _parse_timestamp(eligibility.get("frozen_at"), "eligibility.frozen_at")
    if frozen_at != eligibility.get("frozen_at"):
        raise ShadowCaptureError("eligibility.frozen_at is not normalized")
    normalized_outcome = _normalize_outcome(record.get("outcome"))
    if normalized_outcome != record.get("outcome"):
        raise ShadowCaptureError("outcome is not normalized")
    refs = _normalize_evidence_refs(
        record.get("primary_evidence_refs"),
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=True,
    )
    if refs != record.get("primary_evidence_refs"):
        raise ShadowCaptureError("primary_evidence_refs is not normalized")
    captured_at = _parse_timestamp(record.get("captured_at"), "captured_at")
    if captured_at != record.get("captured_at"):
        raise ShadowCaptureError("captured_at is not normalized")
    if _timestamp_value(frozen_at) > _timestamp_value(
        normalized_outcome["observed_at"]
    ):
        raise ShadowCaptureError(
            "eligibility must be frozen before outcome observation"
        )
    if _timestamp_value(normalized_outcome["observed_at"]) > _timestamp_value(
        captured_at
    ):
        raise ShadowCaptureError(
            "outcome observation must not occur after capture sealing"
        )
    if record.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    # Prove the full prospective -> eligibility-v2 -> record lineage: the record
    # carries the stable prospective identity fields, so both the eligibility v2
    # payload and the prospective payload can be reconstructed and re-hashed.
    _prove_prospective_binding(
        workspace_id=workspace_id,
        plan_sha256=eligibility["plan_sha256"],
        workspace_case_id=eligibility["workspace_case_id"],
        prospective_eligibility_id=eligibility["prospective_eligibility_id"],
        route_ref=record["canonical_route_evidence"],
        features=record["features"],
        frozen_at=frozen_at,
        no_effect=record["no_effect"],
    )
    reconstructed_eligibility = {
        "schema_version": ELIGIBILITY_V2_SCHEMA_VERSION,
        "prospective_eligibility": {
            "schema_version": PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION,
            "prospective_eligibility_id": eligibility["prospective_eligibility_id"],
            "workspace_id": workspace_id,
            "plan_sha256": eligibility["plan_sha256"],
            "workspace_case_id": eligibility["workspace_case_id"],
            "frozen_at": frozen_at,
        },
        "eligible_case": record["eligible_case"],
        "canonical_route_evidence": record["canonical_route_evidence"],
        "features": record["features"],
        "frozen_at": frozen_at,
        "no_effect": record["no_effect"],
    }
    if _sha256_json(reconstructed_eligibility) != eligibility["eligibility_id"]:
        raise ShadowCaptureError(
            "eligibility reference does not match the reconstructed eligibility "
            "v2 payload"
        )
    payload = {key: record[key] for key in record if key != "record_id"}
    if _sha256_json(payload) != record_id:
        raise ShadowCaptureError(
            "record_id does not match the canonical record v2 payload"
        )
    return record


def build_shadow_record_v3(
    eligibility_receipt: dict[str, Any],
    *,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    execution_provenance: dict[str, Any] | None,
    semantic_assessments: list[dict[str, Any]] | None,
    captured_at: str,
) -> dict[str, Any]:
    eligibility = validate_bound_eligibility_v3(eligibility_receipt)
    normalized_outcome = _normalize_outcome(outcome)
    refs = _normalize_evidence_refs(
        primary_evidence_refs,
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=True,
    )
    execution = _normalize_execution_provenance(execution_provenance)
    assessments = _normalize_semantic_assessments(semantic_assessments)
    if assessments:
        if normalized_outcome.get("status") != "reviewed":
            raise ShadowCaptureError(
                "semantic assessments require a reviewed primary outcome"
            )
        if assessments[0]["kind"] != normalized_outcome["kind"]:
            raise ShadowCaptureError(
                "semantic assessments must address the reviewed outcome kind"
            )
    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")
    frozen_at = eligibility["frozen_at"]
    _validate_v3_timeline(
        frozen_at=frozen_at,
        outcome=normalized_outcome,
        execution=execution,
        assessments=assessments,
        captured_at=normalized_captured_at,
    )
    prospective = eligibility["prospective_eligibility"]
    payload = {
        "schema_version": RECORD_V3_SCHEMA_VERSION,
        "eligibility": {
            "schema_version": ELIGIBILITY_V3_SCHEMA_VERSION,
            "eligibility_id": eligibility["eligibility_id"],
            "prospective_eligibility_id": prospective["prospective_eligibility_id"],
            "workspace_id": prospective["workspace_id"],
            "plan_sha256": prospective["plan_sha256"],
            "workspace_case_id": prospective["workspace_case_id"],
            "frozen_at": frozen_at,
        },
        "eligible_case": dict(eligibility["eligible_case"]),
        "canonical_route_evidence": dict(eligibility["canonical_route_evidence"]),
        "features": dict(eligibility["features"]),
        "case_provenance": dict(eligibility["case_provenance"]),
        "outcome": normalized_outcome,
        "primary_evidence_refs": refs,
        "execution_provenance": execution,
        "semantic_assessments": assessments,
        "captured_at": normalized_captured_at,
        "no_effect": dict(NO_EFFECT),
    }
    record = {"record_id": _sha256_json(payload), **payload}
    validate_shadow_record_v3(record)
    return record


def validate_shadow_record_v3(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != RECORD_V3_FIELDS:
        raise ShadowCaptureError("shadow record v3 shape is invalid")
    if record.get("schema_version") != RECORD_V3_SCHEMA_VERSION:
        raise ShadowCaptureError("shadow record v3 schema_version is invalid")
    record_id = record.get("record_id")
    if not isinstance(record_id, str) or SHA256_RE.fullmatch(record_id) is None:
        raise ShadowCaptureError("record_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        record.get("eligible_case"),
        record.get("canonical_route_evidence"),
        manifest_field="manifest_identity_sha256",
    )
    _validate_features(record.get("features"), route_schema_version=route_schema_version)
    provenance = _normalize_case_provenance(record.get("case_provenance"))
    if provenance != record.get("case_provenance"):
        raise ShadowCaptureError("case_provenance is not normalized")
    normalized_outcome = _normalize_outcome(record.get("outcome"))
    if normalized_outcome != record.get("outcome"):
        raise ShadowCaptureError("outcome is not normalized")
    refs = _normalize_evidence_refs(
        record.get("primary_evidence_refs"),
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=True,
    )
    if refs != record.get("primary_evidence_refs"):
        raise ShadowCaptureError("primary_evidence_refs is not normalized")
    execution = _normalize_execution_provenance(record.get("execution_provenance"))
    if execution != record.get("execution_provenance"):
        raise ShadowCaptureError("execution_provenance is not normalized")
    assessments = _normalize_semantic_assessments(record.get("semantic_assessments"))
    if assessments != record.get("semantic_assessments"):
        raise ShadowCaptureError("semantic_assessments are not normalized")
    if assessments:
        if normalized_outcome.get("status") != "reviewed":
            raise ShadowCaptureError(
                "semantic assessments require a reviewed primary outcome"
            )
        if assessments[0]["kind"] != normalized_outcome["kind"]:
            raise ShadowCaptureError(
                "semantic assessments must address the reviewed outcome kind"
            )
    eligibility = record.get("eligibility")
    expected_ref = {
        "schema_version",
        "eligibility_id",
        "prospective_eligibility_id",
        "workspace_id",
        "plan_sha256",
        "workspace_case_id",
        "frozen_at",
    }
    if not isinstance(eligibility, dict) or set(eligibility) != expected_ref:
        raise ShadowCaptureError("eligibility v3 reference shape is invalid")
    if eligibility.get("schema_version") != ELIGIBILITY_V3_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility v3 reference schema is invalid")
    for field in ("eligibility_id", "prospective_eligibility_id", "plan_sha256", "workspace_case_id"):
        value = eligibility.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ShadowCaptureError(f"eligibility v3 reference {field} is invalid")
    workspace_id = eligibility.get("workspace_id")
    if not isinstance(workspace_id, str) or workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None:
        raise ShadowCaptureError("eligibility v3 reference workspace_id is invalid")
    frozen_at = _parse_timestamp(eligibility.get("frozen_at"), "eligibility.frozen_at")
    captured_at = _parse_timestamp(record.get("captured_at"), "captured_at")
    if frozen_at != eligibility.get("frozen_at") or captured_at != record.get("captured_at"):
        raise ShadowCaptureError("record v3 timestamps are not normalized")
    _validate_v3_timeline(
        frozen_at=frozen_at,
        outcome=normalized_outcome,
        execution=execution,
        assessments=assessments,
        captured_at=captured_at,
    )
    if record.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    _prove_prospective_binding(
        workspace_id=workspace_id,
        plan_sha256=eligibility["plan_sha256"],
        workspace_case_id=eligibility["workspace_case_id"],
        prospective_eligibility_id=eligibility["prospective_eligibility_id"],
        route_ref=record["canonical_route_evidence"],
        features=record["features"],
        frozen_at=frozen_at,
        no_effect=record["no_effect"],
        prospective_schema_version=PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION,
        case_provenance=record["case_provenance"],
    )
    reconstructed_eligibility = {
        "schema_version": ELIGIBILITY_V3_SCHEMA_VERSION,
        "prospective_eligibility": {
            "schema_version": PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION,
            "prospective_eligibility_id": eligibility["prospective_eligibility_id"],
            "workspace_id": workspace_id,
            "plan_sha256": eligibility["plan_sha256"],
            "workspace_case_id": eligibility["workspace_case_id"],
            "frozen_at": frozen_at,
        },
        "eligible_case": record["eligible_case"],
        "canonical_route_evidence": record["canonical_route_evidence"],
        "features": record["features"],
        "case_provenance": record["case_provenance"],
        "frozen_at": frozen_at,
        "no_effect": record["no_effect"],
    }
    if _sha256_json(reconstructed_eligibility) != eligibility["eligibility_id"]:
        raise ShadowCaptureError("eligibility reference does not match the reconstructed eligibility v3 payload")
    payload = {key: record[key] for key in record if key != "record_id"}
    if _sha256_json(payload) != record_id:
        raise ShadowCaptureError("record_id does not match the canonical record v3 payload")
    return record


def _validate_any_record(record: Any) -> dict[str, Any]:
    schema_version = record.get("schema_version") if isinstance(record, dict) else None
    if schema_version == RECORD_V2_SCHEMA_VERSION:
        return validate_shadow_record_v2(record)
    if schema_version == RECORD_V3_SCHEMA_VERSION:
        return validate_shadow_record_v3(record)
    raise ShadowCaptureError("unsupported sealed shadow record schema")


def _validate_new_capture_payload(record: dict[str, Any]) -> None:
    schema_version = record.get("schema_version") if isinstance(record, dict) else None
    if schema_version == PROSPECTIVE_ELIGIBILITY_SCHEMA_VERSION:
        validate_prospective_eligibility(record)
    elif schema_version == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION:
        validate_prospective_eligibility_v2(record)
    elif schema_version == ELIGIBILITY_V2_SCHEMA_VERSION:
        validate_bound_eligibility_v2(record)
    elif schema_version == ELIGIBILITY_V3_SCHEMA_VERSION:
        validate_bound_eligibility_v3(record)
    elif schema_version == RECORD_V2_SCHEMA_VERSION:
        validate_shadow_record_v2(record)
    elif schema_version == RECORD_V3_SCHEMA_VERSION:
        validate_shadow_record_v3(record)
    elif schema_version == CAPTURE_ATTEMPT_SCHEMA_VERSION:
        _validate_capture_attempt(record)
    else:
        raise ShadowCaptureError("unsupported prospective capture schema")


def write_new_capture_create_only(path: Path, record: dict[str, Any]) -> None:
    _validate_new_capture_payload(record)
    candidate = _absolute_unresolved(path)
    parent_descriptor = _open_directory_fd(candidate.parent)
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        _publish_create_only(
            parent_descriptor,
            candidate.name,
            data,
            conflict_message=(
                "refusing to overwrite an existing prospective capture record"
            ),
        )
    finally:
        os.close(parent_descriptor)


def write_new_capture_idempotent(path: Path, record: dict[str, Any]) -> bool:
    """Create one record, or accept an exact already-present record without updating it."""
    try:
        write_new_capture_create_only(path, record)
        return True
    except ShadowRecordExistsError:
        pass
    existing = _read_regular_json(path, label="existing prospective capture record")
    _validate_new_capture_payload(existing)
    if existing != record:
        raise ShadowCaptureError(
            "existing prospective capture record conflicts with deterministic identity"
        )
    return False


def write_prospective_identity_idempotent(
    path: Path, receipt: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    """Preserve the first real freeze timestamp for one deterministic workspace case."""
    _validate_any_prospective(receipt)
    try:
        write_new_capture_create_only(path, receipt)
        return receipt, True
    except ShadowRecordExistsError:
        pass
    existing = _read_regular_json(path, label="existing prospective eligibility")
    _validate_any_prospective(existing)
    if existing["workspace_case"] != receipt["workspace_case"]:
        raise ShadowCaptureError(
            "existing prospective eligibility conflicts with deterministic case identity"
        )
    existing_route = existing["canonical_route_evidence"]
    candidate_route = receipt["canonical_route_evidence"]
    route_identity_fields = (
        "source",
        "schema_version",
        "recommendation_id",
        "route_evidence_sha256",
    )
    if any(
        existing_route[field] != candidate_route[field]
        for field in route_identity_fields
    ):
        raise ShadowCaptureError(
            "existing prospective eligibility conflicts with canonical route identity"
        )
    if (
        existing["features"] != receipt["features"]
        or existing["no_effect"] != receipt["no_effect"]
    ):
        raise ShadowCaptureError(
            "existing prospective eligibility conflicts with deterministic case features"
        )
    if (
        existing.get("schema_version") == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION
        and receipt.get("schema_version") == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION
        and existing["case_provenance"] != receipt["case_provenance"]
    ):
        raise ShadowCaptureError(
            "existing prospective eligibility conflicts with frozen case provenance"
        )
    # A pre-upgrade v1 freeze wins unchanged. Its missing provenance remains
    # explicitly unobservable rather than being backfilled after the fact.
    return existing, False


def _ensure_private_child(parent: Path, name: str) -> Path:
    if not name or "/" in name or name in {".", ".."}:
        raise ShadowCaptureError("private capture directory name is invalid")
    parent_descriptor = _open_directory_fd(parent)
    child_descriptor: int | None = None
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        child_descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(child_descriptor)
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ShadowCaptureError("private capture directory is not owner-private")
    except OSError as exc:
        raise ShadowCaptureError(
            "private capture directory is unavailable or unsafe"
        ) from exc
    finally:
        if child_descriptor is not None:
            os.close(child_descriptor)
        os.close(parent_descriptor)
    return parent / name


def _cohort_directories(root: Path) -> tuple[Path, Path, Path, Path]:
    candidate = _absolute_unresolved(root)
    parent = candidate.parent
    if not parent.exists():
        raise ShadowCaptureError("prospective cohort root parent must already exist")
    root_path = _ensure_private_child(parent, candidate.name)
    prospective = _ensure_private_child(root_path, "prospective")
    eligibility = _ensure_private_child(root_path, "eligibility")
    records = _ensure_private_child(root_path, "records")
    attempts = _ensure_private_child(root_path, "attempts")
    return prospective, eligibility, records, attempts


ATTEMPT_STAGE = "prospective_eligibility_freeze"


def _attempt_identity_id(
    *,
    workspace_id: str,
    plan_sha256: str,
    status: str,
    reason_code: str,
    prospective_eligibility_id: str | None,
) -> str:
    """Stable attempt identity that deliberately excludes ``attempted_at``.

    Repeated identical rejects/duplicates therefore collapse onto one file
    instead of minting a fresh attempt per retry timestamp.
    """
    return _sha256_json(
        {
            "schema_version": "operator-routing-shadow-capture-attempt-identity.v1",
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "stage": ATTEMPT_STAGE,
            "status": status,
            "reason_code": reason_code,
            "prospective_eligibility_id": prospective_eligibility_id,
        }
    )


def _capture_attempt(
    *,
    workspace_id: str,
    plan_sha256: str,
    status: str,
    reason_code: str,
    prospective_eligibility_id: str | None,
    attempted_at: str,
) -> dict[str, Any]:
    if status not in ATTEMPT_STATUSES:
        raise ShadowCaptureError("capture attempt status is invalid")
    attempt_id = _attempt_identity_id(
        workspace_id=workspace_id,
        plan_sha256=plan_sha256,
        status=status,
        reason_code=reason_code,
        prospective_eligibility_id=prospective_eligibility_id,
    )
    return {
        "schema_version": CAPTURE_ATTEMPT_SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "workspace_id": workspace_id,
        "plan_sha256": plan_sha256,
        "stage": ATTEMPT_STAGE,
        "status": status,
        "reason_code": reason_code,
        "prospective_eligibility_id": prospective_eligibility_id,
        "attempted_at": _parse_timestamp(attempted_at, "attempted_at"),
        "no_effect": dict(NO_EFFECT),
    }


def _validate_capture_attempt(record: Any) -> dict[str, Any]:
    expected = {
        "schema_version",
        "attempt_id",
        "workspace_id",
        "plan_sha256",
        "stage",
        "status",
        "reason_code",
        "prospective_eligibility_id",
        "attempted_at",
        "no_effect",
    }
    if not isinstance(record, dict) or set(record) != expected:
        raise ShadowCaptureError("capture attempt shape is invalid")
    if record.get("schema_version") != CAPTURE_ATTEMPT_SCHEMA_VERSION:
        raise ShadowCaptureError("capture attempt schema_version is invalid")
    if (
        record.get("stage") != ATTEMPT_STAGE
        or record.get("status") not in ATTEMPT_STATUSES
    ):
        raise ShadowCaptureError("capture attempt stage or status is invalid")
    if (
        not isinstance(record.get("workspace_id"), str)
        or workspace.WORKSPACE_ID_RE.fullmatch(record["workspace_id"]) is None
    ):
        raise ShadowCaptureError("capture attempt workspace_id is invalid")
    if (
        not isinstance(record.get("plan_sha256"), str)
        or SHA256_RE.fullmatch(record["plan_sha256"]) is None
    ):
        raise ShadowCaptureError("capture attempt plan_sha256 is invalid")
    reason = record.get("reason_code")
    if (
        not isinstance(reason, str)
        or not 1 <= len(reason) <= 80
        or not re.fullmatch(r"[a-z0-9_]+", reason)
    ):
        raise ShadowCaptureError("capture attempt reason_code is invalid")
    prospective_id = record.get("prospective_eligibility_id")
    if prospective_id is not None and (
        not isinstance(prospective_id, str)
        or SHA256_RE.fullmatch(prospective_id) is None
    ):
        raise ShadowCaptureError(
            "capture attempt prospective_eligibility_id is invalid"
        )
    attempted_at = _parse_timestamp(record.get("attempted_at"), "attempted_at")
    if attempted_at != record.get("attempted_at"):
        raise ShadowCaptureError("capture attempt timestamp is not normalized")
    if record.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    expected_id = _attempt_identity_id(
        workspace_id=record["workspace_id"],
        plan_sha256=record["plan_sha256"],
        status=record["status"],
        reason_code=reason,
        prospective_eligibility_id=prospective_id,
    )
    if expected_id != record.get("attempt_id"):
        raise ShadowCaptureError("capture attempt id does not match canonical identity")
    return record


def write_attempt_identity_idempotent(path: Path, attempt: dict[str, Any]) -> bool:
    """Create one attempt receipt, or accept a same-identity one unchanged.

    Two attempts sharing the stable identity differ only by ``attempted_at``;
    the first written timestamp wins and later retries are duplicates, so a
    workspace that keeps rejecting for the same reason cannot grow files.
    """
    _validate_capture_attempt(attempt)
    try:
        write_new_capture_create_only(path, attempt)
        return True
    except ShadowRecordExistsError:
        pass
    existing = _read_regular_json(path, label="existing capture attempt")
    _validate_capture_attempt(existing)
    if existing["attempt_id"] != attempt["attempt_id"]:
        raise ShadowCaptureError(
            "existing capture attempt conflicts with deterministic identity"
        )
    return False


def seal_prospective_case(
    prospective_receipt: dict[str, Any],
    manifest: dict[str, Any],
    *,
    eligible_task_id: str,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    root: Path,
    captured_at: str | None = None,
    execution_provenance: dict[str, Any] | None | object = _UNSET,
    semantic_assessments: list[dict[str, Any]] | None | object = _UNSET,
) -> dict[str, Any]:
    """Bind and seal one prospective case without deriving or changing its outcome."""
    prospective_dir, eligibility_dir, records_dir, _ = _cohort_directories(root)
    prospective = _validate_any_prospective(prospective_receipt)
    stored_path = prospective_dir / f"{prospective['workspace_case']['case_id']}.json"
    try:
        stored_path.lstat()
    except FileNotFoundError as exc:
        raise ShadowCaptureError(
            "prospective eligibility is not present in the create-only cohort store"
        ) from exc
    stored_prospective = _read_regular_json(
        stored_path, label="stored prospective eligibility"
    )
    _validate_any_prospective(stored_prospective)
    if stored_prospective != prospective:
        raise ShadowCaptureError(
            "prospective eligibility does not match the create-only stored freeze"
        )
    latest_contract = (
        stored_prospective["schema_version"]
        == PROSPECTIVE_ELIGIBILITY_V2_SCHEMA_VERSION
    )
    execution_provided = execution_provenance is not _UNSET
    assessments_provided = semantic_assessments is not _UNSET
    if latest_contract:
        eligibility = build_bound_eligibility_v3(
            stored_prospective, manifest, eligible_task_id=eligible_task_id
        )
    else:
        if (execution_provided and execution_provenance is not None) or (
            assessments_provided and semantic_assessments is not None
        ):
            raise ShadowCaptureError(
                "legacy prospective cases cannot be backfilled with v3 observability"
            )
        eligibility = build_bound_eligibility_v2(
            stored_prospective, manifest, eligible_task_id=eligible_task_id
        )
    case_id = eligibility["eligible_case"]["case_id"]
    eligibility_path = eligibility_dir / f"{case_id}.json"
    record_path = records_dir / f"{case_id}.json"

    normalized_outcome = _normalize_outcome(outcome)
    refs = _normalize_evidence_refs(
        primary_evidence_refs,
        reviewed=normalized_outcome["status"] == "reviewed",
        sort=True,
    )
    normalized_execution = _normalize_execution_provenance(
        None if not execution_provided else execution_provenance
    )
    normalized_assessments = _normalize_semantic_assessments(
        None if not assessments_provided else semantic_assessments
    )

    try:
        record_path.lstat()
    except FileNotFoundError:
        existing = None
    else:
        existing = _read_regular_json(
            record_path, label="existing sealed shadow record"
        )
    if existing is not None:
        _validate_any_record(existing)
        conflicts = (
            existing["eligible_case"] != eligibility["eligible_case"]
            or existing["eligibility"]["eligibility_id"] != eligibility["eligibility_id"]
            or existing["outcome"] != normalized_outcome
            or existing["primary_evidence_refs"] != refs
        )
        if latest_contract:
            conflicts = conflicts or (
                existing.get("schema_version") != RECORD_V3_SCHEMA_VERSION
                or existing.get("case_provenance") != eligibility["case_provenance"]
            )
            if execution_provided:
                conflicts = conflicts or (
                    existing.get("execution_provenance") != normalized_execution
                )
            if assessments_provided:
                conflicts = conflicts or (
                    existing.get("semantic_assessments") != normalized_assessments
                )
        if conflicts:
            raise ShadowCaptureError(
                "existing sealed shadow record conflicts with the requested case or outcome"
            )
        eligibility_created = write_new_capture_idempotent(
            eligibility_path, eligibility
        )
        return {
            "schema_version": 1,
            "status": "duplicate",
            "eligibility_created": eligibility_created,
            "eligibility_id": eligibility["eligibility_id"],
            "record_id": existing["record_id"],
            "record_schema_version": existing["schema_version"],
            "case_id": case_id,
            "no_effect": dict(NO_EFFECT),
        }

    if latest_contract:
        record = build_shadow_record_v3(
            eligibility,
            outcome=normalized_outcome,
            primary_evidence_refs=refs,
            execution_provenance=normalized_execution,
            semantic_assessments=normalized_assessments,
            captured_at=captured_at or _utc_now(),
        )
    else:
        record = build_shadow_record_v2(
            eligibility,
            outcome=normalized_outcome,
            primary_evidence_refs=refs,
            captured_at=captured_at or _utc_now(),
        )

    eligibility_created = write_new_capture_idempotent(eligibility_path, eligibility)
    write_new_capture_create_only(record_path, record)
    return {
        "schema_version": 1,
        "status": "created",
        "eligibility_created": eligibility_created,
        "eligibility_id": eligibility["eligibility_id"],
        "record_id": record["record_id"],
        "record_schema_version": record["schema_version"],
        "case_id": case_id,
        "no_effect": dict(NO_EFFECT),
    }

def _capture_reason(exc: BaseException) -> str:
    text = str(exc).lower()
    if "route evidence" in text:
        return "ineligible_route_evidence"
    if "before workspace tasks" in text:
        return "task_already_bound"
    if "workspace_id" in text or "plan_sha256" in text:
        return "invalid_workspace_identity"
    if "directory" in text or "output path" in text or "overwrite" in text:
        return "storage_failure"
    return "capture_error"


def capture_workspace_eligibility_best_effort(
    manifest: dict[str, Any],
    *,
    root: Path | None = None,
    frozen_at: str | None = None,
    case_origin: str | None = None,
    prestart_attestation: object | None = None,
) -> dict[str, Any]:
    """Best-effort pre-start freeze. Never raises into workspace execution."""
    enabled = (
        os.environ.get("GRABOWSKI_ROUTING_SHADOW_COHORT_ENABLED", "1").strip().lower()
    )
    if enabled in {"0", "false", "no", "off"}:
        return {
            "schema_version": 1,
            "status": "disabled",
            "reason_code": "capture_disabled",
            "no_effect": dict(NO_EFFECT),
        }
    attempted_at = frozen_at or _utc_now()
    workspace_id = manifest.get("workspace_id") if isinstance(manifest, dict) else None
    plan_sha256 = manifest.get("plan_sha256") if isinstance(manifest, dict) else None
    cohort_root = root or Path(
        os.environ.get(
            "GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT",
            str(Path.home() / ".local/state/grabowski/operator-routing-shadow-cohort"),
        )
    )
    prospective_dir: Path | None = None
    attempts_dir: Path | None = None
    try:
        prospective_dir, _, _, attempts_dir = _cohort_directories(cohort_root)
        workspace_prestart = prestart_attestation is _WORKSPACE_PRESTART_ATTESTATION
        direct_task_prestart = prestart_attestation is _DIRECT_TASK_PRESTART_ATTESTATION
        trusted_prestart = workspace_prestart or direct_task_prestart
        resolved_capture_path = (
            WORKSPACE_PRESTART_CAPTURE_PATH
            if workspace_prestart
            else DIRECT_TASK_PRESTART_CAPTURE_PATH
            if direct_task_prestart
            else DIRECT_CAPTURE_PATH
        )
        resolved_case_origin = (
            (
                case_origin
                if case_origin is not None
                else ("production" if trusted_prestart else "synthetic")
            )
            .strip()
            .lower()
        )
        if not trusted_prestart and resolved_case_origin == "production":
            resolved_case_origin = "quarantined"
        receipt = build_prospective_eligibility_v2(
            manifest,
            frozen_at=attempted_at,
            case_origin=resolved_case_origin,
            capture_path=resolved_capture_path,
        )
        case_id = receipt["workspace_case"]["case_id"]
        receipt, created = write_prospective_identity_idempotent(
            prospective_dir / f"{case_id}.json", receipt
        )
        status = "created" if created else "duplicate"
        attempt = _capture_attempt(
            workspace_id=receipt["workspace_case"]["workspace_id"],
            plan_sha256=receipt["workspace_case"]["plan_sha256"],
            status=status,
            reason_code="eligible_verified_route",
            prospective_eligibility_id=receipt["prospective_eligibility_id"],
            attempted_at=attempted_at,
        )
        attempt_id: str | None = attempt["attempt_id"]
        attempt_audit_status = "unavailable"
        try:
            attempt_created = write_attempt_identity_idempotent(
                attempts_dir / f"{attempt['attempt_id']}.json", attempt
            )
            attempt_audit_status = "created" if attempt_created else "duplicate"
        except Exception:
            attempt_id = None
        return {
            "schema_version": 1,
            "status": status,
            "reason_code": "eligible_verified_route",
            "prospective_eligibility_id": receipt["prospective_eligibility_id"],
            "workspace_case_id": case_id,
            "attempt_id": attempt_id,
            "attempt_audit_status": attempt_audit_status,
            "no_effect": dict(NO_EFFECT),
        }
    except Exception as exc:
        reason = _capture_reason(exc)
        attempt_id = None
        audit_status = "unavailable"
        if (
            attempts_dir is not None
            and isinstance(workspace_id, str)
            and workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is not None
            and isinstance(plan_sha256, str)
            and SHA256_RE.fullmatch(plan_sha256) is not None
        ):
            try:
                attempt = _capture_attempt(
                    workspace_id=workspace_id,
                    plan_sha256=plan_sha256,
                    status="rejected"
                    if isinstance(exc, ShadowCaptureError)
                    else "error",
                    reason_code=reason,
                    prospective_eligibility_id=None,
                    attempted_at=attempted_at,
                )
                attempt_created = write_attempt_identity_idempotent(
                    attempts_dir / f"{attempt['attempt_id']}.json", attempt
                )
                attempt_id = attempt["attempt_id"]
                audit_status = "created" if attempt_created else "duplicate"
            except Exception:
                pass
        return {
            "schema_version": 1,
            "status": "rejected" if isinstance(exc, ShadowCaptureError) else "error",
            "reason_code": reason,
            "attempt_id": attempt_id,
            "attempt_audit_status": audit_status,
            "no_effect": dict(NO_EFFECT),
        }


def _direct_task_binding_directory(root: Path) -> Path:
    candidate = _absolute_unresolved(root)
    parent = candidate.parent
    if not parent.exists():
        raise ShadowCaptureError("prospective cohort root parent must already exist")
    root_path = _ensure_private_child(parent, candidate.name)
    return _ensure_private_child(root_path, "direct-task-bindings")

def _direct_task_workspace_id(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise ShadowCaptureError("direct task id is invalid")
    workspace_id = f"gaw-direct-task-{task_id}"
    if workspace.WORKSPACE_ID_RE.fullmatch(workspace_id) is None:
        raise ShadowCaptureError("direct task workspace identity is invalid")
    return workspace_id

def _direct_task_identity(
    *,
    host: str,
    argv_sha256: str,
    cwd: str,
    resource_keys: list[str],
    runtime_seconds: int,
) -> dict[str, Any]:
    if not isinstance(host, str) or not 1 <= len(host) <= 255:
        raise ShadowCaptureError("direct task host is invalid")
    if not isinstance(argv_sha256, str) or SHA256_RE.fullmatch(argv_sha256) is None:
        raise ShadowCaptureError("direct task argv_sha256 is invalid")
    if not isinstance(cwd, str) or not cwd or len(cwd) > 4096:
        raise ShadowCaptureError("direct task cwd is invalid")
    if (
        not isinstance(resource_keys, list)
        or len(resource_keys) > 128
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 4096
            for item in resource_keys
        )
    ):
        raise ShadowCaptureError("direct task resource keys are invalid")
    if (
        isinstance(runtime_seconds, bool)
        or not isinstance(runtime_seconds, int)
        or not 1 <= runtime_seconds <= 604800
    ):
        raise ShadowCaptureError("direct task runtime_seconds is invalid")
    return {
        "host_sha256": hashlib.sha256(host.encode("utf-8")).hexdigest(),
        "argv_sha256": argv_sha256,
        "cwd_sha256": hashlib.sha256(cwd.encode("utf-8")).hexdigest(),
        "resource_keys_sha256": _sha256_json(sorted(set(resource_keys))),
        "runtime_seconds": runtime_seconds,
    }

def _direct_task_plan_sha256(
    task_id: str, task_identity: dict[str, Any], route: dict[str, Any]
) -> str:
    return _sha256_json(
        {
            "schema_version": "operator-routing-shadow-direct-task-plan.v1",
            "task_id": task_id,
            "task_identity": task_identity,
            "route_evidence_sha256": _sha256_json(route),
        }
    )

def _direct_task_manifest(
    *,
    task_id: str,
    plan_sha256: str,
    route: dict[str, Any],
    writer_bound: bool,
) -> dict[str, Any]:
    return {
        "workspace_id": _direct_task_workspace_id(task_id),
        "plan_sha256": plan_sha256,
        "routing_surface": "direct_task",
        "route_evidence": route,
        "tasks": {
            "writer": task_id if writer_bound else None,
            "tests": None,
            "review": None,
        },
    }

def validate_direct_task_binding(value: Any) -> dict[str, Any]:
    expected = {
        "schema_version",
        "binding_id",
        "task_id",
        "workspace_id",
        "plan_sha256",
        "task_identity",
        "route_evidence",
        "prospective",
        "created_at",
        "no_effect",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ShadowCaptureError("direct task binding shape is invalid")
    if value.get("schema_version") != DIRECT_TASK_BINDING_SCHEMA_VERSION:
        raise ShadowCaptureError("direct task binding schema_version is invalid")
    task_id = value.get("task_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise ShadowCaptureError("direct task binding task_id is invalid")
    if value.get("workspace_id") != _direct_task_workspace_id(task_id):
        raise ShadowCaptureError("direct task binding workspace_id is invalid")
    plan_sha256 = value.get("plan_sha256")
    if not isinstance(plan_sha256, str) or SHA256_RE.fullmatch(plan_sha256) is None:
        raise ShadowCaptureError("direct task binding plan_sha256 is invalid")
    identity = value.get("task_identity")
    identity_fields = {
        "host_sha256",
        "argv_sha256",
        "cwd_sha256",
        "resource_keys_sha256",
        "runtime_seconds",
    }
    if not isinstance(identity, dict) or set(identity) != identity_fields:
        raise ShadowCaptureError("direct task binding task_identity is invalid")
    for field in identity_fields - {"runtime_seconds"}:
        item = identity.get(field)
        if not isinstance(item, str) or SHA256_RE.fullmatch(item) is None:
            raise ShadowCaptureError(f"direct task binding {field} is invalid")
    runtime_seconds = identity.get("runtime_seconds")
    if (
        isinstance(runtime_seconds, bool)
        or not isinstance(runtime_seconds, int)
        or not 1 <= runtime_seconds <= 604800
    ):
        raise ShadowCaptureError("direct task binding runtime_seconds is invalid")
    route = _validated_route_evidence(
        value.get("route_evidence"), execution_surface="direct_task"
    )
    if route != value.get("route_evidence"):
        raise ShadowCaptureError("direct task binding route evidence is not normalized")
    if plan_sha256 != _direct_task_plan_sha256(task_id, identity, route):
        raise ShadowCaptureError("direct task binding plan identity is invalid")
    prospective = value.get("prospective")
    if not isinstance(prospective, dict) or set(prospective) != {
        "status",
        "prospective_eligibility_id",
        "workspace_case_id",
    }:
        raise ShadowCaptureError("direct task binding prospective reference is invalid")
    if prospective.get("status") != "created":
        raise ShadowCaptureError("direct task binding prospective status is invalid")
    for field in ("prospective_eligibility_id", "workspace_case_id"):
        item = prospective.get(field)
        if not isinstance(item, str) or SHA256_RE.fullmatch(item) is None:
            raise ShadowCaptureError(f"direct task binding {field} is invalid")
    created_at = _parse_timestamp(
        value.get("created_at"), "direct_task_binding.created_at"
    )
    if created_at != value.get("created_at"):
        raise ShadowCaptureError("direct task binding created_at is not normalized")
    if value.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("direct task binding no_effect boundary is invalid")
    payload = {key: item for key, item in value.items() if key != "binding_id"}
    binding_id = value.get("binding_id")
    if not isinstance(binding_id, str) or binding_id != _sha256_json(payload):
        raise ShadowCaptureError("direct task binding_id is invalid")
    return value

def _write_direct_task_binding_idempotent(
    path: Path, binding: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    """Create one binding or preserve the first timestamp for the same identity."""
    validate_direct_task_binding(binding)
    candidate = _absolute_unresolved(path)
    parent_descriptor = _open_directory_fd(candidate.parent)
    data = (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        try:
            _publish_create_only(
                parent_descriptor,
                candidate.name,
                data,
                conflict_message="refusing to overwrite an existing direct task binding",
            )
            return binding, True
        except ShadowRecordExistsError:
            pass
    finally:
        os.close(parent_descriptor)
    existing = _read_regular_json(path, label="existing direct task binding")
    validate_direct_task_binding(existing)
    identity_fields = set(binding) - {"binding_id", "created_at"}
    if any(existing[field] != binding[field] for field in identity_fields):
        raise ShadowCaptureError(
            "existing direct task binding conflicts with deterministic identity"
        )
    return existing, False

def capture_direct_task_start_best_effort(
    *,
    task_id: str,
    route_evidence: dict[str, Any],
    host: str,
    argv_sha256: str,
    cwd: str,
    resource_keys: list[str],
    runtime_seconds: int,
    root: Path | None = None,
    frozen_at: str | None = None,
) -> dict[str, Any]:
    """Freeze one routed direct task before launch without affecting task execution."""
    cohort_root = root or Path(
        os.environ.get(
            "GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT",
            str(Path.home() / ".local/state/grabowski/operator-routing-shadow-cohort"),
        )
    )
    attempted_at = frozen_at or _utc_now()
    try:
        route = _validated_route_evidence(
            route_evidence, execution_surface="direct_task"
        )
        identity = _direct_task_identity(
            host=host,
            argv_sha256=argv_sha256,
            cwd=cwd,
            resource_keys=resource_keys,
            runtime_seconds=runtime_seconds,
        )
        plan_sha256 = _direct_task_plan_sha256(task_id, identity, route)
        manifest = _direct_task_manifest(
            task_id=task_id,
            plan_sha256=plan_sha256,
            route=route,
            writer_bound=False,
        )
        capture = capture_workspace_eligibility_best_effort(
            manifest,
            root=cohort_root,
            frozen_at=attempted_at,
            case_origin="production",
            prestart_attestation=_DIRECT_TASK_PRESTART_ATTESTATION,
        )
        if capture.get("status") not in {"created", "duplicate"}:
            return {**capture, "binding_status": "not_created"}
        prospective = {
            "status": "created",
            "prospective_eligibility_id": capture["prospective_eligibility_id"],
            "workspace_case_id": capture["workspace_case_id"],
        }
        payload = {
            "schema_version": DIRECT_TASK_BINDING_SCHEMA_VERSION,
            "task_id": task_id,
            "workspace_id": manifest["workspace_id"],
            "plan_sha256": plan_sha256,
            "task_identity": identity,
            "route_evidence": route,
            "prospective": prospective,
            "created_at": _parse_timestamp(
                attempted_at, "direct_task_binding.created_at"
            ),
            "no_effect": dict(NO_EFFECT),
        }
        binding = {"binding_id": _sha256_json(payload), **payload}
        binding_dir = _direct_task_binding_directory(cohort_root)
        stored_binding, created = _write_direct_task_binding_idempotent(
            binding_dir / f"{task_id}.json", binding
        )
        return {
            **capture,
            "binding_status": "created" if created else "duplicate",
            "binding_id": stored_binding["binding_id"],
            "plan_sha256": plan_sha256,
        }
    except Exception as exc:
        return {
            "schema_version": 1,
            "status": "rejected" if isinstance(exc, ShadowCaptureError) else "error",
            "reason_code": _capture_reason(exc),
            "binding_status": "not_created",
            "no_effect": dict(NO_EFFECT),
        }

def read_direct_task_binding(
    task_id: str, *, root: Path | None = None
) -> dict[str, Any]:
    cohort_root = root or Path(
        os.environ.get(
            "GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT",
            str(Path.home() / ".local/state/grabowski/operator-routing-shadow-cohort"),
        )
    )
    binding_dir = _direct_task_binding_directory(cohort_root)
    binding = _read_regular_json(
        binding_dir / f"{task_id}.json", label="direct task routing shadow binding"
    )
    return validate_direct_task_binding(binding)

def seal_direct_task_case(
    *,
    task_id: str,
    outcome: dict[str, Any],
    primary_evidence_refs: list[str],
    execution_provenance: dict[str, Any] | None,
    semantic_assessments: list[dict[str, Any]] | None,
    root: Path | None = None,
    captured_at: str | None = None,
) -> dict[str, Any]:
    cohort_root = root or Path(
        os.environ.get(
            "GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT",
            str(Path.home() / ".local/state/grabowski/operator-routing-shadow-cohort"),
        )
    )
    normalized_outcome = _normalize_outcome(outcome)
    normalized_assessments = _normalize_semantic_assessments(semantic_assessments)
    if normalized_outcome["status"] == "reviewed" and len(normalized_assessments) < 2:
        raise ShadowCaptureError(
            "reviewed direct task outcome requires at least 2 independent semantic assessments"
        )
    binding = read_direct_task_binding(task_id, root=cohort_root)
    prospective_dir, _, _, _ = _cohort_directories(cohort_root)
    prospective = _read_regular_json(
        prospective_dir / f"{binding['prospective']['workspace_case_id']}.json",
        label="direct task prospective eligibility",
    )
    _validate_any_prospective(prospective)
    manifest = _direct_task_manifest(
        task_id=task_id,
        plan_sha256=binding["plan_sha256"],
        route=binding["route_evidence"],
        writer_bound=True,
    )
    return seal_prospective_case(
        prospective,
        manifest,
        eligible_task_id=task_id,
        outcome=normalized_outcome,
        primary_evidence_refs=primary_evidence_refs,
        root=cohort_root,
        captured_at=captured_at,
        execution_provenance=execution_provenance,
        semantic_assessments=normalized_assessments,
    )

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    freeze = subparsers.add_parser(
        "freeze", help="freeze eligibility before outcome review"
    )
    freeze.add_argument("--manifest", required=True)
    freeze.add_argument("--task-id", required=True)
    freeze.add_argument("--output", required=True)

    seal = subparsers.add_parser(
        "seal", help="seal an outcome against frozen eligibility"
    )
    seal.add_argument("--eligibility", required=True)
    seal.add_argument(
        "--outcome",
        required=True,
        help="JSON file containing outcome and primary_evidence_refs",
    )
    seal.add_argument("--output", required=True)
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    if args.command == "freeze":
        manifest = _read_regular_json(Path(args.manifest), label="manifest")
        receipt = build_eligibility_receipt(
            manifest,
            eligible_task_id=args.task_id,
            frozen_at=_utc_now(),
        )
        write_create_only(Path(args.output), receipt)
        print(
            json.dumps(
                {
                    "schema_version": ELIGIBILITY_SCHEMA_VERSION,
                    "eligibility_id": receipt["eligibility_id"],
                    "created": True,
                }
            )
        )
        return 0

    eligibility = _read_regular_json(
        Path(args.eligibility), label="eligibility receipt"
    )
    review_input = _read_regular_json(Path(args.outcome), label="outcome input")
    if set(review_input) != {"outcome", "primary_evidence_refs"}:
        raise ShadowCaptureError("outcome input shape is invalid")
    record = build_shadow_record(
        eligibility,
        outcome=review_input["outcome"],
        primary_evidence_refs=review_input["primary_evidence_refs"],
        captured_at=_utc_now(),
    )
    write_create_only(Path(args.output), record)
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "record_id": record["record_id"],
                "created": True,
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ShadowCaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

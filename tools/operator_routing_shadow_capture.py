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


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


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
    return parsed.isoformat().replace("+00:00", "Z")


def _absolute_unresolved(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def _open_directory_fd(path: Path) -> int:
    candidate = _absolute_unresolved(path)
    if not candidate.is_absolute():
        raise ShadowCaptureError("directory path must resolve from an absolute anchor")
    parts = candidate.parts
    descriptor = os.open(
        parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    )
    try:
        for part in parts[1:]:
            try:
                next_descriptor = os.open(
                    part,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW,
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
            raise ShadowCaptureError(f"{label} must be a regular non-symlink file") from exc
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


def _normalize_evidence_refs(value: Any, *, reviewed: bool) -> list[str]:
    if not isinstance(value, list) or len(value) > 16:
        raise ShadowCaptureError("primary_evidence_refs must be a list with at most 16 entries")
    refs: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not 1 <= len(item) <= 300
            or not item.startswith(EVIDENCE_PREFIXES)
        ):
            raise ShadowCaptureError("primary_evidence_refs contains an invalid reference")
        refs.append(item)
    if len(set(refs)) != len(refs):
        raise ShadowCaptureError("primary_evidence_refs must not contain duplicates")
    if reviewed and not refs:
        raise ShadowCaptureError("reviewed outcomes require at least one primary evidence reference")
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
            "observed_at": _parse_timestamp(value.get("observed_at"), "outcome.observed_at"),
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
            "observed_at": _parse_timestamp(value.get("observed_at"), "outcome.observed_at"),
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
        raise ShadowCaptureError("verified route evidence schema_version is unsupported")
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
    if not isinstance(features["task_kind"], str) or not 1 <= len(features["task_kind"]) <= 40:
        raise ShadowCaptureError("features.task_kind is invalid")
    for field in ("changed_file_estimate", "expected_duration_minutes"):
        value = features[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ShadowCaptureError(f"features.{field} is invalid")
    if not isinstance(features["novelty"], str) or not 1 <= len(features["novelty"]) <= 32:
        raise ShadowCaptureError("features.novelty is invalid")
    flags = features["risk_flags"]
    if (
        not isinstance(flags, list)
        or len(flags) > 32
        or len(set(flags)) != len(flags)
        or any(not isinstance(item, str) or not 1 <= len(item) <= 32 for item in flags)
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
    if isinstance(hypotheses, bool) or not isinstance(hypotheses, int) or not 1 <= hypotheses <= 4:
        raise ShadowCaptureError("features.architecture_hypotheses is invalid")



def _validated_route_evidence(value: Any) -> dict[str, Any]:
    persisted = isinstance(value, dict) and (
        "status" in value or "evidence_complete" in value
    )
    candidate = value
    if persisted:
        if value.get("status") != "verified" or value.get("evidence_complete") is not True:
            raise ShadowCaptureError("canonical route evidence is missing or incomplete")
        candidate = {
            key: item
            for key, item in value.items()
            if key not in {"status", "evidence_complete"}
        }
    try:
        normalized = workspace._normalize_route_evidence(candidate)
    except workspace.AgentWorkspaceError as exc:
        raise ShadowCaptureError(f"canonical route evidence is invalid: {exc}") from exc
    if normalized.get("status") != "verified" or normalized.get("evidence_complete") is not True:
        raise ShadowCaptureError("canonical route evidence is missing or incomplete")
    if persisted and normalized != value:
        raise ShadowCaptureError(
            "persisted canonical route evidence does not match deterministic policy replay"
        )
    return normalized

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
        "source": "agent-workspace-manifest",
        "schema_version": route["schema_version"],
        "recommendation_id": route["recommendation_id"],
        "route_evidence_sha256": _sha256_json(route),
        "manifest_sha256": _sha256_json(manifest),
    }


def _validate_case_and_route(eligible: Any, route_ref: Any) -> tuple[str, str, int]:
    if not isinstance(eligible, dict) or set(eligible) != {"task_id", "case_id"}:
        raise ShadowCaptureError("eligible_case shape is invalid")
    task_id = eligible.get("task_id")
    case_id = eligible.get("case_id")
    if not isinstance(task_id, str) or TASK_ID_RE.fullmatch(task_id) is None:
        raise ShadowCaptureError("eligible_case.task_id is invalid")
    if not isinstance(case_id, str) or SHA256_RE.fullmatch(case_id) is None:
        raise ShadowCaptureError("eligible_case.case_id is invalid")
    if not isinstance(route_ref, dict) or set(route_ref) != {
        "source", "schema_version", "recommendation_id", "route_evidence_sha256", "manifest_sha256"
    }:
        raise ShadowCaptureError("canonical_route_evidence shape is invalid")
    route_schema_version = route_ref.get("schema_version")
    if route_ref.get("source") != "agent-workspace-manifest" or route_schema_version not in {1, 2}:
        raise ShadowCaptureError("canonical_route_evidence source or schema_version is invalid")
    for field in ("recommendation_id", "route_evidence_sha256", "manifest_sha256"):
        value = route_ref.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ShadowCaptureError(f"canonical_route_evidence.{field} is invalid")
    expected_case_id = _case_id(task_id, route_ref["recommendation_id"])
    if case_id != expected_case_id:
        raise ShadowCaptureError("eligible_case.case_id is not bound to task and route evidence")
    return task_id, case_id, route_schema_version


def build_eligibility_receipt(
    manifest: dict[str, Any],
    *,
    eligible_task_id: str,
    frozen_at: str,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ShadowCaptureError("manifest must be an object")
    if not isinstance(eligible_task_id, str) or TASK_ID_RE.fullmatch(eligible_task_id) is None:
        raise ShadowCaptureError("eligible_task_id must be a Grabowski task id")
    if eligible_task_id not in _task_references(manifest):
        raise ShadowCaptureError("eligible_task_id is not referenced by the workspace manifest")
    route = _validated_route_evidence(manifest.get("route_evidence"))
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
    if not isinstance(eligibility_id, str) or SHA256_RE.fullmatch(eligibility_id) is None:
        raise ShadowCaptureError("eligibility_id is invalid")
    _, _, route_schema_version = _validate_case_and_route(
        receipt.get("eligible_case"), receipt.get("canonical_route_evidence")
    )
    _validate_features(receipt.get("features"), route_schema_version=route_schema_version)
    frozen_at = _parse_timestamp(receipt.get("frozen_at"), "frozen_at")
    if frozen_at != receipt.get("frozen_at"):
        raise ShadowCaptureError("frozen_at is not normalized")
    if receipt.get("no_effect") != NO_EFFECT:
        raise ShadowCaptureError("no_effect boundary is invalid")
    payload = {key: receipt[key] for key in receipt if key != "eligibility_id"}
    if _sha256_json(payload) != eligibility_id:
        raise ShadowCaptureError("eligibility_id does not match the canonical eligibility payload")
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
    )
    normalized_captured_at = _parse_timestamp(captured_at, "captured_at")
    frozen_at = eligibility["frozen_at"]
    observed_at = normalized_outcome["observed_at"]
    if _timestamp_value(frozen_at) > _timestamp_value(observed_at):
        raise ShadowCaptureError("eligibility must be frozen before outcome observation")
    if _timestamp_value(observed_at) > _timestamp_value(normalized_captured_at):
        raise ShadowCaptureError("outcome observation must not occur after capture sealing")
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
    _validate_features(record.get("features"), route_schema_version=route_schema_version)
    eligibility_ref = record.get("eligibility")
    if not isinstance(eligibility_ref, dict) or set(eligibility_ref) != {
        "schema_version", "eligibility_id", "frozen_at"
    }:
        raise ShadowCaptureError("eligibility reference shape is invalid")
    if eligibility_ref.get("schema_version") != ELIGIBILITY_SCHEMA_VERSION:
        raise ShadowCaptureError("eligibility reference schema_version is invalid")
    eligibility_id = eligibility_ref.get("eligibility_id")
    if not isinstance(eligibility_id, str) or SHA256_RE.fullmatch(eligibility_id) is None:
        raise ShadowCaptureError("eligibility reference id is invalid")
    frozen_at = _parse_timestamp(eligibility_ref.get("frozen_at"), "eligibility.frozen_at")
    if frozen_at != eligibility_ref.get("frozen_at"):
        raise ShadowCaptureError("eligibility.frozen_at is not normalized")
    normalized_outcome = _normalize_outcome(record.get("outcome"))
    if normalized_outcome != record.get("outcome"):
        raise ShadowCaptureError("outcome is not normalized")
    refs = _normalize_evidence_refs(
        record.get("primary_evidence_refs"),
        reviewed=normalized_outcome["status"] == "reviewed",
    )
    if refs != record.get("primary_evidence_refs"):
        raise ShadowCaptureError("primary_evidence_refs is not normalized")
    captured_at = _parse_timestamp(record.get("captured_at"), "captured_at")
    if captured_at != record.get("captured_at"):
        raise ShadowCaptureError("captured_at is not normalized")
    if _timestamp_value(frozen_at) > _timestamp_value(normalized_outcome["observed_at"]):
        raise ShadowCaptureError("eligibility must be frozen before outcome observation")
    if _timestamp_value(normalized_outcome["observed_at"]) > _timestamp_value(captured_at):
        raise ShadowCaptureError("outcome observation must not occur after capture sealing")
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
        raise ShadowCaptureError("eligibility reference does not match frozen record fields")
    payload = {key: record[key] for key in record if key != "record_id"}
    if _sha256_json(payload) != record_id:
        raise ShadowCaptureError("record_id does not match the canonical record payload")
    return record


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
    descriptor: int | None = None
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        try:
            descriptor = os.open(
                candidate.name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError as exc:
            raise ShadowCaptureError(
                "refusing to overwrite an existing shadow record"
            ) from exc
        except OSError as exc:
            raise ShadowCaptureError(
                "output path must resolve to a new regular non-symlink file"
            ) from exc
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    freeze = subparsers.add_parser("freeze", help="freeze eligibility before outcome review")
    freeze.add_argument("--manifest", required=True)
    freeze.add_argument("--task-id", required=True)
    freeze.add_argument("--output", required=True)

    seal = subparsers.add_parser("seal", help="seal an outcome against frozen eligibility")
    seal.add_argument("--eligibility", required=True)
    seal.add_argument(
        "--outcome", required=True,
        help="JSON file containing outcome and primary_evidence_refs",
    )
    seal.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.command == "freeze":
        manifest = _read_regular_json(Path(args.manifest), label="manifest")
        receipt = build_eligibility_receipt(
            manifest,
            eligible_task_id=args.task_id,
            frozen_at=_utc_now(),
        )
        write_create_only(Path(args.output), receipt)
        print(json.dumps({
            "schema_version": ELIGIBILITY_SCHEMA_VERSION,
            "eligibility_id": receipt["eligibility_id"],
            "created": True,
        }))
        return 0

    eligibility = _read_regular_json(Path(args.eligibility), label="eligibility receipt")
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
    print(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "record_id": record["record_id"],
        "created": True,
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ShadowCaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

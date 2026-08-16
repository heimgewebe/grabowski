from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

import grabowski_candidate_verification as candidate_verification


SCHEMA_VERSION = 1
ADOPTION_KIND = "CandidateAdoptionReceipt.v1"
INTENT_KIND = "CandidateAdoptionIntent.v1"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LANE_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class CandidateAdoptionError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _required_string(value: Any, field: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CandidateAdoptionError(f"{field} must be a non-empty bounded string")
    if any(character in value for character in "\r\n\x00"):
        raise CandidateAdoptionError(f"{field} contains an invalid control character")
    return value


def _required_sha40(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA40_RE.fullmatch(value) is None:
        raise CandidateAdoptionError(f"{field} must be a lowercase Git SHA")
    return value


def _required_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CandidateAdoptionError(f"{field} must be a lowercase SHA-256")
    return value


def _candidate_and_verification(
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    try:
        candidate = candidate_verification.validate_candidate_manifest(candidate_manifest)
        receipts = [
            candidate_verification.validate_verification_receipt(
                value,
                expected_candidate_id=candidate["candidate_id"],
            )
            for value in verification_receipts
        ]
        summary = candidate_verification.validate_verification_summary(
            verification_summary,
            candidate_manifest=candidate,
            verification_receipts=receipts,
        )
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateAdoptionError(str(exc)) from exc
    if summary.get("outcome") != "PASS":
        raise CandidateAdoptionError("candidate verification must be PASS before adoption")
    if summary.get("missing_required_verifiers"):
        raise CandidateAdoptionError("candidate verification is incomplete")
    lane_id = candidate.get("lane_id")
    if not isinstance(lane_id, str) or LANE_ID_RE.fullmatch(lane_id) is None:
        raise CandidateAdoptionError("candidate adoption requires a lane-backed candidate")
    return candidate, receipts, summary


def build_adoption_intent(
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
    controller_actor: str,
    integration_target: str,
    expected_git_tree_sha: str,
    expected_commit_sha: str,
) -> dict[str, Any]:
    candidate, receipts, summary = _candidate_and_verification(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
    )
    verifier_receipts = {
        receipt["verifier_kind"]: receipt["receipt_sha256"]
        for receipt in sorted(receipts, key=lambda item: item["verifier_kind"])
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": INTENT_KIND,
        "candidate_id": candidate["candidate_id"],
        "candidate_manifest_sha256": sha256_json(candidate),
        "verification_receipt_sha256": verifier_receipts,
        "verification_summary_sha256": summary["summary_sha256"],
        "controller_actor": _required_string(controller_actor, "controller_actor", maximum=128),
        "source_lane_id": candidate["lane_id"],
        "source_workspace_id": candidate["workspace_id"],
        "integration_target": _required_string(integration_target, "integration_target"),
        "integration_base_head": candidate["base_head"],
        "expected_git_tree_sha": _required_sha40(expected_git_tree_sha, "expected_git_tree_sha"),
        "expected_commit_sha": _required_sha40(expected_commit_sha, "expected_commit_sha"),
        "resulting_tree_sha256": candidate["resulting_tree_sha256"],
    }
    return {**body, "intent_sha256": sha256_json(body)}


def validate_adoption_intent(
    value: Any,
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateAdoptionError("candidate adoption intent must be an object")
    expected_keys = {
        "schema_version",
        "kind",
        "candidate_id",
        "candidate_manifest_sha256",
        "verification_receipt_sha256",
        "verification_summary_sha256",
        "controller_actor",
        "source_lane_id",
        "source_workspace_id",
        "integration_target",
        "integration_base_head",
        "expected_git_tree_sha",
        "expected_commit_sha",
        "resulting_tree_sha256",
        "intent_sha256",
    }
    if set(value) != expected_keys:
        raise CandidateAdoptionError("candidate adoption intent shape is not canonical")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != INTENT_KIND:
        raise CandidateAdoptionError("candidate adoption intent contract is unsupported")
    expected = build_adoption_intent(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        controller_actor=value.get("controller_actor"),
        integration_target=value.get("integration_target"),
        expected_git_tree_sha=value.get("expected_git_tree_sha"),
        expected_commit_sha=value.get("expected_commit_sha"),
    )
    if value != expected:
        raise CandidateAdoptionError("candidate adoption intent binding mismatch")
    return expected


def _validated_readback(
    value: Any,
    *,
    integration_base_head: str,
    resulting_commit_sha: str,
    resulting_git_tree_sha: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateAdoptionError("integration readback must be an object")
    expected_keys = {
        "branch",
        "head_sha",
        "parent_sha",
        "git_tree_sha",
        "clean",
        "staged_changes",
        "untracked_changes",
    }
    if set(value) != expected_keys:
        raise CandidateAdoptionError("integration readback shape is not canonical")
    branch = _required_string(value.get("branch"), "integration_readback.branch", maximum=512)
    head = _required_sha40(value.get("head_sha"), "integration_readback.head_sha")
    parent = _required_sha40(value.get("parent_sha"), "integration_readback.parent_sha")
    tree = _required_sha40(value.get("git_tree_sha"), "integration_readback.git_tree_sha")
    for field in ("clean", "staged_changes", "untracked_changes"):
        if not isinstance(value.get(field), bool):
            raise CandidateAdoptionError(f"integration_readback.{field} must be a boolean")
    if head != resulting_commit_sha:
        raise CandidateAdoptionError("integration readback head does not match adopted commit")
    if parent != integration_base_head:
        raise CandidateAdoptionError("integration readback parent does not match adoption base")
    if tree != resulting_git_tree_sha:
        raise CandidateAdoptionError("integration readback tree does not match adopted tree")
    if value["clean"] is not True or value["staged_changes"] or value["untracked_changes"]:
        raise CandidateAdoptionError("integration readback must prove a clean adopted checkout")
    return {
        "branch": branch,
        "head_sha": head,
        "parent_sha": parent,
        "git_tree_sha": tree,
        "clean": True,
        "staged_changes": False,
        "untracked_changes": False,
    }


def build_adoption_receipt(
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
    adoption_intent: dict[str, Any],
    resulting_commit_sha: str,
    resulting_git_tree_sha: str,
    integration_readback: dict[str, Any],
    adopted_at_unix: int | None = None,
) -> dict[str, Any]:
    candidate, receipts, summary = _candidate_and_verification(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
    )
    intent = validate_adoption_intent(
        adoption_intent,
        candidate_manifest=candidate,
        verification_receipts=receipts,
        verification_summary=summary,
    )
    commit_sha = _required_sha40(resulting_commit_sha, "resulting_commit_sha")
    git_tree_sha = _required_sha40(resulting_git_tree_sha, "resulting_git_tree_sha")
    if git_tree_sha != intent["expected_git_tree_sha"]:
        raise CandidateAdoptionError("adopted Git tree differs from prepared candidate tree")
    if commit_sha != intent["expected_commit_sha"]:
        raise CandidateAdoptionError("adopted commit differs from prepared adoption commit")
    readback = _validated_readback(
        integration_readback,
        integration_base_head=candidate["base_head"],
        resulting_commit_sha=commit_sha,
        resulting_git_tree_sha=git_tree_sha,
    )
    if readback["branch"] != intent["integration_target"]:
        raise CandidateAdoptionError("integration readback branch differs from adoption target")
    timestamp = int(time.time()) if adopted_at_unix is None else adopted_at_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise CandidateAdoptionError("adopted_at_unix must be a non-negative integer")
    verifier_receipts = {
        receipt["verifier_kind"]: receipt["receipt_sha256"]
        for receipt in sorted(receipts, key=lambda item: item["verifier_kind"])
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": ADOPTION_KIND,
        "candidate_id": candidate["candidate_id"],
        "candidate_manifest_sha256": sha256_json(candidate),
        "verification_receipt_sha256": verifier_receipts,
        "verification_summary_sha256": summary["summary_sha256"],
        "adoption_intent_sha256": intent["intent_sha256"],
        "controller_actor": intent["controller_actor"],
        "source_lane_id": candidate["lane_id"],
        "source_workspace_id": candidate["workspace_id"],
        "integration_target": intent["integration_target"],
        "integration_base_head": candidate["base_head"],
        "resulting_tree_sha256": candidate["resulting_tree_sha256"],
        "resulting_commit_sha": commit_sha,
        "resulting_git_tree_sha": git_tree_sha,
        "integration_readback": readback,
        "integration_readback_sha256": sha256_json(readback),
        "adopted_at_unix": timestamp,
    }
    return {**body, "receipt_sha256": sha256_json(body)}


def validate_adoption_receipt(
    value: Any,
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
    adoption_intent: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateAdoptionError("candidate adoption receipt must be an object")
    expected_keys = {
        "schema_version",
        "kind",
        "candidate_id",
        "candidate_manifest_sha256",
        "verification_receipt_sha256",
        "verification_summary_sha256",
        "adoption_intent_sha256",
        "controller_actor",
        "source_lane_id",
        "source_workspace_id",
        "integration_target",
        "integration_base_head",
        "resulting_tree_sha256",
        "resulting_commit_sha",
        "resulting_git_tree_sha",
        "integration_readback",
        "integration_readback_sha256",
        "adopted_at_unix",
        "receipt_sha256",
    }
    if set(value) != expected_keys:
        raise CandidateAdoptionError("candidate adoption receipt shape is not canonical")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != ADOPTION_KIND:
        raise CandidateAdoptionError("candidate adoption receipt contract is unsupported")
    expected = build_adoption_receipt(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        adoption_intent=adoption_intent,
        resulting_commit_sha=value.get("resulting_commit_sha"),
        resulting_git_tree_sha=value.get("resulting_git_tree_sha"),
        integration_readback=value.get("integration_readback"),
        adopted_at_unix=value.get("adopted_at_unix"),
    )
    if value != expected:
        raise CandidateAdoptionError("candidate adoption receipt binding mismatch")
    return expected


def persist_adoption_intent(
    path: Path,
    payload: dict[str, Any],
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
) -> bool:
    validator = lambda value: validate_adoption_intent(
        value,
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
    )
    try:
        return candidate_verification.persist_immutable_receipt(
            path,
            payload,
            validator=validator,
        )
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateAdoptionError(str(exc)) from exc


def read_adoption_intent(
    path: Path,
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
) -> dict[str, Any]:
    validator = lambda value: validate_adoption_intent(
        value,
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
    )
    try:
        return candidate_verification.read_immutable_receipt(path, validator=validator)
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateAdoptionError(str(exc)) from exc


def persist_adoption_receipt(
    path: Path,
    payload: dict[str, Any],
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
    adoption_intent: dict[str, Any],
) -> bool:
    validator = lambda value: validate_adoption_receipt(
        value,
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        adoption_intent=adoption_intent,
    )
    try:
        return candidate_verification.persist_immutable_receipt(
            path,
            payload,
            validator=validator,
        )
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateAdoptionError(str(exc)) from exc


def read_adoption_receipt(
    path: Path,
    *,
    candidate_manifest: dict[str, Any],
    verification_receipts: list[dict[str, Any]],
    verification_summary: dict[str, Any],
    adoption_intent: dict[str, Any],
) -> dict[str, Any]:
    validator = lambda value: validate_adoption_receipt(
        value,
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        adoption_intent=adoption_intent,
    )
    try:
        return candidate_verification.read_immutable_receipt(path, validator=validator)
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateAdoptionError(str(exc)) from exc

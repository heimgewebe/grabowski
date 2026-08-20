from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

import grabowski_candidate_verification as candidate_verification
import grabowski_execution_plan as execution_plan


SCHEMA_VERSION = 1
ADOPTION_KIND = "CandidateAdoptionReceipt.v1"
INTENT_KIND = "CandidateAdoptionIntent.v1"
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LANE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
DELIVERY_MANIFEST_KIND = "CandidateDeliveryManifest.v1"
DELIVERY_MODE = "commit_range"
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
MAX_DELIVERY_TITLE_BYTES = 1024
MAX_DELIVERY_BODY_BYTES = 131072
MAX_DELIVERY_MANIFEST_BYTES = 262144


class CandidateAdoptionError(ValueError):
    pass


class CandidateDeliveryError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CandidateDeliveryError("value is not canonical JSON") from exc


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


def _delivery_sha40(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA40_RE.fullmatch(value) is None:
        raise CandidateDeliveryError(f"{field} must be a lowercase Git SHA")
    return value


def _delivery_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CandidateDeliveryError(f"{field} must be a lowercase SHA-256")
    return value


def _delivery_text(
    value: Any,
    field: str,
    *,
    maximum_bytes: int,
    empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise CandidateDeliveryError(f"{field} must be bounded text")
    if "\x00" in value or len(value.encode("utf-8")) > maximum_bytes:
        raise CandidateDeliveryError(f"{field} must be bounded text without NUL")
    return value


def _delivery_branch(value: Any, field: str) -> str:
    branch = _delivery_text(value, field, maximum_bytes=255)
    if (
        BRANCH_RE.fullmatch(branch) is None
        or branch.startswith("/")
        or branch.endswith(("/", ".", ".lock"))
        or "//" in branch
        or ".." in branch
        or "@{" in branch
    ):
        raise CandidateDeliveryError(f"{field} is not a safe branch name")
    return branch


def _delivery_collection_digest(value: Mapping[str, Any]) -> str:
    projected = {key: item for key, item in value.items() if key != "result_sha256"}
    return hashlib.sha256(canonical_json_bytes(projected)).hexdigest()


def _validated_delivery_evidence(
    *,
    candidate_manifest: Mapping[str, Any],
    verification_receipts: Sequence[Mapping[str, Any]],
    verification_summary: Mapping[str, Any],
    collection_result: Mapping[str, Any],
    execution_plan_value: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        candidate = candidate_verification.validate_candidate_manifest(
            dict(candidate_manifest)
        )
        receipts = [
            candidate_verification.validate_verification_receipt(
                dict(receipt), expected_candidate_id=candidate["candidate_id"]
            )
            for receipt in verification_receipts
        ]
        summary = candidate_verification.validate_verification_summary(
            dict(verification_summary),
            candidate_manifest=candidate,
            verification_receipts=receipts,
        )
    except (TypeError, candidate_verification.CandidateVerificationError) as exc:
        raise CandidateDeliveryError(
            f"Candidate verification evidence is invalid: {exc}"
        ) from exc
    collection = dict(collection_result)
    result_sha256 = collection.get("result_sha256")
    if (
        collection.get("state") != "complete"
        or not isinstance(result_sha256, str)
        or SHA256_RE.fullmatch(result_sha256) is None
        or _delivery_collection_digest(collection) != result_sha256
    ):
        raise CandidateDeliveryError("collection result digest is invalid")
    if (
        collection.get("candidate_id") != candidate["candidate_id"]
        or collection.get("candidate_manifest") != candidate
        or collection.get("verification_receipts") != list(verification_receipts)
        or collection.get("verification_summary") != summary
    ):
        raise CandidateDeliveryError(
            "collection result is not the exact verified Candidate"
        )
    if (
        summary.get("outcome") != "PASS"
        or summary.get("missing_required_verifiers")
        or collection.get("tests", {}).get("status") != "passed"
        or collection.get("review", {}).get("status") != "passed"
        or collection.get("review", {}).get("verdict") != "PASS"
        or collection.get("review", {}).get("findings") != []
    ):
        raise CandidateDeliveryError(
            "delivery requires an exact complete PASS verification"
        )
    try:
        plan = execution_plan.validate_execution_plan(dict(execution_plan_value))
    except (TypeError, execution_plan.ExecutionPlanError) as exc:
        raise CandidateDeliveryError(f"ExecutionPlan.v1 is invalid: {exc}") from exc
    route = plan["route_binding"]
    if route.get("effect_profile") != "delivery" or route.get("executor") != "scoped_writer":
        raise CandidateDeliveryError(
            "delivery requires a delivery-bound scoped_writer ExecutionPlan.v1"
        )
    source = plan.get("source_binding")
    if not isinstance(source, dict):
        raise CandidateDeliveryError("delivery ExecutionPlan source binding is missing")
    lane_id = candidate.get("lane_id")
    if not isinstance(lane_id, str) or LANE_ID_RE.fullmatch(lane_id) is None:
        raise CandidateDeliveryError("delivery requires a lane-backed Candidate")
    return candidate, receipts, summary, collection, plan


def build_candidate_delivery_manifest(
    *,
    candidate_manifest: Mapping[str, Any],
    verification_receipts: Sequence[Mapping[str, Any]],
    verification_summary: Mapping[str, Any],
    collection_result: Mapping[str, Any],
    execution_plan_value: Mapping[str, Any],
    lane_receipt_sha256: str,
    base_commit: str,
    head_commit: str,
    candidate_git_tree_sha: str,
    commit_git_tree_sha: str,
    writer_branch: str,
    base_branch: str,
    title: str,
    body: str = "",
    draft: bool = False,
    remote: str = "origin",
) -> dict[str, Any]:
    candidate, _receipts, summary, collection, plan = _validated_delivery_evidence(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        collection_result=collection_result,
        execution_plan_value=execution_plan_value,
    )
    lane_receipt = _delivery_sha256(lane_receipt_sha256, "lane_receipt_sha256")
    base = _delivery_sha40(base_commit, "base_commit")
    head = _delivery_sha40(head_commit, "head_commit")
    candidate_tree = _delivery_sha40(
        candidate_git_tree_sha, "candidate_git_tree_sha"
    )
    commit_tree = _delivery_sha40(commit_git_tree_sha, "commit_git_tree_sha")
    if base != candidate.get("base_head"):
        raise CandidateDeliveryError("delivery base commit differs from Candidate base")
    if head == base:
        raise CandidateDeliveryError("delivery commit range must contain one new commit")
    if candidate_tree != commit_tree:
        raise CandidateDeliveryError(
            "delivery commit tree differs from verified Candidate tree"
        )
    writer = _delivery_branch(writer_branch, "writer_branch")
    target = _delivery_branch(base_branch, "base_branch")
    if writer == target:
        raise CandidateDeliveryError("delivery writer and base branches must differ")
    if remote != "origin":
        raise CandidateDeliveryError("delivery publication remote must be origin")
    pr_title = _delivery_text(
        title, "title", maximum_bytes=MAX_DELIVERY_TITLE_BYTES
    )
    pr_body = _delivery_text(
        body, "body", maximum_bytes=MAX_DELIVERY_BODY_BYTES, empty=True
    )
    if not isinstance(draft, bool):
        raise CandidateDeliveryError("draft must be a boolean")
    write_scope = list(plan["write_scope"])
    commit_message = f"Deliver candidate {candidate['candidate_id'][:12]}"
    identity = {
        "workspace_id": candidate["workspace_id"],
        "lane_id": candidate["lane_id"],
        "lane_receipt_sha256": lane_receipt,
        "route_recommendation_sha256": plan["route_binding"][
            "recommendation_sha256"
        ],
        "execution_plan_id": plan["plan_id"],
    }
    candidate_binding = {
        "candidate_id": candidate["candidate_id"],
        "candidate_manifest_sha256": sha256_json(candidate),
        "verification_summary_sha256": summary["summary_sha256"],
        "collection_result_sha256": collection["result_sha256"],
    }
    commit_action_body = {
        "kind": "writer_commit",
        "candidate_id": candidate["candidate_id"],
        "workspace_id": candidate["workspace_id"],
        "lane_id": candidate["lane_id"],
        "branch": writer,
        "base_commit": base,
        "head_commit": head,
        "git_tree_sha": commit_tree,
        "message": commit_message,
    }
    commit_action = {
        **commit_action_body,
        "action_id": sha256_json(commit_action_body),
    }
    remote_ref = f"refs/heads/{writer}"
    push_action_body = {
        "kind": "branch_publish",
        "commit_action_id": commit_action["action_id"],
        "remote": remote,
        "remote_ref": remote_ref,
        "expected_head": head,
    }
    push_action = {**push_action_body, "action_id": sha256_json(push_action_body)}
    pr_action_body = {
        "kind": "pr_create_or_update",
        "push_action_id": push_action["action_id"],
        "base": target,
        "head": writer,
        "head_sha": head,
        "draft": draft,
        "title": pr_title,
        "body": pr_body,
    }
    pr_action = {**pr_action_body, "action_id": sha256_json(pr_action_body)}
    body_value = {
        "schema_version": SCHEMA_VERSION,
        "kind": DELIVERY_MANIFEST_KIND,
        "delivery_mode": DELIVERY_MODE,
        "identity": identity,
        "candidate": candidate_binding,
        "commit_range": {
            "base_commit": base,
            "head_commit": head,
            "candidate_git_tree_sha": candidate_tree,
            "commit_git_tree_sha": commit_tree,
        },
        "scope": {
            "write_paths": write_scope,
            "write_scope_sha256": sha256_json(write_scope),
        },
        "branch": {
            "writer_branch": writer,
            "base_branch": target,
            "remote": remote,
            "remote_ref": remote_ref,
        },
        "actions": {
            "commit": commit_action,
            "push": push_action,
            "pr": pr_action,
        },
    }
    if len(canonical_json_bytes(body_value)) > MAX_DELIVERY_MANIFEST_BYTES:
        raise CandidateDeliveryError("CandidateDeliveryManifest.v1 is too large")
    return {**body_value, "manifest_id": sha256_json(body_value)}


def validate_candidate_delivery_manifest(
    value: Any,
    *,
    candidate_manifest: Mapping[str, Any],
    verification_receipts: Sequence[Mapping[str, Any]],
    verification_summary: Mapping[str, Any],
    collection_result: Mapping[str, Any],
    execution_plan_value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidateDeliveryError("CandidateDeliveryManifest.v1 must be an object")
    expected_keys = {
        "schema_version",
        "kind",
        "delivery_mode",
        "manifest_id",
        "identity",
        "candidate",
        "commit_range",
        "scope",
        "branch",
        "actions",
    }
    if set(value) != expected_keys:
        raise CandidateDeliveryError(
            "CandidateDeliveryManifest.v1 shape is not canonical"
        )
    if (
        value.get("schema_version") != SCHEMA_VERSION
        or value.get("kind") != DELIVERY_MANIFEST_KIND
        or value.get("delivery_mode") != DELIVERY_MODE
    ):
        raise CandidateDeliveryError(
            "CandidateDeliveryManifest.v1 contract is unsupported"
        )
    commit_range = value.get("commit_range")
    branch = value.get("branch")
    actions = value.get("actions")
    pr = actions.get("pr") if isinstance(actions, Mapping) else None
    if not all(
        isinstance(item, Mapping) for item in (commit_range, branch, actions, pr)
    ):
        raise CandidateDeliveryError(
            "CandidateDeliveryManifest.v1 bindings are incomplete"
        )
    rebuilt = build_candidate_delivery_manifest(
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        collection_result=collection_result,
        execution_plan_value=execution_plan_value,
        lane_receipt_sha256=value.get("identity", {}).get("lane_receipt_sha256"),
        base_commit=commit_range.get("base_commit"),
        head_commit=commit_range.get("head_commit"),
        candidate_git_tree_sha=commit_range.get("candidate_git_tree_sha"),
        commit_git_tree_sha=commit_range.get("commit_git_tree_sha"),
        writer_branch=branch.get("writer_branch"),
        base_branch=branch.get("base_branch"),
        remote=branch.get("remote"),
        title=pr.get("title"),
        body=pr.get("body"),
        draft=pr.get("draft"),
    )
    if dict(value) != rebuilt:
        raise CandidateDeliveryError(
            "CandidateDeliveryManifest.v1 identity or action binding drifted"
        )
    return rebuilt


def persist_candidate_delivery_manifest(
    path: Path,
    payload: dict[str, Any],
    *,
    candidate_manifest: Mapping[str, Any],
    verification_receipts: Sequence[Mapping[str, Any]],
    verification_summary: Mapping[str, Any],
    collection_result: Mapping[str, Any],
    execution_plan_value: Mapping[str, Any],
) -> bool:
    validator = lambda observed: validate_candidate_delivery_manifest(
        observed,
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        collection_result=collection_result,
        execution_plan_value=execution_plan_value,
    )
    try:
        return candidate_verification.persist_immutable_receipt(
            path, payload, validator=validator
        )
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateDeliveryError(str(exc)) from exc


def read_candidate_delivery_manifest(
    path: Path,
    *,
    candidate_manifest: Mapping[str, Any],
    verification_receipts: Sequence[Mapping[str, Any]],
    verification_summary: Mapping[str, Any],
    collection_result: Mapping[str, Any],
    execution_plan_value: Mapping[str, Any],
) -> dict[str, Any]:
    validator = lambda observed: validate_candidate_delivery_manifest(
        observed,
        candidate_manifest=candidate_manifest,
        verification_receipts=verification_receipts,
        verification_summary=verification_summary,
        collection_result=collection_result,
        execution_plan_value=execution_plan_value,
    )
    try:
        return candidate_verification.read_immutable_receipt(path, validator=validator)
    except candidate_verification.CandidateVerificationError as exc:
        raise CandidateDeliveryError(str(exc)) from exc

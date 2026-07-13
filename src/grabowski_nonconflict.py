from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = 1
PROOF_KIND = "grabowski_nonconflict_proof"
ACQUISITION_KIND = "grabowski_nonconflict_acquisition"
MAX_PROOF_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 5
SHA_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9._:@/+\-=]{1,512}\Z")
FORBIDDEN_GLOB_CHARS = frozenset("*?[]{}")
LIST_AXES = (
    "paths",
    "components",
    "runtime_resources",
    "processes",
    "deployments",
    "migrations",
    "generated_artifacts",
    "shared_gates",
)
EFFECTS = frozenset(
    {
        "read",
        "write",
        "generate",
        "process",
        "deploy",
        "migrate",
        "merge",
        "worktree-admin",
    }
)
GLOBAL_GATE_BY_EFFECT = {
    "deploy": "repository-runtime-deploy",
    "migrate": "repository-migration",
    "merge": "repository-merge",
    "worktree-admin": "repository-worktree-admin",
}
REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "task_id",
        "base_head",
        "head",
        "branch",
        "worktree",
        "effects",
        *LIST_AXES,
    }
)
RESOURCE_AXIS_BY_KIND = {
    "component": "components",
    "process": "processes",
    "deployment": "deployments",
    "migration": "migrations",
    "gate": "shared_gates",
}
RUNTIME_RESOURCE_KINDS = frozenset({"service", "port", "display", "browser-profile"})
EXPECTED_AXIS_NAMES = (
    "task",
    "branch",
    "worktree",
    "base_head",
    "paths",
    "generated_artifacts",
    "path_generated_cross",
    "worktree_paths_cross",
    "components",
    "runtime_resources",
    "processes",
    "deployments",
    "migrations",
    "shared_gates",
)
LEASE_SNAPSHOT_KEYS = frozenset(
    {
        "resource_key",
        "owner_id",
        "acquired_at_unix",
        "updated_at_unix",
        "expires_at_unix",
        "metadata_sha256",
    }
)
DOES_NOT_ESTABLISH = [
    "merge_authority",
    "deploy_authority",
    "migration_authority",
    "permission_to_release_foreign_lease",
    "permission_to_modify_foreign_worktree",
]
PROOF_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "decision",
        "issued_at_unix",
        "expires_at_unix",
        "blocked_lease",
        "requesting_owner",
        "resource_keys",
        "resource_keys_sha256",
        "purpose_sha256",
        "existing_scope_sha256",
        "requested_scope",
        "requested_scope_complete",
        "requested_scope_sha256",
        "axis_results",
        "blocker_axes",
        "does_not_establish",
        "proof_sha256",
    }
)
AXIS_RESULT_KEYS = frozenset({"axis", "status", "overlap_sha256", "overlap_count"})


class NonConflictDenied(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _text(value: Any, *, label: str, max_bytes: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = value.strip()
    if not text or "\x00" in text or len(text.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} is empty, too large or contains NUL")
    if any(char in text for char in FORBIDDEN_GLOB_CHARS):
        raise ValueError(f"{label} may not contain wildcard characters")
    return text


def _token(value: Any, *, label: str) -> str:
    text = _text(value, label=label)
    if TOKEN_RE.fullmatch(text) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return text


def _absolute_path(value: Any, *, label: str) -> str:
    text = _text(value, label=label, max_bytes=4096)
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    return os.path.realpath(os.path.normpath(str(path)))


def _head(value: Any) -> str:
    text = _text(value, label="head", max_bytes=64).lower()
    if SHA_RE.fullmatch(text) is None:
        raise ValueError("head must be a 40- or 64-character hexadecimal digest")
    return text


def _list(value: Any, *, label: str, paths: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    if len(value) > 128:
        raise ValueError(f"{label} may contain at most 128 entries")
    normalized = {
        (_absolute_path(item, label=f"{label} entry") if paths else _token(item, label=f"{label} entry"))
        for item in value
    }
    return sorted(normalized)


def _path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def normalize_scope_manifest(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUIRED_KEYS:
        missing = sorted(REQUIRED_KEYS - set(value) if isinstance(value, dict) else REQUIRED_KEYS)
        extra = sorted(set(value) - REQUIRED_KEYS) if isinstance(value, dict) else []
        raise ValueError(f"scope_manifest keys invalid; missing={missing} extra={extra}")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"scope_manifest schema_version must be {SCHEMA_VERSION}")
    repository = _absolute_path(value["repository"], label="repository")
    worktree = _absolute_path(value["worktree"], label="worktree")
    repo_parent = os.path.dirname(repository)
    if worktree != repository and (
        worktree == repo_parent or not _path_within(worktree, repo_parent)
    ):
        raise ValueError("worktree must be the repository root or a distinct path below its parent")
    effects = _list(value["effects"], label="effects")
    unknown_effects = sorted(set(effects) - EFFECTS)
    if unknown_effects:
        raise ValueError(f"unsupported effects: {unknown_effects}")
    if not effects:
        raise ValueError("effects may not be empty")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": repository,
        "task_id": _token(value["task_id"], label="task_id"),
        "base_head": _head(value["base_head"]),
        "head": _head(value["head"]),
        "branch": _token(value["branch"], label="branch"),
        "worktree": worktree,
        "effects": effects,
    }
    for axis in LIST_AXES:
        result[axis] = _list(value[axis], label=axis, paths=axis in {"paths", "generated_artifacts"})

    for axis in ("paths", "generated_artifacts"):
        for path in result[axis]:
            if not (_path_within(path, repository) or _path_within(path, worktree)):
                raise ValueError(f"{axis} entry must be inside repository or declared worktree")

    mutating = bool(set(effects) - {"read"})
    if mutating and not (result["paths"] or result["components"] or result["runtime_resources"]):
        raise ValueError("mutating scope requires paths, components or runtime_resources")
    required_by_effect = {
        "generate": "generated_artifacts",
        "process": "processes",
        "deploy": "deployments",
        "migrate": "migrations",
    }
    for effect, axis in required_by_effect.items():
        if effect in effects and not result[axis]:
            raise ValueError(f"effect {effect} requires non-empty {axis}")
    for effect, gate in GLOBAL_GATE_BY_EFFECT.items():
        if effect in effects and gate not in result["shared_gates"]:
            raise ValueError(f"effect {effect} requires shared gate {gate}")
    return result


def validate_resource_scope_binding(resource_keys: Sequence[str], scope: Any) -> dict[str, Any]:
    normalized = normalize_scope_manifest(scope)
    if isinstance(resource_keys, (str, bytes)) or not isinstance(resource_keys, Sequence):
        raise ValueError("resource_keys must be a sequence")
    if any(not isinstance(key, str) for key in resource_keys):
        raise ValueError("resource keys must be text")
    keys = sorted(set(resource_keys))
    if not keys:
        raise NonConflictDenied("exact-scopes-required", "at least one exact resource key is required")
    represented: dict[str, set[str]] = {axis: set() for axis in LIST_AXES}
    filesystem_resources: set[str] = set()
    for key in keys:
        if ":" not in key:
            raise ValueError("resource key must use kind:value syntax")
        kind, resource_value = key.split(":", 1)
        if kind == "repo":
            raise NonConflictDenied(
                "exact-scopes-required",
                "non-conflict exception requests must not include repository leases",
            )
        if kind == "path":
            canonical = os.path.realpath(os.path.normpath(resource_value))
            if canonical != resource_value:
                raise NonConflictDenied(
                    "noncanonical-resource",
                    "path resource keys must use canonical paths without symlink aliases",
                )
            filesystem_resources.add(canonical)
            continue
        if kind in RUNTIME_RESOURCE_KINDS:
            represented["runtime_resources"].add(key)
            continue
        axis = RESOURCE_AXIS_BY_KIND.get(kind)
        if axis is None:
            raise ValueError(f"unsupported non-conflict resource kind: {kind}")
        represented[axis].add(resource_value)

    expected_filesystem = set(normalized["paths"]) | set(normalized["generated_artifacts"])
    if filesystem_resources != expected_filesystem:
        raise NonConflictDenied(
            "resource-scope-mismatch",
            "path resource keys and scope filesystem entries differ",
        )
    for axis in LIST_AXES:
        if axis in {"paths", "generated_artifacts"}:
            continue
        expected = set(normalized[axis])
        actual = represented[axis]
        if actual != expected:
            raise NonConflictDenied(
                "resource-scope-mismatch",
                f"resource keys and scope axis {axis} differ",
            )
    return normalized


def _path_overlap(left: str, right: str) -> bool:
    try:
        common = os.path.commonpath([left, right])
    except ValueError:
        return False
    return common == left or common == right


def _path_pairs(left: Sequence[str], right: Sequence[str]) -> list[str]:
    return [f"{a}\n{b}" for a in left for b in right if _path_overlap(a, b)]


def _axis_result(axis: str, overlaps: Sequence[str]) -> dict[str, Any]:
    values = sorted(set(overlaps))
    return {
        "axis": axis,
        "status": "conflict" if values else "disjoint",
        "overlap_sha256": _sha256(values),
        "overlap_count": len(values),
    }


def evaluate_scope_manifests(existing: Any, requested: Any) -> dict[str, Any]:
    left = normalize_scope_manifest(existing)
    right = normalize_scope_manifest(requested)
    if left["repository"] != right["repository"]:
        raise NonConflictDenied("different-repository", "proof must compare work in the same repository")

    results: list[dict[str, Any]] = [
        _axis_result("task", [left["task_id"]] if left["task_id"] == right["task_id"] else []),
        _axis_result("branch", [left["branch"]] if left["branch"] == right["branch"] else []),
        _axis_result("worktree", [left["worktree"]] if left["worktree"] == right["worktree"] else []),
        _axis_result(
            "base_head",
            [] if left["base_head"] == right["base_head"] else [
                f"{left['base_head']}\n{right['base_head']}"
            ],
        ),
        _axis_result("paths", _path_pairs(left["paths"], right["paths"])),
        _axis_result(
            "generated_artifacts",
            _path_pairs(left["generated_artifacts"], right["generated_artifacts"]),
        ),
        _axis_result(
            "path_generated_cross",
            _path_pairs(left["paths"], right["generated_artifacts"])
            + _path_pairs(left["generated_artifacts"], right["paths"]),
        ),
        _axis_result(
            "worktree_paths_cross",
            _path_pairs([left["worktree"]], right["paths"] + right["generated_artifacts"])
            + _path_pairs(left["paths"] + left["generated_artifacts"], [right["worktree"]]),
        ),
    ]
    for axis in (
        "components",
        "runtime_resources",
        "processes",
        "deployments",
        "migrations",
        "shared_gates",
    ):
        results.append(_axis_result(axis, sorted(set(left[axis]) & set(right[axis]))))

    blockers = [item["axis"] for item in results if item["status"] == "conflict"]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_nonconflict_evaluation",
        "existing_scope_sha256": _sha256(left),
        "requested_scope_sha256": _sha256(right),
        "axis_results": results,
        "decision": "deny" if blockers else "allow",
        "blocker_axes": blockers,
        "normalized_existing_scope": left,
        "normalized_requested_scope": right,
    }


def _lease_snapshot(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "resource_key": row["resource_key"],
        "owner_id": row["owner_id"],
        "acquired_at_unix": int(row["acquired_at_unix"]),
        "updated_at_unix": int(row["updated_at_unix"]),
        "expires_at_unix": int(row["expires_at_unix"]),
        "metadata_sha256": row["metadata_sha256"],
    }


def create_nonconflict_proof(
    *,
    blocked_lease: Mapping[str, Any],
    existing_scope: Any,
    requesting_owner: str,
    resource_keys: Sequence[str],
    purpose: str,
    requested_scope: Any,
    requested_scope_complete: bool,
    proof_ttl_seconds: int = MAX_PROOF_TTL_SECONDS,
    now: int | None = None,
) -> dict[str, Any]:
    issued = int(time.time()) if now is None else int(now)
    if not isinstance(proof_ttl_seconds, int) or not 30 <= proof_ttl_seconds <= MAX_PROOF_TTL_SECONDS:
        raise ValueError(f"proof_ttl_seconds must be between 30 and {MAX_PROOF_TTL_SECONDS}")
    if requested_scope_complete is not True:
        raise NonConflictDenied(
            "requested-scope-unattested",
            "requesting owner did not attest that the scope manifest is complete",
        )
    snapshot = _lease_snapshot(blocked_lease)
    if snapshot["owner_id"] == requesting_owner:
        raise NonConflictDenied("same-owner", "non-conflict exception requires a different owner")
    if snapshot["expires_at_unix"] <= issued:
        raise NonConflictDenied("blocked-lease-expired", "blocked lease is no longer active")
    normalized_request = validate_resource_scope_binding(resource_keys, requested_scope)
    evaluation = evaluate_scope_manifests(existing_scope, normalized_request)
    if evaluation["decision"] != "allow":
        raise NonConflictDenied(
            "scope-conflict",
            "scope manifests overlap on: " + ", ".join(evaluation["blocker_axes"]),
        )
    keys = sorted(set(resource_keys))
    valid_until = min(issued + proof_ttl_seconds, snapshot["expires_at_unix"])
    if valid_until - issued < 30:
        raise NonConflictDenied(
            "blocked-lease-too-short",
            "blocking lease has less than 30 seconds remaining",
        )
    core = {
        "schema_version": SCHEMA_VERSION,
        "kind": PROOF_KIND,
        "decision": "allow",
        "issued_at_unix": issued,
        "expires_at_unix": valid_until,
        "blocked_lease": snapshot,
        "requesting_owner": requesting_owner,
        "resource_keys": keys,
        "resource_keys_sha256": _sha256(keys),
        "purpose_sha256": hashlib.sha256(purpose.encode("utf-8")).hexdigest(),
        "existing_scope_sha256": evaluation["existing_scope_sha256"],
        "requested_scope": evaluation["normalized_requested_scope"],
        "requested_scope_complete": True,
        "requested_scope_sha256": evaluation["requested_scope_sha256"],
        "axis_results": evaluation["axis_results"],
        "blocker_axes": [],
        "does_not_establish": DOES_NOT_ESTABLISH,
    }
    return {**core, "proof_sha256": _sha256(core)}


def validate_public_proof(proof: Any, *, now: int | None = None) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    if not isinstance(proof, dict) or set(proof) != PROOF_KEYS:
        missing = sorted(PROOF_KEYS - set(proof) if isinstance(proof, dict) else PROOF_KEYS)
        extra = sorted(set(proof) - PROOF_KEYS) if isinstance(proof, dict) else []
        raise ValueError(f"nonconflict proof keys invalid; missing={missing} extra={extra}")
    proof_sha = proof["proof_sha256"]
    if not isinstance(proof_sha, str) or re.fullmatch(r"[0-9a-f]{64}", proof_sha) is None:
        raise ValueError("nonconflict proof SHA-256 is invalid")
    core = {key: value for key, value in proof.items() if key != "proof_sha256"}
    if _sha256(core) != proof_sha:
        raise ValueError("nonconflict proof SHA-256 mismatch")
    if proof["schema_version"] != SCHEMA_VERSION or proof["kind"] != PROOF_KIND:
        raise ValueError("nonconflict proof schema or kind is unsupported")
    if proof["decision"] != "allow" or proof["blocker_axes"] != []:
        raise NonConflictDenied("proof-denied", "nonconflict proof does not allow execution")
    if proof["requested_scope_complete"] is not True:
        raise NonConflictDenied("requested-scope-unattested", "requested scope is not attested complete")
    issued = proof["issued_at_unix"]
    expires = proof["expires_at_unix"]
    if type(issued) is not int or type(expires) is not int:
        raise ValueError("nonconflict proof timestamps are invalid")
    duration = expires - issued
    if issued > current + MAX_CLOCK_SKEW_SECONDS:
        raise NonConflictDenied("proof-from-future", "nonconflict proof is from the future")
    if expires <= current or not 30 <= duration <= MAX_PROOF_TTL_SECONDS:
        raise NonConflictDenied("proof-expired", "nonconflict proof is expired or has invalid duration")

    blocked = proof["blocked_lease"]
    if not isinstance(blocked, dict) or set(blocked) != LEASE_SNAPSHOT_KEYS:
        raise ValueError("blocked lease snapshot is malformed")
    if not isinstance(blocked["resource_key"], str) or not blocked["resource_key"].startswith("repo:/"):
        raise ValueError("blocked lease snapshot must identify an absolute repository resource")
    _token(blocked["owner_id"], label="blocked lease owner")
    for field in ("acquired_at_unix", "updated_at_unix", "expires_at_unix"):
        if type(blocked[field]) is not int:
            raise ValueError(f"blocked lease {field} is invalid")
    if not (blocked["acquired_at_unix"] <= blocked["updated_at_unix"] < blocked["expires_at_unix"]):
        raise ValueError("blocked lease timestamps are inconsistent")
    if not isinstance(blocked["metadata_sha256"], str) or re.fullmatch(
        r"[0-9a-f]{64}", blocked["metadata_sha256"]
    ) is None:
        raise ValueError("blocked lease metadata SHA-256 is invalid")
    if expires > blocked["expires_at_unix"]:
        raise NonConflictDenied("proof-outlives-blocker", "proof outlives its blocking lease")

    _token(proof["requesting_owner"], label="requesting_owner")
    keys = proof["resource_keys"]
    if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys):
        raise ValueError("proof resource_keys must be a list of text values")
    if keys != sorted(set(keys)):
        raise ValueError("proof resource_keys must be sorted and unique")
    normalized_requested = validate_resource_scope_binding(keys, proof["requested_scope"])
    if _sha256(normalized_requested) != proof["requested_scope_sha256"]:
        raise ValueError("requested scope hash mismatch")
    if _sha256(keys) != proof["resource_keys_sha256"]:
        raise ValueError("resource key hash mismatch")
    for field in ("resource_keys_sha256", "purpose_sha256", "existing_scope_sha256", "requested_scope_sha256"):
        value = proof[field]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError(f"{field} is invalid")

    axis_results = proof["axis_results"]
    if not isinstance(axis_results, list) or len(axis_results) != len(EXPECTED_AXIS_NAMES):
        raise ValueError("nonconflict proof axis results are incomplete")
    observed_axes: list[str] = []
    for item in axis_results:
        if not isinstance(item, dict) or set(item) != AXIS_RESULT_KEYS:
            raise ValueError("nonconflict proof axis result is malformed")
        observed_axes.append(item["axis"] if isinstance(item["axis"], str) else "")
        if item["status"] != "disjoint" or item["overlap_count"] != 0:
            raise NonConflictDenied("proof-axis-conflict", "nonconflict proof contains a conflicting axis")
        if not isinstance(item["overlap_sha256"], str) or re.fullmatch(
            r"[0-9a-f]{64}", item["overlap_sha256"]
        ) is None:
            raise ValueError("nonconflict proof axis hash is invalid")
    if tuple(observed_axes) != EXPECTED_AXIS_NAMES:
        raise ValueError("nonconflict proof axis order or membership is invalid")
    if proof["does_not_establish"] != DOES_NOT_ESTABLISH:
        raise ValueError("nonconflict proof boundary claims are invalid")
    return proof


def validate_proof_against_live_lease(
    proof: Any,
    *,
    live_lease: Mapping[str, Any],
    live_existing_scope: Any,
    requesting_owner: str,
    resource_keys: Sequence[str],
    purpose: str,
    requested_scope: Any,
    requested_ttl_seconds: int,
    now: int | None = None,
) -> dict[str, Any]:
    current = int(time.time()) if now is None else int(now)
    checked = validate_public_proof(proof, now=current)
    if requesting_owner != checked.get("requesting_owner"):
        raise NonConflictDenied("owner-drift", "requesting owner changed after proof creation")
    if live_lease["owner_id"] == requesting_owner:
        raise NonConflictDenied("same-owner", "non-conflict exception cannot target the same owner")
    if _lease_snapshot(live_lease) != checked.get("blocked_lease"):
        raise NonConflictDenied("blocked-lease-drift", "blocked lease changed after proof creation")
    keys = sorted(set(resource_keys))
    if keys != checked.get("resource_keys"):
        raise NonConflictDenied("resource-drift", "requested resource keys changed after proof creation")
    if hashlib.sha256(purpose.encode("utf-8")).hexdigest() != checked.get("purpose_sha256"):
        raise NonConflictDenied("purpose-drift", "purpose changed after proof creation")
    normalized_request = validate_resource_scope_binding(keys, requested_scope)
    if normalized_request != checked.get("requested_scope"):
        raise NonConflictDenied("scope-drift", "requested scope changed after proof creation")
    evaluation = evaluate_scope_manifests(live_existing_scope, normalized_request)
    if evaluation["decision"] != "allow":
        raise NonConflictDenied("scope-conflict", "live scopes are no longer disjoint")
    if evaluation["existing_scope_sha256"] != checked.get("existing_scope_sha256"):
        raise NonConflictDenied("existing-scope-drift", "blocked scope changed after proof creation")
    if requested_ttl_seconds > MAX_PROOF_TTL_SECONDS or current + requested_ttl_seconds > checked["expires_at_unix"]:
        raise NonConflictDenied("lease-outlives-proof", "requested lease would outlive the non-conflict proof")
    receipt_core = {
        "schema_version": SCHEMA_VERSION,
        "kind": ACQUISITION_KIND,
        "decision": "allow",
        "proof_sha256": checked["proof_sha256"],
        "owner_id": requesting_owner,
        "resource_keys_sha256": checked["resource_keys_sha256"],
        "blocked_lease_resource_key": checked["blocked_lease"]["resource_key"],
        "blocked_lease_owner_id": checked["blocked_lease"]["owner_id"],
        "blocked_lease_metadata_sha256": checked["blocked_lease"]["metadata_sha256"],
        "validated_at_unix": current,
        "valid_until_unix": checked["expires_at_unix"],
    }
    return {**receipt_core, "receipt_sha256": _sha256(receipt_core)}


def validate_governor_proof(proof: Any, *, now: int | None = None) -> dict[str, Any]:
    checked = validate_public_proof(proof, now=now)
    return {
        "valid": True,
        "proof_sha256": checked["proof_sha256"],
        "blocked_lease_resource_key": checked["blocked_lease"]["resource_key"],
        "blocked_lease_metadata_sha256": checked["blocked_lease"]["metadata_sha256"],
        "expires_at_unix": checked["expires_at_unix"],
        "note": "proposal only; resource acquisition must revalidate the live lease atomically",
    }

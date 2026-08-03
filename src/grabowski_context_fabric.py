"""Operator Context Fabric V1.

A compact read-only composition surface that binds and labels claims which
existing Grabowski authorities have already observed. The fabric owns no
lifecycle truth: it never re-derives pull-request, Bureau or deployment state,
it only binds caller-supplied observations to a declared target, attaches the
owning authority, and preserves contradictions instead of resolving them.

The whole surface is pure: it reads no files, keeps no memory database, holds
no chat history and writes nothing back. It fails closed whenever a required
target binding or a required authoritative source is missing.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:  # pragma: no cover - direct module execution
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

SCHEMA_VERSION = 1
CONTRACT_ID = "grabowski-operator-context-fabric-v1"
PLAN_KIND = "grabowski_context_fabric_plan"
CONTEXT_KIND = "grabowski_context_fabric_context"
CLAIM_KIND = "grabowski_context_fabric_claim"
EXPLANATION_KIND = "grabowski_context_fabric_explanation"
COMPARISON_KIND = "grabowski_context_fabric_comparison"

MAX_OBSERVATIONS = 200
MAX_CLAIM_BUDGET = 200
MAX_EVIDENCE_REFS = 8
MAX_TEXT_CHARS = 240
MAX_BINDING_VALUE_CHARS = 200
MAX_REJECTED_OBSERVATIONS = 40
MAX_NESTING_DEPTH = 6

FABRIC_AUTHORITY = "derived_binding_and_labeling_only"
FABRIC_ROLE = "binds_and_labels_existing_authority_claims"
CONFLICT_RESOLUTION = "not_performed"

SENSITIVITY_LEVELS = (
    "public_operational",
    "internal_operational",
    "restricted_operational",
)
SENSITIVITY_RANK = {name: index for index, name in enumerate(SENSITIVITY_LEVELS)}

FABRIC_DOES_NOT_ESTABLISH = (
    "lifecycle_truth_ownership",
    "current_truth_after_observation",
    "source_record_authenticity",
    "conflict_resolution",
    "merge_readiness",
    "deployment_authorization",
    "bureau_publication_authority",
    "task_completion",
    "policy_change",
    "routing_authority",
    "retry_permission",
    "secret_content_access",
    "global_operator_memory",
    "chat_persistence",
    "write_back_to_any_authority",
)

FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "body",
        "content",
        "cookie",
        "credential",
        "credentials",
        "passphrase",
        "password",
        "private_key",
        "secret",
        "secret_value",
        "secrets",
        "session_token",
        "token",
        "tokens",
        "value",
    }
)

EVIDENCE_REF_TYPES = frozenset(
    {
        "audit_record",
        "bureau_run",
        "bureau_task",
        "check_run",
        "chronik_event",
        "commit",
        "git_ref",
        "lease",
        "pr",
        "receipt",
        "release",
        "systemd_unit",
    }
)
EVIDENCE_REF_KEYS = ("type", "id", "repo", "url", "sha256", "head_sha")

OBSERVATION_KEYS = frozenset(
    {
        "source_tool",
        "claim_type",
        "binding",
        "observed_at",
        "historical",
        "status",
        "detail",
        "evidence_refs",
        "sensitivity",
    }
)

REPOSITORY_RE = re.compile(r"[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,64}\Z")
SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
HTTPS_URL_RE = re.compile(
    r"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,512}\Z"
)

BINDING_FIELD_KINDS = {
    "repository": "repository_slug",
    "pull_request": "positive_integer",
    "head_sha": "git_object_sha",
    "run_id": "identifier",
    "registry_binding_sha256": "sha256_digest",
    "release_id": "identifier",
    "repo_head": "git_object_sha",
}

PROFILES: dict[str, dict[str, Any]] = {
    "pr": {
        "scope": "pull_request",
        "binding_fields": ("repository", "pull_request", "head_sha"),
        "required_sources": ("grabowski_github_pr_view",),
        "optional_sources": (
            "grabowski_github_checks",
            "grabowski_git_status",
            "grabowski_chronik_history",
        ),
        "fresh_seconds": 900,
        "aging_seconds": 3_600,
        "does_not_establish": (
            "review_approval",
            "ci_pass_authority",
            "branch_protection_state",
        ),
    },
    "bureau": {
        "scope": "bureau_run",
        "binding_fields": ("run_id", "registry_binding_sha256"),
        "required_sources": ("grabowski_bureau_pickup_status",),
        "optional_sources": (
            "grabowski_bureau_candidate_assess",
            "grabowski_bureau_task_publish_preview",
            "grabowski_chronik_history",
        ),
        "fresh_seconds": 600,
        "aging_seconds": 1_800,
        "does_not_establish": (
            "lease_acquisition_permission",
            "lease_ownership_transfer",
            "pickup_permission",
        ),
    },
    "deployment": {
        "scope": "runtime_deployment",
        "binding_fields": ("release_id", "repo_head"),
        "required_sources": ("grabowski_deployment_identity",),
        "optional_sources": (
            "grabowski_runtime_health",
            "grabowski_service_status",
            "grabowski_contract_drift",
            "grabowski_chronik_history",
        ),
        "fresh_seconds": 300,
        "aging_seconds": 900,
        "does_not_establish": (
            "rollback_permission",
            "release_correctness",
            "restart_permission",
        ),
    },
}

SOURCES: dict[str, dict[str, Any]] = {
    "grabowski_github_pr_view": {
        "authority": "github_pull_request_registry",
        "truth_owner": "github",
        "profiles": ("pr",),
        "claim_types": (
            "pull_request_state",
            "pull_request_head_binding",
            "pull_request_mergeability",
        ),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": (
            "ci_result_truth",
            "local_worktree_state",
            "merge_permission",
        ),
    },
    "grabowski_github_checks": {
        "authority": "github_check_registry",
        "truth_owner": "github",
        "profiles": ("pr",),
        "claim_types": ("pull_request_check_result",),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("merge_permission", "review_approval"),
    },
    "grabowski_git_status": {
        "authority": "local_git_worktree",
        "truth_owner": "local_repository",
        "profiles": ("pr",),
        "claim_types": ("local_worktree_state", "local_head_binding"),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("remote_branch_state", "pull_request_state"),
    },
    "grabowski_bureau_pickup_status": {
        "authority": "bureau_run_registry",
        "truth_owner": "bureau",
        "profiles": ("bureau",),
        "claim_types": ("bureau_run_state", "bureau_lease_state"),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("lease_acquisition_permission", "task_completion"),
    },
    "grabowski_bureau_candidate_assess": {
        "authority": "bureau_intake_assessment",
        "truth_owner": "bureau",
        "profiles": ("bureau",),
        "claim_types": ("bureau_candidate_admissibility",),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("publication_authority", "task_completion"),
    },
    "grabowski_bureau_task_publish_preview": {
        "authority": "bureau_publication_preview",
        "truth_owner": "bureau",
        "profiles": ("bureau",),
        "claim_types": ("bureau_publication_readiness",),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("publication_authority", "live_register_state"),
    },
    "grabowski_deployment_identity": {
        "authority": "runtime_release_identity",
        "truth_owner": "grabowski_runtime",
        "profiles": ("deployment",),
        "claim_types": ("deployment_release_identity", "deployment_integrity_flag"),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("deployment_authorization", "runtime_health_state"),
    },
    "grabowski_runtime_health": {
        "authority": "runtime_health_observer",
        "truth_owner": "grabowski_runtime",
        "profiles": ("deployment",),
        "claim_types": ("runtime_health_state",),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("deployment_authorization", "release_correctness"),
    },
    "grabowski_service_status": {
        "authority": "systemd_user_service",
        "truth_owner": "systemd",
        "profiles": ("deployment",),
        "claim_types": ("service_unit_state",),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("deployment_authorization", "release_correctness"),
    },
    "grabowski_contract_drift": {
        "authority": "runtime_contract_observer",
        "truth_owner": "grabowski_runtime",
        "profiles": ("deployment",),
        "claim_types": ("runtime_contract_drift",),
        "historical": False,
        "max_sensitivity": "internal_operational",
        "does_not_establish": ("deployment_authorization", "tool_surface_approval"),
    },
    "grabowski_chronik_history": {
        "authority": "chronik_historical_ledger",
        "truth_owner": "chronik",
        "profiles": ("pr", "bureau", "deployment"),
        "claim_types": ("historical_run_outcome",),
        "historical": True,
        "max_sensitivity": "internal_operational",
        "does_not_establish": (
            "current_git_state",
            "current_ci_state",
            "current_runtime_state",
            "safe_retry",
        ),
    },
}


class ContextFabricError(ValueError):
    """Raised for structurally invalid Operator Context Fabric input."""


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _has_control_character(text: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in text)


def _bounded_text(value: Any, *, label: str, max_chars: int = MAX_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        raise ContextFabricError(f"{label} must be a string")
    text = operator._redact(value).strip()
    if not text:
        raise ContextFabricError(f"{label} must be non-empty")
    if _has_control_character(text):
        raise ContextFabricError(f"{label} must not contain control characters")
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def _optional_bounded_text(value: Any, *, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label=label)


def _scan_for_secret_material(value: Any, *, label: str, depth: int = 0) -> None:
    """Reject payload shapes that could carry secret content.

    Every nested structure of this surface already uses a strict key allowlist.
    This scan runs first so that a smuggled secret produces one explicit,
    testable failure instead of a generic unknown-key rejection.
    """
    if depth > MAX_NESTING_DEPTH:
        raise ContextFabricError(f"{label} is nested too deeply")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContextFabricError(f"{label} keys must be strings")
            if key.strip().lower() in FORBIDDEN_PAYLOAD_KEYS:
                raise ContextFabricError(
                    f"{label} field '{key}' may carry secret content and is rejected"
                )
            _scan_for_secret_material(item, label=label, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_OBSERVATIONS:
            raise ContextFabricError(f"{label} contains too many entries")
        for item in value:
            _scan_for_secret_material(item, label=label, depth=depth + 1)


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    text = _bounded_text(value, label=label, max_chars=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ContextFabricError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ContextFabricError(f"{label} must carry an explicit UTC offset")
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _binding_value(field: str, value: Any) -> str | int:
    kind = BINDING_FIELD_KINDS[field]
    if kind == "positive_integer":
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000_000:
            raise ContextFabricError(f"binding field {field} must be a positive integer")
        return value
    text = _bounded_text(value, label=f"binding field {field}", max_chars=MAX_BINDING_VALUE_CHARS)
    patterns = {
        "repository_slug": REPOSITORY_RE,
        "git_object_sha": SHA_RE,
        "sha256_digest": SHA256_RE,
        "identifier": IDENTIFIER_RE,
    }
    if patterns[kind].fullmatch(text) is None:
        raise ContextFabricError(f"binding field {field} does not match {kind}")
    return text


def _normalize_binding(
    profile_name: str, binding: Any
) -> tuple[dict[str, Any], list[str]]:
    """Return the profile-bound target and the list of missing required fields."""
    profile = PROFILES[profile_name]
    if binding is None:
        binding = {}
    if not isinstance(binding, dict):
        raise ContextFabricError("binding must be an object")
    fields = profile["binding_fields"]
    unsupported = sorted(set(binding) - set(fields))
    if unsupported:
        raise ContextFabricError(
            f"binding contains fields outside profile {profile_name}: {unsupported}"
        )
    normalized: dict[str, Any] = {}
    missing: list[str] = []
    for field in fields:
        if field not in binding or binding[field] is None:
            missing.append(field)
            continue
        normalized[field] = _binding_value(field, binding[field])
    return normalized, missing


def _evidence_ref(value: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContextFabricError(f"evidence reference {index} must be an object")
    unsupported = sorted(set(value) - set(EVIDENCE_REF_KEYS))
    if unsupported:
        raise ContextFabricError(
            f"evidence reference {index} has unsupported fields: {unsupported}"
        )
    reference_type = _bounded_text(
        value.get("type"), label=f"evidence reference {index} type", max_chars=64
    )
    if reference_type not in EVIDENCE_REF_TYPES:
        raise ContextFabricError(f"evidence reference {index} type is unsupported")
    reference: dict[str, Any] = {
        "type": reference_type,
        "id": _bounded_text(value.get("id"), label=f"evidence reference {index} id"),
    }
    repo = _optional_bounded_text(value.get("repo"), label=f"evidence reference {index} repo")
    if repo is not None:
        if REPOSITORY_RE.fullmatch(repo) is None:
            raise ContextFabricError(f"evidence reference {index} repo is invalid")
        reference["repo"] = repo
    if value.get("url") is not None:
        url = _bounded_text(value.get("url"), label=f"evidence reference {index} url", max_chars=512)
        if HTTPS_URL_RE.fullmatch(url) is None:
            raise ContextFabricError(f"evidence reference {index} url must be an HTTPS URL")
        reference["url"] = url
    digest = _optional_bounded_text(value.get("sha256"), label=f"evidence reference {index} sha256")
    if digest is not None:
        if SHA256_RE.fullmatch(digest) is None:
            raise ContextFabricError(f"evidence reference {index} sha256 is invalid")
        reference["sha256"] = digest
    head_sha = _optional_bounded_text(value.get("head_sha"), label=f"evidence reference {index} head_sha")
    if head_sha is not None:
        if SHA_RE.fullmatch(head_sha) is None:
            raise ContextFabricError(f"evidence reference {index} head_sha is invalid")
        reference["head_sha"] = head_sha
    return reference


def _normalize_evidence_refs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ContextFabricError("each observation requires at least one evidence reference")
    if len(value) > MAX_EVIDENCE_REFS:
        raise ContextFabricError("observation has too many evidence references")
    return [_evidence_ref(item, index=index) for index, item in enumerate(value)]


def _sensitivity(value: Any, *, source: dict[str, Any]) -> str:
    ceiling = source["max_sensitivity"]
    if value is None:
        return ceiling
    text = _bounded_text(value, label="sensitivity", max_chars=64)
    if text not in SENSITIVITY_RANK:
        raise ContextFabricError("sensitivity is unsupported")
    if SENSITIVITY_RANK[text] > SENSITIVITY_RANK[ceiling]:
        raise ContextFabricError("sensitivity exceeds the ceiling declared for the source")
    return text


def _freshness(
    *, historical: bool, observed_at: datetime | None, as_of: datetime, profile: dict[str, Any]
) -> tuple[str, int | None]:
    if historical or observed_at is None:
        return "historical", None
    age_seconds = int((as_of - observed_at).total_seconds())
    if age_seconds <= profile["fresh_seconds"]:
        return "fresh", age_seconds
    if age_seconds <= profile["aging_seconds"]:
        return "aging", age_seconds
    return "stale", age_seconds


def _claim_does_not_establish(
    profile: dict[str, Any], source: dict[str, Any]
) -> list[str]:
    return sorted(
        {
            *FABRIC_DOES_NOT_ESTABLISH,
            *profile["does_not_establish"],
            *source["does_not_establish"],
        }
    )


def _build_claim(
    observation: Any,
    *,
    profile_name: str,
    binding: dict[str, Any],
    binding_sha256: str,
    as_of: datetime,
) -> dict[str, Any]:
    profile = PROFILES[profile_name]
    if not isinstance(observation, dict):
        raise ContextFabricError("observation must be an object")
    unsupported = sorted(set(observation) - OBSERVATION_KEYS)
    if unsupported:
        raise ContextFabricError(f"observation has unsupported fields: {unsupported}")

    source_tool = _bounded_text(
        observation.get("source_tool"), label="source_tool", max_chars=128
    )
    source = SOURCES.get(source_tool)
    if source is None:
        raise ContextFabricError("source_tool is not a declared authoritative source")
    if profile_name not in source["profiles"]:
        raise ContextFabricError(
            f"source_tool {source_tool} is not an authority for profile {profile_name}"
        )

    claim_type = _bounded_text(observation.get("claim_type"), label="claim_type", max_chars=128)
    if claim_type not in source["claim_types"]:
        raise ContextFabricError(
            f"authority {source['authority']} may not establish claim_type {claim_type}"
        )

    observation_binding, missing = _normalize_binding(profile_name, observation.get("binding"))
    if missing:
        raise ContextFabricError(f"observation binding is incomplete: {missing}")
    if observation_binding != binding:
        raise ContextFabricError("observation binding does not match the target binding")

    historical_flag = observation.get("historical", False)
    if not isinstance(historical_flag, bool):
        raise ContextFabricError("historical must be a boolean")
    if historical_flag != bool(source["historical"]):
        raise ContextFabricError(
            f"source {source_tool} requires historical={bool(source['historical'])}"
        )
    observed_at: datetime | None = None
    if historical_flag:
        if observation.get("observed_at") is not None:
            raise ContextFabricError("historical observations may not carry observed_at")
    else:
        if observation.get("observed_at") is None:
            raise ContextFabricError("live observations require observed_at")
        observed_at = _parse_timestamp(observation.get("observed_at"), label="observed_at")
        if observed_at > as_of:
            raise ContextFabricError("observed_at may not be later than as_of")

    status = _bounded_text(observation.get("status"), label="status", max_chars=128)
    detail = _optional_bounded_text(observation.get("detail"), label="detail")
    evidence_refs = _normalize_evidence_refs(observation.get("evidence_refs"))
    sensitivity = _sensitivity(observation.get("sensitivity"), source=source)
    freshness, age_seconds = _freshness(
        historical=historical_flag,
        observed_at=observed_at,
        as_of=as_of,
        profile=profile,
    )

    identity = {
        "authority": source["authority"],
        "binding_sha256": binding_sha256,
        "claim_type": claim_type,
        "detail": detail,
        "evidence_refs": evidence_refs,
        "historical": historical_flag,
        "observed_at": _timestamp_text(observed_at) if observed_at else None,
        "scope": profile["scope"],
        "sensitivity": sensitivity,
        "source_tool": source_tool,
        "status": status,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": CLAIM_KIND,
        "claim_id": "sha256:" + _sha256_json(identity),
        "claim_type": claim_type,
        "authority": source["authority"],
        "authority_tool": source_tool,
        "truth_owner": source["truth_owner"],
        "fabric_role": FABRIC_ROLE,
        "scope": profile["scope"],
        "binding": dict(binding),
        "binding_sha256": binding_sha256,
        "temporal_marker": "historical" if historical_flag else "observed",
        "historical": historical_flag,
        "observed_at": _timestamp_text(observed_at) if observed_at else None,
        "age_seconds": age_seconds,
        "status": status,
        "detail": detail,
        "freshness": freshness,
        "sensitivity": sensitivity,
        "evidence_refs": evidence_refs,
        "assertion_sha256": _sha256_json({"detail": detail, "status": status}),
        "conflicts": [],
        "does_not_establish": _claim_does_not_establish(profile, source),
    }


def _apply_conflicts(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Link contradicting claims without resolving or ranking them."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for claim in claims:
        groups.setdefault((claim["claim_type"], claim["scope"]), []).append(claim)
    contradictions: list[dict[str, Any]] = []
    for (claim_type, scope), group in sorted(groups.items()):
        assertions = {claim["assertion_sha256"] for claim in group}
        if len(assertions) < 2:
            continue
        for claim in group:
            claim["conflicts"] = sorted(
                other["claim_id"]
                for other in group
                if other["claim_id"] != claim["claim_id"]
                and other["assertion_sha256"] != claim["assertion_sha256"]
            )
        contradictions.append(
            {
                "claim_type": claim_type,
                "scope": scope,
                "claim_ids": sorted(claim["claim_id"] for claim in group),
                "distinct_assertion_count": len(assertions),
                "authorities": sorted({claim["authority"] for claim in group}),
                "resolution": CONFLICT_RESOLUTION,
            }
        )
    return contradictions


def _context_envelope(
    *,
    profile_name: str,
    binding: dict[str, Any],
    missing_binding_fields: list[str],
    as_of: datetime,
    claim_budget: int,
) -> dict[str, Any]:
    profile = PROFILES[profile_name]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": CONTEXT_KIND,
        "contract_id": CONTRACT_ID,
        "authority": FABRIC_AUTHORITY,
        "fabric_role": FABRIC_ROLE,
        "profile": profile_name,
        "scope": profile["scope"],
        "as_of": _timestamp_text(as_of),
        "binding": dict(binding),
        "binding_sha256": _sha256_json(binding),
        "binding_complete": not missing_binding_fields,
        "missing_binding_fields": list(missing_binding_fields),
        "required_sources": list(profile["required_sources"]),
        "optional_sources": list(profile["optional_sources"]),
        "observed_sources": [],
        "missing_required_sources": list(profile["required_sources"]),
        "claim_count": 0,
        "claims": [],
        "contradiction_count": 0,
        "contradictions": [],
        "conflict_resolution": CONFLICT_RESOLUTION,
        "freshness_counts": {},
        "packing": {
            "claim_budget": claim_budget,
            "input_observation_count": 0,
            "accepted_observation_count": 0,
            "emitted_claim_count": 0,
            "dropped_claim_count": 0,
            "dropped_claim_ids": [],
            "truncated": False,
        },
        "rejected_observation_count": 0,
        "rejected_observations": [],
        "rejected_observations_truncated": False,
        "sensitivity_ceiling": "restricted_operational",
        "secret_content_returned": False,
        "composed": False,
        "failure": None,
        "does_not_establish": sorted(
            {*FABRIC_DOES_NOT_ESTABLISH, *profile["does_not_establish"]}
        ),
    }


def _sealed(context: dict[str, Any]) -> dict[str, Any]:
    unsigned = {key: value for key, value in context.items() if key != "context_sha256"}
    return {**unsigned, "context_sha256": _sha256_json(unsigned)}


def _validated_profile(value: Any) -> str:
    name = _bounded_text(value, label="profile", max_chars=64)
    if name not in PROFILES:
        raise ContextFabricError(f"profile must be one of {sorted(PROFILES)}")
    return name


def _validated_claim_budget(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_CLAIM_BUDGET:
        raise ContextFabricError(f"claim_budget must be between 1 and {MAX_CLAIM_BUDGET}")
    return value


def plan_context(profile: Any, binding: Any = None) -> dict[str, Any]:
    """Return the read plan and fail-closed preconditions for one profile."""
    profile_name = _validated_profile(profile)
    _scan_for_secret_material(binding, label="binding")
    definition = PROFILES[profile_name]
    normalized, missing = _normalize_binding(profile_name, binding)
    source_plan = [
        {
            "source_tool": name,
            "authority": SOURCES[name]["authority"],
            "truth_owner": SOURCES[name]["truth_owner"],
            "requirement": "required" if name in definition["required_sources"] else "optional",
            "temporal_marker": "historical" if SOURCES[name]["historical"] else "observed",
            "claim_types": list(SOURCES[name]["claim_types"]),
            "max_sensitivity": SOURCES[name]["max_sensitivity"],
            "does_not_establish": list(SOURCES[name]["does_not_establish"]),
        }
        for name in (*definition["required_sources"], *definition["optional_sources"])
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "contract_id": CONTRACT_ID,
        "authority": FABRIC_AUTHORITY,
        "fabric_role": FABRIC_ROLE,
        "profile": profile_name,
        "scope": definition["scope"],
        "binding_fields": [
            {"field": field, "kind": BINDING_FIELD_KINDS[field], "required": True}
            for field in definition["binding_fields"]
        ],
        "binding": normalized,
        "missing_binding_fields": missing,
        "binding_complete": not missing,
        "ready": not missing,
        "sources": source_plan,
        "freshness_bands": {
            "fresh_seconds": definition["fresh_seconds"],
            "aging_seconds": definition["aging_seconds"],
            "beyond_aging": "stale",
            "historical_observations": "historical",
        },
        "limits": {
            "max_observations": MAX_OBSERVATIONS,
            "max_claim_budget": MAX_CLAIM_BUDGET,
            "max_evidence_refs_per_observation": MAX_EVIDENCE_REFS,
        },
        "fail_closed_conditions": [
            "missing_required_binding_field",
            "missing_required_authoritative_source",
            "claim_budget_excludes_required_authority",
        ],
        "does_not_establish": sorted(
            {*FABRIC_DOES_NOT_ESTABLISH, *definition["does_not_establish"]}
        ),
    }


def compose_context(
    profile: Any,
    binding: Any,
    as_of: Any,
    observations: Any = None,
    claim_budget: Any = 50,
) -> dict[str, Any]:
    """Compose and pack one evidence-bound, fail-closed operator context."""
    profile_name = _validated_profile(profile)
    budget = _validated_claim_budget(claim_budget)
    _scan_for_secret_material(binding, label="binding")
    _scan_for_secret_material(observations, label="observations")
    reference_time = _parse_timestamp(as_of, label="as_of")
    definition = PROFILES[profile_name]
    normalized_binding, missing_binding = _normalize_binding(profile_name, binding)

    if observations is None:
        observations = []
    if not isinstance(observations, list):
        raise ContextFabricError("observations must be a list")
    if len(observations) > MAX_OBSERVATIONS:
        raise ContextFabricError(f"observations may not exceed {MAX_OBSERVATIONS} entries")

    context = _context_envelope(
        profile_name=profile_name,
        binding=normalized_binding,
        missing_binding_fields=missing_binding,
        as_of=reference_time,
        claim_budget=budget,
    )
    context["packing"]["input_observation_count"] = len(observations)

    if missing_binding:
        context["failure"] = {
            "code": "missing_required_binding_fields",
            "detail": "The target binding is incomplete; no claim may be bound.",
            "missing_binding_fields": list(missing_binding),
            "missing_required_sources": list(definition["required_sources"]),
        }
        return _sealed(context)

    binding_sha256 = context["binding_sha256"]
    claims: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    rejected_count = 0
    for index, observation in enumerate(observations):
        try:
            claims.append(
                _build_claim(
                    observation,
                    profile_name=profile_name,
                    binding=normalized_binding,
                    binding_sha256=binding_sha256,
                    as_of=reference_time,
                )
            )
        except ContextFabricError as exc:
            rejected_count += 1
            if len(rejected) < MAX_REJECTED_OBSERVATIONS:
                rejected.append(
                    {
                        "index": index,
                        "code": "invalid_observation",
                        "detail": _bounded_text(str(exc), label="rejection detail"),
                    }
                )

    context["rejected_observation_count"] = rejected_count
    context["rejected_observations"] = rejected
    context["rejected_observations_truncated"] = rejected_count > MAX_REJECTED_OBSERVATIONS
    context["packing"]["accepted_observation_count"] = len(claims)

    required = set(definition["required_sources"])
    observed_sources = sorted({claim["authority_tool"] for claim in claims})
    missing_required = sorted(required - set(observed_sources))
    context["observed_sources"] = observed_sources
    context["missing_required_sources"] = missing_required
    if missing_required:
        context["failure"] = {
            "code": "missing_required_authoritative_sources",
            "detail": "A required authority produced no accepted observation.",
            "missing_binding_fields": [],
            "missing_required_sources": missing_required,
        }
        return _sealed(context)

    def claim_sort_key(claim: dict[str, Any]) -> tuple[Any, ...]:
        return (
            0 if claim["authority_tool"] in required else 1,
            claim["claim_type"],
            claim["authority_tool"],
            claim["claim_id"],
        )

    claims.sort(key=claim_sort_key)
    required_source_order = tuple(definition["required_sources"])
    if budget < len(required_source_order):
        context["packing"]["dropped_claim_count"] = len(claims)
        context["packing"]["dropped_claim_ids"] = [claim["claim_id"] for claim in claims]
        context["packing"]["truncated"] = bool(claims)
        context["failure"] = {
            "code": "claim_budget_excludes_required_authority",
            "detail": "The claim budget is too small to carry every required authority.",
            "missing_binding_fields": [],
            "missing_required_sources": [],
        }
        return _sealed(context)

    required_representatives = [
        next(claim for claim in claims if claim["authority_tool"] == source_tool)
        for source_tool in required_source_order
    ]
    representative_objects = {id(claim) for claim in required_representatives}
    remaining = [claim for claim in claims if id(claim) not in representative_objects]
    kept = required_representatives + remaining[: budget - len(required_representatives)]
    kept.sort(key=claim_sort_key)
    kept_objects = {id(claim) for claim in kept}
    dropped = [claim for claim in claims if id(claim) not in kept_objects]

    contradictions = _apply_conflicts(kept)
    freshness_counts: dict[str, int] = {}
    for claim in kept:
        freshness_counts[claim["freshness"]] = freshness_counts.get(claim["freshness"], 0) + 1
    ceiling = "public_operational"
    for claim in kept:
        if SENSITIVITY_RANK[claim["sensitivity"]] > SENSITIVITY_RANK[ceiling]:
            ceiling = claim["sensitivity"]

    context["claims"] = kept
    context["claim_count"] = len(kept)
    context["contradictions"] = contradictions
    context["contradiction_count"] = len(contradictions)
    context["freshness_counts"] = dict(sorted(freshness_counts.items()))
    context["sensitivity_ceiling"] = ceiling
    context["packing"]["emitted_claim_count"] = len(kept)
    context["packing"]["dropped_claim_count"] = len(dropped)
    context["packing"]["dropped_claim_ids"] = [claim["claim_id"] for claim in dropped]
    context["packing"]["truncated"] = bool(dropped)
    context["composed"] = True
    return _sealed(context)


def _verified_context(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContextFabricError(f"{label} must be an object")
    if value.get("kind") != CONTEXT_KIND or value.get("contract_id") != CONTRACT_ID:
        raise ContextFabricError(f"{label} is not an Operator Context Fabric context")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ContextFabricError(f"{label} uses an unsupported schema version")
    claimed = value.get("context_sha256")
    unsigned = {key: item for key, item in value.items() if key != "context_sha256"}
    if not isinstance(claimed, str) or SHA256_RE.fullmatch(claimed) is None:
        raise ContextFabricError(f"{label} digest is malformed")
    if claimed != _sha256_json(unsigned):
        raise ContextFabricError(f"{label} digest does not bind its content")
    profile_name = value.get("profile")
    if profile_name not in PROFILES:
        raise ContextFabricError(f"{label} declares an unsupported profile")
    return value


def explain_context(context: Any, claim_id: Any = None) -> dict[str, Any]:
    """Explain why a bound context carries each claim, without adding truth."""
    verified = _verified_context(context, label="context")
    selected = None
    if claim_id is not None:
        selected = _bounded_text(claim_id, label="claim_id", max_chars=128)
    profile_name = str(verified["profile"])
    required = set(PROFILES[profile_name]["required_sources"])
    raw_claims = verified.get("claims")
    if not isinstance(raw_claims, list):
        raise ContextFabricError("context claims must be a list")
    explanations: list[dict[str, Any]] = []
    for claim in raw_claims:
        if not isinstance(claim, dict):
            raise ContextFabricError("context claims must be objects")
        if selected is not None and claim.get("claim_id") != selected:
            continue
        authority_tool = str(claim.get("authority_tool", ""))
        conflicts = claim.get("conflicts") or []
        explanations.append(
            {
                "claim_id": claim.get("claim_id"),
                "claim_type": claim.get("claim_type"),
                "authority": claim.get("authority"),
                "authority_tool": authority_tool,
                "truth_owner": claim.get("truth_owner"),
                "scope": claim.get("scope"),
                "binding_sha256": claim.get("binding_sha256"),
                "inclusion_reason": (
                    "required_authority"
                    if authority_tool in required
                    else "optional_supporting_authority"
                ),
                "temporal_marker": claim.get("temporal_marker"),
                "observed_at": claim.get("observed_at"),
                "age_seconds": claim.get("age_seconds"),
                "freshness": claim.get("freshness"),
                "sensitivity": claim.get("sensitivity"),
                "evidence_ref_count": len(claim.get("evidence_refs") or []),
                "conflicts": list(conflicts),
                "conflict_status": "contradicted" if conflicts else "uncontradicted",
                "reread_before_acting": [authority_tool] if authority_tool else [],
                "does_not_establish": list(claim.get("does_not_establish") or []),
            }
        )
    if selected is not None and not explanations:
        raise ContextFabricError("claim_id is not present in the supplied context")
    coverage = {
        "required_sources": sorted(required),
        "observed_sources": list(verified.get("observed_sources") or []),
        "missing_required_sources": list(verified.get("missing_required_sources") or []),
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": EXPLANATION_KIND,
        "contract_id": CONTRACT_ID,
        "authority": FABRIC_AUTHORITY,
        "fabric_role": FABRIC_ROLE,
        "profile": profile_name,
        "scope": verified.get("scope"),
        "context_sha256": verified.get("context_sha256"),
        "context_digest_matches": True,
        "producer_authenticated": False,
        "composed": verified.get("composed") is True,
        "failure": verified.get("failure"),
        "selected_claim_id": selected,
        "explanation_count": len(explanations),
        "explanations": explanations,
        "authority_coverage": coverage,
        "contradiction_count": verified.get("contradiction_count", 0),
        "conflict_resolution": CONFLICT_RESOLUTION,
        "does_not_establish": list(verified.get("does_not_establish") or []),
    }


def compare_contexts(baseline: Any, candidate: Any) -> dict[str, Any]:
    """Compare two bound contexts for the same target without ranking them."""
    left = _verified_context(baseline, label="baseline")
    right = _verified_context(candidate, label="candidate")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": COMPARISON_KIND,
        "contract_id": CONTRACT_ID,
        "authority": FABRIC_AUTHORITY,
        "fabric_role": FABRIC_ROLE,
        "profile": left.get("profile"),
        "baseline_context_sha256": left.get("context_sha256"),
        "candidate_context_sha256": right.get("context_sha256"),
        "baseline_as_of": left.get("as_of"),
        "candidate_as_of": right.get("as_of"),
        "binding_sha256": left.get("binding_sha256"),
        "comparable": False,
        "failure": None,
        "added_claim_ids": [],
        "removed_claim_ids": [],
        "retained_claim_ids": [],
        "changed_assertions": [],
        "authority_delta": {"added_sources": [], "removed_sources": []},
        "freshness_counts": {
            "baseline": dict(left.get("freshness_counts") or {}),
            "candidate": dict(right.get("freshness_counts") or {}),
        },
        "contradiction_delta": {
            "baseline": left.get("contradiction_count", 0),
            "candidate": right.get("contradiction_count", 0),
            "resolution": CONFLICT_RESOLUTION,
        },
        "does_not_establish": sorted(
            {
                *FABRIC_DOES_NOT_ESTABLISH,
                "progress",
                "regression",
                "approval_to_proceed",
            }
        ),
    }
    if left.get("profile") != right.get("profile"):
        result["failure"] = {
            "code": "profile_mismatch",
            "detail": "Contexts for different profiles are not comparable.",
        }
        return result
    if left.get("binding_sha256") != right.get("binding_sha256"):
        result["failure"] = {
            "code": "binding_mismatch",
            "detail": "Contexts bound to different targets are not comparable.",
        }
        return result
    if left.get("composed") is not True or right.get("composed") is not True:
        result["failure"] = {
            "code": "uncomposed_context",
            "detail": "A fail-closed context carries no claims to compare.",
        }
        return result

    def indexed(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
        claims = context.get("claims")
        if not isinstance(claims, list):
            raise ContextFabricError("context claims must be a list")
        table: dict[str, dict[str, Any]] = {}
        for claim in claims:
            if not isinstance(claim, dict) or not isinstance(claim.get("claim_id"), str):
                raise ContextFabricError("context claims must carry a claim_id")
            table[claim["claim_id"]] = claim
        return table

    left_claims = indexed(left)
    right_claims = indexed(right)
    result["added_claim_ids"] = sorted(set(right_claims) - set(left_claims))
    result["removed_claim_ids"] = sorted(set(left_claims) - set(right_claims))
    result["retained_claim_ids"] = sorted(set(left_claims) & set(right_claims))

    def assertions(table: dict[str, dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
        grouped: dict[tuple[str, str], set[str]] = {}
        for claim in table.values():
            key = (str(claim.get("claim_type")), str(claim.get("authority_tool")))
            grouped.setdefault(key, set()).add(str(claim.get("status")))
        return grouped

    left_assertions = assertions(left_claims)
    right_assertions = assertions(right_claims)
    for key in sorted(set(left_assertions) | set(right_assertions)):
        before = sorted(left_assertions.get(key, set()))
        after = sorted(right_assertions.get(key, set()))
        if before != after:
            result["changed_assertions"].append(
                {
                    "claim_type": key[0],
                    "authority_tool": key[1],
                    "baseline_status": before,
                    "candidate_status": after,
                }
            )
    left_sources = set(left.get("observed_sources") or [])
    right_sources = set(right.get("observed_sources") or [])
    result["authority_delta"] = {
        "added_sources": sorted(right_sources - left_sources),
        "removed_sources": sorted(left_sources - right_sources),
    }
    result["comparable"] = True
    return result


@mcp.tool(name="grabowski_context_fabric_plan", annotations=READ_ONLY)
def grabowski_context_fabric_plan(
    profile: str,
    binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Plan one evidence-bound operator context read for pr, bureau or deployment."""
    return plan_context(profile, binding)


@mcp.tool(name="grabowski_context_fabric_compose", annotations=READ_ONLY)
def grabowski_context_fabric_compose(
    profile: str,
    binding: dict[str, Any],
    as_of: str,
    observations: list[dict[str, Any]] | None = None,
    claim_budget: int = 50,
) -> dict[str, Any]:
    """Compose and pack one fail-closed, authority-bound operator context."""
    return compose_context(profile, binding, as_of, observations, claim_budget)


@mcp.tool(name="grabowski_context_fabric_explain", annotations=READ_ONLY)
def grabowski_context_fabric_explain(
    composed_context: dict[str, Any],
    claim_id: str | None = None,
) -> dict[str, Any]:
    """Explain claim inclusion, authority and freshness for one bound context."""
    return explain_context(composed_context, claim_id)


@mcp.tool(name="grabowski_context_fabric_compare", annotations=READ_ONLY)
def grabowski_context_fabric_compare(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Compare two digest-bound contexts for one target without ranking them."""
    return compare_contexts(baseline, candidate)

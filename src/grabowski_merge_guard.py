from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
from typing import Any
from urllib.parse import quote
import weakref

import grabowski_merge_delivery


_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
_MERGE_GUARD_TTL_SECONDS = 300
_MERGE_GUARD_MAX_CHANGED_PATHS = 100
_MERGE_GUARD_MAX_CHANGED_PATH_BYTES = 8 * 1024
_MERGE_GUARD_REPLAY_PARAMETERS = frozenset({"merge_lease_snapshot", "merge_guard_receipt"})
_CODEX_REVIEW_ACTORS = frozenset({
    "chatgpt-codex-connector",
    "chatgpt-codex-connector[bot]",
})
_CODEX_REQUEST_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
_CODEX_REQUEST_RE = re.compile(
    r"<!--\s*grabowski-codex-review-request:v1\s*(\{.*?\})\s*-->",
    re.DOTALL,
)
_CODEX_CLEAN_FOOTER_PATTERN = (
    r"<details> <summary>ℹ️ About Codex in GitHub</summary>\n"
    r"<br/>\n\n"
    r"\[Your team has set up Codex to review pull requests in this repo\]"
    r"\(https://chatgpt\.com/codex/cloud/settings/general\)\. "
    r"Reviews are triggered when you\n"
    r"- Open a pull request for review\n"
    r"- Mark a draft as ready\n"
    r'- Comment "@codex review"\.\n\n'
    r"If Codex has suggestions, it will comment; otherwise it will react with 👍\."
    r"\n{2,6}"
    r"Codex can also answer questions or update the PR\. Try commenting "
    r'"@codex address that feedback"\.\n\n'
    r"</details>"
)
_CODEX_CLEAN_RESULT_RE = re.compile(
    r"\ACodex Review: Didn't find any major issues\. "
    r"(?:[^\n]{0,79}[.!?]|[^\n]{0,62}:[a-z0-9_+-]{1,16}:)\n\n"
    r"\*\*Reviewed commit:\*\* `([0-9a-f]{10,40})`\n\n"
    + _CODEX_CLEAN_FOOTER_PATTERN
    + r"\Z"
)
_CODEX_THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100) {
        nodes {
          id
          isResolved
          comments(first: 100) {
            nodes {
              databaseId
              createdAt
              author { login }
              commit { oid }
              pullRequestReview { databaseId }
            }
            pageInfo { hasNextPage }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  }
}
""".strip()
_SERVER_ACTOR_SCHEMA_VERSION = 1
_SERVER_ACTOR_KIND = "grabowski_server_runtime_actor_identity"
_SERVER_ACTOR_TTL_SECONDS = 300
_SERVER_ACTOR_SECRET = secrets.token_bytes(32)
_SERVER_ACTOR_LOCK = threading.Lock()
_SERVER_ACTOR_SESSIONS: weakref.WeakKeyDictionary[Any, str] = weakref.WeakKeyDictionary()
_SERVER_ACTOR_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "owner_id",
        "profile",
        "issued_at_unix",
        "expires_at_unix",
        "proof_sha256",
    }
)
_SERVER_TASK_DELEGATION_SCHEMA_VERSION = 1
_SERVER_TASK_DELEGATION_KIND = "grabowski_server_task_lease_delegation"
_SERVER_TASK_DELEGATION_TTL_SECONDS = 300
_SERVER_TASK_DELEGATION_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "actor_owner_id",
        "actor_identity_sha256",
        "task_id",
        "lease_owner_id",
        "task_record_sha256",
        "resource_keys",
        "resource_keys_sha256",
        "lease_bindings_sha256",
        "captain_request_sha256",
        "issued_at_unix",
        "expires_at_unix",
        "proof_sha256",
    }
)
_SERVER_OPERATOR_DELEGATION_SCHEMA_VERSION = 1
_SERVER_OPERATOR_DELEGATION_KIND = "grabowski_server_operator_lease_delegation"
_SERVER_OPERATOR_DELEGATION_TTL_SECONDS = 300
_LEASE_SNAPSHOT_KEYS = frozenset(
    {
        "resource_key",
        "owner_id",
        "acquired_at_unix",
        "updated_at_unix",
        "expires_at_unix",
        "metadata_sha256",
    }
)
_SERVER_OPERATOR_DELEGATION_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "actor_owner_id",
        "actor_identity_sha256",
        "lease_owner_id",
        "resource_keys",
        "resource_keys_sha256",
        "lease_snapshots",
        "lease_bindings_sha256",
        "captain_request_sha256",
        "issued_at_unix",
        "expires_at_unix",
        "proof_sha256",
    }
)
_SERVER_RESERVED_PARAMETER_KEYS = frozenset(
    {
        "_server_runtime_actor_identity",
        "_server_task_lease_delegation",
        "_server_operator_lease_delegation",
    }
)
_TASK_OWNER_RE = re.compile(r"task:([0-9a-f]{24})\Z")
_DIRECT_OPERATOR_OWNER_RE = re.compile(r"operator:[A-Za-z0-9._:@-]{1,119}\Z")


def _normalize_codex_comment_body(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).rstrip("\n")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def issue_server_runtime_actor_identity(
    session: Any,
    *,
    profile: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Issue one short-lived, server-authenticated owner identity for an MCP session."""
    if session is None:
        raise ValueError("server runtime actor session is required")
    if _OWNER_RE.fullmatch(profile) is None:
        raise ValueError("server runtime actor profile is invalid")
    with _SERVER_ACTOR_LOCK:
        try:
            session_nonce = _SERVER_ACTOR_SESSIONS.get(session)
        except TypeError as exc:
            raise ValueError("server runtime actor session must support weak references") from exc
        if session_nonce is None:
            session_nonce = secrets.token_hex(32)
            try:
                _SERVER_ACTOR_SESSIONS[session] = session_nonce
            except TypeError as exc:
                raise ValueError("server runtime actor session must support weak references") from exc
    owner_digest = hmac.new(
        _SERVER_ACTOR_SECRET,
        b"owner\x00" + session_nonce.encode("ascii") + b"\x00" + profile.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    issued_at = int(time.time()) if now_unix is None else int(now_unix)
    payload: dict[str, Any] = {
        "schema_version": _SERVER_ACTOR_SCHEMA_VERSION,
        "kind": _SERVER_ACTOR_KIND,
        "owner_id": f"runtime-actor:{owner_digest}",
        "profile": profile,
        "issued_at_unix": issued_at,
        "expires_at_unix": issued_at + _SERVER_ACTOR_TTL_SECONDS,
    }
    payload["proof_sha256"] = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return payload


def verify_server_runtime_actor_identity(
    value: Any,
    *,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Verify a server-issued runtime actor proof and return bounded receipt evidence."""
    if not isinstance(value, dict) or set(value) != _SERVER_ACTOR_KEYS:
        raise ValueError("server runtime actor identity shape is invalid")
    if value.get("schema_version") != _SERVER_ACTOR_SCHEMA_VERSION:
        raise ValueError("server runtime actor identity schema is invalid")
    if value.get("kind") != _SERVER_ACTOR_KIND:
        raise ValueError("server runtime actor identity kind is invalid")
    owner_id = value.get("owner_id")
    profile = value.get("profile")
    if not isinstance(owner_id, str) or _OWNER_RE.fullmatch(owner_id) is None:
        raise ValueError("server runtime actor owner is invalid")
    if not isinstance(profile, str) or _OWNER_RE.fullmatch(profile) is None:
        raise ValueError("server runtime actor profile is invalid")
    issued_at = value.get("issued_at_unix")
    expires_at = value.get("expires_at_unix")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise ValueError("server runtime actor issue time is invalid")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ValueError("server runtime actor expiry is invalid")
    if expires_at - issued_at != _SERVER_ACTOR_TTL_SECONDS:
        raise ValueError("server runtime actor lifetime is invalid")
    current = int(time.time()) if now_unix is None else int(now_unix)
    if issued_at > current + 5 or expires_at < current:
        raise ValueError("server runtime actor identity is not current")
    unsigned = {key: value[key] for key in value if key != "proof_sha256"}
    expected_proof = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    proof = value.get("proof_sha256")
    if not isinstance(proof, str) or not hmac.compare_digest(proof, expected_proof):
        raise ValueError("server runtime actor proof is invalid")
    return {
        "owner_id": owner_id,
        "profile": profile,
        "identity_sha256": _sha256_json(value),
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
    }


def captain_request_sha256(parameters: dict[str, Any]) -> str:
    if not isinstance(parameters, dict):
        raise ValueError("captain request parameters must be an object")
    visible = {
        key: value
        for key, value in parameters.items()
        if key not in _SERVER_RESERVED_PARAMETER_KEYS and key != "session_escalation"
    }
    return _sha256_json(visible)


def issue_server_task_lease_delegation(
    actor_identity: dict[str, Any],
    task_evidence: dict[str, Any],
    *,
    captain_request_sha256_value: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    actor = verify_server_runtime_actor_identity(actor_identity, now_unix=now_unix)
    if _SHA256_RE.fullmatch(captain_request_sha256_value) is None:
        raise ValueError("captain request digest is invalid")
    expected_evidence_keys = {
        "schema_version",
        "kind",
        "task_id",
        "lease_owner_id",
        "state",
        "attempt",
        "updated_at_unix",
        "resource_keys_sha256",
        "lease_bindings_sha256",
        "task_record_sha256",
        "resource_keys",
        "minimum_expires_at_unix",
        "observed_at_unix",
    }
    if not isinstance(task_evidence, dict) or set(task_evidence) != expected_evidence_keys:
        raise ValueError("task delegation evidence shape is invalid")
    if task_evidence.get("schema_version") != 1:
        raise ValueError("task delegation evidence schema is invalid")
    if task_evidence.get("kind") != "grabowski_live_task_lease_delegation_evidence":
        raise ValueError("task delegation evidence kind is invalid")
    task_id = task_evidence.get("task_id")
    lease_owner_id = task_evidence.get("lease_owner_id")
    if not isinstance(task_id, str) or re.fullmatch(r"[0-9a-f]{24}", task_id) is None:
        raise ValueError("task delegation task_id is invalid")
    if lease_owner_id != f"task:{task_id}":
        raise ValueError("task delegation lease owner is invalid")
    if task_evidence.get("state") != "running":
        raise ValueError("task delegation requires a running task")
    for field in ("attempt", "updated_at_unix", "observed_at_unix"):
        field_value = task_evidence.get(field)
        if not isinstance(field_value, int) or isinstance(field_value, bool) or field_value < 0:
            raise ValueError(f"task delegation {field} is invalid")
    resource_keys = task_evidence.get("resource_keys")
    if (
        not isinstance(resource_keys, list)
        or not resource_keys
        or len(resource_keys) > 64
        or any(not isinstance(key, str) or not key for key in resource_keys)
        or resource_keys != sorted(set(resource_keys))
    ):
        raise ValueError("task delegation resource keys are invalid")
    resource_keys_sha256 = _sha256_json(resource_keys)
    if task_evidence.get("resource_keys_sha256") != resource_keys_sha256:
        raise ValueError("task delegation resource key digest is invalid")
    lease_bindings_sha256 = task_evidence.get("lease_bindings_sha256")
    task_record_sha256 = task_evidence.get("task_record_sha256")
    if not isinstance(lease_bindings_sha256, str) or _SHA256_RE.fullmatch(lease_bindings_sha256) is None:
        raise ValueError("task delegation lease binding digest is invalid")
    if not isinstance(task_record_sha256, str) or _SHA256_RE.fullmatch(task_record_sha256) is None:
        raise ValueError("task delegation task record digest is invalid")
    task_binding = {
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "state": task_evidence["state"],
        "attempt": task_evidence["attempt"],
        "updated_at_unix": task_evidence["updated_at_unix"],
        "resource_keys_sha256": resource_keys_sha256,
        "lease_bindings_sha256": lease_bindings_sha256,
    }
    if _sha256_json(task_binding) != task_record_sha256:
        raise ValueError("task delegation task record digest does not match evidence")
    current = int(time.time()) if now_unix is None else int(now_unix)
    minimum_expiry = task_evidence.get("minimum_expires_at_unix")
    if not isinstance(minimum_expiry, int) or isinstance(minimum_expiry, bool):
        raise ValueError("task delegation minimum lease expiry is invalid")
    expires_at = min(
        current + _SERVER_TASK_DELEGATION_TTL_SECONDS,
        int(actor["expires_at_unix"]),
        minimum_expiry,
    )
    if expires_at <= current:
        raise ValueError("task delegation has no live validity window")
    payload: dict[str, Any] = {
        "schema_version": _SERVER_TASK_DELEGATION_SCHEMA_VERSION,
        "kind": _SERVER_TASK_DELEGATION_KIND,
        "actor_owner_id": actor["owner_id"],
        "actor_identity_sha256": actor["identity_sha256"],
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "task_record_sha256": task_record_sha256,
        "resource_keys": resource_keys,
        "resource_keys_sha256": resource_keys_sha256,
        "lease_bindings_sha256": lease_bindings_sha256,
        "captain_request_sha256": captain_request_sha256_value,
        "issued_at_unix": current,
        "expires_at_unix": expires_at,
    }
    payload["proof_sha256"] = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return payload


def verify_server_task_lease_delegation(
    value: Any,
    *,
    actor_identity: dict[str, Any],
    captain_request_sha256_value: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    actor = verify_server_runtime_actor_identity(actor_identity, now_unix=now_unix)
    if not isinstance(value, dict) or set(value) != _SERVER_TASK_DELEGATION_KEYS:
        raise ValueError("server task lease delegation shape is invalid")
    if value.get("schema_version") != _SERVER_TASK_DELEGATION_SCHEMA_VERSION:
        raise ValueError("server task lease delegation schema is invalid")
    if value.get("kind") != _SERVER_TASK_DELEGATION_KIND:
        raise ValueError("server task lease delegation kind is invalid")
    task_id = value.get("task_id")
    lease_owner_id = value.get("lease_owner_id")
    if not isinstance(task_id, str) or re.fullmatch(r"[0-9a-f]{24}", task_id) is None:
        raise ValueError("server task lease delegation task_id is invalid")
    if lease_owner_id != f"task:{task_id}":
        raise ValueError("server task lease delegation owner is invalid")
    if value.get("actor_owner_id") != actor["owner_id"]:
        raise ValueError("server task lease delegation actor owner mismatch")
    if value.get("actor_identity_sha256") != actor["identity_sha256"]:
        raise ValueError("server task lease delegation actor identity mismatch")
    if value.get("captain_request_sha256") != captain_request_sha256_value:
        raise ValueError("server task lease delegation captain request mismatch")
    resource_keys = value.get("resource_keys")
    if (
        not isinstance(resource_keys, list)
        or not resource_keys
        or len(resource_keys) > 64
        or any(not isinstance(key, str) or not key for key in resource_keys)
        or resource_keys != sorted(set(resource_keys))
    ):
        raise ValueError("server task lease delegation resource keys are invalid")
    if value.get("resource_keys_sha256") != _sha256_json(resource_keys):
        raise ValueError("server task lease delegation resource key digest is invalid")
    for field in ("task_record_sha256", "lease_bindings_sha256"):
        field_value = value.get(field)
        if not isinstance(field_value, str) or _SHA256_RE.fullmatch(field_value) is None:
            raise ValueError(f"server task lease delegation {field} is invalid")
    issued_at = value.get("issued_at_unix")
    expires_at = value.get("expires_at_unix")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise ValueError("server task lease delegation issue time is invalid")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ValueError("server task lease delegation expiry is invalid")
    if expires_at <= issued_at or expires_at - issued_at > _SERVER_TASK_DELEGATION_TTL_SECONDS:
        raise ValueError("server task lease delegation lifetime is invalid")
    current = int(time.time()) if now_unix is None else int(now_unix)
    if issued_at > current + 5 or expires_at < current:
        raise ValueError("server task lease delegation is not current")
    unsigned = {key: value[key] for key in value if key != "proof_sha256"}
    expected_proof = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    proof = value.get("proof_sha256")
    if not isinstance(proof, str) or not hmac.compare_digest(proof, expected_proof):
        raise ValueError("server task lease delegation proof is invalid")
    return {
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "task_record_sha256": value["task_record_sha256"],
        "resource_keys": resource_keys,
        "resource_keys_sha256": value["resource_keys_sha256"],
        "lease_bindings_sha256": value["lease_bindings_sha256"],
        "captain_request_sha256": captain_request_sha256_value,
        "delegation_sha256": _sha256_json(value),
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
    }



def issue_server_operator_lease_delegation(
    actor_identity: dict[str, Any],
    lease_evidence: dict[str, Any],
    *,
    captain_request_sha256_value: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    actor = verify_server_runtime_actor_identity(actor_identity, now_unix=now_unix)
    if _SHA256_RE.fullmatch(captain_request_sha256_value) is None:
        raise ValueError("captain request digest is invalid")
    expected_evidence_keys = {
        "schema_version",
        "kind",
        "lease_owner_id",
        "resource_keys",
        "resource_keys_sha256",
        "lease_snapshots",
        "lease_bindings_sha256",
        "minimum_expires_at_unix",
        "observed_at_unix",
    }
    if not isinstance(lease_evidence, dict) or set(lease_evidence) != expected_evidence_keys:
        raise ValueError("Operator delegation evidence shape is invalid")
    if lease_evidence.get("schema_version") != 1:
        raise ValueError("Operator delegation evidence schema is invalid")
    if lease_evidence.get("kind") != "grabowski_live_operator_lease_delegation_evidence":
        raise ValueError("Operator delegation evidence kind is invalid")
    lease_owner_id = lease_evidence.get("lease_owner_id")
    if not isinstance(lease_owner_id, str) or _DIRECT_OPERATOR_OWNER_RE.fullmatch(lease_owner_id) is None:
        raise ValueError("Operator delegation lease owner is invalid")
    resource_keys = lease_evidence.get("resource_keys")
    if (
        not isinstance(resource_keys, list)
        or not resource_keys
        or len(resource_keys) > 64
        or any(not isinstance(key, str) or not key for key in resource_keys)
        or resource_keys != sorted(set(resource_keys))
    ):
        raise ValueError("Operator delegation resource keys are invalid")
    resource_keys_sha256 = _sha256_json(resource_keys)
    if lease_evidence.get("resource_keys_sha256") != resource_keys_sha256:
        raise ValueError("Operator delegation resource key digest is invalid")
    raw_snapshots = lease_evidence.get("lease_snapshots")
    if (
        not isinstance(raw_snapshots, list)
        or len(raw_snapshots) != len(resource_keys)
        or any(not isinstance(item, dict) or set(item) != _LEASE_SNAPSHOT_KEYS for item in raw_snapshots)
    ):
        raise ValueError("Operator delegation lease snapshots are invalid")
    lease_snapshots = [dict(item) for item in raw_snapshots]
    if [item["resource_key"] for item in lease_snapshots] != resource_keys:
        raise ValueError("Operator delegation lease snapshot keys are invalid")
    if any(item["owner_id"] != lease_owner_id for item in lease_snapshots):
        raise ValueError("Operator delegation lease snapshot owner mismatch")
    for snapshot in lease_snapshots:
        if not isinstance(snapshot["metadata_sha256"], str) or _SHA256_RE.fullmatch(snapshot["metadata_sha256"]) is None:
            raise ValueError("Operator delegation metadata digest is invalid")
        for field in ("acquired_at_unix", "updated_at_unix", "expires_at_unix"):
            value = snapshot[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"Operator delegation {field} is invalid")
    lease_bindings_sha256 = _sha256_json(lease_snapshots)
    if lease_evidence.get("lease_bindings_sha256") != lease_bindings_sha256:
        raise ValueError("Operator delegation lease binding digest is invalid")
    current = int(time.time()) if now_unix is None else int(now_unix)
    minimum_expiry = lease_evidence.get("minimum_expires_at_unix")
    observed_at = lease_evidence.get("observed_at_unix")
    if not isinstance(minimum_expiry, int) or isinstance(minimum_expiry, bool):
        raise ValueError("Operator delegation minimum lease expiry is invalid")
    if not isinstance(observed_at, int) or isinstance(observed_at, bool) or observed_at < 0:
        raise ValueError("Operator delegation observation time is invalid")
    expires_at = min(
        current + _SERVER_OPERATOR_DELEGATION_TTL_SECONDS,
        int(actor["expires_at_unix"]),
        minimum_expiry,
    )
    if expires_at <= current:
        raise ValueError("Operator delegation has no live validity window")
    payload: dict[str, Any] = {
        "schema_version": _SERVER_OPERATOR_DELEGATION_SCHEMA_VERSION,
        "kind": _SERVER_OPERATOR_DELEGATION_KIND,
        "actor_owner_id": actor["owner_id"],
        "actor_identity_sha256": actor["identity_sha256"],
        "lease_owner_id": lease_owner_id,
        "resource_keys": resource_keys,
        "resource_keys_sha256": resource_keys_sha256,
        "lease_snapshots": lease_snapshots,
        "lease_bindings_sha256": lease_bindings_sha256,
        "captain_request_sha256": captain_request_sha256_value,
        "issued_at_unix": current,
        "expires_at_unix": expires_at,
    }
    payload["proof_sha256"] = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return payload


def verify_server_operator_lease_delegation(
    value: Any,
    *,
    actor_identity: dict[str, Any],
    captain_request_sha256_value: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    actor = verify_server_runtime_actor_identity(actor_identity, now_unix=now_unix)
    if not isinstance(value, dict) or set(value) != _SERVER_OPERATOR_DELEGATION_KEYS:
        raise ValueError("server Operator lease delegation shape is invalid")
    if value.get("schema_version") != _SERVER_OPERATOR_DELEGATION_SCHEMA_VERSION:
        raise ValueError("server Operator lease delegation schema is invalid")
    if value.get("kind") != _SERVER_OPERATOR_DELEGATION_KIND:
        raise ValueError("server Operator lease delegation kind is invalid")
    lease_owner_id = value.get("lease_owner_id")
    if not isinstance(lease_owner_id, str) or _DIRECT_OPERATOR_OWNER_RE.fullmatch(lease_owner_id) is None:
        raise ValueError("server Operator lease delegation owner is invalid")
    if value.get("actor_owner_id") != actor["owner_id"]:
        raise ValueError("server Operator lease delegation actor owner mismatch")
    if value.get("actor_identity_sha256") != actor["identity_sha256"]:
        raise ValueError("server Operator lease delegation actor identity mismatch")
    if value.get("captain_request_sha256") != captain_request_sha256_value:
        raise ValueError("server Operator lease delegation captain request mismatch")
    resource_keys = value.get("resource_keys")
    if (
        not isinstance(resource_keys, list)
        or not resource_keys
        or len(resource_keys) > 64
        or any(not isinstance(key, str) or not key for key in resource_keys)
        or resource_keys != sorted(set(resource_keys))
        or value.get("resource_keys_sha256") != _sha256_json(resource_keys)
    ):
        raise ValueError("server Operator lease delegation resource keys are invalid")
    raw_snapshots = value.get("lease_snapshots")
    if (
        not isinstance(raw_snapshots, list)
        or len(raw_snapshots) != len(resource_keys)
        or any(not isinstance(item, dict) or set(item) != _LEASE_SNAPSHOT_KEYS for item in raw_snapshots)
    ):
        raise ValueError("server Operator lease delegation snapshots are invalid")
    lease_snapshots = [dict(item) for item in raw_snapshots]
    if [item["resource_key"] for item in lease_snapshots] != resource_keys:
        raise ValueError("server Operator lease delegation snapshot keys are invalid")
    if any(item["owner_id"] != lease_owner_id for item in lease_snapshots):
        raise ValueError("server Operator lease delegation snapshot owner mismatch")
    if value.get("lease_bindings_sha256") != _sha256_json(lease_snapshots):
        raise ValueError("server Operator lease delegation binding digest is invalid")
    issued_at = value.get("issued_at_unix")
    expires_at = value.get("expires_at_unix")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise ValueError("server Operator lease delegation issue time is invalid")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise ValueError("server Operator lease delegation expiry is invalid")
    if expires_at <= issued_at or expires_at - issued_at > _SERVER_OPERATOR_DELEGATION_TTL_SECONDS:
        raise ValueError("server Operator lease delegation lifetime is invalid")
    current = int(time.time()) if now_unix is None else int(now_unix)
    if issued_at > current + 5 or expires_at < current:
        raise ValueError("server Operator lease delegation is not current")
    unsigned = {key: value[key] for key in value if key != "proof_sha256"}
    expected_proof = hmac.new(
        _SERVER_ACTOR_SECRET,
        _canonical_json(unsigned).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    proof = value.get("proof_sha256")
    if not isinstance(proof, str) or not hmac.compare_digest(proof, expected_proof):
        raise ValueError("server Operator lease delegation proof is invalid")
    return {
        "lease_owner_id": lease_owner_id,
        "resource_keys": resource_keys,
        "resource_keys_sha256": value["resource_keys_sha256"],
        "lease_snapshots": lease_snapshots,
        "lease_bindings_sha256": value["lease_bindings_sha256"],
        "captain_request_sha256": captain_request_sha256_value,
        "delegation_sha256": _sha256_json(value),
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
    }

def _merge_guard_identifier(namespace: str, value: str) -> str:
    if not isinstance(namespace, str) or not namespace:
        raise ValueError("merge guard identifier namespace is required")
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("merge guard identifier value is invalid")
    digest = hashlib.sha256(
        namespace.encode("utf-8") + b"\x00" + value.encode("utf-8")
    ).hexdigest()
    return f"{namespace}-{digest}"


def merge_guard_repository_root(repo_path: Path) -> Path:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
        env={
            "HOME": str(Path.home()),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if completed.returncode != 0:
        raise RuntimeError("merge guard cannot resolve Git common directory")
    common_dir = Path(completed.stdout.strip()).resolve()
    if common_dir.name != ".git" or not common_dir.is_dir():
        raise RuntimeError("merge guard Git common directory is not a canonical .git directory")
    repository = common_dir.parent.resolve()
    if not repository.is_dir():
        raise RuntimeError("merge guard canonical repository root is unavailable")
    return repository


def merge_guard_resource_keys(
    repo_path: Path,
    *,
    repo_slug: str,
    pr_number: int,
    base: str,
    head: str,
) -> list[str]:
    repository_id = _merge_guard_identifier("repository", repo_slug.lower())
    base_branch_id = _merge_guard_identifier("branch", base)
    head_branch_id = _merge_guard_identifier("branch", head)
    return sorted(
        {
            f"component:github-repository:{repository_id}",
            f"component:github-branch:{repository_id}:{base_branch_id}",
            f"component:github-branch:{repository_id}:{head_branch_id}",
            f"service:github-main:{repository_id}",
            f"service:github-pr:{repository_id}:{pr_number}",
            f"gate:github-merge:{repository_id}:{base_branch_id}",
            f"deployment:github:{repository_id}:{base_branch_id}",
        }
    )


def _merge_guard_result_info(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": "runner returned non-object",
            "stdout_bytes": None,
            "stderr_bytes": None,
        }
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    if isinstance(stdout, bytes):
        stdout_text = stdout.decode("utf-8", errors="replace")
        stdout_bytes: bytes | None = stdout
    else:
        stdout_text = str(stdout)
        raw_stdout = result.get("stdout_bytes")
        stdout_bytes = raw_stdout if isinstance(raw_stdout, bytes) else None
    if isinstance(stderr, bytes):
        stderr_text = stderr.decode("utf-8", errors="replace")
        stderr_bytes: bytes | None = stderr
    else:
        stderr_text = str(stderr)
        raw_stderr = result.get("stderr_bytes")
        stderr_bytes = raw_stderr if isinstance(raw_stderr, bytes) else None
    return {
        "returncode": int(result.get("returncode", 1)),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
    }


_BASE_UPDATE_GUARD_MAX_ACTIVE_RULES = 100
_BASE_UPDATE_GUARD_MAX_RULESETS = 16


def _github_json_call(
    repo_path: Path,
    github_runner: Any,
    args: list[str],
    *,
    label: str,
) -> tuple[Any | None, dict[str, Any], list[str]]:
    try:
        raw = github_runner(repo_path, args)
    except Exception as exc:
        return None, {
            "label": label,
            "command": ["gh", *args],
            "exception_type": type(exc).__name__,
        }, [f"{label}_exception:{type(exc).__name__}"]
    info = _merge_guard_result_info(raw)
    evidence = {
        "label": label,
        "command": ["gh", *args],
        "returncode": info["returncode"],
        "stdout_sha256": hashlib.sha256(info["stdout"].encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(info["stderr"].encode("utf-8")).hexdigest(),
    }
    if info["returncode"] != 0:
        return None, evidence, [f"{label}_query_failed"]
    try:
        value = json.loads(info["stdout"])
    except json.JSONDecodeError:
        return None, evidence, [f"{label}_invalid_json"]
    evidence["value_sha256"] = _sha256_json(value)
    return value, evidence, []


def _ruleset_detail_endpoint(active_rule: dict[str, Any]) -> str | None:
    ruleset_id = active_rule.get("ruleset_id")
    source_type = active_rule.get("ruleset_source_type")
    source = active_rule.get("ruleset_source")
    if type(ruleset_id) is not int or ruleset_id <= 0 or not isinstance(source, str):
        return None
    if source_type == "Repository" and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source):
        return f"repos/{source}/rulesets/{ruleset_id}"
    if source_type == "Organization" and re.fullmatch(r"[A-Za-z0-9_.-]+", source):
        return f"orgs/{source}/rulesets/{ruleset_id}"
    if source_type == "Enterprise" and re.fullmatch(r"[A-Za-z0-9_.-]+", source):
        return f"enterprises/{source}/rulesets/{ruleset_id}"
    return None


def _strict_status_rule(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("type") != "required_status_checks":
        return None
    parameters = value.get("parameters")
    if not isinstance(parameters, dict):
        return None
    checks = parameters.get("required_status_checks")
    if parameters.get("strict_required_status_checks_policy") is not True:
        return None
    if not isinstance(checks, list) or not checks:
        return None
    normalized_checks: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            return None
        context = check.get("context")
        integration_id = check.get("integration_id")
        if not isinstance(context, str) or not context.strip():
            return None
        if integration_id is not None and type(integration_id) is not int:
            return None
        normalized_checks.append(
            {"context": context.strip(), "integration_id": integration_id}
        )
    return {
        "strict_required_status_checks_policy": True,
        "required_status_checks": sorted(
            normalized_checks,
            key=lambda item: (item["context"], item["integration_id"] or -1),
        ),
    }


def verify_github_base_update_guard(
    repo_path: Path,
    github_runner: Any,
    *,
    repo_slug: str,
    base_branch: str,
) -> tuple[dict[str, Any] | None, dict[str, Any], list[str]]:
    """Prove a server-enforced, non-bypassable strict base-update barrier."""
    encoded_branch = quote(base_branch, safe="")
    active_args = ["api", f"repos/{repo_slug}/rules/branches/{encoded_branch}"]
    active, active_evidence, errors = _github_json_call(
        repo_path, github_runner, active_args, label="base_update_guard_active_rules"
    )
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_github_base_update_guard_evidence",
        "repository": repo_slug,
        "base_branch": base_branch,
        "active_rules": active_evidence,
        "rulesets": [],
    }
    if errors:
        evidence["errors"] = list(errors)
        return None, evidence, errors
    if not isinstance(active, list):
        errors.append("base_update_guard_active_rules_not_list")
    elif len(active) > _BASE_UPDATE_GUARD_MAX_ACTIVE_RULES:
        errors.append("base_update_guard_active_rules_exceed_limit")
    if errors:
        evidence["errors"] = list(errors)
        return None, evidence, errors

    candidates: dict[int, dict[str, Any]] = {}
    for rule in active:
        if not isinstance(rule, dict):
            errors.append("base_update_guard_active_rule_invalid")
            continue
        strict = _strict_status_rule(rule)
        endpoint = _ruleset_detail_endpoint(rule)
        ruleset_id = rule.get("ruleset_id")
        if strict is None or endpoint is None or type(ruleset_id) is not int:
            continue
        candidates[ruleset_id] = {
            "active_rule": rule,
            "active_strict_rule": strict,
            "endpoint": endpoint,
        }
    if len(candidates) > _BASE_UPDATE_GUARD_MAX_RULESETS:
        errors.append("base_update_guard_candidate_rulesets_exceed_limit")
    if not candidates:
        errors.append("base_update_guard_strict_ruleset_missing")
    if errors:
        evidence["errors"] = list(errors)
        return None, evidence, errors

    accepted: list[dict[str, Any]] = []
    rejection_codes: list[str] = []
    for ruleset_id in sorted(candidates):
        candidate = candidates[ruleset_id]
        detail_args = ["api", candidate["endpoint"]]
        detail, detail_evidence, detail_errors = _github_json_call(
            repo_path,
            github_runner,
            detail_args,
            label=f"base_update_guard_ruleset_{ruleset_id}",
        )
        record: dict[str, Any] = {
            "ruleset_id": ruleset_id,
            "active_rule_sha256": _sha256_json(candidate["active_rule"]),
            "query": detail_evidence,
            "accepted": False,
            "errors": list(detail_errors),
        }
        if detail_errors:
            rejection_codes.extend(detail_errors)
            evidence["rulesets"].append(record)
            continue
        detail_codes: list[str] = []
        if not isinstance(detail, dict) or detail.get("id") != ruleset_id:
            detail_codes.append("base_update_guard_ruleset_detail_invalid")
        else:
            if detail.get("enforcement") != "active":
                detail_codes.append("base_update_guard_ruleset_not_active")
            if detail.get("current_user_can_bypass") != "never":
                detail_codes.append("base_update_guard_current_actor_can_bypass")
            bypass_actors = detail.get("bypass_actors")
            if not isinstance(bypass_actors, list) or bypass_actors:
                detail_codes.append("base_update_guard_bypass_actors_present")
            detail_rules = detail.get("rules")
            strict_rules = (
                [item for item in detail_rules if _strict_status_rule(item) is not None]
                if isinstance(detail_rules, list)
                else []
            )
            if not strict_rules:
                detail_codes.append("base_update_guard_ruleset_strict_rule_missing")
        record["errors"] = detail_codes
        record["accepted"] = not detail_codes
        if isinstance(detail, dict):
            record["detail_sha256"] = _sha256_json(detail)
        evidence["rulesets"].append(record)
        if detail_codes:
            rejection_codes.extend(detail_codes)
            continue
        assert isinstance(detail, dict)
        accepted.append(
            {
                "ruleset_id": ruleset_id,
                "source_type": candidate["active_rule"].get("ruleset_source_type"),
                "source": candidate["active_rule"].get("ruleset_source"),
                "current_user_can_bypass": detail["current_user_can_bypass"],
                "strict_status_rule": candidate["active_strict_rule"],
                "detail_sha256": _sha256_json(detail),
            }
        )
    if not accepted:
        errors.append("base_update_guard_no_unbypassable_strict_ruleset")
        errors.extend(sorted(set(rejection_codes)))
        evidence["errors"] = list(errors)
        return None, evidence, errors

    policy: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_github_base_update_guard",
        "repository": repo_slug,
        "base_branch": base_branch,
        "mode": "strict_required_status_checks_ruleset",
        "accepted_rulesets": accepted,
        "active_rules_sha256": _sha256_json(active),
        "does_not_establish": [
            "absence_of_external_ruleset_changes_after_observation",
            "absence_of_noncooperating_external_github_actors",
            "semantic_correctness_of_required_status_checks",
            "exact_base_ref_compare_and_swap",
        ],
    }
    policy["binding_sha256"] = _sha256_json(policy)
    evidence["policy_sha256"] = _sha256_json(policy)
    evidence["errors"] = []
    return policy, evidence, []


def _github_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _github_actor(value: Any) -> str:
    if isinstance(value, dict):
        login = value.get("login")
        if isinstance(login, str):
            return login.strip().lower()
    if isinstance(value, str):
        return value.strip().lower()
    return ""


class CaptainMergeGuardRunner:
    def __init__(
        self,
        *,
        repo_path: Path,
        action: dict[str, Any],
        parameters: dict[str, Any],
        github_runner: Any,
        execution_intent_sha256: str,
        lease_owner_id: str,
        server_actor_identity: dict[str, Any] | None = None,
        server_task_lease_delegation: dict[str, Any] | None = None,
        server_operator_lease_delegation: dict[str, Any] | None = None,
    ) -> None:
        self.repo_path = repo_path.resolve()
        self.action = action
        self.parameters = parameters
        self.github_runner = github_runner
        self.execution_intent_sha256 = execution_intent_sha256
        self.requested_lease_owner_id = lease_owner_id
        self.lease_owner_id = lease_owner_id
        self.lease_owner_source = "execution-intent-context"
        self.server_actor_identity: dict[str, Any] | None = None
        self.server_actor_identity_error = False
        self.server_task_lease_delegation: dict[str, Any] | None = None
        self.server_task_lease_delegation_error = False
        self.server_operator_lease_delegation: dict[str, Any] | None = None
        self.server_operator_lease_delegation_error = False
        if server_actor_identity is not None:
            try:
                verified_actor = verify_server_runtime_actor_identity(server_actor_identity)
            except ValueError:
                self.lease_owner_id = ""
                self.server_actor_identity_error = True
            else:
                self.server_actor_identity = verified_actor
                self.lease_owner_id = str(verified_actor["owner_id"])
                self.lease_owner_source = "server-runtime-session-v1"
                if server_task_lease_delegation is not None:
                    try:
                        verified_delegation = verify_server_task_lease_delegation(
                            server_task_lease_delegation,
                            actor_identity=server_actor_identity,
                            captain_request_sha256_value=captain_request_sha256(parameters),
                        )
                    except ValueError:
                        self.lease_owner_id = ""
                        self.server_task_lease_delegation_error = True
                    else:
                        if verified_delegation["lease_owner_id"] != lease_owner_id:
                            self.lease_owner_id = ""
                            self.server_task_lease_delegation_error = True
                        else:
                            self.server_task_lease_delegation = verified_delegation
                            self.lease_owner_id = str(verified_delegation["lease_owner_id"])
                            self.lease_owner_source = "server-runtime-task-delegation-v1"
                if server_operator_lease_delegation is not None:
                    if server_task_lease_delegation is not None:
                        self.lease_owner_id = ""
                        self.server_operator_lease_delegation_error = True
                    else:
                        try:
                            verified_operator_delegation = (
                                verify_server_operator_lease_delegation(
                                    server_operator_lease_delegation,
                                    actor_identity=server_actor_identity,
                                    captain_request_sha256_value=captain_request_sha256(
                                        parameters
                                    ),
                                )
                            )
                        except ValueError:
                            self.lease_owner_id = ""
                            self.server_operator_lease_delegation_error = True
                        else:
                            if (
                                verified_operator_delegation["lease_owner_id"]
                                != lease_owner_id
                            ):
                                self.lease_owner_id = ""
                                self.server_operator_lease_delegation_error = True
                            else:
                                self.server_operator_lease_delegation = (
                                    verified_operator_delegation
                                )
                                self.lease_owner_id = str(
                                    verified_operator_delegation["lease_owner_id"]
                                )
                                self.lease_owner_source = (
                                    "server-runtime-operator-delegation-v1"
                                )
        self.owner_id: str | None = None
        self.resource_keys: list[str] = []
        self.held_resource_keys: list[str] = []
        self.acquisition: dict[str, Any] | None = None
        self.dispatch_called = False
        self.repository_policy_args: list[str] | None = None
        self.repository_policy_snapshot: dict[str, bool] | None = None
        does_not_establish = [
            "merge_authority",
            "review_completeness",
            "ci_freshness",
            "authorization",
            "absence_of_noncooperating_external_github_actors",
        ]
        if self.server_actor_identity is None:
            does_not_establish.append("server_authenticated_lease_owner_identity")
        if self.server_task_lease_delegation is not None:
            does_not_establish.append("task_creator_identity")
        if self.server_operator_lease_delegation is not None:
            does_not_establish.append("identity_of_original_lease_creator")
        self.receipt: dict[str, Any] = {
            "schema_version": 1,
            "kind": "grabowski_captain_merge_lease_guard",
            "status": "not_reached",
            "contract_satisfied": False,
            "dispatch_called": False,
            "resource_keys": [],
            "lease_owner_binding": {
                "source": self.lease_owner_source,
                "server_authenticated": self.server_actor_identity is not None,
                "identity_sha256": (
                    self.server_actor_identity.get("identity_sha256")
                    if self.server_actor_identity is not None
                    else None
                ),
                "task_id": (
                    self.server_task_lease_delegation.get("task_id")
                    if self.server_task_lease_delegation is not None
                    else None
                ),
                "delegation_sha256": (
                    (
                        self.server_task_lease_delegation
                        or self.server_operator_lease_delegation
                        or {}
                    ).get("delegation_sha256")
                ),
                "delegation_expires_at_unix": (
                    (
                        self.server_task_lease_delegation
                        or self.server_operator_lease_delegation
                        or {}
                    ).get("expires_at_unix")
                ),
                "delegation_kind": (
                    "task"
                    if self.server_task_lease_delegation is not None
                    else (
                        "direct_operator"
                        if self.server_operator_lease_delegation is not None
                        else None
                    )
                ),
                "delegated_resource_keys_sha256": (
                    (
                        self.server_task_lease_delegation
                        or self.server_operator_lease_delegation
                        or {}
                    ).get("resource_keys_sha256")
                ),
            },
            "does_not_establish": does_not_establish,
        }
        self.static_errors = self._static_binding_errors()
        if self.static_errors:
            self.receipt["status"] = "blocked_before_guard"
            self.receipt["errors"] = list(self.static_errors)

    def _is_repository_policy_query(self, args: list[str]) -> bool:
        target_repo = str(self.action["target"].get("repo", ""))
        return (
            len(args) == 4
            and args[0] == "api"
            and args[1] == f"repos/{target_repo}"
            and args[2] == "--jq"
            and isinstance(args[3], str)
            and args[3].startswith("{")
            and args[3].endswith("}")
        )

    def _repository_policy_snapshot_info(
        self,
        result: Any,
        *,
        command: list[str],
    ) -> tuple[dict[str, bool] | None, dict[str, Any], list[str]]:
        info = _merge_guard_result_info(result)
        evidence = {
            "command": ["gh", *command],
            "returncode": info["returncode"],
            "stdout_sha256": hashlib.sha256(info["stdout"].encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(info["stderr"].encode("utf-8")).hexdigest(),
        }
        errors: list[str] = []
        if info["returncode"] != 0:
            errors.append("merge_guard_repository_policy_query_failed")
            return None, evidence, errors
        try:
            raw = json.loads(info["stdout"])
        except json.JSONDecodeError:
            errors.append("merge_guard_repository_policy_invalid_json")
            return None, evidence, errors
        if (
            not isinstance(raw, dict)
            or not raw
            or any(not isinstance(key, str) or not isinstance(value, bool) for key, value in raw.items())
        ):
            errors.append("merge_guard_repository_policy_invalid_shape")
            return None, evidence, errors
        snapshot = {key: raw[key] for key in sorted(raw)}
        evidence["settings"] = snapshot
        evidence["settings_sha256"] = _sha256_json(snapshot)
        return snapshot, evidence, errors

    def _capture_repository_policy_snapshot(
        self,
        args: list[str],
        result: Any,
    ) -> None:
        snapshot, evidence, errors = self._repository_policy_snapshot_info(
            result,
            command=args,
        )
        evidence["errors"] = list(errors)
        self.receipt["repository_policy_snapshot"] = evidence
        self.repository_policy_args = list(args)
        self.repository_policy_snapshot = snapshot

    def _revalidate_repository_policy(self) -> list[str]:
        if self.repository_policy_args is None or self.repository_policy_snapshot is None:
            errors = ["merge_guard_repository_policy_snapshot_missing"]
            self.receipt["repository_policy_revalidation"] = {"errors": errors}
            return errors
        try:
            raw = self.github_runner(self.repo_path, list(self.repository_policy_args))
        except Exception as exc:
            errors = [f"merge_guard_repository_policy_revalidation_exception:{type(exc).__name__}"]
            self.receipt["repository_policy_revalidation"] = {
                "command": ["gh", *self.repository_policy_args],
                "errors": errors,
            }
            return errors
        snapshot, evidence, errors = self._repository_policy_snapshot_info(
            raw,
            command=self.repository_policy_args,
        )
        evidence["initial_settings_sha256"] = _sha256_json(self.repository_policy_snapshot)
        if not errors and snapshot != self.repository_policy_snapshot:
            errors.append("merge_guard_repository_policy_drift")
        evidence["matched"] = not errors
        evidence["errors"] = list(errors)
        self.receipt["repository_policy_revalidation"] = evidence
        return errors

    def _codex_api_json(
        self,
        args: list[str],
        *,
        label: str,
        observations: list[dict[str, Any]],
        errors: list[str],
    ) -> Any | None:
        try:
            raw = self.github_runner(self.repo_path, args)
        except Exception as exc:
            errors.append(
                f"merge_guard_codex_{label}_exception:{type(exc).__name__}"
            )
            observations.append(
                {
                    "label": label,
                    "command": ["gh", *args],
                    "exception_type": type(exc).__name__,
                }
            )
            return None
        info = _merge_guard_result_info(raw)
        observation = {
            "label": label,
            "command": ["gh", *args],
            "returncode": info["returncode"],
            "stdout_sha256": hashlib.sha256(
                info["stdout"].encode("utf-8")
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(
                info["stderr"].encode("utf-8")
            ).hexdigest(),
        }
        observations.append(observation)
        if info["returncode"] != 0:
            errors.append(f"merge_guard_codex_{label}_query_failed")
            return None
        try:
            return json.loads(info["stdout"])
        except json.JSONDecodeError:
            errors.append(f"merge_guard_codex_{label}_invalid_json")
            return None

    def _codex_single_page(
        self,
        args: list[str],
        *,
        label: str,
        observations: list[dict[str, Any]],
        errors: list[str],
    ) -> list[dict[str, Any]] | None:
        pages = self._codex_api_json(
            args,
            label=label,
            observations=observations,
            errors=errors,
        )
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            errors.append(f"merge_guard_codex_{label}_pages_invalid")
            return None
        if len(pages) != 1:
            errors.append(f"merge_guard_codex_{label}_truncated")
            return None
        if any(not isinstance(item, dict) for item in pages[0]):
            errors.append(f"merge_guard_codex_{label}_item_invalid")
            return None
        return [dict(item) for item in pages[0]]

    def _revalidate_codex_review(
        self,
        bindings: dict[str, Any],
        *,
        phase: str,
    ) -> list[str]:
        errors: list[str] = []
        observations: list[dict[str, Any]] = []
        review_evidence = self.parameters.get("review_evidence")
        review_tier = (
            review_evidence.get("review_tier")
            if isinstance(review_evidence, dict)
            else None
        )
        required = (
            review_tier == "high_critical"
            or self.parameters.get("codex_review_required") is True
        )
        evidence = self.parameters.get("codex_review_evidence")
        exception = self.parameters.get("codex_review_exception")
        receipt_key = f"{phase}_codex_review_revalidation"
        receipt: dict[str, Any] = {
            "required": required,
            "review_tier": review_tier,
            "evidence_sha256": (
                _sha256_json(evidence) if isinstance(evidence, dict) else None
            ),
            "exception_sha256": (
                _sha256_json(exception) if isinstance(exception, dict) else None
            ),
            "observations": observations,
            "errors": errors,
        }
        self.receipt[receipt_key] = receipt
        if evidence is not None and exception is not None:
            errors.append("merge_guard_codex_evidence_exception_ambiguous")
            receipt["status"] = "blocked"
            return errors
        if exception is not None:
            if not isinstance(exception, dict):
                errors.append("merge_guard_codex_exception_malformed")
            else:
                expires_at = _github_datetime(exception.get("expires_at"))
                if expires_at is None:
                    errors.append("merge_guard_codex_exception_expiry_invalid")
                elif expires_at <= datetime.now(timezone.utc):
                    errors.append("merge_guard_codex_exception_expired")
                if exception.get("head_sha") != bindings.get("head_sha"):
                    errors.append("merge_guard_codex_exception_head_drift")
                if exception.get("diff_sha256") != bindings.get("diff_sha256"):
                    errors.append("merge_guard_codex_exception_diff_drift")
                if str(exception.get("repo", "")).lower() != str(
                    bindings.get("repository", "")
                ).lower():
                    errors.append("merge_guard_codex_exception_repo_drift")
                if exception.get("pr") != bindings.get("pull_request"):
                    errors.append("merge_guard_codex_exception_pr_drift")
            receipt["status"] = "blocked" if errors else "exception_current"
            return errors
        if evidence is None:
            if required:
                errors.append("merge_guard_codex_evidence_missing")
                receipt["status"] = "blocked"
            else:
                receipt["status"] = "not_required"
            return errors
        if not isinstance(evidence, dict):
            errors.append("merge_guard_codex_evidence_malformed")
            receipt["status"] = "blocked"
            return errors

        repository = str(bindings.get("repository", "")).lower()
        pr_number = int(bindings.get("pull_request", 0))
        head_sha = str(bindings.get("head_sha", ""))
        diff_sha256 = str(bindings.get("diff_sha256", ""))
        base_sha = str(bindings.get("base_sha", ""))
        if str(evidence.get("repo", "")).lower() != repository:
            errors.append("merge_guard_codex_evidence_repo_drift")
        if evidence.get("pr") != pr_number:
            errors.append("merge_guard_codex_evidence_pr_drift")
        if evidence.get("head_sha") != head_sha:
            errors.append("merge_guard_codex_evidence_head_drift")
        if evidence.get("diff_sha256") != diff_sha256:
            errors.append("merge_guard_codex_evidence_diff_drift")
        if evidence.get("base_sha") != base_sha:
            errors.append("merge_guard_codex_evidence_base_drift")
        request_core = {
            "schema_version": 1,
            "kind": "grabowski_codex_review_request",
            "repo": repository,
            "pr": pr_number,
            "head_sha": head_sha,
            "diff_sha256": diff_sha256,
        }
        expected_marker = {
            **request_core,
            "request_id": _sha256_json(request_core)[:32],
        }
        request = evidence.get("request")
        completion = evidence.get("completion")
        if not isinstance(request, dict) or not isinstance(completion, dict):
            errors.append("merge_guard_codex_evidence_shape_invalid")
            receipt["status"] = "blocked"
            return errors
        request_comment_id = request.get("comment_id")
        if (
            isinstance(request_comment_id, bool)
            or not isinstance(request_comment_id, int)
            or request_comment_id <= 0
        ):
            errors.append("merge_guard_codex_request_comment_id_invalid")
            receipt["status"] = "blocked"
            return errors

        request_payload = self._codex_api_json(
            [
                "api",
                f"repos/{repository}/issues/comments/{request_comment_id}",
            ],
            label="request_comment",
            observations=observations,
            errors=errors,
        )
        request_time: datetime | None = None
        if isinstance(request_payload, dict):
            request_body = request_payload.get("body")
            live_request_actor = _github_actor(request_payload.get("user"))
            live_association = request_payload.get("author_association")
            request_time = _github_datetime(request_payload.get("created_at"))
            if not isinstance(request_body, str):
                errors.append("merge_guard_codex_request_body_missing")
            else:
                if hashlib.sha256(request_body.encode("utf-8")).hexdigest() != request.get(
                    "body_sha256"
                ):
                    errors.append("merge_guard_codex_request_body_drift")
                marker = _CODEX_REQUEST_RE.search(request_body)
                marker_payload: Any = None
                if marker is not None:
                    try:
                        marker_payload = json.loads(marker.group(1))
                    except json.JSONDecodeError:
                        marker_payload = None
                if marker_payload != expected_marker:
                    errors.append("merge_guard_codex_request_marker_drift")
                if request.get("request_id") != expected_marker["request_id"]:
                    errors.append("merge_guard_codex_request_id_drift")
            if live_request_actor != str(request.get("actor", "")).lower():
                errors.append("merge_guard_codex_request_actor_drift")
            if (
                live_association not in _CODEX_REQUEST_ASSOCIATIONS
                and live_request_actor != "github-actions[bot]"
            ):
                errors.append("merge_guard_codex_request_actor_untrusted")
            expected_request_time = _github_datetime(request.get("created_at"))
            if (
                request_time is None
                or expected_request_time is None
                or request_time != expected_request_time
            ):
                errors.append("merge_guard_codex_request_time_drift")
        else:
            errors.append("merge_guard_codex_request_comment_missing")

        request_comments = self._codex_single_page(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/issues/{pr_number}/comments?per_page=100",
            ],
            label="request_comments",
            observations=observations,
            errors=errors,
        )
        canonical_requests: list[dict[str, Any]] = []
        if request_comments is not None:
            for item in request_comments:
                body = item.get("body")
                actor = _github_actor(item.get("user"))
                association = item.get("author_association")
                created = _github_datetime(item.get("created_at"))
                comment_id = item.get("id")
                if (
                    not isinstance(body, str)
                    or created is None
                    or isinstance(comment_id, bool)
                    or not isinstance(comment_id, int)
                    or (
                        association not in _CODEX_REQUEST_ASSOCIATIONS
                        and actor != "github-actions[bot]"
                    )
                ):
                    continue
                marker = _CODEX_REQUEST_RE.search(body)
                marker_payload: Any = None
                if marker is not None:
                    try:
                        marker_payload = json.loads(marker.group(1))
                    except json.JSONDecodeError:
                        marker_payload = None
                if marker_payload == expected_marker:
                    canonical_requests.append(
                        {
                            "id": comment_id,
                            "created": created,
                            "actor": actor,
                        }
                    )
        canonical_requests.sort(key=lambda item: (item["created"], item["id"]))
        if not canonical_requests:
            errors.append("merge_guard_codex_canonical_request_missing")
        else:
            earliest_request = canonical_requests[0]
            if earliest_request["id"] != request_comment_id:
                errors.append("merge_guard_codex_request_not_earliest_canonical")
            if request_time is None or earliest_request["created"] != request_time:
                errors.append("merge_guard_codex_canonical_request_time_drift")
        receipt["canonical_request_count"] = len(canonical_requests)
        receipt["canonical_request_ids_sha256"] = _sha256_json(
            [item["id"] for item in canonical_requests]
        )


        review_items = self._codex_single_page(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/pulls/{pr_number}/reviews?per_page=100",
            ],
            label="reviews",
            observations=observations,
            errors=errors,
        )
        live_reviews: list[dict[str, Any]] = []
        if review_items is not None:
            for item in review_items:
                actor = _github_actor(item.get("user"))
                state = str(item.get("state") or "").upper()
                submitted = _github_datetime(item.get("submitted_at"))
                review_id = item.get("id")
                if (
                    actor not in _CODEX_REVIEW_ACTORS
                    or item.get("commit_id") != head_sha
                    or isinstance(review_id, bool)
                    or not isinstance(review_id, int)
                ):
                    continue
                if state == "PENDING":
                    live_reviews.append(
                        {
                            "id": review_id,
                            "state": state,
                            "submitted": None,
                        }
                    )
                    continue
                if submitted is None or request_time is None:
                    continue
                live_reviews.append(
                    {
                        "id": review_id,
                        "state": state,
                        "submitted": submitted,
                    }
                )
        minimum_time = datetime.min.replace(tzinfo=timezone.utc)
        live_reviews.sort(
            key=lambda item: (
                item["submitted"] if isinstance(item["submitted"], datetime) else minimum_time,
                item["id"],
            )
        )
        pending_reviews = [
            item for item in live_reviews if item["state"] == "PENDING"
        ]
        if pending_reviews:
            errors.append("merge_guard_codex_outstanding_pending_review")
        blockers = [
            item for item in live_reviews if item["state"] == "CHANGES_REQUESTED"
        ]
        if blockers:
            latest_blocker = blockers[-1]
            superseding_approval = any(
                item["state"] == "APPROVED"
                and isinstance(item["submitted"], datetime)
                and isinstance(latest_blocker["submitted"], datetime)
                and (item["submitted"], item["id"])
                > (latest_blocker["submitted"], latest_blocker["id"])
                for item in live_reviews
            )
            if not superseding_approval:
                errors.append("merge_guard_codex_outstanding_blocking_review")
        receipt["current_head_review_count"] = len(live_reviews)
        receipt["current_head_review_set_sha256"] = _sha256_json(
            [
                {
                    "id": item["id"],
                    "state": item["state"],
                    "submitted_at": (
                        item["submitted"].isoformat()
                        if isinstance(item["submitted"], datetime)
                        else None
                    ),
                }
                for item in live_reviews
            ]
        )

        mode = completion.get("mode")
        completion_time: datetime | None = None
        if mode == "review":
            review_id = completion.get("review_id")
            if review_id not in {item["id"] for item in live_reviews}:
                errors.append("merge_guard_codex_completion_review_not_in_live_set")
            if (
                isinstance(review_id, bool)
                or not isinstance(review_id, int)
                or review_id <= 0
            ):
                errors.append("merge_guard_codex_review_id_invalid")
            else:
                review_payload = self._codex_api_json(
                    [
                        "api",
                        f"repos/{repository}/pulls/{pr_number}/reviews/{review_id}",
                    ],
                    label="review",
                    observations=observations,
                    errors=errors,
                )
                if isinstance(review_payload, dict):
                    actor = _github_actor(review_payload.get("user"))
                    state = str(review_payload.get("state") or "").upper()
                    body = str(review_payload.get("body") or "")
                    completion_time = _github_datetime(
                        review_payload.get("submitted_at")
                    )
                    if actor not in _CODEX_REVIEW_ACTORS:
                        errors.append("merge_guard_codex_review_actor_untrusted")
                    if actor != str(completion.get("actor", "")).lower():
                        errors.append("merge_guard_codex_review_actor_drift")
                    if state not in {"APPROVED", "COMMENTED"}:
                        errors.append("merge_guard_codex_review_state_blocking")
                    if state != completion.get("state"):
                        errors.append("merge_guard_codex_review_state_drift")
                    if review_payload.get("commit_id") != head_sha:
                        errors.append("merge_guard_codex_review_head_drift")
                    if hashlib.sha256(body.encode("utf-8")).hexdigest() != completion.get(
                        "body_sha256"
                    ):
                        errors.append("merge_guard_codex_review_body_drift")
                else:
                    errors.append("merge_guard_codex_review_missing")
        elif mode == "clean_comment":
            comment_id = completion.get("comment_id")
            if (
                isinstance(comment_id, bool)
                or not isinstance(comment_id, int)
                or comment_id <= 0
            ):
                errors.append("merge_guard_codex_clean_comment_id_invalid")
            else:
                matching_comments = [
                    item
                    for item in (request_comments or [])
                    if item.get("id") == comment_id
                ]
                if len(matching_comments) != 1:
                    errors.append("merge_guard_codex_clean_comment_missing_or_ambiguous")
                else:
                    live_comment = matching_comments[0]
                    actor = _github_actor(live_comment.get("user"))
                    body = live_comment.get("body")
                    completion_time = _github_datetime(live_comment.get("created_at"))
                    if actor not in _CODEX_REVIEW_ACTORS:
                        errors.append("merge_guard_codex_clean_comment_actor_untrusted")
                    if actor != str(completion.get("actor", "")).lower():
                        errors.append("merge_guard_codex_clean_comment_actor_drift")
                    if not isinstance(body, str):
                        errors.append("merge_guard_codex_clean_comment_body_missing")
                    else:
                        match = _CODEX_CLEAN_RESULT_RE.fullmatch(
                            _normalize_codex_comment_body(body)
                        )
                        if match is None:
                            errors.append("merge_guard_codex_clean_comment_shape_invalid")
                        else:
                            reviewed_prefix = match.group(1)
                            if not head_sha.startswith(reviewed_prefix):
                                errors.append("merge_guard_codex_clean_comment_head_drift")
                            if reviewed_prefix != completion.get(
                                "reviewed_commit_prefix"
                            ):
                                errors.append(
                                    "merge_guard_codex_clean_comment_prefix_drift"
                                )
                        if hashlib.sha256(body.encode("utf-8")).hexdigest() != completion.get(
                            "body_sha256"
                        ):
                            errors.append("merge_guard_codex_clean_comment_body_drift")
                    if completion.get("state") != "CLEAN":
                        errors.append("merge_guard_codex_clean_comment_state_drift")
                    if (
                        request_time is not None
                        and completion_time is not None
                        and completion_time < request_time
                    ):
                        errors.append("merge_guard_codex_clean_comment_predates_request")
                    expected_url = completion.get("url")
                    if (
                        isinstance(expected_url, str)
                        and expected_url
                        and live_comment.get("html_url") != expected_url
                    ):
                        errors.append("merge_guard_codex_clean_comment_url_drift")
        elif mode == "unavailable_comment":
            errors.append("merge_guard_codex_unavailable_comment_unbound")
        elif mode == "reaction":
            reaction_comment_id = completion.get("comment_id")
            reacted_request_time: datetime | None = None
            if (
                isinstance(reaction_comment_id, bool)
                or not isinstance(reaction_comment_id, int)
                or reaction_comment_id <= 0
            ):
                errors.append("merge_guard_codex_reaction_comment_id_invalid")
                reactions: list[dict[str, Any]] = []
            else:
                reacted_requests = [
                    item
                    for item in canonical_requests
                    if item["id"] == reaction_comment_id
                ]
                if len(reacted_requests) != 1:
                    errors.append(
                        "merge_guard_codex_reaction_request_missing_or_ambiguous"
                    )
                    reactions = []
                else:
                    reacted_request_time = reacted_requests[0]["created"]
                    bounded_reactions = self._codex_single_page(
                        [
                            "api",
                            "--paginate",
                            "--slurp",
                            (
                                f"repos/{repository}/issues/comments/"
                                f"{reaction_comment_id}/reactions?per_page=100"
                            ),
                        ],
                        label="reactions",
                        observations=observations,
                        errors=errors,
                    )
                    reactions = bounded_reactions or []
            matching_reactions: list[dict[str, Any]] = []
            for reaction in reactions:
                actor = _github_actor(reaction.get("user"))
                created = _github_datetime(reaction.get("created_at"))
                if (
                    actor in _CODEX_REVIEW_ACTORS
                    and reaction.get("content") == "+1"
                    and created is not None
                    and reacted_request_time is not None
                    and created >= reacted_request_time
                ):
                    matching_reactions.append(
                        {**reaction, "_actor": actor, "_created": created}
                    )
            expected_completion_time = _github_datetime(completion.get("submitted_at"))
            matching = [
                item
                for item in matching_reactions
                if item["_actor"] == str(completion.get("actor", "")).lower()
                and item["_created"] == expected_completion_time
            ]
            if not matching:
                errors.append("merge_guard_codex_reaction_missing_or_drifted")
            else:
                completion_time = matching[-1]["_created"]
            if completion.get("state") != "THUMBS_UP":
                errors.append("merge_guard_codex_reaction_state_drift")
            if completion.get("body_sha256") != hashlib.sha256(
                b"THUMBS_UP"
            ).hexdigest():
                errors.append("merge_guard_codex_reaction_body_drift")
        else:
            errors.append("merge_guard_codex_completion_mode_invalid")
        expected_completion_time = _github_datetime(completion.get("submitted_at"))
        if (
            completion_time is None
            or expected_completion_time is None
            or completion_time != expected_completion_time
        ):
            errors.append("merge_guard_codex_completion_time_drift")
        if (
            request_time is not None
            and completion_time is not None
            and completion_time < request_time
        ):
            errors.append("merge_guard_codex_completion_predates_request")

        owner, _, name = repository.partition("/")
        threads_payload = self._codex_api_json(
            [
                "api",
                "graphql",
                "-f",
                f"query={_CODEX_THREADS_QUERY}",
                "-F",
                f"owner={owner}",
                "-F",
                f"name={name}",
                "-F",
                f"number={pr_number}",
            ],
            label="threads",
            observations=observations,
            errors=errors,
        )
        thread_ids: list[str] = []
        unresolved_thread_ids: list[str] = []
        if isinstance(threads_payload, dict):
            try:
                connection = threads_payload["data"]["repository"]["pullRequest"][
                    "reviewThreads"
                ]
            except (KeyError, TypeError):
                connection = None
            if not isinstance(connection, dict):
                errors.append("merge_guard_codex_threads_shape_invalid")
            else:
                page_info = connection.get("pageInfo")
                nodes = connection.get("nodes")
                if not isinstance(page_info, dict) or page_info.get("hasNextPage") is not False:
                    errors.append("merge_guard_codex_threads_truncated")
                if not isinstance(nodes, list):
                    errors.append("merge_guard_codex_threads_nodes_invalid")
                else:
                    for thread in nodes:
                        if not isinstance(thread, dict):
                            errors.append("merge_guard_codex_thread_invalid")
                            continue
                        thread_id = thread.get("id")
                        comments = thread.get("comments")
                        if not isinstance(thread_id, str) or not thread_id:
                            errors.append("merge_guard_codex_thread_id_invalid")
                            continue
                        if not isinstance(comments, dict):
                            errors.append("merge_guard_codex_thread_comments_invalid")
                            continue
                        page = comments.get("pageInfo")
                        comment_nodes = comments.get("nodes")
                        if not isinstance(page, dict) or page.get("hasNextPage") is not False:
                            errors.append(
                                f"merge_guard_codex_thread_comments_truncated:{thread_id}"
                            )
                            continue
                        if not isinstance(comment_nodes, list):
                            errors.append(
                                f"merge_guard_codex_thread_comments_invalid:{thread_id}"
                            )
                            continue
                        matched = False
                        for comment in comment_nodes:
                            if not isinstance(comment, dict):
                                continue
                            actor = _github_actor(comment.get("author"))
                            commit = comment.get("commit")
                            commit_sha = (
                                commit.get("oid") if isinstance(commit, dict) else None
                            )
                            created = _github_datetime(comment.get("createdAt"))
                            if (
                                actor in _CODEX_REVIEW_ACTORS
                                and commit_sha == head_sha
                                and created is not None
                            ):
                                matched = True
                        if matched:
                            thread_ids.append(thread_id)
                            if thread.get("isResolved") is not True:
                                unresolved_thread_ids.append(thread_id)
        thread_ids = sorted(set(thread_ids))
        unresolved_thread_ids = sorted(set(unresolved_thread_ids))
        expected_thread_ids = evidence.get("thread_ids")
        if thread_ids != expected_thread_ids:
            errors.append("merge_guard_codex_thread_set_drift")
        if _sha256_json(thread_ids) != evidence.get("thread_ids_sha256"):
            errors.append("merge_guard_codex_thread_digest_drift")
        if unresolved_thread_ids:
            errors.append("merge_guard_codex_unresolved_threads_present")
        if evidence.get("unresolved_thread_ids") != []:
            errors.append("merge_guard_codex_evidence_claims_unresolved_threads")
        receipt.update(
            {
                "status": "blocked" if errors else "settled",
                "request_comment_id": request_comment_id,
                "completion_mode": mode,
                "completion_id": completion.get("review_id"),
                "completion_comment_id": completion.get("comment_id"),
                "review_performed": True,
                "settlement_reason": completion.get("reason"),
                "thread_count": len(thread_ids),
                "thread_ids_sha256": _sha256_json(thread_ids),
                "unresolved_thread_count": len(unresolved_thread_ids),
                "unresolved_thread_ids_sha256": _sha256_json(
                    unresolved_thread_ids
                ),
                "binding_sha256": _sha256_json(
                    {
                        "repository": repository,
                        "pull_request": pr_number,
                        "head_sha": head_sha,
                        "base_sha": base_sha,
                        "diff_sha256": diff_sha256,
                        "request_comment_id": request_comment_id,
                        "completion_mode": mode,
                        "completion_id": completion.get("review_id"),
                        "completion_comment_id": completion.get("comment_id"),
                        "review_performed": True,
                        "settlement_reason": completion.get("reason"),
                        "thread_ids": thread_ids,
                        "unresolved_thread_ids": unresolved_thread_ids,
                    }
                ),
            }
        )
        return errors

    def _static_binding_errors(self) -> list[str]:
        expected_head = str(self.parameters.get("expected_head", ""))
        expected_base_sha = str(self.parameters.get("expected_base_sha", ""))
        expected_diff = str(self.parameters.get("diff_sha256", ""))
        errors: list[str] = []
        if self.server_actor_identity_error:
            errors.append("merge_guard_server_actor_identity_invalid")
        if self.server_task_lease_delegation_error:
            errors.append("merge_guard_server_task_lease_delegation_invalid")
        if self.server_operator_lease_delegation_error:
            errors.append("merge_guard_server_operator_lease_delegation_invalid")
        if (
            _TASK_OWNER_RE.fullmatch(self.requested_lease_owner_id) is not None
            and self.server_task_lease_delegation is None
        ):
            errors.append("merge_guard_server_task_lease_delegation_required")
        if (
            _DIRECT_OPERATOR_OWNER_RE.fullmatch(self.requested_lease_owner_id)
            is not None
            and self.server_operator_lease_delegation is None
        ):
            errors.append("merge_guard_server_operator_lease_delegation_required")
        if _OWNER_RE.fullmatch(self.lease_owner_id) is None:
            errors.append("merge_guard_lease_owner_invalid")
        if _SHA40_RE.fullmatch(expected_head) is None:
            errors.append("merge_guard_expected_head_invalid")
        if _SHA40_RE.fullmatch(expected_base_sha) is None:
            errors.append("merge_guard_expected_base_sha_invalid")
        if _SHA256_RE.fullmatch(expected_diff) is None:
            errors.append("merge_guard_expected_diff_sha256_invalid")
        delivery_receipt = self.parameters.get("merge_delivery_receipt")
        delivery_receipt_sha256 = self.parameters.get(
            "merge_delivery_receipt_sha256"
        )
        if not isinstance(delivery_receipt, dict) or not delivery_receipt:
            errors.append("merge_guard_delivery_receipt_missing")
        if (
            not isinstance(delivery_receipt_sha256, str)
            or _SHA256_RE.fullmatch(delivery_receipt_sha256) is None
        ):
            errors.append("merge_guard_delivery_receipt_sha256_invalid")
        replay_fields = sorted(_MERGE_GUARD_REPLAY_PARAMETERS.intersection(self.parameters))
        if replay_fields:
            errors.append("merge_guard_cached_snapshot_input_forbidden:" + ",".join(replay_fields))
        return errors

    def _live_bindings(self) -> tuple[dict[str, Any] | None, list[str]]:
        target = self.action["target"]
        repo_slug = str(target["repo"])
        pr_number = int(target["pr"])
        expected_base = str(target["base"])
        expected_head = str(self.parameters.get("expected_head", ""))
        expected_base_sha = str(self.parameters.get("expected_base_sha", ""))
        expected_diff = str(self.parameters.get("diff_sha256", ""))
        errors = list(self.static_errors)
        if errors:
            return None, errors
        try:
            delivery_info = grabowski_merge_delivery.verify_merge_delivery(
                self.parameters.get("merge_delivery_receipt"),
                expected_repository=repo_slug,
                expected_pull_request=pr_number,
                expected_base_sha=expected_base_sha,
                expected_head_sha=expected_head,
                expected_diff_sha256=expected_diff,
                expected_receipt_sha256=str(
                    self.parameters.get("merge_delivery_receipt_sha256", "")
                ),
            )
        except (ValueError, grabowski_merge_delivery.MergeDeliveryError) as exc:
            errors.append(
                f"merge_guard_delivery_receipt_invalid:{type(exc).__name__}:{exc}"
            )
            self.receipt["merge_delivery"] = {
                "valid": False,
                "error_type": type(exc).__name__,
            }
            return None, errors
        self.receipt["merge_delivery"] = delivery_info

        view_args = [
            "pr",
            "view",
            str(pr_number),
            "--repo",
            repo_slug,
            "--json",
            "number,state,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,mergeable,mergeStateStatus,changedFiles,files",
        ]
        try:
            view_raw = self.github_runner(self.repo_path, view_args)
        except Exception as exc:
            errors.append(f"merge_guard_live_view_exception:{type(exc).__name__}")
            return None, errors
        view_info = _merge_guard_result_info(view_raw)
        self.receipt["live_view"] = {
            "command": ["gh", *view_args],
            "returncode": view_info["returncode"],
            "stdout_sha256": hashlib.sha256(view_info["stdout"].encode()).hexdigest(),
            "stderr_sha256": hashlib.sha256(view_info["stderr"].encode()).hexdigest(),
        }
        if view_info["returncode"] != 0:
            errors.append("merge_guard_live_view_failed")
            return None, errors
        try:
            viewed = json.loads(view_info["stdout"])
        except json.JSONDecodeError:
            errors.append("merge_guard_live_view_invalid_json")
            return None, errors
        if not isinstance(viewed, dict):
            errors.append("merge_guard_live_view_not_object")
            return None, errors
        base_sha = viewed.get("baseRefOid")
        if not isinstance(base_sha, str) or _SHA40_RE.fullmatch(base_sha) is None:
            errors.append("merge_guard_base_sha_missing_or_invalid")
        elif base_sha != expected_base_sha:
            errors.append("merge_guard_base_sha_drift")
        if viewed.get("number") != pr_number:
            errors.append("merge_guard_pr_number_drift")
        if viewed.get("state") != "OPEN":
            errors.append("merge_guard_pr_not_open")
        if viewed.get("isDraft") is not False:
            errors.append("merge_guard_pr_draft_state_not_confirmed")
        head_branch = viewed.get("headRefName")
        if (
            not isinstance(head_branch, str)
            or not head_branch
            or "\x00" in head_branch
            or len(head_branch.encode("utf-8")) > 1024
        ):
            errors.append("merge_guard_head_branch_missing_or_invalid")
        if viewed.get("headRefOid") != expected_head:
            errors.append("merge_guard_head_drift")
        if viewed.get("baseRefName") != expected_base:
            errors.append("merge_guard_base_branch_drift")
        if viewed.get("mergeable") != "MERGEABLE":
            errors.append("merge_guard_mergeable_not_confirmed")
        if viewed.get("mergeStateStatus") != "CLEAN":
            errors.append("merge_guard_merge_state_not_clean")

        changed_files = viewed.get("changedFiles")
        raw_files = viewed.get("files")
        changed_paths: list[str] = []
        if type(changed_files) is not int or changed_files < 1:
            errors.append("merge_guard_changed_file_count_invalid")
        if not isinstance(raw_files, list):
            errors.append("merge_guard_changed_file_list_missing")
        else:
            for index, item in enumerate(raw_files):
                if not isinstance(item, dict):
                    errors.append(f"merge_guard_changed_file_invalid:{index}")
                    continue
                path = item.get("path")
                change_type = item.get("changeType")
                if (
                    not isinstance(path, str)
                    or not path
                    or path.startswith("/")
                    or "\x00" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                ):
                    errors.append(f"merge_guard_changed_path_invalid:{index}")
                    continue
                if change_type in {"RENAMED", "COPIED"}:
                    errors.append(f"merge_guard_changed_path_requires_previous_name:{index}")
                    continue
                if change_type not in {"ADDED", "MODIFIED", "DELETED"}:
                    errors.append(f"merge_guard_change_type_invalid:{index}")
                    continue
                changed_paths.append(path)
            if type(changed_files) is int and changed_files > _MERGE_GUARD_MAX_CHANGED_PATHS:
                errors.append("merge_guard_changed_file_count_exceeds_supported_limit")
            if type(changed_files) is int and changed_files != len(raw_files):
                errors.append("merge_guard_changed_file_list_incomplete")
            if len(raw_files) > _MERGE_GUARD_MAX_CHANGED_PATHS:
                errors.append("merge_guard_changed_path_count_exceeds_limit")
            if len(changed_paths) != len(set(changed_paths)):
                errors.append("merge_guard_changed_paths_duplicate")
        changed_paths = sorted(set(changed_paths))
        if not changed_paths:
            errors.append("merge_guard_changed_paths_empty")
        elif len(_canonical_json(changed_paths).encode("utf-8")) > (
            _MERGE_GUARD_MAX_CHANGED_PATH_BYTES
        ):
            errors.append("merge_guard_changed_paths_exceed_byte_limit")

        diff_args = ["pr", "diff", str(pr_number), "--repo", repo_slug]
        try:
            diff_raw = self.github_runner(self.repo_path, diff_args)
        except Exception as exc:
            errors.append(f"merge_guard_live_diff_exception:{type(exc).__name__}")
            return None, errors
        diff_info = _merge_guard_result_info(diff_raw)
        if isinstance(diff_info.get("stdout_bytes"), bytes):
            live_diff_bytes = diff_info["stdout_bytes"]
            diff_canonicalization = "raw-command-bytes"
        else:
            live_diff_bytes = diff_info["stdout"].encode("utf-8")
            diff_canonicalization = "utf8-runner-text-exact-fallback"
        live_diff_sha256 = hashlib.sha256(live_diff_bytes).hexdigest()
        self.receipt["live_diff"] = {
            "command": ["gh", *diff_args],
            "returncode": diff_info["returncode"],
            "bytes": len(live_diff_bytes),
            "canonicalization": diff_canonicalization,
            "sha256": live_diff_sha256,
            "stderr_sha256": hashlib.sha256(diff_info["stderr"].encode()).hexdigest(),
        }
        if diff_info["returncode"] != 0:
            errors.append("merge_guard_live_diff_failed")
        elif not live_diff_bytes:
            errors.append("merge_guard_live_diff_empty")
        elif live_diff_sha256 != expected_diff:
            errors.append("merge_guard_diff_drift")
        bindings = {
            "repository": repo_slug,
            "pull_request": pr_number,
            "base_branch": expected_base,
            "base_sha": base_sha,
            "expected_base_sha": expected_base_sha,
            "head_branch": head_branch,
            "head_sha": expected_head,
            "diff_sha256": live_diff_sha256,
            "execution_intent_sha256": self.execution_intent_sha256,
            "merge_delivery_receipt_sha256": delivery_info["receipt_sha256"],
            "merge_delivery_binding_sha256": delivery_info["binding_sha256"],
            "merge_delivery_confirmed_at_unix_ns": delivery_info[
                "delivery_confirmed_at_unix_ns"
            ],
            "changed_paths": changed_paths,
            "changed_paths_sha256": _sha256_json(changed_paths),
        }
        if not errors:
            errors.extend(
                self._revalidate_codex_review(bindings, phase="initial")
            )
        return bindings, errors

    def _revalidate_dispatch_bindings(self, bindings: dict[str, Any]) -> list[str]:
        target = self.action["target"]
        errors: list[str] = []
        try:
            delivery_info = grabowski_merge_delivery.verify_merge_delivery(
                self.parameters.get("merge_delivery_receipt"),
                expected_repository=str(target["repo"]),
                expected_pull_request=int(target["pr"]),
                expected_base_sha=str(bindings["expected_base_sha"]),
                expected_head_sha=str(bindings["head_sha"]),
                expected_diff_sha256=str(bindings["diff_sha256"]),
                expected_receipt_sha256=str(
                    bindings["merge_delivery_receipt_sha256"]
                ),
            )
        except (ValueError, grabowski_merge_delivery.MergeDeliveryError) as exc:
            errors.append(
                f"merge_guard_dispatch_delivery_revalidation_failed:{type(exc).__name__}:{exc}"
            )
            self.receipt["dispatch_delivery_revalidation"] = {
                "valid": False,
                "error_type": type(exc).__name__,
            }
        else:
            self.receipt["dispatch_delivery_revalidation"] = delivery_info
            if delivery_info["binding_sha256"] != bindings[
                "merge_delivery_binding_sha256"
            ]:
                errors.append("merge_guard_dispatch_delivery_binding_drift")
        view_args = [
            "pr",
            "view",
            str(target["pr"]),
            "--repo",
            str(target["repo"]),
            "--json",
            "number,state,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,mergeable,mergeStateStatus",
        ]
        try:
            raw = self.github_runner(self.repo_path, view_args)
        except Exception as exc:
            errors.append(f"merge_guard_dispatch_revalidation_exception:{type(exc).__name__}")
            self.receipt["dispatch_revalidation"] = {
                "command": ["gh", *view_args],
                "errors": list(errors),
            }
            return errors
        info = _merge_guard_result_info(raw)
        stdout_bytes = (
            info["stdout_bytes"]
            if isinstance(info.get("stdout_bytes"), bytes)
            else info["stdout"].encode("utf-8")
        )
        self.receipt["dispatch_revalidation"] = {
            "command": ["gh", *view_args],
            "returncode": info["returncode"],
            "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "stderr_sha256": hashlib.sha256(info["stderr"].encode("utf-8")).hexdigest(),
        }
        if info["returncode"] != 0:
            errors.append("merge_guard_dispatch_revalidation_failed")
            return errors
        try:
            viewed = json.loads(info["stdout"])
        except json.JSONDecodeError:
            errors.append("merge_guard_dispatch_revalidation_invalid_json")
            return errors
        if not isinstance(viewed, dict):
            errors.append("merge_guard_dispatch_revalidation_not_object")
            return errors
        expected = {
            "number": bindings["pull_request"],
            "state": "OPEN",
            "headRefName": bindings["head_branch"],
            "headRefOid": bindings["head_sha"],
            "baseRefName": bindings["base_branch"],
            "baseRefOid": bindings["base_sha"],
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        }
        for field, expected_value in expected.items():
            if viewed.get(field) != expected_value:
                errors.append(f"merge_guard_dispatch_revalidation_drift:{field}")
        self.receipt["dispatch_revalidation"]["errors"] = list(errors)
        self.receipt["dispatch_revalidation"]["binding_sha256"] = _sha256_json(
            {field: viewed.get(field) for field in sorted(expected)}
        )
        (
            base_update_guard,
            base_update_guard_evidence,
            base_update_guard_errors,
        ) = verify_github_base_update_guard(
            self.repo_path,
            self.github_runner,
            repo_slug=str(bindings["repository"]),
            base_branch=str(bindings["base_branch"]),
        )
        base_update_guard_evidence["policy"] = base_update_guard
        self.receipt["dispatch_base_update_guard"] = base_update_guard_evidence
        errors.extend(base_update_guard_errors)
        if not errors:
            errors.extend(
                self._revalidate_codex_review(bindings, phase="dispatch")
            )
        self.receipt["dispatch_revalidation"]["errors"] = list(errors)
        return errors

    def __call__(self, repo_path: Path, args: list[str]) -> dict[str, Any]:
        if args[:2] != ["pr", "merge"]:
            result = self.github_runner(repo_path, args)
            if self._is_repository_policy_query(args):
                self._capture_repository_policy_snapshot(args, result)
            return result
        if self.receipt["status"] != "not_reached":
            raise RuntimeError("merge lease guard permits exactly one merge dispatch")
        observed_at_ns = time.time_ns()
        try:
            resource_repository = merge_guard_repository_root(self.repo_path)
        except Exception as exc:
            self.receipt["status"] = "blocked_before_guard"
            self.receipt["observed_at_unix_ns"] = observed_at_ns
            self.receipt["errors"] = [f"merge_guard_repository_identity_failed:{type(exc).__name__}:{exc}"]
            raise RuntimeError("merge lease guard repository identity failed") from exc
        bindings, errors = self._live_bindings()
        self.receipt["observed_at_unix_ns"] = observed_at_ns
        self.receipt["bindings"] = bindings
        if errors or bindings is None:
            self.receipt["status"] = "blocked_before_guard"
            self.receipt["errors"] = errors
            raise RuntimeError("merge lease guard blocked: " + "; ".join(errors))

        import grabowski_resources as resources

        target = self.action["target"]
        bindings["local_resource_repository"] = str(resource_repository)
        absolute_changed_paths = [
            str(Path(resource_repository, path))
            for path in bindings["changed_paths"]
        ]
        self.resource_keys = merge_guard_resource_keys(
            resource_repository,
            repo_slug=str(target["repo"]),
            pr_number=int(target["pr"]),
            base=str(target["base"]),
            head=str(bindings["head_branch"]),
        )
        self.owner_id = "captain-merge:" + hashlib.sha256(
            f"{self.execution_intent_sha256}:{time.time_ns()}".encode("utf-8")
        ).hexdigest()[:24]
        metadata = {
            "merge_guard": {
                **bindings,
                "resource_keys_sha256": _sha256_json(self.resource_keys),
                "observed_at_unix_ns": observed_at_ns,
            }
        }
        try:
            self.acquisition = resources.acquire_merge_guard_resources(
                self.owner_id,
                self.lease_owner_id,
                self.resource_keys,
                repository=str(resource_repository),
                changed_paths=absolute_changed_paths,
                purpose=(
                    f"Captain atomic merge guard for {bindings['repository']}#{bindings['pull_request']} "
                    f"head={bindings['head_sha']} diff={bindings['diff_sha256']}"
                ),
                ttl_seconds=_MERGE_GUARD_TTL_SECONDS,
                metadata=metadata,
                delegated_task=self.server_task_lease_delegation,
                delegated_operator=self.server_operator_lease_delegation,
            )
        except Exception as exc:
            self.receipt["status"] = "blocked_by_live_lease"
            self.receipt["errors"] = [f"{type(exc).__name__}:{exc}"]
            self.receipt["resource_keys"] = self.resource_keys
            raise RuntimeError("merge lease guard acquisition failed") from exc

        self.resource_keys = list(self.acquisition["resource_keys"])
        self.held_resource_keys = list(self.acquisition["held_resource_keys"])
        lease_snapshot = {
            "observed_leases": self.acquisition["observed_leases"],
            "acquired_leases": self.acquisition["acquired_leases"],
            "held_resource_keys": self.held_resource_keys,
        }
        self.receipt.update(
            {
                "status": "guard_acquired",
                "contract_satisfied": True,
                "owner_id": self.owner_id,
                "resource_keys": self.resource_keys,
                "resource_keys_sha256": _sha256_json(self.resource_keys),
                "lease_snapshot": lease_snapshot,
                "lease_snapshot_sha256": _sha256_json(lease_snapshot),
                "lease_owner_id": self.lease_owner_id,
                "lease_owner_source": self.lease_owner_source,
                "changed_paths": bindings["changed_paths"],
                "changed_paths_sha256": bindings["changed_paths_sha256"],
                "held_resource_keys": self.held_resource_keys,
                "guard_acquired_at_unix": self.acquisition["observed_at_unix"],
                "lease_snapshot_observed_at_unix_ns": self.acquisition[
                    "observed_at_unix_ns"
                ],
                "guard_expires_at_unix": self.acquisition["expires_at_unix"],
                "delegated_task_id": self.acquisition.get("delegated_task_id"),
                "task_authority_adoption_sha256": (
                    self.acquisition.get("task_authority_adoption", {}).get("binding_sha256")
                    if isinstance(self.acquisition.get("task_authority_adoption"), dict)
                    else None
                ),
                "delegated_task_resource_keys_sha256": (
                    _sha256_json(self.acquisition.get("delegated_task_resource_keys", []))
                    if self.acquisition.get("delegated_task_id") is not None
                    else None
                ),
                "delegated_operator_resource_keys_sha256": (
                    _sha256_json(
                        self.acquisition.get("delegated_operator_resource_keys", [])
                    )
                    if self.acquisition.get("delegated_operator_lease_owner_id")
                    is not None
                    else None
                ),
                "delegated_operator_target_resource_keys_sha256": (
                    _sha256_json(
                        self.acquisition.get(
                            "delegated_operator_target_resource_keys", []
                        )
                    )
                    if self.acquisition.get("delegated_operator_lease_owner_id")
                    is not None
                    else None
                ),
                "delegated_operator_lease_bindings_sha256": self.acquisition.get(
                    "delegated_operator_lease_bindings_sha256"
                ),
                "delegated_operator_delegation_sha256": self.acquisition.get(
                    "delegated_operator_delegation_sha256"
                ),
                "delegated_operator_authority_key": self.acquisition.get(
                    "delegated_operator_authority_key"
                ),
            }
        )
        revalidation_errors = self._revalidate_dispatch_bindings(bindings)
        revalidation_errors.extend(self._revalidate_repository_policy())
        if revalidation_errors:
            self.receipt["status"] = "blocked_after_guard_revalidation"
            self.receipt["contract_satisfied"] = False
            self.receipt["errors"] = revalidation_errors
            raise RuntimeError(
                "merge lease guard dispatch revalidation blocked: "
                + "; ".join(revalidation_errors)
            )
        self.receipt["dispatch_at_unix_ns"] = time.time_ns()
        self.receipt["dispatch_called"] = True
        self.dispatch_called = True
        return self.github_runner(repo_path, args)

    def _delegated_operator_terminal_evidence(
        self, execution_result: dict[str, Any]
    ) -> dict[str, Any] | None:
        if self.server_operator_lease_delegation is None or self.owner_id is None:
            return None
        if execution_result.get("verification_passed") is True:
            status = "success"
        elif (
            self.acquisition is not None
            and not self.dispatch_called
            and not bool(execution_result.get("remote_mutation_observed"))
        ):
            status = "authoritative_abort"
        else:
            return None
        material: dict[str, Any] = {
            "schema_version": 1,
            "kind": "grabowski_captain_operator_lease_terminal_evidence",
            "status": status,
            "guard_owner_id": self.owner_id,
            "dispatch_called": self.dispatch_called,
            "execution_invoked": bool(execution_result.get("execution_invoked")),
            "verification_passed": execution_result.get("verification_passed") is True,
            "observed_at_unix_ns": int(self.receipt["completed_at_unix_ns"]),
        }
        return {**material, "terminal_evidence_sha256": _sha256_json(material)}

    def finalize(self, execution_result: dict[str, Any]) -> None:
        import grabowski_resources as resources

        self.receipt["completed_at_unix_ns"] = time.time_ns()
        cleanup_required = self.acquisition is not None and self.owner_id is not None
        cleanup_passed = True
        cleanup_error: str | None = None
        self.receipt["external_merge_observed"] = bool(
            execution_result.get("remote_mutation_observed") and not self.dispatch_called
        )
        if self.receipt["external_merge_observed"]:
            verified_pr = execution_result.get("verified_pr")
            merged_at_unix_ns = grabowski_merge_delivery.github_timestamp_unix_ns(
                verified_pr.get("mergedAt")
                if isinstance(verified_pr, dict)
                else None
            )
            reconciliation = grabowski_merge_delivery.github_merge_ordering(
                self.receipt.get("merge_delivery", {}), merged_at_unix_ns
            )
            self.receipt["external_merge_reconciliation"] = reconciliation
            execution_result["external_merge_reconciliation"] = reconciliation
        self.receipt["merge_command_returncode"] = execution_result.get("merge_returncode")
        self.receipt["post_merge_verification_passed"] = execution_result.get("verification_passed") is True
        if self.acquisition is not None and self.owner_id is not None:
            cleanup_failures: list[str] = []
            release_failed = False
            delegated_operator_owner = self.acquisition.get(
                "delegated_operator_lease_owner_id"
            )
            if delegated_operator_owner is not None:
                terminal_evidence = self._delegated_operator_terminal_evidence(
                    execution_result
                )
                if terminal_evidence is None:
                    retained_keys = self.acquisition.get(
                        "delegated_operator_resource_keys", []
                    )
                    self.receipt["delegated_operator_lease_convergence"] = {
                        "schema_version": 1,
                        "kind": "grabowski_delegated_operator_lease_convergence",
                        "owner_id_sha256": hashlib.sha256(
                            str(delegated_operator_owner).encode("utf-8")
                        ).hexdigest(),
                        "resource_keys_sha256": _sha256_json(retained_keys),
                        "lease_bindings_sha256": self.acquisition.get(
                            "delegated_operator_lease_bindings_sha256"
                        ),
                        "status": "retained_missing_terminal_evidence",
                        "released_count": 0,
                        "retained_count": len(retained_keys),
                        "does_not_establish": [
                            "terminal_success",
                            "permission_to_release_changed_lease",
                            "permission_to_release_foreign_lease",
                        ],
                    }
                else:
                    self.receipt["delegated_operator_terminal_evidence"] = (
                        terminal_evidence
                    )
                    try:
                        convergence = resources.reconcile_delegated_operator_leases(
                            str(delegated_operator_owner),
                            self.acquisition.get(
                                "delegated_operator_lease_snapshots", []
                            ),
                            expected_lease_bindings_sha256=str(
                                self.acquisition.get(
                                    "delegated_operator_lease_bindings_sha256", ""
                                )
                            ),
                            delegation_sha256=str(
                                self.acquisition.get(
                                    "delegated_operator_delegation_sha256", ""
                                )
                            ),
                            authority_resource_key=str(
                                self.acquisition.get(
                                    "delegated_operator_authority_key", ""
                                )
                            ),
                            terminal_source=terminal_evidence,
                        )
                        self.receipt["delegated_operator_lease_convergence"] = (
                            convergence
                        )
                    except Exception as exc:
                        cleanup_failures.append(
                            "delegated Operator lease convergence failed"
                        )
                        self.receipt[
                            "delegated_operator_lease_convergence_error"
                        ] = f"{type(exc).__name__}:{exc}"

            released: dict[str, Any] | None = None
            try:
                released = resources.release_resources(
                    self.owner_id, self.held_resource_keys, force=False
                )
                self.receipt["release"] = released
                released_keys = sorted(
                    item["resource_key"] for item in released.get("released", [])
                )
                if released_keys != self.held_resource_keys:
                    cleanup_failures.append("merge lease guard release incomplete")
            except Exception as exc:
                release_failed = True
                cleanup_failures.append("merge lease guard release failed")
                self.receipt["release_error"] = f"{type(exc).__name__}:{exc}"

            delegated_task_id = self.acquisition.get("delegated_task_id")
            if delegated_task_id is not None:
                try:
                    adoption_release = resources.release_task_authority_adoption(
                        self.owner_id, delegated_task_id
                    )
                    self.receipt["task_authority_adoption_release"] = adoption_release
                    if adoption_release.get("released") is not True:
                        cleanup_failures.append(
                            "merge task authority adoption release incomplete"
                        )
                except Exception as exc:
                    release_failed = True
                    cleanup_failures.append(
                        "merge task authority adoption release failed"
                    )
                    self.receipt["task_authority_adoption_release_error"] = (
                        f"{type(exc).__name__}:{exc}"
                    )

            if cleanup_failures:
                cleanup_passed = False
                cleanup_error = "; ".join(cleanup_failures)
                self.receipt["status"] = (
                    "guard_release_failed" if release_failed else "guard_release_incomplete"
                )
                self.receipt["contract_satisfied"] = False
            elif self.receipt["status"] == "guard_acquired":
                self.receipt["status"] = "completed"
            else:
                self.receipt["status"] = self.receipt["status"] + "_released"
        if (
            not self.dispatch_called
            and self.receipt["status"] != "not_reached"
        ):
            execution_result["execution_invoked"] = False
            execution_result["execution_attempted"] = False
            execution_result["command_returned"] = False
            execution_result["merge_dispatch_blocked_by_lease_guard"] = True
            if self.receipt["external_merge_observed"]:
                execution_result["verification_error"] = (
                    "external_merge_observed_after_merge_guard_block"
                )
                execution_result["post_verify_errors"] = [
                    "external_merge_observed_after_merge_guard_block"
                ]
            else:
                execution_result["verification_error"] = (
                    "merge_dispatch_blocked_by_lease_guard"
                )
                execution_result["post_verify_errors"] = [
                    "merge_dispatch_blocked_by_lease_guard"
                ]
        execution_result["merge_guard_cleanup_required"] = cleanup_required
        execution_result["merge_guard_cleanup_passed"] = cleanup_passed
        if cleanup_error is not None:
            execution_result["merge_guard_cleanup_error"] = cleanup_error
            operational_errors = list(execution_result.get("operational_errors", []))
            operational_errors.append(cleanup_error)
            execution_result["operational_errors"] = operational_errors
        self.receipt["cleanup_required"] = cleanup_required
        self.receipt["cleanup_passed"] = cleanup_passed
        if cleanup_error is not None:
            self.receipt["cleanup_error"] = cleanup_error
        receipt_material = dict(self.receipt)
        self.receipt["receipt_sha256"] = _sha256_json(receipt_material)
        execution_result["merge_lease_guard"] = self.receipt

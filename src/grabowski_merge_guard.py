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
from urllib.parse import quote, urlsplit
import weakref

import grabowski_decision_reviews as decision_reviews
from grabowski_pr_diff import (
    GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION,
    canonicalize_github_pr_diff_identity,
    github_pr_diff_identity_sha256,
)


_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")
_GITHUB_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_GITHUB_SCP_REMOTE_RE = re.compile(r"(?:[^@\s]+@)?github\.com:(?P<path>[^?#\s]+)\Z", re.IGNORECASE)
_MERGE_GUARD_TTL_SECONDS = 300
_MERGE_GUARD_MAX_CHANGED_PATHS = 3000
_MERGE_GUARD_MAX_CHANGED_PATH_BYTES = 512 * 1024
_MERGE_GUARD_MAX_SINGLE_CHANGED_PATH_BYTES = 8 * 1024
_MERGE_GUARD_GITHUB_DIFF_MAX_FILES = 300
_MERGE_GUARD_MAX_DIFF_BYTES = 32 * 1024 * 1024
_MERGE_GUARD_BINARY_DIFF_RE = re.compile(
    rb"(?m)^(?:GIT binary patch|Binary files [^\r\n]+ and [^\r\n]+ differ)\r?$"
)
_MERGE_GUARD_REPLAY_PARAMETERS = frozenset({"merge_lease_snapshot", "merge_guard_receipt"})
_CODEX_REVIEW_ACTORS = frozenset({
    "chatgpt-codex-connector",
    "chatgpt-codex-connector[bot]",
})
_CLAUDE_REVIEW_ACTORS = frozenset({
    "claude",
    "claude[bot]",
    "claude-code",
    "claude-code[bot]",
    "anthropic",
    "anthropic[bot]",
})
_TRUSTED_REVIEW_FINDING_ACTORS = _CODEX_REVIEW_ACTORS | _CLAUDE_REVIEW_ACTORS
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
      reviews(last: 100) {
        nodes {
          databaseId
          state
          submittedAt
          author { login }
          commit { oid }
        }
        pageInfo { hasPreviousPage }
      }
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
_SERVER_ACTOR_SESSIONS: weakref.WeakKeyDictionary[
    Any, tuple[weakref.ReferenceType[Any], str]
] = weakref.WeakKeyDictionary()
_SERVER_ACTOR_FALLBACK_TTL_SECONDS = 300
_SERVER_ACTOR_FALLBACK_MAX_SESSIONS = 1024


class _ServerActorFallbackSession:
    __slots__ = ("session", "session_nonce", "expires_at_monotonic")

    def __init__(
        self,
        session: Any,
        session_nonce: str,
        expires_at_monotonic: float,
    ) -> None:
        self.session = session
        self.session_nonce = session_nonce
        self.expires_at_monotonic = expires_at_monotonic


_SERVER_ACTOR_FALLBACK_SESSIONS: dict[int, _ServerActorFallbackSession] = {}
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


def _server_actor_weak_session_nonce(session: Any) -> str | None:
    """Return a nonce only when WeakKeyDictionary has object-identity semantics."""
    session_type = type(session)
    if (
        session_type.__eq__ is not object.__eq__
        or session_type.__hash__ is not object.__hash__
    ):
        return None
    try:
        entry = _SERVER_ACTOR_SESSIONS.get(session)
    except TypeError:
        return None
    if entry is not None:
        session_ref, session_nonce = entry
        return session_nonce if session_ref() is session else None
    session_nonce = secrets.token_hex(32)
    try:
        session_ref = weakref.ref(session)
        _SERVER_ACTOR_SESSIONS[session] = (session_ref, session_nonce)
    except TypeError:
        return None
    return session_nonce


def _prune_server_actor_fallback_sessions(*, now_monotonic: float) -> None:
    expired_session_ids = [
        session_id
        for session_id, entry in _SERVER_ACTOR_FALLBACK_SESSIONS.items()
        if entry.expires_at_monotonic <= now_monotonic
    ]
    for session_id in expired_session_ids:
        _SERVER_ACTOR_FALLBACK_SESSIONS.pop(session_id, None)


def _server_actor_fallback_session_nonce(
    session: Any,
    *,
    now_monotonic: float,
) -> str:
    """Return a bounded strong-reference nonce without consulting object equality."""
    session_id = id(session)
    entry = _SERVER_ACTOR_FALLBACK_SESSIONS.get(session_id)
    if entry is not None:
        if entry.session is session:
            entry.expires_at_monotonic = (
                now_monotonic + _SERVER_ACTOR_FALLBACK_TTL_SECONDS
            )
            _SERVER_ACTOR_FALLBACK_SESSIONS.pop(session_id)
            _SERVER_ACTOR_FALLBACK_SESSIONS[session_id] = entry
            return entry.session_nonce
        # The strong reference makes this unreachable under normal Python id rules.
        # If those assumptions ever change, rotate instead of aliasing the objects.
        _SERVER_ACTOR_FALLBACK_SESSIONS.pop(session_id)

    while len(_SERVER_ACTOR_FALLBACK_SESSIONS) >= _SERVER_ACTOR_FALLBACK_MAX_SESSIONS:
        oldest_session_id = next(iter(_SERVER_ACTOR_FALLBACK_SESSIONS))
        _SERVER_ACTOR_FALLBACK_SESSIONS.pop(oldest_session_id)

    session_nonce = secrets.token_hex(32)
    _SERVER_ACTOR_FALLBACK_SESSIONS[session_id] = _ServerActorFallbackSession(
        session,
        session_nonce,
        now_monotonic + _SERVER_ACTOR_FALLBACK_TTL_SECONDS,
    )
    return session_nonce


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
        now_monotonic = time.monotonic()
        _prune_server_actor_fallback_sessions(now_monotonic=now_monotonic)
        session_nonce = _server_actor_weak_session_nonce(session)
        if session_nonce is None:
            session_nonce = _server_actor_fallback_session_nonce(
                session,
                now_monotonic=now_monotonic,
            )
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


def _merge_guard_github_repository_identity(remote: str) -> str:
    if not isinstance(remote, str):
        raise RuntimeError("merge guard origin remote is not text")
    value = remote.strip()
    if not value or "\x00" in value or value != remote.strip("\r\n"):
        raise RuntimeError("merge guard origin remote is not canonical")
    path: str | None = None
    if "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"git", "http", "https", "ssh"}
            or (parsed.hostname or "").lower() != "github.com"
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError("merge guard origin remote is not a canonical GitHub URL")
        path = parsed.path
    else:
        match = _GITHUB_SCP_REMOTE_RE.fullmatch(value)
        if match is not None:
            path = match.group("path")
    if path is None:
        raise RuntimeError("merge guard origin remote does not identify GitHub owner/repository")
    identity = path.strip("/")
    if identity.endswith(".git"):
        identity = identity[:-4]
    if _GITHUB_REPOSITORY_RE.fullmatch(identity) is None:
        raise RuntimeError("merge guard origin remote owner/repository identity is invalid")
    return identity


def merge_guard_repository_identity(repo_path: Path) -> tuple[Path, str]:
    repository = merge_guard_repository_root(repo_path)
    completed = subprocess.run(
        ["git", "-C", str(repository), "remote", "get-url", "origin"],
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
        raise RuntimeError("merge guard cannot read canonical origin remote")
    return repository, _merge_guard_github_repository_identity(completed.stdout)


def resolve_captain_merge_repository(
    repo_path: Path,
    *,
    repo_slug: str,
    allow_canonical_fallback: bool,
) -> tuple[Path, str]:
    if not isinstance(repo_slug, str) or _GITHUB_REPOSITORY_RE.fullmatch(repo_slug) is None:
        raise RuntimeError("merge guard target repository slug is invalid")
    repository_name = repo_slug.split("/", 1)[1]
    canonical_candidate = (Path.home() / "repos" / repository_name).resolve()
    canonical_root: Path | None = None
    if canonical_candidate.is_dir():
        canonical_root, canonical_identity = merge_guard_repository_identity(
            canonical_candidate
        )
        if canonical_identity.casefold() != repo_slug.casefold():
            raise RuntimeError("merge guard canonical checkout origin does not match target repository")

    try:
        requested_root, requested_identity = merge_guard_repository_identity(repo_path)
    except RuntimeError:
        if allow_canonical_fallback and canonical_root is not None:
            return canonical_root, "canonical-target-fallback"
        raise
    if requested_identity.casefold() != repo_slug.casefold():
        raise RuntimeError("merge guard requested checkout origin does not match target repository")
    if canonical_root is not None and requested_root != canonical_root:
        raise RuntimeError("merge guard requested checkout is not the canonical repository common-dir")
    return requested_root, "requested-target-bound"


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


def _merge_guard_git_environment() -> dict[str, str]:
    return {
        "HOME": str(Path.home()),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }


def _merge_guard_local_git_bytes(
    repo_path: Path, args: list[str], *, timeout: int = 30
) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_path),
            "-c",
            "core.pager=cat",
            "-c",
            "diff.external=",
            "-c",
            "diff.trustExitCode=false",
            *args,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
        env=_merge_guard_git_environment(),
    )
    return {
        "returncode": completed.returncode,
        "stdout_bytes": completed.stdout,
        "stderr_bytes": completed.stderr,
    }


def _merge_guard_commit_probe(
    repo_path: Path, sha: str
) -> tuple[bool, dict[str, Any]]:
    info: dict[str, Any] = {"sha": sha}
    if not isinstance(sha, str) or _SHA40_RE.fullmatch(sha) is None:
        info["returncode"] = None
        info["valid"] = False
        return False, info
    try:
        result = _merge_guard_local_git_bytes(
            repo_path, ["cat-file", "-e", f"{sha}^{{commit}}"]
        )
    except (OSError, subprocess.SubprocessError) as exc:
        info.update({"returncode": None, "error_class": type(exc).__name__})
        return False, info
    stderr = result["stderr_bytes"]
    info.update(
        {
            "returncode": result["returncode"],
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        }
    )
    return result["returncode"] == 0, info


def _merge_guard_ensure_pr_objects(
    repo_path: Path,
    *,
    base_branch: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
) -> tuple[dict[str, Any], list[str]]:
    receipt: dict[str, Any] = {
        "source": "local-git-object-availability",
        "base_sha": base_sha,
        "head_sha": head_sha,
        "fetch_attempted": False,
    }
    if (
        not isinstance(base_branch, str)
        or not base_branch
        or "\x00" in base_branch
        or not isinstance(pr_number, int)
        or isinstance(pr_number, bool)
        or pr_number < 1
        or not isinstance(base_sha, str)
        or _SHA40_RE.fullmatch(base_sha) is None
        or not isinstance(head_sha, str)
        or _SHA40_RE.fullmatch(head_sha) is None
    ):
        return receipt, ["merge_guard_pr_object_binding_invalid"]

    base_present, base_probe = _merge_guard_commit_probe(repo_path, base_sha)
    head_present, head_probe = _merge_guard_commit_probe(repo_path, head_sha)
    receipt["before"] = {"base": base_probe, "head": head_probe}
    if base_present and head_present:
        receipt["available"] = True
        return receipt, []

    base_ref = f"refs/heads/{base_branch}"
    pr_head_ref = f"refs/pull/{pr_number}/head"
    fetch_args = [
        "-c",
        "remote.origin.uploadpack=git-upload-pack",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "protocol.file.allow=never",
        "fetch",
        "--no-tags",
        "--no-write-fetch-head",
        "--no-recurse-submodules",
        "--",
        "origin",
        base_ref,
        pr_head_ref,
    ]
    receipt["fetch_attempted"] = True
    receipt["fetch_refs"] = [base_ref, pr_head_ref]
    try:
        fetched = _merge_guard_local_git_bytes(repo_path, fetch_args, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        receipt["fetch"] = {"returncode": None, "error_class": type(exc).__name__}
        return receipt, [f"merge_guard_pr_object_fetch_exception:{type(exc).__name__}"]
    fetch_stdout = fetched["stdout_bytes"]
    fetch_stderr = fetched["stderr_bytes"]
    receipt["fetch"] = {
        "returncode": fetched["returncode"],
        "stdout_sha256": hashlib.sha256(fetch_stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(fetch_stderr).hexdigest(),
    }
    if fetched["returncode"] != 0:
        return receipt, ["merge_guard_pr_object_fetch_failed"]

    base_present, base_probe = _merge_guard_commit_probe(repo_path, base_sha)
    head_present, head_probe = _merge_guard_commit_probe(repo_path, head_sha)
    receipt["after"] = {"base": base_probe, "head": head_probe}
    receipt["available"] = base_present and head_present
    errors: list[str] = []
    if not base_present:
        errors.append("merge_guard_base_object_unavailable_after_fetch")
    if not head_present:
        errors.append("merge_guard_head_object_unavailable_after_fetch")
    return receipt, errors


def _merge_guard_diff_contains_binary_metadata(diff_bytes: bytes) -> bool:
    return _MERGE_GUARD_BINARY_DIFF_RE.search(diff_bytes) is not None


def _merge_guard_local_changed_paths(
    repo_path: Path, *, base_sha: str, head_sha: str
) -> tuple[list[str], dict[str, Any], list[str]]:
    info: dict[str, Any] = {
        "source": "local-bound-git-name-only",
        "base_sha": base_sha,
        "head_sha": head_sha,
    }
    if (
        not isinstance(base_sha, str)
        or not isinstance(head_sha, str)
        or _SHA40_RE.fullmatch(base_sha) is None
        or _SHA40_RE.fullmatch(head_sha) is None
    ):
        return [], info, ["merge_guard_local_changed_paths_revision_invalid"]
    try:
        result = _merge_guard_local_git_bytes(
            repo_path,
            [
                "diff",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                base_sha,
                head_sha,
                "--",
            ],
        )
    except (OSError, subprocess.SubprocessError) as exc:
        info["error_class"] = type(exc).__name__
        return [], info, [f"merge_guard_local_changed_paths_exception:{type(exc).__name__}"]
    stdout = result["stdout_bytes"]
    stderr = result["stderr_bytes"]
    info.update(
        {
            "returncode": result["returncode"],
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stdout_bytes": len(stdout),
        }
    )
    if result["returncode"] != 0:
        return [], info, ["merge_guard_local_changed_paths_failed"]
    if len(stdout) > _MERGE_GUARD_MAX_CHANGED_PATH_BYTES:
        return [], info, ["merge_guard_local_changed_paths_exceed_byte_limit"]
    raw_paths = stdout.split(b"\x00")
    if raw_paths and raw_paths[-1] == b"":
        raw_paths.pop()
    paths: list[str] = []
    for index, raw_path in enumerate(raw_paths):
        try:
            path = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return [], info, [f"merge_guard_local_changed_path_not_utf8:{index}"]
        if (
            not path
            or path.startswith("/")
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or len(path.encode("utf-8")) > _MERGE_GUARD_MAX_SINGLE_CHANGED_PATH_BYTES
        ):
            return [], info, [f"merge_guard_local_changed_path_invalid:{index}"]
        paths.append(path)
    if len(paths) != len(set(paths)):
        return [], info, ["merge_guard_local_changed_paths_duplicate"]
    if len(paths) > _MERGE_GUARD_MAX_CHANGED_PATHS:
        return [], info, ["merge_guard_local_changed_paths_exceed_entry_limit"]
    return sorted(paths), info, []


def _merge_guard_local_diff_bytes(
    repo_path: Path, *, base_sha: str, head_sha: str
) -> tuple[bytes, dict[str, Any], list[str]]:
    info: dict[str, Any] = {
        "source": "local-bound-git-diff",
        "base_sha": base_sha,
        "head_sha": head_sha,
    }
    if (
        not isinstance(base_sha, str)
        or not isinstance(head_sha, str)
        or _SHA40_RE.fullmatch(base_sha) is None
        or _SHA40_RE.fullmatch(head_sha) is None
    ):
        return b"", info, ["merge_guard_local_diff_revision_invalid"]
    try:
        result = _merge_guard_local_git_bytes(
            repo_path,
            [
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--no-color",
                base_sha,
                head_sha,
                "--",
            ],
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        info["error_class"] = type(exc).__name__
        return b"", info, [f"merge_guard_local_diff_exception:{type(exc).__name__}"]
    stdout = result["stdout_bytes"]
    stderr = result["stderr_bytes"]
    info.update(
        {
            "returncode": result["returncode"],
            "raw_sha256": hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "source_bytes": len(stdout),
        }
    )
    if result["returncode"] != 0:
        return b"", info, ["merge_guard_local_diff_failed"]
    if not stdout:
        return b"", info, ["merge_guard_local_diff_empty"]
    if len(stdout) > _MERGE_GUARD_MAX_DIFF_BYTES:
        return b"", info, ["merge_guard_local_diff_exceeds_byte_limit"]
    if _merge_guard_diff_contains_binary_metadata(stdout):
        return b"", info, ["merge_guard_local_diff_binary_unsupported"]
    canonical = canonicalize_github_pr_diff_identity(stdout)
    info.update(
        {
            "bytes": len(canonical),
            "sha256": hashlib.sha256(canonical).hexdigest(),
            "canonicalization": "local-bound-git-diff+" + GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION,
        }
    )
    return stdout, info, []


def _merge_guard_github_diff_too_large(
    info: dict[str, Any], *, changed_files: int
) -> bool:
    if changed_files <= _MERGE_GUARD_GITHUB_DIFF_MAX_FILES or info.get("returncode") == 0:
        return False
    message = f"{info.get('stderr', '')}\n{info.get('stdout', '')}"
    return (
        "PullRequest.diff too_large" in message
        or "diff exceeded the maximum number of files" in message
    )


def _merge_guard_github_file_records(
    repo_path: Path,
    github_runner: Any,
    *,
    repo_slug: str,
    pr_number: int,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    args = [
        "api",
        "--paginate",
        f"repos/{repo_slug}/pulls/{pr_number}/files?per_page=100",
        "--jq",
        ".[] | [.filename,.status,(.previous_filename // null)] | @json",
    ]
    try:
        raw = github_runner(repo_path, args)
    except Exception as exc:
        return [], {"command": ["gh", *args], "error_class": type(exc).__name__}, [
            f"merge_guard_live_files_exception:{type(exc).__name__}"
        ]
    info = _merge_guard_result_info(raw)
    receipt = {
        "command": ["gh", *args],
        "returncode": info["returncode"],
        "stdout_sha256": hashlib.sha256(info["stdout"].encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(info["stderr"].encode()).hexdigest(),
    }
    if info["returncode"] != 0:
        return [], receipt, ["merge_guard_live_files_failed"]
    records: list[dict[str, Any]] = []
    status_map = {
        "added": "ADDED",
        "modified": "MODIFIED",
        "removed": "DELETED",
        "renamed": "RENAMED",
        "copied": "COPIED",
    }
    for index, line in enumerate(info["stdout"].splitlines()):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return [], receipt, [f"merge_guard_live_files_invalid_json:{index}"]
        if not isinstance(item, list) or len(item) != 3:
            return [], receipt, [f"merge_guard_live_files_invalid_record:{index}"]
        path, status, previous_path = item
        mapped_status = status_map.get(status) if isinstance(status, str) else None
        record: dict[str, Any] = {"path": path, "changeType": mapped_status}
        if previous_path is not None:
            record["previousPath"] = previous_path
        records.append(record)
        if len(records) > _MERGE_GUARD_MAX_CHANGED_PATHS:
            return [], receipt, ["merge_guard_live_files_exceed_entry_limit"]
    receipt["record_count"] = len(records)
    receipt["records_sha256"] = _sha256_json(records)
    return records, receipt, []


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


def required_pr_checks_probe(
    repo_path: Path,
    github_runner: Any,
    *,
    repo_slug: str,
    pr_number: int | str,
) -> dict[str, Any]:
    args = [
        "pr",
        "checks",
        str(pr_number),
        "--repo",
        repo_slug,
        "--required",
        "--json",
        "name,state,bucket",
    ]
    value, query, query_errors = _github_json_call(
        repo_path,
        github_runner,
        args,
        label="required_pr_checks",
    )
    probe: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_required_pr_checks_probe",
        "repository": repo_slug,
        "pull_request": int(pr_number),
        "query": query,
        "status": "unavailable" if query_errors else "unknown",
        "required_check_count": None,
        "non_passing_required_check_count": None,
        "required_check_names": [],
        "errors": list(query_errors),
    }
    if query_errors:
        return probe
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        probe["status"] = "unparseable"
        probe["errors"] = ["required_pr_checks_payload_invalid"]
        return probe
    checks = [dict(item) for item in value]
    non_passing = [item for item in checks if item.get("bucket") != "pass"]
    probe["required_check_count"] = len(checks)
    probe["non_passing_required_check_count"] = len(non_passing)
    probe["required_check_names"] = sorted(
        str(item.get("name"))
        for item in checks
        if isinstance(item.get("name"), str)
    )
    if non_passing:
        probe["status"] = "not_green"
        probe["errors"] = ["required_pr_checks_not_green"]
    else:
        probe["status"] = "green"
    return probe


def _normalize_active_rule_pages(value: Any) -> tuple[list[Any] | None, int]:
    if not isinstance(value, list):
        return None, 0
    if not value:
        return [], 0
    if all(isinstance(item, dict) for item in value):
        return list(value), 1
    if not all(isinstance(page, list) for page in value):
        return None, 0
    flattened: list[Any] = []
    for page in value:
        flattened.extend(page)
    return flattened, len(value)


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
    active_args = [
        "api",
        "--method",
        "GET",
        "--paginate",
        "--slurp",
        "-f",
        f"per_page={_BASE_UPDATE_GUARD_MAX_ACTIVE_RULES}",
        f"repos/{repo_slug}/rules/branches/{encoded_branch}",
    ]
    active_payload, active_evidence, errors = _github_json_call(
        repo_path, github_runner, active_args, label="base_update_guard_active_rules"
    )
    active, active_page_count = _normalize_active_rule_pages(active_payload)
    active_evidence["page_count"] = active_page_count
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
    accepted_details: dict[int, Any] = {}
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
        accepted_details[ruleset_id] = detail
    if not accepted:
        errors.append("base_update_guard_no_unbypassable_strict_ruleset")
        errors.extend(sorted(set(rejection_codes)))
        evidence["errors"] = list(errors)
        return None, evidence, errors

    (
        active_revalidated_payload,
        active_revalidation_evidence,
        active_revalidation_errors,
    ) = _github_json_call(
        repo_path,
        github_runner,
        active_args,
        label="base_update_guard_active_rules_revalidation",
    )
    active_revalidated, active_revalidation_page_count = (
        _normalize_active_rule_pages(active_revalidated_payload)
    )
    active_revalidation_evidence["page_count"] = active_revalidation_page_count
    evidence["active_rules_revalidation"] = active_revalidation_evidence
    errors.extend(active_revalidation_errors)
    if not active_revalidation_errors and active_revalidated is None:
        errors.append("base_update_guard_active_rules_revalidation_not_list")
    elif not active_revalidation_errors and active_revalidated != active:
        errors.append("base_update_guard_active_rules_drift")

    detail_revalidation_records: list[dict[str, Any]] = []
    if not errors:
        for accepted_ruleset in accepted:
            ruleset_id = int(accepted_ruleset["ruleset_id"])
            detail_revalidated, detail_revalidation_evidence, detail_revalidation_errors = (
                _github_json_call(
                    repo_path,
                    github_runner,
                    ["api", str(candidates[ruleset_id]["endpoint"])],
                    label=f"base_update_guard_ruleset_{ruleset_id}_revalidation",
                )
            )
            record = {
                "ruleset_id": ruleset_id,
                "query": detail_revalidation_evidence,
                "errors": list(detail_revalidation_errors),
                "matches_initial_detail": False,
            }
            errors.extend(detail_revalidation_errors)
            if not detail_revalidation_errors:
                record["matches_initial_detail"] = (
                    detail_revalidated == accepted_details[ruleset_id]
                )
                if not record["matches_initial_detail"]:
                    errors.append(
                        f"base_update_guard_ruleset_detail_drift:{ruleset_id}"
                    )
            detail_revalidation_records.append(record)
    evidence["ruleset_detail_revalidation"] = detail_revalidation_records
    if errors:
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


def _github_actor_identity(value: Any) -> str:
    """Canonicalize GitHub bot aliases without weakening actor allowlisting."""
    return _github_actor(value).removesuffix("[bot]")


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
        self.action = action
        self.parameters = parameters
        self.requested_repo_path = repo_path.resolve()
        self.repository_binding_error: str | None = None
        self.repository_binding_source = "unresolved"
        try:
            self.repo_path, self.repository_binding_source = (
                resolve_captain_merge_repository(
                    self.requested_repo_path,
                    repo_slug=str(action.get("target", {}).get("repo", "")),
                    allow_canonical_fallback=not (
                        isinstance(parameters.get("local_repo"), str)
                        and bool(str(parameters.get("local_repo")).strip())
                    ),
                )
            )
        except RuntimeError as exc:
            self.repo_path = self.requested_repo_path
            self.repository_binding_error = f"{type(exc).__name__}:{exc}"
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
        self.branch_merge_policy_args: list[str] | None = None
        self.branch_merge_policy_snapshot: list[dict[str, Any]] | None = None
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
            "local_repository_binding": {
                "source": self.repository_binding_source,
                "requested_path_sha256": hashlib.sha256(
                    str(self.requested_repo_path).encode("utf-8")
                ).hexdigest(),
                "resolved_path_sha256": (
                    hashlib.sha256(str(self.repo_path).encode("utf-8")).hexdigest()
                    if self.repository_binding_error is None
                    else None
                ),
                "target_repository": str(action.get("target", {}).get("repo", "")),
                "error": self.repository_binding_error,
            },
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

    def _explicit_merge_method_requested(self) -> bool:
        target = self.action.get("target")
        return isinstance(target, dict) and isinstance(target.get("merge_method"), str)

    def _is_branch_merge_policy_query(self, args: list[str]) -> bool:
        if not self._explicit_merge_method_requested():
            return False
        target = self.action["target"]
        encoded_branch = quote(str(target.get("base", "")), safe="")
        expected = [
            "api",
            "--method",
            "GET",
            "--paginate",
            "--slurp",
            "-f",
            "per_page=100",
            f"repos/{target.get('repo', '')}/rules/branches/{encoded_branch}",
        ]
        return args == expected

    def _branch_merge_policy_snapshot_info(
        self,
        result: Any,
        *,
        command: list[str],
    ) -> tuple[list[dict[str, Any]] | None, dict[str, Any], list[str]]:
        info = _merge_guard_result_info(result)
        evidence = {
            "command": ["gh", *command],
            "returncode": info["returncode"],
            "stdout_sha256": hashlib.sha256(info["stdout"].encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(info["stderr"].encode("utf-8")).hexdigest(),
        }
        errors: list[str] = []
        if info["returncode"] != 0:
            errors.append("merge_guard_branch_merge_policy_query_failed")
            return None, evidence, errors
        try:
            raw = json.loads(info["stdout"])
        except json.JSONDecodeError:
            errors.append("merge_guard_branch_merge_policy_invalid_json")
            return None, evidence, errors
        if not isinstance(raw, list):
            errors.append("merge_guard_branch_merge_policy_invalid_shape")
            return None, evidence, errors
        if raw and all(isinstance(item, dict) for item in raw):
            rules = list(raw)
        elif all(isinstance(page, list) for page in raw):
            rules = [item for page in raw for item in page]
        else:
            errors.append("merge_guard_branch_merge_policy_invalid_pages")
            return None, evidence, errors
        if len(rules) > 1000 or any(not isinstance(rule, dict) for rule in rules):
            errors.append("merge_guard_branch_merge_policy_invalid_rules")
            return None, evidence, errors

        supported_methods = {"merge", "squash", "rebase"}
        projected_rules: list[dict[str, Any]] = []
        for rule in rules:
            rule_type = rule.get("type")
            if rule_type == "pull_request":
                parameters = rule.get("parameters")
                methods = (
                    parameters.get("allowed_merge_methods")
                    if isinstance(parameters, dict)
                    else None
                )
                if (
                    not isinstance(methods, list)
                    or not methods
                    or any(
                        not isinstance(method, str)
                        or method not in supported_methods
                        for method in methods
                    )
                ):
                    errors.append(
                        "merge_guard_branch_merge_policy_allowed_methods_invalid"
                    )
                    return None, evidence, errors
                projected_rules.append(
                    {
                        "type": "pull_request",
                        "allowed_merge_methods": sorted(set(methods)),
                    }
                )
            elif rule_type == "merge_queue":
                parameters = rule.get("parameters")
                merge_method = (
                    parameters.get("merge_method")
                    if isinstance(parameters, dict)
                    else None
                )
                normalized_method = (
                    merge_method.lower() if isinstance(merge_method, str) else None
                )
                if normalized_method not in supported_methods:
                    errors.append(
                        "merge_guard_branch_merge_policy_queue_method_invalid"
                    )
                    return None, evidence, errors
                projected_rules.append(
                    {
                        "type": "merge_queue",
                        "merge_method": normalized_method,
                    }
                )

        snapshot = sorted(projected_rules, key=_canonical_json)
        evidence["active_rule_count"] = len(rules)
        evidence["merge_policy_rule_count"] = len(snapshot)
        evidence["merge_policy_sha256"] = _sha256_json(snapshot)
        return snapshot, evidence, errors

    def _capture_branch_merge_policy_snapshot(
        self,
        args: list[str],
        result: Any,
    ) -> None:
        snapshot, evidence, errors = self._branch_merge_policy_snapshot_info(
            result, command=args
        )
        evidence["errors"] = list(errors)
        self.receipt["branch_merge_policy_snapshot"] = evidence
        self.branch_merge_policy_args = list(args)
        self.branch_merge_policy_snapshot = snapshot

    def _revalidate_branch_merge_policy(self) -> list[str]:
        if not self._explicit_merge_method_requested():
            return []
        if (
            self.branch_merge_policy_args is None
            or self.branch_merge_policy_snapshot is None
        ):
            errors = ["merge_guard_branch_merge_policy_snapshot_missing"]
            self.receipt["branch_merge_policy_revalidation"] = {"errors": errors}
            return errors
        try:
            raw = self.github_runner(
                self.repo_path, list(self.branch_merge_policy_args)
            )
        except Exception as exc:
            errors = [
                f"merge_guard_branch_merge_policy_revalidation_exception:{type(exc).__name__}"
            ]
            self.receipt["branch_merge_policy_revalidation"] = {
                "command": ["gh", *self.branch_merge_policy_args],
                "errors": errors,
            }
            return errors
        snapshot, evidence, errors = self._branch_merge_policy_snapshot_info(
            raw, command=self.branch_merge_policy_args
        )
        evidence["initial_rules_sha256"] = _sha256_json(
            self.branch_merge_policy_snapshot
        )
        if not errors and snapshot != self.branch_merge_policy_snapshot:
            errors.append("merge_guard_branch_merge_policy_drift")
        evidence["matched"] = not errors
        evidence["errors"] = list(errors)
        self.receipt["branch_merge_policy_revalidation"] = evidence
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

    def _review_thread_sets(
        self,
        threads_payload: Any,
        *,
        head_sha: str,
        errors: list[str],
    ) -> dict[str, Any]:
        trusted_thread_ids: list[str] = []
        unresolved_trusted_thread_ids: list[str] = []
        codex_current_thread_ids: list[str] = []
        unresolved_codex_current_thread_ids: list[str] = []
        trusted_actors: set[str] = set()
        trusted_comments: list[dict[str, Any]] = []
        trusted_reviews: list[dict[str, Any]] = []
        outstanding_review_ids: list[int] = []
        if not isinstance(threads_payload, dict):
            errors.append("merge_guard_review_findings_payload_invalid")
            return {
                "trusted_thread_ids": [],
                "unresolved_trusted_thread_ids": [],
                "codex_current_thread_ids": [],
                "unresolved_codex_current_thread_ids": [],
                "trusted_actors": [],
                "trusted_comments": [],
                "trusted_reviews": [],
                "outstanding_review_ids": [],
            }
        try:
            pull_request = threads_payload["data"]["repository"]["pullRequest"]
        except (KeyError, TypeError):
            pull_request = None
        if not isinstance(pull_request, dict):
            errors.append("merge_guard_review_findings_pull_request_shape_invalid")
            return {
                "trusted_thread_ids": [],
                "unresolved_trusted_thread_ids": [],
                "codex_current_thread_ids": [],
                "unresolved_codex_current_thread_ids": [],
                "trusted_actors": [],
                "trusted_comments": [],
                "trusted_reviews": [],
                "outstanding_review_ids": [],
            }

        reviews_connection = pull_request.get("reviews")
        if not isinstance(reviews_connection, dict):
            errors.append("merge_guard_review_findings_reviews_shape_invalid")
        else:
            review_page = reviews_connection.get("pageInfo")
            review_nodes = reviews_connection.get("nodes")
            if (
                not isinstance(review_page, dict)
                or review_page.get("hasPreviousPage") is not False
            ):
                errors.append("merge_guard_review_findings_reviews_truncated")
            if not isinstance(review_nodes, list):
                errors.append("merge_guard_review_findings_reviews_nodes_invalid")
            else:
                for item in review_nodes:
                    if not isinstance(item, dict):
                        errors.append("merge_guard_review_finding_review_invalid")
                        continue
                    actor = _github_actor(item.get("author"))
                    if actor not in _TRUSTED_REVIEW_FINDING_ACTORS:
                        continue
                    state = str(item.get("state") or "").upper()
                    if state not in {"CHANGES_REQUESTED", "APPROVED"}:
                        continue
                    review_id = item.get("databaseId")
                    submitted = _github_datetime(item.get("submittedAt"))
                    commit = item.get("commit")
                    commit_sha = commit.get("oid") if isinstance(commit, dict) else None
                    if (
                        isinstance(review_id, bool)
                        or not isinstance(review_id, int)
                        or review_id <= 0
                    ):
                        errors.append("merge_guard_review_finding_review_id_invalid")
                        continue
                    if submitted is None:
                        if state == "CHANGES_REQUESTED":
                            errors.append(
                                "merge_guard_review_finding_review_time_invalid"
                            )
                        continue
                    trusted_actors.add(actor)
                    trusted_reviews.append(
                        {
                            "id": review_id,
                            "actor": actor,
                            "actor_key": actor.removesuffix("[bot]"),
                            "state": state,
                            "submitted": submitted,
                            "commit_sha": commit_sha,
                        }
                    )
        trusted_reviews.sort(key=lambda item: (item["submitted"], item["id"]))
        reviews_by_actor: dict[str, list[dict[str, Any]]] = {}
        for item in trusted_reviews:
            reviews_by_actor.setdefault(str(item["actor_key"]), []).append(item)
        for actor_reviews in reviews_by_actor.values():
            blockers = [
                item for item in actor_reviews if item["state"] == "CHANGES_REQUESTED"
            ]
            if not blockers:
                continue
            latest_blocker = blockers[-1]
            if not any(
                item["state"] == "APPROVED"
                and item.get("commit_sha") == head_sha
                and (item["submitted"], item["id"])
                > (latest_blocker["submitted"], latest_blocker["id"])
                for item in actor_reviews
            ):
                outstanding_review_ids.append(int(latest_blocker["id"]))

        connection = pull_request.get("reviewThreads")
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
                    if not isinstance(comment_nodes, list) or not comment_nodes:
                        errors.append(
                            f"merge_guard_codex_thread_comments_invalid:{thread_id}"
                        )
                        continue
                    root = comment_nodes[0]
                    trusted_root = False
                    if isinstance(root, dict):
                        root_actor = _github_actor(root.get("author"))
                        trusted_root = root_actor in _TRUSTED_REVIEW_FINDING_ACTORS
                        if trusted_root:
                            trusted_actors.add(root_actor)
                    if trusted_root:
                        trusted_thread_ids.append(thread_id)
                        unresolved = thread.get("isResolved") is not True
                        if unresolved:
                            unresolved_trusted_thread_ids.append(thread_id)
                        root_id = root.get("databaseId") if isinstance(root, dict) else None
                        root_created = (
                            _github_datetime(root.get("createdAt"))
                            if isinstance(root, dict)
                            else None
                        )
                        root_commit = root.get("commit") if isinstance(root, dict) else None
                        root_commit_sha = (
                            root_commit.get("oid")
                            if isinstance(root_commit, dict)
                            else None
                        )
                        if (
                            isinstance(root_id, int)
                            and not isinstance(root_id, bool)
                            and root_id > 0
                            and root_created is not None
                        ):
                            trusted_comments.append(
                                {
                                    "thread_id": thread_id,
                                    "comment_id": root_id,
                                    "actor": _github_actor(root.get("author")),
                                    "commit_sha": root_commit_sha,
                                }
                            )
                        elif unresolved:
                            if (
                                isinstance(root_id, bool)
                                or not isinstance(root_id, int)
                                or root_id <= 0
                            ):
                                errors.append(
                                    f"merge_guard_review_finding_comment_id_invalid:{thread_id}"
                                )
                            if root_created is None:
                                errors.append(
                                    f"merge_guard_review_finding_created_at_invalid:{thread_id}"
                                )
                    codex_current_match = False
                    for comment in comment_nodes:
                        if not isinstance(comment, dict):
                            continue
                        actor = _github_actor(comment.get("author"))
                        commit = comment.get("commit")
                        commit_sha = commit.get("oid") if isinstance(commit, dict) else None
                        created = _github_datetime(comment.get("createdAt"))
                        if (
                            actor in _CODEX_REVIEW_ACTORS
                            and commit_sha == head_sha
                            and created is not None
                        ):
                            codex_current_match = True
                    if codex_current_match:
                        codex_current_thread_ids.append(thread_id)
                        if thread.get("isResolved") is not True:
                            unresolved_codex_current_thread_ids.append(thread_id)
        trusted_comments.sort(
            key=lambda item: (item["thread_id"], item["comment_id"], item["actor"])
        )
        trusted_review_receipts = [
            {
                "id": item["id"],
                "actor": item["actor"],
                "state": item["state"],
                "submitted_at": item["submitted"].isoformat(),
                "commit_sha": item["commit_sha"],
            }
            for item in trusted_reviews
        ]
        return {
            "trusted_thread_ids": sorted(set(trusted_thread_ids)),
            "unresolved_trusted_thread_ids": sorted(
                set(unresolved_trusted_thread_ids)
            ),
            "codex_current_thread_ids": sorted(set(codex_current_thread_ids)),
            "unresolved_codex_current_thread_ids": sorted(
                set(unresolved_codex_current_thread_ids)
            ),
            "trusted_actors": sorted(trusted_actors),
            "trusted_comments": trusted_comments,
            "trusted_reviews": trusted_review_receipts,
            "outstanding_review_ids": sorted(set(outstanding_review_ids)),
        }

    def _query_review_thread_sets(
        self,
        bindings: dict[str, Any],
        *,
        observations: list[dict[str, Any]],
        errors: list[str],
    ) -> dict[str, Any]:
        repository = str(bindings.get("repository", "")).lower()
        pr_number = int(bindings.get("pull_request", 0))
        head_sha = str(bindings.get("head_sha", ""))
        owner, separator, name = repository.partition("/")
        if not owner or separator != "/" or not name:
            errors.append("merge_guard_review_findings_repository_invalid")
            return self._review_thread_sets(None, head_sha=head_sha, errors=errors)
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
        return self._review_thread_sets(
            threads_payload,
            head_sha=head_sha,
            errors=errors,
        )

    def _apply_existing_review_finding_debt(
        self,
        receipt: dict[str, Any],
        thread_sets: dict[str, Any],
        errors: list[str],
    ) -> None:
        trusted_thread_ids = list(thread_sets["trusted_thread_ids"])
        unresolved = list(thread_sets["unresolved_trusted_thread_ids"])
        trusted_comments = list(thread_sets["trusted_comments"])
        trusted_reviews = list(thread_sets["trusted_reviews"])
        outstanding_review_ids = list(thread_sets["outstanding_review_ids"])
        blocked = bool(unresolved or outstanding_review_ids)
        receipt["existing_review_findings"] = {
            "trusted_actors": list(thread_sets["trusted_actors"]),
            "thread_count": len(trusted_thread_ids),
            "thread_ids_sha256": _sha256_json(trusted_thread_ids),
            "comment_count": len(trusted_comments),
            "comments_sha256": _sha256_json(trusted_comments),
            "unresolved_thread_count": len(unresolved),
            "unresolved_thread_ids_sha256": _sha256_json(unresolved),
            "review_count": len(trusted_reviews),
            "reviews_sha256": _sha256_json(trusted_reviews),
            "outstanding_review_count": len(outstanding_review_ids),
            "outstanding_review_ids_sha256": _sha256_json(
                outstanding_review_ids
            ),
            "status": "blocked" if blocked else "clear",
        }
        if unresolved:
            errors.append("merge_guard_review_findings_unresolved_threads_present")
        if outstanding_review_ids:
            errors.append("merge_guard_review_findings_changes_requested_present")

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
        explicit_required = self.parameters.get("codex_review_required")
        policy_required = (
            isinstance(review_evidence, dict)
            and review_evidence.get("external_review_required") is True
        )
        required = policy_required or explicit_required is True
        evidence = self.parameters.get("codex_review_evidence")
        exception = self.parameters.get("codex_review_exception")
        receipt_key = f"{phase}_codex_review_revalidation"
        receipt: dict[str, Any] = {
            "required": required,
            "review_tier": review_tier,
            "external_review_required": policy_required,
            "explicitly_required": explicit_required is True,
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
        if explicit_required is not None and not isinstance(explicit_required, bool):
            errors.append("merge_guard_codex_required_invalid")
            receipt["status"] = "blocked"
            return errors
        if evidence is not None and exception is not None:
            errors.append("merge_guard_codex_evidence_exception_ambiguous")
            receipt["status"] = "blocked"
            return errors
        if not required and exception is None:
            thread_sets = self._query_review_thread_sets(
                bindings,
                observations=observations,
                errors=errors,
            )
            self._apply_existing_review_finding_debt(receipt, thread_sets, errors)
            diagnostic_present = evidence is not None
            receipt["status"] = "blocked" if errors else "not_required"
            receipt["diagnostic_evidence_present"] = diagnostic_present
            receipt["diagnostic_evidence_ignored_for_authority"] = diagnostic_present
            return errors
        if exception is not None:
            thread_sets = self._query_review_thread_sets(
                bindings,
                observations=observations,
                errors=errors,
            )
            self._apply_existing_review_finding_debt(receipt, thread_sets, errors)
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
                if exception.get("base_sha") != bindings.get("base_sha"):
                    errors.append("merge_guard_codex_exception_base_drift")
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
            errors.append("merge_guard_codex_evidence_missing")
            receipt["status"] = "blocked"
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
            "base_sha": base_sha,
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
                    if _github_actor_identity(actor) != _github_actor_identity(
                        completion.get("actor")
                    ):
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
                    if _github_actor_identity(actor) != _github_actor_identity(
                        completion.get("actor")
                    ):
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

        thread_sets = self._query_review_thread_sets(
            bindings,
            observations=observations,
            errors=errors,
        )
        self._apply_existing_review_finding_debt(receipt, thread_sets, errors)
        thread_ids = list(thread_sets["codex_current_thread_ids"])
        unresolved_thread_ids = list(
            thread_sets["unresolved_codex_current_thread_ids"]
        )
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
        if self.repository_binding_error is not None:
            errors.append("merge_guard_local_repository_binding_invalid")
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
        merge_state_status = viewed.get("mergeStateStatus")
        if merge_state_status == "UNSTABLE":
            required_checks = required_pr_checks_probe(
                self.repo_path,
                self.github_runner,
                repo_slug=repo_slug,
                pr_number=pr_number,
            )
            self.receipt["required_checks_probe"] = required_checks
            if required_checks.get("status") != "green":
                errors.append("merge_guard_required_checks_not_green_for_unstable_merge_state")
        elif merge_state_status != "CLEAN":
            errors.append("merge_guard_merge_state_not_clean")

        changed_files = viewed.get("changedFiles")
        raw_files = viewed.get("files")
        changed_paths: list[str] = []
        if type(changed_files) is not int or changed_files < 1:
            errors.append("merge_guard_changed_file_count_invalid")
        elif changed_files > _MERGE_GUARD_MAX_CHANGED_PATHS:
            errors.append("merge_guard_changed_file_count_exceeds_supported_limit")
        if (
            type(changed_files) is int
            and 100 < changed_files <= _MERGE_GUARD_MAX_CHANGED_PATHS
        ):
            complete_files, files_receipt, files_errors = _merge_guard_github_file_records(
                self.repo_path,
                self.github_runner,
                repo_slug=repo_slug,
                pr_number=pr_number,
            )
            self.receipt["live_files"] = files_receipt
            errors.extend(files_errors)
            if not files_errors:
                raw_files = complete_files
            else:
                errors.append("merge_guard_changed_file_count_exceeds_supported_limit")
                if isinstance(raw_files, list) and len(raw_files) > 128:
                    errors.append("merge_guard_changed_path_count_exceeds_limit")
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
            if type(changed_files) is int and changed_files != len(raw_files):
                errors.append("merge_guard_changed_file_list_incomplete")
            if len(raw_files) > _MERGE_GUARD_MAX_CHANGED_PATHS:
                errors.append("merge_guard_changed_path_count_exceeds_limit")
            if len(changed_paths) != len(set(changed_paths)):
                errors.append("merge_guard_changed_paths_duplicate")
        changed_paths = sorted(set(changed_paths))
        if not changed_paths:
            errors.append("merge_guard_changed_paths_empty")
        elif (
            any(
                len(path.encode("utf-8")) > _MERGE_GUARD_MAX_SINGLE_CHANGED_PATH_BYTES
                for path in changed_paths
            )
            or len(_canonical_json(changed_paths).encode("utf-8"))
            > _MERGE_GUARD_MAX_CHANGED_PATH_BYTES
        ):
            errors.append("merge_guard_changed_paths_exceed_byte_limit")

        diff_args = ["pr", "diff", str(pr_number), "--repo", repo_slug]
        try:
            diff_raw = self.github_runner(self.repo_path, diff_args)
        except Exception as exc:
            errors.append(f"merge_guard_live_diff_exception:{type(exc).__name__}")
            return None, errors
        diff_info = _merge_guard_result_info(diff_raw)
        provider_stdout_bytes = (
            diff_info["stdout_bytes"]
            if isinstance(diff_info.get("stdout_bytes"), bytes)
            else diff_info["stdout"].encode("utf-8")
        )
        provider_attempt = {
            "command": ["gh", *diff_args],
            "returncode": diff_info["returncode"],
            "stdout_sha256": hashlib.sha256(provider_stdout_bytes).hexdigest(),
            "stderr_sha256": hashlib.sha256(diff_info["stderr"].encode()).hexdigest(),
            "source_bytes": len(provider_stdout_bytes),
        }
        raw_live_diff_bytes = provider_stdout_bytes
        diff_source = (
            "raw-command-bytes"
            if isinstance(diff_info.get("stdout_bytes"), bytes)
            else "utf8-runner-text-exact-fallback"
        )
        selected_diff_returncode = diff_info["returncode"]
        if type(changed_files) is int and _merge_guard_github_diff_too_large(
            diff_info, changed_files=changed_files
        ):
            object_receipt, object_errors = _merge_guard_ensure_pr_objects(
                self.repo_path,
                base_branch=expected_base,
                pr_number=pr_number,
                base_sha=base_sha,
                head_sha=expected_head,
            )
            self.receipt["local_object_fallback"] = object_receipt
            errors.extend(object_errors)
            local_paths: list[str] = []
            local_paths_info: dict[str, Any] = {"skipped": bool(object_errors)}
            local_path_errors: list[str] = []
            if not object_errors:
                local_paths, local_paths_info, local_path_errors = (
                    _merge_guard_local_changed_paths(
                        self.repo_path, base_sha=base_sha, head_sha=expected_head
                    )
                )
            self.receipt["local_changed_paths_fallback"] = local_paths_info
            errors.extend(local_path_errors)
            if not local_path_errors and local_paths != changed_paths:
                errors.append("merge_guard_local_changed_paths_drift")
            if not local_path_errors and local_paths == changed_paths:
                local_diff, local_diff_info, local_diff_errors = _merge_guard_local_diff_bytes(
                    self.repo_path, base_sha=base_sha, head_sha=expected_head
                )
                self.receipt["local_diff_fallback"] = local_diff_info
                errors.extend(local_diff_errors)
                if not local_diff_errors:
                    raw_live_diff_bytes = local_diff
                    diff_source = "local-bound-git-diff-after-github-too-large"
                    selected_diff_returncode = 0
        live_diff_bytes = canonicalize_github_pr_diff_identity(raw_live_diff_bytes)
        live_diff_sha256 = github_pr_diff_identity_sha256(raw_live_diff_bytes)
        diff_canonicalization = diff_source
        if live_diff_bytes != raw_live_diff_bytes:
            diff_canonicalization += "+" + GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION
        self.receipt["live_diff"] = {
            "command": ["gh", *diff_args],
            "returncode": selected_diff_returncode,
            "provider_attempt": provider_attempt,
            "source": diff_source,
            "source_bytes": len(raw_live_diff_bytes),
            "bytes": len(live_diff_bytes),
            "canonicalization": diff_canonicalization,
            "raw_sha256": hashlib.sha256(raw_live_diff_bytes).hexdigest(),
            "sha256": live_diff_sha256,
            "stderr_sha256": hashlib.sha256(diff_info["stderr"].encode()).hexdigest(),
        }
        if selected_diff_returncode != 0:
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
            "merge_state_status": merge_state_status,
            "diff_sha256": live_diff_sha256,
            "execution_intent_sha256": self.execution_intent_sha256,
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
        }
        for field, expected_value in expected.items():
            if viewed.get(field) != expected_value:
                errors.append(f"merge_guard_dispatch_revalidation_drift:{field}")
        dispatch_merge_state = viewed.get("mergeStateStatus")
        if dispatch_merge_state == "UNSTABLE":
            required_checks = required_pr_checks_probe(
                self.repo_path,
                self.github_runner,
                repo_slug=str(bindings["repository"]),
                pr_number=int(bindings["pull_request"]),
            )
            self.receipt["dispatch_required_checks_probe"] = required_checks
            if required_checks.get("status") != "green":
                errors.append(
                    "merge_guard_dispatch_required_checks_not_green_for_unstable_merge_state"
                )
        elif dispatch_merge_state != "CLEAN":
            errors.append("merge_guard_dispatch_revalidation_drift:mergeStateStatus")
        self.receipt["dispatch_revalidation"]["errors"] = list(errors)
        self.receipt["dispatch_revalidation"]["binding_sha256"] = _sha256_json(
            {
                **{field: viewed.get(field) for field in sorted(expected)},
                "mergeStateStatus": dispatch_merge_state,
            }
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
            elif (
                self.branch_merge_policy_args is None
                and self._is_branch_merge_policy_query(args)
            ):
                self._capture_branch_merge_policy_snapshot(args, result)
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
        metadata_bindings = {
            key: value for key, value in bindings.items() if key != "changed_paths"
        }
        metadata = {
            "merge_guard": {
                **metadata_bindings,
                "changed_path_count": len(bindings["changed_paths"]),
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
        operation_nonconflicts = list(
            self.acquisition.get("operation_nonconflicts", [])
        )
        operation_nonconflicts_sha256 = self.acquisition.get(
            "operation_nonconflicts_sha256"
        )
        if operation_nonconflicts_sha256 != _sha256_json(operation_nonconflicts):
            raise RuntimeError("merge lease guard operation non-conflict evidence drift")
        lease_snapshot = {
            "observed_leases": self.acquisition["observed_leases"],
            "operation_nonconflicts": operation_nonconflicts,
            "operation_nonconflicts_sha256": operation_nonconflicts_sha256,
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
                "operation_nonconflicts": operation_nonconflicts,
                "operation_nonconflicts_sha256": operation_nonconflicts_sha256,
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
        decision_binding = {
            "schema_version": decision_reviews.BINDING_SCHEMA_VERSION,
            "kind": decision_reviews.BINDING_KIND,
            "repo": str(bindings["repository"]),
            "pr": int(bindings["pull_request"]),
            "head_sha": str(bindings["head_sha"]),
            "base_sha": str(bindings["base_sha"]),
            "diff_sha256": str(bindings["diff_sha256"]),
            "slot": "merge-guard-lock",
        }
        # The same per-PR/head lock is taken by grabowski_job_start whenever a
        # reviewer is declared decision-bound.  Holding it through the final
        # live revalidation and GitHub merge dispatch closes the registration
        # TOCTOU: a reviewer cannot become decision-bound between reconciliation
        # and the merge call and then be omitted from this decision.
        with decision_reviews.decision_review_lock(decision_binding):
            decision_reconciliation = decision_reviews.reconcile(
                repo=str(bindings["repository"]),
                pr=int(bindings["pull_request"]),
                head_sha=str(bindings["head_sha"]),
                base_sha=str(bindings["base_sha"]),
                diff_sha256=str(bindings["diff_sha256"]),
            )
            self.receipt["decision_bound_review_reconciliation"] = (
                decision_reconciliation
            )
            revalidation_errors = list(decision_reconciliation.get("errors", []))
            revalidation_errors.extend(self._revalidate_dispatch_bindings(bindings))
            revalidation_errors.extend(self._revalidate_repository_policy())
            revalidation_errors.extend(self._revalidate_branch_merge_policy())
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
            reconciliation = {
                "schema_version": 1,
                "kind": "grabowski_external_merge_reconciliation",
                "external_merge_observed": True,
                "dispatch_called": self.dispatch_called,
                "duplicate_dispatch_prevented": not self.dispatch_called,
                "does_not_establish": [
                    "identity_of_external_merger",
                    "review_or_ci_completeness",
                    "absence_of_external_side_effects",
                ],
            }
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

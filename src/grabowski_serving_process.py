"""Bind runtime identity to the process that actually serves a call.

``grabowski_deployment_identity`` reads the deployment manifest from disk. A
long-lived MCP server process keeps the code it imported at start, so the two
can diverge without any field showing it: the manifest advertises a new release
while the serving process still answers from the code of an older one.

This module freezes the release identity observed when the process loaded its
code and compares it against the manifest read at call time. A positive
mismatch means the serving process predates the deployed release; its tool
surface and its gates are those of the older code regardless of what the
manifest claims.

Blue-green cutover extensions:

- A process may be closed for new mutations after connector cutover while
  already-admitted reads are allowed to drain.
- Only effect-bearing (mutating) calls are tracked for terminalization before
  retirement. Long-lived reads never block retirement.
- ``is_stale`` continues to mean identity mismatch or closed-for-mutations so
  the existing operator mutation gate refuses post-cutover work without a
  separate operator edit.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from typing import Any


SCHEMA_VERSION = 1
KIND = "grabowski_serving_process_identity"
CALL_KIND_EFFECT_BEARING = "effect_bearing"
CALL_KIND_READ = "read"
CALL_KINDS = frozenset({CALL_KIND_EFFECT_BEARING, CALL_KIND_READ})
ROLE_ACTIVE = "active"
ROLE_STANDBY = "standby"
ROLE_RETIRING = "retiring"
ROLES = frozenset({ROLE_ACTIVE, ROLE_STANDBY, ROLE_RETIRING})
_MAX_ACTIVE_CALLS = 4_096
_MAX_TOOL_NAME_CHARS = 128

_HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")

_PROCESS_STARTED_AT_UNIX = int(time.time())
_frozen: dict[str, str] | None = None
_frozen_attempted = False
_mutations_closed = False
_mutations_closed_reason: str | None = None
_mutations_closed_at_unix: int | None = None
_role = ROLE_ACTIVE
_call_lock = threading.Lock()
_active_calls: dict[str, dict[str, Any]] = {}
_terminalized_effect_calls: dict[str, dict[str, Any]] = {}


def _valid_release_id(value: Any) -> str | None:
    if not isinstance(value, str) or not value or value.strip() != value:
        return None
    return value if len(value) <= 512 else None


def _valid_repo_head(value: Any) -> str | None:
    if not isinstance(value, str) or _HEAD_RE.fullmatch(value) is None:
        return None
    return value


def freeze(release_id: Any, repo_head: Any) -> None:
    """Record the release identity this process loaded its code under.

    Only the first successful call takes effect, so a later manifest change
    cannot rewrite what this process actually started with.
    """
    global _frozen, _frozen_attempted
    _frozen_attempted = True
    if _frozen is not None:
        return
    release = _valid_release_id(release_id)
    head = _valid_repo_head(repo_head)
    if release is None or head is None:
        return
    _frozen = {"release_id": release, "repo_head": head}


def set_role(role: str) -> None:
    """Set the blue-green role of this serving process."""
    global _role
    if role not in ROLES:
        raise ValueError(f"unknown serving process role: {role!r}")
    _role = role


def role() -> str:
    return _role


def close_for_mutations(*, reason: str = "blue-green-cutover") -> dict[str, Any]:
    """Refuse new mutations while allowing admitted reads to continue.

    This is the post-cutover blue-runtime state: the connector already points
    at green, so this process must not accept new effect-bearing work.
    """
    global _mutations_closed, _mutations_closed_reason, _mutations_closed_at_unix, _role
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
        raise ValueError("mutations-closed reason must be a bounded non-empty string")
    closed_at = int(time.time())
    _mutations_closed = True
    _mutations_closed_reason = reason.strip()
    _mutations_closed_at_unix = closed_at
    if _role == ROLE_ACTIVE:
        _role = ROLE_RETIRING
    return {
        "mutations_closed": True,
        "reason": _mutations_closed_reason,
        "closed_at_unix": closed_at,
        "role": _role,
    }


def mutations_closed() -> bool:
    return _mutations_closed


def mutations_closed_state() -> dict[str, Any]:
    return {
        "mutations_closed": _mutations_closed,
        "reason": _mutations_closed_reason,
        "closed_at_unix": _mutations_closed_at_unix,
        "role": _role,
    }


def register_call(tool_name: Any, kind: str) -> str:
    """Register one in-flight call for cutover accounting.

    Only ``effect_bearing`` identities participate in retirement terminalization.
    Read identities are diagnostic and never block cutover completion.
    """
    if kind not in CALL_KINDS:
        raise ValueError(f"unknown serving call kind: {kind!r}")
    name = tool_name if isinstance(tool_name, str) and tool_name else "unnamed"
    name = name[:_MAX_TOOL_NAME_CHARS]
    with _call_lock:
        if len(_active_calls) >= _MAX_ACTIVE_CALLS:
            raise RuntimeError("serving process active-call registry is full")
        if _mutations_closed and kind == CALL_KIND_EFFECT_BEARING:
            raise RuntimeError(
                "serving process rejects new effect-bearing calls after "
                f"mutations were closed ({_mutations_closed_reason})"
            )
        identity_value = uuid.uuid4().hex
        while identity_value in _active_calls:
            identity_value = uuid.uuid4().hex
        _active_calls[identity_value] = {
            "identity": identity_value,
            "tool_name": name,
            "kind": kind,
            "started_at_unix": time.time(),
            "started_monotonic": time.monotonic(),
            "terminalized": False,
        }
        return identity_value


def release_call(identity_value: Any) -> bool:
    if not isinstance(identity_value, str) or not identity_value:
        return False
    with _call_lock:
        return _active_calls.pop(identity_value, None) is not None


def active_calls(*, kind: str | None = None) -> list[dict[str, Any]]:
    with _call_lock:
        items = [dict(entry) for entry in _active_calls.values()]
    if kind is not None:
        if kind not in CALL_KINDS:
            raise ValueError(f"unknown serving call kind: {kind!r}")
        items = [entry for entry in items if entry["kind"] == kind]
    items.sort(key=lambda entry: entry["started_monotonic"])
    return items


def active_effect_bearing_calls() -> list[dict[str, Any]]:
    return active_calls(kind=CALL_KIND_EFFECT_BEARING)


def active_read_calls() -> list[dict[str, Any]]:
    return active_calls(kind=CALL_KIND_READ)


def terminalize_effect_bearing_calls() -> dict[str, Any]:
    """Terminalize every active effect-bearing call without waiting on reads.

    Long-lived reads remain registered until they complete naturally. Retirement
    therefore never depends on a global drain of all tool calls.
    """
    now = time.time()
    terminalized: list[dict[str, Any]] = []
    remaining_reads: list[dict[str, Any]] = []
    with _call_lock:
        remaining: dict[str, dict[str, Any]] = {}
        for identity_value, entry in _active_calls.items():
            if entry["kind"] == CALL_KIND_EFFECT_BEARING:
                closed = {
                    **entry,
                    "terminalized": True,
                    "terminalized_at_unix": now,
                }
                _terminalized_effect_calls[identity_value] = closed
                terminalized.append(dict(closed))
            else:
                remaining[identity_value] = entry
                remaining_reads.append(dict(entry))
        _active_calls.clear()
        _active_calls.update(remaining)
    terminalized.sort(key=lambda entry: entry["started_monotonic"])
    remaining_reads.sort(key=lambda entry: entry["started_monotonic"])
    return {
        "schema_version": 1,
        "kind": "grabowski_serving_process_effect_terminalization",
        "terminalized_count": len(terminalized),
        "terminalized_effect_bearing_calls": terminalized,
        "remaining_read_count": len(remaining_reads),
        "remaining_read_calls": remaining_reads,
        "mutations_closed": _mutations_closed,
        "does_not_establish": [
            "that read calls have finished",
            "application-level success of terminalized mutations",
            "global admission-drain emptiness",
        ],
    }


def reset_for_tests() -> None:
    """Clear frozen identity and cutover state so tests can exercise both branches."""
    global _frozen, _frozen_attempted
    global _mutations_closed, _mutations_closed_reason, _mutations_closed_at_unix, _role
    _frozen = None
    _frozen_attempted = False
    _mutations_closed = False
    _mutations_closed_reason = None
    _mutations_closed_at_unix = None
    _role = ROLE_ACTIVE
    with _call_lock:
        _active_calls.clear()
        _terminalized_effect_calls.clear()


def identity(
    current_release_id: Any = None, current_repo_head: Any = None
) -> dict[str, Any]:
    """Project the serving process identity against the deployed manifest."""
    current_release = _valid_release_id(current_release_id)
    current_head = _valid_repo_head(current_repo_head)
    process_known = _frozen is not None
    manifest_known = current_release is not None and current_head is not None

    if process_known and manifest_known:
        matches = (
            _frozen["release_id"] == current_release
            and _frozen["repo_head"] == current_head
        )
    else:
        matches = None

    identity_stale = matches is False
    serves = matches is True and not _mutations_closed
    if _mutations_closed:
        next_action = (
            "use the post-cutover green runtime; this process is closed for "
            "new mutations while admitted reads may drain"
        )
    elif identity_stale:
        next_action = (
            "reconnect the MCP connector so a new process serves the deployed "
            "release"
        )
    else:
        next_action = "none"

    with _call_lock:
        effect_count = sum(
            1
            for entry in _active_calls.values()
            if entry["kind"] == CALL_KIND_EFFECT_BEARING
        )
        read_count = sum(
            1 for entry in _active_calls.values() if entry["kind"] == CALL_KIND_READ
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "process_identity_known": process_known,
        "manifest_identity_known": manifest_known,
        "process_release_id": _frozen["release_id"] if process_known else None,
        "process_repo_head": _frozen["repo_head"] if process_known else None,
        "manifest_release_id": current_release,
        "manifest_repo_head": current_head,
        "matches_deployed_manifest": matches,
        "serves_deployed_release": serves,
        "stale": identity_stale,
        "mutations_closed": _mutations_closed,
        "mutations_closed_reason": _mutations_closed_reason,
        "mutations_closed_at_unix": _mutations_closed_at_unix,
        "role": _role,
        "active_effect_bearing_calls": effect_count,
        "active_read_calls": read_count,
        "process_started_at_unix": _PROCESS_STARTED_AT_UNIX,
        "recommended_next_action": next_action,
        "does_not_establish": [
            "that the deployed release is itself correct",
            "that an unknown identity is current",
            "application-level success of any tool",
            "that remaining reads have drained",
        ],
    }


def is_stale(current_release_id: Any = None, current_repo_head: Any = None) -> bool:
    """Return True when mutations must be refused.

    Identity mismatch and post-cutover mutation closure both refuse mutations.
    An unknown identity on either side is never reported as identity-stale, but
    an explicit mutations-closed process still refuses mutations.
    """
    if _mutations_closed:
        return True
    return (
        identity(
            current_release_id=current_release_id,
            current_repo_head=current_repo_head,
        )["matches_deployed_manifest"]
        is False
    )


def mutations_admitted(
    current_release_id: Any = None, current_repo_head: Any = None
) -> bool:
    """Return True only when this process may still accept effect-bearing work."""
    if _mutations_closed:
        return False
    matches = identity(
        current_release_id=current_release_id,
        current_repo_head=current_repo_head,
    )["matches_deployed_manifest"]
    return matches is True


def mutation_rejection_message(
    current_release_id: Any = None, current_repo_head: Any = None
) -> str:
    """Return the typed operator-facing reason a mutation was refused."""
    if _mutations_closed:
        reason = _mutations_closed_reason or "blue-green-cutover"
        return (
            "serving process is closed for new mutations after "
            f"{reason}; admitted reads may drain, but effect-bearing work must "
            "use the active green runtime. Reconnect the MCP connector before "
            "mutating; deploying again does not repair this session."
        )
    projection = identity(
        current_release_id=current_release_id,
        current_repo_head=current_repo_head,
    )
    return (
        "serving process runs release "
        f"{projection['process_release_id']} while the deployed manifest is "
        f"{projection['manifest_release_id']}; this process keeps the tool "
        "surface and gates of the older code. Reconnect the MCP connector "
        "before mutating; deploying again does not repair this session."
    )

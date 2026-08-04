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
"""

from __future__ import annotations

import re
import time
from typing import Any


SCHEMA_VERSION = 1
KIND = "grabowski_serving_process_identity"

_HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")

_PROCESS_STARTED_AT_UNIX = int(time.time())
_frozen: dict[str, str] | None = None
_frozen_attempted = False


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


def reset_for_tests() -> None:
    """Clear the frozen identity so tests can exercise both branches."""
    global _frozen, _frozen_attempted
    _frozen = None
    _frozen_attempted = False


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
        "serves_deployed_release": matches is True,
        "stale": matches is False,
        "process_started_at_unix": _PROCESS_STARTED_AT_UNIX,
        "recommended_next_action": (
            "reconnect the MCP connector so a new process serves the deployed "
            "release"
            if matches is False
            else "none"
        ),
        "does_not_establish": [
            "that the deployed release is itself correct",
            "that an unknown identity is current",
            "application-level success of any tool",
        ],
    }


def is_stale(current_release_id: Any = None, current_repo_head: Any = None) -> bool:
    """Return True only on a positively observed mismatch.

    An unknown identity on either side is never reported as stale, so a
    manifest that cannot be read does not brick a healthy process.
    """
    return (
        identity(
            current_release_id=current_release_id,
            current_repo_head=current_repo_head,
        )["matches_deployed_manifest"]
        is False
    )


def mutation_rejection_message(
    current_release_id: Any = None, current_repo_head: Any = None
) -> str:
    """Return the typed operator-facing reason a mutation was refused."""
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

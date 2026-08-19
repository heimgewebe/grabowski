from __future__ import annotations

from pathlib import Path
import re
from typing import Any


_REST_PULL_MERGE_RE = re.compile(
    r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pulls/[1-9][0-9]*/merge\Z"
)


def github_merge_bypass_reason(arguments: Any) -> str | None:
    """Classify direct GitHub pull-request merge dispatch arguments.

    This is intentionally narrow and deterministic.  It recognizes the public
    GitHub CLI merge command and equivalent direct REST/GraphQL merge endpoints.
    It does not claim complete detection of arbitrary indirect execution.
    """
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        return None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"--hostname", "--repo", "-R"}:
            index += 2
            continue
        if token.startswith("--hostname=") or token.startswith("--repo="):
            index += 1
            continue
        break
    command = arguments[index:]
    if command[:2] == ["pr", "merge"]:
        return "direct_pr_merge"
    if command[:1] != ["api"]:
        return None
    for token in command[1:]:
        endpoint = token.lstrip("/")
        if _REST_PULL_MERGE_RE.fullmatch(endpoint) is not None:
            return "rest_pull_merge"
        if "mergePullRequest" in token:
            return "graphql_pull_merge"
    return None


def direct_merge_bypass_reason(argv: Any) -> str | None:
    """Classify direct ``gh`` merge dispatch in an argv command.

    Absolute executable paths are supported through basename normalization.
    """
    if not isinstance(argv, list) or not argv or not isinstance(argv[0], str):
        return None
    if Path(argv[0]).name != "gh":
        return None
    return github_merge_bypass_reason(argv[1:])

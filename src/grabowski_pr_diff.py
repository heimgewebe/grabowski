from __future__ import annotations

import hashlib
import re


GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION = "github-index-oid-prefix-7-v1"

_INDEX_LINE_RE = re.compile(
    rb"(?m)^index (?P<old>[0-9a-f]{7,64})\.\.(?P<new>[0-9a-f]{7,64})(?P<suffix> [0-7]{6})?(?P<cr>\r?)$"
)


def canonicalize_github_pr_diff_identity(diff_bytes: bytes) -> bytes:
    """Stabilize redundant Git index metadata without changing patch content.

    GitHub may render the same blob object id with different abbreviation lengths
    across otherwise identical ``gh pr diff`` responses.  Base and head commits
    are bound separately by the review and merge contracts, so seven hexadecimal
    characters are sufficient here to make only that redundant representation
    deterministic.  Every other byte, including line endings, is preserved.
    """
    if not isinstance(diff_bytes, bytes):
        raise TypeError("diff_bytes must be bytes")

    def replace_index_line(match: re.Match[bytes]) -> bytes:
        return b"".join(
            (
                b"index ",
                match.group("old")[:7],
                b"..",
                match.group("new")[:7],
                match.group("suffix") or b"",
                match.group("cr") or b"",
            )
        )

    return _INDEX_LINE_RE.sub(replace_index_line, diff_bytes)


def github_pr_diff_identity_sha256(diff_bytes: bytes) -> str:
    return hashlib.sha256(canonicalize_github_pr_diff_identity(diff_bytes)).hexdigest()

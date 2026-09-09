from __future__ import annotations

import hashlib
import re


GITHUB_PR_DIFF_IDENTITY_CANONICALIZATION = "github-index-oid-prefix-7+hunk-context-strip-v2"
GITHUB_PR_DIFF_IDENTITY_PREVIOUS_CANONICALIZATION = "github-index-oid-prefix-7-v1"

_INDEX_LINE_RE = re.compile(
    rb"(?m)^index (?P<old>[0-9a-f]{7,64})\.\.(?P<new>[0-9a-f]{7,64})(?P<suffix> [0-7]{6})?(?P<cr>\r?)$"
)
_HUNK_HEADER_RE = re.compile(
    rb"(?m)^(?P<header>@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@)(?:[^\r\n]*)?(?P<cr>\r?)$"
)


def _canonicalize_github_pr_diff_identity_v1(diff_bytes: bytes) -> bytes:
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


def canonicalize_github_pr_diff_identity(diff_bytes: bytes) -> bytes:
    """Stabilize redundant Git diff metadata without changing patch content.

    GitHub may render the same blob object id with different abbreviation lengths
    and Git renderers may add different optional context labels after a unified
    diff hunk range. Base and head commits are bound separately by the review and
    merge contracts, so seven hexadecimal characters are sufficient for index
    identity and the non-applying hunk label can be omitted. Hunk ranges, patch
    lines and line endings remain byte-significant.
    """
    if not isinstance(diff_bytes, bytes):
        raise TypeError("diff_bytes must be bytes")

    def replace_hunk_header(match: re.Match[bytes]) -> bytes:
        return (match.group("header") or b"") + (match.group("cr") or b"")

    canonical = _canonicalize_github_pr_diff_identity_v1(diff_bytes)
    return _HUNK_HEADER_RE.sub(replace_hunk_header, canonical)


def github_pr_diff_identity_sha256(diff_bytes: bytes) -> str:
    return hashlib.sha256(canonicalize_github_pr_diff_identity(diff_bytes)).hexdigest()


def github_pr_diff_identity_sha256_v1(diff_bytes: bytes) -> str:
    """Return the immediately preceding canonical identity for transition checks."""
    if not isinstance(diff_bytes, bytes):
        raise TypeError("diff_bytes must be bytes")
    return hashlib.sha256(_canonicalize_github_pr_diff_identity_v1(diff_bytes)).hexdigest()

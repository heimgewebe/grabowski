from __future__ import annotations

import hashlib
import re
from pathlib import Path


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


def canonicalize_github_pr_diff_identity_v1(diff_bytes: bytes) -> bytes:
    """Return the immediately preceding canonical diff bytes for transition checks."""
    if not isinstance(diff_bytes, bytes):
        raise TypeError("diff_bytes must be bytes")
    return _canonicalize_github_pr_diff_identity_v1(diff_bytes)


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

    canonical = canonicalize_github_pr_diff_identity_v1(diff_bytes)
    return _HUNK_HEADER_RE.sub(replace_hunk_header, canonical)


def github_pr_diff_identity_sha256(diff_bytes: bytes) -> str:
    return hashlib.sha256(canonicalize_github_pr_diff_identity(diff_bytes)).hexdigest()


def github_pr_diff_identity_sha256_v1(diff_bytes: bytes) -> str:
    """Return the immediately preceding canonical identity for transition checks."""
    return hashlib.sha256(canonicalize_github_pr_diff_identity_v1(diff_bytes)).hexdigest()

LOCAL_PR_DIFF_MAX_BYTES = 32 * 1024 * 1024
_LOCAL_DIFF_STDERR_LIMIT = 128 * 1024


class BoundLocalDiffError(RuntimeError):
    """No complete, reproducible local PR diff is available."""


def _bounded_git_capture(
    args: list[str], *, cwd: str, env: dict[str, str],
    stdout_limit: int, timeout: int,
) -> bytes:
    """Collect both pipes below hard byte caps, killing the group on overflow."""
    import os
    import selectors
    import signal
    import subprocess
    import time

    if stdout_limit <= 0 or timeout <= 0:
        raise ValueError("invalid local git output budget")
    proc = subprocess.Popen(
        args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    out, err = bytearray(), bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        assert proc.stdout is not None and proc.stderr is not None
        selector.register(proc.stdout, selectors.EVENT_READ, out)
        selector.register(proc.stderr, selectors.EVENT_READ, err)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BoundLocalDiffError("local git command timed out")
            for key, _ in selector.select(timeout=min(0.2, remaining)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = key.data
                limit = stdout_limit if target is out else _LOCAL_DIFF_STDERR_LIMIT
                if len(target) + len(chunk) > limit:
                    raise BoundLocalDiffError("local git output exceeds byte budget")
                target.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BoundLocalDiffError("local git command timed out")
        try:
            rc = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise BoundLocalDiffError("local git command timed out") from exc
        if rc:
            raise BoundLocalDiffError("local git command failed")
        return bytes(out)
    finally:
        selector.close()
        # The group may still own inherited pipes even if its leader exited.
        # Kill the entire session on every exit path, never just a live leader.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()
        proc.wait()


def bound_local_pr_git_diff(
    repo: "Path", *, merge_base: str, head: str,
    timeout: int = 90, max_diff_bytes: int = LOCAL_PR_DIFF_MAX_BYTES,
) -> bytes:
    """Produce a full SHA-bound diff using only HEAD's attribute blobs.

    Git 2.34 cannot select the attribute source by SHA. Use an isolated
    worktree with only HEAD's tracked .gitattributes, an empty temporary
    index, and disabled system/global attributes. No PR code is checked out.
    """
    import os
    import tempfile

    if (
        not isinstance(merge_base, str)
        or not isinstance(head, str)
        or re.fullmatch(r"[0-9a-f]{40}", merge_base) is None
        or re.fullmatch(r"[0-9a-f]{40}", head) is None
        or max_diff_bytes <= 0 or max_diff_bytes > LOCAL_PR_DIFF_MAX_BYTES
    ):
        raise BoundLocalDiffError("invalid local PR revision or byte budget")
    repo = Path(repo).resolve()
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0", LC_ALL="C")

    def read_git(*args: str, limit: int = 8192) -> bytes:
        return _bounded_git_capture(
            ["git", "-C", str(repo), "-c", "core.pager=cat", *args],
            cwd=str(repo), env=env, timeout=timeout, stdout_limit=limit,
        )

    gitdir = Path(read_git("rev-parse", "--absolute-git-dir").decode().strip())
    common = Path(read_git("rev-parse", "--git-common-dir").decode().strip())
    if not common.is_absolute():
        common = repo / common
    # git info/attributes outranks even a pinned HEAD .gitattributes.
    for root in (gitdir, common):
        info_attrs = root / "info" / "attributes"
        if info_attrs.exists() or info_attrs.is_symlink():
            raise BoundLocalDiffError("non-revision-bound info/attributes is present")
    tree = read_git("ls-tree", "-r", "-z", "--full-tree", head, limit=8 * 1024 * 1024)
    blobs: list[tuple[str, str]] = []
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        meta, tab, name = entry.partition(b"\t")
        if not tab:
            raise BoundLocalDiffError("invalid HEAD tree entry")
        if name != b".gitattributes" and not name.endswith(b"/.gitattributes"):
            continue
        try:
            path = name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BoundLocalDiffError("invalid attribute path") from exc
        if any(p in ("", ".", "..", ".git") for p in path.split("/")):
            raise BoundLocalDiffError("unsafe attribute path")
        fields = meta.split(b" ")
        if (len(fields) != 3 or fields[0] not in (b"100644", b"100755")
            or fields[1] != b"blob"
            or re.fullmatch(rb"[0-9a-f]{40,64}", fields[2]) is None):
            raise BoundLocalDiffError("HEAD attribute is not a regular blob")
        blobs.append((path, fields[2].decode("ascii")))
        if len(blobs) > 256:
            raise BoundLocalDiffError("too many HEAD attribute files")
    with tempfile.TemporaryDirectory(prefix="grabowski-pr-diff-") as temp:
        scratch = Path(temp)
        root = scratch / "worktree"
        root.mkdir()
        total = 0
        for relative, oid in blobs:
            remaining = 4 * 1024 * 1024 - total
            if remaining <= 0:
                raise BoundLocalDiffError("HEAD attributes exceed byte budget")
            blob = read_git("cat-file", "blob", oid, limit=remaining)
            total += len(blob)
            dest = root.joinpath(*relative.split("/"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob)
        isolated = dict(env)
        isolated.update(GIT_DIR=str(gitdir), GIT_WORK_TREE=str(root),
                        GIT_INDEX_FILE=str(scratch / "empty-index"))
        flags = ["git", "-c", "core.pager=cat", "-c",
                 "core.attributesFile=/dev/null", "-c", "diff.external=",
                 "-c", "diff.trustExitCode=false"]
        _bounded_git_capture([*flags, "read-tree", "--empty"], cwd=str(root),
                             env=isolated, timeout=timeout, stdout_limit=8192)
        return _bounded_git_capture(
            [*flags, "diff", "--no-ext-diff", "--no-textconv",
             "--no-renames", "--no-color", merge_base, head, "--"],
            cwd=str(root), env=isolated, timeout=timeout, stdout_limit=max_diff_bytes,
        )
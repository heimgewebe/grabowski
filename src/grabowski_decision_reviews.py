from __future__ import annotations

from contextlib import closing, contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Iterator

import grabowski_job_origin as job_origin
import grabowski_coding_agent_catalog_data as catalog_data


STATE_ROOT = Path.home() / ".local" / "state" / "grabowski"
JOBS_ROOT = STATE_ROOT / "jobs"
LOCKS_ROOT = STATE_ROOT / "decision-review-locks"
BINDING_KIND = "grabowski_decision_bound_review"
BINDING_SCHEMA_VERSION = 1
RESULT_KIND = "grabowski_decision_bound_review_result"
RESULT_SCHEMA_VERSION = 1
RESULT_PREFIX = "GRABOWSKI_DECISION_REVIEW_V1="
# Full registry scan retains late material REJECTs; this is not an archive solution.
MAX_JOB_DIRECTORIES = 16_384  # Hard cap on all scanned directory entries
MAX_BOUND_REVIEW_JOBS = 10_000  # Independent attempts, not unrelated job entries
MAX_METADATA_BYTES = 256 * 1024
MAX_TOTAL_METADATA_BYTES = 128 * 1024 * 1024
MAX_FINALIZATION_BYTES = 256 * 1024
MAX_STDOUT_TAIL_BYTES = 256 * 1024
# Non-review origins must not conceal review results retained in their job logs.
# This is a separate, bounded verification budget, not a limit increase for
# admitted review evidence.
MAX_UNBOUND_STDOUT_BYTES = 32 * 1024 * 1024
MAX_ROLE_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_REVIEW_ROLE_MODULE_BYTES = 1024 * 1024
REVIEW_ROLE_MODULE = "grabowski_agent_role"
REVIEW_ROLE_ATTEMPT_RECEIPT_NAME = "review-role-attempt.json"

class ReviewMetadataBudgetExceeded(ValueError):
    pass

REVIEW_ROLE_SANDBOX = "bubblewrap-minimal-root-read-only-worktree-v1"
REVIEW_ROLE_PYTHON = os.path.abspath(sys.executable)
REVIEW_ROLE_STABLE_PYTHON = Path.home() / ".local/share/grabowski-mcp/.venv/bin/python"
REVIEW_ROLE_STABLE_VENV_TARGET = REVIEW_ROLE_STABLE_PYTHON.parent.parent.resolve(strict=False)
REVIEW_ROLE_RELEASE_ROOT = Path.home() / ".local/share/grabowski-mcp-releases"
REVIEW_ROLE_LAUNCHER_PREFIX = (
    REVIEW_ROLE_PYTHON,
    "-I",
    "-m",
    REVIEW_ROLE_MODULE,
)
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_SLOT_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
_UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})\Z")
_RGPM_UNIT_RE = re.compile(r"grabowski-job-rgpm-[0-9a-f]{16}-[0-9]{2}\Z")
_REVIEW_ROLE_RELEASE_ID_RE = re.compile(
    r"[0-9a-f]{12}-srcset[0-9a-f]{12}-lock[0-9a-f]{12}-contract[0-9a-f]{12}"
    r"(?:-attempt[1-9][0-9]{0,2})?\Z"
)
_REVIEW_ROLE_PYTHON_DIR_RE = re.compile(r"python[0-9]+\.[0-9]+\Z")
_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "repo",
        "pr",
        "head_sha",
        "base_sha",
        "diff_sha256",
        "slot",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "repo",
        "pr",
        "head_sha",
        "base_sha",
        "diff_sha256",
        "slot",
        "verdict",
        "material_findings",
    }
)
_TERMINAL_STATUSES = frozenset(
    {"succeeded", "failed", "timed_out", "signalled", "terminated_unclear"}
)
_PRE_RESULT_INFRASTRUCTURE_STATUSES = frozenset(
    {"failed", "timed_out", "signalled", "terminated_unclear"}
)
_VERDICTS = frozenset({"PASS_THIS_REVISION", "REJECT_THIS_REVISION"})
# Only the observed human-readable no-inference quota response is an
# infrastructure error. Unknown message shapes are ambiguous, never review PASS.
_CLAUDE_QUOTA_RESULT_RE = re.compile(
    r"\A(?:You've hit your weekly limit"
    # Claude also returns "resets 10am (UTC)" without a month/day.
    # Accept only the exact hour-and-UTC shape, not arbitrary quota prose.
    r"(?: · resets (?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"(?:[1-9]|[12][0-9]|3[01]), )?"
    r"(?:[1-9]|1[0-2])(?::[0-5][0-9])?(?:am|pm) \(UTC\))?"
    r"|You've hit your session limit · resets "
    r"(?:[1-9]|1[0-2])(?::[0-5][0-9])?(?:am|pm) \(UTC\))\Z"
)
# New provider fields must be understood before claiming zero semantic output.
_CLAUDE_QUOTA_UUID_RE = re.compile(
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z"
)
_CLAUDE_QUOTA_ENVELOPE_FIELDS = frozenset({
    "type", "is_error", "terminal_reason", "api_error_status", "duration_api_ms",
    "modelUsage", "structured_output", "result", "usage", "subagent_stats",
    "permission_denials", "total_cost_usd", "duration_ms", "num_turns",
    "stop_reason", "session_id", "fast_mode_state",
    "fast_mode_disabled_reason", "subtype", "uuid", "queued_turn_count",
    "result_index",
})


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _agent_role_command_sha256(value: Any) -> str:
    """Match grabowski_agent_role.digest for cross-module argv receipts."""
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _review_role_module_identity() -> tuple[str, str] | None:
    """Bind reviewer provenance to the server-installed role module bytes."""
    module_path = Path(__file__).with_name(f"{REVIEW_ROLE_MODULE}.py")
    try:
        metadata = module_path.lstat()
        payload = module_path.read_bytes()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return None
    return (
        str(module_path.resolve(strict=False)),
        hashlib.sha256(payload).hexdigest(),
    )


def _historical_review_role_module_matches(
    value: Any, *, expected_sha256: str
) -> bool:
    """Accept immutable prior-release role modules only when bytes still match."""

    if (
        not isinstance(value, str)
        or not value
        or not isinstance(expected_sha256, str)
        or _SHA256_RE.fullmatch(expected_sha256) is None
    ):
        return False
    path = Path(value)
    if not path.is_absolute():
        return False
    try:
        root_path = REVIEW_ROLE_RELEASE_ROOT.expanduser()
        if root_path.is_symlink():
            return False
        root_metadata = root_path.stat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
        ):
            return False
        root = root_path.resolve(strict=True)
        resolved = path.resolve(strict=True)
        if resolved != path:
            return False
        relative = resolved.relative_to(root)
        metadata = resolved.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_size > MAX_REVIEW_ROLE_MODULE_BYTES
        ):
            return False
        payload = resolved.read_bytes()
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        return False

    parts = relative.parts
    if (
        len(parts) != 6
        or _REVIEW_ROLE_RELEASE_ID_RE.fullmatch(parts[0]) is None
        or parts[1:3] != (".venv", "lib")
        or _REVIEW_ROLE_PYTHON_DIR_RE.fullmatch(parts[3]) is None
        or parts[4:] != ("site-packages", f"{REVIEW_ROLE_MODULE}.py")
    ):
        return False
    return hmac.compare_digest(hashlib.sha256(payload).hexdigest(), expected_sha256)


def _historical_review_role_python_matches(value: Any) -> bool:
    """Accept only canonical historical runner paths to the current interpreter."""

    if not isinstance(value, str) or not value:
        return False
    path = Path(value)
    if not path.is_absolute():
        return False
    try:
        stable_python = REVIEW_ROLE_STABLE_PYTHON.expanduser()
        stable_allowed = path == stable_python

        root_path = REVIEW_ROLE_RELEASE_ROOT.expanduser()
        if root_path.is_symlink():
            return False
        root_metadata = root_path.stat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.getuid()
        ):
            return False
        root = root_path.resolve(strict=True)
        if root != root_path:
            return False

        release_allowed = False
        if not stable_allowed:
            relative = path.relative_to(root_path)
            parts = relative.parts
            release_allowed = (
                len(parts) == 4
                and _REVIEW_ROLE_RELEASE_ID_RE.fullmatch(parts[0]) is not None
                and parts[1:] == (".venv", "bin", "python")
            )
        if not (stable_allowed or release_allowed):
            return False

        parent = path.parent
        if stable_allowed:
            trusted_venv = Path(REVIEW_ROLE_STABLE_VENV_TARGET)
            trusted_relative = trusted_venv.relative_to(root)
            trusted_parts = trusted_relative.parts
            trusted_metadata = trusted_venv.stat()
            if (
                len(trusted_parts) != 2
                or _REVIEW_ROLE_RELEASE_ID_RE.fullmatch(trusted_parts[0]) is None
                or trusted_parts[1] != ".venv"
                or trusted_venv.resolve(strict=True) != trusted_venv
                or not stat.S_ISDIR(trusted_metadata.st_mode)
                or trusted_metadata.st_uid != os.getuid()
                or parent.resolve(strict=True) != trusted_venv / "bin"
            ):
                return False
        elif parent.resolve(strict=True) != parent:
            return False

        link_metadata = path.lstat()
        if (
            not (
                stat.S_ISLNK(link_metadata.st_mode)
                or stat.S_ISREG(link_metadata.st_mode)
            )
            or link_metadata.st_uid != os.getuid()
        ):
            return False

        resolved = path.resolve(strict=True)
        expected = Path(REVIEW_ROLE_PYTHON).resolve(strict=True)
        resolved_metadata = resolved.stat()
        expected_metadata = expected.stat()
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        return False

    return (
        stat.S_ISREG(resolved_metadata.st_mode)
        and stat.S_ISREG(expected_metadata.st_mode)
        and resolved == expected
        and resolved_metadata.st_dev == expected_metadata.st_dev
        and resolved_metadata.st_ino == expected_metadata.st_ino
    )



_NAMED_SLOT_PROVIDER_FAMILIES = {
    "gemini": "google",
    "google": "google",
    "grok": "xai",
    "xai": "xai",
    "claude": "anthropic",
    "anthropic": "anthropic",
    "codex": "openai",
    "openai": "openai",
}


def _named_slot_provider_family(slot: str) -> str | None:
    """Only explicit provider tokens bind slot identity; generic names stay generic."""
    families = {
        _NAMED_SLOT_PROVIDER_FAMILIES[token]
        for token in re.split(r"[._:-]+", slot.lower())
        if token in _NAMED_SLOT_PROVIDER_FAMILIES
    }
    if len(families) > 1:
        raise ValueError("decision review slot names conflicting reviewer providers")
    return next(iter(families), None)

def normalize_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        raise ValueError("decision review binding has an invalid shape")
    if value.get("schema_version") != BINDING_SCHEMA_VERSION or isinstance(
        value.get("schema_version"), bool
    ):
        raise ValueError("decision review binding schema_version must be integer 1")
    if value.get("kind") != BINDING_KIND:
        raise ValueError(f"decision review binding kind must be {BINDING_KIND}")
    repo = value.get("repo")
    if not isinstance(repo, str) or _REPO_RE.fullmatch(repo.strip()) is None:
        raise ValueError("decision review repo must have owner/repo form")
    pr = value.get("pr")
    if isinstance(pr, bool) or not isinstance(pr, int) or pr <= 0:
        raise ValueError("decision review pr must be a positive integer")
    head_sha = value.get("head_sha")
    base_sha = value.get("base_sha")
    diff_sha256 = value.get("diff_sha256")
    if not isinstance(head_sha, str) or _SHA40_RE.fullmatch(head_sha.lower()) is None:
        raise ValueError("decision review head_sha must be a 40 character SHA")
    if not isinstance(base_sha, str) or _SHA40_RE.fullmatch(base_sha.lower()) is None:
        raise ValueError("decision review base_sha must be a 40 character SHA")
    if not isinstance(diff_sha256, str) or _SHA256_RE.fullmatch(diff_sha256.lower()) is None:
        raise ValueError("decision review diff_sha256 must be a 64 character SHA-256")
    slot = value.get("slot")
    if not isinstance(slot, str) or _SLOT_RE.fullmatch(slot.strip()) is None:
        raise ValueError("decision review slot must be a bounded identifier")
    _named_slot_provider_family(slot.strip().lower())
    return {
        "schema_version": BINDING_SCHEMA_VERSION,
        "kind": BINDING_KIND,
        "repo": repo.strip().lower(),
        "pr": pr,
        "head_sha": head_sha.lower(),
        "base_sha": base_sha.lower(),
        "diff_sha256": diff_sha256.lower(),
        "slot": slot.strip().lower(),
    }


def result_contract(binding: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_binding(binding)
    return {
        "prefix": RESULT_PREFIX,
        "required_result": {
            "schema_version": RESULT_SCHEMA_VERSION,
            "kind": RESULT_KIND,
            "repo": normalized["repo"],
            "pr": normalized["pr"],
            "head_sha": normalized["head_sha"],
            "base_sha": normalized["base_sha"],
            "diff_sha256": normalized["diff_sha256"],
            "slot": normalized["slot"],
            "verdict": "PASS_THIS_REVISION | REJECT_THIS_REVISION",
            "material_findings": "integer >= 0; PASS requires 0, REJECT requires >0",
        },
        "rule": (
            "emit exactly one final marker line; infrastructure failures may emit no marker, "
            "but every declared slot still requires a later successful PASS and any material "
            "REJECT remains merge-blocking"
        ),
    }


def _lock_key(binding: dict[str, Any]) -> str:
    normalized = normalize_binding(binding)
    return sha256_json(
        {
            "repo": normalized["repo"],
            "pr": normalized["pr"],
            "head_sha": normalized["head_sha"],
        }
    )


@contextmanager
def decision_review_lock(binding: dict[str, Any]) -> Iterator[None]:
    key = _lock_key(binding)
    root = LOCKS_ROOT
    if root.exists() and root.is_symlink():
        raise PermissionError("decision review lock root may not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / f"{key}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _review_stat_file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Compare physical identity and all writable inode metadata of evidence."""
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def _review_stat_parent_identity(value: os.stat_result) -> tuple[int, ...]:
    """Pin a V1 external receipt's parent without blocking unrelated writes."""
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_nlink,
    )


def _read_private_bytes(
    path: Path, max_bytes: int, *, require_private_parent: bool = True,
    parent_fd: int | None = None,
    aggregate_metadata_bytes: list[int] | None = None,
    allow_legacy_readable: bool = False,
    external_v1_snapshots: list[tuple[Path, tuple[int, ...], tuple[int, ...] | None]] | None = None,
) -> bytes:
    """Read bounded stable owner-owned bytes; ordinary legacy logs may be 0644.

    The only relaxed caller searches for blocking evidence under a verified
    owner-private directory. It cannot use such bytes to grant a review PASS.
    """
    if allow_legacy_readable and not require_private_parent:
        raise ValueError("legacy readable stdout requires an owner-private parent")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    owns_parent = parent_fd is None
    if parent_fd is None:
        try:
            parent_fd = os.open(path.parent, flags | os.O_DIRECTORY)
        except FileNotFoundError as exc:
            if external_v1_snapshots is not None:
                # Without a pinned parent, late V1 evidence could hide a REJECT.
                raise ValueError("external V1 role receipt parent missing") from exc
            raise
    try:
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode):
            raise ValueError("review evidence parent is not a directory")
        external_parent_identity = (
            _review_stat_parent_identity(parent)
            if external_v1_snapshots is not None else None
        )
        if require_private_parent and (
            parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) & 0o077
        ):
            raise ValueError("review evidence parent is not owner-private")
        try:
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if external_v1_snapshots is not None:
                # A missing V1 role receipt can publish later during the scan.
                # Pin that negative observation just like a previously read file.
                if (
                    _review_stat_parent_identity(os.fstat(parent_fd))
                    != external_parent_identity
                ):
                    raise ValueError("external V1 role receipt parent changed")
                external_v1_snapshots.append(
                    (path, external_parent_identity, None)
                )
            raise
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or (
                    stat.S_IMODE(before.st_mode) & 0o077
                    and not (
                        allow_legacy_readable
                        and stat.S_IMODE(before.st_mode) == 0o644
                    )
                )
            ):
                raise ValueError(f"{path.name} is not one owner-private regular file")
            if before.st_size > max_bytes:
                raise ValueError(f"{path.name} is too large")
            if aggregate_metadata_bytes is not None:
                observed = aggregate_metadata_bytes[0] + before.st_size
                if observed > MAX_TOTAL_METADATA_BYTES:
                    raise ReviewMetadataBudgetExceeded(
                        "decision review metadata aggregate budget exceeded"
                    )
                aggregate_metadata_bytes[0] = observed
            content = bytearray()
            while len(content) <= max_bytes:
                chunk = os.read(descriptor, min(65536, max_bytes + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            after = os.fstat(descriptor)
            if (
                len(content) > max_bytes
                or len(content) != before.st_size
                or (before.st_dev, before.st_ino, before.st_nlink,
                    before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_nlink,
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            ):
                raise ValueError(f"{path.name} changed during read")
            if external_v1_snapshots is not None:
                # V1 receipts can live outside the job root. Preserve the FD
                # preimage, not a later path stat: both inode rewrites and
                # replacements must invalidate a formerly observed PASS.
                file_identity = _review_stat_file_identity(before)
                linked = os.stat(
                    path.name, dir_fd=parent_fd, follow_symlinks=False
                )
                if (
                    _review_stat_file_identity(linked) != file_identity
                    or _review_stat_parent_identity(os.fstat(parent_fd))
                    != external_parent_identity
                ):
                    raise ValueError(f"{path.name} changed after review evidence read")
                external_v1_snapshots.append(
                    (path, external_parent_identity, file_identity)
                )
            return bytes(content)
        finally:
            os.close(descriptor)
    finally:
        if owns_parent:
            os.close(parent_fd)


def _read_private_json(
    path: Path, max_bytes: int, *, require_private_parent: bool = True,
    parent_fd: int | None = None,
    aggregate_metadata_bytes: list[int] | None = None,
    external_v1_snapshots: list[tuple[Path, tuple[int, ...], tuple[int, ...] | None]] | None = None,
) -> dict[str, Any]:
    """Read one stable owner-private JSON object without following its path."""
    content = _read_private_bytes(
        path, max_bytes, require_private_parent=require_private_parent,
        parent_fd=parent_fd, aggregate_metadata_bytes=aggregate_metadata_bytes,
        external_v1_snapshots=external_v1_snapshots,
    )
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be an object")
    return value


def _read_stdout_tail(
    path: Path, *, parent_fd: int | None = None
) -> tuple[str, str]:
    payload = _read_private_bytes(path, MAX_STDOUT_TAIL_BYTES, parent_fd=parent_fd)
    return payload.decode("utf-8", errors="replace"), hashlib.sha256(payload).hexdigest()


def _unbound_review_result_visible(
    directory: Path, *, parent_fd: int, aggregate_bytes: list[int],
    expected: dict[str, Any], allow_legacy_readable_stdout: bool = False,
) -> bool:
    """Find review evidence in a job whose valid origin now denies review status.

    Only evidence for this exact PR/head blocks. Unrelated ordinary jobs may
    print literal marker text or retain other revisions' role receipts.
    This detects surviving evidence, not coordinated same-UID tampering of
    metadata plus every secondary artifact.
    """
    try:
        receipt = _read_private_json(
            directory / REVIEW_ROLE_ATTEMPT_RECEIPT_NAME,
            MAX_ROLE_RECEIPT_BYTES, parent_fd=parent_fd,
            aggregate_metadata_bytes=aggregate_bytes,
        )
    except FileNotFoundError:
        pass
    else:
        head = receipt.get("expected_head")
        if not isinstance(head, str) or _SHA40_RE.fullmatch(head) is None:
            raise ValueError("unbound role receipt head is invalid")
        if head == expected["head_sha"]:
            base_head = receipt.get("expected_base_head")
            if not isinstance(base_head, str) or _SHA40_RE.fullmatch(base_head) is None:
                raise ValueError("unbound role receipt base head is invalid")
            # A matching HEAD from another PR base is not proof of a review
            # of this revision. The role's expected_diff_sha256 is a workspace
            # diff and cannot be equated to the canonical PR diff identity.
            # Still scan any surviving stdout for an exact-bound REJECT.
            if base_head == expected["base_sha"]:
                return True
    # An oversized unbound stdout can retain a material REJECT even after
    # its origin metadata has been rebound to an ordinary job. Without an
    # independent, authenticated origin record, it cannot be classified as
    # harmless. Keep the FD-pinned bounded read fail-closed on oversize.
    stdout = _read_private_bytes(
        directory / "stdout.log", MAX_UNBOUND_STDOUT_BYTES,
        parent_fd=parent_fd, aggregate_metadata_bytes=aggregate_bytes,
        allow_legacy_readable=allow_legacy_readable_stdout,
    )
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        if not line.startswith(RESULT_PREFIX):
            continue
        try:
            marker = json.loads(line[len(RESULT_PREFIX):])
        except json.JSONDecodeError:
            # A quoted marker name is not an authenticated review decision.
            continue
        if isinstance(marker, dict) and _raw_binding_targets_pr_head(marker, expected):
            return True
    return False


def _exact_empty_prelaunch_stub(directory_fd: int) -> bool:
    """Narrow legacy footprint from failed pre-origin job preparation.

    This is a pinned filesystem classification, NOT proof that an adversary
    never started work and subsequently erased all same-UID evidence.
    """
    parent_before = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(parent_before.st_mode)
        or parent_before.st_uid != os.geteuid()
        or stat.S_IMODE(parent_before.st_mode) & 0o077
    ):
        return False
    observed: dict[str, os.stat_result] = {}
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if len(observed) >= 2 or entry.name not in {"stdout.log", "stderr.log"}:
                return False
            observed[entry.name] = entry.stat(follow_symlinks=False)
    if set(observed) != {"stdout.log", "stderr.log"}:
        return False
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
    descriptors: list[int] = []
    try:
        for name in ("stdout.log", "stderr.log"):
            fd = os.open(name, flags, dir_fd=directory_fd)
            descriptors.append(fd)
            before = os.fstat(fd)
            snapshot = observed[name]
            identity = lambda s: (
                s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink,
                s.st_size, s.st_mtime_ns, s.st_ctime_ns,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size != 0
                or identity(before) != identity(snapshot)
                or os.read(fd, 1) != b""
                or identity(os.fstat(fd)) != identity(before)
                or identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
                != identity(before)
            ):
                return False
        with os.scandir(directory_fd) as entries:
            after_names = sorted(entry.name for entry in entries)
        after = os.fstat(directory_fd)
        return (
            after_names == ["stderr.log", "stdout.log"]
            and (
                parent_before.st_dev, parent_before.st_ino,
                parent_before.st_mtime_ns, parent_before.st_ctime_ns,
            ) == (
                after.st_dev, after.st_ino,
                after.st_mtime_ns, after.st_ctime_ns,
            )
        )
    finally:
        for fd in descriptors:
            os.close(fd)


def _raw_binding_targets_pr_head(value: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(value, dict):
        return False
    repo = value.get("repo")
    pr = value.get("pr")
    head_sha = value.get("head_sha")
    return (
        isinstance(repo, str)
        and repo.strip().lower() == expected["repo"]
        and isinstance(pr, int)
        and not isinstance(pr, bool)
        and pr == expected["pr"]
        and isinstance(head_sha, str)
        and head_sha.strip().lower() == expected["head_sha"]
    )


def _proven_not_started(metadata: dict[str, Any]) -> bool:
    terminalization = metadata.get("terminalization_evidence")
    launcher = metadata.get("launcher_evidence")
    return (
        metadata.get("final_status") == "launch_failed"
        and metadata.get("dispatch_outcome") == "not_started"
        and isinstance(terminalization, dict)
        and terminalization.get("source") == "systemd-run-launch"
        and terminalization.get("query_valid") is True
        and terminalization.get("final_status") == "launch_failed"
        and terminalization.get("systemd_visible") is False
        and isinstance(launcher, dict)
        and isinstance(launcher.get("returncode"), int)
        and not isinstance(launcher.get("returncode"), bool)
        and launcher["returncode"] != 0
    )

def _validated_origin_binding(
    directory: Path, *, raw_metadata: dict[str, Any] | None = None,
    parent_fd: int | None = None, expected: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    unit = directory.name
    if _UNIT_RE.fullmatch(unit) is None:
        raise ValueError("job unit is invalid")
    metadata = (
        raw_metadata if raw_metadata is not None
        else _read_private_json(
            directory / "metadata.json", MAX_METADATA_BYTES, parent_fd=parent_fd
        )
    )
    try:
        origin = job_origin.validate_origin(
            metadata.get("origin"),
            metadata.get("origin_sha256"),
            expected_unit=unit,
        )
    except ValueError as exc:
        raise ValueError(f"job origin invalid: {exc}") from exc
    for key in ("unit", "job_id", "owner", "argv_sha256", "scope"):
        if metadata.get(key) != origin.get(key):
            raise ValueError(f"job metadata {key} binding mismatch")
    scope = origin.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("job origin scope is invalid")
    raw_binding = scope.get("decision_bound_review")
    if raw_binding is None:
        return metadata, None, None
    binding = normalize_binding(raw_binding)
    # A foreign PR/head cannot contribute a PASS to this reconciliation.
    # Its authenticated Origin and structured binding are still verified;
    # the caller must scan any retained exact-head role receipt/stdout for
    # a displaced REJECT. Do not require historical runner binaries for
    # unrelated reviews after a runtime or release rotation.
    if expected is not None and not _binding_matches_pr_head(binding, expected):
        return metadata, binding, None
    origin_cwd = scope.get("cwd")
    if not isinstance(origin_cwd, str) or not origin_cwd:
        raise ValueError("job origin cwd is invalid")
    attempt_epoch = scope.get("decision_review_attempt_epoch")
    if attempt_epoch is not None and attempt_epoch != 2:
        raise ValueError("decision review attempt epoch is invalid")
    provenance = _normalize_review_role_provenance(
        scope.get("decision_review_provenance"), binding, cwd=origin_cwd,
        attempt_directory=directory,
    )
    if (
        attempt_epoch == 2
        and provenance is not None
        and provenance.get("schema_version") != 2
    ):
        raise ValueError("new decision review attempt cannot use historical role provenance")
    if provenance is None and attempt_epoch is None:
        exact_argv = metadata.get("argv")
        if (
            isinstance(exact_argv, list)
            and all(isinstance(item, str) for item in exact_argv)
            and sha256_json(exact_argv) == origin.get("argv_sha256")
        ):
            stable_python = str(REVIEW_ROLE_STABLE_PYTHON.expanduser())
            if exact_argv and exact_argv[0] != stable_python:
                provenance = review_role_provenance(
                    exact_argv, binding, cwd=Path(origin_cwd)
                )
                if provenance is None:
                    provenance = _historical_review_role_provenance(
                        exact_argv, binding, cwd=Path(origin_cwd)
                    )
    return metadata, binding, provenance


def _validated_finalization(
    directory: Path, metadata: dict[str, Any], *, parent_fd: int | None = None,
) -> dict[str, Any] | None:
    path = directory / "finalization.json"
    try:
        receipt = _read_private_json(path, MAX_FINALIZATION_BYTES, parent_fd=parent_fd)
    except FileNotFoundError:
        return None
    payload_sha256 = receipt.get("payload_sha256")
    material = {key: value for key, value in receipt.items() if key != "payload_sha256"}
    expected_payload = sha256_json(material)
    if not isinstance(payload_sha256, str) or not hmac.compare_digest(
        payload_sha256, expected_payload
    ):
        raise ValueError("job finalization payload hash mismatch")
    status = receipt.get("final_status")
    if status not in _TERMINAL_STATUSES:
        raise ValueError("job finalization status is not terminal")
    if receipt.get("unit") != directory.name:
        raise ValueError("job finalization unit mismatch")
    if receipt.get("job_id") != metadata.get("job_id"):
        raise ValueError("job finalization job_id mismatch")
    if receipt.get("argv_sha256") != metadata.get("argv_sha256"):
        raise ValueError("job finalization argv hash mismatch")
    contract = metadata.get("finalization_contract")
    if not isinstance(contract, dict):
        raise ValueError("decision-bound review requires a finalization contract")
    if receipt.get("contract_sha256") != contract.get("contract_sha256"):
        raise ValueError("job finalization contract hash mismatch")
    return receipt


def _parse_result_marker(stdout_text: str, binding: dict[str, Any]) -> dict[str, Any] | None:
    marker_lines = [
        line[len(RESULT_PREFIX) :]
        for line in stdout_text.splitlines()
        if line.startswith(RESULT_PREFIX)
    ]
    if not marker_lines:
        return None
    if len(marker_lines) != 1:
        raise ValueError("decision review output must contain exactly one result marker")
    try:
        result = json.loads(marker_lines[0])
    except json.JSONDecodeError as exc:
        raise ValueError("decision review result marker is invalid JSON") from exc
    if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
        raise ValueError("decision review result marker has an invalid shape")
    if result.get("schema_version") != RESULT_SCHEMA_VERSION or isinstance(
        result.get("schema_version"), bool
    ):
        raise ValueError("decision review result schema_version must be integer 1")
    if result.get("kind") != RESULT_KIND:
        raise ValueError(f"decision review result kind must be {RESULT_KIND}")
    expected = normalize_binding(binding)
    for key in ("repo", "pr", "head_sha", "base_sha", "diff_sha256", "slot"):
        actual = result.get(key)
        if isinstance(actual, str) and key in {"repo", "head_sha", "base_sha", "diff_sha256", "slot"}:
            actual = actual.strip().lower()
        if actual != expected[key]:
            raise ValueError(f"decision review result {key} mismatch")
    verdict = result.get("verdict")
    findings = result.get("material_findings")
    if verdict not in _VERDICTS:
        raise ValueError("decision review verdict is invalid")
    if isinstance(findings, bool) or not isinstance(findings, int) or findings < 0:
        raise ValueError("decision review material_findings must be an integer >= 0")
    if verdict == "PASS_THIS_REVISION" and findings != 0:
        raise ValueError("decision review PASS requires zero material findings")
    if verdict == "REJECT_THIS_REVISION" and findings <= 0:
        raise ValueError("decision review REJECT requires at least one material finding")
    return {
        **expected,
        "verdict": verdict,
        "material_findings": findings,
    }


def _agent_role_receipt_sha256(value: dict[str, Any]) -> str:
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    payload = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _review_route_evidence(command: list[str]) -> dict[str, Any] | None:
    try:
        catalog = json.loads(catalog_data.CATALOG_JSON)
    except (AttributeError, json.JSONDecodeError):
        return None
    routes = catalog.get("routes")
    models = catalog.get("models")
    if not isinstance(routes, list) or not isinstance(models, dict):
        return None
    matches: list[dict[str, Any]] = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        prefix = route.get("argv_prefix")
        if (
            route.get("enabled") is not True
            or route.get("review_only") is not True
            or route.get("contrast_only") is True
            or "independent-review" not in route.get("task_classes", [])
            or not isinstance(prefix, list)
            or not prefix
            or any(not isinstance(item, str) or not item for item in prefix)
            or len(command) != len(prefix) + 1
            or command[: len(prefix)] != prefix
            or not command[-1].strip()
            or command[-1].startswith("-")
        ):
            continue
        model_id = route.get("model")
        model = models.get(model_id) if isinstance(model_id, str) else None
        provider_family = model.get("provider_family") if isinstance(model, dict) else None
        route_id = route.get("id")
        independence_group = route.get("independence_group")
        if not all(
            isinstance(value, str) and value
            for value in (route_id, model_id, provider_family, independence_group)
        ):
            continue
        matches.append(
            {
                "route_id": route_id,
                "model": model_id,
                "provider_family": provider_family,
                "independence_group": independence_group,
                "argv_prefix_sha256": sha256_json(prefix),
            }
        )
    if len(matches) != 1:
        return None
    return matches[0]


def review_role_provenance(
    argv: list[str], binding: dict[str, Any], *, cwd: Path,
    attempt_directory: Path | None = None,
) -> dict[str, Any] | None:
    """Derive server-owned reviewer provenance from the pre-redaction launch argv."""
    normalized = normalize_binding(binding)
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        return None
    if (
        len(argv) < 20
        or tuple(argv[:4]) != REVIEW_ROLE_LAUNCHER_PREFIX
        or argv.count("--") != 1
    ):
        return None
    separator = argv.index("--")
    options = argv[4:separator]
    required_order = [
        "--role",
        "--repository",
        "--expected-head",
        "--expected-base-head",
        "--expected-diff-sha256",
        "--expected-dirty",
        "--output",
    ]
    if len(options) != len(required_order) * 2 or options[::2] != required_order:
        return None
    values = dict(zip(options[::2], options[1::2], strict=True))
    if values["--role"] != "review":
        return None
    if values["--expected-head"].lower() != normalized["head_sha"]:
        return None
    if values["--expected-base-head"].lower() != normalized["base_sha"]:
        return None
    workspace_diff = values["--expected-diff-sha256"].lower()
    if _SHA256_RE.fullmatch(workspace_diff) is None or values["--expected-dirty"] != "false":
        return None
    repository = Path(values["--repository"]).expanduser()
    if not repository.is_absolute():
        repository = cwd / repository
    if repository.resolve(strict=False) != cwd.resolve(strict=False):
        return None
    output = Path(values["--output"]).expanduser()
    if not output.is_absolute():
        output = cwd / output
    reviewer_command = argv[separator + 1 :]
    if not reviewer_command:
        return None
    if attempt_directory is not None:
        # Do not resolve the output through a caller-controlled symlink.
        expected_path = attempt_directory / REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
        if (
            _UNIT_RE.fullmatch(attempt_directory.name) is None
            or output != expected_path
        ):
            return None
    review_route = _review_route_evidence(reviewer_command)
    if review_route is None:
        return None
    required_family = _named_slot_provider_family(normalized["slot"])
    if required_family is not None and review_route["provider_family"] != required_family:
        return None
    module_identity = _review_role_module_identity()
    if module_identity is None:
        return None
    runner_module_path, runner_module_sha256 = module_identity
    material = {
        "schema_version": 2 if attempt_directory is not None else 1,
        "kind": "grabowski_decision_review_provenance",
        "role": "review",
        "runner_python": REVIEW_ROLE_PYTHON,
        "runner_isolated": True,
        "runner_module": REVIEW_ROLE_MODULE,
        "runner_module_path": runner_module_path,
        "runner_module_sha256": runner_module_sha256,
        "sandbox": REVIEW_ROLE_SANDBOX,
        "repository": str(repository.resolve(strict=False)),
        "head_sha": normalized["head_sha"],
        "base_sha": normalized["base_sha"],
        "workspace_diff_sha256": workspace_diff,
        "expected_dirty": False,
        "role_receipt_path": str(output if attempt_directory is not None else output.resolve(strict=False)),
        **({"attempt_unit": attempt_directory.name} if attempt_directory is not None else {}),
        "reviewer_command_sha256": _agent_role_command_sha256(reviewer_command),
        "review_route": review_route,
        "binding_sha256": sha256_json(normalized),
    }
    return {**material, "provenance_sha256": sha256_json(material)}


def bind_job_review_role_argv(
    argv: list[str], binding: dict[str, Any], *,
    cwd: Path, attempt_directory: Path,
) -> list[str]:
    """Bind one canonical independent reviewer to a unique job-owned receipt."""
    if tuple(argv[:4]) != REVIEW_ROLE_LAUNCHER_PREFIX:
        if _named_slot_provider_family(normalize_binding(binding)["slot"]) is not None:
            raise ValueError("named provider slot requires a canonical independent reviewer")
        # Accept generic, origin-bound review jobs, but never admit a role
        # launcher under a release-python alias or other wrapper as V1.
        if any(
            item == REVIEW_ROLE_MODULE
            or Path(item).name == f"{REVIEW_ROLE_MODULE}.py"
            for item in argv
        ):
            raise ValueError("noncanonical decision-bound role launcher is not admitted")
        return argv
    provenance = review_role_provenance(argv, binding, cwd=cwd)
    if provenance is None:
        raise ValueError("decision-bound role launcher is not a valid read-only reviewer")
    # The role's --expected-diff-sha256 is a *workspace fingerprint*, not
    # the separately signed GitHub PR diff. Reject mistaken hashes BEFORE
    # reserving a decision-bound attempt. This cannot clear old ambiguous jobs
    # or replace the role's own second check immediately before provider spawn.
    from grabowski_agent_role import current_binding

    try:
        observed_head, observed_diff, observed_dirty = current_binding(
            Path(provenance["repository"]), provenance["base_sha"]
        )
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        raise ValueError("decision-bound review prelaunch identity unavailable") from exc
    if (
        observed_head != provenance["head_sha"]
        or observed_diff != provenance["workspace_diff_sha256"]
        or observed_dirty is not False
    ):
        raise ValueError("decision-bound review prelaunch identity mismatch")
    separator = argv.index("--")
    output_index = argv.index("--output", 4, separator) + 1
    result = list(argv)
    result[output_index] = str(attempt_directory / REVIEW_ROLE_ATTEMPT_RECEIPT_NAME)
    if review_role_provenance(
        result, binding, cwd=cwd, attempt_directory=attempt_directory
    ) is None:
        raise ValueError("job-owned review role receipt binding is invalid")
    return result


def _historical_review_role_module_path_for_python(
    runner_python: Any, *, expected_sha256: str
) -> str | None:
    """Bind one historical immutable runner to its same-release role module."""

    if not isinstance(runner_python, str) or not runner_python:
        return None
    if runner_python == str(REVIEW_ROLE_STABLE_PYTHON.expanduser()):
        # A historical stable alias has no time-bound target without stored
        # launch provenance. Never reconstruct that missing fact from today's
        # alias target.
        return None
    if not _historical_review_role_python_matches(runner_python):
        return None
    runner_path = Path(runner_python)
    try:
        venv = runner_path.parents[1]
    except IndexError:
        return None
    module_path = (
        venv
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / f"{REVIEW_ROLE_MODULE}.py"
    )
    if not _historical_review_role_module_matches(
        str(module_path), expected_sha256=expected_sha256
    ):
        return None
    try:
        return str(module_path.resolve(strict=True))
    except (FileNotFoundError, OSError, RuntimeError):
        return None


def _historical_review_role_provenance(
    argv: list[str], binding: dict[str, Any], *, cwd: Path
) -> dict[str, Any] | None:
    """Reconstruct legacy provenance only from one immutable historical release."""

    if (
        not isinstance(argv, list)
        or any(not isinstance(item, str) for item in argv)
        or len(argv) < 4
        or tuple(argv[1:4]) != ("-I", "-m", REVIEW_ROLE_MODULE)
    ):
        return None
    module_identity = _review_role_module_identity()
    if module_identity is None:
        return None
    _current_module_path, current_module_sha256 = module_identity
    historical_module_path = _historical_review_role_module_path_for_python(
        argv[0], expected_sha256=current_module_sha256
    )
    if historical_module_path is None:
        return None

    current_shape = [REVIEW_ROLE_PYTHON, *argv[1:]]
    provenance = review_role_provenance(current_shape, binding, cwd=cwd)
    if provenance is None:
        return None
    material = {
        key: item
        for key, item in provenance.items()
        if key != "provenance_sha256"
    }
    material["runner_python"] = argv[0]
    material["runner_module_path"] = historical_module_path
    material["runner_module_sha256"] = current_module_sha256
    return {**material, "provenance_sha256": sha256_json(material)}


def _normalize_review_role_provenance(
    value: Any, binding: dict[str, Any], *, cwd: str,
    attempt_directory: Path | None = None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("decision review provenance is invalid")
    required = {
        "schema_version", "kind", "role", "runner_python", "runner_isolated",
        "runner_module", "runner_module_path", "runner_module_sha256", "sandbox",
        "repository", "head_sha", "base_sha", "workspace_diff_sha256",
        "expected_dirty", "role_receipt_path", "reviewer_command_sha256",
        "review_route", "binding_sha256", "provenance_sha256",
    }
    schema = value.get("schema_version")
    if schema == 2:
        required.add("attempt_unit")
    elif schema != 1:
        raise ValueError("decision review provenance schema is invalid")
    if set(value) != required:
        raise ValueError("decision review provenance has an invalid shape")
    material = {key: item for key, item in value.items() if key != "provenance_sha256"}
    if value.get("provenance_sha256") != sha256_json(material):
        raise ValueError("decision review provenance digest mismatch")
    normalized = normalize_binding(binding)
    module_identity = _review_role_module_identity()
    if module_identity is None:
        raise ValueError("trusted decision review role module is unavailable")
    runner_module_path, runner_module_sha256 = module_identity
    recorded_runner_python = value.get("runner_python")
    stable_python = str(REVIEW_ROLE_STABLE_PYTHON.expanduser())
    runner_python_matches = (
        recorded_runner_python == REVIEW_ROLE_PYTHON
        and recorded_runner_python != stable_python
    ) or _historical_review_role_python_matches(recorded_runner_python)
    recorded_module_path = value.get("runner_module_path")
    recorded_module_sha256 = value.get("runner_module_sha256")
    # Historical attempts bind the module bytes installed when the review ran.
    # A later source upgrade must not erase that evidence. Never trust an
    # arbitrary caller-selected digest: require the exact byte-matching module
    # in an owner-controlled, immutable release-layout path.
    module_identity_matches = (
        (
            recorded_module_sha256 == runner_module_sha256
            and recorded_module_path == runner_module_path
        )
        or _historical_review_role_module_matches(
            recorded_module_path,
            expected_sha256=recorded_module_sha256,
        )
    )
    if (
        schema not in {1, 2}
        or value.get("kind") != "grabowski_decision_review_provenance"
        or value.get("role") != "review"
        or not runner_python_matches
        or value.get("runner_isolated") is not True
        or value.get("runner_module") != REVIEW_ROLE_MODULE
        or not module_identity_matches
        or value.get("sandbox") != REVIEW_ROLE_SANDBOX
        or value.get("head_sha") != normalized["head_sha"]
        or value.get("base_sha") != normalized["base_sha"]
        or value.get("expected_dirty") is not False
        or value.get("binding_sha256") != sha256_json(normalized)
    ):
        raise ValueError("decision review provenance binding mismatch")
    repository = value.get("repository")
    receipt_path = value.get("role_receipt_path")
    workspace_diff = value.get("workspace_diff_sha256")
    command_sha = value.get("reviewer_command_sha256")
    route = value.get("review_route")
    if (
        not isinstance(repository, str)
        or Path(repository).resolve(strict=False) != Path(cwd).resolve(strict=False)
        or not isinstance(receipt_path, str)
        or not Path(receipt_path).is_absolute()
        or not isinstance(workspace_diff, str)
        or _SHA256_RE.fullmatch(workspace_diff) is None
        or not isinstance(command_sha, str)
        or _SHA256_RE.fullmatch(command_sha) is None
        or not isinstance(route, dict)
    ):
        raise ValueError("decision review provenance fields are invalid")
    if schema == 2:
        expected = (
            attempt_directory / REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
            if attempt_directory is not None else None
        )
        if (
            expected is None
            or _UNIT_RE.fullmatch(attempt_directory.name) is None
            or value.get("attempt_unit") != attempt_directory.name
            or Path(receipt_path) != expected
        ):
            raise ValueError("decision review attempt receipt belongs to another job")
    for key in ("route_id", "model", "provider_family", "independence_group", "argv_prefix_sha256"):
        if not isinstance(route.get(key), str) or not route[key]:
            raise ValueError("decision review route provenance is invalid")
    required_family = _named_slot_provider_family(normalized["slot"])
    if required_family is not None and route["provider_family"] != required_family:
        raise ValueError("decision review role provider does not match named slot")
    return value


def _claude_no_external_activity(usage: Any, subagents: Any) -> bool:
    """Require known zero-activity counters; reject unknown names even when zero."""
    def strictly_zero(value: Any) -> bool:
        return type(value) is int and value == 0
    if not isinstance(usage, dict):
        return False
    # A newly introduced usage field is ambiguous until its semantics are known.
    known_usage = {
        "input_tokens", "output_tokens", "cache_creation_input_tokens",
        "cache_read_input_tokens", "server_tool_use", "output_tokens_details",
        "cache_creation", "service_tier", "inference_geo", "iterations",
        "speed", "fallback_credit",
    }
    if set(usage) - known_usage:
        return False
    for section, required in (
        ("output_tokens_details", {"thinking_tokens"}),
        ("cache_creation", {"ephemeral_1h_input_tokens", "ephemeral_5m_input_tokens"}),
    ):
        fields = usage.get(section)
        if (
            not isinstance(fields, dict)
            or set(fields) != required
            or any(not strictly_zero(value) for value in fields.values())
        ):
            return False
    if (
        usage.get("service_tier") != "standard"
        or usage.get("speed") != "standard"
        or usage.get("inference_geo") != ""
        or usage.get("fallback_credit") is not None
    ):
        return False
    tools = usage.get("server_tool_use")
    if (
        not isinstance(tools, dict)
        or set(tools) != {"web_search_requests", "web_fetch_requests"}
        or any(not strictly_zero(value) for value in tools.values())
    ):
        return False
    scalar = {
        "spawned", "started_in_background", "max_depth",
        "spawned_by_subagents", "completed", "failed",
    }
    groups = {
        "requested": {"background", "foreground", "unset"},
        "refused": {"depth_limit", "concurrency_limit", "budget"},
        "killed": {"parent", "user", "system"},
    }
    if (
        not isinstance(subagents, dict)
        or any(not strictly_zero(subagents.get(field)) for field in scalar)
    ):
        return False
    for name, required in groups.items():
        counters = subagents.get(name)
        if (
            not isinstance(counters, dict)
            or set(counters) != required
            or any(not strictly_zero(value) for value in counters.values())
        ):
            return False
    if "by_type" in subagents:
        types = subagents["by_type"]
        if types != {}:
            return False
    if set(subagents) - (scalar | set(groups) | {"by_type"}):
        return False
    return True


def _proven_claude_quota_failure_before_review(
    receipt: dict[str, Any], provenance: dict[str, Any]
) -> bool:
    """Accept only an exact, bound 429 transport envelope with zero model work.

    This never grants a review PASS: a later independent PASS from the same
    registered provider slot is still mandatory before settlement.
    """
    if (
        provenance.get("schema_version") != 2
        or provenance.get("review_route", {}).get("provider_family") != "anthropic"
        or receipt.get("verdict") != "INVALID"
        or receipt.get("findings") != []
        or receipt.get("failure_classification") != "invalid_review_output"
        or receipt.get("returncode") != 126
        or receipt.get("review_document_bytes") != 0
        or receipt.get("review_document_sha256") is not None
        or receipt.get("review_findings_normalized") is not False
        or receipt.get("stderr_bytes") != 0
        or receipt.get("review_provider_contract") != "claude-headless-bound-diff-json-v1"
    ):
        return False
    tail = receipt.get("stdout_tail")
    if not isinstance(tail, str):
        return False
    encoded = tail.encode("utf-8")
    if (
        not encoded
        or type(receipt.get("stdout_bytes")) is not int
        or len(encoded) != receipt["stdout_bytes"]
        or receipt.get("review_provider_envelope_bytes") != len(encoded)
        or receipt.get("stdout_sha256") != hashlib.sha256(encoded).hexdigest()
        or receipt.get("review_provider_envelope_sha256") != receipt["stdout_sha256"]
    ):
        return False
    # object_pairs_hook rejects duplicates at every depth. json.loads otherwise
    # silently takes the last value and can hide semantic REJECT material.
    def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for name, item in pairs:
            if name in value:
                raise ValueError("duplicate Claude quota envelope JSON field")
            value[name] = item
        return value

    try:
        envelope = json.loads(tail, object_pairs_hook=unique_json_object)
    except ValueError:
        return False
    if not isinstance(envelope, dict) or set(envelope) - _CLAUDE_QUOTA_ENVELOPE_FIELDS:
        return False
    # The actual 429 result has one CLI wrapper turn, not one model turn.
    # An unexpected count, tool trace or provider state is not pre-result proof.
    for zero_key in ("queued_turn_count", "result_index"):
        if zero_key in envelope and (
            type(envelope[zero_key]) is not int or envelope[zero_key] != 0
        ):
            return False
    if "num_turns" in envelope and (
        type(envelope["num_turns"]) is not int or envelope["num_turns"] != 1
    ):
        return False
    if "duration_ms" in envelope and (
        type(envelope["duration_ms"]) is not int or envelope["duration_ms"] < 0
    ):
        return False
    for key, expected in (
        ("stop_reason", "stop_sequence"), ("subtype", "success"),
        ("fast_mode_state", "off"),
        ("fast_mode_disabled_reason", "sdk_opt_in_required"),
    ):
        if key in envelope and envelope[key] != expected:
            return False
    for key in ("session_id", "uuid"):
        if key in envelope and (
            not isinstance(envelope[key], str)
            or _CLAUDE_QUOTA_UUID_RE.fullmatch(envelope[key]) is None
        ):
            return False
    usage = envelope.get("usage")
    subagents = envelope.get("subagent_stats")
    return (
        envelope.get("type") == "result"
        and envelope.get("is_error") is True
        and envelope.get("terminal_reason") == "api_error"
        and type(envelope.get("api_error_status")) is int
        and envelope["api_error_status"] == 429
        and type(envelope.get("duration_api_ms")) is int
        and envelope["duration_api_ms"] == 0
        and envelope.get("modelUsage") == {}
        and envelope.get("structured_output") is None
        and isinstance(envelope.get("result"), str)
        and len(envelope["result"]) <= 256
        and _CLAUDE_QUOTA_RESULT_RE.fullmatch(envelope["result"]) is not None
        and isinstance(usage, dict) and usage.get("iterations") == []
        and envelope.get("permission_denials") == []
        and type(envelope.get("total_cost_usd")) in {int, float}
        and envelope["total_cost_usd"] == 0
        and isinstance(usage, dict)
        and all(
            type(usage.get(field)) is int and usage[field] == 0
            for field in (
                "input_tokens", "output_tokens",
                "cache_creation_input_tokens", "cache_read_input_tokens",
            )
        )
        and _claude_no_external_activity(usage, subagents)
    )


def _proven_grok_quota_failure_before_review(
    receipt: dict[str, Any], provenance: dict[str, Any]
) -> bool:
    """Recognize only the authenticated, three-event, pre-result xAI 402.

    Recognition is *not* a review decision. It keeps the failed job in history
    and requires a later real independent PASS from the same provider slot.
    Any model text, tool use, unknown event, truncation or ambiguous error
    remains invalid_result, permanently fail-closed.
    """
    route = provenance.get("review_route")
    if (
        provenance.get("schema_version") != 2
        or not isinstance(route, dict)
        or route.get("provider_family") != "xai"
        or route.get("route_id") != "grok-4.6-review-high"
        or receipt.get("verdict") != "INVALID"
        or receipt.get("findings") != []
        or receipt.get("failure_classification") != "invalid_review_output"
        or type(receipt.get("returncode")) is not int
        or receipt["returncode"] != 126
        or receipt.get("error") != "Grok review stream used unsupported event type: error"
        or type(receipt.get("review_document_bytes")) is not int
        or receipt["review_document_bytes"] != 0
        or receipt.get("review_document_sha256") is not None
        or receipt.get("review_document_normalizations") != []
        or receipt.get("review_findings_normalized") is not False
        or receipt.get("review_input_source") != "committed_diff"
        or type(receipt.get("review_input_bytes")) is not int
        or not 0 < receipt["review_input_bytes"] <= 1024 * 1024
        or not isinstance(receipt.get("review_input_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt["review_input_sha256"]) is None
    ):
        return False
    probe = receipt.get("post_failure_toolchain_probe")
    if (
        not isinstance(probe, dict)
        or probe.get("passed") is not True
        or probe.get("failure_classification") != "passed"
        or probe.get("missing_executable") is not False
        or probe.get("missing_python_module") is not False
    ):
        return False
    provider_fields = {
        "review_provider_available_commands_events",
        "review_provider_available_tools",
        "review_provider_completed_commands",
        "review_provider_completed_tool_calls",
        "review_provider_completed_tools",
        "review_provider_stream_bytes",
        "review_provider_stream_contract",
        "review_provider_stream_events",
        "review_provider_stream_sha256",
    }
    if (
        {key for key in receipt if key.startswith("review_provider_")} != provider_fields
        or receipt.get("review_provider_stream_contract")
        != "grok-streaming-json-bound-diff-review-v2"
        or type(receipt.get("review_provider_stream_events")) is not int
        or receipt["review_provider_stream_events"] != 3
        # The original parser returns on the unsupported "error" event
        # before committing its in-progress available-command count.
        or type(receipt.get("review_provider_available_commands_events")) is not int
        or receipt["review_provider_available_commands_events"] != 0
        or receipt.get("review_provider_available_tools") != []
        or receipt.get("review_provider_completed_commands") != []
        or type(receipt.get("review_provider_completed_tool_calls")) is not int
        or receipt["review_provider_completed_tool_calls"] != 0
        or receipt.get("review_provider_completed_tools") != []
    ):
        return False
    stdout = receipt.get("stdout_tail")
    stderr = receipt.get("stderr_tail")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return False
    raw_stdout = stdout.encode("utf-8")
    raw_stderr = stderr.encode("utf-8")
    if (
        not raw_stdout or len(raw_stdout) > 4096
        or type(receipt.get("stdout_bytes")) is not int
        or receipt["stdout_bytes"] != len(raw_stdout)
        or receipt.get("stdout_sha256") != hashlib.sha256(raw_stdout).hexdigest()
        or type(receipt.get("review_provider_stream_bytes")) is not int
        or receipt["review_provider_stream_bytes"] != len(raw_stdout)
        or receipt.get("review_provider_stream_sha256") != receipt["stdout_sha256"]
        or type(receipt.get("stderr_bytes")) is not int
        or receipt["stderr_bytes"] != len(raw_stderr)
        or receipt.get("stderr_sha256") != hashlib.sha256(raw_stderr).hexdigest()
    ):
        return False

    error_message = (
        "API error (status 402 Payment Required): "
        "Grok Build usage balance exhausted"
    )
    wrapped = (
        'Internal error: {\n  "message": "' + error_message
        + '",\n  "http_status": 402\n}'
    )
    if stderr != "Error: " + wrapped + "\n":
        return False
    # No silent duplicate JSON member, Unicode alias, partial/truncated stream,
    # embedded prose, usage, tool event or end_turn can masquerade as zero work.
    lines = stdout.splitlines(keepends=True)
    if len(lines) != 3 or any(not line.endswith("\n") for line in lines):
        return False

    def reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate Grok quota stream key")
            value[key] = item
        return value

    try:
        events = [
            json.loads(line[:-1], object_pairs_hook=reject_duplicate_members)
            for line in lines
        ]
    except (ValueError, UnicodeError):
        return False
    six_commands = [
        "compact", "always-approve", "context",
        "session-info", "feedback", "goal",
    ]
    # These are the only two complete provider preflight sequences proven
    # in immutable, origin-bound failed review receipts. Do not accept subsets,
    # mixed lists, reordered commands or any additional result/tool events.
    known_commands = (
        six_commands,
        [*six_commands[:2], "memory", *six_commands[2:]],
    )
    return any(
        events == [
            {"type": "available_commands", "tools": [], "commands": commands},
            {"type": "available_commands", "tools": [], "commands": commands},
            {"type": "error", "message": wrapped},
        ]
        for commands in known_commands
    )


def _validated_review_role_evidence(
    metadata: dict[str, Any], binding: dict[str, Any], provenance: dict[str, Any] | None,
    *, directory: Path | None = None, parent_fd: int | None = None,
    aggregate_bytes: list[int] | None = None,
    external_v1_snapshots: list[tuple[Path, tuple[int, ...], tuple[int, ...] | None]] | None = None,
) -> dict[str, Any] | None:
    if provenance is None:
        return None
    # V1 allowed caller-selected private files in shared directories. Retain
    # its fd/no-follow/owner/nlink/size checks; require a private parent for
    # new V2 job-owned receipts only.
    receipt_path = Path(provenance["role_receipt_path"])
    pinned_receipt_fd = None
    if provenance["schema_version"] == 2 and parent_fd is not None:
        if (
            directory is None
            or receipt_path != directory / REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
        ):
            raise ValueError("review role receipt directory binding mismatch")
        pinned_receipt_fd = parent_fd
    receipt = _read_private_json(
        receipt_path, MAX_ROLE_RECEIPT_BYTES,
        require_private_parent=provenance["schema_version"] == 2,
        parent_fd=pinned_receipt_fd,
        aggregate_metadata_bytes=aggregate_bytes,
        external_v1_snapshots=(
            external_v1_snapshots if provenance["schema_version"] == 1 else None
        ),
    )
    expected_receipt_sha256 = _agent_role_receipt_sha256(receipt)
    if receipt.get("receipt_sha256") != expected_receipt_sha256:
        raise ValueError("decision review role receipt digest mismatch")
    workspace_diff = provenance["workspace_diff_sha256"]
    expected_fields = {
        "schema_version": 1,
        "role": "review",
        "expected_head": binding["head_sha"],
        "expected_base_head": binding["base_sha"],
        "expected_diff_sha256": workspace_diff,
        "expected_dirty": False,
        "head_before": binding["head_sha"],
        "head_after": binding["head_sha"],
        "diff_after": workspace_diff,
        "worktree_dirty_after": False,
        "sandbox": REVIEW_ROLE_SANDBOX,
        "review_receipt_generated_by": REVIEW_ROLE_MODULE,
        "argv_sha256": provenance["reviewer_command_sha256"],
    }
    if provenance["schema_version"] == 2:
        expected_fields.update({
            "review_attempt_unit": metadata["unit"],
            "review_attempt_origin_sha256": metadata["origin_sha256"],
        })
    for key, expected_value in expected_fields.items():
        if receipt.get(key) != expected_value:
            raise ValueError(f"decision review role receipt {key} mismatch")
    verdict = receipt.get("verdict")
    findings = receipt.get("findings")
    failure_classification = receipt.get("failure_classification")
    result: dict[str, Any] | None = None
    if verdict == "PASS" and findings == [] and receipt.get("returncode") == 0 and failure_classification == "passed":
        result = {**normalize_binding(binding), "verdict": "PASS_THIS_REVISION", "material_findings": 0}
    elif (
        verdict in {"NEEDS_CHANGE", "BLOCK"}
        and isinstance(findings, list) and findings
        and all(isinstance(item, dict) for item in findings)
        and failure_classification == "review_verdict"
    ):
        result = {**normalize_binding(binding), "verdict": "REJECT_THIS_REVISION", "material_findings": len(findings)}
    return {
        "role_verified": True,
        "route_verified": True,
        "independence_verified": True,
        "role_receipt_sha256": expected_receipt_sha256,
        "review_route": provenance["review_route"],
        "result": result,
        "pre_result_quota_failure_verified": (
            result is None
            and (
                _proven_claude_quota_failure_before_review(receipt, provenance)
                or _proven_grok_quota_failure_before_review(receipt, provenance)
            )
        ),
    }


def _binding_matches_pr_head(
    binding: dict[str, Any], expected: dict[str, Any]
) -> bool:
    return (
        binding["repo"] == expected["repo"]
        and binding["pr"] == expected["pr"]
        and binding["head_sha"] == expected["head_sha"]
    )


def _attempt_started_after(candidate: dict[str, Any], prior: dict[str, Any]) -> bool:
    candidate_created = candidate.get("created_at_unix")
    prior_created = prior.get("created_at_unix")
    if (
        isinstance(candidate_created, bool)
        or not isinstance(candidate_created, int)
        or candidate_created < 0
        or isinstance(prior_created, bool)
        or not isinstance(prior_created, int)
        or prior_created < 0
    ):
        return False
    if candidate_created != prior_created:
        return candidate_created > prior_created

    candidate_ns = candidate.get("started_at_unix_ns")
    prior_ns = prior.get("started_at_unix_ns")
    if (
        isinstance(candidate_ns, bool)
        or not isinstance(candidate_ns, int)
        or candidate_ns < 0
        or isinstance(prior_ns, bool)
        or not isinstance(prior_ns, int)
        or prior_ns < 0
        or candidate_ns // 1_000_000_000 != candidate_created
        or prior_ns // 1_000_000_000 != prior_created
    ):
        return False
    return candidate_ns > prior_ns



def _external_v1_role_receipts_unchanged(
    snapshots: list[tuple[Path, tuple[int, ...], tuple[int, ...] | None]],
) -> bool:
    """Recheck every earlier external V1 receipt after the full registry scan.

    Unlike V2 evidence, historical V1 role receipts can reside outside the
    scanned job directory. No receipt is reinterpreted or granted authority
    here; this only invalidates prior observations if their path, parent or
    physical file identity changed.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    for path, parent_identity, file_identity in snapshots:
        try:
            parent_fd = os.open(path.parent, flags)
            try:
                if _review_stat_parent_identity(os.fstat(parent_fd)) != parent_identity:
                    return False
                try:
                    observed = os.stat(
                        path.name, dir_fd=parent_fd, follow_symlinks=False
                    )
                except FileNotFoundError:
                    if file_identity is not None:
                        return False
                else:
                    if (
                        file_identity is None
                        or _review_stat_file_identity(observed) != file_identity
                    ):
                        return False
            finally:
                os.close(parent_fd)
        except OSError:
            return False
    return True


def _review_child_file_snapshot(
    directory_fd: int,
) -> tuple[tuple[str, tuple[int, ...] | None], ...]:
    """Bounded no-follow snapshots of files whose in-place writes can hide R3.

    A directory's mtime/ctime does not advance when an existing child file is
    rewritten. Keep the first file-level stat preimages and verify them both
    after examining a job and at the end of the complete registry scan.
    This is drift detection, not authentication against prior same-UID edits.
    """
    snapshots: list[tuple[str, tuple[int, ...] | None]] = []
    for name in (
        "metadata.json", "stdout.log", "stderr.log", "finalization.json",
        REVIEW_ROLE_ATTEMPT_RECEIPT_NAME, "review-role-receipt.json",
    ):
        try:
            value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            snapshots.append((name, None))
            continue
        snapshots.append((name, (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
        )))
    return tuple(snapshots)


def _iter_pinned_review_job_directories(
    root: Path, errors: list[str], metadata_budget: list[int], *,
    expected: dict[str, Any], unbound_stdout_budget: list[int],
) -> Iterator[tuple[Path, int]]:
    dir_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, dir_flags)
    except OSError:
        errors.append("decision_review_jobs_root_invalid")
        return
    try:
        root_stat = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o077
        ):
            errors.append("decision_review_jobs_root_invalid")
            return
        names: list[tuple[str, int, int]] = []
        # Child writes do not advance the jobs root mtime. Revalidate each
        # processed child's pinned directory identity after the whole scan.
        inspected_children: list[tuple[str, tuple[int, ...], tuple[Any, ...]]] = []
        seen = 0
        with os.scandir(root_fd) as entries:
            for entry in entries:
                seen += 1
                if seen > MAX_JOB_DIRECTORIES:
                    errors.append("decision_review_job_inventory_truncated")
                    return
                if _UNIT_RE.fullmatch(entry.name) is not None:
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        errors.append("decision_review_job_inventory_unverifiable")
                        return
                    if not stat.S_ISDIR(entry_stat.st_mode):
                        errors.append("decision_review_job_inventory_unverifiable")
                        return
                    # Bind the observed dentry inode to its later O_NOFOLLOW fd.
                    names.append((entry.name, entry_stat.st_dev, entry_stat.st_ino))
                    continue
                try:
                    if entry.is_symlink():
                        errors.append("decision_review_noncanonical_job_unverifiable")
                        return
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    errors.append("decision_review_noncanonical_job_unverifiable")
                    return
                if not is_dir:
                    if entry.name.startswith("grabowski-job-"):
                        errors.append("decision_review_noncanonical_job_unverifiable")
                        return
                    continue
                try:
                    foreign_fd = os.open(entry.name, dir_flags, dir_fd=root_fd)
                except OSError:
                    errors.append("decision_review_noncanonical_job_unverifiable")
                    return
                foreign_files_before = None
                try:
                    foreign_stat = os.fstat(foreign_fd)
                    if (
                        not stat.S_ISDIR(foreign_stat.st_mode)
                        or foreign_stat.st_uid != os.geteuid()
                        or stat.S_IMODE(foreign_stat.st_mode) & 0o077
                    ):
                        errors.append("decision_review_noncanonical_job_unverifiable")
                        return
                    # Pin both the directory and the already existing files.
                    # In-place writes do not change the directory timestamps.
                    foreign_files_before = _review_child_file_snapshot(foreign_fd)
                    inspected_children.append((entry.name, (
                        foreign_stat.st_dev, foreign_stat.st_ino,
                        foreign_stat.st_mode, foreign_stat.st_uid,
                        foreign_stat.st_nlink, foreign_stat.st_mtime_ns,
                        foreign_stat.st_ctime_ns,
                    ), foreign_files_before))
                    # RepoGround rgpm jobs are a separate, signed job namespace.
                    # Inspect their metadata, but NEVER admit them as DecisionReviews.
                    if _RGPM_UNIT_RE.fullmatch(entry.name) is None:
                        try:
                            os.stat("metadata.json", dir_fd=foreign_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            # A renamed old R3 job may retain an exact-bound
                            # REJECT stdout even when its metadata is missing.
                            # Unknown noncanonical bundles are still harmless
                            # only when no such secondary evidence survives.
                            try:
                                if _unbound_review_result_visible(
                                    root / entry.name, parent_fd=foreign_fd,
                                    aggregate_bytes=unbound_stdout_budget,
                                    expected=expected,
                                    allow_legacy_readable_stdout=True,
                                ):
                                    errors.append(
                                        f"decision_review_unbound_result:{entry.name}"
                                    )
                                    return
                            except FileNotFoundError:
                                pass  # A genuine bundle may have no stdout.
                            except (OSError, ValueError) as exc:
                                errors.append(
                                    f"decision_review_unbound_evidence_invalid:"
                                    f"{entry.name}:{type(exc).__name__}"
                                )
                                return
                            continue
                        except OSError:
                            errors.append("decision_review_noncanonical_job_unverifiable")
                            return
                        errors.append("decision_review_noncanonical_job_directory")
                        return
                    try:
                        foreign_metadata = _read_private_json(
                            root / entry.name / "metadata.json", MAX_METADATA_BYTES,
                            parent_fd=foreign_fd,
                            aggregate_metadata_bytes=metadata_budget,
                        )
                    except FileNotFoundError:
                        foreign_metadata = None  # Historical rgpm jobs may lack metadata.
                    except (OSError, ValueError):
                        errors.append("decision_review_noncanonical_job_unverifiable")
                        return
                    if foreign_metadata is not None:
                        try:
                            foreign_origin = job_origin.validate_origin(
                                foreign_metadata.get("origin"),
                                foreign_metadata.get("origin_sha256"),
                                expected_unit=entry.name,
                            )
                            if any(
                                foreign_metadata.get(key) != foreign_origin.get(key)
                                for key in ("unit", "job_id", "owner", "argv_sha256", "scope")
                            ):
                                raise ValueError("foreign job metadata origin mismatch")
                            foreign_scope = foreign_origin.get("scope")
                            if (
                                not isinstance(foreign_scope, dict)
                                or foreign_scope.get("decision_bound_review") is not None
                            ):
                                raise ValueError("foreign job may contain a review decision")
                        except ValueError:
                            errors.append("decision_review_noncanonical_job_unverifiable")
                            return
                    # A hash-valid rgpm/ordinary Origin cannot prove a formerly
                    # bound review never existed. The canonical job might have
                    # been renamed and rebound while retaining a material REJECT.
                    # Reuse the same bounded FD-pinned secondary-evidence check;
                    # never grant foreign jobs a PASS or advance their clock.
                    try:
                        if _unbound_review_result_visible(
                            root / entry.name, parent_fd=foreign_fd,
                            aggregate_bytes=unbound_stdout_budget, expected=expected,
                            allow_legacy_readable_stdout=True,
                        ):
                            errors.append(f"decision_review_unbound_result:{entry.name}")
                            return
                    except FileNotFoundError:
                        # Legitimate historic rgpm jobs may lack stdout. A
                        # matching role receipt would already have blocked above.
                        pass
                    except (OSError, ValueError) as exc:
                        errors.append(
                            f"decision_review_unbound_evidence_invalid:"
                            f"{entry.name}:{type(exc).__name__}"
                        )
                        return
                    continue
                except OSError:
                    errors.append("decision_review_noncanonical_job_unverifiable")
                    return
                finally:
                    if foreign_files_before is not None:
                        try:
                            if _review_child_file_snapshot(foreign_fd) != foreign_files_before:
                                errors.append("decision_review_job_file_changed")
                        except OSError:
                            errors.append("decision_review_job_file_changed")
                    os.close(foreign_fd)
        if errors:
            return
        for unit, expected_dev, expected_ino in sorted(names):
            try:
                job_fd = os.open(unit, dir_flags, dir_fd=root_fd)
            except OSError:
                errors.append("decision_review_job_inventory_unverifiable")
                return
            job_stat = None
            job_files_before = None
            try:
                job_stat = os.fstat(job_fd)
                if (
                    not stat.S_ISDIR(job_stat.st_mode)
                    or job_stat.st_uid != os.geteuid()
                    or stat.S_IMODE(job_stat.st_mode) & 0o077
                    or (job_stat.st_dev, job_stat.st_ino) != (expected_dev, expected_ino)
                ):
                    errors.append("decision_review_job_inventory_unverifiable")
                    return
                job_files_before = _review_child_file_snapshot(job_fd)
                yield root / unit, job_fd
            finally:
                try:
                    if job_stat is not None:
                        job_after = os.fstat(job_fd)
                        if (
                            job_after.st_mtime_ns != job_stat.st_mtime_ns
                            or job_after.st_ctime_ns != job_stat.st_ctime_ns
                        ):
                            errors.append("decision_review_job_directory_changed")
                        elif job_files_before is not None:
                            if _review_child_file_snapshot(job_fd) != job_files_before:
                                errors.append("decision_review_job_file_changed")
                            else:
                                inspected_children.append((unit, (
                                    job_after.st_dev, job_after.st_ino,
                                    job_after.st_mode, job_after.st_uid,
                                    job_after.st_nlink, job_after.st_mtime_ns,
                                    job_after.st_ctime_ns,
                                ), job_files_before))
                except OSError:
                    errors.append("decision_review_job_directory_changed")
                finally:
                    os.close(job_fd)
        # An earlier stub may publish metadata or a material REJECT while
        # a later child is being evaluated. A final root-only stat misses it.
        for unit, snapshot, files_before in inspected_children:
            try:
                child_fd = os.open(unit, dir_flags, dir_fd=root_fd)
                try:
                    child_after = os.fstat(child_fd)
                    files_after = _review_child_file_snapshot(child_fd)
                finally:
                    os.close(child_fd)
            except OSError:
                errors.append("decision_review_job_directory_changed")
                return
            if (
                not stat.S_ISDIR(child_after.st_mode)
                or (
                    child_after.st_dev, child_after.st_ino,
                    child_after.st_mode, child_after.st_uid,
                    child_after.st_nlink, child_after.st_mtime_ns,
                    child_after.st_ctime_ns,
                ) != snapshot
            ):
                errors.append("decision_review_job_directory_changed")
                return
            if files_after != files_before:
                errors.append("decision_review_job_file_changed")
                return
        try:
            after = os.stat(root, follow_symlinks=False)
        except OSError:
            errors.append("decision_review_jobs_root_invalid")
            return
        if (
            root_stat.st_dev, root_stat.st_ino,
            root_stat.st_mtime_ns, root_stat.st_ctime_ns,
        ) != (
            after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns,
        ):
            errors.append("decision_review_jobs_root_changed")
    finally:
        os.close(root_fd)


def reconcile(
    *,
    repo: str,
    pr: int,
    head_sha: str,
    base_sha: str,
    diff_sha256: str,
    equivalent_diff_sha256s: list[str] | tuple[str, ...] | None = None,
    defer_diff_identity: bool = False,
    jobs_root: Path | None = None,
) -> dict[str, Any]:
    expected = normalize_binding(
        {
            "schema_version": BINDING_SCHEMA_VERSION,
            "kind": BINDING_KIND,
            "repo": repo,
            "pr": pr,
            "head_sha": head_sha,
            "base_sha": base_sha,
            "diff_sha256": diff_sha256,
            "slot": "merge-gate-probe",
        }
    )
    expected.pop("slot")
    if not isinstance(defer_diff_identity, bool):
        raise ValueError("decision review defer_diff_identity must be boolean")
    aliases = [] if equivalent_diff_sha256s is None else equivalent_diff_sha256s
    if not isinstance(aliases, (list, tuple)):
        raise ValueError("decision review equivalent diff digests must be a list or tuple")
    accepted_diff_sha256s = {expected["diff_sha256"]}
    for alias in aliases:
        if (
            not isinstance(alias, str)
            or _SHA256_RE.fullmatch(alias.strip().lower()) is None
        ):
            raise ValueError("decision review equivalent diff digest must be SHA-256")
        accepted_diff_sha256s.add(alias.strip().lower())
    accepted_diff_sha256s_projection = sorted(accepted_diff_sha256s)
    root = JOBS_ROOT if jobs_root is None else Path(jobs_root)
    errors: list[str] = []
    attempts: list[dict[str, Any]] = []
    if not root.exists():
        return {
            "schema_version": 1,
            "kind": "grabowski_decision_review_reconciliation",
            "status": "not_applicable",
            "binding": expected,
            "binding_sha256": sha256_json(expected),
            "accepted_diff_sha256s": accepted_diff_sha256s_projection,
            "accepted_diff_sha256s_sha256": sha256_json(accepted_diff_sha256s_projection),
            "attempt_count": 0,
            "skipped_prelaunch_stub_count": 0,
            "skipped_prelaunch_stub_units_sha256": sha256_json([]),
            "slot_count": 0,
            "slots": [],
            "errors": [],
            "does_not_establish": [
                "review_quality",
                "semantic_correctness",
                "reviews_started_outside_grabowski_job_start",
            ],
        }
    metadata_budget = [0]
    unbound_stdout_budget = [0]
    external_v1_snapshots: list[tuple[Path, tuple[int, ...], tuple[int, ...] | None]] = []
    skipped_prelaunch_stubs: list[str] = []
    iterator = _iter_pinned_review_job_directories(
        root, errors, metadata_budget, expected=expected,
        unbound_stdout_budget=unbound_stdout_budget,
    )
    review_attempt_count = 0
    with closing(iterator):
        for directory, directory_fd in iterator:
            raw_targets_pr_head = False
            try:
                try:
                    raw_metadata = _read_private_json(
                        directory / "metadata.json", MAX_METADATA_BYTES,
                        parent_fd=directory_fd, aggregate_metadata_bytes=metadata_budget,
                    )
                except FileNotFoundError:
                    if _exact_empty_prelaunch_stub(directory_fd):
                        skipped_prelaunch_stubs.append(directory.name)
                        continue
                    raise
                raw_scope = raw_metadata.get("scope")
                raw_review_binding = (
                    raw_scope.get("decision_bound_review")
                    if isinstance(raw_scope, dict)
                    else None
                )
                raw_origin = raw_metadata.get("origin")
                raw_origin_scope = (
                    raw_origin.get("scope")
                    if isinstance(raw_origin, dict) else None
                )
                raw_origin_binding = (
                    raw_origin_scope.get("decision_bound_review")
                    if isinstance(raw_origin_scope, dict) else None
                )
                raw_targets_pr_head = (
                    _raw_binding_targets_pr_head(raw_review_binding, expected)
                    or _raw_binding_targets_pr_head(raw_origin_binding, expected)
                )
                if raw_review_binding is not None or raw_origin_binding is not None:
                    review_attempt_count += 1
                    if review_attempt_count > MAX_BOUND_REVIEW_JOBS:
                        errors.append("decision_review_attempt_inventory_truncated")
                        attempts = []
                        break
                metadata, binding, provenance = _validated_origin_binding(
                    directory, raw_metadata=raw_metadata, parent_fd=directory_fd,
                    expected=expected,
                )
            except ReviewMetadataBudgetExceeded:
                errors.append("decision_review_metadata_aggregate_budget_exceeded")
                attempts = []
                break
            except (FileNotFoundError, OSError, ValueError) as exc:
                # Missing or corrupted canonical metadata could conceal a
                # material REJECT, regardless of any recoverable PR/head hint.
                # Do not infer a legacy exemption from absence of evidence.
                errors.append(
                    f"decision_review_origin_invalid:{directory.name}:{type(exc).__name__}"
                )
                continue
            if binding is None or not _binding_matches_pr_head(binding, expected):
                # A review origin rewritten as an ordinary job OR as a valid
                # review for a foreign revision must not conceal surviving
                # evidence from this PR/head.
                try:
                    if _unbound_review_result_visible(
                        directory, parent_fd=directory_fd,
                        aggregate_bytes=unbound_stdout_budget,
                        expected=expected,
                    ):
                        errors.append(f"decision_review_unbound_result:{directory.name}")
                except (OSError, ValueError) as exc:
                    errors.append(
                        f"decision_review_unbound_evidence_invalid:"
                        f"{directory.name}:{type(exc).__name__}"
                    )
                continue

            attempt: dict[str, Any] = {
                "unit": directory.name,
                "slot": binding["slot"],
                "origin_sha256": metadata.get("origin_sha256"),
                "created_at_unix": metadata["origin"].get("created_at_unix"),
                "started_at_unix_ns": metadata["scope"].get("started_at_unix_ns"),
                "terminal": False,
                "terminal_status": None,
                "classification": "unresolved",
                "verdict": None,
                "material_findings": None,
                "result_sha256": None,
                "stdout_tail_sha256": None,
                "review_role_verified": False,
                "review_route_verified": False,
                "review_route_id": None,
                "review_provider_family": None,
                "independence_verified": False,
                "review_role_receipt_sha256": None,
                "diff_identity_deferred": False,
            }
            if binding["base_sha"] != expected["base_sha"]:
                errors.append(f"decision_review_base_sha_drift:{directory.name}")
                attempt["classification"] = "binding_drift"
                attempts.append(attempt)
                continue
            diff_binding_drift = False
            if binding["diff_sha256"] not in accepted_diff_sha256s:
                if defer_diff_identity:
                    attempt["diff_identity_deferred"] = True
                else:
                    diff_binding_drift = True
            if _proven_not_started(metadata):
                attempt["terminal"] = True
                attempt["terminal_status"] = "launch_failed"
                if diff_binding_drift:
                    errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
                    attempt["classification"] = "binding_drift"
                else:
                    attempt["classification"] = "infrastructure_error"
                attempts.append(attempt)
                continue
            try:
                finalization = _validated_finalization(directory, metadata, parent_fd=directory_fd)
            except (FileNotFoundError, OSError, ValueError) as exc:
                errors.append(f"decision_review_finalization_invalid:{directory.name}:{type(exc).__name__}")
                attempt["classification"] = "invalid_finalization"
                attempts.append(attempt)
                continue
            if finalization is None:
                errors.append(f"decision_review_not_terminal:{directory.name}")
                attempt["classification"] = "not_terminal"
                attempts.append(attempt)
                continue
            attempt["terminal"] = True
            attempt["terminal_status"] = finalization["final_status"]
            try:
                stdout_text, stdout_tail_sha256 = _read_stdout_tail(directory / "stdout.log", parent_fd=directory_fd)
                attempt["stdout_tail_sha256"] = stdout_tail_sha256
            except (FileNotFoundError, OSError, ValueError) as exc:
                errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
                attempt["classification"] = "invalid_result"
                attempts.append(attempt)
                continue
            try:
                role_evidence = _validated_review_role_evidence(
                    metadata, binding, provenance, directory=directory,
                    parent_fd=directory_fd, aggregate_bytes=metadata_budget,
                    external_v1_snapshots=external_v1_snapshots,
                )
            except FileNotFoundError as exc:
                # A drifted diff binding is repairable only when a valid provenance-
                # bound role receipt proves that no semantic review result exists.
                # Missing role evidence cannot establish that narrow condition.
                if diff_binding_drift:
                    errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
                    attempt["classification"] = "binding_drift"
                    attempts.append(attempt)
                    continue
                # A non-success terminal provenance-bound reviewer whose role
                # receipt was never created has no semantic review result. Treat
                # only the known pre-result termination states like the existing
                # no-marker infrastructure path so a later exact-bound PASS can
                # supersede them. A succeeded reviewer missing its create-only
                # receipt is contradictory and remains fail-closed, as do malformed,
                # unreadable or binding-invalid receipts below.
                # The V2 reviewer can have finished a material REJECT before a
                # failed receipt write. A missing receipt is not proof of a
                # pre-review failure, even when systemd reports a failed unit.
                # Only a server-proven non-start above can be retried safely.
                if (
                    (provenance is None or provenance.get("schema_version") != 2)
                    and attempt["terminal_status"] in _PRE_RESULT_INFRASTRUCTURE_STATUSES
                ):
                    attempt["classification"] = "infrastructure_error"
                    attempts.append(attempt)
                    continue
                errors.append(
                    f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}"
                )
                attempt["classification"] = "invalid_result"
                attempts.append(attempt)
                continue
            except (OSError, ValueError) as exc:
                errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
                attempt["classification"] = "invalid_result"
                attempts.append(attempt)
                continue
            if role_evidence is not None:
                attempt["review_role_verified"] = role_evidence["role_verified"]
                attempt["review_route_verified"] = role_evidence["route_verified"]
                attempt["independence_verified"] = role_evidence["independence_verified"]
                attempt["review_role_receipt_sha256"] = role_evidence["role_receipt_sha256"]
                review_route = role_evidence.get("review_route")
                if isinstance(review_route, dict):
                    attempt["review_route_id"] = review_route.get("route_id")
                    attempt["review_provider_family"] = review_route.get("provider_family")
                result = role_evidence["result"]
            else:
                try:
                    result = _parse_result_marker(stdout_text, binding)
                except ValueError as exc:
                    errors.append(f"decision_review_result_invalid:{directory.name}:{type(exc).__name__}")
                    attempt["classification"] = "invalid_result"
                    attempts.append(attempt)
                    continue
            if result is not None:
                attempt["result_sha256"] = sha256_json(result)
                attempt["verdict"] = result["verdict"]
                attempt["material_findings"] = result["material_findings"]
            if diff_binding_drift:
                # Never accept a semantic PASS/REJECT for an unproven diff identity.
                # A terminal failed reviewer with no formal semantic result is
                # different: it established no review decision at all, so it may be
                # superseded by a later exact-bound PASS in the same slot.
                if (
                    result is None
                    and attempt["terminal_status"] in _PRE_RESULT_INFRASTRUCTURE_STATUSES
                    and (provenance is None or provenance.get("schema_version") != 2)
                ):
                    attempt["classification"] = "infrastructure_error"
                    attempts.append(attempt)
                    continue
                errors.append(f"decision_review_diff_sha256_drift:{directory.name}")
                attempt["classification"] = "binding_drift"
                attempts.append(attempt)
                continue
            if result is None:
                # A V2 role receipt containing malformed or non-semantic output
                # cannot prove whether the provider emitted a material finding.
                # Preserve legacy handling for old immutable attempts, but never
                # supersede the new ambiguous evidence on a later PASS.
                if provenance is not None and provenance.get("schema_version") == 2:
                    if (
                        role_evidence is not None
                        and role_evidence.get("pre_result_quota_failure_verified") is True
                        and attempt["terminal_status"] in _PRE_RESULT_INFRASTRUCTURE_STATUSES
                        and attempt["terminal_status"] == "failed"
                    ):
                        attempt["classification"] = "infrastructure_error"
                        attempt["pre_result_quota_failure_verified"] = True
                    else:
                        attempt["classification"] = "invalid_result"
                        errors.append(f"decision_review_result_invalid:{directory.name}:InvalidReviewDocument")
                else:
                    attempt["classification"] = "infrastructure_error"
                attempts.append(attempt)
                continue
            if result["verdict"] == "REJECT_THIS_REVISION":
                attempt["classification"] = "material_reject"
                errors.append(f"decision_review_material_reject:{binding['slot']}:{directory.name}")
            elif finalization["final_status"] != "succeeded":
                attempt["classification"] = "pass_from_failed_job"
                errors.append(f"decision_review_pass_from_failed_job:{directory.name}")
            else:
                attempt["classification"] = "pass"
            attempts.append(attempt)

    if not _external_v1_role_receipts_unchanged(external_v1_snapshots):
        errors.append("decision_review_external_role_receipt_changed")

    slots: list[dict[str, Any]] = []
    for slot in sorted({str(item["slot"]) for item in attempts}):
        slot_attempts = [item for item in attempts if item["slot"] == slot]
        passes = [item for item in slot_attempts if item["classification"] == "pass"]
        independent_passes = [
            item for item in passes if item.get("independence_verified") is True
        ]
        rejects = [
            item for item in slot_attempts if item["classification"] == "material_reject"
        ]
        unresolved = [
            item
            for item in slot_attempts
            if item["classification"]
            not in {"pass", "material_reject", "infrastructure_error"}
        ]
        infrastructure = [
            item
            for item in slot_attempts
            if item["classification"] == "infrastructure_error"
        ]
        unsuperseded_infrastructure = []
        for infrastructure_attempt in infrastructure:
            eligible_passes = passes
            if infrastructure_attempt.get("pre_result_quota_failure_verified") is True:
                # A legacy generic PASS cannot replace authenticated Claude
                # quota evidence. The later PASS itself must be independent
                # and from the same provider family, not merely an old PASS.
                family = infrastructure_attempt.get("review_provider_family")
                eligible_passes = [
                    item for item in independent_passes
                    if item.get("review_provider_family") == family
                ]
            if not any(
                _attempt_started_after(pass_attempt, infrastructure_attempt)
                for pass_attempt in eligible_passes
            ):
                unsuperseded_infrastructure.append(infrastructure_attempt)
        if not passes and not rejects:
            errors.append(f"decision_review_slot_without_pass:{slot}")
        named_family = _named_slot_provider_family(slot)
        if named_family is not None and not any(
            attempt["classification"] == "pass"
            and attempt.get("independence_verified") is True
            and attempt.get("review_provider_family") == named_family
            for attempt in slot_attempts
        ):
            errors.append(
                f"decision_review_named_provider_slot_without_independent_pass:{slot}"
            )
        for infrastructure_attempt in unsuperseded_infrastructure:
            errors.append(
                "decision_review_infrastructure_not_superseded:"
                f"{slot}:{infrastructure_attempt['unit']}"
            )
        slots.append(
            {
                "slot": slot,
                "attempt_count": len(slot_attempts),
                "pass_count": len(passes),
                "independent_pass_count": len(independent_passes),
                "material_reject_count": len(rejects),
                "infrastructure_error_count": len(infrastructure),
                "unresolved_count": len(unresolved),
                "units_sha256": sha256_json(sorted(item["unit"] for item in slot_attempts)),
            }
        )

    errors = sorted(set(errors))
    status = "not_applicable" if not attempts and not errors else "blocked" if errors else "settled"
    attempts_projection = [
        {
            key: item[key]
            for key in (
                "unit",
                "slot",
                "origin_sha256",
                "created_at_unix",
                "started_at_unix_ns",
                "terminal",
                "terminal_status",
                "classification",
                "verdict",
                "material_findings",
                "result_sha256",
                "stdout_tail_sha256",
                "review_role_verified",
                "review_route_verified",
                "review_route_id",
                "review_provider_family",
                "independence_verified",
                "review_role_receipt_sha256",
                "diff_identity_deferred",
            )
        }
        for item in sorted(attempts, key=lambda item: (str(item["slot"]), str(item["unit"])))
    ]
    return {
        "schema_version": 1,
        "kind": "grabowski_decision_review_reconciliation",
        "status": status,
        "binding": expected,
        "binding_sha256": sha256_json(expected),
        "accepted_diff_sha256s": accepted_diff_sha256s_projection,
        "accepted_diff_sha256s_sha256": sha256_json(accepted_diff_sha256s_projection),
        "attempt_count": len(attempts_projection),
        "skipped_prelaunch_stub_count": len(skipped_prelaunch_stubs),
        "skipped_prelaunch_stub_units_sha256": sha256_json(sorted(skipped_prelaunch_stubs)),
        "slot_count": len(slots),
        "slots": slots,
        "deferred_diff_identity_count": sum(
            1 for item in attempts_projection if item["diff_identity_deferred"]
        ),
        "attempts": attempts_projection,
        "attempts_sha256": sha256_json(attempts_projection),
        "errors": errors,
        "read_by_merge_guard": bool(attempts_projection),
        "does_not_establish": [
            "review_quality",
            "semantic_correctness",
            "reviews_started_outside_grabowski_job_start",
            "absence_of_same_uid_out_of_band_file_tampering",
        ],
    }

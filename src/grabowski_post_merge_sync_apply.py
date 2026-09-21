from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any, Callable

import grabowski_resources as resources


CommandRunner = Callable[[Path, list[str]], dict[str, Any]]
RemoteHeadReader = Callable[[str, bool], str]
PinnedTargetFactory = Callable[[str], tuple[str, str]]

CONFIRMATION = "apply-protected-post-merge-sync"
PROTECTED_BRANCHES = frozenset({"main", "master"})
REMOTE_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
LEASE_TTL_SECONDS = 900


class PostMergeSyncApplyError(RuntimeError):
    pass


class PostMergeSyncNonFastForward(PostMergeSyncApplyError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _run(
    repo: Path,
    runner: CommandRunner,
    argv: list[str],
    *,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    result = runner(repo, argv)
    try:
        returncode = int(result.get("returncode", 1))
    except (AttributeError, TypeError, ValueError) as exc:
        raise PostMergeSyncApplyError("Git runner returned an invalid result") from exc
    if returncode not in allowed_returncodes:
        message = str(result.get("stderr") or result.get("stdout") or "git command failed")
        raise PostMergeSyncApplyError(
            f"git {' '.join(argv)} failed with {returncode}: {message}"
        )
    return result


def _stdout(result: dict[str, Any]) -> str:
    return str(result.get("stdout", "")).strip()


def _resolve_git_path(repo: Path, raw: str) -> Path:
    value = Path(raw).expanduser()
    if not value.is_absolute():
        value = repo / value
    return value.resolve(strict=True)


def _checkout_identity(repo: Path, runner: CommandRunner) -> dict[str, Any]:
    top = _run(repo, runner, ["rev-parse", "--show-toplevel"])
    common = _run(repo, runner, ["rev-parse", "--git-common-dir"])
    git_dir = _run(repo, runner, ["rev-parse", "--git-dir"])
    try:
        top_path = _resolve_git_path(repo, _stdout(top))
        common_path = _resolve_git_path(repo, _stdout(common))
        git_dir_path = _resolve_git_path(repo, _stdout(git_dir))
        primary_git_dir = (repo / ".git").resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PostMergeSyncApplyError("checkout identity is not canonical/readable") from exc
    return {
        "top_level": str(top_path),
        "git_common_dir": str(common_path),
        "git_dir": str(git_dir_path),
        "canonical_primary_checkout": (
            top_path == repo
            and common_path == git_dir_path
            and common_path == primary_git_dir
        ),
    }


def _current_branch(repo: Path, runner: CommandRunner) -> str | None:
    result = _run(
        repo,
        runner,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        allowed_returncodes=(0, 1),
    )
    if int(result.get("returncode", 1)) == 1:
        return None
    value = _stdout(result)
    if not value or value.startswith("-") or value.startswith("refs/") or ":" in value:
        raise PostMergeSyncApplyError("current branch name is unsafe")
    return value


def _head(repo: Path, runner: CommandRunner) -> str:
    value = _stdout(_run(repo, runner, ["rev-parse", "--verify", "HEAD"])).lower()
    if SHA_RE.fullmatch(value) is None:
        raise PostMergeSyncApplyError("current HEAD is not a canonical Git object id")
    return value


def _status(repo: Path, runner: CommandRunner) -> tuple[bool, str]:
    raw = str(
        _run(
            repo,
            runner,
            ["status", "--porcelain=v1", "--untracked-files=all"],
        ).get("stdout", "")
    )
    return not bool(raw.strip()), hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _upstream(repo: Path, runner: CommandRunner) -> str | None:
    result = _run(
        repo,
        runner,
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
        allowed_returncodes=(0, 128),
    )
    if int(result.get("returncode", 1)) != 0:
        return None
    return _stdout(result) or None


def _ref_head(
    repo: Path,
    runner: CommandRunner,
    ref: str,
    *,
    sha_length: int,
) -> str | None:
    result = _run(
        repo,
        runner,
        ["show-ref", "--verify", "--hash", ref],
        allowed_returncodes=(0, 1),
    )
    if int(result.get("returncode", 1)) == 1:
        return None
    value = _stdout(result).lower()
    if len(value) != sha_length or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise PostMergeSyncApplyError(f"local ref is malformed: {ref}")
    return value


def _commit_head(repo: Path, runner: CommandRunner, revision: str) -> str:
    result = _run(
        repo,
        runner,
        ["rev-parse", "--verify", f"{revision}^{{commit}}"],
    )
    value = _stdout(result).lower()
    if value != revision.lower():
        raise PostMergeSyncApplyError(
            f"commit readback differs from bound identity: {revision}"
        )
    return value


def _tree(repo: Path, runner: CommandRunner, revision: str) -> str:
    value = _stdout(
        _run(repo, runner, ["rev-parse", "--verify", f"{revision}^{{tree}}"])
    ).lower()
    if not value or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise PostMergeSyncApplyError(f"tree identity is invalid for {revision}")
    return value


def _snapshot(
    repo: Path,
    runner: CommandRunner,
    *,
    target_branch: str,
    remote: str,
    sha_length: int,
) -> dict[str, Any]:
    clean, status_sha256 = _status(repo, runner)
    return {
        "identity": _checkout_identity(repo, runner),
        "branch": _current_branch(repo, runner),
        "head": _head(repo, runner),
        "clean": clean,
        "status_sha256": status_sha256,
        "upstream": _upstream(repo, runner),
        "tracking_ref": f"refs/remotes/{remote}/{target_branch}",
        "tracking_head": _ref_head(
            repo,
            runner,
            f"refs/remotes/{remote}/{target_branch}",
            sha_length=sha_length,
        ),
    }


def _final_exact(
    snapshot: dict[str, Any],
    *,
    repo: Path,
    target_branch: str,
    remote: str,
    expected_remote_head: str,
) -> bool:
    identity = snapshot.get("identity")
    return bool(
        isinstance(identity, dict)
        and identity.get("canonical_primary_checkout") is True
        and identity.get("top_level") == str(repo)
        and snapshot.get("branch") == target_branch
        and snapshot.get("head") == expected_remote_head
        and snapshot.get("clean") is True
        and snapshot.get("upstream") == f"{remote}/{target_branch}"
        and snapshot.get("tracking_head") == expected_remote_head
    )


def _blocked(state: str, **extra: Any) -> dict[str, Any]:
    return {
        "receipt_status": "blocked",
        "state": state,
        "effect_started": False,
        "retry_authorized": False,
        **extra,
    }


def apply(
    *,
    repo: Path,
    target_branch: str,
    expected_local_head: str,
    expected_remote_head: str,
    remote: str,
    remote_target: str,
    confirmation: str,
    runner: CommandRunner,
    remote_head_reader: RemoteHeadReader,
    pinned_target_factory: PinnedTargetFactory,
) -> dict[str, Any]:
    repo = repo.expanduser().resolve(strict=True)
    expected_local_head = expected_local_head.lower()
    expected_remote_head = expected_remote_head.lower()

    if target_branch not in PROTECTED_BRANCHES:
        return _blocked("unsupported_target_branch", target_branch=target_branch)
    if confirmation != CONFIRMATION:
        return _blocked("confirmation_mismatch")
    if (
        SHA_RE.fullmatch(expected_local_head) is None
        or SHA_RE.fullmatch(expected_remote_head) is None
        or len(expected_local_head) != len(expected_remote_head)
    ):
        return _blocked("invalid_bound_heads")
    if REMOTE_RE.fullmatch(remote) is None or remote.startswith("-"):
        return _blocked("invalid_remote")

    sha_length = len(expected_remote_head)
    expected_upstream = f"{remote}/{target_branch}"
    initial = _snapshot(
        repo,
        runner,
        target_branch=target_branch,
        remote=remote,
        sha_length=sha_length,
    )
    identity = initial["identity"]
    if (
        identity.get("canonical_primary_checkout") is not True
        or initial.get("branch") != target_branch
    ):
        return _blocked(
            "canonical_checkout_mismatch",
            before=initial,
        )
    if initial.get("clean") is not True:
        return _blocked("dirty_checkout", before=initial)
    if initial.get("head") not in {expected_local_head, expected_remote_head}:
        return _blocked("local_head_mismatch", before=initial)
    if initial.get("upstream") != expected_upstream:
        return _blocked("upstream_mismatch", before=initial)

    try:
        remote_before = remote_head_reader("before", False)
    except Exception as exc:
        return _blocked(
            "remote_read_failed",
            before=initial,
            error_class=type(exc).__name__,
        )
    if remote_before != expected_remote_head:
        return _blocked(
            "remote_head_mismatch",
            before=initial,
            actual_remote_head=remote_before,
        )

    try:
        _commit_head(repo, runner, expected_local_head)
    except PostMergeSyncApplyError as exc:
        return _blocked(
            "local_preimage_commit_unreadable",
            before=initial,
            error=str(exc),
        )

    if initial.get("head") == expected_remote_head:
        if initial.get("tracking_head") != expected_remote_head:
            return _blocked(
                "tracking_ref_mismatch_on_replay",
                before=initial,
            )
        return {
            "receipt_status": "passed",
            "state": "already_synced",
            "effect_started": False,
            "preimage_verified": True,
            "idempotent": True,
            "retry_authorized": False,
            "old_head": expected_remote_head,
            "new_head": expected_remote_head,
            "remote_head": expected_remote_head,
            "post_state": initial,
            "post_state_verified": True,
            "merge_commit_created": False,
        }

    preimage = {
        "repo": str(repo),
        "target_branch": target_branch,
        "remote": remote,
        "expected_local_head": expected_local_head,
        "expected_remote_head": expected_remote_head,
        "identity": identity,
        "upstream": expected_upstream,
        "tracking_head": initial.get("tracking_head"),
    }
    preimage_sha256 = _sha256_json(preimage)
    owner_id = (
        f"operator:post-merge-sync-{preimage_sha256[:16]}-"
        f"{secrets.token_hex(12)}"
    )
    resource_keys = resources.normalize_resource_keys(
        [
            f"repo:{repo}",
            f"path:{repo}",
            f"path:{identity['git_common_dir']}",
        ]
    )
    try:
        acquisition = resources.acquire_resources(
            owner_id,
            resource_keys,
            purpose=(
                f"exclusive protected post-merge fast-forward "
                f"{target_branch}@{expected_remote_head[:12]}"
            ),
            ttl_seconds=LEASE_TTL_SECONDS,
        )
    except Exception as exc:
        return _blocked(
            "lease_acquisition_blocked",
            before=initial,
            preimage_sha256=preimage_sha256,
            lease_owner_id=owner_id,
            resource_keys=resource_keys,
            error_class=type(exc).__name__,
        )

    lease_snapshots = acquisition.get("leases")
    if (
        not isinstance(lease_snapshots, list)
        or len(lease_snapshots) != len(resource_keys)
    ):
        output = {
            "receipt_status": "failed",
            "state": "lease_snapshot_invalid",
            "effect_started": False,
            "retry_authorized": False,
            "preimage_sha256": preimage_sha256,
            "lease_owner_id": owner_id,
            "resource_keys": resource_keys,
            "readback_required": True,
            "next_action": (
                "authoritative local and remote readback before any new intent"
            ),
        }
        try:
            released = resources.release_resources(owner_id, resource_keys)
        except Exception as exc:
            cleanup_next_action = (
                "inspect and clean the exact owned leases before any new intent"
            )
            output["lease_cleanup_required"] = True
            output["lease_release"] = {
                "status": "failed",
                "error_class": type(exc).__name__,
            }
            output["lease_cleanup_next_action"] = cleanup_next_action
            output["next_action"] = (
                f"{output['next_action']}; then {cleanup_next_action}"
            )
        else:
            output["lease_release"] = {
                "status": "released",
                "count": len(released.get("released", [])),
            }
        return output

    output: dict[str, Any] | None = None
    effect_started = False
    worktree_effect_started = False
    branch_cas_started = False
    serialization_verified = False
    preimage_verified = False
    fast_forward_verified = False
    release_error: Exception | None = None
    try:
        live = resources.inspect_resources(resource_keys)
        if (
            set(live) != set(resource_keys)
            or any(
                not isinstance(value, dict)
                or value.get("owner_id") != owner_id
                for value in live.values()
            )
        ):
            output = _blocked(
                "lease_preimage_drift",
                before=initial,
                preimage_sha256=preimage_sha256,
                resource_keys=resource_keys,
                serialization_verified=False,
            )

        if output is None:
            serialization_verified = True
            locked = _snapshot(
                repo,
                runner,
                target_branch=target_branch,
                remote=remote,
                sha_length=sha_length,
            )
            if locked != initial or locked.get("head") != expected_local_head:
                output = _blocked(
                    "preimage_drift_after_lease",
                    before=initial,
                    locked=locked,
                    preimage_sha256=preimage_sha256,
                    resource_keys=resource_keys,
                    serialization_verified=serialization_verified,
                )

        if output is None:
            preimage_verified = True

        if output is None:
            try:
                remote_locked = remote_head_reader("locked", False)
            except Exception as exc:
                output = _blocked(
                    "remote_read_failed_after_lease",
                    before=initial,
                    preimage_sha256=preimage_sha256,
                    resource_keys=resource_keys,
                    serialization_verified=serialization_verified,
                    error_class=type(exc).__name__,
                )
            else:
                if remote_locked != expected_remote_head:
                    output = _blocked(
                        "remote_head_drift_after_lease",
                        before=initial,
                        preimage_sha256=preimage_sha256,
                        resource_keys=resource_keys,
                        serialization_verified=serialization_verified,
                        actual_remote_head=remote_locked,
                    )

        if output is None:
            try:
                fetch_remote, fetch_pin_config = pinned_target_factory(remote_target)
                effect_started = True
                _run(
                    repo,
                    runner,
                    [
                        "-c",
                        fetch_pin_config,
                        "-c",
                        "protocol.ext.allow=never",
                        "-c",
                        "fetch.writeCommitGraph=false",
                        "-c",
                        "gc.auto=0",
                        "-c",
                        "maintenance.auto=false",
                        "fetch",
                        "--no-tags",
                        "--no-write-fetch-head",
                        "--no-recurse-submodules",
                        "--no-prune",
                        "--refmap=",
                        "--upload-pack=git-upload-pack",
                        fetch_remote,
                        expected_remote_head,
                    ],
                )
                _commit_head(repo, runner, expected_remote_head)
                if remote_head_reader("after_fetch", True) != expected_remote_head:
                    raise PostMergeSyncApplyError(
                        "remote branch advanced during exact-head materialization"
                    )

                ancestry = _run(
                    repo,
                    runner,
                    [
                        "--no-replace-objects",
                        "merge-base",
                        "--is-ancestor",
                        expected_local_head,
                        expected_remote_head,
                    ],
                    allowed_returncodes=(0, 1),
                )
                if int(ancestry.get("returncode", 1)) != 0:
                    raise PostMergeSyncNonFastForward(
                        "materialized remote head is not a fast-forward of the local head"
                    )
                fast_forward_verified = True

                tracking_ref = f"refs/remotes/{remote}/{target_branch}"
                tracking_before = _ref_head(
                    repo,
                    runner,
                    tracking_ref,
                    sha_length=sha_length,
                )
                if tracking_before != expected_remote_head:
                    _run(
                        repo,
                        runner,
                        [
                            "update-ref",
                            tracking_ref,
                            expected_remote_head,
                            tracking_before or ("0" * sha_length),
                        ],
                    )
                if (
                    _ref_head(
                        repo,
                        runner,
                        tracking_ref,
                        sha_length=sha_length,
                    )
                    != expected_remote_head
                ):
                    raise PostMergeSyncApplyError(
                        "remote-tracking ref did not converge"
                    )

                ready = _snapshot(
                    repo,
                    runner,
                    target_branch=target_branch,
                    remote=remote,
                    sha_length=sha_length,
                )
                if (
                    ready.get("identity") != identity
                    or ready.get("branch") != target_branch
                    or ready.get("head") != expected_local_head
                    or ready.get("clean") is not True
                    or ready.get("upstream") != expected_upstream
                    or ready.get("tracking_head") != expected_remote_head
                ):
                    raise PostMergeSyncApplyError(
                        "checkout preimage drifted before worktree update"
                    )

                branch_ref = f"refs/heads/{target_branch}"
                if (
                    _ref_head(
                        repo,
                        runner,
                        branch_ref,
                        sha_length=sha_length,
                    )
                    != expected_local_head
                ):
                    raise PostMergeSyncApplyError(
                        "protected branch ref drifted before worktree update"
                    )

                worktree_effect_started = True
                _run(
                    repo,
                    runner,
                    [
                        "-c",
                        "core.hooksPath=/dev/null",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "submodule.recurse=false",
                        "read-tree",
                        "-u",
                        "-m",
                        expected_local_head,
                        expected_remote_head,
                    ],
                )
                target_tree = _tree(repo, runner, expected_remote_head)
                index_tree = _stdout(_run(repo, runner, ["write-tree"])).lower()
                unstaged = _run(
                    repo,
                    runner,
                    ["diff", "--quiet", "--"],
                    allowed_returncodes=(0, 1),
                )
                if (
                    index_tree != target_tree
                    or int(unstaged.get("returncode", 1)) != 0
                ):
                    raise PostMergeSyncApplyError(
                        "worktree/index did not reach the exact target tree"
                    )
                if (
                    _ref_head(
                        repo,
                        runner,
                        branch_ref,
                        sha_length=sha_length,
                    )
                    != expected_local_head
                ):
                    raise PostMergeSyncApplyError(
                        "protected branch ref drifted before CAS"
                    )

                branch_cas_started = True
                _run(
                    repo,
                    runner,
                    [
                        "update-ref",
                        branch_ref,
                        expected_remote_head,
                        expected_local_head,
                    ],
                )

                final = _snapshot(
                    repo,
                    runner,
                    target_branch=target_branch,
                    remote=remote,
                    sha_length=sha_length,
                )
                remote_final = remote_head_reader("final", True)
                final_tree = _stdout(_run(repo, runner, ["write-tree"])).lower()
                if (
                    not _final_exact(
                        final,
                        repo=repo,
                        target_branch=target_branch,
                        remote=remote,
                        expected_remote_head=expected_remote_head,
                    )
                    or remote_final != expected_remote_head
                    or final_tree != target_tree
                ):
                    raise PostMergeSyncApplyError(
                        "terminal readback does not match the exact final state"
                    )
                output = {
                    "receipt_status": "passed",
                    "state": "synced",
                    "effect_started": True,
                    "worktree_effect_started": True,
                    "branch_cas_started": True,
                    "serialization_verified": serialization_verified,
                    "fast_forward_verified": fast_forward_verified,
                    "retry_authorized": False,
                    "preimage_sha256": preimage_sha256,
                    "resource_keys": resource_keys,
                    "branch": target_branch,
                    "remote": remote,
                    "old_head": expected_local_head,
                    "new_head": expected_remote_head,
                    "remote_head": remote_final,
                    "tracking_head": final.get("tracking_head"),
                    "git_common_dir": identity["git_common_dir"],
                    "post_state": final,
                    "post_state_verified": True,
                    "merge_commit_created": False,
                }
            except Exception as exc:
                try:
                    readback = _snapshot(
                        repo,
                        runner,
                        target_branch=target_branch,
                        remote=remote,
                        sha_length=sha_length,
                    )
                except Exception as read_exc:
                    readback = {"readback_error_type": type(read_exc).__name__}
                local_final_exact = (
                    isinstance(readback, dict)
                    and _final_exact(
                        readback,
                        repo=repo,
                        target_branch=target_branch,
                        remote=remote,
                        expected_remote_head=expected_remote_head,
                    )
                )
                remote_readback: str | None = None
                remote_readback_error_type: str | None = None
                if local_final_exact:
                    try:
                        remote_readback = remote_head_reader(
                            "error_readback",
                            True,
                        )
                    except Exception as remote_exc:
                        remote_readback_error_type = type(remote_exc).__name__
                remote_final_exact = (
                    local_final_exact
                    and remote_readback == expected_remote_head
                )
                old_exact = bool(
                    isinstance(readback, dict)
                    and isinstance(readback.get("identity"), dict)
                    and readback["identity"].get("canonical_primary_checkout") is True
                    and readback.get("branch") == target_branch
                    and readback.get("head") == expected_local_head
                    and readback.get("clean") is True
                    and readback.get("upstream") == expected_upstream
                    and readback.get("tracking_head")
                    == initial.get("tracking_head")
                )
                local_post_verified = bool(local_final_exact)
                if (
                    isinstance(exc, PostMergeSyncNonFastForward)
                    and not worktree_effect_started
                    and not branch_cas_started
                    and old_exact
                ):
                    state = "non_fast_forward"
                    receipt_status = "blocked"
                    post_verified = False
                elif remote_final_exact:
                    state = "effect_confirmed_after_error"
                    receipt_status = "passed"
                    post_verified = True
                elif local_final_exact:
                    state = (
                        "effect_confirmed_remote_unreadable"
                        if remote_readback_error_type is not None
                        else "effect_confirmed_remote_drift"
                    )
                    receipt_status = "blocked"
                    post_verified = False
                elif not branch_cas_started and old_exact:
                    state = "effect_failed_before_branch_cas"
                    receipt_status = "blocked"
                    post_verified = False
                else:
                    state = "outcome_unknown"
                    receipt_status = "failed"
                    post_verified = False
                output = {
                    "receipt_status": receipt_status,
                    "state": state,
                    "effect_started": effect_started,
                    "worktree_effect_started": worktree_effect_started,
                    "branch_cas_started": branch_cas_started,
                    "serialization_verified": serialization_verified,
                    "fast_forward_verified": fast_forward_verified,
                    "retry_authorized": False,
                    "preimage_sha256": preimage_sha256,
                    "resource_keys": resource_keys,
                    "error_class": type(exc).__name__,
                    "error": str(exc),
                    "readback": readback,
                    "remote_readback": remote_readback,
                    "remote_readback_error_type": remote_readback_error_type,
                    "local_post_state_verified": local_post_verified,
                    "post_state_verified": post_verified,
                    "readback_required": state in {
                        "outcome_unknown",
                        "effect_confirmed_remote_drift",
                        "effect_confirmed_remote_unreadable",
                    },
                    "next_action": (
                        "authoritative local and remote readback before any new intent"
                        if state in {
                            "outcome_unknown",
                            "effect_confirmed_remote_drift",
                            "effect_confirmed_remote_unreadable",
                        }
                        else "form a fresh apply intent from current authoritative state"
                    ),
                }
    except Exception as exc:
        try:
            readback = _snapshot(
                repo,
                runner,
                target_branch=target_branch,
                remote=remote,
                sha_length=sha_length,
            )
        except Exception as read_exc:
            readback = {"readback_error_type": type(read_exc).__name__}
        output = {
            "receipt_status": "failed",
            "state": "outcome_unknown",
            "effect_started": effect_started,
            "worktree_effect_started": worktree_effect_started,
            "branch_cas_started": branch_cas_started,
            "serialization_verified": serialization_verified,
            "fast_forward_verified": fast_forward_verified,
            "retry_authorized": False,
            "readback_required": True,
            "preimage_sha256": preimage_sha256,
            "resource_keys": resource_keys,
            "error_class": type(exc).__name__,
            "error": str(exc),
            "readback": readback,
            "local_post_state_verified": False,
            "post_state_verified": False,
            "next_action": (
                "authoritative local and remote readback before any new intent"
            ),
        }
    finally:
        try:
            released = resources.release_resources(
                owner_id,
                resource_keys,
                expected_leases=lease_snapshots,
            )
            release_info = {
                "status": "released",
                "count": len(released.get("released", [])),
            }
            if output is not None:
                output["lease_release"] = release_info
        except Exception as exc:
            release_error = exc

    if output is None:
        output = {
            "receipt_status": "failed",
            "state": "outcome_unknown",
            "effect_started": effect_started,
            "worktree_effect_started": worktree_effect_started,
            "branch_cas_started": branch_cas_started,
            "serialization_verified": serialization_verified,
            "fast_forward_verified": fast_forward_verified,
            "retry_authorized": False,
            "readback_required": True,
            "preimage_sha256": preimage_sha256,
            "resource_keys": resource_keys,
        }
    output.setdefault("preimage_verified", preimage_verified)
    output.setdefault("lease_owner_id", owner_id)
    if release_error is not None:
        cleanup_next_action = (
            "inspect and clean the exact owned leases before any new intent"
        )
        prior_next_action = output.get("next_action")
        if isinstance(prior_next_action, str) and prior_next_action.strip():
            output.setdefault("effect_next_action", prior_next_action)
        if output.get("receipt_status") == "passed":
            output["receipt_status"] = "blocked"
        elif output.get("receipt_status") not in {"blocked", "failed"}:
            output["receipt_status"] = "blocked"
        output["retry_authorized"] = False
        output["lease_cleanup_required"] = True
        output["lease_release"] = {
            "status": "failed",
            "error_class": type(release_error).__name__,
        }
        output["lease_cleanup_next_action"] = cleanup_next_action
        if output.get("readback_required") is True:
            readback_next_action = (
                prior_next_action
                if isinstance(prior_next_action, str) and prior_next_action.strip()
                else "authoritative local and remote readback before any new intent"
            )
            output["next_action"] = (
                f"{readback_next_action}; then {cleanup_next_action}"
            )
        else:
            output["next_action"] = cleanup_next_action
    return output
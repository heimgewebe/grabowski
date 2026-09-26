from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any, Callable

import grabowski_resources as resources
import grabowski_physical_checkout as physical_checkout


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


class PostMergeSyncPhysicalIdentityDrift(PostMergeSyncApplyError):
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


def _physical_node_resource_key(
    identity: dict[str, Any],
    *,
    node_name: str,
    resource_kind: str,
) -> str:
    node = identity.get(node_name)
    if not isinstance(node, dict):
        raise PostMergeSyncApplyError(
            f"physical checkout {node_name} identity is missing"
        )
    device = node.get("device")
    inode = node.get("inode")
    if (
        type(device) is not int
        or device < 0
        or type(inode) is not int
        or inode < 0
    ):
        raise PostMergeSyncApplyError(
            f"physical checkout {node_name} identity is invalid"
        )
    return f"component:{resource_kind}:{device}:{inode}"


def _physical_checkout_resource_keys(identity: dict[str, Any]) -> tuple[str, str]:
    git_dir = identity.get("git_dir")
    common_dir = identity.get("common_dir")
    if not isinstance(git_dir, dict) or not isinstance(common_dir, dict):
        raise PostMergeSyncApplyError(
            "physical Git/common directory identity is missing"
        )
    if (
        git_dir.get("device") != common_dir.get("device")
        or git_dir.get("inode") != common_dir.get("inode")
    ):
        raise PostMergeSyncApplyError(
            "physical Git/common directory identity does not describe one node"
        )
    return (
        _physical_node_resource_key(
            identity,
            node_name="root",
            resource_kind="physical-checkout-root",
        ),
        _physical_node_resource_key(
            identity,
            node_name="common_dir",
            resource_kind="physical-git-common-dir",
        ),
    )


def _fd_bound_runner(
    runner: CommandRunner,
    bound: physical_checkout.BoundPhysicalCheckout,
) -> CommandRunner:
    def run(_repo: Path, argv: list[str]) -> dict[str, Any]:
        return runner(
            bound.effect_root,
            [
                f"--git-dir={bound.effect_git_dir}",
                f"--work-tree={bound.effect_root}",
                *argv,
            ],
        )

    return run


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
    identity_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    clean, status_sha256 = _status(repo, runner)
    return {
        "identity": (
            _checkout_identity(repo, runner)
            if identity_override is None
            else identity_override
        ),
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
    expected_physical_identity_sha256: str,
    remote: str,
    remote_target: str,
    confirmation: str,
    runner: CommandRunner,
    remote_head_reader: RemoteHeadReader,
    pinned_target_factory: PinnedTargetFactory,
) -> dict[str, Any]:
    expected_local_head = expected_local_head.lower()
    expected_remote_head = expected_remote_head.lower()
    expected_physical_identity_sha256 = expected_physical_identity_sha256.lower()
    if re.fullmatch(r"[0-9a-f]{64}", expected_physical_identity_sha256) is None:
        return _blocked(
            "invalid_physical_checkout_identity",
            physical_identity_verified=False,
        )
    try:
        initial_physical = physical_checkout.capture_physical_checkout_identity(
            repo.expanduser()
        )
    except (OSError, ValueError, physical_checkout.PhysicalCheckoutIdentityError) as exc:
        return _blocked(
            "physical_checkout_identity_unreadable",
            physical_identity_verified=False,
            error_class=type(exc).__name__,
        )
    if (
        initial_physical.get("physical_identity_sha256")
        != expected_physical_identity_sha256
    ):
        return _blocked(
            "physical_checkout_identity_mismatch",
            physical_identity_verified=False,
            observed_physical_identity_sha256=initial_physical.get(
                "physical_identity_sha256"
            ),
        )
    repo = Path(str(initial_physical["root"]["path"]))
    physical_identity_verified = True

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

    remote_head_verified = False

    def read_remote_head(stage: str, effect_started: bool) -> str:
        nonlocal remote_head_verified
        try:
            observed = remote_head_reader(stage, effect_started)
        except Exception:
            remote_head_verified = False
            raise
        remote_head_verified = observed == expected_remote_head
        return observed

    try:
        remote_before = read_remote_head("before", False)
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
    remote_head_verified = True

    try:
        _commit_head(repo, runner, expected_local_head)
    except PostMergeSyncApplyError as exc:
        return _blocked(
            "local_preimage_commit_unreadable",
            before=initial,
            remote_head_verified=remote_head_verified,
            error=str(exc),
        )

    if initial.get("head") == expected_remote_head:
        if initial.get("tracking_head") != expected_remote_head:
            return _blocked(
                "tracking_ref_mismatch_on_replay",
                before=initial,
                remote_head_verified=remote_head_verified,
            )
        try:
            with physical_checkout.bind_physical_checkout(repo) as replay_bound:
                rebound_physical = replay_bound.identity
                if (
                    rebound_physical.get("physical_identity_sha256")
                    != expected_physical_identity_sha256
                ):
                    physical_identity_verified = False
                    return _blocked(
                        "physical_checkout_identity_drift_before_replay_success",
                        before=initial,
                        remote_head_verified=remote_head_verified,
                        physical_identity_verified=False,
                        observed_physical_identity_sha256=rebound_physical.get(
                            "physical_identity_sha256"
                        ),
                    )
                replay_runner = _fd_bound_runner(runner, replay_bound)
                rebound = _snapshot(
                    repo,
                    replay_runner,
                    target_branch=target_branch,
                    remote=remote,
                    sha_length=sha_length,
                    identity_override=identity,
                )
                if not _final_exact(
                    rebound,
                    repo=repo,
                    target_branch=target_branch,
                    remote=remote,
                    expected_remote_head=expected_remote_head,
                ):
                    return _blocked(
                        "replay_readback_drift_before_success",
                        before=initial,
                        rebound=rebound,
                        remote_head_verified=remote_head_verified,
                        physical_identity_verified=True,
                    )
                try:
                    replay_remote_final = read_remote_head("replay-final", False)
                except Exception as exc:
                    return _blocked(
                        "remote_read_failed",
                        before=initial,
                        rebound=rebound,
                        remote_head_verified=False,
                        physical_identity_verified=False,
                        error_class=type(exc).__name__,
                    )
                if replay_remote_final != expected_remote_head:
                    return _blocked(
                        "remote_head_mismatch",
                        before=initial,
                        rebound=rebound,
                        actual_remote_head=replay_remote_final,
                        remote_head_verified=False,
                        physical_identity_verified=False,
                    )
                rebound = _snapshot(
                    repo,
                    replay_runner,
                    target_branch=target_branch,
                    remote=remote,
                    sha_length=sha_length,
                    identity_override=identity,
                )
                if not _final_exact(
                    rebound,
                    repo=repo,
                    target_branch=target_branch,
                    remote=remote,
                    expected_remote_head=expected_remote_head,
                ):
                    return _blocked(
                        "replay_readback_drift_before_success",
                        before=initial,
                        rebound=rebound,
                        remote_head_verified=remote_head_verified,
                        physical_identity_verified=True,
                    )
                replay_final_physical = (
                    physical_checkout.capture_physical_checkout_identity(repo)
                )
                if (
                    replay_final_physical.get("physical_identity_sha256")
                    != expected_physical_identity_sha256
                ):
                    physical_identity_verified = False
                    return _blocked(
                        "physical_checkout_identity_drift_before_replay_success",
                        before=initial,
                        rebound=rebound,
                        remote_head_verified=remote_head_verified,
                        physical_identity_verified=False,
                        observed_physical_identity_sha256=(
                            replay_final_physical.get("physical_identity_sha256")
                        ),
                    )
        except (
            OSError,
            ValueError,
            physical_checkout.PhysicalCheckoutIdentityError,
        ) as exc:
            physical_identity_verified = False
            return _blocked(
                "physical_checkout_identity_drift_before_replay_success",
                before=initial,
                remote_head_verified=remote_head_verified,
                physical_identity_verified=False,
                error_class=type(exc).__name__,
            )
        return {
            "receipt_status": "passed",
            "state": "already_synced",
            "effect_started": False,
            "preimage_verified": True,
            "remote_head_verified": remote_head_verified,
            "physical_identity_verified": physical_identity_verified,
            "idempotent": True,
            "retry_authorized": False,
            "old_head": expected_remote_head,
            "new_head": expected_remote_head,
            "remote_head": expected_remote_head,
            "post_state": rebound,
            "post_state_verified": True,
            "merge_commit_created": False,
        }

    preimage = {
        "repo": str(repo),
        "target_branch": target_branch,
        "remote": remote,
        "expected_local_head": expected_local_head,
        "expected_remote_head": expected_remote_head,
        "expected_physical_identity_sha256": expected_physical_identity_sha256,
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
            *_physical_checkout_resource_keys(initial_physical),
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
            _work_admission_mode="convergence",
        )
    except Exception as exc:
        return _blocked(
            "lease_acquisition_blocked",
            before=initial,
            preimage_sha256=preimage_sha256,
            lease_owner_id=owner_id,
            resource_keys=resource_keys,
            remote_head_verified=remote_head_verified,
            physical_identity_verified=physical_identity_verified,
            error_class=type(exc).__name__,
        )

    remote_head_verified = False
    lease_snapshots = acquisition.get("leases")
    if (
        not isinstance(lease_snapshots, list)
        or len(lease_snapshots) != len(resource_keys)
    ):
        output = {
            "receipt_status": "failed",
            "state": "lease_snapshot_invalid",
            "effect_started": False,
            "remote_head_verified": remote_head_verified,
            "physical_identity_verified": physical_identity_verified,
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
    bound_checkout: physical_checkout.BoundPhysicalCheckout | None = None
    effect_runner = runner
    try:
        try:
            bound_checkout = physical_checkout.bind_physical_checkout(repo)
            locked_physical = bound_checkout.identity
            effect_runner = _fd_bound_runner(runner, bound_checkout)
        except (
            OSError,
            ValueError,
            physical_checkout.PhysicalCheckoutIdentityError,
        ) as exc:
            physical_identity_verified = False
            output = _blocked(
                "physical_checkout_identity_drift_after_lease",
                before=initial,
                preimage_sha256=preimage_sha256,
                resource_keys=resource_keys,
                physical_identity_verified=False,
                error_class=type(exc).__name__,
            )
        else:
            if (
                locked_physical.get("physical_identity_sha256")
                != expected_physical_identity_sha256
            ):
                physical_identity_verified = False
                output = _blocked(
                    "physical_checkout_identity_drift_after_lease",
                    before=initial,
                    preimage_sha256=preimage_sha256,
                    resource_keys=resource_keys,
                    physical_identity_verified=False,
                    observed_physical_identity_sha256=locked_physical.get(
                        "physical_identity_sha256"
                    ),
                )

        live = resources.inspect_resources(resource_keys) if output is None else {}
        if output is None and (
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
                effect_runner,
                target_branch=target_branch,
                remote=remote,
                sha_length=sha_length,
                identity_override=identity,
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
                remote_locked = read_remote_head("locked", False)
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
                else:
                    remote_head_verified = True

        if output is None:
            try:
                fetch_remote, fetch_pin_config = pinned_target_factory(remote_target)
                effect_started = True
                _run(
                    repo,
                    effect_runner,
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
                _commit_head(repo, effect_runner, expected_remote_head)
                if read_remote_head("after_fetch", True) != expected_remote_head:
                    raise PostMergeSyncApplyError(
                        "remote branch advanced during exact-head materialization"
                    )

                ancestry = _run(
                    repo,
                    effect_runner,
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
                    effect_runner,
                    tracking_ref,
                    sha_length=sha_length,
                )
                if tracking_before != expected_remote_head:
                    _run(
                        repo,
                        effect_runner,
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
                        effect_runner,
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
                    effect_runner,
                    target_branch=target_branch,
                    remote=remote,
                    sha_length=sha_length,
                    identity_override=identity,
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
                        effect_runner,
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
                    effect_runner,
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
                target_tree = _tree(repo, effect_runner, expected_remote_head)
                index_tree = _stdout(_run(repo, effect_runner, ["write-tree"])).lower()
                unstaged = _run(
                    repo,
                    effect_runner,
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
                        effect_runner,
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
                    effect_runner,
                    [
                        "update-ref",
                        branch_ref,
                        expected_remote_head,
                        expected_local_head,
                    ],
                )

                try:
                    final_physical = physical_checkout.capture_physical_checkout_identity(
                        repo
                    )
                except (
                    OSError,
                    ValueError,
                    physical_checkout.PhysicalCheckoutIdentityError,
                ) as exc:
                    physical_identity_verified = False
                    raise PostMergeSyncPhysicalIdentityDrift(
                        "physical checkout identity became unreadable during effect"
                    ) from exc
                if (
                    final_physical.get("physical_identity_sha256")
                    != expected_physical_identity_sha256
                ):
                    physical_identity_verified = False
                    raise PostMergeSyncPhysicalIdentityDrift(
                        "physical checkout identity changed during effect"
                    )

                remote_final = read_remote_head("final", True)
                final = _snapshot(
                    repo,
                    effect_runner,
                    target_branch=target_branch,
                    remote=remote,
                    sha_length=sha_length,
                    identity_override=identity,
                )
                final_tree = _stdout(_run(repo, effect_runner, ["write-tree"])).lower()
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
                try:
                    terminal_physical = (
                        physical_checkout.capture_physical_checkout_identity(repo)
                    )
                except (
                    OSError,
                    ValueError,
                    physical_checkout.PhysicalCheckoutIdentityError,
                ) as exc:
                    physical_identity_verified = False
                    raise PostMergeSyncPhysicalIdentityDrift(
                        "physical checkout identity became unreadable after terminal readback"
                    ) from exc
                if (
                    terminal_physical.get("physical_identity_sha256")
                    != expected_physical_identity_sha256
                ):
                    physical_identity_verified = False
                    raise PostMergeSyncPhysicalIdentityDrift(
                        "physical checkout identity changed after terminal readback"
                    )
                output = {
                    "receipt_status": "passed",
                    "state": "synced",
                    "effect_started": True,
                    "worktree_effect_started": True,
                    "branch_cas_started": True,
                    "serialization_verified": serialization_verified,
                    "fast_forward_verified": fast_forward_verified,
                    "physical_identity_verified": physical_identity_verified,
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
                        effect_runner,
                        target_branch=target_branch,
                        remote=remote,
                        sha_length=sha_length,
                        identity_override=identity,
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
                recovery_physical_drift = False
                if (
                    local_final_exact
                    and not isinstance(exc, PostMergeSyncPhysicalIdentityDrift)
                ):
                    try:
                        remote_readback = read_remote_head(
                            "error_readback",
                            True,
                        )
                    except Exception as remote_exc:
                        remote_readback_error_type = type(remote_exc).__name__
                    else:
                        if remote_readback == expected_remote_head:
                            try:
                                readback = _snapshot(
                                    repo,
                                    effect_runner,
                                    target_branch=target_branch,
                                    remote=remote,
                                    sha_length=sha_length,
                                    identity_override=identity,
                                )
                            except Exception as read_exc:
                                readback = {
                                    "readback_error_type": type(read_exc).__name__
                                }
                                local_final_exact = False
                            else:
                                local_final_exact = _final_exact(
                                    readback,
                                    repo=repo,
                                    target_branch=target_branch,
                                    remote=remote,
                                    expected_remote_head=expected_remote_head,
                                )
                                if local_final_exact:
                                    try:
                                        recovery_physical = (
                                            physical_checkout.capture_physical_checkout_identity(
                                                repo
                                            )
                                        )
                                    except (
                                        OSError,
                                        ValueError,
                                        physical_checkout.PhysicalCheckoutIdentityError,
                                    ):
                                        physical_identity_verified = False
                                        recovery_physical_drift = True
                                    else:
                                        if (
                                            recovery_physical.get(
                                                "physical_identity_sha256"
                                            )
                                            != expected_physical_identity_sha256
                                        ):
                                            physical_identity_verified = False
                                            recovery_physical_drift = True
                remote_final_exact = (
                    local_final_exact
                    and remote_readback == expected_remote_head
                    and not recovery_physical_drift
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
                    isinstance(exc, PostMergeSyncPhysicalIdentityDrift)
                    or recovery_physical_drift
                ):
                    state = "physical_checkout_identity_drift_final"
                    receipt_status = "failed"
                    post_verified = False
                elif (
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
                    "physical_identity_verified": physical_identity_verified,
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
                        "physical_checkout_identity_drift_final",
                    },
                    "next_action": (
                        "authoritative physical, local and remote readback before any new intent"
                        if state == "physical_checkout_identity_drift_final"
                        else (
                            "authoritative local and remote readback before any new intent"
                            if state in {
                                "outcome_unknown",
                                "effect_confirmed_remote_drift",
                                "effect_confirmed_remote_unreadable",
                            }
                            else "form a fresh apply intent from current authoritative state"
                        )
                    ),
                }
    except Exception as exc:
        try:
            readback = _snapshot(
                repo,
                effect_runner,
                target_branch=target_branch,
                remote=remote,
                sha_length=sha_length,
                identity_override=identity if bound_checkout is not None else None,
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
            "physical_identity_verified": physical_identity_verified,
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
        if bound_checkout is not None:
            try:
                bound_checkout.close()
            except physical_checkout.PhysicalCheckoutIdentityError:
                if output is None:
                    output = {
                        "receipt_status": "failed",
                        "state": "bound_checkout_release_failed",
                        "effect_started": effect_started,
                        "worktree_effect_started": worktree_effect_started,
                        "branch_cas_started": branch_cas_started,
                        "serialization_verified": serialization_verified,
                        "fast_forward_verified": fast_forward_verified,
                        "physical_identity_verified": physical_identity_verified,
                        "retry_authorized": False,
                        "readback_required": True,
                        "preimage_sha256": preimage_sha256,
                        "resource_keys": resource_keys,
                        "next_action": (
                            "authoritative local and remote readback before any new intent"
                        ),
                    }
                elif output.get("receipt_status") == "passed":
                    output["receipt_status"] = "blocked"
                    output["state"] = "bound_checkout_release_failed"
                    output["retry_authorized"] = False
                    output["readback_required"] = True
                    output["next_action"] = (
                        "authoritative local and remote readback before any new intent"
                    )
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
            "physical_identity_verified": physical_identity_verified,
            "retry_authorized": False,
            "readback_required": True,
            "preimage_sha256": preimage_sha256,
            "resource_keys": resource_keys,
        }
    output.setdefault("remote_head_verified", remote_head_verified)
    output.setdefault("preimage_verified", preimage_verified)
    output.setdefault("physical_identity_verified", physical_identity_verified)
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
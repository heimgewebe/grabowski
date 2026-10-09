from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any, Callable

import grabowski_consumer_surface as consumer_surface
import grabowski_physical_checkout as physical_checkout


def _frame(digest: Any, tag: bytes, payload: bytes = b"") -> None:
    digest.update(len(tag).to_bytes(2, "big"))
    digest.update(tag)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def _tracked_index_paths(index_bytes: bytes) -> list[bytes]:
    paths: set[bytes] = set()
    for record in index_bytes.split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        if not separator or not path or len(metadata.split(b" ")) != 3:
            raise RuntimeError("Git index observation has an invalid stage record")
        components = path.split(b"/")
        if path.startswith(b"/") or any(
            component in {b"", b".", b".."} for component in components
        ):
            raise RuntimeError("Git index observation contains an unsafe path")
        paths.add(path)
    return sorted(paths)


def _deadline_guard(deadline_monotonic: float | None, label: str) -> None:
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        raise RuntimeError(f"{label} exceeded the preimage deadline")


def _safe_worktree_paths_sha256(
    repo: Path,
    paths: list[bytes],
    *,
    max_paths: int,
    max_total_bytes: int | None = None,
    deadline_monotonic: float | None = None,
) -> str:
    if max_paths < 1:
        raise ValueError("max_paths must be positive")
    if max_total_bytes is not None and max_total_bytes < 1:
        raise ValueError("max_total_bytes must be positive")
    if len(paths) > max_paths:
        raise RuntimeError("Git worktree path set exceeds continuation bound")
    digest = hashlib.sha256()
    total_bytes = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    root_fd = os.open(repo, directory_flags)
    try:
        for path in sorted(paths):
            _deadline_guard(deadline_monotonic, "untracked worktree hashing")
            components = path.split(b"/")
            if path.startswith(b"/") or any(
                component in {b"", b".", b".."} for component in components
            ):
                raise RuntimeError("Git worktree observation contains an unsafe path")
            _frame(digest, b"path", path)
            directory_fd = os.dup(root_fd)
            parent_snapshots: list[tuple[bytes, os.stat_result]] = []
            try:
                for component in components[:-1]:
                    _deadline_guard(deadline_monotonic, "untracked worktree hashing")
                    linked_parent = os.stat(
                        component, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if not stat.S_ISDIR(linked_parent.st_mode):
                        raise RuntimeError(
                            "Untracked worktree parent changed during preimage capture"
                        )
                    next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                    opened_parent = os.fstat(next_fd)
                    if not _same_open_file(linked_parent, opened_parent):
                        os.close(next_fd)
                        raise RuntimeError(
                            "Untracked worktree parent changed during preimage capture"
                        )
                    parent_snapshots.append((component, opened_parent))
                    os.close(directory_fd)
                    directory_fd = next_fd
                leaf = components[-1]
                linked = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                mode_bytes = linked.st_mode.to_bytes(8, "big", signed=False)
                if stat.S_ISREG(linked.st_mode):
                    descriptor = os.open(leaf, file_flags, dir_fd=directory_fd)
                    try:
                        before = os.fstat(descriptor)
                        if not _same_open_file(linked, before):
                            raise RuntimeError(
                                "Untracked worktree file changed during preimage capture"
                            )
                        content = hashlib.sha256()
                        size = 0
                        while True:
                            _deadline_guard(
                                deadline_monotonic, "untracked worktree hashing"
                            )
                            chunk = os.read(descriptor, 1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            total_bytes += len(chunk)
                            if (
                                max_total_bytes is not None
                                and total_bytes > max_total_bytes
                            ):
                                raise RuntimeError(
                                    "untracked worktree byte limit exceeded"
                                )
                            content.update(chunk)
                        after = os.fstat(descriptor)
                        if not _same_open_file(before, after):
                            raise RuntimeError(
                                "Worktree file changed during preimage capture"
                            )
                    finally:
                        os.close(descriptor)
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        after,
                        label="Untracked worktree file",
                    )
                    _frame(digest, b"regular-mode", mode_bytes)
                    _frame(digest, b"regular-size", size.to_bytes(8, "big"))
                    _frame(digest, b"regular-content-sha256", content.digest())
                elif stat.S_ISLNK(linked.st_mode):
                    target = os.readlink(leaf, dir_fd=directory_fd)
                    target_bytes = (
                        target if isinstance(target, bytes) else os.fsencode(target)
                    )
                    total_bytes += len(target_bytes)
                    if (
                        max_total_bytes is not None
                        and total_bytes > max_total_bytes
                    ):
                        raise RuntimeError("untracked worktree byte limit exceeded")
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        linked,
                        label="Untracked worktree symlink",
                        symlink_target=target_bytes,
                    )
                    _frame(digest, b"symlink-mode", mode_bytes)
                    _frame(digest, b"symlink-target", target_bytes)
                else:
                    raise RuntimeError("Unsupported untracked worktree entry type")
            finally:
                os.close(directory_fd)
    finally:
        os.close(root_fd)
    return digest.hexdigest()


def capture_untracked_preimage(
    repo: Path,
    probe: Callable[[Path, list[str]], subprocess.CompletedProcess[bytes]],
    *,
    max_paths: int = 100,
    max_total_bytes: int | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    _deadline_guard(deadline_monotonic, "untracked preimage capture")
    completed = probe(repo, ["ls-files", "--others", "--exclude-standard", "-z"])
    if completed.returncode != 0:
        raise RuntimeError("Git untracked observation failed")
    paths = [path for path in completed.stdout.split(b"\0") if path]
    digest = _safe_worktree_paths_sha256(
        repo,
        paths,
        max_paths=max_paths,
        max_total_bytes=max_total_bytes,
        deadline_monotonic=deadline_monotonic,
    )
    _deadline_guard(deadline_monotonic, "untracked preimage capture")
    rechecked = probe(
        repo, ["ls-files", "--others", "--exclude-standard", "-z"]
    )
    if rechecked.returncode != 0:
        raise RuntimeError("Git untracked re-observation failed")
    rechecked_paths = [path for path in rechecked.stdout.split(b"\0") if path]
    if rechecked_paths != paths:
        raise RuntimeError("Git untracked path set changed during preimage capture")
    rechecked_digest = _safe_worktree_paths_sha256(
        repo,
        paths,
        max_paths=max_paths,
        max_total_bytes=max_total_bytes,
        deadline_monotonic=deadline_monotonic,
    )
    if rechecked_digest != digest:
        raise RuntimeError("Git untracked worktree changed during preimage capture")
    _deadline_guard(deadline_monotonic, "untracked preimage capture")
    final = probe(repo, ["ls-files", "--others", "--exclude-standard", "-z"])
    if final.returncode != 0:
        raise RuntimeError("Git untracked final observation failed")
    final_paths = [path for path in final.stdout.split(b"\0") if path]
    if final_paths != paths:
        raise RuntimeError("Git untracked path set changed during preimage capture")
    material = {"schema_version": 1, "count": len(paths), "worktree_sha256": digest}
    return {
        **material,
        "preimage_sha256": hashlib.sha256(
            consumer_surface.canonical_json_bytes(material)
        ).hexdigest(),
    }


def _same_open_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _revalidate_worktree_path(
    root_fd: int,
    components: list[bytes],
    parent_snapshots: list[tuple[bytes, os.stat_result]],
    leaf_snapshot: os.stat_result | None,
    *,
    label: str,
    symlink_target: bytes | None = None,
) -> None:
    """Prove the live pathname still resolves to the entry that was hashed."""

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.dup(root_fd)
    try:
        for component, expected in parent_snapshots:
            try:
                linked = os.stat(
                    component, dir_fd=directory_fd, follow_symlinks=False
                )
            except OSError as exc:
                raise RuntimeError(
                    f"{label} parent changed during preimage capture"
                ) from exc
            if not stat.S_ISDIR(linked.st_mode) or not _same_open_file(
                expected, linked
            ):
                raise RuntimeError(
                    f"{label} parent changed during preimage capture"
                )
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(next_fd)
                if not _same_open_file(expected, opened):
                    raise RuntimeError(
                        f"{label} parent changed during preimage capture"
                    )
            except BaseException:
                os.close(next_fd)
                raise
            os.close(directory_fd)
            directory_fd = next_fd

        leaf = components[-1]
        if leaf_snapshot is None:
            try:
                os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise RuntimeError(
                    f"{label} path changed during preimage capture"
                ) from exc
            raise RuntimeError(f"{label} path changed during preimage capture")

        try:
            linked_leaf = os.stat(
                leaf, dir_fd=directory_fd, follow_symlinks=False
            )
        except OSError as exc:
            raise RuntimeError(
                f"{label} path changed during preimage capture"
            ) from exc
        if not _same_open_file(leaf_snapshot, linked_leaf):
            raise RuntimeError(f"{label} path changed during preimage capture")

        if symlink_target is not None:
            current_target = os.readlink(leaf, dir_fd=directory_fd)
            current_target_bytes = (
                current_target
                if isinstance(current_target, bytes)
                else os.fsencode(current_target)
            )
            if current_target_bytes != symlink_target:
                raise RuntimeError(
                    f"{label} path changed during preimage capture"
                )
    finally:
        os.close(directory_fd)


def _tracked_worktree_sha256(
    repo: Path,
    index_bytes: bytes,
    *,
    max_paths: int | None = None,
    max_total_bytes: int | None = None,
    deadline_monotonic: float | None = None,
) -> str:
    """Hash raw tracked worktree bytes without Git clean/smudge normalization."""
    if max_paths is not None and max_paths < 1:
        raise ValueError("max_paths must be positive")
    if max_total_bytes is not None and max_total_bytes < 1:
        raise ValueError("max_total_bytes must be positive")
    _deadline_guard(deadline_monotonic, "tracked worktree hashing")
    paths = _tracked_index_paths(index_bytes)
    if max_paths is not None and len(paths) > max_paths:
        raise RuntimeError("tracked worktree path limit exceeded")
    digest = hashlib.sha256()
    total_bytes = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW

    root_fd = os.open(repo, directory_flags)
    try:
        for path in paths:
            _deadline_guard(deadline_monotonic, "tracked worktree hashing")
            _frame(digest, b"path", path)
            components = path.split(b"/")
            directory_fd = os.dup(root_fd)
            parent_snapshots: list[tuple[bytes, os.stat_result]] = []
            try:
                blocked = False
                blocked_components: list[bytes] | None = None
                blocked_snapshot: os.stat_result | None = None
                blocked_symlink_target: bytes | None = None
                for component in components[:-1]:
                    _deadline_guard(deadline_monotonic, "tracked worktree hashing")
                    try:
                        linked = os.stat(
                            component, dir_fd=directory_fd, follow_symlinks=False
                        )
                    except FileNotFoundError:
                        _frame(digest, b"missing-parent", component)
                        blocked = True
                        blocked_components = [
                            name for name, _snapshot in parent_snapshots
                        ] + [component]
                        break
                    if not stat.S_ISDIR(linked.st_mode):
                        _frame(
                            digest,
                            b"blocked-parent-mode",
                            linked.st_mode.to_bytes(8, "big", signed=False),
                        )
                        if stat.S_ISLNK(linked.st_mode):
                            target = os.readlink(component, dir_fd=directory_fd)
                            blocked_symlink_target = (
                                target
                                if isinstance(target, bytes)
                                else os.fsencode(target)
                            )
                            _frame(
                                digest,
                                b"blocked-parent-link",
                                blocked_symlink_target,
                            )
                        blocked = True
                        blocked_snapshot = linked
                        blocked_components = [
                            name for name, _snapshot in parent_snapshots
                        ] + [component]
                        break
                    next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                    opened = os.fstat(next_fd)
                    if (
                        opened.st_dev != linked.st_dev
                        or opened.st_ino != linked.st_ino
                        or opened.st_mode != linked.st_mode
                    ):
                        os.close(next_fd)
                        raise RuntimeError(
                            "Tracked worktree parent changed during preimage capture"
                        )
                    parent_snapshots.append((component, opened))
                    os.close(directory_fd)
                    directory_fd = next_fd
                if blocked:
                    assert blocked_components is not None
                    _revalidate_worktree_path(
                        root_fd,
                        blocked_components,
                        parent_snapshots,
                        blocked_snapshot,
                        label="Tracked worktree blocked parent",
                        symlink_target=blocked_symlink_target,
                    )
                    continue

                leaf = components[-1]
                try:
                    linked = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        None,
                        label="Tracked worktree file",
                    )
                    _frame(digest, b"missing")
                    continue

                mode_bytes = linked.st_mode.to_bytes(8, "big", signed=False)
                if stat.S_ISREG(linked.st_mode):
                    descriptor = os.open(leaf, file_flags, dir_fd=directory_fd)
                    try:
                        opened_before = os.fstat(descriptor)
                        if (
                            opened_before.st_dev != linked.st_dev
                            or opened_before.st_ino != linked.st_ino
                            or opened_before.st_mode != linked.st_mode
                        ):
                            raise RuntimeError(
                                "Tracked worktree file changed during preimage capture"
                            )
                        content = hashlib.sha256()
                        size = 0
                        while True:
                            _deadline_guard(
                                deadline_monotonic, "tracked worktree hashing"
                            )
                            chunk = os.read(descriptor, 1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            total_bytes += len(chunk)
                            if (
                                max_total_bytes is not None
                                and total_bytes > max_total_bytes
                            ):
                                raise RuntimeError(
                                    "tracked worktree byte limit exceeded"
                                )
                            content.update(chunk)
                        opened_after = os.fstat(descriptor)
                        if not _same_open_file(opened_before, opened_after):
                            raise RuntimeError(
                                "Tracked worktree file changed during preimage capture"
                            )
                    finally:
                        os.close(descriptor)
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        opened_after,
                        label="Tracked worktree file",
                    )
                    _frame(digest, b"regular-mode", mode_bytes)
                    _frame(digest, b"regular-size", size.to_bytes(8, "big"))
                    _frame(digest, b"regular-content-sha256", content.digest())
                elif stat.S_ISLNK(linked.st_mode):
                    target = os.readlink(leaf, dir_fd=directory_fd)
                    target_bytes = (
                        target if isinstance(target, bytes) else os.fsencode(target)
                    )
                    total_bytes += len(target_bytes)
                    if (
                        max_total_bytes is not None
                        and total_bytes > max_total_bytes
                    ):
                        raise RuntimeError("tracked worktree byte limit exceeded")
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        linked,
                        label="Tracked worktree symlink",
                        symlink_target=target_bytes,
                    )
                    _frame(digest, b"symlink-mode", mode_bytes)
                    _frame(digest, b"symlink-target", target_bytes)
                elif stat.S_ISDIR(linked.st_mode):
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        linked,
                        label="Tracked worktree directory",
                    )
                    _frame(digest, b"directory-mode", mode_bytes)
                    _frame(digest, b"directory-inode", linked.st_ino.to_bytes(8, "big"))
                else:
                    _revalidate_worktree_path(
                        root_fd,
                        components,
                        parent_snapshots,
                        linked,
                        label="Tracked worktree special entry",
                    )
                    _frame(digest, b"special-mode", mode_bytes)
                    _frame(
                        digest,
                        b"special-rdev",
                        linked.st_rdev.to_bytes(8, "big", signed=False),
                    )
            finally:
                os.close(directory_fd)
    finally:
        os.close(root_fd)
    return digest.hexdigest()


def _git_operation_state_markers(
    git_dir: Path,
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, str]:
    """Observe administrative Git operation state without following path aliases."""

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(git_dir, directory_flags)
    except OSError as exc:
        raise RuntimeError("Git operation-state directory could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        markers: dict[str, str] = {}
        for name, expected_kind in (
            ("rebase-apply", "directory"),
            ("rebase-merge", "directory"),
            ("sequencer", "directory"),
            ("BISECT_START", "regular"),
            ("BISECT_LOG", "regular"),
            ("BISECT_TERMS", "regular"),
            ("BISECT_NAMES", "regular"),
            ("NOTES_MERGE_REF", "regular"),
            ("NOTES_MERGE_PARTIAL", "regular"),
            ("NOTES_MERGE_WORKTREE", "directory"),
        ):
            _deadline_guard(deadline_monotonic, "Git operation-state observation")
            try:
                observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RuntimeError(
                    f"Git operation-state observation failed: {name}"
                ) from exc
            if stat.S_ISLNK(observed.st_mode):
                raise RuntimeError(
                    f"Git operation-state marker is a symlink: {name}"
                )
            if (
                expected_kind == "directory" and not stat.S_ISDIR(observed.st_mode)
            ) or (
                expected_kind == "regular" and not stat.S_ISREG(observed.st_mode)
            ):
                raise RuntimeError(
                    f"Git operation-state marker has unexpected type: {name}"
                )
            if name == "NOTES_MERGE_WORKTREE":
                child = os.open(name, directory_flags, dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if not _same_open_file(observed, opened):
                        raise RuntimeError(
                            "Git notes-merge worktree changed during observation"
                        )
                    with os.scandir(child) as entries:
                        has_entries = next(entries, None) is not None
                    current = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False
                    )
                    if not _same_open_file(observed, current):
                        raise RuntimeError(
                            "Git notes-merge worktree changed during observation"
                        )
                finally:
                    os.close(child)
                if not has_entries:
                    continue
            markers[f"STATE:{name}"] = "present"
        after = os.fstat(descriptor)
        if not _same_open_file(before, after):
            raise RuntimeError(
                "Git operation-state directory changed during preimage capture"
            )
        return markers
    finally:
        os.close(descriptor)


def _require_effective_git_toplevel(
    repo: Path,
    probe: Callable[[Path, list[str]], subprocess.CompletedProcess[bytes]],
    *,
    deadline_monotonic: float | None = None,
) -> str:
    """Require Git command semantics to remain bound to the managed checkout root."""

    _deadline_guard(deadline_monotonic, "Git effective worktree observation")
    observed = probe(repo, ["rev-parse", "--show-toplevel"])
    if observed.returncode != 0:
        raise RuntimeError("Git effective worktree observation failed")
    try:
        payload = observed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Git effective worktree root is not valid UTF-8") from exc
    root_text = payload.rstrip("\r\n")
    if (
        not root_text
        or "\x00" in root_text
        or "\n" in root_text
        or "\r" in root_text
        or not os.path.isabs(root_text)
    ):
        raise RuntimeError("Git effective worktree root is invalid")
    effective = Path(os.path.abspath(os.path.normpath(root_text)))
    if effective != repo:
        raise RuntimeError(
            "Git effective worktree root does not match the managed checkout"
        )
    return str(effective)


def capture_branch_preimage(
    repo: Path,
    probe: Callable[[Path, list[str]], subprocess.CompletedProcess[bytes]],
    *,
    require_attached: bool = True,
    index_probe: Callable[[Path, list[str]], subprocess.CompletedProcess[bytes]] | None = None,
    max_tracked_paths: int | None = None,
    max_tracked_bytes: int | None = None,
    deadline_monotonic: float | None = None,
    reject_gitlinks: bool = False,
) -> dict[str, Any]:
    """Build one exact branch/index/raw-worktree CAS preimage from safe observations.

    Physical identity brackets the capture and detects persistent checkout replacement.
    The injected Git probe is caller-owned and is not descriptor-pinned against a
    transient same-UID swap-and-restore race during an individual subprocess probe.
    """
    requested_repo = Path(os.path.abspath(os.fspath(repo)))
    _deadline_guard(deadline_monotonic, "branch preimage capture")
    physical_before = physical_checkout.capture_physical_checkout_identity(requested_repo)
    repo = Path(physical_before["root"]["path"])
    _require_effective_git_toplevel(
        repo,
        probe,
        deadline_monotonic=deadline_monotonic,
    )
    branch_probe = probe(repo, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    branch: str | None = None
    if branch_probe.returncode == 0:
        branch = branch_probe.stdout.decode("utf-8", errors="strict").strip()
        if not branch:
            raise RuntimeError("Git branch observation returned an empty branch")
    elif branch_probe.returncode != 1:
        raise RuntimeError("Git branch observation failed")
    if require_attached and branch is None:
        raise PermissionError("Local branch mutation requires an attached Git branch")

    head_probe = probe(repo, ["rev-parse", "--verify", "--quiet", "HEAD"])
    head: str | None
    head_state: str
    if head_probe.returncode == 0:
        head = head_probe.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", head) is None:
            raise RuntimeError("Git HEAD observation is not an object id")
        head_state = "present"
    elif head_probe.returncode == 1 and branch is not None:
        head = None
        head_state = "unborn"
    else:
        raise RuntimeError("Git HEAD observation failed")

    _deadline_guard(deadline_monotonic, "branch preimage capture")
    index_reader = index_probe or probe
    index_result = index_reader(repo, ["ls-files", "--stage", "-z"])
    if index_result.returncode != 0:
        raise RuntimeError("Git index observation failed")
    if reject_gitlinks and any(
        record.startswith(b"160000 ")
        for record in index_result.stdout.split(b"\0")
        if record
    ):
        raise RuntimeError("Git index contains a tracked submodule")
    index_sha256 = hashlib.sha256(index_result.stdout).hexdigest()
    worktree_sha256 = _tracked_worktree_sha256(
        repo,
        index_result.stdout,
        max_paths=max_tracked_paths,
        max_total_bytes=max_tracked_bytes,
        deadline_monotonic=deadline_monotonic,
    )

    operation_refs: dict[str, str] = _git_operation_state_markers(
        Path(physical_before["git_dir"]["path"]),
        deadline_monotonic=deadline_monotonic,
    )
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD"):
        _deadline_guard(deadline_monotonic, "branch preimage capture")
        ref_probe = probe(repo, ["rev-parse", "--verify", "--quiet", name])
        if ref_probe.returncode == 0:
            value = ref_probe.stdout.decode("ascii", errors="strict").strip()
            if value:
                operation_refs[name] = value
        elif ref_probe.returncode != 1:
            raise RuntimeError(f"Git operation-state observation failed: {name}")

    _require_effective_git_toplevel(
        repo,
        probe,
        deadline_monotonic=deadline_monotonic,
    )
    try:
        physical_checkout.verify_physical_checkout_identity(physical_before)
    except physical_checkout.PhysicalCheckoutIdentityError as exc:
        raise physical_checkout.PhysicalCheckoutIdentityError(
            "physical checkout identity changed during preimage capture"
        ) from exc

    _deadline_guard(deadline_monotonic, "branch preimage capture")
    index_recheck = index_reader(repo, ["ls-files", "--stage", "-z"])
    if index_recheck.returncode != 0:
        raise RuntimeError("Git index re-observation failed")
    if index_recheck.stdout != index_result.stdout:
        raise RuntimeError("Git index changed during preimage capture")

    rechecked_worktree_sha256 = _tracked_worktree_sha256(
        repo,
        index_result.stdout,
        max_paths=max_tracked_paths,
        max_total_bytes=max_tracked_bytes,
        deadline_monotonic=deadline_monotonic,
    )
    if rechecked_worktree_sha256 != worktree_sha256:
        raise RuntimeError("Git tracked worktree changed during preimage capture")

    _deadline_guard(deadline_monotonic, "branch preimage capture")
    final_branch_probe = probe(
        repo, ["symbolic-ref", "--quiet", "--short", "HEAD"]
    )
    if final_branch_probe.returncode == 0:
        final_branch = final_branch_probe.stdout.decode(
            "utf-8", errors="strict"
        ).strip()
        if not final_branch:
            raise RuntimeError("Git final branch observation returned an empty branch")
    elif final_branch_probe.returncode == 1:
        final_branch = None
    else:
        raise RuntimeError("Git final branch observation failed")
    if final_branch != branch:
        raise RuntimeError("Git branch changed during preimage capture")

    final_head_probe = probe(repo, ["rev-parse", "--verify", "--quiet", "HEAD"])
    if final_head_probe.returncode == 0:
        final_head = final_head_probe.stdout.decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", final_head) is None:
            raise RuntimeError("Git final HEAD observation is not an object id")
        final_head_state = "present"
    elif final_head_probe.returncode == 1 and final_branch is not None:
        final_head = None
        final_head_state = "unborn"
    else:
        raise RuntimeError("Git final HEAD observation failed")
    if final_head != head or final_head_state != head_state:
        raise RuntimeError("Git HEAD changed during preimage capture")

    final_operation_refs = _git_operation_state_markers(
        Path(physical_before["git_dir"]["path"]),
        deadline_monotonic=deadline_monotonic,
    )
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD"):
        _deadline_guard(deadline_monotonic, "branch preimage capture")
        ref_probe = probe(repo, ["rev-parse", "--verify", "--quiet", name])
        if ref_probe.returncode == 0:
            value = ref_probe.stdout.decode("ascii", errors="strict").strip()
            if value:
                final_operation_refs[name] = value
        elif ref_probe.returncode != 1:
            raise RuntimeError(f"Git final operation-state observation failed: {name}")
    if final_operation_refs != operation_refs:
        raise RuntimeError("Git operation state changed during preimage capture")

    _require_effective_git_toplevel(
        repo,
        probe,
        deadline_monotonic=deadline_monotonic,
    )
    try:
        physical_checkout.verify_physical_checkout_identity(physical_before)
    except physical_checkout.PhysicalCheckoutIdentityError as exc:
        raise physical_checkout.PhysicalCheckoutIdentityError(
            "physical checkout identity changed during preimage capture"
        ) from exc

    _deadline_guard(deadline_monotonic, "branch preimage capture")
    final_index = index_reader(repo, ["ls-files", "--stage", "-z"])
    if final_index.returncode != 0:
        raise RuntimeError("Git final index observation failed")
    if final_index.stdout != index_result.stdout:
        raise RuntimeError("Git index changed during preimage capture")

    terminal_worktree_sha256 = _tracked_worktree_sha256(
        repo,
        index_result.stdout,
        max_paths=max_tracked_paths,
        max_total_bytes=max_tracked_bytes,
        deadline_monotonic=deadline_monotonic,
    )
    if terminal_worktree_sha256 != worktree_sha256:
        raise RuntimeError("Git tracked worktree changed during preimage capture")

    _deadline_guard(deadline_monotonic, "branch preimage capture")
    terminal_index = index_reader(repo, ["ls-files", "--stage", "-z"])
    if terminal_index.returncode != 0:
        raise RuntimeError("Git terminal index observation failed")
    if terminal_index.stdout != index_result.stdout:
        raise RuntimeError("Git index changed during preimage capture")

    material: dict[str, Any] = {
        "schema_version": 2,
        "repository": str(repo),
        "physical_checkout": physical_before,
        "branch": branch,
        "head": head,
        "head_state": head_state,
        "index_sha256": index_sha256,
        "worktree_sha256": worktree_sha256,
        "operation_refs": operation_refs,
    }
    return {
        **material,
        "preimage_sha256": hashlib.sha256(
            consumer_surface.canonical_json_bytes(material)
        ).hexdigest(),
    }
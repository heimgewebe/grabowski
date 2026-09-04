from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
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


def _tracked_worktree_sha256(repo: Path, index_bytes: bytes) -> str:
    """Hash raw tracked worktree bytes without Git clean/smudge normalization."""
    digest = hashlib.sha256()
    # Git diff can normalize bytes or trust index hints, while hash-object --stdin-paths
    # follows symlinks and cannot represent newline-containing paths safely. Walk the
    # index-declared paths through no-follow dirfds so the CAS binds the raw entries
    # that a destructive checkout/restore/reset could replace.
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW

    root_fd = os.open(repo, directory_flags)
    try:
        for path in _tracked_index_paths(index_bytes):
            _frame(digest, b"path", path)
            components = path.split(b"/")
            directory_fd = os.dup(root_fd)
            try:
                blocked = False
                for component in components[:-1]:
                    try:
                        linked = os.stat(
                            component, dir_fd=directory_fd, follow_symlinks=False
                        )
                    except FileNotFoundError:
                        _frame(digest, b"missing-parent", component)
                        blocked = True
                        break
                    if not stat.S_ISDIR(linked.st_mode):
                        _frame(
                            digest,
                            b"blocked-parent-mode",
                            linked.st_mode.to_bytes(8, "big", signed=False),
                        )
                        if stat.S_ISLNK(linked.st_mode):
                            target = os.readlink(component, dir_fd=directory_fd)
                            _frame(
                                digest,
                                b"blocked-parent-link",
                                target
                                if isinstance(target, bytes)
                                else os.fsencode(target),
                            )
                        blocked = True
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
                    os.close(directory_fd)
                    directory_fd = next_fd
                if blocked:
                    continue

                leaf = components[-1]
                try:
                    linked = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
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
                            chunk = os.read(descriptor, 1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            content.update(chunk)
                        opened_after = os.fstat(descriptor)
                        if not _same_open_file(opened_before, opened_after):
                            raise RuntimeError(
                                "Tracked worktree file changed during preimage capture"
                            )
                    finally:
                        os.close(descriptor)
                    _frame(digest, b"regular-mode", mode_bytes)
                    _frame(digest, b"regular-size", size.to_bytes(8, "big"))
                    _frame(digest, b"regular-content-sha256", content.digest())
                elif stat.S_ISLNK(linked.st_mode):
                    target = os.readlink(leaf, dir_fd=directory_fd)
                    _frame(digest, b"symlink-mode", mode_bytes)
                    _frame(
                        digest,
                        b"symlink-target",
                        target if isinstance(target, bytes) else os.fsencode(target),
                    )
                elif stat.S_ISDIR(linked.st_mode):
                    _frame(digest, b"directory-mode", mode_bytes)
                    _frame(digest, b"directory-inode", linked.st_ino.to_bytes(8, "big"))
                else:
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


def capture_branch_preimage(
    repo: Path,
    probe: Callable[[list[str]], subprocess.CompletedProcess[bytes]],
    *,
    require_attached: bool = True,
) -> dict[str, Any]:
    """Build one exact branch/index/raw-worktree CAS preimage from safe observations."""
    repo = Path(os.path.abspath(os.fspath(repo)))
    physical_before = physical_checkout.capture_physical_checkout_identity(repo)
    branch_probe = probe(["symbolic-ref", "--quiet", "--short", "HEAD"])
    branch: str | None = None
    if branch_probe.returncode == 0:
        branch = branch_probe.stdout.decode("utf-8", errors="strict").strip()
        if not branch:
            raise RuntimeError("Git branch observation returned an empty branch")
    elif branch_probe.returncode != 1:
        raise RuntimeError("Git branch observation failed")
    if require_attached and branch is None:
        raise PermissionError("Local branch mutation requires an attached Git branch")

    head_probe = probe(["rev-parse", "--verify", "--quiet", "HEAD"])
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

    index_probe = probe(["ls-files", "--stage", "-z"])
    if index_probe.returncode != 0:
        raise RuntimeError("Git index observation failed")
    index_sha256 = hashlib.sha256(index_probe.stdout).hexdigest()
    worktree_sha256 = _tracked_worktree_sha256(repo, index_probe.stdout)

    operation_refs: dict[str, str] = {}
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD"):
        ref_probe = probe(["rev-parse", "--verify", "--quiet", name])
        if ref_probe.returncode == 0:
            value = ref_probe.stdout.decode("ascii", errors="strict").strip()
            if value:
                operation_refs[name] = value
        elif ref_probe.returncode != 1:
            raise RuntimeError(f"Git operation-state observation failed: {name}")

    try:
        physical_checkout.verify_physical_checkout_identity(physical_before)
    except physical_checkout.PhysicalCheckoutIdentityError as exc:
        raise physical_checkout.PhysicalCheckoutIdentityError(
            "physical checkout identity changed during preimage capture"
        ) from exc

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

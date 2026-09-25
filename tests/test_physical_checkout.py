from __future__ import annotations

from pathlib import Path
import copy
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import grabowski_git_preimage as git_preimage
import grabowski_physical_checkout as physical_checkout


class PhysicalCheckoutIdentityTests(unittest.TestCase):
    def _run(self, *argv: str, cwd: Path | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            list(argv),
            cwd=None if cwd is None else str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def _init_committed_repo(self, path: Path, *, branch: str = "feature") -> None:
        self._run("git", "init", "-q", "-b", branch, str(path))
        self._run("git", "config", "user.name", "Grabowski Test", cwd=path)
        self._run(
            "git",
            "config",
            "user.email",
            "grabowski@example.invalid",
            cwd=path,
        )
        (path / "README.md").write_text("baseline\n", encoding="utf-8")
        self._run("git", "add", "README.md", cwd=path)
        self._run("git", "commit", "-q", "-m", "baseline", cwd=path)

    def _probe(self, _repo: Path):
        def run(
            checkout_root: Path, arguments: list[str]
        ) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                ["git", "-C", str(checkout_root), *arguments],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        return run

    def test_same_path_clone_replacement_is_detected_and_binds_branch_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            checkout = root / "checkout"
            retired = root / "retired"
            self._init_committed_repo(source)
            self._run("git", "clone", "-q", str(source), str(checkout))

            identity_before = physical_checkout.capture_physical_checkout_identity(
                checkout
            )
            preimage_before = git_preimage.capture_branch_preimage(
                checkout, self._probe(checkout)
            )

            checkout.rename(retired)
            self._run("git", "clone", "-q", str(source), str(checkout))

            identity_after = physical_checkout.capture_physical_checkout_identity(
                checkout
            )
            preimage_after = git_preimage.capture_branch_preimage(
                checkout, self._probe(checkout)
            )

            self.assertEqual(preimage_before["branch"], preimage_after["branch"])
            self.assertEqual(preimage_before["head"], preimage_after["head"])
            self.assertEqual(
                preimage_before["index_sha256"], preimage_after["index_sha256"]
            )
            self.assertEqual(
                preimage_before["worktree_sha256"],
                preimage_after["worktree_sha256"],
            )
            self.assertEqual(
                identity_before["root"]["path"], identity_after["root"]["path"]
            )
            self.assertEqual(
                identity_before["git_dir"]["path"],
                identity_after["git_dir"]["path"],
            )
            self.assertNotEqual(
                identity_before["physical_identity_sha256"],
                identity_after["physical_identity_sha256"],
            )
            self.assertNotEqual(
                preimage_before["preimage_sha256"], preimage_after["preimage_sha256"]
            )
            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.verify_physical_checkout_identity(identity_before)

    def test_stable_gitdir_pointer_detects_metadata_directory_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            metadata = root / "metadata"
            retired_metadata = root / "retired-metadata"
            replacement = root / "replacement"
            self._init_committed_repo(checkout)

            shutil.move(str(checkout / ".git"), str(metadata))
            pointer = f"gitdir: {metadata}\n"
            (checkout / ".git").write_text(pointer, encoding="utf-8")
            before = physical_checkout.capture_physical_checkout_identity(checkout)

            metadata.rename(retired_metadata)
            self._run("git", "init", "-q", str(replacement))
            shutil.move(str(replacement / ".git"), str(metadata))
            replacement.rmdir()

            self.assertEqual(pointer, (checkout / ".git").read_text(encoding="utf-8"))
            after = physical_checkout.capture_physical_checkout_identity(checkout)
            self.assertEqual(before["git_dir"]["path"], after["git_dir"]["path"])
            self.assertNotEqual(before["git_dir"]["inode"], after["git_dir"]["inode"])
            self.assertNotEqual(
                before["physical_identity_sha256"], after["physical_identity_sha256"]
            )

    def test_content_commit_branch_and_remote_changes_are_not_physical_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_committed_repo(repo)
            baseline = physical_checkout.capture_physical_checkout_identity(repo)

            (repo / "README.md").write_text("dirty\n", encoding="utf-8")
            dirty = physical_checkout.capture_physical_checkout_identity(repo)
            self.assertEqual(
                baseline["physical_identity_sha256"], dirty["physical_identity_sha256"]
            )

            self._run("git", "add", "README.md", cwd=repo)
            self._run("git", "commit", "-q", "-m", "content", cwd=repo)
            committed = physical_checkout.capture_physical_checkout_identity(repo)
            self.assertEqual(
                baseline["physical_identity_sha256"],
                committed["physical_identity_sha256"],
            )

            self._run("git", "checkout", "-q", "-b", "other", cwd=repo)
            branched = physical_checkout.capture_physical_checkout_identity(repo)
            self.assertEqual(
                baseline["physical_identity_sha256"], branched["physical_identity_sha256"]
            )

            self._run(
                "git",
                "remote",
                "add",
                "origin",
                "https://example.invalid/repository.git",
                cwd=repo,
            )
            remote_changed = physical_checkout.capture_physical_checkout_identity(repo)
            self.assertEqual(
                baseline["physical_identity_sha256"],
                remote_changed["physical_identity_sha256"],
            )

    def test_linked_worktree_resolves_distinct_git_and_common_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "worktree"
            self._init_committed_repo(repo, branch="main")
            self._run(
                "git",
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                str(worktree),
                "HEAD",
                cwd=repo,
            )

            identity = physical_checkout.capture_physical_checkout_identity(worktree)
            self.assertEqual(str(worktree), identity["root"]["path"])
            self.assertNotEqual(
                identity["git_dir"]["path"], identity["common_dir"]["path"]
            )
            physical_checkout.verify_physical_checkout_identity(identity)

    def test_registered_linked_worktree_git_dir_is_exact_and_ambiguity_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "worktree"
            self._init_committed_repo(repo, branch="main")
            self._run(
                "git",
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                str(worktree),
                "HEAD",
                cwd=repo,
            )

            identity = physical_checkout.capture_physical_checkout_identity(worktree)
            registered = physical_checkout.capture_registered_linked_worktree_git_dir(
                identity["common_dir"]["path"], worktree
            )
            self.assertEqual(identity["git_dir"], registered)

            fake = Path(identity["common_dir"]["path"]) / "worktrees" / "fake"
            fake.mkdir()
            (fake / "gitdir").write_text(
                str(worktree / ".git") + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                physical_checkout.PhysicalCheckoutIdentityError,
                "entry bound",
            ):
                physical_checkout.capture_registered_linked_worktree_git_dir(
                    identity["common_dir"]["path"], worktree, max_entries=1
                )
            with self.assertRaisesRegex(
                physical_checkout.PhysicalCheckoutIdentityError,
                "missing or ambiguous",
            ):
                physical_checkout.capture_registered_linked_worktree_git_dir(
                    identity["common_dir"]["path"], worktree
                )

    def test_registered_gitdir_backlink_drift_is_detected_before_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "worktree"
            self._init_committed_repo(repo, branch="main")
            self._run(
                "git",
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                str(worktree),
                "HEAD",
                cwd=repo,
            )
            identity = physical_checkout.capture_physical_checkout_identity(worktree)
            backlink = Path(identity["git_dir"]["path"]) / "gitdir"
            original_open = physical_checkout._open_absolute_directory

            def drift_before_final_open(path: Path, *, label: str):
                if label == "registered worktree git directory":
                    backlink.write_text(
                        str(root / "replacement" / ".git") + "\n",
                        encoding="utf-8",
                    )
                return original_open(path, label=label)

            with (
                patch.object(
                    physical_checkout,
                    "_open_absolute_directory",
                    side_effect=drift_before_final_open,
                ),
                self.assertRaisesRegex(
                    physical_checkout.PhysicalCheckoutIdentityError,
                    "git worktree backlink changed during capture",
                ),
            ):
                physical_checkout.capture_registered_linked_worktree_git_dir(
                    identity["common_dir"]["path"], worktree
                )

    def test_nonmatching_backlink_drift_is_detected_before_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "worktree"
            other = root / "other"
            self._init_committed_repo(repo, branch="main")
            self._run(
                "git",
                "worktree",
                "add",
                "-q",
                "-b",
                "linked-target",
                str(worktree),
                "HEAD",
                cwd=repo,
            )
            self._run(
                "git",
                "worktree",
                "add",
                "-q",
                "-b",
                "linked-other",
                str(other),
                "HEAD",
                cwd=repo,
            )

            identity = physical_checkout.capture_physical_checkout_identity(worktree)
            other_identity = physical_checkout.capture_physical_checkout_identity(other)
            other_backlink = Path(other_identity["git_dir"]["path"]) / "gitdir"
            original_scandir = physical_checkout.os.scandir

            class DriftAfterScan:
                def __init__(self, iterator):
                    self.iterator = iterator
                    self.drifted = False

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    self.iterator.close()
                    return False

                def __iter__(self):
                    return self

                def __next__(self):
                    try:
                        return next(self.iterator)
                    except StopIteration:
                        if not self.drifted:
                            other_backlink.write_text(
                                str(worktree / ".git") + "\n",
                                encoding="utf-8",
                            )
                            self.drifted = True
                        raise

            with (
                patch.object(
                    physical_checkout.os,
                    "scandir",
                    side_effect=lambda fd: DriftAfterScan(original_scandir(fd)),
                ),
                self.assertRaisesRegex(
                    physical_checkout.PhysicalCheckoutIdentityError,
                    "git worktree backlink changed during capture",
                ),
            ):
                physical_checkout.capture_registered_linked_worktree_git_dir(
                    identity["common_dir"]["path"], worktree
                )

    def test_new_registration_during_backlink_revalidation_is_detected_before_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "worktree"
            self._init_committed_repo(repo, branch="main")
            self._run(
                "git",
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                str(worktree),
                "HEAD",
                cwd=repo,
            )

            identity = physical_checkout.capture_physical_checkout_identity(worktree)
            registered_name = Path(identity["git_dir"]["path"]).name
            worktrees = Path(identity["common_dir"]["path"]) / "worktrees"
            duplicate = worktrees / "late-duplicate"
            original_open = physical_checkout._open_relative_directory
            target_admin_open_count = 0

            def create_duplicate_during_revalidation(
                parent_descriptor: int,
                name: str,
                *,
                label: str,
            ):
                nonlocal target_admin_open_count
                if (
                    label == "git worktree admin directory"
                    and name == registered_name
                ):
                    target_admin_open_count += 1
                    if target_admin_open_count == 2:
                        duplicate.mkdir()
                        (duplicate / "gitdir").write_text(
                            str(worktree / ".git") + "\n",
                            encoding="utf-8",
                        )
                return original_open(parent_descriptor, name, label=label)

            with (
                patch.object(
                    physical_checkout,
                    "_open_relative_directory",
                    side_effect=create_duplicate_during_revalidation,
                ),
                self.assertRaisesRegex(
                    physical_checkout.PhysicalCheckoutIdentityError,
                    "git worktrees directory changed during registered identity capture",
                ),
            ):
                physical_checkout.capture_registered_linked_worktree_git_dir(
                    identity["common_dir"]["path"], worktree
                )

            self.assertEqual(2, target_admin_open_count)

    def test_untracked_hash_rejects_atomic_leaf_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "file.txt"
            replacement = root / "replacement.tmp"
            target.write_bytes(b"old-bytes")
            replacement.write_bytes(b"new-bytes")
            original_read = git_preimage.os.read
            replaced = False

            def replace_after_first_read(fd: int, size: int) -> bytes:
                nonlocal replaced
                chunk = original_read(fd, size)
                if chunk and not replaced:
                    os.replace(replacement, target)
                    replaced = True
                return chunk

            with (
                patch.object(
                    git_preimage.os,
                    "read",
                    side_effect=replace_after_first_read,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "(?:Worktree file changed|Untracked worktree file path changed) during preimage capture",
                ),
            ):
                git_preimage._safe_worktree_paths_sha256(
                    root,
                    [b"file.txt"],
                    max_paths=10,
                )

    def test_tracked_hash_rejects_parent_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "sub"
            replacement_parent = root / "replacement-sub"
            retired_parent = root / "retired-sub"
            parent.mkdir()
            replacement_parent.mkdir()
            (parent / "file.txt").write_bytes(b"old-bytes")
            (replacement_parent / "file.txt").write_bytes(b"new-bytes")
            index = b"100644 " + (b"a" * 40) + b" 0\tsub/file.txt\0"
            original_read = git_preimage.os.read
            replaced = False

            def replace_parent_after_first_read(fd: int, size: int) -> bytes:
                nonlocal replaced
                chunk = original_read(fd, size)
                if chunk and not replaced:
                    parent.rename(retired_parent)
                    replacement_parent.rename(parent)
                    replaced = True
                return chunk

            with (
                patch.object(
                    git_preimage.os,
                    "read",
                    side_effect=replace_parent_after_first_read,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "Tracked worktree file parent changed during preimage capture",
                ),
            ):
                git_preimage._tracked_worktree_sha256(
                    root,
                    index,
                    max_paths=10,
                )

    def test_tracked_hash_revalidates_missing_parent_before_accepting_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = b"100644 " + (b"a" * 40) + b" 0\tdir/file.txt\0"
            original_stat = git_preimage.os.stat
            created = False

            def create_after_missing_parent(path, *args, **kwargs):
                nonlocal created
                try:
                    return original_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    if path == b"dir" and not created:
                        (root / "dir").mkdir()
                        (root / "dir" / "file.txt").write_bytes(b"late-bytes")
                        created = True
                    raise

            with (
                patch.object(
                    git_preimage.os,
                    "stat",
                    side_effect=create_after_missing_parent,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "Tracked worktree blocked parent path changed during preimage capture",
                ),
            ):
                git_preimage._tracked_worktree_sha256(
                    root,
                    index,
                    max_paths=10,
                )

    def test_branch_preimage_detects_rebase_apply_operation_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_committed_repo(repo, branch="main")
            (repo / ".git" / "rebase-apply").mkdir()

            preimage = git_preimage.capture_branch_preimage(
                repo,
                self._probe(repo),
            )

            self.assertEqual(
                "present",
                preimage["operation_refs"]["STATE:rebase-apply"],
            )

    def test_gitdir_pointer_preserves_whitespace_as_path_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            metadata = root / "metadata"
            self._init_committed_repo(checkout)
            shutil.move(str(checkout / ".git"), str(metadata))
            (checkout / ".git").write_text(
                f"gitdir: {metadata} \n", encoding="utf-8"
            )

            git_probe = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "--absolute-git-dir"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, git_probe.returncode)
            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.capture_physical_checkout_identity(checkout)

    def test_verify_rejects_schema_shape_and_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_committed_repo(repo)
            identity = physical_checkout.capture_physical_checkout_identity(repo)
            cases = []
            wrong_schema = copy.deepcopy(identity)
            wrong_schema["schema_version"] = 999
            cases.append(wrong_schema)
            wrong_hash = copy.deepcopy(identity)
            wrong_hash["physical_identity_sha256"] = "0" * 64
            cases.append(wrong_hash)
            wrong_inode_type = copy.deepcopy(identity)
            wrong_inode_type["git_dir"]["inode"] = "not-an-int"
            cases.append(wrong_inode_type)
            extra_field = copy.deepcopy(identity)
            extra_field["unexpected"] = True
            cases.append(extra_field)

            for expected in cases:
                with self.subTest(expected=expected):
                    with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                        physical_checkout.verify_physical_checkout_identity(expected)

    def test_branch_preimage_records_one_absolute_repository_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_committed_repo(repo)
            relative = Path(os.path.relpath(repo, Path.cwd()))

            preimage = git_preimage.capture_branch_preimage(relative, self._probe(relative))

            absolute = str(Path(os.path.abspath(os.fspath(relative))))
            self.assertEqual(absolute, preimage["repository"])
            self.assertEqual(absolute, preimage["physical_checkout"]["root"]["path"])

    def test_relative_gitdir_pointer_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            metadata = root / "metadata"
            self._init_committed_repo(checkout)
            shutil.move(str(checkout / ".git"), str(metadata))
            (checkout / ".git").write_text("gitdir: ../metadata\n", encoding="utf-8")

            identity = physical_checkout.capture_physical_checkout_identity(checkout)

            self.assertEqual(str(metadata), identity["git_dir"]["path"])
            physical_checkout.verify_physical_checkout_identity(identity)

    def test_gitdir_pointer_symlink_before_parent_is_rejected_before_collapse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            deep = root / "deep"
            real2 = deep / "real2"
            actual_metadata = deep / "m2"
            decoy_metadata = root / "m2"
            link = root / "link"
            self._init_committed_repo(checkout)
            deep.mkdir()
            real2.mkdir()
            shutil.move(str(checkout / ".git"), str(actual_metadata))
            decoy_metadata.mkdir()
            link.symlink_to(real2, target_is_directory=True)
            (checkout / ".git").write_text(
                "gitdir: ../link/../m2\n", encoding="utf-8"
            )

            git_probe = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "--absolute-git-dir"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertEqual(0, git_probe.returncode, git_probe.stderr)
            self.assertEqual(str(actual_metadata), git_probe.stdout.strip())
            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.capture_physical_checkout_identity(checkout)

    def test_subdirectory_capture_and_branch_preimage_bind_checkout_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            subdir = repo / "nested"
            self._init_committed_repo(repo)
            subdir.mkdir()
            (subdir / "tracked.txt").write_text("nested\n", encoding="utf-8")
            self._run("git", "add", "nested/tracked.txt", cwd=repo)
            self._run("git", "commit", "-q", "-m", "nested", cwd=repo)

            root_identity = physical_checkout.capture_physical_checkout_identity(repo)
            nested_identity = physical_checkout.capture_physical_checkout_identity(subdir)
            self.assertEqual(root_identity, nested_identity)

            root_preimage = git_preimage.capture_branch_preimage(
                repo, self._probe(repo)
            )
            nested_preimage = git_preimage.capture_branch_preimage(
                subdir, self._probe(subdir)
            )
            self.assertEqual(root_preimage, nested_preimage)
            self.assertEqual(str(repo), nested_preimage["repository"])
            self.assertEqual(str(repo), nested_preimage["physical_checkout"]["root"]["path"])

    def test_intermediate_symlink_component_is_rejected_by_current_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real-parent"
            repo = real_parent / "repo"
            alias_parent = root / "alias-parent"
            real_parent.mkdir()
            self._init_committed_repo(repo)
            alias_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.capture_physical_checkout_identity(alias_parent / "repo")

    def test_symlinked_dot_git_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            metadata = root / "metadata"
            self._init_committed_repo(checkout)
            shutil.move(str(checkout / ".git"), str(metadata))
            (checkout / ".git").symlink_to(metadata, target_is_directory=True)

            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.capture_physical_checkout_identity(checkout)

    def test_symlinked_checkout_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            alias = root / "alias"
            self._init_committed_repo(repo)
            alias.symlink_to(repo, target_is_directory=True)

            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.capture_physical_checkout_identity(alias)

    def test_symlinked_gitdir_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            metadata = root / "metadata"
            metadata_alias = root / "metadata-alias"
            self._init_committed_repo(checkout)
            shutil.move(str(checkout / ".git"), str(metadata))
            metadata_alias.symlink_to(metadata, target_is_directory=True)
            (checkout / ".git").write_text(
                f"gitdir: {metadata_alias}\n", encoding="utf-8"
            )

            with self.assertRaises(physical_checkout.PhysicalCheckoutIdentityError):
                physical_checkout.capture_physical_checkout_identity(checkout)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

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

    def _probe(self, repo: Path):
        def run(arguments: list[str]) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                ["git", "-C", str(repo), *arguments],
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

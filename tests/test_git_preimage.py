from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import grabowski_git_preimage as git_preimage


class GitPreimageOperationStateTests(unittest.TestCase):
    def _run(
        self, repo: Path, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def _probe(
        self, repo: Path, arguments: list[str]
    ) -> subprocess.CompletedProcess[bytes]:
        return self._run(repo, *arguments, check=False)

    def _init_repo(self, repo: Path) -> None:
        self._run(repo.parent, "init", "-q", "-b", "main", str(repo))
        self._run(repo, "config", "user.name", "Grabowski Test")
        self._run(
            repo,
            "config",
            "user.email",
            "grabowski@example.invalid",
        )
        tracked = repo / "tracked.txt"
        for index in range(3):
            tracked.write_text(f"revision {index}\n", encoding="utf-8")
            self._run(repo, "add", "tracked.txt")
            self._run(repo, "commit", "-q", "-m", f"revision {index}")

    def test_active_no_checkout_bisect_is_bound_into_branch_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)

            original_head = self._run(repo, "rev-parse", "HEAD").stdout.strip()
            self._run(repo, "bisect", "start", "--no-checkout", "HEAD", "HEAD~2")
            try:
                self.assertEqual(
                    original_head,
                    self._run(repo, "rev-parse", "HEAD").stdout.strip(),
                )
                preimage = git_preimage.capture_branch_preimage(repo, self._probe)
                self.assertEqual(
                    "present",
                    preimage["operation_refs"].get("STATE:BISECT_START"),
                )
            finally:
                self._run(repo, "bisect", "reset")

            settled = git_preimage.capture_branch_preimage(repo, self._probe)
            self.assertNotIn("STATE:BISECT_START", settled["operation_refs"])


    def test_conflicted_notes_merge_in_linked_worktree_is_bound_into_branch_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "linked"
            self._init_repo(repo)
            original_head = self._run(repo, "rev-parse", "HEAD").stdout.strip()
            self._run(
                repo,
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                str(worktree),
                "HEAD",
            )
            self._run(
                worktree,
                "notes",
                "--ref=left",
                "add",
                "-m",
                "left",
                original_head.decode("ascii"),
            )
            self._run(
                worktree,
                "notes",
                "--ref=right",
                "add",
                "-m",
                "right",
                original_head.decode("ascii"),
            )
            merge = self._run(
                worktree,
                "notes",
                "--ref=left",
                "merge",
                "-s",
                "manual",
                "refs/notes/right",
                check=False,
            )
            self.assertNotEqual(merge.returncode, 0)
            self.assertEqual(b"", self._run(worktree, "status", "--porcelain").stdout)
            self.assertEqual(
                original_head,
                self._run(worktree, "rev-parse", "HEAD").stdout.strip(),
            )

            preimage = git_preimage.capture_branch_preimage(
                worktree,
                self._probe,
            )
            self.assertEqual(
                "present",
                preimage["operation_refs"].get("STATE:NOTES_MERGE_REF"),
            )
            self.assertEqual(
                "present",
                preimage["operation_refs"].get("STATE:NOTES_MERGE_PARTIAL"),
            )
            self.assertEqual(
                "present",
                preimage["operation_refs"].get("STATE:NOTES_MERGE_WORKTREE"),
            )

            self._run(worktree, "notes", "--ref=left", "merge", "--abort")
            settled = git_preimage.capture_branch_preimage(
                worktree,
                self._probe,
            )
            self.assertNotIn(
                "STATE:NOTES_MERGE_REF",
                settled["operation_refs"],
            )
            self.assertNotIn(
                "STATE:NOTES_MERGE_PARTIAL",
                settled["operation_refs"],
            )
            self.assertNotIn(
                "STATE:NOTES_MERGE_WORKTREE",
                settled["operation_refs"],
            )


    def test_core_worktree_redirection_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            worktree = root / "linked"
            redirected = root / "redirected"
            redirected.mkdir()
            self._init_repo(repo)
            self._run(
                repo,
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                str(worktree),
                "HEAD",
            )
            self._run(repo, "config", "extensions.worktreeConfig", "true")
            self._run(
                worktree,
                "config",
                "--worktree",
                "core.worktree",
                str(redirected),
            )
            self.assertEqual(
                str(redirected).encode("utf-8"),
                self._run(worktree, "rev-parse", "--show-toplevel").stdout.strip(),
            )

            with self.assertRaisesRegex(
                RuntimeError,
                "effective worktree root does not match",
            ):
                git_preimage.capture_branch_preimage(
                    worktree,
                    self._probe,
                )


    def test_untracked_preimage_reenumerates_paths_after_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            listing_calls = 0

            def racing_probe(
                observed_repo: Path, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal listing_calls
                if arguments == [
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ]:
                    listing_calls += 1
                    if listing_calls == 2:
                        (repo / "late.txt").write_text(
                            "appeared during capture\n",
                            encoding="utf-8",
                        )
                return self._probe(observed_repo, arguments)

            with self.assertRaisesRegex(
                RuntimeError,
                "untracked path set changed during preimage capture",
            ):
                git_preimage.capture_untracked_preimage(
                    repo,
                    racing_probe,
                )
            self.assertEqual(2, listing_calls)

    def test_branch_preimage_rereads_index_after_tracked_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            index_calls = 0

            def racing_index_probe(
                observed_repo: Path, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal index_calls
                if arguments == ["ls-files", "--stage", "-z"]:
                    index_calls += 1
                    if index_calls == 2:
                        (repo / "tracked.txt").write_text(
                            "index changed during capture\n",
                            encoding="utf-8",
                        )
                        self._run(repo, "add", "tracked.txt")
                return self._probe(observed_repo, arguments)

            with self.assertRaisesRegex(
                RuntimeError,
                "index changed during preimage capture",
            ):
                git_preimage.capture_branch_preimage(
                    repo,
                    self._probe,
                    index_probe=racing_index_probe,
                )
            self.assertEqual(2, index_calls)


    def test_untracked_preimage_rehashes_content_after_path_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            untracked = repo / "untracked.txt"
            untracked.write_text("before\n", encoding="utf-8")
            listing_calls = 0

            def racing_probe(
                observed_repo: Path, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal listing_calls
                if arguments == [
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "-z",
                ]:
                    listing_calls += 1
                    if listing_calls == 2:
                        untracked.write_text("after\n", encoding="utf-8")
                return self._probe(observed_repo, arguments)

            with self.assertRaisesRegex(
                RuntimeError,
                "untracked worktree changed during preimage capture",
            ):
                git_preimage.capture_untracked_preimage(repo, racing_probe)
            self.assertEqual(2, listing_calls)

    def test_untracked_preimage_rechecks_paths_after_second_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            (repo / "untracked.txt").write_text("stable\n", encoding="utf-8")
            original_hash = git_preimage._safe_worktree_paths_sha256
            hash_calls = 0

            def racing_hash(*args, **kwargs):
                nonlocal hash_calls
                digest = original_hash(*args, **kwargs)
                hash_calls += 1
                if hash_calls == 2:
                    (repo / "late.txt").write_text(
                        "appeared after second hash\n",
                        encoding="utf-8",
                    )
                return digest

            with (
                patch.object(
                    git_preimage,
                    "_safe_worktree_paths_sha256",
                    side_effect=racing_hash,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "untracked path set changed during preimage capture",
                ),
            ):
                git_preimage.capture_untracked_preimage(repo, self._probe)
            self.assertEqual(2, hash_calls)

    def test_branch_preimage_rehashes_content_after_index_recheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            tracked = repo / "tracked.txt"
            tracked.write_text("before race\n", encoding="utf-8")
            index_calls = 0

            def racing_index_probe(
                observed_repo: Path, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal index_calls
                if arguments == ["ls-files", "--stage", "-z"]:
                    index_calls += 1
                    if index_calls == 2:
                        tracked.write_text("after race\n", encoding="utf-8")
                return self._probe(observed_repo, arguments)

            with self.assertRaisesRegex(
                RuntimeError,
                "tracked worktree changed during preimage capture",
            ):
                git_preimage.capture_branch_preimage(
                    repo,
                    self._probe,
                    index_probe=racing_index_probe,
                )
            self.assertEqual(2, index_calls)

    def test_branch_preimage_rechecks_index_after_second_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            tracked = repo / "tracked.txt"
            tracked.write_text("stable worktree\n", encoding="utf-8")
            original_hash = git_preimage._tracked_worktree_sha256
            hash_calls = 0
            index_calls = 0

            def counting_index_probe(
                observed_repo: Path, arguments: list[str]
            ) -> subprocess.CompletedProcess[bytes]:
                nonlocal index_calls
                if arguments == ["ls-files", "--stage", "-z"]:
                    index_calls += 1
                return self._probe(observed_repo, arguments)

            def racing_hash(*args, **kwargs):
                nonlocal hash_calls
                digest = original_hash(*args, **kwargs)
                hash_calls += 1
                if hash_calls == 2:
                    tracked.write_text(
                        "staged after second hash\n",
                        encoding="utf-8",
                    )
                    self._run(repo, "add", "tracked.txt")
                return digest

            with (
                patch.object(
                    git_preimage,
                    "_tracked_worktree_sha256",
                    side_effect=racing_hash,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "index changed during preimage capture",
                ),
            ):
                git_preimage.capture_branch_preimage(
                    repo,
                    self._probe,
                    index_probe=counting_index_probe,
                )
            self.assertEqual(2, hash_calls)
            self.assertEqual(3, index_calls)


    def test_branch_preimage_rechecks_head_after_second_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            original_hash = git_preimage._tracked_worktree_sha256
            hash_calls = 0

            def racing_hash(*args, **kwargs):
                nonlocal hash_calls
                digest = original_hash(*args, **kwargs)
                hash_calls += 1
                if hash_calls == 2:
                    self._run(
                        repo,
                        "commit",
                        "--allow-empty",
                        "-q",
                        "-m",
                        "advance during capture",
                    )
                return digest

            with (
                patch.object(
                    git_preimage,
                    "_tracked_worktree_sha256",
                    side_effect=racing_hash,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "HEAD changed during preimage capture",
                ),
            ):
                git_preimage.capture_branch_preimage(repo, self._probe)
            self.assertEqual(2, hash_calls)

    def test_branch_preimage_rechecks_operation_state_after_second_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            original_hash = git_preimage._tracked_worktree_sha256
            hash_calls = 0

            def racing_hash(*args, **kwargs):
                nonlocal hash_calls
                digest = original_hash(*args, **kwargs)
                hash_calls += 1
                if hash_calls == 2:
                    self._run(
                        repo,
                        "bisect",
                        "start",
                        "--no-checkout",
                        "HEAD",
                        "HEAD~2",
                    )
                return digest

            with (
                patch.object(
                    git_preimage,
                    "_tracked_worktree_sha256",
                    side_effect=racing_hash,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "operation state changed during preimage capture",
                ),
            ):
                git_preimage.capture_branch_preimage(repo, self._probe)
            self.assertEqual(2, hash_calls)


    def test_branch_preimage_rehashes_after_final_git_probes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)
            tracked = repo / "tracked.txt"
            tracked.write_text("stable before terminal race\n", encoding="utf-8")
            original_hash = git_preimage._tracked_worktree_sha256
            hash_calls = 0

            def racing_hash(*args, **kwargs):
                nonlocal hash_calls
                digest = original_hash(*args, **kwargs)
                hash_calls += 1
                if hash_calls == 2:
                    tracked.write_text(
                        "changed after second hash\n",
                        encoding="utf-8",
                    )
                return digest

            with (
                patch.object(
                    git_preimage,
                    "_tracked_worktree_sha256",
                    side_effect=racing_hash,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "tracked worktree changed during preimage capture",
                ),
            ):
                git_preimage.capture_branch_preimage(repo, self._probe)
            self.assertEqual(3, hash_calls)


if __name__ == "__main__":
    unittest.main()
from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import run_scheduled_deploy as worker


class ScheduledWorkerGitFilterTests(unittest.TestCase):
    """Only disposable Git repositories: no real release/host effects."""

    def test_repository_checks_pin_system_git_outside_ambient_path(self) -> None:
        with patch.dict(os.environ, {"PATH": "/tmp/poisoned", "GIT_EXEC_PATH": "/tmp/poisoned"}):
            binary = worker._git_prefix(Path("/tmp/example"))[0]
        self.assertTrue(Path(binary).is_absolute())
        self.assertIn(binary, ("/usr/bin/git", "/run/current-system/sw/bin/git"))

    def test_nixos_git_must_resolve_inside_immutable_store(self) -> None:
        # Even a root-managed system symlink must not redirect to /tmp.
        with (
            patch.object(
                worker.os.path, "lexists",
                side_effect=lambda path: str(path) == "/run/current-system/sw/bin/git",
            ),
            patch.object(Path, "lstat", return_value=SimpleNamespace(
                st_uid=0, st_mode=stat.S_IFLNK | 0o755,
            )),
            patch.object(Path, "resolve", return_value=Path("/tmp/attacker-git")),
            self.assertRaisesRegex(RuntimeError, "NixOS Git"),
        ):
            worker._trusted_git_binary()

    def test_root_managed_nixos_legacy_git_alias_uses_canonical_binary(self) -> None:
        # NixOS can expose /usr/bin/git as a symlink to its immutable Git.
        # The worker must execute the authenticated canonical system path.
        canonical = "/run/current-system/sw/bin/git"
        executable = Path("/nix/store/" + "a" * 32 + "-git/bin/git")
        with (
            patch.object(
                worker.os.path, "lexists",
                side_effect=lambda path: str(path) in {"/usr/bin/git", canonical},
            ),
            patch.object(Path, "lstat", return_value=SimpleNamespace(
                st_uid=0, st_mode=stat.S_IFLNK | 0o755,
            )),
            patch.object(Path, "resolve", return_value=executable),
            patch.object(Path, "stat", return_value=SimpleNamespace(
                st_uid=0, st_mode=stat.S_IFREG | 0o555,
            )),
            patch.object(worker.os, "access", return_value=True),
        ):
            self.assertEqual(worker._trusted_git_binary(), canonical)

    def test_legacy_git_alias_must_match_canonical_nixos_git(self) -> None:
        canonical = "/run/current-system/sw/bin/git"
        trusted = Path("/nix/store/" + "a" * 32 + "-git/bin/git")

        def resolve(path: Path, *, strict: bool = False) -> Path:
            return Path("/tmp/foreign-git") if str(path) == "/usr/bin/git" else trusted

        with (
            patch.object(
                worker.os.path, "lexists",
                side_effect=lambda path: str(path) in {"/usr/bin/git", canonical},
            ),
            patch.object(Path, "lstat", return_value=SimpleNamespace(
                st_uid=0, st_mode=stat.S_IFLNK | 0o755,
            )),
            patch.object(Path, "resolve", autospec=True, side_effect=resolve),
            self.assertRaisesRegex(RuntimeError, "legacy Git alias"),
        ):
            worker._trusted_git_binary()

    @staticmethod
    def git(repo: Path, *args: str) -> str:
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(repo.parent),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
        }
        completed = subprocess.run(
            [worker._trusted_git_binary(), "-C", str(repo), *args],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            timeout=12,
        )
        return completed.stdout.strip()

    def make_repo(self, root: Path, *, attributes: bool = False) -> tuple[Path, str]:
        repo = root / "source"
        repo.mkdir()
        self.git(repo, "init", "-q", "-b", "main")
        self.git(repo, "config", "user.name", "Filter Fixture")
        self.git(repo, "config", "user.email", "filter@invalid.example")
        (repo / "tracked.txt").write_text("original\n", encoding="utf-8")
        paths = ["tracked.txt"]
        if attributes:
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=proof\n", encoding="utf-8"
            )
            paths.append(".gitattributes")
        self.git(repo, "add", "--", *paths)
        self.git(repo, "commit", "-qm", "initial")
        head = self.git(repo, "rev-parse", "HEAD")
        self.git(repo, "update-ref", "refs/remotes/origin/main", head)
        return repo, head

    def test_configured_clean_filter_cannot_run_in_worker_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-git-filter-") as dirname:
            root = Path(dirname)
            repo, head = self.make_repo(root, attributes=True)
            marker = root / "clean-executed"
            self.git(
                repo, "config", "filter.proof.clean",
                f"/bin/sh -c 'printf executed > {marker}; cat'",
            )
            (repo / "tracked.txt").write_text("changed\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "executable Git filter"):
                worker.verify_repository(repo, repo, "canonical-main", head)
            self.assertFalse(marker.exists(), "repo clean filter executed during preflight")

            # This control makes the regression discriminating on real Git.
            self.git(repo, "diff", "--", "tracked.txt")
            self.assertTrue(marker.exists(), "Git clean-filter fixture did not activate")

    def test_process_filter_configuration_is_rejected_without_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-process-filter-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            self.git(repo, "config", "filter.hazard.process", "/bin/sh -c 'exit 99'")
            with self.assertRaisesRegex(RuntimeError, "executable Git filter"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_inherited_git_scope_cannot_override_checked_repository(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-env-filter-") as dirname:
            root = Path(dirname)
            repo, head = self.make_repo(root)
            polluted = {
                "GIT_DIR": str(root / "foreign"),
                "GIT_WORK_TREE": str(root / "foreign"),
                "GIT_INDEX_FILE": str(root / "other-index"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "filter.poison.clean",
                "GIT_CONFIG_VALUE_0": "/bin/sh -c 'exit 99'",
                "GIT_SSH_COMMAND": "/bin/sh -c 'exit 98'",
                "GIT_TRACE": str(root / "trace"),
                "PATH": str(root / "untrusted-bin"),
            }
            with patch.dict(os.environ, polluted):
                worker.verify_repository(repo, repo, "canonical-main", head)
            self.assertFalse((root / "trace").exists())

    def test_filter_registered_after_audit_cannot_execute_during_dirty_check(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-filter-race-") as dirname:
            root = Path(dirname)
            repo, head = self.make_repo(root, attributes=True)
            tracked = repo / "tracked.txt"
            original = tracked.stat()
            # Same size/mtime forces Git's otherwise hidden clean-filter path.
            tracked.write_text("modified\n", encoding="utf-8")
            os.utime(tracked, ns=(original.st_atime_ns, original.st_mtime_ns))
            marker = root / "raced-filter-executed"
            original_audit = worker._reject_repository_git_filters

            def race_config(checkout: Path) -> None:
                original_audit(checkout)
                self.git(
                    repo, "config", "filter.proof.clean",
                    f"/bin/sh -c 'printf executed > {marker}; cat'",
                )

            with patch.object(worker, "_reject_repository_git_filters", side_effect=race_config):
                with self.assertRaisesRegex(RuntimeError, "dirty"):
                    worker.verify_repository(repo, repo, "canonical-main", head)
            self.assertFalse(marker.exists(), "effect-time clean filter executed")
            # Discriminating control: an ordinary Git content diff executes it.
            self.git(repo, "diff", "--", "tracked.txt")
            self.assertTrue(marker.exists(), "clean-filter control did not trigger")

    def test_staged_and_untracked_changes_are_still_dirty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-raw-clean-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            (repo / "untracked.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)
            (repo / "untracked.txt").unlink()
            (repo / "tracked.txt").write_text("staged\n", encoding="utf-8")
            self.git(repo, "add", "tracked.txt")
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_tracked_fifo_cannot_block_raw_worktree_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-raw-fifo-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            tracked = repo / "tracked.txt"
            tracked.unlink()
            os.mkfifo(tracked)
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_ignored_file_and_tracked_symlink_keep_clean_repo_eligible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-raw-symlink-") as dirname:
            repo, _head = self.make_repo(Path(dirname))
            (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
            (repo / "link.txt").symlink_to("tracked.txt")
            self.git(repo, "add", ".gitignore", "link.txt")
            self.git(repo, "commit", "-qm", "ignore and symlink")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            (repo / "ignored.log").write_text("ignored\n", encoding="utf-8")
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_empty_untracked_directory_is_clean_but_contents_remain_dirty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-empty-dir-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            empty = repo / "generated"
            empty.mkdir()
            worker.verify_repository(repo, repo, "canonical-main", head)
            nested = empty / "nested"
            nested.mkdir()
            worker.verify_repository(repo, repo, "canonical-main", head)
            (nested / "file.txt").write_text("untracked\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_explicit_index_crlf_is_clean_without_git_filter_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-crlf-safe-") as dirname:
            root = Path(dirname)
            repo, _ = self.make_repo(root)
            tracked = repo / "tracked.txt"
            (repo / ".gitattributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Declare explicit CRLF text")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertIn(b"\r\n", tracked.read_bytes())
            self.assertEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            worker.verify_repository(repo, repo, "canonical-main", head)
            tracked.write_bytes(b"modified\r\n")
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_eol_only_index_attribute_is_clean_and_binary_remains_dirty(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-only-") as dirname:
            root = Path(dirname)
            repo, _ = self.make_repo(root)
            tracked = repo / "tracked.txt"
            (repo / ".gitattributes").write_text(
                "tracked.txt eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "EOL implies text")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            worker.verify_repository(repo, repo, "canonical-main", head)
            # No CRLF normalization may accept arbitrary changed binary content.
            tracked.write_bytes(b"original\x00\r\n")
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_crlf_streaming_preserves_pair_across_read_chunks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-chunk-") as dirname:
            root = Path(dirname)
            repo, _ = self.make_repo(root)
            tracked = repo / "tracked.txt"
            original = b"X" * (128 * 1024 - 1) + b"\nlast\n"
            tracked.write_bytes(original)
            (repo / ".gitattributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes", "tracked.txt")
            self.git(repo, "commit", "-qm", "Force CRLF across read boundary")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertEqual(tracked.read_bytes()[128 * 1024 - 1:128 * 1024 + 1], b"\r\n")
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_mutable_info_attributes_cannot_launder_dirty_crlf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-info-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            (repo / ".git" / "info" / "attributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            (repo / "tracked.txt").write_bytes(b"original\r\n")
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_committed_glob_crlf_is_clean_in_nested_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-glob-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            nested = repo / "nested"
            nested.mkdir()
            target = nested / "notes.txt"
            target.write_bytes(b"first\nsecond\n")
            (repo / ".gitattributes").write_text(
                "*.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes", "nested/notes.txt")
            self.git(repo, "commit", "-qm", "Committed safe glob attributes")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            target.unlink()
            self.git(repo, "checkout", "--", "nested/notes.txt")
            self.assertIn(b"\r\n", target.read_bytes())
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_committed_later_eol_override_cannot_launder_from_info(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-override-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "*.txt text eol=crlf\n"
                "tracked.txt -text eol=lf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Later rule overrides CRLF")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            (repo / "tracked.txt").write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_committed_nested_eol_override_cannot_launder_from_info(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-nested-override-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            nested = repo / "nested"
            nested.mkdir()
            tracked = nested / "notes.txt"
            tracked.write_bytes(b"original\n")
            (repo / ".gitattributes").write_text(
                "*.txt text eol=crlf\n", encoding="utf-8"
            )
            (nested / ".gitattributes").write_text(
                "notes.txt -text eol=lf\n", encoding="utf-8"
            )
            self.git(
                repo, "add", ".gitattributes", "nested/.gitattributes", "nested/notes.txt"
            )
            self.git(repo, "commit", "-qm", "Nested committed LF override")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked.write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "nested/notes.txt text eol=crlf\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_committed_binary_macro_cannot_launder_crlf_from_info(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-binary-macro-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "*.txt text eol=crlf\n"
                "tracked.txt binary\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Built-in binary macro overrides text")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            (repo / "tracked.txt").write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_root_anchored_literal_cannot_launder_nested_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-anchor-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            nested = repo / "nested"
            nested.mkdir()
            target = nested / "notes.txt"
            target.write_bytes(b"original\n")
            (repo / ".gitattributes").write_text(
                "/notes.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes", "nested/notes.txt")
            self.git(repo, "commit", "-qm", "Root anchored CRLF rule")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            target.write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "nested/notes.txt text eol=crlf\n", encoding="utf-8"
            )
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_root_anchored_glob_cannot_launder_nested_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-anchor-glob-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            nested = repo / "nested"
            nested.mkdir()
            target = nested / "notes.txt"
            target.write_bytes(b"original\n")
            (repo / ".gitattributes").write_text(
                "/*.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes", "nested/notes.txt")
            self.git(repo, "commit", "-qm", "Root anchored CRLF glob")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            target.write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "nested/notes.txt text eol=crlf\n", encoding="utf-8"
            )
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_quoted_committed_override_cannot_be_replaced_by_info(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-quoted-override-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                '*.txt text eol=crlf\n'
                '"tracked.txt" -text eol=lf\n', encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Quoted pathname overrides CRLF")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            (repo / "tracked.txt").write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_quoted_committed_crlf_rule_remains_eligible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-quoted-clean-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                '"tracked.txt" text eol=crlf\n', encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Quoted CRLF declaration")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked = repo / "tracked.txt"
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertIn(b"\r\n", tracked.read_bytes())
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_sha256_git_tree_crlf_source_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-sha256-crlf-") as dirname:
            repo = Path(dirname) / "source"
            repo.mkdir()
            self.git(repo, "init", "-q", "-b", "main", "--object-format=sha256")
            self.git(repo, "config", "user.name", "SHA256 Fixture")
            self.git(repo, "config", "user.email", "sha256@invalid.example")
            (repo / "tracked.txt").write_bytes(b"original\n")
            (repo / ".gitattributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes", "tracked.txt")
            self.git(repo, "commit", "-qm", "SHA256 CRLF initial")
            head = self.git(repo, "rev-parse", "HEAD")
            self.assertEqual(len(head), 64)
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked = repo / "tracked.txt"
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertIn(b"\r\n", tracked.read_bytes())
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_committed_attribute_macro_can_enable_clean_crlf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-macro-clean-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "[attr]windows text eol=crlf\n"
                "tracked.txt windows\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Commit named CRLF macro")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked = repo / "tracked.txt"
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertIn(b"\r\n", tracked.read_bytes())
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_unknown_wildcard_macro_cannot_launder_crlf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-wildcard-macro-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            nested = repo / "nested"
            nested.mkdir()
            target = nested / "notes.txt"
            target.write_bytes(b"original\n")
            (repo / ".gitattributes").write_text(
                "*.txt text eol=crlf\n"
                "**/*.txt binary\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes", "nested/notes.txt")
            self.git(repo, "commit", "-qm", "Nested glob macro overrides CRLF")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            target.write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "nested/notes.txt text eol=crlf\n", encoding="utf-8"
            )
            self.assertNotEqual(
                self.git(repo, "status", "--porcelain=v1", "--untracked-files=normal"), ""
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_committed_custom_macro_cannot_launder_crlf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-custom-macro-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "[attr]nottext -text eol=lf\n"
                "*.txt text eol=crlf\n"
                "tracked.txt nottext\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Custom macro overrides text")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            (repo / "tracked.txt").write_bytes(b"original\r\n")
            (repo / ".git" / "info" / "attributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_unrelated_macro_definition_keeps_direct_crlf_rule_eligible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-macro-decl-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "[attr]binary -text -diff -merge\n"
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Macro declaration not applied")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked = repo / "tracked.txt"
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertIn(b"\r\n", tracked.read_bytes())
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_last_matching_committed_crlf_rule_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-last-") as dirname:
            repo, _ = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "*.txt -text eol=lf\n"
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "Final matching rule is CRLF")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked = repo / "tracked.txt"
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            self.assertIn(b"\r\n", tracked.read_bytes())
            worker.verify_repository(repo, repo, "canonical-main", head)

    def test_unstaged_crlf_attribute_cannot_disguise_dirty_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-unindexed-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            (repo / ".gitattributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            (repo / "tracked.txt").write_bytes(b"original\r\n")
            with self.assertRaisesRegex(RuntimeError, "dirty"):
                worker.verify_repository(repo, repo, "canonical-main", head)

    def test_crlf_check_does_not_execute_late_registered_filter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-eol-race-") as dirname:
            root = Path(dirname)
            repo, _ = self.make_repo(root)
            tracked = repo / "tracked.txt"
            (repo / ".gitattributes").write_text(
                "tracked.txt text eol=crlf\n", encoding="utf-8"
            )
            self.git(repo, "add", ".gitattributes")
            self.git(repo, "commit", "-qm", "CRLF fixture")
            head = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", head)
            tracked.unlink()
            self.git(repo, "checkout", "--", "tracked.txt")
            marker = root / "helper-executed"
            original_audit = worker._reject_repository_git_filters

            def install_late_filter(checkout: Path) -> None:
                original_audit(checkout)
                self.git(
                    repo, "config", "filter.poison.clean",
                    f"/bin/sh -c 'printf executed > {marker}; cat'",
                )

            with patch.object(
                worker, "_reject_repository_git_filters", side_effect=install_late_filter
            ):
                worker.verify_repository(repo, repo, "canonical-main", head)
            self.assertFalse(marker.exists(), "late filter executed during metadata read")

    def test_plain_repo_remains_eligible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="worker-plain-filter-") as dirname:
            repo, head = self.make_repo(Path(dirname))
            worker.verify_repository(repo, repo, "canonical-main", head)


if __name__ == "__main__":
    unittest.main()

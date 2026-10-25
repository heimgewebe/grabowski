"""Regressions for root-managed Git across Captain merge guard subprocess seams on NixOS."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_merge_guard as guard
import grabowski_git_ssh as git_ssh


class TrustedCaptainNixosGitTests(unittest.TestCase):
    def _assert_trusted_binary(self, action, *, stdout="", returncode=0):
        completed = SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")
        with (
            patch.object(guard.subprocess, "run", return_value=completed) as run,
            patch.dict(os.environ, {"PATH": "/tmp/untrusted-git"}, clear=False),
        ):
            action()
        self.assertEqual(run.call_args.args[0][0], git_ssh.trusted_git_cli_path())
        self.assertNotEqual(run.call_args.args[0][0], "git")

    def test_merge_guard_repository_root_uses_trusted_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".git").mkdir()
            self._assert_trusted_binary(
                lambda: guard.merge_guard_repository_root(repo),
                stdout=str(repo / ".git") + "\n",
            )

    def test_merge_guard_repository_identity_uses_trusted_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            with patch.object(guard, "merge_guard_repository_root", return_value=repo):
                self._assert_trusted_binary(
                    lambda: guard.merge_guard_repository_identity(repo),
                    stdout="git@github.com:heimgewebe/grabowski.git\n",
                )

    def test_merge_guard_local_git_bytes_uses_trusted_git(self):
        self._assert_trusted_binary(
            lambda: guard._merge_guard_local_git_bytes(Path("/tmp/repo"), ["rev-parse", "HEAD"]),
            stdout=b"fixture",
        )

    def test_merge_guard_exact_base_git_uses_trusted_git(self):
        self._assert_trusted_binary(
            lambda: guard._merge_guard_git_command(Path("/tmp/repo"), ["status"]),
            stdout="",
        )

    def test_untrusted_executable_fails_before_any_subprocess(self):
        with (
            patch.object(git_ssh, "trusted_git_cli_path", side_effect=PermissionError("untrusted system Git")) as select,
            patch.object(guard.subprocess, "run", side_effect=AssertionError("must not execute")) as run,
        ):
            with self.assertRaisesRegex(PermissionError, "untrusted system Git"):
                guard._merge_guard_local_git_bytes(Path("/tmp/repo"), ["rev-parse", "HEAD"])
        select.assert_called_once_with()
        run.assert_not_called()

    def test_real_nixos_git_binds_github_origin_and_rejects_other_hosts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "git-fixture"
            trusted_git = git_ssh.trusted_git_cli_path()
            subprocess.run([trusted_git, "init", "-q", str(root)], check=True, capture_output=True)
            subprocess.run(
                [trusted_git, "-C", str(root), "remote", "add",
                 "origin", "git@github.com:heimgewebe/grabowski.git"],
                check=True, capture_output=True,
            )
            observed, identity = guard.merge_guard_repository_identity(root)
            self.assertEqual(root.resolve(), observed)
            self.assertEqual("heimgewebe/grabowski", identity)
            subprocess.run(
                [trusted_git, "-C", str(root), "remote", "set-url",
                 "origin", "git@other.example:heimgewebe/grabowski.git"],
                check=True, capture_output=True,
            )
            with self.assertRaisesRegex(RuntimeError, "origin remote"):
                guard.merge_guard_repository_identity(root)



if __name__ == "__main__":
    unittest.main()
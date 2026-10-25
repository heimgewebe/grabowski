"""Regressions for root-managed Git across Captain merge guard subprocess seams on NixOS."""
from __future__ import annotations

import os
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


if __name__ == "__main__":
    unittest.main()

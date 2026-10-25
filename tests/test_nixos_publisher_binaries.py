"""NixOS trust path regression tests for the Git and GitHub binaries."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_operator_contract import _load_operator_module


class NixosPublisherBinariesTests(unittest.TestCase):
    def test_real_nixos_git_cli_when_usr_bin_missing(self) -> None:
        operator = _load_operator_module()
        if os.path.lexists("/usr/bin/git") or not os.path.lexists("/run/current-system/sw/bin/git"):
            self.skipTest("NixOS-specific fixture unavailable")
        self.assertEqual("/run/current-system/sw/bin/git", operator._trusted_git_cli_path())

    def test_classic_linux_keeps_strict_original_guard(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=True),
            patch.object(operator, "_trusted_root_owned_executable_path", return_value="/usr/bin/git") as check,
        ):
            self.assertEqual("/usr/bin/git", operator._trusted_git_cli_path())
        check.assert_called_once_with(operator.TRUSTED_GIT_CLI_PATH, "Git CLI")

    def test_existing_untrusted_legacy_git_never_falls_back(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=True),
            patch.object(operator, "_trusted_root_owned_executable_path", side_effect=PermissionError("unsafe legacy")),
        ):
            with self.assertRaisesRegex(PermissionError, "unsafe legacy"):
                operator._trusted_git_cli_path()

    def test_missing_nixos_binary_fails_closed(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=False),
            patch.object(operator.Path, "resolve", side_effect=FileNotFoundError("missing")),
        ):
            with self.assertRaisesRegex(RuntimeError, "trusted Git CLI path is unavailable"):
                operator._trusted_git_cli_path()

    def test_invalid_nixos_store_target_is_not_executed(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=False),
            patch.object(operator.Path, "resolve", return_value=Path("/tmp/evil/git")),
        ):
            with self.assertRaisesRegex(PermissionError, "Nix store"):
                operator._trusted_git_cli_path()

    def test_untrusted_symlink_chain_rejected(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=False),
            patch.object(operator.Path, "resolve", return_value=Path("/nix/store/fixture/bin/git")),
            patch.object(operator.grabowski_git_ssh, "_root_managed_chain", side_effect=PermissionError("mutable symlink")),
        ):
            with self.assertRaisesRegex(PermissionError, "mutable symlink"):
                operator._trusted_git_cli_path()

    def test_nonexecutable_nixos_binary_denied(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=False),
            patch.object(operator.Path, "resolve", return_value=Path("/nix/store/safe-store-path/bin/git")),
            patch.object(operator.grabowski_git_ssh, "_root_managed_chain"),
            patch.object(operator.Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)),
        ):
            with self.assertRaises(PermissionError):
                operator._trusted_git_cli_path()

    def test_untrusted_path_environment_ignored(self) -> None:
        operator = _load_operator_module()
        expected = operator._trusted_git_cli_path()
        with patch.dict(os.environ, {"PATH": "/tmp/attacker/bin", "GIT_SSH_COMMAND": "/tmp/evil"}):
            self.assertEqual(expected, operator._trusted_git_cli_path())

    def test_real_nixos_github_cli_when_usr_bin_missing(self) -> None:
        operator = _load_operator_module()
        if os.path.lexists("/usr/bin/gh") or not os.path.lexists("/run/current-system/sw/bin/gh"):
            self.skipTest("NixOS-specific fixture unavailable")
        self.assertEqual("/run/current-system/sw/bin/gh", operator._trusted_github_cli_path())

    def test_github_legacy_cli_is_not_bypassed(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator.os.path, "lexists", return_value=True),
            patch.object(operator, "_trusted_root_owned_executable_path", return_value="/usr/bin/gh") as check,
        ):
            self.assertEqual("/usr/bin/gh", operator._trusted_github_cli_path())
        check.assert_called_once_with(operator.TRUSTED_GITHUB_CLI_PATH, "GitHub CLI")


    def test_grips_git_runner_ignores_untrusted_path(self) -> None:
        import test_grips
        grips = test_grips.grips
        result = SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            patch.object(grips.grabowski_git_ssh, "trusted_git_cli_path", create=True, return_value="/run/current-system/sw/bin/git") as select,
            patch.object(grips.grabowski_git_ssh, "hardened_git_ssh_command", return_value="/trusted/ssh -F /dev/null"),
            patch.object(grips.subprocess, "run", return_value=result) as runner,
            patch.dict(os.environ, {"PATH": "/tmp/untrusted-shim"}),
        ):
            grips._default_command_runner(Path("/tmp/repo"), ["push", "origin", "HEAD:refs/heads/feature"])
        select.assert_called_once_with()
        self.assertEqual(runner.call_args.args[0][0], "/run/current-system/sw/bin/git")

    def test_operator_push_ignores_untrusted_path(self) -> None:
        operator = _load_operator_module()
        with __import__("tempfile").TemporaryDirectory() as directory:
            with (
                patch.object(operator, "_require_operator_mutation"),
                patch.object(operator, "_guard_git"),
                patch.object(operator, "_validate_argv", side_effect=lambda argv, cwd: argv),
                patch.object(operator, "_git_push_environment", return_value={"PATH": "/tmp/untrusted-shim"}),
                patch.object(operator, "_trusted_git_cli_path", return_value="/run/current-system/sw/bin/git") as trusted,
                patch.object(operator, "_run", return_value={"returncode": 0}) as run,
            ):
                operator.grabowski_git(directory, ["push", "origin", "HEAD:refs/heads/feature"])
        trusted.assert_called()
        self.assertEqual(run.call_args.args[0][0], "/run/current-system/sw/bin/git")


if __name__ == "__main__":
    unittest.main()
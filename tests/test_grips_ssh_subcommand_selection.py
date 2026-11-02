"""Guard GitHub SSH credentials against incidental local Git operand names."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_grips as grips


class GitSshSubcommandSelectionTests(unittest.TestCase):
    def _local_command(self, arguments: list[str]) -> None:
        completed = SimpleNamespace(returncode=0, stdout="ok\n", stderr="")
        with (
            patch.object(grips.grabowski_git_ssh, "trusted_git_cli_path", return_value="/trusted/git"),
            patch.object(grips.grabowski_git_ssh, "hardened_git_ssh_command", side_effect=PermissionError("no writer identity")) as identity,
            patch.object(grips.subprocess, "run", return_value=completed) as run,
        ):
            result = grips._default_command_runner(Path("/frozen/repository"), arguments)
        self.assertEqual(0, result["returncode"])
        identity.assert_not_called()
        self.assertEqual("/__grabowski_ssh_transport_disabled__/ssh", run.call_args.kwargs["env"]["GIT_SSH_COMMAND"])

    def test_local_branch_operands_do_not_require_github_identity(self) -> None:
        for branch in ("push", "fetch", "pull", "clone", "ls-remote"):
            with self.subTest(branch=branch):
                self._local_command(["check-ref-format", "--branch", branch])

    def test_local_branch_operand_after_git_global_option_is_not_remote(self) -> None:
        self._local_command(["--no-optional-locks", "check-ref-format", "--branch", "push"])

    def test_network_push_after_git_global_options_still_uses_hardened_identity(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        hardened = "/trusted/ssh -F /dev/null -oBatchMode=yes -i /private/key"
        arguments = ["--no-pager", "-c", "core.quotePath=false", "push", "origin", "HEAD:refs/heads/feature"]
        with (
            patch.object(grips.grabowski_git_ssh, "trusted_git_cli_path", return_value="/trusted/git"),
            patch.object(grips.grabowski_git_ssh, "hardened_git_ssh_command", return_value=hardened) as identity,
            patch.object(grips.subprocess, "run", return_value=completed) as run,
        ):
            result = grips._default_command_runner(Path("/frozen/repository"), arguments)
        self.assertEqual(0, result["returncode"])
        identity.assert_called_once_with()
        self.assertEqual(hardened, run.call_args.kwargs["env"]["GIT_SSH_COMMAND"])


if __name__ == "__main__":
    unittest.main()

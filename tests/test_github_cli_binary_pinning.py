"""Fail-closed GitHub CLI pinning for effect-bearing Grips."""
from __future__ import annotations
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_git_ssh as transport
import grabowski_grips as grips

class PinnedGithubGripCliTests(unittest.TestCase):
    def test_untrusted_path_never_selects_gh(self) -> None:
        pinned = "/nix/store/pinned-verified-gh/bin/gh"
        result = subprocess.CompletedProcess([pinned], 0, b"fixture\n", b"")
        with (
            patch.object(transport, "trusted_github_cli_path", return_value=pinned) as select,
            patch.object(grips.subprocess, "run", return_value=result) as child,
            patch.dict(os.environ, {"PATH": "/tmp/attacker/bin:/home/test/bin"}),
        ):
            receipt = grips._default_github_runner(Path.cwd(), ["--version"])
        select.assert_called_once_with()
        self.assertEqual([pinned, "--version"], child.call_args.args[0])
        self.assertEqual("/run/current-system/sw/bin:/usr/bin:/bin", child.call_args.kwargs["env"]["PATH"])
        self.assertEqual([pinned, "--version"], receipt["argv"])
        self.assertEqual(0, receipt["returncode"])

    def test_untrusted_executable_denied_without_spawning(self) -> None:
        with (
            patch.object(transport, "trusted_github_cli_path", side_effect=PermissionError("untrusted gh")),
            patch.object(grips.subprocess, "run", side_effect=AssertionError("no child")) as child,
        ):
            with self.assertRaisesRegex(PermissionError, "untrusted gh"):
                grips._default_github_runner(Path.cwd(), ["pr", "merge", "1638"])
        child.assert_not_called()

    def test_missing_root_managed_gh_fails_closed(self) -> None:
        with patch.object(transport.os.path, "lexists", return_value=False):
            with self.assertRaisesRegex(FileNotFoundError, "root-managed"):
                transport.trusted_github_cli_path()

    def test_nixos_system_gh_cannot_escape_nix_store(self) -> None:
        with (
            patch.object(transport.os.path, "lexists",
                side_effect=lambda p: str(p) == "/run/current-system/sw/bin/gh"),
            patch.object(transport, "_root_managed_resolution", return_value=Path("/tmp/evil/gh")),
        ):
            with self.assertRaisesRegex(PermissionError, "Nix store"):
                transport.trusted_github_cli_path()

    def test_untrusted_classic_alias_does_not_fall_back(self) -> None:
        with (
            patch.object(transport.os.path, "lexists", return_value=True),
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)),
            patch.object(transport, "_root_managed_resolution",
                side_effect=[Path("/nix/store/one/bin/gh"), Path("/nix/store/other/bin/gh")]),
        ):
            with self.assertRaisesRegex(PermissionError, "does not match"):
                transport.trusted_github_cli_path()

    def test_real_nixos_gh_is_pinned(self) -> None:
        path = Path("/run/current-system/sw/bin/gh")
        if os.path.lexists("/usr/bin/gh") or not os.path.lexists(path):
            self.skipTest("NixOS gh w/o classic alias unavailable")
        self.assertEqual(str(path.resolve(strict=True)), transport.trusted_github_cli_path())

if __name__ == "__main__":
    unittest.main()

"""Fail-closed regression tests for guarded GitHub SSH publication on Linux/NixOS."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_git_ssh as transport


class GitSshTransportTests(unittest.TestCase):
    def _home_with_key(self, base: Path) -> Path:
        home = base / "home"
        home.mkdir(mode=0o700)
        ssh = home / ".ssh"
        ssh.mkdir(mode=0o700)
        key = ssh / "heimgewebe-github-ed25519"
        key.write_text("fake private key fixture; never used on network")
        key.chmod(0o600)
        return home

    def test_command_keeps_guards_and_explicit_identity(self) -> None:
        with (
            patch.object(transport, "_trusted_executable", return_value=Path("/run/current-system/sw/bin/ssh")),
            patch.object(transport, "_trusted_identity", return_value=Path("/home/test/.ssh/heimgewebe-github-ed25519")),
            patch.object(transport.os.path, "lexists", side_effect=lambda path: str(path) == "/run/current-system/sw/bin/ssh"),
        ):
            command = transport.hardened_git_ssh_command()
        self.assertTrue(command.startswith("/run/current-system/sw/bin/ssh -F /dev/null "), command)
        for guard in (
            "-oBatchMode=yes", "-oProxyCommand=none",
            "-oPermitLocalCommand=no", "-oClearAllForwardings=yes",
            "-oIdentitiesOnly=yes", "-oIdentityAgent=none",
            "-oStrictHostKeyChecking=yes",
            "-i /home/test/.ssh/heimgewebe-github-ed25519",
        ):
            self.assertIn(guard, command)

    def test_no_executable_fails_closed(self) -> None:
        with patch.object(transport.os.path, "lexists", return_value=False):
            with self.assertRaises(FileNotFoundError):
                transport.hardened_git_ssh_command()

    def test_untrusted_binary_is_not_used_even_if_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ssh"
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
            with self.assertRaises(PermissionError):
                transport._trusted_executable(path)

    def test_symlink_into_user_controlled_directory_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "fake"
            target.write_text("#!/bin/sh\nexit 0\n")
            target.chmod(0o755)
            link = root / "ssh"
            link.symlink_to(target)
            with self.assertRaises(PermissionError):
                transport._trusted_executable(link)

    def test_key_from_non_private_directory_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home_with_key(Path(tmp))
            (home / ".ssh").chmod(0o777)
            with patch.object(transport.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaises(PermissionError):
                    transport._trusted_identity()

    def test_key_with_excessive_permissions_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home_with_key(Path(tmp))
            (home / ".ssh" / "heimgewebe-github-ed25519").chmod(0o644)
            with patch.object(transport.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaises(PermissionError):
                    transport._trusted_identity()

    def test_key_symlink_is_denied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home_with_key(Path(tmp))
            key = home / ".ssh" / "heimgewebe-github-ed25519"
            target = home / "alternate"
            target.write_text("key")
            target.chmod(0o600)
            key.unlink()
            key.symlink_to(target)
            with patch.object(transport.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaises(PermissionError):
                    transport._trusted_identity()

    def test_missing_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir(mode=0o700)
            (home / ".ssh").mkdir(mode=0o700)
            with patch.object(transport.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaises(FileNotFoundError):
                    transport._trusted_identity()

    def test_environment_home_override_not_consulted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home_with_key(Path(tmp))
            with (
                patch.dict(os.environ, {"HOME": "/tmp/untrusted-key"}),
                patch.object(transport.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))),
            ):
                self.assertEqual(
                    home / ".ssh" / "heimgewebe-github-ed25519",
                    transport._trusted_identity(),
                )

    def test_real_system_binary_on_nixos_or_classic_linux(self) -> None:
        candidates = [p for p in transport.SSH_CANDIDATES if os.path.lexists(p)]
        if not candidates:
            self.skipTest("No supported OpenSSH executable on this host")
        self.assertEqual(candidates[0].resolve(strict=True), transport._trusted_executable(candidates[0]))

    def test_existing_local_explicit_identity(self) -> None:
        """Only execute on machines explicitly provisioned with the writer identity."""
        import pwd
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        if not (home / ".ssh" / "heimgewebe-github-ed25519").exists():
            self.skipTest("Writer identity is not provisioned in this CI environment")
        self.assertEqual(home / ".ssh" / "heimgewebe-github-ed25519", transport._trusted_identity())


if __name__ == "__main__":
    unittest.main()

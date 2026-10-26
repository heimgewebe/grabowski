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

    def test_symlink_hop_is_audited_before_executing_resolved_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            trusted = base / "trusted-ssh"
            trusted.write_text("#!/bin/sh\\nexit 0\\n")
            trusted.chmod(0o755)
            relay = base / "relay"
            relay.symlink_to(trusted)
            intermediate = base / "staging"
            intermediate.mkdir()
            entry = intermediate / "ssh"
            entry.symlink_to(relay)
            inspected = []
            with patch.object(transport, "_root_managed_chain", side_effect=inspected.append):
                self.assertEqual(trusted, transport._root_managed_resolution(entry))
            self.assertIn(entry, inspected)
            self.assertIn(relay, inspected)
            self.assertIn(trusted, inspected)

    def test_mutable_intermediate_symlink_hop_blocks_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            trusted = base / "trusted-ssh"
            trusted.write_text("#!/bin/sh\\nexit 0\\n")
            intermediate = base / "mutable"
            intermediate.mkdir()
            relay = intermediate / "redirect"
            relay.symlink_to(trusted)
            entry = base / "ssh"
            entry.symlink_to(relay)

            def root_managed_check(path: Path) -> None:
                if path == relay:
                    raise PermissionError("mutable intermediate symlink")
            with patch.object(transport, "_root_managed_chain", side_effect=root_managed_check):
                with self.assertRaisesRegex(PermissionError, "mutable intermediate"):
                    transport._root_managed_resolution(entry)

    def test_selected_ssh_pins_realpath_instead_of_using_validated_alias(self) -> None:
        real = Path("/nix/store/pinned-openssh/bin/ssh")
        with (
            patch.object(transport.os.path, "lexists", return_value=True),
            patch.object(transport, "_trusted_executable", return_value=real) as validate,
        ):
            self.assertEqual(real, transport._selected_ssh_executable())
        validate.assert_called_once_with(Path("/usr/bin/ssh"))

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

    def test_ssh_directory_must_be_owner_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home_with_key(Path(tmp))
            (home / ".ssh").chmod(0o755)
            with patch.object(transport.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaises(PermissionError):
                    transport._trusted_identity()

    def test_hardlinked_github_writer_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = self._home_with_key(Path(tmp))
            key = home / ".ssh" / "heimgewebe-github-ed25519"
            os.link(key, home / ".ssh" / "linked-key")
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


    def test_module_is_in_setuptools_distribution(self) -> None:
        pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        modules = next(line for line in pyproject.splitlines() if line.startswith("py-modules = "))
        self.assertIn('"grabowski_git_ssh"', modules)

    def test_real_nixos_git_alias_uses_canonical_nix_git(self) -> None:
        legacy = Path("/usr/bin/git")
        nix = Path("/run/current-system/sw/bin/git")
        if not legacy.is_symlink() or not nix.exists():
            self.skipTest("NixOS legacy Git alias unavailable")
        if legacy.resolve(strict=True) != nix.resolve(strict=True):
            self.skipTest("NixOS Git alias differs")
        self.assertEqual(str(nix.resolve(strict=True)), transport.trusted_git_cli_path())

    def test_foreign_legacy_git_symlink_is_denied(self) -> None:
        with (
            patch.object(transport.os.path, "lexists", return_value=True),
            patch.object(transport.Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)),
            patch.object(transport, "_root_managed_resolution", side_effect=[Path("/nix/store/foreign/bin/git"), Path("/nix/store/system/bin/git")]),
        ):
            with self.assertRaisesRegex(PermissionError, "does not match NixOS"):
                transport.trusted_git_cli_path()

    def test_classic_usr_bin_ssh_is_selected_before_nixos_fallback(self) -> None:
        with (
            patch.object(transport.os.path, "lexists", return_value=True),
            patch.object(transport, "_trusted_executable", return_value=Path("/usr/bin/ssh")) as trust,
        ):
            self.assertEqual(Path("/usr/bin/ssh"), transport._selected_ssh_executable())
        trust.assert_called_once_with(Path("/usr/bin/ssh"))

    def test_nixos_system_link_must_resolve_inside_store(self) -> None:
        with patch.object(Path, "resolve", return_value=Path("/tmp/attacker-ssh")):
            with self.assertRaises(PermissionError):
                transport._trusted_executable(Path("/run/current-system/sw/bin/ssh"))

    def test_caller_ssh_transport_overrides_cannot_change_command(self) -> None:
        with (
            patch.dict(os.environ, {
                "PATH": "/tmp/evil",
                "GIT_SSH": "/tmp/evil-ssh",
                "GIT_SSH_COMMAND": "/tmp/evil-command",
                "SSH_AUTH_SOCK": "/tmp/evil-agent",
            }),
            patch.object(transport, "_selected_ssh_executable", return_value=Path("/usr/bin/ssh")),
            patch.object(transport, "_trusted_identity", return_value=Path("/home/test/.ssh/heimgewebe-github-ed25519")),
        ):
            command = transport.hardened_git_ssh_command()
        self.assertTrue(command.startswith("/usr/bin/ssh -F /dev/null "))
        self.assertNotIn("/tmp/evil", command)
        self.assertIn("-oIdentityAgent=none", command)


if __name__ == "__main__":
    unittest.main()
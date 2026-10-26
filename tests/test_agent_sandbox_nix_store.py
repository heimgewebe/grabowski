from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_sandbox as sandbox


class NixStoreSandboxTests(unittest.TestCase):
    def test_missing_nix_store_preserves_legacy_linux_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.object(sandbox, "_NIX_STORE", root / "missing" / "store"):
                self.assertIsNone(sandbox._trusted_nix_store())
                worktree = root / "worktree"
                worktree.mkdir()
                argv = sandbox.minimal_sandbox_argv(
                    workspace=worktree, command=["/usr/bin/true"],
                    workspace_writable=False,
                )
                self.assertNotIn("/nix/store", argv)
                self.assertIn("--unshare-pid", argv)
                self.assertIn("--die-with-parent", argv)

    def test_symlinked_nix_store_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "nix").mkdir()
            other = root / "other"
            other.mkdir()
            store = root / "nix" / "store"
            store.symlink_to(other, target_is_directory=True)
            with mock.patch.object(sandbox, "_NIX_STORE", store):
                with self.assertRaisesRegex(sandbox.AgentSandboxError, "root-owned"):
                    sandbox._trusted_nix_store()

    def test_group_writable_nix_root_or_store_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            nix_root = root / "nix"
            store = nix_root / "store"
            store.mkdir(parents=True)
            with mock.patch.object(sandbox, "_NIX_STORE", store):
                for candidate in (nix_root, store):
                    with self.subTest(candidate=candidate):
                        original_mode = stat.S_IMODE(candidate.stat().st_mode)
                        candidate.chmod(0o777)
                        try:
                            with self.assertRaisesRegex(sandbox.AgentSandboxError, "root-owned"):
                                sandbox._trusted_nix_store()
                        finally:
                            candidate.chmod(original_mode)

    def test_non_root_owned_nix_store_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = root / "nix" / "store"
            store.mkdir(parents=True)
            real_lstat = Path.lstat

            def untrusted_store_lstat(path: Path):
                info = real_lstat(path)
                if path == store:
                    return SimpleNamespace(st_mode=info.st_mode, st_uid=1000)
                return info

            with mock.patch.object(sandbox, "_NIX_STORE", store), mock.patch.object(
                Path, "lstat", untrusted_store_lstat
            ):
                with self.assertRaisesRegex(sandbox.AgentSandboxError, "root-owned"):
                    sandbox._trusted_nix_store()

    def test_root_owned_nixbld_group_write_without_caller_membership_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = Path(raw) / "nix" / "store"
            store.mkdir(parents=True)
            real_lstat = Path.lstat

            def nixbld_lstat(path: Path):
                info = real_lstat(path)
                return SimpleNamespace(
                    st_mode=(stat.S_IFDIR | (0o1775 if path == store else 0o755)),
                    st_uid=0,
                    st_gid=30000 if path == store else 0,
                )

            with (
                mock.patch.object(sandbox, "_NIX_STORE", store),
                mock.patch.object(Path, "lstat", nixbld_lstat),
                mock.patch.object(sandbox.os, "getgroups", return_value=[100, 990]),
                mock.patch.object(sandbox.os, "getegid", return_value=100),
                mock.patch.object(sandbox.os, "access", return_value=False),
            ):
                self.assertEqual(sandbox._trusted_nix_store(), store)

    def test_same_uid_group_or_acl_write_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            store = Path(raw) / "nix" / "store"
            store.mkdir(parents=True)

            def grouped_stat(path: Path):
                return SimpleNamespace(
                    st_mode=stat.S_IFDIR | (0o1775 if path == store else 0o755),
                    st_uid=0,
                    st_gid=990 if path == store else 0,
                )

            with (
                mock.patch.object(sandbox, "_NIX_STORE", store),
                mock.patch.object(Path, "lstat", grouped_stat),
                mock.patch.object(sandbox.os, "getgroups", return_value=[990]),
                mock.patch.object(sandbox.os, "getegid", return_value=100),
                mock.patch.object(sandbox.os, "access", return_value=False),
            ):
                with self.assertRaisesRegex(sandbox.AgentSandboxError, "non-writable"):
                    sandbox._trusted_nix_store()
            with (
                mock.patch.object(sandbox, "_NIX_STORE", store),
                mock.patch.object(Path, "lstat", grouped_stat),
                mock.patch.object(sandbox.os, "getgroups", return_value=[]),
                mock.patch.object(sandbox.os, "getegid", return_value=100),
                mock.patch.object(sandbox.os, "access", return_value=True),
            ):
                with self.assertRaisesRegex(sandbox.AgentSandboxError, "non-writable"):
                    sandbox._trusted_nix_store()

    def test_fixed_store_is_bound_read_only_without_a_write_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw) / "repo"
            scope = worktree / "scope"
            scope.mkdir(parents=True)
            with mock.patch.object(sandbox, "_trusted_nix_store", return_value=Path("/nix/store")):
                argv = sandbox.minimal_sandbox_argv(
                    workspace=worktree, command=["/usr/bin/true"],
                    workspace_writable=True, writable_paths=(scope,),
                )
            self.assertIn(["--dir", "/nix", "--ro-bind", "/nix/store", "/nix/store"],
                          [argv[i:i + 5] for i in range(len(argv) - 4)])
            self.assertNotIn(["--bind", "/nix/store", "/nix/store"],
                             [argv[i:i + 3] for i in range(len(argv) - 2)])
            self.assertIn(["--bind", str(scope), str(scope)],
                          [argv[i:i + 3] for i in range(len(argv) - 2)])
            self.assertIn("--cap-drop", argv)
            self.assertIn("--unshare-pid", argv)

    def test_caller_cannot_shadow_nix_mount(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw) / "repo"
            worktree.mkdir()
            fixture = worktree / "file"
            fixture.write_text("fixture", encoding="utf-8")
            with mock.patch.object(sandbox, "_trusted_nix_store", return_value=Path("/nix/store")):
                for kwargs in (
                    {"extra_directories": (Path("/nix"),)},
                    {"extra_directories": (Path("/nix/store/rogue"),)},
                    {"extra_read_only": ((fixture, Path("/nix/store/evil")),)},
                    {"extra_read_only": ((fixture, Path("/nix")),)},
                ):
                    with self.subTest(kwargs=kwargs), self.assertRaises(sandbox.AgentSandboxError):
                        sandbox.minimal_sandbox_argv(
                            workspace=worktree,
                            command=["/usr/bin/true"],
                            workspace_writable=False,
                            **kwargs,
                        )

    def test_nix_store_cannot_be_shadowed_through_parent_escape_or_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw) / "repo"
            worktree.mkdir()
            fixture = worktree / "private"
            fixture.write_text("fixture", encoding="utf-8")
            fixture.chmod(0o600)
            alias = worktree / "store_alias"
            alias.symlink_to(Path("/nix/store"), target_is_directory=True)
            cases = (
                {"extra_read_only": ((fixture, Path("/var/../nix/store/override")),)},
                {"extra_read_only": ((fixture, Path("/tmp/../nix/store/override")),)},
                {"extra_read_only": ((fixture, alias / "override"),)},
                {"extra_read_write": ((fixture, Path("/tmp/../nix/store/override")),)},
            )
            with mock.patch.object(sandbox, "_trusted_nix_store", return_value=Path("/nix/store")):
                for kwargs in cases:
                    with self.subTest(kwargs=kwargs), self.assertRaises(sandbox.AgentSandboxError):
                        sandbox.minimal_sandbox_argv(
                            workspace=worktree,
                            command=["/usr/bin/true"],
                            workspace_writable=False,
                            **kwargs,
                        )

    def test_real_nixos_bwrap_executes_from_immutable_store(self) -> None:
        if not Path("/nix/store").is_dir():
            self.skipTest("not running on NixOS")
        bash_binary = shutil.which("bash")
        bwrap_binary = (
            os.environ.get("GRABOWSKI_BWRAP_BIN")
            or shutil.which("bwrap")
            or next((str(item) for item in Path("/nix/store").glob("*-bubblewrap-*/bin/bwrap")), None)
        )
        if not bash_binary or not bwrap_binary:
            self.fail("NixOS integration requires bash and bubblewrap")
        bash_resolved = Path(bash_binary).resolve(strict=True)
        bwrap_resolved = Path(bwrap_binary).resolve(strict=True)
        if not bash_resolved.is_relative_to(Path("/nix/store")):
            self.skipTest("bash executable is not a store binary")
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw) / "repo"
            repo.mkdir()
            argv = sandbox.minimal_sandbox_argv(
                workspace=repo, command=[str(bash_resolved), "--noprofile", "--norc", "-c", "exit 0"],
                workspace_writable=False,
            )
            self.assertIn(["--ro-bind", "/nix/store", "/nix/store"],
                          [argv[i:i + 3] for i in range(len(argv) - 2)])
            completed = subprocess.run(
                [str(bwrap_resolved), *argv[1:]],
                check=False, capture_output=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))


if __name__ == "__main__":
    unittest.main()

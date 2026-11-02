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

    def test_nixos_ca_bundle_requires_trusted_immutable_store_target(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            store = root / "nix" / "store"
            store.mkdir(parents=True)
            trusted_ca = store / "trusted-ca.crt"
            trusted_ca.write_text("test-only root certificate", encoding="utf-8")
            link = root / "ca-certificates.crt"
            link.symlink_to(trusted_ca)
            self.assertEqual(
                sandbox._trusted_nixos_ca_bundle(store, link), trusted_ca
            )
            self.assertIsNone(sandbox._trusted_nixos_ca_bundle(None, link))
            other = root / "mutable-ca.crt"
            other.write_text("outside immutable store", encoding="utf-8")
            link.unlink()
            link.symlink_to(other)
            self.assertIsNone(sandbox._trusted_nixos_ca_bundle(store, link))
            link.unlink()
            self.assertIsNone(sandbox._trusted_nixos_ca_bundle(store, link))

    def test_nixos_ca_bundle_readonly_environment_without_writable_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            worktree = root / "worktree"
            worktree.mkdir()
            store = root / "nix" / "store"
            store.mkdir(parents=True)
            ca_bundle = store / "trusted-ca.crt"
            ca_bundle.write_text("test-only root certificate", encoding="utf-8")
            with (
                mock.patch.object(sandbox, "_trusted_nix_store", return_value=store),
                mock.patch.object(
                    sandbox, "_trusted_nixos_ca_bundle", return_value=ca_bundle
                ),
            ):
                argv = sandbox.minimal_sandbox_argv(
                    workspace=worktree, command=["/usr/bin/true"],
                    workspace_writable=False,
                )
            triples = [argv[index:index + 3] for index in range(len(argv) - 2)]
            self.assertIn(["--setenv", "SSL_CERT_FILE", str(ca_bundle)], triples)
            self.assertNotIn(["--bind", str(ca_bundle), str(ca_bundle)], triples)

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

    def test_nixos_vendor_elf_runtime_rejects_user_owned_loader_and_libs(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            untrusted = Path(raw) / "lib"
            untrusted.mkdir()
            (untrusted / "ld.so").write_bytes(b"fake loader")
            with mock.patch.object(sandbox, "_NIX_LD_LIBRARY_DIR", untrusted):
                with self.assertRaisesRegex(sandbox.AgentSandboxError, "NixOS ELF runtime"):
                    sandbox._trusted_nix_vendor_elf_runtime(Path("/nix/store"))

    def test_nixos_vendor_elf_runtime_requires_real_immutable_store(self) -> None:
        if not Path("/nix/store").is_dir():
            self.skipTest("not running on NixOS")
        loader, libraries = sandbox._trusted_nix_vendor_elf_runtime(Path("/nix/store"))
        self.assertTrue(loader.is_relative_to(Path("/nix/store")))
        self.assertTrue(libraries.is_relative_to(Path("/nix/store")))
        self.assertEqual(loader.stat().st_uid, 0)
        self.assertEqual(libraries.stat().st_uid, 0)

    def test_nixos_vendor_elf_is_readonly_and_only_explicit_for_vendors(self) -> None:
        if not Path("/nix/store").is_dir() or Path("/usr/lib64").exists():
            self.skipTest("NixOS vendor ELF loader scenario not present")
        with tempfile.TemporaryDirectory() as raw:
            worktree = Path(raw) / "worktree"
            worktree.mkdir()
            vendor_fixture = worktree / "vendor-binary"
            vendor_fixture.write_bytes(b"vendor fixture")
            loader, libraries = sandbox._trusted_nix_vendor_elf_runtime(Path("/nix/store"))
            plain = sandbox.minimal_sandbox_argv(
                workspace=worktree, command=["/usr/bin/true"],
                workspace_writable=False,
            )
            self.assertNotIn("LD_LIBRARY_PATH", plain)
            self.assertNotIn("/lib64/ld-linux-x86-64.so.2", plain)
            binds = ((vendor_fixture, sandbox.CLAUDE_SANDBOX_EXECUTABLE),)
            argv = sandbox.minimal_sandbox_argv(
                workspace=worktree,
                command=[str(sandbox.CLAUDE_SANDBOX_EXECUTABLE), "--version"],
                workspace_writable=False,
                extra_read_only=binds,
                extra_directories=(Path("/opt"), Path("/opt/grabowski-external")),
            )
            self.assertIn(
                ["--ro-bind", str(loader), "/lib64/ld-linux-x86-64.so.2"],
                [argv[i:i+3] for i in range(len(argv)-2)],
            )
            self.assertIn(
                ["--setenv", "LD_LIBRARY_PATH", str(libraries)],
                [argv[i:i+3] for i in range(len(argv)-2)],
            )
            self.assertNotIn(str(sandbox._NIX_LD_LIBRARY_DIR), argv)
            self.assertNotIn(["--bind", str(libraries), str(libraries)],
                             [argv[i:i+3] for i in range(len(argv)-2)])
            for forbidden in (
                {"extra_directories": (Path("/lib64"),)},
                {"extra_read_only": (*binds, (vendor_fixture, Path("/lib64/ld-linux-x86-64.so.2")))},
                {"extra_read_only": (*binds, (vendor_fixture, Path("/lib64/libc.so.6")))},
            ):
                with self.subTest(forbidden=forbidden), self.assertRaises(sandbox.AgentSandboxError):
                    sandbox.minimal_sandbox_argv(
                        workspace=worktree,
                        command=[str(sandbox.CLAUDE_SANDBOX_EXECUTABLE), "--version"],
                        workspace_writable=False,
                        extra_read_only=forbidden.get("extra_read_only", binds),
                        extra_directories=forbidden.get(
                            "extra_directories", (Path("/opt"), Path("/opt/grabowski-external"))
                        ),
                    )

    def test_real_nixos_vendor_elf_version_without_credentials(self) -> None:
        # Enabled explicitly for the installed NixOS native Claude ELF CLI.
        binary_value = os.environ.get("GRABOWSKI_NIXOS_VENDOR_ELF_PROBE_BIN")
        if not binary_value or not Path("/nix/store").is_dir():
            self.skipTest("NixOS vendor ELF probe binary not provided")
        source = Path(binary_value).resolve(strict=True)
        bwrap = os.environ.get("GRABOWSKI_BWRAP_BIN") or next(
            (str(p) for p in Path("/nix/store").glob("*-bubblewrap-*/bin/bwrap")), None
        )
        if bwrap is None:
            self.fail("NixOS native vendor ELF requires bubblewrap")
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw) / "worktree"
            workspace.mkdir()
            argv = sandbox.minimal_sandbox_argv(
                workspace=workspace,
                command=[str(sandbox.CLAUDE_SANDBOX_EXECUTABLE), "--version"],
                workspace_writable=False,
                extra_read_only=((source, sandbox.CLAUDE_SANDBOX_EXECUTABLE),),
                extra_directories=(Path("/opt"), Path("/opt/grabowski-external")),
            )
            self.assertNotIn(".credentials.json", " ".join(argv))
            result = subprocess.run(
                [str(Path(bwrap).resolve(strict=True)), *argv[1:]],
                check=False, capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertTrue(result.stdout.strip())

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

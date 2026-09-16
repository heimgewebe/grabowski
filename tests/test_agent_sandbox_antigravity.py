from __future__ import annotations

import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_sandbox as sandbox  # noqa: E402


class AntigravitySandboxTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        executable = root / "agy"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        private_parent = root / "gemini-home"
        private_parent.mkdir(mode=0o700)
        auth_root = private_parent / "antigravity-cli"
        auth_root.mkdir(mode=0o755)
        token = auth_root / "antigravity-oauth-token"
        token.write_text("opaque-token\n", encoding="utf-8")
        token.chmod(0o600)
        settings = auth_root / "settings.json"
        settings.write_text("{}\n", encoding="utf-8")
        settings.chmod(0o600)
        return executable, auth_root, token, settings

    def _prepare(self, executable: Path, auth_root: Path, command: list[str]):
        with mock.patch.dict(
            os.environ,
            {
                "GRABOWSKI_ANTIGRAVITY_BIN": str(executable),
                "GRABOWSKI_ANTIGRAVITY_AUTH_ROOT": str(auth_root),
            },
            clear=False,
        ):
            return sandbox.prepare_external_agent_command(command)

    def test_preparation_binds_only_executable_and_private_auth_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable, auth_root, token, settings = self._fixture(Path(directory))
            prepared = self._prepare(
                executable,
                auth_root,
                ["agy", "--model", "gemini-3.1-pro-high", "review this"],
            )

            self.assertEqual(
                prepared.command,
                (
                    str(sandbox.ANTIGRAVITY_SANDBOX_EXECUTABLE),
                    "--model",
                    "gemini-3.1-pro-high",
                    "--print",
                    "review this",
                ),
            )
            self.assertEqual(prepared.profile, sandbox.ANTIGRAVITY_PROFILE)
            self.assertEqual(
                prepared.probe_executable,
                str(sandbox.ANTIGRAVITY_SANDBOX_EXECUTABLE),
            )
            self.assertEqual(
                prepared.extra_read_only,
                (
                    (executable.resolve(), sandbox.ANTIGRAVITY_SANDBOX_EXECUTABLE),
                    (
                        token.resolve(),
                        sandbox.ANTIGRAVITY_SANDBOX_CONFIG_DIR
                        / "antigravity-oauth-token",
                    ),
                    (
                        settings.resolve(),
                        sandbox.ANTIGRAVITY_SANDBOX_CONFIG_DIR / "settings.json",
                    ),
                ),
            )
            self.assertEqual(prepared.extra_read_write, ())
            self.assertNotIn(
                auth_root.resolve(),
                {source for source, _target in prepared.extra_read_only},
            )

    def test_preparation_rejects_unsafe_host_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable, auth_root, token, settings = self._fixture(Path(directory))
            cases = (
                (executable, 0o720),
                (auth_root.parent, 0o755),
                (auth_root, 0o775),
                (token, 0o640),
                (settings, 0o644),
            )
            for path, unsafe_mode in cases:
                with self.subTest(path=path.name):
                    safe_mode = stat.S_IMODE(path.stat().st_mode)
                    path.chmod(unsafe_mode)
                    try:
                        with self.assertRaises(sandbox.AgentSandboxError):
                            self._prepare(executable, auth_root, ["agy", "--version"])
                    finally:
                        path.chmod(safe_mode)

    def test_minimal_sandbox_keeps_host_home_unmounted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree = root / "repo"
            worktree.mkdir()
            executable, auth_root, _token, _settings = self._fixture(root)
            prepared = self._prepare(executable, auth_root, ["agy", "--version"])
            argv = sandbox.minimal_sandbox_argv(
                workspace=worktree,
                command=list(prepared.command),
                workspace_writable=False,
                extra_read_only=prepared.extra_read_only,
                extra_read_write=prepared.extra_read_write,
                extra_directories=prepared.extra_directories,
            )

            joined = "\n".join(argv)
            self.assertIn(
                "/tmp/.gemini/antigravity-cli/antigravity-oauth-token", joined
            )
            self.assertIn("/tmp/.gemini/antigravity-cli/settings.json", joined)
            self.assertNotIn(f"--ro-bind\n{auth_root.resolve()}\n", joined)
            home_index = argv.index("HOME")
            self.assertEqual(argv[home_index + 1], "/tmp")

    def test_non_prompt_command_preserves_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable, auth_root, _token, _settings = self._fixture(Path(directory))
            prepared = self._prepare(executable, auth_root, ["agy", "--version"])
            self.assertEqual(
                prepared.command,
                (str(sandbox.ANTIGRAVITY_SANDBOX_EXECUTABLE), "--version"),
            )


if __name__ == "__main__":
    unittest.main()

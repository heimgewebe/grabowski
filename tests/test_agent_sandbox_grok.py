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

import grabowski_agent_sandbox as sandbox


class GrokSandboxTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        executable = root / "grok"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        auth_root = root / "grok-home"
        auth_root.mkdir(mode=0o755)
        auth_file = auth_root / "auth.json"
        auth_file.write_text("{}\n", encoding="utf-8")
        auth_file.chmod(0o600)
        return executable, auth_root, auth_file

    def _prepare(self, executable: Path, auth_root: Path, command: list[str]):
        with mock.patch.dict(
            os.environ,
            {
                "GRABOWSKI_GROK_BIN": str(executable),
                "GRABOWSKI_GROK_AUTH_ROOT": str(auth_root),
            },
            clear=False,
        ):
            return sandbox.prepare_external_agent_command(command)

    def test_grok_preparation_binds_only_executable_and_private_auth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable, auth_root, auth_file = self._fixture(Path(directory))
            prepared = self._prepare(
                executable,
                auth_root,
                ["grok", "--model", "grok-4.6", "review this"],
            )

            self.assertEqual(
                prepared.command,
                (
                    str(sandbox.GROK_SANDBOX_EXECUTABLE),
                    "--model",
                    "grok-4.6",
                    "-p",
                    "review this",
                ),
            )
            self.assertEqual(prepared.profile, sandbox.GROK_PROFILE)
            self.assertEqual(
                prepared.probe_executable, str(sandbox.GROK_SANDBOX_EXECUTABLE)
            )
            self.assertEqual(
                prepared.extra_read_only,
                (
                    (executable.resolve(), sandbox.GROK_SANDBOX_EXECUTABLE),
                    (auth_file.resolve(), sandbox.GROK_SANDBOX_CONFIG_DIR / "auth.json"),
                ),
            )
            self.assertEqual(prepared.extra_read_write, ())
            self.assertNotIn(
                auth_root.resolve(),
                {source for source, _target in prepared.extra_read_only},
            )

    def test_grok_preparation_rejects_unsafe_host_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable, auth_root, auth_file = self._fixture(root)
            cases = (
                (executable, 0o720),
                (auth_root, 0o775),
                (auth_file, 0o640),
            )
            for path, unsafe_mode in cases:
                with self.subTest(path=path.name):
                    safe_mode = stat.S_IMODE(path.stat().st_mode)
                    path.chmod(unsafe_mode)
                    try:
                        with self.assertRaises(sandbox.AgentSandboxError):
                            self._prepare(executable, auth_root, ["grok", "--version"])
                    finally:
                        path.chmod(safe_mode)

    def test_grok_minimal_sandbox_keeps_host_home_unmounted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worktree = root / "repo"
            worktree.mkdir()
            executable, auth_root, _auth_file = self._fixture(root)
            prepared = self._prepare(
                executable,
                auth_root,
                ["grok", "--model", "grok-4.6", "review this"],
            )
            argv = sandbox.minimal_sandbox_argv(
                workspace=worktree,
                command=list(prepared.command),
                workspace_writable=False,
                extra_read_only=prepared.extra_read_only,
                extra_read_write=prepared.extra_read_write,
                extra_directories=prepared.extra_directories,
            )

            joined = "\n".join(argv)
            self.assertIn("/tmp/.grok/auth.json", joined)
            self.assertNotIn(f"--ro-bind\n{auth_root.resolve()}\n", joined)
            self.assertNotIn("XAI_API_KEY", joined)
            home_index = argv.index("HOME")
            self.assertEqual(argv[home_index + 1], "/tmp")

    def test_grok_non_review_command_preserves_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable, auth_root, _auth_file = self._fixture(Path(directory))
            prepared = self._prepare(executable, auth_root, ["grok", "--version"])
            self.assertEqual(
                prepared.command,
                (str(sandbox.GROK_SANDBOX_EXECUTABLE), "--version"),
            )


if __name__ == "__main__":
    unittest.main()

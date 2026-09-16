from __future__ import annotations

import hashlib
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

    def test_default_grok_binary_requires_owner_controlled_versioned_containment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            grok_root = home / ".grok"
            bin_directory = grok_root / "bin"
            bin_directory.mkdir(parents=True, mode=0o755)
            native = bin_directory / "grok-1.0.30"
            native.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            native.chmod(0o700)
            canonical = bin_directory / "grok"
            canonical.symlink_to(native.name)
            auth_file = grok_root / "auth.json"
            auth_file.write_text("{}\n", encoding="utf-8")
            auth_file.chmod(0o600)
            environment = {
                "HOME": str(home),
                "GRABOWSKI_GROK_BIN": "",
                "GRABOWSKI_GROK_AUTH_ROOT": str(grok_root),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                prepared = sandbox.prepare_external_agent_command(["grok", "--version"])
                self.assertEqual(prepared.extra_read_only[0][0], native.resolve())

                bin_directory.chmod(0o775)
                try:
                    with self.assertRaisesRegex(sandbox.AgentSandboxError, "binary directory"):
                        sandbox.prepare_external_agent_command(["grok", "--version"])
                finally:
                    bin_directory.chmod(0o755)

                outside = home / "grok-elsewhere"
                outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                outside.chmod(0o700)
                canonical.unlink()
                canonical.symlink_to(outside)
                with self.assertRaisesRegex(sandbox.AgentSandboxError, "versioned native"):
                    sandbox.prepare_external_agent_command(["grok", "--version"])

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


    def test_minimal_sandbox_materializes_anonymous_fd_as_read_only_tmp_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "repo"
            worktree.mkdir()
            argv = sandbox.minimal_sandbox_argv(
                workspace=worktree,
                command=["/usr/bin/true"],
                workspace_writable=False,
                extra_read_only_data_fds=((0, Path("/tmp/grabowski-bound-review-prompt")),),
            )
        bind_index = argv.index("--ro-bind-data")
        self.assertEqual(argv[bind_index - 2 : bind_index + 3], [
            "--perms", "0400", "--ro-bind-data", "0", "/tmp/grabowski-bound-review-prompt"
        ])
        self.assertNotIn("grabowski-grok-review-", "\n".join(argv))

    def test_minimal_sandbox_rejects_unsafe_read_only_data_fd_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "repo"
            worktree.mkdir()
            for binding in ((-1, Path("/tmp/prompt")), (0, Path("/etc/prompt")), (0, Path("relative"))):
                with self.subTest(binding=binding), self.assertRaises(sandbox.AgentSandboxError):
                    sandbox.minimal_sandbox_argv(
                        workspace=worktree,
                        command=["/usr/bin/true"],
                        workspace_writable=False,
                        extra_read_only_data_fds=(binding,),
                    )

    def test_bounded_capture_supplies_large_anonymous_stdin(self) -> None:
        payload = b"x" * 247_109
        code = (
            "import hashlib, sys; "
            "data = sys.stdin.buffer.read(); "
            "print(len(data)); print(hashlib.sha256(data).hexdigest())"
        )
        captured = sandbox.run_bounded_capture(
            [sys.executable, "-c", code],
            stdout_limit=4096,
            stderr_limit=4096,
            stdout_content_limit=4096,
            stdin_content=payload,
        )
        self.assertEqual(captured.returncode, 0)
        self.assertIsNotNone(captured.stdout_content)
        lines = captured.stdout_content.decode("utf-8").splitlines()
        self.assertEqual(lines[0], str(len(payload)))
        self.assertEqual(lines[1], hashlib.sha256(payload).hexdigest())

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

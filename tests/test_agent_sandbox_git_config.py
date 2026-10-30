from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_agent_sandbox as sandbox


def _sandbox_environment(argv: list[str]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for index, item in enumerate(argv[:-2]):
        if item == "--setenv":
            environment[argv[index + 1]] = argv[index + 2]
    return environment


class AgentSandboxGitConfigTests(unittest.TestCase):
    def sandbox_environment(self, workspace: Path, *, writable: bool) -> dict[str, str]:
        writable_paths: tuple[Path, ...] = ()
        if writable:
            target = workspace / "scope"
            target.mkdir()
            writable_paths = (target,)
        argv = sandbox.minimal_sandbox_argv(
            workspace=workspace,
            command=["grok", "-p", "noop"],
            workspace_writable=writable,
            writable_paths=writable_paths,
        )
        return _sandbox_environment(argv)

    def test_read_only_and_writer_sandboxes_pin_executable_git_config(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for writable in (False, True):
                workspace = root / ("writer" if writable else "reader")
                workspace.mkdir()
                environment = self.sandbox_environment(workspace, writable=writable)
                self.assertEqual(environment["GIT_CONFIG_COUNT"], "2")
                self.assertEqual(environment["GIT_CONFIG_KEY_0"], "core.hooksPath")
                self.assertEqual(environment["GIT_CONFIG_VALUE_0"], "/dev/null")
                self.assertEqual(environment["GIT_CONFIG_KEY_1"], "core.fsmonitor")
                self.assertEqual(environment["GIT_CONFIG_VALUE_1"], "false")
                self.assertNotIn("GIT_CONFIG_GLOBAL", environment)
                self.assertNotIn("GIT_CONFIG_NOSYSTEM", environment)

    def test_sandbox_command_scope_wins_over_repo_local_git_config(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            subprocess.run(
                ["git", "init", "-q", str(workspace)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "config", "core.fsmonitor", "/tmp/repo-fsmonitor-helper"],
                cwd=workspace,
                check=True,
            )
            subprocess.run(
                ["git", "config", "core.hooksPath", "/tmp/repo-hooks"],
                cwd=workspace,
                check=True,
            )

            sandbox_environment = self.sandbox_environment(workspace, writable=False)
            environment = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("GIT_CONFIG_")
            }
            environment.update(sandbox_environment)

            fsmonitor = subprocess.run(
                ["git", "config", "--get", "core.fsmonitor"],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            hooks_path = subprocess.run(
                ["git", "config", "--get", "core.hooksPath"],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(fsmonitor.stdout.strip(), "false")
            self.assertEqual(hooks_path.stdout.strip(), "/dev/null")


    def test_safe_git_environment_drops_inherited_git_scope_and_helpers(self) -> None:
        poisoned = {
            "PATH": "/usr/bin:/bin",
            "CUSTOM_LABEL": "preserved",
            "GIT_DIR": "/tmp/forged-git-dir",
            "GIT_WORK_TREE": "/tmp/forged-worktree",
            "GIT_INDEX_FILE": "/tmp/forged-index",
            "GIT_TRACE": "/tmp/trace-leak",
            "GIT_SSH_COMMAND": "/tmp/evil-ssh",
            "GIT_EXEC_PATH": "/tmp/evil-git-exec",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/tmp/evil-hooks",
        }
        safe = sandbox.safe_git_environment(poisoned)
        for key in (
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_TRACE",
            "GIT_SSH_COMMAND", "GIT_EXEC_PATH",
        ):
            self.assertNotIn(key, safe)
        self.assertEqual(safe["PATH"], poisoned["PATH"])
        self.assertEqual(safe["CUSTOM_LABEL"], "preserved")
        self.assertEqual(safe["GIT_CONFIG_COUNT"], "2")
        self.assertEqual(safe["GIT_CONFIG_KEY_0"], "core.hooksPath")
        self.assertEqual(safe["GIT_CONFIG_VALUE_0"], "/dev/null")
        self.assertEqual(safe["GIT_CONFIG_KEY_1"], "core.fsmonitor")
        self.assertEqual(safe["GIT_CONFIG_VALUE_1"], "false")

    def test_safe_git_environment_keeps_git_c_bound_to_selected_repo(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            checkout = Path(raw) / "checkout"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            poisoned = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", str(checkout)),
                "GIT_DIR": str(checkout / "nonexistent-git-dir"),
                "GIT_INDEX_FILE": str(checkout / "forged-index"),
            }
            command = ["git", "-C", str(checkout), "rev-parse", "--git-dir"]
            negative = subprocess.run(command, env=poisoned, capture_output=True, text=True)
            self.assertNotEqual(negative.returncode, 0, "negative precontrol must fail")
            positive = subprocess.run(
                command,
                env=sandbox.safe_git_environment(poisoned),
                capture_output=True,
                text=True,
            )
            self.assertEqual(positive.returncode, 0, positive.stderr)
            self.assertEqual(positive.stdout.strip(), ".git")


if __name__ == "__main__":
    unittest.main()

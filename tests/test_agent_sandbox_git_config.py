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

    def test_sealed_snapshot_filter_preserves_ignore_without_creating_host_attributes(self) -> None:
        """A hostile tracked attribute cannot start a clean filter in status/diff."""
        with tempfile.TemporaryDirectory(prefix="git-filter-effect-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
            for key, value in (
                ("user.name", "Snapshot Test"),
                ("user.email", "snapshot@example.invalid"),
            ):
                subprocess.run(
                    ["git", "config", key, value], cwd=repo, check=True,
                    capture_output=True,
                )
            (repo / "src").mkdir()
            tracked = repo / "src/app.py"
            tracked.write_text("old\n", encoding="utf-8")
            (repo / ".gitattributes").write_text(
                "src/app.py filter=late\n", encoding="utf-8",
            )
            subprocess.run(
                ["git", "add", "src/app.py", ".gitattributes"],
                cwd=repo, check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-qm", "baseline"],
                cwd=repo, check=True, capture_output=True,
            )
            info = repo / ".git/info"
            attributes = info / "attributes"
            self.assertFalse(attributes.exists())
            exclude = info / "exclude"
            exclude.write_text("*.ignored\n", encoding="utf-8")
            original_exclude = exclude.read_bytes()
            (repo / "secret.ignored").write_text("private\n", encoding="utf-8")
            (repo / "visible.txt").write_text("untracked\n", encoding="utf-8")
            marker = root / "executed"
            subprocess.run(
                ["git", "config", "--local", "filter.late.clean",
                 f"sh -c 'touch {marker}; cat'"],
                cwd=repo, check=True, capture_output=True,
            )
            tracked.write_text("new contents\n", encoding="utf-8")
            diff_args = ["git", "diff", "--no-ext-diff", "--no-textconv", "HEAD"]
            control = subprocess.run(
                diff_args, cwd=repo, capture_output=True, check=True,
            )
            self.assertTrue(marker.exists(), "control must execute hostile filter")
            marker.unlink()
            with sandbox.safe_git_snapshot_filter_effect(repo, diff_args) as (
                command, environment, descriptors
            ):
                observed = subprocess.run(
                    command, cwd=repo, env=environment,
                    pass_fds=descriptors, capture_output=True, check=True,
                )
            self.assertEqual(observed.stdout, control.stdout)
            self.assertFalse(marker.exists(), "sealed Git filter override was bypassed")
            self.assertFalse(attributes.exists(), "sandbox mutated host info/attributes")
            with sandbox.safe_git_snapshot_filter_effect(
                repo, ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            ) as (command, environment, descriptors):
                status = subprocess.run(
                    command, cwd=repo, env=environment,
                    pass_fds=descriptors, capture_output=True, check=True,
                )
            self.assertIn(b"?? visible.txt\x00", status.stdout)
            self.assertNotIn(b"secret.ignored", status.stdout)
            self.assertEqual(exclude.read_bytes(), original_exclude)
            self.assertFalse(marker.exists())
            self.assertFalse(attributes.exists(), "host attributes created by bubblewrap")

            # An empty diff.external is an attempted executable, not an inert
            # setting. The sealed snapshot must keep real diff functionality
            # while preventing repository-selected external diff helpers.
            diff_helper = root / "diff-helper"
            diff_marker = root / "external-diff-executed"
            diff_helper.write_text(
                "#!/bin/sh\ntouch " + str(diff_marker) + "\nexit 1\n",
                encoding="utf-8",
            )
            diff_helper.chmod(0o700)
            subprocess.run(
                ["git", "config", "--local", "diff.external", str(diff_helper)],
                cwd=repo, check=True, capture_output=True,
            )
            external_control = subprocess.run(
                ["git", "diff", "HEAD"], cwd=repo, capture_output=True,
            )
            self.assertNotEqual(external_control.returncode, 0)
            self.assertTrue(diff_marker.exists(), "external diff control did not trigger")
            diff_marker.unlink()
            marker.unlink(missing_ok=True)
            for arguments in (
                ["git", "diff", "HEAD"],
                ["git", "diff", "--ext-diff", "--end-of-options", "HEAD"],
            ):
                with self.subTest(arguments=arguments):
                    with sandbox.safe_git_snapshot_filter_effect(
                        repo, arguments
                    ) as (command, environment, descriptors):
                        protected = subprocess.run(
                            command, cwd=repo, env=environment,
                            pass_fds=descriptors, capture_output=True,
                        )
                    self.assertEqual(protected.returncode, 0, protected.stderr)
                    self.assertIn(b"new contents", protected.stdout)
                    self.assertFalse(diff_marker.exists())
                    self.assertFalse(marker.exists(), "clean filter escaped sealed attributes")
                    self.assertFalse(attributes.exists(), "host attributes were created")


    def test_sealed_snapshot_preserves_nonfilter_info_attributes(self) -> None:
        """The original info/attributes -diff must survive filter suppression."""
        with tempfile.TemporaryDirectory(prefix="git-info-attributes-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
            for key, value in (("user.name", "Test"), ("user.email", "t@example.invalid")):
                subprocess.run(
                    ["git", "config", key, value], cwd=repo, check=True, capture_output=True,
                )
            tracked = repo / "file.txt"
            tracked.write_text("before\n", encoding="utf-8")
            subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
            attributes = repo / ".git" / "info" / "attributes"
            attributes.write_bytes(b"file.txt -diff filter=late\n")
            original_attributes = attributes.read_bytes()
            marker = root / "executed"
            subprocess.run(
                ["git", "config", "filter.late.clean", f"sh -c 'touch {marker}; cat'"],
                cwd=repo, check=True,
            )
            tracked.write_text("after\n", encoding="utf-8")
            command = ["git", "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD"]
            control = subprocess.run(command, cwd=repo, capture_output=True, check=True)
            self.assertTrue(marker.exists(), "RED filter control did not execute")
            marker.unlink()
            with sandbox.safe_git_snapshot_filter_effect(
                repo, command
            ) as (argv, environment, descriptors):
                guarded = subprocess.run(
                    argv, cwd=repo, env=environment, pass_fds=descriptors,
                    capture_output=True, check=True,
                )
            self.assertEqual(guarded.stdout, control.stdout)
            self.assertFalse(marker.exists())
            self.assertEqual(attributes.read_bytes(), original_attributes)

    def test_sealed_snapshot_supports_missing_info_directory_without_host_write(self) -> None:
        """Optional Git info must be created only inside the child namespace."""
        with tempfile.TemporaryDirectory(prefix="git-info-absent-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
            for key, value in (("user.name", "Test"), ("user.email", "t@example.invalid")):
                subprocess.run(
                    ["git", "config", key, value], cwd=repo, check=True, capture_output=True,
                )
            tracked = repo / "file.txt"
            tracked.write_text("base\n", encoding="utf-8")
            (repo / ".gitattributes").write_text(
                "file.txt filter=late\n", encoding="utf-8"
            )
            subprocess.run(
                ["git", "add", "file.txt", ".gitattributes"], cwd=repo, check=True,
            )
            subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
            info = repo / ".git" / "info"
            for item in info.iterdir():
                self.assertTrue(item.is_file() and not item.is_symlink())
                item.unlink()
            info.rmdir()
            self.assertFalse(info.exists())
            marker = root / "executed"
            subprocess.run(
                ["git", "config", "filter.late.clean", f"sh -c 'touch {marker}; cat'"],
                cwd=repo, check=True,
            )
            tracked.write_text("changed\n", encoding="utf-8")
            control = subprocess.run(
                ["git", "diff", "HEAD"], cwd=repo, capture_output=True, check=True,
            )
            self.assertTrue(marker.exists(), "RED filter control did not execute")
            marker.unlink()
            with sandbox.safe_git_snapshot_filter_effect(
                repo, ["git", "diff", "HEAD"]
            ) as (argv, environment, descriptors):
                guarded = subprocess.run(
                    argv, cwd=repo, env=environment, pass_fds=descriptors,
                    capture_output=True, check=True,
                )
            self.assertEqual(guarded.stdout, control.stdout)
            self.assertFalse(marker.exists())
            self.assertFalse(info.exists(), "Git info directory was created on the host")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import grabowski_bureau_leases as bureau


class BureauControlLockPortabilityTests(unittest.TestCase):
    def test_missing_posix_lock_api_fails_closed(self) -> None:
        with mock.patch.object(bureau, "_fcntl", None):
            with self.assertRaises(bureau.BureauLeaseContractError) as raised:
                with bureau._bureau_control_lock():
                    self.fail("unavailable lock unexpectedly entered")

        self.assertEqual(
            raised.exception.code,
            "control-checkout-lock-unavailable",
        )


class BureauControlCheckoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.remote = self.root / "remote.git"
        self.seed = self.root / "seed"
        self.shared = self.root / "bureau"
        self.worktrees = self.root / ".bureau-worktrees"
        self.control = self.worktrees / "control-main"
        self.lock = self.root / "state" / "control.lock"
        self._git(self.root, "init", "--bare", str(self.remote))
        self._git(self.root, "init", "-b", "main", str(self.seed))
        (self.seed / "registry.txt").write_text("one\n", encoding="utf-8")
        self._git(self.seed, "add", "registry.txt")
        self._git(self.seed, "commit", "-m", "initial")
        self._git(self.seed, "remote", "add", "origin", str(self.remote))
        self._git(self.seed, "push", "-u", "origin", "main")
        self._git(
            self.root,
            "--git-dir",
            str(self.remote),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        )
        self._git(self.root, "clone", str(self.remote), str(self.shared))
        self.worktrees.mkdir()
        self._git(
            self.shared,
            "worktree",
            "add",
            "--track",
            "-b",
            "ops/bureau-control-main",
            str(self.control),
            "origin/main",
        )
        self.patches = [
            mock.patch.object(bureau, "BUREAU_REPOSITORY_ROOT", self.shared),
            mock.patch.object(bureau, "BUREAU_WORKTREE_ROOT", self.worktrees),
            mock.patch.object(bureau, "BUREAU_CONTROL_ROOT", self.control),
            mock.patch.object(bureau, "BUREAU_CONTROL_LOCK_PATH", self.lock),
            mock.patch.object(
                bureau,
                "BUREAU_CANONICAL_REMOTE_URL",
                str(self.remote),
            ),
            mock.patch.object(
                bureau,
                "_control_git_environment",
                return_value=self._control_environment(),
            ),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_AUTHOR_NAME": "Grabowski Test",
            "GIT_AUTHOR_EMAIL": "grabowski@example.invalid",
            "GIT_COMMITTER_NAME": "Grabowski Test",
            "GIT_COMMITTER_EMAIL": "grabowski@example.invalid",
        }

    @staticmethod
    def _control_environment() -> dict[str, str]:
        return {
            "HOME": str(Path.home()),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ALLOW_PROTOCOL": "file",
        }

    @classmethod
    def _git(cls, cwd: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-c", "protocol.file.allow=always", *arguments],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            env=cls._environment(),
        )
        return completed.stdout.strip()

    def _advance_remote(self) -> str:
        (self.seed / "registry.txt").write_text("two\n", encoding="utf-8")
        self._git(self.seed, "add", "registry.txt")
        self._git(self.seed, "commit", "-m", "advance")
        self._git(self.seed, "push", "origin", "main")
        return self._git(self.seed, "rev-parse", "HEAD")

    def test_refresh_fast_forwards_control_without_touching_dirty_workbench(
        self,
    ) -> None:
        before = bureau.inspect_bureau_control_checkout()
        shared_head = self._git(self.shared, "rev-parse", "HEAD")
        (self.shared / "workbench-only.txt").write_text(
            "foreign work\n", encoding="utf-8"
        )
        expected = self._advance_remote()
        result = bureau.refresh_bureau_control_checkout()
        self.assertTrue(result["updated"])
        self.assertEqual(result["previous_head"], before["head"])
        self.assertEqual(result["head"], expected)
        self.assertEqual(result["origin_main"], expected)
        self.assertFalse(result["dirty"])
        self.assertEqual(self._git(self.shared, "rev-parse", "HEAD"), shared_head)
        self.assertIn(
            "?? workbench-only.txt",
            self._git(self.shared, "status", "--short"),
        )

    def test_dirty_control_checkout_fails_closed_before_fetch(self) -> None:
        (self.control / "control-only.txt").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(
            bureau.BureauLeaseContractError, "control-checkout-dirty"
        ):
            bureau.refresh_bureau_control_checkout()


if __name__ == "__main__":
    unittest.main()

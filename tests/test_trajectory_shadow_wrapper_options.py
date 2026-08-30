from __future__ import annotations

import unittest

from experimental.trajectory_shadow import trajectory_shadow as ts


class TrajectoryShadowWrapperOptionsTests(unittest.TestCase):
    def test_verification_wrapper_options_preserve_nested_command(self) -> None:
        commands = (
            "env -a test pytest -q",
            "env --argv0 test pytest -q",
            "env -u FOO pytest -q",
            "env --unset FOO ruff check .",
            "env -C /tmp pytest -q",
            "env --chdir /tmp pytest -q",
            "env --unset=FOO pytest -q",
            "timeout -s TERM 120 pytest -q",
            "timeout --signal TERM 120 pytest -q",
            "timeout -k 10 120 pytest -q",
            "timeout --signal=TERM 120 pytest -q",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(ts._classify_shell(command, "/tmp/worktree")[0], "verify")

    def test_verification_wrapper_options_without_command_remain_execute(self) -> None:
        commands = (
            "env -u FOO",
            "env --unset FOO",
            "env -C /tmp",
            "timeout -s TERM 120",
            "timeout --signal TERM 120",
            "timeout -k 10 120",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(ts._classify_shell(command, "/tmp/worktree")[0], "execute")


if __name__ == "__main__":
    unittest.main()

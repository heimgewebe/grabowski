"""Reject dynamic shell command-position expansion before Codex admission."""

from __future__ import annotations

import unittest

import test_tasks as fixture


tasks = fixture.tasks


class TaskShellDynamicEntrypointTests(unittest.TestCase):
    def test_embedded_parameter_expansion_must_fail_closed(self) -> None:
        """Even a nonleading dollar may construct 'codex' as the command."""
        candidates = (
            ["/bin/bash", "-c", "c${UNSET}odex exec prompt"],
            ["/bin/bash", "-c", 'c"$UNSET"odex exec prompt'],
            ["/bin/bash", "-c", 'exec c${UNSET}odex exec prompt'],
            ["/bin/bash", "-c", 'command c${UNSET}odex exec prompt'],
            ["/bin/sh", "-c", "c${UNSET}odex exec prompt"],
            ["/bin/bash", "-c", "c\x60printf od\x60ex exec prompt"],
        )
        for argv in candidates:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(
                    RuntimeError, "Codex filesystem sandbox cannot verify dynamic shell command"
                ):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_expansion_only_in_data_is_not_command(self) -> None:
        for source in (
            "printf 'c${UNSET}odex'",
            'echo "c$UNSET"odex',
            "cargo test --filter='c${UNSET}odex'",
        ):
            with self.subTest(source=source):
                tasks._require_direct_codex_filesystem_sandbox(
                    ["/bin/bash", "-c", source]
                )


if __name__ == "__main__":
    unittest.main()

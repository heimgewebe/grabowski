"""Regression: production reviewer/agent Git never inherits caller Git scope overrides."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from grabowski_agent_sandbox import safe_git_environment


class SafeGitEnvironmentIsolationTests(unittest.TestCase):
    def test_inherited_git_environment_is_not_trusted(self) -> None:
        inherited = {
            "HOME": "/tmp/reviewer-fixture-home",
            "PATH": os.environ.get("PATH", "/usr/bin"),
            "GIT_DIR": "/tmp/attacker/repo.git",
            "GIT_COMMON_DIR": "/tmp/attacker/common",
            "GIT_WORK_TREE": "/tmp/attacker/worktree",
            "GIT_INDEX_FILE": "/tmp/attacker/index",
            "GIT_OBJECT_DIRECTORY": "/tmp/attacker/objects",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/tmp/attacker/alternates",
            "GIT_NAMESPACE": "attacker",
            "GIT_REPLACE_REF_BASE": "refs/replace/attacker",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/tmp/attacker/hooks",
            "GIT_CONFIG_PARAMETERS": "'core.fsmonitor=/tmp/attacker/monitor'",
            "GIT_CONFIG_SYSTEM": "/tmp/attacker/system-config",
            "GIT_CONFIG_GLOBAL": "/tmp/attacker/global-config",
            "GIT_SSH_COMMAND": "/tmp/attacker/ssh-wrapper",
            "GIT_ASKPASS": "/tmp/attacker/askpass",
            "GIT_EXEC_PATH": "/tmp/attacker/exec",
            "GIT_TEMPLATE_DIR": "/tmp/attacker/templates",
            "GIT_EXTERNAL_DIFF": "/tmp/attacker/diff",
            "GIT_TRACE": "/tmp/attacker/git-trace",
            "GIT_TRACE_SETUP": "/tmp/attacker/git-setup-trace",
            "GIT_TRACE2_EVENT": "/tmp/attacker/git-trace2",
        }
        snapshot = dict(inherited)
        environment = safe_git_environment(inherited)
        self.assertEqual(inherited, snapshot)
        self.assertEqual(environment["HOME"], inherited["HOME"])
        self.assertEqual(environment["PATH"], inherited["PATH"])
        for key in inherited:
            if key.startswith("GIT_") and key not in {
                "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL",
            }:
                with self.subTest(key=key):
                    self.assertNotIn(key, environment)

        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "ssh:https:file")
        self.assertNotEqual(environment["GIT_CONFIG_VALUE_0"], "/tmp/attacker/hooks")
        pairs = {
            environment[f"GIT_CONFIG_KEY_{index}"]: environment[f"GIT_CONFIG_VALUE_{index}"]
            for index in range(int(environment["GIT_CONFIG_COUNT"]))
        }
        self.assertEqual(pairs["core.hooksPath"], "/dev/null")
        self.assertEqual(pairs["core.fsmonitor"], "false")

    def test_git_c_remains_anchored_despite_inherited_scope(self) -> None:
        with tempfile.TemporaryDirectory(prefix="review-git-env-") as temporary:
            root = Path(temporary)
            expected = root / "expected"
            foreign = root / "foreign"
            for checkout in (expected, foreign):
                clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
                clean["LC_ALL"] = "C"
                subprocess.run(
                    ["git", "init", "-q", "-b", "main", str(checkout)],
                    env=clean, check=True, capture_output=True, timeout=15,
                )
            foreign_index = root / "foreign-index-not-created"
            inherited = {
                "PATH": os.environ.get("PATH", "/usr/bin"),
                "HOME": str(root),
                "GIT_DIR": str(foreign / ".git"),
                "GIT_WORK_TREE": str(foreign),
                "GIT_INDEX_FILE": str(foreign_index),
                "GIT_OBJECT_DIRECTORY": str(root / "foreign-objects"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.hooksPath",
                "GIT_CONFIG_VALUE_0": str(root / "foreign-hooks"),
            }
            safe = safe_git_environment(inherited)
            result = subprocess.run(
                ["git", "-C", str(expected), "rev-parse", "--show-toplevel"],
                env=safe, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(result.stdout.strip()).resolve(), expected.resolve())
            self.assertFalse(foreign_index.exists())
            self.assertFalse((root / "foreign-objects").exists())


if __name__ == "__main__":
    unittest.main()

"""Regression: production reviewer/agent Git never inherits caller Git scope overrides."""

from __future__ import annotations

import os
import pwd
import shlex
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
        self.assertEqual(environment["HOME"], pwd.getpwuid(os.geteuid()).pw_dir)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        for key in inherited:
            if key.startswith("GIT_") and key not in {
                "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL",
                "GIT_SSH_COMMAND", "GIT_ASKPASS",
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


    def test_transport_and_non_git_environment_injection_is_rejected(self) -> None:
        # Independently reported P1: stripping GIT_* is not enough when SSH,
        # PATH, HOME or HTTPS trust paths remain executable overrides.
        incoming = {
            "HOME": "/tmp/attacker-ssh-home",
            "PATH": "/tmp/attacker-binaries:/usr/bin",
            "XDG_CONFIG_HOME": "/tmp/attacker-xdg",
            "SSH_ASKPASS": "/tmp/attacker-askpass",
            "SSH_ASKPASS_REQUIRE": "force",
            "SSH_AUTH_SOCK": "/tmp/attacker-agent.sock",
            "LD_PRELOAD": "/tmp/attacker.so",
            "LD_LIBRARY_PATH": "/tmp/attacker-libs",
            "PYTHONPATH": "/tmp/attacker-python",
            "HTTPS_PROXY": "http://attacker-proxy.invalid:3128",
            "HTTP_PROXY": "http://attacker-proxy.invalid:3128",
            "ALL_PROXY": "socks5://attacker-proxy.invalid:3128",
            "CURL_CA_BUNDLE": "/tmp/attacker-ca",
            "SSL_CERT_FILE": "/tmp/attacker-cert",
            "GIT_SSH_COMMAND": "/tmp/attacker-ssh",
            "GIT_ASKPASS": "/tmp/attacker-git-askpass",
        }
        before = dict(incoming)
        protected = safe_git_environment(incoming)
        self.assertEqual(incoming, before)
        self.assertEqual(protected["PATH"], "/usr/bin:/bin")
        self.assertEqual(protected["HOME"], pwd.getpwuid(os.geteuid()).pw_dir)
        self.assertEqual(protected["SSH_ASKPASS"], "/bin/false")
        self.assertEqual(protected["SSH_ASKPASS_REQUIRE"], "never")
        self.assertEqual(protected["GIT_ASKPASS"], "/bin/false")
        ssh = protected["GIT_SSH_COMMAND"]
        self.assertTrue(ssh.startswith("/usr/bin/ssh -F /dev/null "), ssh)
        for required in (
            "-oBatchMode=yes", "-oProxyCommand=none",
            "-oPermitLocalCommand=no", "-oClearAllForwardings=yes",
            "-oStrictHostKeyChecking=yes",
        ):
            self.assertIn(required, ssh)
        self.assertEqual(protected["GIT_SSH_VARIANT"], "ssh")
        for key in (
            "XDG_CONFIG_HOME", "SSH_AUTH_SOCK", "LD_PRELOAD",
            "LD_LIBRARY_PATH", "PYTHONPATH", "HTTPS_PROXY",
            "HTTP_PROXY", "ALL_PROXY", "CURL_CA_BUNDLE", "SSL_CERT_FILE",
        ):
            with self.subTest(key=key):
                self.assertNotIn(key, protected)

    def test_poisoned_path_cannot_replace_git_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="review-git-path-") as temporary:
            root = Path(temporary)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            marker = root / "fake-git-was-executed"
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\\n: > " + shlex.quote(str(marker))
                + "\\nprintf 'attacker git\\n'\\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o700)
            secure = safe_git_environment({
                "HOME": str(root),
                "PATH": str(fake_bin) + ":/usr/bin:/bin",
            })
            result = subprocess.run(
                ["git", "--version"], env=secure, text=True,
                capture_output=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.startswith("git version "), result.stdout)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()

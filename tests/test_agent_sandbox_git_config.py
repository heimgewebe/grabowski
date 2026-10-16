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
                expected_overrides = (
                    ("core.hooksPath", "/dev/null"),
                    ("core.fsmonitor", "false"),
                    ("core.editor", "/bin/false"),
                    ("core.pager", "cat"),
                    ("sequence.editor", "/bin/false"),
                    ("commit.gpgsign", "false"),
                    ("tag.gpgsign", "false"),
                    ("gpg.program", "/bin/false"),
                    ("gpg.openpgp.program", "/bin/false"),
                    ("gpg.ssh.program", "/bin/false"),
                    ("gpg.x509.program", "/bin/false"),
                    ("protocol.ext.allow", "never"),
                    (
                        "core.sshCommand",
                        "/usr/bin/ssh -F /dev/null -oBatchMode=yes -oProxyCommand=none "
                        "-oProxyJump=none -oControlMaster=no -oControlPath=none "
                        "-oControlPersist=no -oForwardAgent=no -oForwardX11=no "
                        "-oPermitLocalCommand=no -oClearAllForwardings=yes "
                        "-oUpdateHostKeys=no -oKnownHostsCommand=none "
                        "-oUserKnownHostsFile=~/.ssh/known_hosts "
                        "-oStrictHostKeyChecking=yes",
                    ),
                    ("core.askPass", "/bin/false"),
                    ("credential.helper", ""),
                    ("http.proxy", ""),
                    ("http.sslVerify", "true"),
                    ("http.sslCAInfo", "/etc/ssl/certs/ca-certificates.crt"),
                    ("http.sslCAPath", "/etc/ssl/certs"),
                )
                self.assertEqual(
                    environment["GIT_CONFIG_COUNT"], str(len(expected_overrides))
                )
                actual_overrides = tuple(
                    (
                        environment[f"GIT_CONFIG_KEY_{index}"],
                        environment[f"GIT_CONFIG_VALUE_{index}"],
                    )
                    for index in range(len(expected_overrides))
                )
                self.assertEqual(actual_overrides, expected_overrides)
                for key, expected in (
                    ("GIT_ALLOW_PROTOCOL", "ssh:file"),
                    ("GIT_NO_REPLACE_OBJECTS", "1"),
                    ("GIT_GRAFT_FILE", "/dev/null/grabowski-disabled-grafts"),
                    ("GIT_SSL_CAINFO", "/etc/ssl/certs/ca-certificates.crt"),
                    ("GIT_SSL_CAPATH", "/etc/ssl/certs"),
                ):
                    self.assertEqual(environment[key], expected)
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


if __name__ == "__main__":
    unittest.main()
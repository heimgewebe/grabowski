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
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "ssh:file")
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
                "#!/bin/sh\n: > " + shlex.quote(str(marker))
                + "\nprintf 'attacker git\n'\n",
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

    def _two_commit_repo(self, repo: Path, environment: dict[str, str]) -> tuple[str, str]:
        subprocess.run(
            ["git", "init", "-q", "-b", "main", str(repo)],
            env=environment, check=True, capture_output=True, timeout=15,
        )
        tracked = repo / "tracked.txt"
        for index in (1, 2):
            tracked.write_text(str(index), encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repo), "add", "tracked.txt"],
                env=environment, check=True, capture_output=True, timeout=15,
            )
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                 "-c", "user.email=safe@example.invalid", "commit", "-qm", str(index)],
                env=environment, check=True, capture_output=True, timeout=15,
            )
        head = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            env=environment, timeout=15, text=True,
        ).strip()
        parent = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD^"],
            env=environment, timeout=15, text=True,
        ).strip()
        return head, parent

    def test_replace_ref_cannot_rewrite_source_commit_parents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="safe-git-replace-") as temporary:
            repo = Path(temporary) / "repo"
            secure = safe_git_environment()
            head, parent = self._two_commit_repo(repo, secure)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                 "-c", "user.email=safe@example.invalid", "replace", "--graft", "HEAD"],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            actual = subprocess.run(
                ["git", "-C", str(repo), "rev-list", "--parents", "-1", "HEAD"],
                env=secure, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertEqual(actual.stdout.split(), [head, parent])

    def test_graft_file_cannot_rewrite_source_commit_parents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="safe-git-graft-") as temporary:
            repo = Path(temporary) / "repo"
            secure = safe_git_environment()
            head, parent = self._two_commit_repo(repo, secure)
            (repo / ".git" / "info" / "grafts").write_text(head + "\n", encoding="ascii")
            actual = subprocess.run(
                ["git", "-C", str(repo), "rev-list", "--parents", "-1", "HEAD"],
                env=secure, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertEqual(actual.stdout.split(), [head, parent])
            self.assertFalse(actual.stderr, actual.stderr)

    def test_https_system_ca_cannot_be_replaced_from_repository_config(self) -> None:
        # SSL trust must be fixed at libcurl effect time, even when a
        # URL-specific local Git config has a different CA bundle.
        import http.server
        import shutil
        import socket
        import ssl
        import threading

        if not shutil.which("openssl"):
            self.skipTest("openssl unavailable for loopback adversarial TLS fixture")
        with tempfile.TemporaryDirectory(prefix="safe-git-tls-") as temporary:
            root = Path(temporary)
            cert, key = root / "rogue.crt", root / "rogue.key"
            generate = subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "1", "-keyout", str(key), "-out", str(cert),
                 "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                capture_output=True, timeout=20,
            )
            self.assertEqual(generate.returncode, 0, generate.stderr.decode(errors="replace"))
            observed = threading.Event()

            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    observed.set()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok\n")
                def log_message(self, *_: object) -> None:
                    pass

            try:
                server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            except OSError as exc:
                self.skipTest(f"loopback TLS unavailable: {exc}")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert), str(key))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.timeout = 12
            worker = threading.Thread(target=lambda: _accept_tls_once(server), daemon=True)

            def configure_repo() -> Path:
                checkout = root / "repo"
                subprocess.run(
                    ["git", "init", "-q", str(checkout)],
                    env=safe_git_environment(), check=True,
                    capture_output=True, timeout=15,
                )
                url = f"https://localhost:{server.server_port}/repo.git"
                subprocess.run(
                    ["git", "-C", str(checkout), "config",
                     f"http.{url}.sslCAInfo", str(cert)],
                    env=safe_git_environment(), check=True,
                    capture_output=True, timeout=15,
                )
                subprocess.run(
                    ["git", "-C", str(checkout), "config",
                     f"http.{url}.sslVerify", "false"],
                    env=safe_git_environment(), check=True,
                    capture_output=True, timeout=15,
                )
                return checkout, url

            def _accept_tls_once(srv: http.server.HTTPServer) -> None:
                try:
                    srv.handle_request()
                except ssl.SSLError:
                    pass

            try:
                checkout, url = configure_repo()
                worker.start()
                actual = subprocess.run(
                    ["git", "-C", str(checkout), "ls-remote", url, "HEAD"],
                    env=safe_git_environment(), text=True, capture_output=True,
                    timeout=12,
                )
                self.assertNotEqual(actual.returncode, 0)
                self.assertIn("transport 'https' not allowed", actual.stderr)
                self.assertFalse(observed.is_set(), "repository CA override reached rogue HTTPS endpoint")
            finally:
                server.server_close()

    def test_ssh_config_is_effectively_pinned_without_disabling_github_identity(self) -> None:
        command = shlex.split(safe_git_environment()["GIT_SSH_COMMAND"])
        actual = subprocess.run(
            [*command, "-G", "git@github.com"],
            env=safe_git_environment(), text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(actual.returncode, 0, actual.stderr)
        settings = dict(
            line.split(" ", 1)
            for line in actual.stdout.splitlines()
            if " " in line
        )
        for option in ("-oProxyJump=none", "-oControlPath=none"):
            self.assertIn(option, command)
        for key, expected in (
            ("proxyjump", "none"),
            ("controlpath", "none"),
            ("controlmaster", "false"),
            ("updatehostkeys", "false"),
            ("forwardagent", "no"),
            ("forwardx11", "no"),
        ):
            self.assertEqual(settings.get(key, "none"), expected, f"{key}={settings.get(key)}")
        self.assertEqual(
            settings.get("userknownhostsfile"),
            str(Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".ssh" / "known_hosts"),
        )


    def test_repository_git_diff_helper_is_not_executed_by_review_diff(self) -> None:
        # A working adversarial helper must execute in the negative control,
        # but never along the production review's --no-ext-diff boundary.
        from grabowski_agent_role import git as review_git

        with tempfile.TemporaryDirectory(prefix="review-git-helper-") as temporary:
            root = Path(temporary)
            repo = root / "repo"
            safe = safe_git_environment()
            subprocess.run(
                ["git", "init", "-q", "-b", "main", str(repo)],
                env=safe, check=True, capture_output=True, timeout=15,
            )
            (repo / ".gitattributes").write_text(
                "tracked.txt diff=attacker\n", encoding="ascii",
            )
            tracked = repo / "tracked.txt"
            tracked.write_text("before\n", encoding="ascii")
            subprocess.run(["git", "-C", str(repo), "add", "."],
                           env=safe, check=True, capture_output=True, timeout=15)
            identity = ["-c", "user.name=Safe Test", "-c", "user.email=safe@example.invalid"]
            subprocess.run(["git", "-C", str(repo), *identity, "commit", "-qm", "before"],
                           env=safe, check=True, capture_output=True, timeout=15)
            tracked.write_text("after\n", encoding="ascii")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"],
                           env=safe, check=True, capture_output=True, timeout=15)
            subprocess.run(["git", "-C", str(repo), *identity, "commit", "-qm", "after"],
                           env=safe, check=True, capture_output=True, timeout=15)
            marker = root / "malicious-helper-ran"
            helper = root / "malicious-helper"
            helper.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\n",
                              encoding="utf-8")
            helper.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(repo), "config", "diff.attacker.command", str(helper)],
                env=safe, check=True, capture_output=True, timeout=15,
            )
            uncontrolled = subprocess.run(
                ["git", "-C", str(repo), "diff", "HEAD^", "HEAD", "--", "tracked.txt"],
                env=safe, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "adversarial helper must really execute")
            marker.unlink()
            with self.assertRaises(RuntimeError):
                review_git(
                    repo, "diff", "--binary", "--no-ext-diff",
                    "--no-textconv", "HEAD^", "HEAD", "--", "tracked.txt",
                )
            self.assertFalse(marker.exists(), "review diff executed repository helper")

    def test_repository_ssh_helper_is_not_executed_at_transport_effect(self) -> None:
        with tempfile.TemporaryDirectory(prefix="review-git-ssh-helper-") as temporary:
            root = Path(temporary)
            repo = root / "repo"
            secure = safe_git_environment()
            subprocess.run(
                ["git", "init", "-q", str(repo)], env=secure,
                check=True, capture_output=True, timeout=15,
            )
            marker = root / "attacker-ssh-was-executed"
            helper = root / "attacker-ssh"
            helper.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker))
                              + "\nexit 1\n", encoding="utf-8")
            helper.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(repo), "config", "core.sshCommand", str(helper)],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            inherited = dict(os.environ)
            inherited.update({
                "GIT_SSH_COMMAND": str(helper),
                "GIT_SSH": str(helper),
                "SSH_ASKPASS": str(helper),
                "SSH_AUTH_SOCK": str(root / "attacker-agent.sock"),
                "HOME": str(root),
                "PATH": str(root) + ":/usr/bin:/bin",
                "LD_PRELOAD": str(root / "attacker-loader.so"),
            })
            actual = subprocess.run(
                ["git", "-C", str(repo), "ls-remote",
                 "ssh://git@127.0.0.1:1/repo.git", "HEAD"],
                env=safe_git_environment(inherited),
                text=True, capture_output=True, timeout=15,
            )
            self.assertNotEqual(actual.returncode, 0)
            self.assertFalse(marker.exists(),
                             "repo or inherited SSH helper executed at transport effect")

    def test_dirty_review_diff_rejects_repository_clean_filter_before_spawn(self) -> None:
        from grabowski_agent_role import git as review_git

        with tempfile.TemporaryDirectory(prefix="review-git-clean-filter-") as temporary:
            root = Path(temporary)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=attacker\n", encoding="ascii",
            )
            marker = root / "attacker-filter-was-executed"
            helper = root / "attacker-filter"
            helper.write_text("#!/bin/sh\n: > " + shlex.quote(str(marker))
                              + "\ncat\n", encoding="utf-8")
            helper.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(repo), "config", "filter.attacker.clean", str(helper)],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            (repo / "tracked.txt").write_text("dirty mutation\n", encoding="ascii")
            with self.assertRaises(RuntimeError):
                review_git(repo, "diff", "--binary", "--no-ext-diff",
                           "--no-textconv", "HEAD")
            self.assertFalse(marker.exists(), "review executed local clean filter")

    def test_workspace_host_git_rejects_repo_filter_before_add_effect(self) -> None:
        from grabowski_agent_workspace import _run as workspace_run

        with tempfile.TemporaryDirectory(prefix="workspace-git-filter-") as temporary:
            root = Path(temporary)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=attacker\n", encoding="ascii",
            )
            subprocess.run(
                ["git", "-C", str(repo), "add", ".gitattributes"],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                 "-c", "user.email=safe@example.invalid",
                 "commit", "-qm", "tracked attributes"],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            marker = root / "workspace-filter-executed"
            helper = root / "workspace-filter"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(repo), "config",
                 "filter.attacker.clean", str(helper)],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            (repo / "tracked.txt").write_text("dirty\n", encoding="ascii")
            uncontrolled = subprocess.run(
                ["git", "-C", str(repo), "add", "--", "tracked.txt"],
                env=secure, capture_output=True, timeout=15,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "clean-filter negative control did not execute")
            marker.unlink()
            with self.assertRaises(RuntimeError):
                workspace_run(repo, ["git", "add", "--", "tracked.txt"])
            self.assertFalse(marker.exists(), "workspace host Git executed local filter")

    def test_workspace_host_git_add_is_forbidden_even_without_filter_config(self) -> None:
        from grabowski_agent_workspace import _run as workspace_run

        with tempfile.TemporaryDirectory(prefix="workspace-git-add-deny-") as raw:
            repo = Path(raw) / "repo"
            self._two_commit_repo(repo, safe_git_environment())
            (repo / "tracked.txt").write_text("later mutation\n", encoding="ascii")
            for command in (
                ["git", "add", "--", "tracked.txt"],
                ["git", "--literal-pathspecs", "add", "--all", "--", "tracked.txt"],
                ["git", "-c", "core.hooksPath=/dev/null", "add", "tracked.txt"],
            ):
                with self.subTest(command=command):
                    with self.assertRaisesRegex(RuntimeError, "host Git add is forbidden"):
                        workspace_run(repo, command)

    def test_cached_candidate_style_git_apply_never_runs_clean_filter(self) -> None:
        # Effect-bound contrast: git apply --cached stages the exact patch but
        # git add in the same repository executes the configured clean filter.
        with tempfile.TemporaryDirectory(prefix="workspace-cached-apply-") as raw:
            root = Path(raw)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".gitattributes").write_text("tracked.txt filter=attacker\n", encoding="ascii")
            subprocess.run(
                ["git", "-C", str(repo), "add", ".gitattributes"],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                 "-c", "user.email=safe@example.invalid",
                 "commit", "-qm", "attributes"],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            (repo / "tracked.txt").write_text("after\n", encoding="ascii")
            patch = subprocess.check_output(
                ["git", "-C", str(repo), "diff", "--binary", "--no-ext-diff",
                 "--no-textconv", "HEAD"],
                env=secure, timeout=15,
            )
            marker = root / "filter-executed"
            helper = root / "clean-filter"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(repo), "config", "filter.attacker.clean", str(helper)],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            applied = subprocess.run(
                ["git", "-C", str(repo), "apply", "--cached", "--binary",
                 "--whitespace=nowarn", "-"],
                input=patch, env=secure, capture_output=True, timeout=15,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            staged = subprocess.check_output(
                ["git", "-C", str(repo), "show", ":tracked.txt"],
                env=secure, timeout=15,
            )
            self.assertEqual(staged, b"after\n")
            self.assertFalse(marker.exists(), "cached patch staging ran clean filter")
            uncontrolled = subprocess.run(
                ["git", "-C", str(repo), "add", "--", "tracked.txt"],
                env=secure, capture_output=True, timeout=15,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "Git add negative control did not execute")

    def test_workspace_host_git_rejects_external_diff_helper_before_spawn(self) -> None:
        from grabowski_agent_workspace import _run as workspace_run

        with tempfile.TemporaryDirectory(prefix="workspace-external-diff-") as temporary:
            root = Path(temporary)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            marker = root / "external-diff-executed"
            helper = root / "external-diff"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 0\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(repo), "config", "diff.external", str(helper)],
                env=secure, check=True, capture_output=True, timeout=15,
            )
            (repo / "tracked.txt").write_text("dirty\n", encoding="ascii")
            uncontrolled = subprocess.run(
                ["git", "-C", str(repo), "diff", "HEAD"],
                env=secure, capture_output=True, timeout=15,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "external diff negative control did not execute")
            marker.unlink()
            with self.assertRaises(RuntimeError):
                workspace_run(repo, ["git", "diff", "HEAD"])
            self.assertFalse(marker.exists(), "workspace host Git executed repository diff.external")


    def test_workspace_diff_remains_helper_free_when_config_changes_at_spawn(self) -> None:
        # Reproduce the check/spawn race deterministically without relying on
        # a timer. The injected helper must not execute in the protected path.
        from unittest import mock
        from grabowski_agent_workspace import _run as workspace_run

        with tempfile.TemporaryDirectory(prefix="workspace-diff-race-") as temporary:
            root = Path(temporary)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / "tracked.txt").write_text("dirty mutation\n", encoding="ascii")
            marker = root / "late-external-diff-executed"
            helper = root / "late-external-diff"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 0\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
            real_run = subprocess.run
            injected = False

            def inject_after_admission(argv: list[str], *args: object, **kwargs: object):
                nonlocal injected
                if not injected and (argv[:2] == ["git", "diff"] or
                                     (argv[:1] == ["/usr/bin/bwrap"] and "diff" in argv)):
                    injected = True
                    real_run(
                        ["git", "-C", str(repo), "config", "diff.external", str(helper)],
                        env=secure, check=True, capture_output=True, timeout=15,
                    )
                return real_run(argv, *args, **kwargs)

            with mock.patch("subprocess.run", side_effect=inject_after_admission):
                protected = workspace_run(repo, ["git", "diff", "HEAD"])
            self.assertTrue(injected, "the adversarial race was not exercised")
            self.assertEqual(protected["returncode"], 0, protected["stderr"])
            self.assertIn("diff --git", protected["stdout"])
            self.assertFalse(marker.exists(), "late diff.external helper executed")
            uncontrolled = real_run(
                ["git", "-C", str(repo), "diff", "HEAD"],
                env=secure, capture_output=True, timeout=15,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "negative control did not run helper")



    def test_dirty_diff_remains_filter_free_after_late_config_injection(self) -> None:
        """An executable clean filter added after admission must never run."""
        from unittest import mock
        from grabowski_agent_workspace import _run as workspace_run

        with tempfile.TemporaryDirectory(prefix="workspace-late-clean-") as raw:
            root = Path(raw)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=attacker\n", encoding="ascii",
            )
            subprocess.run(
                ["git", "-C", str(repo), "add", ".gitattributes"],
                env=secure, check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                 "-c", "user.email=safe@example.invalid",
                 "commit", "-qm", "selected filter"],
                env=secure, check=True, capture_output=True,
            )
            (repo / "tracked.txt").write_text("dirty after commit\n", encoding="ascii")
            marker = root / "clean-marker"
            helper = root / "clean-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            real_run = subprocess.run
            injected = False

            def inject_before_git_effect(argv: list[str], *args: object, **kwargs: object):
                nonlocal injected
                if not injected and argv and argv[0] in ("git", "/usr/bin/bwrap") and "diff" in argv:
                    injected = True
                    real_run(
                        ["/usr/bin/git", "-C", str(repo),
                         "config", "filter.attacker.clean", str(helper)],
                        env=secure, check=True, capture_output=True,
                    )
                return real_run(argv, *args, **kwargs)

            with mock.patch("subprocess.run", side_effect=inject_before_git_effect):
                result = workspace_run(repo, ["git", "diff", "--binary", "HEAD"])
            self.assertTrue(injected, "the post-admission config mutation was missed")
            self.assertEqual(result["returncode"], 0, result["stderr"])
            self.assertIn("+dirty after commit", result["stdout"])
            self.assertFalse(marker.exists(), "dirty Git diff ran an injected clean filter")

    def test_native_worktree_creation_remains_filter_free_after_late_injection(self) -> None:
        """The native WorkAcquire runner must materialize files without smudge code."""
        from unittest import mock
        import grabowski_work_acquire as work_acquire

        with tempfile.TemporaryDirectory(prefix="lane-late-smudge-") as raw:
            root = Path(raw)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=attacker\n", encoding="ascii",
            )
            subprocess.run(
                ["git", "-C", str(repo), "add", ".gitattributes"],
                env=secure, check=True, capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                 "-c", "user.email=safe@example.invalid",
                 "commit", "-qm", "selected filter"],
                env=secure, check=True, capture_output=True,
            )
            marker = root / "smudge-marker"
            helper = root / "smudge-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            real_operator_run = work_acquire.operator._run
            injected = False

            def inject_before_checkout(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "worktree" in argv and "add" in argv:
                    injected = True
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo),
                         "config", "filter.attacker.smudge", str(helper)],
                        env=secure, check=True, capture_output=True,
                    )
                return real_operator_run(argv, **kwargs)

            checkout = root / "writer"
            with mock.patch.object(work_acquire.operator, "_run", side_effect=inject_before_checkout):
                result = work_acquire._git_runner(
                    repo, ["worktree", "add", "-b", "safe",
                           str(checkout), "HEAD"],
                )
            self.assertTrue(injected, "the post-admission config mutation was missed")
            self.assertEqual(result["returncode"], 0, result["stderr"])
            self.assertTrue((checkout / "tracked.txt").is_file())
            self.assertFalse(marker.exists(), "native worktree checkout ran an injected smudge filter")



    def test_role_and_writer_dirty_diff_reject_late_clean_filter_helper(self) -> None:
        """Both actual host Git diff readers must bind filter denial at Git effect."""
        from unittest import mock
        import grabowski_agent_role as role
        import grabowski_agent_writer as writer

        for label, reader in (
            ("reviewer", lambda repo: role.git(
                repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD",
            )),
            ("writer", lambda repo: writer._git_bytes(
                repo, "diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD",
            )),
        ):
            with self.subTest(reader=label), tempfile.TemporaryDirectory(
                prefix=f"late-clean-{label}-"
            ) as temporary:
                root = Path(temporary)
                repo = root / "repo"
                secure = safe_git_environment()
                self._two_commit_repo(repo, secure)
                (repo / ".gitattributes").write_text(
                    "tracked.txt filter=attacker\n", encoding="ascii",
                )
                subprocess.run(
                    ["git", "-C", str(repo), "add", ".gitattributes"],
                    env=secure, check=True, capture_output=True, timeout=15,
                )
                subprocess.run(
                    ["git", "-C", str(repo), "-c", "user.name=Safe Test",
                     "-c", "user.email=safe@example.invalid", "commit", "-qm",
                     "tracked filter selection"],
                    env=secure, check=True, capture_output=True, timeout=15,
                )
                (repo / "tracked.txt").write_text(
                    "dirty reviewer/writer\n", encoding="ascii",
                )
                marker = root / "executed-clean-filter"
                helper = root / "clean-filter"
                helper.write_text(
                    "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                    encoding="ascii",
                )
                helper.chmod(0o700)
                real_run = subprocess.run
                injected = False

                def inject_at_effect(argv: list[str], *args: object, **kwargs: object):
                    nonlocal injected
                    if not injected and argv[:1] == ["/usr/bin/bwrap"] and "diff" in argv:
                        injected = True
                        real_run(
                            ["/usr/bin/git", "-C", str(repo), "config",
                             "filter.attacker.clean", str(helper)],
                            env=secure, check=True, capture_output=True, timeout=15,
                        )
                    return real_run(argv, *args, **kwargs)

                with mock.patch("subprocess.run", side_effect=inject_at_effect):
                    diff = reader(repo)
                self.assertTrue(injected, f"{label} did not reach a protected Git effect")
                self.assertIn(b"+dirty reviewer/writer", diff)
                self.assertFalse(marker.exists(), f"{label} ran late clean filter")
                uncontrolled = real_run(
                    ["/usr/bin/git", "-C", str(repo), "diff", "--binary", "HEAD"],
                    env=secure, capture_output=True, timeout=15,
                )
                self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
                self.assertTrue(marker.exists(), f"{label} negative control missed filter")



    def test_dirty_diff_pathspec_named_cached_cannot_disable_filter_guard(self) -> None:
        from grabowski_agent_sandbox import git_requires_filter_effect_guard

        for dangerous_pathspec in ("--cached", "--staged", "--no-index"):
            with self.subTest(path=dangerous_pathspec):
                self.assertTrue(
                    git_requires_filter_effect_guard(
                        ["git", "diff", "HEAD", "--", dangerous_pathspec]
                    ),
                    "Git option-like pathspec must not suppress dirty-diff effect guard",
                )
        self.assertFalse(
            git_requires_filter_effect_guard(["git", "diff", "--cached", "HEAD"])
        )



    def test_native_work_acquire_git_diff_blocks_late_external_driver(self) -> None:
        """Native host Git must preserve committed patch bytes without executing a helper."""
        from unittest import mock
        import grabowski_work_acquire as work_acquire

        with tempfile.TemporaryDirectory(prefix="work-acquire-late-diff-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            head, parent = self._two_commit_repo(repo, secure)
            marker, helper = root / "executed", root / "external-driver"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 0\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            original_run = work_acquire.operator._run
            injected = False

            def inject_before_effect(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "diff" in argv:
                    injected = True
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo), "config",
                         "diff.external", str(helper)],
                        env=secure, check=True, capture_output=True,
                    )
                return original_run(argv, **kwargs)

            with mock.patch.object(
                work_acquire.operator, "_run", side_effect=inject_before_effect,
            ):
                result = work_acquire._git_runner(repo, ["diff", parent, head])
            self.assertTrue(injected, "late native Git diff configuration race not tested")
            self.assertEqual(result["returncode"], 0, result["stderr"])
            self.assertIn("diff --git", result["stdout"])
            self.assertFalse(marker.exists(), "native WorkAcquire Git executed late diff helper")
            uncontrolled = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "diff", parent, head],
                capture_output=True, env=secure, check=False,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "late external diff negative control missed")



    def test_merge_driver_inserted_after_admission_stays_inert(self) -> None:
        """A late repository-configured merge driver must not run."""
        from grabowski_agent_sandbox import safe_git_filter_effect

        with tempfile.TemporaryDirectory(prefix="late-merge-driver-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            subprocess.run(["/usr/bin/git", "init", "-q", "-b", "main", str(repo)],
                           env=secure, check=True)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            for key, value in (("user.name", "Safe Test"),
                               ("user.email", "safe@example.invalid")):
                subprocess.run(["/usr/bin/git", "-C", str(repo), "config", key, value],
                               env=secure, check=True)
            tracked = repo / "tracked"
            tracked.write_text("base\n", encoding="ascii")
            (repo / ".gitattributes").write_text("tracked merge=attacker\n", encoding="ascii")
            subprocess.run(["/usr/bin/git", "-C", str(repo), "add",
                            "tracked", ".gitattributes"], env=secure, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(repo), "commit", "-qm", "base"],
                           env=secure, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(repo), "checkout", "-qb", "feature"],
                           env=secure, check=True)
            tracked.write_text("feature\n", encoding="ascii")
            subprocess.run(["/usr/bin/git", "-C", str(repo), "commit", "-qam", "feature"],
                           env=secure, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(repo), "checkout", "-q", "main"],
                           env=secure, check=True)
            tracked.write_text("main\n", encoding="ascii")
            subprocess.run(["/usr/bin/git", "-C", str(repo), "commit", "-qam", "main"],
                           env=secure, check=True)
            marker, helper = root / "helper-ran", root / "merge-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) +
                '\nprintf "MALICIOUS\\n" > "$2"\nexit 0\n', encoding="ascii",
            )
            helper.chmod(0o700)
            with safe_git_filter_effect(
                repo, ["git", "-C", str(repo), "merge", "feature"]
            ) as (command, environment, fds):
                subprocess.run(
                    ["/usr/bin/git", "-C", str(repo), "config",
                     "merge.attacker.driver", f"{helper} %O %A %B"],
                    env=secure, check=True,
                )
                guarded = subprocess.run(
                    command, env=environment, pass_fds=fds,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
            self.assertEqual(guarded.returncode, 1, guarded.stderr)
            self.assertIn("<<<<<<< HEAD", tracked.read_text(encoding="ascii"))
            self.assertFalse(marker.exists(), "late merge driver executed")
            subprocess.run(["/usr/bin/git", "-C", str(repo), "merge", "--abort"],
                           env=secure, check=True, capture_output=True)
            uncontrolled = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "merge", "feature"],
                env=secure, capture_output=True,
            )
            self.assertEqual(uncontrolled.returncode, 0, uncontrolled.stderr)
            self.assertTrue(marker.exists(), "unprotected merge control missed")



    def test_two_oid_diff_custom_command_cannot_run_at_effect_time(self) -> None:
        """A committed Git diff must preserve a patch but never run a late driver."""
        from unittest import mock
        import grabowski_work_acquire as work_acquire

        with tempfile.TemporaryDirectory(prefix="two-oid-diff-driver-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            head, parent = self._two_commit_repo(repo, secure)
            (repo / ".gitattributes").write_text(
                "tracked.txt diff=attacker\n", encoding="ascii",
            )
            subprocess.run(["/usr/bin/git", "-C", str(repo), "add", ".gitattributes"],
                           env=secure, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(repo), "-c", "user.name=Safe Test",
                            "-c", "user.email=safe@example.invalid",
                            "commit", "-qm", "attribute driver"], env=secure, check=True)
            head = subprocess.check_output(
                ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
                env=secure, text=True,
            ).strip()
            marker, helper = root / "external-command-ran", root / "custom-diff"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 0\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            original_run = work_acquire.operator._run
            injected = False

            def inject_at_git_effect(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "diff" in argv:
                    injected = True
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo), "config",
                         "diff.attacker.command", str(helper)],
                        env=secure, check=True,
                    )
                return original_run(argv, **kwargs)

            with mock.patch.object(work_acquire.operator, "_run",
                                   side_effect=inject_at_git_effect):
                result = work_acquire._git_runner(repo, ["diff", parent, head])
            self.assertTrue(injected)
            self.assertEqual(result["returncode"], 0, result["stderr"])
            self.assertIn("diff --git", result["stdout"])
            self.assertFalse(marker.exists(), "two-object Git diff ran custom driver")
            plain = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "diff", parent, head],
                env=secure, capture_output=True,
            )
            self.assertEqual(plain.returncode, 0, plain.stderr)
            self.assertTrue(marker.exists(), "negative control failed to execute driver")



    def test_actual_builtin_git_commands_ignore_shell_aliases(self) -> None:
        """Git builtins cannot be shadowed by repository alias.<builtin>=!cmd."""
        with tempfile.TemporaryDirectory(prefix="native-git-alias-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            marker, helper = root / "alias-marker", root / "alias-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 0\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            for sub, args in (
                ("config", ("--list",)),
                ("status", ("--short",)),
                ("diff", ("HEAD",)),
                ("add", ("--", "tracked.txt")),
                ("rev-parse", ("HEAD",)),
            ):
                with self.subTest(builtin=sub):
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo), "config",
                         "alias." + sub, "!" + str(helper)],
                        env=secure, check=True,
                    )
                    actual = subprocess.run(
                        ["/usr/bin/git", "-C", str(repo), sub, *args],
                        env=secure, capture_output=True,
                    )
                    self.assertEqual(actual.returncode, 0, actual.stderr)
                    self.assertFalse(marker.exists(), "Git builtin was shadowed by alias")

    def test_guard_classifies_actual_worktree_git_effects(self) -> None:
        from grabowski_agent_sandbox import git_requires_filter_effect_guard

        for args in (
            ("status", "--short"),
            ("diff-files", "--quiet", "--"),
            ("diff-index", "--quiet", "HEAD", "--"),
            ("update-index", "--refresh"),
            ("checkout-index", "-a"),
            ("commit", "-am", "message"),
            ("hash-object", "--path=tracked.txt", "tracked.txt"),
            ("cherry-pick", "HEAD"),
            ("revert", "HEAD"),
            ("am", "-3"),
        ):
            with self.subTest(arguments=args):
                self.assertTrue(
                    git_requires_filter_effect_guard(["git", "-C", "/repo", *args]),
                    "untrusted Git worktree operation skipped executable-filter isolation",
                )

    def test_native_grabowski_git_commit_all_blocks_late_clean_filter(self) -> None:
        """Real branch-attempt commit -a must not run injected clean helper."""
        from unittest import mock
        import grabowski_operator as operator
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory(prefix="native-cas-commit-all-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            for key, value in (("user.name", "Test"),
                               ("user.email", "test@example.invalid")):
                subprocess.run(["/usr/bin/git", "-C", str(repo), "config", key, value],
                               check=True, env=secure)
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=attacker\n", encoding="ascii",
            )
            subprocess.run(["/usr/bin/git", "-C", str(repo), "add", ".gitattributes"],
                           env=secure, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(repo), "commit",
                            "-qm", "attributes"], env=secure, check=True)
            (repo / "tracked.txt").write_text("after\n", encoding="ascii")
            marker, helper = root / "clean-ran", root / "clean-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            original_run = operator._run
            injected = False

            def late_config(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "commit" in argv:
                    injected = True
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo),
                         "config", "filter.attacker.clean", str(helper)],
                        check=True, env=secure,
                    )
                return original_run(argv, **kwargs)

            attempt = {
                "schema_version": 1,
                "owner_id": "operator:commit-all-security",
                "operation_id": "late-filter",
                "attempt_id": "commit-1",
                "branch": "main",
                "expected_preimage_sha256": operator._git_branch_preimage(repo)[
                    "preimage_sha256"
                ],
            }
            with (
                mock.patch.object(resources, "RESOURCE_DB", root / "resources.sqlite3"),
                mock.patch.object(operator, "_require_operator_mutation", return_value=None),
                mock.patch.object(operator, "_append_effect_audit", return_value="a" * 64),
                mock.patch.object(operator, "_run", side_effect=late_config),
            ):
                result = operator.grabowski_git(
                    str(repo), ["commit", "-am", "commit-all"], branch_attempt=attempt,
                )
            self.assertTrue(injected)
            self.assertEqual(result["returncode"], 0, result.get("stderr"))
            self.assertEqual(result["branch_mutation"]["status"], "completed")
            self.assertFalse(marker.exists(), "native commit -a ran injected clean helper")
            self.assertEqual(
                subprocess.check_output(
                    ["/usr/bin/git", "-C", str(repo), "show", "HEAD:tracked.txt"]
                ), b"after\n"
            )
            (repo / "tracked.txt").write_text("unprotected-control\n", encoding="ascii")
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "commit", "-am", "unprotected"],
                check=True, env=secure, capture_output=True,
            )
            self.assertTrue(marker.exists(), "unprotected commit -a never ran clean filter")

    def test_native_grabowski_git_dirty_diff_blocks_late_clean_filter(self) -> None:
        """The public Git read must not bypass the shared effect-bound guard."""
        from unittest import mock
        import grabowski_operator as operator

        with tempfile.TemporaryDirectory(prefix="native-dirty-diff-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            (repo / ".gitattributes").write_text(
                "tracked.txt filter=attacker\n", encoding="ascii",
            )
            subprocess.run(["/usr/bin/git", "-C", str(repo), "add", ".gitattributes"],
                           env=secure, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(repo),
                            "-c", "user.name=Safe Test", "-c",
                            "user.email=safe@example.invalid",
                            "commit", "-qm", "attributes"],
                           env=secure, check=True)
            (repo / "tracked.txt").write_text("dirty\n", encoding="ascii")
            marker, helper = root / "clean-ran", root / "clean-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            real_run = operator._run
            injected = False

            def late_config(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "diff" in argv:
                    injected = True
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo),
                         "config", "filter.attacker.clean", str(helper)],
                        check=True, env=secure,
                    )
                return real_run(argv, **kwargs)

            with (
                mock.patch.object(operator, "_require_operator_mutation", return_value=None),
                mock.patch.object(operator, "_run", side_effect=late_config),
            ):
                actual = operator.grabowski_git(str(repo), ["diff", "HEAD"])
            self.assertTrue(injected)
            self.assertEqual(actual["returncode"], 0, actual.get("stderr"))
            self.assertIn("+dirty", actual["stdout"])
            self.assertFalse(marker.exists(), "public native Git dirty diff ran filter")
            unprotected = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "diff", "HEAD"],
                env=secure, capture_output=True,
            )
            self.assertEqual(unprotected.returncode, 0, unprotected.stderr)
            self.assertTrue(marker.exists(), "unprotected diff control missed helper")


    def test_native_cat_file_filters_blocks_late_smudge_helper(self) -> None:
        """cat-file --filters is a real executable-filter effect, not an inert blob read."""
        from unittest import mock
        import grabowski_operator as operator

        with tempfile.TemporaryDirectory(prefix="native-cat-filters-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            (repo / ".gitattributes").write_text("tracked.txt filter=attacker\n")
            subprocess.run(["/usr/bin/git", "-C", str(repo), "add", ".gitattributes"],
                           env=secure, check=True)
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo),
                 "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "attributes"],
                env=secure, check=True,
            )
            marker, helper = root / "smudge-ran", root / "smudge-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            original_run = operator._run
            injected = False

            def inject_after_admission(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected:
                    injected = True
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo), "config",
                         "filter.attacker.smudge", str(helper)],
                        env=secure, check=True,
                    )
                return original_run(argv, **kwargs)

            # Git 2.55 has both --filter and --filters: --filte is ambiguous.
            for filter_option in ("--filters",):
                with self.subTest(filter_option=filter_option):
                    injected = False
                    marker.unlink(missing_ok=True)
                    with (
                        mock.patch.object(operator, "_require_operator_mutation", return_value=None),
                        mock.patch.object(operator, "_run", side_effect=inject_after_admission),
                    ):
                        result = operator.grabowski_git(
                            str(repo), ["cat-file", filter_option,
                                        "--path=tracked.txt", "HEAD:tracked.txt"]
                        )
                    self.assertTrue(injected, "test missed post-admission helper injection")
                    self.assertEqual(result["returncode"], 0, result.get("stderr"))
                    self.assertFalse(marker.exists(), "native cat-file smudge helper ran")
                    subprocess.run(
                        ["/usr/bin/git", "-C", str(repo), "config",
                         "--unset", "filter.attacker.smudge"],
                        env=secure, check=True,
                    )

    def test_native_git_rejects_helper_reenable_options_before_effect(self) -> None:
        """User-supplied --ext-diff/--textconv must not defeat earlier --no-*."""
        from unittest import mock
        import grabowski_operator as operator
        from grabowski_agent_sandbox import AgentSandboxError

        with tempfile.TemporaryDirectory(prefix="native-diff-override-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            (repo / "tracked.txt").write_text("dirty\n", encoding="ascii")
            (repo / ".gitattributes").write_text("tracked.txt diff=attacker\n")
            marker, helper = root / "helper-ran", root / "helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            attacks = (
                ["-c", f"diff.external={helper}", "diff", "--ext-diff", "HEAD"],
                ["-c", f"diff.attacker.textconv={helper}", "diff", "--textconv", "HEAD"],
                ["-c", f"diff.attacker.textconv={helper}", "blame",
                 "--textconv", "HEAD", "--", "tracked.txt"],
                ["-c", f"diff.attacker.textconv={helper}", "cat-file",
                 "--textconv", "--path=tracked.txt", "HEAD:tracked.txt"],
                ["-c", f"diff.attacker.textconv={helper}", "cat-file",
                 "--textc", "--path=tracked.txt", "HEAD:tracked.txt"],
                ["-c", f"diff.attacker.textconv={helper}", "annotate",
                 "--textconv", "HEAD", "--", "tracked.txt"],
                ["-c", f"diff.attacker.textconv={helper}", "grep",
                 "--textconv", "dirty", "HEAD", "--", "tracked.txt"],
                ["-c", f"diff.attacker.textconv={helper}", "show",
                 "--textconv", "HEAD:tracked.txt"],
                ["-c", f"diff.attacker.textconv={helper}", "whatchanged",
                 "--textconv", "-p", "HEAD"],
                ["diff", "--ext-diff", "HEAD"],
                ["diff", "--textconv", "HEAD"],
                ["blame", "--textconv", "HEAD", "--", "tracked.txt"],
                ["cat-file", "--textc", "--path=tracked.txt", "HEAD:tracked.txt"],
                ["grep", "-O", str(helper), "needle"],
                ["grep", "-nO" + str(helper), "needle"],
                ["grep", "--open-files-in-pager=" + str(helper), "needle"],
                ["grep", "--open-files-in-pag=" + str(helper), "needle"],
            )
            with mock.patch.object(
                operator, "_require_operator_mutation", return_value=None
            ):
                for attack in attacks:
                    with self.subTest(attack=attack):
                        marker.unlink(missing_ok=True)
                        with self.assertRaises((AgentSandboxError, PermissionError)):
                            operator.grabowski_git(str(repo), attack)
                        self.assertFalse(marker.exists(), "native Git ran helper")



    def test_native_git_rejects_caller_executable_cli_config(self) -> None:
        """CLI -c overrides safe environment and must never launch hooks/fsmonitor."""
        from unittest import mock
        import grabowski_operator as operator
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory(prefix="native-cli-helper-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            for key, value in (("user.name", "Fixture"),
                               ("user.email", "fixture@example.invalid")):
                subprocess.run(
                    ["/usr/bin/git", "-C", str(repo), "config", key, value],
                    env=secure, check=True,
                )
            hook_dir = root / "hooks"
            hook_dir.mkdir(mode=0o700)
            hook_marker = root / "hook-ran"
            hook = hook_dir / "pre-commit"
            hook.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(hook_marker)) + "\nexit 0\n",
                encoding="ascii",
            )
            hook.chmod(0o700)
            fsmarker = root / "fsmonitor-ran"
            fsmonitor = root / "monitor-helper"
            fsmonitor.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(fsmarker)) + "\nexit 0\n",
                encoding="ascii",
            )
            fsmonitor.chmod(0o700)
            (repo / "tracked.txt").write_text("changed\n")
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "add", "--", "tracked.txt"],
                env=secure, check=True,
            )
            preimage = operator._git_branch_preimage(repo)
            attempt = {
                "schema_version": 1,
                "owner_id": "operator:cli-helper-regression",
                "operation_id": "cli-helper-p1",
                "attempt_id": "hook-1",
                "branch": preimage["branch"],
                "expected_preimage_sha256": preimage["preimage_sha256"],
            }
            with (
                mock.patch.object(resources, "RESOURCE_DB", root / "resources.sqlite3"),
                mock.patch.object(operator, "_require_operator_mutation", return_value=None),
                mock.patch.object(operator, "_append_effect_audit", return_value="a" * 64),
            ):
                for argv in (
                    ["-c", f"core.hooksPath={hook_dir}", "commit", "-m", "no hooks"],
                    ["-c", f"core.fsmonitor={fsmonitor}", "status", "--short"],
                ):
                    marker = hook_marker if "commit" in argv else fsmarker
                    with self.subTest(argv=argv):
                        marker.unlink(missing_ok=True)
                        with self.assertRaises(PermissionError):
                            operator.grabowski_git(
                                str(repo), argv,
                                branch_attempt=attempt if "commit" in argv else None,
                            )
                        self.assertFalse(marker.exists(), "native Git ran caller -c helper")




    def test_git_signing_helper_is_blocked_after_admission(self) -> None:
        """A late repo-configured signing program must never run on native commit -a."""
        from unittest import mock
        import grabowski_operator as operator
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory(prefix="native-gpg-effect-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            (repo / "tracked.txt").write_text("changed", encoding="ascii")
            marker = root / "signer-executed"
            signer = root / "signer"
            signer.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 1\n",
                encoding="ascii",
            )
            signer.chmod(0o700)
            for key, value in (
                ("user.name", "Test"), ("user.email", "test@example.invalid"),
                ("user.signingkey", "attacker-key"),
            ):
                subprocess.run(
                    ["/usr/bin/git", "-C", str(repo), "config", key, value],
                    env=secure, check=True,
                )
            original_run = operator._run
            injected = False

            def late_signer_config(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "commit" in argv:
                    injected = True
                    for key, value in (
                        ("gpg.program", str(signer)), ("commit.gpgsign", "true"),
                    ):
                        subprocess.run(
                            ["/usr/bin/git", "-C", str(repo), "config", key, value],
                            env=secure, check=True,
                        )
                return original_run(argv, **kwargs)

            attempt = {
                "schema_version": 1,
                "owner_id": "operator:gpg-p1-security",
                "operation_id": "gpg-at-effect",
                "attempt_id": "commit-a",
                "branch": "main",
                "expected_preimage_sha256": operator._git_branch_preimage(repo)[
                    "preimage_sha256"
                ],
            }
            with (
                mock.patch.object(resources, "RESOURCE_DB", root / "resources.sqlite3"),
                mock.patch.object(operator, "_require_operator_mutation", return_value=None),
                mock.patch.object(operator, "_append_effect_audit", return_value="a" * 64),
                mock.patch.object(operator, "_run", side_effect=late_signer_config),
            ):
                actual = operator.grabowski_git(
                    str(repo), ["commit", "-am", "protected"], branch_attempt=attempt,
                )
            self.assertTrue(injected, "late signer injection did not run")
            self.assertEqual(actual["returncode"], 0, actual.get("stderr"))
            self.assertEqual(actual["branch_mutation"]["status"], "completed")
            self.assertFalse(marker.exists(), "repo signing helper ran in protected Git")

            from grabowski_agent_sandbox import AgentSandboxError, safe_git_repository_environment
            with self.assertRaises(AgentSandboxError):
                safe_git_repository_environment(repo)

            # Deliberately omit trusted command-scope overrides in the negative control.
            unprotected_env = {
                key: value for key, value in secure.items()
                if not key.startswith("GIT_CONFIG_")
            }
            (repo / "tracked.txt").write_text("again!!", encoding="ascii")
            raw = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "commit", "-am", "unprotected"],
                env=unprotected_env, capture_output=True, timeout=15,
            )
            self.assertNotEqual(raw.returncode, 0)
            self.assertTrue(marker.exists(), "unprotected Git signing control never ran")

    def test_native_git_preserves_ordinary_text_diff(self) -> None:
        from grabowski_agent_sandbox import _git_without_external_diff
        self.assertEqual(
            _git_without_external_diff(["git", "diff", "--text", "HEAD"]),
            ["git", "diff", "--no-ext-diff", "--no-textconv", "--text", "HEAD"],
        )
        self.assertEqual(
            _git_without_external_diff(["git", "show", "--text", "HEAD"]),
            ["git", "show", "--no-ext-diff", "--no-textconv", "--text", "HEAD"],
        )

    def test_writer_status_blocks_late_clean_filter(self) -> None:
        """Writer._git status must pin inactive filters at the exact Git process."""
        from unittest import mock
        import grabowski_agent_writer as writer

        with tempfile.TemporaryDirectory(prefix="writer-status-p2-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            (repo / ".gitattributes").write_text("tracked.txt filter=attacker\n")
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "add", ".gitattributes"],
                env=secure, check=True,
            )
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "-c", "user.name=Test",
                 "-c", "user.email=test@example.invalid", "commit", "-qm", "attributes"],
                env=secure, check=True,
            )
            (repo / "tracked.txt").write_text("3", encoding="ascii")
            marker = root / "filter-executed"
            helper = root / "clean-helper"
            helper.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\ncat\n",
                encoding="ascii",
            )
            helper.chmod(0o700)
            original_run = writer.subprocess.run
            injected = False

            def late_clean(argv: list[str], **kwargs: object):
                nonlocal injected
                if not injected and "status" in argv:
                    injected = True
                    original_run(
                        ["/usr/bin/git", "-C", str(repo),
                         "config", "filter.attacker.clean", str(helper)],
                        env=secure, check=True,
                    )
                return original_run(argv, **kwargs)

            with mock.patch.object(writer.subprocess, "run", side_effect=late_clean):
                output = writer._git(
                    repo, "status", "--porcelain=v1", "--untracked-files=all"
                )
            self.assertTrue(injected)
            self.assertIn("tracked.txt", output)
            self.assertFalse(marker.exists(), "writer status executed late clean helper")
            control = original_run(
                ["/usr/bin/git", "-C", str(repo), "status", "--porcelain=v1"],
                env=secure, capture_output=True, timeout=15,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertTrue(marker.exists(), "unprotected writer status control missed helper")


    def test_git_commit_editor_is_denied_before_spawn(self) -> None:
        """A caller-selected Git editor cannot run through the native Git effect."""
        from grabowski_agent_sandbox import (
            AgentSandboxError, safe_git_filter_effect, safe_git_repository_environment,
        )
        with tempfile.TemporaryDirectory(prefix="native-git-editor-") as directory:
            root = Path(directory)
            repo = root / "repo"
            secure = safe_git_environment()
            self._two_commit_repo(repo, secure)
            (repo / ".git" / "info").mkdir(mode=0o700, exist_ok=True)
            with self.assertRaises(AgentSandboxError):
                with safe_git_filter_effect(
                    repo, ["git", "-C", str(repo), "commit", "--edit", "-m", "fixture"]
                ):
                    self.fail("explicit Git editor was admitted")

            marker = root / "editor-executed"
            editor = root / "editor"
            editor.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 0\n",
                encoding="ascii",
            )
            editor.chmod(0o700)
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "config", "core.editor", str(editor)],
                env=secure, check=True,
            )
            with self.assertRaises(AgentSandboxError):
                safe_git_repository_environment(repo)

            # The identical Git effect without the admission contract does execute it.
            (repo / "tracked.txt").write_text("editor control", encoding="ascii")
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "add", "tracked.txt"],
                env=secure, check=True,
            )
            unprotected_env = {
                key: value for key, value in secure.items()
                if not key.startswith("GIT_CONFIG_") and key != "GIT_EDITOR"
            }
            raw = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "commit", "--edit", "-m", "control"],
                env=unprotected_env, capture_output=True, timeout=15,
            )
            self.assertEqual(raw.returncode, 0, raw.stderr)
            self.assertTrue(marker.exists(), "unprotected editor control missed helper")

if __name__ == "__main__":
    unittest.main()
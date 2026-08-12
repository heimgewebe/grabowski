from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


helper = _load(
    "grabowski_runtime_bootstrap_recover_test_module",
    TOOLS / "grabowski_runtime_bootstrap_recover.py",
)
dual = _load(
    "grabowski_deploy_runtime_dual_bootstrap_test_module",
    TOOLS / "deploy_runtime_dual.py",
)


class RuntimeBootstrapRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.canonical = self.root / "canonical"
        self.recovery_root = self.root / "recovery-worktrees"
        self.recovery_root.mkdir(mode=0o700)
        self._git("init", "--initial-branch=main", str(self.canonical), cwd=self.root)
        self._git("config", "user.email", "test@example.invalid", cwd=self.canonical)
        self._git("config", "user.name", "Bootstrap Test", cwd=self.canonical)
        (self.canonical / "README.md").write_text("bootstrap\n", encoding="utf-8")
        self._git("add", "README.md", cwd=self.canonical)
        self._git("commit", "-m", "bootstrap", cwd=self.canonical)
        self.head = self._git_output("rev-parse", "HEAD", cwd=self.canonical)
        self.origin_url = "git@github.com:heimgewebe/grabowski.git"
        self._git("remote", "add", "origin", self.origin_url, cwd=self.canonical)
        self._git(
            "update-ref",
            "refs/remotes/origin/main",
            self.head,
            cwd=self.canonical,
        )

    def _git(self, *argv: str, cwd: Path) -> None:
        subprocess.run(
            ["/usr/bin/git", *argv],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )

    def _git_output(self, *argv: str, cwd: Path) -> str:
        completed = subprocess.run(
            ["/usr/bin/git", *argv],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return completed.stdout.strip()

    def _patch_repository_constants(self):
        return mock.patch.multiple(
            helper,
            CANONICAL_REPOSITORY=self.canonical,
            CANONICAL_ORIGIN_URL=self.origin_url,
            RECOVERY_WORKTREE_ROOT=self.recovery_root,
            DEPLOY_UID=os.getuid(),
            DEPLOY_GID=os.getgid(),
        )

    def test_submit_reference_accepts_path_socket_and_round_trips_response(self) -> None:
        socket_path = self.root / "broker.sock"
        response = {
            "request_id": "b" * 32,
            "action": "runtime_bootstrap_recover",
            "returncode": 0,
        }
        received: list[dict[str, object]] = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(os.fspath(socket_path))
            server.listen(1)

            def serve() -> None:
                connection, _ = server.accept()
                with connection:
                    chunks: list[bytes] = []
                    while True:
                        chunk = connection.recv(64 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    received.append(json.loads(b"".join(chunks).decode("utf-8")))
                    connection.sendall(json.dumps(response).encode("utf-8"))

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            observed = helper.submit_reference(self.head, socket_path=socket_path)
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(observed, response)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["action"], "runtime_bootstrap_recover")
        target = json.loads(str(received[0]["target"]))
        self.assertEqual(target["expected_head"], self.head)

    def test_reference_is_release_independent_and_has_no_source_path_authority(self) -> None:
        with mock.patch.object(helper.secrets, "token_hex", return_value="a" * 32):
            reference = helper.create_reference(self.head, now_unix=100)
        self.assertEqual(reference["action"], "runtime_bootstrap_recover")
        target = json.loads(reference["target"])
        self.assertEqual(
            target,
            {
                "schema_version": 1,
                "expected_head": self.head,
                "target_runtime": "heim-pc",
            },
        )
        self.assertNotIn("source_repository", target)
        unsigned = dict(reference)
        claimed = unsigned.pop("reference_sha256")
        self.assertEqual(claimed, helper._canonical_sha256(unsigned))
        source = (TOOLS / "grabowski_runtime_bootstrap_recover.py").read_text()
        self.assertNotIn("import grabowski_", source)
        self.assertNotIn("from grabowski_", source)
        self.assertEqual(helper.SAFE_USER_ENV["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(helper.SAFE_USER_ENV["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(helper.SAFE_USER_ENV["GIT_TERMINAL_PROMPT"], "0")

    def test_example_config_reuses_template_broker_without_new_mode(self) -> None:
        config = json.loads((ROOT / "config/privileged-actions.example.json").read_text())
        action = config["actions"]["runtime_bootstrap_recover"]
        self.assertEqual(action["mode"], "template")
        self.assertEqual(
            action["argv"],
            [
                "/usr/local/libexec/grabowski-runtime-bootstrap-recover",
                "root-execute",
                "{target}",
            ],
        )
        self.assertEqual(action["timeout_seconds"], 3600)
        broker_source = (ROOT / "src/grabowski_privileged_broker.py").read_text()
        self.assertNotIn("runtime-bootstrap-recover", broker_source)
        broker_service = (ROOT / "systemd/grabowski-privileged-broker@.service").read_text()
        self.assertNotIn("/home/alex/repos/grabowski/.git", broker_service)

    def test_root_systemd_argv_delegates_only_to_fixed_uid_user_helper(self) -> None:
        argv = helper._root_systemd_argv(self.head, "b" * 24)
        self.assertEqual(argv[:3], ["/usr/bin/systemd-run", "--system", "--wait"])
        self.assertIn("--uid=1000", argv)
        self.assertIn("--gid=1000", argv)
        self.assertIn("--property=NoNewPrivileges=yes", argv)
        self.assertNotIn("ConditionPathExists", "\n".join(argv))
        self.assertIn(str(helper.ROOT_HELPER), argv)
        self.assertIn("user-execute", argv)
        self.assertIn("--expected-head", argv)
        self.assertIn(self.head, argv)
        rendered = "\n".join(argv)
        self.assertNotIn("/bin/sh", rendered)
        self.assertNotIn("/bin/bash", rendered)
        self.assertNotIn("/usr/bin/git", rendered)
        self.assertNotIn("make", rendered)

    def test_root_execute_rejects_free_target_fields_and_kill_switch(self) -> None:
        bad = json.dumps(
            {
                "schema_version": 1,
                "expected_head": self.head,
                "target_runtime": "heim-pc",
                "argv": ["/bin/sh", "-c", "id"],
            }
        )
        with mock.patch.object(helper.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "target contract"):
                helper.root_execute(bad)
        wrong_runtime = json.dumps(
            {
                "schema_version": 1,
                "expected_head": self.head,
                "target_runtime": "other-host",
            }
        )
        with mock.patch.object(helper.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "target_runtime"):
                helper.root_execute(wrong_runtime)
        good = json.dumps(
            {
                "schema_version": 1,
                "expected_head": self.head,
                "target_runtime": "heim-pc",
            }
        )
        with mock.patch.object(helper.os, "geteuid", return_value=0), mock.patch.object(
            helper, "_require_root_helper_identity"
        ), mock.patch.object(
            helper, "_require_kill_switch_clear", side_effect=helper.BootstrapRecoveryError("kill switch")
        ):
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "kill switch"):
                helper.root_execute(good)

    def test_kill_switch_observation_fails_closed_when_marker_is_unreadable(self) -> None:
        marker = Path("/unreadable-marker")
        with mock.patch.object(Path, "lstat", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(
                helper.BootstrapRecoveryError,
                "kill-switch state is unreadable",
            ):
                helper._marker_present(marker)

    def test_user_execute_rechecks_kill_switch_immediately_before_deploy(self) -> None:
        deploy = mock.Mock()
        gate = mock.Mock(
            side_effect=[
                None,
                helper.BootstrapRecoveryError("kill switch appeared"),
            ]
        )
        with mock.patch.object(helper.os, "geteuid", return_value=helper.DEPLOY_UID), mock.patch.object(
            helper.os, "getegid", return_value=helper.DEPLOY_GID
        ), mock.patch.object(
            helper, "_require_kill_switch_clear", gate
        ), mock.patch.object(
            helper, "_schedule_lock", return_value=nullcontext()
        ), mock.patch.object(
            helper,
            "_create_recovery_worktree",
            return_value=(Path("/recovery-worktree"), Path("/canonical-common")),
        ), mock.patch.object(
            helper, "_validate_recovery_worktree"
        ), mock.patch.object(
            helper, "_deploy_exact", deploy
        ):
            with self.assertRaisesRegex(
                helper.BootstrapRecoveryError,
                "kill switch appeared",
            ):
                helper.user_execute(self.head, "e" * 24)
        self.assertEqual(gate.call_count, 2)
        deploy.assert_not_called()

    def test_root_execute_checks_kill_switch_again_immediately_before_dispatch(self) -> None:
        target = json.dumps(
            {
                "schema_version": 1,
                "expected_head": self.head,
                "target_runtime": "heim-pc",
            }
        )
        completed = subprocess.CompletedProcess(
            [],
            0,
            stdout=(
                json.dumps({"state": "completed", "expected_head": self.head}) + "\n"
            ).encode("utf-8"),
            stderr=b"",
        )
        with mock.patch.object(helper.os, "geteuid", return_value=0), mock.patch.object(
            helper, "_require_root_helper_identity"
        ), mock.patch.object(
            helper, "_require_kill_switch_clear"
        ) as kill, mock.patch.object(
            helper.secrets, "token_hex", return_value="c" * 24
        ), mock.patch.object(
            helper.subprocess, "run", return_value=completed
        ) as run:
            result = helper.root_execute(target)
        self.assertEqual(kill.call_count, 2)
        self.assertEqual(result["expected_head"], self.head)
        self.assertEqual(result["user_result"]["state"], "completed")
        self.assertNotIn("stdout", result)
        self.assertNotIn("stderr", result)
        self.assertEqual(run.call_args.args[0], helper._root_systemd_argv(self.head, "c" * 24))

    def test_canonical_repository_validation_is_exact_and_clean(self) -> None:
        with self._patch_repository_constants():
            evidence = helper._canonical_repo_evidence(self.head)
        self.assertEqual(evidence["origin_main"], self.head)
        self.assertEqual(evidence["origin_url"], self.origin_url)
        self.assertEqual(
            evidence["git_common_directory"], str((self.canonical / ".git").resolve())
        )

    def test_canonical_repository_rejects_dirty_origin_drift_and_external_filters(self) -> None:
        with self._patch_repository_constants():
            (self.canonical / "dirty.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "dirty"):
                helper._canonical_repo_evidence(self.head)
            (self.canonical / "dirty.txt").unlink()
            self._git("commit", "--allow-empty", "-m", "origin drift", cwd=self.canonical)
            drift_head = self._git_output("rev-parse", "HEAD", cwd=self.canonical)
            self._git("reset", "--hard", self.head, cwd=self.canonical)
            self._git("update-ref", "refs/remotes/origin/main", drift_head, cwd=self.canonical)
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "origin/main"):
                helper._canonical_repo_evidence(self.head)
            self._git("update-ref", "refs/remotes/origin/main", self.head, cwd=self.canonical)
            self._git("config", "filter.unsafe.smudge", "/bin/false", cwd=self.canonical)
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "filters"):
                helper._canonical_repo_evidence(self.head)

    def test_recovery_worktree_is_detached_exact_and_private(self) -> None:
        with self._patch_repository_constants():
            path, common = helper._create_recovery_worktree(self.head, "d" * 24)
            helper._validate_recovery_worktree(
                path,
                expected_head=self.head,
                expected_common=common,
            )
        self.assertTrue(path.is_dir())
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)
        self.assertEqual(self._git_output("rev-parse", "HEAD", cwd=path), self.head)
        branch = subprocess.run(
            ["/usr/bin/git", "symbolic-ref", "-q", "HEAD"],
            cwd=path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(branch.returncode, 1)

    def test_deploy_exact_invokes_existing_dual_engine_with_expected_head(self) -> None:
        worktree = self.root / "worktree"
        deploy_python = worktree / "build/deploy-tooling/.venv/bin/python"
        deploy_python.parent.mkdir(parents=True)
        deploy_python.write_text("python\n", encoding="utf-8")
        deploy_python.chmod(0o700)
        deploy_script = worktree / "tools/deploy_runtime_dual.py"
        deploy_script.parent.mkdir(parents=True)
        deploy_script.write_text("# deploy\n", encoding="utf-8")
        calls: list[list[str]] = []

        def fake_run(argv, **_kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=b"ok\n", stderr=b"")

        with mock.patch.object(helper, "_command_result", side_effect=fake_run):
            result = helper._deploy_exact(worktree, self.head)
        self.assertEqual(calls[0], ["/usr/bin/make", "-C", str(worktree), "context-check", "deploy-tooling"])
        self.assertEqual(
            calls[1],
            [
                str(deploy_python),
                str(deploy_script),
                "--repo",
                str(worktree),
                "--apply",
                "--bootstrap-recovery",
                "--expected-head",
                self.head,
            ],
        )
        self.assertEqual(result["returncode"], 0)

    def test_dual_deploy_expected_head_fails_at_snapshot_boundary(self) -> None:
        snapshot = SimpleNamespace(repo_head="f" * 40, contract=SimpleNamespace())
        with mock.patch.object(dual.core, "snapshot_from_git", return_value=snapshot):
            with self.assertRaisesRegex(dual.core.DeployError, "expected_head"):
                dual.preflight_url(
                    Path("/repo"),
                    Path("/runtime"),
                    Path("/profile"),
                    expected_head=self.head,
                )

    def test_dual_deploy_matching_expected_head_continues_normal_preflight(self) -> None:
        snapshot = SimpleNamespace(repo_head=self.head, contract=SimpleNamespace())
        topology = SimpleNamespace(kind="legacy-stdio")
        with mock.patch.object(dual.core, "snapshot_from_git", return_value=snapshot), mock.patch.object(
            dual.core, "require_runtime_replaceable", return_value=Path("/runtime")
        ), mock.patch.object(
            dual, "profile_topology", return_value=topology
        ), mock.patch.object(
            dual, "require_topology_matches_contract"
        ):
            observed, runtime, observed_topology = dual.preflight_url(
                Path("/repo"),
                Path("/runtime"),
                Path("/profile"),
                expected_head=self.head,
            )
        self.assertIs(observed, snapshot)
        self.assertEqual(runtime, Path("/runtime"))
        self.assertIs(observed_topology, topology)

    def test_runtime_manifest_readback_requires_exact_completed_head(self) -> None:
        manifest = self.root / "deployment-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 6,
                    "repo_head": self.head,
                    "release_id": "release-test",
                    "completion_status": "complete",
                }
            ),
            encoding="utf-8",
        )
        manifest.chmod(0o600)
        with mock.patch.object(helper, "RUNTIME_MANIFEST", manifest), mock.patch.object(
            helper, "DEPLOY_UID", os.getuid()
        ):
            result = helper._runtime_manifest_readback(self.head)
            self.assertEqual(result["repo_head"], self.head)
            with self.assertRaisesRegex(helper.BootstrapRecoveryError, "expected_head"):
                helper._runtime_manifest_readback("e" * 40)


if __name__ == "__main__":
    unittest.main()

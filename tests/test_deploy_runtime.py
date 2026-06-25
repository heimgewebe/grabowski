from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "deploy_runtime.py"


def load_module():
    spec = importlib.util.spec_from_file_location("deploy_runtime", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("deploy_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy_runtime = load_module()


class DeployRuntimeTests(unittest.TestCase):
    def test_sha256_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("grabowski\n", encoding="utf-8")
            first = deploy_runtime.sha256(path)
            second = deploy_runtime.sha256(path)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)

    def test_require_file_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaises(deploy_runtime.DeployError):
                deploy_runtime.require_file(missing, "test file")

    def test_deployment_lock_rejects_concurrent_holder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "deploy.lock"
            with deploy_runtime.deployment_lock(lock):
                with self.assertRaises(deploy_runtime.DeployError):
                    with deploy_runtime.deployment_lock(lock):
                        self.fail("second holder entered")

    def test_install_and_restore_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            stage = root / "stage"
            runtime.mkdir()
            stage.mkdir()
            (runtime / "old").write_text("old", encoding="utf-8")
            (stage / "new").write_text("new", encoding="utf-8")

            backup = deploy_runtime.install_stage(
                runtime,
                stage,
                stamp="stamp",
            )
            self.assertIsNotNone(backup)
            assert backup is not None
            self.assertTrue((runtime / "new").is_file())

            failed = deploy_runtime.restore_previous_runtime(
                runtime,
                backup,
                stamp="restore",
            )
            self.assertIsNotNone(failed)
            self.assertTrue((runtime / "old").is_file())

    def test_manifest_rejects_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            (runtime / "deployment-manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "repo_head": "head",
                        "source_sha256": "wrong",
                        "runtime_lock_sha256": "lock",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(deploy_runtime.DeployError):
                deploy_runtime.verify_manifest(
                    runtime,
                    repo_head="head",
                    source_hash="source",
                    lockfile_hash="lock",
                )

    def test_running_runtime_is_found_in_process_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            proc = root / "proc"
            for pid in (100, 200):
                (proc / str(pid) / "task" / str(pid)).mkdir(parents=True)
            (proc / "100" / "task" / "100" / "children").write_text(
                "200\n",
                encoding="utf-8",
            )
            (proc / "200" / "task" / "200" / "children").write_text(
                "",
                encoding="utf-8",
            )
            (proc / "100" / "cmdline").write_bytes(b"parent\0")
            (proc / "200" / "cmdline").write_bytes(
                str(runtime / ".venv/bin/python").encode()
                + b"\0"
                + str(runtime / "grabowski_mcp.py").encode()
                + b"\0"
            )

            result = deploy_runtime.verify_running_runtime(
                runtime,
                main_pid=100,
                proc_root=proc,
            )
            self.assertEqual(result["pid"], 200)

    def _runtime_and_stage(self, root: Path) -> tuple[Path, Path]:
        runtime = root / "runtime"
        stage = root / "stage"
        runtime.mkdir()
        stage.mkdir()
        (runtime / "old.txt").write_text("old", encoding="utf-8")
        (stage / "grabowski_mcp.py").write_text(
            "print('new')\n",
            encoding="utf-8",
        )
        return runtime, stage

    @staticmethod
    def _provenance() -> dict[str, str]:
        return {
            "python_version": "3.10.12",
            "python_implementation": "CPython",
            "platform": "test",
            "executable": "/test/python",
            "pip_version": "pip test",
        }

    @staticmethod
    def _successful_result(argv):
        return subprocess.CompletedProcess(argv, 0, "", "")

    def _failure_on_checked_call(self, wanted_call: int):
        state = {"checked_calls": 0}

        def fake_run(argv, **kwargs):
            if kwargs.get("check", True):
                state["checked_calls"] += 1
                if state["checked_calls"] == wanted_call:
                    raise subprocess.CalledProcessError(1, argv)
            return self._successful_result(argv)

        return fake_run

    def _deploy_with(
        self,
        root: Path,
        runtime: Path,
        stage: Path,
        run_side_effect,
        ready_values: list[bool],
    ) -> None:
        with (
            patch.object(
                deploy_runtime,
                "require_clean_repo",
                return_value="head",
            ),
            patch.object(
                deploy_runtime,
                "service_active",
                return_value=True,
            ),
            patch.object(
                deploy_runtime,
                "create_stage",
                return_value=(
                    stage,
                    "2025-06-18",
                    self._provenance(),
                ),
            ),
            patch.object(
                deploy_runtime,
                "run",
                side_effect=run_side_effect,
            ),
            patch.object(
                deploy_runtime,
                "wait_until_ready",
                side_effect=ready_values,
            ),
        ):
            deploy_runtime.deploy(
                ROOT,
                runtime,
                root / "profile.yaml",
                timeout_seconds=1,
            )

    def test_pre_swap_command_failure_preserves_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, stage = self._runtime_and_stage(root)
            with self.assertRaises(subprocess.CalledProcessError):
                self._deploy_with(
                    root,
                    runtime,
                    stage,
                    self._failure_on_checked_call(1),
                    [True],
                )
            self.assertTrue((runtime / "old.txt").is_file())

    def test_post_swap_command_failure_restores_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, stage = self._runtime_and_stage(root)
            with self.assertRaises(subprocess.CalledProcessError):
                self._deploy_with(
                    root,
                    runtime,
                    stage,
                    self._failure_on_checked_call(2),
                    [True],
                )
            self.assertTrue((runtime / "old.txt").is_file())

    def test_readiness_timeout_restores_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, stage = self._runtime_and_stage(root)
            with self.assertRaises(deploy_runtime.DeployError):
                self._deploy_with(
                    root,
                    runtime,
                    stage,
                    self._successful_result,
                    [False, True],
                )
            self.assertTrue((runtime / "old.txt").is_file())

    def test_unhealthy_rollback_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, stage = self._runtime_and_stage(root)
            with self.assertRaisesRegex(
                deploy_runtime.DeployError,
                "wiederhergestellte Runtime wurde nicht ready",
            ):
                self._deploy_with(
                    root,
                    runtime,
                    stage,
                    self._successful_result,
                    [False, False],
                )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "deploy_runtime.py"


def load_module():
    spec = importlib.util.spec_from_file_location("deploy_runtime", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("deploy_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_runtime"] = module
    spec.loader.exec_module(module)
    return module


deploy_runtime = load_module()


class DeployRuntimeTests(unittest.TestCase):
    def _contract(self, module: str = "grabowski_mcp") -> deploy_runtime.RuntimeContract:
        return deploy_runtime.RuntimeContract(
            schema_version=1,
            mode="module",
            module=module,
            source=Path("src/grabowski_mcp.py"),
            expected_tools=("grabowski_status", "grabowski_list_directory"),
        )

    def _snapshot(self, module: str = "grabowski_mcp") -> deploy_runtime.Snapshot:
        contract = self._contract(module)
        return deploy_runtime.Snapshot(
            repo_head="a" * 40,
            dirty=False,
            contract=contract,
            contract_bytes=json.dumps(contract.to_manifest()).encode(),
            runtime_input_bytes=b"mcp==1.27.2\n",
            runtime_lock_bytes=(
                b"mcp==1.27.2 \\\n"
                b"    --hash=sha256:" + b"1" * 64 + b"\n"
            ),
            source_bytes=b"print('snapshot')\n",
        )

    @staticmethod
    def _completed(argv, returncode: int = 0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, returncode, "", "")

    def test_sha256_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("grabowski\n", encoding="utf-8")
            first = deploy_runtime.sha256(path)
            second = deploy_runtime.sha256(path)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)

    def test_module_entrypoint_contract_loads(self) -> None:
        raw = json.dumps(
            {
                "schema_version": 1,
                "mode": "module",
                "module": "grabowski_mcp",
                "source": "src/grabowski_mcp.py",
                "expected_tools": ["grabowski_status"],
            }
        ).encode()
        contract = deploy_runtime.load_contract_bytes(raw)
        self.assertEqual(contract.mode, "module")
        self.assertEqual(contract.module, "grabowski_mcp")
        self.assertEqual(
            contract.command_argv(Path("/release"), Path("/release/.venv/bin/python")),
            ["/release/.venv/bin/python", "-m", "grabowski_mcp"],
        )

    def test_profile_operator_mismatch_stops_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            runtime.mkdir()
            profile = root / "profile.yaml"
            profile.write_text("ignored\n", encoding="utf-8")
            snapshot = self._snapshot("grabowski_mcp")

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable"),
                patch.object(deploy_runtime, "service_active", return_value=True),
                patch.object(deploy_runtime, "profile_entrypoint", return_value=deploy_runtime.EntryPoint(mode="module", python=runtime / ".venv/bin/python", module="grabowski_operator")),
                patch.object(deploy_runtime, "build_release") as build_release,
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "passen nicht zusammen"):
                    deploy_runtime.deploy(ROOT, runtime, profile, timeout_seconds=1)
            build_release.assert_not_called()
            self.assertFalse((root / deploy_runtime.RELEASES_DIR_NAME).exists())

    def test_missing_root_script_is_not_required_for_module_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            venv_module = release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py"
            venv_module.parent.mkdir(parents=True)
            venv_module.write_text("x=1\n", encoding="utf-8")
            with patch.object(deploy_runtime, "import_module_path", return_value=venv_module):
                found = deploy_runtime.verify_entrypoint_importable(
                    release,
                    release / ".venv/bin/python",
                    self._contract(),
                )
            self.assertEqual(found, venv_module)
            self.assertFalse((release / "grabowski_mcp.py").exists())

    def test_module_resolution_outside_release_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            release.mkdir()
            outside = Path(directory) / "outside.py"
            outside.write_text("x=1\n", encoding="utf-8")
            with patch.object(deploy_runtime, "import_module_path", return_value=outside):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "außerhalb"):
                    deploy_runtime.verify_entrypoint_importable(
                        release,
                        release / ".venv/bin/python",
                        self._contract(),
                    )

    def test_python_m_module_process_identity_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            runtime = root / "grabowski-mcp"
            proc = root / "proc"
            real_python = root / "python-real"
            real_python.write_text("", encoding="utf-8")
            (release / ".venv/bin").mkdir(parents=True)
            (release / ".venv/bin/python").symlink_to(real_python)
            module_path = release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py"
            module_path.parent.mkdir(parents=True)
            module_path.write_text("x=1\n", encoding="utf-8")
            runtime.symlink_to(release)

            for pid in (100, 200):
                (proc / str(pid) / "task" / str(pid)).mkdir(parents=True)
            (proc / "100" / "task" / "100" / "children").write_text("200\n", encoding="utf-8")
            (proc / "200" / "task" / "200" / "children").write_text("", encoding="utf-8")
            (proc / "100" / "cmdline").write_bytes(
                str(deploy_runtime.HOME / ".local/bin/tunnel-client").encode()
                + b"\0run\0--profile\0grabowski\0"
            )
            (proc / "200" / "cmdline").write_bytes(
                str(runtime / ".venv/bin/python").encode()
                + b"\0-m\0grabowski_mcp\0"
            )
            (proc / "200" / "exe").symlink_to(real_python)

            with patch.object(deploy_runtime, "import_module_path", return_value=module_path):
                result = deploy_runtime.verify_running_runtime(
                    release,
                    runtime,
                    self._contract(),
                    main_pid=100,
                    proc_root=proc,
                )
            self.assertEqual(result["pid"], 200)

    def test_systemd_profile_name_substring_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            (proc / "100" / "task" / "100").mkdir(parents=True)
            (proc / "100" / "task" / "100" / "children").write_text("", encoding="utf-8")
            (proc / "100" / "cmdline").write_bytes(
                str(deploy_runtime.HOME / ".local/bin/tunnel-client").encode()
                + b"\0run\0--profile\0grabowski-extra\0"
            )
            with self.assertRaisesRegex(deploy_runtime.DeployError, "exakt"):
                deploy_runtime.verify_systemd_tunnel_process(
                    main_pid=100,
                    proc_root=proc,
                )

    def test_build_release_creates_venv_at_final_release_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._snapshot()
            created_venv: list[Path] = []

            def fake_run(argv, **kwargs):
                if argv[:3] == [sys.executable, "-m", "venv"]:
                    venv = Path(argv[3])
                    created_venv.append(venv)
                    (venv / "bin").mkdir(parents=True)
                    (venv / "bin/python").write_text("", encoding="utf-8")
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "site_packages_path", side_effect=lambda python: python.parents[1] / "lib/python3.10/site-packages"),
                patch.object(deploy_runtime, "verify_installed_distributions"),
                patch.object(deploy_runtime, "import_module_path", side_effect=lambda python, module: python.parents[1] / "lib/python3.10/site-packages/grabowski_mcp.py"),
                patch.object(deploy_runtime, "probe_mcp", return_value="2025-06-18"),
                patch.object(deploy_runtime, "python_provenance", return_value={"python_version": "3.10.12", "python_implementation": "CPython", "platform": "linux", "executable": "python", "pip_version": "pip 25"}),
            ):
                result = deploy_runtime.build_release(
                    snapshot,
                    root / deploy_runtime.RELEASES_DIR_NAME,
                    root / "grabowski-mcp",
                )

            self.assertEqual(created_venv, [result.release_path / ".venv"])
            self.assertTrue((result.release_path / "inputs/runtime.lock.txt").is_file())
            self.assertTrue((result.release_path / deploy_runtime.MANIFEST_NAME).is_file())

    def test_apply_snapshot_drift_blocks_activation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            source = release / "inputs/src/grabowski_mcp.py"
            source.parent.mkdir(parents=True)
            snapshot = self._snapshot()
            (release / "inputs/runtime-entrypoint.json").write_bytes(snapshot.contract_bytes)
            (release / "inputs/runtime.in").write_bytes(snapshot.runtime_input_bytes)
            (release / "inputs/runtime.lock.txt").write_bytes(snapshot.runtime_lock_bytes)
            source.write_bytes(snapshot.source_bytes)

            with patch.object(deploy_runtime, "repo_dirty", return_value=True):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Arbeitsbaum"):
                    deploy_runtime.verify_apply_snapshot_unchanged(ROOT, snapshot, release)

    def test_deployment_lock_is_released_after_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "deploy.lock"
            with self.assertRaises(RuntimeError):
                with deploy_runtime.deployment_lock(lock):
                    raise RuntimeError("boom")
            with deploy_runtime.deployment_lock(lock):
                pass

    def _write_manifest(self, release: Path, snapshot: deploy_runtime.Snapshot, runtime: Path) -> None:
        deploy_runtime.write_manifest(
            release,
            release_id="release",
            snapshot=snapshot,
            stable_runtime=runtime,
            input_paths={
                "runtime_entrypoint": str(release / "inputs/runtime-entrypoint.json"),
                "runtime_input": str(release / "inputs/runtime.in"),
                "runtime_lock": str(release / "inputs/runtime.lock.txt"),
                "source": str(release / "inputs/src/grabowski_mcp.py"),
            },
            entrypoint_path=release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py",
            protocol_version="2025-06-18",
            provenance={
                "python_version": "3.10.12",
                "python_implementation": "CPython",
                "platform": "linux",
                "executable": str(release / ".venv/bin/python"),
                "pip_version": "pip 25",
            },
        )

    def test_successful_fake_deploy_switches_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = deploy_runtime.BuildResult(
                release_id="new",
                release_path=new_release,
                python_exe=new_release / ".venv/bin/python",
                entrypoint_path=new_release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py",
                protocol_version="2025-06-18",
                provenance={},
            )
            self._write_manifest(new_release, snapshot, runtime)
            service_values = iter([True, False])

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable"),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "service_active", side_effect=lambda: next(service_values, False)),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv)),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "verify_runtime_identity", return_value={"process": {"pid": 200}, "manifest": {}}),
            ):
                deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), new_release.resolve())

    def test_legacy_migration_rolls_back_to_exact_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            runtime.mkdir()
            (runtime / ".venv").mkdir()
            release = root / "release"
            release.mkdir()
            previous = deploy_runtime.capture_pointer(runtime)
            backup = deploy_runtime.activate_pointer(runtime, release, previous)
            self.assertTrue(runtime.is_symlink())
            deploy_runtime.restore_pointer(runtime, previous, backup)
            self.assertTrue(runtime.is_dir())
            self.assertTrue((runtime / ".venv").is_dir())

    def test_stop_failure_but_inactive_allows_pointer_switch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = deploy_runtime.BuildResult("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)
            service_values = iter([True, False])

            def fake_run(argv, **kwargs):
                if argv[-2:] == ["stop", deploy_runtime.SERVICE]:
                    return self._completed(argv, 1)
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable"),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "service_active", side_effect=lambda: next(service_values, False)),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "verify_runtime_identity", return_value={"process": {"pid": 200}, "manifest": {}}),
            ):
                deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), new_release.resolve())

    def test_stop_failure_and_active_service_keeps_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = deploy_runtime.BuildResult("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable"),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "service_active", return_value=True),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv, 1)),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "active"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "vor Pointermutation"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), old_release.resolve())

    def test_new_start_failure_restores_old_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = deploy_runtime.BuildResult("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)
            service_values = iter([True, False, False])

            def fake_run(argv, **kwargs):
                if "start" in argv:
                    return self._completed(argv, 1)
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable"),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "service_active", side_effect=lambda: next(service_values, False)),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "inactive"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackzustand"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), old_release.resolve())

    def test_process_identity_failure_triggers_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = deploy_runtime.BuildResult("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)
            service_values = iter([True, False, False])

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable"),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "service_active", side_effect=lambda: next(service_values, False)),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv)),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "verify_runtime_identity", side_effect=deploy_runtime.DeployError("identity mismatch")),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "inactive"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackzustand"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), old_release.resolve())

    def test_incomplete_manifest_is_not_schema_valid(self) -> None:
        errors = deploy_runtime.validate_manifest_schema(
            {"schema_version": deploy_runtime.MANIFEST_SCHEMA_VERSION}
        )
        self.assertIn("release_id", errors)

    def test_lock_rejects_duplicate_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock.txt"
            path.write_text(
                "mcp==1.27.2 \\\n"
                "    --hash=sha256:" + "1" * 64 + "\n"
                "MCP==1.27.2 \\\n"
                "    --hash=sha256:" + "2" * 64 + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Doppeltes Paket"):
                deploy_runtime.parse_runtime_lock(path)

    def test_lock_rejects_foreign_continuation_option(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock.txt"
            path.write_text(
                "mcp==1.27.2 \\\n"
                "    --index-url=https://example.invalid/simple\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Fortsetzungsoption"):
                deploy_runtime.parse_runtime_lock(path)

    def test_lock_rejects_bad_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock.txt"
            path.write_text(
                "mcp==1.27.2 \\\n"
                "    --hash=sha256:" + "z" * 64 + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Fortsetzungsoption"):
                deploy_runtime.parse_runtime_lock(path)

    def test_unexpected_installed_distribution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock.txt"
            path.write_text(
                "mcp==1.27.2 \\\n"
                "    --hash=sha256:" + "1" * 64 + "\n",
                encoding="utf-8",
            )
            with patch.object(deploy_runtime, "installed_distributions", return_value={"mcp": "1.27.2", "surprise": "1.0"}):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Unerwartete"):
                    deploy_runtime.verify_installed_distributions(Path("/python"), path)

    def test_command_timeout_becomes_structured_deploy_error(self) -> None:
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 1)

        with patch("subprocess.run", side_effect=timeout):
            with self.assertRaises(deploy_runtime.DeployError) as ctx:
                deploy_runtime.run(["cmd", "--token", "secret"], timeout=1)
        self.assertEqual(ctx.exception.phase, "command-timeout")
        self.assertIn("<redacted>", ctx.exception.details["argv"])

    def test_yaml_parser_ignores_commented_command(self) -> None:
        fake_yaml = types.SimpleNamespace(
            safe_load=lambda text: {"mcp": {"command": "/runtime/.venv/bin/python -m grabowski_mcp"}}
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.yaml"
            path.write_text(
                "# command: /runtime/.venv/bin/python -m wrong\n"
                "mcp:\n"
                "  command: /runtime/.venv/bin/python -m grabowski_mcp\n",
                encoding="utf-8",
            )
            with patch.dict(sys.modules, {"yaml": fake_yaml}):
                argv = deploy_runtime.yaml_profile_command(path)
        self.assertEqual(argv, ["/runtime/.venv/bin/python", "-m", "grabowski_mcp"])


if __name__ == "__main__":
    unittest.main()

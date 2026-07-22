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
TEST_AGENT_INSTRUCTIONS = (
    "Grabowski agent-facing contract grabowski-agent-facing-contract-v1 "
    "(schema 1).\n"
    "1. [truth-hierarchy] Runtime truth first."
)


def load_module():
    spec = importlib.util.spec_from_file_location("deploy_runtime", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("deploy_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_runtime"] = module
    spec.loader.exec_module(module)
    return module


deploy_runtime = load_module()
TEST_AGENT_INSTRUCTIONS_IDENTITY = deploy_runtime.agent_instructions_identity(
    TEST_AGENT_INSTRUCTIONS
)


def _build_result(*args, **kwargs):
    kwargs.setdefault(
        "agent_instructions",
        TEST_AGENT_INSTRUCTIONS_IDENTITY,
    )
    return deploy_runtime.BuildResult(*args, **kwargs)


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

    @staticmethod
    def _obs_active() -> "deploy_runtime.ServiceObservation":
        return deploy_runtime.ServiceObservation(
            query_valid=True,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            main_pid=4321,
            returncode=0,
        )

    @staticmethod
    def _obs_inactive() -> "deploy_runtime.ServiceObservation":
        return deploy_runtime.ServiceObservation(
            query_valid=True,
            load_state="loaded",
            active_state="inactive",
            sub_state="dead",
            main_pid=0,
            returncode=0,
        )

    @staticmethod
    def _obs_unknown() -> "deploy_runtime.ServiceObservation":
        return deploy_runtime.ServiceObservation(
            query_valid=False,
            load_state="unknown",
            active_state="unknown",
            sub_state="unknown",
            main_pid=None,
            returncode=0,
        )

    def _activation(
        self,
        runtime: Path,
        previous: "deploy_runtime.PointerState",
        release_path: Path | None = None,
    ) -> "deploy_runtime.ActivationState":
        return deploy_runtime.ActivationState(
            runtime=runtime,
            release_path=release_path if release_path is not None else runtime.parent / "new",
            previous=previous,
        )

    def test_agent_instructions_identity_is_versioned_hash_bound_and_bounded(self) -> None:
        identity = deploy_runtime.agent_instructions_identity(TEST_AGENT_INSTRUCTIONS)
        self.assertEqual(identity["schema_version"], 1)
        self.assertEqual(identity["version"], "grabowski-agent-facing-contract-v1")
        self.assertEqual(identity["bytes"], len(TEST_AGENT_INSTRUCTIONS.encode("utf-8")))
        self.assertEqual(identity["max_bytes"], 4_096)
        self.assertEqual(len(identity["sha256"]), 64)

    def test_agent_instructions_identity_rejects_missing_header_and_oversize(self) -> None:
        with self.assertRaisesRegex(deploy_runtime.DeployError, "Vertragskopf"):
            deploy_runtime.agent_instructions_identity("not versioned")
        oversized = (
            "Grabowski agent-facing contract grabowski-agent-facing-contract-v1 "
            "(schema 1).\n"
            + "x" * 4_096
        )
        with self.assertRaisesRegex(deploy_runtime.DeployError, "Größenbegrenzung"):
            deploy_runtime.agent_instructions_identity(oversized)

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

    def test_runtime_asset_contract_loads_and_rejects_traversal(self) -> None:
        raw = json.dumps({
            "schema_version": 3, "mode": "module", "module": "grabowski_mcp",
            "source": "src/grabowski_mcp.py", "expected_tools": ["grabowski_status"],
            "supporting_sources": [], "runtime_assets": [{
                "source": "config/coding-agent-catalog.json",
                "destination": "config/coding-agent-catalog.json",
            }],
        }).encode()
        contract = deploy_runtime.load_contract_bytes(raw)
        self.assertEqual(
            contract.runtime_assets[0].destination,
            Path("config/coding-agent-catalog.json"),
        )
        invalid = json.loads(raw)
        invalid["runtime_assets"][0]["destination"] = "../catalog.json"
        with self.assertRaisesRegex(deploy_runtime.DeployError, "repository-relativer"):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())
        invalid = json.loads(raw)
        invalid["runtime_assets"][0]["source"] = "./runtime-entrypoint.json"
        with self.assertRaisesRegex(
            deploy_runtime.DeployError, "reservierten Snapshot-Quellpfad"
        ):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())

    def test_spawn_dependency_contract_loads_and_rejects_open_edges(self) -> None:
        raw = {
            "schema_version": 4,
            "mode": "module",
            "module": "grabowski_mcp",
            "source": "src/grabowski_mcp.py",
            "expected_tools": ["grabowski_status"],
            "supporting_sources": [
                {
                    "module": "grabowski_worker_process",
                    "source": "src/grabowski_worker_process.py",
                }
            ],
            "runtime_assets": [],
            "spawn_dependencies": [
                {
                    "kind": "python_module",
                    "launcher_module": "grabowski_mcp",
                    "spawned_module": "grabowski_worker_process",
                }
            ],
        }
        contract = deploy_runtime.load_contract_bytes(json.dumps(raw).encode())
        self.assertEqual(
            contract.spawn_dependencies[0].spawned_module,
            "grabowski_worker_process",
        )
        self.assertEqual(contract.to_manifest()["spawn_dependencies"], raw["spawn_dependencies"])

        invalid = json.loads(json.dumps(raw))
        invalid["spawn_dependencies"][0]["spawned_module"] = "grabowski_missing"
        with self.assertRaisesRegex(deploy_runtime.DeployError, "Zielmodul"):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())

        invalid = json.loads(json.dumps(raw))
        invalid["spawn_dependencies"].append(dict(invalid["spawn_dependencies"][0]))
        with self.assertRaisesRegex(deploy_runtime.DeployError, "Doppelte Runtime-Spawn-Abhängigkeit"):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())

        invalid = json.loads(json.dumps(raw))
        invalid["schema_version"] = 3
        with self.assertRaisesRegex(deploy_runtime.DeployError, "schema_version 4"):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())

        invalid = json.loads(json.dumps(raw))
        invalid["schema_version"] = 3
        invalid["spawn_dependencies"] = []
        with self.assertRaisesRegex(deploy_runtime.DeployError, "schema_version 4"):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())

        invalid = json.loads(json.dumps(raw))
        del invalid["spawn_dependencies"]
        with self.assertRaisesRegex(deploy_runtime.DeployError, "benötigt spawn_dependencies"):
            deploy_runtime.load_contract_bytes(json.dumps(invalid).encode())

    def test_manifest_validation_rejects_invalid_spawn_dependencies(self) -> None:
        manifest = {
            "entrypoint_contract": {
                "schema_version": 4,
                "mode": "module",
                "module": "grabowski_mcp",
                "source": "src/grabowski_mcp.py",
                "expected_tools": ["grabowski_status"],
                "supporting_sources": [],
                "runtime_assets": [],
                "spawn_dependencies": [
                    {
                        "kind": "python_module",
                        "launcher_module": "grabowski_mcp",
                        "spawned_module": "grabowski_missing",
                    }
                ],
            }
        }
        errors = deploy_runtime.validate_manifest_schema(manifest)
        self.assertIn("entrypoint_contract", errors)

    def test_manifest_validation_handles_invalid_supporting_sources_fail_closed(self) -> None:
        manifest = {
            "entrypoint_contract": {
                "schema_version": 3,
                "mode": "module",
                "module": "grabowski_mcp",
                "source": "src/grabowski_mcp.py",
                "expected_tools": ["grabowski_status"],
                "supporting_sources": "invalid",
                "runtime_assets": [],
            }
        }
        errors = deploy_runtime.validate_manifest_schema(manifest)
        self.assertIn("entrypoint_contract", errors)

    def test_script_entrypoint_contract_is_rejected(self) -> None:
        raw = json.dumps(
            {
                "schema_version": 1,
                "mode": "script",
                "script": "grabowski_mcp.py",
                "source": "src/grabowski_mcp.py",
                "expected_tools": ["grabowski_status"],
            }
        ).encode()
        with self.assertRaisesRegex(deploy_runtime.DeployError, "Nicht unterstützter"):
            deploy_runtime.load_contract_bytes(raw)

    def test_managed_path_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allowed = Path(directory) / "home" / "alex"
            allowed.mkdir(parents=True)
            (Path(directory) / "tmp").mkdir()
            path = allowed / "../../tmp/grabowski-mcp"
            with self.assertRaisesRegex(deploy_runtime.DeployError, "außerhalb"):
                deploy_runtime.normalize_managed_path(path, allowed_root=allowed)

    def test_managed_path_rejects_similar_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "home" / "alex"
            allowed.mkdir(parents=True)
            other = root / "home" / "alex-other"
            other.mkdir(parents=True)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "außerhalb"):
                deploy_runtime.normalize_managed_path(
                    other / "grabowski-mcp",
                    allowed_root=allowed,
                )

    def test_managed_path_rejects_symlinked_parent_outside_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside"
            outside.mkdir()
            link_parent = allowed / "link-to-outside"
            link_parent.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "außerhalb"):
                deploy_runtime.normalize_managed_path(
                    link_parent / "grabowski-mcp",
                    allowed_root=allowed,
                )

    def test_runtime_symlink_component_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allowed = Path(directory) / "allowed"
            allowed.mkdir()
            release = allowed / "release"
            release.mkdir()
            runtime = allowed / "grabowski-mcp"
            runtime.symlink_to(release, target_is_directory=True)
            normalized = deploy_runtime.require_runtime_replaceable(
                runtime,
                allowed_root=allowed,
            )
            self.assertEqual(normalized, runtime)

    def test_releases_root_symlink_is_rejected_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allowed = Path(directory) / "allowed"
            allowed.mkdir()
            outside = Path(directory) / "outside"
            outside.mkdir()
            runtime = allowed / "grabowski-mcp"
            releases = allowed / deploy_runtime.RELEASES_DIR_NAME
            releases.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Releases-Root"):
                deploy_runtime.require_runtime_replaceable(
                    runtime,
                    allowed_root=allowed,
                )
            self.assertFalse(runtime.exists())

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
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
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
            (proc / "100" / "task" / "101").mkdir(parents=True)
            (proc / "100" / "task" / "100" / "children").write_text("", encoding="utf-8")
            (proc / "100" / "task" / "101" / "children").write_text("200\n", encoding="utf-8")
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

    def test_child_pids_aggregates_all_thread_children_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            for tid in (100, 101, 102):
                (proc / "100" / "task" / str(tid)).mkdir(parents=True)
            (proc / "100" / "task" / "100" / "children").write_text(
                "300 200\n", encoding="utf-8"
            )
            (proc / "100" / "task" / "101" / "children").write_text(
                "200 400\n", encoding="utf-8"
            )
            (proc / "100" / "task" / "102" / "children").write_text(
                "", encoding="utf-8"
            )

            self.assertEqual(
                deploy_runtime.child_pids(100, proc),
                [200, 300, 400],
            )

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

    def test_runtime_venv_builder_uses_base_python_outside_active_venv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "deploy-tooling" / ".venv"
            active_python = active / "bin" / "python"
            base_python = root / "system-python"
            active_python.parent.mkdir(parents=True)
            active_python.write_text("", encoding="utf-8")
            base_python.write_text("", encoding="utf-8")

            with (
                patch.object(deploy_runtime.sys, "prefix", str(active)),
                patch.object(deploy_runtime.sys, "base_prefix", str(root / "base-prefix")),
                patch.object(deploy_runtime.sys, "executable", str(active_python)),
                patch.object(deploy_runtime.sys, "_base_executable", str(base_python), create=True),
            ):
                self.assertEqual(
                    deploy_runtime.runtime_venv_builder_python(),
                    base_python.resolve(),
                )

    def test_runtime_venv_builder_rejects_only_active_venv_python(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "deploy-tooling" / ".venv"
            active_python = active / "bin" / "python"
            active_python.parent.mkdir(parents=True)
            active_python.write_text("", encoding="utf-8")

            with (
                patch.object(deploy_runtime.sys, "prefix", str(active)),
                patch.object(deploy_runtime.sys, "base_prefix", str(root / "base-prefix")),
                patch.object(deploy_runtime.sys, "executable", str(active_python)),
                patch.object(deploy_runtime.sys, "_base_executable", "", create=True),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Basis-Python"):
                    deploy_runtime.runtime_venv_builder_python()

    def test_build_release_creates_venv_at_final_release_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = self._snapshot()
            active = root / "deploy-tooling" / ".venv"
            active_python = active / "bin" / "python"
            base_python = root / "system-python"
            active_python.parent.mkdir(parents=True)
            active_python.write_text("", encoding="utf-8")
            base_python.write_text("", encoding="utf-8")
            created_venv: list[Path] = []
            venv_argv: list[list[str]] = []

            def fake_run(argv, **kwargs):
                if argv[1:3] == ["-m", "venv"]:
                    venv_argv.append(list(argv))
                    if argv[0] == str(base_python.resolve()):
                        venv = Path(argv[3])
                        created_venv.append(venv)
                        (venv / "bin").mkdir(parents=True)
                        (venv / "bin/python").write_text("", encoding="utf-8")
                return self._completed(argv)

            with (
                patch.object(deploy_runtime.sys, "prefix", str(active)),
                patch.object(deploy_runtime.sys, "base_prefix", str(root / "base-prefix")),
                patch.object(deploy_runtime.sys, "executable", str(active_python)),
                patch.object(deploy_runtime.sys, "_base_executable", str(base_python), create=True),
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "site_packages_path", side_effect=lambda python: python.parents[1] / "lib/python3.10/site-packages"),
                patch.object(deploy_runtime, "verify_installed_distributions"),
                patch.object(deploy_runtime, "import_module_path", side_effect=lambda python, module: python.parents[1] / "lib/python3.10/site-packages/grabowski_mcp.py"),
                patch.object(
                    deploy_runtime,
                    "probe_mcp",
                    return_value=deploy_runtime.MCPProbeResult(
                        protocol_version="2025-06-18",
                        agent_instructions=deploy_runtime.agent_instructions_identity(
                            TEST_AGENT_INSTRUCTIONS
                        ),
                    ),
                ),
                patch.object(deploy_runtime, "python_provenance", return_value={"python_version": "3.10.12", "python_implementation": "CPython", "platform": "linux", "executable": "python", "pip_version": "pip 25"}),
            ):
                result = deploy_runtime.build_release(
                    snapshot,
                    root / deploy_runtime.RELEASES_DIR_NAME,
                    root / "grabowski-mcp",
                )

            self.assertEqual(venv_argv, [[str(base_python.resolve()), "-m", "venv", str(result.release_path / ".venv")]])
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
            state_root = Path(directory)
            lock = state_root / "deploy.lock"
            with self.assertRaises(RuntimeError):
                with deploy_runtime.deployment_lock(lock, state_root=state_root):
                    raise RuntimeError("boom")
            with deploy_runtime.deployment_lock(lock, state_root=state_root):
                pass

    def test_deployment_lock_rejects_symlink_final_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            target = state_root / "real-target"
            target.write_text("x\n", encoding="utf-8")
            lock = state_root / "deploy.lock"
            lock.symlink_to(target)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Symlink"):
                with deploy_runtime.deployment_lock(lock, state_root=state_root):
                    pass

    def test_deployment_lock_rejects_fifo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            lock = state_root / "deploy.lock"
            os.mkfifo(lock)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "reguläre Datei"):
                with deploy_runtime.deployment_lock(lock, state_root=state_root):
                    pass

    def test_deployment_lock_rejects_path_outside_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory) / "state"
            state_root.mkdir()
            outside = Path(directory) / "elsewhere"
            outside.mkdir()
            lock = outside / "deploy.lock"
            with self.assertRaisesRegex(deploy_runtime.DeployError, "außerhalb|State-Root"):
                with deploy_runtime.deployment_lock(lock, state_root=state_root):
                    pass

    def test_deployment_lock_rejects_symlinked_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            real_root = Path(directory) / "real"
            real_root.mkdir()
            linked_root = Path(directory) / "linked"
            linked_root.symlink_to(real_root, target_is_directory=True)
            lock = linked_root / "deploy.lock"
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Symlink"):
                with deploy_runtime.deployment_lock(lock, state_root=linked_root):
                    pass

    def _write_manifest(self, release: Path, snapshot: deploy_runtime.Snapshot, runtime: Path) -> None:
        deploy_runtime.write_manifest(
            release,
            release_id=release.name,
            snapshot=snapshot,
            stable_runtime=runtime,
            input_paths={
                "runtime_entrypoint": str(release / "inputs/runtime-entrypoint.json"),
                "runtime_input": str(release / "inputs/runtime.in"),
                "runtime_lock": str(release / "inputs/runtime.lock.txt"),
                "source": str(release / "inputs/src/grabowski_mcp.py"),
                "supporting_sources": {},
                "runtime_assets": {
                    item.destination.as_posix(): str(release / "inputs" / item.source)
                    for item in snapshot.contract.runtime_assets
                },
            },
            entrypoint_path=release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py",
            module_paths={
                snapshot.contract.module: release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py"
            },
            runtime_asset_paths={
                item.destination.as_posix(): release / item.destination
                for item in snapshot.contract.runtime_assets
            },
            protocol_version="2025-06-18",
            agent_instructions=deploy_runtime.agent_instructions_identity(
                TEST_AGENT_INSTRUCTIONS
            ),
            provenance={
                "python_version": "3.10.12",
                "python_implementation": "CPython",
                "platform": "linux",
                "executable": str(release / ".venv/bin/python"),
                "pip_version": "pip 25",
            },
        )

    def test_runtime_asset_installation_is_exact_and_payload_mismatch_fails(self) -> None:
        contract = deploy_runtime.RuntimeContract(
            schema_version=3,
            mode="module",
            module="grabowski_mcp",
            source=Path("src/grabowski_mcp.py"),
            expected_tools=("grabowski_status",),
            runtime_assets=(
                deploy_runtime.RuntimeAsset(
                    source=Path("config/coding-agent-catalog.json"),
                    destination=Path("config/coding-agent-catalog.json"),
                ),
            ),
        )
        snapshot = deploy_runtime.Snapshot(
            repo_head="a" * 40,
            dirty=False,
            contract=contract,
            contract_bytes=json.dumps(contract.to_manifest()).encode(),
            runtime_input_bytes=b"mcp==1.27.2\n",
            runtime_lock_bytes=b"mcp==1.27.2\n",
            source_bytes=b"print('snapshot')\n",
            runtime_asset_bytes={
                "config/coding-agent-catalog.json": b"{\"schema_version\": 2}\n"
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            release.mkdir()
            installed = deploy_runtime.install_runtime_assets(snapshot, release)
            target = release / "config/coding-agent-catalog.json"
            self.assertEqual(installed, {"config/coding-agent-catalog.json": target})
            self.assertEqual(
                target.read_bytes(),
                snapshot.runtime_asset_bytes["config/coding-agent-catalog.json"],
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        mismatch = deploy_runtime.Snapshot(
            repo_head=snapshot.repo_head,
            dirty=False,
            contract=contract,
            contract_bytes=snapshot.contract_bytes,
            runtime_input_bytes=snapshot.runtime_input_bytes,
            runtime_lock_bytes=snapshot.runtime_lock_bytes,
            source_bytes=snapshot.source_bytes,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(deploy_runtime.DeployError, "stimmt nicht"):
                deploy_runtime.write_snapshot_inputs(mismatch, Path(directory) / "release")

    def test_runtime_asset_is_bound_to_release_identity_and_final_readback(self) -> None:
        contract = deploy_runtime.RuntimeContract(
            schema_version=3, mode="module", module="grabowski_mcp",
            source=Path("src/grabowski_mcp.py"), expected_tools=("grabowski_status",),
            runtime_assets=(deploy_runtime.RuntimeAsset(
                source=Path("config/coding-agent-catalog.json"),
                destination=Path("config/coding-agent-catalog.json"),
            ),),
        )
        snapshot = deploy_runtime.Snapshot(
            repo_head="a" * 40, dirty=False, contract=contract,
            contract_bytes=json.dumps(contract.to_manifest()).encode(),
            runtime_input_bytes=b"mcp==1.27.2\n",
            runtime_lock_bytes=b"mcp==1.27.2\n",
            source_bytes=b"print('snapshot')\n",
            runtime_asset_bytes={"config/coding-agent-catalog.json": b"{\"schema_version\": 2}\n"},
        )
        changed = deploy_runtime.Snapshot(
            repo_head=snapshot.repo_head, dirty=False, contract=contract,
            contract_bytes=snapshot.contract_bytes,
            runtime_input_bytes=snapshot.runtime_input_bytes,
            runtime_lock_bytes=snapshot.runtime_lock_bytes, source_bytes=snapshot.source_bytes,
            runtime_asset_bytes={"config/coding-agent-catalog.json": b"{}\n"},
        )
        self.assertNotEqual(
            deploy_runtime.release_id_base(snapshot),
            deploy_runtime.release_id_base(changed),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); release = root / "release"; release.mkdir()
            runtime = root / "grabowski-mcp"; runtime.symlink_to(release)
            module = self._write_complete_release(release, snapshot, runtime)
            self._verify_complete_release(release, runtime, snapshot, module)
            (release / "config/coding-agent-catalog.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(deploy_runtime.DeployError, "driftete"):
                self._verify_complete_release(release, runtime, snapshot, module)

    def test_write_manifest_is_private_and_umask_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            snapshot = self._snapshot()
            previous_umask = os.umask(0o022)
            try:
                self._write_manifest(release, snapshot, runtime)
            finally:
                os.umask(previous_umask)
            manifest = release / deploy_runtime.MANIFEST_NAME
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest.stat().st_nlink, 1)
            self.assertEqual(
                json.loads(manifest.read_text(encoding="utf-8"))["repo_head"],
                snapshot.repo_head,
            )

    def test_write_manifest_rejects_symlink_target_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            target = root / "target.json"
            target.write_text("unchanged\n", encoding="utf-8")
            (release / deploy_runtime.MANIFEST_NAME).symlink_to(target)
            with self.assertRaisesRegex(
                deploy_runtime.DeployError, "nicht sicher ersetzbar"
            ):
                self._write_manifest(release, self._snapshot(), runtime)
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged\n")

    def _write_complete_release(
        self,
        release: Path,
        snapshot: deploy_runtime.Snapshot,
        runtime: Path,
    ) -> Path:
        (release / "inputs/src").mkdir(parents=True)
        (release / "inputs/runtime-entrypoint.json").write_bytes(snapshot.contract_bytes)
        (release / "inputs/runtime.in").write_bytes(snapshot.runtime_input_bytes)
        (release / "inputs/runtime.lock.txt").write_bytes(snapshot.runtime_lock_bytes)
        (release / "inputs/src/grabowski_mcp.py").write_bytes(snapshot.source_bytes)
        for item in snapshot.contract.runtime_assets:
            destination = item.destination.as_posix()
            data = snapshot.runtime_asset_bytes[destination]
            snapshot_target = release / "inputs" / item.source
            snapshot_target.parent.mkdir(parents=True, exist_ok=True)
            snapshot_target.write_bytes(data)
            installed_target = release / item.destination
            installed_target.parent.mkdir(parents=True, exist_ok=True)
            installed_target.write_bytes(data)
        python = release / ".venv/bin/python"
        python.parent.mkdir(parents=True)
        python.write_text("", encoding="utf-8")
        module = release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py"
        module.parent.mkdir(parents=True)
        module.write_bytes(snapshot.source_bytes)
        self._write_manifest(release, snapshot, runtime)
        return module

    def _verify_complete_release(
        self,
        release: Path,
        runtime: Path,
        snapshot: deploy_runtime.Snapshot,
        module: Path,
    ) -> None:
        manifest = deploy_runtime.read_manifest(release)
        python = release / ".venv/bin/python"
        with (
            patch.object(deploy_runtime, "import_module_path", return_value=module),
            patch.object(deploy_runtime, "site_packages_path", return_value=module.parent),
        ):
            deploy_runtime.verify_final_release_artifacts(
                release,
                runtime,
                snapshot.contract,
                snapshot=snapshot,
                manifest=manifest,
                process={"exe": str(python)},
            )

    def test_verify_manifest_rejects_agent_instructions_handshake_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            self._write_complete_release(release, snapshot, runtime)
            expected = deploy_runtime.agent_instructions_identity(
                TEST_AGENT_INSTRUCTIONS
            )
            manifest_path = release / deploy_runtime.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["agent_instructions"]["sha256"] = "f" * 64
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                deploy_runtime.DeployError,
                "agent_instructions",
            ):
                deploy_runtime.verify_manifest(
                    release,
                    snapshot=snapshot,
                    stable_runtime=runtime,
                    expected_agent_instructions=expected,
                )

    def test_deploy_rejects_agent_instructions_drift_before_pointer_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = _build_result(
                release_id="new",
                release_path=new_release,
                python_exe=new_release / ".venv/bin/python",
                entrypoint_path=new_release / "module.py",
                protocol_version="2025-06-18",
                provenance={},
            )
            self._write_manifest(new_release, snapshot, runtime)
            manifest_path = new_release / deploy_runtime.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["agent_instructions"]["sha256"] = "f" * 64
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "capture_pointer") as capture_pointer,
            ):
                with self.assertRaisesRegex(
                    deploy_runtime.DeployError,
                    "agent_instructions",
                ):
                    deploy_runtime.deploy(
                        ROOT,
                        runtime,
                        root / "profile.yaml",
                        timeout_seconds=1,
                    )
            capture_pointer.assert_not_called()

    def test_final_identity_accepts_complete_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            self._verify_complete_release(release, runtime, snapshot, module)

    def test_final_identity_rejects_source_snapshot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            (release / "inputs/src/grabowski_mcp.py").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(deploy_runtime.DeployError, "driftete"):
                self._verify_complete_release(release, runtime, snapshot, module)

    def test_final_identity_rejects_lock_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            (release / "inputs/runtime.lock.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(deploy_runtime.DeployError, "driftete"):
                self._verify_complete_release(release, runtime, snapshot, module)

    def test_final_identity_rejects_contract_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            (release / "inputs/runtime-entrypoint.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(deploy_runtime.DeployError, "driftete"):
                self._verify_complete_release(release, runtime, snapshot, module)

    def test_final_identity_rejects_manifest_path_outside_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            manifest = deploy_runtime.read_manifest(release)
            outside = root / "outside.lock"
            outside.write_text("x\n", encoding="utf-8")
            manifest["snapshot_paths"]["runtime_lock"] = str(outside)
            with (
                patch.object(deploy_runtime, "import_module_path", return_value=module),
                patch.object(deploy_runtime, "site_packages_path", return_value=module.parent),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Snapshotpfad"):
                    deploy_runtime.verify_final_release_artifacts(
                        release,
                        runtime,
                        snapshot.contract,
                        snapshot=snapshot,
                        manifest=manifest,
                        process={"exe": str(release / ".venv/bin/python")},
                    )

    def test_final_identity_rejects_unexpected_module_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            other = release / ".venv/lib/python3.10/site-packages/other.py"
            other.write_bytes(snapshot.source_bytes)
            manifest = deploy_runtime.read_manifest(release)
            with (
                patch.object(deploy_runtime, "import_module_path", return_value=other),
                patch.object(deploy_runtime, "site_packages_path", return_value=module.parent),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Modulpfad"):
                    deploy_runtime.verify_final_release_artifacts(
                        release,
                        runtime,
                        snapshot.contract,
                        snapshot=snapshot,
                        manifest=manifest,
                        process={"exe": str(release / ".venv/bin/python")},
                    )

    def test_final_identity_rejects_module_bytes_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            module.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Moduldatei"):
                self._verify_complete_release(release, runtime, snapshot, module)

    def test_final_identity_rejects_changed_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            other = root / "other"
            release.mkdir()
            other.mkdir()
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release)
            snapshot = self._snapshot()
            module = self._write_complete_release(release, snapshot, runtime)
            runtime.unlink()
            runtime.symlink_to(other)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Symlink"):
                self._verify_complete_release(release, runtime, snapshot, module)

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
            build = _build_result(
                release_id="new",
                release_path=new_release,
                python_exe=new_release / ".venv/bin/python",
                entrypoint_path=new_release / ".venv/lib/python3.10/site-packages/grabowski_mcp.py",
                protocol_version="2025-06-18",
                provenance={},
            )
            self._write_manifest(new_release, snapshot, runtime)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
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
            self.assertEqual(previous.kind, "directory")
            self.assertIsNotNone(previous.ino)
            original_ino = previous.ino
            state = self._activation(runtime, previous, release_path=release)
            deploy_runtime.activate_pointer(state)
            self.assertTrue(runtime.is_symlink())
            self.assertTrue(state.legacy_renamed)
            self.assertTrue(state.symlink_replaced)
            deploy_runtime.restore_pointer(state)
            self.assertTrue(runtime.is_dir())
            self.assertFalse(runtime.is_symlink())
            self.assertTrue((runtime / ".venv").is_dir())
            self.assertEqual(deploy_runtime.directory_identity(runtime)[1], original_ino)

    def test_activate_pointer_does_not_self_rollback_between_rename_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            runtime.mkdir()
            (runtime / "marker").write_text("payload\n", encoding="utf-8")
            release = root / "release"
            release.mkdir()
            previous = deploy_runtime.capture_pointer(runtime)
            state = self._activation(runtime, previous, release_path=release)

            with patch.object(
                deploy_runtime,
                "atomic_symlink_replace",
                side_effect=OSError("symlink replace failed"),
            ):
                with self.assertRaises(OSError):
                    deploy_runtime.activate_pointer(state)

            # No hidden rollback: runtime is gone, legacy backup holds the dir.
            self.assertTrue(state.legacy_renamed)
            self.assertFalse(state.symlink_replaced)
            self.assertFalse(runtime.exists())
            self.assertIsNotNone(state.legacy_backup)
            self.assertTrue((state.legacy_backup / "marker").is_file())

            # The explicit rollback owner repairs the directory exactly.
            deploy_runtime.restore_pointer(state)
            self.assertTrue(runtime.is_dir())
            self.assertTrue((runtime / "marker").is_file())
            self.assertEqual(
                deploy_runtime.directory_identity(runtime)[1], previous.ino
            )

    def test_restore_pointer_is_idempotent_for_already_restored_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            runtime.mkdir()
            previous = deploy_runtime.capture_pointer(runtime)
            state = self._activation(runtime, previous, release_path=root / "release")
            # Pointer never moved; legacy_backup is None. Idempotent accept.
            deploy_runtime.restore_pointer(state)
            self.assertTrue(runtime.is_dir())
            self.assertEqual(
                deploy_runtime.directory_identity(runtime)[1], previous.ino
            )

    def test_restore_pointer_rejects_wrong_inode_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            runtime.mkdir()
            previous = deploy_runtime.capture_pointer(runtime)
            release = root / "release"
            release.mkdir()
            state = self._activation(runtime, previous, release_path=release)
            deploy_runtime.activate_pointer(state)
            # Replace the legacy backup with a different directory (wrong inode).
            impostor = root / "impostor"
            impostor.mkdir()
            assert state.legacy_backup is not None
            import shutil as _shutil
            _shutil.rmtree(state.legacy_backup)
            impostor.rename(state.legacy_backup)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "(?i)identität"):
                deploy_runtime.restore_pointer(state)

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
            build = _build_result("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)

            def fake_run(argv, **kwargs):
                if argv[-2:] == ["stop", deploy_runtime.SERVICE]:
                    return self._completed(argv, 1)
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
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
            build = _build_result("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_active()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv, 1)),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackabbruch"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), old_release.resolve())

    def test_pre_pointer_activation_failure_recovers_old_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = _build_result("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)
            live_entrypoint = deploy_runtime.EntryPoint(
                mode="module",
                python=runtime / ".venv/bin/python",
                module="grabowski_mcp",
            )

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract", return_value=live_entrypoint),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv)),
                patch.object(deploy_runtime, "activate_pointer", side_effect=deploy_runtime.DeployError("activate failed")),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)) as wait_ready,
                patch.object(deploy_runtime, "verify_running_profile_entrypoint", return_value={"pid": 200}) as verify_previous,
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackzustand"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), old_release.resolve())
            wait_ready.assert_called()
            verify_previous.assert_called_once_with(live_entrypoint)

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
            build = _build_result("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)

            def fake_run(argv, **kwargs):
                if "start" in argv:
                    return self._completed(argv, 1)
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
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
            build = _build_result("new", new_release, new_release / ".venv/bin/python", new_release / "module.py", "2025-06-18", {})
            self._write_manifest(new_release, snapshot, runtime)

            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract"),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv)),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "verify_runtime_identity", side_effect=deploy_runtime.DeployError("identity mismatch")),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackzustand"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(runtime.resolve(), old_release.resolve())

    def test_rollback_stop_timeout_preserves_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            old.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)

            def fake_run(argv, **kwargs):
                if "stop" in argv:
                    raise deploy_runtime.DeployError(
                        "token=FAKE-SECRET timeout",
                        phase="command-timeout",
                        details={"argv": argv, "timeout_seconds": 1},
                    )
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "active"}),
            ):
                with self.assertRaises(deploy_runtime.DeployError) as ctx:
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original root cause"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="start",
                    )
            message = str(ctx.exception)
            self.assertIn("original root cause", message)
            self.assertIn("rollback-stop-command", message)
            self.assertNotIn("FAKE-SECRET", message)

    def test_rollback_unknown_service_state_does_not_restore_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            old.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)
            with (
                patch.object(deploy_runtime, "run", return_value=self._completed(["stop"])),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", side_effect=deploy_runtime.DeployError("state failed")),
                patch.object(deploy_runtime, "restore_pointer") as restore_pointer,
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "unknown"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackabbruch"):
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="stop",
                    )
            restore_pointer.assert_not_called()

    def test_rollback_active_service_does_not_restore_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            old.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)
            with (
                patch.object(deploy_runtime, "run", return_value=self._completed(["stop"])),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_active()),
                patch.object(deploy_runtime, "restore_pointer") as restore_pointer,
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "active"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackabbruch"):
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="stop",
                    )
            restore_pointer.assert_not_called()

    def test_rollback_pointer_restore_exception_skips_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            old.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)
            calls: list[list[str]] = []

            def fake_run(argv, **kwargs):
                calls.append(argv)
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "restore_pointer", side_effect=OSError("restore failed")),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "inactive"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Restorefehler"):
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="start",
                    )
            self.assertFalse(any("start" in argv for argv in calls))

    def test_rollback_pointer_restore_mismatch_skips_start(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)
            runtime.unlink()
            runtime.symlink_to(new)
            calls: list[list[str]] = []

            def fake_run(argv, **kwargs):
                calls.append(argv)
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "restore_pointer", return_value=None),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "inactive"}),
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Pointerverifikationsfehler"):
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="start",
                    )
            self.assertFalse(any("start" in argv for argv in calls))

    def test_rollback_start_timeout_is_aggregated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            old.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)

            def fake_run(argv, **kwargs):
                if "start" in argv:
                    raise deploy_runtime.DeployError(
                        "start timeout",
                        phase="command-timeout",
                        details={"argv": argv, "timeout_seconds": 1},
                    )
                return self._completed(argv)

            with (
                patch.object(deploy_runtime, "run", side_effect=fake_run),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "service_state", return_value={"ActiveState": "inactive"}),
            ):
                with self.assertRaises(deploy_runtime.DeployError) as ctx:
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="readiness",
                    )
            self.assertIn("rollback-start-command", str(ctx.exception))

    def test_rollback_readiness_and_final_state_errors_are_aggregated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old = root / "old"
            old.mkdir()
            runtime.symlink_to(old)
            previous = deploy_runtime.capture_pointer(runtime)
            with (
                patch.object(deploy_runtime, "run", return_value=self._completed(["cmd"])),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "wait_until_ready", side_effect=deploy_runtime.DeployError("ready failed")),
                patch.object(deploy_runtime, "service_state", side_effect=deploy_runtime.DeployError("final failed")),
            ):
                with self.assertRaises(deploy_runtime.DeployError) as ctx:
                    deploy_runtime.rollback_after_failure(
                        deploy_runtime.DeployError("original"),
                        activation=self._activation(runtime, previous),
                        timeout_seconds=1,
                        phase="identity",
                    )
            message = str(ctx.exception)
            self.assertIn("rollback-readiness", message)
            self.assertIn("rollback-final-service-state", message)

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

    def test_direct_pin_version_mismatch_is_rejected(self) -> None:
        snapshot = self._snapshot()
        snapshot = deploy_runtime.Snapshot(
            repo_head=snapshot.repo_head,
            dirty=snapshot.dirty,
            contract=snapshot.contract,
            contract_bytes=snapshot.contract_bytes,
            runtime_input_bytes=b"mcp==1.27.2\nexample==1.0\n",
            runtime_lock_bytes=(
                b"mcp==1.27.2 \\\n"
                b"    --hash=sha256:" + b"1" * 64 + b"\n"
                b"example==2.0 \\\n"
                b"    --hash=sha256:" + b"2" * 64 + b"\n"
            ),
            source_bytes=snapshot.source_bytes,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Direkte Pins"):
                deploy_runtime.build_release(
                    snapshot,
                    root / deploy_runtime.RELEASES_DIR_NAME,
                    root / "grabowski-mcp",
                )

    def test_mark_incomplete_redacts_fake_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            deploy_runtime.mark_incomplete(
                release,
                "test",
                RuntimeError("token=FAKE-SECRET-VALUE should not persist"),
            )
            marker = (release / deploy_runtime.INCOMPLETE_MARKER).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("FAKE-SECRET-VALUE", marker)
            self.assertIn("<redacted>", marker)

    def test_command_timeout_becomes_structured_deploy_error(self) -> None:
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 1)

        with patch("subprocess.run", side_effect=timeout):
            with self.assertRaises(deploy_runtime.DeployError) as ctx:
                deploy_runtime.run(["cmd", "--token", "secret"], timeout=1)
        self.assertEqual(ctx.exception.phase, "command-timeout")
        self.assertIn("<redacted>", ctx.exception.details["argv"])

    def test_check_mode_does_not_validate_default_runtime_parent(self) -> None:
        args = types.SimpleNamespace(
            repo=ROOT,
            runtime=Path("/missing-home/.local/share/grabowski-mcp"),
            profile_path=Path("/unused-profile.yaml"),
            lock_file=Path("/unused-lock"),
            timeout=1,
            check=True,
            apply=False,
        )
        with (
            patch.object(deploy_runtime, "parse_args", return_value=args),
            patch.object(deploy_runtime, "check", return_value=None) as check,
            patch.object(deploy_runtime, "normalize_managed_path", side_effect=AssertionError("should not normalize")),
        ):
            self.assertEqual(deploy_runtime.main(), 0)
        check.assert_called_once()

    def test_yaml_parser_ignores_commented_command(self) -> None:
        fake_yaml = types.SimpleNamespace(
            __version__=deploy_runtime.TOOLING_PYYAML_VERSION,
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

    def test_yaml_parser_requires_pinned_dependency(self) -> None:
        fake_yaml = types.SimpleNamespace(
            __version__="0.0",
            safe_load=lambda text: {"mcp": {"command": "x"}},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.yaml"
            path.write_text("mcp:\n  command: x\n", encoding="utf-8")
            with patch.dict(sys.modules, {"yaml": fake_yaml}):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "PyYAML-Version"):
                    deploy_runtime.yaml_profile_command(path)

    def test_yaml_parser_rejects_multiple_commands(self) -> None:
        fake_yaml = types.SimpleNamespace(
            __version__=deploy_runtime.TOOLING_PYYAML_VERSION,
            safe_load=lambda text: {
                "mcp": {"command": "one"},
                "nested": {"command": "two"},
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.yaml"
            path.write_text("ignored\n", encoding="utf-8")
            with patch.dict(sys.modules, {"yaml": fake_yaml}):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "genau einen"):
                    deploy_runtime.yaml_profile_command(path)

    def test_yaml_parser_accepts_command_list(self) -> None:
        fake_yaml = types.SimpleNamespace(
            __version__=deploy_runtime.TOOLING_PYYAML_VERSION,
            safe_load=lambda text: {
                "mcp": {"command": ["/runtime/.venv/bin/python", "-m", "grabowski_mcp"]}
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.yaml"
            path.write_text("ignored\n", encoding="utf-8")
            with patch.dict(sys.modules, {"yaml": fake_yaml}):
                argv = deploy_runtime.yaml_profile_command(path)
        self.assertEqual(argv, ["/runtime/.venv/bin/python", "-m", "grabowski_mcp"])

    def test_yaml_parser_error_does_not_include_profile_secret(self) -> None:
        class FakeYamlError(Exception):
            problem_mark = types.SimpleNamespace(line=4, column=2)

        fake_yaml = types.SimpleNamespace(
            __version__=deploy_runtime.TOOLING_PYYAML_VERSION,
            safe_load=lambda text: (_ for _ in ()).throw(
                FakeYamlError("token=FAKE-SECRET in profile")
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.yaml"
            path.write_text("token: FAKE-SECRET\n", encoding="utf-8")
            with patch.dict(sys.modules, {"yaml": fake_yaml}):
                with self.assertRaises(deploy_runtime.DeployError) as ctx:
                    deploy_runtime.yaml_profile_command(path)
        self.assertNotIn("FAKE-SECRET", str(ctx.exception))
        self.assertEqual(ctx.exception.details["line"], 5)


    def test_observe_service_accepts_only_complete_active_state(self) -> None:
        output = (
            "LoadState=loaded\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "MainPID=4321\n"
        )
        completed = subprocess.CompletedProcess(["systemctl"], 0, output, "")
        with patch.object(deploy_runtime, "run", return_value=completed):
            observation = deploy_runtime.observe_service()
        self.assertTrue(observation.query_valid)
        self.assertTrue(observation.confirmed_active)
        self.assertFalse(observation.confirmed_inactive)

    def test_observe_service_accepts_only_complete_inactive_state(self) -> None:
        output = (
            "LoadState=loaded\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "MainPID=0\n"
        )
        completed = subprocess.CompletedProcess(["systemctl"], 0, output, "")
        with patch.object(deploy_runtime, "run", return_value=completed):
            observation = deploy_runtime.observe_service()
        self.assertTrue(observation.query_valid)
        self.assertFalse(observation.confirmed_active)
        self.assertTrue(observation.confirmed_inactive)

    def test_observe_service_rejects_unknown_and_transitional_states(self) -> None:
        cases = (
            (4, "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\n"),
            (0, "LoadState=loaded\nActiveState=deactivating\nSubState=stop-sigterm\nMainPID=4321\n"),
            (0, "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=4321\n"),
            (0, "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"),
            (0, "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=bad\n"),
        )
        for returncode, output in cases:
            with self.subTest(returncode=returncode, output=output):
                completed = subprocess.CompletedProcess(
                    ["systemctl"], returncode, output, ""
                )
                with patch.object(deploy_runtime, "run", return_value=completed):
                    observation = deploy_runtime.observe_service()
                self.assertFalse(observation.confirmed_active)
                self.assertFalse(observation.confirmed_inactive)

    def test_wait_until_confirmed_inactive_polls_transitional_state(self) -> None:
        observations = iter(
            [
                deploy_runtime.ServiceObservation(
                    query_valid=True,
                    load_state="loaded",
                    active_state="deactivating",
                    sub_state="stop-sigterm",
                    main_pid=4321,
                    returncode=0,
                ),
                self._obs_inactive(),
            ]
        )
        with (
            patch.object(deploy_runtime, "observe_service", side_effect=observations),
            patch.object(deploy_runtime.time, "sleep", return_value=None),
        ):
            observation = deploy_runtime.wait_until_confirmed_inactive(1)
        self.assertTrue(observation.confirmed_inactive)


    def test_readiness_requires_confirmed_active_service(self) -> None:
        observation = deploy_runtime.ServiceObservation(
            query_valid=False,
            load_state="loaded",
            active_state="active",
            sub_state="running",
            main_pid=0,
            returncode=0,
        )
        with (
            patch.object(deploy_runtime, "observe_service", return_value=observation),
            patch.object(deploy_runtime, "http_text", side_effect=["live", "ready"]),
        ):
            result = deploy_runtime.readiness_probe()
        self.assertFalse(result.ok)
        self.assertEqual(result.main_pid, 0)
        self.assertFalse(result.service["confirmed_active"])

    def test_readiness_accepts_only_confirmed_active_with_green_http(self) -> None:
        with (
            patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
            patch.object(deploy_runtime, "http_text", side_effect=["live", "ready"]),
        ):
            result = deploy_runtime.readiness_probe()
        self.assertTrue(result.ok)
        self.assertEqual(result.main_pid, 4321)

    def test_deployment_lock_rejects_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            original = state_root / "original"
            original.write_text("x\n", encoding="utf-8")
            lock = state_root / "deploy.lock"
            os.link(original, lock)
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Hardlinks"):
                with deploy_runtime.deployment_lock(lock, state_root=state_root):
                    pass

    def test_lock_rejects_requirement_without_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock.txt"
            path.write_text(
                "mcp==1.27.2\n"
                "    --hash=sha256:" + "1" * 64 + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(deploy_runtime.DeployError, "Fortsetzung"):
                deploy_runtime.parse_runtime_lock(path)

    def test_lock_rejects_open_final_hash_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.lock.txt"
            path.write_text(
                "mcp==1.27.2 \\\n"
                "    --hash=sha256:" + "1" * 64 + " \\\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(deploy_runtime.DeployError, "offener Fortsetzung"):
                deploy_runtime.parse_runtime_lock(path)


    def test_repo_drift_after_stop_blocks_pointer_and_restores_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = _build_result(
                "new", new_release, new_release / ".venv/bin/python",
                new_release / "module.py", "2025-06-18", {}
            )
            self._write_manifest(new_release, snapshot, runtime)
            live = deploy_runtime.EntryPoint(
                mode="module",
                python=runtime / ".venv/bin/python",
                module="grabowski_mcp",
            )
            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(deploy_runtime, "require_profile_matches_contract", return_value=live),
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(
                    deploy_runtime,
                    "verify_apply_snapshot_unchanged",
                    side_effect=[None, deploy_runtime.DeployError("late repo drift")],
                ) as verify_snapshot,
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv)),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "verify_running_profile_entrypoint", return_value={"pid": 200}),
                patch.object(deploy_runtime, "activate_pointer") as activate_pointer,
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackzustand"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(verify_snapshot.call_count, 2)
            activate_pointer.assert_not_called()
            self.assertEqual(runtime.resolve(), old_release.resolve())

    def test_profile_drift_after_stop_blocks_pointer_and_restores_service(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "grabowski-mcp"
            old_release = root / "old"
            old_release.mkdir()
            runtime.symlink_to(old_release)
            new_release = root / "new"
            (new_release / "inputs/src").mkdir(parents=True)
            snapshot = self._snapshot()
            build = _build_result(
                "new", new_release, new_release / ".venv/bin/python",
                new_release / "module.py", "2025-06-18", {}
            )
            self._write_manifest(new_release, snapshot, runtime)
            live = deploy_runtime.EntryPoint(
                mode="module",
                python=runtime / ".venv/bin/python",
                module="grabowski_mcp",
            )
            with (
                patch.object(deploy_runtime, "snapshot_from_git", return_value=snapshot),
                patch.object(deploy_runtime, "require_runtime_replaceable", return_value=runtime),
                patch.object(
                    deploy_runtime,
                    "require_profile_matches_contract",
                    side_effect=[live, deploy_runtime.DeployError("late profile drift")],
                ) as verify_profile,
                patch.object(deploy_runtime, "observe_service", return_value=self._obs_active()),
                patch.object(deploy_runtime, "wait_until_confirmed_inactive", return_value=self._obs_inactive()),
                patch.object(deploy_runtime, "build_release", return_value=build),
                patch.object(deploy_runtime, "verify_apply_snapshot_unchanged"),
                patch.object(deploy_runtime, "run", side_effect=lambda argv, **kwargs: self._completed(argv)),
                patch.object(deploy_runtime, "wait_until_ready", return_value=deploy_runtime.ReadinessResult(True, {}, "live", "ready", 123)),
                patch.object(deploy_runtime, "verify_running_profile_entrypoint", return_value={"pid": 200}),
                patch.object(deploy_runtime, "activate_pointer") as activate_pointer,
            ):
                with self.assertRaisesRegex(deploy_runtime.DeployError, "Rollbackzustand"):
                    deploy_runtime.deploy(ROOT, runtime, root / "profile.yaml", timeout_seconds=1)
            self.assertEqual(verify_profile.call_count, 2)
            activate_pointer.assert_not_called()
            self.assertEqual(runtime.resolve(), old_release.resolve())


if __name__ == "__main__":
    unittest.main()

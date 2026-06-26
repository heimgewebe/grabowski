from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "deploy_runtime.py"


def load_module():
    spec = importlib.util.spec_from_file_location("deploy_runtime_multisource", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("deploy_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_runtime_multisource"] = module
    spec.loader.exec_module(module)
    return module


deploy_runtime = load_module()


class MultiSourceDeployTests(unittest.TestCase):
    def snapshot(self):
        contract = deploy_runtime.RuntimeContract(
            schema_version=2,
            mode="module",
            module="grabowski_operator",
            source=Path("src/grabowski_operator.py"),
            supporting_sources=(
                deploy_runtime.RuntimeSource(
                    module="grabowski_mcp",
                    source=Path("src/grabowski_mcp.py"),
                ),
            ),
            expected_tools=("grabowski_status", "grabowski_terminal_run"),
        )
        return deploy_runtime.Snapshot(
            repo_head="b" * 40,
            dirty=False,
            contract=contract,
            contract_bytes=json.dumps(contract.to_manifest()).encode(),
            runtime_input_bytes=b"runtime-input\\n",
            runtime_lock_bytes=b"runtime-lock\\n",
            source_bytes=b"operator\\n",
            supporting_source_bytes={"grabowski_mcp": b"base\\n"},
        )

    def test_schema_v2_loads_supporting_source(self):
        snapshot = self.snapshot()
        loaded = deploy_runtime.load_contract_bytes(snapshot.contract_bytes)
        self.assertEqual("grabowski_operator", loaded.module)
        self.assertEqual(
            (deploy_runtime.RuntimeSource("grabowski_mcp", Path("src/grabowski_mcp.py")),),
            loaded.supporting_sources,
        )

    def test_apply_snapshot_detects_supporting_source_drift(self):
        snapshot = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = root / "release" / "inputs"
            (inputs / "src").mkdir(parents=True)
            (inputs / "runtime-entrypoint.json").write_bytes(snapshot.contract_bytes)
            (inputs / "runtime.in").write_bytes(snapshot.runtime_input_bytes)
            (inputs / "runtime.lock.txt").write_bytes(snapshot.runtime_lock_bytes)
            (inputs / snapshot.contract.source).write_bytes(snapshot.source_bytes)
            support = inputs / "src/grabowski_mcp.py"
            support.write_bytes(snapshot.supporting_source_bytes["grabowski_mcp"])
            with (
                patch.object(deploy_runtime, "repo_dirty", return_value=False),
                patch.object(deploy_runtime, "git_head", return_value=snapshot.repo_head),
            ):
                deploy_runtime.verify_apply_snapshot_unchanged(
                    ROOT, snapshot, root / "release"
                )
                support.write_bytes(b"drift\\n")
                with self.assertRaisesRegex(
                    deploy_runtime.DeployError, "driftete"
                ):
                    deploy_runtime.verify_apply_snapshot_unchanged(
                        ROOT, snapshot, root / "release"
                    )

    def test_complete_release_binds_both_modules(self):
        snapshot = self.snapshot()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "releases" / "release"
            release.mkdir(parents=True)
            runtime = root / "grabowski-mcp"
            runtime.symlink_to(release, target_is_directory=True)
            input_paths = deploy_runtime.write_snapshot_inputs(snapshot, release)
            python = release / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")
            site_packages = release / ".venv/lib/python3.10/site-packages"
            site_packages.mkdir(parents=True)
            operator_path = site_packages / "grabowski_operator.py"
            base_path = site_packages / "grabowski_mcp.py"
            operator_path.write_bytes(snapshot.source_bytes)
            base_path.write_bytes(snapshot.supporting_source_bytes["grabowski_mcp"])
            module_paths = {
                "grabowski_operator": operator_path,
                "grabowski_mcp": base_path,
            }
            deploy_runtime.write_manifest(
                release,
                release_id=release.name,
                snapshot=snapshot,
                stable_runtime=runtime,
                input_paths=input_paths,
                entrypoint_path=operator_path,
                module_paths=module_paths,
                protocol_version="2025-06-18",
                provenance={
                    "python_version": "3.10.12",
                    "python_implementation": "CPython",
                    "platform": "linux",
                    "executable": str(python),
                    "pip_version": "pip 25",
                },
            )
            manifest = deploy_runtime.verify_manifest(
                release,
                snapshot=snapshot,
                stable_runtime=runtime,
            )

            def import_path(_python, module):
                return module_paths[module]

            with (
                patch.object(deploy_runtime, "import_module_path", side_effect=import_path),
                patch.object(deploy_runtime, "site_packages_path", return_value=site_packages),
            ):
                deploy_runtime.verify_final_release_artifacts(
                    release,
                    runtime,
                    snapshot.contract,
                    snapshot=snapshot,
                    manifest=manifest,
                    process={"exe": str(python)},
                )
                base_path.write_bytes(b"drift\\n")
                with self.assertRaisesRegex(
                    deploy_runtime.DeployError, "driftete"
                ):
                    deploy_runtime.verify_final_release_artifacts(
                        release,
                        runtime,
                        snapshot.contract,
                        snapshot=snapshot,
                        manifest=manifest,
                        process={"exe": str(python)},
                    )


if __name__ == "__main__":
    unittest.main()

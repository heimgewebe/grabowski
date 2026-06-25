from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import platform
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


def _load_grabowski_mcp():
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    module_name = "grabowski_mcp_metadata_test"
    spec = importlib.util.spec_from_file_location(
        module_name, ROOT / "src" / "grabowski_mcp.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_mcp")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "mcp": fake_mcp,
            "mcp.server": fake_server,
            "mcp.server.fastmcp": fake_fastmcp,
            "mcp.types": fake_types,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


grabowski_mcp = _load_grabowski_mcp()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DeploymentMetadataTests(unittest.TestCase):
    def _release(self, root: Path) -> dict[str, Path]:
        releases_root = root / "grabowski-mcp-releases"
        release = releases_root / "release-001"
        inputs = release / "inputs"
        source_snapshot = inputs / "src/grabowski_mcp.py"
        source_snapshot.parent.mkdir(parents=True)
        module = release / ".venv/lib/python/site-packages/grabowski_mcp.py"
        module.parent.mkdir(parents=True)
        release_python = release / ".venv/bin/python"
        release_python.parent.mkdir(parents=True)
        release_python.write_text("python\n", encoding="utf-8")

        source_bytes = b"grabowski-runtime\n"
        source_snapshot.write_bytes(source_bytes)
        module.write_bytes(source_bytes)
        runtime_input = inputs / "runtime.in"
        runtime_input.write_text("mcp==1.27.2\n", encoding="utf-8")
        runtime_lock = inputs / "runtime.lock.txt"
        runtime_lock.write_text("mcp==1.27.2\n", encoding="utf-8")
        contract = {
            "schema_version": 1,
            "mode": "module",
            "module": "grabowski_mcp",
            "source": "src/grabowski_mcp.py",
            "expected_tools": ["grabowski_status"],
        }
        contract_path = inputs / "runtime-entrypoint.json"
        contract_path.write_text(
            json.dumps(contract, sort_keys=True) + "\n", encoding="utf-8"
        )
        stable = root / "grabowski-mcp"
        stable.symlink_to(release, target_is_directory=True)
        manifest = {
            "schema_version": 3,
            "release_id": release.name,
            "repo_head": "a" * 40,
            "entrypoint_contract": contract,
            "entrypoint_contract_sha256": _sha256(contract_path),
            "source_sha256": _sha256(source_snapshot),
            "runtime_input_sha256": _sha256(runtime_input),
            "runtime_lock_sha256": _sha256(runtime_lock),
            "snapshot_paths": {
                "runtime_entrypoint": str(contract_path),
                "runtime_input": str(runtime_input),
                "runtime_lock": str(runtime_lock),
                "source": str(source_snapshot),
            },
            "immutable_release_path": str(release),
            "expected_stable_runtime_path": str(stable),
            "release_python_path": str(release_python),
            "entrypoint_path": str(module),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "mcp_protocol_version": "2025-06-18",
            "created_at_unix": 1,
            "completion_status": "complete",
            "executable": str(release_python),
            "pip_version": f"pip {importlib.metadata.version('pip')}",
        }
        manifest_path = release / "deployment-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        return {
            "release": release,
            "stable": stable,
            "manifest": manifest_path,
            "runtime_input": runtime_input,
            "runtime_lock": runtime_lock,
            "source_snapshot": source_snapshot,
            "module": module,
            "contract": contract_path,
            "release_python": release_python,
        }

    def _metadata(self, paths: dict[str, Path]) -> dict[str, object]:
        stable_manifest = paths["stable"] / "deployment-manifest.json"
        with (
            patch.object(grabowski_mcp, "DEPLOYMENT_MANIFEST", stable_manifest),
            patch.object(grabowski_mcp, "EXPECTED_STABLE_RUNTIME", paths["stable"]),
            patch.object(grabowski_mcp, "__file__", str(paths["module"])),
            patch.object(grabowski_mcp.sys, "executable", str(paths["release_python"])),
        ):
            return grabowski_mcp._deployment_metadata()

    def test_valid_release_through_stable_symlink_has_valid_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            metadata = self._metadata(paths)
        self.assertTrue(metadata["release_path_valid"])
        self.assertTrue(metadata["entrypoint_path_valid"])
        self.assertTrue(metadata["repo_head_valid"])
        self.assertTrue(metadata["platform_identity_valid"])
        self.assertTrue(metadata["provenance_valid"])

    def test_runtime_input_tamper_invalidates_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            paths["runtime_input"].write_text("mcp==9.9.9\n", encoding="utf-8")
            metadata = self._metadata(paths)
        self.assertFalse(metadata["runtime_input_identity_valid"])
        self.assertFalse(metadata["provenance_valid"])

    def test_source_and_module_tamper_are_distinguished(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            paths["source_snapshot"].write_text("snapshot drift\n", encoding="utf-8")
            metadata = self._metadata(paths)
            self.assertFalse(metadata["source_snapshot_identity_valid"])
            self.assertTrue(metadata["source_identity_valid"])
            self.assertFalse(metadata["provenance_valid"])

        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            paths["module"].write_text("module drift\n", encoding="utf-8")
            metadata = self._metadata(paths)
            self.assertTrue(metadata["source_snapshot_identity_valid"])
            self.assertFalse(metadata["source_identity_valid"])
            self.assertFalse(metadata["provenance_valid"])

    def test_embedded_contract_tamper_invalidates_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            manifest["entrypoint_contract"]["module"] = "other_module"
            paths["manifest"].write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            metadata = self._metadata(paths)
        self.assertFalse(metadata["embedded_contract_valid"])
        self.assertFalse(metadata["provenance_valid"])

    def test_wrong_entrypoint_path_invalidates_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            duplicate = paths["module"].with_name("duplicate.py")
            duplicate.write_bytes(paths["module"].read_bytes())
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            manifest["entrypoint_path"] = str(duplicate)
            paths["manifest"].write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            metadata = self._metadata(paths)
        self.assertFalse(metadata["entrypoint_path_valid"])
        self.assertFalse(metadata["provenance_valid"])

    def test_malformed_manifest_never_escapes_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            paths["manifest"].write_text('{"schema_version": 3}\n', encoding="utf-8")
            metadata = self._metadata(paths)
        self.assertTrue(metadata["manifest_parse_valid"])
        self.assertFalse(metadata["manifest_schema_valid"])
        self.assertFalse(metadata["provenance_valid"])


    def test_runtime_lock_tamper_invalidates_artifact_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            paths["runtime_lock"].write_text("drift\n", encoding="utf-8")
            metadata = self._metadata(paths)
        self.assertFalse(metadata["lock_identity_valid"])
        self.assertFalse(metadata["artifact_integrity_valid"])
        self.assertFalse(metadata["provenance_valid"])

    def test_manifest_cannot_self_attest_an_alternate_stable_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            alternate = Path(directory) / "alternate-runtime"
            alternate.symlink_to(paths["release"], target_is_directory=True)
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            manifest["expected_stable_runtime_path"] = str(alternate)
            paths["manifest"].write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            metadata = self._metadata(paths)
        self.assertFalse(metadata["stable_runtime_manifest_valid"])
        self.assertFalse(metadata["runtime_binding_valid"])

    def test_external_contract_path_is_rejected_without_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            outside = Path(directory) / "outside.json"
            outside.write_text('{"schema_version": 1}\n', encoding="utf-8")
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            manifest["snapshot_paths"]["runtime_entrypoint"] = str(outside)
            paths["manifest"].write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            reads: list[Path] = []
            original = Path.read_text

            def tracked(path: Path, *args, **kwargs):
                reads.append(path)
                return original(path, *args, **kwargs)

            with patch.object(Path, "read_text", tracked):
                metadata = self._metadata(paths)
        self.assertNotIn(outside, reads)
        self.assertFalse(metadata["entrypoint_contract_identity_valid"])
        self.assertTrue(metadata["manifest_exists"])

    def test_symlink_contract_snapshot_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            outside = Path(directory) / "contract-copy.json"
            outside.write_bytes(paths["contract"].read_bytes())
            paths["contract"].unlink()
            paths["contract"].symlink_to(outside)
            metadata = self._metadata(paths)
        self.assertFalse(metadata["entrypoint_contract_identity_valid"])
        self.assertFalse(metadata["artifact_integrity_valid"])

    def test_manifest_runtime_fields_are_bound(self) -> None:
        mutations = {
            "executable": "/tmp/not-the-runtime-python",
            "pip_version": "pip 0",
            "mcp_protocol_version": "1900-01-01",
        }
        expected_flags = {
            "executable": "executable_identity_valid",
            "pip_version": "pip_identity_valid",
            "mcp_protocol_version": "protocol_identity_valid",
        }
        for field, value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                paths = self._release(Path(directory))
                manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
                manifest[field] = value
                paths["manifest"].write_text(
                    json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
                )
                metadata = self._metadata(paths)
                self.assertFalse(metadata[expected_flags[field]])
                self.assertFalse(metadata["provenance_valid"])

    def test_platform_drift_only_breaks_environment_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = self._release(Path(directory))
            manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
            manifest["platform"] = "different-platform"
            paths["manifest"].write_text(
                json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
            )
            metadata = self._metadata(paths)
        self.assertTrue(metadata["artifact_integrity_valid"])
        self.assertTrue(metadata["runtime_binding_valid"])
        self.assertFalse(metadata["environment_compatibility_valid"])
        self.assertFalse(metadata["provenance_valid"])


if __name__ == "__main__":
    unittest.main()

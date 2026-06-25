from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


_mcp = types.ModuleType("mcp")
_mcp_server = types.ModuleType("mcp.server")
_mcp_fastmcp = types.ModuleType("mcp.server.fastmcp")
_mcp_types = types.ModuleType("mcp.types")
_mcp_fastmcp.FastMCP = _FakeFastMCP
_mcp_types.ToolAnnotations = _FakeToolAnnotations
sys.modules.setdefault("mcp", _mcp)
sys.modules.setdefault("mcp.server", _mcp_server)
sys.modules.setdefault("mcp.server.fastmcp", _mcp_fastmcp)
sys.modules.setdefault("mcp.types", _mcp_types)

import grabowski_mcp  # noqa: E402


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
            "pip_version": "pip 25.0",
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


if __name__ == "__main__":
    unittest.main()

"""Prove that a release the deployment builder accepts, the runtime accepts too.

The deadlock this test exists to prevent: the deployment builder validated a
runtime entry-point contract with one hand-maintained field list while the
runtime provenance validator used a different one.  A release was therefore
built as valid and then rejected by the very runtime it produced, which closed
every mutation, deployment and recovery path behind an integrity gate that could
no longer be repaired.

Unit tests could not catch that, because each side was tested against a manifest
the test itself had written.  This test instead runs the real lifecycle:

    real contract  ->  real builder staging  ->  real builder manifest
                   ->  real runtime provenance validator

If the two sides ever disagree again, this fails in CI instead of in production.
"""

from __future__ import annotations

import copy
import importlib.metadata
import importlib.util
import json
import platform
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import grabowski_runtime_contract  # noqa: E402


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


def _load_grabowski_mcp():
    """Load the runtime module without requiring the mcp package."""
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    module_name = "grabowski_mcp_release_lifecycle_test"
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


def _load_deploy_runtime():
    name = "deploy_runtime_release_lifecycle_test"
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "tools" / "deploy_runtime.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load deploy_runtime")
    module = importlib.util.module_from_spec(spec)
    # Dataclass construction resolves annotations through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


grabowski_mcp = _load_grabowski_mcp()
deploy_runtime = _load_deploy_runtime()


class StagedRelease:
    """A release staged with the real deployment builder code paths.

    Only the venv creation, the pip install and the live MCP probe are replaced
    -- everything that determines manifest identity (snapshot inputs, installed
    sources, runtime assets, manifest fields) runs the production code.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.snapshot = deploy_runtime.snapshot_from_worktree(ROOT)
        self.releases_root = root / "grabowski-mcp-releases"
        self.release = self.releases_root / "release-lifecycle-001"
        self.stable = root / "grabowski-mcp"
        self.release.mkdir(parents=True)

        self.site_packages = self.release / ".venv/lib/python/site-packages"
        self.site_packages.mkdir(parents=True)
        self.release_python = self.release / ".venv/bin/python"
        self.release_python.parent.mkdir(parents=True, exist_ok=True)
        self.release_python.write_text("python\n", encoding="utf-8")

        input_paths = deploy_runtime.write_snapshot_inputs(self.snapshot, self.release)
        # The byte-compile step is a build-time check, not part of manifest
        # identity; skipping it keeps staging cheap without weakening the
        # identity checks this test exists for.
        with (
            patch.object(
                deploy_runtime, "site_packages_path", return_value=self.site_packages
            ),
            patch.object(deploy_runtime, "run"),
        ):
            module_paths = deploy_runtime.install_runtime_sources(
                self.snapshot, self.release, self.release_python
            )
        runtime_asset_paths = deploy_runtime.install_runtime_assets(
            self.snapshot, self.release
        )
        self.stable.symlink_to(self.release, target_is_directory=True)

        self.module_paths = module_paths
        deploy_runtime.write_manifest(
            self.release,
            release_id=self.release.name,
            snapshot=self.snapshot,
            stable_runtime=self.stable,
            input_paths=input_paths,
            entrypoint_path=module_paths[self.snapshot.contract.module],
            module_paths=module_paths,
            runtime_asset_paths=runtime_asset_paths,
            protocol_version="2025-06-18",
            agent_instructions=grabowski_mcp._agent_instructions_metadata(),
            provenance={
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "platform": platform.platform(),
                "executable": str(self.release_python),
                "pip_version": f"pip {importlib.metadata.version('pip')}",
            },
        )

    @property
    def manifest_path(self) -> Path:
        return self.release / "deployment-manifest.json"

    @property
    def contract_snapshot(self) -> Path:
        return self.release / "inputs/runtime-entrypoint.json"

    def manifest(self) -> dict:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def rewrite_manifest(self, manifest: dict) -> None:
        self.manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )

    def runtime_metadata(self) -> dict:
        """Validate the staged release with the real runtime provenance logic."""
        base_path = self.module_paths["grabowski_mcp"]

        def find_spec(module: str):
            # Resolve every deployed module to its staged release copy, the way
            # a real runtime running out of the release would.
            path = self.module_paths.get(module)
            if path is None:
                return None
            return types.SimpleNamespace(origin=str(path))

        with (
            patch.object(
                grabowski_mcp,
                "DEPLOYMENT_MANIFEST",
                self.stable / "deployment-manifest.json",
            ),
            patch.object(grabowski_mcp, "EXPECTED_STABLE_RUNTIME", self.stable),
            patch.object(grabowski_mcp, "__file__", str(base_path)),
            patch.object(grabowski_mcp.sys, "executable", str(self.release_python)),
            patch.object(
                grabowski_mcp.importlib.util, "find_spec", side_effect=find_spec
            ),
        ):
            return grabowski_mcp._deployment_metadata()


class ReleaseLifecycleConsistencyTests(unittest.TestCase):
    """The builder and the runtime must agree about the same artifact."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.staged = StagedRelease(Path(self._directory.name))

    def test_builder_release_is_accepted_by_the_runtime_validator(self) -> None:
        """The exact failure that deadlocked the runtime, as a regression test."""
        metadata = self.staged.runtime_metadata()

        self.assertTrue(metadata["manifest_schema_valid"])
        self.assertTrue(metadata["entrypoint_contract_identity_valid"])
        self.assertTrue(metadata["artifact_integrity_valid"])
        self.assertTrue(metadata["provenance_valid"])

    def test_canonical_contract_carries_browser_operator_default(self) -> None:
        """The field whose rejection caused the deadlock stays in the release."""
        contract = self.staged.manifest()["entrypoint_contract"]
        browser = contract["browser_operator_default"]

        self.assertEqual(browser["canonical_browser"]["family"], "chrome-stable")
        self.assertIs(browser["transport"]["loopback_only"], True)
        self.assertEqual(browser["profile"]["default"], "ephemeral")
        # The embedded contract and the snapshotted contract file are identical.
        self.assertEqual(
            contract,
            json.loads(self.staged.contract_snapshot.read_text(encoding="utf-8")),
        )

    def test_builder_and_runtime_share_one_schema_verdict(self) -> None:
        """Both validators must agree field for field, not merely in this release."""
        manifest = self.staged.manifest()
        self.assertEqual(deploy_runtime.validate_manifest_schema(manifest), [])
        self.assertTrue(grabowski_mcp._manifest_schema_valid(manifest))

    def test_deployed_release_ships_the_canonical_validator(self) -> None:
        """The runtime cannot validate itself unless the schema travels with it."""
        contract = self.staged.manifest()["entrypoint_contract"]
        modules = grabowski_runtime_contract.contract_modules(contract)

        self.assertIn(
            grabowski_runtime_contract.CANONICAL_VALIDATOR_MODULE, modules
        )
        self.assertTrue(
            (
                self.staged.site_packages
                / f"{grabowski_runtime_contract.CANONICAL_VALIDATOR_MODULE}.py"
            ).is_file()
        )


class ReleaseLifecycleRejectionTests(unittest.TestCase):
    """Drift and malformed contracts must fail closed on both sides."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.staged = StagedRelease(Path(self._directory.name))

    def _reject_both(self, manifest: dict) -> None:
        """Neither validator may accept the mutated manifest."""
        self.assertNotEqual(deploy_runtime.validate_manifest_schema(manifest), [])
        self.assertFalse(grabowski_mcp._manifest_schema_valid(manifest))

    def test_unknown_top_level_contract_field_fails_closed(self) -> None:
        manifest = self.staged.manifest()
        manifest["entrypoint_contract"]["unreviewed_capability"] = {"enabled": True}
        self._reject_both(manifest)

    def test_structurally_invalid_browser_operator_default_fails_closed(self) -> None:
        cases = [
            ("loopback disabled", ["transport", "loopback_only"], False),
            ("non-loopback endpoint", ["transport", "endpoint_address"], "10.0.0.5"),
            ("persistent default profile", ["profile", "default"], "persistent"),
            ("shared profile lease", ["profile", "exclusive_profile_lease"], False),
            ("relative executable", ["canonical_browser", "executable"], "chrome"),
        ]
        for label, path, value in cases:
            with self.subTest(label):
                manifest = self.staged.manifest()
                target = manifest["entrypoint_contract"]["browser_operator_default"]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self._reject_both(manifest)

    def test_browser_operator_default_unknown_nested_field_fails_closed(self) -> None:
        manifest = self.staged.manifest()
        browser = manifest["entrypoint_contract"]["browser_operator_default"]
        browser["canonical_browser"]["unreviewed_flag"] = True
        self._reject_both(manifest)

    def test_browser_operator_default_missing_stop_step_fails_closed(self) -> None:
        manifest = self.staged.manifest()
        browser = manifest["entrypoint_contract"]["browser_operator_default"]
        browser["lifecycle"] = [
            step
            for step in browser["lifecycle"]
            if step != "grabowski_browser_worker_stop"
        ]
        self._reject_both(manifest)

    def test_contract_hash_drift_invalidates_provenance(self) -> None:
        """A manifest whose recorded contract hash no longer matches the file."""
        manifest = self.staged.manifest()
        manifest["entrypoint_contract_sha256"] = "0" * 64
        self.staged.rewrite_manifest(manifest)

        metadata = self.staged.runtime_metadata()

        self.assertFalse(metadata["entrypoint_contract_identity_valid"])
        self.assertFalse(metadata["artifact_integrity_valid"])
        self.assertFalse(metadata["provenance_valid"])

    def test_snapshotted_contract_drift_invalidates_provenance(self) -> None:
        """The snapshotted contract file diverging from the embedded contract."""
        drifted = json.loads(
            self.staged.contract_snapshot.read_text(encoding="utf-8")
        )
        drifted["expected_tools"] = drifted["expected_tools"][:-1]
        self.staged.contract_snapshot.write_text(
            json.dumps(drifted, sort_keys=True) + "\n", encoding="utf-8"
        )

        metadata = self.staged.runtime_metadata()

        self.assertFalse(metadata["entrypoint_contract_identity_valid"])
        self.assertFalse(metadata["embedded_contract_valid"])
        self.assertFalse(metadata["provenance_valid"])

    def test_source_hash_drift_invalidates_provenance(self) -> None:
        manifest = self.staged.manifest()
        manifest["source_sha256s"][self.staged.snapshot.contract.module] = "0" * 64
        self.staged.rewrite_manifest(manifest)

        metadata = self.staged.runtime_metadata()

        self.assertFalse(metadata["provenance_valid"])


class ContractSchemaFailClosedTests(unittest.TestCase):
    """The canonical schema itself, independent of any staged release."""

    def setUp(self) -> None:
        self.contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )

    def test_repository_contract_is_valid(self) -> None:
        self.assertIsNone(grabowski_runtime_contract.contract_error(self.contract))

    def test_unknown_field_is_rejected_with_a_pointer_to_the_schema(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["speculative_field"] = 1

        error = grabowski_runtime_contract.contract_error(contract)

        self.assertIsNotNone(error)
        self.assertIn("speculative_field", error)
        self.assertIn("grabowski_runtime_contract", error)

    def test_field_from_a_later_schema_version_names_the_version(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["schema_version"] = 3
        del contract["spawn_dependencies"]

        error = grabowski_runtime_contract.contract_error(contract)

        self.assertIsNotNone(error)
        self.assertIn("browser_operator_default", error)
        self.assertIn("schema_version 4", error)

    def test_browser_operator_default_is_optional_but_never_untyped(self) -> None:
        without = copy.deepcopy(self.contract)
        del without["browser_operator_default"]
        self.assertIsNone(grabowski_runtime_contract.contract_error(without))

        untyped = copy.deepcopy(self.contract)
        untyped["browser_operator_default"] = "chrome"
        self.assertIsNotNone(grabowski_runtime_contract.contract_error(untyped))

    def test_every_schema_version_has_a_declared_field_policy(self) -> None:
        """A new schema version cannot be half-declared."""
        for version in grabowski_runtime_contract.CONTRACT_SCHEMA_VERSIONS:
            with self.subTest(version=version):
                required = grabowski_runtime_contract.required_contract_fields(version)
                optional = grabowski_runtime_contract.optional_contract_fields(version)
                self.assertTrue(required)
                self.assertFalse(required & optional)


class ImportClosureTests(unittest.TestCase):
    """A release must ship every runtime module its own sources import."""

    def test_repository_release_is_import_closed(self) -> None:
        snapshot = deploy_runtime.snapshot_from_worktree(ROOT)
        deploy_runtime.verify_import_closure(
            module=snapshot.contract.module,
            source_bytes=snapshot.source_bytes,
            supporting=snapshot.supporting_source_bytes,
        )

    def test_missing_import_target_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            deploy_runtime.DeployError, "nicht deployte Runtime-Module"
        ):
            deploy_runtime.verify_import_closure(
                module="grabowski_entry",
                source_bytes=b"import grabowski_absent\n",
                supporting={},
            )

    def test_dropping_the_canonical_validator_fails_closed(self) -> None:
        """Removing the schema module from the release is caught at build time."""
        snapshot = deploy_runtime.snapshot_from_worktree(ROOT)
        supporting = dict(snapshot.supporting_source_bytes)
        supporting.pop(grabowski_runtime_contract.CANONICAL_VALIDATOR_MODULE)

        with self.assertRaisesRegex(
            deploy_runtime.DeployError, "grabowski_runtime_contract"
        ):
            deploy_runtime.verify_import_closure(
                module=snapshot.contract.module,
                source_bytes=snapshot.source_bytes,
                supporting=supporting,
            )


if __name__ == "__main__":
    unittest.main()

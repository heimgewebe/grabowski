from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_bureau_intake as intake  # noqa: E402
import grabowski_bureau_launcher_contract as launcher_contract  # noqa: E402
import grabowski_bureau_leases as leases  # noqa: E402


class BureauLauncherContractParityTests(unittest.TestCase):
    launcher_path = Path("/runtime/bin/bureau")
    manifest_path = Path("/runtime/deployment-manifest.json")

    @staticmethod
    def _canonical(value: object) -> bytes:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def _launcher(self, digest_assignment: str) -> bytes:
        return (
            "#!/usr/bin/env python3\n"
            "# managed-by: heimgewebe-bureau-runtime-v1\n"
            "from pathlib import Path\n"
            f"manifest_path = Path({str(self.manifest_path)!r})\n"
            f"{digest_assignment}"
        ).encode("utf-8")

    def _intake_snapshot(self, launcher_raw: bytes) -> intake.RegularFileSnapshot:
        return intake.RegularFileSnapshot(
            path=self.launcher_path,
            device=1,
            inode=2,
            mode=0o100700,
            size=len(launcher_raw),
            mtime_ns=3,
            ctime_ns=4,
            sha256=hashlib.sha256(launcher_raw).hexdigest(),
            raw=launcher_raw,
        )

    def _parse_both(
        self, launcher_raw: bytes
    ) -> tuple[
        launcher_contract.ManagedLauncherBinding,
        launcher_contract.ManagedLauncherBinding,
    ]:
        intake_binding = intake._parse_managed_launcher_binding(
            self._intake_snapshot(launcher_raw),
            expected_manifest_path=self.manifest_path,
        )
        lease_binding = leases._parse_managed_launcher_binding(
            launcher_raw,
            self.launcher_path,
            expected_manifest_path=self.manifest_path,
        )
        return intake_binding, lease_binding

    def _payload_manifest(
        self, digest: object = None
    ) -> tuple[bytes, dict[str, object]]:
        payload: dict[str, object] = {
            "kind": "bureau_runtime_deployment",
            "schema_version": 1,
        }
        if digest is None:
            digest = hashlib.sha256(self._canonical(payload)).hexdigest()
        manifest = {**payload, "manifest_payload_sha256": digest}
        return self._canonical(manifest), manifest

    def test_consumers_accept_current_manifest_payload_sha256_contract(self) -> None:
        launcher_raw = self._launcher(
            "manifest_digest_field = 'manifest_payload_sha256'\n"
        )
        intake_binding, lease_binding = self._parse_both(launcher_raw)
        self.assertEqual(intake_binding, lease_binding)
        self.assertEqual(
            intake_binding.manifest_binding_kind,
            "manifest-payload-sha256-v2",
        )
        manifest_raw, manifest = self._payload_manifest()
        intake._verify_managed_launcher_manifest(
            intake_binding,
            manifest_raw,
            manifest,
        )
        leases._verify_managed_launcher_manifest(
            lease_binding,
            manifest_raw,
            manifest,
        )

    def test_consumers_reject_missing_or_malformed_launcher_field(self) -> None:
        cases = {
            "missing": (
                self._launcher(""),
                "managed-launcher-binding-invalid",
                "manifest-digest-binding-ambiguous",
            ),
            "malformed": (
                self._launcher("manifest_digest_field = 'manifest_sha256'\n"),
                "managed-launcher-manifest-payload-digest-field-invalid",
                "manifest-payload-digest-field-invalid",
            ),
        }
        for name, (launcher_raw, intake_code, lease_reason) in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(leases.BureauLeaseContractError) as intake_error:
                    intake._parse_managed_launcher_binding(
                        self._intake_snapshot(launcher_raw),
                        expected_manifest_path=self.manifest_path,
                    )
                with self.assertRaises(leases.BureauLeaseContractError) as lease_error:
                    leases._parse_managed_launcher_binding(
                        launcher_raw,
                        self.launcher_path,
                        expected_manifest_path=self.manifest_path,
                    )
                self.assertEqual(intake_error.exception.code, intake_code)
                self.assertEqual(
                    lease_error.exception.details.get("reason"), lease_reason
                )

    def test_consumers_reject_missing_malformed_or_mismatched_payload_digest(
        self,
    ) -> None:
        launcher_raw = self._launcher(
            "manifest_digest_field = 'manifest_payload_sha256'\n"
        )
        intake_binding, lease_binding = self._parse_both(launcher_raw)
        payload = {
            "kind": "bureau_runtime_deployment",
            "schema_version": 1,
        }
        cases = {
            "missing": (
                self._canonical(payload),
                payload,
                "managed-launcher-manifest-payload-digest-invalid",
                "manifest-payload-digest-invalid",
            ),
            "malformed": (
                *self._payload_manifest("not-a-sha256"),
                "managed-launcher-manifest-payload-digest-invalid",
                "manifest-payload-digest-invalid",
            ),
            "mismatched": (
                *self._payload_manifest("0" * 64),
                "managed-launcher-manifest-payload-digest-mismatch",
                "manifest-payload-digest-mismatch",
            ),
        }
        for name, (manifest_raw, manifest, intake_code, lease_reason) in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(leases.BureauLeaseContractError) as intake_error:
                    intake._verify_managed_launcher_manifest(
                        intake_binding,
                        manifest_raw,
                        manifest,
                    )
                with self.assertRaises(leases.BureauLeaseContractError) as lease_error:
                    leases._verify_managed_launcher_manifest(
                        lease_binding,
                        manifest_raw,
                        manifest,
                    )
                self.assertEqual(intake_error.exception.code, intake_code)
                self.assertEqual(
                    lease_error.exception.details.get("reason"), lease_reason
                )

    def test_consumers_reject_noncanonical_payload_manifest(self) -> None:
        launcher_raw = self._launcher(
            "manifest_digest_field = 'manifest_payload_sha256'\n"
        )
        intake_binding, lease_binding = self._parse_both(launcher_raw)
        _canonical_raw, manifest = self._payload_manifest()
        noncanonical_raw = json.dumps(manifest, sort_keys=True).encode("utf-8")
        with self.assertRaises(leases.BureauLeaseContractError) as intake_error:
            intake._verify_managed_launcher_manifest(
                intake_binding,
                noncanonical_raw,
                manifest,
            )
        with self.assertRaises(leases.BureauLeaseContractError) as lease_error:
            leases._verify_managed_launcher_manifest(
                lease_binding,
                noncanonical_raw,
                manifest,
            )
        self.assertEqual(
            intake_error.exception.code,
            "managed-launcher-manifest-payload-not-canonical",
        )
        self.assertEqual(
            lease_error.exception.details.get("reason"),
            "manifest-payload-manifest-not-canonical",
        )

    def test_consumers_preserve_legacy_full_manifest_digest_contract(self) -> None:
        manifest_raw = b'{"kind":"bureau_runtime_deployment","schema_version":1}'
        digest = hashlib.sha256(manifest_raw).hexdigest()
        launcher_raw = self._launcher(f"expected_manifest_sha256 = {digest!r}\n")
        intake_binding, lease_binding = self._parse_both(launcher_raw)
        manifest = json.loads(manifest_raw)
        intake._verify_managed_launcher_manifest(
            intake_binding,
            manifest_raw,
            manifest,
        )
        leases._verify_managed_launcher_manifest(
            lease_binding,
            manifest_raw,
            manifest,
        )
        drifted_raw = manifest_raw + b"\n"
        with self.assertRaises(leases.BureauLeaseContractError) as intake_error:
            intake._verify_managed_launcher_manifest(
                intake_binding,
                drifted_raw,
                manifest,
            )
        with self.assertRaises(leases.BureauLeaseContractError) as lease_error:
            leases._verify_managed_launcher_manifest(
                lease_binding,
                drifted_raw,
                manifest,
            )
        self.assertEqual(
            intake_error.exception.code,
            "managed-launcher-manifest-digest-mismatch",
        )
        self.assertEqual(
            lease_error.exception.details.get("reason"),
            "manifest-binding-mismatch",
        )

    def test_consumers_cannot_reimplement_shared_field_parser(self) -> None:
        parser_fields = (
            "expected_manifest_sha256",
            "manifest_digest_field",
            "manifest_payload_sha256",
        )
        for consumer in (intake, leases):
            source = Path(consumer.__file__).read_text(encoding="utf-8")
            with self.subTest(consumer=consumer.__name__):
                for field in parser_fields:
                    self.assertNotIn(field, source)
                self.assertNotIn("def _literal_launcher_assignment", source)
                self.assertIn(
                    "managed_launcher_contract.parse_managed_launcher_binding",
                    source,
                )
                self.assertIn(
                    "managed_launcher_contract.verify_managed_launcher_manifest",
                    source,
                )

    def test_shared_contract_has_no_grabowski_import_dependency(self) -> None:
        source = Path(launcher_contract.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        self.assertFalse(
            any(module.startswith("grabowski_") for module in imported),
            imported,
        )


if __name__ == "__main__":
    unittest.main()

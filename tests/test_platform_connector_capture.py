from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_client_snapshot as snapshot
import grabowski_connector_contract as connector_contract


RELEASE_ID = "capture-release"
REPO_HEAD = "c" * 40
INSTRUCTIONS_HASH = "b" * 64


class PlatformConnectorCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.platform_path = self.root / "platform-current.json"
        self.patches = (
            mock.patch.object(snapshot, "PLATFORM_SNAPSHOT_PATH", self.platform_path),
            mock.patch.object(snapshot, "PLATFORM_SNAPSHOT_TRUSTED_UID", os.getuid()),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def artifact(self) -> dict[str, object]:
        schemas = {
            "grabowski_bureau_candidate_assess": {
                "type": "object",
                "properties": {
                    name: {"type": "string", "default": ""}
                    for name in sorted(
                        connector_contract.REQUIRED_SCHEMA_PROPERTIES[
                            "grabowski_bureau_candidate_assess"
                        ]
                    )
                },
            },
            "grip_run": {
                "type": "object",
                "properties": {
                    name: {"type": "string", "default": ""}
                    for name in sorted(
                        connector_contract.REQUIRED_SCHEMA_PROPERTIES["grip_run"]
                    )
                },
            },
            "grabowski_secret_reveal": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
            "grabowski_task_start": {
                "type": "object",
                "properties": {
                    name: {"type": "string", "default": ""}
                    for name in sorted(
                        connector_contract.REQUIRED_SCHEMA_PROPERTIES[
                            "grabowski_task_start"
                        ]
                    )
                },
            },
        }
        names = [
            "alpha",
            "grabowski_bureau_candidate_assess",
            "grip_run",
            "grabowski_secret_reveal",
            "grabowski_task_start",
        ]
        return {
            "schema_version": 1,
            "tools": [
                {"name": name, "inputSchema": schemas[name]}
                if name in schemas
                else name
                for name in names
            ],
        }

    def runtime_root(self, names: list[str]) -> Path:
        root = self.root / "runtime"
        root.mkdir(exist_ok=True)
        (root / "deployment-manifest.json").write_text(
            json.dumps(
                {
                    "completion_status": "complete",
                    "release_id": RELEASE_ID,
                    "repo_head": REPO_HEAD,
                    "agent_instructions": {"sha256": INSTRUCTIONS_HASH},
                    "entrypoint_contract": {"expected_tools": names},
                }
            ),
            encoding="utf-8",
        )
        return root

    def test_builder_uses_runtime_manifest_binding_and_catalog_hash(self) -> None:
        artifact = self.artifact()
        observed_names, _schemas, metadata = connector_contract.parse_observed_artifact(
            artifact
        )
        runtime_names = observed_names + ["runtime-only"]
        document = snapshot.build_platform_connector_snapshot(
            observed_tools=artifact,
            runtime_root=self.runtime_root(runtime_names),
            source_reference="chatgpt:connector-catalog:test",
            observed_at_unix=1_000,
        )

        self.assertEqual(document["source"]["kind"], snapshot.PLATFORM_SOURCE_KIND)
        self.assertEqual(document["source"]["catalog_sha256"], metadata["artifact_sha256"])
        self.assertEqual(document["source"]["observed_at_unix"], 1_000)
        self.assertEqual(
            document["runtime_binding"]["registered_tool_count"], len(runtime_names)
        )
        self.assertEqual(
            document["runtime_binding"]["registered_names_sha256"],
            connector_contract.fingerprint(runtime_names),
        )
        unsigned = dict(document)
        snapshot_sha256 = unsigned.pop("snapshot_sha256")
        self.assertEqual(snapshot_sha256, snapshot._sha256_json(unsigned))

    def test_capture_persists_trusted_snapshot_and_reports_name_drift(self) -> None:
        artifact = self.artifact()
        observed_names, _schemas, metadata = connector_contract.parse_observed_artifact(
            artifact
        )
        runtime_names = observed_names + ["runtime-only"]
        runtime_root = self.runtime_root(runtime_names)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        result = snapshot.capture_platform_connector_snapshot(
            observed_tools=artifact,
            runtime_root=runtime_root,
            source_reference="chatgpt:connector-catalog:test",
            observed_at_unix=1_000,
        )

        self.assertEqual(result["state"], "captured")
        self.assertFalse(result["name_contract_matches"])
        self.assertEqual(result["missing_from_platform"], ["runtime-only"])
        self.assertEqual(result["unexpected_in_platform"], [])
        self.assertEqual(result["catalog_sha256"], metadata["artifact_sha256"])
        self.assertEqual(self.platform_path.stat().st_mode & 0o777, 0o600)

        runtime_artifact = {
            "schema_version": 1,
            "tools": list(artifact["tools"]) + ["runtime-only"],
        }
        runtime_metadata = connector_contract.parse_observed_artifact(
            runtime_artifact
        )[2]
        status = snapshot.platform_snapshot_status(
            expected_tool_count=len(runtime_names),
            expected_names_sha256=runtime_metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=runtime_artifact,
            now_unix=1_100,
        )
        self.assertEqual(status["state"], "mismatch")
        self.assertFalse(status["observable"])
        self.assertEqual(status["missing_from_platform"], ["runtime-only"])
        self.assertTrue(status["fresh"])

    def test_capture_reuses_persisted_runtime_binding_for_outcome(self) -> None:
        artifact = self.artifact()
        observed_names = connector_contract.parse_observed_artifact(artifact)[0]
        runtime_names_a = observed_names + ["runtime-a-only"]
        runtime_root = self.runtime_root(runtime_names_a)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        binding_a = snapshot._runtime_platform_binding(runtime_root)
        runtime_names_b = observed_names + ["runtime-b-only"]
        binding_b = (
            {
                **binding_a[0],
                "registered_tool_count": len(runtime_names_b),
                "registered_names_sha256": connector_contract.fingerprint(
                    runtime_names_b
                ),
                "release_id": "capture-release-b",
            },
            runtime_names_b,
        )

        with mock.patch.object(
            snapshot,
            "_runtime_platform_binding",
            side_effect=[binding_a, binding_b],
        ) as runtime_binding:
            result = snapshot.capture_platform_connector_snapshot(
                observed_tools=artifact,
                runtime_root=runtime_root,
                source_reference="chatgpt:connector-catalog:cutover-test",
                observed_at_unix=1_000,
            )

        self.assertEqual(runtime_binding.call_count, 1)
        self.assertEqual(result["runtime_tool_count"], len(runtime_names_a))
        self.assertEqual(result["missing_from_platform"], ["runtime-a-only"])
        self.assertNotIn("runtime-b-only", result["missing_from_platform"])
        persisted = json.loads(self.platform_path.read_text(encoding="utf-8"))
        self.assertEqual(persisted["runtime_binding"], binding_a[0])

    def test_capture_requires_trusted_uid_and_trusted_parent(self) -> None:
        artifact = self.artifact()
        observed_names = connector_contract.parse_observed_artifact(artifact)[0]
        runtime_root = self.runtime_root(observed_names)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        with mock.patch.object(
            snapshot, "PLATFORM_SNAPSHOT_TRUSTED_UID", os.getuid() + 1
        ):
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "trusted root authority"
            ):
                snapshot.capture_platform_connector_snapshot(
                    observed_tools=artifact,
                    runtime_root=runtime_root,
                    source_reference="chatgpt:connector-catalog:test",
                )

        self.platform_path.parent.chmod(0o777)
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "trusted root-owned directory"
        ):
            snapshot.capture_platform_connector_snapshot(
                observed_tools=artifact,
                runtime_root=runtime_root,
                source_reference="chatgpt:connector-catalog:test",
            )


if __name__ == "__main__":
    unittest.main()

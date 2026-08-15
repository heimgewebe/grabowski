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
            mock.patch.dict(
                os.environ,
                {
                    "GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(
                        self.root / "operator-obligations"
                    )
                },
            ),
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
        return connector_contract.mixed_artifact_from_runtime_tools(
            [
                {
                    "name": name,
                    "inputSchema": schemas.get(
                        name,
                        {"type": "object", "properties": {"value": {"type": "string"}}},
                    ),
                }
                for name in names
            ]
        )

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
        self.assertEqual(
            result["complete_schema_sha256"], metadata["complete_schema_sha256"]
        )
        mode = self.platform_path.stat().st_mode & 0o777
        self.assertEqual(snapshot.PLATFORM_SNAPSHOT_MODE, 0o644)
        self.assertEqual(mode, snapshot.PLATFORM_SNAPSHOT_MODE)
        self.assertEqual(mode & 0o022, 0)
        self.assertEqual(mode & 0o044, 0o044)

        runtime_artifact = connector_contract.mixed_artifact_from_runtime_tools(
            [
                {
                    "name": item["name"] if isinstance(item, dict) else item,
                    "inputSchema": (
                        item["inputSchema"]
                        if isinstance(item, dict)
                        else {"type": "object", "properties": {"value": {"type": "string"}}}
                    ),
                }
                for item in artifact["tools"]
            ]
            + [
                {
                    "name": "runtime-only",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        )
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
        self.assertEqual(status["state"], "publication_pending")
        self.assertTrue(status["publication_pending"])
        self.assertFalse(status["observable"])
        self.assertEqual(status["missing_from_platform"], ["runtime-only"])
        self.assertTrue(status["fresh"])

    def test_root_capture_binds_to_runtime_owner_obligation_store(self) -> None:
        runtime_root = self.root / "runtime-owner-root"
        runtime_root.mkdir()
        owner_home = self.root / "runtime-owner-home"
        owner_home.mkdir()
        key = "GRABOWSKI_OPERATOR_OBLIGATION_ROOT"
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(key, None)
            with mock.patch("pwd.getpwuid", return_value=mock.Mock(pw_dir=str(owner_home))):
                resolved = snapshot._platform_obligation_root_for_runtime(runtime_root)
        self.assertEqual(
            resolved,
            owner_home / ".local" / "state" / "grabowski" / "operator-obligations",
        )

    def test_new_publication_contract_supersedes_prior_open_obligation(self) -> None:
        artifact = self.artifact()
        names, _schemas, metadata = connector_contract.parse_observed_artifact(artifact)
        first = snapshot._platform_publication_contract(
            registered_tool_count=len(names),
            registered_names_sha256=metadata["names_sha256"],
            schema_sha256_by_tool=metadata["schema_sha256_by_tool"],
        )
        opened = snapshot._reconcile_platform_publication_obligation(first, now_unix=1_000)
        second = dict(first)
        second["names_sha256"] = "a" * 64
        successor = snapshot._reconcile_platform_publication_obligation(second, now_unix=1_100)

        self.assertEqual(successor["state"], "publication_pending")
        self.assertNotEqual(successor["obligation_id"], opened["obligation_id"])
        import grabowski_operator_obligation as obligations

        prior = obligations.status_obligation(opened["obligation_id"])
        self.assertEqual(prior["state"], "blocked")
        self.assertEqual(prior["resolution_disposition"], "superseded")
        current = obligations.status_obligation(successor["obligation_id"])
        self.assertEqual(current["state"], "open")

    def test_supersede_crash_window_is_reconciled_before_successor_open(self) -> None:
        artifact = self.artifact()
        names, _schemas, metadata = connector_contract.parse_observed_artifact(artifact)
        first = snapshot._platform_publication_contract(
            registered_tool_count=len(names),
            registered_names_sha256=metadata["names_sha256"],
            schema_sha256_by_tool=metadata["schema_sha256_by_tool"],
        )
        opened = snapshot._reconcile_platform_publication_obligation(first, now_unix=1_000)
        second = dict(first)
        second["names_sha256"] = "b" * 64

        import grabowski_operator_obligation as obligations

        obligations.close_obligation(
            {
                "obligation_id": opened["obligation_id"],
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "platform-contract-superseded",
                        "detail": "simulated crash after close",
                        "reference": snapshot._platform_publication_contract_reference(second),
                        "sha256": snapshot._sha256_json(second),
                    }
                ],
                "next_action": "continue with successor",
            }
        )
        interrupted = obligations.status_obligation(opened["obligation_id"])
        self.assertIsNone(interrupted["resolution_disposition"])

        successor = snapshot._reconcile_platform_publication_obligation(second, now_unix=1_100)
        prior = obligations.status_obligation(opened["obligation_id"])
        self.assertEqual(prior["resolution_disposition"], "superseded")
        self.assertEqual(successor["state"], "publication_pending")
        self.assertNotEqual(successor["obligation_id"], opened["obligation_id"])

    def test_stale_matching_surface_does_not_open_republish_obligation(self) -> None:
        artifact = self.artifact()
        names, _schemas, metadata = connector_contract.parse_observed_artifact(artifact)
        contract = snapshot._platform_publication_contract(
            registered_tool_count=len(names),
            registered_names_sha256=metadata["names_sha256"],
            schema_sha256_by_tool=metadata["schema_sha256_by_tool"],
        )
        document = snapshot.build_platform_connector_snapshot(
            observed_tools=artifact,
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector-catalog:old-but-matching",
            observed_at_unix=1_000,
        )

        lifecycle = snapshot._reconcile_platform_publication_obligation(
            contract, document=document, now_unix=5_000
        )

        self.assertEqual(lifecycle["state"], "stale")
        self.assertIsNone(lifecycle["obligation_id"])
        self.assertTrue(lifecycle["observation"]["names_match"])
        self.assertTrue(lifecycle["observation"]["schemas_match"])
        self.assertFalse(lifecycle["observation"]["fresh"])

    def test_matching_capture_closes_pending_platform_publication_obligation(self) -> None:
        artifact = self.artifact()
        observed_names, _schemas, metadata = connector_contract.parse_observed_artifact(
            artifact
        )
        contract = snapshot._platform_publication_contract(
            registered_tool_count=len(observed_names),
            registered_names_sha256=metadata["names_sha256"],
            schema_sha256_by_tool=metadata["schema_sha256_by_tool"],
        )
        pending = snapshot._reconcile_platform_publication_obligation(
            contract, now_unix=1_000
        )
        self.assertEqual(pending["state"], "publication_pending")
        self.assertTrue(pending["obligation_id"].startswith("goo-platform-catalog-convergence-"))

        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        result = snapshot.capture_platform_connector_snapshot(
            observed_tools=artifact,
            runtime_root=self.runtime_root(observed_names),
            source_reference="chatgpt:connector-catalog:converged",
            observed_at_unix=1_100,
        )

        lifecycle = result["platform_publication"]
        self.assertIsInstance(lifecycle, dict)
        self.assertEqual(lifecycle["state"], "matched")
        self.assertEqual(lifecycle["obligation_id"], pending["obligation_id"])
        self.assertEqual(lifecycle["obligation"]["state"], "completed")
        self.assertTrue(lifecycle["observation"]["names_match"])
        self.assertTrue(lifecycle["observation"]["schemas_match"])
        self.assertTrue(lifecycle["observation"]["fresh"])

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

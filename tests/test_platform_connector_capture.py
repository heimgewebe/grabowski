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
        self.publication_root = self.root / "platform-publication"
        self.patches = (
            mock.patch.object(snapshot, "PLATFORM_SNAPSHOT_PATH", self.platform_path),
            mock.patch.object(snapshot, "PLATFORM_SNAPSHOT_TRUSTED_UID", os.getuid()),
            mock.patch.object(snapshot, "LOCK_PATH", self.root / "snapshot.lock"),
            mock.patch.object(snapshot, "PLATFORM_PUBLICATION_ROOT", self.publication_root),
            mock.patch.object(
                snapshot, "PLATFORM_PUBLICATION_REQUEST_ROOT", self.publication_root / "requests"
            ),
            mock.patch.object(
                snapshot, "PLATFORM_PUBLICATION_ATTEMPT_ROOT", self.publication_root / "attempts"
            ),
            mock.patch.object(
                snapshot, "PLATFORM_PUBLICATION_RECEIPT_ROOT", self.publication_root / "receipts"
            ),
            mock.patch.object(
                snapshot, "PLATFORM_PUBLICATION_RESOLUTION_ROOT", self.publication_root / "resolutions"
            ),
            mock.patch.object(
                snapshot, "PLATFORM_PUBLICATION_CURRENT_PATH", self.publication_root / "current.json"
            ),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def runtime_tool_objects(self) -> list[dict[str, object]]:
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
        return [
            {
                "name": name,
                "inputSchema": schemas.get(
                    name,
                    {"type": "object", "properties": {"value": {"type": "string"}}},
                ),
            }
            for name in names
        ]

    def artifact(self) -> dict[str, object]:
        return connector_contract.mixed_artifact_from_runtime_tools(
            self.runtime_tool_objects()
        )

    def complete_artifact(
        self, tools: list[dict[str, object]] | None = None
    ) -> dict[str, object]:
        tools = self.runtime_tool_objects() if tools is None else tools
        schemas = {item["name"]: item["inputSchema"] for item in tools}
        return {
            "schema_version": connector_contract.OBSERVED_ARTIFACT_SCHEMA_VERSION,
            "tools": tools,
            "complete_schema_count": len(tools),
            "complete_schema_sha256": connector_contract.complete_schema_fingerprint(
                schemas
            ),
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

    def publication_contract(self, artifact: dict[str, object]) -> dict[str, object]:
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        return snapshot._platform_publication_contract(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
        )

    def prepare_request(
        self, artifact: dict[str, object], *, cutover_id: str = "cutover-test", now_unix: int = 1_000
    ) -> dict[str, object]:
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        return snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            cutover_id=cutover_id,
            now_unix=now_unix,
        )

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
            observation_scope="chat_session_catalog",
            observation_id="session-test-1",
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
            observation_scope="chat_session_catalog",
            observation_id="session-test-1",
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
        self.assertEqual(status["state"], "mismatch")
        self.assertEqual(status["publication_state"], "publication_request_required")
        self.assertTrue(status["publication_pending"])
        self.assertFalse(status["observable"])
        self.assertEqual(status["missing_from_platform"], ["runtime-only"])
        self.assertTrue(status["fresh"])

    def test_full_schema_contract_changes_when_non_sentinel_schema_changes(self) -> None:
        first = self.artifact()
        tools = json.loads(json.dumps(self.runtime_tool_objects()))
        alpha = next(item for item in tools if item["name"] == "alpha")
        alpha["inputSchema"]["properties"]["value"]["minLength"] = 1
        second = connector_contract.mixed_artifact_from_runtime_tools(tools)

        first_contract = self.publication_contract(first)
        second_contract = self.publication_contract(second)

        self.assertEqual(first_contract["tool_count"], second_contract["tool_count"])
        self.assertEqual(
            first_contract["tool_names_sha256"], second_contract["tool_names_sha256"]
        )
        self.assertNotEqual(
            first_contract["tool_schemas_sha256"], second_contract["tool_schemas_sha256"]
        )
        self.assertNotEqual(
            first_contract["tool_contract_sha256"], second_contract["tool_contract_sha256"]
        )

    def test_prepare_activate_and_replay_are_idempotent(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact)
        self.assertEqual(prepared["state"], "pending_activation")
        request_id = prepared["request_id"]
        request = snapshot._read_publication_request(request_id)
        self.assertEqual(
            request["expected_contract"]["tool_contract_sha256"],
            prepared["contract"]["tool_contract_sha256"],
        )

        activated = snapshot.activate_platform_publication_request(
            request_id=request_id, now_unix=1_010
        )
        replay = snapshot.activate_platform_publication_request(
            request_id=request_id, now_unix=1_020
        )
        self.assertEqual(activated["state"], "publication_pending")
        self.assertTrue(replay["idempotent"])
        self.assertEqual(
            snapshot._read_publication_current()["state"], "publication_pending"
        )

    def test_reconcile_recovers_pending_activation_when_runtime_contract_matches(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact, cutover_id="cutover-restart")
        metadata = connector_contract.parse_observed_artifact(artifact)[2]

        recovered = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_050,
        )

        self.assertEqual(recovered["state"], "publication_pending")
        self.assertTrue(recovered["recovered_pending_activation"])
        self.assertEqual(recovered["request_id"], prepared["request_id"])
        self.assertEqual(
            snapshot._read_publication_current()["state"], "publication_pending"
        )

    def test_activate_recovers_after_supersede_resolution_crash(self) -> None:
        first = self.artifact()
        first_prepared = self.prepare_request(first, cutover_id="activate-first")
        snapshot.activate_platform_publication_request(
            request_id=first_prepared["request_id"], now_unix=1_005
        )
        tools = json.loads(json.dumps(self.runtime_tool_objects()))
        tools.append(
            {"name": "beta", "inputSchema": {"type": "object", "properties": {}}}
        )
        second = connector_contract.mixed_artifact_from_runtime_tools(tools)
        metadata = connector_contract.parse_observed_artifact(second)[2]
        second_prepared = snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            cutover_id="activate-second",
            now_unix=1_100,
        )
        original_write = snapshot._write_publication_current
        with mock.patch.object(
            snapshot,
            "_write_publication_current",
            side_effect=RuntimeError("simulated post-resolution crash"),
        ):
            with self.assertRaisesRegex(RuntimeError, "post-resolution crash"):
                snapshot.activate_platform_publication_request(
                    request_id=second_prepared["request_id"], now_unix=1_110
                )
        resolution = snapshot._read_publication_resolution(first_prepared["request_id"])
        self.assertEqual(resolution["outcome"], "superseded")
        self.assertEqual(
            resolution["successor_request_id"], second_prepared["request_id"]
        )
        self.assertEqual(
            snapshot._read_publication_current()["state"], "pending_activation"
        )

        replay = snapshot.activate_platform_publication_request(
            request_id=second_prepared["request_id"], now_unix=2_000
        )
        self.assertEqual(replay["state"], "publication_pending")
        self.assertEqual(
            snapshot._read_publication_resolution(first_prepared["request_id"])[
                "resolution_sha256"
            ],
            resolution["resolution_sha256"],
        )
        self.assertIs(original_write, snapshot._write_publication_current)

    def test_attempt_replay_repairs_projection_after_record_crash(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        with mock.patch.object(
            snapshot,
            "_write_publication_current",
            side_effect=RuntimeError("simulated post-attempt crash"),
        ):
            with self.assertRaisesRegex(RuntimeError, "post-attempt crash"):
                snapshot.record_platform_publication_attempt(
                    request_id=request_id,
                    attempt_id="attempt-crash",
                    outcome="submitted",
                    reference="chatgpt:connector-refresh:submitted",
                    now_unix=1_010,
                )
        self.assertEqual(
            snapshot._read_publication_current()["state"], "publication_pending"
        )
        self.assertIsNone(snapshot._read_publication_current()["attempt_id"])
        immutable = snapshot._read_publication_attempt(request_id, "attempt-crash")

        replay = snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-crash",
            outcome="submitted",
            reference="chatgpt:connector-refresh:submitted",
            now_unix=2_000,
        )
        self.assertTrue(replay["idempotent"])
        self.assertTrue(replay["recovered_projection"])
        self.assertEqual(replay["attempt_sha256"], immutable["attempt_sha256"])
        current = snapshot._read_publication_current()
        self.assertEqual(current["state"], "awaiting_platform_observation")
        self.assertEqual(current["attempt_id"], "attempt-crash")

    def test_later_attempt_replay_repairs_over_older_current_attempt(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact, cutover_id="attempt-chain")
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-failed-first",
            outcome="failed",
            reference="chatgpt:connector-refresh:failed-first",
            now_unix=1_010,
        )
        prior_current = snapshot._read_publication_current()
        self.assertEqual(prior_current["attempt_id"], "attempt-failed-first")
        self.assertEqual(prior_current["state"], "publication_pending")

        with mock.patch.object(
            snapshot,
            "_write_publication_current",
            side_effect=RuntimeError("simulated later-attempt projection crash"),
        ):
            with self.assertRaisesRegex(RuntimeError, "later-attempt projection crash"):
                snapshot.record_platform_publication_attempt(
                    request_id=request_id,
                    attempt_id="attempt-submitted-second",
                    outcome="submitted",
                    reference="chatgpt:connector-refresh:submitted-second",
                    now_unix=1_020,
                )
        orphan = snapshot._read_publication_attempt(
            request_id, "attempt-submitted-second"
        )
        self.assertEqual(
            orphan["previous_current_sha256"], prior_current["current_sha256"]
        )
        self.assertEqual(orphan["previous_attempt_id"], "attempt-failed-first")
        self.assertEqual(
            snapshot._read_publication_current()["current_sha256"],
            prior_current["current_sha256"],
        )

        replay = snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-submitted-second",
            outcome="submitted",
            reference="chatgpt:connector-refresh:submitted-second",
            now_unix=2_000,
        )
        self.assertTrue(replay["idempotent"])
        self.assertTrue(replay["recovered_projection"])
        current = snapshot._read_publication_current()
        self.assertEqual(current["attempt_id"], "attempt-submitted-second")
        self.assertEqual(current["state"], "awaiting_platform_observation")

    def test_orphaned_attempt_cannot_overwrite_genuinely_newer_projection(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact, cutover_id="attempt-newer-projection")
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-old-current",
            outcome="failed",
            reference="chatgpt:connector-refresh:old-failure",
            now_unix=1_010,
        )
        with mock.patch.object(
            snapshot,
            "_write_publication_current",
            side_effect=RuntimeError("simulated orphaned second attempt"),
        ):
            with self.assertRaisesRegex(RuntimeError, "orphaned second attempt"):
                snapshot.record_platform_publication_attempt(
                    request_id=request_id,
                    attempt_id="attempt-orphaned",
                    outcome="submitted",
                    reference="chatgpt:connector-refresh:orphaned",
                    now_unix=1_020,
                )
        snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-newer-current",
            outcome="outcome_unknown",
            reference="chatgpt:connector-refresh:newer-current",
            now_unix=1_030,
        )
        newer = snapshot._read_publication_current()
        self.assertEqual(newer["attempt_id"], "attempt-newer-current")

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "newer or different current projection"
        ):
            snapshot.record_platform_publication_attempt(
                request_id=request_id,
                attempt_id="attempt-orphaned",
                outcome="submitted",
                reference="chatgpt:connector-refresh:orphaned",
                now_unix=2_000,
            )
        self.assertEqual(
            snapshot._read_publication_current()["current_sha256"],
            newer["current_sha256"],
        )

    def test_durable_publication_state_survives_missing_platform_snapshot(self) -> None:
        artifact = self.artifact()
        names, _schemas, metadata = connector_contract.parse_observed_artifact(artifact)
        prepared = self.prepare_request(artifact, cutover_id="missing-platform-snapshot")
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)

        pending = snapshot.snapshot_status(
            expected_tool_count=metadata["name_count"],
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=artifact,
            now_unix=1_010,
        )
        self.assertEqual(pending["platform_evidence_state"], "missing")
        self.assertEqual(pending["platform_publication_state"], "publication_pending")
        self.assertTrue(pending["platform_publication_pending"])
        self.assertEqual(pending["platform_publication_request_id"], request_id)
        self.assertEqual(
            pending["platform_publication_contract_sha256"],
            prepared["contract"]["tool_contract_sha256"],
        )

        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:before-reboot",
            observation_scope="connector_catalog",
            observation_id="connector-before-reboot",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        converged = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )
        self.assertEqual(converged["state"], "platform_converged")
        self.platform_path.unlink()

        after_reboot = snapshot.snapshot_status(
            expected_tool_count=metadata["name_count"],
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=artifact,
            now_unix=1_120,
        )
        self.assertEqual(after_reboot["platform_evidence_state"], "missing")
        self.assertEqual(
            after_reboot["platform_publication_state"], "platform_converged"
        )
        self.assertFalse(after_reboot["platform_publication_pending"])
        self.assertEqual(after_reboot["platform_publication_request_id"], request_id)
        self.assertEqual(
            after_reboot["platform_snapshot"]["publication_projection"]["state"],
            "platform_converged",
        )

    def test_pending_activation_from_earlier_cutover_blocks_new_cutover(self) -> None:
        artifact = self.artifact()
        self.prepare_request(artifact, cutover_id="cutover-a")
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        with self.assertRaisesRegex(snapshot.ClientSnapshotError, "pending activation"):
            snapshot.prepare_platform_publication_for_runtime(
                registered_tool_count=metadata["name_count"],
                registered_names_sha256=metadata["names_sha256"],
                complete_schema_count=metadata["complete_schema_count"],
                complete_schema_sha256=metadata["complete_schema_sha256"],
                cutover_id="cutover-b",
                now_unix=1_010,
            )

    def test_outcome_unknown_attempt_is_not_converged_and_replays(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(
            request_id=request_id, now_unix=1_005
        )
        first = snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-1",
            outcome="outcome_unknown",
            reference="chatgpt:connector-refresh:unknown",
            now_unix=1_010,
        )
        replay = snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-1",
            outcome="outcome_unknown",
            reference="chatgpt:connector-refresh:unknown",
            now_unix=2_000,
        )
        self.assertEqual(first["attempt_sha256"], replay["attempt_sha256"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(first["state"], "outcome_unknown")
        self.assertEqual(
            snapshot._read_publication_current()["state"], "outcome_unknown"
        )

    def test_capture_cli_accepts_complete_artifact_file_above_argv_limit(self) -> None:
        runtime_artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(runtime_artifact)[0]
        prepared = self.prepare_request(runtime_artifact)
        complete = self.complete_artifact()
        alpha = next(item for item in complete["tools"] if item["name"] == "alpha")
        alpha["inputSchema"]["description"] = "x" * 140_000
        complete["complete_schema_sha256"] = connector_contract.complete_schema_fingerprint(
            {item["name"]: item["inputSchema"] for item in complete["tools"]}
        )
        artifact_path = self.root / "complete-platform-artifact.json"
        artifact_path.write_text(json.dumps(complete), encoding="utf-8")
        self.assertGreater(artifact_path.stat().st_size, 131_072)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        result = snapshot.main(
            [
                "capture-platform",
                "--runtime-root",
                str(self.runtime_root(names)),
                "--source-reference",
                "chatgpt:connector:file-transport",
                "--observation-scope",
                "connector_catalog",
                "--observation-id",
                "connector-file-transport",
                "--publication-request-id",
                prepared["request_id"],
                "--requested-contract-sha256",
                prepared["contract"]["tool_contract_sha256"],
                "--observed-tools-file",
                str(artifact_path),
            ]
        )

        self.assertEqual(result, 0)
        persisted = json.loads(self.platform_path.read_text(encoding="utf-8"))
        self.assertEqual(
            persisted["observed_tools"]["complete_schema_sha256"],
            complete["complete_schema_sha256"],
        )

    def test_request_bound_capture_rejects_compact_schema_hash_claim(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "must contain exactly name and inputSchema",
        ):
            snapshot.capture_platform_connector_snapshot(
                observed_tools=artifact,
                runtime_root=self.runtime_root(names),
                source_reference="chatgpt:connector:compact-claim",
                observation_scope="connector_catalog",
                observation_id="connector-compact-claim",
                publication_request_id=prepared["request_id"],
                requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
                observed_at_unix=1_100,
            )
        self.assertFalse(self.platform_path.exists())

    def test_request_bound_capture_rejects_hash_not_derived_from_platform_schemas(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        complete = self.complete_artifact()
        complete["complete_schema_sha256"] = "0" * 64
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "does not match the supplied schemas",
        ):
            snapshot.capture_platform_connector_snapshot(
                observed_tools=complete,
                runtime_root=self.runtime_root(names),
                source_reference="chatgpt:connector:forged-hash",
                observation_scope="connector_catalog",
                observation_id="connector-forged-hash",
                publication_request_id=prepared["request_id"],
                requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
                observed_at_unix=1_100,
            )
        self.assertFalse(self.platform_path.exists())

    def test_root_capture_does_not_mutate_user_publication_state(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        snapshot.activate_platform_publication_request(
            request_id=prepared["request_id"], now_unix=1_005
        )
        before = snapshot.PLATFORM_PUBLICATION_CURRENT_PATH.read_bytes()
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        result = snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector-catalog:session",
            observation_scope="chat_session_catalog",
            observation_id="session-existing-chat",
            publication_request_id=prepared["request_id"],
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )

        self.assertEqual(result["platform_publication"]["state"], "captured_unreconciled")
        self.assertEqual(before, snapshot.PLATFORM_PUBLICATION_CURRENT_PATH.read_bytes())

    def test_session_observation_cannot_close_global_convergence(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:session:old-chat",
            observation_scope="chat_session_catalog",
            observation_id="session-old-chat",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        reconciled = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )
        self.assertEqual(reconciled["state"], "publication_pending")
        self.assertEqual(reconciled["reason"], "session_observation_not_connector_authority")

    def test_stale_request_bound_observation_cannot_close(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:stale",
            observation_scope="connector_catalog",
            observation_id="connector-stale",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        reconciled = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=5_000,
        )
        self.assertNotEqual(reconciled["state"], "platform_converged")
        self.assertEqual(reconciled["reason"], "stale_platform_observation")

    def test_fresh_exact_request_bound_connector_observation_converges(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-submit",
            outcome="submitted",
            reference="chatgpt:connector-refresh:submitted",
            now_unix=1_010,
        )
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:refreshed",
            observation_scope="connector_catalog",
            observation_id="connector-refreshed-1",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        reconciled = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )
        self.assertEqual(reconciled["state"], "platform_converged")
        self.assertTrue(snapshot._publication_receipt_path(request_id).exists())
        self.assertEqual(
            snapshot._read_publication_current()["state"], "platform_converged"
        )

    def test_observation_bound_to_older_contract_is_historical_not_convergent(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:wrong-request",
            observation_scope="connector_catalog",
            observation_id="connector-wrong-request",
            publication_request_id="gpp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            requested_contract_sha256="a" * 64,
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        reconciled = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )
        self.assertEqual(reconciled["reason"], "historical_or_unbound_observation")
        self.assertNotEqual(reconciled["state"], "platform_converged")

    def test_corrupt_current_fails_closed(self) -> None:
        artifact = self.artifact()
        prepared = self.prepare_request(artifact)
        current_path = snapshot.PLATFORM_PUBLICATION_CURRENT_PATH
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["current_sha256"] = "0" * 64
        current_path.write_text(json.dumps(current), encoding="utf-8")
        projection = snapshot._publication_projection_for_contract(
            prepared["contract"], now_unix=1_100
        )
        self.assertEqual(projection["state"], "invalid")
        self.assertTrue(projection["publication_pending"])

    def test_rollback_recovers_after_resolution_record_crash(self) -> None:
        first = self.artifact()
        first_prepared = self.prepare_request(first, cutover_id="rollback-first")
        snapshot.activate_platform_publication_request(
            request_id=first_prepared["request_id"], now_unix=1_005
        )
        tools = json.loads(json.dumps(self.runtime_tool_objects()))
        tools.append(
            {"name": "beta", "inputSchema": {"type": "object", "properties": {}}}
        )
        second = connector_contract.mixed_artifact_from_runtime_tools(tools)
        metadata = connector_contract.parse_observed_artifact(second)[2]
        second_prepared = snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            cutover_id="rollback-second",
            now_unix=1_100,
        )
        with mock.patch.object(
            snapshot,
            "_write_publication_current",
            side_effect=RuntimeError("simulated post-rollback-resolution crash"),
        ):
            with self.assertRaisesRegex(RuntimeError, "post-rollback-resolution crash"):
                snapshot.rollback_platform_publication_request(
                    request_id=second_prepared["request_id"],
                    active_contract=first_prepared["contract"],
                    now_unix=1_110,
                )
        resolution = snapshot._read_publication_resolution(second_prepared["request_id"])
        self.assertEqual(resolution["outcome"], "rolled_back")
        self.assertEqual(
            snapshot._read_publication_current()["request_id"],
            second_prepared["request_id"],
        )

        replay = snapshot.rollback_platform_publication_request(
            request_id=second_prepared["request_id"],
            active_contract=first_prepared["contract"],
            now_unix=2_000,
        )
        self.assertEqual(replay["state"], "rolled_back")
        self.assertEqual(replay["resolution_sha256"], resolution["resolution_sha256"])
        self.assertEqual(
            snapshot._read_publication_current()["request_id"],
            first_prepared["request_id"],
        )

    def test_reconcile_recovers_after_receipt_record_crash(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact, cutover_id="receipt-crash")
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        snapshot.record_platform_publication_attempt(
            request_id=request_id,
            attempt_id="attempt-receipt-crash",
            outcome="submitted",
            reference="chatgpt:connector-refresh:submitted",
            now_unix=1_010,
        )
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:receipt-crash",
            observation_scope="connector_catalog",
            observation_id="connector-receipt-crash",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        with mock.patch.object(
            snapshot,
            "_write_publication_current",
            side_effect=RuntimeError("simulated post-receipt crash"),
        ):
            with self.assertRaisesRegex(RuntimeError, "post-receipt crash"):
                snapshot.reconcile_platform_publication_for_runtime(
                    registered_tool_count=metadata["name_count"],
                    registered_names_sha256=metadata["names_sha256"],
                    complete_schema_count=metadata["complete_schema_count"],
                    complete_schema_sha256=metadata["complete_schema_sha256"],
                    now_unix=1_110,
                )
        receipt = snapshot._read_publication_receipt(request_id)
        self.assertEqual(
            snapshot._read_publication_current()["state"],
            "awaiting_platform_observation",
        )

        replay = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=2_000,
        )
        self.assertEqual(replay["state"], "platform_converged")
        self.assertEqual(replay["receipt_sha256"], receipt["receipt_sha256"])
        self.assertEqual(
            snapshot._read_publication_current()["state"], "platform_converged"
        )

    def test_rollback_restores_previous_contract_after_failed_pre_switch_cutover(self) -> None:
        first = self.artifact()
        first_prepared = self.prepare_request(first, cutover_id="cutover-first")
        snapshot.activate_platform_publication_request(
            request_id=first_prepared["request_id"], now_unix=1_005
        )
        tools = json.loads(json.dumps(self.runtime_tool_objects()))
        tools.append(
            {"name": "beta", "inputSchema": {"type": "object", "properties": {}}}
        )
        second = connector_contract.mixed_artifact_from_runtime_tools(tools)
        second_metadata = connector_contract.parse_observed_artifact(second)[2]
        second_prepared = snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=second_metadata["name_count"],
            registered_names_sha256=second_metadata["names_sha256"],
            complete_schema_count=second_metadata["complete_schema_count"],
            complete_schema_sha256=second_metadata["complete_schema_sha256"],
            cutover_id="cutover-second",
            now_unix=1_100,
        )
        rolled_back = snapshot.rollback_platform_publication_request(
            request_id=second_prepared["request_id"],
            active_contract=first_prepared["contract"],
            now_unix=1_110,
        )
        self.assertEqual(rolled_back["state"], "rolled_back")
        self.assertEqual(
            snapshot._read_publication_current()["request_id"], first_prepared["request_id"]
        )

    def test_same_count_different_name_reports_exact_diff(self) -> None:
        runtime_artifact = self.artifact()
        runtime_names = connector_contract.parse_observed_artifact(runtime_artifact)[0]
        platform_tools = json.loads(json.dumps(self.runtime_tool_objects()))
        alpha = next(item for item in platform_tools if item["name"] == "alpha")
        alpha["name"] = "omega"
        platform_artifact = connector_contract.mixed_artifact_from_runtime_tools(
            platform_tools
        )
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=platform_artifact,
            runtime_root=self.runtime_root(runtime_names),
            source_reference="chatgpt:connector:same-count-different-name",
            observation_scope="connector_catalog",
            observation_id="connector-name-drift",
            observed_at_unix=1_000,
        )
        metadata = connector_contract.parse_observed_artifact(runtime_artifact)[2]
        status = snapshot.platform_snapshot_status(
            expected_tool_count=metadata["name_count"],
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=runtime_artifact,
            now_unix=1_100,
        )
        self.assertEqual(status["catalog"]["name_count"], metadata["name_count"])
        self.assertEqual(status["missing_from_platform"], ["alpha"])
        self.assertEqual(status["unexpected_in_platform"], ["omega"])
        self.assertFalse(status["publication_contract_matches"])
        self.assertEqual(status["publication_state"], "publication_request_required")

    def test_same_names_full_schema_drift_cannot_converge(self) -> None:
        runtime_artifact = self.artifact()
        runtime_names = connector_contract.parse_observed_artifact(runtime_artifact)[0]
        prepared = self.prepare_request(runtime_artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        platform_tools = json.loads(json.dumps(self.runtime_tool_objects()))
        alpha = next(item for item in platform_tools if item["name"] == "alpha")
        alpha["inputSchema"]["properties"]["value"]["minLength"] = 1
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(platform_tools),
            runtime_root=self.runtime_root(runtime_names),
            source_reference="chatgpt:connector:schema-drift",
            observation_scope="connector_catalog",
            observation_id="connector-schema-drift",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(runtime_artifact)[2]
        reconciled = snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )
        self.assertEqual(reconciled["reason"], "platform_surface_mismatch")
        self.assertEqual(reconciled["state"], "publication_pending")
        self.assertFalse(reconciled["observation"]["surface_matches"])

    def test_extra_platform_tool_is_reported_exactly(self) -> None:
        runtime_artifact = self.artifact()
        runtime_names = connector_contract.parse_observed_artifact(runtime_artifact)[0]
        platform_tools = json.loads(json.dumps(self.runtime_tool_objects()))
        platform_tools.append(
            {"name": "platform-extra", "inputSchema": {"type": "object", "properties": {}}}
        )
        platform_artifact = connector_contract.mixed_artifact_from_runtime_tools(
            platform_tools
        )
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=platform_artifact,
            runtime_root=self.runtime_root(runtime_names),
            source_reference="chatgpt:connector:extra-tool",
            observation_scope="connector_catalog",
            observation_id="connector-extra-tool",
            observed_at_unix=1_000,
        )
        metadata = connector_contract.parse_observed_artifact(runtime_artifact)[2]
        status = snapshot.platform_snapshot_status(
            expected_tool_count=metadata["name_count"],
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=runtime_artifact,
            now_unix=1_100,
        )
        self.assertEqual(status["missing_from_platform"], [])
        self.assertEqual(status["unexpected_in_platform"], ["platform-extra"])
        self.assertFalse(status["publication_contract_matches"])

    def test_converged_semantic_contract_survives_provenance_only_deploy(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:converged",
            observation_scope="new_chat_catalog",
            observation_id="new-chat-converged",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )

        status = snapshot.platform_snapshot_status(
            expected_tool_count=metadata["name_count"],
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id="new-release-same-surface",
            expected_repo_head="d" * 40,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=artifact,
            now_unix=1_120,
        )
        self.assertEqual(status["state"], "mismatch")
        self.assertFalse(status["provenance_matches"])
        self.assertEqual(status["publication_state"], "platform_converged")
        self.assertFalse(status["publication_pending"])
        replay = snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            cutover_id="later-code-only-deploy",
            now_unix=1_130,
        )
        self.assertTrue(replay["reused"])
        self.assertEqual(replay["state"], "platform_converged")
        self.assertEqual(replay["request_id"], request_id)

    def test_missing_convergence_receipt_invalidates_terminal_projection(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        prepared = self.prepare_request(artifact)
        request_id = prepared["request_id"]
        snapshot.activate_platform_publication_request(request_id=request_id, now_unix=1_005)
        self.platform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot.capture_platform_connector_snapshot(
            observed_tools=self.complete_artifact(),
            runtime_root=self.runtime_root(names),
            source_reference="chatgpt:connector:receipt-test",
            observation_scope="connector_catalog",
            observation_id="connector-receipt-test",
            publication_request_id=request_id,
            requested_contract_sha256=prepared["contract"]["tool_contract_sha256"],
            observed_at_unix=1_100,
        )
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        snapshot.reconcile_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            now_unix=1_110,
        )
        snapshot._publication_receipt_path(request_id).unlink()
        projection = snapshot._publication_projection_for_contract(
            prepared["contract"], now_unix=1_120
        )
        self.assertEqual(projection["state"], "invalid")
        self.assertTrue(projection["publication_pending"])
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "convergence receipt is unavailable or invalid"
        ):
            snapshot.prepare_platform_publication_for_runtime(
                registered_tool_count=metadata["name_count"],
                registered_names_sha256=metadata["names_sha256"],
                complete_schema_count=metadata["complete_schema_count"],
                complete_schema_sha256=metadata["complete_schema_sha256"],
                cutover_id="code-only-after-corrupt-receipt",
                now_unix=1_130,
            )
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "lacks a valid convergence receipt"
        ):
            snapshot.activate_platform_publication_request(
                request_id=request_id, now_unix=1_140
            )

    def test_request_binding_pair_is_fail_closed(self) -> None:
        artifact = self.artifact()
        names = connector_contract.parse_observed_artifact(artifact)[0]
        with self.assertRaisesRegex(snapshot.ClientSnapshotError, "must be supplied together"):
            snapshot.build_platform_connector_snapshot(
                observed_tools=artifact,
                runtime_root=self.runtime_root(names),
                source_reference="chatgpt:connector:bad-binding",
                observation_scope="connector_catalog",
                observation_id="connector-bad-binding",
                publication_request_id="gpp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )

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
                observation_scope="chat_session_catalog",
                observation_id="session-cutover-test",
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
                    observation_scope="chat_session_catalog",
                    observation_id="session-trust-test",
                )

        self.platform_path.parent.chmod(0o777)
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "trusted root-owned directory"
        ):
            snapshot.capture_platform_connector_snapshot(
                observed_tools=artifact,
                runtime_root=runtime_root,
                source_reference="chatgpt:connector-catalog:test",
                observation_scope="chat_session_catalog",
                observation_id="session-parent-test",
            )


if __name__ == "__main__":
    unittest.main()

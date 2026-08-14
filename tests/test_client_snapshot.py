from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_client_snapshot as snapshot
import grabowski_connector_contract as connector_contract


TOOL_HASH = "a" * 64
INSTRUCTIONS_HASH = "b" * 64
RELEASE_ID = "release-test"
REPO_HEAD = "c" * 40


class ClientSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "client-snapshot"
        self.patches = (
            mock.patch.object(snapshot, "STATE_ROOT", root),
            mock.patch.object(snapshot, "SNAPSHOT_PATH", root / "current.json"),
            mock.patch.object(snapshot, "OBSERVER_STATE_PATH", root / "observer.json"),
            mock.patch.object(snapshot, "LOCK_PATH", root / ".lock"),
            mock.patch.object(
                snapshot, "PLATFORM_SNAPSHOT_PATH", root / "platform-current.json"
            ),
            mock.patch.object(snapshot, "PLATFORM_SNAPSHOT_TRUSTED_UID", os.getuid()),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def parameters(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "client_id": "chatgpt-api-tool",
            "session_id": "session-1",
            "observed_tool_count": 140,
            "observed_names_sha256": TOOL_HASH,
            "observed_release_id": RELEASE_ID,
            "observed_agent_instructions_sha256": INSTRUCTIONS_HASH,
            "_server_tool_contract": {
                "registered_tool_count": 140,
                "registered_names_sha256": TOOL_HASH,
                "runtime_matches_deployment_contract": True,
            },
            "_server_runtime": {
                "release_id": RELEASE_ID,
                "repo_head": REPO_HEAD,
            },
            "_server_agent_instructions_sha256": INSTRUCTIONS_HASH,
        }
        value.update(overrides)
        return value

    def status(self, *, now_unix: int = 1_100) -> dict[str, object]:
        return snapshot.snapshot_status(
            expected_tool_count=140,
            expected_names_sha256=TOOL_HASH,
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            now_unix=now_unix,
        )

    def schema_artifact(self) -> dict[str, object]:
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
                        {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                        },
                    ),
                }
                for name in names
            ]
        )

    def schema_parameters(self, **overrides: object) -> dict[str, object]:
        artifact = self.schema_artifact()
        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            artifact
        )
        value = self.parameters(
            observed_tool_count=len(names),
            observed_names_sha256=metadata["names_sha256"],
            observed_tools=artifact,
            _server_tool_contract={
                "registered_tool_count": len(names),
                "registered_names_sha256": metadata["names_sha256"],
                "runtime_matches_deployment_contract": True,
            },
            _server_observed_tools=artifact,
        )
        value.update(overrides)
        return value

    def write_platform_snapshot(
        self,
        artifact: dict[str, object] | None = None,
        *,
        observed_at_unix: int = 1_000,
        release_id: str = RELEASE_ID,
        repo_head: str = REPO_HEAD,
    ) -> dict[str, object]:
        observed_tools = self.schema_artifact() if artifact is None else artifact
        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            observed_tools
        )
        document: dict[str, object] = {
            "schema_version": snapshot.PLATFORM_SNAPSHOT_SCHEMA_VERSION,
            "kind": snapshot.PLATFORM_SNAPSHOT_KIND,
            "source": {
                "kind": snapshot.PLATFORM_SOURCE_KIND,
                "connector": "grabowski",
                "reference": "chatgpt:connector-catalog:test-observation",
                "observed_at_unix": observed_at_unix,
                "catalog_sha256": metadata["artifact_sha256"],
            },
            "runtime_binding": {
                "registered_tool_count": len(names),
                "registered_names_sha256": metadata["names_sha256"],
                "release_id": release_id,
                "repo_head": repo_head,
                "agent_instructions_sha256": INSTRUCTIONS_HASH,
            },
            "observed_tools": observed_tools,
        }
        document["snapshot_sha256"] = snapshot._sha256_json(document)
        snapshot.PLATFORM_SNAPSHOT_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        snapshot._write_private_json(snapshot.PLATFORM_SNAPSHOT_PATH, document)
        return document

    def platform_status(
        self,
        *,
        platform_artifact: dict[str, object] | None = None,
        runtime_artifact: dict[str, object] | None = None,
        now_unix: int = 1_100,
    ) -> dict[str, object]:
        platform_artifact = (
            self.schema_artifact() if platform_artifact is None else platform_artifact
        )
        runtime_artifact = (
            self.schema_artifact() if runtime_artifact is None else runtime_artifact
        )
        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            runtime_artifact
        )
        return snapshot.platform_snapshot_status(
            expected_tool_count=len(names),
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=runtime_artifact,
            now_unix=now_unix,
        )

    def test_matching_snapshot_is_fresh_and_observable(self) -> None:
        result = snapshot.bind_snapshot(self.parameters(), now_unix=1_000)

        self.assertTrue(result["verified"])
        self.assertEqual(result["state"], "matched")
        observed = self.status()
        self.assertEqual(observed["state"], "matched")
        self.assertTrue(observed["observable"])
        self.assertFalse(observed["schema_observable"])
        self.assertFalse(observed["schema_evidence_observed"])
        self.assertTrue(observed["fresh"])
        self.assertTrue(observed["matched"])
        self.assertEqual(snapshot.SNAPSHOT_PATH.stat().st_mode & 0o777, 0o600)

    def test_schema_snapshot_is_independently_observable(self) -> None:
        parameters = self.schema_parameters()
        result = snapshot.bind_snapshot(parameters, now_unix=1_000)

        self.assertTrue(result["verified"])
        self.assertTrue(result["matches"])
        self.assertTrue(result["name_contract_matches"])
        self.assertTrue(result["runtime_contract_matches"])
        self.assertTrue(result["schema_contract_matches"])
        self.assertEqual(
            result["observation_scope"],
            snapshot.OBSERVATION_SCOPE_EXTERNAL_CLIENT,
        )
        self.assertEqual(result["missing_schema_sentinels"], [])
        self.assertEqual(result["required_schema_property_mismatches"], [])
        self.assertEqual(result["schema_mismatches"], [])

        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            parameters["observed_tools"]
        )
        observed = snapshot.snapshot_status(
            expected_tool_count=len(names),
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=parameters["observed_tools"],
            now_unix=1_100,
        )
        self.assertTrue(observed["observable"])
        self.assertTrue(observed["schema_observable"])
        self.assertTrue(observed["schema_evidence_observed"])
        self.assertTrue(observed["schema_contract_matches"])
        self.assertTrue(observed["external_client_snapshot_observable"])
        self.assertTrue(observed["external_client_schema_observable"])
        self.assertFalse(observed["platform_connector_snapshot_observable"])
        self.assertFalse(observed["platform_connector_schema_observable"])
        self.assertEqual(observed["platform_evidence_state"], "missing")
        self.assertFalse(observed["server_loopback_observable"])
        self.assertIn(
            "platform connector catalog snapshot",
            observed["recommended_next_action"],
        )

    def test_watchdog_snapshot_is_loopback_evidence_not_platform_publication(self) -> None:
        parameters = self.schema_parameters(
            client_id=snapshot.AUTO_REFRESH_CLIENT_ID,
            session_id=snapshot.connector_session_id(10, 20),
        )
        result = snapshot.bind_snapshot(parameters, now_unix=1_000)

        self.assertTrue(result["verified"])
        self.assertTrue(result["schema_contract_matches"])
        self.assertEqual(
            result["observation_scope"],
            snapshot.OBSERVATION_SCOPE_SERVER_LOOPBACK,
        )

        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            parameters["observed_tools"]
        )
        observed = snapshot.snapshot_status(
            expected_tool_count=len(names),
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            now_unix=1_100,
        )

        self.assertTrue(observed["observable"])
        self.assertEqual(
            observed["observation_scope"],
            snapshot.OBSERVATION_SCOPE_SERVER_LOOPBACK,
        )
        self.assertTrue(observed["server_loopback_observable"])
        self.assertTrue(observed["server_loopback_schema_observable"])
        self.assertTrue(observed["server_loopback_schema_contract_matches"])
        self.assertFalse(observed["platform_connector_snapshot_observable"])
        self.assertFalse(observed["platform_connector_schema_observable"])
        self.assertFalse(observed["schema_observable"])
        self.assertFalse(observed["schema_contract_matches"])
        self.assertIn(
            "platform connector catalog snapshot",
            observed["recommended_next_action"],
        )
        self.assertTrue(
            any(
                "tool schema visibility in ChatGPT" in item
                for item in observed["does_not_establish"]
            )
        )

    def test_full_platform_snapshot_convergence_is_separate_and_observable(self) -> None:
        parameters = self.schema_parameters()
        artifact = parameters["observed_tools"]
        snapshot.bind_snapshot(parameters, now_unix=1_000)
        self.write_platform_snapshot(artifact)
        names, _schemas, metadata = connector_contract.parse_observed_artifact(artifact)

        observed = snapshot.snapshot_status(
            expected_tool_count=len(names),
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=artifact,
            now_unix=1_100,
        )

        self.assertTrue(observed["external_client_snapshot_observable"])
        self.assertTrue(observed["platform_connector_snapshot_observable"])
        self.assertTrue(observed["platform_connector_schema_observable"])
        self.assertEqual(observed["platform_evidence_state"], "matched")
        self.assertEqual(
            observed["platform_snapshot"]["source"]["kind"],
            snapshot.PLATFORM_SOURCE_KIND,
        )
        self.assertEqual(observed["recommended_next_action"], "none")

    def test_platform_match_fields_remain_paired_without_client_receipt(self) -> None:
        artifact = self.schema_artifact()
        self.write_platform_snapshot(artifact)
        names, _schemas, metadata = connector_contract.parse_observed_artifact(artifact)

        observed = snapshot.snapshot_status(
            expected_tool_count=len(names),
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            expected_runtime_tools=artifact,
            now_unix=1_100,
        )

        self.assertEqual(observed["state"], "missing")
        self.assertFalse(observed["observable"])
        self.assertFalse(observed["matched"])
        self.assertTrue(observed["platform_connector_snapshot_observable"])
        self.assertTrue(observed["platform_connector_snapshot_fresh"])
        self.assertTrue(observed["platform_connector_snapshot_matched"])
        self.assertEqual(observed["platform_evidence_state"], "matched")

    def test_platform_snapshot_missing_grip_run_allow_mutation_fails_closed(self) -> None:
        runtime_artifact = self.schema_artifact()
        platform_artifact = json.loads(json.dumps(runtime_artifact))
        grip_run = next(
            item
            for item in platform_artifact["tools"]
            if isinstance(item, dict) and item["name"] == "grip_run"
        )
        del grip_run["inputSchema"]["properties"]["allow_mutation"]
        self.write_platform_snapshot(platform_artifact)

        observed = self.platform_status(runtime_artifact=runtime_artifact)

        self.assertEqual(observed["state"], "mismatch")
        self.assertFalse(observed["observable"])
        self.assertFalse(observed["schema_observable"])
        self.assertIn(
            {
                "tool": "grip_run",
                "source": "platform",
                "missing_properties": ["allow_mutation"],
            },
            observed["required_schema_property_mismatches"],
        )

    def test_platform_snapshot_stale_and_revision_drift_fail_closed(self) -> None:
        self.write_platform_snapshot(observed_at_unix=1_000)
        stale = self.platform_status(now_unix=5_000)
        self.assertEqual(stale["state"], "stale")
        self.assertFalse(stale["observable"])

        self.write_platform_snapshot(repo_head="d" * 40)
        drifted = self.platform_status()
        self.assertEqual(drifted["state"], "mismatch")
        self.assertFalse(drifted["observable"])
        self.assertIn("repo_head", drifted["binding_mismatches"])

    def test_platform_snapshot_integrity_and_trust_boundary_fail_closed(self) -> None:
        document = self.write_platform_snapshot()
        document["source"]["reference"] = "tampered"
        snapshot._write_private_json(snapshot.PLATFORM_SNAPSHOT_PATH, document)
        tampered = self.platform_status()
        self.assertEqual(tampered["state"], "invalid")
        self.assertFalse(tampered["observable"])

        self.write_platform_snapshot()
        with mock.patch.object(
            snapshot, "PLATFORM_SNAPSHOT_TRUSTED_UID", os.getuid() + 1
        ):
            untrusted = self.platform_status()
        self.assertEqual(untrusted["state"], "invalid")
        self.assertFalse(untrusted["observable"])

    def test_schema_snapshot_fails_closed_on_field_and_binding_drift(self) -> None:
        for field in sorted(
            connector_contract.REQUIRED_SCHEMA_PROPERTIES[
                "grabowski_task_start"
            ]
        ):
            with self.subTest(field=field):
                parameters = self.schema_parameters()
                artifact = parameters["observed_tools"]
                task_start = next(
                    item
                    for item in artifact["tools"]
                    if isinstance(item, dict)
                    and item["name"] == "grabowski_task_start"
                )
                del task_start["inputSchema"]["properties"][field]
                names, _schemas, metadata = (
                    connector_contract.parse_observed_artifact(artifact)
                )
                parameters["observed_tool_count"] = len(names)
                parameters["observed_names_sha256"] = metadata["names_sha256"]
                result = snapshot.bind_snapshot(parameters, now_unix=1_000)
                self.assertFalse(result["verified"])
                self.assertIn("schema_contract", result["mismatches"])
                self.assertIn(
                    {
                        "tool": "grabowski_task_start",
                        "source": "connector",
                        "missing_properties": [field],
                    },
                    result["required_schema_property_mismatches"],
                )

        parameters = self.schema_parameters(observed_release_id="stale-release")
        result = snapshot.bind_snapshot(parameters, now_unix=1_000)
        self.assertFalse(result["verified"])
        self.assertIn("release_id", result["mismatches"])

        parameters = self.schema_parameters()
        snapshot.bind_snapshot(parameters, now_unix=1_000)
        names, _schemas, metadata = connector_contract.parse_observed_artifact(
            parameters["observed_tools"]
        )
        head_drift = snapshot.snapshot_status(
            expected_tool_count=len(names),
            expected_names_sha256=metadata["names_sha256"],
            expected_release_id=RELEASE_ID,
            expected_repo_head="d" * 40,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            now_unix=1_100,
        )
        self.assertFalse(head_drift["observable"])
        self.assertFalse(head_drift["schema_observable"])

    def test_mismatch_is_persisted_but_never_observable(self) -> None:
        result = snapshot.bind_snapshot(
            self.parameters(observed_tool_count=139),
            now_unix=1_000,
        )

        self.assertFalse(result["verified"])
        self.assertEqual(result["mismatches"], ["tool_count"])
        observed = self.status()
        self.assertEqual(observed["state"], "mismatch")
        self.assertFalse(observed["observable"])

    def test_stale_snapshot_is_not_observable(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)

        observed = self.status(
            now_unix=1_000 + snapshot.SNAPSHOT_TTL_SECONDS + 1
        )
        self.assertEqual(observed["state"], "stale")
        self.assertFalse(observed["observable"])
        self.assertFalse(observed["fresh"])

    def test_tampered_receipt_fails_closed(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)
        document = json.loads(snapshot.SNAPSHOT_PATH.read_text(encoding="utf-8"))
        document["verified"] = False
        snapshot.SNAPSHOT_PATH.write_text(
            json.dumps(document),
            encoding="utf-8",
        )
        snapshot.SNAPSHOT_PATH.chmod(0o600)

        observed = self.status()
        self.assertEqual(observed["state"], "invalid")
        self.assertFalse(observed["observable"])

    def test_symlink_receipt_is_rejected(self) -> None:
        snapshot.STATE_ROOT.mkdir(mode=0o700, parents=True)
        target = snapshot.STATE_ROOT / "target.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        snapshot.SNAPSHOT_PATH.symlink_to(target.name)

        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot.bind_snapshot(self.parameters(), now_unix=1_000)

    def test_server_context_cannot_be_omitted_or_spoofed_by_shape(self) -> None:
        parameters = self.parameters()
        parameters.pop("_server_tool_contract")
        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot.bind_snapshot(parameters, now_unix=1_000)

        parameters = self.parameters(
            _server_tool_contract={
                "registered_tool_count": 140,
                "registered_names_sha256": TOOL_HASH,
                "runtime_matches_deployment_contract": False,
            }
        )
        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot.bind_snapshot(parameters, now_unix=1_000)

    def test_auto_refresh_preserves_fresh_external_snapshot_until_renewal_window(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)
        reason = snapshot._snapshot_refresh_reason(
            session_id=snapshot.connector_session_id(10, 20),
            expected_release_id=RELEASE_ID,
            now_unix=1_100,
        )
        self.assertIsNone(reason)

    def _rewrite_snapshot_binding_release(self, release_id: str) -> None:
        receipt = snapshot._read_private_json(snapshot.SNAPSHOT_PATH)
        receipt["server_binding"]["release_id"] = release_id
        unsigned = dict(receipt)
        unsigned.pop("receipt_sha256", None)
        receipt["receipt_sha256"] = snapshot._sha256_json(unsigned)
        snapshot._write_private_json(snapshot.SNAPSHOT_PATH, receipt)

    def test_auto_refresh_detects_loopback_declaration_release_lag_after_cutover(self) -> None:
        session = snapshot.connector_session_id(10, 20)
        snapshot.bind_snapshot(
            self.parameters(client_id=snapshot.AUTO_REFRESH_CLIENT_ID, session_id=session),
            now_unix=1_000,
        )
        self._rewrite_snapshot_binding_release("new-release")
        self.assertEqual(
            snapshot._snapshot_refresh_reason(
                session_id=session,
                expected_release_id="new-release",
                now_unix=1_100,
            ),
            "runtime-release-changed",
        )

    def test_auto_refresh_preserves_external_declaration_across_binding_transition(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)
        self._rewrite_snapshot_binding_release("new-release")
        self.assertIsNone(
            snapshot._snapshot_refresh_reason(
                session_id=snapshot.connector_session_id(10, 20),
                expected_release_id="new-release",
                now_unix=1_100,
            )
        )

    def test_auto_refresh_detects_tunnel_session_change(self) -> None:
        session = snapshot.connector_session_id(10, 20)
        snapshot.bind_snapshot(
            self.parameters(client_id=snapshot.AUTO_REFRESH_CLIENT_ID, session_id=session),
            now_unix=1_000,
        )
        reason = snapshot._snapshot_refresh_reason(
            session_id=snapshot.connector_session_id(11, 21),
            expected_release_id=RELEASE_ID,
            now_unix=1_100,
        )
        self.assertEqual(reason, "connector-session-changed")

    def test_auto_refresh_detects_release_change_and_renewal_window(self) -> None:
        session = snapshot.connector_session_id(10, 20)
        snapshot.bind_snapshot(
            self.parameters(client_id=snapshot.AUTO_REFRESH_CLIENT_ID, session_id=session),
            now_unix=1_000,
        )
        self.assertEqual(
            snapshot._snapshot_refresh_reason(
                session_id=session,
                expected_release_id="new-release",
                now_unix=1_100,
            ),
            "runtime-release-changed",
        )
        self.assertEqual(
            snapshot._snapshot_refresh_reason(
                session_id=session,
                expected_release_id=RELEASE_ID,
                now_unix=1_000 + snapshot.SNAPSHOT_TTL_SECONDS - snapshot.AUTO_REFRESH_RENEW_MARGIN_SECONDS,
            ),
            "renewal-window",
        )


    def test_external_snapshot_uses_observer_marker_to_detect_later_session_change(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)
        first = snapshot.connector_session_id(10, 20)
        snapshot._write_observer_state(
            session_id=first, release_id=RELEASE_ID, now_unix=1_000
        )
        last_session, invalid = snapshot._observer_session_state()
        self.assertFalse(invalid)
        self.assertEqual(
            snapshot._snapshot_refresh_reason(
                session_id=snapshot.connector_session_id(11, 21),
                expected_release_id=RELEASE_ID,
                now_unix=1_100,
                last_observed_session_id=last_session,
                observer_state_invalid=invalid,
            ),
            "connector-session-changed",
        )

    def test_tool_listing_collects_all_pages_and_rejects_cursor_cycles(self) -> None:
        class Page:
            def __init__(self, names: list[str], next_cursor: str | None) -> None:
                self.tools = [type("Tool", (), {"name": name})() for name in names]
                self.nextCursor = next_cursor

        class Client:
            def __init__(self, pages: dict[str | None, Page]) -> None:
                self.pages = pages

            async def list_tools(self, cursor: str | None = None) -> Page:
                return self.pages[cursor]

        names = asyncio.run(
            snapshot._list_all_tool_names(
                Client({None: Page(["b"], "next"), "next": Page(["a"], None)})
            )
        )
        self.assertEqual(names, ["b", "a"])
        with self.assertRaises(snapshot.ClientSnapshotError):
            asyncio.run(
                snapshot._list_all_tool_names(
                    Client({None: Page(["a"], "loop"), "loop": Page(["b"], "loop")})
                )
            )

    def test_tool_observation_builds_exact_mixed_schema_artifact(self) -> None:
        schemas = {
            item["name"]: item["inputSchema"]
            for item in self.schema_artifact()["tools"]
            if isinstance(item, dict)
        }

        class Tool:
            def __init__(self, name: str, schema: dict[str, object] | None = None) -> None:
                self.name = name
                self.inputSchema = schema

        tools = [
            Tool(
                "zeta",
                {"type": "object", "properties": {"value": {"type": "string"}}},
            ),
            Tool("grabowski_task_start", schemas["grabowski_task_start"]),
            Tool("grip_run", schemas["grip_run"]),
            Tool("grabowski_secret_reveal", schemas["grabowski_secret_reveal"]),
            Tool(
                "grabowski_bureau_candidate_assess",
                schemas["grabowski_bureau_candidate_assess"],
            ),
            Tool("alpha", {"type": "object", "properties": {"ignored": {}}}),
        ]
        artifact = snapshot._mixed_observed_tool_artifact(tools)
        names, observed_schemas, metadata = (
            connector_contract.parse_observed_artifact(artifact)
        )

        self.assertEqual(names, sorted(tool.name for tool in tools))
        self.assertEqual(
            sorted(observed_schemas),
            sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS),
        )
        self.assertEqual(metadata["schema_coverage_count"], 4)
        self.assertLessEqual(
            metadata["artifact_bytes"],
            connector_contract.MAX_OBSERVED_ARTIFACT_BYTES,
        )
        self.assertNotIn("alpha", observed_schemas)

    def test_tool_observation_rejects_missing_or_duplicate_sentinel_evidence(self) -> None:
        class Tool:
            def __init__(self, name: str, schema: object = None) -> None:
                self.name = name
                self.inputSchema = schema

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "runtime schema for grabowski_task_start is unavailable",
        ):
            snapshot._mixed_observed_tool_artifact(
                [
                    Tool("grabowski_task_start"),
                    Tool("grip_run", {}),
                    Tool("grabowski_secret_reveal", {}),
                    Tool("grabowski_bureau_candidate_assess", {}),
                ]
            )
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "duplicate runtime tool: alpha",
        ):
            snapshot._mixed_observed_tool_artifact([Tool("alpha"), Tool("alpha")])

    def test_observer_binds_mixed_schema_artifact_and_requires_schema_match(
        self,
    ) -> None:
        import sys
        import types

        schemas = {
            item["name"]: item["inputSchema"]
            for item in self.schema_artifact()["tools"]
            if isinstance(item, dict)
        }

        class Tool:
            def __init__(self, name: str, schema: dict[str, object] | None = None) -> None:
                self.name = name
                self.inputSchema = schema

        tools = [
            Tool("alpha", {"type": "object", "properties": {"ignored": {}}}),
            Tool(
                "grabowski_bureau_candidate_assess",
                schemas["grabowski_bureau_candidate_assess"],
            ),
            Tool("grabowski_secret_reveal", schemas["grabowski_secret_reveal"]),
            Tool("grip_run", schemas["grip_run"]),
            Tool("grabowski_task_start", schemas["grabowski_task_start"]),
            Tool(
                "zeta",
                {"type": "object", "properties": {"value": {"type": "string"}}},
            ),
        ]
        artifact = snapshot._mixed_observed_tool_artifact(tools)
        names, _observed_schemas, metadata = (
            connector_contract.parse_observed_artifact(artifact)
        )

        class Page:
            def __init__(self) -> None:
                self.tools = tools
                self.nextCursor = None

        class AsyncContext:
            def __init__(self, value: object) -> None:
                self.value = value

            async def __aenter__(self) -> object:
                return self.value

            async def __aexit__(self, *_args: object) -> bool:
                return False

        declarations: list[dict[str, object]] = []
        request_metas: list[dict[str, object] | None] = []
        transport_headers: list[dict[str, str] | None] = []
        connector_capability = "C" * 43

        class Client:
            async def initialize(self) -> None:
                return None

            async def list_tools(self, *, cursor: str | None = None) -> Page:
                if cursor is not None:
                    raise AssertionError("unexpected pagination cursor")
                return Page()

            async def call_tool(
                self,
                name: str,
                arguments: dict[str, object],
                *,
                meta: dict[str, object] | None = None,
            ) -> object:
                request_metas.append(meta)
                if name == "grip_run":
                    declarations.append(arguments)
                return object()

        client = Client()
        schema_match = True

        def payload(_result: object, *, label: str) -> dict[str, object]:
            if label == "grabowski_status":
                return {
                    "runtime": {"release_id": RELEASE_ID},
                    "agent_instructions": {"sha256": INSTRUCTIONS_HASH},
                    "tool_contract": {
                        "registered_tool_count": len(names),
                        "registered_names_sha256": metadata["names_sha256"],
                        "runtime_matches_deployment_contract": True,
                    },
                }
            if label == "transport roundtrip begin grip":
                return {
                    "status": "passed",
                    "output": {
                        "state": "challenge_pending",
                        "mutation_gate_open": False,
                        "challenge_receipt_sha256": "e" * 64,
                    },
                }
            if label == "transport roundtrip execute grip":
                return {
                    "status": "passed",
                    "output": {
                        "state": "executed",
                        "mutation_gate_open": False,
                        "verification_receipt_sha256": "f" * 64,
                        "target_result": {"isError": False, "structuredContent": {}},
                        "target_error": None,
                    },
                }
            return {
                "status": "passed",
                "output": {
                    "verified": True,
                    "state": "matched",
                    "schema_contract_matches": schema_match,
                    "receipt_sha256": "d" * 64,
                },
            }

        mcp_module = types.ModuleType("mcp")
        mcp_module.__path__ = []
        mcp_module.ClientSession = lambda _read, _write: AsyncContext(client)
        client_module = types.ModuleType("mcp.client")
        client_module.__path__ = []
        streamable_http_module = types.ModuleType("mcp.client.streamable_http")
        streamable_http_module.streamablehttp_client = (
            lambda _url, *, headers=None: (
                transport_headers.append(headers)
                or AsyncContext((object(), object(), None))
            )
        )

        with (
            mock.patch.dict(
                sys.modules,
                {
                    "mcp": mcp_module,
                    "mcp.client": client_module,
                    "mcp.client.streamable_http": streamable_http_module,
                },
            ),
            mock.patch.object(snapshot, "_mcp_tool_payload", side_effect=payload),
        ):
            result = asyncio.run(
                snapshot._observe_and_bind_snapshot(
                    mcp_url="http://127.0.0.1:18181/mcp",
                    session_id="session-schema",
                    connector_capability=connector_capability,
                    timeout_seconds=1.0,
                )
            )
            self.assertTrue(result["schema_contract_matches"])
            self.assertEqual(result["schema_coverage_count"], 4)
            self.assertEqual(
                transport_headers,
                [
                    {
                        snapshot.TRANSPORT_CONNECTOR_CAPABILITY_HEADER: (
                            connector_capability
                        )
                    }
                ],
            )
            self.assertNotIn(connector_capability, json.dumps(result))
            self.assertEqual(
                result["transport_verification_receipt_sha256"],
                "f" * 64,
            )
            self.assertEqual(
                request_metas[:3],
                [{"client_id": snapshot.AUTO_REFRESH_CLIENT_ID}] * 3,
            )
            self.assertEqual(len(declarations), 2)
            self.assertEqual(
                [entry["name"] for entry in declarations],
                ["transport-roundtrip", "transport-roundtrip"],
            )
            # Atomic execute stays bound to the exact binder declared by begin;
            # a second direct binder call would duplicate the effect.
            begin_parameters = declarations[-2]["parameters"]
            self.assertEqual(begin_parameters["action"], "begin")
            self.assertEqual(begin_parameters["target_tool_name"], "grip_run")
            bind_arguments = begin_parameters["target_arguments"]
            self.assertEqual(
                declarations[-1]["parameters"],
                {
                    "action": "execute",
                    "challenge_receipt_sha256": "e" * 64,
                    "target_tool_name": "grip_run",
                    "target_arguments": bind_arguments,
                },
            )
            self.assertEqual(bind_arguments["name"], "connector-snapshot-bind")
            declaration = bind_arguments["parameters"]
            self.assertEqual(declaration["observed_tools"], artifact)
            self.assertEqual(declaration["observed_tool_count"], len(names))

            schema_match = False
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError,
                "connector snapshot bind did not pass verification",
            ):
                asyncio.run(
                    snapshot._observe_and_bind_snapshot(
                        mcp_url="http://127.0.0.1:18181/mcp",
                        session_id="session-schema-failed",
                        connector_capability=connector_capability,
                        timeout_seconds=1.0,
                    )
                )

    def test_auto_refresh_capability_is_bound_to_operator_endpoint(self) -> None:
        self.assertEqual(
            snapshot._validate_loopback_mcp_url("http://127.0.0.1:18181/mcp"),
            snapshot.AUTO_REFRESH_MCP_URL,
        )
        for url in (
            "http://127.0.0.1:18180/mcp",
            "http://127.0.0.1:1/mcp",
            "http://localhost:18181/mcp",
        ):
            with self.subTest(url=url), self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "bound loopback operator endpoint"
            ):
                snapshot._validate_loopback_mcp_url(url)

    def test_runtime_readiness_probe_endpoints_are_auth_mode_bound(self) -> None:
        self.assertEqual(
            snapshot._validate_runtime_probe_mcp_url(
                "http://127.0.0.1:18182/mcp", auth_mode="connector"
            ),
            "http://127.0.0.1:18182/mcp",
        )
        self.assertEqual(
            snapshot._validate_runtime_probe_mcp_url(
                "http://127.0.0.1:18180/mcp", auth_mode="ingress"
            ),
            "http://127.0.0.1:18180/mcp",
        )
        for url, auth_mode in (
            ("http://127.0.0.1:18180/mcp", "connector"),
            ("http://127.0.0.1:18182/mcp", "ingress"),
            ("http://127.0.0.1:18181/mcp", "connector"),
            ("http://localhost:18182/mcp", "connector"),
        ):
            with self.subTest(url=url, auth_mode=auth_mode), self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "bound loopback endpoint"
            ):
                snapshot._validate_runtime_probe_mcp_url(url, auth_mode=auth_mode)

    def test_auto_refresh_connector_capability_reader_is_private_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "primary.token"
            token = "D" * 43
            target.write_text(token + "\r\n", encoding="ascii")
            target.chmod(0o600)
            self.assertEqual(
                snapshot._read_transport_connector_capability(target),
                token,
            )

            linked = target.lstat()
            stale_linked = mock.Mock(
                st_mode=linked.st_mode,
                st_uid=linked.st_uid,
                st_nlink=linked.st_nlink,
                st_size=linked.st_size,
                st_dev=linked.st_dev,
                st_ino=linked.st_ino,
                st_mtime_ns=linked.st_mtime_ns + 1,
                st_ctime_ns=linked.st_ctime_ns,
            )
            with mock.patch.object(Path, "lstat", return_value=stale_linked):
                with self.assertRaisesRegex(
                    snapshot.ClientSnapshotError, "changed during open"
                ):
                    snapshot._read_transport_connector_capability(target)

            target.chmod(0o644)
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "capability file is unsafe"
            ):
                snapshot._read_transport_connector_capability(target)

            target.unlink()
            real = root / "real.token"
            real.write_text(token, encoding="ascii")
            real.chmod(0o600)
            target.symlink_to(real)
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "capability file is unsafe"
            ):
                snapshot._read_transport_connector_capability(target)

            target.unlink()
            os.link(real, target)
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "capability file is unsafe"
            ):
                snapshot._read_transport_connector_capability(target)
            target.unlink()
            real.unlink()

            target.write_bytes(b"D" * (snapshot.MAX_TRANSPORT_CONNECTOR_TOKEN_BYTES + 1))
            target.chmod(0o600)
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "capability file is unsafe"
            ):
                snapshot._read_transport_connector_capability(target)

            target.write_bytes(b"D" * 42 + b"\xff")
            target.chmod(0o600)
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "must be ASCII"
            ):
                snapshot._read_transport_connector_capability(target)

            target.write_text("!" * 43, encoding="ascii")
            target.chmod(0o600)
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError, "capability is invalid"
            ):
                snapshot._read_transport_connector_capability(target)

    def test_mcp_tool_payload_accepts_json_safe_embedded_result(self) -> None:
        payload = snapshot._mcp_tool_payload(
            {"isError": False, "structuredContent": {"status": "passed"}},
            label="embedded tool result",
        )
        self.assertEqual(payload, {"status": "passed"})
        direct = {"status": "passed", "output": {"state": "matched"}}
        self.assertEqual(
            snapshot._mcp_tool_payload(direct, label="direct grip result"),
            direct,
        )
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "embedded tool result returned an MCP tool error",
        ):
            snapshot._mcp_tool_payload(
                {"isError": True, "content": []},
                label="embedded tool result",
            )

    def test_tool_name_hash_matches_runtime_contract_encoding(self) -> None:
        expected = snapshot.hashlib.sha256(b'["a","b"]').hexdigest()
        self.assertEqual(snapshot._tool_names_sha256(["b", "a"]), expected)
        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot._tool_names_sha256(["a", "a"])

    def test_runtime_release_id_is_read_from_current_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "deployment-manifest.json").write_text(
                json.dumps({"release_id": RELEASE_ID}), encoding="utf-8"
            )
            self.assertEqual(snapshot._runtime_release_id(root), RELEASE_ID)


if __name__ == "__main__":
    unittest.main()

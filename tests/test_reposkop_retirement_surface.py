from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_client_snapshot as snapshot
import grabowski_connector_contract as connector_contract


class ReposkopRetirementSurfaceRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.publication_root = self.root / "platform-publication"
        self.patches = (
            mock.patch.object(snapshot, "LOCK_PATH", self.root / "snapshot.lock"),
            mock.patch.object(snapshot, "PLATFORM_PUBLICATION_ROOT", self.publication_root),
            mock.patch.object(
                snapshot,
                "PLATFORM_PUBLICATION_REQUEST_ROOT",
                self.publication_root / "requests",
            ),
            mock.patch.object(
                snapshot,
                "PLATFORM_PUBLICATION_ATTEMPT_ROOT",
                self.publication_root / "attempts",
            ),
            mock.patch.object(
                snapshot,
                "PLATFORM_PUBLICATION_RECEIPT_ROOT",
                self.publication_root / "receipts",
            ),
            mock.patch.object(
                snapshot,
                "PLATFORM_PUBLICATION_RESOLUTION_ROOT",
                self.publication_root / "resolutions",
            ),
            mock.patch.object(
                snapshot,
                "PLATFORM_RETIREMENT_OBSERVATION_ROOT",
                self.publication_root / "retirement-observations",
            ),
            mock.patch.object(
                snapshot,
                "PLATFORM_RETIREMENT_RESOLUTION_ROOT",
                self.publication_root / "retirement-resolutions",
            ),
            mock.patch.object(
                snapshot,
                "PLATFORM_PUBLICATION_CURRENT_PATH",
                self.publication_root / "current.json",
            ),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def _artifact(self) -> dict[str, object]:
        def required_properties(tool_name: str) -> dict[str, object]:
            return {
                name: {"type": "string", "default": ""}
                for name in sorted(
                    connector_contract.REQUIRED_SCHEMA_PROPERTIES[tool_name]
                )
            }

        tools = [
            {
                "name": "alpha",
                "inputSchema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                },
            },
            {
                "name": "grabowski_bureau_candidate_assess",
                "inputSchema": {
                    "type": "object",
                    "properties": required_properties(
                        "grabowski_bureau_candidate_assess"
                    ),
                },
            },
            {
                "name": "grip_run",
                "inputSchema": {
                    "type": "object",
                    "properties": required_properties("grip_run"),
                },
            },
            {
                "name": "grabowski_secret_reveal",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            },
            {
                "name": "grabowski_task_start",
                "inputSchema": {
                    "type": "object",
                    "properties": required_properties("grabowski_task_start"),
                },
            },
        ]
        schemas = {item["name"]: item["inputSchema"] for item in tools}
        return {
            "schema_version": connector_contract.OBSERVED_ARTIFACT_SCHEMA_VERSION,
            "tools": tools,
            "complete_schema_count": len(tools),
            "complete_schema_sha256": connector_contract.complete_schema_fingerprint(
                schemas
            ),
        }

    def _activated_request(self) -> str:
        artifact = self._artifact()
        metadata = connector_contract.parse_observed_artifact(artifact)[2]
        prepared = snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=metadata["name_count"],
            registered_names_sha256=metadata["names_sha256"],
            complete_schema_count=metadata["complete_schema_count"],
            complete_schema_sha256=metadata["complete_schema_sha256"],
            cutover_id="reposkop-retirement-regression",
            now_unix=1_000,
        )
        request_id = str(prepared["request_id"])
        snapshot.activate_platform_publication_request(
            request_id=request_id,
            now_unix=1_001,
        )
        return request_id

    def test_newer_forbidden_observation_invalidates_older_positive_resolution(self) -> None:
        request_id = self._activated_request()
        first = snapshot.record_platform_retirement_surface_observation(
            request_id=request_id,
            surface_id="grabowski",
            observation_id="chatgpt-zero-first",
            query="reposkop",
            matched_tool_names=[],
            source_reference="chatgpt-tool-discovery:thread:grabowski:zero",
            now_unix=1_002,
        )
        self.assertEqual(first["state"], "retirement_surface_converged")
        resolution_path = snapshot._retirement_resolution_path(
            request_id,
            "grabowski",
        )
        self.assertTrue(resolution_path.exists())

        second = snapshot.record_platform_retirement_surface_observation(
            request_id=request_id,
            surface_id="grabowski",
            observation_id="chatgpt-forbidden-later",
            query="reposkop",
            matched_tool_names=["grabowski_reposkop_context"],
            source_reference="chatgpt-tool-discovery:thread:grabowski:forbidden",
            now_unix=1_003,
        )

        self.assertEqual(second["state"], "retirement_surface_blocked")
        if resolution_path.exists():
            projection = snapshot._read_private_json(resolution_path)
            self.assertNotEqual(
                projection.get("criterion"),
                "exact_forbidden_tool_names_absent",
            )
            self.assertNotEqual(
                projection.get("state"),
                "retirement_surface_converged",
            )

    def test_any_tool_matching_reposkop_query_blocks_retirement(self) -> None:
        request_id = self._activated_request()

        result = snapshot.record_platform_retirement_surface_observation(
            request_id=request_id,
            surface_id="grabowski",
            observation_id="chatgpt-novel-reposkop-match",
            query="reposkop",
            matched_tool_names=["future_reposkop_diagnostic"],
            source_reference="chatgpt-tool-discovery:thread:grabowski:novel",
            now_unix=1_002,
        )

        self.assertEqual(result["state"], "retirement_surface_blocked")
        self.assertFalse(
            snapshot._retirement_resolution_path(
                request_id,
                "grabowski",
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()

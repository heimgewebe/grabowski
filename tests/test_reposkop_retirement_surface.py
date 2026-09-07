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
        self.state_root = self.root / "state"
        self.publication_root = self.root / "platform-publication"
        self.patches = (
            mock.patch.object(snapshot, "STATE_ROOT", self.state_root),
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

    def _binding(
        self,
        *,
        connector_id: str = "primary",
        surface_id: str = "grabowski",
        client_scope_sha256: str = "1" * 64,
        state_scope_sha256: str | None = None,
        runtime_binding_sha256: str = "3" * 64,
        repo_head: str = "4" * 40,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "connector_id": connector_id,
            "surface_id": surface_id,
            "client_scope_kind": "connector_capability",
            "client_scope_sha256": client_scope_sha256,
            "state_scope_sha256": (
                snapshot._retirement_state_scope_sha256()
                if state_scope_sha256 is None
                else state_scope_sha256
            ),
            "runtime_binding_sha256": runtime_binding_sha256,
            "release_id": "release-test",
            "repo_head": repo_head,
            "registered_names_sha256": "5" * 64,
            "agent_instructions_sha256": "6" * 64,
        }

    def _record(
        self,
        request_id: str,
        *,
        observation_id: str,
        matched_tool_names: list[str],
        now_unix: int,
        binding: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return snapshot.record_platform_retirement_surface_observation(
            request_id=request_id,
            surface_id="grabowski",
            observation_id=observation_id,
            query="reposkop",
            matched_tool_names=matched_tool_names,
            source_reference=f"chatgpt-tool-discovery:thread:grabowski:{observation_id}",
            server_binding=self._binding() if binding is None else binding,
            now_unix=now_unix,
        )

    def test_newer_forbidden_observation_invalidates_older_positive_resolution(self) -> None:
        request_id = self._activated_request()
        first = self._record(
            request_id,
            observation_id="chatgpt-zero-first",
            matched_tool_names=[],
            now_unix=1_002,
        )
        self.assertEqual(first["state"], "retirement_surface_converged")
        first_resolution_sha256 = first["resolution_sha256"]

        second = self._record(
            request_id,
            observation_id="chatgpt-forbidden-later",
            matched_tool_names=["grabowski_reposkop_context"],
            now_unix=1_003,
        )

        self.assertEqual(second["state"], "retirement_surface_blocked")
        self.assertNotEqual(second["resolution_sha256"], first_resolution_sha256)
        projection = snapshot._read_private_json(
            snapshot._retirement_resolution_path(request_id, "grabowski")
        )
        self.assertEqual(projection["state"], "retirement_surface_blocked")
        self.assertEqual(projection["criterion"], "reposkop_query_has_matches")
        self.assertEqual(
            projection["matched_tool_names"], ["grabowski_reposkop_context"]
        )

    def test_any_tool_matching_reposkop_query_blocks_retirement(self) -> None:
        request_id = self._activated_request()

        result = self._record(
            request_id,
            observation_id="chatgpt-novel-reposkop-match",
            matched_tool_names=["future_reposkop_diagnostic"],
            now_unix=1_002,
        )

        self.assertEqual(result["state"], "retirement_surface_blocked")
        self.assertEqual(
            result["forbidden_tool_names_present"], ["future_reposkop_diagnostic"]
        )
        projection = snapshot._read_private_json(
            snapshot._retirement_resolution_path(request_id, "grabowski")
        )
        self.assertEqual(projection["state"], "retirement_surface_blocked")

    def test_replay_of_old_zero_cannot_resurrect_after_newer_block(self) -> None:
        request_id = self._activated_request()
        first = self._record(
            request_id,
            observation_id="chatgpt-zero-first",
            matched_tool_names=[],
            now_unix=1_002,
        )
        blocked = self._record(
            request_id,
            observation_id="chatgpt-block-second",
            matched_tool_names=["future_reposkop_diagnostic"],
            now_unix=1_003,
        )

        replay = self._record(
            request_id,
            observation_id="chatgpt-zero-first",
            matched_tool_names=[],
            now_unix=1_004,
        )

        self.assertEqual(replay["state"], "retirement_surface_blocked")
        self.assertTrue(replay["idempotent"])
        self.assertTrue(replay["replay_superseded"])
        self.assertEqual(replay["observation_sha256"], blocked["observation_sha256"])
        self.assertEqual(
            replay["replayed_observation_sha256"], first["observation_sha256"]
        )

    def test_crash_after_projection_before_observation_fails_closed_and_retry_repairs(self) -> None:
        request_id = self._activated_request()
        binding = self._binding()
        self._record(
            request_id,
            observation_id="chatgpt-zero-before-crash",
            matched_tool_names=[],
            now_unix=1_002,
            binding=binding,
        )
        failed_observation_id = "chatgpt-block-crash-window"
        failed_observation_path = snapshot._retirement_observation_path(
            request_id, "grabowski", failed_observation_id
        )

        with mock.patch.object(
            snapshot,
            "_create_private_json",
            side_effect=OSError("simulated observation persistence failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated observation persistence failure"):
                self._record(
                    request_id,
                    observation_id=failed_observation_id,
                    matched_tool_names=["future_reposkop_diagnostic"],
                    now_unix=1_003,
                    binding=binding,
                )

        projection = snapshot._read_private_json(
            snapshot._retirement_resolution_path(request_id, "grabowski")
        )
        self.assertEqual(projection["state"], "retirement_surface_blocked")
        self.assertEqual(projection["observation_id"], failed_observation_id)
        self.assertFalse(failed_observation_path.exists())
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "pending recovery"
        ):
            snapshot.retirement_surface_status(
                request_id=request_id,
                surface_id="grabowski",
                server_binding=binding,
                now_unix=1_003,
            )

        newer = self._record(
            request_id,
            observation_id="chatgpt-newer-block-after-crash",
            matched_tool_names=["future_reposkop_diagnostic"],
            now_unix=1_004,
            binding=binding,
        )
        self.assertEqual(newer["state"], "retirement_surface_blocked")
        self.assertTrue(failed_observation_path.exists())

        replay = self._record(
            request_id,
            observation_id=failed_observation_id,
            matched_tool_names=["future_reposkop_diagnostic"],
            now_unix=1_005,
            binding=binding,
        )
        self.assertEqual(replay["state"], "retirement_surface_blocked")
        self.assertTrue(replay["idempotent"])
        self.assertTrue(replay["replay_superseded"])

    def test_interrupted_zero_cannot_overwrite_newer_block_on_retry(self) -> None:
        request_id = self._activated_request()
        binding = self._binding()
        zero_id = "chatgpt-zero-interrupted-before-observation"
        zero_path = snapshot._retirement_observation_path(
            request_id, "grabowski", zero_id
        )
        with mock.patch.object(
            snapshot,
            "_create_private_json",
            side_effect=OSError("simulated zero observation persistence failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated zero observation persistence failure"):
                self._record(
                    request_id,
                    observation_id=zero_id,
                    matched_tool_names=[],
                    now_unix=1_002,
                    binding=binding,
                )
        self.assertFalse(zero_path.exists())

        blocked = self._record(
            request_id,
            observation_id="chatgpt-block-after-interrupted-zero",
            matched_tool_names=["future_reposkop_diagnostic"],
            now_unix=1_003,
            binding=binding,
        )
        self.assertEqual(blocked["state"], "retirement_surface_blocked")
        self.assertTrue(zero_path.exists())

        replay = self._record(
            request_id,
            observation_id=zero_id,
            matched_tool_names=[],
            now_unix=1_004,
            binding=binding,
        )
        self.assertEqual(replay["state"], "retirement_surface_blocked")
        self.assertTrue(replay["idempotent"])
        self.assertTrue(replay["replay_superseded"])

    def test_pending_transaction_after_observation_requires_recovery(self) -> None:
        request_id = self._activated_request()
        binding = self._binding()
        transaction_path = snapshot._retirement_transaction_path(
            request_id, "grabowski"
        )
        original_write = snapshot._write_private_json

        def fail_complete(path: Path, payload: dict[str, object]) -> None:
            if path == transaction_path and payload.get("state") == "complete":
                raise OSError("simulated transaction completion failure")
            original_write(path, payload)

        with mock.patch.object(snapshot, "_write_private_json", side_effect=fail_complete):
            with self.assertRaisesRegex(OSError, "transaction completion failure"):
                self._record(
                    request_id,
                    observation_id="chatgpt-zero-before-complete-marker",
                    matched_tool_names=[],
                    now_unix=1_002,
                    binding=binding,
                )

        pending = snapshot._read_private_json(transaction_path)
        self.assertEqual(pending["state"], "pending")
        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "pending recovery"
        ):
            snapshot.retirement_surface_status(
                request_id=request_id,
                surface_id="grabowski",
                server_binding=binding,
                now_unix=1_003,
            )

        recovered = self._record(
            request_id,
            observation_id="chatgpt-zero-before-complete-marker",
            matched_tool_names=[],
            now_unix=1_003,
            binding=binding,
        )
        self.assertEqual(recovered["state"], "retirement_surface_converged")
        completed = snapshot._read_private_json(transaction_path)
        self.assertEqual(completed["state"], "complete")

    def test_replay_revalidates_current_runtime_binding(self) -> None:
        request_id = self._activated_request()
        first_binding = self._binding(runtime_binding_sha256="3" * 64)
        later_binding = self._binding(runtime_binding_sha256="9" * 64)
        self._record(
            request_id,
            observation_id="chatgpt-runtime-a",
            matched_tool_names=[],
            now_unix=1_002,
            binding=first_binding,
        )
        self._record(
            request_id,
            observation_id="chatgpt-runtime-b",
            matched_tool_names=[],
            now_unix=1_003,
            binding=later_binding,
        )

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError, "resolution binding mismatch"
        ):
            self._record(
                request_id,
                observation_id="chatgpt-runtime-a",
                matched_tool_names=[],
                now_unix=1_004,
                binding=first_binding,
            )

    def test_same_observation_id_cannot_bind_conflicting_evidence(self) -> None:
        request_id = self._activated_request()
        self._record(
            request_id,
            observation_id="chatgpt-same-id",
            matched_tool_names=[],
            now_unix=1_002,
        )

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "already binds different evidence",
        ):
            self._record(
                request_id,
                observation_id="chatgpt-same-id",
                matched_tool_names=["future_reposkop_diagnostic"],
                now_unix=1_003,
            )

    def test_status_becomes_stale_after_retirement_ttl(self) -> None:
        request_id = self._activated_request()
        binding = self._binding()
        result = self._record(
            request_id,
            observation_id="chatgpt-fresh-zero",
            matched_tool_names=[],
            now_unix=1_002,
            binding=binding,
        )
        self.assertTrue(result["fresh"])

        status = snapshot.retirement_surface_status(
            request_id=request_id,
            surface_id="grabowski",
            server_binding=binding,
            now_unix=1_002 + snapshot.REPOSKOP_RETIREMENT_TTL_SECONDS + 1,
        )

        self.assertEqual(status["state"], "retirement_surface_stale")
        self.assertFalse(status["valid"])
        self.assertFalse(status["fresh"])
        self.assertEqual(status["projected_state"], "retirement_surface_converged")

    def test_runtime_binding_drift_invalidates_status_consumption(self) -> None:
        request_id = self._activated_request()
        binding = self._binding()
        self._record(
            request_id,
            observation_id="chatgpt-runtime-bound",
            matched_tool_names=[],
            now_unix=1_002,
            binding=binding,
        )
        drifted = {**binding, "runtime_binding_sha256": "9" * 64}

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "resolution binding mismatch",
        ):
            snapshot.retirement_surface_status(
                request_id=request_id,
                surface_id="grabowski",
                server_binding=drifted,
                now_unix=1_003,
            )

    def test_state_store_scope_swap_is_rejected_before_persistence(self) -> None:
        request_id = self._activated_request()
        binding = self._binding(state_scope_sha256="9" * 64)

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "state-store scope binding mismatch",
        ):
            self._record(
                request_id,
                observation_id="chatgpt-wrong-store",
                matched_tool_names=[],
                now_unix=1_002,
                binding=binding,
            )

    def test_primary_receipt_cannot_be_rebound_to_maulwurf_surface(self) -> None:
        request_id = self._activated_request()
        binding = self._binding(
            connector_id="kleiner-maulwurf",
            surface_id="der_kleine_maulwurf",
        )

        with self.assertRaisesRegex(
            snapshot.ClientSnapshotError,
            "surface/principal binding mismatch",
        ):
            self._record(
                request_id,
                observation_id="chatgpt-surface-swap",
                matched_tool_names=[],
                now_unix=1_002,
                binding=binding,
            )

    def test_changed_forbidden_set_invalidates_existing_projection(self) -> None:
        request_id = self._activated_request()
        binding = self._binding()
        self._record(
            request_id,
            observation_id="chatgpt-zero-before-forbidden-contract-change",
            matched_tool_names=[],
            now_unix=1_002,
            binding=binding,
        )
        expanded = frozenset(
            set(snapshot.REPOSKOP_RETIREMENT_FORBIDDEN_TOOLS)
            | {"future_reposkop_diagnostic"}
        )

        with mock.patch.object(
            snapshot, "REPOSKOP_RETIREMENT_FORBIDDEN_TOOLS", expanded
        ):
            with self.assertRaisesRegex(
                snapshot.ClientSnapshotError,
                "forbidden-set",
            ):
                snapshot.retirement_surface_status(
                    request_id=request_id,
                    surface_id="grabowski",
                    server_binding=binding,
                    now_unix=1_003,
                )

    def test_noncanonical_query_is_rejected_with_server_binding(self) -> None:
        request_id = self._activated_request()

        with self.assertRaisesRegex(snapshot.ClientSnapshotError, "exact reposkop query"):
            snapshot.record_platform_retirement_surface_observation(
                request_id=request_id,
                surface_id="grabowski",
                observation_id="chatgpt-wrong-query",
                query="repo",
                matched_tool_names=[],
                source_reference="chatgpt-tool-discovery:thread:grabowski:wrong-query",
                server_binding=self._binding(),
                now_unix=1_002,
            )

    def test_generic_publication_projection_is_unchanged(self) -> None:
        request_id = self._activated_request()
        before = snapshot._read_publication_current()

        result = self._record(
            request_id,
            observation_id="chatgpt-zero-generic-unchanged",
            matched_tool_names=[],
            now_unix=1_002,
        )

        self.assertTrue(result["generic_platform_publication_unchanged"])
        self.assertEqual(snapshot._read_publication_current(), before)
        self.assertIn("platform_converged", result["does_not_establish"])


if __name__ == "__main__":
    unittest.main()

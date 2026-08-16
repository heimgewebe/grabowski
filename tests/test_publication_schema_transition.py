"""Rebind across an *authorised* connector schema change.

Continuity of the tool surface is the ordinary cutover.  A schema change is the
case Publication-v2 exists for, and the old rebind refused it unconditionally --
which is what left the productive cutover stranded after its selector switch.

These tests pin both halves of the correction: an authorised change is accepted
and hash-bound, and every unauthorised variant of it is refused *before* the
snapshot is written.  The last test pins the honesty requirement: after a
schema change the preserved declaration is history, never a claim that some
client already looked at green.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for module_root in (SRC, TOOLS):
    if str(module_root) not in sys.path:
        sys.path.insert(0, str(module_root))

import grabowski_client_snapshot as client_snapshot
import grabowski_connector_contract as connector_contract


HEAD_BLUE = "a" * 40
HEAD_GREEN = "b" * 40
NAMES_SHA256 = "12" * 32
INSTRUCTIONS_SHA256 = "34" * 32
ARTIFACT_SHA256 = "56" * 32
BLUE_SCHEMA_BY_TOOL = {
    name: f"{index + 16:02x}" * 32
    for index, name in enumerate(sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS))
}
GREEN_SCHEMA_BY_TOOL = {
    name: f"{index + 48:02x}" * 32
    for index, name in enumerate(sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS))
}
BLUE_SCHEMA_IDENTITY = client_snapshot._sha256_json(BLUE_SCHEMA_BY_TOOL)
GREEN_SCHEMA_IDENTITY = client_snapshot._sha256_json(GREEN_SCHEMA_BY_TOOL)
BLUE_COMPLETE_SCHEMA = "91" * 32
GREEN_COMPLETE_SCHEMA = "93" * 32
TOOL_COUNT = len(BLUE_SCHEMA_BY_TOOL)
CUTOVER_ID = "bgc-schema-transition"


def _source_receipt(now_unix: int) -> dict[str, object]:
    declaration = {
        "client_id": "external-client",
        "session_id": "session-1",
        "observation_scope": client_snapshot.OBSERVATION_SCOPE_EXTERNAL_CLIENT,
        "observed_tool_count": TOOL_COUNT,
        "observed_names_sha256": NAMES_SHA256,
        "observed_release_id": "blue",
        "observed_agent_instructions_sha256": INSTRUCTIONS_SHA256,
        "observed_tools_artifact_sha256": ARTIFACT_SHA256,
        "observed_schema_coverage_count": TOOL_COUNT,
        "observed_schema_tools": sorted(BLUE_SCHEMA_BY_TOOL),
        "observed_complete_schema_count": TOOL_COUNT,
        "observed_complete_schema_sha256": BLUE_COMPLETE_SCHEMA,
    }
    artifact = {
        "artifact_sha256": ARTIFACT_SHA256,
        "schema_coverage_count": TOOL_COUNT,
        "schema_tools": sorted(BLUE_SCHEMA_BY_TOOL),
        "schema_sha256_by_tool": dict(BLUE_SCHEMA_BY_TOOL),
        "complete_schema_observable": True,
        "complete_schema_count": TOOL_COUNT,
        "complete_schema_sha256": BLUE_COMPLETE_SCHEMA,
    }
    receipt = {
        "schema_version": client_snapshot.SNAPSHOT_SCHEMA_VERSION,
        "kind": client_snapshot.SNAPSHOT_KIND,
        "created_at_unix": now_unix - 1,
        "expires_at_unix": now_unix + 60,
        "client_declaration": declaration,
        "client_declaration_sha256": client_snapshot._sha256_json(declaration),
        "server_binding": {
            "registered_tool_count": TOOL_COUNT,
            "registered_names_sha256": NAMES_SHA256,
            "release_id": "blue",
            "repo_head": HEAD_BLUE,
            "agent_instructions_sha256": INSTRUCTIONS_SHA256,
        },
        "schema_evidence": {
            "observed_artifact": artifact,
            "server_artifact": dict(artifact),
            "probe": {"matches": True, "schema_contract_matches": True},
        },
        "cutover_binding": None,
        "verified": True,
        "mismatches": [],
        "verification_model": "external-observation-test",
        "does_not_establish": [],
    }
    receipt["receipt_sha256"] = client_snapshot._sha256_json(receipt)
    return receipt


def _green_readiness(
    *,
    schema_by_tool: dict[str, str],
    complete_schema_sha256: str,
) -> dict[str, object]:
    return {
        "ready": True,
        "release_id": "green",
        "repo_head": HEAD_GREEN,
        "names_sha256": NAMES_SHA256,
        "agent_instructions_sha256": INSTRUCTIONS_SHA256,
        "schema_sha256_by_tool": dict(schema_by_tool),
        "schema_identity_sha256": client_snapshot._sha256_json(schema_by_tool),
        "complete_schema_count": TOOL_COUNT,
        "complete_schema_sha256": complete_schema_sha256,
    }


class PublicationSchemaTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now_unix = 1_000
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        state_root = Path(self._temporary.name) / "snapshot"
        state_root.mkdir(mode=0o700)
        publication_root = state_root / "platform-publication"
        self.state_root = state_root
        self.snapshot_path = state_root / "current.json"
        patcher = mock.patch.multiple(
            client_snapshot,
            STATE_ROOT=state_root,
            LOCK_PATH=state_root / "snapshot.lock",
            SNAPSHOT_PATH=self.snapshot_path,
            PLATFORM_SNAPSHOT_PATH=state_root / "platform.json",
            PLATFORM_PUBLICATION_ROOT=publication_root,
            PLATFORM_PUBLICATION_REQUEST_ROOT=publication_root / "requests",
            PLATFORM_PUBLICATION_ATTEMPT_ROOT=publication_root / "attempts",
            PLATFORM_PUBLICATION_RECEIPT_ROOT=publication_root / "receipts",
            PLATFORM_PUBLICATION_RESOLUTION_ROOT=publication_root / "resolutions",
            PLATFORM_PUBLICATION_CURRENT_PATH=publication_root / "current.json",
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.source = _source_receipt(self.now_unix)
        client_snapshot._write_private_json(self.snapshot_path, self.source)

    # ---- helpers ---------------------------------------------------------

    def _prepare_publication(
        self,
        *,
        complete_schema_sha256: str = GREEN_COMPLETE_SCHEMA,
        cutover_id: str = CUTOVER_ID,
        names_sha256: str = NAMES_SHA256,
        activate: bool = True,
    ) -> dict[str, object]:
        prepared = client_snapshot.prepare_platform_publication_for_runtime(
            registered_tool_count=TOOL_COUNT,
            registered_names_sha256=names_sha256,
            complete_schema_count=TOOL_COUNT,
            complete_schema_sha256=complete_schema_sha256,
            cutover_id=cutover_id,
            now_unix=self.now_unix,
        )
        if activate:
            client_snapshot.activate_platform_publication_request(
                request_id=prepared["request_id"], now_unix=self.now_unix
            )
        return prepared

    def _rebind(
        self,
        *,
        schema_by_tool: dict[str, str] = GREEN_SCHEMA_BY_TOOL,
        complete_schema_sha256: str = GREEN_COMPLETE_SCHEMA,
        cutover_id: str = CUTOVER_ID,
    ) -> dict[str, object]:
        return client_snapshot.rebind_authentic_snapshot_for_cutover(
            cutover_id=cutover_id,
            cutover_generation=1,
            current_release_id="blue",
            current_repo_head=HEAD_BLUE,
            green_release_id="green",
            green_repo_head=HEAD_GREEN,
            registered_tool_count=TOOL_COUNT,
            registered_names_sha256=NAMES_SHA256,
            agent_instructions_sha256=INSTRUCTIONS_SHA256,
            green_readiness=_green_readiness(
                schema_by_tool=schema_by_tool,
                complete_schema_sha256=complete_schema_sha256,
            ),
            now_unix=self.now_unix,
        )

    def _assert_snapshot_untouched(self) -> None:
        self.assertEqual(
            json.loads(self.snapshot_path.read_text(encoding="utf-8")), self.source
        )

    # ---- 1: unchanged schema keeps working -------------------------------

    def test_unchanged_schema_rebinds_without_publication_authorization(self) -> None:
        result = self._rebind(
            schema_by_tool=BLUE_SCHEMA_BY_TOOL,
            complete_schema_sha256=BLUE_COMPLETE_SCHEMA,
        )
        self.assertTrue(result["verified"])
        self.assertFalse(result["schema_changed"])
        self.assertIsNone(result["publication_schema_transition"])
        self.assertTrue(result["schema_contract_matches"])

    # ---- 2-6: unauthorised schema changes are refused --------------------

    def test_schema_change_without_publication_request_fails(self) -> None:
        with self.assertRaisesRegex(
            client_snapshot.ClientSnapshotError, "no platform publication request"
        ):
            self._rebind()
        self._assert_snapshot_untouched()

    def test_schema_change_with_pending_activation_fails(self) -> None:
        self._prepare_publication(activate=False)
        with self.assertRaisesRegex(
            client_snapshot.ClientSnapshotError, "not activated"
        ):
            self._rebind()
        self._assert_snapshot_untouched()

    def test_schema_change_with_foreign_cutover_request_fails(self) -> None:
        self._prepare_publication(cutover_id="bgc-some-other-cutover")
        with self.assertRaisesRegex(
            client_snapshot.ClientSnapshotError, "different cutover"
        ):
            self._rebind()
        self._assert_snapshot_untouched()

    def test_schema_change_with_wrong_contract_hash_fails(self) -> None:
        # A publication authorising a different tool-name surface never
        # authorises this green contract, however activated it is.
        self._prepare_publication(names_sha256="ab" * 32)
        with self.assertRaises(client_snapshot.ClientSnapshotError):
            self._rebind()
        self._assert_snapshot_untouched()

    def test_schema_change_with_wrong_complete_schema_hash_fails(self) -> None:
        self._prepare_publication(complete_schema_sha256="cd" * 32)
        with self.assertRaises(client_snapshot.ClientSnapshotError):
            self._rebind()
        self._assert_snapshot_untouched()

    # ---- 7: non-sentinel drift is still a schema change ------------------

    def test_non_sentinel_complete_schema_drift_is_detected(self) -> None:
        # Sentinels identical, complete schema hash different: still a change,
        # so it still needs authorisation rather than passing as continuity.
        with self.assertRaisesRegex(
            client_snapshot.ClientSnapshotError, "no platform publication request"
        ):
            self._rebind(
                schema_by_tool=BLUE_SCHEMA_BY_TOOL,
                complete_schema_sha256=GREEN_COMPLETE_SCHEMA,
            )
        self._assert_snapshot_untouched()

    # ---- 8: the authorised change succeeds -------------------------------

    def test_authorized_schema_change_rebinds_with_hash_bound_transition(self) -> None:
        prepared = self._prepare_publication()
        result = self._rebind()
        self.assertTrue(result["verified"])
        self.assertTrue(result["schema_changed"])
        transition = result["publication_schema_transition"]
        self.assertIsInstance(transition, dict)
        self.assertEqual(transition["publication_request_id"], prepared["request_id"])
        self.assertEqual(transition["cutover_id"], CUTOVER_ID)
        self.assertEqual(
            transition["source_schema_identity_sha256"], BLUE_SCHEMA_IDENTITY
        )
        self.assertEqual(
            transition["target_schema_identity_sha256"], GREEN_SCHEMA_IDENTITY
        )
        self.assertEqual(
            transition["source_complete_schema_sha256"], BLUE_COMPLETE_SCHEMA
        )
        self.assertEqual(
            transition["target_complete_schema_sha256"], GREEN_COMPLETE_SCHEMA
        )
        self.assertEqual(transition["publication_state"], "publication_pending")
        material = {
            key: value
            for key, value in transition.items()
            if key != "transition_sha256"
        }
        self.assertEqual(
            client_snapshot._sha256_json(material), transition["transition_sha256"]
        )
        rebound = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
        # The historical source is preserved verbatim; only the binding moves.
        self.assertEqual(
            rebound["client_declaration"], self.source["client_declaration"]
        )
        self.assertEqual(
            rebound["schema_evidence"], self.source["schema_evidence"]
        )
        self.assertEqual(rebound["server_binding"]["release_id"], "green")
        self.assertEqual(
            rebound["cutover_transition"]["publication_schema_transition"],
            transition,
        )

    # ---- 9: the preserved evidence is not a green observation ------------

    def test_historical_blue_schema_is_not_reported_as_green_observation(self) -> None:
        self._prepare_publication()
        self._rebind()
        status = client_snapshot.snapshot_status(
            expected_tool_count=TOOL_COUNT,
            expected_names_sha256=NAMES_SHA256,
            expected_release_id="green",
            expected_repo_head=HEAD_GREEN,
            expected_agent_instructions_sha256=INSTRUCTIONS_SHA256,
            now_unix=self.now_unix,
        )
        self.assertTrue(status["historical_schema_evidence_only"])
        self.assertFalse(status["external_client_schema_observable"])
        self.assertFalse(status["external_client_complete_schema_observable"])
        self.assertIsNone(status["external_client_complete_schema_sha256"])
        self.assertFalse(status["schema_contract_matches"])
        # The client snapshot itself still binds: only the schema claim is gone.
        self.assertTrue(status["external_client_snapshot_observable"])
        self.assertEqual(
            status["connector_schema_transition"]["target_complete_schema_sha256"],
            GREEN_COMPLETE_SCHEMA,
        )


if __name__ == "__main__":
    unittest.main()

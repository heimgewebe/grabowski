from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import stat
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

import deploy_runtime_dual as dual
import grabowski_client_snapshot as client_snapshot
import grabowski_connector_contract as connector_contract
import grabowski_transport_ingress as ingress


HEAD_BLUE = "a" * 40
HEAD_GREEN = "b" * 40
NAMES_SHA256 = "12" * 32
INSTRUCTIONS_SHA256 = "34" * 32
ARTIFACT_SHA256 = "56" * 32
SOURCE_IDENTITY_SHA256 = "78" * 32
SCHEMA_SHA256_BY_TOOL = {
    name: f"{index + 16:02x}" * 32
    for index, name in enumerate(sorted(connector_contract.REQUIRED_SCHEMA_SENTINELS))
}
SCHEMA_IDENTITY_SHA256 = client_snapshot._sha256_json(SCHEMA_SHA256_BY_TOOL)
COMPLETE_SCHEMA_SHA256 = "91" * 32
TOOL_COUNT = len(SCHEMA_SHA256_BY_TOOL)


def runtime_binding(release_id: str, repo_head: str) -> dict[str, str]:
    return {
        "release_id": release_id,
        "repo_head": repo_head,
        "registered_names_sha256": NAMES_SHA256,
        "agent_instructions_sha256": INSTRUCTIONS_SHA256,
    }


class RoutingSelectorTests(unittest.TestCase):
    def test_selector_is_private_two_target_cas_with_hash_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            selector_path = Path(temporary) / "routing.json"
            blue = ingress.publish_routing_selector(
                path=selector_path,
                expected_selector_sha256=None,
                selected_slot="canonical",
                runtime_binding=runtime_binding("blue", HEAD_BLUE),
                cutover_id="bootstrap",
                now_unix=100,
            )
            self.assertEqual(blue["upstream_port"], 18181)
            self.assertEqual(stat.S_IMODE(selector_path.stat().st_mode), 0o600)

            green = ingress.publish_routing_selector(
                path=selector_path,
                expected_selector_sha256=blue["selector_sha256"],
                selected_slot="green",
                runtime_binding=runtime_binding("green", HEAD_GREEN),
                cutover_id="cutover-1",
                now_unix=101,
            )
            observed = ingress.read_routing_selector(selector_path)
            self.assertEqual(observed, green)
            self.assertEqual(observed["upstream"], "http://127.0.0.1:18182/mcp")
            self.assertEqual(
                observed["previous_selector_sha256"], blue["selector_sha256"]
            )
            with self.assertRaisesRegex(
                ingress.IngressConfigurationError, "CAS precondition"
            ):
                ingress.publish_routing_selector(
                    path=selector_path,
                    expected_selector_sha256=blue["selector_sha256"],
                    selected_slot="canonical",
                    runtime_binding=runtime_binding("green", HEAD_GREEN),
                    cutover_id="stale-writer",
                )
            with self.assertRaisesRegex(
                ingress.IngressConfigurationError, "target is not allowed"
            ):
                ingress.publish_routing_selector(
                    path=selector_path,
                    expected_selector_sha256=green["selector_sha256"],
                    selected_slot="attacker",
                    runtime_binding=runtime_binding("green", HEAD_GREEN),
                    cutover_id="invalid-target",
                )

    def test_systemd_ingress_lifecycle_is_not_owned_by_operator(self) -> None:
        unit = (
            ROOT / "systemd/grabowski-transport-ingress.service.example"
        ).read_text(encoding="utf-8")
        self.assertNotIn("PartOf=grabowski-operator.service", unit)
        self.assertNotIn("Wants=grabowski-operator.service", unit)
        self.assertNotIn("After=grabowski-operator.service", unit)
        self.assertIn("--selector-file", unit)
        self.assertIn("operator-routing-selector.json", unit)


class AuthenticSnapshotCutoverTests(unittest.TestCase):
    def _source_receipt(
        self,
        now_unix: int,
        *,
        observation_scope: str = client_snapshot.OBSERVATION_SCOPE_EXTERNAL_CLIENT,
    ) -> dict[str, object]:
        declaration = {
            "client_id": (
                "external-client"
                if observation_scope == client_snapshot.OBSERVATION_SCOPE_EXTERNAL_CLIENT
                else client_snapshot.AUTO_REFRESH_CLIENT_ID
            ),
            "session_id": "session-1",
            "observation_scope": observation_scope,
            "observed_tool_count": TOOL_COUNT,
            "observed_names_sha256": NAMES_SHA256,
            "observed_release_id": "blue",
            "observed_agent_instructions_sha256": INSTRUCTIONS_SHA256,
            "observed_tools_artifact_sha256": ARTIFACT_SHA256,
            "observed_schema_coverage_count": TOOL_COUNT,
            "observed_schema_tools": sorted(SCHEMA_SHA256_BY_TOOL),
            "observed_complete_schema_count": TOOL_COUNT,
            "observed_complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
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
                "observed_artifact": {
                    "artifact_sha256": ARTIFACT_SHA256,
                    "schema_coverage_count": TOOL_COUNT,
                    "schema_tools": sorted(SCHEMA_SHA256_BY_TOOL),
                    "schema_sha256_by_tool": dict(SCHEMA_SHA256_BY_TOOL),
                    "complete_schema_observable": True,
                    "complete_schema_count": TOOL_COUNT,
                    "complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
                },
                "server_artifact": {
                    "artifact_sha256": ARTIFACT_SHA256,
                    "schema_coverage_count": TOOL_COUNT,
                    "schema_tools": sorted(SCHEMA_SHA256_BY_TOOL),
                    "schema_sha256_by_tool": dict(SCHEMA_SHA256_BY_TOOL),
                    "complete_schema_observable": True,
                    "complete_schema_count": TOOL_COUNT,
                    "complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
                },
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

    def test_rebind_preserves_authentic_external_declaration_and_source_hash(self) -> None:
        now_unix = 1_000
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "snapshot"
            state_root.mkdir(mode=0o700)
            snapshot_path = state_root / "current.json"
            source = self._source_receipt(now_unix)
            with mock.patch.multiple(
                client_snapshot,
                STATE_ROOT=state_root,
                LOCK_PATH=state_root / "snapshot.lock",
                SNAPSHOT_PATH=snapshot_path,
            ):
                client_snapshot._write_private_json(snapshot_path, source)
                result = client_snapshot.rebind_authentic_snapshot_for_cutover(
                    cutover_id="cutover-1",
                    cutover_generation=1,
                    current_release_id="blue",
                    current_repo_head=HEAD_BLUE,
                    green_release_id="green",
                    green_repo_head=HEAD_GREEN,
                    registered_tool_count=TOOL_COUNT,
                    registered_names_sha256=NAMES_SHA256,
                    agent_instructions_sha256=INSTRUCTIONS_SHA256,
                    green_readiness={
                        "ready": True,
                        "release_id": "green",
                        "repo_head": HEAD_GREEN,
                        "names_sha256": NAMES_SHA256,
                        "agent_instructions_sha256": INSTRUCTIONS_SHA256,
                        "schema_sha256_by_tool": dict(SCHEMA_SHA256_BY_TOOL),
                        "schema_identity_sha256": SCHEMA_IDENTITY_SHA256,
                        "complete_schema_count": TOOL_COUNT,
                        "complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
                    },
                    now_unix=now_unix,
                )
                rebound = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(
                result["source_receipt_sha256"], source["receipt_sha256"]
            )
            self.assertEqual(
                rebound["client_declaration"], source["client_declaration"]
            )
            self.assertEqual(rebound["server_binding"]["release_id"], "green")
            self.assertIn(
                "external client has refreshed against green",
                " ".join(result["does_not_establish"]),
            )

    def test_loopback_rebind_preserves_scope_without_platform_claim(self) -> None:
        now_unix = 1_000
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "snapshot"
            state_root.mkdir(mode=0o700)
            snapshot_path = state_root / "current.json"
            platform_path = state_root / "platform.json"
            source = self._source_receipt(
                now_unix,
                observation_scope=client_snapshot.OBSERVATION_SCOPE_SERVER_LOOPBACK,
            )
            with mock.patch.multiple(
                client_snapshot,
                STATE_ROOT=state_root,
                LOCK_PATH=state_root / "snapshot.lock",
                SNAPSHOT_PATH=snapshot_path,
                PLATFORM_SNAPSHOT_PATH=platform_path,
            ):
                client_snapshot._write_private_json(snapshot_path, source)
                result = client_snapshot.rebind_server_loopback_snapshot_for_cutover(
                    cutover_id="cutover-loopback",
                    cutover_generation=1,
                    current_release_id="blue",
                    current_repo_head=HEAD_BLUE,
                    green_release_id="green",
                    green_repo_head=HEAD_GREEN,
                    registered_tool_count=TOOL_COUNT,
                    registered_names_sha256=NAMES_SHA256,
                    agent_instructions_sha256=INSTRUCTIONS_SHA256,
                    green_readiness={
                        "ready": True,
                        "release_id": "green",
                        "repo_head": HEAD_GREEN,
                        "names_sha256": NAMES_SHA256,
                        "agent_instructions_sha256": INSTRUCTIONS_SHA256,
                        "schema_sha256_by_tool": dict(SCHEMA_SHA256_BY_TOOL),
                        "schema_identity_sha256": SCHEMA_IDENTITY_SHA256,
                        "complete_schema_count": TOOL_COUNT,
                        "complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
                    },
                    now_unix=now_unix,
                )
                status = client_snapshot.snapshot_status(
                    expected_tool_count=TOOL_COUNT,
                    expected_names_sha256=NAMES_SHA256,
                    expected_release_id="green",
                    expected_repo_head=HEAD_GREEN,
                    expected_agent_instructions_sha256=INSTRUCTIONS_SHA256,
                    now_unix=now_unix,
                )
            self.assertEqual(
                result["observation_scope"],
                client_snapshot.OBSERVATION_SCOPE_SERVER_LOOPBACK,
            )
            self.assertTrue(status["server_loopback_observable"])
            self.assertTrue(status["server_loopback_schema_observable"])
            self.assertTrue(status["server_loopback_complete_schema_observable"])
            self.assertFalse(status["external_client_snapshot_observable"])
            self.assertFalse(status["external_client_schema_observable"])
            self.assertFalse(status["platform_connector_snapshot_observable"])
            self.assertIn(
                "platform connector catalog publication",
                result["does_not_establish"],
            )

    def test_rebind_rejects_schema_drift_before_writing(self) -> None:
        now_unix = 1_000
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "snapshot"
            state_root.mkdir(mode=0o700)
            snapshot_path = state_root / "current.json"
            source = self._source_receipt(now_unix)
            drifted = dict(SCHEMA_SHA256_BY_TOOL)
            first = sorted(drifted)[0]
            drifted[first] = "ab" * 32
            with mock.patch.multiple(
                client_snapshot,
                STATE_ROOT=state_root,
                LOCK_PATH=state_root / "snapshot.lock",
                SNAPSHOT_PATH=snapshot_path,
            ):
                client_snapshot._write_private_json(snapshot_path, source)
                with self.assertRaisesRegex(
                    client_snapshot.ClientSnapshotError, "schema identity"
                ):
                    client_snapshot.rebind_authentic_snapshot_for_cutover(
                        cutover_id="cutover-schema-drift",
                        cutover_generation=1,
                        current_release_id="blue",
                        current_repo_head=HEAD_BLUE,
                        green_release_id="green",
                        green_repo_head=HEAD_GREEN,
                        registered_tool_count=TOOL_COUNT,
                        registered_names_sha256=NAMES_SHA256,
                        agent_instructions_sha256=INSTRUCTIONS_SHA256,
                        green_readiness={
                            "ready": True,
                            "release_id": "green",
                            "repo_head": HEAD_GREEN,
                            "names_sha256": NAMES_SHA256,
                            "agent_instructions_sha256": INSTRUCTIONS_SHA256,
                            "schema_sha256_by_tool": drifted,
                            "schema_identity_sha256": client_snapshot._sha256_json(drifted),
                            "complete_schema_count": TOOL_COUNT,
                            "complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
                        },
                        now_unix=now_unix,
                    )
                self.assertEqual(
                    json.loads(snapshot_path.read_text(encoding="utf-8")), source
                )

    def test_rebind_rejects_non_sentinel_complete_schema_drift(self) -> None:
        now_unix = 1_000
        with tempfile.TemporaryDirectory() as temporary:
            state_root = Path(temporary) / "snapshot"
            state_root.mkdir(mode=0o700)
            snapshot_path = state_root / "current.json"
            source = self._source_receipt(now_unix)
            with mock.patch.multiple(
                client_snapshot,
                STATE_ROOT=state_root,
                LOCK_PATH=state_root / "snapshot.lock",
                SNAPSHOT_PATH=snapshot_path,
            ):
                client_snapshot._write_private_json(snapshot_path, source)
                with self.assertRaisesRegex(
                    client_snapshot.ClientSnapshotError, "schema identity"
                ):
                    client_snapshot.rebind_authentic_snapshot_for_cutover(
                        cutover_id="cutover-complete-schema-drift",
                        cutover_generation=1,
                        current_release_id="blue",
                        current_repo_head=HEAD_BLUE,
                        green_release_id="green",
                        green_repo_head=HEAD_GREEN,
                        registered_tool_count=TOOL_COUNT,
                        registered_names_sha256=NAMES_SHA256,
                        agent_instructions_sha256=INSTRUCTIONS_SHA256,
                        green_readiness={
                            "ready": True,
                            "release_id": "green",
                            "repo_head": HEAD_GREEN,
                            "names_sha256": NAMES_SHA256,
                            "agent_instructions_sha256": INSTRUCTIONS_SHA256,
                            "schema_sha256_by_tool": dict(SCHEMA_SHA256_BY_TOOL),
                            "schema_identity_sha256": SCHEMA_IDENTITY_SHA256,
                            "complete_schema_count": TOOL_COUNT,
                            "complete_schema_sha256": "92" * 32,
                        },
                        now_unix=now_unix,
                    )
                self.assertEqual(
                    json.loads(snapshot_path.read_text(encoding="utf-8")), source
                )

    def test_rebind_rejects_synthetic_proof_before_writing(self) -> None:
        with self.assertRaisesRegex(client_snapshot.ClientSnapshotError, "synthetic"):
            client_snapshot.rebind_authentic_snapshot_for_cutover(
                cutover_id="cutover-1",
                cutover_generation=1,
                current_release_id="blue",
                current_repo_head=HEAD_BLUE,
                green_release_id="green",
                green_repo_head=HEAD_GREEN,
                registered_tool_count=1,
                registered_names_sha256="0" * 64,
                agent_instructions_sha256=INSTRUCTIONS_SHA256,
                green_readiness={},
            )


class _FakeProductionRuntime:
    def __init__(self, *, fail_phase: str | None = None) -> None:
        self.fail_phase = fail_phase
        self.connector_switched = False
        self.rollback_calls = 0

    def _step(self, phase: str, value: dict[str, object]) -> dict[str, object]:
        if self.fail_phase == phase:
            raise RuntimeError(f"{phase} failed")
        return value

    def start_green(self):
        return self._step("start_green", {"started": True})

    def verify_green(self):
        return self._step("verify_green", {"ready": True})

    def prepare_platform_publication(self):
        return self._step(
            "platform_publication",
            {
                "state": "pending_activation",
                "request_id": "gpp-test-request",
                "contract": {"tool_contract_sha256": "7e" * 32},
            },
        )

    def activate_platform_publication(self):
        return self._step(
            "publication_activation",
            {"state": "publication_pending", "request_id": "gpp-test-request"},
        )

    def rollback_platform_publication(self):
        return self._step(
            "publication_rollback",
            {"state": "rolled_back", "request_id": "gpp-test-request"},
        )

    def close_blue_mutations(self):
        return self._step("close_blue", {"closed": True})

    def terminalize_blue_effects(self):
        return self._step("drain", {"blocking_tool_calls": 0})

    def switch_connector(self):
        value = self._step("switch", {"selector_sha256": "9a" * 32})
        self.connector_switched = True
        return value

    def rebind_snapshot(self, cutover_id, generation):
        return self._step("rebind", {"receipt_sha256": "9b" * 32})

    def retire_blue(self):
        return self._step(
            "retire",
            {"final_routing": {"selector_sha256": "9c" * 32}},
        )

    def authoritative_readback(self):
        return {"authoritative": True, "readback_sha256": "9d" * 32}

    def rollback_green(self):
        self.rollback_calls += 1
        return {"blue_preserved": True}


class ProductionRecoverySemanticsTests(unittest.TestCase):
    def _run(self, runtime: _FakeProductionRuntime) -> dict[str, object]:
        def receipt(**kwargs):
            return {
                "receipt_sha256": "9e" * 32,
                "outcome": kwargs["outcome"],
                "phase": kwargs["phase"],
            }

        with (
            mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
            mock.patch.object(
                dual, "prepare_production_blue_green_runtime", return_value=runtime
            ),
            mock.patch.object(
                dual, "_production_blue_green_receipt", side_effect=receipt
            ),
            mock.patch.object(
                dual,
                "_persist_production_blue_green_receipt",
                return_value={"path": "/state/receipt.json", "receipt_sha256": "9e" * 32},
            ),
        ):
            return dual.run_production_blue_green_cutover(
                repo=ROOT,
                expected_head=HEAD_GREEN,
                source_identity_sha256=SOURCE_IDENTITY_SHA256,
                cutover_id="cutover-test",
            )

    def test_productive_cutover_threads_scheduler_source_identity_into_runtime_context(self) -> None:
        runtime = _FakeProductionRuntime(fail_phase="verify_green")

        def receipt(**kwargs):
            return {
                "receipt_sha256": "9e" * 32,
                "outcome": kwargs["outcome"],
                "phase": kwargs["phase"],
            }

        with (
            mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
            mock.patch.object(
                dual, "prepare_production_blue_green_runtime", return_value=runtime
            ) as prepare,
            mock.patch.object(
                dual, "_production_blue_green_receipt", side_effect=receipt
            ),
            mock.patch.object(
                dual,
                "_persist_production_blue_green_receipt",
                return_value={"path": "/state/receipt.json", "receipt_sha256": "9e" * 32},
            ),
        ):
            dual.run_production_blue_green_cutover(
                repo=ROOT,
                expected_head=HEAD_GREEN,
                source_identity_sha256=SOURCE_IDENTITY_SHA256,
                cutover_id="cutover-source-binding",
            )
        prepare.assert_called_once_with(
            ROOT,
            dual.core.HOME / ".local/share/grabowski-mcp",
            dual.core.DEFAULT_PROFILE_PATH,
            expected_head=HEAD_GREEN,
            cutover_id="cutover-source-binding",
            timeout_seconds=40,
            deployment_source_identity_sha256=SOURCE_IDENTITY_SHA256,
        )

    def test_pre_switch_failure_rolls_back_and_preserves_blue(self) -> None:
        runtime = _FakeProductionRuntime(fail_phase="verify_green")
        result = self._run(runtime)
        self.assertEqual(result["outcome"], "rolled_back")
        self.assertEqual(runtime.rollback_calls, 1)
        self.assertFalse(runtime.connector_switched)

    def test_platform_publication_failure_is_pre_switch_and_rolls_back(self) -> None:
        runtime = _FakeProductionRuntime(fail_phase="platform_publication")
        result = self._run(runtime)
        self.assertEqual(result["outcome"], "rolled_back")
        self.assertEqual(runtime.rollback_calls, 1)
        self.assertFalse(runtime.connector_switched)

    def test_post_switch_failure_is_unknown_without_blind_rollback(self) -> None:
        runtime = _FakeProductionRuntime(fail_phase="rebind")
        result = self._run(runtime)
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(runtime.rollback_calls, 0)
        self.assertTrue(runtime.connector_switched)

    def test_publication_activation_failure_after_switch_is_outcome_unknown(self) -> None:
        runtime = _FakeProductionRuntime(fail_phase="publication_activation")
        result = self._run(runtime)
        self.assertEqual(result["outcome"], "outcome_unknown")
        self.assertEqual(runtime.rollback_calls, 0)
        self.assertTrue(runtime.connector_switched)

    def test_primary_receipt_persistence_replays_identical_existing_cutover(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "receipts"
            receipt = {
                "cutover_id": "cutover-idempotent",
                "receipt_sha256": "9f" * 32,
                "outcome": "completed",
            }
            with mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", root):
                first = dual._persist_production_blue_green_receipt(receipt)
                second = dual._persist_production_blue_green_receipt(receipt)
        self.assertEqual(first, second)
        self.assertEqual(first["receipt_sha256"], "9f" * 32)

    def test_primary_receipt_persistence_rejects_existing_cutover_with_different_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "receipts"
            first = {
                "cutover_id": "cutover-conflict",
                "receipt_sha256": "9f" * 32,
                "outcome": "completed",
            }
            second = {
                **first,
                "receipt_sha256": "8e" * 32,
            }
            with mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", root):
                dual._persist_production_blue_green_receipt(first)
                with self.assertRaisesRegex(
                    RuntimeError, "already binds different receipt evidence"
                ):
                    dual._persist_production_blue_green_receipt(second)

    def test_completed_cutover_preserves_receipt_when_primary_persistence_fails(self) -> None:
        runtime = _FakeProductionRuntime()

        def receipt(**kwargs):
            return {
                "schema_version": 1,
                "kind": "grabowski_blue_green_deployment_receipt",
                "cutover_id": "cutover-persist-failure",
                "receipt_sha256": "9e" * 32,
                "outcome": kwargs["outcome"],
                "phase": kwargs["phase"],
                "expected_head": HEAD_GREEN,
            }

        with (
            mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
            mock.patch.object(
                dual, "prepare_production_blue_green_runtime", return_value=runtime
            ),
            mock.patch.object(
                dual, "_production_blue_green_receipt", side_effect=receipt
            ),
            mock.patch.object(
                dual,
                "_persist_production_blue_green_receipt",
                side_effect=OSError("receipt directory full"),
            ),
        ):
            with self.assertRaises(
                dual.ProductionBlueGreenReceiptPersistenceError
            ) as raised:
                dual.run_production_blue_green_cutover(
                    repo=ROOT,
                    expected_head=HEAD_GREEN,
                    source_identity_sha256=SOURCE_IDENTITY_SHA256,
                    cutover_id="cutover-persist-failure",
                )
        self.assertEqual(raised.exception.outcome, "completed")
        self.assertEqual(raised.exception.receipt["outcome"], "completed")
        self.assertEqual(raised.exception.receipt_sha256, "9e" * 32)
        self.assertEqual(raised.exception.persistence_error_type, "OSError")
        self.assertTrue(runtime.connector_switched)

    def test_failed_snapshot_preflight_still_persists_typed_receipt(self) -> None:
        persisted: list[dict[str, object]] = []

        def persist(receipt):
            persisted.append(receipt)
            return {
                "path": "/state/preflight.json",
                "receipt_sha256": receipt["receipt_sha256"],
            }

        with (
            mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
            mock.patch.object(
                dual,
                "prepare_production_blue_green_runtime",
                side_effect=client_snapshot.ClientSnapshotError(
                    "authentic connector snapshot is unavailable"
                ),
            ),
            mock.patch.object(
                dual, "_persist_production_blue_green_receipt", side_effect=persist
            ),
        ):
            result = dual.run_production_blue_green_cutover(
                repo=ROOT,
                expected_head=HEAD_GREEN,
                source_identity_sha256=SOURCE_IDENTITY_SHA256,
                cutover_id="cutover-preflight",
            )
        self.assertEqual(result["outcome"], "failed_pre_cutover")
        self.assertEqual(len(persisted), 1)
        receipt = persisted[0]
        self.assertEqual(receipt["expected_head"], HEAD_GREEN)
        self.assertEqual(receipt["source_identity_sha256"], SOURCE_IDENTITY_SHA256)
        self.assertIsNone(receipt["selector_switch"])
        self.assertTrue(receipt["recovery"]["blue_preserved"])

    def test_ambiguous_selector_publish_is_classified_post_switch(self) -> None:
        runtime = mock.Mock()
        runtime.selector_before = {"selector_sha256": "1a" * 32}
        runtime.green_binding = runtime_binding("green", HEAD_GREEN)
        runtime.cutover_id = "cutover-ambiguous"
        runtime.connector_switched = False
        runtime.current_selector = runtime.selector_before
        changed = {
            "selector_sha256": "2b" * 32,
            "selected_slot": "green",
        }
        with (
            mock.patch.object(
                dual.transport_ingress,
                "publish_routing_selector",
                side_effect=OSError("readback failed after replace"),
            ),
            mock.patch.object(
                dual.transport_ingress,
                "read_routing_selector",
                return_value=changed,
            ),
        ):
            with self.assertRaises(OSError):
                dual.ProductionBlueGreenRuntime.switch_connector(runtime)
        self.assertTrue(runtime.connector_switched)
        self.assertEqual(runtime.current_selector, changed)


class ProductionPreflightHardeningTests(unittest.TestCase):
    def test_stop_green_requests_stop_while_unit_is_still_activating(self) -> None:
        activating = mock.Mock(
            confirmed_active=False,
            confirmed_inactive=False,
            query_valid=True,
            load_state="loaded",
            active_state="activating",
            main_pid=321,
        )
        inactive = mock.Mock(
            confirmed_active=False,
            confirmed_inactive=True,
            query_valid=True,
            load_state="loaded",
            active_state="inactive",
            main_pid=0,
        )
        inactive.to_dict.return_value = {"active_state": "inactive", "main_pid": 0}
        stop_result = mock.Mock(returncode=0)
        with (
            mock.patch.object(dual, "observe_service", side_effect=[activating, inactive]),
            mock.patch.object(dual.core, "run", return_value=stop_result) as run,
        ):
            result = dual._stop_green_operator(
                "grabowski-green-operator-123456789abc.service"
            )
        run.assert_called_once_with(
            [
                "systemctl",
                "--user",
                "stop",
                "grabowski-green-operator-123456789abc.service",
            ],
            check=False,
            capture=True,
            timeout=dual.core.TIMEOUTS["service_stop"],
        )
        self.assertTrue(result["retired"])
        self.assertEqual(result["service"]["active_state"], "inactive")

    def test_stop_green_accepts_failed_stop_only_after_inactive_readback(self) -> None:
        unknown = mock.Mock(
            confirmed_active=False,
            confirmed_inactive=False,
            query_valid=False,
            load_state="unknown",
            active_state="unknown",
            main_pid=None,
        )
        inactive = mock.Mock(
            confirmed_active=False,
            confirmed_inactive=True,
            query_valid=True,
            load_state="not-found",
            active_state="inactive",
            main_pid=0,
        )
        inactive.to_dict.return_value = {"active_state": "inactive", "main_pid": 0}
        with (
            mock.patch.object(dual, "observe_service", side_effect=[unknown, inactive]),
            mock.patch.object(dual.core, "run", return_value=mock.Mock(returncode=5)),
        ):
            result = dual._stop_green_operator(
                "grabowski-green-operator-123456789abc.service"
            )
        self.assertTrue(result["retired"])

    def test_close_blue_mutations_binds_scheduler_source_identity_not_runtime_snapshot_identity(self) -> None:
        snapshot = mock.Mock()
        snapshot.repo_head = HEAD_GREEN
        snapshot.contract_sha256 = "11" * 32
        snapshot.runtime_input_sha256 = "22" * 32
        snapshot.runtime_lock_sha256 = "33" * 32
        snapshot.source_sha256s = {"grabowski_operator": "44" * 32}
        snapshot.runtime_asset_sha256s = {}
        scheduler_source_identity = "55" * 32
        self.assertNotEqual(
            scheduler_source_identity,
            dual._deployment_source_identity_sha256(snapshot),
        )
        runtime = dual.ProductionBlueGreenRuntime(
            repo=ROOT,
            runtime=Path("/runtime"),
            snapshot=snapshot,
            build=mock.Mock(release_path=Path("/release/green")),
            activation=mock.Mock(),
            blue_manifest={},
            blue_binding=runtime_binding("blue", HEAD_BLUE),
            green_binding=runtime_binding("green", HEAD_GREEN),
            selector_before={"selector_sha256": "7a" * 32},
            cutover_id="cutover-source-domain",
            timeout_seconds=10,
            green_unit="grabowski-green-operator-123456789abc.service",
            deployment_source_identity_sha256=scheduler_source_identity,
        )
        marker = {
            "token": "66" * 32,
            "expected_head": HEAD_GREEN,
            "source_identity_sha256": scheduler_source_identity,
        }
        with mock.patch.object(
            dual,
            "engage_operator_deployment_admission",
            return_value=marker,
        ) as engage:
            closed = runtime.close_blue_mutations()
        engage.assert_called_once_with(
            snapshot,
            timeout_seconds=10,
            source_identity_sha256=scheduler_source_identity,
        )
        self.assertEqual(
            scheduler_source_identity, closed["source_identity_sha256"]
        )

    def test_start_green_marks_possible_unit_before_post_start_verification_failure(self) -> None:
        snapshot = mock.Mock()
        snapshot.contract = mock.Mock()
        build = mock.Mock(release_path=Path("/release/green"))
        runtime = dual.ProductionBlueGreenRuntime(
            repo=ROOT,
            runtime=Path("/runtime"),
            snapshot=snapshot,
            build=build,
            activation=mock.Mock(),
            blue_manifest={},
            blue_binding=runtime_binding("blue", HEAD_BLUE),
            green_binding=runtime_binding("green", HEAD_GREEN),
            selector_before={"selector_sha256": "7a" * 32},
            cutover_id="cutover-start-failure",
            timeout_seconds=10,
            green_unit="grabowski-green-operator-123456789abc.service",
        )
        projection = mock.Mock()
        with (
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(
                dual, "install_watchdog_host_assets", return_value=projection
            ),
            mock.patch.object(
                dual, "install_safety_observer_unit", return_value={"installed": True}
            ),
            mock.patch.object(
                dual,
                "_start_green_operator",
                side_effect=RuntimeError("listener verification failed after unit start"),
            ),
            mock.patch.object(
                dual, "_stop_green_operator", return_value={"retired": True}
            ) as stop_green,
            mock.patch.object(dual, "restore_watchdog_host_assets") as restore_assets,
        ):
            with self.assertRaisesRegex(RuntimeError, "listener verification failed"):
                runtime.start_green()
            self.assertTrue(runtime.green_started)
            recovery = runtime.rollback_green()
        stop_green.assert_called_once_with(runtime.green_unit)
        restore_assets.assert_called_once_with(projection)
        self.assertFalse(runtime.green_started)
        self.assertTrue(recovery["green"]["retired"])

    def test_changed_tool_name_blocks_before_snapshot_selection(self) -> None:
        snapshot = mock.Mock()
        snapshot.repo_head = HEAD_GREEN
        snapshot.contract = mock.Mock(expected_tools=["grabowski_status"])
        topology = mock.Mock(kind="url", server_url_port=18180)
        build = mock.Mock(
            release_path=Path("/release/green"),
            release_id="green",
            agent_instructions={"sha256": INSTRUCTIONS_SHA256},
        )
        blue_binding = runtime_binding("blue", HEAD_BLUE)
        green_binding = runtime_binding("green", HEAD_GREEN)
        selector = {
            "selected_slot": "canonical",
            "selector_sha256": "8a" * 32,
            "runtime_binding": blue_binding,
            "runtime_binding_sha256": "8b" * 32,
        }
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(snapshot, Path("/runtime"), topology),
            ),
            mock.patch.object(dual, "require_service_active"),
            mock.patch.object(
                dual.core,
                "read_manifest",
                return_value={
                    "entrypoint_contract": {"expected_tools": ["old_tool_name"]}
                },
            ),
            mock.patch.object(
                dual.transport_ingress,
                "_read_runtime_binding",
                side_effect=[(blue_binding, []), (green_binding, [])],
            ),
            mock.patch.object(
                dual.transport_ingress,
                "read_routing_selector",
                return_value=selector,
            ),
            mock.patch.object(dual, "_require_selector_authority"),
            mock.patch.object(dual.core, "build_release", return_value=build),
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(dual.core, "verify_manifest"),
            mock.patch.object(dual.client_snapshot, "snapshot_status") as status,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "Blue and green tool-name continuity is unavailable"
            ):
                dual.prepare_production_blue_green_runtime(
                    ROOT,
                    Path("/runtime"),
                    Path("/profile.json"),
                    expected_head=HEAD_GREEN,
                    cutover_id="cutover-name-drift",
                    timeout_seconds=10,
                )
        status.assert_not_called()

    def test_server_loopback_continuity_prepares_unchanged_surface(self) -> None:
        snapshot = mock.Mock()
        snapshot.repo_head = HEAD_GREEN
        snapshot.contract = mock.Mock(expected_tools=["grabowski_status"])
        topology = mock.Mock(kind="url", server_url_port=18180)
        build = mock.Mock(
            release_path=Path("/release/green"),
            release_id="green",
            agent_instructions={"sha256": INSTRUCTIONS_SHA256},
        )
        blue_binding = runtime_binding("blue", HEAD_BLUE)
        green_binding = runtime_binding("green", HEAD_GREEN)
        selector = {
            "selected_slot": "canonical",
            "selector_sha256": "8a" * 32,
            "runtime_binding": blue_binding,
            "runtime_binding_sha256": "8b" * 32,
        }
        loopback_status = {
            "state": "matched",
            "external_client_snapshot_observable": False,
            "external_client_schema_observable": False,
            "server_loopback_observable": True,
            "server_loopback_schema_observable": True,
            "server_loopback_schema_contract_matches": True,
            "server_loopback_complete_schema_observable": True,
            "server_loopback_complete_schema_count": 1,
            "server_loopback_complete_schema_sha256": COMPLETE_SCHEMA_SHA256,
            "client_observed_release_id": "blue",
            "receipt_sha256": "9c" * 32,
            "client_declaration_sha256": "9d" * 32,
            "observation_scope": client_snapshot.OBSERVATION_SCOPE_SERVER_LOOPBACK,
        }
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(snapshot, Path("/runtime"), topology),
            ),
            mock.patch.object(dual, "require_service_active"),
            mock.patch.object(
                dual.core,
                "read_manifest",
                return_value={
                    "entrypoint_contract": {"expected_tools": ["grabowski_status"]}
                },
            ),
            mock.patch.object(
                dual.transport_ingress,
                "_read_runtime_binding",
                side_effect=[(blue_binding, []), (green_binding, [])],
            ),
            mock.patch.object(
                dual.transport_ingress,
                "read_routing_selector",
                return_value=selector,
            ),
            mock.patch.object(dual, "_require_selector_authority"),
            mock.patch.object(dual.core, "build_release", return_value=build),
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(dual.core, "verify_manifest"),
            mock.patch.object(
                dual.client_snapshot,
                "snapshot_status",
                return_value=loopback_status,
            ),
        ):
            runtime = dual.prepare_production_blue_green_runtime(
                ROOT,
                Path("/runtime"),
                Path("/profile.json"),
                expected_head=HEAD_GREEN,
                cutover_id="cutover-loopback-continuity",
                timeout_seconds=10,
            )
        self.assertEqual(runtime.snapshot_rebind_mode, "server_loopback_continuity")
        self.assertEqual(
            runtime.source_complete_schema_sha256, COMPLETE_SCHEMA_SHA256
        )

    def test_server_loopback_continuity_blocks_green_schema_drift_pre_switch(self) -> None:
        snapshot = mock.Mock()
        snapshot.contract = mock.Mock(expected_tools=["grabowski_status"])
        build = mock.Mock(
            release_path=Path("/release/green"),
            release_id="green",
            agent_instructions={"sha256": INSTRUCTIONS_SHA256},
        )
        runtime = dual.ProductionBlueGreenRuntime(
            repo=ROOT,
            runtime=Path("/runtime"),
            snapshot=snapshot,
            build=build,
            activation=mock.Mock(),
            blue_manifest={},
            blue_binding=runtime_binding("blue", HEAD_BLUE),
            green_binding=runtime_binding("green", HEAD_GREEN),
            selector_before={"selector_sha256": "7a" * 32},
            cutover_id="cutover-loopback-schema-drift",
            timeout_seconds=10,
            green_unit="grabowski-green-operator-123456789abc.service",
            source_complete_schema_sha256=COMPLETE_SCHEMA_SHA256,
            snapshot_rebind_mode="server_loopback_continuity",
        )
        with mock.patch.object(
            dual,
            "_probe_release_runtime",
            return_value={
                "ready": True,
                "complete_schema_count": 1,
                "complete_schema_sha256": "ab" * 32,
            },
        ):
            with self.assertRaisesRegex(
                RuntimeError, "Green complete schema identity differs"
            ):
                runtime.verify_green()
        self.assertFalse(runtime.connector_switched)

    def test_stale_external_declaration_fails_before_connector_switch(self) -> None:
        snapshot = mock.Mock()
        snapshot.repo_head = HEAD_GREEN
        snapshot.contract = mock.Mock(expected_tools=["grabowski_status"])
        topology = mock.Mock(kind="url", server_url_port=18180)
        build = mock.Mock(
            release_path=Path("/release/green"),
            release_id="green",
            agent_instructions={"sha256": INSTRUCTIONS_SHA256},
        )
        blue_binding = runtime_binding("blue", HEAD_BLUE)
        green_binding = runtime_binding("green", HEAD_GREEN)
        selector = {
            "selected_slot": "canonical",
            "selector_sha256": "9a" * 32,
            "runtime_binding": blue_binding,
            "runtime_binding_sha256": "9b" * 32,
        }
        stale_transition_status = {
            "state": "matched",
            "external_client_snapshot_observable": True,
            "external_client_schema_observable": True,
            # Internal transition continuity may make snapshot_status matched,
            # but it is not a fresh external observation of current Blue.
            "client_observed_release_id": "older-blue",
            "receipt_sha256": "9c" * 32,
            "client_declaration_sha256": "9d" * 32,
            "observation_scope": client_snapshot.OBSERVATION_SCOPE_EXTERNAL_CLIENT,
            "schema_observable": True,
        }
        with (
            mock.patch.object(
                dual,
                "preflight_url",
                return_value=(snapshot, Path("/runtime"), topology),
            ),
            mock.patch.object(dual, "require_service_active"),
            mock.patch.object(
                dual.core,
                "read_manifest",
                return_value={
                    "entrypoint_contract": {"expected_tools": ["grabowski_status"]}
                },
            ),
            mock.patch.object(
                dual.transport_ingress,
                "_read_runtime_binding",
                side_effect=[(blue_binding, []), (green_binding, [])],
            ),
            mock.patch.object(
                dual.transport_ingress,
                "read_routing_selector",
                return_value=selector,
            ),
            mock.patch.object(dual, "_require_selector_authority"),
            mock.patch.object(dual.core, "build_release", return_value=build),
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(dual.core, "verify_manifest"),
            mock.patch.object(
                dual.client_snapshot,
                "snapshot_status",
                return_value=stale_transition_status,
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "Authentic Blue connector continuity snapshot is unavailable"
            ):
                dual.prepare_production_blue_green_runtime(
                    ROOT,
                    Path("/runtime"),
                    Path("/profile.json"),
                    expected_head=HEAD_GREEN,
                    cutover_id="cutover-stale-external",
                    timeout_seconds=10,
                )

    def test_blue_admission_stays_closed_until_old_operator_is_stopped(self) -> None:
        snapshot = mock.Mock()
        snapshot.contract = mock.Mock()
        build = mock.Mock(
            release_path=Path("/release/green"),
            release_id="green",
            agent_instructions={"sha256": INSTRUCTIONS_SHA256},
        )
        selector = {
            "selector_sha256": "8a" * 32,
            "selected_slot": "green",
            "upstream_port": 18182,
            "runtime_binding": runtime_binding("green", HEAD_GREEN),
            "runtime_binding_sha256": "8b" * 32,
        }
        runtime = dual.ProductionBlueGreenRuntime(
            repo=ROOT,
            runtime=Path("/runtime"),
            snapshot=snapshot,
            build=build,
            activation=mock.Mock(),
            blue_manifest={},
            blue_binding=runtime_binding("blue", HEAD_BLUE),
            green_binding=runtime_binding("green", HEAD_GREEN),
            selector_before=selector,
            cutover_id="cutover-sequence",
            timeout_seconds=10,
            green_unit="grabowski-green-operator-123456789abc.service",
            admission_marker={"marker": "active"},
            green_started=True,
            connector_switched=True,
            current_selector=selector,
        )
        events: list[str] = []
        canonical = {
            **selector,
            "selector_sha256": "8c" * 32,
            "selected_slot": "canonical",
            "upstream_port": 18181,
        }
        with (
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(
                dual.core,
                "activate_pointer",
                side_effect=lambda *_args, **_kwargs: events.append("activate-pointer"),
            ),
            mock.patch.object(
                dual,
                "stop_service",
                side_effect=lambda *_args, **_kwargs: events.append("stop-blue"),
            ),
            mock.patch.object(
                dual,
                "observe_service",
                return_value=mock.Mock(confirmed_active=True),
            ),
            mock.patch.object(dual, "_require_selector_authority", return_value={"authoritative": True}),
            mock.patch.object(
                dual,
                "release_operator_deployment_admission",
                side_effect=lambda *_args, **_kwargs: events.append("release-admission"),
            ),
            mock.patch.object(
                dual,
                "start_service",
                side_effect=lambda *_args, **_kwargs: events.append("start-canonical"),
            ),
            mock.patch.object(dual, "verify_operator_process"),
            mock.patch.object(dual, "_require_loopback_listener", return_value={}),
            mock.patch.object(
                dual.transport_ingress,
                "publish_routing_selector",
                side_effect=lambda **_kwargs: (events.append("switch-canonical") or canonical),
            ),
            mock.patch.object(
                dual,
                "_probe_release_runtime",
                side_effect=lambda **_kwargs: (events.append("canonical-readiness") or {"ready": True}),
            ),
            mock.patch.object(
                dual,
                "_stop_green_operator",
                side_effect=lambda *_args, **_kwargs: (events.append("stop-green") or {"retired": True}),
            ),
            mock.patch.object(dual, "require_service_active"),
            mock.patch.object(
                dual,
                "verify_url_runtime_identity",
                return_value={
                    "process": {"pid": 123},
                    "manifest": {"release_id": "green", "repo_head": HEAD_GREEN},
                },
            ),
        ):
            result = runtime.retire_blue()
        self.assertTrue(result["retired"])
        self.assertLess(events.index("stop-blue"), events.index("start-canonical"))
        self.assertLess(events.index("start-canonical"), events.index("switch-canonical"))
        self.assertLess(
            events.index("switch-canonical"), events.index("canonical-readiness")
        )
        self.assertLess(
            events.index("canonical-readiness"), events.index("stop-green")
        )
        self.assertLess(events.index("stop-green"), events.index("release-admission"))
        self.assertIsNone(runtime.admission_marker)

    def test_canonical_mcp_failure_preserves_green_and_closed_admission(self) -> None:
        snapshot = mock.Mock()
        snapshot.contract = mock.Mock()
        build = mock.Mock(
            release_path=Path("/release/green"),
            release_id="green",
            agent_instructions={"sha256": INSTRUCTIONS_SHA256},
        )
        selector = {
            "selector_sha256": "6a" * 32,
            "selected_slot": "green",
            "upstream_port": 18182,
            "runtime_binding": runtime_binding("green", HEAD_GREEN),
            "runtime_binding_sha256": "6b" * 32,
        }
        marker = {"token": "active-marker"}
        runtime = dual.ProductionBlueGreenRuntime(
            repo=ROOT,
            runtime=Path("/runtime"),
            snapshot=snapshot,
            build=build,
            activation=mock.Mock(),
            blue_manifest={},
            blue_binding=runtime_binding("blue", HEAD_BLUE),
            green_binding=runtime_binding("green", HEAD_GREEN),
            selector_before=selector,
            cutover_id="cutover-canonical-readiness-failure",
            timeout_seconds=10,
            green_unit="grabowski-green-operator-123456789abc.service",
            admission_marker=marker,
            green_started=True,
            connector_switched=True,
            current_selector=selector,
        )
        canonical = {
            **selector,
            "selector_sha256": "6c" * 32,
            "selected_slot": "canonical",
            "upstream_port": 18181,
        }
        with (
            mock.patch.object(dual.core, "verify_apply_snapshot_unchanged"),
            mock.patch.object(dual.core, "activate_pointer"),
            mock.patch.object(dual, "stop_service"),
            mock.patch.object(dual, "observe_service", return_value=mock.Mock(confirmed_active=True)),
            mock.patch.object(dual, "_require_selector_authority", return_value={"authoritative": True}),
            mock.patch.object(dual, "start_service"),
            mock.patch.object(dual, "verify_operator_process"),
            mock.patch.object(dual, "_require_loopback_listener", return_value={}),
            mock.patch.object(dual.transport_ingress, "publish_routing_selector", return_value=canonical),
            mock.patch.object(
                dual,
                "_probe_release_runtime",
                side_effect=RuntimeError("canonical MCP readiness failed"),
            ),
            mock.patch.object(dual, "_stop_green_operator") as stop_green,
            mock.patch.object(dual, "release_operator_deployment_admission") as release_admission,
        ):
            with self.assertRaisesRegex(RuntimeError, "canonical MCP readiness failed"):
                runtime.retire_blue()
        stop_green.assert_not_called()
        release_admission.assert_not_called()
        self.assertTrue(runtime.green_started)
        self.assertIs(runtime.admission_marker, marker)

    def test_green_inherits_only_canonical_nonsecret_recovery_environment(self) -> None:
        observed = mock.Mock(
            returncode=0,
            stdout=(
                "PYTHONUNBUFFERED=1 "
                "GRABOWSKI_SERVER_RECOVERY_HOST=heimberry "
                "GRABOWSKI_SERVER_RECOVERY_TARGET=heimberry:rest-server/probe "
                "UNRELATED_SECRET=do-not-copy"
            ),
        )
        with mock.patch.object(dual.core, "run", return_value=observed) as run:
            environment = dual._canonical_operator_green_environment()
        self.assertEqual(
            environment,
            {
                "GRABOWSKI_SERVER_RECOVERY_HOST": "heimberry",
                "GRABOWSKI_SERVER_RECOVERY_TARGET": "heimberry:rest-server/probe",
            },
        )
        self.assertEqual(
            run.call_args.kwargs["timeout"], dual.core.TIMEOUTS["systemd_query"]
        )


class ScheduledPathContractTests(unittest.TestCase):
    def test_normal_runner_has_no_simulated_or_stop_world_default(self) -> None:
        source = (ROOT / "tools/run_scheduled_deploy.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("run_production_blue_green_cutover", source)
        self.assertNotIn("default_local_blue_green_hooks", source)
        self.assertNotIn('["make", "deploy-apply"]', source)


if __name__ == "__main__":
    unittest.main()

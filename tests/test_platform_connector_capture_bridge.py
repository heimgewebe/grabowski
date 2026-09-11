from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

operations = importlib.import_module("grabowski_operations")

HELPER_PATH = ROOT / "tools" / "grabowski_platform_connector_capture.py"
SPEC = importlib.util.spec_from_file_location(
    "grabowski_platform_connector_capture_test", HELPER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("grabowski_platform_connector_capture.py could not be loaded")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


ARTIFACT_SHA = "a" * 64
CONTRACT_SHA = "b" * 64
OBSERVED_PATH = f"/home/alex/worktrees/.grabowski-platform-observed-{ARTIFACT_SHA}.json"
STAGED_PATH = Path(
    "/home/alex/worktrees/.grabowski-platform-snapshot-11111111111111111111111111111111.json"
)


def _parameters(**overrides: str) -> dict[str, str]:
    result = {
        "observed_artifact_path": OBSERVED_PATH,
        "expected_artifact_sha256": ARTIFACT_SHA,
        "source_reference": "chatgpt:connector-catalog:test",
        "observation_scope": "connector_catalog",
        "observation_id": "catalog-test-1",
        "publication_request_id": "request-test-1",
        "requested_contract_sha256": CONTRACT_SHA,
        "observed_at_unix": "1000",
    }
    result.update(overrides)
    return result


def _snapshot_document() -> dict[str, object]:
    observed = {
        "schema_version": 2,
        "tools": [
            {
                "name": "alpha",
                "inputSchema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                },
            }
        ],
        "complete_schema_count": 1,
        "complete_schema_sha256": "c" * 64,
    }
    catalog_sha = hashlib.sha256(helper._canonical_bytes(observed)).hexdigest()
    document: dict[str, object] = {
        "schema_version": 2,
        "kind": helper.SNAPSHOT_KIND,
        "source": {
            "kind": helper.SOURCE_KIND,
            "platform": "chatgpt",
            "connector_id": "grabowski",
            "observation_scope": "connector_catalog",
            "observation_id": "catalog-test-1",
            "publication_request_id": "request-test-1",
            "requested_contract_sha256": CONTRACT_SHA,
            "reference": "chatgpt:connector-catalog:test",
            "observed_at_unix": 1000,
            "catalog_sha256": catalog_sha,
        },
        "runtime_binding": {
            "registered_tool_count": 1,
            "registered_names_sha256": "d" * 64,
            "release_id": "release-test-1",
            "repo_head": "e" * 40,
            "agent_instructions_sha256": "f" * 64,
        },
        "observed_tools": observed,
    }
    document["snapshot_sha256"] = hashlib.sha256(
        helper._canonical_bytes(document)
    ).hexdigest()
    return document


class PlatformConnectorCaptureBridgeTests(unittest.TestCase):
    def test_plan_is_fixed_path_hash_and_authoritative_scope_bound(self) -> None:
        plan = operations._platform_connector_capture_plan(_parameters())
        self.assertEqual(plan["artifact_path"], OBSERVED_PATH)
        self.assertEqual(plan["artifact_sha256"], ARTIFACT_SHA)
        self.assertEqual(plan["effect"], "platform_observation_publish_and_reconcile")
        self.assertTrue(plan["typed_builtin"])

        with self.assertRaisesRegex(ValueError, "fixed platform capture inbox"):
            operations._platform_connector_capture_plan(
                _parameters(observed_artifact_path="/tmp/observed.json")
            )
        with self.assertRaisesRegex(ValueError, "expected_artifact_sha256"):
            operations._platform_connector_capture_plan(
                _parameters(expected_artifact_sha256="short")
            )
        with self.assertRaisesRegex(ValueError, "not publication-authoritative"):
            operations._platform_connector_capture_plan(
                _parameters(observation_scope="chat_session_catalog")
            )

    def test_root_target_requires_canonical_fixed_staging_path(self) -> None:
        target = json.dumps(
            {
                "source_path": str(STAGED_PATH),
                "expected_file_sha256": "1" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        parsed = operations._platform_capture_root_target(target)
        self.assertEqual(parsed["source_path"], str(STAGED_PATH))

        with self.assertRaisesRegex(ValueError, "canonical JSON"):
            operations._platform_capture_root_target(
                json.dumps(
                    {
                        "source_path": str(STAGED_PATH),
                        "expected_file_sha256": "1" * 64,
                    },
                    sort_keys=True,
                )
            )
        with self.assertRaisesRegex(ValueError, "binding is invalid"):
            operations._platform_capture_root_target(
                json.dumps(
                    {
                        "source_path": "/tmp/snapshot.json",
                        "expected_file_sha256": "1" * 64,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )

    def test_root_helper_validates_snapshot_hash_and_binding_shape(self) -> None:
        document = _snapshot_document()
        expected = document["snapshot_sha256"]
        self.assertEqual(helper._validate_snapshot(document), expected)

        tampered = json.loads(json.dumps(document))
        tampered["runtime_binding"]["repo_head"] = "0" * 40
        with self.assertRaisesRegex(helper.CaptureError, "content hash mismatch"):
            helper._validate_snapshot(tampered)

        malformed = json.loads(json.dumps(document))
        malformed["snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(helper.CaptureError, "content hash mismatch"):
            helper._validate_snapshot(malformed)

    def test_wrong_current_request_stops_before_any_root_staging(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        stage = Mock()
        invoke = Mock()
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "build_platform_connector_snapshot",
                return_value={"snapshot_sha256": "2" * 64, "runtime_binding": binding},
            ),
            patch.object(
                operations,
                "_platform_runtime_context",
                return_value=(binding, {}, metadata),
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_current",
                return_value={
                    "state": "awaiting_platform_observation",
                    "request_id": "different-request",
                    "contract_sha256": CONTRACT_SHA,
                    "current_sha256": "7" * 64,
                },
            ),
            patch.object(operations, "_write_platform_capture_stage", stage),
            patch.object(operations, "_invoke_mainpid_privileged_action", invoke),
        ):
            with self.assertRaisesRegex(ValueError, "publication request is not current"):
                operations._run_platform_connector_capture_operation(_parameters())

        stage.assert_not_called()
        invoke.assert_not_called()

    def test_publication_binding_rejects_stale_contract_and_pre_request_time(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        current = {
            "state": "awaiting_platform_observation",
            "request_id": "request-test-1",
            "contract_sha256": CONTRACT_SHA,
            "current_sha256": "7" * 64,
        }
        request = {
            "request_id": "request-test-1",
            "request_sha256": "8" * 64,
            "requested_at_unix": 900,
            "expected_contract": {"tool_contract_sha256": CONTRACT_SHA},
        }
        with (
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_current",
                return_value=current,
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_request",
                return_value=request,
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_platform_publication_contract",
                return_value={"tool_contract_sha256": "different"},
            ),
        ):
            with self.assertRaisesRegex(ValueError, "active runtime contract differs"):
                operations._platform_capture_publication_binding(
                    operations._platform_connector_capture_plan(_parameters()),
                    binding,
                    metadata,
                )

        pre_request = _parameters(observed_at_unix="800")
        with (
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_current",
                return_value=current,
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_request",
                return_value=request,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "predates the publication request"):
                operations._platform_capture_publication_binding(
                    operations._platform_connector_capture_plan(pre_request),
                    binding,
                    metadata,
                )

    def test_future_observation_is_rejected_before_root_staging(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        current = {
            "state": "awaiting_platform_observation",
            "request_id": "request-test-1",
            "contract_sha256": CONTRACT_SHA,
            "current_sha256": "7" * 64,
        }
        request = {
            "request_id": "request-test-1",
            "request_sha256": "8" * 64,
            "requested_at_unix": 900,
            "expected_contract": {"tool_contract_sha256": CONTRACT_SHA},
        }
        future = str(
            1000
            + operations.base.grabowski_client_snapshot.SNAPSHOT_CLOCK_SKEW_SECONDS
            + 1
        )
        with (
            patch.object(operations.time, "time", return_value=1000),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_current",
                return_value=current,
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "_read_publication_request",
                return_value=request,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "too far in the future"):
                operations._platform_capture_publication_binding(
                    operations._platform_connector_capture_plan(
                        _parameters(observed_at_unix=future)
                    ),
                    binding,
                    metadata,
                )

    def test_runtime_drift_while_building_stops_before_root_staging(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        stage = Mock()
        invoke = Mock()
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(
                operations,
                "_platform_runtime_context",
                return_value=(binding, {}, metadata),
            ),
            patch.object(
                operations,
                "_platform_capture_publication_binding",
                return_value={"request_sha256": "f" * 64},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "build_platform_connector_snapshot",
                return_value={
                    "snapshot_sha256": "2" * 64,
                    "runtime_binding": {**binding, "repo_head": "0" * 40},
                },
            ),
            patch.object(operations, "_write_platform_capture_stage", stage),
            patch.object(operations, "_invoke_mainpid_privileged_action", invoke),
        ):
            with self.assertRaisesRegex(ValueError, "runtime changed while building"):
                operations._run_platform_connector_capture_operation(_parameters())

        stage.assert_not_called()
        invoke.assert_not_called()

    def test_runtime_drift_immediately_before_root_staging_is_rejected(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        drifted_binding = {**binding, "repo_head": "0" * 40}
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        document = {"snapshot_sha256": "2" * 64, "runtime_binding": binding}
        stage = Mock()
        invoke = Mock()
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(
                operations,
                "_platform_runtime_context",
                side_effect=[
                    (binding, {}, metadata),
                    (drifted_binding, {}, metadata),
                ],
            ),
            patch.object(
                operations,
                "_platform_capture_publication_binding",
                return_value={"request_sha256": "f" * 64},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "build_platform_connector_snapshot",
                return_value=document,
            ),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                return_value={"snapshot_sha256": None},
            ),
            patch.object(operations, "_write_platform_capture_stage", stage),
            patch.object(operations, "_invoke_mainpid_privileged_action", invoke),
        ):
            with self.assertRaisesRegex(ValueError, "runtime changed before root capture"):
                operations._run_platform_connector_capture_operation(_parameters())

        stage.assert_not_called()
        invoke.assert_not_called()

    def test_pretransport_broker_exception_removes_stage(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        document = {"snapshot_sha256": "2" * 64, "runtime_binding": binding}
        staged = Mock()
        staged.__str__ = Mock(
            return_value="/home/alex/worktrees/.grabowski-platform-snapshot-11111111111111111111111111111111.json"
        )
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(
                operations,
                "_platform_runtime_context",
                return_value=(binding, {}, metadata),
            ),
            patch.object(
                operations,
                "_platform_capture_publication_binding",
                return_value={"request_sha256": "f" * 64},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "build_platform_connector_snapshot",
                return_value=document,
            ),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                return_value={"snapshot_sha256": None},
            ),
            patch.object(
                operations,
                "_write_platform_capture_stage",
                return_value=(staged, "7" * 64),
            ),
            patch.object(
                operations,
                "_invoke_mainpid_privileged_action",
                side_effect=PermissionError("broker unavailable"),
            ),
        ):
            with self.assertRaisesRegex(PermissionError, "broker unavailable"):
                operations._run_platform_connector_capture_operation(_parameters())

        staged.unlink.assert_called_once_with(missing_ok=True)

    def test_unknown_broker_exact_write_separates_root_effect_from_contract_mismatch(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "6" * 64,
        }
        document = {"snapshot_sha256": "2" * 64, "runtime_binding": binding}
        staged = Mock()
        staged.__str__ = Mock(
            return_value="/home/alex/worktrees/.grabowski-platform-snapshot-11111111111111111111111111111111.json"
        )
        reconcile = Mock()
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(operations, "_platform_runtime_context", return_value=(binding, {}, metadata)),
            patch.object(operations, "_platform_capture_publication_binding", return_value={"request_sha256": "f" * 64}),
            patch.object(operations.base.grabowski_client_snapshot, "build_platform_connector_snapshot", return_value=document),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                side_effect=[
                    {"snapshot_sha256": None},
                    {
                        "snapshot_sha256": document["snapshot_sha256"],
                        "runtime_binding_matches": True,
                        "publication_contract_matches": False,
                    },
                ],
            ),
            patch.object(operations, "_write_platform_capture_stage", return_value=(staged, "7" * 64)),
            patch.object(operations, "_invoke_mainpid_privileged_action", return_value={"outcome": "unknown"}),
            patch.object(operations.base.grabowski_client_snapshot, "reconcile_platform_publication_for_runtime", reconcile),
        ):
            result = operations._run_platform_connector_capture_operation(_parameters())

        self.assertEqual(result["outcome"], "failed")
        self.assertTrue(result["root_effect_confirmed"])
        self.assertTrue(result["post_runtime_stable"])
        self.assertTrue(result["runtime_binding_matches"])
        self.assertFalse(result["publication_contract_matches"])
        staged.unlink.assert_called_once_with(missing_ok=True)
        reconcile.assert_not_called()

    def test_definitive_broker_outcome_cleans_stage_when_post_readback_raises(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {"complete_schema_count": 1, "complete_schema_sha256": "6" * 64}
        document = {"snapshot_sha256": "2" * 64, "runtime_binding": binding}
        staged = Mock()
        staged.__str__ = Mock(
            return_value="/home/alex/worktrees/.grabowski-platform-snapshot-11111111111111111111111111111111.json"
        )
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(operations, "_platform_runtime_context", return_value=(binding, {}, metadata)),
            patch.object(operations, "_platform_capture_publication_binding", return_value={"request_sha256": "f" * 64}),
            patch.object(operations.base.grabowski_client_snapshot, "build_platform_connector_snapshot", return_value=document),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                side_effect=[{"snapshot_sha256": None}, RuntimeError("readback unavailable")],
            ),
            patch.object(operations, "_write_platform_capture_stage", return_value=(staged, "7" * 64)),
            patch.object(operations, "_invoke_mainpid_privileged_action", return_value={"outcome": "succeeded"}),
        ):
            with self.assertRaisesRegex(RuntimeError, "readback unavailable"):
                operations._run_platform_connector_capture_operation(_parameters())

        staged.unlink.assert_called_once_with(missing_ok=True)

    def test_unknown_broker_outcome_retains_stage_when_post_readback_raises(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        metadata = {"complete_schema_count": 1, "complete_schema_sha256": "6" * 64}
        document = {"snapshot_sha256": "2" * 64, "runtime_binding": binding}
        staged = Mock()
        staged.__str__ = Mock(
            return_value="/home/alex/worktrees/.grabowski-platform-snapshot-11111111111111111111111111111111.json"
        )
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(operations, "_platform_runtime_context", return_value=(binding, {}, metadata)),
            patch.object(operations, "_platform_capture_publication_binding", return_value={"request_sha256": "f" * 64}),
            patch.object(operations.base.grabowski_client_snapshot, "build_platform_connector_snapshot", return_value=document),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                side_effect=[{"snapshot_sha256": None}, RuntimeError("readback unavailable")],
            ),
            patch.object(operations, "_write_platform_capture_stage", return_value=(staged, "7" * 64)),
            patch.object(operations, "_invoke_mainpid_privileged_action", return_value={"outcome": "unknown"}),
        ):
            result = operations._run_platform_connector_capture_operation(_parameters())

        self.assertEqual(result["outcome"], "unknown")
        self.assertFalse(result["root_effect_confirmed"])
        self.assertTrue(result["staged_snapshot_retained"])
        self.assertEqual(result["postflight_error_class"], "RuntimeError")
        staged.unlink.assert_not_called()

    def test_unknown_root_outcome_stops_before_reconciliation(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "3" * 64,
            "release_id": "release-test-1",
            "repo_head": "4" * 40,
            "agent_instructions_sha256": "5" * 64,
        }
        document = {"snapshot_sha256": "2" * 64, "runtime_binding": binding}
        reconcile = Mock()
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(
                operations,
                "_platform_capture_publication_binding",
                return_value={"request_sha256": "f" * 64},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "build_platform_connector_snapshot",
                return_value=document,
            ),
            patch.object(
                operations,
                "_platform_runtime_context",
                return_value=(binding, {}, {"complete_schema_count": 1, "complete_schema_sha256": "6" * 64}),
            ),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                side_effect=[{"snapshot_sha256": None}, {"snapshot_sha256": None}],
            ),
            patch.object(
                operations,
                "_write_platform_capture_stage",
                return_value=(STAGED_PATH, "7" * 64),
            ),
            patch.object(
                operations,
                "_invoke_mainpid_privileged_action",
                return_value={"outcome": "unknown"},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "reconcile_platform_publication_for_runtime",
                reconcile,
            ),
        ):
            result = operations._run_platform_connector_capture_operation(_parameters())

        self.assertEqual(result["outcome"], "unknown")
        self.assertFalse(result["root_effect_confirmed"])
        self.assertTrue(result["staged_snapshot_retained"])
        reconcile.assert_not_called()

    def test_exact_root_effect_reconciles_once(self) -> None:
        binding = {
            "registered_tool_count": 1,
            "registered_names_sha256": "9" * 64,
            "release_id": "release-test-1",
            "repo_head": "a" * 40,
            "agent_instructions_sha256": "b" * 64,
        }
        metadata = {
            "complete_schema_count": 1,
            "complete_schema_sha256": "c" * 64,
        }
        document = {"snapshot_sha256": "8" * 64, "runtime_binding": binding}
        reconcile = Mock(return_value={"state": "platform_converged"})
        with (
            patch.object(operations.operator, "_require_operator_capability"),
            patch.object(operations.operator, "_require_operator_mutation"),
            patch.object(operations, "_read_platform_capture_artifact", return_value={}),
            patch.object(
                operations,
                "_platform_capture_publication_binding",
                return_value={"request_sha256": "f" * 64},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "build_platform_connector_snapshot",
                return_value=document,
            ),
            patch.object(
                operations,
                "_platform_runtime_context",
                return_value=(binding, {}, metadata),
            ),
            patch.object(
                operations,
                "_platform_snapshot_readback",
                side_effect=[
                    {"snapshot_sha256": None},
                    {
                        "snapshot_sha256": document["snapshot_sha256"],
                        "runtime_binding_matches": True,
                        "publication_contract_matches": True,
                    },
                    {
                        "snapshot_sha256": document["snapshot_sha256"],
                        "state": "matched",
                        "runtime_binding_matches": True,
                        "publication_state": "platform_converged",
                        "publication_contract_matches": True,
                    },
                ],
            ),
            patch.object(
                operations,
                "_write_platform_capture_stage",
                return_value=(STAGED_PATH, "d" * 64),
            ),
            patch.object(
                operations,
                "_invoke_mainpid_privileged_action",
                return_value={"outcome": "succeeded"},
            ),
            patch.object(
                operations.base.grabowski_client_snapshot,
                "reconcile_platform_publication_for_runtime",
                reconcile,
            ),
            patch.object(operations.base, "_append_audit"),
        ):
            result = operations._run_platform_connector_capture_operation(_parameters())

        self.assertTrue(result["success"])
        self.assertTrue(result["root_effect_confirmed"])
        self.assertEqual(result["platform_publication_state"], "platform_converged")
        reconcile.assert_called_once_with(
            registered_tool_count=1,
            registered_names_sha256="9" * 64,
            complete_schema_count=1,
            complete_schema_sha256="c" * 64,
        )


if __name__ == "__main__":
    unittest.main()

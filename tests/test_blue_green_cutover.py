from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import Mock

import grabowski_client_snapshot as client_snapshot
import grabowski_connector_contract as contract
import grabowski_convergence as convergence
import grabowski_deployment_observer as observer
import grabowski_serving_process as serving

ROOT = Path(__file__).resolve().parents[1]


class _FakeFastMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def _load_self_deploy():
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_pydantic = types.ModuleType("pydantic")
    fake_pydantic.Field = lambda **kwargs: kwargs
    operator = types.ModuleType("grabowski_operator_core")
    operator.mcp = _FakeFastMCP()
    operator._require_operator_mutation = Mock()
    operator._require_operator_capability = Mock()
    operator.grabowski_job_start = Mock()
    operator._start_job = Mock()
    operator.JOB_PREFIX = "grabowski-job-"
    operator.JOBS_DIR = Path.home() / ".local/state/grabowski/jobs"
    operator._argv_hash = lambda argv: hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    operator._jobs_root = Mock()
    operator._read_job_metadata = Mock()
    operator.grabowski_job_status = Mock()
    base = types.ModuleType("grabowski_mcp")
    base._append_audit = Mock()
    read_surface = types.ModuleType("grabowski_read_surface")
    read_surface._git_command = lambda repo, *args: ["git", "-C", str(repo), *args]
    read_surface._run_read = Mock()
    name = "grabowski_self_deploy_blue_green_test"
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "src" / "grabowski_self_deploy.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load self deploy module")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(
        sys.modules,
        {
            "mcp": fake_mcp,
            "mcp.types": fake_types,
            "pydantic": fake_pydantic,
            "grabowski_operator_core": operator,
            "grabowski_mcp": base,
            "grabowski_read_surface": read_surface,
            name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


self_deploy = _load_self_deploy()


RELEASE_BLUE = "blueblueblue-srcsetblue-lockblue-contractblue"
RELEASE_GREEN = "greengreengreen-srcsetgreen-lockgreen-contractgreen"
HEAD_BLUE = "a" * 40
HEAD_GREEN = "b" * 40
SOURCE_SHA = "c" * 64
NAMES_SHA = "d" * 64
INSTRUCTIONS_SHA = "e" * 64

NAMES = [
    "alpha",
    "grabowski_bureau_candidate_assess",
    "grabowski_secret_reveal",
    "grabowski_task_start",
    "grip_run",
]


def _object_schema(properties: set[str]) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            name: {"type": "string", "default": ""}
            for name in sorted(properties)
        },
    }


def _sentinel_schemas() -> dict[str, dict[str, object]]:
    return {
        "grabowski_bureau_candidate_assess": _object_schema(
            contract.REQUIRED_SCHEMA_PROPERTIES[
                "grabowski_bureau_candidate_assess"
            ]
        ),
        "grabowski_secret_reveal": _object_schema({"path"}),
        "grabowski_task_start": _object_schema(
            contract.REQUIRED_SCHEMA_PROPERTIES["grabowski_task_start"]
        ),
        "grip_run": _object_schema(
            contract.REQUIRED_SCHEMA_PROPERTIES["grip_run"]
        ),
    }


def _ready_green() -> dict[str, object]:
    names = list(NAMES)
    schemas = _sentinel_schemas()
    return contract.evaluate_green_readiness(
        observed_names=names,
        observed_schemas=schemas,
        runtime_names=names,
        runtime_schemas=schemas,
        contract_names=names,
        observed_release_id=RELEASE_GREEN,
        expected_release_id=RELEASE_GREEN,
        observed_repo_head=HEAD_GREEN,
        expected_repo_head=HEAD_GREEN,
        observed_agent_instructions_sha256=INSTRUCTIONS_SHA,
        expected_agent_instructions_sha256=INSTRUCTIONS_SHA,
    )


def _plan(**overrides: object) -> dict[str, object]:
    kwargs = {
        "expected_head": HEAD_GREEN,
        "blue_release_id": RELEASE_BLUE,
        "green_release_id": RELEASE_GREEN,
        "source_identity_sha256": SOURCE_SHA,
        "expected_names_sha256": NAMES_SHA,
        "expected_agent_instructions_sha256": INSTRUCTIONS_SHA,
        "cutover_id": "bgc-test-001",
        "cutover_generation": 1,
    }
    kwargs.update(overrides)
    return self_deploy.build_blue_green_plan(**kwargs)


class ServingProcessBlueGreenTests(unittest.TestCase):
    def setUp(self) -> None:
        serving.reset_for_tests()
        self.addCleanup(serving.reset_for_tests)

    def test_long_lived_reads_do_not_block_effect_terminalization(self) -> None:
        serving.freeze(RELEASE_BLUE, HEAD_BLUE)
        read_id = serving.register_call("grabowski_status", serving.CALL_KIND_READ)
        effect_id = serving.register_call(
            "grabowski_task_start", serving.CALL_KIND_EFFECT_BEARING
        )
        serving.close_for_mutations(reason="blue-green-cutover")
        result = serving.terminalize_effect_bearing_calls()

        self.assertEqual(result["terminalized_count"], 1)
        self.assertEqual(result["remaining_read_count"], 1)
        self.assertEqual(
            result["terminalized_effect_bearing_calls"][0]["identity"], effect_id
        )
        self.assertEqual(result["remaining_read_calls"][0]["identity"], read_id)
        self.assertEqual(len(serving.active_read_calls()), 1)
        self.assertEqual(serving.active_effect_bearing_calls(), [])

    def test_mutations_close_blocks_new_effects_but_allows_reads(self) -> None:
        serving.freeze(RELEASE_BLUE, HEAD_BLUE)
        serving.close_for_mutations()
        with self.assertRaisesRegex(RuntimeError, "rejects new effect-bearing"):
            serving.register_call("grabowski_task_start", serving.CALL_KIND_EFFECT_BEARING)
        read_id = serving.register_call("grabowski_context", serving.CALL_KIND_READ)
        self.assertTrue(read_id)
        self.assertTrue(serving.is_stale(RELEASE_BLUE, HEAD_BLUE))
        self.assertFalse(serving.mutations_admitted(RELEASE_BLUE, HEAD_BLUE))
        message = serving.mutation_rejection_message(RELEASE_BLUE, HEAD_BLUE)
        self.assertIn("closed for new mutations", message)
        self.assertIn("green runtime", message)

    def test_identity_projection_exposes_role_and_call_counts(self) -> None:
        serving.freeze(RELEASE_BLUE, HEAD_BLUE)
        serving.register_call("read", serving.CALL_KIND_READ)
        serving.register_call("write", serving.CALL_KIND_EFFECT_BEARING)
        serving.set_role(serving.ROLE_RETIRING)
        serving.close_for_mutations()
        projection = serving.identity(RELEASE_BLUE, HEAD_BLUE)
        self.assertEqual(projection["role"], serving.ROLE_RETIRING)
        self.assertTrue(projection["mutations_closed"])
        self.assertEqual(projection["active_read_calls"], 1)
        self.assertEqual(projection["active_effect_bearing_calls"], 1)
        self.assertFalse(projection["serves_deployed_release"])


class ConnectorGreenReadinessTests(unittest.TestCase):
    def test_ready_when_all_axes_match(self) -> None:
        result = _ready_green()
        self.assertTrue(result["ready"])
        self.assertTrue(result["bedienvertrag_matches"])
        self.assertTrue(result["manifest_identity_matches"])
        self.assertEqual(result["mismatches"], [])
        self.assertEqual(
            set(result["schema_sentinels"]), set(contract.REQUIRED_SCHEMA_SENTINELS)
        )

    def test_bedienvertrag_mismatch_fails_closed(self) -> None:
        names = list(NAMES)
        schemas = _sentinel_schemas()
        result = contract.evaluate_green_readiness(
            observed_names=names,
            observed_schemas=schemas,
            runtime_names=names,
            runtime_schemas=schemas,
            contract_names=names,
            observed_release_id=RELEASE_GREEN,
            expected_release_id=RELEASE_GREEN,
            observed_repo_head=HEAD_GREEN,
            expected_repo_head=HEAD_GREEN,
            observed_agent_instructions_sha256="f" * 64,
            expected_agent_instructions_sha256=INSTRUCTIONS_SHA,
        )
        self.assertFalse(result["ready"])
        self.assertIn("agent_instructions_sha256", result["mismatches"])


class SnapshotCutoverRebindTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.state_root = root / "client-snapshot"
        self.snapshot_path = self.state_root / "current.json"
        self.lock_path = self.state_root / ".lock"
        self.patches = [
            mock.patch.object(client_snapshot, "STATE_ROOT", self.state_root),
            mock.patch.object(client_snapshot, "SNAPSHOT_PATH", self.snapshot_path),
            mock.patch.object(client_snapshot, "LOCK_PATH", self.lock_path),
            mock.patch.object(
                client_snapshot, "OBSERVER_STATE_PATH", self.state_root / "observer.json"
            ),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def _parameters(self) -> dict[str, object]:
        names = list(NAMES)
        artifact = {
            "schema_version": 1,
            "tools": [
                {"name": name, "inputSchema": _sentinel_schemas()[name]}
                if name in _sentinel_schemas()
                else name
                for name in names
            ],
        }
        return {
            "client_id": "cutover-client",
            "session_id": "cutover-session",
            "observed_tool_count": len(names),
            "observed_names_sha256": contract.fingerprint(names),
            "observed_release_id": RELEASE_GREEN,
            "observed_agent_instructions_sha256": INSTRUCTIONS_SHA,
            "observed_tools": artifact,
            "_server_tool_contract": {
                "registered_tool_count": len(names),
                "registered_names_sha256": contract.fingerprint(names),
                "runtime_matches_deployment_contract": True,
            },
            "_server_runtime": {
                "release_id": RELEASE_GREEN,
                "repo_head": HEAD_GREEN,
            },
            "_server_agent_instructions_sha256": INSTRUCTIONS_SHA,
            "_server_observed_tools": artifact,
        }

    def test_rebind_is_part_of_cutover_and_fails_on_mismatch(self) -> None:
        result = client_snapshot.rebind_for_cutover(
            self._parameters(),
            cutover_id="bgc-snap-1",
            cutover_generation=3,
            now_unix=1_700_000_000,
        )
        self.assertTrue(result["cutover_rebind"])
        self.assertEqual(result["state"], "matched")
        self.assertEqual(result["cutover_binding"]["cutover_id"], "bgc-snap-1")
        self.assertEqual(result["cutover_binding"]["cutover_generation"], 3)
        self.assertIn("cutover-rebind-v1", result["verification_model"])

        bad = self._parameters()
        bad["observed_release_id"] = RELEASE_BLUE
        with self.assertRaisesRegex(client_snapshot.ClientSnapshotError, "did not match"):
            client_snapshot.rebind_for_cutover(
                bad,
                cutover_id="bgc-snap-2",
                cutover_generation=1,
                now_unix=1_700_000_100,
            )


class BlueGreenOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        serving.reset_for_tests()
        self.addCleanup(serving.reset_for_tests)

    def test_successful_cutover_receipt_binds_all_required_axes(self) -> None:
        serving.freeze(RELEASE_BLUE, HEAD_BLUE)
        long_read = serving.register_call(
            "grabowski_job_logs", serving.CALL_KIND_READ
        )
        mutation = serving.register_call(
            "grabowski_task_start", serving.CALL_KIND_EFFECT_BEARING
        )
        plan = _plan()
        hooks = self_deploy.default_local_blue_green_hooks(green_readiness=_ready_green())
        receipt = self_deploy.execute_blue_green_cutover(plan, hooks)

        self.assertEqual(receipt["outcome"], "completed")
        self.assertEqual(receipt["phase"], "completed")
        self.assertEqual(receipt["green_release_id"], RELEASE_GREEN)
        self.assertEqual(receipt["names_sha256"], NAMES_SHA)
        self.assertEqual(receipt["agent_instructions_sha256"], INSTRUCTIONS_SHA)
        self.assertEqual(
            set(receipt["schema_sentinels"]), set(contract.REQUIRED_SCHEMA_SENTINELS)
        )
        self.assertTrue(receipt["green_readiness"]["ready"])
        self.assertEqual(receipt["effect_terminalization"]["terminalized_count"], 1)
        self.assertEqual(receipt["effect_terminalization"]["remaining_read_count"], 1)
        self.assertIn("manifest_integrity", receipt["preserves"])
        self.assertTrue(serving.mutations_closed())
        self.assertEqual(len(serving.active_read_calls()), 1)
        self.assertEqual(serving.active_read_calls()[0]["identity"], long_read)
        self.assertNotIn(
            mutation,
            {item["identity"] for item in serving.active_effect_bearing_calls()},
        )
        phases = [item["phase"] for item in hooks.observations]
        self.assertEqual(phases[0], "prepare")
        self.assertEqual(phases[-1], "completed")
        self.assertIn("cutover", phases)
        self.assertIn("terminalize_effects", phases)

    def test_pre_cutover_failure_rolls_back_without_switching(self) -> None:
        plan = _plan()
        hooks = self_deploy.default_local_blue_green_hooks(
            green_readiness={"ready": False, "mismatches": ["schemas_or_sentinels"]}
        )
        switched = {"value": False}

        def switch() -> dict[str, object]:
            switched["value"] = True
            return {"switched": True}

        hooks.switch_connector = switch
        receipt = self_deploy.execute_blue_green_cutover(plan, hooks)
        self.assertEqual(receipt["outcome"], "rolled_back")
        self.assertEqual(receipt["phase"], "rolled_back")
        self.assertFalse(switched["value"])
        self.assertEqual(receipt["recovery"]["action"], "retry_from_clean_blue")

    def test_post_cutover_failure_is_outcome_unknown(self) -> None:
        plan = _plan()
        hooks = self_deploy.default_local_blue_green_hooks(green_readiness=_ready_green())

        def boom() -> dict[str, object]:
            raise RuntimeError("retire failed after switch")

        hooks.retire_blue = boom
        receipt = self_deploy.execute_blue_green_cutover(plan, hooks)
        self.assertEqual(receipt["outcome"], "outcome_unknown")
        self.assertEqual(receipt["phase"], "outcome_unknown")
        self.assertEqual(
            receipt["recovery"]["action"], "readback_active_runtime_and_recover"
        )
        self.assertTrue(receipt["recovery"]["connector_switched"])

    def test_active_mutation_is_terminalized_while_long_read_remains(self) -> None:
        serving.freeze(RELEASE_BLUE, HEAD_BLUE)
        serving.register_call("long-read", serving.CALL_KIND_READ)
        serving.register_call("active-mutation", serving.CALL_KIND_EFFECT_BEARING)
        plan = _plan()
        hooks = self_deploy.default_local_blue_green_hooks(green_readiness=_ready_green())
        receipt = self_deploy.execute_blue_green_cutover(plan, hooks)
        self.assertEqual(receipt["outcome"], "completed")
        self.assertEqual(receipt["effect_terminalization"]["terminalized_count"], 1)
        self.assertEqual(receipt["effect_terminalization"]["remaining_read_count"], 1)
        self.assertEqual(len(serving.active_read_calls()), 1)
        self.assertEqual(serving.active_effect_bearing_calls(), [])


class ConvergenceBlueGreenTests(unittest.TestCase):
    def test_profile_and_assessment_bind_completed_receipt(self) -> None:
        serving.reset_for_tests()
        self.addCleanup(serving.reset_for_tests)
        serving.freeze(RELEASE_BLUE, HEAD_BLUE)
        serving.register_call("mutation", serving.CALL_KIND_EFFECT_BEARING)
        plan = _plan()
        hooks = self_deploy.default_local_blue_green_hooks(green_readiness=_ready_green())
        receipt = self_deploy.execute_blue_green_cutover(plan, hooks)
        profile = convergence.build_blue_green_deployment_profile(receipt)
        self.assertEqual(profile["profile_id"], convergence.BLUE_GREEN_PROFILE_ID)
        self.assertEqual(profile["categories"]["deployment_receipt"]["status"], "present")
        self.assertEqual(profile["categories"]["green_readiness"]["status"], "ready")
        self.assertEqual(profile["categories"]["snapshot_rebind"]["status"], "matched")
        self.assertEqual(
            profile["categories"]["effect_terminalization"]["status"], "present"
        )
        self.assertEqual(profile["categories"]["runtime_identity"]["status"], "bound")
        request = convergence.build_blue_green_assessment_request(
            receipt,
            observed_at="2026-08-05T12:00:00Z",
            evidence_authority="supplied",
        )
        self.assertEqual(request["classification"]["change_class"], "runtime")
        self.assertIn(
            "supplied_evidence_requires_authoritative_read",
            request["classification"]["blocked_by"],
        )
        self.assertTrue(request["effects"])
        self.assertTrue(request["verifications"])

    def test_missing_receipt_does_not_claim_completion(self) -> None:
        profile = convergence.build_blue_green_deployment_profile({})
        self.assertIn("deployment_receipt", profile["missing_evidence"])
        self.assertIn(
            "evidence_missing:deployment_receipt", profile["blocked_by"]
        )


class DeploymentObserverCutoverTests(unittest.TestCase):
    def test_failure_class_splits_pre_and_post_cutover(self) -> None:
        self.assertEqual(
            observer.cutover_failure_class("verify_green"), "pre_cutover_rollback"
        )
        self.assertEqual(
            observer.cutover_failure_class("cutover"), "post_cutover_outcome_unknown"
        )
        observation = observer.build_cutover_observation(
            cutover_id="bgc-obs",
            phase="post_cutover",
            expected_head=HEAD_GREEN,
            blue_release_id=RELEASE_BLUE,
            green_release_id=RELEASE_GREEN,
            source_identity_sha256=SOURCE_SHA,
            details={"note": "closed"},
            observed_at_unix=1_700_000_000,
        )
        self.assertEqual(observation["kind"], "grabowski_blue_green_cutover_observation")
        self.assertEqual(observation["failure_class"], "post_cutover_outcome_unknown")
        self.assertIn("observation_sha256", observation)


if __name__ == "__main__":
    unittest.main()

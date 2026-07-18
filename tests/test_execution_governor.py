from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import inspect
import json
import re
import time
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


class ExecutionGovernorRuntimeTests(unittest.TestCase):
    def _load_module(self):
        import importlib.util
        import sys
        import tempfile
        import types

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        fake_base = types.ModuleType("grabowski_mcp")
        fake_base._append_audit = lambda payload: None
        fake_base._require_mutations_enabled = lambda capability: None
        fake_base.grabowski_status = lambda: {
            "deployment": {
                "completion_status": "complete",
                "repo_head": "abc",
                "source_identity_valid": True,
                "runtime_binding_valid": True,
                "environment_compatibility_valid": True,
                "provenance_valid": True,
            },
            "tool_contract": {
                "registered_tool_count": 109,
                "expected_tool_count": 109,
                "runtime_matches_deployment_contract": True,
                "client_snapshot_observable": False,
            },
            "kill_switch": {"engaged": False},
        }

        class FakeMCP:
            def tool(self, *args, **kwargs):
                return lambda function: function

        fake_operator = types.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_operator.MUTATING = {}
        fake_operator.STATE_DIR = root / "state"
        fake_operator.HOME = root
        fake_operator._redact = lambda value: value
        fake_operator._require_operator_capability = lambda capability: None
        fake_operator._validate_unit = lambda unit: unit
        fake_operator._safe_environment = lambda: {}
        fake_operator._redact_argv = lambda argv: argv
        fake_operator._argv_hash = lambda argv: "argv-hash"
        fake_operator._redacted_command = lambda argv: " ".join(argv)
        fake_operator._limit = lambda text, max_bytes: (text, False)
        fake_operator._parse_show = lambda text: dict(
            line.split("=", 1) for line in text.splitlines() if "=" in line
        )

        old_base = sys.modules.get("grabowski_mcp")
        old_core = sys.modules.get("grabowski_operator_core")
        sys.modules["grabowski_mcp"] = fake_base
        sys.modules["grabowski_operator_core"] = fake_operator

        name = f"_execution_governor_{id(self)}"
        spec = importlib.util.spec_from_file_location(
            name, ROOT / "src/grabowski_friction.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)

        def restore_modules() -> None:
            if old_base is None:
                sys.modules.pop("grabowski_mcp", None)
            else:
                sys.modules["grabowski_mcp"] = old_base
            if old_core is None:
                sys.modules.pop("grabowski_operator_core", None)
            else:
                sys.modules["grabowski_operator_core"] = old_core
            sys.modules.pop(name, None)

        self.addCleanup(restore_modules)
        module.FRICTION_LOG = root / "state" / "friction" / "events.jsonl"
        module.FRICTION_DECISION_LOG = root / "state" / "friction" / "decisions.jsonl"
        module.EXECUTION_OUTCOME_LOG = (
            root / "state" / "friction" / "execution-outcomes.jsonl"
        )
        return module

    @staticmethod
    def _write_events(module, events):
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

    @staticmethod
    def _recommend(module, **overrides):
        values = {
            "operation_class": "read",
            "risk_level": "low",
            "may_mutate": False,
            "typed_tool_available": True,
            "lease_state": "free",
        }
        values.update(overrides)
        return module.execution_shape_recommendation(**values)

    def test_tools_and_capability_contract_are_registered(self) -> None:
        friction_source = (ROOT / "src/grabowski_friction.py").read_text(
            encoding="utf-8"
        )
        mcp_source = (ROOT / "src/grabowski_mcp.py").read_text(encoding="utf-8")
        for name in (
            "grabowski_execution_shape",
            "grabowski_execution_outcome_record",
            "grabowski_execution_governor_summary",
        ):
            self.assertIn(f'name="{name}"', friction_source)
            self.assertRegex(mcp_source, rf'["\']{re.escape(name)}["\']')
        self.assertRegex(
            mcp_source,
            r'["\']grabowski_execution_outcome_record["\']:\s*\(["\']friction_record["\'],\)',
        )

    def test_input_surface_is_typed_and_excludes_raw_command_text(self) -> None:
        module = self._load_module()
        parameters = set(
            inspect.signature(module.execution_shape_recommendation).parameters
        )
        self.assertNotIn("argv", parameters)
        self.assertNotIn("command", parameters)
        self.assertNotIn("secret", parameters)
        with self.assertRaisesRegex(ValueError, "operation_class"):
            self._recommend(module, operation_class="run-anything")
        with self.assertRaisesRegex(ValueError, "may_mutate=true"):
            self._recommend(module, operation_class="mutation", may_mutate=False)
        with self.assertRaisesRegex(ValueError, "requires may_mutate=false"):
            self._recommend(module, operation_class="read", may_mutate=True)
        with self.assertRaisesRegex(ValueError, "command_count"):
            self._recommend(module, command_count=101)

    def test_broad_read_is_split_from_connector_evidence(self) -> None:
        module = self._load_module()
        self._write_events(
            module,
            [
                {
                    "event_id": "transport-1",
                    "kind": "connector_transport",
                    "surface": "connector",
                    "operation": "read",
                    "symptom": "502 upstream error",
                    "resolved": False,
                },
                {
                    "event_id": "transport-2",
                    "kind": "connector_transport",
                    "surface": "connector",
                    "operation": "read",
                    "symptom": "stream exception",
                    "resolved": False,
                },
            ],
        )
        result = self._recommend(
            module,
            expected_output_bytes=1000,
            prior_failure_class="connector_transport",
        )
        self.assertEqual(result["authority"], "proposal_only_shadow_mode")
        self.assertEqual(result["recommended_route"], "split_read")
        self.assertTrue(result["action_shape"]["split_reads"])
        self.assertFalse(result["action_shape"]["batch_reads"])
        self.assertEqual(result["retry_policy"]["retry_limit"], 1)
        self.assertFalse(result["retry_policy"]["unchanged_retry_allowed"])
        self.assertIn("recurring_connector_transport_evidence", result["reason_codes"])
        self.assertEqual(
            result["friction_evidence"]["evidence_event_ids"],
            ["transport-1", "transport-2"],
        )
        self.assertRegex(result["recommendation_id"], r"^[0-9a-f]{64}$")

    def test_platform_filter_blocks_unchanged_retry(self) -> None:
        module = self._load_module()
        self._write_events(
            module,
            [
                {
                    "event_id": "filter-1",
                    "kind": "platform_filter",
                    "surface": "chat_tool",
                    "operation": "mutation",
                    "symptom": "blocked",
                    "resolved": False,
                }
            ],
        )
        result = self._recommend(
            module,
            operation_class="mutation",
            may_mutate=True,
            prior_failure_class="platform_filter",
            post_state_read_available=True,
        )
        self.assertEqual(result["recommended_route"], "operator_stop")
        self.assertFalse(result["route_feasible"])
        self.assertFalse(result["execution_authorized"])
        self.assertTrue(result["action_shape"]["stop"])
        self.assertFalse(result["action_shape"]["isolated_mutation"])
        self.assertEqual(result["retry_policy"]["retry_limit"], 0)
        self.assertFalse(result["retry_policy"]["unchanged_retry_allowed"])
        self.assertIn(
            "unknown", result["retry_policy"]["possible_mutation_transport_rule"]
        )
        self.assertTrue(result["post_state_readback"]["required"])

    def test_invalid_friction_evidence_stops_routing(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.FRICTION_LOG.write_text("not-json\n", encoding="utf-8")
        module.FRICTION_LOG.chmod(0o600)
        result = self._recommend(module)
        self.assertEqual(result["recommended_route"], "operator_stop")
        self.assertFalse(result["route_feasible"])
        self.assertIn("friction_evidence_integrity_invalid", result["reason_codes"])
        self.assertEqual(result["retry_policy"]["retry_limit"], 0)

    def test_post_mutation_transport_failure_requires_state_readback(self) -> None:
        module = self._load_module()
        result = self._recommend(
            module,
            operation_class="external_mutation",
            may_mutate=True,
            lease_state="owned",
            prior_failure_class="connector_transport",
            post_state_read_available=True,
        )
        self.assertEqual(result["recommended_route"], "state_readback")
        self.assertTrue(result["route_feasible"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["retry_policy"]["retry_limit"], 0)
        self.assertIn("possible_mutation_outcome_unknown", result["reason_codes"])
        self.assertTrue(result["action_shape"]["state_readback_only"])
        self.assertFalse(result["action_shape"]["isolated_mutation"])
        self.assertIn(
            "read the exact target state", " ".join(result["preflight_required"])
        )

    def _nonconflict_proof(
        self, module, *, issued_at: int | None = None, ttl: int = 90
    ):
        now = int(time.time()) if issued_at is None else issued_at
        proof_root = Path("/tmp/grabowski-governor-proof")
        repository = str(proof_root / "repo")
        existing = {
            "schema_version": 1,
            "repository": repository,
            "task_id": "TASK-A",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": "feat/a",
            "worktree": str(proof_root / "worktrees" / "a"),
            "effects": ["write"],
            "paths": [str(proof_root / "repo" / "src" / "a.py")],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        requested = {
            **existing,
            "task_id": "TASK-B",
            "head": "b" * 40,
            "branch": "feat/b",
            "worktree": str(proof_root / "worktrees" / "b"),
            "paths": [str(proof_root / "repo" / "src" / "b.py")],
            "components": [],
        }
        lease = {
            "resource_key": f"repo:{repository}",
            "owner_id": "owner-a",
            "acquired_at_unix": now,
            "updated_at_unix": now,
            "expires_at_unix": now + 180,
            "metadata_sha256": "c" * 64,
        }
        return module.nonconflict.create_nonconflict_proof(
            blocked_lease=lease,
            existing_scope=existing,
            requesting_owner="owner-b",
            resource_keys=[f"path:{repository}/src/b.py"],
            purpose="secondary exact work",
            requested_scope=requested,
            requested_scope_complete=True,
            proof_ttl_seconds=ttl,
            now=now,
        )

    def test_valid_nonconflict_proof_removes_only_the_lease_stop(self) -> None:
        module = self._load_module()
        proof = self._nonconflict_proof(module)
        result = self._recommend(
            module,
            operation_class="mutation",
            may_mutate=True,
            lease_state="conflict",
            post_state_read_available=True,
            nonconflict_proof=proof,
        )
        self.assertEqual(result["recommended_route"], "typed_tool")
        self.assertTrue(result["route_feasible"])
        self.assertFalse(result["execution_authorized"])
        self.assertIn("resource_lease_nonconflict_proof_valid", result["reason_codes"])
        self.assertTrue(result["nonconflict_evidence"]["valid"])
        self.assertTrue(
            result["nonconflict_evidence"]["requires_atomic_resource_revalidation"]
        )
        self.assertIn("atomically revalidate", " ".join(result["preflight_required"]))

    def test_invalid_or_stale_nonconflict_proof_keeps_the_lease_stop(self) -> None:
        module = self._load_module()
        proof = self._nonconflict_proof(module)
        proof["requesting_owner"] = "tampered-owner"
        tampered = self._recommend(
            module,
            operation_class="mutation",
            may_mutate=True,
            lease_state="conflict",
            nonconflict_proof=proof,
        )
        self.assertEqual(tampered["recommended_route"], "stop_resource_conflict")
        self.assertIn(
            "resource_lease_nonconflict_proof_invalid", tampered["reason_codes"]
        )
        stale = self._nonconflict_proof(
            module, issued_at=int(time.time()) - 120, ttl=30
        )
        stale_result = self._recommend(
            module,
            operation_class="mutation",
            may_mutate=True,
            lease_state="conflict",
            nonconflict_proof=stale,
        )
        self.assertEqual(stale_result["recommended_route"], "stop_resource_conflict")
        self.assertFalse(stale_result["nonconflict_evidence"]["valid"])

    def test_nonconflict_proof_does_not_bypass_high_impact_preflight(self) -> None:
        module = self._load_module()
        result = self._recommend(
            module,
            operation_class="high_impact",
            risk_level="critical",
            may_mutate=True,
            lease_state="conflict",
            nonconflict_proof=self._nonconflict_proof(module),
        )
        self.assertEqual(result["recommended_route"], "explicit_preflight")
        self.assertFalse(result["route_feasible"])
        self.assertFalse(result["execution_authorized"])
        self.assertIn("immutable_high_impact_boundary", result["reason_codes"])

    def test_policy_gate_never_becomes_an_adaptive_bypass(self) -> None:
        module = self._load_module()
        result = self._recommend(
            module,
            operation_class="mutation",
            may_mutate=True,
            lease_state="owned",
            prior_failure_class="policy_gate",
        )
        self.assertEqual(result["recommended_route"], "operator_stop")
        self.assertFalse(result["route_feasible"])
        self.assertIn(
            "policy_gate_requires_deliberate_evidence_or_policy_decision",
            result["reason_codes"],
        )
        self.assertEqual(result["retry_policy"]["retry_limit"], 0)

    def test_mutation_stops_on_resource_conflict_or_missing_readback(self) -> None:
        module = self._load_module()
        conflict = self._recommend(
            module,
            operation_class="mutation",
            may_mutate=True,
            lease_state="conflict",
            post_state_read_available=True,
        )
        self.assertEqual(conflict["recommended_route"], "stop_resource_conflict")
        self.assertFalse(conflict["route_feasible"])
        self.assertFalse(conflict["execution_authorized"])

        no_readback = self._recommend(
            module,
            operation_class="external_mutation",
            may_mutate=True,
            lease_state="owned",
            post_state_read_available=False,
        )
        self.assertEqual(no_readback["recommended_route"], "stop_missing_readback")
        self.assertFalse(no_readback["route_feasible"])
        self.assertFalse(no_readback["execution_authorized"])
        self.assertTrue(no_readback["action_shape"]["one_mutation_per_attempt"])

    def test_high_risk_never_receives_live_adaptive_authority(self) -> None:
        module = self._load_module()
        result = self._recommend(
            module,
            operation_class="high_impact",
            risk_level="critical",
            may_mutate=True,
            lease_state="owned",
            post_state_read_available=True,
        )
        self.assertEqual(result["recommended_route"], "explicit_preflight")
        self.assertFalse(result["route_feasible"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["promotion"]["applied"])
        self.assertEqual(result["promotion"]["eligible_risk_levels"], ["low", "medium"])
        self.assertIn("authorization", result["immutable_boundaries"])
        self.assertIn("recovery", result["immutable_boundaries"])
        self.assertIn("merge", result["immutable_boundaries"])
        self.assertIn("deployment", result["immutable_boundaries"])

    def test_bound_outcome_is_idempotent_and_accepts_workspace_routes(self) -> None:
        module = self._load_module()
        binding_id = "b" * 64
        kwargs = {
            "binding_id": binding_id,
            "recommendation_id": "a" * 64,
            "operation_class": "long_running",
            "risk_level": "critical",
            "recommended_route": "workspace_with_contrast",
            "actual_route": "full_workspace",
            "first_pass_success": True,
            "unchanged_retries": 0,
            "ambiguous_mutation_outcomes": 0,
            "tool_call_count": 4,
            "elapsed_ms": 120000,
            "evidence_ref": "artifact:agent-workspace:gaw-test:close:" + "c" * 64,
        }
        audit = Mock()
        module.base._append_audit = audit
        with patch.object(module.time, "time", return_value=1_783_773_600):
            first = module.record_execution_outcome_once(**kwargs)
            second = module.record_execution_outcome_once(**kwargs)
        self.assertEqual(
            [call.args[0]["operation"] for call in audit.call_args_list],
            [
                "execution-governor-outcome-record",
                "execution-governor-outcome-readback",
            ],
        )
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(first["outcome_id"], second["outcome_id"])
        lines = module.EXECUTION_OUTCOME_LOG.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["recommended_route"], "workspace_with_contrast")
        self.assertEqual(record["actual_route"], "full_workspace")

    def test_bound_outcome_rejects_same_binding_with_changed_evidence(self) -> None:
        module = self._load_module()
        kwargs = {
            "binding_id": "b" * 64,
            "recommendation_id": "a" * 64,
            "operation_class": "long_running",
            "risk_level": "high",
            "recommended_route": "full_workspace",
            "actual_route": "full_workspace",
            "first_pass_success": True,
            "unchanged_retries": 0,
            "ambiguous_mutation_outcomes": 0,
            "tool_call_count": 4,
            "elapsed_ms": 120000,
            "evidence_ref": "artifact:agent-workspace:gaw-test:close:" + "c" * 64,
        }
        with patch.object(module.time, "time", return_value=1_783_773_600):
            module.record_execution_outcome_once(**kwargs)
            with self.assertRaisesRegex(RuntimeError, "different evidence"):
                module.record_execution_outcome_once(
                    **{**kwargs, "first_pass_success": False}
                )
        self.assertEqual(
            len(module.EXECUTION_OUTCOME_LOG.read_text(encoding="utf-8").splitlines()),
            1,
        )

    def test_shadow_outcomes_create_low_risk_candidate_without_applying_it(
        self,
    ) -> None:
        module = self._load_module()
        now = 1_783_773_600
        with patch.object(module.time, "time", return_value=now):
            for _ in range(module.EXECUTION_GOVERNOR_MIN_EVIDENCE):
                receipt = module.record_execution_outcome(
                    recommendation_id="a" * 64,
                    operation_class="read",
                    risk_level="low",
                    recommended_route="typed_tool",
                    actual_route="typed_tool",
                    first_pass_success=True,
                    unchanged_retries=0,
                    ambiguous_mutation_outcomes=0,
                    tool_call_count=1,
                    elapsed_ms=50,
                    evidence_ref="receipt:shadow-success",
                )
                self.assertTrue(receipt["shadow_mode"])
                self.assertFalse(receipt["promotion_applied"])

        summary = module.execution_governor_summary(now_unix=now)
        self.assertEqual(summary["authority"], "shadow_evaluation_only")
        self.assertFalse(summary["automatic_live_routing_enabled"])
        self.assertEqual(len(summary["live_promotions"]), 0)
        candidate = summary["candidates"][0]
        self.assertEqual(candidate["status"], "eligible_shadow_candidate")
        self.assertTrue(candidate["promotion_eligible"])
        self.assertFalse(candidate["promotion_applied"])
        self.assertEqual(candidate["rollback_state"], "not_applicable_shadow_only")
        self.assertRegex(summary["summary_sha256"], r"^[0-9a-f]{64}$")

    def test_circuit_breaker_disables_regressing_candidate(self) -> None:
        module = self._load_module()
        now = 1_783_773_600
        with patch.object(module.time, "time", return_value=now):
            for index in range(module.EXECUTION_GOVERNOR_MIN_EVIDENCE):
                module.record_execution_outcome(
                    recommendation_id="b" * 64,
                    operation_class="mutation",
                    risk_level="medium",
                    recommended_route="grip",
                    actual_route="grip",
                    first_pass_success=index > 1,
                    unchanged_retries=1 if index < 2 else 0,
                    ambiguous_mutation_outcomes=1 if index == 0 else 0,
                    tool_call_count=2,
                    elapsed_ms=100,
                    evidence_ref="receipt:shadow-regression",
                    regression_signal=index < 2,
                )

        candidate = module.execution_governor_summary(now_unix=now)["candidates"][0]
        self.assertTrue(candidate["circuit_breaker_open"])
        self.assertEqual(candidate["status"], "disabled_by_circuit_breaker")
        self.assertFalse(candidate["promotion_eligible"])
        self.assertFalse(candidate["promotion_applied"])

    def test_time_decay_and_high_risk_exclusion_are_explicit(self) -> None:
        module = self._load_module()
        now = 1_783_773_600
        old = now - module.EXECUTION_GOVERNOR_DECAY_SECONDS - 1
        module.EXECUTION_OUTCOME_LOG.parent.mkdir(parents=True, exist_ok=True)

        def record(
            *, outcome_id: str, recorded_at: int, operation: str, risk: str, route: str
        ):
            return {
                "schema_version": 1,
                "outcome_id": outcome_id,
                "recorded_at_unix": recorded_at,
                "recommendation_id": "d" * 64,
                "operation_class": operation,
                "risk_level": risk,
                "recommended_route": route,
                "actual_route": route,
                "first_pass_success": True,
                "unchanged_retries": 0,
                "ambiguous_mutation_outcomes": 0,
                "tool_call_count": 1,
                "elapsed_ms": 1,
                "regression_signal": False,
                "friction_event_ids": [],
                "evidence_ref": "receipt:manual-fixture",
            }

        records = [
            record(
                outcome_id="0" * 32,
                recorded_at=old,
                operation="read",
                risk="low",
                route="typed_tool",
            )
        ]
        records.extend(
            record(
                outcome_id=f"{index + 1:032x}",
                recorded_at=now,
                operation="high_impact",
                risk="high",
                route="explicit_preflight",
            )
            for index in range(module.EXECUTION_GOVERNOR_MIN_EVIDENCE)
        )
        module.EXECUTION_OUTCOME_LOG.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in records),
            encoding="utf-8",
        )
        module.EXECUTION_OUTCOME_LOG.chmod(0o600)
        summary = module.execution_governor_summary(now_unix=now)
        self.assertTrue(summary["ledger_integrity_valid"])
        self.assertEqual(summary["expired_by_decay"], 1)
        self.assertEqual(summary["future_dated"], 0)
        candidate = summary["candidates"][0]
        self.assertEqual(candidate["status"], "excluded_high_risk")
        self.assertFalse(candidate["promotion_eligible"])
        self.assertIn("live_routing_promotion", summary["does_not_establish"])
        self.assertIn(
            "caller_supplied_outcome_correctness", summary["does_not_establish"]
        )

    def test_unrelated_historical_transport_does_not_force_every_read_to_split(
        self,
    ) -> None:
        module = self._load_module()
        self._write_events(
            module,
            [
                {
                    "event_id": f"transport-{index}",
                    "kind": "connector_transport",
                    "surface": "connector",
                    "operation": "old unrelated call",
                    "symptom": "502 upstream error",
                    "resolved": False,
                }
                for index in range(3)
            ],
        )
        result = self._recommend(module, prior_failure_class="unknown")
        self.assertEqual(result["recommended_route"], "typed_tool")
        self.assertTrue(result["action_shape"]["batch_reads"])
        self.assertNotIn(
            "recurring_connector_transport_evidence", result["reason_codes"]
        )
        self.assertFalse(result["execution_authorized"])

    def test_parallel_outcome_appends_remain_unique_and_parseable(self) -> None:
        module = self._load_module()
        now = 1_783_773_600

        def append(index: int):
            return module.record_execution_outcome(
                recommendation_id=f"{index + 1:064x}",
                operation_class="read",
                risk_level="low",
                recommended_route="typed_tool",
                actual_route="typed_tool",
                first_pass_success=True,
                unchanged_retries=0,
                ambiguous_mutation_outcomes=0,
                tool_call_count=1,
                elapsed_ms=index,
                evidence_ref=f"receipt:parallel-{index}",
            )

        with patch.object(module.time, "time", return_value=now):
            with ThreadPoolExecutor(max_workers=8) as executor:
                receipts = list(executor.map(append, range(20)))
        self.assertEqual(len({item["outcome_id"] for item in receipts}), 20)
        summary = module.execution_governor_summary(now_unix=now)
        self.assertTrue(summary["ledger_integrity_valid"])
        self.assertEqual(summary["returned"], 20)
        self.assertEqual(summary["invalid_lines"], 0)
        self.assertEqual(summary["duplicate_outcome_ids"], [])

    def test_outcome_timestamp_is_captured_after_append_lock(self) -> None:
        module = self._load_module()
        before_lock = 1_783_773_500
        after_lock = 1_783_773_600
        clock = Mock(return_value=before_lock)

        @contextmanager
        def delayed_lock(*, exclusive: bool):
            self.assertTrue(exclusive)
            clock.return_value = after_lock
            yield

        with patch.object(module, "_execution_outcome_log_lock", delayed_lock):
            with patch.object(module.time, "time", clock):
                module.record_execution_outcome(
                    recommendation_id="9" * 64,
                    operation_class="read",
                    risk_level="low",
                    recommended_route="typed_tool",
                    actual_route="typed_tool",
                    first_pass_success=True,
                    unchanged_retries=0,
                    ambiguous_mutation_outcomes=0,
                    tool_call_count=1,
                    elapsed_ms=1,
                    evidence_ref="receipt:post-lock-timestamp",
                )

        record = json.loads(module.EXECUTION_OUTCOME_LOG.read_text(encoding="utf-8"))
        self.assertEqual(record["recorded_at_unix"], after_lock)

    def test_integrity_scan_covers_lines_older_than_summary_window(self) -> None:
        module = self._load_module()
        now = 1_783_773_600

        def record(*, outcome_id: str, recommendation_id: str) -> dict[str, object]:
            return {
                "schema_version": 1,
                "outcome_id": outcome_id,
                "recorded_at_unix": now,
                "recommendation_id": recommendation_id,
                "operation_class": "read",
                "risk_level": "low",
                "recommended_route": "typed_tool",
                "actual_route": "typed_tool",
                "first_pass_success": True,
                "unchanged_retries": 0,
                "ambiguous_mutation_outcomes": 0,
                "tool_call_count": 1,
                "elapsed_ms": 1,
                "regression_signal": False,
                "friction_event_ids": [],
                "evidence_ref": "receipt:full-ledger-integrity",
            }

        duplicate = record(outcome_id="1" * 32, recommendation_id="a" * 64)
        recent = record(outcome_id="2" * 32, recommendation_id="b" * 64)
        module.EXECUTION_OUTCOME_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.EXECUTION_OUTCOME_LOG.write_text(
            "not-json\n"
            + json.dumps(duplicate, sort_keys=True)
            + "\n"
            + json.dumps(duplicate, sort_keys=True)
            + "\n"
            + json.dumps(recent, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        module.EXECUTION_OUTCOME_LOG.chmod(0o600)

        summary = module.execution_governor_summary(limit=1, now_unix=now)
        self.assertEqual(summary["returned"], 1)
        self.assertEqual(summary["valid_records_total"], 3)
        self.assertEqual(summary["scanned_lines"], 4)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["duplicate_outcome_ids"], ["1" * 32])
        self.assertFalse(summary["ledger_integrity_valid"])
        candidate = summary["candidates"][0]
        self.assertEqual(candidate["status"], "disabled_by_integrity_gate")
        self.assertTrue(candidate["circuit_breaker_open"])
        self.assertFalse(candidate["promotion_eligible"])

    def test_future_dated_record_outside_summary_window_opens_integrity_gate(
        self,
    ) -> None:
        module = self._load_module()
        now = 1_783_773_600

        def record(*, outcome_id: str, recorded_at: int) -> dict[str, object]:
            return {
                "schema_version": 1,
                "outcome_id": outcome_id,
                "recorded_at_unix": recorded_at,
                "recommendation_id": "a" * 64,
                "operation_class": "read",
                "risk_level": "low",
                "recommended_route": "typed_tool",
                "actual_route": "typed_tool",
                "first_pass_success": True,
                "unchanged_retries": 0,
                "ambiguous_mutation_outcomes": 0,
                "tool_call_count": 1,
                "elapsed_ms": 1,
                "regression_signal": False,
                "friction_event_ids": [],
                "evidence_ref": "receipt:future-date-integrity",
            }

        future = record(outcome_id="1" * 32, recorded_at=now + 61)
        recent = record(outcome_id="2" * 32, recorded_at=now)
        module.EXECUTION_OUTCOME_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.EXECUTION_OUTCOME_LOG.write_text(
            json.dumps(future, sort_keys=True)
            + "\n"
            + json.dumps(recent, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        module.EXECUTION_OUTCOME_LOG.chmod(0o600)

        summary = module.execution_governor_summary(limit=1, now_unix=now)
        self.assertEqual(summary["returned"], 1)
        self.assertEqual(summary["future_dated"], 1)
        self.assertFalse(summary["ledger_integrity_valid"])
        candidate = summary["candidates"][0]
        self.assertEqual(candidate["status"], "disabled_by_integrity_gate")
        self.assertTrue(candidate["circuit_breaker_open"])
        self.assertFalse(candidate["promotion_eligible"])
        with patch.object(module.time, "time", return_value=now):
            with self.assertRaisesRegex(RuntimeError, "integrity"):
                module.record_execution_outcome(
                    recommendation_id="b" * 64,
                    operation_class="read",
                    risk_level="low",
                    recommended_route="typed_tool",
                    actual_route="typed_tool",
                    first_pass_success=True,
                    unchanged_retries=0,
                    ambiguous_mutation_outcomes=0,
                    tool_call_count=1,
                    elapsed_ms=1,
                    evidence_ref="receipt:blocked-future-date-append",
                )

    def test_invalid_or_duplicate_outcome_ledger_opens_integrity_gate(self) -> None:
        module = self._load_module()
        now = 1_783_773_600
        valid = {
            "schema_version": 1,
            "outcome_id": "1" * 32,
            "recorded_at_unix": now,
            "recommendation_id": "e" * 64,
            "operation_class": "read",
            "risk_level": "low",
            "recommended_route": "typed_tool",
            "actual_route": "typed_tool",
            "first_pass_success": True,
            "unchanged_retries": 0,
            "ambiguous_mutation_outcomes": 0,
            "tool_call_count": 1,
            "elapsed_ms": 1,
            "regression_signal": False,
            "friction_event_ids": [],
            "evidence_ref": "receipt:integrity-fixture",
        }
        module.EXECUTION_OUTCOME_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.EXECUTION_OUTCOME_LOG.write_text(
            json.dumps(valid, sort_keys=True)
            + "\n"
            + json.dumps(valid, sort_keys=True)
            + "\n"
            + "not-json\n",
            encoding="utf-8",
        )
        module.EXECUTION_OUTCOME_LOG.chmod(0o600)
        summary = module.execution_governor_summary(now_unix=now)
        self.assertFalse(summary["ledger_integrity_valid"])
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["duplicate_outcome_ids"], ["1" * 32])
        candidate = summary["candidates"][0]
        self.assertTrue(candidate["circuit_breaker_open"])
        self.assertEqual(candidate["status"], "disabled_by_integrity_gate")
        self.assertFalse(candidate["promotion_eligible"])
        with self.assertRaisesRegex(RuntimeError, "integrity"):
            module.record_execution_outcome(
                recommendation_id="f" * 64,
                operation_class="read",
                risk_level="low",
                recommended_route="typed_tool",
                actual_route="typed_tool",
                first_pass_success=True,
                unchanged_retries=0,
                ambiguous_mutation_outcomes=0,
                tool_call_count=1,
                elapsed_ms=1,
                evidence_ref="receipt:blocked-append",
            )

    def test_outcome_schema_is_strict_and_evidence_bound(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/execution-governor-outcome.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertIn("evidence_ref", schema["required"])
        self.assertEqual(schema["properties"]["friction_event_ids"]["maxItems"], 20)
        self.assertEqual(
            schema["properties"]["recommendation_id"]["pattern"], "^[0-9a-f]{64}$"
        )

    def test_outcome_record_rejects_unbounded_or_invalid_values(self) -> None:
        module = self._load_module()
        with self.assertRaisesRegex(ValueError, "recommendation_id"):
            module.record_execution_outcome(
                recommendation_id="not-a-digest",
                operation_class="read",
                risk_level="low",
                recommended_route="typed_tool",
                actual_route="typed_tool",
                first_pass_success=True,
                unchanged_retries=0,
                ambiguous_mutation_outcomes=0,
                tool_call_count=1,
                elapsed_ms=1,
                evidence_ref="receipt:invalid-digest",
            )
        with self.assertRaisesRegex(ValueError, "friction_event_ids"):
            module.record_execution_outcome(
                recommendation_id="c" * 64,
                operation_class="read",
                risk_level="low",
                recommended_route="typed_tool",
                actual_route="typed_tool",
                first_pass_success=True,
                unchanged_retries=0,
                ambiguous_mutation_outcomes=0,
                tool_call_count=1,
                elapsed_ms=1,
                evidence_ref="receipt:too-many-events",
                friction_event_ids=[f"event-{index}" for index in range(21)],
            )


if __name__ == "__main__":
    unittest.main()

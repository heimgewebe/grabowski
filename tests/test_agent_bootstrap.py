from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class AgentBootstrapTests(unittest.TestCase):
    def load_module(self):
        spec = importlib.util.spec_from_file_location(
            f"_agent_bootstrap_{id(self)}", ROOT / "src/grabowski_agent_bootstrap.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_call_shape_allows_one_bounded_read(self) -> None:
        module = self.load_module()
        result = module.call_shape_check(
            intent_count=1,
            command_count=1,
            expected_output_bytes=4096,
            may_mutate=False,
            transport_sensitive=False,
            typed_tool_available=True,
            post_state_read_available=True,
        )
        self.assertTrue(result["allowed_shape"])
        self.assertEqual(result["recommendation"], "proceed_bounded")
        self.assertNotIn("execution_authorized", result)
        self.assertIn("permission_to_execute", result["does_not_establish"])

    def test_call_shape_rejects_collection_action(self) -> None:
        module = self.load_module()
        result = module.call_shape_check(
            intent_count=3,
            command_count=4,
            expected_output_bytes=200000,
            may_mutate=True,
            transport_sensitive=True,
            typed_tool_available=True,
            post_state_read_available=False,
        )
        self.assertFalse(result["allowed_shape"])
        self.assertEqual(result["recommendation"], "split_before_execution")
        self.assertIn("multiple_or_missing_independent_intents", result["findings"])
        self.assertIn("mutation_must_be_isolated", result["findings"])
        self.assertIn("mutation_requires_post_state_readback", result["findings"])
        self.assertEqual(result["retry_limit_after_operator_stop"], 0)

    def test_call_shape_is_deterministic(self) -> None:
        module = self.load_module()
        kwargs = dict(
            intent_count=1,
            command_count=1,
            expected_output_bytes=100,
            may_mutate=True,
            transport_sensitive=False,
            typed_tool_available=True,
            post_state_read_available=True,
        )
        self.assertEqual(
            module.call_shape_check(**kwargs)["shape_sha256"],
            module.call_shape_check(**kwargs)["shape_sha256"],
        )

    def test_bootstrap_defers_workspace_metrics_from_synchronous_entry(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }

        first = module._workspace_metrics_snapshot(50)
        second = module._workspace_metrics_snapshot(50)
        adaptive = module.agent_bootstrap()["adaptive_evidence"]

        self.assertEqual(first, second)
        self.assertEqual(first["report_kind"], "workspace_metrics_snapshot_deferred")
        self.assertEqual(
            first["collection_mode"],
            "deferred_to_dedicated_workspace_observer",
        )
        self.assertFalse(first["integrity_valid"])
        self.assertIsNone(first["friction_fingerprint_sha256"])
        self.assertEqual(first["current_cohort_sample_size"], 0)
        self.assertEqual(first["requested_limit"], 50)
        self.assertEqual(
            first["recommended_tool"],
            "grabowski_agent_workspace_optimize",
        )
        self.assertNotIn("execution_authorized", first)
        self.assertIn("permission_to_execute", first["does_not_establish"])
        self.assertEqual(
            adaptive["workspace_fingerprint_unavailable_reason"],
            "workspace_metrics_deferred_from_synchronous_bootstrap",
        )
        self.assertEqual(
            adaptive["workspace_metrics_report_kind"],
            "workspace_metrics_snapshot_deferred",
        )
        self.assertEqual(
            adaptive["workspace_metrics_collection_mode"],
            "deferred_to_dedicated_workspace_observer",
        )
        self.assertEqual(
            adaptive["workspace_metrics_recommended_tool"],
            "grabowski_agent_workspace_optimize",
        )
        with self.assertRaisesRegex(ValueError, "integer"):
            module._workspace_metrics_snapshot(True)
        for invalid_limit in (0, 51):
            with self.subTest(invalid_limit=invalid_limit):
                with self.assertRaisesRegex(ValueError, "between 1 and 50"):
                    module._workspace_metrics_snapshot(invalid_limit)

    def test_bootstrap_fail_closed_on_invalid_governor_integrity(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module._workspace_metrics_snapshot = lambda _limit: {
            "integrity_valid": True,
            "friction_fingerprint_sha256": "c" * 64,
            "snapshot_sha256": "d" * 64,
            "current_cohort": {"cohort_key": "release:test"},
            "current_cohort_sample_size": 3,
            "friction_fingerprint_unavailable_reason": None,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": False,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        result = module.agent_bootstrap()
        self.assertEqual(result["adaptive_mode"], "disabled_fail_closed")
        self.assertNotIn("execution_authorized", result)
        self.assertIn("execution_authority", result["does_not_establish"])
        self.assertFalse(result["automatic_live_routing_enabled"])

    def test_bootstrap_uses_current_workspace_cohort_fingerprint_when_generic_is_absent(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": None,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        module._workspace_metrics_snapshot = lambda _limit: {
            "integrity_valid": True,
            "friction_fingerprint_sha256": "c" * 64,
            "snapshot_sha256": "d" * 64,
            "current_cohort": {"cohort_key": "release:test"},
            "current_cohort_sample_size": 5,
            "friction_fingerprint_unavailable_reason": None,
        }
        result = module.agent_bootstrap()
        adaptive = result["adaptive_evidence"]
        self.assertEqual(adaptive["friction_fingerprint_sha256"], "c" * 64)
        self.assertEqual(adaptive["workspace_friction_fingerprint_sha256"], "c" * 64)
        self.assertEqual(adaptive["workspace_current_cohort_sample_size"], 5)
        self.assertEqual(result["learning_contract"]["workspace_route_calibration_mode"], "shadow_only")
        self.assertFalse(result["automatic_live_routing_enabled"])

    def test_bootstrap_rejects_workspace_fingerprint_when_snapshot_integrity_is_invalid(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": None,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        module._workspace_metrics_snapshot = lambda _limit: {
            "integrity_valid": False,
            "friction_fingerprint_sha256": "c" * 64,
            "snapshot_sha256": "d" * 64,
            "current_cohort": {"cohort_key": "release:test"},
            "current_cohort_sample_size": 5,
            "friction_fingerprint_unavailable_reason": None,
        }
        adaptive = module.agent_bootstrap()["adaptive_evidence"]
        self.assertIsNone(adaptive["friction_fingerprint_sha256"])
        self.assertIsNone(adaptive["workspace_friction_fingerprint_sha256"])
        self.assertFalse(adaptive["workspace_metrics_integrity_valid"])
        self.assertEqual(
            adaptive["workspace_fingerprint_unavailable_reason"],
            "workspace_metrics_integrity_invalid",
        )

    def test_bootstrap_preserves_immutable_boundaries(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module._workspace_metrics_snapshot = lambda _limit: {
            "integrity_valid": True,
            "friction_fingerprint_sha256": "c" * 64,
            "snapshot_sha256": "d" * 64,
            "current_cohort": {"cohort_key": "release:test"},
            "current_cohort_sample_size": 5,
            "friction_fingerprint_unavailable_reason": None,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [{"circuit_breaker_open": False}],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        result = module.agent_bootstrap()
        self.assertEqual(result["adaptive_mode"], "shadow")
        self.assertIn("authorization", result["immutable_boundaries"])
        self.assertIn("resource_leases", result["immutable_boundaries"])
        self.assertTrue(result["call_rules"]["one_independent_intent_per_call"])
        self.assertFalse(result["call_rules"]["unchanged_mutation_retry_allowed"])
        self.assertFalse(result["call_rules"]["generic_sync_shell_composition_allowed"])
        self.assertFalse(result["call_rules"]["generic_sync_known_wrapper_execution_allowed"])
        self.assertFalse(
            result["call_rules"]["generic_sync_indirect_execution_detection_complete"]
        )
        self.assertEqual(
            result["enforced_runtime_boundaries"]["known_wrapper_execution"],
            "deny_before_process_start",
        )
        self.assertEqual(
            result["enforced_runtime_boundaries"]["arbitrary_indirect_execution"],
            "not_claimed_detectable",
        )
        self.assertEqual(result["call_rules"]["generic_sync_timeout_ceiling_seconds"], 30)
        self.assertEqual(result["call_rules"]["generic_sync_output_ceiling_bytes"], 64 * 1024)
        self.assertFalse(result["call_rules"]["client_selected_sync_timeout_allowed"])
        self.assertFalse(result["call_rules"]["client_selected_sync_output_limit_allowed"])
        self.assertEqual(result["enforced_runtime_boundaries"]["limits_owned_by"], "server")
        self.assertEqual(
            result["enforced_runtime_boundaries"]["long_running_required_route"],
            "durable_task",
        )
        self.assertTrue(
            result["enforced_runtime_boundaries"]["internal_server_timeouts_retained"]
        )


    def test_bootstrap_selectively_consumes_historical_recall_before_execution_shape(self) -> None:
        module = self.load_module()
        history_step = "read_relevant_historical_recall_when_high_value_or_repeat_signal"
        self.assertIn(history_step, module.ENTRY_SEQUENCE)
        self.assertLess(
            module.ENTRY_SEQUENCE.index("discover_existing_capability_or_route"),
            module.ENTRY_SEQUENCE.index(history_step),
        )
        self.assertLess(
            module.ENTRY_SEQUENCE.index(history_step),
            module.ENTRY_SEQUENCE.index(
                "request_execution_shape_for_nontrivial_or_mutating_work"
            ),
        )

        policy = module.HISTORICAL_RECALL
        self.assertEqual(policy["tool"], "grabowski_operator_historical_recall")
        self.assertEqual(policy["exact_search_tool"], "grabowski_chronik_full_search")
        self.assertEqual(
            policy["exact_search_selectors"],
            ["pr_number", "bureau_task_id", "run_id", "task_id", "event_id"],
        )
        order = policy["selection_order"]
        self.assertLess(
            order.index("prefer_full_search_for_exact_or_cross_project_history"),
            order.index("use_bounded_historical_recall_only_for_pattern_summaries"),
        )
        self.assertIn(
            "filter_host_scoped_project_events_by_subject_component_not_source_repo",
            order,
        )
        self.assertIn("check_exhaustive_integrity_before_concluding_no_record", order)
        self.assertIn(
            "full_search_cursors_are_bound_to_snapshot_and_must_restart_when_stale",
            policy["requirements"],
        )
        self.assertIn(
            "missing_record_is_not_evidence_that_work_never_occurred",
            policy["requirements"],
        )
        self.assertEqual(policy["mode"], "target_first_fail_open_then_selective_patterns")
        self.assertIn("service_status", policy["trigger_profiles"])
        self.assertIn("recovery", policy["trigger_signals"])
        self.assertIn("repeated_failure", policy["trigger_signals"])
        self.assertIn("unbound_nonproject_task", policy["skip_for"])
        self.assertNotIn("status_only_without_repeat_signal", policy["skip_for"])
        self.assertIn("fresh_live_truth_precedes_every_effect", policy["requirements"])
        self.assertIn(
            "fresh_owning_authority_must_be_rechecked_before_effect",
            policy["requirements"],
        )
        self.assertEqual(
            policy["does_not_establish"],
            [
                "current_truth",
                "safe_retry",
                "routing_authority",
                "policy_authority",
                "merge_readiness",
                "deployment_authorization",
                "bureau_publication_authority",
                "task_completion",
            ],
        )

        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        capsule = module.agent_bootstrap()
        self.assertEqual(capsule["historical_recall"], policy)


    def test_reuse_before_build_orders_discovery_before_new_infrastructure(self) -> None:
        module = self.load_module()
        self.assertEqual(
            module.ENTRY_SEQUENCE[4],
            "discover_existing_capability_or_route",
        )
        policy = module.REUSE_BEFORE_BUILD
        self.assertEqual(
            policy["ordered_discovery"],
            [
                "native_typed_surface",
                "host_capability_locator_if_host_local_and_no_native_surface",
                "declared_specialized_route_if_non_host_or_host_not_found",
                "live_readiness_of_selected_authority",
            ],
        )
        self.assertEqual(
            policy["host_capability_tool"],
            "grabowski_host_capability_resolve",
        )
        self.assertEqual(
            policy["new_infrastructure_gate"],
            "only_when_no_existing_authority_or_declared_route_is_found",
        )
        self.assertIn("not_ready_is_not_not_found", policy["invariants"])
        self.assertIn(
            "not_ready_requires_existing_authority_recovery_not_parallel_replacement",
            policy["invariants"],
        )
        self.assertIn(
            "host_capability_blocked_stops_host_local_discovery",
            policy["invariants"],
        )
        self.assertIn(
            "non_host_intent_does_not_require_host_contract",
            policy["invariants"],
        )
        self.assertIn(
            "do_not_duplicate_existing_control_plane",
            policy["invariants"],
        )
        self.assertIn("virtualenv", policy["creation_triggers"])
        self.assertIn("worker", policy["creation_triggers"])
        self.assertIn("cloud_fallback", policy["creation_triggers"])

        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        capsule = module.agent_bootstrap()
        self.assertEqual(capsule["reuse_before_build"], policy)
        self.assertTrue(
            capsule["call_rules"][
                "reuse_existing_capability_before_new_infrastructure"
            ]
        )


    def test_adler_sidecar_contract_is_advisory_and_fail_open_for_local_work(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        capsule = module.agent_bootstrap()
        contract = capsule["adler_sidecar"]
        self.assertEqual(contract["path"], ".adler/inbox.json")
        self.assertEqual(contract["on_lane_entry"], "read_if_present")
        self.assertEqual(contract["before_commit"], "reread_if_present")
        self.assertEqual(contract["absence_semantics"], "unknown_not_no_findings")
        self.assertEqual(contract["failure_semantics"], "local_reversible_work_may_continue")
        self.assertIn("read_adler_inbox_if_present", module.ENTRY_SEQUENCE)
        self.assertIn("blocking_authority", contract["does_not_establish"])

    def test_chronik_first_returns_historical_receipt_for_exact_repository(self) -> None:
        module = self.load_module()
        calls = []
        def search(**kwargs):
            calls.append(kwargs)
            return {
                "available": True, "historical_only": True,
                "search_exhaustive": True, "matching_count": 1, "has_more": False,
                "result_sha256": "d" * 64,
                "ledger_snapshot": {
                    "integrity_valid": True, "invalid_record_count": 0,
                    "sha256": "c" * 64,
                },
                "events": [{
                    "event_ref": "chronik:agent.ledger:sha256:" + "a" * 64,
                    "canonical_event_sha256": "b" * 64,
                    "event": {
                        "ts": "2026-11-07T12:00:00Z", "kind": "agent.run.failed",
                        "data": {"result": "failed", "operation": "review", "task_class": "review"},
                        "source": {"run_id": "task-123"},
                        "subject": {"scope": "repository", "repo": "heimgewebe/grabowski"},
                        "evidence_refs": ["grabowski-task:123"],
                        "private_payload": "MUST_NOT_LEAK",
                    },
                }],
            }
        context = module._chronik_first_context(
            repo="heimgewebe/grabowski", search_fn=search,
        )
        self.assertEqual(calls, [{"repo": "heimgewebe/grabowski", "limit": 10}])
        self.assertEqual(context["status"], "available")
        self.assertEqual(context["events"][0]["outcome"], "failed")
        self.assertNotIn("private_payload", str(context))
        self.assertNotIn("MUST_NOT_LEAK", str(context))
        self.assertEqual(context["snapshot_sha256"], "c" * 64)
        self.assertTrue(context["historical_only"])
        self.assertEqual(context["matching_count"], 1)
        self.assertTrue(context["selection_complete"])
        self.assertIsNone(context["context_gap"])

    def test_chronik_first_supports_host_component_and_exact_pr(self) -> None:
        module = self.load_module()
        calls = []
        def search(**kwargs):
            calls.append(kwargs)
            return {
                "available": True, "historical_only": True,
                "search_exhaustive": True, "matching_count": 0,
                "has_more": False, "events": [],
                "ledger_snapshot": {"integrity_valid": True, "invalid_record_count": 0},
            }
        host = module._chronik_first_context(
            host="heim-pc", subject_component="rustdesk", search_fn=search,
        )
        pr = module._chronik_first_context(
            repo="heimgewebe/grabowski", pr_number=1724, search_fn=search,
        )
        self.assertEqual(host["status"], "available")
        self.assertEqual(pr["status"], "available")
        self.assertEqual(calls[0], {"host": "heim-pc", "subject_component": "rustdesk", "limit": 10})
        self.assertEqual(calls[1], {"repo": "heimgewebe/grabowski", "pr_number": 1724, "limit": 10})

    def test_chronik_first_skips_unbound_nonproject_work(self) -> None:
        module = self.load_module()
        def no_search(**kwargs):
            self.fail("unbound target triggered Chronik")
        result = module._chronik_first_context(search_fn=no_search)
        self.assertEqual(result["status"], "skipped_unbound_target")
        self.assertEqual(result["events"], [])

    def test_chronik_first_rejects_producer_repo_as_subject(self) -> None:
        module = self.load_module()
        def search(**kwargs):
            return {
                "available": True, "historical_only": True,
                "search_exhaustive": True, "matching_count": 55112,
                "has_more": True,
                "ledger_snapshot": {"integrity_valid": True, "invalid_record_count": 0},
                "events": [{"event": {
                    "source": {"repo": "heimgewebe/grabowski"},
                    "subject": subject,
                }} for subject in (
                    {"scope": "host", "host": "heim-pc"},
                    {"scope": "repository", "repo": "heimgewebe/other"},
                    {},
                )],
            }
        context = module._chronik_first_context(repo="heimgewebe/grabowski", search_fn=search)
        self.assertEqual(context["events"], [])
        self.assertEqual(context["discarded_source_only_matches"], 3)
        self.assertIsNone(context["matching_count"])
        self.assertEqual(context["provider_matching_count"], 55112)
        self.assertFalse(context["selection_complete"])
        self.assertEqual(context["context_gap"], "bounded_candidate_page_only")

    def test_chronik_first_incident_continuation_uses_exact_task(self) -> None:
        module = self.load_module()
        calls = []
        def search(**kwargs):
            calls.append(kwargs)
            return {
                "available": True, "historical_only": True,
                "search_exhaustive": True, "matching_count": 1, "has_more": False,
                "ledger_snapshot": {"integrity_valid": True, "invalid_record_count": 0},
                "events": [{"event_ref": "chronik:agent.ledger:incident",
                            "canonical_event_sha256": "b" * 64,
                            "event": {"data": {"operation": "diagnose", "result": "failed"}}}],
            }
        context = module._chronik_first_context(task_id="a" * 24, search_fn=search)
        self.assertEqual(calls, [{"task_id": "a" * 24, "limit": 10}])
        self.assertEqual(context["status"], "available")
        self.assertEqual(context["events"][0]["outcome"], "failed")

    def test_chronik_first_failure_is_nonblocking_and_explicit(self) -> None:
        module = self.load_module()
        def unavailable(**kwargs):
            raise TimeoutError("simulated unavailable Chronik")
        context = module._chronik_first_context(
            repo="heimgewebe/grabowski", search_fn=unavailable,
        )
        self.assertEqual(context["status"], "historical_context_unavailable")
        self.assertEqual(context["failure_code"], "TimeoutError")
        self.assertEqual(context["events"], [])

    def test_chronik_first_invoked_before_live_bootstrap_for_target(self) -> None:
        module = self.load_module()
        self.assertEqual(
            module.ENTRY_SEQUENCE[0],
            "read_chronik_history_for_explicit_target_if_available",
        )
        prior = module._chronik_first_context
        observations = []
        try:
            module._chronik_first_context = lambda **kwargs: (
                observations.append(kwargs) or {"status": "historical_context_unavailable"}
            )
            result = module.agent_bootstrap(repo="heimgewebe/grabowski")
            self.assertEqual(observations[0]["repo"], "heimgewebe/grabowski")
            self.assertEqual(result["chronik_first"]["status"], "historical_context_unavailable")
        finally:
            module._chronik_first_context = prior


if __name__ == "__main__":
    unittest.main()

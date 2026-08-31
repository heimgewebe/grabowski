from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_operator_optimization as optimization


REPOSITORY = "/home/alex/repos/grabowski"


def health_provider() -> dict:
    return {
        "healthy": True,
        "release_id": "release-1",
        "repo_head": "a" * 40,
    }


def audit_provider(**_kwargs) -> dict:
    return {
        "projection_sha256": "audit-projection-sha",
        "findings_sha256": "audit-findings-sha",
        "source_binding": {
            "record_count": 50_000,
            "last_record_sha256": "b" * 64,
        },
        "windows": [
            {
                "label": "24h",
                "record_count": 3_000,
                "failure_signal_count": 120,
                "task_activity": {"task-start": 900, "task-cancel": 20},
                "resource_activity": {
                    "resource-acquire": 250,
                    "resource-release": 150,
                    "resource_reclamation_event_count": 20,
                    "reclaimed_resource_count": 35,
                },
                "bureau_activity": {
                    "bureau-candidate-record": 250,
                    "bureau-task-propose": 40,
                    "bureau-task-publish": 10,
                },
            },
            {
                "label": "7d",
                "record_count": 21_000,
                "failure_signal_count": 700,
                "task_activity": {"task-start": 10_000, "task-cancel": 160},
                "resource_activity": {
                    "resource-acquire": 3_000,
                    "resource-release": 1_000,
                    "resource_reclamation_event_count": 280,
                    "reclaimed_resource_count": 500,
                },
                "bureau_activity": {
                    "bureau-candidate-record": 1_000,
                    "bureau-task-propose": 390,
                    "bureau-task-publish": 130,
                },
            },
            {
                "label": "30d",
                "record_count": 48_000,
                "failure_signal_count": 900,
                "task_activity": {"task-start": 21_000, "task-cancel": 300},
                "resource_activity": {
                    "resource-acquire": 7_000,
                    "resource-release": 2_500,
                    "resource_reclamation_event_count": 530,
                    "reclaimed_resource_count": 960,
                },
                "bureau_activity": {
                    "bureau-candidate-record": 1_300,
                    "bureau-task-propose": 520,
                    "bureau-task-publish": 180,
                },
            },
        ],
        "candidate_patterns": [
            {
                "pattern": "repeated_bureau_contract_failures",
                "count_7d": 483,
            },
            {
                "pattern": "repeated_resource_reclamation",
                "event_count_7d": 288,
                "reclaimed_resource_count_7d": 513,
            },
        ],
        "signal_projection": {
            "signals": [
                {
                    "id": "uncertain_outcome",
                    "status": "observed",
                    "severity": "critical",
                    "count": 2,
                    "evidence_refs": ["audit-record-sha256:uncertain"],
                    "recommended_action": "read the exact target state and recovery evidence before any retry",
                    "does_not_establish": [
                        "mutation_failure",
                        "safe_retry",
                        "root_cause",
                    ],
                },
                {
                    "id": "contract_contradiction",
                    "status": "clear",
                    "severity": "none",
                    "count": 0,
                    "evidence_refs": [],
                    "recommended_action": "none",
                    "does_not_establish": ["root_cause"],
                },
                {
                    "id": "transition_gap",
                    "status": "observed",
                    "severity": "high",
                    "count": 1,
                    "evidence_refs": ["audit-record-sha256:transition"],
                    "recommended_action": "trace each unmatched intent and read the exact target state before retry",
                    "does_not_establish": [
                        "effect_absence_outside_the_audit_chain",
                        "causality",
                        "safe_retry",
                    ],
                },
                {
                    "id": "repeated_blockade",
                    "status": "observed",
                    "severity": "medium",
                    "count": 28,
                    "evidence_refs": ["friction-event:blockade"],
                },
                {
                    "id": "stale_attention",
                    "status": "observed",
                    "severity": "medium",
                    "count": 5,
                    "evidence_refs": ["friction-event:stale"],
                },
            ]
        },
    }


def friction_provider(**_kwargs) -> dict:
    return {
        "event_log_integrity": {"integrity_valid": True},
        "decision_log": {"integrity_valid": True},
        "failure_classification": {"decision_required_count": 83},
        "pagination": {"snapshot_sha256": "friction-snapshot-sha"},
    }


def outcome_provider(**_kwargs) -> dict:
    return {
        "summary_sha256": "outcome-summary-sha",
        "ledger_integrity_valid": True,
        "active_after_decay": 0,
        "minimum_evidence": 5,
        "candidates": [],
    }


def current_work_provider(*_args, **_kwargs) -> dict:
    return {
        "snapshot_sha256": "current-work-sha",
        "generated_at_unix": 100,
        "count": 50,
        "total_projected": 198,
        "state_counts": {
            "active": 11,
            "blocking": 177,
            "resumable": 0,
            "terminal_archived": 0,
            "unknown": 10,
        },
        "convergence_summary": {
            "primary_stage": "blocking",
            "blocking_count": 177,
        },
        "scope_contract": {
            "kind": "mixed_global_and_repository_filtered",
            "repository_filters": [REPOSITORY],
            "repository_filtered_sources": [
                "checkouts",
                "checkout_binding_reconciliation",
            ],
            "global_sources": [
                "tasks",
                "attention",
                "resources",
                "browser_workers",
                "gui_workers",
                "tmux",
                "processes",
            ],
            "aggregate_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
            "repository_scoped_aggregates": False,
            "aggregates_depend_on_repository_filters": True,
            "filter_propagation": "repository-filtered checkout evidence may attach to global work groups and change their projected state or action reasons",
            "does_not_establish": [
                "repository-scoped total_projected",
                "repository-scoped state_counts",
                "repository-scoped convergence_summary",
                "repository-filter-invariant aggregate values",
            ],
        },
        "total_projected_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "state_counts_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "convergence_summary_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "source_counts": {"tasks": 2, "worktrees": 185},
        "source_counts_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "unbound_physical_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "recommended_next_action_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "next_convergence_action_scope": "mixed_global_and_repository_filtered_bounded_source_snapshot",
        "scope_notes": ["mixed source scope"],
        "source_truncation": {"attention": True, "tasks": False},
        "source_errors": [],
        "warnings": ["one or more source surfaces were truncated"],
    }


class OperatorOptimizationReportTests(unittest.TestCase):
    def build(self, **kwargs) -> dict:
        return optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            health_provider=health_provider,
            audit_provider=audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=current_work_provider,
            **kwargs,
        )

    def test_report_composes_existing_truth_without_personal_telemetry(self) -> None:
        result = self.build(window="7d")

        finding_ids = {item["id"] for item in result["findings"]}
        self.assertTrue(
            {
                "uncertain_outcome",
                "transition_gap",
                "repeated_bureau_contract_failures",
                "repeated_resource_reclamation",
                "repeated_blockade",
                "stale_attention",
                "friction_decision_backlog",
                "current_work_attention_noise",
            }.issubset(finding_ids)
        )
        self.assertFalse(result["scope"]["personal_activity_observation"])
        self.assertIn("shell_history", result["scope"]["excluded_personal_telemetry"])
        self.assertNotIn("source_evidence", result)
        self.assertEqual(result["authority"], "derived_read_only_advisory")
        self.assertTrue(result["source_health"]["all_sources_available"])
        self.assertFalse(result["source_health"]["bounded_source_set_complete"])
        self.assertFalse(
            any(item.get("code") == "current_work_mixed_scope" for item in result["warnings"])
        )
        self.assertEqual(
            result["scope"]["repositories_apply_to"],
            [
                "current_work.checkouts",
                "current_work.checkout_binding_reconciliation",
            ],
        )
        self.assertFalse(result["scope"]["repository_scoped_findings"])
        self.assertEqual(
            result["scope"]["current_work_scope_contract"]["kind"],
            "mixed_global_and_repository_filtered",
        )
        current_finding = next(
            item for item in result["findings"]
            if item["id"] == "current_work_attention_noise"
        )
        self.assertIn("mixed-scope", current_finding["observation"])
        self.assertIn("Global task", current_finding["alternative_interpretation"])
        self.assertIn("genuinely contain many dirty", current_finding["alternative_interpretation"])
        self.assertIn(
            "repository_specific_blocker_count",
            current_finding["does_not_establish"],
        )
        self.assertIn("operator_productivity", result["does_not_establish"])
        self.assertIn("repository_scoped_findings", result["does_not_establish"])
        self.assertTrue(result["report_sha256"])
        self.assertEqual(result["findings"][0]["id"], "uncertain_outcome")
        self.assertEqual(result["findings"][0]["severity"], "critical")
        self.assertEqual(result["recommendations"][0]["priority"], "critical")
        self.assertEqual(
            result["recommended_next_action"],
            "read the exact target state and recovery evidence before any retry",
        )
        uncertain = next(
            item for item in result["findings"] if item["id"] == "uncertain_outcome"
        )
        self.assertEqual(
            uncertain["evidence_refs"], ["audit-record-sha256:uncertain"]
        )
        self.assertIn("safe_retry", uncertain["does_not_establish"])
        transition = next(
            item for item in result["findings"] if item["id"] == "transition_gap"
        )
        self.assertEqual(transition["severity"], "high")
        self.assertIn("unmatched transition intents", transition["observation"])
        self.assertEqual(
            transition["recommended_action"],
            "trace each unmatched intent and read the exact target state before retry",
        )

    def test_observed_contract_contradiction_becomes_ranked_finding(self) -> None:
        def contradiction_audit_provider(**_kwargs) -> dict:
            payload = audit_provider()
            contradiction = next(
                item
                for item in payload["signal_projection"]["signals"]
                if item["id"] == "contract_contradiction"
            )
            contradiction.update(
                {
                    "status": "observed",
                    "severity": "high",
                    "count": 3,
                    "evidence_refs": ["audit-record-sha256:contradiction"],
                    "recommended_action": "bind both surfaces before repair",
                    "does_not_establish": [
                        "root_cause",
                        "automatic_contract_change_authority",
                    ],
                }
            )
            return payload

        result = optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            health_provider=health_provider,
            audit_provider=contradiction_audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=current_work_provider,
        )
        contradiction = next(
            item
            for item in result["findings"]
            if item["id"] == "contract_contradiction"
        )
        self.assertEqual(contradiction["severity"], "high")
        self.assertEqual(
            contradiction["evidence_refs"],
            ["audit-record-sha256:contradiction"],
        )
        self.assertEqual(
            contradiction["recommended_action"], "bind both surfaces before repair"
        )
        self.assertIn(
            "automatic_contract_change_authority",
            contradiction["does_not_establish"],
        )

    def test_report_uses_bounded_reclamation_and_retryability_attribution(self) -> None:
        def attributed_audit_provider(**_kwargs) -> dict:
            payload = audit_provider()
            patterns = {
                item["pattern"]: item for item in payload["candidate_patterns"]
            }
            patterns["repeated_bureau_contract_failures"].update(
                {
                    "failure_retryable_count_7d": 1,
                    "failure_nonretryable_count_7d": 5,
                    "failure_retryability_unknown_count_7d": 477,
                    "failure_retryability_coverage": round(6 / 483, 6),
                    "failure_identity_complete_count_7d": 120,
                    "failure_identity_partial_count_7d": 5,
                    "failure_identity_unknown_count_7d": 358,
                    "failure_identity_coverage": round(120 / 483, 6),
                    "failure_identity_group_count_7d": 4,
                }
            )
            patterns["repeated_resource_reclamation"].update(
                {
                    "same_owner_reclaimed_resource_count_7d": 39,
                    "foreign_owner_reclaimed_resource_count_7d": 25,
                    "unattributed_reclaimed_resource_count_7d": 449,
                    "reclamation_attribution_coverage": round(64 / 513, 6),
                }
            )
            return payload

        result = optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            health_provider=health_provider,
            audit_provider=attributed_audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=current_work_provider,
        )
        findings = {item["id"]: item for item in result["findings"]}
        bureau = findings["repeated_bureau_contract_failures"]
        self.assertIn("6 of 483", bureau["observation"])
        self.assertIn("120 of 483", bureau["observation"])
        self.assertIn("4 exact identity groups", bureau["observation"])
        self.assertIn("5 are partial", bureau["observation"])
        self.assertIn("358 remain unknown", bureau["observation"])
        self.assertIn("non-retryable", bureau["recommended_action"])
        self.assertIn("shared root cause", bureau["recommended_action"])
        self.assertIn("not causality", bureau["alternative_interpretation"])

        reclamation = findings["repeated_resource_reclamation"]
        self.assertEqual(reclamation["severity"], "low")
        self.assertEqual(
            reclamation["title"], "Resource reclamation attribution is incomplete"
        )
        self.assertIn("39 same-owner", reclamation["observation"])
        self.assertIn("25 foreign-owner", reclamation["observation"])
        self.assertIn("449 remain historical or unattributed", reclamation["observation"])
        self.assertIn("do not change lease duration", reclamation["recommended_action"])

    def test_report_compares_normalized_overlapping_window_rates(self) -> None:
        result = self.build(window="7d")
        comparison = result["measurement"]["comparison"]

        self.assertEqual(comparison["selected_label"], "7d")
        self.assertEqual(comparison["comparison_label"], "30d")
        self.assertGreater(
            comparison["rates"]["failure_signal_rate"]["relative_change"],
            0,
        )
        selected = result["measurement"]["selected_window"]
        self.assertEqual(
            selected["resource_reclamation_events_per_1000_starts"],
            28.0,
        )
        self.assertEqual(
            selected["reclaimed_resources_per_1000_starts"],
            50.0,
        )
        self.assertGreater(
            comparison["rates"]["resource_reclamation_events_per_1000_starts"][
                "relative_change"
            ],
            0,
        )
        self.assertGreater(
            comparison["rates"]["reclaimed_resources_per_1000_starts"][
                "relative_change"
            ],
            0,
        )
        self.assertIn("overlap", comparison["semantics"])

    def test_reclamation_rates_are_unavailable_without_task_starts(self) -> None:
        def no_task_starts_audit_provider(**_kwargs) -> dict:
            payload = audit_provider()
            selected = next(
                item for item in payload["windows"] if item["label"] == "7d"
            )
            selected["task_activity"]["task-start"] = 0
            self.assertGreater(
                selected["resource_activity"]["resource_reclamation_event_count"],
                0,
            )
            return payload

        result = optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            window="7d",
            health_provider=health_provider,
            audit_provider=no_task_starts_audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=current_work_provider,
        )

        selected = result["measurement"]["selected_window"]
        self.assertIsNone(
            selected["resource_reclamation_events_per_1000_starts"]
        )
        self.assertIsNone(selected["reclaimed_resources_per_1000_starts"])
        comparison = result["measurement"]["comparison"]["rates"]
        self.assertIsNone(
            comparison["resource_reclamation_events_per_1000_starts"][
                "selected_minus_comparison"
            ]
        )
        self.assertIsNone(
            comparison["resource_reclamation_events_per_1000_starts"][
                "relative_change"
            ]
        )
        self.assertIsNone(
            comparison["reclaimed_resources_per_1000_starts"][
                "selected_minus_comparison"
            ]
        )
        self.assertIsNone(
            comparison["reclaimed_resources_per_1000_starts"][
                "relative_change"
            ]
        )

    def test_evidence_view_remains_bounded_and_omits_raw_events(self) -> None:
        result = self.build(view="evidence")

        evidence = result["source_evidence"]
        self.assertIn("audit_candidate_patterns", evidence)
        self.assertIn("friction_failure_classification", evidence)
        self.assertNotIn(
            "fresh_execution_outcomes_missing",
            {item["id"] for item in result["findings"]},
        )
        self.assertTrue(result["source_health"]["execution_outcomes_available"])
        self.assertEqual(
            result["source_bindings"]["execution_outcomes"]["summary_sha256"],
            "outcome-summary-sha",
        )
        self.assertIn("execution_governor_candidates", evidence)
        self.assertEqual(
            evidence["current_work_summary"]["scope_contract"]["kind"],
            "mixed_global_and_repository_filtered",
        )
        self.assertEqual(
            result["source_bindings"]["current_work"]["scope_contract"]["kind"],
            "mixed_global_and_repository_filtered",
        )
        self.assertEqual(
            evidence["current_work_summary"]["source_counts_scope"],
            "mixed_global_and_repository_filtered_bounded_source_snapshot",
        )
        self.assertIn("scope_notes", evidence["current_work_summary"])
        self.assertNotIn("events", evidence)
        self.assertNotIn("work", evidence["current_work_summary"])

    def test_legacy_current_work_payload_remains_compatible(self) -> None:
        def legacy_current_work_provider(*_args, **_kwargs) -> dict:
            payload = current_work_provider()
            for key in (
                "scope_contract",
                "total_projected_scope",
                "state_counts_scope",
                "convergence_summary_scope",
                "source_counts_scope",
                "unbound_physical_scope",
                "recommended_next_action_scope",
                "next_convergence_action_scope",
                "scope_notes",
            ):
                payload.pop(key, None)
            return payload

        result = optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            health_provider=health_provider,
            audit_provider=audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=legacy_current_work_provider,
        )
        finding = next(
            item for item in result["findings"]
            if item["id"] == "current_work_attention_noise"
        )
        self.assertNotIn("mixed-scope", finding["observation"])
        self.assertIn("genuinely contain many independent", finding["alternative_interpretation"])
        self.assertIsNone(result["scope"]["current_work_scope_contract"])
        self.assertIn("repository_specific_blocker_count", finding["does_not_establish"])

    def test_scope_notes_do_not_degrade_source_health(self) -> None:
        def complete_current_work_provider(*_args, **_kwargs) -> dict:
            payload = current_work_provider()
            payload["source_truncation"] = {
                key: False for key in payload["source_truncation"]
            }
            payload["source_errors"] = []
            payload["warnings"] = []
            payload["scope_notes"] = ["mixed source scope"]
            return payload

        result = optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            health_provider=health_provider,
            audit_provider=audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=complete_current_work_provider,
        )
        self.assertTrue(result["source_health"]["bounded_source_set_complete"])
        self.assertTrue(result["source_health"]["complete"])

    def test_partial_source_failure_is_explicit_not_false_green(self) -> None:
        def broken_health() -> dict:
            raise RuntimeError("unavailable")

        result = optimization.build_operator_optimization_report(
            [REPOSITORY],
            now_unix=1_785_220_000,
            health_provider=broken_health,
            audit_provider=audit_provider,
            friction_provider=friction_provider,
            outcome_provider=outcome_provider,
            current_work_provider=current_work_provider,
        )

        self.assertFalse(result["source_health"]["runtime_available"])
        self.assertFalse(result["source_health"]["complete"])
        self.assertIn(
            "runtime_health",
            {
                item.get("source")
                for item in result["warnings"]
                if item.get("code") == "source_unavailable"
            },
        )

    def test_hashes_are_deterministic_for_same_bound_sources(self) -> None:
        first = self.build()
        second = self.build()

        self.assertEqual(first["findings_sha256"], second["findings_sha256"])
        self.assertEqual(first["report_sha256"], second["report_sha256"])

    def test_invalid_scope_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            optimization.build_operator_optimization_report([])
        with self.assertRaises(ValueError):
            optimization.build_operator_optimization_report([REPOSITORY, REPOSITORY])
        with self.assertRaises(ValueError):
            self.build(window="90d")
        with self.assertRaises(ValueError):
            self.build(current_work_limit=0)
        with self.assertRaises(ValueError):
            self.build(current_work_limit=51)
        with self.assertRaises(ValueError):
            self.build(friction_limit=101)


if __name__ == "__main__":
    unittest.main()

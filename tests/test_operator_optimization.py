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
        "source_counts": {"tasks": 2, "worktrees": 185},
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
        self.assertIn("operator_productivity", result["does_not_establish"])
        self.assertTrue(result["report_sha256"])

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
        self.assertNotIn("events", evidence)
        self.assertNotIn("work", evidence["current_work_summary"])

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

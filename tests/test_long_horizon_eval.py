from __future__ import annotations

import json
import unittest

from tools import grabowski_long_horizon_eval as evaluator


SCHEMA = evaluator.TRACE_SCHEMA_VERSION


def event(run_id: str, step: int, kind: str, **extra: object) -> str:
    payload = {
        "schema_version": SCHEMA,
        "run_id": run_id,
        "step": step,
        "kind": kind,
        **extra,
    }
    return json.dumps(payload, sort_keys=True)


def evaluate(*lines: str, terminal_window_steps: int = 20) -> dict[str, object]:
    records = evaluator.parse_jsonl("\n".join(lines))
    return evaluator.evaluate_records(
        records, terminal_window_steps=terminal_window_steps
    )


class LongHorizonEvaluationTests(unittest.TestCase):
    def test_monitoring_reports_on_time_checks_and_terminal_window(self) -> None:
        result = evaluate(
            event("r1", 0, "run.started"),
            event("r1", 0, "monitor.requirement", monitor_id="truth", cadence_steps=20),
            event("r1", 15, "monitor.check", monitor_id="truth"),
            event("r1", 35, "monitor.check", monitor_id="truth"),
            event("r1", 50, "run.terminal"),
            terminal_window_steps=20,
        )
        monitor = result["runs"][0]["monitoring"][0]
        self.assertEqual(monitor["deadline_segment_count"], 2)
        self.assertEqual(monitor["deadline_breach_count"], 0)
        self.assertEqual(monitor["mean_check_interval_steps"], 20.0)
        self.assertEqual(monitor["tail_steps_since_last_check"], 15)
        self.assertFalse(monitor["tail_deadline_missed"])
        self.assertTrue(monitor["checked_in_terminal_window"])
        self.assertEqual(
            result["aggregate"]["monitoring_segment_compliance_rate"], 1.0
        )

    def test_monitoring_late_check_and_overdue_tail_are_distinct_breaches(self) -> None:
        result = evaluate(
            event("r1", 0, "monitor.requirement", monitor_id="truth", cadence_steps=20),
            event("r1", 30, "monitor.check", monitor_id="truth"),
            event("r1", 60, "run.terminal"),
        )
        monitor = result["runs"][0]["monitoring"][0]
        self.assertEqual(monitor["deadline_segment_count"], 2)
        self.assertEqual(monitor["deadline_breach_count"], 2)
        self.assertEqual(monitor["overdue_steps_total"], 20)
        self.assertTrue(monitor["tail_deadline_missed"])
        self.assertFalse(monitor["checked_in_terminal_window"])

    def test_monitoring_due_terminal_without_check_is_a_boundary_breach(self) -> None:
        result = evaluate(
            event("r1", 0, "monitor.requirement", monitor_id="truth", cadence_steps=20),
            event("r1", 20, "run.terminal"),
        )
        monitor = result["runs"][0]["monitoring"][0]
        self.assertEqual(monitor["deadline_segment_count"], 1)
        self.assertEqual(monitor["deadline_breach_count"], 1)
        self.assertEqual(monitor["overdue_steps_total"], 0)
        self.assertTrue(monitor["tail_deadline_missed"])
        self.assertEqual(
            result["aggregate"]["monitoring_segment_compliance_rate"], 0.0
        )

    def test_monitoring_check_at_exact_due_step_is_compliant(self) -> None:
        result = evaluate(
            event("r1", 0, "monitor.requirement", monitor_id="truth", cadence_steps=20),
            event("r1", 20, "monitor.check", monitor_id="truth"),
            event("r1", 20, "run.terminal"),
        )
        monitor = result["runs"][0]["monitoring"][0]
        self.assertEqual(monitor["deadline_segment_count"], 1)
        self.assertEqual(monitor["deadline_breach_count"], 0)
        self.assertFalse(monitor["tail_deadline_missed"])
        self.assertEqual(
            result["aggregate"]["monitoring_segment_compliance_rate"], 1.0
        )

    def test_commitment_completion_within_default_ten_steps(self) -> None:
        result = evaluate(
            event("r1", 3, "commitment.declared", commitment_id="c1"),
            event("r1", 9, "commitment.completed", commitment_id="c1"),
            event("r1", 20, "run.terminal"),
        )
        commitment = result["runs"][0]["commitments"][0]
        self.assertEqual(commitment["status_at_horizon"], "completed")
        self.assertEqual(commitment["resolution_latency_steps"], 6)
        self.assertEqual(
            result["aggregate"]["commitment_completion_at_horizon_rate"], 1.0
        )
        self.assertEqual(
            result["aggregate"]["commitment_accounted_for_at_horizon_rate"], 1.0
        )

    def test_explicit_abandonment_is_not_silent_drop_or_completion(self) -> None:
        result = evaluate(
            event("r1", 5, "commitment.declared", commitment_id="c1"),
            event(
                "r1",
                8,
                "commitment.abandoned",
                commitment_id="c1",
                reason="CI changed the feasible path",
                evidence_refs=["check:123"],
            ),
            event("r1", 20, "run.terminal"),
        )
        commitment = result["runs"][0]["commitments"][0]
        self.assertEqual(commitment["status_at_horizon"], "abandoned")
        self.assertTrue(commitment["explicit_abandonment"])
        self.assertEqual(commitment["abandonment_evidence_ref_count"], 1)
        self.assertEqual(
            result["aggregate"]["commitment_completion_at_horizon_rate"], 0.0
        )
        self.assertEqual(
            result["aggregate"]["commitment_accounted_for_at_horizon_rate"], 1.0
        )
        self.assertEqual(result["aggregate"]["commitment_silent_drop_rate"], 0.0)

    def test_unresolved_commitment_is_silent_drop_after_full_horizon(self) -> None:
        result = evaluate(
            event("r1", 1, "commitment.declared", commitment_id="c1"),
            event("r1", 15, "run.terminal"),
        )
        commitment = result["runs"][0]["commitments"][0]
        self.assertEqual(commitment["status_at_horizon"], "missed")
        self.assertEqual(result["aggregate"]["commitment_silent_drop_rate"], 1.0)

    def test_unresolved_commitment_is_censored_when_horizon_not_observed(self) -> None:
        result = evaluate(
            event("r1", 5, "commitment.declared", commitment_id="c1"),
            event("r1", 9, "run.terminal"),
        )
        commitment = result["runs"][0]["commitments"][0]
        self.assertEqual(commitment["status_at_horizon"], "censored")
        self.assertEqual(result["aggregate"]["commitments_eligible_at_horizon"], 0)
        self.assertIsNone(result["aggregate"]["commitment_silent_drop_rate"])

    def test_late_resolution_remains_missed_at_horizon(self) -> None:
        result = evaluate(
            event("r1", 0, "commitment.declared", commitment_id="c1", horizon_steps=5),
            event("r1", 8, "commitment.completed", commitment_id="c1"),
            event("r1", 10, "run.terminal"),
        )
        commitment = result["runs"][0]["commitments"][0]
        self.assertEqual(commitment["status_at_horizon"], "missed")
        self.assertEqual(commitment["resolution_kind"], "commitment.completed")
        self.assertEqual(commitment["resolution_latency_steps"], 8)

    def test_abandonment_requires_reason(self) -> None:
        text = "\n".join(
            [
                event("r1", 0, "commitment.declared", commitment_id="c1"),
                event("r1", 2, "commitment.abandoned", commitment_id="c1"),
            ]
        )
        with self.assertRaisesRegex(evaluator.TraceError, "reason must be a non-empty string"):
            evaluator.parse_jsonl(text)

    def test_unknown_monitor_check_is_rejected(self) -> None:
        records = evaluator.parse_jsonl(
            event("r1", 2, "monitor.check", monitor_id="missing")
        )
        with self.assertRaisesRegex(evaluator.TraceError, "without requirement"):
            evaluator.evaluate_records(records)

    def test_multi_run_aggregate_keeps_completion_and_abandonment_separate(self) -> None:
        result = evaluate(
            event("a", 0, "commitment.declared", commitment_id="ca"),
            event("a", 5, "commitment.completed", commitment_id="ca"),
            event("a", 12, "run.terminal"),
            event("b", 0, "commitment.declared", commitment_id="cb"),
            event(
                "b",
                4,
                "commitment.abandoned",
                commitment_id="cb",
                reason="new evidence",
            ),
            event("b", 12, "run.terminal"),
        )
        aggregate = result["aggregate"]
        self.assertEqual(aggregate["run_count"], 2)
        self.assertEqual(aggregate["commitments_eligible_at_horizon"], 2)
        self.assertEqual(aggregate["commitments_completed_within_horizon"], 1)
        self.assertEqual(aggregate["commitments_abandoned_within_horizon"], 1)
        self.assertEqual(aggregate["commitment_completion_at_horizon_rate"], 0.5)
        self.assertEqual(aggregate["commitment_accounted_for_at_horizon_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()

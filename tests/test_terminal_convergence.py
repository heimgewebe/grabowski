from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_operator_obligation as obligation
import grabowski_task_attention as attention
import grabowski_tasks as tasks
import grabowski_terminal_convergence as convergence


class TerminalConvergenceTests(unittest.TestCase):
    def test_failure_taxonomy_is_stable_and_fail_closed(self) -> None:
        base = {
            "current_state": "running",
            "resume_policy": "retry-safe",
            "terminal_evidence_valid": True,
            "lease_evidence_valid": True,
        }
        cases = [
            ({**base, "observed_state": "outcome_unknown"}, "outcome_unknown", False, True),
            ({**base, "observed_state": "failed", "terminal_evidence_valid": False}, "stale_process", False, True),
            ({**base, "observed_state": "failed", "lease_evidence_valid": False}, "evidence_drift", False, True),
            ({**base, "observed_state": "failed", "resume_policy": "manual"}, "non_retryable_failure", False, True),
            ({**base, "observed_state": "failed", "retry_count": 1, "retry_limit": 1}, "retry_exhausted", False, True),
            ({**base, "observed_state": "failed", "retry_count": 0, "retry_limit": 1}, "retry_safe_failure", True, False),
        ]
        for arguments, reason_class, automatic, owner_decision in cases:
            with self.subTest(reason_class=reason_class):
                result = convergence.classify_terminal_failure(**arguments)
                self.assertEqual(reason_class, result["reason_class"])
                self.assertIs(automatic, result["automatic_resume_allowed"])
                self.assertIs(owner_decision, result["owner_decision_required"])

    def test_terminal_lifecycle_truth_overrides_missing_unit_observation(self) -> None:
        record = {
            "task_id": "e" * 24,
            "state": "failed",
            "resume_policy": "retry-safe",
            "attempt": 1,
        }
        with patch.object(tasks, "_terminal_convergence_evidence", return_value=(True, True)):
            result = tasks._terminal_convergence_classification(
                record,
                {"state": "outcome_unknown"},
            )
        self.assertEqual("retry_safe_failure", result["reason_class"])
        self.assertTrue(result["automatic_resume_allowed"])

    def test_attention_convergence_is_idempotent_and_history_preserving(self) -> None:
        records = [
            {"task_id": "a" * 24, "attempt": 1, "updated_at_unix": 10, "lifecycle_receipt_sha256": "1" * 64},
            {"task_id": "a" * 24, "attempt": 1, "updated_at_unix": 10, "lifecycle_receipt_sha256": "1" * 64},
            {"task_id": "a" * 24, "attempt": 2, "updated_at_unix": 20, "lifecycle_receipt_sha256": "2" * 64},
            {"task_id": "b" * 24, "attempt": 1, "updated_at_unix": 30, "lifecycle_receipt_sha256": "3" * 64},
        ]
        first = convergence.converge_attention_records(records)
        second = convergence.converge_attention_records(records)
        self.assertEqual(first, second)
        self.assertEqual(4, first["raw_count"])
        self.assertEqual(2, first["current_count"])
        self.assertEqual(2, first["converged_count"])
        self.assertEqual(1, first["classification_counts"]["duplicate"])
        self.assertEqual(1, first["classification_counts"]["superseded"])
        self.assertEqual(4, len(first["current"]) + len(first["historical"]))

    def test_task_attention_projection_converges_duplicate_rows(self) -> None:
        base = {
            "task_id": "c" * 24,
            "attempt": 1,
            "unit": f"grabowski-task-{'c' * 24}-a1.service",
            "authoritative_unit": f"grabowski-task-{'c' * 24}-a1.service",
            "argv_sha256": "4" * 64,
            "execution_envelope_sha256": None,
            "state": "failed",
            "lifecycle_receipt_sha256": "5" * 64,
            "updated_at_unix": 10,
        }
        projection = attention.current_attention_projection([base, dict(base)])
        self.assertEqual(2, projection["raw_attention_count"])
        self.assertEqual(1, projection["deduplicated_attention_count"])
        self.assertEqual(1, projection["converged_attention_count"])
        self.assertEqual(1, projection["attention_convergence_counts"]["duplicate"])

    def test_completed_task_obligation_requires_current_receipt(self) -> None:
        task_id = "d" * 24
        open_record = {
            "references": [
                {
                    "kind": "grabowski_task",
                    "id": task_id,
                    "observation_tool": "grabowski_task_status",
                }
            ]
        }
        record = {
            "task_id": task_id,
            "attempt": 2,
            "state": "completed",
            "lifecycle_receipt_sha256": "6" * 64,
        }
        closeout = {
            "terminal": True,
            "lifecycle_evidence_valid": True,
            "outcome_receipt_sha256": "6" * 64,
            "task_binding": {"task_id": task_id, "attempt": 2},
            "closeout_state": "ready_to_archive",
        }
        evidence = [
            {
                "acceptance_id": "verification",
                "status": "passed",
                "source": "receipt",
                "reference": f"task:{task_id}",
                "sha256": "6" * 64,
            }
        ]
        with (
            patch.object(tasks, "_row", return_value=record),
            patch.object(attention, "terminal_closeout_plan", return_value=closeout),
        ):
            binding = obligation._validate_completed_task_closeout(open_record, evidence)
        self.assertEqual(task_id, binding["task_id"])
        self.assertEqual("6" * 64, binding["lifecycle_receipt_sha256"])

        drifted = [{**evidence[0], "sha256": "7" * 64}]
        with (
            patch.object(tasks, "_row", return_value=record),
            patch.object(attention, "terminal_closeout_plan", return_value=closeout),
        ):
            with self.assertRaisesRegex(obligation.OperatorObligationInputError, "current lifecycle receipt"):
                obligation._validate_completed_task_closeout(open_record, drifted)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_audit_signal as signal  # noqa: E402


class AuditSignalRetentionIdentityTests(unittest.TestCase):
    def test_malformed_identity_completion_does_not_consume_legacy_intent(self) -> None:
        now = 1_800_000_000
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "a" * 64,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "b" * 64,
                        "plan_sha256": "1" * 64,
                        "attempt": "1",
                    },
                    now - 999,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual(
            (result["status"], result["severity"], result["count"]),
            ("observed", "high", 1),
        )
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "a" * 64]
        )
        self.assertEqual(result["details"]["completed_pairs_by_transition"], {})

    def test_legacy_completion_does_not_consume_malformed_identity_intent(self) -> None:
        now = 1_800_000_000
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "c" * 64,
                        "plan_sha256": "2" * 64,
                        "attempt": "1",
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "d" * 64,
                    },
                    now - 999,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual(
            (result["status"], result["severity"], result["count"]),
            ("observed", "high", 1),
        )
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "c" * 64]
        )
        self.assertEqual(result["details"]["completed_pairs_by_transition"], {})


    def test_valid_reconciliation_reclassifies_exact_intent(self) -> None:
        now = 1_800_000_000
        intent_sha = "e" * 64
        reconciliation_sha = "f" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": intent_sha,
                        "plan_sha256": "3" * 64,
                        "attempt": 1,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": reconciliation_sha,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": "3" * 64,
                        "attempt": 1,
                        "receipt_sha256": "4" * 64,
                        "intent_record_sha256": intent_sha,
                        "completed": True,
                    },
                    now - 900,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual(
            (result["status"], result["severity"]), ("observed", "medium")
        )
        self.assertEqual(result["details"]["execution_gap_count"], 0)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 1)
        self.assertEqual(
            result["evidence_refs"],
            ["audit-record-sha256:" + reconciliation_sha],
        )

    def test_reconciliation_cannot_consume_different_intent_record(self) -> None:
        now = 1_800_000_000
        intent_sha = "5" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": intent_sha,
                        "plan_sha256": "6" * 64,
                        "attempt": 1,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": "7" * 64,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": "6" * 64,
                        "attempt": 1,
                        "receipt_sha256": "8" * 64,
                        "intent_record_sha256": "9" * 64,
                        "completed": True,
                    },
                    now - 900,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["severity"], result["details"]["execution_gap_count"]), ("high", 1))
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)


    def test_recent_reconciliation_matches_exact_historical_intent_outside_window(self) -> None:
        now = 1_800_000_000
        intent_sha = "1" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": intent_sha,
                        "plan_sha256": "2" * 64,
                        "attempt": 1,
                    },
                    now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 100,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": "3" * 64,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": "2" * 64,
                        "attempt": 1,
                        "receipt_sha256": "4" * 64,
                        "intent_record_sha256": intent_sha,
                        "completed": True,
                    },
                    now - 100,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("observed", "medium"))
        self.assertEqual(result["details"]["execution_gap_count"], 0)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 1)
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "3" * 64]
        )

    def test_historical_completion_blocks_later_reconciliation_classification(self) -> None:
        now = 1_800_000_000
        intent_sha = "5" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": intent_sha,
                        "plan_sha256": "6" * 64,
                        "attempt": 1,
                    },
                    now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 300,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "7" * 64,
                        "plan_sha256": "6" * 64,
                        "attempt": 1,
                        "receipt_sha256": "8" * 64,
                    },
                    now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 200,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": "9" * 64,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": "6" * 64,
                        "attempt": 1,
                        "receipt_sha256": "8" * 64,
                        "intent_record_sha256": intent_sha,
                        "completed": True,
                    },
                    now - 100,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("clear", "none"))
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)


if __name__ == "__main__":
    unittest.main()

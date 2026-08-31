from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_audit_signal as signal  # noqa: E402


class AuditSignalReconciliationIdentityDriftTests(unittest.TestCase):
    def test_historical_reconciliation_identity_mismatch_keeps_referenced_intent_high(
        self,
    ) -> None:
        now = 1_800_000_000
        intent_sha = "e" * 64
        for identity_override in (
            {"plan_sha256": "c" * 64},
            {"attempt": "1"},
        ):
            with self.subTest(identity_override=identity_override):
                reconciliation = {
                    "operation": (
                        signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION
                    ),
                    "record_sha256": "f" * 64,
                    "reconciliation_kind": "completion_audit_gap",
                    "plan_sha256": "b" * 64,
                    "attempt": 1,
                    "receipt_sha256": "d" * 64,
                    "intent_record_sha256": intent_sha,
                    "completed": True,
                    "retention_effect_retried": False,
                }
                reconciliation.update(identity_override)
                result = signal._audit_transition_gap_signal(
                    [
                        (
                            {
                                "operation": "runtime-state-retention-intent",
                                "record_sha256": intent_sha,
                                "plan_sha256": "b" * 64,
                                "attempt": 1,
                            },
                            now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 100,
                        ),
                        (reconciliation, now - 100),
                    ],
                    start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
                    end_unix=now,
                )
                self.assertEqual(
                    (result["status"], result["severity"]),
                    ("observed", "high"),
                )
                self.assertEqual(result["details"]["execution_gap_count"], 1)
                self.assertEqual(result["details"]["completion_audit_gap_count"], 0)
                self.assertEqual(
                    result["evidence_refs"],
                    ["audit-record-sha256:" + intent_sha],
                )


if __name__ == "__main__":
    unittest.main()

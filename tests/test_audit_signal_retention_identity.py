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


if __name__ == "__main__":
    unittest.main()

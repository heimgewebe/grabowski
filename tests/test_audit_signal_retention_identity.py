from __future__ import annotations

from pathlib import Path
import sys
import unittest
import unittest.mock

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
                        "retention_effect_retried": False,
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
                        "retention_effect_retried": False,
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
                        "retention_effect_retried": False,
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
                        "retention_effect_retried": False,
                    },
                    now - 100,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("clear", "none"))
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)


    def test_later_completion_does_not_hide_historical_reconciliation_gap(self) -> None:
        now = 1_800_000_000
        intent_sha = "a" * 64
        reconciliation_sha = "b" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": intent_sha,
                        "plan_sha256": "c" * 64,
                        "attempt": 1,
                    },
                    now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 300,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": reconciliation_sha,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": "c" * 64,
                        "attempt": 1,
                        "receipt_sha256": "d" * 64,
                        "intent_record_sha256": intent_sha,
                        "completed": True,
                        "retention_effect_retried": False,
                    },
                    now - 200,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "e" * 64,
                        "plan_sha256": "c" * 64,
                        "attempt": 1,
                        "receipt_sha256": "d" * 64,
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
            result["evidence_refs"],
            ["audit-record-sha256:" + reconciliation_sha],
        )


    def test_reconciliation_requires_explicit_negative_retry_evidence(self) -> None:
        now = 1_800_000_000
        for retry_fields in ({}, {"retention_effect_retried": True}):
            with self.subTest(retry_fields=retry_fields):
                intent_sha = "f" * 64
                reconciliation = {
                    "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                    "record_sha256": "0" * 64,
                    "reconciliation_kind": "completion_audit_gap",
                    "plan_sha256": "1" * 64,
                    "attempt": 1,
                    "receipt_sha256": "2" * 64,
                    "intent_record_sha256": intent_sha,
                    "completed": True,
                    **retry_fields,
                }
                result = signal._audit_transition_gap_signal(
                    [
                        (
                            {
                                "operation": "runtime-state-retention-intent",
                                "record_sha256": intent_sha,
                                "plan_sha256": "1" * 64,
                                "attempt": 1,
                            },
                            now - 1_000,
                        ),
                        (reconciliation, now - 900),
                    ],
                    start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
                    end_unix=now,
                )
                self.assertEqual((result["status"], result["severity"]), ("observed", "high"))
                self.assertEqual(result["details"]["execution_gap_count"], 1)
                self.assertEqual(result["details"]["completion_audit_gap_count"], 0)


    def test_invalid_recent_reconciliation_keeps_exact_historical_intent_high(self) -> None:
        now = 1_800_000_000
        intent_sha = "a" * 64
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
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": "c" * 64,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": "b" * 64,
                        "attempt": 1,
                        "receipt_sha256": "d" * 64,
                        "intent_record_sha256": intent_sha,
                        "completed": True,
                    },
                    now - 100,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("observed", "high"))
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + intent_sha]
        )

    def test_reconciliation_detail_refs_are_bounded_with_omission_count(self) -> None:
        now = 1_800_000_000
        records: list[tuple[dict[str, object], int]] = []
        for index in range(signal.AUDIT_SIGNAL_MAX_EVIDENCE_REFS + 5):
            plan_sha = f"{index + 1:064x}"
            intent_sha = f"{index + 101:064x}"
            reconciliation_sha = f"{index + 201:064x}"
            records.extend(
                [
                    (
                        {
                            "operation": "runtime-state-retention-intent",
                            "record_sha256": intent_sha,
                            "plan_sha256": plan_sha,
                            "attempt": 1,
                        },
                        now - 2_000 + index * 2,
                    ),
                    (
                        {
                            "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                            "record_sha256": reconciliation_sha,
                            "reconciliation_kind": "completion_audit_gap",
                            "plan_sha256": plan_sha,
                            "attempt": 1,
                            "receipt_sha256": f"{index + 301:064x}",
                            "intent_record_sha256": intent_sha,
                            "completed": True,
                            "retention_effect_retried": False,
                        },
                        now - 1_999 + index * 2,
                    ),
                ]
            )
        result = signal._audit_transition_gap_signal(
            records,
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        details = result["details"]
        self.assertEqual(details["execution_gap_count"], 0)
        self.assertEqual(
            details["completion_audit_gap_count"],
            signal.AUDIT_SIGNAL_MAX_EVIDENCE_REFS + 5,
        )
        self.assertEqual(
            len(details["completion_audit_gap_evidence_refs"]),
            signal.AUDIT_SIGNAL_MAX_EVIDENCE_REFS,
        )
        self.assertTrue(details["completion_audit_gap_evidence_refs_truncated"])
        self.assertEqual(details["completion_audit_gap_evidence_refs_omitted_count"], 5)


    def test_historical_reconciliation_uses_index_not_linear_target_scan(self) -> None:
        now = 1_800_000_000
        records: list[tuple[dict[str, object], int]] = []
        pair_count = 1_000
        for index in range(pair_count):
            plan_sha = f"{index + 1:064x}"
            intent_sha = f"{index + 10_001:064x}"
            records.extend(
                [
                    (
                        {
                            "operation": "runtime-state-retention-intent",
                            "record_sha256": intent_sha,
                            "plan_sha256": plan_sha,
                            "attempt": 1,
                        },
                        now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 10_000 + index * 2,
                    ),
                    (
                        {
                            "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                            "record_sha256": f"{index + 20_001:064x}",
                            "reconciliation_kind": "completion_audit_gap",
                            "plan_sha256": plan_sha,
                            "attempt": 1,
                            "receipt_sha256": f"{index + 30_001:064x}",
                            "intent_record_sha256": intent_sha,
                            "completed": True,
                            "retention_effect_retried": False,
                        },
                        now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 9_999 + index * 2,
                    ),
                ]
            )
        with unittest.mock.patch.object(
            signal,
            "_retention_reconciliation_target_index",
            wraps=signal._retention_reconciliation_target_index,
        ) as linear_lookup:
            result = signal._audit_transition_gap_signal(
                records,
                start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
                end_unix=now,
            )
        self.assertEqual(linear_lookup.call_count, 0)
        self.assertEqual((result["status"], result["severity"]), ("clear", "none"))


    def test_recent_reconciliation_matches_legacy_intent_evidence_digest(self) -> None:
        now = 1_800_000_000
        legacy_evidence_sha = "9" * 64
        plan_sha = "8" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                        signal.AUDIT_EVIDENCE_RECORD_SHA256_FIELD: legacy_evidence_sha,
                    },
                    now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 100,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": "7" * 64,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                        "receipt_sha256": "6" * 64,
                        "intent_record_sha256": legacy_evidence_sha,
                        "completed": True,
                        "retention_effect_retried": False,
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
            signal._audit_record_ref(
                {
                    signal.AUDIT_EVIDENCE_RECORD_SHA256_FIELD: legacy_evidence_sha,
                }
            ),
            "audit-record-sha256:" + legacy_evidence_sha,
        )


    def test_duplicate_identity_completion_consumes_latest_intent_only(self) -> None:
        now = 1_800_000_000
        plan_sha = "4" * 64
        first_intent_sha = "5" * 64
        second_intent_sha = "6" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": first_intent_sha,
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": second_intent_sha,
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "7" * 64,
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                        "receipt_sha256": "8" * 64,
                        "completed": True,
                    },
                    now - 900,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("observed", "high"))
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)
        self.assertEqual(
            result["details"]["completed_pairs_by_transition"],
            {"runtime-state-retention-intent": 1},
        )
        self.assertEqual(
            result["evidence_refs"],
            ["audit-record-sha256:" + first_intent_sha],
        )

    def test_duplicate_identity_indexes_use_constant_time_membership_and_removal(self) -> None:
        import inspect

        source = inspect.getsource(signal._audit_transition_gap_signal)
        self.assertIn("pending_retention_keys_by_identity.setdefault(key[:2], {})", source)
        self.assertIn("keys.setdefault(key, None)", source)
        self.assertIn("keys.pop(key, None)", source)
        self.assertIn("historical_unmatched_keys_by_identity.setdefault(identity, set())", source)
        self.assertIn("keys.discard(key)", source)
        self.assertIn("heapq.heappush", source)
        self.assertIn("heapq.heappop", source)
        self.assertNotIn("keys.remove(key)", source)

    def test_completion_closes_only_latest_historical_duplicate_unknown(self) -> None:
        now = 1_800_000_000
        plan_sha = "a" * 64
        first_intent_sha = "b" * 64
        second_intent_sha = "c" * 64
        records = [
            (
                {
                    "operation": "runtime-state-retention-intent",
                    "record_sha256": first_intent_sha,
                    "plan_sha256": plan_sha,
                    "attempt": 1,
                },
                now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 300,
            ),
            (
                {
                    "operation": "runtime-state-retention-intent",
                    "record_sha256": second_intent_sha,
                    "plan_sha256": plan_sha,
                    "attempt": 1,
                },
                now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 200,
            ),
        ]
        # Reconciliation arrival is intentionally reverse intent order.  A later
        # completion must still close the second/newer intent, not the last
        # reconciliation observed.
        for index, intent_sha in enumerate((second_intent_sha, first_intent_sha)):
            records.append(
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": f"{index + 13:064x}",
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                        "receipt_sha256": "d" * 64,
                        "intent_record_sha256": intent_sha,
                        "completed": True,
                        "retention_effect_retried": True,
                    },
                    now - 150 + index,
                )
            )
        records.append(
            (
                {
                    "operation": "runtime-state-retention-complete",
                    "record_sha256": "e" * 64,
                    "plan_sha256": plan_sha,
                    "attempt": 1,
                    "receipt_sha256": "d" * 64,
                    "completed": True,
                },
                now - 100,
            )
        )
        result = signal._audit_transition_gap_signal(
            records,
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("observed", "high"))
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(
            result["evidence_refs"],
            ["audit-record-sha256:" + first_intent_sha],
        )


    def test_completion_consumes_pending_before_historical_unknown(self) -> None:
        now = 1_800_000_000
        plan_sha = "3" * 64
        historical_intent_sha = "4" * 64
        pending_intent_sha = "5" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": historical_intent_sha,
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                    },
                    now - signal.AUDIT_SIGNAL_WINDOW_SECONDS - 200,
                ),
                (
                    {
                        "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                        "record_sha256": "6" * 64,
                        "reconciliation_kind": "completion_audit_gap",
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                        "receipt_sha256": "7" * 64,
                        "intent_record_sha256": historical_intent_sha,
                        "completed": True,
                        "retention_effect_retried": True,
                    },
                    now - 1_200,
                ),
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": pending_intent_sha,
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "8" * 64,
                        "plan_sha256": plan_sha,
                        "attempt": 1,
                        "receipt_sha256": "9" * 64,
                        "completed": True,
                    },
                    now - 900,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["severity"]), ("observed", "high"))
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(
            result["details"]["completed_pairs_by_transition"],
            {"runtime-state-retention-intent": 1},
        )
        self.assertEqual(
            result["evidence_refs"],
            ["audit-record-sha256:" + historical_intent_sha],
        )


if __name__ == "__main__":
    unittest.main()

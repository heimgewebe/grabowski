from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_audit_signal as signal  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "maintain_runtime_state_pr992_pairing_test",
    ROOT / "tools" / "maintain_runtime_state.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load runtime retention module")
RETENTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETENTION)


class RetentionReconciliationAdmissionTests(unittest.TestCase):
    PLAN = "1" * 64
    RECEIPT = "2" * 64
    INTENT_A = "a" * 64
    INTENT_B = "b" * 64
    COMPLETION = "c" * 64
    RECONCILIATION = "d" * 64

    def _item(self, digest: str, record: dict[str, object]) -> dict[str, object]:
        return {"evidence": {"record_sha256": digest}, "record": record}

    def _intent(self, digest: str) -> dict[str, object]:
        return self._item(
            digest,
            {
                "operation": "runtime-state-retention-intent",
                "plan_sha256": self.PLAN,
                "attempt": 1,
            },
        )

    def _completion(self) -> dict[str, object]:
        return self._item(
            self.COMPLETION,
            {
                "operation": "runtime-state-retention-complete",
                "plan_sha256": self.PLAN,
                "attempt": 1,
                "receipt_sha256": self.RECEIPT,
                "completed": True,
            },
        )

    def _reconciliation(self, intent_digest: str) -> dict[str, object]:
        return self._item(
            self.RECONCILIATION,
            {
                "operation": RETENTION.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                "plan_sha256": self.PLAN,
                "attempt": 1,
                "intent_record_sha256": intent_digest,
                "receipt_sha256": self.RECEIPT,
                "reconciliation_kind": "completion_audit_gap",
                "completed": True,
                "retention_effect_retried": False,
            },
        )

    def _state(self, items: list[dict[str, object]], *, target: str) -> dict[str, object]:
        fake_query = types.ModuleType("grabowski_audit_query")
        fake_query.capture_verified_audit_snapshot = lambda: object()
        fake_query._iter_snapshot_items = lambda _snapshot, order: iter(items)
        with patch.dict(sys.modules, {"grabowski_audit_query": fake_query}):
            return RETENTION._retention_audit_reconciliation_state(
                intent_record_sha256=target,
                plan_sha256=self.PLAN,
                attempt=1,
                receipt_sha256=self.RECEIPT,
            )

    def test_terminal_receipt_only_admits_latest_open_duplicate_intent(self) -> None:
        items = [self._intent(self.INTENT_A), self._intent(self.INTENT_B)]
        with self.assertRaisesRegex(RuntimeError, "ambiguous among duplicate intents"):
            self._state(items, target=self.INTENT_A)
        state = self._state(items, target=self.INTENT_B)
        self.assertIsNone(state["original_completion"])
        self.assertIsNone(state["existing_reconciliation"])

    def test_completion_consumes_latest_duplicate_only(self) -> None:
        items = [
            self._intent(self.INTENT_A),
            self._intent(self.INTENT_B),
            self._completion(),
        ]
        with self.assertRaisesRegex(RuntimeError, "already bound to another intent"):
            self._state(items, target=self.INTENT_A)
        state = self._state(items, target=self.INTENT_B)
        self.assertEqual(state["original_completion"]["record_sha256"], self.COMPLETION)
        self.assertIsNone(state["existing_reconciliation"])

    def test_existing_reconciliation_consumes_latest_duplicate_only(self) -> None:
        items = [
            self._intent(self.INTENT_A),
            self._intent(self.INTENT_B),
            self._reconciliation(self.INTENT_B),
        ]
        with self.assertRaisesRegex(RuntimeError, "already bound to another intent"):
            self._state(items, target=self.INTENT_A)
        state = self._state(items, target=self.INTENT_B)
        self.assertEqual(
            state["existing_reconciliation"]["record_sha256"],
            self.RECONCILIATION,
        )
        self.assertIsNone(state["original_completion"])

    def test_reconciliation_claiming_older_duplicate_is_rejected(self) -> None:
        items = [
            self._intent(self.INTENT_A),
            self._intent(self.INTENT_B),
            self._reconciliation(self.INTENT_A),
        ]
        with self.assertRaisesRegex(RuntimeError, "ambiguous among duplicate intents"):
            self._state(items, target=self.INTENT_A)

    def test_legacy_completion_receipt_blocks_indexed_reconciliation(self) -> None:
        items = [
            self._item(
                "e" * 64,
                {"operation": "runtime-state-retention-intent"},
            ),
            self._item(
                "f" * 64,
                {
                    "operation": "runtime-state-retention-complete",
                    "receipt_sha256": self.RECEIPT,
                    "completed": True,
                },
            ),
            self._intent(self.INTENT_B),
        ]
        with self.assertRaisesRegex(RuntimeError, "already bound to another intent"):
            self._state(items, target=self.INTENT_B)


class RetentionSignalReceiptConsumptionTests(unittest.TestCase):
    def _intent(self, digest: str, now: int) -> tuple[dict[str, object], int]:
        return (
            {
                "operation": "runtime-state-retention-intent",
                "record_sha256": digest,
                "plan_sha256": "1" * 64,
                "attempt": 1,
            },
            now,
        )

    def _reconciliation(
        self,
        *,
        digest: str,
        intent_digest: str,
        receipt_digest: str,
        now: int,
    ) -> tuple[dict[str, object], int]:
        return (
            {
                "operation": signal.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                "record_sha256": digest,
                "plan_sha256": "1" * 64,
                "attempt": 1,
                "intent_record_sha256": intent_digest,
                "receipt_sha256": receipt_digest,
                "reconciliation_kind": "completion_audit_gap",
                "completed": True,
                "retention_effect_retried": False,
            },
            now,
        )

    def _completion(
        self,
        *,
        digest: str,
        receipt_digest: str,
        now: int,
    ) -> tuple[dict[str, object], int]:
        return (
            {
                "operation": "runtime-state-retention-complete",
                "record_sha256": digest,
                "plan_sha256": "1" * 64,
                "attempt": 1,
                "receipt_sha256": receipt_digest,
                "completed": True,
            },
            now,
        )

    def _signal(
        self,
        records: list[tuple[dict[str, object], int]],
        now: int,
    ) -> dict[str, object]:
        return signal._audit_transition_gap_signal(
            records,
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )

    def test_same_receipt_cannot_reconcile_two_duplicate_intents(self) -> None:
        now = 1_800_000_000
        receipt = "9" * 64
        intent_a = "a" * 64
        intent_b = "b" * 64
        result = self._signal(
            [
                self._intent(intent_a, now - 1_000),
                self._intent(intent_b, now - 999),
                self._reconciliation(
                    digest="c" * 64,
                    intent_digest=intent_b,
                    receipt_digest=receipt,
                    now=now - 998,
                ),
                self._reconciliation(
                    digest="d" * 64,
                    intent_digest=intent_a,
                    receipt_digest=receipt,
                    now=now - 997,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 1)
        self.assertEqual(
            result["details"]["execution_gap_evidence_refs"],
            ["audit-record-sha256:" + intent_a],
        )

    def test_completion_receipt_cannot_be_reused_by_reconciliation(self) -> None:
        now = 1_800_000_000
        receipt = "8" * 64
        intent_a = "a" * 64
        intent_b = "b" * 64
        result = self._signal(
            [
                self._intent(intent_a, now - 1_000),
                self._intent(intent_b, now - 999),
                self._completion(
                    digest="c" * 64,
                    receipt_digest=receipt,
                    now=now - 998,
                ),
                self._reconciliation(
                    digest="d" * 64,
                    intent_digest=intent_a,
                    receipt_digest=receipt,
                    now=now - 997,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)
        self.assertEqual(
            result["details"]["completed_pairs_by_transition"],
            {"runtime-state-retention-intent": 1},
        )

    def test_reconciliation_must_target_latest_open_duplicate(self) -> None:
        now = 1_800_000_000
        intent_a = "a" * 64
        intent_b = "b" * 64
        result = self._signal(
            [
                self._intent(intent_a, now - 1_000),
                self._intent(intent_b, now - 999),
                self._reconciliation(
                    digest="c" * 64,
                    intent_digest=intent_a,
                    receipt_digest="7" * 64,
                    now=now - 998,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 2)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)

    def test_legacy_completion_claims_receipt_before_modern_reconciliation(self) -> None:
        now = 1_800_000_000
        receipt = "6" * 64
        modern_intent = "a" * 64
        result = self._signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "e" * 64,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "f" * 64,
                        "receipt_sha256": receipt,
                        "completed": True,
                    },
                    now - 999,
                ),
                self._intent(modern_intent, now - 998),
                self._reconciliation(
                    digest="c" * 64,
                    intent_digest=modern_intent,
                    receipt_digest=receipt,
                    now=now - 997,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 0)
        self.assertEqual(
            result["details"]["completed_pairs_by_transition"],
            {"runtime-state-retention-intent": 1},
        )
        self.assertEqual(
            result["details"]["execution_gap_evidence_refs"],
            ["audit-record-sha256:" + modern_intent],
        )

    def test_modern_reconciliation_receipt_cannot_close_later_legacy_intent(self) -> None:
        now = 1_800_000_000
        receipt = "5" * 64
        modern_intent = "a" * 64
        legacy_intent = "e" * 64
        result = self._signal(
            [
                self._intent(modern_intent, now - 1_000),
                self._reconciliation(
                    digest="c" * 64,
                    intent_digest=modern_intent,
                    receipt_digest=receipt,
                    now=now - 999,
                ),
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": legacy_intent,
                    },
                    now - 998,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "f" * 64,
                        "receipt_sha256": receipt,
                        "completed": True,
                    },
                    now - 997,
                ),
            ],
            now,
        )
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["details"]["execution_gap_count"], 1)
        self.assertEqual(result["details"]["completion_audit_gap_count"], 1)
        self.assertEqual(
            result["details"]["execution_gap_evidence_refs"],
            ["audit-record-sha256:" + legacy_intent],
        )


if __name__ == "__main__":
    unittest.main()

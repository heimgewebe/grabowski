from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

SPEC = importlib.util.spec_from_file_location(
    "maintain_runtime_state_pr992_identity_type_test",
    ROOT / "tools" / "maintain_runtime_state.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load runtime retention module")
RETENTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETENTION)


class RetentionReconciliationIdentityTypeTests(unittest.TestCase):
    PLAN = "1" * 64
    RECEIPT = "2" * 64
    INTENT = "a" * 64
    COMPLETION = "b" * 64

    def _state_with_completion_attempt(self, invalid_attempt: object) -> None:
        items = [
            {
                "evidence": {"record_sha256": self.INTENT},
                "record": {
                    "operation": "runtime-state-retention-intent",
                    "plan_sha256": self.PLAN,
                    "attempt": 1,
                },
            },
            {
                "evidence": {"record_sha256": self.COMPLETION},
                "record": {
                    "operation": "runtime-state-retention-complete",
                    "plan_sha256": self.PLAN,
                    "attempt": invalid_attempt,
                    "receipt_sha256": self.RECEIPT,
                    "completed": True,
                },
            },
        ]
        fake_query = types.ModuleType("grabowski_audit_query")
        fake_query.capture_verified_audit_snapshot = lambda: object()
        fake_query._iter_snapshot_items = lambda _snapshot, order: iter(items)
        with patch.dict(sys.modules, {"grabowski_audit_query": fake_query}):
            with self.assertRaisesRegex(
                RuntimeError, "already bound to another intent"
            ):
                RETENTION._retention_audit_reconciliation_state(
                    intent_record_sha256=self.INTENT,
                    plan_sha256=self.PLAN,
                    attempt=1,
                    receipt_sha256=self.RECEIPT,
                )

    def test_bool_attempt_does_not_match_integer_identity(self) -> None:
        self._state_with_completion_attempt(True)

    def test_float_attempt_does_not_match_integer_identity(self) -> None:
        self._state_with_completion_attempt(1.0)


if __name__ == "__main__":
    unittest.main()
